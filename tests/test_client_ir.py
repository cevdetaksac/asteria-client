"""IR engine tests with fake WTS/system layers (contract 1.4.92)."""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import client_ir as ir


class FakeWts:
    def __init__(self, own=2):
        self.own = own
        self.logged_off, self.disconnected = [], []
        self.sessions = [
            {"session_id": 0, "station": "Services", "state": "Disconnected", "username": "", "domain": ""},
            {"session_id": 1, "station": "Console", "state": "Active", "username": "alice", "domain": "PC"},
            {"session_id": 2, "station": "RDP-Tcp#1", "state": "Active", "username": "svcagent", "domain": "PC"},
            {"session_id": 3, "station": "RDP-Tcp#2", "state": "Active", "username": "mallory", "domain": "PC"},
            {"session_id": 4, "station": "", "state": "Disconnected", "username": "bob", "domain": "PC"},
            {"session_id": 65536, "station": "RDP-Tcp", "state": "Listen", "username": "", "domain": ""},
        ]

    def own_session_id(self): return self.own
    def enumerate(self): return [dict(s) for s in self.sessions]
    def logoff(self, sid): self.logged_off.append(sid); return True
    def disconnect(self, sid): self.disconnected.append(sid); return True


class FakeOps:
    def __init__(self):
        self.active = {"Administrator": True, "admin2": True, "alice": True, "bob": True,
                       "Guest": False, "DefaultAccount": False, "WDAGUtilityAccount": False, "PC$": True}
        self.sids = {"Administrator": "S-1-5-21-1-500", "Guest": "S-1-5-21-1-501",
                     "DefaultAccount": "S-1-5-21-1-503", "WDAGUtilityAccount": "S-1-5-21-1-504"}
        self.rules = {}

    def local_users(self):
        return [{"name": n, "enabled": a, "sid": self.sids.get(n, "S-1-5-21-1-1001")} for n, a in self.active.items()]
    def admin_names(self): return ["Administrator", "admin2"]
    def set_user_active(self, n, a): self.active[n] = a
    def rdp_ports(self): return [3389, 50123]
    def fw_add_block(self, name, ports, proto, remote): self.rules[name] = (ports, proto, remote)
    def fw_delete(self, name): self.rules.pop(name, None)


class TestIR(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.wts, self.ops = FakeWts(), FakeOps()
        self.e = ir.IncidentResponse(wts=self.wts, ops=self.ops, store_dir=self.tmp.name, log=lambda m: None)

    def test_logoff_session_protects_own_and_zero(self):
        self.assertEqual(self.e.logoff_session(2)["actions"][0]["error"], "protected_session")
        self.assertEqual(self.e.logoff_session(0)["actions"][0]["error"], "protected_session")
        r = self.e.logoff_session(3)
        self.assertTrue(r["ok"]); self.assertEqual(self.wts.logged_off, [3])

    def test_disconnect_and_dry_run(self):
        self.assertTrue(self.e.disconnect_session(3)["ok"]); self.assertEqual(self.wts.disconnected, [3])
        r = self.e.logoff_session(1, dry_run=True)
        self.assertTrue(r["actions"][0]["dry_run"]); self.assertEqual(self.wts.logged_off, [])

    def test_logoff_all_skips_protected_listener_and_excluded(self):
        r = self.e.logoff_all_sessions(exclude_users=["bob"])
        self.assertEqual(sorted(self.wts.logged_off), [1, 3])
        skipped = [a for a in r["actions"] if a.get("skipped")]
        self.assertEqual([a["target"] for a in skipped], [4])
        self.assertTrue(r["ok"])

    def test_lockdown_full_and_undo(self):
        r = self.e.emergency_lockdown(logoff_all=True, block_rdp=True, disable_non_admin=True,
                                      keep_admins=["alice"], management_ip="203.0.113.7", duration_minutes=0)
        self.assertTrue(r["ok"], r); lid = r["undo_id"]
        self.assertEqual(len(self.ops.rules), 2)
        ports, proto, remote = next(iter(self.ops.rules.values()))
        self.assertEqual(ports, [3389, 50123])
        self.assertNotIn("203.0.113.7/32", remote.split(","))
        self.assertIn("::/0", remote)
        # bob disabled; alice kept; admins/builtin/machine untouched
        self.assertFalse(self.ops.active["bob"]); self.assertTrue(self.ops.active["alice"])
        self.assertTrue(self.ops.active["admin2"]); self.assertTrue(self.ops.active["PC$"])
        self.assertNotIn(1, self.wts.logged_off)  # alice kept
        u = self.e.emergency_lockdown_undo(lid)
        self.assertTrue(u["ok"]); self.assertEqual(self.ops.rules, {}); self.assertTrue(self.ops.active["bob"])
        self.assertEqual(self.e.emergency_lockdown_undo(lid)["actions"][0]["skipped"], "already_undone")

    def test_lockdown_dry_run_changes_nothing(self):
        r = self.e.emergency_lockdown(disable_non_admin=True, dry_run=True)
        self.assertTrue(r["dry_run"]); self.assertNotIn("undo_id", r)
        self.assertEqual(self.ops.rules, {}); self.assertTrue(self.ops.active["bob"]); self.assertEqual(self.wts.logged_off, [])

    def test_invalid_ip_and_unknown_undo(self):
        self.assertFalse(self.e.emergency_lockdown(management_ip="nope")["ok"])
        self.assertEqual(self.e.emergency_lockdown_undo("zzz")["actions"][0]["error"], "unknown_lockdown_id")

    def test_remote_ranges(self):
        r = ir.remote_ranges_excluding("10.0.0.1").split(",")
        self.assertEqual(len(r), 33)


class TestSupervisor(unittest.TestCase):
    def test_restarts_on_crash_then_stops_on_return(self):
        import client_supervisor as sv
        calls = []
        def target():
            calls.append(1)
            if len(calls) < 3:
                raise RuntimeError("boom")
        t = sv.start_supervised(target, name="t-sup", sleep=lambda s: None)
        t.join(5)
        self.assertEqual(len(calls), 3)
        self.assertEqual(sv.stats()["t-sup"]["restarts"], 2)


if __name__ == "__main__":
    unittest.main()
