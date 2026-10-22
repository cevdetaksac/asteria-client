#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Admin commands v2: standard result shape, create_user/kill/restart/logoff/reboot."""

import json
import os
import tempfile
import threading
import time
import unittest
from unittest import mock

import client_admin_ops as ops


class _WinErr(Exception):
    def __init__(self, code, msg="err"):
        super().__init__(code, "fn", msg)
        self.winerror = code


class FakeNet:
    def __init__(self, existing=(), fail_add=None, fail_group=None):
        self.users = {u.lower() for u in existing}
        self.fail_add = fail_add
        self.fail_group = fail_group or {}
        self.group_adds = []
        self.passwords = {}

    def user_exists(self, u):
        return u.lower() in self.users

    def add_user(self, u, p, comment, flags):
        if self.fail_add:
            raise _WinErr(self.fail_add)
        self.users.add(u.lower())
        self.passwords[u] = p

    def reset_user(self, u, p, flags):
        self.passwords[u] = p

    def resolve_group(self, g):
        return g

    def add_to_group(self, g, u):
        if g in self.fail_group:
            raise _WinErr(self.fail_group[g])
        self.group_adds.append((g, u))


class TestStdShape(unittest.TestCase):
    def test_shape(self):
        r = ops.std(False, "X", "msg", [ops.step("a", False)], foo=1)
        for k in ("ok", "success", "code", "message", "steps", "error", "data"):
            self.assertIn(k, r)
        self.assertEqual(r["error"], "X")
        self.assertNotIn("error", ops.std(True, "OK", "m"))


class TestCreateUser(unittest.TestCase):
    def test_created_with_groups(self):
        net = FakeNet()
        r = ops.create_user("bob", "Passw0rd!x", ["Administrators", "Remote Desktop Users"], net=net)
        self.assertTrue(r["ok"], r)
        self.assertEqual(r["code"], "USER_CREATED")
        self.assertEqual(len([s for s in r["steps"] if s["step"] == "group"]), 2)
        self.assertNotIn("Passw0rd!x", json.dumps(r))

    def test_password_policy(self):
        r = ops.create_user("bob", "a", ["Users"], net=FakeNet(fail_add=2245))
        self.assertFalse(r["ok"])
        self.assertEqual(r["code"], "PASSWORD_POLICY")

    def test_group_failure_reported(self):
        r = ops.create_user("bob", "Passw0rd!x", ["Users", "Nope"],
                            net=FakeNet(fail_group={"Nope": 1376}))
        self.assertFalse(r["ok"])
        self.assertEqual(r["code"], "GROUP_ADD_FAILED")
        self.assertEqual(r["data"]["failed_groups"], ["Nope"])
        self.assertEqual(r["data"]["groups"], ["Users"])

    def test_already_member_ok(self):
        r = ops.create_user("bob", "Passw0rd!x", ["Users"], net=FakeNet(fail_group={"Users": 1378}))
        self.assertTrue(r["ok"])

    def test_exists_reset_enable(self):
        r = ops.create_user("bob", "Passw0rd!x", [], if_exists="reset_enable", net=FakeNet(existing={"bob"}))
        self.assertTrue(r["ok"])
        self.assertEqual(r["code"], "USER_RESET")


class _FakePs:
    class NoSuchProcess(Exception):
        pass

    class AccessDenied(Exception):
        pass

    def __init__(self, procs):
        self.procs = procs  # pid -> dict(name, ct, children, killed)

    def Process(self, pid):
        if pid not in self.procs:
            raise self.NoSuchProcess()
        ps = self

        class P:
            def __init__(s, pid):
                s.pid = pid

            def name(s):
                return ps.procs[s.pid]["name"]

            def create_time(s):
                return ps.procs[s.pid]["ct"]

            def children(s, recursive=False):
                return [P(c) for c in ps.procs[s.pid].get("children", [])]

            def kill(s):
                ps.procs[s.pid]["killed"] = True

        return P(pid)

    def wait_procs(self, procs, timeout=None):
        alive = [p for p in procs if not self.procs.get(p.pid, {}).get("killed")]
        return [p for p in procs if p not in alive], alive


class TestKillProcess(unittest.TestCase):
    def test_gone(self):
        r = ops.kill_process(42, psutil_mod=_FakePs({}))
        self.assertEqual(r["code"], "PROCESS_GONE")

    def test_stale_image(self):
        r = ops.kill_process(42, expected_image="notepad.exe",
                             psutil_mod=_FakePs({42: {"name": "calc.exe", "ct": 100.0}}))
        self.assertEqual(r["code"], "STALE_TARGET")

    def test_stale_start_time(self):
        r = ops.kill_process(42, expected_image="notepad.exe", process_start_time=50.0,
                             psutil_mod=_FakePs({42: {"name": "notepad.exe", "ct": 100.0}}))
        self.assertEqual(r["code"], "STALE_TARGET")

    def test_iso_start_time_and_tree(self):
        ps = _FakePs({42: {"name": "notepad.exe", "ct": 100.0, "children": [43]},
                      43: {"name": "child.exe", "ct": 101.0}})
        r = ops.kill_process(42, expected_image="NOTEPAD.EXE",
                             process_start_time="1970-01-01T00:01:40+00:00", tree=True, psutil_mod=ps)
        self.assertTrue(r["ok"], r)
        self.assertEqual(sorted(r["data"]["killed"]), [42, 43])

    def test_protected(self):
        r = ops.kill_process(42, protected_names={"lsass.exe"},
                             psutil_mod=_FakePs({42: {"name": "lsass.exe", "ct": 1.0}}))
        self.assertEqual(r["code"], "PROTECTED_PROCESS")
        self.assertEqual(ops.kill_process(4)["code"], "PROTECTED_PROCESS")


class FakeSvc:
    def __init__(self, states, deps=None, stuck=None):
        self.states = dict(states)
        self.deps = deps or {}
        self.stuck = set(stuck or [])
        self.calls = []

    def state(self, n):
        if n not in self.states:
            raise _WinErr(1060)
        return self.states[n]

    def stop(self, n):
        self.calls.append(("stop", n))
        if n not in self.stuck:
            self.states[n] = ops.SVC_STOPPED

    def start(self, n):
        self.calls.append(("start", n))
        self.states[n] = ops.SVC_RUNNING

    def active_dependents(self, n):
        return [d for d in self.deps.get(n, []) if self.states.get(d) == ops.SVC_RUNNING]


class _Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t

    def sleep(self, s):
        self.t += s


class TestRestartService(unittest.TestCase):
    def test_with_dependents(self):
        svc = FakeSvc({"TermService": 4, "UmRdpService": 4}, deps={"TermService": ["UmRdpService"]})
        r = ops.restart_service("TermService", svc=svc)
        self.assertTrue(r["ok"], r)
        self.assertEqual(svc.calls, [("stop", "UmRdpService"), ("stop", "TermService"),
                                     ("start", "TermService"), ("start", "UmRdpService")])
        self.assertEqual([s["step"] for s in r["steps"]],
                         ["query", "stop_dependent", "stop", "start", "start_dependent"])

    def test_stop_timeout(self):
        c = _Clock()
        svc = FakeSvc({"Spooler": 4}, stuck={"Spooler"})
        r = ops.restart_service("Spooler", svc=svc, timeout=3, sleep=c.sleep, clock=c)
        self.assertEqual(r["code"], "STOP_TIMEOUT")

    def test_not_found_and_protected(self):
        self.assertEqual(ops.restart_service("X", svc=FakeSvc({}))["code"], "SERVICE_NOT_FOUND")
        self.assertEqual(ops.restart_service("WinDefend", svc=FakeSvc({}), protected={"windefend"})["code"],
                         "PROTECTED_SERVICE")


class FakeWts:
    def __init__(self, sessions, sticky=()):
        self.sessions = {s["session_id"]: dict(s) for s in sessions}
        self.sticky = set(sticky)
        self.logged = []

    def enumerate(self):
        return list(self.sessions.values())

    def logoff(self, sid):
        self.logged.append(sid)
        if sid not in self.sticky:
            self.sessions.pop(sid, None)
        return True


SESS = [
    {"session_id": 0, "station": "Services", "state": "Disconnected", "username": ""},
    {"session_id": 1, "station": "Console", "state": "Active", "username": "caksac"},
    {"session_id": 2, "station": "RDP-Tcp#1", "state": "Active", "username": "logo"},
    {"session_id": 65536, "station": "RDP-Tcp", "state": "Listen", "username": ""},
]


class TestLogoff(unittest.TestCase):
    def test_single(self):
        w = FakeWts(SESS)
        r = ops.logoff_session(2, wts=w, protected_ids={0})
        self.assertTrue(r["ok"], r)
        self.assertEqual(r["data"]["sessions"], [2])

    def test_all_excludes_protected(self):
        w = FakeWts(SESS)
        r = ops.logoff_session("all", wts=w, protected_ids={0})
        self.assertTrue(r["ok"])
        self.assertEqual(sorted(w.logged), [1, 2])

    def test_by_username(self):
        w = FakeWts(SESS)
        r = ops.logoff_session("LOGO", wts=w, protected_ids={0})
        self.assertEqual(w.logged, [2])
        self.assertTrue(r["ok"])

    def test_verify_fails(self):
        c = _Clock()
        w = FakeWts(SESS, sticky={2})
        r = ops.logoff_session(2, wts=w, protected_ids={0}, verify_timeout=3, sleep=c.sleep, clock=c)
        self.assertFalse(r["ok"])
        self.assertEqual(r["code"], "LOGOFF_FAILED")

    def test_protected(self):
        r = ops.logoff_session(0, wts=FakeWts(SESS), protected_ids={0})
        self.assertFalse(r["ok"])


class _R:
    def __init__(self, rc, out=""):
        self.returncode = rc
        self.stdout = out
        self.stderr = ""


class TestReboot(unittest.TestCase):
    def test_scheduled_and_marker(self):
        with tempfile.TemporaryDirectory() as d:
            mp = os.path.join(d, "m.json")
            r = ops.schedule_reboot(30, "t", command_id="c1", runner=lambda *a, **k: _R(0),
                                    marker_path=mp, boot_time=lambda: 1000.0)
            self.assertTrue(r["ok"])
            self.assertEqual(r["code"], "SCHEDULED")
            self.assertIsNone(ops.consume_reboot_marker(mp, boot_time=lambda: 1000.0))
            info = ops.consume_reboot_marker(mp, boot_time=lambda: 5000.0)
            self.assertEqual(info["command_id"], "c1")
            self.assertTrue(info["rebooted"])
            self.assertFalse(os.path.exists(mp))

    def test_exit_code_checked(self):
        r = ops.schedule_reboot(30, "t", runner=lambda *a, **k: _R(5), marker_path=os.devnull)
        self.assertFalse(r["ok"])
        self.assertEqual(r["code"], "ACCESS_DENIED")
        r = ops.schedule_reboot(30, "t", runner=lambda *a, **k: _R(1190), marker_path=os.devnull)
        self.assertEqual(r["code"], "ALREADY_SCHEDULED")


class TestExecutorIsolation(unittest.TestCase):
    def setUp(self):
        from client_remote_commands import RemoteCommandExecutor
        self.ex = RemoteCommandExecutor(api_client=None, token_getter=lambda: "")

    def test_handler_timeout_releases(self):
        import client_remote_commands as crc
        with mock.patch.dict(crc._HANDLER_TIMEOUTS, {"list_sessions": 0.3}):
            with mock.patch.object(self.ex, "_cmd_list_sessions",
                                   side_effect=lambda p: time.sleep(5) or {"success": True}):
                t0 = time.time()
                r = self.ex._execute({"command_type": "list_sessions", "params": {}})
        self.assertLess(time.time() - t0, 2.0)
        self.assertEqual(r["code"], "TIMEOUT")

    def test_rd_command_does_not_hold_admin_lock(self):
        self.ex._running = True
        gate = threading.Event()
        try:
            with mock.patch.object(self.ex, "_validate", return_value=None), \
                 mock.patch.object(self.ex, "_cmd_remote_stream_start",
                                   side_effect=lambda p: gate.wait(3) or {"success": True}), \
                 mock.patch.object(self.ex, "_cmd_list_sessions", return_value={"success": True}):
                self.ex.handle_incoming_command(
                    {"command_id": "rd1", "command_type": "remote_stream_start", "params": {}})
                time.sleep(0.2)
                t0 = time.time()
                out = self.ex.handle_incoming_command(
                    {"command_id": "a1", "command_type": "list_sessions", "params": {}})
                self.assertLess(time.time() - t0, 1.0)
                self.assertTrue(out["ok"])
        finally:
            gate.set()
            self.ex._running = False


if __name__ == "__main__":
    unittest.main()
