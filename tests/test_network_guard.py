"""Unit tests for Network Guard (contract >=4.7.0 — agent/network-guard.md)."""

import os
import sys
import json
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import client_network_guard as ng


class TestScoring(unittest.TestCase):
    def test_canary_is_max(self):
        self.assertEqual(ng.score_signals(False, False, False, canary=True), 100)

    def test_net_cut_plus_storm_triggers(self):
        # net_cut + fs_storm should clear the default 70 threshold
        s = ng.score_signals(net_cut=True, fs_storm=True, suspicious_origin=False)
        self.assertGreaterEqual(s, 70)

    def test_single_signal_below_threshold(self):
        self.assertLess(ng.score_signals(net_cut=True, fs_storm=False,
                                         suspicious_origin=False), 70)
        self.assertLess(ng.score_signals(net_cut=False, fs_storm=True,
                                         suspicious_origin=False), 70)

    def test_storm_plus_origin_triggers(self):
        s = ng.score_signals(net_cut=False, fs_storm=True, suspicious_origin=True)
        self.assertGreaterEqual(s, 65)

    def test_capped_at_100(self):
        self.assertEqual(ng.score_signals(True, True, True, True, False), 100)


class TestConnectivityDiff(unittest.TestCase):
    def test_internet_lost_flagged(self):
        base = {"connectivity": {"internet_ok": True}, "adapters": []}
        cur = {"internet_ok": False, "_adapters": []}
        d = ng.diff_connectivity(base, cur)
        self.assertTrue(d["internet_lost"])
        self.assertTrue(d["net_cut"])

    def test_no_cut_when_still_online(self):
        base = {"connectivity": {"internet_ok": True}, "adapters": []}
        cur = {"internet_ok": True, "_adapters": []}
        d = ng.diff_connectivity(base, cur)
        self.assertFalse(d["net_cut"])


class TestRestorePlan(unittest.TestCase):
    def test_dry_run_plan_is_pure_and_bounded(self):
        baseline = {
            "adapters": [{
                "name": "Ethernet", "state": "up",
                "dns": ["1.1.1.1", "8.8.8.8"],
            }],
            "firewall": {"domain": "on", "private": "on", "public": "off"},
            "mapped_drives": [{
                "letter": "Z:", "unc": r"\\server\share", "persistent": True,
            }],
        }
        plan = ng.plan_network_restore(baseline)
        self.assertTrue(any(item["target"] == "adapter" for item in plan))
        self.assertTrue(any(item["target"] == "dns" for item in plan))
        self.assertTrue(any(item["target"] == "firewall" for item in plan))
        self.assertTrue(any(item["target"] == "mapped_drive" for item in plan))
        self.assertLessEqual(len(plan), 128)

    def test_target_filter_only_plans_requested_area(self):
        baseline = {
            "adapters": [{"name": "Ethernet", "state": "up", "dns": ["1.1.1.1"]}],
            "firewall": {"domain": "on"},
            "mapped_drives": [],
        }
        plan = ng.plan_network_restore(baseline, targets=["dns"])
        self.assertEqual({item["target"] for item in plan}, {"dns"})

    def test_adapter_down_reported_but_not_cut_when_online(self):
        base = {"connectivity": {"internet_ok": True},
                "adapters": [{"name": "Ethernet", "state": "up"}]}
        cur = {"internet_ok": True,
               "_adapters": [{"name": "Ethernet", "state": "disabled"}]}
        d = ng.diff_connectivity(base, cur)
        self.assertIn("Ethernet", d["adapters_down"])
        # adapter-down is informational only; net_cut requires internet loss
        self.assertFalse(d["net_cut"])

    def test_adapter_down_with_internet_loss_is_cut(self):
        base = {"connectivity": {"internet_ok": True},
                "adapters": [{"name": "Ethernet", "state": "up"}]}
        cur = {"internet_ok": False,
               "_adapters": [{"name": "Ethernet", "state": "disabled"}]}
        d = ng.diff_connectivity(base, cur)
        self.assertTrue(d["net_cut"])

    def test_no_baseline_is_safe(self):
        d = ng.diff_connectivity(None, {"internet_ok": True, "_adapters": []})
        self.assertFalse(d["net_cut"])

    def test_online_with_no_adapter_snapshot_is_not_cut(self):
        # Regression: internet up + _adapters None must NOT flag every baseline
        # adapter as down (this froze Chrome/Cursor/GameLoop in 4.7.0/4.7.1).
        base = {"connectivity": {"internet_ok": True},
                "adapters": [{"name": "Wi-Fi", "state": "up"},
                             {"name": "Radmin VPN", "state": "up"}]}
        cur = {"internet_ok": True, "_adapters": None}
        d = ng.diff_connectivity(base, cur)
        self.assertFalse(d["net_cut"])
        self.assertEqual(d["adapters_down"], [])

    def test_adapter_churn_without_internet_loss_is_not_cut(self):
        # Adapter down but internet still reachable => not a ransomware signal.
        base = {"connectivity": {"internet_ok": True},
                "adapters": [{"name": "Wi-Fi", "state": "up"}]}
        cur = {"internet_ok": True,
               "_adapters": [{"name": "Wi-Fi", "state": "disconnected"}]}
        d = ng.diff_connectivity(base, cur)
        self.assertFalse(d["net_cut"])
        self.assertIn("Wi-Fi", d["adapters_down"])


class TestBaselineDiff(unittest.TestCase):
    def test_first_baseline_is_change(self):
        self.assertTrue(ng._baseline_meaningful_change(None, {"mapped_drives": []}))

    def test_same_topology_no_change(self):
        a = {"mapped_drives": [{"letter": "Z:"}], "shares": [], "adapters": [],
             "firewall": {"domain": "on"}}
        b = dict(a)
        self.assertFalse(ng._baseline_meaningful_change(a, b))

    def test_new_mapped_drive_is_change(self):
        a = {"mapped_drives": [], "shares": [], "adapters": [], "firewall": {}}
        b = {"mapped_drives": [{"letter": "Z:"}], "shares": [], "adapters": [],
             "firewall": {}}
        self.assertTrue(ng._baseline_meaningful_change(a, b))


class TestSigning(unittest.TestCase):
    def test_sign_verify_round_trip(self):
        with mock.patch.object(ng, "_read_token", return_value="tok-123"):
            payload = {"version": 1, "mapped_drives": [], "adapters": []}
            payload["sig"] = ng._sign_baseline(payload)
            self.assertTrue(ng.verify_baseline(payload))

    def test_tamper_breaks_signature(self):
        with mock.patch.object(ng, "_read_token", return_value="tok-123"):
            payload = {"version": 1, "mapped_drives": []}
            payload["sig"] = ng._sign_baseline(payload)
            payload["mapped_drives"] = [{"letter": "X:", "unc": "\\\\evil\\s"}]
            self.assertFalse(ng.verify_baseline(payload))

    def test_missing_sig_is_invalid(self):
        self.assertFalse(ng.verify_baseline({"version": 1}))


class TestSaveBaselineRotation(unittest.TestCase):
    def test_version_bumps_and_persists(self):
        with tempfile.TemporaryDirectory() as d:
            bfile = os.path.join(d, "network_baseline.json")
            hdir = os.path.join(d, "history")
            with mock.patch.object(ng, "BASELINE_FILE", bfile), \
                 mock.patch.object(ng, "BASELINE_HISTORY_DIR", hdir), \
                 mock.patch.object(ng, "MACHINE_DATA_DIR", d), \
                 mock.patch.object(ng, "_read_token", return_value="t"):
                p1 = ng.save_baseline({"mapped_drives": [], "shares": [],
                                       "adapters": [], "firewall": {"domain": "on"},
                                       "connectivity": {}})
                self.assertEqual(p1["version"], 1)
                # topology change -> version 2
                p2 = ng.save_baseline({"mapped_drives": [{"letter": "Z:"}],
                                       "shares": [], "adapters": [],
                                       "firewall": {"domain": "on"},
                                       "connectivity": {}})
                self.assertEqual(p2["version"], 2)
                loaded = ng.load_baseline()
                self.assertEqual(loaded["version"], 2)
                self.assertTrue(ng.verify_baseline(loaded))


class TestConfig(unittest.TestCase):
    def test_defaults_are_safe(self):
        # SAFETY: process auto-actions OFF; network-surface restore ON (1.4.14)
        c = ng.load_config(None)
        self.assertTrue(c["enabled"])
        self.assertFalse(c["auto_contain"])
        self.assertFalse(c["auto_kill"])
        self.assertFalse(c["auto_restore"])
        self.assertTrue(c["auto_restore_network"])
        self.assertTrue(c["require_strong_signal"])

    def test_override_from_client_config(self):
        c = ng.load_config({"protection": {"network_guard": {
            "auto_contain": True, "score_threshold": 90,
            "auto_restore_network": False, "bogus": 1}}})
        # Without fleet canary gate, config cannot enable auto containment (fail-closed).
        self.assertFalse(c["auto_contain"])
        self.assertEqual(c["score_threshold"], 90)
        self.assertFalse(c["auto_restore_network"])
        self.assertNotIn("bogus", c)


class TestStatus(unittest.TestCase):
    def test_status_shape(self):
        guard = ng.NetworkGuard(config=ng.load_config(None))
        guard._last_baseline = {
            "version": 3,
            "mapped_drives": [{"letter": "Z:"}],
            "adapters": [],
            "firewall": {"domain": "on", "private": "on", "public": "on"},
            "connectivity": {"internet_ok": True},
            "captured_at": "2026-07-21T00:00:00+00:00",
            "sig": "x",
        }
        with mock.patch.object(ng, "collect_adapters", return_value=[]), \
             mock.patch.object(ng, "collect_mapped_drives", return_value=[]), \
             mock.patch.object(ng, "collect_firewall", return_value={
                 "domain": "on", "private": "on", "public": "on"}), \
             mock.patch.object(ng, "check_connectivity", return_value={
                 "internet_ok": True, "dns_ok": True, "gateway_ok": True}), \
             mock.patch.object(ng, "verify_baseline", return_value=True):
            st = guard.status()
        self.assertEqual(st["baseline_version"], 3)
        self.assertTrue(st["internet_ok"])
        self.assertFalse(st["auto_kill"])
        self.assertFalse(st["auto_contain"])
        self.assertTrue(st["auto_restore_network"])
        self.assertEqual(st["suspended_processes"], 0)
        self.assertIn("live", st)
        self.assertIn("baseline", st)
        # STATUS must not require live collectors (cache may be empty)
        self.assertEqual(st.get("live", {}).get("adapters"), [])


class TestSurfaceDiff(unittest.TestCase):
    def test_dns_drift_detected(self):
        base = {
            "adapters": [{
                "name": "Wi-Fi", "state": "up", "ipv4": "192.168.1.30",
                "dns": ["1.1.1.1"], "dhcp": True,
            }],
            "mapped_drives": [],
            "firewall": {"domain": "on", "private": "on", "public": "on"},
        }
        live = [{
            "name": "Wi-Fi", "state": "up", "ipv4": "192.168.1.30",
            "dns": ["8.8.8.8"], "dhcp": True,
        }]
        changes = ng.diff_network_surface(
            base, live_adapters=live, live_drives=[],
            live_firewall=base["firewall"],
        )
        self.assertTrue(any(c["target"] == "dns" for c in changes))

    def test_plan_includes_ipv4_dhcp(self):
        baseline = {
            "adapters": [{
                "name": "Wi-Fi", "state": "up", "dns": ["1.1.1.1"], "dhcp": True,
            }],
            "firewall": {},
            "mapped_drives": [],
        }
        plan = ng.plan_network_restore(baseline, targets=["ipv4"])
        self.assertEqual(plan[0]["action"], "dhcp")


class TestMaintenance(unittest.TestCase):
    def test_enter_exit_persists(self):
        with tempfile.TemporaryDirectory() as d:
            mfile = os.path.join(d, "maint.json")
            with mock.patch.object(ng, "MAINTENANCE_FILE", mfile), \
                 mock.patch.object(ng, "MACHINE_DATA_DIR", d):
                self.assertFalse(ng.get_maintenance()["active"])
                ng.set_maintenance(True, reason="test", paused_by="unit")
                self.assertTrue(ng.get_maintenance()["active"])
                guard = ng.NetworkGuard(config=ng.load_config(None))
                with mock.patch.object(guard, "stop") as st:
                    out = guard.enter_maintenance(reason="vpn", paused_by="gui")
                st.assert_called()
                self.assertTrue(out["maintenance"])
                with mock.patch.object(ng, "save_baseline", return_value={
                    "version": 99, "captured_at": "t",
                }), mock.patch.object(ng, "capture_baseline", return_value={}), \
                     mock.patch.object(guard, "start") as start:
                    out2 = guard.exit_maintenance(snapshot=True, paused_by="gui")
                start.assert_called()
                self.assertFalse(ng.get_maintenance()["active"])
                self.assertEqual(out2.get("baseline_version"), 99)

    def test_start_blocked_during_maintenance(self):
        with tempfile.TemporaryDirectory() as d:
            mfile = os.path.join(d, "maint.json")
            with mock.patch.object(ng, "MAINTENANCE_FILE", mfile), \
                 mock.patch.object(ng, "MACHINE_DATA_DIR", d):
                ng.set_maintenance(True, paused_by="gui")
                guard = ng.NetworkGuard(config=ng.load_config(None))
                guard.start()
                self.assertFalse(guard._running)


class TestCommandWhitelist(unittest.TestCase):
    def test_network_commands_registered(self):
        from client_remote_commands import (
            ALLOWED_COMMANDS, REQUIRES_CONFIRMATION,
        )
        for c in ("network_snapshot", "network_restore", "list_network_baseline",
                  "network_diff", "network_maintenance_start",
                  "network_maintenance_end", "network_accept_surface",
                  "network_disable_adapter"):
            self.assertIn(c, ALLOWED_COMMANDS)
        self.assertIn("network_restore", REQUIRES_CONFIRMATION)
        self.assertIn("network_disable_adapter", REQUIRES_CONFIRMATION)
        # read-only snapshot/list must NOT require confirmation
        self.assertNotIn("network_snapshot", REQUIRES_CONFIRMATION)
        self.assertNotIn("network_accept_surface", REQUIRES_CONFIRMATION)
        self.assertNotIn("list_network_baseline", REQUIRES_CONFIRMATION)
        self.assertNotIn("network_diff", REQUIRES_CONFIRMATION)

    def test_handlers_exist(self):
        from client_remote_commands import RemoteCommandExecutor
        ex = RemoteCommandExecutor(token_getter=lambda: "")
        for c in ("network_snapshot", "network_restore", "list_network_baseline",
                  "network_diff", "network_maintenance_start",
                  "network_maintenance_end", "network_accept_surface",
                  "network_disable_adapter"):
            self.assertTrue(hasattr(ex, f"_cmd_{c}"), c)


class TestSurfaceInform(unittest.TestCase):
    """Contract 1.4.17 — additive inform must not feed auto_restore."""

    def test_ethernet_up_is_inform_not_drift(self):
        base = {
            "adapters": [
                {"name": "Wi-Fi", "state": "up", "ipv4": "192.168.1.30",
                 "dhcp": True, "dns": ["1.1.1.1"]},
                {"name": "Ethernet", "state": "disconnected",
                 "ipv4": "169.254.1.1", "dhcp": True, "dns": []},
            ],
            "mapped_drives": [],
            "firewall": {"domain": "on", "private": "on", "public": "on"},
        }
        live = [
            {"name": "Wi-Fi", "state": "up", "ipv4": "192.168.1.30",
             "dhcp": True, "dns": ["1.1.1.1"]},
            {"name": "Ethernet", "state": "up", "ipv4": "192.168.1.21",
             "dhcp": True, "dns": ["1.1.1.1"]},
        ]
        drift = ng.diff_network_surface(
            base, live_adapters=live, live_drives=[], live_firewall=base["firewall"],
        )
        inform = ng.diff_network_surface_inform(base, live_adapters=live)
        self.assertEqual(drift, [])
        self.assertTrue(any(c.get("kind") == "adapter_enabled" for c in inform))
        self.assertTrue(any(c.get("interface") == "Ethernet" for c in inform))

    def test_dhcp_lease_change_inform_only(self):
        base = {
            "adapters": [
                {"name": "Wi-Fi", "state": "up", "ipv4": "192.168.1.30",
                 "dhcp": True, "dns": ["1.1.1.1"]},
            ],
            "mapped_drives": [],
            "firewall": {"private": "on"},
        }
        live = [
            {"name": "Wi-Fi", "state": "up", "ipv4": "192.168.1.55",
             "dhcp": True, "dns": ["1.1.1.1"]},
        ]
        drift = ng.diff_network_surface(
            base, live_adapters=live, live_drives=[], live_firewall=base["firewall"],
        )
        inform = ng.diff_network_surface_inform(base, live_adapters=live)
        self.assertEqual(drift, [])
        self.assertTrue(any(c.get("kind") == "dhcp_lease" for c in inform))

    def test_adapter_down_still_subtractive_drift(self):
        base = {
            "adapters": [
                {"name": "Ethernet", "state": "up", "ipv4": "192.168.1.21",
                 "dhcp": True, "dns": ["1.1.1.1"]},
            ],
            "mapped_drives": [],
            "firewall": {"private": "on"},
        }
        live = [
            {"name": "Ethernet", "state": "disconnected", "ipv4": "169.254.1.1",
             "dhcp": True, "dns": ["1.1.1.1"]},
        ]
        drift = ng.diff_network_surface(
            base, live_adapters=live, live_drives=[], live_firewall=base["firewall"],
        )
        inform = ng.diff_network_surface_inform(base, live_adapters=live)
        self.assertTrue(any(c.get("id") == "adapter.Ethernet" for c in drift))
        self.assertEqual(inform, [])

    def test_inform_alert_is_soft(self):
        sent = []

        class _Pipe:
            def handle_alert(self, a):
                sent.append(a)

        guard = ng.NetworkGuard(alert_pipeline=_Pipe(), config=ng.load_config(None))
        guard._emit_surface_inform([
            {"id": "adapter_up.Ethernet", "kind": "adapter_enabled",
             "interface": "Ethernet", "ipv4": "192.168.1.21"},
        ])
        self.assertEqual(len(sent), 1)
        a = sent[0]
        self.assertEqual(a["threat_type"], "network_surface_changed")
        self.assertEqual(a["severity"], "info")
        self.assertFalse(a.get("force_urgent"))


class TestTriggerFlow(unittest.TestCase):
    def _mk(self, cfg_over=None):
        sent = []

        class _Pipe:
            def send_urgent(self, a):
                sent.append(a)

        cfg = ng.load_config(None)
        if cfg_over:
            cfg.update(cfg_over)
        return ng.NetworkGuard(alert_pipeline=_Pipe(), config=cfg), sent

    def _suspects(self):
        return [{"pid": 4242, "image": "invoice.exe",
                 "path": "C:\\Users\\Public\\invoice.exe",
                 "cmdline": "invoice.exe", "suspicious_origin": True}]

    def test_default_is_alert_only_no_suspend(self):
        # SAFETY regression: default config must NEVER freeze a process.
        guard, sent = self._mk()
        netdiff = {"internet_lost": True, "adapters_down": [], "net_cut": True}
        with mock.patch.object(guard, "_suspend_pid", return_value=True) as sp, \
             mock.patch.object(guard, "_emergency_vss", return_value=True) as vss:
            guard._trigger("network_cut+fs_storm", 90, netdiff, self._suspects(),
                           baseline={"adapters": []}, strong=False)
        sp.assert_not_called()
        vss.assert_not_called()
        self.assertEqual(len(sent), 1)
        alert = sent[0]
        self.assertEqual(alert["threat_type"], "ransomware_offline_suspect")
        self.assertEqual(alert["severity"], "warning")
        self.assertEqual(alert["system_context"]["network_guard"]["suspects"][0]["state"],
                         "observed")
        self.assertEqual(alert["auto_response_taken"], ["alert_only"])

    def test_auto_contain_requires_strong_signal(self):
        # auto_contain enabled but no strong signal => still alert-only.
        guard, sent = self._mk({"auto_contain": True})
        netdiff = {"internet_lost": True, "adapters_down": [], "net_cut": True}
        with mock.patch.object(guard, "_suspend_pid", return_value=True) as sp:
            guard._trigger("network_cut+fs_storm", 90, netdiff, self._suspects(),
                           baseline={"adapters": []}, strong=False)
        sp.assert_not_called()
        self.assertEqual(sent[0]["threat_type"], "ransomware_offline_suspect")

    def test_even_strong_signal_needs_operator_command(self):
        guard, sent = self._mk({"auto_contain": True, "auto_restore": True})
        netdiff = {"internet_lost": True, "adapters_down": ["Ethernet"],
                   "net_cut": True}
        with mock.patch.object(guard, "_suspend_pid", return_value=True) as sp, \
             mock.patch.object(guard, "_emergency_vss", return_value=True) as vss, \
             mock.patch.object(guard, "restore_network",
                               return_value={"restore_actions": ["adapter_enable:Ethernet"]}) as restore:
            guard._trigger("network_cut+fs_storm", 90, netdiff, self._suspects(),
                           baseline={"adapters": []}, strong=True)
        sp.assert_not_called()
        vss.assert_not_called()
        restore.assert_not_called()
        alert = sent[0]
        self.assertEqual(alert["threat_type"], "ransomware_offline_suspect")
        self.assertEqual(alert["severity"], "warning")
        ngc = alert["system_context"]["network_guard"]
        self.assertFalse(ngc["auto_contain"])
        self.assertFalse(ngc["network"]["restored"])
        self.assertEqual(ngc["suspects"][0]["state"], "observed")
        self.assertFalse(ngc["vss_emergency_snapshot"])

    def test_trigger_debounced(self):
        guard, sent = self._mk()
        netdiff = {"internet_lost": True, "adapters_down": [], "net_cut": True}
        guard._trigger("fs_storm", 90, netdiff, self._suspects(),
                       baseline={"adapters": []}, strong=False)
        guard._trigger("fs_storm", 90, netdiff, self._suspects(),
                       baseline={"adapters": []}, strong=False)
        self.assertEqual(len(sent), 1)  # same trigger+pid dedupe ≥5 min


class TestRestoreRollback(unittest.TestCase):
    def test_missing_rollback_version_fails_closed(self):
        guard = ng.NetworkGuard(config={})
        with mock.patch.object(ng, "load_baseline_version", return_value=None):
            result = guard.restore_network(rollback_version=9)
        self.assertEqual(result["error"], "rollback_baseline_not_found_or_invalid")

    def test_rollback_version_uses_signed_retained_baseline(self):
        guard = ng.NetworkGuard(config={})
        baseline = {
            "version": 3,
            "adapters": [],
            "firewall": {},
            "mapped_drives": [],
            "hmac": "x",
        }
        with mock.patch.object(ng, "load_baseline_version", return_value=baseline) as load, \
                mock.patch.object(ng, "verify_baseline", return_value=True), \
                mock.patch.object(ng, "check_connectivity",
                                  return_value={"internet_ok": True}):
            result = guard.restore_network(
                rollback_version=3, dry_run=True, targets=["firewall"]
            )
        load.assert_called_once_with(3)
        self.assertTrue(result["dry_run"])
        self.assertEqual(result["baseline_version"], 3)
        self.assertEqual(result["restore_actions"], [])


if __name__ == "__main__":
    unittest.main()
