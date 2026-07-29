#!/usr/bin/env python3
"""Network adapter apply + golden watchdog (contract 1.4.42)."""

import unittest
from unittest import mock

from client_network_guard import (
    NetworkGuard,
    clamp_watchdog_sec,
    is_last_mgmt_adapter,
    probe_mode_ok,
)
from client_remote_commands import (
    ALLOWED_COMMANDS,
    REQUIRES_CONFIRMATION,
    RemoteCommandExecutor,
)


class TestHelpers(unittest.TestCase):
    def test_clamp_watchdog(self):
        self.assertEqual(clamp_watchdog_sec(10), 10)
        self.assertEqual(clamp_watchdog_sec(1), 5)
        self.assertEqual(clamp_watchdog_sec(99), 15)
        self.assertEqual(clamp_watchdog_sec(None), 10)

    def test_probe_modes(self):
        ok = {"internet_ok": True, "gateway_ok": True, "dns_ok": True}
        bad = {"internet_ok": False, "gateway_ok": True, "dns_ok": False}
        self.assertTrue(probe_mode_ok(ok, "internet"))
        self.assertFalse(probe_mode_ok(bad, "internet"))
        self.assertTrue(probe_mode_ok(bad, "gateway"))
        self.assertFalse(probe_mode_ok(bad, "internet_and_gateway"))

    def test_last_mgmt(self):
        live = [
            {"name": "Ethernet", "state": "up", "gateway": "192.168.1.1"},
            {"name": "Wi-Fi", "state": "down", "gateway": ""},
        ]
        self.assertTrue(is_last_mgmt_adapter("Ethernet", live))
        self.assertFalse(is_last_mgmt_adapter("Wi-Fi", live))
        live2 = live + [
            {"name": "VPN", "state": "up", "gateway": "10.0.0.1"},
        ]
        self.assertFalse(is_last_mgmt_adapter("Ethernet", live2))


class TestAdapterApply(unittest.TestCase):
    def setUp(self):
        self.guard = NetworkGuard(config={"enabled": True, "auto_restore_network": True})
        self.golden = {
            "version": 12,
            "sig": "x",
            "connectivity": {"internet_ok": True, "dns_ok": True, "gateway_ok": True},
            "adapters": [
                {
                    "name": "Ethernet",
                    "state": "up",
                    "ipv4": "192.168.1.10",
                    "gateway": "192.168.1.1",
                    "dns": ["1.1.1.1"],
                    "dhcp": False,
                    "prefix_length": 24,
                }
            ],
        }

    def test_no_golden(self):
        with mock.patch("client_network_guard.load_baseline", return_value=None):
            out = self.guard.adapter_apply({"adapter": "Ethernet", "op": "enable"})
        self.assertEqual(out["error"], "NO_GOLDEN")

    def test_golden_unhealthy(self):
        bad = dict(self.golden)
        bad["connectivity"] = {"internet_ok": False}
        with mock.patch("client_network_guard.load_baseline", return_value=bad), mock.patch(
            "client_network_guard.verify_baseline", return_value=True
        ):
            out = self.guard.adapter_apply({"adapter": "Ethernet", "op": "enable"})
        self.assertEqual(out["error"], "GOLDEN_UNHEALTHY")

    def test_last_mgmt_refuse(self):
        with mock.patch("client_network_guard.load_baseline", return_value=self.golden), mock.patch(
            "client_network_guard.verify_baseline", return_value=True
        ), mock.patch(
            "client_network_guard.collect_adapters",
            return_value=[{
                "name": "Ethernet", "state": "up", "gateway": "192.168.1.1",
            }],
        ):
            out = self.guard.adapter_apply({"adapter": "Ethernet", "op": "disable"})
        self.assertEqual(out["error"], "LAST_MGMT_ADAPTER")
        self.assertFalse(out.get("applied"))

    def test_success_keep(self):
        with mock.patch("client_network_guard.load_baseline", return_value=self.golden), mock.patch(
            "client_network_guard.verify_baseline", return_value=True
        ), mock.patch(
            "client_network_guard.collect_adapters",
            return_value=[{
                "name": "Ethernet", "state": "up",
                "ipv4": "192.168.1.50", "gateway": "192.168.1.1",
                "dns": ["1.1.1.1", "8.8.8.8"], "dhcp": False, "prefix_length": 24,
            }],
        ), mock.patch.object(
            self.guard, "_adapter_apply_mutate", return_value=None
        ), mock.patch.object(
            self.guard, "_adapter_apply_watchdog",
            return_value={
                "mode": "internet", "ok": True,
                "internet_ok": True, "dns_ok": True, "gateway_ok": True,
                "elapsed_ms": 500,
            },
        ):
            out = self.guard.adapter_apply({
                "adapter": "Ethernet",
                "op": "set_config",
                "ipv4": {
                    "dhcp": False, "address": "192.168.1.50",
                    "prefix_length": 24, "gateway": "192.168.1.1",
                },
                "dns": ["1.1.1.1", "8.8.8.8"],
                "watchdog_sec": 10,
                "on_success": "keep",
            })
        self.assertTrue(out["ok"])
        self.assertTrue(out["applied"])
        self.assertFalse(out["rolled_back"])
        self.assertEqual(out["golden_version"], 12)
        self.assertEqual(out["live_adapter"]["ipv4"], "192.168.1.50")

    def test_watchdog_rollback(self):
        with mock.patch("client_network_guard.load_baseline", return_value=self.golden), mock.patch(
            "client_network_guard.verify_baseline", return_value=True
        ), mock.patch(
            "client_network_guard.collect_adapters",
            return_value=[{
                "name": "Ethernet", "state": "up", "gateway": "192.168.1.1",
                "ipv4": "10.0.0.1",
            }, {
                "name": "Wi-Fi", "state": "up", "gateway": "10.0.0.1",
            }],
        ), mock.patch.object(
            self.guard, "_adapter_apply_mutate", return_value=None
        ), mock.patch.object(
            self.guard, "_adapter_apply_watchdog",
            return_value={
                "mode": "internet", "ok": False,
                "internet_ok": False, "dns_ok": False, "gateway_ok": False,
                "elapsed_ms": 10050,
            },
        ), mock.patch.object(
            self.guard, "restore_network",
            return_value={"restore_actions": ["ipv4_static:Ethernet", "dns_restore:Ethernet"]},
        ) as restore, mock.patch.object(
            self.guard, "_emit_adapter_apply_rolled_back"
        ) as emit:
            out = self.guard.adapter_apply({
                "adapter": "Ethernet",
                "op": "set_ipv4",
                "ipv4": {"dhcp": False, "address": "10.0.0.1", "prefix_length": 24},
                "watchdog_sec": 10,
            })
        self.assertFalse(out["ok"])
        self.assertEqual(out["error"], "WATCHDOG_ROLLBACK")
        self.assertTrue(out["rolled_back"])
        restore.assert_called_once()
        kwargs = restore.call_args.kwargs
        self.assertEqual(kwargs.get("adapter_names"), ["Ethernet"])
        self.assertEqual(set(kwargs.get("targets") or []), {"adapter", "ipv4", "dns"})
        emit.assert_called_once()

    def test_accept_surface_on_success(self):
        with mock.patch("client_network_guard.load_baseline", return_value=self.golden), mock.patch(
            "client_network_guard.verify_baseline", return_value=True
        ), mock.patch(
            "client_network_guard.collect_adapters",
            return_value=[{"name": "Ethernet", "state": "up", "gateway": "1.1"}],
        ), mock.patch.object(
            self.guard, "_adapter_apply_mutate", return_value=None
        ), mock.patch.object(
            self.guard, "_adapter_apply_watchdog",
            return_value={"mode": "internet", "ok": True, "internet_ok": True,
                          "dns_ok": True, "gateway_ok": True, "elapsed_ms": 100},
        ), mock.patch.object(
            self.guard, "accept_surface",
            return_value={"ok": True, "version": 13},
        ) as accept:
            out = self.guard.adapter_apply({
                "adapter": "Ethernet",
                "op": "enable",
                "on_success": "accept_surface",
            })
        self.assertTrue(out["ok"])
        accept.assert_called_once()
        self.assertEqual(out["golden_version"], 13)

    def test_pauses_auto_restore(self):
        with mock.patch("client_network_guard.load_baseline", return_value=self.golden), mock.patch(
            "client_network_guard.verify_baseline", return_value=True
        ), mock.patch(
            "client_network_guard.collect_adapters",
            return_value=[{"name": "Ethernet", "state": "up", "gateway": "1.1"}],
        ), mock.patch.object(
            self.guard, "_adapter_apply_mutate", return_value=None
        ), mock.patch.object(
            self.guard, "_adapter_apply_watchdog",
            return_value={"mode": "internet", "ok": True, "internet_ok": True,
                          "dns_ok": True, "gateway_ok": True, "elapsed_ms": 10},
        ):
            self.guard.adapter_apply({"adapter": "Ethernet", "op": "enable", "watchdog_sec": 10})
        # Cleared after success
        self.assertEqual(self.guard._adapter_apply_pause_until, 0.0)


class TestRemote(unittest.TestCase):
    def test_whitelisted(self):
        self.assertIn("network_adapter_apply", ALLOWED_COMMANDS)
        self.assertIn("network_adapter_apply", REQUIRES_CONFIRMATION)

    def test_handler(self):
        ex = RemoteCommandExecutor()
        ng = mock.Mock()
        ng.adapter_apply.return_value = {
            "ok": True, "applied": True, "rolled_back": False, "op": "enable",
            "adapter": "Ethernet",
        }
        ex.network_guard = ng
        result = ex._cmd_network_adapter_apply({"adapter": "Ethernet", "op": "enable"})
        self.assertTrue(result["success"])
        ng.adapter_apply.assert_called_once()


if __name__ == "__main__":
    unittest.main()
