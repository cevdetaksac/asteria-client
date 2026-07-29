#!/usr/bin/env python3
"""relocate_service — contract 1.4.45 close-out (C-REL-1…9)."""

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from client_remote_commands import (
    ALLOWED_COMMANDS,
    REQUIRES_CONFIRMATION,
    RemoteCommandExecutor,
    _IR_URGENT_COMMANDS,
)
from client_service_relocate import (
    DEFAULT_SAFE_PORTS,
    clamp_verify_sec,
    firewall_rule_name,
    is_forbidden_target_port,
    prefill_targets_from_tunnel,
    relocate_service,
    reserved_ports,
    resolve_service,
)


class TestDefaults(unittest.TestCase):
    def test_safe_ports_4xxxx(self):
        self.assertEqual(DEFAULT_SAFE_PORTS["RDP"], 43389)

    def test_forbid_range_and_obsolete(self):
        self.assertEqual(is_forbidden_target_port(80), "privileged_port")
        self.assertEqual(is_forbidden_target_port(53389), "FORBIDDEN_PORT_53389")
        self.assertEqual(is_forbidden_target_port(90022), "FORBIDDEN_PORT_9XXXX")
        self.assertIsNone(is_forbidden_target_port(43389))

    def test_reserved_classic(self):
        r = reserved_ports()
        self.assertIn(3389, r)
        self.assertIn(22, r)

    def test_firewall_name(self):
        self.assertEqual(firewall_rule_name("RDP", 43389), "AR-RELOCATE-RDP-43389")

    def test_prefill(self):
        out = prefill_targets_from_tunnel(
            {"relocate_state": {"RDP": {"saved_target_port": 43389}}}
        )
        self.assertEqual(out["RDP"], 43389)

    def test_clamp(self):
        self.assertEqual(clamp_verify_sec(99), 10.0)


class TestResolve(unittest.TestCase):
    def test_rdp(self):
        sid, prof, err = resolve_service({"service": "RDP"})
        self.assertIsNone(err)
        self.assertEqual(sid, "RDP")
        self.assertEqual(prof["scm"], "TermService")


class TestRelocate(unittest.TestCase):
    def setUp(self):
        self.params = {
            "service": "RDP",
            "target_port": 43389,
            "verify_sec": 3,
            "skip_precheck": True,
        }

    def test_target_port_param(self):
        """Dashboard sends target_port — must not fall back to default blindly."""
        with mock.patch("client_service_relocate.is_admin", return_value=True), mock.patch(
            "client_service_relocate._read_golden", return_value=3389
        ), mock.patch("client_service_relocate.save_golden_snapshot", return_value=True), mock.patch(
            "client_service_relocate._ensure_firewall"
        ), mock.patch(
            "client_service_relocate._write_config", return_value=True
        ), mock.patch(
            "client_service_relocate.ServiceController.stop", return_value=True
        ), mock.patch(
            "client_service_relocate.ServiceController.start", return_value=True
        ), mock.patch(
            "client_service_relocate._verify_bind", return_value=True
        ), mock.patch(
            "client_service_relocate.clear_golden_snapshot"
        ):
            out = relocate_service(
                {"service": "RDP", "target_port": 43389, "skip_precheck": True, "verify_sec": 3},
                sleep_fn=lambda *_: None,
            )
        self.assertEqual(out["status"], "ok")
        self.assertEqual(out["new_port"], 43389)
        self.assertEqual(out["target_port"], 43389)

    def test_forbidden_port(self):
        out = relocate_service({"service": "RDP", "target_port": 53389}, sleep_fn=lambda *_: None)
        self.assertEqual(out["status"], "error")
        self.assertEqual(out["error"], "FORBIDDEN_PORT_53389")

    def test_reserved_classic_of_other(self):
        # 1433 = MSSQL classic (≥1024 so C-REL-6 does not fire first)
        out = relocate_service(
            {"service": "RDP", "target_port": 1433, "skip_precheck": True},
            sleep_fn=lambda *_: None,
        )
        self.assertEqual(out["reason"], "port_reserved_classic")

    def test_target_busy_precheck(self):
        with mock.patch("client_service_relocate.is_admin", return_value=True), mock.patch(
            "client_service_relocate._read_golden", return_value=3389
        ), mock.patch("client_service_relocate._bind_ok", return_value=True):
            out = relocate_service(
                {"service": "RDP", "target_port": 43389, "verify_sec": 3},
                sleep_fn=lambda *_: None,
            )
        self.assertEqual(out["reason"], "target_port_in_use")

    def test_golden_persisted(self):
        with tempfile.TemporaryDirectory() as td:
            with mock.patch(
                "client_service_relocate._golden_dir", return_value=Path(td)
            ), mock.patch("client_service_relocate.is_admin", return_value=True), mock.patch(
                "client_service_relocate._read_golden", return_value=3389
            ), mock.patch(
                "client_service_relocate._ensure_firewall"
            ), mock.patch(
                "client_service_relocate._write_config", return_value=True
            ), mock.patch(
                "client_service_relocate.ServiceController.stop", return_value=True
            ), mock.patch(
                "client_service_relocate.ServiceController.start", return_value=True
            ), mock.patch(
                "client_service_relocate._verify_bind", return_value=True
            ):
                out = relocate_service(self.params, sleep_fn=lambda *_: None)
            self.assertEqual(out["status"], "ok")
            # cleared after success
            self.assertFalse((Path(td) / "RDP.json").is_file())

    def test_success_order_firewall_before_write(self):
        calls = []

        def fw(svc, port):
            calls.append(("fw", svc, port))

        def write(profile, port):
            calls.append(("write", port))
            return True

        with mock.patch("client_service_relocate.is_admin", return_value=True), mock.patch(
            "client_service_relocate._read_golden", return_value=3389
        ), mock.patch("client_service_relocate.save_golden_snapshot", return_value=True), mock.patch(
            "client_service_relocate._ensure_firewall", side_effect=fw
        ), mock.patch(
            "client_service_relocate._write_config", side_effect=write
        ), mock.patch(
            "client_service_relocate.ServiceController.stop", return_value=True
        ), mock.patch(
            "client_service_relocate.ServiceController.start", return_value=True
        ), mock.patch(
            "client_service_relocate._verify_bind", return_value=True
        ), mock.patch(
            "client_service_relocate.clear_golden_snapshot"
        ):
            out = relocate_service(self.params, sleep_fn=lambda *_: None)
        self.assertEqual(out["status"], "ok")
        self.assertEqual(calls[0][0], "fw")
        self.assertEqual(calls[0][1], "RDP")
        self.assertEqual(calls[1][0], "write")

    def test_bind_fail_rolls_back_shape(self):
        with mock.patch("client_service_relocate.is_admin", return_value=True), mock.patch(
            "client_service_relocate._read_golden", return_value=3389
        ), mock.patch("client_service_relocate.save_golden_snapshot", return_value=True), mock.patch(
            "client_service_relocate._ensure_firewall"
        ), mock.patch(
            "client_service_relocate._remove_firewall"
        ) as rm, mock.patch(
            "client_service_relocate._write_config", return_value=True
        ), mock.patch(
            "client_service_relocate.ServiceController.stop", return_value=True
        ), mock.patch(
            "client_service_relocate.ServiceController.start", return_value=True
        ), mock.patch(
            "client_service_relocate._verify_bind", side_effect=[False, True]
        ):
            out = relocate_service(self.params, sleep_fn=lambda *_: None)
        self.assertEqual(out["status"], "rollback")
        self.assertEqual(out["reason"], "bind_verify_failed")
        self.assertEqual(out["target_port"], 43389)
        self.assertTrue(out["rolled_back"])
        rm.assert_called()


class TestCommandWiring(unittest.TestCase):
    def test_allowed(self):
        self.assertIn("relocate_service", ALLOWED_COMMANDS)
        self.assertIn("relocate_service", REQUIRES_CONFIRMATION)
        self.assertIn("relocate_service", _IR_URGENT_COMMANDS)

    def test_handler_rollback_shape(self):
        ex = RemoteCommandExecutor(api_client=None)
        with mock.patch(
            "client_service_relocate.relocate_service",
            return_value={
                "ok": False,
                "success": False,
                "status": "rollback",
                "reason": "bind_verify_failed",
                "error": "GOLDEN_ROLLBACK",
                "service": "RDP",
                "old_port": 3389,
                "new_port": 43389,
                "target_port": 43389,
                "rolled_back": True,
            },
        ), mock.patch.object(ex, "_schedule_open_ports_refresh"):
            out = ex._cmd_relocate_service({"service": "RDP", "target_port": 43389})
        self.assertFalse(out["success"])
        self.assertEqual(out["status"], "rollback")
        self.assertEqual(out["reason"], "bind_verify_failed")
        self.assertEqual(out["target_port"], 43389)


if __name__ == "__main__":
    unittest.main()
