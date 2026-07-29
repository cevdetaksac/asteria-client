#!/usr/bin/env python3
"""relocate_service — contract 1.4.45 (golden→fw→config→restart→verify→rollback)."""

import unittest
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
    is_forbidden_target_port,
    prefill_targets_from_tunnel,
    relocate_service,
    resolve_service,
)


class TestDefaults(unittest.TestCase):
    def test_safe_ports_4xxxx(self):
        self.assertEqual(DEFAULT_SAFE_PORTS["RDP"], 43389)
        self.assertEqual(DEFAULT_SAFE_PORTS["MSSQL"], 41433)
        self.assertEqual(DEFAULT_SAFE_PORTS["MYSQL"], 43306)
        self.assertEqual(DEFAULT_SAFE_PORTS["SSH"], 40022)
        self.assertEqual(DEFAULT_SAFE_PORTS["FTP"], 40021)

    def test_forbid_53389_and_9xxxx(self):
        self.assertEqual(is_forbidden_target_port(53389), "FORBIDDEN_PORT_53389")
        self.assertEqual(is_forbidden_target_port(90022), "FORBIDDEN_PORT_9XXXX")
        self.assertIsNone(is_forbidden_target_port(43389))

    def test_prefill_from_tunnel(self):
        payload = {
            "relocate_state": {
                "RDP": {"saved_target_port": 43389},
                "SSH": {"default_safe_port": 40022},
            }
        }
        out = prefill_targets_from_tunnel(payload)
        self.assertEqual(out["RDP"], 43389)
        self.assertEqual(out["SSH"], 40022)
        self.assertEqual(out["MSSQL"], 41433)

    def test_prefill_rejects_forbidden_saved(self):
        payload = {"relocate_state": {"RDP": {"saved_target_port": 53389}}}
        out = prefill_targets_from_tunnel(payload)
        self.assertEqual(out["RDP"], 43389)

    def test_clamp_verify(self):
        self.assertEqual(clamp_verify_sec(10), 10.0)
        self.assertEqual(clamp_verify_sec(99), 10.0)
        self.assertEqual(clamp_verify_sec(1), 3.0)


class TestResolve(unittest.TestCase):
    def test_rdp_aliases(self):
        for name in ("RDP", "TermService", "remote-desktop"):
            sid, prof, err = resolve_service({"service": name})
            self.assertIsNone(err, name)
            self.assertEqual(sid, "RDP")
            self.assertEqual(prof["scm"], "TermService")

    def test_missing(self):
        _, _, err = resolve_service({})
        self.assertEqual(err, "missing_service")


class TestRelocate(unittest.TestCase):
    def setUp(self):
        self.params = {"service": "RDP", "port": 43389, "verify_sec": 3}

    def test_forbidden_port(self):
        out = relocate_service({"service": "RDP", "port": 53389}, sleep_fn=lambda *_: None)
        self.assertEqual(out["status"], "error")
        self.assertEqual(out["error"], "FORBIDDEN_PORT_53389")

    def test_admin_required(self):
        with mock.patch("client_service_relocate.is_admin", return_value=False), mock.patch(
            "client_service_relocate._read_golden", return_value=3389
        ):
            out = relocate_service(self.params, sleep_fn=lambda *_: None)
        self.assertEqual(out["error"], "ADMIN_REQUIRED")

    def test_noop_same_port(self):
        with mock.patch("client_service_relocate.is_admin", return_value=True), mock.patch(
            "client_service_relocate._read_golden", return_value=43389
        ), mock.patch("client_service_relocate._bind_ok", return_value=True):
            out = relocate_service(self.params, sleep_fn=lambda *_: None)
        self.assertEqual(out["status"], "ok")
        self.assertTrue(out.get("noop"))

    def test_success_path_order(self):
        calls = []

        def fw(port):
            calls.append(("fw", port))

        def write(profile, port):
            calls.append(("write", port))
            return True

        def stop(*_a, **_k):
            calls.append(("stop",))
            return True

        def start(*_a, **_k):
            calls.append(("start",))
            return True

        with mock.patch("client_service_relocate.is_admin", return_value=True), mock.patch(
            "client_service_relocate._read_golden", return_value=3389
        ), mock.patch("client_service_relocate._ensure_firewall", side_effect=fw), mock.patch(
            "client_service_relocate._write_config", side_effect=write
        ), mock.patch(
            "client_service_relocate.ServiceController.stop", side_effect=stop
        ), mock.patch(
            "client_service_relocate.ServiceController.start", side_effect=start
        ), mock.patch(
            "client_service_relocate._verify_bind", return_value=True
        ):
            out = relocate_service(self.params, sleep_fn=lambda *_: None)
        self.assertEqual(out["status"], "ok")
        self.assertEqual(out["old_port"], 3389)
        self.assertEqual(out["new_port"], 43389)
        # C-REL: firewall before config before restart
        self.assertEqual(calls[0][0], "fw")
        self.assertEqual(calls[1][0], "write")
        self.assertEqual(calls[2][0], "stop")
        self.assertEqual(calls[3][0], "start")

    def test_bind_fail_rolls_back(self):
        with mock.patch("client_service_relocate.is_admin", return_value=True), mock.patch(
            "client_service_relocate._read_golden", return_value=3389
        ), mock.patch("client_service_relocate._ensure_firewall"), mock.patch(
            "client_service_relocate._write_config", return_value=True
        ) as w, mock.patch(
            "client_service_relocate.ServiceController.stop", return_value=True
        ), mock.patch(
            "client_service_relocate.ServiceController.start", return_value=True
        ), mock.patch(
            "client_service_relocate._verify_bind", side_effect=[False, True]
        ):
            out = relocate_service(self.params, sleep_fn=lambda *_: None)
        self.assertEqual(out["status"], "rollback")
        self.assertEqual(out["reason"], "BIND_FAILED")
        self.assertTrue(out["rolled_back"])
        self.assertFalse(out["success"])
        # target write + golden restore
        self.assertGreaterEqual(w.call_count, 2)
        self.assertEqual(w.call_args_list[-1].args[1], 3389)


class TestCommandWiring(unittest.TestCase):
    def test_allowed_and_confirm(self):
        self.assertIn("relocate_service", ALLOWED_COMMANDS)
        self.assertIn("relocate_service", REQUIRES_CONFIRMATION)
        self.assertIn("relocate_service", _IR_URGENT_COMMANDS)

    def test_handler_success_shape(self):
        ex = RemoteCommandExecutor(api_client=None)
        with mock.patch(
            "client_service_relocate.relocate_service",
            return_value={
                "ok": True,
                "success": True,
                "status": "ok",
                "applied": True,
                "rolled_back": False,
                "service": "RDP",
                "old_port": 3389,
                "new_port": 43389,
                "message": "ok",
                "scm": "TermService",
            },
        ), mock.patch.object(ex, "_schedule_open_ports_refresh"):
            out = ex._cmd_relocate_service({"service": "RDP", "port": 43389})
        self.assertTrue(out["success"])
        self.assertEqual(out["status"], "ok")
        self.assertEqual(out["service"], "RDP")
        self.assertEqual(out["old_port"], 3389)
        self.assertEqual(out["new_port"], 43389)

    def test_handler_rollback_shape(self):
        ex = RemoteCommandExecutor(api_client=None)
        with mock.patch(
            "client_service_relocate.relocate_service",
            return_value={
                "ok": False,
                "success": False,
                "status": "rollback",
                "reason": "BIND_FAILED",
                "error": "GOLDEN_ROLLBACK",
                "service": "RDP",
                "old_port": 3389,
                "new_port": 43389,
                "rolled_back": True,
            },
        ), mock.patch.object(ex, "_schedule_open_ports_refresh"):
            out = ex._cmd_relocate_service({"service": "RDP", "port": 43389})
        self.assertFalse(out["success"])
        self.assertEqual(out["status"], "rollback")
        self.assertEqual(out["reason"], "BIND_FAILED")


if __name__ == "__main__":
    unittest.main()
