#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""C-RD-CAD / C-RD-IN-WL unit tests (contract 1.4.53 / ≥4.9.86)."""

import unittest
from unittest import mock


class TestSoftwareSasPolicy(unittest.TestCase):
    def test_allows_services_values(self):
        from client_rd_winlogon import software_sas_allows_services

        self.assertTrue(software_sas_allows_services(1))
        self.assertTrue(software_sas_allows_services(3))
        self.assertFalse(software_sas_allows_services(0))
        self.assertFalse(software_sas_allows_services(2))
        self.assertFalse(software_sas_allows_services(None))

    def test_classify_ui_from_titles(self):
        from client_rd_winlogon import secure_attention_ui_state_from

        self.assertEqual(
            secure_attention_ui_state_from(
                ["Press Ctrl+Alt+Delete to unlock"], []
            ),
            "cad_tip",
        )
        self.assertEqual(
            secure_attention_ui_state_from(["Windows Security"], []),
            "sas_ui",
        )
        self.assertEqual(
            secure_attention_ui_state_from([], ["SomeChrome"]),
            "other",
        )
        self.assertEqual(secure_attention_ui_state_from([], []), "unknown")

    def test_classify_sas_transition(self):
        from client_rd_winlogon import classify_sas_transition

        ok, _ = classify_sas_transition("cad_tip", "sas_ui")
        self.assertTrue(ok)
        ok, _ = classify_sas_transition("cad_tip", "other")
        self.assertTrue(ok)
        ok, _ = classify_sas_transition("cad_tip", "cad_tip")
        self.assertFalse(ok)


class TestRemoteSendSasHonesty(unittest.TestCase):
    def _executor(self):
        from client_remote_commands import RemoteCommandExecutor

        ex = RemoteCommandExecutor.__new__(RemoteCommandExecutor)
        return ex

    def test_software_sas_disabled_when_ensure_fails(self):
        ex = self._executor()
        rd = mock.MagicMock()
        rd._target_session_id = 2
        rd._winlogon_mode = True
        rd._persistent_helper_connected.return_value = False
        rd._desktop_name = "Winlogon"
        with mock.patch.object(ex, "_get_remote_desktop", return_value=rd), mock.patch(
            "client_rd_winlogon.ensure_software_sas_generation",
            return_value=(0, "enable_failed"),
        ), mock.patch(
            "client_rd_winlogon.software_sas_allows_services", return_value=False
        ), mock.patch(
            "client_rd_winlogon.console_session_id", return_value=2
        ):
            out = ex._cmd_remote_send_sas({"prefer": "winlogon", "pre_logon": True})
        self.assertFalse(out.get("success"))
        self.assertEqual(out.get("error"), "SOFTWARE_SAS_DISABLED")
        data = out.get("data") or {}
        self.assertEqual(data.get("software_sas_generation"), 0)
        self.assertIsInstance(data.get("software_sas_generation"), int)

    def test_sas_no_effect_when_void_call_unchanged(self):
        ex = self._executor()
        rd = mock.MagicMock()
        rd._target_session_id = 2
        rd._winlogon_mode = True
        rd._persistent_helper_connected.return_value = False
        rd._desktop_name = "Winlogon"
        with mock.patch.object(ex, "_get_remote_desktop", return_value=rd), mock.patch(
            "client_rd_winlogon.ensure_software_sas_generation",
            return_value=(1, "policy_ok"),
        ), mock.patch(
            "client_rd_winlogon.software_sas_allows_services", return_value=True
        ), mock.patch(
            "client_rd_winlogon.invoke_send_sas",
            return_value=(True, "SendSAS(FALSE) invoked"),
        ), mock.patch(
            "client_rd_winlogon.watch_sas_effect",
            return_value=(False, "no_sas_effect state=cad_tip", "cad_tip"),
        ), mock.patch(
            "client_rd_winlogon.send_sas_with_console_affinity",
            return_value=(True, "SendSAS(FALSE) invoked", {
                "token_source": "process:winlogon.exe",
                "impersonated": True,
                "desktop": "Winlogon",
            }),
        ):
            out = ex._cmd_remote_send_sas({"prefer": "winlogon"})
        self.assertFalse(out.get("success"))
        self.assertEqual(out.get("error"), "SAS_NO_EFFECT")
        data = out.get("data") or {}
        self.assertEqual(data.get("session_id"), 2)
        self.assertEqual(data.get("software_sas_generation"), 1)
        self.assertNotEqual(data.get("ui_after"), None)

    def test_service_path_success_when_effect_observed(self):
        ex = self._executor()
        rd = mock.MagicMock()
        rd._target_session_id = 2
        rd._winlogon_mode = True
        rd._persistent_helper_connected.return_value = False
        rd._desktop_name = "Winlogon"
        with mock.patch.object(ex, "_get_remote_desktop", return_value=rd), mock.patch(
            "client_rd_winlogon.ensure_software_sas_generation",
            return_value=(1, "enabled"),
        ), mock.patch(
            "client_rd_winlogon.software_sas_allows_services", return_value=True
        ), mock.patch(
            "client_rd_winlogon.invoke_send_sas",
            return_value=(True, "SendSAS(FALSE) invoked"),
        ), mock.patch(
            "client_rd_winlogon.watch_sas_effect",
            return_value=(True, "secure_attention_ui=sas_ui", "sas_ui"),
        ):
            out = ex._cmd_remote_send_sas({"prefer": "winlogon"})
        self.assertTrue(out.get("success"))
        self.assertEqual((out.get("data") or {}).get("path"), "service")
        self.assertEqual((out.get("data") or {}).get("software_sas_generation"), 1)

    def test_helper_path_success_when_effect_observed(self):
        ex = self._executor()
        helper = mock.MagicMock()
        helper.send_sas.return_value = {
            "ok": True,
            "effect": True,
            "detail": "SendSAS(FALSE) invoked; secure_attention_ui=sas_ui",
            "ui_before": "cad_tip",
            "ui_after": "sas_ui",
            "as_user": False,
            "path": "helper",
        }
        helper.query_ui_state.return_value = {
            "ok": True,
            "ui": "cad_tip",
            "fp": "abc",
        }
        rd = mock.MagicMock()
        rd._target_session_id = 2
        rd._winlogon_mode = True
        rd._persistent_helper_connected.return_value = True
        rd._session_helper = helper
        with mock.patch.object(ex, "_get_remote_desktop", return_value=rd), mock.patch(
            "client_rd_winlogon.ensure_software_sas_generation",
            return_value=(1, "policy_ok"),
        ), mock.patch(
            "client_rd_winlogon.software_sas_allows_services", return_value=True
        ), mock.patch(
            "client_rd_winlogon.invoke_send_sas",
            return_value=(True, "SendSAS(FALSE) invoked"),
        ):
            # Service path polls helper UI and stays on tip → then helper path wins.
            helper.query_ui_state.return_value = {
                "ok": True,
                "ui": "cad_tip",
                "fp": "abc",
            }
            out = ex._cmd_remote_send_sas({"prefer": "winlogon"})
        self.assertTrue(out.get("success"))
        self.assertEqual((out.get("data") or {}).get("path"), "helper")
        self.assertEqual((out.get("data") or {}).get("ui_after"), "sas_ui")


class TestCadKeyIgnored(unittest.TestCase):
    def test_ctrl_alt_delete_key_not_success(self):
        from client_remote_desktop import RemoteDesktopStreamer

        rd = RemoteDesktopStreamer(api_client=None, token_getter=lambda: "")
        rd._running = True
        out = rd.apply_input({"event": "key", "key": "ctrl+alt+delete"})
        self.assertFalse(out.get("success"))
        self.assertEqual(out.get("error"), "cad_key_ignored")


if __name__ == "__main__":
    unittest.main()
