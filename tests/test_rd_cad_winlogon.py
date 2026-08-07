#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""C-RD-CAD / C-RD-IN-WL unit tests (contract 1.4.52)."""

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


class TestRemoteSendSasHonesty(unittest.TestCase):
    def _executor(self):
        from client_remote_commands import RemoteCommandExecutor

        ex = RemoteCommandExecutor.__new__(RemoteCommandExecutor)
        return ex

    def test_software_sas_disabled_when_policy_blocks(self):
        ex = self._executor()
        rd = mock.MagicMock()
        rd._target_session_id = 2
        rd._winlogon_mode = True
        rd._persistent_helper_connected.return_value = False
        rd._desktop_name = "Winlogon"
        with mock.patch.object(ex, "_get_remote_desktop", return_value=rd), mock.patch(
            "client_rd_winlogon.software_sas_generation", return_value=0
        ), mock.patch(
            "client_rd_winlogon.software_sas_allows_services", return_value=False
        ), mock.patch(
            "client_rd_winlogon.console_session_id", return_value=2
        ):
            out = ex._cmd_remote_send_sas({"prefer": "winlogon", "pre_logon": True})
        self.assertFalse(out.get("success"))
        self.assertEqual(out.get("error"), "SOFTWARE_SAS_DISABLED")
        self.assertIn("software_sas_generation", out.get("data") or {})

    def test_sas_no_effect_when_void_call_unchanged(self):
        ex = self._executor()
        rd = mock.MagicMock()
        rd._target_session_id = 2
        rd._winlogon_mode = True
        rd._persistent_helper_connected.return_value = False
        rd._desktop_name = "Winlogon"
        with mock.patch.object(ex, "_get_remote_desktop", return_value=rd), mock.patch(
            "client_rd_winlogon.software_sas_generation", return_value=1
        ), mock.patch(
            "client_rd_winlogon.software_sas_allows_services", return_value=True
        ), mock.patch(
            "client_rd_winlogon.secure_attention_ui_state", return_value="cad_tip"
        ), mock.patch(
            "client_rd_winlogon.desktop_surface_fingerprint", return_value="abc"
        ), mock.patch(
            "client_rd_winlogon.send_sas_with_console_affinity",
            return_value=(True, "SendSAS(FALSE) invoked", {
                "token_source": "process:winlogon.exe",
                "impersonated": True,
                "desktop": "Winlogon",
            }),
        ), mock.patch(
            "client_rd_winlogon.watch_sas_effect",
            return_value=(False, "no_sas_effect state=cad_tip"),
        ):
            out = ex._cmd_remote_send_sas({"prefer": "winlogon"})
        self.assertFalse(out.get("success"))
        self.assertEqual(out.get("error"), "SAS_NO_EFFECT")
        data = out.get("data") or {}
        self.assertEqual(data.get("session_id"), 2)
        self.assertFalse(data.get("as_user"))
        self.assertEqual(data.get("software_sas_generation"), 1)

    def test_helper_path_success_when_effect_observed(self):
        ex = self._executor()
        helper = mock.MagicMock()
        helper.send_sas.return_value = {
            "ok": True,
            "detail": "SendSAS(FALSE) invoked",
            "path": "helper",
        }
        rd = mock.MagicMock()
        rd._target_session_id = 2
        rd._winlogon_mode = True
        rd._persistent_helper_connected.return_value = True
        rd._session_helper = helper
        with mock.patch.object(ex, "_get_remote_desktop", return_value=rd), mock.patch(
            "client_rd_winlogon.software_sas_generation", return_value=1
        ), mock.patch(
            "client_rd_winlogon.secure_attention_ui_state",
            side_effect=["cad_tip", "sas_ui"],
        ), mock.patch(
            "client_rd_winlogon.desktop_surface_fingerprint", return_value="abc"
        ), mock.patch(
            "client_rd_winlogon.watch_sas_effect",
            return_value=(True, "secure_attention_ui=sas_ui"),
        ):
            out = ex._cmd_remote_send_sas({"prefer": "winlogon"})
        self.assertTrue(out.get("success"))
        self.assertEqual((out.get("data") or {}).get("path"), "helper")


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
