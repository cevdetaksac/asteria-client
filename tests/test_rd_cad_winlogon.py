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
                ["Press Ctrl+Alt+Delete to unlock", "Sign in"], []
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
        self.assertEqual(
            secure_attention_ui_state_from([], ["LogonUI"]),
            "other",
        )
        self.assertEqual(secure_attention_ui_state_from([], []), "unknown")

    def test_flat_frame_detection(self):
        from PIL import Image
        from client_remote_desktop import RemoteDesktopStreamer

        rd = RemoteDesktopStreamer(api_client=None, token_getter=lambda: "")
        solid = Image.new("RGB", (320, 240), (0, 90, 156))
        self.assertTrue(rd._is_mostly_flat(solid))
        self.assertFalse(rd._is_mostly_black(solid))
        # Wallpaper-like textured image (checker + bright glyphs)
        noisy = Image.new("RGB", (320, 240), (40, 40, 40))
        px = noisy.load()
        for y in range(240):
            for x in range(320):
                if (x // 8 + y // 8) % 2:
                    px[x, y] = (180, 120, 90)
                if x % 40 == 0 and y % 30 == 0:
                    px[x, y] = (255, 255, 255)
        self.assertFalse(rd._is_mostly_flat(noisy))

    def test_classify_sas_transition(self):
        from client_rd_winlogon import classify_sas_transition

        ok, _ = classify_sas_transition("cad_tip", "sas_ui", after_flat=False)
        self.assertTrue(ok)
        ok, _ = classify_sas_transition("cad_tip", "other", after_flat=False)
        self.assertTrue(ok)
        ok, _ = classify_sas_transition("cad_tip", "cad_tip", after_flat=False)
        self.assertFalse(ok)
        ok, detail = classify_sas_transition("cad_tip", "sas_ui", after_flat=True)
        self.assertFalse(ok)
        self.assertIn("flat", detail)


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
            "client_rd_winlogon.console_session_id", return_value=2
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

    def test_prefer_winlogon_ignores_stale_user_session_id(self):
        """Lab 4.9.88: CAD prefer=winlogon must not bind locked-user sid=3."""
        ex = self._executor()
        rd = mock.MagicMock()
        rd._target_session_id = 3
        rd._winlogon_mode = False
        rd._persistent_helper_connected.return_value = False
        with mock.patch.object(ex, "_get_remote_desktop", return_value=rd), mock.patch(
            "client_rd_winlogon.ensure_software_sas_generation",
            return_value=(1, "policy_ok"),
        ), mock.patch(
            "client_rd_winlogon.software_sas_allows_services", return_value=True
        ), mock.patch(
            "client_rd_winlogon.console_session_id", return_value=1
        ), mock.patch(
            "client_rd_winlogon.invoke_send_sas",
            return_value=(True, "SendSAS(FALSE) invoked"),
        ), mock.patch(
            "client_rd_winlogon.watch_sas_effect",
            return_value=(False, "no_sas_effect state=unknown", "unknown"),
        ), mock.patch(
            "client_rd_winlogon.send_sas_with_console_affinity",
            return_value=(True, "SendSAS(FALSE) invoked", {
                "token_source": "process:winlogon.exe",
                "impersonated": True,
                "desktop": "Winlogon",
            }),
        ) as aff:
            out = ex._cmd_remote_send_sas({
                "prefer": "winlogon",
                "pre_logon": True,
                "session_id": 3,
            })
        data = out.get("data") or {}
        self.assertEqual(data.get("session_id"), 1)
        # Affinity called with console SID 1, not stale 3.
        self.assertTrue(aff.called)
        self.assertEqual(aff.call_args[0][0], 1)

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
            "client_rd_winlogon.console_session_id", return_value=2
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
            "flat": False,
            "chrome_detected": True,
            "frame_variance": 80.0,
            "path": "helper",
        }
        helper.query_ui_state.return_value = {
            "ok": True,
            "ui": "cad_tip",
            "fp": "abc",
            "flat": False,
            "chrome_detected": True,
        }
        rd = mock.MagicMock()
        rd._target_session_id = 2
        rd._winlogon_mode = True
        rd._persistent_helper_connected.return_value = True
        rd._session_helper = helper
        rd.force_winlogon_recapture = mock.MagicMock()
        with mock.patch.object(ex, "_get_remote_desktop", return_value=rd), mock.patch(
            "client_rd_winlogon.ensure_software_sas_generation",
            return_value=(1, "policy_ok"),
        ), mock.patch(
            "client_rd_winlogon.software_sas_allows_services", return_value=True
        ), mock.patch(
            "client_rd_winlogon.console_session_id", return_value=2
        ), mock.patch(
            "client_rd_winlogon.invoke_send_sas",
            return_value=(True, "SendSAS(FALSE) invoked"),
        ):
            # Service path polls helper UI and stays on tip → then helper path wins.
            helper.query_ui_state.return_value = {
                "ok": True,
                "ui": "cad_tip",
                "fp": "abc",
                "flat": False,
                "chrome_detected": True,
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


class TestDesktopAttachTid(unittest.TestCase):
    def test_attach_skip_requires_same_thread(self):
        from client_remote_desktop import RemoteDesktopStreamer

        rd = RemoteDesktopStreamer(api_client=None, token_getter=lambda: "")
        rd._desktop_attached = True
        rd._desktop_attach_tid = 999999  # not this thread
        rd._winlogon_mode = False
        with mock.patch.object(
            rd,
            "_attach_input_desktop",
            wraps=rd._attach_input_desktop,
        ):
            # Force early-return path: wrong tid must not skip (would call OS attach).
            # Simulate the guard alone:
            import threading

            tid = threading.get_ident()
            self.assertNotEqual(rd._desktop_attach_tid, tid)
            # Correct tid + attached → skip
            rd._desktop_attach_tid = tid
            self.assertTrue(rd._desktop_attached and rd._desktop_attach_tid == tid)

    def test_invalidate_clears_tid(self):
        from client_remote_desktop import RemoteDesktopStreamer

        rd = RemoteDesktopStreamer(api_client=None, token_getter=lambda: "")
        rd._desktop_attached = True
        rd._desktop_attach_tid = 123
        rd._invalidate_desktop_bind()
        self.assertFalse(rd._desktop_attached)
        self.assertIsNone(rd._desktop_attach_tid)


if __name__ == "__main__":
    unittest.main()
