#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for Winlogon / pre-logon remote-desktop helpers."""

import unittest
from unittest import mock

from client_rd_winlogon import synthesize_console_session
from client_remote_session import _can_capture, prepare_remote_session


class TestCanCapture(unittest.TestCase):
    def test_active_rdp_still_capturable(self):
        self.assertTrue(_can_capture("Active", 2, "RDP"))

    def test_disconnected_rdp_not_capturable(self):
        self.assertFalse(_can_capture("Disconnected", 2, "RDP"))

    def test_console_pre_logon_capturable(self):
        self.assertTrue(_can_capture("Connected", 1, "Console", pre_logon=True))

    def test_services_never(self):
        self.assertFalse(_can_capture("Active", 0, "Services"))


class TestSynthesizeConsole(unittest.TestCase):
    def test_adds_when_missing(self):
        with mock.patch(
            "client_rd_winlogon.console_session_id", return_value=1
        ), mock.patch(
            "client_remote_desktop.RemoteDesktopStreamer._session_connect_state",
            return_value="Connected",
        ):
            row = synthesize_console_session([])
        self.assertIsNotNone(row)
        self.assertEqual(row["session_id"], 1)
        self.assertTrue(row["pre_logon"])
        self.assertTrue(row["can_capture"])
        self.assertEqual(row["username"], "")

    def test_adds_sibling_when_user_listed(self):
        with mock.patch(
            "client_rd_winlogon.console_session_id", return_value=1
        ), mock.patch(
            "client_remote_desktop.RemoteDesktopStreamer._session_connect_state",
            return_value="Connected",
        ):
            row = synthesize_console_session([
                {"session_id": 1, "username": "alice", "protocol": "Console"},
            ])
        self.assertIsNotNone(row)
        self.assertTrue(row["pre_logon"])
        self.assertTrue(row["alongside_user_session"])
        self.assertEqual(row["label"], "Logon / Lock screen")

    def test_skips_when_pre_logon_already_present(self):
        with mock.patch("client_rd_winlogon.console_session_id", return_value=1):
            row = synthesize_console_session([
                {"session_id": 1, "username": "", "pre_logon": True},
            ])
        self.assertIsNone(row)


class TestPrepareWinlogon(unittest.TestCase):
    def test_prefer_winlogon_uses_probe(self):
        fake = {
            "ok": True,
            "session_id": 1,
            "width": 1920,
            "height": 1080,
            "desktop": "Winlogon",
            "method": "winlogon",
        }
        with mock.patch(
            "client_rd_winlogon.probe_winlogon_capture", return_value=fake
        ), mock.patch(
            "client_rd_winlogon.console_session_id", return_value=1
        ):
            out = prepare_remote_session(username="", prefer="winlogon")
        self.assertTrue(out["success"])
        self.assertTrue(out["data"]["ready_for_stream"])
        self.assertEqual(out["data"]["method"], "winlogon")
        self.assertEqual(out["data"]["session_id"], 1)

    def test_missing_user_falls_back_to_winlogon(self):
        fake = {
            "ok": True,
            "session_id": 1,
            "width": 800,
            "height": 600,
            "desktop": "Winlogon",
        }
        with mock.patch(
            "client_remote_session.enumerate_sessions_rich", return_value=[]
        ), mock.patch(
            "client_rd_winlogon.probe_winlogon_capture", return_value=fake
        ), mock.patch(
            "client_rd_winlogon.console_session_id", return_value=1
        ):
            out = prepare_remote_session(username="bob", password="")
        self.assertTrue(out["success"])
        self.assertEqual(out["data"]["method"], "winlogon")
        self.assertEqual(out["data"]["username"], "bob")

    def test_existing_only_still_unsupported(self):
        with mock.patch(
            "client_remote_session.enumerate_sessions_rich", return_value=[]
        ):
            out = prepare_remote_session(
                username="bob", password="", prefer="existing"
            )
        self.assertFalse(out["success"])
        self.assertEqual(out["error"], "UNSUPPORTED")


class TestSelectSessionRow(unittest.TestCase):
    def test_prefer_winlogon_picks_pre_logon_sibling(self):
        from client_remote_desktop import RemoteDesktopStreamer
        rows = [
            {"session_id": 2, "username": "alice", "protocol": "Console"},
            {
                "session_id": 2,
                "username": "",
                "pre_logon": True,
                "desktop": "winlogon",
            },
        ]
        pick = RemoteDesktopStreamer._select_session_row(
            rows, want_winlogon=True, username=""
        )
        self.assertTrue(pick["pre_logon"])

    def test_default_prefers_user_row(self):
        from client_remote_desktop import RemoteDesktopStreamer
        rows = [
            {
                "session_id": 2,
                "username": "",
                "pre_logon": True,
                "desktop": "winlogon",
            },
            {"session_id": 2, "username": "alice", "protocol": "Console"},
        ]
        pick = RemoteDesktopStreamer._select_session_row(
            rows, want_winlogon=False, username=None
        )
        self.assertEqual(pick["username"], "alice")


class TestWinlogonStartContract(unittest.TestCase):
    """C-RD-CON-2/3 — omit SID → console; never bind username on winlogon."""

    def _make_rd(self):
        from client_remote_desktop import RemoteDesktopStreamer
        return RemoteDesktopStreamer(api_client=None, token_getter=lambda: "")

    def test_omit_session_id_uses_console_not_rdp(self):
        rd = self._make_rd()
        sessions = [
            {
                "session_id": 1,
                "username": "rdpuser",
                "protocol": "RDP",
                "status": "Active",
            },
            {
                "session_id": 3,
                "username": "",
                "protocol": "Console",
                "status": "Connected",
                "pre_logon": True,
                "desktop": "winlogon",
                "can_capture": True,
            },
        ]

        with mock.patch.object(
            rd, "_enumerate_sessions", return_value=sessions
        ), mock.patch(
            "client_rd_winlogon.console_session_id", return_value=3
        ), mock.patch.object(
            rd, "_session_ids", return_value=(0, 3)
        ), mock.patch.object(
            rd, "_start_persistent_helper", return_value=False
        ), mock.patch.object(
            rd, "_stop_persistent_helper"
        ), mock.patch.object(
            rd, "_grab_via_user_helper", return_value=(None, 0, 0)
        ), mock.patch.object(
            rd, "emit_stream_progress"
        ):
            result = rd.start(
                prefer="winlogon",
                pre_logon=True,
                desktop="Winlogon",
                username="should-be-ignored",
            )
        self.assertEqual(rd._target_session_id, 3)
        self.assertEqual(rd._target_username, "")
        self.assertTrue(rd._winlogon_mode)
        self.assertFalse(result.get("success"))

    def test_winlogon_strips_username_even_when_sid_given(self):
        rd = self._make_rd()
        sessions = [
            {
                "session_id": 2,
                "username": "alice",
                "protocol": "Console",
                "status": "Active",
            },
            {
                "session_id": 2,
                "username": "",
                "pre_logon": True,
                "desktop": "winlogon",
                "protocol": "Console",
                "can_capture": True,
            },
        ]
        with mock.patch.object(
            rd, "_enumerate_sessions", return_value=sessions
        ), mock.patch.object(
            rd, "_session_ids", return_value=(0, 2)
        ), mock.patch.object(
            rd, "_start_persistent_helper", return_value=False
        ), mock.patch.object(
            rd, "_stop_persistent_helper"
        ), mock.patch.object(
            rd, "_grab_via_user_helper", return_value=(None, 0, 0)
        ), mock.patch.object(
            rd, "emit_stream_progress"
        ):
            rd.start(
                session_id=2,
                prefer="winlogon",
                pre_logon=True,
                username="alice",
            )
        self.assertEqual(rd._target_session_id, 2)
        self.assertEqual(rd._target_username, "")
        self.assertTrue(rd._winlogon_mode)

    def test_winlogon_session0_uses_helper_desktop(self):
        rd = self._make_rd()
        rd._winlogon_mode = True
        self.assertEqual(rd._helper_desktop().lower(), r"winsta0\winlogon")
        rd._winlogon_mode = False
        self.assertEqual(rd._helper_desktop().lower(), r"winsta0\default")


class TestAttachStrictWinlogon(unittest.TestCase):
    def test_strict_rejects_non_winlogon_input(self):
        from client_rd_winlogon import attach_console_desktop

        fake_user32 = mock.MagicMock()
        fake_user32.OpenDesktopW.return_value = 0
        fake_user32.OpenInputDesktop.return_value = 99
        fake_user32.SetThreadDesktop.return_value = True
        fake_user32.CloseDesktop.return_value = True

        with mock.patch("client_rd_winlogon._user32", fake_user32), mock.patch(
            "client_rd_winlogon._kernel32.SetLastError"
        ), mock.patch(
            "client_rd_winlogon._kernel32.GetLastError", return_value=5
        ), mock.patch(
            "client_rd_winlogon.desktop_name", return_value="Default"
        ), mock.patch(
            "client_rd_winlogon.switch_to_winsta0", return_value=(True, "WinSta0")
        ):
            ok, detail, hdesk = attach_console_desktop(
                prefer_winlogon=True, strict_winlogon=True
            )
        self.assertFalse(ok)
        self.assertIsNone(hdesk)
        self.assertIn("strict Winlogon", detail)


if __name__ == "__main__":
    unittest.main()
