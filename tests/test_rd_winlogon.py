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
        ), mock.patch(
            "client_rd_winlogon.session_username", return_value=""
        ), mock.patch(
            "client_rd_winlogon.session_has_logonui", return_value=False
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
        self.assertEqual(result.get("error"), "SESSION0_HELPER_SPAWN_FAILED")

    def test_live_console_user_skips_winlogon_helper(self):
        rd = self._make_rd()
        sessions = [
            {
                "session_id": 3,
                "username": "administrator",
                "protocol": "Console",
                "status": "Active",
            },
            {
                "session_id": 3,
                "username": "",
                "pre_logon": True,
                "desktop": "winlogon",
                "protocol": "Console",
            },
        ]
        jpeg = b"\xff\xd8" + b"x" * 2000 + b"\xff\xd9"
        with mock.patch.object(
            rd, "_enumerate_sessions", return_value=sessions
        ), mock.patch(
            "client_rd_winlogon.console_session_id", return_value=3
        ), mock.patch(
            "client_rd_winlogon.session_username", return_value="administrator"
        ), mock.patch(
            "client_rd_winlogon.session_has_logonui", return_value=False
        ), mock.patch(
            "client_rd_winlogon.session_lock_state", return_value=False
        ), mock.patch(
            "client_rd_winlogon.session_has_process", return_value=True
        ), mock.patch.object(
            rd, "_session_ids", return_value=(0, 3)
        ), mock.patch.object(
            rd, "_start_persistent_helper", return_value=True
        ) as start_helper, mock.patch.object(
            rd, "_stop_persistent_helper"
        ), mock.patch.object(
            rd, "_grab_via_persistent_helper", return_value=(jpeg, 1024, 768)
        ), mock.patch.object(
            rd, "_persistent_helper_connected", return_value=False
        ), mock.patch.object(
            rd, "_webrtc_available", return_value=False
        ), mock.patch.object(
            rd, "emit_stream_progress"
        ), mock.patch.object(
            rd, "_session_connect_state", return_value="Active"
        ):
            rd._thread = None
            result = rd.start(
                topology="follow",
                fps=12,
            )
            try:
                self.assertTrue(result.get("success"), result)
                self.assertFalse(rd._winlogon_mode)
                self.assertEqual(rd._target_session_id, 3)
                self.assertEqual(rd._target_username, "administrator")
                self.assertEqual((rd._desktop_name or "").lower(), "default")
                self.assertNotEqual(result.get("error"), "SESSION0_HELPER_SPAWN_FAILED")
                start_helper.assert_called()
            finally:
                try:
                    rd.stop()
                except Exception:
                    pass

    def test_follow_lock_listed_user_uses_winlogon_helper(self):
        rd = self._make_rd()
        rd._target_session_id = 3
        rd._follow_console = True
        with mock.patch.object(
            rd, "_console_interactive_username", return_value="administrator"
        ), mock.patch(
            "client_rd_winlogon.session_has_logonui", return_value=False
        ), mock.patch(
            "client_rd_winlogon.session_lock_state", return_value=True
        ), mock.patch(
            "client_rd_winlogon.session_has_process", return_value=True
        ):
            rd._apply_follow_secure_or_default()
        self.assertTrue(rd._winlogon_mode)
        self.assertEqual(rd._target_username, "")

    def test_promote_gdi_black_user_helper(self):
        rd = self._make_rd()
        rd._follow_console = True
        rd._winlogon_mode = False
        rd._capture_method = "persistent-user-helper:gdi+black"
        rd._desktop_name = "Winlogon"
        self.assertTrue(rd._should_promote_follow_to_winlogon())

    def test_healthy_frame_blocks_black_webrtc(self):
        rd = self._make_rd()
        rd._capture_method = "gdi+black"
        self.assertFalse(rd._frame_is_healthy())
        self.assertFalse(rd._media_ready())

    def test_secure_desktop_still_uses_winlogon(self):
        from client_rd_winlogon import console_start_secure_desktop
        self.assertTrue(
            console_start_secure_desktop(username="administrator", logonui_present=True)
        )
        self.assertTrue(console_start_secure_desktop(username="", logonui_present=False))
        self.assertTrue(
            console_start_secure_desktop(username="administrator", logonui_present=False)
        )
        self.assertFalse(
            console_start_secure_desktop(
                username="administrator",
                logonui_present=False,
                session_locked=False,
                explorer_present=True,
            )
        )
        self.assertTrue(
            console_start_secure_desktop(
                username="administrator",
                logonui_present=False,
                session_locked=True,
                explorer_present=True,
            )
        )

    def test_lock_flags_and_helper_mode_mismatch(self):
        from client_rd_winlogon import interpret_session_lock_flags
        self.assertTrue(interpret_session_lock_flags(0))
        self.assertFalse(interpret_session_lock_flags(1))
        self.assertIsNone(interpret_session_lock_flags(0xFFFFFFFF))
        rd = self._make_rd()
        rd._winlogon_mode = True
        rd._helper_spawned_winlogon = False

        class Helper:
            connected = True

        rd._session_helper = Helper()
        self.assertFalse(rd._persistent_helper_matches_mode())


class TestSessionHasLogonui(unittest.TestCase):
    def _make_rd(self):
        from client_remote_desktop import RemoteDesktopStreamer
        return RemoteDesktopStreamer(api_client=None, token_getter=lambda: "")

    def test_unreadable_session_counts_on_console(self):
        from client_rd_winlogon import session_has_logonui
        with mock.patch(
            "client_rd_winlogon._pids_named",
            side_effect=lambda image: [42] if "logonui" in image.lower() else [],
        ), mock.patch(
            "client_rd_winlogon._session_of_pid", return_value=-1
        ), mock.patch(
            "client_rd_winlogon.console_session_id", return_value=3
        ):
            self.assertTrue(session_has_logonui(3))
            self.assertFalse(session_has_logonui(9))

    def test_resolve_start_topology_named(self):
        from client_rd_winlogon import resolve_start_topology
        mode, force = resolve_start_topology(
            topology="", prefer="winlogon", session_id_omitted=True
        )
        self.assertEqual(mode, "follow")
        self.assertFalse(force)
        mode, force = resolve_start_topology(
            topology="winlogon", prefer="winlogon", session_id_omitted=True
        )
        self.assertEqual(mode, "winlogon")
        self.assertTrue(force)
        mode, force = resolve_start_topology(
            topology="follow", prefer="", session_id_omitted=True
        )
        self.assertEqual(mode, "follow")
        self.assertFalse(force)
        mode, force = resolve_start_topology(
            topology="", prefer="winlogon", session_id_omitted=False
        )
        self.assertEqual(mode, "winlogon")
        self.assertTrue(force)

    def test_omit_session_id_refuses_invented_sid_when_no_console(self):
        rd = self._make_rd()
        sessions = [
            {
                "session_id": 1,
                "username": "rdpuser",
                "protocol": "RDP",
                "status": "Active",
            },
        ]
        with mock.patch.object(
            rd, "_enumerate_sessions", return_value=sessions
        ), mock.patch(
            "client_rd_winlogon.console_session_id", return_value=0
        ), mock.patch.object(
            rd, "_session_ids", return_value=(0, 0)
        ), mock.patch.object(
            rd, "emit_stream_progress"
        ):
            result = rd.start(
                prefer="winlogon",
                pre_logon=True,
                desktop="Winlogon",
            )
        self.assertFalse(result.get("success"))
        self.assertEqual(result.get("error"), "NO_CONSOLE_SESSION")
        self.assertIsNone(rd._target_session_id)

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


class TestSession0TokenChain(unittest.TestCase):
    def test_open_session_interactive_token_refuses_session_zero(self):
        from client_rd_winlogon import open_session_interactive_token

        h, src = open_session_interactive_token(0)
        self.assertIsNone(h)
        self.assertEqual(src, "refused_session_zero")

    def test_open_session_tries_winlogon_after_wts_fail(self):
        from client_rd_winlogon import open_session_interactive_token

        with mock.patch("client_rd_winlogon.enable_process_privileges"), mock.patch(
            "client_rd_winlogon._wtsapi32.WTSQueryUserToken", return_value=0
        ), mock.patch(
            "client_rd_winlogon._kernel32.GetLastError", return_value=1008
        ), mock.patch(
            "client_rd_winlogon._pids_named", return_value=[4242]
        ), mock.patch(
            "client_rd_winlogon._session_of_pid", return_value=2
        ), mock.patch(
            "client_rd_winlogon._duplicate_primary_token", return_value=99
        ):
            h, src = open_session_interactive_token(2)
        self.assertEqual(h, 99)
        self.assertTrue(src.startswith("process:"))


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


class TestDecideConsoleFollow(unittest.TestCase):
    def test_sid_change_on_console_start(self):
        from client_rd_winlogon import decide_console_follow

        self.assertEqual(
            decide_console_follow(
                follow_console=True,
                winlogon_mode=True,
                spawn_session_id=1,
                console_sid=2,
                console_username="administrator",
                helper_desktop="Winlogon",
                logonui_hwnd=1,
                chrome_detected=True,
            ),
            "console_sid_changed",
        )

    def test_sid_change_ignored_on_shortcut_sid(self):
        from client_rd_winlogon import decide_console_follow

        self.assertIsNone(
            decide_console_follow(
                follow_console=False,
                winlogon_mode=True,
                spawn_session_id=1,
                console_sid=2,
                console_username="bob",
                helper_desktop="Winlogon",
            )
        )

    def test_default_desktop_triggers(self):
        from client_rd_winlogon import decide_console_follow

        self.assertEqual(
            decide_console_follow(
                follow_console=True,
                winlogon_mode=True,
                spawn_session_id=1,
                console_sid=1,
                helper_desktop="Default",
            ),
            "desktop_default",
        )

    def test_user_active_same_sid_stays_until_default_desktop(self):
        from client_rd_winlogon import decide_console_follow

        self.assertIsNone(
            decide_console_follow(
                follow_console=True,
                winlogon_mode=True,
                spawn_session_id=1,
                console_sid=1,
                console_username="administrator",
                helper_desktop="Winlogon",
                logonui_hwnd=0,
                chrome_detected=False,
            )
        )

    def test_lock_promotes_user_helper_to_winlogon(self):
        from client_rd_winlogon import decide_console_secure

        self.assertEqual(
            decide_console_secure(
                follow_console=True,
                winlogon_mode=False,
                helper_desktop="Winlogon",
                logonui_present=False,
                console_username="administrator",
                black_frame=True,
            ),
            "input_desktop_winlogon",
        )
        self.assertEqual(
            decide_console_secure(
                follow_console=True,
                winlogon_mode=False,
                helper_desktop="Default",
                logonui_present=False,
                console_username="",
                black_frame=False,
            ),
            "no_user",
        )
        self.assertIsNone(
            decide_console_secure(
                follow_console=True,
                winlogon_mode=False,
                helper_desktop="Default",
                logonui_present=False,
                console_username="administrator",
                black_frame=True,
            )
        )

    def test_still_on_logonui(self):
        from client_rd_winlogon import decide_console_follow

        self.assertIsNone(
            decide_console_follow(
                follow_console=True,
                winlogon_mode=True,
                spawn_session_id=1,
                console_sid=1,
                console_username="",
                helper_desktop="Winlogon",
                logonui_hwnd=3,
                chrome_detected=True,
            )
        )


if __name__ == "__main__":
    unittest.main()
