#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for C-RD-HOST active-RDP fallback + host prep helpers."""

import unittest
from unittest import mock


class TestActiveRdpFallback(unittest.TestCase):
    def test_picks_active_rdp_over_console(self):
        from client_remote_desktop import RemoteDesktopStreamer

        rd = RemoteDesktopStreamer.__new__(RemoteDesktopStreamer)
        rd._winlogon_mode = True
        rd._active_rdp_fallback_attempted = False
        rd._target_session_id = 1
        rd._force_secure_desktop = True
        rd._prefer_dxgi = False
        rd._follow_console = True
        rd._target_username = ""
        rd._desktop_name = "Winlogon"
        rd._capture_method = "gdi+flat"
        rd._stats = {}
        rd._last_helper_fail_phase = ""
        rd._last_helper_raw = None

        sessions = [
            {"session_id": 1, "username": "", "status": "Connected", "protocol": "Console", "pre_logon": True},
            {"session_id": 2, "username": "Administrator", "status": "Active", "protocol": "RDP"},
        ]

        with mock.patch.object(rd, "_enumerate_sessions", return_value=sessions), \
             mock.patch.object(rd, "emit_stream_progress"), \
             mock.patch.object(rd, "_stop_persistent_helper"), \
             mock.patch.object(rd, "_start_persistent_helper", return_value=True), \
             mock.patch.object(rd, "_grab_via_persistent_helper", return_value=(b"x" * 2000, 1280, 720)), \
             mock.patch("client_remote_desktop.log"):
            out = rd._fallback_flat_winlogon_to_active_rdp()

        self.assertIsNotNone(out)
        self.assertEqual(rd._target_session_id, 2)
        self.assertEqual(rd._target_username, "Administrator")
        self.assertFalse(rd._winlogon_mode)
        self.assertIn("active-rdp-fallback", rd._capture_method)

    def test_skips_second_attempt(self):
        from client_remote_desktop import RemoteDesktopStreamer

        rd = RemoteDesktopStreamer.__new__(RemoteDesktopStreamer)
        rd._winlogon_mode = True
        rd._active_rdp_fallback_attempted = True
        self.assertIsNone(rd._fallback_flat_winlogon_to_active_rdp())

    def test_allow_default_respawns_active_console(self):
        """Post-logon Default gdi+black → Active Console helper respawn (HOST-2)."""
        from client_remote_desktop import RemoteDesktopStreamer

        rd = RemoteDesktopStreamer.__new__(RemoteDesktopStreamer)
        rd._winlogon_mode = False
        rd._active_rdp_fallback_attempted = False
        rd._target_session_id = 2
        rd._force_secure_desktop = False
        rd._prefer_dxgi = True
        rd._follow_console = True
        rd._target_username = "administrator"
        rd._desktop_name = "Default"
        rd._capture_method = "persistent-user-helper:gdi+black"
        rd._stats = {}
        rd._last_helper_fail_phase = ""
        rd._last_helper_raw = None
        rd._use_user_helper = True
        rd._dxcam = None
        rd._locked_encode_w = 0
        rd._locked_encode_h = 0

        sessions = [
            {
                "session_id": 2,
                "username": "administrator",
                "status": "Active",
                "protocol": "Console",
            },
        ]
        healthy = (b"\xff\xd8" + b"y" * 2000 + b"\xff\xd9", 1024, 768)

        with mock.patch.object(rd, "_enumerate_sessions", return_value=sessions), \
             mock.patch.object(rd, "emit_stream_progress"), \
             mock.patch.object(rd, "_stop_persistent_helper"), \
             mock.patch.object(rd, "_start_persistent_helper", return_value=True), \
             mock.patch.object(rd, "_grab_via_persistent_helper", return_value=healthy), \
             mock.patch.object(rd, "_reset_dxgi_camera"), \
             mock.patch("client_remote_desktop.log"):
            out = rd._fallback_flat_winlogon_to_active_rdp(allow_default=True)

        self.assertIsNotNone(out)
        self.assertEqual(rd._target_session_id, 2)
        self.assertFalse(rd._winlogon_mode)
        self.assertIn("active-rdp-fallback", rd._capture_method)

    def test_allow_default_blocked_without_flag(self):
        from client_remote_desktop import RemoteDesktopStreamer

        rd = RemoteDesktopStreamer.__new__(RemoteDesktopStreamer)
        rd._winlogon_mode = False
        rd._active_rdp_fallback_attempted = False
        self.assertIsNone(rd._fallback_flat_winlogon_to_active_rdp())


class TestHostPrep(unittest.TestCase):
    def test_skip_non_windows(self):
        from client_rd_host_prep import apply_rd_host_prep
        with mock.patch("client_rd_host_prep.os.name", "posix"):
            out = apply_rd_host_prep(force=True)
        self.assertTrue(out.get("skipped"))


if __name__ == "__main__":
    unittest.main()
