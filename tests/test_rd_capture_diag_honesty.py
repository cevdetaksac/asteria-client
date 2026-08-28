#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Capture health honesty: healthy PrintWindow must not stay FAIL · no_frame."""

import unittest
from unittest import mock


class TestCaptureDiagHonesty(unittest.TestCase):
    def _rd(self):
        from client_remote_desktop import RemoteDesktopStreamer

        rd = RemoteDesktopStreamer.__new__(RemoteDesktopStreamer)
        rd._capture_method = "persistent-winlogon-helper:printwindow-logonui"
        rd._chrome_detected = True
        rd._last_frame_variance = 2343.0
        rd._last_frame_bright_ratio = 0.94
        rd._black_streak_started = 1.0  # stale — must not mark black
        rd._flat_streak_started = 0.0
        rd._last_helper_fail_phase = "no_frame"
        rd._last_helper_fail_detail = "method=helper jpeg=0B"
        rd._last_helper_token_source = "process:winlogon.exe"
        rd._desktop_name = "Winlogon"
        rd._winlogon_mode = True
        rd._force_secure_desktop = True
        rd._follow_console = True
        rd._prefer_dxgi = False
        rd._use_user_helper = True
        rd._in_session_helper = False
        rd._desktop_attached = True
        rd._desktop_attach_tid = 1
        rd._target_session_id = 4
        rd._target_username = ""
        rd._helper_spawned_winlogon = True
        rd._session_helper = mock.Mock(connected=True)
        rd._stats = {
            "frames_sent": 12,
            "frames_failed": 1,
            "black_frames": 0,
            "flat_frames": 0,
        }
        rd._seq = 12
        rd._logonui_hwnd_count = 1
        rd._last_unhealthy_jpeg_bytes = 0
        rd._last_stream_error = ""
        rd._last_diag_dump_path = ""
        rd._capture_recovery_steps = []
        rd._last_hwnd_classes = []
        rd._preferred_transport = "websocket"
        rd._transport = "websocket"
        rd._ws_ok = True
        rd._running = True
        rd._media = mock.Mock()
        rd._media.status.return_value = {
            "available": True,
            "active": False,
            "connection_state": "failed",
            "ice_state": "failed",
            "error": "peer setup failed",
            "jpeg_fallback_active": True,
        }
        rd._jpeg_ws_primary = mock.Mock(return_value=True)
        rd._persistent_helper_connected = mock.Mock(return_value=True)
        return rd

    def test_healthy_printwindow_clears_stale_no_frame(self):
        rd = self._rd()
        with mock.patch(
            "client_rd_winlogon.console_capture_env",
            return_value={"logonui": True, "resolve_mode": "winlogon"},
        ):
            snap = rd._capture_diag_snapshot()
        self.assertTrue(snap["healthy"])
        self.assertEqual(snap["helper_fail_phase"], "")
        self.assertNotIn("WEBRTC_PEER_ERROR", snap["faults"])
        self.assertEqual(snap["blame"], "none")
        self.assertEqual(snap["layer"], "ok")
        self.assertFalse(snap["black_frame"])
        self.assertEqual(snap["root_cause"], "")

    def test_note_healthy_wire_emits_live_diag(self):
        rd = self._rd()
        rd._last_diag_was_healthy = False
        rd._last_diag_emit_mono = 0.0
        with mock.patch.object(rd, "_enqueue_capture_diag") as enq:
            rd._note_healthy_wire_frame(detail="1024x768")
        self.assertEqual(rd._last_helper_fail_phase, "")
        self.assertTrue(rd._last_diag_was_healthy)
        self.assertEqual(rd._black_streak_started, 0.0)
        enq.assert_called()
        kwargs = enq.call_args.kwargs
        self.assertEqual(kwargs.get("phase"), "live")


if __name__ == "__main__":
    unittest.main()
