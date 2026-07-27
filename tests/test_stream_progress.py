#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Contract 1.4.39 — stream_progress emit (C-RD-PROG-*)."""

import json
import time
import unittest
from unittest import mock


class TestStreamProgressEmit(unittest.TestCase):
    def _streamer(self):
        from client_remote_desktop import RemoteDesktopStreamer
        rd = RemoteDesktopStreamer(api_client=None, token_getter=lambda: "tok")
        rd._stream_id = "abc123"
        rd._command_id = "cmd-1"
        return rd

    def test_payload_shape(self):
        rd = self._streamer()
        with mock.patch.object(rd, "_q_put_text") as q:
            ok = rd.emit_stream_progress("running", "hello", force=True)
        self.assertTrue(ok)
        raw = q.call_args[0][0]
        payload = json.loads(raw)
        self.assertEqual(payload["t"], "stream_progress")
        self.assertEqual(payload["protocol"], 1)
        self.assertEqual(payload["stream_id"], "abc123")
        self.assertEqual(payload["command_id"], "cmd-1")
        self.assertEqual(payload["phase"], "running")
        self.assertEqual(payload["message"], "hello")
        self.assertIn("ts", payload)

    def test_failed_includes_error(self):
        rd = self._streamer()
        with mock.patch.object(rd, "_q_put_text") as q:
            rd.emit_stream_progress(
                "failed", "no desk", error="CAPTURE_NO_DESKTOP", force=True
            )
        payload = json.loads(q.call_args[0][0])
        self.assertEqual(payload["error"], "CAPTURE_NO_DESKTOP")

    def test_rate_limit_four_per_second(self):
        rd = self._streamer()
        phases = ["ice", "dtls", "webrtc", "channel_open", "encoding", "streaming"]
        with mock.patch.object(rd, "_q_put_text") as q:
            for phase in phases:
                rd.emit_stream_progress(phase, f"tick-{phase}")
        # First 4 ok; 5th/6th dropped within same second
        self.assertEqual(q.call_count, 4)

    def test_no_live_for_black_fill(self):
        rd = self._streamer()
        rd._capture_method = "bitblt+black"
        with mock.patch.object(rd, "_q_put_text") as q:
            ok = rd.emit_stream_progress("live", "should not", force=True)
        self.assertFalse(ok)
        q.assert_not_called()

    def test_control_ws_fallback(self):
        rd = self._streamer()
        seen = []
        rd.set_control_progress_sender(lambda p: seen.append(p) or True)
        with mock.patch.object(rd, "_q_put_text"):
            rd.emit_stream_progress("running", "via ctrl", force=True)
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0]["t"], "stream_progress")

    def test_heartbeat_emits_when_silent(self):
        rd = self._streamer()
        rd._running = True
        rd._progress_last_emit = time.time() - 5.0
        rd._stats["frames_sent"] = 0
        with mock.patch.object(rd, "emit_stream_progress") as em:
            rd._progress_heartbeat_tick()
        em.assert_called()
        self.assertEqual(em.call_args[0][0], "capturing")


if __name__ == "__main__":
    unittest.main()
