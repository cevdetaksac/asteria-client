#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Focused rd2 (transport) + rd3 (input v2) tests.

These exercise the transport decision, latest-frame queue, input budgets,
move coalescing, relative movement and stuck-button release without needing a
real Windows desktop session (all injection primitives are stubbed).
"""

import time
import unittest

from client_remote_desktop import (
    MOVE_RATE_LIMIT,
    RemoteDesktopStreamer,
)


JPEG = b"\xff\xd8" + (b"z" * 4000) + b"\xff\xd9"


class FakeApi:
    base_url = "https://example.test/api"

    def __init__(self):
        self.uploads = []
        self.input_polls = 0

    def upload_remote_frame(self, token, jpeg_bytes, width, height, seq, fps):
        self.uploads.append({"seq": seq, "len": len(jpeg_bytes)})
        return {"ok": True, "inputs": []}

    def fetch_remote_inputs(self, token, limit=80):
        self.input_polls += 1
        return []


class FakeWS:
    def __init__(self):
        self.sent = []  # list of (payload, opcode)

    def send(self, data, opcode=None):
        self.sent.append((data, opcode))


class FakeMailbox:
    """Stand-in for PersistentSessionHelper on the daemon side."""

    connected = True

    def __init__(self):
        self.events = []  # (event_dict, wait_flag)

    def send_input(self, event, wait=False, timeout=0.2):
        self.events.append((event, wait))
        return True


class FakeConnectedMedia:
    available = True
    active = True

    def __init__(self):
        self.frames = []

    def publish_frame(self, jpeg, metadata=None):
        self.frames.append((jpeg, metadata))
        return True

    def publish_raw(self, rgb, width, height, metadata=None):
        self.frames.append(("raw", width, height, metadata))
        return True

    def status(self):
        return {
            "available": True,
            "active": True,
            "connection_state": "connected",
            "ice_state": "completed",
            "codec": "H264",
        }

    def capabilities(self):
        return {"webrtc": True, "codecs": ["H264"]}

    def stop(self):
        return None


def _make(running=True, api=None):
    rd = RemoteDesktopStreamer(api_client=api, token_getter=lambda: "tok")
    rd._running = running
    rd._screen_w, rd._screen_h = 1920, 1080
    rd._capture_w, rd._capture_h = 1280, 720
    return rd


class TestTransportSelection(unittest.TestCase):
    def test_requested_jpeg_fps_is_not_clamped_to_ten(self):
        rd = _make()
        rd._requested_fps = 30.0
        rd._adaptive.reset(30.0, 60, 1280)
        rd._apply_effective_settings(
            rd._adaptive.effective, notify_helper=False
        )
        self.assertEqual(rd._adaptive.requested["fps"], 30.0)
        self.assertEqual(rd._fps, 30.0)

    def test_connected_media_drops_pending_jpeg_and_skips_ws_http(self):
        api = FakeApi()
        media = FakeConnectedMedia()
        rd = RemoteDesktopStreamer(
            api_client=api, token_getter=lambda: "tok", media_transport=media
        )
        rd._running = True
        rd._ws_ok = True
        rd._pending_frame = b"stale-jpeg"
        rd._dispatch_frame("tok", JPEG, 1280, 720, 1)
        self.assertEqual(len(media.frames), 1)
        self.assertIsNone(rd._pending_frame)
        self.assertEqual(api.uploads, [])
        self.assertEqual(rd._transport, "webrtc")

    def test_ws_flush_never_sends_binary_while_media_connected(self):
        rd = RemoteDesktopStreamer(
            api_client=FakeApi(),
            token_getter=lambda: "tok",
            media_transport=FakeConnectedMedia(),
        )
        rd._running = True
        rd._q_put_text('{"t":"meta"}')
        rd._q_put_frame(JPEG)
        ws = FakeWS()
        rd._ws_flush_out(ws)
        self.assertTrue(ws.sent)
        self.assertTrue(all(opcode is None for _payload, opcode in ws.sent))
        self.assertIsNone(rd._pending_frame)

    def test_media_capture_settings_ignore_jpeg_fps_quality(self):
        rd = RemoteDesktopStreamer(
            api_client=FakeApi(),
            token_getter=lambda: "tok",
            media_transport=FakeConnectedMedia(),
        )
        rd._fps = 4.0
        rd._quality = 25
        fps, quality, _width = rd._effective_capture_settings()
        self.assertEqual(fps, 45.0)
        self.assertEqual(quality, 78)

    def test_ws_healthy_sends_no_http(self):
        api = FakeApi()
        rd = _make(api=api)
        rd._ws_ok = True
        rd._dispatch_frame("tok", JPEG, 1280, 720, 1)
        self.assertEqual(api.uploads, [])                 # no duplicate HTTP
        self.assertEqual(rd._pending_frame, JPEG)         # buffered for WS thread
        self.assertEqual(rd._transport, "websocket")
        self.assertEqual(rd._stats["frames_sent"], 0)     # queueing != transmission

    def test_http_fallback_when_ws_down(self):
        api = FakeApi()
        rd = _make(api=api)
        rd._ws_ok = False
        rd._dispatch_frame("tok", JPEG, 1280, 720, 1)
        self.assertEqual(len(api.uploads), 1)
        self.assertEqual(rd._transport, "http")
        self.assertEqual(rd._stats["frames_sent"], 1)
        self.assertEqual(rd._stats["http_fallbacks"], 1)

    def test_ws_send_counts_only_on_actual_send(self):
        rd = _make()
        rd._ws_ok = True
        rd._enqueue_meta(force=True)     # control/meta (text)
        rd._q_put_frame(JPEG)            # latest frame (binary)
        ws = FakeWS()
        rd._ws_flush_out(ws)
        # Text/control flushed before the binary frame.
        self.assertIsNone(ws.sent[0][1])                       # first is text
        self.assertEqual(ws.sent[-1][0], JPEG)                 # last is the frame
        self.assertEqual(ws.sent[-1][1], rd._ws_binary_opcode())
        self.assertEqual(rd._stats["frames_sent"], 1)
        self.assertEqual(rd._stats["bytes_sent"], len(JPEG))


class TestLatestFrameQueue(unittest.TestCase):
    def test_stale_frame_is_coalesced(self):
        rd = _make()
        rd._q_put_frame(b"A")
        rd._q_put_frame(b"B")
        self.assertEqual(rd._pending_frame, b"B")
        self.assertEqual(rd._stats["frames_coalesced"], 1)

    def test_control_messages_are_retained_in_order(self):
        rd = _make()
        rd._ws_ok = True
        rd._q_put_text("m1")
        rd._q_put_text("m2")
        rd._q_put_frame(JPEG)
        ws = FakeWS()
        rd._ws_flush_out(ws)
        payloads = [d for (d, _op) in ws.sent]
        self.assertEqual(payloads[:2], ["m1", "m2"])
        self.assertEqual(ws.sent[-1][0], JPEG)


class TestCriticalEdgeNonDrop(unittest.TestCase):
    def test_moves_limited_but_critical_never_dropped(self):
        rd = _make()
        rd._use_user_helper = True
        mb = FakeMailbox()
        rd._session_helper = mb

        limited = 0
        for _ in range(MOVE_RATE_LIMIT + 20):
            r = rd.apply_input({"event": "move", "x": 0.5, "y": 0.5})
            if not r.get("success"):
                limited += 1
        self.assertGreater(limited, 0)  # move budget enforced

        # A critical edge after the move flood must still be accepted.
        r = rd.apply_input({"event": "mousedown", "x": 0.1, "y": 0.1, "button": "left"})
        self.assertTrue(r["success"])

        downs = [(e, w) for (e, w) in mb.events if e.get("event") == "mousedown"]
        self.assertTrue(downs)
        # Critical edges forwarded with a (short) ACK; moves are fire-and-forget.
        self.assertTrue(all(w for (_e, w) in downs))
        move_waits = [w for (e, w) in mb.events if e.get("event") == "move"]
        self.assertTrue(move_waits and not any(move_waits))

    def test_wheel_and_key_not_move_limited(self):
        rd = _make()
        rd._use_user_helper = True
        rd._session_helper = FakeMailbox()
        for _ in range(MOVE_RATE_LIMIT + 5):
            rd.apply_input({"event": "move", "x": 0.5, "y": 0.5})
        self.assertTrue(rd.apply_input({"event": "wheel", "x": 0.5, "y": 0.5, "delta": -120})["success"])
        self.assertTrue(rd.apply_input({"event": "key", "key": "enter"})["success"])


class TestMoveCoalescing(unittest.TestCase):
    def test_relative_moves_accumulate(self):
        out = RemoteDesktopStreamer._coalesce_events([
            {"event": "move_relative", "dx": 5, "dy": 1},
            {"event": "move_relative", "dx": 3, "dy": 2},
        ])
        self.assertEqual(len(out), 1)
        self.assertEqual((out[0]["dx"], out[0]["dy"]), (8, 3))

    def test_absolute_moves_keep_last_position(self):
        out = RemoteDesktopStreamer._coalesce_events([
            {"event": "move", "x": 0.1, "y": 0.1},
            {"event": "move", "x": 0.2, "y": 0.2},
        ])
        self.assertEqual(len(out), 1)
        self.assertEqual((out[0]["x"], out[0]["y"]), (0.2, 0.2))

    def test_ordering_boundaries_preserved_around_edges(self):
        out = RemoteDesktopStreamer._coalesce_events([
            {"event": "move", "x": 0.1, "y": 0.1},
            {"event": "move", "x": 0.2, "y": 0.2},
            {"event": "mousedown", "button": "left"},
            {"event": "move_relative", "dx": 4, "dy": 4},
            {"event": "mouseup", "button": "left"},
        ])
        self.assertEqual(
            [e["event"] for e in out],
            ["move", "mousedown", "move_relative", "mouseup"],
        )
        self.assertEqual((out[0]["x"], out[0]["y"]), (0.2, 0.2))


class TestRelativeMoveInjection(unittest.TestCase):
    def test_relative_move_uses_relative_emit(self):
        rd = _make()
        recorded = []
        rd._emit_mouse_move_relative = lambda dx, dy: recorded.append((dx, dy))
        r = rd.apply_input({"event": "move_relative", "dx": 6, "dy": -3})
        self.assertTrue(r["success"])
        self.assertEqual(recorded, [(6, -3)])

    def test_pointer_relative_mode(self):
        rd = _make()
        recorded = []
        rd._emit_mouse_move_relative = lambda dx, dy: recorded.append((dx, dy))
        r = rd.apply_input({"event": "pointer", "mode": "relative", "dx": 2, "dy": 9})
        self.assertTrue(r["success"])
        self.assertEqual(recorded, [(2, 9)])


class TestStuckButtonRelease(unittest.TestCase):
    def test_pressed_buttons_released_on_stop(self):
        rd = _make()
        flags = []
        rd._emit_mouse_button = lambda px, py, flag: flags.append(flag)
        rd.apply_input({"event": "mousedown", "x": 0.5, "y": 0.5, "button": "left"})
        rd.apply_input({"event": "mousedown", "x": 0.5, "y": 0.5, "button": "right"})
        self.assertEqual(rd._pressed_buttons, {"left", "right"})
        rd.stop()
        self.assertEqual(rd._pressed_buttons, set())
        self.assertIn(0x0004, flags)   # left button up
        self.assertIn(0x0010, flags)   # right button up

    def test_mouseup_clears_pressed_state(self):
        rd = _make()
        rd._emit_mouse_button = lambda px, py, flag: None
        rd.apply_input({"event": "mousedown", "x": 0.5, "y": 0.5, "button": "left"})
        self.assertIn("left", rd._pressed_buttons)
        rd.apply_input({"event": "mouseup", "x": 0.5, "y": 0.5, "button": "left"})
        self.assertNotIn("left", rd._pressed_buttons)


class TestWinlogonHelperInput(unittest.TestCase):
    def test_in_session_helper_injects_locally_not_nested(self):
        """Helper process must SendInput locally — never spawn another helper."""
        rd = _make()
        rd._winlogon_mode = True
        rd._in_session_helper = True
        rd._use_user_helper = False
        rd._session_helper = None
        calls = []
        rd._inject_local = lambda ev, p: calls.append((ev, p.get("text"))) or True
        rd._start_persistent_helper = lambda **kwargs: (_ for _ in ()).throw(
            AssertionError("must not spawn nested helper")
        )
        out = rd.apply_input({"event": "type_text", "text": "abc"})
        self.assertTrue(out.get("success"))
        self.assertEqual(calls, [("type_text", "abc")])
        self.assertEqual(rd._stats["inputs_applied"], 3)
        self.assertEqual(rd._last_input_event, "type_text")

    def test_parent_winlogon_forwards_to_helper(self):
        rd = _make()
        rd._winlogon_mode = True
        rd._in_session_helper = False
        helper = FakeMailbox()
        rd._session_helper = helper
        rd._persistent_helper_connected = lambda: True
        out = rd.apply_input({"protocol": 2, "input": {"event": "type_text", "text": "x"}})
        self.assertTrue(out.get("success"))
        self.assertEqual(len(helper.events), 1)
        forwarded, waited = helper.events[0]
        self.assertTrue(waited)
        # Parent forwards normalized-or-raw envelope; either must carry type_text.
        blob = str(forwarded)
        self.assertIn("type_text", blob)
        self.assertEqual(rd._stats["inputs_applied"], 1)
        self.assertEqual(rd._last_input_event, "type_text")

    def test_parent_syncs_helper_inputs_applied_from_ack(self):
        rd = _make()
        rd._winlogon_mode = True
        rd._in_session_helper = False
        rd._stats["inputs_applied"] = 2

        class AckHelper(FakeMailbox):
            def send_input_result(self, event, wait=False, timeout=0.2):
                self.events.append((event, wait))
                return {
                    "ok": True,
                    "inputs_applied": 5,
                    "last_input_event": "type_text",
                    "event": "type_text",
                }

        rd._session_helper = AckHelper()
        rd._persistent_helper_connected = lambda: True
        out = rd.apply_input({"event": "type_text", "text": "pw"})
        self.assertTrue(out.get("success"))
        self.assertEqual(rd._stats["inputs_applied"], 4)
        self.assertEqual(rd._last_input_event, "type_text")

    def test_parent_does_not_freeze_on_helper_tally_max(self):
        """4.9.91 lab: max(parent=260, helper=4) stuck; bullets still worked."""
        rd = _make()
        rd._winlogon_mode = True
        rd._in_session_helper = False
        rd._stats["inputs_applied"] = 260

        class AckHelper(FakeMailbox):
            def send_input_result(self, event, wait=False, timeout=0.2):
                self.events.append((event, wait))
                return {
                    "ok": True,
                    "inputs_applied": 4,
                    "last_input_event": "key",
                    "event": "key",
                }

        rd._session_helper = AckHelper()
        rd._persistent_helper_connected = lambda: True
        out = rd.apply_input({"event": "type_text", "text": "zz91"})
        self.assertTrue(out.get("success"))
        self.assertEqual(rd._stats["inputs_applied"], 264)
        self.assertEqual(rd._last_input_event, "type_text")
        out2 = rd.apply_input({"event": "key", "key": "z"})
        self.assertTrue(out2.get("success"))
        self.assertEqual(rd._stats["inputs_applied"], 265)
        self.assertEqual(rd._last_input_event, "type_text")

    def test_sync_helper_frame_telemetry_clears_stale_flat(self):
        from PIL import Image

        rd = _make()
        rd._winlogon_mode = True
        rd._capture_method = "persistent-winlogon-helper:gdi+flat"
        rd._chrome_detected = False
        rd._flat_streak_started = time.time()
        # Noisy non-flat RGB
        img = Image.new("RGB", (64, 36))
        px = img.load()
        for y in range(36):
            for x in range(64):
                px[x, y] = (x * 3 % 255, y * 7 % 255, (x + y) % 255)
        raw = img.tobytes()
        rd._sync_helper_frame_telemetry(
            {"method": "gdi+flat", "format": "rgb", "hwnd": 4, "desktop": "Winlogon"},
            payload=raw,
            width=64,
            height=36,
            fmt="rgb",
        )
        self.assertNotIn("+flat", rd._capture_method)
        self.assertTrue(rd._chrome_detected)
        self.assertEqual(rd._logonui_hwnd_count, 4)
        self.assertEqual(rd._flat_streak_started, 0.0)

    def test_protocol2_type_text_normalized(self):
        from client_remote_desktop import RemoteDesktopStreamer

        p = RemoteDesktopStreamer._normalize_input_envelope({
            "protocol": 2,
            "input": {"event": "type_text", "text": "hi"},
        })
        self.assertEqual(p.get("event"), "type_text")
        self.assertEqual(p.get("text"), "hi")


if __name__ == "__main__":
    unittest.main()
