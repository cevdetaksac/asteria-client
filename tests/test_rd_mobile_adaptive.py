#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Deterministic rd4 mobile protocol and rd5 adaptive-stream tests."""

import json
import unittest

from client_rd_adaptive import AdaptiveStreamController
from client_remote_desktop import RemoteDesktopStreamer, normalize_stream_knobs


class FakeClock:
    def __init__(self):
        self.value = 0.0

    def __call__(self):
        return self.value

    def advance(self, seconds):
        self.value += float(seconds)


def make_streamer():
    rd = RemoteDesktopStreamer()
    rd._running = True
    rd._screen_w, rd._screen_h = 1920, 1080
    rd._capture_w, rd._capture_h = 1280, 720
    rd.mouse = []
    rd.moves = []
    rd.wheels = []
    rd.hwheels = []
    rd._emit_mouse_button = (
        lambda px, py, flag: rd.mouse.append((px, py, flag))
    )
    rd._emit_set_cursor = lambda px, py: rd.moves.append((px, py))
    rd._emit_mouse_move_relative = lambda dx, dy: rd.moves.append((dx, dy))
    rd._emit_mouse_wheel = lambda px, py, delta: rd.wheels.append(delta)
    rd._emit_mouse_hwheel = lambda px, py, delta: rd.hwheels.append(delta)
    return rd


class TestProtocolV2(unittest.TestCase):
    def test_versioned_envelope_preserves_id_and_legacy_still_works(self):
        rd = make_streamer()
        result = rd.apply_input({
            "protocol": 2,
            "id": "evt-7",
            "ts": 12345,
            "input": {"gesture": "tap", "x": 0.25, "y": 0.5},
        })
        self.assertTrue(result["success"])
        self.assertEqual(result["id"], "evt-7")
        self.assertEqual(result["protocol"], 2)
        self.assertTrue(rd.apply_input({
            "event": "click", "x": 0.2, "y": 0.3,
        })["success"])

    def test_ws_protocol_v2_queues_result_ack(self):
        rd = make_streamer()
        rd._on_ws_message(json.dumps({
            "t": "input",
            "protocol": 2,
            "id": 99,
            "input": {"event": "tap", "x": 0.5, "y": 0.5},
        }))
        messages = [json.loads(item) for item in rd._pending_text]
        ack = next(item for item in messages if item.get("t") == "input_ack")
        self.assertEqual(ack["id"], 99)
        self.assertTrue(ack["success"])

    def test_coalesced_moves_acknowledge_all_ids(self):
        rd = make_streamer()
        rd._ingest_events([
            {"protocol": 2, "id": "a", "event": "move", "x": 0.1, "y": 0.1},
            {"protocol": 2, "id": "b", "event": "move", "x": 0.2, "y": 0.2},
        ], emit_ack=True)
        ids = [
            json.loads(item).get("id")
            for item in rd._pending_text
            if json.loads(item).get("t") == "input_ack"
        ]
        self.assertEqual(ids, ["a", "b"])


class TestMobileGestures(unittest.TestCase):
    def test_tap_double_tap_and_long_press(self):
        rd = make_streamer()
        rd.apply_input({"event": "tap", "x": 0.5, "y": 0.5})
        self.assertEqual([flag for _, _, flag in rd.mouse], [0x0002, 0x0004])
        rd.mouse.clear()
        rd.apply_input({"event": "double_tap", "x": 0.5, "y": 0.5})
        self.assertEqual(
            [flag for _, _, flag in rd.mouse],
            [0x0002, 0x0004, 0x0002, 0x0004],
        )
        rd.mouse.clear()
        rd.apply_input({"event": "long_press", "x": 0.5, "y": 0.5})
        self.assertEqual([flag for _, _, flag in rd.mouse], [0x0008, 0x0010])

    def test_drag_duplicate_start_and_end_without_start_are_safe(self):
        rd = make_streamer()
        self.assertTrue(rd.apply_input({
            "event": "drag_end", "x": 0.1, "y": 0.1,
        })["success"])
        self.assertEqual(rd.mouse, [])
        rd.apply_input({"event": "drag_start", "x": 0.1, "y": 0.1})
        rd.apply_input({"event": "drag_start", "x": 0.2, "y": 0.2})
        rd.apply_input({"event": "drag_move", "x": 0.3, "y": 0.3})
        rd.apply_input({"event": "drag_end", "x": 0.4, "y": 0.4})
        rd.apply_input({"event": "drag_end", "x": 0.5, "y": 0.5})
        flags = [flag for _, _, flag in rd.mouse]
        self.assertEqual(flags.count(0x0002), 1)
        self.assertEqual(flags.count(0x0004), 1)
        self.assertFalse(rd._drag_active)

    def test_drag_forced_release_on_stop(self):
        rd = make_streamer()
        rd.apply_input({"event": "drag_start", "x": 0.1, "y": 0.1})
        rd.stop()
        self.assertIn(0x0004, [flag for _, _, flag in rd.mouse])
        self.assertFalse(rd._drag_active)

    def test_trackpad_relative_and_two_finger_scroll(self):
        rd = make_streamer()
        rd.apply_input({
            "event": "trackpad_move", "mode": "trackpad", "dx": 8, "dy": -4,
        })
        self.assertEqual(rd.moves[-1], (8, -4))
        rd.apply_input({
            "event": "two_finger_scroll",
            "deltaX": 30,
            "deltaY": 50,
        })
        self.assertEqual(rd.wheels[-1], -50)
        self.assertEqual(rd.hwheels[-1], -30)

    def test_gesture_edges_bound_move_coalescing(self):
        events = RemoteDesktopStreamer._coalesce_events([
            {"event": "drag_start", "x": 0.1, "y": 0.1},
            {"event": "drag_move", "x": 0.2, "y": 0.2},
            {"event": "drag_move", "x": 0.3, "y": 0.3},
            {"event": "drag_end", "x": 0.4, "y": 0.4},
        ])
        self.assertEqual(
            [item["event"] for item in events],
            ["drag_start", "drag_move", "drag_end"],
        )
        self.assertEqual(events[1]["x"], 0.3)


class TestMonitorOrigin(unittest.TestCase):
    def test_normalized_coordinates_include_negative_origin(self):
        rd = make_streamer()
        rd._screen_x, rd._screen_y = -1920, -200
        rd._screen_w, rd._screen_h = 1920, 1080
        self.assertEqual(rd._norm_to_px(0.0, 0.0), (-1920, -200))
        self.assertEqual(rd._norm_to_px(1.0, 1.0), (-1, 879))
        px, py = rd._norm_to_px(0.5, 0.5)
        self.assertTrue(-962 <= px <= -960)
        self.assertTrue(338 <= py <= 340)

    def test_origin_present_in_status_and_meta(self):
        rd = make_streamer()
        rd._screen_x, rd._screen_y = -1280, 50
        rd._last_capture_mono = 12.5
        status = rd.get_status()
        self.assertEqual(status["screen"]["x"], -1280)
        self.assertEqual(status["screen"]["y"], 50)
        rd._enqueue_meta(force=True)
        meta = json.loads(rd._pending_text[-1])
        self.assertEqual((meta["origin_x"], meta["origin_y"]), (-1280, 50))
        self.assertEqual(meta["capture_mono_ms"], 12500)

    def test_helper_frame_origin_updates_injection_rectangle(self):
        rd = make_streamer()

        class Mailbox:
            connected = True

            def wait_frame(self, after_id, timeout):
                return (
                    1,
                    b"\xff\xd8x\xff\xd9",
                    {
                        "width": 800,
                        "height": 450,
                        "native_width": 1600,
                        "native_height": 900,
                        "origin_x": -1600,
                        "origin_y": 100,
                    },
                )

        rd._session_helper = Mailbox()
        rd._grab_via_persistent_helper()
        self.assertEqual((rd._screen_x, rd._screen_y), (-1600, 100))
        self.assertEqual(rd._norm_to_px(0, 0), (-1600, 100))


class TestAdaptiveController(unittest.TestCase):
    def make(self):
        clock = FakeClock()
        controller = AdaptiveStreamController(
            24, 60, 1600,
            clock=clock,
            degrade_cooldown=5,
            stable_window=20,
        )
        return clock, controller

    def test_coalescing_does_not_count_as_congestion(self):
        _clock, controller = self.make()
        controller.note_coalesced(8)
        self.assertIsNone(controller.evaluate())
        self.assertEqual(controller.effective["fps"], 24)
        self.assertEqual(controller.metrics["coalesced_frames"], 8)

    def test_degrades_under_backpressure(self):
        _clock, controller = self.make()
        controller.note_ws_failure()
        changed = controller.evaluate()
        self.assertIsNotNone(changed)
        self.assertLess(changed["fps"], 24)
        self.assertLess(changed["quality"], 60)
        # Resolution must stay locked — dashboard UX.
        self.assertEqual(changed["max_width"], 1600)
        self.assertEqual(controller.metrics["degrades"], 1)

    def test_no_oscillation_inside_cooldown(self):
        clock, controller = self.make()
        controller.note_ws_failure()
        first = controller.evaluate()
        controller.note_ws_failure()
        clock.advance(1)
        second = controller.evaluate()
        self.assertIsNotNone(first)
        self.assertIsNone(second)
        self.assertEqual(controller.metrics["degrades"], 1)

    def test_recovers_gradually_after_stable_window(self):
        clock, controller = self.make()
        controller.note_ws_failure()
        degraded = controller.evaluate()
        clock.advance(21)
        recovered = controller.evaluate()
        self.assertIsNotNone(recovered)
        self.assertGreater(recovered["quality"], degraded["quality"])
        self.assertLessEqual(recovered["quality"], 60)
        self.assertEqual(recovered["max_width"], 1600)
        self.assertEqual(controller.metrics["recovers"], 1)

    def test_width_floor_is_1280(self):
        controller = AdaptiveStreamController(24, 60, 400)
        self.assertEqual(controller.effective["max_width"], 1280)

    def test_telemetry_records_capture_send_and_failures(self):
        _clock, controller = self.make()
        controller.observe_capture(0.2)
        controller.observe_send(0.9, transport="http", ok=False)
        snap = controller.snapshot()
        metrics = snap["metrics"]
        self.assertEqual(metrics["capture_samples"], 1)
        self.assertEqual(metrics["send_samples"], 1)
        self.assertEqual(metrics["http_failures"], 1)
        self.assertGreater(metrics["capture_ms_ewma"], 0)

    def test_effective_update_notifies_persistent_helper(self):
        rd = make_streamer()

        class Helper:
            connected = True

            def __init__(self):
                self.configs = []

            def update_config(self, config):
                self.configs.append(config)
                return True

        helper = Helper()
        rd._session_helper = helper
        rd._apply_effective_settings({
            "fps": 4.0, "quality": 30, "max_width": 900,
        })
        self.assertEqual(rd.get_status()["effective"]["fps"], 4.0)
        self.assertEqual(helper.configs[-1]["max_width"], 900)


class TestNormalizeStreamKnobs(unittest.TestCase):
    def test_legacy_dashboard_slideshow_is_lifted_to_video(self):
        fps, quality, width = normalize_stream_knobs(12, 40, 800)
        self.assertEqual(fps, 30.0)
        self.assertEqual(quality, 72)
        self.assertEqual(width, 1920)

    def test_high_knobs_are_clamped(self):
        fps, quality, width = normalize_stream_knobs(120, 99, 3840)
        self.assertEqual(fps, 60.0)
        self.assertEqual(quality, 90)
        self.assertEqual(width, 1920)


class TestEncodeSizeLock(unittest.TestCase):
    def test_locks_first_frame_size_for_session(self):
        rd = RemoteDesktopStreamer()
        first = rd._resolve_encode_size(1920, 1080, 1280)
        second = rd._resolve_encode_size(1920, 1080, 900)  # adaptive shrink ignored
        self.assertEqual(first, (1280, 720))
        self.assertEqual(second, (1280, 720))

    def test_upgrades_lock_when_real_monitor_appears(self):
        rd = RemoteDesktopStreamer()
        rd._winlogon_mode = False
        first = rd._resolve_encode_size(1024, 768, 1920)
        self.assertEqual(first, (1024, 768))
        second = rd._resolve_encode_size(1920, 1080, 1920)
        self.assertEqual(second, (1920, 1080))

    def test_min_floor_1280x720_when_source_allows(self):
        rd = RemoteDesktopStreamer()
        w, h = rd._compute_encode_size(1920, 1080, 800)
        self.assertGreaterEqual(w, 1280)
        self.assertGreaterEqual(h, 720)
        w2, h2 = rd._compute_encode_size(1600, 1200, 800)
        self.assertEqual((w2, h2), (1280, 960))


if __name__ == "__main__":
    unittest.main()
