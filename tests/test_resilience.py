#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SR-001/002 unit tests — no SCM or live service required."""

import os
import tempfile
import time
import unittest
from unittest import mock

import client_resilience as resilience


class TestResilienceStormBreaker(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)
        self.state_path = os.path.join(self._tmpdir.name, "resilience_state.json")
        self._patches = [
            mock.patch.object(resilience, "STATE_FILE", self.state_path),
            mock.patch.object(resilience, "STORM_WINDOW_SEC", 60),
            mock.patch.object(resilience, "STORM_THRESHOLD", 3),
            mock.patch.object(
                resilience, "RECOVERY_BACKOFF_SEC", [1, 2, 4, 8, 16]
            ),
        ]
        for p in self._patches:
            p.start()
            self.addCleanup(p.stop)
        with resilience._lock:
            resilience._state = {
                "version": "test",
                "daemon_restarts": [],
                "guardian_restarts": [],
                "last_recovery_ms": 0,
                "last_recovery_leg": "",
                "last_recovery_ok": False,
                "restart_storm": False,
                "stand_down_reason": "",
                "binary_integrity": "unknown",
                "guardian_exit_code": None,
            }

    def test_backoff_after_repeated_failures(self):
        now = time.time()
        with mock.patch.object(resilience, "_now", return_value=now):
            for _ in range(3):
                resilience.record_recovery_attempt(
                    "daemon", ok=False, duration_ms=100
                )
            allowed, wait = resilience.should_attempt_recovery("daemon")
        self.assertFalse(allowed)
        self.assertGreater(wait, 0)
        snap = resilience.snapshot()
        self.assertTrue(snap["restart_storm"])
        self.assertEqual(snap["daemon_restarts_24h"], 3)

    def test_stand_down_clears_storm_flag(self):
        resilience.record_recovery_attempt("daemon", ok=False, duration_ms=10)
        resilience.note_stand_down("update_or_operator_stop")
        snap = resilience.snapshot()
        # Contract 1.4.2 enum: update | operator_pin | uninstall | null
        self.assertEqual(snap["stand_down_reason"], "update")
        self.assertFalse(snap["restart_storm"])

    def test_stand_down_reason_normalizes_to_contract_enum(self):
        for raw, expected in [
            ("update", "update"),
            ("operator_pin", "operator_pin"),
            ("pin_stop", "operator_pin"),
            ("uninstall", "uninstall"),
            ("something_update_related", "update"),
        ]:
            resilience.note_stand_down(raw)
            self.assertEqual(resilience.snapshot()["stand_down_reason"], expected)
        resilience.clear_stand_down()
        self.assertIsNone(resilience.snapshot()["stand_down_reason"])

    def test_snapshot_includes_draft_fields(self):
        snap = resilience.snapshot(
            guardian_installed=True, guardian_running=False
        )
        for key in (
            "guardian_installed",
            "guardian_running",
            "daemon_restarts_24h",
            "guardian_restarts_24h",
            "last_recovery_ms",
            "restart_backoff_sec",
            "restart_storm",
            "binary_integrity",
        ):
            self.assertIn(key, snap)
        self.assertTrue(snap["guardian_installed"])
        self.assertFalse(snap["guardian_running"])

    def test_normalize_heals_test_version_and_sticky_ok(self):
        with resilience._lock:
            resilience._state["version"] = "test"
            resilience._state["last_recovery_ok"] = False
            resilience._state["last_recovery_ms"] = 50
            resilience._state["restart_storm"] = False
            resilience._state["daemon_restarts"] = [time.time()]
        self.assertTrue(resilience._normalize_state(persist=True))
        with open(self.state_path, "r", encoding="utf-8") as fh:
            disk = __import__("json").load(fh)
        self.assertEqual(disk["version"], resilience.VERSION)
        self.assertTrue(disk["last_recovery_ok"])


if __name__ == "__main__":
    unittest.main()
