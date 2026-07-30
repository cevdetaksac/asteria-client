#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Single-flight operation gate — no stacked UPDATE-family ops."""

from __future__ import annotations

import os
import tempfile
import unittest
from unittest import mock


class TestOperationGate(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.mkdtemp(prefix="asteria_gate_test_")
        self._gate = os.path.join(self._tmpdir, "operation_gate.json")
        self._p1 = mock.patch(
            "client_operation_gate._gate_path",
            return_value=self._gate,
        )
        self._p2 = mock.patch(
            "client_operation_gate.acquire_update_lock",
            create=True,
        )
        # Patch the import target used inside try_acquire/release
        self._p3 = mock.patch("client_utils.acquire_update_lock", return_value=True)
        self._p4 = mock.patch("client_utils.release_update_lock")
        self._p5 = mock.patch("client_utils.is_update_in_progress", return_value=False)
        self._p1.start()
        self._p3.start()
        self._p4.start()
        self._p5.start()
        from client_operation_gate import force_clear

        force_clear(resume_updaters=False)

    def tearDown(self):
        try:
            from client_operation_gate import force_clear

            force_clear(resume_updaters=False)
        except Exception:
            pass
        for p in (self._p1, self._p3, self._p4, self._p5):
            try:
                p.stop()
            except Exception:
                pass
        try:
            import shutil

            shutil.rmtree(self._tmpdir, ignore_errors=True)
        except Exception:
            pass

    def test_second_acquire_returns_busy_snapshot(self):
        from client_operation_gate import (
            try_acquire,
            release,
            touch,
            busy_result_from_snapshot,
            snapshot,
        )

        ok1, info1 = try_acquire("self_update", to_version="4.9.68")
        self.assertTrue(ok1)
        self.assertTrue(info1.get("token"))

        touch(phase="downloading", progress_pct=42, detail="mid", token=info1["token"])

        ok2, info2 = try_acquire("silent_update", to_version="4.9.69")
        self.assertFalse(ok2)
        self.assertTrue(info2.get("busy"))
        self.assertEqual(info2.get("phase"), "downloading")
        self.assertEqual(int(info2.get("progress_pct") or 0), 42)

        busy = busy_result_from_snapshot(info2)
        self.assertTrue(busy.get("busy"))
        self.assertEqual(busy.get("error"), "busy")
        self.assertTrue(busy.get("in_flight"))

        snap = snapshot()
        self.assertIsNotNone(snap)
        self.assertEqual(snap.get("op"), "self_update")

        self.assertTrue(release(info1["token"], resume_updaters=False))
        self.assertIsNone(snapshot())

        ok3, _ = try_acquire("gui_self_update")
        self.assertTrue(ok3)

    def test_force_reclaims_holder(self):
        from client_operation_gate import try_acquire, snapshot

        ok1, info1 = try_acquire("self_update")
        self.assertTrue(ok1)
        ok2, info2 = try_acquire("self_update", force=True)
        self.assertTrue(ok2)
        self.assertNotEqual(info1.get("token"), info2.get("token"))
        snap = snapshot()
        self.assertEqual(snap.get("token"), info2.get("token"))

    def test_run_self_update_busy_short_circuit(self):
        from client_operation_gate import try_acquire
        from client_updater import run_self_update_command

        ok, info = try_acquire("self_update", to_version="4.9.68", detail="holder")
        self.assertTrue(ok)
        try:
            out = run_self_update_command({"tag": "v4.9.69", "force": False})
            self.assertFalse(out.get("ok"))
            self.assertTrue(out.get("busy"))
            self.assertEqual(out.get("error"), "busy")
            self.assertTrue(out.get("in_flight"))
        finally:
            from client_operation_gate import release

            release(info["token"], resume_updaters=False)


if __name__ == "__main__":
    unittest.main()
