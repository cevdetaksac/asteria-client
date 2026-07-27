#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for stuck update / brick recovery."""

import os
import tempfile
import time
import unittest
from unittest import mock

import client_update_recovery as ur


class TestDiagnoseAndAbort(unittest.TestCase):
    def setUp(self):
        self._tdir = tempfile.mkdtemp()
        self._lock = os.path.join(self._tdir, "update_in_progress.lock")
        self._patches = [
            mock.patch.object(ur, "_lock_path", return_value=self._lock),
            mock.patch.object(ur, "_programdata_asteria", return_value=self._tdir),
            mock.patch.object(ur, "_motor_healthy", return_value=False),
            mock.patch.object(ur, "_helper_recently_started", return_value=False),
            mock.patch.object(ur, "_pid_alive", return_value=False),
            mock.patch.object(ur, "_pid_looks_like_ours", return_value=False),
        ]
        for p in self._patches:
            p.start()

    def tearDown(self):
        for p in self._patches:
            p.stop()
        try:
            if os.path.isfile(self._lock):
                os.remove(self._lock)
            os.rmdir(self._tdir)
        except OSError:
            pass

    def _write_lock(self, phase="silent-download", pid=999999, started=None, mtime_age=120.0):
        started = time.time() - (started if started is not None else mtime_age)
        with open(self._lock, "w", encoding="utf-8") as fh:
            fh.write(f"{phase}\n{pid}\n{started}\n")
        # Age the mtime
        past = time.time() - mtime_age
        os.utime(self._lock, (past, past))

    def test_orphan_lock_detected_as_stuck(self):
        self._write_lock(mtime_age=60)
        diag = ur.diagnose_update_state()
        self.assertTrue(diag["stuck"])
        self.assertTrue(any("orphan" in r for r in diag["reasons"]))

    def test_abort_clears_lock_and_resumes(self):
        self._write_lock(mtime_age=120)
        with mock.patch("client_utils.release_update_lock") as rel, \
             mock.patch("client_resilience.clear_stand_down") as clr, \
             mock.patch("client_update_ui.set_update_ui_status") as set_ui, \
             mock.patch("client_daemon_ipc.ensure_daemon_running", return_value=True) as ens:
            result = ur.abort_stuck_update(reason="test_abort", resume_motor=True, force=True)
        self.assertTrue(result["aborted"])
        rel.assert_called()
        clr.assert_called()
        set_ui.assert_called()
        ens.assert_called()

    def test_not_stuck_skips_without_force(self):
        # No lock file
        diag = ur.diagnose_update_state()
        self.assertFalse(diag["stuck"])
        result = ur.abort_stuck_update(force=False)
        self.assertFalse(result.get("aborted"))

    def test_motor_down_with_stale_lock(self):
        self._write_lock(phase="silent-download", mtime_age=100)
        # Pretend PID is somehow alive but foreign — still stuck via motor_down
        with mock.patch.object(ur, "_pid_alive", return_value=True), \
             mock.patch.object(ur, "_pid_looks_like_ours", return_value=True):
            diag = ur.diagnose_update_state()
        self.assertTrue(diag["stuck"])
        self.assertTrue(any("motor_down" in r for r in diag["reasons"]))

    def test_maybe_auto_recover_calls_abort(self):
        self._write_lock(mtime_age=120)
        with mock.patch.object(ur, "abort_stuck_update", return_value={"aborted": True}) as ab:
            ok = ur.maybe_auto_recover_stuck_update()
        self.assertTrue(ok)
        ab.assert_called()


class TestFinalizeClearedLock(unittest.TestCase):
    def test_is_update_in_progress_finalizes_dead_pid(self):
        import client_utils as cu

        tdir = tempfile.mkdtemp()
        lock = os.path.join(tdir, "update_in_progress.lock")
        with open(lock, "w", encoding="utf-8") as fh:
            fh.write("silent-download\n1\n1.0\n")
        past = time.time() - 30
        os.utime(lock, (past, past))

        with mock.patch.object(cu, "_update_lock_path", return_value=lock), \
             mock.patch.object(cu, "_finalize_cleared_update_lock") as fin:
            # PID 1 may or may not be alive on Windows — force dead
            with mock.patch("ctypes.windll.kernel32.OpenProcess", return_value=0):
                alive = cu.is_update_in_progress()
        self.assertFalse(alive)
        self.assertFalse(os.path.isfile(lock))
        fin.assert_called()
        try:
            os.rmdir(tdir)
        except OSError:
            pass


if __name__ == "__main__":
    unittest.main()
