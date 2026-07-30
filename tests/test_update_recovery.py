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

    def test_abort_clears_banner_when_motor_ok(self):
        self._write_lock(mtime_age=120)
        with mock.patch("client_utils.release_update_lock"), \
             mock.patch("client_resilience.clear_stand_down"), \
             mock.patch("client_update_ui.set_update_ui_status"), \
             mock.patch("client_update_ui.clear_update_ui_status") as clr, \
             mock.patch.object(ur, "_motor_healthy", side_effect=[False, True, True]), \
             mock.patch("client_daemon_ipc.ensure_daemon_running", return_value=True):
            result = ur.abort_stuck_update(
                reason="operator_recover", resume_motor=True, force=True
            )
        self.assertTrue(result["aborted"])
        self.assertTrue(result["motor_ok"])
        clr.assert_called()

    def test_abort_keeps_failed_when_motor_still_down(self):
        self._write_lock(mtime_age=120)
        with mock.patch("client_utils.release_update_lock"), \
             mock.patch("client_resilience.clear_stand_down"), \
             mock.patch("client_update_ui.set_update_ui_status") as set_ui, \
             mock.patch("client_update_ui.clear_update_ui_status") as clr, \
             mock.patch.object(ur, "_motor_healthy", return_value=False), \
             mock.patch("client_daemon_ipc.ensure_daemon_running", return_value=False):
            result = ur.abort_stuck_update(
                reason="operator_recover", resume_motor=True, force=True
            )
        self.assertTrue(result["aborted"])
        self.assertFalse(result["motor_ok"])
        set_ui.assert_called()
        clr.assert_not_called()

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

    def test_finalize_clears_banner_if_motor_healthy(self):
        import client_utils as cu

        with mock.patch("client_resilience.clear_stand_down"), \
             mock.patch.object(cu, "resume_competing_updaters"), \
             mock.patch("client_daemon_ipc.is_motor_healthy", return_value=True), \
             mock.patch("client_update_ui.clear_update_ui_status") as clr, \
             mock.patch("client_update_ui._read_raw", return_value={
                 "phase": "failed", "from_version": "4.9.54", "to_version": "4.9.61",
             }), \
             mock.patch("client_update_ui.set_update_ui_status") as set_ui:
            cu._finalize_cleared_update_lock("orphan_lock_dead_pid")
        clr.assert_called()
        set_ui.assert_not_called()


class TestSelfUpdatePreempt(unittest.TestCase):
    def test_preempts_orphan_without_force(self):
        from client_updater import run_self_update_command

        calls = {"abort": 0}
        iup_iter = iter([True, False])

        def _abort(**kwargs):
            calls["abort"] += 1
            return {"aborted": True, "ok": True}

        with mock.patch("client_updater._current_installed_version", return_value="4.9.54"), \
             mock.patch("client_utils.heal_update_machinery"), \
             mock.patch(
                 "client_utils.is_update_in_progress",
                 side_effect=lambda *a, **k: next(iup_iter, False),
             ), \
             mock.patch(
                 "client_update_recovery.diagnose_update_state",
                 return_value={
                     "stuck": True,
                     "actionable": True,
                     "reasons": ["orphan_lock_dead_or_foreign_pid"],
                     "motor_ok": False,
                 },
             ), \
             mock.patch("client_update_recovery.abort_stuck_update", side_effect=_abort), \
             mock.patch("client_utils.acquire_update_lock", return_value=True), \
             mock.patch("client_utils.pause_competing_updaters"), \
             mock.patch(
                 "client_updater._is_allowed_update_url", return_value=True
             ), \
             mock.patch(
                 "client_updater.download_installer_complete",
                 return_value=(False, "stop_early"),
             ), \
             mock.patch("client_utils.release_update_lock"), \
             mock.patch("client_updater._lifecycle_fail"), \
             mock.patch("client_update_ui.set_update_ui_status"):
            out = run_self_update_command(
                {
                    "tag": "4.9.62",
                    "download_url": (
                        "https://github.com/cevdetaksac/asteria-client/"
                        "releases/download/v4.9.62/cloud-client-installer.exe"
                    ),
                    "force": False,
                },
                api_client=None,
            )
        self.assertEqual(calls["abort"], 1)
        self.assertEqual(out.get("error"), "download_failed")


if __name__ == "__main__":
    unittest.main()
