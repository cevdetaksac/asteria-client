#!/usr/bin/env python3
"""Contract 1.4.46 — self_update progress ticks (C-UPD-PROG-1..4)."""

import time
import unittest
from unittest import mock

from client_updater import SelfUpdateProgressBus, _call_download_progress


class TestCallDownloadProgress(unittest.TestCase):
    def test_three_arg_preferred(self):
        seen = []

        def cb(pct, done=None, total=None):
            seen.append((pct, done, total))

        _call_download_progress(cb, 42, 48000, 100000)
        self.assertEqual(seen, [(42, 48000, 100000)])

    def test_legacy_one_arg(self):
        seen = []

        def cb(pct):
            seen.append(pct)

        _call_download_progress(cb, 10, 1, 2)
        self.assertEqual(seen, [10])


class TestSelfUpdateResolveOrder(unittest.TestCase):
    def test_default_url_preferred_before_github_api(self):
        """Tag-only params must not wait on GitHub API before download URL exists."""
        import inspect
        from client_updater import run_self_update_command

        src = inspect.getsource(run_self_update_command)
        constructed = src.find("using constructed release URL")
        github = src.find("GitHub resolve failed")
        self.assertGreater(constructed, 0)
        self.assertGreater(github, 0)
        # First constructed-URL path must appear before GitHub resolve log
        self.assertLess(constructed, github)


class TestSelfUpdateProgressBus(unittest.TestCase):
    def test_phase_change_emits_immediately(self):
        seen = []
        bus = SelfUpdateProgressBus(
            seen.append,
            from_version="4.9.54",
            to_version="4.9.60",
            tag="4.9.60",
            min_interval=2.0,
        )
        bus.tick("queued", progress_pct=0, force=True)
        bus.tick("downloading", progress_pct=1, bytes_done=100, bytes_total=1000, force=True)
        self.assertEqual(seen[-1]["phase"], "downloading")
        self.assertEqual(seen[-1]["status"], "running")
        self.assertEqual(seen[-1]["message"], "update_accepted")
        self.assertEqual(seen[-1]["progress_pct"], 1)
        self.assertEqual(seen[-1]["bytes_done"], 100)
        self.assertEqual(seen[-1]["tag"], "v4.9.60")
        bus.stop()

    def test_throttle_within_interval(self):
        seen = []
        bus = SelfUpdateProgressBus(
            seen.append,
            from_version="4.9.54",
            to_version="4.9.60",
            tag="v4.9.60",
            min_interval=2.0,
        )
        bus.tick("downloading", progress_pct=10, force=True)
        n = len(seen)
        bus.tick("downloading", progress_pct=11)  # same phase, too soon
        self.assertEqual(len(seen), n)
        bus.stop()

    def test_heartbeat_reemits(self):
        seen = []
        bus = SelfUpdateProgressBus(
            seen.append,
            from_version="4.9.54",
            to_version="4.9.60",
            tag="4.9.60",
            min_interval=0.2,
        )
        bus.HEARTBEAT_SEC = 0.25
        bus.start()
        bus.tick("downloading", progress_pct=5, bytes_done=1, bytes_total=10, force=True)
        n = len(seen)
        time.sleep(0.7)
        bus.stop()
        self.assertGreater(len(seen), n)
        self.assertEqual(seen[-1]["phase"], "downloading")


class TestCmdSelfUpdateProgressWire(unittest.TestCase):
    def test_handler_passes_progress_emit(self):
        from client_remote_commands import RemoteCommandExecutor

        ex = RemoteCommandExecutor(api_client=None, token_getter=lambda: "t")
        ex._current_cmd = {
            "command_id": "cmd-1",
            "command_type": "self_update",
            "params": {"tag": "v4.9.61"},
        }
        reported = []

        def _sync(cmd, result, timeout=8.0):
            reported.append((cmd.get("command_id"), result))

        ex._report_result_sync = _sync

        with mock.patch(
            "client_updater.run_self_update_command",
            side_effect=lambda params, api_client=None, progress_emit=None: (
                progress_emit(
                    {
                        "status": "running",
                        "message": "update_accepted",
                        "phase": "downloading",
                        "progress_pct": 42,
                        "bytes_done": 48,
                        "bytes_total": 100,
                    }
                )
                or {
                    "success": True,
                    "ok": True,
                    "message": "update_started",
                    "phase": "installing",
                    "progress_pct": 95,
                    "restart_required": True,
                }
            ),
        ):
            out = ex._cmd_self_update({"tag": "v4.9.61", "force": True})

        # Progress POST is async — wait briefly for the worker thread.
        deadline = time.time() + 2.0
        while not reported and time.time() < deadline:
            time.sleep(0.05)

        self.assertEqual(out["message"], "update_started")
        self.assertEqual(out["phase"], "installing")
        self.assertTrue(reported)
        self.assertEqual(reported[0][0], "cmd-1")
        self.assertEqual(reported[0][1]["phase"], "downloading")
        self.assertEqual(reported[0][1]["progress_pct"], 42)


if __name__ == "__main__":
    unittest.main()
