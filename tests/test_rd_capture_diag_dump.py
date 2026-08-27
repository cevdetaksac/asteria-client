#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Capture-fail dump writer for rare-host forensics."""

import json
import os
import tempfile
import unittest
from unittest import mock


class TestCaptureFailDump(unittest.TestCase):
    def test_write_dump_json_and_jpeg(self):
        from client_rd_capture_diag_dump import write_capture_fail_dump

        with tempfile.TemporaryDirectory() as td:
            with mock.patch(
                "client_rd_capture_diag_dump.dump_dir", return_value=td
            ):
                jpeg = b"\xff\xd8" + (b"\x00" * 200) + b"\xff\xd9"
                out = write_capture_fail_dump(
                    reason="winlogon_capture_flat",
                    diag={"frames_sent": 0, "flat_frame": True},
                    extra={"detail": "lab"},
                    jpeg=jpeg,
                    stream_id="abc123",
                )
                self.assertTrue(out.get("ok"))
                self.assertTrue(os.path.isfile(out["path"]))
                self.assertTrue(os.path.isfile(out["jpeg_path"]))
                with open(out["path"], encoding="utf-8") as fh:
                    payload = json.load(fh)
                self.assertEqual(payload["reason"], "winlogon_capture_flat")
                self.assertEqual(payload["capture_diag"]["frames_sent"], 0)
                self.assertNotIn("password", payload["extra"])


if __name__ == "__main__":
    unittest.main()
