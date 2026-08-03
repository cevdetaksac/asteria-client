#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Completion-based installer download (not wall-clock timeout)."""

import os
import tempfile
import unittest
from unittest import mock


class TestInstallerLooksComplete(unittest.TestCase):
    def test_incomplete_content_length(self):
        from client_updater import _installer_looks_complete

        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "a.exe")
            data = b"MZ" + (b"\0" * 100)
            with open(path, "wb") as fh:
                fh.write(data)
            with mock.patch("client_updater._DOWNLOAD_MIN_BYTES", 10):
                ok, detail = _installer_looks_complete(
                    path,
                    bytes_written=len(data),
                    content_length=len(data) + 50,
                )
            self.assertFalse(ok)
            self.assertIn("incomplete_content_length", detail)

    def test_complete_pe(self):
        from client_updater import _installer_looks_complete

        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "a.exe")
            data = b"MZ" + (b"\0" * 100)
            with open(path, "wb") as fh:
                fh.write(data)
            with mock.patch("client_updater._DOWNLOAD_MIN_BYTES", 10):
                ok, detail = _installer_looks_complete(
                    path,
                    bytes_written=len(data),
                    content_length=len(data),
                )
            self.assertTrue(ok)
            self.assertEqual(detail, "complete")

    def test_rejects_non_pe(self):
        from client_updater import _installer_looks_complete

        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "a.exe")
            data = b"<html>error</html>" + (b"x" * 100)
            with open(path, "wb") as fh:
                fh.write(data)
            with mock.patch("client_updater._DOWNLOAD_MIN_BYTES", 10):
                ok, detail = _installer_looks_complete(
                    path,
                    bytes_written=len(data),
                    content_length=len(data),
                )
            self.assertFalse(ok)
            self.assertEqual(detail, "not_pe_mz")


class TestDownloadInstallerComplete(unittest.TestCase):
    def test_retries_then_succeeds(self):
        from client_updater import download_installer_complete

        payload = b"MZ" + (b"\0" * 2048)
        calls = {"n": 0}

        class _Resp:
            status_code = 200
            headers = {"Content-Length": str(len(payload))}

            def raise_for_status(self):
                return None

            def iter_content(self, chunk_size=1):
                # First call: truncated body → incomplete; then full.
                calls["n"] += 1
                if calls["n"] == 1:
                    yield payload[:100]
                    return
                yield payload

        with tempfile.TemporaryDirectory() as td:
            dest = os.path.join(td, "installer.exe")
            with mock.patch("client_updater._DOWNLOAD_MIN_BYTES", 100), mock.patch(
                "client_updater._DOWNLOAD_RETRY_BACKOFF_SEC", (0, 0, 0, 0, 0)
            ), mock.patch(
                "client_security_utils.ensure_ca_bundle", return_value=None
            ), mock.patch(
                "client_security_utils.resolve_tls_verify", return_value=False
            ), mock.patch(
                "requests.get", return_value=_Resp()
            ), mock.patch(
                "client_authenticode.assert_update_authenticode",
                return_value={"trusted": False, "skipped": True},
            ), mock.patch(
                "client_utils.get_from_config", return_value=True
            ):
                ok, detail = download_installer_complete(
                    "https://github.com/cevdetaksac/yesnext-cloud-honeypot-client/"
                    "releases/download/v4.9.25/asteria-client-installer.exe",
                    dest,
                    max_attempts=3,
                    log_func=lambda *_a, **_k: None,
                )
            self.assertTrue(ok)
            self.assertEqual(detail, "complete")
            self.assertTrue(os.path.isfile(dest))
            self.assertEqual(os.path.getsize(dest), len(payload))
            self.assertGreaterEqual(calls["n"], 2)


if __name__ == "__main__":
    unittest.main()
