#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Update staging / artifact cleanup tests."""

import os
import tempfile
import unittest
from unittest import mock

from client_utils import (
    cleanup_update_artifacts,
    stage_installer_for_update,
    _is_our_installer_filename,
)


class TestUpdateArtifactCleanup(unittest.TestCase):
    def test_installer_filename_detect(self):
        self.assertTrue(_is_our_installer_filename("asteria-client-installer-4.9.41.exe"))
        self.assertTrue(_is_our_installer_filename("asteria-client-installer.exe"))
        # Legacy-named installers stay recognized so staged files still get pruned.
        self.assertTrue(_is_our_installer_filename("cloud-client-installer-4.9.5.exe"))
        self.assertTrue(_is_our_installer_filename("cloud-client-installer-v4.9.5.exe"))
        self.assertFalse(_is_our_installer_filename("update-and-install.ps1"))
        self.assertFalse(_is_our_installer_filename("notes.txt"))

    def test_cleanup_keeps_helper_and_optional_installer(self):
        with tempfile.TemporaryDirectory() as td:
            keep = os.path.join(td, "cloud-client-installer-4.9.5.exe")
            old = os.path.join(td, "cloud-client-installer-4.9.1.exe")
            launcher = os.path.join(td, "run-update-1234.ps1")
            helper = os.path.join(td, "update-and-install.ps1")
            for p, data in (
                (keep, b"KEEP"),
                (old, b"OLD"),
                (launcher, b"#ps"),
                (helper, b"#helper"),
            ):
                with open(p, "wb") as fh:
                    fh.write(data)

            with mock.patch(
                "client_utils._update_helper_staging_dir", return_value=td
            ):
                stats = cleanup_update_artifacts(
                    keep_installer=keep,
                    include_downloads=False,
                    only_if_not_updating=False,
                )

            self.assertTrue(os.path.isfile(keep))
            self.assertTrue(os.path.isfile(helper))
            self.assertFalse(os.path.isfile(old))
            self.assertFalse(os.path.isfile(launcher))
            self.assertEqual(stats["installers"], 1)
            self.assertEqual(stats["launchers"], 1)

    def test_stage_prunes_previous_installers(self):
        with tempfile.TemporaryDirectory() as td:
            src = os.path.join(td, "src.exe")
            with open(src, "wb") as fh:
                fh.write(b"NEWINSTALLER")
            stale = os.path.join(td, "cloud-client-installer-4.8.0.exe")
            with open(stale, "wb") as fh:
                fh.write(b"STALE")

            with mock.patch(
                "client_utils._update_helper_staging_dir", return_value=td
            ):
                dest = stage_installer_for_update(src, version="4.9.5")

            self.assertTrue(dest and os.path.isfile(dest))
            self.assertIn("4.9.5", dest)
            self.assertFalse(os.path.isfile(stale))
            with open(dest, "rb") as fh:
                self.assertEqual(fh.read(), b"NEWINSTALLER")


if __name__ == "__main__":
    unittest.main()
