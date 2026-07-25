#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import tempfile
import unittest
from unittest import mock


class ProgramDataMigrateTests(unittest.TestCase):
    def test_migrate_copies_legacy_token_once(self):
        import client_paths as cp

        with tempfile.TemporaryDirectory() as td:
            legacy = os.path.join(td, "YesNext", "CloudHoneypotClient")
            dest = os.path.join(td, "Asteria")
            os.makedirs(legacy, exist_ok=True)
            with open(os.path.join(legacy, "token.dat"), "w", encoding="utf-8") as fh:
                fh.write("legacy-token-value")

            with mock.patch.object(cp, "_PROGRAMDATA", td), mock.patch.object(
                cp, "MACHINE_DATA_DIR", dest
            ), mock.patch.object(cp, "LEGACY_MACHINE_CLIENT", legacy), mock.patch.object(
                cp, "LEGACY_MACHINE_VENDOR", os.path.join(td, "missing")
            ), mock.patch.object(cp, "LEGACY_USER_CLIENT", os.path.join(td, "nouser")):
                first = cp.migrate_legacy_programdata(force=True)
                second = cp.migrate_legacy_programdata()

            self.assertTrue(first["ok"])
            self.assertGreaterEqual(first["copied"], 1)
            self.assertTrue(os.path.isfile(os.path.join(dest, "token.dat")))
            with open(os.path.join(dest, "token.dat"), encoding="utf-8") as fh:
                self.assertEqual(fh.read(), "legacy-token-value")
            self.assertTrue(second["already_done"])


if __name__ == "__main__":
    unittest.main()
