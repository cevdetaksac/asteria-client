#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MySQL authlog prep: log_error_verbosity=3 for AuthLogWatcher."""

import os
import tempfile
import unittest
from unittest import mock

from client_mysql_authlog_prep import (
    _ensure_verbosity_in_text,
    ensure_ini_verbosity,
    ensure_mysql_authlog_prep,
)


class TestEnsureVerbosityText(unittest.TestCase):
    def test_insert_under_mysqld(self):
        src = "[mysqld]\ndatadir=C:/data\n"
        out, changed, detail = _ensure_verbosity_in_text(src, target=3)
        self.assertTrue(changed)
        self.assertIn("inserted", detail)
        self.assertIn("log_error_verbosity=3", out)
        self.assertIn("datadir=C:/data", out)

    def test_update_existing(self):
        src = "[mysqld]\nlog_error_verbosity=2\n"
        out, changed, detail = _ensure_verbosity_in_text(src, target=3)
        self.assertTrue(changed)
        self.assertIn("updated_line=2->3", detail)
        self.assertIn("log_error_verbosity=3", out)
        self.assertNotIn("log_error_verbosity=2", out)

    def test_already_ok(self):
        src = "[mysqld]\nlog_error_verbosity=3\n"
        out, changed, detail = _ensure_verbosity_in_text(src, target=3)
        self.assertFalse(changed)
        self.assertEqual(detail, "already_ok")
        self.assertEqual(out, src)

    def test_hyphen_key(self):
        src = "[mysqld]\nlog-error-verbosity = 1\n"
        out, changed, _ = _ensure_verbosity_in_text(src, target=3)
        self.assertTrue(changed)
        self.assertRegex(out, r"log-error-verbosity\s*=\s*3")


class TestEnsureIniFile(unittest.TestCase):
    def test_writes_backup_and_value(self):
        with tempfile.TemporaryDirectory() as td:
            ini = os.path.join(td, "my.ini")
            with open(ini, "w", encoding="utf-8") as fh:
                fh.write("[mysqld]\nport=3306\n")
            res = ensure_ini_verbosity(ini)
            self.assertTrue(res["changed"])
            with open(ini, "r", encoding="utf-8") as fh:
                body = fh.read()
            self.assertIn("log_error_verbosity=3", body)
            self.assertTrue(os.path.isfile(ini + ".asteria.bak"))

    def test_prep_skips_with_env(self):
        with mock.patch.dict(os.environ, {"ASTERIA_SKIP_MYSQL_AUTHLOG_PREP": "1"}):
            summary = ensure_mysql_authlog_prep(force=False, restart=False)
        self.assertTrue(summary["skipped"])


if __name__ == "__main__":
    unittest.main()
