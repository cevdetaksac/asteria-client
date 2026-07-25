# -*- coding: utf-8 -*-
"""Unit tests for Threat Center local inventory helpers."""

from __future__ import annotations

import unittest
from unittest.mock import patch

from client_threat_local import (
    DEFAULT_SHARES,
    list_smb_shares,
    list_third_party_services,
    remove_smb_share,
    stop_windows_service,
)


class ThreatLocalSharesTests(unittest.TestCase):
    def test_refuse_default_share(self):
        out = remove_smb_share("ADMIN$")
        self.assertFalse(out.get("ok"))
        self.assertEqual(out.get("error"), "default_share_protected")

    def test_refuse_invalid_share(self):
        out = remove_smb_share("bad name; rm -rf")
        self.assertFalse(out.get("ok"))

    @patch("client_threat_local._run_ps")
    def test_list_shares_marks_defaults(self, run_ps):
        run_ps.return_value = (
            0,
            '[{"Name":"ADMIN$","Path":"C:\\\\Windows","CurrentUsers":0},'
            '{"Name":"paylas","Path":"D:\\\\x","CurrentUsers":2}]',
            "",
        )
        out = list_smb_shares()
        self.assertTrue(out["ok"])
        self.assertEqual(out["custom_count"], 1)
        names = {r["name"]: r for r in out["shares"]}
        self.assertTrue(names["ADMIN$"]["is_default"])
        self.assertFalse(names["paylas"]["is_default"])
        self.assertIn("ADMIN$", DEFAULT_SHARES)


class ThreatLocalServiceTests(unittest.TestCase):
    @patch("client_threat_local._run_ps")
    def test_filters_microsoft_paths(self, run_ps):
        run_ps.return_value = (
            0,
            "["
            '{"Name":"WinDefend","DisplayName":"Defender",'
            '"PathName":"C:\\\\Windows\\\\System32\\\\svchost.exe","StartMode":"Auto","StartName":"LocalSystem"},'
            '{"Name":"EvlWatcher","DisplayName":"EvlWatcher",'
            '"PathName":"C:\\\\Program Files\\\\EvlWatcher\\\\EvlWatcher.exe","StartMode":"Auto","StartName":"LocalSystem"}'
            "]",
            "",
        )
        out = list_third_party_services()
        self.assertTrue(out["ok"])
        names = [s["name"] for s in out["services"]]
        self.assertNotIn("WinDefend", names)
        self.assertIn("EvlWatcher", names)
        self.assertGreaterEqual(out["unknown_count"], 1)

    def test_refuse_protected_stop(self):
        out = stop_windows_service("WinDefend")
        self.assertFalse(out.get("ok"))
        self.assertEqual(out.get("error"), "PROTECTED_SERVICE")


if __name__ == "__main__":
    unittest.main()
