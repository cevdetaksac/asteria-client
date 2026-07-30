#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""remove-legacy-install.ps1 must purge CloudClient + ProgramData YesNext."""

import unittest
from pathlib import Path


class TestRemoveLegacyScript(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parents[1]
        cls.script = (root / "scripts" / "remove-legacy-install.ps1").read_text(
            encoding="utf-8", errors="replace"
        )

    def test_purges_cloudclient_and_programdata(self):
        self.assertIn("YesNext\\CloudClient", self.script)
        self.assertIn("ProgramData", self.script)
        self.assertIn('Join-Path $pd "YesNext"', self.script)

    def test_purges_user_yesnext_appdata(self):
        self.assertIn("Removed user legacy", self.script)


class TestUpdateHelperGuardianStop(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parents[1]
        cls.upd = (root / "scripts" / "update-and-install.ps1").read_text(
            encoding="utf-8", errors="replace"
        )
        cls.kill = (root / "scripts" / "kill-honeypot.ps1").read_text(
            encoding="utf-8", errors="replace"
        )

    def test_stops_guardian_before_kill(self):
        self.assertIn("function Stop-AsteriaGuardian", self.upd)
        self.assertIn("Stop-AsteriaGuardian", self.upd)
        self.assertIn("sc.exe stop AsteriaGuardian", self.kill)

    def test_silent_skips_helper_tray_when_motor_ready(self):
        self.assertIn("skip helper tray", self.upd)
        self.assertIn("motorReady", self.upd)


if __name__ == "__main__":
    unittest.main()
