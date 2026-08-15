#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""C-PROC-INSPECT + rundll32 LOLBIN heuristic (contract 1.4.57 / ≥4.9.93)."""

import unittest

from client_system_health import (
    SystemHealthMonitor,
    parse_rundll32_cmdline,
)


class TestRundll32Lolbin(unittest.TestCase):
    def test_system32_dll_entry_is_not_lolbin(self):
        sus, reasons = SystemHealthMonitor._process_suspicion(
            "rundll32.exe",
            r"C:\Windows\System32\rundll32.exe",
            r'C:\Windows\System32\rundll32.exe shell32.dll,Control_RunDLL',
        )
        self.assertFalse(sus)
        self.assertNotIn("lolbin", reasons)

    def test_http_payload_is_lolbin(self):
        sus, reasons = SystemHealthMonitor._process_suspicion(
            "rundll32.exe",
            r"C:\Windows\System32\rundll32.exe",
            r"rundll32.exe javascript:alert(1)",
        )
        self.assertTrue(sus)
        self.assertIn("lolbin", reasons)

    def test_temp_dll_is_off_system(self):
        sus, reasons = SystemHealthMonitor._process_suspicion(
            "rundll32.exe",
            r"C:\Windows\System32\rundll32.exe",
            r'rundll32.exe "C:\Users\Public\evil.dll",Start',
        )
        self.assertTrue(sus)
        self.assertIn("lolbin_off_system_dll", reasons)

    def test_parse_export(self):
        p = parse_rundll32_cmdline(
            r"C:\Windows\System32\rundll32.exe shell32.dll,Control_RunDLL"
        )
        self.assertTrue(p["dll_path"].lower().endswith("shell32.dll"))
        self.assertEqual(p["dll_export"], "Control_RunDLL")


if __name__ == "__main__":
    unittest.main()
