"""Lightweight checks for canary spam helpers (no tkinter)."""
from __future__ import annotations
import re
import unittest
from pathlib import Path


SRC = Path(__file__).resolve().parents[1] / "client_ransomware_shield.py"


class SourceContractTests(unittest.TestCase):
    def setUp(self):
        self.src = SRC.read_text(encoding="utf-8", errors="replace")

    def test_burst_constants_present(self):
        self.assertIn("CANARY_BURST_COALESCE_SEC = 90", self.src)
        self.assertIn("CANARY_BURST_MAX_FILES = 30", self.src)

    def test_ms_signed_helper_present(self):
        self.assertIn("def _is_ms_signed_sync_image", self.src)
        self.assertIn("microsoft onedrive", self.src.lower())

    def test_soft_deleted_for_sync(self):
        self.assertIn('change_type == "DELETED"', self.src)
        self.assertIn("sync_only", self.src)
        self.assertIn("canary burst coalesce", self.src.lower())


if __name__ == "__main__":
    unittest.main()
