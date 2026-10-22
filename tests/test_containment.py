#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Containment P0–P2 unit tests (no live isolate)."""
import json
import os
import tempfile
import unittest
from unittest import mock

import client_contain as contain
import client_playbooks as pb
from client_remote_commands import (
    ALLOWED_COMMANDS, REQUIRES_CONFIRMATION, RemoteCommandExecutor, _ADMIN_ACK_COMMANDS,
)


class TestCatalog(unittest.TestCase):
    def test_commands_allowed(self):
        for c in (
            "contain_process", "release_process", "unblock_process",
            "isolate_host", "lift_isolation", "delete_user", "disable_service",
            "run_playbook", "undo_playbook", "list_playbooks",
        ):
            self.assertIn(c, ALLOWED_COMMANDS)
            self.assertIn(c, _ADMIN_ACK_COMMANDS) if c not in (
                "list_playbooks", "lift_isolation", "release_process",
                "unblock_process", "undo_playbook",
            ) else None
        self.assertIn("contain_process", REQUIRES_CONFIRMATION)
        self.assertIn("isolate_host", REQUIRES_CONFIRMATION)
        self.assertIn("run_playbook", REQUIRES_CONFIRMATION)
        self.assertIn("delete_user", REQUIRES_CONFIRMATION)


class TestContainUnit(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.patcher = mock.patch.object(contain, "_contain_dir", return_value=self.tmp.name)
        self.patcher.start()
        self.addCleanup(self.patcher.stop)

    def test_suspend_resume_std(self):
        proc = mock.Mock()
        proc.name.return_value = "sample.exe"
        proc.exe.return_value = r"C:\Temp\sample.exe"
        proc.create_time.return_value = 1000.0
        ps = mock.Mock()
        ps.Process.return_value = proc
        r = contain.suspend_process(42, expected_image="sample.exe",
                                    process_start_time=1000.0, psutil_mod=ps)
        self.assertTrue(r["ok"], r)
        self.assertEqual(r["code"], "SUSPENDED")
        proc.suspend.assert_called_once()
        r2 = contain.resume_process(42, expected_image="sample.exe", psutil_mod=ps)
        self.assertTrue(r2["ok"])
        proc.resume.assert_called_once()

    def test_contain_dry_run(self):
        proc = mock.Mock()
        proc.name.return_value = "sample.exe"
        proc.exe.return_value = r"C:\Temp\sample.exe"
        proc.create_time.return_value = 1000.0
        ps = mock.Mock()
        ps.Process.return_value = proc
        with mock.patch.object(contain, "find_persistence", return_value={"services": [], "tasks": [], "run_keys": []}):
            r = contain.contain_process(
                42, expected_image="sample.exe", process_start_time=1000.0,
                dry_run=True, psutil_mod=ps,
            )
        self.assertTrue(r["ok"])
        self.assertEqual(r["code"], "DRY_RUN")

    def test_release_roundtrip_state(self):
        undo = "11111111-2222-3333-4444-555555555555"
        contain._save_state(undo, {
            "kind": "contain_process", "undo_id": undo, "pid": None,
            "suspended": False, "rule_name": None, "persistence": {},
            "ifeo_image": None, "image": "x.exe",
        })
        r = contain.release_process(undo)
        self.assertTrue(r["ok"], r)
        self.assertEqual(r["code"], "RELEASED")
        self.assertIsNone(contain._load_state(undo))


class TestPlaybooks(unittest.TestCase):
    def test_list(self):
        r = pb.list_playbooks()
        self.assertTrue(r["ok"])
        ids = {p["id"] for p in r["data"]["playbooks"]}
        self.assertEqual(ids, {"rdp_attack", "compromised_admin", "malicious_process"})

    def test_dry_run_malicious(self):
        calls = []
        def ex(cmd, p):
            calls.append(cmd)
            return {"ok": True, "success": True, "code": "OK"}
        r = pb.run_playbook(
            "malicious_process",
            {"pid": 1, "expected_image": "evil.exe", "process_start_time": 1.0, "dry_run": True},
            execute=ex, dry_run=True,
        )
        self.assertTrue(r["ok"], r)
        self.assertEqual(r["code"], "DRY_RUN")
        self.assertEqual(calls, [])  # dry_run does not execute


class TestValidate(unittest.TestCase):
    def test_contain_requires_identity(self):
        ex = RemoteCommandExecutor()
        self.assertEqual(
            ex._validate({"command_type": "contain_process", "params": {"pid": 1}}),
            "missing_expected_image",
        )


class TestCloudValid(unittest.TestCase):
    def test_helpers(self):
        import sys
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "cloud"))
        try:
            from helpers import VALID_COMMAND_TYPES, requires_destructive_confirm
        except ImportError as e:
            self.skipTest(f"cloud deps missing: {e}")
        for c in ("contain_process", "release_process", "unblock_process",
                  "isolate_host", "delete_user", "disable_service", "run_playbook"):
            self.assertIn(c, VALID_COMMAND_TYPES)
        self.assertTrue(requires_destructive_confirm("isolate_host", {}))
        self.assertFalse(requires_destructive_confirm("isolate_host", {"dry_run": True}))
        self.assertFalse(requires_destructive_confirm("contain_process", {"dry_run": True}))


if __name__ == "__main__":
    unittest.main()
