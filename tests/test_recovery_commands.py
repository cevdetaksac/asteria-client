#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Contract 1.2.0 (client 4.6.0): disaster-recovery commands + autologon marker."""

import os
import tempfile
import unittest
from unittest import mock

import client_autologon
from client_remote_commands import RemoteCommandExecutor


class TestRecoveryValidation(unittest.TestCase):
    def setUp(self):
        self.ex = RemoteCommandExecutor(token_getter=lambda: "")

    def test_create_user_requires_password(self):
        r = self.ex._validate({"command_type": "create_user",
                               "params": {"username": "Administrator2"}})
        self.assertEqual(r, "missing_password")

    def test_create_user_requires_username(self):
        r = self.ex._validate({"command_type": "create_user",
                               "params": {"password": "x"}})
        self.assertEqual(r, "missing_username")

    def test_recovery_rejects_protected_account(self):
        for ct in ("create_user", "remote_logon", "set_autologon"):
            r = self.ex._validate({"command_type": ct,
                                   "params": {"username": "SYSTEM", "password": "x"}})
            self.assertTrue(r and "Protected account" in r, f"{ct}: {r}")

    def test_remote_logon_requires_credentials(self):
        r = self.ex._validate({"command_type": "remote_logon",
                               "params": {"username": "Administrator"}})
        self.assertEqual(r, "missing_password")

    def test_recovery_commands_whitelisted(self):
        from client_remote_commands import ALLOWED_COMMANDS, REQUIRES_CONFIRMATION
        for ct in ("create_user", "remote_logon", "set_autologon",
                   "clear_autologon", "reboot"):
            self.assertIn(ct, ALLOWED_COMMANDS)
        for ct in ("create_user", "remote_logon", "set_autologon", "reboot"):
            self.assertIn(ct, REQUIRES_CONFIRMATION)


class TestCreateUserExec(unittest.TestCase):
    def setUp(self):
        self.ex = RemoteCommandExecutor(token_getter=lambda: "")

    def test_create_user_adds_to_group(self):
        from test_admin_ops import FakeNet
        net = FakeNet()
        with mock.patch("client_admin_ops.Win32Net", return_value=net), \
             mock.patch.object(RemoteCommandExecutor, "_resolve_sid", return_value="S-1-5-21-x"):
            res = self.ex._cmd_create_user({
                "username": "Administrator2",
                "password": "S3cretPassw0rd!",
                "groups": ["Administrators"],
            })
        self.assertTrue(res["success"], res)
        self.assertEqual(res["code"], "USER_CREATED")
        self.assertEqual(res["data"]["username"], "Administrator2")
        self.assertIn("Administrators", res["data"]["groups"])
        self.assertTrue(res["data"]["created"])
        self.assertIn(("Administrators", "Administrator2"), net.group_adds)
        self.assertNotIn("S3cretPassw0rd!", repr(res))

    def test_create_user_existing_without_reset_enable_fails(self):
        from test_admin_ops import FakeNet
        net = FakeNet(existing={"existinguser"})
        with mock.patch("client_admin_ops.Win32Net", return_value=net):
            res = self.ex._cmd_create_user({
                "username": "ExistingUser",
                "password": "S3cretPassw0rd!",
            })
        self.assertFalse(res["success"])
        self.assertEqual(res["error"], "USER_EXISTS")


class TestAutologonMarker(unittest.TestCase):
    def test_marker_round_trip(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "autologon_pending.json")
            with mock.patch.object(client_autologon, "_PENDING", path), \
                 mock.patch.object(client_autologon, "MACHINE_DATA_DIR", d):
                self.assertIsNone(client_autologon.read_pending_marker())
                client_autologon.write_pending_marker("Administrator", "cmd-123")
                m = client_autologon.read_pending_marker()
                self.assertEqual(m["username"], "Administrator")
                self.assertEqual(m["command_id"], "cmd-123")
                self.assertTrue(m["one_shot"])
                client_autologon.clear_pending_marker()
                self.assertIsNone(client_autologon.read_pending_marker())


if __name__ == "__main__":
    unittest.main()
