#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Local SAM user inventory enrichment for cloud Server Management."""

import unittest
from unittest import mock


class TestListLocalUsersEnrichment(unittest.TestCase):
    def test_disabled_row_flags(self):
        from client_remote_session import list_local_users

        ps_users = [
            {
                "Name": "alice",
                "FullName": "Alice",
                "Enabled": False,
                "LastLogon": None,
                "SID": {"Value": "S-1-5-21-1"},
                "PrincipalSource": "Local",
                "Description": "",
            },
            {
                "Name": "bob",
                "FullName": "",
                "Enabled": True,
                "LastLogon": None,
                "SID": {"Value": "S-1-5-21-2"},
                "PrincipalSource": "Local",
                "Description": "",
            },
        ]
        with mock.patch(
            "client_remote_session.run_ps",
            side_effect=[
                (0, __import__("json").dumps(ps_users), ""),
                (0, "[]", ""),
            ],
        ), mock.patch(
            "client_remote_session.enumerate_sessions_rich", return_value=[]
        ):
            rows = list_local_users(include_disabled=True)
        by_name = {r["username"]: r for r in rows}
        self.assertEqual(by_name["alice"]["status"], "disabled")
        self.assertTrue(by_name["alice"]["can_enable"])
        self.assertFalse(by_name["alice"]["can_disable"])
        self.assertEqual(by_name["bob"]["status"], "enabled")
        self.assertEqual(by_name["bob"]["account_status"], "enabled")
        self.assertTrue(by_name["bob"]["can_disable"])
        self.assertFalse(by_name["bob"]["has_session"])
        self.assertIsNone(by_name["bob"]["session_id"])

    def test_disc_session_does_not_mint_ghost_sid(self):
        from client_remote_session import list_local_users

        ps_users = [
            {
                "Name": "Administrator",
                "Enabled": True,
                "SID": {"Value": "S-1-5-21-9"},
                "PrincipalSource": "Local",
            },
        ]
        with mock.patch(
            "client_remote_session.run_ps",
            side_effect=[
                (0, __import__("json").dumps(ps_users), ""),
                (0, '["Administrator"]', ""),
            ],
        ), mock.patch(
            "client_remote_session.enumerate_sessions_rich",
            return_value=[
                {
                    "username": "Administrator",
                    "session_id": 3,
                    "status": "Disc",
                }
            ],
        ):
            rows = list_local_users(include_disabled=True)
        admin = rows[0]
        self.assertEqual(admin["status"], "enabled")
        self.assertFalse(admin["has_session"])
        self.assertIsNone(admin["session_id"])
        self.assertIsNone(admin["session_status"])

    def test_include_disabled_false_filters(self):
        from client_remote_session import list_local_users

        ps_users = [
            {"Name": "alice", "Enabled": False, "SID": "S-1", "PrincipalSource": "Local"},
            {"Name": "bob", "Enabled": True, "SID": "S-2", "PrincipalSource": "Local"},
        ]
        with mock.patch(
            "client_remote_session.run_ps",
            side_effect=[
                (0, __import__("json").dumps(ps_users), ""),
                (0, "[]", ""),
            ],
        ), mock.patch(
            "client_remote_session.enumerate_sessions_rich", return_value=[]
        ):
            rows = list_local_users(include_disabled=False)
        self.assertEqual([r["username"] for r in rows], ["bob"])


if __name__ == "__main__":
    unittest.main()
