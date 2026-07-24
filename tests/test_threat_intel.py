#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Threat-intel AR-INTEL apply / legacy reconcile unit tests."""

import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

from client_threat_intel import (
    ThreatIntelManager,
    _is_expired,
    _collect_allowlist,
    _severity_rank,
)
from client_firewall import WindowsFirewallBackend


class TestThreatIntelHelpers(unittest.TestCase):
    def test_severity_rank(self):
        self.assertGreater(_severity_rank("critical"), _severity_rank("high"))
        self.assertGreater(_severity_rank("high"), _severity_rank("medium"))

    def test_expired(self):
        past = (datetime.now(timezone.utc) - timedelta(days=1)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        future = (datetime.now(timezone.utc) + timedelta(days=1)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        self.assertTrue(_is_expired({"expires_at": past}))
        self.assertFalse(_is_expired({"expires_at": future}))
        self.assertFalse(_is_expired({}))

    def test_allowlist(self):
        allow = _collect_allowlist(
            {"allowlist_ips": ["1.2.3.4", {"ip": "5.6.7.8"}]},
            {"allowlist": ["9.9.9.9"]},
        )
        self.assertIn("1.2.3.4", allow)
        self.assertIn("5.6.7.8", allow)
        self.assertIn("9.9.9.9", allow)

    def test_intel_rule_name(self):
        self.assertEqual(
            WindowsFirewallBackend.intel_rule_name("feodo-ip-abc"),
            "AR-INTEL-feodo-ip-abc",
        )
        self.assertTrue(
            WindowsFirewallBackend.intel_rule_name("a/b c").startswith("AR-INTEL-")
        )


class TestThreatIntelFirewallApply(unittest.TestCase):
    def setUp(self):
        with mock.patch.object(ThreatIntelManager, "_load_cache"):
            self.mgr = ThreatIntelManager(api_client=None, token_getter=lambda: "")
        self.backend = mock.Mock(spec=WindowsFirewallBackend)
        self.backend.intel_rule_name = WindowsFirewallBackend.intel_rule_name
        self.backend.list_intel_rules.return_value = []
        self.backend.apply_intel_block.return_value = True
        self.backend.remove_intel_block.return_value = True
        self.mgr._fw_backend = self.backend

    def test_auto_block_false_purges_and_skips(self):
        self.backend.list_intel_rules.return_value = [
            {"name": "HP-INTEL-old", "remoteip": "1.1.1.1", "id": "old"}
        ]
        out = self.mgr._apply_firewall(
            [{"id": "x", "value": "2.2.2.2", "action": "block_ip", "severity": "high"}],
            {"auto_block_firewall": False},
            bundle={},
        )
        self.assertEqual(out["firewall_removed"], 1)
        self.assertGreaterEqual(out["firewall_skipped"], 1)
        self.backend.apply_intel_block.assert_not_called()

    def test_adds_ar_intel_not_auto_response(self):
        ar = mock.Mock()
        ar._is_whitelisted = mock.Mock(return_value=False)
        self.mgr.auto_response = ar
        future = (datetime.now(timezone.utc) + timedelta(days=7)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        blocks = [
            {
                "id": "feodo-ip-aaa",
                "value": "50.16.16.211",
                "action": "block_ip",
                "severity": "high",
                "expires_at": future,
            }
        ]
        out = self.mgr._apply_firewall(
            blocks,
            {"auto_block_firewall": True, "intel_block_requires_severity_at_least": "high"},
            bundle={},
        )
        self.assertEqual(out["firewall_added"], 1)
        self.backend.apply_intel_block.assert_called_once_with(
            "feodo-ip-aaa", "50.16.16.211"
        )
        ar.block_ip.assert_not_called()

    def test_orphan_removed(self):
        self.backend.list_intel_rules.return_value = [
            {"name": "HP-INTEL-gone", "remoteip": "9.9.9.9", "id": "gone"}
        ]
        future = (datetime.now(timezone.utc) + timedelta(days=7)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        out = self.mgr._apply_firewall(
            [{
                "id": "keep",
                "value": "1.1.1.1",
                "action": "block_ip",
                "severity": "high",
                "expires_at": future,
            }],
            {"auto_block_firewall": True},
            bundle={},
        )
        self.backend.remove_intel_block.assert_any_call(rule_name="HP-INTEL-gone")
        self.assertEqual(out["firewall_removed"], 1)

    def test_allowlist_and_low_severity_skipped(self):
        future = (datetime.now(timezone.utc) + timedelta(days=7)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        out = self.mgr._apply_firewall(
            [
                {
                    "id": "a",
                    "value": "1.1.1.1",
                    "action": "block_ip",
                    "severity": "high",
                    "expires_at": future,
                },
                {
                    "id": "b",
                    "value": "2.2.2.2",
                    "action": "block_ip",
                    "severity": "low",
                    "expires_at": future,
                },
            ],
            {
                "auto_block_firewall": True,
                "intel_block_requires_severity_at_least": "high",
                "allowlist_ips": ["1.1.1.1"],
            },
            bundle={},
        )
        self.assertEqual(out["firewall_added"], 0)
        self.assertGreaterEqual(out["firewall_skipped"], 2)
        self.backend.apply_intel_block.assert_not_called()


if __name__ == "__main__":
    unittest.main()
