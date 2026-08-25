#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Contract: register-protection — 3 fail → block_ip (unit)."""

import unittest

from client_threat_engine import ThreatEngine
from client_protection_store import normalize_block_rule, apply_block_rules


class TestProtectionBlockRules(unittest.TestCase):
    def setUp(self):
        self.alerts = []
        self.reports = []

        def _on_alert(alert, ctx=None):
            self.alerts.append(alert)

        def _on_report(entry):
            self.reports.append(entry)

        self.engine = ThreatEngine(
            on_alert=_on_alert,
            on_auth_fail_report=_on_report,
        )

    def test_normalize_contract_rdp_fail_3(self):
        raw = {
            "id": "rdp-fail-3",
            "name": "RDP brute force",
            "enabled": True,
            "service": "RDP",
            "event": "failed_auth",
            "threshold": 3,
            "window_seconds": 1800,
            "action": "block_ip",
            "alert": True,
        }
        n = normalize_block_rule(raw)
        self.assertEqual(n["threshold_count"], 3)
        self.assertEqual(n["window_minutes"], 30)
        self.assertIn("block", n["actions"])
        self.assertEqual(n["services"], "RDP")

    def test_three_rdp_fails_emit_block(self):
        rules = [
            {
                "id": "rdp-fail-3",
                "name": "RDP brute force",
                "enabled": True,
                "service": "RDP",
                "event": "failed_auth",
                "threshold": 3,
                "window_seconds": 1800,
                "action": "block_ip",
                "alert": True,
            }
        ]
        apply_block_rules(self.engine, rules, source="unit")
        ip = "203.0.113.50"
        for _ in range(3):
            self.engine.process_event(
                {
                    "event_type": "failed_logon",
                    "source_ip": ip,
                    "target_service": "RDP",
                    "username": "Administrator",
                }
            )
        self.assertIn(ip, self.engine._rule_blocked_ips)
        self.assertGreaterEqual(self.engine._stats["rule_blocks"], 1)
        self.assertTrue(
            any("block_ip" in (a.get("auto_response") or []) for a in self.alerts)
            or any(a.get("severity") == "critical" for a in self.alerts)
        )
        # Real fails reported to /api/attack path (honeypot optional)
        self.assertGreaterEqual(len(self.reports), 1)
        self.assertEqual(self.reports[0]["service"], "RDP")
        self.assertEqual(self.reports[0]["port"], 3389)
        self.assertEqual(self.reports[0]["password"], "<failed_logon>")
        self.assertEqual(self.reports[0]["source"], "eventlog")

    def test_network_fail_reports_port_445_not_zero(self):
        """Regression: uppercased NETWORK must map to 445 (lab port:0 flood)."""
        apply_block_rules(
            self.engine,
            [
                {
                    "id": "net-fail",
                    "service": "Network",
                    "threshold": 10,
                    "window_seconds": 1800,
                    "action": "block_ip",
                    "alert": True,
                }
            ],
            source="unit",
        )
        self.engine.process_event(
            {
                "event_type": "failed_logon",
                "source_ip": "203.0.113.60",
                "target_service": "Network",
                "username": "Administrator",
                "logon_type": 3,
                "auth_package": "NTLM",
                "logon_process": "NtLmSsp",
            }
        )
        self.assertEqual(len(self.reports), 1)
        self.assertEqual(self.reports[0]["service"], "NETWORK")
        self.assertEqual(self.reports[0]["port"], 445)
        self.assertEqual(self.reports[0]["logon_type"], 3)
        self.assertEqual(self.reports[0]["auth_package"], "NTLM")

    def test_anonymous_network_not_reported(self):
        apply_block_rules(
            self.engine,
            [{"id": "net", "service": "Network", "threshold": 10, "action": "block_ip"}],
            source="unit",
        )
        self.engine.process_event(
            {
                "event_type": "failed_logon",
                "source_ip": "203.0.113.61",
                "target_service": "Network",
                "username": "ANONYMOUS LOGON",
            }
        )
        self.assertEqual(len(self.reports), 0)

    def test_two_fails_do_not_block(self):
        apply_block_rules(
            self.engine,
            [
                {
                    "id": "rdp-fail-3",
                    "service": "RDP",
                    "threshold": 3,
                    "window_seconds": 1800,
                    "action": "block_ip",
                    "alert": True,
                }
            ],
            source="unit",
        )
        ip = "203.0.113.51"
        for _ in range(2):
            self.engine.process_event(
                {
                    "event_type": "failed_logon",
                    "source_ip": ip,
                    "target_service": "RDP",
                }
            )
        self.assertNotIn(ip, self.engine._rule_blocked_ips)

    def test_network_fails_do_not_fill_rdp_threshold(self):
        """Service-aware: Network auth fails must not trigger RDP-only rule."""
        apply_block_rules(
            self.engine,
            [
                {
                    "id": "rdp-fail-3",
                    "service": "RDP",
                    "threshold": 3,
                    "window_seconds": 1800,
                    "action": "block_ip",
                    "alert": True,
                }
            ],
            source="unit",
        )
        ip = "203.0.113.52"
        for _ in range(5):
            self.engine.process_event(
                {
                    "event_type": "failed_logon",
                    "source_ip": ip,
                    "target_service": "Network",
                }
            )
        self.assertNotIn(ip, self.engine._rule_blocked_ips)
        # One RDP fail still under threshold
        self.engine.process_event(
            {
                "event_type": "failed_logon",
                "source_ip": ip,
                "target_service": "RDP",
            }
        )
        self.assertNotIn(ip, self.engine._rule_blocked_ips)

    def test_mixed_services_only_rdp_counts(self):
        apply_block_rules(
            self.engine,
            [
                {
                    "id": "rdp-fail-3",
                    "service": "RDP",
                    "threshold": 3,
                    "window_seconds": 1800,
                    "action": "block_ip",
                    "alert": True,
                }
            ],
            source="unit",
        )
        ip = "203.0.113.53"
        for _ in range(2):
            self.engine.process_event(
                {
                    "event_type": "failed_logon",
                    "source_ip": ip,
                    "target_service": "Network",
                }
            )
        for _ in range(3):
            self.engine.process_event(
                {
                    "event_type": "failed_logon",
                    "source_ip": ip,
                    "target_service": "RDP",
                    "username": "admin",
                }
            )
        self.assertIn(ip, self.engine._rule_blocked_ips)


if __name__ == "__main__":
    unittest.main()
