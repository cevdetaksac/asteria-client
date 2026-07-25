#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Contract 1.1.3: enriched ransomware canary wire payload."""

import unittest
from unittest import mock

from client_ransomware_shield import CanaryState, RansomwareShield
from client_system_health import SystemHealthMonitor


class _AlertPipeline:
    def __init__(self, order=None):
        self.alerts = []
        self.order = order

    def send_urgent(self, alert):
        if self.order is not None:
            self.order.append("urgent")
        self.alerts.append(alert)


class _ApiClient:
    def __init__(self):
        self.payload = None

    def api_request(self, method, path, data=None, **_kwargs):
        self.payload = data
        return {"status": "ok"}


class TestCanaryUrgentWire(unittest.TestCase):
    def test_containment_precedes_enriched_urgent(self):
        order = []
        pipeline = _AlertPipeline(order)
        shield = RansomwareShield(alert_pipeline=pipeline)

        def contain(trigger, focus_path="", mode="kill"):
            order.append("contain")
            return {
                "trigger": trigger,
                "suspects": [{
                    "image": "evil.exe",
                    "path": r"C:\Temp\evil.exe",
                    "pid": 4712,
                    "cmdline": "evil.exe --encrypt",
                    "sha256": "abc123",
                }],
                "actions": ["kill:4712:evil.exe", "ifeo:evil.exe"],
                "quarantine": {"active": True, "entries": 1, "kills": 1},
            }

        shield._contain_after_hit = contain
        shield._block_suspicious_ips = lambda _reason: None
        canary = CanaryState(
            path=r"C:\Users\x\Documents\.cloud-honeypot-canary\!000_budget.xlsx",
            sha256="before",
            size=10,
        )

        with mock.patch(
            "client_defense_policy.process_action_plan",
            return_value={
                "action": "kill_quarantine",
                "contain": True,
                "kill": True,
                "alert_only": False,
                "force_urgent": True,
            },
        ):
            shield._on_canary_triggered(canary, "MODIFIED")

        self.assertEqual(order, ["contain", "urgent"])
        self.assertEqual(len(pipeline.alerts), 1)
        alert = pipeline.alerts[0]
        self.assertEqual(alert["threat_score"], 100)
        self.assertEqual(alert["target_service"], "SYSTEM")
        self.assertEqual(alert["recommended_action"], "review_quarantine")
        self.assertTrue(alert.get("suppress_local_notify"))
        context = alert["system_context"]["ransomware"]
        self.assertEqual(context["file"], canary.path)
        self.assertEqual(context["change_type"], "MODIFIED")
        self.assertEqual(context["suspects"][0]["pid"], 4712)
        process_event = alert["raw_events"][1]
        self.assertEqual(process_event["process_name"], "evil.exe")
        self.assertEqual(process_event["cmdline"], "evil.exe --encrypt")

class TestHealthRansomwareWire(unittest.TestCase):
    def test_health_snapshot_includes_quarantine_details(self):
        class Shield:
            _running = True
            _vss_count = 2

            @staticmethod
            def get_stats():
                return {
                    "canary_alerts": 1,
                    "canary_coverage": {
                        "mode": "observe",
                        "configured": True,
                        "files_total": 1,
                        "files_intact": 0,
                        "files_missing": 1,
                        "roots_covered": 1,
                        "coverage_ok": False,
                    },
                }

            @staticmethod
            def get_quarantine():
                return {
                    "active": True,
                    "locked_at": "2026-07-21T00:00:00",
                    "trigger": r"canary MODIFIED: C:\bait.xlsx",
                    "entries": [{
                        "image": "evil.exe",
                        "path": r"C:\Temp\evil.exe",
                        "pid": 4712,
                        "cmdline": "evil.exe --encrypt",
                        "sha256": "abc123",
                        "ifeo": True,
                        "at": "2026-07-21T00:00:01",
                    }],
                }

        api = _ApiClient()
        monitor = SystemHealthMonitor(
            api_client=api,
            token_getter=lambda: "test-token",
            ransomware_shield=Shield(),
        )
        monitor._latest = {"cpu_percent": 0}

        self.assertTrue(monitor._send_report())
        snapshot = api.payload["snapshot"]
        self.assertFalse(snapshot["canary_files_intact"])
        self.assertEqual(snapshot["ransomware_shield_status"], "active")
        self.assertEqual(snapshot["vss_shadow_count"], 2)
        quarantine = snapshot["ransomware_quarantine"]
        self.assertTrue(quarantine["active"])
        self.assertEqual(quarantine["entries"][0]["pid"], 4712)
        self.assertEqual(
            quarantine["entries"][0]["cmdline"], "evil.exe --encrypt"
        )
        cov = snapshot["canary_coverage"]
        self.assertEqual(cov["files_total"], 1)
        self.assertEqual(cov["files_intact"], 0)
        self.assertFalse(cov["coverage_ok"])
        self.assertNotIn("Users", str(cov))


class TestCanaryPolicy(unittest.TestCase):
    def test_desktop_paths_are_forbidden(self):
        from client_ransomware_shield import is_forbidden_canary_path
        self.assertTrue(is_forbidden_canary_path(
            r"C:\Users\Public\Desktop\.ImportantNotes.docx.canary"
        ))
        self.assertTrue(is_forbidden_canary_path(
            r"C:/Users/Alice/Desktop/bait.xlsx"
        ))
        self.assertFalse(is_forbidden_canary_path(
            r"C:\Users\Public\Documents\.FinancialReport2024.xlsx.canary"
        ))
        self.assertFalse(is_forbidden_canary_path(
            r"C:\ProgramData\.SystemConfig.dat.canary"
        ))

    def test_canary_coverage_is_path_free(self):
        shield = RansomwareShield()
        shield._canaries = [
            CanaryState(path=r"C:\Users\Public\Documents\.cloud-honeypot-canary\!000_reports\a.xlsx",
                        sha256="a" * 64, size=10),
            CanaryState(path=r"C:\ProgramData\.cloud-honeypot-canary\!000_reports\b.xlsx",
                        sha256="b" * 64, size=10),
        ]
        with mock.patch("os.path.isfile", return_value=True):
            stats = shield.get_stats()
        cov = stats["canary_coverage"]
        self.assertEqual(cov["files_total"], 2)
        self.assertEqual(cov["files_intact"], 2)
        self.assertEqual(cov["files_missing"], 0)
        self.assertTrue(cov["coverage_ok"])
        self.assertGreaterEqual(cov["roots_covered"], 1)
        blob = str(cov)
        self.assertNotIn("Documents", blob)
        self.assertNotIn("ProgramData", blob)
        self.assertNotIn(".xlsx", blob)


if __name__ == "__main__":
    unittest.main()
