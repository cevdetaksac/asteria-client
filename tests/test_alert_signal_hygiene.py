#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CLIENT_ALERT_SIGNAL_HYGIENE.md — severity / false-positive rules."""

import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from client_ransomware_shield import (
    CanaryState,
    RansomwareShield,
    classify_shadow_copy_severity,
    is_vss_delete_cmdline,
    is_vss_inventory_cmdline,
)
from client_threat_engine import (
    ThreatEngine,
    TRUSTED_LOGON_SCORE_CAP,
    is_trusted_logon_source,
)


class TestVssInventoryHygiene(unittest.TestCase):
    def test_list_shadows_is_inventory(self):
        self.assertTrue(is_vss_inventory_cmdline("vssadmin list shadows"))
        self.assertTrue(is_vss_inventory_cmdline("vssadmin.exe list shadows"))
        self.assertTrue(is_vss_inventory_cmdline(""))
        self.assertFalse(is_vss_delete_cmdline("vssadmin list shadows"))

    def test_delete_shadows_is_ransomware(self):
        self.assertTrue(is_vss_delete_cmdline("vssadmin delete shadows /all"))
        self.assertFalse(is_vss_inventory_cmdline("vssadmin delete shadows /all"))

    def test_vss_delete_intent_arms_quarantine_without_ifeo(self):
        alerts = []
        shield = RansomwareShield(on_alert=lambda a: alerts.append(a))
        with mock.patch("subprocess.run") as run:
            run.return_value = mock.Mock(returncode=0)
            with mock.patch.object(shield, "_apply_ifeo") as ifeo:
                shield._respond_vss_delete_intent(
                    "vssadmin.exe", 4242,
                    "vssadmin delete shadows /all",
                    "VSS shadow delete", 100,
                )
                ifeo.assert_not_called()
        self.assertTrue(shield._quarantine.get("active"))
        self.assertEqual(shield._quarantine.get("trigger"), "vss_delete_intent")
        types = [a.get("threat_type") for a in alerts]
        self.assertIn("ransomware_vss_delete_intent", types)

    def test_process_monitor_skips_list_shadows(self):
        alerts = []
        shield = RansomwareShield(on_alert=lambda a: alerts.append(a))
        fake = mock.Mock()
        fake.info = {
            "pid": 99901,
            "name": "vssadmin.exe",
            "cmdline": ["vssadmin", "list", "shadows"],
            "create_time": 1.0,
        }
        with mock.patch("psutil.process_iter", return_value=[fake]):
            shield._check_suspicious_processes()
        self.assertEqual(alerts, [])

    def test_process_monitor_fires_on_delete(self):
        alerts = []
        shield = RansomwareShield(on_alert=lambda a: alerts.append(a))
        fake = mock.Mock()
        fake.info = {
            "pid": 99902,
            "name": "vssadmin.exe",
            "cmdline": ["vssadmin", "delete", "shadows", "/all"],
            "create_time": 1.0,
        }
        with mock.patch("psutil.process_iter", return_value=[fake]):
            shield._check_suspicious_processes()
        self.assertTrue(alerts)
        self.assertEqual(alerts[0]["threat_type"], "ransomware_process")
        self.assertEqual(alerts[0]["severity"], "critical")


class TestShadowCopySeverity(unittest.TestCase):
    def test_small_delta_warning(self):
        sev, score = classify_shadow_copy_severity(1, 5)
        self.assertEqual(sev, "warning")
        self.assertLess(score, 81)

    def test_mass_or_zero_remaining_critical(self):
        self.assertEqual(classify_shadow_copy_severity(3, 2)[0], "critical")
        self.assertEqual(classify_shadow_copy_severity(1, 0)[0], "critical")

    def test_delete_cmd_forces_critical(self):
        sev, score = classify_shadow_copy_severity(1, 8, delete_cmd_seen=True)
        self.assertEqual(sev, "critical")
        self.assertEqual(score, 100)

    def test_on_vss_deletion_soft_no_contain(self):
        pipeline_alerts = []
        shield = RansomwareShield(
            alert_pipeline=type("P", (), {
                "send_urgent": lambda self, a: pipeline_alerts.append(a),
            })(),
        )
        shield._contain_after_hit = mock.Mock(return_value={"suspects": [], "actions": []})
        shield._block_suspicious_ips = mock.Mock()
        shield._on_vss_deletion(1, 5)
        self.assertEqual(pipeline_alerts[0]["severity"], "warning")
        shield._contain_after_hit.assert_not_called()
        shield._block_suspicious_ips.assert_not_called()

    def test_on_vss_deletion_critical_single_emit(self):
        pipeline_alerts = []
        on_alerts = []
        shield = RansomwareShield(
            on_alert=lambda a: on_alerts.append(a),
            alert_pipeline=type("P", (), {
                "send_urgent": lambda self, a: pipeline_alerts.append(a),
            })(),
        )
        shield._contain_after_hit = mock.Mock(
            return_value={"suspects": [], "actions": [], "quarantine": {}}
        )
        shield._block_suspicious_ips = mock.Mock()
        shield._on_vss_deletion(3, 0)
        self.assertEqual(len(pipeline_alerts), 1)
        self.assertEqual(len(on_alerts), 0)
        self.assertIn("title", pipeline_alerts[0])
        self.assertEqual(pipeline_alerts[0]["threat_type"], "shadow_copy_deleted")
        shield._contain_after_hit.assert_called_once()

    def test_empty_active_quarantine_auto_disarm(self):
        import json
        import os
        import tempfile

        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        qpath = os.path.join(td.name, "ransomware_quarantine.json")
        with open(qpath, "w", encoding="utf-8") as fh:
            json.dump(
                {
                    "active": True,
                    "locked_at": "2026-07-26T00:00:00",
                    "trigger": "vss_deletion:2",
                    "entries": [],
                },
                fh,
            )
        shield = RansomwareShield()
        shield._quarantine_path = lambda: qpath
        shield._load_quarantine()
        self.assertFalse(shield.get_quarantine().get("active"))
        with open(qpath, "r", encoding="utf-8") as fh:
            disk = json.load(fh)
        self.assertFalse(disk.get("active"))
        self.assertEqual(disk.get("unlock_reason"), "load_empty")


class TestCanaryHygiene(unittest.TestCase):
    def test_self_touch_suppresses(self):
        pipeline = type("P", (), {"alerts": [], "send_urgent": None})()
        pipeline.alerts = []
        pipeline.send_urgent = lambda a: pipeline.alerts.append(a)
        shield = RansomwareShield(alert_pipeline=pipeline)
        shield._contain_after_hit = lambda **_k: {
            "trigger": "t", "suspects": [], "actions": [], "quarantine": {},
        }
        canary = CanaryState(path=r"C:\tmp\canary.xlsx", sha256="a", size=1)
        shield._note_canary_self_touch(canary.path)
        shield._on_canary_triggered(canary, "MODIFIED")
        self.assertEqual(pipeline.alerts, [])

    def test_single_modified_soft_warning(self):
        alerts = []
        shield = RansomwareShield(on_alert=lambda a: alerts.append(a))
        shield._vss_count = 4
        shield._contain_after_hit = lambda **_k: {
            "trigger": "t", "suspects": [], "actions": [],
            "quarantine": {"active": True, "entries": 0},
        }
        shield._block_suspicious_ips = mock.Mock()
        canary = CanaryState(
            path=r"C:\Users\x\Documents\.cloud-honeypot-canary\!000.xlsx",
            sha256="a",
            size=10,
        )
        shield._on_canary_triggered(canary, "MODIFIED")
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["severity"], "warning")
        self.assertLessEqual(alerts[0]["threat_score"], 50)
        self.assertFalse(alerts[0].get("force_urgent"))
        shield._block_suspicious_ips.assert_not_called()

    def test_soft_debounce_30m(self):
        alerts = []
        shield = RansomwareShield(on_alert=lambda a: alerts.append(a))
        shield._vss_count = 4
        shield._contain_after_hit = lambda **_k: {
            "trigger": "t", "suspects": [], "actions": [],
            "quarantine": {"active": False, "entries": 0},
        }
        canary = CanaryState(
            path=r"C:\Users\x\Desktop\bait.xlsx",
            sha256="a",
            size=10,
        )
        shield._on_canary_triggered(canary, "MODIFIED")
        shield._on_canary_triggered(canary, "MODIFIED")
        self.assertEqual(len(alerts), 1)


class TestTrustedLogonHygiene(unittest.TestCase):
    def test_local_is_trusted(self):
        self.assertTrue(is_trusted_logon_source("local"))
        self.assertTrue(is_trusted_logon_source("127.0.0.1"))

    def test_whitelist_local_logon_is_info(self):
        emitted = []
        engine = ThreatEngine(on_alert=lambda a: emitted.append(a))
        engine.update_whitelist({"203.0.113.10"})
        engine.process_event({
            "event_type": "successful_logon",
            "source_ip": "203.0.113.10",
            "event_id": 4624,
            "target_service": "RDP",
            "logon_type": 10,
        })
        self.assertTrue(emitted)
        self.assertEqual(emitted[0]["severity"], "info")
        self.assertLessEqual(emitted[0]["threat_score"], TRUSTED_LOGON_SCORE_CAP)
        self.assertNotIn("Lateral Movement", emitted[0].get("title", ""))

    def test_privilege_assigned_local_info(self):
        emitted = []
        engine = ThreatEngine(on_alert=lambda a: emitted.append(a))
        engine.process_event({
            "event_type": "privilege_assigned",
            "source_ip": "",
            "event_id": 4672,
        })
        self.assertTrue(emitted)
        self.assertEqual(emitted[0]["severity"], "info")
        self.assertLessEqual(emitted[0]["threat_score"], TRUSTED_LOGON_SCORE_CAP)


if __name__ == "__main__":
    unittest.main()
