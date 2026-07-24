#!/usr/bin/env python3
"""Contract 1.4.31: new AR rules, legacy deletion, one-time boot migration."""

import json
import logging
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import client_firewall as fw


class TestArRuleNames(unittest.TestCase):
    def setUp(self):
        self.backend = fw.WindowsFirewallBackend(logging.getLogger("test.fw.brand"))

    def test_block_candidates_include_ar_and_legacy(self):
        names = self.backend.rule_name_candidates("42", "203.0.113.10")
        self.assertIn("AR-BLOCK-42", names)
        self.assertIn("HP-BLOCK-42", names)
        self.assertIn("AR-BLOCK-203.0.113.10", names)
        self.assertIn("HP-BLOCK-203.0.113.10", names)
        self.assertEqual(
            fw.block_rule_name("203.0.113.0/24"),
            "AR-BLOCK-203.0.113.0",
        )
        self.assertEqual(fw.block_rule_name("country:tr"), "AR-BLOCK-country-TR")

    def test_new_block_writes_ar_and_removes_hp(self):
        with (
            mock.patch.object(self.backend, "_delete_rule_by_name") as delete,
            mock.patch.object(self.backend, "_add_rule", return_value=True) as add,
        ):
            self.assertTrue(self.backend.apply_block("203.0.113.10", ["203.0.113.10"]))
        delete.assert_any_call("AR-BLOCK-203.0.113.10")
        delete.assert_any_call("HP-BLOCK-203.0.113.10")
        add.assert_called_once_with("AR-BLOCK-203.0.113.10", "203.0.113.10")

    def test_new_intel_writes_ar_and_removes_hp(self):
        calls = []

        def fake_run(cmd, **_kwargs):
            calls.append(cmd)
            return 0, "Ok.", ""

        with (
            mock.patch.object(self.backend, "_delete_intel_rule_by_name") as delete,
            mock.patch.object(self.backend, "_add_rule", return_value=True) as add,
            mock.patch.object(fw, "run_cmd", side_effect=fake_run),
        ):
            self.assertTrue(self.backend.apply_intel_block("ioc/1", "198.51.100.8"))
        delete.assert_any_call("AR-INTEL-ioc-1")
        delete.assert_any_call("HP-INTEL-ioc-1")
        add.assert_called_once_with("AR-INTEL-ioc-1", "198.51.100.8")
        self.assertTrue(any("name=AR-INTEL-ioc-1" in cmd for cmd in calls))

    def test_scan_enumerates_ar_hp_and_cloudhoneypot(self):
        listing = """
Rule Name:                            AR-BLOCK-203.0.113.1
RemoteIP:                             203.0.113.1

Rule Name:                            AR-INTEL-feed-1
RemoteIP:                             198.51.100.1

Rule Name:                            HP-BLOCK-192.0.2.1
RemoteIP:                             192.0.2.1

Rule Name:                            CloudHoneypotLegacy
RemoteIP:                             192.0.2.2
"""
        with mock.patch.object(fw, "run_cmd", return_value=(0, listing, "")):
            ok, rules = self.backend.scan_existing_rules_detailed()
        self.assertTrue(ok)
        self.assertEqual(
            {r["name"] for r in rules},
            {
                "AR-BLOCK-203.0.113.1",
                "AR-INTEL-feed-1",
                "HP-BLOCK-192.0.2.1",
                "CloudHoneypotLegacy",
            },
        )


class TestBootBrandMigration(unittest.TestCase):
    def test_migrates_once_then_snapshot_syncs(self):
        with tempfile.TemporaryDirectory() as tmp:
            marker = Path(tmp) / "firewall_brand.json"
            agent = fw.FirewallAgent("https://example.test/api", "tok")
            rules = [
                {
                    "name": "HP-BLOCK-203.0.113.5",
                    "remoteip": "203.0.113.5",
                    "suffix": "203.0.113.5",
                    "prefix": "HP-BLOCK-",
                    "legacy": True,
                },
                {
                    "name": "HP-INTEL-feed-1",
                    "remoteip": "198.51.100.7",
                    "suffix": "feed-1",
                    "prefix": "HP-INTEL-",
                    "legacy": True,
                },
            ]
            posts = []

            def post(path, body):
                posts.append((path, dict(body)))
                return {"status": "ok"}, 200

            with (
                mock.patch.object(fw, "_firewall_brand_state_path", return_value=marker),
                mock.patch.object(
                    agent.backend, "scan_existing_rules_detailed",
                    return_value=(True, rules),
                ),
                mock.patch.object(
                    agent.backend, "migrate_legacy_rule", return_value=True
                ) as migrate,
                mock.patch("client_block_store.merge_from_firewall_rules", return_value={}),
                mock.patch("client_block_store.extract_ips_from_rule", side_effect=lambda r: [r["remoteip"]]),
            ):
                agent._post_json = post
                agent._migrate_and_sync_rules()
                self.assertEqual(migrate.call_count, 2)
                self.assertEqual(posts[-1][0], "/api/agent/sync-rules")
                self.assertEqual(posts[-1][1]["mode"], "snapshot")
                names = {x["rule_name"] for x in posts[-1][1]["blocks"]}
                self.assertEqual(
                    names,
                    {"AR-BLOCK-203.0.113.5", "AR-INTEL-feed-1"},
                )
                state = json.loads(marker.read_text(encoding="utf-8"))
                self.assertEqual(state["firewall_brand"], "ar")

                migrate.reset_mock()
                agent._migrate_and_sync_rules()
                migrate.assert_not_called()
                self.assertNotIn("mode", posts[-1][1])

    def test_no_marker_when_snapshot_sync_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            marker = Path(tmp) / "firewall_brand.json"
            agent = fw.FirewallAgent("https://example.test/api", "tok")
            with (
                mock.patch.object(fw, "_firewall_brand_state_path", return_value=marker),
                mock.patch.object(
                    agent.backend, "scan_existing_rules_detailed",
                    return_value=(True, []),
                ),
            ):
                agent._post_json = lambda *_args: (None, 503)
                agent._migrate_and_sync_rules()
            self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
