#!/usr/bin/env python3
"""Firewall Management + Windows parity (contract 1.4.40 / 1.4.41)."""

import unittest
from unittest import mock

from client_firewall_inventory import (
    filter_asteria_rules,
    firewall_rule,
    firewall_rule_requires_confirm,
    match_asteria_prefix,
    parse_profiles_netsh,
    parse_rules_netsh,
    set_firewall_profile,
)
from client_remote_commands import (
    ALLOWED_COMMANDS,
    REQUIRES_CONFIRMATION,
    RemoteCommandExecutor,
    firewall_rule_requires_confirm as remote_fw_confirm,
)


SAMPLE_PROFILES = """
Domain Profile Settings:
----------------------------------------------------------------------
State                                 ON
Firewall Policy                       BlockInbound,AllowOutbound
LocalFirewallRules                    N/A (GPO-store only)

Private Profile Settings:
----------------------------------------------------------------------
State                                 ON
Firewall Policy                       BlockInbound,AllowOutbound

Public Profile Settings:
----------------------------------------------------------------------
State                                 OFF
Firewall Policy                       AllowInbound,BlockOutbound
"""

SAMPLE_RULES = """
Rule Name:                            AR-BLOCK-203.0.113.10
Enabled:                              Yes
Direction:                            In
Profiles:                             Domain,Private,Public
Grouping:
LocalIP:                              Any
RemoteIP:                             203.0.113.10
Protocol:                             Any
LocalPort:                            Any
RemotePort:                           Any
Edge traversal:                       No
Action:                               Block

Rule Name:                            AR-INTEL-bad.example
Enabled:                              No
Direction:                            In
Profiles:                             Domain,Private,Public
RemoteIP:                             198.51.100.1
Protocol:                             TCP
LocalPort:                            Any
RemotePort:                           Any
Action:                               Block

Rule Name:                            HP-BLOCK-10.0.0.1
Enabled:                              Yes
Direction:                            In
RemoteIP:                             10.0.0.1
Protocol:                             Any
Action:                               Block

Rule Name:                            Remote Desktop - User Mode (TCP-In)
Enabled:                              Yes
Direction:                            In
Profiles:                             Domain,Private,Public
Grouping:                             Remote Desktop
LocalIP:                              Any
RemoteIP:                             Any
Protocol:                             TCP
LocalPort:                            3389
RemotePort:                           Any
Edge traversal:                       No
Action:                               Allow

Rule Name:                            SomeOtherRule
Enabled:                              Yes
Direction:                            In
RemoteIP:                             Any
Protocol:                             Any
Action:                               Allow
"""


class TestPrefixMatch(unittest.TestCase):
    def test_prefixes(self):
        self.assertEqual(match_asteria_prefix("AR-BLOCK-1.2.3.4"), "AR-BLOCK")
        self.assertEqual(match_asteria_prefix("AR-MANUAL-9"), "AR-MANUAL")
        self.assertEqual(match_asteria_prefix("ar-intel-x"), "AR-INTEL")
        self.assertEqual(match_asteria_prefix("HP-BLOCK-9"), "HP-BLOCK")
        self.assertEqual(match_asteria_prefix("HONEYPOT_BLOCK_1"), "HONEYPOT")
        self.assertIsNone(match_asteria_prefix("honeypot-client"))
        self.assertIsNone(match_asteria_prefix("HoneypotForward_RDP_3389"))
        self.assertIsNone(match_asteria_prefix("CloudHoneypot-x"))
        self.assertIsNone(match_asteria_prefix("Allow-HTTP"))


class TestParseProfiles(unittest.TestCase):
    def test_allprofiles(self):
        p = parse_profiles_netsh(SAMPLE_PROFILES)
        self.assertEqual(p["domain"]["state"], "on")
        self.assertEqual(p["domain"]["inbound"], "block")
        self.assertEqual(p["domain"]["outbound"], "allow")
        self.assertEqual(p["public"]["state"], "off")
        self.assertEqual(p["public"]["inbound"], "allow")
        self.assertEqual(p["public"]["outbound"], "block")


class TestParseRules(unittest.TestCase):
    def test_canonical_fields(self):
        rules = parse_rules_netsh(SAMPLE_RULES, "In")
        rdp = [r for r in rules if "Remote Desktop" in r["name"]][0]
        self.assertEqual(rdp["local_port"], "3389")
        self.assertEqual(rdp["protocol"], "TCP")
        self.assertEqual(rdp["action"], "Allow")
        self.assertIsNone(rdp["asteria_prefix"])
        ar = [r for r in rules if r["name"].startswith("AR-BLOCK")][0]
        self.assertEqual(ar["asteria_prefix"], "AR-BLOCK")
        self.assertEqual(ar["remote_address"], "203.0.113.10")

    def test_filter_and_counts(self):
        rules = parse_rules_netsh(SAMPLE_RULES, "In")
        capped, counts = filter_asteria_rules(rules, max_rules=500)
        self.assertEqual(counts["asteria_rules"], 3)
        self.assertEqual(counts["ar_block"], 1)
        self.assertEqual(counts["ar_intel"], 1)
        self.assertEqual(counts["hp_legacy"], 1)
        self.assertEqual(len(capped), 3)
        disabled = [r for r in capped if r["name"].startswith("AR-INTEL")][0]
        self.assertFalse(disabled["enabled"])
        self.assertEqual(disabled["prefix"], "AR-INTEL")

    def test_max_rules_cap(self):
        rules = parse_rules_netsh(SAMPLE_RULES, "In")
        capped, counts = filter_asteria_rules(rules, max_rules=1)
        self.assertEqual(len(capped), 1)
        self.assertEqual(counts["asteria_rules"], 3)


class TestSetProfile(unittest.TestCase):
    def test_refuse_unknown_profile(self):
        out = set_firewall_profile("dmz", state="on")
        self.assertFalse(out["ok"])
        self.assertEqual(out["error"], "unknown_profile")

    def test_set_state(self):
        with mock.patch(
            "client_firewall_inventory.run_cmd",
            return_value=(0, "Ok.", ""),
        ) as run, mock.patch(
            "client_firewall_inventory.collect_firewall_profiles",
            return_value={"public": {"state": "on", "inbound": "block", "outbound": "allow"}},
        ):
            out = set_firewall_profile("public", state="on")
        self.assertTrue(out["ok"])
        self.assertIn("profiles", out)
        args = run.call_args[0][0]
        self.assertEqual(args[:4], ["netsh", "advfirewall", "set", "publicprofile"])

    def test_profile_all(self):
        calls = []

        def fake_run(cmd, timeout=30):
            calls.append(cmd)
            return (0, "Ok.", "")

        with mock.patch(
            "client_firewall_inventory.run_cmd", side_effect=fake_run
        ), mock.patch(
            "client_firewall_inventory.collect_firewall_profiles",
            return_value={
                "domain": {"state": "on", "inbound": "block", "outbound": "allow"},
                "private": {"state": "on", "inbound": "block", "outbound": "allow"},
                "public": {"state": "on", "inbound": "block", "outbound": "allow"},
            },
        ):
            out = set_firewall_profile("all", state="on")
        self.assertTrue(out["ok"])
        profiles_hit = {c[3] for c in calls}
        self.assertEqual(
            profiles_hit,
            {"domainprofile", "privateprofile", "publicprofile"},
        )


class TestFirewallRule(unittest.TestCase):
    def test_confirm_gate(self):
        self.assertFalse(firewall_rule_requires_confirm({"op": "enable"}))
        self.assertFalse(firewall_rule_requires_confirm({"op": "disable"}))
        self.assertTrue(firewall_rule_requires_confirm({"op": "delete"}))
        self.assertTrue(firewall_rule_requires_confirm({"op": "add"}))
        self.assertTrue(remote_fw_confirm({"op": "delete"}))

    def test_disable(self):
        with mock.patch(
            "client_firewall_inventory.run_cmd",
            return_value=(0, "Ok.", ""),
        ) as run:
            out = firewall_rule({
                "op": "disable",
                "name": "Remote Desktop - User Mode (TCP-In)",
                "direction": "In",
            })
        self.assertTrue(out["ok"])
        self.assertEqual(out["enabled"], False)
        cmd = run.call_args[0][0]
        self.assertIn("enable=no", cmd)
        self.assertIn("name=Remote Desktop - User Mode (TCP-In)", cmd)

    def test_add_ar_manual(self):
        with mock.patch(
            "client_firewall_inventory.run_cmd",
            return_value=(0, "Ok.", ""),
        ) as run:
            out = firewall_rule({
                "op": "add",
                "remote_address": "203.0.113.10",
                "direction": "In",
                "action": "Block",
            })
        self.assertTrue(out["ok"])
        self.assertTrue(out["name"].startswith("AR-MANUAL-"))
        cmd = run.call_args[0][0]
        self.assertIn("add", cmd)
        self.assertIn("remoteip=203.0.113.10", cmd)

    def test_access_denied(self):
        with mock.patch(
            "client_firewall_inventory.run_cmd",
            return_value=(1, "", "Access is denied."),
        ):
            out = firewall_rule({"op": "delete", "name": "GPO Rule"})
        self.assertFalse(out["ok"])
        self.assertEqual(out["error"], "ACCESS_DENIED")


class TestRemoteWhitelist(unittest.TestCase):
    def test_commands_whitelisted(self):
        self.assertIn("list_firewall", ALLOWED_COMMANDS)
        self.assertIn("firewall_set_profile", ALLOWED_COMMANDS)
        self.assertIn("firewall_rule", ALLOWED_COMMANDS)
        self.assertIn("firewall_set_profile", REQUIRES_CONFIRMATION)
        # enable/disable must not be blanket-gated via REQUIRES_CONFIRMATION
        self.assertNotIn("firewall_rule", REQUIRES_CONFIRMATION)
        self.assertNotIn("list_firewall", REQUIRES_CONFIRMATION)

    def test_list_firewall_handler(self):
        fake = {
            "profiles": {"domain": {"state": "on", "inbound": "block", "outbound": "allow"}},
            "inbound_rules": [{"name": "x"}],
            "outbound_rules": [],
            "asteria_rules": [],
            "counts": {"asteria_rules": 0, "inbound_total": 1},
            "captured_at": "2026-07-29T12:00:00Z",
            "engine": "netsh",
        }
        ex = RemoteCommandExecutor()
        with mock.patch(
            "client_firewall_inventory.list_firewall", return_value=fake
        ):
            result = ex._cmd_list_firewall({"scope": "all"})
        self.assertTrue(result["success"])
        self.assertEqual(result["data"]["engine"], "netsh")

    def test_set_profile_returns_inventory(self):
        ex = RemoteCommandExecutor()
        inv_data = {
            "profiles": {
                "public": {"state": "on", "inbound": "block", "outbound": "allow"},
            },
            "asteria_rules": [],
            "counts": {"asteria_rules": 0},
            "captured_at": "2026-07-29T12:00:00Z",
        }
        with mock.patch(
            "client_firewall_inventory.set_firewall_profile",
            return_value={
                "ok": True,
                "profile": "public",
                "changes": ["state=on"],
                "profiles": inv_data["profiles"],
            },
        ), mock.patch(
            "client_firewall_inventory.list_firewall",
            return_value=inv_data,
        ):
            result = ex._cmd_firewall_set_profile({
                "profile": "public", "state": "on",
            })
        self.assertTrue(result["success"])
        self.assertIn("profiles", result["data"])

    def test_firewall_rule_handler(self):
        ex = RemoteCommandExecutor()
        with mock.patch(
            "client_firewall_inventory.firewall_rule",
            return_value={"ok": True, "name": "R", "op": "disable", "enabled": False},
        ), mock.patch(
            "client_firewall_inventory.list_firewall",
            return_value={"asteria_rules": [], "counts": {}, "captured_at": "t"},
        ):
            result = ex._cmd_firewall_rule({"op": "disable", "name": "R"})
        self.assertTrue(result["success"])
        self.assertEqual(result["data"]["rule_change"]["op"], "disable")


class TestListFirewallScope(unittest.TestCase):
    def test_scope_all_caps(self):
        inbound = parse_rules_netsh(SAMPLE_RULES, "In")
        outbound = [
            {
                "name": "OutRule",
                "enabled": True,
                "direction": "Out",
                "action": "Allow",
                "asteria_prefix": None,
            }
        ] * 5
        with mock.patch(
            "client_firewall_inventory.collect_firewall_profiles",
            return_value={"domain": {"state": "on", "inbound": "block", "outbound": "allow"}},
        ), mock.patch(
            "client_firewall_inventory._enumerate_rules",
            side_effect=lambda d: (True, inbound if d == "In" else outbound),
        ):
            from client_firewall_inventory import list_firewall
            data = list_firewall({
                "scope": "all",
                "max_rules_per_direction": 2,
                "include_asteria_rules": True,
            })
        self.assertEqual(len(data["inbound_rules"]), 2)
        self.assertTrue(data["truncated_inbound"])
        self.assertEqual(data["counts"]["inbound_total"], len(inbound))
        self.assertEqual(data["engine"], "netsh")
        self.assertGreaterEqual(data["counts"]["asteria_rules"], 3)


if __name__ == "__main__":
    unittest.main()
