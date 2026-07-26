#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Fleet canary gates (contract cloud/FLEET_CANARY.md C-CANARY-1…5)."""

import unittest

import client_fleet_canary as fc
from client_network_guard import load_config as ng_load
from client_silent_hours import SilentHoursConfig


class TestFleetCanary(unittest.TestCase):
    def tearDown(self):
        fc.apply_fleet_rollout({})

    def test_missing_fail_closed(self):
        snap = fc.apply_fleet_rollout({})
        self.assertFalse(snap["present"])
        self.assertFalse(snap["in_canary"])
        for g in fc._ALL_GATES:
            self.assertFalse(snap["gates"][g])
            self.assertFalse(fc.gate_allowed(g))

    def test_malformed_schema_fail_closed(self):
        snap = fc.apply_fleet_rollout({
            "fleet_rollout": {"schema": "nope", "gates": {"offline_urgent_queue": True}}
        })
        self.assertFalse(snap["present"])
        self.assertFalse(fc.gate_allowed(fc.GATE_OFFLINE))

    def test_gates_and_enabled(self):
        fc.apply_fleet_rollout({
            "fleet_rollout": {
                "schema": "fleet_rollout/1.0",
                "in_canary": True,
                "gates": {
                    "silent_hours_auto_actions": True,
                    "network_guard_auto_contain": False,
                    "offline_urgent_queue": True,
                    "defense_isolate_armed": True,
                },
            }
        })
        self.assertTrue(fc.and_enabled(fc.GATE_SILENT, True))
        self.assertFalse(fc.and_enabled(fc.GATE_SILENT, False))
        self.assertFalse(fc.and_enabled(fc.GATE_NG, True))
        self.assertTrue(fc.and_enabled(fc.GATE_OFFLINE, True))

    def test_mutate_clears_autos_when_gate_false(self):
        fc.apply_fleet_rollout({
            "fleet_rollout": {
                "schema": "fleet_rollout/1.0",
                "gates": {
                    "silent_hours_auto_actions": False,
                    "network_guard_auto_contain": False,
                    "offline_urgent_queue": False,
                    "defense_isolate_armed": False,
                },
            }
        })
        out = fc.mutate_config_for_gates({
            "silent_hours": {
                "auto_block_ip": True,
                "auto_logoff": True,
                "auto_disable_account": True,
            },
            "protection": {
                "network_guard": {
                    "auto_contain": True,
                    "auto_kill": True,
                    "auto_restore": True,
                },
                "isolate_armed": True,
            },
            "isolate_armed": True,
        })
        sh = out["silent_hours"]
        self.assertFalse(sh["auto_block_ip"])
        self.assertFalse(sh["auto_logoff"])
        self.assertFalse(sh["auto_disable_account"])
        ng = out["protection"]["network_guard"]
        self.assertFalse(ng["auto_contain"])
        self.assertFalse(out["isolate_armed"])

    def test_silent_hours_honors_gate_and(self):
        fc.apply_fleet_rollout({})
        cfg = SilentHoursConfig.from_dict({
            "auto_logoff": True,
            "auto_disable_account": True,
            "auto_block_ip": True,
        })
        self.assertFalse(cfg.auto_logoff)
        self.assertFalse(cfg.auto_disable_account)
        self.assertFalse(cfg.auto_block_ip)

        fc.apply_fleet_rollout({
            "fleet_rollout": {
                "schema": "fleet_rollout/1.0",
                "gates": {"silent_hours_auto_actions": True},
            }
        })
        cfg2 = SilentHoursConfig.from_dict({
            "auto_logoff": True,
            "auto_disable_account": True,
            "auto_block_ip": True,
        })
        self.assertTrue(cfg2.auto_logoff)
        self.assertTrue(cfg2.auto_block_ip)

    def test_network_guard_honors_gate_and(self):
        fc.apply_fleet_rollout({})
        cfg = ng_load({
            "protection": {
                "network_guard": {
                    "enabled": True,
                    "auto_contain": True,
                    "auto_kill": True,
                }
            }
        })
        self.assertFalse(cfg["auto_contain"])
        self.assertFalse(cfg["auto_kill"])

        fc.apply_fleet_rollout({
            "fleet_rollout": {
                "schema": "fleet_rollout/1.0",
                "gates": {"network_guard_auto_contain": True},
            }
        })
        cfg2 = ng_load({
            "protection": {
                "network_guard": {
                    "auto_contain": True,
                    "auto_kill": True,
                }
            }
        })
        self.assertTrue(cfg2["auto_contain"])
        self.assertTrue(cfg2["auto_kill"])


if __name__ == "__main__":
    unittest.main()
