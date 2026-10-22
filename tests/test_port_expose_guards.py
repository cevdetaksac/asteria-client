# -*- coding: utf-8 -*-
"""port_expose / firewall guards (no live RDP changes)."""
from __future__ import annotations

from client_firewall_inventory import (
    firewall_rule_requires_confirm,
    guard_firewall_mutation,
    guard_port_change,
    rule_stable_id,
)
from client_netports import exposure_of_port


def test_rule_stable_id_stable():
    a = rule_stable_id({"name": "X", "direction": "In", "local_port": "45999",
                        "remote_address": "Any", "protocol": "TCP", "action": "Allow"})
    b = rule_stable_id({"name": "X", "direction": "In", "local_port": "45999",
                        "remote_address": "Any", "protocol": "TCP", "action": "Allow"})
    assert a == b and a.startswith("fw-")


def test_edit_requires_confirm():
    assert firewall_rule_requires_confirm({"op": "edit"}) is True
    assert firewall_rule_requires_confirm({"op": "enable"}) is False


def test_guard_blocks_asteria_443():
    g = guard_firewall_mutation(op="add", params={
        "direction": "Out", "action": "block", "remote_port": "443",
        "remote_address": "Any",
    })
    assert g["ok"] is False and g["code"] == "GUARD_ASTERIA_443"


def test_guard_blocks_rdp_close():
    g = guard_port_change(port=3389, mode="close", ips=[], force=False)
    assert g["ok"] is False and g["code"] == "GUARD_RDP_CLOSE"
    assert guard_port_change(port=3389, mode="close", ips=[], force=True)["ok"] is True


def test_guard_allows_dummy_port():
    assert guard_port_change(port=45999, mode="close", ips=[], force=False)["ok"] is True


def test_exposure_of_port_logic():
    assert exposure_of_port(45999, rules=[]) == "closed"
    assert exposure_of_port(45999, rules=[
        {"action": "Allow", "enabled": True, "remote_address": "Any"},
    ]) == "open"
    assert exposure_of_port(45999, rules=[
        {"action": "Allow", "enabled": True, "remote_address": "1.2.3.4"},
    ]) == "restricted"
