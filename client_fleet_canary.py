# -*- coding: utf-8 -*-
"""Fleet canary gates (contract cloud/FLEET_CANARY.md, ≥1.4.37).

C-CANARY-1  Read ``fleet_rollout.gates`` on every threats/config apply
C-CANARY-2  Auto-action allowed only if gate==true AND local/config enable
C-CANARY-3  Missing/malformed fleet_rollout → all gates false (fail-closed)
C-CANARY-4  In-memory only — never durable-cache a previous true across restart
C-CANARY-5  Health/report may echo in_canary + gate map
"""

from __future__ import annotations

import copy
import threading
from typing import Any, Dict, Mapping, Optional

GATE_SILENT = "silent_hours_auto_actions"
GATE_NG = "network_guard_auto_contain"
GATE_OFFLINE = "offline_urgent_queue"
GATE_ISOLATE = "defense_isolate_armed"

_ALL_GATES = (GATE_SILENT, GATE_NG, GATE_OFFLINE, GATE_ISOLATE)

_lock = threading.Lock()
# Process-memory only (C-CANARY-4)
_state: Dict[str, Any] = {
    "schema": "",
    "cohort_id": "",
    "percent": 0,
    "bucket": None,
    "in_canary": False,
    "forced": False,
    "gates": {g: False for g in _ALL_GATES},
    "observe_days_recommended": 7,
    "message": "",
    "present": False,
}


def _false_gates() -> Dict[str, bool]:
    return {g: False for g in _ALL_GATES}


def apply_fleet_rollout(config: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
    """Parse fleet_rollout from threats/config into process memory. Fail-closed."""
    gates = _false_gates()
    snapshot: Dict[str, Any] = {
        "schema": "",
        "cohort_id": "",
        "percent": 0,
        "bucket": None,
        "in_canary": False,
        "forced": False,
        "gates": dict(gates),
        "observe_days_recommended": 7,
        "message": "",
        "present": False,
    }
    raw = None
    if isinstance(config, Mapping):
        raw = config.get("fleet_rollout")
    if isinstance(raw, Mapping) and str(raw.get("schema") or "").startswith("fleet_rollout/"):
        snapshot["present"] = True
        snapshot["schema"] = str(raw.get("schema") or "")
        snapshot["cohort_id"] = str(raw.get("cohort_id") or "")
        try:
            snapshot["percent"] = int(raw.get("percent") or 0)
        except (TypeError, ValueError):
            snapshot["percent"] = 0
        try:
            snapshot["bucket"] = int(raw["bucket"]) if raw.get("bucket") is not None else None
        except (TypeError, ValueError):
            snapshot["bucket"] = None
        snapshot["in_canary"] = bool(raw.get("in_canary"))
        snapshot["forced"] = bool(raw.get("forced"))
        try:
            snapshot["observe_days_recommended"] = int(
                raw.get("observe_days_recommended") or 7
            )
        except (TypeError, ValueError):
            snapshot["observe_days_recommended"] = 7
        snapshot["message"] = str(raw.get("message") or "")[:240]
        src_gates = raw.get("gates")
        if isinstance(src_gates, Mapping):
            for g in _ALL_GATES:
                gates[g] = bool(src_gates.get(g))
        # malformed gates object → already all false
        snapshot["gates"] = dict(gates)
    # else: missing/malformed → present=False, all gates false (C-CANARY-3)

    with _lock:
        _state.clear()
        _state.update(snapshot)
    return snapshot_for_health()


def gate_allowed(name: str) -> bool:
    """True only when the named gate is currently true in memory."""
    with _lock:
        return bool((_state.get("gates") or {}).get(name))


def and_enabled(gate_name: str, local_enabled: bool) -> bool:
    """C-CANARY-2: gate AND local/config enable."""
    return bool(local_enabled) and gate_allowed(gate_name)


def snapshot_for_health() -> Dict[str, Any]:
    with _lock:
        return {
            "schema": _state.get("schema") or "",
            "cohort_id": _state.get("cohort_id") or "",
            "percent": int(_state.get("percent") or 0),
            "bucket": _state.get("bucket"),
            "in_canary": bool(_state.get("in_canary")),
            "forced": bool(_state.get("forced")),
            "gates": dict(_state.get("gates") or _false_gates()),
            "observe_days_recommended": int(
                _state.get("observe_days_recommended") or 7
            ),
            "message": str(_state.get("message") or ""),
            "present": bool(_state.get("present")),
        }


def mutate_config_for_gates(config: Mapping[str, Any]) -> Dict[str, Any]:
    """Return a shallow-copied config with risky autos cleared when gates false.

    Mirrors cloud fail-closed mutation so older local caches cannot re-enable.
    """
    out = copy.deepcopy(dict(config or {}))
    gates = snapshot_for_health()["gates"]

    if not gates.get(GATE_SILENT):
        sh = out.get("silent_hours")
        if isinstance(sh, dict):
            sh = dict(sh)
            sh["auto_block_ip"] = False
            sh["auto_logoff"] = False
            sh["auto_disable_account"] = False
            out["silent_hours"] = sh

    if not gates.get(GATE_NG):
        prot = out.get("protection")
        if not isinstance(prot, dict):
            prot = {}
        else:
            prot = dict(prot)
        ng = prot.get("network_guard")
        if not isinstance(ng, dict):
            ng = {}
        else:
            ng = dict(ng)
        ng["auto_contain"] = False
        ng["auto_kill"] = False
        ng["auto_restore"] = False
        prot["network_guard"] = ng
        out["protection"] = prot

    if not gates.get(GATE_ISOLATE):
        out["isolate_armed"] = False
        prot = out.get("protection")
        if isinstance(prot, dict):
            prot = dict(prot)
            prot["isolate_armed"] = False
            out["protection"] = prot

    return out
