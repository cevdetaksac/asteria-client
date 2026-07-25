# -*- coding: utf-8 -*-
"""Persist / apply protection.block_rules (honeypot-contract agent/register-protection.md)."""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

from client_helpers import log

_STORE_NAME = "protection_block_rules.json"


def _store_path() -> str:
    try:
        from client_utils import _programdata_client_dir
        base = _programdata_client_dir()
    except Exception:
        base = os.path.join(
            os.environ.get("ProgramData", r"C:\ProgramData"),
            "Asteria",
        )
    return os.path.join(base, _STORE_NAME)


def save_protection(protection: Optional[dict]) -> bool:
    """Save full protection object (or {block_rules: …}) to ProgramData."""
    if not isinstance(protection, dict):
        return False
    path = _store_path()
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(protection, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        log(f"[PROTECTION] save error: {e}")
        return False


def load_protection() -> Dict[str, Any]:
    path = _store_path()
    try:
        if not os.path.isfile(path):
            return {}
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception as e:
        log(f"[PROTECTION] load error: {e}")
        return {}


def extract_block_rules(protection_or_config: Optional[dict]) -> Optional[List[dict]]:
    """Return block_rules list from protection{} or threats/config root, else None."""
    if not isinstance(protection_or_config, dict):
        return None
    # Nested: { "protection": { "block_rules": [...] } }
    prot = protection_or_config.get("protection")
    if isinstance(prot, dict) and isinstance(prot.get("block_rules"), list):
        return list(prot.get("block_rules") or [])
    # Flat protection object: { "block_rules": [...] }
    if isinstance(protection_or_config.get("block_rules"), list):
        return list(protection_or_config.get("block_rules") or [])
    return None


def normalize_block_rule(rule: dict) -> dict:
    """Map contract schema → ThreatEngine schema (and pass through legacy)."""
    if not isinstance(rule, dict):
        return {}
    out = dict(rule)

    # service → services (comma string)
    if not out.get("services") and out.get("service"):
        svc = str(out.get("service") or "").strip()
        if svc == "*":
            out["services"] = ""  # empty = match all in engine
        else:
            out["services"] = svc

    # threshold → threshold_count
    if "threshold_count" not in out and out.get("threshold") is not None:
        try:
            out["threshold_count"] = int(out["threshold"])
        except (TypeError, ValueError):
            out["threshold_count"] = 3

    # window_seconds → window_minutes
    if "window_minutes" not in out and out.get("window_seconds") is not None:
        try:
            secs = int(out["window_seconds"])
            out["window_minutes"] = max(1, (secs + 59) // 60)
        except (TypeError, ValueError):
            out["window_minutes"] = 30

    # action / alert → actions string
    if not out.get("actions"):
        parts = []
        action = str(out.get("action") or "").strip().lower()
        if action in ("block_ip", "block"):
            parts.append("block")
        if out.get("alert", True):
            parts.append("email")
        out["actions"] = ",".join(parts) if parts else "email,block"

    if "name" not in out or not out.get("name"):
        out["name"] = str(out.get("id") or "block_rule")

    out.setdefault("enabled", True)
    return out


def apply_block_rules(threat_engine, rules: Optional[List[dict]], *, source: str = "") -> int:
    """Normalize + update_block_rules. Returns number of rules passed in (0 = defaults)."""
    if threat_engine is None or not hasattr(threat_engine, "update_block_rules"):
        return 0
    if not isinstance(rules, list):
        return 0
    normalized = [normalize_block_rule(r) for r in rules if isinstance(r, dict)]
    normalized = [r for r in normalized if r]
    threat_engine.update_block_rules(normalized)
    src = f" ({source})" if source else ""
    log(f"[PROTECTION] applied {len(normalized)} block_rule(s){src}")
    return len(normalized)


def apply_protection_payload(threat_engine, payload: Optional[dict], *, source: str = "") -> int:
    """Extract block_rules from protection/config payload, persist, apply."""
    rules = extract_block_rules(payload)
    if rules is None:
        return 0
    # Persist nested shape for next boot
    if isinstance(payload, dict) and isinstance(payload.get("protection"), dict):
        save_protection(payload.get("protection"))
    elif isinstance(payload, dict) and "block_rules" in payload:
        save_protection({"block_rules": rules})
    return apply_block_rules(threat_engine, rules, source=source)


def hydrate_threat_engine_from_store(threat_engine) -> int:
    """Boot-time: load ProgramData protection into ThreatEngine."""
    prot = load_protection()
    rules = extract_block_rules(prot)
    if not rules:
        return 0
    return apply_block_rules(threat_engine, rules, source="programdata")
