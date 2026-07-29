#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Firewall Management + Windows MMC parity (contract ≥1.4.41).

Commands:
  list_firewall         — profiles + inbound/outbound (+ Asteria convenience)
  firewall_set_profile  — Domain/Private/Public/(all) state + default actions
  firewall_rule         — enable / disable / delete / add

1.4.40 Asteria-only responses remain valid when ``scope=asteria``.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from client_firewall import run_cmd

# Asteria + legacy block families (longest first).
# HONEYPOT matches HONEYPOT_* rule names (same family as client_firewall scan),
# not product names like "honeypot-client".
_ASTERIA_PREFIXES_EXACT: Tuple[str, ...] = (
    "AR-INTEL",
    "AR-BLOCK",
    "AR-MANUAL",
    "HP-INTEL",
    "HP-BLOCK",
)
_HONEYPOT_PREFIXES: Tuple[str, ...] = (
    "HONEYPOT_BLOCK_REMOTE_",
    "HONEYPOT_REMOTE_BLOCK_",
    "HONEYPOT_THREAT_BLOCK_",
    "HONEYPOT_BLOCK_",
    "HONEYPOT_",
)

_VALID_PROFILES = frozenset({"domain", "private", "public", "all"})
_VALID_STATE = frozenset({"on", "off"})
_VALID_ACTION = frozenset({"block", "allow"})
_VALID_RULE_OPS = frozenset({"enable", "disable", "delete", "add"})

_NETSH_PROFILE = {
    "domain": "domainprofile",
    "private": "privateprofile",
    "public": "publicprofile",
}

ENGINE = "netsh"


def match_asteria_prefix(name: str) -> Optional[str]:
    """Return contract prefix if *name* is an Asteria/legacy firewall rule."""
    n = (name or "").strip()
    if not n:
        return None
    upper = n.upper()
    for prefix in _ASTERIA_PREFIXES_EXACT:
        if upper.startswith(prefix):
            return prefix
    for prefix in _HONEYPOT_PREFIXES:
        if upper.startswith(prefix):
            return "HONEYPOT"
    return None


def firewall_rule_requires_confirm(params: Optional[dict] = None) -> bool:
    """True for delete/add (C-FW-RULE-2); False for enable/disable."""
    op = str((params or {}).get("op") or "").strip().lower()
    return op in ("delete", "add")


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def _norm_on_off(raw: str) -> str:
    low = (raw or "").strip().lower()
    if low in ("on", "yes", "true", "1", "açık", "acik", "enabled"):
        return "on"
    if low in ("off", "no", "false", "0", "kapalı", "kapali", "disabled"):
        return "off"
    if "on" in low and "off" not in low:
        return "on"
    if "off" in low:
        return "off"
    return "unknown"


def _norm_block_allow(raw: str) -> str:
    low = (raw or "").strip().lower()
    if "block" in low or "engel" in low:
        return "block"
    if "allow" in low or "izin" in low or "permit" in low:
        return "allow"
    return "unknown"


def _norm_yes_no(raw: str) -> bool:
    low = (raw or "").strip().lower()
    return low in ("yes", "true", "1", "on", "evet", "açık", "acik", "enabled")


def _norm_direction(raw: str, default: str = "In") -> str:
    low = (raw or "").strip().lower()
    if "out" in low or "giden" in low:
        return "Out"
    if "in" in low or "gelen" in low:
        return "In"
    return default


def _classify_netsh_error(err: str, out: str = "") -> Optional[str]:
    blob = f"{err or ''}\n{out or ''}".lower()
    if not blob.strip():
        return None
    if "access is denied" in blob or "erişim engellendi" in blob or "erisim engellendi" in blob:
        return "ACCESS_DENIED"
    if "group policy" in blob or "gpo" in blob or "grup ilkesi" in blob:
        return "GPO_LOCKED"
    return None


def parse_profiles_netsh(text: str) -> Dict[str, dict]:
    """Parse ``netsh advfirewall show allprofiles`` into contract profiles."""
    profiles: Dict[str, dict] = {
        "domain": {"state": "unknown", "inbound": "unknown", "outbound": "unknown"},
        "private": {"state": "unknown", "inbound": "unknown", "outbound": "unknown"},
        "public": {"state": "unknown", "inbound": "unknown", "outbound": "unknown"},
    }
    cur: Optional[str] = None
    for line in (text or "").splitlines():
        raw = line.rstrip()
        low = raw.lower().strip()
        if "domain profile" in low or "etki alanı profili" in low or "etki alani profili" in low:
            cur = "domain"
            continue
        if "private profile" in low or "özel profil" in low or "ozel profil" in low:
            cur = "private"
            continue
        if "public profile" in low or "genel profil" in low:
            cur = "public"
            continue
        if not cur or not low:
            continue

        if ":" in raw:
            key, _, val = raw.partition(":")
            key_l = key.strip().lower()
            val = val.strip()
        else:
            parts = raw.split(None, 1)
            if len(parts) < 2:
                continue
            key_l = parts[0].strip().lower()
            val = parts[1].strip()
            if key_l == "firewall" and val.lower().startswith("policy"):
                key_l = "firewall policy"
                val = val.split(None, 1)[1] if len(val.split(None, 1)) > 1 else ""
            elif key_l in ("güvenlik", "guvenlik") and "duvar" in val.lower():
                key_l = "firewall policy"
                bits = val.split(None, 2)
                val = bits[-1] if bits else ""

        if key_l in ("state", "durum"):
            profiles[cur]["state"] = _norm_on_off(val)
        elif "firewall policy" in key_l or "güvenlik duvarı ilkesi" in key_l or "guvenlik duvari ilkesi" in key_l:
            parts = [p.strip() for p in re.split(r"[,;]", val) if p.strip()]
            inbound = outbound = "unknown"
            for part in parts:
                pl = part.lower()
                if "inbound" in pl or "gelen" in pl:
                    inbound = _norm_block_allow(part)
                elif "outbound" in pl or "giden" in pl:
                    outbound = _norm_block_allow(part)
            if len(parts) >= 2 and inbound == "unknown":
                inbound = _norm_block_allow(parts[0])
            if len(parts) >= 2 and outbound == "unknown":
                outbound = _norm_block_allow(parts[1])
            profiles[cur]["inbound"] = inbound
            profiles[cur]["outbound"] = outbound
    return profiles


def parse_rules_netsh(text: str, default_direction: str = "In") -> List[dict]:
    """Parse ``netsh … show rule name=all dir=…`` into canonical Rule objects."""
    rules: List[dict] = []
    current: Dict[str, Any] = {}

    def _flush() -> None:
        nonlocal current
        name = (current.get("name") or "").strip()
        if name:
            prefix = match_asteria_prefix(name)
            current.setdefault("direction", default_direction)
            current.setdefault("enabled", True)
            current.setdefault("action", "Allow")
            current.setdefault("profile", "Any")
            current.setdefault("program", "Any")
            current.setdefault("local_address", "Any")
            current.setdefault("remote_address", "Any")
            current.setdefault("protocol", "Any")
            current.setdefault("local_port", "Any")
            current.setdefault("remote_port", "Any")
            current.setdefault("edge_traversal", "No")
            current.setdefault("group", current.get("grouping") or "")
            current.setdefault("grouping", current.get("group") or "")
            current.setdefault("description", "")
            current["asteria_prefix"] = prefix
            # 1.4.40 convenience field
            if prefix:
                current["prefix"] = prefix
            rules.append(current)
        current = {}

    for line in (text or "").splitlines():
        stripped = line.strip()
        if not stripped or set(stripped) <= {"-"}:
            if stripped and set(stripped) <= {"-"}:
                continue
            _flush()
            continue
        if ":" not in stripped:
            continue
        key, _, val = stripped.partition(":")
        key_raw = key.strip().lower()
        key_ns = key_raw.replace(" ", "")
        val = val.strip()
        if "rule name" in key_raw or "kural ad" in key_raw:
            _flush()
            current["name"] = val
        elif key_ns in ("enabled", "etkin", "aktif"):
            current["enabled"] = _norm_yes_no(val)
        elif key_ns in ("direction", "yon", "yön"):
            current["direction"] = _norm_direction(val, default_direction)
        elif key_ns in ("profiles", "profiler", "profiller"):
            current["profile"] = val
        elif key_ns in ("grouping", "gruplama", "group"):
            current["group"] = val
            current["grouping"] = val
        elif key_ns in ("localip", "yerelip", "localipv4", "yerelipv4") or "localip" in key_ns:
            current["local_address"] = val
        elif (
            key_ns in ("remoteip", "uzakip", "remoteipv4", "uzakipv4")
            or "remoteip" in key_ns
            or "uzakip" in key_ns
        ):
            current["remote_address"] = val
        elif key_ns in ("protocol", "protokol"):
            current["protocol"] = val or "Any"
        elif key_ns in ("localport", "yerelport"):
            current["local_port"] = val or "Any"
        elif key_ns in ("remoteport", "uzakport"):
            current["remote_port"] = val or "Any"
        elif "edge" in key_ns or "kenar" in key_ns:
            current["edge_traversal"] = val
        elif key_ns in ("action", "eylem", "islem", "işlem"):
            current["action"] = "Block" if _norm_block_allow(val) == "block" else (
                "Allow" if _norm_block_allow(val) == "allow" else val
            )
        elif key_ns in ("program", "programyolu", "application"):
            current["program"] = val or "Any"
        elif key_ns in ("description", "açıklama", "aciklama"):
            current["description"] = val
    _flush()
    return rules


# Back-compat alias used by tests
parse_inbound_rules_netsh = lambda text: parse_rules_netsh(text, "In")  # noqa: E731


def filter_asteria_rules(rules: List[dict], max_rules: int = 500) -> Tuple[List[dict], dict]:
    """Keep Asteria-prefixed rules; return (capped list, full counts)."""
    matched: List[dict] = []
    counts = {
        "asteria_rules": 0,
        "ar_block": 0,
        "ar_intel": 0,
        "hp_legacy": 0,
    }
    for r in rules:
        name = r.get("name") or ""
        prefix = r.get("asteria_prefix") or match_asteria_prefix(name)
        if not prefix:
            continue
        counts["asteria_rules"] += 1
        if prefix in ("AR-BLOCK", "AR-MANUAL"):
            counts["ar_block"] += 1
        elif prefix == "AR-INTEL":
            counts["ar_intel"] += 1
        else:
            counts["hp_legacy"] += 1
        entry = dict(r)
        entry["prefix"] = prefix
        entry["asteria_prefix"] = prefix
        matched.append(entry)

    capped = matched[: max(0, int(max_rules))]
    return capped, counts


def count_inbound_block_and_total(rules: List[dict]) -> Tuple[int, int]:
    """From a full inbound rule dump: (inbound_block, total_inbound)."""
    total = len(rules)
    inbound_block = 0
    for r in rules:
        action = (r.get("action") or "").lower()
        if "block" in action or "engel" in action:
            inbound_block += 1
    return inbound_block, total


def collect_firewall_profiles() -> Dict[str, dict]:
    rc, out, _err = run_cmd(
        ["netsh", "advfirewall", "show", "allprofiles"], timeout=60
    )
    if rc != 0 or not (out or "").strip():
        rc2, out2, _ = run_cmd(
            ["netsh", "advfirewall", "show", "allprofiles", "state"], timeout=30
        )
        if rc2 == 0:
            return parse_profiles_netsh(out2)
        return {
            "domain": {"state": "unknown", "inbound": "unknown", "outbound": "unknown"},
            "private": {"state": "unknown", "inbound": "unknown", "outbound": "unknown"},
            "public": {"state": "unknown", "inbound": "unknown", "outbound": "unknown"},
        }
    return parse_profiles_netsh(out)


def _enumerate_rules(direction: str) -> Tuple[bool, List[dict]]:
    """Enumerate enabled+disabled rules for In or Out."""
    dflag = "in" if direction == "In" else "out"
    attempts = (
        ["netsh", "advfirewall", "firewall", "show", "rule", "name=all", f"dir={dflag}"],
        [
            "netsh", "advfirewall", "firewall", "show", "rule",
            "name=all", f"dir={dflag}", "status=enabled",
        ],
    )
    for cmd in attempts:
        rc, out, _err = run_cmd(cmd, timeout=180)
        if rc == 0 and (out or "").strip():
            return True, parse_rules_netsh(out, default_direction=direction)
    return False, []


def _enumerate_inbound_rules() -> Tuple[bool, List[dict]]:
    return _enumerate_rules("In")


def _slice_rules(
    rules: List[dict], offset: int, limit: int
) -> Tuple[List[dict], bool]:
    offset = max(0, int(offset))
    limit = max(0, int(limit))
    total = len(rules)
    sliced = rules[offset: offset + limit] if limit else []
    truncated = (offset + len(sliced)) < total
    return sliced, truncated


def list_firewall(params: Optional[dict] = None) -> dict:
    """Build list_firewall ``data`` (1.4.40 Asteria + 1.4.41 scope=all)."""
    params = params or {}
    include_profiles = bool(params.get("include_profiles", True))
    include_asteria = bool(params.get("include_asteria_rules", True))
    include_counts = bool(params.get("include_counts", True))
    # 1.4.40 compat flag
    include_non_asteria = bool(params.get("include_non_asteria_summary", True))

    scope = str(params.get("scope") or "all").strip().lower()
    if scope not in ("all", "asteria"):
        scope = "all"

    include_inbound = params.get("include_inbound")
    include_outbound = params.get("include_outbound")
    if include_inbound is None:
        include_inbound = scope == "all"
    if include_outbound is None:
        include_outbound = scope == "all"
    include_inbound = bool(include_inbound)
    include_outbound = bool(include_outbound)

    try:
        max_per = int(
            params.get("max_rules_per_direction")
            if params.get("max_rules_per_direction") is not None
            else (params.get("max_rules") if params.get("max_rules") is not None else 2000)
        )
    except (TypeError, ValueError):
        max_per = 2000
    max_per = max(0, min(max_per, 10000))

    try:
        offset_in = int(params.get("offset_in") or 0)
    except (TypeError, ValueError):
        offset_in = 0
    try:
        offset_out = int(params.get("offset_out") or 0)
    except (TypeError, ValueError):
        offset_out = 0

    # Asteria convenience list cap (1.4.40)
    try:
        max_asteria = int(params.get("max_rules") if params.get("max_rules") is not None else 500)
    except (TypeError, ValueError):
        max_asteria = 500
    max_asteria = max(0, min(max_asteria, 5000))

    data: Dict[str, Any] = {
        "captured_at": _utc_now_iso(),
        "engine": ENGINE,
        "scope": scope,
    }

    if include_profiles:
        data["profiles"] = collect_firewall_profiles()

    ok_in, all_inbound = (True, [])
    ok_out, all_outbound = (True, [])
    if include_inbound or include_asteria or include_counts:
        ok_in, all_inbound = _enumerate_rules("In")
    if include_outbound or (include_asteria and scope == "all") or include_counts:
        # Asteria rules can also be outbound (AR-INTEL out); pull when needed
        need_out = include_outbound or scope == "all" or include_asteria
        if need_out:
            ok_out, all_outbound = _enumerate_rules("Out")

    combined_for_asteria = list(all_inbound) + list(all_outbound)
    asteria_capped: List[dict] = []
    prefix_counts = {
        "asteria_rules": 0,
        "ar_block": 0,
        "ar_intel": 0,
        "hp_legacy": 0,
    }
    if ok_in or ok_out:
        source = combined_for_asteria if (ok_in or ok_out) else []
        if not ok_in:
            source = list(all_outbound)
        elif not ok_out:
            source = list(all_inbound)
        asteria_capped, prefix_counts = filter_asteria_rules(source, max_rules=max_asteria)

    def _maybe_filter_asteria_only(rules: List[dict]) -> List[dict]:
        if scope != "asteria":
            return rules
        return [r for r in rules if r.get("asteria_prefix") or match_asteria_prefix(r.get("name") or "")]

    if include_inbound:
        src = _maybe_filter_asteria_only(all_inbound if ok_in else [])
        sliced, trunc = _slice_rules(src, offset_in, max_per)
        data["inbound_rules"] = sliced
        data["truncated_inbound"] = trunc
    if include_outbound:
        src = _maybe_filter_asteria_only(all_outbound if ok_out else [])
        sliced, trunc = _slice_rules(src, offset_out, max_per)
        data["outbound_rules"] = sliced
        data["truncated_outbound"] = trunc

    if include_asteria:
        data["asteria_rules"] = asteria_capped

    if include_counts:
        in_total = len(all_inbound) if ok_in else 0
        out_total = len(all_outbound) if ok_out else 0
        in_en = sum(1 for r in all_inbound if r.get("enabled")) if ok_in else 0
        out_en = sum(1 for r in all_outbound if r.get("enabled")) if ok_out else 0
        inbound_block, _ = count_inbound_block_and_total(all_inbound) if ok_in else (0, 0)
        data["counts"] = {
            **prefix_counts,
            "inbound_total": in_total,
            "outbound_total": out_total,
            "inbound_enabled": in_en,
            "outbound_enabled": out_en,
            # 1.4.40 compat keys
            "inbound_block": inbound_block if include_non_asteria else 0,
            "total_rules": (in_total + out_total) if include_non_asteria else prefix_counts["asteria_rules"],
        }
        if not ok_in or not ok_out:
            data["counts"]["enumeration_ok"] = False

    if not ok_in or (include_outbound and not ok_out):
        data["enumeration_ok"] = False

    return data


def _set_one_profile(
    prof: str,
    state: Optional[str],
    inbound: Optional[str],
    outbound: Optional[str],
) -> dict:
    netsh_prof = _NETSH_PROFILE[prof]
    changes: List[str] = []

    if state is not None and str(state).strip() != "":
        st = str(state).strip().lower()
        if st not in _VALID_STATE:
            return {
                "ok": False,
                "error": "invalid_state",
                "message": f"state must be on|off, got '{state}'",
            }
        rc, out, err = run_cmd(
            ["netsh", "advfirewall", "set", netsh_prof, "state", st],
            timeout=30,
        )
        classified = _classify_netsh_error(err, out)
        if rc != 0:
            return {
                "ok": False,
                "error": classified or "set_state_failed",
                "message": (err or out or "").strip() or f"netsh state {st} failed",
            }
        changes.append(f"state={st}")

    if inbound is not None or outbound is not None:
        cur = collect_firewall_profiles().get(prof) or {}
        inb = (inbound if inbound is not None else cur.get("inbound") or "block")
        outb = (outbound if outbound is not None else cur.get("outbound") or "allow")
        inb = str(inb).strip().lower()
        outb = str(outb).strip().lower()
        if inb not in _VALID_ACTION or outb not in _VALID_ACTION:
            return {
                "ok": False,
                "error": "invalid_policy",
                "message": "inbound/outbound must be block|allow",
            }
        policy = f"{inb}inbound,{outb}outbound"
        rc, out, err = run_cmd(
            ["netsh", "advfirewall", "set", netsh_prof, "firewallpolicy", policy],
            timeout=30,
        )
        classified = _classify_netsh_error(err, out)
        if rc != 0:
            return {
                "ok": False,
                "error": classified or "set_policy_failed",
                "message": (err or out or "").strip() or "netsh firewallpolicy failed",
            }
        changes.append(f"policy={policy}")

    if not changes:
        return {
            "ok": False,
            "error": "no_changes",
            "message": "Provide at least one of state, inbound, outbound",
        }
    return {"ok": True, "profile": prof, "changes": changes}


def set_firewall_profile(
    profile: str,
    state: Optional[str] = None,
    inbound: Optional[str] = None,
    outbound: Optional[str] = None,
) -> dict:
    """Mutate Domain/Private/Public or all (C-FW-PROF-2..4)."""
    prof = (profile or "").strip().lower()
    if prof not in _VALID_PROFILES:
        return {
            "ok": False,
            "error": "unknown_profile",
            "message": f"Unknown profile '{profile}' (expected domain|private|public|all)",
        }

    targets = ["domain", "private", "public"] if prof == "all" else [prof]
    all_changes: List[str] = []
    for t in targets:
        result = _set_one_profile(t, state, inbound, outbound)
        if not result.get("ok"):
            return result
        for c in result.get("changes") or []:
            all_changes.append(f"{t}:{c}")

    return {
        "ok": True,
        "profile": prof,
        "changes": all_changes,
        "profiles": collect_firewall_profiles(),
    }


def _dir_netsh(direction: Optional[str]) -> Optional[str]:
    if not direction:
        return None
    d = _norm_direction(str(direction), "")
    if d == "In":
        return "in"
    if d == "Out":
        return "out"
    return None


def firewall_rule(params: Optional[dict] = None) -> dict:
    """Mutate a single rule (C-FW-RULE-1..5)."""
    params = params or {}
    op = str(params.get("op") or "").strip().lower()
    if op not in _VALID_RULE_OPS:
        return {
            "ok": False,
            "error": "invalid_op",
            "message": f"op must be enable|disable|delete|add, got '{params.get('op')}'",
        }

    if op == "add":
        return _firewall_rule_add(params)

    name = str(params.get("name") or "").strip()
    if not name:
        return {"ok": False, "error": "missing_name", "message": "name is required"}

    direction = params.get("direction")
    dflag = _dir_netsh(direction)

    if op in ("enable", "disable"):
        enable = "yes" if op == "enable" else "no"
        cmd = [
            "netsh", "advfirewall", "firewall", "set", "rule",
            f"name={name}", "new", f"enable={enable}",
        ]
        if dflag:
            cmd.insert(6, f"dir={dflag}")
        rc, out, err = run_cmd(cmd, timeout=60)
        classified = _classify_netsh_error(err, out)
        if rc != 0:
            # Retry without dir if ambiguous / not found with dir
            if dflag:
                cmd2 = [
                    "netsh", "advfirewall", "firewall", "set", "rule",
                    f"name={name}", "new", f"enable={enable}",
                ]
                rc, out, err = run_cmd(cmd2, timeout=60)
                classified = _classify_netsh_error(err, out)
            if rc != 0:
                return {
                    "ok": False,
                    "error": classified or "set_rule_failed",
                    "message": (err or out or "").strip() or f"failed to {op} rule",
                    "name": name,
                    "op": op,
                }
        return {
            "ok": True,
            "name": name,
            "op": op,
            "enabled": op == "enable",
        }

    # delete
    cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"]
    if dflag:
        cmd.append(f"dir={dflag}")
    rc, out, err = run_cmd(cmd, timeout=60)
    classified = _classify_netsh_error(err, out)
    if rc != 0:
        return {
            "ok": False,
            "error": classified or "delete_rule_failed",
            "message": (err or out or "").strip() or "failed to delete rule",
            "name": name,
            "op": op,
        }
    return {"ok": True, "name": name, "op": "delete"}


def _firewall_rule_add(params: dict) -> dict:
    name = str(params.get("name") or "").strip()
    if not name:
        # C-FW-RULE-5 — prefer Asteria-prefixed for dashboard IP blocks
        remote = str(params.get("remote_address") or "").strip()
        if remote and remote.lower() not in ("any", "herhangi"):
            safe = re.sub(r"[^A-Za-z0-9._-]+", "-", remote).strip("-")[:80]
            name = f"AR-MANUAL-{safe or 'rule'}"
        else:
            return {
                "ok": False,
                "error": "missing_name",
                "message": "name is required for add (or provide remote_address)",
            }

    direction = _norm_direction(str(params.get("direction") or "In"), "In")
    action_raw = str(params.get("action") or "Block").strip().lower()
    action = "block" if _norm_block_allow(action_raw) == "block" else "allow"
    enabled = params.get("enabled", True)
    enable = "yes" if bool(enabled) else "no"

    profile = str(params.get("profile") or "any").strip() or "any"
    protocol = str(params.get("protocol") or "Any").strip() or "Any"
    local_port = str(params.get("local_port") or "Any").strip() or "Any"
    remote_port = str(params.get("remote_port") or "Any").strip() or "Any"
    local_address = str(params.get("local_address") or "Any").strip() or "Any"
    remote_address = str(params.get("remote_address") or "Any").strip() or "Any"
    program = str(params.get("program") or "Any").strip() or "Any"
    description = str(params.get("description") or "").strip()

    cmd = [
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={name}",
        f"dir={'in' if direction == 'In' else 'out'}",
        f"action={action}",
        f"enable={enable}",
        f"profile={profile}",
    ]
    if protocol and protocol.lower() != "any":
        cmd.append(f"protocol={protocol}")
    if local_port and local_port.lower() != "any":
        cmd.append(f"localport={local_port}")
    if remote_port and remote_port.lower() != "any":
        cmd.append(f"remoteport={remote_port}")
    if local_address and local_address.lower() not in ("any", "herhangi"):
        cmd.append(f"localip={local_address}")
    if remote_address and remote_address.lower() not in ("any", "herhangi"):
        cmd.append(f"remoteip={remote_address}")
    if program and program.lower() != "any":
        cmd.append(f"program={program}")
    if description:
        cmd.append(f"description={description[:200]}")

    rc, out, err = run_cmd(cmd, timeout=60)
    classified = _classify_netsh_error(err, out)
    if rc != 0:
        return {
            "ok": False,
            "error": classified or "add_rule_failed",
            "message": (err or out or "").strip() or "failed to add rule",
            "name": name,
            "op": "add",
        }
    return {
        "ok": True,
        "name": name,
        "op": "add",
        "enabled": bool(enabled),
        "direction": direction,
        "action": action.capitalize(),
        "asteria_prefix": match_asteria_prefix(name),
    }
