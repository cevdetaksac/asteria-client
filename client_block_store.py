#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Persistent blocked-IP inventory under ProgramData (SYSTEM + GUI shared).

Windows Firewall remains the enforcement source of truth.
This store is a durable cache so GUI / AutoResponse can list hundreds of
blocks after restart without keeping a huge threat IP pool in RAM.
Synced with API via FirewallAgent._sync_rules_to_api (inventory).
"""

from __future__ import annotations

import ipaddress
import json
import os
import threading
import time
from typing import Any, Dict, List, Optional

_LOCK = threading.Lock()
_CACHE: Optional[Dict[str, dict]] = None  # ip -> record
_CACHE_MTIME: float = 0.0
_LAST_FW_REFRESH: float = 0.0

_STORE_NAME = "blocked_ips.json"
_MAX_RECORDS = 5000


def _store_path() -> str:
    base = os.path.join(
        os.environ.get("ProgramData", r"C:\ProgramData"),
        "Asteria",
    )
    try:
        os.makedirs(base, exist_ok=True)
    except OSError:
        pass
    return os.path.join(base, _STORE_NAME)


def _looks_like_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(str(value or "").strip())
        return True
    except ValueError:
        return False


def extract_ips_from_rule(rule: dict) -> List[str]:
    """All real IPs from a firewall rule (multi-RemoteIP chunk rules included)."""
    found: List[str] = []
    seen = set()
    remoteip = str(rule.get("remoteip") or "").strip()
    if remoteip:
        for part in remoteip.split(","):
            token = part.strip().split("/")[0].strip()
            if not token or token.lower() in ("any", "herhangi"):
                continue
            if _looks_like_ip(token) and token not in seen:
                seen.add(token)
                found.append(token)
    if not found:
        suffix = str(rule.get("suffix") or rule.get("ip") or "").strip()
        if suffix:
            cand = suffix.replace("_", ".")
            if _looks_like_ip(cand) and cand not in seen:
                found.append(cand)
    return found


def extract_ip_from_rule(rule: dict) -> Optional[str]:
    """Prefer remoteip; accept suffix only when it is a real IP (not UUID/id)."""
    ips = extract_ips_from_rule(rule)
    return ips[0] if ips else None


def load_blocked_map(*, force: bool = False) -> Dict[str, dict]:
    """Return ip -> {ip, rule_name, source, reason, blocked_at}.

    Auto-reloads when ProgramData file mtime changes (daemon writes, GUI reads).
    """
    global _CACHE, _CACHE_MTIME
    path = _store_path()
    try:
        mtime = os.path.getmtime(path) if os.path.isfile(path) else 0.0
    except OSError:
        mtime = 0.0
    with _LOCK:
        if (
            _CACHE is not None
            and not force
            and mtime
            and abs(mtime - _CACHE_MTIME) < 1e-6
        ):
            return dict(_CACHE)
        data: Dict[str, dict] = {}
        if os.path.isfile(path):
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    raw = json.loads(fh.read() or "{}")
                blocks = raw.get("blocks") if isinstance(raw, dict) else raw
                if isinstance(blocks, list):
                    for item in blocks:
                        if not isinstance(item, dict):
                            continue
                        ip = str(item.get("ip") or "").strip()
                        if not _looks_like_ip(ip):
                            continue
                        data[ip] = {
                            "ip": ip,
                            "rule_name": item.get("rule_name") or f"AR-BLOCK-{ip}",
                            "source": item.get("source") or "firewall",
                            "reason": item.get("reason") or "persisted",
                            "blocked_at": float(item.get("blocked_at") or 0),
                        }
                elif isinstance(blocks, dict):
                    for ip, item in blocks.items():
                        if not _looks_like_ip(ip):
                            continue
                        if not isinstance(item, dict):
                            item = {}
                        data[ip] = {
                            "ip": ip,
                            "rule_name": item.get("rule_name") or f"AR-BLOCK-{ip}",
                            "source": item.get("source") or "firewall",
                            "reason": item.get("reason") or "persisted",
                            "blocked_at": float(item.get("blocked_at") or 0),
                        }
            except Exception:
                data = {}
        _CACHE = data
        _CACHE_MTIME = mtime
        return dict(data)


def save_blocked_map(blocks: Dict[str, dict]) -> None:
    """Replace store contents (atomic-ish write)."""
    global _CACHE, _CACHE_MTIME
    cleaned: Dict[str, dict] = {}
    for ip, item in (blocks or {}).items():
        if not _looks_like_ip(ip):
            continue
        cleaned[ip] = {
            "ip": ip,
            "rule_name": (item or {}).get("rule_name") or f"AR-BLOCK-{ip}",
            "source": (item or {}).get("source") or "firewall",
            "reason": (item or {}).get("reason") or "persisted",
            "blocked_at": float((item or {}).get("blocked_at") or 0),
        }
    # Cap oldest by blocked_at if oversized
    if len(cleaned) > _MAX_RECORDS:
        ordered = sorted(cleaned.values(), key=lambda r: float(r.get("blocked_at") or 0))
        cleaned = {r["ip"]: r for r in ordered[-_MAX_RECORDS:]}

    path = _store_path()
    payload = {
        "updated_at": time.time(),
        "count": len(cleaned),
        "blocks": list(cleaned.values()),
    }
    tmp = path + ".tmp"
    with _LOCK:
        try:
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, ensure_ascii=False, indent=0)
            os.replace(tmp, path)
            _CACHE = cleaned
            try:
                _CACHE_MTIME = os.path.getmtime(path)
            except OSError:
                _CACHE_MTIME = time.time()
        except Exception:
            try:
                if os.path.isfile(tmp):
                    os.remove(tmp)
            except OSError:
                pass


def upsert_block(
    ip: str,
    *,
    rule_name: str = "",
    source: str = "local",
    reason: str = "",
    blocked_at: Optional[float] = None,
) -> None:
    if not _looks_like_ip(ip):
        return
    m = load_blocked_map()
    m[ip] = {
        "ip": ip,
        "rule_name": rule_name or f"AR-BLOCK-{ip}",
        "source": source or "local",
        "reason": reason or "block",
        "blocked_at": float(blocked_at if blocked_at is not None else time.time()),
    }
    save_blocked_map(m)


def remove_block(ip: str) -> None:
    if not ip:
        return
    m = load_blocked_map()
    if ip in m:
        del m[ip]
        save_blocked_map(m)


def merge_from_firewall_rules(rules: List[dict]) -> Dict[str, dict]:
    """Rebuild store from netsh scan (+ keep reason/blocked_at when same IP)."""
    prev = load_blocked_map(force=True)
    merged: Dict[str, dict] = {}
    now = time.time()
    skipped = 0
    for r in rules or []:
        ips = extract_ips_from_rule(r)
        if not ips:
            skipped += 1
            continue
        suffix = str(r.get("suffix") or "")
        source = "dashboard" if suffix.isdigit() else "firewall"
        rule_name = r.get("name") or ""
        for ip in ips:
            old = prev.get(ip) or {}
            merged[ip] = {
                "ip": ip,
                "rule_name": rule_name or f"AR-BLOCK-{ip}",
                "source": old.get("source") or source,
                "reason": old.get("reason") or "firewall_rule",
                "blocked_at": float(old.get("blocked_at") or now),
            }
    save_blocked_map(merged)
    try:
        from client_helpers import log
        log(
            f"[BLOCK-STORE] merge firewall rules={len(rules or [])} "
            f"ips={len(merged)} skipped_no_ip={skipped}"
        )
    except Exception:
        pass
    return merged


def refresh_from_live_firewall(
    *,
    min_interval_sec: float = 30.0,
    force: bool = False,
) -> Dict[str, dict]:
    """Scan live Windows Firewall AR-* plus legacy → rewrite ProgramData store.

    GUI Engellenen and API inventory must track firewall SoT even when the
    SYSTEM daemon has not yet run _migrate_and_sync_rules.
    """
    global _LAST_FW_REFRESH
    now = time.time()
    if (
        not force
        and _LAST_FW_REFRESH
        and (now - _LAST_FW_REFRESH) < float(min_interval_sec)
    ):
        return load_blocked_map(force=True)
    try:
        from client_firewall import WindowsFirewallBackend

        backend = WindowsFirewallBackend(logger=_NullLog())
        ok, rules = backend.scan_existing_rules_detailed()
        if not ok:
            try:
                from client_helpers import log
                log("[BLOCK-STORE] live firewall scan failed — keeping existing store")
            except Exception:
                pass
            return load_blocked_map(force=True)
        # Enrich numbered dashboard rules missing RemoteIP in bulk listing
        enriched = 0
        for r in rules:
            suffix = str(r.get("suffix") or "")
            if not suffix.isdigit():
                continue
            if extract_ips_from_rule(r):
                continue
            name = r.get("name") or ""
            if not name:
                continue
            if enriched >= 120:
                break
            detail = backend.lookup_rule_remoteips(name)
            if detail:
                r["remoteip"] = detail
                enriched += 1
        merged = merge_from_firewall_rules(rules)
        _LAST_FW_REFRESH = time.time()
        try:
            from client_helpers import log
            log(
                f"[BLOCK-STORE] live firewall refresh ips={len(merged)} "
                f"rules={len(rules)} enriched={enriched}"
            )
        except Exception:
            pass
        return merged
    except Exception as e:
        try:
            from client_helpers import log
            log(f"[BLOCK-STORE] live firewall refresh failed: {e}")
        except Exception:
            pass
        return load_blocked_map(force=True)


class _NullLog:
    def info(self, *a, **k):
        pass

    def warning(self, *a, **k):
        pass

    def error(self, *a, **k):
        pass


def list_blocked_ips() -> List[dict]:
    m = load_blocked_map()
    return sorted(m.values(), key=lambda r: float(r.get("blocked_at") or 0), reverse=True)
