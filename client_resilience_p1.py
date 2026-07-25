#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""P1 resilience observe helpers (RES-103/105/106).

All features are additive and default-off until their wire schemas are promoted:
- signed heartbeat v1 candidate (HMAC, no enforcement);
- bounded file/DACL fingerprint inventory;
- ACL drift comparison against a locally HMAC-protected baseline.

This module never mutates ACL/SACL entries and never blocks process startup.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from typing import Iterable, Optional

from client_constants import MACHINE_DATA_DIR

CREATE_NO_WINDOW = 0x08000000
ACL_BASELINE_FILE = os.path.join(MACHINE_DATA_DIR, "acl_baseline_v1.json")
_DEFAULT_PATHS = (
    MACHINE_DATA_DIR,
    os.path.abspath(sys.executable),
    # Install surface observe (M0): catch ACL drift on Program Files root + motor runtime.
    os.path.dirname(os.path.abspath(sys.executable)),
    os.path.join(os.path.dirname(os.path.abspath(sys.executable)), "_internal"),
)


def _enabled(key: str, default: bool = False) -> bool:
    try:
        from client_utils import get_from_config
        return bool(get_from_config(key, default))
    except Exception:
        return default


def heartbeat_observe_enabled() -> bool:
    return _enabled("security.signed_heartbeat_observe", False)


def acl_drift_enabled() -> bool:
    return _enabled("security.acl_drift_observe", False)


def _heartbeat_key(token: str, hostname: str, context: str = "asteria-heartbeat-v1") -> bytes:
    material = f"{token}|{hostname.lower()}|{context}"
    return hashlib.sha256(material.encode("utf-8")).digest()


def make_heartbeat_proof(
    token: str,
    *,
    hostname: str,
    status: str,
    running: bool,
    issued_at: str,
) -> dict:
    """Build the RES-103 candidate proof; caller persists ``issued_at`` verbatim."""
    message = (
        f"v1|{hostname.lower()}|{status}|{1 if running else 0}|{issued_at}"
    ).encode("utf-8")
    signature = hmac.new(
        _heartbeat_key(token, hostname), message, hashlib.sha256
    ).hexdigest()
    return {
        "version": 1,
        "issued_at": issued_at,
        "algorithm": "hmac-sha256",
        "signature": signature,
        "observe": True,
        "enforce": False,
    }


def build_heartbeat_observe(
    token: str,
    *,
    hostname: str,
    status: str,
    running: bool,
) -> Optional[dict]:
    if not heartbeat_observe_enabled() or not token:
        return None
    issued_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    return make_heartbeat_proof(
        token,
        hostname=hostname,
        status=status,
        running=running,
        issued_at=issued_at,
    )


def verify_heartbeat_proof(
    token: str,
    proof: Optional[dict],
    *,
    hostname: str,
    status: str,
    running: bool,
    max_age_sec: float = 300.0,
    now: Optional[datetime] = None,
) -> dict:
    """Local RES-103 verify helper (observe-only; never used for reject-stale)."""
    result = {
        "ok": False,
        "observe": True,
        "enforce": False,
        "reason": "missing",
    }
    if not token or not isinstance(proof, dict):
        return result
    if int(proof.get("version") or 0) != 1:
        result["reason"] = "unsupported_version"
        return result
    issued_at = str(proof.get("issued_at") or "")
    signature = str(proof.get("signature") or "")
    if not issued_at or not signature:
        result["reason"] = "incomplete"
        return result
    expected = make_heartbeat_proof(
        token,
        hostname=hostname,
        status=status,
        running=running,
        issued_at=issued_at,
    )
    message = (
        f"v1|{hostname.lower()}|{status}|{1 if running else 0}|{issued_at}"
    ).encode("utf-8")
    sig_ok = hmac.compare_digest(signature, expected["signature"])
    if not sig_ok:
        # Accept legacy verify during fleet cutover labs.
        legacy = hmac.new(
            _heartbeat_key(token, hostname, "yesnext-heartbeat-v1"),
            message,
            hashlib.sha256,
        ).hexdigest()
        sig_ok = hmac.compare_digest(signature, legacy)
    if not sig_ok:
        result["reason"] = "bad_signature"
        return result
    try:
        issued = datetime.fromisoformat(issued_at.replace("Z", "+00:00"))
        if issued.tzinfo is None:
            issued = issued.replace(tzinfo=timezone.utc)
        reference = now or datetime.now(timezone.utc)
        if reference.tzinfo is None:
            reference = reference.replace(tzinfo=timezone.utc)
        age = (reference - issued).total_seconds()
        if age < -30:
            result["reason"] = "clock_skew"
            return result
        if age > float(max_age_sec):
            result["reason"] = "stale"
            return result
    except Exception:
        result["reason"] = "bad_timestamp"
        return result
    result["ok"] = True
    result["reason"] = "ok"
    return result


def _icacls_fingerprint(path: str) -> dict:
    """Return a bounded hash of icacls output; no principal names leave host."""
    out = {
        "path_hash": hashlib.sha256(
            os.path.normcase(os.path.abspath(path)).encode("utf-8")
        ).hexdigest()[:16],
        "exists": os.path.exists(path),
        "acl_hash": "",
        "readable": False,
    }
    if not out["exists"] or os.name != "nt":
        return out
    try:
        proc = subprocess.run(
            ["icacls", path],
            capture_output=True,
            timeout=10,
            creationflags=CREATE_NO_WINDOW,
        )
        raw = (proc.stdout or b"") + (proc.stderr or b"")
        # Normalize whitespace and case before hashing; never retain raw ACL text.
        normalized = b" ".join(raw.lower().split())
        out["acl_hash"] = hashlib.sha256(normalized).hexdigest()
        out["readable"] = proc.returncode == 0
    except Exception:
        pass
    return out


def collect_acl_fingerprints(paths: Iterable[str] = _DEFAULT_PATHS) -> list[dict]:
    seen = set()
    result = []
    for path in paths:
        normalized = os.path.normcase(os.path.abspath(str(path or "")))
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        result.append(_icacls_fingerprint(normalized))
    return result[:16]


def _baseline_key(token: str) -> bytes:
    return hashlib.sha256(
        f"{token}|acl-baseline-v1".encode("utf-8")
    ).digest()


def _sign_baseline(token: str, payload: dict) -> str:
    body = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hmac.new(_baseline_key(token), body, hashlib.sha256).hexdigest()


def save_acl_baseline(
    token: str,
    fingerprints: list[dict],
    *,
    path: str = ACL_BASELINE_FILE,
) -> bool:
    if not token:
        return False
    payload = {
        "version": 1,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "entries": fingerprints[:16],
    }
    doc = {"payload": payload, "hmac": _sign_baseline(token, payload)}
    try:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as handle:
            json.dump(doc, handle, separators=(",", ":"))
        os.replace(tmp, path)
        return True
    except Exception:
        return False


def load_acl_baseline(token: str, *, path: str = ACL_BASELINE_FILE) -> Optional[dict]:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            doc = json.load(handle)
        payload = doc.get("payload")
        expected = _sign_baseline(token, payload)
        if not hmac.compare_digest(str(doc.get("hmac") or ""), expected):
            return None
        return payload
    except Exception:
        return None


def acl_drift_status(
    token: str,
    *,
    paths: Iterable[str] = _DEFAULT_PATHS,
    baseline_path: str = ACL_BASELINE_FILE,
) -> dict:
    """Observe-only ACL drift summary; never exposes raw ACL/principal names."""
    current = collect_acl_fingerprints(paths)
    result = {
        "observe": acl_drift_enabled(),
        "enforce": False,
        "baseline_valid": False,
        "entries_checked": len(current),
        "changed": 0,
        "missing": 0,
        "status": "disabled",
    }
    if not result["observe"]:
        return result
    baseline = load_acl_baseline(token, path=baseline_path)
    if baseline is None:
        created = save_acl_baseline(token, current, path=baseline_path)
        result["status"] = "baseline_created" if created else "baseline_unavailable"
        return result
    result["baseline_valid"] = True
    old = {entry.get("path_hash"): entry for entry in baseline.get("entries", [])}
    for entry in current:
        previous = old.get(entry.get("path_hash"))
        if not entry.get("exists"):
            result["missing"] += 1
        elif previous and previous.get("acl_hash") != entry.get("acl_hash"):
            result["changed"] += 1
    result["status"] = (
        "degraded" if result["changed"] or result["missing"] else "healthy"
    )
    return result
