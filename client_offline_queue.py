#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""OOB-501 local offline urgent-event queue (contract api/10, 1.4.7).

Bounded, idempotent, replay-safe local spool:
- payload is recursively redacted before persistence;
- Windows uses machine-scope DPAPI via TokenStore;
- each encrypted record is HMAC-protected and has a deterministic event id;
- FIFO load/ack helpers never perform network I/O themselves;
- local TTL 7 days; max payload 200 KB; batch drain ≤ 500.

Flag ``security.offline_urgent_queue`` remains default off until pilot.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import threading
from datetime import datetime, timezone
from typing import Optional

from client_constants import MACHINE_DATA_DIR
from client_security_utils import redact_sensitive

QUEUE_FILE = os.path.join(MACHINE_DATA_DIR, "offline_urgent_queue_v1.jsonl")
STATS_FILE = os.path.join(MACHINE_DATA_DIR, "offline_urgent_queue_stats_v1.json")
MAX_RECORDS = 500
MAX_BATCH = 500
MAX_PAYLOAD_BYTES = 200 * 1024
LOCAL_TTL_SEC = 7 * 24 * 3600
_DROP_REJECT_REASONS = frozenset({"schema", "too_large", "expired"})
_lock = threading.Lock()
_stats = {
    "oldest_dropped": 0,
    "expired_dropped": 0,
    "too_large_rejected": 0,
}
_stats_loaded = False


def offline_queue_enabled() -> bool:
    """Enable only when local flag AND fleet canary gate are both true.

    Default local flag remains **off** (api/10 + PROMOTION_GATES). Missing
    ``fleet_rollout`` fails closed via C-CANARY-3.
    """
    try:
        from client_utils import get_from_config
        local = bool(get_from_config("security.offline_urgent_queue", False))
    except Exception:
        local = False
    try:
        from client_fleet_canary import GATE_OFFLINE, and_enabled
        return and_enabled(GATE_OFFLINE, local)
    except Exception:
        return False


def _ensure_stats_loaded(*, stats_path: str = STATS_FILE) -> None:
    global _stats_loaded
    if _stats_loaded:
        return
    with _lock:
        if _stats_loaded:
            return
        try:
            if os.path.isfile(stats_path):
                with open(stats_path, "r", encoding="utf-8") as handle:
                    data = json.load(handle)
                if isinstance(data, dict):
                    for key in _stats:
                        try:
                            _stats[key] = int(data.get(key) or 0)
                        except (TypeError, ValueError):
                            pass
        except Exception:
            pass
        _stats_loaded = True


def _persist_stats_unlocked(*, stats_path: str = STATS_FILE) -> None:
    try:
        os.makedirs(os.path.dirname(stats_path) or ".", exist_ok=True)
        tmp = stats_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as handle:
            json.dump(_stats, handle, separators=(",", ":"))
        os.replace(tmp, stats_path)
    except Exception:
        pass


def _bump_stat(name: str, delta: int = 1, *, stats_path: str = STATS_FILE) -> None:
    """Increment a counter; caller must hold ``_lock`` for in-critical-section bumps."""
    _stats[name] = int(_stats.get(name) or 0) + int(delta)
    _persist_stats_unlocked(stats_path=stats_path)


def queue_stats(*, stats_path: str = STATS_FILE) -> dict:
    """Durable drop counters (additive observe; survives restart)."""
    _ensure_stats_loaded(stats_path=stats_path)
    with _lock:
        return dict(_stats)


def pending_count(token: str = "", *, path: str = QUEUE_FILE) -> int:
    """Approximate pending rows (decrypt path when token provided)."""
    if token:
        try:
            return len(load(token, path=path, limit=MAX_RECORDS, prune_expired=True))
        except Exception:
            return 0
    if not os.path.isfile(path):
        return 0
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return sum(1 for line in handle if line.strip())
    except Exception:
        return 0


def health_observe_block(token: str = "", *, path: str = QUEUE_FILE) -> dict:
    """Additive health/report block for OOB-501 acceptance visibility."""
    stats = queue_stats()
    try:
        from client_utils import get_from_config
        local_flag = bool(get_from_config("security.offline_urgent_queue", False))
    except Exception:
        local_flag = False
    try:
        from client_fleet_canary import GATE_OFFLINE, gate_allowed
        canary_gate = bool(gate_allowed(GATE_OFFLINE))
    except Exception:
        canary_gate = False
    return {
        "mode": "observe",
        "local_flag": local_flag,
        "canary_gate": canary_gate,
        "enabled": bool(local_flag and canary_gate),
        "pending": pending_count(token, path=path),
        "max_records": MAX_RECORDS,
        "max_batch": MAX_BATCH,
        "max_payload_bytes": MAX_PAYLOAD_BYTES,
        "ttl_sec": LOCAL_TTL_SEC,
        "oldest_dropped": int(stats.get("oldest_dropped") or 0),
        "expired_dropped": int(stats.get("expired_dropped") or 0),
        "too_large_rejected": int(stats.get("too_large_rejected") or 0),
    }


def _key(token: str) -> bytes:
    return hashlib.sha256(f"{token}|offline-queue-v1".encode("utf-8")).digest()


def _seal(raw: bytes) -> bytes:
    if os.name != "nt":
        raise RuntimeError("dpapi unavailable")
    from client_utils import TokenStore
    return TokenStore._crypt_protect(raw)


def _open(blob: bytes) -> bytes:
    if os.name != "nt":
        raise RuntimeError("dpapi unavailable")
    from client_utils import TokenStore
    return TokenStore._crypt_unprotect(blob)


def _record_id(event: dict) -> str:
    stable = json.dumps(
        event, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(stable).hexdigest()


def _parse_queued_at(value) -> Optional[datetime]:
    if not value:
        return None
    try:
        text = str(value).strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def _is_expired(queued_at, *, now: Optional[datetime] = None) -> bool:
    dt = _parse_queued_at(queued_at)
    if dt is None:
        return False
    ref = now or datetime.now(timezone.utc)
    return (ref - dt).total_seconds() > LOCAL_TTL_SEC


def _payload_too_large(payload: dict) -> bool:
    try:
        raw = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    except Exception:
        return True
    return len(raw) > MAX_PAYLOAD_BYTES


def enqueue(
    token: str,
    event: dict,
    *,
    path: str = QUEUE_FILE,
    max_records: int = MAX_RECORDS,
) -> Optional[str]:
    if not token or not isinstance(event, dict):
        return None
    _ensure_stats_loaded()
    safe = redact_sensitive(event)
    if _payload_too_large(safe):
        with _lock:
            _bump_stat("too_large_rejected")
        return None
    event_id = str(safe.get("event_id") or _record_id(safe))
    envelope = {
        "version": 1,
        "event_id": event_id,
        "queued_at": datetime.now(timezone.utc).isoformat(),
        "payload": safe,
    }
    raw = json.dumps(
        envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    try:
        encrypted = _seal(raw)
    except Exception:
        return None
    encoded = base64.b64encode(encrypted).decode("ascii")
    record = {
        "event_id": event_id,
        "blob": encoded,
        "hmac": hmac.new(_key(token), encrypted, hashlib.sha256).hexdigest(),
    }
    with _lock:
        try:
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
            existing = []
            if os.path.isfile(path):
                with open(path, "r", encoding="utf-8") as handle:
                    existing = [line.strip() for line in handle if line.strip()]
            # Idempotent enqueue: do not duplicate an existing event id.
            if any(f'"event_id":"{event_id}"' in line for line in existing):
                return event_id
            existing.append(json.dumps(record, separators=(",", ":")))
            cap = max(1, int(max_records))
            if len(existing) > cap:
                dropped = len(existing) - cap
                _bump_stat("oldest_dropped", dropped)
                existing = existing[-cap:]
            tmp = path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as handle:
                handle.write("\n".join(existing) + "\n")
            os.replace(tmp, path)
            return event_id
        except Exception:
            return None


def load(
    token: str,
    *,
    path: str = QUEUE_FILE,
    limit: int = 50,
    prune_expired: bool = True,
) -> list[dict]:
    if not token or not os.path.isfile(path):
        return []
    with _lock:
        try:
            with open(path, "r", encoding="utf-8") as handle:
                lines = [line.strip() for line in handle if line.strip()]
        except Exception:
            return []
    result = []
    expired_ids: list[str] = []
    now = datetime.now(timezone.utc)
    for line in lines:
        try:
            record = json.loads(line)
            encrypted = base64.b64decode(record["blob"], validate=True)
            expected = hmac.new(_key(token), encrypted, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(str(record.get("hmac") or ""), expected):
                continue
            envelope = json.loads(_open(encrypted).decode("utf-8"))
            if envelope.get("event_id") != record.get("event_id"):
                continue
            if prune_expired and _is_expired(envelope.get("queued_at"), now=now):
                eid = str(envelope.get("event_id") or "")
                if eid:
                    expired_ids.append(eid)
                continue
            result.append(envelope)
        except Exception:
            continue
    if expired_ids:
        _ensure_stats_loaded()
        with _lock:
            _bump_stat("expired_dropped", len(expired_ids))
        acknowledge(expired_ids, path=path)
    return result[: max(1, int(limit))]


def acknowledge(
    event_ids: list[str],
    *,
    path: str = QUEUE_FILE,
) -> int:
    ids = {str(item) for item in event_ids if str(item)}
    if not ids or not os.path.isfile(path):
        return 0
    with _lock:
        try:
            with open(path, "r", encoding="utf-8") as handle:
                lines = [line.strip() for line in handle if line.strip()]
            kept = []
            removed = 0
            for line in lines:
                try:
                    event_id = str(json.loads(line).get("event_id") or "")
                except Exception:
                    event_id = ""
                if event_id in ids:
                    removed += 1
                else:
                    kept.append(line)
            tmp = path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as handle:
                if kept:
                    handle.write("\n".join(kept) + "\n")
            os.replace(tmp, path)
            return removed
        except Exception:
            return 0


def _rejected_drop_ids(rejected) -> list[str]:
    """Drop schema/too_large/expired; leave transient for retry."""
    out: list[str] = []
    if not isinstance(rejected, list):
        return out
    for item in rejected:
        if not isinstance(item, dict):
            continue
        reason = str(item.get("reason") or "").strip().lower()
        event_id = str(item.get("event_id") or "").strip()
        if event_id and reason in _DROP_REJECT_REASONS:
            out.append(event_id)
    return out


def drain_to_cloud(
    api_client,
    token: str,
    *,
    path: str = QUEUE_FILE,
    limit: int = MAX_BATCH,
) -> dict:
    """POST /api/alerts/urgent/batch and ACK per contract 1.4.7.

    Delete local rows for ``acked``, ``duplicate``, and non-retry ``rejected``
    (schema / too_large / expired). Keep ``transient`` for a later drain.
    Observe/default-off only. Never raises into callers.
    """
    out = {
        "attempted": 0,
        "acked": 0,
        "duplicate": 0,
        "rejected": 0,
        "dropped_rejected": 0,
        "error": "",
    }
    if not offline_queue_enabled() or not api_client or not token:
        out["error"] = "disabled_or_unconfigured"
        return out
    cap = min(MAX_BATCH, max(1, int(limit)))
    events = load(token, path=path, limit=cap)
    if not events:
        return out
    out["attempted"] = len(events)
    try:
        body = {
            "events": [
                {
                    "event_id": item.get("event_id"),
                    "queued_at": item.get("queued_at"),
                    "payload": item.get("payload") or {},
                }
                for item in events
                if item.get("event_id")
            ]
        }
        resp = api_client.api_request(
            "POST", "alerts/urgent/batch", data=body, timeout=20
        )
        if not isinstance(resp, dict):
            out["error"] = "bad_response"
            return out
        acked = [str(x) for x in (resp.get("acked") or []) if x]
        duplicate = [str(x) for x in (resp.get("duplicate") or []) if x]
        rejected = resp.get("rejected") or []
        drop_rejected = _rejected_drop_ids(rejected)
        out["acked"] = len(acked)
        out["duplicate"] = len(duplicate)
        out["rejected"] = len(rejected) if isinstance(rejected, list) else 0
        out["dropped_rejected"] = len(drop_rejected)
        done = acked + duplicate + drop_rejected
        if done:
            acknowledge(done, path=path)
        return out
    except Exception as exc:
        out["error"] = str(exc)[:200]
        return out
