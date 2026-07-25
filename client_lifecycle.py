# -*- coding: utf-8 -*-
"""
Client lifecycle logger — crash / watchdog / memory-restart events.

Writes to:
  %ProgramData%\\YesNext\\CloudHoneypotClient\\lifecycle-YYYY-MM-DD.log
  %ProgramData%\\YesNext\\CloudHoneypotClient\\lifecycle_queue.jsonl  (pending API)

Best-effort POST /api/alerts/lifecycle when token + API available.
Never blocks restart paths on network failure.
"""

from __future__ import annotations

import json
import os
import socket
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional

from client_log_retention import cleanup_daily_logs, current_local_date, daily_log_path

_MACHINE_DIR = os.path.join(
    os.environ.get("ProgramData", r"C:\ProgramData"),
    "YesNext",
    "CloudHoneypotClient",
)
LIFECYCLE_LOG = os.path.join(_MACHINE_DIR, "lifecycle.log")
LIFECYCLE_QUEUE = os.path.join(_MACHINE_DIR, "lifecycle_queue.jsonl")
_LOG_RETENTION_DAYS = 7
_MAX_QUEUE_LINES = 200
_lock = threading.Lock()
_last_cleanup_day = None
# Same event_type within the same UTC second → single emit/POST (hygiene §8)
_last_emit_key: Optional[str] = None
_last_emit_mono: float = 0.0
_GUI_QUIT_MIN_INTERVAL_SEC = 60.0
_last_gui_quit_mono: float = 0.0


def _dedupe_key(event_type: str, ts: Optional[str] = None) -> str:
    """event_type + UTC second bucket."""
    bucket = (ts or _utc_iso())[:19]  # YYYY-MM-DDTHH:MM:SS
    return f"{event_type}|{bucket}"


def _should_skip_duplicate(event_type: str, ts: str) -> bool:
    """True if identical event_type already emitted this UTC second (cross-process)."""
    global _last_emit_key, _last_emit_mono
    key = _dedupe_key(event_type, ts)
    now = time.time()
    path = os.path.join(_MACHINE_DIR, "lifecycle_emit_dedupe.json")
    with _lock:
        if key == _last_emit_key and (now - _last_emit_mono) < 1.5:
            return True
        # Cross-process: same event_type in same UTC second
        try:
            _ensure_dir()
            prev = {}
            if os.path.isfile(path):
                with open(path, "r", encoding="utf-8") as f:
                    prev = json.load(f) or {}
            if str(prev.get("key") or "") == key and (now - float(prev.get("mono") or 0)) < 2.0:
                _last_emit_key = key
                _last_emit_mono = now
                return True
            with open(path, "w", encoding="utf-8") as f:
                json.dump({"key": key, "mono": now}, f)
        except Exception:
            pass
        _last_emit_key = key
        _last_emit_mono = now
    return False


def _should_rate_limit_gui_quit() -> bool:
    global _last_gui_quit_mono
    now = time.time()
    with _lock:
        if now - _last_gui_quit_mono < _GUI_QUIT_MIN_INTERVAL_SEC:
            return True
        _last_gui_quit_mono = now
    return False


def _drop_matching_queue_event(event: dict) -> None:
    """Remove queued copies of this event after a successful immediate POST."""
    if not os.path.isfile(LIFECYCLE_QUEUE):
        return
    et = str(event.get("event_type") or "")
    ts = str(event.get("ts") or "")
    pid = event.get("pid")
    kept = []
    try:
        with open(LIFECYCLE_QUEUE, "r", encoding="utf-8") as f:
            lines = [ln.strip() for ln in f if ln.strip()]
    except OSError:
        return
    for ln in lines:
        try:
            row = json.loads(ln)
        except Exception:
            kept.append(ln)
            continue
        if (
            str(row.get("event_type") or "") == et
            and str(row.get("ts") or "") == ts
            and row.get("pid") == pid
        ):
            continue
        kept.append(ln)
    try:
        with open(LIFECYCLE_QUEUE, "w", encoding="utf-8") as f:
            for ln in kept:
                f.write(ln + "\n")
    except OSError:
        pass


def _ensure_dir() -> None:
    try:
        os.makedirs(_MACHINE_DIR, exist_ok=True)
    except OSError:
        pass


def _utc_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _hostname() -> str:
    try:
        return socket.gethostname()
    except Exception:
        return ""


def _version() -> str:
    try:
        from client_constants import VERSION
        return str(VERSION)
    except Exception:
        return ""


def _current_lifecycle_log() -> str:
    global _last_cleanup_day
    day = current_local_date()
    if day != _last_cleanup_day:
        cleanup_daily_logs(
            LIFECYCLE_LOG,
            _LOG_RETENTION_DAYS,
            today=day,
        )
        _last_cleanup_day = day
    return daily_log_path(LIFECYCLE_LOG, day)


def _append_queue(event: dict) -> None:
    try:
        with open(LIFECYCLE_QUEUE, "a", encoding="utf-8") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")
        # Trim if huge
        try:
            with open(LIFECYCLE_QUEUE, "r", encoding="utf-8") as f:
                lines = f.readlines()
            if len(lines) > _MAX_QUEUE_LINES:
                with open(LIFECYCLE_QUEUE, "w", encoding="utf-8") as f:
                    f.writelines(lines[-_MAX_QUEUE_LINES:])
        except OSError:
            pass
    except OSError:
        pass


def emit(
    event_type: str,
    reason: str = "",
    details: Optional[Dict[str, Any]] = None,
    *,
    severity: str = "info",
    queue_for_api: bool = True,
    log_func: Optional[Callable[[str], None]] = None,
) -> Optional[dict]:
    """Record a lifecycle event locally (+ queue for API flush).

    Returns None when suppressed (same event_type within the same UTC second,
    or gui_quit rate-limit).
    """
    et = str(event_type or "unknown")
    if et == "gui_quit" and _should_rate_limit_gui_quit():
        if log_func:
            try:
                log_func("[LIFECYCLE] gui_quit rate-limited")
            except Exception:
                pass
        return None

    _ensure_dir()
    ts = _utc_iso()
    if _should_skip_duplicate(et, ts):
        if log_func:
            try:
                log_func(f"[LIFECYCLE] dedupe skip {et} @{ts}")
            except Exception:
                pass
        return None

    event = {
        "ts": ts,
        "event_type": et,
        "reason": str(reason or ""),
        "severity": str(severity or "info"),
        "hostname": _hostname(),
        "version": _version(),
        "pid": os.getpid(),
        "details": details or {},
    }
    line = (
        f"{event['ts']} [{event['severity'].upper()}] "
        f"{event['event_type']}: {event['reason']}"
    )
    if details:
        try:
            line += " | " + json.dumps(details, ensure_ascii=False)
        except Exception:
            pass

    with _lock:
        try:
            with open(_current_lifecycle_log(), "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except OSError:
            pass
        if queue_for_api:
            _append_queue(event)

    if log_func:
        try:
            log_func(f"[LIFECYCLE] {event['event_type']}: {event['reason']}")
        except Exception:
            pass
    return event


def load_token() -> str:
    """Load machine token (DPAPI) for headless watchdog / flush."""
    try:
        from client_constants import TOKEN_FILE
        from client_utils import TokenStore
        return (TokenStore.load(TOKEN_FILE) or "").strip()
    except Exception:
        return ""


def flush_queue_to_api(
    api_client=None,
    token: Optional[str] = None,
    log_func: Optional[Callable[[str], None]] = None,
) -> int:
    """Send queued lifecycle events to API. Returns number sent."""
    token = (token or load_token() or "").strip()
    if not token:
        return 0

    if api_client is None:
        try:
            from client_constants import API_URL
            from client_api import AsteriaAPIClient
            api_client = AsteriaAPIClient(API_URL, log_func=log_func or (lambda m: None))
        except Exception:
            return 0

    if not os.path.isfile(LIFECYCLE_QUEUE):
        return 0

    with _lock:
        try:
            with open(LIFECYCLE_QUEUE, "r", encoding="utf-8") as f:
                lines = [ln.strip() for ln in f if ln.strip()]
        except OSError:
            return 0
        if not lines:
            return 0

    sent = 0
    remaining = []
    for ln in lines:
        try:
            event = json.loads(ln)
        except Exception:
            continue
        try:
            ok = False
            if hasattr(api_client, "report_lifecycle_event"):
                ok = bool(api_client.report_lifecycle_event(token, event))
            if ok:
                sent += 1
            else:
                remaining.append(ln)
        except Exception:
            remaining.append(ln)

    with _lock:
        try:
            with open(LIFECYCLE_QUEUE, "w", encoding="utf-8") as f:
                for ln in remaining:
                    f.write(ln + "\n")
        except OSError:
            pass

    if log_func and sent:
        try:
            log_func(f"[LIFECYCLE] Flushed {sent} event(s) to API "
                     f"({len(remaining)} pending)")
        except Exception:
            pass
    return sent


def report_now(
    event_type: str,
    reason: str = "",
    details: Optional[Dict[str, Any]] = None,
    *,
    severity: str = "info",
    api_client=None,
    token: Optional[str] = None,
    log_func: Optional[Callable[[str], None]] = None,
) -> bool:
    """Emit locally and try immediate API post (still queues on failure).

    On successful POST, drop the queued copy — do NOT flush-repost (hygiene §8).
    """
    event = emit(
        event_type, reason, details,
        severity=severity, queue_for_api=True, log_func=log_func,
    )
    if event is None:
        return False
    token = (token or load_token() or "").strip()
    if not token:
        return False
    try:
        if api_client is None:
            from client_constants import API_URL
            from client_api import AsteriaAPIClient
            api_client = AsteriaAPIClient(API_URL, log_func=log_func or (lambda m: None))
        if hasattr(api_client, "report_lifecycle_event"):
            if api_client.report_lifecycle_event(token, event):
                with _lock:
                    _drop_matching_queue_event(event)
                return True
    except Exception as e:
        if log_func:
            try:
                log_func(f"[LIFECYCLE] API report failed: {e}")
            except Exception:
                pass
    return False
