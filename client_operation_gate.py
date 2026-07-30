#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Single-flight operation gate — no stacked critical work.

One UPDATE-family operation at a time across GUI / dashboard / silent paths.
Busy callers receive the in-flight snapshot instead of starting a duplicate.

Gate file: %ProgramData%\\Asteria\\operation_gate.json
Also keeps update_in_progress.lock in sync for back-compat observers.
"""

from __future__ import annotations

import json
import os
import threading
import time
import uuid
from typing import Any, Dict, Optional, Tuple

_GATE_LOCK = threading.RLock()

# Families that are mutually exclusive within themselves.
FAMILY_UPDATE = "update"

_OP_FAMILY = {
    "self_update": FAMILY_UPDATE,
    "silent_update": FAMILY_UPDATE,
    "interactive_update": FAMILY_UPDATE,
    "dashboard_self_update": FAMILY_UPDATE,
    "gui_self_update": FAMILY_UPDATE,
}

# Soft reclaim when holder died or phase exceeded budget (seconds).
_PHASE_TIMEOUT_SEC = {
    "queued": 600,
    "accepted": 600,
    "connecting": 300,
    "downloading": 1800,
    "staging": 600,
    "installing": 900,
    "verifying": 600,
}
_DEFAULT_TIMEOUT_SEC = 900


def _gate_path() -> str:
    base = os.path.join(
        os.environ.get("ProgramData", r"C:\ProgramData"),
        "Asteria",
    )
    try:
        os.makedirs(base, exist_ok=True)
    except OSError:
        pass
    return os.path.join(base, "operation_gate.json")


def _pid_alive(pid: int) -> bool:
    if not pid or pid <= 0:
        return False
    try:
        import ctypes

        SYNCHRONIZE = 0x00100000
        h = ctypes.windll.kernel32.OpenProcess(SYNCHRONIZE, False, int(pid))
        if h:
            ctypes.windll.kernel32.CloseHandle(h)
            return True
    except Exception:
        pass
    try:
        os.kill(int(pid), 0)
        return True
    except OSError:
        return False
    except Exception:
        return False


def _read_raw() -> Optional[Dict[str, Any]]:
    path = _gate_path()
    try:
        if not os.path.isfile(path):
            return None
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _write_raw(payload: Dict[str, Any]) -> bool:
    path = _gate_path()
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
        os.replace(tmp, path)
        return True
    except Exception:
        try:
            if os.path.isfile(tmp):
                os.remove(tmp)
        except OSError:
            pass
        return False


def _clear_file() -> None:
    path = _gate_path()
    try:
        if os.path.isfile(path):
            os.remove(path)
    except OSError:
        pass


def _family_for(op: str) -> str:
    return _OP_FAMILY.get(str(op or "").strip().lower(), str(op or "op"))


def _is_stale(snap: Dict[str, Any]) -> bool:
    try:
        pid = int(snap.get("pid") or 0)
    except (TypeError, ValueError):
        pid = 0
    if pid and not _pid_alive(pid):
        return True
    phase = str(snap.get("phase") or "queued").strip().lower()
    try:
        started = float(snap.get("started_at") or snap.get("updated_at") or 0)
    except (TypeError, ValueError):
        started = 0.0
    if started <= 0:
        return True
    budget = float(_PHASE_TIMEOUT_SEC.get(phase, _DEFAULT_TIMEOUT_SEC))
    return (time.time() - started) > budget


def snapshot() -> Optional[Dict[str, Any]]:
    """Return current gate snapshot (or None if idle)."""
    with _GATE_LOCK:
        snap = _read_raw()
        if not snap:
            return None
        if _is_stale(snap):
            _clear_file()
            return None
        return dict(snap)


def is_busy(family: str = FAMILY_UPDATE) -> bool:
    snap = snapshot()
    if not snap:
        return False
    return str(snap.get("family") or "") == str(family)


def touch(
    *,
    phase: str = "",
    progress_pct: Optional[int] = None,
    detail: str = "",
    from_version: str = "",
    to_version: str = "",
    token: str = "",
) -> bool:
    """Heartbeat / progress refresh for the holder."""
    with _GATE_LOCK:
        snap = _read_raw()
        if not snap:
            return False
        if token and str(snap.get("token") or "") != str(token):
            # Allow same-pid refresh without token (progress bus)
            try:
                if int(snap.get("pid") or 0) != os.getpid():
                    return False
            except (TypeError, ValueError):
                return False
        now = time.time()
        if phase:
            prev = str(snap.get("phase") or "")
            snap["phase"] = str(phase).strip().lower()
            if snap["phase"] != prev:
                snap["phase_started_at"] = now
        if progress_pct is not None:
            try:
                snap["progress_pct"] = max(0, min(100, int(progress_pct)))
            except (TypeError, ValueError):
                pass
        if detail:
            snap["detail"] = str(detail)[:200]
        if from_version:
            snap["from_version"] = str(from_version)
        if to_version:
            snap["to_version"] = str(to_version)
        snap["updated_at"] = now
        return _write_raw(snap)


def _synthetic_busy_from_legacy() -> Dict[str, Any]:
    """Build busy snapshot when only update_in_progress.lock / UI status exists."""
    phase = "queued"
    pct = 0
    from_v = ""
    to_v = ""
    detail = "operation_in_progress"
    try:
        from client_update_ui import get_update_ui_status

        ui = get_update_ui_status() or {}
        if ui:
            phase = str(ui.get("phase") or phase)
            from_v = str(ui.get("from_version") or "")
            to_v = str(ui.get("to_version") or "")
            detail = str(ui.get("detail") or detail)
            try:
                pct = int(ui.get("progress") if ui.get("progress") is not None else 0)
            except (TypeError, ValueError):
                pct = 0
    except Exception:
        pass
    return {
        "family": FAMILY_UPDATE,
        "op": "self_update",
        "phase": phase,
        "progress_pct": pct,
        "detail": detail,
        "from_version": from_v,
        "to_version": to_v,
        "busy": True,
        "ok": False,
        "error": "busy",
        "legacy_lock": True,
    }


def try_acquire(
    op: str,
    *,
    detail: str = "",
    from_version: str = "",
    to_version: str = "",
    command_id: str = "",
    force: bool = False,
) -> Tuple[bool, Dict[str, Any]]:
    """Try to start ``op``.

    Returns ``(True, {token, ...})`` on success or
    ``(False, {busy: True, ...snapshot})`` when another op owns the family.
    ``force`` reclaims even a live holder (operator recover / explicit force).
    """
    op_l = str(op or "self_update").strip().lower() or "self_update"
    family = _family_for(op_l)
    with _GATE_LOCK:
        snap = _read_raw()
        if snap and not force and not _is_stale(snap):
            if str(snap.get("family") or "") == family:
                out = dict(snap)
                out["busy"] = True
                out["ok"] = False
                out["error"] = "busy"
                out["detail"] = str(snap.get("detail") or "operation_in_progress")
                return False, out
        if family == FAMILY_UPDATE and not force:
            try:
                from client_utils import is_update_in_progress

                if is_update_in_progress():
                    # Gate missing but legacy lock live — refuse duplicate start.
                    if not snap or _is_stale(snap):
                        return False, _synthetic_busy_from_legacy()
            except Exception:
                pass
        if force:
            _clear_file()
            try:
                from client_utils import release_update_lock

                release_update_lock(resume_updaters=False)
            except Exception:
                pass
        # Reclaim stale / forced
        token = uuid.uuid4().hex
        now = time.time()
        payload = {
            "family": family,
            "op": op_l,
            "token": token,
            "pid": os.getpid(),
            "started_at": now,
            "phase_started_at": now,
            "updated_at": now,
            "phase": "queued",
            "progress_pct": 0,
            "detail": str(detail or op_l)[:200],
            "from_version": str(from_version or ""),
            "to_version": str(to_version or ""),
            "command_id": str(command_id or ""),
        }
        if not _write_raw(payload):
            return False, {
                "busy": True,
                "ok": False,
                "error": "busy",
                "detail": "gate_write_failed",
            }
        # Mirror legacy lock for observers (watchdog / tamper)
        try:
            from client_utils import acquire_update_lock

            acquire_update_lock(op_l.replace("_", "-")[:48])
        except Exception:
            pass
        return True, dict(payload)


def release(token: str = "", *, reason: str = "done", resume_updaters: bool = True) -> bool:
    """Release gate if token matches (or same pid / empty token force-clear)."""
    with _GATE_LOCK:
        snap = _read_raw()
        if not snap:
            _clear_legacy_lock(resume_updaters=resume_updaters)
            return True
        tok = str(token or "")
        if tok and str(snap.get("token") or "") != tok:
            try:
                if int(snap.get("pid") or 0) != os.getpid():
                    return False
            except (TypeError, ValueError):
                return False
        _clear_file()
    _clear_legacy_lock(resume_updaters=resume_updaters)
    return True


def force_clear(*, reason: str = "operator_recover", resume_updaters: bool = True) -> None:
    """Operator / recovery path — drop gate regardless of holder."""
    with _GATE_LOCK:
        _clear_file()
    _clear_legacy_lock(resume_updaters=resume_updaters)


def _clear_legacy_lock(*, resume_updaters: bool = True) -> None:
    try:
        from client_utils import release_update_lock

        release_update_lock(resume_updaters=resume_updaters)
    except Exception:
        pass


def busy_result_from_snapshot(snap: Dict[str, Any]) -> Dict[str, Any]:
    """Standard command/GUI payload when refusing a duplicate start."""
    phase = str(snap.get("phase") or "queued")
    pct = snap.get("progress_pct")
    try:
        pct_i = int(pct) if pct is not None else 0
    except (TypeError, ValueError):
        pct_i = 0
    return {
        "success": False,
        "ok": False,
        "busy": True,
        "error": "busy",
        "detail": "operation_in_progress",
        "message": "operation_in_progress",
        "phase": phase,
        "progress_pct": pct_i,
        "from_version": str(snap.get("from_version") or ""),
        "to_version": str(snap.get("to_version") or ""),
        "tag": (
            f"v{snap['to_version']}"
            if snap.get("to_version") and not str(snap.get("to_version")).lower().startswith("v")
            else str(snap.get("to_version") or "")
        ),
        "op": str(snap.get("op") or ""),
        "started_at": snap.get("started_at"),
        "updated_at": snap.get("updated_at"),
        "in_flight": True,
    }
