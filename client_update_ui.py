#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cross-process update status for GUI banner.

SYSTEM daemon handles dashboard self_update; interactive GUI is a separate
process. Status is written to ProgramData so the GUI can poll and show a
top banner ("Güncelleme talimatı alındı…", download %, installing, done).
"""

from __future__ import annotations

import json
import os
import time
from typing import Any, Dict, Optional, Tuple

_VALID_PHASES = frozenset({
    "accepted",
    "downloading",
    "staging",
    "installing",
    "done",
    "failed",
})

# Active phases must not stick forever when helper dies silently.
# Ages use phase_started_at (not updated_at) so helper heartbeats cannot reset the clock.
_PHASE_STALE_SEC = {
    "accepted": 600,       # 10 min
    "downloading": 1800,   # 30 min
    "staging": 600,
    "installing": 600,     # 10 min — helper/NSIS stall or never started
    "done": 86400,
    "failed": 86400,
}


def _status_path() -> str:
    base = os.path.join(
        os.environ.get("ProgramData", r"C:\ProgramData"),
        "Asteria",
    )
    try:
        os.makedirs(base, exist_ok=True)
    except OSError:
        pass
    return os.path.join(base, "update_ui_status.json")


def _norm_ver(v: str) -> str:
    return (v or "").strip().lstrip("vV")


def _ver_tuple(v: str) -> Tuple[int, ...]:
    parts: list = []
    for p in _norm_ver(v).split("."):
        try:
            parts.append(int("".join(ch for ch in p if ch.isdigit()) or "0"))
        except ValueError:
            parts.append(0)
    return tuple(parts) if parts else (0,)


def set_update_ui_status(
    phase: str,
    *,
    from_version: str = "",
    to_version: str = "",
    detail: str = "",
    progress: Optional[int] = None,
    error: str = "",
) -> None:
    """Write update UI status (best-effort; never raises to callers)."""
    try:
        phase = (phase or "").strip().lower()
        if phase not in _VALID_PHASES:
            return
        prev = _read_raw() or {}
        now = time.time()
        prev_phase = (prev.get("phase") or "").strip().lower()
        # Heartbeats must not reset the stale clock
        if prev_phase == phase and prev.get("phase_started_at"):
            started = float(prev.get("phase_started_at") or now)
        else:
            started = now
        payload: Dict[str, Any] = {
            "phase": phase,
            "from_version": (from_version or prev.get("from_version") or "").strip(),
            "to_version": (to_version or prev.get("to_version") or "").strip(),
            "detail": (detail or "").strip(),
            "error": (error or "").strip(),
            "updated_at": now,
            "phase_started_at": started,
        }
        if progress is not None:
            try:
                payload["progress"] = max(0, min(100, int(progress)))
            except (TypeError, ValueError):
                pass
        elif "progress" in prev and phase == "downloading":
            payload["progress"] = prev.get("progress")

        path = _status_path()
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)
        os.replace(tmp, path)
        # Keep single-flight gate heartbeat in sync with banner phases.
        try:
            from client_operation_gate import touch

            touch(
                phase=phase,
                progress_pct=payload.get("progress"),
                detail=str(payload.get("detail") or ""),
                from_version=str(payload.get("from_version") or ""),
                to_version=str(payload.get("to_version") or ""),
            )
        except Exception:
            pass
    except Exception:
        pass


def _read_raw() -> Optional[Dict[str, Any]]:
    try:
        path = _status_path()
        if not os.path.isfile(path):
            return None
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            return None
        phase = (data.get("phase") or "").strip().lower()
        if phase not in _VALID_PHASES:
            return None
        data["phase"] = phase
        return data
    except Exception:
        return None


def _release_stale_lock() -> None:
    try:
        from client_utils import release_update_lock
        release_update_lock(resume_updaters=True)
    except Exception:
        pass
    try:
        from client_resilience import clear_stand_down
        clear_stand_down()
    except Exception:
        pass


def _mark_stalled(st: Dict[str, Any], reason: str = "update_stalled") -> Dict[str, Any]:
    set_update_ui_status(
        "failed",
        from_version=str(st.get("from_version") or ""),
        to_version=str(st.get("to_version") or ""),
        detail=reason,
        error=reason,
    )
    _release_stale_lock()
    return _read_raw() or {
        "phase": "failed",
        "error": reason,
        "from_version": st.get("from_version") or "",
        "to_version": st.get("to_version") or "",
        "updated_at": time.time(),
    }


def _phase_age_sec(data: Dict[str, Any]) -> float:
    started = float(data.get("phase_started_at") or 0)
    if not started:
        started = float(data.get("updated_at") or 0)
    if not started:
        return 0.0
    return max(0.0, time.time() - started)


def reconcile_update_ui_with_version(current_version: str) -> Optional[Dict[str, Any]]:
    """
    If we already run a version >= target (or past a failed mid-update),
    clear / mark done so the banner cannot stick on an obsolete install.
    """
    st = _read_raw()
    if not st:
        return None
    phase = st.get("phase") or ""
    target = _norm_ver(str(st.get("to_version") or ""))
    from_v = _norm_ver(str(st.get("from_version") or ""))
    cur = _norm_ver(current_version)
    if not cur:
        return st

    # Already on/newer than the update target → never keep a stuck/failed banner
    if target and _ver_tuple(cur) >= _ver_tuple(target):
        if phase in ("accepted", "downloading", "staging", "installing"):
            set_update_ui_status(
                "done",
                from_version=str(st.get("from_version") or ""),
                to_version=target or cur,
                detail="already_on_target_or_newer",
            )
            _release_stale_lock()
            return _read_raw()
        if phase in ("failed", "done"):
            # Obsolete failure (e.g. 4.5.43→4.5.45 while running 4.5.49)
            clear_update_ui_status()
            _release_stale_lock()
            return None

    # Moved past from_version with a failed/stale status → clear
    if (
        phase == "failed"
        and from_v
        and _ver_tuple(cur) > _ver_tuple(from_v)
    ):
        clear_update_ui_status()
        _release_stale_lock()
        return None

    if phase not in ("accepted", "downloading", "staging", "installing"):
        return st

    # No target recorded but we left from_version behind → obsolete status
    if from_v and _ver_tuple(cur) > _ver_tuple(from_v) and _phase_age_sec(st) > 60:
        clear_update_ui_status()
        _release_stale_lock()
        return None
    return st


def get_update_ui_status(
    max_age_sec: float = 7200.0,
    current_version: str = "",
) -> Optional[Dict[str, Any]]:
    """Read status file; expire stuck active phases to failed."""
    if current_version:
        reconcile_update_ui_with_version(current_version)

    data = _read_raw()
    if not data:
        return None
    phase = data.get("phase") or ""
    age = _phase_age_sec(data)
    updated = float(data.get("updated_at") or 0)

    stale_limit = float(_PHASE_STALE_SEC.get(phase, max_age_sec))
    if age > stale_limit and phase in (
        "accepted", "downloading", "staging", "installing",
    ):
        return _mark_stalled(data, "update_stalled")

    # Failed banners: auto-expire sooner (2h wall) and delete the file
    fail_max = min(max_age_sec, 7200.0)
    if phase == "failed" and updated and (time.time() - updated) > fail_max:
        clear_update_ui_status()
        return None

    if updated and max_age_sec > 0 and (time.time() - updated) > max_age_sec and phase == "done":
        clear_update_ui_status()
        return None

    return data


def clear_update_ui_status() -> None:
    try:
        path = _status_path()
        if os.path.isfile(path):
            os.remove(path)
    except Exception:
        pass


def maybe_mark_done_on_startup(current_version: str) -> None:
    """
    After install, new process starts: if status targeted this version,
    mark done so GUI can show success briefly.

    If still on old version while phase=installing and status is old → failed
    (helper died after setting 'installing' without finishing).
    """
    try:
        if reconcile_update_ui_with_version(current_version) is None:
            return
        st = _read_raw()
        if not st:
            return
        phase = st.get("phase") or ""
        target = _norm_ver(str(st.get("to_version") or ""))
        cur = _norm_ver(current_version)
        age = _phase_age_sec(st)

        if target and cur and cur == target and phase in (
            "accepted", "downloading", "staging", "installing", "done",
        ):
            set_update_ui_status(
                "done",
                from_version=str(st.get("from_version") or ""),
                to_version=target,
                detail="install_complete",
            )
            return

        # Still old build but banner says installing → helper never finished
        if (
            phase in ("installing", "staging", "accepted", "downloading")
            and target
            and cur
            and cur != target
            and age > 120  # give helper 2 min after relaunch
        ):
            limit = float(_PHASE_STALE_SEC.get(phase, 900))
            if age > min(300.0, limit):  # 5 min soft fail on boot
                _mark_stalled(st, "install_did_not_complete")
    except Exception:
        pass
