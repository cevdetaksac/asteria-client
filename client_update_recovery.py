#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Stuck / brick recovery for the update handoff path.

When a silent/self update acquires ``update_in_progress.lock`` and then dies
(helper never starts, download stalls, PID exits via ``os._exit``), the motor
must not stay down forever and the operator must see an actionable failure.

This module is the single place that:
  1. Diagnoses whether an update is legitimately in flight vs stuck
  2. Aborts the stuck state (lock + UI banner + stand-down + task resume)
  3. Optionally brings the SYSTEM motor back (ensure_daemon_running)

Call sites: heal_update_machinery, ensure_daemon_running, GUI update_banner,
daemon/GUI startup ticks.
"""

from __future__ import annotations

import os
import time
from typing import Any, Callable, Dict, Optional

# --- Thresholds (seconds) -------------------------------------------------
# Lock holder dead → treat as orphan after short grace (PID exit / kill).
DEAD_HOLDER_GRACE_SEC = 15.0
# silent-download / dashboard lock with no mtime heartbeat and motor down.
MOTOR_DOWN_LOCK_SEC = 90.0
# Active download/accept without progress touch (mtime) — abort even if PID "alive"
# (PID reuse false-positive, hung thread, or helper that never heartbeats).
NO_HEARTBEAT_ABORT_SEC = {
    "silent-download": 600.0,       # 10 min
    "dashboard-self-update": 900.0, # 15 min
    "interactive-download": 1800.0, # 30 min
    "installing": 1200.0,           # 20 min hard cap (also in is_update_in_progress)
}
# Helper log must appear after install handoff; otherwise lock is fake.
HELPER_LOG_MISSING_SEC = 120.0

_LogFn = Callable[[str], None]

# Re-entrancy guard: abort → ensure_daemon → maybe_auto_recover must not loop.
_in_recovery = False


def _programdata_asteria() -> str:
    return os.path.join(
        os.environ.get("ProgramData", r"C:\ProgramData"),
        "Asteria",
    )


def _lock_path() -> str:
    try:
        from client_utils import _update_lock_path
        return _update_lock_path()
    except Exception:
        return os.path.join(_programdata_asteria(), "update_in_progress.lock")


def _pid_alive(pid: Optional[int]) -> bool:
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
        return False
    return False


def _pid_looks_like_ours(pid: Optional[int]) -> bool:
    """Reject PID-reuse false positives (OpenProcess succeeds for unrelated process)."""
    if not pid or pid <= 0:
        return False
    if not _pid_alive(pid):
        return False
    try:
        import ctypes
        from ctypes import wintypes

        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        kernel32 = ctypes.windll.kernel32
        h = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid))
        if not h:
            # Cannot verify → be conservative only if process is alive (treat as ours).
            return True
        try:
            buf = ctypes.create_unicode_buffer(1024)
            size = wintypes.DWORD(1024)
            QueryFullProcessImageNameW = kernel32.QueryFullProcessImageNameW
            if not QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)):
                return True
            path = (buf.value or "").lower()
            markers = (
                "asteria-client",
                "asteria-gui",
                "honeypot-client",
                "cloudhoneypot",
                "\\asteria\\",
            )
            return any(m in path for m in markers)
        finally:
            kernel32.CloseHandle(h)
    except Exception:
        return True


def _read_lock() -> Dict[str, Any]:
    path = _lock_path()
    out: Dict[str, Any] = {
        "exists": False,
        "path": path,
        "phase": "",
        "pid": None,
        "started_at": 0.0,
        "age_sec": 0.0,
        "mtime_age_sec": 0.0,
        "pid_alive": False,
        "pid_ours": False,
    }
    if not os.path.isfile(path):
        return out
    out["exists"] = True
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        mtime = time.time()
    out["mtime_age_sec"] = max(0.0, time.time() - mtime)
    lines: list = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            lines = fh.read().splitlines()
    except OSError:
        lines = []
    if lines:
        out["phase"] = str(lines[0]).strip().lower()
    if len(lines) >= 2:
        try:
            out["pid"] = int(str(lines[1]).strip())
        except Exception:
            out["pid"] = None
    if len(lines) >= 3:
        try:
            out["started_at"] = float(str(lines[2]).strip())
        except Exception:
            out["started_at"] = 0.0
    if out["started_at"]:
        out["age_sec"] = max(0.0, time.time() - float(out["started_at"]))
    else:
        out["age_sec"] = out["mtime_age_sec"]
    out["pid_alive"] = _pid_alive(out["pid"])
    out["pid_ours"] = _pid_looks_like_ours(out["pid"]) if out["pid_alive"] else False
    return out


def _helper_recently_started(max_age_sec: float = 600.0) -> bool:
    log_path = os.path.join(_programdata_asteria(), "update-install.log")
    try:
        if not os.path.isfile(log_path):
            return False
        age = time.time() - os.path.getmtime(log_path)
        if age > max_age_sec:
            return False
        with open(log_path, "r", encoding="utf-8", errors="ignore") as fh:
            tail = fh.read()[-2000:]
        return "update-and-install start" in tail and "update-and-install done" not in tail[-400:]
    except Exception:
        return False


def _motor_healthy() -> bool:
    try:
        from client_daemon_ipc import is_motor_healthy
        return bool(is_motor_healthy())
    except Exception:
        return False


def diagnose_update_state() -> Dict[str, Any]:
    """Return a JSON-safe diagnosis for GUI / logs / recovery decisions."""
    lock = _read_lock()
    ui: Dict[str, Any] = {}
    try:
        from client_update_ui import _read_raw
        raw = _read_raw() or {}
        if isinstance(raw, dict):
            ui = {
                "phase": raw.get("phase"),
                "detail": raw.get("detail"),
                "error": raw.get("error"),
                "from_version": raw.get("from_version"),
                "to_version": raw.get("to_version"),
                "progress": raw.get("progress"),
                "phase_started_at": raw.get("phase_started_at"),
                "updated_at": raw.get("updated_at"),
            }
    except Exception:
        ui = {}

    motor_ok = _motor_healthy()
    reasons: list = []
    stuck = False

    if lock["exists"]:
        # Dead or foreign PID holding the lock
        if (not lock["pid_alive"] or not lock["pid_ours"]) and lock["mtime_age_sec"] > DEAD_HOLDER_GRACE_SEC:
            stuck = True
            reasons.append("orphan_lock_dead_or_foreign_pid")

        phase = str(lock.get("phase") or "")
        hb_limit = float(NO_HEARTBEAT_ABORT_SEC.get(phase, 0) or 0)
        if hb_limit and lock["mtime_age_sec"] > hb_limit:
            stuck = True
            reasons.append(f"no_heartbeat:{phase}")

        # Motor down while update lock claims exclusive ownership
        if not motor_ok and lock["mtime_age_sec"] > MOTOR_DOWN_LOCK_SEC:
            # Allow a live helper that just started
            if not _helper_recently_started():
                stuck = True
                reasons.append("motor_down_with_stale_lock")

        # Install handoff without helper log
        if phase.startswith("install") and not _helper_recently_started():
            if lock["age_sec"] > HELPER_LOG_MISSING_SEC or lock["mtime_age_sec"] > HELPER_LOG_MISSING_SEC:
                stuck = True
                reasons.append("helper_log_missing")

    # UI banner stuck in active phase (client_update_ui also expires these)
    ui_phase = str(ui.get("phase") or "")
    if ui_phase in ("accepted", "downloading", "staging", "installing"):
        started = float(ui.get("phase_started_at") or ui.get("updated_at") or 0)
        age = (time.time() - started) if started else 0.0
        limits = {
            "accepted": 600.0,
            "downloading": 1800.0,
            "staging": 600.0,
            "installing": 600.0,
        }
        if age > float(limits.get(ui_phase, 900.0)):
            stuck = True
            reasons.append(f"ui_phase_stale:{ui_phase}")

    return {
        "stuck": stuck,
        "reasons": reasons,
        "motor_ok": motor_ok,
        "lock": {
            "exists": lock["exists"],
            "phase": lock.get("phase") or "",
            "pid": lock.get("pid"),
            "pid_alive": lock.get("pid_alive"),
            "pid_ours": lock.get("pid_ours"),
            "age_sec": round(float(lock.get("age_sec") or 0), 1),
            "mtime_age_sec": round(float(lock.get("mtime_age_sec") or 0), 1),
        },
        "ui": ui,
        "helper_in_flight": _helper_recently_started(),
        "actionable": stuck or (not motor_ok and lock["exists"]),
    }


def abort_stuck_update(
    *,
    reason: str = "update_stalled",
    resume_motor: bool = True,
    force: bool = False,
    log_func: Optional[_LogFn] = None,
) -> Dict[str, Any]:
    """
    Clear update brick state and optionally restart the motor.

    force=True: operator/GUI explicit abort — clear even if diagnose says not stuck
    (still refuses if helper log shows an active install < 60s old unless force).
    """
    global _in_recovery
    _log = log_func or (lambda m: None)
    diag = diagnose_update_state()

    if not force and not diag.get("stuck") and not diag.get("actionable"):
        return {
            "ok": True,
            "aborted": False,
            "reason": "not_stuck",
            "diagnosis": diag,
        }

    # Soft guard: live helper mid-install — only force may interrupt
    if diag.get("helper_in_flight") and not force:
        if diag.get("lock", {}).get("mtime_age_sec", 0) < 180:
            return {
                "ok": False,
                "aborted": False,
                "error": "helper_in_flight",
                "diagnosis": diag,
            }

    _log(f"[UPDATE-RECOVERY] abort reason={reason} force={force} stuck={diag.get('stuck')}")
    _in_recovery = True
    try:
        # 1) UI banner → failed (operator-visible)
        try:
            from client_update_ui import set_update_ui_status
            ui = diag.get("ui") or {}
            set_update_ui_status(
                "failed",
                from_version=str(ui.get("from_version") or ""),
                to_version=str(ui.get("to_version") or ""),
                detail=reason,
                error=reason,
            )
        except Exception as exc:
            _log(f"[UPDATE-RECOVERY] set_update_ui_status failed: {exc}")

        # 2) Release lock + resume scheduled tasks (Background / SilentUpdater / …)
        try:
            from client_utils import release_update_lock
            release_update_lock(resume_updaters=True)
        except Exception as exc:
            _log(f"[UPDATE-RECOVERY] release_update_lock failed: {exc}")
            try:
                path = _lock_path()
                if os.path.isfile(path):
                    os.remove(path)
            except OSError:
                pass

        # 3) Clear resilience stand-down so ensure_daemon_running may run
        try:
            from client_resilience import clear_stand_down
            clear_stand_down()
        except Exception:
            pass

        motor_started = False
        if resume_motor and not _motor_healthy():
            try:
                from client_daemon_ipc import ensure_daemon_running
                motor_started = bool(ensure_daemon_running(log_func=_log, wait_sec=20.0))
                _log(f"[UPDATE-RECOVERY] ensure_daemon_running → {motor_started}")
            except Exception as exc:
                _log(f"[UPDATE-RECOVERY] ensure_daemon failed: {exc}")

        after = diagnose_update_state()
        return {
            "ok": True,
            "aborted": True,
            "reason": reason,
            "motor_ok": bool(after.get("motor_ok")),
            "motor_started": motor_started,
            "diagnosis_before": diag,
            "diagnosis_after": after,
        }
    finally:
        _in_recovery = False


def maybe_auto_recover_stuck_update(
    log_func: Optional[_LogFn] = None,
) -> bool:
    """
    Best-effort auto abort when diagnose says stuck.
    Returns True if an abort ran (caller may retry ensure_daemon).
    """
    _log = log_func or (lambda m: None)
    if _in_recovery:
        return False
    try:
        diag = diagnose_update_state()
        if not diag.get("stuck"):
            return False
        reasons = diag.get("reasons") or ["update_stalled"]
        detail = str(reasons[0]) if reasons else "update_stalled"
        result = abort_stuck_update(
            reason=detail,
            resume_motor=True,
            force=False,
            log_func=_log,
        )
        return bool(result.get("aborted"))
    except Exception as exc:
        _log(f"[UPDATE-RECOVERY] maybe_auto_recover error: {exc}")
        return False