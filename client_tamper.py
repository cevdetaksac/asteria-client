"""Tamper detection + persistence health (contract ≥4.6.0).

- Session marker: unexpected motor exit → agent_tamper urgent on next boot
- Dead-man: periodic motor heartbeat file for cloud-side offline detection
- report_tamper(): POST alerts/urgent with system_context.tamper
"""

from __future__ import annotations

import json
import os
import threading
import time
import uuid
from datetime import datetime, timezone

try:
    from client_constants import MACHINE_DATA_DIR, TOKEN_FILE
except Exception:
    MACHINE_DATA_DIR = os.path.join(
        os.environ.get("ProgramData", r"C:\ProgramData"),
        "Asteria",
    )
    TOKEN_FILE = os.path.join(MACHINE_DATA_DIR, "token.dat")

SESSION_FILE = os.path.join(MACHINE_DATA_DIR, "motor_session.json")
HEARTBEAT_FILE = os.path.join(MACHINE_DATA_DIR, "motor_heartbeat.json")

_tamper_lock = threading.Lock()
_tamper_count_24h = 0
_last_tamper_ts: str | None = None
_deadman_stop = threading.Event()
_deadman_thread: threading.Thread | None = None


def _read_token() -> str:
    try:
        with open(TOKEN_FILE, "r", encoding="utf-8") as f:
            return (f.read() or "").strip()
    except Exception:
        return ""


def _load_json(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _write_json(path: str, data: dict) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f)
    os.replace(tmp, path)


def start_motor_session(pid: int, version: str = "") -> None:
    _write_json(SESSION_FILE, {
        "pid": int(pid),
        "started_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "version": version or "",
        "graceful": False,
    })


def mark_graceful_motor_shutdown() -> None:
    data = _load_json(SESSION_FILE)
    if data:
        data["graceful"] = True
        data["stopped_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        _write_json(SESSION_FILE, data)


def check_previous_session_on_boot() -> bool:
    """Return True if previous session ended unexpectedly (tamper candidate)."""
    data = _load_json(SESSION_FILE)
    if not data or data.get("graceful"):
        return False
    try:
        from client_operator_stop import is_operator_stop_active
        if is_operator_stop_active():
            return False
    except Exception:
        pass
    try:
        from client_utils import is_update_in_progress
        if is_update_in_progress():
            return False
    except Exception:
        pass
    report_tamper(
        reason="unexpected_exit",
        leg="daemon",
        resurrected=True,
        resurrect_ms=0,
        offender=None,
    )
    return True


def start_deadman_beacon(interval_sec: float = 60.0) -> None:
    global _deadman_thread
    if _deadman_thread and _deadman_thread.is_alive():
        return
    _deadman_stop.clear()

    def _loop():
        while not _deadman_stop.is_set():
            try:
                payload = {
                    "ts": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                    "pid": os.getpid(),
                    "graceful_capable": True,
                }
                # RES-103 observe: optional signed proof for Guardian soft-check.
                # Never gates motor liveness; flag default off.
                try:
                    from client_resilience_p1 import (
                        build_heartbeat_observe,
                        heartbeat_observe_enabled,
                    )
                    if heartbeat_observe_enabled():
                        hostname = (
                            os.environ.get("COMPUTERNAME")
                            or os.environ.get("HOSTNAME")
                            or ""
                        )
                        proof = build_heartbeat_observe(
                            _read_token() or "",
                            hostname=hostname,
                            status="online",
                            running=True,
                        )
                        if proof:
                            payload["hostname"] = hostname
                            payload["status"] = "online"
                            payload["running"] = True
                            payload["heartbeat_proof"] = proof
                except Exception:
                    pass
                _write_json(HEARTBEAT_FILE, payload)
            except Exception:
                pass
            _deadman_stop.wait(interval_sec)

    _deadman_thread = threading.Thread(target=_loop, name="DeadmanBeacon", daemon=True)
    _deadman_thread.start()


def stop_deadman_beacon() -> None:
    _deadman_stop.set()


def report_tamper(
    reason: str,
    leg: str = "daemon",
    resurrected: bool = False,
    resurrect_ms: int = 0,
    offender: dict | None = None,
    legitimate: bool = False,
) -> None:
    global _tamper_count_24h, _last_tamper_ts
    if legitimate:
        return
    with _tamper_lock:
        _tamper_count_24h += 1
        _last_tamper_ts = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    token = _read_token()
    if not token:
        return

    tamper_ctx = {
        "reason": reason,
        "leg": leg,
        "legitimate": False,
        "resurrected": bool(resurrected),
        "resurrect_ms": int(resurrect_ms),
        "ts": _last_tamper_ts,
    }
    if offender:
        tamper_ctx["offender"] = offender

    raw_events = [{
        "kind": "agent_tamper",
        "reason": reason,
        "leg": leg,
        "resurrected": bool(resurrected),
    }]
    if offender and offender.get("pid"):
        raw_events[0]["offender_pid"] = offender.get("pid")
        raw_events[0]["image"] = offender.get("image", "")

    payload = {
        "token": token,
        "alert_id": str(uuid.uuid4()),
        "timestamp": _last_tamper_ts,
        "severity": "critical",
        "threat_type": "agent_tamper",
        "title": "AGENT TAMPER — motor durdurulmaya calisildi",
        "description": f"reason={reason} leg={leg} resurrected={resurrected}",
        "threat_score": 100,
        "target_service": "SYSTEM",
        "recommended_action": "isolate_host",
        "system_context": {"tamper": tamper_ctx},
        "raw_events": raw_events,
        "auto_response_taken": [],
    }

    def _send():
        try:
            from client_api import ClientAPI
            from client_helpers import log
            api = ClientAPI()
            api.api_request("POST", "alerts/urgent", data=payload, timeout=15)
            log(f"[TAMPER] urgent sent reason={reason}")
        except Exception as e:
            try:
                from client_helpers import log
                log(f"[TAMPER] urgent send failed: {e}")
            except Exception:
                pass

    threading.Thread(target=_send, name="TamperUrgent", daemon=True).start()


def get_persistence_status(daemon_ok_override=None) -> dict:
    """Return persistence health without recursive daemon IPC.

    `daemon_ok_override` is mandatory for callers already serving the daemon
    STATUS socket. Calling is_motor_healthy() from inside STATUS recursively
    queued another STATUS request on the same single-threaded server and could
    exhaust the listener until every GUI/Guardian probe timed out.
    """
    try:
        from client_guardian_service import (
            is_guardian_service_installed,
            is_guardian_service_running,
        )
        svc_ok = is_guardian_service_running()
        svc_inst = is_guardian_service_installed()
    except Exception:
        svc_ok = False
        svc_inst = False
    if daemon_ok_override is not None:
        daemon_ok = bool(daemon_ok_override)
    else:
        try:
            from client_daemon_ipc import is_motor_healthy
            daemon_ok = bool(is_motor_healthy())
        except Exception:
            daemon_ok = False
    try:
        from client_operator_stop import is_operator_stop_active
        op_stop = is_operator_stop_active()
    except Exception:
        op_stop = False
    out = {
        "service_ok": svc_ok,
        "service_installed": svc_inst,
        "daemon_ok": daemon_ok,
        "tasks_armed": not op_stop,
        "self_protection": True,
        "operator_stop": op_stop,
        "last_tamper_ts": _last_tamper_ts,
        "tamper_count_24h": _tamper_count_24h,
    }
    try:
        from client_resilience import snapshot
        out["resilience"] = snapshot(
            guardian_installed=svc_inst,
            guardian_running=svc_ok,
        )
    except Exception:
        pass
    return out
