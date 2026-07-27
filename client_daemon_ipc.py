# -*- coding: utf-8 -*-
"""
Daemon IPC — GUI frontend talks to Session-0 SYSTEM motor.

Protocol (newline-terminated, UTF-8):
  PING
  STATUS
  CLEAR_FIREWALL
  BLOCK_IP <ip> [reason]
  UNBLOCK_IP <ip>
  RS_UNLOCK
  RS_STATUS
  THREAT_TOP
  IP_TABLE
  SHARES_LIST / SHARE_REMOVE <name>
  SVC_LIST / SVC_STOP <name>
  SELF_UPDATE
  NG_MAINT_START / NG_MAINT_END / NG_MAINT_END_SNAPSHOT / NG_SNAPSHOT
  NG_ACCEPT_SURFACE
  HONEYPOT START <SERVICE> <PORT>
  HONEYPOT STOP <SERVICE>
  HONEYPOT LIST
  SHOW / QUIT  (legacy; daemon replies NOGUI to SHOW)

JSON replies are a single line starting with '{' .
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
from typing import Any, Dict, Optional

try:
    from client_constants import CONTROL_HOST, CONTROL_PORT
except Exception:
    CONTROL_HOST = "127.0.0.1"
    CONTROL_PORT = 58632


def _recv_line(sock: socket.socket, timeout: float = 3.0) -> str:
    sock.settimeout(timeout)
    buf = b""
    while b"\n" not in buf and len(buf) < 262144:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    return buf.split(b"\n", 1)[0].decode("utf-8", "ignore").strip()


def request(cmd: str, timeout: float = 3.0) -> str:
    """Send one command line; return raw reply line (may be JSON)."""
    line = (cmd or "").strip()
    if not line.endswith("\n"):
        line += "\n"
    with socket.create_connection((CONTROL_HOST, CONTROL_PORT), timeout=timeout) as sock:
        sock.sendall(line.encode("utf-8"))
        return _recv_line(sock, timeout=timeout)


def request_json(cmd: str, timeout: float = 3.0) -> Dict[str, Any]:
    raw = request(cmd, timeout=timeout)
    if not raw:
        return {"ok": False, "error": "empty_reply"}
    if raw.startswith("{"):
        try:
            return json.loads(raw)
        except Exception as e:
            return {"ok": False, "error": f"bad_json: {e}", "raw": raw}
    # legacy text
    return {"ok": True, "reply": raw}


def ping(timeout: float = 1.5) -> bool:
    try:
        r = request("PING", timeout=timeout)
        return r.upper().startswith("PONG") or (
            r.startswith("{") and json.loads(r).get("ok") is True
        )
    except Exception:
        return False


def get_status(timeout: float = 3.0) -> Dict[str, Any]:
    try:
        return request_json("STATUS", timeout=timeout)
    except Exception as e:
        return {"ok": False, "error": str(e), "daemon": False}


def clear_firewall(timeout: float = 180.0) -> Dict[str, Any]:
    """Ask SYSTEM daemon to wipe honeypot firewall rules + sync API."""
    try:
        return request_json("CLEAR_FIREWALL", timeout=timeout)
    except Exception as e:
        return {"ok": False, "error": str(e)}


def block_ip(ip: str, reason: str = "gui", timeout: float = 45.0) -> Dict[str, Any]:
    """Ask SYSTEM daemon to apply HP-BLOCK for one IP (elevated)."""
    ip = (ip or "").strip()
    if not ip:
        return {"ok": False, "error": "missing_ip"}
    # reason: no spaces in protocol line
    safe_reason = "".join(c if c.isalnum() or c in "._-" else "_" for c in (reason or "gui"))[:64]
    try:
        return request_json(f"BLOCK_IP {ip} {safe_reason}", timeout=timeout)
    except Exception as e:
        return {"ok": False, "error": str(e)}


def unblock_ip(ip: str, timeout: float = 45.0) -> Dict[str, Any]:
    ip = (ip or "").strip()
    if not ip:
        return {"ok": False, "error": "missing_ip"}
    try:
        return request_json(f"UNBLOCK_IP {ip}", timeout=timeout)
    except Exception as e:
        return {"ok": False, "error": str(e)}


def threat_top(timeout: float = 4.0) -> Dict[str, Any]:
    """Ask SYSTEM motor for top attacker contexts (frontend has no engine)."""
    try:
        return request_json("THREAT_TOP", timeout=timeout)
    except Exception as e:
        return {"ok": False, "error": str(e), "attackers": [], "total": 0}


def self_update(timeout: float = 8.0) -> Dict[str, Any]:
    """Ask SYSTEM motor to start silent self-update (GUI Check for updates)."""
    try:
        return request_json("SELF_UPDATE", timeout=timeout)
    except Exception as e:
        return {"ok": False, "error": str(e), "started": False}


def ip_table(timeout: float = 6.0) -> Dict[str, Any]:
    """Watching / blocked / whitelist inventory for GUI homepage panels."""
    try:
        return request_json("IP_TABLE", timeout=timeout)
    except Exception as e:
        return {
            "ok": False,
            "error": str(e),
            "watching": [],
            "blocked": [],
            "whitelist": [],
            "totals": {"watching": 0, "blocked": 0, "whitelist": 0},
        }


def ransomware_status(timeout: float = 8.0) -> Dict[str, Any]:
    """Ask SYSTEM motor for ransomware shield stats + quarantine."""
    try:
        return request_json("RS_STATUS", timeout=timeout)
    except Exception as e:
        return {"ok": False, "error": str(e)}


def ransomware_unlock(timeout: float = 20.0) -> Dict[str, Any]:
    """Clear ransomware IFEO quarantine on SYSTEM motor."""
    try:
        return request_json("RS_UNLOCK", timeout=timeout)
    except Exception as e:
        return {"ok": False, "error": str(e)}


def network_maintenance_start(timeout: float = 8.0) -> Dict[str, Any]:
    """Pause Network Guard detect + auto_restore (VPN/IP work window)."""
    try:
        return request_json("NG_MAINT_START", timeout=timeout)
    except Exception as e:
        return {"ok": False, "error": str(e)}


def network_maintenance_end(snapshot: bool = True, timeout: float = 30.0) -> Dict[str, Any]:
    """Resume Network Guard; optionally capture golden baseline first."""
    cmd = "NG_MAINT_END_SNAPSHOT" if snapshot else "NG_MAINT_END"
    try:
        return request_json(cmd, timeout=timeout)
    except Exception as e:
        return {"ok": False, "error": str(e)}


def network_accept_surface(timeout: float = 30.0) -> Dict[str, Any]:
    """Accept live additive surface as new golden (Bu bendim)."""
    try:
        return request_json("NG_ACCEPT_SURFACE", timeout=timeout)
    except Exception as e:
        return {"ok": False, "error": str(e)}


def network_snapshot(timeout: float = 30.0) -> Dict[str, Any]:
    """Capture golden network baseline now (without ending maintenance)."""
    try:
        return request_json("NG_SNAPSHOT", timeout=timeout)
    except Exception as e:
        return {"ok": False, "error": str(e)}


def is_motor_healthy(timeout: float = 1.2) -> bool:
    """True only if Session-0 motor answers STATUS with command poller alive.

    Plain PING is not enough — a GUI/tray that bound :58632 also answers PONG
    but never runs commands/pending or remote WS.
    """
    try:
        st = get_status(timeout=timeout)
        if not st.get("ok"):
            return False
        if st.get("motor_ok") is True:
            return True
        # Explicit fields from v4.5.12+
        if "remote_commands_running" in st:
            return bool(st.get("daemon")) and bool(st.get("remote_commands_running"))
        # role=daemon without the new flag (older motor still OK if role set)
        if st.get("role") == "daemon" and st.get("daemon") is True:
            return True
        return False
    except Exception:
        return False


def shares_list(timeout: float = 12.0) -> Dict[str, Any]:
    try:
        return request_json("SHARES_LIST", timeout=timeout)
    except Exception as e:
        return {"ok": False, "error": str(e), "shares": [], "custom_count": 0}


def share_remove(name: str, timeout: float = 15.0) -> Dict[str, Any]:
    share = str(name or "").strip()
    if not share:
        return {"ok": False, "error": "missing_share"}
    # Protocol line: no spaces in share names expected (SMB names)
    safe = "".join(c if c.isalnum() or c in "._$-" else "_" for c in share)[:80]
    try:
        return request_json(f"SHARE_REMOVE {safe}", timeout=timeout)
    except Exception as e:
        return {"ok": False, "error": str(e)}


def svc_list(timeout: float = 25.0) -> Dict[str, Any]:
    try:
        return request_json("SVC_LIST", timeout=timeout)
    except Exception as e:
        return {"ok": False, "error": str(e), "services": [], "unknown_count": 0}


def svc_stop(name: str, timeout: float = 20.0) -> Dict[str, Any]:
    svc = str(name or "").strip()
    if not svc:
        return {"ok": False, "error": "missing_service"}
    safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in svc)[:128]
    try:
        return request_json(f"SVC_STOP {safe}", timeout=timeout)
    except Exception as e:
        return {"ok": False, "error": str(e)}


def honeypot_start(service: str, port: int, timeout: float = 8.0) -> Dict[str, Any]:
    svc = str(service).upper().strip()
    try:
        return request_json(f"HONEYPOT START {svc} {int(port)}", timeout=timeout)
    except Exception as e:
        return {"ok": False, "error": str(e)}


def honeypot_stop(service: str, timeout: float = 8.0) -> Dict[str, Any]:
    svc = str(service).upper().strip()
    try:
        return request_json(f"HONEYPOT STOP {svc}", timeout=timeout)
    except Exception as e:
        return {"ok": False, "error": str(e)}


def honeypot_list(timeout: float = 3.0) -> Dict[str, Any]:
    try:
        return request_json("HONEYPOT LIST", timeout=timeout)
    except Exception as e:
        return {"ok": False, "error": str(e), "services": []}


def ensure_daemon_running(log_func=None, wait_sec: float = 20.0) -> bool:
    """If SYSTEM motor is unhealthy, start --mode=daemon and wait for motor_ok."""
    if log_func is None:
        log_func = print
    if is_motor_healthy():
        return True

    # Never fight a *live* update handoff or signed operator PIN stop.
    # Stuck/orphan update locks must not brick the motor forever — auto-recover first.
    try:
        from client_resilience import is_legitimate_stand_down, note_stand_down
        if is_legitimate_stand_down():
            recovered = False
            try:
                from client_update_recovery import maybe_auto_recover_stuck_update
                recovered = bool(maybe_auto_recover_stuck_update(log_func=log_func))
            except Exception as e:
                log_func(f"[IPC] stuck-update probe failed: {e}")
            if recovered:
                log_func("[IPC] stuck update aborted — continuing daemon start")
            elif is_legitimate_stand_down():
                note_stand_down("update_or_operator_stop")
                log_func("[IPC] ensure_daemon_running skipped — legitimate stand-down")
                return False
    except Exception:
        pass

    if ping() and not is_motor_healthy():
        log_func(
            "[IPC] Control port answers PING but motor_ok=false "
            "(likely GUI stole :58632) — starting Background daemon anyway"
        )

    try:
        from client_helpers import ClientHelpers
        if ClientHelpers.is_daemon_running():
            log_func("[IPC] Daemon process present — waiting for motor health...")
            deadline = time.time() + min(8.0, wait_sec)
            while time.time() < deadline:
                if is_motor_healthy():
                    return True
                time.sleep(0.5)
    except Exception:
        pass

    # Prefer scheduled Background task (SYSTEM Session 0) over user-context spawn
    started = False
    try:
        from client_task_scheduler import TASK_NAME_BACKGROUND
        from client_winproc import run_hidden, popen_detached
        run_hidden(
            ["schtasks", "/change", "/tn", TASK_NAME_BACKGROUND, "/enable"],
            timeout=10,
        )
        rc, _, _ = run_hidden(
            ["schtasks", "/run", "/tn", TASK_NAME_BACKGROUND],
            timeout=15,
        )
        started = rc == 0
        log_func(f"[IPC] schtasks /run {TASK_NAME_BACKGROUND}: rc={rc}")
    except Exception as e:
        log_func(f"[IPC] schtasks Background run failed: {e}")

    if not started:
        log_func("[IPC] Starting SYSTEM daemon motor (direct spawn)...")
        try:
            from client_winproc import popen_detached
            if getattr(sys, "frozen", False):
                exe = sys.executable
                args = [exe, "--mode=daemon", "--silent"]
            else:
                script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "client.py")
                args = [sys.executable, script, "--mode=daemon", "--silent"]
            if popen_detached(args) is None:
                raise RuntimeError("popen_detached failed")
            started = True
        except Exception as e:
            log_func(f"[IPC] Failed to spawn daemon: {e}")
            return False

    deadline = time.time() + wait_sec
    while time.time() < deadline:
        if is_motor_healthy():
            log_func("[IPC] Daemon motor ready (remote_commands_running)")
            return True
        time.sleep(0.5)
    # Soft success: process may be up but port stolen — still better than nothing
    if ping():
        log_func(
            "[IPC] WARN: listener up but motor_ok still false — "
            "command poll may be missing until Background owns Session 0"
        )
    else:
        log_func("[IPC] Daemon did not become healthy in time")
    return is_motor_healthy()
