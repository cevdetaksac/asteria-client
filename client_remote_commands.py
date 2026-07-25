#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Asteria Client — Remote Command Executor (v4.0)

Polls the backend API for pending commands issued from the dashboard
and executes them securely on the local machine.  This is the
generalised successor of the existing pending-blocks pattern in
client_firewall.py.

Flow:
  1. Prefer control WS push (wss://…/ws/agent/control) for instant commands
  2. Fallback / safety: Poll GET /api/commands/pending (Bearer) 
  3. Coalesce duplicate remote_stream_start (latest wins; older → cancelled)
  4. Validate command (type, expiry, protected targets)
  5. Execute via AutoResponse / subprocess
  6. Report result POST /api/commands/result (+ WS command_result dual-send)

Supported commands:
  block_ip, unblock_ip, clear_firewall, logoff_user, contain_user, disable_account,
  disable_all_users, enable_account, reset_password, kill_process, stop_service, disable_service,
  emergency_lockdown, lift_lockdown, list_sessions, list_processes,
  snapshot, collect_diagnostics, self_update, check_update

Security layers:
  - Command whitelist (ALLOWED_COMMANDS)
  - 5-minute expiry window
  - Protected accounts / processes / services
  - Rate limiting (max 10 commands/minute)

Exports:
  RemoteCommandExecutor — main class (start / stop / get_stats)
"""

import os
import subprocess
import threading
import time
from collections import deque
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional, Set

from client_helpers import log
from client_security_utils import inspect_command_signature, sign_command

# ── Constants ─────────────────────────────────────────────────────

try:
    from client_constants import REMOTE_CMD_POLL_INTERVAL as _POLL
    POLL_INTERVAL = max(1, int(_POLL))
except Exception:
    POLL_INTERVAL = 1
try:
    from client_constants import REMOTE_CMD_IR_POLL_INTERVAL as _IR_POLL
    IR_POLL_INTERVAL = max(0.25, float(_IR_POLL))
except Exception:
    IR_POLL_INTERVAL = 0.5
try:
    from client_constants import REMOTE_CMD_IR_STICKY_SECONDS as _IR_STICKY
    IR_STICKY_SECONDS = max(5, float(_IR_STICKY))
except Exception:
    IR_STICKY_SECONDS = 45
try:
    from client_constants import REMOTE_CMD_MAX_PER_MINUTE as _MAX_RPM
    MAX_COMMANDS_PER_MINUTE = max(10, int(_MAX_RPM))
except Exception:
    MAX_COMMANDS_PER_MINUTE = 30
COMMAND_EXPIRY_SECONDS = 300  # 5 minutes (default)
SELF_UPDATE_EXPIRY_SECONDS = 1800  # 30 minutes (dashboard self_update TTL)

CREATE_NO_WINDOW = 0x08000000

ALLOWED_COMMANDS: Set[str] = {
    "block_ip", "unblock_ip", "clear_firewall", "migrate_firewall_brand",
    "logoff_user", "disable_account", "enable_account", "reset_password",
    "contain_user",  # IR: logoff + password reset (+ optional disable) in one shot
    "disable_all_users",  # IR panic: disable every local SAM user (excl. machine IDs)
    "kill_process", "suspend_process", "resume_process", "block_process",
    "allow_process", "list_allowed_processes",
    "isolate_host", "lift_isolation",
    "stop_service", "start_service", "restart_service", "disable_service",
    "emergency_lockdown", "lift_lockdown",
    "enable_lockdown", "disable_lockdown",  # aliases
    "unlock_ransomware_quarantine", "list_ransomware_quarantine",
    "list_sessions", "list_processes", "list_local_users", "list_services", "snapshot",
    "collect_diagnostics",
    "remote_stream_start", "remote_stream_stop", "remote_input",
    "remote_send_sas",
    "remote_session_prepare", "remote_session_logoff",
    "self_update", "check_update",
    # Disaster recovery (contract ≥4.6.0 — agent/disaster-recovery.md)
    "create_user", "remote_logon", "set_autologon", "clear_autologon", "reboot",
    # Network Guard (contract ≥4.7.0 — agent/network-guard.md)
    "network_snapshot", "network_restore", "list_network_baseline",
    "network_diff",
    "network_maintenance_start", "network_maintenance_end",
    "network_accept_surface", "network_disable_adapter",
    # System Recovery (contract ≥1.4.13 — agent/system-recovery.md)
    "system_recovery_snapshot", "list_system_recovery",
    "system_recovery_diff", "system_recovery_restore",
    # GUI PIN management from dashboard (contract ≥4.8.3)
    "set_gui_pin", "clear_gui_pin",
    # Honeypot bait start/stop (contract attacks-and-services — dashboard "tunnel")
    "tunnel_start", "tunnel_stop",
}

# High-frequency IR commands — skip global cmd/min rate limit
_STREAM_COMMANDS = frozenset({
    "remote_stream_start", "remote_stream_stop", "remote_input",
    "remote_send_sas",
    "remote_session_prepare", "list_local_users", "list_sessions",
    "list_processes", "list_services",
})

# Incident-response: always fast poll + no rate limit (breach containment)
_IR_URGENT_COMMANDS = frozenset({
    "kill_process", "suspend_process", "resume_process", "block_process",
    "allow_process",
    "isolate_host", "lift_isolation",
    "logoff_user", "contain_user",
    "block_ip", "unblock_ip",
    "disable_account", "disable_all_users", "reset_password",
    "stop_service", "start_service", "restart_service", "disable_service",
    "tunnel_start", "tunnel_stop",
    "list_services",
    "emergency_lockdown", "lift_lockdown",
    "enable_lockdown", "disable_lockdown",
    "unlock_ransomware_quarantine",
    "clear_firewall", "migrate_firewall_brand",
    "self_update", "check_update",  # dashboard update — same urgency as IR
    "remote_session_prepare", "list_local_users",
    "list_processes", "list_sessions",
    # Disaster recovery — must reach a compromised host instantly
    "create_user", "remote_logon", "set_autologon", "clear_autologon", "reboot",
    # Network Guard — offline bomb response must reach host instantly
    "network_snapshot", "network_restore", "list_network_baseline",
    "network_diff",
    "network_maintenance_start", "network_maintenance_end",
    "network_accept_surface", "network_disable_adapter",
    # System Recovery — attack-surface restore
    "system_recovery_snapshot", "list_system_recovery",
    "system_recovery_diff", "system_recovery_restore",
})
# Back-compat alias
_CRITICAL_FAST_POLL = _IR_URGENT_COMMANDS
CRITICAL_POLL_INTERVAL = IR_POLL_INTERVAL

# Only OS machine identities — never IR-block real users (incl. Administrator).
# Compromised Administrator must be logoff + password-reset from dashboard instantly.
PROTECTED_ACCOUNTS: Set[str] = {
    "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE",
}

PROTECTED_PROCESSES: Set[str] = {
    "system", "smss.exe", "csrss.exe", "wininit.exe",
    "services.exe", "lsass.exe", "svchost.exe",
    "asteria-client.exe",
    "honeypot-client.exe",
}

PROTECTED_SERVICES: Set[str] = {
    "wuauserv", "windefend", "eventlog", "mpssvc",
    "cloudhoneypotguardian",
}

# Commands that require dashboard-side confirmation before reaching here.
# Mutating network_restore needs confirm; dry_run-only must not (contract 1.4.5).
REQUIRES_CONFIRMATION: Set[str] = {
    "emergency_lockdown", "reset_password", "disable_account",
    "disable_all_users", "contain_user",
    # Process containment is only sent after explicit operator approval.
    "suspend_process",
    "allow_process",
    # Network isolate — P2; always confirm; client hard-rejects unsafe policy
    "isolate_host",
    "lift_isolation",
    # Disaster recovery (destructive / reboot) — server confirm + HMAC
    "create_user", "remote_logon", "set_autologon", "reboot",
    # Network Guard — mutating restore only (see network_restore_requires_confirm)
    "network_restore",
    "network_disable_adapter",
    # System Recovery — mutating restore (dry_run exempt via helper)
    "system_recovery_restore",
    # GUI PIN — overwrite/reset local anti-tamper PIN needs operator confirm
    "set_gui_pin", "clear_gui_pin",
}


def network_restore_requires_confirm(params: Optional[dict] = None) -> bool:
    """True for mutating restore; False for dry-run plan-only (contract 1.4.5)."""
    params = params or {}
    return not bool(params.get("dry_run", False))


def network_disable_adapter_requires_confirm(params: Optional[dict] = None) -> bool:
    """True for mutating disable; False for dry-run (contract 1.4.17)."""
    params = params or {}
    return not bool(params.get("dry_run", False))


def system_recovery_restore_requires_confirm(params: Optional[dict] = None) -> bool:
    """True for mutating system recovery; False for dry-run (contract 1.4.13)."""
    params = params or {}
    return not bool(params.get("dry_run", False))

# Hard-skip only (AGENT_DISABLE_ALL_USERS_PROMPT) — Administrator is NOT here
_SKIP_DISABLE_ALWAYS: Set[str] = {
    "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE",
    "WDAGUTILITYACCOUNT", "DEFAULTACCOUNT",
}

# Concurrent disable_all_users lock
_disable_all_lock = threading.Lock()
_disable_all_busy = False


# ── Remote Command Executor ──────────────────────────────────────

class RemoteCommandExecutor:
    """
    Polls for and executes dashboard-issued remote commands.

    Usage:
        executor = RemoteCommandExecutor(
            api_client=api_client,
            token_getter=lambda: state.get("token", ""),
            auto_response=auto_response,
        )
        executor.start()
    """

    def __init__(
        self,
        api_client=None,
        token_getter: Optional[Callable[[], str]] = None,
        auto_response=None,
        health_monitor=None,
        cleanup_manager=None,
        ransomware_shield=None,
        service_manager=None,
        on_threat_config_updated: Optional[Callable[[dict], None]] = None,
    ):
        self.api_client = api_client
        self.token_getter = token_getter or (lambda: "")
        self.auto_response = auto_response  # AutoResponse instance
        self.health_monitor = health_monitor  # SystemHealthMonitor (wired after init)
        self.cleanup_manager = cleanup_manager  # DataCleanupManager (wired after init)
        self.ransomware_shield = ransomware_shield
        self.service_manager = service_manager  # ServiceManager — honeypot tunnel cmds
        self.on_threat_config_updated = on_threat_config_updated
        self.network_guard = None  # NetworkGuard — wired after init (≥4.7.0)
        self.threat_intel = None  # ThreatIntelManager — wired after init (WS push)
        self._gui_bump: Optional[Callable[[], None]] = None  # optional STATUS generation bump

        self._running = False
        self._poll_thread: Optional[threading.Thread] = None
        self._next_poll_sleep = POLL_INTERVAL
        self._ir_until = 0.0  # sticky fast-poll window after IR
        self._exec_lock = threading.Lock()
        self._seen_cmd_ids: Dict[str, float] = {}  # command_id → seen_at
        self._seen_lock = threading.Lock()
        self._control_ws = None

        # Remote desktop screen mirror (lazy init)
        self._remote_desktop = None

        # Rate limiting
        self._cmd_timestamps: deque = deque(maxlen=MAX_COMMANDS_PER_MINUTE * 2)

        # Stats (signature_* are local observe counters — not wire fields yet)
        self._stats = {
            "commands_received": 0,
            "commands_executed": 0,
            "commands_failed": 0,
            "commands_rejected": 0,
            "commands_expired": 0,
            "commands_deduped": 0,
            "poll_errors": 0,
            "control_ws": False,
            "signature_ok": 0,
            "signature_missing": 0,
            "signature_invalid": 0,
            "signature_disabled": 0,
            "signature_no_token": 0,
        }

        # Command history (last 50)
        self._history: deque = deque(maxlen=50)

    # ── Lifecycle ─────────────────────────────────────────────────

    def start(self):
        """Start HTTP poll + control WebSocket (push)."""
        if self._running:
            return
        self._running = True
        self._poll_thread = threading.Thread(
            target=self._poll_loop,
            name="RemoteCommands-Poll",
            daemon=True,
        )
        self._poll_thread.start()
        try:
            from client_control_ws import AgentControlWebSocket
            self._control_ws = AgentControlWebSocket(
                api_client=self.api_client,
                token_getter=self.token_getter,
                on_command=lambda cmd: self.handle_incoming_command(cmd, source="ws"),
                on_threat_intel_updated=self._on_threat_intel_updated,
                on_threat_config_updated=self._on_threat_config_updated,
                on_connected=self._drain_offline_urgent_queue,
            )
            self._control_ws.start()
            try:
                from client_presence import configure as configure_presence
                configure_presence(
                    control_ws=self._control_ws,
                    api_client=self.api_client,
                    token_getter=self.token_getter,
                    reconnect_cb=self._control_ws.request_reconnect,
                )
                from client_presence import reset_goodbye_flag
                reset_goodbye_flag()
            except Exception as e:
                log(f"[REMOTE-CMD] presence configure failed: {e}")
        except Exception as e:
            log(f"[REMOTE-CMD] control WS start failed (HTTP poll only): {e}")
            self._control_ws = None
        log(f"[REMOTE-CMD] Remote command executor started "
            f"(poll={POLL_INTERVAL}s, IR={IR_POLL_INTERVAL}s, control_ws=on)")
        # Break-glass: resume a pending autologon after reboot (contract ≥4.6.0)
        threading.Thread(
            target=self._resume_pending_autologon,
            name="RemoteCommands-AutologonResume",
            daemon=True,
        ).start()

    def _resume_pending_autologon(self) -> None:
        """After reboot: if an autologon was armed, wait for the console session,
        clear autologon artifacts (defense beyond AutoLogonCount=1), and report
        completion for the originating remote_logon command."""
        try:
            from client_autologon import (
                read_pending_marker, clear_autologon, clear_pending_marker,
            )
            marker = read_pending_marker()
            if not marker:
                return
            username = str(marker.get("username") or "")
            command_id = str(marker.get("command_id") or "")
            log(f"[AUTOLOGON] pending marker found user={username} cmd={command_id}")

            from client_remote_session import enumerate_sessions_rich
            deadline = time.time() + 180
            session_id = None
            while time.time() < deadline and self._running:
                try:
                    for s in enumerate_sessions_rich():
                        if (str(s.get("username") or "").lower() == username.lower()
                                and int(s.get("session_id") or 0) > 0
                                and str(s.get("status") or "").lower() == "active"):
                            session_id = int(s.get("session_id"))
                            break
                except Exception:
                    pass
                if session_id is not None:
                    break
                time.sleep(3.0)

            # Always clear autologon artifacts once we're done waiting
            clear_autologon()
            clear_pending_marker()

            ready = session_id is not None
            log(f"[AUTOLOGON] resume done ready={ready} session_id={session_id}")
            if command_id:
                fake_cmd = {"command_id": command_id, "command_type": "remote_logon"}
                self._report_result_sync(fake_cmd, {
                    "success": ready,
                    "ok": ready,
                    "status": "completed" if ready else "failed",
                    "username": username,
                    "error": None if ready else "LOGON_TIMEOUT",
                    "data": {
                        "method": "autologon_reboot",
                        "ready_for_stream": ready,
                        "session_id": session_id,
                    },
                })
        except Exception as e:
            log(f"[AUTOLOGON] resume error: {e}")

    def _drain_offline_urgent_queue(self) -> None:
        """OOB-501: drain local spool after control WS reconnect (contract 1.4.7)."""
        try:
            from client_offline_queue import drain_to_cloud, offline_queue_enabled
            if not offline_queue_enabled():
                return
            token = ""
            try:
                token = self.token_getter() if callable(self.token_getter) else ""
            except Exception:
                token = ""
            if not token or not self.api_client:
                return
            out = drain_to_cloud(self.api_client, token)
            attempted = int(out.get("attempted") or 0)
            if attempted:
                log(
                    "[REMOTE-CMD] offline urgent drain "
                    f"attempted={attempted} acked={out.get('acked', 0)} "
                    f"dup={out.get('duplicate', 0)} "
                    f"drop_rej={out.get('dropped_rejected', 0)}"
                )
        except Exception as exc:
            log(f"[REMOTE-CMD] offline urgent drain skip: {exc}")

    def _on_threat_intel_updated(self, data: dict) -> None:
        """Control WS push → sync threat-intel bundle immediately (contract 09)."""
        ti = self.threat_intel
        if ti is None or not hasattr(ti, "sync_once"):
            log("[REMOTE-CMD] threat_intel_updated ignored — ThreatIntelManager not wired")
            return

        def _run():
            try:
                ok = bool(ti.sync_once())
                ver = (data or {}).get("bundle_version") or ""
                log(f"[THREAT-INTEL] WS push sync ok={ok} hint_version={ver}")
            except Exception as e:
                log(f"[THREAT-INTEL] WS push sync error: {e}")

        threading.Thread(target=_run, name="ThreatIntel-WSPush", daemon=True).start()

    def _on_threat_config_updated(self, data: dict) -> None:
        """Control WS push → fetch/apply effective security config immediately."""
        cb = self.on_threat_config_updated
        if not callable(cb):
            log("[REMOTE-CMD] threat_config_updated ignored — callback not wired")
            return
        threading.Thread(
            target=lambda: cb(data or {}),
            name="ThreatConfig-WSPush",
            daemon=True,
        ).start()

    def stop(self, goodbye_reason: Optional[str] = "shutdown"):
        """Stop polling, control WS, and remote desktop stream.

        goodbye_reason: WS/HTTP presence offline signal (None = skip goodbye,
        e.g. transient internal restart). Default shutdown for graceful exits.
        """
        self._running = False
        try:
            if goodbye_reason:
                from client_presence import signal_goodbye
                signal_goodbye(str(goodbye_reason), http_fallback=True, close_after=False)
        except Exception:
            pass
        try:
            if self._control_ws:
                # goodbye already sent via presence module; just close
                self._control_ws.stop()
        except Exception:
            pass
        self._control_ws = None
        try:
            if self._remote_desktop:
                self._remote_desktop.stop(reason="executor_stop")
        except Exception:
            pass
        log("[REMOTE-CMD] ✅ Stopped")

    def get_stats(self) -> dict:
        st = dict(self._stats)
        try:
            if self._control_ws:
                st["control_ws"] = self._control_ws.get_stats()
        except Exception:
            st["control_ws"] = False
        return st

    def get_signing_health(self) -> dict:
        """ZT-600 observe block for health/report (contract 1.4.2).

        observe=True, enforce=False during transition. Counters are local; cloud
        keeps its own coverage. Missing block on cloud side means legacy.
        """
        try:
            from client_security_utils import command_signing_enabled
            enabled = bool(command_signing_enabled())
        except Exception:
            enabled = True
        s = self._stats
        return {
            "observe": enabled,
            "enforce": False,
            "ok": int(s.get("signature_ok", 0) or 0),
            "missing": int(s.get("signature_missing", 0) or 0),
            "invalid": int(s.get("signature_invalid", 0) or 0),
            "no_token": int(s.get("signature_no_token", 0) or 0),
            "disabled": int(s.get("signature_disabled", 0) or 0),
            "last_error": "",
        }

    def get_history(self) -> List[dict]:
        return list(self._history)

    # ── Polling Loop ──────────────────────────────────────────────

    def _poll_loop(self):
        """HTTP pending poll — safety net; primary path is control WS push."""
        while self._running:
            try:
                commands = self._fetch_pending()
                commands, cancelled_starts = self._coalesce_stream_starts(commands)
                for stale in cancelled_starts:
                    self._stats["commands_received"] += 1
                    self._stats["commands_rejected"] += 1
                    cid = stale.get("command_id", "?")
                    log(f"[REMOTE-CMD] ⏭ remote_stream_start cancelled (stale) id={cid}")
                    self._report_result(stale, {
                        "success": False,
                        "error": "SUPERSEDED",
                        "status": "cancelled",
                        "message": "Superseded by a newer remote_stream_start in the same poll batch",
                    })

                commands = self._prioritize_commands(commands)
                saw_ir = False
                need_health_refresh = False
                for cmd in commands:
                    cmd_type = cmd.get("command_type", "")
                    prio = str(cmd.get("priority", "") or "").lower()
                    is_ir = (
                        prio in ("critical", "high", "urgent")
                        or cmd_type in _IR_URGENT_COMMANDS
                    )
                    if is_ir:
                        saw_ir = True
                    outcome = self.handle_incoming_command(cmd, source="poll")
                    if outcome.get("health_refresh"):
                        need_health_refresh = True

                if need_health_refresh:
                    self._async_health_refresh()

                if saw_ir:
                    self._ir_until = time.time() + IR_STICKY_SECONDS

                # WS healthy → slower HTTP safety poll (Faz 1 dual delivery)
                ws_hint = None
                try:
                    if self._control_ws:
                        ws_hint = self._control_ws.poll_interval_hint()
                except Exception:
                    ws_hint = None
                if saw_ir or time.time() < self._ir_until:
                    self._next_poll_sleep = IR_POLL_INTERVAL
                elif ws_hint:
                    self._next_poll_sleep = max(float(ws_hint), float(POLL_INTERVAL))
                else:
                    self._next_poll_sleep = POLL_INTERVAL

            except Exception as e:
                self._stats["poll_errors"] += 1
                log(f"[REMOTE-CMD] Poll error: {e}")

            time.sleep(self._next_poll_sleep)

    def _remember_command_id(self, cmd_id: str) -> bool:
        """Return True if this command_id was already seen (dedup)."""
        if not cmd_id:
            return False
        now = time.time()
        with self._seen_lock:
            # prune > 1h
            stale = [k for k, ts in self._seen_cmd_ids.items() if now - ts > 3600]
            for k in stale:
                self._seen_cmd_ids.pop(k, None)
            if cmd_id in self._seen_cmd_ids:
                return True
            self._seen_cmd_ids[cmd_id] = now
            return False

    def _forget_command_id(self, cmd_id: str) -> None:
        """Allow a later retry (e.g. rate-limit defer without ACK)."""
        if not cmd_id:
            return
        with self._seen_lock:
            self._seen_cmd_ids.pop(cmd_id, None)

    def _bump_gui(self) -> None:
        """Ask GUI STATUS consumers to refresh sooner after local apply."""
        try:
            if callable(self._gui_bump):
                self._gui_bump()
        except Exception:
            pass
        # Health push also refreshes cloud inventory used by dashboard
        try:
            if self.health_monitor and hasattr(self.health_monitor, "force_report"):
                self._async_health_refresh()
        except Exception:
            pass

    def handle_incoming_command(self, cmd: dict, source: str = "poll") -> dict:
        """Shared execute path for HTTP poll and control WS push.

        Returns summary dict: {ok, skipped, health_refresh, ...}
        """
        out = {"ok": False, "skipped": False, "health_refresh": False, "source": source}
        if not isinstance(cmd, dict):
            return out

        cmd_id = str(cmd.get("command_id") or cmd.get("id") or "")
        cmd_type = str(cmd.get("command_type") or cmd.get("type") or "")
        if cmd_type and not cmd.get("command_type"):
            cmd = dict(cmd)
            cmd["command_type"] = cmd_type
        if cmd_id and not cmd.get("command_id"):
            cmd = dict(cmd)
            cmd["command_id"] = cmd_id

        if cmd_id and self._remember_command_id(cmd_id):
            self._stats["commands_deduped"] += 1
            log(f"[REMOTE-CMD] dedup skip {cmd_type} id={cmd_id} source={source}")
            out["skipped"] = True
            return out

        # Serialize execute so poll + WS never overlap
        with self._exec_lock:
            return self._run_one_command_locked(cmd, source)

    def _run_one_command_locked(self, cmd: dict, source: str) -> dict:
        out = {"ok": False, "skipped": False, "health_refresh": False, "source": source}
        self._stats["commands_received"] += 1
        cmd_id = str(cmd.get("command_id") or "")
        cmd_type = cmd.get("command_type", "")
        prio = str(cmd.get("priority", "") or "").lower()
        is_ir = (
            prio in ("critical", "high", "urgent")
            or cmd_type in _IR_URGENT_COMMANDS
        )

        # Optional quick ack on WS before validate/execute
        try:
            cid = cmd.get("command_id", "")
            if cid and self._control_ws and self._control_ws.connected:
                self._control_ws.send_ack(str(cid), state="received")
        except Exception:
            pass

        rejection = self._validate(cmd)
        if rejection:
            log(f"[REMOTE-CMD] ❌ Rejected: {cmd.get('command_type', '?')} — {rejection} ({source})")
            self._stats["commands_rejected"] += 1
            self._report_result(cmd, {
                "success": False,
                "error": rejection,
                "status": "rejected",
            })
            return out

        if (cmd_type not in _STREAM_COMMANDS
                and cmd_type not in _IR_URGENT_COMMANDS
                and not self._check_rate_limit()):
            # Do NOT leave the id in the seen-cache without an ACK — that permanently
            # sticks the dashboard command in pending until process restart.
            self._forget_command_id(cmd_id)
            log(f"[REMOTE-CMD] ⚠️ Rate limit — deferring id={cmd_id or '?'} ({source})")
            self._stats["commands_rejected"] += 1
            out["skipped"] = True
            return out

        if cmd_type == "self_update":
            self._report_result_sync(cmd, {
                "success": True,
                "ok": True,
                "status": "running",
                "message": "update_accepted",
                "detail": "download_starting",
            })
            self._ir_until = time.time() + IR_STICKY_SECONDS
            try:
                params = cmd.get("parameters") or cmd.get("params") or {}
                from client_update_ui import set_update_ui_status
                from client_constants import VERSION as _cur_ver
                tag = ""
                try:
                    tag = str(params.get("tag") or params.get("version") or "").strip()
                    if tag.lower().startswith("v"):
                        tag = tag[1:]
                except Exception:
                    tag = ""
                set_update_ui_status(
                    "accepted",
                    from_version=str(_cur_ver),
                    to_version=tag,
                    detail="update_accepted",
                )
            except Exception:
                pass

        self._current_cmd = cmd
        try:
            result = self._execute(cmd)
        finally:
            self._current_cmd = None

        if cmd_type not in _STREAM_COMMANDS and cmd_type not in _IR_URGENT_COMMANDS:
            self._cmd_timestamps.append(time.time())
        hist_params = dict(cmd.get("parameters") or cmd.get("params") or {})
        # Never persist one-shot passwords in in-memory history
        for k in ("password", "new_password", "pass", "pwd"):
            if k in hist_params:
                hist_params[k] = "***"
        self._history.append({
            "command_type": cmd.get("command_type", ""),
            "command_id": cmd.get("command_id", ""),
            "parameters": hist_params,
            "result": result,
            "executed_at": time.time(),
            "source": source,
        })

        if result.get("success"):
            self._stats["commands_executed"] += 1
            out["ok"] = True
            if cmd_type != "remote_input":
                log(f"[REMOTE-CMD] ✅ {cmd['command_type']} — {result.get('message', 'OK')} ({source})")
            if cmd_type in (
                "kill_process", "block_process", "suspend_process", "resume_process",
                "allow_process", "isolate_host", "lift_isolation",
                "logoff_user", "contain_user",
                "reset_password", "disable_account", "enable_account",
                "disable_all_users", "create_user",
                "stop_service", "start_service", "restart_service", "disable_service",
                "tunnel_start", "tunnel_stop",
                "emergency_lockdown",
                "block_ip", "unblock_ip", "clear_firewall",
            ):
                out["health_refresh"] = True
                try:
                    self._refresh_inventory_after_mutate(cmd_type)
                except Exception:
                    pass
                self._bump_gui()
        else:
            self._stats["commands_failed"] += 1
            log(f"[REMOTE-CMD] ❌ {cmd['command_type']} — {result.get('error', 'Failed')} ({source})")

        if result.get("restart_required") and cmd_type == "self_update":
            self._report_result_sync(cmd, result)
            log("[REMOTE-CMD] self_update — exiting for installer helper")
            time.sleep(1.2)
            try:
                from client_self_protection import disarm_for_update
                disarm_for_update(reason="dashboard_self_update")
            except Exception:
                pass
            os._exit(0)
        elif is_ir:
            self._report_result_sync(cmd, result)
        else:
            self._report_result(cmd, result)

        if is_ir:
            self._ir_until = time.time() + IR_STICKY_SECONDS
        return out

    @staticmethod
    def _coalesce_stream_starts(commands: List[dict]) -> tuple:
        """Keep only the newest remote_stream_start; return (kept, cancelled).

        Dashboard may queue multiple Start clicks. Applying all would thrash
        capture/WS — keep the last in the batch (API typically oldest→newest).
        """
        if not commands:
            return [], []
        starts = [c for c in commands if c.get("command_type") == "remote_stream_start"]
        if len(starts) <= 1:
            return list(commands), []

        def _start_key(cmd: dict):
            # Prefer explicit timestamps / ids when present
            for key in ("created_at", "created", "queued_at", "timestamp"):
                val = cmd.get(key)
                if val:
                    return (1, str(val))
            cid = cmd.get("command_id") or cmd.get("id") or ""
            return (0, str(cid))

        keep = max(starts, key=_start_key)
        # If keys tie, fall back to last occurrence in list (newest enqueue order)
        if sum(1 for s in starts if _start_key(s) == _start_key(keep)) > 1:
            keep = starts[-1]

        keep_id = keep.get("command_id") or keep.get("id")
        cancelled = []
        kept = []
        for cmd in commands:
            if cmd.get("command_type") != "remote_stream_start":
                kept.append(cmd)
                continue
            cid = cmd.get("command_id") or cmd.get("id")
            if keep_id and cid == keep_id:
                kept.append(cmd)
            elif not keep_id and cmd is keep:
                kept.append(cmd)
            else:
                cancelled.append(cmd)
        return kept, cancelled

    @staticmethod
    def _prioritize_commands(commands: List[dict]) -> List[dict]:
        """Run kill/logoff/block before list/snapshot in the same poll."""
        if not commands or len(commands) < 2:
            return commands

        def _rank(cmd: dict) -> int:
            ct = cmd.get("command_type", "")
            prio = str(cmd.get("priority", "") or "").lower()
            if ct in ("kill_process", "logoff_user", "contain_user",
                      "emergency_lockdown", "self_update", "disable_all_users"):
                return 0
            if ct in ("reset_password", "disable_account"):
                return 0  # same urgency as logoff — breach containment
            if ct in _IR_URGENT_COMMANDS or prio in ("critical", "high", "urgent"):
                return 1
            # Stream start before generic diagnostics so remote opens quickly
            if ct == "remote_stream_start":
                return 1
            if ct in _STREAM_COMMANDS:
                return 2
            return 3

        return sorted(commands, key=_rank)

    def _async_health_refresh(self) -> None:
        """Push sessions/processes after IR — never block kill/logoff path."""
        hm = self.health_monitor
        if not hm or not hasattr(hm, "force_report"):
            return

        def _run():
            try:
                hm.force_report(refresh=True)
            except Exception as e:
                log(f"[REMOTE-CMD] health refresh after IR failed: {e}")

        threading.Thread(target=_run, name="RemoteCmd-HealthRefresh", daemon=True).start()

    # ── API Communication ─────────────────────────────────────────

    def _fetch_pending(self) -> List[dict]:
        """GET /api/commands/pending"""
        if not self.api_client:
            return []
        token = self.token_getter()
        if not token:
            return []

        try:
            resp = self.api_client.api_request(
                "GET", "commands/pending",
                token=token,
                timeout=3,
            )
            if isinstance(resp, list):
                return [c for c in resp if isinstance(c, dict)]
            if isinstance(resp, dict):
                for key in ("commands", "pending", "items", "data"):
                    val = resp.get(key)
                    if isinstance(val, list):
                        return [c for c in val if isinstance(c, dict)]
                    if isinstance(val, dict) and isinstance(val.get("commands"), list):
                        return [c for c in val["commands"] if isinstance(c, dict)]
        except Exception as e:
            self._stats["poll_errors"] += 1
            log(f"[REMOTE-CMD] pending fetch error: {e}")
        return []

    def _report_result(self, cmd: dict, result: dict):
        """POST /api/commands/result"""
        if not self.api_client:
            return
        token = self.token_getter()
        if not token:
            return

        def _send():
            try:
                self._post_command_result(cmd, result, token)
            except Exception as e:
                log(f"[REMOTE-CMD] Result report error: {e}")

        threading.Thread(target=_send, daemon=True).start()

    def _report_result_sync(self, cmd: dict, result: dict, timeout: float = 8.0):
        """Synchronous result report (needed before process exit on self_update)."""
        if not self.api_client:
            return
        token = self.token_getter()
        if not token:
            return
        try:
            self._post_command_result(cmd, result, token)
        except Exception as e:
            log(f"[REMOTE-CMD] Sync result report error: {e}")

    def _post_command_result(self, cmd: dict, result: dict, token: str):
        cmd_id = cmd.get("command_id", "")
        cmd_type = cmd.get("command_type", "")
        executed_at = datetime.now(timezone.utc).isoformat()
        # Lifecycle only — never forward SAM active/disabled as command status
        try:
            from client_brick_guard import lifecycle_status_from_result

            status = lifecycle_status_from_result(result)
        except Exception:
            status = (
                "completed"
                if (result.get("success") or result.get("ok"))
                else "failed"
            )
        # Prefer prompt-shaped payload fields inside result
        payload = {
            "token": token,
            "command_id": cmd_id,
            "status": status,
            "result": result,
            "executed_at": executed_at,
            "execution_time_ms": result.get("execution_time_ms", 0),
            "signature": sign_command(token, cmd_id, cmd_type, executed_at),
        }
        if result.get("error") and status == "failed":
            payload["error"] = result.get("error")

        # Dual-send: control WS (fast UI) + HTTP (durable)
        try:
            if self._control_ws and self._control_ws.connected:
                self._control_ws.send_command_result(
                    command_id=str(cmd_id or ""),
                    command_type=str(cmd_type or ""),
                    status=str(status),
                    result=result,
                    executed_at=executed_at,
                    signature=str(payload.get("signature") or ""),
                )
        except Exception:
            pass

        self.api_client.api_request("POST", "commands/result", data=payload)

    # ── Validation ────────────────────────────────────────────────

    def _validate(self, cmd: dict) -> Optional[str]:
        """
        Validate command. Returns rejection reason or None if valid.
        """
        # 0. HMAC signature — observe always; reject only invalid (ZT-600)
        token = self.token_getter() or ""
        verdict = inspect_command_signature(token, cmd)
        stat_key = {
            "ok": "signature_ok",
            "missing": "signature_missing",
            "invalid": "signature_invalid",
            "disabled": "signature_disabled",
            "no_token": "signature_no_token",
        }.get(verdict)
        if stat_key:
            self._stats[stat_key] = int(self._stats.get(stat_key, 0) or 0) + 1
        if verdict in ("missing", "invalid", "no_token", "disabled"):
            cmd_id = str(cmd.get("command_id") or cmd.get("id") or "?")
            cmd_type_obs = str(
                cmd.get("command_type") or cmd.get("type") or cmd.get("command") or "?"
            )
            log(
                f"[REMOTE-CMD] signature observe "
                f"verdict={verdict} type={cmd_type_obs} id={cmd_id}"
            )
        if verdict == "invalid":
            return "Invalid command signature"

        cmd_type = cmd.get("command_type", "")

        # 1. Known command?
        if cmd_type not in ALLOWED_COMMANDS:
            return f"Unknown command: {cmd_type}"

        # 2. Expired?
        # Prefer cloud expires_at when present (self_update TTL = 30 min)
        expires_at = cmd.get("expires_at") or ""
        if expires_at:
            try:
                exp = datetime.fromisoformat(str(expires_at).replace("Z", "+00:00"))
                if datetime.now(timezone.utc) > exp:
                    self._stats["commands_expired"] += 1
                    return "Command expired (past expires_at)"
            except (ValueError, TypeError):
                pass
        else:
            issued_at = cmd.get("issued_at") or cmd.get("requested_at") or cmd.get("created_at") or ""
            if issued_at:
                try:
                    issued = datetime.fromisoformat(issued_at.replace("Z", "+00:00"))
                    age = (datetime.now(timezone.utc) - issued).total_seconds()
                    max_age = (
                        SELF_UPDATE_EXPIRY_SECONDS
                        if cmd_type in ("self_update", "check_update")
                        else COMMAND_EXPIRY_SECONDS
                    )
                    if age > max_age:
                        self._stats["commands_expired"] += 1
                        return f"Command expired ({int(age)}s old, max {max_age}s)"
                except (ValueError, TypeError):
                    pass

        # 3. Protected target checks — accept both "parameters" and "params"
        params = cmd.get("parameters") or cmd.get("params") or {}

        # Account mutate / IR — block only OS machine identities (SYSTEM etc.).
        # Administrator/Guest/any real user MUST be containable during breach.
        if cmd_type in ("disable_account", "enable_account", "reset_password", "contain_user"):
            username = params.get("username", "")
            sam = self._sam_account_name(username).upper()
            if sam in PROTECTED_ACCOUNTS:
                return f"Protected account: {username}"

        # reset_password / contain_user: dashboard MUST send new_password (≥8)
        if cmd_type in ("reset_password", "contain_user"):
            new_pass = params.get("new_password")
            if new_pass is None or str(new_pass).strip() == "":
                return "missing_password"
            if len(str(new_pass)) < 8:
                return "password_too_short"

        # Disaster recovery: create_user / remote_logon / set_autologon need creds
        if cmd_type in ("create_user", "remote_logon", "set_autologon"):
            username = self._sam_account_name(params.get("username", ""))
            if not username:
                return "missing_username"
            if self._account_key(username) in {
                self._account_key(x) for x in PROTECTED_ACCOUNTS
            }:
                return f"Protected account: {username}"
            pwd = params.get("password")
            # set_autologon may reuse an existing session's stored creds → password optional
            if cmd_type in ("create_user", "remote_logon"):
                if pwd is None or str(pwd).strip() == "":
                    return "missing_password"
                if len(str(pwd)) < 1:
                    return "password_too_short"

        # Dashboard PIN set: 4-12 digits (same rule as local GuiLock)
        if cmd_type == "set_gui_pin":
            pin = str(params.get("pin") or "").strip()
            if not pin:
                return "missing_pin"
            if not pin.isdigit() or not (4 <= len(pin) <= 12):
                return "invalid_pin_format"

        if cmd_type == "logoff_user":
            sid = params.get("session_id")
            if sid is not None and str(sid).strip() == "0":
                return "Cannot logoff session 0 (services)"

        if cmd_type in ("kill_process", "suspend_process", "resume_process"):
            pname = params.get("process_name", "").lower()
            if pname in PROTECTED_PROCESSES:
                return f"Protected process: {pname}"
        if cmd_type in ("suspend_process", "resume_process"):
            if params.get("pid") is None:
                return "missing_pid"
            if not (params.get("expected_image") or params.get("process_name")):
                return "missing_expected_image"
            if params.get("process_start_time") is None:
                return "missing_process_start_time"

        if cmd_type in ("stop_service", "disable_service"):
            sname = params.get("service_name", "").lower()
            if sname in PROTECTED_SERVICES:
                return f"Protected service: {sname}"

        return None

    # ── Rate Limiting ─────────────────────────────────────────────

    def _check_rate_limit(self) -> bool:
        now = time.time()
        minute_ago = now - 60
        recent = [t for t in self._cmd_timestamps if t >= minute_ago]
        return len(recent) < MAX_COMMANDS_PER_MINUTE

    # ── Command Execution ─────────────────────────────────────────

    def _execute(self, cmd: dict) -> dict:
        """Route to the appropriate handler."""
        cmd_type = cmd.get("command_type", "")
        # API may send "params" or "parameters" — accept both
        params = cmd.get("parameters") or cmd.get("params") or {}

        handler = getattr(self, f"_cmd_{cmd_type}", None)
        if handler:
            try:
                start_ms = time.monotonic()
                result = handler(params)
                elapsed_ms = int((time.monotonic() - start_ms) * 1000)
                result["execution_time_ms"] = elapsed_ms
                return result
            except Exception as e:
                return {"success": False, "error": str(e)}

        return {"success": False, "error": f"No handler for: {cmd_type}"}

    def _refresh_inventory_after_mutate(self, cmd_type: str) -> None:
        """Best-effort health refresh so dashboard poll sees fresh sessions/processes."""
        if cmd_type in (
            "stop_service", "start_service", "restart_service", "disable_service",
        ):
            # Services are cached from list_services results, not health.
            return
        hm = self.health_monitor
        if hm is None or not hasattr(hm, "force_report"):
            return

        def _run():
            try:
                hm.force_report(refresh=True)
            except Exception as exc:
                log(f"[REMOTE-CMD] post-mutate health refresh: {exc}")

        threading.Thread(
            target=_run, name="ServerMgmt-InventoryRefresh", daemon=True
        ).start()

    def get_remote_desktop_status(self) -> dict:
        """UI / diagnostics — lazy-init streamer status without starting stream."""
        try:
            rd = self._get_remote_desktop()
            st = rd.get_status()
            st["ready"] = True
            st["controlled_by"] = "dashboard"
            return st
        except Exception as e:
            return {
                "ready": False,
                "streaming": False,
                "error": str(e),
                "controlled_by": "dashboard",
            }

    def stop_remote_desktop_local(self, reason: str = "local_ui") -> dict:
        """Emergency stop from tray UI (if stream active)."""
        try:
            if not self._remote_desktop:
                return {"success": True, "message": "not streaming"}
            return self._remote_desktop.stop(reason=reason)
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _get_remote_desktop(self):
        if self._remote_desktop is None:
            from client_remote_desktop import RemoteDesktopStreamer
            self._remote_desktop = RemoteDesktopStreamer(
                api_client=self.api_client,
                token_getter=self.token_getter,
            )
        return self._remote_desktop

    def _cmd_remote_stream_start(self, params: dict) -> dict:
        rd = self._get_remote_desktop()
        sid = params.get("session_id")
        try:
            sid = int(sid) if sid is not None and str(sid).strip() != "" else None
        except (TypeError, ValueError):
            sid = None
        mon = params.get("monitor", 0)
        try:
            mon = int(mon) if mon is not None else 0
        except (TypeError, ValueError):
            mon = 0
        result = rd.start(
            fps=float(params.get("fps", 6.0) or 6.0),
            quality=int(params.get("quality", 35) or 35),
            max_width=int(params.get("max_width", 1280) or 1280),
            session_id=sid,
            username=(params.get("username") or None),
            monitor=mon,
            prefer=(params.get("prefer") or None),
            desktop=(params.get("desktop") or None),
            pre_logon=(
                bool(params.get("pre_logon"))
                if params.get("pre_logon") is not None
                else None
            ),
        )
        if result.get("success"):
            self._notify_remote_desktop_ui("started")
        else:
            log(f"[REMOTE-DESKTOP] start rejected: {result.get('error')} {result.get('message')}")
            self._notify_remote_desktop_ui("failed")
        return result

    def _cmd_remote_stream_stop(self, params: dict) -> dict:
        rd = self._get_remote_desktop()
        result = rd.stop(reason="command")
        self._notify_remote_desktop_ui("stopped")
        return result

    def _notify_remote_desktop_ui(self, event: str) -> None:
        """Best-effort tray toast + GUI refresh hook."""
        try:
            cb = getattr(self, "on_remote_desktop_event", None)
            if callable(cb):
                cb(event)
        except Exception:
            pass
        try:
            # Tray balloon if wired via alert pipeline later
            log(f"[REMOTE-DESKTOP] UI event: {event}")
        except Exception:
            pass

    def _cmd_remote_input(self, params: dict) -> dict:
        rd = self._get_remote_desktop()
        return rd.apply_input(params or {})

    def _cmd_remote_send_sas(self, params: dict) -> dict:
        """Ctrl+Alt+Del Secure Attention Sequence via SendSAS (sas.dll)."""
        session_id = params.get("session_id")
        try:
            ok, detail = self._send_sas(session_id=session_id)
            if ok:
                return {
                    "success": True,
                    "message": "SendSAS ok",
                    "data": {"session_id": session_id, "detail": detail},
                }
            return {
                "success": False,
                "error": "SEND_SAS_FAILED",
                "message": detail or "SendSAS failed",
                "data": {"session_id": session_id},
            }
        except Exception as e:
            log(f"[REMOTE-CMD] remote_send_sas error: {e}")
            return {"success": False, "error": str(e), "message": str(e)}

    def _cmd_list_local_users(self, params: dict) -> dict:
        from client_remote_session import list_local_users
        # Server Management / cloud always want the full SAM inventory.
        include_disabled = bool(params.get("include_disabled", True))
        try:
            users = list_local_users(include_disabled=include_disabled)
            enabled_n = sum(1 for u in users if u.get("enabled"))
            disabled_n = len(users) - enabled_n
            return {
                "success": True,
                "message": (
                    f"{len(users)} local user(s) "
                    f"(active={enabled_n}, disabled={disabled_n})"
                ),
                "data": {
                    "users": users,
                    "include_disabled": include_disabled,
                    "counts": {
                        "total": len(users),
                        "active": enabled_n,
                        "disabled": disabled_n,
                    },
                },
            }
        except Exception as e:
            return {"success": False, "error": str(e), "message": str(e)}

    def _cmd_remote_session_prepare(self, params: dict) -> dict:
        """Activate/unlock user desktop before remote_stream_start."""
        from client_remote_session import prepare_remote_session

        username = (params.get("username") or "").strip()
        password = params.get("password")
        if password is None:
            password = ""
        else:
            password = str(password)
        sid = params.get("session_id")
        try:
            sid = int(sid) if sid is not None and str(sid).strip() != "" else None
        except (TypeError, ValueError):
            sid = None
        prefer = str(params.get("prefer") or "existing_then_logon")
        try:
            timeout_sec = float(params.get("timeout_sec") or 45)
        except (TypeError, ValueError):
            timeout_sec = 45.0

        # Mid-flight running reports (no password in payload)
        parent_cmd = getattr(self, "_current_cmd", None)

        def _progress(phase: str, msg: str = ""):
            if not parent_cmd:
                return
            try:
                self._report_result_sync(parent_cmd, {
                    "success": True,
                    "ok": True,
                    "status": "running",
                    "message": phase,
                    "data": {
                        "username": username,
                        "phase": phase,
                        "detail": (msg or "")[:120],
                        "session_id": sid,
                    },
                })
            except Exception:
                pass

        try:
            return prepare_remote_session(
                username=username,
                password=password,
                session_id=sid,
                prefer=prefer,
                timeout_sec=timeout_sec,
                progress_cb=_progress,
            )
        finally:
            # Best-effort: drop local reference (str immutable; avoid lingering copies in frames)
            password = ""
            try:
                params.pop("password", None)
            except Exception:
                pass

    def _cmd_remote_session_logoff(self, params: dict) -> dict:
        """Logoff by session_id or username — same IR path as logoff_user."""
        return self._cmd_logoff_user(params)

    @staticmethod
    def _send_sas(session_id=None) -> tuple:
        """Call SendSAS(FALSE) from sas.dll. Requires elevated / SYSTEM often.

        Returns (ok, detail_message).
        """
        import ctypes
        from ctypes import wintypes

        # Prefer documented API: BOOL SendSAS(BOOL AsUser);
        # AsUser=FALSE → simulate CAD for current session context
        try:
            sas = ctypes.WinDLL("sas.dll")
        except OSError as e:
            return False, f"sas.dll not loadable: {e}"

        try:
            SendSAS = sas.SendSAS
            SendSAS.argtypes = [wintypes.BOOL]
            SendSAS.restype = None  # void
        except AttributeError:
            return False, "sas.dll has no SendSAS export"

        try:
            # FALSE = not AsUser — standard remote CAD path for services
            SendSAS(0)
            log(f"[REMOTE-CMD] SendSAS(0) invoked session_id={session_id}")
            return True, "SendSAS(0) called"
        except Exception as e:
            return False, f"SendSAS raised: {e}"

    # ── Command Handlers ──────────────────────────────────────────

    def _cmd_block_ip(self, params: dict) -> dict:
        ip = params.get("ip", "")
        if not ip:
            return {"success": False, "error": "No IP specified"}
        duration = params.get("duration_hours", 24)
        reason = params.get("reason", "Remote command")

        if self.auto_response:
            ok = self.auto_response.block_ip(ip, reason=reason, duration_hours=duration)
            return {"success": ok, "message": f"IP {ip} blocked for {duration}h"}

        # Fallback: direct netsh
        return self._netsh_block(ip, f"AR-BLOCK-{ip}")

    def _cmd_unblock_ip(self, params: dict) -> dict:
        ip = params.get("ip", "")
        if not ip:
            return {"success": False, "error": "No IP specified"}
        # Same delete path as pending-unblocks (all rule-name variants + ACK)
        if self.auto_response:
            ok = self.auto_response.unblock_ip(ip)
            return {"success": ok, "message": f"IP {ip} unblocked"}
        try:
            from client_firewall import WindowsFirewallBackend, make_logger
            backend = WindowsFirewallBackend(logger=make_logger())
            ok = backend.remove_block("", ip_or_cidr=ip)
            return {"success": ok, "message": f"IP {ip} unblocked (direct)"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _cmd_clear_firewall(self, params: dict) -> dict:
        """Dashboard maintenance: wipe AR rules and all HP/HONEYPOT legacy names.

        params:
          wipe_all_honeypot_rules: bool (default True)
          wipe_prefixes: optional AR/HP/HONEYPOT prefix list (treated as wipe)
          ips: optional list — also delete known name templates per IP
          reason: audit string
        """
        wipe_all = params.get("wipe_all_honeypot_rules", True)
        if wipe_all is None:
            wipe_all = True
        wipe_prefixes = params.get("wipe_prefixes") or []
        if isinstance(wipe_prefixes, list) and wipe_prefixes:
            wipe_all = True
        ips = params.get("ips") or []
        if not isinstance(ips, list):
            ips = []
        reason = params.get("reason") or "dashboard_firewall_cleanup"
        rules_removed = 0
        auto_cleared = 0
        api_synced = False
        extras_removed = 0
        wiped = False

        # Prefer shared cleanup manager (local cache + sync-rules + clear-data blocks)
        cm = self.cleanup_manager
        if wipe_all and cm and hasattr(cm, "clear_firewall"):
            try:
                out = cm.clear_firewall(sync_dashboard=True)
                rules_removed = int(out.get("rules_removed") or 0)
                auto_cleared = int(out.get("auto_blocks_cleared") or 0)
                api_synced = bool(out.get("api_synced"))
                wiped = True
            except Exception as e:
                log(f"[REMOTE-CMD] clear_firewall via cleanup_manager failed: {e}")

        if wipe_all and not wiped:
            # Direct purge if manager missing / failed
            try:
                from client_firewall import WindowsFirewallBackend, make_logger, is_windows
                if is_windows():
                    backend = WindowsFirewallBackend(logger=make_logger())
                    rules = backend.scan_existing_rules()
                    for r in rules:
                        name = r.get("name") or ""
                        if not name:
                            continue
                        st, _, _, _ = backend._delete_rule_by_name(name)
                        if st == "removed":
                            rules_removed += 1
                    if self.auto_response and hasattr(self.auto_response, "clear_all_blocks"):
                        auto_cleared = self.auto_response.clear_all_blocks()
                    elif self.auto_response and hasattr(self.auto_response, "_blocks"):
                        with self.auto_response._lock:
                            auto_cleared = len(self.auto_response._blocks)
                            self.auto_response._blocks.clear()
                    token = self.token_getter()
                    if token and self.api_client and hasattr(self.api_client, "sync_firewall_rules"):
                        api_synced = bool(self.api_client.sync_firewall_rules(token, []))
                    if token and self.api_client and hasattr(self.api_client, "clear_client_data"):
                        try:
                            self.api_client.clear_client_data(
                                token, scopes=["blocks"], reason=reason,
                            )
                        except Exception:
                            pass
            except Exception as e:
                return {"success": False, "error": str(e), "rules_removed": rules_removed}

        # Backup: delete known name templates for each IP in params
        if ips:
            try:
                from client_firewall import WindowsFirewallBackend, make_logger, is_windows
                if is_windows():
                    backend = WindowsFirewallBackend(logger=make_logger())
                    for ip in ips:
                        ip = str(ip or "").strip().split("/")[0]
                        if not ip:
                            continue
                        for name in WindowsFirewallBackend.rule_name_candidates("", ip):
                            st, _, _, _ = backend._delete_rule_by_name(name)
                            if st == "removed":
                                extras_removed += 1
                        if self.auto_response and hasattr(self.auto_response, "unblock_ip"):
                            try:
                                self.auto_response.unblock_ip(ip)
                            except Exception:
                                pass
            except Exception as e:
                log(f"[REMOTE-CMD] clear_firewall per-IP backup error: {e}")

        total = rules_removed + extras_removed
        return {
            "success": True,
            "status": "completed",
            "message": f"Firewall honeypot rules cleared ({total} removed)",
            "rules_removed": total,
            "auto_blocks_cleared": auto_cleared,
            "api_synced": api_synced,
            "reason": reason,
            "wipe_all": bool(wipe_all),
            "ips_requested": len(ips),
        }

    def _cmd_migrate_firewall_brand(self, params: dict) -> dict:
        """Force the idempotent HP→AR migration and snapshot sync."""
        token = self.token_getter()
        base = str(getattr(self.api_client, "base_url", "") or "").rstrip("/")
        if base.lower().endswith("/api"):
            base = base[:-4]
        if not token or not base:
            return {"success": False, "error": "missing_token_or_api_base"}
        try:
            from client_firewall import (
                FirewallAgent,
                _firewall_brand_state_path,
                make_logger,
            )
            marker = _firewall_brand_state_path()
            try:
                marker.unlink()
            except FileNotFoundError:
                pass
            agent = FirewallAgent(
                api_base=base,
                token=token,
                logger=make_logger(),
                auto_response=self.auto_response,
            )
            agent._migrate_and_sync_rules()
            migrated = False
            try:
                migrated = marker.exists()
            except OSError:
                pass
            return {
                "success": migrated,
                "message": "Firewall brand migration completed" if migrated
                else "Migration/sync incomplete; will retry at boot",
                "firewall_brand": "ar" if migrated else "pending",
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _cmd_logoff_user(self, params: dict) -> dict:
        """Terminate session(s) immediately — any account including Administrator."""
        t0 = time.time()
        username = (params.get("username") or "").strip()
        session_id = params.get("session_id")
        if session_id is not None and str(session_id).strip().isdigit():
            result = self._terminate_session_id(str(session_id).strip())
        elif not username:
            result = {"success": False, "error": "No username or session_id specified"}
        else:
            # Single thorough path (query user + session, logoff + reset)
            result = self._logoff_direct(username)
        result["execution_time_ms"] = int((time.time() - t0) * 1000)
        return result

    def _cmd_contain_user(self, params: dict) -> dict:
        """
        Breach containment in one command:
          1) logoff all sessions
          2) apply dashboard-supplied new_password (required)
          3) optionally disable account (default True)
        Password is never echoed in result — dashboard already knows it.
        """
        t0 = time.time()
        username = (params.get("username") or "").strip()
        if not username:
            return {"success": False, "ok": False, "error": "No username specified"}

        new_pass = params.get("new_password")
        if new_pass is None or str(new_pass).strip() == "":
            return {
                "success": False,
                "ok": False,
                "error": "missing_password",
                "username": self._sam_account_name(username),
            }
        if len(str(new_pass)) < 8:
            return {
                "success": False,
                "ok": False,
                "error": "password_too_short",
                "username": self._sam_account_name(username),
            }

        disable = params.get("disable")
        if disable is None:
            disable = True
        disable = bool(disable)

        session_id = params.get("session_id")
        if session_id is not None and str(session_id).strip().isdigit():
            logoff = self._terminate_session_id(str(session_id).strip())
        else:
            logoff = self._logoff_direct(username)
            if not logoff.get("success") and "No live session" in str(logoff.get("error") or ""):
                logoff = {
                    "success": True,
                    "ok": True,
                    "message": "no live session (password reset still applied)",
                    "skipped": True,
                }

        reset = self._cmd_reset_password({
            "username": username,
            "new_password": new_pass,
        })

        disabled = {"success": True, "ok": True, "skipped": True, "message": "disable skipped"}
        if disable:
            disabled = self._cmd_disable_account({"username": username})

        ok = bool(reset.get("ok") or reset.get("success")) and (
            bool(logoff.get("success")) or logoff.get("skipped")
        )
        if disable and not (disabled.get("ok") or disabled.get("success")):
            ok = False

        sam = self._sam_account_name(username)
        return {
            "success": ok,
            "ok": ok,
            "username": sam,
            "message": (
                f"Contained {sam}: logoff + password reset"
                + (" + disabled" if disable else "")
            ),
            "logoff": logoff,
            "password_reset": {
                "ok": bool(reset.get("ok") or reset.get("success")),
                "error": reset.get("error"),
            },
            "account_disabled": disabled,
            "execution_time_ms": int((time.time() - t0) * 1000),
            "error": None if ok else (
                reset.get("error")
                or disabled.get("error")
                or logoff.get("error")
                or "contain_user failed"
            ),
        }

    def _account_mutate_result(
        self, username: str, *, want_enabled: bool, ok: bool, action: str
    ) -> dict:
        """Shared enable/disable result with refreshed user row for cloud UI.

        Wire: SAM ``active``/``disabled`` lives only under ``data`` — never as
        top-level ``status`` (that field is reserved for completed/failed…).
        """
        from client_remote_session import find_local_user
        from client_brick_guard import sam_account_status

        user = None
        try:
            user = find_local_user(username, include_disabled=True)
        except Exception:
            user = None
        enabled = bool(user.get("enabled")) if isinstance(user, dict) else want_enabled if ok else None
        account_status = sam_account_status(enabled)
        err = None
        if not ok:
            try:
                from client_auto_response import PROTECTED_ACCOUNTS
                if username.upper() in PROTECTED_ACCOUNTS:
                    err = "PROTECTED_ACCOUNT"
            except Exception:
                pass
            if not err and self.auto_response is not None:
                last = getattr(self.auto_response, "_last_disable_error", None)
                if last and action == "disabled":
                    err = str(last)
            err = err or f"Failed to {action} {username}"
        return {
            "success": ok,
            "ok": ok,
            "username": username,
            "enabled": enabled,
            "message": (
                f"Account {username} {action}"
                if ok
                else (err or f"Failed to {action} {username}")
            ),
            "error": None if ok else err,
            "data": {
                "username": username,
                "enabled": enabled,
                "status": account_status,
                "account_status": account_status,
                "user": user,
            },
        }

    def _cmd_disable_account(self, params: dict) -> dict:
        username = self._sam_account_name(params.get("username", ""))
        if not username:
            return {"success": False, "ok": False, "error": "No username specified"}
        if self.auto_response:
            ok = self.auto_response.disable_account(username, allow_privileged=True)
        else:
            raw = self._run_net_user(username, "/active:no", "disabled")
            ok = bool(raw.get("ok") or raw.get("success"))
        return self._account_mutate_result(
            username, want_enabled=False, ok=ok, action="disabled"
        )

    def _cmd_enable_account(self, params: dict) -> dict:
        username = self._sam_account_name(params.get("username", ""))
        if not username:
            return {"success": False, "ok": False, "error": "No username specified"}
        if self.auto_response:
            ok = self.auto_response.enable_account(username)
        else:
            raw = self._run_net_user(username, "/active:yes", "enabled")
            ok = bool(raw.get("ok") or raw.get("success"))
        return self._account_mutate_result(
            username, want_enabled=True, ok=ok, action="enabled"
        )

    def _cmd_disable_all_users(self, params: dict) -> dict:
        """
        Panic IR — AGENT_DISABLE_ALL_USERS_PROMPT (unified cloud+agent).

        params:
          logoff: bool (default True) — also accept logoff_sessions alias
          exclude: string|string[] — break-glass (never disable)
        Administrator IS disabled unless listed in exclude.
        """
        global _disable_all_busy
        t0 = time.time()

        if not _disable_all_lock.acquire(blocking=False):
            return {
                "success": False,
                "ok": False,
                "status": "failed",
                "error": "busy",
                "detail": "disable_all_users_already_running",
                "disabled": [],
                "skipped": [],
                "failed": [],
                "logged_off": [],
            }
        _disable_all_busy = True

        try:
            return self._disable_all_users_locked(params, t0)
        finally:
            _disable_all_busy = False
            try:
                _disable_all_lock.release()
            except Exception:
                pass

    def _disable_all_users_locked(self, params: dict, t0: float) -> dict:
        do_logoff = params.get("logoff")
        if do_logoff is None:
            do_logoff = params.get("logoff_sessions")
        if do_logoff is None:
            do_logoff = True
        do_logoff = bool(do_logoff)

        # Hard skip: OS / virtual only (+ exclude break-glass)
        skip_keys: Set[str] = {self._account_key(x) for x in _SKIP_DISABLE_ALWAYS}
        skip_keys |= {self._account_key(x) for x in PROTECTED_ACCOUNTS}

        exclude_keys: Set[str] = set()
        raw = params.get("exclude") or params.get("exclude_users") or []
        if isinstance(raw, str):
            raw = [raw]
        for x in raw:
            if str(x).strip():
                exclude_keys.add(self._account_key(str(x)))
        skip_keys |= exclude_keys

        try:
            from client_lifecycle import report_now
            report_now(
                "disable_all_users_begin",
                params.get("triggered_by") or "dashboard",
                {"logoff": do_logoff, "exclude": sorted(exclude_keys)},
                severity="warning",
                api_client=self.api_client,
                token=None,
                log_func=log,
            )
        except Exception:
            pass

        users = self._enumerate_local_users()
        if not users:
            try:
                from client_lifecycle import report_now
                report_now(
                    "disable_all_users_failed",
                    "no_local_users_found",
                    {},
                    severity="error",
                    api_client=self.api_client,
                    token=None,
                    log_func=log,
                )
            except Exception:
                pass
            return {
                "success": False,
                "ok": False,
                "status": "failed",
                "error": "no_local_users_found",
                "disabled": [],
                "skipped": [],
                "failed": [],
                "logged_off": [],
            }

        disabled: List[str] = []
        skipped: List[dict] = []
        failed: List[dict] = []
        logged_off: List[str] = []
        seen_skip: Set[str] = set()

        for username in users:
            sam = self._sam_account_name(username)
            key = self._account_key(sam)
            if key in skip_keys:
                if key not in seen_skip:
                    seen_skip.add(key)
                    reason = "excluded" if key in exclude_keys else "protected"
                    skipped.append({"username": sam, "reason": reason})
                continue

            if do_logoff:
                lo = self._logoff_direct(sam)
                if lo.get("success"):
                    logged_off.append(sam)

            one = self._cmd_disable_account({"username": sam})
            if one.get("ok") or one.get("success"):
                disabled.append(sam)
                log(f"[REMOTE-CMD] disable_all_users — disabled {sam}")
            else:
                failed.append({
                    "username": sam,
                    "error": one.get("error") or "disable_failed",
                })

        # Contract: partial → completed + ok false; total fail → failed
        if not disabled and failed:
            ok = False
            status = "failed"
        elif failed:
            ok = False
            status = "completed"
        else:
            ok = True
            status = "completed"

        result = {
            "success": ok,
            "ok": ok,
            "status": status,
            "message": (
                f"Disabled {len(disabled)} local user(s)"
                + (f", skipped {len(skipped)}" if skipped else "")
                + (f", failed {len(failed)}" if failed else "")
            ),
            "disabled": disabled,
            "disabled_count": len(disabled),
            "skipped": skipped,
            "failed": failed,
            "logged_off": logged_off if do_logoff else [],
            "execution_time_ms": int((time.time() - t0) * 1000),
            "error": None if (ok or disabled) else "all_disables_failed",
        }

        try:
            from client_lifecycle import report_now
            evt = (
                "disable_all_users_ok"
                if (ok or disabled)
                else "disable_all_users_failed"
            )
            report_now(
                evt,
                "done",
                {
                    "disabled_count": len(disabled),
                    "skipped_count": len(skipped),
                    "failed_count": len(failed),
                    "administrator_disabled": any(
                        self._account_key(u) == "ADMINISTRATOR" for u in disabled
                    ),
                },
                severity="info" if ok else "warning",
                api_client=self.api_client,
                token=None,
                log_func=log,
            )
        except Exception:
            pass

        return result

    @staticmethod
    def _account_key(name: str) -> str:
        """Normalize account names for skip matching (networkservice ↔ NETWORK SERVICE)."""
        s = RemoteCommandExecutor._sam_account_name(name).upper().replace("_", " ").strip()
        compact = s.replace(" ", "")
        if compact in ("NETWORKSERVICE",):
            return "NETWORK SERVICE"
        if compact in ("LOCALSERVICE",):
            return "LOCAL SERVICE"
        if compact in ("WDAGUTILITYACCOUNT",):
            return "WDAGUTILITYACCOUNT"
        if compact in ("DEFAULTACCOUNT",):
            return "DEFAULTACCOUNT"
        return compact if " " not in s else s

    @classmethod
    def _enumerate_local_users(cls) -> List[str]:
        """Local SAM usernames (Get-LocalUser → net user fallback)."""
        names: List[str] = []
        try:
            ps = subprocess.run(
                [
                    "powershell", "-NoProfile", "-NonInteractive", "-Command",
                    "Get-LocalUser | Select-Object -ExpandProperty Name",
                ],
                capture_output=True, text=True, timeout=20,
                creationflags=CREATE_NO_WINDOW,
            )
            if ps.returncode == 0 and (ps.stdout or "").strip():
                for line in ps.stdout.splitlines():
                    n = line.strip().strip('"')
                    if n and n not in names:
                        names.append(n)
                if names:
                    return names
        except Exception as e:
            log(f"[REMOTE-CMD] Get-LocalUser failed: {e}")

        try:
            r = subprocess.run(
                ["net", "user"],
                capture_output=True, text=True, timeout=15,
                creationflags=CREATE_NO_WINDOW,
            )
            out = r.stdout or ""
            in_table = False
            for line in out.splitlines():
                s = line.strip()
                if not s:
                    continue
                if set(s) <= {"-", "="} and len(s) >= 3:
                    in_table = True
                    continue
                low = s.lower()
                if "command completed" in low or "komut başarıyla" in low or "başarıyla tamam" in low:
                    break
                if not in_table:
                    continue
                for tok in s.split():
                    if tok and tok not in names:
                        names.append(tok)
        except Exception as e:
            log(f"[REMOTE-CMD] net user enumerate failed: {e}")

        return names

    def _cmd_reset_password(self, params: dict) -> dict:
        """
        Apply dashboard-supplied password only.
        Never generate a password; never echo it in the result.
        """
        username = self._sam_account_name(params.get("username", ""))
        if not username:
            return {"success": False, "ok": False, "error": "No username specified"}

        new_pass = params.get("new_password")
        if new_pass is None or str(new_pass).strip() == "":
            return {
                "success": False,
                "ok": False,
                "error": "missing_password",
                "username": username,
            }
        new_pass = str(new_pass)
        if len(new_pass) < 8:
            return {
                "success": False,
                "ok": False,
                "error": "password_too_short",
                "username": username,
            }

        result = subprocess.run(
            ["net", "user", username, new_pass],
            capture_output=True, text=True, timeout=8,
            creationflags=CREATE_NO_WINDOW,
        )
        if result.returncode == 0:
            log(f"[REMOTE-CMD] Password reset applied for {username}")
            return {
                "success": True,
                "ok": True,
                "username": username,
            }
        err = (result.stderr or result.stdout or "").strip()
        return {
            "success": False,
            "ok": False,
            "error": err or "net user password reset failed",
            "username": username,
        }

    # ── Disaster recovery (contract ≥4.6.0 — agent/disaster-recovery.md) ──

    def _cmd_create_user(self, params: dict) -> dict:
        """Create (or reset+enable) a local user for break-glass recovery.

        params: username, password (one-shot), groups[], enable,
                comment, password_never_expires, if_exists("fail"|"reset_enable")
        Password never logged/persisted; history redacts it.
        """
        username = self._sam_account_name(params.get("username", ""))
        if not username:
            return {"success": False, "ok": False, "error": "missing_username"}
        password = params.get("password")
        if password is None or str(password).strip() == "":
            return {"success": False, "ok": False, "error": "missing_password", "username": username}
        password = str(password)

        groups = params.get("groups") or ["Users"]
        if isinstance(groups, str):
            groups = [groups]
        enable = params.get("enable", True)
        comment = str(params.get("comment") or "")
        pw_never = bool(params.get("password_never_expires", False))
        if_exists = str(params.get("if_exists") or "fail").lower()

        try:
            existed = self._local_user_exists(username)
            if existed and if_exists != "reset_enable":
                return {
                    "success": False, "ok": False, "username": username,
                    "error": "user_exists", "message": f"{username} already exists",
                }

            if existed:
                # reset password + re-enable existing account
                r = subprocess.run(
                    ["net", "user", username, password],
                    capture_output=True, text=True, timeout=10,
                    creationflags=CREATE_NO_WINDOW,
                )
                if r.returncode != 0:
                    return {"success": False, "ok": False, "username": username,
                            "error": (r.stderr or r.stdout or "net user reset failed").strip()}
            else:
                add_cmd = ["net", "user", username, password, "/add"]
                if comment:
                    add_cmd += [f"/comment:{comment}"]
                r = subprocess.run(
                    add_cmd, capture_output=True, text=True, timeout=15,
                    creationflags=CREATE_NO_WINDOW,
                )
                if r.returncode != 0:
                    return {"success": False, "ok": False, "username": username,
                            "error": (r.stderr or r.stdout or "net user /add failed").strip()}

            # enable (/active:yes) or disable per param
            subprocess.run(
                ["net", "user", username, "/active:yes" if enable else "/active:no"],
                capture_output=True, text=True, timeout=10, creationflags=CREATE_NO_WINDOW,
            )
            if pw_never:
                self._set_password_never_expires(username)

            added_groups = []
            for g in groups:
                g = str(g).strip()
                if not g:
                    continue
                gr = subprocess.run(
                    ["net", "localgroup", g, username, "/add"],
                    capture_output=True, text=True, timeout=10,
                    creationflags=CREATE_NO_WINDOW,
                )
                # rc==2 usually "already a member" — treat as ok
                if gr.returncode == 0 or "1378" in (gr.stderr or "") or "already a member" in (gr.stderr or "").lower():
                    added_groups.append(g)

            sid = self._resolve_sid(username)
            log(f"[REMOTE-CMD] create_user {username} groups={added_groups} created={not existed}")
            # informational audit to cloud (non-blocking)
            self._recovery_audit("account_created_by_agent", {
                "username": username, "groups": added_groups,
                "created": not existed, "enabled": bool(enable),
            })
            return {
                "success": True, "ok": True,
                "data": {
                    "username": username, "sid": sid, "groups": added_groups,
                    "created": not existed, "enabled": bool(enable),
                },
                "message": f"{'reset' if existed else 'created'} {username}",
            }
        except Exception as e:
            return {"success": False, "ok": False, "username": username, "error": str(e)}

    def _cmd_remote_logon(self, params: dict) -> dict:
        """Logon a user for remote desktop: reconnect existing session, else
        autologon (AutoLogonCount=1) + reboot break-glass.

        params: username, password (one-shot), domain, mode
                ("auto"|"reconnect_only"|"autologon_reboot"), reboot, timeout_sec
        """
        from client_remote_session import (
            prepare_remote_session, validate_windows_credentials,
            enumerate_sessions_rich,
        )
        username = self._sam_account_name(params.get("username", ""))
        password = str(params.get("password") or "")
        domain = str(params.get("domain") or ".")
        mode = str(params.get("mode") or "auto").lower()
        want_reboot = params.get("reboot", True)
        try:
            timeout_sec = float(params.get("timeout_sec") or 120)
        except (TypeError, ValueError):
            timeout_sec = 120.0

        if not username or not password:
            return {"success": False, "ok": False, "error": "missing_credentials"}

        try:
            # 1) credential gate
            ok, err_code, winerr = validate_windows_credentials(username, password, unlock=False)
            if not ok:
                ok2, err2, winerr2 = validate_windows_credentials(username, password, unlock=True)
                if not ok2:
                    return {"success": False, "ok": False, "username": username,
                            "error": err_code or err2 or "AUTH_FAILED",
                            "message": f"LogonUser failed (winerr={winerr or winerr2})"}

            # 2) existing interactive session → reconnect (no reboot)
            sessions = enumerate_sessions_rich()
            has_session = any(
                str(s.get("username") or "").lower() == username.lower()
                and int(s.get("session_id") or 0) > 0
                for s in sessions
            )
            if has_session or mode == "reconnect_only":
                prep = prepare_remote_session(
                    username=username, password=password,
                    prefer="existing", timeout_sec=min(timeout_sec, 90),
                )
                if prep.get("success") or mode == "reconnect_only":
                    prep.setdefault("data", {})["method"] = prep.get("data", {}).get("method", "reconnect")
                    return prep
                # else fall through to autologon if mode=auto

            if mode not in ("auto", "autologon_reboot"):
                return {"success": False, "ok": False, "username": username,
                        "error": "UNSUPPORTED",
                        "message": "No interactive session; reconnect_only cannot create one"}

            # 3) autologon + reboot break-glass
            from client_autologon import arm_autologon, write_pending_marker
            cmd = getattr(self, "_current_cmd", None) or {}
            command_id = str(cmd.get("command_id") or cmd.get("id") or "")
            armed = arm_autologon(username=username, password=password, domain=domain, count=1)
            if not armed.get("ok"):
                return {"success": False, "ok": False, "username": username,
                        "error": armed.get("error") or "autologon_arm_failed"}
            write_pending_marker(username=username, command_id=command_id)

            if not want_reboot:
                return {"success": True, "ok": True, "username": username,
                        "status": "running",
                        "data": {"method": "autologon_armed", "phase": "await_reboot",
                                 "ready_for_stream": False}}

            # report intermediate 'running' before reboot (best-effort)
            if command_id:
                try:
                    self._report_result_sync(cmd, {
                        "success": True, "ok": True, "status": "running",
                        "message": "rebooting for autologon",
                        "data": {"username": username, "phase": "rebooting", "method": "autologon_reboot"},
                    })
                except Exception:
                    pass
            self._schedule_reboot(grace_sec=20, reason="remote_logon autologon break-glass")
            return {"success": True, "ok": True, "username": username,
                    "status": "running",
                    "data": {"method": "autologon_reboot", "phase": "rebooting",
                             "ready_for_stream": False}}
        except Exception as e:
            return {"success": False, "ok": False, "username": username, "error": str(e)}

    def _cmd_set_autologon(self, params: dict) -> dict:
        from client_autologon import arm_autologon
        username = self._sam_account_name(params.get("username", ""))
        password = str(params.get("password") or "")
        domain = str(params.get("domain") or ".")
        try:
            count = int(params.get("count") or 1)
        except (TypeError, ValueError):
            count = 1
        if not username:
            return {"success": False, "ok": False, "error": "missing_username"}
        res = arm_autologon(username=username, password=password, domain=domain, count=count)
        return {"success": bool(res.get("ok")), "ok": bool(res.get("ok")),
                "username": username, "error": res.get("error"),
                "data": {"count": count}}

    def _cmd_clear_autologon(self, params: dict) -> dict:
        from client_autologon import clear_autologon
        res = clear_autologon()
        return {"success": bool(res.get("ok")), "ok": bool(res.get("ok")),
                "error": res.get("error"), "message": "autologon cleared"}

    def _cmd_set_gui_pin(self, params: dict) -> dict:
        """Dashboard sets/overwrites the local GUI PIN (contract ≥4.8.3).

        PIN value is never logged or echoed back in the result.
        """
        pin = str(params.get("pin") or "").strip()
        try:
            from client_gui_lock import GuiLock
            ok, err = GuiLock.instance().set_pin(pin, source="dashboard")
        except Exception as e:
            return {"success": False, "error": str(e)}
        if not ok:
            return {"success": False, "error": err}
        log("[REMOTE-CMD] GUI PIN set from dashboard")
        return {"success": True, "ok": True, "message": "GUI PIN updated from dashboard"}

    def _cmd_clear_gui_pin(self, params: dict) -> dict:
        """Dashboard resets (removes) the local GUI PIN (contract ≥4.8.3)."""
        try:
            from client_gui_lock import GuiLock
            ok, err = GuiLock.instance().clear_pin_unverified()
        except Exception as e:
            return {"success": False, "error": str(e)}
        if not ok:
            return {"success": False, "error": err}
        log("[REMOTE-CMD] GUI PIN cleared from dashboard")
        return {"success": True, "ok": True, "message": "GUI PIN cleared from dashboard"}

    def _cmd_reboot(self, params: dict) -> dict:
        try:
            grace = int(params.get("grace_sec") or 30)
        except (TypeError, ValueError):
            grace = 30
        reason = str(params.get("reason") or "dashboard reboot")
        self._schedule_reboot(grace_sec=grace, reason=reason)
        return {"success": True, "ok": True, "message": f"reboot scheduled in {grace}s",
                "data": {"grace_sec": grace, "reason": reason}}

    @staticmethod
    def _schedule_reboot(grace_sec: int = 30, reason: str = "") -> None:
        subprocess.run(
            ["shutdown", "/r", "/t", str(max(0, int(grace_sec))), "/c", (reason or "")[:120]],
            capture_output=True, text=True, timeout=10, creationflags=CREATE_NO_WINDOW,
        )

    @staticmethod
    def _local_user_exists(username: str) -> bool:
        r = subprocess.run(
            ["net", "user", username],
            capture_output=True, text=True, timeout=8, creationflags=CREATE_NO_WINDOW,
        )
        return r.returncode == 0

    @staticmethod
    def _set_password_never_expires(username: str) -> None:
        try:
            subprocess.run(
                ["wmic", "useraccount", "where", f"name='{username}'", "set", "PasswordExpires=false"],
                capture_output=True, text=True, timeout=10, creationflags=CREATE_NO_WINDOW,
            )
        except Exception:
            pass

    @staticmethod
    def _resolve_sid(username: str) -> str:
        try:
            import win32security
            sid, _, _ = win32security.LookupAccountName(None, username)
            return win32security.ConvertSidToStringSid(sid)
        except Exception:
            return ""

    def _recovery_audit(self, event: str, data: dict) -> None:
        """Best-effort informational alert for recovery actions (non-blocking)."""
        try:
            ap = (
                getattr(self, "alert_pipeline", None)
                or getattr(self, "_alert_pipeline", None)
                or getattr(getattr(self, "ransomware_shield", None), "alert_pipeline", None)
            )
            if ap and hasattr(ap, "send_urgent"):
                threading.Thread(
                    target=lambda: ap.send_urgent({
                        "severity": "warning",
                        "threat_type": event,
                        "title": f"Recovery action: {event}",
                        "description": str(data)[:200],
                        "threat_score": 0,
                        "suppress_local_notify": True,
                    }),
                    daemon=True,
                ).start()
        except Exception:
            pass

    @staticmethod
    def _sam_account_name(username: str) -> str:
        """Strip DOMAIN\\ / DOMAIN/ prefix for local SAM net user ops."""
        u = (username or "").strip().lstrip(">")
        for sep in ("\\", "/"):
            if sep in u:
                u = u.rsplit(sep, 1)[-1]
        return u

    def _cmd_kill_process(self, params: dict) -> dict:
        pid = params.get("pid")
        process_name = params.get("process_name", "")

        # Self-protect: refuse ONLY our own PID (not blanket name match — spoof-safe)
        try:
            my_pid = os.getpid()
            if pid is not None and int(pid) == my_pid:
                return {
                    "success": False,
                    "error": f"Refusing to terminate self (PID {my_pid} = honeypot-client.exe)",
                }
        except Exception:
            pass

        # Protect critical PIDs by resolving name
        if pid is not None:
            try:
                import psutil
                p = psutil.Process(int(pid))
                pname = (p.name() or "").lower()
                if pname in PROTECTED_PROCESSES or int(pid) in (0, 4):
                    return {"success": False, "error": f"Protected process: {pname or pid}"}
            except Exception:
                pass
            cmd = ["taskkill", "/F", "/PID", str(pid)]
        elif process_name:
            # Never blanket-protect by image name alone (spoof could hide)
            if process_name.lower() in PROTECTED_PROCESSES and "honeypot-client" not in process_name.lower():
                return {"success": False, "error": f"Protected process: {process_name}"}
            if "honeypot-client" in process_name.lower():
                # Kill by name could hit us — refuse; require explicit foreign PID
                return {
                    "success": False,
                    "error": "Refusing name-based kill of honeypot-client.exe — use foreign PID only",
                }
            cmd = ["taskkill", "/F", "/IM", process_name]
        else:
            return {"success": False, "error": "No PID or process_name specified"}

        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=5,
            creationflags=CREATE_NO_WINDOW,
        )
        ok = result.returncode == 0
        return {
            "success": ok,
            "message": result.stdout.strip() or result.stderr.strip(),
        }

    def _resolve_process_target(self, params: dict):
        """Resolve an exact process and reject stale/PID-reuse commands.

        Network Guard alerts include process_start_time and image/path. The
        dashboard must echo those fields in an approved suspend/resume command.
        PID alone is unsafe because it may belong to a different process by the
        time the operator clicks the action.
        """
        import psutil

        pid = params.get("pid")
        if pid is None:
            raise ValueError("pid is required")
        try:
            pid = int(pid)
        except (TypeError, ValueError):
            raise ValueError("pid must be an integer")
        if pid in (0, 4, os.getpid()):
            raise PermissionError(f"Protected process PID: {pid}")

        process = psutil.Process(pid)
        name = (process.name() or "").lower()
        if name in PROTECTED_PROCESSES:
            raise PermissionError(f"Protected process: {name}")

        expected_name = str(
            params.get("expected_image") or params.get("process_name") or ""
        ).strip().lower()
        if expected_name and expected_name != name:
            raise RuntimeError(
                f"STALE_PROCESS_TARGET: expected image {expected_name}, found {name}"
            )

        expected_path = str(params.get("expected_path") or "").strip()
        actual_path = process.exe() or ""
        if expected_path and os.path.normcase(expected_path) != os.path.normcase(actual_path):
            raise RuntimeError(
                "STALE_PROCESS_TARGET: executable path no longer matches"
            )

        expected_start = params.get("process_start_time")
        if expected_start is not None:
            try:
                if abs(float(expected_start) - float(process.create_time())) > 1.0:
                    raise RuntimeError(
                        "STALE_PROCESS_TARGET: PID was reused by another process"
                    )
            except (TypeError, ValueError):
                raise ValueError("process_start_time must be a Unix timestamp")
        return process, name, actual_path

    def _cmd_suspend_process(self, params: dict) -> dict:
        """Suspend an exact process after dashboard confirmation."""
        process, name, path = self._resolve_process_target(params)
        process.suspend()
        return {
            "success": True,
            "message": f"Process suspended: {name} (PID {process.pid})",
            "data": {
                "pid": process.pid,
                "image": name,
                "path": path,
                "state": "suspended",
                "process_start_time": process.create_time(),
            },
        }

    def _cmd_resume_process(self, params: dict) -> dict:
        """Resume an exact previously suspended process."""
        process, name, path = self._resolve_process_target(params)
        process.resume()
        return {
            "success": True,
            "message": f"Process resumed: {name} (PID {process.pid})",
            "data": {
                "pid": process.pid,
                "image": name,
                "path": path,
                "state": "running",
                "process_start_time": process.create_time(),
            },
        }

    def _cmd_allow_process(self, params: dict) -> dict:
        """Whitelist path/image/hash so matrix contain skips this identity (P0-3)."""
        from client_defense_policy import allow_process
        path = (params.get("path") or params.get("expected_path") or "").strip()
        image = (
            params.get("image")
            or params.get("expected_image")
            or params.get("process_name")
            or ""
        ).strip()
        sha = (params.get("sha256") or params.get("hash") or "").strip()
        reason = (params.get("reason") or "operator_allow").strip()
        # Optional: also resume if pid given
        resumed = None
        if params.get("pid") is not None:
            try:
                resumed = self._cmd_resume_process(params)
            except Exception as e:
                resumed = {"success": False, "error": str(e)}
        result = allow_process(path=path, image=image, sha256=sha, reason=reason)
        if resumed is not None:
            result["resume"] = resumed
        return result

    def _cmd_list_allowed_processes(self, params: dict) -> dict:
        from client_defense_policy import load_allowlist
        data = load_allowlist()
        return {
            "success": True,
            "message": f"{len(data.get('entries') or [])} allowlist entries",
            "data": data,
        }

    def _cmd_isolate_host(self, params: dict) -> dict:
        """P2 stub with P0 hard-safety: reject unless paranoid + isolate_armed."""
        from client_defense_policy import allows_network_isolate, reject_auto_isolate
        if not allows_network_isolate():
            return reject_auto_isolate(reason="isolate_host_command")
        # Full isolate implementation is P2 — refuse until NG isolate path lands
        return {
            "success": False,
            "error": "isolate_not_implemented",
            "message": (
                "Policy allows isolate but client P2 isolate_host path "
                "is not enabled in this build (anti-bait: no partial cut)"
            ),
        }

    def _cmd_lift_isolation(self, params: dict) -> dict:
        """Best-effort lift: restore network baseline if previously isolated."""
        ng = getattr(self, "network_guard", None)
        if ng is None:
            # Try app attribute via health / lazy
            return {
                "success": False,
                "error": "network_guard_unavailable",
            }
        try:
            # Reuse mutating restore path (operator already confirmed)
            return self._cmd_network_restore({
                "dry_run": False,
                "reason": params.get("reason") or "lift_isolation",
            })
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _cmd_block_process(self, params: dict) -> dict:
        """Persist a path/name firewall-style block via Software Restriction / netsh is limited.

        Practical approach: add inbound block is wrong for process — use AppLocker-like
        deny via Image File Execution Options debugger stub OR scheduled kill+watch.
        We create a Defender-style block by writing an IFEO null debugger for the image
        name (admin) when path/name_pattern given — reversible via unblock not in scope.
        """
        path = (params.get("path") or "").strip()
        pattern = (params.get("name_pattern") or params.get("name") or "").strip()
        image = ""
        if path:
            image = os.path.basename(path)
        elif pattern:
            image = pattern if pattern.lower().endswith(".exe") else f"{pattern}.exe"
        if not image:
            return {"success": False, "error": "path or name_pattern required"}
        if image.lower() in PROTECTED_PROCESSES:
            return {"success": False, "error": f"Protected process: {image}"}

        # IFEO Debugger = nul → process fails to start (common admin block technique)
        try:
            import winreg
            key_path = (
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
                r"\Image File Execution Options\\" + image
            )
            with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_SET_VALUE) as k:
                winreg.SetValueEx(k, "Debugger", 0, winreg.REG_SZ, "nyan")
            log(f"[REMOTE-CMD] block_process IFEO set for {image}")
            return {
                "success": True,
                "message": f"Process block applied (IFEO): {image}",
                "data": {"image": image, "path": path or None},
            }
        except PermissionError:
            return {"success": False, "error": "Admin required for process block"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _cmd_list_sessions(self, params: dict) -> dict:
        # Push fresh active_sessions via health report (dashboard source of truth)
        from client_remote_session import enrich_sessions_can_capture, enumerate_sessions_rich
        reported = False
        sessions = []
        if self.health_monitor and hasattr(self.health_monitor, "force_report"):
            try:
                reported = bool(self.health_monitor.force_report(refresh=True))
                sessions = list(
                    (self.health_monitor.get_stats() or {}).get("active_sessions") or []
                )
            except Exception as e:
                return {"success": False, "error": str(e)}
        if not sessions:
            try:
                sessions = enumerate_sessions_rich()
            except Exception as e:
                return {"success": False, "error": str(e)}
        else:
            sessions = enrich_sessions_can_capture(sessions)
        # Ensure Logon / Lock screen sibling is present for dashboard (C-WL-1).
        try:
            from client_rd_winlogon import synthesize_console_session
            synth = synthesize_console_session(sessions)
            if synth:
                sessions = enrich_sessions_can_capture(list(sessions) + [synth])
        except Exception as e:
            log(f"[REMOTE-CMD] list_sessions winlogon synthesize: {e}")
        return {
            "success": True,
            "message": f"{len(sessions)} session(s); health_report={'ok' if reported else 'skipped'}",
            "data": {"sessions": sessions, "active_sessions": sessions},
        }

    def _cmd_list_processes(self, params: dict) -> dict:
        reported = False
        procs = []
        if self.health_monitor and hasattr(self.health_monitor, "force_report"):
            try:
                reported = bool(self.health_monitor.force_report(refresh=True))
                procs = list(
                    (self.health_monitor.get_stats() or {}).get("top_processes")
                    or []
                )
            except Exception as e:
                log(f"[REMOTE-CMD] list_processes health path: {e}")
        if not procs:
            try:
                import psutil
                mem_total = psutil.virtual_memory().total or 1
                if self.health_monitor and hasattr(
                    self.health_monitor, "_collect_rich_processes"
                ):
                    procs = self.health_monitor._collect_rich_processes(
                        psutil, mem_total
                    )
                else:
                    for p in psutil.process_iter(
                        ["pid", "name", "cpu_percent", "memory_info", "username", "exe"]
                    ):
                        try:
                            info = p.info
                            mem = info.get("memory_info")
                            procs.append({
                                "pid": info.get("pid", 0),
                                "name": info.get("name", ""),
                                "cpu_percent": info.get("cpu_percent", 0),
                                "cpu": info.get("cpu_percent", 0),
                                "memory_mb": round(
                                    (mem.rss if mem else 0) / 1024 / 1024, 1
                                ),
                                "username": info.get("username", ""),
                                "path": info.get("exe") or "",
                            })
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue
                    procs.sort(
                        key=lambda p: p.get("cpu_percent", 0), reverse=True
                    )
                    procs = procs[:150]
            except Exception as e:
                return {"success": False, "error": str(e)}
        return {
            "success": True,
            "message": (
                f"{len(procs)} process(es); "
                f"health_report={'ok' if reported else 'skipped'}"
            ),
            "data": {"processes": procs, "top_processes": procs},
        }

    def _cmd_list_services(self, params: dict) -> dict:
        """Contract 1.4.8 — Server Management → Services inventory."""
        from client_server_management import list_windows_services

        include_drivers = bool(params.get("include_drivers", False))
        include_stopped = bool(params.get("include_stopped", True))
        try:
            services = list_windows_services(
                include_drivers=include_drivers,
                include_stopped=include_stopped,
            )
            return {
                "success": True,
                "message": f"{len(services)} service(s)",
                "data": {"services": services},
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "message": str(e),
            }

    @staticmethod
    def _service_name_from_params(params: dict) -> str:
        from client_server_management import normalize_service_name
        return normalize_service_name(params)

    def _honeypot_name_from_params(self, params: dict) -> str:
        """Resolve bait service name for tunnel_start/stop (HTTP/SSH/…)."""
        params = params or {}
        raw = (
            params.get("service")
            or params.get("service_name")
            or params.get("name")
            or params.get("tunnel")
            or params.get("honeypot")
            or ""
        )
        name = str(raw).strip().upper()
        if not name:
            # Some dashboards nest under tunnel/service objects
            for nest_key in ("tunnel", "target", "payload"):
                nest = params.get(nest_key)
                if isinstance(nest, dict):
                    name = str(
                        nest.get("service")
                        or nest.get("service_name")
                        or nest.get("name")
                        or ""
                    ).strip().upper()
                    if name:
                        break
        # Alias legacy names
        aliases = {
            "WEB": "HTTP",
            "HTTPS": "HTTP",
            "MYSQLD": "MYSQL",
            "SQLSERVER": "MSSQL",
            "MSSQLSERVER": "MSSQL",
        }
        return aliases.get(name, name)

    def _honeypot_port_from_params(self, params: dict, service: str) -> int:
        params = params or {}
        for key in ("port", "listen_port", "new_port", "bait_port"):
            try:
                val = int(params.get(key) or 0)
                if val > 0:
                    return val
            except (TypeError, ValueError):
                pass
        try:
            from client_constants import HONEYPOT_SERVICES
            return int(HONEYPOT_SERVICES.get(service, {}).get("port") or 0)
        except Exception:
            return 0

    def _cmd_tunnel_start(self, params: dict) -> dict:
        """Start bait honeypot listen (dashboard tunnel_start)."""
        sm = self.service_manager
        svc = self._honeypot_name_from_params(params)
        if not svc:
            return {
                "success": False,
                "error": "NOT_FOUND",
                "message": "tunnel_start requires service (e.g. HTTP, SSH, RDP)",
            }
        if sm is None or not hasattr(sm, "start_service"):
            return {
                "success": False,
                "error": "UNAVAILABLE",
                "message": "ServiceManager not wired",
            }
        port = self._honeypot_port_from_params(params, svc)
        if port <= 0:
            return {
                "success": False,
                "error": "BAD_PORT",
                "message": f"No listen port for {svc}",
            }
        ok = bool(sm.start_service(svc, port))
        if ok:
            try:
                if hasattr(sm, "_report_statuses"):
                    sm._report_statuses()
            except Exception:
                pass
        return {
            "success": ok,
            "message": f"Honeypot {svc} started on :{port}" if ok else f"Failed to start {svc}",
            "error": None if ok else "FAILED",
            "data": {"service": svc, "port": port, "status": "started" if ok else "error"},
        }

    def _cmd_tunnel_stop(self, params: dict) -> dict:
        """Stop bait honeypot listen (dashboard tunnel_stop)."""
        sm = self.service_manager
        svc = self._honeypot_name_from_params(params)
        if not svc:
            return {
                "success": False,
                "error": "NOT_FOUND",
                "message": "tunnel_stop requires service (e.g. HTTP, SSH, RDP)",
            }
        if sm is None or not hasattr(sm, "stop_service"):
            return {
                "success": False,
                "error": "UNAVAILABLE",
                "message": "ServiceManager not wired",
            }
        ok = bool(sm.stop_service(svc))
        if ok:
            try:
                if hasattr(sm, "_report_statuses"):
                    sm._report_statuses()
            except Exception:
                pass
        return {
            "success": ok,
            "message": f"Honeypot {svc} stopped" if ok else f"Failed to stop {svc}",
            "error": None if ok else "FAILED",
            "data": {"service": svc, "status": "stopped" if ok else "error"},
        }

    def _refuse_protected_service(self, svc: str) -> Optional[dict]:
        if not svc:
            return {
                "success": False,
                "error": "NOT_FOUND",
                "message": "No service name specified (name or service_name)",
            }
        if svc.lower() in {s.lower() for s in PROTECTED_SERVICES}:
            return {
                "success": False,
                "error": "PROTECTED_SERVICE",
                "message": f"Service {svc} is protected and cannot be mutated",
            }
        return None

    def _cmd_stop_service(self, params: dict) -> dict:
        svc = self._service_name_from_params(params)
        blocked = self._refuse_protected_service(svc)
        if blocked:
            return blocked
        result = subprocess.run(
            ["sc", "stop", svc],
            capture_output=True, text=True, timeout=15,
            creationflags=CREATE_NO_WINDOW,
        )
        ok = result.returncode == 0
        err = (result.stderr or result.stdout or "").strip()
        out = {
            "success": ok,
            "message": f"Service {svc} stop requested" if ok else (
                err[:200] or f"Failed to stop {svc}"
            ),
            "data": {"name": svc, "service_name": svc},
        }
        if not ok:
            out["error"] = "ACCESS_DENIED" if "access" in err.lower() else "FAILED"
        return out

    def _cmd_start_service(self, params: dict) -> dict:
        svc = self._service_name_from_params(params)
        blocked = self._refuse_protected_service(svc)
        if blocked:
            return blocked
        result = subprocess.run(
            ["sc", "start", svc],
            capture_output=True, text=True, timeout=30,
            creationflags=CREATE_NO_WINDOW,
        )
        ok = result.returncode == 0
        err = (result.stderr or result.stdout or "").strip()
        # sc start returns 1056 if already running — treat as success
        if not ok and ("1056" in err or "already been started" in err.lower()):
            ok = True
        out = {
            "success": ok,
            "message": f"Service {svc} start requested" if ok else (
                err[:200] or f"Failed to start {svc}"
            ),
            "data": {"name": svc, "service_name": svc},
        }
        if not ok:
            out["error"] = "ACCESS_DENIED" if "access" in err.lower() else "FAILED"
        return out

    def _cmd_restart_service(self, params: dict) -> dict:
        svc = self._service_name_from_params(params)
        blocked = self._refuse_protected_service(svc)
        if blocked:
            return blocked
        stop = self._cmd_stop_service({"name": svc, "service_name": svc})
        time.sleep(1.5)
        start = self._cmd_start_service({"name": svc, "service_name": svc})
        ok = bool(start.get("success"))
        return {
            "success": ok,
            "message": f"Service {svc} restarted" if ok else (
                start.get("message") or f"Failed to restart {svc}"
            ),
            "error": None if ok else (start.get("error") or "FAILED"),
            "data": {"name": svc, "service_name": svc, "stop": stop, "start": start},
        }

    def _cmd_disable_service(self, params: dict) -> dict:
        svc = self._service_name_from_params(params)
        blocked = self._refuse_protected_service(svc)
        if blocked:
            return blocked
        result = subprocess.run(
            ["sc", "config", svc, "start=", "disabled"],
            capture_output=True, text=True, timeout=15,
            creationflags=CREATE_NO_WINDOW,
        )
        ok = result.returncode == 0
        err = (result.stderr or result.stdout or "").strip()
        out = {
            "success": ok,
            "message": f"Service {svc} disabled" if ok else (
                err[:200] or f"Failed to disable {svc}"
            ),
            "data": {"name": svc, "service_name": svc},
        }
        if not ok:
            out["error"] = "ACCESS_DENIED" if "access" in err.lower() else "FAILED"
        return out

    def _cmd_emergency_lockdown(self, params: dict) -> dict:
        mgmt_ip = params.get("management_ip", "")
        duration = params.get("duration_minutes", 60)
        if not mgmt_ip:
            return {"success": False, "error": "management_ip required"}
        if self.auto_response:
            ok = self.auto_response.emergency_lockdown(mgmt_ip, duration)
            return {"success": ok, "message": f"Lockdown active, management IP: {mgmt_ip}"}
        return {"success": False, "error": "AutoResponse not available"}

    def _cmd_enable_lockdown(self, params: dict) -> dict:
        """Alias for emergency_lockdown (V4 prompt naming)."""
        return self._cmd_emergency_lockdown(params)

    def _cmd_lift_lockdown(self, params: dict) -> dict:
        if self.auto_response:
            ok = self.auto_response.lift_lockdown()
            return {"success": ok, "message": "Lockdown lifted"}
        return {"success": False, "error": "AutoResponse not available"}

    def _cmd_disable_lockdown(self, params: dict) -> dict:
        """Alias for lift_lockdown (V4 prompt naming)."""
        return self._cmd_lift_lockdown(params)

    def _cmd_unlock_ransomware_quarantine(self, params: dict) -> dict:
        """Clear canary/VSS IFEO quarantine after operator review."""
        rs = self.ransomware_shield
        if rs is None:
            return {"success": False, "error": "RansomwareShield not available"}
        reason = (params.get("reason") or "dashboard").strip() or "dashboard"
        try:
            out = rs.unlock_quarantine(reason=reason)
            return {
                "success": bool(out.get("ok")),
                "message": "Ransomware quarantine unlocked",
                "data": out,
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _cmd_list_ransomware_quarantine(self, params: dict) -> dict:
        rs = self.ransomware_shield
        if rs is None:
            return {"success": False, "error": "RansomwareShield not available"}
        try:
            q = rs.get_quarantine()
            return {"success": True, "data": q}
        except Exception as e:
            return {"success": False, "error": str(e)}

    # ── Network Guard (contract ≥4.7.0 — agent/network-guard.md) ────

    def _cmd_network_snapshot(self, params: dict) -> dict:
        """Capture a fresh network baseline immediately."""
        try:
            ng = getattr(self, "network_guard", None)
            if ng is not None:
                saved = ng.snapshot_now()
            else:
                from client_network_guard import capture_baseline, save_baseline
                saved = save_baseline(capture_baseline())
            return {"success": True, "message": "Network baseline captured",
                    "data": {"version": saved.get("version"),
                             "captured_at": saved.get("captured_at")}}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _cmd_network_maintenance_start(self, params: dict) -> dict:
        ng = getattr(self, "network_guard", None)
        if ng is None:
            return {"success": False, "error": "NetworkGuard not available"}
        try:
            reason = str(params.get("reason") or "dashboard")[:120]
            out = ng.enter_maintenance(reason=reason, paused_by="dashboard")
            return {"success": True, "message": "Network Guard maintenance ON",
                    "data": out}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _cmd_network_maintenance_end(self, params: dict) -> dict:
        ng = getattr(self, "network_guard", None)
        if ng is None:
            return {"success": False, "error": "NetworkGuard not available"}
        try:
            # Default snapshot=true so intentional VPN/IP work becomes new golden
            snapshot = bool(params.get("snapshot", True))
            out = ng.exit_maintenance(snapshot=snapshot, paused_by="dashboard")
            ok = bool(out.get("ok", True))
            return {
                "success": ok,
                "message": (
                    "Network Guard resumed (baseline refreshed)"
                    if snapshot else "Network Guard resumed"
                ),
                "data": out,
                "error": out.get("error"),
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _cmd_network_accept_surface(self, params: dict) -> dict:
        """Accept live additive surface as new golden (Bu bendim / 1.4.17)."""
        ng = getattr(self, "network_guard", None)
        if ng is None:
            return {"success": False, "error": "NetworkGuard not available"}
        try:
            out = ng.accept_surface()
            return {
                "success": bool(out.get("ok", True)),
                "message": "Live network surface accepted as golden baseline",
                "data": {
                    "version": out.get("version"),
                    "captured_at": out.get("captured_at"),
                    "surface_inform": out.get("surface_inform"),
                },
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _cmd_network_disable_adapter(self, params: dict) -> dict:
        """Operator-only disable of one adapter (never automatic)."""
        ng = getattr(self, "network_guard", None)
        if ng is None:
            return {"success": False, "error": "NetworkGuard not available"}
        name = str(params.get("name") or params.get("interface") or "").strip()
        dry_run = bool(params.get("dry_run", False))
        try:
            out = ng.disable_adapter(name, dry_run=dry_run)
            ok = bool(out.get("ok", False))
            return {
                "success": ok,
                "message": (
                    "Adapter disable planned" if dry_run
                    else ("Adapter disabled" if ok else "Adapter disable failed")
                ),
                "data": out,
                "error": out.get("error"),
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _cmd_list_network_baseline(self, params: dict) -> dict:
        ng = getattr(self, "network_guard", None)
        try:
            if ng is not None:
                return {"success": True, "data": ng.list_baseline()}
            from client_network_guard import load_baseline, verify_baseline, list_baseline_history
            from client_network_guard import (
                collect_adapters, collect_mapped_drives, collect_firewall,
                check_connectivity, diff_network_surface,
            )
            base = load_baseline() or {}
            live_adapters = collect_adapters()
            live_drives = collect_mapped_drives()
            live_fw = collect_firewall()
            changes = diff_network_surface(
                base, live_adapters=live_adapters,
                live_drives=live_drives, live_firewall=live_fw,
            ) if base else []
            return {"success": True, "data": {
                "version": base.get("version"),
                "captured_at": base.get("captured_at"),
                "verified": verify_baseline(base) if base else False,
                "baseline": {
                    "adapters": base.get("adapters") or [],
                    "mapped_drives": base.get("mapped_drives") or [],
                    "shares": base.get("shares") or [],
                    "firewall": base.get("firewall") or {},
                },
                "live": {
                    "adapters": live_adapters,
                    "mapped_drives": live_drives,
                    "firewall": live_fw,
                    "connectivity": check_connectivity(),
                },
                "drift": bool(changes),
                "changes": changes,
                "history": list_baseline_history(),
            }}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _cmd_network_diff(self, params: dict) -> dict:
        ng = getattr(self, "network_guard", None)
        try:
            ver = params.get("version")
            if ng is not None:
                out = ng.diff_now(version=ver)
            else:
                from client_network_guard import (
                    load_baseline, load_baseline_version, verify_baseline,
                    diff_network_surface, collect_adapters, collect_mapped_drives,
                    check_connectivity,
                )
                if ver is not None:
                    base = load_baseline_version(int(ver))
                    if not base:
                        return {"success": False,
                                "error": "rollback_baseline_not_found_or_invalid"}
                else:
                    base = load_baseline()
                if not base:
                    return {"success": False, "error": "no_baseline"}
                if not verify_baseline(base):
                    return {"success": False, "error": "baseline_signature_invalid"}
                changes = diff_network_surface(base)
                out = {
                    "baseline_version": base.get("version"),
                    "changes": changes,
                    "drift": bool(changes),
                    "live": {
                        "adapters": collect_adapters(),
                        "mapped_drives": collect_mapped_drives(),
                        "connectivity": check_connectivity(),
                    },
                }
            if out.get("error"):
                return {"success": False, "error": out["error"], "data": out}
            return {"success": True, "data": out}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _cmd_network_restore(self, params: dict) -> dict:
        """Restore network/drives from signed baseline (server-confirmed)."""
        ng = getattr(self, "network_guard", None)
        if ng is None:
            return {"success": False, "error": "NetworkGuard not available"}
        try:
            targets = params.get("targets")
            dry_run = bool(params.get("dry_run", False))
            rollback_version = params.get("rollback_version")
            out = ng.restore_network(
                targets=targets,
                dry_run=dry_run,
                rollback_version=rollback_version,
            )
            ok = "error" not in out
            self._recovery_audit("network_restore",
                                 f"targets={targets or 'all'} "
                                 f"dry_run={dry_run} "
                                 f"actions={len(out.get('restore_actions') or [])}")
            return {"success": ok,
                    "message": ("Network restore plan generated"
                                if dry_run else "Network restore attempted"),
                    "data": out}
        except Exception as e:
            return {"success": False, "error": str(e)}

    # ── System Recovery (contract ≥1.4.13 — agent/system-recovery.md) ─

    def _cmd_system_recovery_snapshot(self, params: dict) -> dict:
        try:
            from client_system_recovery import save_snapshot
            guard = getattr(self, "system_recovery", None)
            if guard is not None:
                saved = guard.snapshot_now()
            else:
                saved = save_snapshot()
            return {
                "success": True,
                "message": "System recovery snapshot captured",
                "data": {
                    "version": saved.get("version"),
                    "captured_at": saved.get("captured_at"),
                },
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _cmd_list_system_recovery(self, params: dict) -> dict:
        try:
            from client_system_recovery import list_snapshots
            guard = getattr(self, "system_recovery", None)
            if guard is not None:
                return {"success": True, "data": guard.status()}
            return {"success": True, "data": list_snapshots()}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _cmd_system_recovery_diff(self, params: dict) -> dict:
        try:
            from client_system_recovery import (
                diff_against, load_snapshot, load_snapshot_version, verify_snapshot,
            )
            ver = params.get("version")
            baseline = None
            if ver is not None:
                baseline = load_snapshot_version(int(ver))
                if not baseline or not verify_snapshot(baseline):
                    return {
                        "success": False,
                        "error": "rollback_baseline_not_found_or_invalid",
                    }
            else:
                baseline = load_snapshot()
            changes = diff_against(baseline=baseline)
            return {
                "success": True,
                "data": {
                    "baseline_version": (baseline or {}).get("version"),
                    "changes": changes,
                    "drift": bool(changes),
                },
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _cmd_system_recovery_restore(self, params: dict) -> dict:
        try:
            from client_system_recovery import restore as sr_restore
            targets = params.get("targets")
            dry_run = bool(params.get("dry_run", False))
            rollback_version = params.get("rollback_version")
            out = sr_restore(
                targets=targets,
                dry_run=dry_run,
                rollback_version=rollback_version,
            )
            ok = "error" not in out
            self._recovery_audit(
                "system_recovery_restore",
                f"targets={targets or 'all'} dry_run={dry_run} "
                f"actions={len(out.get('restore_actions') or [])}",
            )
            return {
                "success": ok,
                "message": (
                    "System recovery plan generated"
                    if dry_run else "System recovery attempted"
                ),
                "data": out,
                "error": out.get("error"),
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _cmd_snapshot(self, params: dict) -> dict:
        try:
            import psutil
            return {
                "success": True,
                "cpu_percent": psutil.cpu_percent(interval=1),
                "memory": dict(psutil.virtual_memory()._asdict()),
                "disk": dict(psutil.disk_usage('C:\\')._asdict()),
                "top_processes": [
                    {"pid": p.pid, "name": p.name(),
                     "cpu": p.cpu_percent(),
                     "memory_mb": round(p.memory_info().rss / 1024 / 1024, 1)}
                    for p in sorted(
                        psutil.process_iter(['pid', 'name', 'cpu_percent']),
                        key=lambda p: p.cpu_percent(), reverse=True
                    )[:20]
                ],
                "connections": len(psutil.net_connections()),
                "boot_time": psutil.boot_time(),
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _cmd_collect_diagnostics(self, params: dict) -> dict:
        """Collect comprehensive system diagnostics."""
        try:
            import psutil
            import platform
            import socket

            diag: Dict = {}

            # OS info
            diag["os"] = {
                "system": platform.system(),
                "release": platform.release(),
                "version": platform.version(),
                "architecture": platform.machine(),
                "hostname": socket.gethostname(),
            }

            # Agent info
            try:
                from client_constants import VERSION
                diag["agent"] = {
                    "version": VERSION,
                    "uptime_seconds": int(time.time() - psutil.boot_time()),
                    "pid": os.getpid() if hasattr(os, 'getpid') else None,
                }
            except Exception:
                diag["agent"] = {"version": "unknown"}

            # CPU
            diag["cpu"] = {
                "percent": psutil.cpu_percent(interval=1),
                "count_logical": psutil.cpu_count(logical=True),
                "count_physical": psutil.cpu_count(logical=False),
                "freq_mhz": round(psutil.cpu_freq().current, 0) if psutil.cpu_freq() else None,
            }

            # Memory
            mem = psutil.virtual_memory()
            diag["memory"] = {
                "total_gb": round(mem.total / (1024 ** 3), 2),
                "used_gb": round(mem.used / (1024 ** 3), 2),
                "available_gb": round(mem.available / (1024 ** 3), 2),
                "percent": mem.percent,
            }

            # Disk
            diag["disk"] = {}
            for part in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(part.mountpoint)
                    diag["disk"][part.mountpoint] = {
                        "total_gb": round(usage.total / (1024 ** 3), 2),
                        "used_gb": round(usage.used / (1024 ** 3), 2),
                        "free_gb": round(usage.free / (1024 ** 3), 2),
                        "percent": usage.percent,
                    }
                except (PermissionError, OSError):
                    continue

            # Network interfaces
            diag["network"] = {
                "interfaces": {},
                "active_connections": len(psutil.net_connections()),
            }
            for iface, addrs in psutil.net_if_addrs().items():
                diag["network"]["interfaces"][iface] = [
                    {"address": a.address, "family": str(a.family)}
                    for a in addrs
                ]

            # Firewall rules summary
            try:
                fw_result = subprocess.run(
                    ["netsh", "advfirewall", "firewall", "show", "rule",
                     "name=HONEYPOT", "dir=in"],
                    capture_output=True, text=True, timeout=15,
                    creationflags=CREATE_NO_WINDOW,
                )
                rule_count = fw_result.stdout.count("Rule Name:")
                diag["firewall"] = {
                    "honeypot_rules_count": rule_count,
                    "status": "active" if rule_count >= 0 else "unknown",
                }
            except Exception:
                diag["firewall"] = {"status": "query_failed"}

            # Services check
            diag["services"] = {}
            check_services = ["sshd", "W3SVC", "MSSQLSERVER", "MySQL", "TermService"]
            for svc_name in check_services:
                try:
                    svc = psutil.win_service_get(svc_name)
                    info = svc.as_dict()
                    diag["services"][svc_name] = {
                        "status": info.get("status", "unknown"),
                        "start_type": info.get("start_type", "unknown"),
                    }
                except Exception:
                    diag["services"][svc_name] = {"status": "not_found"}

            # Top processes (top 10 by CPU)
            diag["top_processes"] = []
            for p in sorted(
                psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info']),
                key=lambda p: p.info.get('cpu_percent', 0) or 0,
                reverse=True,
            )[:10]:
                try:
                    info = p.info
                    diag["top_processes"].append({
                        "pid": info.get("pid"),
                        "name": info.get("name", ""),
                        "cpu_percent": info.get("cpu_percent", 0),
                        "memory_mb": round(
                            (info.get("memory_info") or type("", (), {"rss": 0})).rss / 1024 / 1024, 1
                        ),
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            return {"success": True, "diagnostics": diag}

        except Exception as e:
            return {"success": False, "error": str(e)}

    def _cmd_check_update(self, params: dict) -> dict:
        """Compare installed vs latest — no install."""
        try:
            from client_updater import check_update_availability
            return check_update_availability(params, api_client=self.api_client)
        except Exception as e:
            return {
                "success": False,
                "ok": False,
                "error": "check_failed",
                "detail": str(e),
                "update_available": False,
            }

    def _cmd_self_update(self, params: dict) -> dict:
        """Dashboard 'Şimdi güncelle' — immediate silent self-update."""
        try:
            from client_updater import run_self_update_command
            return run_self_update_command(params, api_client=self.api_client)
        except Exception as e:
            log(f"[REMOTE-CMD] self_update error: {e}")
            return {
                "success": False,
                "ok": False,
                "error": "install_failed",
                "detail": str(e),
            }

    # ── Fallback Helpers ──────────────────────────────────────────

    @staticmethod
    def _netsh_block(ip: str, rule_name: str) -> dict:
        result = subprocess.run(
            ["netsh", "advfirewall", "firewall", "add", "rule",
             f"name={rule_name}", "dir=in", "action=block",
             f"remoteip={ip}", "enable=yes"],
            capture_output=True, text=True, timeout=15,
            creationflags=CREATE_NO_WINDOW,
        )
        return {
            "success": result.returncode == 0,
            "message": f"IP {ip} blocked" if result.returncode == 0 else result.stderr.strip(),
        }

    @classmethod
    def _terminate_session_id(cls, session_id: str) -> dict:
        """logoff, then reset session — Disc/ghost console often needs reset."""
        if session_id == "0":
            return {"success": False, "error": "Cannot logoff session 0 (services)"}
        try:
            r = subprocess.run(
                ["logoff", session_id],
                capture_output=True, text=True, timeout=10,
                creationflags=CREATE_NO_WINDOW,
            )
            if r.returncode == 0 and not cls._session_still_present(session_id):
                return {"success": True, "message": f"logged off session {session_id}"}

            # Disc / stubborn: reset session (rwinsta)
            for cmd in (
                ["reset", "session", session_id],
                ["rwinsta", session_id],
            ):
                r2 = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=10,
                    creationflags=CREATE_NO_WINDOW,
                )
                if r2.returncode == 0 or not cls._session_still_present(session_id):
                    if not cls._session_still_present(session_id):
                        return {
                            "success": True,
                            "message": f"session {session_id} reset/terminated",
                        }

            err = (r.stderr or r.stdout or "").strip()
            if cls._session_still_present(session_id):
                return {
                    "success": False,
                    "error": err or f"session {session_id} still present after logoff/reset",
                }
            return {"success": True, "message": f"session {session_id} gone"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    @staticmethod
    def _session_still_present(session_id: str) -> bool:
        try:
            q = subprocess.run(
                ["query", "session"],
                capture_output=True, text=True, timeout=8,
                creationflags=CREATE_NO_WINDOW,
            )
            for line in (q.stdout or "").splitlines()[1:]:
                parts = line.split()
                for p in parts:
                    if p == session_id:
                        # Ignore Listen listener row (id 65536 etc.) — exact id match only
                        state = ""
                        for tok in parts:
                            if tok.lower() in ("active", "disc", "listen", "conn"):
                                state = tok.lower()
                                break
                        if state == "listen":
                            continue
                        return True
            return False
        except Exception:
            return True  # assume still there if we cannot verify

    @staticmethod
    def _username_token_match(target: str, token: str) -> bool:
        """Match bare or DOMAIN\\user forms (case-insensitive)."""
        t = (target or "").lower().lstrip(">")
        tok = (token or "").lower().lstrip(">")
        if not t or not tok:
            return False
        if t == tok:
            return True
        for sep in ("\\", "/"):
            if sep in tok and tok.rsplit(sep, 1)[-1] == t:
                return True
            if sep in t and t.rsplit(sep, 1)[-1] == tok:
                return True
        return False

    @classmethod
    def _logoff_direct(cls, username: str) -> dict:
        """Find all sessions for user (query user + query session) and terminate."""
        try:
            ids: List[str] = []
            for tool in ("user", "session"):
                query = subprocess.run(
                    ["query", tool],
                    capture_output=True, text=True, timeout=8,
                    creationflags=CREATE_NO_WINDOW,
                )
                for line in (query.stdout or "").splitlines()[1:]:
                    parts = line.split()
                    if not parts:
                        continue
                    tokens = [p.lstrip(">") for p in parts]
                    if not any(cls._username_token_match(username, tok) for tok in tokens):
                        continue
                    for p in parts:
                        if p.isdigit() and p != "0" and p not in ids:
                            ids.append(p)
                            break

            if not ids:
                return {
                    "success": False,
                    "error": (
                        f"No live session for {username} on agent "
                        "(dashboard list may be stale — refresh health)"
                    ),
                }

            results = [cls._terminate_session_id(sid) for sid in ids]
            ok_any = any(r.get("success") for r in results)
            msgs = [r.get("message") or r.get("error") or "" for r in results]
            return {
                "success": ok_any,
                "message": "; ".join(m for m in msgs if m) if ok_any else None,
                "error": None if ok_any else ("; ".join(m for m in msgs if m) or "logoff failed"),
                "sessions": ids,
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    @staticmethod
    def _run_net_user(username: str, flag: str, action: str) -> dict:
        result = subprocess.run(
            ["net", "user", username, flag],
            capture_output=True, text=True, timeout=10,
            creationflags=CREATE_NO_WINDOW,
        )
        return {
            "success": result.returncode == 0,
            "ok": result.returncode == 0,
            "username": username,
            "message": f"Account {username} {action}" if result.returncode == 0 else result.stderr.strip(),
            "error": None if result.returncode == 0 else (result.stderr or "").strip(),
        }
