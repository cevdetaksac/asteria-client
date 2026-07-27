#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Asteria Client — Auto-Response Engine (v4.0)

Executes automatic defensive actions when threat score thresholds
are exceeded. Integrates with Windows Firewall, user session management,
and the alert pipeline.

Actions:
  block_ip           — Add Windows Firewall inbound block rule
  unblock_ip         — Remove block rule (scheduled or manual)
  logoff_user        — Terminate active RDP/console session
  disable_account    — Disable Windows user account
  enable_account     — Re-enable Windows user account
  emergency_lockdown — Block all inbound except management IP
  lift_lockdown      — Remove lockdown rules

Safety guards:
  - Max blocks per hour/day
  - Whitelist IPs/subnets never blocked
  - Protected accounts (SYSTEM, LOCAL SERVICE, etc.)
  - Auto-unblock timer (default 24h)

Exports:
  AutoResponse — main class (block_ip / unblock_ip / logoff_user / ...)
"""

import ipaddress
import secrets
import string
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set

from client_helpers import log
from client_winproc import run_hidden

# ── Constants ─────────────────────────────────────────────────────

FIREWALL_RULE_PREFIX = "AR-BLOCK"

# Safety limits
MAX_BLOCKS_PER_HOUR = 50
MAX_BLOCKS_PER_DAY = 200
AUTO_UNBLOCK_HOURS = 24

# Protected resources — OS machine identities (never touch)
PROTECTED_ACCOUNTS: Set[str] = {
    "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE",
    "WDAGUTILITYACCOUNT",
}

# Auto / silent-hours / alert-pipeline must not disable these without explicit
# cloud confirm IR (allow_privileged=True). Prevents stuck servers.
AUTO_SAFE_ACCOUNTS: Set[str] = {
    "ADMINISTRATOR",
    "ADMIN",
    "GUEST",
    "DEFAULTACCOUNT",
    "WDAGUTILITYACCOUNT",
}

PROTECTED_PROCESSES: Set[str] = {
    "system", "smss.exe", "csrss.exe", "wininit.exe",
    "services.exe", "lsass.exe", "svchost.exe",
    "asteria-client.exe",
    "honeypot-client.exe",
}

PROTECTED_SERVICES: Set[str] = {
    "wuauserv", "windefend", "eventlog", "mpssvc",
    "w32time", "dnscache",
}


# ── Block Tracking ───────────────────────────────────────────────

@dataclass
class BlockRecord:
    """Tracks a firewall block for auto-unblock scheduling."""
    ip: str
    rule_name: str
    reason: str
    blocked_at: float
    unblock_at: float  # 0 = permanent until manual removal
    auto_unblock: bool = True


# ── Auto-Response Engine ─────────────────────────────────────────

class AutoResponse:
    """
    Automatic defensive action executor.

    Usage:
        ar = AutoResponse(
            api_client=api_client,
            token_getter=lambda: state.get("token", ""),
            whitelist_ips={"10.0.0.1"},
        )
        ar.start()
        ar.block_ip("1.2.3.4", reason="Brute force", duration_hours=24)
    """

    def __init__(
        self,
        api_client=None,
        token_getter: Optional[Callable[[], str]] = None,
        whitelist_ips: Optional[Set[str]] = None,
        whitelist_subnets: Optional[List[str]] = None,
    ):
        self.api_client = api_client
        self.token_getter = token_getter or (lambda: "")
        self.whitelist_ips: Set[str] = whitelist_ips or set()
        self.whitelist_subnets: List[str] = whitelist_subnets or []

        # Active blocks
        self._blocks: Dict[str, BlockRecord] = {}
        self._lock = threading.Lock()

        # Rate limiting (overridable via threats/config sync)
        self.max_blocks_per_hour = MAX_BLOCKS_PER_HOUR
        self.max_blocks_per_day = MAX_BLOCKS_PER_DAY
        self.auto_block_enabled = True
        self.auto_block_threshold = 80
        self.auto_block_duration_hours = AUTO_UNBLOCK_HOURS
        self._block_timestamps: deque = deque(maxlen=MAX_BLOCKS_PER_DAY)

        # Auto-unblock thread
        self._running = False
        self._unblock_thread: Optional[threading.Thread] = None

        # Lockdown state
        self._lockdown_active = False
        self._lockdown_management_ip: Optional[str] = None

        # Optional alert pipeline for C-BRICK skip notices
        self.alert_pipeline = None
        self._last_disable_error: Optional[str] = None

        # Stats
        self._stats = {
            "blocks_applied": 0,
            "blocks_removed": 0,
            "accounts_disabled": 0,
            "logoffs_executed": 0,
            "rate_limited": 0,
            "whitelisted_skipped": 0,
            "skipped_unlinked": 0,
            "last_admin_refused": 0,
            "last_admin_rollback": 0,
            "errors": 0,
        }

    # ── Lifecycle ─────────────────────────────────────────────────

    def start(self):
        """Start the auto-unblock scheduler thread."""
        if self._running:
            return
        self._running = True
        self._unblock_thread = threading.Thread(
            target=self._unblock_scheduler_loop,
            name="AutoResponse-Unblock",
            daemon=True,
        )
        self._unblock_thread.start()
        log("[AUTO-RESPONSE] 🚀 Auto-response engine started")

    def stop(self):
        """Stop the engine."""
        self._running = False
        log("[AUTO-RESPONSE] ✅ Stopped")

    def get_stats(self) -> dict:
        """Return action statistics."""
        stats = dict(self._stats)
        with self._lock:
            stats["active_blocks"] = len(self._blocks)
            stats["lockdown_active"] = self._lockdown_active
        return stats

    def get_blocked_ips(self) -> List[dict]:
        """Return list of currently blocked IPs."""
        with self._lock:
            return [
                {
                    "ip": b.ip,
                    "reason": b.reason,
                    "blocked_at": b.blocked_at,
                    "unblock_at": b.unblock_at,
                    "auto_unblock": b.auto_unblock,
                }
                for b in self._blocks.values()
            ]

    def hydrate_from_inventory(self, inventory: dict) -> int:
        """Load firewall/ProgramData inventory into RAM (no new netsh rules).

        inventory: {ip: {rule_name, reason, blocked_at, source}}
        """
        if not inventory:
            return 0
        added = 0
        with self._lock:
            for ip, info in inventory.items():
                if not ip or ip in self._blocks:
                    continue
                info = info or {}
                self._blocks[ip] = BlockRecord(
                    ip=ip,
                    rule_name=info.get("rule_name") or f"{FIREWALL_RULE_PREFIX}-{ip}",
                    reason=info.get("reason") or "firewall_persist",
                    blocked_at=float(info.get("blocked_at") or time.time()),
                    unblock_at=0,
                    auto_unblock=False,
                )
                added += 1
            # Hydrated permanent blocks: allow up to 5000 for GUI listing
            self._trim_blocks_locked(max_blocks=5000)
        if added:
            log(f"[AUTO-RESPONSE] Hydrated {added} blocked IP(s) from firewall/store")
        return added

    # ── IP Blocking ───────────────────────────────────────────────

    def block_ip(self, ip: str, reason: str = "",
                 duration_hours: int = AUTO_UNBLOCK_HOURS) -> bool:
        """
        Block an IP via Windows Firewall.
        Returns True if successfully blocked.
        """
        # Safety: feature disabled via config?
        if not getattr(self, "auto_block_enabled", True):
            log(f"[AUTO-RESPONSE] ⚪ Auto-block disabled — skip {ip}")
            return False

        # Safety: whitelist check — never block; clear existing block if any
        if self._is_whitelisted(ip):
            log(f"[AUTO-RESPONSE] ⚪ Skipped whitelist IP: {ip}")
            self._stats["whitelisted_skipped"] += 1
            try:
                self.unblock_ip(ip)
            except Exception:
                pass
            return False

        # Safety: already blocked?
        with self._lock:
            if ip in self._blocks:
                log(f"[AUTO-RESPONSE] Already blocked: {ip}")
                return True

        # Safety: rate limit check
        if not self._check_rate_limit():
            log(f"[AUTO-RESPONSE] ⚠️ Rate limit reached — skipping block for {ip}")
            self._stats["rate_limited"] += 1
            return False

        # Execute firewall command
        rule_name = f"{FIREWALL_RULE_PREFIX}-{ip}"
        # Prefix cutover is idempotent: remove the old HP name before AR write.
        self._run_system_cmd([
            "netsh", "advfirewall", "firewall", "delete", "rule",
            f"name=HP-BLOCK-{ip}", "dir=in",
        ])
        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}", "dir=in", "action=block",
            f"remoteip={ip}", "enable=yes",
        ]

        success = self._run_system_cmd(cmd)
        if success:
            now = time.time()
            unblock_at = now + (duration_hours * 3600) if duration_hours > 0 else 0

            with self._lock:
                self._blocks[ip] = BlockRecord(
                    ip=ip,
                    rule_name=rule_name,
                    reason=reason,
                    blocked_at=now,
                    unblock_at=unblock_at,
                    auto_unblock=duration_hours > 0,
                )
                self._trim_blocks_locked()

            self._block_timestamps.append(now)
            self._stats["blocks_applied"] += 1
            log(f"[AUTO-RESPONSE] 🚫 Blocked: {ip} — {reason} "
                f"(auto-unblock: {duration_hours}h)")

            try:
                from client_block_store import upsert_block
                upsert_block(
                    ip,
                    rule_name=rule_name,
                    source="auto_response",
                    reason=reason or "auto_block",
                    blocked_at=now,
                )
            except Exception:
                pass

            # Report to API (auto-block + block-applied)
            self._report_block_to_api(ip, reason, duration_hours)
            self._report_block_applied(ip, rule_name)
            return True
        else:
            self._stats["errors"] += 1
            log(f"[AUTO-RESPONSE] ❌ Failed to block: {ip}")
            return False

    def _trim_blocks_locked(self, max_blocks: int = 500) -> int:
        """Cap in-memory block dict (call with _lock held). Drop temporary first."""
        if len(self._blocks) <= max_blocks:
            return 0

        def _evict_prio(b: BlockRecord) -> int:
            if b.auto_unblock:
                return 0
            if (b.reason or "").startswith("firewall"):
                return 2  # keep firewall/persist longest
            return 1

        items = sorted(
            self._blocks.values(),
            key=lambda b: (_evict_prio(b), b.blocked_at),
        )
        drop_n = len(self._blocks) - max_blocks
        removed = 0
        for rec in items[:drop_n]:
            self._blocks.pop(rec.ip, None)
            removed += 1
        if removed:
            log(f"[AUTO-RESPONSE] 🧹 trimmed {removed} in-memory blocks "
                f"(cap={max_blocks})")
        return removed

    def trim_blocks(self, max_blocks: int = 500) -> int:
        """MemoryGuard / cleanup hook."""
        with self._lock:
            return self._trim_blocks_locked(max_blocks)

    def unblock_ip(self, ip: str) -> bool:
        """Remove firewall block for an IP (all known rule-name variants)."""
        with self._lock:
            record = self._blocks.pop(ip, None)

        rule_names = []
        if record and getattr(record, "rule_name", None):
            rule_names.append(record.rule_name)
        try:
            from client_firewall import WindowsFirewallBackend
            for n in WindowsFirewallBackend.rule_name_candidates("", ip):
                if n not in rule_names:
                    rule_names.append(n)
        except Exception:
            rule_names.append(f"{FIREWALL_RULE_PREFIX}-{ip}")

        # Also drop any AR/HP-INTEL rules whose RemoteIP matches this host.
        try:
            from client_firewall import WindowsFirewallBackend
            import logging as _logging
            be = WindowsFirewallBackend(_logging.getLogger("honeypot.wl_unblock"))
            for r in be.list_intel_rules() or []:
                remote = str(r.get("remoteip") or "")
                name = str(r.get("name") or "")
                if not name:
                    continue
                ip_root = (ip or "").split("/")[0]
                if ip_root and (ip_root == remote.split("/")[0] or ip_root in remote.replace(" ", "")):
                    if name not in rule_names:
                        rule_names.append(name)
        except Exception:
            pass

        success = False
        hard_fail = False
        for rule_name in rule_names:
            # Prefer delete without dir= so in+out INTEL pairs clear together
            cmds = [
                [
                    "netsh", "advfirewall", "firewall", "delete", "rule",
                    f"name={rule_name}",
                ],
                [
                    "netsh", "advfirewall", "firewall", "delete", "rule",
                    f"name={rule_name}", "dir=in",
                ],
            ]
            for cmd in cmds:
                ok, out = self._run_system_cmd_detail(cmd)
                combined = (out or "").lower()
                if ok:
                    if "0 rule" not in combined:
                        success = True
                    if "0 rule" in combined or "no rules match" in combined:
                        success = success or True
                else:
                    if any(x in combined for x in ("no rules match", "not found", "bulunamad")):
                        success = True  # already gone
                    elif any(x in combined for x in ("access", "denied", "privilege")):
                        hard_fail = True

        if success or not hard_fail:
            # Treat pure-missing as success
            if not hard_fail:
                success = True
            self._stats["blocks_removed"] += 1
            log(f"[AUTO-RESPONSE] ✅ Unblocked: {ip}")
            try:
                from client_block_store import remove_block
                remove_block(ip)
            except Exception:
                pass
            self._report_unblock_to_api(ip)
            return True
        log(f"[AUTO-RESPONSE] ❌ Unblock failed: {ip}")
        return False

    def forget_block(self, ip: str) -> None:
        """Drop IP from local block cache only (firewall already handled)."""
        with self._lock:
            self._blocks.pop(ip, None)
        try:
            from client_block_store import remove_block
            remove_block(ip)
        except Exception:
            pass

    def clear_all_blocks(self, report_api: bool = False) -> int:
        """Remove all tracked firewall blocks (maintenance cleanup).

        By default skips per-IP API reports; caller syncs empty list / clear-data.
        """
        with self._lock:
            items = list(self._blocks.items())
            self._blocks.clear()

        removed = 0
        for ip, record in items:
            rule_name = getattr(record, "rule_name", None) or f"{FIREWALL_RULE_PREFIX}-{ip}"
            cmd = [
                "netsh", "advfirewall", "firewall", "delete", "rule",
                f"name={rule_name}", "dir=in",
            ]
            if self._run_system_cmd(cmd):
                removed += 1
                self._stats["blocks_removed"] += 1
                if report_api:
                    try:
                        self._report_unblock_to_api(ip)
                    except Exception:
                        pass
        log(f"[AUTO-RESPONSE] Cleared {removed}/{len(items)} blocks (maintenance)")
        return removed

    # ── Session Management ────────────────────────────────────────

    def logoff_user(self, username: str, *, auto: bool = False) -> bool:
        """Force logoff all sessions for user (Active + Disc), including Administrator.

        ``auto=True`` marks local critical auto paths (alerts / silent-hours /
        logon-challenge). Those require a fresh account link (C-BRICK-1).
        """
        if not (username or "").strip():
            return False

        if auto and not self._allow_local_critical_auto("logoff_user", username):
            return False

        try:
            session_ids: list = []
            for tool in ("user", "session"):
                _rc, _out, _ = run_hidden(["query", tool], timeout=10)
                for line in (_out or "").splitlines()[1:]:
                    parts = line.split()
                    if not parts:
                        continue
                    tokens = [p.lstrip(">") for p in parts]
                    matched = False
                    uname = username.lower().lstrip(">")
                    for tok in tokens:
                        tl = tok.lower()
                        if tl == uname:
                            matched = True
                            break
                        for sep in ("\\", "/"):
                            if sep in tl and tl.rsplit(sep, 1)[-1] == uname:
                                matched = True
                                break
                            if sep in uname and uname.rsplit(sep, 1)[-1] == tl:
                                matched = True
                                break
                        if matched:
                            break
                    if not matched:
                        continue
                    for p in parts:
                        if p.isdigit() and p != "0" and p not in session_ids:
                            session_ids.append(p)
                            break

            if not session_ids:
                log(f"[AUTO-RESPONSE] No active session found for: {username}")
                return False

            any_ok = False
            for session_id in session_ids:
                logoff_rc, _, _ = run_hidden(["logoff", session_id], timeout=10)
                still = self._session_id_present(session_id)
                if logoff_rc != 0 or still:
                    for cmd in (
                        ["reset", "session", session_id],
                        ["rwinsta", session_id],
                    ):
                        run_hidden(cmd, timeout=10)
                        if not self._session_id_present(session_id):
                            break
                if not self._session_id_present(session_id):
                    any_ok = True
                    self._stats["logoffs_executed"] += 1
                    log(f"[AUTO-RESPONSE] 🚪 Logged off: {username} (session {session_id})")
                else:
                    log(f"[AUTO-RESPONSE] Logoff incomplete for {username} session {session_id}")

            return any_ok

        except Exception as e:
            self._stats["errors"] += 1
            log(f"[AUTO-RESPONSE] Logoff error for {username}: {e}")
            return False

    @staticmethod
    def _session_id_present(session_id: str) -> bool:
        try:
            _qrc, qout, _ = run_hidden(["query", "session"], timeout=8)
            for line in (qout or "").splitlines()[1:]:
                parts = line.split()
                if session_id in parts:
                    low = [p.lower() for p in parts]
                    if "listen" in low:
                        continue
                    return True
            return False
        except Exception:
            return True

    # ── Account Management ────────────────────────────────────────

    def _allow_local_critical_auto(self, action: str, username: str = "") -> bool:
        """C-BRICK-1: local critical auto only when account is freshly linked."""
        try:
            from client_brick_guard import (
                account_linked_for_auto,
                emit_skipped_unlinked,
            )

            tok = ""
            try:
                tok = (self.token_getter() or "") if self.token_getter else ""
            except Exception:
                tok = ""
            if account_linked_for_auto(token=tok, api_client=self.api_client):
                return True
            self._stats["skipped_unlinked"] = self._stats.get("skipped_unlinked", 0) + 1
            self._last_disable_error = "SKIPPED_UNLINKED"
            emit_skipped_unlinked(
                self.alert_pipeline,
                action=action,
                username=username,
            )
            return False
        except Exception as e:
            log(f"[AUTO-RESPONSE] linked gate error (fail-closed): {e}")
            self._stats["skipped_unlinked"] = self._stats.get("skipped_unlinked", 0) + 1
            self._last_disable_error = "SKIPPED_UNLINKED"
            return False

    def disable_account(
        self,
        username: str,
        *,
        allow_privileged: bool = False,
        force_last_admin: bool = False,
    ) -> bool:
        """Disable a Windows user account.

        ``allow_privileged=True`` is reserved for cloud IR with confirm:true.
        Local alert / silent-hours auto paths must leave it False so
        Administrator (and other safe accounts) cannot be auto-disabled.

        C-BRICK-1: auto path requires fresh account_linked.
        C-BRICK-6: refuse (or rollback) closing the last enabled admin.
        """
        self._last_disable_error = None
        uname = (username or "").strip()
        if not uname:
            return False
        upper = uname.upper()
        if upper in PROTECTED_ACCOUNTS:
            log(f"[AUTO-RESPONSE] ⚪ Cannot disable protected account: {uname}")
            self._last_disable_error = "PROTECTED_ACCOUNT"
            return False
        if not allow_privileged:
            if not self._allow_local_critical_auto("disable_account", uname):
                return False
            # C-BRICK-1.3: admin-class needs peer admin or live undo-mail path.
            try:
                from client_brick_guard import (
                    admin_class_break_glass_ok,
                    emit_skipped_no_break_glass,
                    is_enabled_local_admin,
                    probe_undo_mail_path,
                )

                tok = ""
                try:
                    tok = (self.token_getter() or "") if self.token_getter else ""
                except Exception:
                    tok = ""
                if is_enabled_local_admin(uname):
                    if not admin_class_break_glass_ok(
                        uname, token=tok, api_client=self.api_client
                    ):
                        self._stats["skipped_no_break_glass"] = (
                            self._stats.get("skipped_no_break_glass", 0) + 1
                        )
                        self._last_disable_error = "NO_BREAK_GLASS"
                        emit_skipped_no_break_glass(
                            self.alert_pipeline,
                            action="disable_account",
                            username=uname,
                        )
                        return False
                # RID-500 / well-known names: still require undo-mail even when
                # another admin exists (extra caution for built-in Administrator).
                if upper in AUTO_SAFE_ACCOUNTS:
                    if not probe_undo_mail_path(
                        token=tok, api_client=self.api_client
                    ):
                        log(
                            f"[AUTO-RESPONSE] ⛔ Refusing auto-disable of privileged "
                            f"account {uname} (undo_mail_path not live)"
                        )
                        self._stats["skipped_no_break_glass"] = (
                            self._stats.get("skipped_no_break_glass", 0) + 1
                        )
                        self._last_disable_error = "NO_BREAK_GLASS"
                        emit_skipped_no_break_glass(
                            self.alert_pipeline,
                            action="disable_account",
                            username=uname,
                        )
                        return False
            except Exception as e:
                log(f"[AUTO-RESPONSE] break-glass gate error (fail-closed): {e}")
                self._last_disable_error = "NO_BREAK_GLASS"
                return False

        # C-BRICK-6: never close the last admin path without undo-mail break-glass
        if not force_last_admin:
            try:
                from client_brick_guard import (
                    probe_undo_mail_path,
                    would_close_last_admin,
                )

                if would_close_last_admin(uname):
                    tok = ""
                    try:
                        tok = (self.token_getter() or "") if self.token_getter else ""
                    except Exception:
                        tok = ""
                    if not probe_undo_mail_path(token=tok, api_client=self.api_client):
                        self._stats["last_admin_refused"] = (
                            self._stats.get("last_admin_refused", 0) + 1
                        )
                        self._last_disable_error = "LAST_ADMIN"
                        log(
                            f"[AUTO-RESPONSE] ⛔ Refusing disable of last admin "
                            f"{uname} (C-BRICK-6 / no undo_mail_path)"
                        )
                        return False
            except Exception as e:
                log(f"[AUTO-RESPONSE] last-admin check error (refuse): {e}")
                self._last_disable_error = "LAST_ADMIN"
                return False

        cmd = ["net", "user", uname, "/active:no"]
        success = self._run_system_cmd(cmd)
        if success:
            # Rollback if host left with zero enabled admins
            if not force_last_admin:
                try:
                    from client_brick_guard import (
                        count_enabled_local_admins,
                        emit_critical_action_rolled_back,
                    )

                    if count_enabled_local_admins() < 1:
                        log(
                            f"[AUTO-RESPONSE] ♻️ Rollback disable of {uname} — "
                            f"no enabled admin left (C-BRICK-6)"
                        )
                        self.enable_account(uname)
                        self._stats["last_admin_rollback"] = (
                            self._stats.get("last_admin_rollback", 0) + 1
                        )
                        self._last_disable_error = "LAST_ADMIN"
                        emit_critical_action_rolled_back(
                            self.alert_pipeline,
                            action="disable_account",
                            username=uname,
                            reason="zero_enabled_admin_after_disable",
                        )
                        return False
                except Exception as e:
                    log(f"[AUTO-RESPONSE] last-admin rollback check error: {e}")
            self._stats["accounts_disabled"] += 1
            log(f"[AUTO-RESPONSE] 🔒 Account disabled: {uname}")
        return success

    def enable_account(self, username: str) -> bool:
        """Re-enable a Windows user account."""
        cmd = ["net", "user", username, "/active:yes"]
        success = self._run_system_cmd(cmd)
        if success:
            log(f"[AUTO-RESPONSE] 🔓 Account enabled: {username}")
        return success

    # ── Emergency Lockdown ────────────────────────────────────────

    def emergency_lockdown(self, management_ip: str,
                           duration_minutes: int = 60) -> bool:
        """
        Block ALL inbound traffic except from management IP.
        Use with extreme caution — only for active ransomware/compromise.
        """
        if not management_ip:
            log("[AUTO-RESPONSE] ❌ Lockdown requires management_ip")
            return False

        if self._lockdown_active:
            log("[AUTO-RESPONSE] Lockdown already active")
            return True

        # Add rule: block all inbound
        cmd_block = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            "name=HONEYPOT_LOCKDOWN_BLOCK", "dir=in", "action=block",
            "enable=yes",
        ]
        # Add rule: allow management IP
        cmd_allow = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            "name=HONEYPOT_LOCKDOWN_ALLOW", "dir=in", "action=allow",
            f"remoteip={management_ip}", "enable=yes",
        ]

        if self._run_system_cmd(cmd_allow) and self._run_system_cmd(cmd_block):
            self._lockdown_active = True
            self._lockdown_management_ip = management_ip
            log(f"[AUTO-RESPONSE] 🛑 EMERGENCY LOCKDOWN — only {management_ip} can access")

            # Schedule auto-lift
            if duration_minutes > 0:
                threading.Timer(
                    duration_minutes * 60,
                    self.lift_lockdown,
                ).start()

            return True

        self._stats["errors"] += 1
        return False

    def lift_lockdown(self) -> bool:
        """Remove emergency lockdown rules."""
        if not self._lockdown_active:
            return True

        cmd1 = [
            "netsh", "advfirewall", "firewall", "delete", "rule",
            "name=HONEYPOT_LOCKDOWN_BLOCK", "dir=in",
        ]
        cmd2 = [
            "netsh", "advfirewall", "firewall", "delete", "rule",
            "name=HONEYPOT_LOCKDOWN_ALLOW", "dir=in",
        ]
        self._run_system_cmd(cmd1)
        self._run_system_cmd(cmd2)
        self._lockdown_active = False
        self._lockdown_management_ip = None
        log("[AUTO-RESPONSE] ✅ Lockdown lifted — normal traffic restored")
        return True

    # ── Whitelist Management ──────────────────────────────────────

    def update_whitelist(self, ips: Set[str], subnets: Optional[List[str]] = None):
        """Update whitelist IPs and subnets (thread-safe).

        Immediately clears existing AR/HP BLOCK and INTEL rules for those IPs.
        """
        self.whitelist_ips = set(ips or set())
        if subnets is not None:
            self.whitelist_subnets = list(subnets)
        try:
            n = self.enforce_whitelist_unblocks()
            if n:
                log(f"[AUTO-RESPONSE] Whitelist enforce: cleared {n} block(s)")
        except Exception as e:
            log(f"[AUTO-RESPONSE] Whitelist enforce error: {e}")

    def enforce_whitelist_unblocks(self) -> int:
        """Remove firewall blocks for every currently whitelisted IP (idempotent)."""
        targets: Set[str] = set()
        with self._lock:
            targets |= set(self.whitelist_ips or set())
            # In-memory blocks that match whitelist/subnets
            for ip in list(self._blocks.keys()):
                if self._is_whitelisted(ip):
                    targets.add(ip)

        cleared = 0
        for ip in sorted(targets):
            if not ip or ip in ("127.0.0.1", "::1"):
                continue
            try:
                # Always attempt delete — unblock_ip is idempotent
                if self.unblock_ip(ip):
                    cleared += 1
            except Exception as e:
                log(f"[AUTO-RESPONSE] whitelist unblock {ip}: {e}")
        return cleared

    def apply_threat_config(self, config: dict):
        """Apply GET /api/threats/config auto-block fields."""
        if not isinstance(config, dict):
            return
        if "auto_block_enabled" in config:
            self.auto_block_enabled = bool(config.get("auto_block_enabled"))
        if "auto_block_threshold" in config:
            try:
                self.auto_block_threshold = int(config.get("auto_block_threshold", 80))
            except (TypeError, ValueError):
                pass
        if "auto_block_duration_hours" in config:
            try:
                self.auto_block_duration_hours = int(config.get("auto_block_duration_hours", 24))
            except (TypeError, ValueError):
                pass
        if "max_auto_blocks_per_hour" in config:
            try:
                self.max_blocks_per_hour = int(config.get("max_auto_blocks_per_hour", 50))
            except (TypeError, ValueError):
                pass
        if "max_auto_blocks_per_day" in config:
            try:
                self.max_blocks_per_day = int(config.get("max_auto_blocks_per_day", 200))
            except (TypeError, ValueError):
                pass
        log(
            f"[AUTO-RESPONSE] Config applied — enabled={self.auto_block_enabled} "
            f"threshold={self.auto_block_threshold} duration={self.auto_block_duration_hours}h "
            f"limits={self.max_blocks_per_hour}/h {self.max_blocks_per_day}/d"
        )

    def _is_whitelisted(self, ip: str) -> bool:
        """Check if IP is whitelisted (exact match or subnet)."""
        if ip in self.whitelist_ips:
            return True
        if ip in ("127.0.0.1", "::1", ""):
            return True
        try:
            addr = ipaddress.ip_address(ip)
            for subnet_str in self.whitelist_subnets:
                try:
                    if addr in ipaddress.ip_network(subnet_str, strict=False):
                        return True
                except ValueError:
                    continue
        except ValueError:
            pass
        return False

    # ── Rate Limiting ─────────────────────────────────────────────

    def _check_rate_limit(self) -> bool:
        """Check hourly and daily block rate limits."""
        now = time.time()
        hour_ago = now - 3600
        day_ago = now - 86400

        recent = [t for t in self._block_timestamps if t >= day_ago]
        hourly = [t for t in recent if t >= hour_ago]

        if len(hourly) >= getattr(self, "max_blocks_per_hour", MAX_BLOCKS_PER_HOUR):
            return False
        if len(recent) >= getattr(self, "max_blocks_per_day", MAX_BLOCKS_PER_DAY):
            return False
        return True

    # ── Auto-Unblock Scheduler ────────────────────────────────────

    def _unblock_scheduler_loop(self):
        """Check for expired blocks every 60 seconds."""
        while self._running:
            try:
                self._process_expired_blocks()
            except Exception as e:
                log(f"[AUTO-RESPONSE] Unblock scheduler error: {e}")
            time.sleep(60)

    def _process_expired_blocks(self):
        """Remove blocks that have exceeded their duration."""
        now = time.time()
        expired = []

        with self._lock:
            for ip, record in self._blocks.items():
                if record.auto_unblock and record.unblock_at > 0 and now >= record.unblock_at:
                    expired.append(ip)

        for ip in expired:
            log(f"[AUTO-RESPONSE] ⏰ Auto-unblocking expired: {ip}")
            self.unblock_ip(ip)

    # ── API Reporting ─────────────────────────────────────────────

    def _report_block_to_api(self, ip: str, reason: str, duration_hours: int):
        """Report block action to API (fire-and-forget).

        Canonical: POST /api/alerts/auto-block
        """
        if not self.api_client:
            return

        def _send():
            try:
                token = self.token_getter()
                if not token:
                    return

                from datetime import datetime, timezone
                blocked_at = datetime.now(timezone.utc).isoformat()
                rule_name = f"{FIREWALL_RULE_PREFIX}-{ip}"

                payload = {
                    "token": token,
                    "blocked_ip": ip,
                    "reason": reason,
                    "threat_score": 90,
                    "duration_hours": duration_hours,
                    "blocked_at": blocked_at,
                    "firewall_rule_name": rule_name,
                }
                result = self.api_client.api_request(
                    "POST", "alerts/auto-block", data=payload
                )
                if result:
                    log(f"[AUTO-RESPONSE] ✅ Block reported to API: {ip}")
                else:
                    log(f"[AUTO-RESPONSE] ⚠️ Block report failed for: {ip}")
            except Exception as e:
                log(f"[AUTO-RESPONSE] API report error: {e}")

        from client_helpers import submit_background
        submit_background(_send)

    def _report_unblock_to_api(self, ip: str):
        """Report unblock — prefer agent/block-removed (cloud ACK)."""
        if not self.api_client:
            return

        def _send():
            try:
                token = self.token_getter()
                if not token:
                    return

                from datetime import datetime, timezone
                result = self.api_client.api_request(
                    "POST", "agent/block-removed",
                    data={"token": token, "ip": ip},
                )
                if isinstance(result, dict):
                    updated = result.get("updated")
                    log(
                        f"[AUTO-RESPONSE] ✅ block-removed reported: {ip} "
                        f"updated={updated}"
                    )
                    if updated == 0:
                        log(
                            f"[AUTO-RESPONSE] ⚠️ block-removed updated=0 for {ip} "
                            f"— cloud row may stay in 'removing' (dashboard)"
                        )
                    return
                if result:
                    log(f"[AUTO-RESPONSE] ✅ block-removed reported: {ip}")
                    return
                payload = {
                    "token": token,
                    "blocked_ip": ip,
                    "unblocked_at": datetime.now(timezone.utc).isoformat(),
                }
                alt = self.api_client.api_request(
                    "POST", "v4/auto-unblock", data=payload
                )
                if alt:
                    log(f"[AUTO-RESPONSE] ✅ Unblock reported (legacy): {ip}")
                else:
                    log(f"[AUTO-RESPONSE] ⚠️ Unblock report failed for: {ip}")
            except Exception as e:
                log(f"[AUTO-RESPONSE] API unblock report error: {e}")

        from client_helpers import submit_background
        submit_background(_send)

    def _report_block_applied(self, ip: str, rule_name: str):
        """Report block-applied to API (same endpoint as FirewallAgent).

        POST /api/agent/block-applied
        Body: {token, ip, rule_name, blocked_at (ISO)}
        """
        if not self.api_client:
            return

        def _send():
            try:
                token = self.token_getter()
                if not token:
                    return

                from datetime import datetime, timezone
                payload = {
                    "token": token,
                    "ip": ip,
                    "rule_name": rule_name,
                    "blocked_at": datetime.now(timezone.utc).isoformat(),
                    "source": "auto_response",
                }
                result = self.api_client.api_request(
                    "POST", "agent/block-applied", data=payload
                )
                if result:
                    log(f"[AUTO-RESPONSE] ✅ block-applied reported: {ip}")
                else:
                    log(f"[AUTO-RESPONSE] ⚠️ block-applied report failed: {ip}")
            except Exception as e:
                log(f"[AUTO-RESPONSE] block-applied error: {e}")

        from client_helpers import submit_background
        submit_background(_send)

    # ── System Command Runner ─────────────────────────────────────

    @staticmethod
    def _run_system_cmd(cmd: list, timeout: int = 15) -> bool:
        """Run a system command and return success status."""
        ok, _ = AutoResponse._run_system_cmd_detail(cmd, timeout=timeout)
        return ok

    @staticmethod
    def _run_system_cmd_detail(cmd: list, timeout: int = 15):
        """Run command; return (ok: bool, combined_output: str)."""
        try:
            rc, out, err = run_hidden(cmd, timeout=timeout)
            combined = f"{out or ''}\n{err or ''}"
            return rc == 0, combined
        except Exception as e:
            log(f"[AUTO-RESPONSE] Command error: {e}")
            return False, str(e)

    # ── Password Generation ───────────────────────────────────────

    @staticmethod
    def generate_strong_password(length: int = 16) -> str:
        """Generate a cryptographically strong random password."""
        chars = string.ascii_letters + string.digits + "!@#$%&*"
        while True:
            pwd = ''.join(secrets.choice(chars) for _ in range(length))
            if (any(c.isupper() for c in pwd) and any(c.islower() for c in pwd)
                    and any(c.isdigit() for c in pwd)
                    and any(c in "!@#$%&*" for c in pwd)):
                return pwd
