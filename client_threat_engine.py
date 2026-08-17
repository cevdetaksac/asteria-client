#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Asteria Client — Threat Detection Engine (v4.0)

Receives structured events from EventLogWatcher and performs:
  1. Enrichment   — add context (IP history, service info)
  2. Scoring      — assign threat score per event type
  3. Correlation  — detect multi-event attack patterns
  4. Decision     — emit ThreatAlert when threshold exceeded

IP-based context pool tracks cumulative threat score, failed/successful
login counts, targeted services, and recent event history per source IP.

Exports:
  ThreatEngine  — main engine class (process_event / get_ip_context / get_recent_threats)
  IPContext      — per-IP state dataclass
"""

import threading
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set, Tuple

from client_helpers import log

# ── Threat Scores ─────────────────────────────────────────────────

THREAT_SCORES: Dict[str, int] = {
    # Authentication — bare success is alert-worthy, NEVER critical/100 alone.
    # Caps enforced in _calculate_score / should_auto_block (contract: office RDP).
    "successful_logon":                45,   # Interactive / generic 4624
    "successful_logon_rdp":             55,   # RemoteInteractive — external/new IP band
    "successful_logon_network":         40,
    "successful_logon_sql":             50,
    "failed_logon_single":               5,
    "failed_logon_burst":               40,   # 10+ failures in 5 min
    "failed_then_success":              95,   # Brute then success — MAY block

    # Privilege escalation / identity
    "new_user_created":                 90,
    "user_added_to_admin_group":        90,
    "privilege_assigned":               75,
    "security_group_changed":           70,
    "password_change_attempt":          70,
    "password_reset_attempt":           80,

    # Persistence
    "new_service_installed":            65,
    "service_start_type_changed":       50,
    "new_process_suspicious":           55,

    # Anti-forensics
    "audit_log_cleared":               100,
    "unexpected_restart":               50,

    # SQL-specific
    "sql_successful_logon":             50,
    "sql_failed_logon":                  5,
    "xp_cmdshell_executed":            100,   # Command execution via SQL

    # RDP-specific (session noise — keep below auto-block threshold)
    "rdp_connection_succeeded":         50,
    "rdp_session_logon":                45,
    "rdp_session_reconnect":            35,

    # Honeypot-specific
    "honeypot_credential":              90,   # Anyone hitting a honeypot is malicious
}

# Bare successful-logon score ceilings (100 reserved for canary/VSS/tamper/ransomware)
SUCCESS_LOGON_SCORE_CAP = 70          # new / external IP
SUCCESS_LOGON_SCORE_CAP_SILENT = 80   # during silent hours (still no auto-block)

# Correlation / threat_type aliases that mean "bare success" (no block)
BARE_SUCCESS_TYPES: Set[str] = {
    "successful_logon",
    "successful_logon_rdp",
    "successful_logon_network",
    "successful_logon_sql",
    "sql_successful_logon",
    "rdp_connection_succeeded",
    "rdp_session_logon",
    "rdp_session_reconnect",
    "rdp_login_success",
    "explicit_credential_logon",
}

# Correlation rules that MAY auto-block after a successful logon
BLOCKABLE_SUCCESS_CORRELATIONS: Set[str] = {
    "brute_force_then_access",
    "honeypot_brute_force",
    "post_exploitation",
    # lateral_movement kept alert-elevated but block only with prior fails — see should_auto_block
}

# Correlation rule definitions
CORRELATION_RULES = [
    {
        "name": "brute_force_then_access",
        "description": "Brute force followed by successful login — account compromised!",
        "precondition": "failed_logon",
        "precondition_count": 5,
        "precondition_window": 600,          # 10 min
        "trigger": "successful_logon",
        "trigger_window": 1800,              # 30 min
        "same_ip": True,
        "score": 95,
        "severity": "critical",
        "auto_response": ["block_ip", "notify_urgent"],
    },
    {
        "name": "rdp_after_hours",
        "description": "RDP access during off-hours (00:00-06:00)",
        "precondition": None,
        "trigger": "rdp_logon",
        "time_range": (0, 6),                # midnight to 6am
        "score": 60,
        "severity": "high",
        "auto_response": ["notify_urgent"],
    },
    {
        "name": "lateral_movement",
        "description": "Successful logins to 2+ services from same IP",
        "precondition": None,
        "trigger": "multi_service_logon",
        "distinct_services": 2,
        "window": 3600,                      # 1 hour
        "score": 75,
        "severity": "high",
        "auto_response": ["notify_urgent"],  # alert only — bare multi-service ≠ HP-BLOCK
    },
    {
        "name": "post_exploitation",
        "description": "New service/user creation after successful login",
        "precondition": "successful_logon",
        "precondition_count": 1,
        "precondition_window": 3600,
        "trigger": "persistence_action",     # new service OR new user
        "trigger_window": 3600,
        "same_ip": True,
        "score": 95,
        "severity": "critical",
        "auto_response": ["block_ip", "notify_urgent"],
    },
    {
        "name": "honeypot_brute_force",
        "description": "Multiple honeypot hits from same IP — active attacker",
        "precondition": None,
        "trigger": "honeypot_credential",
        "precondition_count": 3,
        "precondition_window": 600,          # 10 min
        "score": 95,
        "severity": "critical",
        "auto_response": ["block_ip", "notify_urgent"],
    },
]

# Severity thresholds for standalone events
SEVERITY_THRESHOLDS = {
    "critical": 81,
    "high":     61,
    "warning":  31,
    "info":      0,
}

# Events that qualify as "successful logon" for correlation
LOGON_EVENT_TYPES: Set[str] = {
    "successful_logon", "successful_logon_rdp", "successful_logon_network",
    "sql_successful_logon", "rdp_connection_succeeded", "rdp_session_logon",
    "explicit_credential_logon",
}

# Trusted / local logon noise — info only (CLIENT_ALERT_SIGNAL_HYGIENE.md §6)
TRUSTED_LOGON_NOISE_TYPES: Set[str] = {
    "successful_logon",
    "successful_logon_rdp",
    "successful_logon_network",
    "successful_logon_sql",
    "sql_successful_logon",
    "explicit_credential_logon",
    "privilege_assigned",
    "rdp_connection_succeeded",
    "rdp_session_logon",
    "rdp_login_success",
}
TRUSTED_LOGON_SCORE_CAP = 10
_LOCAL_IP_KEYS = frozenset({"local", "", "127.0.0.1", "::1", "localhost"})


def is_trusted_logon_source(ip_key: str, whitelist: Optional[Set[str]] = None) -> bool:
    """Whitelist or local/loopback — trusted logon noise (info ≤10)."""
    key = (ip_key or "").strip().lower()
    if key in _LOCAL_IP_KEYS:
        return True
    if whitelist and ip_key in whitelist:
        return True
    if whitelist and key in {w.lower() for w in whitelist}:
        return True
    return False


# These must always reach API immediately (POST /api/alerts/urgent)
URGENT_IMMEDIATE_TYPES: Set[str] = LOGON_EVENT_TYPES | {
    "audit_log_cleared",
    "xp_cmdshell_executed",
    "honeypot_credential",
    "new_user_created",
    "user_added_to_admin_group",
    "failed_then_success",
}

# Events that qualify as "failed logon"
FAILED_LOGON_TYPES: Set[str] = {
    "failed_logon", "sql_failed_logon",
}

# Events that qualify as "persistence action"
PERSISTENCE_TYPES: Set[str] = {
    "new_service_installed", "new_user_created", "user_added_to_admin_group",
    "service_start_type_changed",
}

# Events related to RDP
RDP_LOGON_TYPES: Set[str] = {
    "rdp_connection_succeeded", "rdp_session_logon", "rdp_session_reconnect",
    "successful_logon_rdp",
}

# Context pool cleanup interval (seconds)
CONTEXT_CLEANUP_INTERVAL = 300       # 5 min
# Max age for IP context entries without new events
CONTEXT_MAX_AGE = 86400              # 24 hours


def should_auto_block(
    event_type: str,
    *,
    correlation_rule: str = "",
    failed_attempts: int = 0,
    is_whitelisted: bool = False,
    is_honeypot: bool = False,
    operator_forced: bool = False,
) -> bool:
    """Decide whether this event may create an HP-BLOCK firewall rule.

    Bare successful_logon / rdp success → never.
    Block only for: brute_force_then_success (correlation / failed_then_success),
    honeypot IOC, protection.block_rules path (caller), or explicit operator command.
    """
    if is_whitelisted:
        return False
    if operator_forced:
        return True
    if is_honeypot or event_type == "honeypot_credential":
        return True
    et = (event_type or "").strip().lower()
    rule = (correlation_rule or "").strip()
    if rule in ("brute_force_then_access", "honeypot_brute_force", "post_exploitation"):
        return True
    if et == "failed_then_success" or (
        et in BARE_SUCCESS_TYPES and failed_attempts >= 3 and rule == "brute_force_then_access"
    ):
        return True
    # Bare success family — alert / challenge / email only
    if et in BARE_SUCCESS_TYPES or et in {
        "successful_logon", "rdp_login_success",
    }:
        return False
    if et in LOGON_EVENT_TYPES:
        return False
    # Critical non-auth (audit clear, xp_cmdshell, etc.) still block via severity path
    return True

# Default block rules when no API rules are configured.
# Her servis için ideal varsayılan koruma — kullanıcı dashboard'dan özelleştirebilir.
DEFAULT_BLOCK_RULES = [
    {
        "name": "default_rdp",
        "services": "RDP",
        "threshold_count": 3,
        "window_minutes": 30,
        "actions": "email,block",
        "enabled": True,
    },
    {
        "name": "default_mssql",
        "services": "MSSQL",
        "threshold_count": 3,
        "window_minutes": 30,
        "actions": "email,block",
        "enabled": True,
    },
    {
        "name": "default_ssh",
        "services": "SSH",
        "threshold_count": 3,
        "window_minutes": 30,
        "actions": "email,block",
        "enabled": True,
    },
    {
        "name": "default_ftp",
        "services": "FTP",
        "threshold_count": 3,
        "window_minutes": 30,
        "actions": "email,block",
        "enabled": True,
    },
    {
        "name": "default_mysql",
        "services": "MYSQL",
        "threshold_count": 3,
        "window_minutes": 30,
        "actions": "email,block",
        "enabled": True,
    },
    # Network (LogonType 3) — yüksek eşik değeri ile otomatik blok.
    # SMB/dosya paylaşımı gibi meşru erişimlerden false positive önlenir.
    {
        "name": "default_network",
        "services": "Network",
        "threshold_count": 10,
        "window_minutes": 30,
        "actions": "email,block",
        "enabled": True,
    },
]


# ── IP Context ────────────────────────────────────────────────────

# Maximum number of usernames to track per IP (memory cap)
_MAX_USERNAMES_PER_IP = 100


@dataclass
class IPContext:
    """Per-IP accumulated threat context."""
    ip: str
    first_seen: float = 0.0
    last_seen: float = 0.0
    failed_attempts: int = 0
    successful_logins: int = 0
    services_targeted: Set[str] = field(default_factory=set)
    usernames_tried: Set[str] = field(default_factory=set)
    threat_score: float = 0.0
    events: deque = field(default_factory=lambda: deque(maxlen=100))
    is_blocked: bool = False
    alerts_sent: int = 0
    last_alert_time: float = 0.0

    def add_event(self, event: dict, score: float):
        """Record an event and update counters."""
        now = time.time()
        self.last_seen = now
        if not self.first_seen:
            self.first_seen = now

        self.threat_score = min(100.0, self.threat_score + score)
        # Cap cumulative score when only bare-success noise is stacking
        etype = event.get("event_type", "")
        if etype in BARE_SUCCESS_TYPES or etype in LOGON_EVENT_TYPES:
            # Allow climb above success cap only once failed_then_success / non-auth added score
            if self.failed_attempts < 3 and score < 90:
                self.threat_score = min(float(SUCCESS_LOGON_SCORE_CAP_SILENT), self.threat_score)
        self.events.append({
            "event_type": event.get("event_type", ""),
            "event_id": event.get("event_id", 0),
            "timestamp": now,
            "score": score,
            "target_service": (
                event.get("target_service", "") or event.get("service", "") or ""
            ),
        })

        # Update counters
        if etype in FAILED_LOGON_TYPES or etype == "failed_logon_single":
            self.failed_attempts += 1
        if etype in LOGON_EVENT_TYPES:
            self.successful_logins += 1

        svc = event.get("target_service", "") or event.get("service", "")
        if svc:
            self.services_targeted.add(svc)

        uname = event.get("username", "")
        if uname:
            if len(self.usernames_tried) < _MAX_USERNAMES_PER_IP:
                self.usernames_tried.add(uname)

    def get_recent_events(self, window_seconds: int) -> List[dict]:
        """Get events within the last N seconds."""
        cutoff = time.time() - window_seconds
        return [e for e in self.events if e["timestamp"] >= cutoff]

    def decay_score(self, amount: float = 1.0):
        """Reduce threat score over time (called periodically)."""
        self.threat_score = max(0.0, self.threat_score - amount)


# ── Threat Engine ─────────────────────────────────────────────────

class ThreatEngine:
    """
    Stateful threat detection engine.

    Usage:
        engine = ThreatEngine(on_alert=alert_pipeline.handle_alert)
        engine.start()  # starts housekeeping thread
        # ... events fed via process_event() from EventLogWatcher ...
        engine.stop()
    """

    def __init__(self, on_alert: Optional[Callable] = None,
                 on_auth_fail_report: Optional[Callable] = None):
        """
        Args:
            on_alert:  Callback receiving (alert_dict, ip_context) when threshold hit.
            on_auth_fail_report: Optional callback for real EventLog failed auth
                (honeypot optional). Receives a dict with attacker_ip, username,
                password placeholder, service, port — same shape as honeypot queue.
        """
        self.on_alert = on_alert
        self.on_auth_fail_report = on_auth_fail_report
        self._ip_pool: Dict[str, IPContext] = {}
        self._lock = threading.Lock()
        self._running = False
        self._housekeeping_thread: Optional[threading.Thread] = None

        # API block rules — fetched from dashboard
        self._block_rules: List[dict] = list(DEFAULT_BLOCK_RULES)
        self._block_rules_lock = threading.Lock()
        # Track which IPs were already blocked by rule engine
        self._rule_blocked_ips: Set[str] = set()

        # Whitelist — dashboard'dan gelen güvenli IP'ler
        self._whitelist_ips: Set[str] = set()

        # RDP Grace — bağlantı koptuğunda yeniden bağlanma süresince
        # failed logon eventlerini blok kuralından muaf tut.
        # {ip: disconnect_timestamp}
        self._rdp_grace: Dict[str, float] = {}
        self._RDP_GRACE_WINDOW = 300  # 5 dakika grace süresi

        # Real auth-fail → /api/attack rate limit: (ip, service, user) → last ts
        self._auth_fail_report_ts: Dict[str, float] = {}
        self._AUTH_FAIL_REPORT_INTERVAL = 15.0

        # Urgent alert dedup: "ip:event_type" → last emit (başarılı logon spam engeli)
        self._urgent_dedup: Dict[str, float] = {}
        # Ring of recent alerts for Control Center (dashboard-parity detail).
        self._recent_alerts: deque = deque(maxlen=80)

        # Stats
        self._stats = {
            "events_scored": 0,
            "alerts_generated": 0,
            "correlations_matched": 0,
            "rule_blocks": 0,
            "auth_fail_reports": 0,
            "active_ips": 0,
            "highest_threat_ip": "",
            "highest_threat_score": 0,
        }

    # ── Public API ────────────────────────────────────────────────

    @property
    def is_running(self) -> bool:
        """True while housekeeping / scoring pipeline is active."""
        return bool(self._running)

    def get_active_block_rules(self) -> List[dict]:
        """Snapshot of currently applied block rules (API or local defaults)."""
        with self._block_rules_lock:
            return list(self._block_rules)

    def update_block_rules(self, rules: List[dict]):
        """Update API-defined block rules.

        Accepts legacy dashboard shape OR contract protection.block_rules:
          {id, service, threshold, window_seconds, action, alert, enabled}
        → normalized to {name, services, threshold_count, window_minutes, actions, enabled}

        Empty / all-disabled payload → fall back to DEFAULT_BLOCK_RULES so
        real-port monitoring still blocks when honeypots are stopped.
        """
        try:
            from client_protection_store import normalize_block_rule
            raw = rules or []
            rules = [normalize_block_rule(r) for r in raw if isinstance(r, dict)]
            rules = [r for r in rules if r]
        except Exception:
            rules = [r for r in (rules or []) if isinstance(r, dict)]

        with self._block_rules_lock:
            enabled = [r for r in rules if r.get("enabled", True)] if rules else []
            using_defaults = not enabled
            self._block_rules = enabled if enabled else list(DEFAULT_BLOCK_RULES)
        rule_names = [r.get("name", "?") for r in self._block_rules]
        if using_defaults:
            log(f"[THREAT] No dashboard rules — using local defaults: {rule_names}")
        else:
            log(f"[THREAT] Block rules updated: {rule_names}")

    def update_whitelist(self, ips: Set[str]):
        """Update whitelisted IPs from dashboard/API."""
        self._whitelist_ips = set(ips)
        log(f"[THREAT] 🛡️ Whitelist updated: {len(ips)} IP(s)")

    def hydrate_blocked_ips(self, ips) -> int:
        """Mark IPs as blocked for GUI/listing (from firewall / ProgramData)."""
        added = 0
        for ip in ips or []:
            ip = str(ip or "").strip()
            if not ip or ip in ("local", "127.0.0.1", "::1"):
                continue
            if ip not in self._rule_blocked_ips:
                self._rule_blocked_ips.add(ip)
                added += 1
        if added:
            log(f"[THREAT] Hydrated {added} blocked IP(s) from firewall/store")
        return added

    def start(self):
        """Start the housekeeping (cleanup + score decay) thread."""
        if self._running:
            return
        self._running = True
        self._housekeeping_thread = threading.Thread(
            target=self._housekeeping_loop,
            name="ThreatEngine-Housekeeping",
            daemon=True,
        )
        self._housekeeping_thread.start()
        log("[THREAT] 🚀 Threat engine started")

    def stop(self):
        """Stop the housekeeping thread."""
        self._running = False
        log("[THREAT] Stopped")

    def process_event(self, event: dict):
        """
        Main entry point — called by EventLogWatcher for each parsed event.

        1. Classify & score the event
        2. Update IP context
        3. Run correlation rules
        4. Emit alert if threshold met
        """
        try:
            source_ip = event.get("source_ip", "")
            event_type = event.get("event_type", "")

            if not event_type:
                return

            ip_key = source_ip if source_ip else "local"

            # ── RDP bağlantı kopma/yeniden bağlanma yönetimi ─────
            # Event 24 = rdp_session_disconnect → grace süresi başlat
            if event_type == "rdp_session_disconnect" and source_ip:
                self._rdp_grace[source_ip] = time.time()
                log(f"[THREAT] 🔄 RDP disconnect from {source_ip} — "
                    f"{self._RDP_GRACE_WINDOW}s grace started")

            # Başarılı oturum açma → o IP'nin fail counter'ını temizle
            # (kullanıcı yeniden bağlandıysa, önceki fail'ler saldırı değildi)
            if event_type in LOGON_EVENT_TYPES and source_ip:
                if source_ip in self._rule_blocked_ips:
                    self._rule_blocked_ips.discard(source_ip)
                    log(f"[THREAT] ✅ Successful logon from {source_ip} — "
                        f"removed from rule-blocked set")
                # Grace süresini de temizle
                self._rdp_grace.pop(source_ip, None)

            # 1. Score the event
            score = self._calculate_score(event)

            # 2. Update IP context (even for events without IP, use "local")
            with self._lock:
                if ip_key not in self._ip_pool:
                    self._ip_pool[ip_key] = IPContext(ip=ip_key)
                ctx = self._ip_pool[ip_key]
                ctx.add_event(event, score)

            self._stats["events_scored"] += 1

            # 2b. API block rules — simple threshold check (e.g. 3 RDP fails → block)
            # failed_logon, sql_failed_logon, honeypot_credential hepsi kontrol edilir
            if (event_type in FAILED_LOGON_TYPES
                    or event_type == "failed_logon_single"
                    or event_type == "honeypot_credential"):
                self._check_block_rules(ip_key, ctx, event)
                # Real EventLog fails → dashboard Attacks (honeypot on/off irrelevant)
                if event_type != "honeypot_credential":
                    self._maybe_report_auth_fail(event)

            # 2c. Silent hours + logon challenge (successful logons)
            if event_type in LOGON_EVENT_TYPES:
                sh = getattr(self, "silent_hours_guard", None)
                if sh:
                    try:
                        sh.check(event)
                    except Exception as e:
                        log(f"[THREAT] silent_hours check error: {e}")
                lc = getattr(self, "logon_challenge_guard", None)
                if lc:
                    try:
                        lc.handle_successful_logon(event)
                    except Exception as e:
                        log(f"[THREAT] logon_challenge error: {e}")

            # 3. Correlation rules
            correlation_match = self._check_correlations(ip_key, ctx, event)

            # Whitelist — lower effective score, never HP-BLOCK from this path
            whitelisted = ip_key in getattr(self, "_whitelist_ips", set())
            trusted = is_trusted_logon_source(
                ip_key, getattr(self, "_whitelist_ips", set())
            )
            trusted_noise = trusted and event_type in TRUSTED_LOGON_NOISE_TYPES

            # 4. Alert decision — successful logons always emit (urgent path)
            force_urgent = event_type in URGENT_IMMEDIATE_TYPES
            if trusted_noise:
                # Trusted/local logon: info only — never inflate to high/critical
                force_urgent = False
            if correlation_match:
                corr_sev = correlation_match["severity"]
                corr_score = float(correlation_match["score"])
                if trusted_noise:
                    corr_score = min(corr_score, float(TRUSTED_LOGON_SCORE_CAP))
                    corr_sev = "info"
                elif force_urgent and corr_sev not in ("critical", "high"):
                    corr_sev = "high"
                if whitelisted and not trusted_noise:
                    corr_score = min(corr_score, 40.0)
                    corr_sev = "warning" if corr_sev == "critical" else corr_sev
                auto_resp = list(correlation_match.get("auto_response") or [])
                if trusted_noise:
                    auto_resp = [a for a in auto_resp if a != "block_ip"]
                    auto_resp = [a for a in auto_resp if a != "notify_urgent"]
                elif "block_ip" in auto_resp and not should_auto_block(
                    event_type,
                    correlation_rule=correlation_match.get("name") or "",
                    failed_attempts=ctx.failed_attempts,
                    is_whitelisted=whitelisted,
                    is_honeypot=(event_type == "honeypot_credential"),
                ):
                    auto_resp = [a for a in auto_resp if a != "block_ip"]
                    if "notify_urgent" not in auto_resp:
                        auto_resp.append("notify_urgent")
                self._emit_alert(
                    event=event,
                    ctx=ctx,
                    score=corr_score,
                    severity=corr_sev,
                    rule_name=correlation_match["name"],
                    description=correlation_match["description"],
                    auto_response=auto_resp,
                    force_urgent=(
                        False
                        if trusted_noise
                        else (force_urgent or corr_sev in ("critical", "high"))
                    ),
                )
            elif (
                force_urgent
                or score >= SEVERITY_THRESHOLDS["warning"]
                or trusted_noise
            ):
                alert_score = float(score)
                if trusted_noise:
                    alert_score = min(alert_score, float(TRUSTED_LOGON_SCORE_CAP))
                    severity = "info"
                elif event_type in BARE_SUCCESS_TYPES or event_type in LOGON_EVENT_TYPES:
                    # Report capped score for bare success (not cumulative 100 from stacking)
                    alert_score = min(alert_score, float(self._success_score_cap(event)))
                    if whitelisted:
                        alert_score = min(alert_score, 25.0)
                    severity = self._score_to_severity(alert_score)
                else:
                    severity = self._score_to_severity(alert_score)
                if (
                    not trusted_noise
                    and force_urgent
                    and severity not in ("critical", "high")
                ):
                    # Keep urgent delivery but do not inflate bare success to critical
                    if event_type in BARE_SUCCESS_TYPES or event_type in LOGON_EVENT_TYPES:
                        severity = "high"
                    else:
                        severity = "high"
                # Identity password events stay alert-only (no disable/lockout).
                standalone_auto_response: List[str] = []
                if trusted_noise:
                    standalone_auto_response = []
                elif event_type in (
                    "password_change_attempt",
                    "password_reset_attempt",
                ):
                    standalone_auto_response = []
                elif should_auto_block(
                    event_type,
                    correlation_rule="",
                    failed_attempts=ctx.failed_attempts,
                    is_whitelisted=whitelisted,
                    is_honeypot=(event_type == "honeypot_credential"),
                ) and (
                    event_type == "honeypot_credential"
                    or severity == "critical"
                ):
                    standalone_auto_response = ["block_ip", "notify_urgent"]
                elif force_urgent or severity in ("high", "critical"):
                    standalone_auto_response = ["notify_urgent"]
                self._emit_alert(
                    event=event,
                    ctx=ctx,
                    score=alert_score,
                    severity=severity,
                    rule_name="",
                    description=f"{event_type} detected from {ip_key}",
                    auto_response=standalone_auto_response,
                    force_urgent=(
                        False
                        if trusted_noise
                        else (force_urgent or severity in ("critical", "high"))
                    ),
                    alert_threat_score=int(alert_score),
                )

            # Update stats
            self._update_stats()

        except Exception as e:
            log(f"[THREAT] process_event error: {e}")

    def get_ip_context(self, ip: str) -> Optional[IPContext]:
        """Get threat context for a specific IP."""
        with self._lock:
            return self._ip_pool.get(ip)

    def get_all_contexts(self) -> Dict[str, IPContext]:
        """Get all IP contexts (copy)."""
        with self._lock:
            return dict(self._ip_pool)

    def get_recent_threats(self, max_age_seconds: int = 60,
                           min_score: int = 70) -> List[dict]:
        """
        Get IPs with active threats in the last N seconds.
        Used by Safe Last Breath mechanism.
        """
        cutoff = time.time() - max_age_seconds
        threats = []
        with self._lock:
            for ip, ctx in self._ip_pool.items():
                if ip == "local":
                    continue
                if ctx.last_seen >= cutoff and ctx.threat_score >= min_score:
                    threats.append({
                        "ip": ctx.ip,
                        "threat_score": ctx.threat_score,
                        "last_seen": ctx.last_seen,
                        "failed_attempts": ctx.failed_attempts,
                        "successful_logins": ctx.successful_logins,
                        "services": list(ctx.services_targeted),
                    })
        return sorted(threats, key=lambda t: t["threat_score"], reverse=True)

    def get_last_attacker(self) -> Optional[dict]:
        """
        Return the most recently seen attacker IP (by last_seen timestamp).
        Used by the dashboard "Son Saldırı" card.
        Returns None if no attackers tracked.
        """
        latest = None
        with self._lock:
            for ip, ctx in self._ip_pool.items():
                if ip == "local":
                    continue
                if ctx.threat_score < 1:
                    continue
                if latest is None or ctx.last_seen > latest.last_seen:
                    latest = ctx
        if latest:
            return {
                "ip": latest.ip,
                "threat_score": latest.threat_score,
                "last_seen": latest.last_seen,
                "failed_attempts": latest.failed_attempts,
                "successful_logins": latest.successful_logins,
                "services": list(latest.services_targeted),
            }
        return None

    def get_stats(self) -> dict:
        """Return engine statistics."""
        stats = dict(self._stats)
        with self._lock:
            stats["active_ips"] = len(self._ip_pool)
        return stats

    def clear_contexts(self) -> int:
        """Clear all IP threat contexts (local cleanup / maintenance)."""
        with self._lock:
            n = len(self._ip_pool)
            self._ip_pool.clear()
            if hasattr(self, "_rule_blocked_ips"):
                self._rule_blocked_ips.clear()
            if hasattr(self, "_rdp_grace"):
                self._rdp_grace.clear()
        log(f"[THREAT] Cleared {n} IP contexts (maintenance)")
        return n

    def get_threat_level(self) -> Tuple[str, str]:
        """
        Return overall threat level for the dashboard.
        Returns: (level, color) — e.g. ("CRITICAL", "#FF4444")
        """
        with self._lock:
            if not self._ip_pool:
                return ("SAFE", "#2ECC71")
            max_score = max(
                (ctx.threat_score for ctx in self._ip_pool.values()),
                default=0
            )
        if max_score >= 81:
            return ("CRITICAL", "#FF4444")
        elif max_score >= 61:
            return ("HIGH", "#FF8C00")
        elif max_score >= 31:
            return ("WARNING", "#FFD700")
        else:
            return ("SAFE", "#2ECC71")

    # ── Scoring ───────────────────────────────────────────────────

    def _success_score_cap(self, event: Optional[dict] = None) -> int:
        """Ceiling for bare successful-logon scores (never 100)."""
        try:
            sh = getattr(self, "silent_hours_guard", None)
            if sh and hasattr(sh, "is_silent_now") and sh.is_silent_now():
                return SUCCESS_LOGON_SCORE_CAP_SILENT
        except Exception:
            pass
        return SUCCESS_LOGON_SCORE_CAP

    def _calculate_score(self, event: dict) -> float:
        """Calculate threat score for a single event."""
        event_type = event.get("event_type", "")
        logon_type = event.get("logon_type")
        target_service = event.get("target_service", "")

        # Refine event type for RDP/network logons
        score_key = event_type
        if event_type == "successful_logon" and logon_type is not None:
            if logon_type == 10:
                score_key = "successful_logon_rdp"
            elif logon_type == 3:
                score_key = "successful_logon_network"
        elif event_type == "successful_logon" and target_service == "MSSQL":
            score_key = "sql_successful_logon"
        elif event_type == "failed_logon":
            score_key = "failed_logon_single"
        elif event_type == "sql_failed_logon":
            score_key = "sql_failed_logon"

        base_score = THREAT_SCORES.get(score_key, 0)

        # Check for burst (brute force) — failed logon burst multiplier
        if event_type in FAILED_LOGON_TYPES:
            source_ip = event.get("source_ip", "")
            if source_ip:
                with self._lock:
                    ctx = self._ip_pool.get(source_ip)
                    if ctx:
                        recent_failures = sum(
                            1 for e in ctx.get_recent_events(300)
                            if e["event_type"] in FAILED_LOGON_TYPES
                        )
                        if recent_failures >= 10:
                            base_score = THREAT_SCORES.get("failed_logon_burst", 40)

        # Failed-then-success — elevated score (may block via correlation / should_auto_block)
        brute_then_success = False
        if event_type in LOGON_EVENT_TYPES:
            source_ip = event.get("source_ip", "")
            if source_ip:
                with self._lock:
                    ctx = self._ip_pool.get(source_ip)
                    if ctx and ctx.failed_attempts >= 3:
                        base_score = max(
                            base_score,
                            THREAT_SCORES.get("failed_then_success", 95),
                        )
                        brute_then_success = True

        # Whitelist: dampen
        source_ip = (event.get("source_ip") or "").strip()
        if source_ip and source_ip in getattr(self, "_whitelist_ips", set()):
            base_score = min(base_score, 20)

        ip_key = source_ip if source_ip else "local"
        if (
            event_type in TRUSTED_LOGON_NOISE_TYPES
            and is_trusted_logon_source(
                ip_key, getattr(self, "_whitelist_ips", set())
            )
        ):
            base_score = min(base_score, float(TRUSTED_LOGON_SCORE_CAP))

        # Cap bare success — 100 reserved for canary/VSS/tamper/ransomware
        if (
            (event_type in BARE_SUCCESS_TYPES or event_type in LOGON_EVENT_TYPES)
            and not brute_then_success
        ):
            base_score = min(base_score, self._success_score_cap(event))

        return float(base_score)

    # ── API Block Rules (Dashboard kuralları) ─────────────────────

    # Event types that count as "failed auth" for block rules
    _BLOCK_RULE_FAIL_TYPES: Set[str] = (
        FAILED_LOGON_TYPES | {"failed_logon_single", "honeypot_credential"}
    )

    # Default ports when EventLog omits target_port
    _SERVICE_DEFAULT_PORTS: Dict[str, int] = {
        "RDP": 3389,
        "MSSQL": 1433,
        "MYSQL": 3306,
        "SSH": 22,
        "FTP": 21,
        "Network": 445,
    }

    @staticmethod
    def _rule_service_set(rule: dict) -> Optional[Set[str]]:
        """None = match all services; else uppercased service names."""
        raw = rule.get("services", "") or rule.get("service", "")
        if not raw or str(raw).strip() in ("*", ""):
            return None
        return {s.strip().upper() for s in str(raw).split(",") if s.strip()}

    @staticmethod
    def _fail_matches_services(event_svc: str, rule_services: Optional[Set[str]]) -> bool:
        if rule_services is None:
            return True
        svc = (event_svc or "").strip().upper()
        if not svc:
            return False
        return svc in rule_services

    def _service_has_enabled_rule(self, service: str) -> bool:
        """True if any enabled block rule covers this service (or all services)."""
        svc = (service or "").strip().upper()
        if not svc:
            return False
        with self._block_rules_lock:
            rules = list(self._block_rules)
        for rule in rules:
            if not rule.get("enabled", True):
                continue
            rule_svcs = self._rule_service_set(rule)
            if rule_svcs is None or svc in rule_svcs:
                return True
        return False

    def _maybe_report_auth_fail(self, event: dict) -> None:
        """Report real Windows auth fails to /api/attack when block rules cover the service.

        Honeypot may be off — EventLog + protection.block_rules still feed Attacks UI
        and cloud notification counters. Rate-limited; password is a placeholder.
        """
        cb = self.on_auth_fail_report
        if not cb:
            return
        source_ip = (event.get("source_ip") or "").strip()
        if not source_ip or source_ip in ("local", "127.0.0.1", "::1", "-"):
            return
        if source_ip in self._whitelist_ips:
            return
        service = (
            event.get("target_service", "") or event.get("service", "") or ""
        ).strip().upper()
        if not service or service == "SYSTEM":
            return
        if not self._service_has_enabled_rule(service):
            return

        username = (event.get("username") or "").strip() or "unknown"
        dedup_key = f"{source_ip}|{service}|{username.lower()}"
        now = time.time()
        last = self._auth_fail_report_ts.get(dedup_key, 0.0)
        if now - last < self._AUTH_FAIL_REPORT_INTERVAL:
            return
        self._auth_fail_report_ts[dedup_key] = now
        # Bound map under scan floods
        if len(self._auth_fail_report_ts) > 4096:
            cutoff = now - 600.0
            self._auth_fail_report_ts = {
                k: ts for k, ts in self._auth_fail_report_ts.items() if ts >= cutoff
            }

        try:
            port = int(event.get("target_port") or event.get("port") or 0)
        except (TypeError, ValueError):
            port = 0
        if port <= 0:
            port = self._SERVICE_DEFAULT_PORTS.get(service, 0)

        try:
            cb({
                "attacker_ip": source_ip,
                "username": username,
                "password": "<failed_logon>",
                "service": service,
                "port": port,
                "timestamp": now,
                "source": "eventlog",
            })
            self._stats["auth_fail_reports"] = int(
                self._stats.get("auth_fail_reports") or 0
            ) + 1
        except Exception as e:
            log(f"[THREAT] auth_fail report callback error: {e}")

    def _check_block_rules(self, ip: str, ctx: IPContext, event: dict):
        """
        Dashboard'dan gelen (veya varsayılan) blok kurallarını kontrol et.
        Örnek kural: RDP servisi, eşik=3, pencere=30dk → 3 failed login = anında blokla.
        Honeypot credential'lar da failed auth olarak sayılır.
        Fail sayacı **servis bilinçli** — Network fail'leri RDP eşiğini doldurmaz.
        """
        if ip in ("local", "", "127.0.0.1", "::1"):
            return
        if ip in self._rule_blocked_ips:
            return  # zaten bu kural ile bloklanmış

        # Whitelist kontrolü — dashboard'dan gelen güvenli IP'ler
        if ip in self._whitelist_ips:
            return

        # RDP grace kontrolü — bağlantı kopmasından sonra yeniden
        # bağlanma denemeleri saldırı olarak sayılmaz
        grace_ts = self._rdp_grace.get(ip)
        if grace_ts:
            if (time.time() - grace_ts) < self._RDP_GRACE_WINDOW:
                event_service = (
                    event.get("target_service", "") or
                    event.get("service", "") or ""
                ).upper()
                if event_service == "RDP":
                    log(f"[THREAT] 🔄 RDP fail from {ip} ignored — "
                        f"within grace period")
                    return
            else:
                # Grace süresi dolmuş, temizle
                del self._rdp_grace[ip]

        # Servis tespiti: EventLog → target_service, Honeypot → service
        event_service = (
            event.get("target_service", "") or event.get("service", "") or ""
        ).upper()

        with self._block_rules_lock:
            rules = list(self._block_rules)

        for rule in rules:
            if not rule.get("enabled", True):
                continue

            # Servis eşleştirmesi (contract: service / services; empty / * = all)
            rule_services = self._rule_service_set(rule)
            if rule_services is not None:
                if not event_service or event_service not in rule_services:
                    continue

            # Contract event filter (default failed_auth)
            rule_event = str(rule.get("event") or "failed_auth").strip().lower()
            if rule_event and rule_event not in ("failed_auth", "*", "any"):
                # Future event kinds — skip unknown for now
                continue

            threshold = int(
                rule.get("threshold_count", rule.get("threshold", 3))
            )
            if rule.get("window_minutes") is not None:
                window_sec = int(rule.get("window_minutes", 30)) * 60
            elif rule.get("window_seconds") is not None:
                window_sec = int(rule.get("window_seconds", 1800))
            else:
                window_sec = 30 * 60
            actions_str = rule.get("actions", "email,block")
            if not actions_str and rule.get("action"):
                actions_str = "block" if "block" in str(rule.get("action")).lower() else "email,block"
                if rule.get("alert", True) and "email" not in actions_str:
                    actions_str = f"email,{actions_str}"
            actions = {a.strip().lower() for a in str(actions_str).split(",") if a.strip()}

            # Pencere içindeki failed login — yalnızca bu kuralın servisine uyanlar
            recent = ctx.get_recent_events(window_sec)
            fail_count = sum(
                1 for e in recent
                if e["event_type"] in self._BLOCK_RULE_FAIL_TYPES
                and self._fail_matches_services(
                    e.get("target_service", ""), rule_services
                )
            )

            if fail_count < threshold:
                continue

            # Eşik aşıldı!
            rule_name = rule.get("name", "block_rule")
            log(f"[THREAT] Block rule '{rule_name}' triggered: "
                f"IP={ip} service={event_service} "
                f"fails={fail_count}/{threshold} window={window_sec}s")

            self._rule_blocked_ips.add(ip)
            self._stats["rule_blocks"] += 1

            # Aksiyonları belirle
            auto_response = []
            if "block" in actions:
                auto_response.append("block_ip")
            if "email" in actions:
                auto_response.append("notify_urgent")
            if not auto_response:
                auto_response = ["block_ip", "notify_urgent"]

            # Alert üret → AlertPipeline → AutoResponse.block_ip()
            self._emit_alert(
                event=event,
                ctx=ctx,
                score=95,
                severity="critical",
                rule_name=f"api_rule_{rule_name}",
                description=(
                    f"Block rule '{rule_name}': {fail_count} failed login(s) "
                    f"from {ip} to {event_service} in {rule.get('window_minutes')} min "
                    f"(threshold: {threshold})"
                ),
                auto_response=auto_response,
            )
            break  # İlk eşleşen kural yeterli

    # ── Correlation ───────────────────────────────────────────────

    def _check_correlations(self, ip: str, ctx: IPContext,
                            event: dict) -> Optional[dict]:
        """Run correlation rules against the current IP context."""
        event_type = event.get("event_type", "")

        for rule in CORRELATION_RULES:
            try:
                matched = self._evaluate_rule(rule, ip, ctx, event, event_type)
                if matched:
                    self._stats["correlations_matched"] += 1
                    log(f"[THREAT] 🎯 Correlation: {rule['name']} — IP: {ip}")
                    return rule
            except Exception as e:
                log(f"[THREAT] Correlation rule error ({rule['name']}): {e}")

        return None

    def _evaluate_rule(self, rule: dict, ip: str, ctx: IPContext,
                       event: dict, event_type: str) -> bool:
        """Evaluate a single correlation rule."""

        # ── rdp_after_hours ───────────────────────────────────────
        if rule["name"] == "rdp_after_hours":
            if event_type in RDP_LOGON_TYPES or (
                event_type in LOGON_EVENT_TYPES and
                event.get("target_service") == "RDP"
            ):
                hour = time.localtime().tm_hour
                start, end = rule.get("time_range", (0, 6))
                return start <= hour < end
            return False

        # ── brute_force_then_access ───────────────────────────────
        if rule["name"] == "brute_force_then_access":
            if event_type not in LOGON_EVENT_TYPES:
                return False
            window = rule.get("precondition_window", 600)
            required = rule.get("precondition_count", 5)
            recent = ctx.get_recent_events(window)
            fail_count = sum(
                1 for e in recent
                if e["event_type"] in FAILED_LOGON_TYPES
            )
            return fail_count >= required

        # ── lateral_movement ──────────────────────────────────────
        if rule["name"] == "lateral_movement":
            if event_type not in LOGON_EVENT_TYPES:
                return False
            required = rule.get("distinct_services", 2)
            return len(ctx.services_targeted) >= required

        # ── post_exploitation ─────────────────────────────────────
        if rule["name"] == "post_exploitation":
            if event_type not in PERSISTENCE_TYPES:
                return False
            # Check if there was a successful logon from this IP recently
            window = rule.get("trigger_window", 3600)
            recent = ctx.get_recent_events(window)
            has_logon = any(
                e["event_type"] in LOGON_EVENT_TYPES for e in recent
            )
            return has_logon

        # ── honeypot_brute_force ──────────────────────────────────
        if rule["name"] == "honeypot_brute_force":
            if event_type != "honeypot_credential":
                return False
            window = rule.get("precondition_window", 600)
            required = rule.get("precondition_count", 3)
            recent = ctx.get_recent_events(window)
            hp_count = sum(
                1 for e in recent
                if e["event_type"] == "honeypot_credential"
            )
            return hp_count >= required

        return False

    # ── Alert Emission ────────────────────────────────────────────

    def _emit_alert(self, event: dict, ctx: IPContext, score: float,
                    severity: str, rule_name: str, description: str,
                    auto_response: List[str], force_urgent: bool = False,
                    alert_threat_score: Optional[int] = None):
        """Build alert dict and forward to alert pipeline callback."""

        # Rate limiting — don't spam for same IP/type
        # Successful logon / kritik olaylar: ayrı kısa cooldown (diğer alert'ler engellemesin)
        now = time.time()
        etype = event.get("event_type", "")
        if force_urgent:
            udeup_key = f"{ctx.ip}:{etype}"
            last_u = self._urgent_dedup.get(udeup_key, 0)
            if now - last_u < 15:
                return
            self._urgent_dedup[udeup_key] = now
            # Cap map size
            if len(self._urgent_dedup) > 5000:
                cutoff = now - 3600
                self._urgent_dedup = {
                    k: v for k, v in self._urgent_dedup.items() if v >= cutoff
                }
        else:
            cooldowns = {"critical": 60, "high": 300, "warning": 900, "info": 3600}
            cooldown = cooldowns.get(severity, 300)
            if now - ctx.last_alert_time < cooldown:
                return

        ctx.last_alert_time = now
        ctx.alerts_sent += 1
        self._stats["alerts_generated"] += 1

        # Bare success: never publish cumulative 100 from stacked RDP events
        reported_score = (
            int(alert_threat_score)
            if alert_threat_score is not None
            else int(score if score else ctx.threat_score)
        )
        if (
            (etype in BARE_SUCCESS_TYPES or etype in LOGON_EVENT_TYPES)
            and not rule_name
        ):
            reported_score = min(reported_score, int(self._success_score_cap(event)))

        # §9 hard cap: local / trusted console noise never score 100 critical
        if is_trusted_logon_source(
            ctx.ip, getattr(self, "_whitelist_ips", set())
        ) and (
            etype in TRUSTED_LOGON_NOISE_TYPES
            or (event.get("event_type") or "") in TRUSTED_LOGON_NOISE_TYPES
        ):
            reported_score = min(reported_score, int(TRUSTED_LOGON_SCORE_CAP))
            severity = "info"
            force_urgent = False

        # Final safety: bare success never carries block_ip
        safe_response = list(auto_response or [])
        if not should_auto_block(
            etype,
            correlation_rule=rule_name or "",
            failed_attempts=int(getattr(ctx, "failed_attempts", 0) or 0),
            is_whitelisted=(ctx.ip in getattr(self, "_whitelist_ips", set())),
            is_honeypot=(etype == "honeypot_credential"),
        ):
            safe_response = [a for a in safe_response if a != "block_ip"]

        alert = {
            "alert_id": str(uuid.uuid4()),
            "timestamp": now,
            "severity": severity,
            "threat_type": event.get("event_type", ""),
            "title": self._build_title(event, rule_name),
            "description": description,
            "source_ip": ctx.ip,
            "target_service": event.get("target_service", "") or event.get("service", ""),
            "target_port": int(event.get("target_port", 0) or event.get("port", 0) or 0),
            "username": event.get("username", ""),
            # Never forward credential material from Event Log / honeypot parsers.
            "password": "",
            "threat_score": reported_score,
            "event_ids": [event.get("event_id", 0)],
            "correlation_rule": rule_name,
            "recommended_action": self._recommend_action(severity, rule_name, etype),
            "auto_response": safe_response,
            "force_urgent": bool(force_urgent),
            "ip_context": {
                "failed_attempts": ctx.failed_attempts,
                "successful_logins": ctx.successful_logins,
                "services": list(ctx.services_targeted),
                "usernames": list(ctx.usernames_tried)[:10],
            },
        }
        if event.get("event_type") in (
            "password_change_attempt",
            "password_reset_attempt",
        ):
            alert["recommended_action"] = "review_identity_activity"
            alert["auto_response"] = []
            alert["system_context"] = {
                "identity": {
                    "actor_username": event.get("actor_username", ""),
                    "actor_domain": event.get("actor_domain", ""),
                    "target_username": event.get("username", ""),
                    "target_domain": event.get("target_domain", ""),
                    "computer": event.get("computer", ""),
                    "result": event.get("result", "") or "unknown",
                    "event_id": int(event.get("event_id", 0) or 0),
                }
            }

        log(f"[THREAT] 🚨 Alert [{severity.upper()}] "
            f"{alert['title']} — IP: {ctx.ip} — Score: {int(ctx.threat_score)}")

        if self.on_alert:
            try:
                self.on_alert(alert)
            except Exception as e:
                log(f"[THREAT] Alert callback error: {e}")

        # Keep a GUI-facing copy (no secrets); dashboard "Son Kritik" parity.
        try:
            snap = {
                "alert_id": alert.get("alert_id"),
                "timestamp": alert.get("timestamp"),
                "severity": alert.get("severity"),
                "threat_type": alert.get("threat_type"),
                "title": alert.get("title"),
                "description": alert.get("description"),
                "source_ip": alert.get("source_ip"),
                "target_service": alert.get("target_service"),
                "target_port": alert.get("target_port"),
                "username": alert.get("username"),
                "threat_score": alert.get("threat_score"),
                "correlation_rule": alert.get("correlation_rule"),
                "recommended_action": alert.get("recommended_action"),
                "auto_response": list(alert.get("auto_response") or []),
            }
            with self._lock:
                self._recent_alerts.appendleft(snap)
        except Exception:
            pass

    def get_recent_alerts(self, limit: int = 25) -> List[dict]:
        """Most recent emitted alerts for Control Center (newest first)."""
        with self._lock:
            out = list(self._recent_alerts)[: max(1, int(limit))]
        return out

    @staticmethod
    def summarize_ip_context(ctx: "IPContext") -> dict:
        """Human title/description for an IP row (dashboard-style Tehdit column)."""
        events = list(ctx.events) if ctx.events else []
        last = events[-1] if events else {}
        etype = str(last.get("event_type") or "")
        services = list(ctx.services_targeted or [])[:6]
        users = list(ctx.usernames_tried or [])[:8]
        title = ThreatEngine._build_title({"event_type": etype}, "")
        bits = []
        if ctx.failed_attempts:
            bits.append(f"{int(ctx.failed_attempts)} failed logon")
        if ctx.successful_logins:
            bits.append(f"{int(ctx.successful_logins)} successful logon")
        if services:
            bits.append("services: " + ", ".join(str(s) for s in services))
        if users:
            bits.append("users: " + ", ".join(str(u) for u in users))
        if etype and not bits:
            bits.append(f"{etype.replace('_', ' ')} from {ctx.ip}")
        description = "; ".join(bits) if bits else f"Activity from {ctx.ip}"
        return {
            "title": title,
            "description": description,
            "threat_type": etype or "unknown",
            "services": services,
            "usernames": users,
            "last_event_type": etype,
            "successful_logins": int(ctx.successful_logins or 0),
        }

    @staticmethod
    def _build_title(event: dict, rule_name: str) -> str:
        """Build a human-readable alert title."""
        if rule_name:
            # API rule-based blocks
            if rule_name.startswith("api_rule_"):
                display_name = rule_name[len("api_rule_"):]
                return f"🚫 Block Rule: {display_name}"
            titles = {
                "brute_force_then_access": "🔓 Brute Force → Successful Login",
                "rdp_after_hours":         "🌙 RDP Access After Hours",
                "lateral_movement":        "🔐 Multi-service logon activity",
                "post_exploitation":       "💀 Post-Exploitation Activity",
            }
            return titles.get(rule_name, f"⚠️ Correlation: {rule_name}")

        etype = event.get("event_type", "")
        titles = {
            "audit_log_cleared":         "🗑️ Audit Log Cleared",
            "xp_cmdshell_executed":      "💉 xp_cmdshell Executed (SQL Injection)",
            "new_user_created":          "👤 New User Account Created",
            "user_added_to_admin_group": "⬆️ User Added to Admin Group",
            "password_change_attempt":   "🔑 Password Change Attempt",
            "password_reset_attempt":    "🔑 Password Reset Attempt",
            "successful_logon_rdp":      "🖥️ RDP Successful Login",
            "successful_logon":          "🔐 Successful Login",
            "failed_logon_burst":        "🔨 Brute Force Attack Detected",
            "new_service_installed":     "⚙️ New Service Installed",
            "rdp_connection_succeeded":  "🖥️ RDP Connection Established",
            "sql_successful_logon":      "🗄️ SQL Successful Login",
            "honeypot_credential":       "🍯 Honeypot Credential Captured",
        }
        return titles.get(etype, f"⚠️ {etype.replace('_', ' ').title()}")

    @staticmethod
    def _recommend_action(severity: str, rule_name: str, event_type: str = "") -> str:
        """Return recommended action text."""
        if rule_name and rule_name.startswith("api_rule_"):
            return "IP blocked by dashboard block rule — review attack pattern"
        if rule_name == "brute_force_then_access":
            return "Block IP immediately, review compromised account, check for lateral movement"
        if rule_name == "post_exploitation":
            return "Block IP, isolate system, review installed services and user accounts"
        if rule_name == "lateral_movement":
            return "Review multi-service sessions — alert only unless brute-force history"
        et = (event_type or "").strip().lower()
        if et in BARE_SUCCESS_TYPES or et in LOGON_EVENT_TYPES:
            return (
                "Notify / logon challenge — do not firewall-block bare successful logon; "
                "whitelist office IPs if expected"
            )
        if severity == "critical":
            return "Investigate immediately — potential active compromise"
        if severity == "high":
            return "Review within 15 minutes — suspicious activity"
        return "Monitor and review during next assessment"

    @staticmethod
    def _score_to_severity(score: float) -> str:
        """Convert numeric score to severity string."""
        if score >= 81:
            return "critical"
        elif score >= 61:
            return "high"
        elif score >= 31:
            return "warning"
        return "info"

    # ── Housekeeping ──────────────────────────────────────────────

    def _housekeeping_loop(self):
        """Periodic cleanup: remove stale IPs, decay scores."""
        while self._running:
            try:
                self._cleanup_stale_contexts()
                self._decay_scores()
            except Exception as e:
                log(f"[THREAT] Housekeeping error: {e}")
            time.sleep(CONTEXT_CLEANUP_INTERVAL)

    def _cleanup_stale_contexts(self):
        """Remove IP contexts that haven't had activity in 24h.
        Blocked IPs are cleaned after 72h to prevent unbounded memory growth."""
        now = time.time()
        cutoff_normal = now - CONTEXT_MAX_AGE
        cutoff_blocked = now - (CONTEXT_MAX_AGE * 3)  # 72h for blocked IPs
        with self._lock:
            stale_ips = [
                ip for ip, ctx in self._ip_pool.items()
                if (ctx.last_seen < cutoff_normal and not ctx.is_blocked)
                   or (ctx.last_seen < cutoff_blocked and ctx.is_blocked)
            ]
            for ip in stale_ips:
                del self._ip_pool[ip]

            # Cap pool size — evict LRU if over 10k (including blocked under hard pressure)
            if len(self._ip_pool) > 10000:
                sorted_ips = sorted(
                    self._ip_pool.items(),
                    key=lambda x: x[1].last_seen
                )
                evict_count = len(self._ip_pool) - 8000  # shrink to 8k
                evicted = 0
                for ip, ctx in sorted_ips:
                    if evicted >= evict_count:
                        break
                    if ip == "local":
                        continue
                    del self._ip_pool[ip]
                    evicted += 1
                log(f"[THREAT] 🧹 LRU evicted {evicted} IP contexts (pool was >10k)")

            # Cleanup _rule_blocked_ips — keep firewall/store blocks even if
            # they have no threat context (GUI Engellenen tab needs them).
            try:
                from client_block_store import load_blocked_map
                persisted = set(load_blocked_map().keys())
            except Exception:
                persisted = set()
            stale_blocked = (
                self._rule_blocked_ips
                - set(self._ip_pool.keys())
                - persisted
            )
            if stale_blocked:
                self._rule_blocked_ips -= stale_blocked

            # Cleanup _rdp_grace — remove expired entries
            expired_grace = [
                ip for ip, ts in self._rdp_grace.items()
                if (now - ts) > self._RDP_GRACE_WINDOW
            ]
            for ip in expired_grace:
                del self._rdp_grace[ip]

            if stale_ips:
                log(f"[THREAT] Cleaned up {len(stale_ips)} stale IP contexts "
                    f"(pool size: {len(self._ip_pool)})")

    def _decay_scores(self):
        """Gradually reduce threat scores over time."""
        with self._lock:
            for ctx in self._ip_pool.values():
                # Decay 1 point per cleanup interval for non-blocked IPs
                if not ctx.is_blocked and ctx.threat_score > 0:
                    ctx.decay_score(1.0)

    def _update_stats(self):
        """Update highest-threat stats."""
        with self._lock:
            if self._ip_pool:
                top_ip = max(
                    self._ip_pool.values(),
                    key=lambda c: c.threat_score,
                    default=None,
                )
                if top_ip:
                    self._stats["highest_threat_ip"] = top_ip.ip
                    self._stats["highest_threat_score"] = int(top_ip.threat_score)
