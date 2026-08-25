#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Asteria Client — Windows Event Log Watcher (v4.0)

Real-time monitoring of Windows Security, System, Application and RDP
event logs using win32evtlog push-based subscriptions (EvtSubscribe).

Watched events:
  Security   — 4624/4625/4648/4672/4688/4697/4720/4723/4724/4732/1102
  System     — 1074/6005/6006/7045/7040
  Application — 18453/18456/15457/17135 (MSSQL)
  RDP        — 1149/21/24/25

Each parsed event is forwarded to ThreatEngine.process_event().

Exports:
  EventLogWatcher  — main watcher class (start / stop / get_stats)
"""

import threading
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set
from collections import defaultdict

from client_helpers import log

# ── win32evtlog import (graceful fallback) ────────────────────────
try:
    import win32evtlog
    import win32con
    EVTLOG_AVAILABLE = True
except ImportError:
    EVTLOG_AVAILABLE = False
    log("[EVENTLOG] pywin32 not available — event log monitoring disabled")


# ── Constants ─────────────────────────────────────────────────────

# Channels → Event IDs to watch
WATCHED_CHANNELS: Dict[str, List[int]] = {
    "Security": [
        4624, 4625, 4648, 4672, 4688, 4697, 4720, 4723, 4724, 4732, 4735, 1102,
    ],
    "System": [1074, 6005, 6006, 7045, 7040],
    "Application": [18453, 18456, 15457, 17135],
    "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational": [1149],
    "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational": [21, 24, 25],
}

# Accounts to ignore (machine accounts, system accounts)
IGNORED_ACCOUNTS: Set[str] = {
    "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE",
    "ANONYMOUS LOGON", "Font Driver Host",
}

# Logon types we ignore (5=Service, 7=Unlock)
IGNORED_LOGON_TYPES: Set[int] = {5, 7}

# Prefixes for machine/DWM accounts to skip
IGNORED_ACCOUNT_PREFIXES = ("DWM-", "UMFD-", "IUSR")

# Recent TerminalServices 1149 IPs — promote LogonType-3 NLA fails to RDP.
_RDP_IP_HINTS: Dict[str, float] = {}
_RDP_HINT_TTL_SEC = 180.0
_RDP_HINT_LOCK = threading.Lock()


def note_rdp_source_ip(ip: str) -> None:
    """Remember an IP that just hit TerminalServices (Event 1149)."""
    addr = (ip or "").strip()
    if not addr or addr in ("-", "::1", "127.0.0.1"):
        return
    now = time.time()
    with _RDP_HINT_LOCK:
        _RDP_IP_HINTS[addr] = now
        if len(_RDP_IP_HINTS) > 2048:
            cutoff = now - _RDP_HINT_TTL_SEC
            stale = [k for k, ts in _RDP_IP_HINTS.items() if ts < cutoff]
            for k in stale:
                _RDP_IP_HINTS.pop(k, None)


def _rdp_hint_recent(ip: str) -> bool:
    addr = (ip or "").strip()
    if not addr:
        return False
    now = time.time()
    with _RDP_HINT_LOCK:
        ts = _RDP_IP_HINTS.get(addr)
        if ts is None:
            return False
        if now - float(ts) > _RDP_HINT_TTL_SEC:
            _RDP_IP_HINTS.pop(addr, None)
            return False
        return True


# Map Event ID → human-readable event type for ThreatEngine
EVENT_TYPE_MAP: Dict[int, str] = {
    # Auth
    4624: "successful_logon",
    4625: "failed_logon",
    4648: "explicit_credential_logon",
    4672: "privilege_assigned",
    4688: "new_process",
    4697: "new_service_installed",
    4720: "new_user_created",
    4723: "password_change_attempt",
    4724: "password_reset_attempt",
    4732: "user_added_to_admin_group",
    4735: "security_group_changed",
    1102: "audit_log_cleared",
    # System
    1074: "system_shutdown",
    6005: "eventlog_started",
    6006: "eventlog_stopped",
    7045: "new_service_installed",
    7040: "service_start_type_changed",
    # MSSQL
    18453: "sql_successful_logon",
    18456: "sql_failed_logon",
    15457: "xp_cmdshell_executed",
    17135: "sql_server_restarted",
    # RDP
    1149: "rdp_connection_succeeded",
    21:   "rdp_session_logon",
    24:   "rdp_session_disconnect",
    25:   "rdp_session_reconnect",
}

# Logon type descriptions (for Event 4624)
LOGON_TYPE_NAMES: Dict[int, str] = {
    2:  "Interactive",
    3:  "Network",
    4:  "Batch",
    5:  "Service",
    7:  "Unlock",
    10: "RemoteInteractive",
    11: "CachedInteractive",
}


# ── XPath query builder ──────────────────────────────────────────

def _build_xpath(event_ids: List[int]) -> str:
    """Build XPath filter for specific Event IDs — efficient server-side filtering."""
    id_clauses = " or ".join(f"EventID={eid}" for eid in event_ids)
    return f"*[System[{id_clauses}]]"


# ── Main Watcher ─────────────────────────────────────────────────

class EventLogWatcher:
    """
    Real-time Windows Event Log watcher using EvtSubscribe (push-based).

    Usage:
        watcher = EventLogWatcher(on_event=threat_engine.process_event)
        watcher.start()
        ...
        watcher.stop()
    """

    def __init__(self, on_event: Callable[[dict], None],
                 whitelist_ips: Optional[Set[str]] = None):
        """
        Args:
            on_event:       Callback receiving parsed event dicts.
            whitelist_ips:  IPs to ignore completely (user-configured).
        """
        self.on_event = on_event
        self.whitelist_ips: Set[str] = whitelist_ips or set()
        self._subscriptions: list = []
        self._running = False
        self._lock = threading.Lock()
        # Channel enable flags from threats/config monitored_event_channels
        self._channel_flags = {
            "security": True,
            "system": True,
            "application": True,
            "rdp": True,
        }

        # Stats
        self._stats = {
            "events_processed": 0,
            "events_filtered": 0,
            "errors": 0,
            "started_at": 0.0,
            "channels_active": 0,
        }
        try:
            from client_identity_correlation import PasswordBurstCorrelator
            self.identity_correlator = PasswordBurstCorrelator()
        except Exception:
            self.identity_correlator = None

    # ── Public API ────────────────────────────────────────────────

    @property
    def is_running(self) -> bool:
        """True while EventLog subscriptions are active (port monitoring)."""
        return bool(self._running)

    def start(self):
        """Subscribe to all configured event channels."""
        if not EVTLOG_AVAILABLE:
            log("[EVENTLOG] ⚠️ Cannot start — pywin32 not installed")
            return

        if self._running:
            log("[EVENTLOG] Already running")
            return

        log("[EVENTLOG] 🚀 Starting Windows Event Log monitoring...")
        self._running = True
        self._stats["started_at"] = time.time()

        active = 0
        for channel, event_ids in WATCHED_CHANNELS.items():
            if not self._is_channel_enabled(channel):
                log(f"[EVENTLOG] ⏭ Skipped (config): {channel}")
                continue
            try:
                xpath = _build_xpath(event_ids)
                handle = win32evtlog.EvtSubscribe(
                    channel,
                    win32evtlog.EvtSubscribeToFutureEvents,
                    Query=xpath,
                    Callback=self._on_event_callback,
                )
                self._subscriptions.append(handle)
                active += 1
                log(f"[EVENTLOG] ✅ Subscribed: {channel} ({len(event_ids)} event IDs)")
            except Exception as e:
                log(f"[EVENTLOG] ❌ Failed to subscribe to {channel}: {e}")
                self._stats["errors"] += 1

        self._stats["channels_active"] = active
        log(f"[EVENTLOG] Monitoring active — {active}/{len(WATCHED_CHANNELS)} channels")

    def _is_channel_enabled(self, channel: str) -> bool:
        cl = channel.lower()
        if cl == "security":
            return self._channel_flags.get("security", True)
        if cl == "system":
            return self._channel_flags.get("system", True)
        if cl == "application":
            return self._channel_flags.get("application", True)
        if "terminalservices" in cl or "rdp" in cl:
            return self._channel_flags.get("rdp", True)
        return True

    def update_monitored_channels(self, channels: dict):
        """Apply monitored_event_channels from threats/config; restart if running."""
        if not isinstance(channels, dict):
            return
        changed = False
        for key in ("security", "system", "application", "rdp"):
            if key in channels:
                val = bool(channels.get(key))
                if self._channel_flags.get(key) != val:
                    self._channel_flags[key] = val
                    changed = True
        log(f"[EVENTLOG] Channel flags: {self._channel_flags}")
        if changed and self._running:
            try:
                self.stop()
                self.start()
            except Exception as e:
                log(f"[EVENTLOG] Channel re-subscribe error: {e}")

    def stop(self):
        """Unsubscribe from all channels and clean up."""
        if not self._running:
            return

        log("[EVENTLOG] Stopping event log monitoring...")
        self._running = False

        for handle in self._subscriptions:
            try:
                win32evtlog.EvtClose(handle)
            except Exception:
                pass

        self._subscriptions.clear()
        self._stats["channels_active"] = 0
        log("[EVENTLOG] ✅ Stopped")

    def get_stats(self) -> dict:
        """Return monitoring statistics."""
        stats = dict(self._stats)
        if stats["started_at"]:
            stats["uptime_seconds"] = int(time.time() - stats["started_at"])
        return stats

    def get_health(self) -> dict:
        """ID-401 observe block for health/report (contract 1.4.2).

        Bounded sensor health only — no raw event payloads until the final
        4723/4724 schema is promoted on the cloud side.
        """
        s = self._stats
        return {
            "available": bool(EVTLOG_AVAILABLE),
            "running": bool(self._running),
            "channels_active": int(s.get("channels_active", 0) or 0),
            "channels_total": len(WATCHED_CHANNELS),
            "events_processed": int(s.get("events_processed", 0) or 0),
            "events_filtered": int(s.get("events_filtered", 0) or 0),
            "errors": int(s.get("errors", 0) or 0),
            "watched_ids": sorted(
                {eid for ids in WATCHED_CHANNELS.values() for eid in ids}
            ),
            "password_burst": self._password_burst_health(),
        }

    def _password_burst_health(self) -> dict:
        correlator = getattr(self, "identity_correlator", None)
        if correlator is not None and hasattr(correlator, "status"):
            return correlator.status()
        from client_identity_correlation import PasswordBurstCorrelator
        return PasswordBurstCorrelator.idle_status()

    def update_whitelist(self, ips: Set[str]):
        """Update whitelisted IPs (thread-safe)."""
        with self._lock:
            self.whitelist_ips = set(ips)

    # ── Internal callback ─────────────────────────────────────────

    def _on_event_callback(self, reason, context, event_handle):
        """
        Called by EvtSubscribe for each matching event.
        Runs on a win32 thread — keep it fast.
        """
        if reason != win32evtlog.EvtSubscribeActionDeliver:
            return

        if not self._running:
            return

        try:
            event = self._parse_event(event_handle)
            if event is None:
                return  # filtered out

            # Apply whitelist filter
            src_ip = event.get("source_ip", "")
            if src_ip and src_ip in self.whitelist_ips:
                self._stats["events_filtered"] += 1
                return

            # Apply account filter
            username = event.get("username", "")
            if self._is_ignored_account(username):
                self._stats["events_filtered"] += 1
                return

            # Apply logon type filter (for Event 4624)
            logon_type = event.get("logon_type")
            if logon_type is not None and logon_type in IGNORED_LOGON_TYPES:
                self._stats["events_filtered"] += 1
                return

            self._stats["events_processed"] += 1
            try:
                if self.identity_correlator is not None:
                    self.identity_correlator.record(event)
            except Exception:
                pass

            # Forward to threat engine (non-blocking)
            try:
                self.on_event(event)
            except Exception as e:
                log(f"[EVENTLOG] on_event callback error: {e}")

        except Exception as e:
            self._stats["errors"] += 1
            log(f"[EVENTLOG] Event parse error: {e}")

    # ── Event Parsing ─────────────────────────────────────────────

    def _parse_event(self, handle) -> Optional[dict]:
        """
        Render event to XML and extract structured data.
        Returns None if event should be filtered.
        """
        try:
            xml_str = win32evtlog.EvtRender(handle, win32evtlog.EvtRenderEventXml)
            root = ET.fromstring(xml_str)

            # XML namespaces
            ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

            # System section
            system = root.find("e:System", ns)
            if system is None:
                return None

            event_id_el = system.find("e:EventID", ns)
            event_id = int(event_id_el.text) if event_id_el is not None and event_id_el.text else 0

            channel_el = system.find("e:Channel", ns)
            channel = channel_el.text if channel_el is not None else ""

            time_el = system.find("e:TimeCreated", ns)
            timestamp = time_el.get("SystemTime", "") if time_el is not None else ""

            computer_el = system.find("e:Computer", ns)
            computer = computer_el.text if computer_el is not None else ""

            provider_el = system.find("e:Provider", ns)
            provider = provider_el.get("Name", "") if provider_el is not None else ""

            # EventData section — varies per event
            event_data = {}
            data_section = root.find("e:EventData", ns)
            if data_section is not None:
                for data_el in data_section.findall("e:Data", ns):
                    name = data_el.get("Name", "")
                    value = data_el.text or ""
                    if name:
                        event_data[name] = value

            # Build structured result
            event_type = EVENT_TYPE_MAP.get(event_id, f"unknown_{event_id}")
            safe_raw = self._sanitize_event_data(event_data, event_id)

            result = {
                "event_id": event_id,
                "event_type": event_type,
                "channel": channel,
                "timestamp": timestamp,
                "computer": computer,
                "provider": provider,
                # Extracted fields (may be empty depending on event type)
                "source_ip": self._extract_ip(event_data, event_id),
                "username": self._extract_username(event_data, event_id),
                "actor_username": self._extract_actor_username(event_data, event_id),
                "actor_domain": self._extract_domain(
                    event_data, "SubjectDomainName", event_id
                ),
                "target_domain": self._extract_domain(
                    event_data, "TargetDomainName", event_id
                ),
                "result": self._extract_result(event_data, event_id),
                "logon_type": self._extract_logon_type(event_data, event_id),
                "target_service": self._detect_service(event_id, channel, event_data),
                "target_port": self._detect_port(event_id, event_data),
                "auth_package": (
                    event_data.get("AuthenticationPackageName")
                    or event_data.get("AuthenticationPackage")
                    or ""
                ),
                "logon_process": (
                    event_data.get("LogonProcessName")
                    or event_data.get("LogonProcess")
                    or ""
                ),
                "status": event_data.get("Status", ""),
                "substatus": event_data.get("SubStatus", ""),
                "workstation": event_data.get("WorkstationName", ""),
                "process_name": event_data.get("NewProcessName", event_data.get("ProcessName", "")),
                "service_name": event_data.get("ServiceName", ""),
                # Local correlation only — identity events use a whitelist.
                "raw_data": safe_raw,
            }

            return result

        except Exception as e:
            log(f"[EVENTLOG] XML parse error: {e}")
            return None

    # ── Field Extractors ──────────────────────────────────────────

    @staticmethod
    def _extract_ip(data: dict, event_id: int) -> str:
        """Extract source IP from event data."""
        # Security log events
        ip = data.get("IpAddress", "")
        if ip and ip not in ("-", "::1", "127.0.0.1", ""):
            return ip

        # MSSQL events often have client info in message text
        if event_id in (18453, 18456):
            # Pattern: "CLIENT: 1.2.3.4"
            for key in ("Message", "EventMessage"):
                msg = data.get(key, "")
                if "CLIENT:" in msg.upper():
                    parts = msg.upper().split("CLIENT:")
                    if len(parts) > 1:
                        ip_part = parts[1].strip().strip("[]").split("]")[0].strip()
                        if ip_part and ip_part not in ("-", "::1", "127.0.0.1"):
                            return ip_part

        # RDP events
        if event_id == 1149:
            return data.get("Param3", data.get("IpAddress", ""))

        return ""

    @staticmethod
    def _extract_username(data: dict, event_id: int) -> str:
        """Extract target username from event data."""
        # Standard logon / account events (4723/4724: TargetUserName)
        username = data.get("TargetUserName", "")
        if not username:
            username = data.get("SubjectUserName", "")
        if not username:
            username = data.get("UserName", "")

        # MSSQL — login name from event data
        if event_id in (18453, 18456) and not username:
            username = data.get("Param1", "")

        # RDP 1149
        if event_id == 1149:
            username = data.get("Param1", username)

        return username

    @staticmethod
    def _extract_actor_username(data: dict, event_id: int) -> str:
        """Subject/actor that initiated the change (distinct from target)."""
        if event_id not in (4723, 4724, 4720, 4732, 4735):
            return ""
        actor = (data.get("SubjectUserName") or "").strip()
        if actor in ("-", ""):
            return ""
        return actor

    @staticmethod
    def _extract_domain(data: dict, key: str, event_id: int) -> str:
        if event_id not in (4723, 4724, 4720, 4732, 4735):
            return ""
        value = (data.get(key) or "").strip()
        return "" if value in ("-", "") else value

    @staticmethod
    def _extract_result(data: dict, event_id: int) -> str:
        if event_id not in (4723, 4724):
            return ""
        status = str(data.get("Status") or data.get("FailureCode") or "").strip()
        if not status or status in ("-",):
            # Success audits often omit Status; treat as success when event exists.
            return "success"
        try:
            code = int(status, 16) if status.lower().startswith("0x") else int(status)
            return "success" if code == 0 else "failure"
        except Exception:
            return "unknown"

    @staticmethod
    def _sanitize_event_data(data: dict, event_id: int) -> dict:
        """Drop password-like keys; whitelist identity EventData for 4723/4724."""
        if not isinstance(data, dict):
            return {}
        if event_id in (4723, 4724):
            allow = {
                "SubjectUserName", "SubjectDomainName", "SubjectUserSid",
                "TargetUserName", "TargetDomainName", "TargetUserSid",
                "Status", "FailureCode",
            }
            return {
                key: str(data.get(key) or "")[:256]
                for key in allow
                if key in data
            }
        banned = {
            "password", "Password", "NewPassword", "OldPassword",
            "credentials", "Credential", "secret", "token",
        }
        return {
            key: value
            for key, value in data.items()
            if key not in banned and "password" not in key.lower()
        }

    @staticmethod
    def _extract_logon_type(data: dict, event_id: int) -> Optional[int]:
        """Extract logon type (only for Event 4624/4625)."""
        if event_id not in (4624, 4625):
            return None
        lt_str = data.get("LogonType", "")
        try:
            return int(lt_str) if lt_str else None
        except (ValueError, TypeError):
            return None

    @staticmethod
    def _detect_service(event_id: int, channel: str, data: dict) -> str:
        """Infer which service is being targeted based on event source.

        RDP with NLA/CredSSP writes Security 4624/4625 as **LogonType 3**
        (Network), not type 10. Classifying those as ``Network`` made RDP
        block rules never fire while honeypot was optional/off. Prefer RDP
        when NLA fingerprints or a recent TerminalServices 1149 exist.
        """
        if event_id in (18453, 18456, 15457, 17135):
            return "MSSQL"
        if event_id in (1149, 21, 24, 25) or "TerminalServices" in (channel or ""):
            if event_id == 1149:
                note_rdp_source_ip(
                    str(data.get("Param3") or data.get("IpAddress") or "")
                )
            return "RDP"
        if event_id in (4624, 4625):
            logon_type = data.get("LogonType", "")
            try:
                lt = int(logon_type) if logon_type else 0
            except (ValueError, TypeError):
                lt = 0
            if lt == 10:
                return "RDP"
            if lt == 3:
                ip = str(data.get("IpAddress") or "")
                if _rdp_hint_recent(ip):
                    return "RDP"
                auth = str(
                    data.get("AuthenticationPackageName")
                    or data.get("AuthenticationPackage")
                    or ""
                ).strip().lower()
                proc = str(
                    data.get("LogonProcessName") or data.get("LogonProcess") or ""
                ).strip().lower()
                # NLA / CredSSP: Negotiate + User32/Advapi (not NtLmSsp SMB).
                if "negotiate" in auth:
                    return "RDP"
                if (
                    proc in ("user32", "advapi")
                    or proc.startswith("user32")
                    or proc.startswith("advapi")
                ):
                    return "RDP"
                if "ntlmssp" in proc.replace(" ", ""):
                    return "Network"
                # External type-3 with NTLM and no workstation often RDP NLA scanners.
                workstation = str(data.get("WorkstationName") or "").strip()
                if "ntlm" in auth and (not workstation or workstation == "-"):
                    return "RDP"
                return "Network"
        return "System"

    @staticmethod
    def _detect_port(event_id: int, data: dict) -> int:
        """Infer target port if possible."""
        if event_id in (18453, 18456, 15457, 17135):
            return 1433
        if event_id in (1149, 21, 24, 25):
            return 3389
        if event_id in (4624, 4625):
            # Same NLA heuristics as _detect_service — type 3 can still be RDP:3389.
            svc = EventLogWatcher._detect_service(event_id, "", data)
            if svc == "RDP":
                return 3389
            if svc == "MSSQL":
                return 1433
            if svc in ("Network", "SMB", "NETWORK"):
                return 445
        return 0

    @staticmethod
    def _is_ignored_account(username: str) -> bool:
        """Check if username is a system/machine account to ignore."""
        if not username:
            return True
        upper = username.upper()
        if upper in IGNORED_ACCOUNTS:
            return True
        if upper.endswith("$"):  # Machine accounts
            return True
        for prefix in IGNORED_ACCOUNT_PREFIXES:
            if upper.startswith(prefix.upper()):
                return True
        return False
