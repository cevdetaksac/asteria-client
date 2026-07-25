#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Logon challenge — require email/dashboard approval before session stays open.

When enabled: successful remote logon → immediate logoff + urgent API challenge.
Until the owner approves (email "This is me" / dashboard), IP is not whitelisted
and subsequent logons are dropped the same way.

Break-glass: dashboard can approve/whitelist; local PIN does not bypass this
(owner must confirm identity via Account email).
"""

from __future__ import annotations

import threading
import time
import uuid
from typing import Callable, Optional, Set

from client_helpers import log

# Local pending challenges (also reported to API when online)
_PENDING_TTL = 3600  # 1 hour


class LogonChallengeGuard:
    """Challenge successful logons until owner approval."""

    def __init__(
        self,
        auto_response=None,
        alert_pipeline=None,
        api_client=None,
        token_getter: Optional[Callable[[], str]] = None,
        threat_engine=None,
        event_watcher=None,
    ):
        self.auto_response = auto_response
        self.alert_pipeline = alert_pipeline
        self.api_client = api_client
        self.token_getter = token_getter or (lambda: "")
        self.threat_engine = threat_engine
        self.event_watcher = event_watcher

        self._lock = threading.RLock()
        self.enabled = False  # flipped by threats/config or local config
        self.auto_logoff = True
        self.require_whitelist_after_approve = True
        # IPs approved locally after API poll
        self._approved_ips: Set[str] = set()
        # challenge_id → meta
        self._pending: dict = {}
        self._stats = {
            "challenges": 0,
            "logoffs": 0,
            "approvals": 0,
            "skips_whitelist": 0,
            "skips_disabled": 0,
        }

    def update_config(self, cfg: dict) -> None:
        if not isinstance(cfg, dict):
            return
        with self._lock:
            if "enabled" in cfg:
                self.enabled = bool(cfg.get("enabled"))
            if "auto_logoff" in cfg:
                self.auto_logoff = bool(cfg.get("auto_logoff", True))
            log(f"[LOGON-CHALLENGE] config enabled={self.enabled} "
                f"auto_logoff={self.auto_logoff}")

    def is_approved(self, ip: str) -> bool:
        if not ip:
            return False
        with self._lock:
            if ip in self._approved_ips:
                return True
        # Also respect threat/auto whitelist
        try:
            if self.threat_engine and ip in getattr(self.threat_engine, "_whitelist_ips", set()):
                return True
        except Exception:
            pass
        try:
            if self.auto_response and self.auto_response._is_whitelisted(ip):
                return True
        except Exception:
            pass
        return False

    def approve_ip(self, ip: str, source: str = "api") -> None:
        if not ip:
            return
        with self._lock:
            self._approved_ips.add(ip)
            self._stats["approvals"] += 1
            # drop pending for this IP
            drop = [cid for cid, m in self._pending.items() if m.get("ip") == ip]
            for cid in drop:
                self._pending.pop(cid, None)

        # Sync whitelist sets
        try:
            if self.threat_engine:
                self.threat_engine._whitelist_ips.add(ip)
        except Exception:
            pass
        try:
            if self.auto_response:
                self.auto_response.whitelist_ips.add(ip)
                # Ensure not blocked
                try:
                    self.auto_response.unblock_ip(ip)
                except Exception:
                    pass
        except Exception:
            pass
        try:
            if self.event_watcher and hasattr(self.event_watcher, "whitelist_ips"):
                self.event_watcher.whitelist_ips.add(ip)
        except Exception:
            pass
        log(f"[LOGON-CHALLENGE] ✅ Approved IP {ip} via {source}")

    def handle_successful_logon(self, event: dict) -> bool:
        """
        Returns True if logon was challenged (logoff / blocked pending approval).
        """
        with self._lock:
            if not self.enabled:
                self._stats["skips_disabled"] += 1
                return False

        source_ip = (event.get("source_ip") or "").strip()
        username = (event.get("username") or "").strip()
        service = (
            event.get("target_service")
            or event.get("service")
            or "Logon"
        )
        logon_type = event.get("logon_type")

        # Skip local interactive without network IP (console) — optional
        if not source_ip or source_ip in ("127.0.0.1", "::1", "local"):
            return False

        # Unlock / Service logons already filtered upstream; still skip type 5/7
        if logon_type in (5, 7):
            return False

        if self.is_approved(source_ip):
            with self._lock:
                self._stats["skips_whitelist"] += 1
            return False

        challenge_id = str(uuid.uuid4())
        now = time.time()
        with self._lock:
            self._stats["challenges"] += 1
            self._pending[challenge_id] = {
                "ip": source_ip,
                "username": username,
                "service": service,
                "logon_type": logon_type,
                "created_at": now,
                "event_id": event.get("event_id"),
            }
            # prune old
            cutoff = now - _PENDING_TTL
            self._pending = {
                k: v for k, v in self._pending.items()
                if v.get("created_at", 0) >= cutoff
            }

        log(
            f"[LOGON-CHALLENGE] 🔐 Challenge {challenge_id[:8]}… "
            f"{source_ip} user={username} svc={service} — forcing logoff"
        )

        actions = []
        if self.auto_logoff and self.auto_response and username:
            try:
                # C-BRICK-1: auto logoff requires fresh account_linked
                from client_brick_guard import account_linked_for_auto

                tok = ""
                try:
                    tok = (self.token_getter() or "") if self.token_getter else ""
                except Exception:
                    tok = ""
                if not account_linked_for_auto(
                    token=tok, api_client=self.api_client
                ):
                    actions.append("skipped_unlinked")
                    try:
                        from client_brick_guard import emit_skipped_unlinked
                        emit_skipped_unlinked(
                            self.alert_pipeline,
                            action="logoff_user",
                            username=username,
                        )
                    except Exception:
                        pass
                elif self.auto_response.logoff_user(username, auto=True):
                    actions.append("logoff_user")
                    with self._lock:
                        self._stats["logoffs"] += 1
            except Exception as e:
                log(f"[LOGON-CHALLENGE] logoff error: {e}")

        # Report to API (email "This is me" button)
        token = ""
        try:
            token = self.token_getter() or ""
        except Exception:
            pass
        if token and self.api_client and hasattr(self.api_client, "report_logon_challenge"):
            try:
                self.api_client.report_logon_challenge(token, {
                    "challenge_id": challenge_id,
                    "source_ip": source_ip,
                    "username": username,
                    "service": str(service),
                    "logon_type": logon_type,
                    "event_id": event.get("event_id"),
                    "actions_taken": actions,
                    "message": (
                        "Successful logon requires owner approval. "
                        "Session was logged off pending email confirmation."
                    ),
                })
            except Exception as e:
                log(f"[LOGON-CHALLENGE] API report error: {e}")

        if self.alert_pipeline:
            try:
                self.alert_pipeline.send_urgent({
                    "alert_id": challenge_id,
                    "severity": "critical",
                    "threat_type": "logon_challenge",
                    "title": f"🔐 Logon approval required — {source_ip}",
                    "description": (
                        f"Successful {service} logon by {username} from {source_ip}. "
                        f"Session logged off until you confirm via email/dashboard "
                        f"('This is me') — IP will be whitelisted on approve."
                    ),
                    "source_ip": source_ip,
                    "target_service": service,
                    "username": username,
                    "threat_score": 90,
                    "force_urgent": True,
                    "auto_response_taken": actions,
                    "challenge_id": challenge_id,
                })
            except Exception as e:
                log(f"[LOGON-CHALLENGE] urgent alert error: {e}")

        return True

    def sync_approvals_from_api(self) -> int:
        """Poll API for approved challenges / whitelist updates. Returns new approvals."""
        token = ""
        try:
            token = self.token_getter() or ""
        except Exception:
            pass
        if not token or not self.api_client:
            return 0
        if not hasattr(self.api_client, "fetch_logon_challenge_status"):
            return 0
        try:
            data = self.api_client.fetch_logon_challenge_status(token)
        except Exception as e:
            log(f"[LOGON-CHALLENGE] poll error: {e}")
            return 0
        if not data:
            return 0
        count = 0
        approved = data.get("approved_ips") or data.get("whitelist_ips") or []
        for ip in approved:
            ip = str(ip).strip()
            if ip and not self.is_approved(ip):
                self.approve_ip(ip, source="api_poll")
                count += 1
        for item in data.get("approved_challenges") or []:
            if isinstance(item, dict):
                ip = str(item.get("source_ip") or item.get("ip") or "").strip()
                if ip and not self.is_approved(ip):
                    self.approve_ip(ip, source="api_challenge")
                    count += 1
        return count

    def get_stats(self) -> dict:
        with self._lock:
            s = dict(self._stats)
            s["pending"] = len(self._pending)
            s["approved_ips"] = len(self._approved_ips)
            s["enabled"] = self.enabled
            return s
