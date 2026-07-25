#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Brick-prevention guards (C-BRICK-1 / C-BRICK-6).

C-BRICK-1  account_linked != true → local critical auto forbidden
           (disable_account / silent-hours disable·logoff). Fail-closed
           skip + alert ``skipped_unlinked``. Link cache max age 15 min.
C-BRICK-6  Never close the last enabled local Administrators path;
           rollback disable if the host would be left with zero admins.
"""

from __future__ import annotations

import time
from typing import Any, Optional, Set

from client_helpers import log

# C-BRICK-1 — do not trust link cache older than this for auto paths
ACCOUNT_LINK_CACHE_MAX_AGE_SEC = 15 * 60

# Wire: POST /api/commands/result.status — lifecycle only (not SAM active/disabled)
COMMAND_LIFECYCLE_STATUSES: Set[str] = {
    "pending",
    "running",
    "completed",
    "failed",
    "expired",
    "rejected",
}

SKIP_REASON_UNLINKED = "skipped_unlinked"
SKIP_REASON_LAST_ADMIN = "last_admin"


def account_link_cache_age_sec() -> Optional[float]:
    """Seconds since account_link.json was updated, or None if unknown."""
    try:
        from client_utils import load_account_link_pref

        data = load_account_link_pref()
        ts = data.get("updated_at")
        if ts is None:
            return None
        return max(0.0, time.time() - float(ts))
    except Exception:
        return None


def account_linked_for_auto(
    *,
    max_age_sec: float = ACCOUNT_LINK_CACHE_MAX_AGE_SEC,
    token: str = "",
    api_client=None,
) -> bool:
    """True only when this agent is linked and the cache is fresh enough.

    Fail-closed: stale linked cache must refresh successfully to True;
    missing/unknown/unlinked → False (local critical auto skipped).
    """
    try:
        from client_utils import load_account_link_pref, refresh_account_link_status

        data = load_account_link_pref()
        linked = bool(data.get("linked"))
        age = account_link_cache_age_sec()
        fresh = age is not None and age <= float(max_age_sec)

        if linked and fresh:
            return True

        tok = (token or "").strip()
        if not tok and api_client is not None and hasattr(api_client, "token_getter"):
            try:
                tok = (api_client.token_getter() or "").strip()  # type: ignore[attr-defined]
            except Exception:
                tok = ""

        # Stale or unlinked: try cloud refresh when we have a token path
        if tok or api_client is not None:
            try:
                refreshed = refresh_account_link_status(tok, api_client=api_client)
                if refreshed is True:
                    return True
                if refreshed is False:
                    return False
            except Exception as e:
                log(f"[BRICK] account link refresh failed (fail-closed): {e}")

        # Fail-closed: not linked, or linked-but-stale with no fresh confirmation
        return False
    except Exception as e:
        log(f"[BRICK] account_linked_for_auto error (fail-closed): {e}")
        return False


def emit_skipped_unlinked(
    alert_pipeline=None,
    *,
    action: str,
    username: str = "",
) -> None:
    """Log + optional alert when local critical auto is skipped (C-BRICK-1)."""
    uname = (username or "").strip()
    log(
        f"[BRICK] {SKIP_REASON_UNLINKED} action={action}"
        + (f" user={uname}" if uname else "")
    )
    if alert_pipeline is None:
        return
    try:
        payload = {
            "severity": "warning",
            "threat_type": SKIP_REASON_UNLINKED,
            "title": "Otomatik işlem atlandı — hesap bağlı değil",
            "description": (
                f"Yerel kritik otomatik aksiyon ({action}) C-BRICK-1 nedeniyle "
                f"atlandı. Asteria Account bağlantısı gerekir"
                + (f" (hedef: {uname})." if uname else ".")
            ),
            "username": uname,
            "skip_reason": SKIP_REASON_UNLINKED,
            "auto_response_taken": [SKIP_REASON_UNLINKED],
            "threat_score": 40,
        }
        if hasattr(alert_pipeline, "handle_alert"):
            alert_pipeline.handle_alert(payload)
        elif hasattr(alert_pipeline, "send_urgent"):
            alert_pipeline.send_urgent(payload)
    except Exception as e:
        log(f"[BRICK] skipped_unlinked alert error: {e}")


def count_enabled_local_admins() -> int:
    """How many local Administrators group members are currently enabled."""
    try:
        from client_remote_session import list_local_users

        n = 0
        for u in list_local_users(include_disabled=True):
            if u.get("is_admin") and u.get("enabled"):
                n += 1
        return n
    except Exception as e:
        log(f"[BRICK] count_enabled_local_admins error: {e}")
        # Fail-closed for disable: treat as unknown → refuse last-admin risk
        return 0


def is_enabled_local_admin(username: str) -> bool:
    try:
        from client_remote_session import find_local_user

        u = find_local_user(username, include_disabled=True)
        return bool(u and u.get("is_admin") and u.get("enabled"))
    except Exception:
        return False


def would_close_last_admin(username: str) -> bool:
    """True if disabling this user would remove the only enabled admin."""
    uname = (username or "").strip()
    if not uname:
        return False
    if not is_enabled_local_admin(uname):
        return False
    return count_enabled_local_admins() <= 1


def lifecycle_status_from_result(result: Optional[dict]) -> str:
    """Map a command handler result to wire lifecycle status (not SAM state)."""
    if not isinstance(result, dict):
        return "failed"
    raw = result.get("status")
    if isinstance(raw, str) and raw in COMMAND_LIFECYCLE_STATUSES:
        return raw
    if result.get("success") or result.get("ok"):
        return "completed"
    return "failed"


def sam_account_status(enabled: Optional[bool]) -> Optional[str]:
    """SAM active/disabled label — only for result.data, never commands/result.status."""
    if enabled is None:
        return None
    return "active" if enabled else "disabled"
