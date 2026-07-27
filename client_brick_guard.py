#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Brick-prevention guards (C-BRICK-1 / C-BRICK-6).

C-BRICK-1  account_linked != true → local critical auto forbidden
           (disable_account / silent-hours disable·logoff). Fail-closed
           skip + alert ``skipped_unlinked``. Link cache max age 15 min.
C-BRICK-1.3 admin-class auto-disable only with break-glass:
           other enabled local admin **or** cloud ``undo_mail_path`` live.
C-BRICK-6  Never close the last enabled local Administrators path without
           undo-mail; rollback disable + ``critical_action_rolled_back``.
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
SKIP_REASON_NO_BREAK_GLASS = "skipped_no_break_glass"
THREAT_ROLLED_BACK = "critical_action_rolled_back"

# Process-memory only: never durable-cache a previous true across restart.
_undo_mail_cache = {"value": False, "at": 0.0}
_UNDO_MAIL_CACHE_TTL_SEC = 60.0


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

        if tok or api_client is not None:
            try:
                refreshed = refresh_account_link_status(tok, api_client=api_client)
                if refreshed is True:
                    return True
                if refreshed is False:
                    return False
            except Exception as e:
                log(f"[BRICK] account link refresh failed (fail-closed): {e}")

        return False
    except Exception as e:
        log(f"[BRICK] account_linked_for_auto error (fail-closed): {e}")
        return False


def _extract_undo_mail_flag(payload: Any) -> Optional[bool]:
    """Parse additive account-status fields (contract ≥1.4.38). None = missing."""
    if not isinstance(payload, dict):
        return None
    if "undo_mail_path" in payload:
        return bool(payload.get("undo_mail_path"))
    recovery = payload.get("recovery")
    if isinstance(recovery, dict) and "undo_mail_ready" in recovery:
        return bool(recovery.get("undo_mail_ready"))
    if isinstance(recovery, dict) and "undo_mail_path" in recovery:
        return bool(recovery.get("undo_mail_path"))
    bg = payload.get("break_glass")
    if isinstance(bg, dict) and "undo_mail" in bg:
        return bool(bg.get("undo_mail"))
    return None


def probe_undo_mail_path(
    *,
    token: str = "",
    api_client=None,
    force: bool = False,
) -> bool:
    """C-BRICK-1.3 / C-BRICK-5: cloud undo-mail path live?

    Fail-closed: missing field / error → False.
    Short in-memory TTL only (never durable true across restart).
    """
    now = time.time()
    if (
        not force
        and _undo_mail_cache["at"]
        and (now - float(_undo_mail_cache["at"])) < _UNDO_MAIL_CACHE_TTL_SEC
    ):
        return bool(_undo_mail_cache["value"])

    live = False
    try:
        tok = (token or "").strip()
        if not tok and api_client is not None and hasattr(api_client, "token_getter"):
            try:
                tok = (api_client.token_getter() or "").strip()  # type: ignore[attr-defined]
            except Exception:
                tok = ""
        resp = None
        if api_client is not None and hasattr(api_client, "get_account_status") and tok:
            try:
                resp = api_client.get_account_status(tok)
            except Exception:
                resp = None
        if resp is None and api_client is not None and tok:
            try:
                resp = api_client.api_request(
                    "GET",
                    "agent/account-status",
                    params={"token": tok},
                    timeout=8,
                    verbose_logging=False,
                )
            except Exception:
                resp = None
        flag = _extract_undo_mail_flag(resp)
        live = bool(flag) if flag is not None else False
    except Exception as e:
        log(f"[BRICK] undo_mail_path probe error (fail-closed): {e}")
        live = False

    _undo_mail_cache["value"] = live
    _undo_mail_cache["at"] = now
    return live


def admin_class_break_glass_ok(
    username: str,
    *,
    token: str = "",
    api_client=None,
) -> bool:
    """True when admin-class auto-disable has a break-glass path (C-BRICK-1.3).

    Break-glass = another enabled local admin remains after disable, **or**
    cloud undo-mail path is live.
    """
    uname = (username or "").strip()
    if not uname:
        return False
    if not is_enabled_local_admin(uname):
        return True
    if not would_close_last_admin(uname):
        return True
    return probe_undo_mail_path(token=token, api_client=api_client)


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


def emit_skipped_no_break_glass(
    alert_pipeline=None,
    *,
    action: str,
    username: str = "",
) -> None:
    """Admin-class auto skipped — no peer admin and undo-mail path not live."""
    uname = (username or "").strip()
    log(
        f"[BRICK] {SKIP_REASON_NO_BREAK_GLASS} action={action}"
        + (f" user={uname}" if uname else "")
    )
    if alert_pipeline is None:
        return
    try:
        payload = {
            "severity": "warning",
            "threat_type": SKIP_REASON_NO_BREAK_GLASS,
            "title": "Otomatik işlem atlandı — break-glass yok",
            "description": (
                f"Admin-class otomatik aksiyon ({action}) C-BRICK-1.3 nedeniyle "
                f"atlandı: başka aktif local admin yok ve cloud undo-mail path "
                f"canlı değil"
                + (f" (hedef: {uname})." if uname else ".")
            ),
            "username": uname,
            "skip_reason": SKIP_REASON_NO_BREAK_GLASS,
            "auto_response_taken": [SKIP_REASON_NO_BREAK_GLASS],
            "threat_score": 55,
            "recommended_action": (
                "Cloud C-BRICK-5 undo-mail path’i açın veya ikinci bir local "
                "admin bırakın; ya da dashboard’dan onaylı IR kullanın."
            ),
        }
        if hasattr(alert_pipeline, "handle_alert"):
            alert_pipeline.handle_alert(payload)
        elif hasattr(alert_pipeline, "send_urgent"):
            alert_pipeline.send_urgent(payload)
    except Exception as e:
        log(f"[BRICK] skipped_no_break_glass alert error: {e}")


def emit_critical_action_rolled_back(
    alert_pipeline=None,
    *,
    action: str,
    username: str = "",
    reason: str = "",
) -> None:
    """C-BRICK-6: rollback after action would leave zero admin path."""
    uname = (username or "").strip()
    why = (reason or SKIP_REASON_LAST_ADMIN).strip()
    log(
        f"[BRICK] {THREAT_ROLLED_BACK} action={action}"
        + (f" user={uname}" if uname else "")
        + f" reason={why}"
    )
    if alert_pipeline is None:
        return
    try:
        payload = {
            "severity": "critical",
            "threat_type": THREAT_ROLLED_BACK,
            "title": "Kritik aksiyon geri alındı",
            "description": (
                f"Yerel aksiyon ({action}) C-BRICK-6 nedeniyle geri alındı"
                + (f" (hedef: {uname})" if uname else "")
                + f": {why}."
            ),
            "username": uname,
            "rollback_reason": why,
            "auto_response_taken": [THREAT_ROLLED_BACK, "enable_account"],
            "threat_score": 80,
            "recommended_action": (
                "Dashboard’dan IR kullanın; son admin yolunu otomatik kapatmayın."
            ),
        }
        if hasattr(alert_pipeline, "handle_alert"):
            alert_pipeline.handle_alert(payload)
        elif hasattr(alert_pipeline, "send_urgent"):
            alert_pipeline.send_urgent(payload)
    except Exception as e:
        log(f"[BRICK] rolled_back alert error: {e}")


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
