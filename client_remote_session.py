#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Remote session prepare — list local users, auth, reconnect Disconnected desktop.

Password stays in RAM only (ctypes buffer wiped). Never log credentials.
Session 0 agent must use user-helper / tscon / WTSConnectSession — never fake JPEG.
"""

from __future__ import annotations

import ctypes
import json
import time
from ctypes import wintypes
from typing import Any, Dict, List, Optional, Tuple

from client_helpers import log
from client_winproc import run_hidden, run_ps

LOGON32_LOGON_INTERACTIVE = 2
LOGON32_LOGON_UNLOCK = 7
LOGON32_PROVIDER_DEFAULT = 0

ERROR_LOGON_FAILURE = 1326
ERROR_ACCOUNT_DISABLED = 1331
ERROR_ACCOUNT_LOCKED_OUT = 1909
ERROR_PASSWORD_EXPIRED = 1330
ERROR_LOGON_TYPE_NOT_GRANTED = 1385


def _wipe_unicode_buffer(buf) -> None:
    try:
        ctypes.memset(ctypes.addressof(buf), 0, ctypes.sizeof(buf))
    except Exception:
        pass


def validate_windows_credentials(
    username: str,
    password: str,
    *,
    unlock: bool = False,
) -> Tuple[bool, str, int]:
    """LogonUser check. Returns (ok, error_code_or_empty, winerr).

    Does not log password. Wipes the unicode buffer after use.
    """
    user = (username or "").strip()
    if not user:
        return False, "AUTH_FAILED", 0
    # DOMAIN\\user or user@domain → split
    domain = "."
    sam = user
    if "\\" in user:
        domain, sam = user.split("\\", 1)
    elif "@" in user:
        sam, domain = user.split("@", 1)

    logon_type = LOGON32_LOGON_UNLOCK if unlock else LOGON32_LOGON_INTERACTIVE
    adv = ctypes.windll.advapi32
    token = wintypes.HANDLE()
    pwd_buf = ctypes.create_unicode_buffer(password or "")
    try:
        ok = adv.LogonUserW(
            sam,
            domain,
            pwd_buf,
            logon_type,
            LOGON32_PROVIDER_DEFAULT,
            ctypes.byref(token),
        )
        if not ok:
            err = int(ctypes.GetLastError() or 0)
            if err in (ERROR_ACCOUNT_LOCKED_OUT,):
                return False, "ACCOUNT_LOCKED", err
            if err in (ERROR_ACCOUNT_DISABLED,):
                return False, "ACCOUNT_DISABLED", err
            if err in (ERROR_PASSWORD_EXPIRED,):
                return False, "AUTH_FAILED", err
            return False, "AUTH_FAILED", err
        try:
            ctypes.windll.kernel32.CloseHandle(token)
        except Exception:
            pass
        return True, "", 0
    finally:
        _wipe_unicode_buffer(pwd_buf)


def list_local_users(*, include_disabled: bool = True) -> List[Dict[str, Any]]:
    """Local SAM users via PowerShell; enriched with session info.

    Disabled accounts are included by default so Server Management / cloud
    can show and toggle active ↔ disabled. Pass ``include_disabled=False``
    only for legacy remote-desktop dropdowns that want enabled-only.
    """
    users: List[Dict[str, Any]] = []
    try:
        rc, out, _ = run_ps(
            "Get-LocalUser | Select-Object Name, FullName, Enabled, LastLogon, "
            "SID, PrincipalSource, Description, PasswordRequired, "
            "UserMayChangePassword, PasswordExpires | ConvertTo-Json -Depth 3",
            timeout=15,
        )
        if rc == 0 and (out or "").strip():
            data = json.loads(out.strip())
            if isinstance(data, dict):
                data = [data]
            for u in data or []:
                name = (u.get("Name") or "").strip()
                if not name:
                    continue
                enabled = bool(u.get("Enabled", True))
                if not include_disabled and not enabled:
                    continue
                sid = ""
                try:
                    sid_obj = u.get("SID")
                    if isinstance(sid_obj, dict):
                        sid = str(sid_obj.get("Value") or "")
                    else:
                        sid = str(sid_obj or "")
                except Exception:
                    sid = ""
                last = u.get("LastLogon")
                last_iso = ""
                if isinstance(last, str) and last:
                    # /Date(…)/ or already readable — best-effort
                    if "/Date(" in last:
                        try:
                            ms = int(last.split("(")[1].split(")")[0].split("+")[0].split("-")[0])
                            last_iso = time.strftime(
                                "%Y-%m-%dT%H:%M:%SZ", time.gmtime(ms / 1000.0)
                            )
                        except Exception:
                            last_iso = ""
                    else:
                        last_iso = last
                src = str(u.get("PrincipalSource") or "")
                protected = _is_protected_local_account(name)
                users.append({
                    "username": name,
                    "full_name": (u.get("FullName") or "") or "",
                    "description": (u.get("Description") or "") or "",
                    "sid": sid,
                    "enabled": enabled,
                    # SAM account state — never "active" (that word is WTS session state;
                    # cloud password modal confused Administrator status=active with a live SID).
                    "status": "enabled" if enabled else "disabled",
                    "account_status": "enabled" if enabled else "disabled",
                    "protected": protected,
                    "can_enable": (not enabled) and (not protected),
                    "can_disable": enabled and (not protected),
                    "local": "ActiveDirectory" not in src,
                    "is_admin": False,
                    "groups": [],
                    "last_logon": last_iso or None,
                    "has_session": False,
                    "session_id": None,
                    "session_status": None,
                })
    except Exception as e:
        log(f"[REMOTE-SESSION] list_local_users parse error: {e}")

    # Admin group membership (best-effort)
    try:
        rc2, out2, _ = run_ps(
            "Get-LocalGroupMember -Group Administrators -ErrorAction SilentlyContinue | "
            "Select-Object -ExpandProperty Name | ConvertTo-Json",
            timeout=12,
        )
        admin_names = set()
        if rc2 == 0 and (out2 or "").strip():
            raw = json.loads(out2.strip())
            if isinstance(raw, str):
                raw = [raw]
            for n in raw or []:
                short = str(n).split("\\")[-1].lower()
                admin_names.add(short)
        for u in users:
            if u["username"].lower() in admin_names:
                u["is_admin"] = True
                if "Administrators" not in u["groups"]:
                    u["groups"].append("Administrators")
    except Exception:
        pass

    # Attach live sessions
    sessions = enumerate_sessions_rich()
    by_user: Dict[str, dict] = {}
    for s in sessions:
        un = str(s.get("username") or "").lower()
        if un and un not in by_user:
            by_user[un] = s
    for u in users:
        if "groups" not in u:
            u["groups"] = []
        s = by_user.get(u["username"].lower())
        if s:
            st = str(s.get("status") or "").strip().lower()
            # Only live interactive sessions (Active/Connected) — Disc/Listen must
            # not mint a ghost session_id that cloud treats as an unlock target.
            live = st in ("active", "connected")
            u["has_session"] = live
            if live:
                try:
                    sid_n = int(s.get("session_id") or 0)
                except (TypeError, ValueError):
                    sid_n = 0
                u["session_id"] = sid_n or None
                u["session_status"] = s.get("status")
            else:
                u["session_id"] = None
                u["session_status"] = None
        else:
            u["has_session"] = False
            u["session_id"] = None
            u["session_status"] = None

    return users


def _is_protected_local_account(username: str) -> bool:
    try:
        from client_auto_response import PROTECTED_ACCOUNTS
        return str(username or "").strip().upper() in PROTECTED_ACCOUNTS
    except Exception:
        return str(username or "").strip().upper() in {
            "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "WDAGUTILITYACCOUNT",
        }


def find_local_user(username: str, *, include_disabled: bool = True) -> Optional[Dict[str, Any]]:
    """Return one enriched local-user row (or None)."""
    want = str(username or "").strip().lower()
    if not want:
        return None
    for u in list_local_users(include_disabled=include_disabled):
        if str(u.get("username") or "").strip().lower() == want:
            return u
    return None


def _can_capture(status: str, session_id: int, protocol: str, *, pre_logon: bool = False) -> bool:
    if session_id <= 0:
        return False
    if str(protocol or "").lower() in ("services",):
        return False
    if pre_logon:
        return True
    if str(protocol or "").lower() == "console":
        st = str(status or "").lower()
        return st in ("active", "connected", "listen", "")
    return str(status or "").lower() == "active"


def enumerate_sessions_rich() -> List[Dict[str, Any]]:
    """WTS sessions with can_capture flag."""
    from client_remote_desktop import RemoteDesktopStreamer
    raw = RemoteDesktopStreamer._enumerate_sessions()
    out = []
    for s in raw:
        sid = int(s.get("session_id") or 0)
        status = str(s.get("status") or "")
        protocol = str(s.get("protocol") or "")
        item = dict(s)
        item["can_capture"] = _can_capture(
            status, sid, protocol, pre_logon=bool(item.get("pre_logon"))
        )
        item.setdefault("client_name", None)
        item.setdefault("client_ip", None)
        item.setdefault("login_time", None)
        item.setdefault("idle_sec", None)
        out.append(item)
    return out


def enrich_sessions_can_capture(sessions: List[dict]) -> List[dict]:
    out = []
    for s in sessions or []:
        item = dict(s)
        try:
            sid = int(item.get("session_id") or 0)
        except (TypeError, ValueError):
            sid = 0
        status = str(item.get("status") or "")
        protocol = str(item.get("protocol") or "")
        item["can_capture"] = _can_capture(
            status, sid, protocol, pre_logon=bool(item.get("pre_logon"))
        )
        out.append(item)
    return out


def _wts_connect_session(session_id: int, password: str) -> bool:
    """Reconnect Disconnected session onto console (wtsapi32.WTSConnectSession)."""
    if session_id <= 0:
        return False
    try:
        wts = ctypes.windll.wtsapi32
        console = int(ctypes.windll.kernel32.WTSGetActiveConsoleSessionId())
        if console <= 0:
            console = session_id
        pwd_buf = ctypes.create_unicode_buffer(password or "")
        try:
            ok = wts.WTSConnectSession(
                wintypes.ULONG(session_id),
                wintypes.ULONG(console),
                pwd_buf,
                True,
            )
            if ok:
                log(f"[REMOTE-SESSION] WTSConnectSession({session_id}→{console}) ok")
                return True
            err = ctypes.GetLastError()
            log(f"[REMOTE-SESSION] WTSConnectSession({session_id}→{console}) failed err={err}")
            return False
        finally:
            _wipe_unicode_buffer(pwd_buf)
    except Exception as e:
        log(f"[REMOTE-SESSION] WTSConnectSession error: {e}")
        return False


def _tscon_to_console(session_id: int) -> bool:
    if session_id <= 0:
        return False
    rc, out, err = run_hidden(
        ["tscon", str(int(session_id)), "/dest:console"],
        timeout=15,
    )
    ok = rc == 0
    log(f"[REMOTE-SESSION] tscon {session_id}→console rc={rc} "
        f"{(out or err or '')[:80]}")
    return ok


def prepare_remote_session(
    *,
    username: str,
    password: str = "",
    session_id: Optional[int] = None,
    prefer: str = "existing_then_logon",
    timeout_sec: float = 45.0,
    progress_cb=None,
) -> Dict[str, Any]:
    """Make target user desktop Active + capturable before remote_stream_start.

    password: one-shot from dashboard — never written to disk/logs.
    prefer:
      - existing_then_logon (default): existing session, else console Winlogon
      - existing: require an existing interactive session
      - winlogon: console pre-logon UI (type credentials on stream)
    """
    user = (username or "").strip()
    prefer_l = str(prefer or "existing_then_logon").strip().lower()
    if prefer_l in ("winlogon", "console", "pre_logon", "pre-logon"):
        return _prepare_winlogon(progress_cb=progress_cb)

    if not user and prefer_l != "existing":
        # Empty username → operator wants the logon screen itself.
        return _prepare_winlogon(progress_cb=progress_cb)

    if not user:
        return {
            "success": False,
            "error": "AUTH_FAILED",
            "message": "username required",
            "data": {},
        }

    timeout_sec = max(10.0, min(float(timeout_sec or 45.0), 120.0))
    deadline = time.time() + timeout_sec
    pwd = password or ""
    method = "existing"

    def _progress(phase: str, msg: str = ""):
        if callable(progress_cb):
            try:
                progress_cb(phase, msg)
            except Exception:
                pass

    # 1) Credential gate (if password provided)
    if pwd:
        _progress("auth", "validating")
        ok, err_code, winerr = validate_windows_credentials(user, pwd, unlock=False)
        if not ok:
            # Try unlock logon type (locked desktop)
            ok2, err2, winerr2 = validate_windows_credentials(user, pwd, unlock=True)
            if not ok2:
                return {
                    "success": False,
                    "error": err_code or err2 or "AUTH_FAILED",
                    "message": f"LogonUser failed (winerr={winerr or winerr2})",
                    "data": {"username": user, "winerr": winerr or winerr2},
                }

    # 2) Resolve session
    sessions = enumerate_sessions_rich()
    target: Optional[dict] = None
    if session_id is not None:
        try:
            sid_i = int(session_id)
        except (TypeError, ValueError):
            sid_i = -1
        target = next((s for s in sessions if int(s.get("session_id") or 0) == sid_i), None)
        if target is None:
            return {
                "success": False,
                "error": "NO_INTERACTIVE_DESKTOP",
                "message": f"session_id={session_id} not found",
                "data": {"username": user, "session_id": session_id},
            }
    else:
        ul = user.lower()
        cands = [
            s for s in sessions
            if str(s.get("username") or "").lower() == ul and not s.get("pre_logon")
        ]
        if cands:
            # Prefer Active then highest session id
            cands.sort(
                key=lambda s: (
                    0 if str(s.get("status") or "").lower() == "active" else 1,
                    -int(s.get("session_id") or 0),
                )
            )
            target = cands[0]

    if target is None:
        if prefer_l == "existing":
            return {
                "success": False,
                "error": "UNSUPPORTED",
                "message": (
                    "No existing interactive session for this user. "
                    "Use prefer=winlogon to mirror the console logon UI, "
                    "or log on once via console/RDP / remote_logon."
                ),
                "data": {
                    "username": user,
                    "ready_for_stream": False,
                    "prefer": prefer,
                },
            }
        # Default: fall through to console Winlogon so credentials can be typed.
        _progress("winlogon", "no user session — console logon UI")
        wl = _prepare_winlogon(progress_cb=progress_cb)
        if wl.get("success"):
            wl.setdefault("data", {})["username"] = user
            wl["message"] = "ready_for_stream (winlogon — type credentials on stream)"
        return wl

    sid = int(target.get("session_id") or 0)
    status = str(target.get("status") or "")
    if target.get("pre_logon"):
        return _prepare_winlogon(progress_cb=progress_cb)

    # 3) Activate Disconnected
    if status.lower() != "active":
        _progress("reconnect", f"session={sid} status={status}")
        method = "unlock" if pwd else "existing"
        if pwd:
            _wts_connect_session(sid, pwd)
        _tscon_to_console(sid)
        # Wait until Active or timeout
        while time.time() < deadline:
            time.sleep(1.0)
            sessions = enumerate_sessions_rich()
            cur = next((s for s in sessions if int(s.get("session_id") or 0) == sid), None)
            if cur and str(cur.get("status") or "").lower() == "active":
                status = "Active"
                target = cur
                break
        if str(status).lower() != "active":
            return {
                "success": False,
                "error": "LOGON_TIMEOUT",
                "message": (
                    f"Session {sid} still {status} after reconnect attempts. "
                    "Desktop not Active — cannot capture."
                ),
                "data": {
                    "username": user,
                    "session_id": sid,
                    "session_status": status,
                    "ready_for_stream": False,
                },
            }

    # 4) Probe desktop bitmap via streamer helper (no stream start)
    _progress("probe", f"session={sid}")
    try:
        from client_remote_desktop import RemoteDesktopStreamer
        rd = RemoteDesktopStreamer(api_client=None, token_getter=lambda: "")
        rd._target_session_id = sid
        rd._target_username = user
        rd._use_user_helper = True
        jpeg, w, h = rd._grab_via_user_helper()
        if (not jpeg or w <= 0 or h <= 0) and time.time() < deadline:
            # One more tscon + probe
            _tscon_to_console(sid)
            time.sleep(0.8)
            jpeg, w, h = rd._grab_via_user_helper()
        if not jpeg or w <= 0 or h <= 0:
            return {
                "success": False,
                "error": "NO_INTERACTIVE_DESKTOP",
                "message": (
                    f"Active session {sid} but capture probe returned 0×0 "
                    "(lock screen / no desktop). Unlock interactively or retry."
                ),
                "data": {
                    "username": user,
                    "session_id": sid,
                    "session_status": "Active",
                    "screen": {"w": int(w or 0), "h": int(h or 0)},
                    "ready_for_stream": False,
                    "method": method,
                },
            }
        return {
            "success": True,
            "message": "ready_for_stream",
            "data": {
                "ready_for_stream": True,
                "session_id": sid,
                "username": user,
                "session_status": "Active",
                "screen": {"w": int(w), "h": int(h)},
                "method": method,
                # Cloud MUST Start with these — not topology=follow / omit-SID
                # (password → Default DXGI; 4.9.115).
                "topology": "session",
                "prefer": "default",
                "force_secure": False,
            },
        }
    except Exception as e:
        log(f"[REMOTE-SESSION] prepare probe error: {e}")
        return {
            "success": False,
            "error": "NO_INTERACTIVE_DESKTOP",
            "message": str(e),
            "data": {"username": user, "session_id": sid},
        }


def _prepare_winlogon(*, progress_cb=None) -> Dict[str, Any]:
    """Probe console Winlogon / input desktop for pre-logon remote desktop."""
    def _progress(phase: str, msg: str = ""):
        if callable(progress_cb):
            try:
                progress_cb(phase, msg)
            except Exception:
                pass

    _progress("winlogon", "probing console desktop")
    try:
        from client_rd_winlogon import probe_winlogon_capture, console_session_id
        probe = probe_winlogon_capture()
    except Exception as exc:
        return {
            "success": False,
            "error": "NO_WINLOGON_DESKTOP",
            "message": str(exc),
            "data": {"ready_for_stream": False, "method": "winlogon"},
        }
    sid = int(probe.get("session_id") or console_session_id() or 0)
    if not probe.get("ok"):
        return {
            "success": False,
            "error": probe.get("error") or "NO_WINLOGON_DESKTOP",
            "message": probe.get("message") or "console Winlogon not capturable",
            "data": {
                "ready_for_stream": False,
                "session_id": sid or None,
                "desktop": probe.get("desktop") or "",
                "method": "winlogon",
            },
        }
    return {
        "success": True,
        "message": "ready_for_stream (winlogon)",
        "data": {
            "ready_for_stream": True,
            "session_id": sid,
            "username": "",
            "session_status": "Connected",
            "screen": {
                "w": int(probe.get("width") or 0),
                "h": int(probe.get("height") or 0),
            },
            "desktop": probe.get("desktop") or "Winlogon",
            "method": "winlogon",
            "pre_logon": True,
        },
    }
