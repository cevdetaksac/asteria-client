# -*- coding: utf-8 -*-
"""Console WinSta0 / Winlogon desktop attach for pre-logon remote desktop.

When nobody is logged on, the interactive input desktop is typically
``Winlogon`` on window station ``WinSta0``. A Session-0 (SYSTEM) agent must
switch the process window station before OpenInputDesktop / BitBlt / SendInput
can see that surface.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
from typing import Optional, Tuple

from client_helpers import log

WINSTA_ALL_ACCESS = 0x037F
DESKTOP_GENERIC_ALL = 0x10000000
UOI_NAME = 2

_user32 = ctypes.windll.user32
_kernel32 = ctypes.windll.kernel32


def console_session_id() -> int:
    try:
        sid = int(_kernel32.WTSGetActiveConsoleSessionId())
        return sid if sid > 0 else 0
    except Exception:
        return 0


def desktop_name(hdesk) -> str:
    if not hdesk:
        return ""
    try:
        needed = wintypes.DWORD(0)
        _user32.GetUserObjectInformationW(hdesk, UOI_NAME, None, 0, ctypes.byref(needed))
        if needed.value <= 0:
            return ""
        buf = ctypes.create_unicode_buffer(max(1, needed.value // 2))
        if not _user32.GetUserObjectInformationW(
            hdesk, UOI_NAME, buf, needed, ctypes.byref(needed)
        ):
            return ""
        return (buf.value or "").strip()
    except Exception:
        return ""


def switch_to_winsta0() -> Tuple[bool, str]:
    """Attach this process to the interactive window station (WinSta0)."""
    try:
        OpenWindowStationW = _user32.OpenWindowStationW
        OpenWindowStationW.argtypes = [wintypes.LPCWSTR, wintypes.BOOL, wintypes.DWORD]
        OpenWindowStationW.restype = wintypes.HWINSTA
        hwinsta = OpenWindowStationW("WinSta0", False, WINSTA_ALL_ACCESS)
        if not hwinsta:
            return False, f"OpenWindowStation(WinSta0) err={_kernel32.GetLastError()}"
        if not _user32.SetProcessWindowStation(hwinsta):
            return False, f"SetProcessWindowStation err={_kernel32.GetLastError()}"
        return True, "WinSta0"
    except Exception as exc:
        return False, str(exc)


def attach_console_desktop(
    *,
    prefer_winlogon: bool = True,
    strict_winlogon: bool = False,
    follow_input: bool = False,
    close_previous: Optional[int] = None,
) -> Tuple[bool, str, Optional[int]]:
    """Bind the calling thread to the console input desktop.

    When ``prefer_winlogon`` is True, try the named ``Winlogon`` desktop first
    (logon / lock UI). OpenInputDesktop alone is insufficient when Default is
    active (C-RD-CON-4).

    ``strict_winlogon=True`` refuses falling through to Default — Logon-ekranı
    start must not claim Winlogon while capturing Default.

    ``follow_input=True`` skips named OpenDesktop and binds whatever the console
    currently presents (Winlogon while locked; Default after logon — C-RD-CON-6).

    Returns ``(ok, desktop_name_or_error, hdesk)``.
    Caller owns ``hdesk`` and should CloseDesktop when replacing.
    """
    if close_previous:
        try:
            _user32.CloseDesktop(close_previous)
        except Exception:
            pass

    ok_ws, ws_detail = switch_to_winsta0()
    if not ok_ws:
        log(f"[RD-WINLOGON] {ws_detail}")

    tried = []

    def _try_input_desktop() -> Tuple[bool, str, Optional[int]]:
        try:
            _kernel32.SetLastError(0)
            hdesk = _user32.OpenInputDesktop(0, False, DESKTOP_GENERIC_ALL)
            if not hdesk:
                tried.append(f"OpenInputDesktop err={_kernel32.GetLastError()}")
                return False, "", None
            resolved = desktop_name(hdesk) or "Input"
            if prefer_winlogon and strict_winlogon and resolved.lower() != "winlogon":
                tried.append(f"OpenInputDesktop={resolved} (rejected: strict Winlogon)")
                try:
                    _user32.CloseDesktop(hdesk)
                except Exception:
                    pass
                return False, "", None
            if _user32.SetThreadDesktop(hdesk):
                log(f"[RD-WINLOGON] attached via OpenInputDesktop name={resolved}")
                return True, resolved, int(hdesk)
            tried.append(f"Input/SetThread err={_kernel32.GetLastError()}")
            try:
                _user32.CloseDesktop(hdesk)
            except Exception:
                pass
            return False, "", None
        except Exception as exc:
            tried.append(f"OpenInputDesktop: {exc}")
            return False, "", None

    if follow_input:
        ok, name, hdesk = _try_input_desktop()
        if ok:
            return True, name, hdesk
        detail = "; ".join(tried)[:240] or "attach_failed"
        log(f"[RD-WINLOGON] follow_input failed: {detail}")
        return False, detail, None

    if prefer_winlogon and strict_winlogon:
        names = ("Winlogon",)
    elif prefer_winlogon:
        names = ("Winlogon", "Default")
    else:
        names = ("Default", "Winlogon")

    OpenDesktopW = _user32.OpenDesktopW
    OpenDesktopW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.BOOL, wintypes.DWORD
    ]
    OpenDesktopW.restype = wintypes.HDESK

    # Named desktops first when targeting Winlogon (do not short-circuit on Default).
    for name in names:
        try:
            _kernel32.SetLastError(0)
            hdesk = OpenDesktopW(name, 0, False, DESKTOP_GENERIC_ALL)
            if not hdesk:
                tried.append(f"OpenDesktop({name}) err={_kernel32.GetLastError()}")
                continue
            if _user32.SetThreadDesktop(hdesk):
                resolved = desktop_name(hdesk) or name
                log(f"[RD-WINLOGON] attached via OpenDesktop name={resolved}")
                return True, resolved, int(hdesk)
            tried.append(f"SetThreadDesktop({name}) err={_kernel32.GetLastError()}")
            try:
                _user32.CloseDesktop(hdesk)
            except Exception:
                pass
        except Exception as exc:
            tried.append(f"OpenDesktop({name}): {exc}")

    # Fallback: current input desktop (may be Winlogon at pre-logon / lock).
    ok, name, hdesk = _try_input_desktop()
    if ok:
        return True, name, hdesk

    detail = "; ".join(tried)[:240] or "attach_failed"
    log(f"[RD-WINLOGON] attach failed: {detail}")
    return False, detail, None


def probe_winlogon_capture(max_width: int = 1280) -> dict:
    """One-shot BitBlt of the console desktop (Winlogon or Default)."""
    ok, name, hdesk = attach_console_desktop(
        prefer_winlogon=True, strict_winlogon=True
    )
    if not ok:
        return {
            "ok": False,
            "error": "NO_WINLOGON_DESKTOP",
            "message": name,
            "desktop": "",
            "session_id": console_session_id(),
            "width": 0,
            "height": 0,
        }
    try:
        from client_remote_desktop import RemoteDesktopStreamer
        from PIL import Image
        import io

        rd = RemoteDesktopStreamer(api_client=None, token_getter=lambda: "")
        rd._desktop_attached = True
        rd._input_desktop = hdesk
        rd._winlogon_mode = True
        img = rd._grab_gdi()
        if img is None:
            return {
                "ok": False,
                "error": "CAPTURE_NO_DESKTOP",
                "message": f"BitBlt empty on desktop={name}",
                "desktop": name,
                "session_id": console_session_id(),
                "width": 0,
                "height": 0,
            }
        w, h = img.size
        if w > max_width and w > 0:
            nh = max(1, int(h * (max_width / float(w))))
            resample = (
                Image.Resampling.BILINEAR
                if hasattr(Image, "Resampling")
                else Image.BILINEAR
            )
            img = img.resize((max_width, nh), resample)
            w, h = img.size
        buf = io.BytesIO()
        img.convert("RGB").save(buf, format="JPEG", quality=40, optimize=False)
        jpeg = buf.getvalue()
        return {
            "ok": True,
            "error": "",
            "message": "winlogon_probe_ok",
            "desktop": name,
            "session_id": console_session_id(),
            "width": int(w),
            "height": int(h),
            "jpeg_bytes": len(jpeg),
            "method": "winlogon",
        }
    except Exception as exc:
        return {
            "ok": False,
            "error": "CAPTURE_NO_DESKTOP",
            "message": str(exc),
            "desktop": name,
            "session_id": console_session_id(),
            "width": 0,
            "height": 0,
        }


def synthesize_console_session(existing: list) -> Optional[dict]:
    """Ensure a captureable console/Winlogon row exists for dashboard.

    - No interactive user: synthesize pre_logon console (query user empty).
    - User already listed on console: still offer a sibling pre_logon row so the
      dashboard can choose "Logon / Lock screen" via prefer=winlogon.
    """
    sid = console_session_id()
    if sid <= 0:
        return None
    has_pre = False
    has_console_user = False
    for item in existing or []:
        try:
            item_sid = int(item.get("session_id") or 0)
        except (TypeError, ValueError):
            continue
        if item_sid != sid:
            continue
        if item.get("pre_logon"):
            has_pre = True
        if str(item.get("username") or "").strip():
            has_console_user = True
    if has_pre:
        return None
    # If console user session already present, still add pre_logon option
    # (same session_id — dashboard distinguishes via pre_logon / empty username).
    state = "Connected"
    try:
        from client_remote_desktop import RemoteDesktopStreamer
        state = RemoteDesktopStreamer._session_connect_state(
            RemoteDesktopStreamer, sid
        ) or "Connected"
    except Exception:
        pass
    return {
        "username": "",
        "session_id": sid,
        "session_name": "Winlogon",
        "status": state if state not in ("unknown", "query_failed") else "Connected",
        "protocol": "Console",
        "desktop": "winlogon",
        "can_capture": True,
        "pre_logon": True,
        "label": "Logon / Lock screen",
        "alongside_user_session": bool(has_console_user),
    }
