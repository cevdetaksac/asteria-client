# -*- coding: utf-8 -*-
"""Console WinSta0 / Winlogon desktop attach for pre-logon remote desktop.

When nobody is logged on, the interactive input desktop is typically
``Winlogon`` on window station ``WinSta0``. A Session-0 (SYSTEM) agent must
switch the process window station before OpenInputDesktop / BitBlt / SendInput
can see that surface.
"""

from __future__ import annotations

import ctypes
import time
from ctypes import wintypes
from typing import Optional, Tuple

from client_helpers import log

WINSTA_ALL_ACCESS = 0x037F
DESKTOP_GENERIC_ALL = 0x10000000
UOI_NAME = 2

_user32 = ctypes.windll.user32
_kernel32 = ctypes.windll.kernel32
_advapi32 = ctypes.windll.advapi32
_wtsapi32 = ctypes.windll.wtsapi32

TOKEN_ALL_ACCESS = 0xF01FF
TOKEN_ASSIGN_PRIMARY = 0x0001
TOKEN_DUPLICATE = 0x0002
TOKEN_QUERY = 0x0008
TOKEN_ADJUST_DEFAULT = 0x0080
TOKEN_ADJUST_SESSIONID = 0x0100
TokenPrimary = 1
SecurityImpersonation = 2
TokenSessionId = 12
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
TH32CS_SNAPPROCESS = 0x00000002


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * 260),
    ]


def console_session_id() -> int:
    try:
        sid = int(_kernel32.WTSGetActiveConsoleSessionId())
        return sid if sid > 0 else 0
    except Exception:
        return 0


def enable_process_privileges(*names: str) -> None:
    """Best-effort enable SeDebugPrivilege / SeAssignPrimaryTokenPrivilege etc."""
    try:
        h_token = wintypes.HANDLE()
        if not _advapi32.OpenProcessToken(
            _kernel32.GetCurrentProcess(),
            0x0020 | 0x0008,  # TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY
            ctypes.byref(h_token),
        ):
            return

        class LUID(ctypes.Structure):
            _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]

        class LUID_AND_ATTRIBUTES(ctypes.Structure):
            _fields_ = [("Luid", LUID), ("Attributes", wintypes.DWORD)]

        class TOKEN_PRIVILEGES(ctypes.Structure):
            _fields_ = [
                ("PrivilegeCount", wintypes.DWORD),
                ("Privileges", LUID_AND_ATTRIBUTES * 1),
            ]

        SE_PRIVILEGE_ENABLED = 0x00000002
        for name in names:
            if not name:
                continue
            luid = LUID()
            if not _advapi32.LookupPrivilegeValueW(None, name, ctypes.byref(luid)):
                continue
            tp = TOKEN_PRIVILEGES()
            tp.PrivilegeCount = 1
            tp.Privileges[0].Luid = luid
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
            _advapi32.AdjustTokenPrivileges(
                h_token, False, ctypes.byref(tp), 0, None, None
            )
        _kernel32.CloseHandle(h_token)
    except Exception:
        pass


def _pids_named(image_base: str) -> list:
    """Return PIDs whose exe basename matches ``image_base`` (case-insensitive)."""
    want = (image_base or "").strip().lower()
    if not want:
        return []
    out = []
    try:
        snap = _kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if not snap or snap == wintypes.HANDLE(-1).value:
            return []
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        if not _kernel32.Process32FirstW(snap, ctypes.byref(entry)):
            _kernel32.CloseHandle(snap)
            return []
        while True:
            name = (entry.szExeFile or "").strip().lower()
            if name == want or name.endswith("\\" + want):
                out.append(int(entry.th32ProcessID))
            if not _kernel32.Process32NextW(snap, ctypes.byref(entry)):
                break
        _kernel32.CloseHandle(snap)
    except Exception:
        return out
    return out


def _session_of_pid(pid: int) -> int:
    try:
        sid = wintypes.DWORD(0)
        if _kernel32.ProcessIdToSessionId(int(pid), ctypes.byref(sid)):
            return int(sid.value)
    except Exception:
        pass
    return -1


def _duplicate_primary_token(pid: int):
    """Open ``pid`` and return a duplicated primary token HANDLE, or None."""
    access = PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION
    h_proc = _kernel32.OpenProcess(access, False, int(pid))
    if not h_proc:
        h_proc = _kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid))
    if not h_proc:
        return None
    try:
        h_tok = wintypes.HANDLE()
        if not _advapi32.OpenProcessToken(
            h_proc, TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY, ctypes.byref(h_tok)
        ):
            return None
        h_dup = wintypes.HANDLE()
        ok = _advapi32.DuplicateTokenEx(
            h_tok,
            TOKEN_ALL_ACCESS
            | TOKEN_ASSIGN_PRIMARY
            | TOKEN_DUPLICATE
            | TOKEN_QUERY
            | TOKEN_ADJUST_DEFAULT
            | TOKEN_ADJUST_SESSIONID,
            None,
            SecurityImpersonation,
            TokenPrimary,
            ctypes.byref(h_dup),
        )
        _kernel32.CloseHandle(h_tok)
        if not ok:
            return None
        return h_dup
    finally:
        try:
            _kernel32.CloseHandle(h_proc)
        except Exception:
            pass


def open_session_interactive_token(session_id: int):
    """C-RD-S0-4 token chain for Session-0 → interactive helper spawn.

    Order:
      1. ``WTSQueryUserToken`` (logged-on / locked user)
      2. ``winlogon.exe`` / ``LogonUI.exe`` primary token in that session
      3. SYSTEM primary + ``TokenSessionId`` (last resort)

    Returns ``(HANDLE|None, source_tag)``. Caller must ``CloseHandle`` the token.
    """
    sid = int(session_id or 0)
    if sid <= 0:
        return None, "refused_session_zero"

    enable_process_privileges(
        "SeDebugPrivilege",
        "SeTcbPrivilege",
        "SeAssignPrimaryTokenPrivilege",
        "SeIncreaseQuotaPrivilege",
    )

    h_token = wintypes.HANDLE()
    if _wtsapi32.WTSQueryUserToken(sid, ctypes.byref(h_token)):
        return h_token, "user"

    user_err = int(_kernel32.GetLastError() or 0)

    for image in ("winlogon.exe", "LogonUI.exe", "logonui.exe"):
        for pid in _pids_named(image):
            if _session_of_pid(pid) != sid:
                continue
            h_dup = _duplicate_primary_token(pid)
            if h_dup:
                log(
                    f"[RD-WINLOGON] session token via {image} pid={pid} "
                    f"session={sid} (WTS user err={user_err})"
                )
                return h_dup, f"process:{image}"

    # SYSTEM + TokenSessionId fallback
    h_proc = wintypes.HANDLE()
    if not _advapi32.OpenProcessToken(
        _kernel32.GetCurrentProcess(), TOKEN_ALL_ACCESS, ctypes.byref(h_proc)
    ):
        log(
            f"[RD-WINLOGON] WTSQueryUserToken({sid}) err={user_err}; "
            f"no winlogon/LogonUI token; OpenProcessToken err={_kernel32.GetLastError()}"
        )
        return None, "no_token"

    h_dup = wintypes.HANDLE()
    ok_dup = _advapi32.DuplicateTokenEx(
        h_proc,
        TOKEN_ALL_ACCESS,
        None,
        SecurityImpersonation,
        TokenPrimary,
        ctypes.byref(h_dup),
    )
    _kernel32.CloseHandle(h_proc)
    if not ok_dup:
        log(
            f"[RD-WINLOGON] WTSQueryUserToken({sid}) err={user_err}; "
            f"DuplicateTokenEx err={_kernel32.GetLastError()}"
        )
        return None, "no_token"

    sess = wintypes.DWORD(sid)
    if not _advapi32.SetTokenInformation(
        h_dup, TokenSessionId, ctypes.byref(sess), ctypes.sizeof(sess)
    ):
        err = int(_kernel32.GetLastError() or 0)
        _kernel32.CloseHandle(h_dup)
        log(
            f"[RD-WINLOGON] WTSQueryUserToken({sid}) err={user_err}; "
            f"SetTokenInformation(TokenSessionId) err={err}"
        )
        return None, "no_token"

    log(
        f"[RD-WINLOGON] session token via SYSTEM+TokenSessionId "
        f"session={sid} (WTS user err={user_err})"
    )
    return h_dup, "system_session"


def software_sas_generation() -> Optional[int]:
    """Read SoftwareSASGeneration policy (C-RD-CAD-3).

    0=None, 1=Services, 2=Ease of Access, 3=Both.
    ``None`` = key missing.
    """
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            0,
            winreg.KEY_READ,
        )
        try:
            val, _ = winreg.QueryValueEx(key, "SoftwareSASGeneration")
            return int(val)
        finally:
            winreg.CloseKey(key)
    except FileNotFoundError:
        return None
    except OSError:
        return None
    except Exception:
        return None


def software_sas_allows_services(policy: Optional[int]) -> bool:
    """True when services may call SendSAS (policy ∈ {1,3}).

    ``None`` (missing key) is treated as disabled for the service path (C-RD-CAD-3).
    """
    try:
        return int(policy) in (1, 3)
    except (TypeError, ValueError):
        return False


def invoke_send_sas(*, as_user: bool = False) -> Tuple[bool, str]:
    """Load sas.dll and call SendSAS. Returns (invoked, detail).

    SendSAS is VOID — a True here only means the export was called without
    raising; it does **not** prove the secure desktop changed (C-RD-CAD-4).
    """
    try:
        sas = ctypes.WinDLL("sas.dll")
    except OSError as exc:
        return False, f"sas.dll not loadable: {exc}"
    try:
        send = sas.SendSAS
        send.argtypes = [wintypes.BOOL]
        send.restype = None
    except AttributeError:
        return False, "sas.dll has no SendSAS export"
    try:
        send(1 if as_user else 0)
        return True, f"SendSAS({'TRUE' if as_user else 'FALSE'}) invoked"
    except Exception as exc:
        return False, f"SendSAS raised: {exc}"


_SAS_UI_HINTS = (
    "windows security",
    "windows güvenliği",
    "security options",
    "güvenlik seçenekleri",
    "sign in",
    "oturum aç",
    "task manager",
    "görev yöneticisi",
    "switch user",
    "kullanıcı değiştir",
    "credential",
)
_CAD_TIP_HINTS = (
    "ctrl+alt+delete",
    "ctrl + alt + delete",
    "ctrl+alt+del",
    "kilidi açmak için",
    "press ctrl",
    "ctrl+alt+delete tuşlarına",
)


def _enum_visible_window_titles() -> list:
    titles = []

    @ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    def _cb(hwnd, _lp):
        try:
            if not _user32.IsWindowVisible(hwnd):
                return True
            length = int(_user32.GetWindowTextLengthW(hwnd) or 0)
            if length <= 0:
                return True
            buf = ctypes.create_unicode_buffer(length + 1)
            _user32.GetWindowTextW(hwnd, buf, length + 1)
            title = (buf.value or "").strip()
            if title:
                titles.append(title)
        except Exception:
            pass
        return True

    try:
        _user32.EnumWindows(_cb, 0)
    except Exception:
        pass
    return titles


def secure_attention_ui_state() -> str:
    """Heuristic UI state on the current thread desktop.

    Returns ``sas_ui`` | ``cad_tip`` | ``unknown``.
    """
    titles = _enum_visible_window_titles()
    joined = " | ".join(t.lower() for t in titles)
    for hint in _SAS_UI_HINTS:
        if hint in joined:
            return "sas_ui"
    for hint in _CAD_TIP_HINTS:
        if hint in joined:
            return "cad_tip"
    return "unknown"


def desktop_surface_fingerprint(max_side: int = 64) -> str:
    """Tiny desktop hash for SAS post-condition (best-effort)."""
    try:
        import hashlib
        from PIL import Image

        hdc = _user32.GetDC(0)
        if not hdc:
            return ""
        try:
            gdi32 = ctypes.windll.gdi32
            width = int(_user32.GetSystemMetrics(0) or 0)
            height = int(_user32.GetSystemMetrics(1) or 0)
            if width <= 0 or height <= 0:
                return ""
            scale = max(1, max(width, height) // max(8, int(max_side)))
            tw, th = max(8, width // scale), max(8, height // scale)
            memdc = gdi32.CreateCompatibleDC(hdc)
            bmp = gdi32.CreateCompatibleBitmap(hdc, tw, th)
            old = gdi32.SelectObject(memdc, bmp)
            # SRCCOPY|CAPTUREBLT
            gdi32.StretchBlt(memdc, 0, 0, tw, th, hdc, 0, 0, width, height, 0x40CC0020)

            class BITMAPINFOHEADER(ctypes.Structure):
                _fields_ = [
                    ("biSize", wintypes.DWORD),
                    ("biWidth", wintypes.LONG),
                    ("biHeight", wintypes.LONG),
                    ("biPlanes", wintypes.WORD),
                    ("biBitCount", wintypes.WORD),
                    ("biCompression", wintypes.DWORD),
                    ("biSizeImage", wintypes.DWORD),
                    ("biXPelsPerMeter", wintypes.LONG),
                    ("biYPelsPerMeter", wintypes.LONG),
                    ("biClrUsed", wintypes.DWORD),
                    ("biClrImportant", wintypes.DWORD),
                ]

            bi = BITMAPINFOHEADER()
            bi.biSize = ctypes.sizeof(BITMAPINFOHEADER)
            bi.biWidth = tw
            bi.biHeight = -th
            bi.biPlanes = 1
            bi.biBitCount = 32
            buf = (ctypes.c_char * (tw * th * 4))()
            gdi32.GetDIBits(memdc, bmp, 0, th, buf, ctypes.byref(bi), 0)
            gdi32.SelectObject(memdc, old)
            gdi32.DeleteObject(bmp)
            gdi32.DeleteDC(memdc)
            img = Image.frombuffer("RGB", (tw, th), bytes(buf), "raw", "BGRX", 0, 1)
            return hashlib.md5(img.tobytes()).hexdigest()
        finally:
            _user32.ReleaseDC(0, hdc)
    except Exception:
        return ""


def watch_sas_effect(*, timeout_sec: float = 2.0, before_fp: str = "") -> Tuple[bool, str]:
    """Poll ≤timeout for SAS UI or desktop surface change (C-RD-CAD-4)."""
    deadline = time.time() + max(0.4, float(timeout_sec))
    last_state = secure_attention_ui_state()
    while time.time() < deadline:
        state = secure_attention_ui_state()
        if state == "sas_ui":
            return True, f"secure_attention_ui={state}"
        if before_fp:
            now_fp = desktop_surface_fingerprint()
            if now_fp and now_fp != before_fp:
                # Tip → options usually changes composition a lot
                if state != "cad_tip":
                    return True, f"desktop_changed state={state}"
        last_state = state
        time.sleep(0.2)
    return False, f"no_sas_effect state={last_state}"


def send_sas_with_console_affinity(
    session_id: int,
    *,
    as_user: bool = False,
    prefer_winlogon: bool = True,
) -> Tuple[bool, str, dict]:
    """Impersonate console session token, attach desktop, call SendSAS.

    Returns ``(api_invoked, detail, meta)``. Does **not** assert UI effect.
    """
    import time as _time  # noqa: F401 — used by watch_sas_effect import side

    meta = {
        "session_id": int(session_id or 0),
        "as_user": bool(as_user),
        "token_source": "",
        "impersonated": False,
        "desktop": "",
    }
    sid = int(session_id or 0)
    if sid <= 0:
        return False, "no_console_session", meta

    enable_process_privileges(
        "SeDebugPrivilege",
        "SeTcbPrivilege",
        "SeAssignPrimaryTokenPrivilege",
        "SeIncreaseQuotaPrivilege",
        "SeImpersonatePrivilege",
    )
    h_token, src = open_session_interactive_token(sid)
    meta["token_source"] = src
    if not h_token:
        return False, f"no_interactive_token ({src})", meta

    impersonated = False
    try:
        if not _advapi32.ImpersonateLoggedOnUser(h_token):
            err = int(_kernel32.GetLastError() or 0)
            return False, f"ImpersonateLoggedOnUser failed err={err}", meta
        impersonated = True
        meta["impersonated"] = True
        ok_desk, desk, hdesk = attach_console_desktop(
            prefer_winlogon=prefer_winlogon,
            strict_winlogon=bool(prefer_winlogon),
        )
        meta["desktop"] = desk if ok_desk else ""
        if not ok_desk and prefer_winlogon:
            # Still attempt SendSAS after impersonation — some hosts keep Default.
            attach_console_desktop(prefer_winlogon=False)
        invoked, detail = invoke_send_sas(as_user=as_user)
        if hdesk:
            try:
                _user32.CloseDesktop(hdesk)
            except Exception:
                pass
        return invoked, detail, meta
    finally:
        if impersonated:
            try:
                _advapi32.RevertToSelf()
            except Exception:
                pass
        try:
            _kernel32.CloseHandle(h_token)
        except Exception:
            pass


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
    """One-shot BitBlt of the console desktop (Winlogon or Default).

    Session-0 agents that OpenWindowStation(WinSta0) see *Session 0's* Winlogon
    (often solid black). Attach success with deferred capture still means stream
    start can launch a helper into the console session on ``winsta0\\Winlogon``.
    """
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
        pid_sid = 0
        try:
            import ctypes
            sid = ctypes.c_ulong()
            if ctypes.windll.kernel32.ProcessIdToSessionId(
                ctypes.windll.kernel32.GetCurrentProcessId(), ctypes.byref(sid)
            ):
                pid_sid = int(sid.value)
        except Exception:
            pid_sid = 0

        if img is None:
            if pid_sid == 0:
                # Attach named Winlogon OK; pixels require in-session helper at stream.
                return {
                    "ok": True,
                    "error": "",
                    "message": "winlogon_attach_ok_capture_deferred",
                    "desktop": name,
                    "session_id": console_session_id(),
                    "width": 0,
                    "height": 0,
                    "jpeg_bytes": 0,
                    "method": "winlogon_deferred",
                    "deferred_capture": True,
                }
            return {
                "ok": False,
                "error": "CAPTURE_NO_DESKTOP",
                "message": f"BitBlt empty on desktop={name}",
                "desktop": name,
                "session_id": console_session_id(),
                "width": 0,
                "height": 0,
            }
        black = False
        try:
            black = bool(rd._is_mostly_black(img))
        except Exception:
            black = False
        if black and pid_sid == 0:
            return {
                "ok": True,
                "error": "",
                "message": "winlogon_attach_ok_capture_deferred",
                "desktop": name,
                "session_id": console_session_id(),
                "width": int(img.size[0]),
                "height": int(img.size[1]),
                "jpeg_bytes": 0,
                "method": "winlogon_deferred",
                "deferred_capture": True,
                "black_frame": True,
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
            "black_frame": bool(black),
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
