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


WTS_USERNAME = 5
WTS_SESSIONINFO_EX = 25
WTS_SESSIONSTATE_LOCK = 0x00000000
WTS_SESSIONSTATE_UNLOCK = 0x00000001
WTS_SESSIONSTATE_UNKNOWN = 0xFFFFFFFF


def session_username(session_id: int) -> str:
    """WTSQuerySessionInformationW UserName for one SID (empty if none)."""
    try:
        sid = int(session_id or 0)
    except (TypeError, ValueError):
        return ""
    if sid <= 0:
        return ""
    buf = ctypes.c_void_p()
    length = wintypes.DWORD()
    try:
        if not _wtsapi32.WTSQuerySessionInformationW(
            0, sid, WTS_USERNAME, ctypes.byref(buf), ctypes.byref(length)
        ):
            return ""
        try:
            if not buf.value:
                return ""
            name = ctypes.wstring_at(buf) or ""
            return str(name).strip()
        finally:
            _wtsapi32.WTSFreeMemory(buf)
    except Exception:
        return ""


def decide_console_follow(
    *,
    follow_console: bool,
    winlogon_mode: bool,
    spawn_session_id: int,
    console_sid: int,
    console_username: str = "",
    helper_desktop: str = "",
    logonui_hwnd: int = 0,
    chrome_detected: bool = False,
    session_locked: Optional[bool] = None,
    explorer_present: Optional[bool] = None,
    logonui_present: Optional[bool] = None,
) -> Optional[str]:
    """C-RD-FOLLOW: reason to leave Winlogon on the same stream, else None.

    ``follow_console`` is True when start omitted ``session_id`` (physical
    console). Shortcut starts (explicit SID) still follow Winlogon→Default
    on that SID but do not jump to a different console SID.

    Unlock after credentials: LogonUI gone + not locked (+ optional explorer)
    must leave Winlogon even while helper_desktop is still named Winlogon —
    otherwise the stream freezes on "Windows is getting ready" (FOLLOW-4).
    """
    if not winlogon_mode and str(helper_desktop or "").strip().lower() != "winlogon":
        return None
    try:
        spawn_sid = int(spawn_session_id or 0)
        csid = int(console_sid or 0)
    except (TypeError, ValueError):
        return None
    desk = str(helper_desktop or "").strip().lower()
    user = str(console_username or "").strip()
    if csid > 0 and spawn_sid > 0 and csid != spawn_sid and follow_console:
        return "console_sid_changed"
    if desk == "default":
        return "desktop_default"
    # Explicit unlock signals beat a stale Winlogon desktop label.
    hwnd_gone = int(logonui_hwnd or 0) <= 0
    if logonui_present is False:
        hwnd_gone = True
    if logonui_present is True:
        hwnd_gone = False
    unlocked = session_locked is False
    if user and unlocked and hwnd_gone and desk != "winlogon":
        return "unlocked_shell"
    if user and unlocked and hwnd_gone and explorer_present is True:
        return "unlocked_explorer"
    if user and unlocked and hwnd_gone and explorer_present is not False:
        # Shell starting after password ("Windows is getting ready") — leave
        # Winlogon helper before frames freeze on the welcome surface.
        return "post_logon"
    # WTS unlocked + username: LogonUI.exe can linger on Welcome / "getting
    # ready". Staying on Winlogon freezes the last logon JPEG (FOLLOW-4).
    if user and unlocked:
        return "post_logon_welcome"
    # Stay on Winlogon while lock/LogonUI is still the interactive surface.
    return None


def decide_console_secure(
    *,
    follow_console: bool,
    winlogon_mode: bool,
    helper_desktop: str = "",
    logonui_present: bool = False,
    console_username: str = "",
    black_frame: bool = False,
) -> Optional[str]:
    """Physical console locked / logged-off → Winlogon helper (same stream)."""
    if not follow_console or winlogon_mode:
        return None
    desk = str(helper_desktop or "").strip().lower()
    if desk == "winlogon":
        return "input_desktop_winlogon"
    if logonui_present:
        return "logonui"
    if not str(console_username or "").strip():
        return "no_user"
    if black_frame and desk != "default":
        return "black_secure"
    return None


def console_capture_env(session_id: int = 0) -> dict:
    """Host fingerprint for Capture health compare (PASS host vs Derin FAIL).

    Explains *why* resolve picked Winlogon vs Default — not just the outcome.
    """
    try:
        sid = int(session_id or 0)
    except (TypeError, ValueError):
        sid = 0
    if sid <= 0:
        try:
            sid = int(console_session_id() or 0)
        except Exception:
            sid = 0
    user = ""
    logonui = False
    locked = None
    explorer = None
    try:
        if sid > 0:
            user = session_username(sid) or ""
            logonui = bool(session_has_logonui(sid))
            locked = session_lock_state(sid)
            explorer = session_has_process(sid, "explorer.exe")
    except Exception:
        pass
    screen_cx = screen_cy = 0
    monitor_count = 0
    try:
        import ctypes
        user32 = ctypes.windll.user32
        screen_cx = int(user32.GetSystemMetrics(0) or 0)  # SM_CXSCREEN
        screen_cy = int(user32.GetSystemMetrics(1) or 0)
        # SM_CMONITORS
        monitor_count = int(user32.GetSystemMetrics(80) or 0)
    except Exception:
        pass
    winlogon_pids = 0
    logonui_pids = 0
    try:
        if sid > 0:
            for pid in _pids_named("winlogon.exe"):
                if _session_of_pid(pid) == sid:
                    winlogon_pids += 1
            for image in ("LogonUI.exe", "logonui.exe", "LockApp.exe"):
                for pid in _pids_named(image):
                    if _session_of_pid(pid) == sid:
                        logonui_pids += 1
    except Exception:
        pass
    resolve = "winlogon"
    try:
        resolve = resolve_console_capture_mode(sid)
    except Exception:
        resolve = "error"
    out = {
        "console_sid": int(sid or 0),
        "username": str(user or ""),
        "logonui": bool(logonui),
        "logonui_pids": int(logonui_pids),
        "winlogon_pids": int(winlogon_pids),
        "locked": locked,
        "explorer": explorer,
        "resolve_mode": str(resolve),
        "screen_cx": int(screen_cx),
        "screen_cy": int(screen_cy),
        "monitor_count": int(monitor_count),
        "headless_hint": bool(
            monitor_count <= 0
            or screen_cx <= 0
            or screen_cy <= 0
        ),
    }
    out["decision"] = console_capture_env_decision_note(out)
    return out


def session_has_logonui(session_id: int) -> bool:
    """True when LogonUI / LockApp is running in the console session.

    If ProcessIdToSessionId fails (access), still treat a lock process as
    present when it is the active console — otherwise follow+lock falls through
    to Default GDI black (C-RD-PIX-3).
    """
    try:
        sid = int(session_id or 0)
    except (TypeError, ValueError):
        return False
    if sid <= 0:
        return False
    unmatched = False
    for image in ("LogonUI.exe", "logonui.exe", "LockApp.exe", "LockAppHost.exe"):
        for pid in _pids_named(image):
            try:
                psid = _session_of_pid(pid)
            except Exception:
                psid = -1
            if psid == sid:
                return True
            if psid < 0:
                unmatched = True
    if unmatched:
        try:
            return int(console_session_id() or 0) == sid
        except Exception:
            return True
    return False


def resolve_start_topology(
    *,
    topology: str = "",
    prefer: str = "",
    desktop: str = "",
    pre_logon: Optional[bool] = None,
    session_id_omitted: bool = True,
) -> Tuple[str, bool]:
    """Named Start topology (contract 1.4.59).

    Returns ``(mode, force_secure)``:
    - ``winlogon`` + force: lock/logon row — never skip Winlogon helper
    - ``follow``: omit-sid / topology=follow — Winlogon only if secure desktop
    - ``session``: user shortcut with explicit SID
    """
    t = str(topology or "").strip().lower()
    p = str(prefer or "").strip().lower()
    d = str(desktop or "").strip().lower()
    if t in ("winlogon", "lock", "logon", "secure") or p in ("lock", "secure"):
        return "winlogon", True
    if t in ("follow", "default") or p in ("follow", "default"):
        return "follow", False
    if session_id_omitted:
        return "follow", False
    if (
        p in ("winlogon", "console", "pre_logon", "pre-logon")
        or d == "winlogon"
        or pre_logon is True
        or t in ("winlogon",)
    ):
        return "winlogon", True
    return "session", False


def interpret_session_lock_flags(flags) -> Optional[bool]:
    """WTSINFOEX SessionFlags → locked True / unlocked False / unknown None."""
    try:
        value = int(flags) & 0xFFFFFFFF
    except (TypeError, ValueError):
        return None
    if value == WTS_SESSIONSTATE_UNKNOWN:
        return None
    if value == WTS_SESSIONSTATE_UNLOCK:
        return False
    if value == WTS_SESSIONSTATE_LOCK:
        return True
    return (value & 1) == 0


def session_has_process(session_id: int, image_base: str) -> bool:
    try:
        sid = int(session_id or 0)
    except (TypeError, ValueError):
        return False
    if sid <= 0:
        return False
    for pid in _pids_named(image_base):
        if _session_of_pid(pid) == sid:
            return True
    return False


def session_lock_state(session_id: int) -> Optional[bool]:
    """True when WTS says the session is locked; None if unreadable."""
    try:
        sid = int(session_id or 0)
    except (TypeError, ValueError):
        return None
    if sid <= 0:
        return None
    buf = ctypes.c_void_p()
    length = wintypes.DWORD()
    try:
        if not _wtsapi32.WTSQuerySessionInformationW(
            0, sid, WTS_SESSIONINFO_EX, ctypes.byref(buf), ctypes.byref(length)
        ):
            return None
        try:
            nbytes = int(length.value or 0)
            if not buf.value or nbytes < 16:
                return None
            raw = ctypes.string_at(buf.value, nbytes)
            level = int.from_bytes(raw[0:4], "little")
            if level != 1:
                return None
            sid_at_4 = int.from_bytes(raw[4:8], "little")
            sid_at_8 = int.from_bytes(raw[8:12], "little")
            if sid_at_4 == sid:
                flags = int.from_bytes(raw[12:16], "little", signed=True)
            elif sid_at_8 == sid and nbytes >= 20:
                flags = int.from_bytes(raw[16:20], "little", signed=True)
            else:
                flags = int.from_bytes(raw[12:16], "little", signed=True)
            return interpret_session_lock_flags(flags)
        finally:
            _wtsapi32.WTSFreeMemory(buf)
    except Exception:
        return None


def console_start_secure_desktop(
    *,
    username: str = "",
    logonui_present: bool = False,
    session_locked: Optional[bool] = None,
    explorer_present: Optional[bool] = None,
    input_desktop: str = "",
    prefer_default_on_unknown: bool = False,
) -> bool:
    """Winlogon helper when the *input* desktop is secure — not when WTS lists a user.

    Listed username + live Default is PIX-4. Listed username + Win+L is PIX-3.
    Unknown lock with a username used to skip Winlogon and paint user-helper
    ``gdi+black`` (Derin-Web follow). Prefer Winlogon unless Default is proven live.

    ``prefer_default_on_unknown=True``: password / explicit SID+user Start — if
    LogonUI is absent and lock is not True, stay on Default (restore direct
    user login). Follow / omit-SID keeps ``False`` (safe Winlogon bias).
    """
    desk = str(input_desktop or "").strip().lower()
    if desk == "winlogon":
        return True
    if logonui_present or session_locked is True:
        return True
    if not str(username or "").strip():
        return True
    # Post-password Welcome / shell start: unlocked + no LogonUI → Default even
    # before explorer.exe exists. Waiting for explorer kept capture on a dead
    # Winlogon helper (frozen "Windows is getting ready", FOLLOW-4).
    if (
        session_locked is False
        and not logonui_present
        and desk != "winlogon"
    ):
        return False
    if prefer_default_on_unknown and not logonui_present and session_locked is not True:
        # Explicit user session Start after prepare — do not force Winlogon on
        # unreadable lock flags (password login regression in 4.9.10x).
        if desk != "winlogon":
            return False
    if explorer_present is False and session_locked is not False:
        return True
    # Unknown lock (None) must NOT unlock Default — Derin user-helper black.
    if desk == "default" and session_locked is False and not logonui_present:
        return False
    if (
        explorer_present is True
        and session_locked is False
        and not logonui_present
        and desk != "winlogon"
    ):
        return False
    return True


def resolve_console_capture_mode(
    session_id: int,
    *,
    input_desktop: str = "",
) -> str:
    """Chrome Remote Desktop model: which desktop is live on the console now?

    Returns ``\"winlogon\"`` (lock / logoff / empty) or ``\"default\"`` (unlocked
    shell). Decision uses LogonUI + WTS lock + explorer — **not** a listed
    username alone. Optional ``input_desktop`` is the live OpenInputDesktop name.
    """
    try:
        sid = int(session_id or 0)
    except (TypeError, ValueError):
        sid = 0
    if sid <= 0:
        return "winlogon"
    user = ""
    logonui = False
    locked = None
    explorer = None
    try:
        user = session_username(sid)
        logonui = bool(session_has_logonui(sid))
        locked = session_lock_state(sid)
        explorer = session_has_process(sid, "explorer.exe")
    except Exception:
        return "winlogon"
    desk = str(input_desktop or "").strip()
    if console_start_secure_desktop(
        username=user,
        logonui_present=logonui,
        session_locked=locked,
        explorer_present=explorer,
        input_desktop=desk,
    ):
        return "winlogon"
    return "default"


def console_capture_env_decision_note(env: dict) -> str:
    """One-line why Winlogon vs Default was chosen (for logs / Capture health)."""
    if not isinstance(env, dict):
        return ""
    mode = str(env.get("resolve_mode") or "")
    if mode == "winlogon":
        if env.get("logonui"):
            return "winlogon_because_logonui"
        if env.get("locked") is True:
            return "winlogon_because_locked"
        if not str(env.get("username") or "").strip():
            return "winlogon_because_no_user"
        if env.get("explorer") is False:
            return "winlogon_because_no_explorer"
        return "winlogon_secure_default"
    if env.get("headless_hint"):
        return "default_but_headless_hint"
    return "default_unlocked_shell"


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


def open_session_interactive_token(
    session_id: int, *, for_secure_desktop: bool = False
):
    """C-RD-S0-4 token chain for Session-0 → interactive helper spawn.

    Default (Default desktop DXGI): user token first.
    Winlogon/lock: ``winlogon.exe`` / LogonUI token first — a logged-on user
    token cannot BitBlt ``winsta0\\Winlogon`` (lab gdi+black).

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

    def _from_secure_processes():
        for image in ("winlogon.exe", "LogonUI.exe", "logonui.exe", "LockApp.exe"):
            for pid in _pids_named(image):
                if _session_of_pid(pid) != sid:
                    continue
                h_dup = _duplicate_primary_token(pid)
                if h_dup:
                    log(
                        f"[RD-WINLOGON] session token via {image} pid={pid} "
                        f"session={sid} secure={for_secure_desktop}"
                    )
                    return h_dup, f"process:{image}"
        return None, ""

    if for_secure_desktop:
        h_sec, tag = _from_secure_processes()
        if h_sec:
            return h_sec, tag
    else:
        h_token = wintypes.HANDLE()
        if _wtsapi32.WTSQueryUserToken(sid, ctypes.byref(h_token)):
            return h_token, "user"
        user_err = int(_kernel32.GetLastError() or 0)
        h_sec, tag = _from_secure_processes()
        if h_sec:
            log(
                f"[RD-WINLOGON] session token via {tag} "
                f"session={sid} (WTS user err={user_err})"
            )
            return h_sec, tag

    h_token = wintypes.HANDLE()
    if not for_secure_desktop:
        user_err = int(_kernel32.GetLastError() or 0)
    else:
        user_err = 0
        if _wtsapi32.WTSQueryUserToken(sid, ctypes.byref(h_token)):
            return h_token, "user_last"

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
    ``None`` = key missing / unreadable.
    """
    try:
        import winreg
        access = winreg.KEY_READ
        if hasattr(winreg, "KEY_WOW64_64KEY"):
            access |= winreg.KEY_WOW64_64KEY
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            0,
            access,
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


def set_software_sas_generation(value: int) -> Tuple[bool, str]:
    """Write SoftwareSASGeneration DWORD (requires SYSTEM / admin)."""
    try:
        import winreg
        access = winreg.KEY_SET_VALUE | winreg.KEY_READ
        if hasattr(winreg, "KEY_WOW64_64KEY"):
            access |= winreg.KEY_WOW64_64KEY
        key = winreg.CreateKeyEx(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            0,
            access,
        )
        try:
            winreg.SetValueEx(
                key, "SoftwareSASGeneration", 0, winreg.REG_DWORD, int(value)
            )
        finally:
            winreg.CloseKey(key)
        return True, f"SoftwareSASGeneration={int(value)}"
    except Exception as exc:
        return False, f"set_software_sas_generation failed: {exc}"


def ensure_software_sas_generation(
    *, enable_services: bool = True
) -> Tuple[int, str]:
    """Return concrete policy int 0..3 and a note (C-RD-CAD-3 residual 1.4.53).

    Never returns ``None`` in the result slot used for JSON — missing reads as
    ``0``. When ``enable_services`` and policy ∉ {1,3}, SYSTEM writes ``1``
    (Services) so Session-0 ``SendSAS(FALSE)`` can route to the console.
    """
    current = software_sas_generation()
    if current in (1, 3):
        return int(current), "policy_ok"
    if not enable_services:
        return int(current) if current is not None else 0, "disabled"
    # Auto-enable Services so CAD can actually raise the secure UI.
    target = 1 if current in (None, 0, 2) else int(current)
    if current == 2:
        target = 3  # Ease of Access → Both
    ok, note = set_software_sas_generation(target)
    after = software_sas_generation()
    if ok and after in (1, 3):
        log(f"[RD-WINLOGON] SoftwareSASGeneration {current!r} → {after} ({note})")
        return int(after), f"enabled:{note}"
    final = int(after) if after is not None else (int(current) if current is not None else 0)
    return final, f"enable_failed:{note}"


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

    When policy allows Services and this runs in the **Session-0 service**,
    ``SendSAS(FALSE)`` is routed by Windows to the **active console session**.
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
    "other user",
    "başka kullanıcı",
    "password",
    "parola",
    "şifre",
)
_CAD_TIP_HINTS = (
    "ctrl+alt+delete",
    "ctrl + alt + delete",
    "ctrl+alt+del",
    "ctrl + alt + del",
    "kilidi açmak için",
    "press ctrl",
    "ctrl+alt+delete tuşlarına",
    "press ctrl+alt+delete",
)


_SAS_CLASS_HINTS = (
    "authui",
    "credential",
    "logonui",
    "securityoptions",
    "lockappframedynamic",
)
_CAD_TIP_CLASS_HINTS = (
    # Rare; tip text usually comes from window titles / static labels.
)


def _enum_hwnd_meta() -> Tuple[list, list]:
    """Return (titles, class_names) for visible top-level windows on this desktop."""
    titles: list = []
    classes: list = []

    @ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    def _cb(hwnd, _lp):
        try:
            if not _user32.IsWindowVisible(hwnd):
                return True
            cbuf = ctypes.create_unicode_buffer(256)
            if _user32.GetClassNameW(hwnd, cbuf, 256):
                cname = (cbuf.value or "").strip()
                if cname:
                    classes.append(cname)
            length = int(_user32.GetWindowTextLengthW(hwnd) or 0)
            if length > 0:
                tbuf = ctypes.create_unicode_buffer(length + 1)
                _user32.GetWindowTextW(hwnd, tbuf, length + 1)
                title = (tbuf.value or "").strip()
                if title:
                    titles.append(title)
        except Exception:
            pass
        return True

    try:
        # Prefer current-thread desktop (Winlogon after attach) over global EnumWindows.
        EnumDesktopWindows = getattr(_user32, "EnumDesktopWindows", None)
        hdesk = _user32.GetThreadDesktop(_kernel32.GetCurrentThreadId())
        if EnumDesktopWindows and hdesk:
            EnumDesktopWindows(hdesk, _cb, 0)
        else:
            _user32.EnumWindows(_cb, 0)
    except Exception:
        try:
            _user32.EnumWindows(_cb, 0)
        except Exception:
            pass
    return titles, classes


def _enum_visible_window_titles() -> list:
    titles, _classes = _enum_hwnd_meta()
    return titles


def visible_surface_signature() -> Tuple[str, frozenset, int]:
    """(ui_state, title+class tokens, visible_hwnd_count) for effect compare."""
    titles, classes = _enum_hwnd_meta()
    tokens = frozenset(t.lower() for t in titles) | frozenset(c.lower() for c in classes)
    return secure_attention_ui_state_from(titles, classes), tokens, len(classes)


def secure_attention_ui_state_from(titles: list, classes: list) -> str:
    """Classify lock/CAD chrome from titles + class names.

    Returns ``sas_ui`` | ``cad_tip`` | ``other`` | ``unknown``.
    ``unknown`` only when the desktop yields no enumerable chrome at all
    (Session-0 empty view). Prefer ``other`` over ``unknown`` when windows exist.

    C-RD-CHROME-3: class-alone (LogonUI/AuthUI) is NOT enough for ``sas_ui``.
    Tip text wins over SAS title hints when both appear (lock tip still up).
    """
    if not titles and not classes:
        return "unknown"
    joined = " | ".join(t.lower() for t in titles)
    class_joined = " | ".join(c.lower() for c in classes)
    # Tip first — Derin-Web lab: ui_before=sas_ui while tip still visible.
    for hint in _CAD_TIP_HINTS:
        if hint in joined:
            return "cad_tip"
    for hint in _CAD_TIP_CLASS_HINTS:
        if hint in class_joined:
            return "cad_tip"
    for hint in _SAS_UI_HINTS:
        if hint in joined:
            return "sas_ui"
    for hint in _SAS_CLASS_HINTS:
        if hint in class_joined:
            return "other"
    return "other"


def secure_attention_ui_state() -> str:
    """Heuristic UI state on the current thread desktop."""
    titles, classes = _enum_hwnd_meta()
    return secure_attention_ui_state_from(titles, classes)


def desktop_surface_luma_stats(max_side: int = 64) -> dict:
    """Luma mean/variance/bright_ratio of current desktop (C-RD-CHROME-2/5)."""
    try:
        from PIL import Image

        hdc = _user32.GetDC(0)
        if not hdc:
            return {"mean": 0.0, "variance": 0.0, "bright_ratio": 0.0, "flat": True}
        try:
            gdi32 = ctypes.windll.gdi32
            width = int(_user32.GetSystemMetrics(0) or 0)
            height = int(_user32.GetSystemMetrics(1) or 0)
            if width <= 0 or height <= 0:
                return {"mean": 0.0, "variance": 0.0, "bright_ratio": 0.0, "flat": True}
            scale = max(1, max(width, height) // max(8, int(max_side)))
            tw, th = max(8, width // scale), max(8, height // scale)
            memdc = gdi32.CreateCompatibleDC(hdc)
            bmp = gdi32.CreateCompatibleBitmap(hdc, tw, th)
            old = gdi32.SelectObject(memdc, bmp)
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
            small = img.convert("L")
            data = list(small.getdata())
            n = max(1, len(data))
            mean = float(sum(data)) / n
            var = float(sum((x - mean) ** 2 for x in data)) / n
            bright = float(sum(1 for x in data if x >= 200)) / n
            flat = bool(var < 12.0 and bright < 0.005 and mean >= 6.0)
            return {
                "mean": mean,
                "variance": var,
                "bright_ratio": bright,
                "flat": flat,
            }
        finally:
            _user32.ReleaseDC(0, hdc)
    except Exception:
        return {"mean": 0.0, "variance": 0.0, "bright_ratio": 0.0, "flat": True}


def desktop_surface_is_flat() -> bool:
    """True when BitBlt of the current desktop is a solid fill (no glyphs)."""
    try:
        return bool(desktop_surface_luma_stats().get("flat"))
    except Exception:
        return True


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


def classify_sas_transition(
    before_state: str,
    after_state: str,
    *,
    before_tokens: Optional[frozenset] = None,
    after_tokens: Optional[frozenset] = None,
    before_fp: str = "",
    after_fp: str = "",
    after_flat: Optional[bool] = None,
) -> Tuple[bool, str]:
    """Decide if a Secure Attention UI transition occurred (C-RD-CAD-1/4).

    C-RD-CHROME-3: flat pixel fill must not count as ``sas_ui`` success.
    """
    if after_flat is None:
        try:
            after_flat = desktop_surface_is_flat()
        except Exception:
            after_flat = False
    if after_flat:
        if after_state == "sas_ui":
            after_state = "other"
        return False, f"no_sas_effect flat_frame state={after_state}"
    if after_state == "sas_ui":
        return True, f"secure_attention_ui={after_state}"
    if before_state == "cad_tip" and after_state in ("sas_ui", "other"):
        return True, f"left_cad_tip {before_state}->{after_state}"
    if (
        before_state
        and after_state
        and before_state != after_state
        and after_state not in ("unknown",)
        and before_state == "cad_tip"
    ):
        return True, f"ui_state {before_state}->{after_state}"
    if before_tokens is not None and after_tokens is not None:
        if before_tokens and after_tokens and before_tokens != after_tokens:
            if after_state != "cad_tip" or before_state == "cad_tip":
                if not (before_state == "cad_tip" and after_state == "cad_tip"):
                    return True, "window_chrome_changed"
    if before_fp and after_fp and before_fp != after_fp:
        if after_state == "sas_ui":
            return True, f"desktop_changed state={after_state}"
        if before_state == "cad_tip" and after_state != "cad_tip":
            return True, f"desktop_changed state={after_state}"
    return False, f"no_sas_effect state={after_state or before_state or 'unknown'}"


def watch_sas_effect(
    *,
    timeout_sec: float = 2.0,
    before_fp: str = "",
    before_state: str = "",
    before_tokens: Optional[frozenset] = None,
) -> Tuple[bool, str, str]:
    """Poll ≤timeout for SAS UI or desktop surface change (C-RD-CAD-4).

    Returns ``(effect, detail, last_ui_state)``.
    """
    if not before_state:
        before_state, before_tokens, _n = visible_surface_signature()
        if not before_fp:
            before_fp = desktop_surface_fingerprint()
    deadline = time.time() + max(0.4, float(timeout_sec))
    last_state = before_state or secure_attention_ui_state()
    last_tokens = before_tokens or frozenset()
    while time.time() < deadline:
        state, tokens, _n = visible_surface_signature()
        now_fp = desktop_surface_fingerprint() if before_fp else ""
        flat = desktop_surface_is_flat()
        if flat and state == "sas_ui":
            state = "other"
        ok, detail = classify_sas_transition(
            before_state,
            state,
            before_tokens=before_tokens if before_tokens is not None else last_tokens,
            after_tokens=tokens,
            before_fp=before_fp,
            after_fp=now_fp,
            after_flat=flat,
        )
        last_state = state
        last_tokens = tokens
        if ok:
            return True, detail, state
        time.sleep(0.15)
    return False, f"no_sas_effect state={last_state}", last_state


def run_send_sas_on_attached_desktop(
    *,
    prefer_winlogon: bool = True,
    timeout_sec: float = 2.0,
    try_as_user: bool = True,
) -> dict:
    """Attach desktop, snapshot UI, call SendSAS, poll effect (helper / affinity).

    Prefer ``SendSAS(FALSE)`` first; optionally retry ``SendSAS(TRUE)`` when the
    caller already holds an interactive token (impersonation / in-session helper).
    """
    before_state, before_tokens, before_n = visible_surface_signature()
    before_fp = desktop_surface_fingerprint()
    ok_desk, desk, hdesk = attach_console_desktop(
        prefer_winlogon=prefer_winlogon,
        strict_winlogon=bool(prefer_winlogon),
    )
    if ok_desk:
        # Re-sample after attach — Session-0 / Default → Winlogon changes chrome.
        before_state, before_tokens, before_n = visible_surface_signature()
        before_fp = desktop_surface_fingerprint() or before_fp

    details = []
    invoked_any = False
    for as_user in (False, True) if try_as_user else (False,):
        invoked, detail = invoke_send_sas(as_user=as_user)
        details.append(detail)
        invoked_any = invoked_any or invoked
        if not invoked:
            continue
        effect, effect_detail, after_state = watch_sas_effect(
            timeout_sec=timeout_sec,
            before_fp=before_fp,
            before_state=before_state,
            before_tokens=before_tokens,
        )
        after_fp = desktop_surface_fingerprint()
        _, after_tokens, after_n = visible_surface_signature()
        if hdesk:
            try:
                _user32.CloseDesktop(hdesk)
            except Exception:
                pass
            hdesk = None
        return {
            "invoked": True,
            "effect": bool(effect),
            "detail": "; ".join(details + [effect_detail]),
            "ui_before": before_state,
            "ui_after": after_state,
            "desktop": desk if ok_desk else "",
            "as_user": bool(as_user),
            "fp_changed": bool(before_fp and after_fp and before_fp != after_fp),
            "chrome_before": before_n,
            "chrome_after": after_n,
            "tokens_changed": bool(before_tokens != after_tokens),
        }

    if hdesk:
        try:
            _user32.CloseDesktop(hdesk)
        except Exception:
            pass
    after_state, _tok, after_n = visible_surface_signature()
    return {
        "invoked": invoked_any,
        "effect": False,
        "detail": "; ".join(details) or "SendSAS not invoked",
        "ui_before": before_state,
        "ui_after": after_state,
        "desktop": desk if ok_desk else "",
        "as_user": False,
        "fp_changed": False,
        "chrome_before": before_n,
        "chrome_after": after_n,
        "tokens_changed": False,
    }


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
        names = ("Default",)

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
        img.convert("RGB").save(buf, format="JPEG", quality=72, optimize=False)
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
