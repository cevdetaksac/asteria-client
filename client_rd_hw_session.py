"""Cross-session asteria-encode spawn via CreateProcessAsUser (C-RD-HW-CON/SES).

Replaces plain subprocess.Popen when the agent is Session-0 SYSTEM (or any
session that is not the capture target). Stdio is redirected through inheritable
anonymous pipes so the existing JSON-lines protocol keeps working.
"""
from __future__ import annotations

import ctypes
import json
import logging
import os
import subprocess
import sys
import threading
from ctypes import wintypes
from pathlib import Path
from typing import Any, Optional, Tuple

log = logging.getLogger("asteria.rd_hw")

# Win32 constants
HANDLE_FLAG_INHERIT = 0x00000001
STARTF_USESTDHANDLES = 0x00000100
CREATE_NO_WINDOW = 0x08000000
CREATE_UNICODE_ENVIRONMENT = 0x00000400
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
DUPLICATE_CLOSE_SOURCE = 0x00000001
DUPLICATE_SAME_ACCESS = 0x00000002


class _SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("nLength", wintypes.DWORD),
        ("lpSecurityDescriptor", wintypes.LPVOID),
        ("bInheritHandle", wintypes.BOOL),
    ]


class _STARTUPINFO(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR),
        ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD),
        ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD),
        ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD),
        ("lpReserved2", ctypes.POINTER(ctypes.c_byte)),
        ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
    ]


class _PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
    ]


def current_process_session_id() -> int:
    try:
        pid = os.getpid()
        sid = wintypes.DWORD()
        if ctypes.windll.kernel32.ProcessIdToSessionId(pid, ctypes.byref(sid)):
            return int(sid.value)
    except Exception:
        pass
    return -1


def console_session_id() -> int:
    try:
        from client_rd_winlogon import console_session_id as _cs

        return int(_cs() or 0)
    except Exception:
        try:
            return int(ctypes.windll.kernel32.WTSGetActiveConsoleSessionId())
        except Exception:
            return 0


def resolve_hw_target(
    session_target: Optional[dict],
    *,
    winlogon: bool = False,
    explicit_session_id: Optional[int] = None,
) -> Tuple[int, str, str]:
    """Return (session_id, desktop, reason).

    desktop is ``winsta0\\Winlogon`` or ``winsta0\\default``.
    """
    st = session_target if isinstance(session_target, dict) else {}
    kind = str(st.get("kind") or "console").lower()
    if explicit_session_id is not None:
        sid = int(explicit_session_id)
    elif kind == "session" and st.get("session_id") is not None:
        sid = int(st["session_id"])
    else:
        sid = console_session_id()
    if sid <= 0:
        raise ValueError(f"refused_session_zero sid={sid}")
    secure = bool(winlogon) or kind in ("console", "winlogon") and (
        winlogon or str(st.get("desktop") or "").lower() == "winlogon"
    )
    # Pre-logon / no-user: always Winlogon on the console session
    if kind in ("console", "winlogon") or winlogon:
        # Detect nobody logged on: no username on console → Winlogon
        try:
            from client_rd_winlogon import session_username, session_has_logonui

            uname = (session_username(sid) or "").strip()
            if not uname or session_has_logonui(sid) or winlogon:
                secure = True
        except Exception:
            if winlogon:
                secure = True
    desk = r"winsta0\Winlogon" if secure else r"winsta0\default"
    reason = "winlogon" if secure else ("session" if kind == "session" else "console")
    return sid, desk, reason


def needs_cross_session(session_id: int) -> bool:
    """True when encode must be CreateProcessAsUser'd into session_id."""
    cur = current_process_session_id()
    if cur < 0:
        return True  # unknown → try cross-session
    if cur == 0 and session_id > 0:
        return True  # Session-0 service → interactive
    return int(cur) != int(session_id)


def _make_pipe(inherit_read: bool, inherit_write: bool):
    sa = _SECURITY_ATTRIBUTES()
    sa.nLength = ctypes.sizeof(_SECURITY_ATTRIBUTES)
    sa.bInheritHandle = True
    r = wintypes.HANDLE()
    w = wintypes.HANDLE()
    kernel = ctypes.windll.kernel32
    if not kernel.CreatePipe(ctypes.byref(r), ctypes.byref(w), ctypes.byref(sa), 0):
        raise OSError(f"CreatePipe failed err={kernel.GetLastError()}")
    # Only the child-side ends stay inheritable
    if not inherit_read:
        kernel.SetHandleInformation(r, HANDLE_FLAG_INHERIT, 0)
    if not inherit_write:
        kernel.SetHandleInformation(w, HANDLE_FLAG_INHERIT, 0)
    return r, w


def spawn_in_session(
    exe: Path,
    args: list,
    session_id: int,
    desktop: str,
    *,
    for_secure_desktop: bool = False,
) -> subprocess.Popen:
    """CreateProcessAsUser(exe) in session_id with stdio pipes → Popen-like object."""
    from client_rd_winlogon import enable_process_privileges, open_session_interactive_token

    enable_process_privileges(
        "SeDebugPrivilege",
        "SeTcbPrivilege",
        "SeAssignPrimaryTokenPrivilege",
        "SeIncreaseQuotaPrivilege",
    )
    h_token, token_src = open_session_interactive_token(
        int(session_id), for_secure_desktop=for_secure_desktop
    )
    if not h_token:
        raise RuntimeError(f"no interactive token session={session_id} ({token_src})")

    kernel = ctypes.windll.kernel32
    adv = ctypes.windll.advapi32

    # Parent writes child stdin; parent reads child stdout/stderr
    child_stdin_r, parent_stdin_w = _make_pipe(inherit_read=True, inherit_write=False)
    parent_stdout_r, child_stdout_w = _make_pipe(inherit_read=False, inherit_write=True)
    parent_stderr_r, child_stderr_w = _make_pipe(inherit_read=False, inherit_write=True)

    si = _STARTUPINFO()
    si.cb = ctypes.sizeof(_STARTUPINFO)
    si.lpDesktop = desktop
    si.dwFlags = STARTF_USESTDHANDLES
    si.hStdInput = child_stdin_r
    si.hStdOutput = child_stdout_w
    si.hStdError = child_stderr_w
    pi = _PROCESS_INFORMATION()

    cmdline = subprocess.list2cmdline([str(exe)] + list(args))
    cmd_buf = ctypes.create_unicode_buffer(cmdline)
    # Do NOT use CREATE_NO_WINDOW — DXGI/DWM need a real desktop process (C-RD-HW-CON).
    flags = 0
    env_block = None
    try:
        if "winlogon" not in desktop.lower():
            env_ptr = ctypes.c_void_p()
            if adv.CreateEnvironmentBlock(ctypes.byref(env_ptr), h_token, False):
                env_block = env_ptr
                flags |= CREATE_UNICODE_ENVIRONMENT
    except Exception:
        env_block = None

    ok = adv.CreateProcessAsUserW(
        h_token,
        None,
        cmd_buf,
        None,
        None,
        True,  # inherit handles
        flags,
        env_block.value if env_block else None,
        None,
        ctypes.byref(si),
        ctypes.byref(pi),
    )
    last_err = int(kernel.GetLastError() or 0)
    # Prefer SYSTEM+TokenSessionId over LogonUI when spawn hits memory/access errors
    if (not ok) and last_err in (8, 1450, 1455, 5) and token_src != "system_session":
        try:
            kernel.CloseHandle(h_token)
        except Exception:
            pass
        h_token = None
        h2, src2 = open_session_interactive_token(
            int(session_id), for_secure_desktop=True
        )
        if h2 and src2 == "system_session":
            h_token, token_src = h2, src2
            ok = adv.CreateProcessAsUserW(
                h_token,
                None,
                cmd_buf,
                None,
                None,
                True,
                0,
                None,
                None,
                ctypes.byref(si),
                ctypes.byref(pi),
            )
            last_err = int(kernel.GetLastError() or 0)
            log.info(
                "HW encode CreateProcessAsUser retry token=%s ok=%s err=%s",
                token_src, bool(ok), last_err,
            )
    # Close child-side ends in parent
    for h in (child_stdin_r, child_stdout_w, child_stderr_w):
        try:
            kernel.CloseHandle(h)
        except Exception:
            pass
    if env_block and env_block.value:
        try:
            adv.DestroyEnvironmentBlock(env_block)
        except Exception:
            pass
    if h_token:
        try:
            kernel.CloseHandle(h_token)
        except Exception:
            pass

    if not ok:
        for h in (parent_stdin_w, parent_stdout_r, parent_stderr_r):
            try:
                kernel.CloseHandle(h)
            except Exception:
                pass
        raise OSError(
            f"CreateProcessAsUser failed err={last_err} session={session_id} "
            f"desktop={desktop} token={token_src}"
        )

    log.info(
        "HW encode CreateProcessAsUser ok session=%s desktop=%s token=%s pid=%s",
        session_id,
        desktop,
        token_src,
        pi.dwProcessId,
    )

    # Wrap handles as Python file objects / Popen-compatible
    import msvcrt

    def _fd(handle, mode: str):
        hv = int(handle.value) if hasattr(handle, "value") else int(handle)
        # 0 = default access; open_osfhandle takes ownership of the HANDLE
        fd = msvcrt.open_osfhandle(hv, 0)
        return open(fd, mode + "b", buffering=0)

    # Detach OS handles into Python owned fds (open_osfhandle takes ownership)
    stdin_f = _fd(parent_stdin_w, "w")
    stdout_f = _fd(parent_stdout_r, "r")
    stderr_f = _fd(parent_stderr_r, "r")

    class _Proc:
        def __init__(self):
            self.stdin = stdin_f
            self.stdout = stdout_f
            self.stderr = stderr_f
            self.pid = int(pi.dwProcessId)
            self._hProcess = pi.hProcess
            self.returncode = None

        def poll(self):
            if self.returncode is not None:
                return self.returncode
            # WAIT_OBJECT_0 = 0, WAIT_TIMEOUT = 258
            r = kernel.WaitForSingleObject(self._hProcess, 0)
            if r == 0:
                code = wintypes.DWORD()
                kernel.GetExitCodeProcess(self._hProcess, ctypes.byref(code))
                self.returncode = int(code.value)
                return self.returncode
            return None

        def wait(self, timeout=None):
            ms = 0xFFFFFFFF if timeout is None else int(max(0, timeout) * 1000)
            r = kernel.WaitForSingleObject(self._hProcess, ms)
            if r == 0:
                return self.poll()
            raise subprocess.TimeoutExpired(cmd=cmdline, timeout=timeout)

        def kill(self):
            kernel.TerminateProcess(self._hProcess, 1)

        def __del__(self):
            try:
                kernel.CloseHandle(self._hProcess)
                kernel.CloseHandle(pi.hThread)
            except Exception:
                pass

    return _Proc()  # type: ignore[return-value]
