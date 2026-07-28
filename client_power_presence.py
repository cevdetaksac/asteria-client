#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Windows sleep/hibernate → presence suspend; resume → online.

Uses PowerRegisterSuspendResumeNotification when available (Session-0 safe),
plus SetConsoleCtrlHandler for OS shutdown. Contract: api/11-presence-realtime.md
"""

from __future__ import annotations

import ctypes
import threading
import time
from ctypes import wintypes
from typing import Callable, Optional

try:
    from client_helpers import log
except Exception:  # pragma: no cover
    def log(*_a, **_k):
        pass

PBT_APMSUSPEND = 0x0004
PBT_APMRESUMESUSPEND = 0x0007
PBT_APMRESUMEAUTOMATIC = 0x0012
PBT_APMQUERYSUSPEND = 0x0000

DEVICE_NOTIFY_CALLBACK = 2
DEVICE_NOTIFY_CALLBACK_ROUTINE = ctypes.WINFUNCTYPE(
    wintypes.ULONG, ctypes.c_void_p, wintypes.ULONG, ctypes.c_void_p
)

CTRL_C_EVENT = 0
CTRL_BREAK_EVENT = 1
CTRL_CLOSE_EVENT = 2
CTRL_LOGOFF_EVENT = 5
CTRL_SHUTDOWN_EVENT = 6

# Suppress false agent_persistence_degraded while IPC/DNS settle after wake.
RESUME_GRACE_SEC = 180.0

_started = False
_lock = threading.Lock()
_registration = None
_callback_ref = None
_ctrl_ref = None
_resume_grace_until = 0.0


class DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS(ctypes.Structure):
    _fields_ = [
        ("Callback", DEVICE_NOTIFY_CALLBACK_ROUTINE),
        ("Context", ctypes.c_void_p),
    ]


def note_resume_grace(seconds: float = RESUME_GRACE_SEC) -> None:
    global _resume_grace_until
    try:
        sec = float(seconds)
    except Exception:
        sec = RESUME_GRACE_SEC
    _resume_grace_until = time.time() + max(0.0, sec)


def in_resume_grace() -> bool:
    return time.time() < float(_resume_grace_until or 0.0)


def _on_suspend(reason: str = "sleep") -> None:
    try:
        from client_presence import emit_lifecycle_mirror, signal_presence
        signal_presence("suspend", reason, http_fallback=True, timeout=1.5)
        emit_lifecycle_mirror(
            "host_hibernate" if reason == "hibernate" else "host_sleep",
            reason,
        )
    except Exception as e:
        log(f"[POWER] suspend signal failed: {e}")


def _on_resume() -> None:
    note_resume_grace()
    try:
        from client_presence import (
            emit_lifecycle_mirror,
            mark_online_on_next_connect,
            request_ws_reconnect,
            signal_presence,
        )
        mark_online_on_next_connect()
        request_ws_reconnect()
        signal_presence("online", "resume", http_fallback=True, timeout=2.0)
        emit_lifecycle_mirror("host_resume", "wake")
    except Exception as e:
        log(f"[POWER] resume signal failed: {e}")


def _on_shutdown() -> None:
    try:
        from client_presence import emit_lifecycle_mirror, signal_goodbye
        signal_goodbye("shutdown", http_fallback=True, close_after=False)
        emit_lifecycle_mirror("host_shutdown", "shutdown")
    except Exception as e:
        log(f"[POWER] shutdown signal failed: {e}")


def _power_callback(context, type_, setting):
    try:
        evt = int(type_ or 0)
    except Exception:
        return 0
    if evt == PBT_APMSUSPEND:
        log("[POWER] PBT_APMSUSPEND")
        _on_suspend("sleep")
    elif evt in (PBT_APMRESUMESUSPEND, PBT_APMRESUMEAUTOMATIC):
        log(f"[POWER] resume evt=0x{evt:X}")
        _on_resume()
    return 0


def _ctrl_handler(ctrl_type):
    try:
        ct = int(ctrl_type)
    except Exception:
        return 0
    if ct in (CTRL_SHUTDOWN_EVENT, CTRL_CLOSE_EVENT):
        log(f"[POWER] console ctrl={ct} → goodbye")
        _on_shutdown()
        return 1
    if ct == CTRL_LOGOFF_EVENT:
        # Session logoff must NOT offline SYSTEM daemon presence
        return 0
    return 0


def start_power_presence_watcher() -> bool:
    """Idempotent. Call from Session-0 run_daemon only."""
    global _started, _registration, _callback_ref, _ctrl_ref
    with _lock:
        if _started:
            return True
        _started = True

    ok_power = False
    try:
        powrprof = ctypes.WinDLL("powrprof")
        cb = DEVICE_NOTIFY_CALLBACK_ROUTINE(_power_callback)
        _callback_ref = cb  # keep alive
        params = DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS()
        params.Callback = cb
        params.Context = None
        handle = wintypes.HANDLE()
        # BOOLEAN PowerRegisterSuspendResumeNotification(Flags, Recipient, *Reg)
        # Recipient = pointer to DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS when CALLBACK
        fn = powrprof.PowerRegisterSuspendResumeNotification
        fn.argtypes = [wintypes.DWORD, wintypes.LPVOID, ctypes.POINTER(wintypes.HANDLE)]
        fn.restype = wintypes.DWORD
        rc = fn(
            DEVICE_NOTIFY_CALLBACK,
            ctypes.byref(params),
            ctypes.byref(handle),
        )
        if rc == 0:
            _registration = handle
            ok_power = True
            log("[POWER] SuspendResumeNotification registered")
        else:
            log(f"[POWER] PowerRegisterSuspendResumeNotification rc={rc}")
    except Exception as e:
        log(f"[POWER] SuspendResumeNotification unavailable: {e}")

    try:
        HandlerRoutine = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.DWORD)
        _ctrl_ref = HandlerRoutine(_ctrl_handler)
        if ctypes.windll.kernel32.SetConsoleCtrlHandler(_ctrl_ref, True):
            log("[POWER] SetConsoleCtrlHandler armed")
        else:
            log("[POWER] SetConsoleCtrlHandler failed")
    except Exception as e:
        log(f"[POWER] console handler failed: {e}")

    # Message-only window fallback (helps some Session-0 hosts)
    if not ok_power:
        threading.Thread(
            target=_message_window_loop,
            name="PowerPresenceWnd",
            daemon=True,
        ).start()

    return True


def _message_window_loop() -> None:
    try:
        user32 = ctypes.windll.user32
        kernel32 = ctypes.windll.kernel32
        WM_POWERBROADCAST = 0x0218
        HWND_MESSAGE = -3

        WNDPROC = ctypes.WINFUNCTYPE(
            ctypes.c_long, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM
        )

        def _wndproc(hwnd, msg, wparam, lparam):
            if msg == WM_POWERBROADCAST:
                wp = int(wparam)
                if wp == PBT_APMSUSPEND:
                    log("[POWER] WM_POWERBROADCAST SUSPEND")
                    _on_suspend("sleep")
                elif wp in (PBT_APMRESUMESUSPEND, PBT_APMRESUMEAUTOMATIC):
                    log(f"[POWER] WM_POWERBROADCAST resume 0x{wp:X}")
                    _on_resume()
                return 1
            return user32.DefWindowProcW(hwnd, msg, wparam, lparam)

        wndproc = WNDPROC(_wndproc)
        class_name = "YesNextPresencePowerWnd"

        class WNDCLASSW(ctypes.Structure):
            _fields_ = [
                ("style", wintypes.UINT),
                ("lpfnWndProc", WNDPROC),
                ("cbClsExtra", ctypes.c_int),
                ("cbWndExtra", ctypes.c_int),
                ("hInstance", wintypes.HINSTANCE),
                ("hIcon", wintypes.HICON),
                ("hCursor", wintypes.HANDLE),
                ("hbrBackground", wintypes.HBRUSH),
                ("lpszMenuName", wintypes.LPCWSTR),
                ("lpszClassName", wintypes.LPCWSTR),
            ]

        hinst = kernel32.GetModuleHandleW(None)
        wc2 = WNDCLASSW()
        wc2.style = 0
        wc2.lpfnWndProc = wndproc
        wc2.cbClsExtra = 0
        wc2.cbWndExtra = 0
        wc2.hInstance = hinst
        wc2.hIcon = None
        wc2.hCursor = None
        wc2.hbrBackground = None
        wc2.lpszMenuName = None
        wc2.lpszClassName = class_name
        if not user32.RegisterClassW(ctypes.byref(wc2)):
            err = kernel32.GetLastError()
            if err not in (1410,):  # already registered
                log(f"[POWER] RegisterClassW failed err={err}")
                return
        hwnd = user32.CreateWindowExW(
            0,
            class_name,
            "YesNextPresence",
            0,
            0, 0, 0, 0,
            HWND_MESSAGE,
            None,
            hinst,
            None,
        )
        if not hwnd:
            log(f"[POWER] CreateWindowExW failed err={kernel32.GetLastError()}")
            return
        log("[POWER] message-only power window ready")
        msg = wintypes.MSG()
        while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
            user32.TranslateMessage(ctypes.byref(msg))
            user32.DispatchMessageW(ctypes.byref(msg))
    except Exception as e:
        log(f"[POWER] message window loop failed: {e}")
