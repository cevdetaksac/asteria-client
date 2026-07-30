#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Client Instance Management — Singleton control & process management.

Ensures only one Asteria Client instance runs at a time using
Windows named mutexes. Handles graceful shutdown of existing instances.

Key exports:
  check_singleton(mode)         — Acquire global mutex, shutdown conflicts
  try_acquire_mutex_soft()      — Acquire without killing (tray must not steal GUI)
  request_show_existing()       — Tell running instance to SHOW GUI (no steal)
  shutdown_existing_instance()  — Find & terminate running instances
  InstanceManager               — OOP wrapper around singleton logic
"""

import os
import sys
import time
import socket
import subprocess
import win32event
import win32api
import winerror
import psutil

from client_constants import (
    SINGLETON_MUTEX_NAME,
    DAEMON_MUTEX_NAME,
    LEGACY_GUI_SHOW_EVENT_NAME,
    LEGACY_GUI_SHOW_EVENT_NAME_V1,
    LEGACY_GUI_SHOW_EVENT_WEBVIEW,
    CONTROL_HOST,
    CONTROL_PORT,
    gui_mutex_name,
    gui_show_event_name,
)
from client_helpers import log

# Keep mutex handle alive for process lifetime
_MUTEX_HANDLE = None
_DAEMON_MUTEX_HANDLE = None
_GUI_MUTEX_HANDLE = None
_GUI_SHOW_EVENT_HANDLE = None
_GUI_SHOW_WATCHER_STARTED = False


def try_acquire_daemon_mutex() -> bool:
    """Acquire daemon-only mutex. False if another SYSTEM motor is already up."""
    global _DAEMON_MUTEX_HANDLE
    try:
        mutex = win32event.CreateMutex(None, False, DAEMON_MUTEX_NAME)
        last_error = win32api.GetLastError()
        if last_error == winerror.ERROR_ALREADY_EXISTS:
            try:
                win32api.CloseHandle(mutex)
            except Exception:
                pass
            return False
        _DAEMON_MUTEX_HANDLE = mutex
        return True
    except Exception as e:
        log(f"ERROR: Daemon mutex acquire failed: {e}")
        return False


def try_acquire_mutex_soft() -> bool:
    """Acquire legacy singleton mutex without killing others. False if already taken."""
    global _MUTEX_HANDLE
    try:
        mutex = win32event.CreateMutex(None, False, SINGLETON_MUTEX_NAME)
        last_error = win32api.GetLastError()
        if last_error == winerror.ERROR_ALREADY_EXISTS:
            try:
                win32api.CloseHandle(mutex)
            except Exception:
                pass
            return False
        _MUTEX_HANDLE = mutex
        return True
    except Exception as e:
        log(f"ERROR: Soft mutex acquire failed: {e}")
        return False


def try_acquire_gui_mutex() -> bool:
    """Acquire per-session GUI/tray mutex. False if another frontend already owns it."""
    global _GUI_MUTEX_HANDLE
    try:
        name = gui_mutex_name()
        mutex = win32event.CreateMutex(None, False, name)
        last_error = win32api.GetLastError()
        if last_error == winerror.ERROR_ALREADY_EXISTS:
            try:
                win32api.CloseHandle(mutex)
            except Exception:
                pass
            return False
        _GUI_MUTEX_HANDLE = mutex
        return True
    except Exception as e:
        log(f"ERROR: GUI mutex acquire failed: {e}")
        return False


def signal_existing_gui_show() -> bool:
    """Pulse show-event so the running tray/GUI raises its window."""
    names = (
        gui_show_event_name(),
        LEGACY_GUI_SHOW_EVENT_NAME,
        LEGACY_GUI_SHOW_EVENT_NAME_V1,
        LEGACY_GUI_SHOW_EVENT_WEBVIEW,
    )
    ok = False
    for name in names:
        try:
            handle = win32event.CreateEvent(None, False, False, name)
            win32event.SetEvent(handle)
            try:
                win32api.CloseHandle(handle)
            except Exception:
                pass
            ok = True
        except Exception:
            continue
    if not ok:
        log("[SINGLETON] signal_existing_gui_show failed for all event names")
    return ok


def activate_existing_gui_windows() -> bool:
    """Best-effort: restore/foreground any honeypot window in this session."""
    try:
        import ctypes
        from ctypes import wintypes

        user32 = ctypes.windll.user32
        pids = set(list_interactive_honeypot_pids())
        if not pids:
            return False
        found = []

        @ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND, wintypes.LPARAM)
        def _enum(hwnd, _lparam):
            pid = wintypes.DWORD()
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            if int(pid.value) not in pids:
                return True
            # Include hidden / iconic (tray-minimized main window)
            if user32.IsWindow(hwnd):
                found.append(int(hwnd))
            return True

        user32.EnumWindows(_enum, 0)
        SW_RESTORE = 9
        raised = 0
        for hwnd in found:
            try:
                user32.ShowWindow(hwnd, SW_RESTORE)
                user32.SetForegroundWindow(hwnd)
                raised += 1
            except Exception:
                pass
        if raised:
            log(f"[SINGLETON] Raised {raised} existing GUI window(s)")
            return True
    except Exception as e:
        log(f"[SINGLETON] activate_existing_gui_windows failed: {e}")
    return False


def handoff_to_existing_gui() -> bool:
    """Ask the already-running frontend to show; return True if we should exit."""
    signaled = signal_existing_gui_show()
    activated = activate_existing_gui_windows()
    # Control-port SHOW hits the daemon (NOGUI) in frontend architecture — keep as last try
    try:
        request_show_existing(timeout=0.6)
    except Exception:
        pass
    ok = bool(signaled or activated or has_interactive_honeypot())
    if ok:
        log("[SINGLETON] Existing GUI/tray present — handoff done, new instance will exit")
    return ok


def start_gui_show_watcher(show_callback) -> None:
    """Daemon thread: wait for show-event and call show_callback (Tk-safe via callback)."""
    global _GUI_SHOW_EVENT_HANDLE, _GUI_SHOW_WATCHER_STARTED
    if _GUI_SHOW_WATCHER_STARTED or not callable(show_callback):
        return
    _GUI_SHOW_WATCHER_STARTED = True
    try:
        import threading

        _GUI_SHOW_EVENT_HANDLE = win32event.CreateEvent(
            None, False, False, gui_show_event_name()
        )

        def _loop():
            while True:
                try:
                    rc = win32event.WaitForSingleObject(_GUI_SHOW_EVENT_HANDLE, 5000)
                    if rc == win32event.WAIT_OBJECT_0:
                        try:
                            show_callback()
                        except Exception as e:
                            log(f"[SINGLETON] show_callback error: {e}")
                except Exception:
                    time.sleep(1.0)

        threading.Thread(target=_loop, name="GuiShowWatcher", daemon=True).start()
        log("[SINGLETON] GUI show watcher started")
    except Exception as e:
        log(f"[SINGLETON] start_gui_show_watcher failed: {e}")
        _GUI_SHOW_WATCHER_STARTED = False


def mutex_already_held() -> bool:
    """True if another honeypot-client instance owns the singleton mutex."""
    try:
        mutex = win32event.CreateMutex(None, False, SINGLETON_MUTEX_NAME)
        last_error = win32api.GetLastError()
        try:
            win32api.CloseHandle(mutex)
        except Exception:
            pass
        return last_error == winerror.ERROR_ALREADY_EXISTS
    except Exception:
        return False


def request_show_existing(timeout: float = 1.2) -> bool:
    """Ask the already-running instance to bring its GUI to the front.

    Returns True only if the peer confirmed a visible GUI (OK).
    Daemon-only instances reply NOGUI → False so the launcher can take over.
    """
    try:
        with socket.create_connection((CONTROL_HOST, CONTROL_PORT), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(b"SHOW\n")
            try:
                data = sock.recv(64) or b""
            except Exception:
                data = b""
            reply = data.strip().upper()
            if reply.startswith(b"OK"):
                log("[SINGLETON] SHOW OK — existing GUI raised")
                return True
            if reply.startswith(b"NOGUI"):
                log("[SINGLETON] SHOW NOGUI — existing instance has no window")
                return False
            # Legacy peers (no reply): treat as unknown — do not claim success
            log(f"[SINGLETON] SHOW ambiguous reply {reply!r} — will allow takeover")
            return False
    except Exception as e:
        log(f"[SINGLETON] SHOW failed (no healthy control socket): {e}")
        return False


def _kill_script_path() -> str:
    candidates = []
    here = os.path.dirname(os.path.abspath(__file__))
    candidates.append(os.path.join(here, "scripts", "kill-honeypot.ps1"))
    if getattr(sys, "frozen", False):
        candidates.insert(0, os.path.join(os.path.dirname(sys.executable), "scripts", "kill-honeypot.ps1"))
        mei = getattr(sys, "_MEIPASS", "") or ""
        if mei:
            candidates.insert(0, os.path.join(mei, "scripts", "kill-honeypot.ps1"))
    return next((p for p in candidates if os.path.isfile(p)), "")


def force_kill_honeypot_processes() -> None:
    """Best-effort hard kill (QUIT + kill script + taskkill). Used when DACL blocks terminate()."""
    try:
        with socket.create_connection((CONTROL_HOST, CONTROL_PORT), timeout=0.6) as sock:
            sock.sendall(b"QUIT\n")
        time.sleep(0.8)
    except Exception:
        pass

    script = _kill_script_path()
    if script:
        try:
            subprocess.run(
                [
                    "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                    "-File", script, "-Force",
                ],
                capture_output=True,
                timeout=25,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
        except Exception as e:
            log(f"[SINGLETON] kill-honeypot.ps1 failed: {e}")

    try:
        subprocess.run(
            ["taskkill", "/F", "/T", "/IM", "honeypot-client.exe"],
            capture_output=True,
            timeout=8,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
    except Exception:
        pass


# ===================== SINGLETON SYSTEM ===================== #

def check_singleton(mode: str, *, allow_steal: bool = True) -> bool:
    """Check if another instance is running and handle accordingly.

    allow_steal=False: if mutex taken, return False without killing (tray mode).
    allow_steal=True: try graceful then force shutdown, then take mutex (GUI / --show-gui).
    """
    global _MUTEX_HANDLE
    try:
        mutex = win32event.CreateMutex(None, True, SINGLETON_MUTEX_NAME)
        last_error = win32api.GetLastError()

        if last_error == winerror.ERROR_ALREADY_EXISTS:
            try:
                win32api.CloseHandle(mutex)
            except Exception:
                pass

            if not allow_steal:
                log(f"Singleton held — soft mode will not steal ({mode})")
                return False

            log("Another instance detected - attempting graceful shutdown")

            ok = shutdown_existing_instance()
            if not ok:
                log("Graceful shutdown failed — forcing kill (DACL / hung control socket)")
                force_kill_honeypot_processes()
                time.sleep(1.0)
                ok = not _any_honeypot_running()

            if not ok:
                log("ERROR: Failed to shutdown existing instance")
                return False

            log("Existing instance shutdown — waiting before start")
            time.sleep(1.0)

            mutex = win32event.CreateMutex(None, True, SINGLETON_MUTEX_NAME)
            last_error = win32api.GetLastError()

            if last_error == winerror.ERROR_ALREADY_EXISTS:
                # Mutex can linger briefly after process death
                time.sleep(1.5)
                try:
                    win32api.CloseHandle(mutex)
                except Exception:
                    pass
                mutex = win32event.CreateMutex(None, True, SINGLETON_MUTEX_NAME)
                last_error = win32api.GetLastError()

            if last_error == winerror.ERROR_ALREADY_EXISTS:
                log("ERROR: Could not acquire singleton mutex after shutdown attempt")
                try:
                    win32api.CloseHandle(mutex)
                except Exception:
                    pass
                return False
            _MUTEX_HANDLE = mutex
        else:
            _MUTEX_HANDLE = mutex

        log(f"Singleton mutex acquired for mode: {mode}")
        return True

    except Exception as e:
        log(f"ERROR: Singleton check failed: {e}")
        return False


def _any_honeypot_running() -> bool:
    current_pid = os.getpid()
    try:
        for p in psutil.process_iter(["pid", "name"]):
            name = (p.info.get("name") or "").lower()
            if name in ("honeypot-client.exe", "client.exe") and p.info["pid"] != current_pid:
                return True
    except Exception:
        pass
    return False


def list_interactive_honeypot_pids(exclude_pid=None) -> list:
    """PIDs of honeypot-client in interactive sessions (SessionId > 0)."""
    found = []
    me = exclude_pid if exclude_pid is not None else os.getpid()
    try:
        for p in psutil.process_iter(["pid", "name"]):
            name = (p.info.get("name") or "").lower()
            if name not in ("honeypot-client.exe", "client.exe"):
                continue
            pid = p.info.get("pid")
            if pid == me:
                continue
            try:
                sid = psutil.Process(pid).session_id()
            except Exception:
                continue
            if sid and int(sid) > 0:
                found.append(int(pid))
    except Exception:
        pass
    return found


def has_interactive_honeypot(exclude_pid=None) -> bool:
    """True if another honeypot runs in a user desktop session (multi-user safe)."""
    return bool(list_interactive_honeypot_pids(exclude_pid=exclude_pid))


def shutdown_existing_instance() -> bool:
    """Find and gracefully shutdown existing honeypot-client.exe processes"""
    try:
        current_pid = os.getpid()
        processes_found = []

        for proc in psutil.process_iter(["pid", "name", "cmdline"]):
            name = (proc.info.get("name") or "").lower()
            if name in ("honeypot-client.exe", "client.exe") and proc.info["pid"] != current_pid:
                processes_found.append(proc)

        if not processes_found:
            log("No existing instances found")
            return True

        log(f"Found {len(processes_found)} existing processes to shutdown")

        # Prefer QUIT via control socket (process exits itself → DACL bypass)
        try:
            with socket.create_connection((CONTROL_HOST, CONTROL_PORT), timeout=0.8) as sock:
                sock.sendall(b"QUIT\n")
            time.sleep(1.2)
        except Exception:
            pass

        for proc in list(processes_found):
            try:
                if not proc.is_running():
                    continue
                log(f"Gracefully terminating PID {proc.info['pid']}")
                proc.terminate()
                proc.wait(timeout=4)
                log(f"Successfully terminated PID {proc.info['pid']}")
            except psutil.TimeoutExpired:
                try:
                    log(f"Force killing PID {proc.info['pid']}")
                    proc.kill()
                    proc.wait(timeout=2)
                except Exception:
                    pass
            except Exception as e:
                log(f"Terminate PID {proc.info.get('pid')} failed: {e}")

        time.sleep(0.4)
        if _any_honeypot_running():
            log("WARNING: process(es) still running after graceful shutdown")
            return False
        return True

    except Exception as e:
        log(f"ERROR: shutdown_existing_instance failed: {e}")
        return False


class InstanceManager:
    """OOP wrapper around singleton helpers."""

    def acquire(self, mode: str = "gui", allow_steal: bool = True) -> bool:
        return check_singleton(mode, allow_steal=allow_steal)
