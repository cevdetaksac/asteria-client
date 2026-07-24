#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Asteria Client - Helper Functions
Yardımcı fonksiyonlar ve genel amaçlı utilities

Version: See client_constants.VERSION

Features:
- Public IP caching with 5-minute TTL (reduces HTTP calls)
- Token obfuscation and security helpers
- GUI message utilities
- Hash and checksum functions

Performance Notes:
- get_public_ip() now caches results for 60 seconds
- Use force_refresh=True to bypass cache when needed
"""

import os
import sys
import time
import socket
import threading
import requests
import tkinter as tk
from typing import Dict, Optional
import logging

# Import required modules
from client_utils import SystemUtils

# Global logger reference - will be set by main application
LOGGER: Optional[logging.Logger] = None

# IP Cache for performance optimization
# Short TTL so laptop Wi‑Fi / network switches report WAN IP quickly via update-ip
_ip_cache = {
    'ip': None,
    'last_check': 0,
    'cache_duration': 60  # 1 minute (was 300s)
}

def get_windows_session_id() -> int:
    """Return current process Windows session id, or -1 on failure."""
    try:
        import ctypes
        from ctypes import wintypes
        sid = wintypes.DWORD()
        if ctypes.windll.kernel32.ProcessIdToSessionId(
            ctypes.windll.kernel32.GetCurrentProcessId(),
            ctypes.byref(sid),
        ):
            return int(sid.value)
    except Exception:
        pass
    return -1


def is_session_zero() -> bool:
    """True when running in Session 0 (services / SYSTEM) — GUI is invisible to users."""
    return get_windows_session_id() == 0


def has_interactive_user_session(query_stdout: Optional[str] = None) -> bool:
    """True if any Active console/RDP session with id > 0 exists (not services/Session 0).

    Locale-aware: EN Active, TR Aktif, DE Aktiv, ES Activo, IT Attivo, …

    Note: ``query session`` often returns exit code 1 on Windows even when it
    printed a valid Active console line — never discard stdout solely on rc.
    """
    try:
        from client_winproc import run_hidden
        stdout = query_stdout
        if stdout is None:
            rc, out, _ = run_hidden(["query", "session"], timeout=10)
            stdout = out or ""
            # Prefer parsing session output even when rc != 0 (common on Win10/11)
            if _stdout_has_active_interactive(stdout):
                return True
            # Fallback: query user (also localized)
            rc2, out2, _ = run_hidden(["query", "user"], timeout=10)
            stdout = out2 or ""
            if _stdout_has_active_interactive(stdout):
                return True
            return False
        return bool(_stdout_has_active_interactive(stdout))
    except Exception:
        return False


# Windows "query session/user" state column — not always English "Active"
_ACTIVE_STATE_TOKENS = frozenset({
    "active", "aktif", "aktiv", "activo", "attivo", "активно",
})


def _is_active_state_token(tok: str) -> bool:
    t = (tok or "").strip().lower().lstrip(">")
    if not t:
        return False
    if t in _ACTIVE_STATE_TOKENS:
        return True
    # Some builds prefix / suffix punctuation
    return any(t.startswith(a) or t.endswith(a) for a in _ACTIVE_STATE_TOKENS)


def _stdout_has_active_interactive(stdout: str) -> bool:
    for line in (stdout or "").splitlines()[1:]:
        low = line.lower()
        if "services" in low or "servis" in low:
            continue
        parts = line.split()
        if not parts:
            continue
        try:
            idx = next(i for i, p in enumerate(parts) if _is_active_state_token(p))
        except StopIteration:
            continue
        # Session id is typically immediately before state
        sid = None
        if idx >= 1:
            try:
                sid = int(parts[idx - 1])
            except ValueError:
                sid = None
        if sid is not None:
            if sid > 0:
                return True
            continue
        # No numeric id parsed — still treat console/rdp Active as interactive
        if "console" in low or "rdp" in low or "tcp#" in low:
            return True
    return False


def get_active_interactive_session_id() -> int:
    """Best-effort WTS session id (>0) for Active console/RDP, or 0."""
    try:
        from client_winproc import run_hidden
        rc, out, _ = run_hidden(["query", "session"], timeout=10)
        # query session often exits 1 with valid stdout — still parse it
        for line in (out or "").splitlines()[1:]:
            low = line.lower()
            if "services" in low or "servis" in low:
                continue
            parts = line.split()
            try:
                idx = next(i for i, p in enumerate(parts) if _is_active_state_token(p))
                sid = int(parts[idx - 1])
                if sid > 0:
                    return sid
            except (StopIteration, ValueError, IndexError):
                continue
        if rc != 0:
            return 0
    except Exception:
        pass
    return 0


def interactive_frontend_running() -> bool:
    """True if honeypot-client GUI/tray is already running in a user session (session id > 0)."""
    try:
        import ctypes
        import psutil
        from ctypes import wintypes

        me = os.getpid()
        kernel32 = ctypes.windll.kernel32
        for proc in psutil.process_iter(["pid", "name", "cmdline"]):
            try:
                pid = int(proc.info.get("pid") or 0)
                if pid == me:
                    continue
                name = (proc.info.get("name") or "").lower()
                cmdline = " ".join(proc.info.get("cmdline") or [])
                if "honeypot-client" not in name and "client.py" not in cmdline:
                    continue
                if "--watchdog" in cmdline or "--silent-update" in cmdline:
                    continue
                if "--mode=daemon" in cmdline or "--daemon" in cmdline:
                    continue
                sid = wintypes.DWORD()
                if kernel32.ProcessIdToSessionId(pid, ctypes.byref(sid)):
                    if int(sid.value) > 0:
                        return True
            except (psutil.NoSuchProcess, psutil.AccessDenied, TypeError, ValueError):
                continue
        return False
    except Exception:
        return False


def launch_interactive_tray_gui() -> bool:
    """Start CloudHoneypot-Tray in the logged-on user session (visible desktop)."""
    try:
        import sys
        import time
        from client_task_scheduler import TASK_NAME_TRAY
        from client_winproc import run_hidden
        if interactive_frontend_running():
            log(f"[SESSION] Interactive frontend already running — skip {TASK_NAME_TRAY}")
            return True

        # 1) Prefer Task Scheduler Logon task (runs in user session)
        run_hidden(
            ["schtasks", "/change", "/tn", TASK_NAME_TRAY, "/enable"],
            timeout=10,
        )
        rc, _, _ = run_hidden(
            ["schtasks", "/run", "/tn", TASK_NAME_TRAY],
            timeout=15,
        )
        ok = rc == 0
        log(f"[SESSION] Trigger {TASK_NAME_TRAY}: rc={rc} ok={ok}")
        if ok:
            time.sleep(2.5)
            if interactive_frontend_running():
                return True
            log("[SESSION] schtasks /run returned ok but no interactive frontend yet — trying CreateProcessAsUser")

        # 2) SYSTEM → inject into Active interactive session (Admin RDP / console)
        if _launch_tray_via_wts():
            time.sleep(1.5)
            if interactive_frontend_running():
                log("[SESSION] Tray started via WTS CreateProcessAsUser")
                return True

        return interactive_frontend_running()
    except Exception as e:
        log(f"[SESSION] launch_interactive_tray_gui failed: {e}")
        return False


def _launch_tray_via_wts() -> bool:
    """CreateProcessAsUser(--mode=tray) into Active session id > 0 (needs SYSTEM)."""
    try:
        import ctypes
        import sys
        from ctypes import wintypes

        session_id = get_active_interactive_session_id()
        if session_id <= 0:
            log("[SESSION] WTS launch: no active interactive session id")
            return False

        if getattr(sys, "frozen", False):
            exe = sys.executable
            cmdline = f'"{exe}" --mode=tray'
        else:
            exe = sys.executable
            script = os.path.abspath(sys.argv[0]) if sys.argv else ""
            cmdline = f'"{exe}" "{script}" --mode=tray'

        wts = ctypes.windll.wtsapi32
        adv = ctypes.windll.advapi32
        kernel = ctypes.windll.kernel32

        h_token = wintypes.HANDLE()
        if not wts.WTSQueryUserToken(session_id, ctypes.byref(h_token)):
            err = kernel.GetLastError()
            log(f"[SESSION] WTSQueryUserToken({session_id}) failed err={err}")
            return False

        class STARTUPINFO(ctypes.Structure):
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
                ("lpReserved2", ctypes.POINTER(wintypes.BYTE)),
                ("hStdInput", wintypes.HANDLE),
                ("hStdOutput", wintypes.HANDLE),
                ("hStdError", wintypes.HANDLE),
            ]

        class PROCESS_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("hProcess", wintypes.HANDLE),
                ("hThread", wintypes.HANDLE),
                ("dwProcessId", wintypes.DWORD),
                ("dwThreadId", wintypes.DWORD),
            ]

        si = STARTUPINFO()
        si.cb = ctypes.sizeof(STARTUPINFO)
        si.lpDesktop = "winsta0\\default"
        pi = PROCESS_INFORMATION()
        CREATE_UNICODE_ENVIRONMENT = 0x00000400
        CREATE_NEW_CONSOLE = 0x00000010
        cmd_buf = ctypes.create_unicode_buffer(cmdline)

        ok = adv.CreateProcessAsUserW(
            h_token,
            None,
            cmd_buf,
            None,
            None,
            False,
            CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_CONSOLE,
            None,
            None,
            ctypes.byref(si),
            ctypes.byref(pi),
        )
        try:
            kernel.CloseHandle(h_token)
        except Exception:
            pass
        if not ok:
            log(f"[SESSION] CreateProcessAsUser failed err={kernel.GetLastError()}")
            return False
        try:
            kernel.CloseHandle(pi.hThread)
            kernel.CloseHandle(pi.hProcess)
        except Exception:
            pass
        log(f"[SESSION] CreateProcessAsUser tray pid={pi.dwProcessId} session={session_id}")
        return True
    except Exception as e:
        log(f"[SESSION] _launch_tray_via_wts: {e}")
        return False


def set_logger(logger: logging.Logger) -> None:
    """Set global logger for helper functions"""
    global LOGGER
    LOGGER = logger

# ===================== GLOBAL UTILITY FUNCTIONS ===================== #

def log(msg: str) -> None:
    """Centralized logging function with error handling"""
    try:
        if LOGGER:
            LOGGER.info(str(msg))
        else:
            print(f"[LOG] {msg}")  # Fallback to print if logger not set
    except Exception as e:
        if LOGGER:
            LOGGER.error(f"Log error: {e}")
        else:
            print(f"[LOG ERROR] {e}")

def run_cmd(cmd, timeout: int = 20, suppress_rc_log: bool = False):
    """Execute system commands using modular SystemUtils"""
    return SystemUtils.run_cmd(cmd, timeout, suppress_rc_log, log)

def is_port_in_use(port: int) -> bool:
    """Check if a TCP port is currently in use (native socket — no subprocess)"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            result = s.connect_ex(("127.0.0.1", int(port)))
            return result == 0  # 0 = connected = port in use
    except Exception:
        return False

# ===================== HELPER FUNCTIONS CLASS ===================== #

class ClientHelpers:
    """Container class for client helper functions"""
    
    @staticmethod
    def get_public_ip(force_refresh: bool = False, *, allow_network: bool = True) -> str:
        """Get public IP address with caching for performance.

        allow_network=False: never block (GUI startup) — return cache or "".
        """
        global _ip_cache
        current_time = time.time()
        
        # Return cached IP if still valid and not forcing refresh
        if not force_refresh and _ip_cache['ip'] and \
           (current_time - _ip_cache['last_check']) < _ip_cache['cache_duration']:
            return _ip_cache['ip']

        if not allow_network:
            return _ip_cache['ip'] if _ip_cache['ip'] else ""
        
        # Fetch new IP
        try:
            ip = requests.get("https://api.ipify.org", timeout=5).text.strip()
            _ip_cache['ip'] = ip
            _ip_cache['last_check'] = current_time
            return ip
        except Exception as e:
            log(f"get_public_ip error: {e}")
            # Return cached IP if available, otherwise fallback
            return _ip_cache['ip'] if _ip_cache['ip'] else "0.0.0.0"

    @staticmethod
    def is_system_motor_alive(timeout: float = 0.8) -> bool:
        """True if Session-0 security motor is healthy (not merely any GUI process)."""
        try:
            from client_daemon_ipc import is_motor_healthy
            if is_motor_healthy(timeout=timeout):
                return True
        except Exception:
            pass
        try:
            import ctypes
            import psutil
            from ctypes import wintypes

            kernel32 = ctypes.windll.kernel32
            current_pid = os.getpid()
            for proc in psutil.process_iter(["pid", "name", "cmdline"]):
                try:
                    pid = int(proc.info.get("pid") or 0)
                    if pid == current_pid:
                        continue
                    name = (proc.info.get("name") or "").lower()
                    cmdline = " ".join(proc.info.get("cmdline") or []).lower()
                    if "honeypot-client" not in name and "client.py" not in cmdline:
                        continue
                    if "--watchdog" in cmdline or "--silent-update" in cmdline:
                        continue
                    sid = wintypes.DWORD()
                    if not kernel32.ProcessIdToSessionId(pid, ctypes.byref(sid)):
                        continue
                    if int(sid.value) != 0:
                        continue
                    # Session 0 honeypot process = candidate motor
                    if "--mode=daemon" in cmdline or "--daemon" in cmdline or "honeypot-client" in name:
                        return True
                except (psutil.NoSuchProcess, psutil.AccessDenied, TypeError, ValueError):
                    continue
        except Exception as e:
            log(f"is_system_motor_alive error: {e}")
        return False

    @staticmethod
    def is_app_running() -> bool:
        """Check if main app is currently running"""
        try:
            import psutil
            current_pid = os.getpid()
            
            # Check for other instances of this app
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    if proc.info['pid'] == current_pid:
                        continue  # Skip current process
                    
                    # Check if it's our executable
                    if proc.info['name'] and 'honeypot-client' in proc.info['name'].lower():
                        return True
                    
                    # Check command line for python script
                    if proc.info['cmdline']:
                        cmdline = ' '.join(proc.info['cmdline'])
                        if 'client.py' in cmdline and '--watchdog' not in cmdline:
                            return True
                            
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            return False
            
        except ImportError:
            log("psutil not available, checking via process name")
            # Fallback to simpler check
            try:
                from client_winproc import run_hidden
                _rc, out, _ = run_hidden(
                    ["tasklist", "/FI", "IMAGENAME eq asteria-client.exe"],
                    timeout=10,
                )
                return ("asteria-client.exe" in (out or "").lower() or "honeypot-client.exe" in (out or "").lower())
            except Exception as e:
                log(f"Process check error: {e}")
                return False
        except Exception as e:
            log(f"is_app_running error: {e}")
            return False

    @staticmethod
    def is_daemon_running() -> bool:
        """Check if daemon mode is currently running"""
        try:
            import psutil
            current_pid = os.getpid()
            
            # Check for daemon instances of this app
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    if proc.info['pid'] == current_pid:
                        continue  # Skip current process
                    
                    # Check command line for daemon mode
                    if proc.info['cmdline']:
                        cmdline = ' '.join(proc.info['cmdline'])
                        if ('client.py' in cmdline or 'asteria-client' in cmdline.lower() or 'honeypot-client' in cmdline.lower()) and '--mode=daemon' in cmdline:
                            return True
                            
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            return False
            
        except ImportError:
            log("psutil not available, using mutex check for daemon")
            # Check if daemon mutex exists
            try:
                import tempfile
                daemon_mutex_file = os.path.join(tempfile.gettempdir(), "CloudHoneypotClient_daemon.lock")
                return os.path.exists(daemon_mutex_file)
            except Exception as e:
                log(f"Daemon check error: {e}")
                return False
        except Exception as e:
            log(f"is_daemon_running error: {e}")
            return False


# ===================== BOUNDED BACKGROUND TASKS ===================== #
# Prevents thread explosion from fire-and-forget API reports / retries.

_bg_pool = None
_bg_sem = None
_bg_lock = threading.Lock()
_BG_MAX_WORKERS = 8
_BG_MAX_PENDING = 64


def submit_background(fn, *args, **kwargs) -> bool:
    """Run fn in a bounded thread pool. Returns False if queue saturated (task dropped)."""
    import threading as _threading
    from concurrent.futures import ThreadPoolExecutor

    global _bg_pool, _bg_sem
    with _bg_lock:
        if _bg_pool is None:
            _bg_pool = ThreadPoolExecutor(
                max_workers=_BG_MAX_WORKERS, thread_name_prefix="HP-BG"
            )
            _bg_sem = _threading.Semaphore(_BG_MAX_PENDING)

    if not _bg_sem.acquire(blocking=False):
        try:
            log("[BG] background queue full — dropping task")
        except Exception:
            pass
        return False

    def _wrap():
        try:
            fn(*args, **kwargs)
        except Exception as e:
            try:
                log(f"[BG] background task error: {e}")
            except Exception:
                pass
        finally:
            _bg_sem.release()

    try:
        _bg_pool.submit(_wrap)
        return True
    except Exception:
        _bg_sem.release()
        return False
