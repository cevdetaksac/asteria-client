"""Asteria interactive GUI host.

Separate from the SYSTEM motor. Exposes an allowlisted bridge so the React
Control Center can read status and request elevated actions via :58632 without
embedding agent secrets in WebView JavaScript.
"""

from __future__ import annotations

import json
import logging
import os
import socket
import sys
import threading
import time
import webbrowser
from pathlib import Path
from typing import Any, Dict, Optional

try:
    import webview
except ImportError:  # unit tests / headless without pywebview
    webview = None  # type: ignore

from client_daemon_ipc import (
    block_ip,
    clear_firewall,
    get_status,
    honeypot_list,
    honeypot_start,
    honeypot_stop,
    ip_table,
    network_accept_surface,
    network_maintenance_end,
    network_maintenance_start,
    network_snapshot,
    ping,
    ransomware_status,
    ransomware_unlock,
    threat_top,
    unblock_ip,
)

_MUTEX_NAME = "Local\\AsteriaGuiWebView"
_SHOW_EVENT_NAME = "Local\\AsteriaGuiWebViewShow"
_kernel_handles: list[int] = []
_quitting = False
_tray_state: Dict[str, Any] = {
    "icon": None,
    "thread": None,
    "stop": False,
    "window": None,
    "bridge": None,
    "logger": None,
}
_hide_lock = threading.Lock()
_hide_pending = False

# Explicit IPC ops the WebView may request (maps to client_daemon_ipc helpers).
_IPC_ALLOWLIST = frozenset(
    {
        "STATUS",
        "THREAT_TOP",
        "IP_TABLE",
        "CLEAR_FIREWALL",
        "BLOCK_IP",
        "UNBLOCK_IP",
        "RS_STATUS",
        "RS_UNLOCK",
        "NG_MAINT_START",
        "NG_MAINT_END",
        "NG_MAINT_END_SNAPSHOT",
        "NG_SNAPSHOT",
        "NG_ACCEPT_SURFACE",
        "HONEYPOT_LIST",
        "HONEYPOT_START",
        "HONEYPOT_STOP",
    }
)

_CLOUD_ALLOWLIST = frozenset(
    {
        ("GET", "threats/config"),
        ("POST", "threats/config"),
    }
)

_SHELL_ALLOWLIST = frozenset(
    {
        "open_dashboard",
        "open_servers",
        "open_website",
        "open_github",
        "copy_token",
        "open_logs",
        "check_updates",
        "about",
        "minimize",
        "quit",
    }
)

# Deep-link targets for settings help links (allowlisted only — no free-form URLs).
_DASHBOARD_OPEN_TARGETS = {
    "": "https://asteria.run/dashboard",
    "dashboard": "https://asteria.run/dashboard",
    "alerts": "https://asteria.run/dashboard?view=alerts",
    "blocking": "https://asteria.run/dashboard?view=blocking",
    "webhooks": "https://asteria.run/dashboard?view=webhooks",
    "settings": "https://asteria.run/dashboard?view=settings",
}

_ACCOUNT_ACTIONS = frozenset({"status", "link", "unlink"})
_HARDEN_FIX_TARGETS = frozenset({"winrm", "nla", "antivirus"})
_RDP_MOVE_MODES = frozenset({"secure", "rollback"})
_RDP_ACTIONS = frozenset({"status", "move", "begin", "confirm", "cancel"})
_RDP_CONFIRM_SECONDS = 60
_IR_ACTIONS = frozenset({"list", "logoff", "disable", "enable", "reset_password"})
_UPDATE_ACTIONS = frozenset({"status", "dismiss"})
_I18N_LANGS = frozenset({"tr", "en"})


def _acquire_single_instance() -> bool:
    """One GUI per interactive session; second launch pulses the show event."""
    if os.name != "nt":
        return True
    import ctypes

    kernel32 = ctypes.windll.kernel32
    mutex = kernel32.CreateMutexW(None, False, _MUTEX_NAME)
    if not mutex:
        return True
    _kernel_handles.append(mutex)
    if kernel32.GetLastError() != 183:  # ERROR_ALREADY_EXISTS
        return True

    event = kernel32.OpenEventW(0x0002, False, _SHOW_EVENT_NAME)
    if event:
        kernel32.SetEvent(event)
        kernel32.CloseHandle(event)
    return False


def _pulse_session_gate(window: Any) -> None:
    """Tell the WebView to re-read session() (e.g. after tray hide re-locks PIN)."""
    try:
        window.evaluate_js(
            "try{window.dispatchEvent(new CustomEvent('asteria-session-gate'))}catch(e){}"
        )
    except Exception:
        pass


def _schedule_webview(fn, *, delay: float = 0.0) -> None:
    """Run WebView ops off the pystray / closing callback thread.

    Hiding inside events.closing (or blocking show from tray) can hang Win32
    message dispatch — icon stays visible but clicks/menus die (pywebview bug).
    """

    def _run() -> None:
        if delay > 0:
            time.sleep(delay)
        try:
            fn()
        except Exception:
            pass

    threading.Thread(target=_run, name="AsteriaGuiUiOp", daemon=True).start()


def _hide_to_tray(window: Any, bridge: Optional["MotorBridge"] = None) -> None:
    """Async hide + re-lock PIN (safe from closing callback / shell minimize)."""
    global _hide_pending
    with _hide_lock:
        if _hide_pending or _quitting:
            return
        _hide_pending = True

    def _do() -> None:
        global _hide_pending
        try:
            try:
                window.hide()
            except Exception:
                pass
            try:
                lock = getattr(bridge, "_gui_lock", None) if bridge is not None else None
                if lock is not None:
                    lock.lock_session()
            except Exception:
                pass
            _pulse_session_gate(window)
        finally:
            with _hide_lock:
                _hide_pending = False

    # Small delay so closing callback can return False before hide().
    _schedule_webview(_do, delay=0.05)


def _show_from_tray(window: Any) -> None:
    def _do() -> None:
        try:
            window.show()
            window.restore()
            _pulse_session_gate(window)
        except Exception:
            pass

    _schedule_webview(_do)


def _start_show_watcher(window: Any) -> None:
    if os.name != "nt":
        return
    import ctypes

    kernel32 = ctypes.windll.kernel32
    event = kernel32.CreateEventW(None, False, False, _SHOW_EVENT_NAME)
    if not event:
        return
    _kernel_handles.append(event)

    def _watch() -> None:
        while True:
            if kernel32.WaitForSingleObject(event, 0xFFFFFFFF) != 0:
                return
            if _quitting:
                return
            _ensure_tray_alive()
            _show_from_tray(window)

    threading.Thread(
        target=_watch, name="AsteriaGuiShow", daemon=True
    ).start()


def _load_tray_image(status: str = "online"):
    """Load branded tray icon from logo_set / certs (status: online|offline|disabled|stay)."""
    from PIL import Image, ImageDraw

    key = (status or "online").strip().lower()
    if key not in ("online", "offline", "disabled", "stay"):
        key = "online"
    candidates = [
        _resource_path("certs", f"asteria_{key}_64.png"),
        _resource_path("logo_set", f"icon_{key}.png"),
        _resource_path("certs", f"asteria_{key}_64.ico"),
        Path(__file__).resolve().parent / "certs" / f"asteria_{key}_64.png",
        Path(__file__).resolve().parent / "logo_set" / f"icon_{key}.png",
        _resource_path("logo_set", "favicon_light.png"),
    ]
    for path in candidates:
        try:
            if path.is_file():
                img = Image.open(path).convert("RGBA")
                return img.resize((64, 64), Image.Resampling.LANCZOS)
        except Exception:
            continue
    image = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    draw.ellipse((5, 5, 59, 59), fill=(8, 13, 20, 255), outline=(46, 168, 209, 255), width=4)
    return image


def _run_tray_icon_once(window: Any, bridge: "MotorBridge", logger: logging.Logger):
    """Create one pystray Icon and block until stop/crash (supervised by _tray_loop)."""
    import pystray

    image = _load_tray_image("online")

    def show_gui(_icon=None, _item=None):
        _show_from_tray(window)

    def open_dashboard(_icon=None, _item=None):
        try:
            bridge.shell("open_dashboard")
        except Exception as exc:
            logger.info("Tray dashboard failed: %s", exc)

    def copy_token(_icon=None, _item=None):
        try:
            bridge.shell("copy_token")
        except Exception as exc:
            logger.info("Tray copy token failed: %s", exc)

    def quit_gui(icon=None, _item=None):
        global _quitting
        _quitting = True
        _tray_state["stop"] = True
        try:
            if icon:
                icon.stop()
        except Exception:
            pass
        def _destroy():
            try:
                window.destroy()
            except Exception:
                pass
        _schedule_webview(_destroy)

    icon = pystray.Icon(
        "asteria-gui",
        image,
        "Asteria",
        menu=pystray.Menu(
            pystray.MenuItem("Asteria'yı Aç", show_gui, default=True),
            pystray.MenuItem("Dashboard", open_dashboard),
            pystray.MenuItem("Token Kopyala", copy_token),
            pystray.MenuItem("Arayüzden Çık", quit_gui),
        ),
    )
    _tray_state["icon"] = icon
    try:
        icon.run()  # blocking — owns Win32 message pump for this icon
    finally:
        if _tray_state.get("icon") is icon:
            _tray_state["icon"] = None


def _tray_loop(window: Any, bridge: "MotorBridge", logger: logging.Logger) -> None:
    """Supervised tray loop — recreate icon after crash / explorer TaskbarCreated."""
    while not _tray_state.get("stop") and not _quitting:
        try:
            _run_tray_icon_once(window, bridge, logger)
        except Exception as exc:
            logger.info("Tray icon loop error: %s", exc)
        _tray_state["icon"] = None
        if _tray_state.get("stop") or _quitting:
            break
        logger.info("Tray icon ended — restarting in 1.5s")
        time.sleep(1.5)


def _ensure_tray_alive() -> bool:
    """Restart supervised tray thread if it died while GUI process still runs."""
    if _quitting or _tray_state.get("stop"):
        return False
    thread = _tray_state.get("thread")
    window = _tray_state.get("window")
    bridge = _tray_state.get("bridge")
    logger = _tray_state.get("logger")
    if thread is not None and thread.is_alive():
        icon = _tray_state.get("icon")
        if icon is not None:
            try:
                icon.visible = True
            except Exception:
                pass
        return True
    if window is None or bridge is None or logger is None:
        return False
    logger.info("Tray thread dead while GUI alive — restarting")
    t = threading.Thread(
        target=_tray_loop,
        args=(window, bridge, logger),
        name="AsteriaGuiTray",
        daemon=True,
    )
    _tray_state["thread"] = t
    t.start()
    return True


def _start_tray(window: Any, bridge: "MotorBridge", logger: logging.Logger):
    """Own the interactive tray outside the SYSTEM motor (supervised + revive)."""
    _tray_state["stop"] = False
    _tray_state["window"] = window
    _tray_state["bridge"] = bridge
    _tray_state["logger"] = logger

    t = threading.Thread(
        target=_tray_loop,
        args=(window, bridge, logger),
        name="AsteriaGuiTray",
        daemon=True,
    )
    _tray_state["thread"] = t
    t.start()

    def _sync_tray_status() -> None:
        while not _quitting and not _tray_state.get("stop"):
            try:
                time.sleep(8)
                if _quitting or _tray_state.get("stop"):
                    return
                _ensure_tray_alive()
                icon = _tray_state.get("icon")
                if icon is None:
                    continue
                pong = bridge.ping()
                next_key = "online" if pong.get("ok") else "offline"
                icon.icon = _load_tray_image(next_key)
            except Exception:
                try:
                    time.sleep(8)
                except Exception:
                    return

    threading.Thread(target=_sync_tray_status, name="AsteriaTrayStatus", daemon=True).start()
    return _tray_state


def _resource_path(*parts: str) -> Path:
    root = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
    return root.joinpath(*parts)


def _setup_logging() -> logging.Logger:
    log_dir = Path(
        os.environ.get("LOCALAPPDATA", os.environ.get("TEMP", "."))
    ) / "Asteria" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("asteria-gui")
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        handler = logging.FileHandler(
            log_dir / "asteria-gui.log", encoding="utf-8"
        )
        handler.setFormatter(
            logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
        )
        logger.addHandler(handler)
    return logger


def _json_safe(payload: Any) -> Any:
    return json.loads(json.dumps(payload, default=str))


def _clipboard_set(text: str) -> bool:
    if os.name != "nt":
        return False
    try:
        import ctypes

        CF_UNICODETEXT = 13
        GMEM_MOVEABLE = 0x0002
        user32 = ctypes.windll.user32
        kernel32 = ctypes.windll.kernel32
        if not user32.OpenClipboard(None):
            return False
        try:
            user32.EmptyClipboard()
            data = (text or "").encode("utf-16-le") + b"\x00\x00"
            handle = kernel32.GlobalAlloc(GMEM_MOVEABLE, len(data))
            if not handle:
                return False
            locked = kernel32.GlobalLock(handle)
            ctypes.memmove(locked, data, len(data))
            kernel32.GlobalUnlock(handle)
            user32.SetClipboardData(CF_UNICODETEXT, handle)
            return True
        finally:
            user32.CloseClipboard()
    except Exception:
        return False


class MotorBridge:
    """WebView API — keep the allowlist explicit and secrets host-side."""

    def __init__(
        self,
        logger: logging.Logger | None = None,
        window: Any | None = None,
    ) -> None:
        self.log = logger or logging.getLogger("asteria-gui")
        self._window = window
        os.environ["ASTERIA_GUI_HOST"] = "1"
        from client_gui_lock import GuiLock

        self._gui_lock = GuiLock.instance()

    def bind_window(self, window: Any) -> None:
        self._window = window

    def _agent_identity(self) -> Dict[str, Any]:
        """Safe agent identity for the top bar — never the full token (prefix only)."""
        server_name = ""
        try:
            from client_constants import SERVER_NAME

            server_name = str(SERVER_NAME or "")
        except Exception:
            try:
                server_name = socket.gethostname()
            except Exception:
                server_name = ""
        token = ""
        try:
            token = self._load_token() or ""
        except Exception:
            token = ""
        preview = ""
        if token:
            preview = token[:16] + ("…" if len(token) > 16 else "")
        client_id = ""
        try:
            from client_utils import load_account_link_pref

            pref = load_account_link_pref() or {}
            cid = pref.get("client_id")
            if cid is not None and str(cid).strip():
                client_id = str(cid).strip()
        except Exception:
            pass
        return {
            "server_name": server_name,
            "token_present": bool(token),
            "token_preview": preview,
            "client_id": client_id,
        }

    def session(self) -> Dict[str, Any]:
        """Session gate — readable while locked (includes account link for PIN recovery hint)."""
        has_pin = self._gui_lock.has_pin()
        linked = False
        email = ""
        try:
            from client_utils import get_linked_account_email, is_account_linked

            linked = bool(is_account_linked())
            email = get_linked_account_email() or ""
        except Exception:
            pass
        identity = self._agent_identity()
        return {
            "ok": True,
            "locked": bool(has_pin and not self._gui_lock.is_session_unlocked()),
            "pin_enabled": has_pin,
            "account_linked": linked,
            "account_email": email,
            "server_name": identity.get("server_name") or "",
            "token_present": bool(identity.get("token_present")),
            "token_preview": identity.get("token_preview") or "",
            "client_id": identity.get("client_id") or "",
        }

    def unlock(self, pin: str) -> Dict[str, Any]:
        ok, reason = self._gui_lock.verify_pin(
            str(pin or ""), unlock_on_success=True
        )
        self.log.info("GUI unlock: ok=%s reason=%s", ok, reason)
        return {
            "ok": ok,
            "reason": reason,
            "lockout_seconds": round(self._gui_lock.lockout_remaining()),
        }

    def _authorized(self) -> bool:
        return not self._gui_lock.has_pin() or self._gui_lock.is_session_unlocked()

    def _deny_locked(self) -> Dict[str, Any]:
        return {"ok": False, "error": "gui_locked"}

    def ping(self) -> Dict[str, Any]:
        healthy = ping(timeout=1.5)
        return {"ok": healthy, "motor": "online" if healthy else "offline"}

    def status(self) -> Dict[str, Any]:
        if not self._authorized():
            return self._deny_locked()
        result = get_status(timeout=3.0)
        safe = _json_safe(result)
        self.log.info("STATUS bridge: ok=%s", bool(safe.get("ok")))
        return safe

    def catalog(self) -> Dict[str, Any]:
        """Honeypot service catalog (ports/names) — no secrets."""
        if not self._authorized():
            return self._deny_locked()
        try:
            from client_utils import get_port_table, get_rdp_secure_port

            rows = []
            for entry in get_port_table() or []:
                if not entry:
                    continue
                if len(entry) >= 3:
                    port, _mid, service = entry[0], entry[1], entry[2]
                elif len(entry) == 2:
                    port, service = entry[0], entry[1]
                else:
                    continue
                rows.append(
                    {
                        "port": str(port),
                        "service": str(service).upper(),
                    }
                )
            return {
                "ok": True,
                "services": rows,
                "rdp_secure_port": int(get_rdp_secure_port()),
            }
        except Exception as exc:
            return {"ok": False, "error": str(exc), "services": []}

    def ipc(self, cmd: str, args: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if not self._authorized():
            return self._deny_locked()
        name = str(cmd or "").strip().upper().replace(" ", "_")
        if name not in _IPC_ALLOWLIST:
            return {"ok": False, "error": "ipc_denied", "cmd": name}
        payload = self._normalize_args(args)
        try:
            result = self._dispatch_ipc(name, payload)
            self.log.info("IPC %s -> ok=%s", name, bool((result or {}).get("ok", True)))
        except Exception as exc:
            self.log.info("IPC %s failed: %s", name, exc)
            return {"ok": False, "error": str(exc), "cmd": name}
        return _json_safe(result)

    @staticmethod
    def _normalize_args(args: Any) -> Dict[str, Any]:
        if args is None:
            return {}
        if isinstance(args, dict):
            return args
        if isinstance(args, str):
            try:
                parsed = json.loads(args)
                return parsed if isinstance(parsed, dict) else {}
            except Exception:
                return {}
        return {}

    def _dispatch_ipc(self, name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        if name == "STATUS":
            return get_status(timeout=3.0)
        if name == "THREAT_TOP":
            return threat_top(timeout=4.0)
        if name == "IP_TABLE":
            return ip_table(timeout=6.0)
        if name == "CLEAR_FIREWALL":
            return clear_firewall(timeout=180.0)
        if name == "BLOCK_IP":
            return block_ip(str(args.get("ip") or ""), str(args.get("reason") or "gui"))
        if name == "UNBLOCK_IP":
            return unblock_ip(str(args.get("ip") or ""))
        if name == "RS_STATUS":
            return ransomware_status(timeout=8.0)
        if name == "RS_UNLOCK":
            return ransomware_unlock(timeout=20.0)
        if name == "NG_MAINT_START":
            return network_maintenance_start()
        if name == "NG_MAINT_END":
            return network_maintenance_end(snapshot=False)
        if name == "NG_MAINT_END_SNAPSHOT":
            return network_maintenance_end(snapshot=True)
        if name == "NG_SNAPSHOT":
            return network_snapshot()
        if name == "NG_ACCEPT_SURFACE":
            return network_accept_surface()
        if name == "HONEYPOT_LIST":
            return honeypot_list()
        if name == "HONEYPOT_START":
            return honeypot_start(
                str(args.get("service") or ""),
                int(args.get("port") or 0),
            )
        if name == "HONEYPOT_STOP":
            return honeypot_stop(str(args.get("service") or ""))
        return {"ok": False, "error": "ipc_unhandled", "cmd": name}

    def cloud(
        self,
        method: str,
        path: str,
        body: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Host-held token proxy for allowlisted cloud paths."""
        if not self._authorized():
            return self._deny_locked()
        m = str(method or "GET").upper().strip()
        p = str(path or "").strip().lstrip("/")
        if (m, p) not in _CLOUD_ALLOWLIST:
            return {"ok": False, "error": "cloud_denied", "path": p}
        token = self._load_token()
        if not token:
            return {"ok": False, "error": "token_missing"}
        try:
            from client_api import AsteriaAPIClient
            from client_constants import API_URL

            client = AsteriaAPIClient(API_URL, log_func=self.log.info)
            patch = self._normalize_args(body)
            if m == "GET" and p == "threats/config":
                data = client.fetch_threat_config(token)
            elif m == "POST" and p == "threats/config":
                data = client.update_threat_config(token, patch)
            else:
                return {"ok": False, "error": "cloud_unhandled"}
            if data is None:
                return {"ok": False, "error": "cloud_empty"}
            self.log.info("cloud %s %s -> ok", m, p)
            return _json_safe({"ok": True, "data": data})
        except Exception as exc:
            self.log.info("cloud %s %s failed: %s", m, p, exc)
            return {"ok": False, "error": str(exc)}

    def account(
        self,
        action: str = "status",
        email: str = "",
        password: str = "",
        pin: str = "",
    ) -> Dict[str, Any]:
        """In-app Account link/unlink with fresh local PIN confirmation."""
        if not self._authorized():
            return self._deny_locked()
        act = str(action or "status").strip().lower()
        if act not in _ACCOUNT_ACTIONS:
            return {"ok": False, "error": "account_unknown_action"}
        try:
            from client_utils import get_linked_account_email, is_account_linked

            if act == "status":
                return {
                    "ok": True,
                    "linked": bool(is_account_linked()),
                    "email": get_linked_account_email() or "",
                }
            # A currently unlocked session is not sufficient for account ownership
            # changes. Require the local PIN again and do not extend the session.
            if not self._gui_lock.has_pin():
                return {"ok": False, "error": "pin_required"}
            ok_pin, pin_reason = self._gui_lock.verify_pin(
                str(pin or ""), unlock_on_success=False
            )
            if not ok_pin:
                return {
                    "ok": False,
                    "error": "pin_verification_failed",
                    "reason": pin_reason,
                    "lockout_seconds": round(self._gui_lock.lockout_remaining()),
                }
            token = self._load_token()
            if not token:
                return {"ok": False, "error": "token_missing"}
            if act == "link":
                from client_api import link_account_with_credentials

                result = link_account_with_credentials(
                    str(email or ""),
                    str(password or ""),
                    token,
                    log_func=self.log.info,
                )
                return _json_safe({"ok": bool(result.get("ok")), **result})
            from client_api import unlink_account_with_credentials

            result = unlink_account_with_credentials(
                str(email or ""),
                str(password or ""),
                token,
                log_func=self.log.info,
            )
            return _json_safe({"ok": bool(result.get("ok")), **result})
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def harden(self, action: str = "status", target: str = "") -> Dict[str, Any]:
        """WinRM / NLA / Defender overview + fix actions (old CTk parity)."""
        if not self._authorized():
            return self._deny_locked()
        act = str(action or "status").strip().lower()
        if act == "status":
            return _json_safe({"ok": True, "checks": self._harden_checks()})
        if act == "fix":
            tgt = str(target or "").strip().lower()
            if tgt not in _HARDEN_FIX_TARGETS:
                return {"ok": False, "error": "harden_unknown_target"}
            return _json_safe(self._harden_fix(tgt))
        return {"ok": False, "error": "harden_unknown_action"}

    def rdp(self, action: str = "status", mode: str = "") -> Dict[str, Any]:
        """RDP port protection: status / begin (60s confirm) / confirm / cancel / move."""
        if not self._authorized():
            return self._deny_locked()
        act = str(action or "status").strip().lower()
        if act not in _RDP_ACTIONS:
            return {"ok": False, "error": "rdp_unknown_action"}
        try:
            from client_constants import RDP_SECURE_PORT
            from client_utils import ServiceController, is_admin

            # Expire pending before answering status
            if act in ("status", "begin", "confirm", "cancel", "move"):
                self._rdp_expire_pending_if_needed()

            current = ServiceController.get_rdp_port() or 3389
            protected = int(current) == int(RDP_SECURE_PORT)
            pending = self._rdp_load_pending()
            seconds_left = 0
            if pending:
                try:
                    seconds_left = max(
                        0, int(float(pending.get("deadline") or 0) - time.time())
                    )
                except Exception:
                    seconds_left = 0

            if act == "status":
                return {
                    "ok": True,
                    "protected": protected,
                    "current_port": int(current),
                    "secure_port": int(RDP_SECURE_PORT),
                    "standard_port": 3389,
                    "admin": bool(is_admin()),
                    "confirm_seconds": _RDP_CONFIRM_SECONDS,
                    "pending": bool(pending),
                    "pending_mode": (pending or {}).get("mode"),
                    "pending_from": (pending or {}).get("from_port"),
                    "pending_to": (pending or {}).get("to_port"),
                    "seconds_left": seconds_left,
                }

            if act == "confirm":
                if not pending:
                    return {"ok": False, "error": "rdp_no_pending"}
                self._rdp_clear_pending()
                final = ServiceController.get_rdp_port() or current
                return {
                    "ok": True,
                    "confirmed": True,
                    "protected": int(final) == int(RDP_SECURE_PORT),
                    "current_port": int(final),
                    "secure_port": int(RDP_SECURE_PORT),
                }

            if act == "cancel":
                # Explicit abort: roll back to from_port if still pending
                if not pending:
                    return {"ok": False, "error": "rdp_no_pending"}
                revert_mode = (
                    "rollback" if str(pending.get("mode")) == "secure" else "secure"
                )
                # Prefer restoring exact from_port
                ok = self._rdp_transition(revert_mode)
                self._rdp_clear_pending()
                final = ServiceController.get_rdp_port() or current
                return {
                    "ok": bool(ok),
                    "cancelled": True,
                    "protected": int(final) == int(RDP_SECURE_PORT),
                    "current_port": int(final),
                    "secure_port": int(RDP_SECURE_PORT),
                }

            # begin or legacy move
            if act in ("begin", "move"):
                if pending:
                    return {
                        "ok": False,
                        "error": "rdp_already_pending",
                        "seconds_left": seconds_left,
                        "pending_to": pending.get("to_port"),
                    }
                mv = str(mode or "").strip().lower()
                if not mv:
                    mv = "rollback" if protected else "secure"
                if mv not in _RDP_MOVE_MODES:
                    return {"ok": False, "error": "rdp_unknown_mode"}
                if not is_admin():
                    return {
                        "ok": False,
                        "error": "admin_required",
                        "detail": "RDP taşıma için yükseltilmiş süreç gerekir",
                    }
                from_port = int(current)
                to_port = int(RDP_SECURE_PORT) if mv == "secure" else 3389
                ok = self._rdp_transition(mv)
                if not ok:
                    return {
                        "ok": False,
                        "error": "rdp_transition_failed",
                        "current_port": int(ServiceController.get_rdp_port() or current),
                    }
                if act == "begin":
                    self._rdp_save_pending(
                        {
                            "mode": mv,
                            "from_port": from_port,
                            "to_port": to_port,
                            "deadline": time.time() + _RDP_CONFIRM_SECONDS,
                            "started_at": time.time(),
                        }
                    )
                    self._rdp_arm_expire_timer()
                final = ServiceController.get_rdp_port() or to_port
                return {
                    "ok": True,
                    "mode": mv,
                    "pending": act == "begin",
                    "protected": int(final) == int(RDP_SECURE_PORT),
                    "current_port": int(final),
                    "secure_port": int(RDP_SECURE_PORT),
                    "from_port": from_port,
                    "to_port": to_port,
                    "seconds_left": _RDP_CONFIRM_SECONDS if act == "begin" else 0,
                    "confirm_seconds": _RDP_CONFIRM_SECONDS,
                }

            return {"ok": False, "error": "rdp_unknown_action"}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def _rdp_pending_path(self) -> Path:
        from client_utils import _programdata_client_dir

        return Path(_programdata_client_dir()) / "rdp_secure_move.json"

    def _rdp_load_pending(self) -> Optional[Dict[str, Any]]:
        try:
            path = self._rdp_pending_path()
            if not path.is_file():
                return None
            data = json.loads(path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) and data.get("mode") else None
        except Exception:
            return None

    def _rdp_save_pending(self, payload: Dict[str, Any]) -> None:
        try:
            path = self._rdp_pending_path()
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        except Exception as exc:
            self.log.info("rdp pending save failed: %s", exc)

    def _rdp_clear_pending(self) -> None:
        try:
            path = self._rdp_pending_path()
            if path.is_file():
                path.unlink()
        except Exception:
            pass

    def _rdp_expire_pending_if_needed(self) -> bool:
        """If confirm window elapsed, auto-revert port. Returns True if expired."""
        pending = self._rdp_load_pending()
        if not pending:
            return False
        try:
            deadline = float(pending.get("deadline") or 0)
        except Exception:
            deadline = 0
        if deadline and time.time() < deadline:
            return False
        mode = str(pending.get("mode") or "secure")
        revert = "rollback" if mode == "secure" else "secure"
        self.log.info("RDP secure-move confirm expired — reverting (%s)", revert)
        try:
            self._rdp_transition(revert)
        except Exception as exc:
            self.log.info("RDP auto-revert failed: %s", exc)
        self._rdp_clear_pending()
        return True

    def _rdp_arm_expire_timer(self) -> None:
        """Daemon timer so rollback happens even if UI disconnects."""

        def _watch() -> None:
            try:
                pending = self._rdp_load_pending()
                if not pending:
                    return
                deadline = float(pending.get("deadline") or 0)
                delay = max(1.0, deadline - time.time() + 0.5)
                time.sleep(delay)
                self._rdp_expire_pending_if_needed()
            except Exception:
                pass

        threading.Thread(
            target=_watch, name="AsteriaRdpConfirm", daemon=True
        ).start()

    def ir(
        self,
        action: str,
        username: str = "",
        new_password: str = "",
    ) -> Dict[str, Any]:
        """Incident response: list local users / logoff / enable / disable / reset password."""
        if not self._authorized():
            return self._deny_locked()
        act = str(action or "").strip().lower()
        user = str(username or "").strip()
        if act not in _IR_ACTIONS:
            return {"ok": False, "error": "ir_unknown_action"}

        if act == "list":
            return self._ir_list_users()

        if not user:
            return {"ok": False, "error": "username_required"}

        # Never let the interactive operator disable/logoff themselves.
        if act in ("logoff", "disable") and self._is_self_account(user):
            return {
                "ok": False,
                "error": "self_account",
                "detail": "Cannot logoff/disable the signed-in operator account",
                "username": user,
            }

        try:
            from client_auto_response import AutoResponse
            from client_winproc import run_hidden

            ar = AutoResponse()
            ar.alert_pipeline = None
            if act == "logoff":
                ok = bool(ar.logoff_user(user))
                return {"ok": ok, "action": "logoff", "username": user}
            if act == "enable":
                ok = bool(ar.enable_account(user))
                return {"ok": ok, "action": "enable", "username": user}
            if act == "disable":
                ok = bool(ar.disable_account(user, allow_privileged=True))
                err = getattr(ar, "_last_disable_error", None)
                out: Dict[str, Any] = {
                    "ok": ok,
                    "action": "disable",
                    "username": user,
                }
                if not ok and err:
                    out["error"] = err
                return out
            if act == "reset_password":
                pw = str(new_password or "")
                if len(pw) < 8:
                    return {
                        "ok": False,
                        "error": "password_too_short",
                        "username": user,
                    }
                rc, _out, err = run_hidden(["net", "user", user, pw], timeout=12)
                ok = rc == 0
                return {
                    "ok": ok,
                    "action": "reset_password",
                    "username": user,
                    "error": None if ok else (err or "password_reset_failed"),
                }
            return {"ok": False, "error": "ir_unknown_action"}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def _ir_current_username(self) -> str:
        try:
            import getpass

            return (getpass.getuser() or "").strip()
        except Exception:
            return (os.environ.get("USERNAME") or "").strip()

    def _is_self_account(self, username: str) -> bool:
        want = (username or "").strip().lower()
        if not want:
            return False
        me = self._ir_current_username().lower()
        if me and want == me:
            return True
        # DOMAIN\user → compare short SAM
        if "\\" in want:
            want = want.rsplit("\\", 1)[-1]
        if me and "\\" in me:
            me = me.rsplit("\\", 1)[-1]
        return bool(me) and want == me

    def _ir_list_users(self) -> Dict[str, Any]:
        try:
            from client_remote_session import list_local_users

            rows = list_local_users(include_disabled=True)
            me = self._ir_current_username()
            me_l = me.lower()
            users = []
            for u in rows or []:
                if not isinstance(u, dict):
                    continue
                name = str(u.get("username") or "").strip()
                if not name:
                    continue
                is_self = bool(me_l) and name.lower() == me_l
                enabled = bool(u.get("enabled"))
                protected = bool(u.get("protected"))
                can_disable = bool(u.get("can_disable")) and (not is_self)
                can_logoff = bool(u.get("has_session")) and (not is_self)
                can_enable = bool(u.get("can_enable"))
                # Password reset OK for operator (including self); refuse OS protected accounts
                can_reset = not protected
                users.append({
                    "username": name,
                    "full_name": u.get("full_name") or "",
                    "enabled": enabled,
                    "status": u.get("status") or ("active" if enabled else "disabled"),
                    "protected": protected,
                    "is_admin": bool(u.get("is_admin")),
                    "is_self": is_self,
                    "groups": u.get("groups") or [],
                    "last_logon": u.get("last_logon"),
                    "has_session": bool(u.get("has_session")),
                    "session_status": u.get("session_status"),
                    "can_enable": can_enable,
                    "can_disable": can_disable,
                    "can_logoff": can_logoff,
                    "can_reset_password": can_reset,
                })
            active = sum(1 for x in users if x.get("enabled"))
            return {
                "ok": True,
                "action": "list",
                "users": users,
                "counts": {
                    "total": len(users),
                    "active": active,
                    "disabled": len(users) - active,
                },
                "current_user": me,
            }
        except Exception as exc:
            return {"ok": False, "error": str(exc), "users": []}

    def update_banner(self, action: str = "status") -> Dict[str, Any]:
        """Cross-process update UI status (ProgramData update_ui_status.json)."""
        if not self._authorized():
            return self._deny_locked()
        act = str(action or "status").strip().lower()
        if act not in _UPDATE_ACTIONS:
            return {"ok": False, "error": "update_unknown_action"}
        try:
            from client_constants import VERSION
            from client_update_ui import clear_update_ui_status, get_update_ui_status

            if act == "dismiss":
                clear_update_ui_status()
                return {"ok": True, "dismissed": True}
            st = get_update_ui_status(current_version=VERSION)
            return {"ok": True, "status": st, "current_version": VERSION}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def i18n(self, lang: str = "") -> Dict[str, Any]:
        """Get or set UI language; return flat string table for the active lang."""
        # Language read is allowed while locked so lock screen can localize later.
        try:
            from client_utils import load_i18n, resolve_app_language, update_language_config

            requested = str(lang or "").strip().lower()
            if requested:
                if not self._authorized():
                    return self._deny_locked()
                if requested not in _I18N_LANGS:
                    return {"ok": False, "error": "i18n_unknown_lang"}
                update_language_config(requested, True)
            active = resolve_app_language()
            if active not in _I18N_LANGS:
                active = "tr"
            table = load_i18n(language=active)
            strings = {}
            if isinstance(table, dict):
                strings = table.get(active) or table.get("tr") or table.get("en") or {}
                if not isinstance(strings, dict):
                    strings = {}
            return {
                "ok": True,
                "lang": active,
                "strings": _json_safe(strings),
                "restart_hint": bool(requested),
            }
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def pin(self, action: str, value: str = "", current: str = "") -> Dict[str, Any]:
        act = str(action or "").strip().lower()
        if act == "check":
            return self.session()
        if not self._authorized() and act not in ("check",):
            # Setting a PIN when unlocked-or-no-pin is OK; clearing needs auth.
            if act == "set" and not self._gui_lock.has_pin():
                pass
            elif act == "set" and self._gui_lock.is_session_unlocked():
                pass
            else:
                return self._deny_locked()
        try:
            if act == "set":
                if self._gui_lock.has_pin() and not self._gui_lock.is_session_unlocked():
                    ok_v, reason_v = self._gui_lock.verify_pin(
                        str(current or ""), unlock_on_success=True
                    )
                    if not ok_v:
                        return {"ok": False, "reason": reason_v}
                ok, reason = self._gui_lock.set_pin(str(value or ""), source="webview")
                return {"ok": ok, "reason": reason}
            if act == "clear":
                ok, reason = self._gui_lock.clear_pin(str(current or value or ""))
                return {"ok": ok, "reason": reason}
            return {"ok": False, "error": "pin_unknown_action"}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def shell(self, action: str, path: str = "") -> Dict[str, Any]:
        act = str(action or "").strip().lower()
        if act not in _SHELL_ALLOWLIST:
            return {"ok": False, "error": "shell_denied"}
        # Most open_* / about / check_updates do not require PIN (tray parity).
        try:
            if act == "open_dashboard":
                target_key = str(path or "").strip().lower()
                url = _DASHBOARD_OPEN_TARGETS.get(target_key)
                if url is None:
                    return {"ok": False, "error": "dashboard_path_denied"}
                webbrowser.open(url)
                return {"ok": True, "url": url}
            if act == "open_website":
                webbrowser.open("https://asteria.run")
                return {"ok": True}
            if act == "open_servers":
                webbrowser.open("https://asteria.run/servers")
                return {"ok": True}
            if act == "open_github":
                from client_constants import GITHUB_OWNER, GITHUB_REPO

                webbrowser.open(f"https://github.com/{GITHUB_OWNER}/{GITHUB_REPO}")
                return {"ok": True}
            if act == "copy_token":
                if not self._authorized():
                    return self._deny_locked()
                token = self._load_token() or ""
                copied = bool(token) and _clipboard_set(token)
                return {"ok": copied, "copied": copied, "empty": not bool(token)}
            if act == "open_logs":
                log_path = self._resolve_log_path()
                if log_path.is_file():
                    os.startfile(str(log_path))  # noqa: S606 — local log open
                    return {"ok": True, "path": str(log_path)}
                return {"ok": False, "error": "log_missing"}
            if act == "about":
                from client_constants import GITHUB_OWNER, GITHUB_REPO, VERSION

                log_path = self._resolve_log_path()
                return {
                    "ok": True,
                    "version": VERSION,
                    "website": "https://asteria.run",
                    "github": f"https://github.com/{GITHUB_OWNER}/{GITHUB_REPO}",
                    "log_path": str(log_path) if log_path else "",
                }
            if act == "check_updates":
                if not self._authorized():
                    return self._deny_locked()
                from client_updater import check_update_availability

                info = check_update_availability() or {}
                available = bool(info.get("update_available"))
                latest = str(info.get("latest") or "")
                installed = str(info.get("installed") or "")
                download_url = str(info.get("download_url") or "").strip()
                if available and download_url:
                    # Open release/installer URL; motor/updater owns silent apply.
                    try:
                        webbrowser.open(download_url)
                    except Exception:
                        pass
                elif available:
                    from client_constants import GITHUB_OWNER, GITHUB_REPO

                    tag = str(info.get("tag") or (f"v{latest}" if latest else ""))
                    url = (
                        f"https://github.com/{GITHUB_OWNER}/{GITHUB_REPO}/releases/tag/{tag}"
                        if tag
                        else f"https://github.com/{GITHUB_OWNER}/{GITHUB_REPO}/releases/latest"
                    )
                    try:
                        webbrowser.open(url)
                    except Exception:
                        pass
                return {
                    "ok": bool(info.get("ok", True)),
                    "update_available": available,
                    "installed": installed,
                    "latest": latest,
                    "tag": str(info.get("tag") or ""),
                    "download_url": download_url,
                    "message": str(info.get("message") or ""),
                    "error": info.get("error"),
                    "detail": info.get("detail"),
                }
            if act == "minimize":
                if self._window is not None:
                    _hide_to_tray(self._window, self)
                return {"ok": True}
            if act == "quit":
                global _quitting
                _quitting = True
                _tray_state["stop"] = True
                try:
                    icon = _tray_state.get("icon")
                    if icon is not None:
                        icon.stop()
                except Exception:
                    pass
                if self._window is not None:
                    self._window.destroy()
                return {"ok": True}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}
        return {"ok": False, "error": "shell_unhandled"}

    def _resolve_log_path(self) -> Path:
        log_path = (
            Path(os.environ.get("LOCALAPPDATA", ""))
            / "Asteria"
            / "logs"
            / "asteria-gui.log"
        )
        try:
            from client_utils import _programdata_client_dir

            pd = Path(_programdata_client_dir()) / "logs"
            if pd.is_dir():
                candidates = sorted(pd.glob("*.log"), key=lambda p: p.stat().st_mtime)
                if candidates:
                    return candidates[-1]
        except Exception:
            pass
        return log_path

    def _load_token(self) -> Optional[str]:
        """Read durable token without importing TokenManager (pulls client_helpers/Tk)."""
        try:
            from client_utils import TokenStore, _programdata_client_dir

            path = os.path.join(_programdata_client_dir(), "token.dat")
            tok = TokenStore.load(path)
            if tok:
                return tok
            # Legacy plain-text fallback (rare)
            legacy = os.path.join(_programdata_client_dir(), "token.txt")
            if os.path.isfile(legacy):
                with open(legacy, "r", encoding="utf-8") as fh:
                    plain = fh.read().strip()
                return plain or None
            return None
        except Exception as exc:
            self.log.info("token load failed: %s", exc)
            return None

    def _harden_checks(self) -> list:
        from client_winproc import run_hidden, run_ps

        checks: list = []
        try:
            rc, out, _ = run_hidden(
                ["netsh", "advfirewall", "show", "allprofiles", "state"], timeout=5
            )
            fw_on = "ON" in (out or "").upper() if rc == 0 else False
            checks.append(
                {
                    "id": "firewall",
                    "label": "Windows Firewall",
                    "ok": fw_on,
                    "detail": "Aktif" if fw_on else "Kapalı — risk",
                    "fixable": not fw_on,
                }
            )
        except Exception:
            checks.append(
                {"id": "firewall", "label": "Windows Firewall", "ok": None, "detail": "Doğrulanamadı"}
            )
        try:
            rc, out, _ = run_ps(
                "Get-MpComputerStatus | Select-Object -ExpandProperty RealTimeProtectionEnabled",
                timeout=10,
            )
            av_on = "TRUE" in (out or "").upper().strip() if rc == 0 else False
            checks.append(
                {
                    "id": "antivirus",
                    "label": "Windows Defender",
                    "ok": av_on,
                    "detail": "Gerçek zamanlı açık" if av_on else "Kapalı — risk",
                    "fixable": not av_on,
                }
            )
        except Exception:
            checks.append(
                {"id": "antivirus", "label": "Windows Defender", "ok": None, "detail": "Doğrulanamadı"}
            )
        try:
            rc, out, _ = run_hidden(["sc", "query", "WinRM"], timeout=5)
            winrm_running = "RUNNING" in (out or "").upper() if rc == 0 else False
            checks.append(
                {
                    "id": "winrm",
                    "label": "WinRM",
                    "ok": not winrm_running,
                    "detail": "Kapalı (güvenli)" if not winrm_running else "Açık — uzaktan risk",
                    "fixable": winrm_running,
                }
            )
        except Exception:
            checks.append(
                {"id": "winrm", "label": "WinRM", "ok": True, "detail": "Servis yok"}
            )
        try:
            rc, out, _ = run_hidden(
                [
                    "reg",
                    "query",
                    r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
                    "/v",
                    "UserAuthentication",
                ],
                timeout=5,
            )
            nla_on = "0x1" in (out or "") if rc == 0 else False
            checks.append(
                {
                    "id": "nla",
                    "label": "RDP NLA",
                    "ok": nla_on,
                    "detail": "Aktif" if nla_on else "Kapalı — risk",
                    "fixable": not nla_on,
                }
            )
        except Exception:
            checks.append(
                {"id": "nla", "label": "RDP NLA", "ok": None, "detail": "Doğrulanamadı"}
            )
        return checks

    def _harden_fix(self, target: str) -> Dict[str, Any]:
        from client_winproc import run_hidden, run_ps

        try:
            if target == "winrm":
                run_ps(
                    "Stop-Service WinRM -Force; "
                    "Set-Service WinRM -StartupType Disabled; "
                    "Disable-PSRemoting -Force -ErrorAction SilentlyContinue",
                    timeout=15,
                )
                return {"ok": True, "target": target}
            if target == "nla":
                rc, _, err = run_hidden(
                    [
                        "reg",
                        "add",
                        r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
                        "/v",
                        "UserAuthentication",
                        "/t",
                        "REG_DWORD",
                        "/d",
                        "1",
                        "/f",
                    ],
                    timeout=10,
                )
                return {"ok": rc == 0, "target": target, "error": err if rc else None}
            if target == "antivirus":
                rc, _, err = run_ps(
                    "Set-MpPreference -DisableRealtimeMonitoring $false",
                    timeout=15,
                )
                return {"ok": rc == 0, "target": target, "error": err if rc else None}
            return {"ok": False, "error": "harden_unknown_target"}
        except Exception as exc:
            return {"ok": False, "target": target, "error": str(exc)}

    def _rdp_transition(self, mode: str) -> bool:
        """Move RDP port without importing client_rdp (Tk-heavy)."""
        from client_constants import RDP_SECURE_PORT
        from client_utils import ServiceController, is_admin
        from client_winproc import run_hidden

        if not is_admin():
            return False
        target = int(RDP_SECURE_PORT) if mode == "secure" else 3389
        rc, _, _ = run_hidden(
            [
                "reg",
                "add",
                r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
                "/v",
                "PortNumber",
                "/t",
                "REG_DWORD",
                "/d",
                str(target),
                "/f",
            ],
            timeout=10,
        )
        if rc != 0:
            return False
        if mode == "secure":
            try:
                # Best-effort firewall for both classic + secure RDP ports.
                run_hidden(
                    [
                        "netsh",
                        "advfirewall",
                        "firewall",
                        "add",
                        "rule",
                        f"name=Asteria RDP {target}",
                        "dir=in",
                        "action=allow",
                        "protocol=TCP",
                        f"localport={target}",
                    ],
                    timeout=10,
                )
            except Exception:
                pass
        if not ServiceController.restart("TermService", self.log.info):
            return False
        import time

        time.sleep(2.5)
        final = ServiceController.get_rdp_port()
        return int(final or 0) == target


def _webview2_runtime_present() -> bool:
    """Best-effort check for Edge WebView2 Evergreen Runtime (blank white UI without it)."""
    if os.name != "nt":
        return True
    try:
        import winreg

        keys = (
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"),
        )
        for hive, path in keys:
            try:
                with winreg.OpenKey(hive, path) as key:
                    ver, _ = winreg.QueryValueEx(key, "pv")
                    if ver and str(ver) not in ("", "0.0.0.0"):
                        return True
            except OSError:
                continue
    except Exception:
        pass
    return False


def _warn_missing_webview2(logger: logging.Logger) -> None:
    msg = (
        "Microsoft Edge WebView2 Runtime bulunamadı.\n\n"
        "Asteria Control Center boş/beyaz pencere gösterir.\n"
        "https://developer.microsoft.com/microsoft-edge/webview2/ adresinden "
        "Evergreen Runtime kurun, sonra asteria-gui.exe'yi yeniden açın.\n\n"
        "Log: %LOCALAPPDATA%\\Asteria\\logs\\asteria-gui.log"
    )
    logger.error("WebView2 Runtime missing — GUI will be blank")
    try:
        import ctypes

        ctypes.windll.user32.MessageBoxW(0, msg, "Asteria — WebView2 gerekli", 0x10)
    except Exception:
        pass


def main() -> int:
    global _quitting
    logger = _setup_logging()
    if webview is None:
        logger.error("pywebview is not installed")
        return 2
    if not _webview2_runtime_present():
        _warn_missing_webview2(logger)
        return 3
    if not _acquire_single_instance():
        logger.info("Existing GUI signaled; exiting second launch")
        return 0
    index = _resource_path("ui", "index.html")
    if not index.is_file():
        logger.error("UI bundle missing: %s", index)
        raise FileNotFoundError(f"Asteria UI bundle missing: {index}")

    logger.info("Starting asteria-gui.exe; UI=%s", index)
    tray_start = any(arg.lower() in ("--tray", "--mode=tray") for arg in sys.argv[1:])
    bridge = MotorBridge(logger)
    window = webview.create_window(
        "Asteria",
        index.as_uri(),
        js_api=bridge,
        width=1280,
        height=840,
        min_size=(1024, 680),
        hidden=tray_start,
        background_color="#080d14",
    )
    bridge.bind_window(window)
    _start_show_watcher(window)
    _start_tray(window, bridge, logger)

    def _on_closing():
        # Never call window.hide() synchronously here — pywebview/Win32 can hang
        # and brick the tray icon (visible but dead clicks/menus).
        if _quitting:
            return True
        _hide_to_tray(window, bridge)
        return False

    window.events.closing += _on_closing
    try:
        webview.start(gui="edgechromium", debug=False, private_mode=True)
    except Exception as exc:
        logger.exception("WebView start failed: %s", exc)
        _warn_missing_webview2(logger)
        return 4
    _quitting = True
    _tray_state["stop"] = True
    try:
        icon = _tray_state.get("icon")
        if icon is not None:
            icon.stop()
    except Exception:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
