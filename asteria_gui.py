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

# Explicit IPC ops the WebView may request (maps to client_daemon_ipc helpers).
_IPC_ALLOWLIST = frozenset(
    {
        "STATUS",
        "THREAT_TOP",
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

_ACCOUNT_ACTIONS = frozenset({"status", "link", "unlink"})
_HARDEN_FIX_TARGETS = frozenset({"winrm", "nla", "antivirus"})
_RDP_MOVE_MODES = frozenset({"secure", "rollback"})
_IR_ACTIONS = frozenset({"logoff", "disable"})
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
            try:
                window.show()
                window.restore()
                _pulse_session_gate(window)
            except Exception:
                return

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


def _start_tray(window: Any, bridge: "MotorBridge", logger: logging.Logger):
    """Own the interactive tray outside the SYSTEM motor."""
    import pystray

    image = _load_tray_image("online")

    def show_gui(_icon=None, _item=None):
        try:
            window.show()
            window.restore()
            _pulse_session_gate(window)
        except Exception as exc:
            logger.info("Tray show failed: %s", exc)

    def open_dashboard(_icon=None, _item=None):
        bridge.shell("open_dashboard")

    def copy_token(_icon=None, _item=None):
        bridge.shell("copy_token")

    def quit_gui(icon=None, _item=None):
        global _quitting
        _quitting = True
        try:
            if icon:
                icon.stop()
            window.destroy()
        except Exception:
            pass

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
    icon.run_detached()

    def _sync_tray_status() -> None:
        while True:
            try:
                import time

                time.sleep(8)
                if _quitting:
                    return
                pong = bridge.ping()
                next_key = "online" if pong.get("ok") else "offline"
                icon.icon = _load_tray_image(next_key)
            except Exception:
                try:
                    import time

                    time.sleep(8)
                except Exception:
                    return

    threading.Thread(target=_sync_tray_status, name="AsteriaTrayStatus", daemon=True).start()
    return icon


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
        """RDP port protection status / move (admin required for move)."""
        if not self._authorized():
            return self._deny_locked()
        act = str(action or "status").strip().lower()
        try:
            from client_constants import RDP_SECURE_PORT
            from client_utils import ServiceController, is_admin

            current = ServiceController.get_rdp_port() or 3389
            protected = int(current) == int(RDP_SECURE_PORT)
            if act == "status":
                return {
                    "ok": True,
                    "protected": protected,
                    "current_port": int(current),
                    "secure_port": int(RDP_SECURE_PORT),
                    "admin": bool(is_admin()),
                }
            if act == "move":
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
                ok = self._rdp_transition(mv)
                final = ServiceController.get_rdp_port() or current
                return {
                    "ok": bool(ok),
                    "protected": int(final) == int(RDP_SECURE_PORT),
                    "current_port": int(final),
                    "secure_port": int(RDP_SECURE_PORT),
                    "mode": mv,
                }
            return {"ok": False, "error": "rdp_unknown_action"}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def ir(self, action: str, username: str = "") -> Dict[str, Any]:
        """Incident response: logoff / disable local account."""
        if not self._authorized():
            return self._deny_locked()
        act = str(action or "").strip().lower()
        user = str(username or "").strip()
        if act not in _IR_ACTIONS:
            return {"ok": False, "error": "ir_unknown_action"}
        if not user:
            return {"ok": False, "error": "username_required"}
        try:
            from client_auto_response import AutoResponse

            ar = AutoResponse()
            if act == "logoff":
                ok = bool(ar.logoff_user(user))
                return {"ok": ok, "action": "logoff", "username": user}
            ok = bool(ar.disable_account(user, allow_privileged=True))
            return {"ok": ok, "action": "disable", "username": user}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

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

    def shell(self, action: str) -> Dict[str, Any]:
        act = str(action or "").strip().lower()
        if act not in _SHELL_ALLOWLIST:
            return {"ok": False, "error": "shell_denied"}
        # Most open_* / about / check_updates do not require PIN (tray parity).
        try:
            if act == "open_dashboard":
                webbrowser.open("https://asteria.run")
                return {"ok": True}
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
                    self._window.hide()
                    try:
                        self._gui_lock.lock_session()
                    except Exception:
                        pass
                    _pulse_session_gate(self._window)
                return {"ok": True}
            if act == "quit":
                global _quitting
                _quitting = True
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
    tray_icon = _start_tray(window, bridge, logger)

    def _on_closing():
        if _quitting:
            return True
        window.hide()
        try:
            bridge._gui_lock.lock_session()
        except Exception:
            pass
        _pulse_session_gate(window)
        return False

    window.events.closing += _on_closing
    try:
        webview.start(gui="edgechromium", debug=False, private_mode=True)
    except Exception as exc:
        logger.exception("WebView start failed: %s", exc)
        _warn_missing_webview2(logger)
        return 4
    try:
        tray_icon.stop()
    except Exception:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
