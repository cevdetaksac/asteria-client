# -*- coding: utf-8 -*-
"""UX screenshot tour — capture every main GUI page for review.

Launches ModernGUI with a lightweight stub app (real I18N + optional live
token/config), walks each sidebar page, and saves PNGs under docs/ux-review/.
"""
from __future__ import annotations

import json
import os
import sys
import time
import types
from pathlib import Path

# Run from cloud-client root (script lives in scripts/)
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)

OUT = ROOT / "docs" / "ux-review"
OUT.mkdir(parents=True, exist_ok=True)

import customtkinter as ctk
from PIL import ImageGrab
import win32gui
import win32con

from client_utils import load_i18n
from client_constants import __version__, API_URL
from client_gui import ModernGUI


I18N = load_i18n()


class FakeServiceManager:
    def __init__(self):
        self.running_services = ["SSH", "RDP", "FTP"]
        self.session_stats = {
            "total_credentials": 2,
            "last_attack_ts": time.time() - 120,
            "last_attacker_ip": "203.0.113.50",
            "last_service": "RDP",
        }


class FakeAPI:
    def __init__(self, token: str):
        self.token = token
        self._cfg = None

    def fetch_threat_config(self, token):
        if self._cfg is not None:
            return self._cfg
        try:
            from client_api import AsteriaAPIClient
            from client_helpers import log as _log

            real = AsteriaAPIClient(API_URL, _log)
            cfg = real.fetch_threat_config(token)
            if isinstance(cfg, dict) and cfg:
                self._cfg = cfg
                return cfg
        except Exception as e:
            print("live config fetch failed:", e)
        # Realistic fallback so Settings/Layers render meaningfully
        self._cfg = {
            "ransomware_protection_enabled": True,
            "canary_files_enabled": True,
            "alert_email_enabled": True,
            "instant_email_for_critical": True,
            "min_severity_for_email": "medium",
            "daily_digest_enabled": False,
            "auto_block_enabled": True,
            "auto_block_threshold": 3,
            "auto_block_duration_hours": 0,
            "max_auto_blocks_per_hour": 20,
            "max_auto_blocks_per_day": 100,
            "silent_hours": {
                "enabled": True,
                "mode": "night_only",
                "night_start": "00:00",
                "night_end": "07:00",
            },
            "webhook_enabled": False,
            "webhook_url": "",
            "protection": {
                "network_guard": {"enabled": True},
            },
            "whitelist_ips": [],
            "whitelist_subnets": [],
        }
        return self._cfg

    def update_threat_config(self, token, patch):
        cfg = dict(self.fetch_threat_config(token) or {})
        for k, v in (patch or {}).items():
            if isinstance(v, dict) and isinstance(cfg.get(k), dict):
                nested = dict(cfg[k])
                nested.update(v)
                cfg[k] = nested
            else:
                cfg[k] = v
        self._cfg = cfg
        return cfg


class FakeApp:
    def __init__(self, token: str = ""):
        self.lang = "tr"
        self.state = {
            "token": token or "ux-tour-token",
            "public_ip": "212.154.81.43",
            "server_name": "DESKTOP-F5SCL3G",
        }
        self.root = None
        self.service_manager = FakeServiceManager()
        self.api_client = FakeAPI(token)
        # List of (port, service) like the real client property
        self.PORT_TABLOSU = [
            (2222, "SSH"), (3389, "RDP"), (2121, "FTP"),
            (1433, "MSSQL"), (3306, "MYSQL"),
        ]
        self._last_attack_count = 6
        self._last_api_ok = True
        self._tray_mode = types.SimpleNamespace(set=lambda: None, is_set=lambda: False)
        self.ip_entry = None
        self.attack_entry = None
        self.threat_engine = None
        self.ransomware_shield = None
        self.network_guard = None
        self.silent_hours_guard = None
        self.health_monitor = None
        # Keep process_protection truthy so Koruma card isn't falsely OFF
        self.process_protection = object()
        self.remote_commands = None
        self.frontend_only = True
        self.row_controls = {}

    def t(self, key: str) -> str:
        return I18N.get(self.lang, {}).get(key, key)

    def refresh_attack_count(self, async_thread=True):
        pass

    def on_close(self):
        try:
            if self.root:
                self.root.destroy()
        except Exception:
            pass

    def _open_dashboard(self):
        pass

    def get_protection_mode(self):
        return "monitoring"

    def read_status(self):
        running = [(2222, "SSH"), (3389, "RDP"), (2121, "FTP")]
        return running, True

    def update_header_status(self, *_a, **_k):
        pass

    def start_honeypot(self, *_a, **_k):
        return True

    def stop_honeypot(self, *_a, **_k):
        return True

    def toggle_rdp_protection(self, *_a, **_k):
        return True


def _hwnd_for_title(substr: str):
    found = []

    def _enum(hwnd, _):
        if win32gui.IsWindowVisible(hwnd):
            title = win32gui.GetWindowText(hwnd) or ""
            if substr.lower() in title.lower():
                found.append(hwnd)
        return True

    win32gui.EnumWindows(_enum, None)
    return found[0] if found else None


def dismiss_pin_dialogs(root: ctk.CTk):
    """Destroy any Güvenlik PIN toplevels that obscure the tour."""
    try:
        import client_gui_lock as gl
        lock = gl.GuiLock.instance()
        lock._unlocked = True
        lock._prompt_active = False
        if getattr(lock, "_prompt_window", None):
            try:
                lock._prompt_window.destroy()
            except Exception:
                pass
            lock._prompt_window = None
    except Exception:
        pass
    # Sweep leftover Toplevels titled like PIN
    try:
        for w in root.winfo_children():
            try:
                title = str(w.title()) if hasattr(w, "title") else ""
            except Exception:
                title = ""
            if "PIN" in title.upper() or "Güvenlik" in title:
                try:
                    w.destroy()
                except Exception:
                    pass
    except Exception:
        pass
    # Also enum Win32 dialogs
    try:
        targets = []

        def _enum(hwnd, _):
            t = win32gui.GetWindowText(hwnd) or ""
            if "PIN" in t.upper() and win32gui.IsWindowVisible(hwnd):
                targets.append(hwnd)
            return True

        win32gui.EnumWindows(_enum, None)
        for hwnd in targets:
            try:
                win32gui.PostMessage(hwnd, win32con.WM_CLOSE, 0, 0)
            except Exception:
                pass
    except Exception:
        pass


def wait_label_contains(gui, attr: str, needles, timeout=6.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            lbl = getattr(gui, attr, None)
            text = (lbl.cget("text") if lbl else "") or ""
            if any(n in text for n in needles):
                return True
        except Exception:
            pass
        try:
            gui.root.update()
        except Exception:
            pass
        time.sleep(0.15)
    return False


def capture(path: Path, root: ctk.CTk):
    """PrintWindow capture — excludes foreign overlay windows (live PIN)."""
    import ctypes
    import win32ui
    from PIL import Image

    dismiss_pin_dialogs(root)
    root.update()
    root.update_idletasks()
    time.sleep(0.3)
    root.update()

    by_title = _hwnd_for_title("UX Tour")
    if not by_title:
        by_title = _hwnd_for_title("Cloud Honeypot Security")
    hwnd = by_title or int(root.winfo_id())
    try:
        outer = win32gui.GetAncestor(hwnd, win32con.GA_ROOT)
        if outer:
            hwnd = outer
    except Exception:
        pass

    left, top, right, bottom = win32gui.GetWindowRect(hwnd)
    width, height = max(1, right - left), max(1, bottom - top)

    hwnd_dc = win32gui.GetWindowDC(hwnd)
    mfc_dc = win32ui.CreateDCFromHandle(hwnd_dc)
    save_dc = mfc_dc.CreateCompatibleDC()
    bitmap = win32ui.CreateBitmap()
    bitmap.CreateCompatibleBitmap(mfc_dc, width, height)
    save_dc.SelectObject(bitmap)
    ok = ctypes.windll.user32.PrintWindow(hwnd, save_dc.GetSafeHdc(), 2)
    if not ok:
        ok = ctypes.windll.user32.PrintWindow(hwnd, save_dc.GetSafeHdc(), 0)
    bmpinfo = bitmap.GetInfo()
    bmpstr = bitmap.GetBitmapBits(True)
    img = Image.frombuffer(
        "RGB",
        (bmpinfo["bmWidth"], bmpinfo["bmHeight"]),
        bmpstr, "raw", "BGRX", 0, 1,
    )
    win32gui.DeleteObject(bitmap.GetHandle())
    save_dc.DeleteDC()
    mfc_dc.DeleteDC()
    win32gui.ReleaseDC(hwnd, hwnd_dc)

    if not ok or img.getbbox() is None:
        img = ImageGrab.grab(bbox=(left, top, right, bottom), all_screens=True)

    img.save(path)
    print(f"saved {path.name} ({img.size[0]}x{img.size[1]}) pw={ok}")
    return path


def load_token() -> str:
    try:
        from client_tokens import TokenStore
        from client_constants import TOKEN_FILE
        return (TokenStore.load(TOKEN_FILE) or "").strip()
    except Exception as e:
        print("token load:", e)
        return ""


def main():
    token = load_token()
    print("token present:", bool(token), "version:", __version__)

    # Prevent GuiLock PIN from blocking the tour — unlock before any after() fires
    try:
        import client_gui_lock as gl

        lock = gl.GuiLock.instance()
        lock._unlocked = True
        lock._data = {}  # no PIN configured for tour
        # has_pin reads _data — force false
        lock.has_pin = lambda: False  # type: ignore
        gl.require_gui_unlock = lambda *a, **k: True  # type: ignore
    except Exception as e:
        print("pin bypass note:", e)

    app = FakeApp(token=token)
    ctk.set_appearance_mode("dark")
    root = ctk.CTk()
    app.root = root
    gui = ModernGUI(app)

    # Build shell; skip deferred PIN / minimize
    gui.build(root, startup_mode="gui")
    root.title(f"Cloud Honeypot Security v{__version__} — UX Tour")
    root.geometry("1100x720")
    root.deiconify()
    root.lift()
    root.update()
    dismiss_pin_dialogs(root)

    # Force-build every page synchronously so screenshots are complete
    pages = [
        ("status", "01-anlik-durum.png"),
        ("threat", "02-tehdit-merkezi.png"),
        ("services", "03-honeypot-servisleri.png"),
        ("layers", "04-guvenlik-katmanlari.png"),
        ("settings", "05-ayarlar.png"),
    ]

    results = []
    for page_id, fname in pages:
        print(f"--- capturing {page_id} ---")
        dismiss_pin_dialogs(root)
        try:
            gui._ensure_page_built(page_id)
        except Exception as e:
            print(f"build {page_id} error:", e)
        try:
            gui._show_page(page_id)
        except Exception as e:
            print(f"show {page_id} error:", e)
        root.update()
        for _ in range(10):
            root.update()
            time.sleep(0.1)
        dismiss_pin_dialogs(root)

        if page_id == "status":
            gui._cached_motor_ok = True
            gui._cached_daemon_status = {
                "ok": True,
                "motor_ok": True,
                "ransomware_running": True,
                "rs_quarantine": {"active": False, "entries": 0, "alerts_total": 0},
                "network_guard": {
                    "present": True, "enabled": True, "running": True,
                    "suspended_processes": 0, "internet_ok": True,
                },
                "persistence": {
                    "daemon_ok": True, "service_ok": True, "tasks_armed": True,
                    "self_protection": True, "tamper_count_24h": 0,
                },
            }
            try:
                gui._refresh_protection_strip()
                gui._refresh_dashboard()
            except Exception as e:
                print("strip refresh:", e)
            root.update()
            time.sleep(0.4)

        if page_id == "layers":
            # Force sync from already-fetched (or fallback) config
            try:
                cfg = app.api_client.fetch_threat_config(token) or {}
                gui._set_layer_controls(gui._effective_threat_config(cfg))
            except Exception as e:
                print("layers force:", e)
            wait_label_contains(
                gui, "_layers_sync_label",
                ["eşitlendi", "synced", "✓"], timeout=5.0,
            )

        if page_id == "settings":
            try:
                from client_settings_util import extract_settings_values
                cfg = app.api_client.fetch_threat_config(token) or {}
                gui._apply_settings_values(
                    extract_settings_values(gui._effective_threat_config(cfg))
                )
            except Exception as e:
                print("settings force:", e)
            wait_label_contains(
                gui, "_settings_status_label",
                ["eşitlendi", "synced", "✓", "Kaydedildi"], timeout=5.0,
            )

        # Threat page builds heavy chunks async — give them time
        if page_id == "threat":
            for _ in range(40):
                root.update()
                time.sleep(0.1)

        path = OUT / fname
        capture(path, root)
        results.append(str(path))

    (OUT / "manifest.json").write_text(
        json.dumps({"version": __version__, "pages": results}, indent=2),
        encoding="utf-8",
    )
    print("DONE", OUT)
    try:
        root.destroy()
    except Exception:
        pass


if __name__ == "__main__":
    main()
