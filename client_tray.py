#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CLIENT TRAY MODULE — System tray integration for Cloud Honeypot Client.
Version: See client_constants.VERSION

Provides:
  - TrayManager class: centralized tray icon lifecycle, context menu, window show/hide/exit
  - Dynamic status icons: green (active tunnels) / red (inactive) via pystray + PIL
  - Fallback: programmatic icon generation if .ico files are missing
  - Thread model: daemon thread for tray loop, thread-safe UI coordination

Used by: client.py (initialize_tray_manager, update_tray_icon, on_close)
Depends on: client_constants, client_helpers, pystray, PIL
"""

import os
import ctypes
import threading
from typing import Optional, Callable, Any

from client_constants import TRY_TRAY, __version__
from client_helpers import log

# Optional tray support - import after constants are loaded
if TRY_TRAY:
    try:
        import pystray
        from pystray import MenuItem as TrayItem
        from PIL import Image, ImageDraw
    except ImportError:
        TRY_TRAY = False

# ===================== TRAY MANAGEMENT ===================== #

# Cached tray images — reopening .ico on every health tick causes UI stutter
_TRAY_ICON_CACHE = {}


def tray_make_image(active: bool) -> Image.Image:
    """Load appropriate tray icon based on protection status (cached)."""
    try:
        key = bool(active)
        cached = _TRAY_ICON_CACHE.get(key)
        if cached is not None:
            return cached

        from client_utils import get_resource_path
        
        # Determine icon file based on state
        if active:
            icon_file = get_resource_path("certs/honeypot_active_16.ico")
        else:
            icon_file = get_resource_path("certs/honeypot_inactive_16.ico")
        
        # Try to load from file system first
        if os.path.exists(icon_file):
            from PIL import Image
            img = Image.open(icon_file)
            # Copy so pystray mutations cannot corrupt cache
            img = img.copy()
            _TRAY_ICON_CACHE[key] = img
            return img
        
        # Fallback to programmatic generation
        from PIL import Image, ImageDraw
        size = 16
        bg_color = (76, 175, 80, 255) if active else (244, 67, 54, 255)  # Green or Red
        
        img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        
        # Draw background circle
        center = size // 2
        radius = int(size * 0.4)
        draw.ellipse([center - radius, center - radius, center + radius, center + radius], 
                     fill=bg_color)
        
        # Draw simplified cloud shape
        cloud_color = (255, 255, 255, 255)  # White
        cloud_radius = int(size * 0.2)
        draw.ellipse([center - cloud_radius, center - cloud_radius,
                      center + cloud_radius, center + cloud_radius],
                     fill=cloud_color)
        
        _TRAY_ICON_CACHE[key] = img
        return img
        
    except Exception as e:
        # Ultimate fallback - simple colored circle
        from PIL import Image, ImageDraw
        col = "green" if active else "red"
        img = Image.new('RGB', (16, 16), "white")
        d = ImageDraw.Draw(img)
        d.ellipse((2, 2, 14, 14), fill=col)
        return img

def update_window_icon(root, is_active: bool):
    """Update window icon based on protection status"""
    if not root: return
    try:
        from client_utils import get_resource_path
        
        if is_active:
            window_icon_path = get_resource_path('certs/honeypot_active_32.ico')
        else:
            window_icon_path = get_resource_path('certs/honeypot_inactive_32.ico')
        
        if os.path.exists(window_icon_path):
            root.iconbitmap(window_icon_path)
            
    except Exception as e:
        log(f"Window icon update error: {e}")

class TrayManager:
    """System tray management"""
    
    def __init__(self, app_instance, translation_func: Callable[[str], str]):
        self.app_instance = app_instance
        self.t = translation_func
        self.tray_icon = None
        self.tray_thread = None
        self.show_callback = None
        self.minimize_callback = None
        self._tray_stop = False
        self._tray_starting = False
        self._taskbar_watcher_stop = None
        

    def is_protection_active(self) -> bool:
        """Port izleme (EventLog) veya honeypot bait aktifse True.

        Honeypot kapalı workstation'larda da threat kuralları açıksa
        koruma aktif sayılır — bait yok diye 'pasif' gösterme.
        """
        try:
            if hasattr(self.app_instance, "is_protection_active"):
                return bool(self.app_instance.is_protection_active())
            if hasattr(self.app_instance, "service_manager"):
                return len(self.app_instance.service_manager.running_services) > 0
        except Exception as e:
            log(f"[TRAY] Protection status check error: {e}")
        return False

    def update_tray_icon(self):
        """Update tray icon to reflect current protection status"""
        is_active = self.is_protection_active()
        mode = "inactive"
        try:
            if hasattr(self.app_instance, "get_protection_mode"):
                mode = self.app_instance.get_protection_mode()
        except Exception:
            mode = "full" if is_active else "inactive"

        # Skip disk/PIL work when nothing changed (health check calls this often)
        prev = getattr(self, "_tray_last_state", None)
        new_state = (bool(is_active), str(mode))
        if prev == new_state and self.tray_icon:
            return
        self._tray_last_state = new_state

        # Update tray icon
        if TRY_TRAY and self.tray_icon:
            try:
                new_icon = tray_make_image(is_active)
                self.tray_icon.icon = new_icon

                if mode == "monitoring":
                    status = self.t("protection_monitoring")
                elif mode == "full":
                    status = self.t("protection_active")
                else:
                    status = self.t("protection_inactive")
                self.tray_icon.title = f"{self.t('app_title')} - {status}"

            except Exception as e:
                log(f"Tray icon update error: {e}")
                
        # Update window icon as well
        if hasattr(self.app_instance, 'root') and self.app_instance.root:
            update_window_icon(self.app_instance.root, is_active)
    
    def show_window(self):
        """Show main window from tray (must run on Tk main thread). PIN-gated."""
        def _do_show():
            try:
                root = getattr(self.app_instance, 'root', None)
                if not root or not root.winfo_exists():
                    return

                # Already prompting / showing — tray re-clicks must not stack PIN dialogs
                if getattr(self, "_show_busy", False):
                    try:
                        from client_gui_lock import GuiLock
                        gl = GuiLock.instance()
                        if gl._prompt_window is not None:
                            gl._prompt_window.lift()
                            gl._prompt_window.focus_force()
                    except Exception:
                        pass
                    return

                # Window already visible + unlocked → just focus (no PIN again)
                try:
                    from client_gui_lock import GuiLock
                    gl = GuiLock.instance()
                    visible = False
                    try:
                        visible = bool(root.winfo_viewable()) and str(root.state()) != "withdrawn"
                    except Exception:
                        visible = False
                    if visible and (gl.is_session_unlocked() or not gl.has_pin()):
                        self.app_instance._tray_mode.clear()
                        root.deiconify()
                        root.lift()
                        root.focus_force()
                        if os.name == "nt":
                            try:
                                hwnd = root.winfo_id()
                                parent = ctypes.windll.user32.GetParent(hwnd)
                                target = parent if parent else hwnd
                                ctypes.windll.user32.SetForegroundWindow(target)
                            except Exception:
                                pass
                        return
                except Exception:
                    pass

                self._show_busy = True
                try:
                    # PIN unlock required before revealing GUI
                    try:
                        from client_gui_lock import require_gui_unlock
                        if not require_gui_unlock(self.app_instance, reason="show"):
                            log("[TRAY] Show blocked — PIN required")
                            return
                    except Exception as e:
                        log(f"[TRAY] PIN gate error: {e}")

                    self.app_instance._tray_mode.clear()
                    root.deiconify()
                    root.update_idletasks()
                    root.lift()
                    root.attributes("-topmost", True)
                    root.after(150, lambda: root.attributes("-topmost", False))
                    root.focus_force()

                    # Windows: bring window to foreground (focus_force alone is often ignored)
                    if os.name == "nt":
                        try:
                            hwnd = root.winfo_id()
                            # CTk may need parent HWND on some setups
                            parent = ctypes.windll.user32.GetParent(hwnd)
                            target = parent if parent else hwnd
                            ctypes.windll.user32.SetForegroundWindow(target)
                        except Exception:
                            pass

                    from client_constants import WINDOW_WIDTH, WINDOW_HEIGHT
                    sw = root.winfo_screenwidth()
                    sh = root.winfo_screenheight()
                    cx = int(sw / 2 - WINDOW_WIDTH / 2)
                    cy = int(sh / 2 - WINDOW_HEIGHT / 2)
                    root.geometry(f"{WINDOW_WIDTH}x{WINDOW_HEIGHT}+{cx}+{cy}")
                finally:
                    self._show_busy = False
            except Exception as e:
                self._show_busy = False
                log(f"Show window error: {e}")

        try:
            if hasattr(self.app_instance, '_gui_safe'):
                self.app_instance._gui_safe(_do_show)
            elif getattr(self.app_instance, 'root', None):
                self.app_instance.root.after(0, _do_show)
        except Exception as e:
            log(f"Show window schedule error: {e}")
                
    def minimize_to_tray(self):
        """Minimize window to tray (Tk main thread)."""
        def _do_minimize():
            try:
                # Onboarding / no token → keep window visible for dashboard registration
                try:
                    from client_utils import should_force_gui_visible
                    tok = ""
                    if hasattr(self.app_instance, "get_token"):
                        tok = self.app_instance.get_token() or ""
                    tok = tok or (getattr(self.app_instance, "state", {}) or {}).get("token", "")
                    if should_force_gui_visible(bool(tok)):
                        log("[TRAY] Skip minimize — onboarding / registration required")
                        self.show_window()
                        return
                except Exception:
                    pass
                root = getattr(self.app_instance, 'root', None)
                if root and root.winfo_exists():
                    self.app_instance._tray_mode.set()
                    root.withdraw()
                    try:
                        from client_gui_lock import GuiLock
                        GuiLock.instance().lock_session()
                    except Exception:
                        pass
            except Exception as e:
                log(f"Minimize error: {e}")

        try:
            if hasattr(self.app_instance, '_gui_safe'):
                self.app_instance._gui_safe(_do_minimize)
            elif getattr(self.app_instance, 'root', None):
                self.app_instance.root.after(0, _do_minimize)
        except Exception as e:
            log(f"Minimize schedule error: {e}")
                
    def exit_app(self):
        """Exit application from tray — PIN required; stops watchdog (intentional)."""
        # PIN gate — attacker cannot quit without PIN
        try:
            from client_gui_lock import require_gui_unlock
            if not require_gui_unlock(self.app_instance, reason="exit"):
                log("[EXIT] Blocked — PIN required to quit")
                try:
                    import tkinter.messagebox as messagebox
                    messagebox.showwarning(self.t("warn"), self.t("pin_exit_denied"))
                except Exception:
                    pass
                return
        except Exception as e:
            log(f"[EXIT] PIN gate error: {e}")
            return

        # ServiceManager üzerinden aktif servis kontrolü
        active_services_exist = False
        try:
            if hasattr(self.app_instance, 'service_manager'):
                running = self.app_instance.service_manager.running_services
                if running:
                    active_services_exist = True
                    log(f"[EXIT] Aktif servisler bulundu: {running}")
        except Exception as e:
            log(f"[EXIT] Servis durumu kontrol hatası: {e}")
        
        if active_services_exist:
            try:
                import tkinter.messagebox as messagebox
                messagebox.showwarning(self.t("warn"), self.t("tray_warn_stop_first"))
            except:
                pass
            return
        
        # Son offline heartbeat gönder
        try:
            self.app_instance.send_heartbeat_once("offline")
            log("[EXIT] Offline heartbeat sent before exit")
        except Exception as e:
            log(f"[EXIT] Heartbeat error during exit: {e}")
        
        # Cleanup heartbeat file
        try:
            from client_monitoring import cleanup_heartbeat_file
            cleanup_heartbeat_file(getattr(self.app_instance, 'heartbeat_path', ''))
        except Exception as e:
            log(f"[EXIT] Heartbeat cleanup error: {e}")
            
        # Watchdog'u durdur + imzalı operator stop (motor da QUIT ile kapanır)
        try:
            from client_operator_stop import arm_operator_stop
            from client_daemon_ipc import request as ipc_request
            if arm_operator_stop():
                log("[EXIT] operator_stop armed (signed PIN token)")
                try:
                    ipc_request("QUIT", timeout=8.0)
                except Exception as e:
                    log(f"[EXIT] motor QUIT IPC: {e}")
            else:
                log("[EXIT] operator_stop arm failed — motor may stay up")
        except Exception as e:
            log(f"[EXIT] operator_stop error: {e}")
        try:
            from client_utils import write_watchdog_token
            from client_constants import WATCHDOG_TOKEN_FILE
            write_watchdog_token('stop', WATCHDOG_TOKEN_FILE)
        except Exception as e:
            log(f"Watchdog stop error: {e}")
            
        # Tray ikonunu kaldır
        try:
            if self.tray_icon:
                self.tray_icon.stop()
        except Exception:
            pass
            
        # Merkezi temiz çıkış
        self.app_instance.graceful_exit(0)
    
    def tray_loop(self):
        """Supervised tray loop — restarts icon after crash or explorer TaskbarCreated."""
        if not TRY_TRAY:
            return
        import time

        while not self._tray_stop:
            if getattr(self.app_instance, "_exiting", False):
                break
            try:
                self._run_tray_icon_once()
            except Exception as e:
                log(f"[TRAY] icon loop error: {e}")
            self.tray_icon = None
            if self._tray_stop or getattr(self.app_instance, "_exiting", False):
                break
            log("[TRAY] Icon loop ended — restarting in 1.5s (explorer restart / crash recovery)")
            time.sleep(1.5)

    def _start_taskbar_created_watcher(self, icon) -> None:
        """When explorer.exe restarts, Windows broadcasts TaskbarCreated — stop icon to respawn."""
        stop = threading.Event()
        self._taskbar_watcher_stop = stop

        def _watch():
            hwnd = None
            try:
                import time as _time
                try:
                    import win32gui
                    import win32con
                    import win32api
                except ImportError:
                    return

                msg_id = win32gui.RegisterWindowMessage("TaskbarCreated")
                if not msg_id:
                    return

                class_name = f"CloudHoneypotTrayTB{os.getpid()}"

                def _wndproc(h, msg, wparam, lparam):
                    if msg == msg_id:
                        log("[TRAY] TaskbarCreated — restarting NotifyIcon")
                        try:
                            icon.stop()
                        except Exception:
                            pass
                        stop.set()
                        return 0
                    return win32gui.DefWindowProc(h, msg, wparam, lparam)

                # Keep callback alive for the window lifetime
                self._tb_wndproc = _wndproc
                wc = win32gui.WNDCLASS()
                wc.lpfnWndProc = _wndproc
                wc.hInstance = win32api.GetModuleHandle(None)
                wc.lpszClassName = class_name
                try:
                    win32gui.RegisterClass(wc)
                except Exception:
                    # Already registered in this process from a prior icon cycle
                    pass
                hwnd = win32gui.CreateWindowEx(
                    0,
                    class_name,
                    "CHPTrayWatch",
                    0,
                    0, 0, 0, 0,
                    win32con.HWND_MESSAGE,
                    0,
                    wc.hInstance,
                    None,
                )
                while not stop.is_set() and not self._tray_stop:
                    # Pump with timeout so we can exit
                    if win32gui.PumpWaitingMessages() == 0:
                        _time.sleep(0.25)
            except Exception as e:
                log(f"[TRAY] TaskbarCreated watcher error: {e}")
            finally:
                if hwnd:
                    try:
                        import win32gui
                        win32gui.DestroyWindow(hwnd)
                    except Exception:
                        pass

        threading.Thread(target=_watch, name="TrayTaskbarWatch", daemon=True).start()

    def _run_tray_icon_once(self):
        """Create and run one pystray Icon until stop/crash/TaskbarCreated."""
        icon = pystray.Icon("honeypot_client")
        self.tray_icon = icon
        self._tray_starting = False
        icon.title = f"{self.t('app_title')} v{__version__}"
        icon.icon = tray_make_image(self.app_instance.state.get("running", False))
        
        # Callback'leri kaydet
        self.show_callback = self.show_window
        self.minimize_callback = self.minimize_to_tray
        
        # Tray menüsünü oluştur
        try:
            def _open_dashboard():
                try:
                    import webbrowser
                    from client_constants import API_URL
                    base = API_URL.rsplit("/api", 1)[0]
                    tok = ""
                    if hasattr(self.app_instance, "get_token"):
                        tok = self.app_instance.get_token() or ""
                    tok = tok or (getattr(self.app_instance, "state", {}) or {}).get("token", "")
                    url = f"{base}/dashboard?token={tok}" if tok else f"{base}/dashboard"
                    webbrowser.open(url)
                    try:
                        from client_utils import clear_force_gui_onboarding
                        if tok:
                            clear_force_gui_onboarding()
                    except Exception:
                        pass
                except Exception as e:
                    log(f"tray dashboard open error: {e}")

            def _copy_token():
                try:
                    tok = ""
                    if hasattr(self.app_instance, "get_token"):
                        tok = self.app_instance.get_token() or ""
                    tok = tok or (getattr(self.app_instance, "state", {}) or {}).get("token", "")
                    root = getattr(self.app_instance, "root", None)
                    if root and tok:
                        def _clip():
                            root.clipboard_clear()
                            root.clipboard_append(tok)
                            root.update()
                        if hasattr(self.app_instance, "_gui_safe"):
                            self.app_instance._gui_safe(_clip)
                        else:
                            root.after(0, _clip)
                        self.notify(self.t("copy"), self.t("token_copied_toast"))
                except Exception as e:
                    log(f"tray copy token error: {e}")

            def _link_account():
                try:
                    self.show_window()
                    gui = getattr(self.app_instance, "gui", None)
                    if gui and hasattr(gui, "_open_link_account"):
                        tok = ""
                        if hasattr(self.app_instance, "get_token"):
                            tok = self.app_instance.get_token() or ""
                        tok = tok or (getattr(self.app_instance, "state", {}) or {}).get("token", "")
                        # Schedule on Tk thread after window shown
                        root = getattr(self.app_instance, "root", None)
                        if root:
                            root.after(200, lambda: gui._open_link_account(tok))
                        else:
                            gui._open_link_account(tok)
                        return
                    # Fallback: browser
                    import webbrowser
                    from client_constants import API_URL
                    base = API_URL.rsplit("/api", 1)[0]
                    tok = ""
                    if hasattr(self.app_instance, "get_token"):
                        tok = self.app_instance.get_token() or ""
                    tok = tok or (getattr(self.app_instance, "state", {}) or {}).get("token", "")
                    if tok:
                        _copy_token()
                    webbrowser.open(f"{base}/servers" if tok else f"{base}/?login=1")
                except Exception as e:
                    log(f"tray link account error: {e}")

            from client_constants import SERVER_NAME
            from client_utils import is_account_linked
            # Do NOT call refresh_account_link_status here — it blocks tray icon (~API timeout)
            host_label = f"{SERVER_NAME}"[:40]
            account_item = (
                TrayItem(self.t('btn_account_linked'), lambda: _link_account())
                if is_account_linked()
                else TrayItem(self.t('btn_link_account'), lambda: _link_account())
            )
            menu = pystray.Menu(
                TrayItem(self.t('tray_show'), lambda: self.show_window(), default=True),
                TrayItem(host_label, lambda: None, enabled=False),
                TrayItem(self.t('tray_dashboard'), lambda: _open_dashboard()),
                account_item,
                TrayItem(self.t('menu_copy_token'), lambda: _copy_token()),
                TrayItem(self.t('tray_exit'), lambda: self.exit_app())
            )
            icon.menu = menu
        except Exception as e:
            log(f"Tray menu error: {e}")
            # Fallback: basit menü
            icon.menu = (
                TrayItem(self.t('tray_show'), lambda: self.show_window()),
                TrayItem(self.t('tray_exit'), lambda: self.exit_app())
            )

        self._start_taskbar_created_watcher(icon)
        try:
            icon.run()
        finally:
            try:
                if self._taskbar_watcher_stop:
                    self._taskbar_watcher_stop.set()
            except Exception:
                pass

    def ensure_tray_alive(self) -> bool:
        """Restart tray thread if it died while GUI process still runs."""
        if not TRY_TRAY:
            return False
        if self._tray_stop or getattr(self.app_instance, "_exiting", False):
            return False
        alive = bool(self.tray_thread and self.tray_thread.is_alive())
        if alive and self.tray_icon:
            # Soft re-assert visibility (helps some explorer races without full restart)
            try:
                self.tray_icon.visible = True
            except Exception:
                pass
            return True
        if alive:
            return True
        log("[TRAY] Tray thread dead while GUI alive — restarting")
        return self.start_tray_system()

    def start_tray_system(self):
        """Start tray system in background thread (idempotent if already alive)."""
        if not TRY_TRAY:
            log("Tray support not available")
            return False
        if self.tray_thread and self.tray_thread.is_alive():
            return True
            
        try:
            self._tray_stop = False
            self._tray_starting = True
            self.tray_thread = threading.Thread(
                target=self.tray_loop, 
                daemon=True,
                name="TrayManager"
            )
            self.tray_thread.start()
            log("Tray system started")
            return True
        except Exception as e:
            self._tray_starting = False
            log(f"Tray system start error: {e}")
            return False
    
    def stop_tray_system(self):
        """Stop tray system"""
        try:
            self._tray_stop = True
            try:
                if self._taskbar_watcher_stop:
                    self._taskbar_watcher_stop.set()
            except Exception:
                pass
            if self.tray_icon:
                self.tray_icon.stop()
            log("Tray system stopped")
        except Exception as e:
            log(f"Tray system stop error: {e}")

    def notify(self, title: str, message: str):
        """Tray balloon / notification (thread-safe)."""
        if not TRY_TRAY or not self.tray_icon:
            return
        try:
            # pystray 0.19+ notify
            if hasattr(self.tray_icon, "notify"):
                self.tray_icon.notify(message, title)
                return
        except Exception as e:
            log(f"Tray notify error: {e}")
        # Fallback: Windows balloon via ctypes
        if os.name == "nt":
            try:
                import ctypes
                from ctypes import wintypes
                NIIF_INFO = 0x01
                NIM_MODIFY = 0x01
                class NOTIFYICONDATAW(ctypes.Structure):
                    _fields_ = [
                        ("cbSize", wintypes.DWORD),
                        ("hWnd", wintypes.HWND),
                        ("uID", wintypes.UINT),
                        ("uFlags", wintypes.UINT),
                        ("uCallbackMessage", wintypes.UINT),
                        ("hIcon", wintypes.HICON),
                        ("szTip", wintypes.WCHAR * 128),
                        ("dwState", wintypes.DWORD),
                        ("dwStateMask", wintypes.DWORD),
                        ("szInfo", wintypes.WCHAR * 256),
                        ("uVersion", wintypes.UINT),
                        ("szInfoTitle", wintypes.WCHAR * 64),
                        ("dwInfoFlags", wintypes.DWORD),
                    ]
                flags = 0x10  # NIF_INFO
                nid = NOTIFYICONDATAW()
                nid.cbSize = ctypes.sizeof(nid)
                nid.uID = 1
                nid.uFlags = flags
                nid.szInfoTitle = title[:63]
                nid.szInfo = message[:255]
                nid.dwInfoFlags = NIIF_INFO
                ctypes.windll.shell32.Shell_NotifyIconW(NIM_MODIFY, ctypes.byref(nid))
            except Exception as ex:
                log(f"Tray balloon fallback error: {ex}")
    
    def on_window_close(self):
        """Handle main window close - prefer tray minimize; never exit mid-startup."""
        try:
            tray_ready = bool(TRY_TRAY and (
                self.tray_icon
                or self._tray_starting
                or (self.tray_thread and self.tray_thread.is_alive())
            ))
            if tray_ready:
                if self.minimize_callback:
                    self.minimize_callback()
                else:
                    self.minimize_to_tray()
                return

            if TRY_TRAY:
                import time
                for _ in range(10):
                    time.sleep(0.1)
                    if self.tray_icon or (self.tray_thread and self.tray_thread.is_alive()):
                        self.minimize_to_tray()
                        return

            if self.app_instance.state.get("running", False):
                try:
                    import tkinter.messagebox as messagebox
                    messagebox.showwarning(self.t("warn"), self.t("tray_warn_stop_first"))
                except Exception:
                    pass
                return

            if hasattr(self.app_instance, "root") and self.app_instance.root:
                self.app_instance.root.destroy()

            self.app_instance.graceful_exit(0)
        except Exception as e:
            log(f"Window close error: {e}")
