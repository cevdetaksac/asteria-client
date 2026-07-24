#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Asteria Client — Modern GUI Module (CustomTkinter).

Tüm GUI bileşenlerini içerir. client.py'deki iş mantığından bağımsızdır.
CloudHoneypotClient instance'ı üzerinden veri ve aksiyonlara erişir.
"""

import os
import time
import threading
import webbrowser
from tkinter import messagebox
from typing import Dict, Any, Optional

import customtkinter as ctk

from client_helpers import log, ClientHelpers
from client_utils import (
    get_config_value, update_language_config, get_resource_path
)
from client_constants import (
    LOG_FILE, RDP_SECURE_PORT, GITHUB_OWNER, GITHUB_REPO, __version__,
    GUI_DASHBOARD_REFRESH_MS,
)
from client_utils import get_from_config


from client_gui_theme import (
    COLORS, SERVICE_ICONS, SIDEBAR_WIDTH,
    NAV_ITEM_HEIGHT, NAV_ICON_WIDTH, NAV_PAD_X, NAV_ICON_TEXT_GAP,
    NAV_FONT_ICON, NAV_FONT_LABEL,
)


class ModernGUI:
    """CustomTkinter tabanlı modern GUI — CloudHoneypotClient'a bağlanır."""

    def __init__(self, app):
        """
        Args:
            app: CloudHoneypotClient instance
        """
        self.app = app
        self.row_controls: Dict[str, dict] = {}
        self._active_page: str = "status"
        self._lazy_intel = bool(get_from_config("advanced.lazy_security_intel", True))
        self._refresh_ms = GUI_DASHBOARD_REFRESH_MS
        self._pages_built: Dict[str, bool] = {}
        self._page_placeholders: Dict[str, Any] = {}
        self._page_data_loaded: Dict[str, bool] = {}
        self._refresh_loop_started = False

    # ─── Yardımcılar ─── #
    def t(self, key: str) -> str:
        return self.app.t(key)

    def _emoji_font(self, size: int = 16, weight: str = "normal"):
        """Windows'ta emoji için Segoe UI Emoji; yoksa varsayılan font."""
        try:
            return ctk.CTkFont(family="Segoe UI Emoji", size=size, weight=weight)
        except Exception:
            return ctk.CTkFont(size=size, weight=weight)

    def _gui_safe(self, func):
        """Thread-safe CTk çağrısı"""
        try:
            if self.app.root and self.app.root.winfo_exists():
                self.app.root.after(0, func)
        except Exception:
            pass

    @staticmethod
    def _widget_is_under(widget, ancestor) -> bool:
        """True if widget is ancestor or a descendant (Tk parent chain)."""
        w = widget
        guard = 0
        while w is not None and guard < 64:
            if w == ancestor:
                return True
            w = getattr(w, "master", None)
            guard += 1
        return False

    def _iter_widget_tree(self, root_widget):
        yield root_widget
        try:
            children = list(root_widget.winfo_children())
        except Exception:
            children = []
        for child in children:
            yield from self._iter_widget_tree(child)

    def _bind_hover_click(
        self,
        root_widget,
        *,
        on_click=None,
        on_enter=None,
        on_leave=None,
        cursor: str = "hand2",
    ) -> None:
        """Make a card/chip fully clickable — including labels inside it.

        Tk/CustomTkinter fires Leave when the pointer moves onto a child label,
        which breaks border hover. We ignore Leave while the pointer is still
        inside the root widget tree, and bind click/hover to all descendants.
        """
        def _enter(_event=None):
            if on_enter:
                on_enter()

        def _leave(_event=None):
            try:
                x, y = root_widget.winfo_pointerxy()
                under = root_widget.winfo_containing(x, y)
                if under is not None and self._widget_is_under(under, root_widget):
                    return
            except Exception:
                pass
            if on_leave:
                on_leave()

        def _click(_event=None):
            if on_click:
                on_click()
            return "break"

        for w in self._iter_widget_tree(root_widget):
            if on_enter is not None:
                w.bind("<Enter>", _enter, add="+")
            if on_leave is not None:
                w.bind("<Leave>", _leave, add="+")
            if on_click is not None:
                w.bind("<Button-1>", _click, add="+")
            if cursor:
                try:
                    w.configure(cursor=cursor)
                except Exception:
                    pass

    # ═══════════════════════════════════════════════════════════════
    #  ANA BUILD
    # ═══════════════════════════════════════════════════════════════
    def build(self, root: ctk.CTk, startup_mode: str = "gui"):
        """Ana GUI — modern sidebar navigasyon."""
        self.root = root
        self._start_time = time.time()

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        root.title(f"{self.t('app_title')} v{__version__}")
        root.geometry("1100x720")
        root.configure(fg_color=COLORS["bg"])
        root.minsize(960, 640)

        self._set_window_icon(root)
        self._build_top_bar(root)
        self._build_update_banner(root)
        root.protocol("WM_DELETE_WINDOW", self.app.on_close)

        # Ana gövde: sidebar + içerik
        body = ctk.CTkFrame(root, fg_color=COLORS["bg"], corner_radius=0)
        self._main_body = body
        body.pack(fill="both", expand=True)

        sidebar = ctk.CTkFrame(body, width=SIDEBAR_WIDTH, fg_color=COLORS["sidebar"], corner_radius=0)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)

        # Marka alanı
        brand = ctk.CTkFrame(sidebar, fg_color="transparent")
        brand.pack(fill="x", padx=16, pady=(20, 8))
        ctk.CTkLabel(
            brand, text="🛡️",
            font=self._emoji_font(28),
        ).pack(anchor="w")
        ctk.CTkLabel(
            brand, text=self.t("app_title"),
            font=ctk.CTkFont(size=15, weight="bold"),
            text_color=COLORS["text_bright"],
        ).pack(anchor="w")
        ctk.CTkLabel(
            brand, text=f"v{__version__}",
            font=ctk.CTkFont(size=11),
            text_color=COLORS["text_dim"],
        ).pack(anchor="w", pady=(0, 8))

        self._header_status = ctk.CTkLabel(
            sidebar,
            text="● " + self.t("protection_inactive"),
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=COLORS["red"],
        )
        self._header_status.pack(anchor="w", padx=16, pady=(0, 12))

        # Navigasyon bölümü — hizalı butonlar
        nav_frame = ctk.CTkFrame(sidebar, fg_color="transparent")
        nav_frame.pack(fill="x", padx=10, pady=(4, 12))

        self._content_area = ctk.CTkFrame(body, fg_color=COLORS["bg"], corner_radius=0)
        self._content_area.pack(side="left", fill="both", expand=True, padx=(0, 0), pady=0)

        # Most pages scroll; IP Lists uses a plain frame so only the table scrolls.
        self._pages: Dict[str, Any] = {}
        self._nav_buttons: Dict[str, dict] = {}
        self._pages_built = {
            "status": False, "threat": False, "iplist": False, "services": False,
            "layers": False, "settings": False,
        }
        self._page_placeholders = {}
        self._page_data_loaded = {}

        nav_items = [
            ("status", "📊", self.t("tab_status")),
            ("threat", "🛡", self.t("tab_threat_center")),
            ("iplist", "📡", self.t("tab_ip_lists")),
            ("services", "🐝", self.t("tab_services")),
            ("layers", "⚙", self.t("tab_security_layers")),
            ("settings", "🛠", self.t("tab_settings")),
        ]

        for page_id, icon, label in nav_items:
            self._nav_buttons[page_id] = self._create_sidebar_nav_item(
                nav_frame, page_id, icon, label,
            )
            if page_id == "iplist":
                page = ctk.CTkFrame(self._content_area, fg_color="transparent")
            else:
                page = ctk.CTkScrollableFrame(self._content_area, fg_color="transparent")
            self._pages[page_id] = page
            # Lightweight placeholder — real widgets built lazily
            ph = ctk.CTkLabel(
                page,
                text=self.t("gui_loading"),
                font=ctk.CTkFont(size=13),
                text_color=COLORS["text_dim"],
            )
            ph.pack(anchor="w", padx=8, pady=24)
            self._page_placeholders[page_id] = ph

        self.app.ip_entry = None
        self.app.attack_entry = None

        # Show empty status shell immediately (widgets fill after paint)
        self._active_page = "status"
        for pid, frame in self._pages.items():
            if pid == "status":
                frame.pack(fill="both", expand=True, padx=16, pady=16)
            else:
                frame.pack_forget()
        for pid, nav in self._nav_buttons.items():
            self._set_nav_item_style(nav, pid == "status")

        if startup_mode == "minimized":
            self.app._tray_mode.set()
            root.withdraw()
        else:
            if not self.app._tray_mode.is_set():
                root.deiconify()
                try:
                    root.update_idletasks()
                except Exception:
                    pass
                def _startup_pin_gate():
                    try:
                        from client_gui_lock import GuiLock, require_gui_unlock
                        if GuiLock.instance().has_pin():
                            if not require_gui_unlock(self.app, reason="show"):
                                self.app._tray_mode.set()
                                root.withdraw()
                    except Exception as e:
                        log(f"[GUI] startup PIN gate: {e}")
                try:
                    root.after(200, _startup_pin_gate)
                except Exception:
                    _startup_pin_gate()

        # Staggered content + data (GUI already visible)
        try:
            root.after(30, lambda: self._ensure_page_built("status"))
            root.after(120, self._lazy_load_status_data)
            root.after(400, self._start_refresh_loop_once)
            root.after(600, self._start_update_banner_poll)
            # Prewarm delayed — early prewarm competed with Status paint and started IPC timers
            root.after(8000, lambda: self._prewarm_page("services"))
            root.after(10000, lambda: self._prewarm_page("iplist"))
            root.after(12000, lambda: self._prewarm_page("threat"))
            log("[PERF] GUI shell ready; status@30ms data@120ms prewarm@8s/10s/12s")
        except Exception:
            self._ensure_page_built("status")
            self._lazy_load_status_data()
            self._start_refresh_loop_once()
            try:
                self._start_update_banner_poll()
            except Exception:
                pass

    def _clear_page_placeholder(self, page_id: str):
        ph = self._page_placeholders.pop(page_id, None)
        if ph is None:
            return
        try:
            ph.destroy()
        except Exception:
            pass

    def _prewarm_page(self, page_id: str):
        """Build page widgets in idle time without switching away from current tab."""
        if self._pages_built.get(page_id) or getattr(self, "_pages_building", {}).get(page_id):
            return
        # Only prewarm if user is still on status (don't jank mid-interaction)
        if self._active_page not in ("status", page_id):
            # Retry later
            try:
                if self.root:
                    self.root.after(800, lambda p=page_id: self._prewarm_page(p))
            except Exception:
                pass
            return
        self._schedule_page_build(page_id)

    def _schedule_page_build(self, page_id: str):
        """Non-blocking page build on Tk idle."""
        if self._pages_built.get(page_id):
            return
        if not hasattr(self, "_pages_building"):
            self._pages_building = {}
        if self._pages_building.get(page_id):
            return
        self._pages_building[page_id] = True

        def _do():
            try:
                self._ensure_page_built(page_id)
            finally:
                self._pages_building[page_id] = False
                if page_id == self._active_page and page_id == "threat":
                    try:
                        self.root.after(30, self._lazy_load_threat_data)
                    except Exception:
                        self._lazy_load_threat_data()

        try:
            if self.root:
                self.root.after(0, _do)
            else:
                _do()
        except Exception:
            _do()

    def _ensure_page_built(self, page_id: str) -> bool:
        """Build page widgets (skeleton only — data loads separately)."""
        if self._pages_built.get(page_id):
            return False
        page = self._pages.get(page_id)
        if page is None:
            return False
        self._clear_page_placeholder(page_id)
        t0 = time.time()
        try:
            if page_id == "status":
                self._build_dashboard(page)
                self._ensure_pulse_blink()
            elif page_id == "threat":
                self._build_threat_center(page)
            elif page_id == "iplist":
                self._build_ip_activity_table(page)
            elif page_id == "services":
                self._build_services_section(page)
            elif page_id == "layers":
                self._build_security_layers(page)
            elif page_id == "settings":
                self._build_settings_page(page)
            else:
                return False
            self._pages_built[page_id] = True
            log(f"[PERF] page_build '{page_id}' {(time.time() - t0) * 1000:.0f}ms")
            return True
        except Exception as e:
            log(f"[PERF] page_build '{page_id}' FAILED {(time.time() - t0) * 1000:.0f}ms: {e}")
            self._pages_built[page_id] = True  # avoid tight retry loop
            return False

    def _lazy_load_status_data(self):
        """Fill status page data after widgets exist (async where possible)."""
        if self._page_data_loaded.get("status"):
            return
        self._page_data_loaded["status"] = True
        try:
            if not self._pages_built.get("status"):
                self._ensure_page_built("status")
            tok = self.app.state.get("token", "")
            if tok:
                self.app.refresh_attack_count(async_thread=True)
            self._refresh_dashboard()
            # IP Lists live on their own tab now.
        except Exception as e:
            log(f"[GUI] status data load: {e}")

    def _lazy_load_threat_data(self):
        if self._page_data_loaded.get("threat"):
            return
        if not self._pages_built.get("threat"):
            return
        self._page_data_loaded["threat"] = True
        try:
            # Heavy scans staggered — never all at once on tab click
            if self.root:
                self.root.after(50, self._refresh_security_intel)
                self.root.after(400, self._refresh_active_sessions)
                if hasattr(self, "_refresh_remote_desktop_status"):
                    self.root.after(700, self._refresh_remote_desktop_status)
            else:
                self._refresh_security_intel()
                self._refresh_active_sessions()
                if hasattr(self, "_refresh_remote_desktop_status"):
                    self._refresh_remote_desktop_status()
        except Exception as e:
            log(f"[GUI] threat data load: {e}")

    def _start_refresh_loop_once(self):
        if self._refresh_loop_started:
            return
        self._refresh_loop_started = True
        self._schedule_dashboard_refresh()

    def _show_page(self, page_id: str):
        """Instant tab switch — never sync-build on click (prewarm / idle build)."""
        t0 = time.time()
        self._active_page = page_id

        # Switch visibility first (feels instant)
        for pid, frame in self._pages.items():
            if pid == page_id:
                frame.pack(fill="both", expand=True, padx=16, pady=16)
            else:
                frame.pack_forget()
        for pid, nav in self._nav_buttons.items():
            self._set_nav_item_style(nav, pid == page_id)

        # If widgets missing, schedule build — do NOT block this click
        if not self._pages_built.get(page_id):
            self._schedule_page_build(page_id)
            log(f"[PERF] nav '{page_id}' switch {(time.time() - t0) * 1000:.0f}ms (build scheduled)")
            return

        # Data once (no heavy refresh every revisit)
        if page_id == "status" and not self._page_data_loaded.get("status"):
            try:
                self.root.after(50, self._lazy_load_status_data)
            except Exception:
                self._lazy_load_status_data()
        elif page_id == "iplist":
            try:
                self.root.after(30, self._fit_ip_table_to_viewport)
                self.root.after(50, lambda: self._refresh_ip_table(force_firewall=True))
            except Exception:
                self._fit_ip_table_to_viewport()
                self._refresh_ip_table(force_firewall=True)
        elif page_id == "threat" and not self._page_data_loaded.get("threat"):
            try:
                self.root.after(50, self._lazy_load_threat_data)
            except Exception:
                self._lazy_load_threat_data()
        elif page_id == "layers":
            # Always re-sync toggles with the cloud source of truth on revisit
            # so the shown state can never drift from the live daemon config.
            try:
                self.root.after(50, self._load_security_layers)
            except Exception:
                self._load_security_layers()
        elif page_id == "settings":
            try:
                self.root.after(50, self._load_settings_values)
                self.root.after(80, self._refresh_settings_pin_ui)
            except Exception:
                self._load_settings_values()
                self._refresh_settings_pin_ui()
        log(f"[PERF] nav '{page_id}' switch {(time.time() - t0) * 1000:.0f}ms")

    def _create_sidebar_nav_item(
        self, parent, page_id: str, icon: str, label: str,
    ) -> dict:
        """Sidebar satırı — sabit ikon sütunu + metin (emoji genişlik farkını önler)."""
        row = ctk.CTkFrame(
            parent, fg_color="transparent",
            height=NAV_ITEM_HEIGHT, corner_radius=10,
        )
        row.pack(fill="x", pady=2)
        row.pack_propagate(False)

        inner = ctk.CTkFrame(row, fg_color="transparent", corner_radius=10)
        inner.pack(fill="both", expand=True, padx=(NAV_PAD_X, NAV_PAD_X))

        icon_col = ctk.CTkFrame(inner, fg_color="transparent", width=NAV_ICON_WIDTH)
        icon_col.pack(side="left", fill="y")
        icon_col.pack_propagate(False)

        icon_lbl = ctk.CTkLabel(
            icon_col, text=icon, anchor="center",
            font=self._emoji_font(NAV_FONT_ICON),
            text_color=COLORS["text"],
        )
        icon_lbl.pack(expand=True, fill="both")

        text_lbl = ctk.CTkLabel(
            inner, text=label, anchor="w",
            font=ctk.CTkFont(size=NAV_FONT_LABEL),
            text_color=COLORS["text"],
        )
        text_lbl.pack(side="left", fill="x", expand=True, padx=(NAV_ICON_TEXT_GAP, 0))

        def _activate(_event=None):
            self._show_page(page_id)

        def _on_enter():
            if self._active_page != page_id:
                row.configure(fg_color=COLORS["nav_hover"])

        def _on_leave():
            if self._active_page != page_id:
                row.configure(fg_color="transparent")

        self._bind_hover_click(
            row,
            on_click=_activate,
            on_enter=_on_enter,
            on_leave=_on_leave,
        )

        return {"frame": row, "icon": icon_lbl, "text": text_lbl, "page_id": page_id}

    def _set_nav_item_style(self, nav: dict, active: bool):
        row = nav["frame"]
        icon_lbl = nav["icon"]
        text_lbl = nav["text"]
        if active:
            row.configure(fg_color=COLORS["nav_active"])
            icon_lbl.configure(text_color=COLORS["text_bright"])
            text_lbl.configure(text_color=COLORS["text_bright"])
        else:
            row.configure(fg_color="transparent")
            icon_lbl.configure(text_color=COLORS["text"])
            text_lbl.configure(text_color=COLORS["text"])

    # ═══════════════════════════════════════════════════════════════
    #  BİRLEŞİK ÜST BAR  (Kimlik + Dashboard + Menü — tek satır)
    # ═══════════════════════════════════════════════════════════════
    def _build_top_bar(self, root):
        """Sol: PC/IP | Token  —  Sağ: v3.0 | Dashboard | Ayarlar | Yardım"""
        bar = ctk.CTkFrame(root, fg_color=COLORS["sidebar"], corner_radius=0, height=48)
        bar.pack(fill="x", side="top")
        bar.pack_propagate(False)

        # Token & IP yükle
        token = self.app.state.get("token", "")
        public_ip = self.app.state.get("public_ip", "")
        from client_constants import SERVER_NAME, API_URL

        def _dashboard_url() -> str:
            base = API_URL.rsplit("/api", 1)[0]
            tok = self.app.state.get("token", "") or token
            if tok:
                return f"{base}/dashboard?token={tok}"
            return f"{base}/dashboard"

        # ════════ SOL TARAF ════════ #
        # PC Adı
        ctk.CTkLabel(
            bar, text=f"💻 {SERVER_NAME}",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=COLORS["text_bright"],
        ).pack(side="left", padx=(10, 2))

        # IP
        ip_lbl = ctk.CTkLabel(
            bar, text=f"({public_ip})" if public_ip else "",
            font=ctk.CTkFont(size=11),
            text_color=COLORS["text_dim"],
        )
        ip_lbl.pack(side="left", padx=(0, 6))
        self._identity_ip_lbl = ip_lbl

        # Separator
        ctk.CTkFrame(bar, width=1, fg_color=COLORS["border"]).pack(
            side="left", fill="y", padx=4, pady=7
        )

        # Token
        token_short = token[:16] + "…" if len(token) > 16 else token
        ctk.CTkLabel(
            bar, text=f"{self.t('lbl_token')}: {token_short}",
            font=ctk.CTkFont(size=11, family="Consolas"),
            text_color=COLORS["text_dim"],
        ).pack(side="left", padx=(6, 2))

        # Kopyala
        ctk.CTkButton(
            bar, text="📋", width=26, height=22,
            font=ctk.CTkFont(size=10),
            fg_color="transparent", hover_color=COLORS["accent"],
            corner_radius=4,
            command=lambda: self._copy_token_with_hint(token),
        ).pack(side="left", padx=(0, 4))

        # Hesaba bağla — API account-status (fallback: local cache)
        self._account_slot = ctk.CTkFrame(bar, fg_color="transparent")
        self._account_slot.pack(side="left", padx=(0, 4))
        self._render_account_link_controls(token)
        # Background sync (don't block UI build)
        try:
            self.root.after(800, lambda: self._sync_account_link_from_api(force_ui=True))
        except Exception:
            pass

        # ════════ SAĞ TARAF ════════ #
        # Yardım butonu
        help_btn = ctk.CTkButton(
            bar, text=f"❓ {self.t('menu_help')}",
            font=ctk.CTkFont(size=11), width=70, height=26,
            fg_color="transparent", hover_color=COLORS["accent"],
            text_color=COLORS["text"], corner_radius=5,
        )
        help_btn.pack(side="right", padx=(2, 8), pady=5)
        help_btn.configure(command=lambda: self._show_popup_menu(help_btn, "help"))

        # Ayarlar butonu
        settings_btn = ctk.CTkButton(
            bar, text=f"⚙ {self.t('menu_settings')}",
            font=ctk.CTkFont(size=11), width=76, height=26,
            fg_color="transparent", hover_color=COLORS["accent"],
            text_color=COLORS["text"], corner_radius=5,
        )
        settings_btn.pack(side="right", padx=2, pady=5)
        # Sidebar "Ayarlar" sekmesine git — eski popup menü çift anlam yaratıyordu
        settings_btn.configure(command=lambda: self._show_page("settings"))

        # Dashboard butonu
        ctk.CTkButton(
            bar, text=self.t("btn_dashboard"),
            font=ctk.CTkFont(size=11), width=90, height=26,
            fg_color=COLORS["accent"], hover_color=COLORS["blue"],
            text_color=COLORS["text_bright"], corner_radius=5,
            command=self._open_dashboard,
        ).pack(side="right", padx=2, pady=5)

        # Separator
        ctk.CTkFrame(bar, width=1, fg_color=COLORS["border"]).pack(
            side="right", fill="y", padx=4, pady=7
        )

        # Versiyon (text)
        from client_constants import DEBUG_MODE
        ver_text = f"v{__version__}"
        if DEBUG_MODE:
            ver_text += "  DEBUG"
        ctk.CTkLabel(
            bar, text=ver_text,
            font=ctk.CTkFont(size=11), text_color=COLORS["orange"] if DEBUG_MODE else COLORS["text_dim"],
        ).pack(side="right", padx=(4, 4))

        # Kaynak kullanımı (motor STATUS → CPU/RAM/ağ) — versiyonun solunda
        ctk.CTkFrame(bar, width=1, fg_color=COLORS["border"]).pack(
            side="right", fill="y", padx=4, pady=7
        )
        self._resource_badge = ctk.CTkLabel(
            bar,
            text=self.t("resource_badge_na"),
            font=ctk.CTkFont(size=10, family="Consolas"),
            text_color=COLORS["text_dim"],
            cursor="hand2",
        )
        self._resource_badge.pack(side="right", padx=(2, 2))
        try:
            self._resource_badge.bind("<Button-1>", lambda _e: self._detail_cpu_ram())
        except Exception:
            pass
        try:
            self.root.after(1200, self._refresh_resource_badge)
        except Exception:
            pass

    def _refresh_resource_badge(self):
        """Top-bar corner: motor process + host CPU/RAM/net from STATUS cache."""
        lbl = getattr(self, "_resource_badge", None)
        if lbl is None:
            return
        try:
            st = getattr(self, "_cached_daemon_status", None) or {}
            res = st.get("resources") if isinstance(st, dict) else None
            if not isinstance(res, dict) or not res:
                lbl.configure(text=self.t("resource_badge_na"), text_color=COLORS["text_dim"])
                return

            from client_resources import format_bps

            p_cpu = res.get("process_cpu_percent")
            p_ram = res.get("process_rss_mb")
            h_cpu = res.get("host_cpu_percent")
            h_ram = res.get("host_memory_percent")
            down = format_bps(res.get("net_recv_bps"))
            up = format_bps(res.get("net_sent_bps"))

            proc_bit = "—"
            if p_cpu is not None and p_ram is not None:
                proc_bit = f"{float(p_cpu):.0f}%/{float(p_ram):.0f}MB"
            elif p_ram is not None:
                proc_bit = f"{float(p_ram):.0f}MB"

            host_bit = "—"
            if h_cpu is not None and h_ram is not None:
                host_bit = f"{float(h_cpu):.0f}%/{float(h_ram):.0f}%"

            text = self.t("resource_badge").format(
                proc=proc_bit, host=host_bit, down=down, up=up
            )
            hot = False
            try:
                hot = float(h_cpu or 0) >= 90 or float(p_cpu or 0) >= 40
            except Exception:
                hot = False
            color = COLORS["orange"] if hot else COLORS["text_dim"]
            lbl.configure(text=text, text_color=color)

            prio = (res.get("priority") or {}).get("applied") or ""
            tip = self.t("resource_badge_tip").format(priority=prio or "—")
            try:
                lbl.configure(textvariable=None)
            except Exception:
                pass
            self._resource_badge_tip = tip
        except Exception:
            try:
                lbl.configure(text=self.t("resource_badge_na"), text_color=COLORS["text_dim"])
            except Exception:
                pass

    def _build_update_banner(self, root):
        """Top banner for dashboard self_update progress (daemon → ProgramData → GUI)."""
        self._update_banner = ctk.CTkFrame(
            root, fg_color=COLORS["card"], corner_radius=0, height=40,
            border_width=1, border_color=COLORS["orange"],
        )
        # Hidden until an update status appears
        self._update_banner_visible = False
        self._update_banner_last_phase = ""
        self._update_banner_toasted = ""
        self._update_banner_done_at = 0.0

        inner = ctk.CTkFrame(self._update_banner, fg_color="transparent")
        inner.pack(fill="both", expand=True, padx=12, pady=6)

        self._update_banner_icon = ctk.CTkLabel(
            inner, text="⬇️", font=self._emoji_font(14), text_color=COLORS["orange"],
        )
        self._update_banner_icon.pack(side="left", padx=(0, 8))

        text_col = ctk.CTkFrame(inner, fg_color="transparent")
        text_col.pack(side="left", fill="x", expand=True)

        self._update_banner_title = ctk.CTkLabel(
            text_col, text="",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=COLORS["orange"],
            anchor="w",
        )
        self._update_banner_title.pack(anchor="w")

        self._update_banner_detail = ctk.CTkLabel(
            text_col, text="",
            font=ctk.CTkFont(size=11),
            text_color=COLORS["text"],
            anchor="w",
        )
        self._update_banner_detail.pack(anchor="w")

        self._update_banner_ver = ctk.CTkLabel(
            inner, text="",
            font=ctk.CTkFont(size=11, family="Consolas"),
            text_color=COLORS["text_dim"],
        )
        self._update_banner_ver.pack(side="right", padx=(8, 4))

        self._update_banner_close = ctk.CTkButton(
            inner,
            text="✕",
            width=28,
            height=28,
            corner_radius=6,
            fg_color="transparent",
            hover_color=COLORS.get("card_hover", COLORS["card"]),
            text_color=COLORS["text_dim"],
            font=ctk.CTkFont(size=14, weight="bold"),
            command=self._dismiss_update_banner,
        )
        self._update_banner_close.pack(side="right", padx=(0, 0))

    def _dismiss_update_banner(self):
        """User closed the banner — clear ProgramData status so it stays gone."""
        try:
            from client_update_ui import clear_update_ui_status
            clear_update_ui_status()
        except Exception:
            pass
        self._update_banner_done_at = 0.0
        self._update_banner_last_phase = ""
        self._hide_update_banner()

    def _start_update_banner_poll(self):
        if getattr(self, "_update_banner_poll_started", False):
            return
        self._update_banner_poll_started = True
        self._poll_update_banner()

    def _poll_update_banner(self):
        try:
            self._refresh_update_banner()
        except Exception:
            pass
        try:
            if self.root and self.root.winfo_exists():
                self.root.after(1000, self._poll_update_banner)
        except Exception:
            pass

    def _hide_update_banner(self):
        banner = getattr(self, "_update_banner", None)
        if not banner:
            return
        try:
            if self._update_banner_visible:
                banner.pack_forget()
                self._update_banner_visible = False
        except Exception:
            pass

    def _show_update_banner(self):
        banner = getattr(self, "_update_banner", None)
        if not banner or self._update_banner_visible:
            return
        try:
            body = getattr(self, "_main_body", None)
            if body is not None:
                banner.pack(fill="x", side="top", before=body)
            else:
                banner.pack(fill="x", side="top")
            self._update_banner_visible = True
        except Exception:
            pass

    def _refresh_update_banner(self):
        from client_update_ui import get_update_ui_status, clear_update_ui_status
        from client_constants import VERSION as _CUR_VER

        st = get_update_ui_status(current_version=_CUR_VER)
        if not st:
            self._hide_update_banner()
            return

        phase = (st.get("phase") or "").strip().lower()
        from_v = (st.get("from_version") or "").strip().lstrip("vV")
        to_v = (st.get("to_version") or "").strip().lstrip("vV")
        progress = st.get("progress")
        err = (st.get("error") or "").strip()

        # Auto-dismiss success ~12s; failed ~45s (user can also ✕)
        dismiss_after = 12 if phase == "done" else (45 if phase == "failed" else 0)
        if dismiss_after:
            if not self._update_banner_done_at:
                self._update_banner_done_at = time.time()
            elif (time.time() - self._update_banner_done_at) > dismiss_after:
                clear_update_ui_status()
                self._hide_update_banner()
                self._update_banner_done_at = 0.0
                return
        else:
            self._update_banner_done_at = 0.0

        phase_keys = {
            "accepted": ("update_banner_accepted", "⬇️", "warning"),
            "downloading": ("update_banner_downloading", "⬇️", "info"),
            "staging": ("update_banner_staging", "📦", "info"),
            "installing": ("update_banner_installing", "⚙️", "warning"),
            "done": ("update_banner_done", "✅", "info"),
            "failed": ("update_banner_failed", "⚠️", "high"),
        }
        key, icon, toast_sev = phase_keys.get(phase, ("update_banner_accepted", "⬇️", "info"))
        title = self.t(key)
        if phase == "downloading" and progress is not None:
            try:
                title = self.t("update_banner_downloading_pct").format(pct=int(progress))
            except Exception:
                title = f"{title} ({progress}%)"

        detail = ""
        if from_v or to_v:
            left = f"v{from_v}" if from_v else "?"
            right = f"v{to_v}" if to_v else "?"
            detail = self.t("update_banner_version_line").format(from_v=left, to_v=right)
        if phase == "failed" and err:
            detail = (detail + " — " if detail else "") + err[:80]
            if err in ("update_stalled", "install_did_not_complete"):
                title = self.t("update_banner_stalled")

        border = COLORS["orange"]
        title_color = COLORS["orange"]
        if phase == "done":
            border = COLORS["green"]
            title_color = COLORS["green"]
        elif phase == "failed":
            border = COLORS["red"]
            title_color = COLORS["red"]
        elif phase in ("downloading", "staging"):
            border = COLORS["blue"]
            title_color = COLORS["blue"]

        try:
            self._update_banner.configure(border_color=border)
            self._update_banner_icon.configure(text=icon, text_color=title_color)
            self._update_banner_title.configure(text=title, text_color=title_color)
            self._update_banner_detail.configure(text=detail)
            self._update_banner_ver.configure(
                text=f"{from_v or '?'} → {to_v or '?'}" if (from_v or to_v) else ""
            )
        except Exception:
            pass

        self._show_update_banner()

        # Toast once per phase transition (accepted / fail / done)
        if phase != self._update_banner_last_phase:
            if phase in ("accepted", "failed", "done") or (
                not self._update_banner_last_phase and phase in ("downloading", "installing")
            ):
                try:
                    msg = title if phase != "accepted" else self.t("update_banner_accepted")
                    self.show_toast(
                        self.t("update_toast_title"),
                        msg,
                        severity=toast_sev,
                        duration_ms=6000 if phase != "failed" else 9000,
                    )
                except Exception:
                    pass
            self._update_banner_last_phase = phase

    def _render_account_link_controls(self, token: str = ""):
        """Rebuild account CTA / linked badge inside _account_slot."""
        from client_utils import is_account_linked, get_linked_account_email

        slot = getattr(self, "_account_slot", None)
        if slot is None:
            return
        try:
            for child in list(slot.winfo_children()):
                child.destroy()
        except Exception:
            pass

        tok = token or self.app.state.get("token", "") or ""
        linked = is_account_linked()
        self._account_linked = linked
        if linked:
            email = get_linked_account_email()
            label = f"✓ {self.t('btn_account_linked')}"
            if email:
                short = email if len(email) <= 28 else (email[:26] + "…")
                label = f"✓ {short}"
            ctk.CTkLabel(
                slot, text=label,
                font=ctk.CTkFont(size=10),
                text_color=COLORS["green"],
            ).pack(side="left")
            # Click badge → account manage (Settings) + My servers
            try:
                def _on_badge(_e=None):
                    try:
                        self._show_page("settings")
                        self._refresh_settings_account_section()
                    except Exception:
                        webbrowser.open(f"{self._account_base_url()}/servers")
                slot.bind("<Button-1>", _on_badge)
            except Exception:
                pass
        else:
            ctk.CTkButton(
                slot, text=self.t("btn_link_account"),
                width=100, height=22,
                font=ctk.CTkFont(size=10),
                fg_color=COLORS["accent"], hover_color=COLORS["blue"],
                text_color=COLORS["text_bright"], corner_radius=4,
                command=lambda: self._open_link_account(tok),
            ).pack(side="left")

    def _sync_account_link_from_api(self, *, force_ui: bool = False):
        """Refresh account_linked from cloud; update top-bar if state changed."""
        def _work():
            try:
                from client_utils import (
                    is_account_linked,
                    refresh_account_link_status,
                )
                tok = self.app.state.get("token", "") or ""
                if not tok:
                    return
                prev = is_account_linked()
                result = refresh_account_link_status(
                    tok,
                    api_client=getattr(self.app, "api_client", None),
                )
                now = is_account_linked()
                if force_ui or (result is not None and prev != now):
                    self._gui_safe(lambda: self._render_account_link_controls(tok))
                    self._gui_safe(self._refresh_settings_account_section)
            except Exception as e:
                log(f"account link sync error: {e}")

        try:
            import threading
            threading.Thread(target=_work, daemon=True, name="AccountLinkSync").start()
        except Exception:
            _work()

    def _account_base_url(self) -> str:
        from client_constants import API_URL
        return API_URL.rsplit("/api", 1)[0]

    def _copy_token_with_hint(self, token: str):
        """Copy agent token + instruct user how to link on web."""
        tok = token or self.app.state.get("token", "") or ""
        if not tok:
            messagebox.showwarning(self.t("warn"), self.t("err_no_token"))
            return
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(tok)
            self.root.update()
        except Exception as e:
            log(f"clipboard error: {e}")
            return
        messagebox.showinfo(
            self.t("copy"),
            self.t("token_copied_link_hint"),
        )
        try:
            from client_utils import clear_force_gui_onboarding
            clear_force_gui_onboarding()
        except Exception:
            pass
        try:
            self.show_toast(self.t("copy"), self.t("token_copied_toast"), "info")
        except Exception:
            pass

    def _open_dashboard(self):
        """Open web dashboard; after first open allow tray minimize."""
        try:
            from client_constants import API_URL
            base = API_URL.rsplit("/api", 1)[0]
            tok = self.app.state.get("token", "") or ""
            url = f"{base}/dashboard?token={tok}" if tok else f"{base}/dashboard"
            webbrowser.open(url)
        except Exception as e:
            log(f"open dashboard error: {e}")
        try:
            from client_utils import clear_force_gui_onboarding
            if self.app.state.get("token"):
                clear_force_gui_onboarding()
        except Exception:
            pass
        # Re-check link status after user may have linked on web
        try:
            self.root.after(5000, lambda: self._sync_account_link_from_api(force_ui=True))
        except Exception:
            pass

    def _open_link_account(self, token: str = ""):
        """In-app popup: email + password → link this agent token to YesNext Account."""
        tok = token or self.app.state.get("token", "") or ""
        if not tok:
            messagebox.showwarning(self.t("warn"), self.t("err_no_token"))
            return
        self._show_link_account_dialog(tok)

    def _show_link_account_dialog(self, token: str):
        """Modal dialog for account email/password linking."""
        try:
            dlg = ctk.CTkToplevel(self.root)
        except Exception:
            # Fallback: open web flow
            self._open_link_account_web(token)
            return

        dlg.title(self.t("btn_link_account"))
        dlg.resizable(False, False)
        dlg.grab_set()
        try:
            dlg.transient(self.root)
        except Exception:
            pass

        frame = ctk.CTkFrame(dlg, fg_color=COLORS["card"], corner_radius=10)
        frame.pack(fill="both", expand=True, padx=14, pady=14)

        ctk.CTkLabel(
            frame,
            text=self.t("link_account_dialog_title"),
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color=COLORS["text_bright"],
        ).pack(anchor="w", pady=(4, 6))

        ctk.CTkLabel(
            frame,
            text=self.t("link_account_dialog_hint"),
            font=ctk.CTkFont(size=11),
            text_color=COLORS["text_dim"],
            wraplength=360,
            justify="left",
        ).pack(anchor="w", pady=(0, 10))

        email_var = ctk.StringVar()
        pass_var = ctk.StringVar()
        status_var = ctk.StringVar(value="")

        # Prefill last known email from cache if any
        try:
            from client_utils import get_linked_account_email
            prev = get_linked_account_email()
            if prev:
                email_var.set(prev)
        except Exception:
            pass

        ctk.CTkLabel(frame, text=self.t("link_account_email"), text_color=COLORS["text"]).pack(anchor="w")
        email_entry = ctk.CTkEntry(frame, textvariable=email_var, width=360, height=32)
        email_entry.pack(fill="x", pady=(2, 8))

        ctk.CTkLabel(frame, text=self.t("link_account_password"), text_color=COLORS["text"]).pack(anchor="w")
        pass_entry = ctk.CTkEntry(frame, textvariable=pass_var, show="*", width=360, height=32)
        pass_entry.pack(fill="x", pady=(2, 8))

        status_lbl = ctk.CTkLabel(
            frame, textvariable=status_var, text_color=COLORS["orange"],
            font=ctk.CTkFont(size=11), wraplength=360, justify="left",
        )
        status_lbl.pack(anchor="w", pady=(0, 8))

        btn_row = ctk.CTkFrame(frame, fg_color="transparent")
        btn_row.pack(fill="x", pady=(4, 0))

        def _set_busy(busy: bool):
            state = "disabled" if busy else "normal"
            try:
                link_btn.configure(state=state)
                web_btn.configure(state=state)
                email_entry.configure(state=state)
                pass_entry.configure(state=state)
            except Exception:
                pass

        def _do_link():
            email = (email_var.get() or "").strip()
            password = pass_var.get() or ""
            if not email or not password:
                status_var.set(self.t("link_account_need_fields"))
                return
            _set_busy(True)
            status_var.set(self.t("link_account_working"))

            def _work():
                from client_api import link_account_with_credentials
                from client_constants import API_URL
                result = link_account_with_credentials(
                    email, password, token, api_url=str(API_URL), log_func=log,
                )

                def _done():
                    _set_busy(False)
                    if result.get("ok"):
                        try:
                            from client_utils import clear_force_gui_onboarding
                            clear_force_gui_onboarding()
                        except Exception:
                            pass
                        self._render_account_link_controls(token)
                        try:
                            self._refresh_settings_account_section()
                        except Exception:
                            pass
                        try:
                            dlg.destroy()
                        except Exception:
                            pass
                        messagebox.showinfo(
                            self.t("btn_account_linked"),
                            self.t("link_account_success"),
                        )
                        try:
                            self.show_toast(
                                self.t("btn_account_linked"),
                                self.t("link_account_success"),
                                "info",
                            )
                        except Exception:
                            pass
                        # Confirm from API
                        try:
                            self._sync_account_link_from_api(force_ui=True)
                        except Exception:
                            pass
                        return

                    err = result.get("error") or "link_failed"
                    if err == "invalid_credentials":
                        status_var.set(self.t("link_account_bad_credentials"))
                    elif err == "missing_token":
                        status_var.set(self.t("err_no_token"))
                    else:
                        status_var.set(self.t("link_account_failed").format(err=err))

                self._gui_safe(_done)

            import threading
            threading.Thread(target=_work, daemon=True, name="AccountLink").start()

        def _open_web():
            try:
                dlg.destroy()
            except Exception:
                pass
            self._open_link_account_web(token)

        link_btn = ctk.CTkButton(
            btn_row,
            text=self.t("btn_link_account"),
            width=150, height=32,
            fg_color=COLORS["accent"], hover_color=COLORS["blue"],
            command=_do_link,
        )
        link_btn.pack(side="left", padx=(0, 8))

        web_btn = ctk.CTkButton(
            btn_row,
            text=self.t("link_account_open_web"),
            width=140, height=32,
            fg_color="transparent", border_width=1,
            border_color=COLORS["border"], hover_color=COLORS["card_hover"],
            command=_open_web,
        )
        web_btn.pack(side="left")

        ctk.CTkButton(
            frame,
            text=self.t("update_not_now"),
            width=100, height=28,
            fg_color="transparent", text_color=COLORS["text_dim"],
            command=dlg.destroy,
        ).pack(anchor="e", pady=(10, 0))

        dlg.update_idletasks()
        w, h = 420, 340
        try:
            x = self.root.winfo_rootx() + (self.root.winfo_width() - w) // 2
            y = self.root.winfo_rooty() + (self.root.winfo_height() - h) // 2
            dlg.geometry(f"{w}x{h}+{max(0, x)}+{max(0, y)}")
        except Exception:
            dlg.geometry(f"{w}x{h}")

        email_entry.focus_set()
        dlg.bind("<Return>", lambda _e: _do_link())

    def _open_link_account_web(self, token: str = ""):
        """Legacy/fallback: copy token and open My servers in browser."""
        tok = token or self.app.state.get("token", "") or ""
        if tok:
            try:
                self.root.clipboard_clear()
                self.root.clipboard_append(tok)
                self.root.update()
            except Exception:
                pass
        base = self._account_base_url()
        url = f"{base}/servers" if tok else f"{base}/?login=1"
        try:
            webbrowser.open(url)
        except Exception as e:
            log(f"open link account error: {e}")
        msg = self.t("link_account_opened")
        if tok:
            msg = self.t("token_copied_link_hint")
        messagebox.showinfo(self.t("btn_link_account"), msg)
        try:
            from client_utils import clear_force_gui_onboarding
            if tok:
                clear_force_gui_onboarding()
        except Exception:
            pass
        try:
            self.show_toast(self.t("btn_link_account"), self.t("token_copied_toast"), "info")
        except Exception:
            pass
        for delay_ms in (8000, 20000, 45000):
            try:
                self.root.after(
                    delay_ms,
                    lambda: self._sync_account_link_from_api(force_ui=True),
                )
            except Exception:
                pass

    def _mark_account_linked(self):
        """Settings: already linked on web — hide Hesaba bağla CTA (offline fallback)."""
        try:
            from client_utils import set_account_linked, refresh_account_link_status
            tok = self.app.state.get("token", "") or ""
            api_state = refresh_account_link_status(
                tok, api_client=getattr(self.app, "api_client", None)
            )
            if api_state is True:
                messagebox.showinfo(self.t("info"), self.t("link_account_marked"))
                self._render_account_link_controls(tok)
                return
            set_account_linked(True, source="user_mark")
            self._account_linked = True
            messagebox.showinfo(self.t("info"), self.t("link_account_marked"))
            self._render_account_link_controls(tok)
        except Exception as e:
            log(f"mark account linked error: {e}")

    def _unmark_account_linked(self):
        """Settings: clear local mark (API remains source of truth when online)."""
        try:
            from client_utils import set_account_linked, refresh_account_link_status
            tok = self.app.state.get("token", "") or ""
            api_state = refresh_account_link_status(
                tok, api_client=getattr(self.app, "api_client", None)
            )
            if api_state is True:
                messagebox.showinfo(
                    self.t("info"),
                    self.t("link_account_api_still_linked"),
                )
                self._render_account_link_controls(tok)
                return
            set_account_linked(False, source="user_unmark")
            self._account_linked = False
            messagebox.showinfo(self.t("info"), self.t("link_account_unmarked"))
            self._render_account_link_controls(tok)
        except Exception as e:
            log(f"unmark account linked error: {e}")

    # ═══════════════════════════════════════════════════════════════
    #  BAŞLIK BANDI
    # ═══════════════════════════════════════════════════════════════
    def update_header_status(self, active=None):
        """Koruma durumu badge'ini güncelle.

        active: bool (eski API) veya 'full'|'monitoring'|'inactive' mode str.
        Never triggers IPC — uses cache via get_protection_mode().
        """
        try:
            mode = active
            if isinstance(active, bool) or active is None:
                if hasattr(self.app, "get_protection_mode"):
                    mode = self.app.get_protection_mode()
                else:
                    mode = "full" if active else "inactive"
            if mode == "monitoring":
                self._header_status.configure(
                    text="● " + self.t("protection_monitoring"),
                    text_color=COLORS["blue"],
                )
            elif mode == "full":
                self._header_status.configure(
                    text="● " + self.t("protection_active"),
                    text_color=COLORS["green"],
                )
            else:
                self._header_status.configure(
                    text="● " + self.t("protection_inactive"),
                    text_color=COLORS["red"],
                )
        except Exception:
            pass

    def _ensure_pulse_blink(self):
        """Start header pulse once (no IPC — uses cached protection mode)."""
        if getattr(self, "_pulse_started", False):
            return
        self._pulse_started = True
        self._start_pulse_blink()
        log("[PERF] pulse blink started (cache-only)")

    # ═══════════════════════════════════════════════════════════════
    #  SECURITY LAYERS — cloud source of truth, immediate daemon push
    # ═══════════════════════════════════════════════════════════════
    def _build_security_layers(self, parent):
        shell = ctk.CTkFrame(parent, fg_color=COLORS["card"], corner_radius=12)
        shell.pack(fill="x", pady=(0, 12))

        ctk.CTkLabel(
            shell, text=f"⚙  {self.t('layers_title')}",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color=COLORS["text_bright"],
        ).pack(anchor="w", padx=18, pady=(16, 2))
        ctk.CTkLabel(
            shell, text=self.t("layers_subtitle"), justify="left", wraplength=760,
            font=ctk.CTkFont(size=12), text_color=COLORS["text_dim"],
        ).pack(anchor="w", padx=18, pady=(0, 12))

        safety = ctk.CTkFrame(
            shell, fg_color=COLORS["bg"], corner_radius=8,
            border_width=1, border_color=COLORS["orange"],
        )
        safety.pack(fill="x", padx=18, pady=(0, 12))
        self._layers_mode_banner_frame = safety
        self._layers_mode_banner = ctk.CTkLabel(
            safety, text=f"🛟  {self.t('layers_mode_observe')}",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=COLORS["orange"],
            justify="left", wraplength=740,
        )
        self._layers_mode_banner.pack(anchor="w", padx=12, pady=9)

        # Defense Policy education + mode actions (contract 1.4.19)
        self._build_defense_policy_card(shell)

        self._layer_switches = {}
        self._layer_values = {}
        definitions = [
            (
                "ransomware_protection_enabled",
                self.t("layers_ransomware"),
                self.t("layers_ransomware_desc"),
            ),
            (
                "canary_files_enabled",
                self.t("layers_canary"),
                self.t("layers_canary_desc"),
            ),
            (
                "network_guard.enabled",
                self.t("layers_network_guard"),
                self.t("layers_network_guard_desc"),
            ),
        ]
        for key, title, description in definitions:
            row = ctk.CTkFrame(
                shell, fg_color=COLORS["bg"], corner_radius=8,
                border_width=1, border_color=COLORS["border"],
            )
            row.pack(fill="x", padx=18, pady=5)
            text = ctk.CTkFrame(row, fg_color="transparent")
            text.pack(side="left", fill="x", expand=True, padx=12, pady=10)
            ctk.CTkLabel(
                text, text=title, font=ctk.CTkFont(size=13, weight="bold"),
                text_color=COLORS["text_bright"],
            ).pack(anchor="w")
            ctk.CTkLabel(
                text, text=description, justify="left", wraplength=650,
                font=ctk.CTkFont(size=11), text_color=COLORS["text_dim"],
            ).pack(anchor="w", pady=(2, 0))
            switch = ctk.CTkSwitch(
                row, text="", width=48,
                command=lambda k=key: self._on_security_layer_toggle(k),
                state="disabled",
            )
            switch.pack(side="right", padx=14)
            self._layer_switches[key] = switch

        footer = ctk.CTkFrame(shell, fg_color="transparent")
        footer.pack(fill="x", padx=18, pady=(8, 16))
        self._layers_sync_label = ctk.CTkLabel(
            footer, text=self.t("layers_syncing"),
            font=ctk.CTkFont(size=11), text_color=COLORS["text_dim"],
        )
        self._layers_sync_label.pack(side="left")
        ctk.CTkButton(
            footer, text=f"🛠 {self.t('prot_manage_settings')}",
            font=ctk.CTkFont(size=11), width=110, height=26,
            fg_color="transparent", hover_color=COLORS["accent"],
            border_width=1, border_color=COLORS["border"],
            text_color=COLORS["text"], corner_radius=6,
            command=lambda: self._show_page("settings"),
        ).pack(side="right")
        self._load_security_layers()

    def _build_defense_policy_card(self, parent):
        """Observe / Balanced / Paranoid education + CTA (contract 1.4.19)."""
        card = ctk.CTkFrame(
            parent, fg_color=COLORS["bg"], corner_radius=8,
            border_width=1, border_color=COLORS["border"],
        )
        card.pack(fill="x", padx=18, pady=(0, 12))
        self._dp_card = card
        self._dp_title = ctk.CTkLabel(
            card, text=self.t("dp_title"),
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=COLORS["text_bright"],
        )
        self._dp_title.pack(anchor="w", padx=12, pady=(10, 2))
        self._dp_status = ctk.CTkLabel(
            card, text="", justify="left", wraplength=720,
            font=ctk.CTkFont(size=11), text_color=COLORS["text_dim"],
        )
        self._dp_status.pack(anchor="w", padx=12, pady=(0, 6))
        edu = ctk.CTkFrame(card, fg_color="transparent")
        edu.pack(fill="x", padx=8, pady=(0, 6))
        try:
            from client_defense_policy import all_education
            lang = "tr"
            try:
                lang = "en" if str(getattr(self, "lang", "tr")).lower().startswith("en") else "tr"
            except Exception:
                pass
            for item in all_education(lang):
                row = ctk.CTkFrame(edu, fg_color="transparent")
                row.pack(fill="x", padx=4, pady=2)
                ctk.CTkLabel(
                    row, text=f"• {item.get('title')}:",
                    font=ctk.CTkFont(size=11, weight="bold"),
                    text_color=COLORS["text"],
                ).pack(anchor="w")
                ctk.CTkLabel(
                    row, text=item.get("blurb") or "",
                    justify="left", wraplength=700,
                    font=ctk.CTkFont(size=10), text_color=COLORS["text_dim"],
                ).pack(anchor="w")
        except Exception:
            pass
        btns = ctk.CTkFrame(card, fg_color="transparent")
        btns.pack(fill="x", padx=10, pady=(4, 12))
        self._dp_btn_balanced = ctk.CTkButton(
            btns, text=self.t("dp_btn_balanced"),
            font=ctk.CTkFont(size=11), height=28, width=160,
            fg_color=COLORS.get("green", "#2d6a4f"),
            command=lambda: self._set_defense_policy_gui("balanced"),
        )
        self._dp_btn_balanced.pack(side="left", padx=4)
        self._dp_btn_observe = ctk.CTkButton(
            btns, text=self.t("dp_btn_observe_lock"),
            font=ctk.CTkFont(size=11), height=28, width=160,
            fg_color="transparent", border_width=1, border_color=COLORS["border"],
            text_color=COLORS["text"],
            command=self._lock_observe_gui,
        )
        self._dp_btn_observe.pack(side="left", padx=4)
        self._dp_btn_paranoid = ctk.CTkButton(
            btns, text=self.t("dp_btn_paranoid"),
            font=ctk.CTkFont(size=11), height=28, width=140,
            fg_color="transparent", border_width=1, border_color=COLORS["orange"],
            text_color=COLORS["orange"],
            command=lambda: self._set_defense_policy_gui("paranoid"),
        )
        self._dp_btn_paranoid.pack(side="left", padx=4)
        self._refresh_defense_policy_card()

    def _refresh_defense_policy_card(self):
        try:
            from client_defense_policy import education_for, get_state, promote_due_info
            st = get_state()
            due = promote_due_info()
            policy = str(st.get("policy_name") or "observe").lower()
            edu = education_for(policy, "tr")
            days = int(st.get("observe_auto_promote_days") or 3)
            extra = ""
            if policy == "observe" and not st.get("defense_policy_locked"):
                if due.get("due"):
                    extra = " — " + self.t("dp_promote_due")
                elif due.get("in_sec") is not None:
                    extra = f" — {self.t('dp_promote_in')} ~{max(1, int(due['in_sec']) // 86400)}g / {days}g"
            text = (
                f"{self.t('dp_current')}: {edu.get('title')} "
                f"({policy}){extra}\n{edu.get('blurb')}"
            )
            if getattr(self, "_dp_status", None):
                self._dp_status.configure(text=text)
            self._refresh_layers_mode_banner(policy)
            self._refresh_defense_policy_buttons(policy, bool(st.get("defense_policy_locked")))
        except Exception:
            pass

    def _refresh_layers_mode_banner(self, policy: str):
        """Top safety strip must match active defense mode (not a stale observe tip)."""
        label = getattr(self, "_layers_mode_banner", None)
        frame = getattr(self, "_layers_mode_banner_frame", None)
        if not label:
            return
        key = {
            "observe": "layers_mode_observe",
            "balanced": "layers_mode_balanced",
            "paranoid": "layers_mode_paranoid",
        }.get(str(policy or "observe").lower(), "layers_mode_observe")
        color = {
            "observe": COLORS["orange"],
            "balanced": COLORS.get("green", "#2d6a4f"),
            "paranoid": COLORS.get("red", "#c1121f"),
        }.get(str(policy or "observe").lower(), COLORS["orange"])
        try:
            label.configure(text=f"🛟  {self.t(key)}", text_color=color)
            if frame is not None:
                frame.configure(border_color=color)
        except Exception:
            pass

    def _refresh_defense_policy_buttons(self, policy: str, locked: bool = False):
        """Highlight the active mode; keep others as clear switch actions."""
        policy = str(policy or "observe").lower()
        green = COLORS.get("green", "#2d6a4f")
        orange = COLORS["orange"]
        transparent = "transparent"
        border = COLORS["border"]
        text = COLORS["text"]

        bal = getattr(self, "_dp_btn_balanced", None)
        obs = getattr(self, "_dp_btn_observe", None)
        par = getattr(self, "_dp_btn_paranoid", None)
        if bal:
            if policy == "balanced":
                bal.configure(
                    text=self.t("dp_btn_balanced_active"),
                    fg_color=green,
                    state="disabled",
                )
            else:
                bal.configure(
                    text=self.t("dp_btn_balanced"),
                    fg_color=green,
                    state="normal",
                )
        if obs:
            if policy == "observe":
                obs.configure(
                    text=self.t("dp_btn_observe_lock"),
                    fg_color=transparent,
                    border_width=1,
                    border_color=orange if not locked else border,
                    text_color=orange if not locked else text,
                    state="normal",
                    command=self._lock_observe_gui,
                )
            else:
                obs.configure(
                    text=self.t("dp_btn_observe"),
                    fg_color=transparent,
                    border_width=1,
                    border_color=border,
                    text_color=text,
                    state="normal",
                    command=lambda: self._set_defense_policy_gui("observe"),
                )
        if par:
            if policy == "paranoid":
                par.configure(
                    text=self.t("dp_btn_paranoid_active"),
                    fg_color=orange,
                    text_color=COLORS.get("text_bright", "#fff"),
                    state="disabled",
                )
            else:
                par.configure(
                    text=self.t("dp_btn_paranoid"),
                    fg_color=transparent,
                    border_width=1,
                    border_color=orange,
                    text_color=orange,
                    state="normal",
                )

    def _set_defense_policy_gui(self, policy_name: str):
        token = self.app.state.get("token", "")

        def _worker():
            try:
                from client_defense_policy import set_policy_user
                st = set_policy_user(policy_name)
                if token and self.app.api_client:
                    self.app.api_client.update_threat_config(token, {
                        "protection": {
                            "defense_policy": policy_name,
                            "isolate_armed": False,
                            "policy_user_set": True,
                            "observe_auto_promote_enabled": policy_name == "observe",
                            "defense_rules": dict(st.get("rules") or {}),
                        }
                    })
            except Exception as e:
                log(f"[GUI] defense_policy set error: {e}")
            self._gui_safe(self._refresh_defense_policy_card)

        threading.Thread(target=_worker, name="GUI-DefensePolicy", daemon=True).start()

    def _lock_observe_gui(self):
        token = self.app.state.get("token", "")

        def _worker():
            try:
                from client_defense_policy import set_observe_locked, set_policy_user
                set_policy_user("observe")
                set_observe_locked(True)
                if token and self.app.api_client:
                    self.app.api_client.update_threat_config(token, {
                        "protection": {
                            "defense_policy": "observe",
                            "defense_policy_locked": True,
                            "observe_auto_promote_enabled": False,
                            "policy_user_set": True,
                        }
                    })
            except Exception as e:
                log(f"[GUI] observe lock error: {e}")
            self._gui_safe(self._refresh_defense_policy_card)

        threading.Thread(target=_worker, name="GUI-ObserveLock", daemon=True).start()

    @staticmethod
    def _effective_threat_config(payload: dict) -> dict:
        if not isinstance(payload, dict):
            return {}
        nested = payload.get("config")
        return nested if isinstance(nested, dict) else payload

    def _set_layer_controls(self, config: dict):
        protection = config.get("protection") or {}
        network_guard = protection.get("network_guard") or {}
        values = {
            "ransomware_protection_enabled": bool(
                config.get("ransomware_protection_enabled", True)
            ),
            "canary_files_enabled": bool(config.get("canary_files_enabled", True)),
            "network_guard.enabled": bool(network_guard.get("enabled", True)),
        }
        self._layer_values = values
        for key, switch in getattr(self, "_layer_switches", {}).items():
            try:
                # CTkSwitch.select()/deselect() are no-ops while the widget is
                # disabled, so enable it FIRST and only then set the knob state.
                switch.configure(state="normal")
                if values.get(key, True):
                    switch.select()
                else:
                    switch.deselect()
            except Exception:
                pass
        try:
            self._layers_sync_label.configure(
                text=f"✓ {self.t('layers_synced')}", text_color=COLORS["green"]
            )
        except Exception:
            pass

    def _load_security_layers(self):
        token = self.app.state.get("token", "")
        if not token:
            self._layers_sync_label.configure(
                text=self.t("layers_no_token"), text_color=COLORS["orange"]
            )
            return

        def _worker():
            config = self.app.api_client.fetch_threat_config(token) or {}
            self._gui_safe(
                lambda: self._set_layer_controls(
                    self._effective_threat_config(config)
                )
            )

        threading.Thread(
            target=_worker, name="GUI-SecurityLayers-Load", daemon=True
        ).start()

    def _on_security_layer_toggle(self, key: str):
        switch = self._layer_switches.get(key)
        if switch is None:
            return
        new_value = bool(switch.get())
        old_value = bool(self._layer_values.get(key, not new_value))
        token = self.app.state.get("token", "")
        if not token:
            if old_value:
                switch.select()
            else:
                switch.deselect()
            self._layers_sync_label.configure(
                text=self.t("layers_no_token"), text_color=COLORS["orange"]
            )
            return

        for ctl in self._layer_switches.values():
            ctl.configure(state="disabled")
        self._layers_sync_label.configure(
            text=self.t("layers_syncing"), text_color=COLORS["blue"]
        )
        patch = (
            {"protection": {"network_guard": {"enabled": new_value}}}
            if key == "network_guard.enabled"
            else {key: new_value}
        )

        def _worker():
            response = self.app.api_client.update_threat_config(token, patch)
            if response is None:
                def _rollback():
                    # Re-enable before select/deselect — a disabled CTkSwitch
                    # ignores select()/deselect() and would keep the old knob.
                    for ctl in self._layer_switches.values():
                        ctl.configure(state="normal")
                    if old_value:
                        switch.select()
                    else:
                        switch.deselect()
                    self._layers_sync_label.configure(
                        text=self.t("layers_sync_failed"),
                        text_color=COLORS["red"],
                    )
                self._gui_safe(_rollback)
                return

            effective = self._effective_threat_config(response)
            # Some API versions return only {status:"ok"}; re-read the source
            # of truth instead of assuming the requested value is effective.
            if not any(k in effective for k in (
                "ransomware_protection_enabled", "canary_files_enabled", "protection"
            )):
                effective = self._effective_threat_config(
                    self.app.api_client.fetch_threat_config(token) or {}
                )
            self._gui_safe(lambda: self._set_layer_controls(effective))

        threading.Thread(
            target=_worker, name="GUI-SecurityLayers-Save", daemon=True
        ).start()

    # ═══════════════════════════════════════════════════════════════
    #  TAB 5: AYARLAR — cloud threats/config ile çift yönlü eşitleme
    # ═══════════════════════════════════════════════════════════════
    def _build_settings_page(self, parent):
        """Settings tab — widgets generated from client_settings_util.SECTIONS."""
        from client_settings_util import SECTIONS

        shell = ctk.CTkFrame(parent, fg_color=COLORS["card"], corner_radius=12)
        shell.pack(fill="x", pady=(0, 12))

        ctk.CTkLabel(
            shell, text=f"🛠  {self.t('settings_title')}",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color=COLORS["text_bright"],
        ).pack(anchor="w", padx=18, pady=(16, 2))
        ctk.CTkLabel(
            shell, text=self.t("settings_subtitle"), justify="left", wraplength=760,
            font=ctk.CTkFont(size=12), text_color=COLORS["text_dim"],
        ).pack(anchor="w", padx=18, pady=(0, 12))

        self._settings_widgets: Dict[str, dict] = {}

        for sec_label_key, fields in SECTIONS:
            sec = ctk.CTkFrame(
                shell, fg_color=COLORS["bg"], corner_radius=8,
                border_width=1, border_color=COLORS["border"],
            )
            sec.pack(fill="x", padx=18, pady=6)
            ctk.CTkLabel(
                sec, text=self.t(sec_label_key),
                font=ctk.CTkFont(size=13, weight="bold"),
                text_color=COLORS["text_bright"],
            ).pack(anchor="w", padx=12, pady=(10, 4))

            for flat_key, kind, label_key, extra in fields:
                row = ctk.CTkFrame(sec, fg_color="transparent")
                row.pack(fill="x", padx=12, pady=3)
                ctk.CTkLabel(
                    row, text=self.t(label_key), font=ctk.CTkFont(size=12),
                    text_color=COLORS["text"], anchor="w",
                ).pack(side="left", fill="x", expand=True)

                if kind == "bool":
                    widget = ctk.CTkSwitch(row, text="", width=48, state="disabled")
                    widget.pack(side="right", padx=4)
                    meta = {"kind": kind, "widget": widget}
                elif kind == "choice":
                    from client_settings_util import CHOICE_LABEL_KEYS
                    label_map = CHOICE_LABEL_KEYS.get(flat_key, {})
                    # Display human labels; keep reverse map for save
                    display_values = [
                        self.t(label_map[v]) if v in label_map else v
                        for v in (extra or [])
                    ]
                    value_by_display = {
                        (self.t(label_map[v]) if v in label_map else v): v
                        for v in (extra or [])
                    }
                    display_by_value = {v: d for d, v in value_by_display.items()}
                    first = display_values[0] if display_values else ""
                    var = ctk.StringVar(value=first)
                    widget = ctk.CTkOptionMenu(
                        row, values=display_values, variable=var,
                        width=180, height=26, font=ctk.CTkFont(size=11),
                        state="disabled",
                    )
                    widget._settings_var = var
                    widget.pack(side="right", padx=4)
                    meta = {
                        "kind": kind, "widget": widget,
                        "value_by_display": value_by_display,
                        "display_by_value": display_by_value,
                    }
                elif kind in ("int", "time"):
                    widget = ctk.CTkEntry(
                        row, width=80, height=26, font=ctk.CTkFont(size=12),
                        justify="center", state="disabled",
                    )
                    widget.pack(side="right", padx=4)
                    meta = {"kind": kind, "widget": widget}
                else:  # str
                    widget = ctk.CTkEntry(
                        row, width=280, height=26, font=ctk.CTkFont(size=12),
                        state="disabled",
                    )
                    widget.pack(side="right", padx=4)
                    meta = {"kind": kind, "widget": widget}

                self._settings_widgets[flat_key] = meta
            ctk.CTkFrame(sec, height=6, fg_color="transparent").pack()

        # Yerel güvenlik PIN — cloud SECTIONS dışında (GuiLock)
        self._build_settings_account_section(shell)
        self._build_settings_pin_section(shell)

        # Alt satır: durum etiketi + kaydet
        footer = ctk.CTkFrame(shell, fg_color="transparent")
        footer.pack(fill="x", padx=18, pady=(8, 16))
        self._settings_status_label = ctk.CTkLabel(
            footer, text=self.t("layers_syncing"),
            font=ctk.CTkFont(size=11), text_color=COLORS["text_dim"],
        )
        self._settings_status_label.pack(side="left")
        self._settings_save_btn = ctk.CTkButton(
            footer, text=self.t("settings_save"),
            font=ctk.CTkFont(size=12, weight="bold"), width=140, height=30,
            fg_color=COLORS["accent"], hover_color=COLORS["blue"],
            text_color=COLORS["text_bright"], corner_radius=6,
            command=self._save_settings, state="disabled",
        )
        self._settings_save_btn.pack(side="right")

        # Title-row save — visible without scrolling past webhook
        self._settings_save_btn_top = ctk.CTkButton(
            shell, text=self.t("settings_save"),
            font=ctk.CTkFont(size=12, weight="bold"), width=140, height=28,
            fg_color=COLORS["accent"], hover_color=COLORS["blue"],
            text_color=COLORS["text_bright"], corner_radius=6,
            command=self._save_settings, state="disabled",
        )
        self._settings_save_btn_top.place(relx=1.0, x=-18, y=18, anchor="ne")

        self._load_settings_values()
        self._refresh_settings_pin_ui()

    def _build_settings_account_section(self, parent):
        """Hesap bağlantısı — durum, bağla / ayır / Sunucularım (Ayarlar'da görünür)."""
        sec = ctk.CTkFrame(
            parent, fg_color=COLORS["bg"], corner_radius=8,
            border_width=1, border_color=COLORS["border"],
        )
        sec.pack(fill="x", padx=18, pady=6)
        self._settings_account_frame = sec
        ctk.CTkLabel(
            sec, text=self.t("settings_account_title"),
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=COLORS["text_bright"],
        ).pack(anchor="w", padx=12, pady=(10, 2))
        ctk.CTkLabel(
            sec, text=self.t("settings_account_hint"),
            font=ctk.CTkFont(size=11), text_color=COLORS["text_dim"],
            justify="left", wraplength=720,
        ).pack(anchor="w", padx=12, pady=(0, 8))
        self._settings_account_status = ctk.CTkLabel(
            sec, text="",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=COLORS["text"],
            justify="left", wraplength=720,
        )
        self._settings_account_status.pack(anchor="w", padx=12, pady=(0, 8))
        btns = ctk.CTkFrame(sec, fg_color="transparent")
        btns.pack(fill="x", padx=10, pady=(0, 12))
        self._settings_account_btn_link = ctk.CTkButton(
            btns, text=self.t("btn_link_account"),
            font=ctk.CTkFont(size=11), height=28, width=130,
            fg_color=COLORS["accent"],
            command=lambda: self._open_link_account(self.app.state.get("token", "")),
        )
        self._settings_account_btn_link.pack(side="left", padx=4)
        self._settings_account_btn_unlink = ctk.CTkButton(
            btns, text=self.t("btn_unlink_account"),
            font=ctk.CTkFont(size=11), height=28, width=140,
            fg_color="transparent", border_width=1, border_color=COLORS["orange"],
            text_color=COLORS["orange"],
            command=self._open_unlink_account,
        )
        self._settings_account_btn_unlink.pack(side="left", padx=4)
        ctk.CTkButton(
            btns, text=self.t("menu_open_my_servers"),
            font=ctk.CTkFont(size=11), height=28, width=120,
            fg_color="transparent", border_width=1, border_color=COLORS["border"],
            text_color=COLORS["text"],
            command=lambda: webbrowser.open(f"{self._account_base_url()}/servers"),
        ).pack(side="left", padx=4)
        ctk.CTkButton(
            btns, text=self.t("settings_account_refresh"),
            font=ctk.CTkFont(size=11), height=28, width=100,
            fg_color="transparent", border_width=1, border_color=COLORS["border"],
            text_color=COLORS["text"],
            command=lambda: self._sync_account_link_from_api(force_ui=True),
        ).pack(side="left", padx=4)
        self._refresh_settings_account_section()

    def _refresh_settings_account_section(self):
        try:
            from client_utils import get_linked_account_email, is_account_linked
            linked = is_account_linked()
            email = get_linked_account_email()
            lbl = getattr(self, "_settings_account_status", None)
            btn_link = getattr(self, "_settings_account_btn_link", None)
            btn_unlink = getattr(self, "_settings_account_btn_unlink", None)
            if lbl:
                if linked:
                    shown = email or self.t("btn_account_linked")
                    lbl.configure(
                        text=self.t("settings_account_linked_fmt").format(email=shown),
                        text_color=COLORS["green"],
                    )
                else:
                    lbl.configure(
                        text=self.t("settings_account_not_linked"),
                        text_color=COLORS["text_dim"],
                    )
            if btn_link:
                btn_link.configure(state="disabled" if linked else "normal")
            if btn_unlink:
                btn_unlink.configure(state="normal" if linked else "disabled")
        except Exception:
            pass

    def _open_unlink_account(self):
        tok = self.app.state.get("token", "") or ""
        if not tok:
            messagebox.showwarning(self.t("warn"), self.t("err_no_token"))
            return
        self._show_unlink_account_dialog(tok)

    def _show_unlink_account_dialog(self, token: str):
        """Confirm unlink with account email+password (cloud source of truth)."""
        try:
            dlg = ctk.CTkToplevel(self.root)
        except Exception:
            webbrowser.open(f"{self._account_base_url()}/servers")
            messagebox.showinfo(self.t("info"), self.t("link_account_api_still_linked"))
            return

        dlg.title(self.t("btn_unlink_account"))
        dlg.resizable(False, False)
        dlg.grab_set()
        try:
            dlg.transient(self.root)
        except Exception:
            pass

        frame = ctk.CTkFrame(dlg, fg_color=COLORS["card"], corner_radius=10)
        frame.pack(fill="both", expand=True, padx=14, pady=14)

        ctk.CTkLabel(
            frame,
            text=self.t("unlink_account_dialog_title"),
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color=COLORS["text_bright"],
        ).pack(anchor="w", pady=(4, 6))
        ctk.CTkLabel(
            frame,
            text=self.t("unlink_account_dialog_hint"),
            font=ctk.CTkFont(size=11),
            text_color=COLORS["text_dim"],
            wraplength=360,
            justify="left",
        ).pack(anchor="w", pady=(0, 10))

        email_var = ctk.StringVar()
        pass_var = ctk.StringVar()
        status_var = ctk.StringVar(value="")
        try:
            from client_utils import get_linked_account_email
            prev = get_linked_account_email()
            if prev:
                email_var.set(prev)
        except Exception:
            pass

        ctk.CTkLabel(frame, text=self.t("link_account_email"), text_color=COLORS["text"]).pack(anchor="w")
        email_entry = ctk.CTkEntry(frame, textvariable=email_var, width=360, height=32)
        email_entry.pack(fill="x", pady=(2, 8))
        ctk.CTkLabel(frame, text=self.t("link_account_password"), text_color=COLORS["text"]).pack(anchor="w")
        pass_entry = ctk.CTkEntry(frame, textvariable=pass_var, show="*", width=360, height=32)
        pass_entry.pack(fill="x", pady=(2, 8))
        status_lbl = ctk.CTkLabel(
            frame, textvariable=status_var, text_color=COLORS["orange"],
            font=ctk.CTkFont(size=11), wraplength=360, justify="left",
        )
        status_lbl.pack(anchor="w", pady=(0, 8))
        btn_row = ctk.CTkFrame(frame, fg_color="transparent")
        btn_row.pack(fill="x", pady=(4, 0))

        def _set_busy(busy: bool):
            state = "disabled" if busy else "normal"
            try:
                unlink_btn.configure(state=state)
                web_btn.configure(state=state)
                email_entry.configure(state=state)
                pass_entry.configure(state=state)
            except Exception:
                pass

        def _do_unlink():
            email = (email_var.get() or "").strip()
            password = pass_var.get() or ""
            if not email or not password:
                status_var.set(self.t("link_account_need_fields"))
                return
            if not messagebox.askyesno(
                self.t("btn_unlink_account"),
                self.t("unlink_account_confirm"),
            ):
                return
            _set_busy(True)
            status_var.set(self.t("unlink_account_working"))

            def _work():
                from client_api import unlink_account_with_credentials
                result = unlink_account_with_credentials(
                    email, password, token, log_func=log,
                )

                def _done():
                    _set_busy(False)
                    if result.get("ok"):
                        try:
                            dlg.destroy()
                        except Exception:
                            pass
                        messagebox.showinfo(
                            self.t("info"), self.t("unlink_account_success")
                        )
                        self._render_account_link_controls(token)
                        self._refresh_settings_account_section()
                        return
                    err = str(result.get("error") or "")
                    if err == "invalid_credentials":
                        status_var.set(self.t("link_account_bad_credentials"))
                    elif err == "unlink_api_unavailable":
                        status_var.set(self.t("unlink_account_use_web"))
                        try:
                            webbrowser.open(f"{self._account_base_url()}/servers")
                        except Exception:
                            pass
                    else:
                        status_var.set(
                            self.t("unlink_account_failed").format(err=err or "?")
                        )

                self._gui_safe(_done)

            threading.Thread(target=_work, daemon=True, name="AccountUnlink").start()

        unlink_btn = ctk.CTkButton(
            btn_row, text=self.t("btn_unlink_account"),
            fg_color=COLORS["orange"], text_color=COLORS["text_bright"],
            width=140, height=32, command=_do_unlink,
        )
        unlink_btn.pack(side="left", padx=(0, 8))
        web_btn = ctk.CTkButton(
            btn_row, text=self.t("menu_open_my_servers"),
            fg_color="transparent", border_width=1, border_color=COLORS["border"],
            text_color=COLORS["text"], width=120, height=32,
            command=lambda: webbrowser.open(f"{self._account_base_url()}/servers"),
        )
        web_btn.pack(side="left")
        try:
            email_entry.focus_set()
        except Exception:
            pass

    def _build_settings_pin_section(self, parent):
        """Local GUI PIN: set / change / clear (not part of cloud threat-config)."""
        sec = ctk.CTkFrame(
            parent, fg_color=COLORS["bg"], corner_radius=8,
            border_width=1, border_color=COLORS["border"],
        )
        sec.pack(fill="x", padx=18, pady=6)
        self._settings_pin_section = sec

        ctk.CTkLabel(
            sec, text=self.t("settings_sec_pin"),
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=COLORS["text_bright"],
        ).pack(anchor="w", padx=12, pady=(10, 2))
        ctk.CTkLabel(
            sec, text=self.t("settings_pin_desc"),
            font=ctk.CTkFont(size=11), text_color=COLORS["text_dim"],
            justify="left", wraplength=720, anchor="w",
        ).pack(anchor="w", padx=12, pady=(0, 6))

        status_row = ctk.CTkFrame(sec, fg_color="transparent")
        status_row.pack(fill="x", padx=12, pady=(0, 4))
        ctk.CTkLabel(
            status_row, text=self.t("settings_pin_status_label"),
            font=ctk.CTkFont(size=12), text_color=COLORS["text"],
        ).pack(side="left")
        self._settings_pin_status = ctk.CTkLabel(
            status_row, text=self.t("pin_not_set"),
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=COLORS["orange"],
        )
        self._settings_pin_status.pack(side="left", padx=(8, 0))

        self._settings_pin_hint = ctk.CTkLabel(
            sec, text="", font=ctk.CTkFont(size=11),
            text_color=COLORS["text_dim"], justify="left",
            wraplength=720, anchor="w",
        )
        self._settings_pin_hint.pack(anchor="w", padx=12, pady=(0, 6))

        btn_row = ctk.CTkFrame(sec, fg_color="transparent")
        btn_row.pack(fill="x", padx=12, pady=(0, 12))
        self._settings_pin_btn_set = ctk.CTkButton(
            btn_row, text=self.t("settings_pin_set"),
            font=ctk.CTkFont(size=12), width=130, height=30,
            fg_color=COLORS["accent"], hover_color=COLORS["blue"],
            text_color=COLORS["text_bright"], corner_radius=6,
            command=self._pin_set_or_change,
        )
        self._settings_pin_btn_change = ctk.CTkButton(
            btn_row, text=self.t("settings_pin_change"),
            font=ctk.CTkFont(size=12), width=130, height=30,
            fg_color=COLORS["card"], hover_color=COLORS["accent"],
            text_color=COLORS["text_bright"], corner_radius=6,
            border_width=1, border_color=COLORS["border"],
            command=self._pin_set_or_change,
        )
        self._settings_pin_btn_clear = ctk.CTkButton(
            btn_row, text=self.t("settings_pin_clear"),
            font=ctk.CTkFont(size=12), width=130, height=30,
            fg_color=COLORS.get("red") or "#f43f5e",
            hover_color=COLORS.get("red_hover") or "#fb7185",
            text_color=COLORS["text_bright"], corner_radius=6,
            command=self._pin_clear,
        )

    def _refresh_settings_pin_ui(self):
        """Update PIN status + which action buttons are visible."""
        if not getattr(self, "_settings_pin_status", None):
            return
        has_pin = False
        try:
            from client_gui_lock import GuiLock, dashboard_pin_hint
            has_pin = bool(GuiLock.instance().has_pin())
            hint = dashboard_pin_hint(self.t) or ""
        except Exception:
            hint = ""

        try:
            if has_pin:
                self._settings_pin_status.configure(
                    text=self.t("settings_pin_status_on"),
                    text_color=COLORS.get("green") or "#10b981",
                )
            else:
                self._settings_pin_status.configure(
                    text=self.t("settings_pin_status_off"),
                    text_color=COLORS.get("orange") or "#f59e0b",
                )
        except Exception:
            pass

        try:
            self._settings_pin_hint.configure(text=hint)
            if hint:
                self._settings_pin_hint.pack(anchor="w", padx=12, pady=(0, 6))
            else:
                self._settings_pin_hint.pack_forget()
        except Exception:
            pass

        try:
            self._settings_pin_btn_set.pack_forget()
            self._settings_pin_btn_change.pack_forget()
            self._settings_pin_btn_clear.pack_forget()
            if has_pin:
                self._settings_pin_btn_change.pack(side="left", padx=(0, 8))
                self._settings_pin_btn_clear.pack(side="left")
            else:
                self._settings_pin_btn_set.pack(side="left")
        except Exception:
            pass

    def _settings_set_status(self, text: str, color: str):
        try:
            self._settings_status_label.configure(text=text, text_color=color)
        except Exception:
            pass

    def _apply_settings_values(self, values: dict):
        """Fill widgets from flat values, then enable editing."""
        for flat_key, meta in getattr(self, "_settings_widgets", {}).items():
            kind, widget = meta["kind"], meta["widget"]
            val = values.get(flat_key)
            try:
                # Enable FIRST — disabled CTk widgets ignore state mutations
                widget.configure(state="normal")
                if kind == "bool":
                    if val:
                        widget.select()
                    else:
                        widget.deselect()
                elif kind == "choice":
                    display = meta.get("display_by_value", {}).get(str(val), str(val))
                    widget._settings_var.set(display)
                else:
                    widget.delete(0, "end")
                    widget.insert(0, "" if val is None else str(val))
            except Exception:
                pass
        for btn_name in ("_settings_save_btn", "_settings_save_btn_top"):
            try:
                getattr(self, btn_name).configure(state="normal")
            except Exception:
                pass
        self._settings_set_status(f"✓ {self.t('layers_synced')}", COLORS["green"])

    def _collect_settings_values(self) -> dict:
        values = {}
        for flat_key, meta in getattr(self, "_settings_widgets", {}).items():
            kind, widget = meta["kind"], meta["widget"]
            try:
                if kind == "bool":
                    values[flat_key] = bool(widget.get())
                elif kind == "choice":
                    display = widget._settings_var.get()
                    values[flat_key] = meta.get("value_by_display", {}).get(
                        display, display
                    )
                else:
                    values[flat_key] = widget.get()
            except Exception:
                pass
        return values

    def _load_settings_values(self):
        token = self.app.state.get("token", "")
        if not token:
            self._settings_set_status(self.t("layers_no_token"), COLORS["orange"])
            return

        def _worker():
            from client_settings_util import extract_settings_values
            config = self.app.api_client.fetch_threat_config(token) or {}
            config = self._effective_threat_config(config)
            values = extract_settings_values(config)
            self._gui_safe(lambda: self._apply_settings_values(values))

        threading.Thread(
            target=_worker, name="GUI-Settings-Load", daemon=True
        ).start()

    def _save_settings(self):
        from client_settings_util import build_threat_config_patch
        token = self.app.state.get("token", "")
        if not token:
            self._settings_set_status(self.t("layers_no_token"), COLORS["orange"])
            return
        values = self._collect_settings_values()
        patch, errors = build_threat_config_patch(values)
        if errors:
            labels = []
            from client_settings_util import SECTIONS
            for _sec, fields in SECTIONS:
                for flat_key, _kind, label_key, _extra in fields:
                    if flat_key in errors:
                        labels.append(self.t(label_key))
            self._settings_set_status(
                self.t("settings_invalid").format(fields=", ".join(labels)),
                COLORS["red"],
            )
            return
        if not patch:
            return

        try:
            self._settings_save_btn.configure(state="disabled")
            self._settings_save_btn_top.configure(state="disabled")
        except Exception:
            pass
        self._settings_set_status(self.t("layers_syncing"), COLORS["blue"])

        def _worker():
            response = self.app.api_client.update_threat_config(token, patch)
            if response is None:
                def _fail():
                    self._settings_set_status(
                        self.t("layers_sync_failed"), COLORS["red"]
                    )
                    try:
                        self._settings_save_btn.configure(state="normal")
                        self._settings_save_btn_top.configure(state="normal")
                    except Exception:
                        pass
                self._gui_safe(_fail)
                return
            # Cloud accepted — re-read effective config so the daemon and GUI
            # both converge on the same source of truth.
            from client_settings_util import extract_settings_values
            effective = self._effective_threat_config(response)
            if not any(k in effective for k in (
                "alert_email_enabled", "auto_block_enabled", "silent_hours"
            )):
                effective = self._effective_threat_config(
                    self.app.api_client.fetch_threat_config(token) or {}
                )
            values2 = extract_settings_values(effective)

            def _done():
                self._apply_settings_values(values2)
                self._settings_set_status(
                    f"✓ {self.t('settings_saved')}", COLORS["green"]
                )
            self._gui_safe(_done)

        threading.Thread(
            target=_worker, name="GUI-Settings-Save", daemon=True
        ).start()

    # ═══════════════════════════════════════════════════════════════
    #  DASHBOARD İSTATİSTİK KARTLARI
    # ═══════════════════════════════════════════════════════════════
    def _build_dashboard(self, parent):
        """Mini dashboard — canlı istatistik kartları (Tab 1: Anlık Durum)."""
        # Koruma şeridi ÖNCE — ilk bakışta tüm katmanlar scroll'suz görünsün
        self._build_protection_strip(parent)

        sec = ctk.CTkFrame(parent, fg_color=COLORS["card"], corner_radius=12)
        sec.pack(fill="x", pady=(0, 12))

        # Başlık
        hdr_row = ctk.CTkFrame(sec, fg_color="transparent")
        hdr_row.pack(fill="x", padx=16, pady=(12, 6))

        dash_hdr = ctk.CTkFrame(hdr_row, fg_color="transparent")
        dash_hdr.pack(side="left")
        ctk.CTkLabel(
            dash_hdr, text="📈",
            font=self._emoji_font(14),
            text_color=COLORS["text_bright"],
        ).pack(side="left")
        ctk.CTkLabel(
            dash_hdr, text=f"  {self.t('dash_title')}",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=COLORS["text_bright"],
        ).pack(side="left")

        # Canlı pulse göstergesi (●)
        self._pulse_dot = ctk.CTkLabel(
            hdr_row, text="●",
            font=ctk.CTkFont(size=10),
            text_color=COLORS["green"],
        )
        self._pulse_dot.pack(side="right", padx=8)
        self._pulse_visible = True

        sep = ctk.CTkFrame(sec, height=1, fg_color=COLORS["border"])
        sep.pack(fill="x", padx=16, pady=(0, 10))

        # Kart grid — 2 satır × 3 sütun
        grid = ctk.CTkFrame(sec, fg_color="transparent")
        grid.pack(fill="x", padx=12, pady=(0, 14))
        for c in range(3):
            grid.columnconfigure(c, weight=1)

        # Referans dict — refresh'te güncellenir
        self._dash_cards: Dict[str, dict] = {}

        # ── İlk değerleri hesapla (sync API yok — çat diye açılış) ── #
        token = self.app.state.get("token", "")
        total_attacks = getattr(self.app, "_last_attack_count", None)
        if total_attacks is None:
            total_attacks = 0
        active_count = len(self.app.service_manager.running_services)
        total_services = len(self.app.PORT_TABLOSU) or 1
        session_attacks = 0
        try:
            session_attacks = self.app.service_manager.session_stats.get("total_credentials", 0)
        except Exception:
            pass
        # Async fill — do not block dashboard paint
        if token:
            try:
                self.app.refresh_attack_count(async_thread=True)
            except Exception:
                pass

        # ── Kartları oluştur (Tab 1 — Anlık Durum) ── #
        cards_data = [
            # (key, emoji, label_key, value, color, row, col, click_handler)
            ("total_attacks",   "🎯", "dash_total_attacks",   str(total_attacks),   COLORS["red"],    0, 0, "_detail_total_attacks"),
            ("session_attacks", "⚡", "dash_session_attacks",  str(session_attacks), COLORS["orange"], 0, 1, "_detail_session_attacks"),
            ("active_services", "🟢", "dash_active_services",  f"{active_count}/{total_services}",  COLORS["green"],  0, 2, "_detail_active_services"),
            ("uptime",          "⏱️", "dash_uptime",           "0dk",                COLORS["blue"],   1, 0, None),
            ("last_attack",     "🕵️", "dash_last_attack",      self.t("dash_no_attack"), COLORS["text_dim"], 1, 1, "_detail_last_attack"),
            ("connection",      "🌐", "dash_connection",       self.t("dash_connected"), COLORS["green"], 1, 2, "_detail_api_health"),
        ]

        for key, emoji, label_key, value, color, row, col, handler_name in cards_data:
            handler = getattr(self, handler_name, None) if handler_name else None
            card = self._create_stat_card(grid, emoji, self.t(label_key), value, color,
                                          on_click=handler)
            card.grid(row=row, column=col, padx=6, pady=5, sticky="nsew")
            self._dash_cards[key] = card

        # ── Faz 3 Durum Kartları — Satır 3 ── #
        faz3_cards_data = [
            ("ransomware",      "🧬", self.t("card_ransomware"),    "SAFE",  COLORS["green"],    2, 0, "_detail_ransomware"),
            ("cpu_usage",       "💻", self.t("card_cpu_ram"),     "—",     COLORS["text_dim"], 2, 1, "_detail_cpu_ram"),
            ("self_protect",    "🔒", self.t("card_protection"),    "ACTIVE", COLORS["green"],   2, 2, "_detail_self_protect"),
        ]

        for key, emoji, label, value, color, row, col, handler_name in faz3_cards_data:
            handler = getattr(self, handler_name, None) if handler_name else None
            card = self._create_stat_card(grid, emoji, label, value, color,
                                          on_click=handler)
            card.grid(row=row, column=col, padx=6, pady=5, sticky="nsew")
            self._dash_cards[key] = card

    # ═══════════════════════════════════════════════════════════════
    #  KORUMA DURUMU ŞERİDİ (Tab 1 — tüm katmanların canlı özeti)
    # ═══════════════════════════════════════════════════════════════
    def _build_protection_strip(self, parent):
        """Live one-glance status chips for every protection layer + shortcuts."""
        sec = ctk.CTkFrame(parent, fg_color=COLORS["card"], corner_radius=12)
        sec.pack(fill="x", pady=(0, 12))

        hdr = ctk.CTkFrame(sec, fg_color="transparent")
        hdr.pack(fill="x", padx=16, pady=(12, 6))
        ctk.CTkLabel(
            hdr, text="🛡", font=self._emoji_font(14),
            text_color=COLORS["text_bright"],
        ).pack(side="left")
        ctk.CTkLabel(
            hdr, text=f"  {self.t('prot_strip_title')}",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=COLORS["text_bright"],
        ).pack(side="left")

        # Sağda kısayollar — teknik bilgi gerektirmeden yönetim
        ctk.CTkButton(
            hdr, text=self.t("prot_manage_settings"),
            font=ctk.CTkFont(size=11), width=100, height=24,
            fg_color="transparent", hover_color=COLORS["accent"],
            border_width=1, border_color=COLORS["border"],
            text_color=COLORS["text"], corner_radius=6,
            command=lambda: self._show_page("settings"),
        ).pack(side="right", padx=(4, 0))
        ctk.CTkButton(
            hdr, text=self.t("prot_manage_layers"),
            font=ctk.CTkFont(size=11), width=120, height=24,
            fg_color=COLORS["accent"], hover_color=COLORS["blue"],
            text_color=COLORS["text_bright"], corner_radius=6,
            command=lambda: self._show_page("layers"),
        ).pack(side="right", padx=(4, 4))

        ctk.CTkFrame(sec, height=1, fg_color=COLORS["border"]).pack(
            fill="x", padx=16, pady=(0, 8)
        )

        grid = ctk.CTkFrame(sec, fg_color="transparent")
        grid.pack(fill="x", padx=12, pady=(0, 12))
        for c in range(3):
            grid.columnconfigure(c, weight=1)

        self._prot_chips: Dict[str, dict] = {}
        chip_defs = [
            # (key, emoji, label_key, on_click)
            ("motor",      "⚙️", "prot_chip_motor",      self._detail_self_protect),
            ("ransomware", "🧬", "prot_chip_ransomware", self._detail_ransomware),
            ("netguard",   "🌐", "prot_chip_netguard",   self._detail_network_guard),
            ("guardian",   "🛟", "prot_chip_guardian",   self._detail_persistence),
            ("honeypots",  "🐝", "prot_chip_honeypots",  lambda: self._show_page("services")),
            ("quarantine", "🔐", "prot_chip_quarantine", self._detail_ransomware),
        ]
        for idx, (key, emoji, label_key, handler) in enumerate(chip_defs):
            row, col = divmod(idx, 3)
            chip = ctk.CTkFrame(
                grid, fg_color=COLORS["bg"], corner_radius=8,
                border_width=1, border_color=COLORS["border"], cursor="hand2",
            )
            chip.grid(row=row, column=col, padx=5, pady=4, sticky="nsew")

            inner = ctk.CTkFrame(chip, fg_color="transparent")
            inner.pack(fill="x", padx=10, pady=8)
            ctk.CTkLabel(
                inner, text=emoji, font=self._emoji_font(14),
            ).pack(side="left", padx=(0, 6))
            text_col = ctk.CTkFrame(inner, fg_color="transparent")
            text_col.pack(side="left", fill="x", expand=True)
            ctk.CTkLabel(
                text_col, text=self.t(label_key),
                font=ctk.CTkFont(size=11), text_color=COLORS["text_dim"],
            ).pack(anchor="w")
            status_lbl = ctk.CTkLabel(
                text_col, text="…",
                font=ctk.CTkFont(size=12, weight="bold"),
                text_color=COLORS["text_dim"],
            )
            status_lbl.pack(anchor="w")

            self._bind_hover_click(
                chip,
                on_click=handler,
                on_enter=lambda frame=chip: frame.configure(border_color=COLORS["blue"]),
                on_leave=lambda frame=chip: frame.configure(border_color=COLORS["border"]),
            )

            self._prot_chips[key] = {"frame": chip, "status": status_lbl}

    def _set_prot_chip(self, key: str, text: str, color: str):
        chip = getattr(self, "_prot_chips", {}).get(key)
        if not chip:
            return
        try:
            chip["status"].configure(text=text, text_color=color)
        except Exception:
            pass

    def _refresh_protection_strip(self):
        """Update chips from cached daemon STATUS (or local engines if any)."""
        if not getattr(self, "_prot_chips", None):
            return
        st = getattr(self, "_cached_daemon_status", None) or {}
        on = self.t("prot_state_on")
        off = self.t("prot_state_off")

        # 1) Motor (SYSTEM daemon)
        motor_ok = bool(getattr(self, "_cached_motor_ok", False))
        self._set_prot_chip(
            "motor", on if motor_ok else off,
            COLORS["green"] if motor_ok else COLORS["red"],
        )

        # 2) Ransomware Shield — daemon truth first, local engine fallback
        rs_running = st.get("ransomware_running")
        if rs_running is None:
            rs = getattr(self.app, "ransomware_shield", None)
            try:
                rs_running = bool(rs and rs.get_stats().get("running"))
            except Exception:
                rs_running = False
        self._set_prot_chip(
            "ransomware", on if rs_running else off,
            COLORS["green"] if rs_running else COLORS["red"],
        )

        # 3) Network Guard
        ng = st.get("network_guard") or {}
        if ng.get("present"):
            if ng.get("maintenance"):
                self._set_prot_chip(
                    "netguard", self.t("ng_chip_maintenance"), COLORS["orange"],
                )
            elif ng.get("surface_inform"):
                n = int(ng.get("surface_inform_count") or 0)
                label = self.t("ng_chip_surface_inform")
                if n > 1:
                    label = f"{label} · {n}"
                self._set_prot_chip(
                    "netguard", label, COLORS["orange"],
                )
                self._maybe_toast_surface_inform(ng)
            else:
                ng_on = bool(ng.get("running")) and bool(ng.get("enabled", True))
                extra = ""
                susp = int(ng.get("suspended_processes") or 0)
                if susp:
                    extra = f" · {susp} susp"
                self._set_prot_chip(
                    "netguard", (on if ng_on else off) + extra,
                    COLORS["orange"] if susp else (
                        COLORS["green"] if ng_on else COLORS["red"]),
                )
                self._ng_surface_toast_fp = ""
        else:
            local_ng = getattr(self.app, "network_guard", None)
            ng_on = bool(local_ng and getattr(local_ng, "_running", False))
            self._set_prot_chip(
                "netguard", on if ng_on else "—",
                COLORS["green"] if ng_on else COLORS["text_dim"],
            )

        # 4) Guardian / persistence + tamper
        pers = st.get("persistence") or {}
        svc_ok = bool(pers.get("service_ok"))
        tamper = int(pers.get("tamper_count_24h") or 0)
        if pers:
            if tamper > 0:
                self._set_prot_chip(
                    "guardian", f"⚠ {tamper}/24h", COLORS["orange"]
                )
            else:
                self._set_prot_chip(
                    "guardian", on if svc_ok else off,
                    COLORS["green"] if svc_ok else COLORS["orange"],
                )
        else:
            self._set_prot_chip("guardian", "—", COLORS["text_dim"])

        # 5) Honeypot services
        try:
            active = len(self.app.service_manager.running_services)
            total = len(self.app.PORT_TABLOSU) or 1
            self._set_prot_chip(
                "honeypots", f"{active}/{total}",
                COLORS["green"] if active > 0 else COLORS["text_dim"],
            )
        except Exception:
            pass

        # 6) RS quarantine
        rq = st.get("rs_quarantine") or {}
        if rq.get("active"):
            self._set_prot_chip(
                "quarantine",
                self.t("prot_quarantine_active").format(
                    count=int(rq.get("entries") or 0)
                ),
                COLORS["red"],
            )
        else:
            self._set_prot_chip(
                "quarantine", self.t("prot_quarantine_clear"), COLORS["green"]
            )

    # ── Detail: Network Guard / bakım (VPN-IP) ── #
    def _maybe_toast_surface_inform(self, ng: dict):
        """One soft toast per inform fingerprint — no PIN, no blocking modal."""
        try:
            changes = ng.get("surface_inform_changes") or []
            fp = "|".join(
                sorted(str(c.get("id") or "") for c in changes if c.get("id"))
            )
            if not fp or fp == getattr(self, "_ng_surface_toast_fp", ""):
                return
            self._ng_surface_toast_fp = fp
            bits = []
            for c in changes[:3]:
                iface = c.get("interface") or "?"
                ip = c.get("ipv4") or c.get("to") or ""
                bits.append(f"{iface}" + (f" · {ip}" if ip else ""))
            detail = ", ".join(bits) if bits else ""
            msg = self.t("ng_toast_surface_inform")
            if detail:
                msg = f"{msg} ({detail})"
            self.show_toast(self.t("prot_chip_netguard"), msg, "info")
        except Exception:
            pass

    def _detail_network_guard(self):
        popup = self._show_detail_window(
            f"🌐 {self.t('prot_chip_netguard')}", height=520,
        )
        self._ng_detail_popup = popup
        self._ng_detail_content = popup._content
        self._refresh_network_guard_detail()

    def _refresh_network_guard_detail(self):
        content = getattr(self, "_ng_detail_content", None)
        if content is None:
            return
        try:
            for w in content.winfo_children():
                w.destroy()
        except Exception:
            return

        st = getattr(self, "_cached_daemon_status", None) or {}
        ng = st.get("network_guard") or {}
        if not ng.get("present"):
            try:
                from client_daemon_ipc import get_status
                ng = (get_status(timeout=3.0) or {}).get("network_guard") or {}
            except Exception:
                ng = {}

        maint = bool(ng.get("maintenance"))
        running = bool(ng.get("running")) and bool(ng.get("enabled", True)) and not maint
        status_txt = (
            self.t("ng_status_maintenance") if maint
            else (self.t("ng_status_on") if running else self.t("ng_status_off"))
        )
        status_color = (
            COLORS["orange"] if maint
            else (COLORS["green"] if running else COLORS["red"])
        )
        ctk.CTkLabel(
            content, text=status_txt,
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=status_color,
        ).pack(anchor="w", padx=8, pady=(4, 2))
        ctk.CTkLabel(
            content, text=self.t("ng_maint_help"),
            font=ctk.CTkFont(size=11), text_color=COLORS["text_dim"],
            wraplength=480, justify="left",
        ).pack(anchor="w", padx=8, pady=(0, 8))

        ver = ng.get("baseline_version")
        age = ng.get("baseline_age_sec")
        age_txt = f"{age}s" if age is not None else "—"
        ctk.CTkLabel(
            content,
            text=self.t("ng_baseline_line").format(version=ver or "—", age=age_txt),
            font=ctk.CTkFont(size=12), text_color=COLORS["text"],
        ).pack(anchor="w", padx=8, pady=(0, 6))

        live = (ng.get("live") or {}).get("adapters") or []
        if live:
            ctk.CTkLabel(
                content, text=self.t("ng_live_adapters"),
                font=ctk.CTkFont(size=12, weight="bold"),
                text_color=COLORS["text_bright"],
            ).pack(anchor="w", padx=8, pady=(4, 2))
            for a in live[:6]:
                line = (
                    f"{a.get('name')}: {a.get('state')} · "
                    f"{a.get('ipv4') or '—'} · DNS {', '.join(a.get('dns') or []) or '—'}"
                )
                ctk.CTkLabel(
                    content, text=line, font=ctk.CTkFont(size=11),
                    text_color=COLORS["text_dim"],
                ).pack(anchor="w", padx=12, pady=1)

        inform = ng.get("surface_inform_changes") or []
        if ng.get("surface_inform") and inform:
            ctk.CTkLabel(
                content, text=self.t("ng_surface_inform_title"),
                font=ctk.CTkFont(size=12, weight="bold"),
                text_color=COLORS["orange"],
            ).pack(anchor="w", padx=8, pady=(10, 2))
            ctk.CTkLabel(
                content, text=self.t("ng_surface_inform_help"),
                font=ctk.CTkFont(size=11), text_color=COLORS["text_dim"],
                wraplength=480, justify="left",
            ).pack(anchor="w", padx=8, pady=(0, 4))
            for c in inform[:6]:
                line = (
                    f"{c.get('interface') or '?'}: {c.get('kind') or c.get('id')}"
                    f" · {c.get('ipv4') or c.get('to') or ''}"
                ).strip(" ·")
                ctk.CTkLabel(
                    content, text=line, font=ctk.CTkFont(size=11),
                    text_color=COLORS["text"],
                ).pack(anchor="w", padx=12, pady=1)

        btns = ctk.CTkFrame(content, fg_color="transparent")
        btns.pack(fill="x", padx=8, pady=(14, 4))

        def _run(action: str):
            def _worker():
                try:
                    from client_daemon_ipc import (
                        network_maintenance_start,
                        network_maintenance_end,
                        network_snapshot,
                        network_accept_surface,
                        get_status,
                    )
                    if action == "pause":
                        out = network_maintenance_start()
                    elif action == "snapshot":
                        out = network_snapshot()
                    elif action == "accept":
                        out = network_accept_surface()
                    elif action == "resume":
                        out = network_maintenance_end(snapshot=True)
                    else:
                        out = {"ok": False, "error": "bad_action"}
                    ok = bool(out.get("ok", out.get("success", False)))
                    try:
                        fresh = get_status(timeout=4.0) or {}
                        if fresh.get("network_guard"):
                            st2 = getattr(self, "_cached_daemon_status", None) or {}
                            if isinstance(st2, dict):
                                st2 = dict(st2)
                                st2["network_guard"] = fresh["network_guard"]
                                self._cached_daemon_status = st2
                    except Exception:
                        pass

                    def _done():
                        if ok:
                            self.show_toast(
                                self.t("prot_chip_netguard"),
                                self.t(f"ng_toast_{action}_ok"),
                                "info",
                            )
                            if action in ("accept", "snapshot", "resume"):
                                self._ng_surface_toast_fp = ""
                        else:
                            self.show_toast(
                                self.t("prot_chip_netguard"),
                                str(out.get("error") or self.t("ng_toast_fail")),
                                "high",
                            )
                        self._refresh_network_guard_detail()
                        try:
                            self._refresh_protection_strip()
                        except Exception:
                            pass

                    self._gui_safe(_done)
                except Exception as e:
                    err = str(e)
                    self._gui_safe(lambda: self.show_toast(
                        self.t("prot_chip_netguard"), err, "high",
                    ))

            threading.Thread(
                target=_worker, name=f"GUI-NG-{action}", daemon=True,
            ).start()

        if ng.get("surface_inform") and not maint:
            ctk.CTkButton(
                btns, text=self.t("ng_btn_accept_surface"),
                font=ctk.CTkFont(size=12, weight="bold"),
                fg_color=COLORS["green"], hover_color=COLORS["green"],
                height=32, command=lambda: _run("accept"),
            ).pack(fill="x", pady=3)

        if not maint:
            ctk.CTkButton(
                btns, text=self.t("ng_btn_pause"),
                font=ctk.CTkFont(size=12, weight="bold"),
                fg_color=COLORS["orange"], hover_color=COLORS["orange"],
                height=32, command=lambda: _run("pause"),
            ).pack(fill="x", pady=3)
        else:
            ctk.CTkButton(
                btns, text=self.t("ng_btn_snapshot"),
                font=ctk.CTkFont(size=12), height=32,
                command=lambda: _run("snapshot"),
            ).pack(fill="x", pady=3)
            ctk.CTkButton(
                btns, text=self.t("ng_btn_resume"),
                font=ctk.CTkFont(size=12, weight="bold"),
                fg_color=COLORS["green"], hover_color=COLORS["green"],
                height=32, command=lambda: _run("resume"),
            ).pack(fill="x", pady=3)

        def _open_layers():
            pop = getattr(self, "_ng_detail_popup", None)
            try:
                if pop is not None:
                    pop.destroy()
            except Exception:
                pass
            self._show_page("layers")

        ctk.CTkButton(
            btns, text=self.t("ng_btn_layers"),
            font=ctk.CTkFont(size=11), height=28,
            fg_color="transparent", border_width=1,
            border_color=COLORS["border"], text_color=COLORS["text"],
            command=_open_layers,
        ).pack(fill="x", pady=(8, 2))

    # ── Detail: Guardian / kalıcılık durumu ── #
    def _detail_persistence(self):
        popup = self._show_detail_window(f"🛟 {self.t('prot_chip_guardian')}", height=430)
        content = popup._content
        st = getattr(self, "_cached_daemon_status", None) or {}
        pers = st.get("persistence") or {}
        if not pers:
            try:
                from client_daemon_ipc import get_status
                pers = (get_status(timeout=3.0) or {}).get("persistence") or {}
            except Exception:
                pers = {}
        if not pers:
            ctk.CTkLabel(content, text=self.t("detail_no_data"),
                         text_color=COLORS["text_dim"]).pack(anchor="w", padx=4)
            return
        rows = [
            ("prot_pers_daemon", bool(pers.get("daemon_ok"))),
            ("prot_pers_service", bool(pers.get("service_ok"))),
            ("prot_pers_tasks", bool(pers.get("tasks_armed"))),
            ("prot_pers_selfprot", bool(pers.get("self_protection"))),
        ]
        for label_key, ok in rows:
            row = ctk.CTkFrame(content, fg_color="transparent")
            row.pack(fill="x", padx=8, pady=3)
            ctk.CTkLabel(
                row, text="🟢" if ok else "🔴", font=self._emoji_font(12),
            ).pack(side="left", padx=(0, 8))
            ctk.CTkLabel(
                row, text=self.t(label_key), font=ctk.CTkFont(size=13),
                text_color=COLORS["text"],
            ).pack(side="left")
        tamper = int(pers.get("tamper_count_24h") or 0)
        color = COLORS["orange"] if tamper else COLORS["text_dim"]
        ctk.CTkLabel(
            content,
            text=self.t("prot_pers_tamper").format(count=tamper),
            font=ctk.CTkFont(size=12), text_color=color,
        ).pack(anchor="w", padx=8, pady=(10, 2))
        if pers.get("operator_stop"):
            ctk.CTkLabel(
                content, text=self.t("prot_pers_operator_stop"),
                font=ctk.CTkFont(size=12, weight="bold"),
                text_color=COLORS["orange"],
            ).pack(anchor="w", padx=8, pady=2)

    # ═══════════════════════════════════════════════════════════════
    #  TAB 2: TEHDİT MERKEZİ
    # ═══════════════════════════════════════════════════════════════
    def _build_threat_center(self, parent):
        """Tab 2 — light core first; heavy panels scheduled in idle chunks."""
        # ── Threat Detection Kartları ── #
        threat_sec = ctk.CTkFrame(parent, fg_color=COLORS["card"], corner_radius=12)
        threat_sec.pack(fill="x", pady=(0, 12))

        ctk.CTkLabel(
            threat_sec, text=self.t("section_threat_detection"),
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=COLORS["text_bright"],
        ).pack(anchor="w", padx=16, pady=(12, 8))

        sep = ctk.CTkFrame(threat_sec, height=1, fg_color=COLORS["border"])
        sep.pack(fill="x", padx=16, pady=(0, 10))

        threat_grid = ctk.CTkFrame(threat_sec, fg_color="transparent")
        threat_grid.pack(fill="x", padx=12, pady=(0, 14))
        for c in range(3):
            threat_grid.columnconfigure(c, weight=1)

        threat_cards_data = [
            ("threat_level",    "🛡️", self.t("card_threat_level"),  "SAFE", COLORS["green"],    0, 0, "_detail_threat_level"),
            ("events_per_hour", "📊", self.t("card_events_per_hour"),   "0",    COLORS["text_dim"], 0, 1, "_detail_events_per_hour"),
            ("blocked_ips",     "🚫", self.t("card_blocked_ips"),   "0",    COLORS["text_dim"], 0, 2, "_open_blocked_ips_tab"),
        ]

        for key, emoji, label, value, color, row, col, handler_name in threat_cards_data:
            handler = getattr(self, handler_name, None) if handler_name else None
            card = self._create_stat_card(threat_grid, emoji, label, value, color,
                                          on_click=handler)
            card.grid(row=row, column=col, padx=6, pady=5, sticky="nsew")
            self._dash_cards[key] = card

        # ── Live Threat Feed + quick actions (still light) ── #
        self._build_threat_feed(threat_sec)
        self._build_response_buttons(threat_sec)

        # Heavy panels in idle slices so tab switch / prewarm doesn't freeze UI
        def _chunk1():
            try:
                self._build_security_overview(parent)
                self._build_user_accounts_panel(parent)
            except Exception as e:
                log(f"[GUI] threat chunk1: {e}")
            try:
                if self.root:
                    self.root.after(20, _chunk2)
                else:
                    _chunk2()
            except Exception:
                _chunk2()

        def _chunk2():
            try:
                self._build_network_shares_panel(parent)
                self._build_suspicious_services_panel(parent)
                self._build_command_history(parent)
            except Exception as e:
                log(f"[GUI] threat chunk2: {e}")
            try:
                if self.root:
                    self.root.after(20, _chunk3)
                else:
                    _chunk3()
            except Exception:
                _chunk3()

        def _chunk3():
            try:
                self._build_active_sessions(parent)
                self._build_remote_desktop_panel(parent)
                self._build_trend_panel(parent)
            except Exception as e:
                log(f"[GUI] threat chunk3: {e}")

        try:
            if self.root:
                self.root.after(10, _chunk1)
            else:
                _chunk1()
        except Exception:
            _chunk1()

    # ═══════════════════════════════════════════════════════════════
    #  SECURITY INTELLIGENCE PANELS (v4.0.2)
    # ═══════════════════════════════════════════════════════════════

    # ─── System Security Overview ─── #
    def _build_security_overview(self, parent):
        """Genel güvenlik durumu — yeşil/kırmızı check listesi."""
        sec = ctk.CTkFrame(parent, fg_color=COLORS["card"], corner_radius=12)
        sec.pack(fill="x", pady=(0, 12))

        hdr = ctk.CTkFrame(sec, fg_color="transparent")
        hdr.pack(fill="x", padx=16, pady=(12, 4))

        ctk.CTkLabel(
            hdr, text=self.t("section_system_security"),
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=COLORS["text_bright"],
        ).pack(side="left")

        ctk.CTkButton(
            hdr, text="🔄", width=28, height=22,
            font=self._emoji_font(11),
            fg_color=COLORS["bg"], border_width=1, border_color=COLORS["border"],
            hover_color="#2a2b3e",
            command=self._refresh_security_intel,
        ).pack(side="right")

        sep = ctk.CTkFrame(sec, height=1, fg_color=COLORS["border"])
        sep.pack(fill="x", padx=16, pady=(4, 8))

        self._security_checks_frame = ctk.CTkFrame(sec, fg_color="transparent")
        self._security_checks_frame.pack(fill="x", padx=16, pady=(0, 12))

        # Başlangıç: "Taranıyor..." göster
        self._security_check_label = ctk.CTkLabel(
            self._security_checks_frame,
            text=self.t("loading_system_scanning"),
            font=ctk.CTkFont(size=12),
            text_color=COLORS["text_dim"],
        )
        self._security_check_label.pack(anchor="w", padx=4, pady=2)
        # Data load deferred — _lazy_load_threat_data / refresh loop

    # ─── User Accounts Panel ─── #
    def _build_user_accounts_panel(self, parent):
        """Windows kullanıcı hesapları — aktif, devre dışı, gizli."""
        sec = ctk.CTkFrame(parent, fg_color=COLORS["card"], corner_radius=12)
        sec.pack(fill="x", pady=(0, 12))

        hdr = ctk.CTkFrame(sec, fg_color="transparent")
        hdr.pack(fill="x", padx=16, pady=(12, 4))

        ctk.CTkLabel(
            hdr, text=self.t("section_user_accounts"),
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=COLORS["text_bright"],
        ).pack(side="left")

        ctk.CTkButton(
            hdr, text="🔄", width=28, height=22,
            font=self._emoji_font(11),
            fg_color=COLORS["bg"], border_width=1, border_color=COLORS["border"],
            hover_color="#2a2b3e",
            command=self._refresh_user_accounts,
        ).pack(side="right")

        sep = ctk.CTkFrame(sec, height=1, fg_color=COLORS["border"])
        sep.pack(fill="x", padx=16, pady=(4, 8))

        self._users_content_frame = ctk.CTkFrame(sec, fg_color="transparent")
        self._users_content_frame.pack(fill="x", padx=16, pady=(0, 12))

        self._users_loading_label = ctk.CTkLabel(
            self._users_content_frame,
            text=self.t("loading_users_scanning"),
            font=ctk.CTkFont(size=12), text_color=COLORS["text_dim"],
        )
        self._users_loading_label.pack(anchor="w", padx=4, pady=2)

    # ─── Network Shares Panel ─── #
    def _build_network_shares_panel(self, parent):
        """Ağ paylaşımları — açık paylaşımlar."""
        sec = ctk.CTkFrame(parent, fg_color=COLORS["card"], corner_radius=12)
        sec.pack(fill="x", pady=(0, 12))

        hdr = ctk.CTkFrame(sec, fg_color="transparent")
        hdr.pack(fill="x", padx=16, pady=(12, 4))

        ctk.CTkLabel(
            hdr, text=self.t("section_network_shares"),
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=COLORS["text_bright"],
        ).pack(side="left")

        sep = ctk.CTkFrame(sec, height=1, fg_color=COLORS["border"])
        sep.pack(fill="x", padx=16, pady=(4, 8))

        self._shares_content_frame = ctk.CTkFrame(sec, fg_color="transparent")
        self._shares_content_frame.pack(fill="x", padx=16, pady=(0, 12))

        self._shares_loading_label = ctk.CTkLabel(
            self._shares_content_frame,
            text=self.t("loading_shares_scanning"),
            font=ctk.CTkFont(size=12), text_color=COLORS["text_dim"],
        )
        self._shares_loading_label.pack(anchor="w", padx=4, pady=2)

    # ─── Suspicious Services Panel ─── #
    def _build_suspicious_services_panel(self, parent):
        """Windows dışı 3. parti çalışan servisler."""
        sec = ctk.CTkFrame(parent, fg_color=COLORS["card"], corner_radius=12)
        sec.pack(fill="x", pady=(0, 12))

        hdr = ctk.CTkFrame(sec, fg_color="transparent")
        hdr.pack(fill="x", padx=16, pady=(12, 4))

        ctk.CTkLabel(
            hdr, text=self.t("section_third_party_services"),
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=COLORS["text_bright"],
        ).pack(side="left")

        sep = ctk.CTkFrame(sec, height=1, fg_color=COLORS["border"])
        sep.pack(fill="x", padx=16, pady=(4, 8))

        self._services_content_frame = ctk.CTkFrame(sec, fg_color="transparent")
        self._services_content_frame.pack(fill="x", padx=16, pady=(0, 12))

        self._services_loading_label = ctk.CTkLabel(
            self._services_content_frame,
            text=self.t("loading_services_scanning"),
            font=ctk.CTkFont(size=12), text_color=COLORS["text_dim"],
        )
        self._services_loading_label.pack(anchor="w", padx=4, pady=2)

    # ═══════════════════════════════════════════════════════════════
    #  SECURITY DATA COLLECTORS (v4.0.2) — background threads
    # ═══════════════════════════════════════════════════════════════

    def _refresh_security_intel(self):
        """Güvenlik panellerini arka planda yenile (coalesce + sequential PS)."""
        if self._lazy_intel and self._active_page != "threat":
            return
        if getattr(self, "_security_intel_busy", False):
            self._security_intel_pending = True
            return
        self._security_intel_busy = True
        self._security_intel_pending = False

        def _worker():
            try:
                # One worker — avoid parallel PowerShell storms
                self._collect_security_overview()
                self._collect_user_accounts()
                self._collect_network_shares()
                self._collect_suspicious_services()
            finally:
                def _done():
                    self._security_intel_busy = False
                    if getattr(self, "_security_intel_pending", False):
                        self._security_intel_pending = False
                        self._refresh_security_intel()
                try:
                    self._gui_safe(_done)
                except Exception:
                    self._security_intel_busy = False

        threading.Thread(target=_worker, daemon=True, name="SecurityIntel").start()

    def _refresh_user_accounts(self):
        """Sadece kullanıcı hesaplarını yenile."""
        threading.Thread(
            target=self._collect_user_accounts, daemon=True, name="UserAccounts"
        ).start()

    # ─── Collector: System Security Overview ─── #
    def _collect_security_overview(self):
        """Sistem güvenlik kontrollerini çalıştır ve GUI'yi güncelle."""
        from client_winproc import run_hidden, run_ps
        checks = []

        # 1) Windows Firewall
        try:
            rc, out, _ = run_hidden(
                ["netsh", "advfirewall", "show", "allprofiles", "state"], timeout=5,
            )
            fw_on = "ON" in out.upper() if rc == 0 else False
            checks.append((self.t("check_firewall"), fw_on,
                           self.t("check_active") if fw_on else self.t("check_disabled_warning"),
                           None if fw_on else "firewall"))
        except Exception:
            checks.append((self.t("check_firewall"), None, self.t("check_unable_to_verify")))

        # 2) Windows Defender / Antivirus
        try:
            rc, out, _ = run_ps(
                "Get-MpComputerStatus | Select-Object -ExpandProperty RealTimeProtectionEnabled",
                timeout=10,
            )
            av_on = "TRUE" in out.upper().strip() if rc == 0 else False
            checks.append((self.t("check_antivirus"), av_on,
                           self.t("check_realtime_on") if av_on else self.t("check_disabled_warning"),
                           None if av_on else "antivirus"))
        except Exception:
            checks.append((self.t("check_antivirus"), None, self.t("check_unable_to_verify")))

        # 3) WinRM (uzaktan yönetim — kapalı olmalı)
        try:
            rc, out, _ = run_hidden(["sc", "query", "WinRM"], timeout=5)
            winrm_running = "RUNNING" in out.upper() if rc == 0 else False
            checks.append((self.t("check_winrm"), not winrm_running,
                           self.t("check_closed_safe") if not winrm_running else self.t("check_open_remote_risk"),
                           "winrm" if winrm_running else None))
        except Exception:
            checks.append((self.t("check_winrm"), True, self.t("check_service_not_found")))

        # 4) RDP Network Level Authentication
        try:
            rc, out, _ = run_hidden(
                ["reg", "query",
                 r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
                 "/v", "UserAuthentication"],
                timeout=5,
            )
            nla_on = "0x1" in out if rc == 0 else False
            checks.append((self.t("check_rdp_nla"), nla_on,
                           self.t("check_nla_active") if nla_on else self.t("check_nla_off_risk"),
                           None if nla_on else "nla"))
        except Exception:
            checks.append((self.t("check_rdp_nla"), None, self.t("check_unable_to_verify")))

        # 5) Ransomware Shield
        rs = getattr(self.app, 'ransomware_shield', None)
        if rs:
            try:
                stats = rs.get_stats() if hasattr(rs, 'get_stats') else {}
                running = stats.get("running", False)
                alerts = stats.get("canary_alerts", 0)
                canary_count = stats.get("canary_files", 0)
                if running and alerts == 0:
                    checks.append((self.t("check_ransomware_shield"), True,
                                   self.t("check_rs_active").format(count=canary_count)))
                elif running and alerts > 0:
                    checks.append((self.t("check_ransomware_shield"), False,
                                   f"⚠️ {self.t('check_rs_alerts').format(count=alerts)}"))
                else:
                    checks.append((self.t("check_ransomware_shield"), False, self.t("check_rs_not_running")))
            except Exception:
                checks.append((self.t("check_ransomware_shield"), None, self.t("check_unable_to_verify")))
        else:
            checks.append((self.t("check_ransomware_shield"), False, self.t("check_rs_not_installed")))

        # 6) Windows Update (son güncelleme tarihi)
        try:
            rc, out, _ = run_ps(
                "(Get-HotFix | Sort-Object InstalledOn -Descending | "
                "Select-Object -First 1).InstalledOn.ToString('dd.MM.yyyy')",
                timeout=15,
            )
            if rc == 0 and out.strip():
                checks.append((self.t("check_last_update"), True, out.strip()))
            else:
                checks.append((self.t("check_last_update"), None, self.t("check_info_unavailable")))
        except Exception:
            checks.append((self.t("check_last_update"), None, self.t("check_unable_to_verify")))

        self._gui_safe(lambda: self._render_security_checks(checks))

    def _render_security_checks(self, checks: list):
        """Güvenlik kontrol sonuçlarını GUI'de göster — aksiyon butonları ile."""
        try:
            # Mevcut widget'ları temizle
            for w in self._security_checks_frame.winfo_children():
                w.destroy()

            all_ok = all(c[1] is True for c in checks)

            # Genel durum banner
            if all_ok:
                banner_text = self.t("security_all_ok")
                banner_color = COLORS["green"]
            else:
                fail_count = sum(1 for c in checks if c[1] is False)
                banner_text = self.t("security_warnings_found").format(count=fail_count)
                banner_color = COLORS["orange"]

            banner = ctk.CTkLabel(
                self._security_checks_frame,
                text=banner_text,
                font=ctk.CTkFont(size=13, weight="bold"),
                text_color=banner_color,
            )
            banner.pack(anchor="w", padx=4, pady=(0, 8))

            # Her kontrol için satır — check_id ile aksiyon butonu eklenir
            for item in checks:
                name, status, detail = item[0], item[1], item[2]
                check_id = item[3] if len(item) > 3 else None

                row = ctk.CTkFrame(self._security_checks_frame, fg_color="transparent")
                row.pack(fill="x", padx=4, pady=1)

                if status is True:
                    icon = "✅"
                    color = COLORS["green"]
                elif status is False:
                    icon = "❌"
                    color = COLORS["red"]
                else:
                    icon = "⚪"
                    color = COLORS["text_dim"]

                ctk.CTkLabel(
                    row, text=f"{icon}  {name}:",
                    font=ctk.CTkFont(size=12, weight="bold"),
                    text_color=color, width=180, anchor="w",
                ).pack(side="left")

                ctk.CTkLabel(
                    row, text=detail,
                    font=ctk.CTkFont(size=12),
                    text_color=COLORS["text_dim"], anchor="w",
                ).pack(side="left", padx=(4, 0))

                # Aksiyon butonları — sadece sorunlu öğeler için
                if status is False and check_id:
                    btn_cfg = self._get_fix_button_config(check_id)
                    if btn_cfg:
                        ctk.CTkButton(
                            row, text=btn_cfg["text"],
                            width=btn_cfg.get("width", 70), height=22,
                            font=ctk.CTkFont(size=10),
                            fg_color=btn_cfg.get("color", COLORS["accent"]),
                            hover_color=btn_cfg.get("hover", COLORS["blue"]),
                            text_color=COLORS["text_bright"],
                            corner_radius=4,
                            command=btn_cfg["command"],
                        ).pack(side="right", padx=(4, 0))

        except Exception:
            pass

    def _get_fix_button_config(self, check_id: str) -> dict:
        """Güvenlik sorunları için düzeltme butonu konfigürasyonu."""
        configs = {
            "winrm": {
                "text": self.t("btn_fix_winrm"),
                "color": COLORS["red"],
                "hover": COLORS["red_hover"],
                "width": 60,
                "command": self._fix_winrm,
            },
            "nla": {
                "text": self.t("btn_fix_nla"),
                "color": COLORS["blue"],
                "hover": COLORS["blue_hover"],
                "width": 80,
                "command": self._fix_nla,
            },
            "antivirus": {
                "text": self.t("btn_fix_antivirus"),
                "color": COLORS["orange"],
                "hover": COLORS["orange_hover"],
                "width": 50,
                "command": self._fix_antivirus,
            },
            "firewall": {
                "text": self.t("btn_fix_firewall_warn"),
                "color": COLORS["orange"],
                "hover": COLORS["orange_hover"],
                "width": 200,
                "command": lambda: None,  # Sadece uyarı
            },
        }
        return configs.get(check_id)

    # ── Güvenlik Düzeltme Aksiyonları ─────────────────────────────

    def _fix_winrm(self):
        """WinRM servisini kapat."""
        if not messagebox.askyesno("WinRM", self.t("fix_winrm_confirm")):
            return
        from client_winproc import run_ps
        def _do():
            try:
                run_ps(
                    "Stop-Service WinRM -Force; "
                    "Set-Service WinRM -StartupType Disabled; "
                    "Disable-PSRemoting -Force -ErrorAction SilentlyContinue",
                    timeout=15,
                )
                self._gui_safe(lambda: messagebox.showinfo("WinRM", self.t("fix_winrm_ok")))
            except Exception:
                self._gui_safe(lambda: messagebox.showerror("WinRM", self.t("fix_winrm_fail")))
            self._refresh_security_intel()
        threading.Thread(target=_do, daemon=True).start()

    def _fix_nla(self):
        """RDP NLA'yı aktifleştir."""
        if not messagebox.askyesno("RDP NLA", self.t("fix_nla_confirm")):
            return
        from client_winproc import run_hidden
        def _do():
            try:
                run_hidden(
                    ["reg", "add",
                     r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
                     "/v", "UserAuthentication", "/t", "REG_DWORD", "/d", "1", "/f"],
                    timeout=10,
                )
                self._gui_safe(lambda: messagebox.showinfo("RDP NLA", self.t("fix_nla_ok")))
            except Exception:
                self._gui_safe(lambda: messagebox.showerror("RDP NLA", self.t("fix_nla_fail")))
            self._refresh_security_intel()
        threading.Thread(target=_do, daemon=True).start()

    def _fix_antivirus(self):
        """Windows Defender gerçek zamanlı korumayı aç."""
        if not messagebox.askyesno("Antivirus", self.t("fix_av_confirm")):
            return
        from client_winproc import run_ps
        def _do():
            try:
                rc, _, _ = run_ps(
                    "Set-MpPreference -DisableRealtimeMonitoring $false",
                    timeout=15,
                )
                if rc == 0:
                    self._gui_safe(lambda: messagebox.showinfo("Antivirus", self.t("fix_av_ok")))
                else:
                    self._gui_safe(lambda: messagebox.showerror("Antivirus", self.t("fix_av_fail")))
            except Exception:
                self._gui_safe(lambda: messagebox.showerror("Antivirus", self.t("fix_av_fail")))
            self._refresh_security_intel()
        threading.Thread(target=_do, daemon=True).start()

    # ─── Collector: User Accounts ─── #
    def _collect_user_accounts(self):
        """Windows kullanıcı hesaplarını topla — grup üyelikleri + IIS tespiti."""
        import json
        from client_winproc import run_ps, run_ps_script
        users = []

        # 1) Kullanıcı listesini al
        try:
            rc, out, _ = run_ps(
                "Get-LocalUser | Select-Object Name, Enabled, "
                "LastLogon, Description | ConvertTo-Json",
                timeout=10,
            )
            if rc == 0 and out.strip():
                data = json.loads(out.strip())
                if isinstance(data, dict):
                    data = [data]
                users = data
        except Exception:
            pass

        # 2) Her kullanıcının grup üyeliklerini topla (EncodedCommand ile $_ escape)
        group_map: dict = {}   # username -> [group1, group2, ...]
        try:
            ps_groups = (
                'Get-LocalGroup | ForEach-Object { $g=$_.Name; '
                'try { Get-LocalGroupMember -Group $g -ErrorAction Stop | '
                'ForEach-Object { [PSCustomObject]@{Group=$g; User=$_.Name} } } '
                'catch {} } | ConvertTo-Json -Depth 3'
            )
            rc2, out2, _ = run_ps_script(ps_groups, timeout=20)
            if rc2 == 0 and out2.strip():
                memberships = json.loads(out2.strip())
                if isinstance(memberships, dict):
                    memberships = [memberships]
                for m in memberships:
                    raw_user = m.get("User", "")
                    # User can be DOMAIN\name or just name
                    short = raw_user.split("\\")[-1] if "\\" in raw_user else raw_user
                    group_map.setdefault(short, []).append(m.get("Group", ""))
        except Exception:
            pass

        # 3) IIS App Pool kimliklerini tespit et (EncodedCommand ile $_ escape)
        iis_pool_users: set = set()
        try:
            ps_iis = (
                'try { Import-Module WebAdministration -ErrorAction Stop; '
                'Get-ChildItem IIS:\\AppPools | Select-Object Name, '
                '@{N="Identity";E={$_.processModel.userName}}, '
                '@{N="IdType";E={$_.processModel.identityType}} '
                '| ConvertTo-Json } catch { "[]" }'
            )
            rc3, out3, _ = run_ps_script(ps_iis, timeout=10)
            if rc3 == 0 and out3.strip():
                pools = json.loads(out3.strip())
                if isinstance(pools, dict):
                    pools = [pools]
                for pool in pools:
                    id_type = str(pool.get("IdType", ""))
                    identity = pool.get("Identity", "") or ""
                    pool_name = pool.get("Name", "") or ""
                    if "ApplicationPoolIdentity" in id_type:
                        iis_pool_users.add(pool_name.lower())
                    elif identity:
                        short = identity.split("\\")[-1] if "\\" in identity else identity
                        iis_pool_users.add(short.lower())
        except Exception:
            pass

        # Attach enrichment to each user
        for u in users:
            name = u.get("Name", "")
            u["_groups"] = group_map.get(name, [])
            u["_is_iis"] = name.lower() in iis_pool_users

        self._gui_safe(lambda: self._render_user_accounts(users))

    def _render_user_accounts(self, users: list):
        """Kullanıcı hesaplarını tablo formatında göster — Tür, Gruplar, Son Giriş, Aksiyon."""
        import re as _re
        try:
            for w in self._users_content_frame.winfo_children():
                w.destroy()

            if not users:
                ctk.CTkLabel(
                    self._users_content_frame,
                    text=self.t("users_info_unavailable"),
                    font=ctk.CTkFont(size=12), text_color=COLORS["text_dim"],
                ).pack(anchor="w", padx=4, pady=2)
                return

            # ── Domain uzantısı ile IIS App Pool tespiti ──
            domain_pattern = _re.compile(
                r'^[a-zA-Z0-9][a-zA-Z0-9.-]+\.(com|com\.tr|net|org|io|dev|info|biz|co|co\.uk|edu|gov)$',
                _re.IGNORECASE
            )

            active_users = []
            disabled_users = []

            for u in users:
                name = u.get("Name", "")
                enabled = u.get("Enabled", False)
                desc = u.get("Description", "") or ""
                last_logon = u.get("LastLogon", "")
                groups = u.get("_groups", [])
                is_iis_pool = u.get("_is_iis", False)

                # Domain adı benzeri kullanıcılar da IIS App Pool
                if not is_iis_pool and domain_pattern.match(name):
                    is_iis_pool = True

                # Son giriş tarihini formatla
                logon_str = ""
                if last_logon and isinstance(last_logon, str) and "/Date(" in last_logon:
                    try:
                        ts = int(last_logon.split("(")[1].split(")")[0]) / 1000
                        from datetime import datetime
                        logon_str = datetime.fromtimestamp(ts).strftime("%d.%m.%Y %H:%M")
                    except Exception:
                        logon_str = ""

                # Kullanıcı türünü belirle
                nl = name.lower()
                if nl == "administrator":
                    user_type = self.t("user_type_admin")
                    type_color = COLORS["orange"]
                elif is_iis_pool:
                    user_type = "IIS App Pool"
                    type_color = "#4fc3f7"
                elif nl in ("defaultaccount", "guest", "wdagutilityaccount",
                            "varsayılanhesap"):
                    user_type = self.t("user_type_system")
                    type_color = COLORS["text_dim"]
                else:
                    user_type = self.t("user_type_user")
                    type_color = COLORS["green"]

                # Grup listesini oluştur
                group_tags = []
                gl = [g.lower() for g in groups]
                if any("admin" in g for g in gl):
                    group_tags.append("Admin")
                if any(g in ("remote desktop users", "uzak masaüstü kullanıcıları") for g in gl):
                    group_tags.append("RDP")
                if any("iis" in g for g in gl):
                    group_tags.append("IIS")
                if any("users" in g and "admin" not in g and "remote" not in g for g in gl):
                    group_tags.append("Users")
                # Diğer özel gruplar
                known_groups = {
                    "administrators", "users", "remote desktop users",
                    "uzak masaüstü kullanıcıları", "iis_iusrs",
                    "guests", "system managed accounts group",
                    "device owners", "performance log users",
                    "performance monitor users", "event log readers",
                    "distributed com users", "cryptographic operators",
                    "network configuration operators",
                    "access control assistance operators",
                    "certificate service dcom access",
                    "backup operators", "hyper-v administrators",
                    "power users", "replicator",
                }
                for g in groups:
                    if g.lower() not in known_groups:
                        group_tags.append(g)
                groups_str = ", ".join(group_tags) if group_tags else "—"

                entry = {
                    "name": name, "enabled": enabled, "desc": desc,
                    "logon": logon_str, "groups_str": groups_str,
                    "user_type": user_type, "type_color": type_color,
                    "is_iis": is_iis_pool,
                }

                if not enabled:
                    disabled_users.append(entry)
                else:
                    active_users.append(entry)

            # Genel özet
            total = len(users)
            active_count = len(active_users)
            disabled_count = len(disabled_users)
            iis_count = sum(1 for u in active_users if u["is_iis"])

            parts = [f"{self.t('users_total')}: {total}", f"{self.t('users_active')}: {active_count}"]
            if iis_count:
                parts.append(f"{self.t('users_iis')}: {iis_count}")
            parts.append(f"{self.t('users_disabled')}: {disabled_count}")

            ctk.CTkLabel(
                self._users_content_frame,
                text="👥  " + "  |  ".join(parts),
                font=ctk.CTkFont(size=12, weight="bold"),
                text_color=COLORS["green"],
            ).pack(anchor="w", padx=4, pady=(0, 4))

            # ── Tablo başlığı ──
            hdr = ctk.CTkFrame(self._users_content_frame, fg_color=COLORS["bg"],
                               corner_radius=4)
            hdr.pack(fill="x", padx=4, pady=(0, 2))
            for text, w in [(self.t("users_col_name"), 140), (self.t("users_col_type"), 90), (self.t("users_col_groups"), 130),
                            (self.t("users_col_last_logon"), 120), ("", 70)]:
                ctk.CTkLabel(
                    hdr, text=text, width=w, anchor="w",
                    font=ctk.CTkFont(size=10, weight="bold"),
                    text_color=COLORS["text_dim"],
                ).pack(side="left", padx=2)

            # ── Disable callback ──
            def _on_disable_click(username: str):
                import tkinter.messagebox as mbox
                if username.lower() == "administrator":
                    mbox.showwarning(self.t("warn"), self.t("users_admin_no_disable"))
                    return
                ok = mbox.askyesno(
                    self.t("msgbox_disable_user_title"),
                    self.t("msgbox_disable_user_confirm").format(user=username),
                )
                if not ok:
                    return
                auto_response = getattr(self.app, 'auto_response', None)
                if auto_response:
                    result = auto_response.disable_account(username)
                    if result:
                        mbox.showinfo(self.t("info"), self.t("msgbox_user_disabled_ok").format(user=username))
                        import threading as _th
                        _th.Thread(target=self._collect_user_accounts, daemon=True).start()
                    else:
                        mbox.showerror(self.t("error"), self.t("msgbox_user_disabled_fail").format(user=username))
                else:
                    mbox.showerror(self.t("error"), self.t("msgbox_autoresponse_unavailable"))

            # ── Aktif kullanıcı satırları ──
            for u in active_users:
                row = ctk.CTkFrame(self._users_content_frame, fg_color="transparent")
                row.pack(fill="x", padx=4, pady=1)

                is_admin = u["name"].lower() == "administrator"

                # İkon
                if is_admin:
                    icon = "👑"
                elif u["is_iis"]:
                    icon = "🌐"
                else:
                    icon = "👤"

                # Kullanıcı adı
                ctk.CTkLabel(
                    row, text=f"{icon} {u['name']}",
                    font=ctk.CTkFont(size=11, weight="bold"),
                    text_color=u["type_color"], width=140, anchor="w",
                ).pack(side="left", padx=2)

                # Tür sütunu
                ctk.CTkLabel(
                    row, text=u["user_type"],
                    font=ctk.CTkFont(size=10),
                    text_color=u["type_color"], width=90, anchor="w",
                ).pack(side="left", padx=2)

                # Gruplar sütunu
                ctk.CTkLabel(
                    row, text=u["groups_str"],
                    font=ctk.CTkFont(size=10),
                    text_color=COLORS["text_dim"], width=130, anchor="w",
                ).pack(side="left", padx=2)

                # Son giriş sütunu
                ctk.CTkLabel(
                    row, text=u["logon"] if u["logon"] else "—",
                    font=ctk.CTkFont(size=10),
                    text_color=COLORS["text_dim"], width=120, anchor="w",
                ).pack(side="left", padx=2)

                # Pasife Al butonu (admin hariç)
                if not is_admin:
                    uname = u["name"]
                    ctk.CTkButton(
                        row, text=self.t("btn_disable_user"), width=70, height=20,
                        font=ctk.CTkFont(size=10),
                        fg_color="#8B0000", hover_color="#B22222",
                        command=lambda n=uname: _on_disable_click(n),
                    ).pack(side="right", padx=(4, 0))

            # ── Devre dışı kullanıcılar ──
            if disabled_users:
                ctk.CTkLabel(
                    self._users_content_frame,
                    text=f"🔒  {self.t('users_disabled_accounts')} ({disabled_count}):",
                    font=ctk.CTkFont(size=11),
                    text_color=COLORS["text_dim"],
                ).pack(anchor="w", padx=4, pady=(6, 2))

                names = ", ".join(u["name"] for u in disabled_users)
                ctk.CTkLabel(
                    self._users_content_frame,
                    text=f"    {names}",
                    font=ctk.CTkFont(size=11),
                    text_color=COLORS["text_dim"],
                    wraplength=700,
                ).pack(anchor="w", padx=4, pady=0)

        except Exception:
            pass

    # ─── Collector: Network Shares ─── #
    def _collect_network_shares(self):
        """Ağ paylaşımlarını topla."""
        import json
        from client_winproc import run_ps
        shares = []

        try:
            rc, out, _ = run_ps(
                "Get-SmbShare | Select-Object Name, Path, Description, "
                "ShareType, CurrentUsers | ConvertTo-Json",
                timeout=10,
            )
            if rc == 0 and out.strip():
                data = json.loads(out.strip())
                if isinstance(data, dict):
                    data = [data]
                shares = data
        except Exception:
            pass

        self._gui_safe(lambda: self._render_network_shares(shares))

    def _render_network_shares(self, shares: list):
        """Ağ paylaşımlarını GUI'de göster."""
        try:
            for w in self._shares_content_frame.winfo_children():
                w.destroy()

            if not shares:
                ctk.CTkLabel(
                    self._shares_content_frame,
                    text=self.t("shares_info_unavailable"),
                    font=ctk.CTkFont(size=12), text_color=COLORS["text_dim"],
                ).pack(anchor="w", padx=4, pady=2)
                return

            # Varsayılan Windows paylaşımları
            default_shares = {"ADMIN$", "C$", "IPC$", "D$", "E$"}

            custom_shares = [s for s in shares
                             if s.get("Name", "") not in default_shares]
            default_only = len(custom_shares) == 0

            if default_only:
                ctk.CTkLabel(
                    self._shares_content_frame,
                    text=self.t("shares_default_only"),
                    font=ctk.CTkFont(size=12, weight="bold"),
                    text_color=COLORS["green"],
                ).pack(anchor="w", padx=4, pady=(0, 4))
            else:
                ctk.CTkLabel(
                    self._shares_content_frame,
                    text=self.t("shares_custom_detected").format(count=len(custom_shares)),
                    font=ctk.CTkFont(size=12, weight="bold"),
                    text_color=COLORS["orange"],
                ).pack(anchor="w", padx=4, pady=(0, 4))

            for s in shares:
                name = s.get("Name", "")
                path = s.get("Path", "")
                desc = s.get("Description", "") or ""
                users = s.get("CurrentUsers", 0) or 0
                is_default = name in default_shares

                row = ctk.CTkFrame(self._shares_content_frame, fg_color="transparent")
                row.pack(fill="x", padx=4, pady=1)

                icon = "📁" if is_default else "📂"
                color = COLORS["text_dim"] if is_default else COLORS["orange"]

                ctk.CTkLabel(
                    row, text=f"{icon} {name}",
                    font=ctk.CTkFont(size=11, weight="bold"),
                    text_color=color, width=120, anchor="w",
                ).pack(side="left")

                detail = path or desc
                if users > 0:
                    detail += f"  ({users} {self.t('shares_connected_users')})"
                ctk.CTkLabel(
                    row, text=detail,
                    font=ctk.CTkFont(size=11),
                    text_color=COLORS["text_dim"], anchor="w",
                ).pack(side="left", padx=(4, 0), fill="x", expand=True)

                if not is_default and name:
                    ctk.CTkButton(
                        row, text=self.t("shares_btn_remove"),
                        width=70, height=20, font=ctk.CTkFont(size=9),
                        fg_color=COLORS["red"], hover_color=COLORS["red_hover"],
                        command=lambda n=name: self._remove_network_share(n),
                    ).pack(side="right", padx=2)

        except Exception:
            pass

    def _remove_network_share(self, share_name: str):
        """Remove a custom SMB share after confirmation."""
        import tkinter.messagebox as mbox
        try:
            from client_gui_lock import require_gui_unlock
            if not require_gui_unlock(self.app, reason="mutate"):
                return
        except Exception:
            return
        if not mbox.askyesno(
            self.t("shares_remove_title"),
            self.t("shares_remove_confirm").format(name=share_name),
        ):
            return

        def _work():
            from client_winproc import run_ps
            rc, out, err = run_ps(
                f'Remove-SmbShare -Name "{share_name}" -Force',
                timeout=15,
            )
            ok = rc == 0

            def _ui():
                if ok:
                    self.show_toast(
                        self.t("shares_remove_ok"),
                        share_name, "info",
                    )
                    threading.Thread(
                        target=self._collect_network_shares, daemon=True
                    ).start()
                else:
                    self.show_toast(
                        self.t("shares_remove_fail"),
                        (err or out or "")[:160], "warning",
                    )

            self._gui_safe(_ui)

        threading.Thread(target=_work, daemon=True, name="ShareRemove").start()

    # ─── Collector: Suspicious Services ─── #
    def _collect_suspicious_services(self):
        """Windows dışı 3. parti çalışan servisleri topla."""
        import json
        from client_winproc import run_ps_script
        services = []

        try:
            ps_script = (
                'Get-CimInstance Win32_Service | '
                'Where-Object { $_.State -eq "Running" } | '
                'Select-Object Name, DisplayName, PathName, StartMode, StartName | '
                'ConvertTo-Json -Depth 2'
            )
            rc, out, _ = run_ps_script(ps_script, timeout=20)
            if rc == 0 and out.strip():
                data = json.loads(out.strip())
                if isinstance(data, dict):
                    data = [data]
                services = data
        except Exception:
            pass

        self._gui_safe(lambda: self._render_suspicious_services(services))

    def _render_suspicious_services(self, services: list):
        """3. parti servisleri GUI'de göster."""
        try:
            for w in self._services_content_frame.winfo_children():
                w.destroy()

            if not services:
                ctk.CTkLabel(
                    self._services_content_frame,
                    text=self.t("services_info_unavailable"),
                    font=ctk.CTkFont(size=12), text_color=COLORS["text_dim"],
                ).pack(anchor="w", padx=4, pady=2)
                return

            # Microsoft/Windows path'leri (güvenli kabul)
            safe_paths = [
                "c:\\windows\\", "c:\\program files\\common files\\microsoft",
                "c:\\program files\\windows", "\\systemroot\\",
                "c:\\windows\\system32\\", "c:\\windows\\syswow64\\",
            ]

            # Bilinen güvenli 3. parti uygulamalar
            known_safe = [
                "mysql", "mssql", "sqlserver", "apache", "nginx", "iis",
                "maestropanel", "google", "chrome", "honeypot", "yesnext",
                "sqlbackup", "php", "node", "cloudflare", "defender",
            ]

            third_party = []
            for svc in services:
                path = (svc.get("PathName") or "").lower()
                name = (svc.get("Name") or "").lower()
                display = svc.get("DisplayName") or svc.get("Name", "")

                # Windows/Microsoft yolundan çalışanları atla
                is_system = any(path.startswith(sp) for sp in safe_paths)
                if is_system:
                    continue

                # Bilinen güvenli mi?
                is_known = any(k in name or k in path for k in known_safe)
                third_party.append({
                    "name": svc.get("Name", ""),
                    "display": display,
                    "path": svc.get("PathName", ""),
                    "start_mode": svc.get("StartMode", ""),
                    "account": svc.get("StartName", ""),
                    "known": is_known,
                })

            if not third_party:
                ctk.CTkLabel(
                    self._services_content_frame,
                    text=self.t("services_no_suspicious"),
                    font=ctk.CTkFont(size=12, weight="bold"),
                    text_color=COLORS["green"],
                ).pack(anchor="w", padx=4, pady=2)
                return

            unknown_count = sum(1 for s in third_party if not s["known"])
            if unknown_count == 0:
                summary = self.t("services_all_known").format(count=len(third_party))
                summary_color = COLORS["green"]
            else:
                summary = self.t("services_unknown_detected").format(count=unknown_count)
                summary_color = COLORS["orange"]

            ctk.CTkLabel(
                self._services_content_frame,
                text=summary,
                font=ctk.CTkFont(size=12, weight="bold"),
                text_color=summary_color,
            ).pack(anchor="w", padx=4, pady=(0, 6))

            # Bilinmeyenleri önce göster
            sorted_svcs = sorted(third_party, key=lambda x: x["known"])
            for svc in sorted_svcs[:15]:  # En fazla 15 göster
                row = ctk.CTkFrame(self._services_content_frame, fg_color="transparent")
                row.pack(fill="x", padx=4, pady=1)

                if svc["known"]:
                    icon = "✅"
                    color = COLORS["text_dim"]
                else:
                    icon = "⚠️"
                    color = COLORS["orange"]

                ctk.CTkLabel(
                    row, text=f"{icon} {svc['display']}",
                    font=ctk.CTkFont(size=11, weight="bold" if not svc["known"] else "normal"),
                    text_color=color, anchor="w", width=220,
                ).pack(side="left")

                # Kısa path göster
                short_path = svc["path"][:60] + "..." if len(svc["path"]) > 60 else svc["path"]
                ctk.CTkLabel(
                    row, text=f"  {short_path}",
                    font=ctk.CTkFont(size=10),
                    text_color=COLORS["text_dim"], anchor="w",
                ).pack(side="left", padx=(4, 0), fill="x", expand=True)

                svc_name = svc.get("name") or ""
                if svc_name and not svc["known"]:
                    ctk.CTkButton(
                        row, text=self.t("services_btn_stop"),
                        width=60, height=20, font=ctk.CTkFont(size=9),
                        fg_color=COLORS["red"], hover_color=COLORS["red_hover"],
                        command=lambda n=svc_name, d=svc["display"]: self._stop_windows_service(n, d),
                    ).pack(side="right", padx=2)

            if len(third_party) > 15:
                ctk.CTkLabel(
                    self._services_content_frame,
                    text=self.t("services_more_count").format(count=len(third_party) - 15),
                    font=ctk.CTkFont(size=11),
                    text_color=COLORS["text_dim"],
                ).pack(anchor="w", padx=4, pady=(4, 0))

        except Exception:
            pass

    def _stop_windows_service(self, service_name: str, display_name: str = ""):
        """Stop a third-party Windows service after confirmation."""
        import tkinter.messagebox as mbox
        try:
            from client_gui_lock import require_gui_unlock
            if not require_gui_unlock(self.app, reason="mutate"):
                return
        except Exception:
            return
        label = display_name or service_name
        if not mbox.askyesno(
            self.t("services_stop_title"),
            self.t("services_stop_confirm").format(name=label),
        ):
            return

        def _work():
            import subprocess
            result = subprocess.run(
                ["sc", "stop", service_name],
                capture_output=True, text=True, timeout=20,
                creationflags=0x08000000,
            )
            ok = result.returncode == 0

            def _ui():
                if ok:
                    self.show_toast(
                        self.t("services_stop_ok"), label, "info"
                    )
                    threading.Thread(
                        target=self._collect_suspicious_services, daemon=True
                    ).start()
                else:
                    self.show_toast(
                        self.t("services_stop_fail"),
                        (result.stderr or result.stdout or "")[:160],
                        "warning",
                    )

            self._gui_safe(_ui)

        threading.Thread(target=_work, daemon=True, name="SvcStop").start()

    # ─── Live Threat Feed (v4.0 Faz 2) ─── #
    def _build_threat_feed(self, parent):
        """Scrollable live threat feed — shows last 20 alerts in real-time."""
        feed_frame = ctk.CTkFrame(parent, fg_color="transparent")
        feed_frame.pack(fill="x", padx=12, pady=(0, 4))

        ctk.CTkLabel(
            feed_frame, text=self.t("section_live_threat_feed"),
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=COLORS["text_bright"],
        ).pack(anchor="w", padx=4, pady=(0, 4))

        self._threat_feed_box = ctk.CTkTextbox(
            feed_frame, height=100, fg_color=COLORS["bg"],
            border_width=1, border_color=COLORS["border"],
            font=ctk.CTkFont(family="Consolas", size=11),
            text_color=COLORS["text_dim"],
            state="disabled", wrap="word",
        )
        self._threat_feed_box.pack(fill="x", padx=4, pady=(0, 6))

        # Placeholder — veri gelince otomatik temizlenir
        self._threat_feed_box.configure(state="normal")
        self._threat_feed_box.insert("1.0", self.t("placeholder_threat_feed"))
        self._threat_feed_box.configure(state="disabled")
        self._threat_feed_has_data = False

    def _build_response_buttons(self, parent):
        """Quick-action response buttons for dashboard."""
        btn_frame = ctk.CTkFrame(parent, fg_color="transparent")
        btn_frame.pack(fill="x", padx=12, pady=(0, 10))

        ctk.CTkLabel(
            btn_frame, text=self.t("section_quick_response"),
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=COLORS["text_bright"],
        ).pack(anchor="w", padx=4, pady=(0, 6))

        btn_row = ctk.CTkFrame(btn_frame, fg_color="transparent")
        btn_row.pack(fill="x", padx=4)

        buttons = [
            (self.t("btn_block_ip"),   self._on_block_ip_click),
            (self.t("btn_logoff"),     self._on_logoff_click),
            (self.t("btn_disable"),    self._on_disable_click),
            (self.t("btn_snapshot"),   self._on_snapshot_click),
        ]
        for i, (label, cmd) in enumerate(buttons):
            btn = ctk.CTkButton(
                btn_row, text=label, width=100, height=28,
                font=ctk.CTkFont(size=11),
                fg_color=COLORS.get("bg", "#1a1b2e"),
                border_width=1, border_color=COLORS["border"],
                hover_color="#2a2b3e",
                command=cmd,
            )
            btn.pack(side="left", padx=(0, 6), pady=2)

        # Silent hours status indicator
        self._silent_hours_label = ctk.CTkLabel(
            btn_row, text="",
            font=ctk.CTkFont(size=11),
            text_color=COLORS["text_dim"],
        )
        self._silent_hours_label.pack(side="right", padx=4)

    def append_threat_feed(self, text: str):
        """Append a line to the live threat feed (thread-safe via root.after)."""
        def _append():
            try:
                if not hasattr(self, '_threat_feed_box'):
                    return
                self._threat_feed_box.configure(state="normal")
                # İlk gerçek veri geldiğinde placeholder'ı temizle
                if not getattr(self, '_threat_feed_has_data', False):
                    self._threat_feed_box.delete("1.0", "end")
                    self._threat_feed_has_data = True
                self._threat_feed_box.insert("end", text + "\n")
                self._threat_feed_box.see("end")
                # Keep only last 200 lines
                content = self._threat_feed_box.get("1.0", "end")
                lines = content.splitlines()
                if len(lines) > 200:
                    self._threat_feed_box.delete("1.0", f"{len(lines)-200}.0")
                self._threat_feed_box.configure(state="disabled")
            except Exception:
                pass
        if self.root:
            self.root.after(0, _append)

    # ─── Quick Response Button Handlers ─── #
    def _on_block_ip_click(self):
        """Prompt for IP and block it via AutoResponse."""
        dialog = ctk.CTkInputDialog(
            text=self.t("dialog_enter_ip"), title=self.t("dialog_block_ip_title"),
        )
        ip = dialog.get_input()
        if ip and ip.strip():
            ip = ip.strip()
            auto_response = getattr(self.app, 'auto_response', None)
            if auto_response:
                ok = auto_response.block_ip(ip, reason="Manual block from dashboard")
                self.show_toast(
                    self.t("toast_ip_blocked") if ok else self.t("toast_block_failed"),
                    self.t("toast_ip_blocked_msg").format(ip=ip) if ok else self.t("toast_ip_block_failed_msg").format(ip=ip),
                    "high" if ok else "warning",
                )

    def _on_logoff_click(self):
        """Prompt for username and logoff."""
        dialog = ctk.CTkInputDialog(
            text=self.t("dialog_enter_user_logoff"), title=self.t("dialog_logoff_title"),
        )
        username = dialog.get_input()
        if username and username.strip():
            username = username.strip()
            auto_response = getattr(self.app, 'auto_response', None)
            if auto_response:
                ok = auto_response.logoff_user(username)
                self.show_toast(
                    self.t("toast_session_closed") if ok else self.t("toast_logoff_failed"),
                    self.t("toast_logoff_ok_msg").format(user=username) if ok else self.t("toast_logoff_fail_msg").format(user=username),
                    "high" if ok else "warning",
                )

    def _on_disable_click(self):
        """Prompt for username and disable account."""
        dialog = ctk.CTkInputDialog(
            text=self.t("dialog_enter_user_disable"), title=self.t("dialog_disable_title"),
        )
        username = dialog.get_input()
        if username and username.strip():
            username = username.strip()
            auto_response = getattr(self.app, 'auto_response', None)
            if auto_response:
                ok = auto_response.disable_account(username)
                self.show_toast(
                    self.t("toast_account_disabled") if ok else self.t("toast_disable_failed"),
                    self.t("toast_disable_ok_msg").format(user=username) if ok else self.t("toast_disable_fail_msg").format(user=username),
                    "high" if ok else "warning",
                )

    def _on_snapshot_click(self):
        """Take a system snapshot via RemoteCommandExecutor."""
        remote_cmd = getattr(self.app, 'remote_commands', None)
        if remote_cmd:
            result = remote_cmd._cmd_snapshot({})
            if result.get("success"):
                cpu = result.get("cpu_percent", 0)
                mem = result.get("memory", {})
                mem_pct = mem.get("percent", 0)
                conns = result.get("connections", 0)
                self.show_toast(
                    self.t("toast_snapshot_title"),
                    f"CPU: {cpu}%  |  RAM: {mem_pct}%  |  Connections: {conns}",
                    "info", duration_ms=8000,
                )
            else:
                self.show_toast(self.t("toast_snapshot_failed"), result.get("error", "Unknown error"), "warning")

    # ═══════════════════════════════════════════════════════════════
    #  IP AKTİVİTE TABLOSU (Tab 1 — Anlık Durum)
    # ═══════════════════════════════════════════════════════════════

    def _build_ip_activity_table(self, parent):
        """IP listeleri — Aktivite | Engellenen | Whitelist sekmeleri.

        Parent page is a non-scrollable frame so only the table body scrolls
        (avoids nested / double scrollbars).
        """
        sec = ctk.CTkFrame(parent, fg_color=COLORS["card"], corner_radius=12)
        sec.pack(fill="both", expand=True)
        self._ip_table_sec = sec

        self._ip_table_tab = "activity"
        self._ip_table_rows: list = []
        self._ip_tab_buttons: Dict[str, ctk.CTkButton] = {}
        self._ip_tab_keys = {
            "activity": "ip_tab_activity",
            "blocked": "ip_tab_blocked",
            "whitelist": "ip_tab_whitelist",
        }

        hdr = ctk.CTkFrame(sec, fg_color="transparent")
        hdr.pack(fill="x", padx=16, pady=(12, 4))

        title_row = ctk.CTkFrame(hdr, fg_color="transparent")
        title_row.pack(side="left")
        ctk.CTkLabel(
            title_row, text="📡",
            font=self._emoji_font(14),
            text_color=COLORS["text_bright"],
        ).pack(side="left")
        ctk.CTkLabel(
            title_row, text=f"  {self.t('section_ip_activity')}",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=COLORS["text_bright"],
        ).pack(side="left")

        ctk.CTkButton(
            hdr, text="🔄", width=28, height=22,
            font=self._emoji_font(11),
            fg_color=COLORS["bg"], border_width=1, border_color=COLORS["border"],
            hover_color="#2a2b3e",
            command=lambda: self._refresh_ip_table(force_firewall=True),
        ).pack(side="right")

        self._ip_clear_blocked_btn = ctk.CTkButton(
            hdr, text=self.t("ip_btn_clear_all_blocked"),
            width=118, height=22,
            font=ctk.CTkFont(size=11),
            fg_color=COLORS["bg"], border_width=1, border_color=COLORS["red"],
            hover_color="#3a1f28",
            text_color=COLORS["red"],
            command=self._clear_all_blocked_ips,
        )
        self._ip_clear_blocked_btn.pack(side="right", padx=(0, 6))

        # Hızlı aksiyonlar — elle IP girip anında engelle / whitelist'e ekle
        ctk.CTkButton(
            hdr, text=self.t("ip_btn_quick_whitelist"),
            width=118, height=22,
            font=ctk.CTkFont(size=11, weight="bold"),
            fg_color=COLORS["green"], hover_color=COLORS["green_hover"],
            text_color=COLORS["text_bright"],
            command=self._ip_quick_whitelist,
        ).pack(side="right", padx=(0, 6))
        ctk.CTkButton(
            hdr, text=self.t("ip_btn_quick_block"),
            width=100, height=22,
            font=ctk.CTkFont(size=11, weight="bold"),
            fg_color=COLORS["red"], hover_color=COLORS["red_hover"],
            text_color=COLORS["text_bright"],
            command=self._ip_quick_block,
        ).pack(side="right", padx=(0, 6))

        # Sekme çubuğu
        tabs = ctk.CTkFrame(sec, fg_color="transparent")
        tabs.pack(fill="x", padx=16, pady=(6, 4))

        for tab_id, key in (
            ("activity", "ip_tab_activity"),
            ("blocked", "ip_tab_blocked"),
            ("whitelist", "ip_tab_whitelist"),
        ):
            btn = ctk.CTkButton(
                tabs, text=f"{self.t(key)} (0)",
                height=28, width=128,
                font=ctk.CTkFont(size=12, weight="bold"),
                corner_radius=6,
                command=lambda t=tab_id: self._set_ip_table_tab(t),
            )
            btn.pack(side="left", padx=(0, 6))
            self._ip_tab_buttons[tab_id] = btn
        self._update_ip_tab_styles()
        self._update_ip_tab_labels([])

        sep = ctk.CTkFrame(sec, height=1, fg_color=COLORS["border"])
        sep.pack(fill="x", padx=16, pady=(4, 8))

        # Tablo başlığı
        header_row = ctk.CTkFrame(sec, fg_color=COLORS["accent"], corner_radius=4)
        header_row.pack(fill="x", padx=16, pady=(0, 2))

        cols = [
            (self.t("ip_col_address"), 140),
            (self.t("ip_col_service"), 65),
            (self.t("ip_col_score"), 60),
            (self.t("ip_col_last_time"), 130),
            (self.t("ip_col_status"), 80),
        ]
        for text, width in cols:
            ctk.CTkLabel(
                header_row, text=text, width=width,
                font=ctk.CTkFont(size=11, weight="bold"),
                text_color=COLORS["text_bright"], anchor="w",
            ).pack(side="left", padx=4, pady=4)

        ctk.CTkLabel(
            header_row, text=self.t("ip_col_actions"),
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=COLORS["text_bright"], anchor="w",
        ).pack(side="left", padx=4, pady=4, fill="x", expand=True)

        # Tablo içeriği — tek scrollbar; yükseklik viewport'a uyumlanır
        self._ip_table_frame = ctk.CTkScrollableFrame(
            sec, fg_color="transparent", height=240,
        )
        self._ip_table_frame.pack(fill="both", expand=True, padx=16, pady=(0, 12))

        # Boş mesaj
        self._ip_table_empty = ctk.CTkLabel(
            self._ip_table_frame,
            text=self.t("ip_no_activity"),
            font=ctk.CTkFont(size=12),
            text_color=COLORS["text_dim"],
        )
        self._ip_table_empty.pack(anchor="w", padx=4, pady=8)

        def _on_ip_page_configure(_event=None):
            self._fit_ip_table_to_viewport()

        try:
            parent.bind("<Configure>", _on_ip_page_configure, add="+")
        except Exception:
            pass
        if self.root:
            try:
                self.root.after(80, self._fit_ip_table_to_viewport)
            except Exception:
                pass

    def _fit_ip_table_to_viewport(self):
        """IP Lists table fills remaining page height — one scrollbar only."""
        try:
            page = self._pages.get("iplist")
            sec = getattr(self, "_ip_table_sec", None)
            table = getattr(self, "_ip_table_frame", None)
            if page is None or sec is None or table is None:
                return
            page.update_idletasks()
            page_h = int(page.winfo_height() or 0)
            if page_h < 100:
                return
            used = 0
            for child in sec.winfo_children():
                if child is table:
                    continue
                try:
                    used += max(int(child.winfo_reqheight()), int(child.winfo_height()))
                except Exception:
                    continue
            # Card padding + bottom margin
            avail = page_h - used - 36
            table.configure(height=max(140, avail))
        except Exception:
            pass

    def _update_ip_tab_styles(self):
        """Aktif sekme vurgusu."""
        for tab_id, btn in getattr(self, "_ip_tab_buttons", {}).items():
            if tab_id == getattr(self, "_ip_table_tab", "activity"):
                btn.configure(
                    fg_color=COLORS["blue"],
                    hover_color=COLORS["blue_hover"],
                    text_color=COLORS["text_bright"],
                    border_width=0,
                )
            else:
                btn.configure(
                    fg_color=COLORS["bg"],
                    hover_color=COLORS["card_hover"],
                    text_color=COLORS["text"],
                    border_width=1,
                    border_color=COLORS["border"],
                )

    def _ip_tab_counts(self, rows: list) -> Dict[str, int]:
        """Sekme bazlı toplam sayılar (tüm satırlar üzerinden)."""
        activity = blocked = whitelist = 0
        for r in rows or []:
            status = r.get("status")
            if status == "blocked":
                blocked += 1
            elif status == "whitelisted":
                whitelist += 1
            elif status == "watching":
                activity += 1
        return {
            "activity": activity,
            "blocked": blocked,
            "whitelist": whitelist,
        }

    def _update_ip_tab_labels(self, rows: Optional[list] = None):
        """Sekme başlıkları: Aktivite (N) | Engellenen (N) | Whitelist (N)."""
        rows = rows if rows is not None else getattr(self, "_ip_table_rows", [])
        counts = self._ip_tab_counts(rows)
        keys = getattr(self, "_ip_tab_keys", {})
        for tab_id, btn in getattr(self, "_ip_tab_buttons", {}).items():
            try:
                label = self.t(keys.get(tab_id, f"ip_tab_{tab_id}"))
                btn.configure(text=f"{label} ({counts.get(tab_id, 0)})")
            except Exception:
                pass

    def _set_ip_table_tab(self, tab_id: str):
        """Sekme değiştir — mevcut veriyi filtrele."""
        self._ip_table_tab = tab_id
        self._ip_table_fp = None  # force re-render for new filter
        self._update_ip_tab_styles()
        self._render_ip_table(getattr(self, "_ip_table_rows", []))

    def _refresh_ip_table(self, force_firewall: bool = False):
        """IP tablo verisini arka planda topla (coalesce overlapping refreshes)."""
        if getattr(self, "_ip_table_busy", False):
            self._ip_table_pending = True
            self._ip_table_pending_force = bool(
                getattr(self, "_ip_table_pending_force", False) or force_firewall
            )
            return
        self._ip_table_busy = True
        self._ip_table_pending = False
        self._ip_table_pending_force = False

        def _done_coalesce():
            self._ip_table_busy = False
            if getattr(self, "_ip_table_pending", False):
                force = bool(getattr(self, "_ip_table_pending_force", False))
                self._ip_table_pending = False
                self._ip_table_pending_force = False
                self._refresh_ip_table(force_firewall=force)

        def _worker():
            try:
                self._collect_ip_table_data(force_firewall=bool(force_firewall))
            finally:
                try:
                    self._gui_safe(_done_coalesce)
                except Exception:
                    self._ip_table_busy = False

        threading.Thread(target=_worker, daemon=True, name="IpTableRefresh").start()

    def _clear_all_blocked_ips(self):
        """Engellenen: tüm honeypot firewall kurallarını sil + API bildir."""
        self._run_cleanup("firewall", refresh_ip_table=True)

    def _prompt_ip_address(self, title: str) -> Optional[str]:
        """Elle IP girişi — geçerli IPv4/IPv6 döner, geçersizse toast + None."""
        dialog = ctk.CTkInputDialog(title=title, text=self.t("ip_dialog_prompt"))
        raw = dialog.get_input()
        if raw is None:
            return None
        raw = raw.strip()
        if not raw:
            return None
        try:
            import ipaddress
            ipaddress.ip_address(raw)
            return raw
        except ValueError:
            self.show_toast(
                title, self.t("ip_dialog_invalid").format(ip=raw), "warning",
            )
            return None

    def _ip_quick_block(self):
        """Sağ üst hızlı aksiyon: IP sor → engelle."""
        ip = self._prompt_ip_address(self.t("ip_dialog_block_title"))
        if ip:
            self._ip_table_block(ip)

    def _ip_quick_whitelist(self):
        """Sağ üst hızlı aksiyon: IP sor → whitelist'e ekle."""
        ip = self._prompt_ip_address(self.t("ip_dialog_whitelist_title"))
        if ip:
            self._ip_table_whitelist(ip)

    def _collect_ip_table_data(self, force_firewall: bool = False):
        """Arka planda IP verilerini topla (aktivite + engellenen + whitelist).

        Frontend-only (SYSTEM daemon): threat_engine is None — Engellenen must
        still come from ProgramData blocked_ips.json (firewall inventory cache).
        """
        threat_engine = getattr(self.app, 'threat_engine', None)
        auto_response = getattr(self.app, 'auto_response', None)

        rows = []
        seen: set = set()
        contexts = {}
        blocked_ips: set = set()
        whitelist_ips: set = set()

        if threat_engine:
            try:
                contexts = threat_engine.get_all_contexts() or {}
            except Exception:
                contexts = {}
            blocked_ips = set(getattr(threat_engine, '_rule_blocked_ips', set()) or set())
            whitelist_ips = set(getattr(threat_engine, '_whitelist_ips', set()) or set())

        # Live firewall SoT → ProgramData (throttled). Fixes Engellenen(1) vs hundreds of HP-BLOCK.
        try:
            from client_block_store import refresh_from_live_firewall, load_blocked_map
            store_meta = refresh_from_live_firewall(
                min_interval_sec=20.0, force=bool(force_firewall),
            )
            if not store_meta:
                store_meta = load_blocked_map(force=True)
            blocked_ips |= set(store_meta.keys())
        except Exception:
            store_meta = {}
            try:
                from client_block_store import load_blocked_map
                store_meta = load_blocked_map(force=True)
                blocked_ips |= set(store_meta.keys())
            except Exception:
                store_meta = {}

        # AutoResponse'daki aktif blokları / whitelist'i de birleştir
        ar_blocked: set = set()
        if auto_response:
            try:
                ar_blocked = set(getattr(auto_response, '_blocks', {}).keys())
            except Exception:
                pass
            try:
                whitelist_ips |= set(getattr(auto_response, 'whitelist_ips', set()) or set())
            except Exception:
                pass
        ew = getattr(self.app, 'event_watcher', None)
        if ew and hasattr(ew, 'whitelist_ips'):
            try:
                whitelist_ips |= set(ew.whitelist_ips or set())
            except Exception:
                pass

        # Cloud SoT — frontend-only GUI'de engine setleri boş; whitelist
        # threats/config'ten okunmazsa tablo hep "Whitelist boş" gösterir.
        try:
            whitelist_ips |= self._cloud_whitelist_ips(force=bool(force_firewall))
        except Exception:
            pass

        skip = {"local", "", "127.0.0.1", "::1"}

        for ip, ctx in contexts.items():
            if ip in skip:
                continue
            if ctx.threat_score < 1 and ctx.failed_attempts < 1:
                # Blok/whitelist kayıtları aşağıda ayrıca eklenir
                if ip not in blocked_ips and ip not in ar_blocked and ip not in whitelist_ips:
                    continue

            services = list(ctx.services_targeted) if ctx.services_targeted else ["—"]
            service_str = "/".join(services[:2])

            if ip in whitelist_ips:
                status = "whitelisted"
            elif ip in blocked_ips or ip in ar_blocked or getattr(ctx, "is_blocked", False):
                status = "blocked"
            else:
                status = "watching"

            rows.append({
                "ip": ip,
                "service": service_str,
                "attempts": ctx.failed_attempts,
                "last_seen": ctx.last_seen,
                "status": status,
                "score": ctx.threat_score,
            })
            seen.add(ip)

        # Context'te olmayan engellenmiş IP'ler (firewall / store)
        for ip in (blocked_ips | ar_blocked):
            if ip in skip or ip in seen or ip in whitelist_ips:
                continue
            meta = store_meta.get(ip) or {}
            rows.append({
                "ip": ip,
                "service": "—",
                "attempts": 0,
                "last_seen": float(meta.get("blocked_at") or 0),
                "status": "blocked",
                "score": 0,
            })
            seen.add(ip)

        # Context'te olmayan whitelist IP'ler
        for ip in whitelist_ips:
            if ip in skip or ip in seen:
                continue
            rows.append({
                "ip": ip,
                "service": "—",
                "attempts": 0,
                "last_seen": 0,
                "status": "whitelisted",
                "score": 0,
            })
            seen.add(ip)

        rows.sort(key=lambda r: r["last_seen"], reverse=True)
        # Cap display; Engellenen may hold thousands — show newest 2000
        rows = rows[:2000]

        self._gui_safe(lambda: self._render_ip_table(rows))

    def _filter_ip_rows(self, rows: list) -> list:
        """Aktif sekmeye göre satırları filtrele."""
        tab = getattr(self, "_ip_table_tab", "activity")
        if tab == "blocked":
            return [r for r in rows if r.get("status") == "blocked"]
        if tab == "whitelist":
            return [r for r in rows if r.get("status") == "whitelisted"]
        # Aktivite: izlenen + son aktivitesi olan (blocked/whitelist hariç)
        return [r for r in rows if r.get("status") == "watching"]

    def _ip_empty_message(self) -> str:
        tab = getattr(self, "_ip_table_tab", "activity")
        if tab == "blocked":
            return self.t("ip_no_blocked")
        if tab == "whitelist":
            return self.t("ip_no_whitelist")
        return self.t("ip_no_activity")

    def _render_ip_table(self, rows: list):
        """IP tablosunu GUI'ye render et (aktif sekmeye göre)."""
        try:
            self._ip_table_rows = list(rows)
            self._update_ip_tab_labels(rows)
            filtered = self._filter_ip_rows(rows)

            # Skip full destroy/rebuild when visible data unchanged
            fp = tuple(
                (
                    r.get("ip"),
                    r.get("status"),
                    r.get("score"),
                    r.get("service"),
                    r.get("last_seen"),
                )
                for r in filtered[:80]
            )
            if (
                fp == getattr(self, "_ip_table_fp", None)
                and getattr(self, "_ip_table_frame", None)
                and self._ip_table_frame.winfo_children()
            ):
                return
            self._ip_table_fp = fp

            t0 = time.time()
            for w in self._ip_table_frame.winfo_children():
                w.destroy()

            if not filtered:
                ctk.CTkLabel(
                    self._ip_table_frame,
                    text=self._ip_empty_message(),
                    font=ctk.CTkFont(size=12),
                    text_color=COLORS["text_dim"],
                ).pack(anchor="w", padx=4, pady=8)
                return

            from datetime import datetime

            # Cap visible rows to keep Status tab snappy
            visible = filtered[:60]
            for i, r in enumerate(visible):
                bg = COLORS["bg"] if i % 2 == 0 else COLORS["card"]
                row_frame = ctk.CTkFrame(
                    self._ip_table_frame, fg_color=bg,
                    corner_radius=4, height=30,
                )
                row_frame.pack(fill="x", pady=1)
                row_frame.pack_propagate(False)

                # IP
                ip_color = COLORS["red"] if r["status"] == "blocked" else (
                    COLORS["green"] if r["status"] == "whitelisted" else COLORS["text"])
                ctk.CTkLabel(
                    row_frame, text=r["ip"], width=140,
                    font=ctk.CTkFont(family="Consolas", size=11),
                    text_color=ip_color, anchor="w",
                ).pack(side="left", padx=4)

                # Servis
                ctk.CTkLabel(
                    row_frame, text=r["service"], width=65,
                    font=ctk.CTkFont(size=11),
                    text_color=COLORS["text_dim"], anchor="w",
                ).pack(side="left", padx=4)

                # Tehdit skoru (0–100) — eşik karşılaştırması skor üzerinden
                score_val = int(float(r.get("score") or 0))
                score_color = COLORS["red"] if score_val >= 80 else (
                    COLORS["orange"] if score_val >= 40 else COLORS["text_dim"])
                ctk.CTkLabel(
                    row_frame, text=str(score_val), width=60,
                    font=ctk.CTkFont(size=11, weight="bold"),
                    text_color=score_color, anchor="w",
                ).pack(side="left", padx=4)

                # Son zaman
                try:
                    if r["last_seen"]:
                        ts = datetime.fromtimestamp(r["last_seen"]).strftime("%d.%m %H:%M:%S")
                    else:
                        ts = "—"
                except Exception:
                    ts = "—"
                ctk.CTkLabel(
                    row_frame, text=ts, width=130,
                    font=ctk.CTkFont(size=10),
                    text_color=COLORS["text_dim"], anchor="w",
                ).pack(side="left", padx=4)

                # Durum
                status = r["status"]
                if status == "blocked":
                    st_text = self.t("ip_status_blocked")
                    st_color = COLORS["red"]
                elif status == "whitelisted":
                    st_text = self.t("ip_status_whitelisted")
                    st_color = COLORS["green"]
                else:
                    st_text = self.t("ip_status_watching")
                    st_color = COLORS["orange"]
                ctk.CTkLabel(
                    row_frame, text=st_text, width=80,
                    font=ctk.CTkFont(size=10, weight="bold"),
                    text_color=st_color, anchor="w",
                ).pack(side="left", padx=4)

                # Aksiyon butonları — duruma göre dinamik
                ip = r["ip"]
                if status == "blocked":
                    ctk.CTkButton(
                        row_frame, text=self.t("ip_btn_unblock"),
                        width=70, height=20,
                        font=ctk.CTkFont(size=9),
                        fg_color=COLORS["orange"], hover_color=COLORS["orange_hover"],
                        text_color=COLORS["text_bright"], corner_radius=3,
                        command=lambda _ip=ip: self._ip_table_unblock(_ip),
                    ).pack(side="left", padx=2)
                    ctk.CTkButton(
                        row_frame, text=self.t("ip_btn_whitelist"),
                        width=55, height=20,
                        font=ctk.CTkFont(size=9),
                        fg_color=COLORS["green"], hover_color=COLORS["green_hover"],
                        text_color=COLORS["text_bright"], corner_radius=3,
                        command=lambda _ip=ip: self._ip_table_whitelist(_ip),
                    ).pack(side="left", padx=2)
                elif status == "whitelisted":
                    ctk.CTkButton(
                        row_frame, text=self.t("ip_btn_remove_whitelist"),
                        width=75, height=20,
                        font=ctk.CTkFont(size=9),
                        fg_color=COLORS["orange"], hover_color=COLORS["orange_hover"],
                        text_color=COLORS["text_bright"], corner_radius=3,
                        command=lambda _ip=ip: self._ip_table_remove_whitelist(_ip),
                    ).pack(side="left", padx=2)
                    ctk.CTkButton(
                        row_frame, text=self.t("ip_btn_block"),
                        width=55, height=20,
                        font=ctk.CTkFont(size=9),
                        fg_color=COLORS["red"], hover_color=COLORS["red_hover"],
                        text_color=COLORS["text_bright"], corner_radius=3,
                        command=lambda _ip=ip: self._ip_table_block(_ip),
                    ).pack(side="left", padx=2)
                else:
                    ctk.CTkButton(
                        row_frame, text=self.t("ip_btn_block"),
                        width=55, height=20,
                        font=ctk.CTkFont(size=9),
                        fg_color=COLORS["red"], hover_color=COLORS["red_hover"],
                        text_color=COLORS["text_bright"], corner_radius=3,
                        command=lambda _ip=ip: self._ip_table_block(_ip),
                    ).pack(side="left", padx=2)
                    ctk.CTkButton(
                        row_frame, text=self.t("ip_btn_whitelist"),
                        width=55, height=20,
                        font=ctk.CTkFont(size=9),
                        fg_color=COLORS["green"], hover_color=COLORS["green_hover"],
                        text_color=COLORS["text_bright"], corner_radius=3,
                        command=lambda _ip=ip: self._ip_table_whitelist(_ip),
                    ).pack(side="left", padx=2)

            ms = (time.time() - t0) * 1000
            if ms > 50:
                log(f"[PERF] ip_table_render {ms:.0f}ms rows={len(visible)}")

        except Exception as e:
            log(f"[GUI] IP table render error: {e}")

    def _ip_table_block(self, ip: str):
        """IP tablosundan hizli engelle — off-thread (+ daemon IPC)."""
        try:
            from client_gui_lock import require_gui_unlock
            if not require_gui_unlock(self.app, reason="mutate"):
                return
        except Exception:
            return

        def _work():
            ok = self._firewall_mutate_ip(ip, block=True, reason="Manual_block_IP_table")

            def _ui():
                if ok:
                    self.show_toast(
                        self.t("toast_ip_blocked"),
                        self.t("toast_ip_blocked_msg").format(ip=ip),
                        "high",
                    )
                else:
                    self.show_toast(
                        self.t("toast_block_failed"),
                        self.t("toast_ip_blocked_msg").format(ip=ip),
                        "warning",
                    )
                self._refresh_ip_table(force_firewall=True)

            self._gui_safe(_ui)

        threading.Thread(target=_work, daemon=True, name="IpBlock").start()

    def _ip_table_unblock(self, ip: str):
        """IP tablosundan engeli kaldir — off-thread (+ daemon IPC)."""
        try:
            from client_gui_lock import require_gui_unlock
            if not require_gui_unlock(self.app, reason="mutate"):
                return
        except Exception:
            return

        def _work():
            self._firewall_mutate_ip(ip, block=False)

            def _ui():
                self.show_toast(
                    self.t("toast_ip_unblocked"),
                    self.t("toast_ip_unblocked_msg").format(ip=ip),
                    "info",
                )
                self._refresh_ip_table(force_firewall=True)

            self._gui_safe(_ui)

        threading.Thread(target=_work, daemon=True, name="IpUnblock").start()

    def _firewall_mutate_ip(self, ip: str, *, block: bool, reason: str = "gui") -> bool:
        """Apply block/unblock via SYSTEM daemon IPC when possible, else local AR."""
        ip = (ip or "").strip()
        if not ip:
            return False
        try:
            from client_daemon_ipc import is_motor_healthy, block_ip as ipc_block, unblock_ip as ipc_unblock
            if is_motor_healthy(timeout=1.0):
                out = ipc_block(ip, reason=reason) if block else ipc_unblock(ip)
                if out.get("ok"):
                    return True
        except Exception:
            pass

        auto_response = getattr(self.app, "auto_response", None)
        threat_engine = getattr(self.app, "threat_engine", None)
        if block:
            if threat_engine:
                threat_engine._whitelist_ips.discard(ip)
            ew = getattr(self.app, "event_watcher", None)
            if ew and hasattr(ew, "whitelist_ips"):
                ew.whitelist_ips.discard(ip)
            if auto_response:
                auto_response.whitelist_ips.discard(ip)
                ok = bool(auto_response.block_ip(ip, reason=reason.replace("_", " ")))
                if ok and threat_engine:
                    threat_engine._rule_blocked_ips.add(ip)
                    ctx = threat_engine.get_ip_context(ip)
                    if ctx:
                        ctx.is_blocked = True
                return ok
            return False

        ok = False
        if auto_response:
            ok = bool(auto_response.unblock_ip(ip))
        if threat_engine:
            threat_engine._rule_blocked_ips.discard(ip)
            ctx = threat_engine.get_ip_context(ip)
            if ctx:
                ctx.is_blocked = False
            ok = True
        return ok

    def _cloud_whitelist_ips(self, force: bool = False) -> set:
        """Cloud threats/config whitelist_ips — SoT (frontend GUI'de engine yok).

        60 sn cache'lenir; add/remove sonrası effective config ile tazelenir.
        """
        now = time.time()
        cached = getattr(self, "_wl_cloud_cache", None)
        if (
            not force
            and cached is not None
            and now - getattr(self, "_wl_cloud_ts", 0) < 60
        ):
            return set(cached)
        token = self.app.state.get("token", "")
        if not token or not getattr(self.app, "api_client", None):
            return set(cached or [])
        cfg = self.app.api_client.fetch_threat_config(token)
        if isinstance(cfg, dict) and "whitelist_ips" in cfg:
            self._wl_cloud_cache = set(cfg.get("whitelist_ips") or [])
            self._wl_cloud_ts = now
        return set(getattr(self, "_wl_cloud_cache", set()) or set())

    def _persist_whitelist_to_cloud(self, add=None, remove=None) -> bool:
        """Merge-update cloud whitelist_ips (cloud SoT — never blind overwrite).

        Frontend-only GUI has no engine objects; reading only local sets used
        to push an empty list and wipe the cloud whitelist. Start from the
        cloud's current set, union local engine sets (daemon-mode GUI), then
        apply the explicit add/remove delta.
        """
        token = self.app.state.get("token", "")
        if not token or not getattr(self.app, "api_client", None):
            return False
        ips = self._cloud_whitelist_ips(force=True)
        te = getattr(self.app, "threat_engine", None)
        ar = getattr(self.app, "auto_response", None)
        ew = getattr(self.app, "event_watcher", None)
        if te and hasattr(te, "_whitelist_ips"):
            ips |= set(te._whitelist_ips or [])
        if ar and hasattr(ar, "whitelist_ips"):
            ips |= set(ar.whitelist_ips or [])
        if ew and hasattr(ew, "whitelist_ips"):
            ips |= set(ew.whitelist_ips or [])
        for ip in (add or []):
            ips.add(ip)
        for ip in (remove or []):
            ips.discard(ip)
        resp = self.app.api_client.update_threat_config(
            token, {"whitelist_ips": sorted(ips)}
        )
        if not isinstance(resp, dict):
            return False
        effective = resp.get("whitelist_ips")
        self._wl_cloud_cache = (
            set(effective) if isinstance(effective, list) else set(ips)
        )
        self._wl_cloud_ts = time.time()
        return True

    def _ip_table_whitelist(self, ip: str):
        """IP tablosundan guvenli listeye ekle — off-thread + cloud persist."""
        try:
            from client_gui_lock import require_gui_unlock
            if not require_gui_unlock(self.app, reason="mutate"):
                return
        except Exception:
            return

        def _work():
            self._firewall_mutate_ip(ip, block=False)
            threat_engine = getattr(self.app, "threat_engine", None)
            auto_response = getattr(self.app, "auto_response", None)
            if auto_response:
                auto_response.whitelist_ips.add(ip)
            if threat_engine:
                threat_engine._rule_blocked_ips.discard(ip)
                threat_engine._whitelist_ips.add(ip)
                ctx = threat_engine.get_ip_context(ip)
                if ctx:
                    ctx.is_blocked = False
            ew = getattr(self.app, "event_watcher", None)
            if ew and hasattr(ew, "whitelist_ips"):
                ew.whitelist_ips.add(ip)
            synced = self._persist_whitelist_to_cloud(add=[ip])

            def _ui():
                self.show_toast(
                    self.t("ip_status_whitelisted"),
                    self.t("toast_ip_whitelisted_msg").format(ip=ip)
                    + (" ✓" if synced else f" — {self.t('layers_sync_failed')}"),
                    "info" if synced else "warning",
                )
                self._refresh_ip_table(force_firewall=True)

            self._gui_safe(_ui)

        threading.Thread(target=_work, daemon=True, name="IpWhitelist").start()

    def _ip_table_remove_whitelist(self, ip: str):
        """IP'yi güvenli listeden çıkar + cloud'a yaz."""
        try:
            from client_gui_lock import require_gui_unlock
            if not require_gui_unlock(self.app, reason="mutate"):
                return
        except Exception:
            return
        threat_engine = getattr(self.app, 'threat_engine', None)
        auto_response = getattr(self.app, 'auto_response', None)

        if threat_engine:
            threat_engine._whitelist_ips.discard(ip)
        ew = getattr(self.app, 'event_watcher', None)
        if ew and hasattr(ew, 'whitelist_ips'):
            ew.whitelist_ips.discard(ip)
        if auto_response:
            auto_response.whitelist_ips.discard(ip)

        def _work():
            synced = self._persist_whitelist_to_cloud(remove=[ip])

            def _ui():
                self.show_toast(
                    "Whitelist",
                    self.t("toast_ip_removed_whitelist").format(ip=ip)
                    + (" ✓" if synced else f" — {self.t('layers_sync_failed')}"),
                    "info" if synced else "warning",
                )
                self._refresh_ip_table()

            self._gui_safe(_ui)

        threading.Thread(target=_work, daemon=True, name="IpWhitelistRemove").start()

    def _create_stat_card(self, parent, emoji: str, label: str, value: str,
                         color: str, on_click=None) -> ctk.CTkFrame:
        """Tek bir istatistik kartı — ikon + değer aynı satırda."""
        card = ctk.CTkFrame(parent, fg_color=COLORS["bg"], corner_radius=10,
                            border_width=1, border_color=COLORS["border"])

        # Üst satır: ikon | büyük değer (yan yana — wrap yok)
        top = ctk.CTkFrame(card, fg_color="transparent")
        top.pack(fill="x", padx=12, pady=(10, 0))

        emoji_lbl = ctk.CTkLabel(
            top, text=emoji, font=self._emoji_font(20),
            width=28, anchor="w",
        )
        emoji_lbl.pack(side="left", padx=(0, 8))

        value_lbl = ctk.CTkLabel(
            top, text=value,
            font=ctk.CTkFont(size=22, weight="bold"),
            text_color=color,
            anchor="w",
        )
        value_lbl.pack(side="left", fill="x", expand=True)

        # Açıklama
        label_lbl = ctk.CTkLabel(
            card, text=label,
            font=ctk.CTkFont(size=11),
            text_color=COLORS["text_dim"],
            anchor="w",
        )
        label_lbl.pack(anchor="w", padx=12, pady=(2, 0), fill="x")

        # Tıkla göstergesi
        if on_click:
            hint_row = ctk.CTkFrame(card, fg_color="transparent")
            hint_row.pack(anchor="w", padx=12, pady=(0, 6), fill="x")
            hint_icon = ctk.CTkLabel(
                hint_row, text="🔍",
                font=self._emoji_font(9),
                text_color=COLORS["text_dim"],
            )
            hint_icon.pack(side="left")
            hint_lbl = ctk.CTkLabel(
                hint_row, text=" " + self.t("card_click_detail"),
                font=ctk.CTkFont(size=9),
                text_color=COLORS["text_dim"],
            )
            hint_lbl.pack(side="left")
            # Hover/click on card + every child (labels used to steal Leave/clicks)
            self._bind_hover_click(
                card,
                on_click=on_click,
                on_enter=lambda: card.configure(border_color=COLORS["blue"]),
                on_leave=lambda: card.configure(border_color=COLORS["border"]),
            )
        else:
            # Alt padding
            ctk.CTkFrame(card, height=8, fg_color="transparent").pack()

        # value_lbl ve label_lbl referansları card objesine ekleniyor
        card._value_lbl = value_lbl  # type: ignore[attr-defined]
        card._label_lbl = label_lbl  # type: ignore[attr-defined]
        return card

    # ═══════════════════════════════════════════════════════════════
    #  DETAIL POPUP SİSTEMİ — Tıklanabilir Kart Detayları
    # ═══════════════════════════════════════════════════════════════

    def _show_detail_window(self, title: str, width: int = 620, height: int = 480) -> ctk.CTkToplevel:
        """Reusable detail popup — single themed header (no native Win32 title bar).

        Windows note: do NOT combine overrideredirect + transient + grab_set.
        That remaps the Toplevel off-screen / invisible while grab freezes the
        main window (looks like a hang after card click).
        """
        # Close previous detail dialog if still open
        prev = getattr(self, "_active_detail_popup", None)
        if prev is not None:
            try:
                prev.destroy()
            except Exception:
                pass
            self._active_detail_popup = None

        popup = ctk.CTkToplevel(self.root)
        self._active_detail_popup = popup
        try:
            popup.withdraw()
        except Exception:
            pass

        # Frameless BEFORE map — avoids flash of native chrome and Win11 remap bugs
        try:
            popup.overrideredirect(True)
        except Exception:
            pass

        popup.geometry(f"{width}x{height}")
        popup.configure(fg_color=COLORS["bg"])
        # No transient() with overrideredirect — breaks focus/visibility on Windows
        try:
            popup.attributes("-topmost", True)
        except Exception:
            pass

        # Center on parent
        try:
            self.root.update_idletasks()
            px = int(self.root.winfo_rootx() + (self.root.winfo_width() - width) / 2)
            py = int(self.root.winfo_rooty() + (self.root.winfo_height() - height) / 2)
            popup.geometry(f"{width}x{height}+{max(0, px)}+{max(0, py)}")
        except Exception:
            pass

        # Outer border so frameless window still reads as a dialog
        shell = ctk.CTkFrame(
            popup, fg_color=COLORS["bg"],
            border_width=1, border_color=COLORS.get("border", COLORS["accent"]),
            corner_radius=0,
        )
        shell.pack(fill="both", expand=True)

        hdr = ctk.CTkFrame(shell, fg_color=COLORS["accent"], corner_radius=0, height=40)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        title_lbl = ctk.CTkLabel(
            hdr, text=f"  {title}",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=COLORS["text_bright"],
        )
        title_lbl.pack(side="left", padx=8)

        def _close_detail():
            try:
                popup.destroy()
            except Exception:
                pass
            if getattr(self, "_active_detail_popup", None) is popup:
                self._active_detail_popup = None

        ctk.CTkButton(
            hdr, text="✕", width=32, height=28,
            font=ctk.CTkFont(size=13), fg_color="transparent",
            hover_color=COLORS["red"], text_color=COLORS["text_bright"],
            command=_close_detail,
        ).pack(side="right", padx=4)

        # Drag window from custom header (no OS title bar)
        def _start_drag(event):
            popup._drag_ox = event.x_root - popup.winfo_x()
            popup._drag_oy = event.y_root - popup.winfo_y()

        def _on_drag(event):
            try:
                popup.geometry(
                    f"+{event.x_root - getattr(popup, '_drag_ox', 0)}"
                    f"+{event.y_root - getattr(popup, '_drag_oy', 0)}"
                )
            except Exception:
                pass

        for w in (hdr, title_lbl):
            w.bind("<ButtonPress-1>", _start_drag)
            w.bind("<B1-Motion>", _on_drag)

        try:
            popup.bind("<Escape>", lambda _e: _close_detail())
        except Exception:
            pass

        def _on_destroy(_event=None):
            if getattr(self, "_active_detail_popup", None) is popup:
                self._active_detail_popup = None

        try:
            popup.bind("<Destroy>", _on_destroy)
        except Exception:
            pass

        content = ctk.CTkScrollableFrame(shell, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=8, pady=8)
        popup._content = content  # type: ignore[attr-defined]

        def _show():
            try:
                popup.deiconify()
                popup.lift()
                popup.focus_force()
            except Exception:
                pass

        # Show after widgets exist; never grab_set (modal freeze if map fails)
        popup.after(1, _show)
        return popup

    def _add_detail_table(self, parent, headers: list, rows: list,
                          col_widths: list = None, row_actions: list = None):
        """Detail popup'a tablo ekler. row_actions = [(text, color, callback), ...] per row."""
        if not col_widths:
            col_widths = [max(60, 500 // len(headers))] * len(headers)

        # Başlık satırı
        hdr_frame = ctk.CTkFrame(parent, fg_color=COLORS["accent"], corner_radius=6)
        hdr_frame.pack(fill="x", pady=(0, 4))
        for i, text in enumerate(headers):
            w = col_widths[i] if i < len(col_widths) else 100
            ctk.CTkLabel(
                hdr_frame, text=text, width=w, anchor="w",
                font=ctk.CTkFont(size=11, weight="bold"),
                text_color=COLORS["text_bright"],
            ).pack(side="left", padx=4, pady=4)

        # Veri satırları
        for idx, row_data in enumerate(rows):
            bg = COLORS["card"] if idx % 2 == 0 else COLORS["bg"]
            row_frame = ctk.CTkFrame(parent, fg_color=bg, corner_radius=4)
            row_frame.pack(fill="x", pady=1)
            for i, cell in enumerate(row_data):
                w = col_widths[i] if i < len(col_widths) else 100
                color = COLORS["text"]
                # Renkli hücreler — özel prefix ile
                if isinstance(cell, tuple):
                    cell, color = cell
                ctk.CTkLabel(
                    row_frame, text=str(cell), width=w, anchor="w",
                    font=ctk.CTkFont(size=11),
                    text_color=color,
                ).pack(side="left", padx=4, pady=3)

            # Aksiyon butonları
            if row_actions and idx < len(row_actions):
                for btn_text, btn_color, btn_cmd in (row_actions[idx] or []):
                    ctk.CTkButton(
                        row_frame, text=btn_text, width=70, height=22,
                        font=ctk.CTkFont(size=9),
                        fg_color=btn_color, hover_color=btn_color,
                        text_color=COLORS["text_bright"], corner_radius=3,
                        command=btn_cmd,
                    ).pack(side="right", padx=2, pady=2)

    # ── Detail: Toplam Saldırılar ── #
    def _detail_total_attacks(self):
        """Toplam saldırı detay popup — threat engine'den en aktif IP'ler."""
        popup = self._show_detail_window(f"🎯 {self.t('dash_total_attacks')}")
        content = popup._content

        total = getattr(self.app, '_last_attack_count', 0) or 0
        ctk.CTkLabel(
            content, text=f"{self.t('dash_total_attacks')}: {total}",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color=COLORS["red"],
        ).pack(anchor="w", padx=4, pady=(0, 8))

        # Top saldırgan IP'leri — yerel engine (daemon) yoksa IPC ile motordan al.
        attackers = self._collect_top_attackers()

        if not attackers:
            # Bulut toplamı > 0 ama motorda anlık IP context yoksa (ör. saldırılar
            # geçmişte kaydedildi / GUI frontend) kullanıcıya boş ekran değil,
            # bağlamlı bir açıklama göster.
            msg = self.t("detail_no_attacks") if total == 0 else \
                self.t("detail_attacks_cloud_only").format(total=total)
            ctk.CTkLabel(content, text=msg, justify="left",
                         text_color=COLORS["text_dim"]).pack(anchor="w", padx=4)
            return

        from datetime import datetime
        headers = ["IP", self.t("ip_col_service"), self.t("ip_col_attempts"),
                    self.t("detail_score"), self.t("ip_col_last_time")]
        rows = []
        actions = []
        for atk in attackers:
            ip = atk["ip"]
            svc_list = atk.get("services") or []
            services = "/".join(svc_list[:2]) if svc_list else "—"
            last_seen = atk.get("last_seen") or 0
            try:
                ts = datetime.fromtimestamp(last_seen).strftime("%d.%m %H:%M:%S") \
                    if last_seen else "—"
            except Exception:
                ts = "—"
            score = atk.get("threat_score", 0)
            score_color = COLORS["red"] if score >= 80 else (
                COLORS["orange"] if score >= 40 else COLORS["text_dim"])
            rows.append([ip, services, str(atk.get("failed_attempts", 0)),
                         (str(score), score_color), ts])
            _ip = ip
            actions.append([
                (self.t("ip_btn_block"), COLORS["red"],
                 lambda i=_ip: (self._ip_table_block(i), popup.destroy())),
            ])

        self._add_detail_table(content, headers, rows,
                               col_widths=[130, 70, 65, 55, 110], row_actions=actions)

    def _collect_top_attackers(self, limit: int = 25) -> list:
        """Top attacker rows from the local engine, or the SYSTEM motor via IPC.

        The GUI usually runs frontend-only (SYSTEM daemon owns the threat
        engine), so reading ``self.app.threat_engine`` alone leaves the popup
        empty. Fall back to the daemon IPC snapshot in that case.
        """
        threat_engine = getattr(self.app, "threat_engine", None)
        if threat_engine is not None:
            try:
                contexts = threat_engine.get_all_contexts() or {}
                blocked = set(getattr(threat_engine, "_rule_blocked_ips", set()) or set())
                rows = [
                    {
                        "ip": ip,
                        "services": list(ctx.services_targeted or []),
                        "failed_attempts": int(ctx.failed_attempts),
                        "threat_score": int(ctx.threat_score),
                        "last_seen": float(ctx.last_seen or 0),
                        "is_blocked": bool(ctx.is_blocked or ip in blocked),
                    }
                    for ip, ctx in contexts.items()
                    if ip not in ("local", "", "127.0.0.1", "::1")
                    and (ctx.failed_attempts > 0 or ctx.threat_score > 0)
                ]
                rows.sort(key=lambda r: r["failed_attempts"], reverse=True)
                return rows[:limit]
            except Exception as e:
                log(f"[GUI] local top-attacker read failed: {e}")

        try:
            from client_daemon_ipc import threat_top
            resp = threat_top()
            if resp.get("ok"):
                return list(resp.get("attackers") or [])[:limit]
        except Exception as e:
            log(f"[GUI] IPC threat_top failed: {e}")
        return []

    # ── Detail: Oturum Saldırıları ── #
    def _detail_session_attacks(self):
        """Oturumdaki saldırı detayları — servis bazlı credential yakalama istatistikleri."""
        popup = self._show_detail_window(f"⚡ {self.t('dash_session_attacks')}")
        content = popup._content

        sm = self.app.service_manager
        sess = sm.session_stats

        total = sess.get("total_credentials", 0)
        ctk.CTkLabel(
            content, text=f"{self.t('dash_session_attacks')}: {total}",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color=COLORS["orange"],
        ).pack(anchor="w", padx=4, pady=(0, 8))

        # Servis bazlı istatistikler
        svc_stats = sess.get("per_service", {})
        if svc_stats:
            headers = [self.t("ip_col_service"), self.t("ip_col_attempts"),
                       self.t("detail_last_user"), self.t("ip_col_last_time")]
            rows = []
            for svc, data in svc_stats.items():
                count = data if isinstance(data, int) else data.get("count", 0)
                last_user = data.get("last_user", "—") if isinstance(data, dict) else "—"
                last_time = data.get("last_time", "—") if isinstance(data, dict) else "—"
                rows.append([svc.upper(), str(count), last_user, str(last_time)])
            self._add_detail_table(content, headers, rows,
                                   col_widths=[100, 80, 140, 130])

        # Son saldırılar listesi — threat feed'den son 20
        last_ip = sess.get("last_attacker_ip", "")
        last_svc = sess.get("last_service", "")
        if last_ip:
            ctk.CTkLabel(
                content,
                text=f"\n{self.t('detail_last_attacker')}: {last_ip} ({last_svc})",
                font=ctk.CTkFont(size=12, weight="bold"),
                text_color=COLORS["red"],
            ).pack(anchor="w", padx=4, pady=(8, 4))

    # ── Detail: Aktif Servisler ── #
    def _detail_active_services(self):
        """Aktif honeypot servislerinin detayı."""
        popup = self._show_detail_window(f"🟢 {self.t('dash_active_services')}", height=350)
        content = popup._content

        sm = self.app.service_manager
        running = sm.running_services
        total = len(self.app.PORT_TABLOSU)
        monitoring = False
        try:
            monitoring = bool(self.app.is_threat_monitoring_active())
        except Exception:
            monitoring = False

        ctk.CTkLabel(
            content,
            text=f"{self.t('dash_active_services')}: {len(running)}/{total}",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color=COLORS["green"] if running else COLORS["text_dim"],
        ).pack(anchor="w", padx=4, pady=(0, 4))

        # Honeypot bait ≠ port monitoring — kurallar bait kapalıyken de çalışır
        mon_color = COLORS["green"] if monitoring else COLORS["text_dim"]
        mon_text = (
            self.t("detail_port_monitoring_on")
            if monitoring
            else self.t("detail_port_monitoring_off")
        )
        ctk.CTkLabel(
            content,
            text=mon_text,
            font=ctk.CTkFont(size=12),
            text_color=mon_color,
            wraplength=420,
            justify="left",
        ).pack(anchor="w", padx=4, pady=(0, 8))

        headers = [self.t("ip_col_service"), "Port", self.t("detail_status")]
        rows = []
        actions = []
        for port, svc in self.app.PORT_TABLOSU:
            is_active = svc.upper() in [s.upper() for s in running]
            status_text = self.t("status_running") if is_active else self.t("status_stopped")
            status_color = COLORS["green"] if is_active else COLORS["red"]
            rows.append([svc.upper(), str(port), (status_text, status_color)])
            if is_active:
                actions.append([
                    (self.t("honeypot_btn_stop"), COLORS["red"],
                     lambda p=port, s=svc: (
                         self._honeypot_service_action(p, s, start=False),
                         popup.destroy(),
                     )),
                ])
            else:
                actions.append([
                    (self.t("honeypot_btn_start"), COLORS["green"],
                     lambda p=port, s=svc: (
                         self._honeypot_service_action(p, s, start=True),
                         popup.destroy(),
                     )),
                ])
        self._add_detail_table(
            content, headers, rows, col_widths=[150, 80, 120], row_actions=actions
        )

    def _honeypot_service_action(self, port, service, *, start: bool):
        """Start/stop a honeypot bait service from a detail popup."""
        try:
            from client_gui_lock import require_gui_unlock
            if not require_gui_unlock(self.app, reason="mutate"):
                return
        except Exception:
            return

        def _work():
            try:
                if start:
                    ok = bool(self.app.start_single_row(port, service, manual_action=True))
                else:
                    ok = bool(self.app.stop_single_row(port, service, manual_action=True))
            except Exception as e:
                ok = False
                err = str(e)
            else:
                err = ""

            def _ui():
                if ok:
                    self.show_toast(
                        self.t("honeypot_btn_start") if start else self.t("honeypot_btn_stop"),
                        f"{service}:{port}", "info",
                    )
                    self._refresh_dashboard()
                else:
                    self.show_toast(
                        self.t("error"), err or f"{service}:{port}", "warning"
                    )

            self._gui_safe(_ui)

        threading.Thread(target=_work, daemon=True, name="HpServiceAction").start()

    # ── Detail: Son Saldırı ── #
    def _detail_last_attack(self):
        """Son saldırı detayı — en son saldıranın tam profili."""
        popup = self._show_detail_window(f"🕵️ {self.t('dash_last_attack')}", height=400)
        content = popup._content

        threat_engine = getattr(self.app, 'threat_engine', None)
        if not threat_engine:
            ctk.CTkLabel(content, text=self.t("detail_no_data"),
                         text_color=COLORS["text_dim"]).pack(anchor="w", padx=4)
            return

        latest = threat_engine.get_last_attacker()
        if not latest:
            ctk.CTkLabel(content, text=self.t("dash_no_attack"),
                         font=ctk.CTkFont(size=14),
                         text_color=COLORS["text_dim"]).pack(anchor="w", padx=4)
            return

        from datetime import datetime
        ip = latest.get("ip", "—")
        score = latest.get("threat_score", 0)
        fails = latest.get("failed_attempts", 0)
        logins = latest.get("successful_logins", 0)
        services = ", ".join(latest.get("services", []))
        try:
            ts = datetime.fromtimestamp(latest["last_seen"]).strftime("%d.%m.%Y %H:%M:%S")
        except Exception:
            ts = "—"

        info_lines = [
            (f"IP: {ip}", COLORS["red"]),
            (f"Threat Score: {score}", COLORS["orange"] if score >= 40 else COLORS["text"]),
            (f"{self.t('ip_col_attempts')}: {fails}", COLORS["text"]),
            (f"Successful Logins: {logins}", COLORS["red"] if logins > 0 else COLORS["text"]),
            (f"{self.t('ip_col_service')}: {services}", COLORS["text"]),
            (f"{self.t('ip_col_last_time')}: {ts}", COLORS["text_dim"]),
        ]
        for text, color in info_lines:
            ctk.CTkLabel(
                content, text=text, font=ctk.CTkFont(size=13),
                text_color=color,
            ).pack(anchor="w", padx=8, pady=2)

        # Aksiyon butonları
        btn_frame = ctk.CTkFrame(content, fg_color="transparent")
        btn_frame.pack(fill="x", padx=8, pady=(12, 4))
        ctk.CTkButton(
            btn_frame, text=f"🚫 {self.t('ip_btn_block')} {ip}",
            width=160, height=32, font=ctk.CTkFont(size=12, weight="bold"),
            fg_color=COLORS["red"], hover_color=COLORS["red_hover"],
            command=lambda: (self._ip_table_block(ip), popup.destroy()),
        ).pack(side="left", padx=4)
        ctk.CTkButton(
            btn_frame, text=f"✅ {self.t('ip_btn_whitelist')} {ip}",
            width=160, height=32, font=ctk.CTkFont(size=12, weight="bold"),
            fg_color=COLORS["green"], hover_color=COLORS["green_hover"],
            command=lambda: (self._ip_table_whitelist(ip), popup.destroy()),
        ).pack(side="left", padx=4)

    # ── Detail: API Sağlık Durumu ── #
    def _detail_api_health(self):
        """API bağlantı sağlık detayları."""
        popup = self._show_detail_window(f"🌐 {self.t('detail_api_health')}", height=400)
        content = popup._content

        api_ok = getattr(self.app, '_last_api_ok', False)
        status_text = self.t("dash_connected") if api_ok else self.t("dash_disconnected")
        status_color = COLORS["green"] if api_ok else COLORS["red"]

        ctk.CTkLabel(
            content,
            text=f"API: {status_text}",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color=status_color,
        ).pack(anchor="w", padx=8, pady=(0, 8))

        # API istatistikleri — client_api istatistikleri
        api_client = getattr(self.app, 'api_client', None)
        base_url = api_client.base_url if api_client else "—"

        info_items = [
            (f"Base URL: {base_url}", COLORS["text"]),
            (f"Token: {self.app.state.get('token', '—')[:20]}...", COLORS["text_dim"]),
        ]

        # Heartbeat durumu
        hb_ok = getattr(self.app, '_last_heartbeat_ok', None)
        if hb_ok is not None:
            hb_text = "✅ OK" if hb_ok else "❌ FAIL"
            hb_color = COLORS["green"] if hb_ok else COLORS["red"]
            info_items.append((f"Heartbeat: {hb_text}", hb_color))

        # Alert pipeline istatistikleri
        alert_pipeline = getattr(self.app, 'alert_pipeline', None)
        if alert_pipeline:
            try:
                al_stats = alert_pipeline.get_stats()
                sent = al_stats.get("total_sent", 0)
                failed = al_stats.get("total_failed", 0)
                dedup = al_stats.get("dedup_table_size", 0)
                info_items.append((f"Alerts Sent: {sent}", COLORS["green"] if sent > 0 else COLORS["text_dim"]))
                info_items.append((f"Alerts Failed: {failed}", COLORS["red"] if failed > 0 else COLORS["text_dim"]))
                info_items.append((f"Dedup Table: {dedup}", COLORS["text_dim"]))
            except Exception:
                pass

        # MemoryGuard
        mem_guard = getattr(self.app, 'memory_guard', None)
        if mem_guard:
            try:
                import psutil
                proc = psutil.Process()
                mem_mb = proc.memory_info().rss / (1024 * 1024)
                info_items.append((f"Client RAM: {mem_mb:.0f} MB", 
                                   COLORS["red"] if mem_mb > 500 else COLORS["text"]))
            except Exception:
                pass

        for text, color in info_items:
            ctk.CTkLabel(
                content, text=text, font=ctk.CTkFont(size=12),
                text_color=color,
            ).pack(anchor="w", padx=8, pady=2)

        # Bağlantı testi butonu
        def _test_api():
            def _do():
                try:
                    ok = api_client.check_authenticated(max_attempts=1, delay=0) if api_client else False
                    def _show():
                        if ok:
                            self.show_toast("API", self.t("detail_api_ok"), "info")
                        else:
                            self.show_toast("API", self.t("detail_api_fail"), "warning")
                    self._gui_safe(_show)
                except Exception:
                    pass
            threading.Thread(target=_do, daemon=True).start()

        ctk.CTkButton(
            content, text=f"🔄 {self.t('detail_test_connection')}",
            width=200, height=32, font=ctk.CTkFont(size=12, weight="bold"),
            fg_color=COLORS["blue"], hover_color=COLORS["blue_hover"],
            command=_test_api,
        ).pack(anchor="w", padx=8, pady=(12, 4))

    # ── Detail: Ransomware Shield ── #
    def _detail_ransomware(self):
        """Ransomware shield detayları — tespit edilen olaylar + aksiyon butonları."""
        popup = self._show_detail_window(f"🧬 {self.t('card_ransomware')}", height=560)
        content = popup._content

        rs = getattr(self.app, 'ransomware_shield', None)
        stats = {}
        detections = []
        quarantine = {}
        if rs:
            stats = rs.get_stats()
            detections = rs.get_detections()
            quarantine = rs.get_quarantine() if hasattr(rs, "get_quarantine") else {}
        else:
            # Frontend → SYSTEM motor IPC
            try:
                from client_daemon_ipc import ransomware_status
                resp = ransomware_status(timeout=8.0)
                if resp.get("ok"):
                    stats = resp.get("stats") or {}
                    detections = resp.get("detections") or []
                    quarantine = resp.get("quarantine") or {}
            except Exception:
                pass

        if not stats and not rs:
            ctk.CTkLabel(content, text=self.t("detail_no_data"),
                         text_color=COLORS["text_dim"]).pack(anchor="w", padx=4)
            return

        running = stats.get("running", False)
        canary_alerts = stats.get("canary_alerts", 0)
        fs_alerts = stats.get("fs_alerts", 0)
        process_alerts = stats.get("process_alerts", 0)
        vss_alerts = stats.get("vss_alerts", 0)
        total_alerts = stats.get("alerts_total", 0)
        canary_files = stats.get("canary_files", 0)
        q_active = bool(
            quarantine.get("active")
            or stats.get("quarantine_active")
        )
        q_entries = int(
            len(quarantine.get("entries") or [])
            or stats.get("quarantine_entries")
            or 0
        )

        status_text = "🟢 ACTIVE" if running else "🔴 OFF"
        status_color = COLORS["green"] if running else COLORS["red"]

        ctk.CTkLabel(
            content, text=f"Ransomware Shield: {status_text}",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color=status_color,
        ).pack(anchor="w", padx=8, pady=(0, 4))

        if q_active:
            ctk.CTkLabel(
                content,
                text=self.t("detail_rs_quarantine_active").format(count=q_entries),
                font=ctk.CTkFont(size=13, weight="bold"),
                text_color=COLORS["red"],
            ).pack(anchor="w", padx=8, pady=(0, 4))
            ctk.CTkButton(
                content,
                text=self.t("detail_rs_unlock"),
                width=220,
                height=28,
                font=ctk.CTkFont(size=12, weight="bold"),
                fg_color=COLORS["orange"],
                hover_color=COLORS.get("orange_hover") or COLORS["orange"],
                command=lambda: self._unlock_rs_quarantine(popup),
            ).pack(anchor="w", padx=8, pady=(0, 8))

        # Özet istatistikler
        summary_items = [
            (f"📁 Canary Files: {canary_files}", COLORS["text"]),
            (f"🚨 {self.t('detail_rs_canary')}: {canary_alerts}",
             COLORS["red"] if canary_alerts > 0 else COLORS["text_dim"]),
            (f"📂 {self.t('detail_rs_filesystem')}: {fs_alerts}",
             COLORS["red"] if fs_alerts > 0 else COLORS["text_dim"]),
            (f"⚙️ {self.t('detail_rs_process')}: {process_alerts}",
             COLORS["red"] if process_alerts > 0 else COLORS["text_dim"]),
            (f"💾 {self.t('detail_rs_vss')}: {vss_alerts}",
             COLORS["red"] if vss_alerts > 0 else COLORS["text_dim"]),
            (f"📊 {self.t('detail_rs_total')}: {total_alerts}",
             COLORS["orange"] if total_alerts > 0 else COLORS["text_dim"]),
        ]
        for text, color in summary_items:
            ctk.CTkLabel(content, text=text, font=ctk.CTkFont(size=12),
                         text_color=color).pack(anchor="w", padx=8, pady=1)

        # Tespit edilen olaylar — detay tablosu
        if detections:
            ctk.CTkLabel(
                content,
                text=f"\n🔍 {self.t('detail_rs_detections')} ({len(detections)}):",
                font=ctk.CTkFont(size=13, weight="bold"),
                text_color=COLORS["orange"],
            ).pack(anchor="w", padx=8, pady=(8, 4))

            for det in detections[-20:]:  # Son 20 tespit
                det_type = det.get("type", "unknown")
                score = det.get("threat_score", 0)
                score_color = COLORS["red"] if score >= 80 else (
                    COLORS["orange"] if score >= 50 else COLORS["text_dim"])

                det_frame = ctk.CTkFrame(content, fg_color=COLORS["card"], corner_radius=6)
                det_frame.pack(fill="x", padx=8, pady=2)

                if det_type == "canary_triggered":
                    file_path = det.get("file", "—")
                    change = det.get("change", "—")
                    text = f"🚨 CANARY: {os.path.basename(file_path)} — {change}"
                elif det_type == "suspicious_process":
                    pname = det.get("process", "—")
                    pid = det.get("pid", 0)
                    reason = det.get("reason", "—")
                    text = f"⚙️ PROCESS: {pname} (PID {pid}) — {reason}"
                elif det_type == "vss_deletion":
                    text = f"💾 VSS: {det.get('details', 'Shadow copy deletion detected')}"
                elif det_type == "quarantine_lock":
                    text = f"🔒 QUARANTINE: {det.get('trigger', 'lock')}"
                else:
                    text = f"📂 {det_type}: {det.get('details', str(det))}"

                ctk.CTkLabel(
                    det_frame, text=text, font=ctk.CTkFont(size=11),
                    text_color=COLORS["text"], wraplength=550,
                ).pack(side="left", anchor="w", padx=8, pady=4, fill="x", expand=True)

                ctk.CTkLabel(
                    det_frame, text=f"Score: {score}",
                    font=ctk.CTkFont(size=10, weight="bold"),
                    text_color=score_color, width=65,
                ).pack(side="right", padx=4)

                # Süreç durdurma butonu (process tespitleri için)
                if det_type == "suspicious_process" and det.get("pid"):
                    pid = det["pid"]
                    pname = det.get("process", "")
                    ctk.CTkButton(
                        det_frame, text=self.t("detail_kill_process"),
                        width=70, height=20, font=ctk.CTkFont(size=9),
                        fg_color=COLORS["red"], hover_color=COLORS["red_hover"],
                        command=lambda p=pid, n=pname: self._kill_process(p, n),
                    ).pack(side="right", padx=2)
        else:
            ctk.CTkLabel(
                content,
                text=f"\n✅ {self.t('detail_rs_no_detections')}",
                font=ctk.CTkFont(size=13),
                text_color=COLORS["green"],
            ).pack(anchor="w", padx=8, pady=(8, 4))

    def _unlock_rs_quarantine(self, popup=None):
        """GUI / IPC: lift ransomware IFEO quarantine."""
        ok = False
        msg = ""
        rs = getattr(self.app, "ransomware_shield", None)
        try:
            if rs and hasattr(rs, "unlock_quarantine"):
                out = rs.unlock_quarantine(reason="gui")
                ok = bool(out.get("ok"))
                msg = str(out)
            else:
                from client_daemon_ipc import ransomware_unlock
                resp = ransomware_unlock(timeout=20.0)
                ok = bool(resp.get("ok"))
                msg = resp.get("error") or str(resp)
        except Exception as e:
            msg = str(e)
        try:
            self.show_toast(
                self.t("detail_rs_unlock_ok") if ok else self.t("detail_rs_unlock_fail"),
                msg[:180] if msg else "",
            )
        except Exception:
            pass
        try:
            if popup is not None and hasattr(popup, "destroy"):
                popup.destroy()
        except Exception:
            pass

    # ── Detail: CPU / RAM ── #
    def _detail_cpu_ram(self):
        """CPU ve RAM kullanım detayları + en çok kaynak kullanan süreçler."""
        popup = self._show_detail_window(f"💻 {self.t('card_cpu_ram')}", height=480)
        content = popup._content

        import psutil

        cpu = psutil.cpu_percent(interval=0.5)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage("C:\\")

        ctk.CTkLabel(
            content,
            text=f"CPU: {cpu:.1f}%  |  RAM: {mem.percent:.1f}%  |  Disk: {disk.percent:.1f}%",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color=COLORS["orange"] if cpu > 70 or mem.percent > 80 else COLORS["green"],
        ).pack(anchor="w", padx=8, pady=(0, 4))

        info = [
            (f"RAM: {mem.used / (1024**3):.1f} GB / {mem.total / (1024**3):.1f} GB", COLORS["text"]),
            (f"Disk: {disk.used / (1024**3):.0f} GB / {disk.total / (1024**3):.0f} GB", COLORS["text"]),
            (f"CPU Cores: {psutil.cpu_count(logical=True)}", COLORS["text_dim"]),
        ]
        for text, color in info:
            ctk.CTkLabel(content, text=text, font=ctk.CTkFont(size=12),
                         text_color=color).pack(anchor="w", padx=8, pady=1)

        # Client process memory
        proc = psutil.Process()
        client_mem = proc.memory_info().rss / (1024 * 1024)
        client_color = COLORS["red"] if client_mem > 500 else (
            COLORS["orange"] if client_mem > 200 else COLORS["green"])
        ctk.CTkLabel(
            content,
            text=f"Honeypot Client RAM: {client_mem:.0f} MB",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=client_color,
        ).pack(anchor="w", padx=8, pady=(4, 8))

        # Top süreçler
        ctk.CTkLabel(
            content,
            text=f"🔝 {self.t('detail_top_processes')}:",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=COLORS["text_bright"],
        ).pack(anchor="w", padx=8, pady=(4, 4))

        processes = []
        for p in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info']):
            try:
                pinfo = p.info
                mem_mb = pinfo['memory_info'].rss / (1024 * 1024) if pinfo.get('memory_info') else 0
                processes.append({
                    'pid': pinfo['pid'],
                    'name': pinfo['name'] or '—',
                    'cpu': pinfo.get('cpu_percent', 0) or 0,
                    'mem_mb': mem_mb,
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # RAM'e göre sırala
        top_procs = sorted(processes, key=lambda p: p['mem_mb'], reverse=True)[:15]

        headers = ["PID", self.t("detail_process_name"), "CPU %", "RAM (MB)"]
        rows = []
        actions = []
        for p in top_procs:
            cpu_color = COLORS["red"] if p['cpu'] > 50 else COLORS["text"]
            mem_color = COLORS["orange"] if p['mem_mb'] > 200 else COLORS["text"]
            rows.append([
                str(p['pid']), p['name'],
                (f"{p['cpu']:.1f}", cpu_color),
                (f"{p['mem_mb']:.0f}", mem_color),
            ])
            actions.append([
                (self.t("detail_kill_process"), COLORS["red"],
                 lambda pid=p['pid'], name=p['name']: self._kill_process(pid, name)),
            ])

        self._add_detail_table(content, headers, rows,
                               col_widths=[60, 200, 65, 80], row_actions=actions)

    # ── Detail: Self-Protection ── #
    def _detail_self_protect(self):
        """Protection engine / self-protection detayları.

        Frontend-only GUI'de yerel `process_protection` nesnesi bulunmaz; bu
        nesne yalnızca SYSTEM daemon sürecinde yaşar. Bu yüzden durumu, koruma
        şeridi chip'iyle AYNI kaynaktan — daemon STATUS (IPC) — okuruz. Böylece
        "chip AKTİF ama popup OFF" çelişkisi ortadan kalkar.
        """
        popup = self._show_detail_window(f"🔒 {self.t('card_protection')}", height=360)
        content = popup._content

        st = getattr(self, "_cached_daemon_status", None) or {}
        if not st:
            try:
                from client_daemon_ipc import get_status
                st = get_status(timeout=3.0) or {}
            except Exception:
                st = {}
        pers = st.get("persistence") or {}

        pp = getattr(self.app, "process_protection", None)
        motor_ok = bool(getattr(self, "_cached_motor_ok", False) or st.get("motor_ok"))
        # Koruma AKTİF sayılır: yerel engine varsa, daemon self_protection true ise,
        # ya da SYSTEM motoru sağlıklıysa (frontend GUI için tek gerçek kaynak).
        prot_on = bool(pp) or bool(pers.get("self_protection")) or motor_ok

        on, off = self.t("prot_state_on"), self.t("prot_state_off")
        ctk.CTkLabel(
            content,
            text=f"🔒 {self.t('card_protection')}: {on if prot_on else off}",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color=COLORS["green"] if prot_on else COLORS["red"],
        ).pack(anchor="w", padx=8, pady=(0, 4))
        if prot_on:
            ctk.CTkLabel(content, text=self.t("detail_sp_desc"),
                         font=ctk.CTkFont(size=12),
                         text_color=COLORS["text"]).pack(anchor="w", padx=8, pady=2)

        # Koruma motoru (SYSTEM daemon) — şeritteki "Koruma Motoru" chip'iyle aynı
        ctk.CTkLabel(
            content,
            text=f"⚙️ {self.t('prot_chip_motor')}: {on if motor_ok else off}",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=COLORS["green"] if motor_ok else COLORS["red"],
        ).pack(anchor="w", padx=8, pady=(8, 1))

        # Guardian / kalıcılık servisi
        if pers:
            svc_ok = bool(pers.get("service_ok"))
            tamper = int(pers.get("tamper_count_24h") or 0)
            ctk.CTkLabel(
                content,
                text=f"🛟 {self.t('prot_chip_guardian')}: {on if svc_ok else off}",
                font=ctk.CTkFont(size=12),
                text_color=COLORS["green"] if svc_ok else COLORS["orange"],
            ).pack(anchor="w", padx=8, pady=1)
            if tamper > 0:
                ctk.CTkLabel(
                    content, text=f"⚠ tamper 24h: {tamper}",
                    font=ctk.CTkFont(size=12),
                    text_color=COLORS["orange"],
                ).pack(anchor="w", padx=8, pady=1)

        # MemoryGuard — yerel nesne varsa ya da motor sağlıklıysa aktiftir
        mg = getattr(self.app, "memory_guard", None)
        if mg or motor_ok:
            ctk.CTkLabel(content, text="🧠 MemoryGuard: ACTIVE",
                         font=ctk.CTkFont(size=13, weight="bold"),
                         text_color=COLORS["green"]).pack(anchor="w", padx=8, pady=(8, 2))
            if mg:
                try:
                    import psutil
                    client_mem = psutil.Process().memory_info().rss / (1024 * 1024)
                    ctk.CTkLabel(content, text=f"Current: {client_mem:.0f} MB",
                                 font=ctk.CTkFont(size=12),
                                 text_color=COLORS["text"]).pack(anchor="w", padx=8, pady=1)
                except Exception:
                    pass

    # ── Detail: Threat Level ── #
    def _detail_threat_level(self):
        """Tehdit seviyesi detayı — en yüksek skorlu IP'ler."""
        popup = self._show_detail_window(f"🛡️ {self.t('card_threat_level')}")
        content = popup._content

        threat_engine = getattr(self.app, 'threat_engine', None)
        if not threat_engine:
            ctk.CTkLabel(content, text=self.t("detail_no_data"),
                         text_color=COLORS["text_dim"]).pack(anchor="w", padx=4)
            return

        level, level_color = threat_engine.get_threat_level()
        ctk.CTkLabel(
            content,
            text=f"{self.t('card_threat_level')}: {level}",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color=level_color,
        ).pack(anchor="w", padx=8, pady=(0, 8))

        # Son tehditler (yüksek skor)
        recent = threat_engine.get_recent_threats(max_age_seconds=3600, min_score=20)
        if recent:
            from datetime import datetime
            headers = ["IP", self.t("detail_score"), self.t("ip_col_attempts"),
                       self.t("ip_col_service"), self.t("ip_col_last_time")]
            rows = []
            actions = []
            for t in recent[:20]:
                score_color = COLORS["red"] if t["threat_score"] >= 80 else (
                    COLORS["orange"] if t["threat_score"] >= 40 else COLORS["text_dim"])
                services = "/".join(t.get("services", [])[:2])
                try:
                    ts = datetime.fromtimestamp(t["last_seen"]).strftime("%d.%m %H:%M")
                except Exception:
                    ts = "—"
                rows.append([t["ip"], (str(t["threat_score"]), score_color),
                             str(t["failed_attempts"]), services, ts])
                _ip = t["ip"]
                actions.append([
                    (self.t("ip_btn_block"), COLORS["red"],
                     lambda i=_ip: (self._ip_table_block(i), popup.destroy())),
                ])
            self._add_detail_table(content, headers, rows,
                                   col_widths=[130, 55, 65, 80, 100], row_actions=actions)
        else:
            ctk.CTkLabel(content, text=f"✅ {self.t('detail_no_threats')}",
                         font=ctk.CTkFont(size=13),
                         text_color=COLORS["green"]).pack(anchor="w", padx=8, pady=8)

    # ── Detail: Olaylar/Saat ── #
    def _detail_events_per_hour(self):
        """Olay/saat detayı — ThreatEngine istatistikleri."""
        popup = self._show_detail_window(f"📊 {self.t('card_events_per_hour')}", height=350)
        content = popup._content

        threat_engine = getattr(self.app, 'threat_engine', None)
        if not threat_engine:
            ctk.CTkLabel(content, text=self.t("detail_no_data"),
                         text_color=COLORS["text_dim"]).pack(anchor="w", padx=4)
            return

        stats = threat_engine.get_stats()
        events_scored = stats.get("events_scored", 0)
        uptime_sec = int(time.time() - self._start_time) or 1
        eph = int(events_scored / (uptime_sec / 3600)) if uptime_sec > 60 else 0

        ctk.CTkLabel(
            content,
            text=f"{self.t('card_events_per_hour')}: {eph}",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color=COLORS["orange"] if eph > 100 else COLORS["text"],
        ).pack(anchor="w", padx=8, pady=(0, 8))

        info = [
            (f"{self.t('detail_events_total')}: {events_scored}", COLORS["text"]),
            (f"{self.t('detail_events_blocked')}: {stats.get('ips_blocked', 0)}", COLORS["red"]),
            (f"Uptime: {self._format_uptime(uptime_sec)}", COLORS["text_dim"]),
            (f"Active IPs: {stats.get('active_ips', 0)}", COLORS["text"]),
        ]
        for text, color in info:
            ctk.CTkLabel(content, text=text, font=ctk.CTkFont(size=12),
                         text_color=color).pack(anchor="w", padx=8, pady=2)

    # ── Detail: Engellenen IP'ler ── #
    def _tracked_ip_snapshot(self) -> dict:
        """One canonical dataset for the tracked-IP card and its detail view."""
        threat_engine = getattr(self.app, "threat_engine", None)
        store_blocks = []
        try:
            from client_block_store import list_blocked_ips
            store_blocks = list_blocked_ips()
        except Exception:
            pass

        blocked = {
            str(b.get("ip") or "") for b in store_blocks if b.get("ip")
        }
        contexts = {}
        if threat_engine:
            blocked |= set(
                getattr(threat_engine, "_rule_blocked_ips", set()) or set()
            )
            try:
                contexts = threat_engine.get_all_contexts() or {}
            except Exception:
                pass
        active_ips = [
            (ip, ctx) for ip, ctx in contexts.items()
            if ip not in ("local", "", "127.0.0.1", "::1")
            and (ctx.threat_score > 0 or ctx.failed_attempts > 0)
        ]
        watching = [
            (ip, ctx) for ip, ctx in active_ips
            if ip not in blocked and not getattr(ctx, "is_blocked", False)
        ]
        # Union semantics: a blocked address is counted once even if it also has
        # an active threat context.
        return {
            "threat_engine": threat_engine,
            "store_blocks": store_blocks,
            "blocked": blocked,
            "contexts": contexts,
            "active_ips": active_ips,
            "watching": watching,
            "total": len(blocked) + len(watching),
        }

    def _open_blocked_ips_tab(self):
        """Tehdit Merkezi kartı → IP Listeleri sekmesi (Engellenen filtresi)."""
        self._show_page("iplist")
        try:
            self._set_ip_table_tab("blocked")
        except Exception:
            self._ip_table_tab = "blocked"
        try:
            self._refresh_ip_table(force_firewall=True)
        except Exception:
            pass

    def _detail_blocked_ips(self):
        """Geriye uyumluluk: eski detay popup yerine IP Listeleri sekmesini aç."""
        self._open_blocked_ips_tab()

    # ── Süreç Durdurma (Process Kill) ── #
    def _kill_process(self, pid: int, name: str = ""):
        """Belirtilen PID'li süreci durdur."""
        import tkinter.messagebox as mbox
        ok = mbox.askyesno(
            self.t("detail_kill_confirm_title"),
            self.t("detail_kill_confirm_msg").format(name=name, pid=pid),
        )
        if not ok:
            return
        try:
            import psutil
            proc = psutil.Process(pid)
            proc.terminate()
            # 3 saniye bekle, hala yaşıyorsa kill
            try:
                proc.wait(timeout=3)
            except psutil.TimeoutExpired:
                proc.kill()
            self.show_toast(
                self.t("detail_process_killed"),
                self.t("detail_process_killed_msg").format(name=name, pid=pid),
                "high",
            )
        except psutil.NoSuchProcess:
            self.show_toast(self.t("detail_process_not_found"),
                            f"PID {pid}", "warning")
        except psutil.AccessDenied:
            self.show_toast(self.t("detail_process_access_denied"),
                            f"{name} (PID {pid})", "warning")
        except Exception as e:
            self.show_toast(self.t("error"), str(e), "warning")

    # ─── Command History Panel (v4.0 Faz 4) ─── #
    def _build_command_history(self, parent):
        """Scrollable command execution history — last 50 remote commands & results."""
        sec = ctk.CTkFrame(parent, fg_color=COLORS["card"], corner_radius=12)
        sec.pack(fill="x", pady=(0, 12))

        ctk.CTkLabel(
            sec, text=self.t("section_command_history"),
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=COLORS["text_bright"],
        ).pack(anchor="w", padx=16, pady=(12, 4))

        self._cmd_history_box = ctk.CTkTextbox(
            sec, height=100, fg_color=COLORS["bg"],
            border_width=1, border_color=COLORS["border"],
            font=ctk.CTkFont(family="Consolas", size=10),
            text_color=COLORS["text_dim"],
            state="disabled", wrap="word",
        )
        self._cmd_history_box.pack(fill="x", padx=16, pady=(0, 12))

        # Placeholder
        self._cmd_history_box.configure(state="normal")
        self._cmd_history_box.insert("1.0", self.t("placeholder_command_history"))
        self._cmd_history_box.configure(state="disabled")
        self._cmd_history_has_data = False

    # ─── Active Sessions Panel (v4.0 Faz 4) ─── #
    def _build_active_sessions(self, parent):
        """Active RDP/console sessions display with refresh button."""
        sec = ctk.CTkFrame(parent, fg_color=COLORS["card"], corner_radius=12)
        sec.pack(fill="x", pady=(0, 12))

        hdr = ctk.CTkFrame(sec, fg_color="transparent")
        hdr.pack(fill="x", padx=16, pady=(12, 4))

        ctk.CTkLabel(
            hdr, text=self.t("section_active_sessions"),
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=COLORS["text_bright"],
        ).pack(side="left")

        ctk.CTkButton(
            hdr, text="🔄", width=28, height=22,
            font=self._emoji_font(11),
            fg_color=COLORS.get("bg", "#1a1b2e"),
            border_width=1, border_color=COLORS["border"],
            hover_color="#2a2b3e",
            command=self._refresh_active_sessions,
        ).pack(side="right")

        self._sessions_box = ctk.CTkTextbox(
            sec, height=80, fg_color=COLORS["bg"],
            border_width=1, border_color=COLORS["border"],
            font=ctk.CTkFont(family="Consolas", size=10),
            text_color=COLORS["text_dim"],
            state="disabled", wrap="word",
        )
        self._sessions_box.pack(fill="x", padx=16, pady=(0, 12))

        # Placeholder + otomatik yükle
        self._sessions_box.configure(state="normal")
        self._sessions_box.insert("1.0", self.t("loading_sessions"))
        self._sessions_box.configure(state="disabled")
        # Data load deferred — _lazy_load_threat_data

    # ─── Remote Desktop Status Panel ─── #
    def _build_remote_desktop_panel(self, parent):
        """Dashboard-controlled screen mirror status (ready / streaming / idle)."""
        sec = ctk.CTkFrame(parent, fg_color=COLORS["card"], corner_radius=12)
        sec.pack(fill="x", pady=(0, 12))

        hdr = ctk.CTkFrame(sec, fg_color="transparent")
        hdr.pack(fill="x", padx=16, pady=(12, 4))

        ctk.CTkLabel(
            hdr, text=self.t("section_remote_desktop"),
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=COLORS["text_bright"],
        ).pack(side="left")

        self._rd_badge = ctk.CTkLabel(
            hdr, text=self.t("rd_badge_ready"),
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=COLORS.get("green", "#10b981"),
        )
        self._rd_badge.pack(side="left", padx=(10, 0))

        btn_row = ctk.CTkFrame(hdr, fg_color="transparent")
        btn_row.pack(side="right")

        ctk.CTkButton(
            btn_row, text=self.t("rd_btn_stop"), width=70, height=22,
            font=ctk.CTkFont(size=10),
            fg_color=COLORS.get("red", "#f43f5e"),
            hover_color=COLORS.get("red_hover", "#fb7185"),
            command=self._stop_remote_desktop_local,
        ).pack(side="right", padx=(6, 0))

        ctk.CTkButton(
            btn_row, text="🔄", width=28, height=22,
            font=self._emoji_font(11),
            fg_color=COLORS.get("bg", "#1a1b2e"),
            border_width=1, border_color=COLORS["border"],
            hover_color="#2a2b3e",
            command=self._refresh_remote_desktop_status,
        ).pack(side="right")

        self._rd_info = ctk.CTkLabel(
            sec,
            text=self.t("rd_hint"),
            font=ctk.CTkFont(size=11),
            text_color=COLORS["text_dim"],
            justify="left",
            anchor="w",
            wraplength=520,
        )
        self._rd_info.pack(fill="x", padx=16, pady=(4, 12))

        # Wire event callback + first paint
        try:
            rc = getattr(self.app, "remote_commands", None)
            if rc is not None:
                rc.on_remote_desktop_event = lambda ev: self._gui_safe(
                    lambda: self._on_remote_desktop_event(ev)
                )
        except Exception:
            pass
        # Status refresh deferred — _lazy_load_threat_data

    def _refresh_remote_desktop_status(self):
        """Update remote-desktop badge + details from CommandExecutor."""
        def _do():
            st = {
                "ready": False,
                "streaming": False,
            }
            try:
                rc = getattr(self.app, "remote_commands", None)
                if rc and hasattr(rc, "get_remote_desktop_status"):
                    st = rc.get_remote_desktop_status() or st
                elif rc is None:
                    st = {"ready": False, "streaming": False, "error": "remote_commands_off"}
            except Exception as e:
                st = {"ready": False, "streaming": False, "error": str(e)}

            streaming = bool(st.get("streaming"))
            ready = bool(st.get("ready", True)) and not st.get("error")
            transport = (st.get("transport") or "idle").lower()
            stats = st.get("stats") or {}
            fps = st.get("fps", 0)
            frames = stats.get("frames_sent", 0)
            failed = stats.get("frames_failed", 0)
            inputs = stats.get("inputs_applied", 0)
            cap = st.get("capture") or {}
            cw, ch = cap.get("w") or 0, cap.get("h") or 0

            if streaming:
                if transport == "websocket" or st.get("websocket"):
                    badge = self.t("rd_badge_ws")
                    color = COLORS.get("green", "#10b981")
                    detail = self.t("rd_detail_streaming_ws").format(
                        fps=fps, w=cw, h=ch, frames=frames, failed=failed, inputs=inputs,
                        method=st.get("capture_method") or "—",
                    )
                else:
                    badge = self.t("rd_badge_http")
                    color = COLORS.get("orange", "#f59e0b")
                    detail = self.t("rd_detail_streaming_http").format(
                        fps=fps, w=cw, h=ch, frames=frames, failed=failed, inputs=inputs,
                        method=st.get("capture_method") or "—",
                    )
            elif ready:
                badge = self.t("rd_badge_ready")
                color = COLORS.get("green", "#10b981")
                detail = self.t("rd_detail_ready")
            else:
                badge = self.t("rd_badge_unavailable")
                color = COLORS.get("red", "#f43f5e")
                detail = self.t("rd_detail_unavailable").format(
                    error=st.get("error") or "—",
                )

            def _paint():
                try:
                    if hasattr(self, "_rd_badge"):
                        self._rd_badge.configure(text=badge, text_color=color)
                    if hasattr(self, "_rd_info"):
                        self._rd_info.configure(text=detail)
                except Exception:
                    pass

            self._gui_safe(_paint)

        threading.Thread(target=_do, daemon=True, name="RDStatusRefresh").start()

    def _stop_remote_desktop_local(self):
        """Local emergency stop if dashboard left the stream running."""
        rc = getattr(self.app, "remote_commands", None)
        if not rc or not hasattr(rc, "stop_remote_desktop_local"):
            messagebox.showinfo(self.t("section_remote_desktop"), self.t("rd_detail_unavailable").format(error="n/a"))
            return
        result = rc.stop_remote_desktop_local(reason="local_ui")
        self._refresh_remote_desktop_status()
        if result.get("success"):
            messagebox.showinfo(self.t("section_remote_desktop"), self.t("rd_stopped_local"))
        else:
            messagebox.showerror(
                self.t("section_remote_desktop"),
                result.get("error") or self.t("rd_stop_fail"),
            )

    def _on_remote_desktop_event(self, event: str):
        self._refresh_remote_desktop_status()
        try:
            if event == "started":
                self.show_toast(self.t("section_remote_desktop"), self.t("rd_toast_started"), severity="warning")
            elif event == "stopped":
                self.show_toast(self.t("section_remote_desktop"), self.t("rd_toast_stopped"), severity="info")
        except Exception:
            pass

    def _refresh_active_sessions(self):
        """Fetch and display active sessions via 'query user' + 'query session'."""
        from client_winproc import run_hidden

        def _do():
            lines = []
            try:
                # query user — RDP/console oturumlarını gösterir
                _rc1, raw, _ = run_hidden(["query", "user"], timeout=5)
                raw = (raw or "").strip()
                if raw:
                    # Parse query user output into Turkish-friendly format
                    for line in raw.splitlines():
                        parts = line.split()
                        if not parts:
                            continue
                        # Header line
                        if parts[0].upper() in ("USERNAME", "KULLANICI"):
                            lines.append("  " + self.t("sessions_header"))
                            lines.append("  " + "─" * 60)
                            continue
                        # Data line — may start with > for current user
                        marker = ""
                        if parts[0].startswith(">"):
                            parts[0] = parts[0][1:]
                            marker = "► "
                        username = parts[0] if len(parts) > 0 else ""
                        session = parts[1] if len(parts) > 1 else ""
                        sess_id = parts[2] if len(parts) > 2 else ""
                        state = parts[3] if len(parts) > 3 else ""
                        # Logon time is typically the last 2 parts
                        logon = " ".join(parts[-2:]) if len(parts) >= 6 else ""
                        state_tr = self.t("session_active") if state.lower() == "active" else (
                            self.t("session_disconnected") if state.lower() == "disc" else state)
                        icon = "🟢" if state.lower() == "active" else "🔴"
                        lines.append(
                            f"  {marker}{icon} {username:<18} {session:<13} {state_tr:<12} {logon}"
                        )
            except Exception:
                pass

            if not lines:
                # Fallback: query session
                try:
                    _rc2, out2, _ = run_hidden(["query", "session"], timeout=5)
                    if (out2 or "").strip():
                        lines = ["  " + l for l in out2.strip().splitlines()]
                except Exception:
                    pass

            output = "\n".join(lines) if lines else self.t("sessions_none")

            def _update():
                try:
                    if hasattr(self, '_sessions_box'):
                        self._sessions_box.configure(state="normal")
                        self._sessions_box.delete("1.0", "end")
                        self._sessions_box.insert("1.0", output)
                        self._sessions_box.configure(state="disabled")
                except Exception:
                    pass
            if self.root:
                self.root.after(0, _update)

        import threading as _th
        _th.Thread(target=_do, daemon=True).start()

    # ─── Trend Mini-Charts (v4.0 Faz 4) ─── #
    def _build_trend_panel(self, parent):
        """ASCII-style trend mini-charts for CPU, events/hour, and threat score."""
        sec = ctk.CTkFrame(parent, fg_color=COLORS["card"], corner_radius=12)
        sec.pack(fill="x", pady=(0, 12))

        ctk.CTkLabel(
            sec, text=self.t("section_trends"),
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=COLORS["text_bright"],
        ).pack(anchor="w", padx=16, pady=(12, 4))

        self._trend_box = ctk.CTkTextbox(
            sec, height=80, fg_color=COLORS["bg"],
            border_width=1, border_color=COLORS["border"],
            font=ctk.CTkFont(family="Consolas", size=10),
            text_color=COLORS["text_dim"],
            state="disabled", wrap="none",
        )
        self._trend_box.pack(fill="x", padx=16, pady=(0, 12))

    def _refresh_trend_panel(self):
        """Update trend mini-charts with ASCII sparklines."""
        try:
            perf = getattr(self.app, 'perf_optimizer', None)
            if not perf or not hasattr(perf, 'get_trend_data'):
                return

            data = perf.get_trend_data(30)
            if not data:
                return

            # Build ASCII sparklines
            bars = " ▁▂▃▄▅▆▇█"

            def sparkline(values, max_val=None):
                if not values:
                    return ""
                if max_val is None:
                    max_val = max(values) if max(values) > 0 else 1
                return "".join(bars[min(8, int(v / max_val * 8))] for v in values)

            cpus = [d["cpu"] for d in data]
            mems = [d["mem"] for d in data]
            eps_vals = [d["eps"] for d in data]

            cpu_spark = sparkline(cpus, 100)
            mem_spark = sparkline(mems, 100)
            eps_spark = sparkline(eps_vals)

            cpu_now = f"{cpus[-1]:.0f}%" if cpus else "—"
            mem_now = f"{mems[-1]:.0f}%" if mems else "—"
            eps_now = f"{eps_vals[-1]:.1f}" if eps_vals else "—"

            text = (
                f"CPU  {cpu_spark}  {cpu_now}\n"
                f"RAM  {mem_spark}  {mem_now}\n"
                f"E/s  {eps_spark}  {eps_now}"
            )

            if hasattr(self, '_trend_box'):
                self._trend_box.configure(state="normal")
                self._trend_box.delete("1.0", "end")
                self._trend_box.insert("1.0", text)
                self._trend_box.configure(state="disabled")

        except Exception:
            pass

    # ─── Dashboard Refresh ─── #
    def _start_motor_health_poll(self):
        """Cache daemon motor health off the Tk thread (avoid 400ms stalls)."""
        if getattr(self, "_motor_poll_thread_started", False):
            return
        self._motor_poll_thread_started = True
        self._cached_motor_ok = False

        def _loop():
            while True:
                try:
                    if not self.root or not self.root.winfo_exists():
                        return
                except Exception:
                    return
                ok = False
                st = {}
                try:
                    from client_daemon_ipc import get_status
                    st = get_status(timeout=0.8) or {}
                    ok = bool(st.get("motor_ok") or (
                        st.get("daemon") and st.get("remote_commands_running")
                    ))
                except Exception:
                    st = {}
                    ok = False
                if not ok:
                    rc = getattr(self.app, "remote_commands", None)
                    ok = bool(rc is not None and getattr(rc, "_running", False))
                self._cached_motor_ok = ok
                # Full daemon STATUS payload for the protection strip
                # (persistence, network_guard, ransomware_running, rs_quarantine)
                self._cached_daemon_status = st if st.get("ok") else {}
                import time as _t
                _t.sleep(3.0)

        threading.Thread(target=_loop, daemon=True, name="MotorHealthPoll").start()

    def _schedule_dashboard_refresh(self):
        """Dashboard kartlarını config aralığında günceller (varsayılan 10 sn)."""
        # Skip until status widgets exist
        if self._pages_built.get("status"):
            self._refresh_dashboard()
        try:
            self._refresh_resource_badge()
        except Exception:
            pass

        ticks_per_ip = max(1, int(20000 / self._refresh_ms))  # ~20 sn
        if not hasattr(self, '_ip_table_tick'):
            self._ip_table_tick = 0
        self._ip_table_tick += 1
        if (
            self._active_page == "iplist"
            and self._pages_built.get("iplist")
            and self._ip_table_tick >= ticks_per_ip
        ):
            self._ip_table_tick = 0
            self._refresh_ip_table(force_firewall=False)

        ticks_per_intel = max(1, int(60000 / self._refresh_ms))  # ~60 sn
        if not hasattr(self, '_security_tick'):
            self._security_tick = 0
        self._security_tick += 1
        if (
            self._active_page == "threat"
            and self._pages_built.get("threat")
            and self._security_tick >= ticks_per_intel
        ):
            self._security_tick = 0
            self._refresh_security_intel()
            self._refresh_active_sessions()
            if hasattr(self, "_refresh_remote_desktop_status"):
                self._refresh_remote_desktop_status()

        # Account link status from API (~60s)
        ticks_per_account = max(1, int(60000 / self._refresh_ms))
        if not hasattr(self, "_account_link_tick"):
            self._account_link_tick = 0
        self._account_link_tick += 1
        if self._account_link_tick >= ticks_per_account:
            self._account_link_tick = 0
            try:
                self._sync_account_link_from_api(force_ui=False)
            except Exception:
                pass

        try:
            if self.root and self.root.winfo_exists():
                self.root.after(self._refresh_ms, self._schedule_dashboard_refresh)
        except Exception:
            pass

    def _refresh_dashboard(self):
        """Dashboard kartlarının anlık değerlerini güncelle."""
        t0 = time.time()
        try:
            if not hasattr(self, '_dash_cards') or not self._dash_cards:
                return

            sm = self.app.service_manager

            # 1) Aktif servisler
            active_count = len(sm.running_services)
            total_services = len(self.app.PORT_TABLOSU)
            self._update_card("active_services", f"{active_count}/{total_services}",
                              COLORS["green"] if active_count > 0 else COLORS["text_dim"])

            # 2) Oturum saldırıları
            sess = sm.session_stats
            session_count = sess.get("total_credentials", 0)
            self._update_card("session_attacks", str(session_count),
                              COLORS["orange"] if session_count > 0 else COLORS["text_dim"])

            # 3) Toplam saldırılar (API'den — _last_attack_count client.py tarafından güncellenir)
            total = getattr(self.app, '_last_attack_count', None)
            if total is not None:
                self._update_card("total_attacks", str(total),
                                  COLORS["red"] if total > 0 else COLORS["text_dim"])

            # 4) Uptime
            elapsed = int(time.time() - self._start_time)
            self._update_card("uptime", self._format_uptime(elapsed), COLORS["blue"])

            # 5) Son saldırı zamanı — honeypot credential + threat engine birleştir
            last_ts = sess.get("last_attack_ts")
            last_ip = sess.get("last_attacker_ip", "")
            last_svc = sess.get("last_service", "")

            # Threat Engine'den en son saldıranı al
            threat_engine = getattr(self.app, 'threat_engine', None)
            if threat_engine:
                try:
                    latest = threat_engine.get_last_attacker()
                    if latest:
                        te_ts = latest.get("last_seen", 0)
                        if not last_ts or te_ts > last_ts:
                            last_ts = te_ts
                            last_ip = latest.get("ip", "")
                            svcs = latest.get("services", [])
                            last_svc = svcs[0] if svcs else "SCAN"
                except Exception:
                    pass

            if last_ts:
                ago_sec = time.time() - last_ts
                ago = self._format_ago(ago_sec)
                if last_ip:
                    display = f"{last_ip} ({last_svc})"
                else:
                    display = ago
                color = COLORS["red"] if ago_sec < 300 else (
                    COLORS["orange"] if ago_sec < 3600 else COLORS["text_dim"])
                self._update_card("last_attack", display, color,
                                  label=f"{self.t('dash_last_attack')} — {ago}")
            else:
                self._update_card("last_attack", self.t("dash_no_attack"), COLORS["text_dim"])

            # 6) API + motor (dashboard poll) — auth alone is not "online"
            api_ok = getattr(self.app, '_last_api_ok', False)
            motor_ok = bool(getattr(self, "_cached_motor_ok", False))
            if not motor_ok:
                rc = getattr(self.app, "remote_commands", None)
                motor_ok = bool(rc is not None and getattr(rc, "_running", False))
            if not getattr(self, "_motor_poll_started", False):
                self._motor_poll_started = True
                self._start_motor_health_poll()
            if api_ok and motor_ok:
                self._update_card("connection", self.t("dash_connected"), COLORS["green"])
            elif api_ok and not motor_ok:
                try:
                    label = self.t("dash_api_no_motor")
                except Exception:
                    label = "API var · motor yok"
                self._update_card("connection", label, COLORS["orange"])
            else:
                self._update_card("connection", self.t("dash_disconnected"), COLORS["red"])

            # 7) Threat Detection cards — blocked IP count matches IP Lists tab
            threat_engine = getattr(self.app, 'threat_engine', None)
            blocked_count = len(self._tracked_ip_snapshot()["blocked"])
            if threat_engine:
                try:
                    level, level_color = threat_engine.get_threat_level()
                    self._update_card("threat_level", level, level_color)

                    engine_stats = threat_engine.get_stats()
                    events_scored = engine_stats.get("events_scored", 0)
                    uptime_sec = int(time.time() - self._start_time) or 1
                    events_per_hour = int(events_scored / (uptime_sec / 3600)) if uptime_sec > 60 else 0
                    eph_color = COLORS["red"] if events_per_hour > 100 else (
                        COLORS["orange"] if events_per_hour > 20 else COLORS["text_dim"])
                    self._update_card("events_per_hour", str(events_per_hour), eph_color)

                    blocked_color = COLORS["red"] if blocked_count > 5 else (
                        COLORS["orange"] if blocked_count > 0 else COLORS["text_dim"])
                    self._update_card("blocked_ips", str(blocked_count), blocked_color)
                except Exception:
                    if blocked_count:
                        self._update_card(
                            "blocked_ips",
                            str(blocked_count),
                            COLORS["red"] if blocked_count > 5 else COLORS["orange"],
                        )
            else:
                blocked_color = COLORS["red"] if blocked_count > 5 else (
                    COLORS["orange"] if blocked_count > 0 else COLORS["text_dim"])
                self._update_card("blocked_ips", str(blocked_count), blocked_color)

            # 8) Silent Hours status (v4.0 Faz 2)
            sh_guard = getattr(self.app, 'silent_hours_guard', None)
            if sh_guard and hasattr(self, '_silent_hours_label'):
                try:
                    if sh_guard.is_silent_now():
                        self._silent_hours_label.configure(
                            text=self.t("status_silent_hours_active"),
                            text_color=COLORS["orange"],
                        )
                    else:
                        self._silent_hours_label.configure(
                            text=self.t("status_normal_hours"),
                            text_color=COLORS["text_dim"],
                        )
                except Exception:
                    pass

            # 9) Ransomware Shield status (v4.0 Faz 3)
            rs = getattr(self.app, 'ransomware_shield', None)
            if rs:
                try:
                    rs_stats = rs.get_stats() if hasattr(rs, 'get_stats') else {}
                    rs_running = rs_stats.get("running", False)
                    rs_alerts = rs_stats.get("alerts_total", 0)
                    if rs_alerts > 0:
                        self._update_card("ransomware", f"⚠ {rs_alerts}", COLORS["red"])
                    elif rs_running:
                        self._update_card("ransomware", "SAFE", COLORS["green"])
                    else:
                        self._update_card("ransomware", "OFF", COLORS["text_dim"])
                except Exception:
                    pass
            else:
                # Frontend-only GUI: read shield state from daemon STATUS cache
                try:
                    dst = getattr(self, "_cached_daemon_status", None) or {}
                    rq = dst.get("rs_quarantine") or {}
                    rs_alerts = int(rq.get("alerts_total") or 0)
                    rs_running = dst.get("ransomware_running")
                    if rq.get("active"):
                        self._update_card(
                            "ransomware",
                            f"⚠ {int(rq.get('entries') or 0)}", COLORS["red"],
                        )
                    elif rs_alerts > 0:
                        self._update_card("ransomware", f"⚠ {rs_alerts}", COLORS["red"])
                    elif rs_running:
                        self._update_card("ransomware", "SAFE", COLORS["green"])
                    elif rs_running is False and dst:
                        self._update_card("ransomware", "OFF", COLORS["text_dim"])
                except Exception:
                    pass

            # 10) CPU / RAM usage — prefer daemon STATUS resources (frontend-safe)
            try:
                dst = getattr(self, "_cached_daemon_status", None) or {}
                res = dst.get("resources") if isinstance(dst, dict) else None
                cpu = ram = None
                if isinstance(res, dict) and res:
                    cpu = res.get("host_cpu_percent")
                    ram = res.get("host_memory_percent")
                if cpu is None or ram is None:
                    hm = getattr(self.app, "health_monitor", None)
                    if hm and hasattr(hm, "get_snapshot"):
                        snap = hm.get_snapshot() or {}
                        cpu = snap.get("cpu_percent", 0) if cpu is None else cpu
                        ram = snap.get("memory_percent", 0) if ram is None else ram
                if cpu is not None and ram is not None:
                    cpu_f = float(cpu)
                    ram_f = float(ram)
                    cpu_color = COLORS["red"] if cpu_f > 90 else (
                        COLORS["orange"] if cpu_f > 70 else COLORS["text_dim"])
                    self._update_card(
                        "cpu_usage", f"{cpu_f:.0f}% / {ram_f:.0f}%", cpu_color
                    )
            except Exception:
                pass

            # 11) Self-Protection status (v4.0 Faz 3)
            # Kart, koruma şeridi chip'iyle AYNI kaynağı kullanmalı: yerel
            # process_protection nesnesi frontend GUI'de yoktur, bu yüzden
            # daemon STATUS (motor_ok / persistence.self_protection) gerçeği
            # esas alınır — aksi halde chip AKTİF, kart OFF çelişkisi doğar.
            try:
                pp = getattr(self.app, 'process_protection', None)
                dst = getattr(self, "_cached_daemon_status", None) or {}
                pers = dst.get("persistence") or {}
                motor_ok = bool(getattr(self, "_cached_motor_ok", False) or dst.get("motor_ok"))
                prot_on = bool(pp) or bool(pers.get("self_protection")) or motor_ok
                if prot_on:
                    self._update_card("self_protect", "ACTIVE", COLORS["green"])
                else:
                    self._update_card("self_protect", "OFF", COLORS["text_dim"])
            except Exception:
                pass

            # 11b) Koruma Durumu şeridi — daemon STATUS cache'inden
            try:
                self._refresh_protection_strip()
            except Exception:
                pass

            # 12) Trend mini-charts — sadece threat sekmesi açıkken
            if self._active_page == "threat":
                self._refresh_trend_panel()

            # 13) Performance throttle info (v4.0 Faz 4)
            perf = getattr(self.app, 'perf_optimizer', None)
            if perf:
                try:
                    ps = perf.get_stats()
                    mode = ps.get("throttle_mode", "NORMAL")
                    if mode == "CRITICAL":
                        self.append_threat_feed(
                            f"⚠️ PERF: Throttle mode CRITICAL — CPU/RAM high"
                        )
                except Exception:
                    pass

            # Header badge — cache only (IPC poller updates cache off-UI)
            try:
                mode = self.app.get_protection_mode()
            except Exception:
                mode = "full" if active_count > 0 else "inactive"
            self.update_header_status(mode)

            ms = (time.time() - t0) * 1000
            if ms > 80:
                log(f"[PERF] dashboard_refresh {ms:.0f}ms page={self._active_page}")

        except Exception:
            pass

    # _update_tab_badges kaldırıldı — CTkTabview tab isimlerini runtime'da
    # değiştirmek (rename, dict key update vb.) segmented button click
    # callback'lerini bozuyor. Tab isimleri artık sabit.

    def _start_pulse_blink(self):
        """Header pulse dot'u 800ms aralıkla yanıp söndürür (cache only — no IPC)."""
        def _blink():
            try:
                if not self.root or not self.root.winfo_exists():
                    return
                self._pulse_visible = not self._pulse_visible
                if hasattr(self, '_pulse_dot'):
                    try:
                        mode = self.app.get_protection_mode()
                    except Exception:
                        mode = "inactive"
                    any_active = mode != "inactive"
                    if mode == "monitoring":
                        pulse_color = COLORS["blue"]
                    elif any_active:
                        pulse_color = COLORS["green"]
                    else:
                        pulse_color = COLORS["text_dim"]
                    self._pulse_dot.configure(
                        text_color=pulse_color if self._pulse_visible else COLORS["card"]
                    )
                self.root.after(800, _blink)
            except Exception:
                pass
        _blink()

    def _update_card(self, key: str, value: str, color: str, label: str = ""):
        """Bir dashboard kartının değerini (ve opsiyonel alt yazısını) güncelle."""
        card = self._dash_cards.get(key)
        if card and hasattr(card, '_value_lbl'):
            try:
                card._value_lbl.configure(text=value, text_color=color)
                if label and hasattr(card, '_label_lbl'):
                    card._label_lbl.configure(text=label)
            except Exception:
                pass

    def _format_uptime(self, seconds: int) -> str:
        """Saniyeyi insanca okunur süreye çevirir."""
        d = self.t("dash_days")
        h = self.t("dash_hours")
        m = self.t("dash_minutes")
        if seconds < 60:
            return f"<1{m}"
        elif seconds < 3600:
            return f"{seconds // 60}{m}"
        elif seconds < 86400:
            hrs = seconds // 3600
            mins = (seconds % 3600) // 60
            return f"{hrs}{h} {mins}{m}"
        else:
            days = seconds // 86400
            hrs = (seconds % 86400) // 3600
            return f"{days}{d} {hrs}{h}"

    def _format_ago(self, seconds: float) -> str:
        """Saniyeyi '3dk önce' formatına çevirir."""
        s = int(seconds)
        if s < 10:
            return self.t("dash_just_now")
        elif s < 60:
            return self.t("dash_ago").format(val=f"{s}{self.t('dash_seconds')}")
        elif s < 3600:
            return self.t("dash_ago").format(val=f"{s // 60}{self.t('dash_minutes')}")
        elif s < 86400:
            return self.t("dash_ago").format(val=f"{s // 3600}{self.t('dash_hours')}")
        else:
            return self.t("dash_ago").format(val=f"{s // 86400}{self.t('dash_days')}")

    # ─── Toast Notification (v4.0) ─── #
    def show_toast(self, title: str, message: str, severity: str = "info",
                   duration_ms: int = 5000):
        """
        Show a temporary toast notification at the bottom-right of the window.
        Severity: info (blue), warning (orange), high (red), critical (pulsing red).
        """
        self._gui_safe(lambda: self._render_toast(title, message, severity, duration_ms))

    def _render_toast(self, title: str, message: str, severity: str, duration_ms: int):
        """Render toast on the GUI thread."""
        try:
            if not self.root or not self.root.winfo_exists():
                return

            severity_colors = {
                "info":     COLORS["blue"],
                "warning":  COLORS["orange"],
                "high":     COLORS["red"],
                "critical": "#FF0000",
            }
            bg_color = severity_colors.get(severity, COLORS["blue"])
            severity_icons = {
                "info": "ℹ️", "warning": "⚠️", "high": "🚨", "critical": "💀",
            }
            icon = severity_icons.get(severity, "ℹ️")

            toast = ctk.CTkFrame(
                self.root, fg_color=COLORS["card"], corner_radius=12,
                border_width=2, border_color=bg_color,
            )
            toast.place(relx=1.0, rely=1.0, x=-16, y=-16, anchor="se")

            # Title row
            title_lbl = ctk.CTkLabel(
                toast, text=f"{icon}  {title}",
                font=ctk.CTkFont(size=13, weight="bold"),
                text_color=bg_color,
            )
            title_lbl.pack(anchor="w", padx=12, pady=(10, 2))

            # Message
            msg_lbl = ctk.CTkLabel(
                toast, text=message,
                font=ctk.CTkFont(size=11),
                text_color=COLORS["text"],
                wraplength=280,
            )
            msg_lbl.pack(anchor="w", padx=12, pady=(0, 10))

            # Auto-dismiss
            def _dismiss():
                try:
                    toast.destroy()
                except Exception:
                    pass

            self.root.after(duration_ms, _dismiss)

        except Exception as e:
            log(f"Toast render error: {e}")

    # ═══════════════════════════════════════════════════════════════
    #  HONEYPOT SERVİSLERİ
    # ═══════════════════════════════════════════════════════════════
    def _build_services_section(self, parent):
        sec = ctk.CTkFrame(parent, fg_color=COLORS["card"], corner_radius=12)
        sec.pack(fill="x", pady=(0, 8))

        # Başlık
        ctk.CTkLabel(
            sec, text=f"🐝  {self.t('port_tunnel')}",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=COLORS["text_bright"],
        ).pack(anchor="w", padx=16, pady=(12, 8))

        sep = ctk.CTkFrame(sec, height=1, fg_color=COLORS["border"])
        sep.pack(fill="x", padx=16, pady=(0, 8))

        # Servis kartları
        saved_rows, saved_running = self.app.read_status()
        running_names = [str(r[1]).upper() for r in saved_rows] if saved_rows else []

        for (port, service) in self.app.PORT_TABLOSU:
            is_active = str(service).upper() in running_names
            self._build_service_card(sec, str(port), str(service), is_active)

        # İlk açılışta header durumunu cache'ten set et (IPC yok)
        try:
            self.update_header_status(self.app.get_protection_mode())
        except Exception:
            self.update_header_status("full" if running_names else "inactive")

        self._ensure_pulse_blink()

        # Alt padding
        ctk.CTkFrame(sec, height=8, fg_color="transparent").pack()

    def _build_service_card(self, parent, port: str, service: str, initially_active: bool):
        """Tek bir servis kartı oluşturur."""
        svc_upper = service.upper()
        icon = SERVICE_ICONS.get(svc_upper, "⚙️")

        # ── Kart Frame ── #
        card_color = COLORS["card_active"] if initially_active else COLORS["bg"]
        card = ctk.CTkFrame(parent, fg_color=card_color, corner_radius=10,
                            border_width=1, border_color=COLORS["border"])
        card.pack(fill="x", padx=16, pady=3)

        # ── İç container: sol / sağ ayrımı ── #
        inner = ctk.CTkFrame(card, fg_color="transparent")
        inner.pack(fill="x", padx=12, pady=10)

        # ── Sol: İkon + İsim ── #
        left = ctk.CTkFrame(inner, fg_color="transparent")
        left.pack(side="left", fill="y")

        ctk.CTkLabel(
            left, text=icon, font=ctk.CTkFont(size=22),
            text_color=COLORS["text_bright"], width=30, anchor="center",
        ).pack(side="left", padx=(0, 8))

        name_frame = ctk.CTkFrame(left, fg_color="transparent")
        name_frame.pack(side="left")

        ctk.CTkLabel(
            name_frame, text=service,
            font=ctk.CTkFont(size=15, weight="bold"),
            text_color=COLORS["text_bright"],
        ).pack(anchor="w")

        ctk.CTkLabel(
            name_frame, text=f"Port: {port}",
            font=ctk.CTkFont(size=12),
            text_color=COLORS["text_dim"],
        ).pack(anchor="w")

        # ── Sağ: Butonlar + Durum (sağa hizalı) ── #
        right = ctk.CTkFrame(inner, fg_color="transparent")
        right.pack(side="right", fill="y")

        # ── Durum göstergesi ── #
        status_text = self.t("status_running") if initially_active else self.t("status_stopped")
        status_color = COLORS["status_dot_on"] if initially_active else COLORS["status_dot_off"]

        status_frame = ctk.CTkFrame(right, fg_color="transparent")
        status_frame.pack(side="left", padx=(0, 12))

        status_dot = ctk.CTkLabel(
            status_frame, text="●",
            font=ctk.CTkFont(size=14),
            text_color=status_color,
        )
        status_dot.pack(side="left", padx=(0, 4))

        status_lbl = ctk.CTkLabel(
            status_frame, text=status_text,
            font=ctk.CTkFont(size=12),
            text_color=COLORS["text_dim"],
        )
        status_lbl.pack(side="left")

        # ── Buton grubu ── #
        btn_inner = ctk.CTkFrame(right, fg_color="transparent")
        btn_inner.pack(side="left")

        # RDP özel butonu
        rdp_btn = None
        if svc_upper == "RDP":
            rdp_btn = self._build_rdp_move_button(btn_inner)
            rdp_btn.pack(side="left", padx=(0, 6))

        # Başlat / Durdur butonu
        if initially_active:
            btn_text = self.t("btn_row_stop")
            btn_color = COLORS["red"]
            btn_hover = COLORS["red_hover"]
        else:
            btn_text = self.t("btn_row_start")
            btn_color = COLORS["green"]
            btn_hover = COLORS["green_hover"]

        toggle_btn = ctk.CTkButton(
            btn_inner, text=btn_text, width=100, height=36,
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color=btn_color, hover_color=btn_hover,
            corner_radius=8,
        )
        toggle_btn.pack(side="left")

        # ── Referans kaydet ── #
        ctrl = {
            "card": card, "button": toggle_btn, "status_lbl": status_lbl,
            "status_dot": status_dot, "rdp_button": rdp_btn,
        }
        self.row_controls[(port, svc_upper)] = ctrl

        # client.py uyumluluğu
        self.app.row_controls[(port, svc_upper)] = {
            "frame": card, "button": toggle_btn, "status": status_lbl,
        }
        if rdp_btn:
            self.app.row_controls[(port, svc_upper)]["rdp_button"] = rdp_btn

        # ── Toggle komutu ── #
        def toggle(p=port, s=service, b=toggle_btn, c=card, sl=status_lbl, sd=status_dot):
            self._toggle_service(p, s, b, c, sl, sd)

        toggle_btn.configure(command=toggle)

    def _build_rdp_move_button(self, parent) -> ctk.CTkButton:
        """RDP Taşı butonu oluşturur."""
        try:
            is_protected, _ = self.app.rdp_manager.get_rdp_protection_status()
            target = 3389 if is_protected else RDP_SECURE_PORT
            color = COLORS["orange"] if is_protected else COLORS["blue"]
            hover = COLORS["orange_hover"] if is_protected else COLORS["blue_hover"]
        except Exception:
            target = RDP_SECURE_PORT
            color = COLORS["blue"]
            hover = COLORS["blue_hover"]

        btn = ctk.CTkButton(
            parent, text=f"RDP Taşı: {target}", width=120, height=36,
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color=color, hover_color=hover, corner_radius=8,
            command=self.app.toggle_rdp_protection,
        )
        return btn

    # ─── Servis Toggle ─── #
    def _toggle_service(self, port, service, btn, card, status_lbl, status_dot):
        """Tek bir servisi başlat/durdur — off-thread (Tk freeze yok)."""
        try:
            from client_gui_lock import require_gui_unlock
            if not require_gui_unlock(self.app, reason="mutate"):
                return
        except Exception as e:
            log(f"[GUI] PIN service gate: {e}")
            return

        svc_upper = str(service).upper()
        is_rdp = svc_upper == "RDP"
        try:
            cur_text = btn.cget("text").lower()
        except Exception:
            return
        want_start = cur_text == self.t("btn_row_start").lower()

        try:
            btn.configure(state="disabled")
        except Exception:
            pass

        if is_rdp:
            self.app.service_manager.reconciliation_paused = True
            log("RDP işlemi için uzlaştırma döngüsü duraklatıldı.")

        def _work():
            ok = False
            try:
                if want_start:
                    ok = bool(self.app.start_single_row(port, service, manual_action=True))
                else:
                    ok = bool(self.app.stop_single_row(port, service, manual_action=True))
            except Exception as e:
                log(f"[GUI] service toggle error: {e}")
                ok = False
            finally:
                if is_rdp:
                    self.app.service_manager.reconciliation_paused = False
                    log("RDP işlemi tamamlandı, uzlaştırma döngüsü devam ettiriliyor.")
                    try:
                        threading.Thread(
                            target=self.app.report_service_status_once, daemon=True
                        ).start()
                    except Exception:
                        pass

            def _ui():
                try:
                    btn.configure(state="normal")
                except Exception:
                    pass
                if ok and not is_rdp:
                    if want_start:
                        self._set_card_active(btn, card, status_lbl, status_dot)
                    else:
                        self._set_card_inactive(btn, card, status_lbl, status_dot)

            self._gui_safe(_ui)

        threading.Thread(target=_work, daemon=True, name=f"SvcToggle-{svc_upper}").start()

    # ─── Kart Durumu Güncelleyiciler ─── #
    def _set_card_active(self, btn, card, status_lbl, status_dot):
        btn.configure(text=self.t("btn_row_stop"), fg_color=COLORS["red"], hover_color=COLORS["red_hover"])
        card.configure(fg_color=COLORS["card_active"])
        status_lbl.configure(text=self.t("status_running"))
        status_dot.configure(text_color=COLORS["status_dot_on"])

    def _set_card_inactive(self, btn, card, status_lbl, status_dot):
        btn.configure(text=self.t("btn_row_start"), fg_color=COLORS["green"], hover_color=COLORS["green_hover"])
        card.configure(fg_color=COLORS["bg"])
        status_lbl.configure(text=self.t("status_stopped"))
        status_dot.configure(text_color=COLORS["status_dot_off"])

    # ═══════════════════════════════════════════════════════════════
    #  UPDATE ROW UI — client.py._update_row_ui tarafından çağrılır
    # ═══════════════════════════════════════════════════════════════
    def update_row_ui(self, listen_port: str, service_name: str, active: bool):
        """Bir servis satırının UI durumunu güncelle (thread-safe)."""
        def apply():
            key = (str(listen_port), str(service_name).upper())
            ctrl = self.row_controls.get(key)
            if not ctrl:
                return
            btn = ctrl["button"]
            card = ctrl["card"]
            sl = ctrl["status_lbl"]
            sd = ctrl["status_dot"]
            if active:
                self._set_card_active(btn, card, sl, sd)
            else:
                self._set_card_inactive(btn, card, sl, sd)

            # Header badge (threat monitoring may stay active without bait)
            try:
                self.update_header_status(self.app.get_protection_mode())
            except Exception:
                self.update_header_status(
                    len(self.app.service_manager.running_services) > 0
                )

        self._gui_safe(apply)

    # ═══════════════════════════════════════════════════════════════
    #  RDP BUTON GÜNCELLEME
    # ═══════════════════════════════════════════════════════════════
    def update_rdp_button(self):
        """RDP Taşı butonunun metnini/rengini güncel duruma göre güncelle."""
        try:
            rdp_ctrl = self.row_controls.get(("3389", "RDP"))
            if not rdp_ctrl or not rdp_ctrl.get("rdp_button"):
                return
            rdp_btn = rdp_ctrl["rdp_button"]
            is_protected, _ = self.app.rdp_manager.get_rdp_protection_status()
            target = 3389 if is_protected else RDP_SECURE_PORT
            if is_protected:
                rdp_btn.configure(text=f"RDP Taşı: {target}",
                                  fg_color=COLORS["orange"], hover_color=COLORS["orange_hover"])
            else:
                rdp_btn.configure(text=f"RDP Taşı: {target}",
                                  fg_color=COLORS["blue"], hover_color=COLORS["blue_hover"])
        except Exception as e:
            log(f"RDP buton güncelleme hatası: {e}")

    def _close_popup(self):
        """Mevcut popup'ı güvenli şekilde kapat."""
        popup = getattr(self, "_active_popup", None)
        if popup is not None:
            try:
                popup.destroy()
            except Exception:
                pass
            self._active_popup = None
        # Global click binding'i temizle
        bid = getattr(self, "_popup_click_bid", None)
        if bid is not None:
            try:
                self.root.unbind("<Button-1>", bid)
            except Exception:
                pass
            self._popup_click_bid = None

    def _show_popup_menu(self, anchor_widget, menu_type: str):
        """CTkToplevel popup menü — dark mode uyumlu."""
        if menu_type == "settings":
            try:
                from client_gui_lock import require_gui_unlock
                if not require_gui_unlock(self.app, reason="settings"):
                    return
            except Exception as e:
                log(f"[GUI] PIN settings gate: {e}")
                return

        # Zaten açıksa kapat (toggle davranışı)
        if getattr(self, "_active_popup", None) is not None:
            self._close_popup()
            return

        popup = ctk.CTkToplevel(self.root)
        popup.overrideredirect(True)
        popup.configure(fg_color=COLORS["card"])
        popup.attributes("-topmost", True)
        self._active_popup = popup

        # Pozisyon hesapla
        x = anchor_widget.winfo_rootx()
        y = anchor_widget.winfo_rooty() + anchor_widget.winfo_height() + 2
        popup.geometry(f"+{x}+{y}")

        def _run_and_close(action):
            """Menü öğesi tıklanınca: önce kapat, sonra action çalıştır."""
            def _handler():
                self._close_popup()
                action()
            return _handler

        items = []
        if menu_type == "settings":
            from client_utils import is_account_linked
            linked = is_account_linked()
            # Structured rows: ("header"|"item"|"sep", label_key_or_text, cmd|None)
            items = [("header", self.t("menu_section_account"), None)]
            if linked:
                items += [
                    ("status", self.t("btn_account_linked"), None),
                    ("item", self.t("menu_open_my_servers"), _run_and_close(
                        lambda: webbrowser.open(f"{self._account_base_url()}/servers"))),
                    ("item", self.t("menu_unmark_account_linked"), _run_and_close(
                        self._unmark_account_linked)),
                ]
            else:
                items += [
                    ("item", self.t("btn_link_account"), _run_and_close(
                        lambda: self._open_link_account(self.app.state.get("token", "")))),
                    ("item", self.t("menu_mark_account_linked"), _run_and_close(
                        self._mark_account_linked)),
                ]
            items += [
                ("item", self.t("menu_copy_token"), _run_and_close(
                    lambda: self._copy_token_with_hint(self.app.state.get("token", "")))),
                ("sep", None, None),
                ("header", self.t("menu_section_security"), None),
                ("item", self.t("menu_pin_set"), _run_and_close(self._pin_set_or_change)),
            ]
            try:
                from client_gui_lock import GuiLock
                if GuiLock.instance().has_pin():
                    items.append(
                        ("item", self.t("menu_pin_clear"), _run_and_close(self._pin_clear))
                    )
            except Exception:
                pass
            items += [
                ("sep", None, None),
                ("header", self.t("menu_section_language"), None),
                ("item", self.t("menu_lang_tr"), _run_and_close(lambda: self._set_lang("tr"))),
                ("item", self.t("menu_lang_en"), _run_and_close(lambda: self._set_lang("en"))),
                ("sep", None, None),
                ("header", self.t("menu_section_maintenance"), None),
                ("item", self.t("menu_cleanup_local"), _run_and_close(lambda: self._run_cleanup("local"))),
                ("item", self.t("menu_cleanup_firewall"), _run_and_close(lambda: self._run_cleanup("firewall"))),
                ("item", self.t("menu_cleanup_server"), _run_and_close(lambda: self._run_cleanup("server"))),
                ("item", self.t("menu_cleanup_all"), _run_and_close(lambda: self._run_cleanup("all"))),
            ]
        elif menu_type == "help":
            items = [
                ("item", self.t("menu_logs"), _run_and_close(self._open_logs)),
                ("item", self.t("menu_github"), _run_and_close(self._open_github)),
                ("sep", None, None),
                ("item", self.t("menu_check_updates"), _run_and_close(self.app.check_updates_and_prompt)),
            ]

        muted = COLORS.get("text_muted") or COLORS.get("text_secondary") or "#8B93A7"
        for kind, label, cmd in items:
            if kind == "sep":
                ctk.CTkFrame(popup, height=1, fg_color=COLORS["border"]).pack(
                    fill="x", padx=10, pady=6
                )
            elif kind == "header":
                ctk.CTkLabel(
                    popup,
                    text=str(label or "").upper(),
                    anchor="w",
                    font=ctk.CTkFont(size=10, weight="bold"),
                    text_color=muted,
                ).pack(fill="x", padx=12, pady=(6, 2))
            elif kind == "status":
                ctk.CTkLabel(
                    popup,
                    text=f"✓  {label}",
                    anchor="w",
                    font=ctk.CTkFont(size=12),
                    text_color=COLORS.get("success") or "#3DDC97",
                ).pack(fill="x", padx=12, pady=(2, 4))
            else:
                btn = ctk.CTkButton(
                    popup, text=str(label or ""), anchor="w",
                    font=ctk.CTkFont(size=12), height=30, width=260,
                    fg_color="transparent", hover_color=COLORS["accent"],
                    text_color=COLORS["text"], corner_radius=4,
                    command=cmd,
                )
                btn.pack(fill="x", padx=6, pady=1)

        # Dışına tıklanınca kapat (root üzerinde global click)
        def _on_root_click(event):
            try:
                # Tıklanan widget popup içinde mi kontrol et
                w = event.widget
                while w is not None:
                    if w == popup:
                        return  # popup içine tıklandı, kapatma
                    w = getattr(w, "master", None)
            except Exception:
                pass
            self._close_popup()

        # Bir sonraki event loop'ta bind et (mevcut click'i yutmasın)
        self.root.after(50, lambda: self._bind_popup_click(_on_root_click))

    def _bind_popup_click(self, handler):
        """Popup dışı click handler'ı güvenli şekilde bağla."""
        if getattr(self, "_active_popup", None) is None:
            return  # Popup zaten kapandı
        try:
            self._popup_click_bid = self.root.bind("<Button-1>", handler, add="+")
        except Exception:
            pass

    def _rebuild_gui(self):
        """Tüm widget'ları yıkıp GUI'yi yeniden oluşturur (dil değişimi vb.)."""
        try:
            # Mevcut dashboard refresh / pulse timer'ları widget yıkılınca
            # winfo_exists() == False olacak ve doğal olarak duracak.
            # Tüm root children'ları yık
            for child in list(self.root.winfo_children()):
                try:
                    child.destroy()
                except Exception:
                    pass
            # Dahili referansları temizle
            self._dash_cards = {}
            self.row_controls = {}
            self.app.row_controls = {}
            self._active_popup = None
            self._pages = {}
            self._nav_buttons = {}
            self._content_area = None
            # Yeniden oluştur (mevcut modda — görünürse gui, gizliyse minimized)
            mode = "minimized" if self.app._tray_mode.is_set() else "gui"
            self.build(self.root, mode)
            log("[GUI] GUI rebuilt successfully (hot-reload)")
        except Exception as e:
            log(f"[GUI] Rebuild error: {e}")

    def _pin_set_or_change(self):
        """PIN oluştur veya değiştir."""
        from client_gui_lock import (
            GuiLock, prompt_pin_dialog, require_gui_unlock, dashboard_pin_hint,
        )
        lock = GuiLock.instance()
        hint = dashboard_pin_hint(self.t)
        if lock.has_pin():
            if not require_gui_unlock(self.app, reason="settings"):
                return
            old = prompt_pin_dialog(
                self.root, self.t("pin_title"), self.t("pin_unlock_prompt"),
                confirm=False, hint=hint,
            )
            if not old:
                return
            ok, err = lock.verify_pin(old, unlock_on_success=False)
            if not ok:
                messagebox.showerror(self.t("pin_title"), self.t("pin_wrong"))
                return
            new = prompt_pin_dialog(
                self.root, self.t("pin_set_title"), self.t("pin_set_prompt"), confirm=True,
            )
            if not new:
                return
            ok, err = lock.set_pin(new)
            if ok:
                messagebox.showinfo(self.t("pin_title"), self.t("pin_saved"))
                self._refresh_settings_pin_ui()
            else:
                messagebox.showerror(self.t("pin_title"), f"{self.t('pin_wrong')} ({err})")
        else:
            new = prompt_pin_dialog(
                self.root, self.t("pin_set_title"), self.t("pin_set_prompt"),
                confirm=True, hint=hint,
            )
            if not new:
                return
            ok, err = lock.set_pin(new)
            if ok:
                messagebox.showinfo(self.t("pin_title"), self.t("pin_saved"))
                self._refresh_settings_pin_ui()
            else:
                messagebox.showerror(self.t("pin_title"), str(err))

    def _pin_clear(self):
        """PIN kaldır (mevcut PIN gerekli)."""
        from client_gui_lock import GuiLock, prompt_pin_dialog, dashboard_pin_hint
        lock = GuiLock.instance()
        if not lock.has_pin():
            messagebox.showinfo(self.t("pin_title"), self.t("pin_not_set"))
            self._refresh_settings_pin_ui()
            return
        pin = prompt_pin_dialog(
            self.root, self.t("pin_title"), self.t("pin_unlock_prompt"),
            confirm=False, hint=dashboard_pin_hint(self.t),
        )
        if not pin:
            return
        ok, err = lock.clear_pin(pin)
        if ok:
            messagebox.showinfo(self.t("pin_title"), self.t("pin_cleared"))
            self._refresh_settings_pin_ui()
        else:
            messagebox.showerror(self.t("pin_title"), self.t("pin_wrong"))

    def _set_lang(self, code: str):
        try:
            update_language_config(code, True)
            log(f"[CONFIG] Language changed to: {code}")
        except Exception as e:
            log(f"[CONFIG] Language change error: {e}")
        # Dili anında değiştir ve GUI'yi yeniden oluştur (restart gerekmez)
        self.app.lang = code
        self._rebuild_gui()

    def _run_cleanup(self, scope: str, refresh_ip_table: bool = False):
        """Ayarlar → Bakım/Temizlik: local | firewall | server | all"""
        cm = getattr(self.app, "cleanup_manager", None)
        if not cm:
            messagebox.showerror(self.t("cleanup_title"), self.t("cleanup_unavailable"))
            return

        confirm_key = {
            "local": "cleanup_confirm_local",
            "firewall": "cleanup_confirm_firewall",
            "server": "cleanup_confirm_server",
            "all": "cleanup_confirm_all",
        }.get(scope, "cleanup_confirm_all")

        if not messagebox.askyesno(self.t("cleanup_title"), self.t(confirm_key)):
            return

        def _worker():
            try:
                if scope == "local":
                    result = cm.clear_local()
                    msg = self.t("cleanup_done_local").format(
                        ips=result.get("ip_pool_cleared", 0),
                    )
                elif scope == "firewall":
                    result = None
                    # Prefer SYSTEM daemon (elevated) — GUI netsh delete needs admin
                    try:
                        from client_daemon_ipc import clear_firewall as ipc_clear
                        from client_daemon_ipc import is_motor_healthy
                        if is_motor_healthy(timeout=2.0):
                            log("[CLEANUP] CLEAR_FIREWALL via daemon IPC…")
                            result = ipc_clear(timeout=180.0)
                            log(f"[CLEANUP] daemon IPC result: {result}")
                    except Exception as e:
                        log(f"[CLEANUP] daemon IPC clear failed: {e}")
                        result = None

                    if not result or not result.get("ok"):
                        # Local fallback only when this process is elevated
                        try:
                            from client_utils import is_admin
                            admin = bool(is_admin())
                        except Exception:
                            admin = False
                        if admin and cm:
                            result = cm.clear_firewall(sync_dashboard=True)
                        else:
                            err = (result or {}).get("error") or "daemon_unavailable"
                            msg = self.t("cleanup_firewall_need_daemon").format(err=err)
                            self._gui_safe(
                                lambda m=msg: messagebox.showerror(self.t("cleanup_title"), m)
                            )
                            return

                    if result.get("error") and not result.get("ok"):
                        msg = self.t("cleanup_firewall_fail").format(
                            err=result.get("error"),
                            rules=result.get("rules_removed", 0),
                            left=result.get("rules_left", "?"),
                        )
                        self._gui_safe(
                            lambda m=msg: messagebox.showerror(self.t("cleanup_title"), m)
                        )
                        return

                    msg = self.t("cleanup_done_firewall").format(
                        rules=result.get("rules_removed", 0),
                        synced="✓" if result.get("api_synced") else "—",
                        server="✓" if result.get("server_cleared") else "—",
                    )
                elif scope == "server":
                    result = cm.clear_server()
                    if result.get("ok"):
                        msg = self.t("cleanup_done_server")
                    else:
                        msg = self.t("cleanup_server_fail").format(
                            err=result.get("error") or "unknown",
                        )
                else:
                    # Full cleanup: firewall via daemon first, then local+server
                    fw = None
                    try:
                        from client_daemon_ipc import clear_firewall as ipc_clear
                        from client_daemon_ipc import is_motor_healthy
                        if is_motor_healthy(timeout=2.0):
                            fw = ipc_clear(timeout=180.0)
                    except Exception:
                        fw = None
                    if not fw or not fw.get("ok"):
                        fw = cm.clear_firewall(sync_dashboard=True)
                    local = cm.clear_local()
                    srv = cm.clear_server(
                        scopes=["attacks", "blocks", "alerts", "threat_summary", "all"]
                    )
                    result = {"local": local, "firewall": fw, "server": srv}
                    srv_ok = (result.get("server") or {}).get("ok")
                    msg = self.t("cleanup_done_all").format(
                        ips=(result.get("local") or {}).get("ip_pool_cleared", 0),
                        rules=(result.get("firewall") or {}).get("rules_removed", 0),
                        server="✓" if srv_ok else "—",
                    )
                def _done():
                    messagebox.showinfo(self.t("cleanup_title"), msg)
                    if refresh_ip_table or scope in ("firewall", "all", "local"):
                        try:
                            self._ip_table_tab = "blocked" if scope == "firewall" else getattr(
                                self, "_ip_table_tab", "activity"
                            )
                            self._update_ip_tab_styles()
                            self._refresh_ip_table(force_firewall=True)
                        except Exception:
                            pass
                        try:
                            self._refresh_dashboard()
                        except Exception:
                            pass
                self._gui_safe(_done)
            except Exception as e:
                log(f"[CLEANUP] GUI cleanup error: {e}")
                self._gui_safe(
                    lambda: messagebox.showerror(
                        self.t("cleanup_title"),
                        self.t("cleanup_error").format(error=e),
                    )
                )

        threading.Thread(target=_worker, daemon=True, name="CleanupWorker").start()

    def _open_logs(self):
        try:
            from client_log_retention import daily_log_path
            current_log = daily_log_path(LOG_FILE)
            if os.name == "nt":
                os.startfile(current_log)
            else:
                webbrowser.open(f"file://{current_log}")
        except Exception as e:
            log(f"open_logs error: {e}")
            messagebox.showerror(self.t("error"), self.t("log_file_error").format(error=e))

    def _open_github(self):
        try:
            webbrowser.open(f"https://github.com/{GITHUB_OWNER}/{GITHUB_REPO}")
        except Exception as e:
            log(f"open_github error: {e}")

    # ─── Window İkon ─── #
    def _set_window_icon(self, root):
        try:
            icon_path = get_resource_path("certs/honeypot.ico")
            if os.path.exists(icon_path):
                root.iconbitmap(icon_path)
                try:
                    from PIL import Image, ImageTk
                    img = Image.open(icon_path)
                    photo = ImageTk.PhotoImage(img)
                    root.iconphoto(True, photo)
                except Exception:
                    pass
        except Exception as e:
            log(f"Icon setup error: {e}")

    # ═══════════════════════════════════════════════════════════════
    #  CONSENT DİALOG (modern)
    # ═══════════════════════════════════════════════════════════════
    def show_consent_dialog(self) -> dict:
        """Modern onay dialogu gösterir. Kabul edilmişse skip eder."""
        cons = self.app.read_consent()
        if cons.get("accepted"):
            self.app.state["consent"] = cons
            return cons

        dialog = ctk.CTkToplevel(self.root)
        dialog.title(self.t("consent_title"))
        dialog.geometry("520x380")
        dialog.configure(fg_color=COLORS["bg"])
        dialog.transient(self.root)
        dialog.grab_set()

        # İçerik
        ctk.CTkLabel(
            dialog, text=self.t("consent_msg").replace("\\n", "\n"),
            font=ctk.CTkFont(size=13), text_color=COLORS["text"],
            justify="left", wraplength=480,
        ).pack(padx=20, pady=(20, 12))

        var_rdp = ctk.BooleanVar(value=True)
        var_auto = ctk.BooleanVar(value=False)

        ctk.CTkCheckBox(
            dialog, text=self.t("consent_rdp"), variable=var_rdp,
            fg_color=COLORS["green"], hover_color=COLORS["green_hover"],
            text_color=COLORS["text"],
        ).pack(anchor="w", padx=24, pady=4)

        ctk.CTkCheckBox(
            dialog, text=self.t("consent_auto"), variable=var_auto,
            fg_color=COLORS["green"], hover_color=COLORS["green_hover"],
            text_color=COLORS["text"],
        ).pack(anchor="w", padx=24, pady=4)

        accepted = {"val": False}

        def do_accept():
            accepted["val"] = True
            self.app.write_consent(True, var_rdp.get(), var_auto.get())
            self.app.state["consent"] = self.app.read_consent()
            dialog.destroy()

        def do_cancel():
            self.app.write_consent(False, var_rdp.get(), var_auto.get())
            self.app.state["consent"] = self.app.read_consent()
            dialog.destroy()

        btn_frame = ctk.CTkFrame(dialog, fg_color="transparent")
        btn_frame.pack(pady=16)

        ctk.CTkButton(
            btn_frame, text=self.t("consent_accept"), width=140, height=38,
            fg_color=COLORS["green"], hover_color=COLORS["green_hover"],
            font=ctk.CTkFont(size=13, weight="bold"), corner_radius=8,
            command=do_accept,
        ).pack(side="left", padx=8)

        ctk.CTkButton(
            btn_frame, text=self.t("consent_cancel"), width=120, height=38,
            fg_color=COLORS["accent"], hover_color=COLORS["red"],
            font=ctk.CTkFont(size=13), corner_radius=8,
            command=do_cancel,
        ).pack(side="left", padx=8)

        dialog.wait_window()
        return self.app.state.get("consent", cons)
