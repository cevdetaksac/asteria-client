#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import threading
import tkinter as tk
from tkinter import ttk
from typing import Callable, Optional, Tuple
import logging

# Import required modules
from client_constants import RDP_SECURE_PORT, RDP_TRANSITION_TIMEOUT, RDP_REGISTRY_KEY_PATH
from client_helpers import log
from client_utils import ServiceController, SystemUtils, is_admin

# Global logger reference - will be set by main application
LOGGER: Optional[logging.Logger] = None

def set_logger(logger: logging.Logger) -> None:
    """Set global logger for RDP module"""
    global LOGGER
    LOGGER = logger

class RDPManager:
    """RDP koruma sistemi yöneticisi"""
    
    def __init__(self, main_app=None):
        """RDP Manager başlatıcısı"""
        self.main_app = main_app
        self.rdp_transition_complete = threading.Event()
        
    def get_rdp_protection_status(self) -> Tuple[bool, int]:
        """
        RDP koruma durumunu kontrol et
        Returns: (is_protected, current_port)
        """
        try:
            current_port = ServiceController.get_rdp_port()
            if current_port is None:
                current_port = 3389
            is_protected = current_port == RDP_SECURE_PORT
            # Sadece durum değişikliklerinde logla
            if not hasattr(self, '_last_rdp_status') or self._last_rdp_status != (is_protected, current_port):
                log(f"🔍 RDP koruma durumu: port={current_port}, korumalı={'Evet' if is_protected else 'Hayır'}")
                self._last_rdp_status = (is_protected, current_port)
            return is_protected, current_port
        except Exception as e:
            log(f"❌ RDP durum kontrolü hatası: {e}")
            return False, 3389
    
    def is_rdp_protection_active(self) -> bool:
        """RDP korumasının aktif olup olmadığını kontrol et"""
        is_protected, _ = self.get_rdp_protection_status()
        return is_protected
    
    def check_initial_rdp_state(self):
        """Uygulama başlatıldığında RDP durumunu kontrol et - SADECE DURUM BİLGİSİ"""
        try:
            current_rdp_port = ServiceController.get_rdp_port()
            log(f"🔍 Açılış RDP durumu: Mevcut port={current_rdp_port}, Güvenli port={RDP_SECURE_PORT}")
            
            if current_rdp_port == RDP_SECURE_PORT:
                log(f"📋 RDP güvenli portta ({RDP_SECURE_PORT}) - API kontrolü bekleniyor")
                log(f"ℹ️  RDP tünel durumu API'den gelecek komutlar ile belirlenecek")
            else:
                log(f"📋 RDP normal portta ({current_rdp_port}) - API kontrolü bekleniyor")
                
            # NOT: Artık otomatik tünel başlatmıyoruz, API reconcile loop işleyecek
            log(f"� RDP durumu API reconcile döngüsü tarafından yönetilecek")
                
        except Exception as e:
            log(f"❌ RDP durumu kontrol hatası: {e}")
    
    def start_rdp_transition(self, transition_mode: str = "secure") -> bool:
        """RDP port geçişini başlat"""
        try:
            log(f"🔄 RDP geçişi başlatılıyor: {transition_mode} modu")
            
            if transition_mode == "secure":
                # Güvenli porta taşı
                log("📝 Registry güncelleniyor...")
                if not self._set_rdp_port_registry(RDP_SECURE_PORT):
                    log("❌ Registry güncellenemedi!")
                    return False
                log("✅ Registry başarıyla güncellendi")
                
                log("🔥 Firewall kuralları ayarlanıyor...")
                self._ensure_rdp_firewall_both()
                log("✅ Firewall kuralları tamamlandı")
                
                log("🔄 Terminal Services yeniden başlatılıyor...")
                if not ServiceController.restart("TermService", log):
                    log("❌ Terminal Services yeniden başlatılamadı!")
                    return False
                log("✅ Terminal Services başarıyla yeniden başlatıldı")
                
                log("⏱️ Port değişikliği doğrulanıyor...")
                time.sleep(3)
                
                final_port = ServiceController.get_rdp_port()
                if final_port == RDP_SECURE_PORT:
                    log(f"✅ RDP başarıyla güvenli porta taşındı: {RDP_SECURE_PORT}")
                    return True
                else:
                    log(f"❌ RDP port değişikliği başarısız: mevcut={final_port}, hedef={RDP_SECURE_PORT}")
                    return False
                    
            elif transition_mode == "rollback":
                # Normal porta geri dön
                log("📝 Registry normal porta döndürülüyor...")
                if not self._set_rdp_port_registry(3389):
                    log("❌ Registry güncellenemedi!")
                    return False
                log("✅ Registry başarıyla güncellendi")
                
                log("🔄 Terminal Services yeniden başlatılıyor...")
                if not ServiceController.restart("TermService", log):
                    log("❌ Terminal Services yeniden başlatılamadı!")
                    return False
                log("✅ Terminal Services başarıyla yeniden başlatıldı")
                
                log("⏱️ Port değişikliği doğrulanıyor...")
                time.sleep(3)
                
                final_port = ServiceController.get_rdp_port()
                if final_port == 3389:
                    log("✅ RDP başarıyla normal porta geri döndürüldü: 3389")
                    return True
                else:
                    log(f"❌ RDP rollback başarısız: mevcut={final_port}, hedef=3389")
                    return False
            else:
                log(f"❌ Bilinmeyen geçiş modu: {transition_mode}")
                return False
            
        except Exception as e:
            log(f"❌ RDP geçiş hatası: {e}")
            return False
    
    def _get_current_rdp_port(self) -> int:
        """Registry'den mevcut RDP portunu oku"""
        try:
            from client_winproc import run_ps

            registry_path = (
                r"HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
            )
            rc, out, err = run_ps(
                f"Get-ItemProperty -Path '{registry_path}' -Name PortNumber "
                f"| Select-Object -ExpandProperty PortNumber",
                timeout=15,
            )
            if rc == 0 and (out or "").strip():
                port = int(out.strip().splitlines()[-1].strip())
                log(f"🔍 Registry'den RDP port okundu: {port}")
                return port
            log(f"⚠️ Registry'den port okunamadı (RC:{rc}), varsayılan 3389 kullanılıyor")
            if err:
                log(f"⚠️ PowerShell hatası: {err}")
            return 3389
        except Exception as e:
            log(f"❌ RDP port okuma hatası: {e}")
            return 3389

    def _set_rdp_port_registry(self, new_port: int) -> bool:
        """RDP portunu registry'de güncelle - PowerShell kullanarak"""
        try:
            if not is_admin():
                log(f"❌ Admin yetkisi gerekli - RDP port değişikliği yapılamaz")
                return False

            from client_winproc import run_ps

            registry_path = (
                r"HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
            )
            log(f"🔧 PowerShell Registry komutu çalıştırılıyor...")
            log(f"📝 Hedef yol: {registry_path}")
            log(f"🎯 Yeni port değeri: {new_port}")

            rc, out, err = run_ps(
                f"Set-ItemProperty -Path '{registry_path}' -Name PortNumber "
                f"-Value {int(new_port)} -Type DWord",
                timeout=20,
            )
            if rc == 0:
                log(f"✅ Registry başarıyla güncellendi: Port {new_port}")
                vrc, vout, _ = run_ps(
                    f"Get-ItemProperty -Path '{registry_path}' -Name PortNumber "
                    f"| Select-Object -ExpandProperty PortNumber",
                    timeout=15,
                )
                if vrc == 0 and (vout or "").strip():
                    actual_port = vout.strip().splitlines()[-1].strip()
                    log(f"🔍 Registry doğrulaması: Okunan port = {actual_port}")
                    if actual_port == str(new_port):
                        log(f"✅ Registry değeri doğrulandı: {new_port}")
                        return True
                    log(f"❌ Registry değeri eşleşmiyor: beklenen={new_port}, okunan={actual_port}")
                    return False
                log(f"❌ Registry doğrulaması başarısız")
                if err:
                    log(f"⚠️ Set stderr: {err}")
                return False
            log(f"❌ Registry güncelleme başarısız RC:{rc} err={(err or '')[:200]}")
            return False
        except Exception as e:
            log(f"❌ RDP registry güncelleme hatası: {e}")
            return False
    
    def _ensure_rdp_firewall_both(self):
        """RDP için firewall kurallarını ayarla"""
        try:
            # Hem 3389 hem de güvenli port için kurallar oluştur
            for port in [3389, RDP_SECURE_PORT]:
                SystemUtils.run_cmd(
                    f'netsh advfirewall firewall add rule name="RDP-In-{port}" protocol=TCP dir=in localport={port} action=allow',
                    suppress_rc_log=True,
                    log_func=log
                )
        except Exception as e:
            log(f"Firewall kural hatası: {e}")
    
    def show_rdp_rollback_popup(self):
        """RDP rollback popup'ını göster"""
        if hasattr(self.main_app, 't'):
            # Popup manager kullan
            popup_manager = RDPPopupManager(self.main_app, self.main_app.t)
            
            def on_rollback_confirm():
                return self.start_rdp_transition("rollback")
            
            popup_manager.show_rdp_popup("rollback", on_rollback_confirm)
        else:
            # Direct rollback yap
            log("🔄 RDP rollback başlatılıyor...")
            self.start_rdp_transition("rollback")

class RDPPopupManager:
    """RDP popup pencere yöneticisi"""
    
    def __init__(self, main_app=None, translation_func=None):
        """Popup Manager başlatıcısı"""
        self.main_app = main_app
        self.t = translation_func if translation_func else lambda x: x
        
    def show_rdp_popup(self, mode: str, on_confirm_callback: Callable):
        """RDP işlem popup'ını göster"""
        try:
            log(f"🎯 RDP popup gösteriliyor: {mode} modu")
            
            # Modern popup penceresi - tamamen beyaz arkaplan, daha yüksek
            popup = tk.Toplevel()
            popup.title(self.t("rdp_title"))
            popup.geometry("600x450")  # Yüksekliği 380'den 450'ye artırdık
            popup.configure(bg="white")
            popup.resizable(False, False)
            
            # Pencereyi merkeze al ve modal yap
            popup.transient()
            popup.grab_set()
            
            # Ana container - beyaz arkaplan ile
            main_container = tk.Frame(popup, bg="white")
            main_container.pack(fill=tk.BOTH, expand=True, padx=40, pady=30)
            
            # Header - İkon ve başlık için özel container
            header_frame = tk.Frame(main_container, bg="white")
            header_frame.pack(fill=tk.X, pady=(0, 25))
            
            # İkon için özel container - tam ortalama
            icon_container = tk.Frame(header_frame, bg="white")
            icon_container.pack(fill=tk.X)
            
            # Büyük güvenlik ikonu - kesinlikle ortalanmış
            icon_label = tk.Label(
                icon_container,
                text="🛡️",
                font=("Segoe UI", 50),  # Biraz daha büyük
                justify=tk.CENTER,
                bg="white",
                fg="black"
            )
            icon_label.pack(expand=True)  # expand=True ile tam ortalama
            
            # Başlık için ayrı container
            title_container = tk.Frame(header_frame, bg="white") 
            title_container.pack(fill=tk.X, pady=(10, 0))
            
            title_label = tk.Label(
                title_container,
                text="RDP Güvenlik İşlemi",
                font=("Segoe UI", 20, "bold"),
                foreground="#2c3e50",
                justify=tk.CENTER,
                bg="white"
            )
            title_label.pack(expand=True)
            
            # İçerik alanı - beyaz arkaplan, daha fazla alan
            content_frame = tk.Frame(main_container, bg="white")
            content_frame.pack(fill=tk.X, pady=(0, 25))
            
            # Basit mesaj
            if mode == "secure":
                simple_message = "RDP portun güvenli konuma (53389) taşınacak.\n5 saniye sonra geçiş başlayacak."
            elif mode == "rollback":
                simple_message = "RDP portun eski konuma (3389) geri alınacak.\n5 saniye sonra geçiş başlayacak."
            else:
                simple_message = "RDP port değişikliği yapılacak.\n5 saniye sonra geçiş başlayacak."
            
            message_label = tk.Label(
                content_frame,
                text=simple_message,
                wraplength=500,
                justify=tk.CENTER,
                font=("Segoe UI", 12),
                foreground="#34495e",
                bg="white"
            )
            message_label.pack(anchor=tk.CENTER, pady=(0, 20))
            
            # Zamanlayıcı alanı - beyaz arkaplan
            timer_frame = tk.Frame(content_frame, bg="white")
            timer_frame.pack(fill=tk.X)
            
            # Birleştirilmiş zamanlayıcı - ortalanmış
            unified_timer_label = tk.Label(
                timer_frame,
                text="",
                font=("Segoe UI", 13, "bold"),
                foreground="#e74c3c",
                anchor=tk.CENTER,
                bg="white"
            )
            unified_timer_label.pack(anchor=tk.CENTER)
            
            # Buton alanı - daha fazla padding ile
            button_frame = tk.Frame(main_container, bg="white")
            button_frame.pack(fill=tk.X, pady=(15, 0))  # Üstten biraz boşluk
            
            # Buton container - tam ortalanmış
            button_container = tk.Frame(button_frame, bg="white")
            button_container.pack(expand=True)  # expand=True ile tam ortalama
            
            # Buton click handler'ları
            def on_confirm():
                popup.destroy()
                on_confirm_callback()
            
            def on_cancel():
                popup.destroy()
            
            # Modern butonlar - daha büyük ve belirgin
            confirm_btn = tk.Button(
                button_container,
                text="⏰ Onaylıyorum (10s bekleyin)",
                command=on_confirm,
                state="disabled",
                width=25,
                height=2,  # Yükseklik eklendi
                font=("Segoe UI", 11),
                bg="#6c757d",
                fg="white",
                relief=tk.FLAT,
                pady=5
            )
            confirm_btn.pack(side=tk.LEFT, padx=(0, 15))
            
            cancel_btn = tk.Button(
                button_container,
                text="❌ İptal Et",
                command=on_cancel,
                width=15,
                height=2,  # Yükseklik eklendi
                font=("Segoe UI", 11),
                bg="#dc3545",
                fg="white",
                relief=tk.FLAT,
                pady=5
            )
            cancel_btn.pack(side=tk.LEFT)
            
            # Timer kontrolü için flag
            timer_active = [True]  # List kullanarak mutable referans
            
            # Güvenli widget config fonksiyonu
            def safe_widget_config(widget, **kwargs):
                """Widget'ı güvenli şekilde configure et"""
                try:
                    if widget.winfo_exists():
                        widget.config(**kwargs)
                except:
                    pass  # Widget yok edilmişse silent fail
            
            # Birleştirilmiş zamanlayıcı fonksiyonu - güvenli
            def unified_countdown_timer(auto_seconds=120, button_seconds=10):
                """Tek fonksiyonda her iki zamanlayıcıyı yönet - güvenli"""
                if not timer_active[0]:
                    return  # Timer durdurulmuş
                
                try:
                    if auto_seconds > 0:
                        # Ana zamanlayıcı metni
                        auto_minutes = auto_seconds // 60
                        auto_secs = auto_seconds % 60
                        
                        if button_seconds > 0:
                            # Buton henüz aktif değil
                            safe_widget_config(
                                unified_timer_label,
                                text=f"⏰ Otomatik işlem: {auto_minutes:02d}:{auto_secs:02d} | Onay butonu: {button_seconds}s kaldı",
                                foreground="#e74c3c"
                            )
                            safe_widget_config(confirm_btn, text=f"⏰ Onaylıyorum ({button_seconds}s bekleyin)")
                            popup.after(1000, lambda: unified_countdown_timer(auto_seconds - 1, button_seconds - 1))
                        else:
                            # Buton aktif
                            safe_widget_config(
                                unified_timer_label,
                                text=f"⏰ Otomatik işlem: {auto_minutes:02d}:{auto_secs:02d} | ✅ Onaylayabilirsiniz",
                                foreground="#27ae60"
                            )
                            safe_widget_config(confirm_btn, 
                                             text="✅ Onaylıyorum ve Devam Et", 
                                             state="normal",
                                             bg="#28a745")
                            popup.after(1000, lambda: unified_countdown_timer(auto_seconds - 1, 0))
                    else:
                        # Süre doldu, otomatik onay
                        if timer_active[0]:  # Hala aktifse
                            popup.destroy()
                            on_confirm_callback()
                except Exception as e:
                    log(f"❌ Timer hatası: {e}")
                    # Hata durumunda timer'ı durdur
                    timer_active[0] = False
            
            # Popup kapanma fonksiyonlarını güvenli hale getir
            original_on_cancel = on_cancel
            def safe_on_cancel():
                timer_active[0] = False
                original_on_cancel()
            
            original_on_confirm = on_confirm  
            def safe_on_confirm():
                timer_active[0] = False
                original_on_confirm()
            
            # Buton komutlarını güncelle
            confirm_btn.config(command=safe_on_confirm)
            cancel_btn.config(command=safe_on_cancel)
            
            # RDP geçiş süreci (5 saniye sonra başlar)
            def start_rdp_process():
                """5 saniye sonra RDP geçişini başlat"""
                log("🔄 5 saniye bilgilendirme süresi doldu, RDP geçişi başlatılıyor...")
                
                def run_transition():
                    """Arkaplan thread'de RDP geçişi yap"""
                    try:
                        if self.main_app and hasattr(self.main_app, 'rdp_manager'):
                            success = self.main_app.rdp_manager.start_rdp_transition(mode)
                            if success:
                                log("✅ RDP arkaplan geçişi başarılı - kullanıcı onayı bekleniyor")
                            else:
                                log("❌ RDP arkaplan geçişi başarısız - kullanıcıya bildirilecek")
                                # Hata durumunu popup'ta göster
                                popup.after(0, lambda: self._show_error_in_popup(popup, 
                                    "❌ RDP Geçiş Hatası", 
                                    "RDP port değişikliği başarısız oldu.\nAdmin yetkisi gerekli veya sistem hatası.\n\nPopup 5 saniye sonra kapanacak."))
                        else:
                            log("❌ RDP manager bulunamadı!")
                            popup.after(0, lambda: self._show_error_in_popup(popup,
                                "❌ Sistem Hatası", 
                                "RDP yönetim sistemi bulunamadı.\n\nPopup 5 saniye sonra kapanacak."))
                    except Exception as e:
                        log(f"❌ RDP arkaplan geçiş hatası: {e}")
                        popup.after(0, lambda: self._show_error_in_popup(popup,
                            "❌ Beklenmeyen Hata", 
                            f"RDP geçişi sırasında hata oluştu:\n{str(e)}\n\nPopup 5 saniye sonra kapanacak."))
                
                # RDP geçişini arkaplan thread'de başlat
                transition_thread = threading.Thread(target=run_transition, daemon=True)
                transition_thread.start()
            
            # 5 saniye sonra RDP geçişini başlat
            popup.after(5000, start_rdp_process)
            
            # Birleştirilmiş zamanlayıcıyı başlat
            unified_countdown_timer(120, 10)  # 120s otomatik + 10s buton bekleme
            
            # Pencereyi merkeze al
            popup.update_idletasks()
            width = popup.winfo_width()
            height = popup.winfo_height()
            x = (popup.winfo_screenwidth() // 2) - (width // 2)
            y = (popup.winfo_screenheight() // 2) - (height // 2)
            popup.geometry(f"{width}x{height}+{x}+{y}")
            
            log("✅ RDP popup başarıyla gösterildi")
            
        except Exception as e:
            log(f"❌ RDP popup hatası: {e}")
    
    def _show_error_in_popup(self, popup_window, error_title, error_message):
        """Popup içinde hata mesajı göster"""
        try:
            # Popup'taki tüm widget'ları temizle
            for widget in popup_window.winfo_children():
                widget.destroy()
            
            # Popup'u beyaz yap
            popup_window.configure(bg="white")
            
            # Hata container - beyaz arkaplan
            error_frame = tk.Frame(popup_window, bg="white")
            error_frame.pack(fill=tk.BOTH, expand=True, padx=30, pady=30)
            
            # Hata ikonu ve başlık
            title_frame = tk.Frame(error_frame, bg="white")
            title_frame.pack(fill=tk.X, pady=(0, 20))
            
            error_title_label = tk.Label(
                title_frame,
                text=error_title,
                font=("Segoe UI", 16, "bold"),
                foreground="#dc3545",
                anchor=tk.CENTER,
                bg="white"
            )
            error_title_label.pack(anchor=tk.CENTER)
            
            # Hata mesajı
            error_msg_label = tk.Label(
                error_frame,
                text=error_message,
                wraplength=500,
                justify=tk.CENTER,
                font=("Segoe UI", 11),
                foreground="#6c757d",
                bg="white"
            )
            error_msg_label.pack(anchor=tk.CENTER, pady=(0, 30))
            
            # Kapat butonu
            close_btn = tk.Button(
                error_frame,
                text="❌ Kapat",
                command=popup_window.destroy,
                width=20,
                font=("Segoe UI", 10),
                bg="#dc3545",
                fg="white",
                relief=tk.FLAT,
                pady=8
            )
            close_btn.pack(anchor=tk.CENTER)
            
            # 5 saniye sonra otomatik kapat
            popup_window.after(5000, popup_window.destroy)
            
        except Exception as e:
            log(f"❌ Hata popup gösterim hatası: {e}")
            # Son çare - popup'ı kapat
            popup_window.destroy()
    
    def show_rdp_rollback_popup(self):
        """RDP rollback popup'ını göster"""
        def on_rollback_confirm():
            # Main app'deki RDP manager'dan rollback yap
            if self.main_app and hasattr(self.main_app, 'rdp_manager'):
                return self.main_app.rdp_manager.start_rdp_transition("rollback")
            return False
        
        self.show_rdp_popup("rollback", on_rollback_confirm)