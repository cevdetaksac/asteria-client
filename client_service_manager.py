#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Asteria Client - Service Manager

Tüm honeypot servislerinin yaşam döngüsünü yönetir:
    - Dashboard config ile senkronizasyon (start/stop reconciliation)
    - Credential yakalama → queue → batch API reporting
    - Watchdog: çökmüş servisleri otomatik yeniden başlatma
    - RDP özel yönetimi (port migration ile koordinasyon)

Thread yapısı (3 daemon thread):
    _batch_reporter_loop  — Queue'dan credential'ları topla, API'ye batch gönder
    _sync_loop            — Dashboard'dan istenen durumları al, reconcile et
    _watchdog_loop        — Servis sağlığını kontrol et, auto-restart

Kullanım:
    from client_service_manager import ServiceManager
    from client_api import ClientAPI

    api = ClientAPI(token="...", target_ip="...")
    mgr = ServiceManager(api_client=api)
    mgr.start()
    ...
    mgr.shutdown()
"""

import queue
import threading
import time
from typing import Callable, Dict, Optional

from client_constants import (
    HONEYPOT_SERVICES,
    CREDENTIAL_BATCH_SIZE, CREDENTIAL_BATCH_INTERVAL,
    SERVICE_SYNC_INTERVAL, SERVICE_SYNC_CHECK,
    SERVICE_WATCHDOG_INTERVAL,
    HONEYPOT_AUTO_RESTART_MAX, HONEYPOT_RESTART_BACKOFF,
)
from client_helpers import log
from client_honeypots import (
    BaseHoneypot,
    FTPHoneypot,
    SSHHoneypot,
    MySQLHoneypot,
    MSSQLHoneypot,
    RDPHoneypot,
    HTTPHoneypot,
    SMBHoneypot,
)


# ===================== SERVICE FACTORY ===================== #

_HONEYPOT_CLASSES: Dict[str, type] = {
    "FTP":   FTPHoneypot,
    "SSH":   SSHHoneypot,
    "MYSQL": MySQLHoneypot,
    "MSSQL": MSSQLHoneypot,
    "RDP":   RDPHoneypot,
    "HTTP":  HTTPHoneypot,
    "SMB":   SMBHoneypot,
}


def _create_honeypot(service_name: str, port: int,
                     on_credential: Callable) -> BaseHoneypot:
    """Factory: servis adına göre doğru honeypot sınıfını oluşturur."""
    cls = _HONEYPOT_CLASSES.get(service_name.upper())
    if cls is None:
        raise ValueError(f"Bilinmeyen honeypot servisi: {service_name}")
    return cls(port=port, on_credential=on_credential)


# ===================== SERVICE MANAGER ===================== #

class ServiceManager:
    """Tüm honeypot servislerinin merkezi yöneticisi.

    Sorumluluklar:
        1. Honeypot instance oluşturma / başlatma / durdurma
        2. Credential callback → queue → batch API reporting
        3. Dashboard reconciliation (istenen durum vs gerçek durum)
        4. Watchdog: çökmüş servisleri auto-restart (exponential backoff)
    """

    def __init__(self, api_client, rdp_manager=None, token_getter=None, threat_engine=None):
        """
        Args:
            api_client: ClientAPI instance — report_attack_batch, get_service_statuses,
                        update_service_statuses, report_service_action metodlarını sağlar
            rdp_manager: RDPManager instance (opsiyonel) — RDP port migration koordinasyonu
            token_getter: callable — güncel token döndüren fonksiyon
            threat_engine: ThreatEngine instance — honeypot credential'larını threat skorlamasına besler
        """
        self._api = api_client
        self._rdp_manager = rdp_manager
        self._token_getter = token_getter or (lambda: "")
        self._threat_engine = threat_engine

        # Honeypot instances: {"SSH": SSHHoneypot(...), "FTP": FTPHoneypot(...), ...}
        self._honeypots: Dict[str, BaseHoneypot] = {}
        self._lock = threading.Lock()

        # Attack queue — honeypot callback'leri buraya yazar, batch thread okur
        self._attack_queue: queue.Queue = queue.Queue(maxsize=10000)

        # Auto-restart tracking
        self._restart_counts: Dict[str, int] = {}
        self._restart_timestamps: Dict[str, float] = {}

        # Reconciliation pause flag (RDP transition sırasında)
        self.reconciliation_paused = False

        # Session-level statistics (unique_ips capped for months-long uptime)
        self.session_stats = {
            "total_credentials": 0,
            "per_service": {},        # {"SSH": 3, "FTP": 1, ...}
            "last_attack_ts": None,   # timestamp of last credential captured
            "last_attacker_ip": None,
            "last_service": None,
            "unique_ips": set(),
            "unique_ips_overflow": 0,  # count of IPs dropped after cap
        }
        self._stats_lock = threading.Lock()
        self._unique_ips_max = 5000

        # Shutdown signal
        self._stop_evt = threading.Event()

        # Daemon threads
        self._threads: list[threading.Thread] = []

    # ==================== PUBLIC API ==================== #

    def start(self):
        """3 daemon thread'i başlat — non-blocking."""
        if any(t.is_alive() for t in self._threads):
            log("[ServiceManager] Zaten çalışıyor — start atlandı")
            return
        if self._stop_evt.is_set():
            self._stop_evt.clear()
        self._threads.clear()

        threads_spec = [
            ("SvcMgr-BatchReporter", self._batch_reporter_loop),
            ("SvcMgr-Sync", self._sync_loop),
            ("SvcMgr-Watchdog", self._watchdog_loop),
        ]
        for name, target in threads_spec:
            t = threading.Thread(target=target, daemon=True, name=name)
            t.start()
            self._threads.append(t)
        log("[ServiceManager] Başlatıldı (3 thread)")

    def shutdown(self):
        """Tüm servisleri durdur, queue'yu flush et, thread'leri sonlandır."""
        log("[ServiceManager] Kapatılıyor...")
        self._stop_evt.set()

        # Tüm honeypotları durdur
        with self._lock:
            for name, hp in list(self._honeypots.items()):
                try:
                    hp.stop()
                    log(f"[ServiceManager] {name} durduruldu")
                except Exception as exc:
                    log(f"[ServiceManager] {name} durdurma hatası: {exc}")
            self._honeypots.clear()

        # Kalan credential'ları flush et
        self._flush_queue()

        log("[ServiceManager] Kapatıldı")

    def start_service(self, service_name: str, port: int) -> bool:
        """Bir honeypot servisini başlat.

        Returns:
            True  — başarıyla başlatıldı
            False — hata (port çakışması, bilinmeyen servis, vb.)
        """
        service_name = service_name.upper()

        with self._lock:
            # Zaten çalışıyorsa skip
            existing = self._honeypots.get(service_name)
            if existing and existing.running:
                log(f"[ServiceManager] {service_name} zaten çalışıyor (port {existing.port})")
                return True

            # Eski instance varsa temizle
            if existing:
                try:
                    existing.stop()
                except Exception:
                    pass

        try:
            hp = _create_honeypot(service_name, port, self._on_credential)
            hp.start()

            # Kısa süre bekle — bind hatası olup olmadığını kontrol et
            time.sleep(0.5)
            if hp.error:
                log(f"[ServiceManager] {service_name} başlatma hatası: {hp.error}")
                return False

            with self._lock:
                self._honeypots[service_name] = hp
                self._restart_counts[service_name] = 0  # Reset restart counter

            log(f"[ServiceManager] {service_name} başlatıldı (port {port})")
            self._report_action(service_name, port, "started")
            return True

        except Exception as exc:
            log(f"[ServiceManager] {service_name} oluşturma hatası: {exc}")
            return False

    def stop_service(self, service_name: str) -> bool:
        """Bir honeypot servisini durdur."""
        service_name = service_name.upper()

        with self._lock:
            hp = self._honeypots.pop(service_name, None)

        if hp is None:
            log(f"[ServiceManager] {service_name} zaten durmuş")
            return True

        port = hp.port
        try:
            hp.stop()
        except Exception as exc:
            log(f"[ServiceManager] {service_name} durdurma hatası: {exc}")

        self._report_action(service_name, port, "stopped")
        return True

    def restart_service(self, service_name: str, port: int) -> bool:
        """Servisi dur-kalk ile yeniden başlat."""
        self.stop_service(service_name)
        time.sleep(1)
        return self.start_service(service_name, port)

    def get_status(self, service_name: str) -> str:
        """Tek bir servisin durumunu döndür: started | stopped | error."""
        with self._lock:
            hp = self._honeypots.get(service_name.upper())
        if hp is None:
            return "stopped"
        return hp.get_status()

    def get_all_statuses(self) -> Dict[str, dict]:
        """Tüm servislerin durumlarını döndür.

        Returns:
            {"SSH": {"status": "started", "port": 22}, ...}
        """
        result = {}
        with self._lock:
            for name, hp in self._honeypots.items():
                result[name] = {
                    "status": hp.get_status(),
                    "port": hp.port,
                    "error": hp.error,
                }
        # Çalışmayan servisleri de ekle
        for name in HONEYPOT_SERVICES:
            if name not in result:
                result[name] = {
                    "status": "stopped",
                    "port": HONEYPOT_SERVICES[name]["port"],
                    "error": None,
                }
        return result

    def get_deception_health(self) -> list:
        """Bounded DEC health for health/report (no credentials/banners)."""
        rows = []
        with self._lock:
            items = list(self._honeypots.items())
        for _name, hp in items:
            try:
                if hasattr(hp, "get_health"):
                    rows.append(hp.get_health())
            except Exception:
                continue
        return rows[:16]

    @property
    def running_services(self) -> list[str]:
        """Çalışan servis adlarının listesi."""
        with self._lock:
            return [n for n, hp in self._honeypots.items() if hp.running]

    # ==================== CREDENTIAL CALLBACK ==================== #

    def _on_credential(self, *, attacker_ip: str, username: str,
                       password: str, service: str, port: int):
        """Her honeypot bu callback'i çağırır — queue'ya yazar + ThreatEngine'e besler."""
        entry = {
            "attacker_ip": attacker_ip,
            "username": username,
            "password": password,
            "service": service,
            "port": port,
            "timestamp": time.time(),
        }
        try:
            self._attack_queue.put_nowait(entry)
        except queue.Full:
            log(f"[ServiceManager] Attack queue dolu — credential atılıyor ({service})")

        # Update session stats
        with self._stats_lock:
            s = self.session_stats
            s["total_credentials"] += 1
            svc_upper = str(service).upper()
            s["per_service"][svc_upper] = s["per_service"].get(svc_upper, 0) + 1
            s["last_attack_ts"] = time.time()
            s["last_attacker_ip"] = attacker_ip
            s["last_service"] = svc_upper
            ips = s["unique_ips"]
            if attacker_ip not in ips:
                if len(ips) >= self._unique_ips_max:
                    # Drop arbitrary half to keep set bounded under scan floods
                    drop = list(ips)[: len(ips) // 2]
                    for old in drop:
                        ips.discard(old)
                    s["unique_ips_overflow"] = int(s.get("unique_ips_overflow") or 0) + len(drop)
                ips.add(attacker_ip)

        # Feed ThreatEngine — honeypot credential'ları threat skorlamasına girer
        if self._threat_engine:
            try:
                self._threat_engine.process_event({
                    "event_type": "honeypot_credential",
                    "source_ip": attacker_ip,
                    "username": username,
                    "password": password,
                    "service": str(service).upper(),
                    "port": port,
                    "timestamp": time.time(),
                })
            except Exception as e:
                log(f"[ServiceManager] ThreatEngine feed error: {e}")

    def trim_unique_ips(self, max_ips: int = 5000) -> int:
        """MemoryGuard hook — keep unique_ips set bounded."""
        with self._stats_lock:
            ips = self.session_stats.get("unique_ips") or set()
            if len(ips) <= max_ips:
                return 0
            drop = list(ips)[: len(ips) - max_ips]
            for old in drop:
                ips.discard(old)
            self.session_stats["unique_ips_overflow"] = int(
                self.session_stats.get("unique_ips_overflow") or 0
            ) + len(drop)
            return len(drop)

    # ==================== BATCH REPORTER THREAD ==================== #

    def _batch_reporter_loop(self):
        """Queue'dan credential'ları topla, batch olarak API'ye gönder."""
        log("[BatchReporter] Başlatıldı")
        while not self._stop_evt.is_set():
            try:
                batch = self._drain_queue(max_items=CREDENTIAL_BATCH_SIZE)
                if batch:
                    self._send_batch(batch)
            except Exception as exc:
                log(f"[BatchReporter] Hata: {exc}")

            # CREDENTIAL_BATCH_INTERVAL kadar bekle (stop event ile kesilebilir)
            self._stop_evt.wait(timeout=CREDENTIAL_BATCH_INTERVAL)

    def _drain_queue(self, max_items: int) -> list[dict]:
        """Queue'dan max_items kadar credential çek."""
        items = []
        for _ in range(max_items):
            try:
                item = self._attack_queue.get_nowait()
                items.append(item)
            except queue.Empty:
                break
        return items

    def _send_batch(self, batch: list[dict]):
        """Credential'ları tek tek API'ye gönder (POST /api/attack)."""
        try:
            token = self._token_getter()
            if not token:
                log(f"[BatchReporter] Token yok, {len(batch)} credential gönderilemedi")
                return

            sent = 0
            for entry in batch:
                try:
                    ok = self._api.report_attack(
                        token,
                        attacker_ip=entry["attacker_ip"],
                        target_ip="",
                        username=entry["username"],
                        password=entry["password"],
                        service=entry["service"],
                        port=entry["port"],
                    )
                    if ok:
                        sent += 1
                except Exception:
                    pass
            if sent:
                log(f"[BatchReporter] {sent}/{len(batch)} credential gönderildi")
            else:
                log(f"[BatchReporter] Hiçbir credential gönderilemedi ({len(batch)} kayıt)")
        except Exception as exc:
            log(f"[BatchReporter] API hatası: {exc}")

    def _flush_queue(self):
        """Kalan tüm credential'ları gönder (shutdown sırasında)."""
        remaining = self._drain_queue(max_items=1000)
        if remaining:
            log(f"[ServiceManager] Flush: {len(remaining)} kalan credential gönderiliyor")
            self._send_batch(remaining)

    # ==================== SYNC THREAD ==================== #

    def _sync_loop(self):
        """Dashboard'dan istenen durumları al, yerel durumla karşılaştır."""
        log("[SyncLoop] Başlatıldı")
        last_sync = 0

        while not self._stop_evt.is_set():
            now = time.time()

            if now - last_sync >= SERVICE_SYNC_INTERVAL:
                if not self.reconciliation_paused:
                    self._do_reconcile()
                    self._report_statuses()
                last_sync = now

            self._stop_evt.wait(timeout=SERVICE_SYNC_CHECK)

    @staticmethod
    def _normalize_desired_services(payload) -> dict:
        """Extract service status map from tunnel-status API payload.

        Backend may return either:
          {"services": {"RDP": {...}, ...}, "pending_tunnel_commands": [...], ...}
          or a flat map mixed with non-service keys (lists, server_time, etc.).
        """
        if not isinstance(payload, dict):
            return {}
        nested = payload.get("services")
        if isinstance(nested, dict):
            return {
                k: v for k, v in nested.items()
                if isinstance(v, dict)
            }
        skip = {"services", "pending_tunnel_commands", "server_time"}
        out = {}
        for key, value in payload.items():
            if key in skip or not isinstance(value, dict):
                continue
            if "status" in value or "desired" in value:
                out[key] = value
        return out

    def _do_reconcile(self):
        """Dashboard desired state vs local actual state → start/stop."""
        try:
            token = self._token_getter()
            if not token:
                return
            desired = self._api.get_service_statuses(token)
            if not desired:
                return  # API hatası veya boş yanıt

            services = self._normalize_desired_services(desired)
            if not services:
                return

            for service_name, info in services.items():
                service_name = service_name.upper()
                # Prefer explicit desired state; fall back to reported status
                want = (info.get("desired") or info.get("status") or "").lower()
                want_running = want == "started"
                port = (
                    info.get("new_port")
                    or info.get("listen_port")
                    or info.get("port")
                    or HONEYPOT_SERVICES.get(service_name, {}).get("port", 0)
                )

                current_status = self.get_status(service_name)
                is_running = current_status == "started"

                if want_running and not is_running:
                    log(f"[Reconcile] {service_name} başlatılıyor (dashboard isteği)")
                    self.start_service(service_name, port)

                elif not want_running and is_running:
                    log(f"[Reconcile] {service_name} durduruluyor (dashboard isteği)")
                    self.stop_service(service_name)

        except Exception as exc:
            log(f"[Reconcile] Hata: {exc}")

    def _report_statuses(self):
        """Güncel durumları API'ye bildir."""
        try:
            statuses = self.get_all_statuses()
            status_list = []
            for name, info in statuses.items():
                port = int(info.get("port") or 0)
                status_list.append({
                    "service": name,
                    "listen_port": port,
                    "port": port,  # legacy alias — server accepts both
                    "status": info["status"],
                })
            token = self._token_getter()
            if not token:
                return
            self._api.update_service_statuses(token, status_list)
        except Exception as exc:
            log(f"[StatusReport] Hata: {exc}")

    # ==================== WATCHDOG THREAD ==================== #

    def _watchdog_loop(self):
        """Servis sağlığını kontrol et, çökmüş servisleri yeniden başlat."""
        log("[Watchdog] Başlatıldı")
        while not self._stop_evt.is_set():
            self._stop_evt.wait(timeout=SERVICE_WATCHDOG_INTERVAL)
            if self._stop_evt.is_set():
                break

            with self._lock:
                services_snapshot = list(self._honeypots.items())

            for name, hp in services_snapshot:
                # Thread alive ama running=False → çökmüş olabilir
                if not hp.is_alive() or hp.error:
                    self._handle_crashed_service(name, hp.port)

    def _handle_crashed_service(self, service_name: str, port: int):
        """Çökmüş bir servisi exponential backoff ile yeniden başlat."""
        count = self._restart_counts.get(service_name, 0)

        if count >= HONEYPOT_AUTO_RESTART_MAX:
            log(f"[Watchdog] {service_name} max restart sınırına ulaştı ({HONEYPOT_AUTO_RESTART_MAX})")
            # Honeypot'u temizle — artık otomatik başlatılmayacak
            with self._lock:
                self._honeypots.pop(service_name, None)
            self._report_action(service_name, port, "stopped")
            return

        # Backoff süresi hesapla
        backoff_idx = min(count, len(HONEYPOT_RESTART_BACKOFF) - 1)
        backoff_secs = HONEYPOT_RESTART_BACKOFF[backoff_idx]

        # Son restart'tan yeterli süre geçti mi?
        last_restart = self._restart_timestamps.get(service_name, 0)
        elapsed = time.time() - last_restart
        if elapsed < backoff_secs:
            return  # Henüz backoff süresi dolmadı

        log(f"[Watchdog] {service_name} yeniden başlatılıyor (deneme {count + 1}/{HONEYPOT_AUTO_RESTART_MAX}, backoff={backoff_secs}s)")

        self._restart_counts[service_name] = count + 1
        self._restart_timestamps[service_name] = time.time()

        # Eski instance'ı temizle
        with self._lock:
            old = self._honeypots.pop(service_name, None)
            if old:
                try:
                    old.stop()
                except Exception:
                    pass

        # Yeni instance başlat
        self.start_service(service_name, port)

    # ==================== HELPERS ==================== #

    def _report_action(self, service_name: str, port: int, action: str):
        """Servis durum değişikliğini API'ye bildir."""
        try:
            token = self._token_getter()
            if not token:
                return
            self._api.report_service_action(token, service_name, action, port)
        except Exception as exc:
            log(f"[ServiceManager] Action report hatası ({service_name}): {exc}")
