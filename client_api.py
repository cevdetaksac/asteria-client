# -*- coding: utf-8 -*-
"""
Asteria Client - API Management Module

Bu modül, Cloud Honeypot sunucusu ile olan tüm API iletişimini yönetir.
İstemci kaydı, IP güncellemeleri, heartbeat gönderimi, servis durumu raporlama,
saldırı bildirim (credential capture) ve saldırı sayısı sorgulama işlemlerini
merkezileştirir.

Sınıflar:
    - AsteriaAPIClient: API ile etkileşim kurmak için ana sınıf.

Fonksiyonlar:
    - api_request_with_token: Token ile API isteği wrapper.
    - report_service_action_api: Servis eylemlerini raporlar.
"""

# Import constants for timeout values
try:
    from client_constants import API_REQUEST_TIMEOUT
except ImportError:
    API_REQUEST_TIMEOUT = 8

import json
import requests
import time
from typing import Dict, Optional, Any, Union
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from client_security_utils import (
    auth_headers,
    redact_sensitive,
    resolve_tls_verify,
    use_legacy_token_query,
)

class AsteriaAPIClient:
    """Asteria API bağlantı yönetimi sınıfı"""
    
    def __init__(self, base_url: str, log_func=None, legacy_base_url: str = ""):
        self.base_url = base_url.rstrip('/')
        self.primary_base_url = self.base_url
        try:
            from client_constants import API_URL_LEGACY
            default_legacy = API_URL_LEGACY
        except Exception:
            default_legacy = "https://honeypot.yesnext.com.tr/api"
        self.legacy_base_url = (legacy_base_url or default_legacy).rstrip("/")
        self._using_legacy = False
        self.session = self._create_session()
        self.log = log_func if log_func else print
        self._auth_token: Optional[str] = None
        # Progress heartbeat + download/command threads share this client — lock
        # the session so concurrent api_request cannot wedge requests.Session.
        import threading
        self._request_lock = threading.RLock()

    def _create_session(self) -> requests.Session:
        """HTTP session oluştur"""
        session = requests.Session()
        
        # Retry stratejisi
        retry_strategy = Retry(
            total=3,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "POST", "OPTIONS"],
            backoff_factor=1
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # Default headers
        try:
            from client_constants import VERSION as _VER
        except Exception:
            _VER = "1.0"
        session.headers.update({
            'User-Agent': f'Asteria-Client/{_VER}',
            'Content-Type': 'application/json'
        })
        
        return session

    def _activate_legacy_failover(self, reason: str) -> bool:
        """One-shot session failover to legacy host (contract rebrand-asteria)."""
        if self._using_legacy:
            return False
        legacy = (self.legacy_base_url or "").rstrip("/")
        if not legacy or legacy == self.base_url:
            return False
        self.base_url = legacy
        self._using_legacy = True
        try:
            self.log(f"[API] Primary unreachable ({reason}) — failover to legacy host")
        except Exception:
            pass
        return True

    def set_auth_token(self, token: Optional[str]) -> None:
        """Set default Bearer token for subsequent requests."""
        self._auth_token = token
        if token:
            self.session.headers.update(auth_headers(token))
        elif "Authorization" in self.session.headers:
            del self.session.headers["Authorization"]

    def _prepare_request(
        self,
        params: Optional[Dict],
        data: Optional[Dict],
        token: Optional[str] = None,
    ) -> tuple[Optional[Dict], Optional[Dict], Dict[str, str]]:
        """Merge Bearer auth header; optional legacy ?token= only if configured."""
        tok = token or self._auth_token
        req_params = dict(params) if params else None
        req_data = dict(data) if data else None
        headers: Dict[str, str] = {}
        if tok:
            headers.update(auth_headers(tok))
            # Prefer Authorization only — query token leaks into access logs
            if use_legacy_token_query():
                if req_params is None:
                    req_params = {}
                req_params.setdefault("token", tok)
            elif req_params and "token" in req_params:
                # Never ship token in query when legacy mode is off
                req_params = {k: v for k, v in req_params.items() if k != "token"}
                if not req_params:
                    req_params = None
        return req_params, req_data, headers

    def api_request(self, method: str, endpoint: str, data: Optional[Dict] = None,
                   params: Optional[Dict] = None, timeout: int = API_REQUEST_TIMEOUT,
                   verbose_logging: bool = False, token: Optional[str] = None) -> Optional[Dict]:
        """API isteği gönder (primary → legacy failover on transport/5xx failure)."""
        lock = getattr(self, "_request_lock", None)
        if lock is None:
            return self._api_request_unlocked(
                method, endpoint, data=data, params=params, timeout=timeout,
                verbose_logging=verbose_logging, token=token,
            )
        with lock:
            return self._api_request_unlocked(
                method, endpoint, data=data, params=params, timeout=timeout,
                verbose_logging=verbose_logging, token=token,
            )

    def _api_request_unlocked(
        self,
        method: str,
        endpoint: str,
        data: Optional[Dict] = None,
        params: Optional[Dict] = None,
        timeout: int = API_REQUEST_TIMEOUT,
        verbose_logging: bool = False,
        token: Optional[str] = None,
    ) -> Optional[Dict]:
        """API request body (caller holds ``_request_lock`` when present)."""
        try:
            from client_constants import VERBOSE_LOGGING
            ep = (endpoint or "").lstrip("/")
            # High-frequency polls — never dump full bodies at INFO (disk spam).
            is_frequent_endpoint = ep in {
                "attack-count",
                "heartbeat",
                "premium/tunnel-status",
                "agent/tunnel-status",
                "commands/pending",
                "attack",
                "agent/account-status",
                "client_status",
                "agent/open-ports",
                "events/batch",
                "agent/health",
                "agent/sync-rules",
                "agent/pending-blocks",
                "agent/pending-unblocks",
                "commands/result",
                "threats/config",
                "alerts/list",
            } or ep.startswith("commands/") or ep.startswith("alerts/")
            # Opt-in only: caller verbose_logging=True OR global VERBOSE_LOGGING.
            show_logs = bool(verbose_logging or VERBOSE_LOGGING) and not is_frequent_endpoint

            attempts = 0
            while attempts < 2:
                attempts += 1
                url = f"{self.base_url}/{ep}"
                req_params, req_data, extra_headers = self._prepare_request(params, data, token)
                tok = token or self._auth_token
                if tok and req_data is not None and "token" not in req_data:
                    req_data["token"] = tok

                if show_logs and attempts == 1:
                    self.log(f"[API] {method.upper()} isteği: {url}")
                    if req_params:
                        self.log(f"[API] Params: {redact_sensitive(req_params)}")
                    if req_data:
                        self.log(f"[API] JSON: {redact_sensitive(req_data)}")

                try:
                    response = self.session.request(
                        method=method,
                        url=url,
                        json=req_data,
                        params=req_params,
                        timeout=timeout,
                        verify=resolve_tls_verify(),
                        headers=extra_headers or None,
                    )
                except requests.exceptions.RequestException as e:
                    if attempts == 1 and self._activate_legacy_failover(str(e)):
                        continue
                    self.log(f"[API] İstek hatası: {e}")
                    return None

                if show_logs or response.status_code != 200:
                    self.log(f"[API] Yanıt: HTTP {response.status_code}")

                if 200 <= response.status_code < 300:
                    try:
                        result = response.json()
                    except Exception:
                        result = {"status": "ok"}
                    if show_logs:
                        # Cap body size — tunnel-status alone is multi-KB per poll.
                        preview = redact_sensitive(result)
                        text = repr(preview)
                        if len(text) > 400:
                            text = text[:400] + "…"
                        self.log(f"[API] Başarılı yanıt: {text}")
                    return result

                # 499 = client closed before upstream answered (sleep/proxy kill).
                # Never treat as fatal auth — caller/worker must keep retrying.
                if response.status_code == 499:
                    self.log(
                        f"[API] HTTP 499 on {endpoint} (client closed / interrupted) — transient"
                    )
                if (
                    attempts == 1
                    and response.status_code in (500, 502, 503, 504)
                    and self._activate_legacy_failover(f"HTTP {response.status_code}")
                ):
                    continue

                body_text = response.text or ""
                if response.status_code == 422:
                    try:
                        detail = response.json()
                        self.log(f"[API] 422 schema error ({endpoint}): {redact_sensitive(detail)}")
                    except Exception:
                        self.log(f"[API] 422 schema error ({endpoint}): {body_text[:500]}")
                else:
                    self.log(f"[API] Hata yanıtı: {body_text[:500]}")
                return None

            return None

        except json.JSONDecodeError as e:
            self.log(f"[API] JSON parse hatası: {e}")
            return None
        except Exception as e:
            self.log(f"[API] Beklenmeyen hata: {e}")
            return None

    def register_client(
        self,
        server_name: str,
        ip_address: str,
        machine_id: str = "",
        machine_guid: str = "",
    ) -> Optional[str]:
        """İstemciyi API'ye kaydeder ve bir token alır (machine_id ile upsert tercih edilir).

        Register body ``protection.block_rules`` → ProgramData (ThreatEngine boot/sync).
        """
        try:
            payload = {"server_name": server_name, "ip": ip_address}
            mid = (machine_id or "").strip()
            if mid:
                payload["machine_id"] = mid
                payload["hwid"] = mid
            guid = (machine_guid or "").strip()
            if guid:
                payload["machine_guid"] = guid
            response = self.api_request("POST", "register", data=payload)
            if response and "token" in response:
                token = response["token"]
                try:
                    prot = response.get("protection")
                    if isinstance(prot, dict):
                        from client_protection_store import save_protection
                        save_protection(prot)
                        n = len(prot.get("block_rules") or []) if isinstance(prot.get("block_rules"), list) else 0
                        self.log(f"[PROTECTION] register saved block_rules={n}")
                except Exception as pe:
                    self.log(f"[PROTECTION] register persist skip: {pe}")
                self.log(f"İstemci başarıyla kaydedildi, token alındı: {token[:8]}...")
                return token
            self.log("İstemci kaydı başarısız oldu veya token alınamadı.")
            return None
        except Exception as e:
            self.log(f"[API] İstemci kaydı sırasında hata: {e}")
            return None

    def update_client_ip(self, token: str, new_ip: str) -> bool:
        """İstemcinin genel IP adresini API'de günceller."""
        try:
            payload = {"token": token, "ip": new_ip}
            response = self.api_request("POST", "update-ip", data=payload)
            if response:
                self.log(f"IP adresi başarıyla güncellendi: {new_ip}")
                return True
            self.log(f"IP adresi güncellemesi başarısız oldu.")
            return False
        except Exception as e:
            self.log(f"[API] IP güncelleme hatası: {e}")
            return False

    def send_heartbeat(self, token: str, ip: str, hostname: str, running: bool, status: str,
                        system_context: dict = None) -> bool:
        """API'ye zengin heartbeat sinyali gönderir.
        
        Args:
            token: Client authentication token
            ip: Public IP address
            hostname: Server hostname
            running: Whether the client is running
            status: Status string (online/idle/offline)
            system_context: Optional dict with rich system info:
                agent_version, os_info, uptime_hours, cpu_percent, memory_percent,
                active_services, threat_level, blocked_ips, total_attacks, etc.
        """
        try:
            payload = {
                "token": token, "ip": ip, "hostname": hostname,
                "running": running, "status": status
            }
            # Merge rich system context if provided
            if system_context:
                payload["system_context"] = system_context
            response = self.api_request("POST", "heartbeat", data=payload, verbose_logging=False)
            # P1: heartbeat body may include account_linked
            try:
                from client_utils import apply_account_link_from_payload
                apply_account_link_from_payload(response, source="heartbeat")
            except Exception:
                pass
            return response is not None
        except Exception as e:
            self.log(f"[API] Heartbeat gönderme hatası: {e}")
            return False

    def get_account_status(self, token: str) -> Optional[Dict]:
        """GET /api/agent/account-status — AccountClient membership for this agent token.

        Falls back to client_status when dedicated endpoint is missing or has no
        account_linked field. Returns the raw JSON dict that carries link state,
        or None if unknown.
        """
        tok = (token or "").strip()
        if not tok:
            return None
        try:
            from client_utils import parse_account_link_payload

            # Dedicated endpoint (P0)
            primary = self.api_request(
                "GET",
                "agent/account-status",
                params={"token": tok},
                token=tok,
                timeout=8,
                verbose_logging=False,
            )
            if isinstance(primary, dict) and parse_account_link_payload(primary) is not None:
                return primary

            # Fallback: client_status with embedded account_linked (P1)
            secondary = self.api_request(
                "GET",
                "client_status",
                params={"token": tok},
                token=tok,
                timeout=8,
                verbose_logging=False,
            )
            if isinstance(secondary, dict) and parse_account_link_payload(secondary) is not None:
                return secondary
            # If primary had data but no link field, still return it for callers
            if isinstance(primary, dict):
                return primary
            return None
        except Exception as e:
            self.log(f"[API] account-status error: {e}")
            return None

    def report_open_ports(self, token: str, ports: list) -> bool:
        """İstemcideki açık portları API'ye raporlar."""
        try:
            payload = {"token": token, "ports": ports}
            response = self.api_request("POST", "agent/open-ports", data=payload)
            return response is not None
        except Exception as e:
            self.log(f"[API] Açık portları raporlama hatası: {e}")
            return False

    def report_relocate(
        self,
        token: str,
        *,
        service: str,
        status: str,
        old_port: Optional[int] = None,
        new_port: Optional[int] = None,
        source: str = "gui",
        auto_start_bait: Optional[bool] = None,
        open_ports: Optional[list] = None,
        reason: Optional[str] = None,
    ) -> Optional[Dict]:
        """POST /api/agent/relocate-report — GUI/local relocate sync (contract 1.4.45)."""
        try:
            payload: Dict[str, Any] = {
                "token": token,
                "service": str(service or "").upper(),
                "status": str(status or "error"),
                "source": str(source or "gui"),
            }
            if old_port is not None:
                payload["old_port"] = int(old_port)
            if new_port is not None:
                payload["new_port"] = int(new_port)
            if auto_start_bait is not None:
                payload["auto_start_bait"] = bool(auto_start_bait)
            if open_ports is not None:
                payload["open_ports"] = list(open_ports)
            if reason:
                payload["reason"] = str(reason)
            return self.api_request("POST", "agent/relocate-report", data=payload)
        except Exception as e:
            self.log(f"[API] relocate-report error: {e}")
            return None

    def report_service_action(self, token: str, service: str, action: str, port: Optional[int] = None) -> bool:
        """Bir servis eylemini (başlatma/durdurma) API'ye bildirir."""
        try:
            payload = {
                "token": token,
                "service": str(service or "").upper(),
                "action": "start" if action == "start" else "stop",
            }
            if port and str(port) != '-':
                payload["port"] = int(str(port))

            response = self.api_request("POST", "premium/tunnel-set", data=payload)
            if isinstance(response, dict) and response.get("status") in ("queued", "ok", "success"):
                self.log(f"Servis eylemi bildirildi: {payload}")
                return True
            
            self.log(f"Servis eylemi bildirimi başarısız: {response}")
            return False
        except Exception as e:
            self.log(f"Servis eylemi raporlama hatası: {e}")
            return False
    
    def check_connection(self, max_attempts: int = 5, delay: int = 5) -> bool:
        """API bağlantısını kontrol et - orijinal try_api_connection mantığına uygun"""
        for attempt in range(1, max_attempts + 1):
            self.log(f"[API] Bağlantı kontrol denemesi {attempt}/{max_attempts}")
            
            try:
                # Strip any trailing slash from base_url (orijinal koddan)
                base_url = self.base_url.rstrip('/')
                health_url = f"{base_url.rsplit('/api', 1)[0]}/healthz"
                self.log(f"Checking API health at {health_url}...")
                
                response = self.session.get(
                    health_url,
                    timeout=15,
                    verify=resolve_tls_verify(),
                )
                
                if response.status_code == 200:
                    try:
                        health_data = response.json()
                        if health_data.get("status") == "ok":
                            client_count = health_data.get("clients", 0)
                            self.log(f"API connection successful - {client_count} clients registered")
                            return True
                    except ValueError:
                        self.log("API health check succeeded but returned invalid JSON")
                
                if response.status_code in [401, 403]:  # API çalışıyor ama token gerekiyor
                    self.log("API connection successful but requires authentication")
                    return True
                    
                self.log(f"API connection failed: HTTP {response.status_code}")
                    
            except Exception as e:
                self.log(f"[API] Bağlantı denemesi {attempt} başarısız: {e}")
            
            if attempt < max_attempts:
                self.log(f"[API] {delay} saniye bekleyip tekrar deneniyor...")
                time.sleep(delay)
        
        self.log("[API] Bağlantı kurulamadı!")
        return False
    
    def get_service_statuses(self, token: str) -> Optional[Dict]:
        """Servis durumlarını al"""
        try:
            return self.api_request('GET', 'premium/tunnel-status', token=token)
        except Exception as e:
            self.log(f"[API] Servis durumu alma hatası: {e}")
            return None
    
    def update_service_statuses(self, token: str, statuses: list) -> bool:
        """Servis durumlarını güncelle"""
        try:
            data = {
                'token': token,
                'statuses': statuses
            }
            result = self.api_request('POST', 'agent/tunnel-status', data=data)
            return result is not None
        except Exception as e:
            self.log(f"[API] Servis durumu güncelleme hatası: {e}")
            return False
    
    def report_attack(self, token: str, attacker_ip: str, target_ip: str,
                       username: str, password: str, service: str, port: int) -> bool:
        """Yakalanan saldırı (credential) bilgisini API'ye raporlar.
        
        Args:
            token: Client authentication token
            attacker_ip: Saldırganın IP adresi
            target_ip: Hedef (yerel) IP adresi
            username: Yakalanan kullanıcı adı
            password: Yakalanan şifre
            service: Servis türü (RDP, SSH, FTP, MYSQL, MSSQL)
            port: Hedef port numarası
            
        Returns:
            bool: Raporlama başarılı ise True
        """
        try:
            from client_constants import MAX_CREDENTIAL_LENGTH
            # Truncate credentials to max length
            username = str(username or "")[:MAX_CREDENTIAL_LENGTH]
            password = str(password or "")[:MAX_CREDENTIAL_LENGTH]
            
            payload = {
                "token": token,
                "attacker_ip": attacker_ip,
                "ip": attacker_ip,  # canonical alias
                "target_ip": target_ip,
                "username": username,
                "password": password,
                "service": str(service or "").upper(),
                "port": int(port),
            }
            response = self.api_request("POST", "attack", data=payload)
            if response is not None:
                if isinstance(response, dict) and response.get("status") not in (
                    None, "ok", "success", "created",
                ):
                    # Unexpected status string — still treat 2xx body as success
                    self.log(f"[API] Saldırı yanıtı: {response}")
                self.log(f"[API] Saldırı raporlandı: {service}:{port} <- {attacker_ip}")
                return True
            
            self.log(f"[API] Saldırı raporlama başarısız: {response}")
            return False
        except Exception as e:
            self.log(f"[API] Saldırı raporlama hatası: {e}")
            return False
    
    def report_attack_batch(self, token: str, attacks: list) -> bool:
        """Birden fazla saldırıyı toplu olarak raporlar.
        
        Args:
            token: Client authentication token
            attacks: Liste of attack dicts with keys:
                     attacker_ip, target_ip, username, password, service, port
        Returns:
            bool: Raporlama başarılı ise True
        """
        try:
            from client_constants import MAX_CREDENTIAL_LENGTH
            sanitized = []
            for atk in attacks:
                sanitized.append({
                    "attacker_ip": atk.get("attacker_ip", ""),
                    "target_ip": atk.get("target_ip", ""),
                    "username": str(atk.get("username", ""))[:MAX_CREDENTIAL_LENGTH],
                    "password": str(atk.get("password", ""))[:MAX_CREDENTIAL_LENGTH],
                    "service": str(atk.get("service", "")).upper(),
                    "port": int(atk.get("port", 0)),
                })
            
            payload = {"token": token, "attacks": sanitized}
            response = self.api_request("POST", "attacks/batch", data=payload)
            if isinstance(response, dict) and response.get("status") in ("ok", "success", "created"):
                self.log(f"[API] {len(sanitized)} saldırı toplu raporlandı")
                return True
            
            self.log(f"[API] Toplu saldırı raporlama başarısız: {response}")
            return False
        except Exception as e:
            self.log(f"[API] Toplu saldırı raporlama hatası: {e}")
            return False

    def get_attack_count(self, token: str) -> Optional[int]:
        """Saldırı sayısını al"""
        try:
            result = self.api_request('GET', 'attack-count', token=token, verbose_logging=False)
            
            if result:
                for key in ('count', 'attack_count', 'total', 'attacks'):
                    if key in result:
                        return int(result[key])
            
            return None
        except Exception as e:
            self.log(f"[API] Saldırı sayısı alma hatası: {e}")
            return None

    def check_authenticated(self, token: str) -> bool:
        """Token ile kimlik doğrulamalı API erişimini test et."""
        if not token:
            return False
        try:
            if self.get_attack_count(token) is not None:
                return True
            status = self.get_service_statuses(token)
            return isinstance(status, dict)
        except Exception:
            return False

    # ===================== THREAT DETECTION v4.0 — Faz 2 ===================== #

    def report_auto_block(self, token: str, data: dict) -> bool:
        """POST /api/alerts/auto-block — Otomatik engelleme bildirimi"""
        try:
            payload = {"token": token, **data}
            resp = self.api_request("POST", "alerts/auto-block", data=payload)
            return isinstance(resp, dict) and resp.get("status") in ("ok", "success", "created")
        except Exception as e:
            self.log(f"[API] auto-block report error: {e}")
            return False

    def fetch_pending_commands(self, token: str) -> list:
        """GET /api/commands/pending — Bekleyen uzak komutları çek"""
        try:
            resp = self.api_request(
                "GET", "commands/pending",
                token=token,
                timeout=8, verbose_logging=False,
            )
            if isinstance(resp, dict):
                return resp.get("commands", [])
            return []
        except Exception as e:
            self.log(f"[API] fetch pending commands error: {e}")
            return []

    def report_command_result(self, token: str, command_id: str, status: str,
                              result: dict) -> bool:
        """POST /api/commands/result — Komut sonucunu raporla"""
        try:
            from datetime import datetime, timezone
            payload = {
                "token": token,
                "command_id": command_id,
                "status": status,
                "result": result,
                "executed_at": datetime.now(timezone.utc).isoformat(),
            }
            resp = self.api_request("POST", "commands/result", data=payload)
            return isinstance(resp, dict) and resp.get("status") in ("ok", "success")
        except Exception as e:
            self.log(f"[API] command result report error: {e}")
            return False

    def fetch_threat_config(self, token: str) -> Optional[Dict]:
        """GET /api/threats/config — Tehdit algılama + sessiz saat konfigürasyonu"""
        try:
            resp = self.api_request(
                "GET", "threats/config",
                token=token,
                timeout=8, verbose_logging=False,
            )
            if isinstance(resp, dict):
                return resp
            return None
        except Exception as e:
            self.log(f"[API] fetch threat config error: {e}")
            return None

    def update_threat_config(self, token: str, patch: Dict) -> Optional[Dict]:
        """POST /api/threats/config — update security layers immediately.

        The cloud remains the source of truth. Callers should apply the returned
        effective config locally only after this request succeeds.
        """
        try:
            if not token or not isinstance(patch, dict) or not patch:
                return None
            resp = self.api_request(
                "POST", "threats/config",
                token=token, data=patch,
                timeout=10, verbose_logging=False,
            )
            return resp if isinstance(resp, dict) else None
        except Exception as e:
            self.log(f"[API] update threat config error: {e}")
            return None

    def fetch_block_rules(self, token: str) -> Optional[list]:
        """GET /api/premium/rules — Dashboard'dan tanımlanan blok kurallarını çek.

        Her kural şu yapıda:
          {
            "id": 1,
            "name": "RDP",
            "services": "RDP",
            "threshold_count": 3,
            "window_minutes": 30,
            "actions": "email,block",
            "enabled": true,
            "email_cooldown_min": 10,
            "match_usernames": "admin\nroot"
          }
        """
        try:
            resp = self.api_request(
                "GET", "premium/rules",
                token=token,
                timeout=8, verbose_logging=False,
            )
            if isinstance(resp, list):
                return resp
            # API bazen {"rules": [...]} döndürebilir
            if isinstance(resp, dict) and "rules" in resp:
                rules = resp["rules"]
                if isinstance(rules, list):
                    return rules
            return None
        except Exception as e:
            self.log(f"[API] fetch block rules error: {e}")
            return None

    def report_silent_hours_event(self, token: str, data: dict) -> bool:
        """POST /api/alerts/silent-hours — Sessiz saat ihlali bildirimi"""
        try:
            payload = {"token": token, **data}
            resp = self.api_request("POST", "alerts/silent-hours", data=payload)
            return isinstance(resp, dict) and resp.get("status") in ("ok", "success", "created")
        except Exception as e:
            self.log(f"[API] silent hours event report error: {e}")
            return False

    # ───────── Faz 3  ─  System Health ─────────
    def report_health(self, token: str, snapshot: dict) -> bool:
        """POST /api/health/report — Sistem sağlık raporu gönder"""
        try:
            payload = {"token": token, **snapshot}
            resp = self.api_request("POST", "health/report", data=payload)
            return isinstance(resp, dict) and resp.get("status") in ("ok", "success", "created")
        except Exception as e:
            self.log(f"[API] health report error: {e}")
            return False

    def report_ransomware_event(self, token: str, data: dict) -> bool:
        """POST /api/alerts/ransomware — Ransomware algılama bildirimi"""
        try:
            payload = {"token": token, **data}
            resp = self.api_request("POST", "alerts/ransomware", data=payload)
            return isinstance(resp, dict) and resp.get("status") in ("ok", "success", "created")
        except Exception as e:
            self.log(f"[API] ransomware event report error: {e}")
            return False

    def fetch_threat_intel(
        self,
        token: str,
        *,
        since_version: Optional[str] = None,
        etag: Optional[str] = None,
        client_version: str = "",
        os_name: str = "windows",
    ) -> Optional[dict]:
        """GET /api/agent/threat-intel — cloud threat bundle (docs/CLOUD_THREAT_INTEL_API.md).

        Returns:
          {"not_modified": True} on HTTP 304
          {"bundle": {...}, "etag": "..."} on 200
          None on error / unavailable endpoint
        """
        try:
            url = f"{self.base_url}/agent/threat-intel"
            params = {"token": token, "os": os_name or "windows"}
            if since_version:
                params["since_version"] = since_version
            if client_version:
                params["client_version"] = client_version
            headers = {}
            req_params, _, prep_headers = self._prepare_request(params, None, token)
            if prep_headers:
                headers.update(prep_headers)
            if etag:
                headers["If-None-Match"] = etag if str(etag).startswith('"') else f'"{etag}"'

            r = self.session.get(
                url,
                params=req_params or params,
                headers=headers or None,
                timeout=30,
                verify=resolve_tls_verify(),
            )
            if r.status_code == 304:
                return {"not_modified": True}
            if r.status_code in (404, 501, 503):
                # Cloud not ready yet — soft fail
                return None
            if not (200 <= r.status_code < 300):
                self.log(f"[API] threat-intel HTTP {r.status_code}")
                return None
            try:
                data = r.json()
            except Exception:
                return None
            if not isinstance(data, dict):
                return None
            resp_etag = r.headers.get("ETag") or data.get("etag") or ""
            return {"bundle": data, "etag": resp_etag}
        except Exception as e:
            self.log(f"[API] threat-intel fetch error: {e}")
            return None

    def ack_threat_intel(self, token: str, bundle_version: str, stats: Optional[dict] = None) -> bool:
        """POST /api/agent/threat-intel/ack — soft-fail if missing."""
        try:
            payload = {
                "token": token,
                "bundle_version": bundle_version,
                "applied_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "stats": stats or {},
            }
            resp = self.api_request(
                "POST", "agent/threat-intel/ack", data=payload, timeout=15, verbose_logging=False,
            )
            return isinstance(resp, dict)
        except Exception as e:
            self.log(f"[API] threat-intel ack error: {e}")
            return False

    def report_self_protection_event(self, token: str, data: dict) -> bool:
        """POST /api/alerts/self-protection — Self-protection olay bildirimi"""
        try:
            payload = {"token": token, **data}
            resp = self.api_request("POST", "alerts/self-protection", data=payload)
            return isinstance(resp, dict) and resp.get("status") in ("ok", "success", "created")
        except Exception as e:
            self.log(f"[API] self-protection event report error: {e}")
            return False

    def report_lifecycle_event(self, token: str, data: dict) -> bool:
        """POST /api/alerts/lifecycle — client crash/watchdog/memory-restart olaylari.

        Soft-fail if endpoint missing (404) so older backends do not break clients.
        """
        try:
            payload = {"token": token, **(data or {})}
            resp = self.api_request(
                "POST", "alerts/lifecycle", data=payload, timeout=10,
            )
            if isinstance(resp, dict) and resp.get("status") in (
                "ok", "success", "created", "accepted",
            ):
                return True
            # Some APIs return empty 200/204 — treat non-exception as soft ok only if dict
            if resp is True:
                return True
            return False
        except Exception as e:
            # Do not spam — lifecycle flush retries from queue
            self.log(f"[API] lifecycle event report error: {e}")
            return False

    def report_logon_challenge(self, token: str, data: dict) -> bool:
        """POST /api/alerts/logon-challenge — Email onaylı logon challenge."""
        try:
            payload = {"token": token, **(data or {})}
            resp = self.api_request("POST", "alerts/logon-challenge", data=payload)
            if isinstance(resp, dict):
                return True
            # Endpoint henüz yoksa urgent zaten ayrı gidiyor — soft-fail
            return False
        except Exception as e:
            self.log(f"[API] logon-challenge report error: {e}")
            return False

    def fetch_logon_challenge_status(self, token: str) -> Optional[Dict]:
        """GET /api/agent/logon-challenges — onaylanan IP / challenge listesi."""
        try:
            resp = self.api_request(
                "GET", "agent/logon-challenges",
                token=token,
            )
            return resp if isinstance(resp, dict) else None
        except Exception as e:
            self.log(f"[API] logon-challenges fetch error: {e}")
            return None

    # ───────── Faz 4  ─  Threat Summary + Notification Preferences ─────────
    def fetch_threat_summary(self, token: str, period: str = "24h") -> Optional[Dict]:
        """GET /api/threats/summary — Tehdit özeti çek"""
        try:
            resp = self.api_request(
                "GET", "threats/summary",
                params={"period": period},
                token=token,
            )
            return resp if isinstance(resp, dict) else None
        except Exception as e:
            self.log(f"[API] threat summary fetch error: {e}")
            return None

    def fetch_alerts_list(self, token: str, limit: int = 40) -> Optional[Dict]:
        """GET /api/alerts/list — recent alerts for Control Center (dashboard parity)."""
        try:
            resp = self.api_request(
                "GET",
                "alerts/list",
                params={"limit": int(limit)},
                token=token,
                timeout=12,
            )
            if isinstance(resp, list):
                return {"alerts": resp, "total": len(resp)}
            if isinstance(resp, dict):
                return resp
            return None
        except Exception as e:
            self.log(f"[API] alerts/list fetch error: {e}")
            return None

    def update_notification_preferences(self, token: str, prefs: dict) -> bool:
        """PUT /api/notifications/preferences — Bildirim tercihleri güncelle"""
        try:
            payload = {"token": token, **prefs}
            resp = self.api_request("PUT", "notifications/preferences", data=payload)
            return isinstance(resp, dict) and resp.get("status") in ("ok", "success", "updated")
        except Exception as e:
            self.log(f"[API] notification preferences update error: {e}")
            return False

    def report_events_batch(self, token: str, events: list,
                            batch_id: str = None, summary: dict = None) -> bool:
        """POST /api/events/batch — Toplu olay gönderimi (canonical schema)."""
        try:
            import uuid as _uuid
            payload = {
                "token": token,
                "batch_id": batch_id or str(_uuid.uuid4()),
                "events": events,
            }
            if summary:
                payload["summary"] = summary
            resp = self.api_request("POST", "events/batch", data=payload)
            return isinstance(resp, dict) and resp.get("status") in (
                "ok", "success", "received",
            )
        except Exception as e:
            self.log(f"[API] events batch report error: {e}")
            return False

    def report_urgent_alert(self, token: str, alert: dict) -> Optional[Dict]:
        """POST /api/alerts/urgent — Kritik tehdit bildirimi."""
        try:
            payload = {"token": token, **alert}
            resp = self.api_request("POST", "alerts/urgent", data=payload, timeout=15)
            return resp if isinstance(resp, dict) else None
        except Exception as e:
            self.log(f"[API] urgent alert error: {e}")
            return None

    def upload_remote_frame(self, token: str, jpeg_bytes: bytes,
                            width: int, height: int, seq: int,
                            fps: float = 2.0) -> dict:
        """POST /api/remote/frame (multipart) — fallback frame-json base64.

        Returns ``{"ok": bool, "inputs": list}``. Cloud may piggyback drained
        remote-input events on the ACK (AGENT_REMOTE_INPUT_HOTFIX).
        """
        import base64

        empty = {"ok": False, "inputs": []}
        try:
            url = f"{self.base_url}/remote/frame"
            req_params, _, headers = self._prepare_request(None, None, token)
            headers = dict(headers or {})
            headers.pop("Content-Type", None)

            files = {
                "file": ("frame.jpg", jpeg_bytes, "image/jpeg"),
            }
            data = {
                "token": token,
                "width": str(int(width)),
                "height": str(int(height)),
                "seq": str(int(seq)),
                "fps": str(fps),
            }
            r = self.session.post(
                url,
                data=data,
                files=files,
                params=req_params,
                headers=headers or None,
                timeout=20,
                verify=resolve_tls_verify(),
            )
            if 200 <= r.status_code < 300:
                return {"ok": True, "inputs": self._extract_remote_inputs(r)}

            b64 = base64.b64encode(jpeg_bytes).decode("ascii")
            alt = self.api_request(
                "POST", "remote/frame-json",
                data={
                    "token": token,
                    "image_base64": b64,
                    "width": int(width),
                    "height": int(height),
                    "seq": int(seq),
                    "fps": fps,
                },
                timeout=20,
                verbose_logging=False,
                token=token,
            )
            if alt is None:
                return empty
            inputs = []
            if isinstance(alt, dict):
                inputs = self._inputs_from_payload(alt)
            elif isinstance(alt, list):
                inputs = alt
            return {"ok": True, "inputs": inputs}
        except Exception as e:
            self.log(f"[API] remote frame upload error: {e}")
            return empty

    @staticmethod
    def _inputs_from_payload(payload) -> list:
        if not isinstance(payload, dict):
            return []
        for key in ("inputs", "events", "items"):
            val = payload.get(key)
            if isinstance(val, list):
                return val
        data = payload.get("data")
        if isinstance(data, dict):
            for key in ("inputs", "events", "items"):
                val = data.get(key)
                if isinstance(val, list):
                    return val
        if isinstance(data, list):
            return data
        return []

    def _extract_remote_inputs(self, response) -> list:
        """Parse inputs[] from multipart/frame-json HTTP response body."""
        try:
            ctype = (response.headers.get("Content-Type") or "").lower()
            if "json" in ctype or (response.text or "").lstrip().startswith(("{", "[")):
                data = response.json()
                if isinstance(data, list):
                    return data
                return self._inputs_from_payload(data if isinstance(data, dict) else {})
        except Exception:
            pass
        return []

    def fetch_remote_inputs(self, token: str, limit: int = 80) -> list:
        """GET /api/remote/inputs — backup queue (primary = frame ACK inputs[])."""
        try:
            resp = self.api_request(
                "GET", "remote/inputs",
                token=token,
                params={"limit": int(limit)},
                timeout=5,
                verbose_logging=False,
            )
            if isinstance(resp, list):
                return resp
            if isinstance(resp, dict):
                return self._inputs_from_payload(resp)
            return []
        except Exception as e:
            self.log(f"[API] remote inputs poll error: {e}")
            return []

    def clear_client_data(self, token: str, scopes: list,
                          reason: str = "user_requested_cleanup") -> Optional[Dict]:
        """POST /api/agent/clear-data — Dashboard/sunucu verilerini temizle.

        Canonical scopes: attacks | blocks | alerts | threat_summary | all
        Backend yoksa None döner; client yerel temizliği yine yapar.
        """
        try:
            payload = {
                "token": token,
                "scopes": scopes or ["all"],
                "reason": reason,
            }
            resp = self.api_request("POST", "agent/clear-data", data=payload, timeout=30)
            if resp is not None:
                return resp if isinstance(resp, dict) else {"status": "ok"}
            # Alias fallback
            if "attacks" in (scopes or []) or "all" in (scopes or []):
                alt = self.api_request("POST", "attacks/clear", data={
                    "token": token, "reason": reason,
                }, timeout=30)
                if alt is not None:
                    return alt if isinstance(alt, dict) else {"status": "ok"}
            return None
        except Exception as e:
            self.log(f"[API] clear-data error: {e}")
            return None

    def sync_firewall_rules(self, token: str, blocks: list) -> bool:
        """POST /api/agent/sync-rules — Yerel blok listesini dashboard ile hizala."""
        try:
            from datetime import datetime, timezone
            payload = {
                "token": token,
                "blocks": blocks or [],
                "total_rules": len(blocks or []),
                "synced_at": datetime.now(timezone.utc).isoformat(),
            }
            resp = self.api_request("POST", "agent/sync-rules", data=payload, timeout=20)
            return resp is not None
        except Exception as e:
            self.log(f"[API] sync-rules error: {e}")
            return False

# ===================== API WRAPPER FUNCTIONS ===================== #
# Purpose: High-level API request functions for client integration

def api_request_with_token(api_client, token: str, method: str, endpoint: str, 
                          data: Optional[Dict] = None, params: Optional[Dict] = None, timeout: int = API_REQUEST_TIMEOUT, 
                          json: Optional[Dict] = None) -> Optional[Dict]:
    """API request wrapper with token authentication"""
    try:
        return api_client.api_request(
            method=method, endpoint=endpoint,
            data=json if json else data, params=params, timeout=timeout,
            token=token,
        )
    except Exception as e:
        if hasattr(api_client, 'log') and api_client.log:
            api_client.log(f"[API] Wrapper hatası: {e}")
        return None

# ===================== SERVICE ACTION REPORTING ===================== #
# Purpose: Report service state changes to honeypot server

def report_service_action_api(api_request_func, token: str, service: str, action: str,
                           port: Optional[Union[str, int]] = None, log_func=None) -> bool:
    """Report service action to API using provided api_request function"""
    try:
        if not token:
            if log_func: log_func("Token yok; eylem bildirilemedi")
            return False

        payload: Dict[str, Any] = {
            "token": token,
            "service": str(service or "").upper(),
            "action": action if action in ("start", "stop") else "stop",
        }
        if port and str(port) != '-':
            payload["port"] = int(str(port))

        resp = api_request_func("POST", "premium/tunnel-set", json=payload)
        if isinstance(resp, dict) and resp.get("status") in ("queued", "ok", "success"):
            if log_func: log_func(f"Servis eylemi bildirildi: {payload}")
            return True

        if log_func: log_func(f"Servis eylemi bildirimi başarısız: {resp}")
        return False
    except Exception as e:
        if log_func: log_func(f"Servis eylemi raporlanırken hata: {e}")
        return False

# ===================== CLIENT REGISTRATION ===================== #

def link_account_with_credentials(
    email: str,
    password: str,
    agent_token: str,
    *,
    api_url: str = "",
    log_func=None,
) -> Dict[str, Any]:
    """Link this agent token to an Asteria Account using email+password.

    Prefer JSON: POST /api/agent/link-account
    Fallback: form login + /account/link-server (session cookie).

    Returns dict:
      ok: bool
      account_linked: bool
      account: optional dict
      error: optional str (user-facing)
      source: 'agent_api' | 'web_fallback'
    """
    import requests
    from client_constants import API_URL
    from client_utils import apply_account_link_from_payload

    def _log(msg: str):
        if log_func:
            try:
                log_func(msg)
            except Exception:
                pass

    email = (email or "").strip()
    password = password or ""
    tok = (agent_token or "").strip()
    if not email or not password:
        return {"ok": False, "account_linked": False, "error": "missing_credentials"}
    if not tok:
        return {"ok": False, "account_linked": False, "error": "missing_token"}

    api_base = (api_url or API_URL).rstrip("/")
    site_base = api_base.rsplit("/api", 1)[0]
    verify = resolve_tls_verify()

    # --- P0: dedicated agent JSON endpoint ---
    for path in ("agent/link-account", "account/link-by-agent"):
        try:
            r = requests.post(
                f"{api_base}/{path}",
                json={"email": email, "password": password, "token": tok, "client_token": tok},
                timeout=20,
                verify=verify,
                headers={"Accept": "application/json"},
            )
            if r.status_code == 404:
                continue
            if r.status_code == 401:
                return {
                    "ok": False,
                    "account_linked": False,
                    "error": "invalid_credentials",
                    "source": "agent_api",
                }
            if r.status_code in (403, 409):
                detail = ""
                try:
                    detail = str((r.json() or {}).get("detail") or "")
                except Exception:
                    detail = ""
                detail_l = detail.lower()
                err = "already_linked_other"
                if "other" in detail_l or "another" in detail_l or "conflict" in detail_l:
                    err = "already_linked_other"
                return {
                    "ok": False,
                    "account_linked": False,
                    "error": err,
                    "detail": detail,
                    "source": "agent_api",
                }
            if 200 <= r.status_code < 300:
                try:
                    data = r.json() if r.content else {}
                except Exception:
                    data = {}
                if not isinstance(data, dict):
                    data = {"account_linked": True}
                data.setdefault("account_linked", True)
                if isinstance(data.get("account"), dict) and not data["account"].get("email"):
                    data["account"]["email"] = email
                elif "account" not in data:
                    data["account"] = {"email": email}
                apply_account_link_from_payload(data, source="link_account")
                _log(f"[ACCOUNT] Linked via {path}")
                return {
                    "ok": True,
                    "account_linked": True,
                    "account": data.get("account"),
                    "source": "agent_api",
                    "raw": data,
                }
            # Other errors from agent API
            detail = ""
            try:
                detail = str((r.json() or {}).get("detail") or "")
            except Exception:
                detail = (r.text or "")[:120]
            return {
                "ok": False,
                "account_linked": False,
                "error": detail or f"http_{r.status_code}",
                "source": "agent_api",
            }
        except Exception as e:
            _log(f"[ACCOUNT] {path} failed: {e}")

    # --- Fallback: web form login + link-server ---
    try:
        session = requests.Session()
        login = session.post(
            f"{site_base}/account/login",
            data={"email": email, "password": password},
            timeout=20,
            verify=verify,
            allow_redirects=True,
        )
        body = (login.text or "").lower()
        if "invalid" in body and "credential" in body:
            return {
                "ok": False,
                "account_linked": False,
                "error": "invalid_credentials",
                "source": "web_fallback",
            }
        if "login" in (login.url or "") and login.status_code == 200 and not session.cookies:
            # Still on login page without session → treat as auth failure
            if "invalid" in body or "incorrect" in body or "error" in body:
                return {
                    "ok": False,
                    "account_linked": False,
                    "error": "invalid_credentials",
                    "source": "web_fallback",
                }

        linked_ok = False
        last_err = ""
        for payload in (
            {"token": tok},
            {"client_token": tok},
            {"agent_token": tok},
            {"token": tok, "email": email},
        ):
            try:
                lr = session.post(
                    f"{site_base}/account/link-server",
                    data=payload,
                    timeout=20,
                    verify=verify,
                    allow_redirects=True,
                    headers={"Accept": "application/json, text/html"},
                )
                txt = (lr.text or "").lower()
                # Success heuristics for HTML/JSON endpoints
                if lr.status_code in (200, 302, 303):
                    if "invalid" in txt and "token" in txt:
                        last_err = "invalid_token"
                        continue
                    if "not found" in txt:
                        last_err = "client_not_found"
                        continue
                    linked_ok = True
                    break
                last_err = f"http_{lr.status_code}"
            except Exception as e:
                last_err = str(e)

        if not linked_ok:
            return {
                "ok": False,
                "account_linked": False,
                "error": last_err or "link_failed",
                "source": "web_fallback",
            }

        # Confirm via account-status when possible
        try:
            from client_utils import refresh_account_link_status
            st = refresh_account_link_status(tok)
            if st is False:
                # link may have succeeded but status lag — still mark local from email
                pass
        except Exception:
            pass

        apply_account_link_from_payload(
            {"account_linked": True, "account": {"email": email}},
            source="link_account_web",
        )
        _log("[ACCOUNT] Linked via web login + link-server fallback")
        return {
            "ok": True,
            "account_linked": True,
            "account": {"email": email},
            "source": "web_fallback",
        }
    except Exception as e:
        _log(f"[ACCOUNT] web fallback error: {e}")
        return {
            "ok": False,
            "account_linked": False,
            "error": str(e),
            "source": "web_fallback",
        }


def request_unlink_confirmation(
    email: str,
    password: str,
    agent_token: str,
    *,
    api_url: str = "",
    log_func=None,
) -> Dict[str, Any]:
    """Ask cloud to email a one-time unlink confirmation code (contract P0d).

    Returns ok=True when mail was queued. When endpoints are missing, returns
    ``mail_confirm=False`` / ``unlink_mail_unavailable`` so the GUI can fall
    back to password+PIN unlink until cloud ships the mailer.
    """
    import requests
    from client_constants import API_URL

    def _log(msg: str):
        if log_func:
            try:
                log_func(msg)
            except Exception:
                pass

    email = (email or "").strip()
    password = password or ""
    tok = (agent_token or "").strip()
    if not email or not password:
        return {"ok": False, "error": "missing_credentials", "mail_confirm": True}
    if not tok:
        return {"ok": False, "error": "missing_token", "mail_confirm": True}

    api_base = (api_url or API_URL).rstrip("/")
    verify = resolve_tls_verify()
    body = {
        "email": email,
        "password": password,
        "token": tok,
        "client_token": tok,
    }
    saw_404 = False
    for path in (
        "agent/unlink-account/request",
        "agent/unlink-account-request",
        "account/unlink-request",
    ):
        try:
            r = requests.post(
                f"{api_base}/{path}",
                json=body,
                timeout=20,
                verify=verify,
                headers={"Accept": "application/json"},
            )
            if r.status_code == 404:
                saw_404 = True
                continue
            if r.status_code == 401:
                return {
                    "ok": False,
                    "error": "invalid_credentials",
                    "mail_confirm": True,
                    "source": "agent_api",
                }
            if 200 <= r.status_code < 300:
                try:
                    data = r.json() if r.content else {}
                except Exception:
                    data = {}
                if not isinstance(data, dict):
                    data = {}
                _log(f"[ACCOUNT] Unlink confirm code requested via {path}")
                return {
                    "ok": True,
                    "sent": True,
                    "mail_confirm": True,
                    "expires_in": data.get("expires_in"),
                    "source": "agent_api",
                    "raw": data,
                }
            detail = ""
            try:
                detail = str((r.json() or {}).get("detail") or "")
            except Exception:
                detail = (r.text or "")[:120]
            return {
                "ok": False,
                "error": detail or f"http_{r.status_code}",
                "mail_confirm": True,
                "source": "agent_api",
            }
        except Exception as e:
            _log(f"[ACCOUNT] unlink request {path}: {e}")
            continue

    if saw_404:
        return {
            "ok": False,
            "error": "unlink_mail_unavailable",
            "mail_confirm": False,
            "source": "none",
        }
    return {
        "ok": False,
        "error": "unlink_mail_unavailable",
        "mail_confirm": False,
        "source": "none",
    }


def unlink_account_with_credentials(
    email: str,
    password: str,
    agent_token: str,
    *,
    confirm_code: str = "",
    require_confirm_code: bool = False,
    api_url: str = "",
    log_func=None,
) -> Dict[str, Any]:
    """Unlink this agent token from an Asteria Account (email+password confirm).

    Prefer JSON: POST /api/agent/unlink-account
    When ``require_confirm_code`` is True, ``confirm_code`` must be present and
    is sent for cloud mail-OTP verification (contract P0d).

    Returns dict: ok, account_linked, error?, source
    """
    import requests
    from client_constants import API_URL
    from client_utils import apply_account_link_from_payload, set_account_linked

    def _log(msg: str):
        if log_func:
            try:
                log_func(msg)
            except Exception:
                pass

    email = (email or "").strip()
    password = password or ""
    tok = (agent_token or "").strip()
    code = str(confirm_code or "").strip()
    if not email or not password:
        return {"ok": False, "account_linked": True, "error": "missing_credentials"}
    if not tok:
        return {"ok": False, "account_linked": True, "error": "missing_token"}
    if require_confirm_code and not code:
        return {"ok": False, "account_linked": True, "error": "missing_confirm_code"}

    api_base = (api_url or API_URL).rstrip("/")
    verify = resolve_tls_verify()

    payload = {
        "email": email,
        "password": password,
        "token": tok,
        "client_token": tok,
    }
    if code:
        payload["confirm_code"] = code
        payload["code"] = code

    paths = ("agent/unlink-account", "account/unlink-by-agent")
    if code:
        paths = (
            "agent/unlink-account/confirm",
            "agent/unlink-account",
            "account/unlink-by-agent",
        )

    for path in paths:
        try:
            r = requests.post(
                f"{api_base}/{path}",
                json=payload,
                timeout=20,
                verify=verify,
                headers={"Accept": "application/json"},
            )
            if r.status_code == 404:
                continue
            if r.status_code == 401:
                detail = ""
                try:
                    detail = str((r.json() or {}).get("detail") or "").lower()
                except Exception:
                    detail = ""
                err = "invalid_credentials"
                if "code" in detail or "confirm" in detail:
                    err = "invalid_confirm_code"
                return {
                    "ok": False,
                    "account_linked": True,
                    "error": err,
                    "source": "agent_api",
                }
            if r.status_code == 422 and require_confirm_code:
                return {
                    "ok": False,
                    "account_linked": True,
                    "error": "missing_confirm_code",
                    "source": "agent_api",
                }
            if 200 <= r.status_code < 300:
                try:
                    data = r.json() if r.content else {}
                except Exception:
                    data = {}
                if not isinstance(data, dict):
                    data = {}
                data["account_linked"] = False
                data["account"] = None
                apply_account_link_from_payload(data, source="unlink_account")
                set_account_linked(False, source="unlink_account")
                _log(f"[ACCOUNT] Unlinked via {path}")
                return {
                    "ok": True,
                    "account_linked": False,
                    "source": "agent_api",
                    "raw": data,
                }
            detail = ""
            try:
                detail = str((r.json() or {}).get("detail") or "")
            except Exception:
                detail = (r.text or "")[:120]
            detail_l = detail.lower()
            err = detail or f"http_{r.status_code}"
            if "code" in detail_l or "confirm" in detail_l:
                err = "invalid_confirm_code"
            return {
                "ok": False,
                "account_linked": True,
                "error": err,
                "source": "agent_api",
            }
        except Exception as e:
            _log(f"[ACCOUNT] unlink {path}: {e}")
            continue

    return {
        "ok": False,
        "account_linked": True,
        "error": "unlink_api_unavailable",
        "source": "none",
    }


def register_client_api(
    api_url: str,
    server_name: str,
    ip: str,
    token_save_func=None,
    log_func=None,
    machine_id: str = "",
    machine_guid: str = "",
) -> Optional[str]:
    """Register client with API and get token.

    Sends machine_id (hardware fingerprint: MachineGuid+MACs+SMBIOS hash) so the
    API can upsert and return the SAME durable token for this machine. VM clones
    that keep MachineGuid but get new NICs enroll as distinct clients.

    On success, persists ``protection.block_rules`` from the register body
    (honeypot-contract agent/register-protection.md) for ThreatEngine boot apply.

    Do **not** call this while a known old token still exists — use
    ``rotate_token_api`` (contract 1.4.29) to avoid ghost Client rows.
    """
    import requests
    
    try:
        payload = {
            "server_name": f"{server_name} ({ip})",
            "ip": ip,
        }
        mid = (machine_id or "").strip()
        if mid:
            payload["machine_id"] = mid
            payload["hwid"] = mid  # alias for older/newer API field names
        guid = (machine_guid or "").strip()
        if guid:
            payload["machine_guid"] = guid  # additive telemetry (contract ≥1.4.26)
        response = requests.post(
            f"{api_url}/register", json=payload, timeout=15,
            verify=resolve_tls_verify(),
        )
        
        if response.status_code == 200:
            data = response.json()
            token = data.get("token")
            if token:
                if token_save_func:
                    token_save_func(token)
                # Contract: protection.block_rules on register response
                try:
                    prot = data.get("protection")
                    if isinstance(prot, dict):
                        from client_protection_store import save_protection
                        if save_protection(prot):
                            n = len(prot.get("block_rules") or []) if isinstance(prot.get("block_rules"), list) else 0
                            if log_func:
                                log_func(f"[PROTECTION] register saved block_rules={n}")
                except Exception as pe:
                    if log_func:
                        log_func(f"[PROTECTION] register persist skip: {pe}")
                if log_func: log_func(f"Client registration successful: {server_name}")
                return token
        
        if log_func: log_func(f"Registration failed: HTTP {response.status_code}")
        return None
            
    except Exception as e:
        if log_func: log_func(f"Registration error: {e}")
        return None


def rotate_token_api(
    api_url: str,
    old_token: str,
    new_token: str,
    *,
    machine_id: str = "",
    reason: str = "identity_v2",
    log_func=None,
) -> dict:
    """In-place token rotate — same client_id (contract 1.4.29).

    Returns a dict:
      ok, status_code, token, client_id, detail, idempotent, rotated, raw
    Never writes disk; caller persists only on ok=True.
    """
    import requests

    _log = log_func or (lambda *_a, **_k: None)
    old_token = (old_token or "").strip()
    new_token = (new_token or "").strip()
    out = {
        "ok": False,
        "status_code": 0,
        "token": "",
        "client_id": None,
        "detail": "",
        "idempotent": False,
        "rotated": False,
        "raw": None,
    }
    if not old_token or not new_token:
        out["detail"] = "old_token and new_token required"
        out["status_code"] = 422
        return out
    if old_token == new_token:
        out["ok"] = True
        out["status_code"] = 200
        out["token"] = new_token
        out["idempotent"] = True
        out["detail"] = "same_token"
        return out

    base = (api_url or "").rstrip("/")
    # Prefer /api/agent/... ; api_url is typically .../api
    url = f"{base}/agent/rotate-token"
    payload = {
        "old_token": old_token,
        "new_token": new_token,
        "reason": (reason or "identity_v2").strip() or "identity_v2",
    }
    mid = (machine_id or "").strip()
    if mid:
        payload["machine_id"] = mid
        payload["hwid"] = mid

    headers = {
        "Authorization": f"Bearer {old_token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    try:
        resp = requests.post(
            url,
            json=payload,
            headers=headers,
            timeout=20,
            verify=resolve_tls_verify(),
        )
        out["status_code"] = int(resp.status_code)
        try:
            data = resp.json() if resp.content else {}
        except Exception:
            data = {}
        if not isinstance(data, dict):
            data = {}
        out["raw"] = data
        detail = (
            data.get("detail")
            or data.get("error")
            or data.get("message")
            or (resp.text or "")[:200]
        )
        out["detail"] = str(detail or "")

        if resp.status_code == 200:
            tok = (data.get("token") or new_token or "").strip()
            out["ok"] = True
            out["token"] = tok
            out["client_id"] = data.get("client_id")
            out["rotated"] = bool(data.get("rotated", True))
            out["idempotent"] = bool(data.get("idempotent", False))
            _log(
                f"[TOKEN] rotate-token ok client_id={out['client_id']} "
                f"rotated={out['rotated']} idempotent={out['idempotent']}"
            )
            return out

        _log(f"[TOKEN] rotate-token HTTP {resp.status_code}: {out['detail']}")
        return out
    except Exception as e:
        out["detail"] = str(e)
        out["status_code"] = 0
        _log(f"[TOKEN] rotate-token error: {e}")
        return out


# Backward-compatible alias (pre-Asteria brand). Prefer AsteriaAPIClient.
HoneypotAPIClient = AsteriaAPIClient
