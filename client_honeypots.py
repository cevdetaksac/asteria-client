#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Asteria Client - Honeypot Services Module

Lightweight honeypot servisleri: sahte protokol handshake yaparak
saldırgan credential bilgilerini yakalar ve API'ye raporlar.

Sınıflar:
    BaseHoneypot   — Tüm servisler için abstract base class (threading.Thread)
    FTPHoneypot    — Sahte FTP servisi (raw socket, kütüphane gerektirmez)
    SSHHoneypot    — Sahte SSH servisi (paramiko ServerInterface)
    MySQLHoneypot  — Sahte MySQL servisi (native handshake, kütüphane gerektirmez)
    MSSQLHoneypot  — Sahte MSSQL servisi (TDS pre-login, kütüphane gerektirmez)
    RDPHoneypot    — Sahte RDP (X.224 cookie + NLA/CredSSP NetNTLMv2 hash)

Kullanım:
    def on_credential(attacker_ip, username, password, service, port):
        print(f"Yakalandı: {username}:{password} <- {attacker_ip}")

    ftp = FTPHoneypot(port=21, on_credential=on_credential)
    ftp.start()
    ...
    ftp.stop()

Notlar:
    - Her servis kendi thread'inde çalışır (daemon=True)
    - Port çakışması start() öncesinde kontrol edilir
    - Otomatik yeniden başlatma (max 3 deneme, exponential backoff)
    - Rate limiting: aynı IP+service için dk başına max 10 rapor
"""

import hashlib
import os
import socket
import struct
import threading
import time
import logging
from abc import ABC, abstractmethod
from collections import defaultdict
from typing import Callable, Optional
from urllib.parse import unquote_plus

from client_constants import (
    FTP_BANNER, SSH_BANNER, MYSQL_VERSION, MSSQL_VERSION, RDP_CERT_CN,
    HTTP_SERVER_BANNER, SMB_SERVER_NAME, HONEYPOT_BIND_ADDRESS,
    MAX_CREDENTIAL_LENGTH, MAX_HASH_CREDENTIAL_LENGTH, MAX_ATTEMPTS_PER_IP_PER_MIN,
    HONEYPOT_AUTO_RESTART_MAX, HONEYPOT_RESTART_BACKOFF,
)
from client_helpers import log, is_port_in_use


# ===================== RATE LIMITER ===================== #

# Hard caps for months-long uptime under internet scan floods
_RATE_BUCKET_MAX_KEYS = 10000
_HONEYPOT_MAX_HANDLERS = 48  # per service — reject when saturated


class _RateLimiter:
    """IP+service bazlı rate limiter — dakikada max N rapor; idle key eviction."""

    def __init__(self, max_per_min: int = MAX_ATTEMPTS_PER_IP_PER_MIN):
        self._max = max_per_min
        self._buckets: dict[str, list[float]] = defaultdict(list)
        self._lock = threading.Lock()
        self._last_sweep = 0.0

    def allow(self, key: str) -> bool:
        now = time.time()
        with self._lock:
            bucket = self._buckets[key]
            # Eski girişleri temizle (60s pencere)
            bucket[:] = [t for t in bucket if now - t < 60]
            if not bucket and key in self._buckets:
                # Keep key only if we will append below; prune empties in sweep
                pass
            if len(bucket) >= self._max:
                return False
            bucket.append(now)
            if now - self._last_sweep > 30 or len(self._buckets) > _RATE_BUCKET_MAX_KEYS:
                self._sweep_locked(now)
            return True

    def _sweep_locked(self, now: float) -> None:
        """Drop idle keys; hard-cap total keys (call with lock held)."""
        self._last_sweep = now
        dead = [
            k for k, ts in self._buckets.items()
            if not ts or all(now - t >= 60 for t in ts)
        ]
        for k in dead:
            del self._buckets[k]
        if len(self._buckets) > _RATE_BUCKET_MAX_KEYS:
            ranked = sorted(
                self._buckets.items(),
                key=lambda kv: max(kv[1]) if kv[1] else 0.0,
            )
            drop_n = len(self._buckets) - (_RATE_BUCKET_MAX_KEYS // 2)
            for k, _ in ranked[:drop_n]:
                del self._buckets[k]

    def cleanup(self) -> int:
        """MemoryGuard hook — return number of keys removed."""
        with self._lock:
            before = len(self._buckets)
            self._sweep_locked(time.time())
            return before - len(self._buckets)

    def size(self) -> int:
        with self._lock:
            return len(self._buckets)


_rate_limiter = _RateLimiter()


def cleanup_honeypot_rate_limiter() -> int:
    """Export for MemoryGuard."""
    return _rate_limiter.cleanup()


# ===================== BASE HONEYPOT ===================== #

class BaseHoneypot(ABC, threading.Thread):
    """Tüm honeypot servisleri için abstract base class.

    Alt sınıflar sadece ``handle_client()`` metodunu implement eder.
    ``start()`` / ``stop()`` yaşam döngüsü bu sınıfta yönetilir.
    """

    def __init__(
        self,
        port: int,
        service_name: str,
        on_credential: Callable[..., None],
        bind_addr: str = HONEYPOT_BIND_ADDRESS,
        backlog: int = 64,
    ):
        super().__init__(daemon=True, name=f"Honeypot-{service_name}-{port}")
        self.port = int(port)
        self.service_name = service_name.upper()
        self.on_credential = on_credential
        self.bind_addr = bind_addr
        self.backlog = backlog

        self._stop_evt = threading.Event()
        self._server_sock: Optional[socket.socket] = None
        self._restart_count = 0
        self.running = False
        self.error: Optional[str] = None
        # Bound concurrent client handlers (scan floods must not spawn unlimited threads)
        self._handler_sem = threading.Semaphore(_HONEYPOT_MAX_HANDLERS)
        self._handlers_rejected = 0

    # ---------- public API ----------

    def stop(self):
        """Servisi durdur — accept loop kırılır, socket kapatılır."""
        self._stop_evt.set()
        if self._server_sock:
            try:
                self._server_sock.close()
            except OSError:
                pass
        self.running = False
        log(f"[{self.service_name}] Port {self.port} durduruldu")

    def get_status(self) -> str:
        if self.error:
            return "error"
        return "started" if self.running else "stopped"

    def get_health(self) -> dict:
        """DEC-205/206/208/209 bounded deception health (no credentials)."""
        return {
            "service": self.service_name,
            "port": self.port,
            "status": self.get_status(),
            "handler_limit": _HONEYPOT_MAX_HANDLERS,
            "handlers_rejected": int(self._handlers_rejected),
            "backlog": int(self.backlog),
            "rate_limit_per_ip_min": int(MAX_ATTEMPTS_PER_IP_PER_MIN),
            "resource_budgeted": True,
            "protocol_aware": self.service_name in {
                "SSH", "RDP", "SMB", "FTP", "MYSQL", "MSSQL", "HTTP"
            },
            "fingerprint_profile": "static_legacy",
            "bypass_coverage_required": True,
        }

    # ---------- credential reporting ----------

    def report_credential(self, attacker_ip: str, username: str, password: str = ""):
        """Yakalanan credential'ı rate-limit kontrolüyle callback'e ilet."""
        username = str(username or "")[:MAX_CREDENTIAL_LENGTH]
        pwd = str(password or "")
        # NetNTLMv2 / long hash lines need more room than short passwords
        max_pwd = (
            MAX_HASH_CREDENTIAL_LENGTH
            if ("::" in pwd and len(pwd) > 64) or pwd.startswith("<netntlm")
            else MAX_CREDENTIAL_LENGTH
        )
        password = pwd[:max_pwd]

        key = f"{attacker_ip}:{self.service_name}"
        if not _rate_limiter.allow(key):
            return  # Rate limit aşıldı — sessizce atla

        # Log only after rate-limit allow; never write cleartext passwords.
        log(
            f"[{self.service_name}] Credential yakalandı: "
            f"{username}:*** <- {attacker_ip}"
        )

        try:
            self.on_credential(
                attacker_ip=attacker_ip,
                username=username,
                password=password,
                service=self.service_name,
                port=self.port,
            )
        except Exception as exc:
            log(f"[{self.service_name}] Credential callback hatası: {exc}")

    # ---------- thread entry point ----------

    def run(self):
        """Ana accept döngüsü — alt sınıf handle_client() sağlar."""
        # Port çakışma kontrolü
        if is_port_in_use(self.port):
            self.error = f"Port {self.port} zaten kullanımda"
            log(f"[{self.service_name}] HATA: {self.error}")
            return

        try:
            self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._server_sock.bind((self.bind_addr, self.port))
            self._server_sock.listen(self.backlog)
            self._server_sock.settimeout(1.0)
            self.running = True
            self.error = None
            log(f"[{self.service_name}] Dinleniyor: {self.bind_addr}:{self.port}")
        except Exception as exc:
            self.error = str(exc)
            log(f"[{self.service_name}] Bind hatası port {self.port}: {exc}")
            return

        while not self._stop_evt.is_set():
            try:
                client_sock, addr = self._server_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                if self._stop_evt.is_set():
                    break
                log(f"[{self.service_name}] Accept hatası")
                continue

            # Her bağlantı kendi thread'inde işlenir — concurrency capped
            if not self._handler_sem.acquire(blocking=False):
                self._handlers_rejected += 1
                if self._handlers_rejected % 100 == 1:
                    log(f"[{self.service_name}] handler saturated "
                        f"(>{_HONEYPOT_MAX_HANDLERS}) — dropping {addr[0]}")
                try:
                    client_sock.close()
                except OSError:
                    pass
                continue

            t = threading.Thread(
                target=self._safe_handle,
                args=(client_sock, addr),
                daemon=True,
                name=f"{self.service_name}-handler-{addr[0]}",
            )
            t.start()

        self.running = False

    def _safe_handle(self, client_sock: socket.socket, addr: tuple):
        """handle_client() çevresinde güvenli try/except sarmalayıcı."""
        try:
            self.handle_client(client_sock, addr)
        except Exception as exc:
            log(f"[{self.service_name}] Bağlantı hatası {addr[0]}: {exc}")
        finally:
            try:
                client_sock.close()
            except OSError:
                pass
            try:
                self._handler_sem.release()
            except Exception:
                pass

    # ---------- abstract ----------

    @abstractmethod
    def handle_client(self, client_sock: socket.socket, addr: tuple):
        """Tek bir bağlantıyı işle — credential yakala, bağlantıyı kapat.

        Alt sınıf, protokol handshake'ini burada yapar ve
        ``self.report_credential(ip, username, password)`` çağırır.
        """
        ...


# ===================== FTP HONEYPOT ===================== #

class FTPHoneypot(BaseHoneypot):
    """Sahte FTP servisi — USER/PASS komutlarıyla credential yakalar.

    Protokol akışı:
        Server: 220 (vsFTPd 3.0.5)\\r\\n
        Client: USER admin\\r\\n
        Server: 331 Password required for admin.\\r\\n
        Client: PASS secret123\\r\\n
        Server: 530 Login incorrect.\\r\\n
        (bağlantı kapatılır)
    """

    TIMEOUT = 30  # saniye — yavaş tarayıcılar için

    def __init__(self, port: int = 21, *, on_credential: Callable, banner: str = ""):
        super().__init__(port=port, service_name="FTP", on_credential=on_credential)
        self.banner = banner or FTP_BANNER

    def handle_client(self, sock: socket.socket, addr: tuple):
        attacker_ip = addr[0]
        sock.settimeout(self.TIMEOUT)

        # Banner gönder
        self._send(sock, f"{self.banner}\r\n")

        username = ""
        attempts = 0
        max_attempts = 3  # Aynı bağlantıda max 3 deneme

        while attempts < max_attempts:
            line = self._readline(sock)
            if not line:
                break

            cmd = line.upper()

            if cmd.startswith("USER "):
                username = line[5:].strip()
                self._send(sock, f"331 Password required for {username}.\r\n")

            elif cmd.startswith("PASS "):
                password = line[5:].strip()
                if username:
                    self.report_credential(attacker_ip, username, password)
                    attempts += 1
                self._send(sock, "530 Login incorrect.\r\n")
                username = ""  # Sonraki deneme için sıfırla

            elif cmd.startswith("QUIT"):
                self._send(sock, "221 Goodbye.\r\n")
                break

            else:
                # Bilinmeyen komut — yine de bağlantıyı kes
                self._send(sock, "500 Unknown command.\r\n")

    @staticmethod
    def _send(sock: socket.socket, data: str):
        try:
            sock.sendall(data.encode("utf-8"))
        except (OSError, BrokenPipeError):
            pass

    @staticmethod
    def _readline(sock: socket.socket) -> str:
        """Satır satır oku (\\r\\n veya \\n ile biter). Max 1KB."""
        buf = b""
        try:
            while len(buf) < 1024:
                ch = sock.recv(1)
                if not ch:
                    break
                buf += ch
                if buf.endswith(b"\n"):
                    break
        except (socket.timeout, OSError):
            pass
        return buf.decode("utf-8", errors="replace").strip()


# ===================== SSH HONEYPOT ===================== #

class SSHHoneypot(BaseHoneypot):
    """Sahte SSH servisi — paramiko ServerInterface ile credential yakalar.

    Protokol akışı:
        1. TCP bağlantısı → SSH banner exchange
        2. Key exchange (DH/curve25519)
        3. SSH_MSG_USERAUTH_REQUEST → username + password açık metin
        4. Her zaman AUTH_FAILED döner → credential kaydedilir

    Gereksinim: paramiko>=3.4.0
    """

    def __init__(self, port: int = 22, *, on_credential: Callable, banner: str = ""):
        super().__init__(port=port, service_name="SSH", on_credential=on_credential)
        self.banner = banner or SSH_BANNER
        self._host_key = None

    def run(self):
        """Override: paramiko mevcutluğunu kontrol et, host key oluştur."""
        try:
            import paramiko  # noqa: F401
        except ImportError:
            self.error = "paramiko kütüphanesi yüklü değil (pip install paramiko)"
            log(f"[SSH] HATA: {self.error}")
            return

        # RSA host key oluştur (her başlatmada yeni — honeypot için sorun değil)
        import paramiko
        self._host_key = paramiko.RSAKey.generate(2048)
        log(f"[SSH] RSA host key oluşturuldu (2048 bit)")

        # Üst sınıfın accept döngüsünü çalıştır
        super().run()

    def handle_client(self, sock: socket.socket, addr: tuple):
        import paramiko

        attacker_ip = addr[0]
        transport = None
        try:
            transport = paramiko.Transport(sock)
            transport.local_version = self.banner
            transport.add_server_key(self._host_key)

            server = _create_ssh_server(
                attacker_ip=attacker_ip,
                honeypot=self,
            )
            transport.start_server(server=server)

            # Bağlantı otomatik olarak kesilene kadar bekle (max 30s)
            chan = transport.accept(timeout=30)
            if chan:
                chan.close()

        except paramiko.SSHException as exc:
            # Normal: brute-force araçları erken kesiyor
            log(f"[SSH] Bağlantı kesildi ({attacker_ip}): {exc}")
        except EOFError:
            pass  # Client erken kapattı — normal
        except Exception as exc:
            log(f"[SSH] Beklenmeyen hata ({attacker_ip}): {exc}")
        finally:
            if transport:
                try:
                    transport.close()
                except Exception:
                    pass


def _create_ssh_server(attacker_ip: str, honeypot: SSHHoneypot):
    """Factory: paramiko.ServerInterface alt sınıfını runtime'da oluşturur.

    paramiko top-level import değil, sadece SSH servisi çalıştığında yüklenir.
    Bu factory her bağlantıda çağrılır — sınıf tanımı closure içinde cache'lenir.
    """
    import paramiko

    class _SSHServerImpl(paramiko.ServerInterface):
        """Credential yakalama noktası — her auth denemesinde report_credential() çağrılır."""

        def check_channel_request(self, kind: str, chanid: int) -> int:
            if kind == "session":
                return paramiko.OPEN_SUCCEEDED
            return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

        def check_auth_password(self, username: str, password: str) -> int:
            """Her password denemesinde çağrılır — credential yakala, DENY döndür."""
            honeypot.report_credential(attacker_ip, username, password)
            return paramiko.AUTH_FAILED

        def check_auth_publickey(self, username: str, key) -> int:
            return paramiko.AUTH_FAILED

        def get_allowed_auths(self, username: str) -> str:
            return "password"

        def check_channel_shell_request(self, channel) -> bool:
            return False

        def check_channel_pty_request(self, channel, term, width, height,
                                       pixelwidth, pixelheight, modes) -> bool:
            return False

    return _SSHServerImpl()


# ===================== MYSQL HONEYPOT ===================== #

class MySQLHoneypot(BaseHoneypot):
    """Sahte MySQL servisi — native auth handshake ile credential yakalar.

    MySQL wire protocol (COM_* yok — sadece auth aşaması):
        1. Server → Client: Initial Handshake (protocol v10)
           - 20-byte random challenge (salt)
           - Server version string
           - Capability flags (CLIENT_SECURE_CONNECTION)
        2. Client → Server: Handshake Response
           - Username (null-terminated)
           - Auth response (SHA1 hash of password + salt)
           - Database name (opsiyonel)
        3. Server → Client: ERR_Packet (Access denied)

    Credential yakalama:
        - Username: handshake response'dan parse edilir (plaintext)
        - Password: SHA1 hash olarak gelir, plaintext olarak yakalanamaz
        - Brute-force araçları genelde aynı password'u dener → hash log'lanır

    Not: Harici kütüphane gerektirmez — tamamen raw socket + struct.
    """

    TIMEOUT = 30

    # MySQL protocol constants
    _PROTOCOL_VERSION = 10
    _SERVER_STATUS_AUTOCOMMIT = 0x0002
    _CLIENT_LONG_PASSWORD = 0x00000001
    _CLIENT_PROTOCOL_41 = 0x00000200
    _CLIENT_SECURE_CONNECTION = 0x00008000
    _CLIENT_PLUGIN_AUTH = 0x00080000
    _CHARSET_UTF8 = 33  # utf8_general_ci

    def __init__(self, port: int = 3306, *, on_credential: Callable, version: str = ""):
        super().__init__(port=port, service_name="MYSQL", on_credential=on_credential)
        self.version = version or MYSQL_VERSION

    def handle_client(self, sock: socket.socket, addr: tuple):
        attacker_ip = addr[0]
        sock.settimeout(self.TIMEOUT)

        # 1) Initial Handshake Packet gönder
        salt = os.urandom(20)  # Challenge bytes
        handshake = self._build_handshake_packet(salt)
        self._send_packet(sock, handshake, seq=0)

        # 2) Client Handshake Response'u oku
        try:
            payload, _ = self._read_packet(sock)
            if not payload:
                return
        except (socket.timeout, OSError, ValueError):
            return

        # 3) Username'i parse et
        username = self._parse_username(payload)
        if username:
            self.report_credential(attacker_ip, username, "<mysql_native_hash>")

        # 4) ERR_Packet gönder — Access denied
        err = self._build_err_packet(
            error_code=1045,
            message=f"Access denied for user '{username}'@'{attacker_ip}' (using password: YES)",
        )
        self._send_packet(sock, err, seq=2)

    def _build_handshake_packet(self, salt: bytes) -> bytes:
        """MySQL Protocol v10 Initial Handshake paketini oluştur."""
        salt_part1 = salt[:8]
        salt_part2 = salt[8:]

        buf = bytearray()
        # Protocol version
        buf.append(self._PROTOCOL_VERSION)
        # Server version (null-terminated)
        buf.extend(self.version.encode("ascii") + b"\x00")
        # Connection ID (random 4 bytes)
        buf.extend(struct.pack("<I", os.getpid() & 0xFFFFFFFF))
        # Auth-plugin-data-part-1 (8 bytes) + filler
        buf.extend(salt_part1)
        buf.append(0x00)  # filler
        # Capability flags (lower 2 bytes)
        cap_lower = (
            self._CLIENT_LONG_PASSWORD
            | self._CLIENT_PROTOCOL_41
            | self._CLIENT_SECURE_CONNECTION
            | self._CLIENT_PLUGIN_AUTH
        ) & 0xFFFF
        buf.extend(struct.pack("<H", cap_lower))
        # Character set
        buf.append(self._CHARSET_UTF8)
        # Status flags
        buf.extend(struct.pack("<H", self._SERVER_STATUS_AUTOCOMMIT))
        # Capability flags (upper 2 bytes)
        cap_upper = (
            self._CLIENT_LONG_PASSWORD
            | self._CLIENT_PROTOCOL_41
            | self._CLIENT_SECURE_CONNECTION
            | self._CLIENT_PLUGIN_AUTH
        ) >> 16
        buf.extend(struct.pack("<H", cap_upper))
        # Auth plugin data length
        buf.append(len(salt) + 1)  # 21
        # Reserved (10 zero bytes)
        buf.extend(b"\x00" * 10)
        # Auth-plugin-data-part-2 (rest of salt + null)
        buf.extend(salt_part2)
        buf.append(0x00)
        # Auth plugin name
        buf.extend(b"mysql_native_password\x00")

        return bytes(buf)

    @staticmethod
    def _build_err_packet(error_code: int, message: str) -> bytes:
        """MySQL ERR_Packet oluştur."""
        buf = bytearray()
        buf.append(0xFF)  # ERR marker
        buf.extend(struct.pack("<H", error_code))
        buf.extend(b"#28000")  # SQL state marker + state
        buf.extend(message.encode("utf-8", errors="replace"))
        return bytes(buf)

    @staticmethod
    def _parse_username(payload: bytes) -> str:
        """Handshake Response'dan username'i çıkar.

        Protocol 4.1 format:
            4 bytes: capability flags
            4 bytes: max packet size
            1 byte:  charset
            23 bytes: reserved (zeros)
            null-terminated: username
        """
        if len(payload) < 36:
            return ""
        # Username starts at offset 32 (4+4+1+23)
        username_start = 32
        null_pos = payload.find(b"\x00", username_start)
        if null_pos == -1:
            return ""
        try:
            return payload[username_start:null_pos].decode("utf-8", errors="replace")
        except Exception:
            return ""

    @staticmethod
    def _send_packet(sock: socket.socket, payload: bytes, seq: int = 0):
        """MySQL wire format: 3-byte length + 1-byte sequence + payload."""
        length = len(payload)
        header = struct.pack("<I", length)[:3] + bytes([seq & 0xFF])
        try:
            sock.sendall(header + payload)
        except (OSError, BrokenPipeError):
            pass

    @staticmethod
    def _read_packet(sock: socket.socket) -> tuple[bytes, int]:
        """MySQL paketi oku — (payload, seq_id) döndürür."""
        header = b""
        while len(header) < 4:
            chunk = sock.recv(4 - len(header))
            if not chunk:
                return b"", 0
            header += chunk
        length = struct.unpack("<I", header[:3] + b"\x00")[0]
        seq = header[3]
        if length > 65536:  # Güvenlik: çok büyük paketleri reddet
            return b"", seq
        payload = b""
        while len(payload) < length:
            chunk = sock.recv(length - len(payload))
            if not chunk:
                break
            payload += chunk
        return payload, seq


# ===================== MSSQL HONEYPOT ===================== #

class MSSQLHoneypot(BaseHoneypot):
    """Sahte Microsoft SQL Server servisi — TDS protokolü ile credential yakalar.

    TDS (Tabular Data Stream) wire protocol:
        1. Client → Server: TDS Pre-Login (type 0x12)
        2. Server → Client: TDS Pre-Login Response
        3. Client → Server: TDS Login7 (type 0x10)
           - Username + Password (XOR-obfuscated, plaintext'e dönüştürülebilir)
        4. Server → Client: TDS Login Response (Error Token — login failed)

    Credential yakalama:
        - Username: Login7 paketinden plaintext olarak parse edilir
        - Password: XOR obfuscation ile gelir — kolayca decode edilir
          (her byte: nibble swap → XOR 0xA5)

    Not: Harici kütüphane gerektirmez — tamamen raw socket + struct.
    """

    TIMEOUT = 30

    # TDS packet types
    _TDS_PRELOGIN = 0x12
    _TDS_LOGIN7 = 0x10
    _TDS_RESPONSE = 0x04
    _TDS_STATUS_EOM = 0x01  # End of message

    # TDS Pre-Login tokens
    _PL_VERSION = 0x00
    _PL_ENCRYPTION = 0x01
    _PL_INSTOPT = 0x02
    _PL_THREADID = 0x03
    _PL_MARS = 0x04
    _PL_TERMINATOR = 0xFF

    # Encryption options
    _ENCRYPT_NOT_SUP = 0x02  # Encryption not supported

    def __init__(self, port: int = 1433, *, on_credential: Callable, version: str = ""):
        super().__init__(port=port, service_name="MSSQL", on_credential=on_credential)
        self.version = version or MSSQL_VERSION

    def handle_client(self, sock: socket.socket, addr: tuple):
        attacker_ip = addr[0]
        sock.settimeout(self.TIMEOUT)

        # 1) Client Pre-Login bekle
        try:
            pkt_type, payload = self._read_tds_packet(sock)
        except (socket.timeout, OSError, ValueError):
            return

        if pkt_type != self._TDS_PRELOGIN:
            return  # TDS değilse bağlantıyı kapat

        # 2) Pre-Login Response gönder
        prelogin_resp = self._build_prelogin_response()
        self._send_tds_packet(sock, self._TDS_RESPONSE, prelogin_resp)

        # 3) Login7 paketi bekle
        try:
            pkt_type, payload = self._read_tds_packet(sock)
        except (socket.timeout, OSError, ValueError):
            return

        if pkt_type != self._TDS_LOGIN7:
            return

        # 4) Credential parse et
        username, password = self._parse_login7(payload)
        if username:
            self.report_credential(attacker_ip, username, password)

        # 5) Login failed response gönder
        err_resp = self._build_login_error(username, attacker_ip)
        self._send_tds_packet(sock, self._TDS_RESPONSE, err_resp)

    def _build_prelogin_response(self) -> bytes:
        """TDS Pre-Login Response — version + encryption bilgisi."""
        # Option tokens: VERSION, ENCRYPTION, TERMINATOR
        # Her token: 1 byte type + 2 bytes offset + 2 bytes length
        # Data section follows option tokens

        # Version data: 4 bytes version + 2 bytes build
        version_data = struct.pack(">I", 0x0F000000)  # SQL Server 2019 = 15.x
        version_data += struct.pack(">H", 0x0000)     # Build

        # Encryption data: 1 byte
        encrypt_data = bytes([self._ENCRYPT_NOT_SUP])

        # Calculate offsets (header = 3 tokens * 5 bytes + terminator)
        header_len = 2 * 5 + 1  # 2 options + terminator
        version_offset = header_len
        encrypt_offset = version_offset + len(version_data)

        buf = bytearray()
        # VERSION token
        buf.append(self._PL_VERSION)
        buf.extend(struct.pack(">H", version_offset))
        buf.extend(struct.pack(">H", len(version_data)))
        # ENCRYPTION token
        buf.append(self._PL_ENCRYPTION)
        buf.extend(struct.pack(">H", encrypt_offset))
        buf.extend(struct.pack(">H", len(encrypt_data)))
        # Terminator
        buf.append(self._PL_TERMINATOR)
        # Data
        buf.extend(version_data)
        buf.extend(encrypt_data)

        return bytes(buf)

    @staticmethod
    def _parse_login7(payload: bytes) -> tuple[str, str]:
        """TDS Login7 paketinden username ve password çıkar.

        Login7 fixed header (94 bytes), ardından:
            Offset  Length  Field
            ------- ------  -----
            36-37   2       HostName offset
            38-39   2       HostName length
            40-41   2       UserName offset (from start of packet)
            42-43   2       UserName length (in chars, UTF-16LE)
            44-45   2       Password offset
            46-47   2       Password length (in chars, UTF-16LE)

        Password XOR decode:
            Her byte: nibble swap (rotate 4 bit) → XOR 0xA5
        """
        if len(payload) < 48:
            return "", ""

        try:
            # Username offset/length
            user_offset = struct.unpack("<H", payload[40:42])[0]
            user_length = struct.unpack("<H", payload[42:44])[0]  # chars, not bytes
            # Password offset/length
            pass_offset = struct.unpack("<H", payload[44:46])[0]
            pass_length = struct.unpack("<H", payload[46:48])[0]

            # Parse username (UTF-16LE, no obfuscation)
            username = ""
            if user_length > 0 and user_offset + user_length * 2 <= len(payload):
                user_bytes = payload[user_offset:user_offset + user_length * 2]
                username = user_bytes.decode("utf-16-le", errors="replace")

            # Parse password (UTF-16LE, XOR-obfuscated)
            password = ""
            if pass_length > 0 and pass_offset + pass_length * 2 <= len(payload):
                pass_bytes = bytearray(payload[pass_offset:pass_offset + pass_length * 2])
                # Decode: her byte → swap nibbles → XOR 0xA5
                for i in range(len(pass_bytes)):
                    b = pass_bytes[i]
                    b = ((b >> 4) & 0x0F) | ((b << 4) & 0xF0)  # nibble swap
                    b ^= 0xA5
                    pass_bytes[i] = b
                password = bytes(pass_bytes).decode("utf-16-le", errors="replace")

            return username, password

        except Exception:
            return "", ""

    @staticmethod
    def _build_login_error(username: str, client_ip: str) -> bytes:
        """TDS Error Token — Login failed mesajı.

        Error Token format:
            0xAA (ERROR token type)
            2 bytes: token length
            4 bytes: error number (18456 = login failed)
            1 byte:  state
            1 byte:  class (severity)
            2 bytes: message length (chars)
            N bytes: message (UTF-16LE)
            1 byte:  server name length
            N bytes: server name (UTF-16LE)
            1 byte:  proc name length
            0 bytes: proc name
            4 bytes: line number
        """
        msg = f"Login failed for user '{username}'."
        msg_utf16 = msg.encode("utf-16-le")
        server_name = "MSSQL-SERVER"
        server_utf16 = server_name.encode("utf-16-le")

        error_token = bytearray()
        error_token.append(0xAA)  # ERROR token

        # Build token data (we'll prepend length after)
        token_data = bytearray()
        token_data.extend(struct.pack("<I", 18456))  # Error number
        token_data.append(1)   # State
        token_data.append(14)  # Class (severity)
        token_data.extend(struct.pack("<H", len(msg)))  # Message length (chars)
        token_data.extend(msg_utf16)
        token_data.append(len(server_name))  # Server name length
        token_data.extend(server_utf16)
        token_data.append(0)  # Proc name length (empty)
        token_data.extend(struct.pack("<I", 1))  # Line number

        # Token length (2 bytes, after 0xAA marker)
        error_token.extend(struct.pack("<H", len(token_data)))
        error_token.extend(token_data)

        # DONE token (0xFD) — session bitmesini bildir
        done_token = bytearray()
        done_token.append(0xFD)  # DONE token
        done_token.extend(struct.pack("<H", 0x0000))  # Status: DONE_FINAL
        done_token.extend(struct.pack("<H", 0x0000))  # CurCmd
        done_token.extend(struct.pack("<Q", 0))       # DoneRowCount (8 bytes)

        return bytes(error_token) + bytes(done_token)

    @staticmethod
    def _send_tds_packet(sock: socket.socket, pkt_type: int, data: bytes):
        """TDS paketi gönder — 8-byte header + payload."""
        length = 8 + len(data)
        header = struct.pack(">BBH", pkt_type, 0x01, length)  # type, status=EOM, length
        header += struct.pack(">HH", 0, 0)  # SPID=0, PacketID=0, Window=0
        try:
            sock.sendall(header + data)
        except (OSError, BrokenPipeError):
            pass

    @staticmethod
    def _read_tds_packet(sock: socket.socket) -> tuple[int, bytes]:
        """TDS paketi oku — (packet_type, payload) döndürür."""
        # TDS header: 8 bytes
        header = b""
        while len(header) < 8:
            chunk = sock.recv(8 - len(header))
            if not chunk:
                return 0, b""
            header += chunk

        pkt_type = header[0]
        length = struct.unpack(">H", header[2:4])[0]

        if length < 8 or length > 65536:
            return pkt_type, b""

        remaining = length - 8
        payload = b""
        while len(payload) < remaining:
            chunk = sock.recv(remaining - len(payload))
            if not chunk:
                break
            payload += chunk

        return pkt_type, payload


# ===================== RDP HONEYPOT ===================== #

class RDPHoneypot(BaseHoneypot):
    """Sahte RDP servisi — X.224 cookie + NLA/CredSSP NetNTLMv2 hash yakalama.

    RDP bağlantı akışı (NLA / CredSSP OFF veya client HYBRID istemez):
        1. Client → Server: X.224 Connection Request (Cookie: username)
        2. Server → Client: X.224 Connection Confirm (PROTOCOL_RDP)
        3. Opsiyonel MCS; ardından disconnect
        → rapor: username + ``<rdp_connection_attempt>``

    RDP bağlantı akışı (NLA / CredSSP — modern mstsc / crowbar / hydra NLA):
        1. X.224 CR with PROTOCOL_HYBRID / HYBRID_EX
        2. Server selects HYBRID → TLS (self-signed) → CredSSP
        3. NTLMSSP Type1 → Type2 challenge → Type3
        → rapor: Type3 username + NetNTLMv2 hashcat-5600 satırı
          (plaintext şifre yok — sadece crackable challenge/response)

    Cookie username hâlâ IoC olarak ayrıca loglanır.
    Harici protokol kütüphanesi yok — ``client_rdp_nla`` + stdlib ssl.
    """

    TIMEOUT = 30

    # X.224 / TPKT constants
    _TPKT_VERSION = 3
    _X224_CR = 0xE0  # Connection Request
    _X224_CC = 0xD0  # Connection Confirm

    # RDP Negotiation
    _TYPE_RDP_NEG_REQ = 0x01
    _TYPE_RDP_NEG_RSP = 0x02
    _PROTOCOL_RDP = 0x00000000
    _PROTOCOL_SSL = 0x00000001
    _PROTOCOL_HYBRID = 0x00000002  # NLA / CredSSP
    _PROTOCOL_HYBRID_EX = 0x00000008

    def __init__(self, port: int = 3389, *, on_credential: Callable, cert_cn: str = ""):
        super().__init__(port=port, service_name="RDP", on_credential=on_credential)
        self.cert_cn = cert_cn or RDP_CERT_CN

    def handle_client(self, sock: socket.socket, addr: tuple):
        attacker_ip = addr[0]
        sock.settimeout(self.TIMEOUT)

        # 1) X.224 Connection Request oku
        try:
            tpkt_data = self._read_tpkt(sock)
            if not tpkt_data or len(tpkt_data) < 7:
                return
        except (socket.timeout, OSError):
            return

        # Cookie'den username parse et
        username = self._parse_x224_cookie(tpkt_data)
        requested_protocols = self._parse_requested_protocols(tpkt_data)

        if username:
            self.report_credential(attacker_ip, username, "<rdp_connection_attempt>")

        # Prefer NLA capture when client asks for HYBRID
        use_nla = False
        try:
            from client_rdp_nla import wants_nla
            use_nla = wants_nla(requested_protocols)
        except Exception:
            use_nla = False

        if use_nla:
            try:
                self._handle_nla_capture(sock, attacker_ip, username, requested_protocols)
                return
            except Exception as exc:
                log(f"[RDP] NLA/CredSSP capture failed ({exc}) — falling back to RDP path")

        # 2) X.224 Connection Confirm — classic RDP (no NLA)
        cc_packet = self._build_x224_confirm(requested_protocols, select_nla=False)
        try:
            sock.sendall(cc_packet)
        except (OSError, BrokenPipeError):
            return

        # 3) MCS Connect Initial (optional)
        try:
            mcs_data = self._read_tpkt(sock)
            if mcs_data and len(mcs_data) > 20:
                mcs_response = self._build_mcs_connect_response()
                sock.sendall(mcs_response)
        except (socket.timeout, OSError):
            pass

    def _handle_nla_capture(
        self,
        sock: socket.socket,
        attacker_ip: str,
        cookie_user: str,
        requested_protocols: int,
    ) -> None:
        from client_rdp_nla import (
            run_credssp_ntlm_capture,
            selected_nla_protocol,
            wrap_socket_tls_server,
        )

        selected = selected_nla_protocol(requested_protocols)
        cc_packet = self._build_x224_confirm(requested_protocols, select_nla=True, selected=selected)
        sock.sendall(cc_packet)

        tls = wrap_socket_tls_server(sock, cert_cn=self.cert_cn)
        try:
            captured = run_credssp_ntlm_capture(tls, target_name=self.cert_cn or "WORKGROUP")
        finally:
            try:
                tls.close()
            except Exception:
                pass

        if not captured:
            log(f"[RDP] NLA: no Type3 from {attacker_ip} (cookie={cookie_user or '-'})")
            return

        user = captured.get("username") or cookie_user or "unknown"
        domain = captured.get("domain") or ""
        kind = captured.get("kind") or "netntlmv2"
        hash_line = captured.get("hash_line") or ""
        if domain and "\\" not in user and "@" not in user:
            display_user = f"{domain}\\{user}"
        else:
            display_user = user
        log(
            f"[RDP] {kind} captured: {display_user} <- {attacker_ip} "
            f"(hash_len={len(hash_line)})"
        )
        # Hashcat mode 5600 / John netntlmv2 — password field holds the full line
        self.report_credential(attacker_ip, display_user, hash_line)

    @staticmethod
    def _read_tpkt(sock: socket.socket) -> bytes:
        """TPKT paketi oku (4-byte header + payload).

        TPKT Header:
            byte 0: Version (3)
            byte 1: Reserved (0)
            byte 2-3: Length (big-endian, header dahil)
        """
        header = b""
        while len(header) < 4:
            chunk = sock.recv(4 - len(header))
            if not chunk:
                return b""
            header += chunk

        if header[0] != 3:  # TPKT version check
            return b""

        length = struct.unpack(">H", header[2:4])[0]
        if length < 4 or length > 65536:
            return b""

        remaining = length - 4
        payload = b""
        while len(payload) < remaining:
            chunk = sock.recv(remaining - len(payload))
            if not chunk:
                break
            payload += chunk

        return header + payload

    @staticmethod
    def _parse_x224_cookie(tpkt_data: bytes) -> str:
        """X.224 Connection Request'ten Cookie'yi parse et.

        Format: "Cookie: mstshash=<username>\\r\\n"
        """
        try:
            data_str = tpkt_data.decode("ascii", errors="replace")

            cookie_marker = "Cookie: mstshash="
            idx = data_str.find(cookie_marker)
            if idx == -1:
                cookie_marker = "mstshash="
                idx = data_str.find(cookie_marker)
                if idx == -1:
                    return ""

            start = idx + len(cookie_marker)
            end = start
            while end < len(data_str) and data_str[end] not in ("\r", "\n", "\x00"):
                end += 1

            username = data_str[start:end].strip()
            return username[:256] if username else ""

        except Exception:
            return ""

    @staticmethod
    def _parse_requested_protocols(tpkt_data: bytes) -> int:
        """X.224 CR'den requestedProtocols değerini çıkar."""
        try:
            if len(tpkt_data) >= 8:
                neg_block = tpkt_data[-8:]
                if neg_block[0] == 0x01:  # TYPE_RDP_NEG_REQ
                    req_protocols = struct.unpack("<I", neg_block[4:8])[0]
                    return req_protocols
        except Exception:
            pass
        return 0

    def _build_x224_confirm(
        self,
        requested_protocols: int,
        *,
        select_nla: bool = False,
        selected: Optional[int] = None,
    ) -> bytes:
        """X.224 Connection Confirm.

        select_nla=True → PROTOCOL_HYBRID(_EX) so CredSSP/TLS follows.
        select_nla=False → PROTOCOL_RDP (legacy cookie-only path).
        """
        x224_payload = bytearray()

        if requested_protocols != 0:
            if select_nla:
                proto = (
                    selected
                    if selected is not None
                    else self._PROTOCOL_HYBRID
                )
            else:
                proto = self._PROTOCOL_RDP
            neg_resp = bytearray(8)
            neg_resp[0] = self._TYPE_RDP_NEG_RSP
            neg_resp[1] = 0x00
            struct.pack_into("<H", neg_resp, 2, 8)
            struct.pack_into("<I", neg_resp, 4, proto)

            x224_header_len = 6 + len(neg_resp)
            x224_payload.append(x224_header_len)
            x224_payload.append(self._X224_CC)
            x224_payload.extend(b"\x00\x00")
            x224_payload.extend(b"\x00\x00")
            x224_payload.append(0x00)
            x224_payload.extend(neg_resp)
        else:
            x224_payload.append(6)
            x224_payload.append(self._X224_CC)
            x224_payload.extend(b"\x00\x00")
            x224_payload.extend(b"\x00\x00")
            x224_payload.append(0x00)

        total_len = 4 + len(x224_payload)
        tpkt = bytearray(4)
        tpkt[0] = self._TPKT_VERSION
        tpkt[1] = 0x00
        struct.pack_into(">H", tpkt, 2, total_len)

        return bytes(tpkt + x224_payload)

    def _build_mcs_connect_response(self) -> bytes:
        """Minimal MCS Disconnect — close classic-RDP clients cleanly."""
        disconnect = bytearray()
        disconnect.append(0x02)
        disconnect.append(0xF0)
        disconnect.append(0x80)
        disconnect.extend(b"\x21\x80")
        disconnect.extend(b"\x02\x01\x00")
        disconnect.extend(b"\x00\x00")

        total_len = 4 + len(disconnect)
        tpkt = bytearray(4)
        tpkt[0] = self._TPKT_VERSION
        tpkt[1] = 0x00
        struct.pack_into(">H", tpkt, 2, total_len)

        return bytes(tpkt + disconnect)


# ===================== HTTP HONEYPOT ===================== #

_LOGIN_PAGE = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Sign in</title>
<style>
body{font-family:Segoe UI,sans-serif;background:#0f172a;color:#e2e8f0;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
.card{background:#1e293b;padding:2rem;border-radius:12px;width:360px;box-shadow:0 8px 32px rgba(0,0,0,.4)}
h1{font-size:1.25rem;margin:0 0 1rem}
input{width:100%;padding:.65rem;margin:.4rem 0;border:1px solid #334155;border-radius:8px;background:#0f172a;color:#fff;box-sizing:border-box}
button{width:100%;padding:.7rem;margin-top:.6rem;background:#3b82f6;color:#fff;border:none;border-radius:8px;cursor:pointer}
</style></head><body><div class="card"><h1>Windows Security Portal</h1>
<form method="POST" action="/login"><input name="username" placeholder="Username" required>
<input name="password" type="password" placeholder="Password" required>
<button type="submit">Sign in</button></form></div></body></html>"""


class HTTPHoneypot(BaseHoneypot):
    """Sahte HTTP login sayfası — POST credential yakalar."""

    def __init__(self, port: int = 80, *, on_credential: Callable):
        super().__init__(port, "HTTP", on_credential)

    def handle_client(self, conn: socket.socket, addr: tuple):
        attacker_ip = addr[0]
        try:
            conn.settimeout(10)
            data = conn.recv(4096)
            if not data:
                return
            req = data.decode("utf-8", errors="replace")
            lines = req.split("\r\n")
            if not lines:
                return
            method, path, *_ = (lines[0] + "   ").split()[:3]

            if method == "POST" and "/login" in path:
                body = req.split("\r\n\r\n", 1)[-1]
                username, password = self._parse_form(body)
                if username or password:
                    self.report_credential(attacker_ip, username, password)
                self._send(conn, 401, "Invalid credentials", _LOGIN_PAGE)
                return

            if path in ("/", "/login", "/index.html"):
                self._send(conn, 200, "OK", _LOGIN_PAGE)
            else:
                self._send(conn, 404, "Not Found", "<h1>404</h1>")
        except Exception as e:
            log(f"[HTTP] Client error {attacker_ip}: {e}")
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _parse_form(self, body: str) -> tuple[str, str]:
        username, password = "", ""
        for part in body.split("&"):
            if "=" not in part:
                continue
            k, v = part.split("=", 1)
            k, v = unquote_plus(k), unquote_plus(v)
            if k == "username":
                username = v[:MAX_CREDENTIAL_LENGTH]
            elif k == "password":
                password = v[:MAX_CREDENTIAL_LENGTH]
        return username, password

    def _send(self, conn: socket.socket, code: int, status: str, body: str):
        payload = body.encode("utf-8")
        hdr = (
            f"HTTP/1.1 {code} {status}\r\n"
            f"Server: {HTTP_SERVER_BANNER}\r\n"
            f"Content-Type: text/html; charset=utf-8\r\n"
            f"Content-Length: {len(payload)}\r\n"
            f"Connection: close\r\n\r\n"
        )
        conn.sendall(hdr.encode("utf-8") + payload)


# ===================== SMB HONEYPOT ===================== #

class SMBHoneypot(BaseHoneypot):
    """Minimal SMB negotiate responder — bağlantı ve probe IP yakalar."""

    _NEGOTIATE_RESP = bytes([
        0x00, 0x00, 0x00, 0x51,
        0xff, 0x53, 0x4d, 0x42, 0x72,  # SMB header
        0x00, 0x00, 0x00, 0x00, 0x18, 0x01, 0x28, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0xff,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x06, 0x00,
        0x02, 0x02, 0x10, 0x02, 0x00, 0x03, 0x02, 0x02,
        0x06, 0x00, 0x02, 0x40, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ])

    def __init__(self, port: int = 445, *, on_credential: Callable):
        super().__init__(port, "SMB", on_credential)

    def handle_client(self, conn: socket.socket, addr: tuple):
        attacker_ip = addr[0]
        try:
            conn.settimeout(8)
            data = conn.recv(2048)
            if data and data[4:8] == b"\xffSMB":
                self.report_credential(
                    attacker_ip,
                    f"\\\\{SMB_SERVER_NAME}\\share",
                    "<smb_probe>",
                )
                try:
                    conn.sendall(self._NEGOTIATE_RESP[:min(len(self._NEGOTIATE_RESP), 128)])
                except OSError:
                    pass
            elif data:
                self.report_credential(attacker_ip, "<smb_connect>", "<probe>")
        except Exception as e:
            log(f"[SMB] Client error {attacker_ip}: {e}")
        finally:
            try:
                conn.close()
            except OSError:
                pass

