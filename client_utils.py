"""
Asteria Client - Utilities Module
Yardımcı fonksiyonlar ve araçlar modülü
"""

import os
import sys
import json
import hashlib
import socket
import time
import struct
import tempfile
import ctypes
import ctypes.wintypes as wintypes
import subprocess
from typing import Dict, Any, Optional

def get_resource_path(relative_path: str) -> str:
    """Get absolute path to resource, works for dev and for PyInstaller.

    Priority order:
    1. Exe directory (NSIS installer copies updated files here)
    2. PyInstaller temp (_MEIPASS bundle)
    3. Current working directory (dev mode)
    """
    # 1) Exe (installer) dizini — NSIS güncellenen dosyayı buraya koyar
    exe_dir = os.path.dirname(os.path.abspath(sys.executable))
    exe_path = os.path.join(exe_dir, relative_path)
    if os.path.exists(exe_path) and hasattr(sys, '_MEIPASS'):
        return exe_path

    # 2) PyInstaller bundle (_MEIPASS)
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    full_path = os.path.join(base_path, relative_path)

    # 3) Fallback: current working directory
    if not os.path.exists(full_path):
        fallback_path = os.path.join(os.path.abspath("."), relative_path)
        if os.path.exists(fallback_path):
            return fallback_path

    return full_path

class SystemUtils:
    """Sistem yardımcıları"""
    
    @staticmethod
    def run_cmd(cmd, timeout: int = 20, suppress_rc_log: bool = False, log_func=None):
        """Terminal komutu çalıştır - Unicode safe"""
        if log_func is None:
            log_func = print
            
        try:
            if isinstance(cmd, str):
                cmd = cmd.split()
            
            creationflags = 0x08000000 if os.name == 'nt' else 0
            completed = subprocess.run(
                cmd, shell=False, capture_output=True, text=True,
                creationflags=creationflags, timeout=timeout,
                encoding='utf-8', errors='replace'  # Unicode safe encoding
            )
            
            if not suppress_rc_log:
                log_func(f"Command: {' '.join(cmd)} -> RC: {completed.returncode}")
                
            return completed
        except subprocess.TimeoutExpired:
            log_func(f"Command timeout: {' '.join(cmd)}")
            return None
        except UnicodeDecodeError as e:
            log_func(f"Command encoding error: {e}")
            # Fallback: try with different encoding
            try:
                creationflags = 0x08000000 if os.name == 'nt' else 0
                completed = subprocess.run(
                    cmd, shell=False, capture_output=True, text=True,
                    creationflags=creationflags, timeout=timeout,
                    encoding='cp1254', errors='replace'  # Windows Turkish encoding
                )
                return completed
            except Exception as fallback_error:
                log_func(f"Command fallback failed: {fallback_error}")
                return None
        except Exception as e:
            log_func(f"Command error: {e}")
            return None

def load_i18n(lang_file: str = "client_lang.json", language: str = "tr") -> dict:
    """Load all language data from JSON file.

    İki kaynaktan okur ve merge eder (installer güncellemelerini garantile):
    1. Exe (installer) dizinindeki dosya
    2. PyInstaller bundle (_MEIPASS) içindeki dosya
    Exe dizinindeki dosya daha güncel olabilir, öncelik ona verilir.
    """
    all_languages: dict = {"tr": {}, "en": {}}

    def _load_from(path: str) -> dict:
        try:
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    return json.load(f)
        except Exception as e:
            print(f"[LANG] Error loading {path}: {e}")
        return {}

    # 1) PyInstaller bundle'dan yükle (base)
    try:
        meipass = sys._MEIPASS
        bundle_path = os.path.join(meipass, lang_file)
        base = _load_from(bundle_path)
        if base:
            for lang_code in base:
                if isinstance(base[lang_code], dict):
                    all_languages.setdefault(lang_code, {}).update(base[lang_code])
            print(f"[LANG] Base loaded from bundle: {bundle_path}")
    except AttributeError:
        pass  # Not running from PyInstaller

    # 2) Exe (installer) dizininden yükle (override) — en güncel
    exe_dir = os.path.dirname(os.path.abspath(sys.executable))
    exe_path = os.path.join(exe_dir, lang_file)
    exe_data = _load_from(exe_path)
    if exe_data:
        for lang_code in exe_data:
            if isinstance(exe_data[lang_code], dict):
                all_languages.setdefault(lang_code, {}).update(exe_data[lang_code])
        print(f"[LANG] Override loaded from exe dir: {exe_path}")

    # 3) Fallback: resolved path (dev mode / cwd)
    if not exe_data and not any(all_languages.get(lc) for lc in all_languages):
        resolved = get_resource_path(lang_file)
        fallback = _load_from(resolved)
        if fallback:
            all_languages = fallback
            print(f"[LANG] Fallback loaded from: {resolved}")

    print(f"[LANG] Available languages: {list(all_languages.keys())}")
    tr_count = len(all_languages.get("tr", {}))
    en_count = len(all_languages.get("en", {}))
    print(f"[LANG] Key counts — TR: {tr_count}, EN: {en_count}")
    return all_languages

# ===================== TOKEN STORE ===================== #
class TokenStore:
    """Windows DPAPI ile token saklama sınıfı"""
    CRYPTPROTECT_UI_FORBIDDEN = 0x1
    CRYPTPROTECT_LOCAL_MACHINE = 0x4

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]

    @staticmethod
    def _to_blob(b: bytes):
        buf = ctypes.create_string_buffer(b)
        blob = TokenStore.DATA_BLOB(len(b), ctypes.cast(buf, ctypes.POINTER(ctypes.c_byte)))
        return blob, buf  # keep buf referenced

    @staticmethod
    def _from_blob(blob) -> bytes:
        size = int(blob.cbData)
        ptr = ctypes.cast(blob.pbData, ctypes.POINTER(ctypes.c_byte))
        return ctypes.string_at(ptr, size)

    @staticmethod
    def _crypt_protect(data: bytes) -> bytes:
        crypt32  = ctypes.windll.crypt32
        kernel32 = ctypes.windll.kernel32
        flags = TokenStore.CRYPTPROTECT_UI_FORBIDDEN | TokenStore.CRYPTPROTECT_LOCAL_MACHINE
        payload = struct.pack("I", len(data)) + data
        in_blob, in_buf = TokenStore._to_blob(payload)
        out_blob = TokenStore.DATA_BLOB()
        if not crypt32.CryptProtectData(ctypes.byref(in_blob), None, None, None, None, flags, ctypes.byref(out_blob)):
            raise RuntimeError("CryptProtectData failed")
        try:
            out = TokenStore._from_blob(out_blob)
        finally:
            try:
                kernel32.LocalFree(out_blob.pbData)
            except Exception:
                pass
        return out

    @staticmethod
    def _crypt_unprotect(data: bytes) -> bytes:
        crypt32  = ctypes.windll.crypt32
        kernel32 = ctypes.windll.kernel32
        flags = TokenStore.CRYPTPROTECT_UI_FORBIDDEN | TokenStore.CRYPTPROTECT_LOCAL_MACHINE
        in_blob, in_buf = TokenStore._to_blob(data)
        out_blob = TokenStore.DATA_BLOB()
        if not crypt32.CryptUnprotectData(ctypes.byref(in_blob), None, None, None, None, flags, ctypes.byref(out_blob)):
            raise RuntimeError("CryptUnprotectData failed")
        try:
            out = TokenStore._from_blob(out_blob)
        finally:
            try:
                kernel32.LocalFree(out_blob.pbData)
            except Exception:
                pass
        return out[4:]  # strip prepended length

    @staticmethod
    def save(
        token: str,
        token_file_new: str,
        overwrite: bool = False,
        fingerprint: str = "",
    ):
        """Persist token with DPAPI. By default refuses to replace a different existing token.

        CHP2 embeds a hardware fingerprint so VM clones that copy token.dat but
        have different NIC MACs fail the bind check and must re-enroll.
        """
        try:
            token = (token or "").strip()
            if not token:
                return
            parent = os.path.dirname(token_file_new)
            if parent:
                os.makedirs(parent, exist_ok=True)
            if os.path.isfile(token_file_new) and not overwrite:
                existing = TokenStore.load(token_file_new)
                if existing is None:
                    # File present but unreadable — never clobber (ghost identity risk)
                    print(
                        f"token save refused: unreadable existing identity "
                        f"(file={token_file_new})"
                    )
                    return
                if existing and existing != token:
                    # Immutable identity: never clobber a different durable token
                    print(
                        f"token save refused: existing identity differs "
                        f"(file={token_file_new})"
                    )
                    return
                if existing and existing == token and not fingerprint:
                    return  # already stored
            data = token.encode("utf-8")
            h = hashlib.sha256(data).hexdigest().encode("ascii")
            fp = (fingerprint or "").strip().encode("ascii", "ignore")
            if fp:
                payload = b"CHP2|" + fp + b"|" + h + b"|" + data
            else:
                payload = b"CHP1|" + h + b"|" + data
            enc = TokenStore._crypt_protect(payload)
            # Atomic replace to avoid partial writes during kill/update
            fd, tmp_path = tempfile.mkstemp(
                prefix="token_", suffix=".tmp", dir=parent or None
            )
            try:
                with os.fdopen(fd, "wb") as f:
                    f.write(enc)
                    f.flush()
                    os.fsync(f.fileno())
                os.replace(tmp_path, token_file_new)
            except Exception:
                try:
                    if os.path.isfile(tmp_path):
                        os.remove(tmp_path)
                except OSError:
                    pass
                raise
        except Exception as e:
            print(f"token save error: {e}")

    @staticmethod
    def load_meta(token_file_new: str) -> tuple:
        """Return (token, bound_fingerprint_or_None). Fingerprint mismatch → (None, fp)."""
        try:
            if not os.path.exists(token_file_new):
                return None, None
            enc = open(token_file_new, "rb").read()
            if not enc:
                return None, None
            dec = TokenStore._crypt_unprotect(enc)
            if dec.startswith(b"CHP2|"):
                parts = dec.split(b"|", 3)
                if len(parts) != 4:
                    return None, None
                _, fp_b, h, data = parts
                if hashlib.sha256(data).hexdigest().encode("ascii") != h:
                    return None, None
                tok = data.decode("utf-8", "ignore").strip()
                fp = fp_b.decode("ascii", "ignore").strip() or None
                return (tok or None), fp
            if dec.startswith(b"CHP1|"):
                _, h, data = dec.split(b"|", 2)
                if hashlib.sha256(data).hexdigest().encode("ascii") != h:
                    return None, None
                tok = data.decode("utf-8", "ignore").strip()
                return (tok or None), None
            return None, None
        except Exception as e:
            print(f"token load error: {e}")
            return None, None

    @staticmethod
    def load(token_file_new: str) -> Optional[str]:
        tok, _fp = TokenStore.load_meta(token_file_new)
        return tok

    @staticmethod
    def migrate_from_plain(
        token_file_old: str,
        token_file_new: str,
        only_if_missing: bool = True,
    ):
        try:
            if only_if_missing and TokenStore.load(token_file_new):
                # Still remove plaintext leftover if present
                if os.path.exists(token_file_old):
                    try:
                        os.remove(token_file_old)
                    except Exception:
                        pass
                return
            if os.path.exists(token_file_old):
                token = open(token_file_old, "r", encoding="utf-8").read().strip()
                if token:
                    TokenStore.save(token, token_file_new, overwrite=False)
                try:
                    os.remove(token_file_old)
                except Exception:
                    pass
        except Exception as e:
            print(f"token migration error: {e}")

# ===================== SERVICE CONTROLLER ===================== #
class ServiceController:
    """Windows servis kontrolü sınıfı"""
    
    @staticmethod
    def _sc_query_code(svc_name: str) -> int:
        """
        Returns numeric state code independent of locale.
        1 STOPPED, 2 START_PENDING, 3 STOP_PENDING, 4 RUNNING ...
        """
        try:
            creationflags = 0x08000000 if os.name == 'nt' else 0
            completed = subprocess.run(['sc', 'queryex', svc_name],
                                       shell=False, capture_output=True, text=True,
                                       creationflags=creationflags, timeout=8)
            txt = (completed.stdout or "")
            for line in txt.splitlines():
                if 'STATE' in line.upper():
                    after = line.split(':', 1)[1].strip()
                    num = after.split()[0]
                    return int(num)
        except Exception as e:
            print(f"sc query error: {e}")
        return -1

    @staticmethod
    def _wait_state_code(svc_name: str, desired_code: int, timeout: int = 40) -> bool:
        t0 = time.time()
        while time.time() - t0 < timeout:
            code = ServiceController._sc_query_code(svc_name)
            if code == desired_code:
                return True
            # START/STOP pending ise biraz sabret
            if code in (2,3):
                time.sleep(1.2)
            else:
                time.sleep(0.6)
        return False

    @staticmethod
    def stop(svc_name: str, timeout: int = 40, log_func=None) -> bool:
        if log_func is None:
            log_func = print
            
        code = ServiceController._sc_query_code(svc_name)
        if code == 1:
            return True

        # 1) sc stop dene (kısa tekrarlar)
        for _ in range(2):
            SystemUtils.run_cmd(['sc', 'stop', svc_name], timeout=10, log_func=log_func)
            if ServiceController._wait_state_code(svc_name, 1, 12):
                return True
            time.sleep(2)

        # 2) PowerShell Stop-Service -Force
        SystemUtils.run_cmd(['powershell', '-NoProfile', '-Command',
                 f'Stop-Service -Name "{svc_name}" -Force -ErrorAction SilentlyContinue'], timeout=20, log_func=log_func)
        if ServiceController._wait_state_code(svc_name, 1, 15):
            return True

        log_func(f"Service {svc_name} did not stop in time")
        return False

    @staticmethod
    def start(svc_name: str, timeout: int = 40, log_func=None) -> bool:
        if log_func is None:
            log_func = print
            
        code = ServiceController._sc_query_code(svc_name)
        if code == 4:
            return True

        SystemUtils.run_cmd(['sc', 'start', svc_name], timeout=10, log_func=log_func)
        if ServiceController._wait_state_code(svc_name, 4, timeout):
            return True

        SystemUtils.run_cmd(['powershell', '-NoProfile', '-Command',
                 f'Start-Service -Name "{svc_name}" -ErrorAction SilentlyContinue'], timeout=20, log_func=log_func)
        return ServiceController._wait_state_code(svc_name, 4, 20)

    @staticmethod
    def restart(svc_name: str, log_func=None) -> bool:
        if log_func is None:
            log_func = print
            
        SystemUtils.run_cmd(['powershell', '-NoProfile', '-Command',
                 f'Restart-Service -Name "{svc_name}" -Force -ErrorAction SilentlyContinue'], timeout=25, log_func=log_func)
        if ServiceController._wait_state_code(svc_name, 4, 20):
            return True
        # fallback
        return ServiceController.stop(svc_name, 20, log_func) and ServiceController.start(svc_name, 20, log_func)

    @staticmethod
    def _check_port_in_use(port: int) -> bool:
        """Belirtilen portun kullanımda olup olmadığını kontrol eder"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                return s.connect_ex(('127.0.0.1', int(port))) == 0
        except Exception:
            return False

    @staticmethod
    def get_rdp_port(log_func=None, *, probe_listen: bool = False) -> Optional[int]:
        """Read RDP port from registry. Netstat probe is optional (slow — skip at startup)."""
        if log_func is None:
            log_func = print
            
        if os.name != 'nt':
            return None
        try:
            import winreg as _wr
            key = _wr.OpenKey(_wr.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp")
            val, typ = _wr.QueryValueEx(key, "PortNumber")
            _wr.CloseKey(key)
            if isinstance(val, int):
                if probe_listen:
                    log_func(f"Regedit RDP Port değeri: {val}")
                    svc_status = ServiceController._sc_query_code("TermService")
                    log_func(f"Terminal Servis durumu: {svc_status}")
                    try:
                        netstat = SystemUtils.run_cmd(["netstat", "-an"], timeout=5, log_func=log_func)
                        if netstat and netstat.stdout:
                            for line in netstat.stdout.splitlines():
                                if f":{val}" in line:
                                    log_func(f"RDP Port {val} durumu: {line.strip()}")
                    except Exception as e:
                        log_func(f"RDP Port {val} netstat kontrolü hatası: {e}")
                return val
        except Exception as e:
            log_func(f"get_rdp_port error: {e}")
        return None

# ===================== HELPER FUNCTIONS ===================== #
def firewall_allow_exists_tcp_port(port: int, log_func=None) -> bool:
    """Checks if an inbound allow firewall rule exists for given TCP local port (Windows only)."""
    if log_func is None:
        log_func = print
        
    if os.name != 'nt':
        return False
    # Primary method: Use netsh (faster and more reliable than PowerShell)
    try:
        res = SystemUtils.run_cmd([
            'netsh', 'advfirewall', 'firewall', 'show', 'rule', 
            'name=all', 'dir=in', 'type=allow'
        ], timeout=10, suppress_rc_log=True, log_func=log_func)
        
        if res and hasattr(res, 'returncode') and res.returncode == 0:
            txt = str(res.stdout or "").lower()
            port_str = str(int(port))
            
            # Look for patterns indicating the port is allowed
            patterns = [
                f'localport: {port_str}',
                f'localport:{port_str}',
                f'localport = {port_str}',
                f'local port: {port_str}'
            ]
            
            for pattern in patterns:
                if pattern in txt:
                    return True
                    
            # Also check if 'any' is specified for local port
            if 'localport: any' in txt or 'localport:any' in txt:
                return True
                
    except Exception as e:
        if log_func:
            log_func(f"Firewall check error: {e}")
    
    # Fallback: Quick PowerShell check (simplified)
    try:
        ps = f"if (Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow | Get-NetFirewallPortFilter | Where-Object LocalPort -eq {port}) {{ Write-Output 'FOUND' }}"
        
        res = SystemUtils.run_cmd([
            'powershell', '-NoProfile', '-Command', ps
        ], timeout=5, suppress_rc_log=True, log_func=log_func)
        
        if res and res.returncode == 0:
            stdout = str(getattr(res, 'stdout', ''))
            if 'FOUND' in stdout:
                return True
                
    except Exception:
        pass
    return False

def ensure_firewall_allow_for_port(port: int, rule_name: str = None, log_func=None):
    """Ensure an inbound allow rule exists for TCP port; add if missing (Windows only)."""
    if log_func is None:
        log_func = print
        
    if os.name != 'nt':
        return
    
    if firewall_allow_exists_tcp_port(port, log_func):
        return
    
    if rule_name is None:
        rule_name = f"Allow_TCP_{port}"
    
    try:
        SystemUtils.run_cmd(['netsh','advfirewall','firewall','add','rule',
                           f'name={rule_name}','dir=in','action=allow','protocol=TCP',
                           f'localport={port}'], timeout=10, log_func=log_func)
        log_func(f"Firewall rule added for port {port}")
    except Exception as e:
        log_func(f"Failed to add firewall rule for port {port}: {e}")

def is_process_running_windows(pid: int) -> bool:
    """Windows'ta process'in çalışıp çalışmadığını kontrol et"""
    try:
        import psutil
        return psutil.pid_exists(pid)
    except ImportError:
        try:
            # tasklist fallback
            result = subprocess.run(['tasklist', '/FI', f'PID eq {pid}'], 
                                  capture_output=True, text=True, timeout=5,
                                  creationflags=subprocess.CREATE_NO_WINDOW)
            return str(pid) in result.stdout
        except:
            return False
    except:
        return False

def write_watchdog_token(value: str, token_file: str):
    """Watchdog token dosyasına yaz"""
    try:
        with open(token_file, "w", encoding="utf-8") as f:
            f.write(value.strip())
    except Exception as e:
        print(f"write_watchdog_token error: {e}")

def read_watchdog_token(token_file: str) -> str:
    """Watchdog token dosyasından oku"""
    try:
        if os.path.exists(token_file):
            with open(token_file, "r", encoding="utf-8") as f:
                return f.read().strip()
    except Exception as e:
        print(f"read_watchdog_token error: {e}")
    return ""

def start_watchdog_if_needed(watchdog_token_file: str, log_func=None):
    """Watchdog process'ini gerekirse başlat"""
    if log_func is None:
        log_func = print
        
    try:
        token = read_watchdog_token(watchdog_token_file)
        if not token:
            return
            
        try:
            pid = int(token)
            if is_process_running_windows(pid):
                log_func(f"Watchdog already running with PID {pid}")
                return
        except ValueError:
            pass
        
        # Watchdog yoksa başlat
        current_exe = sys.executable
        script_path = os.path.abspath(__file__).replace('client_utils.py', 'client.py')
        
        if os.path.exists(script_path):
            import subprocess
            proc = subprocess.Popen([current_exe, script_path, "--watchdog"],
                                  creationflags=0x08000000 if os.name == 'nt' else 0)
            write_watchdog_token(str(proc.pid), watchdog_token_file)
            log_func(f"Started watchdog process with PID {proc.pid}")
    except Exception as e:
        log_func(f"start_watchdog_if_needed error: {e}")

def is_admin() -> bool:
    """Admin yetkileri kontrolü"""
    if os.name != 'nt':
        return os.geteuid() == 0
    
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

def watchdog_main(parent_pid: int, log_func=None):
    """Watchdog ana fonksiyonu - process izleme ve yeniden başlatma"""
    if log_func is None:
        log_func = print
        
    attempts = 0
    max_attempts = 5
    
    # Check for installer stop flags at multiple locations
    def check_stop_flag():
        """Check if installer has requested watchdog to stop"""
        stop_locations = [
            os.path.join(os.environ.get('TEMP', ''), 'honeypot_watchdog_token.txt'),
            os.path.join(os.environ.get('APPDATA', ''), 'YesNext', 'CloudHoneypot', 'watchdog_token.txt'),
            os.path.join(os.environ.get('APPDATA', ''), 'Asteria', 'watchdog.token'),
            os.path.join(os.environ.get('ProgramData', 'C:\\ProgramData'), 'YesNext', 'CloudHoneypot', 'watchdog_stop.flag'),
        ]
        for loc in stop_locations:
            try:
                if os.path.exists(loc):
                    with open(loc, 'r') as f:
                        content = f.read().strip().lower()
                        if content == 'stop':
                            log_func(f"[watchdog] Stop flag found at {loc}, exiting")
                            return True
            except:
                pass
        return False
    
    while attempts < max_attempts:
        time.sleep(5)
        
        # Check stop flags (installer places these)
        if check_stop_flag():
            return
        
        # Watchdog token kontrolü (eski yöntem)
        token = read_watchdog_token("")
        if token.lower() == 'stop':
            return
            
        # Parent process kontrolü
        alive = is_process_running_windows(int(parent_pid))
        if not alive:
            # Before restarting, check stop flags again
            if check_stop_flag():
                return
            
            log_func(f"[watchdog] Parent process {parent_pid} not found, attempting restart")
            attempts += 1
            
            try:
                # Yeni instance başlat
                if getattr(sys, 'frozen', False):
                    subprocess.Popen([sys.executable], shell=False,
                                   creationflags=subprocess.CREATE_NO_WINDOW)
                else:
                    subprocess.Popen([sys.executable, os.path.abspath(sys.argv[0])], shell=False,
                                   creationflags=subprocess.CREATE_NO_WINDOW)
                time.sleep(10)  # Başlamasını bekle
            except Exception as e:
                log_func(f"[watchdog] Restart error: {e}")
        else:
            attempts = 0  # Parent yaşıyorsa attempt'ları sıfırla
            
        time.sleep(10)  # Genel bekleme
    
    log_func(f"[watchdog] Maximum attempts ({max_attempts}) reached, exiting")

def install_excepthook(log_func=None):
    """Exception hook kurulumu (main + worker threads)."""
    import threading

    if log_func is None:
        log_func = print
        
    def _hook(exc_type, exc, tb):
        try:
            import traceback
            log_func("UNHANDLED EXCEPTION:\n" + "".join(traceback.format_exception(exc_type, exc, tb)))
        except Exception as e:
            log_func(f"Exception hook error: {e}")
    
    try:
        sys.excepthook = _hook
    except Exception:
        pass

    if hasattr(threading, "excepthook"):
        def _thread_hook(args):  # type: ignore[no-untyped-def]
            try:
                if getattr(args, "exc_type", None) is SystemExit:
                    return
                import traceback
                name = getattr(getattr(args, "thread", None), "name", "?")
                log_func(
                    "UNHANDLED THREAD EXCEPTION name=%s:\n%s"
                    % (
                        name,
                        "".join(
                            traceback.format_exception(
                                args.exc_type, args.exc_value, args.exc_traceback
                            )
                        ),
                    )
                )
            except Exception as e:
                try:
                    log_func(f"Thread exception hook error: {e}")
                except Exception:
                    pass

        try:
            threading.excepthook = _thread_hook  # type: ignore[assignment]
        except Exception:
            pass

# ===== CONFIG MANAGEMENT =====

# Single config file next to executable (no AppData)
def get_config_file_path() -> str:
    """Get config file path - always next to executable"""
    if hasattr(sys, 'frozen'):
        # Build versiyonunda: executable yanındaki config
        exe_dir = os.path.dirname(sys.executable)
        return os.path.join(exe_dir, "client_config.json")
    else:
        # Development versiyonunda: script yanındaki config
        script_dir = os.path.dirname(os.path.abspath(__file__))
        return os.path.join(script_dir, "client_config.json")

CONFIG_FILE = get_config_file_path()

# Default application configuration — single source of truth
DEFAULT_CONFIG: dict = {
    "application": {
        "name": "Asteria Client",
        "version": "0.0.0",
        "author": "Asteria"
    },
    "language": {
        "selected": "en",
        "selected_by_user": False,
        "available_languages": ["tr", "en"],
        "default": "en"
    },
    "ui": {
        "window_width": 900,
        "window_height": 700,
        "theme": "dark",
        "show_loading_screen": True,
        "loading_timeout": 30
    },
    "admin": {
        "require_admin_privileges": True,
        "auto_restart_as_admin": False,
        "show_admin_dialog": True
    },
    "logging": {
        "level": "INFO",
        "max_file_size_mb": 10,
        "backup_count": 5,
        "debug_mode": False
    },
    "api": {
        "base_url": "https://asteria.run/api",
        "legacy_base_url": "https://honeypot.yesnext.com.tr/api",
        "timeout": 30,
        "retry_count": 3
    },
    "services": {
        "auto_start": False,
        "rdp_port": 43389,
        "honeypots": [
            {"port": 3389, "service": "RDP", "enabled": True},
            {"port": 1433, "service": "MSSQL", "enabled": False},
            {"port": 3306, "service": "MySQL", "enabled": False},
            {"port": 21, "service": "FTP", "enabled": False},
            {"port": 22, "service": "SSH", "enabled": False}
        ]
    },
    "updates": {
        "auto_check": True,
        "check_interval_hours": 24,
        "show_notifications": True
    },
    "advanced": {
        "startup_delay": 0,
        "minimize_to_tray": True,
        "auto_start_with_windows": False,
        "single_instance": True
    }
}

def load_config() -> dict:
    """Load application configuration - single file system"""
    try:
        # Single config file system - no AppData
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                config = json.load(f)
                # Merge with defaults to ensure all keys exist
                return merge_configs(DEFAULT_CONFIG, config)
        else:
            # Create default config file if not exists
            save_config(DEFAULT_CONFIG)
            return DEFAULT_CONFIG.copy()
            
    except Exception as e:
        print(f"[CONFIG] Error loading config: {e}")
        return DEFAULT_CONFIG.copy()

def save_config(config: dict) -> bool:
    """Save application configuration to single config file"""
    try:
        # No directory creation needed - config is next to executable
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
        print(f"[CONFIG] Configuration saved to: {CONFIG_FILE}")
        return True
    except Exception as e:
        print(f"[CONFIG] Error saving config: {e}")
        return False

def merge_configs(default: dict, user: dict) -> dict:
    """Recursively merge user config with default config"""
    result = default.copy()
    for key, value in user.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = merge_configs(result[key], value)
        else:
            result[key] = value
    return result

def get_config_value(key_path: str, default=None):
    """Get a configuration value using dot notation (e.g., 'language.selected')"""
    config = load_config()
    keys = key_path.split('.')
    value = config
    
    try:
        for key in keys:
            value = value[key]
        return value
    except (KeyError, TypeError):
        return default

# Alias for backward compatibility
def get_from_config(key_path: str, fallback):
    """Helper to get values from config with fallback - alias for get_config_value"""
    return get_config_value(key_path, fallback)

def get_port_table():
    """Get service/port table from configuration file
    
    Returns:
        List[Tuple[str, str]]: Port table in format [(port, service), ...]
    """
    try:
        config = load_config()
        honeypots = config.get("services", {}).get("honeypots", [])
        
        port_table = []
        for svc_cfg in honeypots:
            port = str(svc_cfg.get("port", ""))
            service = str(svc_cfg.get("service", ""))
            
            if port and service:
                port_table.append((port, service))
        
        print(f"[CONFIG] Service table loaded from config: {len(port_table)} entries")
        return port_table
        
    except Exception as e:
        print(f"[CONFIG] Error loading service table: {e}")
        # Fallback to default table
        return [
            ("3389", "-", "RDP"),
            ("1433", "-", "MSSQL"),
            ("3306", "-", "MySQL"),
            ("21", "-", "FTP"),
            ("22", "-", "SSH"),
        ]

def get_rdp_secure_port():
    """Get RDP secure port from configuration
    
    Returns:
        int: RDP secure port number
    """
    try:
        return get_config_value("services.rdp_port", 43389)
    except Exception:
        return 43389

def set_config_value(key_path: str, value) -> bool:
    """Set a configuration value using dot notation"""
    config = load_config()
    keys = key_path.split('.')
    
    # Navigate to the parent of the target key
    current = config
    for key in keys[:-1]:
        if key not in current:
            current[key] = {}
        current = current[key]
    
    # Set the final key
    current[keys[-1]] = value
    
    return save_config(config)

def update_language_config(language: str, selected_by_user: bool = True) -> bool:
    """Update language configuration (exe config + ProgramData so upgrades keep user choice)."""
    config = load_config()
    if "language" not in config or not isinstance(config["language"], dict):
        config["language"] = {}
    config["language"]["selected"] = language
    config["language"]["selected_by_user"] = selected_by_user
    ok = save_config(config)
    try:
        prefs_dir = os.path.join(
            os.environ.get("ProgramData", r"C:\ProgramData"),
            "Asteria",
        )
        os.makedirs(prefs_dir, exist_ok=True)
        prefs_path = os.path.join(prefs_dir, "language_pref.json")
        with open(prefs_path, "w", encoding="utf-8") as fh:
            json.dump(
                {"selected": language, "selected_by_user": bool(selected_by_user)},
                fh,
                ensure_ascii=False,
            )
    except OSError:
        pass
    return ok


def detect_windows_ui_language() -> str:
    """Map Windows UI language to supported app language (tr|en)."""
    try:
        lang_id = int(ctypes.windll.kernel32.GetUserDefaultUILanguage())
        # LANGID primary language: Turkish=0x1F (0x041F)
        if (lang_id & 0xFF) == 0x1F:
            return "tr"
    except Exception:
        pass
    try:
        import locale
        loc = (locale.getdefaultlocale() or (None,))[0] or ""
        if loc.lower().startswith("tr"):
            return "tr"
    except Exception:
        pass
    return "en"


def _load_language_pref() -> Optional[dict]:
    try:
        prefs_path = os.path.join(
            os.environ.get("ProgramData", r"C:\ProgramData"),
            "Asteria",
            "language_pref.json",
        )
        if os.path.isfile(prefs_path):
            with open(prefs_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, dict):
                return data
    except Exception:
        pass
    return None


def resolve_app_language() -> str:
    """First run: follow Windows UI language. After user picks a language, keep it across upgrades."""
    try:
        available = ["tr", "en"]
        prefs = _load_language_pref()
        if prefs and prefs.get("selected_by_user") and prefs.get("selected") in available:
            return prefs["selected"]

        config = load_config()
        lang_cfg = config.get("language") or {}
        available = lang_cfg.get("available_languages") or available
        if lang_cfg.get("selected_by_user") and lang_cfg.get("selected") in available:
            # Migrate into ProgramData so next installer overwrite keeps choice
            update_language_config(lang_cfg["selected"], selected_by_user=True)
            return lang_cfg["selected"]

        detected = detect_windows_ui_language()
        if detected not in available:
            detected = "en"
        update_language_config(detected, selected_by_user=False)
        return detected
    except Exception:
        return detect_windows_ui_language()


def _programdata_client_dir() -> str:
    """%ProgramData%\\Asteria — durable client state (brand SoT ≥4.9.41)."""
    try:
        from client_paths import programdata_client_dir

        return programdata_client_dir()
    except Exception:
        base = os.path.join(
            os.environ.get("ProgramData", r"C:\ProgramData"),
            "Asteria",
        )
        try:
            os.makedirs(base, exist_ok=True)
        except OSError:
            pass
        return base


def _account_link_pref_path() -> str:
    return os.path.join(_programdata_client_dir(), "account_link.json")


def load_account_link_pref() -> dict:
    """Local cache of last known Account link status (API is source of truth when online)."""
    try:
        path = _account_link_pref_path()
        if os.path.isfile(path):
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, dict):
                return data
    except Exception:
        pass
    return {}


def is_account_linked() -> bool:
    """True when API (or local cache) says this client is linked to an Asteria Account."""
    try:
        data = load_account_link_pref()
        return bool(data.get("linked"))
    except Exception:
        return False


def get_linked_account_email() -> str:
    """Cached account email from last successful API status (may be masked)."""
    try:
        data = load_account_link_pref()
        email = data.get("email") or data.get("email_masked") or ""
        return str(email) if email else ""
    except Exception:
        return ""


def set_account_linked(
    linked: bool = True,
    *,
    source: str = "user",
    email: str = "",
    email_masked: str = "",
    account_id=None,
    raw: Optional[dict] = None,
) -> None:
    """Persist Account↔Client link state (ProgramData cache)."""
    try:
        path = _account_link_pref_path()
        prev = load_account_link_pref()
        payload = {
            "linked": bool(linked),
            "source": source,
            "updated_at": time.time(),
            "email": email or prev.get("email") or "",
            "email_masked": email_masked or prev.get("email_masked") or "",
            "account_id": account_id if account_id is not None else prev.get("account_id"),
        }
        if not linked:
            payload["email"] = email or ""
            payload["email_masked"] = email_masked or ""
            payload["account_id"] = account_id
        if isinstance(raw, dict):
            # Keep a small non-secret snapshot for UI (no tokens/hashes)
            payload["server_name"] = raw.get("server_name") or prev.get("server_name")
            payload["client_id"] = raw.get("client_id") or prev.get("client_id")
            payload["linked_at"] = raw.get("linked_at") or prev.get("linked_at")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)
    except OSError:
        pass


def parse_account_link_payload(resp: Optional[dict]) -> Optional[bool]:
    """Extract account_linked from API JSON.

    Returns True/False when the payload explicitly carries link state;
    None when the response has no account-link fields (legacy / unrelated).
    """
    if not isinstance(resp, dict):
        return None
    linked = None
    for key in (
        "account_linked", "linked", "has_account", "is_linked",
        "linked_to_account", "has_account_membership",
    ):
        if key in resp:
            linked = bool(resp.get(key))
            break
    acct = resp.get("account")
    if linked is None and isinstance(acct, dict):
        if acct.get("linked") is False:
            linked = False
        elif acct.get("email") or acct.get("email_masked") or acct.get("id"):
            linked = True
    if linked is None and "accounts" in resp and isinstance(resp.get("accounts"), list):
        linked = len(resp["accounts"]) > 0
    return linked


def apply_account_link_from_payload(resp: Optional[dict], *, source: str = "api") -> Optional[bool]:
    """Update local cache from API payload. Returns linked bool or None if unknown."""
    linked = parse_account_link_payload(resp)
    if linked is None:
        return None
    email = ""
    email_masked = ""
    account_id = None
    acct = resp.get("account") if isinstance(resp, dict) else None
    if isinstance(acct, dict):
        email = str(acct.get("email") or "")
        email_masked = str(acct.get("email_masked") or "")
        account_id = acct.get("id")
    if not email:
        email = str((resp or {}).get("email") or "")
    if not email_masked:
        email_masked = str((resp or {}).get("email_masked") or "")
    set_account_linked(
        linked,
        source=source,
        email=email,
        email_masked=email_masked,
        account_id=account_id,
        raw=resp if isinstance(resp, dict) else None,
    )
    return linked


def refresh_account_link_status(token: str = "", api_client=None) -> Optional[bool]:
    """Ask cloud whether this client token is linked to an Account.

    Source of truth when API answers with account_linked (or equivalent).
    Returns True/False when cloud answers; None when endpoint missing / unknown.
    """
    tok = (token or "").strip()
    if not tok:
        return None
    try:
        resp = None
        if api_client is not None and hasattr(api_client, "get_account_status"):
            resp = api_client.get_account_status(tok)
        elif api_client is not None and hasattr(api_client, "api_request"):
            # Dedicated endpoint first
            resp = api_client.api_request(
                "GET", "agent/account-status",
                params={"token": tok},
                token=tok,
                timeout=8,
                verbose_logging=False,
            )
            # Fallback: client_status may embed account_linked (P1)
            if resp is None or parse_account_link_payload(resp) is None:
                cs = api_client.api_request(
                    "GET", "client_status",
                    params={"token": tok},
                    token=tok,
                    timeout=8,
                    verbose_logging=False,
                )
                if parse_account_link_payload(cs) is not None:
                    resp = cs
        else:
            import requests
            from client_constants import API_URL
            from client_security_utils import resolve_tls_verify
            base = API_URL.rstrip("/")
            for path in ("agent/account-status", "client_status"):
                try:
                    r = requests.get(
                        f"{base}/{path}",
                        params={"token": tok},
                        timeout=8,
                        verify=resolve_tls_verify(),
                    )
                    if r.status_code == 404:
                        # Route missing vs client missing — try next path on bare Not Found
                        try:
                            detail = (r.json() or {}).get("detail", "")
                        except Exception:
                            detail = ""
                        if path == "agent/account-status" and str(detail).lower() in (
                            "not found", "", "none"
                        ):
                            continue
                        if path == "agent/account-status":
                            continue
                        break
                    if 200 <= r.status_code < 300:
                        data = r.json()
                        if path == "client_status" and parse_account_link_payload(data) is None:
                            continue
                        resp = data
                        break
                except Exception:
                    continue
        return apply_account_link_from_payload(resp, source="api")
    except Exception:
        return None


# ===== CONFIG SYSTEM FINALIZED =====
# All settings are now managed through client_config.json
# No legacy migration needed - pure config-driven architecture


# ===================== INSTALLER-BASED UPDATE SYSTEM ===================== #

class InstallerUpdateManager:
    """Yeni installer tabanlı güncelleme sistemi"""
    
    def __init__(self, github_owner: str, github_repo: str, log_func=None):
        self.github_owner = github_owner
        self.github_repo = github_repo
        self.log = log_func if log_func else print
        self.base_url = f"https://api.github.com/repos/{github_owner}/{github_repo}/releases/latest"
        
    def get_current_version(self) -> str:
        """Mevcut sürümü al — constants'dan (config dosyası eski kalabilir)"""
        try:
            from client_constants import VERSION
            return VERSION
        except ImportError:
            try:
                config = load_config()
                return config.get("application", {}).get("version", "1.0.0")
            except:
                return "1.0.0"
    
    def check_for_updates(self) -> Dict[str, Any]:
        """Güncelleme kontrolü yap"""
        try:
            self.log("[UPDATE] Güncelleme kontrol ediliyor...")
            
            # GitHub API'den son sürüm bilgisini al
            import requests
            from client_security_utils import resolve_tls_verify, ensure_ca_bundle
            try:
                ensure_ca_bundle()
            except Exception:
                pass
            response = requests.get(self.base_url, timeout=15, verify=resolve_tls_verify())
            if response.status_code != 200:
                return {"error": "API erişim hatası", "current_version": self.get_current_version()}
            
            data = response.json()
            latest_tag = data.get("tag_name") or data.get("name", "")
            latest_version = latest_tag.lstrip('v')
            current_version = self.get_current_version().lstrip('v')
            
            self.log(f"[UPDATE] Mevcut sürüm: {current_version}")
            self.log(f"[UPDATE] Son sürüm: {latest_version}")
            
            # Sürüm karşılaştırması
            if self._compare_versions(latest_version, current_version) <= 0:
                return {
                    "has_update": False,
                    "current_version": current_version,
                    "latest_version": latest_version,
                    "message": "Güncel sürüm kullanılıyor"
                }
            
            # Installer asset'ini bul
            assets = data.get("assets", [])
            installer_asset = None
            
            for asset in assets:
                name = asset.get("name", "").lower()
                if name.endswith("-installer.exe") or name.endswith("installer.exe"):
                    installer_asset = asset
                    break
            
            if not installer_asset:
                return {"error": "Installer dosyası bulunamadı", "current_version": current_version}
            
            # Latest version'u saklayalım download için
            self._latest_version = latest_version
            
            return {
                "has_update": True,
                "current_version": current_version,
                "latest_version": latest_version,
                "release_notes": data.get("body", ""),
                "installer_url": installer_asset.get("browser_download_url"),
                "installer_size": installer_asset.get("size", 0),
                "installer_name": installer_asset.get("name"),
                "published_at": data.get("published_at")
            }
            
        except Exception as e:
            self.log(f"[UPDATE] Kontrol hatası: {e}")
            msg = str(e)
            low = msg.lower()
            if "cacert" in low or "tls ca" in low or "certificate bundle" in low:
                msg = "TLS sertifika dosyasi bulunamadi (gecici PyInstaller yolu). Uygulamayi yeniden baslatin."
            return {"error": msg, "current_version": self.get_current_version()}
    
    def _compare_versions(self, version1: str, version2: str) -> int:
        """Sürüm karşılaştırması (-1: v1<v2, 0: v1=v2, 1: v1>v2)"""
        try:
            def normalize(v):
                return [int(x) for x in v.replace('v', '').split('.')]
            
            v1_parts = normalize(version1)
            v2_parts = normalize(version2)
            
            # Uzunlukları eşitle
            max_len = max(len(v1_parts), len(v2_parts))
            v1_parts.extend([0] * (max_len - len(v1_parts)))
            v2_parts.extend([0] * (max_len - len(v2_parts)))
            
            if v1_parts < v2_parts:
                return -1
            elif v1_parts > v2_parts:
                return 1
            else:
                return 0
        except:
            return 0
    
    def download_installer(self, download_url: str, progress_callback=None) -> Optional[str]:
        """Download installer until complete (size/stream verified), then return path."""
        try:
            version = "unknown"
            try:
                if hasattr(self, "_latest_version") and self._latest_version:
                    version = self._latest_version
                else:
                    import re
                    version_match = re.search(r"v?(\d+\.\d+\.\d+)", download_url or "")
                    if version_match:
                        version = version_match.group(1)
            except Exception:
                pass

            downloads_dir = _update_helper_staging_dir()
            installer_filename = f"asteria-client-installer-v{version}.exe"
            installer_path = os.path.join(downloads_dir, installer_filename)
            try:
                os.makedirs(downloads_dir, exist_ok=True)
            except OSError:
                pass

            self.log(f"[UPDATE] İndirme yeri: {installer_path}")

            expected = str(getattr(self, "_expected_sha256", "") or "").strip()
            if not expected:
                try:
                    expected = str(get_from_config("updates.expected_sha256", "") or "").strip()
                except Exception:
                    expected = ""
            expected_size = None
            try:
                expected_size = int(getattr(self, "_expected_size", 0) or 0) or None
            except Exception:
                expected_size = None

            from client_updater import download_installer_complete
            ok, detail = download_installer_complete(
                download_url,
                installer_path,
                expected_size=expected_size,
                expected_sha256=expected,
                progress_callback=progress_callback,
                max_attempts=5,
                log_func=self.log,
            )
            if not ok:
                self.log(f"[UPDATE] İndirme tamamlanamadı: {detail}")
                return None
            self.log(f"[UPDATE] Installer başarıyla indirildi: {installer_path}")
            return installer_path
        except Exception as e:
            self.log(f"[UPDATE] İndirme hatası: {e}")
            return None
    

    
# ===================== UPDATE UI HELPERS ===================== #

def onboarding_flag_path() -> str:
    base = os.path.join(
        os.environ.get("ProgramData", r"C:\ProgramData"),
        "Asteria",
    )
    try:
        os.makedirs(base, exist_ok=True)
    except OSError:
        pass
    return os.path.join(base, "force_gui_onboarding.flag")


def clear_force_gui_onboarding() -> None:
    try:
        path = onboarding_flag_path()
        if os.path.isfile(path):
            os.remove(path)
    except OSError:
        pass


def should_force_gui_visible(has_token: bool = False) -> bool:
    """True only while this machine has no durable agent token yet.

    Once a token exists, onboarding is done — allow minimize-to-tray and clear
    any stale force_gui_onboarding.flag (otherwise close-to-tray stays blocked forever).
    """
    if has_token:
        clear_force_gui_onboarding()
        return False
    try:
        if os.path.isfile(onboarding_flag_path()):
            return True
    except OSError:
        pass
    # No token yet → keep window visible for first registration
    return True


def _update_lock_path() -> str:
    """Machine-wide lock — SYSTEM SilentUpdater and user GUI must share the same file.

    Previous APPDATA path failed: interactive download locked user profile, while
    Asteria-SilentUpdater (S-1-5-18) looked at SystemProfile AppData → race kill.
    """
    base = os.path.join(
        os.environ.get("ProgramData", r"C:\ProgramData"),
        "Asteria",
    )
    try:
        os.makedirs(base, exist_ok=True)
    except OSError:
        pass
    return os.path.join(base, "update_in_progress.lock")


def acquire_update_lock(reason: str = "interactive") -> bool:
    """Mark that an update download/install is in progress (all sessions)."""
    try:
        path = _update_lock_path()
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(f"{reason}\n{os.getpid()}\n{time.time()}\n")
        return True
    except OSError:
        return False


def touch_update_lock() -> None:
    """Heartbeat during long downloads so lock is never treated as stale."""
    try:
        path = _update_lock_path()
        if os.path.isfile(path):
            os.utime(path, None)
            return
        acquire_update_lock("heartbeat")
    except OSError:
        pass


def _finalize_cleared_update_lock(reason: str = "orphan_update_lock") -> None:
    """After deleting a stale lock: resume tasks, clear stand-down, mark UI failed.

    Critical: a bare ``os.remove(lock)`` used to leave Background/SilentUpdater
    disabled and the GUI with no banner — hosts stayed motor-down indefinitely.

    If the motor is (or becomes) healthy after the clear, do **not** leave a
    scary failed banner — that was the 4.9.54→newer orphan_lock UX brick.
    """
    try:
        from client_resilience import clear_stand_down
        clear_stand_down()
    except Exception:
        pass
    try:
        resume_competing_updaters()
    except Exception:
        pass

    motor_ok = False
    try:
        from client_daemon_ipc import is_motor_healthy
        motor_ok = bool(is_motor_healthy())
    except Exception:
        motor_ok = False
    if not motor_ok:
        try:
            from client_daemon_ipc import ensure_daemon_running
            motor_ok = bool(ensure_daemon_running(log_func=lambda _m: None, wait_sec=12.0))
        except Exception:
            motor_ok = False

    try:
        from client_update_ui import set_update_ui_status, clear_update_ui_status, _read_raw
        prev = _read_raw() or {}
        phase = str(prev.get("phase") or "").strip().lower()
        if motor_ok:
            # Lock heal succeeded and motor answers — drop obsolete failure strip.
            if phase in ("", "accepted", "downloading", "staging", "installing", "failed"):
                clear_update_ui_status()
            return
        # Don't overwrite a fresh "done"; only active/empty → failed.
        if phase in ("", "accepted", "downloading", "staging", "installing"):
            set_update_ui_status(
                "failed",
                from_version=str(prev.get("from_version") or ""),
                to_version=str(prev.get("to_version") or ""),
                detail=reason,
                error=reason,
            )
    except Exception:
        pass


def is_update_in_progress(max_age_sec: float = 7200.0) -> bool:
    """True if update lock exists and holder still looks alive."""
    try:
        path = _update_lock_path()
        if not os.path.isfile(path):
            # Migrate: also honour legacy per-user lock if present
            legacy = os.path.join(
                os.environ.get("APPDATA", os.path.expanduser("~")),
                "Asteria", "update_in_progress.lock",
            )
            if os.path.isfile(legacy):
                path = legacy
            else:
                return False
        age = time.time() - os.path.getmtime(path)
        lock_pid = None
        lines: list = []
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                lines = fh.read().splitlines()
            if len(lines) >= 2:
                lock_pid = int(str(lines[1]).strip())
        except Exception:
            lock_pid = None
            lines = []

        pid_alive = False
        if lock_pid and lock_pid > 0:
            try:
                import ctypes
                SYNCHRONIZE = 0x00100000
                h = ctypes.windll.kernel32.OpenProcess(SYNCHRONIZE, False, int(lock_pid))
                if h:
                    ctypes.windll.kernel32.CloseHandle(h)
                    pid_alive = True
            except Exception:
                pid_alive = False

        # Dead holder → stale immediately after a short grace (helper often never
        # starts; 90s+ blocked every SilentUpdater tick and looked like "hours stuck").
        phase = str(lines[0]).strip().lower() if lines else ""

        def _clear_stale(why: str) -> bool:
            try:
                os.remove(path)
            except OSError:
                pass
            _finalize_cleared_update_lock(why)
            return False

        if lock_pid and not pid_alive and age > 15:
            return _clear_stale("orphan_lock_dead_pid")

        # Absolute ceiling (downloads can be long — touch_update_lock refreshes mtime)
        if age > max_age_sec:
            return _clear_stale("update_lock_max_age")

        # "installing" with no live holder — helper died or never spawned
        if phase.startswith("install") and not pid_alive and age > 30:
            return _clear_stale("orphan_install_lock")

        # installing lock but holder still "alive" while no helper ever ran (orphaned
        # after failed schtasks) — hard cap 20 min so hosts recover within the 1h SLA
        if phase.startswith("install") and age > 1200:
            return _clear_stale("install_lock_hard_cap")

        return True
    except OSError:
        return False


def heal_update_machinery(log_func=None) -> None:
    """Clear stale locks and re-enable update/watchdog tasks after failed updates."""
    _log = log_func or (lambda m: None)
    try:
        # Central stuck/brick recovery (lock + banner + stand-down + motor).
        try:
            from client_update_recovery import maybe_auto_recover_stuck_update
            if maybe_auto_recover_stuck_update(log_func=_log):
                _log("[UPDATE] Auto-recovered stuck update handoff")
        except Exception as e:
            _log(f"[UPDATE] update recovery probe failed: {e}")

        # Force-evaluate stale lock (dead PID / short grace) — also resumes tasks
        if not is_update_in_progress(max_age_sec=1200.0):
            pass
        path = _update_lock_path()
        if os.path.isfile(path):
            age = time.time() - os.path.getmtime(path)
            lock_pid = None
            phase = ""
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                    lines = fh.read().splitlines()
                if lines:
                    phase = str(lines[0]).strip().lower()
                if len(lines) >= 2:
                    lock_pid = int(str(lines[1]).strip())
            except Exception:
                pass
            pid_alive = False
            if lock_pid and lock_pid > 0:
                try:
                    SYNCHRONIZE = 0x00100000
                    h = ctypes.windll.kernel32.OpenProcess(SYNCHRONIZE, False, int(lock_pid))
                    if h:
                        ctypes.windll.kernel32.CloseHandle(h)
                        pid_alive = True
                except Exception:
                    pid_alive = False
            # Aggressively clear orphan installing locks (helper never logged)
            if (not pid_alive and age > 15) or age > 1200 or (
                phase.startswith("install") and age > 120 and not pid_alive
            ):
                try:
                    os.remove(path)
                    _finalize_cleared_update_lock("heal_stale_lock")
                    _log("[UPDATE] Cleared stale update lock")
                except OSError:
                    pass
            # Launcher-only storm: PS helper parse-dead — clear lock so next tick can retry
            try:
                from client_update_hardening import detect_launcher_only_storm
                log_path = os.path.join(
                    os.environ.get("ProgramData", r"C:\ProgramData"),
                    "Asteria", "update-install.log",
                )
                if detect_launcher_only_storm(log_path) and phase.startswith("install"):
                    try:
                        os.remove(path)
                        _finalize_cleared_update_lock("helper_parse_fail_storm")
                        _log("[UPDATE] Cleared lock after launcher-only storm (helper parse fail)")
                    except OSError:
                        pass
                    # Force re-stage good/emergency helper for next attempt
                    try:
                        stage_update_install_helper(allow_emergency=True)
                    except Exception:
                        pass
            except Exception:
                pass
    except Exception:
        pass
    try:
        resume_competing_updaters()
        _log("[UPDATE] Re-enabled updater/watchdog scheduled tasks")
    except Exception as e:
        _log(f"[UPDATE] Task resume failed: {e}")


def _is_our_installer_filename(name: str) -> bool:
    n = (name or "").strip().lower()
    if not n.endswith(".exe"):
        return False
    try:
        from client_constants import INSTALLER_FILE_PREFIXES
        prefixes = INSTALLER_FILE_PREFIXES
    except Exception:
        prefixes = ("asteria-client-installer", "cloud-client-installer")
    return any(n.startswith(p) for p in prefixes)


def _is_our_update_launcher_filename(name: str) -> bool:
    n = (name or "").strip().lower()
    return bool(
        n.startswith("run-update-")
        or n.startswith("run-nsis-")
        or n.startswith("force-restart-")
    ) and n.endswith(".ps1")


def cleanup_update_artifacts(
    *,
    keep_installer: Optional[str] = None,
    remove_installers: bool = True,
    remove_launchers: bool = True,
    include_downloads: bool = True,
    only_if_not_updating: bool = False,
) -> Dict[str, int]:
    """Prune staged update EXEs / launcher scripts that bloat ProgramData.

    Keeps ``update-and-install.ps1`` and optional ``keep_installer``.
    Safe to call after a successful install or on daemon startup.
    """
    stats = {"installers": 0, "launchers": 0, "downloads": 0, "temp_dirs": 0}
    keep_abs = ""
    try:
        if keep_installer and os.path.isfile(keep_installer):
            keep_abs = os.path.abspath(keep_installer)
    except Exception:
        keep_abs = ""

    if only_if_not_updating:
        try:
            if is_update_in_progress():
                return stats
        except Exception:
            pass

    staging = ""
    try:
        staging = _update_helper_staging_dir()
    except Exception:
        staging = ""

    if staging and os.path.isdir(staging):
        try:
            for name in os.listdir(staging):
                path = os.path.join(staging, name)
                if not os.path.isfile(path):
                    continue
                try:
                    if keep_abs and os.path.abspath(path) == keep_abs:
                        continue
                except Exception:
                    pass
                try:
                    if remove_installers and _is_our_installer_filename(name):
                        os.remove(path)
                        stats["installers"] += 1
                    elif remove_launchers and _is_our_update_launcher_filename(name):
                        os.remove(path)
                        stats["launchers"] += 1
                except Exception:
                    pass
        except Exception:
            pass

    if include_downloads and remove_installers:
        candidates = []
        try:
            user_dl = os.path.join(os.path.expanduser("~"), "Downloads")
            if os.path.isdir(user_dl) and "systemprofile" not in user_dl.lower():
                candidates.append(user_dl)
        except Exception:
            pass
        try:
            public_dl = os.path.join(
                os.environ.get("PUBLIC", r"C:\Users\Public"), "Downloads"
            )
            if os.path.isdir(public_dl):
                candidates.append(public_dl)
        except Exception:
            pass
        for folder in candidates:
            try:
                for name in os.listdir(folder):
                    if not _is_our_installer_filename(name):
                        continue
                    path = os.path.join(folder, name)
                    if not os.path.isfile(path):
                        continue
                    try:
                        if keep_abs and os.path.abspath(path) == keep_abs:
                            continue
                        os.remove(path)
                        stats["downloads"] += 1
                    except Exception:
                        pass
            except Exception:
                pass

    # Orphan TEMP scratch dirs from interrupted self/silent updates
    try:
        temp_root = os.environ.get("TEMP") or os.environ.get("TMP") or ""
        if temp_root and os.path.isdir(temp_root):
            for name in os.listdir(temp_root):
                if not (
                    name.startswith("honeypot_update_")
                    or name.startswith("honeypot_self_update_")
                ):
                    continue
                path = os.path.join(temp_root, name)
                if not os.path.isdir(path):
                    continue
                try:
                    import shutil

                    shutil.rmtree(path, ignore_errors=True)
                    stats["temp_dirs"] += 1
                except Exception:
                    pass
    except Exception:
        pass

    if any(stats.values()):
        try:
            from client_helpers import log as _ulog
            _ulog(
                f"[UPDATE] Cleanup artifacts: installers={stats['installers']} "
                f"launchers={stats['launchers']} downloads={stats['downloads']} "
                f"temp_dirs={stats['temp_dirs']}"
            )
        except Exception:
            pass
    return stats


def stage_installer_for_update(src_path: str, version: str = "") -> Optional[str]:
    """Copy installer to ProgramData so TEMP cleanup cannot delete it mid-helper."""
    import re
    import shutil

    if not src_path or not os.path.isfile(src_path):
        return None
    try:
        dest_dir = _update_helper_staging_dir()
        raw = (version or "").replace(" ", "")
        m = re.search(r"(\d+\.\d+\.\d+)", raw) or re.search(
            r"(\d+\.\d+\.\d+)", os.path.basename(src_path)
        )
        ver = m.group(1) if m else (raw.strip("-_") or "latest")
        # Avoid asteria-client-installer-asteria-client-installer-X.Y.Z.exe
        ver = (
            re.sub(r"(?i)^(?:asteria|cloud)-client-installer-?", "", ver) or "latest"
        )
        dest = os.path.join(dest_dir, f"asteria-client-installer-{ver}.exe")
        shutil.copy2(src_path, dest)
        if not os.path.isfile(dest):
            return None
        # Drop older staged EXEs / launchers; keep only this installer for the helper.
        try:
            cleanup_update_artifacts(
                keep_installer=dest,
                remove_installers=True,
                remove_launchers=True,
                include_downloads=False,
                only_if_not_updating=False,
            )
        except Exception:
            pass
        # Source was a TEMP/Downloads scratch copy — remove after successful stage.
        try:
            src_abs = os.path.abspath(src_path)
            dest_abs = os.path.abspath(dest)
            if src_abs != dest_abs and (
                _is_our_installer_filename(os.path.basename(src_path))
                or "honeypot_update_" in src_abs
                or "honeypot_self_update_" in src_abs
                or os.path.basename(os.path.dirname(src_abs)).startswith("honeypot_")
            ):
                os.remove(src_path)
        except Exception:
            pass
        return dest
    except Exception:
        return src_path if os.path.isfile(src_path) else None


def pause_competing_updaters() -> None:
    """Stop respawners mid-download — never /end SilentUpdater or Updater.

    Ending Asteria-SilentUpdater from inside --silent-update-check kills
    THIS process before the install helper starts (lock stuck, tasks disabled).
    """
    import subprocess

    # Only force-stop tasks that would restart/kill us during download.
    # Do NOT schtasks /end SilentUpdater or Updater (suicide).
    for task in (
        "Asteria-MemoryRestart",
        "Asteria-Watchdog",
    ):
        try:
            subprocess.run(
                ["schtasks", "/end", "/tn", task],
                capture_output=True,
                timeout=3,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
        except Exception:
            pass

    for task in (
        "Asteria-SilentUpdater",
        "Asteria-Updater",
        "Asteria-MemoryRestart",
        "Asteria-Watchdog",
    ):
        try:
            subprocess.run(
                ["schtasks", "/change", "/tn", task, "/disable"],
                capture_output=True,
                timeout=3,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
        except Exception:
            pass


def resume_competing_updaters() -> None:
    """Re-enable updater/watchdog tasks after interactive download ends without install."""
    import subprocess

    for task in (
        "Asteria-SilentUpdater",
        "Asteria-Updater",
        "Asteria-MemoryRestart",
        "Asteria-Watchdog",
    ):
        try:
            subprocess.run(
                ["schtasks", "/change", "/tn", task, "/enable"],
                capture_output=True,
                timeout=3,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
        except Exception:
            pass


def release_update_lock(*, resume_updaters: bool = True) -> None:
    """Clear interactive update lock."""
    try:
        path = _update_lock_path()
        if os.path.isfile(path):
            os.remove(path)
    except OSError:
        pass
    if resume_updaters:
        try:
            resume_competing_updaters()
        except Exception:
            pass


def prepare_client_for_installer(*, kill_processes: bool = True) -> None:
    """Installer öncesi watchdog/self-protect yeniden başlatmayı engelle.

    kill_processes=False: sadece görevleri durdur/devre dışı bırak (indirme sırasında kullanma).
    kill_processes=True: QUIT + kill-honeypot (yalnızca installer başlatılırken).
    Prefer launch_safe_update_install() for interactive/silent updates — it runs
    elevated and waits for a clean process exit before overwriting the onefile EXE.
    """
    import socket
    import subprocess

    # Always disarm self-protect on THIS process first (DACL + Guard).
    # Without this, update helpers cannot close the client reliably.
    try:
        from client_self_protection import disarm_for_update
        disarm_for_update(reason="prepare_client_for_installer")
    except Exception:
        pass

    flag_paths = [
        os.path.join(os.environ.get("TEMP", ""), "honeypot_watchdog_token.txt"),
        os.path.join(os.environ.get("APPDATA", ""), "YesNext", "CloudHoneypot", "watchdog_token.txt"),
        os.path.join(os.environ.get("APPDATA", ""), "Asteria", "watchdog.token"),
        os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "YesNext", "CloudHoneypot", "watchdog_stop.flag"),
    ]
    for path in flag_paths:
        try:
            parent = os.path.dirname(path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("stop")
        except OSError:
            pass

    for task in (
        "Asteria-Background",
        "Asteria-Tray",
        "Asteria-Watchdog",
        "Asteria-Updater",
        "Asteria-SilentUpdater",
        "Asteria-MemoryRestart",
        "AsteriaClientGuard",
    ):
        try:
            # Never /end SilentUpdater/Updater from the update process itself —
            # that suicides --silent-update-check before the helper can start.
            # The detached helper will /end everything after it is running.
            if kill_processes or task not in (
                "Asteria-SilentUpdater",
                "Asteria-Updater",
            ):
                subprocess.run(
                    ["schtasks", "/end", "/tn", task],
                    capture_output=True,
                    timeout=3,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                )
            subprocess.run(
                ["schtasks", "/change", "/tn", task, "/disable"],
                capture_output=True,
                timeout=3,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
        except Exception:
            pass

    if not kill_processes:
        return

    try:
        from client_guardian_service import uninstall_guardian_service
        uninstall_guardian_service()
    except Exception:
        pass

    # Graceful QUIT via control socket (process exits itself → DACL bypass)
    try:
        with socket.create_connection(("127.0.0.1", 58632), timeout=0.8) as sock:
            sock.sendall(b"QUIT\n")
    except Exception:
        pass

    # Prefer dedicated kill script when available (SeDebugPrivilege)
    # -Force: we already finished download / are installing — lock may still say "download"
    script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scripts", "kill-honeypot.ps1")
    if os.path.isfile(script):
        try:
            # Mark lock as installing so kill script (and parallel tasks) know kill is intentional
            try:
                acquire_update_lock("installing")
            except Exception:
                pass
            subprocess.run(
                [
                    "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                    "-File", script, "-Force",
                ],
                capture_output=True,
                timeout=30,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
        except Exception:
            pass


def _update_helper_staging_dir() -> str:
    base = os.path.join(
        os.environ.get("ProgramData", r"C:\ProgramData"),
        "Asteria",
        "update",
    )
    os.makedirs(base, exist_ok=True)
    return base


def stage_update_install_helper(*, allow_emergency: bool = True) -> Optional[str]:
    """Stage update-and-install.ps1 under ProgramData (ASCII + parse-validated).

    Windows PowerShell 5.1 mis-parses UTF-8-without-BOM scripts that contain
    em-dashes (U+2014) — launcher logs start then the helper never runs.
    Never copy2 raw Unicode. On failure, fall back to the embedded emergency
    ASCII bootstrap so self-update remains possible on Win10/11/Server 2012+.
    """
    from client_update_hardening import (
        normalize_ps1_to_ascii,
        resolve_helper_source_candidates,
        validate_powershell_parse,
        write_ascii_ps1,
        write_emergency_bootstrap,
    )

    dst = os.path.join(_update_helper_staging_dir(), "update-and-install.ps1")
    src = next((p for p in resolve_helper_source_candidates() if os.path.isfile(p)), None)

    def _harden_update_staging(path: str) -> None:
        folder = os.path.dirname(path)
        # Never rewrite ACLs on an injected/test directory. Production helpers
        # are staged only below ProgramData.
        program_data = os.path.abspath(
            os.environ.get("ProgramData", r"C:\ProgramData")
        )
        try:
            if os.path.commonpath(
                (program_data, os.path.abspath(folder))
            ).lower() != program_data.lower():
                return
        except (OSError, ValueError):
            return
        try:
            subprocess.run(
                [
                    "icacls", folder,
                    "/inheritance:r",
                    "/grant:r", "NT AUTHORITY\\SYSTEM:(OI)(CI)F",
                    "/grant:r", "BUILTIN\\Administrators:(OI)(CI)F",
                    "/remove:g", "BUILTIN\\Users",
                    "/remove:g", "Everyone",
                    "/remove:g", "NT AUTHORITY\\Authenticated Users",
                    "/T", "/C", "/Q",
                ],
                capture_output=True,
                timeout=20,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except Exception:
            pass

    def _try_stage_text(raw: str, tag: str) -> Optional[str]:
        ascii_body = normalize_ps1_to_ascii(raw)
        if not write_ascii_ps1(dst, ascii_body):
            return None
        ok, detail = validate_powershell_parse(dst)
        if ok:
            _harden_update_staging(dst)
            return dst
        try:
            log_path = os.path.join(
                os.environ.get("ProgramData", r"C:\ProgramData"),
                "Asteria", "update-install.log",
            )
            with open(log_path, "a", encoding="ascii", errors="replace") as fh:
                fh.write(
                    f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] "
                    f"helper_stage_parse_fail tag={tag} detail={detail[:200]}\n"
                )
        except Exception:
            pass
        return None

    if src:
        try:
            with open(src, "r", encoding="utf-8", errors="replace") as fh:
                raw = fh.read()
            staged = _try_stage_text(raw, tag=os.path.basename(src))
            if staged:
                return staged
        except OSError:
            pass

    if allow_emergency:
        emergency = write_emergency_bootstrap(dst)
        if emergency:
            try:
                log_path = os.path.join(
                    os.environ.get("ProgramData", r"C:\ProgramData"),
                    "Asteria", "update-install.log",
                )
                with open(log_path, "a", encoding="ascii", errors="replace") as fh:
                    fh.write(
                        f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] "
                        "helper_stage_emergency_bootstrap=1\n"
                    )
            except Exception:
                pass
            return emergency
    return None


def _shell_execute_runas(file_path: str, params: str = "", *, show_cmd: int = 0) -> int:
    """ShellExecuteW runas. Returns >32 on success, 1223 if UAC cancelled, else error code."""
    try:
        rc = int(
            ctypes.windll.shell32.ShellExecuteW(
                None,
                "runas",
                file_path,
                params or None,
                None,
                int(show_cmd),
            )
        )
        return rc
    except Exception:
        return 0


def launch_safe_update_install(
    installer_path: str,
    *,
    silent: bool = False,
    show_gui_after: bool = True,
    expect_exit_pid: Optional[int] = None,
    elevate: bool = True,
    grace_wait_sec: int = 20,
    prefer_emergency: bool = False,
) -> bool:
    """Start elevated update helper (detached). Caller should then exit quickly.

    Interactive path uses ShellExecuteW runas so the UAC prompt is visible (hidden
    CREATE_NO_WINDOW parents often swallow/skip UAC and the installer never starts).

    The helper waits for expect_exit_pid, force-kills leftovers, runs the installer,
    then starts the new app.

    ``prefer_emergency``: stage ASCII emergency bootstrap first (after
    ``launch_helper_failed`` / launcher-only storms). Silent path always waits for
    ``update-and-install start`` before returning True.
    """
    import subprocess

    if not installer_path or not os.path.isfile(installer_path):
        return False

    log_path_early = os.path.join(
        os.environ.get("ProgramData", r"C:\ProgramData"),
        "Asteria", "update-install.log",
    )
    force_emergency = bool(prefer_emergency)
    if not force_emergency:
        try:
            from client_update_hardening import detect_launcher_only_storm
            if detect_launcher_only_storm(log_path_early):
                force_emergency = True
        except Exception:
            pass

    helper = None
    if force_emergency:
        try:
            from client_update_hardening import write_emergency_bootstrap
            dst = os.path.join(_update_helper_staging_dir(), "update-and-install.ps1")
            helper = write_emergency_bootstrap(dst)
            if helper:
                try:
                    with open(log_path_early, "a", encoding="ascii", errors="replace") as fh:
                        fh.write(
                            f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] "
                            "helper_stage_prefer_emergency=1\n"
                        )
                except Exception:
                    pass
        except Exception:
            helper = None
    if not helper:
        # Always re-stage helper from package so older ProgramData copies are refreshed
        helper = stage_update_install_helper(allow_emergency=True)
    if not helper:
        try:
            with open(log_path_early, "a", encoding="ascii", errors="replace") as fh:
                fh.write(
                    f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] "
                    "launch_helper_failed detail=stage_helper\n"
                )
        except Exception:
            pass
        return False

    pid = int(expect_exit_pid if expect_exit_pid is not None else os.getpid())
    already_admin = False
    try:
        already_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        already_admin = False
    if elevate:
        elevate = not already_admin

    # Stable installer copy (TEMP dirs vanish / get cleaned)
    # Prefer clean version tag — avoid asteria-client-installer-asteria-client-installer-*.exe
    ver_hint = ""
    try:
        import re
        base = os.path.splitext(os.path.basename(installer_path))[0]
        m = re.search(r"(\d+\.\d+\.\d+)", base)
        ver_hint = (
            m.group(1)
            if m
            else re.sub(
                r"(?i)^(?:asteria|cloud)-client-installer-?", "", base
            ).strip("-_")
        )
    except Exception:
        ver_hint = "latest"
    stable = stage_installer_for_update(installer_path, version=ver_hint or "latest")
    if stable:
        installer_path = stable

    try:
        from client_update_hardening import preflight_update_ready
        ok_pf, pf_detail = preflight_update_ready(installer_path)
        if not ok_pf:
            try:
                log_path = os.path.join(
                    os.environ.get("ProgramData", r"C:\ProgramData"),
                    "Asteria", "update-install.log",
                )
                with open(log_path, "a", encoding="ascii", errors="replace") as fh:
                    fh.write(
                        f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] "
                        f"preflight_fail detail={pf_detail}\n"
                    )
            except Exception:
                pass
            return False
    except Exception:
        pass

    # SUP-001b: trust gate immediately before execute (policy-gated soft-skip).
    try:
        from client_authenticode import AuthenticodeError, assert_update_authenticode
        assert_update_authenticode(installer_path)
    except AuthenticodeError:
        try:
            log_path = os.path.join(
                os.environ.get("ProgramData", r"C:\ProgramData"),
                "Asteria", "update-install.log",
            )
            with open(log_path, "a", encoding="ascii", errors="replace") as fh:
                fh.write(
                    f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] "
                    "preflight_fail detail=authenticode_rejected\n"
                )
        except Exception:
            pass
        return False
    except Exception:
        pass

    acquire_update_lock("installing")
    # Stop respawn tasks only. Do NOT QUIT this process here — that raced with
    # ShellExecute/Popen and aborted interactive installs before the helper started.
    # kill_processes=False also skips /end of SilentUpdater (avoids suicide).
    prepare_client_for_installer(kill_processes=False)

    staging = _update_helper_staging_dir()
    launcher = os.path.join(staging, f"run-update-{pid}.ps1")
    flags = []
    if silent:
        flags.append("-Silent")
    if show_gui_after:
        flags.append("-ShowGuiAfter")
    flag_str = " ".join(flags)
    # Escape single quotes in paths for PowerShell single-quoted strings
    helper_q = helper.replace("'", "''")
    installer_q = installer_path.replace("'", "''")
    grace = max(8, int(grace_wait_sec))
    launcher_body = (
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        f"& '{helper_q}' -InstallerPath '{installer_q}' "
        f"-ExpectExitPid {pid} -GraceWaitSec {grace} -KillRounds 4 {flag_str}\n"
        "exit $LASTEXITCODE\n"
    )
    try:
        # ASCII-friendly write; BOM-less UTF-8 is fine for this launcher
        with open(launcher, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(launcher_body)
    except OSError:
        try:
            release_update_lock(resume_updaters=True)
        except Exception:
            pass
        return False

    try:
        # Interactive (visible UAC) only — silent must wait for helper log.
        if elevate and not silent:
            # Interactive: ShellExecute runas from this process (has desktop/GUI affinity)
            # so UAC is visible. Hidden powershell parents often fail to show UAC.
            params = f'-NoProfile -ExecutionPolicy Bypass -File "{launcher}"'
            rc = _shell_execute_runas("powershell.exe", params, show_cmd=0)  # SW_HIDE after consent
            if rc == 1223:
                # User cancelled UAC
                try:
                    release_update_lock(resume_updaters=True)
                except Exception:
                    pass
                return False
            if rc <= 32:
                # Fallback: Start-Process -Verb RunAs (visible)
                ps = (
                    "Start-Process -FilePath 'powershell.exe' -Verb RunAs "
                    f"-ArgumentList '-NoProfile -ExecutionPolicy Bypass -File \"{launcher}\"' "
                    "-Wait:$false"
                )
                try:
                    subprocess.Popen(
                        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps],
                        creationflags=getattr(subprocess, "CREATE_NEW_CONSOLE", 0x00000010),
                        close_fds=True,
                    )
                except Exception:
                    try:
                        release_update_lock(resume_updaters=True)
                    except Exception:
                        pass
                    return False
            return True

        # Already admin / silent SYSTEM path — helper MUST survive our exit AND
        # must write update-install.log BEFORE we return True.
        # Bug (4.5.49–51): Popen looked alive for 0.4s → return True → parent
        # exited → child died in job object → no install log → stuck "installing".
        log_path = os.path.join(
            os.environ.get("ProgramData", r"C:\ProgramData"),
            "Asteria", "update-install.log",
        )
        try:
            log_size0 = os.path.getsize(log_path) if os.path.isfile(log_path) else 0
        except OSError:
            log_size0 = 0
        launch_token = f"launch-{pid}-{int(time.time())}"

        def _fresh_helper_log() -> bool:
            """True only if NEW bytes after spawn contain launcher/helper start."""
            try:
                if not os.path.isfile(log_path):
                    return False
                with open(log_path, "r", encoding="utf-8", errors="ignore") as fh:
                    fh.seek(max(0, log_size0))
                    new = fh.read()
                if not new:
                    return False
                if launch_token in new and "update-and-install start" in new:
                    return True
                # Require real helper start — launcher-only was a false positive when
                # update-and-install.ps1 failed to parse (Unicode em-dash vs PS 5.1).
                if "update-and-install start" in new:
                    return True
            except Exception:
                return False
            return False

        def _wait_helper_log(timeout_sec: float = 20.0) -> bool:
            deadline = time.time() + timeout_sec
            while time.time() < deadline:
                if _fresh_helper_log():
                    return True
                time.sleep(0.25)
            return _fresh_helper_log()

        # Launcher with unique token + Continue (not SilentlyContinue) so failures surface
        try:
            with open(launcher, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(
                    "$ErrorActionPreference = 'Continue'\n"
                    "$logDir = Join-Path $env:ProgramData 'Asteria'\n"
                    "try {\n"
                    "  if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }\n"
                    f"  Add-Content -Path (Join-Path $logDir 'update-install.log') "
                    f"-Value ('[' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '] launcher start {launch_token} pid=' + $PID) -Encoding UTF8\n"
                    "} catch {}\n"
                    f"& '{helper_q}' -InstallerPath '{installer_q}' "
                    f"-ExpectExitPid {pid} -GraceWaitSec {grace} -KillRounds 4 {flag_str}\n"
                    "exit $LASTEXITCODE\n"
                )
        except OSError:
            try:
                release_update_lock(resume_updaters=True)
            except Exception:
                pass
            return False

        ps_cmd = (
            f'powershell.exe -NoProfile -ExecutionPolicy Bypass '
            f'-WindowStyle Hidden -File "{launcher}"'
        )

        # --- Method 1: WMI Win32_Process.Create (escapes scheduled-task job objects) ---
        try:
            import pythoncom
            import win32com.client

            pythoncom.CoInitialize()
            try:
                locator = win32com.client.Dispatch("WbemScripting.SWbemLocator")
                svc = locator.ConnectServer(".", "root\\cimv2")
                process = svc.Get("Win32_Process")
                startup = svc.Get("Win32_ProcessStartup").SpawnInstance_()
                startup.ShowWindow = 0
                # Dynamic Dispatch: (ReturnValue, ProcessId)
                out = process.Create(ps_cmd, staging, startup)
                rc_wmi = out[0] if isinstance(out, (tuple, list)) else int(out)
                if rc_wmi == 0 and _wait_helper_log(20.0):
                    return True
            finally:
                try:
                    pythoncom.CoUninitialize()
                except Exception:
                    pass
        except Exception:
            pass

        # --- Method 2: cmd start /b (classic breakaway from parent job) ---
        try:
            subprocess.Popen(
                [
                    "cmd.exe", "/c", "start", "", "/b",
                    "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
                    "-WindowStyle", "Hidden", "-File", launcher,
                ],
                cwd=staging,
                close_fds=True,
                creationflags=subprocess.CREATE_NO_WINDOW
                | getattr(subprocess, "DETACHED_PROCESS", 0x00000008)
                | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200),
            )
            if _wait_helper_log(20.0):
                return True
        except Exception:
            pass

        # --- Method 3: schtasks UpdateOnce — do NOT delete until fresh log ---
        try:
            task = f"Asteria-UpdateOnce-{pid}"
            subprocess.run(
                [
                    "schtasks", "/Create", "/TN", task, "/TR", ps_cmd,
                    "/SC", "ONCE", "/ST", "00:00", "/RU", "SYSTEM",
                    "/RL", "HIGHEST", "/F",
                ],
                capture_output=True,
                timeout=15,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            run = subprocess.run(
                ["schtasks", "/Run", "/TN", task],
                capture_output=True,
                timeout=15,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            helper_seen = bool(run.returncode == 0 and _wait_helper_log(25.0))
            try:
                subprocess.run(
                    ["schtasks", "/Delete", "/TN", task, "/F"],
                    capture_output=True,
                    timeout=10,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                )
            except Exception:
                pass
            if helper_seen:
                return True
        except Exception:
            pass

        # --- Method 4: breakaway Popen — still require fresh log ---
        try:
            CREATE_BREAKAWAY_FROM_JOB = 0x01000000
            det_flags = (
                subprocess.CREATE_NO_WINDOW
                | getattr(subprocess, "DETACHED_PROCESS", 0x00000008)
                | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200)
                | CREATE_BREAKAWAY_FROM_JOB
            )
            subprocess.Popen(
                [
                    "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                    "-WindowStyle", "Hidden", "-File", launcher,
                ],
                creationflags=det_flags,
                close_fds=True,
                cwd=staging,
            )
            if _wait_helper_log(20.0):
                return True
        except Exception:
            pass

        # --- Method 5: emergency bootstrap rewrite + WMI/schtasks retry ---
        # Covers: full helper still broken on disk, parse gate race, AV quarantine.
        try:
            from client_update_hardening import write_emergency_bootstrap
            emergency = write_emergency_bootstrap(helper)
            if emergency:
                helper_q = emergency.replace("'", "''")
                with open(launcher, "w", encoding="ascii", newline="\n") as fh:
                    fh.write(
                        "$ErrorActionPreference = 'Continue'\n"
                        "$logDir = Join-Path $env:ProgramData 'Asteria'\n"
                        "try {\n"
                        "  if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }\n"
                        f"  Add-Content -Path (Join-Path $logDir 'update-install.log') "
                        f"-Value ('[' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '] launcher start {launch_token}-emg pid=' + $PID) -Encoding ASCII\n"
                        "} catch {}\n"
                        f"& '{helper_q}' -InstallerPath '{installer_q}' "
                        f"-ExpectExitPid {pid} -GraceWaitSec {grace} -KillRounds 4 {flag_str}\n"
                        "exit $LASTEXITCODE\n"
                    )
                # Prefer schtasks SYSTEM one-shot for Session-0 immortality
                task = f"Asteria-UpdateEmg-{pid}"
                subprocess.run(
                    [
                        "schtasks", "/Create", "/TN", task, "/TR", ps_cmd,
                        "/SC", "ONCE", "/ST", "00:00", "/RU", "SYSTEM",
                        "/RL", "HIGHEST", "/F",
                    ],
                    capture_output=True,
                    timeout=15,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                )
                run = subprocess.run(
                    ["schtasks", "/Run", "/TN", task],
                    capture_output=True,
                    timeout=15,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                )
                helper_seen = bool(run.returncode == 0 and _wait_helper_log(30.0))
                try:
                    subprocess.run(
                        ["schtasks", "/Delete", "/TN", task, "/F"],
                        capture_output=True,
                        timeout=10,
                        creationflags=subprocess.CREATE_NO_WINDOW,
                    )
                except Exception:
                    pass
                if helper_seen:
                    return True
        except Exception:
            pass

        # --- Method 6: last-resort direct emergency bootstrap via schtasks ---
        try:
            from client_update_hardening import write_emergency_bootstrap
            task = f"Asteria-NsisOnce-{pid}"
            nsis_launcher = os.path.join(staging, f"run-nsis-{pid}.ps1")
            if write_emergency_bootstrap(nsis_launcher):
                nsis_cmd = (
                    f'powershell.exe -NoProfile -ExecutionPolicy Bypass '
                    f'-WindowStyle Hidden -File "{nsis_launcher}" '
                    f'-InstallerPath "{installer_path}" -ExpectExitPid {pid} '
                    f'-GraceWaitSec {grace} -KillRounds 4 -Silent'
                )
                subprocess.run(
                    [
                        "schtasks", "/Create", "/TN", task, "/TR", nsis_cmd,
                        "/SC", "ONCE", "/ST", "00:00", "/RU", "SYSTEM",
                        "/RL", "HIGHEST", "/F",
                    ],
                    capture_output=True,
                    timeout=15,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                )
                run = subprocess.run(
                    ["schtasks", "/Run", "/TN", task],
                    capture_output=True,
                    timeout=15,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                )
                helper_seen = bool(run.returncode == 0 and _wait_helper_log(30.0))
                try:
                    subprocess.run(
                        ["schtasks", "/Delete", "/TN", task, "/F"],
                        capture_output=True,
                        timeout=10,
                        creationflags=subprocess.CREATE_NO_WINDOW,
                    )
                except Exception:
                    pass
                if helper_seen:
                    return True
        except Exception:
            pass

        try:
            with open(log_path, "a", encoding="ascii", errors="replace") as fh:
                fh.write(
                    f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] "
                    "launch_helper_failed detail=methods_exhausted\n"
                )
        except Exception:
            pass
        try:
            release_update_lock(resume_updaters=True)
        except Exception:
            pass
        return False
    except Exception:
        try:
            release_update_lock(resume_updaters=True)
        except Exception:
            pass
        return False


def launch_installer_elevated_fallback(installer_path: str) -> bool:
    """Open NSIS installer with a visible window (UAC if needed)."""
    if not installer_path or not os.path.isfile(installer_path):
        return False
    try:
        already_admin = False
        try:
            already_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            already_admin = False

        if already_admin:
            # Visible; no UAC. DETACHED so it survives our upcoming exit.
            subprocess.Popen(
                [installer_path],
                cwd=os.path.dirname(installer_path) or None,
                close_fds=True,
                creationflags=getattr(subprocess, "DETACHED_PROCESS", 0x00000008)
                | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200),
            )
            return True

        rc = _shell_execute_runas(installer_path, "", show_cmd=1)  # SW_SHOWNORMAL
        if rc == 1223:
            return False
        if rc > 32:
            return True
        # Fallback Start-Process -Verb RunAs
        q = installer_path.replace("'", "''")
        subprocess.Popen(
            [
                "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                "-Command",
                f"Start-Process -FilePath '{q}' -Verb RunAs",
            ],
            creationflags=getattr(subprocess, "CREATE_NEW_CONSOLE", 0x00000010),
            close_fds=True,
        )
        return True
    except Exception:
        return False


def launch_interactive_installer_and_exit_prep(installer_path: str) -> bool:
    """Interactive update: open NSIS now (visible), do NOT QUIT-self before launch.

    NSIS PreInstallKill handles leftover processes. Returning True means caller
    should exit the client shortly so the onefile EXE can be overwritten.
    """
    if not installer_path or not os.path.isfile(installer_path):
        return False
    try:
        acquire_update_lock("installing")
    except Exception:
        pass
    # Stop respawners only — do not QUIT ourselves here (that raced and aborted launch)
    try:
        prepare_client_for_installer(kill_processes=False)
    except Exception:
        pass
    return launch_installer_elevated_fallback(installer_path)


class UpdateProgressDialog:
    """Güncelleme progress dialog'u"""
    
    def __init__(self, parent=None, title="Güncelleme"):
        self.parent = parent
        self.title = title
        self.dialog = None
        self.progress_var = None
        self.status_var = None
        self.percent_var = None
        self.progress_bar = None
    
    def create_dialog(self):
        """Dialog oluştur"""
        try:
            import tkinter as tk
            from tkinter import ttk
            
            self.dialog = tk.Toplevel(self.parent) if self.parent else tk.Tk()
            self.dialog.title(self.title)
            self.dialog.geometry("400x150")
            self.dialog.resizable(False, False)
            
            # Ortala
            if self.parent:
                self.dialog.transient(self.parent)
                self.dialog.grab_set()
                
                # Parent'ın merkezine konumlandır
                parent_x = self.parent.winfo_rootx()
                parent_y = self.parent.winfo_rooty()
                parent_w = self.parent.winfo_width()
                parent_h = self.parent.winfo_height()
                
                x = parent_x + (parent_w // 2) - 200
                y = parent_y + (parent_h // 2) - 75
                self.dialog.geometry(f"400x150+{x}+{y}")
            
            # Durum metni
            self.status_var = tk.StringVar(value="Başlatılıyor...")
            status_label = tk.Label(
                self.dialog, 
                textvariable=self.status_var, 
                font=("Arial", 10)
            )
            status_label.pack(pady=15)
            
            # Progress bar
            self.progress_var = tk.IntVar()
            self.progress_bar = ttk.Progressbar(
                self.dialog,
                variable=self.progress_var,
                maximum=100,
                length=350
            )
            self.progress_bar.pack(pady=10)
            
            # Progress yüzdesi
            self.percent_var = tk.StringVar(value="0%")
            percent_label = tk.Label(
                self.dialog,
                textvariable=self.percent_var,
                font=("Arial", 9)
            )
            percent_label.pack()

            self.dialog.update_idletasks()
            self.dialog.lift()
            self.dialog.attributes("-topmost", True)
            self.dialog.after(250, lambda: self.dialog.attributes("-topmost", False))
            
            return True
            
        except Exception as e:
            print(f"Dialog oluşturma hatası: {e}")
            return False
    
    def update_progress(self, percent: int, message: str = ""):
        """Progress güncelle"""
        try:
            if self.dialog and self.progress_var and self.status_var:
                self.progress_var.set(percent)
                if message:
                    self.status_var.set(message)
                if self.percent_var:
                    self.percent_var.set(f"{percent}%")
                self.dialog.update()
                    
        except Exception as e:
            print(f"Progress güncelleme hatası: {e}")
    
    def close_dialog(self):
        """Dialog'u kapat"""
        try:
            if self.dialog:
                self.dialog.destroy()
                self.dialog = None
        except Exception as e:
            print(f"Dialog kapatma hatası: {e}")


def create_update_manager(github_owner: str = "cevdetaksac", 
                         github_repo: str = "asteria-client",
                         log_func=None) -> InstallerUpdateManager:
    """Update manager factory fonksiyonu"""
    return InstallerUpdateManager(github_owner, github_repo, log_func)