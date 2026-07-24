#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Token Management - machine-scoped immutable client identity.

Token is the server's durable identity. It must:
  - Live in ProgramData (shared by SYSTEM daemon + user GUI)
  - Never be overwritten by a newly minted /register token (except controlled
    hardware rebind / clone split)
  - Never auto-re-register merely because load/decrypt failed

Hardware binding (schema v2) + in-place rotate (contract 1.4.29):
  machine_id / hwid sent to /register is a SHA-256 over MachineGuid + NIC MACs
  + SMBIOS UUID. When regenerating token.dat (identity v2 / rekey), call
  POST /api/agent/rotate-token BEFORE writing disk — never bare /register while
  the old token is still known (ghost Client rows).

Create (/register) only when NO token file exists after migration - or when
hardware binding requires a controlled re-enroll.
"""

from __future__ import annotations

import json
import os
import re
import time
import hashlib
import subprocess
from typing import Optional, List

from client_helpers import ClientHelpers, log
from client_utils import TokenStore, _programdata_client_dir
from client_api import register_client_api, rotate_token_api

CREATE_NO_WINDOW = 0x08000000
IDENTITY_SCHEMA_VERSION = 2
_FP_CACHE: Optional[str] = None


def get_windows_machine_guid() -> str:
    """Raw Windows MachineGuid (may be identical across unsysprep'd clones)."""
    try:
        import winreg
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Cryptography",
        ) as key:
            guid, _ = winreg.QueryValueEx(key, "MachineGuid")
            if guid:
                return str(guid).strip()
    except Exception:
        pass
    return ""


def get_nic_macs() -> List[str]:
    """Stable sorted MAC list (lowercase hex, no separators)."""
    macs: set = set()
    try:
        import uuid as uuid_mod
        node = int(uuid_mod.getnode())
        # uuid.getnode is random if no NIC - skip the "locally administered random" bit pattern
        if node and node != 0xFFFFFFFFFFFF:
            macs.add(f"{node:012x}")
    except Exception:
        pass

    # Prefer WMI - covers multiple adapters; ignore empties / all-zero
    try:
        script = (
            "Get-CimInstance Win32_NetworkAdapterConfiguration -EA SilentlyContinue "
            "| Where-Object { $_.MACAddress } "
            "| Select-Object -ExpandProperty MACAddress"
        )
        proc = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                script,
            ],
            capture_output=True,
            text=True,
            timeout=12,
            creationflags=CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
        if proc.returncode == 0 and proc.stdout:
            for line in proc.stdout.splitlines():
                raw = re.sub(r"[^0-9A-Fa-f]", "", (line or "").strip())
                if len(raw) == 12 and raw.lower() != ("0" * 12):
                    macs.add(raw.lower())
    except Exception:
        pass

    return sorted(macs)


def get_smbios_uuid() -> str:
    """SMBIOS / hardware UUID when available (empty on failure)."""
    try:
        script = (
            "$u=(Get-CimInstance Win32_ComputerSystemProduct -EA SilentlyContinue).UUID; "
            "if ($u) { $u.ToString().Trim() }"
        )
        proc = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                script,
            ],
            capture_output=True,
            text=True,
            timeout=12,
            creationflags=CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
        if proc.returncode == 0:
            val = (proc.stdout or "").strip()
            if val and val.lower() not in ("", "ffffffff-ffff-ffff-ffff-ffffffffffff"):
                return val
    except Exception:
        pass
    return ""


def get_volume_serial_fallback() -> str:
    try:
        import ctypes
        vol_serial = ctypes.c_ulong(0)
        ctypes.windll.kernel32.GetVolumeInformationW(
            "C:\\", None, 0, ctypes.byref(vol_serial), None, None, None, 0
        )
        return f"{vol_serial.value:08x}"
    except Exception:
        return ""


def get_device_fingerprint(force_refresh: bool = False) -> str:
    """SHA-256 hardware fingerprint used as /register machine_id (unique per host).

    Material: schema|MachineGuid|mac1,mac2,...|smbios_uuid|vol_serial
    Cloned VMs that keep MachineGuid but receive new NIC MACs get a new id.
    """
    global _FP_CACHE
    if _FP_CACHE and not force_refresh:
        return _FP_CACHE
    guid = get_windows_machine_guid() or "no-guid"
    macs = ",".join(get_nic_macs()) or "no-mac"
    smbios = get_smbios_uuid() or "no-smbios"
    vol = get_volume_serial_fallback() or "no-vol"
    raw = f"v2|{guid}|{macs}|{smbios}|{vol}"
    _FP_CACHE = hashlib.sha256(raw.encode("utf-8", "ignore")).hexdigest()
    return _FP_CACHE


def get_machine_id() -> str:
    """Stable per-machine id for API upsert - hardware fingerprint (MAC-bound)."""
    try:
        return get_device_fingerprint()
    except Exception:
        pass
    # Last-resort fallback
    try:
        raw = f"{os.environ.get('COMPUTERNAME', '')}-{get_volume_serial_fallback()}"
        return hashlib.sha256(raw.encode("utf-8", "ignore")).hexdigest()
    except Exception:
        return hashlib.sha256(
            (os.environ.get("COMPUTERNAME") or "unknown").encode("utf-8")
        ).hexdigest()


def get_canonical_token_path() -> str:
    """Machine-wide token path - same for SYSTEM and interactive user."""
    return os.path.join(_programdata_client_dir(), "token.dat")


def _binding_path() -> str:
    return os.path.join(_programdata_client_dir(), "device_binding.json")


def _load_binding() -> dict:
    path = _binding_path()
    try:
        if not os.path.isfile(path):
            return {}
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_binding(*, fingerprint: str, token: str, reason: str = "") -> None:
    path = _binding_path()
    try:
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        payload = {
            "schema": IDENTITY_SCHEMA_VERSION,
            "fingerprint": (fingerprint or "").strip(),
            "machine_guid": get_windows_machine_guid(),
            "macs": get_nic_macs(),
            "smbios_uuid": get_smbios_uuid(),
            "token_prefix": ((token or "").strip()[:8]),
            "bound_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "reason": reason or "bind",
        }
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, ensure_ascii=True)
        os.replace(tmp, path)
    except Exception as e:
        log(f"[TOKEN] device_binding save failed: {e}")


def quarantine_local_identity(reason: str = "rebind") -> None:
    """Move token.dat aside and clear account-link cache (clone / hardware rebind)."""
    stamp = time.strftime("%Y%m%d%H%M%S")

    def _aside(path: str) -> None:
        if not path or not os.path.isfile(path):
            return
        try:
            dest = f"{path}.stale_{reason}_{stamp}"
            os.replace(path, dest)
            log(f"[TOKEN] Quarantined {path} -> {os.path.basename(dest)}")
        except OSError as e:
            log(f"[TOKEN] Quarantine failed for {path}: {e}")
            try:
                os.remove(path)
            except OSError:
                pass

    _aside(get_canonical_token_path())
    # Prevent migrate_token_to_canonical from resurrecting a cloned legacy copy
    for path in get_legacy_token_paths(""):
        try:
            if os.path.normcase(os.path.abspath(path)) == os.path.normcase(
                os.path.abspath(get_canonical_token_path())
            ):
                continue
        except Exception:
            pass
        _aside(path)

    try:
        from client_utils import set_account_linked
        set_account_linked(False, email="", source=f"identity_{reason}")
    except Exception:
        pass
    try:
        link = os.path.join(_programdata_client_dir(), "account_link.json")
        _aside(link)
    except Exception:
        pass
    _aside(_binding_path())


def get_legacy_token_paths(app_dir: str = "") -> List[str]:
    """Historical locations that may hold a valid token (migrate → ProgramData)."""
    paths: List[str] = []
    seen = set()

    def _add(p: str):
        if not p:
            return
        norm = os.path.normcase(os.path.abspath(p))
        if norm in seen:
            return
        seen.add(norm)
        paths.append(p)

    # Prefer user AppData (interactive GUI often created the first identity)
    user_appdata = os.environ.get("APPDATA") or ""
    if user_appdata:
        _add(os.path.join(user_appdata, "YesNext", "CloudHoneypotClient", "token.dat"))

    # Explicit app_dir (may equal user AppData)
    if app_dir:
        _add(os.path.join(app_dir, "token.dat"))

    # SYSTEM profile used by CloudHoneypot-Background / SilentUpdater
    windir = os.environ.get("WINDIR", r"C:\Windows")
    _add(
        os.path.join(
            windir,
            "System32",
            "config",
            "systemprofile",
            "AppData",
            "Roaming",
            "YesNext",
            "CloudHoneypotClient",
            "token.dat",
        )
    )
    # WOW64 view sometimes used by 32-bit helpers
    _add(
        os.path.join(
            windir,
            "SysWOW64",
            "config",
            "systemprofile",
            "AppData",
            "Roaming",
            "YesNext",
            "CloudHoneypotClient",
            "token.dat",
        )
    )

    # Install / CWD leftovers
    try:
        import sys
        if getattr(sys, "frozen", False):
            _add(os.path.join(os.path.dirname(sys.executable), "token.dat"))
            _add(os.path.join(os.path.dirname(sys.executable), "token.txt"))
    except Exception:
        pass
    _add(os.path.join(os.getcwd(), "token.dat"))
    _add(os.path.join(os.getcwd(), "token.txt"))
    _add("token.txt")

    return paths


def get_token_file_paths(app_dir: str = "") -> tuple:
    """Return (canonical_token.dat, legacy_plain_token.txt) for TokenManager."""
    return get_canonical_token_path(), "token.txt"


def _is_plain_token_file(path: str) -> bool:
    return path.lower().endswith(".txt")


def _read_token_from_path(path: str) -> Optional[str]:
    if not path or not os.path.isfile(path):
        return None
    try:
        if _is_plain_token_file(path):
            with open(path, "r", encoding="utf-8") as fh:
                tok = fh.read().strip()
            return tok or None
        return TokenStore.load(path)
    except Exception as e:
        log(f"[TOKEN] Failed reading {path}: {e}")
        return None


def migrate_token_to_canonical(app_dir: str = "") -> Optional[str]:
    """Find any existing valid token and copy it to ProgramData. Never /register."""
    canonical = get_canonical_token_path()
    existing = TokenStore.load(canonical)
    if existing:
        return existing

    for path in get_legacy_token_paths(app_dir):
        if os.path.normcase(os.path.abspath(path)) == os.path.normcase(
            os.path.abspath(canonical)
        ):
            continue
        tok = _read_token_from_path(path)
        if not tok:
            continue
        try:
            TokenStore.save(tok, canonical, overwrite=False)
            log(f"[TOKEN] Migrated durable identity from {path} -> {canonical}")
            # Best-effort cleanup of plain-text leftovers only
            if _is_plain_token_file(path):
                try:
                    os.remove(path)
                except OSError:
                    pass
            return tok
        except Exception as e:
            log(f"[TOKEN] Migration save failed from {path}: {e}")
            # Still return token for this process even if ProgramData write failed
            return tok

    # Plain migrate helper (CWD token.txt) without clobbering a good file
    TokenStore.migrate_from_plain("token.txt", canonical, only_if_missing=True)
    return TokenStore.load(canonical)


def _registration_lock_path() -> str:
    return os.path.join(_programdata_client_dir(), "token_register.lock")


def _acquire_register_lock(timeout_sec: float = 30.0):
    """Exclusive lock so daemon + tray cannot double-register."""
    path = _registration_lock_path()
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR)
            os.write(fd, f"{os.getpid()}\n{time.time()}\n".encode("ascii", "ignore"))
            return fd
        except FileExistsError:
            # Stale lock? If older than 5 minutes, break it
            try:
                age = time.time() - os.path.getmtime(path)
                if age > 300:
                    os.remove(path)
                    continue
            except OSError:
                pass
            time.sleep(0.25)
        except OSError:
            time.sleep(0.25)
    return None


def _release_register_lock(fd) -> None:
    if fd is None:
        return
    try:
        os.close(fd)
    except OSError:
        pass
    try:
        os.remove(_registration_lock_path())
    except OSError:
        pass


class TokenManager:
    """Machine-scoped token identity manager."""

    def __init__(self, api_url: str, server_name: str, token_file_new: str, token_file_old: str):
        self.api_url = api_url
        self.server_name = server_name
        # Always prefer canonical ProgramData path (ignore legacy caller path if different)
        self.token_file_new = get_canonical_token_path()
        self.token_file_old = token_file_old or "token.txt"
        self._app_dir_hint = os.path.dirname(token_file_new) if token_file_new else ""

    def get_token(self) -> Optional[str]:
        """Load only - never creates a new identity."""
        tok = migrate_token_to_canonical(self._app_dir_hint)
        if tok:
            return tok
        return TokenStore.load(self.token_file_new)

    def _persist_token(self, tok: str, fingerprint: str, *, overwrite: bool = False, reason: str = "register") -> None:
        TokenStore.save(
            tok,
            self.token_file_new,
            overwrite=overwrite,
            fingerprint=fingerprint,
        )
        _save_binding(fingerprint=fingerprint, token=tok, reason=reason)

    def register_client(self, root_window=None, t_func=None) -> Optional[str]:
        """Register ONLY when no durable token exists. Uses hardware fingerprint upsert.

        Bare /register while an old token is still known creates ghost Clients —
        use ``_rotate_in_place`` for rekey (contract 1.4.29).
        """
        # Re-check under lock - another process may have just registered
        existing = self.get_token()
        if existing:
            log("[TOKEN] Register skipped - durable token already present")
            return existing

        lock_fd = _acquire_register_lock()
        if lock_fd is None:
            log("[TOKEN] Register lock timeout - refusing to mint a new identity")
            return self.get_token()

        try:
            existing = self.get_token()
            if existing:
                return existing

            # File exists but unreadable → NEVER mint (would orphan API identity)
            if os.path.isfile(self.token_file_new):
                log(
                    "[TOKEN] token.dat exists but could not be read - "
                    "refusing auto-register to protect identity"
                )
                return None

            machine_id = get_machine_id()
            machine_guid = get_windows_machine_guid()
            for attempt in range(3):
                try:
                    ip = ClientHelpers.get_public_ip()

                    def save_token(tok):
                        self._persist_token(tok, machine_id, overwrite=False, reason="register")

                    token = register_client_api(
                        self.api_url,
                        self.server_name,
                        ip,
                        save_token,
                        log,
                        machine_id=machine_id,
                        machine_guid=machine_guid,
                    )
                    if token:
                        log(
                            f"[TOKEN] Registered durable identity "
                            f"(fingerprint={machine_id[:12]}...)"
                        )
                        return token

                    msg = "API kaydı başarısız. Tekrar deneniyor..."
                    if root_window:
                        try:
                            import tkinter.messagebox as messagebox
                            messagebox.showwarning("Uyarı", msg)
                        except Exception:
                            pass
                    log(msg)
                except Exception as e:
                    msg = f"API kaydı başarısız: {e}. Tekrar deneniyor..."
                    if root_window:
                        try:
                            import tkinter.messagebox as messagebox
                            messagebox.showwarning("Uyarı", msg)
                        except Exception:
                            pass
                    log(msg)
                time.sleep(5)

            if root_window and t_func:
                try:
                    import tkinter.messagebox as messagebox
                    messagebox.showwarning(t_func("warn"), t_func("api_registration_warning"))
                except Exception:
                    pass
            return None
        finally:
            _release_register_lock(lock_fd)

    def _rotate_in_place(self, old_token: str, reason: str) -> Optional[str]:
        """Contract 1.4.29: mint new uuid in memory, rotate on cloud, then write disk.

        Returns new token on success; None if rotate failed (caller must not
        discard old token.dat until quarantine is intentional).
        """
        import uuid as uuid_mod

        old_token = (old_token or "").strip()
        if not old_token:
            return None

        fp = get_device_fingerprint()
        # Legacy cloud rows may still store MachineGuid as machine_id.
        mid_candidates = [fp, "", get_windows_machine_guid()]

        for _uuid_try in range(2):
            new_token = str(uuid_mod.uuid4())
            saw_409 = False
            for mid in mid_candidates:
                result = rotate_token_api(
                    self.api_url,
                    old_token,
                    new_token,
                    machine_id=mid,
                    reason=reason,
                    log_func=log,
                )
                if result.get("ok"):
                    tok = (result.get("token") or new_token).strip()
                    self._persist_token(tok, fp, overwrite=True, reason=reason)
                    log(
                        f"[TOKEN] In-place rotate saved "
                        f"(reason={reason}, client_id={result.get('client_id')})"
                    )
                    return tok
                code = int(result.get("status_code") or 0)
                if code == 409:
                    log("[TOKEN] rotate 409 new_token_in_use — retrying with fresh uuid")
                    saw_409 = True
                    break
                if code == 403:
                    continue
                if code == 404:
                    log("[TOKEN] rotate 404 old_token_not_found")
                    return None
                # Network / 5xx / unexpected — keep old token on disk
                return None
            if not saw_409:
                log("[TOKEN] rotate failed for all machine_id candidates")
                return None
        return None

    def _reenroll(self, reason: str, root_window=None, t_func=None) -> Optional[str]:
        """Rekey identity: prefer in-place rotate; bare register only if old token gone.

        Contract 1.4.29 — never bare /register while old_token is still known
        (creates ghost Client + orphaned attack history / Account link).
        """
        log(f"[TOKEN] Re-enroll required ({reason})")
        old = self.get_token()
        if old:
            rotated = self._rotate_in_place(old, reason=reason)
            if rotated:
                return rotated
            # 404 / hard failure: forget local old token, then register reclaim
            log(
                f"[TOKEN] rotate failed for reason={reason} — "
                "quarantine local then register (old no longer usable)"
            )
            quarantine_local_identity(reason=reason)
            return self.register_client(root_window, t_func)

        quarantine_local_identity(reason=reason)
        return self.register_client(root_window, t_func)

    def ensure_hardware_binding(self, root_window=None, t_func=None) -> Optional[str]:
        """Bind token to hardware fingerprint; rekey via rotate-token (1.4.29).

        - CHP2 / binding fingerprint mismatch → clone or NIC change → re-enroll
        - schema < 2 → one-time in-place rotate under MAC-bound machine_id
        """
        fp = get_device_fingerprint()
        tok, bound_fp = TokenStore.load_meta(self.token_file_new)
        if not tok:
            tok = self.get_token()
            bound_fp = None
        if not tok:
            return None

        binding = _load_binding()
        bind_fp = str(binding.get("fingerprint") or "").strip()
        schema = int(binding.get("schema") or 0)

        if bound_fp and bound_fp != fp:
            log(
                f"[TOKEN] CHP2 fingerprint mismatch "
                f"(bound={bound_fp[:12]}... now={fp[:12]}...) - clone/hardware change"
            )
            return self._reenroll("fp_mismatch", root_window, t_func)

        if bind_fp and bind_fp != fp:
            log(
                f"[TOKEN] device_binding fingerprint mismatch "
                f"(bound={bind_fp[:12]}... now={fp[:12]}...) - clone/hardware change"
            )
            return self._reenroll("binding_mismatch", root_window, t_func)

        if schema < IDENTITY_SCHEMA_VERSION:
            log(
                "[TOKEN] Identity schema upgrade -> in-place rotate-token "
                "(contract 1.4.29; preserves client_id / Account link)"
            )
            return self._reenroll("identity_v2", root_window, t_func)

        # Already bound - refresh CHP2 envelope if still CHP1 on disk
        if not bound_fp:
            try:
                self._persist_token(tok, fp, overwrite=True, reason="chp2_upgrade")
            except Exception as e:
                log(f"[TOKEN] CHP2 upgrade save failed: {e}")
        elif not binding:
            _save_binding(fingerprint=fp, token=tok, reason="repair")

        return tok

    def load_token(self, root_window=None, t_func=None) -> Optional[str]:
        """Load durable token; register only if no token file exists anywhere."""
        tok = self.get_token()
        if tok:
            return self.ensure_hardware_binding(root_window, t_func)

        # Corrupt/unreadable canonical file → do not register
        if os.path.isfile(self.token_file_new):
            log("[TOKEN] Canonical token.dat present but unreadable - not re-registering")
            return None

        # Any legacy file present but unreadable → still do not mint
        for path in get_legacy_token_paths(self._app_dir_hint):
            if os.path.isfile(path):
                log(f"[TOKEN] Legacy token file present but unreadable ({path}) - not re-registering")
                return None

        log("[TOKEN] No durable token found - first-run registration")
        return self.register_client(root_window, t_func)


def create_token_manager(api_url: str, server_name: str, token_file_new: str, token_file_old: str) -> TokenManager:
    """Factory function to create TokenManager instance"""
    return TokenManager(api_url, server_name, token_file_new, token_file_old)
