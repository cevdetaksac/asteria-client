"""Autologon break-glass helper (contract ≥4.6.0 — agent/disaster-recovery.md).

Arms a one-shot Windows autologon so a Session 0 daemon can create a fresh
interactive session after a reboot (the only service-feasible way to get a
desktop from zero sessions). Password is stored as an LSA secret
("DefaultPassword") when possible — never plaintext registry unless LSA fails.
`AutoLogonCount` makes it single-use; the daemon also clears it on next boot.

Public API:
    arm_autologon(username, password, domain=".", count=1) -> {"ok": bool, "error": str}
    clear_autologon() -> {"ok": bool, "error": str}
    write_pending_marker(username, command_id) -> None
    read_pending_marker() -> dict | None
    clear_pending_marker() -> None
"""

from __future__ import annotations

import json
import os
import winreg
from typing import Optional

try:
    from client_helpers import log
except Exception:  # pragma: no cover
    def log(*_a, **_k):
        pass

try:
    from client_constants import MACHINE_DATA_DIR
except Exception:  # pragma: no cover
    MACHINE_DATA_DIR = os.path.join(
        os.environ.get("ProgramData", r"C:\ProgramData"),
        "Asteria",
    )

_WINLOGON = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
_PENDING = os.path.join(MACHINE_DATA_DIR, "autologon_pending.json")
_LSA_KEY = "DefaultPassword"


# ── LSA secret (preferred password store) ───────────────────────────

def _lsa_store_password(password: Optional[str]) -> bool:
    """Store (or clear when None) the DefaultPassword LSA secret."""
    try:
        import win32security
        POLICY = win32security.POLICY_CREATE_SECRET | win32security.POLICY_GET_PRIVATE_INFORMATION
        policy = win32security.LsaOpenPolicy(None, POLICY)
        try:
            if password is None:
                win32security.LsaStorePrivateData(policy, _LSA_KEY, None)
            else:
                # LSA private data is raw bytes; Winlogon expects UTF-16-LE
                win32security.LsaStorePrivateData(
                    policy, _LSA_KEY, password.encode("utf-16-le")
                )
            return True
        finally:
            win32security.LsaClose(policy)
    except Exception as e:
        log(f"[AUTOLOGON] LSA store failed: {e}")
        return False


# ── Winlogon registry ────────────────────────────────────────────────

def _open_winlogon(access):
    return winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _WINLOGON, 0, access)


def _set_sz(key, name, value):
    winreg.SetValueEx(key, name, 0, winreg.REG_SZ, str(value))


def _set_dword(key, name, value):
    winreg.SetValueEx(key, name, 0, winreg.REG_DWORD, int(value))


def _del_value(key, name):
    try:
        winreg.DeleteValue(key, name)
    except FileNotFoundError:
        pass
    except OSError:
        pass


def arm_autologon(username: str, password: str, domain: str = ".", count: int = 1) -> dict:
    """Arm a one-shot autologon. Returns {"ok": bool, "error": str|None}."""
    username = (username or "").strip()
    if not username:
        return {"ok": False, "error": "missing_username"}
    domain = (domain or ".").strip() or "."
    count = max(1, int(count or 1))

    lsa_ok = _lsa_store_password(password)
    try:
        key = _open_winlogon(winreg.KEY_SET_VALUE)
        try:
            _set_sz(key, "DefaultUserName", username)
            _set_sz(key, "DefaultDomainName", domain)
            _set_sz(key, "AutoAdminLogon", "1")
            _set_dword(key, "AutoLogonCount", count)
            if lsa_ok:
                # ensure no stale plaintext copy remains
                _del_value(key, "DefaultPassword")
            else:
                # fallback: plaintext registry (last resort)
                _set_sz(key, "DefaultPassword", password)
                log("[AUTOLOGON] WARNING: fell back to plaintext DefaultPassword")
        finally:
            winreg.CloseKey(key)
        log(f"[AUTOLOGON] armed user={username} domain={domain} count={count} lsa={lsa_ok}")
        return {"ok": True, "error": None, "lsa": lsa_ok}
    except Exception as e:
        log(f"[AUTOLOGON] arm failed: {e}")
        return {"ok": False, "error": str(e)}


def clear_autologon() -> dict:
    """Remove all autologon artifacts (registry + LSA secret + marker)."""
    _lsa_store_password(None)
    try:
        key = _open_winlogon(winreg.KEY_SET_VALUE)
        try:
            _set_sz(key, "AutoAdminLogon", "0")
            _del_value(key, "AutoLogonCount")
            _del_value(key, "DefaultPassword")
            # leave DefaultUserName/DefaultDomainName (harmless without AutoAdminLogon)
        finally:
            winreg.CloseKey(key)
        clear_pending_marker()
        log("[AUTOLOGON] cleared")
        return {"ok": True, "error": None}
    except Exception as e:
        log(f"[AUTOLOGON] clear failed: {e}")
        return {"ok": False, "error": str(e)}


# ── Pending marker (survives reboot; consumed by daemon on next boot) ──

def write_pending_marker(username: str, command_id: str = "") -> None:
    try:
        os.makedirs(MACHINE_DATA_DIR, exist_ok=True)
        import time as _t
        with open(_PENDING, "w", encoding="utf-8") as f:
            json.dump({
                "username": username,
                "command_id": command_id,
                "requested_at": _t.strftime("%Y-%m-%dT%H:%M:%SZ", _t.gmtime()),
                "one_shot": True,
            }, f)
    except Exception as e:
        log(f"[AUTOLOGON] marker write failed: {e}")


def read_pending_marker() -> Optional[dict]:
    try:
        if not os.path.exists(_PENDING):
            return None
        with open(_PENDING, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def clear_pending_marker() -> None:
    try:
        if os.path.exists(_PENDING):
            os.remove(_PENDING)
    except Exception:
        pass
