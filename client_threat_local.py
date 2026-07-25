# -*- coding: utf-8 -*-
"""Threat Center local inventory — SMB shares + third-party services.

Runs under the SYSTEM motor (GUI IPC). Mirrors the old CTk collectors in
``client_gui.py`` but keeps privilege/protection rules aligned with remote
``stop_service`` (PROTECTED_SERVICES).
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from typing import Any, Dict, List, Optional, Set

CREATE_NO_WINDOW = 0x08000000

DEFAULT_SHARES: Set[str] = {"ADMIN$", "C$", "IPC$", "D$", "E$"}

SAFE_PATH_PREFIXES = (
    "c:\\windows\\",
    "c:\\program files\\common files\\microsoft",
    "c:\\program files\\windows",
    "\\systemroot\\",
    "c:\\windows\\system32\\",
    "c:\\windows\\syswow64\\",
)

KNOWN_SAFE_TOKENS = (
    "mysql", "mssql", "sqlserver", "apache", "nginx", "iis",
    "maestropanel", "google", "chrome", "honeypot", "yesnext",
    "asteria", "sqlbackup", "php", "node", "cloudflare", "defender",
    "postgresql", "mongod", "redis", "docker", "vmware", "virtualbox",
)

# Soft cap for Threat Center UI (unknown first).
MAX_THIRD_PARTY_ROWS = 20


def _run_ps(script: str, timeout: float = 15.0) -> tuple[int, str, str]:
    try:
        from client_winproc import run_ps, run_ps_script
        if "\n" in script or len(script) > 400:
            return run_ps_script(script, timeout=timeout)
        return run_ps(script, timeout=timeout)
    except Exception:
        # Fallback without client_winproc
        encoded = script
        try:
            result = subprocess.run(
                [
                    "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                    "-Command", encoded,
                ],
                capture_output=True, text=True, timeout=timeout,
                creationflags=CREATE_NO_WINDOW,
            )
            return result.returncode, result.stdout or "", result.stderr or ""
        except Exception as e:
            return 1, "", str(e)


def _parse_json_list(raw: str) -> List[Dict[str, Any]]:
    text = (raw or "").strip()
    if not text:
        return []
    try:
        data = json.loads(text)
    except Exception:
        return []
    if isinstance(data, dict):
        return [data]
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    return []


def _safe_share_name(name: str) -> Optional[str]:
    n = str(name or "").strip()
    if not n or len(n) > 80:
        return None
    if not re.match(r"^[\w.\-$]+$", n, re.UNICODE):
        return None
    return n


def list_smb_shares() -> Dict[str, Any]:
    """Return SMB shares for Threat Center."""
    rc, out, err = _run_ps(
        "Get-SmbShare | Select-Object Name, Path, Description, "
        "ShareType, CurrentUsers | ConvertTo-Json",
        timeout=12.0,
    )
    if rc != 0:
        return {
            "ok": False,
            "error": (err or out or "get_smbshare_failed")[:200],
            "shares": [],
            "custom_count": 0,
        }

    rows: List[Dict[str, Any]] = []
    for item in _parse_json_list(out):
        name = str(item.get("Name") or "").strip()
        if not name:
            continue
        is_default = name.upper() in {s.upper() for s in DEFAULT_SHARES}
        rows.append({
            "name": name,
            "path": str(item.get("Path") or ""),
            "description": str(item.get("Description") or ""),
            "share_type": str(item.get("ShareType") or ""),
            "current_users": int(item.get("CurrentUsers") or 0),
            "is_default": is_default,
        })

    custom = sum(1 for r in rows if not r["is_default"])
    return {
        "ok": True,
        "shares": rows,
        "custom_count": custom,
        "default_only": custom == 0 and len(rows) > 0,
    }


def remove_smb_share(name: str) -> Dict[str, Any]:
    """Remove a non-default SMB share."""
    share = _safe_share_name(name)
    if not share:
        return {"ok": False, "error": "invalid_share_name"}
    if share.upper() in {s.upper() for s in DEFAULT_SHARES}:
        return {"ok": False, "error": "default_share_protected", "name": share}

    # Escape for single-quoted PowerShell string
    escaped = share.replace("'", "''")
    rc, out, err = _run_ps(
        f"Remove-SmbShare -Name '{escaped}' -Force",
        timeout=15.0,
    )
    if rc != 0:
        return {
            "ok": False,
            "error": (err or out or "remove_failed")[:200],
            "name": share,
        }
    return {"ok": True, "name": share}


def _protected_names() -> Set[str]:
    names = {"wuauserv", "windefend", "eventlog", "mpssvc", "cloudhoneypotguardian"}
    try:
        from client_remote_commands import PROTECTED_SERVICES
        names |= {s.lower() for s in PROTECTED_SERVICES}
    except Exception:
        pass
    # Never stop our own stack from Threat Center
    names |= {
        "asteriaguardian", "cloudhoneypotguardian",
        "asteria-client", "honeypot-client",
    }
    return names


def list_third_party_services(*, max_rows: int = MAX_THIRD_PARTY_ROWS) -> Dict[str, Any]:
    """Running non-Microsoft services (Threat Center filter)."""
    script = (
        "Get-CimInstance Win32_Service | "
        "Where-Object { $_.State -eq 'Running' } | "
        "Select-Object Name, DisplayName, PathName, StartMode, StartName | "
        "ConvertTo-Json -Depth 2"
    )
    rc, out, err = _run_ps(script, timeout=22.0)
    if rc != 0:
        return {
            "ok": False,
            "error": (err or out or "cim_failed")[:200],
            "services": [],
            "unknown_count": 0,
        }

    third: List[Dict[str, Any]] = []
    for svc in _parse_json_list(out):
        path = str(svc.get("PathName") or "").lower()
        name = str(svc.get("Name") or "")
        name_l = name.lower()
        display = str(svc.get("DisplayName") or name)
        if any(path.startswith(sp) for sp in SAFE_PATH_PREFIXES):
            continue
        # Strip quoted exe path for known-safe matching
        path_for_match = path.strip('"')
        is_known = any(k in name_l or k in path_for_match for k in KNOWN_SAFE_TOKENS)
        third.append({
            "name": name,
            "display": display,
            "path": str(svc.get("PathName") or ""),
            "start_mode": str(svc.get("StartMode") or ""),
            "account": str(svc.get("StartName") or ""),
            "known": is_known,
            "status": "Running",
        })

    # Unknown first, then known
    third.sort(key=lambda r: (1 if r.get("known") else 0, str(r.get("display") or "").lower()))
    unknown = sum(1 for r in third if not r.get("known"))
    return {
        "ok": True,
        "services": third[: max(1, int(max_rows))],
        "total_matched": len(third),
        "unknown_count": unknown,
    }


def stop_windows_service(name: str) -> Dict[str, Any]:
    """Stop a service with PROTECTED_SERVICES guard (same as remote stop_service)."""
    svc = str(name or "").strip()
    if not svc or len(svc) > 128:
        return {"ok": False, "error": "invalid_service_name"}
    if svc.lower() in _protected_names():
        return {"ok": False, "error": "PROTECTED_SERVICE", "name": svc}

    try:
        result = subprocess.run(
            ["sc", "stop", svc],
            capture_output=True, text=True, timeout=15,
            creationflags=CREATE_NO_WINDOW,
        )
        ok = result.returncode == 0
        err = (result.stderr or result.stdout or "").strip()
        if not ok:
            return {
                "ok": False,
                "error": err[:200] or "FAILED",
                "name": svc,
            }
        return {"ok": True, "name": svc, "status": "stop_pending"}
    except Exception as e:
        return {"ok": False, "error": str(e), "name": svc}
