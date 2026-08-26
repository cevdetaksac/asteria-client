# -*- coding: utf-8 -*-
"""Real listen-port cache for Attack reports (relocate-aware).

Bait honeypot ports and real service ports are independent. When TermService
was moved to 43389, EventLog RDP fails must report port 43389 — not bait 3389.
"""

from __future__ import annotations

import threading
from typing import Dict, List, Optional

_lock = threading.Lock()
# Uppercased service → current listen port
_PORTS: Dict[str, int] = {
    "RDP": 3389,
    "SSH": 22,
    "FTP": 21,
    "MYSQL": 3306,
    "MSSQL": 1433,
    "NETWORK": 445,
    "SMB": 445,
    "HTTP": 80,
}

# Process image hints from open_ports collection
_PROC_TO_SERVICE = {
    "termservice": "RDP",
    "svchost": None,  # ambiguous — only use with port match below
    "sshd": "SSH",
    "sshd.exe": "SSH",
    "ssh.exe": "SSH",
    "mysqld": "MYSQL",
    "mysqld.exe": "MYSQL",
    "sqlservr": "MSSQL",
    "sqlservr.exe": "MSSQL",
    "ftpsvc": "FTP",
    "filezilla": "FTP",
    "filezilla server.exe": "FTP",
}


def get_listen_port(service: str, default: int = 0) -> int:
    key = (service or "").strip().upper()
    if not key:
        return int(default or 0)
    with _lock:
        val = int(_PORTS.get(key, 0) or 0)
    if val > 0:
        return val
    return int(default or 0)


def set_listen_port(service: str, port: int) -> None:
    key = (service or "").strip().upper()
    try:
        p = int(port)
    except (TypeError, ValueError):
        return
    if not key or p <= 0 or p > 65535:
        return
    with _lock:
        _PORTS[key] = p


def refresh_rdp_from_registry() -> Optional[int]:
    """Read TermService RDP-Tcp PortNumber (relocate golden)."""
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
            0,
            winreg.KEY_READ,
        )
        try:
            val, _ = winreg.QueryValueEx(key, "PortNumber")
            port = int(val)
        finally:
            winreg.CloseKey(key)
        if 1 <= port <= 65535:
            set_listen_port("RDP", port)
            return port
    except Exception:
        pass
    return None


def update_from_open_ports(ports: List[dict]) -> None:
    """Best-effort map LISTEN rows → service ports."""
    if not isinstance(ports, list):
        return
    refresh_rdp_from_registry()
    for row in ports:
        if not isinstance(row, dict):
            continue
        try:
            port = int(row.get("port") or 0)
        except (TypeError, ValueError):
            continue
        if port <= 0:
            continue
        proc = str(row.get("process") or row.get("name") or "").strip().lower()
        # Strip path
        if "\\" in proc:
            proc = proc.rsplit("\\", 1)[-1]
        svc = _PROC_TO_SERVICE.get(proc)
        if svc:
            set_listen_port(svc, port)
            continue
        # Well-known ports if process unknown
        if port == 22:
            set_listen_port("SSH", port)
        elif port == 21:
            set_listen_port("FTP", port)
        elif port == 3306:
            set_listen_port("MYSQL", port)
        elif port == 1433:
            set_listen_port("MSSQL", port)
        elif port in (3389, 43389) or (40000 <= port < 50000 and "rdp" in proc):
            set_listen_port("RDP", port)


def snapshot() -> Dict[str, int]:
    with _lock:
        return dict(_PORTS)
