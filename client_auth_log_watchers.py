# -*- coding: utf-8 -*-
"""Tail real-service auth logs that do not land in Security EventLog.

MySQL/MariaDB → ``*.err`` \"Access denied\".
IIS FTP → ``inetpub\\logs\\LogFiles\\FTPSVC*`` W3C lines with sc-status **530**.

Feeds ThreatEngine the same shape as EventLog fails so honeypot-off still
reports MYSQL / FTP brute force.
"""

from __future__ import annotations

import glob
import os
import re
import threading
import time
from typing import Callable, Dict, List, Optional, Tuple

from client_helpers import log

# Access denied for user 'root'@'203.0.113.10' (using password: YES)
_MYSQL_DENIED = re.compile(
    r"Access denied for user\s+'([^']*)'@'([^']+)'",
    re.IGNORECASE,
)

_MYSQL_GLOB_CANDIDATES = (
    r"C:\ProgramData\MySQL\MySQL Server *\Data\*.err",
    r"C:\Program Files\MySQL\MySQL Server *\data\*.err",
    r"C:\Program Files\MariaDB *\data\*.err",
    r"C:\ProgramData\MariaDB\*\data\*.err",
)

_FTP_GLOB_CANDIDATES = (
    r"C:\inetpub\logs\LogFiles\FTPSVC*\u_ex*.log",
    r"C:\inetpub\logs\LogFiles\FTPSVC*\*.log",
)

_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


class AuthLogWatcher:
    """Polls MySQL error logs + IIS FTP W3C logs → on_event callbacks."""

    def __init__(self, on_event: Callable[[dict], None], interval_sec: float = 5.0):
        self.on_event = on_event
        self.interval_sec = max(2.0, float(interval_sec))
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        # path → byte offset
        self._offsets: dict = {}
        self._seen_keys: dict = {}  # dedupe key → ts
        # path → W3C field names from last #Fields: line
        self._ftp_fields: Dict[str, List[str]] = {}

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop, name="AuthLogWatcher", daemon=True
        )
        self._thread.start()
        log("[AUTHLOG] MySQL + IIS FTP log watcher started")

    def stop(self) -> None:
        self._stop.set()
        t = self._thread
        if t and t.is_alive():
            t.join(timeout=3.0)
        self._thread = None

    def _loop(self) -> None:
        while not self._stop.wait(self.interval_sec):
            try:
                for path in self._discover_mysql_logs():
                    self._scan_file(path, kind="mysql")
                for path in self._discover_ftp_logs():
                    self._scan_file(path, kind="ftp")
            except Exception as exc:
                log(f"[AUTHLOG] scan error: {exc}")

    def _discover_mysql_logs(self) -> List[str]:
        return self._discover(_MYSQL_GLOB_CANDIDATES, limit=4)

    def _discover_ftp_logs(self) -> List[str]:
        return self._discover(_FTP_GLOB_CANDIDATES, limit=6)

    @staticmethod
    def _discover(patterns: Tuple[str, ...], limit: int) -> List[str]:
        found: List[str] = []
        for pattern in patterns:
            try:
                found.extend(glob.glob(pattern))
            except Exception:
                pass
        uniq = []
        seen = set()
        for p in sorted(
            found,
            key=lambda x: os.path.getmtime(x) if os.path.isfile(x) else 0,
            reverse=True,
        ):
            if p not in seen and os.path.isfile(p):
                seen.add(p)
                uniq.append(p)
        return uniq[:limit]

    def _scan_file(self, path: str, *, kind: str) -> None:
        try:
            size = os.path.getsize(path)
        except OSError:
            return
        offset = int(self._offsets.get(path, -1))
        if offset < 0:
            # First see: jump near end (last 64 KiB) to avoid historic flood
            offset = max(0, size - 65536)
            self._offsets[path] = offset
        if size < offset:
            offset = 0  # rotated
            self._ftp_fields.pop(path, None)
        if size == offset:
            return
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                fh.seek(offset)
                chunk = fh.read()
                self._offsets[path] = fh.tell()
        except OSError:
            return
        for line in chunk.splitlines():
            if kind == "mysql":
                self._emit_mysql_line(line)
            elif kind == "ftp":
                self._emit_ftp_line(path, line)

    def _emit_mysql_line(self, line: str) -> None:
        m = _MYSQL_DENIED.search(line or "")
        if not m:
            return
        username = (m.group(1) or "").strip() or "unknown"
        host = (m.group(2) or "").strip()
        if not host or host in ("localhost", "127.0.0.1", "::1"):
            return
        source_ip = host.split()[0] if host else ""
        if not source_ip or source_ip.startswith("/"):
            return
        self._emit_fail(
            service="MYSQL",
            source_ip=source_ip,
            username=username,
            port_default=3306,
            event_type="sql_failed_logon",
            channel="mysql_error_log",
            auth_package="mysql_native_password",
            logon_process="mysqld",
            line=line,
        )

    def _emit_ftp_line(self, path: str, line: str) -> None:
        text = (line or "").strip()
        if not text:
            return
        if text.startswith("#Fields:"):
            fields = text[len("#Fields:") :].strip().split()
            if fields:
                self._ftp_fields[path] = fields
            return
        if text.startswith("#"):
            return
        fields = self._ftp_fields.get(path)
        # Fallback W3C-ish: date time c-ip … sc-status often near end
        parts = text.split()
        if not parts:
            return
        source_ip = ""
        username = "unknown"
        status = ""
        s_port = 0
        if fields and len(parts) >= len(fields):
            row = {fields[i]: parts[i] for i in range(len(fields))}
            source_ip = str(row.get("c-ip") or row.get("cip") or "")
            username = str(row.get("cs-username") or row.get("cs-user") or "unknown")
            status = str(row.get("sc-status") or row.get("sc-ftpstatus") or "")
            try:
                s_port = int(row.get("s-port") or row.get("serverport") or 0)
            except (TypeError, ValueError):
                s_port = 0
        else:
            # Heuristic: look for 530 token and first IPv4
            if "530" not in parts:
                return
            status = "530"
            for tok in parts:
                if _IPV4_RE.match(tok) and tok not in ("127.0.0.1",):
                    source_ip = tok
                    break
            # username often after IP in IIS FTP logs — best effort
            if source_ip and source_ip in parts:
                idx = parts.index(source_ip)
                if idx + 1 < len(parts) and parts[idx + 1] not in ("-", "PASS", "USER"):
                    username = parts[idx + 1]
        if status != "530":
            return
        if not source_ip or source_ip in ("127.0.0.1", "::1", "-"):
            return
        if username in ("", "-", "anonymous"):
            # still report anonymous 530 spray — use literal
            username = username if username and username != "-" else "anonymous"
        self._emit_fail(
            service="FTP",
            source_ip=source_ip,
            username=username,
            port_default=int(s_port) if s_port > 0 else 21,
            event_type="failed_logon",
            channel="iis_ftp_w3c",
            auth_package="ftp",
            logon_process="ftpsvc",
            line=text,
        )

    def _emit_fail(
        self,
        *,
        service: str,
        source_ip: str,
        username: str,
        port_default: int,
        event_type: str,
        channel: str,
        auth_package: str,
        logon_process: str,
        line: str,
    ) -> None:
        now = time.time()
        dedup = f"{service}|{source_ip}|{username.lower()}"
        last = float(self._seen_keys.get(dedup, 0))
        if now - last < 10.0:
            return
        self._seen_keys[dedup] = now
        if len(self._seen_keys) > 2048:
            cutoff = now - 600
            self._seen_keys = {k: t for k, t in self._seen_keys.items() if t >= cutoff}
        try:
            from client_service_ports import get_listen_port
            port = get_listen_port(service, port_default)
        except Exception:
            port = port_default
        if port <= 0:
            port = port_default
        event = {
            "event_id": 0,
            "event_type": event_type,
            "channel": channel,
            "source_ip": source_ip,
            "username": username,
            "target_service": service,
            "target_port": int(port),
            "result": "failure",
            "logon_type": None,
            "auth_package": auth_package,
            "logon_process": logon_process,
            "status": "530" if service == "FTP" else "",
            "substatus": "",
            "workstation": "",
            "raw_data": {"line": (line or "")[:240]},
        }
        try:
            self.on_event(event)
        except Exception as exc:
            log(f"[AUTHLOG] on_event error: {exc}")
