# -*- coding: utf-8 -*-
"""Tail real-service auth logs that do not land in Security EventLog.

MySQL/MariaDB → ``*.err`` / ``*.log`` \"Access denied\".
IIS FTP → ``inetpub\\logs\\LogFiles\\FTPSVC*`` W3C lines with sc-status **530**.
MSSQL → ``ERRORLOG*`` \"Login failed for user … [CLIENT: ip]\".

Optional lab overrides:
  ``ASTERIA_AUTHLOG_EXTRA`` — ``;``-separated glob patterns
  ``%ProgramData%\\Asteria\\authlog_probe\\{mysql,ftp,mssql}\\*``

Feeds ThreatEngine the same shape as EventLog fails so honeypot-off still
reports MYSQL / FTP / MSSQL brute force.
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

# Login failed for user 'sa'. Reason: ... [CLIENT: 203.0.113.1]
_MSSQL_LOGIN_FAILED = re.compile(
    r"Login failed for user\s+'([^']*)'.*?\[CLIENT:\s*([^\]]+)\]",
    re.IGNORECASE | re.DOTALL,
)
_MSSQL_LOGIN_FAILED_SIMPLE = re.compile(
    r"Login failed for user\s+'([^']*)'\.",
    re.IGNORECASE,
)
_MSSQL_CLIENT_IP = re.compile(r"\[CLIENT:\s*([^\]]+)\]", re.IGNORECASE)

# Prefer *.err — Access denied lives in the error log. Avoid *-slow.log / general log noise.
_MYSQL_GLOB_CANDIDATES = (
    r"C:\ProgramData\MySQL\MySQL Server *\Data\*.err",
    r"C:\Program Files\MySQL\MySQL Server *\data\*.err",
    r"C:\Program Files\MariaDB *\data\*.err",
    r"C:\ProgramData\MariaDB\*\data\*.err",
    r"C:\xampp\mysql\data\*.err",
    r"C:\wamp64\bin\mysql\mysql*\data\*.err",
    r"C:\laragon\data\mysql*\*.err",
    # my.ini / config locations (resolved in _discover_mysql_from_ini)
)

_MYSQL_INI_GLOBS = (
    r"C:\ProgramData\MySQL\MySQL Server *\my.ini",
    r"C:\ProgramData\MySQL\MySQL Server *\my.cnf",
    r"C:\Program Files\MySQL\MySQL Server *\my.ini",
    r"C:\Program Files\MariaDB *\my.ini",
    r"C:\Program Files\MariaDB *\data\my.ini",
    r"C:\xampp\mysql\bin\my.ini",
)

_FTP_GLOB_CANDIDATES = (
    r"C:\inetpub\logs\LogFiles\FTPSVC*\u_ex*.log",
    r"C:\inetpub\logs\LogFiles\FTPSVC*\*.log",
)

# Default SQL Server instance + named instances
_MSSQL_GLOB_CANDIDATES = (
    r"C:\Program Files\Microsoft SQL Server\MSSQL*\MSSQL\Log\ERRORLOG",
    r"C:\Program Files\Microsoft SQL Server\MSSQL*\MSSQL\Log\ERRORLOG.*",
    r"C:\Program Files (x86)\Microsoft SQL Server\MSSQL*\MSSQL\Log\ERRORLOG",
    r"C:\Program Files (x86)\Microsoft SQL Server\MSSQL*\MSSQL\Log\ERRORLOG.*",
)

# Skip non-auth MySQL logs that match broad *.log globs
_MYSQL_SKIP_NAME_RE = re.compile(
    r"(?:-slow\.log$|\.pid$|ib_logfile|binlog|relay-log|general\.log$)",
    re.IGNORECASE,
)

_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_LOOPBACK = frozenset({"localhost", "127.0.0.1", "::1", "-", ""})


def _programdata_probe_globs() -> Tuple[str, ...]:
    root = os.environ.get("PROGRAMDATA") or r"C:\ProgramData"
    base = os.path.join(root, "Asteria", "authlog_probe")
    return (
        os.path.join(base, "mysql", "*"),
        os.path.join(base, "ftp", "*"),
        os.path.join(base, "mssql", "*"),
    )


def _env_extra_globs() -> Tuple[str, ...]:
    raw = (os.environ.get("ASTERIA_AUTHLOG_EXTRA") or "").strip()
    if not raw:
        return ()
    return tuple(p.strip() for p in raw.split(";") if p.strip())


class AuthLogWatcher:
    """Polls MySQL / IIS FTP / MSSQL ERRORLOG → on_event callbacks."""

    def __init__(
        self,
        on_event: Callable[[dict], None],
        interval_sec: float = 5.0,
        extra_globs: Optional[Tuple[str, ...]] = None,
    ):
        self.on_event = on_event
        self.interval_sec = max(2.0, float(interval_sec))
        self._extra_globs = tuple(extra_globs or ())
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        # path → byte offset
        self._offsets: dict = {}
        self._seen_keys: dict = {}  # dedupe key → ts
        # path → W3C field names from last #Fields: line
        self._ftp_fields: Dict[str, List[str]] = {}
        self._last_discover: Dict[str, List[str]] = {
            "mysql": [],
            "ftp": [],
            "mssql": [],
        }
        self._stats = {
            "scans": 0,
            "emits": 0,
            "errors": 0,
            "started_at": 0.0,
        }

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._stats["started_at"] = time.time()
        self._thread = threading.Thread(
            target=self._loop, name="AuthLogWatcher", daemon=True
        )
        self._thread.start()
        paths = self.discover_status()
        log(
            "[AUTHLOG] MySQL + IIS FTP + MSSQL ERRORLOG watcher started "
            f"(mysql={len(paths['mysql'])} ftp={len(paths['ftp'])} "
            f"mssql={len(paths['mssql'])})"
        )

    def stop(self) -> None:
        self._stop.set()
        t = self._thread
        if t and t.is_alive():
            t.join(timeout=3.0)
        self._thread = None

    def discover_status(self) -> Dict[str, List[str]]:
        """Return currently discoverable log paths (for health / lab)."""
        return {
            "mysql": self._discover_mysql_logs(),
            "ftp": self._discover_ftp_logs(),
            "mssql": self._discover_mssql_logs(),
        }

    def get_health(self) -> dict:
        paths = self.discover_status()
        denied_tail = self._sample_mysql_denied_tail(paths["mysql"])
        hint = ""
        if paths["mysql"] and denied_tail == 0:
            hint = (
                "MySQL error log found but no 'Access denied' in recent tail — "
                "set log_error_verbosity=3 under [mysqld] and restart MySQL "
                "(MySQL 8 defaults hide auth Notes)."
            )
        return {
            "running": bool(self._thread and self._thread.is_alive()),
            "interval_sec": self.interval_sec,
            "mysql_paths": paths["mysql"][:8],
            "ftp_paths": paths["ftp"][:8],
            "mssql_paths": paths["mssql"][:8],
            "mysql_count": len(paths["mysql"]),
            "ftp_count": len(paths["ftp"]),
            "mssql_count": len(paths["mssql"]),
            "mysql_access_denied_tail": denied_tail,
            "mysql_logging_hint": hint,
            "attempts": int(self._stats.get("attempts", 0)),
            "scans": int(self._stats.get("scans", 0)),
            "emits": int(self._stats.get("emits", 0)),
            "errors": int(self._stats.get("errors", 0)),
        }

    def _loop(self) -> None:
        warned_mysql_verbosity = False
        while not self._stop.wait(self.interval_sec):
            try:
                self._stats["scans"] = int(self._stats.get("scans", 0)) + 1
                mysql = self._discover_mysql_logs()
                ftp = self._discover_ftp_logs()
                mssql = self._discover_mssql_logs()
                self._last_discover = {"mysql": mysql, "ftp": ftp, "mssql": mssql}
                if (
                    mysql
                    and not warned_mysql_verbosity
                    and self._sample_mysql_denied_tail(mysql) == 0
                ):
                    log(
                        "[AUTHLOG] MySQL err log present but no Access denied in tail — "
                        "likely log_error_verbosity<3; auth fails will not hit Attacks"
                    )
                    warned_mysql_verbosity = True
                for path in mysql:
                    self._scan_file(path, kind="mysql")
                for path in ftp:
                    self._scan_file(path, kind="ftp")
                for path in mssql:
                    self._scan_file(path, kind="mssql")
            except Exception as exc:
                self._stats["errors"] = int(self._stats.get("errors", 0)) + 1
                log(f"[AUTHLOG] scan error: {exc}")

    def _discover_mysql_logs(self) -> List[str]:
        probes = _programdata_probe_globs()
        found = self._discover(
            _MYSQL_GLOB_CANDIDATES
            + (probes[0],)
            + self._extra_for("mysql"),
            limit=16,
            kind="mysql",
        )
        # Merge my.ini-resolved paths (log-error / datadir\*.err)
        for p in self._discover_mysql_from_ini():
            if p not in found and os.path.isfile(p):
                found.append(p)
        return found[:8]

    def _discover_ftp_logs(self) -> List[str]:
        probes = _programdata_probe_globs()
        return self._discover(
            _FTP_GLOB_CANDIDATES
            + (probes[1],)
            + self._extra_for("ftp"),
            limit=8,
        )

    def _discover_mssql_logs(self) -> List[str]:
        probes = _programdata_probe_globs()
        found = self._discover(
            _MSSQL_GLOB_CANDIDATES
            + (probes[2],)
            + self._extra_for("mssql"),
            limit=16,
        )
        for p in self._discover_mssql_from_registry():
            if p not in found and os.path.isfile(p):
                found.append(p)
        return found[:8]

    def _extra_for(self, kind: str) -> Tuple[str, ...]:
        """Ctor extras + ASTERIA_AUTHLOG_EXTRA, filtered by kind keywords."""
        candidates = list(self._extra_globs) + list(_env_extra_globs())
        out: List[str] = []
        for g in candidates:
            gl = g.lower().replace("\\", "/")
            if kind == "mysql":
                if any(k in gl for k in ("mysql", ".err", "authlog_probe/mysql")):
                    out.append(g)
            elif kind == "ftp":
                if any(k in gl for k in ("ftp", "ftpsvc", "authlog_probe/ftp")):
                    out.append(g)
            elif kind == "mssql":
                if any(k in gl for k in ("mssql", "errorlog", "authlog_probe/mssql")):
                    out.append(g)
        return tuple(out)

    @staticmethod
    def _discover(
        patterns: Tuple[str, ...],
        limit: int,
        kind: str = "",
    ) -> List[str]:
        found: List[str] = []
        for pattern in patterns:
            try:
                found.extend(glob.glob(pattern))
            except Exception:
                pass
        uniq: List[str] = []
        seen = set()
        for p in sorted(
            found,
            key=lambda x: os.path.getmtime(x) if os.path.isfile(x) else 0,
            reverse=True,
        ):
            if p in seen or not os.path.isfile(p):
                continue
            if kind == "mysql" and _MYSQL_SKIP_NAME_RE.search(os.path.basename(p) or ""):
                continue
            seen.add(p)
            uniq.append(p)
        return uniq[:limit]

    @staticmethod
    def _discover_mysql_from_ini() -> List[str]:
        """Resolve log-error / datadir from my.ini (Derin: Server 8.04 style)."""
        out: List[str] = []
        ini_files: List[str] = []
        for pattern in _MYSQL_INI_GLOBS:
            try:
                ini_files.extend(glob.glob(pattern))
            except Exception:
                pass
        for ini in ini_files[:12]:
            try:
                with open(ini, "r", encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
            except OSError:
                continue
            datadir = ""
            log_error = ""
            in_mysqld = False
            for raw in text.splitlines():
                line = raw.strip()
                if not line or line.startswith("#") or line.startswith(";"):
                    continue
                low = line.lower()
                if low.startswith("[") and low.endswith("]"):
                    in_mysqld = low in ("[mysqld]", "[mysqld_safe]", "[server]")
                    continue
                if not in_mysqld:
                    continue
                if low.startswith("datadir") and "=" in line:
                    datadir = line.split("=", 1)[1].strip().strip('"').strip("'")
                elif low.startswith("log-error") or low.startswith("log_error"):
                    if "=" in line:
                        log_error = line.split("=", 1)[1].strip().strip('"').strip("'")
            if log_error:
                # Absolute or relative to datadir
                if os.path.isabs(log_error) and os.path.isfile(log_error):
                    out.append(log_error)
                elif datadir:
                    cand = os.path.join(datadir, log_error)
                    if os.path.isfile(cand):
                        out.append(cand)
                    # Windows often uses bare name without .err
                    if not log_error.lower().endswith(".err"):
                        cand2 = cand + ".err"
                        if os.path.isfile(cand2):
                            out.append(cand2)
            if datadir and os.path.isdir(datadir):
                try:
                    for name in os.listdir(datadir):
                        if name.lower().endswith(".err"):
                            out.append(os.path.join(datadir, name))
                except OSError:
                    pass
        # Dedupe preserve order
        seen = set()
        uniq = []
        for p in out:
            rp = os.path.normpath(p)
            if rp in seen:
                continue
            seen.add(rp)
            uniq.append(rp)
        return uniq

    @staticmethod
    def _discover_mssql_from_registry() -> List[str]:
        """Find ERRORLOG via SQL Server instance registry (custom install dirs)."""
        out: List[str] = []
        try:
            import winreg  # type: ignore
        except ImportError:
            return out
        roots = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Microsoft SQL Server"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Microsoft SQL Server"),
        ]
        instance_names: List[str] = []
        for hive, path in roots:
            try:
                with winreg.OpenKey(hive, path + r"\Instance Names\SQL") as key:
                    i = 0
                    while True:
                        try:
                            _name, value, _ = winreg.EnumValue(key, i)
                            if value:
                                instance_names.append(str(value))
                            i += 1
                        except OSError:
                            break
            except OSError:
                continue
        for inst in instance_names:
            for hive, path in roots:
                try:
                    with winreg.OpenKey(
                        hive, path + rf"\{inst}\Setup"
                    ) as key:
                        sql_path, _ = winreg.QueryValueEx(key, "SQLPath")
                except OSError:
                    continue
                # SQLPath is often ...\MSSQL — Log\ERRORLOG sits under it
                for rel in (
                    r"Log\ERRORLOG",
                    r"MSSQL\Log\ERRORLOG",
                ):
                    cand = os.path.join(str(sql_path), rel)
                    if os.path.isfile(cand):
                        out.append(cand)
        seen = set()
        uniq = []
        for p in out:
            rp = os.path.normpath(p)
            if rp in seen:
                continue
            seen.add(rp)
            uniq.append(rp)
        return uniq

    @staticmethod
    def _sample_mysql_denied_tail(paths: List[str], nbytes: int = 262144) -> int:
        """Count Access denied hits in the last nbytes of each mysql err log."""
        total = 0
        for path in paths[:4]:
            try:
                size = os.path.getsize(path)
                with open(path, "rb") as fh:
                    start = max(0, size - nbytes)
                    fh.seek(start)
                    chunk = fh.read().decode("utf-8", errors="replace")
                total += len(_MYSQL_DENIED.findall(chunk))
            except OSError:
                continue
        return total

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
            elif kind == "mssql":
                self._emit_mssql_line(line)

    def _emit_mysql_line(self, line: str) -> None:
        m = _MYSQL_DENIED.search(line or "")
        if not m:
            return
        username = (m.group(1) or "").strip() or "unknown"
        host = (m.group(2) or "").strip()
        source_ip = self._normalize_source_host(host)
        if not source_ip:
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

    def _emit_mssql_line(self, line: str) -> None:
        text = line or ""
        if "Login failed for user" not in text and "login failed for user" not in text.lower():
            return
        m = _MSSQL_LOGIN_FAILED.search(text)
        if m:
            username = (m.group(1) or "").strip() or "unknown"
            source_ip = self._normalize_source_host((m.group(2) or "").strip())
        else:
            m2 = _MSSQL_LOGIN_FAILED_SIMPLE.search(text)
            if not m2:
                return
            username = (m2.group(1) or "").strip() or "unknown"
            cm = _MSSQL_CLIENT_IP.search(text)
            source_ip = self._normalize_source_host(cm.group(1).strip() if cm else "")
        if not source_ip:
            return
        self._emit_fail(
            service="MSSQL",
            source_ip=source_ip,
            username=username,
            port_default=1433,
            event_type="sql_failed_logon",
            channel="mssql_errorlog",
            auth_package="sql_login",
            logon_process="sqlservr",
            line=text,
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
        source_ip = self._normalize_source_host(source_ip)
        if not source_ip:
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

    @staticmethod
    def _normalize_source_host(host: str) -> str:
        """Return a reportable attacker IP; drop loopback / empty."""
        h = (host or "").strip().strip("[]")
        if not h or h.lower() in _LOOPBACK:
            return ""
        # MySQL sometimes logs "host" with trailing spaces / local pipe
        if h.startswith("/") or h.lower() in ("local", "localmachine"):
            return ""
        # Keep IPv4 as-is; hostnames kept so ThreatEngine still has source
        if _IPV4_RE.match(h):
            return h
        # IPv6 compressed — pass through if not loopback
        if ":" in h and h not in ("::1",):
            return h
        # Hostname from MySQL (skip-name-resolve off) → resolve to an IP so the
        # rule engine / firewall can actually block it. Unresolvable → keep name.
        if h.lower() not in _LOOPBACK:
            ip = resolve_host_cached(h)
            if ip and ip not in ("127.0.0.1",):
                return ip
            return h
        return ""

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
        # Every attempt feeds the rule engine (burst = N attempts, not 1).
        # Attacks-list / e-mail rate limiting happens in ThreatEngine reporting.
        self._stats["attempts"] = int(self._stats.get("attempts", 0)) + 1
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
            "status": "530" if service == "FTP" else ("18456" if service == "MSSQL" else ""),
            "substatus": "",
            "workstation": "",
            "raw_data": {"line": (line or "")[:240]},
        }
        try:
            self.on_event(event)
            self._stats["emits"] = int(self._stats.get("emits", 0)) + 1
        except Exception as exc:
            log(f"[AUTHLOG] on_event error: {exc}")


# ── Hostname → IP (MySQL logs host names when name resolution is on) ──
_RESOLVE_CACHE: Dict[str, Tuple[float, str]] = {}
_RESOLVE_TTL = 3600.0
_RESOLVE_NEG_TTL = 300.0


def resolve_host_cached(host: str, resolver=None) -> str:
    """Resolve host → IPv4/IPv6 string (cached, ~2s budget); '' when unresolved."""
    h = (host or "").strip().strip("[]").rstrip(".")
    if not h:
        return ""
    now = time.time()
    hit = _RESOLVE_CACHE.get(h.lower())
    if hit and hit[0] > now:
        return hit[1]
    ip = ""
    try:
        if resolver is not None:
            ip = str(resolver(h) or "")
        else:
            import socket
            old = socket.getdefaulttimeout()
            socket.setdefaulttimeout(2.0)
            try:
                infos = socket.getaddrinfo(h, None)
            finally:
                socket.setdefaulttimeout(old)
            v4 = [i[4][0] for i in infos if i[0] == socket.AF_INET]
            ip = (v4 or [i[4][0] for i in infos] or [""])[0]
    except Exception:
        ip = ""
    _RESOLVE_CACHE[h.lower()] = (now + (_RESOLVE_TTL if ip else _RESOLVE_NEG_TTL), ip)
    if len(_RESOLVE_CACHE) > 4096:
        for k in list(_RESOLVE_CACHE)[:1024]:
            _RESOLVE_CACHE.pop(k, None)
    return ip
