#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Service Port Relocate — contract 1.4.45 (client ≥4.9.45).

Flow: pre-check → golden (disk) → firewall → config → restart → ≤10s verify
→ local golden rollback on failure (C-REL-1…9).

Defaults use 4XXXX safe ports (not 53389 / 9XXXX).
One relocate at a time (C-REL-3).
"""

from __future__ import annotations

import json
import os
import re
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from client_helpers import log
from client_utils import ServiceController, is_admin

# Fallback defaults only — prefer cloud relocate_state.saved_target_port
DEFAULT_SAFE_PORTS: Dict[str, int] = {
    "RDP": 43389,
    "MSSQL": 41433,
    "MYSQL": 43306,
    "SSH": 40022,
    "FTP": 40021,
}

WELL_KNOWN_PORTS: Dict[str, int] = {
    "RDP": 3389,
    "MSSQL": 1433,
    "MYSQL": 3306,
    "SSH": 22,
    "FTP": 21,
}

_RDP_REG = r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
_RDP_VALUE = "PortNumber"

_PROFILES: Dict[str, Dict[str, Any]] = {
    "RDP": {
        "scm": "TermService",
        "kind": "rdp_registry",
        "aliases": ("rdp", "termservice", "term service", "remote desktop", "remote_desktop"),
    },
    "SSH": {
        "scm": "sshd",
        "kind": "sshd_config",
        "aliases": ("ssh", "sshd", "openssh"),
    },
    "MSSQL": {
        "scm": "MSSQLSERVER",
        "kind": "mssql_registry",
        "aliases": ("mssql", "sqlserver", "sql server", "mssqlserver"),
    },
    "MYSQL": {
        "scm": "MySQL",
        "kind": "mysql_ini",
        "aliases": ("mysql", "mysqld", "mariadb"),
    },
    "FTP": {
        "scm": "ftpsvc",
        "kind": "ftp_unsupported",
        "aliases": ("ftp", "ftpsvc", "microsoft ftp"),
    },
}

_RELOCATE_LOCK = threading.Lock()
_RELOCATE_BUSY = False


def _norm(s: str) -> str:
    return " ".join(str(s or "").strip().lower().replace("_", " ").replace("-", " ").split())


def default_safe_port(service: str) -> int:
    key = str(service or "").strip().upper()
    if key == "MYSQL":
        return DEFAULT_SAFE_PORTS["MYSQL"]
    return int(DEFAULT_SAFE_PORTS.get(key) or 0)


def well_known_port(service: str) -> int:
    key = str(service or "").strip().upper()
    if key == "MYSQL":
        return WELL_KNOWN_PORTS["MYSQL"]
    return int(WELL_KNOWN_PORTS.get(key) or 0)


def is_forbidden_target_port(port: int) -> Optional[str]:
    """C-REL-6 + obsolete bans: 1024–65535 only; never 53389 / 9XXXX."""
    try:
        p = int(port)
    except (TypeError, ValueError):
        return "invalid_port"
    if p == 53389:
        return "FORBIDDEN_PORT_53389"
    if 90000 <= p <= 99999:
        return "FORBIDDEN_PORT_9XXXX"
    if p < 1024:
        return "privileged_port"
    if p > 65535:
        return "invalid_port"
    return None


def clamp_verify_sec(raw: Any, default: float = 10.0) -> float:
    """C-REL-4: verify window ≤10s."""
    try:
        v = float(raw)
    except (TypeError, ValueError):
        return default
    return max(3.0, min(10.0, v))


def _parse_target_port(params: dict, service_id: str) -> int:
    """Accept contract `target_port` plus legacy aliases."""
    for key in ("target_port", "port", "to_port", "new_port"):
        if params.get(key) is None or params.get(key) == "":
            continue
        try:
            n = int(params.get(key))
            if n > 0:
                return n
        except (TypeError, ValueError):
            continue
    return default_safe_port(service_id)


def reserved_ports(extra_relocated: Optional[Dict[str, int]] = None) -> Set[int]:
    """C-REL-7 — classic (+ known relocated) ports of other services."""
    reserved = set(int(v) for v in WELL_KNOWN_PORTS.values())
    if isinstance(extra_relocated, dict):
        for v in extra_relocated.values():
            try:
                reserved.add(int(v))
            except (TypeError, ValueError):
                pass
    return reserved


def _golden_dir() -> Path:
    try:
        from client_utils import _programdata_client_dir

        base = Path(_programdata_client_dir())
    except Exception:
        base = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "Asteria" / "Client"
    path = base / "relocate_golden"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _golden_path(service: str) -> Path:
    return _golden_dir() / f"{str(service).upper()}.json"


def save_golden_snapshot(payload: dict) -> bool:
    """C-REL-2 — persist golden to disk before config mutate."""
    try:
        svc = str(payload.get("service") or "").upper()
        if not svc:
            return False
        path = _golden_path(svc)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(str(tmp), str(path))
        return True
    except Exception as exc:
        log(f"[RELOCATE] golden save failed: {exc}")
        return False


def load_golden_snapshot(service: str) -> Optional[dict]:
    try:
        path = _golden_path(service)
        if not path.is_file():
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def clear_golden_snapshot(service: str) -> None:
    try:
        path = _golden_path(service)
        if path.is_file():
            path.unlink()
    except Exception:
        pass


def firewall_rule_name(service: str, port: int) -> str:
    """C-REL-5 — AR-RELOCATE-<SVC>-<PORT>."""
    svc = re.sub(r"[^A-Z0-9]+", "", str(service or "SVC").upper()) or "SVC"
    return f"AR-RELOCATE-{svc}-{int(port)}"


def _ensure_firewall(service: str, port: int) -> None:
    """Add inbound allow for target before restart (C-REL-5)."""
    name = firewall_rule_name(service, port)
    try:
        from client_winproc import run_hidden

        run_hidden(
            ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"],
            timeout=8,
        )
    except Exception:
        pass
    try:
        from client_winproc import run_hidden

        run_hidden(
            [
                "netsh",
                "advfirewall",
                "firewall",
                "add",
                "rule",
                f"name={name}",
                "dir=in",
                "action=allow",
                "protocol=TCP",
                f"localport={int(port)}",
            ],
            timeout=10,
        )
    except Exception as exc:
        log(f"[RELOCATE] firewall ensure {name}: {exc}")


def _remove_firewall(service: str, port: int) -> None:
    """Remove AR-RELOCATE rule on rollback / cleanup (C-REL-5)."""
    name = firewall_rule_name(service, port)
    try:
        from client_winproc import run_hidden

        run_hidden(
            ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"],
            timeout=8,
        )
    except Exception as exc:
        log(f"[RELOCATE] firewall remove {name}: {exc}")


def resolve_service(params: dict) -> Tuple[Optional[str], Optional[Dict[str, Any]], Optional[str]]:
    """Return (SERVICE_ID, profile, error)."""
    raw = (
        params.get("service")
        or params.get("service_name")
        or params.get("name")
        or ""
    )
    key = _norm(str(raw))
    if not key:
        return None, None, "missing_service"

    for sid, prof in _PROFILES.items():
        aliases = {_norm(a) for a in prof.get("aliases") or ()}
        aliases.add(_norm(sid))
        aliases.add(_norm(prof.get("scm") or ""))
        if key in aliases or key == _norm(sid):
            out = dict(prof)
            out["id"] = sid
            return sid, out, None

    # Explicit custom registry relocate (advanced)
    reg_path = str(params.get("registry_path") or params.get("reg_path") or "").strip()
    reg_value = str(params.get("registry_value") or params.get("reg_value") or "").strip()
    scm = str(params.get("scm") or params.get("scm_name") or raw).strip()
    if reg_path and reg_value and scm:
        return (
            str(raw).strip().upper() or "CUSTOM",
            {
                "id": "CUSTOM",
                "scm": scm,
                "kind": "custom_registry",
                "registry_path": reg_path.lstrip("\\"),
                "registry_value": reg_value,
            },
            None,
        )
    return None, None, "unsupported_service"


def _read_dword(path: str, value: str) -> Optional[int]:
    try:
        import winreg

        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path)
        try:
            val, _typ = winreg.QueryValueEx(key, value)
        finally:
            winreg.CloseKey(key)
        return int(val)
    except Exception as exc:
        log(f"[RELOCATE] read {path}\\{value} failed: {exc}")
        return None


def _write_dword(path: str, value: str, port: int) -> bool:
    try:
        import winreg

        key = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_SET_VALUE)
        try:
            winreg.SetValueEx(key, value, 0, winreg.REG_DWORD, int(port))
        finally:
            winreg.CloseKey(key)
        return _read_dword(path, value) == int(port)
    except Exception as exc:
        log(f"[RELOCATE] write {path}\\{value}={port} failed: {exc}")
        return False


def _bind_ok(port: int) -> bool:
    try:
        return bool(ServiceController._check_port_in_use(int(port)))
    except Exception:
        return False


def _verify_bind(port: int, verify_sec: float, settle: float = 1.0) -> bool:
    deadline = time.time() + max(1.0, float(verify_sec))
    time.sleep(max(0.0, settle))
    while time.time() < deadline:
        if _bind_ok(port):
            return True
        time.sleep(0.4)
    return _bind_ok(port)


# ── per-kind golden read / write ───────────────────────────────────

def _sshd_config_paths() -> List[str]:
    paths = [
        os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "ssh", "sshd_config"),
        r"C:\Program Files\OpenSSH\sshd_config",
    ]
    return [p for p in paths if os.path.isfile(p)]


def _read_sshd_port() -> Optional[int]:
    for path in _sshd_config_paths():
        try:
            text = open(path, encoding="utf-8", errors="replace").read()
        except Exception:
            continue
        for line in text.splitlines():
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            m = re.match(r"(?i)^Port\s+(\d+)\s*$", s)
            if m:
                return int(m.group(1))
        return 22
    return None


def _write_sshd_port(port: int) -> bool:
    paths = _sshd_config_paths()
    if not paths:
        return False
    path = paths[0]
    try:
        text = open(path, encoding="utf-8", errors="replace").read()
        lines = text.splitlines(keepends=True)
        out: List[str] = []
        replaced = False
        for line in lines:
            if re.match(r"(?i)^\s*Port\s+\d+", line) and not line.lstrip().startswith("#"):
                nl = "\n" if line.endswith("\n") else ""
                out.append(f"Port {int(port)}{nl}")
                replaced = True
            else:
                out.append(line)
        if not replaced:
            out.append(f"\nPort {int(port)}\n")
        open(path, "w", encoding="utf-8", newline="").write("".join(out))
        return _read_sshd_port() == int(port)
    except Exception as exc:
        log(f"[RELOCATE] sshd_config write failed: {exc}")
        return False


def _mssql_tcp_key() -> Optional[str]:
    """Resolve SQL Server IPAll TcpPort registry path (default instance)."""
    try:
        import winreg

        base = r"SOFTWARE\Microsoft\Microsoft SQL Server"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base + r"\Instance Names\SQL") as key:
            try:
                inst, _ = winreg.QueryValueEx(key, "MSSQLSERVER")
            except OSError:
                # first value
                inst, _ = winreg.EnumValue(key, 0)[1], None
        path = rf"{base}\{inst}\MSSQLServer\SuperSocketNetLib\Tcp\IPAll"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path):
            return path
    except Exception as exc:
        log(f"[RELOCATE] mssql key resolve failed: {exc}")
        return None


def _read_mssql_port() -> Optional[int]:
    path = _mssql_tcp_key()
    if not path:
        return None
    try:
        import winreg

        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as key:
            try:
                val, _ = winreg.QueryValueEx(key, "TcpPort")
                s = str(val or "").strip()
                if s and s.isdigit():
                    return int(s)
            except OSError:
                pass
            try:
                val, _ = winreg.QueryValueEx(key, "TcpDynamicPorts")
                s = str(val or "").strip()
                if s and s.isdigit():
                    return int(s)
            except OSError:
                pass
    except Exception:
        pass
    return None


def _write_mssql_port(port: int) -> bool:
    path = _mssql_tcp_key()
    if not path:
        return False
    try:
        import winreg

        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, "TcpPort", 0, winreg.REG_SZ, str(int(port)))
            winreg.SetValueEx(key, "TcpDynamicPorts", 0, winreg.REG_SZ, "")
        return _read_mssql_port() == int(port)
    except Exception as exc:
        log(f"[RELOCATE] mssql write failed: {exc}")
        return False


def _find_mysql_ini() -> Optional[str]:
    candidates = [
        r"C:\ProgramData\MySQL\MySQL Server 8.0\my.ini",
        r"C:\ProgramData\MySQL\MySQL Server 8.4\my.ini",
        r"C:\ProgramData\MySQL\MySQL Server 5.7\my.ini",
        r"C:\Program Files\MySQL\my.ini",
    ]
    for p in candidates:
        if os.path.isfile(p):
            return p
    # Probe service ImagePath
    try:
        import winreg

        for name in ("MySQL", "MySQL80", "MySQL84", "MariaDB"):
            try:
                with winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    rf"SYSTEM\CurrentControlSet\Services\{name}",
                ) as key:
                    img, _ = winreg.QueryValueEx(key, "ImagePath")
                img_s = str(img or "")
                m = re.search(r'(?i)--defaults-file[= ]"?([^"\s]+)"?', img_s)
                if m and os.path.isfile(m.group(1)):
                    return m.group(1)
                basedir = os.path.dirname(img_s.strip('"').split()[0])
                for rel in ("my.ini", r"..\my.ini", r"..\..\my.ini"):
                    cand = os.path.normpath(os.path.join(basedir, rel))
                    if os.path.isfile(cand):
                        return cand
            except OSError:
                continue
    except Exception:
        pass
    return None


def _read_mysql_port() -> Optional[int]:
    path = _find_mysql_ini()
    if not path:
        return None
    try:
        text = open(path, encoding="utf-8", errors="replace").read()
        in_mysqld = False
        for line in text.splitlines():
            s = line.strip()
            if s.startswith("[") and s.endswith("]"):
                in_mysqld = s.lower() in ("[mysqld]", "[mysqld.1]")
                continue
            if in_mysqld and re.match(r"(?i)^port\s*=\s*\d+", s):
                return int(re.split(r"[=]", s, 1)[1].strip())
        return 3306
    except Exception:
        return None


def _write_mysql_port(port: int) -> bool:
    path = _find_mysql_ini()
    if not path:
        return False
    try:
        text = open(path, encoding="utf-8", errors="replace").read()
        lines = text.splitlines(keepends=True)
        out: List[str] = []
        in_mysqld = False
        replaced = False
        for line in lines:
            s = line.strip()
            if s.startswith("[") and s.endswith("]"):
                in_mysqld = s.lower() in ("[mysqld]", "[mysqld.1]")
                out.append(line)
                continue
            if in_mysqld and re.match(r"(?i)^\s*port\s*=", line):
                nl = "\n" if line.endswith("\n") else ""
                out.append(f"port={int(port)}{nl}")
                replaced = True
            else:
                out.append(line)
        if not replaced:
            # append under [mysqld]
            joined = "".join(out)
            if "[mysqld]" in joined.lower():
                out2: List[str] = []
                inserted = False
                for line in out:
                    out2.append(line)
                    if not inserted and line.strip().lower() == "[mysqld]":
                        out2.append(f"port={int(port)}\n")
                        inserted = True
                out = out2
            else:
                out.append(f"\n[mysqld]\nport={int(port)}\n")
        open(path, "w", encoding="utf-8", newline="").write("".join(out))
        return _read_mysql_port() == int(port)
    except Exception as exc:
        log(f"[RELOCATE] mysql write failed: {exc}")
        return False


def _resolve_scm(profile: Dict[str, Any], params: dict) -> str:
    override = str(params.get("scm") or params.get("scm_name") or "").strip()
    if override:
        return override
    scm = str(profile.get("scm") or "")
    # MYSQL often installed as MySQL80 etc.
    if profile.get("id") == "MYSQL":
        for name in ("MySQL80", "MySQL84", "MySQL57", "MySQL", "MariaDB"):
            if ServiceController._sc_query_code(name) >= 0:
                return name
    if profile.get("id") == "MSSQL":
        for name in ("MSSQLSERVER", "MSSQL$SQLEXPRESS"):
            code = ServiceController._sc_query_code(name)
            if code >= 0:
                return name
    if profile.get("id") == "SSH":
        for name in ("sshd", "OpenSSH", "ssh-agent"):
            if name != "ssh-agent" and ServiceController._sc_query_code(name) >= 0:
                return name
    return scm


def _read_golden(profile: Dict[str, Any], params: dict) -> Optional[int]:
    kind = profile.get("kind")
    if kind in ("rdp_registry",):
        return _read_dword(_RDP_REG, _RDP_VALUE) or well_known_port("RDP")
    if kind == "custom_registry":
        return _read_dword(str(profile["registry_path"]), str(profile["registry_value"]))
    if kind == "sshd_config":
        return _read_sshd_port() or well_known_port("SSH")
    if kind == "mssql_registry":
        return _read_mssql_port() or well_known_port("MSSQL")
    if kind == "mysql_ini":
        return _read_mysql_port() or well_known_port("MYSQL")
    if kind == "ftp_unsupported":
        return well_known_port("FTP")
    return None


def _write_config(profile: Dict[str, Any], port: int) -> bool:
    kind = profile.get("kind")
    if kind == "rdp_registry":
        return _write_dword(_RDP_REG, _RDP_VALUE, int(port))
    if kind == "custom_registry":
        return _write_dword(str(profile["registry_path"]), str(profile["registry_value"]), int(port))
    if kind == "sshd_config":
        return _write_sshd_port(int(port))
    if kind == "mssql_registry":
        return _write_mssql_port(int(port))
    if kind == "mysql_ini":
        return _write_mysql_port(int(port))
    return False


def prefill_targets_from_tunnel(tunnel_payload: Optional[dict]) -> Dict[str, int]:
    """Build service → target port from GET premium/tunnel-status relocate_state."""
    out = {k: int(v) for k, v in DEFAULT_SAFE_PORTS.items()}
    if not isinstance(tunnel_payload, dict):
        return out
    state = tunnel_payload.get("relocate_state") or tunnel_payload.get("relocate") or {}
    if not isinstance(state, dict):
        return out
    for svc, defaults in DEFAULT_SAFE_PORTS.items():
        entry = state.get(svc) or state.get(svc.lower()) or state.get(svc.title())
        if isinstance(entry, dict):
            saved = entry.get("saved_target_port") or entry.get("target_port")
            try:
                if saved is not None and not is_forbidden_target_port(int(saved)):
                    out[svc] = int(saved)
                    continue
            except (TypeError, ValueError):
                pass
            dsp = entry.get("default_safe_port")
            try:
                if dsp is not None and not is_forbidden_target_port(int(dsp)):
                    out[svc] = int(dsp)
                    continue
            except (TypeError, ValueError):
                pass
        elif entry is not None:
            try:
                p = int(entry)
                if not is_forbidden_target_port(p):
                    out[svc] = p
            except (TypeError, ValueError):
                pass
        out.setdefault(svc, defaults)
    return out


def collect_listen_ports() -> List[dict]:
    """Minimal open_ports snapshot for relocate-report / agent/open-ports."""
    items: List[dict] = []
    try:
        import subprocess

        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        res = subprocess.run(
            ["netstat", "-ano", "-p", "TCP"],
            capture_output=True,
            text=True,
            timeout=10,
            creationflags=flags,
        )
        if res.returncode != 0:
            return items
        for line in (res.stdout or "").splitlines():
            parts = line.split()
            if len(parts) < 4 or parts[0].upper() != "TCP":
                continue
            state = parts[3].upper()
            if state not in ("LISTEN", "LISTENING"):
                continue
            local = parts[1]
            try:
                _addr, port_s = local.rsplit(":", 1)
                port = int(port_s)
            except Exception:
                continue
            pid = int(parts[4]) if len(parts) >= 5 and parts[4].isdigit() else None
            items.append(
                {
                    "port": port,
                    "protocol": "tcp",
                    "state": "LISTEN",
                    "addr": _addr,
                    "pid": pid,
                }
            )
    except Exception as exc:
        log(f"[RELOCATE] collect_listen_ports: {exc}")
    return items


def relocate_service(
    params: Optional[dict] = None,
    *,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> dict:
    """Execute relocate_service (1.4.45). Returns command/GUI result dict."""
    global _RELOCATE_BUSY
    params = params if isinstance(params, dict) else {}

    # C-REL-3 — serialize: one relocate at a time per host
    if not _RELOCATE_LOCK.acquire(blocking=False):
        return {
            "success": False,
            "ok": False,
            "status": "error",
            "error": "RELOCATE_BUSY",
            "reason": "relocate_busy",
            "applied": False,
            "rolled_back": False,
        }

    try:
        if _RELOCATE_BUSY:
            return {
                "success": False,
                "ok": False,
                "status": "error",
                "error": "RELOCATE_BUSY",
                "reason": "relocate_busy",
                "applied": False,
                "rolled_back": False,
            }
        _RELOCATE_BUSY = True
        return _relocate_unlocked(params, sleep_fn=sleep_fn)
    finally:
        _RELOCATE_BUSY = False
        _RELOCATE_LOCK.release()


def _relocate_unlocked(params: dict, *, sleep_fn: Callable[[float], None]) -> dict:
    sid, profile, err = resolve_service(params)
    if err or not profile or not sid:
        return {
            "success": False,
            "ok": False,
            "status": "error",
            "error": err or "unsupported_service",
            "reason": err or "unsupported_service",
            "applied": False,
            "rolled_back": False,
        }

    if profile.get("kind") == "ftp_unsupported" and not (
        params.get("registry_path") and params.get("registry_value")
    ):
        return {
            "success": False,
            "ok": False,
            "status": "error",
            "error": "unsupported_service",
            "reason": "ftp_relocate_not_supported",
            "service": "FTP",
            "applied": False,
            "rolled_back": False,
        }

    target = _parse_target_port(params, sid)

    forbid = is_forbidden_target_port(target)
    if forbid:
        return {
            "success": False,
            "ok": False,
            "status": "error",
            "error": forbid,
            "reason": forbid,
            "service": sid,
            "old_port": None,
            "target_port": int(target),
            "new_port": int(target),
            "applied": False,
            "rolled_back": False,
        }

    # C-REL-7 — cannot land on another service's classic (or known relocated) port
    extra = params.get("reserved_ports") if isinstance(params.get("reserved_ports"), dict) else None
    reserved = reserved_ports(extra)
    own_classic = well_known_port(sid)
    if int(target) in reserved and int(target) != own_classic:
        return {
            "success": False,
            "ok": False,
            "status": "error",
            "error": "PORT_RESERVED",
            "reason": "port_reserved_classic",
            "service": sid,
            "target_port": int(target),
            "new_port": int(target),
            "applied": False,
            "rolled_back": False,
        }

    on_fail = str(params.get("on_fail") or "restore_golden").strip().lower()
    if on_fail != "restore_golden":
        return {
            "success": False,
            "ok": False,
            "status": "error",
            "error": "invalid_on_fail",
            "reason": "invalid_on_fail",
            "service": sid,
            "applied": False,
            "rolled_back": False,
        }

    if not is_admin():
        return {
            "success": False,
            "ok": False,
            "status": "error",
            "error": "ADMIN_REQUIRED",
            "reason": "admin_required",
            "service": sid,
            "applied": False,
            "rolled_back": False,
        }

    scm = _resolve_scm(profile, params)
    verify_sec = clamp_verify_sec(params.get("verify_sec") or params.get("watchdog_sec") or 10)
    ensure_fw = params.get("ensure_firewall", True) is not False
    skip_precheck = bool(params.get("skip_precheck"))

    # Golden = current listen/config port
    golden_port = _read_golden(profile, params)
    if golden_port is None:
        return {
            "success": False,
            "ok": False,
            "status": "error",
            "error": "NO_GOLDEN",
            "reason": "no_golden",
            "service": sid,
            "applied": False,
            "rolled_back": False,
        }

    expected_from = params.get("from_port") or params.get("current_port") or params.get("old_port")
    if expected_from is not None:
        try:
            if int(expected_from) != int(golden_port):
                return {
                    "success": False,
                    "ok": False,
                    "status": "error",
                    "error": "PORT_MISMATCH",
                    "reason": "port_mismatch",
                    "service": sid,
                    "old_port": int(golden_port),
                    "target_port": int(target),
                    "new_port": int(target),
                    "applied": False,
                    "rolled_back": False,
                }
        except (TypeError, ValueError):
            pass

    base = {
        "service": sid,
        "scm": scm,
        "old_port": int(golden_port),
        "new_port": int(target),
        "target_port": int(target),
        "verify_sec": verify_sec,
    }

    if int(golden_port) == int(target):
        return {
            "success": True,
            "ok": True,
            "status": "ok",
            "applied": False,
            "rolled_back": False,
            "noop": True,
            "bind_ok": _bind_ok(target),
            "message": f"{sid} already on :{target}",
            **base,
        }

    # Pre-check: target must be free (1c); classic-in-use is soft warning only
    if not skip_precheck:
        if _bind_ok(int(target)):
            return {
                "success": False,
                "ok": False,
                "status": "error",
                "error": "TARGET_BUSY",
                "reason": "target_port_in_use",
                "applied": False,
                "rolled_back": False,
                **base,
            }

    # C-REL-2 — persist golden to disk before mutate
    golden_payload = {
        "service": sid,
        "scm": scm,
        "old_port": int(golden_port),
        "target_port": int(target),
        "kind": profile.get("kind"),
        "registry_path": profile.get("registry_path"),
        "registry_value": profile.get("registry_value"),
        "saved_at": time.time(),
    }
    if not save_golden_snapshot(golden_payload):
        return {
            "success": False,
            "ok": False,
            "status": "error",
            "error": "GOLDEN_PERSIST_FAILED",
            "reason": "golden_persist_failed",
            "applied": False,
            "rolled_back": False,
            **base,
        }

    def _reason_token(reason: str) -> str:
        mapping = {
            "START_FAILED": "start_failed",
            "BIND_FAILED": "bind_verify_failed",
            "CONFIG_DRIFT": "config_drift",
        }
        return mapping.get(reason, str(reason or "error").lower())

    def _rollback(reason: str) -> dict:
        # C-REL-1 — local rollback; C-REL-5 — drop new-port firewall
        token = _reason_token(reason)
        log(f"[RELOCATE] rollback -> :{golden_port} ({token})")
        if ensure_fw:
            _remove_firewall(sid, int(target))
        wrote = _write_config(profile, int(golden_port))
        ServiceController.stop(scm, timeout=40, log_func=log)
        sleep_fn(1.0)
        started = ServiceController.start(scm, timeout=40, log_func=log)
        sleep_fn(1.0)
        bind = _verify_bind(int(golden_port), min(verify_sec, 8.0), settle=0.4)
        # Keep golden on disk until success so crash recovery can use it
        return {
            "success": False,
            "ok": False,
            "status": "rollback",
            "error": "GOLDEN_ROLLBACK",
            "reason": token,
            "applied": True,
            "rolled_back": True,
            "rollback_wrote": wrote,
            "rollback_started": bool(started),
            "bind_ok": bool(bind),
            "message": f"{sid} relocate failed ({token}); restored :{golden_port}",
            **base,
        }

    # C-REL-5 — firewall before config/restart
    if ensure_fw:
        _ensure_firewall(sid, int(target))

    if not _write_config(profile, int(target)):
        if ensure_fw:
            _remove_firewall(sid, int(target))
        return {
            "success": False,
            "ok": False,
            "status": "error",
            "error": "CONFIG_FAILED",
            "reason": "config_failed",
            "applied": False,
            "rolled_back": False,
            **base,
        }

    ServiceController.stop(scm, timeout=40, log_func=log)
    sleep_fn(1.0)
    if not ServiceController.start(scm, timeout=40, log_func=log):
        return _rollback("START_FAILED")

    # C-REL-4 — ≤10s bind verify
    if not _verify_bind(int(target), verify_sec):
        return _rollback("BIND_FAILED")

    clear_golden_snapshot(sid)
    log(f"[RELOCATE] {sid} :{golden_port} -> :{target} OK")
    return {
        "success": True,
        "ok": True,
        "status": "ok",
        "applied": True,
        "rolled_back": False,
        "bind_ok": True,
        "message": f"{sid} relocated :{golden_port} -> :{target}",
        **base,
    }
