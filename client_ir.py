# -*- coding: utf-8 -*-
"""Incident response: session logoff/disconnect + full emergency lockdown (contract 1.4.92).

WTS APIs via ctypes. Never touches session 0 or the agent's own session.
Results: {"ok": bool, "actions": [{"type", "target", "ok", "error"}], "undo_id"?}
"""
from __future__ import annotations

import ctypes
import ipaddress
import json
import os
import subprocess
import threading
import time
import uuid
from typing import Callable, Dict, Iterable, List, Optional

CREATE_NO_WINDOW = 0x08000000
WTS_CURRENT_SERVER_HANDLE = 0
WTSUserName = 5
WTSDomainName = 7
# WTS_CONNECTSTATE_CLASS
STATE_NAMES = {0: "Active", 1: "Connected", 2: "ConnectQuery", 3: "Shadow",
               4: "Disconnected", 5: "Idle", 6: "Listen", 7: "Reset", 8: "Down", 9: "Init"}
RDP_KEY = r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
FW_PREFIX = "ASTERIA_IR_RDP_"
# Built-in / machine identities never disabled (RID suffix)
BUILTIN_RIDS = {"-500", "-501", "-503", "-504"}  # Administrator handled via keep/admin set
UNDO_TTL_SEC = 24 * 3600


def _ir_dir() -> str:
    base = os.environ.get("ProgramData") or r"C:\ProgramData"
    d = os.path.join(base, "Asteria", "ir")
    os.makedirs(d, exist_ok=True)
    return d


def _act(type_: str, target, ok: bool, error: Optional[str] = None, **extra) -> dict:
    a = {"type": type_, "target": target, "ok": bool(ok), "error": error}
    a.update(extra)
    return a


# ---------------------------------------------------------------- WTS layer
class _WTS_SESSION_INFOW(ctypes.Structure):
    _fields_ = [("SessionId", ctypes.c_uint32),
                ("pWinStationName", ctypes.c_wchar_p),
                ("State", ctypes.c_int)]


class WtsApi:
    """Thin ctypes wrapper; replaced by a fake in tests."""

    def __init__(self):
        self._wts = ctypes.windll.wtsapi32
        self._k32 = ctypes.windll.kernel32

    def own_session_id(self) -> int:
        sid = ctypes.c_uint32(0)
        self._k32.ProcessIdToSessionId(self._k32.GetCurrentProcessId(), ctypes.byref(sid))
        return int(sid.value)

    def _query(self, sid: int, cls: int) -> str:
        buf = ctypes.c_wchar_p()
        n = ctypes.c_uint32(0)
        if not self._wts.WTSQuerySessionInformationW(
                WTS_CURRENT_SERVER_HANDLE, sid, cls, ctypes.byref(buf), ctypes.byref(n)):
            return ""
        try:
            return buf.value or ""
        finally:
            self._wts.WTSFreeMemory(buf)

    def enumerate(self) -> List[dict]:
        p = ctypes.POINTER(_WTS_SESSION_INFOW)()
        count = ctypes.c_uint32(0)
        if not self._wts.WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1,
                                               ctypes.byref(p), ctypes.byref(count)):
            raise OSError(f"WTSEnumerateSessionsW failed err={ctypes.GetLastError()}")
        out = []
        try:
            for i in range(count.value):
                s = p[i]
                sid = int(s.SessionId)
                out.append({
                    "session_id": sid,
                    "station": s.pWinStationName or "",
                    "state": STATE_NAMES.get(int(s.State), str(s.State)),
                    "username": self._query(sid, WTSUserName),
                    "domain": self._query(sid, WTSDomainName),
                })
        finally:
            self._wts.WTSFreeMemory(p)
        return out

    def logoff(self, sid: int) -> bool:
        if not self._wts.WTSLogoffSession(WTS_CURRENT_SERVER_HANDLE, int(sid), False):
            raise OSError(f"WTSLogoffSession err={ctypes.GetLastError()}")
        return True

    def disconnect(self, sid: int) -> bool:
        if not self._wts.WTSDisconnectSession(WTS_CURRENT_SERVER_HANDLE, int(sid), False):
            raise OSError(f"WTSDisconnectSession err={ctypes.GetLastError()}")
        return True


# ---------------------------------------------------------------- system layer
def _run(cmd: List[str], timeout: int = 20) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                          creationflags=CREATE_NO_WINDOW)


class SystemOps:
    """Users / firewall / registry; replaced by a fake in tests."""

    def local_users(self) -> List[dict]:
        r = _run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                  "Get-LocalUser | Select-Object Name,Enabled,@{n='SID';e={$_.SID.Value}} | ConvertTo-Json -Compress"])
        data = json.loads((r.stdout or "").strip() or "[]")
        if isinstance(data, dict):
            data = [data]
        return [{"name": d.get("Name"), "enabled": bool(d.get("Enabled")), "sid": d.get("SID") or ""} for d in data]

    def admin_names(self) -> List[str]:
        r = _run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                  "Get-LocalGroupMember -SID S-1-5-32-544 | ForEach-Object { $_.Name.Split('\\')[-1] } | ConvertTo-Json -Compress"])
        data = json.loads((r.stdout or "").strip() or "[]")
        if isinstance(data, str):
            data = [data]
        return [str(x) for x in data]

    def set_user_active(self, name: str, active: bool) -> None:
        r = _run(["net", "user", name, "/active:yes" if active else "/active:no"])
        if r.returncode != 0:
            raise OSError(((r.stderr or r.stdout or "") or "net user failed").strip()[:200])

    def rdp_ports(self) -> List[int]:
        ports = {3389}
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, RDP_KEY) as k:
                v, _ = winreg.QueryValueEx(k, "PortNumber")
                if int(v) > 0:
                    ports.add(int(v))
        except Exception:
            pass
        return sorted(ports)

    def fw_add_block(self, name: str, ports: List[int], protocol: str, remoteip: str) -> None:
        r = _run(["netsh", "advfirewall", "firewall", "add", "rule", f"name={name}", "dir=in",
                  "action=block", "enable=yes", f"protocol={protocol}",
                  "localport=" + ",".join(str(p) for p in ports), f"remoteip={remoteip}"])
        if r.returncode != 0:
            raise OSError(((r.stderr or r.stdout or "") or "netsh failed").strip()[:200])

    def fw_delete(self, name: str) -> None:
        r = _run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"])
        if r.returncode != 0 and "No rules" not in (r.stdout or ""):
            raise OSError(((r.stderr or r.stdout or "") or "netsh failed").strip()[:200])


def remote_ranges_excluding(mgmt_ip: str) -> str:
    """netsh remoteip list = everything except mgmt_ip (block rules win over allow)."""
    ip = ipaddress.ip_address(mgmt_ip)
    universe = ipaddress.ip_network("0.0.0.0/0" if ip.version == 4 else "::/0")
    nets = list(universe.address_exclude(ipaddress.ip_network(f"{ip}/{ip.max_prefixlen}")))
    other = "::/0" if ip.version == 4 else "0.0.0.0/0"
    return ",".join(sorted(str(n) for n in nets) + [other])


# ---------------------------------------------------------------- IR engine
class IncidentResponse:
    def __init__(self, wts=None, ops=None, store_dir: Optional[str] = None,
                 log: Callable[[str], None] = print):
        self._wts = wts
        self._ops = ops or SystemOps()
        self._dir = store_dir
        self._log = log
        self._lock = threading.Lock()

    @property
    def wts(self):
        if self._wts is None:
            self._wts = WtsApi()
        return self._wts

    def _store(self) -> str:
        return self._dir or _ir_dir()

    # ---- sessions
    def protected_session_ids(self) -> set:
        prot = {0}
        try:
            prot.add(int(self.wts.own_session_id()))
        except Exception:
            pass
        return prot

    def list_sessions(self) -> List[dict]:
        prot = self.protected_session_ids()
        out = []
        for s in self.wts.enumerate():
            s = dict(s)
            s["protected"] = s["session_id"] in prot
            s["user_session"] = bool(s.get("username")) and s.get("state") != "Listen"
            out.append(s)
        return out

    def _session_op(self, kind: str, session_id, dry_run: bool) -> dict:
        try:
            sid = int(session_id)
        except (TypeError, ValueError):
            return _act(kind, session_id, False, "invalid_session_id")
        if sid in self.protected_session_ids():
            return _act(kind, sid, False, "protected_session")
        if dry_run:
            return _act(kind, sid, True, None, dry_run=True)
        try:
            (self.wts.logoff if kind == "logoff_session" else self.wts.disconnect)(sid)
            return _act(kind, sid, True)
        except Exception as e:
            return _act(kind, sid, False, str(e)[:200])

    def logoff_session(self, session_id, dry_run: bool = False) -> dict:
        a = self._session_op("logoff_session", session_id, dry_run)
        return {"ok": a["ok"], "actions": [a]}

    def disconnect_session(self, session_id, dry_run: bool = False) -> dict:
        a = self._session_op("disconnect_session", session_id, dry_run)
        return {"ok": a["ok"], "actions": [a]}

    def logoff_all_sessions(self, exclude_session_ids: Iterable = (), exclude_users: Iterable = (),
                            include_console: bool = True, dry_run: bool = False) -> dict:
        ex_ids = {int(x) for x in (exclude_session_ids or []) if str(x).strip().lstrip("-").isdigit()}
        ex_users = {str(u).strip().lower() for u in (exclude_users or []) if str(u).strip()}
        actions = []
        for s in self.list_sessions():
            if not s["user_session"] or s["protected"]:
                continue
            if s["session_id"] in ex_ids or (s.get("username") or "").lower() in ex_users:
                actions.append(_act("logoff_session", s["session_id"], True, None,
                                    skipped="excluded", username=s.get("username")))
                continue
            if not include_console and (s.get("station") or "").lower() == "console":
                actions.append(_act("logoff_session", s["session_id"], True, None,
                                    skipped="console", username=s.get("username")))
                continue
            a = self._session_op("logoff_session", s["session_id"], dry_run)
            a["username"] = s.get("username")
            actions.append(a)
        return {"ok": all(a["ok"] for a in actions), "actions": actions}

    # ---- lockdown
    def _non_admin_targets(self, keep: set) -> List[str]:
        admins = {a.lower() for a in self._ops.admin_names()}
        out = []
        for u in self._ops.local_users():
            name = (u.get("name") or "").strip()
            sid = u.get("sid") or ""
            if not name or not u.get("enabled"):
                continue
            if name.endswith("$") or any(sid.endswith(r) for r in BUILTIN_RIDS):
                continue
            if name.lower() in admins or name.lower() in keep:
                continue
            out.append(name)
        return out

    def emergency_lockdown(self, *, logoff_all: bool = True, block_rdp: bool = True,
                           disable_non_admin: bool = False, keep_admins: Iterable = (),
                           management_ip: str = "", duration_minutes: int = 60,
                           dry_run: bool = False) -> dict:
        keep = {str(k).strip().lower() for k in (keep_admins or []) if str(k).strip()}
        if management_ip:
            try:
                ipaddress.ip_address(management_ip)
            except ValueError:
                return {"ok": False, "actions": [_act("validate", "management_ip", False, "invalid_ip")]}
        lid = uuid.uuid4().hex[:12]
        actions: List[dict] = []
        record = {"lockdown_id": lid, "created_at": time.time(), "fw_rules": [],
                  "disabled_users": [], "management_ip": management_ip or None,
                  "duration_minutes": int(duration_minutes or 0), "undone": False}
        with self._lock:
            if block_rdp:
                ports = self._ops.rdp_ports()
                remote = remote_ranges_excluding(management_ip) if management_ip else "any"
                for proto in ("TCP", "UDP"):
                    name = f"{FW_PREFIX}{lid}_{proto}"
                    if dry_run:
                        actions.append(_act("block_rdp", name, True, None, ports=ports, dry_run=True))
                        continue
                    try:
                        self._ops.fw_add_block(name, ports, proto, remote)
                        record["fw_rules"].append(name)
                        actions.append(_act("block_rdp", name, True, None, ports=ports))
                    except Exception as e:
                        actions.append(_act("block_rdp", name, False, str(e)[:200], ports=ports))
            if disable_non_admin:
                for name in self._non_admin_targets(keep):
                    if dry_run:
                        actions.append(_act("disable_user", name, True, None, dry_run=True))
                        continue
                    try:
                        self._ops.set_user_active(name, False)
                        record["disabled_users"].append(name)
                        actions.append(_act("disable_user", name, True))
                    except Exception as e:
                        actions.append(_act("disable_user", name, False, str(e)[:200]))
            if logoff_all:
                res = self.logoff_all_sessions(exclude_users=keep, dry_run=dry_run)
                actions.extend(res["actions"])
            ok = all(a["ok"] for a in actions)
            out = {"ok": ok, "actions": actions}
            if dry_run:
                out["dry_run"] = True
                return out
            if record["fw_rules"] or record["disabled_users"]:
                self._save(record)
                out["undo_id"] = lid
                if record["duration_minutes"] > 0:
                    t = threading.Timer(record["duration_minutes"] * 60,
                                        lambda: self.emergency_lockdown_undo(lid, reason="expired"))
                    t.daemon = True
                    t.start()
            return out

    def _path(self, lid: str) -> str:
        safe = "".join(c for c in str(lid) if c.isalnum())[:32]
        return os.path.join(self._store(), f"lockdown-{safe}.json")

    def _save(self, rec: dict) -> None:
        p = self._path(rec["lockdown_id"])
        tmp = p + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(rec, f)
        os.replace(tmp, p)

    def load(self, lid: str) -> Optional[dict]:
        try:
            with open(self._path(lid), encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None

    def emergency_lockdown_undo(self, lockdown_id: str, reason: str = "operator") -> dict:
        rec = self.load(lockdown_id)
        if not rec:
            return {"ok": False, "actions": [_act("undo", lockdown_id, False, "unknown_lockdown_id")]}
        if rec.get("undone"):
            return {"ok": True, "actions": [_act("undo", lockdown_id, True, None, skipped="already_undone")]}
        actions = []
        with self._lock:
            for name in rec.get("fw_rules") or []:
                try:
                    self._ops.fw_delete(name)
                    actions.append(_act("unblock_rdp", name, True))
                except Exception as e:
                    actions.append(_act("unblock_rdp", name, False, str(e)[:200]))
            for user in rec.get("disabled_users") or []:
                try:
                    self._ops.set_user_active(user, True)
                    actions.append(_act("enable_user", user, True))
                except Exception as e:
                    actions.append(_act("enable_user", user, False, str(e)[:200]))
            ok = all(a["ok"] for a in actions)
            if ok:
                rec["undone"] = True
                rec["undone_at"] = time.time()
                rec["undo_reason"] = reason
                self._save(rec)
        return {"ok": ok, "actions": actions, "undo_id": lockdown_id}

    def resume_pending_expiry(self) -> int:
        """On agent start: undo expired lockdowns, re-arm timers for active ones."""
        n = 0
        try:
            names = [f for f in os.listdir(self._store()) if f.startswith("lockdown-") and f.endswith(".json")]
        except Exception:
            return 0
        for fn in names:
            lid = fn[len("lockdown-"):-len(".json")]
            rec = self.load(lid)
            if not rec or rec.get("undone") or not rec.get("duration_minutes"):
                continue
            left = rec["created_at"] + rec["duration_minutes"] * 60 - time.time()
            if left <= 0:
                self.emergency_lockdown_undo(lid, reason="expired")
            else:
                t = threading.Timer(left, lambda l=lid: self.emergency_lockdown_undo(l, reason="expired"))
                t.daemon = True
                t.start()
            n += 1
        return n


_ENGINE: Optional[IncidentResponse] = None


def engine(log: Callable[[str], None] = print) -> IncidentResponse:
    global _ENGINE
    if _ENGINE is None:
        _ENGINE = IncidentResponse(log=log)
    return _ENGINE
