#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""System Recovery — allowlist attack-surface snapshot / drift / restore.

Contract: agent/system-recovery.md (≥1.4.13, client target ≥4.9.12).

NOT a full registry backup. Only curated policy keys, critical services, and
firewall profile state that ransomware typically breaks with a one-shot EXE.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import subprocess
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

from client_helpers import log

try:
    from client_constants import MACHINE_DATA_DIR, TOKEN_FILE
except Exception:  # pragma: no cover
    MACHINE_DATA_DIR = os.path.join(
        os.environ.get("ProgramData", r"C:\ProgramData"),
        "Asteria",
    )
    TOKEN_FILE = os.path.join(MACHINE_DATA_DIR, "token.dat")

SNAPSHOT_FILE = os.path.join(MACHINE_DATA_DIR, "system_recovery.json")
SNAPSHOT_HISTORY_DIR = os.path.join(MACHINE_DATA_DIR, "system_recovery_history")
SNAPSHOT_KEEP = 10
WATCH_INTERVAL_SEC = 60
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

# ── Allowlist definitions ───────────────────────────────────────────

# healthy: expected live value for "good" state
# For DWORD policies: 0 or absent is healthy; 1 = attacker lock
REG_TARGETS = [
    {
        "id": "policy.taskmgr",
        "hive": "HKCU",
        "key": r"Software\Microsoft\Windows\CurrentVersion\Policies\System",
        "name": "DisableTaskMgr",
        "healthy": 0,
        "group": "policy",
    },
    {
        "id": "policy.taskmgr_hklm",
        "hive": "HKLM",
        "key": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "name": "DisableTaskMgr",
        "healthy": 0,
        "group": "policy",
    },
    {
        "id": "policy.regedit",
        "hive": "HKCU",
        "key": r"Software\Microsoft\Windows\CurrentVersion\Policies\System",
        "name": "DisableRegistryTools",
        "healthy": 0,
        "group": "policy",
    },
    {
        "id": "policy.regedit_hklm",
        "hive": "HKLM",
        "key": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "name": "DisableRegistryTools",
        "healthy": 0,
        "group": "policy",
    },
    {
        "id": "policy.cmd",
        "hive": "HKCU",
        "key": r"Software\Microsoft\Windows\CurrentVersion\Policies\System",
        "name": "DisableCMD",
        "healthy": 0,
        "group": "policy",
    },
    {
        "id": "policy.norun",
        "hive": "HKCU",
        "key": r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer",
        "name": "NoRun",
        "healthy": 0,
        "group": "policy",
    },
    {
        "id": "policy.noclose",
        "hive": "HKCU",
        "key": r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer",
        "name": "NoClose",
        "healthy": 0,
        "group": "policy",
    },
]

SERVICE_TARGETS = [
    {"id": "service.vss", "name": "VSS", "group": "service", "want_running": True},
    {"id": "service.swprv", "name": "swprv", "group": "service", "want_running": True},
    {"id": "service.wscsvc", "name": "wscsvc", "group": "service", "want_running": True},
    {"id": "service.eventlog", "name": "EventLog", "group": "service", "want_running": True},
    {"id": "service.schedule", "name": "Schedule", "group": "service", "want_running": True},
]

FIREWALL_PROFILES = ("domain", "private", "public")


# ── Signing (same family as network_guard) ──────────────────────────

def _read_token() -> str:
    try:
        with open(TOKEN_FILE, "r", encoding="utf-8") as f:
            return (f.read() or "").strip()
    except Exception:
        return ""


def _signing_secret(token: str, context: str = "asteria-chp-v1") -> bytes:
    machine = os.environ.get("COMPUTERNAME", "unknown")
    material = f"{token}|{machine}|{context}"
    return hashlib.sha256(material.encode("utf-8")).digest()


def _strip_sig(payload: dict) -> dict:
    return {k: v for k, v in payload.items() if k != "sig"}


def _sign_snapshot(payload: dict, token: str = None) -> str:
    token = _read_token() if token is None else token
    body = json.dumps(_strip_sig(payload), sort_keys=True, ensure_ascii=False)
    return hmac.new(
        _signing_secret(token), body.encode("utf-8"), hashlib.sha256
    ).hexdigest()


def verify_snapshot(payload: dict) -> bool:
    sig = payload.get("sig") or ""
    if not sig:
        return False
    try:
        token = _read_token()
        body = json.dumps(_strip_sig(payload), sort_keys=True, ensure_ascii=False).encode(
            "utf-8"
        )
        for context in ("asteria-chp-v1", "yesnext-chp-v1"):
            expected = hmac.new(
                _signing_secret(token, context), body, hashlib.sha256
            ).hexdigest()
            if hmac.compare_digest(sig, expected):
                return True
        return False
    except Exception:
        return False


def _atomic_write(path: str, payload: dict) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


# ── Collectors ──────────────────────────────────────────────────────

def _interactive_user_sids() -> List[str]:
    """Loaded interactive user hives under HKEY_USERS (S-1-5-21-*).

    Daemon runs as SYSTEM — HKEY_CURRENT_USER is the service account, not the
    console user. Attackers lock TaskMgr/Regedit/CMD on the interactive hive.
    """
    import winreg
    sids: List[str] = []
    try:
        with winreg.OpenKey(winreg.HKEY_USERS, "") as root:
            i = 0
            while True:
                try:
                    name = winreg.EnumKey(root, i)
                except OSError:
                    break
                i += 1
                if name.startswith("S-1-5-21-") and "_Classes" not in name:
                    sids.append(name)
    except Exception:
        pass
    return sids


def _read_dword_at(root, subkey: str, name: str) -> Optional[int]:
    try:
        import winreg
        with winreg.OpenKey(root, subkey, 0, winreg.KEY_READ) as k:
            val, _typ = winreg.QueryValueEx(k, name)
            return int(val)
    except OSError:
        return None
    except Exception:
        return None


def _write_dword_at(root, subkey: str, name: str, value: int) -> bool:
    try:
        import winreg
        with winreg.CreateKeyEx(root, subkey, 0, winreg.KEY_SET_VALUE) as k:
            winreg.SetValueEx(k, name, 0, winreg.REG_DWORD, int(value))
        return True
    except Exception as e:
        log(f"[SYS-RECOVERY] reg_set failed {subkey}\\{name}: {e}")
        return False


def _delete_value_at(root, subkey: str, name: str) -> bool:
    try:
        import winreg
        with winreg.OpenKey(root, subkey, 0, winreg.KEY_SET_VALUE) as k:
            winreg.DeleteValue(k, name)
        return True
    except FileNotFoundError:
        return True
    except OSError:
        return True
    except Exception as e:
        log(f"[SYS-RECOVERY] reg_del failed {subkey}\\{name}: {e}")
        return False


def read_reg_dword(hive: str, key: str, name: str) -> Optional[int]:
    """Return DWORD value or None if absent.

    HKCU: worst-case across loaded interactive user hives (+ current user).
    Any non-healthy value wins so drift is visible from the SYSTEM daemon.
    """
    import winreg
    if hive == "HKLM":
        return _read_dword_at(winreg.HKEY_LOCAL_MACHINE, key, name)
    if hive != "HKCU":
        return None
    values: List[int] = []
    for sid in _interactive_user_sids():
        v = _read_dword_at(winreg.HKEY_USERS, f"{sid}\\{key}", name)
        if v is not None:
            values.append(v)
    v = _read_dword_at(winreg.HKEY_CURRENT_USER, key, name)
    if v is not None:
        values.append(v)
    if not values:
        return None
    for v in values:
        if int(v) != 0:
            return int(v)
    return int(values[0])


def write_reg_dword(hive: str, key: str, name: str, value: int) -> bool:
    import winreg
    if hive == "HKLM":
        return _write_dword_at(winreg.HKEY_LOCAL_MACHINE, key, name, value)
    if hive != "HKCU":
        return False
    ok = False
    for sid in _interactive_user_sids():
        if _write_dword_at(winreg.HKEY_USERS, f"{sid}\\{key}", name, value):
            ok = True
    if _write_dword_at(winreg.HKEY_CURRENT_USER, key, name, value):
        ok = True
    return ok


def delete_reg_value(hive: str, key: str, name: str) -> bool:
    import winreg
    if hive == "HKLM":
        return _delete_value_at(winreg.HKEY_LOCAL_MACHINE, key, name)
    if hive != "HKCU":
        return False
    ok = False
    for sid in _interactive_user_sids():
        if _delete_value_at(winreg.HKEY_USERS, f"{sid}\\{key}", name):
            ok = True
    if _delete_value_at(winreg.HKEY_CURRENT_USER, key, name):
        ok = True
    return ok


def _query_service(name: str) -> dict:
    """Return {state, start_type} best-effort via sc.exe."""
    out = {"name": name, "state": "UNKNOWN", "start_type": "unknown"}
    try:
        r = subprocess.run(
            ["sc", "query", name],
            capture_output=True, text=True, timeout=8,
            creationflags=_NO_WINDOW,
        )
        text = (r.stdout or "") + (r.stderr or "")
        if "RUNNING" in text:
            out["state"] = "RUNNING"
        elif "STOPPED" in text:
            out["state"] = "STOPPED"
        elif "1060" in text or "does not exist" in text.lower():
            out["state"] = "MISSING"
    except Exception:
        pass
    try:
        r = subprocess.run(
            ["sc", "qc", name],
            capture_output=True, text=True, timeout=8,
            creationflags=_NO_WINDOW,
        )
        text = (r.stdout or "").upper()
        if "AUTO_START" in text:
            out["start_type"] = "auto"
        elif "DEMAND_START" in text:
            out["start_type"] = "demand"
        elif "DISABLED" in text:
            out["start_type"] = "disabled"
    except Exception:
        pass
    return out


def _firewall_profiles() -> dict:
    """domain/private/public -> on|off|unknown via netsh."""
    result = {p: "unknown" for p in FIREWALL_PROFILES}
    try:
        r = subprocess.run(
            ["netsh", "advfirewall", "show", "allprofiles"],
            capture_output=True, timeout=10, creationflags=_NO_WINDOW,
        )
        raw = r.stdout or b""
        text = ""
        for enc in ("utf-8", "cp1254", "cp850", "latin-1"):
            try:
                text = raw.decode(enc, errors="replace")
                break
            except Exception:
                continue
        current = None
        for line in text.splitlines():
            low = line.strip().lower()
            for p in FIREWALL_PROFILES:
                if p in low and ("profile" in low or "profil" in low):
                    current = p
            if current and (
                "state" in low or "durum" in low or "estado" in low
            ):
                if "on" in low or "açık" in low or "acik" in low or "enable" in low:
                    result[current] = "on"
                elif "off" in low or "kapalı" in low or "kapali" in low or "disable" in low:
                    result[current] = "off"
    except Exception as e:
        log(f"[SYS-RECOVERY] firewall query failed: {e}")
    return result


def capture_live() -> dict:
    """Capture current allowlist surface (unsigned)."""
    policies = {}
    for t in REG_TARGETS:
        policies[t["id"]] = {
            "hive": t["hive"],
            "key": t["key"],
            "name": t["name"],
            "value": read_reg_dword(t["hive"], t["key"], t["name"]),
            "healthy": t["healthy"],
            "group": t["group"],
        }
    services = {}
    for t in SERVICE_TARGETS:
        q = _query_service(t["name"])
        services[t["id"]] = {
            "name": t["name"],
            "state": q.get("state"),
            "start_type": q.get("start_type"),
            "want_running": t.get("want_running", True),
            "group": t["group"],
        }
    return {
        "policies": policies,
        "services": services,
        "firewall": _firewall_profiles(),
        "captured_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }


def capture_snapshot() -> dict:
    live = capture_live()
    prev = load_snapshot() or {}
    version = int(prev.get("version") or 0) + 1
    payload = {
        "version": version,
        "captured_at": live["captured_at"],
        "policies": live["policies"],
        "services": live["services"],
        "firewall": live["firewall"],
    }
    payload["sig"] = _sign_snapshot(payload)
    return payload


def load_snapshot() -> Optional[dict]:
    try:
        with open(SNAPSHOT_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def save_snapshot(payload: Optional[dict] = None) -> dict:
    payload = payload or capture_snapshot()
    if "sig" not in payload:
        payload["sig"] = _sign_snapshot(payload)
    os.makedirs(MACHINE_DATA_DIR, exist_ok=True)
    # archive previous
    try:
        if os.path.isfile(SNAPSHOT_FILE):
            prev = load_snapshot()
            if prev and prev.get("version"):
                os.makedirs(SNAPSHOT_HISTORY_DIR, exist_ok=True)
                hp = os.path.join(
                    SNAPSHOT_HISTORY_DIR,
                    f"system_recovery.{int(prev['version'])}.json",
                )
                _atomic_write(hp, prev)
                files = sorted(
                    (
                        os.path.join(SNAPSHOT_HISTORY_DIR, f)
                        for f in os.listdir(SNAPSHOT_HISTORY_DIR)
                        if f.startswith("system_recovery.")
                    )
                )
                for old in files[:-SNAPSHOT_KEEP]:
                    try:
                        os.remove(old)
                    except OSError:
                        pass
    except Exception:
        pass
    _atomic_write(SNAPSHOT_FILE, payload)
    log(f"[SYS-RECOVERY] snapshot v{payload.get('version')} saved")
    return payload


def load_snapshot_version(version: int) -> Optional[dict]:
    path = os.path.join(
        SNAPSHOT_HISTORY_DIR, f"system_recovery.{int(version)}.json"
    )
    if not os.path.isfile(path):
        if os.path.isfile(SNAPSHOT_FILE):
            cur = load_snapshot()
            if cur and int(cur.get("version") or 0) == int(version):
                return cur
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def list_snapshots() -> dict:
    cur = load_snapshot() or {}
    history = []
    try:
        if os.path.isdir(SNAPSHOT_HISTORY_DIR):
            for f in sorted(os.listdir(SNAPSHOT_HISTORY_DIR)):
                if not f.startswith("system_recovery."):
                    continue
                try:
                    with open(
                        os.path.join(SNAPSHOT_HISTORY_DIR, f),
                        "r",
                        encoding="utf-8",
                    ) as fh:
                        row = json.load(fh)
                    history.append({
                        "version": row.get("version"),
                        "captured_at": row.get("captured_at"),
                        "verified": verify_snapshot(row),
                    })
                except Exception:
                    continue
    except Exception:
        pass
    age = None
    try:
        if cur.get("captured_at"):
            dt = datetime.fromisoformat(
                str(cur["captured_at"]).replace("Z", "+00:00")
            )
            age = int((datetime.now(timezone.utc) - dt).total_seconds())
    except Exception:
        pass
    return {
        "version": cur.get("version"),
        "captured_at": cur.get("captured_at"),
        "baseline_age_sec": age,
        "verified": verify_snapshot(cur) if cur else False,
        "history": history[-SNAPSHOT_KEEP:],
    }


# ── Diff / plan / restore ───────────────────────────────────────────

def _policy_is_bad(value: Optional[int], healthy: int = 0) -> bool:
    if value is None:
        return False
    return int(value) != int(healthy)


def diff_against(baseline: Optional[dict] = None, live: Optional[dict] = None) -> List[dict]:
    """Return list of drift changes (live vs healthy allowlist + baseline hint)."""
    baseline = baseline or load_snapshot() or {}
    live = live or capture_live()
    changes: List[dict] = []

    for t in REG_TARGETS:
        lid = t["id"]
        live_val = (live.get("policies") or {}).get(lid, {}).get("value")
        # Prefer healthy allowlist: any non-healthy live value is drift
        if _policy_is_bad(live_val, t["healthy"]):
            base_val = (baseline.get("policies") or {}).get(lid, {}).get("value")
            changes.append({
                "id": lid,
                "group": "policy",
                "kind": "reg",
                "from": base_val if base_val is not None else t["healthy"],
                "to": live_val,
                "hive": t["hive"],
                "key": t["key"],
                "name": t["name"],
            })

    for t in SERVICE_TARGETS:
        lid = t["id"]
        svc = (live.get("services") or {}).get(lid) or {}
        state = str(svc.get("state") or "")
        start = str(svc.get("start_type") or "")
        if t.get("want_running") and state == "STOPPED":
            changes.append({
                "id": lid,
                "group": "service",
                "kind": "service",
                "from": "RUNNING",
                "to": state,
                "name": t["name"],
                "start_type": start,
            })
        if start == "disabled":
            changes.append({
                "id": lid + ".start",
                "group": "service",
                "kind": "service_start_type",
                "from": "auto",
                "to": "disabled",
                "name": t["name"],
            })

    fw_live = live.get("firewall") or {}
    fw_base = baseline.get("firewall") or {}
    for p in FIREWALL_PROFILES:
        cur = str(fw_live.get(p) or "unknown")
        if cur == "off":
            changes.append({
                "id": f"firewall.{p}",
                "group": "firewall",
                "kind": "firewall",
                "from": fw_base.get(p) or "on",
                "to": "off",
                "profile": p,
            })
    return changes


def plan_restore(
    targets: Optional[List[str]] = None,
    baseline: Optional[dict] = None,
) -> List[dict]:
    """Build restore plan from current drift (optionally filtered)."""
    changes = diff_against(baseline=baseline)
    want = None
    if targets:
        want = {str(t).lower() for t in targets}
    plan = []
    for ch in changes:
        gid = ch.get("group") or ""
        iid = ch.get("id") or ""
        if want is not None:
            if not (
                iid.lower() in want
                or gid.lower() in want
                or any(iid.lower().startswith(w) for w in want)
            ):
                continue
        if ch.get("kind") == "reg":
            plan.append({
                "id": iid,
                "action": "reg_set",
                "hive": ch["hive"],
                "path": ch["key"],
                "name": ch["name"],
                "to": 0,
            })
        elif ch.get("kind") == "service":
            plan.append({
                "id": iid,
                "action": "service_start",
                "name": ch["name"],
            })
        elif ch.get("kind") == "service_start_type":
            plan.append({
                "id": iid,
                "action": "service_config_auto",
                "name": ch["name"],
            })
        elif ch.get("kind") == "firewall":
            plan.append({
                "id": iid,
                "action": "firewall_on",
                "profile": ch["profile"],
            })
    return plan


def apply_plan(plan: List[dict]) -> List[str]:
    actions: List[str] = []
    for step in plan:
        act = step.get("action")
        try:
            if act == "reg_set":
                ok = write_reg_dword(
                    step["hive"], step["path"], step["name"], int(step.get("to") or 0)
                )
                if ok:
                    actions.append(f"reg_set:{step['id']}")
            elif act == "reg_delete":
                ok = delete_reg_value(step["hive"], step["path"], step["name"])
                if ok:
                    actions.append(f"reg_del:{step['id']}")
            elif act == "service_start":
                subprocess.run(
                    ["sc", "start", step["name"]],
                    capture_output=True, timeout=20, creationflags=_NO_WINDOW,
                )
                actions.append(f"service_start:{step['name']}")
            elif act == "service_config_auto":
                subprocess.run(
                    ["sc", "config", step["name"], "start=", "auto"],
                    capture_output=True, timeout=15, creationflags=_NO_WINDOW,
                )
                actions.append(f"service_config_auto:{step['name']}")
            elif act == "firewall_on":
                prof = step.get("profile") or "private"
                subprocess.run(
                    [
                        "netsh", "advfirewall", "set", f"{prof}profile",
                        "state", "on",
                    ],
                    capture_output=True, timeout=15, creationflags=_NO_WINDOW,
                )
                actions.append(f"firewall_on:{prof}")
        except Exception as e:
            log(f"[SYS-RECOVERY] apply step failed {step}: {e}")
    return actions


def restore(
    targets: Optional[List[str]] = None,
    dry_run: bool = False,
    rollback_version: Optional[int] = None,
) -> dict:
    baseline = None
    if rollback_version is not None:
        baseline = load_snapshot_version(int(rollback_version))
        if not baseline:
            return {"error": "rollback_baseline_not_found_or_invalid"}
        if not verify_snapshot(baseline):
            return {"error": "baseline_signature_invalid"}
    else:
        baseline = load_snapshot()
        if not baseline:
            return {"error": "no_baseline"}
        if not verify_snapshot(baseline):
            return {"error": "baseline_signature_invalid"}

    plan = plan_restore(targets=targets, baseline=baseline)
    if dry_run:
        return {
            "dry_run": True,
            "baseline_version": baseline.get("version"),
            "plan": plan,
            "restore_actions": [],
        }
    actions = apply_plan(plan)
    return {
        "dry_run": False,
        "baseline_version": baseline.get("version"),
        "plan": plan,
        "restore_actions": actions,
    }


def classify_drift_severity(changes: List[dict]) -> Tuple[str, int]:
    if not changes:
        return "info", 0
    groups = {c.get("group") for c in changes}
    critical_ids = {
        c.get("id") for c in changes
        if str(c.get("id") or "").startswith("policy.")
        or str(c.get("id") or "").startswith("firewall.")
    }
    if len(critical_ids) >= 3 or (
        "policy" in groups and "firewall" in groups
    ):
        return "high", 75
    if "policy" in groups or "firewall" in groups:
        return "warning", 55
    return "warning", 40


# ── Watcher service ─────────────────────────────────────────────────

class SystemRecoveryGuard:
    """Periodic drift watch + STATUS helper."""

    def __init__(self, alert_pipeline=None, enabled: bool = True):
        self.alert_pipeline = alert_pipeline
        self.enabled = bool(enabled)
        self._running = False
        self._lock = threading.RLock()
        self._last_snapshot: Optional[dict] = None
        self._last_drift_ids: set = set()
        self._last_alert_mono = 0.0

    def start(self):
        if self._running or not self.enabled:
            return
        self._running = True
        threading.Thread(
            target=self._loop, name="SystemRecoveryWatch", daemon=True
        ).start()
        log("[SYS-RECOVERY] watcher started")

    def stop(self):
        self._running = False

    def _loop(self):
        try:
            self._last_snapshot = save_snapshot()
        except Exception as e:
            log(f"[SYS-RECOVERY] initial snapshot failed: {e}")
        while self._running:
            time.sleep(WATCH_INTERVAL_SEC)
            if not self._running:
                break
            try:
                self._tick()
            except Exception as e:
                log(f"[SYS-RECOVERY] watch error: {e}")

    def _tick(self):
        base = self._last_snapshot or load_snapshot()
        if not base:
            self._last_snapshot = save_snapshot()
            return
        changes = diff_against(baseline=base)
        if not changes:
            self._last_drift_ids = set()
            return
        ids = {c.get("id") for c in changes}
        # Alert when new drift ids appear, or re-alert after 15 min
        now = time.time()
        new_ids = ids - self._last_drift_ids
        if not new_ids and (now - self._last_alert_mono) < 900:
            return
        self._last_drift_ids = ids
        self._last_alert_mono = now
        self._emit_drift(changes, base)

    def _emit_drift(self, changes: List[dict], baseline: dict):
        sev, score = classify_drift_severity(changes)
        desc = "; ".join(
            f"{c.get('id')}={c.get('to')}" for c in changes[:8]
        )
        alert = {
            "severity": sev,
            "threat_type": "system_recovery_drift",
            "title": "Sistem yüzeyi değişti (policy/service/firewall)",
            "description": desc,
            "threat_score": score,
            "target_service": "SYSTEM",
            "recommended_action": "system_recovery_restore",
            "force_urgent": sev == "high",
            "suppress_local_notify": False,
            "system_context": {
                "system_recovery": {
                    "baseline_version": baseline.get("version"),
                    "changes": changes[:20],
                }
            },
        }
        try:
            if self.alert_pipeline and hasattr(self.alert_pipeline, "handle_alert"):
                self.alert_pipeline.handle_alert(alert)
            elif self.alert_pipeline and hasattr(self.alert_pipeline, "send_urgent"):
                if sev == "high":
                    self.alert_pipeline.send_urgent(alert)
            log(f"[SYS-RECOVERY] drift alert sev={sev} n={len(changes)}")
        except Exception as e:
            log(f"[SYS-RECOVERY] drift alert failed: {e}")

    def status(self) -> dict:
        info = list_snapshots()
        # STATUS path must stay fast — skip live reg/service/firewall scan here.
        # Operators use system_recovery_diff for full drift.
        return {
            "present": True,
            "enabled": self.enabled,
            "baseline_version": info.get("version"),
            "baseline_age_sec": info.get("baseline_age_sec"),
            "last_snapshot_at": info.get("captured_at"),
            "verified": info.get("verified"),
            "drift": None,
            "drift_count": None,
        }

    def snapshot_now(self) -> dict:
        self._last_snapshot = save_snapshot()
        return self._last_snapshot
