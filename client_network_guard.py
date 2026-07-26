"""Network Guard — offline ransomware bomb defense + network-drive backup/recovery.

Contract: agent/network-guard.md (>= 4.7.0).

Five parts:
  A) Signed network baseline snapshot (mapped drives, shares, adapters, DNS,
     routes, firewall, connectivity) with version rotation.
  B) Offline behavioural detection (no internet needed): network-cut delta vs
     baseline + per-process file-write storm (psutil io_counters) + suspicious
     origin scoring. Net-cut + FS-storm => trigger without waiting for canary.
  C) Aggressive containment, suspend-first (freeze suspects, best-effort
     emergency VSS snapshot, register into quarantine; operator confirms
     kill/release).
  D) Network / connectivity recovery from baseline (re-enable adapter, restore
     DNS/firewall/routes/mapped-drives/shares) so the daemon can reconnect.
  E) ransomware_offline_bomb urgent alert (system_context.network_guard).

Honest limit: this is not a full EDR/AV. Behavioural mass-encryption detection
can false-positive; defaults are safe (suspend-first) and thresholds tunable.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import socket
import subprocess
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

try:
    import psutil
except Exception:  # pragma: no cover
    psutil = None

try:
    from client_constants import MACHINE_DATA_DIR, TOKEN_FILE
except Exception:  # pragma: no cover - test/deploy fallback
    MACHINE_DATA_DIR = os.path.join(
        os.environ.get("ProgramData", os.path.expanduser("~")),
        "Asteria",
    )
    TOKEN_FILE = os.path.join(MACHINE_DATA_DIR, "token.dat")

try:
    from client_utils import log
except Exception:  # pragma: no cover
    def log(msg: str) -> None:
        print(msg)


BASELINE_FILE = os.path.join(MACHINE_DATA_DIR, "network_baseline.json")
BASELINE_HISTORY_DIR = os.path.join(MACHINE_DATA_DIR, "network_baseline_history")
BASELINE_KEEP = 10
MAINTENANCE_FILE = os.path.join(MACHINE_DATA_DIR, "network_guard_maintenance.json")

# Windows CREATE_NO_WINDOW for subprocess (no console flash)
_NO_WINDOW = 0x08000000 if os.name == "nt" else 0

# Images never suspended/killed (OS + our own stack + common backup/AV)
_PROTECTED_IMAGES = {
    "system", "system idle process", "smss.exe", "csrss.exe", "wininit.exe",
    "winlogon.exe", "services.exe", "lsass.exe", "svchost.exe", "explorer.exe",
    "dwm.exe", "fontdrvhost.exe", "spoolsv.exe", "taskhostw.exe",
    "honeypot-client.exe", "python.exe", "pythonw.exe",
    "msmpeng.exe", "mssense.exe", "sense.exe",  # Defender
    "vssvc.exe", "wbengine.exe", "veeam.exe", "backup.exe",  # backup/VSS
    "onedrive.exe", "searchindexer.exe", "searchprotocolhost.exe",
}

_SUSPICIOUS_ORIGIN = re.compile(
    r"(\\temp\\|\\tmp\\|\\downloads\\|\\appdata\\local\\temp\\|"
    r"\\users\\public\\|\\programdata\\(?!yesnext)|^[a-z]:\\\$recycle|"
    r"^\\\\)",  # UNC / network share
    re.I,
)


# ── Config ─────────────────────────────────────────────────────────

DEFAULT_CONFIG = {
    "enabled": True,
    "baseline_interval_sec": 1800,          # 30 min
    "detect_interval_sec": 4.0,
    # Raw write-rate is only a WEAK supporting signal (browsers/editors/games
    # legitimately write fast). Thresholds are high to avoid alarm noise; they
    # never, on their own, contain a process.
    "fs_write_bytes_per_sec": 150 * 1024 * 1024,  # 150 MB/s sustained
    "fs_write_count_per_sec": 400,          # 400 file writes/s
    "score_threshold": 70,
    # SAFETY: automatic containment is OFF by default. NetworkGuard only raises
    # an alert; the operator confirms suspend/kill/restore from the dashboard
    # (contract: suspend-first + operator confirmation). Auto-actions caused
    # catastrophic false positives (froze Chrome/Cursor/GameLoop) and are gated.
    "auto_contain": False,                  # do NOT auto-suspend on detection
    "auto_kill": False,                     # never auto-kill
    "auto_restore": False,                  # legacy bomb-path; unused / hard-false
    # Network-surface only (adapters/DNS/IPv4/drives/firewall) — default ON.
    # Intentional IP change: operator network_snapshot BEFORE changing the host.
    "auto_restore_network": True,
    # Only these high-confidence signals may drive auto-containment when
    # auto_contain is explicitly enabled by an operator.
    "require_strong_signal": True,
}


def load_config(client_config: Optional[dict] = None) -> dict:
    cfg = dict(DEFAULT_CONFIG)
    try:
        ng = ((client_config or {}).get("protection") or {}).get("network_guard")
        if isinstance(ng, dict):
            cfg.update({k: v for k, v in ng.items() if k in cfg})
    except Exception:
        pass
    # C-CANARY-2: auto contain/kill/restore only when fleet gate AND config.
    # Missing canary → fail-closed (all false). Network-surface restore stays
    # separately gated by auto_restore_network (contract 1.4.14).
    want_contain = bool(cfg.get("auto_contain", False))
    want_kill = bool(cfg.get("auto_kill", False))
    want_restore = bool(cfg.get("auto_restore", False))
    try:
        from client_fleet_canary import GATE_NG, and_enabled
        cfg["auto_contain"] = and_enabled(GATE_NG, want_contain)
        cfg["auto_kill"] = and_enabled(GATE_NG, want_kill)
        cfg["auto_restore"] = and_enabled(GATE_NG, want_restore)
    except Exception:
        cfg["auto_contain"] = False
        cfg["auto_kill"] = False
        cfg["auto_restore"] = False
    cfg["auto_restore_network"] = bool(cfg.get("auto_restore_network", True))
    return cfg


# ── Operator maintenance mode (pause protect while changing VPN/IP) ──

def get_maintenance() -> dict:
    """Local persistent maintenance flag — survives restart; cloud enabled≠clear."""
    try:
        with open(MAINTENANCE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict) and data.get("active"):
            return {
                "active": True,
                "started_at": data.get("started_at"),
                "reason": data.get("reason") or "operator",
                "paused_by": data.get("paused_by") or "unknown",
            }
    except Exception:
        pass
    return {"active": False}


def set_maintenance(
    active: bool,
    reason: str = "operator",
    paused_by: str = "operator",
) -> dict:
    os.makedirs(MACHINE_DATA_DIR, exist_ok=True)
    if active:
        payload = {
            "active": True,
            "started_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "reason": str(reason or "operator")[:120],
            "paused_by": str(paused_by or "operator")[:64],
        }
    else:
        payload = {"active": False, "ended_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")}
    tmp = MAINTENANCE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    os.replace(tmp, MAINTENANCE_FILE)
    return get_maintenance() if active else {"active": False}


# ── Signing ────────────────────────────────────────────────────────

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


def _sign_baseline(payload: dict, token: str = None) -> str:
    token = _read_token() if token is None else token
    body = json.dumps(_strip_sig(payload), sort_keys=True, ensure_ascii=False)
    return hmac.new(_signing_secret(token), body.encode("utf-8"),
                    hashlib.sha256).hexdigest()


def _strip_sig(payload: dict) -> dict:
    return {k: v for k, v in payload.items() if k != "sig"}


def verify_baseline(payload: dict) -> bool:
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


# ── Collectors (Windows, best-effort) ───────────────────────────────

def _run(cmd: List[str], timeout: float = 8.0) -> str:
    """Run a command and decode output defensively.

    Windows console tools (netsh / net / powershell) emit OEM/locale-encoded
    bytes that break the default locale text decoder (e.g. cp1254 on TR hosts).
    Capture raw bytes and decode utf-8 first, then cp1254, always errors=replace.
    """
    try:
        r = subprocess.run(
            cmd, capture_output=True, timeout=timeout,
            creationflags=_NO_WINDOW,
        )
        raw = (r.stdout or b"") + (r.stderr or b"")
        for enc in ("utf-8", "cp1254", "cp850", "latin-1"):
            try:
                return raw.decode(enc)
            except Exception:
                continue
        return raw.decode("utf-8", errors="replace")
    except Exception:
        return ""


def _prefix_to_netmask(prefix: int) -> str:
    prefix = max(0, min(32, int(prefix or 24)))
    mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF if prefix else 0
    return ".".join(str((mask >> shift) & 0xFF) for shift in (24, 16, 8, 0))


def collect_mapped_drives() -> List[dict]:
    """Parse `net use` for mapped network drives."""
    out = _run(["net", "use"])
    drives: List[dict] = []
    for line in out.splitlines():
        m = re.search(r"([A-Z]:)\s+(\\\\[^\s]+)", line)
        if m:
            drives.append({"letter": m.group(1), "unc": m.group(2),
                           "persistent": "OK" in line or "Yes" in line})
    return drives


def collect_shares() -> List[dict]:
    """Parse `net share` for shares this host serves (skip default admin$)."""
    out = _run(["net", "share"])
    shares: List[dict] = []
    for line in out.splitlines():
        m = re.match(r"^(\S+)\s+([A-Za-z]:\\\S.*?)\s*$", line)
        if m:
            name = m.group(1)
            if name.endswith("$"):  # ADMIN$, C$, IPC$
                continue
            shares.append({"name": name, "path": m.group(2).strip()})
    return shares


def collect_adapters() -> List[dict]:
    """Adapter up/down + IPv4/DNS/gateway/DHCP via PowerShell."""
    ps = (
        "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; "
        "Get-NetIPConfiguration | ForEach-Object { "
        "$if=$_.InterfaceAlias; "
        "$dhcp=$false; $pfx=$null; "
        "try { $ip=Get-NetIPInterface -InterfaceAlias $if -AddressFamily IPv4 "
        "-ErrorAction SilentlyContinue | Select-Object -First 1; "
        "if ($ip) { $dhcp=($ip.Dhcp -eq 'Enabled') } } catch {}; "
        "try { $addr=$_.IPv4Address | Select-Object -First 1; "
        "if ($addr) { $pfx=$addr.PrefixLength } } catch {}; "
        "[pscustomobject]@{ name=$if; "
        "state=$_.NetAdapter.Status; "
        "ipv4=($_.IPv4Address.IPAddress -join ','); "
        "gateway=($_.IPv4DefaultGateway.NextHop -join ','); "
        "dns=($_.DNSServer | Where-Object {$_.AddressFamily -eq 2} | "
        "ForEach-Object {$_.ServerAddresses} ) -join ','; "
        "dhcp=$dhcp; prefix_length=$pfx } } | ConvertTo-Json -Compress"
    )
    out = _run(["powershell", "-NoProfile", "-Command", ps], timeout=15.0)
    adapters: List[dict] = []
    try:
        data = json.loads(out.strip()) if out.strip() else []
        if isinstance(data, dict):
            data = [data]
        for a in data:
            pfx = a.get("prefix_length")
            try:
                pfx = int(pfx) if pfx is not None and str(pfx) != "" else None
            except (TypeError, ValueError):
                pfx = None
            adapters.append({
                "name": a.get("name", ""),
                "state": str(a.get("state", "")).lower(),
                "ipv4": a.get("ipv4", "") or "",
                "gateway": a.get("gateway", "") or "",
                "dns": [d for d in str(a.get("dns", "")).split(",") if d],
                "dhcp": bool(a.get("dhcp")),
                "prefix_length": pfx,
            })
    except Exception:
        pass
    return adapters


def collect_firewall() -> dict:
    out = _run(["netsh", "advfirewall", "show", "allprofiles", "state"])
    fw = {"domain": "unknown", "private": "unknown", "public": "unknown"}
    cur = None
    for line in out.splitlines():
        low = line.lower()
        if "domain profile" in low:
            cur = "domain"
        elif "private profile" in low:
            cur = "private"
        elif "public profile" in low:
            cur = "public"
        elif cur and "state" in low:
            fw[cur] = "on" if "on" in low else ("off" if "off" in low else "unknown")
    return fw


def check_connectivity(dns_host: str = "8.8.8.8", port: int = 53,
                       timeout: float = 2.5) -> dict:
    internet_ok = False
    try:
        s = socket.create_connection((dns_host, port), timeout=timeout)
        s.close()
        internet_ok = True
    except Exception:
        internet_ok = False
    dns_ok = False
    try:
        socket.gethostbyname("cloudflare.com")
        dns_ok = True
    except Exception:
        dns_ok = False
    return {"internet_ok": internet_ok, "dns_ok": dns_ok,
            "gateway_ok": internet_ok}


def capture_baseline() -> dict:
    payload = {
        "version": 0,
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "mapped_drives": collect_mapped_drives(),
        "shares": collect_shares(),
        "adapters": collect_adapters(),
        "firewall": collect_firewall(),
        "connectivity": check_connectivity(),
    }
    return payload


# ── Baseline persistence + diff (pure, testable) ─────────────────────

def load_baseline() -> Optional[dict]:
    try:
        with open(BASELINE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data
    except Exception:
        return None


def _baseline_meaningful_change(old: Optional[dict], new: dict) -> bool:
    if not old:
        return True
    keys = ("mapped_drives", "shares", "adapters", "firewall")
    for k in keys:
        if json.dumps(old.get(k), sort_keys=True) != json.dumps(new.get(k), sort_keys=True):
            return True
    return False


def save_baseline(payload: dict) -> dict:
    """Persist baseline with version bump + rotation. Returns saved payload."""
    prev = load_baseline()
    if not _baseline_meaningful_change(prev, payload) and prev:
        # connectivity may change often; refresh connectivity in place only
        prev["connectivity"] = payload.get("connectivity", prev.get("connectivity"))
        prev["captured_at"] = payload.get("captured_at")
        prev["sig"] = _sign_baseline(prev)
        _atomic_write(BASELINE_FILE, prev)
        return prev
    payload["version"] = int((prev or {}).get("version", 0)) + 1
    payload["sig"] = _sign_baseline(payload)
    os.makedirs(MACHINE_DATA_DIR, exist_ok=True)
    _atomic_write(BASELINE_FILE, payload)
    _rotate_history(payload)
    return payload


def _atomic_write(path: str, data: dict) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def _rotate_history(payload: dict) -> None:
    try:
        os.makedirs(BASELINE_HISTORY_DIR, exist_ok=True)
        hp = os.path.join(BASELINE_HISTORY_DIR,
                          f"network_baseline.{payload['version']}.json")
        _atomic_write(hp, payload)
        files = sorted(
            (os.path.join(BASELINE_HISTORY_DIR, f)
             for f in os.listdir(BASELINE_HISTORY_DIR)
             if f.endswith(".json")),
            key=os.path.getmtime,
        )
        for old in files[:-BASELINE_KEEP]:
            try:
                os.remove(old)
            except Exception:
                pass
    except Exception:
        pass


def load_baseline_version(version: int) -> Optional[dict]:
    """Load and verify a retained baseline version for controlled rollback."""
    try:
        path = os.path.join(
            BASELINE_HISTORY_DIR, f"network_baseline.{int(version)}.json"
        )
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        return data if verify_baseline(data) else None
    except Exception:
        return None


def plan_network_restore(
    baseline: dict,
    targets: Optional[List[str]] = None,
) -> List[dict]:
    """NET-501 pure dry-run plan; never executes a command."""
    do = lambda name: targets is None or name in targets
    plan: List[dict] = []
    if do("adapter"):
        for adapter in baseline.get("adapters", []):
            if str(adapter.get("state")).lower() == "up" and adapter.get("name"):
                plan.append({
                    "target": "adapter",
                    "action": "enable",
                    "interface": adapter["name"],
                })
    if do("ipv4"):
        for adapter in baseline.get("adapters", []):
            if not adapter.get("name"):
                continue
            if str(adapter.get("state")).lower() != "up":
                continue
            if adapter.get("dhcp", True):
                plan.append({
                    "target": "ipv4",
                    "action": "dhcp",
                    "interface": adapter["name"],
                })
            elif adapter.get("ipv4"):
                plan.append({
                    "target": "ipv4",
                    "action": "static",
                    "interface": adapter["name"],
                    "ipv4": adapter.get("ipv4"),
                    "prefix_length": adapter.get("prefix_length") or 24,
                    "gateway": adapter.get("gateway") or "",
                })
    if do("dns"):
        for adapter in baseline.get("adapters", []):
            dns = adapter.get("dns") or []
            if dns and adapter.get("name"):
                plan.append({
                    "target": "dns",
                    "action": "set",
                    "interface": adapter["name"],
                    "servers": list(dns)[:8],
                })
    if do("firewall"):
        enabled = [
            profile for profile in ("domain", "private", "public")
            if (baseline.get("firewall") or {}).get(profile) == "on"
        ]
        plan.append({
            "target": "firewall",
            "action": "enable_profiles",
            "profiles": enabled,
        })
    if do("mapped_drive"):
        for drive in baseline.get("mapped_drives", []):
            if drive.get("persistent") and drive.get("letter") and drive.get("unc"):
                plan.append({
                    "target": "mapped_drive",
                    "action": "reconnect",
                    "letter": drive["letter"],
                    "unc": drive["unc"],
                })
    return plan[:128]


def _adapter_by_name(adapters: List[dict], name: str) -> Optional[dict]:
    for a in adapters or []:
        if a.get("name") == name:
            return a
    return None


def _is_link_local(ipv4: Optional[str]) -> bool:
    ip = (ipv4 or "").strip()
    return ip.startswith("169.254.")


def _adapter_is_up(adapter: Optional[dict]) -> bool:
    return str((adapter or {}).get("state") or "").lower() == "up"


def diff_network_surface(
    baseline: Optional[dict],
    live_adapters: Optional[List[dict]] = None,
    live_drives: Optional[List[dict]] = None,
    live_firewall: Optional[dict] = None,
) -> List[dict]:
    """Subtractive drift vs golden — feeds auto_restore_network only.

    Additive enrichment (adapter up / DHCP lease) belongs in
    ``diff_network_surface_inform`` and must never trigger restore (1.4.17).
    """
    if not baseline:
        return []
    live_adapters = live_adapters if live_adapters is not None else collect_adapters()
    live_drives = live_drives if live_drives is not None else collect_mapped_drives()
    live_firewall = live_firewall if live_firewall is not None else collect_firewall()
    changes: List[dict] = []

    for ba in baseline.get("adapters") or []:
        name = ba.get("name")
        if not name:
            continue
        la = _adapter_by_name(live_adapters, name)
        if str(ba.get("state")).lower() == "up":
            live_state = str((la or {}).get("state") or "").lower()
            if live_state in ("disconnected", "disabled", "down", "not present", ""):
                changes.append({
                    "id": f"adapter.{name}",
                    "target": "adapter",
                    "from": "up",
                    "to": live_state or "missing",
                    "interface": name,
                })
        if la is None:
            continue
        base_dns = [str(x) for x in (ba.get("dns") or [])]
        live_dns = [str(x) for x in (la.get("dns") or [])]
        if base_dns and set(base_dns) != set(live_dns):
            changes.append({
                "id": f"dns.{name}",
                "target": "dns",
                "from": base_dns,
                "to": live_dns,
                "interface": name,
            })
        if "dhcp" in ba and ba.get("dhcp") is not None:
            base_dhcp = bool(ba.get("dhcp"))
            live_dhcp = bool(la.get("dhcp", True))
            if base_dhcp != live_dhcp:
                changes.append({
                    "id": f"ipv4_mode.{name}",
                    "target": "ipv4",
                    "from": "dhcp" if base_dhcp else "static",
                    "to": "dhcp" if live_dhcp else "static",
                    "interface": name,
                })
            elif not base_dhcp:
                if (ba.get("ipv4") or "") and (la.get("ipv4") or "") != (ba.get("ipv4") or ""):
                    changes.append({
                        "id": f"ipv4.{name}",
                        "target": "ipv4",
                        "from": ba.get("ipv4"),
                        "to": la.get("ipv4"),
                        "interface": name,
                    })

    live_letters = {
        str(d.get("letter") or "").upper()
        for d in (live_drives or [])
        if d.get("letter")
    }
    for d in baseline.get("mapped_drives") or []:
        letter = str(d.get("letter") or "").upper()
        if letter and letter not in live_letters:
            changes.append({
                "id": f"drive.{letter}",
                "target": "mapped_drive",
                "from": d.get("unc"),
                "to": None,
                "letter": letter,
            })

    fw_base = baseline.get("firewall") or {}
    for prof in ("domain", "private", "public"):
        if fw_base.get(prof) == "on" and (live_firewall or {}).get(prof) == "off":
            changes.append({
                "id": f"firewall.{prof}",
                "target": "firewall",
                "from": "on",
                "to": "off",
                "profile": prof,
            })
    return changes


def diff_network_surface_inform(
    baseline: Optional[dict],
    live_adapters: Optional[List[dict]] = None,
) -> List[dict]:
    """Additive / benign enrichment vs golden — inform only, never restore.

    Examples: Ethernet cable plug-in, new NIC, DHCP lease change while online.
    Contract 1.4.17: while internet stays up, soft notify — no panic / no brick.
    """
    if not baseline:
        return []
    live_adapters = live_adapters if live_adapters is not None else collect_adapters()
    base_by = {
        a.get("name"): a for a in (baseline.get("adapters") or []) if a.get("name")
    }
    changes: List[dict] = []

    for la in live_adapters or []:
        name = la.get("name")
        if not name or not _adapter_is_up(la):
            continue
        live_ip = (la.get("ipv4") or "").strip()
        ba = base_by.get(name)
        if ba is None:
            changes.append({
                "id": f"adapter_new.{name}",
                "kind": "adapter_appeared",
                "target": "inform",
                "interface": name,
                "from": None,
                "to": "up",
                "ipv4": live_ip or None,
            })
            continue
        if not _adapter_is_up(ba):
            changes.append({
                "id": f"adapter_up.{name}",
                "kind": "adapter_enabled",
                "target": "inform",
                "interface": name,
                "from": str(ba.get("state") or "disconnected").lower(),
                "to": "up",
                "ipv4": live_ip or None,
            })
            continue
        # Both up: DHCP lease churn is inform-only (never auto_restore).
        if bool(ba.get("dhcp", True)) and bool(la.get("dhcp", True)):
            base_ip = (ba.get("ipv4") or "").strip()
            if (
                base_ip and live_ip and base_ip != live_ip
                and not (_is_link_local(base_ip) and _is_link_local(live_ip))
            ):
                changes.append({
                    "id": f"dhcp_lease.{name}",
                    "kind": "dhcp_lease",
                    "target": "inform",
                    "interface": name,
                    "from": base_ip,
                    "to": live_ip,
                    "ipv4": live_ip,
                })
    return changes


def inform_fingerprint(changes: List[dict]) -> str:
    return "|".join(sorted(str(c.get("id") or "") for c in (changes or []) if c.get("id")))


def refresh_baseline_connectivity(baseline: dict) -> dict:
    """Update connectivity probe only — never poison golden adapters/IP/DNS."""
    if not baseline:
        return baseline
    row = dict(baseline)
    row["connectivity"] = check_connectivity()
    # Keep captured_at as golden timestamp; probe time is separate.
    row["last_probe_at"] = datetime.now(timezone.utc).isoformat()
    row["sig"] = _sign_baseline(row)
    try:
        _atomic_write(BASELINE_FILE, row)
    except Exception as e:
        log(f"[NET-GUARD] connectivity refresh write failed: {e}")
    return row


def list_baseline_history() -> List[dict]:
    history: List[dict] = []
    try:
        if not os.path.isdir(BASELINE_HISTORY_DIR):
            return history
        files = sorted(
            (os.path.join(BASELINE_HISTORY_DIR, f)
             for f in os.listdir(BASELINE_HISTORY_DIR)
             if f.startswith("network_baseline.") and f.endswith(".json")),
        )
        for path in files[-BASELINE_KEEP:]:
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    row = json.load(fh)
                history.append({
                    "version": row.get("version"),
                    "captured_at": row.get("captured_at"),
                    "verified": verify_baseline(row),
                })
            except Exception:
                continue
    except Exception:
        pass
    return history


# ── Detection scoring (pure, testable) ───────────────────────────────

def score_signals(net_cut: bool, fs_storm: bool, suspicious_origin: bool,
                  vss_deleted: bool = False, canary: bool = False) -> int:
    if canary:
        return 100
    score = 0
    if net_cut:
        score += 45
    if fs_storm:
        score += 45
    if suspicious_origin:
        score += 20
    if vss_deleted:
        score += 45
    return min(score, 100)


def diff_connectivity(baseline: Optional[dict], current: dict) -> dict:
    """Return network-cut signal vs baseline.

    IMPORTANT: adapter-down is only evaluated when we actually have a fresh
    current adapter list (`_adapters` is a non-None list). If the caller did not
    collect adapters (None), we must NOT infer that every baseline adapter is
    down — that produced catastrophic false positives that froze normal apps.
    """
    base_conn = (baseline or {}).get("connectivity") or {}
    base_adapters = (baseline or {}).get("adapters") or []
    base_up = [a for a in base_adapters if str(a.get("state")).lower() == "up"]
    internet_lost = bool(base_conn.get("internet_ok")) and not current.get("internet_ok")

    adapters_down: List[str] = []
    cur_adapters = current.get("_adapters")
    # Only compute adapter-down when we have a real, non-empty current snapshot.
    if base_up and isinstance(cur_adapters, list) and cur_adapters:
        cur_up_names = {a.get("name") for a in cur_adapters
                        if str(a.get("state")).lower() == "up"}
        adapters_down = [a.get("name") for a in base_up
                         if a.get("name") not in cur_up_names]

    # Net-cut requires losing actual internet reachability. Adapter churn alone
    # (VPN toggling, Wi-Fi roaming) is NOT a ransomware signal on its own.
    return {
        "internet_lost": internet_lost,
        "adapters_down": adapters_down,
        "net_cut": bool(internet_lost),
    }


# ── NetworkGuard ─────────────────────────────────────────────────────

class NetworkGuard:
    def __init__(self, alert_pipeline=None, ransomware_shield=None,
                 config: Optional[dict] = None):
        self.alert_pipeline = alert_pipeline
        self.ransomware_shield = ransomware_shield
        self.cfg = config or dict(DEFAULT_CONFIG)
        self._running = False
        self._io_prev: Dict[int, tuple] = {}
        self._suspended: Dict[int, dict] = {}
        self._lock = threading.RLock()
        self._last_trigger_ts: Optional[str] = None
        self._last_baseline: Optional[dict] = None
        # Wi-Fi flap hygiene: internet_lost must persist before net_cut scores
        self._internet_lost_since: Optional[float] = None
        # Per trigger+pid dedupe (≥5 min) — CLIENT_ALERT_SIGNAL_HYGIENE.md §4
        self._trigger_dedupe: Dict[str, float] = {}
        self._TRIGGER_DEDUPE_SEC = 300
        self._NET_CUT_PERSIST_SEC = 15
        self._last_auto_restore_mono = 0.0
        self._AUTO_RESTORE_DEDUPE_SEC = 300
        # Additive surface inform (contract 1.4.17) — soft, never auto-disable
        self._inform_changes: List[dict] = []
        self._inform_fp: str = ""
        self._last_inform_emit_mono = 0.0
        self._INFORM_DEDUPE_SEC = 900
        # Cached live surface for STATUS — never block the single-threaded
        # control socket with PowerShell Get-NetIPConfiguration.
        self._cached_live: Dict[str, Any] = {}
        self._cached_live_mono = 0.0

    # -- lifecycle --

    def start(self):
        if get_maintenance().get("active"):
            log("[NET-GUARD] maintenance active — detect/auto-restore paused")
            self._running = False
            return
        if self._running or not self.cfg.get("enabled", True):
            return
        self._running = True
        threading.Thread(target=self._baseline_loop,
                         name="NetGuard-Baseline", daemon=True).start()
        threading.Thread(target=self._detect_loop,
                         name="NetGuard-Detect", daemon=True).start()
        log("[NET-GUARD] Started (baseline + offline detection)")

    def stop(self):
        self._running = False

    def enter_maintenance(self, reason: str = "operator", paused_by: str = "operator") -> dict:
        """Pause detect + auto_restore while operator changes VPN/IP/drives."""
        maint = set_maintenance(True, reason=reason, paused_by=paused_by)
        self.stop()
        log(f"[NET-GUARD] maintenance ON by={paused_by} reason={reason}")
        out = dict(self.status())
        out["ok"] = True
        return out

    def exit_maintenance(self, snapshot: bool = True, paused_by: str = "operator") -> dict:
        """End maintenance; optionally capture golden baseline then resume."""
        set_maintenance(False)
        saved = None
        if snapshot:
            try:
                saved = save_baseline(capture_baseline())
                self._last_baseline = saved
                log(f"[NET-GUARD] golden baseline v{saved.get('version')} after maintenance")
            except Exception as e:
                log(f"[NET-GUARD] post-maintenance snapshot failed: {e}")
                return {"ok": False, "error": f"snapshot_failed:{e}", **self.status()}
        # Resume if layer still enabled
        if self.cfg.get("enabled", True):
            self.start()
        log(f"[NET-GUARD] maintenance OFF by={paused_by} snapshot={bool(snapshot)}")
        out = dict(self.status())
        out["ok"] = True
        if saved:
            out["baseline_version"] = saved.get("version")
            out["captured_at"] = saved.get("captured_at")
        return out

    def snapshot_now(self) -> dict:
        saved = save_baseline(capture_baseline())
        self._last_baseline = saved
        # Accepting live as golden clears soft-inform pending state.
        self._inform_changes = []
        self._inform_fp = ""
        self._last_inform_emit_mono = 0.0
        return saved

    # -- A: baseline loop (golden — no poison) --

    def _baseline_loop(self):
        try:
            existing = load_baseline()
            if existing and verify_baseline(existing):
                self._last_baseline = existing
                log(f"[NET-GUARD] golden baseline v{existing.get('version')} loaded")
            else:
                self._last_baseline = save_baseline(capture_baseline())
                log(f"[NET-GUARD] baseline v{self._last_baseline.get('version')} captured")
        except Exception as e:
            log(f"[NET-GUARD] baseline capture error: {e}")
        interval = float(self.cfg.get("baseline_interval_sec", 1800))
        while self._running:
            time.sleep(min(interval, 60))
            if not self._running:
                break
            # Connectivity probe only — never adopt attacker IP/DNS into golden.
            if int(time.time()) % max(int(interval), 60) < 60:
                try:
                    base = self._last_baseline or load_baseline()
                    if base:
                        self._last_baseline = refresh_baseline_connectivity(base)
                except Exception as e:
                    log(f"[NET-GUARD] connectivity refresh error: {e}")

    # -- B: detection loop --

    def _detect_loop(self):
        interval = float(self.cfg.get("detect_interval_sec", 4.0))
        while self._running:
            time.sleep(interval)
            try:
                self._evaluate(interval)
            except Exception as e:
                log(f"[NET-GUARD] detect error: {e}")

    def _evaluate(self, interval: float):
        if get_maintenance().get("active"):
            return
        baseline = self._last_baseline or load_baseline()
        conn = check_connectivity()
        # Surface watch always needs adapters for auto_restore_network + dashboard.
        live_adapters = collect_adapters()
        live_drives = collect_mapped_drives()
        live_fw = collect_firewall()
        self._cached_live = {
            "adapters": live_adapters,
            "mapped_drives": live_drives,
            "firewall": live_fw,
            "connectivity": conn,
        }
        self._cached_live_mono = time.time()
        conn["_adapters"] = live_adapters if self._maybe_net_change(baseline, conn) else None
        netdiff = diff_connectivity(baseline, conn)

        # Short Wi-Fi flaps: require sustained internet_lost before net_cut scores
        now = time.time()
        if netdiff.get("internet_lost"):
            if self._internet_lost_since is None:
                self._internet_lost_since = now
            net_cut = (now - self._internet_lost_since) >= float(
                self.cfg.get("net_cut_persist_sec", self._NET_CUT_PERSIST_SEC)
            )
        else:
            self._internet_lost_since = None
            net_cut = False
        netdiff = dict(netdiff)
        netdiff["net_cut"] = bool(net_cut)

        # Network-surface auto restore (contract 1.4.14) — subtractive only
        self._maybe_auto_restore_network(baseline, live_adapters)
        # Additive soft inform while internet stays up (contract 1.4.17)
        self._maybe_surface_inform(baseline, live_adapters, conn)

        storm_suspects = self._fs_storm_suspects(interval)
        fs_storm = bool(storm_suspects)
        suspicious_origin = any(s.get("suspicious_origin") for s in storm_suspects)

        score = score_signals(
            net_cut=netdiff["net_cut"],
            fs_storm=fs_storm,
            suspicious_origin=suspicious_origin,
        )
        if score >= int(self.cfg.get("score_threshold", 70)):
            trigger = "+".join(
                t for t, on in (("network_cut", netdiff["net_cut"]),
                                ("fs_storm", fs_storm)) if on
            ) or "fs_storm"
            strong = self._has_strong_signal()
            self._trigger(trigger, score, netdiff, storm_suspects, baseline,
                          strong=strong)

    def _maybe_auto_restore_network(
        self,
        baseline: Optional[dict],
        live_adapters: Optional[List[dict]],
    ) -> None:
        if not bool(self.cfg.get("auto_restore_network", True)):
            return
        if get_maintenance().get("active"):
            return
        if not baseline or not verify_baseline(baseline):
            return
        now = time.time()
        if now - self._last_auto_restore_mono < self._AUTO_RESTORE_DEDUPE_SEC:
            return
        changes = diff_network_surface(baseline, live_adapters=live_adapters)
        if not changes:
            return
        targets = sorted({c.get("target") for c in changes if c.get("target")})
        log(f"[NET-GUARD] auto_restore_network targets={targets} n={len(changes)}")
        self._last_auto_restore_mono = now
        out = self.restore_network(baseline=baseline, targets=list(targets))
        self._emit_surface_restored(changes, out)

    def _maybe_surface_inform(
        self,
        baseline: Optional[dict],
        live_adapters: Optional[List[dict]],
        conn: Optional[dict],
    ) -> None:
        """Soft-notify additive enrichment; never disable / never restore."""
        if get_maintenance().get("active"):
            self._inform_changes = []
            self._inform_fp = ""
            return
        if not baseline:
            return
        # Panic path is internet loss — soft inform only while reachable.
        if conn is not None and conn.get("internet_ok") is False:
            return
        changes = diff_network_surface_inform(baseline, live_adapters=live_adapters)
        fp = inform_fingerprint(changes)
        self._inform_changes = list(changes)
        if not changes:
            self._inform_fp = ""
            return
        now = time.time()
        if fp == self._inform_fp and (
            now - self._last_inform_emit_mono
        ) < float(self.cfg.get("surface_inform_dedupe_sec", self._INFORM_DEDUPE_SEC)):
            return
        self._inform_fp = fp
        self._last_inform_emit_mono = now
        log(
            f"[NET-GUARD] surface_inform n={len(changes)} "
            f"ids={[c.get('id') for c in changes[:6]]}"
        )
        self._emit_surface_inform(changes, internet_ok=True)

    def _emit_surface_inform(
        self, changes: List[dict], *, internet_ok: bool = True
    ) -> None:
        if not self.alert_pipeline:
            return
        bits = []
        for c in changes[:6]:
            iface = c.get("interface") or "?"
            kind = c.get("kind") or c.get("id")
            ip = c.get("ipv4") or c.get("to") or ""
            bits.append(f"{iface}: {kind}" + (f" · {ip}" if ip else ""))
        alert = {
            "severity": "info",
            "threat_type": "network_surface_changed",
            "title": "Ağ yüzeyi genişledi (internet açık)",
            "description": "; ".join(bits) or "network surface changed",
            "threat_score": 15,
            "target_service": "SYSTEM",
            "recommended_action": "review_network",
            "force_urgent": False,
            "system_context": {
                "network_guard": {
                    "trigger": "surface_inform",
                    "internet_ok": bool(internet_ok),
                    "inform_changes": changes[:20],
                    "ts": datetime.now(timezone.utc).isoformat(),
                }
            },
        }
        try:
            if hasattr(self.alert_pipeline, "handle_alert"):
                self.alert_pipeline.handle_alert(alert)
            elif hasattr(self.alert_pipeline, "send_alert"):
                self.alert_pipeline.send_alert(alert)
            elif hasattr(self.alert_pipeline, "send_urgent"):
                # Last resort — still non-urgent payload (force_urgent=false)
                self.alert_pipeline.send_urgent(alert)
        except Exception as e:
            log(f"[NET-GUARD] surface inform alert failed: {e}")

    def accept_surface(self) -> dict:
        """Operator/user accepted live surface as new golden (Bu bendim)."""
        saved = self.snapshot_now()
        self._inform_changes = []
        self._inform_fp = ""
        self._last_inform_emit_mono = 0.0
        log(f"[NET-GUARD] surface accepted → golden v{saved.get('version')}")
        out = dict(self.status())
        out["ok"] = True
        out["version"] = saved.get("version")
        out["captured_at"] = saved.get("captured_at")
        return out

    def disable_adapter(self, name: str, *, dry_run: bool = False) -> dict:
        """Dashboard-only: disable one adapter. Never called automatically."""
        name = (name or "").strip()
        if not name:
            return {"ok": False, "error": "missing_name"}
        plan = [{
            "target": "adapter",
            "action": "disable",
            "interface": name,
        }]
        if dry_run:
            return {"ok": True, "dry_run": True, "plan": plan}
        out = _run([
            "netsh", "interface", "set", "interface",
            f"name={name}", "admin=DISABLED",
        ])
        low = (out or "").lower()
        ok = "error" not in low and "not found" not in low and "bulunamad" not in low
        # Empty output usually means success for netsh set interface.
        if out.strip() == "":
            ok = True
        log(f"[NET-GUARD] disable_adapter name={name!r} ok={ok}")
        return {
            "ok": bool(ok),
            "plan": plan,
            "restore_actions": [f"adapter_disable:{name}"] if ok else [],
            "error": None if ok else (out.strip() or "disable_failed"),
        }

    def _emit_surface_restored(self, changes: List[dict], restored: dict) -> None:
        if not self.alert_pipeline:
            return
        actions = restored.get("restore_actions") or []
        alert = {
            "severity": "warning",
            "threat_type": "network_surface_restored",
            "title": "Ağ yüzeyi golden baseline'dan geri yüklendi",
            "description": "; ".join(
                f"{c.get('id')}->{c.get('to')}" for c in changes[:8]
            ),
            "threat_score": 55,
            "target_service": "SYSTEM",
            "recommended_action": "review_network",
            "force_urgent": False,
            "system_context": {
                "network_guard": {
                    "trigger": "network_surface_drift",
                    "network": {
                        "restored": bool(actions),
                        "restore_actions": actions,
                        "changes": changes[:20],
                    },
                    "ts": datetime.now(timezone.utc).isoformat(),
                }
            },
        }
        try:
            if hasattr(self.alert_pipeline, "handle_alert"):
                self.alert_pipeline.handle_alert(alert)
            elif hasattr(self.alert_pipeline, "send_urgent"):
                self.alert_pipeline.send_urgent(alert)
        except Exception as e:
            log(f"[NET-GUARD] surface restore alert failed: {e}")

    def _has_strong_signal(self) -> bool:
        """High-confidence ransomware proof from the shield (canary / VSS)."""
        rs = self.ransomware_shield
        if rs is None:
            return False
        try:
            q = rs.get_quarantine() if hasattr(rs, "get_quarantine") else {}
            return bool(q.get("active"))
        except Exception:
            return False

    def _maybe_net_change(self, baseline, conn) -> bool:
        base_conn = (baseline or {}).get("connectivity") or {}
        return bool(base_conn.get("internet_ok")) and not conn.get("internet_ok")

    def _fs_storm_suspects(self, interval: float) -> List[dict]:
        """Per-process write-rate storm via psutil io_counters."""
        if psutil is None:
            return []
        suspects: List[dict] = []
        bps_thr = float(self.cfg.get("fs_write_bytes_per_sec", 40 * 1024 * 1024))
        cnt_thr = float(self.cfg.get("fs_write_count_per_sec", 150))
        now = time.time()
        cur: Dict[int, tuple] = {}
        for p in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
            try:
                pid = p.info["pid"]
                name = (p.info.get("name") or "").lower()
                if name in _PROTECTED_IMAGES:
                    continue
                io = p.io_counters()
                cur[pid] = (io.write_bytes, io.write_count, now)
                prev = self._io_prev.get(pid)
                if not prev:
                    continue
                dt = max(now - prev[2], 0.5)
                bps = (io.write_bytes - prev[0]) / dt
                cps = (io.write_count - prev[1]) / dt
                if bps >= bps_thr or cps >= cnt_thr:
                    exe = p.info.get("exe") or ""
                    suspects.append({
                        "pid": pid,
                        "image": name,
                        "path": exe,
                        "cmdline": " ".join(p.info.get("cmdline") or []),
                        # Stable process identity for operator-approved suspend.
                        # PID alone is unsafe because Windows may reuse it before
                        # the user clicks the dashboard action.
                        "process_start_time": float(p.create_time()),
                        "write_bytes_sec": int(bps),
                        "write_count_sec": int(cps),
                        "suspicious_origin": bool(_SUSPICIOUS_ORIGIN.search(exe or "")),
                    })
            except Exception:
                continue
        self._io_prev = cur
        return suspects

    # -- C: containment (suspend-first) --

    def _trigger(self, trigger: str, score: int, netdiff: dict,
                 suspects: List[dict], baseline: Optional[dict],
                 strong: bool = False):
        # Debounce identical trigger+pid (≥5 min) — avoid Wi-Fi/update storms
        now = time.time()
        pid = None
        if suspects:
            try:
                pid = int(suspects[0].get("pid") or 0) or None
            except (TypeError, ValueError):
                pid = None
        dedupe_key = f"{trigger}:{pid or 0}"
        dedupe_sec = float(
            self.cfg.get("trigger_dedupe_sec", self._TRIGGER_DEDUPE_SEC)
        )
        last = self._trigger_dedupe.get(dedupe_key, 0.0)
        if now - last < dedupe_sec:
            return
        # Legacy global debounce (tests / burst) — keep mild floor
        if now - getattr(self, "_last_trigger_mono", 0) < 5:
            return
        self._trigger_dedupe[dedupe_key] = now
        self._last_trigger_mono = now
        self._last_trigger_ts = datetime.now(timezone.utc).isoformat()

        # Auto-contain only when canary gate AND config enable (load_config AND).
        # Default / out-of-canary remains alert-only (C-CANARY-2).
        auto_contain = bool(strong and self.cfg.get("auto_contain", False))
        log(f"[NET-GUARD] {'CONTAIN' if auto_contain else 'ALERT-ONLY'} "
            f"{trigger} score={score} suspects={len(suspects)} strong={strong}")

        suspended = []
        if auto_contain:
            for s in suspects:
                if self._suspend_pid(s["pid"]):
                    s["state"] = "suspended"
                    with self._lock:
                        self._suspended[s["pid"]] = s
                    suspended.append(s)
                elif self.cfg.get("auto_kill"):
                    self._kill_pid(s["pid"])
                    s["state"] = "killed"
                    suspended.append(s)
        else:
            # Alert-only: mark suspects as observed, take no destructive action.
            for s in suspects:
                s["state"] = "observed"

        vss_ok = False
        restored = {}
        if auto_contain:
            vss_ok = self._emergency_vss()
            if self.cfg.get("auto_restore", False) and netdiff.get("net_cut"):
                restored = self.restore_network(baseline)

        self._send_alert(trigger, score, netdiff, suspects if not auto_contain
                         else suspended, vss_ok, restored, auto_contain)

    def _suspend_pid(self, pid: int) -> bool:
        if psutil is None:
            return False
        try:
            psutil.Process(pid).suspend()
            log(f"[NET-GUARD] suspended pid={pid}")
            return True
        except Exception as e:
            log(f"[NET-GUARD] suspend pid={pid} failed: {e}")
            return False

    def _kill_pid(self, pid: int) -> bool:
        if psutil is None:
            return False
        try:
            psutil.Process(pid).kill()
            return True
        except Exception:
            return False

    def release_suspended(self, pid: int) -> bool:
        if psutil is None:
            return False
        try:
            psutil.Process(pid).resume()
            with self._lock:
                self._suspended.pop(pid, None)
            return True
        except Exception:
            return False

    def kill_suspended(self, pid: int) -> bool:
        ok = self._kill_pid(pid)
        with self._lock:
            self._suspended.pop(pid, None)
        return ok

    def _emergency_vss(self) -> bool:
        """Best-effort shadow copy of system drive before encryption spreads."""
        drive = os.environ.get("SystemDrive", "C:") + "\\"
        out = _run(["wmic", "shadowcopy", "call", "create",
                    f"Volume={drive}"], timeout=30.0)
        ok = "ReturnValue = 0" in out or "successful" in out.lower()
        log(f"[NET-GUARD] emergency VSS snapshot ok={ok}")
        return ok

    # -- D: recovery --

    def restore_network(self, baseline: Optional[dict] = None,
                        targets: Optional[List[str]] = None,
                        dry_run: bool = False,
                        rollback_version: Optional[int] = None) -> dict:
        if rollback_version is not None:
            baseline = load_baseline_version(int(rollback_version))
            if not baseline:
                return {"error": "rollback_baseline_not_found_or_invalid"}
        baseline = baseline or self._last_baseline or load_baseline()
        if not baseline:
            return {"error": "no_baseline"}
        if not verify_baseline(baseline):
            return {"error": "baseline_signature_invalid"}
        plan = plan_network_restore(baseline, targets)
        if dry_run:
            return {
                "dry_run": True,
                "baseline_version": baseline.get("version"),
                "plan": plan,
                "restore_actions": [],
                "connectivity": check_connectivity(),
            }
        do = lambda t: (targets is None or t in targets)
        actions: List[str] = []

        if do("adapter"):
            for a in baseline.get("adapters", []):
                if str(a.get("state")).lower() == "up" and a.get("name"):
                    _run(["netsh", "interface", "set", "interface",
                          f'name={a["name"]}', "admin=enable"])
                    actions.append(f"adapter_enable:{a['name']}")
        if do("ipv4"):
            for a in baseline.get("adapters", []):
                name = a.get("name")
                if not name or str(a.get("state")).lower() != "up":
                    continue
                if a.get("dhcp", True):
                    _run(["netsh", "interface", "ip", "set", "address",
                          f"name={name}", "dhcp"])
                    actions.append(f"ipv4_dhcp:{name}")
                elif a.get("ipv4"):
                    ip = str(a.get("ipv4") or "").split(",")[0].strip()
                    pfx = int(a.get("prefix_length") or 24)
                    # netsh wants dotted mask; derive from prefix
                    mask = _prefix_to_netmask(pfx)
                    gw = str(a.get("gateway") or "").split(",")[0].strip()
                    cmd = ["netsh", "interface", "ip", "set", "address",
                           f"name={name}", "static", ip, mask]
                    if gw:
                        cmd.append(gw)
                    _run(cmd)
                    actions.append(f"ipv4_static:{name}")
        if do("dns"):
            for a in baseline.get("adapters", []):
                dns = a.get("dns") or []
                if dns and a.get("name"):
                    _run(["netsh", "interface", "ip", "set", "dns",
                          f'name={a["name"]}', "static", dns[0]])
                    for extra in dns[1:]:
                        _run(["netsh", "interface", "ip", "add", "dns",
                              f'name={a["name"]}', extra, "index=2"])
                    actions.append(f"dns_restore:{a['name']}")
        if do("firewall"):
            fw = baseline.get("firewall") or {}
            for prof in ("domain", "private", "public"):
                if fw.get(prof) == "on":
                    _run(["netsh", "advfirewall", "set", f"{prof}profile",
                          "state", "on"])
            actions.append("firewall_restore")
        if do("mapped_drive"):
            for d in baseline.get("mapped_drives", []):
                if d.get("persistent") and d.get("letter") and d.get("unc"):
                    _run(["net", "use", d["letter"], d["unc"], "/persistent:yes"])
                    actions.append(f"netuse:{d['letter']}")

        # verify connectivity after restore
        conn = check_connectivity()
        log(f"[NET-GUARD] restore actions={actions} internet_ok={conn['internet_ok']}")
        return {
            "dry_run": False,
            "baseline_version": baseline.get("version"),
            "rollback_version": rollback_version,
            "plan": plan,
            "restore_actions": actions,
            "connectivity": conn,
        }

    # -- E: alert --

    def _send_alert(self, trigger, score, netdiff, suspects, vss_ok, restored,
                    auto_contain=False):
        if not self.alert_pipeline or not hasattr(self.alert_pipeline, "send_urgent"):
            return
        ng = {
            "trigger": trigger,
            "score": score,
            "auto_contain": bool(auto_contain),
            "network": {
                "internet_lost": netdiff.get("internet_lost"),
                "adapters_down": netdiff.get("adapters_down") or [],
                "restored": bool(restored.get("restore_actions")),
                "restore_actions": restored.get("restore_actions") or [],
            },
            "suspects": [
                {k: s.get(k) for k in ("pid", "image", "path", "cmdline",
                                       "state", "write_bytes_sec",
                                       "write_count_sec", "suspicious_origin",
                                       "process_start_time")}
                for s in suspects
            ],
            "vss_emergency_snapshot": bool(vss_ok),
            "ts": self._last_trigger_ts,
        }
        # Alert-only detections are "suspicious", not confirmed critical —
        # avoid crying wolf (and avoid isolate_host recommendations) unless we
        # actually contained something on strong evidence.
        if auto_contain:
            threat_type = "ransomware_offline_bomb"
            severity = "critical"
            title = "🔴 OFFLINE FİDYE BOMBASI — kütle şifreleme (containment)"
            desc = (f"Yüksek güvenli fidye imzası (trigger={trigger}, skor={score}). "
                    f"{len(suspects)} süreç donduruldu; "
                    f"ağ {'geri yüklendi' if ng['network']['restored'] else 'incelendi'}.")
            action = "isolate_host"
            resp = (["suspend", "emergency_vss"]
                    + (["network_restore"] if ng["network"]["restored"] else []))
        else:
            threat_type = "ransomware_offline_suspect"
            severity = "warning"
            title = "🟠 Şüpheli yoğun disk aktivitesi (inceleme)"
            desc = (f"Yoğun yazma/ağ sinyali gözlendi (trigger={trigger}, skor={score}). "
                    f"{len(suspects)} süreç işaretlendi — otomatik müdahale YAPILMADI. "
                    f"Dashboard'dan inceleyip gerekirse suspend/kill onaylayın.")
            action = "review_suspects"
            resp = ["alert_only"]
        try:
            self.alert_pipeline.send_urgent({
                "severity": severity,
                "threat_type": threat_type,
                "title": title,
                "description": desc,
                "threat_score": score,
                "target_service": "SYSTEM",
                "recommended_action": action,
                "system_context": {"network_guard": ng},
                "raw_events": [{
                    "kind": "network_guard",
                    "trigger": trigger,
                    "auto_contain": bool(auto_contain),
                    "suspect_pid": (suspects[0]["pid"] if suspects else None),
                    "image": (suspects[0]["image"] if suspects else None),
                    "state": (suspects[0].get("state") if suspects else None),
                }],
                "auto_response_taken": resp,
            })
        except Exception as e:
            log(f"[NET-GUARD] send_urgent failed: {e}")

    # -- status --

    def status(self) -> dict:
        """Fast STATUS snapshot — uses detect-loop cache, no PowerShell.

        Full live collect belongs on `list_baseline` / `diff_now` (commands).
        """
        base = self._last_baseline or load_baseline() or {}
        age = None
        try:
            if base.get("captured_at"):
                dt = datetime.fromisoformat(base["captured_at"].replace("Z", "+00:00"))
                age = int((datetime.now(timezone.utc) - dt).total_seconds())
        except Exception:
            pass
        cached = dict(self._cached_live or {})
        live_adapters = list(cached.get("adapters") or [])
        live_drives = list(cached.get("mapped_drives") or [])
        live_fw = dict(cached.get("firewall") or {})
        live_conn = dict(cached.get("connectivity") or {})
        changes: List[dict] = []
        inform: List[dict] = []
        try:
            if base and (live_adapters or live_drives or live_fw):
                changes = diff_network_surface(
                    base, live_adapters=live_adapters,
                    live_drives=live_drives, live_firewall=live_fw,
                )
                inform = diff_network_surface_inform(
                    base, live_adapters=live_adapters,
                )
        except Exception:
            pass
        # Prefer live compute; fall back to last detect-loop cache
        if not inform and self._inform_changes:
            inform = list(self._inform_changes)
        with self._lock:
            suspended = len(self._suspended)
        maint = get_maintenance()
        cache_age = None
        try:
            if self._cached_live_mono:
                cache_age = int(time.time() - self._cached_live_mono)
        except Exception:
            pass
        return {
            "present": True,
            "enabled": bool(self.cfg.get("enabled", True)),
            "maintenance": bool(maint.get("active")),
            "maintenance_started_at": maint.get("started_at"),
            "maintenance_reason": maint.get("reason"),
            "maintenance_paused_by": maint.get("paused_by"),
            "baseline_version": base.get("version"),
            "baseline_age_sec": age,
            "baseline_captured_at": base.get("captured_at"),
            "verified": verify_baseline(base) if base else False,
            "internet_ok": live_conn.get("internet_ok",
                                         (base.get("connectivity") or {}).get("internet_ok")),
            "mapped_drives": len(live_drives) if live_drives else len(base.get("mapped_drives") or []),
            "suspended_processes": suspended,
            "last_trigger_ts": self._last_trigger_ts,
            "drift": bool(changes),
            "drift_count": len(changes),
            "surface_inform": bool(inform),
            "surface_inform_count": len(inform),
            "surface_inform_changes": inform[:20],
            "live_cache_age_sec": cache_age,
            "auto_contain": bool(self.cfg.get("auto_contain", False)),
            "auto_restore": bool(self.cfg.get("auto_restore", False)),
            "auto_kill": bool(self.cfg.get("auto_kill", False)),
            "auto_restore_network": bool(self.cfg.get("auto_restore_network", True))
            and not bool(maint.get("active")),
            "live": {
                "adapters": live_adapters,
                "mapped_drives": live_drives,
                "firewall": live_fw,
                "connectivity": live_conn,
            },
            "baseline": {
                "adapters": base.get("adapters") or [],
                "mapped_drives": base.get("mapped_drives") or [],
                "firewall": base.get("firewall") or {},
            },
        }

    def list_baseline(self) -> dict:
        base = self._last_baseline or load_baseline() or {}
        live_adapters = collect_adapters()
        live_drives = collect_mapped_drives()
        live_fw = collect_firewall()
        live_conn = check_connectivity()
        changes = diff_network_surface(
            base, live_adapters=live_adapters,
            live_drives=live_drives, live_firewall=live_fw,
        ) if base else []
        inform = diff_network_surface_inform(
            base, live_adapters=live_adapters,
        ) if base else []
        return {
            "version": base.get("version"),
            "captured_at": base.get("captured_at"),
            "verified": verify_baseline(base) if base else False,
            "baseline": {
                "adapters": base.get("adapters") or [],
                "mapped_drives": base.get("mapped_drives") or [],
                "shares": base.get("shares") or [],
                "firewall": base.get("firewall") or {},
                "connectivity": base.get("connectivity") or {},
            },
            # Backward-compatible flat keys
            "mapped_drives": base.get("mapped_drives") or [],
            "shares": base.get("shares") or [],
            "adapters": base.get("adapters") or [],
            "firewall": base.get("firewall") or {},
            "live": {
                "adapters": live_adapters,
                "mapped_drives": live_drives,
                "firewall": live_fw,
                "connectivity": live_conn,
            },
            "drift": bool(changes),
            "changes": changes,
            "surface_inform": bool(inform),
            "inform_changes": inform,
            "history": list_baseline_history(),
            "auto_restore_network": bool(self.cfg.get("auto_restore_network", True)),
        }

    def diff_now(self, version: Optional[int] = None) -> dict:
        baseline = None
        if version is not None:
            baseline = load_baseline_version(int(version))
            if not baseline:
                return {"error": "rollback_baseline_not_found_or_invalid"}
        else:
            baseline = self._last_baseline or load_baseline()
        if not baseline:
            return {"error": "no_baseline"}
        if not verify_baseline(baseline):
            return {"error": "baseline_signature_invalid"}
        changes = diff_network_surface(baseline)
        inform = diff_network_surface_inform(baseline)
        return {
            "baseline_version": baseline.get("version"),
            "changes": changes,
            "drift": bool(changes),
            "inform_changes": inform,
            "surface_inform": bool(inform),
            "live": {
                "adapters": collect_adapters(),
                "mapped_drives": collect_mapped_drives(),
                "connectivity": check_connectivity(),
            },
        }
