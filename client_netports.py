# -*- coding: utf-8 -*-
"""Port exposure + port_expose command (contract ≥1.4.107).

Modes for a local TCP port:
  all   — inbound Allow from Any (internet-open)
  ips   — inbound Allow from a closed list of remote IPs
  close — remove Asteria-managed allow rules for that port

Also used by ThreatEngine's privileged-SQL first-fail check: a service is
"internet-exposed" when any inbound Allow for its listen port has remote=Any.
"""
from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

CREATE_NO_WINDOW = 0x08000000

_SERVICE_PORTS = {
    "RDP": 3389, "MSSQL": 1433, "MYSQL": 3306, "SSH": 22, "FTP": 21,
}
_RISKY = {1433, 3306, 3389, 22, 21, 445}
_UNDO_DIR = os.path.join(os.environ.get("PROGRAMDATA", r"C:\ProgramData"), "Asteria", "fw_undo")


def _run(cmd, timeout=30) -> Tuple[int, str, str]:
    try:
        p = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            creationflags=CREATE_NO_WINDOW,
        )
        return p.returncode, p.stdout or "", p.stderr or ""
    except Exception as e:
        return 1, "", str(e)


def _ps(script: str, timeout: int = 60) -> Tuple[int, str, str]:
    return _run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
        timeout=timeout,
    )


def listen_port_for(service: str) -> int:
    try:
        from client_service_ports import get_listen_port
        return int(get_listen_port(service, _SERVICE_PORTS.get(service.upper(), 0)))
    except Exception:
        return int(_SERVICE_PORTS.get((service or "").upper(), 0) or 0)


def service_exposed(service: str) -> bool:
    """True when the service's listen port has an inbound Allow from Any."""
    port = listen_port_for(service)
    if port <= 0:
        return False
    return exposure_of_port(port) == "open"


def exposure_of_port(port: int, rules: Optional[List[dict]] = None) -> str:
    """open | restricted | closed | local_only."""
    try:
        port = int(port)
    except (TypeError, ValueError):
        return "closed"
    if port <= 0:
        return "closed"
    if rules is None:
        rules = inbound_rules_for_port(port)
    allows = [r for r in rules if str(r.get("action") or "").lower() == "allow"
              and bool(r.get("enabled", True))]
    if not allows:
        return "closed"
    any_open = False
    restricted = False
    for r in allows:
        rem = str(r.get("remote_address") or r.get("RemoteAddress") or "Any").strip()
        rem_l = rem.lower()
        if rem_l in ("any", "herhangi", "*", ""):
            any_open = True
        elif rem_l in ("localsubnet", "local subnet"):
            restricted = True
        else:
            # Specific IPs / CIDRs — still inbound from outside the host
            restricted = True
    if any_open:
        return "open"
    if restricted:
        return "restricted"
    return "closed"


def inbound_rules_for_port(port: int) -> List[dict]:
    """Best-effort: enumerate inbound rules that mention this local port."""
    try:
        from client_firewall_inventory import list_firewall
        data = list_firewall({
            "scope": "all", "include_profiles": False,
            "include_inbound": True, "include_outbound": False,
            "include_asteria_rules": False, "include_counts": False,
            "max_rules_per_direction": 5000,
        })
        rules = data.get("inbound_rules") or []
    except Exception:
        rules = []
    out = []
    for r in rules:
        lp = str(r.get("local_port") or r.get("LocalPort") or "").strip()
        if not lp or lp.lower() == "any":
            continue
        if str(port) in {p.strip() for p in re.split(r"[,;]", lp)}:
            out.append(r)
    return out


def classify_listening(ports: List[dict], fw_rules: Optional[List[dict]] = None) -> List[dict]:
    """Annotate open_ports rows with exposure + risk flag."""
    out = []
    for p in ports or []:
        row = dict(p)
        try:
            port = int(row.get("port") or 0)
        except (TypeError, ValueError):
            port = 0
        rules = inbound_rules_for_port(port) if fw_rules is None else [
            r for r in fw_rules
            if str(port) in {x.strip() for x in re.split(
                r"[,;]", str(r.get("local_port") or "")
            )}
        ]
        exposure = exposure_of_port(port, rules)
        # Bind address hints "local only"
        bind = str(row.get("address") or row.get("local_address") or "").strip()
        if bind in ("127.0.0.1", "::1", "localhost") and exposure != "closed":
            exposure = "local_only"
        row["exposure"] = exposure
        row["risky"] = bool(port in _RISKY and exposure == "open")
        out.append(row)
    return out


# ── port_expose ───────────────────────────────────────────────────

def _save_undo(undo_id: str, data: dict) -> str:
    os.makedirs(_UNDO_DIR, exist_ok=True)
    path = os.path.join(_UNDO_DIR, f"{undo_id}.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
    return path


def _load_undo(undo_id: str) -> Optional[dict]:
    path = os.path.join(_UNDO_DIR, f"{undo_id}.json")
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return None


def _drop_undo(undo_id: str) -> None:
    try:
        os.remove(os.path.join(_UNDO_DIR, f"{undo_id}.json"))
    except OSError:
        pass


def port_expose(params: Optional[dict] = None) -> dict:
    """mode=all|ips|close for a local TCP port. Always snapshots for undo."""
    from client_admin_ops import std, step
    params = params or {}
    if params.get("undo_id") and (params.get("restore") or params.get("op") == "undo"):
        return port_expose_undo(str(params["undo_id"]))

    try:
        port = int(params.get("port") or 0)
    except (TypeError, ValueError):
        port = 0
    mode = str(params.get("mode") or "").strip().lower()
    ips = params.get("ips") or params.get("addresses") or []
    if isinstance(ips, str):
        ips = [x.strip() for x in re.split(r"[,;\s]+", ips) if x.strip()]
    force = bool(params.get("force"))
    dry = bool(params.get("dry_run"))
    if port <= 0 or port > 65535:
        return std(False, "BAD_PORT", "port 1-65535 gerekli")
    if mode not in ("all", "ips", "close"):
        return std(False, "BAD_MODE", "mode must be all|ips|close")
    if mode == "ips" and not ips:
        return std(False, "MISSING_IPS", "ips[] gerekli (mode=ips)")

    # Self-lockout guard — never close / restrict RDP away from management IP
    # and never touch outbound 443 (handled in firewall_rule).
    try:
        from client_firewall_inventory import guard_port_change
        g = guard_port_change(port=port, mode=mode, ips=ips, force=force)
        if not g.get("ok"):
            return std(False, g.get("code") or "GUARD", g.get("message") or "guard",
                       steps=[step("guard", False, g.get("message") or "")],
                       **{k: v for k, v in g.items() if k not in ("ok", "code", "message")})
    except Exception as e:
        return std(False, "GUARD_ERROR", str(e))

    existing = inbound_rules_for_port(port)
    undo_id = str(uuid.uuid4())
    snapshot = {
        "kind": "port_expose", "port": port, "mode": mode,
        "created_at": time.time(),
        "rules": [
            {
                "name": r.get("name"), "id": r.get("id") or r.get("guid"),
                "enabled": r.get("enabled"), "action": r.get("action"),
                "remote_address": r.get("remote_address"),
                "direction": r.get("direction") or "In",
                "local_port": r.get("local_port"),
                "protocol": r.get("protocol") or "TCP",
                "asteria_managed": bool(r.get("asteria_prefix") or
                                       str(r.get("name") or "").startswith("AR-PORT-")),
            }
            for r in existing
        ],
        "created_rule": None,
    }
    steps = [step("snapshot", True, f"{len(existing)} rule(s)")]
    if dry:
        return std(True, "DRY_RUN", f"port {port} → {mode}", steps=steps,
                   undo_id=undo_id, exposure_before=exposure_of_port(port, existing),
                   planned={"mode": mode, "ips": ips})

    # Remove previous AR-PORT-* rules for this port so mode switches cleanly
    for r in existing:
        name = str(r.get("name") or "")
        if name.startswith("AR-PORT-"):
            _run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"], 30)
            steps.append(step("delete_old", True, name))

    created = None
    if mode in ("all", "ips"):
        remote = "Any" if mode == "all" else ",".join(ips)
        name = f"AR-PORT-{port}-{mode}"
        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={name}", "dir=in", "action=allow", "enable=yes",
            "protocol=TCP", f"localport={port}", f"remoteip={remote}",
            f"description=Asteria port_expose {mode}",
        ]
        rc, out, err = _run(cmd, 60)
        if rc != 0:
            return std(False, "ADD_FAILED", (err or out or "add failed")[:300], steps=steps)
        created = name
        steps.append(step("add_allow", True, f"{name} remote={remote}"))
        snapshot["created_rule"] = name
    else:
        # close: also disable non-Asteria allow rules that open the port to Any
        for r in existing:
            if str(r.get("action") or "").lower() != "allow":
                continue
            rem = str(r.get("remote_address") or "Any").lower()
            if rem not in ("any", "herhangi", "*", ""):
                continue
            name = str(r.get("name") or "")
            if not name:
                continue
            # Prefer disable (reversible) over delete for third-party rules
            rc, out, err = _run(
                ["netsh", "advfirewall", "firewall", "set", "rule",
                 f"name={name}", "new", "enable=no"], 60,
            )
            steps.append(step("disable", rc == 0, name))

    _save_undo(undo_id, snapshot)
    # Arm a dead-man: if the cloud can't reach us after a risky change, undo
    if mode in ("close", "ips") and port == listen_port_for("RDP"):
        try:
            from client_firewall_inventory import arm_firewall_dead_man
            arm_firewall_dead_man(undo_id, minutes=5)
            steps.append(step("dead_man", True, "5m"))
        except Exception:
            pass
    return std(True, "PORT_EXPOSED", f"port {port} → {mode}", steps=steps,
               undo_id=undo_id, port=port, mode=mode, created_rule=created,
               exposure=exposure_of_port(port))


def port_expose_undo(undo_id: str) -> dict:
    from client_admin_ops import std, step
    snap = _load_undo(undo_id)
    if not snap:
        return std(False, "UNDO_MISSING", f"undo_id {undo_id} yok")
    steps = []
    created = snap.get("created_rule")
    if created:
        _run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={created}"], 30)
        steps.append(step("delete_created", True, created))
    for r in snap.get("rules") or []:
        name = str(r.get("name") or "")
        if not name:
            continue
        if r.get("asteria_managed") and str(r.get("enabled")):
            # Recreate Asteria-managed allow that we deleted
            rem = r.get("remote_address") or "Any"
            cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={name}", "dir=in",
                f"action={(r.get('action') or 'Allow').lower()}",
                f"enable={'yes' if r.get('enabled') else 'no'}",
                f"protocol={r.get('protocol') or 'TCP'}",
                f"localport={r.get('local_port') or snap.get('port')}",
                f"remoteip={rem}",
            ]
            rc, out, err = _run(cmd, 60)
            steps.append(step("restore_ar", rc == 0, name))
        else:
            # Re-enable third-party rule we disabled
            rc, out, err = _run(
                ["netsh", "advfirewall", "firewall", "set", "rule",
                 f"name={name}", "new",
                 f"enable={'yes' if r.get('enabled') else 'no'}"], 60,
            )
            steps.append(step("restore", rc == 0, name))
    _drop_undo(undo_id)
    try:
        from client_firewall_inventory import cancel_firewall_dead_man
        cancel_firewall_dead_man(undo_id)
    except Exception:
        pass
    return std(True, "PORT_RESTORED", f"port {snap.get('port')} restored",
               steps=steps, undo_id=undo_id, port=snap.get("port"))
