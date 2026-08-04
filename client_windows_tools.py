#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Windows admin tool shortcuts + health repair helpers for Control Center Tools page.

Repairs are allowlisted and confirmation-gated for destructive actions.
Prefer running elevated (Administrator). ASCII-safe logging.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
import winreg
from pathlib import Path
from typing import Any, Dict, List, Optional

# MMC / control panel shortcuts (open in user session)
# Includes classic Administrative Tools entries commonly present on Server/Client.
_OPEN_TOOLS: Dict[str, Dict[str, str]] = {
    "eventvwr": {"label": "Event Viewer", "target": "eventvwr.msc"},
    "services": {"label": "Services", "target": "services.msc"},
    "taskmgr": {"label": "Task Manager", "target": "taskmgr.exe"},
    "regedit": {"label": "Registry Editor", "target": "regedit.exe"},
    "firewall": {"label": "Windows Firewall", "target": "firewall.cpl"},
    "wf": {"label": "Advanced Firewall", "target": "wf.msc"},
    "msconfig": {"label": "System Configuration", "target": "msconfig.exe"},
    "compmgmt": {"label": "Computer Management", "target": "compmgmt.msc"},
    "devmgmt": {"label": "Device Manager", "target": "devmgmt.msc"},
    "diskmgmt": {"label": "Disk Management", "target": "diskmgmt.msc"},
    "taskschd": {"label": "Task Scheduler", "target": "taskschd.msc"},
    "lusrmgr": {"label": "Local Users", "target": "lusrmgr.msc"},
    "gpedit": {"label": "Local Group Policy", "target": "gpedit.msc"},
    "secpol": {"label": "Local Security Policy", "target": "secpol.msc"},
    "comexp": {"label": "Component Services", "target": "comexp.msc"},
    "printmgmt": {"label": "Print Management", "target": "printmanagement.msc"},
    "hyperv": {"label": "Hyper-V Manager", "target": "virtmgmt.msc"},
    "tsadmin": {"label": "Terminal Services", "target": "tsadmin.msc"},
    "server_manager": {"label": "Server Manager", "target": "ServerManager.exe"},
    "wbadmin": {"label": "Windows Server Backup", "target": "wbadmin.msc"},
    "iscsi": {"label": "iSCSI Initiator", "target": "iscsicpl.exe"},
    "odbc64": {"label": "ODBC Data Sources (64-bit)", "target": "odbcad32.exe"},
    "odbc32": {"label": "ODBC Data Sources (32-bit)", "target": r"%SystemRoot%\SysWOW64\odbcad32.exe"},
    "msinfo": {"label": "System Information", "target": "msinfo32.exe"},
    "dfrgui": {"label": "Optimize Drives", "target": "dfrgui.exe"},
    "mdsched": {"label": "Windows Memory Diagnostic", "target": "mdsched.exe"},
    "recovery_drive": {"label": "Recovery Drive", "target": "RecoveryDrive.exe"},
    "ncpa": {"label": "Network Adapters", "target": "ncpa.cpl"},
    "appwiz": {"label": "Programs and Features", "target": "appwiz.cpl"},
    "sysdm": {"label": "System Properties", "target": "sysdm.cpl"},
    "optionalfeatures": {"label": "Windows Features", "target": "optionalfeatures.exe"},
    "winver": {"label": "Windows Version", "target": "winver.exe"},
    "control": {"label": "Control Panel", "target": "control.exe"},
    "powershell": {"label": "PowerShell", "target": "powershell.exe"},
    "cmd": {"label": "Command Prompt", "target": "cmd.exe"},
    "resmon": {"label": "Resource Monitor", "target": "resmon.exe"},
    "perfmon": {"label": "Performance Monitor", "target": "perfmon.exe"},
    "cleanmgr": {"label": "Disk Cleanup", "target": "cleanmgr.exe"},
    "dxdiag": {"label": "DirectX Diagnostic", "target": "dxdiag.exe"},
}

_REPAIR_ACTIONS = frozenset(
    {
        "status",
        "diagnose",
        "dns_flush",
        "webview2",
        "winsock_reset",
        "firewall_reset",
        "wu_reset",
        "sfc_scan",
        "dism_health",
        "policy_restore",
        "fix_taskmgr",
        "fix_regedit",
        "fix_cmd",
        "fix_shell",
        "restart_explorer",
        "restart_taskmgr",
        "restart_critical_services",
        "icon_cache",
        "clear_temp",
        "time_sync",
        "auto_fix_findings",
        "full_safe",
        "share_network_fix",
        "printer_fix",
        "audio_fix",
    }
)

_DESTRUCTIVE = frozenset({"winsock_reset", "firewall_reset", "wu_reset"})

# Soft repairs that do not need confirm and can run without full admin in some cases
_SOFT_NO_ADMIN = frozenset(
    {
        "status",
        "diagnose",
        "dns_flush",
        "sfc_scan",
        "dism_health",
        "restart_explorer",
        "restart_taskmgr",
        "icon_cache",
        "clear_temp",
    }
)

_CRITICAL_SERVICES = (
    "EventLog",
    "Schedule",
    "Winmgmt",
    "RpcSs",
    "Dnscache",
    "Dhcp",
    "LanmanServer",
    "LanmanWorkstation",
    "wuauserv",
    "BITS",
    "CryptSvc",
    "Spooler",
    "AudioSrv",
    "Themes",
    "ProfSvc",
)


def list_open_tools() -> List[Dict[str, str]]:
    return [{"id": k, **v} for k, v in _OPEN_TOOLS.items()]


def is_admin() -> bool:
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _reg_dword(hive: int, path: str, name: str) -> Optional[int]:
    try:
        with winreg.OpenKey(hive, path) as key:
            val, typ = winreg.QueryValueEx(key, name)
            if typ == winreg.REG_DWORD:
                return int(val)
    except OSError:
        return None
    return None


def _reg_sz(hive: int, path: str, name: str) -> Optional[str]:
    try:
        with winreg.OpenKey(hive, path) as key:
            val, _ = winreg.QueryValueEx(key, name)
            return str(val) if val is not None else None
    except OSError:
        return None


def _delete_reg_value(hive: int, path: str, name: str) -> bool:
    try:
        with winreg.OpenKey(hive, path, 0, winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, name)
            return True
    except OSError:
        return False


def _set_reg_sz(hive: int, path: str, name: str, value: str) -> bool:
    try:
        with winreg.CreateKeyEx(hive, path, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, name, 0, winreg.REG_SZ, value)
            return True
    except OSError:
        return False


def _set_reg_dword(hive: int, path: str, name: str, value: int) -> bool:
    try:
        with winreg.CreateKeyEx(hive, path, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, name, 0, winreg.REG_DWORD, int(value))
            return True
    except OSError:
        return False


def _svc_auto_start(name: str) -> Dict[str, Any]:
    cfg = _run_hidden(["sc.exe", "config", name, "start=", "auto"], timeout=15)
    start = _run_hidden(["sc.exe", "start", name], timeout=25)
    return {
        "config_ok": bool(cfg.get("ok")),
        "start_code": start.get("exit_code"),
        "start_ok": bool(start.get("ok"))
        or "RUNNING"
        in ((start.get("stdout") or "") + (start.get("stderr") or "")).upper(),
    }


def _process_running(name: str) -> bool:
    try:
        raw = subprocess.check_output(  # noqa: S603
            ["tasklist", "/FI", f"IMAGENAME eq {name}", "/NH"],
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            timeout=15,
        )
        out = raw.decode("utf-8", errors="replace") if isinstance(raw, (bytes, bytearray)) else str(raw)
        return name.lower() in out.lower()
    except Exception:
        return False


def _policy_disabled(name: str) -> bool:
    """True when a Disable* policy DWORD is set to a blocking value."""
    paths = (
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Policies\System"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"),
    )
    for hive, path in paths:
        val = _reg_dword(hive, path, name)
        if val is not None and int(val) != 0:
            return True
    return False


def diagnose() -> Dict[str, Any]:
    """Detect common Windows breakage; each finding may suggest a repair id."""
    findings: List[Dict[str, Any]] = []

    def add(fid: str, severity: str, ok: bool, detail: str, fix: str = "") -> None:
        findings.append(
            {
                "id": fid,
                "severity": severity,
                "ok": ok,
                "detail": detail,
                "fix": fix,
            }
        )

    # Task Manager
    if _policy_disabled("DisableTaskMgr"):
        add("taskmgr_policy", "high", False, "Task Manager disabled by policy", "fix_taskmgr")
    else:
        add("taskmgr_policy", "ok", True, "Task Manager policy OK", "")

    # Regedit
    if _policy_disabled("DisableRegistryTools"):
        add("regedit_policy", "high", False, "Registry Editor disabled by policy", "fix_regedit")
    else:
        add("regedit_policy", "ok", True, "Registry Editor policy OK", "")

    # CMD
    if _policy_disabled("DisableCMD"):
        add("cmd_policy", "high", False, "Command Prompt disabled by policy", "fix_cmd")
    else:
        add("cmd_policy", "ok", True, "CMD policy OK", "")

    # Explorer shell
    shell = _reg_sz(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        "Shell",
    )
    if shell and "explorer.exe" not in shell.lower():
        add("winlogon_shell", "critical", False, f"Winlogon Shell={shell}", "fix_shell")
    else:
        add("winlogon_shell", "ok", True, f"Shell={shell or 'explorer.exe'}", "")

    userinit = _reg_sz(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        "Userinit",
    )
    if userinit and "userinit.exe" not in userinit.lower():
        add("winlogon_userinit", "critical", False, f"Userinit={userinit}", "fix_shell")
    else:
        add("winlogon_userinit", "ok", True, "Userinit OK", "")

    # Explorer process
    if not _process_running("explorer.exe"):
        add("explorer_running", "critical", False, "explorer.exe not running", "restart_explorer")
    else:
        add("explorer_running", "ok", True, "explorer.exe running", "")

    # WebView2
    wv = webview2_status()
    if not wv.get("present"):
        add("webview2", "high", False, "WebView2 Runtime missing", "webview2")
    else:
        add("webview2", "ok", True, str(wv.get("detail") or "present"), "")

    # Critical services
    down = []
    optional = {"AudioSrv", "Themes", "Spooler", "wuauserv", "BITS"}
    for svc in _CRITICAL_SERVICES:
        try:
            r = _run_hidden(["sc.exe", "query", svc], timeout=10)
            text = ((r.get("stdout") or "") + (r.get("stderr") or "")).upper()
            if "RUNNING" not in text:
                down.append(f"{svc}:optional" if svc in optional else svc)
        except Exception:
            down.append(svc)
    hard_down = [x for x in down if not str(x).endswith(":optional")]
    if hard_down:
        add(
            "critical_services",
            "high",
            False,
            "Stopped: " + ", ".join(hard_down[:8]),
            "restart_critical_services",
        )
    else:
        add("critical_services", "ok", True, "Core services running", "")

    # Firewall profiles
    try:
        r = _run_hidden(["netsh", "advfirewall", "show", "allprofiles"], timeout=20)
        text = (r.get("stdout") or "").lower()
        if "state                                 off" in text or "state                                 kapalı" in text:
            add("firewall_profiles", "medium", False, "At least one firewall profile is OFF", "firewall_reset")
        else:
            add("firewall_profiles", "ok", True, "Firewall profiles appear on", "")
    except Exception:
        add("firewall_profiles", "medium", False, "Could not query firewall", "")

    # Policy drift via system recovery
    try:
        from client_system_recovery import diff_against, load_snapshot

        changes = diff_against(baseline=load_snapshot())
        if changes:
            add(
                "policy_drift",
                "high",
                False,
                f"{len(changes)} attack-surface drift item(s)",
                "policy_restore",
            )
        else:
            add("policy_drift", "ok", True, "No policy drift vs snapshot", "")
    except Exception as exc:
        add("policy_drift", "low", True, f"Drift check skipped: {exc}", "")

    bad = [f for f in findings if not f.get("ok")]
    return {
        "ok": True,
        "findings": findings,
        "issues": len(bad),
        "critical": sum(1 for f in bad if f.get("severity") == "critical"),
        "high": sum(1 for f in bad if f.get("severity") == "high"),
    }


def _clear_policy_values(names: List[str]) -> Dict[str, Any]:
    cleared = []
    paths = (
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Policies\System"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"),
    )
    for name in names:
        for hive, path in paths:
            if _delete_reg_value(hive, path, name):
                cleared.append(f"{path}:{name}")
    return {"ok": True, "cleared": cleared, "detail": f"cleared={len(cleared)}"}


def fix_taskmgr() -> Dict[str, Any]:
    r = _clear_policy_values(["DisableTaskMgr"])
    # Also try system recovery path
    try:
        pr = repair_policy_surface()
        r["policy_restore"] = pr
    except Exception:
        pass
    return r


def fix_regedit() -> Dict[str, Any]:
    return _clear_policy_values(["DisableRegistryTools"])


def fix_cmd() -> Dict[str, Any]:
    return _clear_policy_values(["DisableCMD"])


def fix_shell() -> Dict[str, Any]:
    ok1 = _set_reg_sz(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        "Shell",
        "explorer.exe",
    )
    # Keep existing Userinit if present and valid; otherwise restore default
    ui = _reg_sz(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        "Userinit",
    )
    ok2 = True
    if not ui or "userinit.exe" not in ui.lower():
        system32 = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "userinit.exe"
        ok2 = _set_reg_sz(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            "Userinit",
            f"{system32},",
        )
    restart = restart_explorer()
    return {"ok": bool(ok1 and ok2), "shell_set": ok1, "userinit_set": ok2, "explorer": restart}


def restart_explorer() -> Dict[str, Any]:
    """Kill explorer in the interactive user session and relaunch via CreateProcessAsUser.

    Session-0 / no interactive session → explorer_wrong_session (never start there).
    """
    try:
        from client_helpers import (
            create_process_in_session,
            kill_image_in_session,
            process_running_in_session,
            resolve_interactive_session_id,
        )
    except Exception as exc:
        return {"ok": False, "error": "explorer_wrong_session", "detail": str(exc), "session_id": 0}

    sid = int(resolve_interactive_session_id() or 0)
    if sid <= 0:
        return {
            "ok": False,
            "error": "explorer_wrong_session",
            "detail": "no_interactive_session",
            "session_id": 0,
        }

    kill = kill_image_in_session("explorer.exe", sid)
    time.sleep(0.8)
    root = os.environ.get("SystemRoot", r"C:\Windows")
    cmd = f'"{root}\\explorer.exe"'
    launched = create_process_in_session(
        sid,
        cmd,
        desktop=r"winsta0\default",
        wait_ms=0,
    )
    if not launched.get("ok"):
        return {
            "ok": False,
            "error": str(launched.get("error") or "explorer_wrong_session"),
            "detail": launched.get("detail") or "launch_failed",
            "session_id": sid,
            "killed": kill.get("killed") or [],
        }
    time.sleep(1.2)
    running = process_running_in_session("explorer.exe", sid)
    return {
        "ok": bool(running),
        "detail": "explorer_restarted" if running else "explorer_launch_no_process",
        "session_id": sid,
        "pid": launched.get("pid"),
        "desktop": r"winsta0\default",
        "killed": kill.get("killed") or [],
        "error": None if running else "explorer_wrong_session",
    }


def restart_taskmgr() -> Dict[str, Any]:
    """Unlock Task Manager policy and launch taskmgr.exe in the user session."""
    fix_taskmgr()
    try:
        from client_helpers import (
            create_process_in_session,
            process_running_in_session,
            resolve_interactive_session_id,
        )
    except Exception as exc:
        return {"ok": False, "error": "explorer_wrong_session", "detail": str(exc), "session_id": 0}

    sid = int(resolve_interactive_session_id() or 0)
    if sid <= 0:
        return {
            "ok": False,
            "error": "explorer_wrong_session",
            "detail": "no_interactive_session",
            "session_id": 0,
        }
    root = os.environ.get("SystemRoot", r"C:\Windows")
    cmd = f'"{root}\\System32\\taskmgr.exe"'
    launched = create_process_in_session(
        sid,
        cmd,
        desktop=r"winsta0\\default",
        wait_ms=0,
    )
    if not launched.get("ok"):
        return {
            "ok": False,
            "error": str(launched.get("error") or "explorer_wrong_session"),
            "detail": launched.get("detail") or "launch_failed",
            "session_id": sid,
        }
    time.sleep(0.6)
    running = process_running_in_session("taskmgr.exe", sid)
    return {
        "ok": bool(running or launched.get("pid")),
        "detail": "taskmgr_started",
        "session_id": sid,
        "pid": launched.get("pid"),
        "desktop": r"winsta0\default",
        "error": None if (running or launched.get("pid")) else "explorer_wrong_session",
    }


def restart_critical_services() -> Dict[str, Any]:
    results = {}
    for svc in _CRITICAL_SERVICES:
        _run_hidden(["sc.exe", "config", svc, "start=", "auto"], timeout=15)
        r = _run_hidden(["sc.exe", "start", svc], timeout=20)
        results[svc] = r.get("exit_code")
    return {"ok": True, "detail": "services_start_attempted", "results": results}


def rebuild_icon_cache() -> Dict[str, Any]:
    # Stop explorer in interactive session, delete iconcache*, restart via CreateProcessAsUser
    try:
        from client_helpers import kill_image_in_session, resolve_interactive_session_id
    except Exception:
        kill_image_in_session = None  # type: ignore[assignment]
        resolve_interactive_session_id = None  # type: ignore[assignment]

    local = os.environ.get("LOCALAPPDATA", "")
    sid = 0
    killed: Dict[str, Any] = {"killed": [], "count": 0}
    if resolve_interactive_session_id and kill_image_in_session:
        sid = int(resolve_interactive_session_id() or 0)
        if sid > 0:
            killed = kill_image_in_session("explorer.exe", sid)
        else:
            killed = {"killed": [], "count": 0, "error": "no_interactive_session"}
    else:
        _run_hidden(["taskkill", "/F", "/IM", "explorer.exe"], timeout=20)
    deleted = []
    if local:
        base = Path(local) / "Microsoft" / "Windows" / "Explorer"
        for pattern in ("iconcache*", "thumbcache*"):
            for p in Path(local).glob(pattern):
                try:
                    p.unlink()
                    deleted.append(str(p.name))
                except OSError:
                    pass
            if base.is_dir():
                for p in base.glob(pattern):
                    try:
                        p.unlink()
                        deleted.append(str(p.name))
                    except OSError:
                        pass
    restart = restart_explorer()
    return {
        "ok": bool(restart.get("ok")),
        "deleted": deleted[:20],
        "kill": killed,
        "explorer": restart,
        "session_id": restart.get("session_id") or sid,
    }


def clear_temp() -> Dict[str, Any]:
    roots = [
        Path(os.environ.get("TEMP", r"C:\Windows\Temp")),
        Path(os.environ.get("TMP", r"C:\Windows\Temp")),
        Path(os.environ.get("SystemRoot", r"C:\Windows")) / "Temp",
    ]
    removed = 0
    for root in roots:
        if not root.is_dir():
            continue
        for p in root.iterdir():
            try:
                if p.is_file():
                    p.unlink()
                    removed += 1
                elif p.is_dir():
                    import shutil

                    shutil.rmtree(p, ignore_errors=True)
                    removed += 1
            except OSError:
                continue
            if removed >= 5000:
                break
    return {"ok": True, "detail": f"temp_cleared~{removed}"}


def time_sync() -> Dict[str, Any]:
    a = _run_hidden(["w32tm", "/resync", "/force"], timeout=60)
    return {"ok": bool(a.get("ok")), "detail": "time_resync", **a}


def fix_share_network() -> Dict[str, Any]:
    """Everyday LAN/share/VPN folder + discovery fix (guest auth, discovery services, firewall)."""
    steps: Dict[str, Any] = {}
    steps["guest_auth"] = _set_reg_dword(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters",
        "AllowInsecureGuestAuth",
        1,
    )
    # Also unlock network printer RPC privacy (0x0000011b) — often needed with share+print
    steps["print_rpc_privacy"] = _set_reg_dword(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Control\Print",
        "RpcAuthnLevelPrivacyEnabled",
        0,
    )
    svc_results = {}
    for svc in (
        "fdPHost",
        "FDResPub",
        "SSDPSRV",
        "upnphost",
        "LanmanServer",
        "LanmanWorkstation",
        "dnscache",
    ):
        svc_results[svc] = _svc_auto_start(svc)
    steps["services"] = svc_results

    fw_results = []
    for group in (
        "File and Printer Sharing",
        "Dosya ve Yazıcı Paylaşımı",
        "Network Discovery",
        "Ağ Bulma",
    ):
        fw_results.append(
            {
                "group": group,
                **_run_hidden(
                    [
                        "netsh",
                        "advfirewall",
                        "firewall",
                        "set",
                        "rule",
                        f"group={group}",
                        "new",
                        "enable=Yes",
                    ],
                    timeout=30,
                ),
            }
        )
    steps["firewall_groups"] = fw_results
    dns = _run_hidden(["ipconfig", "/flushdns"], timeout=20)
    steps["dns_flush"] = bool(dns.get("ok"))
    ok = bool(steps["guest_auth"]) or any(v.get("start_ok") or v.get("config_ok") for v in svc_results.values())
    return {"ok": ok, "detail": "share_network_fixed", "steps": steps}


def fix_printer() -> Dict[str, Any]:
    """Fix PrintNightmare/0x0000011b, restart Spooler, clear stuck print queue."""
    steps: Dict[str, Any] = {}
    steps["print_rpc_privacy"] = _set_reg_dword(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Control\Print",
        "RpcAuthnLevelPrivacyEnabled",
        0,
    )
    _run_hidden(["sc.exe", "stop", "Spooler"], timeout=30)
    time.sleep(0.6)
    cleared = 0
    spool = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "spool" / "PRINTERS"
    if spool.is_dir():
        for p in spool.iterdir():
            try:
                if p.is_file():
                    p.unlink()
                    cleared += 1
            except OSError:
                continue
    steps["queue_cleared"] = cleared
    steps["spooler"] = _svc_auto_start("Spooler")
    # Print Spooler helpers
    for svc in ("PrintNotify",):
        steps[f"svc_{svc}"] = _svc_auto_start(svc)
    for group in ("File and Printer Sharing", "Dosya ve Yazıcı Paylaşımı"):
        _run_hidden(
            [
                "netsh",
                "advfirewall",
                "firewall",
                "set",
                "rule",
                f"group={group}",
                "new",
                "enable=Yes",
            ],
            timeout=30,
        )
    return {
        "ok": bool(steps.get("print_rpc_privacy")) or bool((steps.get("spooler") or {}).get("start_ok")),
        "detail": "printer_fixed",
        "steps": steps,
    }


def fix_audio() -> Dict[str, Any]:
    """Restart Windows Audio stack — common everyday glitch."""
    results = {}
    for svc in ("Audiosrv", "AudioEndpointBuilder", "RpcSs"):
        if svc == "RpcSs":
            # RpcSs usually already running; start only
            results[svc] = _run_hidden(["sc.exe", "start", svc], timeout=15)
        else:
            _run_hidden(["sc.exe", "stop", svc], timeout=15)
            time.sleep(0.3)
            results[svc] = _svc_auto_start(svc)
    return {"ok": True, "detail": "audio_restarted", "results": results}


def auto_fix_findings() -> Dict[str, Any]:
    diag = diagnose()
    steps = []
    seen = set()
    for finding in diag.get("findings") or []:
        if finding.get("ok"):
            continue
        fix = str(finding.get("fix") or "")
        if not fix or fix in seen or fix in _DESTRUCTIVE:
            continue
        seen.add(fix)
        steps.append({"step": fix, "result": run_repair(fix)})
    # Always refresh explorer after policy fixes
    if any(s["step"].startswith("fix_") for s in steps):
        steps.append({"step": "restart_explorer", "result": restart_explorer()})
    return {
        "ok": True,
        "detail": "auto_fix_done",
        "diagnosed_issues": diag.get("issues"),
        "steps": steps,
    }


def webview2_status() -> Dict[str, Any]:
    guid = "{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"
    keys = (
        (winreg.HKEY_LOCAL_MACHINE, rf"SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{guid}"),
        (winreg.HKEY_LOCAL_MACHINE, rf"SOFTWARE\Microsoft\EdgeUpdate\Clients\{guid}"),
        (winreg.HKEY_CURRENT_USER, rf"SOFTWARE\Microsoft\EdgeUpdate\Clients\{guid}"),
    )
    for hive, path in keys:
        try:
            with winreg.OpenKey(hive, path) as key:
                ver, _ = winreg.QueryValueEx(key, "pv")
                if ver and str(ver) not in ("", "0.0.0.0"):
                    return {"ok": True, "present": True, "detail": f"pv={ver}"}
        except OSError:
            continue
    for base in (
        os.environ.get("ProgramFiles", r"C:\Program Files"),
        os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
    ):
        exe = Path(base) / "Microsoft" / "EdgeWebView" / "Application" / "msedgewebview2.exe"
        if exe.is_file():
            return {"ok": True, "present": True, "detail": "fs"}
    return {"ok": True, "present": False, "detail": "missing"}


def open_tool(tool_id: str) -> Dict[str, Any]:
    tid = str(tool_id or "").strip().lower()
    meta = _OPEN_TOOLS.get(tid)
    if not meta:
        return {"ok": False, "error": "unknown_tool"}
    target = os.path.expandvars(meta["target"])
    # Prefer System32 for bare filenames so PATH/SysWOW64 surprises are avoided.
    if "\\" not in target and "/" not in target and not Path(target).is_file():
        sys32 = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / target
        if sys32.is_file():
            target = str(sys32)
    try:
        # ShellExecute via startfile / os.startfile handles .msc and .cpl
        if tid in ("powershell", "cmd"):
            subprocess.Popen(  # noqa: S603
                [target],
                cwd=os.environ.get("SystemRoot", r"C:\Windows"),
                creationflags=getattr(subprocess, "CREATE_NEW_CONSOLE", 0),
            )
        else:
            os.startfile(target)  # noqa: S606
        return {"ok": True, "tool": tid, "target": target}
    except Exception as exc:
        # Fallback: cmd start
        try:
            subprocess.Popen(  # noqa: S603
                ["cmd.exe", "/c", "start", "", target],
                shell=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            return {"ok": True, "tool": tid, "target": target, "via": "cmd_start"}
        except Exception as exc2:
            return {"ok": False, "error": str(exc2 or exc), "tool": tid}


def _run_hidden(args: List[str], timeout: Optional[int] = 120) -> Dict[str, Any]:
    try:
        completed = subprocess.run(  # noqa: S603
            args,
            capture_output=True,
            timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )

        def _dec(raw: Optional[bytes]) -> str:
            if not raw:
                return ""
            for enc in ("utf-8", "cp1254", "cp857", "latin-1"):
                try:
                    return raw.decode(enc)
                except UnicodeDecodeError:
                    continue
            return raw.decode("utf-8", errors="replace")

        return {
            "ok": completed.returncode == 0,
            "exit_code": completed.returncode,
            "stdout": _dec(completed.stdout)[-2000:],
            "stderr": _dec(completed.stderr)[-1000:],
        }
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "timeout"}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def _find_webview2_payload() -> Optional[Path]:
    names = (
        "MicrosoftEdgeWebView2RuntimeInstallerX64.exe",
        "MicrosoftEdgeWebview2Setup.exe",
    )
    roots = [
        Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Asteria" / "Asteria Client",
        Path(__file__).resolve().parent,
        Path(__file__).resolve().parent / "vendor",
    ]
    try:
        roots.insert(0, Path(os.path.dirname(os.path.abspath(__file__))).parent)
    except Exception:
        pass
    for root in roots:
        for name in names:
            p = root / name
            try:
                if p.is_file() and p.stat().st_size > 100_000:
                    return p
            except OSError:
                continue
    return None


def repair_webview2() -> Dict[str, Any]:
    st = webview2_status()
    if st.get("present"):
        return {"ok": True, "detail": "already_present", **st}

    # Revive EdgeUpdate services
    for svc in ("edgeupdate", "edgeupdatem", "MicrosoftEdgeElevationService"):
        _run_hidden(["sc.exe", "config", svc, "start=", "demand"], timeout=15)
        _run_hidden(["sc.exe", "start", svc], timeout=15)

    payload = _find_webview2_payload()
    script = Path(__file__).resolve().parent / "scripts" / "repair-webview2.ps1"
    # scripts/ sits next to package root when frozen under _internal or repo root
    for cand in (
        Path(__file__).resolve().parent / "scripts" / "repair-webview2.ps1",
        Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
        / "Asteria"
        / "Asteria Client"
        / "scripts"
        / "repair-webview2.ps1",
    ):
        if cand.is_file():
            script = cand
            break

    if script.is_file():
        args = [
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(script),
        ]
        if payload:
            args += ["-PayloadPath", str(payload)]
        result = _run_hidden(args, timeout=300)
        st2 = webview2_status()
        return {
            "ok": bool(st2.get("present")),
            "detail": st2.get("detail"),
            "script_exit": result.get("exit_code"),
            "script_error": result.get("error"),
        }

    if payload:
        result = _run_hidden([str(payload), "/silent", "/install"], timeout=300)
        for _ in range(10):
            time.sleep(2)
            st2 = webview2_status()
            if st2.get("present"):
                return {"ok": True, "detail": st2.get("detail"), "installer": result}
        return {"ok": False, "detail": "not_detected", "installer": result}

    return {
        "ok": False,
        "error": "webview2_payload_missing",
        "hint": "https://developer.microsoft.com/microsoft-edge/webview2/",
    }


def repair_policy_surface() -> Dict[str, Any]:
    """Restore Task Manager / registry policy drift via client_system_recovery."""
    try:
        from client_system_recovery import diff_against, plan_restore, apply_plan, load_snapshot

        baseline = load_snapshot()
        changes = diff_against(baseline=baseline)
        if not changes:
            return {"ok": True, "detail": "no_policy_drift", "changes": 0}
        plan = plan_restore(changes)
        applied = apply_plan(plan)
        return {
            "ok": True,
            "detail": "policy_surface_restored",
            "changes": len(changes),
            "applied": applied,
        }
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def run_repair(action: str, *, confirm: bool = False) -> Dict[str, Any]:
    act = str(action or "").strip().lower()
    if act not in _REPAIR_ACTIONS:
        return {"ok": False, "error": "unknown_repair"}
    if act == "status":
        return {
            "ok": True,
            "admin": is_admin(),
            "webview2": webview2_status(),
            "computer": os.environ.get("COMPUTERNAME", ""),
            "diagnose_summary": {
                "issues": diagnose().get("issues"),
                "critical": diagnose().get("critical"),
            },
        }
    if act == "diagnose":
        return diagnose()
    if act == "policy_restore":
        return repair_policy_surface()
    if act == "fix_taskmgr":
        return fix_taskmgr()
    if act == "fix_regedit":
        return fix_regedit()
    if act == "fix_cmd":
        return fix_cmd()
    if act == "fix_shell":
        return fix_shell()
    if act == "restart_explorer":
        return restart_explorer()
    if act == "restart_taskmgr":
        return restart_taskmgr()
    if act == "restart_critical_services":
        return restart_critical_services()
    if act == "icon_cache":
        return rebuild_icon_cache()
    if act == "clear_temp":
        return clear_temp()
    if act == "time_sync":
        return time_sync()
    if act == "auto_fix_findings":
        return auto_fix_findings()
    if act in _DESTRUCTIVE and not confirm:
        return {"ok": False, "error": "confirm_required", "action": act}
    if not is_admin() and act not in _SOFT_NO_ADMIN:
        return {"ok": False, "error": "admin_required", "action": act}

    if act == "share_network_fix":
        return fix_share_network()
    if act == "printer_fix":
        return fix_printer()
    if act == "audio_fix":
        return fix_audio()

    if act == "dns_flush":
        r = _run_hidden(["ipconfig", "/flushdns"], timeout=30)
        return {"ok": bool(r.get("ok")), "detail": "dns_flushed", **r}

    if act == "winsock_reset":
        a = _run_hidden(["netsh", "winsock", "reset"], timeout=60)
        b = _run_hidden(["netsh", "int", "ip", "reset"], timeout=60)
        return {
            "ok": bool(a.get("ok") or b.get("ok")),
            "detail": "winsock_reset_reboot_recommended",
            "winsock": a,
            "ip": b,
        }

    if act == "firewall_reset":
        r = _run_hidden(["netsh", "advfirewall", "reset"], timeout=60)
        return {"ok": bool(r.get("ok")), "detail": "firewall_defaults_restored", **r}

    if act == "wu_reset":
        for svc in ("bits", "wuauserv", "cryptsvc", "msiserver"):
            _run_hidden(["sc.exe", "stop", svc], timeout=30)
        root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
        stamp = time.strftime("%Y%m%d%H%M%S")
        for name in ("SoftwareDistribution", r"System32\catroot2"):
            d = root / name
            if d.is_dir():
                bak = d.with_name(d.name + f".bak_{stamp}")
                try:
                    d.rename(bak)
                except OSError:
                    pass
        for svc in ("bits", "wuauserv", "cryptsvc", "msiserver"):
            _run_hidden(["sc.exe", "start", svc], timeout=30)
        return {"ok": True, "detail": "wu_components_reset"}

    if act == "sfc_scan":
        try:
            subprocess.Popen(  # noqa: S603
                [str(Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "sfc.exe"), "/scannow"],
                creationflags=getattr(subprocess, "CREATE_NEW_CONSOLE", 0),
            )
            return {"ok": True, "detail": "sfc_started"}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    if act == "dism_health":
        try:
            dism = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "DISM.exe"
            subprocess.Popen(  # noqa: S603
                [str(dism), "/Online", "/Cleanup-Image", "/RestoreHealth"],
                creationflags=getattr(subprocess, "CREATE_NEW_CONSOLE", 0),
            )
            return {"ok": True, "detail": "dism_started"}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    if act == "webview2":
        return repair_webview2()

    if act == "full_safe":
        steps = [
            {"step": "dns_flush", "result": run_repair("dns_flush")},
            {"step": "auto_fix_findings", "result": auto_fix_findings()},
            {"step": "webview2", "result": run_repair("webview2")},
            {"step": "restart_critical_services", "result": restart_critical_services()},
            {"step": "dism_health", "result": run_repair("dism_health")},
            {"step": "sfc_scan", "result": run_repair("sfc_scan")},
        ]
        ok = all(bool(s["result"].get("ok")) for s in steps)
        return {"ok": ok, "detail": "full_safe_started", "steps": steps}

    return {"ok": False, "error": "unhandled"}


def tools_catalog() -> Dict[str, Any]:
    """Full catalog for GUI + remote (includes nested diagnose)."""
    return remote_tools_surface(include_open_tools=True)


def remote_tools_surface(*, include_open_tools: bool = True) -> Dict[str, Any]:
    """Flat payload dashboard / Control WS catalog+diagnose expect (contract 1.4.49)."""
    diag = diagnose()
    repairs = [
        {"id": "share_network_fix", "destructive": False, "group": "daily"},
        {"id": "printer_fix", "destructive": False, "group": "daily"},
        {"id": "audio_fix", "destructive": False, "group": "daily"},
        {"id": "dns_flush", "destructive": False, "group": "daily"},
        {"id": "time_sync", "destructive": False, "group": "daily"},
        {"id": "auto_fix_findings", "destructive": False, "group": "critical"},
        {"id": "fix_taskmgr", "destructive": False, "group": "critical"},
        {"id": "restart_taskmgr", "destructive": False, "group": "critical"},
        {"id": "restart_explorer", "destructive": False, "group": "critical"},
        {"id": "fix_shell", "destructive": False, "group": "critical"},
        {"id": "fix_regedit", "destructive": False, "group": "critical"},
        {"id": "fix_cmd", "destructive": False, "group": "critical"},
        {"id": "policy_restore", "destructive": False, "group": "critical"},
        {"id": "restart_critical_services", "destructive": False, "group": "services"},
        {"id": "webview2", "destructive": False, "group": "runtime"},
        {"id": "icon_cache", "destructive": False, "group": "shell"},
        {"id": "clear_temp", "destructive": False, "group": "shell"},
        {"id": "sfc_scan", "destructive": False, "group": "deep"},
        {"id": "dism_health", "destructive": False, "group": "deep"},
        {"id": "full_safe", "destructive": False, "group": "deep"},
        {"id": "winsock_reset", "destructive": True, "group": "danger"},
        {"id": "firewall_reset", "destructive": True, "group": "danger"},
        {"id": "wu_reset", "destructive": True, "group": "danger"},
    ]
    out: Dict[str, Any] = {
        "ok": True,
        "admin": is_admin(),
        "issues": int(diag.get("issues") or 0),
        "critical": int(diag.get("critical") or 0),
        "high": int(diag.get("high") or 0),
        "findings": list(diag.get("findings") or []),
        "repairs": repairs,
        "webview2": webview2_status(),
        "computer": os.environ.get("COMPUTERNAME", ""),
        # Nested copies for GUI twin / older consumers
        "status": {
            "ok": True,
            "admin": is_admin(),
            "webview2": webview2_status(),
            "computer": os.environ.get("COMPUTERNAME", ""),
        },
        "diagnose": diag,
    }
    if include_open_tools:
        out["open_tools"] = list_open_tools()
    return out


def dry_run_plan(action: str) -> List[Dict[str, Any]]:
    """Bounded plan preview — no mutation (contract 1.4.49)."""
    act = str(action or "").strip().lower()
    plans: Dict[str, List[Dict[str, Any]]] = {
        "dns_flush": [{"step": "ipconfig", "args": ["/flushdns"]}],
        "time_sync": [{"step": "w32tm", "args": ["/resync", "/force"]}],
        "winsock_reset": [
            {"step": "netsh", "args": ["winsock", "reset"]},
            {"step": "netsh", "args": ["int", "ip", "reset"]},
        ],
        "firewall_reset": [{"step": "netsh", "args": ["advfirewall", "reset"]}],
        "wu_reset": [
            {"step": "sc", "args": ["stop", "bits|wuauserv|cryptsvc|msiserver"]},
            {"step": "rename", "args": ["SoftwareDistribution", "catroot2"]},
            {"step": "sc", "args": ["start", "bits|wuauserv|cryptsvc|msiserver"]},
        ],
        "sfc_scan": [{"step": "sfc", "args": ["/scannow"]}],
        "dism_health": [
            {"step": "DISM", "args": ["/Online", "/Cleanup-Image", "/RestoreHealth"]}
        ],
        "share_network_fix": [
            {"step": "reg", "args": ["AllowInsecureGuestAuth=1"]},
            {"step": "reg", "args": ["RpcAuthnLevelPrivacyEnabled=0"]},
            {"step": "service_start", "args": ["fdPHost", "FDResPub", "SSDPSRV", "upnphost"]},
            {"step": "firewall_group", "args": ["File and Printer Sharing", "Network Discovery"]},
        ],
        "printer_fix": [
            {"step": "reg", "args": ["RpcAuthnLevelPrivacyEnabled=0"]},
            {"step": "spooler_restart", "args": ["clear_queue"]},
        ],
        "audio_fix": [{"step": "service_restart", "args": ["Audiosrv", "AudioEndpointBuilder"]}],
        "restart_explorer": [
            {"step": "resolve_session", "args": ["WTSGetActiveConsoleSessionId|>0"]},
            {"step": "kill_in_session", "args": ["explorer.exe"]},
            {"step": "CreateProcessAsUser", "args": ["explorer.exe", r"winsta0\default"]},
        ],
        "restart_taskmgr": [
            {"step": "resolve_session", "args": ["WTSGetActiveConsoleSessionId|>0"]},
            {"step": "CreateProcessAsUser", "args": ["taskmgr.exe", r"winsta0\default"]},
        ],
        "full_safe": [
            {"step": "auto_fix_findings"},
            {"step": "webview2"},
            {"step": "restart_critical_services"},
            {"step": "dism_health"},
            {"step": "sfc_scan"},
        ],
    }
    if act in plans:
        return plans[act]
    return [{"step": "run_repair", "action": act, "note": "no_side_effects_preview"}]
