#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Remote-desktop host prep for Windows Server / headless consoles (C-RD-HOST-1).

Billur-class hosts often already compose LogonUI for PrintWindow. Derin/Ninety
Server VMs frequently need Themes/DWM alive, no forced screen-off, RDP allowed,
and a writable diag dump dir. Apply idempotently at install and daemon boot.
"""

from __future__ import annotations

import os
import subprocess
import time
from typing import Any, Dict, List


_FLAG_NAME = "rd_host_prep.flag"
_FLAG_TTL_SEC = 6 * 3600  # re-apply at most every 6h per boot cycle


def _programdata_asteria() -> str:
    pd = os.environ.get("ProgramData") or r"C:\ProgramData"
    return os.path.join(pd, "Asteria")


def _flag_path() -> str:
    return os.path.join(_programdata_asteria(), _FLAG_NAME)


def _should_skip(force: bool = False) -> bool:
    if force:
        return False
    path = _flag_path()
    try:
        age = time.time() - os.path.getmtime(path)
        if age < _FLAG_TTL_SEC:
            return True
    except OSError:
        pass
    return False


def _mark_done() -> None:
    root = _programdata_asteria()
    try:
        os.makedirs(root, exist_ok=True)
        with open(_flag_path(), "w", encoding="utf-8") as fh:
            fh.write(f"ok {int(time.time())}\n")
    except OSError:
        pass


def _log(msg: str) -> None:
    try:
        from client_helpers import log
        log(f"[RD-HOST-PREP] {msg}")
    except Exception:
        pass


def _winreg_set_dword(root, path: str, name: str, value: int) -> bool:
    try:
        import winreg
        key = winreg.CreateKeyEx(root, path, 0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY)
        try:
            winreg.SetValueEx(key, name, 0, winreg.REG_DWORD, int(value))
        finally:
            winreg.CloseKey(key)
        return True
    except Exception as exc:
        _log(f"reg {path}\\{name} failed: {exc}")
        return False


def _ensure_service(name: str) -> str:
    """Start service if present; return status tag."""
    try:
        q = subprocess.run(
            ["sc.exe", "query", name],
            capture_output=True,
            text=True,
            timeout=8,
            creationflags=0x08000000,
        )
        out = (q.stdout or "") + (q.stderr or "")
        if q.returncode != 0 and "1060" in out:
            return "missing"
        subprocess.run(
            ["sc.exe", "config", name, "start=", "auto"],
            capture_output=True,
            text=True,
            timeout=8,
            creationflags=0x08000000,
        )
        subprocess.run(
            ["sc.exe", "start", name],
            capture_output=True,
            text=True,
            timeout=15,
            creationflags=0x08000000,
        )
        return "ok"
    except Exception as exc:
        return f"err:{exc}"


def _run(cmd: list, timeout: int = 20) -> int:
    try:
        r = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            creationflags=0x08000000,
        )
        return int(r.returncode or 0)
    except Exception:
        return -1


def is_windows_server() -> bool:
    """True for Server / Domain Controller ProductType."""
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\ProductOptions",
        )
        try:
            val, _ = winreg.QueryValueEx(key, "ProductType")
        finally:
            winreg.CloseKey(key)
        # WinNT=workstation, ServerNT=server, LanmanNT=DC
        return str(val or "").lower() in ("servernt", "lanmannt")
    except Exception:
        return False


def apply_rd_host_prep(*, force: bool = False) -> Dict[str, Any]:
    """Idempotent host prep for remote-desktop capture on Server/headless hosts."""
    steps: List[str] = []
    if os.name != "nt":
        return {"ok": False, "skipped": True, "reason": "not_windows", "steps": steps}
    if _should_skip(force=force):
        return {"ok": True, "skipped": True, "reason": "fresh_flag", "steps": steps}

    server = is_windows_server()
    steps.append(f"product_server={server}")

    # Diag dump ring used by C-RD-DIAG-6
    dump = os.path.join(_programdata_asteria(), "rd_capture_diag")
    try:
        os.makedirs(dump, exist_ok=True)
        steps.append("dump_dir=ok")
    except OSError as exc:
        steps.append(f"dump_dir=err:{exc}")

    import winreg

    # Allow Terminal Services connections (does not open firewall by itself).
    _winreg_set_dword(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Control\Terminal Server",
        "fDenyTSConnections",
        0,
    )
    steps.append("fDenyTSConnections=0")

    # Keep sessions alive when console locked / RDP disconnects briefly.
    _winreg_set_dword(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services",
        "fResetBroken",
        0,
    )
    _winreg_set_dword(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services",
        "MaxDisconnectionTime",
        0,
    )
    steps.append("ts_policy=keepalive")

    # Do not force desktop composition off (legacy policy blocks LogonUI chrome).
    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Policies\Microsoft\Windows\DWM",
            0,
            winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY,
        )
        try:
            winreg.DeleteValue(key, "DisallowComposition")
            steps.append("dwm_disallow_cleared")
        finally:
            winreg.CloseKey(key)
    except FileNotFoundError:
        steps.append("dwm_disallow=absent")
    except OSError:
        steps.append("dwm_disallow=absent")

    # Prefer composition / effects available for LogonUI chrome.
    _winreg_set_dword(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows\DWM",
        "ForceEffectMode",
        2,
    )
    steps.append("dwm_force_effect=2")

    # Services that back LogonUI / DWM composition on Server Desktop Experience.
    for svc in (
        "Themes",
        "UxSms",  # legacy; missing on newer builds is OK
        "DispBrokerDesktopSvc",
        "TermService",
    ):
        tag = _ensure_service(svc)
        steps.append(f"svc:{svc}={tag}")

    # Never blank the console display — headless VMs often go to zero-refresh.
    _run(["powercfg", "/change", "monitor-timeout-ac", "0"])
    _run(["powercfg", "/change", "monitor-timeout-dc", "0"])
    _run(["powercfg", "/change", "standby-timeout-ac", "0"])
    _run(["powercfg", "/change", "standby-timeout-dc", "0"])
    steps.append("powercfg_monitor=0")

    # Best-effort: enable RDP firewall group (custom ports still need ops).
    _run([
        "netsh", "advfirewall", "firewall", "set", "rule",
        "group=remote desktop", "new", "enable=yes",
    ])
    steps.append("firewall_rdp_group=tried")

    # SystemParametersInfo SPI_SETFONTSMOOTHING = 0x004B, SPIF_UPDATEINIFILE|SPIF_SENDCHANGE
    try:
        import ctypes
        SPI_SETFONTSMOOTHING = 0x004B
        SPIF = 0x01 | 0x02
        ctypes.windll.user32.SystemParametersInfoW(SPI_SETFONTSMOOTHING, 1, None, SPIF)
        steps.append("font_smoothing=on")
    except Exception as exc:
        steps.append(f"font_smoothing=err:{exc}")

    if server:
        steps.append("server_sku=prep_extra")
        # Interactive services detection off is modern default; leave alone.
        # Ensure Winlogon AutoRestartShell so explorer recovery works post-logon.
        _winreg_set_dword(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            "AutoRestartShell",
            1,
        )
        steps.append("AutoRestartShell=1")

    _mark_done()
    _log("; ".join(steps[-12:]))
    return {
        "ok": True,
        "skipped": False,
        "server": server,
        "steps": steps,
    }


def ensure_rd_host_prep_on_boot() -> Dict[str, Any]:
    """Daemon/GUI startup hook — never raise."""
    try:
        return apply_rd_host_prep(force=False)
    except Exception as exc:
        _log(f"boot prep failed: {exc}")
        return {"ok": False, "error": str(exc)}
