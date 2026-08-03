#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Update immortality helpers — PS 5.1 safe staging, parse gate, emergency bootstrap.

Windows PowerShell 5.1 (Win10/11/Server 2012+) mis-parses UTF-8-without-BOM scripts
that contain typographic Unicode (em-dash U+2014). That yields launcher-only logs and
a dead install. Everything here forces ASCII (or UTF-8 BOM) and validates parse before
claiming the helper is live.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import time
from typing import Optional, Tuple

# Minimal ASCII-only orchestrator used when the full helper fails to stage/parse.
# Must stay 7-bit ASCII. Marker line MUST match launch success gate.
EMERGENCY_UPDATE_BOOTSTRAP_PS1 = r"""# Asteria Client - EMERGENCY update bootstrap (ASCII only)
# Used when full update-and-install.ps1 cannot be staged/parsed.
param(
    [Parameter(Mandatory = $true)][string]$InstallerPath,
    [int]$ExpectExitPid = 0,
    [switch]$Silent,
    [switch]$ShowGuiAfter,
    [string]$InstallDir = "",
    [int]$GraceWaitSec = 12,
    [int]$KillRounds = 4,
    [int]$InstallerTimeoutSec = 480
)
$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"
function Write-UpLog([string]$Message) {
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$ts] $Message"
    try {
        $dir = Join-Path $env:ProgramData "Asteria"
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        Add-Content -Path (Join-Path $dir "update-install.log") -Value $line -Encoding ASCII
    } catch {}
}
Write-UpLog "=== update-and-install start ==="
Write-UpLog "emergency_bootstrap=1"
Write-UpLog ("Installer=" + $InstallerPath + " Silent=" + [bool]$Silent + " ExpectExitPid=" + $ExpectExitPid)
if (-not (Test-Path -LiteralPath $InstallerPath)) {
    Write-UpLog "ERROR: installer missing"
    exit 2
}
# Disable respawn + Guardian (otherwise motor resurrects mid-kill)
try { & sc.exe stop AsteriaGuardian 2>$null | Out-Null } catch {}
Start-Sleep -Milliseconds 400
try { & sc.exe delete AsteriaGuardian 2>$null | Out-Null } catch {}
foreach ($n in @("AsteriaClientGuard","Asteria-Watchdog","Asteria-Background","Asteria-Tray","Asteria-MemoryRestart","Asteria-Updater","Asteria-SilentUpdater")) {
    try { schtasks /end /tn $n 2>$null | Out-Null } catch {}
    try { schtasks /change /tn $n /disable 2>$null | Out-Null } catch {}
}
# Soft QUIT
try {
    $c = New-Object Net.Sockets.TcpClient
    $c.Connect("127.0.0.1", 58632)
    $b = [Text.Encoding]::ASCII.GetBytes("QUIT`n")
    $c.GetStream().Write($b, 0, $b.Length)
    $c.Close()
} catch {}
# Wait caller
if ($ExpectExitPid -gt 0) {
    $deadline = (Get-Date).AddSeconds([Math]::Max(3, $GraceWaitSec))
    while ((Get-Date) -lt $deadline) {
        try {
            $p = Get-Process -Id $ExpectExitPid -ErrorAction SilentlyContinue
            if (-not $p) { break }
        } catch { break }
        Start-Sleep -Milliseconds 400
    }
}
# Force kill motor + GUI (names matter: fleet is asteria-* now)
$round = 0
do {
    $round++
    Write-UpLog ("Kill round " + $round)
    try { & taskkill.exe /F /T /IM asteria-client.exe 2>$null | Out-Null } catch {}
    try { & taskkill.exe /F /T /IM asteria-gui.exe 2>$null | Out-Null } catch {}
    try { & taskkill.exe /F /T /IM honeypot-client.exe 2>$null | Out-Null } catch {}
    try { Get-Process -Name "asteria-client","asteria-gui","honeypot-client" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue } catch {}
    $left = @(Get-Process -Name "asteria-client","asteria-gui","honeypot-client" -ErrorAction SilentlyContinue)
    if ($left.Count -eq 0) { break }
    Start-Sleep -Milliseconds 300
} while ($round -lt $KillRounds)
Start-Sleep -Milliseconds 800
$args = @()
if ($Silent) { $args = @("/S", "/NCRC") }
Write-UpLog "Starting installer (emergency)..."
try {
    $p = Start-Process -FilePath $InstallerPath -ArgumentList $args -PassThru
    $deadline = (Get-Date).AddSeconds([Math]::Max(60, [int]$InstallerTimeoutSec))
    while ((Get-Date) -lt $deadline) {
        if ($p.HasExited) { break }
        Start-Sleep -Seconds 3
        try { $p.Refresh() } catch {}
    }
    if (-not $p.HasExited) {
        Write-UpLog "ERROR: installer timeout - killing"
        try { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } catch {}
        exit 7
    }
    Write-UpLog ("Installer exit code: " + $p.ExitCode)
    if ($p.ExitCode -ne 0) { exit [int]$p.ExitCode }
} catch {
    Write-UpLog ("ERROR: installer start failed: " + $_.Exception.Message)
    exit 4
}
# Re-enable + start motor
foreach ($n in @("Asteria-Background","Asteria-Watchdog","Asteria-Updater","Asteria-SilentUpdater","Asteria-Tray")) {
    try { schtasks /change /tn $n /enable 2>$null | Out-Null } catch {}
}
try { schtasks /run /tn "Asteria-Background" 2>$null | Out-Null } catch {}
$exe = Join-Path ${env:ProgramFiles} "Asteria\Asteria Client\asteria-client.exe"
if (Test-Path -LiteralPath $exe) {
    try {
        Start-Process -FilePath $exe -ArgumentList "--mode=daemon","--create-tasks" -WindowStyle Hidden
    } catch {}
}
Write-UpLog "=== update-and-install done ==="
exit 0
"""


_TYPOGRAPHIC_REPLACEMENTS = (
    ("\u2014", "-"),
    ("\u2013", "-"),
    ("\u2018", "'"),
    ("\u2019", "'"),
    ("\u201c", '"'),
    ("\u201d", '"'),
    ("\u2026", "..."),
    ("\u00a0", " "),
    ("\uFEFF", ""),  # BOM if read as text
)


def normalize_ps1_to_ascii(raw: str) -> str:
    """Force PowerShell-safe 7-bit ASCII (PS 5.1 UTF-8-no-BOM safe)."""
    if not isinstance(raw, str):
        raw = str(raw or "")
    for bad, good in _TYPOGRAPHIC_REPLACEMENTS:
        raw = raw.replace(bad, good)
    # Drop any remaining non-ASCII (including leftover multi-byte garbage)
    return raw.encode("ascii", errors="replace").decode("ascii")


def assert_file_is_ascii(path: str) -> bool:
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError:
        return False
    if not data:
        return False
    # Allow UTF-8 BOM only if payload after BOM is ASCII
    if data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]
    return all(b < 128 for b in data)


def write_ascii_ps1(path: str, content: str) -> bool:
    """Write CRLF ASCII script (PS 5.1 / Server 2012 friendliest).

    Handles ACL-bricked leftovers: a prior SYSTEM-only ``update-and-install.ps1``
    can block overwrite even when the parent folder is writable. Try remove /
    alternate inode before giving up.
    """
    try:
        text = normalize_ps1_to_ascii(content)
        # Prefer CRLF for Windows PowerShell on older Server builds
        text = text.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "\r\n")
        payload = text.encode("ascii", errors="replace")
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)

        def _write(target: str) -> bool:
            with open(target, "wb") as fh:
                fh.write(payload)
            return os.path.isfile(target) and assert_file_is_ascii(target)

        try:
            return _write(path)
        except OSError:
            # Drop ACL-locked / read-denied prior helper, then rewrite.
            try:
                os.chmod(path, 0o666)
            except OSError:
                pass
            try:
                os.remove(path)
            except OSError:
                pass
            try:
                return _write(path)
            except OSError:
                alt = f"{path}.n{os.getpid()}"
                try:
                    if not _write(alt):
                        return False
                    try:
                        os.replace(alt, path)
                        return os.path.isfile(path) and assert_file_is_ascii(path)
                    except OSError:
                        # Keep alternate path only if caller can discover it —
                        # stage_update_install_helper prefers TEMP fallback instead.
                        try:
                            os.remove(alt)
                        except OSError:
                            pass
                        return False
                except OSError:
                    return False
    except OSError:
        return False


def validate_powershell_parse(path: str, timeout_sec: float = 25.0) -> Tuple[bool, str]:
    """Return (ok, detail). Uses System.Management.Automation.Language.Parser when available."""
    if not path or not os.path.isfile(path):
        return False, "missing"
    if not assert_file_is_ascii(path):
        return False, "non_ascii"
    # Escape for single-quoted PowerShell literal
    path_q = path.replace("'", "''")
    ps = (
        "$e = $null; $null = $null; "
        f"[void][System.Management.Automation.Language.Parser]::ParseFile('{path_q}', [ref]$null, [ref]$e); "
        "if ($e -and $e.Count -gt 0) { "
        "  $e | ForEach-Object { $_.Message } | Out-String | Write-Output; exit 1 "
        "} else { Write-Output 'PARSE_OK'; exit 0 }"
    )
    try:
        r = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                ps,
            ],
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        out = ((r.stdout or "") + (r.stderr or "")).strip()
        if r.returncode == 0 and "PARSE_OK" in out:
            return True, "ok"
        return False, (out[:500] or f"exit_{r.returncode}")
    except FileNotFoundError:
        # No powershell — cannot validate; ASCII gate already passed
        return True, "no_powershell_skip"
    except Exception as e:
        return False, str(e)[:300]


def preflight_update_ready(installer_path: str, *, min_free_mb: int = 80) -> Tuple[bool, str]:
    """Disk + installer sanity before launching helper."""
    if not installer_path or not os.path.isfile(installer_path):
        return False, "installer_missing"
    try:
        size = os.path.getsize(installer_path)
    except OSError:
        return False, "installer_stat_failed"
    if size < 1_000_000:
        return False, f"installer_too_small:{size}"

    need = max(min_free_mb * 1024 * 1024, int(size * 1.5) + 40 * 1024 * 1024)
    for root in (
        os.environ.get("ProgramData", r"C:\ProgramData"),
        os.environ.get("ProgramFiles", r"C:\Program Files"),
        os.path.splitdrive(installer_path)[0] + os.sep,
    ):
        try:
            usage = shutil.disk_usage(root)
            if usage.free < need:
                return False, f"disk_low:{root}:{usage.free}"
        except Exception:
            continue
    return True, "ok"


def detect_launcher_only_storm(log_path: str, *, window_sec: float = 600.0, min_hits: int = 4) -> bool:
    """True if many recent 'launcher start' lines without helper start (broken PS1)."""
    try:
        if not os.path.isfile(log_path):
            return False
        with open(log_path, "r", encoding="utf-8", errors="ignore") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return False
    now = time.time()
    launcher_hits = 0
    helper_hits = 0
    # Parse trailing timestamps loosely: [YYYY-MM-DD HH:MM:SS]
    ts_re = re.compile(r"^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]")
    for line in lines[-80:]:
        m = ts_re.match(line)
        age_ok = True
        if m:
            try:
                # local time approx
                from datetime import datetime

                ts = datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S").timestamp()
                age_ok = (now - ts) <= window_sec
            except Exception:
                age_ok = True
        if not age_ok:
            continue
        if "launcher start" in line:
            launcher_hits += 1
        if "update-and-install start" in line:
            helper_hits += 1
    return launcher_hits >= min_hits and helper_hits == 0


def write_emergency_bootstrap(dst: str) -> Optional[str]:
    if write_ascii_ps1(dst, EMERGENCY_UPDATE_BOOTSTRAP_PS1):
        ok, detail = validate_powershell_parse(dst)
        if ok:
            return dst
        # Still return path if ASCII written — parse tool may be unavailable
        if detail == "no_powershell_skip":
            return dst
    return None


def resolve_helper_source_candidates() -> list:
    candidates = [
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "scripts", "update-and-install.ps1"),
    ]
    if getattr(sys, "frozen", False):
        candidates.insert(
            0,
            os.path.join(os.path.dirname(sys.executable), "scripts", "update-and-install.ps1"),
        )
        try:
            mei = getattr(sys, "_MEIPASS", "") or ""
            if mei:
                candidates.insert(0, os.path.join(mei, "scripts", "update-and-install.ps1"))
        except Exception:
            pass
    return candidates
