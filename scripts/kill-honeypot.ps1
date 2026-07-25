# Kill all Asteria Client processes (installer / updater helper)
# Handles: DACL self-protection, watchdog respawn, HoneypotClientGuard task
# Requires: elevated (admin) for SeDebugPrivilege
#
# Usage:
#   kill-honeypot.ps1           - respects update_in_progress.lock (interactive download)
#   kill-honeypot.ps1 -Force    - kill even during download (installer after download done)
# NOTE: Keep this file ASCII-only. Windows PowerShell may mis-parse UTF-8 em-dashes
# and break installer PRE-KILL (Unexpected token ')' ).

param(
    [switch]$Force
)

$ErrorActionPreference = "SilentlyContinue"

# Refuse non-elevated runs — blocks casual double-click / standard-user abuse.
try {
    $principal = New-Object Security.Principal.WindowsPrincipal(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    )
    if (-not $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )) {
        Write-Host "[KILL] Refusing - Administrator elevation required"
        exit 5
    }
} catch {
    Write-Host "[KILL] Refusing - elevation check failed"
    exit 5
}

function Test-UpdateLockBlocksKill {
    if ($Force) { return $false }
    $candidates = @(
        (Join-Path $env:ProgramData "YesNext\CloudHoneypotClient\update_in_progress.lock"),
        (Join-Path $env:APPDATA "YesNext\CloudHoneypotClient\update_in_progress.lock")
    )
    foreach ($lock in $candidates) {
        if (-not (Test-Path $lock)) { continue }
        try {
            $ageSec = ((Get-Date) - (Get-Item $lock).LastWriteTime).TotalSeconds
            if ($ageSec -gt 7200) { continue }
            $reason = ""
            try { $reason = (Get-Content $lock -TotalCount 1 -ErrorAction SilentlyContinue) } catch {}
            if ($reason -match "download|interactive|silent") {
                Write-Host ("[KILL] Abort - update lock present (reason={0}, age={1}s). Use -Force only after download." -f $reason, [int]$ageSec)
                return $true
            }
            if ($reason -notmatch "install|preparing") {
                Write-Host ("[KILL] Abort - update_in_progress.lock present (age={0}s)" -f [int]$ageSec)
                return $true
            }
        } catch {}
    }
    return $false
}

if (Test-UpdateLockBlocksKill) {
    exit 0
}

function Write-StopFlags {
    $paths = @(
        (Join-Path $env:TEMP "honeypot_watchdog_token.txt"),
        (Join-Path $env:APPDATA "YesNext\CloudHoneypot\watchdog_token.txt"),
        (Join-Path $env:APPDATA "YesNext\CloudHoneypotClient\watchdog.token"),
        (Join-Path $env:ProgramData "YesNext\CloudHoneypot\watchdog_stop.flag")
    )
    foreach ($p in $paths) {
        try {
            $dir = Split-Path $p -Parent
            if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
            Set-Content -Path $p -Value "stop" -Encoding ASCII -Force
        } catch {}
    }
}

function Stop-HoneypotTasksFast {
    # End + disable only the respawn-critical tasks (fast).
    # Full task deletion is handled by installer DeleteAllHoneypotTasks.
    $names = @(
        "HoneypotClientGuard",
        "CloudHoneypot-Watchdog",
        "CloudHoneypot-Background",
        "CloudHoneypot-Tray",
        "CloudHoneypot-MemoryRestart"
    )
    foreach ($n in $names) {
        schtasks /end /tn $n 2>$null | Out-Null
        schtasks /change /tn $n /disable 2>$null | Out-Null
    }
}

function Send-QuitCommandFast {
    # Best-effort graceful exit; keep timeout short for installer speed
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $iar = $client.BeginConnect("127.0.0.1", 58632, $null, $null)
        $ok = $iar.AsyncWaitHandle.WaitOne(150)
        if ($ok -and $client.Connected) {
            $stream = $client.GetStream()
            $bytes = [Text.Encoding]::ASCII.GetBytes("QUIT`n")
            $stream.Write($bytes, 0, $bytes.Length)
            $stream.Flush()
        }
        $client.Close()
    } catch {}
}

function Enable-SeDebugPrivilege {
    $def = @"
using System;
using System.Runtime.InteropServices;
public class HpTok {
  [DllImport("advapi32.dll", ExactSpelling=true, SetLastError=true)]
  public static extern bool OpenProcessToken(IntPtr h, int access, out IntPtr t);
  [DllImport("advapi32.dll", SetLastError=true)]
  public static extern bool LookupPrivilegeValue(string host, string name, out long luid);
  [DllImport("advapi32.dll", ExactSpelling=true, SetLastError=true)]
  public static extern bool AdjustTokenPrivileges(IntPtr t, bool dis, ref TP neu, int len, IntPtr prev, IntPtr rel);
  [StructLayout(LayoutKind.Sequential, Pack=1)]
  public struct TP { public int Count; public long Luid; public int Attr; }
  [DllImport("kernel32.dll", ExactSpelling=true)]
  public static extern IntPtr GetCurrentProcess();
}
"@
    try { Add-Type -TypeDefinition $def -ErrorAction Stop | Out-Null } catch {}
    try {
        $tok = [IntPtr]::Zero
        [void][HpTok]::OpenProcessToken([HpTok]::GetCurrentProcess(), 0x28, [ref]$tok)
        $tp = New-Object HpTok+TP
        $tp.Count = 1
        $tp.Attr = 2
        [void][HpTok]::LookupPrivilegeValue($null, "SeDebugPrivilege", [ref]$tp.Luid)
        [void][HpTok]::AdjustTokenPrivileges($tok, $false, [ref]$tp, 0, [IntPtr]::Zero, [IntPtr]::Zero)
    } catch {}
}

function Ensure-KillTypes {
    $kdef = @"
using System;
using System.Runtime.InteropServices;
public class HpKill {
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool TerminateProcess(IntPtr h, uint code);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool CloseHandle(IntPtr h);
}
"@
    try { Add-Type -TypeDefinition $kdef -ErrorAction Stop | Out-Null } catch {}
}

function Stop-HoneypotProcessesFast {
    # 1) Fastest bulk kill (Asteria motor + GUI + legacy image names)
    try { & taskkill.exe /F /T /IM asteria-client.exe 2>$null | Out-Null } catch {}
    try { & taskkill.exe /F /T /IM asteria-gui.exe 2>$null | Out-Null } catch {}
    try { & taskkill.exe /F /T /IM honeypot-client.exe 2>$null | Out-Null } catch {}
    try {
        Get-CimInstance Win32_Process -Filter "Name='asteria-client.exe'" -ErrorAction SilentlyContinue |
            ForEach-Object {
                try { $_.Terminate() | Out-Null } catch {}
            }
        Get-CimInstance Win32_Process -Filter "Name='asteria-gui.exe'" -ErrorAction SilentlyContinue |
            ForEach-Object {
                try { $_.Terminate() | Out-Null } catch {}
            }
        Get-CimInstance Win32_Process -Filter "Name='honeypot-client.exe'" -ErrorAction SilentlyContinue |
            ForEach-Object {
                try { $_.Terminate() | Out-Null } catch {}
            }
    } catch {}

    # 2) Per-PID TerminateProcess — use TERMINATE|SYNCHRONIZE (0x1F0FFF can fail under DACL)
    $procs = @(Get-Process -Name "asteria-client","asteria-gui","honeypot-client" -ErrorAction SilentlyContinue)
    foreach ($proc in $procs) {
        $procId = [int]$proc.Id
        foreach ($access in @(0x0001, 0x00100001, 0x1F0FFF)) {
            try {
                $h = [HpKill]::OpenProcess([uint32]$access, $false, $procId)
                if ($h -ne [IntPtr]::Zero) {
                    [void][HpKill]::TerminateProcess($h, 1)
                    [void][HpKill]::CloseHandle($h)
                    break
                }
            } catch {}
        }
        try { Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue } catch {}
        try { & taskkill.exe /F /T /PID $procId 2>$null | Out-Null } catch {}
    }
}

# ---- main (fast path) ----
Write-Host "[KILL] stop flags + tasks..."
Write-StopFlags
Stop-HoneypotTasksFast

Write-Host "[KILL] QUIT + SeDebug..."
Send-QuitCommandFast
Enable-SeDebugPrivilege
Ensure-KillTypes

# Brief grace after QUIT so DACL disarm can complete (Force installs too)
$graceMs = 400
if (-not $Force) { $graceMs = 600 }
Start-Sleep -Milliseconds $graceMs

$maxRounds = 5
$round = 0
do {
    $round++
    Write-Host "[KILL] terminate round $round..."
    Stop-HoneypotProcessesFast
    # Also stop any process whose image lives under the install dir (locks _internal\*.pyd).
    try {
        $roots = @(
            (Join-Path ${env:ProgramFiles} "Asteria\Asteria Client"),
            (Join-Path ${env:ProgramFiles} "YesNext\Cloud Honeypot Client"),
            (Join-Path ${env:ProgramFiles} "YesNext\CloudHoneypotClient")
        )
        foreach ($root in $roots) {
            if (-not $root -or -not (Test-Path $root)) { continue }
            $needle = $root.ToLowerInvariant()
            Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | ForEach-Object {
                $ep = [string]($_.ExecutablePath)
                if ($ep -and $ep.ToLowerInvariant().StartsWith($needle)) {
                    try { & taskkill.exe /F /T /PID $_.ProcessId 2>$null | Out-Null } catch {}
                }
            }
        }
    } catch {}
    $left = @(Get-Process -Name "asteria-client","asteria-gui","honeypot-client" -ErrorAction SilentlyContinue)
    if ($left.Count -eq 0) { break }
    Start-Sleep -Milliseconds 120
} while ($round -lt $maxRounds)

$left = @(Get-Process -Name "asteria-client","asteria-gui","honeypot-client" -ErrorAction SilentlyContinue)
if ($left.Count -gt 0) {
    Write-Host "[KILL] WARNING: $($left.Count) process(es) still running"
    exit 1
}

Write-Host "[KILL] All asteria-client / asteria-gui / honeypot-client processes stopped."
exit 0
