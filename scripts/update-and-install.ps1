# Asteria Client - safe update/install orchestrator
# Runs elevated (UAC). Survives killing asteria-client.exe because it is a separate powershell.exe.
#
# Flow:
#   1) Disable/end scheduled tasks (no respawn)
#   2) Wait for caller PID to exit (graceful QUIT)
#   3) Force-kill any remaining asteria-client.exe (SeDebug)
#   4) Verify processes are gone (abort install if not - avoid corrupting onefile exe)
#   5) Run NSIS installer and WAIT
#   6) Re-create tasks / launch GUI
#
# Usage (elevated):
#   update-and-install.ps1 -InstallerPath "C:\Users\..\Downloads\asteria-client-installer-vX.exe" `
#       -ExpectExitPid 1234 -Silent -ShowGuiAfter
# NOTE: Keep this file ASCII-only (Windows PowerShell encoding).

param(
    [Parameter(Mandatory = $true)]
    [string]$InstallerPath,

    [int]$ExpectExitPid = 0,

    [switch]$Silent,

    [switch]$ShowGuiAfter,

    [string]$InstallDir = "",

    [int]$GraceWaitSec = 20,

    [int]$KillRounds = 4,

    # NSIS /S must never hang the orchestrator forever (Defender / file lock / old Exec-daemon).
    [int]$InstallerTimeoutSec = 480
)

$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"

try {
    $principal = New-Object Security.Principal.WindowsPrincipal(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    )
    if (-not $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )) {
        Write-Host "[UPDATE] Refusing - Administrator elevation required"
        exit 5
    }
} catch {
    Write-Host "[UPDATE] Refusing - elevation check failed"
    exit 5
}

function Write-UpLog([string]$Message) {
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$ts] $Message"
    Write-Host $line
    try {
        $dir = Join-Path $env:ProgramData "Asteria"
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        Add-Content -Path (Join-Path $dir "update-install.log") -Value $line -Encoding UTF8
    } catch {}
}

function Initialize-UpLogRetention {
    try {
        $dir = Join-Path $env:ProgramData "Asteria"
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        $active = Join-Path $dir "update-install.log"
        if (Test-Path $active) {
            $todayStamp = Get-Date -Format "yyyy-MM-dd"
            $currentLines = New-Object System.Collections.Generic.List[string]
            foreach ($line in @(Get-Content -LiteralPath $active -ErrorAction SilentlyContinue)) {
                if ($line -match '^\[(\d{4}-\d{2}-\d{2})\]' -and $Matches[1] -ne $todayStamp) {
                    $archive = Join-Path $dir "update-install-$($Matches[1]).log"
                    Add-Content -LiteralPath $archive -Value $line -Encoding UTF8
                } else {
                    [void]$currentLines.Add([string]$line)
                }
            }
            Set-Content -LiteralPath $active -Value $currentLines -Encoding UTF8 -Force
        }
        $cutoff = (Get-Date).Date.AddDays(-6)
        Get-ChildItem -Path $dir -Filter "update-install-????-??-??.log" -File -ErrorAction SilentlyContinue |
            Where-Object {
                try {
                    $stamp = $_.BaseName.Substring("update-install-".Length)
                    [datetime]::ParseExact(
                        $stamp, "yyyy-MM-dd",
                        [Globalization.CultureInfo]::InvariantCulture
                    ) -lt $cutoff
                } catch { $false }
            } |
            Remove-Item -Force -ErrorAction SilentlyContinue
    } catch {}
}

function Set-UpdateLock([string]$Reason) {
    try {
        $dir = Join-Path $env:ProgramData "Asteria"
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        $path = Join-Path $dir "update_in_progress.lock"
        Set-Content -Path $path -Value "$Reason`n$PID`n$((Get-Date).ToFileTimeUtc())" -Encoding ASCII -Force
    } catch {}
}

function Clear-UpdateLock {
    try {
        $path = Join-Path $env:ProgramData "Asteria\update_in_progress.lock"
        if (Test-Path $path) { Remove-Item $path -Force }
    } catch {}
}

function Clear-UpdateArtifacts {
    # After a successful install, delete the used installer and prune orphan
    # (asteria|cloud)-client-installer*.exe / run-update-*.ps1 under
    # ProgramData\...\update and matching Downloads copies. Keep this script.
    param([string]$UsedInstaller = "")
    $script:UaRemoved = 0
    try {
        if ($UsedInstaller -and (Test-Path -LiteralPath $UsedInstaller)) {
            # Only delete the used EXE when it lives under known staging/TEMP/Downloads.
            # Never wipe a developer build path (e.g. repo asteria-client-installer.exe).
            $norm = [string]$UsedInstaller
            $stagingRoot = Join-Path $env:ProgramData "Asteria\update"
            $safe = $false
            if ($norm.StartsWith($stagingRoot, [StringComparison]::OrdinalIgnoreCase)) { $safe = $true }
            elseif ($env:TEMP -and $norm.StartsWith($env:TEMP, [StringComparison]::OrdinalIgnoreCase)) { $safe = $true }
            elseif ($norm -match '(?i)\\Downloads\\(asteria|cloud)-client-installer') { $safe = $true }
            if ($safe) {
                Remove-Item -LiteralPath $UsedInstaller -Force -ErrorAction SilentlyContinue
                if (-not (Test-Path -LiteralPath $UsedInstaller)) {
                    $script:UaRemoved++
                    Write-UpLog "Removed used installer: $UsedInstaller"
                } else {
                    Write-UpLog "WARN: could not delete used installer (locked?): $UsedInstaller"
                }
            } else {
                Write-UpLog "Skip used-installer delete (outside staging): $UsedInstaller"
            }
        }
    } catch {
        Write-UpLog "WARN: used-installer delete: $($_.Exception.Message)"
    }

    $staging = Join-Path $env:ProgramData "Asteria\update"
    if (Test-Path -LiteralPath $staging) {
        Get-ChildItem -LiteralPath $staging -File -ErrorAction SilentlyContinue | ForEach-Object {
            $n = $_.Name
            $kill = $false
            if ($n -match '(?i)^(asteria|cloud)-client-installer.*\.exe$') { $kill = $true }
            elseif ($n -match '(?i)^(run-update-|run-nsis-|force-restart-).+\.ps1$') { $kill = $true }
            if (-not $kill) { return }
            try {
                Remove-Item -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue
                if (-not (Test-Path -LiteralPath $_.FullName)) {
                    $script:UaRemoved++
                    Write-UpLog "Pruned update artifact: $n"
                }
            } catch {}
        }
    }

    # User Downloads copies from older interactive downloads
    $dlRoots = New-Object System.Collections.Generic.List[string]
    try {
        if ($env:USERPROFILE -and ($env:USERPROFILE -notmatch '(?i)systemprofile')) {
            $p = Join-Path $env:USERPROFILE "Downloads"
            if (Test-Path -LiteralPath $p) { [void]$dlRoots.Add($p) }
        }
    } catch {}
    try {
        $pub = Join-Path $env:PUBLIC "Downloads"
        if ($pub -and (Test-Path -LiteralPath $pub)) { [void]$dlRoots.Add($pub) }
    } catch {}
    # Common interactive profiles when helper runs as SYSTEM
    try {
        Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -notin @("Public", "Default", "Default User", "All Users") } |
            ForEach-Object {
                $p = Join-Path $_.FullName "Downloads"
                if (Test-Path -LiteralPath $p) { [void]$dlRoots.Add($p) }
            }
    } catch {}
    foreach ($dl in ($dlRoots | Select-Object -Unique)) {
        Get-ChildItem -LiteralPath $dl -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '(?i)^(asteria|cloud)-client-installer.*\.exe$' } |
            ForEach-Object {
                try {
                    Remove-Item -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue
                    if (-not (Test-Path -LiteralPath $_.FullName)) {
                        $script:UaRemoved++
                        Write-UpLog "Pruned Downloads installer: $($_.FullName)"
                    }
                } catch {}
            }
    }

    # TEMP scratch dirs left by interrupted silent/self updates
    try {
        Get-ChildItem -LiteralPath $env:TEMP -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like "honeypot_update_*" -or $_.Name -like "honeypot_self_update_*" } |
            ForEach-Object {
                try {
                    Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction SilentlyContinue
                    $script:UaRemoved++
                    Write-UpLog "Pruned TEMP update dir: $($_.Name)"
                } catch {}
            }
    } catch {}

    Write-UpLog "Clear-UpdateArtifacts done (removed=$script:UaRemoved)"
}

function Write-StopFlags {
    $paths = @(
        (Join-Path $env:TEMP "honeypot_watchdog_token.txt"),
        (Join-Path $env:APPDATA "YesNext\CloudHoneypot\watchdog_token.txt"),
        (Join-Path $env:APPDATA "Asteria\watchdog.token"),
        (Join-Path $env:ProgramData "YesNext\CloudHoneypot\watchdog_stop.flag")
    )
    foreach ($p in $paths) {
        try {
            $d = Split-Path $p -Parent
            if ($d -and -not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
            Set-Content -Path $p -Value "stop" -Encoding ASCII -Force
        } catch {}
    }
}

function Stop-HoneypotTasks {
    $names = @(
        "AsteriaClientGuard",
        "Asteria-Watchdog",
        "Asteria-Background",
        "Asteria-Tray",
        "Asteria-MemoryRestart",
        "Asteria-Updater",
        "Asteria-SilentUpdater",
        # Pre-4.9.41 wire names
        "HoneypotClientGuard",
        "CloudHoneypot-Watchdog",
        "CloudHoneypot-Background",
        "CloudHoneypot-Tray",
        "CloudHoneypot-MemoryRestart",
        "CloudHoneypot-Updater",
        "CloudHoneypot-SilentUpdater"
    )
    foreach ($n in $names) {
        schtasks /end /tn $n 2>$null | Out-Null
        schtasks /change /tn $n /disable 2>$null | Out-Null
    }
}

function Restore-HoneypotTasks {
    # Re-enable core tasks - MUST run after every update (success OR fail).
    # Stop-HoneypotTasks disables these; leaving them disabled = no daemon forever.
    $names = @(
        "Asteria-SilentUpdater",
        "Asteria-Updater",
        "Asteria-Watchdog",
        "Asteria-Background",
        "Asteria-MemoryRestart",
        "Asteria-Tray"
    )
    foreach ($n in $names) {
        schtasks /change /tn $n /enable 2>$null | Out-Null
    }
    Write-UpLog "Scheduled tasks re-enabled (Background + Watchdog + updaters)"
}

function Ensure-DaemonMotor {
    # Guarantee SYSTEM Session-0 motor is up (dashboard poll / heartbeat).
    param([string]$ExePath = "")
    Restore-HoneypotTasks
    $started = $false
    try {
        schtasks /change /tn "Asteria-Background" /enable 2>$null | Out-Null
        schtasks /change /tn "Asteria-Watchdog" /enable 2>$null | Out-Null
        schtasks /run /tn "Asteria-Background" 2>$null | Out-Null
        if ($LASTEXITCODE -eq 0) {
            $started = $true
            Write-UpLog "Ensure-DaemonMotor: Asteria-Background /run ok"
        }
    } catch {
        Write-UpLog "Ensure-DaemonMotor: Background /run error: $($_.Exception.Message)"
    }
    if (-not $started -and $ExePath -and (Test-Path -LiteralPath $ExePath)) {
        try {
            Start-Process -FilePath $ExePath -ArgumentList "--mode=daemon","--silent" -WorkingDirectory (Split-Path $ExePath) -WindowStyle Hidden
            $started = $true
            Write-UpLog "Ensure-DaemonMotor: Start-Process daemon fallback"
        } catch {
            Write-UpLog "Ensure-DaemonMotor: Start-Process failed: $($_.Exception.Message)"
        }
    }
    $ready = $false
    for ($i = 0; $i -lt 40; $i++) {
        Start-Sleep -Milliseconds 500
        try {
            $tcp = New-Object System.Net.Sockets.TcpClient
            $iar = $tcp.BeginConnect("127.0.0.1", 58632, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne(300) -and $tcp.Connected) {
                $ready = $true
                $tcp.Close()
                break
            }
            $tcp.Close()
        } catch {}
        # Re-kick Background halfway if still silent
        if ($i -eq 20 -and -not $ready) {
            schtasks /run /tn "Asteria-Background" 2>$null | Out-Null
            if ($LASTEXITCODE -ne 0) {
                schtasks /run /tn "CloudHoneypot-Background" 2>$null | Out-Null
            }
            Write-UpLog "Ensure-DaemonMotor: re-kick Background (no :58632 yet)"
        }
    }
    Write-UpLog "Ensure-DaemonMotor: ready=$ready (control :58632)"
    return $ready
}

function Write-UpdateUiStatus {
    param(
        [Parameter(Mandatory = $true)][string]$Phase,
        [string]$Detail = "",
        [string]$ErrorText = "",
        [string]$FromVersion = "",
        [string]$ToVersion = ""
    )
    try {
        $dir = Join-Path $env:ProgramData "Asteria"
        if (-not (Test-Path -LiteralPath $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
        $path = Join-Path $dir "update_ui_status.json"
        $prev = $null
        if (Test-Path -LiteralPath $path) {
            try { $prev = Get-Content -LiteralPath $path -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json } catch {}
        }
        if (-not $FromVersion -and $prev -and $prev.from_version) { $FromVersion = [string]$prev.from_version }
        if (-not $ToVersion -and $prev -and $prev.to_version) { $ToVersion = [string]$prev.to_version }
        $now = [double]((Get-Date).ToUniversalTime() - [datetime]'1970-01-01').TotalSeconds
        # Heartbeats must not reset phase_started_at (GUI stale timeout uses it)
        $started = $now
        if ($prev -and $prev.phase -and ([string]$prev.phase).ToLower() -eq $Phase.ToLower() -and $prev.phase_started_at) {
            try { $started = [double]$prev.phase_started_at } catch { $started = $now }
        }
        $obj = [ordered]@{
            phase             = $Phase
            from_version      = $FromVersion
            to_version        = $ToVersion
            detail            = $Detail
            error             = $ErrorText
            updated_at        = $now
            phase_started_at  = $started
        }
        ($obj | ConvertTo-Json -Compress) | Set-Content -LiteralPath $path -Encoding UTF8 -Force
    } catch {}
}

function Fail-Update([int]$Code, [string]$Message) {
    Write-UpLog $Message
    try {
        Write-UpdateUiStatus -Phase "failed" -Detail $Message -ErrorText $Message
    } catch {}
    Clear-UpdateLock
    $exe = Join-Path ${env:ProgramFiles} "Asteria\Asteria Client\asteria-client.exe"
    if (-not (Test-Path -LiteralPath $exe)) {
        $exe = Join-Path ${env:ProgramFiles} "YesNext\Cloud Honeypot Client\honeypot-client.exe"
    }
    if (-not (Test-Path -LiteralPath $exe)) {
        $exe = Join-Path ${env:ProgramFiles} "Asteria\honeypot-client.exe"
    }
    [void](Ensure-DaemonMotor -ExePath $exe)
    exit $Code
}

function Send-QuitCommand {
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $iar = $client.BeginConnect("127.0.0.1", 58632, $null, $null)
        $ok = $iar.AsyncWaitHandle.WaitOne(200)
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
public class HpTokUp {
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
        [void][HpTokUp]::OpenProcessToken([HpTokUp]::GetCurrentProcess(), 0x28, [ref]$tok)
        $tp = New-Object HpTokUp+TP
        $tp.Count = 1
        $tp.Attr = 2
        [void][HpTokUp]::LookupPrivilegeValue($null, "SeDebugPrivilege", [ref]$tp.Luid)
        [void][HpTokUp]::AdjustTokenPrivileges($tok, $false, [ref]$tp, 0, [IntPtr]::Zero, [IntPtr]::Zero)
    } catch {}
}

function Stop-AsteriaGuardian {
    Write-UpLog "Stopping/deleting AsteriaGuardian (prevents mid-kill resurrect)..."
    try { & sc.exe stop AsteriaGuardian 2>$null | Out-Null } catch {}
    Start-Sleep -Milliseconds 500
    try { & sc.exe delete AsteriaGuardian 2>$null | Out-Null } catch {}
}

function Get-HoneypotPids {
    $list = @()
    Get-Process -Name "asteria-client","asteria-gui","honeypot-client" -ErrorAction SilentlyContinue |
        ForEach-Object { $list += $_.Id }
    return $list
}

function Stop-HoneypotProcesses {
    $kdef = @"
using System;
using System.Runtime.InteropServices;
public class HpKillUp {
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool TerminateProcess(IntPtr h, uint code);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool CloseHandle(IntPtr h);
}
"@
    try { Add-Type -TypeDefinition $kdef -ErrorAction Stop | Out-Null } catch {}

    try { & taskkill.exe /F /T /IM asteria-client.exe 2>$null | Out-Null } catch {}
    try { & taskkill.exe /F /T /IM asteria-gui.exe 2>$null | Out-Null } catch {}
    try { & taskkill.exe /F /T /IM honeypot-client.exe 2>$null | Out-Null } catch {}
    $pids = Get-HoneypotPids
    foreach ($procId in $pids) {
        try {
            $h = [HpKillUp]::OpenProcess(0x1F0FFF, $false, [int]$procId)
            if ($h -ne [IntPtr]::Zero) {
                [void][HpKillUp]::TerminateProcess($h, 1)
                [void][HpKillUp]::CloseHandle($h)
            }
        } catch {}
        try { Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue } catch {}
        try { & taskkill.exe /F /T /PID $procId 2>$null | Out-Null } catch {}
    }
}

function Wait-ProcessesGone([int]$TimeoutSec) {
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        $left = @(Get-HoneypotPids)
        if ($left.Count -eq 0) { return $true }
        Start-Sleep -Milliseconds 200
    }
    return (@(Get-HoneypotPids).Count -eq 0)
}

function Wait-CallerExit([int]$PidToWait, [int]$TimeoutSec) {
    if ($PidToWait -le 0) { return }
    Write-UpLog "Waiting for caller PID $PidToWait to exit (max ${TimeoutSec}s)..."
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        if (-not (Get-Process -Id $PidToWait -ErrorAction SilentlyContinue)) {
            Write-UpLog "Caller PID $PidToWait exited."
            return
        }
        Start-Sleep -Milliseconds 200
    }
    Write-UpLog "Caller PID $PidToWait still running after grace - will force-kill."
}

# -- Main --
Initialize-UpLogRetention
Write-UpLog "=== update-and-install start ==="
Write-UpLog "Installer=$InstallerPath Silent=$Silent ShowGui=$ShowGuiAfter ExpectExitPid=$ExpectExitPid Grace=$GraceWaitSec"

if (-not (Test-Path -LiteralPath $InstallerPath)) {
    Fail-Update 2 "ERROR: Installer not found: $InstallerPath"
}

Set-UpdateLock "installing"
try { Write-UpdateUiStatus -Phase "installing" -Detail "helper_install_start" } catch {}
Write-StopFlags
Write-UpLog "Stopping/disabling scheduled tasks..."
Stop-HoneypotTasks

Write-UpLog "Sending QUIT to control port..."
Send-QuitCommand

Wait-CallerExit -PidToWait $ExpectExitPid -TimeoutSec $GraceWaitSec

Write-UpLog "Enabling SeDebugPrivilege + force terminate..."
Enable-SeDebugPrivilege
Stop-AsteriaGuardian
$round = 0
do {
    $round++
    Write-UpLog "Kill round $round..."
    Stop-HoneypotProcesses
    $left = @(Get-HoneypotPids)
    if ($left.Count -eq 0) { break }
    Start-Sleep -Milliseconds 250
} while ($round -lt $KillRounds)

if (-not (Wait-ProcessesGone -TimeoutSec 5)) {
    $still = @(Get-HoneypotPids)
    Fail-Update 3 "ERROR: honeypot-client still running (PIDs=$($still -join ',')). Aborting install to avoid corrupting onefile EXE."
}

Write-UpLog "Processes gone - settling 0.8s before installer..."
Start-Sleep -Milliseconds 800

# Rename locked onedir trees aside before NSIS extract (avoids FileInUse dialogs).
try {
    $prep = Join-Path $PSScriptRoot "prepare-install-dir.ps1"
    $kill = Join-Path $PSScriptRoot "kill-honeypot.ps1"
    $installDir = Join-Path ${env:ProgramFiles} "Asteria\Asteria Client"
    if (Test-Path $prep) {
        Write-UpLog "prepare-install-dir.ps1..."
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $prep -InstallDir $installDir -KillScript $kill
        Write-UpLog "prepare-install-dir exit=$LASTEXITCODE"
    }
} catch {
    Write-UpLog "WARN: prepare-install-dir failed: $($_.Exception.Message)"
}

$argList = @()
if ($Silent) {
    $argList = @("/S", "/NCRC")
}

$timeoutSec = [Math]::Max(60, [int]$InstallerTimeoutSec)
Write-UpLog "Starting installer (timeout=${timeoutSec}s)..."
try {
    # Interactive: show NSIS UI. Silent: /S args above.
    # Do NOT use -Wait alone - a hung NSIS (Defender nsExec / mid-install Exec)
    # blocked self-update forever with log stuck on "Starting installer (wait)...".
    $p = Start-Process -FilePath $InstallerPath -ArgumentList $argList -PassThru
    if (-not $p) {
        Fail-Update 4 "ERROR: Installer failed to start (null process)"
    }
    Write-UpLog "Installer PID=$($p.Id) - waiting up to ${timeoutSec}s..."
    $deadline = (Get-Date).AddSeconds($timeoutSec)
    $finished = $false
    while ((Get-Date) -lt $deadline) {
        if ($p.HasExited) { $finished = $true; break }
        try {
            Write-UpdateUiStatus -Phase "installing" -Detail ("installer_wait_pid=" + $p.Id)
        } catch {}
        Start-Sleep -Seconds 5
        try { $p.Refresh() } catch {}
    }
    if (-not $finished) {
        Write-UpLog "ERROR: Installer hung after ${timeoutSec}s - killing PID $($p.Id) + children"
        try { & taskkill.exe /F /T /PID $p.Id 2>$null | Out-Null } catch {}
        try { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } catch {}
        # Old NSIS may have started daemon mid-install; clear before Fail-Update restart
        Stop-HoneypotProcesses
        Fail-Update 7 "ERROR: installer_timeout after ${timeoutSec}s"
    }
    $code = $p.ExitCode
    Write-UpLog "Installer exit code: $code"
} catch {
    Fail-Update 4 "ERROR: Installer failed to start: $($_.Exception.Message)"
}

# Old installers Exec'd daemon under /S; stop them so --create-tasks / relaunch is clean
$mid = @(Get-HoneypotPids)
if ($mid.Count -gt 0) {
    Write-UpLog "Post-install: stopping NSIS-spawned honeypot (PIDs=$($mid -join ','))..."
    Enable-SeDebugPrivilege
    Stop-HoneypotProcesses
    Start-Sleep -Milliseconds 400
}

if ($InstallDir -eq "") {
    $InstallDir = Join-Path ${env:ProgramFiles} "Asteria\Asteria Client"
}
$exe = Join-Path $InstallDir "asteria-client.exe"
if (-not (Test-Path -LiteralPath $exe)) {
    $exe = Join-Path $InstallDir "honeypot-client.exe"
}
if (-not (Test-Path -LiteralPath $exe)) {
    $alt = Join-Path ${env:ProgramFiles} "YesNext\Cloud Honeypot Client\honeypot-client.exe"
    if (Test-Path -LiteralPath $alt) { $exe = $alt; $InstallDir = Split-Path $alt -Parent }
}
if (-not (Test-Path -LiteralPath $exe)) {
    $alt = Join-Path ${env:ProgramFiles} "Asteria\honeypot-client.exe"
    if (Test-Path -LiteralPath $alt) { $exe = $alt; $InstallDir = Split-Path $alt -Parent }
}

if (-not (Test-Path -LiteralPath $exe)) {
    Fail-Update 5 "ERROR: asteria-client.exe / honeypot-client.exe missing after install at $InstallDir"
}

$size = (Get-Item -LiteralPath $exe).Length
Write-UpLog "Installed exe OK ($size bytes): $exe"
if ($size -lt 1000000) {
    Fail-Update 6 "ERROR: Installed exe suspiciously small - abort launch"
}

# Drop staged installer + orphan launchers/Downloads copies (disk bloat).
# Do this only after a verified successful install so retries can reuse the EXE.
try {
    Clear-UpdateArtifacts -UsedInstaller $InstallerPath
} catch {
    Write-UpLog "WARN: Clear-UpdateArtifacts: $($_.Exception.Message)"
}

Write-UpLog "Creating scheduled tasks..."
try {
    $ct = Start-Process -FilePath $exe -ArgumentList "--create-tasks" -PassThru -WindowStyle Hidden
    if ($ct) {
        if (-not $ct.WaitForExit(120000)) {
            Write-UpLog "WARN: --create-tasks hung - killing"
            try { Stop-Process -Id $ct.Id -Force -ErrorAction SilentlyContinue } catch {}
            Restore-HoneypotTasks
        } elseif ($ct.ExitCode -ne 0) {
            Write-UpLog "WARN: --create-tasks exit=$($ct.ExitCode)"
            Restore-HoneypotTasks
        }
    }
} catch {
    Write-UpLog "WARN: --create-tasks failed: $($_.Exception.Message)"
    Restore-HoneypotTasks
}

# CRITICAL: Stop-HoneypotTasks disabled Background+Watchdog - always restore + start motor
$motorReady = [bool](Ensure-DaemonMotor -ExePath $exe)

# Keep the update lock alive until the new daemon has completed its boot-time
# previous-session check. Clearing it before Ensure-DaemonMotor made a planned
# installer stop look like unexpected_exit / agent_tamper on every update.
Clear-UpdateLock
try { Write-UpdateUiStatus -Phase "done" -Detail "install_complete" } catch {}

if (-not $Silent) {
    # Interactive NSIS path - visible onboarding/GUI
    Write-UpLog "Launching GUI..."
    try {
        $gui = Join-Path $InstallDir "asteria-gui.exe"
        if (Test-Path -LiteralPath $gui) {
            Start-Process -FilePath $gui -WorkingDirectory $InstallDir
        } else {
            Start-Process -FilePath $exe -ArgumentList "--show-gui" -WorkingDirectory $InstallDir
        }
    } catch {
        Write-UpLog "WARN: GUI launch failed: $($_.Exception.Message)"
    }
} else {
    # Silent update: prefer a single tray owner. create-tasks + daemon already
    # call launch_interactive_tray_gui; a second helper Asteria-Tray race often
    # spawned an extra asteria-gui before the first was visible.
    $wantTray = [bool]$ShowGuiAfter
    if (-not $wantTray) {
        try {
            $q = & query session 2>$null | Out-String
            # EN Active / TR Aktif / Disc(onnected) must not match
            if ($q -match '(?i)(console|rdp-tcp).*\s+(Active|Aktif)\b') {
                $wantTray = $true
            }
        } catch {}
    }
    if ($wantTray) {
        $guiAlready = @(Get-Process -Name "asteria-gui" -ErrorAction SilentlyContinue)
        if ($motorReady -or $guiAlready.Count -gt 0) {
            Write-UpLog "Silent: skip helper tray (motorReady=$motorReady guiCount=$($guiAlready.Count)) - daemon/create-tasks owns handoff"
        } else {
            Write-UpLog "Interactive session - motor not ready, starting Tray after silent update..."
            try {
                schtasks /change /tn "Asteria-Tray" /enable 2>$null | Out-Null
                schtasks /run /tn "Asteria-Tray" 2>$null | Out-Null
                if ($LASTEXITCODE -ne 0) {
                    $gui = Join-Path $InstallDir "asteria-gui.exe"
                    if (Test-Path -LiteralPath $gui) {
                        Write-UpLog "WARN: Asteria-Tray /run failed (exit=$LASTEXITCODE) - trying asteria-gui --tray"
                        Start-Process -FilePath $gui -ArgumentList "--tray" -WorkingDirectory $InstallDir
                    } else {
                        Write-UpLog "WARN: Asteria-Tray /run failed (exit=$LASTEXITCODE) - trying --mode=tray"
                        Start-Process -FilePath $exe -ArgumentList "--mode=tray" -WorkingDirectory $InstallDir
                    }
                }
            } catch {
                Write-UpLog "WARN: Tray handoff after silent update: $($_.Exception.Message)"
            }
        }
    }
}

Write-UpLog "=== update-and-install done ==="
exit 0
