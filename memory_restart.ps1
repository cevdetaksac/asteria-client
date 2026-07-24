# ===============================================================================
# Honeypot Memory Restart Script
# Task Scheduler every 8h: kill client, restart in correct mode, log lifecycle.
# ===============================================================================

param(
    [string]$InstallPath = ""
)

$ErrorActionPreference = "Continue"

# Scheduled task runs as SYSTEM; refuse interactive standard-user launches.
try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    $isAdmin = $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )
    $isSystem = ($id.User.Value -eq "S-1-5-18")
    if (-not ($isAdmin -or $isSystem)) {
        Write-Host "[MEM-RESTART] Refusing - SYSTEM/Administrator required"
        exit 5
    }
} catch {
    exit 5
}
$ProgramDataDir = Join-Path $env:ProgramData "YesNext\CloudHoneypotClient"
$LogDate = Get-Date -Format "yyyy-MM-dd"
$LifecycleLog = Join-Path $ProgramDataDir "lifecycle-$LogDate.log"
$LifecycleQueue = Join-Path $ProgramDataDir "lifecycle_queue.jsonl"
$LegacyLog = Join-Path $env:TEMP "honeypot_memory_restart-$LogDate.log"

function Ensure-Dir([string]$Path) {
    if (-not (Test-Path $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Write-Lifecycle {
    param(
        [string]$EventType,
        [string]$Reason,
        [string]$Severity = "info",
        [hashtable]$Details = @{}
    )
    Ensure-Dir $ProgramDataDir
    try {
        $cutoff = (Get-Date).Date.AddDays(-6)
        Get-ChildItem -Path $ProgramDataDir -Filter "lifecycle-????-??-??.log" -File -ErrorAction SilentlyContinue |
            Where-Object {
                try {
                    $stamp = $_.BaseName.Substring("lifecycle-".Length)
                    [datetime]::ParseExact($stamp, "yyyy-MM-dd", [Globalization.CultureInfo]::InvariantCulture) -lt $cutoff
                } catch { $false }
            } |
            Remove-Item -Force -ErrorAction SilentlyContinue
        Get-ChildItem -Path $env:TEMP -Filter "honeypot_memory_restart-????-??-??.log" -File -ErrorAction SilentlyContinue |
            Where-Object {
                try {
                    $stamp = $_.BaseName.Substring("honeypot_memory_restart-".Length)
                    [datetime]::ParseExact($stamp, "yyyy-MM-dd", [Globalization.CultureInfo]::InvariantCulture) -lt $cutoff
                } catch { $false }
            } |
            Remove-Item -Force -ErrorAction SilentlyContinue
    } catch {}
    $ts = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    $hostName = $env:COMPUTERNAME
    $detailJson = "{}"
    try { $detailJson = ($Details | ConvertTo-Json -Compress -Depth 5) } catch {}
    $line = "$ts [$($Severity.ToUpper())] $EventType`: $Reason | $detailJson"
    try { Add-Content -Path $LifecycleLog -Value $line -Encoding UTF8 } catch {}
    try { Add-Content -Path $LegacyLog -Value $line -Encoding UTF8 } catch {}
    $evt = @{
        ts = $ts
        event_type = $EventType
        reason = $Reason
        severity = $Severity
        hostname = $hostName
        version = ""
        pid = $PID
        details = $Details
    }
    try {
        ($evt | ConvertTo-Json -Compress -Depth 6) | Add-Content -Path $LifecycleQueue -Encoding UTF8
    } catch {}
}

function Resolve-InstallPath {
    param([string]$Hint)
    $candidates = @()
    if ($Hint) { $candidates += $Hint }
    $candidates += @(
        "C:\Program Files\Asteria\Asteria Client",
        "C:\Program Files (x86)\Asteria\Asteria Client",
        "C:\Program Files\YesNext\Cloud Honeypot Client",
        "C:\Program Files (x86)\YesNext\Cloud Honeypot Client",
        "C:\Program Files\YesNext\CloudHoneypotClient",
        (Split-Path -Parent $PSScriptRoot),
        $PSScriptRoot,
        (Get-Location).Path
    )
    foreach ($c in $candidates) {
        if (-not $c) { continue }
        foreach ($name in @("asteria-client.exe", "honeypot-client.exe")) {
            $exe = Join-Path $c $name
            if (Test-Path $exe) { return $c }
        }
    }
    return $null
}

function Get-LastModeFromRegistry {
    try {
        $regPath = "HKCU:\Software\YesNext\CloudHoneypot"
        if (Test-Path $regPath) {
            $lastMode = Get-ItemProperty -Path $regPath -Name "LastMode" -ErrorAction SilentlyContinue
            if ($lastMode -and $lastMode.LastMode) {
                return [string]$lastMode.LastMode
            }
        }
    } catch {}
    return $null
}

function Get-SmartMode {
    try {
        $sessions = quser 2>$null
        if ($sessions) {
            $explorer = Get-Process -Name "explorer" -ErrorAction SilentlyContinue
            if ($explorer) { return "--mode=gui" }
            return "--mode=tray"
        }
    } catch {}
    return "--mode=daemon"
}

Write-Lifecycle -EventType "memory_restart_begin" -Reason "scheduled_8h_cleanup" -Severity "info"

$resolved = Resolve-InstallPath -Hint $InstallPath
if (-not $resolved) {
    Write-Lifecycle -EventType "memory_restart_failed" -Reason "exe_not_found" -Severity "error" -Details @{
        install_path_hint = $InstallPath
        script = $PSCommandPath
    }
    exit 1
}

$exePath = Join-Path $resolved "asteria-client.exe"
Write-Lifecycle -EventType "memory_restart_path" -Reason "resolved" -Severity "info" -Details @{
    install_path = $resolved
    exe = $exePath
}

# Skip while update lock present
$updateLocks = @(
    (Join-Path $env:ProgramData "YesNext\CloudHoneypotClient\update_in_progress.lock"),
    (Join-Path $env:APPDATA "YesNext\CloudHoneypotClient\update_in_progress.lock")
)
foreach ($ul in $updateLocks) {
    if (Test-Path $ul) {
        $age = ((Get-Date) - (Get-Item $ul).LastWriteTime).TotalSeconds
        if ($age -lt 7200) {
            Write-Lifecycle -EventType "memory_restart_skipped" -Reason "update_in_progress" -Severity "warning" -Details @{
                lock = $ul
                age_sec = [int]$age
            }
            exit 0
        }
    }
}

$targetMode = Get-LastModeFromRegistry
if (-not $targetMode) { $targetMode = Get-SmartMode }
# SYSTEM session 0: never force interactive GUI
try {
    $sessionName = $env:SESSIONNAME
    if (-not $sessionName -or $sessionName -eq "Services") {
        if ($targetMode -match "gui|tray|show-gui") {
            $targetMode = "--mode=daemon"
        }
    }
} catch {}

Write-Lifecycle -EventType "memory_restart_kill" -Reason "stopping_session0_only" -Severity "info" -Details @{
    target_mode = $targetMode
}

# Multi-user safe: NEVER kill interactive session GUIs (SessionId > 0).
# Only recycle Session 0 (SYSTEM/daemon) for memory cleanup.
try {
    $all = @(Get-Process -Name "honeypot-client" -ErrorAction SilentlyContinue)
    $interactive = @($all | Where-Object { $_.SessionId -gt 0 })
    $session0 = @($all | Where-Object { $_.SessionId -eq 0 })

    if ($interactive.Count -gt 0 -and $session0.Count -eq 0) {
        Write-Lifecycle -EventType "memory_restart_skipped" -Reason "interactive_gui_only" -Severity "info" -Details @{
            interactive_pids = @($interactive | ForEach-Object { $_.Id })
        }
        exit 0
    }

    if ($session0.Count -gt 0) {
        $session0 | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 3
        Write-Lifecycle -EventType "memory_restart_kill" -Reason "session0_killed" -Severity "info" -Details @{
            killed = @($session0 | ForEach-Object { $_.Id })
            preserved_interactive = @($interactive | ForEach-Object { $_.Id })
        }
    } else {
        Write-Lifecycle -EventType "memory_restart_kill" -Reason "no_session0_process" -Severity "info"
    }
} catch {
    Write-Lifecycle -EventType "memory_restart_kill_error" -Reason $_.Exception.Message -Severity "warning"
}

# Always restart/ensure daemon in Session 0; do not replace interactive GUI mode
$arguments = "--mode=daemon --silent"
try {
    # If interactive GUI already running, only ensure daemon if missing
    $stillInteractive = @(Get-Process -Name "honeypot-client" -ErrorAction SilentlyContinue | Where-Object { $_.SessionId -gt 0 })
    $still0 = @(Get-Process -Name "honeypot-client" -ErrorAction SilentlyContinue | Where-Object { $_.SessionId -eq 0 })
    if ($stillInteractive.Count -gt 0 -and $still0.Count -gt 0) {
        Write-Lifecycle -EventType "memory_restart_ok" -Reason "interactive_preserved_daemon_alive" -Severity "info" -Details @{
            interactive_pids = @($stillInteractive | ForEach-Object { $_.Id })
            daemon_pids = @($still0 | ForEach-Object { $_.Id })
        }
        exit 0
    }
    if ($stillInteractive.Count -gt 0 -and $still0.Count -eq 0) {
        # Start daemon alongside existing GUI (watchdog/Background will also help)
        Start-Process -FilePath $exePath -ArgumentList $arguments -WindowStyle Hidden
        Start-Sleep -Seconds 3
        Write-Lifecycle -EventType "memory_restart_ok" -Reason "daemon_started_beside_gui" -Severity "info"
        exit 0
    }

    Start-Process -FilePath $exePath -ArgumentList $arguments -WindowStyle Hidden
    Start-Sleep -Seconds 4
    $alive = Get-Process -Name "honeypot-client" -ErrorAction SilentlyContinue
    if ($alive) {
        Write-Lifecycle -EventType "memory_restart_ok" -Reason "process_restarted" -Severity "info" -Details @{
            target_mode = "--mode=daemon"
            new_pids = @($alive | ForEach-Object { $_.Id })
        }
        exit 0
    }

    # Fallback: trigger Background scheduled task
    Write-Lifecycle -EventType "memory_restart_fallback" -Reason "process_not_alive_after_start" -Severity "warning" -Details @{
        target_mode = "--mode=daemon"
    }
    schtasks /run /tn "CloudHoneypot-Background" 2>$null | Out-Null
    Start-Sleep -Seconds 5
    $alive2 = Get-Process -Name "honeypot-client" -ErrorAction SilentlyContinue
    if ($alive2) {
        Write-Lifecycle -EventType "memory_restart_ok" -Reason "restarted_via_background_task" -Severity "info" -Details @{
            new_pids = @($alive2 | ForEach-Object { $_.Id })
        }
        exit 0
    }

    Write-Lifecycle -EventType "memory_restart_failed" -Reason "restart_did_not_stick" -Severity "error" -Details @{
        exe = $exePath
        args = $arguments
    }
    exit 1
} catch {
    Write-Lifecycle -EventType "memory_restart_failed" -Reason $_.Exception.Message -Severity "error" -Details @{
        exe = $exePath
        args = $arguments
    }
    exit 1
}
