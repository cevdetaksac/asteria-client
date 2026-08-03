# Asteria installer / uninstaller prep cleanup
# Collapses dozens of sequential NSIS nsExec schtasks/sc calls into one
# elevated PowerShell pass with parallel independent ops.
#
# Order (safety):
#   1) Stop/disable Guardian services + respawn-critical tasks FIRST
#   2) Process kill (kill-honeypot.ps1 -Force when available)
#   3) Bulk delete remaining Asteria / legacy scheduled tasks
#
# Usage:
#   installer-prep-cleanup.ps1 -Mode Full -KillScript <path\to\kill-honeypot.ps1>
#   installer-prep-cleanup.ps1 -Mode TasksOnly
#   installer-prep-cleanup.ps1 -Mode KillOnly -KillScript ...
#
# NOTE: Keep ASCII-only (Windows PowerShell / NSIS embedding).

param(
    [ValidateSet("Full", "TasksOnly", "KillOnly", "GuardianFirst")]
    [string]$Mode = "Full",
    [string]$KillScript = ""
)

$ErrorActionPreference = "SilentlyContinue"

try {
    $principal = New-Object Security.Principal.WindowsPrincipal(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    )
    if (-not $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )) {
        Write-Host "[PREP] Refusing - Administrator elevation required"
        exit 5
    }
} catch {
    Write-Host "[PREP] Refusing - elevation check failed"
    exit 5
}

$GuardianServices = @(
    "AsteriaGuardian",
    "CloudHoneypotGuardian",
    "CloudHoneypotMonitor"
)

# Respawn-critical: end+disable before any process kill.
$CriticalTasks = @(
    "AsteriaClientGuard",
    "Asteria-Watchdog",
    "Asteria-Background",
    "Asteria-Tray",
    "Asteria-MemoryRestart",
    "HoneypotClientGuard",
    "CloudHoneypot-Watchdog",
    "CloudHoneypot-Background",
    "CloudHoneypot-Tray",
    "CloudHoneypot-MemoryRestart"
)

$AllKnownTasks = @(
    "Asteria-Background",
    "Asteria-Tray",
    "Asteria-Watchdog",
    "Asteria-Updater",
    "Asteria-SilentUpdater",
    "Asteria-MemoryRestart",
    "AsteriaClientGuard",
    "CloudHoneypot-Background",
    "CloudHoneypot-Tray",
    "CloudHoneypot-Watchdog",
    "CloudHoneypot-Updater",
    "CloudHoneypot-SilentUpdater",
    "CloudHoneypot-MemoryRestart",
    "CloudHoneypotClientBoot",
    "CloudHoneypotClientLogon",
    "HoneypotClientGuard",
    "Cloud Honeypot Client",
    "HoneypotClientAutostart",
    "CloudHoneypotTray",
    "CloudHoneypotWatchdog",
    "CloudHoneypotUpdater",
    "CloudHoneypotSilentUpdater"
)

function Invoke-ParallelNative {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        [Parameter(Mandatory = $true)]
        [object[]]$ArgSets,
        [int]$TimeoutMs = 12000
    )
    if (-not $ArgSets -or $ArgSets.Count -eq 0) { return }
    $procs = New-Object System.Collections.Generic.List[System.Diagnostics.Process]
    foreach ($args in $ArgSets) {
        try {
            $p = Start-Process -FilePath $FilePath -ArgumentList $args `
                -WindowStyle Hidden -PassThru -ErrorAction SilentlyContinue
            if ($p) { [void]$procs.Add($p) }
        } catch {}
    }
    $deadline = (Get-Date).AddMilliseconds($TimeoutMs)
    foreach ($p in $procs) {
        try {
            if ($p.HasExited) { continue }
            $remain = [int](($deadline - (Get-Date)).TotalMilliseconds)
            if ($remain -lt 1) { $remain = 1 }
            $null = $p.WaitForExit($remain)
            if (-not $p.HasExited) {
                try { $p.Kill() } catch {}
            }
        } catch {}
    }
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
            $dir = Split-Path $p -Parent
            if ($dir -and -not (Test-Path $dir)) {
                New-Item -ItemType Directory -Path $dir -Force | Out-Null
            }
            Set-Content -Path $p -Value "stop" -Encoding ASCII -Force
        } catch {}
    }
}

function Stop-GuardianServices {
    Write-Host "[PREP] Guardian services: stop (parallel)..."
    $stopArgs = @()
    foreach ($svc in $GuardianServices) {
        $stopArgs += , @("stop", $svc)
    }
    Invoke-ParallelNative -FilePath "sc.exe" -ArgSets $stopArgs -TimeoutMs 8000
    Start-Sleep -Milliseconds 250
    Write-Host "[PREP] Guardian services: delete (parallel)..."
    $delArgs = @()
    foreach ($svc in $GuardianServices) {
        $delArgs += , @("delete", $svc)
    }
    Invoke-ParallelNative -FilePath "sc.exe" -ArgSets $delArgs -TimeoutMs 8000
}

function Stop-CriticalTasks {
    Write-Host "[PREP] Critical tasks: end + disable (parallel)..."
    $endArgs = @()
    $disArgs = @()
    foreach ($n in $CriticalTasks) {
        $endArgs += , @("/end", "/tn", $n)
        $disArgs += , @("/change", "/tn", $n, "/disable")
    }
    Invoke-ParallelNative -FilePath "schtasks.exe" -ArgSets $endArgs -TimeoutMs 10000
    Invoke-ParallelNative -FilePath "schtasks.exe" -ArgSets $disArgs -TimeoutMs 10000
}

function Remove-AllHoneypotTasks {
    Write-Host "[PREP] Bulk unregister Asteria / legacy scheduled tasks..."
    try {
        $match = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
            $_.TaskName -like "Asteria-*" -or
            $_.TaskName -like "AsteriaClient*" -or
            $_.TaskName -like "CloudHoneypot*" -or
            $_.TaskName -like "HoneypotClient*" -or
            $_.TaskName -eq "Cloud Honeypot Client"
        }
        foreach ($t in @($match)) {
            try {
                schtasks.exe /end /tn $t.TaskName 2>$null | Out-Null
            } catch {}
            try {
                Unregister-ScheduledTask -TaskName $t.TaskName -Confirm:$false -ErrorAction SilentlyContinue
            } catch {}
        }
    } catch {}

    Write-Host "[PREP] Explicit task delete fallback (parallel)..."
    $delArgs = @()
    foreach ($n in $AllKnownTasks) {
        $delArgs += , @("/delete", "/tn", $n, "/f")
    }
    Invoke-ParallelNative -FilePath "schtasks.exe" -ArgSets $delArgs -TimeoutMs 15000
}

function Invoke-KillHelper {
    if (-not $KillScript -or -not (Test-Path -LiteralPath $KillScript)) {
        Write-Host "[PREP] No kill script - taskkill fallback..."
        foreach ($im in @("asteria-gui.exe", "asteria-client.exe", "honeypot-client.exe")) {
            try { & taskkill.exe /F /T /IM $im 2>$null | Out-Null } catch {}
        }
        return 0
    }
    Write-Host ("[PREP] Invoking kill helper: {0}" -f $KillScript)
    $p = Start-Process -FilePath "powershell.exe" `
        -ArgumentList @(
            "-NoProfile",
            "-ExecutionPolicy", "Bypass",
            "-File", $KillScript,
            "-Force"
        ) `
        -WindowStyle Hidden -Wait -PassThru
    return [int]$p.ExitCode
}

Write-Host ("[PREP] Mode={0}" -f $Mode)

if ($Mode -eq "TasksOnly") {
    Write-StopFlags
    Stop-CriticalTasks
    Remove-AllHoneypotTasks
    Write-Host "[PREP] TasksOnly complete."
    exit 0
}

if ($Mode -eq "GuardianFirst") {
    Write-StopFlags
    Stop-GuardianServices
    Stop-CriticalTasks
    Write-Host "[PREP] GuardianFirst complete."
    exit 0
}

if ($Mode -eq "KillOnly") {
    Write-StopFlags
    Stop-GuardianServices
    Stop-CriticalTasks
    $code = Invoke-KillHelper
    Write-Host ("[PREP] KillOnly complete (kill exit={0})." -f $code)
    exit $code
}

# Full: guardian -> kill -> delete tasks
Write-StopFlags
Stop-GuardianServices
Stop-CriticalTasks
$code = Invoke-KillHelper
Remove-AllHoneypotTasks
Write-Host ("[PREP] Full cleanup complete (kill exit={0})." -f $code)
# Non-zero kill is a warning for installer; still delete tasks above.
if ($code -ne 0) { exit $code }
exit 0
