# Reset Asteria Client durable identity (clone / shared-token recovery).
# Run elevated. Stops agent tasks, quarantines token.dat + account_link, then
# the next agent start performs a fresh /register under the hardware fingerprint.
#
# Usage (Admin PowerShell):
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\reset-agent-identity.ps1
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\reset-agent-identity.ps1 -AlsoKill

param(
    [switch]$AlsoKill,
    [string]$InstallDir = "${env:ProgramFiles}\Asteria\Asteria Client"
)

$ErrorActionPreference = "Stop"
$pd = Join-Path $env:ProgramData "Asteria"
$stamp = Get-Date -Format "yyyyMMddHHmmss"

function Write-IdLog([string]$msg) {
    Write-Host ("[RESET-ID] " + $msg)
}

function Move-Aside([string]$path) {
    if (-not (Test-Path -LiteralPath $path)) { return }
    $dest = "{0}.stale_manual_{1}" -f $path, $stamp
    Move-Item -LiteralPath $path -Destination $dest -Force
    Write-IdLog ("Quarantined: {0}" -f (Split-Path $dest -Leaf))
}

# End/disable tasks that would race a restart
foreach ($tn in @(
        "Asteria-Background",
        "Asteria-Tray",
        "Asteria-Watchdog",
        "Asteria-Updater",
        "Asteria-SilentUpdater",
        "Asteria-MemoryRestart",
        "AsteriaClientGuard",
        # Pre-4.9.41
        "CloudHoneypot-Background",
        "CloudHoneypot-Tray",
        "CloudHoneypot-Watchdog",
        "CloudHoneypot-Updater",
        "CloudHoneypot-SilentUpdater",
        "CloudHoneypot-MemoryRestart",
        "HoneypotClientGuard"
    )) {
    try { & schtasks.exe /end /tn $tn 2>$null | Out-Null } catch {}
    try { & schtasks.exe /change /tn $tn /disable 2>$null | Out-Null } catch {}
}

if ($AlsoKill) {
    $kill = Join-Path $PSScriptRoot "kill-honeypot.ps1"
    if (Test-Path -LiteralPath $kill) {
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $kill -Force
    } else {
        try { & taskkill.exe /F /T /IM asteria-client.exe 2>$null | Out-Null } catch {}
    }
}

New-Item -ItemType Directory -Force -Path $pd | Out-Null
Move-Aside (Join-Path $pd "token.dat")
Move-Aside (Join-Path $pd "device_binding.json")
Move-Aside (Join-Path $pd "account_link.json")

# Legacy locations that migrate back into ProgramData
$legacy = @(
    (Join-Path $env:APPDATA "Asteria\token.dat"),
    (Join-Path $env:WINDIR "System32\config\systemprofile\AppData\Roaming\Asteria\token.dat")
)
foreach ($p in $legacy) { Move-Aside $p }

Write-IdLog "Identity cleared."
Write-IdLog "Next: start Asteria Client (or re-enable scheduled tasks) so it /register's a NEW token."
Write-IdLog "Then: Settings → Account link (each physical server must get its own token)."
Write-IdLog ("Tip: rename hostname if still shared (e.g. WIN-KD60285EPLN clones). InstallDir={0}" -f $InstallDir)
