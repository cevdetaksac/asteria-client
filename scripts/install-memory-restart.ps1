# Lock-safe install of memory_restart.ps1 into $InstallDir\scripts.
# Called from NSIS so FileInUse never surfaces Abort/Retry/Ignore.
# ASCII-only.

param(
    [Parameter(Mandatory = $true)]
    [string]$InstallDir,
    [Parameter(Mandatory = $true)]
    [string]$SourcePath
)

$ErrorActionPreference = "SilentlyContinue"
$InstallDir = $InstallDir.TrimEnd('\', '/')
$scripts = Join-Path $InstallDir "scripts"
$dest = Join-Path $scripts "memory_restart.ps1"

function Write-MrLog([string]$msg) {
    Write-Host ("[MR-INSTALL] " + $msg)
}

if (-not (Test-Path -LiteralPath $SourcePath)) {
    Write-MrLog ("ERROR: source missing: {0}" -f $SourcePath)
    exit 1
}

New-Item -ItemType Directory -Force -Path $scripts | Out-Null

# Stop PowerShell still holding the script (MemoryRestart schtask / leftover).
try {
    $needle = $InstallDir.ToLowerInvariant()
    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Name -match '^(powershell|pwsh|powershell_ise)\.exe$' -and
            $_.CommandLine -and (
                $_.CommandLine.ToLowerInvariant().Contains("memory_restart.ps1") -or
                $_.CommandLine.ToLowerInvariant().Contains($needle)
            )
        } |
        ForEach-Object {
            Write-MrLog ("Stopping PID {0}" -f $_.ProcessId)
            try { & taskkill.exe /F /T /PID $_.ProcessId 2>$null | Out-Null } catch {}
            try { Stop-Process -Id ([int]$_.ProcessId) -Force -ErrorAction SilentlyContinue } catch {}
        }
} catch {}

# Best-effort: end/disable task even if installer already deleted it.
foreach ($tn in @("CloudHoneypot-MemoryRestart", "\CloudHoneypot-MemoryRestart")) {
    try { & schtasks.exe /end /tn $tn 2>$null | Out-Null } catch {}
    try { & schtasks.exe /change /tn $tn /disable 2>$null | Out-Null } catch {}
}

Start-Sleep -Milliseconds 150

# Free the destination path (rename beats delete on locked files).
if (Test-Path -LiteralPath $dest) {
    try {
        $item = Get-Item -LiteralPath $dest -Force
        try { $item.Attributes = "Normal" } catch {}
    } catch {}
    $stamp = Get-Date -Format "yyyyMMddHHmmss"
    $aside = "{0}.stale_{1}" -f $dest, $stamp
    $moved = $false
    for ($i = 0; $i -lt 5; $i++) {
        try {
            Move-Item -LiteralPath $dest -Destination $aside -Force -ErrorAction Stop
            Write-MrLog ("Moved aside -> {0}" -f (Split-Path $aside -Leaf))
            $moved = $true
            break
        } catch {
            Start-Sleep -Milliseconds (200 * ($i + 1))
        }
    }
    if (-not $moved) {
        try {
            Remove-Item -LiteralPath $dest -Force -ErrorAction Stop
            Write-MrLog "Removed locked dest"
        } catch {
            Write-MrLog "WARN: could not free dest; will retry copy"
        }
    }
}

$ok = $false
for ($i = 1; $i -le 10; $i++) {
    try {
        Copy-Item -LiteralPath $SourcePath -Destination $dest -Force -ErrorAction Stop
        if (Test-Path -LiteralPath $dest) {
            $ok = $true
            Write-MrLog ("OK (attempt {0})" -f $i)
            break
        }
    } catch {
        Write-MrLog ("copy attempt {0} failed: {1}" -f $i, $_.Exception.Message)
        Start-Sleep -Milliseconds (250 * $i)
    }
}

if (-not $ok) {
    Write-MrLog "ERROR: could not write memory_restart.ps1 (client will restage on first run)"
    exit 2
}

exit 0
