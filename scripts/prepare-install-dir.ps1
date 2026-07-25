# Prepare install dir so NSIS can overwrite onedir files without Abort/Retry/Ignore.
# Classic Windows pattern: rename locked tree aside, write fresh files, delete stale later.
# ASCII-only (installer PRE-KILL safety).
#
# Usage:
#   prepare-install-dir.ps1 -InstallDir "C:\Program Files\Asteria\Asteria Client"
#   prepare-install-dir.ps1 -InstallDir "..." -KillScript "C:\...\kill-honeypot.ps1"

param(
    [Parameter(Mandatory = $true)]
    [string]$InstallDir,
    [string]$KillScript = "",
    [switch]$SkipDefender
)

$ErrorActionPreference = "SilentlyContinue"
$InstallDir = $InstallDir.TrimEnd('\', '/')

function Write-PrepLog([string]$msg) {
    Write-Host ("[PREP-DIR] " + $msg)
}

function Invoke-KillHelper {
    if ($KillScript -and (Test-Path $KillScript)) {
        Write-PrepLog "Running kill helper..."
        try {
            & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $KillScript -Force
        } catch {}
    }
    try { & taskkill.exe /F /T /IM asteria-client.exe 2>$null | Out-Null } catch {}
    try { & taskkill.exe /F /T /IM asteria-gui.exe 2>$null | Out-Null } catch {}
    try { & taskkill.exe /F /T /IM honeypot-client.exe 2>$null | Out-Null } catch {}
}

function Stop-ProcessesUnderInstallDir {
    if (-not $InstallDir) { return }
    $needle = $InstallDir.ToLowerInvariant()
    try {
        $list = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)
    } catch {
        $list = @()
    }
    foreach ($p in $list) {
        try {
            $path = [string]($p.ExecutablePath)
            $cmd = [string]($p.CommandLine)
            $hit = $false
            if ($path -and $path.ToLowerInvariant().StartsWith($needle)) {
                $hit = $true
            }
            # Scheduled memory_restart / update helpers often lock scripts\*.ps1
            # while powershell.exe lives outside InstallDir.
            if (-not $hit -and $cmd) {
                $cl = $cmd.ToLowerInvariant()
                if ($cl.Contains($needle) -or $cl.Contains("memory_restart.ps1") -or
                    $cl.Contains("update-and-install.ps1") -or $cl.Contains("kill-honeypot.ps1")) {
                    $hit = $true
                }
            }
            if (-not $hit) { continue }
            Write-PrepLog ("Stopping PID {0} ({1})" -f $p.ProcessId, $(if ($path) { $path } else { $p.Name }))
            try { & taskkill.exe /F /T /PID $p.ProcessId 2>$null | Out-Null } catch {}
            try { Stop-Process -Id ([int]$p.ProcessId) -Force -ErrorAction SilentlyContinue } catch {}
        } catch {}
    }
}

function Add-DefenderExclusionFast {
    if ($SkipDefender) { return }
    if (-not $InstallDir) { return }
    Write-PrepLog "Defender exclusion (best-effort)..."
    try {
        Add-MpPreference -ExclusionPath $InstallDir -Force -ErrorAction SilentlyContinue
    } catch {}
    try {
        $exe = Join-Path $InstallDir "asteria-client.exe"
        if (-not (Test-Path $exe)) { $exe = Join-Path $InstallDir "honeypot-client.exe" }
        Add-MpPreference -ExclusionProcess $exe -Force -ErrorAction SilentlyContinue
    } catch {}
}

function Move-Aside([string]$path) {
    if (-not (Test-Path $path)) { return $true }
    $stamp = Get-Date -Format "yyyyMMddHHmmss"
    $rnd = Get-Random -Maximum 9999
    $dest = "{0}.stale_{1}_{2}" -f $path, $stamp, $rnd

    for ($i = 0; $i -lt 4; $i++) {
        try {
            Move-Item -LiteralPath $path -Destination $dest -Force -ErrorAction Stop
            Write-PrepLog ("Moved aside: {0} -> {1}" -f $path, (Split-Path $dest -Leaf))
            return $true
        } catch {
            Start-Sleep -Milliseconds (150 * ($i + 1))
            Stop-ProcessesUnderInstallDir
            try { & taskkill.exe /F /T /IM asteria-client.exe 2>$null | Out-Null } catch {}
            try { & taskkill.exe /F /T /IM asteria-gui.exe 2>$null | Out-Null } catch {}
            try { & taskkill.exe /F /T /IM honeypot-client.exe 2>$null | Out-Null } catch {}
        }
    }

    # Directory still locked (process cwd / open handle): move each FILE aside.
    # Renaming an in-use file frees the original path for NSIS overwrite.
    if (Test-Path $path -PathType Container) {
        Write-PrepLog "Directory move failed - relocating files individually..."
        try { New-Item -ItemType Directory -Path $dest -Force | Out-Null } catch {}
        $failed = 0
        Get-ChildItem -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue |
            Where-Object { -not $_.PSIsContainer } |
            ForEach-Object {
                try {
                    $rel = $_.FullName.Substring($path.Length).TrimStart('\')
                    $target = Join-Path $dest $rel
                    $td = Split-Path $target -Parent
                    if ($td -and -not (Test-Path $td)) {
                        New-Item -ItemType Directory -Path $td -Force | Out-Null
                    }
                    try { $_.Attributes = 'Normal' } catch {}
                    Move-Item -LiteralPath $_.FullName -Destination $target -Force -ErrorAction Stop
                } catch {
                    $failed++
                    # Last chance: rename in place so NSIS can write the canonical name
                    try {
                        $alt = $_.FullName + ".stale"
                        Move-Item -LiteralPath $_.FullName -Destination $alt -Force -ErrorAction Stop
                    } catch {
                        $failed++
                    }
                }
            }
        # Remove now-empty directories under $path
        try {
            Get-ChildItem -LiteralPath $path -Recurse -Force -Directory -ErrorAction SilentlyContinue |
                Sort-Object { $_.FullName.Length } -Descending |
                ForEach-Object {
                    try { Remove-Item -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue } catch {}
                }
            Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        } catch {}
        if (-not (Test-Path $path)) {
            Write-PrepLog ("File-level relocate ok -> {0}" -f (Split-Path $dest -Leaf))
            return $true
        }
        # Path exists but may be empty enough for NSIS to recreate files
        $leftFiles = @(Get-ChildItem -LiteralPath $path -Recurse -File -Force -ErrorAction SilentlyContinue)
        if ($leftFiles.Count -eq 0) {
            Write-PrepLog "Tree emptied for overwrite"
            return $true
        }
        Write-PrepLog ("WARN: {0} file(s) still present under {1}" -f $leftFiles.Count, $path)
        return $false
    }

    try {
        Get-Item -LiteralPath $path -Force | ForEach-Object { try { $_.Attributes = 'Normal' } catch {} }
        Remove-Item -LiteralPath $path -Force -ErrorAction Stop
        Write-PrepLog ("Removed: {0}" -f $path)
        return $true
    } catch {
        Write-PrepLog ("WARN: still locked: {0}" -f $path)
        return $false
    }
}

function Clear-StaleAsync {
    # Best-effort cleanup of previous .stale_* leftovers (non-blocking)
    try {
        $parent = Split-Path $InstallDir -Parent
        if (-not $parent) { return }
        Get-ChildItem -LiteralPath $InstallDir -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '\.stale_\d+' } |
            ForEach-Object {
                $target = $_.FullName
                Start-Process -FilePath "cmd.exe" -ArgumentList "/c","rmdir","/s","/q","`"$target`"" -WindowStyle Hidden -ErrorAction SilentlyContinue | Out-Null
            }
    } catch {}
}

Write-PrepLog ("InstallDir={0}" -f $InstallDir)
if (-not (Test-Path $InstallDir)) {
    try { New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null } catch {}
    Write-PrepLog "Created empty install dir"
    exit 0
}

# Order matters: stop respawn, kill, exclude AV, then rename locked trees.
Invoke-KillHelper
foreach ($tn in @("CloudHoneypot-MemoryRestart", "\CloudHoneypot-MemoryRestart")) {
    try { & schtasks.exe /end /tn $tn 2>$null | Out-Null } catch {}
    try { & schtasks.exe /change /tn $tn /disable 2>$null | Out-Null } catch {}
}
Stop-ProcessesUnderInstallDir
Start-Sleep -Milliseconds 200
Stop-ProcessesUnderInstallDir
Add-DefenderExclusionFast

$okInternal = Move-Aside (Join-Path $InstallDir "_internal")
$okExeA = Move-Aside (Join-Path $InstallDir "asteria-client.exe")
$okExeG = Move-Aside (Join-Path $InstallDir "asteria-gui.exe")
$okExeH = Move-Aside (Join-Path $InstallDir "honeypot-client.exe")
$okExe = ($okExeA -or $okExeH -or $okExeG)

# Also clear common lock-prone helpers next to exe
Move-Aside (Join-Path $InstallDir "asteria-client.exe.manifest") | Out-Null
Move-Aside (Join-Path $InstallDir "honeypot_client.exe.manifest") | Out-Null
Move-Aside (Join-Path $InstallDir "honeypot-client.exe.manifest") | Out-Null

# scripts\memory_restart.ps1 is often locked by schtask PowerShell — rename tree
# so NSIS File never hits Abort/Retry/Ignore on upgrade.
$okScripts = Move-Aside (Join-Path $InstallDir "scripts")
if (-not $okScripts) {
    Move-Aside (Join-Path $InstallDir "scripts\memory_restart.ps1") | Out-Null
    Move-Aside (Join-Path $InstallDir "scripts\update-and-install.ps1") | Out-Null
    Move-Aside (Join-Path $InstallDir "scripts\kill-honeypot.ps1") | Out-Null
}

Clear-StaleAsync

if (-not $okInternal -or -not $okExe) {
    Write-PrepLog "WARN: some paths remain; NSIS may still hit FileInUse (retry/ignore)"
    exit 2
}

Write-PrepLog "Ready for NSIS file extract."
exit 0
