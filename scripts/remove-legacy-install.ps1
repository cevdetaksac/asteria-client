# Remove legacy YesNext / Cloud Honeypot Client Program Files trees and leftovers.
# Called by the Asteria installer so upgrades leave a clean Asteria-only surface.
# ASCII-only (NSIS PreInstallKillFast safety).
#
# Usage:
#   remove-legacy-install.ps1
#   remove-legacy-install.ps1 -KeepIfSameAs "C:\Program Files\Asteria\Asteria Client"

param(
    [string]$KeepIfSameAs = ""
)

$ErrorActionPreference = "SilentlyContinue"

function Write-LegacyLog([string]$msg) {
    Write-Host ("[LEGACY-CLEAN] " + $msg)
}

function Normalize-Dir([string]$p) {
    if (-not $p) { return "" }
    try {
        return ([IO.Path]::GetFullPath($p.TrimEnd('\', '/'))).ToLowerInvariant()
    } catch {
        return ($p.TrimEnd('\', '/')).ToLowerInvariant()
    }
}

# Disable WOW64 file-system redirection so a 32-bit host (NSIS x86 child) can
# see and delete the real 64-bit "C:\Program Files\YesNext\..." tree.
$wow64Disabled = $false
$wow64Old = [IntPtr]::Zero
try {
    $wowType = Add-Type -MemberDefinition @"
[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError=true)]
public static extern bool Wow64DisableWow64FsRedirection(ref IntPtr ptr);
[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError=true)]
public static extern bool Wow64RevertWow64FsRedirection(IntPtr ptr);
"@ -Name "HpWow64Fs" -Namespace "AsteriaLegacyClean" -PassThru -ErrorAction Stop
    $wow64Old = [IntPtr]::Zero
    if ($wowType::Wow64DisableWow64FsRedirection([ref]$wow64Old)) {
        $wow64Disabled = $true
        Write-LegacyLog "WOW64 FS redirection disabled for legacy purge"
    }
} catch {}

try {

# NSIS builds are x86-unicode. Child PowerShell may be 32-bit under WOW64, so
# $env:ProgramFiles points at "Program Files (x86)". Always include ProgramW6432
# (real 64-bit Program Files) or legacy trees under C:\Program Files\YesNext
# survive the "cleanup".
$pfCandidates = @(
    [Environment]::GetEnvironmentVariable("ProgramW6432"),
    ${env:ProgramFiles},
    [Environment]::GetEnvironmentVariable("ProgramFiles(x86)")
) | Where-Object { $_ } | Select-Object -Unique

$keep = Normalize-Dir $KeepIfSameAs

$roots = @()
foreach ($pf in $pfCandidates) {
    $roots += (Join-Path $pf "YesNext\Cloud Honeypot Client")
    $roots += (Join-Path $pf "YesNext\CloudClient")
    $roots += (Join-Path $pf "YesNext\Cloud Honeypot")
    $roots += (Join-Path $pf "Asteria")
}
# ProgramData / roaming leftovers from YesNext era (logs, staging, configs).
# Asteria lives under ProgramData\Asteria — safe to purge the old vendor tree.
$pd = [Environment]::GetEnvironmentVariable("ProgramData")
if ($pd) {
    $roots += (Join-Path $pd "YesNext")
}
$roots = @($roots | Where-Object { $_ } | Select-Object -Unique)

Write-LegacyLog ("PF candidates: " + ($pfCandidates -join " | "))

# Stop anything still running from legacy trees before delete.
foreach ($root in $roots) {
    if (-not (Test-Path -LiteralPath $root)) { continue }
    $needle = Normalize-Dir $root
    if ($keep -and $needle -eq $keep) {
        Write-LegacyLog ("Skip keep path: " + $root)
        continue
    }
    try {
        Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | ForEach-Object {
            $ep = [string]($_.ExecutablePath)
            if ($ep -and $ep.ToLowerInvariant().StartsWith($needle)) {
                try { & taskkill.exe /F /T /PID $_.ProcessId 2>$null | Out-Null } catch {}
            }
        }
    } catch {}
    try { & taskkill.exe /F /T /IM honeypot-client.exe 2>$null | Out-Null } catch {}
    try { & taskkill.exe /F /T /IM asteria-client.exe 2>$null | Out-Null } catch {}
    try { & taskkill.exe /F /T /IM asteria-gui.exe 2>$null | Out-Null } catch {}
}

foreach ($root in $roots) {
    if (-not (Test-Path -LiteralPath $root)) { continue }
    $needle = Normalize-Dir $root
    if ($keep -and $needle -eq $keep) { continue }
    Write-LegacyLog ("Removing tree: " + $root)
    try {
        # Take ownership + reset ACL so locked/denied trees can be deleted.
        & takeown.exe /F $root /R /D Y 2>$null | Out-Null
        & icacls.exe $root /grant Administrators:F /T /C /Q 2>$null | Out-Null
    } catch {}
    try {
        Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction Stop
        Write-LegacyLog ("Removed: " + $root)
    } catch {
        # Fallback: cmd rmdir often succeeds when PowerShell still sees locks.
        try {
            & cmd.exe /c "rmdir /s /q `"$root`"" 2>$null | Out-Null
        } catch {}
        if (Test-Path -LiteralPath $root) {
            Write-LegacyLog ("WARN: still present: " + $root)
        } else {
            Write-LegacyLog ("Removed via rmdir: " + $root)
        }
    }
}

# Empty YesNext vendor folder if nothing else remains under Program Files.
$vendorDirs = @()
foreach ($pf in $pfCandidates) {
    $vendorDirs += (Join-Path $pf "YesNext")
}
$vendorDirs = @($vendorDirs | Where-Object { $_ } | Select-Object -Unique)
foreach ($vendor in $vendorDirs) {
    if (-not $vendor -or -not (Test-Path -LiteralPath $vendor)) { continue }
    try {
        # Remove known leftover leaf dirs that are not the primary product tree.
        foreach ($leaf in @("CloudClient", "Cloud Honeypot", "Updater", "Update")) {
            $extra = Join-Path $vendor $leaf
            if (Test-Path -LiteralPath $extra) {
                try {
                    & takeown.exe /F $extra /R /D Y 2>$null | Out-Null
                    & icacls.exe $extra /grant Administrators:F /T /C /Q 2>$null | Out-Null
                } catch {}
                try {
                    Remove-Item -LiteralPath $extra -Recurse -Force -ErrorAction SilentlyContinue
                    Write-LegacyLog ("Removed leftover: " + $extra)
                } catch {}
            }
        }
        $left = @(Get-ChildItem -LiteralPath $vendor -Force -ErrorAction SilentlyContinue)
        if ($left.Count -eq 0) {
            Remove-Item -LiteralPath $vendor -Force -ErrorAction SilentlyContinue
            Write-LegacyLog ("Removed empty vendor dir: " + $vendor)
        } else {
            Write-LegacyLog ("Vendor dir still has entries: " + $vendor + " -> " + (($left | ForEach-Object { $_.Name }) -join ", "))
        }
    } catch {}
}

# Per-user YesNext AppData leftovers (non-fatal).
foreach ($base in @($env:APPDATA, $env:LOCALAPPDATA)) {
    if (-not $base) { continue }
    $u = Join-Path $base "YesNext"
    if (Test-Path -LiteralPath $u) {
        try {
            Remove-Item -LiteralPath $u -Recurse -Force -ErrorAction SilentlyContinue
            Write-LegacyLog ("Removed user legacy: " + $u)
        } catch {}
    }
}

# Legacy Add/Remove Programs keys (old product names).
$uninstallKeys = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\Cloud Honeypot Client",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\CloudHoneypotClient",
    "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Cloud Honeypot Client",
    "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\CloudHoneypotClient"
)
foreach ($k in $uninstallKeys) {
    if (Test-Path -LiteralPath $k) {
        try {
            Remove-Item -LiteralPath $k -Recurse -Force -ErrorAction Stop
            Write-LegacyLog ("Removed uninstall key: " + $k)
        } catch {}
    }
}

# Legacy Start Menu / desktop shortcuts pointing at honeypot-client.
$shortcutRoots = @(
    (Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\YesNext"),
    (Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\Cloud Honeypot Client"),
    (Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\CloudHoneypot")
)
foreach ($sm in $shortcutRoots) {
    if (Test-Path -LiteralPath $sm) {
        try {
            Remove-Item -LiteralPath $sm -Recurse -Force -ErrorAction SilentlyContinue
            Write-LegacyLog ("Removed Start Menu folder: " + $sm)
        } catch {}
    }
}

foreach ($desk in @(
    (Join-Path ([Environment]::GetFolderPath("CommonDesktopDirectory")) "Cloud Honeypot Client.lnk"),
    (Join-Path ([Environment]::GetFolderPath("CommonDesktopDirectory")) "Cloud Honeypot.lnk"),
    (Join-Path ([Environment]::GetFolderPath("CommonDesktopDirectory")) "Honeypot Client.lnk")
)) {
    if ($desk -and (Test-Path -LiteralPath $desk)) {
        try {
            Remove-Item -LiteralPath $desk -Force -ErrorAction SilentlyContinue
            Write-LegacyLog ("Removed desktop shortcut: " + $desk)
        } catch {}
    }
}

Write-LegacyLog "Done."

} finally {
    if ($wow64Disabled) {
        try {
            [void][AsteriaLegacyClean.HpWow64Fs]::Wow64RevertWow64FsRedirection($wow64Old)
        } catch {}
    }
}

exit 0
