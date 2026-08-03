# WebView2 Evergreen Runtime repair / force reinstall
# ASCII-only. Elevated recommended.
# Usage:
#   repair-webview2.ps1
#   repair-webview2.ps1 -PayloadPath "C:\...\MicrosoftEdgeWebView2RuntimeInstallerX64.exe"

param(
    [string]$PayloadPath = ""
)

$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"

function Test-WebView2Present {
    $guids = "{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"
    $keys = @(
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\$guids",
        "HKLM:\SOFTWARE\Microsoft\EdgeUpdate\Clients\$guids",
        "HKCU:\SOFTWARE\Microsoft\EdgeUpdate\Clients\$guids"
    )
    foreach ($k in $keys) {
        try {
            $pv = (Get-ItemProperty -Path $k -Name pv -ErrorAction Stop).pv
            if ($pv -and $pv -ne "0.0.0.0") {
                return $true
            }
        } catch {}
    }
    $roots = @(
        "${env:ProgramFiles}\Microsoft\EdgeWebView\Application\msedgewebview2.exe",
        "${env:ProgramFiles(x86)}\Microsoft\EdgeWebView\Application\msedgewebview2.exe"
    )
    foreach ($p in $roots) {
        if ($p -and (Test-Path -LiteralPath $p)) { return $true }
    }
    return $false
}

function Find-Payload {
    if ($PayloadPath -and (Test-Path -LiteralPath $PayloadPath)) {
        return (Resolve-Path -LiteralPath $PayloadPath).Path
    }
    $candidates = @(
        (Join-Path ${env:ProgramFiles} "Asteria\Asteria Client\MicrosoftEdgeWebView2RuntimeInstallerX64.exe"),
        (Join-Path ${env:ProgramFiles} "Asteria\Asteria Client\MicrosoftEdgeWebview2Setup.exe"),
        (Join-Path $PSScriptRoot "MicrosoftEdgeWebView2RuntimeInstallerX64.exe"),
        (Join-Path $PSScriptRoot "..\vendor\MicrosoftEdgeWebView2RuntimeInstallerX64.exe")
    )
    foreach ($c in $candidates) {
        if ($c -and (Test-Path -LiteralPath $c)) {
            $len = (Get-Item -LiteralPath $c).Length
            if ($len -gt 100000) { return $c }
        }
    }
    return $null
}

Write-Host "[WV2] Checking runtime..."
if (Test-WebView2Present) {
    Write-Host "[WV2] Already present"
    exit 0
}

# EdgeUpdate service often broken on damaged Server images
foreach ($svc in @("edgeupdate", "edgeupdatem", "MicrosoftEdgeElevationService")) {
    try {
        $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if ($s -and $s.StartType -eq "Disabled") {
            Set-Service -Name $svc -StartupType Manual -ErrorAction SilentlyContinue
        }
        if ($s -and $s.Status -ne "Running") {
            Start-Service -Name $svc -ErrorAction SilentlyContinue
        }
    } catch {}
}

$payload = Find-Payload
if (-not $payload) {
    Write-Host "[WV2] No local payload - opening download page"
    try {
        Start-Process "https://developer.microsoft.com/microsoft-edge/webview2/"
    } catch {}
    exit 2
}

Write-Host "[WV2] Installing from $payload"
$argsList = @("/silent", "/install")
if ($payload -match "Webview2Setup") {
    $argsList = @("/silent", "/install")
}
$p = Start-Process -FilePath $payload -ArgumentList $argsList -Wait -PassThru -WindowStyle Hidden
Write-Host ("[WV2] Installer exit={0}" -f $p.ExitCode)

# Registry can lag several seconds on damaged disks / AV
for ($i = 0; $i -lt 12; $i++) {
    Start-Sleep -Seconds 2
    if (Test-WebView2Present) {
        Write-Host "[WV2] Runtime detected after wait"
        exit 0
    }
}

Write-Host "[WV2] Still missing after install"
exit 1
