# Windows health repair helpers for Asteria Control Center Tools page.
# ASCII-only. Prefer elevated (Administrator).
# Usage:
#   windows-health-repair.ps1 -Action status
#   windows-health-repair.ps1 -Action dns_flush
#   windows-health-repair.ps1 -Action webview2
#   windows-health-repair.ps1 -Action full_safe
#
# Destructive actions (firewall_reset, winsock_reset, wu_reset) require -ConfirmYes

param(
    [Parameter(Mandatory = $true)]
    [ValidateSet(
        "status",
        "dns_flush",
        "webview2",
        "winsock_reset",
        "firewall_reset",
        "wu_reset",
        "sfc_scan",
        "dism_health",
        "full_safe"
    )]
    [string]$Action,
    [switch]$ConfirmYes,
    [string]$WebView2Payload = ""
)

$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"

function Write-JsonResult {
    param([hashtable]$Obj)
    $Obj | ConvertTo-Json -Compress -Depth 6
}

function Test-IsAdmin {
    try {
        $p = New-Object Security.Principal.WindowsPrincipal(
            [Security.Principal.WindowsIdentity]::GetCurrent()
        )
        return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

function Test-WebView2 {
    $guids = "{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"
    foreach ($k in @(
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\$guids",
        "HKLM:\SOFTWARE\Microsoft\EdgeUpdate\Clients\$guids"
    )) {
        try {
            $pv = (Get-ItemProperty -Path $k -Name pv -EA Stop).pv
            if ($pv -and $pv -ne "0.0.0.0") { return @{ ok = $true; detail = "pv=$pv" } }
        } catch {}
    }
    $exe = "${env:ProgramFiles}\Microsoft\EdgeWebView\Application\msedgewebview2.exe"
    if (Test-Path $exe) { return @{ ok = $true; detail = "fs" } }
    return @{ ok = $false; detail = "missing" }
}

function Invoke-DnsFlush {
    ipconfig /flushdns | Out-Null
    return @{ ok = $true; detail = "dns_flushed" }
}

function Invoke-WinsockReset {
    if (-not $ConfirmYes) { return @{ ok = $false; error = "confirm_required" } }
    netsh winsock reset | Out-Null
    netsh int ip reset | Out-Null
    return @{ ok = $true; detail = "winsock_reset_reboot_recommended" }
}

function Invoke-FirewallReset {
    if (-not $ConfirmYes) { return @{ ok = $false; error = "confirm_required" } }
    netsh advfirewall reset | Out-Null
    return @{ ok = $true; detail = "firewall_defaults_restored" }
}

function Invoke-WuReset {
    if (-not $ConfirmYes) { return @{ ok = $false; error = "confirm_required" } }
    $services = @("bits", "wuauserv", "cryptsvc", "msiserver")
    foreach ($s in $services) {
        try { Stop-Service -Name $s -Force -EA SilentlyContinue } catch {}
    }
    $sd = Join-Path $env:SystemRoot "SoftwareDistribution"
    $cr = Join-Path $env:SystemRoot "System32\catroot2"
    foreach ($d in @($sd, $cr)) {
        if (Test-Path $d) {
            $bak = "$d.bak_$([DateTime]::UtcNow.ToString('yyyyMMddHHmmss'))"
            try { Rename-Item -LiteralPath $d -NewName (Split-Path $bak -Leaf) -EA SilentlyContinue } catch {}
        }
    }
    foreach ($s in $services) {
        try { Start-Service -Name $s -EA SilentlyContinue } catch {}
    }
    return @{ ok = $true; detail = "wu_components_reset" }
}

function Invoke-SfcScan {
    # Long-running; start visible so operator can watch.
    Start-Process -FilePath "$env:SystemRoot\System32\sfc.exe" -ArgumentList "/scannow" -Verb RunAs
    return @{ ok = $true; detail = "sfc_started" }
}

function Invoke-DismHealth {
    Start-Process -FilePath "$env:SystemRoot\System32\DISM.exe" `
        -ArgumentList "/Online","/Cleanup-Image","/RestoreHealth" -Verb RunAs
    return @{ ok = $true; detail = "dism_started" }
}

function Invoke-WebView2 {
    $script = Join-Path $PSScriptRoot "repair-webview2.ps1"
    if (-not (Test-Path $script)) {
        return @{ ok = $false; error = "repair_script_missing" }
    }
    $args = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $script)
    if ($WebView2Payload) { $args += @("-PayloadPath", $WebView2Payload) }
    $p = Start-Process -FilePath "powershell.exe" -ArgumentList $args -Wait -PassThru -WindowStyle Hidden
    $present = Test-WebView2
    return @{
        ok = [bool]$present.ok
        detail = "exit=$($p.ExitCode); $($present.detail)"
        exit_code = $p.ExitCode
    }
}

function Get-Status {
    $wv = Test-WebView2
    $fw = $null
    try {
        $fw = (Get-NetFirewallProfile -EA SilentlyContinue | Select-Object Name, Enabled)
    } catch {}
    return @{
        ok = $true
        admin = Test-IsAdmin
        webview2 = $wv
        firewall = $fw
        os = [Environment]::OSVersion.VersionString
        computer = $env:COMPUTERNAME
    }
}

if ($Action -eq "status") {
    Write-JsonResult (Get-Status)
    exit 0
}

if (-not (Test-IsAdmin)) {
    Write-JsonResult @{ ok = $false; error = "admin_required"; action = $Action }
    exit 5
}

$result = switch ($Action) {
    "dns_flush" { Invoke-DnsFlush }
    "winsock_reset" { Invoke-WinsockReset }
    "firewall_reset" { Invoke-FirewallReset }
    "wu_reset" { Invoke-WuReset }
    "sfc_scan" { Invoke-SfcScan }
    "dism_health" { Invoke-DismHealth }
    "webview2" { Invoke-WebView2 }
    "full_safe" {
        $steps = @()
        $steps += @{ step = "dns_flush"; result = Invoke-DnsFlush }
        $steps += @{ step = "webview2"; result = Invoke-WebView2 }
        # Launch long scanners last (non-blocking windows)
        $steps += @{ step = "dism_health"; result = Invoke-DismHealth }
        $steps += @{ step = "sfc_scan"; result = Invoke-SfcScan }
        @{ ok = $true; detail = "full_safe_started"; steps = $steps }
    }
}

Write-JsonResult ($result + @{ action = $Action })
if ($result.ok) { exit 0 } else { exit 1 }
