# Requires: Administrator
# Asteria remote-desktop host prep (C-RD-HOST-1) — Server / headless friendly.
# Called from installer.nsi post-install; motor also applies via client_rd_host_prep.py.

$ErrorActionPreference = 'SilentlyContinue'
$steps = New-Object System.Collections.Generic.List[string]

function Write-Step([string]$s) {
    $steps.Add($s) | Out-Null
    Write-Host "[RD-HOST-PREP] $s"
}

try {
    $pd = Join-Path $env:ProgramData 'Asteria'
    New-Item -ItemType Directory -Force -Path $pd | Out-Null
    New-Item -ItemType Directory -Force -Path (Join-Path $pd 'rd_capture_diag') | Out-Null
    Write-Step 'dump_dir=ok'
} catch {
    Write-Step "dump_dir=err:$($_.Exception.Message)"
}

try {
    $prod = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\ProductOptions' -ErrorAction Stop).ProductType
    $isServer = $prod -in @('ServerNT', 'LanmanNT')
    Write-Step "product=$prod server=$isServer"
} catch {
    $isServer = $false
    Write-Step 'product=unknown'
}

try {
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 0 -Type DWord -Force
    Write-Step 'fDenyTSConnections=0'
} catch { Write-Step 'fDenyTSConnections=fail' }

try {
    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Force | Out-Null
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name fResetBroken -Value 0 -Type DWord -Force
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name MaxDisconnectionTime -Value 0 -Type DWord -Force
    Write-Step 'ts_policy=keepalive'
} catch { Write-Step 'ts_policy=fail' }

try {
    Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DWM' -Name DisallowComposition -Force -ErrorAction SilentlyContinue
    Write-Step 'dwm_disallow_cleared'
} catch { Write-Step 'dwm_disallow=absent' }

try {
    New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\DWM' -Force | Out-Null
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\DWM' -Name ForceEffectMode -Value 2 -Type DWord -Force
    Write-Step 'dwm_force_effect=2'
} catch { Write-Step 'dwm_force=fail' }

foreach ($svc in @('Themes', 'UxSms', 'DispBrokerDesktopSvc', 'TermService')) {
    try {
        $s = Get-Service -Name $svc -ErrorAction Stop
        if ($s.StartType -ne 'Automatic') {
            Set-Service -Name $svc -StartupType Automatic -ErrorAction SilentlyContinue
        }
        if ($s.Status -ne 'Running') {
            Start-Service -Name $svc -ErrorAction SilentlyContinue
        }
        Write-Step "svc:$svc=ok"
    } catch {
        Write-Step "svc:$svc=missing"
    }
}

try {
    powercfg /change monitor-timeout-ac 0 | Out-Null
    powercfg /change monitor-timeout-dc 0 | Out-Null
    powercfg /change standby-timeout-ac 0 | Out-Null
    powercfg /change standby-timeout-dc 0 | Out-Null
    Write-Step 'powercfg_monitor=0'
} catch { Write-Step 'powercfg=fail' }

try {
    netsh advfirewall firewall set rule group="remote desktop" new enable=yes | Out-Null
    Write-Step 'firewall_rdp_group=tried'
} catch { Write-Step 'firewall_rdp=fail' }

if ($isServer) {
    try {
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoRestartShell -Value 1 -Type DWord -Force
        Write-Step 'AutoRestartShell=1'
    } catch { Write-Step 'AutoRestartShell=fail' }
}

try {
    $flag = Join-Path $env:ProgramData 'Asteria\rd_host_prep.flag'
    Set-Content -Path $flag -Value ("ok {0}" -f [int][double]::Parse((Get-Date -UFormat %s))) -Encoding ASCII
    Write-Step 'flag=written'
} catch { Write-Step 'flag=fail' }

Write-Host ("[RD-HOST-PREP] done steps={0}" -f ($steps -join '; '))
exit 0
