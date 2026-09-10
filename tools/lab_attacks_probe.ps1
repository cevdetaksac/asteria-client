# Lab Attacks probe from external PC (contract C-ATK-*)
# Usage: .\tools\lab_attacks_probe.ps1 -HostName 194.5.236.32 -Tag ninety122
param(
    [Parameter(Mandatory=$true)][string]$HostName,
    [Parameter(Mandatory=$true)][string]$Tag
)

$ErrorActionPreference = 'Continue'
$pub = (Invoke-RestMethod -Uri 'https://api.ipify.org?format=json').ip
Write-Host "=== LAB PROBE $Tag -> $HostName (source ~ $pub) ==="

# SMB / NETWORK:445
Write-Host '[1/6] SMB wrong password...'
cmd /c "net use \\$HostName\IPC$ WrongPass_$Tag! /user:lab_$Tag" 2>&1 | Out-Null
Start-Sleep -Seconds 2

# FTP 530 (IIS)
Write-Host '[2/6] FTP wrong password...'
try {
    $ftpReq = [System.Net.FtpWebRequest]::Create("ftp://$HostName/")
    $ftpReq.Method = [System.Net.WebRequestMethods+Ftp]::ListDirectory
    $ftpReq.Credentials = New-Object System.Net.NetworkCredential("lab_$Tag", "WrongPass_$Tag!")
    $ftpReq.UsePassive = $true
    $ftpReq.Timeout = 15000
    $resp = $ftpReq.GetResponse()
    $resp.Close()
} catch {
    Write-Host "  FTP expected fail: $($_.Exception.Message)"
}
Start-Sleep -Seconds 2

# MySQL
Write-Host '[3/6] MySQL wrong password...'
$mysql = Get-Command mysql -ErrorAction SilentlyContinue
if ($mysql) {
    cmd /c "mysql -h $HostName -P 3306 -u lab_$Tag -pWrongPass_$Tag! -e `"select 1`" 2>&1" | Select-Object -First 3
} else {
    Write-Host '  mysql CLI missing — skip (install MySQL client for real probe)'
}
Start-Sleep -Seconds 2

# MSSQL
Write-Host '[4/6] MSSQL wrong password...'
$sqlcmd = Get-Command sqlcmd -ErrorAction SilentlyContinue
if ($sqlcmd) {
    cmd /c "sqlcmd -S $HostName,1433 -U lab_$Tag -P WrongPass_$Tag! -Q `"SELECT 1`" 2>&1" | Select-Object -First 3
} else {
    Write-Host '  sqlcmd missing — skip'
}
Start-Sleep -Seconds 2

# SSH (plink if available)
Write-Host '[5/6] SSH wrong password...'
$plink = Get-Command plink -ErrorAction SilentlyContinue
if ($plink) {
    echo y | plink -ssh -batch -pw "WrongPass_$Tag!" "lab_$Tag@$HostName" exit 2>&1 | Select-Object -First 3
} else {
    Write-Host '  plink missing — skip (PuTTY plink for SSH probe)'
}
Start-Sleep -Seconds 2

# RDP hint — scripted NLA fail needs credssp; note for manual mstsc
Write-Host '[6/6] RDP — use external mstsc wrong password if automated path unavailable'
Write-Host "  mstsc /v:$HostName  user=lab_$Tag  pass=WrongPass_$Tag!"

Write-Host "=== DONE $Tag - wait 15-30s then check Attacks for source $pub ==="
