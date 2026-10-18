#Requires -Version 5.1
<#
.SYNOPSIS
  Publish an Asteria Client GitHub release with BOTH installer asset names.

  Older agents (pre-4.9.138) only accept assets whose name ends with
  ``installer.exe``. Versioned names like ``asteria-client-installer-4.9.137.exe``
  fail that check. Always upload:
    1. asteria-client-installer-<ver>.exe   (canonical, versioned)
    2. asteria-client-installer.exe         (identical bytes — fleet-safe alias)

.EXAMPLE
  .\scripts\release.ps1 -Version 4.9.138
  .\scripts\release.ps1 -Version 4.9.138 -InstallerPath .\asteria-client-installer.exe
#>
param(
  [Parameter(Mandatory=$true)][string]$Version,
  [string]$InstallerPath = ".\asteria-client-installer.exe",
  [string]$Title = "",
  [string]$Notes = ""
)
$ErrorActionPreference = "Stop"
$Version = $Version.TrimStart("v")
if (-not (Test-Path $InstallerPath)) { throw "Installer not found: $InstallerPath" }
$sha = (Get-FileHash $InstallerPath -Algorithm SHA256).Hash
$verName = "asteria-client-installer-$Version.exe"
$aliasName = "asteria-client-installer.exe"
$stage = Join-Path $env:TEMP "asteria-release-$Version"
New-Item -ItemType Directory -Force $stage | Out-Null
$verPath = Join-Path $stage $verName
$aliasPath = Join-Path $stage $aliasName
Copy-Item $InstallerPath $verPath -Force
Copy-Item $InstallerPath $aliasPath -Force
if ((Get-FileHash $aliasPath -Algorithm SHA256).Hash -ne $sha) { throw "hash mismatch after copy" }
if (-not $Title) { $Title = "v$Version" }
if (-not $Notes) { $Notes = "Asteria Client $Version`n`nSHA256: $sha`nAssets: $verName + $aliasName (identical bytes; alias keeps pre-4.9.138 updaters working)." }
$tag = "v$Version"
Write-Host "Creating release $tag ..."
gh release create $tag $verPath $aliasPath --target main --title $Title --notes $Notes
Write-Host "OK $tag SHA256=$sha"