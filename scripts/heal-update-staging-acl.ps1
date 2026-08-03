# Repair ACL-bricked Asteria update staging (run elevated once).
$ErrorActionPreference = "Continue"
$u = Join-Path $env:ProgramData "Asteria\update"
New-Item -ItemType Directory -Path $u -Force | Out-Null
takeown /F $u /R /D Y 2>$null | Out-Null
icacls $u /inheritance:r `
  /grant:r "NT AUTHORITY\SYSTEM:(OI)(CI)F" `
  /grant:r "BUILTIN\Administrators:(OI)(CI)F" `
  /grant:r "BUILTIN\Users:(OI)(CI)M" `
  /remove:g "Everyone" /C /Q
Get-ChildItem -LiteralPath $u -Force -ErrorAction SilentlyContinue | ForEach-Object {
  try { takeown /F $_.FullName /A 2>$null | Out-Null } catch {}
  try {
    icacls $_.FullName /inheritance:e `
      /grant:r "NT AUTHORITY\SYSTEM:F" `
      /grant:r "BUILTIN\Administrators:F" `
      /grant:r "BUILTIN\Users:M" /C /Q | Out-Null
  } catch {}
}
$helper = Join-Path $u "update-and-install.ps1"
if (Test-Path -LiteralPath $helper) {
  try { attrib -R $helper } catch {}
  try { takeown /F $helper /A | Out-Null } catch {}
  try {
    icacls $helper /grant:r "BUILTIN\Administrators:F" /grant:r "BUILTIN\Users:M" /C /Q | Out-Null
  } catch {}
  Remove-Item -LiteralPath $helper -Force -ErrorAction SilentlyContinue
}
$probe = Join-Path $u "acl-heal-ok.txt"
Set-Content -Path $probe -Value "ok" -Encoding ASCII
Remove-Item $probe -Force -ErrorAction SilentlyContinue
$ui = Join-Path $env:ProgramData "Asteria\update_ui_status.json"
if (Test-Path $ui) { Remove-Item $ui -Force -ErrorAction SilentlyContinue }
$lock = Join-Path $env:ProgramData "Asteria\update_in_progress.lock"
if (Test-Path $lock) { Remove-Item $lock -Force -ErrorAction SilentlyContinue }
Write-Host "ASTERIA_UPDATE_ACL_HEALED exists_helper=$(Test-Path $helper)"
