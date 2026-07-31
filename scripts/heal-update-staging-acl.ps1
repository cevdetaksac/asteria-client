# Repair ACL-bricked Asteria update staging (run elevated once).
$ErrorActionPreference = "Continue"
$u = Join-Path $env:ProgramData "Asteria\update"
New-Item -ItemType Directory -Path $u -Force | Out-Null
icacls $u /inheritance:r `
  /grant:r "NT AUTHORITY\SYSTEM:(OI)(CI)F" `
  /grant:r "BUILTIN\Administrators:(OI)(CI)F" `
  /grant:r "BUILTIN\Users:(OI)(CI)M" `
  /remove:g "Everyone" /C /Q
$probe = Join-Path $u "acl-heal-ok.txt"
Set-Content -Path $probe -Value "ok" -Encoding ASCII
Remove-Item $probe -Force -ErrorAction SilentlyContinue
# Clear sticky failed banner so GUI can retry
$ui = Join-Path $env:ProgramData "Asteria\update_ui_status.json"
if (Test-Path $ui) { Remove-Item $ui -Force -ErrorAction SilentlyContinue }
$lock = Join-Path $env:ProgramData "Asteria\update_in_progress.lock"
if (Test-Path $lock) { Remove-Item $lock -Force -ErrorAction SilentlyContinue }
Write-Host "ASTERIA_UPDATE_ACL_HEALED"
