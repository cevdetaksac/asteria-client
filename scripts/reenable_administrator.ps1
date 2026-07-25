# Re-enable local Administrator after false-positive silent-hours auto-disable.
# Run elevated (Administrator PowerShell):
#   powershell -ExecutionPolicy Bypass -File scripts\reenable_administrator.ps1

$ErrorActionPreference = 'Continue'
Write-Host "Re-enabling local Administrator account..."
net user Administrator /active:yes
if ($LASTEXITCODE -eq 0) {
  Write-Host "OK: Administrator is active."
} else {
  Write-Host "FAILED: net user exit=$LASTEXITCODE (need elevated shell? account renamed?)"
  exit $LASTEXITCODE
}
