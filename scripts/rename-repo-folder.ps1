# Rename local source folder cloud-client → asteria-client.
# Close Cursor / any process using the folder, then run from parent:
#   powershell -ExecutionPolicy Bypass -File .\cloud-client\scripts\rename-repo-folder.ps1
# Or from honeypot-cloud after close:
#   Rename-Item cloud-client asteria-client

$ErrorActionPreference = "Stop"
$parent = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$src = Join-Path $parent "cloud-client"
$dst = Join-Path $parent "asteria-client"

if (-not (Test-Path $src)) {
    if (Test-Path $dst) {
        Write-Host "Already renamed: $dst"
        exit 0
    }
    throw "Source not found: $src"
}
if (Test-Path $dst) {
    throw "Destination already exists: $dst"
}

Rename-Item -LiteralPath $src -NewName "asteria-client"
Write-Host "Renamed to $dst"
Write-Host "Re-open Cursor workspace at that path."
