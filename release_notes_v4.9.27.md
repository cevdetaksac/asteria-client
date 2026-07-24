# Cloud Honeypot Client v4.9.27

## Highlights

### Installer — FileInUse on `memory_restart.ps1`
- Upgrade no longer pops NSIS Abort/Retry/Ignore when Scheduled Task PowerShell holds `scripts\memory_restart.ps1`.
- `prepare-install-dir.ps1` relocates the whole `scripts\` tree (and kills PowerShell whose command line references install helpers).
- `memory_restart.ps1` is staged via `install-memory-restart.ps1` (rename + retry copy) — never via NSIS `File` (no dialog).
- Main extract uses `SetOverwrite try` so residual AV/handle races skip silently instead of Abort.

## Install

Silent: `cloud-client-installer.exe /S`
