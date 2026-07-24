# Cloud Honeypot Client v4.9.30

## Highlights

### Critical — tray never auto-started on this PC
Lab evidence on Windows 10/11 TR:

1. **`CloudHoneypot-Tray` task install failed** — XML had `<LogonType>Group</LogonType>`
   which `schtasks` rejects (`incorrect value LogonType:Group`). Installer deleted the
   old task first, so Tray stayed **missing** (`tray_task: false`, repeated
   `Failed to refresh CloudHoneypot-Tray`).
2. **`query session` exit code 1** with valid Active console stdout — watchdog/daemon
   treated “no interactive user” and never launched tray.

### Fixes
- Remove invalid `LogonType=Group` from Tray task principal
- `install_task`: overwrite with `/F` only (never delete-then-create)
- `has_interactive_user_session` / session id: parse stdout even when rc ≠ 0
- (from 4.9.29) supervised tray icon + watchdog relaunch when frontend missing

## Install

Silent: `cloud-client-installer.exe /S`
