# Cloud Honeypot Client v4.9.29

## Highlights

### Tray stay-alive (logged-on session)
- Tray icon could vanish while the daemon was still fine; reopening the app
  brought it back because a new frontend started.
- Fixes:
  - Supervised tray loop (restart after crash / explorer `TaskbarCreated`)
  - GUI health check restarts a dead tray thread
  - Scheduled `--mode=watchdog` now relaunches tray when logon has no frontend
  - Close-to-tray race: no full exit while tray is still starting
  - Silent update session detect accepts Turkish `Aktif`

## Install

Silent: `cloud-client-installer.exe /S`
