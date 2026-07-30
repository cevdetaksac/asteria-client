# Asteria Client 4.9.64 — Clean start (legacy purge + single tray owner)

## Why
Task Manager often showed two `asteria-client.exe` (SYSTEM) and two `asteria-gui.exe`.
Dual SYSTEM clients are usually **daemon + AsteriaGuardian** (intentional). Dual GUI
is often PyInstaller onefile parent+child (also normal). Real bugs remained:
incomplete YesNext leftovers, Guardian resurrecting motor mid-update kill, and
helper+daemon both starting tray after silent update.

## Fixes
- **Legacy purge**: `remove-legacy-install.ps1` now removes `YesNext\CloudClient`,
  `ProgramData\YesNext`, leftover vendor leaf dirs, and per-user `AppData\YesNext`.
- **Guardian stop**: `update-and-install.ps1` / `kill-honeypot.ps1` stop+delete
  `AsteriaGuardian` before kill rounds so it cannot resurrect motor mid-wipe.
- **Single tray owner**: silent update skips helper `Asteria-Tray` when the new
  motor is ready (or GUI already running); daemon/`--create-tasks` owns handoff.
- **GUI mutex**: session-scoped `Global\AsteriaClient_GUI_s{N}` shared by motor and
  `asteria-gui` (crosses integrity levels); CreateMutex failure is fail-closed.

## Verify
- Task Manager: 1× `asteria-client --mode=daemon` + 1× `--mode=guardian` + GUI
  parent/child pair for onefile is OK.
- No `C:\Program Files (x86)\YesNext\CloudClient`, no `C:\ProgramData\YesNext`.
- After silent self-update: one interactive tray, motor `:58632` healthy.
