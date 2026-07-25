# 4.9.41 — Asteria brand paths, installer rename, uninstall fix

## Brand / wire identity
- Durable state lives under `%ProgramData%\Asteria\` (YesNext trees copied once on first run / install).
- Scheduled tasks: `Asteria-Background|Tray|Watchdog|Updater|SilentUpdater|MemoryRestart`.
- Service: `AsteriaGuardian`; self-protect: `AsteriaClientGuard`; mutex/events: `AsteriaClient_*`.
- Install/uninstall still purge legacy `CloudHoneypot-*` / `HoneypotClient*` / `CloudHoneypotGuardian`.

## Installer
- Primary asset: `asteria-client-installer.exe`.
- Releases also publish identical `cloud-client-installer.exe` so agents ≤4.9.40 (hardcoded fallback name) can self-update.
- Self-update tries Asteria name first, then legacy.
- Uninstaller embeds kill helper, stops `asteria-gui.exe` + motor, deletes with `/REBOOTOK`, wipes `$INSTDIR`.

## Control Center
- Dashboard + Refresh moved into Help menu; account chip opens dashboard.
- Lock screen: square logo, PIN-first layout; dashboard deep-links (contract 1.4.35).

## Included from 4.9.40
- GUI `client_helpers` shim + exception capture
- Tray brick fix and Control Center UX from 4.9.39
