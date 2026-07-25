# 4.9.40 — GUI module shim + full error capture

## Fixes
- **No module named `client_helpers`:** WebView host installs a Tk-free runtime
  shim before any `client_*` import (PyInstaller still excludes the real
  Tk-heavy module). Token / session / account paths no longer fail on missing
  helpers.
- Expand `asteria-gui` hiddenimports (`client_winproc`, `client_updater`,
  `client_update_ui`, `client_remote_session`, …).

## Observability
- Uncaught process + thread exception hooks → `%LOCALAPPDATA%\Asteria\logs\asteria-gui.log`
- Motor `install_excepthook` now also captures worker-thread exceptions
- Tray hide/show/menu/restart + closing-callback path fully logged
- Locked STATUS polls logged once/minute (not silent); success STATUS throttled

## Included from 4.9.39
- Tray brick fix (async hide off pywebview `closing`)
- Supervised tray revive
- Presence/WS reconnect harden
- Control Center live meters, IP panels, settings switches
