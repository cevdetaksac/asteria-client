# v4.9.126

## Summary
- **Hotfix:** include `client_supervisor` and `client_ir` in PyInstaller `hiddenimports`.
  4.9.125 crash-looped the daemon (`No module named 'client_supervisor'`) because those
  modules were only lazy-`__import__`ed and never collected into the PYZ.
- Inherits 4.9.125 Phase 2: IR sessions/full lockdown+undo, Network Guard Option A
  (auto_contain permanently hard-off; suspend only on explicit operator command;
  contract **1.4.92**), supervised workers, CONTROL-WS conn_health.

## Installer
WebRTC profile (same as 4.9.124/4.9.125 fleet). Unsigned, matching prior fleet releases.
