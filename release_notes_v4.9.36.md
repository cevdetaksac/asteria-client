# 4.9.36 — emergency safety + account link tooling
#
## Critical
- Silent Hours no longer auto-disables or logoffs accounts (alert-only). Previous defaults
  (`auto_disable_account=True`, weekend all-day silent, Europe/Istanbul) caused false
  positives that disabled Administrator and stuck servers. **Root cause: CLIENT policy,
  not cloud IR** (cloud disable already requires `confirm:true`).
- Alert pipeline skips `disable_account` auto-actions.
- `disable_account` refuses Administrator/Guest unless `allow_privileged=True` (confirmed IR / GUI).
- Silent Hours defaults: `enabled=False`, `weekend_all_day_silent=False`.

## Ops
- `scripts/link_account_local.py` — link host via `ASTERIA_EMAIL` / `ASTERIA_PASSWORD` env (token from ProgramData).
- `scripts/reenable_administrator.ps1` — `net user Administrator /active:yes` recovery.

## Note
Blank white GUI on some interactive users usually means missing WebView2 Runtime or TEMP extract
policy — install Edge WebView2 Evergreen Runtime, then relaunch `asteria-gui.exe`.
