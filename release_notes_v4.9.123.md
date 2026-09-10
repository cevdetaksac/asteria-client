# v4.9.123

## Summary
- Auto-prep MySQL/MariaDB `log_error_verbosity=3` on install/boot so AuthLog sees Access denied
- AuthLog path discovery: my.ini + MSSQL registry; skip slow logs; health hints
- Contract **1.4.90**

## Ops
- Opt-out: `ASTERIA_SKIP_MYSQL_AUTHLOG_PREP=1`
- Backup: `my.ini.asteria.bak` next to each patched ini
- MySQL service restarted only when ini actually changes

## Installer
WebRTC profile (same as 4.9.122 fleet).
