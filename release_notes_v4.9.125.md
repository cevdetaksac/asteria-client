# v4.9.125

## Summary
- Incident response: logoff_session / disconnect_session / logoff_all_sessions; full emergency_lockdown (logoff all + block RDP incl. custom port + optional disable non-admins) with undo record; dry_run supported
- Network Guard: process auto_contain / auto_kill / auto_restore permanently hard-off (contract 1.4.92 Option A) — suspend only on explicit operator command
- Supervised worker threads (heartbeat, session monitor, ports, API retry) with crash restart
- CONTROL-WS: conn_health in hello (reconnect counts + last disconnect reason); SELF-PROTECT stderr NoneType fix
- Contract **1.4.92**

## Installer
WebRTC profile (same as 4.9.124 fleet).