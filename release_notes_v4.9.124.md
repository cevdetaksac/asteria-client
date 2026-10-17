# v4.9.124

## Summary
- CONTROL-WS: disconnects now logged at WARNING with reason/type (were hidden at INFO)
- Reconnect uses jittered exponential backoff (avoids fleet-wide reconnect storms)
- Offline urgent queue: health `enabled` uses the same gate as the queue itself
- Contract **1.4.91** (incident response UI in dashboard: Contain user, Disable all users, Emergency lockdown with typed confirmation)

## Installer
WebRTC profile (same as 4.9.123 fleet).