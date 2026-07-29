# 4.9.57 — GUI loading honesty

Fixes misleading Off / “data failed” flashes while the Control Center is still refreshing.

## Behavior
- Layer / NetGuard / ransomware toggles show an indeterminate **loading** state until STATUS is known
- Last known status is kept during background polls (no Off flash on every 2s tick)
- Soft “Durum güncelleniyor…” vs hard motor-unreachable banner
- Threat tables, Honeypot cards, and Settings switches wait for load before empty/fail copy

## Installer
- Upload **both** `asteria-client-installer.exe` and `cloud-client-installer.exe`.
