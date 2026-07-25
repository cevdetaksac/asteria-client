# Asteria Client v4.9.35

## Highlights
- **Signing cutover (contract ≥1.4.32):** Command HMAC `asteria-chp-v1`, heartbeat `asteria-heartbeat-v1` (legacy `yesnext-*` still accepted on verify).
- **API rename:** `AsteriaAPIClient` (compat alias `HoneypotAPIClient`).
- **Web Control Center:** Account link/unlink, WinRM/NLA/Defender harden, RDP move, IR logoff/disable, update banner, TR/EN i18n.
- **Brand identity:** Bruno Ace wordmark, logo_set `*_light` for dark UI, tray/installer/exe icons from `logo_set`.
- **GUI bridge harden:** Wait for pywebview API readiness; themed password reveal; fixed sidebar nav heights.

## Install
Run `cloud-client-installer.exe` as Administrator.

## Notes
- Dual-track: `asteria-client.exe` (SYSTEM motor) + `asteria-gui.exe` (interactive WebView).
- Wire ProgramData / task names unchanged (`YesNext\CloudHoneypotClient`, `CloudHoneypot-*`).
