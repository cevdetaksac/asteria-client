# Asteria Client v4.9.34

## Asteria brand cutover

- Product display name is **Asteria** (GUI, tray, installer, Start Menu).
- Default API: `https://asteria.run/api` with legacy failover to
  `https://honeypot.yesnext.com.tr/api`.
- New install path: `Program Files\Asteria\Asteria Client\`
- Primary exe: `asteria-client.exe` (still kills/probes legacy
  `honeypot-client.exe`).

## Unchanged wire identities

- ProgramData: `%ProgramData%\YesNext\CloudHoneypotClient`
- Scheduled tasks: `CloudHoneypot-*`
- Command signing: `yesnext-chp-v1`

Contract: **1.4.30+** · Firewall brand: **1.4.31** (`AR-*`)
