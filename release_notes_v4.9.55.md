# 4.9.55 — Remote console parity (contract 1.4.43)

Closes client acceptance for dashboard **Logon ekranı** / physical-console UX.

## Winlogon / console capture
- Omit `session_id` → resolve with `WTSGetActiveConsoleSessionId` (never hardcode SID 1)
- Winlogon Start never binds username
- Strict named `WinSta0\Winlogon` attach (no silent Default while claiming Winlogon)
- After logon, stream follows input desktop → Default without a second Start
- Sustained `gdi+black` on Winlogon path still fails honestly

## CAD
- `remote_send_sas` targets the live stream / console session and attaches Winlogon before SendSAS

## Health
- Logon / Lock `pre_logon:true` sibling row remains always present

## Installer
- Upload **both** `asteria-client-installer.exe` and `cloud-client-installer.exe` (legacy ≤4.9.40 self-update fallback).
