# Cloud Honeypot Client v4.9.32

## Highlights

### In-place token rotation (contract **1.4.29**)
- Rekey / identity v2 / fingerprint rebind no longer calls bare `POST /api/register`
  while the old token is known (that created **ghost** Client rows and broke history).
- Flow: mint `new_token` in memory → `POST /api/agent/rotate-token` → **only on 200**
  write `token.dat` (CHP2) + `device_binding.json`.
- Same `client_id` — attacks, alerts, blocks, AccountClient, alias preserved.
- `409 new_token_in_use` → one retry with a fresh uuid; `403 machine_id_mismatch`
  tries fingerprint / omit / MachineGuid; failed rotate quarantines then register.

## Install

Silent: `cloud-client-installer.exe /S`
