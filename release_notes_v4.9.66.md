# Asteria Client 4.9.66 — Fix remote `launch_helper_failed`

## Why
Dashboard showed download complete (113.6/113.6 MB @ 95%) then
`self_update_failed: launch_helper_failed` (e.g. Derin-Web on **v4.9.61**).

Root causes:
1. **Chicken-egg**: hosts on ≤4.9.61 lack the stronger helper waits/retry; they
   cannot self-heal until one successful install lands newer code.
2. **schtasks /TR overflow**: last-resort Method 6 put `-InstallerPath ...` on the
   task action line (~276 chars > legacy **261** limit) → silent create failure.
3. Emergency bootstrap only tracked legacy `honeypot-client` and did not stop
   `AsteriaGuardian` — motor could resurrect mid-kill.

## Fixes
- Method 6: embed installer args inside the `.ps1`; keep `/TR` short
- Method 7: direct NSIS `/S` via short schtasks + log marker
- Do not delete UpdateOnce tasks immediately on slow start (extra wait / re-run)
- Emergency bootstrap: stop Guardian, kill `asteria-client`/`asteria-gui`
- Longer helper waits; progress tick 98% when helper is live

## Fleet note
Hosts still on **4.9.61** need **one** successful install (RDP `/S` of the already
downloaded installer, or local GUI update) to pick up 4.9.66+. After that, remote
`self_update` uses the hardened launcher.
