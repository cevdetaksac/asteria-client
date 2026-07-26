# 4.9.45 — Contract 1.4.37 client close-out

## Envelope v2 (observe-only)
- RFC 8785 JCS + Ed25519 observe verify (`api/12`); golden fixture from contract seed.
- Wire: parse/log only — never emit `version:2`, never hard-fail v1 HMAC commands.
- Cap: `caps.command_envelope_v2` = `off` | `observe` (default off).

## Fleet canary (C-CANARY-1…5)
- Read `fleet_rollout.gates` on every threats/config apply; fail-closed if missing.
- Auto actions require **gate AND** local/config enable (silent hours, NG contain, isolate, offline queue).
- Process-memory only (no durable true-gate cache). Health/report echoes `fleet_rollout`.

## Offline urgent queue
- Enable only when `security.offline_urgent_queue` **and** canary gate true (still default off / PROMOTION_GATES).

## Remote Desktop P0
- Winlogon black: surface `black_frame`; sustained GDI black ≥2s → `winlogon_capture_black`.
- ICE honesty: no `connected` until ICE+DTLS; JPEG fallback stays active until media verified; clear connected on fail.

## Dual-brand sunset
- Docs/comments: legacy HMAC/host cutover target **2026-10-01**; primary `asteria.run` / `asteria-chp-v1` unchanged; legacy verify kept until sunset.

## Install
`asteria-client-installer.exe` (+ legacy `cloud-client-installer.exe` alias).
