# 4.9.38 — brick prevention + durable identity / legacy token remap

## Brick prevention (C-BRICK)
- **C-BRICK-1:** Local critical auto (`disable_account` / auto logoff) requires fresh `account_linked` (cache ≤15 min). Skip + alert `skipped_unlinked`.
- **C-BRICK-2:** Silent hours / time rules default OFF; cloud cannot force silent-hours auto disable/logoff.
- **C-BRICK-6:** Refuse disable of the last enabled local admin; rollback if zero admins remain.
- **Wire:** `commands/result.status` = completed/failed… only; SAM active/disabled only in `result.data`.

## Token persistence (disconnect / ghost Client)
- Rotate failure (5xx/timeout) **keeps** `token.dat` — no quarantine + bare `/register`.
- Schema / CHP2 upgrades **rewrap** locally; cloud rotate only when intentionally rekeying.
- Fingerprint drift on the **same** MachineGuid refreshes the envelope; ambiguous clones refuse auto re-register.
- Unreadable `token.dat` is never overwritten by migrate/save without explicit overwrite.

## Legacy token → cloud remap (1.4.29)
- On boot, leftover AppData/SYSTEM/install tokens that differ from ProgramData are reported via
  `POST /api/agent/rotate-token` (`old_token` → `new_token`, reason `legacy_supersede`) so the
  server can update that Client row onto the durable token (attacks / Account link preserved).
- After 200 or 404, the leftover file is moved aside.

## GUI
- Top bar identity strip: hostname + masked token preview + copy (full token stays on host).
- Account chip / PIN re-auth for link-unlink (from 4.9.37).
