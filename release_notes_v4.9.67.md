# Asteria Client 4.9.67 — Unstick self_update at 0%

## Why
Dashboard showed **Command received — updating…** with **0% / 0 B** while the
host stayed online (e.g. Derin-Web 4.9.65 → 4.9.66). Download never visibly
moved.

`trust metadata pending` on the resilience card is **cloud observe UI** (null
signing fields) — it does **not** block client download.

Likely client wedges:
1. Progress ticks used **sync** `commands/result` on a shared `requests.Session`
   while heartbeat + download raced → session hang at 0%
2. Sync lifecycle `self_update_begin` blocked the download path
3. Missing URL preferred GitHub API before constructing the release asset URL

## Fixes
- Progress ticks posted on a **daemon thread** (never block the download loop)
- `AsteriaAPIClient` serializes `api_request` with an `RLock`
- Lifecycle begin is fire-and-forget
- Constructed GitHub asset URL runs **before** GitHub API when tag is known
- Download emits `connecting` / `headers_received` phases so UI leaves 0 B ASAP

## Note
Hosts still on 4.9.65 need one successful land on 4.9.67 to get this path.
If stuck mid-flight: dismiss/retry Update now, or clear orphan update lock via
Motoru kurtar if the banner is stuck.
