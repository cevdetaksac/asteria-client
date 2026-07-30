# Asteria Client 4.9.68 — Single-flight update gate

## Why
Repeated Update now / GUI check / silent updater clicks could stack overlapping
download/install work. Dashboard and tray then showed conflicting progress, and
orphan locks left hosts stuck mid-flight.

## Fixes
- Machine-wide **operation gate** (`operation_gate.json`) for the UPDATE family
  (dashboard `self_update`, GUI, silent, interactive)
- Busy callers receive the **in-flight snapshot** (phase / %) instead of starting
  a second process
- Remote early ACK no longer reports a fresh “accepted” when an update is already
  running — it reuses the live progress
- GUI “Check for updates” surfaces the existing banner when work is in flight
- Terminal failure / timeout / operator recover clears the gate; helper handoff
  keeps `installing` until install completes or stale reclaim

## Note
Hosts on ≤4.9.67 need one successful land on 4.9.68 to get the gate.
If already stuck: use **Motoru kurtar** (clears lock + gate), then retry Update now.
