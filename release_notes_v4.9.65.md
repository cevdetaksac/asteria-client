# Asteria Client 4.9.65 — Quiet logs (no more INFO flood)

## Why
Live check showed healthy RAM (~40–70 MB motor / GUI) but today's
`client-YYYY-MM-DD.log` already ~4 MB from INFO spam:
- Full `premium/tunnel-status` JSON every ~15s (endpoint missing from quiet list)
- `[HEALTH] processes collected` every cycle
- Idle `[FW-SYNC] pending_*=0` every poll

Not a classic heap leak — disk / I/O "infinite log" class.

## Fixes
- Quiet API defaults: `verbose_logging=False`; expand frequent endpoints
  (`premium/tunnel-status`, open-ports, events/batch, …); truncate rare bodies
- Throttle HEALTH / idle FW-SYNC INFO lines
- Honor `LOG_MAX_BYTES` / threat log max via within-day `.N` rollover
- Honeypot credential lines only after rate-limit; passwords redacted as `***`
- GUI: `RotatingFileHandler` + cleanup stale `_MEI*` extract dirs

## Verify
- After install: log growth ≪ previous (~KB/hour idle, not MB)
- STATUS `motor_ok`; Working set stable over 10+ minutes
