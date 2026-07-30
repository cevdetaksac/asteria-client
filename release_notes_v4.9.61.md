# 4.9.61 — Self-update progress ticks (1.4.46)

Dashboard update bar advances while the agent downloads/installs.

## Changes
- `self_update` posts mid-flight `commands/result` ticks: `phase`, `progress_pct`, `bytes_done` / `bytes_total`
- Cadence every 2–3s (immediate on phase change); no >5s silence while `running`
- Terminal: `message:update_started`, `phase:installing`, `restart_required`
