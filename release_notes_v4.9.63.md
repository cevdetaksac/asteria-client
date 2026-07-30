# 4.9.63 — Harden launch_helper_failed

Addresses failed updates that stop with `launch_helper_failed` (helper never wrote `update-and-install start`).

## Fixes
- Longer wait for helper log on silent/SYSTEM updates
- Prefer emergency ASCII bootstrap after launcher-only storms
- `self_update` one automatic emergency retry before failing
- Silent updates never claim success without a live helper log
