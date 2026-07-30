# 4.9.62 — Update brick harden (orphan lock / recover)

Fixes sticky failure banners and blocked upgrades seen on older hosts (e.g. 4.9.54 → 4.9.61).

## Fixes
- Preempt stuck/`orphan_lock_dead_or_foreign_pid` locks before `self_update` (even without `force`)
- **Motoru kurtar** clears the failed banner when the motor is healthy again (no sticky `operator_recover`)
- Orphan lock clear resumes tasks and restarts the motor when it was down
