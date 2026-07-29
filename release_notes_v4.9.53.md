# 4.9.53 — Windows Firewall MMC parity

## Contract 1.4.41
- **`list_firewall` `scope=all`** — inbound + outbound rule tables (enabled/disabled), profiles, honest `counts` + `truncated_*`.
- **`firewall_set_profile`** — Domain/Private/Public or `all`; state + default inbound/outbound; confirm-gated.
- **`firewall_rule`** — `enable` / `disable` / `delete` / `add` (delete/add require cloud `confirm:true`). Dashboard IP adds prefer `AR-MANUAL-*`.

## Notes
- Older agents (<4.9.41) keep Asteria tab + sync; Host refresh fills full rules only after this build.
- Applied Blocks / `block_ip` / `sync_firewall_rules` / `clear_firewall` unchanged.
- Future multi-OS note: `docs/LINUX_AGENT_PLAN.md`.
