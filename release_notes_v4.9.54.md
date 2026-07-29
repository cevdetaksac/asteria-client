# 4.9.54 — Firewall MMC parity + Network Adapter Admin

Ships contract **1.4.40–1.4.42** client close-out (since 4.9.51).

## Network Adapter Admin (1.4.42)
- **`network_adapter_apply`** — `enable` / `disable` / `set_ipv4` / `set_dns` / `set_config`
- Local watchdog (5–15s): bad apply → golden restore for that adapter (`WATCHDOG_ROLLBACK`)
- `LAST_MGMT_ADAPTER`, `NO_GOLDEN` / `GOLDEN_UNHEALTHY`; pauses `auto_restore_network` mid-apply
- Optional `on_success=accept_surface`

## Firewall Windows MMC parity (1.4.41)
- **`list_firewall` `scope=all`** — full inbound/outbound + profiles + truncation/counts
- **`firewall_rule`** — enable / disable / delete / add (`AR-MANUAL-*`)
- **`firewall_set_profile`** — Domain/Private/Public/`all`

## Firewall Management (1.4.40)
- Asteria inventory path (`list_firewall` / profile set) kept as degraded scope

## Docs
- Future Linux/macOS agent plan: `docs/LINUX_AGENT_PLAN.md`

## Installer
- Upload **both** `asteria-client-installer.exe` and `cloud-client-installer.exe` (legacy ≤4.9.40 self-update fallback).
