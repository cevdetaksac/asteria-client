# 4.9.52 — Firewall Management inventory

## Contract 1.4.40
- **`list_firewall`** — Domain/Private/Public profiles + Asteria-prefixed inbound rules (`AR-BLOCK` / `AR-INTEL` / `HP-*` / `HONEYPOT`) including disabled + counts (`inbound_block`, `total_rules`).
- **`firewall_set_profile`** — change one profile state/inbound/outbound (dashboard `confirm:true`); returns a fresh inventory snapshot.

## Notes
- Cloud Firewall Yönetimi page already ships; old clients keep cloud mirror + sync, full inventory needs ≥4.9.40.
- Existing `block_ip` / `unblock_ip` / `clear_firewall` / `sync_firewall_rules` unchanged.
