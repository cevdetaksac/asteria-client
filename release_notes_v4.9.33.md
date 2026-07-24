# Cloud Honeypot Client v4.9.33

## Asteria firewall prefix migration

- New firewall blocks are written only as `AR-BLOCK-{ip}`.
- Threat-intel rules are written only as `AR-INTEL-{id}`.
- Unblock, whitelist enforcement, and firewall cleanup remove AR, HP, HONEYPOT,
  and CloudHoneypot legacy rules.
- On first boot, existing `HP-BLOCK-*` and `HP-INTEL-*` rules are migrated
  in-place to AR names, followed by `sync-rules` snapshot reporting.
- Migration is marked complete only after a successful cloud sync.

Contract: **1.4.31** · Minimum client: **4.9.33**
