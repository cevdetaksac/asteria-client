# 4.9.60 — Service Port Relocate close-out (1.4.45)

Closes gaps vs published `agent/service-port-relocate-client.md`.

## Fixes
- Read **`target_port`** from dashboard `relocate_service` params
- **Golden on disk** before mutate (C-REL-2); cleared on success
- Pre-check **target free**; reject privileged `<1024` and other services’ classic ports (C-REL-6/7)
- Firewall rule **`AR-RELOCATE-<SVC>-<PORT>`**; removed on rollback (C-REL-5)
- Rollback ACK: `status:"rollback"`, `reason:"bind_verify_failed"`, `target_port`
- GUI: relocated / relocating badges + busy / `port_available` hints

FTP remains unsupported in GUI (allowed by contract).
