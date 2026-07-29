# 4.9.59 — Service Port Relocate (contract 1.4.45)

Builds on 4.9.58 `relocate_service` with bidirectional sync + client GUI.

## Command
- Flow: **golden → firewall → config → restart → ≤10s verify → local rollback**
- Success result: `{ status:"ok", service, old_port, new_port }`
- Failure/rollback: command failed + `status:"rollback"` + `reason`
- Single in-flight relocate; forbid targets **53389** and **9XXXX**

## Defaults (4XXXX)
| Service | Safe port |
|---------|-----------|
| RDP | 43389 |
| MSSQL | 41433 |
| MYSQL | 43306 |
| SSH | 40022 |
| FTP | 40021 |

## GUI
- Services page **Kolay Port Taşıma** card
- Prefill: `GET /api/premium/tunnel-status` → `relocate_state.<SVC>.saved_target_port || default_safe_port`
- After local run: `POST /api/agent/relocate-report` (`source:"gui"`) + open_ports refresh ≤5s
