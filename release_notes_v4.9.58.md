# 4.9.58 — Easy port relocate (`relocate_service`)

## Client contract
Dashboard easy-port moves now land as **`relocate_service`** (client ≥4.9.44 intent, shipped here):

1. Capture **golden** listen port (registry)
2. **Stop** SCM service
3. **Write** new port config
4. **Start** service
5. **Bind verify** (TCP accept on `127.0.0.1:port`)
6. On failure → **golden rollback** (restore prior port + restart)

## Scope
- Built-in: **RDP / TermService** (`HKLM\...\RDP-Tcp\PortNumber`)
- Advanced: explicit `scm` + `registry_path` + `registry_value`
- Confirm-gated + IR-urgent (same class as `network_adapter_apply`)

## Params (summary)
`service` / `service_name`, `port`, optional `from_port`, `verify_sec` (3–30), `ensure_firewall`, `on_fail=restore_golden`
