# Cloud Honeypot Client v4.9.26

## Highlights

### Remote Desktop — Winlogon / Logon screen
- `list_sessions` / health always offer a **Logon / Lock screen** (`pre_logon`) row (sibling of console user when logged on).
- `remote_stream_start` accepts `prefer=winlogon` / `desktop=winlogon` / `pre_logon=true`.
- Named Winlogon attach before OpenInputDesktop; hello capabilities `winlogon` / `pre_logon`.

### Self-update download completion
- Success only when transfer is complete (Content-Length + PE MZ + min size) — not wall-clock timeout.
- Stall timeout for idle sockets only; up to **5** retries with backoff; then launch installer.

### Server users (contract 1.4.22)
- `list_local_users` includes disabled accounts with `status` / `can_enable` / `can_disable` / `counts`.
- `enable_account` / `disable_account` return refreshed `data.user` for cloud toggle UI.

### GUI / account
- Defense policy banner + buttons refresh with active mode (no stale “Yalnız bildir” after Balanced).
- **Settings → Account link**: status, link, unlink, My servers (contract 1.4.23 `unlink-account`).

## Install

Silent: `cloud-client-installer.exe /S`
