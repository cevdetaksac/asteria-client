# 4.9.43 — Dashboard commands apply + GUI UX

## Critical: pending commands
Dashboard `tunnel_start` / `tunnel_stop` (honeypot bait) were rejected as **Unknown command**, so actions looked stuck. Client now applies them via ServiceManager and reports `commands/result` immediately.

Also fixed rate-limit defer that could leave a command_id in the seen-cache **without ACK** (pending forever), sped HTTP safety poll (5s) and honeypot desired-state reconcile (15s), and GUI STATUS refresh (~1.5–2s) after apply.

## GUI UX
- Centered tooltips above icon actions; table row separators; IR info tip; overflow clip.

## Install
Use `asteria-client-installer.exe` (legacy alias `cloud-client-installer.exe` still published for self-update).
