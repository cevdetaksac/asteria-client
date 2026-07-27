# 4.9.48 — Stream progress + update brick recovery

## Remote Desktop (contract 1.4.39)
- Agent emits `stream_progress` on RD WS: `running` → `capture_start` → `capturing` → `ws`/`webrtc` → `live` (or `failed` + error)
- Heartbeat ≤3s while starting; ≤4 events/s; no `live` for black-fill-only frames
- Also covers `remote_session_prepare`

## Update brick recovery
- Orphan `update_in_progress.lock` now resumes Background tasks, clears stand-down, marks banner failed
- Auto-recover in `ensure_daemon_running` / heal / GUI ping
- GUI: **Motoru kurtar** on stalled update / motor unreachable

## Install
`asteria-client-installer.exe` (+ legacy `cloud-client-installer.exe` alias).
