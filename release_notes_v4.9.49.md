# Asteria Client v4.9.49

## Fixes
- Empty ransomware quarantine no longer stays locked forever after VSS with no attributed writer (auto-heal on load/start + post-contain disarm).
- Shadow-copy alerts emit once (no TR + empty-title duplicate).
- After sleep/wake, persistence health uses a 180s resume grace to avoid false `agent_persistence_degraded` cloud alerts.
- `resilience_state.json` migrates polluted `version=test` and sticky `last_recovery_ok=false`.
- Threat-intel `intel_watch` / `intel_banner` events include titles.

## Notes
- Dual `asteria-client.exe` (Guardian service + Background daemon) remains intentional; only the daemon owns IPC `:58632`.
