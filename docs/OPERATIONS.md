# Operations Guide

## Shared contract

API / agent behavior SoT: [honeypot-contract](https://github.com/cevdetaksac/honeypot-contract) (`VERSION` ≥ **1.4.25**, [`FLEET.md`](https://github.com/cevdetaksac/honeypot-contract/blob/main/FLEET.md)).

## Build & Release

```powershell
cd cloud-client
.\build.ps1 -Clean -WebRTC   # production profile (~69 MB)
# or: .\build.ps1 -Clean     # JPEG/WS only
```

Artifact: `cloud-client-installer.exe` (repo root, not `dist\`).

```powershell
gh release create vX.Y.Z cloud-client-installer.exe --title "vX.Y.Z" --notes-file release_notes_vX.Y.Z.md
```

Repo: `cevdetaksac/yesnext-cloud-honeypot-client`.

## Windows Defender / AV

- Submit installer to [Microsoft Defender portal](https://www.microsoft.com/en-us/wdsi/filesubmission)
- Reference `DEFENDER_MARKERS` in `client_constants.py`
- Prefer Authenticode (`build.ps1 -Sign`) for production

## SIEM / logs

1. **Cloud API** — urgent/batch alerts — contract `agent/threat-engine.md`
2. **Optional webhook** — `notifications.webhook_url` in `client_config.json`
3. **Local logs** — `%ProgramData%\YesNext\CloudHoneypotClient\` (`client-*.log`, `threats-*.log`, `lifecycle-*.log`); ~7-day retention

## Token rotation

If a log with a token was exposed:

1. Revoke token in the dashboard
2. Delete `%ProgramData%\YesNext\CloudHoneypotClient\token.dat`
3. Restart the client to re-register

## Fleet defaults

- `Authorization: Bearer` — agent must not rely on `?token=` query
- Command HMAC — `security.command_signing` (default true) — `api/03-control-websocket.md`
- Destructive IR — cloud dashboard confirmation

## Linux

`client_firewall.py` supports Linux (ipset/iptables). Honeypot decoys and full agent are Windows-focused; Linux path is firewall-oriented today.
