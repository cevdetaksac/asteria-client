# Operations Guide

## Shared contract

API / agent behavior SoT: [honeypot-contract](https://github.com/cevdetaksac/honeypot-contract) (`VERSION` ≥ **1.4.26**, [`FLEET.md`](https://github.com/cevdetaksac/honeypot-contract/blob/main/FLEET.md)).

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

## Clone / shared token (two IPs, one token)

**Symptom:** Two hosts (different public IPs) show the same agent token and often
the same Windows hostname — usually an unsysprep’d VM/golden-image clone that
copied `MachineGuid` and/or `token.dat`. Account link follows the token, so both
appear under the same email.

**Fix (client ≥ 4.9.28):** Upgrade both hosts. Each performs a one-time hardware
fingerprint re-enroll (`MachineGuid` + NIC MACs + SMBIOS). Confirm tokens differ,
then **Settings → Account link** on each server.

**Manual reset (any version):** elevated

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File "C:\Program Files\YesNext\Cloud Honeypot Client\scripts\reset-agent-identity.ps1" -AlsoKill
```

(If the script is not installed yet, run it from the repo `cloud-client\scripts\`.)
Also rename the hostname if both still show the same `WIN-*` name; prefer sysprep
`/generalize` before sealing templates. Never bake `token.dat` into images.

## Fleet defaults

- `Authorization: Bearer` — agent must not rely on `?token=` query
- Command HMAC — `security.command_signing` (default true) — `api/03-control-websocket.md`
- Destructive IR — cloud dashboard confirmation

## Linux

`client_firewall.py` supports Linux (ipset/iptables). Honeypot decoys and full agent are Windows-focused; Linux path is firewall-oriented today.
