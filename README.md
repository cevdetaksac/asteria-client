# Cloud Honeypot Client

**Current Version: 4.9.28**

Windows agent for [YesNext Cloud Honeypot](https://honeypot.yesnext.com.tr): honeypot tunnels, threat response, remote desktop, and firewall sync. Open-source client; cloud/dashboard features may require a license.

| | |
|--|--|
| **Releases** | https://github.com/cevdetaksac/yesnext-cloud-honeypot-client/releases |
| **Latest installer** | [cloud-client-installer.exe](https://github.com/cevdetaksac/yesnext-cloud-honeypot-client/releases/latest/download/cloud-client-installer.exe) |
| **Changelog** | [`docs/CHANGELOG.md`](docs/CHANGELOG.md) |
| **API contract (SoT)** | https://github.com/cevdetaksac/honeypot-contract (`VERSION` ≥ **1.4.25**) |
| **Production floor** | Client ≥ **4.9.0** (see contract [`FLEET.md`](https://github.com/cevdetaksac/honeypot-contract/blob/main/FLEET.md)) |

## Features

- **Honeypot tunnels** — selected service ports over TLS to the cloud
- **Threat / defense policy** — observe → balanced → paranoid; ransomware shield, canaries, Network Guard
- **Remote Desktop** — JPEG/WS + WebRTC; Winlogon / pre-logon mirror (≥4.9.21+)
- **Server management** — sessions, processes, services, local users (enable/disable)
- **Firewall agent** — applies `HP-BLOCK-*` rules from the dashboard
- **Self-update** — GitHub Releases; completion-verified download + retries
- **Tray / GUI** — TR/EN; account link in Settings

## Install (Windows)

1. Download `cloud-client-installer.exe` from the [latest release](https://github.com/cevdetaksac/yesnext-cloud-honeypot-client/releases/latest).
2. Run as Administrator (`/S` for silent).
3. Agent registers with the cloud API and stores the token under ProgramData.

API base (default): `https://honeypot.yesnext.com.tr/api`

## Build

Requirements: Python 3.11/3.12, pip, PyInstaller, NSIS.

```powershell
# Default (JPEG / WS)
powershell -ExecutionPolicy Bypass -File build.ps1 -Clean

# Release profile with WebRTC / H.264 (~69 MB installer)
python -m pip install -r requirements-webrtc.txt
powershell -ExecutionPolicy Bypass -File build.ps1 -Clean -WebRTC
```

Output: `cloud-client-installer.exe` (repo root). Optional Authenticode: `-Sign`.

## Release

```powershell
.\build.ps1 -Clean -WebRTC
gh release create vX.Y.Z cloud-client-installer.exe --title "vX.Y.Z" --notes-file release_notes_vX.Y.Z.md
```

- Version: `VERSION` in `client_constants.py` (single source of truth)
- Full history: `docs/CHANGELOG.md`
- Per-tag notes: `release_notes_v*.md` (for `gh release`)

## Docs

| Doc | Purpose |
|-----|---------|
| [`docs/CHANGELOG.md`](docs/CHANGELOG.md) | Client release history |
| [`docs/OPERATIONS.md`](docs/OPERATIONS.md) | Build / ops notes |
| [`docs/SECURITY.md`](docs/SECURITY.md) | Security reporting |
| [`contract/README.md`](contract/README.md) | Pointer to honeypot-contract |
| [`AGENTS.md`](AGENTS.md) | Cursor / agent reading order |

Local `docs/api/*` files are **stubs** — edit behavior only in [honeypot-contract](https://github.com/cevdetaksac/honeypot-contract).

## Security

Report vulnerabilities privately via [`SECURITY.md`](SECURITY.md) — not public issues.

## License

Apache-2.0 — see [`LICENSE`](LICENSE).
