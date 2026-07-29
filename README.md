# Asteria Client

**Current Version: 4.9.56**

Windows agent for [Asteria](https://asteria.run): honeypot tunnels, threat response, remote desktop, and firewall sync. Open-source client; cloud/dashboard features may require a license.

| | |
|--|--|
| **Releases** | https://github.com/cevdetaksac/asteria-client/releases |
| **Latest installer** | [asteria-client-installer.exe](https://github.com/cevdetaksac/asteria-client/releases/latest/download/asteria-client-installer.exe) |
| **Changelog** | [`docs/CHANGELOG.md`](docs/CHANGELOG.md) |
| **API contract (SoT)** | https://asteria.run/static/shared-contract.zip (`VERSION` ≥ **1.4.36**) |
| **Production floor** | Client ≥ **4.9.0** (see contract [`FLEET.md`](https://github.com/cevdetaksac/asteria-contract/blob/main/FLEET.md)) |

## Features

- **Honeypot tunnels** — selected service ports over TLS to the cloud
- **Threat / defense policy** — observe → balanced → paranoid; ransomware shield, canaries, Network Guard
- **Remote Desktop** — JPEG/WS + WebRTC; Winlogon / pre-logon mirror (≥4.9.21+)
- **Server management** — sessions, processes, services, local users (enable/disable)
- **Firewall agent** — applies `AR-BLOCK-*` / `AR-INTEL-*`; removes HP/legacy rules
- **Self-update** — GitHub Releases; completion-verified download + retries
- **Tray / GUI** — TR/EN; account link in Settings

## Install (Windows)

1. Download `asteria-client-installer.exe` from the [latest release](https://github.com/cevdetaksac/asteria-client/releases/latest).
2. Run as Administrator (`/S` for silent).
3. Agent registers with the cloud API and stores the token under ProgramData.
4. **Control Center** needs [WebView2 Evergreen Runtime](https://developer.microsoft.com/microsoft-edge/webview2/).  
   Installer ≥4.9.47 tries to install it automatically (host needs internet). Motor/honeypots work without it.

API base (default): `https://asteria.run/api` (legacy failover: honeypot.yesnext.com.tr)

## Build

Requirements: Python 3.11/3.12, pip, PyInstaller, Node.js/npm, NSIS,
WebView2 Evergreen.

```powershell
npm --prefix ui install
python -m pip install -r requirements.txt -r requirements-gui.txt

# Default (JPEG / WS)
powershell -ExecutionPolicy Bypass -File build.ps1 -Clean

# Release profile with WebRTC / H.264 (~69 MB installer)
python -m pip install -r requirements-webrtc.txt
powershell -ExecutionPolicy Bypass -File build.ps1 -Clean -WebRTC
```

Output: `asteria-client-installer.exe` (plus a `cloud-client-installer.exe`
alias copy for pre-4.9.41 self-update) containing motor-only
`asteria-client.exe` + onefile `asteria-gui.exe`. Optional dev signing:
`-Sign`; production `-Release` refuses unsigned/non-WebRTC builds.

## Release

```powershell
.\build.ps1 -Clean -WebRTC -Sign -Release
# Upload BOTH assets: agents <= 4.9.40 fall back to the legacy name.
gh release create vX.Y.Z asteria-client-installer.exe cloud-client-installer.exe `
  --title "vX.Y.Z" --notes-file release_notes_vX.Y.Z.md
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
| [`docs/ASTERIA_DUAL_TRACK_ROADMAP.md`](docs/ASTERIA_DUAL_TRACK_ROADMAP.md) | Motor hardening + `asteria-gui.exe` plan |
| [`docs/GUI_WEBVIEW_ROADMAP.md`](docs/GUI_WEBVIEW_ROADMAP.md) | GUI WebView/WebGL detail |
| [`contract/README.md`](contract/README.md) | Pointer to asteria-contract |
| [`AGENTS.md`](AGENTS.md) | Cursor / agent reading order |

Local `docs/api/*` files are **stubs** — edit behavior only in [asteria-contract](https://github.com/cevdetaksac/asteria-contract).

## Security

Report vulnerabilities privately via [`SECURITY.md`](SECURITY.md) — not public issues.

## License

Apache-2.0 — see [`LICENSE`](LICENSE).
