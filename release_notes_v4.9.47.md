# 4.9.47 — WebView2 bootstrapper + modal UX

## Install / Server
- Bundles Microsoft Edge WebView2 Evergreen bootstrapper
- Installer auto-runs `/silent /install` when runtime is missing (common on Windows Server)
- Needs outbound HTTPS on the host to fetch the Evergreen payload
- GUI missing-runtime dialog can launch the local bootstrapper or open the download page

## GUI
- Detail modals: remove redundant bottom **Kapat** (close via × only)
- Layers: Aç/Kapat → on/off **switch** (clear vs modal dismiss)
- Honeypot card labels: Aç/Durdur (EN Start/Stop)

## Install
`asteria-client-installer.exe` (+ legacy `cloud-client-installer.exe` alias).
