# Vendor binaries

## Microsoft Edge WebView2 Runtime (offline)

Build downloads these into `vendor/` (not committed — `*.exe` is gitignored).

### Evergreen Standalone Installer x64 (required)

`MicrosoftEdgeWebView2RuntimeInstallerX64.exe` (~150 MB)

- URL: https://go.microsoft.com/fwlink/?linkid=2124701
- Bundled into `asteria-client-installer.exe`
- NSIS runs `/silent /install` when the runtime is missing — **no internet on the target host**
- Also left under `Program Files\Asteria\Asteria Client\` for GUI self-repair

### Evergreen Bootstrapper (optional fallback)

`MicrosoftEdgeWebview2Setup.exe` (~1.5 MB)

- URL: https://go.microsoft.com/fwlink/p/?LinkId=2124703
- Only used if standalone install did not register the runtime
- Needs outbound HTTPS on the target host

Silent flags (order matters): `/silent /install`
