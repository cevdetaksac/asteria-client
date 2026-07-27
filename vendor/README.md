# Vendor binaries

## Microsoft Edge WebView2 Evergreen Bootstrapper

`MicrosoftEdgeWebview2Setup.exe` is downloaded by `build.ps1` (not committed).

- URL: https://go.microsoft.com/fwlink/p/?LinkId=2124703
- Installer runs it silently when the runtime is missing (`/silent /install`).
- Needs outbound HTTPS on the target host to fetch the Evergreen runtime payload.
