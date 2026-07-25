# Asteria logo_set (design source)

Canonical artwork for client GUI, tray, installer, and exe embedding.
Web/dashboard copies may live under `/static/brand/` (resized) on the cloud side.

| File | Use |
|------|-----|
| `logo.png` / `logo_light.png` | Horizontal lockup — **plain** for light UI, **`_light`** (bright cyan) for **dark UI** |
| `logo_square.png` / `logo_square_light.png` | Stacked lockup — same rule |
| `favicon.png` / `favicon_light.png` | Mark / favicon / app icon source — same rule |
| `icon_online.png` | Tray/status: protection / motor online |
| `icon_offline.png` | Tray/status: offline / inactive |
| `icon_disabled.png` | Tray/status: disabled / paused |
| `icon_stay.png` | Tray/status: stay/hold / warning |

**Naming:** `*_light` = light-ink artwork for **dark backgrounds** (not “light theme”).
Asteria Control Center is dark-mode → always prefer `*_light` in the webview UI.

## Client wiring

| Surface | Asset |
|---------|--------|
| WebView sidebar / lock | `logo_light.png`, `favicon_light.png` (`ui/src/assets/brand/`) |
| Tray (GUI + legacy CTk) | `icon_online` / `icon_offline` (+ disabled/stay reserved) |
| PyInstaller exe icon | `certs/asteria_256.ico` (from `favicon_light.png`) |
| NSIS installer / uninstaller | `certs/asteria_64.ico`, welcome `certs/welcome.bmp` |
| Legacy `certs/honeypot_*.ico` | Regenerated as **aliases** of Asteria art |

After changing files here, regenerate embedded icons:

```bash
python scripts/export_brand_icons.py
```

Then rebuild UI (`ui/npm run build`) and client/gui packages.
