# Asteria Client 4.9.69 — Offline WebView2 + faster installer UI

## Why
Control Center kept showing **WebView2 gerekli** alerts. The old installer only
shipped the ~1.5 MB Evergreen **bootstrapper**, which needs outbound HTTPS on
the host — often flaky on servers — so runtime install failed and the GUI
nagged on every launch.

Installer Welcome also felt slow because heavy kill/legacy cleanup ran in
`.onInit` before any UI appeared.

## Fixes
- Bundle **WebView2 Evergreen Standalone x64** (~150 MB) and silent-install it
  during Asteria setup (`/silent /install`) — **no internet required on target**
- Keep tiny bootstrapper only as fallback
- GUI: filesystem+registry detection, one silent self-repair from bundled
  payload, rate-limited alerts; no WebView2 nag when failure is unrelated
- Installer Welcome appears immediately (heavy cleanup moved to Phase 1)
- Installer window centered and raised to foreground after UAC

## Note
Installer size grows (~260 MB class). Hosts already on a working WebView2 skip
the silent install. One land on 4.9.69 clears the alert loop for Control Center.
