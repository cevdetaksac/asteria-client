# 4.9.39 — tray brick fix + Control Center UX + presence harden

## Tray / Control Center (critical)
- **Fix:** Closing the GUI with ✕ no longer calls `window.hide()` inside the
  pywebview `closing` callback (known Win32 hang). Hide is deferred to a
  worker thread; tray left/right click stay responsive.
- Supervised tray loop (`icon.run()` + auto-restart) with `ensure_tray_alive`
  revive — dead tray thread recreates the NotifyIcon + menu.
- Show/restore dispatched off the pystray callback thread so a stalled WebView
  cannot brick the icon.

## Presence / Control WS
- Ping send failure forces reconnect (no silent zombie TCP).
- Stale RX watchdog (~75s) before cloud idle_timeout (~90s).
- `websocket-client` missing no longer kills the WS worker forever.
- HTTP heartbeat errors use exponential backoff; 499 logged as transient.
- `hello_ack` handled.

## Control Center UX
- Settings: modern switches, help text, dashboard deep-links, threshold `( 0-100 )`.
- Top bar live meters: App/Host CPU·RAM, net ↓↑, API last contact, last command.
- Status homepage 3-col IP panels: watching / blocked / whitelist (+ `IP_TABLE` IPC).
- Threat local accounts IR, RDP secure-move on Honeypot page, Layers selected policy styling.
- Identity strip + prior 4.9.38 brick/token work included in this fleet package.
