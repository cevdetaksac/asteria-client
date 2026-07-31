# Asteria Client 4.9.70 — Fleet console lab (Winlogon + C-RD-VIEW)

## Why
Dashboard shipped contract **1.4.47** C-RD-VIEW (software cursor, CAD, Logon Start
wire, ICE→JPEG ≤2s, black-frame banner). Operators need a current fleet installer
to lab **Proxmox-like Logon ekranı** on real hosts.

## Included (cumulative)
- **≥4.9.49** C-RD-CON Winlogon / pre_logon capture + SAS + post-logon Default
- **4.9.68** single-flight update gate
- **4.9.69** offline WebView2 Standalone in installer + faster centered installer UI
- **4.9.70** WebRTC peer-setup fail path hardened (`_fail` safe before peer attrs)

## Lab (after install)
1. Host locked or no interactive user
2. Dashboard → Logon / Lock screen row → Connect
3. Expect non-black logon/lock pixels + software cursor
4. CAD → type credentials → Default desktop
5. If sustained black: honest `winlogon_capture_black` / degraded banner (client P0-A)

Min dashboard: contract **1.4.47** viewer. Min agent for this lab: **4.9.70** (this build).
