# v4.9.107 — post-logon Default follow + capture_diag

Password on LogonUI no longer freezes on “Windows is getting ready”.
Unlock / post-password follows `WinSta0\Default` on the **same** `stream_id`
(including lock-row Start). Emits `t:capture_diag` / `meta.capture_diag` for
host-to-host compare (Derin vs PASS hosts).

SHA256 `asteria-client-installer.exe`:
`eadff8d77fe5fa7ae2a391fc95ae75ca51ed7a7c14429296726615651da58f2f`

Retest: Logon → type password → Default shell ≤2s (no “Yayın durdu”).
PIX/FOLLOW lab ticks stay open until Derin-Web / Ninety-Web PASS.
