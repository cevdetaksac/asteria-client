# Docs cleanup (no client bump)

Removed `docs/ux-review` screenshots, duplicate resilience/alert plan MDs. Contract **1.4.64** cloud checklist is SoT for dashboard work.

# v4.9.112

## Remote Desktop — rich capture_diag on unhealthy pixels (contract 1.4.79)
- `capture_diag` adds `healthy`, `layer`, `faults[]`, `root_cause`, `advice`, `blame`
- Derin-class `LOGONUI_PRESENT_BUT_FLAT` → `blame=client` / `layer=client_capture`
- Emit on probe withhold, flat/black streak (≥2s), and terminal flat/black fail
- Same object on `t:meta.capture_diag` and Start result `data.capture_diag`

# v4.9.111

## Remote Desktop — honor cloud websocket-primary Start
- `preferred_transport: websocket` (default) keeps JPEG-WS while WebRTC ICE connects
- Suppress JPEG on agent WS only when Start asks `preferred_transport: webrtc` **and** media is truly ready
- `hello.capabilities.preferred_transport` / transport order match Start
- Contract **1.4.77** cloud Live MUST

# v4.9.110

## Remote Desktop — JPEG-WS primary video (contract 1.4.77)
- Unknown lock (`session_locked is None`) must not unlock Default → Winlogon helper (fixes Derin `persistent-user-helper` + black)
- Follow Start prefers live unlock probe over stale stamp
- Never stamp provisional `dxgi:pending`; provisional methods are honest helper names
- `prefer_raw` / media fps only after WebRTC ICE+DTLS ready; until then JPEG-WS ≥30 in-helper
- Input remains immediate on agent WS (`t:input`); HTTP poll is backup only

# v4.9.109

## Dual-channel real-port + bait Attacks (contract 1.4.76)
- Honeypot on/off irrelevant for real RDP/MSSQL/SSH/MYSQL/Network fails → `/api/attack`
- OpenSSH/Operational Event 4 Failed/Invalid → SSH
- MySQL/MariaDB error-log “Access denied” watcher → MYSQL
- IIS FTP W3C logs sc-status 530 → FTP
- Listen-port cache (RDP registry + open_ports) so relocated RDP reports real port
- Bait credential rows remain separate (`source=honeypot`)

# v4.9.108

## Attack service classification (contract 1.4.75)
- Fix `NETWORK` + `port:0` — case-insensitive default ports (Network→445)
- EventLog `target_port` for Network/SMB = 445; RDP NLA remains 3389
- `/api/attack` enrich: logon_type, auth_package, logon_process, status, workstation, source
- Skip anonymous/empty Network Attacks spam; bait `source=honeypot` vs `eventlog`

# v4.9.107

## Post-logon Default follow + capture_diag (contract 1.4.74)
- Unlock after password: leave Winlogon even if `_desktop_name` still says Winlogon
- Lock-row `force_secure` clears on unlock; same `stream_id` → Default DXGI helper
- Do not require explorer.exe before follow (Welcome / shell start)
- Probe healthy Default frame before `phase=live`; else `degraded` + retry
- Emit `t:capture_diag` / `meta.capture_diag` for host-to-host compare

# v4.9.106

## Auto-follow console input desktop (Chrome Remote Desktop model)
- Continuously resolve lock/LogonUI vs unlocked shell (`resolve_console_capture_mode`)
- Mismatch → respawn helper with matching `lpDesktop` + token (SID Start included)
- Default helper uses `OpenInputDesktop` follow — never BitBlt named Default while input is Winlogon
- Force Winlogon respawn when auto-sync decides secure desktop

# v4.9.105

## C-RD-PIX: black screen on follow + SID Start
- Secure-desktop probe runs for **SID Start** as well as `topology=follow` (lab 4.9.103 Active username FAIL)
- Unlocked Default + gdi+black → DXGI retry (encode lock cleared); do not claim Winlogon success
- Promote lock/LogonUI → Winlogon helper even when `follow_console` was false
- Helper spawn: CreateEnvironmentBlock (no CREATE_UNICODE_ENVIRONMENT+NULL); stamp `dxgi:pending`
- Healthy DXGI frames brand `dxgi+nvenc` / `dxgi+desktop-duplication`; never push black probe as Live
- Helper knobs floor 30/72/1920; winlogon probe JPEG quality 72

# v4.9.104

## Real-port auth fails without honeypot
- RDP NLA/CredSSP (Security 4625 LogonType 3) classifies as **RDP**, not Network
- Block-rule fail counters are **service-aware** (Network fails no longer fill RDP threshold)
- Real EventLog fails matching enabled `protection.block_rules` → `/api/attack` (password `<failed_logon>`); honeypot on/off irrelevant

# v4.9.103

## C-RD-PIX-4 + SMOOTH: unlocked console must be DXGI at Start knobs
- Drop `CREATE_NO_WINDOW` on Default session helpers (DXGI/DWM never came up)
- Remove the 8 fps helper-reconnect cap; helper floors 24 fps / q55 / 1280
- DXGI grab retries without clipping to a 1024×768 region; encode lock can grow
- Unlocked explorer + WTS unlocked: do not promote GDI black to Winlogon

# v4.9.102

## C-RD-PIX-3: listed username is not an unlocked desktop
- Win+L / unknown lock → Winlogon helper (`winlogon.exe` token, `winsta0\Winlogon`)
- Skip Winlogon only when explorer is present, WTS unlocked, and no LogonUI
- Do not keep a Default user helper after promoting to Winlogon

# v4.9.101

## Remote desktop video-rate stream (contract 1.4.71)
- Lift dashboard `fps:12` / `q:40` / `w:1280` Start knobs to 30 / 72 / 1920
- JPEG coalescing no longer marks congestion (stale-frame drop is the video path)
- WebRTC 12 Mbps / 60 fps encoder; `needs_turn` + TURNS hint in hello
- Accept WebRTC offer/answer/ice when `protocol` is omitted

# v4.9.100

## Physical-console remote desktop (lock / logon / logoff)
- Do not follow Default while input desktop is still Winlogon (listed username ≠ unlocked)
- Lock/logoff → Winlogon helper with winlogon.exe token (user token cannot BitBlt Winlogon)
- Unlock/logon → DXGI Default on the same stream once helper reports Default

# v4.9.99

## Remote desktop pixels + video-rate capture (contract 1.4.69)
- Follow + lock with a listed username: LogonUI → Winlogon helper (not `persistent-user-helper` `gdi+black`)
- Logging failure must not roll Follow back to Default GDI
- WebRTC JPEG suppress / `connected` health only after one non-black frame
- WebRTC JPEG suppress / `connected` health only after one non-black frame
- Capture 60 fps raw / 8 Mbps target; `t:meta.black_frame` every ≤5 frames

# v4.9.98

## One installer download
- Cross-process `Global\\AsteriaClient_UpdateGate` mutex (JSON gate alone raced)
- Treat ACCESS_DENIED / PermissionError on holder PID as **alive** (do not steal SYSTEM download)

# v4.9.97

## Follow Connect must not capture Session-0 Winlogon GDI
- `topology=follow` no longer sets `want_winlogon` (that picked the Logon sibling and painted `gdi+black`)
- Live console user → Default DXGI helper; lock/LogonUI/no user still uses Winlogon helper
- Dashboard “Logon · varsayılan” black-frame warning on logged-on hosts

# v4.9.96

## Threat-intel ACK + installer alias (contract 1.4.61)
- HTTP 304 never POSTs intel ACK
- ACK `stats.firewall_current` = standing `AR-INTEL-*` count
- `self_update` rewrites legacy `cloud-client-installer.exe` asset name

# v4.9.95

## Named console topology (contract 1.4.59)
- `topology=follow`: omit-SID Start skips Winlogon helper when Default is live
- `topology=winlogon`: lock/logon row forces Winlogon helper
- Legacy omit-SID + `prefer=winlogon` treated as follow

# v4.9.94

## C-RD-FOLLOW: skip Winlogon helper on live Default
- Omit `session_id` follows `WTSGetActiveConsoleSessionId`
- Interactive username + no LogonUI → Default + DXGI (no Winlogon spawn)
- jpeg=0B Winlogon + follow → fallback Default helper

# v4.9.93

## inspect_process + C-RD-FOLLOW
- On-demand PID evidence; rundll32 `dll,Entry` is not lolbin
- After logon, same stream follows console Default

# v4.9.73

## Update path harden + installer alias gone
- Heal update-staging **file** ACLs (not only the folder); rewrite helper after Permission denied
- Probe helper-named `.ps1` writability before trusting `Asteria\update`
- Publish/download only `asteria-client-installer.exe` (no `cloud-client-installer` alias)

# v4.9.72

## GUI: all alert cards at the top
- Update banner + motor/error strip share one `top-alerts` stack above the identity row
- Avoid duplicate **Motoru kurtar** when the update banner already shows it

## GitHub hygiene (follow-up)
- Drop `cloud-client-installer.exe` release alias; self-update resolves only `asteria-client-installer.exe`
- Staging cleanup still recognizes leftover `cloud-client-installer*` files on disk

# v4.9.71

## Fix `launch_helper_failed` / `stage_helper` (ACL brick)
- Stop stripping `BUILTIN\Users` from `%ProgramData%\Asteria\update` (that locked out medium-integrity GUI / SilentUpdater)
- Heal staging ACL to SYSTEM/Admins/Users **M**; fallback `update_work` → `%TEMP%\AsteriaUpdate`
- Emergency helper can stage under TEMP; interactive elevated NSIS fallback if helper still cannot start

# v4.9.67

## Unstick self_update at 0% (Command received, no bytes)
- Progress `commands/result` ticks are async (no shared-session wedge vs download)
- API client `RLock` around `api_request`
- Lifecycle begin non-blocking; constructed release URL before GitHub API
- Download phases: `connecting` / `headers_received` so UI leaves 0 B

# v4.9.66

## Fix remote `launch_helper_failed` (schtasks TR + direct NSIS)
- Method 6: keep schtasks `/TR` under 261 chars (args inside `.ps1`, not on `/TR`)
- Method 7: direct NSIS `/S` short-TR fallback with log start marker
- Slow-start: extra wait / re-run before deleting UpdateOnce tasks
- Emergency bootstrap: stop `AsteriaGuardian`, kill `asteria-*` (not only honeypot-client)
- Progress: 98% when helper is confirmed running

# v4.9.65

## Quiet logs (API / HEALTH / FW spam + size caps)
- `premium/tunnel-status` and other hot polls no longer dump full JSON at INFO
- `api_request` default `verbose_logging=False`; truncate rare success bodies
- Throttle HEALTH process/report and idle FW-SYNC zero-change lines
- Daily logs honor `LOG_MAX_BYTES` (within-day `.N` parts); GUI rotating + `_MEI` cleanup
- Honeypot capture logs only after rate-limit; passwords redacted

# v4.9.64

## Clean start (legacy purge + single tray owner)
- Legacy purge: `YesNext\CloudClient`, `ProgramData\YesNext`, leftover vendor leaves, user `AppData\YesNext`
- Update/kill helpers stop+delete `AsteriaGuardian` before process wipe (no mid-kill resurrect)
- Silent update: skip helper `Asteria-Tray` when motor ready — daemon/`--create-tasks` owns tray handoff
- GUI single-instance: `Global\AsteriaClient_GUI_s{session}` (crosses integrity); CreateMutex fail-closed

# v4.9.63

## Harden `launch_helper_failed`
- Silent update waits longer for `update-and-install start` (no false fail on slow hosts)
- Prefer emergency ASCII bootstrap after launcher-only storms
- `self_update` retries once with `prefer_emergency=1` before failing the banner
- Silent path never returns success without helper log (even if elevate was requested)

# v4.9.62

## Update brick harden (orphan_lock / Motoru kurtar)
- `self_update` preempts stuck/orphan `update_in_progress.lock` even without `force` (no forever `busy`)
- Force path no longer uses `release_update_lock(resume_updaters=False)` alone
- Successful `operator_recover` clears the failed banner when motor is back (no sticky `operator_recover` strip)
- Orphan lock finalize starts motor when down; clears banner if motor healthy

# v4.9.61

## Contract 1.4.46 — self_update progress ticks
- Mid-flight `POST /api/commands/result` with same `command_id`: `status:running` + `phase` / `progress_pct` / bytes (C-UPD-PROG-1..4)
- Cadence ≤3s while downloading; phase change emits immediately; heartbeat avoids >5s silence
- Installer launch → `completed` + `message:update_started` + `phase:installing` + `restart_required`
- Early ACK includes `phase:queued` + version fields

# v4.9.60

## Contract 1.4.45 relocate close-out
- Accept dashboard `target_port`; golden snapshot **on disk** (C-REL-2)
- Pre-check target free; reject `<1024` / classic-port collisions (C-REL-6/7)
- Firewall `AR-RELOCATE-<SVC>-<PORT>`; remove on rollback (C-REL-5)
- Rollback result: `status:rollback` + `reason:bind_verify_failed` + `target_port`
- GUI: relocated/relocating badges, target-busy / port_available hints

# v4.9.59

## Contract 1.4.45 — Service Port Relocate (sync + GUI)
- **`relocate_service`:** golden → firewall → config → restart → ≤10s bind verify → local golden rollback
- Result SoT: `status:"ok"` + `service/old_port/new_port` · rollback → `status:"rollback"` + `reason`
- Default safe ports **4XXXX** (RDP 43389, MSSQL 41433, MYSQL 43306, SSH 40022, FTP 40021) — **no 53389 / 9XXXX**
- GUI Relocate card: prefill from `GET premium/tunnel-status` `relocate_state` · report `POST agent/relocate-report` (`source:gui`)
- C-REL-9: open_ports refresh ≤5s after every attempt
- Single in-flight relocate (C-REL-1)

# v4.9.58

## Easy port relocate (`relocate_service`)
- Dashboard easy-port command: **stop → config → start → bind verify → golden rollback**.
- Built-in **RDP / TermService** (registry `PortNumber`); optional custom `registry_path`+`scm`.
- Confirm-gated + IR-urgent; `GOLDEN_ROLLBACK` on start/bind failure restores prior port.

# v4.9.57

## GUI loading honesty
- Switches/cards show **Yükleniyor…** (indeterminate) while status is unknown — never fake **KAPALI/Off**.
- Keep last known motor status across silent polls; hard “ulaşılamıyor” only when never hydrated or update-stuck.
- Threat / Services / Settings empty states wait for load before “alınamadı”.

# v4.9.56

## Threat Center GUI
- Row actions use visible labeled buttons (`TextActionBtn`) instead of clipped icon-only controls.
- Tables allow horizontal scroll (`overflow-x: auto`, `table-layout: auto`) so action columns stay reachable.
- Accounts accordion defaults open; unblock + whitelist wired on attacker/IP rows.

# v4.9.55

## Remote console parity (contract 1.4.43)
- **C-RD-CON-2:** omit `session_id` on Logon Start → `WTSGetActiveConsoleSessionId` (never assume SID 1 / Active RDP).
- **C-RD-CON-3:** Winlogon path never binds username.
- **C-RD-CON-4/5:** strict named `WinSta0\Winlogon` attach; sustained `gdi+black` still fails.
- **C-RD-CON-6:** periodic reattach follows input desktop → Default after logon (no second Start).
- **C-RD-CON-7:** `remote_send_sas` uses stream/console SID + Winlogon attach before SendSAS.
- **C-RD-CON-8:** Health/`list_sessions` Logon/Lock `pre_logon:true` sibling (unchanged, kept).

# v4.9.54

## Network Adapter Admin (contract 1.4.42)
- Remote command `network_adapter_apply`: enable/disable/set_ipv4/set_dns/set_config.
- Local watchdog (5–15s, default 10) probes connectivity; on fail restores that adapter’s adapter+ipv4+dns from signed golden (`WATCHDOG_ROLLBACK`).
- Pauses `auto_restore_network` during apply; refuses last management NIC disable (`LAST_MGMT_ADAPTER`); optional `on_success=accept_surface`.

# v4.9.53

## Firewall Windows MMC parity (contract 1.4.41)
- `list_firewall` `scope=all`: full inbound/outbound rule lists + profiles + truncation/counts (`engine=netsh`).
- `firewall_rule` ops: enable / disable / delete / add (`AR-MANUAL-*` for dashboard IP adds); delete/add confirm-gated on cloud.
- `firewall_set_profile` accepts `profile=all`; returns updated profiles after mutate.
- Plan note: [`docs/LINUX_AGENT_PLAN.md`](LINUX_AGENT_PLAN.md) (future Linux/macOS agent).

# v4.9.52

## Firewall Management (contract 1.4.40)
- Remote commands `list_firewall` (profiles + AR/HP/HONEYPOT inbound rules + counts) and `firewall_set_profile` (Domain/Private/Public; confirm-gated).
- Inventory module `client_firewall_inventory.py`; cloud dashboard **Tam envanter** needs client ≥4.9.40 (this build).

# v4.9.51

## GUI
- Sidebar foot reordered: centered larger **TR | EN**, then **Motor | Version** pill, then **Minimize to tray**.

# v4.9.50

## GUI
- Sidebar version moved under foot as a pill badge (no longer under brand lockup).
- Sidebar uses official `logo_light.png` wide lockup; sticky viewport sidebar so foot stays visible.
- Quarantine JSON load accepts UTF-8 BOM (`utf-8-sig`).

## Hygiene
- Lifecycle `client_startup` reports real mode (`daemon`/`gui`/…) instead of `unknown`.

# v4.9.49

## State / signal hygiene
- **Empty RS quarantine auto-heal:** `active=true` with zero IFEO entries no longer sticks after VSS/canary miss — heal on load/start and disarm after contain with no writer.
- **Single VSS alert emit:** drop duplicate `on_alert` + `send_urgent` pair (TR + empty-title cloud noise).
- **Resume grace (180s):** after sleep/wake, persistence snapshot stays optimistic so cloud does not spam `agent_persistence_degraded`.
- **Resilience migrate:** rewrite polluted `version=test` to `VERSION`; clear sticky `last_recovery_ok=false` on migrate / empty baseline.
- **Threat intel titles:** `intel_watch` / `intel_banner` always carry a non-empty `title`.

# v4.9.48

## Remote stream progress (contract 1.4.39)
- Agent emits `t: stream_progress` on RD agent WS (`running` → `capture_start` → `capturing` → `ws`/`webrtc` → `live`, or `failed`+`error`).
- C-RD-PROG-1..4: ≤4 evt/s, ≤3s heartbeat while starting, no `live` for black-fill-only, control-WS fallback.
- Wired into `remote_stream_start` + `remote_session_prepare`.

## Update brick / stuck recovery
- **Orphan update lock no longer bricks the motor:** clearing a dead/stale `update_in_progress.lock` now resumes Background/SilentUpdater tasks, clears resilience stand-down, and marks the GUI banner `failed` (`orphan_lock_dead_pid` / heal paths).
- **`client_update_recovery`:** diagnose + auto-abort + operator abort/recover. Wired into `ensure_daemon_running`, `heal_update_machinery`, GUI `ping` / `update_banner` (`abort` | `recover`).
- **GUI:** failed/stalled banner and “motor unreachable” strip expose **Motoru kurtar** so operators can clear a stuck handoff without reinstalling.

# v4.9.47

## WebView2 (Windows Server)
- Installer ships Evergreen bootstrapper and installs silently when runtime missing
- GUI offers to run bootstrapper / open download page if still missing

## GUI UX
- Detail modal: no bottom Kapat (× only); Layers use switch instead of Aç/Kapat twin

# v4.9.46

## GUI feature guides
- Network Guard / Ransomware / Layers / Threat / IP / Honeypot — i18n how-to (GOLD baseline, maintenance, canary decoys)

## Anti-brick (contract 1.4.38)
- Probe `undo_mail_path` on account-status; skip admin-class auto without break-glass
- Rollback alert `critical_action_rolled_back`

# v4.9.45

## Contract 1.4.37 client close-out
- Envelope v2 observe-only (RFC 8785 JCS + Ed25519 fixture verify); no emit/enforce
- Fleet canary C-CANARY-1…5 (`fleet_rollout.gates` AND local enable; health echo)
- Offline urgent queue: local flag AND canary gate (default off)
- RD P0: Winlogon `black_frame` / `winlogon_capture_black`; ICE honesty + JPEG fallback
- Dual-brand sunset notes → **2026-10-01** (legacy verify kept until then)

# v4.9.44

## Threat Center — shares + third-party services
- Motor IPC: `SHARES_LIST` / `SHARE_REMOVE`, `SVC_LIST` / `SVC_STOP` (SYSTEM)
- WebView Threat page panels with row actions (remove share / stop unknown service)
- Default SMB shares protected; `PROTECTED_SERVICES` respected on stop

## Contract 1.4.36 gap-scan
- Verified against published `CLOUD_SURFACE.md` (signing `asteria-chp-v1` / heartbeat `asteria-heartbeat-v1`, anti-brick already ≥4.9.36)
- Added missing remote command **`sync_firewall_rules`** (POST inventory sync)

## GUI (carried from unreleased 4.9.43 UI polish)
- `.ip-cols` 3-column grid; honeypot Aç/Kapat equal cards + RDP Taşıma Aracı; Status/Layers detail modals; Threat threats-first + accounts accordion

# v4.9.43

## Remote commands (dashboard pending stuck)
- **`tunnel_start` / `tunnel_stop`:** contract bait honeypot commands were rejected as unknown — now applied via ServiceManager and ACKed with `commands/result`
- Rate-limit defer no longer leaves command_id in dedup cache without ACK (pending forever)
- Pending fetch logs errors; accepts alternate list shapes
- Control-WS healthy HTTP safety poll default 5s (was 30s); service reconcile 15s (was 45s)
- GUI STATUS poll ~1.5–2s; `status_generation` bump after remote apply

## GUI UX polish
- IP / hesap satır ayırıcıları `tr` border ile tam genişlik; aksiyon hücreleri sağa hizalı
- Tooltip’ler ikonun üstünde ve ortada (`left: 50%` + `translateX(-50%)`); native `title` kaldırıldı
- Threat IR: sıkışık self-hint metni → info ikonu + tooltip
- Whitelist / tablo yatay scroll: `overflow-x: clip`
- Identity strip + parola göster/gizle: CSS tooltip

# v4.9.42
- **Status / IP list actions:** cramped text buttons replaced with Font Awesome icon buttons (block / unblock / whitelist / remove) plus hover tooltip (`title` + CSS).
- **Typography:** slightly smaller base UI fonts (nav, page titles, cards, panels, buttons) for a less dense Control Center.

# v4.9.41
- **ProgramData brand path:** durable state moves to `%ProgramData%\Asteria\` (flat). First run / installer copies YesNext `CloudHoneypotClient` + `CloudHoneypot` (+ AppData legacy) without overwriting newer Asteria files.
- **Installer artifact renamed:** `asteria-client-installer.exe` is now the primary release asset. Releases also publish an identical `cloud-client-installer.exe` alias because agents ≤4.9.40 hardcode that name as their fallback download URL; self-update tries the Asteria name first, then the legacy one. Staging/cleanup recognizes both prefixes.
- **Wire identity rebrand:** new installs create `Asteria-Background|Tray|Watchdog|Updater|SilentUpdater|MemoryRestart`, `AsteriaGuardian`, `AsteriaClientGuard`, and `AsteriaClient_*` mutex/events. Install/uninstall still end+delete all pre-4.9.41 `CloudHoneypot-*` / `HoneypotClient*` / `CloudHoneypotGuardian` names. Registry LastMode writes `HKCU\Software\Asteria`.
- **Uninstall completeness:** uninstaller embeds `kill-honeypot.ps1` (no longer shipped under Program Files), kills `asteria-gui.exe` as well as the motor, deletes GUI/motor with `/REBOOTOK`, recursively wipes `$INSTDIR` (incl. `.stale_*`), cleans Defender exclusions for both exes, Start Menu/Desktop (Asteria + legacy), ARP/HKCU brand keys, and update staging under ProgramData.
- **Header:** Dashboard + Refresh moved into the Help menu; the account chip now opens the dashboard.
- Carries 4.9.40 GUI helpers shim, exception capture, dashboard deep-links (contract 1.4.35).

# v4.9.40
- **GUI:** Tk-free `client_helpers` runtime shim (fixes `No module named client_helpers`); richer GUI exception/tray logging; expanded gui hiddenimports.
- Carries 4.9.39 tray brick fix, presence/WS harden, Control Center UX.

# v4.9.39
- **Tray brick fix:** X-close no longer sync-hides inside pywebview `closing` (Win32 hang); supervised tray loop + revive; show/hide off tray callback thread.
- **Presence/WS:** ping-fail reconnect, 75s stale RX, heartbeat backoff on 499/timeout, `hello_ack`.
- **Control Center:** settings switches + help/dashboard links; top-bar live meters; status 3-col IP panels (`IP_TABLE`); Threat accounts IR; RDP secure-move; Layers selected styling.

# v4.9.38
- **C-BRICK-1:** Local critical auto (`disable_account` / auto logoff) requires fresh `account_linked` (cache ≤15 min, fail-closed). Skip + alert `skipped_unlinked`.
- **C-BRICK-2:** Silent hours / time rules remain default OFF; cloud cannot force auto disable/logoff via silent-hours flags.
- **C-BRICK-6:** Refuse disable of the last enabled local admin; rollback if zero admins remain.
- **Wire:** `commands/result.status` = completed/failed… only; SAM active/disabled only in `result.data`.
- **Token:** Failed rotate keeps identity; schema upgrade rewraps; unreadable `token.dat` never overwritten; leftover legacy tokens remapped via `POST /api/agent/rotate-token` (`legacy_supersede`).
- **GUI:** Top-bar identity strip (host + masked token + copy).

# v4.9.35
- **Signing cutover (contract 1.4.32+):** Emit/verify command HMAC with `asteria-chp-v1`; heartbeat proof with `asteria-heartbeat-v1`. Verify still accepts legacy `yesnext-*` during fleet cutover.
- **API class rename:** `HoneypotAPIClient` → `AsteriaAPIClient` (compat alias retained).
- **Web Control Center parity:** Account link/unlink form, WinRM/NLA/Defender harden+fix, RDP move, IR logoff/disable, update banner, TR/EN i18n. Layers POST uses contract keys (`ransomware_protection_enabled`, `canary_files_enabled`, `protection.network_guard`).

# v4.9.34
- **Asteria rebrand (contract 1.4.30):** Display name, installer, Start Menu, and tray/GUI titles are **Asteria**. Default API host is `https://asteria.run/api` with one-shot failover to legacy `honeypot.yesnext.com.tr`. New installs go to `Program Files\Asteria\Asteria Client\` with `asteria-client.exe` (legacy `honeypot-client.exe` / YesNext path still probed).
- **Wire identities unchanged:** ProgramData `YesNext\CloudHoneypotClient`, `CloudHoneypot-*` tasks, and `yesnext-chp-v1` signing context stay stable.

# v4.9.33
- **Asteria firewall wire identity (contract 1.4.31):** New dashboard/auto blocks use `AR-BLOCK-{ip}` and threat intel uses `AR-INTEL-{id}`. Unblock, whitelist enforcement, and full wipe remove AR, HP, HONEYPOT, and CloudHoneypot legacy names.
- **One-time boot migration:** Existing `HP-BLOCK-*` / `HP-INTEL-*` rules are copied to AR names before legacy deletion, then reported with `sync-rules mode=snapshot`. A ProgramData marker is written only after migration and HTTP 200 sync.

# v4.9.32
- **In-place token rotate (contract 1.4.29):** Rekey/identity_v2 uses POST /api/agent/rotate-token before writing token.dat — no bare /register while old token known (ghost Client fix). Same client_id / Account link / attack history. 409 retry; 403 machine_id candidates; rotate-fail then quarantine+register.

# v4.9.31
- **GUI card hover/click:** Protection chips + stat cards ignore Leave when pointer stays on child labels; bind click/hover to full widget tree (Ransomware Shield / AKTIF text works).

# v4.9.30
- **Critical tray auto-start:** Tray task XML dropped invalid LogonType=Group (schtasks reject left tray_task=false). install_task no longer delete-then-create. has_interactive_user_session parses query session stdout even when exit code is 1 (was blocking watchdog/daemon tray launch).

# v4.9.29
- **Tray stay-alive:** Supervised pystray loop + TaskbarCreated respawn; GUI health restarts dead tray thread; --mode=watchdog relaunches tray when logon has no frontend; close-to-tray no longer exits during tray startup; silent-update session match includes Aktif.

# v4.9.28
- **Critical � clone/shared token:** `/register` `machine_id` = SHA-256(MachineGuid + NIC MACs + SMBIOS + vol serial). CHP2 `token.dat` + `device_binding.json` bind identity; fingerprint mismatch ? quarantine + re-enroll. One-time schema v2 hardware rebind so VM clones that shared one UUID each get a unique Client (re-link Account). Ops: `scripts/reset-agent-identity.ps1`. Contract **1.4.26**.

# v4.9.27
- **Installer FileInUse (`memory_restart.ps1`):** Relocate `scripts\` before extract; kill PowerShell locking install helpers; install `memory_restart.ps1` via lock-safe copy (`install-memory-restart.ps1`) instead of NSIS `File` (no Abort/Retry/Ignore). `SetOverwrite try` on main extract for residual handle races.

# v4.9.26
- **Winlogon on dashboard:** Health/`list_sessions` always offers a `pre_logon` "Logon / Lock screen" sibling (even when a console user is Active). `remote_stream_start` accepts `prefer`/`desktop`/`pre_logon` and attaches named Winlogon before OpenInputDesktop. Hello capabilities advertise `winlogon`/`pre_logon`.
- **self_update download completion:** Installer download succeeds only when transfer is complete (Content-Length match + PE MZ + min size) � never "timeout expired = done". Stall timeout only detects idle sockets. Up to 5 retries with backoff; then launch installer. Richer `detail` on failure.
- **Server users (contract 1.4.22):** `list_local_users` defaults to `include_disabled=true` with `status` / `protected` / `can_enable` / `can_disable` / `counts`. `enable_account` / `disable_account` return refreshed `data.user` snapshot for cloud toggle UI.
- **GUI defense mode UX:** Security Layers banner + action buttons refresh with active policy (no stale "Yaln?z bildir" after switching to Balanced).
- **Account link Settings:** Ayarlar � Hesap ba�lant�s� (durum, ba�la, ba�lant�y� kes, Sunucular�m). In-app unlink via POST /api/agent/unlink-account (contract 1.4.23).

# v4.9.25
- **Source packing fix:** Stop copying `client_*.py` into `_internal` via PyInstaller `datas=` (they were world-readable source). Modules go into PYZ as bytecode via Analysis/`hiddenimports` only. Build fails if any `client_*.py` leaks into onedir.

# v4.9.24
- **Scripts ACL / attack surface:** Do not install `kill-honeypot.ps1` / `update-and-install.ps1` / `prepare-install-dir.ps1` under Program Files (installer embeds them in `$PLUGINSDIR` only). On upgrade, delete leftovers. `scripts\` (+ `_internal\scripts`) ACL = SYSTEM+Administrators only. Kill/update/memory_restart refuse non-elevated runs. Motor QUIT was already gated by operator_stop/update-lock.

# v4.9.23
- **Installer FileInUse (hardened):** If `_internal` directory rename fails (Session-0 cwd lock), relocate each file individually (frees paths like `servicemanager.pyd` for overwrite). Stronger terminate (`Terminate` access + WMI) and longer post-QUIT grace for DACL disarm.

# v4.9.22
- **Installer FileInUse fix:** Before extract, kill install-dir processes, add Defender exclusion, and **rename** locked `_internal` / `honeypot-client.exe` aside (`.stale_*`) so NSIS never stalls on Abort/Retry/Ignore for `servicemanager.pyd` etc. `prepare-install-dir.ps1` + stronger `kill-honeypot.ps1`.

# v4.9.21
- **Remote Desktop Winlogon / pre-logon (contract 1.4.21):** When no interactive user is logged on, mirror console `WinSta0`/`Winlogon` so operators can type credentials on the stream. `list_sessions` synthesizes `pre_logon` console row; `remote_session_prepare` defaults to Winlogon probe instead of `UNSUPPORTED` (`prefer=existing` keeps old gate). Input attaches to Winlogon; switches to Default after logon.

# v4.9.20
- **Remote Desktop smoothness (contract 1.4.20):** WebRTC path uses raw RGB mailbox (no JPEG double-encode); HW H.264 when FFmpeg exposes nvenc/qsv/amf else x264 ultrafast+zerolatency; idle unchanged-frame skip; capture ~45 fps on media; move rate 120/s; critical ACK 80 ms; adaptive JPEG knobs do not thrash helper while WebRTC connected; `media.encoder` / `target_bitrate_bps` telemetry.

# v4.9.19
- **Defense policy sync:** ignore non-defense / invalid cloud defense_rules_sig; bad sig applies unsigned (no false tamper_observe).

# v4.9.18
- **Defense policy cache:** HMAC fail due to empty-token boot race ? re-sign with current token (`programdata_resign`) instead of false `tamper_observe`. Includes 4.9.17 observe default + auto-promote.

# v4.9.17
- **Defense Policy onboarding (contract 1.4.19):** Fresh install / empty cache defaults to **observe** (alerts on, no auto kill). Configurable auto-promote observe?balanced (default 3 days; lockable). GUI education for ?zleme/Denge/Tetikte + CTA. Never auto-opens paranoid/isolate. Cloud POST backup on promote.

# v4.9.16
- **Defense Policy P0 (contract 1.4.18):** `protection.defense_policy` / `defense_rules` / `defense_policy_version` / `isolate_armed` apply via CONFIG-SYNC + boot hydrate. Signed `defense_policy.json` + LKG; tamper -> LKG/observe (never isolate/escalate). Matrix gates canary/VSS/critical process (`alert_only` | `suspend_process` | `kill_quarantine`). Hard-reject `auto_isolate_network` on observe/balanced (and unarmed paranoid). `allow_process` / `list_allowed_processes`; `isolate_host` rejected unless paranoid+armed (P2 path not yet enabled). Session JPEG snapshot on red events (dedupe >=5 min). STATUS/health: `defense_policy{}`. Anti-bait unit tests.

# v4.9.15
- **Network Guard soft surface inform (contract 1.4.17):** Ethernet/DHCP/yeni adapter (additive) ? soft `network_surface_changed` (info, urgent yok); `auto_restore` yaln?z subtractive; asla auto-disable. STATUS `surface_inform` + changes. Komutlar `network_accept_surface` / `network_disable_adapter` (confirm). GUI chip ?A? de?i?ti? + ?Bu bendim ? yede?i g?ncelle? (PIN yok). Internet a??kken panik yok.

# v4.9.14
- **VSS delete intent (contract 1.4.16):** `vssadmin delete shadows` / WMI / wbadmin score?95 ? hemen `taskkill` + quarantine arm (g?lge say?s? d??mesini beklemez). `vssadmin`/`wmic`/`powershell`/`cmd`/`wbadmin` IFEO yok. Process poll 5s?2s. Urgent `ransomware_vss_delete_intent`. Not: `HP-BLOCK` IP firewall?d?r, VSS deny de?ildir.

# v4.9.13
- **STATUS hang fix:** Network Guard / System Recovery `status()` art?k STATUS soketinde PowerShell/`diff` ?al??t?rmaz (detect-loop cache). `list_network_baseline` / `network_diff` / `system_recovery_diff` zengin live i?in kullan?l?r. Tek i? par?ac?kl? `:58632` timeout?lar?n? giderir.
- **Release build:** `build.ps1 -Clean -WebRTC` ? SHA-256 `0318C3543B2DCD36C3585B0466CC6E4C63BE1175F7362D34FDE8EDA7BF5DD414`.

# v4.9.12
- **System Recovery (contract 1.4.13):** sald?r? y?zeyi allowlist ? TaskMgr/Regedit/CMD policy, kritik servisler (VSS/wscsvc/EventLog/?), firewall profil state. ?mzal? snapshot + drift watch (`system_recovery_drift`) + dashboard komutlar? `system_recovery_snapshot` / `list_system_recovery` / `system_recovery_diff` / `system_recovery_restore` (dry_run + confirm). Full registry dump yok. STATUS `system_recovery{}`. HKCU policy okuma/yazma SYSTEM daemon?da `HKEY_USERS\<interactive-SID>` ?zerinden (sald?rgan?n kilitledi?i kullan?c? hive??).
- **Network Guard dashboard panel (contract 1.4.14):** STATUS/`list_network_baseline` full live+golden adapters (IPv4/DNS/dhcp); `network_diff`; golden baseline zehirlenmez (periyodik yaln?z connectivity); `auto_restore_network` default on (s?re? contain h?l? hard-off); IPv4 dhcp/static restore; bilin?li IP de?i?iminde ?nce `network_snapshot`.
- **Network Guard bak?m modu (contract 1.4.15):** GUI chip ? duraklat / yedekle / ba?lat; IPC `NG_MAINT_*`; komutlar `network_maintenance_start` / `network_maintenance_end` (`snapshot` default true); local `network_guard_maintenance.json` cloud sync ile silinmez.
- **Release build:** `build.ps1 -Clean -WebRTC` ? installer 69.3 MB; SHA-256 `4B085CF582BC686B219D088459ECC1B5376ABD980B16C564FFA88B6424B1CB91`.

# v4.9.11
- **Alert sinyal hijyeni** ([CLIENT_ALERT_SIGNAL_HYGIENE.md](CLIENT_ALERT_SIGNAL_HYGIENE.md), cloud hedef ?4.9.9):
  - `vssadmin list shadows` ? `ransomware_process` yok; AlertPipeline urgent drop; yaln?z delete/wbadmin delete critical
  - K???k VSS delta (?2 silinen, kalan ?3) ? `warning`; mass/0 kalan veya delete cmd ? `critical`
  - Canary: self-touch suppress; soft MODIFIED debounce ?30 dk (t?m path); soft ? urgent yok; multi/suspect ? critical
  - Offline: Wi?Fi flap i?in net_cut ?15s persist; ayn? trigger+pid dedupe ?5 dk; suspect=`warning` (bomb yok)
  - Trusted/local logon ? `info` score ?10 (pipeline inflate yok); ?Lateral Movement? ba?l??? kald?r?ld?
  - **?8 Lifecycle:** ayn? `event_type`+saniye dedupe (cross-process); `report_now` ?ift POST yok; `gui_quit` 60s rate-limit; `CLIENT_PROCESS_STOPPED`/`GRACEFUL` ? lifecycle only (urgent de?il)
  - **?10** `intel_watch`/`intel_banner` urgent?e y?kselmez
  - Resilience: guardian_false / update stand-down urgent yok (observe only)

# v4.9.10
- **Guardian restart loop fix:** SCM Event 7009/7000 ? `--mode=guardian` art?k heavy import?tan ?nce fast-path (30s start timeout); `sc` delete+recreate kald?r?ld?; START_PENDING beklenir; `guardian_restarts_24h` yaln?z ba?ar?l? recover (failed heal ? `guardian_heal_attempts_24h`); legacy ?i?mi? saya? prune.
- Power presence `PVOID` fix (?nceki commit) + cloud soft-alert ile uyum: guardian_false tek ba??na alarm de?il.

# v4.9.9
- **Priority hotfix:** `SetPriorityClass` 64-bit handle (ctypes `WinDLL` + restype/argtypes) ? 4.9.8 lab?de winerr=6 ile NORMAL?de kal?yordu; art?k `above_normal` uygulan?r.

# v4.9.8
- **Kaynak k??e bilgisi:** ?st barda k???k badge ? App CPU%/RAM MB ? Host CPU%/RAM% ? a? ?? (daemon STATUS `resources`; t?kla ? CPU/RAM detay).
- **Motor CPU ?nceli?i (RES-101):** Session-0 daemon `ABOVE_NORMAL` (asla `REALTIME`); config `security.motor_priority` (`above_normal`|`high`|`normal`); RES-102 lite guard y?ksek motor CPU?da NORMAL?e d??er.
- STATUS additive `resources{}` (host + process + priority) ? process listesi yok (IPC hafif).
- **Realtime presence (contract 1.4.12 / api/11):** uyku ?ncesi WS `presence` suspend (+ HTTP `POST /api/presence` ?2s); servis/OS kapan?rken `goodbye` sonra close; uyan?nca reconnect + online; update/uninstall/operator_stop reason?lar?; GUI quit ? offline (motor ayaktaysa). Power: `PowerRegisterSuspendResumeNotification` + console shutdown handler.

# v4.9.7
- **Threat Intel HP-INTEL apply (contract 09 / honeypot-contract 1.4.9):** bundle `firewall_blocks` ? `HP-INTEL-<id>` inbound+outbound (no longer `HP-BLOCK-*` / AutoResponse 24h); severity/allowlist/expires/orphan reconcile; `firewall_removed` in ACK; ETag meta+cache durable; 304 ? expire reconcile; clear_firewall includes `HP-INTEL-*`.
- **successful_logon skor/auto-block fix:** bare RDP/success art?k `threat_score` ?70 (sessiz saat ?80), asla 100; `should_auto_block()` bare success?te false; HP-BLOCK yaln?z brute_force_then_success / honeypot / block_rules / operator; sessiz saat firewall kesmez (alert/challenge); whitelist skor d???r?r.
- **Whitelist asla engellenmez:** `block_ip` whitelist?te skip + mevcut kural? an?nda kald?r?r; `update_whitelist` ? `enforce_whitelist_unblocks` (HP-BLOCK + HP-INTEL).

# v4.9.6
- **Update disk bloat:** ba?ar?l? kurulum sonras? `ProgramData\YesNext\CloudHoneypotClient\update\` alt?ndaki `cloud-client-installer*.exe` + `run-update-*.ps1` + Downloads kopyalar? + `TEMP\honeypot_*update_*` temizlenir; indirme art?k user Downloads?a yazmaz; staging?de yaln?zca aktif installer tutulur; daemon auto-enforce prune.
- **Ayarlar ? G?venlik PIN:** yerel PIN belirle / de?i?tir / kald?r b?l?m? (durum + dashboard ipucu); cloud SECTIONS d???nda `GuiLock`.

# v4.9.5
- **`list_services` bo? liste fix (4.9.4 regression):** PowerShell `ConvertTo-Json` ??kt?s? TR locale (`cp1254`) alt?nda `UnicodeDecodeError` ile d???yordu ? `success:true` + `services:[]`. Birincil yol art?k **pywin32 SCM** (`EnumServicesStatus` + `QueryServiceConfig`/`QueryServiceStatusEx`); PS yedek yolu UTF-8 zorlamal?.
- **Uninstall PIN gate:** Control Panel / NSIS kald?rma ?nce GUI PIN (veya PIN yoksa onay); lifecycle `uninstall_*` eventleri; `--uninstall-gate`.

# v4.9.4
- **Contract 1.4.8 Server Management:** `list_services` + `name`/`service_name` on start/stop/restart; protected services refuse; `list_local_users.groups`; rich `list_processes`/`list_sessions` + post-mutate health refresh. Hesap silme yok ? disable.
- **Remote Desktop:** oturum boyunca encode boyutu kilitli; adaptive yaln?z fps/quality; minimum **800?600** taban? ? dashboard?da ??z?n?rl?k z?plamas? giderildi.

# v4.9.3
- **OOB-501 acceptance visibility:** durable `oldest_dropped` / expire / too-large counters; `health/report` ? `offline_urgent_queue{}`; pilot harness (`tests/test_offline_queue_pilot.py`). Flag h?l? default off.
- **GUI:** istatistik kartlar?nda ikon+de?er ayn? sat?r; IP Listeleri tek scrollbar (sayfa y?ksekli?ine oturan tablo).

# v4.9.2
- **OOB-501 ? contract 1.4.7:** `api/10-offline-urgent-queue` hizas? ? yerel TTL 7 g?n prune, payload ?200 KB reddi, batch ?500, `rejected` i?in schema/too_large/expired drop + transient retry; drain art?k ba?ar?l? heartbeat **ve** control WS reconnect sonras?. Flag `security.offline_urgent_queue` h?l? **default off** (pilot drain haz?r).
- **Threat Center UX:** Autoblock e?i?i threat score (0?100); Engellenen IP kart? IP Listeleri ? Engellenen sekmesine gider; Skor kolonu.

# v4.9.1
- **WebRTC JPEG suppression:** ICE+DTLS ger?ekten `connected` oldu?unda bekleyen JPEG temizlenir ve WS sender binary JPEG g?ndermez; fallback durumunda JPEG-WS/HTTP an?nda yeniden devreye girer.
- **10 fps clamp kald?r?ld?:** dashboard `fps=30` istedi?inde client art?k de?eri 10'a d???rmez; JPEG adaptive ceiling 30 fps, WebRTC helper ceiling 60 fps.
- **WebRTC capture pacing:** media capture JPEG-era `fps/quality` de?erlerinden ayr?ld? (30 fps / Q78 ba?lang??); persistent session helper 60 fps'e kadar media iste?ini kabul eder. Stale kareler tek-slot mailbox/WS coalescing ile d???r?l?r.
- **DXGI Desktop Duplication:** WebRTC build profiline opsiyonel `dxcam` eklendi; media modunda ?nce change-driven DXGI capture denenir, yoksa mevcut GDI/ImageGrab/MSS zincirine g?venli fallback olur.
- **Re-offer recovery:** yeni stream offer'lar? serialize edilir; eski peer senkron kapan?r. Yeni peer kurulamazsa agent an?nda `webrtc_reject(reason=peer_setup_failed)` g?nderir ve JPEG fallback'i tetikler.
- **Media telemetry:** `media.encoder`, `effective_capture_fps`, `capture_quality` ve `target_bitrate_bps` additive meta/status alanlar?. Hardware encoder hen?z d?r?st?e ilan edilmez; mevcut aiortc encoder kullan?l?r.
- **P1 security/resilience observe paketi:** signed-heartbeat/ACL drift adaylar?, ETW korelasyon, deception/canary health, network dry-run/version rollback, DPAPI offline queue, identity burst aggregate, operator-key metadata ve read-only TPM capability. T?m? default-off/observe; production enforcement ve floor de?i?medi.

# v4.9.0
- **Release build:** `build.ps1 -WebRTC` profili ile aiortc/AV native runtime i?eren 58.3 MB installer ?retildi; SHA-256 `09082F5497262F688E91B69426943BA5AE1BC3C0A8E69A9FADD810A9BE7F4397`.
- **Remote Desktop v2:** Session 0 art?k her kare i?in yeni proses + ge?ici JPEG ?retmiyor. Se?ili WTS oturumunda tek, kal?c? ve HMAC do?rulamal? helper; g?r?nt?y? bellekte ta??r ve mouse/klavyeyi ayn? oturumda uygular.
- **Ak?c? transport:** Sa?l?kl? agent WebSocket'i g?r?nt?n?n tek yolu; HTTP yaln?z ba?lant? yokken fallback. En g?ncel kare mailbox'? eski kare kuyru?unu ve ?ift upload'? kald?r?r; ger?ek g?nderim/coalesce metrikleri ayr? izlenir.
- **Input v2 + mobil kullan?m:** Move flood kritik `mousedown`/`mouseup`/wheel/key olaylar?n? d???remez. Relative trackpad, direct-touch, tap/double-tap/long-press, g?venli drag ve iki parmak yatay/dikey scroll; ?oklu monit?r negatif origin koordinatlar? desteklenir. Input i?eri?i loglanmaz.
- **Adaptif yay?n:** Capture/send bask?s?na g?re FPS, JPEG kalite ve ??z?n?rl?k kontroll? d??er; stabil pencerede kademeli toparlan?r. Requested/effective de?erler ve gecikme/backpressure telemetrisi status/meta i?inde raporlan?r.
- **WebRTC/H.264 haz?rl???:** Opsiyonel `aiortc`/`av` runtime ile H.264 ?ncelikli WebRTC, strict stream/session signaling, k?sa ?m?rl? cloud STUN/TURN credential t?ketimi ve data-channel input haz?rd?r. Runtime veya cloud signaling yoksa mevcut JPEG/WS otomatik fallback olmaya devam eder. Varsay?lan build WebRTC ba??ml?l?klar?n? i?ermez; yay?n profili `build.ps1 -WebRTC` kullan?r ve runtime eksikse d?r?st?e fail olur.

# v4.8.5
- **Dashboard "Kald?r?l?yor?" tak?l? kalma fix:** Client yerel firewall kural?n? siliyordu ve `pending-unblocks` kuyru?unu bo?alt?yordu, ama `POST /api/agent/block-removed` ACK'i yaln?z `block_ids` ta??yordu. Canl? probe: ayn? endpoint `ip` ile `updated>0` d?n?yor, `block_ids`-only ile ?o?u zaman `updated:0` ? cloud "removing" sat?r?n? kapatm?yor, dashboard butonu sonsuza dek "Kald?r?l?yor?" kal?yor. FW-SYNC art?k ACK'te **hem `block_ids` (int) hem `ips`/`ip`** g?nderir; `updated=0` olursa IP ba??na fallback ACK dener. Yan?t `updated=` art?k loglan?r.
- AutoResponse unblock raporu da `updated=` de?erini loglar (`updated=0` uyar?s?).
- 3 unit test. **Cloud TODO:** `block-removed` remove_pending sat?rlar?n? `block_ids` ile de `updated>0` yapmal?; kuyruk ACK gelene kadar tutulmal? (GET'te silinmemeli).

# v4.8.4
- **Whitelist "eklendi ama g?r?nm?yor" fix (cloud SoT):** frontend-only GUI'de engine nesneleri (`threat_engine`/`auto_response`/`event_watcher`) `None` oldu?undan whitelist ekleme yaln?z yerel setlere yazmaya ?al???yor, buluta **bo? liste** g?nderiyor (mevcut cloud whitelist'i silme riski) ve tablo hep "Whitelist bo?" kal?yordu. Art?k:
  - `_persist_whitelist_to_cloud(add/remove)` bulutun g?ncel `whitelist_ips`'ini okur, yerel setlerle birle?tirir, a??k add/remove deltas?n? uygular ? asla k?r overwrite yapmaz.
  - IP tablosu whitelist sekmesi bulut `threats/config.whitelist_ips`'i de okur (60 sn cache; add/remove sonras? effective response ile tazelenir).
- 5 yeni unit test (merge, wipe korumas?, remove, cache, tokens?z) + canl? round-trip do?rulamas? (1.1.1.1 add ? cloud'da g?r?nd? ? tabloda "G?venli" sat?r? ? remove ? temiz).

# v4.8.3
- **Dashboard'dan GUI PIN y?netimi:** yeni uzak komutlar `set_gui_pin` (pin 4-12 hane, confirm gate, PIN result/log'a asla yaz?lmaz) ve `clear_gui_pin` (PIN s?f?rlama). SYSTEM daemon `gui_lock.json`'u yazar; GUI s?reci dosya mtime'?ndan d?? de?i?ikli?i alg?lay?p hash'i yeniden y?kler ve aktif oturum kilidini d???r?r ? restart gerekmez. Hesap ba?l?ysa (`is_account_linked()`) t?m PIN diyaloglar?nda "Hesab?n?z ba?l? ? PIN kodunuzu dashboard ?zerinden tan?mlayabilir veya s?f?rlayabilirsiniz" ipucu g?sterilir (PIN unutma kurtarma yolu).
- **IP Listeleri h?zl? aksiyon butonlar?:** tablo ba?l???n?n sa? ?st?ne **? IP Engelle** ve **? Whitelist'e Ekle** eklendi. Modal input ile IP al?n?r, `ipaddress` ile do?rulan?r (ge?ersiz ? toast), PIN gate'inden ge?er ve sat?r aksiyonlar?yla ayn? yolu kullan?r (daemon IPC block/unblock + whitelist'in `POST /api/threats/config` sync'i).
- 11 yeni unit test: komut whitelist/confirm, pin format do?rulamas?, set?verify?clear ak???, PIN s?z?nt?s? kontrol?, d?? mtime de?i?ikli?inde relock.

# v4.8.2
- **Ayarlar webhook art?k daemon'da etkili:** GUI Ayarlar sekmesi `webhook_enabled`/`webhook_url`'? buluta (`POST /api/threats/config`) yaz?yordu, ama daemon `_sync_threat_config` bu alanlar? okumuyordu; ger?ek g?nderici (`client_alerts._send_webhook`) yaln?zca yerel `client_config.json` ? `notifications.webhook_*` okudu?u i?in toggle daemon taraf?nda **no-op**'tu. Art?k `_sync_threat_config`, buluttan gelen webhook alanlar?n? yerel `notifications.*`'e k?pr?ler (cloud tek kaynak, forward client'ta). E-posta tercih alanlar?n? (`alert_email_enabled`, `instant_email_for_critical`, `min_severity_for_email`, `daily_digest_enabled`) cloud t?ketir; client apply etmez.

# v4.8.1
- **Koruma detay popup'? ?eli?ki fix:** "Koruma Motoru" chip/kart? **AKT?F** derken detay popup'? **Koruma: OFF** g?steriyordu. K?k neden: popup yerel `process_protection` nesnesini okuyordu; bu nesne yaln?z SYSTEM daemon s?recinde ya?ar, frontend-only GUI'de her zaman `None`. Popup ve `self_protect` kart? art?k chip ile **ayn? kayna??** (daemon STATUS: `motor_ok` + `persistence.self_protection`) kullan?r. Popup ayr?ca motor, Guardian servisi, 24s tamper ve MemoryGuard durumunu tek ekranda tutarl? g?sterir.

# v4.8.0
- **GUI Koruma Durumu ?eridi (Anl?k Durum):** t?m koruma katmanlar? tek bak??ta ? Koruma Motoru, Ransomware Shield, Network Guard, Guardian servisi, honeypot servisleri, karantina. Chip'ler t?klan?nca ilgili detay popup'?/sekmesi a??l?r; "Katmanlar? Y?net" ve "Ayarlar" k?sayollar? eklendi.
- **Yeni Ayarlar sekmesi:** E-posta bildirimleri, otomatik engelleme (e?ik/s?re/limitler), sessiz saatler ve webhook art?k GUI'den y?netilir. T?m de?erler `GET/POST /api/threats/config` ile buluta yaz?l?r; kaydetten sonra efektif config yeniden okunur (bulut = source of truth). ?ema + patch ?retimi `client_settings_util.py`'de, 10 unit test ile.
- **G?venlik Katmanlar? toggle render fix:** `CTkSwitch.select()/deselect()` widget `disabled` iken sessizce no-op ? toggle'lar config `True` olsa bile hep KAPALI g?r?n?yordu. Art?k ?nce `state="normal"` sonra knob set edilir (rollback yolu dahil). Katmanlar ve Ayarlar sekmeleri her ziyarette buluttan yeniden e?itlenir.
- **Daemon STATUS geni?letildi:** `network_guard{present,enabled,running,suspended_processes,baseline_age_sec,internet_ok}` ve `ransomware_running` alanlar? eklendi ? frontend GUI ransomware/nw-guard durumunu motordan okur (yerel engine yokken "OFF" yan?lg?s? biter).
- Guardian/persistence detay popup'?: motor, servis, g?revler, ?z-koruma, 24 saatlik tamper say?s? ve operator-stop durumu tek ekranda.

# v4.7.6
- **Toplam Sald?r? popup fix:** kart bulut `attack-count` (k?m?latif) g?sterirken detay popup yaln?zca yerel `threat_engine`'i okuyordu. GUI frontend-only ?al??t???nda engine `None` oldu?undan popup her zaman "Veri bulunamad?" veriyordu. Yeni `THREAT_TOP` IPC komutu ile motordan ger?ek sald?rgan listesi ?ekilir; motorda anl?k IP context yoksa bo? ekran yerine bulut toplam? + a??klama g?sterilir.
- **G?nl?k log retention:** ana client, threat ve lifecycle loglar? art?k do?rudan `*-YYYY-MM-DD.log` dosyalar?na yaz?l?r; yerel g?n de?i?iminde yeni dosyaya ge?er ve yaln?zca son 7 takvim g?n?n? tutar.
- Daemon + Guardian i?in gece yar?s? rename yar???n? ?nlemek amac?yla klasik timed rename yerine do?rudan tarihli dosya kullan?l?r.
- `update-install.log` aktif/liveness ad? korunur; helper ba?lang?c?nda eski tarihli sat?rlar `update-install-YYYY-MM-DD.log` ar?ivlerine ayr?l?r ve 7 g?n retention uygulan?r.
- GUI ?Loglar? A?? aksiyonu g?ncel tarihli client logunu a?ar. Eski `.1`/`.2` rotasyonlar? retention s?resi dolunca temizlenir.

# v4.7.5
- **Update/tamper handoff hotfix:** `update-and-install.ps1` art?k `update_in_progress.lock` dosyas?n? yeni daemon `Ensure-DaemonMotor` ile haz?r olduktan sonra temizler. ?nceden lock daemon boot'tan ?nce siliniyor; planl? installer kapan??? yeni motor taraf?ndan `unexpected_exit` / `agent_tamper` say?l?yordu.

# v4.7.4
- **IPC health hotfix:** daemon `STATUS` olu?tururken `get_persistence_status()` tekrar ayn? `:58632 STATUS` soketini ?a??r?yordu. Tek-thread control server recursive self-call kuyru?uyla doluyor; GUI/Guardian motor sorgular? timeout oluyor ve ?ok say?da `CLOSE_WAIT` b?rak?yordu. STATUS art?k yerel daemon durumunu override olarak ge?irir ve kendi soketini probe etmez. Regression test eklendi.

# v4.7.3
- **Operator-approved containment (hard safety):** Network Guard detection is **always alert-only**. Cloud config cannot enable `auto_contain` / `auto_kill` / `auto_restore`. Suspend only via confirmed `suspend_process` (exact `pid` + image/path + `process_start_time`); `resume_process` releases.
- **GUI Control Center:** new **G?venlik Katmanlar?** tab ? ransomware / canary / Network Guard toggles write immediately via `POST /api/threats/config`, rollback on failure; daemon applies on `threat_config_updated` WS push.
- **Count/action UX:** tracked-IP card and popup share one blocked?watching snapshot; active services card uses real PORT_TABLOSU total (no hardcoded /5); honeypot Start/Stop in detail; custom share Remove; unknown Windows service Stop; whitelist mutations persist to cloud.

# v4.7.2
- **KR?T?K g?venlik hotfix (Network Guard):** 4.7.0/4.7.1 canl? makinede normal uygulamalar? (Chrome/Firefox/Cursor/GameLoop/EdgeWebView) "offline fidye bombas?" san?p **suspend ediyordu ? PC kilitleniyordu.** ?ki k?k neden + bir tasar?m karar?:
  - **net_cut false-positive:** `diff_connectivity`, internet d??mese bile g?ncel adapter listesi bo?ken t?m baseline adapterlar?n? "down" say?yordu. Art?k `net_cut` yaln?z ger?ek internet eri?im kayb?nda (`internet_lost`) True olur; adapter down/VPN-Wi-Fi churn yaln?z bilgi ama?l?.
  - **Otomatik containment KAPATILDI (varsay?lan):** `auto_contain=false`, `auto_kill=false`, `auto_restore=false`. Network Guard art?k tespit edip **yaln?z alarm** g?nderir (`ransomware_offline_suspect`, severity=warning); s?re? dondurma/a? de?i?tirme yap?lmaz. Operat?r dashboard'dan inceleyip `network_restore`/kill onaylar (kontrat "suspend-first + operat?r onay?").
  - **G??l? imza ?art?:** otomatik containment yaln?z operat?r `auto_contain=true` yapt?ysa VE y?ksek g?venli fidye imzas? (canary/VSS quarantine aktif) varsa ?al???r. Ham yazma h?z? tek ba??na asla s?re? dondurmaz.
  - E?ikler y?kseltildi (150 MB/s, 400 write/s), 60 sn trigger debounce, alarm severity ayr?m? (`_offline_suspect` warning vs `_offline_bomb` critical).

# v4.7.1
- Hotfix (Network Guard): `_run` subprocess ??kt?s? locale/OEM g?venli decode edilir (byte al ? utf-8/cp1254/cp850/latin-1). TR locale'de cp1254 decode hatas? `collect_adapters`/`collect_firewall` ??kt?s?n? yutuyor, baseline `adapters:[]` kal?yordu. PowerShell ??kt?s? UTF-8'e zorland?. Art?k adapter/DNS/route baseline dolu ? a?-kesme tespiti + DNS restore ?al???r.

# v4.7.0
- Contract 1.3.0 ? Network Guard (offline fidye bombas? + a? s?r?c? yedek/kurtarma):
  - **A) Baseline:** `network_baseline.json` (imzal?, HMAC) ? mapped drive / shares / adapter / DNS / route / firewall / connectivity; 30 dk periyot + boot; son 10 s?r?m rotasyonu.
  - **B) Offline tespit:** internetsiz davran??sal skorlama ? a?-kesme (baseline delta) + per-process yazma f?rt?nas? (psutil io_counters) + ??pheli k?ken; a?-kesme + FS-f?rt?nas? ? canary beklemeden tetik.
  - **C) Containment (suspend-first):** ??pheli s?re?ler ?nce **suspend** (kill de?il), acil VSS snapshot, quarantine kayd?; operat?r onay?yla kill/release; opsiyonel `auto_kill`.
  - **D) Kurtarma:** `auto_restore` ile adapter/DNS/firewall/mapped-drive baseline'dan geri y?klenir ? daemon buluta yeniden ba?lan?r.
  - **E) Alarm:** `ransomware_offline_bomb` urgent (`system_context.network_guard`, suspects/network/restored/vss).
  - Komutlar: `network_snapshot`, `network_restore` (confirm), `list_network_baseline`; STATUS/health `network_guard{}` blo?u.
  - Fix: `motor_session.json` version alan? art?k `__version__` ile dolar.

# v4.6.0
- Contract 1.2.0 ? survival + disaster recovery:
  - **Guardian:** `CloudHoneypotGuardian` Windows servisi (SCM restart-on-failure) + motor ?apraz watchdog
  - **Tamper:** beklenmedik motor ??k??? ? `agent_tamper` urgent; dead-man `motor_heartbeat.json`; STATUS/health `persistence{}`
  - **PIN stop:** imzal? `operator_stop.json` ? motor yaln?z update-lock veya PIN ile durur; tray Exit ? motor QUIT
  - **Recovery:** `create_user`, `remote_logon` (reconnect / autologon+reboot), `set_autologon`/`clear_autologon`/`reboot`
  - Autologon: LSA secret + `AutoLogonCount=1`; boot sonras? temizlik + `remote_logon` completion

# v4.5.68
- Hotfix: canary urgent tek zengin yol ? ince `handle_alert` yar??? kalkt?.
- `system_context.ransomware` / `raw_events` / `target_service=SYSTEM` her canary urgent'ta zorunlu.

# v4.5.67
- Contract 1.1.3: Canary urgent alert art?k quarantine/suspect taramas?ndan sonra zengin payload g?nderir.
- `target_service=SYSTEM`, `recommended_action=isolate_host`, structured `raw_events`.
- `system_context.ransomware`: file, change_type, suspects (image/path/PID/cmdline/SHA-256), quarantine ?zeti.
- Health snapshot: `ransomware_quarantine` (active/trigger/entries) ? cloud popup/fleet fallback.

# v4.5.66
- Contract gap close (`honeypot-contract` 1.0.0):
  - `POST /register` ? `protection.block_rules` ProgramData?ya yaz?l?r; boot + ThreatEngine normalize/apply
  - `GET /threats/config` ? `protection.block_rules` SoT (legacy block-rules fetch fallback)
  - Control WS `threat_intel_updated` ? an?nda `ThreatIntelManager.sync_once()` (HTTP poll yedek)

# v4.5.65
- UX: canary tetiklenince yerel tray/toast yok (dashboard/API urgent kal?r) ? kullan?c?y? korkutmama
- OneDrive-backed Documents'a canary konmaz (bulut senkronunda g?r?n?rl?k/kota)
- Canary'lere NotContentIndexed; Explorer Hidden+System (?nceki gibi)
- IFEO asla SearchIndexer / Defender / OneDrive / shell host s?re?lerine uygulanmaz
- GUI metinleri yumu?at?ld? ("tuzak" ? "gizli koruma dosyas?")

# v4.5.64
- SYSTEM motor: ProfileList + scan existing `Users\*\Documents\.cloud-honeypot-canary` so interactive-user canaries are watched (4.5.63 gap found in scenario test)
- Keep quarantine arm-first from 4.5.63

# v4.5.63
- Canary hit: quarantine **immediately armed** (open_files scan time-boxed ?4s) ? STATUS/GUI no longer lag
- SYSTEM motor seeds canaries into interactive users' Documents (not only systemprofile/Public/ProgramData)
- Scenario test on DESKTOP-F5SCL3G: threat-intel OK; canary MODIFIED detected; unlock IPC OK

# v4.5.62
- Canary sertle?tirme: `!000_` sort-bait isimler, Hidden+System dosya+klas?r, README sadece ProgramData
- Canary/VSS hit ? ??pheli s?reci ?ld?r + IFEO karantina; unlock: GUI / `RS_UNLOCK` / `unlock_ransomware_quarantine`
- Canary kontrol aral??? 15 sn; ek TTP (fsutil USN, wevtutil cl, VSS PowerShell, net stop vss)
- Frontend ransomware detay? SYSTEM motor IPC (`RS_STATUS`) ile ?al???r

# v4.5.61

## Cloud threat-intel feed (client consumer)
- Daemon polls `GET /api/agent/threat-intel` (ETag/304), caches under ProgramData.
- Applies firewall IoCs (policy-gated), merges ransomware watch lists, banners/alerts.
- Cloud SoT ? agent does not scrape Abuse.ch/CISA directly.
- Spec for cloud team: `docs/CLOUD_THREAT_INTEL_API.md` + `docs/api/09-threat-intel.md`.

---

# v4.5.60

## Health: disk full / IDE I/O is not ransomware
- `disk_usage_percent` ? capacity only (threshold 98%, no ransomware wording, no threat-engine spam).
- Disk I/O from Cursor/VS Code/browsers/Defender suppressed as benign performance.
- Sustained anonymous writers escalate to `ransomware_suspect` only; real ransomware remains canary/VSS/process layers.

---

# v4.5.59

## Daemon immortality: Watchdog checks SYSTEM motor, not GUI
- Architecture: Session-0 daemon = security motor; per-session tray/GUI = UI only.
- Watchdog no longer treats ?any honeypot-client.exe? as healthy ? requires `motor_ok` / Session 0.
- Interactive `--mode=daemon` no longer converts into a GUI motor (ensures Background + exits).

---

# v4.5.58

## Fix: duplicate tray/GUI instances
- Frontend/tray skipped the singleton check ? two "Security" windows / tray icons.
- Per-session `Local\CloudHoneypotClient_GUI` mutex: second launch exits.
- Named show-event + window restore handoff so the existing UI comes to front.

---

# v4.5.57

## Fix: dashboard detail popup freezes the app
- Root cause (v4.5.53): `overrideredirect` applied after map + `transient` + `grab_set` left the dialog invisible while the main window stayed modal-locked.
- Frameless is set before show; no `grab_set` / no `transient`; lift + focus_force after widgets exist.

---

# v4.5.56

## Immortal self-update (Win10/11/Server 2012+)
- Stage helper as CRLF 7-bit ASCII + PowerShell `Parser` gate before launch (em-dash / UTF-8-no-BOM never ships again).
- Never `copy2` raw Unicode scripts; on stage/parse failure write embedded **emergency ASCII bootstrap**.
- Launch ladder: WMI ? cmd start ? schtasks ? breakaway ? emergency rewrite ? last-resort schtasks bootstrap.
- Preflight: installer size + free disk on ProgramData/ProgramFiles.
- Silent update **refuses to exit** without `update-and-install start` (same as dashboard).
- Heal: detect launcher-only storms and clear stuck lock / re-stage helper.

---

# v4.5.55

## Remote Desktop: frame ACK input piggyback (AGENT_REMOTE_INPUT_HOTFIX)
- Cloud drains `inputs[]` on every `POST /api/remote/frame` / `frame-json` response ? agent was ignoring them ? dead mouse while video worked.
- `upload_remote_frame` returns `{ok, inputs}`; each frame HTTP post applies the batch.
- HTTP frame upload every capture (alongside WS) so the queue does not stall.
- `GET /api/remote/inputs` kept as backup (also while WS is up).

---

# v4.5.54

## Fix: helper script never ran (Unicode broke PowerShell 5.1)
- `update-and-install.ps1` contained em-dashes (U+2014). PS 5.1 UTF-8-without-BOM mis-parsed try/catch ? launcher wrote `launcher start` then died; install never began.
- Script is ASCII-only; staging normalizes dashes/quotes when copying to ProgramData.
- Success now requires `update-and-install start` (not launcher-only).

---

# v4.5.53

## UI: detail popup double title bar
- Dashboard detail popups (Last Attack, etc.) no longer show native Win32 title + custom header together.
- Frameless dialog with one themed header, drag-to-move, Escape to close.

## Also in this train
- v4.5.52 updater fix (fresh `update-install.log` required) ? use dashboard self_update to verify.

---

# v4.5.52

## Fix: self_update helper never started (stuck ?Kurulum ?al???yor?)
- Root cause: `launch_safe_update_install` returned True if PowerShell looked alive for 0.4s; parent exited and the child died in a job object ? no `update-install.log`, banner stuck on installing.
- Now requires a **fresh** log line (`launcher start` token / `update-and-install start`) before success.
- Spawn order: WMI Create ? `cmd start /b` ? schtasks (delete only after log) ? breakaway Popen.
- `self_update` aborts with `helper_log_missing` instead of exiting into a fake install.

---

# v4.5.51

## Fix: stuck update banner
- Obsolete `failed` status (e.g. 4.5.43?4.5.45 while already on 4.5.49) is cleared automatically.
- Banner has an ? dismiss button (clears `update_ui_status.json`).
- Failed banners auto-hide after ~45s; expired status files are deleted.

---

# v4.5.50

## RDP honeypot: NetNTLMv2 hash capture
- When client requests NLA (`PROTOCOL_HYBRID` / `HYBRID_EX`), honeypot accepts CredSSP:
  TLS (self-signed) ? NTLMSSP Type2 challenge ? Type3 ? **hashcat 5600 / John netntlmv2** line.
- Cookie-only probes still report `<rdp_connection_attempt>` (username IoC).
- New module `client_rdp_nla.py`; password field may be up to 2048 chars for hash lines.
- **Not** plaintext RDP passwords (CredSSP sealed credentials remain out of scope).

---

# v4.5.49

## Fix: auto-update stuck on SYSTEM hosts
- `download_installer` no longer writes to `systemprofile\Desktop` (Errno 2); uses ProgramData `update\` staging.
- Helper launch: breakaway detached PowerShell first; schtasks UpdateOnce waits for `update-install.log` before `/Delete` (was cancelling the one-shot).
- Stale `update_in_progress.lock` clears in ~15s when holder PID is dead (was blocking retries for minutes/hours).
- Silent update waits longer for helper log and retries launch once.

---

# v4.5.48

## Remote Desktop prepare path
- `list_local_users`, `list_sessions.can_capture`, `remote_session_prepare` (auth + tscon/WTSConnect + JPEG probe).
- `remote_session_logoff` alias; one-shot password never logged / not stored in history.
- Docs: `docs/api/05-remote-desktop.md` flow (user ? prepare ? stream).

### Note (RDP honeypot passwords)
Cleartext RDP password capture remains a separate CredSSP/NTLM project ? **partially addressed in v4.5.50** (NetNTLMv2 hashes, not plaintext).

---

# v4.5.47

## Cleanup
- Remove unused methods (utils RDP/update helpers, dead client/GUI/helpers/security APIs).
- Delete `_archive/client_networking.py`, scattered `docs/release_notes_v*.md` (CHANGELOG is SoT).
- Drop unused theme tokens (`FONTS`, `CORNER_RADIUS`, purple); ignore local junk logs/probes.

---

# v4.5.46

## Centralization / P1 cleanup
- Threat intel coalesce (sequential PS in one worker); service toggle off-thread.
- Expand `client_winproc` (`run_ps` / `run_ps_script` / `popen_detached`) and migrate GUI + helpers + AR + IPC call sites.

---

# v4.5.45

## Fix: stuck ?Kurulum ?al???yor?
- Helper install heartbeats no longer reset the stale clock (`phase_started_at`).
- Banner auto-dismisses when current version is already ? update target.

---

# v4.5.44

## Stability / performance review
- Periodic Engellenen refresh no longer forces full `netsh name=all` every ~20s (coalesce + throttle).
- Failed firewall scan must not wipe ProgramData / API inventory.
- GUI block/unblock/whitelist off Tk thread; prefer SYSTEM IPC `BLOCK_IP` / `UNBLOCK_IP`.
- `clear_firewall` does not hold cleanup lock across netsh/HTTP (busy flag).
- Motor health cached off UI thread; `client_winproc.run_hidden` centralizes hidden subprocess.
- Architecture doc refreshed: `docs/api/08-architecture.md`.

---

# v4.5.43

## G?ncelleme banner tak?lmas?
- ?Kurulum ?al???yor? helper ?l?nce / NSIS hi? ba?lamay?nca sonsuza kadar kal?yordu.
- Active phase timeout: installing ~10 dk ? `failed` + lock release (?G?ncelleme tak?ld??).
- Boot: h?l? eski s?r?mdeyken `installing` ? `install_did_not_complete`.
- Helper: NSIS beklerken her 5 sn `update_ui_status` heartbeat.

---

# v4.5.42

## T?m?n? temizle: ger?ekten siler (SYSTEM)
- GUI unelevated ? `netsh delete` ?requires elevation? ile sessizce ba?ar?s?z oluyordu; CMD fla? + kural/API de?i?miyordu.
- Fix: GUI `CLEAR_FIREWALL` IPC ? Session-0 Background daemon (elevated) purge + `sync-rules []` + `clear-data`.
- Tek gizli PowerShell `Remove-NetFirewallRule` sweep (CMD ya?muru yok); netsh sadece kalanlar i?in.
- Yetkisiz s?re? store/API?yi bo?altmaz (firewall doluyken yalan UI yok).

---

# v4.5.41

## CMD penceresi fla?lar?
- Firewall `netsh` taramas? (`client_firewall.run_cmd`) art?k `CREATE_NO_WINDOW` + `SW_HIDE` ile gizli ?al???r.
- Engellenen yenileme / daemon poll s?ras?nda siyah konsol a??l?p kapanmaz.
- Birka? di?er gizli olmayan spawn (shutdown, daemon Popen, RDP/helpers) ayn? ?ekilde kapat?ld?.

---

# v4.5.40

## Engellenen listesi d?zeltmesi + T?m?n? temizle
- Root cause: `netsh show rule` without `name=all` fails on Windows ? 0 rules.
- Second cause: `text=True` + cp1254 decode crash on large netsh dumps ? empty stdout.
- Fix: `name=all` + bytes decode (utf-8/cp857/?); failed scan no longer wipes ProgramData store.
- IP table: **T?m?n? temizle** button ? delete all HP-BLOCK/HONEYPOT_* rules + `sync-rules []` + `clear-data` scopes=blocks.

---

# v4.5.39

## GUI: g?ncelleme durumu banner
- Dashboard `self_update` komutu al?nd???nda GUI ?st?nde uyar? band?:
  ?G?ncelleme talimat? al?nd?? ? indirme % ? kurulum ? tamamland?/ba?ar?s?z.
- Daemon (SYSTEM) ? ProgramData `update_ui_status.json` ? GUI poll (1 sn).
- Toast + kal?c? ?st banner; ba?ar? ~12 sn sonra kapan?r.

---

# v4.5.38

## Engellenen = firewall (HP-BLOCK) source of truth
- GUI no longer relies only on empty/stale `blocked_ips.json`.
- On Engellenen refresh: live `netsh` scan ? ProgramData store ? table.
- Numbered dashboard rules (`HP-BLOCK-1010`?) get RemoteIP via per-rule lookup when bulk list omits it.
- Turkish/locale RemoteIP field parsing hardened.

---

# v4.5.37

## Daemon always-on after update (root cause)

Silent/interactive update helper previously **disabled** `CloudHoneypot-Background` + `Watchdog`, then often never re-enabled them on success ? motor dead, dashboard ?poll yok?.

### Fix
- After every install (success **and** fail): `Restore-HoneypotTasks` + `Ensure-DaemonMotor`
- Prefer `schtasks /run CloudHoneypot-Background` (SYSTEM Session 0)
- Wait/re-kick until control port `127.0.0.1:58632` answers
- Then tray (if logon) ? GUI is not the motor

Includes 4.5.36 emergency GUI bridge as safety net.

---

# v4.5.36

## Dashboard offline while GUI says Connected
- GUI ?API Ba?l?? only meant auth worked; **commands/pending poll** is owned by SYSTEM daemon.
- After silent update, if Background daemon is down ? dashboard ??evrimd??? / poll yok?.
- Fix: frontend motor watchdog starts **emergency command bridge** (poll + heartbeat) when daemon won?t come up.
- Connection card: `API var ? motor yok` when auth OK but motor/poll missing.
- Silent helper: prefer `CloudHoneypot-Background` + wait for `:58632` before tray.

---

# Changelog ? Cloud Honeypot Client

Otomatik birle?tirildi: eski 
elease_notes_v*.md dosyalar?.
Kaynak: GitHub Releases + bu dosya.

---

# v4.5.35

## Silent self-update polish
- Dashboard update sonras? g?r?nen `timeout /t 120` CMD penceresi kald?r?ld? (one-shot schtasks hemen siliniyor).
- Sessiz g?ncelleme bitince: SYSTEM daemon + logon varsa **tray** (tam `--show-gui` penceresi yok).

## Included from 4.5.34 (if not yet on host)
- Firewall HP-BLOCK ? Engellenen GUI + periyodik `sync-rules`
- NSIS `/S` mid-install daemon Exec yok; helper installer timeout
- Uzak masa?st?: helper probe 12s, WS ?ncesi JPEG kuyru?u

---

# v4.5.34

## Firewall ? GUI ? API inventory
- Engellenen listesi art?k frontend-only GUI?de de `blocked_ips.json` (ProgramData) ?zerinden doluyor (`threat_engine` ?art de?il).
- Daemon ~15 dk?da bir (ve pending block/unblock sonras?) firewall taramas? ? store ? `POST /api/agent/sync-rules`.
- Store: dosya mtime cache yenileme; kuraldaki t?m RemoteIP?ler.

## Silent self-update (?nceki k?s?r d?ng?)
- NSIS `/S` art?k kurulum ortas?nda daemon ba?latm?yor (helper restart eder).
- Defender exclusion async; helper installer timeout (480s).
- Staging: ?ift `cloud-client-installer-` prefix engellendi.

## Uzak masa?st?
- SYSTEM Session 0 ? RDP oturumu helper probe timeout 3s ? **12s**.
- Helper zorunluyken Session-0 BitBlt fallback kald?r?ld? (siyah ekran tuza??).
- JPEG?ler WS ba?lanmadan ?nce kuyru?a al?n?r (probe kayb? yok).
- Siyah karede input desktop yeniden attach + tscon hedef session.

---

# v4.5.32 ? Silent self_update helper sertle?tirme

- `update_in_progress.lock` varken silent NSIS **daemon ba?latmaz** (helper restart eder) ? installer hang ?nlemi
- SYSTEM helper: `schtasks /Create /RU SYSTEM` one-shot (DETACHED powershell kaybolmas?n)
- Staged installer ad?: `cloud-client-installer-X.Y.Z.exe` (?ift prefix yok)

Not: Dashboard ?Agent bekleniyor? ? client zaten `running`/`completed` POST ediyor; UI status map cloud taraf?nda.

---

# v4.5.31 ? Agent control WebSocket (komut push)

- `wss://?/ws/agent/control` + Bearer ? dashboard komutlar? an?nda
- HTTP `commands/pending` poll emniyet a?? (WS ayaktayken ~30s)
- `command_id` dedup (poll + WS ?ift teslimat)
- Result: WS `command_result` + HTTP `commands/result` (dual)
- `self_update` erken ACK ayn? kanalda

Cloud hub haz?r de?ilse connect fail ? reconnect; poll ?al??maya devam eder.

---

# v4.5.30 ? Engellenen IP?ler ProgramData + firewall hydrate

- `%ProgramData%\YesNext\CloudHoneypotClient\blocked_ips.json` ? kal?c? envanter
- Daemon a??l???nda `HP-BLOCK-*` taran?r ? store + AutoResponse/ThreatEngine hydrate
- GUI Engellenen sekmesi store + firewall envanterinden dolar (RAM ?i?meden y?zlerce IP)
- API `sync-rules` ile e?zamanl?
- Unblock/block store?u g?nceller

---

# v4.5.29 ? IP Listeleri sekmelerinde say?

Aktivite / Engellenen / Whitelist sekme ba?l?klar?nda toplam:
`Activity (3)`, `Blocked (12)`, `Whitelist (1)`.
Refresh ve veri g?ncellemesinde say?lar anl?k g?ncellenir.

---

# v4.5.28 ? Agent API: Bearer auth (no query token)

Token art?k varsay?lan olarak **sadece** `Authorization: Bearer` ile gider.

- `api.legacy_token_query`: **false** (config + kod varsay?lan?)
- GET/POST: query?den `token` kald?r?ld?; POST body `token` uyumluluk i?in duruyor
- Remote Desktop WS: URL?de `?token=` yok; `Authorization: Bearer` header
- Acil rollback: `client_config.json` ? `"legacy_token_query": true`

Cloud dual-read (Bearer ? body ? query) ile uyumlu; dashboard deep-link (`/dashboard?token=`) ayr? konu, de?i?medi.

---

# v4.5.27 ? Installer: Finish checkbox yok, otomatik ba?lat

Kurulum bitince Finish ekran? / ?Launch now? kutusu yok.
Uygulama hemen a??l?r; installer `AutoCloseWindow` ile kapan?r.
Silent: daemon; interaktif: GUI (`--show-gui`).

---

# v4.5.26 ? Logon?da tray (Admin / T?rk?e Windows)

## Sorun
Kimse logon de?ilken Administrator ile giri?te tray d??m?yordu.
T?rk?e Windows `query session` durumunda **Aktif** yazar; agent yaln?zca ?ngilizce **Active** ar?yordu ? oturum ?yok? san?l?p tray tetiklenmiyordu.

## D?zeltme
- Oturum alg?s? locale-aware: Active / Aktif / Aktiv / ?
- `query user` yedek kontrol
- Daemon izleyici: 10 sn poll; logon rising-edge?de hemen tray
- `schtasks /run` yetmezse SYSTEM ? **CreateProcessAsUser** ile Active session?a `--mode=tray`
- Tray LogonTrigger gecikmesi 15s ? **5s**

---

# v4.5.25 ? PIN kald?r yaln?zca PIN varsa

Ayarlar ? G?venlik: **PIN kald?r** men? ??esi sadece PIN tan?ml?ysa g?sterilir.

---

# v4.5.24 ? Ayarlar men?s? + i18n

- Ayarlar popup: **Hesap / G?venlik / Dil / Bak?m** b?l?m ba?l?klar?
- Ba?l? durum rozeti (t?klanmaz); ?ift ?My servers? kald?r?ld?
- Emoji kalabal??? azalt?ld?
- TR: `Sunucular?m`, `Panel verisini temizle`, `G?venlik duvar??`
- Hardcoded `Y?kleniyor?` ? `gui_loading`
- Eksik TR loading_* anahtarlar? tamamland?

---

# v4.5.23 ? disable_all_users = unified AGENT_DISABLE_ALL_USERS_PROMPT

- **Administrator dahil** disable (`exclude` yoksa)
- Params: `logoff` (default true), `exclude` (break-glass)
- Hard-skip: SYSTEM / LOCAL SERVICE / NETWORK SERVICE / WDAGUtilityAccount / DefaultAccount
- `skipped`: `[{username, reason}]`
- K?smi: `completed` + `ok:false`; tam hata: `failed`

---

# v4.5.22 ? disable_all_users ? cloud contract

Cloud `AGENT_DISABLE_ALL_USERS_PROMPT.md` ile hizaland?:

- `skip_protected` (default **true**) ? Administrator / Guest skip
- `logoff_sessions` (alias `logoff`)
- `exclude` + `protected_accounts` skip listesine eklenir
- `skipped` string[] (cloud ?rnekleriyle ayn?)
- K?smi ba?ar? ? `ok: false`
- Concurrent lock + lifecycle begin/ok/failed

**Panik notu:** Cloud varsay?lan? Administrator?? **disable etmez**. Admin?i de kilitlemek i?in send?de:
`skip_protected: false` ve `exclude` i?inden `administrator` ??kar?lmal?  
(veya ayr? `disable_account` / `contain_user`).

---

# v4.5.21 ? `disable_all_users` (panic IR)

Panik: t?m yerel kullan?c?lar? tek komutta disable (Administrator dahil).  
API/dashboard s?zle?mesi: `AGENT_DISABLE_ALL_USERS_API_PROMPT.md`

```json
{ "command_type": "disable_all_users", "parameters": { "logoff": true, "exclude": [] } }
```

Recovery: `reset_password` + `enable_account` (hesap bazl?).

---

# v4.5.20 ? reset_password: dashboard ?ifresi, echo yok

## Ak??
1. Dashboard kullan?c?ya yeni ?ifreyi sorar (?8 karakter).
2. `POST /api/commands/send` ? `{ username, new_password }`
3. Agent: `net user {username} {new_password}`
4. Result (?ifre **d?nmez**):

```json
{
  "command_id": "?",
  "status": "completed",
  "result": { "ok": true, "username": "attacker" }
}
```

## Agent kurallar?
- `new_password` yoksa ? `failed` + `missing_password` (kendi ?retmez)
- `< 8` karakter ? `password_too_short`
- `contain_user` ayn? kural: `new_password` zorunlu, result?ta parola yok

---

# v4.5.19 ? self_update an?nda ACK + fleet g?ncelleme sertle?tirme

## Te?his (v4.5.18)
GitHub?da `cloud-client-installer.exe` **downloadCount = 0** ? sunucular indirmeye hi? ge?memi?.
Yani sorun ?yava? kurulum? de?il; komut ya **poll?a d??memi?** ya da **URL resolve / kilit / size** a?amas?nda tak?lm??.

## Client d?zeltmeleri
- `self_update` / `check_update`: IR poll + **erken ACK** (`status=running`, `update_accepted`) ? dashboard ?pending?de as?l? kalmaz
- `tag` varken GitHub API olmasa bile resmi release URL?si ?retilir
- `force=true`: tak?l? update lock temizlenir
- Yanl?? `size` art?k g?ncellemeyi **engellemez** (sadece uyar?)
- `self_update` ?ncelik s?ras? = kill/logoff ile ayn? (0)

## Dashboard ? fleet komutu (?nerilen payload)
```json
{
  "command_type": "self_update",
  "parameters": {
    "tag": "4.5.19",
    "download_url": "https://github.com/cevdetaksac/yesnext-cloud-honeypot-client/releases/download/v4.5.19/cloud-client-installer.exe",
    "force": true
  }
}
```
`tag` + `download_url` g?nderin; agent?lar?n GitHub API?ye ihtiyac? kalmaz.

## ?nko?ul
- `self_update` handler: **? 4.5.11**
- Motor `commands/pending` poll: **? 4.5.12**
- Daha eski agent?lar remote update alamaz ? manuel installer veya Task Scheduler silent update gerekir

## Beklenen s?re
- Komut al?nma: ~0.5?1 sn (motor ayaktaysa)
- ?ndirme + sessiz kurulum: a? h?z?na g?re 30 sn?birka? dk

---

# v4.5.18 ? IR containment (Administrator dahil)

Sald?r? / s?zma an?nda dashboard?un sunucuyu kurtarma arac?: sald?rgan Administrator olsa bile **an?nda** m?dahale.

## Ne de?i?ti
- **Administrator / Guest / t?m kullan?c?lar** i?in `logoff_user`, `reset_password`, `disable_account` serbest (koruma sadece SYSTEM / LOCAL SERVICE / NETWORK SERVICE).
- Yeni IR komutu **`contain_user`**: tek komutta  
  1) t?m oturumlar? logoff  
  2) g??l? ?ifre ata (`new_password` dashboard?a d?ner)  
  3) hesab? disable (varsay?lan; `disable: false` ile atlanabilir)
- IR sonu?lar? senkron + 0.5 sn poll (?nceki s?r?mden).

## Dashboard kullan?m?
```json
{ "command_type": "contain_user", "parameters": { "username": "Administrator" } }
```
Opsiyonel: `"new_password": "..."`, `"disable": false`, `"session_id": 3`

Ayr? ayr? da kullan?labilir: `logoff_user` ? `reset_password` ? `disable_account` (ayn? poll batch?te hepsi ?ncelikli).

## G?venlik notu
`contain_user` / `reset_password` / `disable_account` i?in dashboard taraf?nda onay diyalo?u ?nerilir (`REQUIRES_CONFIRMATION`). Token ele ge?irilirse bu komutlar kritik ? sunucu imza + onay ?art.

---

# v4.5.17 ? Logoff her hesap + an?nda IR tepkisi

## De?i?iklikler
- **logoff_user**: `Administrator` dahil **t?m** kullan?c? hesaplar? logoff edilebilir (koruma yok). Tek istisna: session 0 (services).
- IR komutlar? (`logoff`, `kill`, `block`, ?) sonu?lar? **senkron** raporlan?r ? dashboard hemen g?r?r.
- IR sonras? **0.5 sn** poll + 45 sn sticky h?zl? tarama.
- Pending fetch timeout 3 sn; domain\user e?le?mesi iyile?tirildi.

## Not
Disable / reset password h?l? `Administrator` i?in korumal?; sadece oturum sonland?rma serbest.

---

# v4.5.16 ? Remote logoff (Disc / ghost sessions)

## Sorun
Dashboard ?Aktif Ba?l? Kullan?c?lar? listesinde kimse logon de?ilken eski Console sat?rlar? g?r?n?yordu; uzaktan logoff ?o?u zaman i?e yaram?yordu.

## D?zeltmeler
- **logoff_user**: `Administrator` art?k sadece hesap disable/reset?te korumal?; oturum sonland?rma (IR) serbest
- Disc / inat?? oturumlar: `logoff` ? `reset session` / `rwinsta`, sonra session h?l? var m? do?rulama
- Ayn? kullan?c? i?in **t?m** session id?ler temizlenir (`query user` + `query session`)
- Ger?ek oturum yoksa net hata: dashboard listesi stale olabilir
- Health: session 0 / services / Listen / kullan?c? ad? bo? sat?rlar raporlanmaz; sahte `login_time=now` kald?r?ld?

## Not
Daemon + `RemoteCommandExecutor` ?al???yor olmal? (?4.5.12 motor poll). G?ncellemeden sonra logoff tekrar deneyin; liste bo?almazsa health report yenilenene kadar bekleyin.

---

# v4.5.15 ? SYSTEM daemon WinError 183 fix

**Hata:**  
`[WinError 183] Halen varolan bir dosya olu?turulamaz: ...\systemprofile\AppData\Roaming\YesNext\CloudHoneypotClient`

**Neden:** Session 0 SYSTEM, Roaming APPDATA alt?nda `makedirs` (dosya/klas?r ?ak??mas?).

**D?zeltme:**
- SYSTEM / Session 0 ? `APP_DIR` = `%ProgramData%\YesNext\CloudHoneypotClient`
- `makedirs` WinError 183?e dayan?kl? (`_ensure_directory`)

---

# v4.5.14 ? onedir (kendi klas?r?)

**Sorun:** `_MEI*` (TEMP veya ProgramData) ? `LoadLibrary: Eri?im engellendi`

**??z?m:** PyInstaller **onedir** ? `python312.dll` art?k  
`C:\Program Files\YesNext\Cloud Honeypot Client\_internal\` alt?nda sabit.

- Runtime extract yok
- Concurrent launch / AV TEMP kilidi yok
- Installer `dist\honeypot-client\*` + `_internal` kurar

---

# v4.5.13 ? PyInstaller TEMP Access denied fix

**Hata:** `Failed to load Python DLL 'C:\WINDOWS\TEMP\_MEI*\python312.dll' ? LoadLibrary: Eri?im engellendi`

**Neden:** Onefile extract `C:\WINDOWS\TEMP` alt?nda; SYSTEM/Admin + AV / execute-from-TEMP politikas? DLL y?klemeyi kesiyor.

**D?zeltme:**
- `runtime_tmpdir` ? `%ProgramData%\YesNext\CloudHoneypotClient\runtime`
- Installer bu klas?r? + Defender exclusion olu?turur

---

# v4.5.12 ? Remote komut / RD poll geri

**Sorun:** GUI `:58632` portuna bind edip PING cevapl?yordu ? herkes ?daemon var? san?yordu ? `commands/pending` ve remote WS hi? a??lm?yordu.

**D?zeltme:**
- STATUS: `daemon` / `motor_ok` / `remote_commands_running` ger?ek motor bilgisi
- Frontend **asla** kontrol portuna bind etmez
- `is_motor_healthy()` ? yaln?zca PING yetmez
- `ensure_daemon_running` ? schtasks Background + motor_ok bekle
- Daemon: RemoteCommands zorunlu construct + poll thread watchdog
- Frontend: 45s motor watchdog

---

# v4.5.11 ? Dashboard self_update

- Remote komutlar: `self_update` + `check_update`
- Dashboard **?imdi g?ncelle** ? pending poll ? hemen silent install (takvim beklemez)
- `force=false` + ayn? s?r?m ? `already_current`
- Sadece resmi GitHub release URL; update lock; lifecycle begin/ok/failed
- `expires_at` / 30 dk TTL deste?i; result sync sonra process exit

---

# v4.5.10 ? GUI performans

- UI thread'de **senkron daemon IPC yok** (protection mode cache + 5s background poller)
- Pulse blink her 800ms IPC ?a??rm?yor (cache)
- Frontend a??l??ta threat/Faz motor stack **kurulmuyor** (daemon zaten motor)
- Prewarm 0.9s/1.6s ? **8s/12s** (Status paint ile yar??m?yor)
- IP tablo: de?i?mediyse rebuild yok; max 60 sat?r
- Session `query` UI thread d???
- `[PERF]` loglar?: page_build, nav, dashboard, ip_table, protection_mode, daemon ping

---

# v4.5.9 ? Logon'da tray otomatik

- Tray g?revi `Users` yerine **Authenticated Users** (Administrator / RDP dahil)
- Daemon oturum izleyici: yaln?zca console de?il, **Active RDP** de tray ba?lat?r
- Sessiz update sonras? etkile?imli oturum varsa Tray de tetiklenir
- Watchdog: daemon varken tray yoksa Logon Tray g?revini ?al??t?r?r

---

# v4.5.8 ? Hizli sekme gecisi

- Tiklamada senkron sayfa build yok (once goster, idle'da doldur)
- Services/Threat acilistan sonra arka planda prewarm
- Threat panelleri 3 dilimde build (UI donmaz)
- Threat'e her donuste security intel yeniden taranmiyor

---

# v4.5.7 ? Lazy GUI pages

- Shell (sidebar + ust bar) hemen acilir
- Sayfa widgetlari ilk ziyarette build edilir (status / threat / services)
- Veriler adim adim yuklenir (attack count, IP tablo, security intel?)
- Threat/Services acilista build edilmez
- Frontend modda motor + agir API h?l? SYSTEM daemon'da; GUI sadece goruntuleme/IPC

Ayrica 4.5.6'dan: RDP buton guncellemesi Tk main thread'e alindi.

---

# v4.5.6 ? Hizli acilis (snappy GUI)

Olculen: `Building main GUI` ? pencere/tray **15?36 sn** suruyordu.

**Kaldirilan engeller:**
- Task Scheduler XML refresh her acilista (artik sadece VERSION degisince)
- schtasks aktivasyon dongusu GUI'de arka plana alindi
- Lifecycle API + exe SHA hash UI thread'den cikti
- ipify / attack-count senkron cagrilar kaldirildi
- Tray menu `refresh_account_link_status` (API) tray baslatmadan once calismiyordu
- RDP netstat probe acilista yok
- PIN dialog build'i bloklamaz; once pencere, sonra PIN
- Tray `after(50)` ile first paint sonrasina alindi

---

# v4.5.5 ? PIN popup stack fix

Tray ikonuna tekrar tiklayinca `wait_window` event loop'u islerken yeni PIN
pencereleri aciliyordu.

- Tek aktif PIN dialog; tekrar tiklayinca mevcut pencere one gelir
- `show_window` busy guard
- Pencere zaten acik + unlock ise PIN sormadan focus

---

# v4.5.4 ? TLS CA / guncelleme alert duzeltmesi

**Sorun:** PyInstaller `Temp\_MEI*\certifi\cacert.pem` yolu RDP/TEMP temizliginde kaybolunca:
- API "Baglanti Yok"
- Guncelleme kontrolu kirmizi alert: `Could not find a suitable TLS CA certificate bundle`

**Cozum:**
- `cacert.pem` ProgramData altina kalici kopyalanir
- `SSL_CERT_FILE` / `REQUESTS_CA_BUNDLE` bu yola isaret eder
- Runtime hook + `resolve_tls_verify()` her HTTPS cagrisinda gecerli bundle kullanir
- GitHub update check/download `verify=` ile ayni bundle'i kullanir

---

# v4.5.3 ? GUI stutter / kasma

- Tray ikonu her health tick'te diskten yeniden aciliyordu ? cache + ayni state skip
- GUI, daemon gelmeden motor (firewall 30s, open-ports, update watchdog) baslatiyordu ? build_gui'de erken PING + frontend skip
- Frontend modda update watchdog GUI'de tekrar baslamasin

---

# v4.5.2 ? Silent auto-update recovery

**Kok neden:** `--silent-update-check` (Task Scheduler SilentUpdater) indirme basinda `schtasks /end CloudHoneypot-SilentUpdater` cagirarak **kendini olduruyordu**. Sonuc:
- `update_in_progress.lock` takili kaliyordu
- Watchdog / SilentUpdater / Background **disable** kalabiliyordu
- Install helper hic baslamiyordu (ProgramData'da `update-install.log` yok)
- Agentler eski surumde mahsur kaliyordu

**Duzeltmeler:**
- SilentUpdater / Updater artik update akisinda `/end` edilmiyor (sadece disable)
- Installer `ProgramData\...\update\` altina stage ediliyor (TEMP yolu kalkti)
- Stale lock: olu PID ? otomatik temizlenir
- Basarisiz helper: gorevler tekrar enable + daemon restart
- SilentUpdater tetikleyicisi CalendarTrigger (15 dk) + `network_required=false`
- Her silent-check basinda `heal_update_machinery()` (kilit + gorev recovery)

---

# v4.5.1 ? GUI acilis hotfix

- Kontrol portu mesgulse GUI artik **sessizce kapanmiyor** (`sys.exit` kaldirildi)
- Kurulum sonrasi GUI hemen acilir; daemon arka planda baslatilir (20sn blok yok)
- `--show-gui` registry LastMode artik `gui` (yanlis `daemon` yazmiyordu)
- Onceki: port mesgul / SHOW path ? pencere gelmiyordu

---

# v4.5.0 ? SYSTEM daemon motor + multi GUI frontend

- **SYSTEM Session 0 daemon** kalici motor: threat, firewall, honeypot, Remote Desktop, API
- **GUI** frontend-only: coklu kullanici ayni anda acabilir; daemon'i oldurmez
- IPC: `127.0.0.1:58632` ? PING / STATUS / HONEYPOT START|STOP|LIST
- Daemon logon olunca artik `os._exit` yapmaz (tray handoff soft)
- `status.json` ? `%ProgramData%\YesNext\CloudHoneypotClient\` (paylasimli)
- Dashboard prompt: `AGENT_SYSTEM_DAEMON_FRONTEND_API_PROMPT.md`

---

# v4.4.53 ? Multi-user GUI stabil + masaustu kisayol opt-in

- **Cok kullanicili RDP:** Tray task `StopExisting` -> `IgnoreNew` (ikinci logon birinci GUI'yi oldurmez)
- **MemoryRestart:** sadece Session 0 daemon; interactive GUI'ye dokunmaz
- **Singleton steal:** baska oturumda interactive client varsa kill yok
- **QUIT** olayi lifecycle log'a yazilir
- Installer: **Desktop Shortcut** varsayilan **kapali** (kullanici isaretlerse eklenir)

---

# v4.4.52 ? Desktop shortcut checkbox + Guest disable

- Installer Components: **Desktop Shortcut** secenegi (varsayilan isaretli); kaldirirsan masaustune kisayol eklenmez
- Start Menu kisayolu her zaman olusur
- **Guest** artik Pasife Al ile kapatilabilir (PROTECTED listeden cikarildi)

---

# v4.4.51 ? Watchdog 2m + MemoryRestart fix + lifecycle API

- **Watchdog:** 15 dk -> **2 dk** (cokme sonrasi hizli kaldirma)
- **MemoryRestart:** yanlis InstallPath duzeltildi (`Cloud Honeypot Client`); exe yoksa Background task fallback
- Script artik `INSTDIR\scripts\memory_restart.ps1` ( _MEIPASS degil )
- **Lifecycle log:** `%ProgramData%\YesNext\CloudHoneypotClient\lifecycle.log`
- API: `POST /api/alerts/lifecycle` (kuyruk + flush) ? prompt: `AGENT_LIFECYCLE_ALERTS_API_PROMPT.md`

---

# v4.4.50 ? Port izleme ? honeypot bait

- Header/tray: honeypot kapal?yken bile EventLog/threat a??ksa **Port ?zleme Aktif**
- Ger?ek port brute-force (RDP 3389 vb.) kurallar aktifken bait?siz de bildir/engelle
- API kural? yoksa yerel `DEFAULT_BLOCK_RULES` (servis ba?? 3 fail / Network 10)
- Aktif servis detay?nda port izleme a??klamas?
- Dashboard seed API: `AGENT_DEFAULT_BLOCK_RULES_API_PROMPT.md`

---

# v4.4.49 ? Remote keyboard fix (Unicode) + CAD SendSAS

- **Klavye:** tek karakter (`a`, `?`, `@`, `?`?) art?k `KEYEVENTF_UNICODE` `SendInput` ? QWERTY VK map yok
- **SendInput** 64-bit g?venli INPUT union (?nceki bozuk struct klavyeyi sessizce d???r?yordu)
- `type_text`, `escape`/`enter`/`ctrl+c` vb. korunuyor
- Log: `[remote-input] t=input event=? key=?`
- **CAD:** `remote_send_sas` ? `sas.dll` `SendSAS(0)` (sentetik ctrl+alt+del de?il)

---

# v4.4.48 ? Remote Desktop session picker

- `remote_stream_start` art?k `session_id` / `username` / `monitor` dinliyor
- 0 interaktif oturum ? `NO_INTERACTIVE_SESSION` (streaming yalan? yok)
- Varsay?lan: Console Active ? Console ? Active RDP ? ilk
- Farkl? WTS session ? `CreateProcessAsUser` helper ile o masa?st?
- Result + WS meta: `session_id`, `username`

---

# v4.4.47 ? Remote command coalesce + faster IP update

- **Remote Desktop:** Ayn? poll batch?inde birden fazla `remote_stream_start` varsa yaln?zca **en yenisi** uygulan?r; eskiler `cancelled` / `SUPERSEDED` olarak raporlan?r
- **Poll docstring** g?ncellendi (1s IR/stream)
- **WAN IP:** Public IP cache **5 dk ? 60 sn**; a? de?i?ince `update-ip` daha h?zl?

---

# v4.4.46 ? Faster silent update checks

- Silent update poll: **30 dk ? 15 dk** (Task Scheduler + in-process watchdog)
- Startup: first check ~**90 sn** after launch (previously waited a full interval)
- Config floor lowered to **5 dk** (`updates.check_interval_minutes`)
- No-update poll is a small GitHub `releases/latest` GET only; installer downloads only when a newer version exists

---

# v4.4.45 ? Update: client must be closable

Self-protect art?k g?ncelleme s?ras?nda kapanmay? engellemez:

- `disarm_for_update()` ? DACL kald?r?l?r, `HoneypotClientGuard` kapat?l?r
- GUI + silent update ??k???nda disarm + QUIT
- `prepare_client_for_installer` her zaman disarm eder
- Update lock varken QUIT asla ignore edilmez (startup grace bypass)
- `graceful_exit` ?nce self-protect?i indirir

---

# v4.4.44 ? Log / runtime fixes

- **Firewall:** `HTTPAdapter` import fixed (`client_firewall.py`) ? agent no longer fails on startup
- **Reconcile:** tunnel-status payload?taki `pending_tunnel_commands` listesi art?k servis san?lm?yor; crash yok
- **Self-protect:** `PROCESS_TERMINATE` i?in `win32con` kullan?l?yor (DACL katman? ?al???r)
- **Tray:** aktif servis yokken spam WARNING kald?r?ld? (i? istasyonunda normal)

---

# v4.4.43 ? Session 0 GUI fix

Kurulum sonras? s?re? ?al???yor ama pencere g?r?nm?yordu: client Session 0 (SYSTEM) i?inde Tk GUI a??yordu; kullan?c? masa?st?nde (Session 1) g?r?nmez.

- Session 0?da GUI a??lmaz; interactive `CloudHoneypot-Tray` / `--show-gui` oturumuna devredilir
- Daemon, ?al??an GUI?yi ?almaz (Watchdog yar??? engellendi)
- Watchdog: herhangi bir client ?rne?i varsa yeni daemon ba?latmaz
- SHOW: Session 0 her zaman `NOGUI` d?ner (yanl?? ?pencere a??ld?? cevab? yok)
- Tray g?revi arg?man?: `--show-gui`

---

# v4.4.38 ? Setup Finish'te Python DLL / _MEI hatasi

## Sorun
- Finish ? Launch: once `--create-tasks` sonra hemen `--show-gui`
- PyInstaller onefile iki kez `%TEMP%\_MEI*` aciyordu ? `Failed to load Python DLL ... python312.dll`

## Fix
- Interactive finish: tek `ExecShell --show-gui` (task'lar app init'te)
- Silent: tek `--mode=daemon` (create-tasks cift launch yok)
- Kill sonrasi 2s bekle (_MEI temizlik)

---

# v4.4.37 ? Uygulama ici hesaba bagla

## Yenilik
- "Hesaba bagla" popup: e-posta + sifre
- Once `POST /api/agent/link-account` (API prompt: `AGENT_ACCOUNT_LINK_INAPP_API_PROMPT.md`)
- Yoksa web fallback: `/account/login` + `/account/link-server`
- Tray menusu ayni popup'i acar; "Web'de ac" hala var

## Not
- Sifre saklanmaz; basarida e-posta cache + account-status sync

---

# v4.4.36 ? GUI tray'e inmiyordu

## Sorun
- `force_gui_onboarding.flag` token olsa bile tray minimize'i engelliyordu
- `--show-gui` bayragi kalici kilitleyebiliyordu

## Fix
- Token varsa onboarding bitmis sayilir ? tray'e izin + bayrak temizlenir
- `--show-gui` artik kalici force flag yazmaz

---

# v4.4.35 ? "Installer'i simdi calistir?" sonrasi installer acilmiyordu

## Sorun
- Evet sonrasi helper once kendi process'ine QUIT gonderiyordu
- Uygulama installer baslamadan kapaninca NSIS hic acilmiyordu
- Gizli powershell yolu da log uretmeden sessiz kaliyordu

## Fix
- Interaktif guncelleme: NSIS installer'i **dogrudan gorunur** ac (UAC/SW_SHOWNORMAL)
- Self-QUIT yarisi kaldirildi; client installer acildiktan sonra cikar
- Silent path helper'i ayri kaldi (arka plan guncelleme)

---

# v4.4.34 ? Kurulum sonrasi GUI acilmiyordu

## Sorun
- Eski/gizli `honeypot-client` ornegi singleton mutex'i tutuyordu
- `--show-gui` DACL yuzunden kapatamayip **exit code 2** ile cikiyordu
- Finish page GUI'yi acamiyordu

## Fix
- Calisan ornege once `SHOW` gonder (pencereyi one getir, yeni process gerekmez)
- Steal basarisizsa `kill-honeypot.ps1 -Force` + taskkill
- Control socket log storm (WinError 10038) duzeltildi
- Installer finish: launch oncesi kill + `--create-tasks`

---

# v4.4.33 ? Token kimligi: ProgramData + asla rastgele yenilenmez

## Sorun
- Token `%APPDATA%` altindaydi; SYSTEM daemon ile kullanici GUI farkli dosya okuyup yeni `/register` yapiyordu
- Load/decrypt fail ? otomatik yeni token (API'de eski "silindi" gibi)

## Fix (client)
- Canonical token: `%ProgramData%\YesNext\CloudHoneypotClient\token.dat`
- Eski AppData / SystemProfile / token.txt ? bir kez migrate
- Dosya varken veya okunamazken **yeni register yok**
- Kayit kilidi (cift register engeli)
- `/register` body: `machine_id` / `hwid` (Windows MachineGuid)
- Mevcut token uzerine farkli token yazma engeli

## API (ayri)
- `AGENT_TOKEN_IMMUTABLE_API_PROMPT.md` ? register upsert by machine_id

---

# v4.4.32 ? GUI guncelleme: indirme sonrasi installer acilmiyordu

## Fix
- UAC artik `ShellExecuteW runas` ile GUI prosesinden aciliyor (gizli powershell UAC'yi yutuyordu)
- Indirme bitince hemen "Installer'i calistir?" soruluyor; Evet ? helper + hizli exit
- Helper basarisiz/UAC iptal ? dogrudan installer fallback
- `update-and-install.ps1` hizlandirildi (kisa grace, hizli kill, 0.8s settle)
- Bloklayan "helper basladi" messagebox kaldirildi (exit gecikiyordu)

---

# v4.4.31 ? Hizli installer kill

## Fix
- PRE-KILL / kill artik tek hizli gecis: taskkill + SeDebug, max 3 kisa tur
- NSIS artik kill scriptini 15 kez tekrar calistirmiyor; process yoksa skip
- Settle sureleri kisaltildi (~15s+ -> ~1-2s tipik)

---

# v4.4.30 ? Installer PRE-KILL fix

## Fix
- `scripts/kill-honeypot.ps1` UTF-8 em-dash (`?`) Windows PowerShell'de string'i k?r?yordu ? `Unexpected token ')'`
- Script art?k ASCII-only; installer PRE-KILL parse hatas? giderildi

---

# v4.4.29 ? Hesap ba?l?l??? API?den

## De?i?iklikler
- `GET /api/agent/account-status?token=` (fallback: `client_status` i?indeki `account_linked`)
- API yan?t? source of truth: `true`/`false` local cache?i g?nceller
- Heartbeat yan?t?nda `account_linked` varsa otomatik sync
- ?st bar: ba?l?ysa e-posta rozeti; ~60 sn + link sonras? poll
- Manuel i?aretleme yaln?zca API yokken offline fallback

---

# v4.4.28 ? Hesaba ba?l? CTA + i18n

## Hesaba ba?la
- Ba?l?ysa ?st barda CTA yerine **Hesaba ba?l?** rozeti.
- Ayarlar ? **Zaten ba?l? ? i?aretle** (mevcut ba?l? sunucular i?in).
- Link sonras? onay sorusu; Evet ? CTA gizlenir.
- ProgramData `account_link.json` (g?ncellemede kal?r).

## i18n
- G?ncelleme diyaloglar?ndaki sabit TR metinler `client_lang.json` (TR/EN).
- Token etiketi `lbl_token` ile dil uyumlu.

---

# v4.4.27 ? G?venli g?ncelleme ak??? (DLL / _MEI hatas?)

## Sorun
?al??an onefile EXE kapanmadan ?zerine yaz?l?nca PyInstaller `_MEI?\python312.dll` y?klenemiyordu.
Kullan?c? d?zeyinde kill, DACL self-protect y?z?nden ?o?u zaman ba?ar?s?zd?.

## Yeni ak??
1. ?ndirme biter ? `update-and-install.ps1` (elevated, ayr? s?re?) ba?lar  
2. Uygulama kendisi ??kar (QUIT)  
3. Helper SeDebug ile kalan s?re?leri ?ld?r?r ve **s?re? yoksa** kurar  
4. Installer WAIT ? `--create-tasks` ? `--show-gui`  

Log: `%ProgramData%\YesNext\CloudHoneypotClient\update-install.log`

---

# v4.4.26 ? Sistem dili + g?ncelleme kill korumas? + ilk kurulum GUI

## Dil
- ?lk a??l??ta Windows aray?z diline g?re (TR/EN).
- Kullan?c? dil de?i?tirirse ProgramData?da saklan?r; g?ncellemede kaybolmaz.

## G?ncelleme ortas?nda kapanma
- `kill-honeypot.ps1` art?k `update_in_progress.lock` varsa (indirme) ?ld?rmez (`-Force` yaln?zca installer).
- MemoryRestart da ayn? kilidi kontrol eder.

## ?lk kurulum ? GUI g?r?n?r
- Tray g?revi ?al??an GUI?yi ?almaz (soft singleton).
- Installer `%ProgramData%` onboarding bayra?? + Tray/Background end.
- `--show-gui` / onboarding?de pencere zorunlu g?r?n?r; tray minimize engellenir.

---

# v4.4.25 ? Onboarding GUI + hesap ba?lant?s? + self-process proof

## Non-silent kurulum
- Silent de?ilse pencere tray?e gizlenmez; kullan?c? token / dashboard kayd? yapabilsin.
- `force_gui_onboarding.flag` (ProgramData) + token yokken pencere zorunlu g?r?n?r.
- Token kopyala / Hesaba ba?la / Dashboard a??ld?ktan sonra tray minimize serbest.

## Hesap / ?oklu sunucu (Account)
- ?st barda **Hesaba ba?la** + token kopyala (Link server talimat?).
- Tray: Dashboard a?, Hesaba ba?la, Token?? kopyala, sunucu ad?.

## Self-process (HMAC)
- Her `health/report` ? `agent_runtime` / `self_process` (pid, exe_path, proof).
- Kendi sat?r: `is_agent_self` + `self_proof`; isim taklidi ? `name_spoof_candidate`.
- `kill_process` kendi PID ? self-refuse (isme g?re blanket protect yok).

---

# v4.4.24 ? G?ncelleme indirme ?imha? d?zeltmesi + daha s?k kontrol

## Sorun
GUI ?G?ncellemeleri Denetle? ile indirirken uygulama kapan?yordu.

**K?k neden:** `update_in_progress.lock` kullan?c? `APPDATA` alt?ndayd?.  
`CloudHoneypot-SilentUpdater` **SYSTEM** olarak ?al???p kilidi g?rm?yor ? indirme ortas?nda `kill-honeypot` / QUIT.

## D?zeltmeler
- Kilit art?k **ProgramData** (makine geneli) ? GUI + SYSTEM ayn? dosya
- ?ndirme s?ras?nda kilit heartbeat (15 sn)
- Silent update: kilidi **indirmeden ?nce** al?r; s?re? ?ld?rme **yaln?zca indirme bitince**
- ?ndirme s?ras?nda SilentUpdater + MemoryRestart + Watchdog **durdurulur**
- S?r?m kontrol?: **30 dk** (Task Scheduler SilentUpdater PT30M + in-process watchdog)
- Mevcut kurulumlarda startup?ta SilentUpdater aral??? yenilenir

## Config
```json
"updates": {
  "auto_check": true,
  "check_interval_minutes": 30
}
```

---

# v4.4.23 ? Uzak masa?st? siyah ekran (RDP disconnected / input desktop)

Dashboard kan?t? (`/api/remote/status`): `has_frame:false`, `live:false` ? viewer WS a??k ama agent JPEG g?ndermiyor.

## K?k neden
RDP oturumu **Disconnected** iken (veya thread input desktop?ta de?ilken) GDI/ImageGrab **siyah** bitmap d?ner; client kareyi bilerek g?ndermez ? dashboard ?Yay?n ba?lat?l?yor??.

## D?zeltme
- Capture thread: `OpenInputDesktop` + `SetThreadDesktop`
- Session state log (Active / Disconnected)
- Disconnected / siyah karede bir kez `tscon <sid> /dest:console` (masa?st? yeniden ?izilsin)
- Probe karesini WS kuyru?una da koy; WS ba?lan?nca son iyi kareyi tekrar g?nder
- HTTP probe ba?ar?s?zsa `frames_sent` yalan s?ylemesin

## Not
`tscon ? /dest:console` fiziksel konsolu k?sa s?re agent oturumuna alabilir ? uzak masa?st? i?in gerekli trade-off.

---

# v4.4.22 ? Aylarca uptime: RAM / thread korumas?

Sald?r? trafi?i alt?nda s?n?rs?z b?y?yebilecek yap?lar ve thread f?rt?nas? giderildi.

## Kritik
- Honeypot rate-limiter: idle key eviction + max 10k key
- Honeypot accept: max **48** concurrent handler / servis (fazlas? drop)
- `unique_ips` set: max **5000** (MemoryGuard trim)
- Alert batch: API down iken hard-cap **1000** (eski drop)
- Dedup map: hard-cap **20k** + her flush?ta temizlik
- Urgent/auto-block API raporlar?: bounded pool (8 worker / 64 pending)
- Auto-response `_blocks`: max **500** in-memory
- Threat IP pool LRU: blocked IP?ler de evict edilebilir
- GDI capture: `finally` ile HDC/HBITMAP s?z?nt?s? yok; log spam azalt?ld?
- FP tuner: stale IP?ler ger?ekten siliniyor
- MemoryGuard: honeypot limiter + unique_ips + auto blocks kay?tl?

## Beklenen
Aylarca a??k sunucuda RAM?in sald?r? yo?unlu?unda kontrols?z ?i?memesi; process kitlenmesi riskinin d??mesi.

---

# v4.4.21 ? Daha h?zl? IR (kill / logoff)

S?zma an?nda dashboard?dan gelen `kill_process` / `logoff_user` 10 sn poll y?z?nden ge? uygulan?yordu.

## De?i?iklikler
- Komut poll: **10s ? 1s** (`threat_detection.command_poll_interval`)
- IR komutlar? rate-limit d???: kill, logoff, block_ip, disable_account, stop_service, lockdown?
- Ayn? poll batch?inde kill/logoff **?nce** ?al???r
- Health report kill/logoff yolunu **bloklamaz** (async)
- `taskkill` / `logoff` timeout 5s

## Beklenen
Dashboard ? Kill/Logoff ? agent ? ~1 sn i?inde uygular.

---

# v4.4.20 ? `clear_firewall` remote command

Dashboard Hesap ? Bak?m ?Firewall bloklar?n? temizle? art?k `clear_firewall` kuyru?a at?yor; agent i?lemezse `HP-BLOCK-*` Windows?ta kal?yordu.

## De?i?iklikler
- `command_type: clear_firewall` handler (`ALLOWED_COMMANDS` + `_cmd_clear_firewall`)
- T?m `HP-BLOCK-`, `HONEYPOT_BLOCK*`, `HONEYPOT_BLOCK_REMOTE*`, legacy prefix?leri sil
- Yerel blok cache bo?alt + `sync-rules []` + `clear-data` scopes=`blocks`
- `params.ips[]` i?in isim ?ablonlar?yla yedek silme
- `priority: critical` / clear_firewall sonras? poll **? 2 sn**
- `DataCleanupManager` remote executor?a ba?land?

## Acceptance
- Dashboard firewall temizle ? ? 60 sn Windows?ta honeypot block kural? kalmaz
- `POST /api/commands/result` success + `rules_removed`

---

# v4.4.19 ? RDP session=2 capture fix (err 1314)

Log ?rne?i:
`pid_session=2 console=1` + `WTSQueryUserToken(1) failed err=1314` + `ImageGrab failed`

**Sorun:** Agent RDP oturumundayken (session 2) helper yanl??l?kla **physical console (1)** i?in token istiyordu ? privilege yok (1314).

## D?zeltme
- Token helper **yaln?zca Session 0**?da ?al???r; session>0 ise atlan?r
- GDI: BitBlt fail ? desktop window DC; brightness log
- ImageGrab: bbox / primary / all_screens varyantlar?

---

# v4.4.18 ? Siyah ekran: CAPTURE_NO_DESKTOP + Session 0 helper

`AGENT_REMOTE_BLACK_SCREEN_PROMPT.md` uyumu:

Kan?t (`frames_sent=0`, `screen 0?0`, `streaming=true`) i?in:

- **D?r?st start:** probe capture; `screen/capture` 0 veya siyah/tiny JPEG ? `success:false`, `error: CAPTURE_NO_DESKTOP` (streaming yalan? yok)
- **Siyah / &lt;1500B kare g?nderme** (API ?Frame too small?)
- **10 sn frames_sent=0** ? stream fail + stop
- **Session 0:** `CreateProcessAsUser` + `--rd-capture-once` ile interaktif session?dan JPEG
- Probe sonras? ilk HTTP keyframe hemen bas?l?r

Acceptance: ba?ar?l? start?ta `screen.w/h > 0`, birka? saniyede `frames_sent` artar.

---

# v4.4.17 ? Uzak masa?st? siyah ekran d?zeltmesi

Dashboard?da siyah g?r?nt? i?in client taraf? sertle?tirildi:

- **GDI BitBlt** birincil yakalama (ImageGrab yedek)
- **Session 0 / yanl?? oturum** uyar?s? (servis oturumunda capture ?o?u zaman siyah)
- **Siyah kare tespiti** + log
- **JPEG magic** do?rulama (`FFD8?FFD9`)
- **Thread-safe WebSocket**: kareler kuyrukla WS thread?inden g?nderilir (bozuk binary ?nlenir)
- **HTTP keyframe** her N karede (WS kopsa / proxy binary d???rse dashboard cache dolu kals?n)

Log ?rnekleri: `first frame ok`, `Nearly-black frame`, `Session ok`.

---

# v4.4.16 ? Tam s?re? listesi (Notepad++ g?r?n?r)

`AGENT_PROCESSES_FULL_LIST_PROMPT.md`:

- `top_processes` / `top_cpu_processes` art?k **80?150 unique PID** (eskiden dashboard?da ~10 top-CPU)
- Birle?im: top 80 CPU + top 40 RAM + **interactive session uygulamalar?** (0% CPU dahil) + ??pheli
- `top_cpu_processes` alias?? art?k k?salt?lm?yor (15 sat?r bug??)
- Acceptance: Notepad++ a??kken ?60 sn i?inde dashboard listesinde

Log: `processes collected: N` / `report ok ? ? processes=N`

---

# v4.4.15 ? Uzak masa?st? ak?c? WebSocket

`AGENT_REMOTE_DESKTOP_PROMPT.md` uyumu:

- **WebSocket birincil:** `wss://?/ws/remote/agent?token=` ? hello + meta JSON + binary JPEG
- **HTTP fallback:** `POST /api/remote/frame` + `GET /api/remote/inputs` (~300 ms) WS yokken
- Hedef **~6 fps** (max 10), JPEG q?35, kare ? ~320 KB
- Girdi: `mousedown` / `move` / `mouseup` (s?r?kle), `wheel`, `click`, `dblclick`, `type_text`, `key`
- UI rozeti: WebSocket (ye?il) / HTTP fallback (turuncu)

---

# v4.4.14 ? Uzak masa?st? durum paneli

- Tehdit sekmesinde **Uzak Masa?st?** kart?: Haz?r / Yay?n aktif / Kullan?lam?yor
- FPS, ??z?n?rl?k, kare/girdi say?lar?; yay?n ba?lay?nca toast
- Yerel **Durdur** (acil kesim) ? ba?latma yaln?zca Dashboard?dan
- Repo: `DASHBOARD_CLEANUP_API_PROMPT.md` (temizlik API dashboard prompt?u)

---

# v4.4.13 ? Login?liyken oturum raporu hi? ba?lam?yordu

**K?k neden:** `CloudHoneypot-Background` (`--mode=daemon`) kullan?c? oturumu g?r?nce GUI?ye ge?iyor ama `start_delayed_api_sync()` ?a?r?lm?yordu. Tray de cmdline?da `--mode=daemon` g?r?p health?i atl?yordu ? **kimse `active_sessions` g?ndermiyordu**.

## D?zeltme
- Daemon?GUI (logon) path?inde `start_delayed_api_sync()` eklendi
- Tray UI-only health fallback (4.4.12) + daemon health (4.4.11) korunuyor

---

# v4.4.12 ? Tray UI-only da oturum raporlas?n

v4.4.11 daemon?a HealthMonitor ekledi; pratikte tray h?l? ?daemon var? deyip health?i atl?yor, daemon logu da g?r?nmeyebiliyor ? oturum yine gitmiyordu.

## D?zeltme
- Tray UI-only: ServiceManager/firewall atlan?r, **HealthMonitor + RemoteCommands mutlaka ba?lar**
- Daemon path (4.4.11) korunur
- Log: `Faz 3 started (tray-ui: ?)` + `report ok ? sessions=N`

---

# v4.4.11 ? Aktif oturumlar daemon?da raporlanm?yordu

**Sorun:** Daemon + Tray (UI-only) mimarisinde `HealthMonitor` hi? ba?lat?lm?yordu. Tray ?daemon halleder? diye atl?yor, daemon ise health/sessions kodunu hi? ?al??t?rm?yordu. Sonu?: giri? yapm?? olsan?z bile dashboard?da **Aktif Ba?l? Kullan?c?lar = 0**.

## D?zeltme
- `run_daemon()` art?k Threat + RemoteCommands + **HealthMonitor** ba?lat?yor
- ?lk health report hemen g?nderiliyor (`force_report`)
- Log: `report ok ? sessions=N processes=M`

---

# v4.4.10 ? G?ncelleme indirme yar?? durumu d?zeltmesi

**Sorun:** "G?ncellemeleri Denetle" ile indirme ~%20?%25 iken t?m client ?rnekleri kapan?yor, indirme yar?da kesiliyordu.

**K?k neden:** `CloudHoneypot-SilentUpdater` (veya saatlik watchdog) kendi indirmesini bitirince `prepare_client_for_installer()` ?a??r?p QUIT + `kill-honeypot.ps1` ile **t?m** `honeypot-client` s?re?lerini ?ld?r?yordu ? GUI indirmesi de dahil.

## D?zeltmeler
- ?ndirme s?ras?nda `update_in_progress.lock` kilidi
- Silent updater / watchdog kilit varken atlan?r
- ?ndirme ba??nda yaln?zca SilentUpdater/Updater g?revleri durdurulur (Background/Tray ?ld?r?lmez)
- S?re? kill yaln?zca installer kullan?c? taraf?ndan ba?lat?l?nca
- Installer ?nce `Start-Process`, sonra kill (Start-Process ka?mas?n)

---

# v4.4.9 ? Uzak Masa?st? (ekran aynas? MVP)

Dashboard **Koruma ? Uzak Masa?st?** i?in agent taraf?.

## Komutlar
- `remote_stream_start` ? JPEG capture loop (fps/quality/max_width)
- `remote_stream_stop` ? yay?n? kes
- `remote_input` ? click / dblclick / type_text / key

## Upload
- `POST /api/remote/frame` (multipart `file`)
- Fallback: `POST /api/remote/frame-json` (base64)

## G?venlik / limit
- Yay?n yaln?zca komut sonras?
- 5 dk idle (input yok) ? otomatik stop
- Input rate limit ~20/sn
- `ctrl+alt+del` OS taraf?ndan engelli (atlan?r)

## Acceptance
- [x] start ? frame upload
- [x] click / type_text
- [x] stop
- [x] Pillow ImageGrab (user session desktop)

---

# v4.4.8 ? V4 update gaps + sessions/processes + stale blocks

## CLIENT_V4_UPDATE_PROMPT ? kapat?lan bo?luklar

| Madde | ?nce | ?imdi |
|--------|------|--------|
| Commands poll | 5s | **10s** |
| events/batch | 60s / max 50 / zay?f summary | **120s / 500** + category + full summary; fail?de buffer korunur |
| Urgent | fire-forget | **3 retry / 30s** + `actions_requested` |
| Urgent cooldown | critical 60s | **5 dk** (threat_type+IP) |
| Config sync | 2 dk | **5 dk** + auto_block limits + channels |
| Health report | const 300 (runtime 60) | **60** |
| Canary check | 10s | **30s** + config paths |
| Remote cmds | eksik start/restart / lockdown alias | **eklendi** |
| Protected accounts | SYSTEM? | + **ADMINISTRATOR** |
| Silent hours TZ | local | **Europe/Istanbul** (zoneinfo) |

## ?nceki 4.4.8 i?leri (ayn? s?r?m)

- `active_sessions` + zengin `top_processes`
- `pending-unblocks` batch ACK
- Bak?m/temizlik men?s? (clear-data)

## Kalan riskler

- Event channel de?i?ince subscription restart gerekir (uyguland?)
- `signed`/WinVerifyTrust h?l? yok (opsiyonel)
- Canary Public Desktop yolu g?r?n?r olabilir ? config?ten kapat?labilir

---

# v4.4.7 ? Bak?m / Temizlik (local + firewall + dashboard)

## ?zet

Dashboard?da eski sald?r?/KPI verisi kalmas?n diye istemci **yerel + firewall + sunucu** temizli?ini s?rayla destekler. Ayarlar men?s?nden ?al??t?r?l?r; otomatik limitler arka planda HP-BLOCK kural say?s?n? ve IP havuzunu s?n?rlar.

## Client

- `DataCleanupManager` (`client_cleanup.py`)
  - Yerel: IP pool, session stats, alert dedup, `threats.log`
  - Firewall: t?m `HP-BLOCK-*` + `sync-rules([])` + `clear-data` scopes=`blocks`
  - Sunucu: `POST /api/agent/clear-data`
  - Tam bak?m: local ? firewall ? server
- Ayarlar men?s?: 4 temizlik eylemi + onay diyaloglar?
- Auto limit: max 500 firewall kural?, max 8000 IP pool (`cleanup.*` config)

## Backend (zorunlu ? dashboard temizli?i i?in)

Detay: [`API_CLEAR_DATA_PROMPT.md`](API_CLEAR_DATA_PROMPT.md)

```
POST /api/agent/clear-data
{ "token", "scopes": ["attacks","blocks","alerts","threat_summary","all"], "reason" }
```

`POST /api/agent/sync-rules` bo? `blocks: []` ile **replace** (listeyi s?f?rla).

Endpoint yoksa client yerel/firewall temizli?i yine yap?l?r; sunucu ad?m? kullan?c?ya uyar? d?ner.

---

# v4.4.6 ? Installer process kill fix

Self-protection DACL + `HoneypotClientGuard` g?revi installer'?n `taskkill`'ini engelliyordu / yeniden ba?lat?yordu.

## D?zeltmeler
- **QUIT control socket:** Installer ?nce `127.0.0.1:58632` ?zerinden `QUIT` g?nderir ? s?re? kendini kapat?r (DACL bypass)
- **SeDebugPrivilege kill:** `scripts/kill-honeypot.ps1` ile admin TerminateProcess (DACL'yi a?ar)
- **HoneypotClientGuard:** Task Scheduler temizli?i art?k `HoneypotClient*` wildcard'?n? da siler
- **Stop flags:** `CloudHoneypotClient\watchdog.token` dahil t?m watchdog yollar?

---

# v4.4.5 ? API s?zle?me hizalamas? (dashboard sync)

AGENT_CLIENT_REVIEW_PROMPT.md referans al?narak ?retim loglar?ndaki uyumsuzluklar giderildi.

## D?zeltmeler

| # | Sorun | D?zeltme |
|---|--------|----------|
| 1 | Auto-block path `v4/auto-block` | Kanonik `POST /api/alerts/auto-block` |
| 2 | Urgent `auto_response` / float score | `auto_response_taken: string[]`, `threat_score: int`, ISO timestamp |
| 3 | Attack payload | `ip` alias eklendi; credential ? urgent'e password aktar?m? |
| 4 | Health field adlar? | `disk_io_*_bytes_sec`, `network_bytes_*_sec`, `open_connections` |
| 5 | Tunnel status | `listen_port` + `port` birlikte g?nderiliyor |
| 6 | events/batch | `batch_id` + kanonik event ?emas? |
| 7 | API 422 | Schema `detail` loglan?yor; 2xx kabul |
| 8 | Open ports | `process` ad? (pid ?zerinden) |
| 9 | Installer kill | 5 turlu watchdog-safe process kill |

## Breaking changes
Yok ? sunucu toleransl? alias'lar korunuyor; client kanonik forma ge?ti.

---

# v4.4.4 ? Sidebar hizalama

- **Sidebar nav:** ?kon + metin d?zeni sabitlendi (sabit ikon s?tunu, metin s?tunu)
- **Tema de?i?kenleri:** Sidebar layout de?erleri `client_gui_theme.py` i?ine ta??nd? (design tokens)

---

# v4.4.3 ? GUI, API & g?ncelleme ak???

- **API ba?lant?:** GET isteklerinde `?token=` query parametresi art?k her zaman ekleniyor
- **Dashboard link:** `?token={full_token}` format?na geri d?nd?
- **Sidebar:** Nav butonlar? hizal? container i?inde yeniden d?zenlendi
- **G?ncelleme UX:** ?lerleme penceresi an?nda a??l?r; installer indirme sonras? kullan?c? onay?yla ba?lar
- **Installer:** ?al??an client ?rnekleri kurulum ba??nda h?zl?ca kapat?l?r

---

# v4.4.2 ? Auto-update fix

- Silent updater now uses `installer_url` from GitHub API (was broken: looked for `download_url`)
- Weekly updater Task Scheduler task fixed (`--silent-update-check` instead of invalid `--mode=updater`)

**Note:** Clients on v4.4.0/v4.4.1 need one manual update (GUI ? G?ncellemeleri Denetle) to receive this fix; after that auto-update works every 2 hours.

---

# v4.4.1 ? Tray, Performance & Debug

**Date:** 2026-07-08

## Tray
- Thread-safe `show_window()` / `minimize_to_tray()` (Tk main thread)
- Windows `SetForegroundWindow` for reliable foreground focus
- Removed session health auto-hide (prevented reopen from tray)
- `TrayManager.notify()` for alert balloons

## Performance
- Dashboard refresh: 10s default (config: `ui.dashboard_refresh_seconds`)
- Lazy security intel: scans only when Threat Center tab is active
- IP table refresh only on Dashboard tab
- `FalsePositiveTuner.start()` periodic cleanup loop
- Non-blocking CPU sampling in PerformanceOptimizer

## Debug
- `--debug` CLI flag (verbose logs, skip consent, skip admin elevation)
- `debug.*` config section unified with `logging.debug_mode`
- DEBUG badge in title bar when active

## Watchdog
- Restart with `--show-gui` so window is visible after crash recovery

---

# v4.4.0 ? Security, Honeypots & Modern UI

**Date:** 2026-07-08

## Security
- TLS certificate verification enabled by default (`api.tls_verify`)
- Bearer token in `Authorization` header; legacy query param optional
- Log redaction for tokens and passwords
- HMAC command signing for remote commands
- `SECURITY.md` added

## Features
- HTTP honeypot (login form decoy, port 80)
- SMB honeypot (minimal negotiate probe, port 445)
- Configurable `services.bind_address`
- Webhook notifications (`notifications.webhook_url`)
- Installer SHA-256 verification option

## UI
- Sidebar navigation (replaces tabs)
- New slate/emerald design system (`client_gui_theme.py`)
- Wider default window (1100?720)

## Quality
- Unit tests (`tests/`)
- GitHub Actions CI
- Pre-commit secret check script
- `OPERATIONS.md` deployment guide

## Migration
1. Update `client_config.json` or reinstall (config merged on upgrade)
2. Revoke old tokens if `client.log` was exposed
3. Backend: enable Bearer auth when ready; set `api.legacy_token_query: false`

---

# v4.0.7 ? Auto-Response Fix: Honeypot Attackers Now Auto-Blocked

**Release Date:** 2025-01-20
**Priority:** ?? Critical Fix

## Problem

Honeypot sald?rganlar? tespit ediliyor ve dashboard'da g?r?n?yordu ama:
- Windows Firewall'a blok kural? **eklenmiyordu**
- API'ye sald?r? IP'si **bildirilmiyordu**
- Sald?rgan engellenmeden ba?lant?lar?na devam edebiliyordu

## Root Causes

### 1. Standalone Alert ? Empty Auto-Response
`ThreatEngine.process_event()` i?inde honeypot credential 90 skor al?yor (critical) ama standalone alert dal? `auto_response=[]` g?nderiyordu. AlertPipeline bo? auto_response g?r?nce `block_ip` ?a??rm?yordu.

**Fix:** `honeypot_credential` event'leri veya `critical` severity durumlar?nda `auto_response = ["block_ip", "notify_urgent"]` set ediliyor.

### 2. Score Degradation ? FAILED_LOGON_TYPES Bug
`honeypot_credential` yanl??l?kla `FAILED_LOGON_TYPES` set'ine eklenmi?ti. 10+ honeypot hit'inde burst detection tetikleniyor ve skor 90'dan 40'a **d???r?l?yordu** (warning seviyesine ? auto_response tetiklenmiyordu).

**Fix:** `honeypot_credential` art?k `FAILED_LOGON_TYPES`'ta de?il. Her honeypot hit sabit 90 skor al?yor.

### 3. Event Field Mapping ? target_service/target_port
Honeypot credential event'leri `service` ve `port` key'lerini kullan?yordu ama `_emit_alert` ve `IPContext.add_event` sadece `target_service` ve `target_port` ar?yordu. Alert'lerde servis/port bilgisi bo? kal?yordu.

**Fix:** Fallback eklendi: `event.get("target_service", "") or event.get("service", "")`

### 4. Missing Alert Title
`_build_title` i?inde `honeypot_credential` event type'? i?in title tan?ml? de?ildi.

**Fix:** `"honeypot_credential": "?? Honeypot Credential Captured"` eklendi.

## Changed Files

| File | Change |
|------|--------|
| `client_threat_engine.py` | Standalone alert auto_response fix, FAILED_LOGON_TYPES fix, field mapping fallback, honeypot title |
| `client_constants.py` | VERSION ? 4.0.7 |

## Expected Behavior After Fix

1. **?lk honeypot hit:** Skor 90 ? severity `critical` ? `auto_response=["block_ip", "notify_urgent"]`
2. **AlertPipeline:** `_execute_auto_response` ? `AutoResponse.block_ip()` ? Windows Firewall inbound block rule
3. **API:** `POST /api/alerts/urgent` + `POST /api/alerts/auto-block` ile bildirim
4. **3+ hit (10 dk i?inde):** `honeypot_brute_force` correlation rule ? ayn? blok aksiyonu
5. **Skor 90'da sabit kal?yor** ? burst logic'e tak?lm?yor

## Test Checklist
- [ ] Honeypot'a ba?lanan ilk IP an?nda firewall'a bloklanmal?
- [ ] Dashboard'da "?? Honeypot Credential Captured" alert g?r?nmeli
- [ ] API'de alerts/urgent ve alerts/auto-block endpoint'lerine bildirim gitmeli
- [ ] Tekrarlayan sald?r?larda skor 40'a d??memeli

---

# ?? Cloud Honeypot Client v4.0.0 ? Advanced Threat Detection & Auto-Response

**Release Date:** February 9, 2026

## ??? Architecture ? 4-Fazl? Tehdit Alg?lama Sistemi

v4.0.0, honeypot istemcisine ger?ek zamanl? tehdit alg?lama, otomatik yan?t, ransomware korumas? ve performans optimizasyonu yetenekleri ekler. **10 yeni mod?l** ile toplam ~5.000+ sat?r yeni kod eklendi.

---

## ? Faz 1 ? Real-Time Threat Detection

### Windows Event Log Watcher (`client_eventlog.py`)
- **EvtSubscribe** push-based real-time event monitoring
- 5 kanal izleme: Security, System, Application, RDP (2 kanal)
- ~25 Event ID takibi (4624/4625/4648/4672/4688/4697/4720/4732/1102 vb.)
- XPath tabanl? verimli sunucu taraf? filtreleme
- Otomatik hesap/IP/logon-type filtreleme (SYSTEM, DWM-, machine accounts)

### Threat Detection Engine (`client_threat_engine.py`)
- IP bazl? ba?lam havuzu (IPContext) ? k?m?latif tehdit skoru
- **THREAT_SCORES** s?zl??? ile 20+ olay tipi skorlamas?
- 4 korelasyon kural?:
  - ?? Brute Force ? Successful Login
  - ?? RDP After Hours (00:00-06:00)
  - ??? Lateral Movement (2+ servise eri?im)
  - ?? Post-Exploitation (login ? service/user creation)
- Z-score decay ile otomatik skor azalmas?
- 24 saat inaktif IP cleanup

### Alert Pipeline (`client_alerts.py`)
- Severity tabanl? routing (critical ? urgent API, high ? normal, warning ? batch)
- Cooldown sistemi ile alert flood ?nleme
- Deque tabanl? alert ge?mi?i (son 200)

---

## ??? Faz 2 ? Automated Response & Remote Commands

### Auto Response (`client_auto_response.py`)
- `block_ip` ? netsh advfirewall ile IP engelleme (s?reli/s?resiz)
- `unblock_ip` ? IP engeli kald?rma
- `logoff_user` ? Aktif oturum sonland?rma
- `disable_account` / `enable_account` ? Hesap y?netimi
- `emergency_lockdown` ? T?m trafi?i engelle, sadece management IP'ye izin ver

### Remote Command Executor (`client_remote_commands.py`)
- Dashboard'dan 14 uzak komut deste?i
- 5 saniyelik polling ile komut bekleme
- **ALLOWED_COMMANDS** whitelist g?venlik katman?
- Korumal? hesaplar/s?re?ler/servisler (SYSTEM, lsass.exe vb.)
- 5 dakika komut expiry s?resi
- Rate limiting (10 komut/dakika)

### Silent Hours Guard (`client_silent_hours.py`)
- 5 mod: Disabled, Night Only, Outside Working, Always, Custom
- Gece-yar?s? ge?en saat aral?klar? deste?i
- Hafta sonu t?m g?n sessiz mod
- IP + Subnet whitelist
- Otomatik aksiyonlar: block_ip + logoff + disable_account

---

## ?? Faz 3 ? Advanced Protection

### Ransomware Shield (`client_ransomware_shield.py`)
- **Katman 1 ? Canary Files**: 45 tuzak dosya (3 klas?r ? 5 dosya ? 3 konum), SHA-256 integrity check
- **Katman 2 ? File System Watchdog**: Toplu rename/modify tespiti
- **Katman 3 ? Suspicious Process Detector**: 9 regex pattern (vssadmin delete shadows, bcdedit, cipher /w vb.)
- **Katman 4 ? VSS Monitor**: Shadow Copy say?s? izleme, silme tespiti
- Skor 100 ? Emergency alert + s?re? ?ld?rme

### System Health Monitor (`client_system_health.py`)
- 9 sistem metri?i izleme (CPU, RAM, Disk, I/O, Network, Process count, Connections)
- **AnomalyDetector**: Hareketli ortalama + z-score > 3.0 anomali tespiti
- Korelasyon: CPU + Disk I/O spike ? kripto madenci ??phesi
- 5 dakikada bir API'ye health snapshot raporu

### Process Self-Protection (`client_self_protection.py`)
- **Katman 1 ? Task Scheduler**: S?re? ?l?rse otomatik yeniden ba?latma
- **Katman 2 ? DACL Korumas?**: `SetProcessShutdownParameters` + DACL ile taskkill engelleme
- **Katman 3 ? Safe Last Breath**: S?re? sonland?r?l?rken g?venli aksiyon
  - Aktif tehdit varsa ? sadece ??pheli IP engellenir
  - Tehdit yoksa ? firewall'a dokunulmaz (sunucu brick olmaz)
  - ?? Tasar?m prensibi: "Primum non nocere"

---

## ?? Faz 4 ? Polish & Production

### Performance Optimizer (`client_performance.py`)
- Adaptif throttling: CPU ?85% ? 2x, ?95% ? 4x interval art???
- Event rate limiting: 50/s max, queue overflow korumas?
- Module interval adjuster callback sistemi
- ASCII sparkline trend verileri (deque maxlen=360, ~3 saat)

### False Positive Tuner (`client_performance.py`)
- Per-event-type cooldown sistemi (failed_logon: 60s, burst: 300s vb.)
- FP_SCORE_ADJUSTMENTS: S?k FP ?reten olaylar i?in skor ?arpanlar?
- Auto-whitelist learning: 50+ event + max_score<10 ? g?venilir IP
- Stale cooldown entry cleanup

### GUI Enhancements
- ?? **Threat Dashboard**: threat_level, events/hour, tracked IPs kartlar?
- ?? **Faz 3 Cards**: Ransomware Shield, CPU/RAM, Protection status
- ?? **Live Threat Feed**: Son 200 sat?r, scrollable
- ? **Quick Response Buttons**: Block IP, Logoff, Disable, Snapshot
- ?? **Silent Hours Indicator**: Aktif/pasif g?sterge
- ?? **Command History**: Son 50 komut, scrollable
- ?? **Active Sessions**: `query session` + yenile butonu
- ?? **Trend Mini-Charts**: ASCII sparklines (????????)

---

## ?? API Endpoints (Backend Gerekli)

| Method | Endpoint | A??klama |
|--------|----------|----------|
| POST | `/api/alerts/urgent` | Kritik alert g?nderimi |
| POST | `/api/events/batch` | Toplu event raporlama |
| POST | `/api/alerts/auto-block` | Otomatik IP block bildirimi |
| GET | `/api/commands/pending` | Bekleyen komutlar? ?ek |
| POST | `/api/commands/result` | Komut sonucu raporla |
| GET | `/api/threats/config` | Tehdit config ?ek |
| POST | `/api/alerts/silent-hours` | Sessiz saat ihlali bildirimi |
| POST | `/api/health/report` | Sistem sa?l?k raporu |
| GET | `/api/threats/summary` | Tehdit ?zeti ?ek |
| PUT | `/api/notifications/preferences` | Bildirim tercihleri g?ncelle |
| POST | `/api/alerts/ransomware` | Ransomware alert bildirimi |
| POST | `/api/alerts/self-protection` | S?re? koruma bildirimi |

---

## ?? Yeni Dosyalar

| Dosya | Sat?r | A??klama |
|-------|-------|----------|
| `client_eventlog.py` | ~442 | Windows Event Log Watcher |
| `client_threat_engine.py` | ~657 | Threat Detection Engine |
| `client_alerts.py` | ~402 | Alert Pipeline |
| `client_auto_response.py` | ~517 | Automated Response |
| `client_remote_commands.py` | ~579 | Remote Command Executor |
| `client_silent_hours.py` | ~401 | Silent Hours Guard |
| `client_ransomware_shield.py` | ~552 | Ransomware Shield |
| `client_system_health.py` | ~393 | System Health Monitor |
| `client_self_protection.py` | ~400 | Process Self-Protection |
| `client_performance.py` | ~419 | Performance Optimizer + FP Tuner |

---

## ?? Bug Fixes

| Sorun | ??z?m |
|-------|-------|
| ProcessProtection constructor TypeError | `alert_pipeline`, `api_client` parametreleri eklendi, `api_url` otomatik t?retilir |
| RansomwareShield `threat_engine` kabul etmiyor | Constructor'a `threat_engine` kwarg eklendi |
| SystemHealthMonitor `threat_engine` kabul etmiyor | Constructor'a `threat_engine` kwarg eklendi |

---

## ?? Notlar

- T?m mod?ller backend API haz?r olmadan da ?al???r (graceful fallback)
- try/except ile API hatalar? sessizce yutulur ? servis kesintisi olmaz
- SilentHoursGuard ve FalsePositiveTuner pasif bile?enlerdir (daemon thread yok)
- Minimum Python 3.9+, ?nerilen: Python 3.12
- Gerekli paketler: `requirements.txt` dosyas?na bak?n?z

---

# ?? Cloud Honeypot Client v3.1.0 - UI Polish & Reliability

**Release Date:** February 8, 2026

## ?? GUI Improvements

### Dark Mode & Layout
- **Unified top bar**: PC/IP, Token, version, Dashboard, Settings, Help ? all in one compact row
- **Custom dark popup menus**: Settings and Help dropdowns now use CTkToplevel dark popups instead of tk.Menu
- **Popup toggle fix**: Menus now properly reopen after first use (replaced FocusOut with global click-away)
- **Service card icon alignment**: Fixed RDP/MSSQL icon extra spacing caused by emoji variation selectors
- **Fixed icon widths**: All service cards now have consistent icon column width (30px, centered)

### Protection Status
- **Accurate header badge**: "Koruma Aktif" (green) shows immediately on startup when services are running ? no more 5-second delay
- **Faster pulse blink**: Status dot now blinks every 800ms (was 5 seconds tied to dashboard refresh)

## ?? Service Auto-Restore

- **Persistent service state**: Services that were running before app close/update are now automatically restarted on next launch
- **Background restore**: Services restart in a background thread so GUI doesn't freeze
- **Consent-aware**: Auto-restore only activates if user consent is accepted
- **Per-service logging**: Each restored service logs success/failure individually

## ?? API Connection Status

- **Real-time tracking**: Dashboard "API Connection" card now reflects actual API call success/failure (`_last_api_ok` flag)
- **Instant disconnect detection**: If API becomes unreachable, status switches to "Disconnected" (red) within one polling cycle
- **No false positives**: Previously showed "Connected" forever after first successful call

## ?? Installer Improvements

### Finish Page
- **Launch checkbox**: "Launch Cloud Honeypot Client now" checkbox on finish page (checked by default)
- **De-elevated launch**: App launches as current user (not admin) via `explorer.exe` ? prevents session/elevation issues
- **No ghost window**: Fixed issue where GUI would flash and disappear into tray after install

### Encoding Fix
- **ASCII-safe finish page**: Replaced Turkish characters with English text in NSIS finish page (NSIS processes .nsi as ACP/ANSI, corrupting Turkish chars like ?, ?, ?, ?, ?, ?)

## ?? Bug Fixes

| Issue | Fix |
|-------|-----|
| Popup menu won't reopen after first use | Replaced `<FocusOut>` with global `<Button-1>` + `_active_popup` tracking |
| Header shows "Koruma Pasif" despite active services | Set header status immediately after service cards build |
| All services reset on every GUI startup | Replaced `write_status([], False)` with `_restore_saved_services()` |
| API status always "Connected" after first success | Track `_last_api_ok` per API call, update dashboard in real-time |
| Installer finish page Turkish chars corrupted | Use English-only text for NSIS finish page defines |
| App launches as admin from installer | Use `explorer.exe` for de-elevated launch via custom NSIS function |
| RDP/MSSQL service card icons misaligned | Remove variation selectors from emojis + fixed 30px icon width |

## ?? Technical Details

- **Commits**: 7 commits in this release
- **Files changed**: `client_gui.py`, `client.py`, `installer.nsi`, `client_constants.py`
- **Compatibility**: Windows 10/11, Python 3.12.6, CustomTkinter 5.2.2

---

# ?? Cloud Honeypot Client v2.8.5 - Performance Optimized

**Release Date:** December 8, 2025

## ?? Performance Improvements

Bu s?r?m uygulaman?n performans?n? ve ak?c?l???n? ?nemli ?l??de art?ran kapsaml? optimizasyonlar i?erir.

### ?? Kritik ?yile?tirmeler

| Sorun | ??z?m | ?yile?tirme |
|-------|-------|-------------|
| Attack count i?in her 10sn'de yeni thread | Thread reuse sistemi | **~8,640 thread/g?n tasarrufu** |
| File heartbeat her 10sn I/O | 60sn'ye optimize edildi | **%83 dosya I/O azaltma** |
| `gc.collect()` GUI thread'inde | Kald?r?ld? | **50-200ms donmalar ?nlendi** |
| HEARTBEAT_INTERVAL ?ift tan?m | FILE/API olarak ayr?ld? | **Bug d?zeltildi** |

### ?? Orta ?ncelikli ?yile?tirmeler

| Sorun | ??z?m | ?yile?tirme |
|-------|-------|-------------|
| Public IP her 60sn HTTP ?a?r?s? | 5 dakika cache sistemi | **%80 HTTP azaltma** |
| ?ki ayr? tunnel loop (sync + watchdog) | Tek loop'a birle?tirildi | **1 thread tasarrufu** |
| GUI IP g?ncelleme spam | Sadece de?i?ince g?ncelle | **Gereksiz render ?nlendi** |
| Log spam | Sadece ?nemli olaylar | **I/O azaltma** |

### ?? Bug Fixes

- **Tray Mode Bug**: Tray modunda pencere kendili?inden a??lma sorunu d?zeltildi
- `minimized_to_tray` flag sistemi eklendi
- `refresh_gui()` art?k tray moduna sayg? g?steriyor

## ?? Optimizasyon Metrikleri

| Metrik | v2.8.4 | v2.8.5 | ?yile?tirme |
|--------|--------|--------|-------------|
| Thread olu?turma/g?n | ~8,640 | ~0 | **%100** |
| Dosya I/O/g?n | ~17,280 | ~1,440 | **%92** |
| HTTP IP ?a?r?s?/g?n | 1,440 | 288 | **%80** |
| GUI health check | 30sn | 60sn | **%50** |
| Attack count poll | 10sn | 15sn | **%33** |
| Dashboard sync | 30sn | 45sn | **%33** |

## ?? Yeni Timing De?erleri

```python
FILE_HEARTBEAT_INTERVAL = 60    # (was 10s)
API_HEARTBEAT_INTERVAL = 60     # API heartbeat
ATTACK_COUNT_REFRESH = 15       # (was 10s)
DASHBOARD_SYNC_INTERVAL = 45    # (was 30s)
DASHBOARD_SYNC_CHECK = 10       # (was 5s)
WATCHDOG_INTERVAL = 15          # (was 10s)
IP_CACHE_DURATION = 300         # 5 min (NEW)
```

## ?? Otomatik G?ncelleme

Client'ler bu s?r?m? otomatik olarak alacakt?r:

- **GUI/Tray Mode**: Her 1 saatte bir g?ncelleme kontrol?
- **Daemon Mode**: Task Scheduler ile her 2 saatte bir (oturum a??k olmasa bile)
- **Silent Update**: Arka planda sessiz g?ncelleme deste?i

## ?? Mod?l G?ncellemeleri

- `client_helpers.py`: IP cache sistemi eklendi
- `client_networking.py`: Tunnel loop'lar birle?tirildi
- `client_constants.py`: Timing sabitleri optimize edildi
- `client.py`: GUI refresh ve tray mode iyile?tirmeleri

## ?? Upgrade Notes

Bu s?r?m geriye d?n?k uyumludur. Mevcut kurulumlar otomatik olarak g?ncellenir.

---

**Full Changelog**: v2.8.4...v2.8.5

