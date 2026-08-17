# Release notes

# Asteria Client 4.9.105 — console pixels (PIX), not gdi+black

Derin-Web lab on 4.9.103 still showed `persistent-user-helper` + black at
~1024×768 / ~8 fps for Default Connect and administrator SID Start. This build
runs the secure-desktop probe on **every** Start (including SID), attaches
Winlogon+winlogon token when locked, prefers DXGI on unlocked Default with a
real DXGI retry after gdi+black, brands healthy frames as `dxgi+…`, and never
pushes a solid-black probe as Live. Helper knobs stay floored at 30/72/1920.

Also includes 4.9.104: real EventLog auth fails report/block without honeypot.

---

# Asteria Client 4.9.104 — real-port RDP attacks without honeypot

RDP with NLA was logged as Security 4625 LogonType **3**, so the agent labeled
it **Network** and never hit RDP block rules (threshold 3). Failures now
classify as RDP (Negotiate/User32, TerminalServices 1149 hint, or type 10),
count only against matching `protection.block_rules`, and POST `/api/attack`
with password `<failed_logon>` even when honeypot listen is off.

---

# Asteria Client 4.9.103 — Default follow is DXGI, not 8 fps GDI black

Derin-Web 4.9.102 Run C (unlocked administrator console) still spawned a
`CREATE_NO_WINDOW` user helper, BitBlt 1024×768 black, and capped JPEG at
8 fps. Default helpers now keep a visible desktop so DXGI can attach, Start
knobs stay at 30/72/1920, encode size can grow off 1024×768, and an unlocked
explorer session is not promoted to Winlogon because GDI was black.

---

# Asteria Client 4.9.102 — lock screen is Winlogon pixels, not user GDI black

Follow Connect with a listed console username was still spawning
`persistent-user-helper` on Default while the input desktop was Winlogon
(Win+L). That helper cannot BitBlt LogonUI, so the viewer stayed 1024×768
black. Follow now uses WTS lock + explorer + LogonUI, prefers the Winlogon
helper unless Default is proven unlocked, and will not reuse a user helper
after switching to Winlogon.

---

# Asteria Client 4.9.101 — remote desktop at video rate

JPEG-WS was a slideshow when WebRTC UDP failed (typical through Cloudflare
TCP 443). Start knobs `fps:12` / `quality:40` plus adaptive treating dropped
stale frames as congestion produced ~8 fps. This build floors Start to
1080p30, keeps coalescing from lowering fps, targets 12 Mbps / 60 fps H.264,
and asks the cloud for TURNS on 443.

---

# Asteria Client 4.9.100 — lock, logon, and logoff like sitting at the PC

Lab on 4.9.99 still showed `persistent-user-helper` + `gdi+black` because a
listed console username made Follow jump to Default while the input desktop
was Winlogon. Follow now waits for Default; lock/logoff respawns the Winlogon
helper with a winlogon.exe token so LogonUI pixels can stream, then DXGI
continues on the same `stream_id` after unlock.

---

# Asteria Client 4.9.99 — LogonUI pixels, video-rate stream

Contract 1.4.69 C-RD-PIX: Default Connect on a locked console must show the
password box, not a solid-black GDI fill advertised as NVENC. Follow promotes
to the Winlogon helper when LogonUI is present or user-helper paints
`gdi+black`. WebRTC is not treated as healthy until one real frame. Capture
targets 60 fps / 8 Mbps so the viewer can stay video-smooth.

---

# Asteria Client 4.9.98 — one update download

Two `asteria-client.exe` processes could both download the installer (JSON gate
TOCTOU + user process treating SYSTEM PID as dead). Named mutex + honest PID check.

---


# Asteria Client 4.9.97 — Follow Connect DXGI, not gdi+black

Dashboard Default Connect (`topology=follow`) was still treating follow as
Winlogon, picking the Logon sibling, and Session-0 GDI painted a black frame
(`gdi+black`). Live console user now attaches Default DXGI helper.

---


Per-version GitHub release write-ups, newest first. Ongoing history: [docs/CHANGELOG.md](docs/CHANGELOG.md).

# Asteria Client 4.9.96 — Intel ACK honesty + installer alias

## Why
Contract 1.4.59/61: 304 threat-intel must not ACK; 200 ACK should report standing
`AR-INTEL-*` count. Legacy `cloud-client-installer.exe` in `self_update` params
must not miss the only published asset.

## Client
- 304: reconcile locally, **no ACK**
- `stats.firewall_current` on apply/ACK
- Rewrite `cloud-client-installer` → `asteria-client-installer.exe`
- `inspect_process` stays off the confirm catalog

---

# Asteria Client 4.9.95 — Named console topology

## Why
Dashboard default Connect still sent `prefer=winlogon` with no `session_id`.
That is correct for an empty/lock host, but on a live Default console it spawned
a Winlogon helper (4.9.93 `SESSION0_HELPER_SPAWN_FAILED`). 4.9.94 skipped the
helper; lock/logon rows still need an explicit **force** so we do not skip when
the operator picked Logon/Lock.

## Client
- `topology=follow` (default Connect, omit SID): skip Winlogon if user Default
- `topology=winlogon` (Logon/Lock row): never skip the helper
- Legacy omit-SID + `prefer=winlogon` = follow (same as 4.9.94)

## Cloud
Contract **1.4.59** — see `cloud/CLOUD_HANDOFF_1.4.59.md`

---

# Asteria Client 4.9.73 — Update path harden + GitHub hygiene

## Why
Fleet updates still hit edge cases after the 4.9.71 folder-ACL fix:
a leftover `update-and-install.ps1` could keep a **SYSTEM-only file ACL**
even when the parent `ProgramData\Asteria\update` folder was writable →
`write_ascii_ps1` failed → TEMP fallback / `stage_helper` storms.

Also finished dropping the `cloud-client-installer.exe` release alias.

## Fixes
- Heal ACLs on **existing children** in update staging; delete bricked helper
- `write_ascii_ps1`: remove/replace when overwrite is Permission denied
- Stage probe checks helper-named `.ps1` writability (not only a tiny probe file)
- Self-update / build publish **only** `asteria-client-installer.exe`
- GitHub: prune old releases; kept tags carry a single installer asset

## Verify on a lab host
1. GUI or dashboard **Check updates** → download progresses past 0%
2. No `launch_helper_failed detail=stage_helper` in `update-install.log`
3. Helper log contains `update-and-install start`
4. Agent comes back on **4.9.73**

---

# Asteria Client 4.9.72 — GUI alerts all at top

## Why
Update failed banner sat above the identity strip, while the motor-stuck
card (`Güncelleme takıldı… Motoru kurtar`) sat below it — two alert cards
in two places.

## Fix
- Wrap update banner + status/error strips in a single `top-alerts` stack
  above the identity/topbar row
- When the update banner already exposes **Motoru kurtar**, do not duplicate
  the button on the error strip

---

# Asteria Client 4.9.71 — Fix `launch_helper_failed` / `stage_helper`

## Why
Hosts on **4.9.68** (and earlier) showed:

`Güncelleme başarısız · 4.9.68 → 4.9.70 · launch_helper_failed`

`%ProgramData%\Asteria\update-install.log` repeated:

`launch_helper_failed detail=stage_helper`

Root cause: `_harden_update_staging` stripped **BUILTIN\Users** from
`%ProgramData%\Asteria\update`. Medium-integrity GUI / SilentUpdater could still
append the log in the parent folder, but could **not** write
`update-and-install.ps1` → permanent stage failure (every ~1 min).

## Fixes
- Stop locking Users out of update staging; heal ACL to SYSTEM/Admins/Users **M**
- Writable probe + fallback dirs: `update` → `update_work` → `%TEMP%\AsteriaUpdate`
- Emergency bootstrap can stage under TEMP when ProgramData is ACL-bricked
- `heal_update_machinery` repairs staging ACL on each tick
- Interactive `self_update`: elevated NSIS fallback if helper still cannot start

## This host (chicken-egg)
4.9.68 cannot self-heal until one successful install lands 4.9.71.
Run the installer once elevated (or reset ACL on `ProgramData\Asteria\update`),
then remote/GUI updates work again.

---

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

---

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

---

# Asteria Client 4.9.68 — Single-flight update gate

## Why
Repeated Update now / GUI check / silent updater clicks could stack overlapping
download/install work. Dashboard and tray then showed conflicting progress, and
orphan locks left hosts stuck mid-flight.

## Fixes
- Machine-wide **operation gate** (`operation_gate.json`) for the UPDATE family
  (dashboard `self_update`, GUI, silent, interactive)
- Busy callers receive the **in-flight snapshot** (phase / %) instead of starting
  a second process
- Remote early ACK no longer reports a fresh “accepted” when an update is already
  running — it reuses the live progress
- GUI “Check for updates” surfaces the existing banner when work is in flight
- Terminal failure / timeout / operator recover clears the gate; helper handoff
  keeps `installing` until install completes or stale reclaim

## Note
Hosts on ≤4.9.67 need one successful land on 4.9.68 to get the gate.
If already stuck: use **Motoru kurtar** (clears lock + gate), then retry Update now.

---

# Asteria Client 4.9.67 — Unstick self_update at 0%

## Why
Dashboard showed **Command received — updating…** with **0% / 0 B** while the
host stayed online (e.g. Derin-Web 4.9.65 → 4.9.66). Download never visibly
moved.

`trust metadata pending` on the resilience card is **cloud observe UI** (null
signing fields) — it does **not** block client download.

Likely client wedges:
1. Progress ticks used **sync** `commands/result` on a shared `requests.Session`
   while heartbeat + download raced → session hang at 0%
2. Sync lifecycle `self_update_begin` blocked the download path
3. Missing URL preferred GitHub API before constructing the release asset URL

## Fixes
- Progress ticks posted on a **daemon thread** (never block the download loop)
- `AsteriaAPIClient` serializes `api_request` with an `RLock`
- Lifecycle begin is fire-and-forget
- Constructed GitHub asset URL runs **before** GitHub API when tag is known
- Download emits `connecting` / `headers_received` phases so UI leaves 0 B ASAP

## Note
Hosts still on 4.9.65 need one successful land on 4.9.67 to get this path.
If stuck mid-flight: dismiss/retry Update now, or clear orphan update lock via
Motoru kurtar if the banner is stuck.

---

# Asteria Client 4.9.66 — Fix remote `launch_helper_failed`

## Why
Dashboard showed download complete (113.6/113.6 MB @ 95%) then
`self_update_failed: launch_helper_failed` (e.g. Derin-Web on **v4.9.61**).

Root causes:
1. **Chicken-egg**: hosts on ≤4.9.61 lack the stronger helper waits/retry; they
   cannot self-heal until one successful install lands newer code.
2. **schtasks /TR overflow**: last-resort Method 6 put `-InstallerPath ...` on the
   task action line (~276 chars > legacy **261** limit) → silent create failure.
3. Emergency bootstrap only tracked legacy `honeypot-client` and did not stop
   `AsteriaGuardian` — motor could resurrect mid-kill.

## Fixes
- Method 6: embed installer args inside the `.ps1`; keep `/TR` short
- Method 7: direct NSIS `/S` via short schtasks + log marker
- Do not delete UpdateOnce tasks immediately on slow start (extra wait / re-run)
- Emergency bootstrap: stop Guardian, kill `asteria-client`/`asteria-gui`
- Longer helper waits; progress tick 98% when helper is live

## Fleet note
Hosts still on **4.9.61** need **one** successful install (RDP `/S` of the already
downloaded installer, or local GUI update) to pick up 4.9.66+. After that, remote
`self_update` uses the hardened launcher.

---

# Asteria Client 4.9.65 — Quiet logs (no more INFO flood)

## Why
Live check showed healthy RAM (~40–70 MB motor / GUI) but today's
`client-YYYY-MM-DD.log` already ~4 MB from INFO spam:
- Full `premium/tunnel-status` JSON every ~15s (endpoint missing from quiet list)
- `[HEALTH] processes collected` every cycle
- Idle `[FW-SYNC] pending_*=0` every poll

Not a classic heap leak — disk / I/O "infinite log" class.

## Fixes
- Quiet API defaults: `verbose_logging=False`; expand frequent endpoints
  (`premium/tunnel-status`, open-ports, events/batch, …); truncate rare bodies
- Throttle HEALTH / idle FW-SYNC INFO lines
- Honor `LOG_MAX_BYTES` / threat log max via within-day `.N` rollover
- Honeypot credential lines only after rate-limit; passwords redacted as `***`
- GUI: `RotatingFileHandler` + cleanup stale `_MEI*` extract dirs

## Verify
- After install: log growth ≪ previous (~KB/hour idle, not MB)
- STATUS `motor_ok`; Working set stable over 10+ minutes

---

# Asteria Client 4.9.64 — Clean start (legacy purge + single tray owner)

## Why
Task Manager often showed two `asteria-client.exe` (SYSTEM) and two `asteria-gui.exe`.
Dual SYSTEM clients are usually **daemon + AsteriaGuardian** (intentional). Dual GUI
is often PyInstaller onefile parent+child (also normal). Real bugs remained:
incomplete YesNext leftovers, Guardian resurrecting motor mid-update kill, and
helper+daemon both starting tray after silent update.

## Fixes
- **Legacy purge**: `remove-legacy-install.ps1` now removes `YesNext\CloudClient`,
  `ProgramData\YesNext`, leftover vendor leaf dirs, and per-user `AppData\YesNext`.
- **Guardian stop**: `update-and-install.ps1` / `kill-honeypot.ps1` stop+delete
  `AsteriaGuardian` before kill rounds so it cannot resurrect motor mid-wipe.
- **Single tray owner**: silent update skips helper `Asteria-Tray` when the new
  motor is ready (or GUI already running); daemon/`--create-tasks` owns handoff.
- **GUI mutex**: session-scoped `Global\AsteriaClient_GUI_s{N}` shared by motor and
  `asteria-gui` (crosses integrity levels); CreateMutex failure is fail-closed.

## Verify
- Task Manager: 1× `asteria-client --mode=daemon` + 1× `--mode=guardian` + GUI
  parent/child pair for onefile is OK.
- No `C:\Program Files (x86)\YesNext\CloudClient`, no `C:\ProgramData\YesNext`.
- After silent self-update: one interactive tray, motor `:58632` healthy.

---

# 4.9.63 — Harden launch_helper_failed

Addresses failed updates that stop with `launch_helper_failed` (helper never wrote `update-and-install start`).

## Fixes
- Longer wait for helper log on silent/SYSTEM updates
- Prefer emergency ASCII bootstrap after launcher-only storms
- `self_update` one automatic emergency retry before failing
- Silent updates never claim success without a live helper log

---

# 4.9.62 — Update brick harden (orphan lock / recover)

Fixes sticky failure banners and blocked upgrades seen on older hosts (e.g. 4.9.54 → 4.9.61).

## Fixes
- Preempt stuck/`orphan_lock_dead_or_foreign_pid` locks before `self_update` (even without `force`)
- **Motoru kurtar** clears the failed banner when the motor is healthy again (no sticky `operator_recover`)
- Orphan lock clear resumes tasks and restarts the motor when it was down

---

# 4.9.61 — Self-update progress ticks (1.4.46)

Dashboard update bar advances while the agent downloads/installs.

## Changes
- `self_update` posts mid-flight `commands/result` ticks: `phase`, `progress_pct`, `bytes_done` / `bytes_total`
- Cadence every 2–3s (immediate on phase change); no >5s silence while `running`
- Terminal: `message:update_started`, `phase:installing`, `restart_required`

---

# 4.9.60 — Service Port Relocate close-out (1.4.45)

Closes gaps vs published `agent/service-port-relocate-client.md`.

## Fixes
- Read **`target_port`** from dashboard `relocate_service` params
- **Golden on disk** before mutate (C-REL-2); cleared on success
- Pre-check **target free**; reject privileged `<1024` and other services’ classic ports (C-REL-6/7)
- Firewall rule **`AR-RELOCATE-<SVC>-<PORT>`**; removed on rollback (C-REL-5)
- Rollback ACK: `status:"rollback"`, `reason:"bind_verify_failed"`, `target_port`
- GUI: relocated / relocating badges + busy / `port_available` hints

FTP remains unsupported in GUI (allowed by contract).

---

# 4.9.59 — Service Port Relocate (contract 1.4.45)

Builds on 4.9.58 `relocate_service` with bidirectional sync + client GUI.

## Command
- Flow: **golden → firewall → config → restart → ≤10s verify → local rollback**
- Success result: `{ status:"ok", service, old_port, new_port }`
- Failure/rollback: command failed + `status:"rollback"` + `reason`
- Single in-flight relocate; forbid targets **53389** and **9XXXX**

## Defaults (4XXXX)
| Service | Safe port |
|---------|-----------|
| RDP | 43389 |
| MSSQL | 41433 |
| MYSQL | 43306 |
| SSH | 40022 |
| FTP | 40021 |

## GUI
- Services page **Kolay Port Taşıma** card
- Prefill: `GET /api/premium/tunnel-status` → `relocate_state.<SVC>.saved_target_port || default_safe_port`
- After local run: `POST /api/agent/relocate-report` (`source:"gui"`) + open_ports refresh ≤5s

---

# 4.9.58 — Easy port relocate (`relocate_service`)

## Client contract
Dashboard easy-port moves now land as **`relocate_service`** (client ≥4.9.44 intent, shipped here):

1. Capture **golden** listen port (registry)
2. **Stop** SCM service
3. **Write** new port config
4. **Start** service
5. **Bind verify** (TCP accept on `127.0.0.1:port`)
6. On failure → **golden rollback** (restore prior port + restart)

## Scope
- Built-in: **RDP / TermService** (`HKLM\...\RDP-Tcp\PortNumber`)
- Advanced: explicit `scm` + `registry_path` + `registry_value`
- Confirm-gated + IR-urgent (same class as `network_adapter_apply`)

## Params (summary)
`service` / `service_name`, `port`, optional `from_port`, `verify_sec` (3–30), `ensure_firewall`, `on_fail=restore_golden`

---

# 4.9.57 — GUI loading honesty

Fixes misleading Off / “data failed” flashes while the Control Center is still refreshing.

## Behavior
- Layer / NetGuard / ransomware toggles show an indeterminate **loading** state until STATUS is known
- Last known status is kept during background polls (no Off flash on every 2s tick)
- Soft “Durum güncelleniyor…” vs hard motor-unreachable banner
- Threat tables, Honeypot cards, and Settings switches wait for load before empty/fail copy

## Installer
- Upload **both** `asteria-client-installer.exe` and `cloud-client-installer.exe`.

---

# 4.9.56 — Threat Center action UX

Completes the GUI polish that was local-only during 4.9.55.

## Threat Center
- Visible labeled row actions (Block / Unblock / Whitelist / Log off / Disable)
- Action columns no longer clipped — tables scroll horizontally when needed
- Accounts section open by default
- Unblock + whitelist from attacker / IP rows

## Included from 4.9.55
- Remote console / Winlogon parity (contract 1.4.43)

## Installer
- Upload **both** `asteria-client-installer.exe` and `cloud-client-installer.exe`.

---

# 4.9.55 — Remote console parity (contract 1.4.43)

Closes client acceptance for dashboard **Logon ekranı** / physical-console UX.

## Winlogon / console capture
- Omit `session_id` → resolve with `WTSGetActiveConsoleSessionId` (never hardcode SID 1)
- Winlogon Start never binds username
- Strict named `WinSta0\Winlogon` attach (no silent Default while claiming Winlogon)
- After logon, stream follows input desktop → Default without a second Start
- Sustained `gdi+black` on Winlogon path still fails honestly

## CAD
- `remote_send_sas` targets the live stream / console session and attaches Winlogon before SendSAS

## Health
- Logon / Lock `pre_logon:true` sibling row remains always present

## Installer
- Upload **both** `asteria-client-installer.exe` and `cloud-client-installer.exe` (legacy ≤4.9.40 self-update fallback).

---

# 4.9.54 — Firewall MMC parity + Network Adapter Admin

Ships contract **1.4.40–1.4.42** client close-out (since 4.9.51).

## Network Adapter Admin (1.4.42)
- **`network_adapter_apply`** — `enable` / `disable` / `set_ipv4` / `set_dns` / `set_config`
- Local watchdog (5–15s): bad apply → golden restore for that adapter (`WATCHDOG_ROLLBACK`)
- `LAST_MGMT_ADAPTER`, `NO_GOLDEN` / `GOLDEN_UNHEALTHY`; pauses `auto_restore_network` mid-apply
- Optional `on_success=accept_surface`

## Firewall Windows MMC parity (1.4.41)
- **`list_firewall` `scope=all`** — full inbound/outbound + profiles + truncation/counts
- **`firewall_rule`** — enable / disable / delete / add (`AR-MANUAL-*`)
- **`firewall_set_profile`** — Domain/Private/Public/`all`

## Firewall Management (1.4.40)
- Asteria inventory path (`list_firewall` / profile set) kept as degraded scope

## Docs
- Future Linux/macOS agent plan: `docs/LINUX_AGENT_PLAN.md`

## Installer
- Upload **both** `asteria-client-installer.exe` and `cloud-client-installer.exe` (legacy ≤4.9.40 self-update fallback).

---

# 4.9.53 — Windows Firewall MMC parity

## Contract 1.4.41
- **`list_firewall` `scope=all`** — inbound + outbound rule tables (enabled/disabled), profiles, honest `counts` + `truncated_*`.
- **`firewall_set_profile`** — Domain/Private/Public or `all`; state + default inbound/outbound; confirm-gated.
- **`firewall_rule`** — `enable` / `disable` / `delete` / `add` (delete/add require cloud `confirm:true`). Dashboard IP adds prefer `AR-MANUAL-*`.

## Notes
- Older agents (<4.9.41) keep Asteria tab + sync; Host refresh fills full rules only after this build.
- Applied Blocks / `block_ip` / `sync_firewall_rules` / `clear_firewall` unchanged.
- Future multi-OS note: `docs/LINUX_AGENT_PLAN.md`.

---

# 4.9.52 — Firewall Management inventory

## Contract 1.4.40
- **`list_firewall`** — Domain/Private/Public profiles + Asteria-prefixed inbound rules (`AR-BLOCK` / `AR-INTEL` / `HP-*` / `HONEYPOT`) including disabled + counts (`inbound_block`, `total_rules`).
- **`firewall_set_profile`** — change one profile state/inbound/outbound (dashboard `confirm:true`); returns a fresh inventory snapshot.

## Notes
- Cloud Firewall Yönetimi page already ships; old clients keep cloud mirror + sync, full inventory needs ≥4.9.40.
- Existing `block_ip` / `unblock_ip` / `clear_firewall` / `sync_firewall_rules` unchanged.

---

# Asteria Client v4.9.51

## GUI
- Sidebar foot: `TR | EN` (centered, larger) → `Motor online | vX.Y.Z` → Minimize to tray.

---

# Asteria Client v4.9.50

## Fixes
- Sidebar: version is a bottom badge (logo lockup no longer crowded).
- Sidebar brand uses official `logo_light.png` lockup; sidebar sticks to viewport.
- Load `ransomware_quarantine.json` with `utf-8-sig` (PowerShell BOM safe).
- Lifecycle startup event reports real process mode instead of `unknown`.

---

# Asteria Client v4.9.49

## Fixes
- Empty ransomware quarantine no longer stays locked forever after VSS with no attributed writer (auto-heal on load/start + post-contain disarm).
- Shadow-copy alerts emit once (no TR + empty-title duplicate).
- After sleep/wake, persistence health uses a 180s resume grace to avoid false `agent_persistence_degraded` cloud alerts.
- `resilience_state.json` migrates polluted `version=test` and sticky `last_recovery_ok=false`.
- Threat-intel `intel_watch` / `intel_banner` events include titles.

## Notes
- Dual `asteria-client.exe` (Guardian service + Background daemon) remains intentional; only the daemon owns IPC `:58632`.

---

# 4.9.48 — Stream progress + update brick recovery

## Remote Desktop (contract 1.4.39)
- Agent emits `stream_progress` on RD WS: `running` → `capture_start` → `capturing` → `ws`/`webrtc` → `live` (or `failed` + error)
- Heartbeat ≤3s while starting; ≤4 events/s; no `live` for black-fill-only frames
- Also covers `remote_session_prepare`

## Update brick recovery
- Orphan `update_in_progress.lock` now resumes Background tasks, clears stand-down, marks banner failed
- Auto-recover in `ensure_daemon_running` / heal / GUI ping
- GUI: **Motoru kurtar** on stalled update / motor unreachable

## Install
`asteria-client-installer.exe` (+ legacy `cloud-client-installer.exe` alias).

---

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

---

# 4.9.46 — Feature guides + anti-brick 1.3/6

## GUI
- i18n feature guides (TR/EN): Network Guard GOLD baseline, Ransomware/canary, Honeypot, Threat, IP Lists, Layers policies
- “Nasıl çalışır?” on Status / Layers / Threat / IP / Honeypot

## Anti-brick (contract 1.4.38)
- C-BRICK-1.3: admin-class auto-disable requires peer admin **or** cloud `undo_mail_path` (fail-closed if missing)
- Built-in Administrator auto-disable additionally requires live undo-mail
- C-BRICK-6: rollback emits `critical_action_rolled_back`

## Install
`asteria-client-installer.exe` (+ legacy `cloud-client-installer.exe` alias).

---

# 4.9.45 — Contract 1.4.37 client close-out

## Envelope v2 (observe-only)
- RFC 8785 JCS + Ed25519 observe verify (`api/12`); golden fixture from contract seed.
- Wire: parse/log only — never emit `version:2`, never hard-fail v1 HMAC commands.
- Cap: `caps.command_envelope_v2` = `off` | `observe` (default off).

## Fleet canary (C-CANARY-1…5)
- Read `fleet_rollout.gates` on every threats/config apply; fail-closed if missing.
- Auto actions require **gate AND** local/config enable (silent hours, NG contain, isolate, offline queue).
- Process-memory only (no durable true-gate cache). Health/report echoes `fleet_rollout`.

## Offline urgent queue
- Enable only when `security.offline_urgent_queue` **and** canary gate true (still default off / PROMOTION_GATES).

## Remote Desktop P0
- Winlogon black: surface `black_frame`; sustained GDI black ≥2s → `winlogon_capture_black`.
- ICE honesty: no `connected` until ICE+DTLS; JPEG fallback stays active until media verified; clear connected on fail.

## Dual-brand sunset
- Docs/comments: legacy HMAC/host cutover target **2026-10-01**; primary `asteria.run` / `asteria-chp-v1` unchanged; legacy verify kept until sunset.

## Install
`asteria-client-installer.exe` (+ legacy `cloud-client-installer.exe` alias).

---

# 4.9.44 — Threat Center inventory + contract 1.4.36

## Threat Center
- **Ağ paylaşımları** and **3. parti servisler** panels (SYSTEM motor IPC).
- Row actions: remove custom SMB share; stop unknown third-party services (protected SCM names refused).

## Contract gap-scan (published 1.4.36 / CLOUD_SURFACE)
- Confirmed signing + anti-brick floors already met.
- Added remote command `sync_firewall_rules` so dashboard inventory sync is no longer rejected.

## GUI polish (bundled)
- IP columns side-by-side; honeypot Aç/Kapat cards + RDP Taşıma Aracı; Status/Layers detail modals; Threat threats table first + accounts accordion.

## Install
`asteria-client-installer.exe` (+ legacy `cloud-client-installer.exe` alias).

---

# 4.9.43 — Dashboard commands apply + GUI UX

## Critical: pending commands
Dashboard `tunnel_start` / `tunnel_stop` (honeypot bait) were rejected as **Unknown command**, so actions looked stuck. Client now applies them via ServiceManager and reports `commands/result` immediately.

Also fixed rate-limit defer that could leave a command_id in the seen-cache **without ACK** (pending forever), sped HTTP safety poll (5s) and honeypot desired-state reconcile (15s), and GUI STATUS refresh (~1.5–2s) after apply.

## GUI UX
- Centered tooltips above icon actions; table row separators; IR info tip; overflow clip.

## Install
Use `asteria-client-installer.exe` (legacy alias `cloud-client-installer.exe` still published for self-update).

---

# 4.9.42 — IP action icons + lighter typography

## Control Center
- Blocked / watching / whitelist row actions use compact Font Awesome icon
  buttons instead of stacked text buttons.
- Hover shows a tooltip (native `title` + CSS bubble).
- Slightly smaller base fonts across the GUI for a less dense layout.

## Included from 4.9.41
- ProgramData\\Asteria migration, installer rename + legacy alias,
  Asteria-* wire identity, uninstall completeness for asteria-gui.exe

---

# 4.9.41 — Asteria brand paths, installer rename, uninstall fix

## Brand / wire identity
- Durable state lives under `%ProgramData%\Asteria\` (YesNext trees copied once on first run / install).
- Scheduled tasks: `Asteria-Background|Tray|Watchdog|Updater|SilentUpdater|MemoryRestart`.
- Service: `AsteriaGuardian`; self-protect: `AsteriaClientGuard`; mutex/events: `AsteriaClient_*`.
- Install/uninstall still purge legacy `CloudHoneypot-*` / `HoneypotClient*` / `CloudHoneypotGuardian`.

## Installer
- Primary asset: `asteria-client-installer.exe`.
- Releases also publish identical `cloud-client-installer.exe` so agents ≤4.9.40 (hardcoded fallback name) can self-update.
- Self-update tries Asteria name first, then legacy.
- Uninstaller embeds kill helper, stops `asteria-gui.exe` + motor, deletes with `/REBOOTOK`, wipes `$INSTDIR`.

## Control Center
- Dashboard + Refresh moved into Help menu; account chip opens dashboard.
- Lock screen: square logo, PIN-first layout; dashboard deep-links (contract 1.4.35).

## Included from 4.9.40
- GUI `client_helpers` shim + exception capture
- Tray brick fix and Control Center UX from 4.9.39

---

# 4.9.40 — GUI module shim + full error capture

## Fixes
- **No module named `client_helpers`:** WebView host installs a Tk-free runtime
  shim before any `client_*` import (PyInstaller still excludes the real
  Tk-heavy module). Token / session / account paths no longer fail on missing
  helpers.
- Expand `asteria-gui` hiddenimports (`client_winproc`, `client_updater`,
  `client_update_ui`, `client_remote_session`, …).

## Observability
- Uncaught process + thread exception hooks → `%LOCALAPPDATA%\Asteria\logs\asteria-gui.log`
- Motor `install_excepthook` now also captures worker-thread exceptions
- Tray hide/show/menu/restart + closing-callback path fully logged
- Locked STATUS polls logged once/minute (not silent); success STATUS throttled

## Included from 4.9.39
- Tray brick fix (async hide off pywebview `closing`)
- Supervised tray revive
- Presence/WS reconnect harden
- Control Center live meters, IP panels, settings switches

---

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

---

# 4.9.38 — brick prevention + durable identity / legacy token remap

## Brick prevention (C-BRICK)
- **C-BRICK-1:** Local critical auto (`disable_account` / auto logoff) requires fresh `account_linked` (cache ≤15 min). Skip + alert `skipped_unlinked`.
- **C-BRICK-2:** Silent hours / time rules default OFF; cloud cannot force silent-hours auto disable/logoff.
- **C-BRICK-6:** Refuse disable of the last enabled local admin; rollback if zero admins remain.
- **Wire:** `commands/result.status` = completed/failed… only; SAM active/disabled only in `result.data`.

## Token persistence (disconnect / ghost Client)
- Rotate failure (5xx/timeout) **keeps** `token.dat` — no quarantine + bare `/register`.
- Schema / CHP2 upgrades **rewrap** locally; cloud rotate only when intentionally rekeying.
- Fingerprint drift on the **same** MachineGuid refreshes the envelope; ambiguous clones refuse auto re-register.
- Unreadable `token.dat` is never overwritten by migrate/save without explicit overwrite.

## Legacy token → cloud remap (1.4.29)
- On boot, leftover AppData/SYSTEM/install tokens that differ from ProgramData are reported via
  `POST /api/agent/rotate-token` (`old_token` → `new_token`, reason `legacy_supersede`) so the
  server can update that Client row onto the durable token (attacks / Account link preserved).
- After 200 or 404, the leftover file is moved aside.

## GUI
- Top bar identity strip: hostname + masked token preview + copy (full token stays on host).
- Account chip / PIN re-auth for link-unlink (from 4.9.37).

---

# 4.9.37 — account re-authentication and durable identity

## Account security
- The signed-in account email is visible in the top-right header with a user icon.
- The Help menu shows **Unlink account** instead of **Link account** when linked.
- Link/unlink operations require a fresh local GUI PIN verification in addition
  to account credentials. An unlocked GUI session alone is not sufficient.

## Token persistence
- Identity schema upgrades rewrap the existing token in the current DPAPI
  envelope instead of rotating it.
- NIC/hardware drift on the same Windows MachineGuid preserves the token and
  repairs only the local binding.
- A failed rotate request never quarantines `token.dat` or creates a new client
  identity. Existing token, client_id, history, and account link are retained.
- Upgrades continue to preserve canonical ProgramData identity:
  `%ProgramData%\YesNext\CloudHoneypotClient\token.dat`.

Cloned machines with a changed/ambiguous MachineGuid are not automatically
re-registered. Run `scripts\reset-agent-identity.ps1` explicitly on the clone.

---

# 4.9.36 — emergency safety + account link tooling
#
## Critical
- Silent Hours no longer auto-disables or logoffs accounts (alert-only). Previous defaults
  (`auto_disable_account=True`, weekend all-day silent, Europe/Istanbul) caused false
  positives that disabled Administrator and stuck servers. **Root cause: CLIENT policy,
  not cloud IR** (cloud disable already requires `confirm:true`).
- Alert pipeline skips `disable_account` auto-actions.
- `disable_account` refuses Administrator/Guest unless `allow_privileged=True` (confirmed IR / GUI).
- Silent Hours defaults: `enabled=False`, `weekend_all_day_silent=False`.

## Ops
- `scripts/link_account_local.py` — link host via `ASTERIA_EMAIL` / `ASTERIA_PASSWORD` env (token from ProgramData).
- `scripts/reenable_administrator.ps1` — `net user Administrator /active:yes` recovery.

## Note
Blank white GUI on some interactive users usually means missing WebView2 Runtime or TEMP extract
policy — install Edge WebView2 Evergreen Runtime, then relaunch `asteria-gui.exe`.

---

# Asteria Client v4.9.35

## Highlights
- **Signing cutover (contract ≥1.4.32):** Command HMAC `asteria-chp-v1`, heartbeat `asteria-heartbeat-v1` (legacy `yesnext-*` still accepted on verify).
- **API rename:** `AsteriaAPIClient` (compat alias `HoneypotAPIClient`).
- **Web Control Center:** Account link/unlink, WinRM/NLA/Defender harden, RDP move, IR logoff/disable, update banner, TR/EN i18n.
- **Brand identity:** Bruno Ace wordmark, logo_set `*_light` for dark UI, tray/installer/exe icons from `logo_set`.
- **GUI bridge harden:** Wait for pywebview API readiness; themed password reveal; fixed sidebar nav heights.

## Install
Run `cloud-client-installer.exe` as Administrator.

## Notes
- Dual-track: `asteria-client.exe` (SYSTEM motor) + `asteria-gui.exe` (interactive WebView).
- Wire ProgramData / task names unchanged (`YesNext\CloudHoneypotClient`, `CloudHoneypot-*`).

---

# Asteria Client v4.9.34

## Asteria brand cutover

- Product display name is **Asteria** (GUI, tray, installer, Start Menu).
- Default API: `https://asteria.run/api` with legacy failover to
  `https://honeypot.yesnext.com.tr/api`.
- New install path: `Program Files\Asteria\Asteria Client\`
- Primary exe: `asteria-client.exe` (still kills/probes legacy
  `honeypot-client.exe`).

## Unchanged wire identities

- ProgramData: `%ProgramData%\YesNext\CloudHoneypotClient`
- Scheduled tasks: `CloudHoneypot-*`
- Command signing: `yesnext-chp-v1`

Contract: **1.4.30+** · Firewall brand: **1.4.31** (`AR-*`)

---

# Cloud Honeypot Client v4.9.33

## Asteria firewall prefix migration

- New firewall blocks are written only as `AR-BLOCK-{ip}`.
- Threat-intel rules are written only as `AR-INTEL-{id}`.
- Unblock, whitelist enforcement, and firewall cleanup remove AR, HP, HONEYPOT,
  and CloudHoneypot legacy rules.
- On first boot, existing `HP-BLOCK-*` and `HP-INTEL-*` rules are migrated
  in-place to AR names, followed by `sync-rules` snapshot reporting.
- Migration is marked complete only after a successful cloud sync.

Contract: **1.4.31** · Minimum client: **4.9.33**

---

# Cloud Honeypot Client v4.9.32

## Highlights

### In-place token rotation (contract **1.4.29**)
- Rekey / identity v2 / fingerprint rebind no longer calls bare `POST /api/register`
  while the old token is known (that created **ghost** Client rows and broke history).
- Flow: mint `new_token` in memory → `POST /api/agent/rotate-token` → **only on 200**
  write `token.dat` (CHP2) + `device_binding.json`.
- Same `client_id` — attacks, alerts, blocks, AccountClient, alias preserved.
- `409 new_token_in_use` → one retry with a fresh uuid; `403 machine_id_mismatch`
  tries fingerprint / omit / MachineGuid; failed rotate quarantines then register.

## Install

Silent: `cloud-client-installer.exe /S`

---

# Cloud Honeypot Client v4.9.31

## Highlights

### GUI cards — hover / click on labels
- Protection chips (Ransomware Shield, etc.) and dashboard stat cards: moving the
  mouse onto the title/`AKTİF` text no longer drops the blue border hover.
- Clicks on labels/icons inside a card now open the same detail as clicking the
  card chrome (Tk Leave-on-child + incomplete child binds).

## Install

Silent: `cloud-client-installer.exe /S`

---

# Cloud Honeypot Client v4.9.30

## Highlights

### Critical — tray never auto-started on this PC
Lab evidence on Windows 10/11 TR:

1. **`CloudHoneypot-Tray` task install failed** — XML had `<LogonType>Group</LogonType>`
   which `schtasks` rejects (`incorrect value LogonType:Group`). Installer deleted the
   old task first, so Tray stayed **missing** (`tray_task: false`, repeated
   `Failed to refresh CloudHoneypot-Tray`).
2. **`query session` exit code 1** with valid Active console stdout — watchdog/daemon
   treated “no interactive user” and never launched tray.

### Fixes
- Remove invalid `LogonType=Group` from Tray task principal
- `install_task`: overwrite with `/F` only (never delete-then-create)
- `has_interactive_user_session` / session id: parse stdout even when rc ≠ 0
- (from 4.9.29) supervised tray icon + watchdog relaunch when frontend missing

## Install

Silent: `cloud-client-installer.exe /S`

---

# Cloud Honeypot Client v4.9.29

## Highlights

### Tray stay-alive (logged-on session)
- Tray icon could vanish while the daemon was still fine; reopening the app
  brought it back because a new frontend started.
- Fixes:
  - Supervised tray loop (restart after crash / explorer `TaskbarCreated`)
  - GUI health check restarts a dead tray thread
  - Scheduled `--mode=watchdog` now relaunches tray when logon has no frontend
  - Close-to-tray race: no full exit while tray is still starting
  - Silent update session detect accepts Turkish `Aktif`

## Install

Silent: `cloud-client-installer.exe /S`

---

# Cloud Honeypot Client v4.9.28

## Highlights

### Critical — unique token per physical host (clone split)
- Two servers sharing one token (same UUID / same account email) usually means an
  unsysprep’d VM clone copied `MachineGuid` and/or `token.dat`.
- `/register` `machine_id` is now a **SHA-256 hardware fingerprint**
  (`MachineGuid` + NIC MACs + SMBIOS UUID + volume serial) — not MachineGuid alone.
- `token.dat` CHP2 + `device_binding.json` bind the token to that fingerprint;
  mismatch → quarantine + fresh enroll.
- **One-time** schema v2 upgrade re-enrolls under the fingerprint so clones that
  already share a token each get a **distinct** Client. Re-link Account on each host
  (Settings → Account link).

### Ops
- `scripts/reset-agent-identity.ps1` — manual identity wipe if needed.
- Prefer sysprep/generalize before sealing images; never bake `token.dat`.

## Install

Silent: `cloud-client-installer.exe /S`

---

# Cloud Honeypot Client v4.9.27

## Highlights

### Installer — FileInUse on `memory_restart.ps1`
- Upgrade no longer pops NSIS Abort/Retry/Ignore when Scheduled Task PowerShell holds `scripts\memory_restart.ps1`.
- `prepare-install-dir.ps1` relocates the whole `scripts\` tree (and kills PowerShell whose command line references install helpers).
- `memory_restart.ps1` is staged via `install-memory-restart.ps1` (rename + retry copy) — never via NSIS `File` (no dialog).
- Main extract uses `SetOverwrite try` so residual AV/handle races skip silently instead of Abort.

## Install

Silent: `cloud-client-installer.exe /S`

---

# Cloud Honeypot Client v4.9.26

## Highlights

### Remote Desktop — Winlogon / Logon screen
- `list_sessions` / health always offer a **Logon / Lock screen** (`pre_logon`) row (sibling of console user when logged on).
- `remote_stream_start` accepts `prefer=winlogon` / `desktop=winlogon` / `pre_logon=true`.
- Named Winlogon attach before OpenInputDesktop; hello capabilities `winlogon` / `pre_logon`.

### Self-update download completion
- Success only when transfer is complete (Content-Length + PE MZ + min size) — not wall-clock timeout.
- Stall timeout for idle sockets only; up to **5** retries with backoff; then launch installer.

### Server users (contract 1.4.22)
- `list_local_users` includes disabled accounts with `status` / `can_enable` / `can_disable` / `counts`.
- `enable_account` / `disable_account` return refreshed `data.user` for cloud toggle UI.

### GUI / account
- Defense policy banner + buttons refresh with active mode (no stale “Yalnız bildir” after Balanced).
- **Settings → Account link**: status, link, unlink, My servers (contract 1.4.23 `unlink-account`).

## Install

Silent: `cloud-client-installer.exe /S`

---

# Cloud Honeypot Client v4.9.25

## Fix — no more plain `.py` sources under Program Files

`honeypot-client.spec` was copying dozens of `client_*.py` files into `_internal` via `datas=`, so the install tree looked like an open source tree.

- Application modules are packaged **only** into the PYZ archive (bytecode)
- `datas=` keeps icons/JSON/`memory_restart.ps1`/update helper only
- Build gate fails if any `client_*.py` appears under `dist/.../_internal`

Note: bytecode is not strong obfuscation against a determined reverse engineer; it stops casual browsing of readable source in Explorer.

---

# Cloud Honeypot Client v4.9.24

## Security — scripts folder attack surface

`Program Files\...\scripts` was world-readable; a local user could run `kill-honeypot.ps1`.

Fixes:
- Kill / prepare / update-and-install **not** installed under Program Files (installer `$PLUGINSDIR` only; self-update stages under ProgramData)
- Leftover helpers deleted on upgrade
- `scripts\` ACL: **SYSTEM + Administrators** only
- Scripts refuse non-elevated execution
- Daemon `QUIT` remains gated (operator_stop / update lock)

Release notes for operators: open the folder as a standard user should no longer list/run kill helpers.

---

# Cloud Honeypot Client v4.9.23

## Installer — FileInUse hardened

Follow-up to 4.9.22 when Session-0 still holds the `_internal` directory:

- Per-file relocate (locked `.pyd` / `.dll` renamed aside → NSIS writes fresh originals)
- Stronger process terminate + longer grace after QUIT (DACL disarm)

Use **v4.9.23+**. If an old installer dialog is still open, click **Durdur**, then run this build.

---

# Cloud Honeypot Client v4.9.22

## Installer — no more FileInUse stalls

Fixes Abort/Retry/Ignore on locked onedir files (e.g. `_internal\win32\servicemanager.pyd`):

1. Stronger kill (any process under install dir)
2. Defender exclusion **before** extract
3. Rename locked `_internal` / exe aside (`.stale_*`), then write a fresh tree
4. Same prep from `update-and-install.ps1` for silent updates

If you still see the dialog on an old installer, cancel and use **v4.9.22+**.

---

# Cloud Honeypot Client v4.9.21

## Remote Desktop — console Winlogon / pre-logon (contract 1.4.21)

- Mirror the Windows logon / lock UI when nobody is logged on (`WinSta0` + `Winlogon`)
- `list_sessions` exposes a `pre_logon` console row with `can_capture=true`
- `remote_session_prepare` falls back to Winlogon instead of `UNSUPPORTED` (use `prefer=existing` to keep the old gate)
- Keyboard/mouse inject after Winlogon attach; desktop re-attaches to `Default` after logon

Cloud/viewer: `honeypot-contract` **1.4.21** → `cloud/REMOTE_DESKTOP_WINLOGON.md` (C-WL-*).

---

# Cloud Honeypot Client v4.9.20

## Remote Desktop — WebRTC smoothness (contract 1.4.20)

Closer to Chrome Remote Desktop fluidity on the agent side:

- **Raw RGB → H.264** on the WebRTC path (no JPEG staging / double-encode)
- **HW encode** when FFmpeg exposes `h264_nvenc` / `h264_qsv` / `h264_amf`; else `libx264` ultrafast + zerolatency
- **Idle skip** when the desktop frame is unchanged
- **Input:** move budget 120/s; critical ACK ≤80 ms; data-channel drain preference
- **Adaptive:** JPEG quality/fps churn does not thrash the session helper while WebRTC is connected
- Telemetry: `media.encoder`, `effective_capture_fps`, `target_bitrate_bps`

Cloud/viewer must-do: `honeypot-contract` **1.4.20** → `cloud/REMOTE_DESKTOP_SMOOTHNESS.md` (C-RD-1…8).

---

# Cloud Honeypot Client v4.9.19

## Hotfix — false defense_policy_tamper

- Do not treat unrelated `config.sig` as defense matrix HMAC
- Invalid `defense_rules_sig` → apply unsigned with hard-safety (no tamper escalate)
- Lab: observe default stays healthy after threats/config sync

Includes 4.9.17–4.9.18 onboarding + cache re-sign.

---

# Cloud Honeypot Client v4.9.18

## Hotfix — defense policy cache token race

- Re-sign valid policy JSON when HMAC fails due to empty-token boot race (avoid false `tamper_observe`)
- Includes 4.9.17 observe default + 3-day auto-promote + GUI education (contract 1.4.19)

---

# Cloud Honeypot Client v4.9.17

## Observe default + auto-promote (contract 1.4.19)

- Fresh install defaults to **Observe** — all alerts, no auto process kill / no isolate
- After **3 days** (configurable) auto-promotes to **Balanced** unless locked
- GUI: education for Observe / Balanced / Paranoid + “Switch to Balanced” / “Stay in Observe”
- Never auto-opens Paranoid or `isolate_armed`

## Includes

- 4.9.16 Defense Policy matrix, signed cache, allow_process, snapshots
- 4.9.15 soft network surface inform

---

# Cloud Honeypot Client v4.9.16

## Defense Policy P0 (contract 1.4.18)

- Apply `defense_policy` / `defense_rules` / `defense_policy_version` / `isolate_armed` from threats/config
- Signed local cache + LKG; tamper fails safe to LKG/observe — **never** isolate or escalate
- Matrix-driven canary / VSS / critical process actions (`alert_only`, `suspend`, `kill_quarantine`)
- Hard-reject `auto_isolate_network` on observe/balanced (anti-bait)
- Commands: `allow_process`, `list_allowed_processes`; `isolate_host` gated (P2 not fully enabled)
- Session JPEG snapshot on red events (≤1 / 5 min / family)
- STATUS + health expose `defense_policy` / version for cloud pull

## Includes

- 4.9.15 soft network surface inform
- 4.9.12–4.9.14 System Recovery, NG panel/maintenance, VSS delete intent

---

# Cloud Honeypot Client v4.9.15

## Soft network surface inform (contract 1.4.17)

- Additive changes (Ethernet up, DHCP lease, new NIC) → soft `network_surface_changed` (info, not urgent)
- **No panic while `internet_ok`** — no auto-disable, no auto-restore on enrichment
- `auto_restore_network` remains subtractive-only (adapter down / DNS / firewall)
- STATUS: `surface_inform` + `surface_inform_changes`
- Commands: `network_accept_surface`, `network_disable_adapter` (confirm)
- GUI: chip “Ağ değişti” + soft toast + **Bu bendim — yedeği güncelle** (no PIN)

## Includes

- 4.9.12–4.9.14 System Recovery, NG panel/maintenance, STATUS cache fix, VSS delete intent

---

# Cloud Honeypot Client v4.9.14

## VSS delete intent (contract 1.4.16)

- `vssadmin delete shadows` / WMI / wbadmin (score ≥95) → immediate `taskkill` + quarantine arm
- Does **not** wait for shadow-count drop (≤120s path)
- No IFEO on `vssadmin` / `wmic` / `powershell` / `cmd` / `wbadmin` (keeps inventory healthy)
- Process poll 5s → 2s
- Urgent alert: `ransomware_vss_delete_intent`

Note: `HP-BLOCK` remains IP firewall identity — it does not deny VSS delete.

## Includes

- 4.9.12 System Recovery + Network Guard panel / auto_restore / maintenance
- 4.9.13 STATUS hang fix (live cache)

---

# Cloud Honeypot Client v4.9.13

## STATUS hang fix

Network Guard / System Recovery no longer run PowerShell or full drift scans
inside the single-threaded `:58632` STATUS handler. Live adapters come from the
detect-loop cache; use `list_network_baseline` / `network_diff` /
`system_recovery_diff` for fresh collects.

## Includes 4.9.12

- System Recovery (contract 1.4.13)
- Network Guard panel + `auto_restore_network` (1.4.14)
- Maintenance pause / snapshot / resume (1.4.15)

---

# Cloud Honeypot Client v4.9.12

## System Recovery (contract 1.4.13)

Attack-surface allowlist — not full Windows/registry backup:

- Policy: DisableTaskMgr / DisableRegistryTools / DisableCMD / NoRun / NoClose
- Services: VSS, swprv, wscsvc, EventLog, Schedule
- Firewall profiles on/off
- Signed snapshots, drift alert `system_recovery_drift`, dashboard commands
  `system_recovery_snapshot` / `list` / `diff` / `restore` (dry_run + confirm)

## Network Guard panel (contract 1.4.14) + maintenance (1.4.15)

- Rich live + golden adapters (IPv4/DNS/dhcp) in STATUS / `list_network_baseline`
- `network_diff`, IPv4 restore, `auto_restore_network` (default on)
- Golden baseline not poisoned by attacker IP changes
- **Maintenance:** GUI chip → Pause → change VPN/IP → Backup → Resume
  (`network_maintenance_start` / `network_maintenance_end`, IPC `NG_MAINT_*`)

See honeypot-contract `agent/system-recovery.md` + `agent/network-guard.md`.

---

# Cloud Honeypot Client v4.9.11

## Alert signal hygiene (§1–10)

Implements https://honeypot.yesnext.com.tr/static/docs/CLIENT_ALERT_SIGNAL_HYGIENE.md

**Critical fixes in this pass:**
- **Lifecycle double POST (§8):** `report_now` no longer flush-reposts; same `event_type`+UTC-second dedupe; `gui_quit` rate-limit; process-stop → lifecycle only
- **Canary 30m loop (§3):** soft single-file MODIFIED debounce ≥30m all paths; soft never `/api/alerts/urgent`
- **list shadows urgent (§1):** process skip + AlertPipeline `_send_urgent` hard drop

Also: shadow delta tiers, offline flap/dedupe, trusted/local info≤10, intel observe-only.

See `docs/CLIENT_ALERT_SIGNAL_HYGIENE.md`.

---

# v4.9.10

- Fix Guardian SCM start timeout loop (Event 7009/7000): fast-path boot before heavy imports.
- Soft heal: no delete+recreate; wait on START_PENDING.
- `guardian_restarts_24h` counts successful recovers only (failed heals → heal_attempts).
- Prunes legacy inflated counters; aligns with cloud soft-alert (guardian_false alone ≠ critical).

---

# v4.9.9

- Hotfix: Session-0 `ABOVE_NORMAL` priority now applies correctly on 64-bit Windows (ctypes handle typing).
- Includes all v4.9.8 features: resource badge, realtime presence (contract 1.4.12).

---

# v4.9.8

- Resource corner badge (App CPU/RAM · Host CPU/RAM · net ↓↑) via STATUS `resources{}`
- Session-0 motor `ABOVE_NORMAL` priority (never REALTIME); optional `security.motor_priority`
- Realtime presence (honeypot-contract **1.4.12** / `api/11-presence-realtime.md`):
  - Sleep: WS `presence` suspend + HTTP `POST /api/presence` ≤2s
  - Stop: `goodbye` then close (`shutdown` / `update` / `uninstall` / `operator_stop`)
  - Wake: reconnect + presence online / hello
  - GUI quit alone does not mark host offline while motor is up

---

# Cloud Honeypot Client v4.9.7

## Highlights

- **Threat Intel → HP-INTEL-\*:** Firewall IoCs apply as dedicated `HP-INTEL-<id>` inbound+outbound rules (not `HP-BLOCK-*`). Severity/allowlist/`expires_at`/orphan reconcile; ACK includes `firewall_removed`. ETag persisted for 304.
- **successful_logon fix:** Bare RDP/success no longer scores 100 or auto HP-BLOCK. Caps 70 (silent 80). `should_auto_block()` false for bare success. Block only brute→success / honeypot / block_rules / operator. Silent hours alert-only.
- **Whitelist enforce:** Whitelist IPs are never blocked; if already blocked, `block_ip` and `update_whitelist` immediately remove HP-BLOCK/HP-INTEL rules.

## Production floor

Unchanged: **client ≥ 4.9.0**.

## Build

`build.ps1 -Clean -WebRTC`

---

# Cloud Honeypot Client v4.9.6

## Highlights

- **Update disk bloat cleanup:** After a successful install, remove staged `cloud-client-installer*.exe`, `run-update-*.ps1` launchers, matching Downloads copies, and `TEMP\honeypot_*update_*` dirs. Downloads are no longer used for installer staging; only the active installer is kept under ProgramData until install completes. Daemon auto-enforce also prunes leftovers when no update is in progress.
- **Settings → Security PIN:** Set / change / remove local GUI PIN from the Ayarlar tab (status + dashboard recovery hint). Uses existing `GuiLock` dialogs.

## Production floor

Unchanged: **client ≥ 4.9.0**.

## Build

`build.ps1 -Clean -WebRTC`

---

# Cloud Honeypot Client v4.9.5

## Highlights

- **`list_services` empty array fix (4.9.4):** Under Turkish Windows locale, PowerShell JSON stdout failed `cp1254` decode → `success:true` with `services:[]`. Primary path is now **Win32 SCM** via pywin32 (`name`, `display_name`, `status`, `start_type`, `pid` when >0). PowerShell CIM/`Get-Service` kept as UTF-8 fallback.
- **Uninstall PIN gate:** NSIS uninstall / Control Panel removal prompts for GUI PIN (or confirm when no PIN); lifecycle events `uninstall_requested` / `uninstall_pin_failed` / `uninstall_aborted` / `uninstall_authorized`; CLI `--uninstall-gate`.

## Production floor

Unchanged: **client ≥ 4.9.0**. Server Management Services table: **≥ 4.9.5**.

## Build

`build.ps1 -Clean -WebRTC`

---

# Cloud Honeypot Client v4.9.4

## Highlights

- **Contract 1.4.8 — Server Management:** `list_services` inventory; service mutate accepts `name` **or** `service_name`; Guardian/OS services protected (`PROTECTED_SERVICE`); local users include `groups`; processes/sessions refresh via health after mutates. No account delete in v1 — use disable.
- **Remote Desktop stability:** encode WxH locked for the stream session (min **800×600** when source allows); adaptive controller no longer thrash resolution — only fps/quality.

## Production floor

Unchanged: **client ≥ 4.9.0**. Target for Server Management UI: **≥ 4.9.4**.

## Build

`build.ps1 -Clean -WebRTC`

---

# Cloud Honeypot Client v4.9.3

## Highlights

- **OOB-501 acceptance visibility:** durable drop counters (`oldest_dropped`, expired, too-large) persist across restart and appear on `health/report` as `offline_urgent_queue{}`. Pilot harness covers canary spool→reconnect drain and 500-cap drop.
- Flag `security.offline_urgent_queue` remains **default off** (one-host live canary pilot still the open gate).
- **GUI polish:** stat cards keep icon + value on one row; IP Lists uses a single scrollbar sized to the window.

## Production floor

Unchanged: **client ≥ 4.9.0**.

## Build

`build.ps1 -Clean -WebRTC`

---

# Cloud Honeypot Client v4.9.2

## Highlights

- **OOB-501 aligned to contract 1.4.7** (`api/10-offline-urgent-queue`): local TTL 7d prune, ≤200 KB payload reject, batch ≤500, drop `schema`/`too_large`/`expired` rejects and retry `transient`; drain after successful heartbeat **or** control WS reconnect.
- Flag `security.offline_urgent_queue` remains **default off** — ready for pilot drain, not fleet-on.
- **Threat Center UX:** autoblock threshold is threat score 0–100; Engellenen IP card opens IP Lists → Engellenen; Skor column.

## Production floor

Unchanged: **client ≥ 4.9.0**. Observe / default-off security surfaces only.

## Build

`build.ps1 -Clean -WebRTC`

---

# Release v4.7.0 — Network Guard (offline ransomware bomb defense)

Contract: `honeypot-contract` **v1.3.0** (`agent/network-guard.md`)

Fire-and-forget + offline fidye yazılımına karşı (dropper çalışır, ağı keser,
internetsiz şifreler) beş parçalı savunma.

## A) Ağ baseline yedeği
- İmzalı `network_baseline.json` (HMAC = agent token + COMPUTERNAME)
- Mapped drive / shares / adapter / DNS / gateway / route / firewall / connectivity
- Boot + 30 dk periyot; anlamlı değişimde versiyon bump; son 10 sürüm rotasyonu

## B) Offline davranışsal tespit (internetsiz)
- Ağ-kesme tespiti: baseline'a göre internet/adapter delta
- FS fırtınası: per-process `io_counters` yazma hızı (bytes/s + write_count/s)
- Şüpheli köken (Temp/Downloads/Public/UNC) skoru
- **Ağ-kesme + FS-fırtınası → canary beklemeden containment**

## C) Agresif containment (suspend-first)
- Şüpheli süreçler önce **suspend** edilir (adli kayıt korunur, geri alınabilir)
- Acil VSS shadow copy (best-effort)
- Ransomware quarantine'e kayıt; operatör onayıyla kill/release
- Opsiyonel `protection.network_guard.auto_kill` (varsayılan kapalı)

## D) Ağ / bağlantı kurtarma
- `auto_restore` (varsayılan açık): adapter enable / DNS / firewall / mapped-drive baseline'dan geri
- Amaç: malware'in kestiği ağı geri açıp **daemon'un buluta alarm atmasını** sağlamak

## E) Alarm
- `ransomware_offline_bomb` urgent → `system_context.network_guard`
  (trigger, score, network{internet_lost/adapters_down/restored/restore_actions},
  suspects[], vss_emergency_snapshot)

## Komutlar (control WS)
- `network_snapshot` — anlık baseline al
- `network_restore` — baseline'dan geri yükle (**server confirm + HMAC**)
- `list_network_baseline` — baseline özeti

## STATUS / health
- `network_guard{}` bloğu (enabled, baseline_version/age, internet_ok, mapped_drives,
  suspended_processes, last_trigger_ts, auto_restore, auto_kill)

## Dürüst sınır
Tam EDR/AV değil; davranışsal tespit ayarlanabilir eşik + güvenli (suspend-first)
varsayılan. Garanti: erken containment + kurtarılabilirlik.

## Ek
- Fix: `motor_session.json` `version` alanı artık `__version__` ile dolar.

## Cloud/API aksiyonları
- Yeni komut tiplerini whitelist + `network_restore` için destructive confirm
- `ransomware_offline_bomb` urgent'i popup builder'da işle (`system_context.network_guard`)
- Health ingest: `network_guard{}` bloğunu koruma sağlığı rozetine bağla

---

# Release v4.6.0 — Survival + disaster recovery

Contract: `honeypot-contract` **v1.2.0**

## Guardian + tamper
- New Windows service `CloudHoneypotGuardian` (`--mode=guardian`, LocalSystem, SCM failure recovery)
- Motor ensures Guardian every 30s; Guardian resurrects motor every 10s if `motor_ok` false
- Motor QUIT rejected unless `update_in_progress.lock` or signed `operator_stop.json` (PIN exit)
- Unexpected motor exit → `agent_tamper` urgent on next boot; `motor_heartbeat.json` dead-man beacon
- STATUS + health report include `persistence{}` block

## Disaster recovery (dashboard IR)
- `create_user` — break-glass local admin (`if_exists=reset_enable`)
- `remote_logon` — existing session reconnect; zero session → autologon + reboot
- `set_autologon` / `clear_autologon` / `reboot` helpers

## Cloud/API actions required
- Whitelist new command types + destructive confirm for `create_user`, `remote_logon`, `set_autologon`, `reboot`
- Handle `agent_tamper` urgent (`system_context.tamper`) in popup builder
- `pending_tunnel_commands` TTL/dedupe (contract `agent/attacks-and-services.md`)
- Optional: cloud dead-man — alert when `motor_heartbeat.json` stale via health ingest

---

# v4.5.68 — Canary urgent wire hotfix

Fixes live smoke gap found after 4.5.67 deploy:

- Canary previously called thin `AlertPipeline.handle_alert` first, then enriched
  `send_urgent`. Live logs showed the thin payload winning the popup.
- Now a **single** enriched urgent is sent after containment (≤4s), including
  `system_context.ransomware`, process-compatible `raw_events`,
  `target_service=SYSTEM`, and `recommended_action=isolate_host`.

Requires cloud popup to prefer `system_context.ransomware` (contract ≥1.1.3).

---

# v4.5.67 — Enriched ransomware canary alert

Implements honeypot-contract **1.1.3**:

- Canary containment and suspect attribution run before the urgent alert (bounded ≤4s).
- `POST /api/alerts/urgent` includes:
  - `threat_score=100`, `target_service=SYSTEM`
  - `recommended_action=isolate_host`
  - structured `raw_events`
  - `system_context.ransomware` with file/change/suspect PID, cmdline, path and SHA-256
- Health snapshots include persisted `ransomware_quarantine` details.

Cloud compatibility: use structured context first; fall back to parsing `Dosya:` and
`Değişiklik:` from ≤4.5.66 descriptions.

---

# v4.5.66 — Contract gaps: protection.block_rules + threat_intel_updated

Implements remaining client gaps against honeypot-contract **1.0.0**:

1. **Register / threats/config** — `protection.block_rules` → ThreatEngine (schema normalize + ProgramData persist)
2. **Control WS** — `t: threat_intel_updated` → immediate threat-intel sync

See `agent/register-protection.md` and `api/09-threat-intel.md`.

---

# v4.5.65 — Canary UX: invisible & non-scary

Daily-use review: traps must not alarm normal users.

- No local tray/toast on canary hit (cloud dashboard still gets urgent)
- Skip OneDrive Documents (would sync bait into user's cloud UI)
- NotContentIndexed + Hidden+System (Search/Explorer stay clean)
- Never IFEO-kill indexer / Defender / OneDrive / shell hosts
- Softer GUI copy (no "tuzak" wording in health check)

---

# v4.5.64 — Interactive-user canaries watched by SYSTEM

## Scenario-tested on this PC
- Threat-intel: fetch / 304 / ack OK (bundle `2026.07.20.011`)
- User Documents sort-bait canaries (H+S) deployed and **watched by Session-0 motor**
- Canary MODIFIED → quarantine armed in ~6s → `RS_UNLOCK` clears
- IFEO process attribution remains best-effort (SYSTEM often cannot see interactive open_files)

## Fixes
- ProfileList + scan `Users\*\Documents\.cloud-honeypot-canary` (4.5.63 deployed files but SYSTEM did not watch them)
- Quarantine arm-first (from 4.5.63)

---

# v4.5.63 — Quarantine arm-first + user Documents canaries

## Fixes from local scenario testing (DESKTOP-F5SCL3G)
- Quarantine now **arms immediately** on canary/VSS hit; suspect `open_files` scan is time-boxed (≤4s) so STATUS/GUI no longer wait ~50s
- SYSTEM daemon also deploys canaries under interactive users' `Documents` (previously only systemprofile + Public + ProgramData)

## Still in 4.5.62
- Sort-bait `!000_` canaries, Hidden+System, IFEO quarantine, unlock via GUI/IPC/dashboard
- Cloud threat-intel consumer

---

# v4.5.62 — Ransomware canary harden + quarantine

## Answer (hiding)
Extreme hiding (ADS / obscure paths) often means ransomware **never touches** the canary — so detection fails. This build uses **Hidden+System + `!000_` sort-bait** so Explorer stays clean but ransomware enum still hits early.

## Client
- Sort-bait canaries (`!000_*`), H+S on files and folders; admin README only in ProgramData
- Canary/VSS hit → kill suspect writer + **IFEO quarantine** until unlock
- Unlock: GUI button, IPC `RS_UNLOCK`, remote `unlock_ransomware_quarantine`
- Faster canary check (15s); extra TTPs (USN wipe, wevtutil, VSS PowerShell, net stop vss)
- Frontend ransomware detail via SYSTEM motor IPC (`RS_STATUS`)

## Cloud threat-intel (verified on this host)
- `GET /api/agent/threat-intel` → bundle `2026.07.20.008`
- Conditional fetch → HTTP 304 `not_modified`
- `POST .../ack` → ok
- Applied locally: firewall blocks + ransomware rules + process watch

---
