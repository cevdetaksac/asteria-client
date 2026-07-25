# GUI Modernization Roadmap — WebView2 + Dashboard-aligned UI

> Tarih: 2026-07-24 (güncelleme: 2026-07-25)  
> Başlangıç: client **4.9.32**, contract `agent/gui-control-center.md`  
> Hedef: CustomTkinter shell → **ayrı `asteria-gui.exe`** (WebView2 host + React/Vite UI);
> dashboard ile görsel/UX uyumu; isteğe bağlı **WebGL** ile canlı görselleştirme  
> Durum: planlama (uygulama başlamadı)  
> **Üst plan (motor + GUI birlikte):** [`ASTERIA_DUAL_TRACK_ROADMAP.md`](ASTERIA_DUAL_TRACK_ROADMAP.md)

Bu belge **GUI detay / parity** yol haritasıdır. Motor hardening, tek-exe ve
imza/attestation **dual-track** belgesindedir. Kod değişikliği değildir.

**Paketleme kararı (2026-07-25):** UI, motor exe içine gömülü host olmak zorunda
değil. Tercih: sistem motoru `asteria-client.exe` + kullanıcı oturumunda
**`asteria-gui.exe`** (hafif WebView2 + React; WebGL seçici). Tray motordan veya
ince yardımcıdan Show ile GUI’yi açar.

---

## 1. Vizyon (tek cümle)

**Daemon motor kalır, tray kalır; arayüz ayrı `asteria-gui.exe` olur** —
WebView2 + React (dashboard dili), localhost IPC ile canlı; motor CTk/WebView taşımaz.

---

## 2. Değişmez mimari ilkeler

1. **Session-0 daemon = motor.** GUI/WebView asla honeypot, firewall veya
   control-WS sahibi olmaz (`api/08-architecture.md`).
2. **Tray ayrı yaşam döngüsü.** `pystray` (veya eşdeğer Win32 tray) logon /
   multi-user / close-to-tray için kalır; WebView yalnızca ana pencereyi değiştirir.
3. **Tek IPC köprüsü.** UI → host → `127.0.0.1:58632` JSON komutları
   (`PING`, `STATUS`, `BLOCK_IP`, `HONEYPOT …`, …). WebView doğrudan elevated
   API çağırmaz.
4. **Cloud SoT ayarlar için.** Toggle/ayar → `POST /api/threats/config`; başarıda
   effective config; hata → UI rollback (`gui-control-center.md`).
5. **Önce durum, sonra detay, sonra aksiyon.** Kart N = popup N; yıkıcı aksiyon
   onay ister.
6. **Offline-first his.** Daemon yokken bile “motor kapalı / bağlanıyor”
   görünür; boş dashboard taklidi yok.
7. **Wire kimlikleri değişmez.** `honeypot-client.exe`, ProgramData yolları,
   task adları, token formatı (`PRODUCT_BRANDING.md`).

---

## 3. Bugünkü durum (kaynak)

| Katman | Bugün | Hedef |
|--------|--------|--------|
| Shell | CustomTkinter `ModernGUI` (~8k satır `client_gui.py`) | İnce native/Python **WebView2 host** |
| Tema | `client_gui_theme.py` slate + emerald | Dashboard design tokens + paylaşılan token paketi |
| Sayfalar | status / threat / iplist / services / layers / settings | Aynı IA, modern layout |
| i18n | `client_lang.json` TR/EN | Aynı anahtarlar → web i18n (veya JSON import) |
| PIN | `client_gui_lock.py` CTk diyalog | Host native dialog **veya** web modal + host doğrulama |
| Toast | CTk + tray balloon | Web toast + tray balloon |
| Build | PyInstaller onedir + NSIS | + `ui/` dist assets + WebView2 Runtime stratejisi |
| Dashboard FE | Bu workspace’te yok (canlı: honeypot.yesnext.com.tr) | Token/bileşen hizalaması ayrı cloud FE repo ile |

**Korunacak yüzeyler (WebView dışında):**

- `client_tray.py` menü: Show, Dashboard, Link, Copy token, Exit  
- Scheduled Tray task + watchdog  
- `GuiLock` dosya sözleşmesi (`%ProgramData%\…\gui_lock`)  
- Uninstall gate PIN  
- Daemon IPC protokolü

---

## 4. Hedef mimari

```
┌─────────────────────────────────────────────────────────────┐
│  Interactive session                                        │
│  ┌──────────────┐   Show/Quit      ┌─────────────────────┐  │
│  │ Tray         │◄────────────────►│ asteria-gui.exe     │  │
│  │ (lifecycle)  │                  │ WebView2 + React    │  │
│  └──────────────┘                  │  - PIN / chrome     │  │
│                                    │  - bridge API       │  │
│                                    │  - Canvas/WebGL viz │  │
│                                    └──────────┬──────────┘  │
│                                               │ TCP :58632  │
└───────────────────────────────────────────────┼─────────────┘
                                                │
┌───────────────────────────────────────────────▼─────────────┐
│  SYSTEM — asteria-client.exe (motor only; no GUI toolkit)   │
└─────────────────────────────────────────────────────────────┘
                         │ HTTPS / WSS
                         ▼
              Cloud API + Dashboard (asteria.run)
```

### 4.1 Teknoloji seçimleri (önerilen)

| Karar | Seçim | Neden |
|-------|--------|--------|
| Host | **Microsoft Edge WebView2** (Evergreen önce) | Win10/11 native, Chromium, imza/güvenlik, Electron’suz |
| UI framework | **React 18+ + Vite + TypeScript** | Dashboard ekosistemi ile hizalama; hızlı HMR |
| Stil | **CSS variables + dashboard token set** (Tailwind isteğe bağlı) | Tek marka dili; purple-AI klişesinden kaçın |
| Grafik | **SVG/Canvas varsayılan; WebGL seçici** | Threat feed / trend / heatmap için; her kart WebGL değil |
| Host köprüsü | WebView2 `postMessage` ↔ Python (`pywebview` **veya** `pythonnet`/`webview2` thin wrapper) | Tek yönlü güven modeli: UI istek atar, host yetkilendirir |
| Paket | UI → `ui/dist` → **`asteria-gui.exe`** (ayrı artifact); motor exe GUI datas taşımaz | Offline; CDN yok |
| Runtime | **Evergreen WebView2** + installer bootstrapper; Fixed Version yalnızca air-gapped | Küçük installer; Fixed ~100MB+ |

**Bilerek seçilmeyenler:** Electron (çift runtime, boyut), CEF gömme (bakım), saf Tk tema cilası (limit aşılmış), GUI’yi motor onedir `_internal` içine gömmek (yüzey + güvenlik).

### 4.2 Bridge sözleşmesi (taslak)

Host, WebView’e yalnızca allowlist’li API sunar:

```ts
// UI → Host
type HostRequest =
  | { op: "ipc"; cmd: string; args?: unknown; id: string }
  | { op: "cloud"; method: "GET"|"POST"; path: string; body?: unknown; id: string }
  | { op: "shell"; action: "open_dashboard"|"copy_token"|"quit"|"minimize" }
  | { op: "i18n"; lang: "tr"|"en" }
  | { op: "pin"; action: "check"|"set"|"clear"; ... };

// Host → UI
type HostEvent =
  | { type: "ipc_result"; id: string; ok: boolean; data?: unknown; error?: string }
  | { type: "status_push"; snapshot: StatusSnapshot }   // throttle 1–2 Hz
  | { type: "toast"; level: "info"|"warn"|"error"; message: string }
  | { type: "update_available"; version: string };
```

Kurallar:

- `cloud.*` çağrıları host’ta token ekler; token WebView JS’e **yazılmaz** (mümkünse).
- `ipc` komutları mevcut daemon sözlüğünün alt kümesi; yeni komut → contract + test.
- Navigasyon / deep-link: `chp://page/threat?ip=…` veya host event `navigate`.

Contract’a eklenecek: `agent/gui-webview-bridge.md` (yeni) + `gui-control-center.md` güncelleme.

---

## 5. Dashboard uyumu

Dashboard FE bu monorepo’da yok. Uyum **tasarım sistemi çıkarma** ile yapılır:

### Faz 0 — Design sync (bloklayıcı değil ama yüksek değer)

1. Canlı dashboard’dan (veya cloud FE repo’dan) token envanteri:
   - renk, tipografi, spacing, radius, shadow, chart palette
2. Client `tokens.css` / `theme.ts` üret (bugünkü slate/emerald köprü olabilir).
3. Ortak hedef: **aynı accent ailesi, aynı tipografi hiyerarşisi, aynı kart dili**.
4. İdeal: `@yesnext/honeypot-ui` veya paylaşılan `design-tokens` paketi
   (cloud FE + agent UI). Yoksa token JSON’u contract’a mirror.

**Marka testi:** Nav kaldırılınca ilk viewport yine Asteria
hissettirmeli; generic “security dashboard” olmamalı.

**Kaçınılacaklar:** mor-indigo AI klişesi, cream+terracotta, broadsheet yoğun kolon,
gereksiz glow / pill cluster / hero-kart yağması.

---

## 6. Faz planı

Durum: `[ ]` plan · `[~]` kısmi · `[x]` bitti

### Faz 0 — Keşif & sözleşme  `[ ]`

| # | İş | Çıktı |
|---|-----|--------|
| 0.1 | Dashboard token / component audit | `docs/design/tokens.md` + screenshot referans |
| 0.2 | Mevcut GUI feature inventory (6 sayfa + chrome) | parity checklist (bu belgede §7) |
| 0.3 | Bridge API taslağı | `honeypot-contract/agent/gui-webview-bridge.md` |
| 0.4 | Host POC: boş WebView2 + `PING` round-trip | `ui-shell` spike branch |
| 0.5 | Runtime kararı: Evergreen vs Fixed | OPERATIONS notu |

**Çıkış kriteri:** POC’ta STATUS JSON UI’da render; tray Show GUI WebView açıyor.

---

### Faz 1 — Shell & iskelet  `[ ]`

| # | İş | Çıktı |
|---|-----|--------|
| 1.1 | `ui/` Vite+React+TS scaffold | `npm run build` → `ui/dist` |
| 1.2 | Python/WebView2 host (`--mode=gui`) | CTk yerine feature-flag |
| 1.3 | Layout chrome: sidebar, top bar, toast host | Dashboard-benzeri IA |
| 1.4 | i18n wiring (`client_lang.json` → web) | TR/EN parity |
| 1.5 | PIN gate (host-first) | Unlock olmadan UI mount yok |
| 1.6 | Build: datas + NSIS + WebView2 bootstrapper | Lab install |

**Feature flag:** `CHP_UI=webview|ctk` (varsayılan ctk ta ki Faz 3 GA).

**Çıkış kriteri:** Flag ile WebView açılır; Status sayfası read-only canlı.

---

### Faz 2 — Sayfa parity (read → write)  `[ ]`

Sıra (risk / değer):

1. **Anlık Durum** — koruma şeridi, stat kartları, detay drawer  
2. **IP Listeleri** — tablolar + block/whitelist/unblock  
3. **Honeypot Servisleri** — start/stop + RDP port  
4. **Güvenlik Katmanları** — cloud config toggles + defense policy  
5. **Ayarlar** — `SECTIONS` şeması, validation, effective config  
6. **Tehdit Merkezi** — feed, quick response, accounts/shares/sessions, RD panel  

Her sayfa için:

- Loading / empty / error / success durumları  
- IPC + cloud hata rollback  
- Parity testi: eski CTk ile yan yana screenshot + checklist  

**Çıkış kriteri:** 6 sayfa write path’leri lab’da CTk ile eşdeğer.

---

### Faz 3 — Polish, WebGL, GA  `[ ]`

| # | İş | Not |
|---|-----|-----|
| 3.1 | Motion: sayfa geçişi, chip pulse, toast | 2–3 bilinçli motion; gürültü yok |
| 3.2 | Threat trend / live sparkline | Canvas veya hafif chart lib |
| 3.3 | WebGL katmanı (opsiyonel) | Attack heatmap / particle feed — düşük CPU bütçesi, toggle |
| 3.4 | Accessibility: klavye, contrast, reduced-motion | WCAG-ish hedef |
| 3.5 | Perf: STATUS push ≤2 Hz; virtualize long tables | Session 0’ı etkilemez |
| 3.6 | CTk kaldır / flag default `webview` | Sürüm notu + contract bump |
| 3.7 | E2E smoke (Playwright against host bridge mock) | CI |

**Çıkış kriteri:** Default UI = WebView; CTk kod yolu deprecated veya silinmiş.

---

### Faz 4 — Derin entegrasyon (sonra)  `[ ]`

- Embedded mini-dashboard panelleri (read-only cloud widgets) — token’suz proxy  
- Shared component library ile cloud FE  
- Tema: system light (şimdilik dark-first yeterli)  
- High-DPI / multi-monitor edge cases  
- Arm64 Windows (ileri)

---

## 7. Feature parity checklist

### 7.1 Navigasyon & chrome

- [ ] Sidebar: status, threat, iplist, services, layers, settings  
- [ ] Top: Open Dashboard, account badge, CPU/RAM/net badge, Help  
- [ ] Update banner  
- [ ] Language TR/EN  
- [ ] Close → tray (destroy değil)  
- [ ] Singleton mutex + ShowGUI event  

### 7.2 Anlık Durum

- [ ] Protection chips: motor, ransomware, network guard, guardian, honeypots, quarantine  
- [ ] Stat cards + detail drawers  
- [ ] Canonical snapshot (kart = popup sayacı)  

### 7.3 Tehdit Merkezi

- [ ] Threat level / events/h / blocked IPs  
- [ ] Live feed  
- [ ] Quick response: Block, Logoff, Disable, Snapshot  
- [ ] Accounts, shares, suspicious services, command history, sessions  
- [ ] Remote Desktop status (stop/refresh; stream cloud’dan)  

### 7.4 IP Listeleri

- [ ] Activity / Blocked / Whitelist  
- [ ] Skor 0–100  
- [ ] Block / whitelist / unblock + quick-add  

### 7.5 Honeypot Servisleri

- [ ] RDP, SSH, FTP, MYSQL, MSSQL, HTTP, SMB  
- [ ] Start/stop via IPC; RDP port-move  

### 7.6 Güvenlik Katmanları

- [ ] Policy: observe / balanced / paranoid (+ lock)  
- [ ] Ransomware / canaries / network guard  
- [ ] Cloud SoT sync  

### 7.7 Ayarlar

- [ ] Email, auto-block, silent hours, webhook (`SECTIONS`)  
- [ ] Account link/unlink  
- [ ] GUI PIN set/change/clear  
- [ ] Cleanup actions (local / firewall / server) — onaylı  

### 7.8 Tray & alerts

- [ ] Show / Dashboard / Link / Copy token / Exit  
- [ ] Toast + balloon  
- [ ] Watchdog relaunch tray  

---

## 8. Repo / dizin önerisi

```
asteria-client/
  ui/                      # React + Vite (yeni)
    src/
      pages/
      components/
      bridge/              # host message types
      theme/
      i18n/
    dist/                  # build çıktısı
  asteria-gui.spec         # ayrı GUI exe (yeni)
  client_webview_host.py   # GUI process entry (yeni)
  client_gui.py            # CTk — G3’e kadar flag ile
  docs/
    ASTERIA_DUAL_TRACK_ROADMAP.md  # motor + GUI üst plan
    GUI_WEBVIEW_ROADMAP.md         # bu belge
    design/
      tokens.md
asteria-contract/
  agent/
    gui-control-center.md
    gui-webview-bridge.md  # bridge SoT (yeni)
```

---

## 9. Build & dağıtım

| Konu | Politika |
|------|----------|
| WebView2 Runtime | Installer: Evergreen bootstrapper (sessiz); yoksa indirme + yeniden dene |
| Fixed Version | Yalnızca offline/air-gap skus; ayrı build profili |
| Boyut | UI dist ~ birkaç MB; Evergreen runtime makinede paylaşımlı |
| İmza | `asteria-client.exe` + `asteria-gui.exe` Authenticode (`build.ps1 -Sign`) |
| Güncelleme | Mevcut updater; her iki exe versioned birlikte |
| Geri dönüş | `ASTERIA_UI=ctk` veya uninstall+eski sürüm (G3 öncesi) |

---

## 10. Güvenlik notları

1. WebView **local file / custom scheme** (`https://app.local/` veya `file` kısıtlı); rastgele internet yok.  
2. `webMessage` allowlist; `eval` / uzak script yok.  
3. Token, PIN hash, machine_id JS global’ine yazılmaz; host proxy eder.  
4. DevTools production’da kapalı (lab flag ile açılır).  
5. XSS: kullanıcı/IP/log stringleri escape; threat feed untrusted.  
6. Elevation: `asteria-gui.exe` non-admin; motor SYSTEM’de.  
7. Motor hardening / `_internal` / Nuitka: [`ASTERIA_DUAL_TRACK_ROADMAP.md`](ASTERIA_DUAL_TRACK_ROADMAP.md) Track M.

---

## 11. Test stratejisi

| Katman | Ne |
|--------|-----|
| Unit | Bridge serializer, settings patch builder (mevcut `client_settings_util`) |
| Host mock | Fake IPC daemon → UI integration (Vitest + mock postMessage) |
| Lab | Gerçek daemon: 6 sayfa smoke + PIN + tray Show |
| Regresyon | Parity checklist §7; screenshot tour (`scripts/ux_screenshot_tour.py` web’e uyarlanır) |
| Perf | STATUS flood → UI FPS / CPU; WebGL off default |

---

## 12. Tahmini sürüm dilimleri (öneri)

| Dilim | Client sürüm bandı | İçerik |
|-------|-------------------|--------|
| Spike | 4.9.x lab / internal | Faz 0–1 POC, flag kapalı |
| Beta | 4.10.0-beta | Flag opt-in WebView, Status+IP+Services |
| RC | 4.10.x | Tam parity, polish |
| GA | 4.11.0 | Default WebView; CTk kaldır |

Sürüm numaraları esnek; her public dilimde contract bridge dokümanı + CHANGELOG.

---

## 13. Riskler & mitigasyon

| Risk | Mitigasyon |
|------|------------|
| WebView2 eksik makine | Bootstrapper + net hata UI + CTk fallback (geçiş dönemi) |
| Tk → web davranış farkı | Parity checklist + lab screenshot |
| Dashboard token drift | Paylaşılan tokens paketi / contract mirror |
| Bridge güvenlik açığı | Allowlist + no token in JS + review |
| Boyut / imza karmaşası | Evergreen varsayılan; Fixed ayrı kanal |
| Tray/GUI yarışı | Mevcut mutex + ShowGUI event korunur |
| WebGL CPU | Opt-in; düşük power / reduced-motion’da kapat |

---

## 14. İlk 2 haftalık sprint önerisi (uygulama başlarsa)

**Hafta 1**

- Dashboard token audit + `tokens.md`  
- `ui/` Vite scaffold + dark slate/emerald köprü tema  
- WebView2 host POC + `PING`/`STATUS` bridge  
- Contract taslak `gui-webview-bridge.md`

**Hafta 2**

- Status sayfası (chips + cards) live  
- Feature flag `CHP_UI`  
- PIN gate host  
- Installer’a `ui/dist` + Evergreen bootstrapper denemesi  

Sonra: kullanıcı onayı ile Faz 2 sayfa sırasına geçilir.

---

## 15. Bilinçli olarak kapsam dışı (şimdi)

- Daemon’u WebView içine taşımak  
- Tray’i kaldırmak  
- Electron’a geçmek  
- Mobil / macOS agent UI  
- Cloud dashboard’u client içine tam embed (auth/cookie karmaşası)  
- CustomTkinter’ı “biraz daha güzelleştirmek” (yolun sonu)

---

## 16. Referanslar

- `honeypot-contract/agent/gui-control-center.md` — UX SoT  
- `honeypot-contract/api/08-architecture.md` — daemon vs frontend  
- `honeypot-contract/cloud/PRODUCT_BRANDING.md` — wire kimlikleri  
- `cloud-client/client_gui.py` — mevcut yüzey  
- `cloud-client/client_gui_theme.py` — geçici tokenler  
- `cloud-client/client_daemon_ipc.py` — IPC  
- `cloud-client/client_settings_util.py` — ayar şeması  
- Canlı dashboard: `https://asteria.run` (legacy alias: honeypot.yesnext.com.tr)  
- Üst plan: [`ASTERIA_DUAL_TRACK_ROADMAP.md`](ASTERIA_DUAL_TRACK_ROADMAP.md)

---

## Durum özeti

| Faz | Durum |
|-----|--------|
| 0 Keşif & sözleşme | `[ ]` |
| 1 Shell & iskelet | `[ ]` |
| 2 Sayfa parity | `[ ]` |
| 3 Polish / WebGL / GA | `[ ]` |
| 4 Derin entegrasyon | `[ ]` |

**Sonraki adım (insan onayı):** Faz 0.1–0.4 spike’ına başlamak veya önce dashboard FE repo / token erişimi sağlamak.
