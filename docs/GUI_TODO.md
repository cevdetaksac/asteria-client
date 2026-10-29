# GUI sadeleştirme + performans — TODO

Kaynak: GUI denetimi 29.10.2026 (Trello 0JIeL9iJ). Aktif GUI: `asteria_gui.py` (pywebview) + `ui/` (React).
Kurallar: 443 çıkış bağlantısı asla kesilmez, yıkıcı komut yok, her faz sonunda testler.

## Faz 1 — Performans hızlı kazanç
- [x] **P1** Pencere gizliyken poll'ları durdur. Hedef: tepsideyken sıfır arka plan sorgusu. Dosyalar: `ui/src/App.tsx`, `ui/src/pages/{Status,Services,Threat}Page.tsx`, yeni `ui/src/usePoll.ts`. Efor 2 sa. Risk düşük.
- [x] **P2** In-flight guard: önceki tur bitmeden yeni tur yok (setInterval → bitince planla). Dosyalar: `ui/src/usePoll.ts`, sayfalar. Efor 2 sa. Risk düşük.
- [x] **P3** SVC_LIST / SHARES_LIST / harden sonuçları 60 sn önbellek; ağır sorgular sadece ilgili sekme açıkken. Dosyalar: `client_threat_local.py`, `asteria_gui.py` (`_harden_checks`), `ui/src/pages/ThreatPage.tsx`. Efor 3 sa. Risk düşük.
- [x] **P4** Motor control socket istekleri paralel (bağlantı başına thread, üst sınırlı); STATUS ağır işleri beklemez. Dosya: `client.py` (`control_server_loop`). Efor 0.5-1 gün. Risk orta (motor) — test + 65'te doğrulama.
- [x] **P5** ipify senkron çağrısı arka plana. Dosya: `asteria_gui.py` (`_ensure_public_ip`). Efor 1 sa. Risk düşük.

## Faz 2 — Temizlik
- [ ] **C1** Eski CTk GUI'yi kaldır (önce kullanım logla, bir sürüm gözle). Dosyalar: `client_gui.py`, `client.py` (ModernGUI yolu), `asteria-client.spec`. Efor 0.5-1 gün. Risk orta.
- [x] **C2** Ortak veri katmanı: threats/config, whitelist, IP_TABLE, harden tek yerden (hook/store), tek poll. Dosyalar: `ui/src/pages/*`, yeni `ui/src/data/*`. Efor 1 gün. Risk orta.
- [x] **C3** Ölü kod: kullanılmayan i18n anahtarları (~209/748), `RdpSecureMoveModal`, `Brand` (doğrula), inline style → CSS. Dosyalar: `ui/src/i18n/catalog.ts`, `ui/src/components/*`. Efor 3 sa. Risk düşük.
  - Sonu?: dinamik anahtarlar (`t(`prefix_${id}`)`, FeatureGuide prefix) hesaba kat?l?nca ger?ekten kullan?lmayan yaln?zca 8 anahtar ??kt? (`help_hp_*`, TR+EN 16 sat?r) ? silindi. `RdpSecureMoveModal` silindi. `Brand` kullan?l?yor (kal?r). Inline style ? CSS ta??ma C4 (dosya b?lme) ile birlikte yap?lacak.
- [ ] **C4** Büyük dosyaları böl: `ThreatPage.tsx` (1039), `SettingsPage.tsx` (767), `StatusPage.tsx` (727), `App.tsx` (783), `style.css` (2398), `asteria_gui.py` (2682). Efor 1 gün. Risk orta.
  - [x] C4a: model/sabit/yard?mc?lar ayr?ld?: `pages/settings/fields.ts` (Settings 769?456), `pages/threat/model.ts` (Threat 1042?968), ortak `data/types.ts` (HardenCheck, IpRow; 3 kopya ? 1).
  - [ ] C4b: ThreatPage sekme JSX'leri, App.tsx, style.css, asteria_gui.py b?lme + inline style ? CSS (kalan).

## Faz 3 — UX / bilgi mimarisi
- [ ] **U1** 7 sayfa → 4: Durum / Tehditler (+IP listeleri) / Koruma (Katmanlar + Honeypot) / Ayarlar (+Araçlar "Gelişmiş"). Dosyalar: `ui/src/App.tsx`, `ui/src/nav.ts`, sayfalar. Efor 1 gün. Risk orta.
- [x] **U2** Teknik jargonu kaldır ('THREAT_TOP total', 'Cloud SoT', 'IPC 127.0.0.1:58632', çift Snapshot, başlıkta token). Dosyalar: `ui/src/i18n/catalog.ts`, sayfalar. Efor 3 sa. Risk düşük.
  - Sonu? (v4.9.153): SoT/IPC/threats-config/THREAT_TOP ifadeleri sade TR+EN metinlerle de?i?ti; Durum kart?nda 127.0.0.1:58632 yerine s?r?m; Tehditler ba?l???ndaki ?ift Snapshot d??mesi kald?r?ld?; ba?l?k ?eridinde token metni yok (kopyalama d??mesi + men? kald?).
- [ ] **U3** En sık aksiyonlar Durum'da tek tık: IP engelle/kaldır, beyaz liste, koruma modu, güncelle, motoru kurtar. Dosya: `StatusPage.tsx`. Efor 0.5 gün. Risk düşük.
- [ ] **U4** Ortak Loading / Empty / Error bileşenleri + tek hata/toast formatı. Dosyalar: `ui/src/components/*`. Efor 0.5 gün. Risk düşük.
- [ ] **U5** Başlık şeridi sade: durum noktası + makine adı, detay açılır. Dosyalar: `IdentityStrip.tsx`, `LiveMeters.tsx`, `App.tsx`. Efor 2 sa. Risk düşük.
- [ ] **U6** Ağır/nadir görünümler dashboard'a link (uyarı geçmişi, servis/paylaşım envanteri, yönetim konsolları). Dosyalar: `ThreatPage.tsx`, `ToolsPage.tsx`. Efor 0.5 gün. Risk düşük.

## Faz 4 — Mimari (başlanmadı)
- [ ] **A1** Motorda periyodik snapshot + olay push; GUI poll'suz. Dosyalar: `client.py`, `client_daemon_ipc.py`, `asteria_gui.py`, `ui/`. Efor 2-3 gün. Risk orta.
- [ ] **A2** Hafif tray + mini pencere; ağır yönetim asteria.run dashboard'da. Efor 1-2 hafta. Risk yüksek. **Ürün kararı gerekli (Cevdet).**