# Security & Resilience Roadmap

> Tarih: 2026-07-22  
> Başlangıç sürümü: client **4.9.0**, contract **1.4.6** (P1 observe schemas
> promoted additive; floor unchanged)  
> Kapsam: agent hayatta kalma, deception, anti-ransomware, ağ kurtarma ve zero-trust  
> Durum: planlama + landed observe primitives; enforce/pilot kapıları
> `honeypot-contract` üzerinden ilerler.
> Ortak Client/Cloud teslim planı:
> [`SECURITY_RESILIENCE_VNEXT.md`](../../honeypot-contract/SECURITY_RESILIENCE_VNEXT.md).

Bu belge dış önerileri mevcut mimari ve daha önce yaşanan üretim
false-positive'ları ile birlikte değerlendirir. Amaç her öneriyi uygulamak
değil; güvenli, ölçülebilir ve geri alınabilir olanları ürüne kazandırmaktır.

## Değişmez güvenlik ilkeleri

1. **Önce zarar verme:** güvenlik motoru sunucuyu kilitlememeli, ağını otomatik
   bozmamalı ve meşru ağır-I/O süreçlerini otomatik dondurmamalıdır.
2. **Kullanıcı modunda “öldürülemez” garantisi yoktur:** hedef; meşru stop/update
   dışında kapanmayı tespit etmek, alarm üretmek ve kontrollü sürede dirilmektir.
3. **Containment insan onaylıdır:** `suspend_process`, `network_restore`,
   `kill_process` ve benzeri aksiyonlar exact-target doğrulaması ve dashboard
   confirmation gate ister.
4. **Cloud ihlali agent yetkisine dönüşmemelidir:** komutlar kimlik doğrulamalı,
   imzalı, süreli, replay-korumalı ve audit edilebilir olmalıdır.
5. **Gizlilik ile imza farklıdır:** private key ile **imza**, public key ile
   **doğrulama** yapılır. İçerik gizliliği ayrıca agent'ın public key'ine
   şifreleme gerektirir.
6. **Her yeni sensör önce shadow mode'da çalışır:** karar üretir ama aksiyon
   almaz; false-positive/CPU/RAM/event-loss ölçülmeden enforcement açılmaz.
7. **Mimari bilinse de güvenli kalmalıdır:** endpoint, port, banner veya detection
   akışının gizli olması bir güvenlik kontrolü değildir. Binary gizleme yalnız
   saldırgan maliyetini artıran ek katmandır.

## Durum işaretleri

- `[x]` Üründe mevcut
- `[~]` Kısmen mevcut / sertleştirme gerekli
- `[ ]` Kabul edildi, planlanacak
- `[R]` Revize edilerek kabul edildi
- `[X]` Reddedildi / ürün politikasına aykırı
- `[A]` Araştırma/PoC; üretim kararı verilmedi

## Öneri değerlendirme özeti

| Öneri | Karar | Gerekçe / ürün karşılığı |
|---|---|---|
| `REALTIME_PRIORITY_CLASS` | `[X]` | Windows'u ve uzaktan müdahaleyi aç bırakabilir. Agent için survival garantisi değildir. Kontrollü `ABOVE_NORMAL`, kritik kontrol thread'i ölçümü ve CPU watchdog değerlendirilecek. |
| İkiz servis/watchdog | `[~]` | Motor + LocalSystem Guardian + Watchdog task zaten var. Milisaniyelik respawn yerine SCM recovery, health probe, backoff ve restart-storm koruması güçlendirilecek. |
| Process ACL / kernel koruma | `[R]` | Process DACL mevcut. PPL sıradan uygulamaya verilemez; kernel driver yüksek saldırı/uyumluluk maliyetlidir. Önce SACL audit, ACL drift ve signed-driver fizibilitesi. |
| Nuitka/Cython | `[A]` | Obfuscation güvenlik sınırı değildir ve Defender false-positive'ını garanti çözmez. İmzalama, SBOM ve reproducible build öncelikli; sonra ölçümlü Nuitka PoC. |
| Credential honeytoken | `[R]` | LSASS/bellek enjeksiyonu yapılmayacak. Yetkisiz/ayrıcalıksız host-unique decoy credential + kullanım telemetrisi, açık opt-in ile PoC. |
| “Görünmez” tuzak dosya | `[R]` | NTFS hidden/system özniteliği gerçek görünmezlik sağlamaz. OS klasörlerini kirletmeden kontrollü canary dizinleri ve erişim telemetrisi genişletilecek. |
| RDP/SMB/SSH banner + tarpit | `[R]` | Gerçek servis portuyla çakışmayan, kaynak limitli düşük-etkileşimli state machine; timeout/rate limit ve hukuki banner incelemesiyle. |
| ETW file I/O | `[~]` | `client_etw_shadow` shadow surface + bounded fan-out/rename/write correlation landed; gerçek provider attach ve corpus hâlâ açık. |
| Şüpheli süreci anında suspend | `[~]` | Exact-target, onaylı suspend/resume zaten var. Otomatik suspend hard-disabled kalır; yüksek güvenli alarm + tek tık onay hızlandırılır. |
| Toplu parola değişimi tespiti | `[R]` | Security Event Log/AD olaylarıyla alert üretilecek. Admin'i otomatik lock etmek availability riski; yalnız operatör/onaylı kimlik sistemi aksiyonu. |
| DNS/ICMP tunneling | `[X]` | Covert channel/malware davranışıdır; müşteri ağ politikasını ve IDS/EDR güvenini ihlal eder. Yönetilen OOB HTTPS/proxy/VPN/cellular ve offline signed queue kullanılacak. |
| Shadow network state | `[~]` | Baseline + confirm restore + dry-run plan/`rollback_version` landed; otomatik connectivity rollback ve NIC safety matrix açık. |
| Asimetrik E2E komutlar | `[R]` | Önce browser/hardware-backed admin imzası + agent verification; sonra gerekirse agent public key'ine payload encryption. Key lifecycle şart. |
| Hardware fingerprint kilidi | `[R]` | UUID+MAC+CPU katı kilit VM clone/NIC/anakart değişiminde sistemi kilitler. TPM-backed device key/certificate + kontrollü re-enrollment tercih edilir. |
| PyInstaller decompilation riski | `[R]` | Python bytecode/metadata çıkarılabilir. Dual-track: GUI ayrılınca motor Nuitka/onefile + signing/attestation — [`ASTERIA_DUAL_TRACK_ROADMAP.md`](ASTERIA_DUAL_TRACK_ROADMAP.md). Secret gömmeme öncelikli. |
| Strings/static analysis | `[R]` | Endpoint/banner hata mesajı secret değildir. Release secret scanner ve gereksiz iç detay/log temizliği uygulanır; güvenlik endpoint gizliliğine bağlanmaz. |
| Procmon/debugger/dinamik analiz | `[R]` | Davranış tamamen saklanamaz. Tamper-evident runtime, signed binary/policy ve server-side enforcement ile bypass değeri azaltılır. |
| Wireshark trafik analizi | `[R]` | Doğru TLS doğrulamasında pasif dinleyici payload okuyamaz; hedef/cloud/TLS trust compromise ayrı tehdittir. E2E bu ikinci tehdidi azaltır. |
| PyArmor/anti-debug | `[A/X]` | Obfuscator yalnız ölçümlü PoC olabilir; agresif anti-debug/packer davranışları AV false-positive ve bakım riskinden dolayı planlanmaz. |

## Mevcut temel — tekrar yapılmayacak

- `[x]` SYSTEM motor + `CloudHoneypotGuardian` LocalSystem servisi +
  `CloudHoneypot-Watchdog` task ile cross-watchdog.
- `[x]` SCM restart-on-failure, Background task recovery ve update/PIN
  stand-down sinyalleri.
- `[x]` Process DACL, tamper wire, signed operator-stop ve update handoff.
- `[x]` Canary dosyaları, VSS/quarantine ve ransomware urgent alert akışı.
- `[x]` HMAC-imzalı, versioned network baseline; snapshot/list/confirm-gated restore.
- `[x]` Network Guard alert-only invariantı; exact
  `pid+image+path+process_start_time` ile onaylı suspend/resume.
- `[x]` Komut whitelist/expiry/rate-limit ve destructive confirmation gate.
- `[~]` Komut HMAC mevcut ama **imzasız komutlar hâlâ kabul edilir**
  (`verify_command_signature` transition-period).
- `[x]` DPAPI ile yerel token saklama.
- `[~]` Device identity: `MachineGuid` + read-only TPM capability PoC
  (`client_device_identity`); enrollment/attestation yok.
- `[~]` Honeypot banner/handshake olgun; handler/rate budgets exposed; gerçek
  tarpit (yavaş yanıt) yok.
- `[x]` Event Log 4723/4724 parola değişimi/reset + ID-402 burst aggregate
  (alert-only, no lockout).
- `[~]` Update SHA-256 + Authenticode/WinVerifyTrust policy hooks; fleet
  signing / enforce hâlâ org-cert + contract bağımlı.

### Kod envanteri (2026-07-22)

| Alan | Olgunluk | Kanıt / boşluk |
|---|---|---|
| Daemon / Guardian / Watchdog | Mature | `client_guardian_service.py`, `client_task_scheduler.py`, `client_tamper.py` |
| Self-protect / DACL / tamper | Mature* | `client_self_protection.py` — *SeDebug bypass mümkün; process-wide priority yok |
| Packaging / signing | Partial | `build.ps1 -Sign` + provenance + WinVerifyTrust policy; org cert yok |
| Canary / decoy credentials | Mature / Partial | canary + coverage counts + protocol bait; LSASS plant yok |
| Honeypot banner / tarpit | Mature / Partial | banner+handshake + `get_health` budgets; delay tarpit yok |
| Ransomware / ETW / suspend | Mature / Partial / Mature | canary/VSS + ETW shadow correlation; provider attach yok; auto-contain kapalı |
| AD/SAM password-change | Partial | 4723/4724 + burst aggregate landed; cloud timeline (ID-403) pending |
| Network baseline / OOB | Mature / Partial | dry-run/rollback selector + DPAPI offline queue primitive; secondary path yok |
| Cmd HMAC / E2E | Partial / Absent | v1 HMAC observe + envelope-v2/keyset scaffold; E2E payload crypto yok |
| Device ID / TPM | Partial | MachineGuid + read-only TPM probe; enrollment yok |

Referanslar:

- [Persistence & tamper](../../honeypot-contract/agent/persistence-and-tamper.md)
- [Network Guard](../../honeypot-contract/agent/network-guard.md)
- [Ransomware Shield](../../honeypot-contract/agent/ransomware-shield.md)
- [Control WebSocket](../../honeypot-contract/api/03-control-websocket.md)
- [`client_self_protection.py`](../client_self_protection.py)
- [`client_guardian_service.py`](../client_guardian_service.py)
- [`client_network_guard.py`](../client_network_guard.py)
- [`client_security_utils.py`](../client_security_utils.py)
- [`client_eventlog.py`](../client_eventlog.py)

## Faz 0 — Ölçüm, güvenlik sınırları ve tedarik zinciri

Hedef: Yeni korumaların yanlış pozitif veya restart storm ile sistemi
etkilemesini önleyecek test/telemetri tabanı; mevcut command-signing ve
update-integrity boşluklarını kapatmak.

- [~] **SR-001 — Resilience SLO'ları:** `client_resilience` + STATUS/health
  additive `resilience{}` (draft); cloud ignore-until-promoted.
- [~] **SR-002 — Restart-storm breaker:** motor/Guardian recovery için bounded
  exponential backoff; storm bayrağı; stand-down (update/PIN) ayrımı.
- [~] **SR-003 — Guardian kurulum sağlığı:** motor cross-watch
  `ensure_guardian_with_backoff`; WIN32_EXIT_CODE okuma; installed-but-down heal.
- [~] **ZT-600 — İmzasız komutları reddet:**
  Observe hazır (`inspect_command_signature` + yerel `signature_*` sayaçları);
  invalid hâlâ reject, missing hâlâ soft-allow. Enforce ancak cloud %100 imza
  + ortak test vektörü + contract promotion sonrası açılır.
- [~] **SUP-001 — Authenticode release signing:** `build.ps1 -Sign` + CertPath
  kancası; cert yoksa unsigned dev build devam eder (cert dış bağımlılık).
- [~] **SUP-001b — WinVerifyTrust on update:** `client_authenticode` + update
  path enforce yalnız `require_authenticode` / `allowed_publishers` ile.
- [~] **SUP-002 — SBOM + provenance:** `dist/release-provenance-v*.json`
  (sha256/size/toolchain); tam SBOM sonraki adım.
- [ ] **SUP-003 — Reproducible-build yaklaşımı:** aynı kaynak/tag için
  doğrulanabilir artifact manifesti; release checksum contract/metadata'ya bağlanır.
- [x] **QA-001 — Fault-injection harness:** `tests/test_fault_injection.py`
  recovery defer/reopen, storm prune, stand-down, Guardian heal. Broader
  scenarios (network cut, disk-full, corrupt baseline, mid-update reboot)
  remain as follow-on coverage.

Kabul:

- Motor beklenmedik kill sonrası hedef sürede geri gelir.
- Tekrarlı crash, CPU/restart storm üretmez.
- Update/uninstall/PIN stop false tamper üretmez.
- İmzasız/yanlış imzalı remote command kabul edilmez.
- Release artifact'ları Authenticode + SBOM ile doğrulanır; update path
  WinVerifyTrust uygular.

## Faz 1 — Agent hayatta kalma ve tamper sertleştirme

### Öncelik politikası

- [ ] **RES-101 — Ölçümlü priority policy:** varsayılan `NORMAL`; yalnız motorun
  control/heartbeat thread'i için gerektiğinde `ABOVE_NORMAL` PoC.
  **Landed (client ≥4.9.8):** Session-0 daemon process-wide `ABOVE_NORMAL`
  (`client_process_priority.py`); config `security.motor_priority`
  (`above_normal`|`high`|`normal`); REALTIME reddedilir.
- [~] **RES-102 — Priority safety guard:** CPU, scheduler latency ve UI/RDP
  erişilebilirliği bozulursa otomatik normal seviyeye dönüş.
  **Lite (client ≥4.9.8):** motor CPU ≥55% ~45s → NORMAL.
- [X] Process-wide `REALTIME_PRIORITY_CLASS` üretimde kullanılmayacak.

### Watchdog ve process koruma

- [~] **RES-103 — Guardian↔motor signed heartbeat:** `client_resilience_p1`
  HMAC candidate + `system_context.heartbeat_proof` (default-off). Guardian
  verify/reject-stale henüz bağlı değil; cloud/schema promote gerekli.
- [x] **RES-104 — Recovery policy testleri:** `tests/test_fault_injection.py`
  recovery defer/reopen, storm prune, stand-down, Guardian heal.
- [ ] **RES-105 — SACL/access audit:** `PROCESS_TERMINATE`,
  `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION`, handle duplication taleplerini
  offender PID/image/hash ile audit et; event kaybını raporla.
  *(Note: RES-105 ACL fingerprint observe is landed under access_integrity;
  process-handle SACL remains open.)*
- [~] **RES-106 — ACL drift monitor:** `client_resilience_p1` icacls fingerprint
  + HMAC baseline → `access_integrity` (default-off). Auto-repair yok.
- [A] **RES-107 — PPL/signed driver feasibility:** Microsoft signing,
  HVCI/WDAC/Defender uyumluluğu, patch cadence ve kernel crash riski incelenir.
  PoC başarı/kabul kriteri olmadan driver geliştirilmez.

### Reverse-engineering threat model ve secret hygiene

- [ ] **REV-101 — Binary exposure threat model:** offline binary sahibi local
  user, local admin/SYSTEM, sandbox/debugger ve cloud compromise yeteneklerini
  ayrı değerlendir; hangi kontrolün hangi saldırgana direnç sağladığını yaz.
- [~] **REV-102 — Embedded secret inventory:** `scripts/scan_embedded_secrets.py`
  (+ CI-friendly path) landed; expand corpus / release-binary scan cadence open.
- [ ] **REV-103 — Local-state protection:** token dışındaki hassas policy,
  network baseline, command cache ve forensic metadata için DPAPI/ACL/içerik
  bütünlüğü matrisi; local admin sınırı açıkça belgelenir.
- [~] **REV-104 — Runtime binary integrity:** `client_integrity.py` observe-only
  Authenticode publisher doğrulaması motor start sonrası çalışır ve
  `resilience.binary_integrity` (`valid|invalid|unknown`) besler. `invalid`
  yalnız *present-but-broken* imza (tamper) için ayrılır; imzasız fleet
  `unknown` raporlar. Startup blocking + kritik module hash manifest + urgent
  alarm sonraki adım (enforce contract promote ile).
- [ ] **REV-105 — Release strings/log hygiene:** secret scanner'a ek olarak
  internal path, verbose exception, test credential ve debug switch envanteri;
  operasyonda gerekli endpoint/banner string'leri kasıtlı ve belgeli kalır.
- [ ] **REV-106 — Customer hardening guidance:** opsiyonel WDAC/AppLocker
  allow-policy, service/file ACL ve EDR exclusion istemeden Authenticode trust.

### Derleme/IP koruma

- [ ] **BUILD-101 — Nuitka karşılaştırma PoC:** startup, RAM, CPU, build süresi,
  installer boyutu, AV false-positive, update/rollback ve crash symbolization
  ölç; `customtkinter`, pywin32, aiortc/AV ve Windows service modlarını test et.
- [ ] **BUILD-102 — Hassas materyal temizliği:** binary içinde uzun ömürlü
  secret/private key bulunmadığını otomatik tarayan release check.
- [ ] **BUILD-103 — Karar kaydı:** PyInstaller vs Nuitka hibrit/tam geçiş için
  ölçümlü ADR; “tersine mühendislik imkânsız” iddiası kullanılmaz.
- [A] **BUILD-104 — Hybrid native security core:** tüm GUI/ürünü taşımak yerine
  command verification, signed-policy parsing, integrity/ETW ve device-key
  işlemlerini küçük Rust/C/C++ native modüle ayırmanın bakım ve güvenlik PoC'si.
- [A] **BUILD-105 — Obfuscation değerlendirmesi:** PyArmor benzeri runtime/
  lisans bağımlılığı, AV skoru, crash/debug kabiliyeti ve update uyumluluğu.
  Sonuç ölçülmeden release pipeline'a girmez.
- [X] Anti-debug, debugger kill, packer/self-modifying code ve yanıltıcı
  system-call teknikleri kullanılmayacak; bunlar yetenekli analisti durdurmaz,
  AV güvenini ve desteklenebilirliği bozar.

## Faz 2 — Deception ve honeytoken genişletmesi

- [~] **DEC-201 — Canary coverage map:** `RansomwareShield.get_stats().canary_coverage`
  path-free counts landed; share/profile inventory expansion + shared
  correlation-id across delete/rename/write still open.
- [~] **DEC-202 — Controlled NTFS canary:** Hidden|System|NotContentIndexed in
  product-owned trees; ACL variant PoC under canary root still open. No
  Windows/Program Files planting.
- [A] **DEC-203 — Credential honeytoken PoC:** ayrıcalıksız, gerçek erişim
  vermeyen, host-unique decoy; kullanım yalnız kontrollü decoy endpoint/domain
  üzerinde alarm üretir. LSASS veya gerçek credential belleğine enjeksiyon yok.
- [ ] **DEC-204 — Honeytoken lifecycle:** create/rotate/revoke, tenant isolation,
  incident correlation, privacy ve uninstall cleanup.
- [~] **DEC-205 — Protocol-aware decoys:** existing SSH/RDP/MySQL/MSSQL/HTTP/SMB
  handlers + port-in-use reject; deeper SMB share decoy + signed banner profiles open.
- [~] **DEC-206 — Tarpit resource budget:** handler cap + rate limiter +
  `BaseHoneypot.get_health()` budgets landed; delay tarpit / emergency disable
  telemetry still open.
- [ ] **DEC-207 — Deception telemetrisi:** auth attempt, username, source IP,
  protocol stage ve dwell time; parola/secret loglamadan.
- [~] **DEC-208 — Fingerprint-resistance:** `fingerprint_profile=static_legacy`
  exposed; contract-controlled banner profiles + jitter not yet distributed.
- [~] **DEC-209 — Bypass-aware coverage:** Event Log + Network Guard + ransomware
  remain independent of honeypot listeners; explicit health matrix narrative open.

Kabul:

- Decoy gerçek sisteme erişim vermez ve gerçek credential içermez.
- Honeypot DoS aracı olmaz; kaynak limitinde otomatik kapanır.
- Uninstall/disable tüm artifact'ları geri alır.

## Faz 3 — ETW tabanlı davranışsal ransomware sensörü

- [~] **RANS-301 — ETW provider PoC:** `client_etw_shadow` shadow yüzeyi +
  event-loss sayaçları (auto-containment kapalı; gerçek provider henüz bağlı değil).
- [~] **RANS-302 — Kayıp olay telemetrisi:** drop/pressure/restart counters in
  `etw_shadow` status; `psutil`/Event Log named fallback wiring still open.
- [~] **RANS-303 — Korelasyon motoru:** bounded fan-out/rename/write correlation
  in shadow sample (no raw paths; no containment). Entropy + canary/VSS join
  and corpus evaluation remain open.
- [ ] **RANS-304 — Shadow mode:** en az iki release boyunca alarm-only ölçüm;
  backup/indexer/compiler/browser/AV false-positive corpus'u.
- [ ] **RANS-305 — Hızlı operatör containment:** yüksek güvenli alarmda exact
  process identity ile tek tık suspend; ardından dump/hash/VSS/resume/kill
  seçenekleri.
- [ ] **RANS-306 — Forensic capture:** onaylı suspend sonrası minimum metadata,
  open files, network connections ve opsiyonel memory dump; retention,
  encryption ve erişim kontrolü.
- [X] Otomatik `NtSuspendProcess` enforcement açılmayacak; mevcut
  operator-confirmed safety invariantı korunacak.

## Faz 4 — Kimlik saldırıları ve parola değişimi görünürlüğü

- [~] **ID-401 — Security Event Log sensörü:** **4723/4724** izleme + skor/
  kategori eklendi (alert-only; otomatik lockout yok).
- [~] **ID-402 — Burst correlation:** `PasswordBurstCorrelator` →
  `event_log_health.password_burst` (sliding window aggregates; no lockout).
  Service-account allowlist expansion open.
- [~] **ID-403 — Cloud incident görünümü:** client emits bounded burst stats;
  dashboard timeline/redaction UX is cloud-owned and still pending.
- [ ] **ID-404 — Onaylı response entegrasyonu:** dashboard önerisi/harici IAM
  playbook; endpoint agent kendi başına domain admin hesabını lock etmez.
- [X] Salt burst sinyaliyle otomatik admin lockout uygulanmayacak.

## Faz 5 — Ağ self-healing ve meşru OOB

- [~] **NET-501 — Baseline diff/dry-run:** `plan_network_restore` + `dry_run`
  on restore commands (no mutate). Interface/NIC safety matrix still open.
- [~] **NET-502 — Versioned rollback:** `rollback_version` selector verifies
  retained signed baseline before mutate; automatic connectivity rollback open.
- [ ] **NET-503 — Restore safety:** RDP/management NIC, VPN, DHCP/statik IP ve
  domain network profili test matrisi.
- [~] **OOB-501 — Offline signed queue:** contract **1.4.7** `api/10` live;
  client spool/drain + durable `oldest_dropped` health block + harness green;
  `security.offline_urgent_queue` still **default off** — **one-host live
  canary pilot** remains the open acceptance gate.
- [ ] **OOB-502 — Secondary HTTPS path:** müşteri onaylı ikinci FQDN/endpoint,
  sistem proxy ve certificate pin/rotation stratejisi.
- [A] **OOB-503 — Managed side channel:** müşterinin sağladığı management VPN,
  ayrı NIC veya cellular gateway entegrasyonu; opt-in ve açık ağ politikasıyla.
- [X] DNS/ICMP içine veri gizleyen tünel geliştirilmeyecek.

## Faz 6 — Zero-trust komut ve cihaz kimliği

### Asimetrik komut yetkilendirme

- [~] **ZT-601 — Canonical command envelope v2:** cloud tasarım kapısı
  `honeypot-contract/cloud/command-envelope-v2-design.md`. Client tarafında
  `client_command_envelope.py` yalnız design/observe iskeleti sağlar:
  deterministik `params_hash`, yapısal/expiry/params sınıflandırıcı ve
  control-WS `hello.caps.command_envelope_v2` için dürüst kapasite (`off`
  varsayılan, opsiyonel `observe`; **enforce asla ilan edilmez**). Asimetrik
  operator imza doğrulaması ve production `version:2` wire, kontrat gate 1
  (serialization/algoritma/test vektörleri promote) ve ZT-603 anahtar dağıtımı
  öncesi **çıkarılmaz**.
- [~] **ZT-602 — Hardware-backed admin signing:** browser WebAuthn still
  cloud/dashboard; client exposes public keyset metadata scaffold only.
- [~] **ZT-603 — Agent verification:** `client_operator_keys.inspect_keyset`
  public metadata/rotation observe; asymmetric verify disabled until cloud
  distributes keys + contract promote.
- [ ] **ZT-604 — Multi-party approval:** panic/isolate/restore/credential gibi
  yüksek etkili komutlarda tenant politikasına göre ikinci onay.
- [ ] **ZT-605 — Replay/ordering:** nonce + TTL + per-device sequence window +
  idempotent result; audit kaydı imza hash'i taşır.
- [~] **ZT-605b — Transport threat model:** documented in
  `docs/P1_SECURITY_RESILIENCE_CLIENT.md` + unit coverage; production pin/
  custom-CA parity on WS path still open.

### Opsiyonel payload gizliliği

- [ ] **ZT-606 — Device encryption key:** TPM-backed mümkünse non-exportable;
  agent public key registration/attestation.
- [A] **ZT-607 — E2E payload encryption:** hassas params agent public key'ine
  HPKE/hybrid encryption; cloud yalnız ciphertext taşır. Routing metadata'nın
  cloud'a görünmeye devam ettiği açıkça belgelenir.
- [ ] **ZT-607b — Server-side minimization:** cloud'un plaintext gerektirmediği
  panic/credential payload'ları log, audit body ve error telemetry'ye girmez;
  agent sonucu da minimum veriyle döner.
- [ ] **ZT-608 — Recovery:** admin/device key kaybı, rotation, cihaz yeniden
  kayıt ve break-glass prosedürü.

### Device identity

- [~] **DEV-601 — TPM device certificate:** `client_device_identity.probe_tpm`
  read-only capability PoC (default-off). No key generation, enrollment, or
  lock on TPM absence.
- [ ] **DEV-602 — Soft signals:** SMBIOS UUID, machine SID ve donanım sinyalleri
  yalnız risk/attestation girdisi; tek başına hard lock değil.
- [ ] **DEV-603 — Re-enrollment:** anakart/NIC/VM clone değişiminde güvenli
  dashboard approval ve eski device credential revocation.
- [X] MAC+CPU+UUID değiştiğinde ajanı koşulsuz çalışmaz hale getiren fingerprint
  kilidi uygulanmayacak.

## Önceliklendirilmiş yapılacaklar listesi

### P0 — Sonraki güvenlik sprinti

> Contract **1.4.2** hizalaması (2026-07-22): cloud additive health şemalarını
> promote etti. Client `health/report` snapshot'ı artık observe blokları
> gönderir: `command_signing{observe,enforce,ok,missing,invalid,no_token,
> disabled}` (ZT-600), `event_log_health{}` (ID-401, ham event yok),
> `etw_shadow{}` (RANS-301, contract anahtarına göre yeniden adlandırıldı) ve
> `resilience.stand_down_reason` artık `update|operator_pin|uninstall|null`
> enum'una normalize edilir. Enforce hepsi kapalı; missing = legacy.

- [~] **ZT-600** Observe telemetry landed + health `command_signing` block; missing-sig enforce blocked on cloud/contract
  - [~] SR-001 Resilience SLO + local/status telemetry (cloud promote pending)
  - [~] SR-002 Restart-storm breaker
  - [~] SR-003 Guardian `installed but not running` self-heal
  - [~] SUP-001 Authenticode signing hook (`build.ps1 -Sign`; needs org cert)
  - [~] **SUP-001b** Update path WinVerifyTrust (policy-gated; soft-skip default)
  - [~] SUP-002 release provenance JSON (full SBOM later)
  - [~] QA-001 Fault-injection harness (`tests/test_fault_injection.py`: recovery/storm/stand-down)
  - [~] **REV-101/102** Embedded secret CI scan (`tools/scan_embedded_secrets.py`)
  - [~] **REV-104** Runtime self-integrity (`client_integrity.py`; observe-only → `binary_integrity`)
  - [~] **ID-401** Event Log 4723/4724 parola değişimi/reset (client sensor)
  - [~] RANS-301 ETW shadow PoC surface (provider attach later)
  - [~] ZT-601 Envelope-v2 scaffolding (`client_command_envelope.py`; design/observe, no verify/emit)

### P1 — P0 ölçümleri yeşil olduktan sonra

- [~] RANS-302/303 ETW event-loss + bounded fan-out/rename/write correlation
  + named `source`/`fallback` (`stub`|`psutil`) observe sampler
  (`threat_detection.etw_psutil_fallback`, default off; real provider/corpus pending)
- [~] DEC-201/202 canary coverage counts (path-free health; Desktop config bait
  removed + deploy-time Desktop path reject; matrix expansion pending);
  `canary_coverage` + `deception_health[]` now on `health/report` (contract 1.4.5)
- [~] RES-103 signed-heartbeat candidate + local `verify_heartbeat_proof`
  + Guardian observe-only deadman soft-check (`client_guardian_service`;
  default off; reject-stale **not** wired)
- [~] RES-105 SACL/access audit (bounded DACL fingerprint landed; SACL privilege
  inventory and canonical health schema pending)
- [~] RES-106 ACL drift monitor (local HMAC baseline, observe-only, no mutation)
- [~] DEC-205/206 protocol-aware decoy + resource budgets already present;
  `BaseHoneypot.get_health` exposes handler/rate/backlog saturation
- [~] DEC-208/209 static fingerprint profile is honestly reported and bypass
  coverage required; contract-controlled profiles/corpus evaluation pending
- [~] NET-501/502 restore dry-run plan + signed retained-version rollback selector
  (automatic connectivity rollback intentionally not enabled)
- [~] OOB-501 DPAPI+HMAC offline queue aligned to contract **1.4.7** api/10
  (batch ACK, soft idempotency, TTL/caps/reject); flag still default off —
  enable only for pilot drain
- [~] ID-402/403 password-change burst correlation in Event Log health; no raw
  identities/passwords and no auto-lockout (dashboard schema pending)
- [~] ZT-602/603 public operator-key poll (`security.operator_keys_observe`) +
  inspect scaffold; asymmetric verify disabled until algorithm/vectors
- [~] ZT-605b TLS/interception/cloud-compromise test matrix documented in
  `docs/P1_SECURITY_RESILIENCE_CLIENT.md`
- [~] DEV-601 read-only TPM capability PoC; no key generation, enrollment or lock

### P2 — Kontrollü pilot

- [ ] DEC-203 credential honeytoken opt-in pilot
- [ ] RANS-304 shadow-mode corpus evaluation
- [ ] OOB-502/503 customer-managed secondary path pilot
- [ ] BUILD-101 Nuitka benchmark
- [ ] BUILD-104 hybrid native security-core PoC
- [ ] BUILD-105 obfuscation benchmark (release kararı değil)
- [ ] ZT-607 E2E payload encryption pilot

## Her iş için zorunlu Definition of Done

- Contract/ADR ve threat model güncel.
- Feature flag + güvenli varsayılan + rollback yolu var.
- Unit/integration/fault-injection testleri var.
- CPU/RAM/disk/network/event-loss bütçesi ölçülmüş.
- False-positive ve allowlist davranışı belgelenmiş.
- Loglarda token, parola, key material veya typed text yok.
- Dashboard status/audit/operatör geri bildirim yolu tamamlanmış.
- Upgrade/uninstall/reboot/Session 0/RDP/çoklu kullanıcı senaryoları test edilmiş.
- Canlı pilot tamamlanmadan fleet-wide enforcement yok.

## Bilinçli olarak kapsam dışı

- Process-wide realtime scheduling.
- Covert DNS/ICMP data tunneling.
- Otomatik admin/domain lockout.
- Alert sinyalinden otomatik process suspend/kill.
- İmzasız veya net bakım planı olmayan kernel driver.
- Donanım değişiminde cihazı geri döndürülemez biçimde kilitleme.
- “Obfuscation = güvenlik” veya “hidden file = görünmez” varsayımı.
- Endpoint/banner/detection akışını secret kabul eden security-by-obscurity.
- Anti-debugger, self-modifying packer veya analiz aracını sabote eden davranış.
- “Nuitka ile aylarca çözülemez” gibi ölçülmemiş güvenlik iddiaları.

