Cloud Honeypot Client
=====================
**Current Version: 4.9.26**

Cloud Honeypot Client; belirlediğiniz servis portlarını güvene alıp ters tünel üzerinden Honeypot servisine ileten, tepside (tray) çalışan bir Windows istemcisidir. Açık kaynak geliştirilir; sunucu/dashboard tarafındaki gelişmiş özellikler ayrıca lisanslanabilir.

Son Sürüm Değişiklikleri
- Tam liste: [`docs/CHANGELOG.md`](docs/CHANGELOG.md) (v4.5.68 güncel)
- Cloud API sözleşmeleri: [`../honeypot-contract`](../honeypot-contract) (`docs/` stub + pointer)

Özellikler
- Ters tünel: Seçili portları TLS üzerinden sunucuya taşır.
- RDP koruma: RDP portunu 3389 ↔ 53389 taşıma ve geri alma akışı.
- Kalıcılık: İsteğe bağlı Görev Zamanlayıcı ile açılışta çalışma.
- Kalp atışı ve saldırı sayacı: API ile haberleşme.
- Kullanıcı onayı: Açılışta görünür onay ve tercihler.
- Dil desteği: Türkçe ve İngilizce; uygulama içinden değiştirilebilir.
- Otomatik güncelleme: GitHub Releases üzerinden yeni sürümü indirip kendini günceller.
- Firewall Agent: Dashboard'tan verilen IP/CIDR/ülke bloklarını (Windows/Linux) yerel firewall'a uygular.

Firewall Agent
- Kural adı: `HP-BLOCK-<id>` (dashboard) / `HP-BLOCK-<ip>` (auto-response)
- Windows: `netsh advfirewall firewall add rule ... action=block remoteip=<CIDR>`; büyük listelerde otomatik parçalama.
- Linux: Tercihen `ipset` + `iptables -m set` (fallback: `iptables` + `comment`).
- Ülke blokları: Varsayılan kaynak ipdeny.com (`https://www.ipdeny.com/ipblocks/data/countries/<cc>.zone`), günlük cache.
- Konfig: `API_BASE`, `TOKEN`, `CIDR_FEED_BASE` (opsiyonel), `REFRESH_INTERVAL_SEC` (varsayılan 10s).

Derleme
- Gereksinimler: Python 3.11/3.12, pip, PyInstaller, NSIS
- Build: `powershell -ExecutionPolicy Bypass -File build.ps1`
  - Çıktı: `cloud-client-installer.exe` (~20 MB)
- WebRTC/H.264 release profili:
  - `python -m pip install -r requirements-webrtc.txt`
  - `powershell -ExecutionPolicy Bypass -File build.ps1 -WebRTC`
  - Runtime doğrulanamazsa build hata verir; normal build yalnız JPEG/WS fallback yayınlar.

İmzalama (isteğe bağlı)
- Üretim için OV/EV Code Signing sertifikası önerilir.
- Geliştirme için self-signed PFX ile imza atabilirsiniz.

Otomatik Güncelleme
- Uygulama açılışında veya menüden "Güncellemeleri Denetle" ile GitHub Releases'ı kontrol eder.
- Yeni sürüm bulursa `cloud-client-installer.exe`'yi indirir ve sessiz kurulum yapar.
- Daemon modu için Task Scheduler her 2 saatte bir güncelleme kontrolü yapar (oturum açık olmasa bile).
- Repo bilgisi `client_constants.py` içinde `GITHUB_OWNER`/`GITHUB_REPO` ile yapılandırılır.

Release
- Changelog: `docs/CHANGELOG.md` (eski `release_notes_v*.md` birleştirildi)
- Manuel release: `gh release create vX.Y.Z --title "vX.Y.Z" --notes-file docs/CHANGELOG.md cloud-client-installer.exe`
  (veya sürüm için kısa notes; tam geçmiş `docs/CHANGELOG.md`)
- Operasyon: `docs/OPERATIONS.md`
- Cloud API: `docs/api/`

Sürümleme
- SemVer: `__version__` değişkeni üzerinden (`client_constants.py`).
- Dağıtımlar GitHub Releases ile etkinleştirilir.

Katkılar
- Lütfen CONTRIBUTING.md ve CODE_OF_CONDUCT.md belgelerini inceleyin.

Güvenlik
- Güvenlik açıklarını kamuya açık issue yerine SECURITY.md'teki kanallardan bildirin.

Lisans
- Apache-2.0 Lisansı (LICENSE dosyasına bakın).

Kullanım (Windows)
- `cloud-client-installer.exe`'yi release sayfasından indirin.
- Installer'ı yönetici olarak çalıştırın.
- İlk açılışta token'ı girin; firewall agent arka planda otomatik başlar.

Notlar
- Ülke CIDR feed'i varsayılan ipdeny.com'dur; istenirse `CIDR_FEED_BASE` ile değiştirilebilir.
- Firewall komutları için Windows'ta Administrator, Linux'ta root yetkisi gerekir.

