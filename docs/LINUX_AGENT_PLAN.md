# Asteria Linux / macOS Agent — Future Plan

> Tarih: 2026-07-29  
> Durum: **plan notu** (henüz implementasyon yok)  
> Bağlam: Windows client **≥4.9.52** canlı; cloud kontrat tek SoT  
> İlgili: [`ASTERIA_DUAL_TRACK_ROADMAP.md`](ASTERIA_DUAL_TRACK_ROADMAP.md) ·  
> contract `FLEET.md` · `agent/firewall-management.md` / `firewall-windows-parity.md`

## Karar özeti

**Tek ürün / tek kontrat / paylaşılan çekirdek — evet.**  
**Mevcut Windows kodunu olduğu gibi Linux/Mac’te koşturmak — hayır.**

Hedef: tek kod tabanı ile Windows + Linux sunucuları (sonra macOS) aynı dashboard’dan korumak; model **ortak motor + OS backend adaptörleri**, “Windows client port” değil.

---

## Neden doğrudan port olmaz?

Windows client şu an OS güvenlik yüzeyine sıkı bağlı:

| Alan | Windows bugün | Linux karşılığı | macOS |
|------|---------------|-----------------|-------|
| Firewall | `netsh` / WFAS | nftables / iptables (+ firewalld) | `pf` |
| Persistence | Scheduled Tasks + Guardian | systemd unit | launchd |
| Users / IR | SAM / net user | passwd/sshd / PAM | Directory Services |
| Ransomware | VSS / IFEO | fanotify / immutable / farklı model | sınırlı |
| Remote Desktop | DXGI / Winlogon / WebRTC | genelde **istemez** (sunucu headless) | ayrı |
| GUI | WebView2 Control Center | opsiyonel / SSH+dashboard | opsiyonel |

Kabaca: sunucu IR + firewall + process/service **ortaklaşabilir**; ransomware / RD / GUI **Windows’a özgü** kalır (veya ayrı ürün hattı).

---

## Hedef mimari

```
asteria-agent (Python çekirdek)
├── core/          # API, heartbeat, signing, remote commands router, policy
├── platform/
│   ├── windows/   # mevcut netsh, tasks, SAM, RD, RS …
│   ├── linux/     # nftables, systemd, proc, users
│   └── macos/     # pf, launchd (dalga 2)
└── features/      # contract handler’lar (list_firewall, block_ip, …)
```

- **Cloud API / kontrat aynı** (`list_firewall`, `block_ip`, `kill_process`, …).
- Eksik OS özelliği → `success:false` + dürüst `error=UNSUPPORTED_ON_PLATFORM` (sessiz no-op yok).
- FLEET’te platform floor: örn. `linux ≥ x.y.z` ayrı satır.

---

## Özellik matrisi (hedef)

| Özellik | Windows | Linux MVP | Linux v2 | macOS |
|---------|---------|-----------|----------|-------|
| Heartbeat / presence / komut kuyruğu | ✅ | ✅ | ✅ | ✅ |
| `block_ip` / `unblock_ip` / sync | ✅ | ✅ | ✅ | ✅ |
| `list_firewall` / profil / kural | ✅ (1.4.41) | nftables subset | parity | pf subset |
| Process / service IR | ✅ | ✅ | ✅ | kısmi |
| Network Guard | ✅ | — | adaptör | — |
| System Recovery | ✅ | — | allowlist | — |
| Ransomware Shield | ✅ | — | ayrı tasarım | — |
| Remote Desktop | ✅ | ❌ | ❌ | belki |
| GUI Control Center | ✅ | opsiyonel | — | opsiyonel |

---

## Uygulama fazları

### Faz 0 — Kontrat / FLEET (dokümantasyon)
- `agent/linux-surface.md` (normative feature floor)
- FLEET satırı: Linux agent min sürüm + desteklenen komut listesi
- Platform hata kodları (`UNSUPPORTED_ON_PLATFORM`)

### Faz 1 — Linux daemon MVP (sunucu IR)
- Headless `asteria-agent` binary (PyInstaller / Nuitka Linux)
- systemd unit + deb/rpm (ve tek binary tarball)
- Heartbeat + Bearer komutlar
- Firewall: `block_ip` / `unblock_ip` / `list_firewall` (nftables veya iptables+ipset; mevcut `LinuxFirewallBackend` iskeleti genişletilir)
- `kill_process`, `list_processes`, `list_services` (systemd)
- Kurulum: root; state `/var/lib/asteria`

### Faz 2 — Operatör parity
- `firewall_set_profile` / `firewall_rule` Linux karşılıkları (zone / chain modeli — Windows profil birebir değil; kontratta “best-effort map” notu)
- Network Guard benzeri (interface + route snapshot; restore dikkatli)
- Self-update Linux kanalı

### Faz 3 — macOS (talep gelirse)
- Workstation odaklı; pf + launchd
- Sunucu önceliği Linux’ta kalır

---

## Bilinçli non-goals (v1 Linux)

- Windows GUI / WebView2’yi Linux’a taşımak
- Tam Remote Desktop parity
- VSS/IFEO ransomware’in birebir kopyası
- “Tek exe her yerde” — paketler OS’e özel olur; **kaynak ve kontrat tek**

---

## Riskler

| Risk | Mitigasyon |
|------|------------|
| nftables vs iptables vs firewalld dağılımı | Distro probe + tek backend seçimi; fallback dokümante |
| Root yetkisi / immutable host | Fail-closed + net hata; container’da sınırlı mod |
| Windows-only dashboard varsayımları | Cloud UI’da OS badge + disabled actions |
| Kod çatallanması | Platform kodunu `platform/*` altında tut; core’a OS if sızdırma |

---

## Sonraki somut adım (başlatınca)

1. Contract PR: `agent/linux-surface.md` + FLEET draft  
2. Repo’da `platform/linux/` iskeleti + CI (Ubuntu runner) smoke  
3. `block_ip` + heartbeat E2E lab (1 VM)

Bu dosya **ilerideki plan notudur**; Windows 1.4.41 firewall parity işinin parçası değildir.
