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
