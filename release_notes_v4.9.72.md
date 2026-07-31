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
