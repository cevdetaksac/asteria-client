# 4.9.135 — CRD touch: trackpad relative + tap-at-cursor

## Fix
- After relative SendInput, sync `_last_px/_last_py` via GetCursorPos (trackpad taps no longer jump)
- `tap`/`double_tap`/`long_press` with `mode=trackpad` click at current cursor

Pairs with cloud v2 CRD touch UI (contract 1.4.96 C-RD-TOUCH).
