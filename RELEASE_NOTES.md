# 4.9.134 — HW path: honor cloud stream_id + do not gate on Session-0 selftest

## Root cause (phone JPEG overlay 13:20–13:28 Istanbul)
Cloud correctly delivered `viewer_backend=webrtc_hw` (remote_audit + pending_commands).
Agent never started the HW sidecar because `_hw_want()` required `caps_from_selftest()`,
which fails under Session-0 SYSTEM even when `asteria-encode.exe` works in the console
session via CreateProcessAsUser. No offer was sent; overlay stayed JPEG.

Secondary bug: agent minted its own `stream_id`, so even a successful offer would be
rejected by the v2 viewer (`stream_id` mismatch).

## Fixes
- `_hw_want()`: binary + viewer_backend is enough; selftest is advisory; always log decision
- Honor cloud `stream_id` and `ice_servers` on `remote_stream_start`
- Cloud: inject `ice_servers` into start params (TURN for phone 4G)
- v2 Teknik ayrıntı: log offer/answer/ICE/first-frame/fallback reasons
