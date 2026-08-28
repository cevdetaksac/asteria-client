## Remote Desktop — Capture health honesty / no Live flicker (contract 1.4.87)

- Clear stale `helper_fail=no_frame` when healthy `printwindow-logonui` / DXGI frames are on the wire
- Healthy method tags win over leftover black/flat streaks
- JPEG-WS primary + healthy pixels: do not advertise `WEBRTC_PEER_ERROR` as Capture FAIL root
- Emit `t:capture_diag phase=live` on recovery so dashboard replaces FAIL · no_frame banner

Lab: Ninety-Web LogonUI — Live badge must stay Canlı without Canlı↔Bekleniyor flicker.

**SHA256:** `f8e65f2ba6f347ee6664d18805cec7e2f770a1ac2c0f0d91f023485ad5ef87c6`
