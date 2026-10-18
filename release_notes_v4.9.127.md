# v4.9.127

## Summary
Phase 3 Remote Desktop quick wins (contract **1.4.93**):
- Dirty-tile JPEG (`ASTT`) + periodic keyframe; viewer canvas/`createImageBitmap` (img fallback)
- Cloud newest-frame-only backpressure; mouse coalesce per rAF
- Trickle ICE; Fit/1:1 scale; stats fps/kbps/RTT; Win/CAD/Alt+Tab; host cursor overlay
- **Build smoke gate** so lazy-import crash-loops (4.9.125) cannot ship again

## Installer
WebRTC profile. Unsigned like prior fleet releases.
