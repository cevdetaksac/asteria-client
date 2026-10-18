# 4.9.136 — HW negotiate timeout → JPEG

If HW sidecar starts but viewer never answers within 8s, stop sidecar and
emit jpeg fallback meta so JPEG-WS continues. Pairs with v2 first-frame watchdog.
