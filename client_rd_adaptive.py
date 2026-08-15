#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Conservative local adaptive controller for remote desktop JPEG streaming."""

from __future__ import annotations

import time
from typing import Callable, Optional


class AdaptiveStreamController:
    """Hysteretic controller bounded by caller-requested ceilings.

    Pressure degrades fps/quality at most once per cooldown. Recovery requires
    a quiet stable window. **Encode width stays locked** for the session —
    oscillating resolution makes the dashboard hard to use.
    """

    MIN_FPS = 12.0
    MIN_QUALITY = 20
    MIN_WIDTH = 800

    def __init__(
        self,
        fps: float,
        quality: int,
        max_width: int,
        *,
        clock: Callable[[], float] = time.monotonic,
        degrade_cooldown: float = 5.0,
        stable_window: float = 20.0,
    ):
        self._clock = clock
        self.degrade_cooldown = float(degrade_cooldown)
        self.stable_window = float(stable_window)
        self.requested = {}
        self.effective = {}
        self.metrics = {
            "capture_ms_ewma": 0.0,
            "send_ms_ewma": 0.0,
            "http_ms_ewma": 0.0,
            "capture_samples": 0,
            "send_samples": 0,
            "http_failures": 0,
            "ws_failures": 0,
            "coalesced_frames": 0,
            "degrades": 0,
            "recovers": 0,
            "last_change_mono_ms": 0,
        }
        now = self._clock()
        self._last_change = now - self.degrade_cooldown
        self._stable_since = now
        self._pressure = 0
        self.reset(fps, quality, max_width, now=now)

    @staticmethod
    def _clamp_requested(fps, quality, max_width) -> dict:
        return {
            "fps": max(12.0, min(float(fps), 60.0)),
            "quality": max(20, min(int(quality), 85)),
            "max_width": max(
                AdaptiveStreamController.MIN_WIDTH,
                min(int(max_width), 1920),
            ),
        }

    def reset(self, fps, quality, max_width, *, now: Optional[float] = None) -> None:
        now = self._clock() if now is None else float(now)
        self.requested = self._clamp_requested(fps, quality, max_width)
        self.effective = dict(self.requested)
        self._last_change = now - self.degrade_cooldown
        self._stable_since = now
        self._pressure = 0

    def update_requested(self, fps, quality, max_width) -> None:
        self.requested = self._clamp_requested(fps, quality, max_width)
        # Keep resolution at the new ceiling when dashboard raises it; never
        # silently shrink below the session floor via adaptive alone.
        self.effective["max_width"] = self.requested["max_width"]
        self.effective["fps"] = min(self.effective["fps"], self.requested["fps"])
        self.effective["quality"] = min(
            self.effective["quality"], self.requested["quality"]
        )

    @staticmethod
    def _ewma(old: float, value: float, alpha: float = 0.2) -> float:
        return value if old <= 0 else ((1.0 - alpha) * old + alpha * value)

    def observe_capture(self, seconds: float) -> None:
        ms = max(0.0, float(seconds) * 1000.0)
        self.metrics["capture_ms_ewma"] = self._ewma(
            self.metrics["capture_ms_ewma"], ms
        )
        self.metrics["capture_samples"] += 1
        budget_ms = 1000.0 / max(self.effective["fps"], 1.0)
        if ms > budget_ms * 0.8:
            self._mark_pressure(1)

    def observe_send(self, seconds: float, *, transport: str, ok: bool = True) -> None:
        ms = max(0.0, float(seconds) * 1000.0)
        self.metrics["send_ms_ewma"] = self._ewma(self.metrics["send_ms_ewma"], ms)
        self.metrics["send_samples"] += 1
        if transport == "http":
            self.metrics["http_ms_ewma"] = self._ewma(
                self.metrics["http_ms_ewma"], ms
            )
            if not ok:
                self.metrics["http_failures"] += 1
                self._mark_pressure(2)
            elif ms > 800:
                self._mark_pressure(1)
        elif not ok:
            self.note_ws_failure()
        budget_ms = 1000.0 / max(self.effective["fps"], 1.0)
        if ms > budget_ms:
            self._mark_pressure(1)

    def note_coalesced(self, count: int = 1) -> None:
        count = max(0, int(count))
        self.metrics["coalesced_frames"] += count
        if count:
            self._mark_pressure(1)

    def note_ws_failure(self) -> None:
        self.metrics["ws_failures"] += 1
        self._mark_pressure(2)

    def _mark_pressure(self, weight: int) -> None:
        self._pressure += max(1, int(weight))
        self._stable_since = self._clock()

    def evaluate(self, *, now: Optional[float] = None) -> Optional[dict]:
        now = self._clock() if now is None else float(now)
        if self._pressure > 0:
            if now - self._last_change < self.degrade_cooldown:
                return None
            changed = self._degrade()
            self._pressure = 0
            self._last_change = now
            self._stable_since = now
            if changed:
                self.metrics["degrades"] += 1
                self.metrics["last_change_mono_ms"] = int(now * 1000)
                return dict(self.effective)
            return None

        if (
            now - self._stable_since >= self.stable_window
            and now - self._last_change >= self.stable_window
            and self.effective != self.requested
        ):
            changed = self._recover()
            self._last_change = now
            self._stable_since = now
            if changed:
                self.metrics["recovers"] += 1
                self.metrics["last_change_mono_ms"] = int(now * 1000)
                return dict(self.effective)
        return None

    def _degrade(self) -> bool:
        old = dict(self.effective)
        self.effective["fps"] = max(
            self.MIN_FPS, round(self.effective["fps"] * 0.8, 1)
        )
        self.effective["quality"] = max(
            self.MIN_QUALITY, self.effective["quality"] - 5
        )
        # Intentionally do not touch max_width — stable frame size for dashboard.
        return self.effective != old

    def _recover(self) -> bool:
        old = dict(self.effective)
        self.effective["fps"] = min(
            self.requested["fps"], round(self.effective["fps"] + 0.5, 1)
        )
        self.effective["quality"] = min(
            self.requested["quality"], self.effective["quality"] + 2
        )
        # Resolution remains locked to requested max_width for the session.
        self.effective["max_width"] = self.requested["max_width"]
        return self.effective != old

    def snapshot(self) -> dict:
        return {
            "requested": dict(self.requested),
            "effective": dict(self.effective),
            "metrics": dict(self.metrics),
        }
