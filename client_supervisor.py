# -*- coding: utf-8 -*-
"""Supervised long-running worker threads: log + restart with jittered backoff.

A target that returns normally is considered finished (no restart). A target that
raises is logged at WARNING and restarted after 1s..60s backoff.
"""
from __future__ import annotations

import random
import threading
import time
import traceback
from typing import Callable, Dict, Optional

_STATS: Dict[str, dict] = {}
_LOCK = threading.Lock()


def _warn(msg: str) -> None:
    try:
        import client_helpers as ch
        if getattr(ch, "LOGGER", None):
            ch.LOGGER.warning(msg)
            return
        ch.log(msg)
    except Exception:
        print(msg)


def stats() -> Dict[str, dict]:
    with _LOCK:
        return {k: dict(v) for k, v in _STATS.items()}


def start_supervised(target: Callable, *, name: str, args: tuple = (), kwargs: Optional[dict] = None,
                     min_backoff: float = 1.0, max_backoff: float = 60.0,
                     should_run: Callable[[], bool] = lambda: True,
                     sleep: Callable[[float], None] = time.sleep) -> threading.Thread:
    kwargs = kwargs or {}

    def runner():
        backoff = min_backoff
        while should_run():
            started = time.time()
            try:
                target(*args, **kwargs)
                return
            except Exception as e:
                with _LOCK:
                    st = _STATS.setdefault(name, {"restarts": 0})
                    st["restarts"] += 1
                    st["last_error"] = f"{type(e).__name__}: {e}"[:300]
                    st["last_error_at"] = time.time()
                _warn(f"[SUPERVISOR] {name} crashed: {type(e).__name__}: {e}; restarting in ~{backoff:.0f}s\n"
                      + traceback.format_exc(limit=5))
                if time.time() - started > 300:
                    backoff = min_backoff  # ran fine for a while: reset
                sleep(backoff * random.uniform(0.5, 1.0))
                backoff = min(max_backoff, backoff * 2)

    t = threading.Thread(target=runner, name=name, daemon=True)
    t.start()
    return t
