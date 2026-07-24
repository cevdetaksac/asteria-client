#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Asteria Client — Performance Optimizer & False Positive Tuning (v4.0 Faz 4)

1. PerformanceOptimizer   — adaptive throttling, resource-aware scheduling, metric collection
2. FalsePositiveTuner     — whitelist learning, cooldown management, score decay tuning
3. MemoryGuard            — periodic GC, self-memory monitoring, leak prevention

Together they ensure the v4.0 threat detection pipeline runs efficiently on
production servers without impacting legitimate workloads.

Exports:
  PerformanceOptimizer  — singleton, adjusts module intervals based on system load
  FalsePositiveTuner    — learns from user feedback, applies whitelist/cooldown rules
  MemoryGuard           — prevents memory bloat for long-running instances
"""

import gc
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

from client_helpers import log

# ═══════════════════════════════════════════════════════════════════
#  PERFORMANCE OPTIMIZER
# ═══════════════════════════════════════════════════════════════════

# Adaptive thresholds
CPU_HIGH_THRESHOLD = 85          # % — start throttling
CPU_CRITICAL_THRESHOLD = 95      # % — aggressive throttling
MEMORY_HIGH_THRESHOLD = 85       # %
ADAPTIVE_CHECK_INTERVAL = 30     # seconds — how often to re-evaluate
THROTTLE_FACTOR_NORMAL = 1.0
THROTTLE_FACTOR_HIGH = 2.0       # double all intervals
THROTTLE_FACTOR_CRITICAL = 4.0   # quadruple all intervals

# Event processing budget
MAX_EVENTS_PER_SECOND = 50       # throttle EventLog processing
EVENT_BATCH_SIZE = 20            # process in batches
EVENT_QUEUE_MAX = 5000           # drop oldest if queue full


@dataclass
class PerformanceSnapshot:
    """Point-in-time performance reading."""
    timestamp: float = 0.0
    cpu_percent: float = 0.0
    memory_percent: float = 0.0
    thread_count: int = 0
    event_queue_size: int = 0
    throttle_factor: float = 1.0
    events_per_second: float = 0.0
    dropped_events: int = 0


class PerformanceOptimizer:
    """
    Monitors system resource usage and adjusts threat detection pipeline
    intervals dynamically to prevent impacting server performance.
    
    Features:
      - Adaptive throttling based on CPU/RAM
      - Event rate limiting with queue management
      - Performance metrics collection for dashboard
      - Module interval adjustment recommendations
    """

    def __init__(self):
        self._running = False
        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None

        # State
        self._throttle_factor: float = THROTTLE_FACTOR_NORMAL
        self._snapshots: deque = deque(maxlen=360)  # ~3 hours @ 30s intervals
        self._event_counter = 0
        self._event_counter_ts = time.time()
        self._dropped_events = 0
        self._events_per_second: float = 0.0

        # Callbacks — modules register their interval adjusters
        self._interval_adjusters: Dict[str, Callable] = {}

        # Event rate limiter
        self._event_times: deque = deque(maxlen=200)

    def start(self):
        """Begin adaptive monitoring loop."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._monitor_loop,
            name="PerfOptimizer",
            daemon=True,
        )
        self._thread.start()
        log("⚙️ PerformanceOptimizer started (adaptive throttling)")

    def stop(self):
        self._running = False

    def register_adjuster(self, name: str, callback: Callable):
        """Register a module's interval adjuster callback.
        
        callback(factor: float) — called when throttle factor changes.
        Module should multiply its base interval by factor.
        """
        with self._lock:
            self._interval_adjusters[name] = callback

    def should_process_event(self) -> bool:
        """Rate limiter — returns True if event should be processed, False to drop."""
        now = time.time()
        self._event_times.append(now)

        # Calculate current rate
        cutoff = now - 1.0
        recent = sum(1 for t in self._event_times if t >= cutoff)

        effective_limit = MAX_EVENTS_PER_SECOND / self._throttle_factor
        if recent > effective_limit:
            self._dropped_events += 1
            return False
        return True

    def record_event_processed(self):
        """Track event processing for rate calculation."""
        self._event_counter += 1

    @property
    def throttle_factor(self) -> float:
        return self._throttle_factor

    def get_stats(self) -> dict:
        """Current performance stats for dashboard."""
        with self._lock:
            return {
                "throttle_factor": self._throttle_factor,
                "events_per_second": round(self._events_per_second, 1),
                "dropped_events": self._dropped_events,
                "cpu_percent": self._snapshots[-1].cpu_percent if self._snapshots else 0,
                "memory_percent": self._snapshots[-1].memory_percent if self._snapshots else 0,
                "thread_count": threading.active_count(),
                "snapshots_count": len(self._snapshots),
                "throttle_mode": self._get_mode_label(),
            }

    def get_trend_data(self, points: int = 30) -> List[dict]:
        """Return recent snapshots for trend mini-chart."""
        with self._lock:
            recent = list(self._snapshots)[-points:]
        return [
            {
                "ts": s.timestamp,
                "cpu": s.cpu_percent,
                "mem": s.memory_percent,
                "eps": s.events_per_second,
                "tf": s.throttle_factor,
            }
            for s in recent
        ]

    # ─── Internal ──────────────────────────────────────────────

    def _monitor_loop(self):
        """Periodic resource check and throttle adjustment."""
        while self._running:
            try:
                snap = self._take_snapshot()
                with self._lock:
                    self._snapshots.append(snap)

                new_factor = self._calculate_throttle(snap)
                if new_factor != self._throttle_factor:
                    old = self._throttle_factor
                    self._throttle_factor = new_factor
                    self._notify_adjusters(new_factor)
                    log(f"⚙️ Throttle adjusted: {old:.1f}x → {new_factor:.1f}x "
                        f"(CPU={snap.cpu_percent:.0f}%, RAM={snap.memory_percent:.0f}%)")

            except Exception as e:
                log(f"[PerfOptimizer] monitor error: {e}")
            time.sleep(ADAPTIVE_CHECK_INTERVAL)

    def _take_snapshot(self) -> PerformanceSnapshot:
        now = time.time()
        cpu = 0.0
        mem = 0.0
        if PSUTIL_AVAILABLE:
            cpu = psutil.cpu_percent(interval=None)
            mem = psutil.virtual_memory().percent

        # Calculate events/sec
        elapsed = now - self._event_counter_ts
        if elapsed > 0:
            self._events_per_second = self._event_counter / elapsed
        self._event_counter = 0
        self._event_counter_ts = now

        return PerformanceSnapshot(
            timestamp=now,
            cpu_percent=cpu,
            memory_percent=mem,
            thread_count=threading.active_count(),
            throttle_factor=self._throttle_factor,
            events_per_second=self._events_per_second,
            dropped_events=self._dropped_events,
        )

    def _calculate_throttle(self, snap: PerformanceSnapshot) -> float:
        """Determine throttle factor based on resource usage."""
        if snap.cpu_percent >= CPU_CRITICAL_THRESHOLD or snap.memory_percent >= 95:
            return THROTTLE_FACTOR_CRITICAL
        if snap.cpu_percent >= CPU_HIGH_THRESHOLD or snap.memory_percent >= MEMORY_HIGH_THRESHOLD:
            return THROTTLE_FACTOR_HIGH
        return THROTTLE_FACTOR_NORMAL

    def _notify_adjusters(self, factor: float):
        with self._lock:
            adjusters = dict(self._interval_adjusters)
        for name, cb in adjusters.items():
            try:
                cb(factor)
            except Exception as e:
                log(f"[PerfOptimizer] adjuster '{name}' error: {e}")

    def _get_mode_label(self) -> str:
        if self._throttle_factor >= THROTTLE_FACTOR_CRITICAL:
            return "CRITICAL"
        if self._throttle_factor >= THROTTLE_FACTOR_HIGH:
            return "THROTTLED"
        return "NORMAL"


# ═══════════════════════════════════════════════════════════════════
#  FALSE POSITIVE TUNER
# ═══════════════════════════════════════════════════════════════════

# Default cooldowns (seconds) — prevent repeated alerts for same source
DEFAULT_COOLDOWNS: Dict[str, int] = {
    "failed_logon_single": 60,       # 1 single fail per minute per IP
    "failed_logon_burst": 300,       # burst alert every 5 min
    "successful_logon_rdp": 120,     # RDP login alert every 2 min
    "successful_logon_network": 120,
    "rdp_session_reconnect": 300,    # reconnect is often normal
    "service_start_type_changed": 600,
}

# Score adjustments for frequently false-positive events
FP_SCORE_ADJUSTMENTS: Dict[str, float] = {
    "rdp_session_reconnect": 0.5,    # halve score for reconnects
    "service_start_type_changed": 0.6,
    "unexpected_restart": 0.7,
}

# Max auto-learned whitelist size
MAX_AUTO_WHITELIST = 200
# Min events to consider auto-whitelisting an IP
AUTO_WHITELIST_MIN_EVENTS = 50
# Max threat score for auto-whitelist consideration
AUTO_WHITELIST_MAX_SCORE = 10


@dataclass
class AlertCooldownEntry:
    """Tracks last alert time per (ip, event_type) pair."""
    last_alert_ts: float = 0.0
    count_suppressed: int = 0
    count_total: int = 0


class FalsePositiveTuner:
    """
    Learns from event patterns and reduces false positive alerts.
    
    Features:
      - Per-event-type cooldowns (prevent alert flooding)
      - Score multiplier adjustments for FP-prone events
      - Auto-whitelist learning for trusted IPs
      - User-configurable whitelist overlays
      - Statistics for dashboard display
    """

    def __init__(self,
                 threat_engine=None,
                 event_watcher=None,
                 user_whitelist_ips: Optional[Set[str]] = None):
        self._lock = threading.Lock()
        self._threat_engine = threat_engine
        self._event_watcher = event_watcher

        # Cooldown tracking: key = (ip, event_type)
        self._cooldowns: Dict[tuple, AlertCooldownEntry] = {}
        self._cooldown_config = dict(DEFAULT_COOLDOWNS)

        # Score multipliers
        self._score_adjustments = dict(FP_SCORE_ADJUSTMENTS)

        # Whitelists
        self._user_whitelist: Set[str] = user_whitelist_ips or set()
        self._auto_whitelist: Set[str] = set()

        # IP reputation tracking for auto-learn
        self._ip_event_counts: Dict[str, int] = defaultdict(int)
        self._ip_max_scores: Dict[str, float] = defaultdict(float)

        # Stats
        self._stats = {
            "events_suppressed": 0,
            "events_adjusted": 0,
            "auto_whitelist_count": 0,
            "user_whitelist_count": len(self._user_whitelist),
        }
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def should_alert(self, ip: str, event_type: str) -> bool:
        """Check if an alert should be emitted or suppressed (cooldown check)."""
        # Always allow if no cooldown defined
        cooldown = self._cooldown_config.get(event_type)
        if cooldown is None:
            return True

        key = (ip, event_type)
        now = time.time()

        with self._lock:
            entry = self._cooldowns.get(key)
            if entry is None:
                self._cooldowns[key] = AlertCooldownEntry(last_alert_ts=now, count_total=1)
                return True

            entry.count_total += 1
            if now - entry.last_alert_ts < cooldown:
                entry.count_suppressed += 1
                self._stats["events_suppressed"] += 1
                return False

            entry.last_alert_ts = now
            return True

    def adjust_score(self, event_type: str, base_score: float) -> float:
        """Apply FP score adjustment multiplier."""
        multiplier = self._score_adjustments.get(event_type, 1.0)
        if multiplier != 1.0:
            with self._lock:
                self._stats["events_adjusted"] += 1
        return base_score * multiplier

    def is_whitelisted(self, ip: str) -> bool:
        """Check if IP is whitelisted (user or auto-learned)."""
        return ip in self._user_whitelist or ip in self._auto_whitelist

    def record_ip_event(self, ip: str, score: float):
        """Track IP events for auto-whitelist learning."""
        with self._lock:
            self._ip_event_counts[ip] += 1
            self._ip_max_scores[ip] = max(self._ip_max_scores[ip], score)

            # Auto-whitelist: high event count + consistently low score
            if (self._ip_event_counts[ip] >= AUTO_WHITELIST_MIN_EVENTS
                    and self._ip_max_scores[ip] <= AUTO_WHITELIST_MAX_SCORE
                    and len(self._auto_whitelist) < MAX_AUTO_WHITELIST
                    and ip not in self._user_whitelist):
                self._auto_whitelist.add(ip)
                self._stats["auto_whitelist_count"] = len(self._auto_whitelist)
                log(f"🔰 Auto-whitelisted IP {ip} "
                    f"(events={self._ip_event_counts[ip]}, max_score={self._ip_max_scores[ip]})")

    def update_user_whitelist(self, ips: Set[str]):
        """Update user-configured whitelist."""
        with self._lock:
            self._user_whitelist = set(ips)
            self._stats["user_whitelist_count"] = len(self._user_whitelist)
            # Remove auto-whitelisted entries that are now user-whitelisted
            self._auto_whitelist -= self._user_whitelist

        # Push to EventLogWatcher if available
        if self._event_watcher and hasattr(self._event_watcher, 'update_whitelist'):
            self._event_watcher.update_whitelist(ips)

    def update_cooldown(self, event_type: str, seconds: int):
        """Update cooldown for a specific event type."""
        with self._lock:
            self._cooldown_config[event_type] = seconds

    def update_score_adjustment(self, event_type: str, multiplier: float):
        """Update score multiplier for a specific event type."""
        with self._lock:
            self._score_adjustments[event_type] = max(0.0, min(2.0, multiplier))

    def get_stats(self) -> dict:
        """Stats for dashboard display."""
        with self._lock:
            stats = dict(self._stats)
            stats["cooldown_rules"] = len(self._cooldown_config)
            stats["score_adjustments"] = len(self._score_adjustments)
            stats["tracked_ips"] = len(self._ip_event_counts)
            stats["auto_whitelist"] = sorted(self._auto_whitelist)[:20]  # sample
            return stats

    def get_cooldown_config(self) -> Dict[str, int]:
        """Return current cooldown config for settings display."""
        with self._lock:
            return dict(self._cooldown_config)

    def cleanup_stale(self, max_age: int = 3600):
        """Remove stale cooldown entries older than max_age seconds."""
        cutoff = time.time() - max_age
        with self._lock:
            stale = [k for k, v in self._cooldowns.items() if v.last_alert_ts < cutoff]
            for k in stale:
                del self._cooldowns[k]
            # Also cleanup IP tracking for IPs not seen recently
            stale_ips = [
                ip for ip, count in self._ip_event_counts.items()
                if self._ip_max_scores.get(ip, 0) > FP_SCORE_ADJUSTMENTS.get("rdp_session_reconnect", 0.5)
                and count < AUTO_WHITELIST_MIN_EVENTS
            ]
            for ip in stale_ips:
                self._ip_event_counts.pop(ip, None)
                self._ip_max_scores.pop(ip, None)
            # Limit tracked IPs to 5000
            if len(self._ip_event_counts) > 5000:
                # Keep only the most active IPs
                sorted_ips = sorted(
                    self._ip_event_counts.items(),
                    key=lambda x: x[1],
                    reverse=True
                )
                keep = {ip for ip, _ in sorted_ips[:3000]}
                remove = set(self._ip_event_counts.keys()) - keep - self._auto_whitelist
                for ip in remove:
                    del self._ip_event_counts[ip]
                    self._ip_max_scores.pop(ip, None)
                log(f"🔰 FP tuner: pruned {len(remove)} tracked IPs (was >5000)")
            elif stale_ips:
                log(f"🔰 FP tuner: removed {len(stale_ips)} stale tracked IPs")

    def start(self, interval: int = 3600):
        """Periodic stale-entry cleanup loop."""
        if getattr(self, "_running", False):
            return
        self._running = True
        self._cleanup_interval = max(300, int(interval))

        def _loop():
            while getattr(self, "_running", False):
                try:
                    self.cleanup_stale(self._cleanup_interval)
                except Exception as e:
                    log(f"[FP-TUNER] cleanup error: {e}")
                for _ in range(self._cleanup_interval):
                    if not getattr(self, "_running", False):
                        break
                    time.sleep(1)

        self._thread = threading.Thread(target=_loop, name="FPTunerCleanup", daemon=True)
        self._thread.start()
        log(f"🔰 FalsePositiveTuner cleanup started (every {self._cleanup_interval}s)")

    def stop(self):
        self._running = False


# ═══════════════════════════════════════════════════════════════════
#  MEMORY GUARD — Long-running instance memory management
# ═══════════════════════════════════════════════════════════════════

# Memory thresholds
MEMORY_WARNING_MB = 500         # Log warning above 500 MB
MEMORY_HIGH_MB = 1024           # Aggressive GC above 1 GB
MEMORY_CRITICAL_MB = 2048       # Force cleanup above 2 GB
MEMORY_CHECK_INTERVAL = 300     # Check every 5 minutes


class MemoryGuard:
    """
    Prevents memory bloat for long-running honeypot client instances.

    Features:
      - Periodic garbage collection
      - Self-memory monitoring with logging
      - Triggers cleanup callbacks when memory exceeds thresholds
      - Reports memory stats for dashboard

    Usage:
        guard = MemoryGuard()
        guard.register_cleanup("threat_engine", threat_engine_cleanup_func)
        guard.start()
    """

    def __init__(self):
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._cleanup_callbacks: Dict[str, Callable] = {}
        self._stats = {
            "gc_runs": 0,
            "forced_cleanups": 0,
            "peak_memory_mb": 0,
            "current_memory_mb": 0,
            "last_gc_collected": 0,
        }

    def start(self):
        """Start memory monitoring loop."""
        if self._running:
            return
        self._running = True
        # Enable automatic GC but with reduced frequency
        gc.enable()
        gc.set_threshold(700, 10, 5)  # Less aggressive for performance
        self._thread = threading.Thread(
            target=self._monitor_loop,
            name="MemoryGuard",
            daemon=True,
        )
        self._thread.start()
        log("🧠 MemoryGuard started (long-running instance protection)")

    def stop(self):
        self._running = False

    def register_cleanup(self, name: str, callback: Callable):
        """Register a cleanup callback that will be called when memory is high.

        callback() should release caches, trim data structures, etc.
        """
        self._cleanup_callbacks[name] = callback

    def get_stats(self) -> dict:
        return dict(self._stats)

    def get_memory_mb(self) -> float:
        """Get current process memory usage in MB."""
        try:
            if PSUTIL_AVAILABLE:
                import psutil
                return psutil.Process().memory_info().rss / 1024 / 1024
        except Exception:
            pass
        return 0.0

    def _monitor_loop(self):
        """Periodic memory check and GC."""
        while self._running:
            try:
                mem_mb = self.get_memory_mb()
                self._stats["current_memory_mb"] = round(mem_mb, 1)
                self._stats["peak_memory_mb"] = max(
                    self._stats["peak_memory_mb"], round(mem_mb, 1)
                )

                if mem_mb >= MEMORY_CRITICAL_MB:
                    log(f"🧠 [MEMORY] ⚠️ CRITICAL: {mem_mb:.0f} MB — "
                        f"forcing aggressive cleanup + GC")
                    self._force_cleanup()
                    collected = gc.collect(2)  # Full collection
                    self._stats["gc_runs"] += 1
                    self._stats["last_gc_collected"] = collected
                    self._stats["forced_cleanups"] += 1

                    new_mem = self.get_memory_mb()
                    log(f"🧠 [MEMORY] After cleanup: {new_mem:.0f} MB "
                        f"(freed ~{mem_mb - new_mem:.0f} MB, "
                        f"GC collected {collected} objects)")

                elif mem_mb >= MEMORY_HIGH_MB:
                    log(f"🧠 [MEMORY] HIGH: {mem_mb:.0f} MB — running GC")
                    collected = gc.collect(1)
                    self._stats["gc_runs"] += 1
                    self._stats["last_gc_collected"] = collected
                    self._force_cleanup()

                elif mem_mb >= MEMORY_WARNING_MB:
                    log(f"🧠 [MEMORY] Warning: {mem_mb:.0f} MB — "
                        f"monitoring (threshold: {MEMORY_HIGH_MB} MB)")
                    # Gentle GC
                    collected = gc.collect(0)
                    self._stats["gc_runs"] += 1
                    self._stats["last_gc_collected"] = collected

                else:
                    # Normal operation — periodic gentle GC
                    collected = gc.collect(0)
                    if collected > 0:
                        self._stats["gc_runs"] += 1
                        self._stats["last_gc_collected"] = collected

            except Exception as e:
                log(f"🧠 [MEMORY] Monitor error: {e}")

            time.sleep(MEMORY_CHECK_INTERVAL)

    def _force_cleanup(self):
        """Call all registered cleanup callbacks."""
        for name, cb in self._cleanup_callbacks.items():
            try:
                cb()
                log(f"🧠 [MEMORY] Cleanup '{name}' completed")
            except Exception as e:
                log(f"🧠 [MEMORY] Cleanup '{name}' error: {e}")
