#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Asteria Client — System Health Monitor (v4.0 Faz 3)

psutil ile sistem metriklerini toplar, hareketli ortalama (z-score)
bazlı anomali tespiti yapar ve sonuçları ThreatEngine'e besler.

İzlenen metrikler:
  - CPU kullanımı (% — eşik: 90)
  - RAM kullanımı (% — eşik: 90)
  - Disk kullanımı (% — eşik: 95)
  - Disk I/O (bytes/s — 3x baseline = anomali)
  - Network I/O (bytes/s — 5x baseline = anomali)
  - Süreç sayısı (2x baseline = anomali)
  - Açık bağlantı sayısı (3x baseline = anomali)

Anomali tespiti:
  - Son 60 ölçümün ortalaması ve std sapması tutulur
  - Z-score > 3.0 → anomali olarak işaretlenir
  - Birden fazla anomali korelasyonu (CPU + Disk I/O → kripto madenci)

API raporlama:
  - POST /api/health/report — periyodik snapshot (her 5 dk)
  - Anomali tespit edilirse ThreatEngine'e skor gönderilir

Exports:
  SystemHealthMonitor — ana sınıf (start / stop / get_stats / get_snapshot)
"""

import statistics
import threading
import time
from collections import deque
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional, Tuple

from client_helpers import log

# ── Constants ─────────────────────────────────────────────────────

COLLECT_INTERVAL = 10       # Collect metrics every 10 seconds
REPORT_INTERVAL = 60        # Health report to API every 60s (sessions/processes for dashboard)
ANOMALY_Z_THRESHOLD = 3.0   # Z-score threshold for anomaly
MIN_SAMPLES = 15            # Minimum samples before anomaly detection
MAX_TOP_PROCESSES = 150     # Cap process list for health report (dashboard full table)
MIN_TOP_PROCESSES = 80      # Prefer at least this many unique PIDs per report

# User-facing apps that must appear even at ~0% CPU
_INTERACTIVE_NAME_HINTS = (
    "notepad", "chrome", "msedge", "firefox", "explorer", "code.exe", "devenv",
    "winword", "excel", "outlook", "teams", "slack", "discord", "spotify",
    "powershell", "pwsh", "cmd.exe", "windowsterminal", "taskmgr", "notepad++",
)

# Suspicious process heuristics
_SUSPICIOUS_NAMES = (
    "mimikatz", "procdump", "psexec", "psexesvc", "nc.exe", "ncat",
    "cobalt", "beacon", "ransom", "lazagne", "sharpdump", "nanodump",
)
_SUSPICIOUS_PATH_MARKERS = (
    "\\temp\\", "\\appdata\\local\\temp\\", "\\downloads\\", "\\public\\",
)
_LOLBIN_HINTS = (
    ("powershell", ("-enc", "-encodedcommand", "-e ", "downloadstring", "iex ")),
    ("pwsh", ("-enc", "-encodedcommand", "downloadstring")),
    ("wscript", (".vbs", ".js", "http")),
    ("cscript", (".vbs", ".js")),
    ("mshta", ("http", ".hta", "javascript:")),
    ("rundll32", ("http", "javascript:", ".dll,")),
    ("certutil", ("-urlcache", "-decode", "-f ")),
)

# Known-benign heavy disk writers — NEVER label as ransomware from I/O alone
_BENIGN_DISK_IO_NAMES = (
    "cursor.exe", "code.exe", "devenv.exe", "chrome.exe", "msedge.exe",
    "firefox.exe", "brave.exe", "opera.exe", "onedrive.exe", "dropbox.exe",
    "googledrivesync.exe", "searchindexer.exe", "searchprotocolhost.exe",
    "msmpeng.exe", "mssense.exe", "defender", "tiworker.exe", "trustedinstaller.exe",
    "wuauclt.exe", "svchost.exe", "steam.exe", "epicgameslauncher.exe",
    "outlook.exe", "teams.exe", "slack.exe", "discord.exe", "spotify.exe",
    "photoshop.exe", "premiere", "afterfx.exe", "node.exe", "python.exe",
)
_BENIGN_DISK_IO_PATHS = (
    "\\programs\\cursor\\",
    "\\microsoft vs code\\",
    "\\jetbrains\\",
    "\\google\\chrome\\",
    "\\microsoft\\edge\\",
    "\\windows defender\\",
    "\\windows\\system32\\",
)

# Metric: (threshold_type, threshold_value, description, base_score, category)
# category: capacity | performance | security | ransomware_suspect
# Disk full is CAPACITY only — never "ransomware".
METRIC_CONFIG = {
    "cpu_percent":          ("fixed", 90, "CPU spike — yuksek sistem yuku", 35, "performance"),
    "memory_percent":       ("fixed", 90, "Memory spike — bellek baskisi", 30, "performance"),
    "disk_usage_percent":   ("fixed", 98, "Disk kapasitesi kritik — yer acin", 10, "capacity"),
    "disk_io_read_rate":    ("multiplier", 4.0, "Disk okuma artisi", 20, "performance"),
    "disk_io_write_rate":   ("multiplier", 4.0, "Disk yazma artisi", 20, "performance"),
    "net_bytes_sent_rate":  ("multiplier", 5.0, "Network outbound spike — data exfiltration riski", 55, "security"),
    "net_bytes_recv_rate":  ("multiplier", 5.0, "Network inbound spike", 40, "performance"),
    "process_count":        ("multiplier", 2.5, "Process count spike", 35, "security"),
    "connection_count":     ("multiplier", 3.5, "Connection count spike — C2 riski", 45, "security"),
}

# How many consecutive I/O anomalies (non-benign) before ransomware_suspect
_IO_RANSOM_STREAK_NEED = 4  # ~40s at 10s collect interval
_CAPACITY_LOG_COOLDOWN_SEC = 600  # don't spam disk-full every 10s


# ── Anomaly Detector ─────────────────────────────────────────────

class AnomalyDetector:
    """
    Hareketli ortalama bazlı anomali dedektörü.
    Z-score > threshold → anomali.
    """

    def __init__(self, window_size: int = 60):
        self.values: deque = deque(maxlen=window_size)

    def add(self, value: float) -> Tuple[bool, float]:
        """
        Yeni değer ekle.
        Returns: (is_anomaly, z_score)
        """
        self.values.append(value)
        if len(self.values) < MIN_SAMPLES:
            return False, 0.0

        mean = statistics.mean(self.values)
        stdev = statistics.stdev(self.values)
        if stdev == 0:
            return False, 0.0

        z_score = (value - mean) / stdev
        return z_score > ANOMALY_Z_THRESHOLD, round(z_score, 2)

    @property
    def mean(self) -> float:
        return statistics.mean(self.values) if len(self.values) >= 2 else 0.0


# ── System Health Monitor ────────────────────────────────────────

class SystemHealthMonitor:
    """
    Sistem sağlık metriklerini toplar ve anomali tespiti yapar.

    Usage:
        monitor = SystemHealthMonitor(
            on_alert=threat_engine.process_event,
            api_client=api_client,
            token_getter=lambda: state.get("token", ""),
        )
        monitor.start()
    """

    def __init__(
        self,
        on_alert: Optional[Callable] = None,
        api_client=None,
        token_getter: Optional[Callable[[], str]] = None,
        threat_engine=None,
        ransomware_shield=None,
    ):
        self.on_alert = on_alert
        self.api_client = api_client
        self.token_getter = token_getter or (lambda: "")
        self.threat_engine = threat_engine
        self._ransomware_shield = ransomware_shield
        # Optional wired-after references for additive observe health (1.4.2+)
        self.remote_commands = None
        self.event_watcher = None
        self.etw_shadow = None
        self.service_manager = None
        self.network_guard = None

        self._running = False

        # Anomaly detectors for each metric
        self._detectors: Dict[str, AnomalyDetector] = {
            name: AnomalyDetector() for name in METRIC_CONFIG
        }

        # Previous I/O counters for rate calculation
        self._prev_disk_io = None
        self._prev_net_io = None
        self._prev_time: float = 0.0

        # Latest snapshot
        self._latest: Dict[str, float] = {}
        self._anomalies: List[str] = []
        self._io_ransom_streak: Dict[str, int] = {}
        self._last_capacity_log_at: float = 0.0
        self._last_benign_io_log_at: float = 0.0

        # Stats
        self._stats = {
            "samples_collected": 0,
            "anomalies_detected": 0,
            "reports_sent": 0,
            "top_cpu_processes": [],
            "top_processes": [],
            "active_sessions": [],
            "suppressed_benign_io": 0,
            "capacity_warnings": 0,
        }
        self._mem_total_bytes = 0
        self._rdp_ports = {3389}
        try:
            from client_constants import RDP_SECURE_PORT
            if RDP_SECURE_PORT:
                self._rdp_ports.add(int(RDP_SECURE_PORT))
        except Exception:
            pass

    # ── Lifecycle ─────────────────────────────────────────────────

    def start(self):
        if self._running:
            return
        self._running = True

        threading.Thread(
            target=self._collect_loop,
            name="HealthMonitor-Collect",
            daemon=True,
        ).start()

        threading.Thread(
            target=self._report_loop,
            name="HealthMonitor-Report",
            daemon=True,
        ).start()

        log("[HEALTH] 💊 System health monitor started")

    def stop(self):
        self._running = False
        log("[HEALTH] ✅ Stopped")

    # ── Data Collection ───────────────────────────────────────────

    def _collect_loop(self):
        """Collect system metrics every COLLECT_INTERVAL seconds."""
        while self._running:
            try:
                self._collect_metrics()
            except Exception as e:
                log(f"[HEALTH] Collection error: {e}")
            time.sleep(COLLECT_INTERVAL)

    def _collect_metrics(self):
        """Gather all system metrics and run anomaly detection."""
        try:
            import psutil
        except ImportError:
            return

        now = time.time()
        metrics: Dict[str, float] = {}

        # ── Static metrics ──
        metrics["cpu_percent"] = psutil.cpu_percent(interval=0)
        mem = psutil.virtual_memory()
        metrics["memory_percent"] = mem.percent

        try:
            disk = psutil.disk_usage("C:\\")
            metrics["disk_usage_percent"] = disk.percent
        except Exception:
            metrics["disk_usage_percent"] = 0

        metrics["process_count"] = len(list(psutil.process_iter()))

        try:
            metrics["connection_count"] = len(psutil.net_connections())
        except (psutil.AccessDenied, OSError):
            metrics["connection_count"] = 0

        # ── Rate-based metrics (I/O) ──
        try:
            disk_io = psutil.disk_io_counters()
            net_io = psutil.net_io_counters()

            if self._prev_disk_io and self._prev_time > 0:
                dt = now - self._prev_time
                if dt > 0:
                    metrics["disk_io_read_rate"] = (
                        disk_io.read_bytes - self._prev_disk_io.read_bytes
                    ) / dt
                    metrics["disk_io_write_rate"] = (
                        disk_io.write_bytes - self._prev_disk_io.write_bytes
                    ) / dt
                    metrics["net_bytes_sent_rate"] = (
                        net_io.bytes_sent - self._prev_net_io.bytes_sent
                    ) / dt
                    metrics["net_bytes_recv_rate"] = (
                        net_io.bytes_recv - self._prev_net_io.bytes_recv
                    ) / dt

            self._prev_disk_io = disk_io
            self._prev_net_io = net_io
            self._prev_time = now
        except Exception:
            pass

        # ── Sessions first (interactive user filter for process list) ──
        try:
            self._stats["active_sessions"] = self._collect_active_sessions()
        except Exception as e:
            log(f"[HEALTH] Session collect error: {e}")

        # ── Rich processes (80–150 unique PIDs) ──
        try:
            mem_total = mem.total or 1
            self._mem_total_bytes = mem_total
            rich = self._collect_rich_processes(psutil, mem_total)
            self._stats["top_processes"] = rich
            # Alias: dashboard may read top_cpu_processes — send FULL list
            self._stats["top_cpu_processes"] = rich
            # Per-cycle INFO flooded the daily log (~every few seconds).
            n = getattr(self, "_proc_collect_logs", 0) + 1
            self._proc_collect_logs = n
            if n == 1 or n % 30 == 0:
                log(f"[HEALTH] processes collected: {len(rich)}")
        except Exception as e:
            log(f"[HEALTH] Process collect error: {e}")

        # ── Anomaly detection ──
        detected_anomalies = []
        for name, value in metrics.items():
            if name not in self._detectors:
                continue

            config = METRIC_CONFIG.get(name)
            if not config:
                continue

            threshold_type, threshold_val, description, score, category = config

            is_anomaly = False

            if threshold_type == "fixed":
                if value >= threshold_val:
                    is_anomaly = True
            elif threshold_type == "multiplier":
                anomaly_flag, z = self._detectors[name].add(value)
                if anomaly_flag:
                    is_anomaly = True
            else:
                self._detectors[name].add(value)

            if not is_anomaly:
                if name.startswith("disk_io_"):
                    self._io_ransom_streak[name] = 0
                continue

            # Capacity: disk full is NOT ransomware
            if category == "capacity" or name == "disk_usage_percent":
                self._stats["capacity_warnings"] = int(self._stats.get("capacity_warnings") or 0) + 1
                now = time.time()
                if now - self._last_capacity_log_at >= _CAPACITY_LOG_COOLDOWN_SEC:
                    self._last_capacity_log_at = now
                    free_gb = 0.0
                    try:
                        import psutil
                        free_gb = psutil.disk_usage("C:\\").free / (1024 ** 3)
                    except Exception:
                        pass
                    log(
                        f"[HEALTH] CAPACITY: disk {value:.1f}% full "
                        f"(free~{free_gb:.1f}GB) — not ransomware"
                    )
                detected_anomalies.append(
                    (name, value, description, min(int(score), 15), "capacity")
                )
                continue

            # Disk I/O: classify benign IDE/browser vs real suspect
            if name.startswith("disk_io_"):
                procs = self._get_top_disk_io_processes()
                if self._is_benign_disk_io(procs):
                    self._io_ransom_streak[name] = 0
                    self._stats["suppressed_benign_io"] = (
                        int(self._stats.get("suppressed_benign_io") or 0) + 1
                    )
                    now = time.time()
                    if now - self._last_benign_io_log_at >= _CAPACITY_LOG_COOLDOWN_SEC:
                        self._last_benign_io_log_at = now
                        top = procs[0] if procs else {}
                        log(
                            f"[HEALTH] Disk I/O high but benign "
                            f"({top.get('name', '?')}) — not ransomware"
                        )
                    # Soft performance note only (low score, no ransom wording)
                    detected_anomalies.append(
                        (
                            name,
                            value,
                            f"Disk I/O yuksek — bilinen uygulama ({(procs[0].get('name') if procs else 'n/a')})",
                            5,
                            "performance",
                        )
                    )
                    continue

                streak = int(self._io_ransom_streak.get(name, 0)) + 1
                self._io_ransom_streak[name] = streak
                if streak < _IO_RANSOM_STREAK_NEED:
                    detected_anomalies.append(
                        (name, value, description, int(score), "performance")
                    )
                else:
                    # Sustained anonymous/suspicious writer → escalate
                    detected_anomalies.append(
                        (
                            name,
                            value,
                            "Surdurulen disk yazma — ransomware adayi (canary/VSS ile dogrulayin)",
                            55,
                            "ransomware_suspect",
                        )
                    )
                continue

            detected_anomalies.append(
                (name, value, description, int(score), category)
            )

        self._latest = metrics
        self._anomalies = [a[0] for a in detected_anomalies]
        self._stats["samples_collected"] += 1

        # ── Alert on anomalies ──
        if detected_anomalies:
            self._stats["anomalies_detected"] += len(detected_anomalies)
            for name, value, desc, score, category in detected_anomalies:
                self._emit_anomaly(name, value, desc, score, category=category)

    # ── Sessions & Processes ──────────────────────────────────────

    def _collect_active_sessions(self) -> List[dict]:
        """Enumerate interactive / RDP sessions (canonical active_sessions schema)."""
        from client_winproc import run_hidden
        sessions: List[dict] = []
        now = time.time()
        remote_ips = self._guess_rdp_client_ips()

        # query user — richest text source
        try:
            _rc, _out, _ = run_hidden(["query", "user"], timeout=8)
            for line in (_out or "").splitlines()[1:]:
                parts = line.split()
                if len(parts) < 3:
                    continue
                if parts[0].startswith(">"):
                    parts[0] = parts[0][1:]
                username = parts[0]
                # Typical: USERNAME SESSIONNAME ID STATE IDLE TIME LOGON TIME
                # Disconnected may omit SESSIONNAME
                session_name = ""
                session_id = None
                status = "Unknown"
                idle_sec = None
                login_time = None

                # Find numeric session id
                id_idx = None
                for i, p in enumerate(parts[1:], 1):
                    if p.isdigit():
                        id_idx = i
                        break
                if id_idx is None:
                    continue
                if id_idx > 1:
                    session_name = parts[1]
                session_id = int(parts[id_idx])
                status_raw = parts[id_idx + 1] if len(parts) > id_idx + 1 else ""
                status = {
                    "active": "Active",
                    "disc": "Disconnected",
                    "listen": "Listen",
                }.get(status_raw.lower(), status_raw or "Unknown")

                # Idle column often "none" or ".:" or "1+00:12"
                rest = parts[id_idx + 2:]
                if rest:
                    idle_tok = rest[0]
                    idle_sec = self._parse_idle_to_sec(idle_tok)
                    logon_parts = rest[1:] if idle_tok.lower() != "none" or len(rest) > 1 else rest
                    if idle_tok.lower() in ("none", ".") or ":" in idle_tok or idle_tok.isdigit() or "+" in idle_tok:
                        logon_parts = rest[1:]
                    else:
                        logon_parts = rest
                    login_time = self._parse_logon_to_iso(" ".join(logon_parts)) if logon_parts else None

                protocol = "Console"
                sn = (session_name or "").lower()
                if sn.startswith("rdp") or "tcp#" in sn:
                    protocol = "RDP"
                elif not session_name or sn in ("console", "services"):
                    protocol = "Console" if sn != "services" else "Services"

                # Skip non-user / listener / session 0 ghosts
                if session_id == 0 or protocol == "Services" or sn == "services":
                    continue
                if status_raw.lower() in ("listen",):
                    continue
                if not username or username.upper() in ("SYSTEM",):
                    continue

                client_ip = ""
                if protocol == "RDP" and status == "Active":
                    if len(remote_ips) == 1:
                        client_ip = remote_ips[0]
                    elif remote_ips:
                        client_ip = remote_ips[0]  # best-effort

                duration_sec = None
                if login_time:
                    try:
                        lt = datetime.fromisoformat(login_time.replace("Z", "+00:00"))
                        duration_sec = max(0, int(now - lt.timestamp()))
                    except Exception:
                        pass

                sessions.append({
                    "username": username,
                    "session_id": session_id,
                    "session_name": session_name or ("Console" if protocol == "Console" else ""),
                    "status": status,
                    "client_ip": client_ip,
                    "protocol": protocol,
                    "logon_type": 10 if protocol == "RDP" else (2 if protocol == "Console" else None),
                    "login_time": login_time,
                    "duration_sec": duration_sec,
                    "idle_sec": idle_sec,
                    "client_name": "",
                    "can_capture": (
                        session_id > 0
                        and status == "Active"
                        and protocol not in ("Services",)
                    ),
                })
        except Exception as e:
            log(f"[HEALTH] query user failed: {e}")

        # Fallback: at least console from query session
        if not sessions:
            try:
                _rc2, _out2, _ = run_hidden(["query", "session"], timeout=8)
                for line in (_out2 or "").splitlines()[1:]:
                    parts = line.split()
                    if len(parts) < 3:
                        continue
                    name = parts[0].lstrip(">")
                    # SESSIONNAME USERNAME ID STATE
                    if len(parts) >= 4 and not parts[1].isdigit():
                        username, sid, state = parts[1], parts[2], parts[3]
                    elif parts[1].isdigit():
                        username, sid, state = "", parts[1], parts[2] if len(parts) > 2 else ""
                    else:
                        continue
                    if not sid.isdigit():
                        continue
                    sid_i = int(sid)
                    state_l = (state or "").lower()
                    name_l = name.lower()
                    if sid_i == 0 or name_l in ("services",) or state_l in ("listen",):
                        continue
                    # Bare console (no username) is pre-logon / lock — keep it;
                    # synthesize_console_session below also adds an explicit row.
                    proto = "RDP" if name_l.startswith("rdp") else "Console"
                    status_norm = {
                        "active": "Active",
                        "disc": "Disconnected",
                        "conn": "Conn",
                        "connected": "Connected",
                    }.get(state_l, state or "Unknown")
                    pre = not bool(str(username or "").strip()) and proto == "Console"
                    sessions.append({
                        "username": username,
                        "session_id": sid_i,
                        "session_name": name if not pre else "Winlogon",
                        "status": status_norm,
                        "client_ip": remote_ips[0] if proto == "RDP" and remote_ips else "",
                        "protocol": proto,
                        "logon_type": 10 if proto == "RDP" else 2,
                        "login_time": None,  # unknown — don't invent "now"
                        "duration_sec": None,
                        "idle_sec": None,
                        "client_name": "",
                        "can_capture": True if pre else (
                            sid_i > 0
                            and status_norm == "Active"
                            and proto not in ("Services",)
                        ),
                        "pre_logon": pre,
                        "desktop": "winlogon" if pre else "",
                        "label": "Logon / Lock screen" if pre else "",
                    })
            except Exception as e:
                log(f"[HEALTH] query session fallback failed: {e}")

        # Always offer Logon / Lock screen row for dashboard (C-WL-1), even when
        # a console user is already Active — same session_id, pre_logon=true.
        try:
            from client_rd_winlogon import synthesize_console_session
            synth = synthesize_console_session(sessions)
            if synth:
                sessions.append(synth)
        except Exception as e:
            log(f"[HEALTH] winlogon session synthesize failed: {e}")

        return sessions

    def _guess_rdp_client_ips(self) -> List[str]:
        """Best-effort remote IPs connected to RDP listen ports."""
        ips: List[str] = []
        try:
            import psutil
            for c in psutil.net_connections(kind="inet"):
                try:
                    if c.status != "ESTABLISHED":
                        continue
                    lport = c.laddr.port if c.laddr else None
                    if lport not in self._rdp_ports:
                        continue
                    rip = c.raddr.ip if c.raddr else ""
                    if rip and rip not in ("127.0.0.1", "::1") and rip not in ips:
                        ips.append(rip)
                except Exception:
                    continue
        except Exception:
            pass
        return ips

    @staticmethod
    def _parse_idle_to_sec(tok: str) -> Optional[int]:
        t = (tok or "").strip().lower()
        if not t or t in (".", "none", "hiçbir"):
            return 0
        try:
            # formats: 1:23, 1+02:15, 12
            days = 0
            if "+" in t:
                d, t = t.split("+", 1)
                days = int(d)
            if ":" in t:
                parts = [int(x) for x in t.split(":")]
                if len(parts) == 2:
                    return days * 86400 + parts[0] * 3600 + parts[1] * 60
                if len(parts) == 3:
                    return days * 86400 + parts[0] * 3600 + parts[1] * 60 + parts[2]
            return int(t) * 60
        except Exception:
            return None

    @staticmethod
    def _parse_logon_to_iso(text: str) -> Optional[str]:
        text = (text or "").strip()
        if not text:
            return None
        # Try common local formats then emit UTC ISO
        from datetime import datetime as _dt
        for fmt in (
            "%d.%m.%Y %H:%M",
            "%d/%m/%Y %H:%M",
            "%m/%d/%Y %I:%M %p",
            "%m/%d/%Y %H:%M",
            "%Y-%m-%d %H:%M",
            "%d.%m.%Y %H:%M:%S",
        ):
            try:
                local = _dt.strptime(text, fmt)
                # Assume local timezone wall clock
                ts = time.mktime(local.timetuple())
                return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            except Exception:
                continue
        return None

    def _collect_rich_processes(self, psutil, mem_total: int) -> List[dict]:
        """Build canonical top_processes list (80–150 unique PIDs).

        Merge: top CPU + top memory + interactive session apps + suspicious.
        Ensures Notepad++/browsers appear even at ~0% CPU.
        """
        now = time.time()
        interactive_users = self._interactive_usernames()

        # Prime CPU counters
        for p in psutil.process_iter(["pid"]):
            try:
                p.cpu_percent(interval=None)
            except Exception:
                pass
        time.sleep(0.15)

        collected: Dict[int, dict] = {}
        for p in psutil.process_iter([
            "pid", "name", "cpu_percent", "memory_info", "username",
            "exe", "create_time", "cmdline", "status",
        ]):
            try:
                info = p.info
                pid = info.get("pid")
                if pid is None:
                    continue
                # Keep PID 0 (Idle) for dashboard sorting; skip negatives only
                try:
                    pid = int(pid)
                except Exception:
                    continue
                if pid < 0:
                    continue
                mem_info = info.get("memory_info")
                rss = getattr(mem_info, "rss", 0) if mem_info else 0
                mem_mb = round(rss / (1024 * 1024), 1)
                mem_pct = round((rss / mem_total) * 100, 2) if mem_total else 0.0
                cpu = float(info.get("cpu_percent") or 0.0)
                path = info.get("exe") or ""
                name = info.get("name") or ""
                cmdline_list = info.get("cmdline") or []
                cmdline = " ".join(cmdline_list) if isinstance(cmdline_list, list) else str(cmdline_list or "")
                create_time = info.get("create_time") or 0
                started_at = None
                runtime_sec = None
                if create_time:
                    started_at = datetime.fromtimestamp(
                        create_time, tz=timezone.utc
                    ).strftime("%Y-%m-%dT%H:%M:%SZ")
                    runtime_sec = max(0, int(now - create_time))

                username = info.get("username") or ""
                suspicious, reasons = self._process_suspicion(name, path, cmdline)
                interactive = self._is_interactive_process(name, username, interactive_users)
                entry = {
                    "pid": pid,
                    "name": name,
                    "path": path[:260] if path else "",
                    "username": username,
                    "cpu_percent": round(cpu, 1),
                    "cpu": round(cpu, 1),
                    "memory_mb": mem_mb,
                    "memory_percent": mem_pct,
                    "status": info.get("status") or "running",
                    "started_at": started_at,
                    "runtime_sec": runtime_sec,
                    "cmdline": (cmdline[:500] if cmdline else ""),
                    "suspicious": suspicious,
                    "suspicion_reasons": reasons,
                    "interactive": interactive,
                }
                self._annotate_agent_self(entry)
                collected[pid] = entry
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception:
                continue

        procs = list(collected.values())
        by_cpu = sorted(procs, key=lambda x: x.get("cpu_percent", 0), reverse=True)[:80]
        by_mem = sorted(procs, key=lambda x: x.get("memory_mb", 0), reverse=True)[:40]
        suspicious = [p for p in procs if p.get("suspicious")]
        interactive = [p for p in procs if p.get("interactive")]

        merged: Dict[int, dict] = {}
        for group in (by_cpu, by_mem, interactive, suspicious):
            for p in group:
                merged[p["pid"]] = p

        # Pad to MIN_TOP_PROCESSES so dashboard is never a skinny top-10
        if len(merged) < MIN_TOP_PROCESSES:
            by_mem_all = sorted(procs, key=lambda x: x.get("memory_mb", 0), reverse=True)
            for p in by_mem_all:
                if len(merged) >= MIN_TOP_PROCESSES:
                    break
                merged[p["pid"]] = p
        if len(merged) < MIN_TOP_PROCESSES:
            for p in sorted(procs, key=lambda x: (x.get("name") or "").lower()):
                if len(merged) >= min(MIN_TOP_PROCESSES, len(procs)):
                    break
                merged[p["pid"]] = p

        out = list(merged.values())
        out.sort(
            key=lambda x: (
                not x.get("suspicious"),
                not x.get("interactive"),
                -(x.get("cpu_percent") or 0),
            ),
        )
        return out[:MAX_TOP_PROCESSES]

    def _interactive_usernames(self) -> set:
        """Lowercased SAM names from active_sessions (best-effort)."""
        users = set()
        try:
            for s in (self._stats.get("active_sessions") or []):
                u = (s.get("username") or "").strip()
                if not u:
                    continue
                users.add(u.lower())
                if "\\" in u:
                    users.add(u.split("\\")[-1].lower())
        except Exception:
            pass
        return users

    @staticmethod
    def _is_interactive_process(name: str, username: str, interactive_users: set) -> bool:
        """True for console/RDP user apps (include even at 0% CPU)."""
        nlow = (name or "").lower()
        ulow = (username or "").lower()
        if any(h in nlow for h in _INTERACTIVE_NAME_HINTS):
            return True
        if interactive_users and ulow:
            for u in interactive_users:
                if u and u in ulow:
                    return True
        # Non-system account with a real username → session process
        if ulow and not any(
            x in ulow
            for x in (
                "nt authority\\system",
                "nt authority\\local service",
                "nt authority\\network service",
                "font driver host",
                "umfd-",
                "dwm-",
            )
        ):
            # Skip pure services account noise: SYSTEM without domain user
            if ulow.endswith("\\system") or ulow == "system":
                return False
            if "\\" in ulow or "@" in ulow:
                return True
        return False

    @staticmethod
    def _process_suspicion(name: str, path: str, cmdline: str) -> Tuple[bool, List[str]]:
        reasons: List[str] = []
        nlow = (name or "").lower()
        plow = (path or "").lower().replace("/", "\\")
        clow = (cmdline or "").lower()

        for marker in _SUSPICIOUS_PATH_MARKERS:
            if marker in plow:
                reasons.append("temp_path")
                break
        for bad in _SUSPICIOUS_NAMES:
            if bad in nlow or bad in plow:
                reasons.append("name_match")
                break
        for bin_name, hints in _LOLBIN_HINTS:
            if bin_name in nlow or bin_name in plow:
                if any(h in clow for h in hints):
                    reasons.append("lolbin")
                    break
        return (len(reasons) > 0), reasons

    def _annotate_agent_self(self, entry: dict) -> None:
        """Mark our PID with HMAC proof; flag name-spoof copies as suspicious."""
        try:
            import os
            import sys
            from client_security_utils import make_agent_self_proof, normalize_exe_path

            my_pid = os.getpid()
            pid = int(entry.get("pid") or 0)
            token = self.token_getter() or ""
            my_exe = ""
            try:
                import psutil
                my_exe = psutil.Process(my_pid).exe() or sys.executable or ""
            except Exception:
                my_exe = sys.executable or ""

            name = (entry.get("name") or "").lower()
            path = entry.get("path") or ""
            is_honeypot_name = "honeypot-client" in name or name == "honeypot-client.exe"

            if pid == my_pid and token:
                proof = make_agent_self_proof(token, my_pid, my_exe or path)
                entry["is_agent_self"] = True
                entry["self_proof"] = proof
                entry["suspicious"] = False
                entry["suspicion_reasons"] = []
                entry["path"] = (my_exe or path)[:260]
                return

            if is_honeypot_name and pid != my_pid:
                # Same image name, different PID → possible spoof
                my_norm = normalize_exe_path(my_exe)
                other_norm = normalize_exe_path(path)
                if other_norm and my_norm and other_norm == my_norm:
                    # Second instance of same install path — still not "self" for this report
                    entry["is_agent_self"] = False
                else:
                    entry["is_agent_self"] = False
                    entry["suspicious"] = True
                    reasons = list(entry.get("suspicion_reasons") or [])
                    if "name_spoof_candidate" not in reasons:
                        reasons.append("name_spoof_candidate")
                    entry["suspicion_reasons"] = reasons
        except Exception:
            pass

    def _build_agent_runtime(self) -> Optional[dict]:
        """agent_runtime block for health/report snapshot."""
        try:
            import os
            import sys
            from client_security_utils import make_agent_self_proof

            token = self.token_getter() or ""
            if not token:
                return None
            pid = os.getpid()
            exe_path = ""
            try:
                import psutil
                exe_path = psutil.Process(pid).exe() or ""
            except Exception:
                exe_path = sys.executable or ""
            if not exe_path:
                return None
            return {
                "pid": pid,
                "exe_path": exe_path,
                "proof": make_agent_self_proof(token, pid, exe_path),
            }
        except Exception:
            return None

    # ── Anomaly Alerting ──────────────────────────────────────────

    def _get_top_disk_io_processes(self, top_n: int = 5) -> List[dict]:
        """Disk I/O anomalisi sırasında en çok disk yazan/okuyan süreçleri tespit et."""
        try:
            import psutil
            procs = []
            for p in psutil.process_iter(['pid', 'name', 'io_counters', 'exe', 'create_time']):
                try:
                    info = p.info
                    io = info.get('io_counters')
                    if io is None:
                        continue
                    procs.append({
                        "pid": info['pid'],
                        "name": info.get('name', 'unknown'),
                        "exe": (info.get('exe') or 'N/A')[:120],
                        "read_bytes": io.read_bytes,
                        "write_bytes": io.write_bytes,
                        "read_mb": round(io.read_bytes / 1024 / 1024, 1),
                        "write_mb": round(io.write_bytes / 1024 / 1024, 1),
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            procs.sort(key=lambda x: x["write_bytes"], reverse=True)
            return procs[:top_n]
        except Exception:
            return []

    def _get_top_network_processes(self, top_n: int = 5) -> List[dict]:
        """Network anomalisi sırasında en çok ağ trafiği oluşturan süreçleri tespit et."""
        try:
            import psutil
            procs = []
            for p in psutil.process_iter(['pid', 'name', 'io_counters', 'exe']):
                try:
                    info = p.info
                    io = info.get('io_counters')
                    if io is None:
                        continue
                    # psutil io_counters doesn't distinguish network from disk
                    # but we can use net connections per process instead
                    try:
                        conns = p.net_connections()
                        conn_count = len(conns)
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        conn_count = 0
                    if conn_count > 0:
                        procs.append({
                            "pid": info['pid'],
                            "name": info.get('name', 'unknown'),
                            "exe": (info.get('exe') or 'N/A')[:120],
                            "connections": conn_count,
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            procs.sort(key=lambda x: x["connections"], reverse=True)
            return procs[:top_n]
        except Exception:
            return []

    def _is_benign_disk_io(self, process_details: List[dict]) -> bool:
        """True if top disk writers look like IDE/browser/OS — not ransomware."""
        if not process_details:
            return False
        # If majority of top writers are benign, treat as benign
        benign_hits = 0
        checked = 0
        for p in process_details[:3]:
            checked += 1
            name = (p.get("name") or "").lower()
            exe = (p.get("exe") or "").lower()
            hit = False
            for b in _BENIGN_DISK_IO_NAMES:
                if b in name or b in exe:
                    hit = True
                    break
            if not hit:
                for path in _BENIGN_DISK_IO_PATHS:
                    if path in exe:
                        hit = True
                        break
            if hit:
                benign_hits += 1
        return checked > 0 and benign_hits >= max(1, (checked + 1) // 2)

    def _emit_anomaly(
        self,
        metric: str,
        value: float,
        description: str,
        score: int,
        *,
        category: str = "performance",
    ):
        """Feed anomaly to ThreatEngine — capacity/benign never look like ransomware."""
        process_details = []
        if "disk_io" in metric:
            process_details = self._get_top_disk_io_processes()
            if process_details:
                proc_lines = "; ".join(
                    f"{p['name']}(PID:{p['pid']}) W:{p['write_mb']}MB R:{p['read_mb']}MB [{p['exe']}]"
                    for p in process_details[:3]
                )
                log(f"[HEALTH] Anomaly: {metric} = {value:.1f} [{category}] — {description}")
                log(f"[HEALTH] Top disk I/O processes: {proc_lines}")
            else:
                log(f"[HEALTH] Anomaly: {metric} = {value:.1f} [{category}] — {description}")
        elif "net_bytes" in metric:
            process_details = self._get_top_network_processes()
            if process_details:
                proc_lines = "; ".join(
                    f"{p['name']}(PID:{p['pid']}) conns:{p['connections']} [{p['exe']}]"
                    for p in process_details[:3]
                )
                log(f"[HEALTH] Anomaly: {metric} = {value:.1f} [{category}] — {description}")
                log(f"[HEALTH] Top network processes: {proc_lines}")
            else:
                log(f"[HEALTH] Anomaly: {metric} = {value:.1f} [{category}] — {description}")
        else:
            # Capacity already logged with cooldown in collect loop
            if category != "capacity":
                log(f"[HEALTH] Anomaly: {metric} = {value:.1f} [{category}] — {description}")

        # Soft / capacity: do not inflate threat engine as ransomware
        if category in ("capacity", "performance") and score < 25:
            threat_type = "capacity_warning" if category == "capacity" else "health_performance"
            severity = "info"
            # Skip threat-engine feed for pure capacity / benign I/O noise
            if category == "capacity" or score <= 5:
                return
        elif category == "ransomware_suspect":
            threat_type = "ransomware_suspect"
            severity = "high"
        elif category == "security":
            threat_type = "health_security"
            severity = "high" if score >= 50 else "warning"
        else:
            threat_type = "health_anomaly"
            severity = "warning" if score < 60 else "high"

        if self.on_alert:
            self.on_alert({
                "event_type": "system_health_anomaly",
                "threat_type": threat_type,
                "severity": severity,
                "threat_score": int(score),
                "details": {
                    "metric": metric,
                    "value": round(value, 2),
                    "description": description,
                    "category": category,
                    "suspect_processes": process_details[:5],
                },
                "description": (
                    f"Sistem anomalisi [{category}]: {description}\n"
                    f"Metrik: {metric} = {value:.1f}\n"
                    + (
                        f"Surecler: {', '.join(p['name'] + '(PID:' + str(p['pid']) + ')' for p in process_details[:3])}"
                        if process_details else ""
                    )
                ),
            })

    # ── API Reporting ─────────────────────────────────────────────

    def _report_loop(self):
        """Report system health snapshot to API periodically."""
        while self._running:
            time.sleep(REPORT_INTERVAL)
            try:
                self._send_report()
            except Exception as e:
                log(f"[HEALTH] Report error: {e}")

    def _send_report(self):
        """POST /api/health/report"""
        if not self.api_client or not self._latest:
            return
        token = self.token_getter()
        if not token:
            return

        # Collect extended memory and disk info
        mem_total_gb = 0.0
        mem_used_gb = 0.0
        disk_total_gb = 0
        disk_free_gb = 0
        self_memory_mb = 0.0
        try:
            import psutil
            mem = psutil.virtual_memory()
            mem_total_gb = round(mem.total / (1024 ** 3), 1)
            mem_used_gb = round(mem.used / (1024 ** 3), 1)
            # Self-process memory usage
            self_memory_mb = round(
                psutil.Process().memory_info().rss / 1024 / 1024, 1
            )
            try:
                disk = psutil.disk_usage("C:\\")
                disk_total_gb = round(disk.total / (1024 ** 3))
                disk_free_gb = round(disk.free / (1024 ** 3))
            except Exception:
                pass
        except Exception:
            pass

        # VSS shadow count + ransomware shield status
        vss_shadow_count = 0
        ransomware_shield_status = "disabled"
        canary_files_intact = True
        ransomware_quarantine = {
            "active": False,
            "locked_at": "",
            "trigger": "",
            "entries": [],
        }
        if self._ransomware_shield:
            try:
                ransomware_shield_status = "active" if self._ransomware_shield._running else "disabled"
                rs_stats = self._ransomware_shield.get_stats()
                canary_files_intact = rs_stats.get("canary_alerts", 0) == 0
                vss_shadow_count = getattr(self._ransomware_shield, "_vss_count", 0) or 0
                quarantine = self._ransomware_shield.get_quarantine()
                ransomware_quarantine = {
                    "active": bool(quarantine.get("active")),
                    "locked_at": quarantine.get("locked_at") or "",
                    "trigger": quarantine.get("trigger") or "",
                    "entries": [
                        {
                            "image": entry.get("image") or "",
                            "path": entry.get("path") or "",
                            "pid": entry.get("pid") or 0,
                            "cmdline": entry.get("cmdline") or "",
                            "sha256": entry.get("sha256") or "",
                            "ifeo": bool(entry.get("ifeo")),
                            "at": entry.get("at") or "",
                        }
                        for entry in (quarantine.get("entries") or [])
                        if isinstance(entry, dict)
                    ],
                }
            except Exception:
                ransomware_shield_status = "error"

        payload = {
            "token": token,
            "snapshot": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "cpu_percent": self._latest.get("cpu_percent", 0),
                "memory_percent": self._latest.get("memory_percent", 0),
                "memory_total_gb": mem_total_gb,
                "memory_used_gb": mem_used_gb,
                "disk_usage_percent": self._latest.get("disk_usage_percent", 0),
                "disk_total_gb": disk_total_gb,
                "disk_free_gb": disk_free_gb,
                # Canonical field names (server also accepts legacy aliases)
                "disk_io_read_bytes_sec": round(self._latest.get("disk_io_read_rate", 0)),
                "disk_io_write_bytes_sec": round(self._latest.get("disk_io_write_rate", 0)),
                "network_bytes_sent_sec": round(self._latest.get("net_bytes_sent_rate", 0)),
                "network_bytes_recv_sec": round(self._latest.get("net_bytes_recv_rate", 0)),
                "process_count": self._latest.get("process_count", 0),
                "open_connections": self._latest.get("connection_count", 0),
                "connection_count": self._latest.get("connection_count", 0),
                "anomalies_detected": self._anomalies,
                "top_processes": list(self._stats.get("top_processes") or []),
                # Full list alias (was truncated to 15 — dashboard showed only top-CPU)
                "top_cpu_processes": list(
                    self._stats.get("top_cpu_processes")
                    or self._stats.get("top_processes")
                    or []
                ),
                "active_sessions": list(self._stats.get("active_sessions") or []),
                "sessions": list(self._stats.get("active_sessions") or []),
                "vss_shadow_count": vss_shadow_count,
                "ransomware_shield_status": ransomware_shield_status,
                "canary_files_intact": canary_files_intact,
                "ransomware_quarantine": ransomware_quarantine,
                "client_memory_mb": self_memory_mb,
            },
        }
        try:
            from client_tamper import get_persistence_status
            persistence = get_persistence_status()
            payload["snapshot"]["persistence"] = persistence
            # Additive draft field — cloud ignores until contract promotion.
            if isinstance(persistence.get("resilience"), dict):
                payload["snapshot"]["resilience"] = persistence["resilience"]
        except Exception:
            pass
        # RANS-301: contract key is `etw_shadow` (bounded sensor health only).
        try:
            etw = getattr(self, "etw_shadow", None)
            if etw is not None and hasattr(etw, "status"):
                payload["snapshot"]["etw_shadow"] = etw.status()
        except Exception:
            pass
        # ZT-600 observe: command-signing coverage from the executor counters.
        try:
            rc = getattr(self, "remote_commands", None)
            if rc is not None and hasattr(rc, "get_signing_health"):
                payload["snapshot"]["command_signing"] = rc.get_signing_health()
        except Exception:
            pass
        # ID-401: event-log sensor health (no event payload until promotion).
        try:
            ew = getattr(self, "event_watcher", None)
            if ew is not None and hasattr(ew, "get_health"):
                payload["snapshot"]["event_log_health"] = ew.get_health()
        except Exception:
            pass
        try:
            ng = getattr(self, "network_guard", None)
            if ng is not None:
                payload["snapshot"]["network_guard"] = ng.status()
        except Exception:
            pass
        # RES-105/106: default-off, observe-only ACL fingerprint/drift summary.
        # Raw ACLs and principal names never leave the host.
        try:
            from client_resilience_p1 import acl_drift_enabled, acl_drift_status
            if acl_drift_enabled():
                payload["snapshot"]["access_integrity"] = acl_drift_status(token)
        except Exception:
            pass
        # DEV-601 read-only TPM capability PoC; no key generation/enrollment.
        try:
            from client_device_identity import observe_enabled, probe_tpm
            if observe_enabled():
                payload["snapshot"]["device_identity"] = probe_tpm()
        except Exception:
            pass
        # DEC-201/202: path-free canary coverage counts (contract 1.4.5).
        try:
            shield = self._ransomware_shield
            if shield is not None and hasattr(shield, "get_stats"):
                cov = (shield.get_stats() or {}).get("canary_coverage")
                if isinstance(cov, dict):
                    payload["snapshot"]["canary_coverage"] = cov
        except Exception:
            pass
        # DEC-205/206/208/209: credential-free deception budgets.
        try:
            sm = getattr(self, "service_manager", None)
            if sm is not None and hasattr(sm, "get_deception_health"):
                payload["snapshot"]["deception_health"] = sm.get_deception_health()
        except Exception:
            pass
        # ZT-602/603: poll observe stub; verify always false.
        try:
            from client_operator_keys import fetch_keyset, observe_enabled as keys_observe
            if keys_observe():
                payload["snapshot"]["operator_keys"] = fetch_keyset(
                    self.api_client, token
                )
        except Exception:
            pass

        # OOB-501: offline urgent queue depth + durable drop counters (api/10).
        try:
            from client_offline_queue import health_observe_block
            payload["snapshot"]["offline_urgent_queue"] = health_observe_block(token)
        except Exception:
            pass

        # C-CANARY-5: echo in_canary + gate map (observe).
        try:
            from client_fleet_canary import snapshot_for_health
            payload["snapshot"]["fleet_rollout"] = snapshot_for_health()
        except Exception:
            pass

        runtime = self._build_agent_runtime()
        if runtime:
            payload["snapshot"]["agent_runtime"] = runtime
            payload["snapshot"]["self_process"] = runtime  # alias

        n_sess = len(payload["snapshot"].get("active_sessions") or [])
        n_proc = len(payload["snapshot"].get("top_processes") or [])
        try:
            resp = self.api_client.api_request(
                "POST", "health/report",
                data=payload, timeout=15, verbose_logging=False,
            )
            if isinstance(resp, dict) and resp.get("status") in ("ok", "success", "received"):
                self._stats["reports_sent"] += 1
                n = int(self._stats.get("reports_sent") or 0)
                if n == 1 or n % 12 == 0:
                    log(f"[HEALTH] report ok — sessions={n_sess} processes={n_proc}")
                return True
            # Accept any 2xx-style non-null response
            if resp is not None:
                self._stats["reports_sent"] += 1
                n = int(self._stats.get("reports_sent") or 0)
                if n == 1 or n % 12 == 0:
                    log(f"[HEALTH] report accepted — sessions={n_sess} processes={n_proc}")
                return True
            log(f"[HEALTH] report unexpected response — sessions={n_sess} processes={n_proc} resp={resp!r}")
        except Exception as e:
            log(f"[HEALTH] API report error: {e}")
        return False

    def force_report(self, refresh: bool = True) -> bool:
        """Immediate health report (dashboard refresh / remote list_* cmds)."""
        try:
            if refresh:
                self._collect_metrics()
            return bool(self._send_report())
        except Exception as e:
            log(f"[HEALTH] force_report error: {e}")
            return False

    # ── Public Accessors ──────────────────────────────────────────

    def get_stats(self) -> dict:
        return dict(self._stats)

    def get_snapshot(self) -> dict:
        """Current system health snapshot for dashboard."""
        return {
            "cpu_percent": self._latest.get("cpu_percent", 0),
            "memory_percent": self._latest.get("memory_percent", 0),
            "disk_usage_percent": self._latest.get("disk_usage_percent", 0),
            "process_count": self._latest.get("process_count", 0),
            "connection_count": self._latest.get("connection_count", 0),
            "net_recv_bps": self._latest.get("net_bytes_recv_rate", 0),
            "net_sent_bps": self._latest.get("net_bytes_sent_rate", 0),
            "anomalies": list(self._anomalies),
            "active_sessions": list(self._stats.get("active_sessions") or []),
            "top_processes": list(self._stats.get("top_processes") or [])[:30],
            "status": self._get_health_status(),
        }

    def _get_health_status(self) -> str:
        """Overall health assessment."""
        if len(self._anomalies) >= 3:
            return "critical"
        elif len(self._anomalies) >= 1:
            return "warning"
        return "healthy"
