#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Asteria Client — main application orchestrator.

Coordinates GUI/tray display, API communication, honeypot service management,
RDP operations, and background health monitoring. Runs in two modes:

  GUI mode  — Tkinter window + system tray, update watchdog thread (1 hr)
  Daemon    — Headless via Task Scheduler, auto-updates every 2 hrs

Modules:
  client_api                     — API layer
  client_honeypots               — Honeypot service implementations (FTP, SSH, MySQL, MSSQL, RDP)
  client_service_manager         — Central service lifecycle manager
  client_rdp / client_firewall   — RDP port mgmt, firewall rules
  client_monitoring / client_security — Health checks, Defender compat
  client_updater / client_tray   — Auto-update, system tray
  client_instance / client_logging — Singleton control, log setup
  client_tokens / client_task_scheduler — Auth tokens, scheduled tasks
  client_memory_restart          — Memory-threshold restart
  client_helpers / client_utils / client_constants — Shared utilities

Exit codes: 0 normal, 1 critical error, 2 another instance running, 3 health-check fail.
"""

# Guardian fast-path — MUST run before heavy imports.
# SCM kills the service if StartServiceCtrlDispatcher is not reached within ~30s.
# Full client.py imports (tk/CTk/numpy/av) regularly exceed that budget and caused
# Event 7009/7000 start timeouts + motor heal loops (guardian_restarts_24h 150+).
import sys as _sys

if __name__ == "__main__":
    try:
        from client_guardian_service import is_guardian_argv, run_guardian_mode
        if is_guardian_argv():
            run_guardian_mode()
            _sys.exit(0)
    except SystemExit:
        raise
    except Exception as _guardian_boot_err:
        # If argv is guardian but import/boot failed, do not fall through to GUI.
        try:
            from client_guardian_service import is_guardian_argv as _iga
            if _iga():
                try:
                    print(f"GUARDIAN FASTPATH ERROR: {_guardian_boot_err}", file=_sys.stderr)
                except Exception:
                    pass
                _sys.exit(1)
        except Exception:
            pass

# Standard library imports
import os, sys, socket, threading, time, json, subprocess, ctypes, argparse
import tkinter as tk
from tkinter import messagebox
from typing import Optional, Dict, Any, Union
import webbrowser, logging

if os.environ.get("ASTERIA_MOTOR_ONLY") == "1":
    ctk = None
else:
    import customtkinter as ctk

# Local module imports  
from client_firewall import FirewallAgent
from client_helpers import log, ClientHelpers, run_cmd, is_session_zero, launch_interactive_tray_gui
import client_helpers
from client_service_manager import ServiceManager
from client_api import AsteriaAPIClient, api_request_with_token
from client_helpers import is_port_in_use
from client_tokens import create_token_manager, get_token_file_paths
from client_task_scheduler import perform_comprehensive_task_management
from client_utils import (ServiceController, load_i18n, install_excepthook, 
                         load_config, get_config_value, set_config_value,
                         get_from_config, start_watchdog_if_needed, get_port_table,
                         update_language_config, resolve_app_language,
                         watchdog_main, ensure_firewall_allow_for_port)

# Import constants from central configuration
from client_constants import (
    GUI_MODE, DAEMON_MODE, API_URL, APP_DIR, LOG_FILE,
    TRY_TRAY, RDP_SECURE_PORT,
    SERVER_NAME, HONEYPOT_SERVICES,
    API_STARTUP_DELAY, API_RETRY_INTERVAL, API_SLOW_RETRY_DELAY,
    API_HEARTBEAT_INTERVAL, ATTACK_COUNT_REFRESH, BLOCK_POLL_INTERVAL,
    CONSENT_FILE, STATUS_FILE,
    WATCHDOG_TOKEN_FILE, __version__, GITHUB_OWNER, GITHUB_REPO,
    WINDOW_WIDTH, WINDOW_HEIGHT, CONTROL_HOST, CONTROL_PORT,
    ENABLE_THREAT_DETECTION
)

# Import RDP management module
from client_rdp import RDPManager, RDPPopupManager

# Import new modular components
from client_monitoring import MonitoringManager, perform_health_check
from client_instance import check_singleton
from client_logging import LoggingManager, setup_logging
from client_security import SecurityManager
from client_updater import UpdateManager
if os.environ.get("ASTERIA_MOTOR_ONLY") == "1":
    TrayManager = None
    ModernGUI = None
else:
    from client_tray import TrayManager
    from client_gui import ModernGUI

# Import threat detection modules (v4.0)
from client_eventlog import EventLogWatcher
from client_threat_engine import ThreatEngine
from client_alerts import AlertPipeline

# Import Faz 2 modules (v4.0)
from client_auto_response import AutoResponse
from client_remote_commands import RemoteCommandExecutor
from client_silent_hours import SilentHoursGuard
from client_logon_challenge import LogonChallengeGuard

# Import Faz 3 modules (v4.0)
from client_ransomware_shield import RansomwareShield
from client_system_health import SystemHealthMonitor
from client_self_protection import ProcessProtection

# Import Faz 4 modules (v4.0)
from client_performance import PerformanceOptimizer, FalsePositiveTuner, MemoryGuard

try:
    from client_memory_restart import enable_simple_memory_restart, get_current_memory_mb, check_previous_restart_state
    MEMORY_RESTART_AVAILABLE = True
except ImportError:
    MEMORY_RESTART_AVAILABLE = False
    # Define dummy functions to prevent errors
    def enable_simple_memory_restart(*args, **kwargs): pass
    def get_current_memory_mb(): return 0
    def check_previous_restart_state(): return None

def get_operation_mode(args) -> str:
    """Determine operation mode from arguments."""
    if getattr(args, 'mode', None) == "daemon" or getattr(args, 'daemon', False):
        return DAEMON_MODE
    elif getattr(args, 'mode', None) == "guardian":
        return "guardian"
    elif getattr(args, 'mode', None) == "watchdog" or getattr(args, 'watchdog', False):
        return "watchdog"
    else:
        return GUI_MODE

# Global logger
LOGGER = None

# Initialize logging through modular system
logging_manager = LoggingManager()
if logging_manager.initialize():
    LOGGER = logging_manager.get_logger()

I18N = load_i18n()


class CloudHoneypotClient:
    # Port mappings loaded from configuration
    @property
    def PORT_TABLOSU(self):
        """Get port table from configuration file"""
        if not hasattr(self, '_port_table_cache'): self._port_table_cache = get_port_table()
        return self._port_table_cache

    def log(self, message: str):
        """Log message using global logger with class context"""
        log(f"[CLIENT] {message}")

    def _gui_safe(self, func):
        """Thread-safe GUI çağrısı — root yoksa veya yok edilmişse sessizce atlar"""
        try:
            if self.root and self.root.winfo_exists():
                self.root.after(0, func)
        except Exception:
            pass  # root destroyed veya erişilemez

    def get_token(self) -> Optional[str]:
        """Kaydedilmiş token'ı yükler"""
        return self.token_manager.get_token()

    def api_request(self, method: str, endpoint: str, data: Dict = None,
                    params: Dict = None, timeout: int = 8, json: Dict = None) -> Optional[Dict]:
        """API request wrapper using modular API client"""
        token = self.state.get("token")
        return api_request_with_token(
            self.api_client, token, method, endpoint, data, params, timeout, json
        )

    def __init__(self):
        install_excepthook()
        
        # Initialize modular managers
        self.monitoring_manager = MonitoringManager(APP_DIR)
        self.security_manager = SecurityManager()
        self.update_manager = UpdateManager()
        
        # Initialize security system (defer heavy exe hash on GUI fast path)
        try:
            _argv0 = " ".join(sys.argv).lower()
            _defer_sec = any(
                x in _argv0
                for x in ("--show-gui", "--mode=gui", "--mode=frontend", "--mode=tray")
            )
            if _defer_sec:
                def _bg_sec():
                    try:
                        self.security_manager.initialize()
                    except Exception as e:
                        log(f"Security initialization warning: {e}")
                threading.Thread(target=_bg_sec, daemon=True, name="SecurityInit").start()
            else:
                log("Initializing security systems...")
                self.security_manager.initialize()
                log("Security systems initialized successfully")
        except Exception as e:
            log(f"Security initialization warning: {e}")
        
        # Load configuration directly - pure config-driven architecture
        self.config = load_config()
        
        # Initialize language with safe fallback from config
        try:
            self.lang = resolve_app_language()
        except Exception:
            self.lang = "en"

        # Initialize core components
        self.api_client = AsteriaAPIClient(str(API_URL), log)
        
        # Initialize token manager
        token_file_new, token_file_old = get_token_file_paths(APP_DIR)
        self.token_manager = create_token_manager(str(API_URL), SERVER_NAME, token_file_new, token_file_old)
        
        if LOGGER: client_helpers.set_logger(LOGGER)
        self.reconciliation_lock = threading.Lock()
        self.rdp_transition_complete = threading.Event()
        
        # Initialize application state FIRST
        self.state = {
            "running": False, "token": None,
            "public_ip": None, "tray": None, "selected_rows": [],
            "selected_ports_map": None, "ctrl_sock": None,
        }
        
        # Initialize RDP Management modules
        self.rdp_manager = RDPManager(main_app=self)
        self.rdp_popup_manager = RDPPopupManager(main_app=self, translation_func=self.t)
        
        # Initialize Service Manager — central lifecycle manager for all honeypots
        self.service_manager = ServiceManager(
            api_client=self.api_client,
            rdp_manager=self.rdp_manager,
            token_getter=lambda: self.state.get("token", ""),
        )

        # Early daemon detect BEFORE motor stack (GUI must stay light)
        self.daemon_is_active = False
        self.frontend_only = False
        self._is_daemon_motor = False
        self._protection_mode_cache = "inactive"
        self._protection_mode_ts = 0.0
        self._protection_poller_started = False
        _argv_join = " ".join(sys.argv)
        _is_daemon_argv = "--mode=daemon" in _argv_join or "--daemon" in _argv_join
        if not _is_daemon_argv:
            try:
                from client_daemon_ipc import is_motor_healthy, ping
                _t_ping = time.time()
                healthy = bool(is_motor_healthy(timeout=0.35))
                pong = True if healthy else bool(ping(timeout=0.15))
                self.daemon_is_active = healthy
                log(
                    f"[PERF] early_motor_check healthy={healthy} ping={pong} "
                    f"{(time.time() - _t_ping) * 1000:.0f}ms"
                )
                if pong and not healthy:
                    log(
                        "[IPC] WARN: :58632 PING ok but motor_ok=false — "
                        "not entering frontend_only (will build motors / ensure Background)"
                    )
            except Exception:
                self.daemon_is_active = False
            if self.daemon_is_active:
                self.frontend_only = True
                self._protection_mode_cache = "monitoring"
                log("[PERF] frontend_only — skipping local threat/Faz motor construction")
        
        # Initialize Threat Detection Pipeline (v4.0) — daemon owns this in frontend mode
        self.alert_pipeline = None
        self.threat_engine = None
        self.event_watcher = None
        if ENABLE_THREAT_DETECTION and not self.frontend_only:
            try:
                self.alert_pipeline = AlertPipeline(
                    api_client=self.api_client,
                    token_getter=lambda: self.state.get("token", ""),
                    machine_name=SERVER_NAME,
                )
                self.threat_engine = ThreatEngine(
                    on_alert=self.alert_pipeline.handle_alert
                )
                self.event_watcher = EventLogWatcher(
                    on_event=self.threat_engine.process_event,
                )
                # Contract: register-persisted protection.block_rules
                try:
                    from client_protection_store import hydrate_threat_engine_from_store
                    n = hydrate_threat_engine_from_store(self.threat_engine)
                    if n:
                        log(f"[PROTECTION] boot hydrate block_rules={n}")
                except Exception as pe:
                    log(f"[PROTECTION] boot hydrate skip: {pe}")
                try:
                    from client_defense_policy import hydrate_from_disk as _dp_hydrate
                    from client_defense_policy import set_tamper_alert_callback as _dp_cb
                    _dp_cb(
                        self.alert_pipeline.handle_alert
                        if self.alert_pipeline
                        else None
                    )
                    st = _dp_hydrate()
                    log(
                        f"[DEFENSE-POLICY] boot hydrate "
                        f"policy={st.get('policy_name')} src={st.get('source')}"
                    )
                except Exception as dpe:
                    log(f"[DEFENSE-POLICY] boot hydrate skip: {dpe}")
                # Wire ThreatEngine into ServiceManager for honeypot credential scoring
                self.service_manager._threat_engine = self.threat_engine
                log("✅ Threat detection modules initialized (v4.0)")
            except Exception as e:
                log(f"⚠️ Threat detection init failed: {e}")
                self.alert_pipeline = None
                self.threat_engine = None
                self.event_watcher = None

        # Initialize Faz 2 modules (v4.0) — Auto-Response, Remote Commands, Silent Hours
        self.auto_response = None
        self.remote_commands = None
        self.silent_hours_guard = None
        self.logon_challenge_guard = None
        if ENABLE_THREAT_DETECTION and not self.frontend_only:
            try:
                self.auto_response = AutoResponse(
                    api_client=self.api_client,
                    token_getter=lambda: self.state.get("token", ""),
                )
                self.auto_response.alert_pipeline = self.alert_pipeline
                self.remote_commands = RemoteCommandExecutor(
                    api_client=self.api_client,
                    token_getter=lambda: self.state.get("token", ""),
                    auto_response=self.auto_response,
                    service_manager=getattr(self, "service_manager", None),
                    on_threat_config_updated=lambda _data: self._sync_threat_config(),
                )
                self.silent_hours_guard = SilentHoursGuard(
                    auto_response=self.auto_response,
                    alert_pipeline=self.alert_pipeline,
                )
                self.logon_challenge_guard = LogonChallengeGuard(
                    auto_response=self.auto_response,
                    alert_pipeline=self.alert_pipeline,
                    api_client=self.api_client,
                    token_getter=lambda: self.state.get("token", ""),
                    threat_engine=self.threat_engine,
                    event_watcher=self.event_watcher,
                )
                # Local default: challenge off until dashboard enables it
                try:
                    from client_utils import get_from_config
                    lc_en = bool(get_from_config("logon_challenge.enabled", False))
                    self.logon_challenge_guard.update_config({
                        "enabled": lc_en,
                        "auto_logoff": bool(get_from_config("logon_challenge.auto_logoff", True)),
                    })
                except Exception:
                    pass
                # Wire auto_response into alert pipeline for auto-blocking
                if self.alert_pipeline:
                    self.alert_pipeline.auto_response = self.auto_response
                    self.auto_response.alert_pipeline = self.alert_pipeline
                # Wire silent hours + logon challenge into threat engine
                if self.threat_engine:
                    self.threat_engine.silent_hours_guard = self.silent_hours_guard
                    self.threat_engine.logon_challenge_guard = self.logon_challenge_guard
                log("✅ Faz 2 modules initialized (AutoResponse, RemoteCmd, SilentHours, LogonChallenge)")
            except Exception as e:
                log(f"⚠️ Faz 2 init failed: {e}")
                self.auto_response = None
                self.remote_commands = None
                self.silent_hours_guard = None
                self.logon_challenge_guard = None

        # Data cleanup / maintenance (local + firewall + server sync)
        try:
            from client_cleanup import DataCleanupManager
            self.cleanup_manager = DataCleanupManager(self)
        except Exception as e:
            log(f"⚠️ Cleanup manager init failed: {e}")
            self.cleanup_manager = None

        # Wire cleanup + honeypot manager into remote commands
        if self.remote_commands is not None and self.cleanup_manager is not None:
            self.remote_commands.cleanup_manager = self.cleanup_manager
        if self.remote_commands is not None and getattr(self, "service_manager", None) is not None:
            self.remote_commands.service_manager = self.service_manager
            try:
                self.remote_commands._gui_bump = lambda: self._bump_status_generation()
            except Exception:
                pass

        # Initialize Faz 3 modules (v4.0) — Ransomware Shield, System Health, Self-Protection
        self.ransomware_shield = None
        self.health_monitor = None
        self.process_protection = None
        self.network_guard = None
        if ENABLE_THREAT_DETECTION and not self.frontend_only:
            try:
                from client_constants import (
                    ENABLE_RANSOMWARE_SHIELD, ENABLE_SELF_PROTECTION,
                )
                if ENABLE_RANSOMWARE_SHIELD:
                    self.ransomware_shield = RansomwareShield(
                        on_alert=self.alert_pipeline.handle_alert if self.alert_pipeline else None,
                        auto_response=self.auto_response,
                        alert_pipeline=self.alert_pipeline,
                        threat_engine=self.threat_engine,
                    )
                # Network Guard — offline ransomware bomb + net-drive recovery (≥4.7.0)
                try:
                    from client_network_guard import NetworkGuard
                    from client_network_guard import load_config as _ng_load_config
                    self.network_guard = NetworkGuard(
                        alert_pipeline=self.alert_pipeline,
                        ransomware_shield=self.ransomware_shield,
                        config=_ng_load_config(getattr(self, "config", None)),
                    )
                except Exception as nge:
                    log(f"⚠️ NetworkGuard init failed: {nge}")
                    self.network_guard = None
                # System Recovery — policy/service/firewall allowlist (≥4.9.12)
                try:
                    from client_system_recovery import SystemRecoveryGuard
                    self.system_recovery = SystemRecoveryGuard(
                        alert_pipeline=self.alert_pipeline,
                        enabled=True,
                    )
                except Exception as sre:
                    log(f"⚠️ SystemRecovery init failed: {sre}")
                    self.system_recovery = None
                self.health_monitor = SystemHealthMonitor(
                    api_client=self.api_client,
                    token_getter=lambda: self.state.get("token", ""),
                    threat_engine=self.threat_engine,
                    ransomware_shield=self.ransomware_shield,
                )
                # RANS-301: ETW shadow surface (default off; health-only, no contain)
                try:
                    from client_utils import get_from_config
                    if bool(get_from_config(
                        "threat_detection.etw_file_io_shadow", False
                    )):
                        from client_etw_shadow import EtwShadowSensor
                        psutil_fb = bool(get_from_config(
                            "threat_detection.etw_psutil_fallback", False
                        ))
                        self.health_monitor.etw_shadow = EtwShadowSensor(
                            enable_psutil_fallback=psutil_fb,
                        )
                        self.health_monitor.etw_shadow.start()
                except Exception as etw_exc:
                    log(f"⚠️ ETW shadow init skipped: {etw_exc}")
                if ENABLE_SELF_PROTECTION:
                    self.process_protection = ProcessProtection(
                        threat_engine=self.threat_engine,
                        alert_pipeline=self.alert_pipeline,
                        api_client=self.api_client,
                        token_getter=lambda: self.state.get("token", ""),
                    )
                log("✅ Faz 3 modules initialized (RansomwareShield, HealthMonitor, SelfProtection)")
            except Exception as e:
                log(f"⚠️ Faz 3 init failed: {e}")
                self.ransomware_shield = None
                self.health_monitor = None
                self.process_protection = None
                self.system_recovery = None

        # Wire ransomware shield into remote command executor (created earlier)
        if getattr(self, "remote_commands", None) is not None and self.ransomware_shield is not None:
            self.remote_commands.ransomware_shield = self.ransomware_shield
        # Wire network guard into remote command executor + health monitor
        if getattr(self, "remote_commands", None) is not None and self.network_guard is not None:
            self.remote_commands.network_guard = self.network_guard
        if getattr(self, "remote_commands", None) is not None and getattr(
            self, "system_recovery", None
        ) is not None:
            self.remote_commands.system_recovery = self.system_recovery
        if getattr(self, "health_monitor", None) is not None and self.network_guard is not None:
            self.health_monitor.network_guard = self.network_guard
        if getattr(self, "health_monitor", None) is not None:
            self.health_monitor.service_manager = getattr(self, "service_manager", None)

        # Cloud threat-intel (daemon only) — soft if API not ready
        self.threat_intel = None
        if ENABLE_THREAT_DETECTION and not self.frontend_only:
            try:
                from client_threat_intel import ThreatIntelManager
                self.threat_intel = ThreatIntelManager(
                    api_client=self.api_client,
                    token_getter=lambda: self.state.get("token", ""),
                    ransomware_shield=self.ransomware_shield,
                    auto_response=self.auto_response,
                    on_alert=self.alert_pipeline.handle_alert if self.alert_pipeline else None,
                )
                log("[THREAT-INTEL] manager initialized")
            except Exception as e:
                log(f"[THREAT-INTEL] init failed: {e}")
                self.threat_intel = None

        # Control WS threat_intel_updated → ThreatIntelManager.sync_once
        if getattr(self, "remote_commands", None) is not None and self.threat_intel is not None:
            self.remote_commands.threat_intel = self.threat_intel

        # Wire health monitor into remote commands (list_sessions / list_processes push)
        if getattr(self, "remote_commands", None) and getattr(self, "health_monitor", None):
            self.remote_commands.health_monitor = self.health_monitor

        # Wire observe-health sources into health monitor (contract 1.4.2):
        # command_signing (ZT-600) + event_log_health (ID-401) additive blocks.
        if getattr(self, "health_monitor", None):
            if getattr(self, "remote_commands", None):
                self.health_monitor.remote_commands = self.remote_commands
            if getattr(self, "event_watcher", None):
                self.health_monitor.event_watcher = self.event_watcher

        # Initialize Faz 4 modules (v4.0) — Performance Optimizer, False Positive Tuner
        self.perf_optimizer = None
        self.fp_tuner = None
        if ENABLE_THREAT_DETECTION and not self.frontend_only:
            try:
                from client_constants import (
                    ENABLE_PERFORMANCE_OPTIMIZER, ENABLE_FALSE_POSITIVE_TUNER,
                )
                if ENABLE_PERFORMANCE_OPTIMIZER:
                    self.perf_optimizer = PerformanceOptimizer()
                if ENABLE_FALSE_POSITIVE_TUNER:
                    self.fp_tuner = FalsePositiveTuner(
                        threat_engine=self.threat_engine,
                        event_watcher=getattr(self, 'event_watcher', None),
                    )
                log("✅ Faz 4 modules initialized (PerfOptimizer, FPTuner)")
            except Exception as e:
                log(f"⚠️ Faz 4 init failed: {e}")
                self.perf_optimizer = None
                self.fp_tuner = None

        # Initialize MemoryGuard — long-running instance memory protection
        self.memory_guard = MemoryGuard()

        # Load token early - before any API operations
        try:
            token = self.token_manager.load_token(self.root if hasattr(self, 'root') else None, self.t)
            self.state["token"] = token
            if token:
                pass
        except Exception as e:
            log(f"Token yükleme hatası: {e}")
            self.state["token"] = None
        
        # Initialize heartbeat system through monitoring manager
        if self.monitoring_manager.start_heartbeat_system(self):
            self.heartbeat_path = self.monitoring_manager.get_heartbeat_path()
        else:
            self.heartbeat_path = ""
        
        # Late re-check only if we still think we're a local motor (GUI path)
        if not self.frontend_only and not _is_daemon_argv:
            try:
                from client_daemon_ipc import is_motor_healthy
                if is_motor_healthy(timeout=0.25):
                    self.daemon_is_active = True
                    self.frontend_only = True
                    self._protection_mode_cache = "monitoring"
                    log("[PERF] late motor_ok — switching to frontend_only")
            except Exception as e:
                log(f"⚠️ Daemon detection failed: {e}")
        
        # Initialize GUI elements
        self.root = None
        self.gui = None
        self.attack_entry = self.ip_entry = self.show_cb = None
        
        # Tray mode tracking - thread-safe flag (prevents window from auto-showing)
        self._tray_mode = threading.Event()  # set() = in tray, clear() = visible
        # Installer/--show-gui: ignore QUIT briefly (kill scripts race with new process)
        self._quit_protect_until = 0.0
        try:
            if any(a in ("--show-gui", "/show-gui") for a in sys.argv):
                self._quit_protect_until = time.time() + 25.0
                log("[GUI] QUIT protect armed (25s) for --show-gui launch")
        except Exception:
            pass
        
        # GUI health monitoring
        self.gui_health = {
            'update_count': 0,
            'health_check_interval': 60  # seconds
        }
        self._last_api_ok = False
        self._last_api_ok_at = None
        self._last_api_check_at = None
        self._last_heartbeat_ok = None
        self._last_heartbeat_at = None
        
        # Check initial RDP state (registry only — no netstat at startup)
        self.rdp_manager.check_initial_rdp_state()
        
        # Registry'ye current mode'u kaydet (Task Scheduler için)
        self._update_registry_mode()
        
        # Task Scheduler + lifecycle: NEVER block first paint.
        # GUI/frontend → background light check; daemon → full sync OK (no window).
        _argv = " ".join(sys.argv).lower()
        _gui_fast = any(
            x in _argv
            for x in ("--show-gui", "--mode=gui", "--mode=frontend", "--mode=tray", "/show-gui")
        ) or not ("--mode=daemon" in _argv or "--daemon" in _argv)

        def _bg_tasks_and_lifecycle():
            try:
                from client_task_scheduler import perform_comprehensive_task_management
                perform_comprehensive_task_management(
                    log_func=log,
                    app_state=self.state,
                    light=bool(_gui_fast),
                )
            except Exception as e:
                log(f"Task Scheduler management error (bg): {e}")
            try:
                from client_lifecycle import report_now, flush_queue_to_api
                report_now(
                    "client_startup",
                    "app_init",
                    {
                        "mode": getattr(self, "_startup_mode", None) or "unknown",
                        "tasks_ok": True,
                    },
                    severity="info",
                    api_client=getattr(self, "api_client", None),
                    token=(self.state.get("token") or ""),
                    log_func=log,
                )
                flush_queue_to_api(
                    api_client=getattr(self, "api_client", None),
                    token=(self.state.get("token") or ""),
                    log_func=log,
                )
            except Exception as e:
                log(f"[LIFECYCLE] startup report error: {e}")
            try:
                from client_update_ui import maybe_mark_done_on_startup
                maybe_mark_done_on_startup(__version__)
            except Exception:
                pass

        if _gui_fast:
            threading.Thread(
                target=_bg_tasks_and_lifecycle, daemon=True, name="StartupTasks"
            ).start()
            log("[STARTUP] Task/lifecycle deferred (fast GUI path)")
        else:
            _bg_tasks_and_lifecycle()
        
        # Memory management — restart every 8 hours if threshold exceeded
        if MEMORY_RESTART_AVAILABLE:
            try:
                # Check if this is a restart from previous session
                previous_state = check_previous_restart_state()
                if previous_state:
                    gui_state = previous_state.get('gui_state', 'unknown')
                    log(f"🔄 Restart detected - previous state: {gui_state}")
                
                current_memory = get_current_memory_mb()
                
                # Her durumda restart schedule aktif (basit ve etkili)
                enable_simple_memory_restart(restart_hours=8)
                
                log(f"� Simple memory restart enabled: Current {current_memory:.1f}MB, Restart every 8h")
                
            except Exception as e:
                log(f"⚠️ Memory restart setup failed: {e}")
        else:
            log("⚠️ Memory restart disabled - module not available")

    def _update_registry_mode(self):
        """Current mode'u registry'ye kaydet (Task Scheduler için)"""
        try:
            current_mode = self._detect_current_mode()
            
            import winreg
            key_path = r"Software\Asteria"
            legacy_path = r"Software\YesNext\CloudHoneypot"
            
            try:
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE)
            except FileNotFoundError:
                key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path)
            
            winreg.SetValueEx(key, "LastMode", 0, winreg.REG_SZ, current_mode)
            winreg.CloseKey(key)

            # Best-effort mirror removal of pre-Asteria LastMode key
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, legacy_path)
            except OSError:
                pass
            
            log(f"📋 Registry mode updated: {current_mode}")
            
        except Exception as e:
            log(f"⚠️ Registry update failed: {e}")
    
    def _detect_current_mode(self):
        """Mevcut çalışma modunu tespit et"""
        try:
            argv = " ".join(sys.argv).lower()
            for arg in sys.argv:
                if "--mode=daemon" in arg:
                    return "--mode=daemon"
                elif "--mode=tray" in arg:
                    return "--mode=tray"
                elif "--mode=gui" in arg or "--mode=frontend" in arg:
                    return "--mode=gui"
            if "--show-gui" in argv or "/show-gui" in argv:
                return "--mode=gui"
            if getattr(self, "_is_daemon_motor", False):
                return "--mode=daemon"
            if hasattr(self, "root") and self.root:
                return "--mode=gui"
            return "--mode=gui"
        except Exception as e:
            log(f"⚠️ Mode detection error: {e}")
            return "--mode=gui"

    def monitor_user_sessions(self):
        """Monitor for user logon sessions in daemon mode (optimized subprocess usage)"""
        import subprocess
        import time
        
        log("Daemon: User session monitoring started")
        check_interval = 10  # seconds — pick up Admin/RDP logon quickly
        last_tray_attempt = 0.0
        had_active = False
        from client_helpers import (
            has_interactive_user_session,
            interactive_frontend_running,
            launch_interactive_tray_gui,
        )
        
        while True:
            try:
                result = subprocess.run(
                    ['query', 'session'],
                    capture_output=True, text=True, timeout=10,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                )
                # Locale-aware Active/Aktif — Admin RDP or console
                if result.returncode == 0:
                    has_active = has_interactive_user_session(result.stdout)
                else:
                    has_active = has_interactive_user_session()

                if has_active and not interactive_frontend_running():
                    now = time.time()
                    rising = has_active and not had_active
                    cooldown = 8 if rising else 45
                    if now - last_tray_attempt >= cooldown:
                        last_tray_attempt = now
                        try:
                            log(
                                "[SESSION] Interactive logon detected "
                                f"(rising={rising}) — launching tray"
                            )
                            launch_interactive_tray_gui()
                        except Exception as e:
                            log(f"Daemon tray handoff (non-fatal): {e}")
                had_active = bool(has_active)

            except subprocess.TimeoutExpired:
                log("Session monitoring: query session timed out")
            except Exception as e:
                log(f"Session monitoring error: {e}")
            
            time.sleep(check_interval)

    def start_delayed_api_sync(self):
        """Start API synchronization with delay in background thread
        
        NOTE: When daemon is running, skip background tasks to avoid duplication.
        Tray mode in UI-only configuration only provides the interface.
        """
        # Skip heavy background tasks if daemon is already handling them — but ALWAYS
        # start HealthMonitor here too: tray used to skip it entirely while daemon also
        # never started it, so dashboard got processes from stale/partial data and
        # active_sessions stayed empty even when the user was logged in.
        if getattr(self, 'frontend_only', False) or getattr(self, 'daemon_is_active', False):
            self.frontend_only = True
            log("🔄 Frontend mode: SYSTEM daemon owns motor — skipping local ServiceManager/threat/RD")

            def _frontend_status_poll():
                try:
                    from client_daemon_ipc import get_status, is_motor_healthy, ensure_daemon_running
                    time.sleep(2)
                    if is_motor_healthy():
                        st = get_status()
                        log(
                            f"[IPC] Daemon STATUS: motor_ok={st.get('motor_ok')} "
                            f"remote_commands={st.get('remote_commands_running')} "
                            f"services={st.get('running_services')} "
                            f"mode={st.get('protection_mode')}"
                        )
                    else:
                        log("[IPC] Motor unhealthy — ensure Background daemon")
                        ok = ensure_daemon_running(log_func=log, wait_sec=15.0)
                        if not ok:
                            self._start_emergency_command_bridge(
                                "frontend_boot_no_motor"
                            )
                except Exception as e:
                    log(f"[IPC] status poll: {e}")

            def _frontend_motor_watchdog():
                """If command poll dies, resurrect Background (dashboard RD / self_update)."""
                fails = 0
                while True:
                    try:
                        time.sleep(45)
                        from client_daemon_ipc import is_motor_healthy, ensure_daemon_running
                        if is_motor_healthy(timeout=1.0):
                            fails = 0
                            # Clear emergency bridge flag if daemon recovered
                            if getattr(self, "_emergency_bridge_active", False):
                                log("[IPC] motor recovered — emergency bridge can idle")
                            continue
                        fails += 1
                        log("[IPC] motor watchdog: unhealthy — ensure_daemon_running")
                        ok = ensure_daemon_running(log_func=log, wait_sec=20.0)
                        if not ok and fails >= 2:
                            self._start_emergency_command_bridge(
                                f"watchdog_fails={fails}"
                            )
                    except Exception as e:
                        log(f"[IPC] motor watchdog: {e}")

            # Frontend still needs API health for the connection card
            try:
                threading.Thread(
                    target=self.api_retry_loop, daemon=True, name="FrontendApiRetry"
                ).start()
            except Exception as e:
                log(f"[IPC] frontend api_retry start: {e}")

            threading.Thread(
                target=_frontend_status_poll,
                daemon=True,
                name="FrontendStatus",
            ).start()
            threading.Thread(
                target=_frontend_motor_watchdog,
                daemon=True,
                name="MotorWatchdog",
            ).start()
            return
            
        def delayed_api_start():
            log(f"API senkronizasyonu {API_STARTUP_DELAY} saniye bekletiliyor (manuel işlemler için)...")
            time.sleep(API_STARTUP_DELAY)
            log("API senkronizasyonu başlatılıyor...")
            # API retry thread'ini başlat
            threading.Thread(target=self.api_retry_loop, daemon=True).start()
            
            # ServiceManager daemon thread'lerini başlat (sync, watchdog, batch reporter)
            self.service_manager.start()
            log("ServiceManager başlatıldı (sync + watchdog + batch reporter)")
            
            # Start Threat + Health (sessions/processes) — shared with daemon path
            if ENABLE_THREAT_DETECTION:
                self._start_threat_and_health_services(source="gui")
                threading.Thread(
                    target=self._threat_config_sync_loop,
                    name="ThreatConfigSync",
                    daemon=True,
                ).start()

            # Start Faz 4 modules (v4.0)
            if ENABLE_THREAT_DETECTION:
                try:
                    if self.perf_optimizer:
                        self.perf_optimizer.start()
                    if self.fp_tuner:
                        from client_utils import get_from_config
                        interval = int(get_from_config(
                            "false_positive_tuner.cleanup_interval_seconds", 3600))
                        self.fp_tuner.start(interval=interval)
                    log("⚙️ Faz 4 started (PerfOptimizer + FPTuner)")
                except Exception as e:
                    log(f"⚠️ Faz 4 start failed: {e}")

            # Start MemoryGuard — long-running instance memory protection
            try:
                if getattr(self, 'memory_guard', None):
                    # Register cleanup callbacks for memory-heavy modules
                    if getattr(self, 'threat_engine', None):
                        self.memory_guard.register_cleanup(
                            "threat_engine",
                            lambda: self.threat_engine._cleanup_stale_contexts()
                        )
                    if getattr(self, 'alert_pipeline', None):
                        self.memory_guard.register_cleanup(
                            "alert_pipeline",
                            lambda: self.alert_pipeline._cleanup_dedup()
                        )
                    if getattr(self, 'fp_tuner', None):
                        self.memory_guard.register_cleanup(
                            "fp_tuner",
                            lambda: self.fp_tuner.cleanup_stale(1800)
                        )
                    try:
                        from client_honeypots import cleanup_honeypot_rate_limiter
                        self.memory_guard.register_cleanup(
                            "honeypot_rate_limiter",
                            cleanup_honeypot_rate_limiter,
                        )
                    except Exception:
                        pass
                    if getattr(self, 'auto_response', None):
                        self.memory_guard.register_cleanup(
                            "auto_response_blocks",
                            lambda: self.auto_response.trim_blocks(500),
                        )
                    sm = getattr(self, 'service_manager', None)
                    if sm is not None:
                        self.memory_guard.register_cleanup(
                            "session_unique_ips",
                            lambda: sm.trim_unique_ips(5000),
                        )
                    self.memory_guard.start()
            except Exception as e:
                log(f"⚠️ MemoryGuard start failed: {e}")

            # Auto firewall / IP-pool limits
            try:
                if getattr(self, "cleanup_manager", None):
                    self.cleanup_manager.start_auto_enforcer()
            except Exception as e:
                log(f"⚠️ Cleanup auto-enforcer start failed: {e}")

        # Geciktirilmiş API başlangıcını başlat
        threading.Thread(target=delayed_api_start, daemon=True).start()

        # Setup persistent high-privilege operation for critical security monitoring
        try:
            if ctypes.windll.shell32.IsUserAnAdmin():
                log("🛡️ Application running with administrative privileges - Security monitoring active")
                # Task Scheduler setup handled in main startup sequence
            else:
                log("⚠️ Application running with limited privileges - Some security features may be restricted")
                log("💡 For full security monitoring capabilities, restart as Administrator")
        except Exception as e:
            log(f"Privilege detection error: {e}")

    # ---------- First-run notice ---------- #
    def _read_status_raw(self):
        try:
            if os.path.exists(STATUS_FILE):
                with open(STATUS_FILE, "r", encoding="utf-8") as f:
                    d = json.load(f)
                    return d if isinstance(d, dict) else {}
        except Exception as e:
            log(f"read status raw error: {e}")
        return {}

    def _write_status_raw(self, data: dict):
        try:
            with open(STATUS_FILE, "w", encoding="utf-8") as f:
                json.dump(data or {}, f, ensure_ascii=False)
        except Exception as e:
            log(f"write status raw error: {e}")

    # ---------- I18N ---------- #
    def t(self, key: str) -> str:
        try:
            # Ensure self.lang is a string, not dict
            lang = self.lang
            if isinstance(lang, dict):
                lang = "tr"  # Fallback if corrupted
            elif not isinstance(lang, str):
                lang = "tr"
                
            # Get language dictionary
            lang_dict = I18N.get(lang, I18N.get("tr", {}))
            if not isinstance(lang_dict, dict): lang_dict = I18N.get("tr", {})
            result = lang_dict.get(key, key)
            return result
        except Exception as e:
            log(f"Translation error for key '{key}': {e}")
            return key  # Return key itself as fallback

    # ---------- Helper Methods ---------- #
    # ---------- API Connection ---------- #
    def try_api_connection(self, show_error: bool = True) -> bool:
        """Check API connection using modular client"""
        try:
            return self.api_client.check_connection(max_attempts=1, delay=0)
        except Exception as e:
            log(f"API connection check error: {e}")
            if show_error and hasattr(self, 'root') and self.root:
                messagebox.showwarning("Uyarı", f"API bağlantı kontrolünde hata: {e}")
            return False

    # ---------- Threat Config Sync (v4.0 Faz 2) ---------- #

    def _sync_threat_config(self):
        """Fetch threat detection + silent hours config + block rules from backend."""
        try:
            token = self.state.get("token", "")
            if not token or not self.api_client:
                return
            config = self.api_client.fetch_threat_config(token)
            if config and isinstance(config, dict):
                # Fleet canary gates (C-CANARY-1…5) — process memory only.
                try:
                    from client_fleet_canary import (
                        apply_fleet_rollout,
                        mutate_config_for_gates,
                        snapshot_for_health,
                    )
                    fr = apply_fleet_rollout(config)
                    config = mutate_config_for_gates(config)
                    log(
                        "[CONFIG-SYNC] fleet_rollout "
                        f"present={fr.get('present')} "
                        f"in_canary={fr.get('in_canary')} "
                        f"gates={fr.get('gates')}"
                    )
                    self._fleet_rollout_snapshot = snapshot_for_health()
                except Exception as fre:
                    log(f"[CONFIG-SYNC] fleet_rollout apply error: {fre}")

                # Update silent hours config
                sh_cfg = config.get("silent_hours")
                if sh_cfg and self.silent_hours_guard:
                    self.silent_hours_guard.update_config(sh_cfg)

                # Logon challenge (email "This is me")
                lc_cfg = config.get("logon_challenge")
                if lc_cfg and getattr(self, "logon_challenge_guard", None):
                    self.logon_challenge_guard.update_config(lc_cfg)
                if getattr(self, "logon_challenge_guard", None):
                    try:
                        n = self.logon_challenge_guard.sync_approvals_from_api()
                        if n:
                            log(f"[CONFIG-SYNC] Logon challenge approvals: {n}")
                    except Exception:
                        pass

                # Auto-block thresholds / limits
                if self.auto_response and hasattr(self.auto_response, "apply_threat_config"):
                    self.auto_response.apply_threat_config(config)

                # Webhook (SIEM forward) — GUI Settings tab writes webhook_enabled/
                # webhook_url to the cloud threats/config, but the local sender
                # (client_alerts._send_webhook) reads notifications.* from
                # client_config.json. Bridge the cloud values into local config so
                # the toggle actually takes effect on the daemon.
                try:
                    if "webhook_enabled" in config or "webhook_url" in config:
                        if "webhook_enabled" in config:
                            set_config_value(
                                "notifications.webhook_enabled",
                                bool(config.get("webhook_enabled")),
                            )
                        if "webhook_url" in config:
                            set_config_value(
                                "notifications.webhook_url",
                                str(config.get("webhook_url") or ""),
                            )
                        log(
                            "[CONFIG-SYNC] webhook bridged from cloud "
                            f"enabled={bool(config.get('webhook_enabled'))}"
                        )
                except Exception as we:
                    log(f"[CONFIG-SYNC] webhook bridge error: {we}")

                # Whitelist IP/subnet'lerini EventLogWatcher, AutoResponse
                # ve ThreatEngine'e ilet — dashboard'dan gelen güvenli IP'ler
                wl_ips = set(config.get("whitelist_ips", []))
                wl_subnets = config.get("whitelist_subnets", [])
                if wl_ips or wl_subnets:
                    if self.event_watcher:
                        self.event_watcher.update_whitelist(wl_ips)
                    if self.auto_response:
                        self.auto_response.update_whitelist(wl_ips, wl_subnets)
                    if self.threat_engine:
                        self.threat_engine.update_whitelist(wl_ips)
                    log(f"[CONFIG-SYNC] Whitelist synced: {len(wl_ips)} IP(s), "
                        f"{len(wl_subnets)} subnet(s)")

                # Monitored event channels
                channels = config.get("monitored_event_channels")
                if channels and self.event_watcher and hasattr(
                    self.event_watcher, "update_monitored_channels"
                ):
                    self.event_watcher.update_monitored_channels(channels)

                # Ransomware / canary toggles
                if self.ransomware_shield:
                    try:
                        if "ransomware_protection_enabled" in config:
                            rs_enabled = bool(
                                config.get("ransomware_protection_enabled")
                            )
                            if rs_enabled:
                                self.ransomware_shield.start()
                            else:
                                self.ransomware_shield.stop()
                            log(f"[CONFIG-SYNC] ransomware protection={rs_enabled}")
                        if "canary_files_enabled" in config:
                            self.ransomware_shield.canary_enabled = bool(
                                config.get("canary_files_enabled")
                            )
                    except Exception:
                        pass

                # Network Guard detect/alert layer. Automatic containment,
                # killing and network restore remain hard-disabled in
                # client_network_guard.load_config; GUI/cloud can only toggle
                # monitoring and tune non-destructive detection thresholds.
                if self.network_guard:
                    try:
                        from client_network_guard import load_config as _ng_load_config
                        from client_network_guard import get_maintenance as _ng_maint
                        ng_cfg = _ng_load_config(config)
                        self.network_guard.cfg.update(ng_cfg)
                        if _ng_maint().get("active"):
                            self.network_guard.stop()
                            log("[CONFIG-SYNC] network_guard maintenance — stay paused")
                        elif ng_cfg.get("enabled", True):
                            self.network_guard.start()
                        else:
                            self.network_guard.stop()
                        log(
                            "[CONFIG-SYNC] network_guard "
                            f"enabled={bool(ng_cfg.get('enabled', True))} "
                            f"maintenance={bool(_ng_maint().get('active'))} "
                            "mode=alert_only"
                        )
                    except Exception as nge:
                        log(f"[CONFIG-SYNC] network_guard apply error: {nge}")

                if getattr(self, "system_recovery", None):
                    try:
                        self.system_recovery.start()
                    except Exception as sre:
                        log(f"[CONFIG-SYNC] system_recovery start error: {sre}")

                # Defense Policy matrix (contract 1.4.18 / client ≥4.9.16)
                try:
                    from client_defense_policy import apply_from_config as _dp_apply
                    from client_defense_policy import set_tamper_alert_callback as _dp_cb
                    _dp_cb(
                        self.alert_pipeline.handle_alert
                        if self.alert_pipeline
                        else None
                    )
                    dp_st = _dp_apply(config, token=token)
                    log(
                        "[CONFIG-SYNC] defense_policy="
                        f"{dp_st.get('policy_name')} "
                        f"ver={dp_st.get('policy_version') or '-'} "
                        f"src={dp_st.get('source')} "
                        f"sig_ok={dp_st.get('sig_ok')}"
                    )
                    # Client backup: observe window elapsed → balanced
                    try:
                        from client_defense_policy import (
                            cloud_promote_patch,
                            maybe_auto_promote,
                            promote_due_info,
                        )
                        due = promote_due_info()
                        if due.get("due"):
                            patch = cloud_promote_patch()
                            try:
                                self.api_client.update_threat_config(token, patch)
                            except Exception as pe:
                                log(f"[DEFENSE-POLICY] cloud promote POST: {pe}")
                            maybe_auto_promote()
                    except Exception as pme:
                        log(f"[DEFENSE-POLICY] auto-promote check: {pme}")
                except Exception as dpe:
                    log(f"[CONFIG-SYNC] defense_policy apply error: {dpe}")

                log("[CONFIG-SYNC] Threat config refreshed from backend")

            # Contract SoT: protection.block_rules (register + threats/config)
            applied_prot = False
            if config and isinstance(config, dict) and self.threat_engine:
                try:
                    from client_protection_store import apply_protection_payload
                    n = apply_protection_payload(
                        self.threat_engine, config, source="threats/config"
                    )
                    applied_prot = n > 0
                except Exception as pe:
                    log(f"[CONFIG-SYNC] protection.block_rules apply error: {pe}")

            # Legacy / premium rules endpoint (fallback if config omitted protection)
            if not applied_prot:
                rules = self.api_client.fetch_block_rules(token)
                if rules is not None and isinstance(rules, list) and self.threat_engine:
                    self.threat_engine.update_block_rules(rules)
                    log(f"[CONFIG-SYNC] Block rules synced: {len(rules)} rule(s) from API")
                elif self.threat_engine:
                    log("[CONFIG-SYNC] Block rules fetch empty/unavailable — keeping local defaults")
        except Exception as e:
            log(f"[CONFIG-SYNC] Error: {e}")

    def _threat_config_sync_loop(self):
        """Periodically re-fetch threat config from backend."""
        from client_constants import THREAT_CONFIG_SYNC_INTERVAL
        while getattr(self, '_running', True):
            time.sleep(THREAT_CONFIG_SYNC_INTERVAL)
            try:
                self._sync_threat_config()
            except Exception:
                pass

    def api_retry_loop(self):
        # Arkaplanda API bağlantısını sürekli dener
        retry_count = 0
        max_quick_retries = 3  # Number of quick retries before slowing down
        
        while True:
            if not self.try_api_connection(show_error=(retry_count == 0)):
                self._note_api_ok(False)
                retry_count += 1
                
                # For the first few failures, retry quickly
                if retry_count <= max_quick_retries:
                    logging.warning(f"API connection failed (attempt {retry_count}/{max_quick_retries}), retrying in 5 seconds...")
                    time.sleep(5)
                else:
                    # After max_quick_retries, slow down to avoid overwhelming the network/server
                    logging.warning(f"API connection still failing after {retry_count} attempts, will retry in 60 seconds...")
                    time.sleep(API_SLOW_RETRY_DELAY)
                continue
                
            # Reset retry count on successful connection
            if retry_count > 0:
                logging.info(f"API connection restored after {retry_count} retries")
            retry_count = 0
            self._note_api_ok(True)
            # Authenticated check (attack-count / tunnel-status)
            try:
                tok = self.state.get("token", "")
                if tok:
                    self._note_api_ok(self.api_client.check_authenticated(tok))
            except Exception:
                pass
                
            time.sleep(API_RETRY_INTERVAL)  # Check connection every minute when healthy

# ---------- IP & Heartbeat Management ---------- #
    def update_client_ip(self, new_ip: str):
        """Update client IP address via session-based API client"""
        token = self.state.get("token")
        if token:
            self.api_client.update_client_ip(token, new_ip)

    def get_intelligent_status(self) -> str:
        """Determine intelligent status based on program and service state"""
        # Program açık olduğu kesin (çünkü bu kod çalışıyor)
        active_services = self.service_manager.running_services
        
        if active_services: return "online"  # en az bir servis aktif
        # Program açık ama servis yok → idle
        return "idle"

    def _build_system_context(self) -> dict:
        """Heartbeat ile gönderilecek zengin sunucu bilgilerini toplar."""
        import platform
        ctx = {
            "agent_version": __version__,
            "os_info": f"{platform.system()} {platform.release()} (build {platform.version()})",
        }

        # Uptime
        try:
            import psutil
            boot = psutil.boot_time()
            ctx["uptime_hours"] = round((time.time() - boot) / 3600, 1)
        except Exception:
            ctx["uptime_hours"] = 0

        # Aktif honeypot servisleri + portlar
        try:
            services = []
            for svc in self.service_manager.running_services:
                port = getattr(svc, "port", None) or getattr(svc, "_port", 0)
                services.append({"name": svc.__class__.__name__.replace("Fake", "").upper(), "port": port})
            ctx["active_services"] = services
            ctx["active_service_count"] = len(services)
        except Exception:
            ctx["active_services"] = []
            ctx["active_service_count"] = 0

        # CPU / RAM özet (varsa health monitor'dan)
        try:
            if self.health_monitor:
                snap = self.health_monitor.get_snapshot()
                ctx["cpu_percent"] = snap.get("cpu_percent", 0)
                ctx["memory_percent"] = snap.get("memory_percent", 0)
        except Exception:
            pass

        # Threat Engine durumu
        try:
            if self.threat_engine:
                level, _ = self.threat_engine.get_threat_level()
                stats = self.threat_engine.get_stats()
                ctx["threat_level"] = level
                ctx["active_threat_ips"] = stats.get("active_ips", 0)
                ctx["total_alerts"] = stats.get("alerts_generated", 0)
        except Exception:
            pass

        # Ransomware Shield durumu
        try:
            if self.ransomware_shield:
                rs_stats = self.ransomware_shield.get_stats()
                ctx["ransomware_shield_status"] = "active" if self.ransomware_shield._running else "disabled"
                ctx["ransomware_detections"] = rs_stats.get("total_detections", 0)
            else:
                ctx["ransomware_shield_status"] = "disabled"
        except Exception:
            ctx["ransomware_shield_status"] = "error"

        # Defense Policy version (cloud stale-policy pull)
        try:
            from client_defense_policy import get_state as _dp_state
            dp = _dp_state()
            ctx["defense_policy"] = dp.get("policy_name")
            ctx["defense_policy_version"] = dp.get("policy_version") or ""
            ctx["isolate_armed"] = bool(dp.get("isolate_armed"))
        except Exception:
            pass

        return ctx

    def send_heartbeat_once(self, status_override: Optional[str] = None):
        """Send single heartbeat to API with intelligent status detection (session-based)"""
        token = self.state.get("token")
        if token:
            ip = self.state.get("public_ip") or ClientHelpers.get_public_ip()
            
            if status_override is None: status_override = self.get_intelligent_status()
            prev_linked = None
            try:
                from client_utils import is_account_linked
                prev_linked = is_account_linked()
            except Exception:
                pass
            system_context = self._build_system_context()
            # RES-103 candidate is default-off until its canonical wire is
            # promoted. Observe mode signs the exact heartbeat status tuple.
            try:
                from client_resilience_p1 import build_heartbeat_observe
                proof = build_heartbeat_observe(
                    token,
                    hostname=SERVER_NAME,
                    status=status_override,
                    running=bool(self.state.get("running", False)),
                )
                if proof:
                    system_context["heartbeat_proof"] = proof
            except Exception:
                pass
            ok = self.api_client.send_heartbeat(
                token, ip, SERVER_NAME,
                self.state.get("running", False), status_override,
                system_context=system_context
            )
            self._last_heartbeat_ok = ok
            self._last_heartbeat_at = time.time()
            if ok:
                self._note_api_ok(True)
                try:
                    from client_offline_queue import drain_to_cloud, offline_queue_enabled
                    if offline_queue_enabled():
                        drain_to_cloud(self.api_client, token)
                except Exception:
                    pass
            # Heartbeat may carry account_linked — refresh top-bar badge if changed
            try:
                from client_utils import is_account_linked
                if prev_linked is not None and is_account_linked() != prev_linked and self.gui:
                    self._gui_safe(
                        lambda: getattr(self.gui, "_render_account_link_controls", lambda *_a, **_k: None)(token)
                    )
            except Exception:
                pass

    def heartbeat_loop(self):
        """Heartbeat loop — reports WAN IP changes via update-ip (cache ~60s).

        Contract agent/polling.md: ~60s cadence when healthy. Errors (timeout,
        499, connection reset) must NOT kill this worker — retry with
        exponential backoff, then settle back to API_HEARTBEAT_INTERVAL.
        """
        last_ip = None
        last_gui_ip = None  # Track last GUI-updated IP to avoid redundant updates
        fail_backoff = 5.0
        fail_backoff_max = 30.0

        while True:
            ok = False
            try:
                token = self.state.get("token")
                if token:
                    # 60s cache in ClientHelpers — laptop network switches report quickly
                    ip = ClientHelpers.get_public_ip()

                    # Only update API if IP changed
                    if ip and ip != last_ip and ip != "0.0.0.0":
                        self.update_client_ip(ip)
                        last_ip = ip
                        log(f"[IP] Public IP changed → API update-ip: {ip}")

                    self.state["public_ip"] = ip

                    # GUI update only if IP actually changed (performance optimization)
                    if ip != last_gui_ip and self.gui:
                        last_gui_ip = ip
                        self._gui_safe(lambda i=ip: self._update_identity_ip(i))

                    # Akıllı heartbeat gönder (online/idle/offline)
                    self.send_heartbeat_once()
                    ok = bool(getattr(self, "_last_heartbeat_ok", False))
                    if not ok:
                        log("[HEARTBEAT] send failed — will retry with backoff (worker stays alive)")
            except Exception as e:
                log(f"heartbeat error: {e}")
                ok = False

            if ok:
                fail_backoff = 5.0
                time.sleep(API_HEARTBEAT_INTERVAL)
            else:
                # Faster recovery after 499/timeout/transport blips; never exit.
                sleep_for = min(fail_backoff, fail_backoff_max)
                time.sleep(sleep_for)
                fail_backoff = min(fail_backoff_max, fail_backoff * 2.0)

    # ---------- Attack Count ---------- #
    def fetch_attack_count_sync(self, token):
        """Honeypot sunucusundan toplam saldırı sayısını sorgular - now uses modular API client"""
        try:
            return self.api_client.get_attack_count(token)
        except Exception as e:
            log(f"[API] Saldırı sayısı sorgulama hatası: {e}")
            return None

    def check_gui_health(self):
        """Periodic GUI health check — tray icon sync, tray thread revive & session monitoring"""
        if not self.root: return
        try:
            self.root.winfo_exists()
            self.gui_health['update_count'] += 1
            
            # Tray must stay alive while user session GUI process is up
            if hasattr(self, 'tray_manager') and self.tray_manager:
                try:
                    self.tray_manager.ensure_tray_alive()
                except Exception as e:
                    log(f"[GUI_HEALTH] tray ensure failed: {e}")

            # Tray icon update — only if service state changed
            if hasattr(self, 'tray_manager'):
                current_state = len(self.service_manager.running_services) > 0
                if not hasattr(self, '_last_tray_state') or current_state != self._last_tray_state:
                    self._last_tray_state = current_state
                    self.update_tray_icon()
            
            # Windows Server session check — every 5th cycle (~5 min), off UI thread
            if self.gui_health['update_count'] % 5 == 0:
                threading.Thread(
                    target=self.check_windows_session_state,
                    daemon=True,
                    name="SessionCheck",
                ).start()
            
            if self.gui_health['update_count'] > 1000: self.gui_health['update_count'] = 0
                
        except Exception as e:
            log(f"[GUI_HEALTH] Sağlık kontrolü hatası: {e}")
            
        # Schedule next check
        try:
            if self.root and self.root.winfo_exists():
                self.root.after(self.gui_health['health_check_interval'] * 1000, self.check_gui_health)
        except Exception:
            pass

    def check_windows_session_state(self):
        """Windows session durumunu kontrol et"""
        try:
            import subprocess
            
            # Session durumunu kontrol et
            result = subprocess.run(['query', 'session'], 
                                  capture_output=True, text=True, timeout=5,
                                  creationflags=subprocess.CREATE_NO_WINDOW)
            
            if result.returncode == 0:
                from client_helpers import has_interactive_user_session
                has_active_session = has_interactive_user_session(result.stdout)
                
                if not has_active_session:
                    log("[GUI_HEALTH] Aktif kullanıcı session'ı yok (headless/RDP disconnect olabilir)")
                    # Otomatik withdraw kaldırıldı — tray'den Göster sonrası pencere tekrar gizlenmesin
                        
        except Exception as e:
            log(f"[GUI_HEALTH] Session kontrolü hatası: {e}")

    def _update_identity_ip(self, ip: str):
        """Identity bar IP label'ını güncelle (thread-safe çağrı için)."""
        try:
            if self.gui and hasattr(self.gui, '_identity_ip_lbl'):
                self.gui._identity_ip_lbl.configure(text=f"({ip})")
        except Exception:
            pass

    def refresh_attack_count(self, async_thread=True):
        """Dashboard kartındaki saldırı sayacını günceller"""
        token = self.state.get("token")
        if not token: return
        if not self.root: return

        def worker():
            try:
                ok = self.api_client.check_authenticated(token)
                self._note_api_ok(ok)
                if not ok:
                    return
                cnt = self.fetch_attack_count_sync(token)
                if cnt is not None:
                    if hasattr(self, '_last_attack_count') and self._last_attack_count == cnt:
                        return
                    self._last_attack_count = cnt
            except Exception:
                self._note_api_ok(False)
                
        if async_thread:
            # PERFORMANCE: Reuse existing thread if already running
            if not hasattr(self, '_attack_count_thread') or not self._attack_count_thread.is_alive():
                self._attack_count_thread = threading.Thread(target=worker, daemon=True, name="AttackCountUpdater")
                self._attack_count_thread.start()
        else:
            worker()

    def poll_attack_count(self):
        """Poll attack count with single-chain scheduling guard"""
        if hasattr(self, '_poll_chain_active') and self._poll_chain_active: return
        self._poll_chain_active = True
        
        self.refresh_attack_count(async_thread=True)
        try:
            if self.root and self.root.winfo_exists():
                self.root.after(ATTACK_COUNT_REFRESH * 1000, self._poll_attack_count_chain)
        except Exception as e:
            self._poll_chain_active = False
            log(f"poll_attack_count scheduling failed: {e}")
    
    def _poll_attack_count_chain(self):
        """Internal polling chain — only runs from a single root.after chain"""
        self.refresh_attack_count(async_thread=True)
        try:
            if self.root and self.root.winfo_exists():
                self.root.after(ATTACK_COUNT_REFRESH * 1000, self._poll_attack_count_chain)
            else:
                self._poll_chain_active = False
        except Exception:
            self._poll_chain_active = False

    # ---------- Single Instance / Daemon IPC Control ---------- #
    def _ipc_status_payload(self) -> dict:
        """Machine status for GUI frontends (JSON over control socket)."""
        try:
            from client_constants import VERSION
            ver = VERSION
        except Exception:
            ver = ""
        running = []
        try:
            running = list(self.service_manager.running_services or [])
        except Exception:
            running = []
        mode = "inactive"
        try:
            mode = self.get_protection_mode()
        except Exception:
            pass
        is_motor = bool(getattr(self, "_is_daemon_motor", False))
        rc = getattr(self, "remote_commands", None)
        rc_running = bool(rc and getattr(rc, "_running", False))
        frontend_only = bool(getattr(self, "frontend_only", False))
        if is_motor:
            role = "daemon"
        elif frontend_only:
            role = "frontend"
        else:
            role = "legacy"
        return {
            "ok": True,
            # CRITICAL: only Session-0 motor reports daemon=true (GUI must not impersonate)
            "daemon": is_motor,
            "role": role,
            "version": ver,
            "pid": os.getpid(),
            "running_services": running,
            "protection_mode": mode,
            "token_present": bool(self.state.get("token")),
            "frontend_only": frontend_only,
            "remote_commands_running": rc_running,
            "motor_ok": bool(is_motor and rc_running),
            "status_generation": int(getattr(self, "_status_generation", 0) or 0),
            "rs_quarantine": self._ipc_rs_quarantine_summary(),
            "persistence": self._ipc_persistence_summary(),
            "network_guard": self._ipc_network_guard_summary(),
            "system_recovery": self._ipc_system_recovery_summary(),
            "ransomware_running": self._ipc_rs_running(),
            "resilience": self._ipc_resilience_summary(),
            "resources": self._ipc_resources_summary(),
            "defense_policy": self._ipc_defense_policy_summary(),
            "api": self._ipc_api_health_summary(),
            "commands_recent": self._ipc_commands_recent(limit=5),
            "public_ip": str(self.state.get("public_ip") or "") or None,
        }

    def _bump_status_generation(self) -> None:
        """Bump so GUI STATUS poll can refresh immediately after remote apply."""
        try:
            self._status_generation = int(getattr(self, "_status_generation", 0) or 0) + 1
        except Exception:
            self._status_generation = 1

    def _ipc_rs_running(self) -> bool:
        rs = getattr(self, "ransomware_shield", None)
        if rs is None:
            return False
        try:
            return bool(rs.get_stats().get("running"))
        except Exception:
            return False

    def _ipc_defense_policy_summary(self) -> dict:
        try:
            from client_defense_policy import status_summary
            return status_summary()
        except Exception:
            return {"present": False}

    def _ipc_network_guard_summary(self) -> dict:
        ng = getattr(self, "network_guard", None)
        if ng is None:
            return {"present": False}
        try:
            st = ng.status() or {}
            st["present"] = True
            st["running"] = bool(getattr(ng, "_running", False))
            return st
        except Exception:
            return {"present": True}

    def _ipc_system_recovery_summary(self) -> dict:
        sr = getattr(self, "system_recovery", None)
        if sr is None:
            return {"present": False}
        try:
            return sr.status()
        except Exception:
            return {"present": True, "enabled": True}

    def _ipc_persistence_summary(self) -> dict:
        try:
            from client_tamper import get_persistence_status
            # We are already inside the daemon STATUS socket. Never probe that
            # same socket recursively; the server is single-threaded.
            is_motor = bool(getattr(self, "_is_daemon_motor", False))
            rc = getattr(self, "remote_commands", None)
            daemon_ok = bool(is_motor and rc and getattr(rc, "_running", False))
            return get_persistence_status(daemon_ok_override=daemon_ok)
        except Exception:
            return {}

    def _ipc_resilience_summary(self) -> dict:
        try:
            persistence = self._ipc_persistence_summary()
            nested = persistence.get("resilience")
            if isinstance(nested, dict) and nested:
                return nested
            from client_resilience import snapshot
            return snapshot(
                guardian_installed=persistence.get("service_installed"),
                guardian_running=persistence.get("service_ok"),
            )
        except Exception:
            return {}

    def _ipc_resources_summary(self) -> dict:
        """Compact host + motor process usage for GUI corner badge (no lists)."""
        try:
            from client_resources import collect_resources
            return collect_resources(getattr(self, "health_monitor", None))
        except Exception:
            return {}

    def _note_api_ok(self, ok: bool) -> None:
        """Track last API contact for GUI live meters."""
        self._last_api_ok = bool(ok)
        self._last_api_check_at = time.time()
        if ok:
            self._last_api_ok_at = self._last_api_check_at

    def _ipc_api_health_summary(self) -> dict:
        hb = getattr(self, "_last_heartbeat_ok", None)
        return {
            "ok": bool(getattr(self, "_last_api_ok", False)),
            "heartbeat_ok": None if hb is None else bool(hb),
            "last_ok_at": getattr(self, "_last_api_ok_at", None),
            "last_check_at": getattr(self, "_last_api_check_at", None),
            "last_heartbeat_at": getattr(self, "_last_heartbeat_at", None),
        }

    def _ipc_commands_recent(self, limit: int = 5) -> list:
        rc = getattr(self, "remote_commands", None)
        if rc is None or not hasattr(rc, "get_history"):
            return []
        try:
            hist = list(rc.get_history() or [])
        except Exception:
            return []
        rows = []
        for item in reversed(hist[-max(1, int(limit)):]):
            if not isinstance(item, dict):
                continue
            result = item.get("result") if isinstance(item.get("result"), dict) else {}
            rows.append({
                "command_type": str(item.get("command_type") or ""),
                "command_id": str(item.get("command_id") or ""),
                "ok": bool(result.get("success")),
                "executed_at": item.get("executed_at"),
                "source": str(item.get("source") or ""),
                "message": str(result.get("message") or result.get("error") or "")[:120],
            })
        return rows

    @staticmethod
    def _ipc_ip_reason(ctx) -> str:
        """Short human summary: attack counts + recent event types / services."""
        parts = []
        try:
            fails = int(getattr(ctx, "failed_attempts", 0) or 0)
            ok_logins = int(getattr(ctx, "successful_logins", 0) or 0)
            if fails:
                parts.append(f"failed×{fails}")
            if ok_logins:
                parts.append(f"success×{ok_logins}")
            events = list(getattr(ctx, "events", []) or [])
            seen_types = []
            for ev in events[-12:]:
                et = str((ev or {}).get("event_type") or "").strip()
                if et and et not in seen_types:
                    seen_types.append(et)
            if seen_types:
                parts.append(", ".join(seen_types[:3]))
            services = list(getattr(ctx, "services_targeted", []) or [])
            if services:
                parts.append("/".join(str(s) for s in services[:2]))
        except Exception:
            pass
        return " · ".join(parts) if parts else "—"

    def _ipc_ip_table_payload(self, limit: int = 40) -> dict:
        """Watching / blocked / whitelist rows for GUI (frontend has no engine)."""
        te = getattr(self, "threat_engine", None)
        auto_response = getattr(self, "auto_response", None)
        contexts = {}
        blocked_ips: set = set()
        whitelist_ips: set = set()
        store_meta: dict = {}

        if te:
            try:
                contexts = te.get_all_contexts() or {}
            except Exception:
                contexts = {}
            try:
                blocked_ips = set(getattr(te, "_rule_blocked_ips", set()) or set())
            except Exception:
                blocked_ips = set()
            try:
                whitelist_ips = set(getattr(te, "_whitelist_ips", set()) or set())
            except Exception:
                whitelist_ips = set()

        try:
            from client_block_store import refresh_from_live_firewall, load_blocked_map

            store_meta = refresh_from_live_firewall(min_interval_sec=20.0, force=False) or {}
            if not store_meta:
                store_meta = load_blocked_map(force=True) or {}
            blocked_ips |= set(store_meta.keys())
        except Exception:
            try:
                from client_block_store import load_blocked_map

                store_meta = load_blocked_map(force=True) or {}
                blocked_ips |= set(store_meta.keys())
            except Exception:
                store_meta = {}

        ar_blocked: set = set()
        if auto_response:
            try:
                ar_blocked = set(getattr(auto_response, "_blocks", {}).keys())
            except Exception:
                ar_blocked = set()
            try:
                whitelist_ips |= set(getattr(auto_response, "whitelist_ips", set()) or set())
            except Exception:
                pass

        ew = getattr(self, "event_watcher", None)
        if ew and hasattr(ew, "whitelist_ips"):
            try:
                whitelist_ips |= set(ew.whitelist_ips or set())
            except Exception:
                pass

        skip = {"local", "", "127.0.0.1", "::1"}
        watching, blocked, whitelist = [], [], []
        seen: set = set()
        lim = max(1, int(limit))

        for ip, ctx in (contexts or {}).items():
            if ip in skip:
                continue
            try:
                score = int(getattr(ctx, "threat_score", 0) or 0)
                attempts = int(getattr(ctx, "failed_attempts", 0) or 0)
            except Exception:
                score, attempts = 0, 0
            if score < 1 and attempts < 1:
                if ip not in blocked_ips and ip not in ar_blocked and ip not in whitelist_ips:
                    continue
            services = list(getattr(ctx, "services_targeted", []) or [])
            if ip in whitelist_ips:
                status = "whitelisted"
            elif ip in blocked_ips or ip in ar_blocked or bool(getattr(ctx, "is_blocked", False)):
                status = "blocked"
            else:
                status = "watching"
            row = {
                "ip": ip,
                "services": services[:4],
                "attempts": attempts,
                "score": score,
                "last_seen": float(getattr(ctx, "last_seen", 0) or 0),
                "reason": self._ipc_ip_reason(ctx),
                "status": status,
            }
            if status == "watching":
                watching.append(row)
            elif status == "blocked":
                blocked.append(row)
            else:
                whitelist.append(row)
            seen.add(ip)

        for ip in (blocked_ips | ar_blocked):
            if ip in skip or ip in seen or ip in whitelist_ips:
                continue
            meta = store_meta.get(ip) or {}
            reason = str(meta.get("reason") or meta.get("source") or "firewall")
            blocked.append({
                "ip": ip,
                "services": [],
                "attempts": 0,
                "score": 0,
                "last_seen": float(meta.get("blocked_at") or 0),
                "reason": reason,
                "status": "blocked",
            })
            seen.add(ip)

        for ip in whitelist_ips:
            if ip in skip or ip in seen:
                continue
            whitelist.append({
                "ip": ip,
                "services": [],
                "attempts": 0,
                "score": 0,
                "last_seen": 0,
                "reason": "whitelist",
                "status": "whitelisted",
            })
            seen.add(ip)

        watching.sort(key=lambda r: (r.get("score") or 0, r.get("attempts") or 0), reverse=True)
        blocked.sort(key=lambda r: float(r.get("last_seen") or 0), reverse=True)
        return {
            "ok": True,
            "engine": te is not None,
            "watching": watching[:lim],
            "blocked": blocked[:lim],
            "whitelist": whitelist[:lim],
            "totals": {
                "watching": len(watching),
                "blocked": len(blocked),
                "whitelist": len(whitelist),
            },
        }

    def _ipc_threat_top_payload(self, limit: int = 25) -> dict:
        """Top attacker contexts for GUI frontends that hold no local engine."""
        te = getattr(self, "threat_engine", None)
        if te is None:
            return {"ok": True, "attackers": [], "recent_alerts": [], "total": 0, "engine": False}
        try:
            contexts = te.get_all_contexts() or {}
        except Exception:
            contexts = {}
        try:
            blocked = set(getattr(te, "_rule_blocked_ips", set()) or set())
        except Exception:
            blocked = set()
        rows = []
        for ip, ctx in contexts.items():
            if ip in ("local", "", "127.0.0.1", "::1"):
                continue
            if ctx.failed_attempts <= 0 and ctx.threat_score <= 0:
                continue
            try:
                summary = te.summarize_ip_context(ctx)
            except Exception:
                summary = {}
            rows.append({
                "ip": ip,
                "services": list(ctx.services_targeted or []),
                "failed_attempts": int(ctx.failed_attempts),
                "successful_logins": int(getattr(ctx, "successful_logins", 0) or 0),
                "threat_score": int(ctx.threat_score),
                "score": int(ctx.threat_score),
                "events": int(ctx.failed_attempts),
                "event_count": int(ctx.failed_attempts),
                "last_seen": float(ctx.last_seen or 0),
                "is_blocked": bool(ctx.is_blocked or ip in blocked),
                "usernames": list(summary.get("usernames") or [])[:8],
                "username": (list(summary.get("usernames") or []) or [""])[0],
                "title": summary.get("title") or "",
                "description": summary.get("description") or "",
                "threat_type": summary.get("threat_type") or "",
                "last_event_type": summary.get("last_event_type") or "",
                "recommended_action": "",
            })
        rows.sort(
            key=lambda r: (int(r.get("threat_score") or 0), int(r.get("failed_attempts") or 0)),
            reverse=True,
        )
        try:
            recent = te.get_recent_alerts(limit=max(10, int(limit)))
        except Exception:
            recent = []
        # Prefer newest alert prose onto matching IP rows when present.
        by_ip = {}
        for alert in recent:
            sip = str(alert.get("source_ip") or "")
            if sip and sip not in by_ip:
                by_ip[sip] = alert
        for row in rows:
            alert = by_ip.get(str(row.get("ip") or ""))
            if not alert:
                continue
            if alert.get("title"):
                row["title"] = alert.get("title")
            if alert.get("description"):
                row["description"] = alert.get("description")
            if alert.get("threat_type"):
                row["threat_type"] = alert.get("threat_type")
            if alert.get("recommended_action"):
                row["recommended_action"] = alert.get("recommended_action")
            if alert.get("username") and not row.get("username"):
                row["username"] = alert.get("username")
            row["severity"] = alert.get("severity") or row.get("severity")
        return {
            "ok": True,
            "engine": True,
            "attackers": rows[: max(1, int(limit))],
            "recent_alerts": recent[: max(1, int(limit))],
            "total": len(rows),
        }

    def _ipc_rs_quarantine_summary(self) -> dict:
        rs = getattr(self, "ransomware_shield", None)
        if rs is None:
            return {"active": False, "entries": 0}
        try:
            st = rs.get_stats()
            return {
                "active": bool(st.get("quarantine_active")),
                "entries": int(st.get("quarantine_entries") or 0),
                "trigger": st.get("quarantine_trigger") or "",
                "locked_at": st.get("quarantine_locked_at") or "",
                "canary_files": int(st.get("canary_files") or 0),
                "alerts_total": int(st.get("alerts_total") or 0),
            }
        except Exception:
            return {"active": False, "entries": 0}

    def control_server_loop(self, sock):
        """Handle control server connections — SHOW/QUIT + daemon IPC."""
        MAX_CMD_LEN = 256
        while True:
            conn = None
            try:
                conn, _ = sock.accept()
                conn.settimeout(2.0)

                buf = conn.recv(MAX_CMD_LEN)
                if not buf:
                    continue

                line = buf.split(b"\n", 1)[0]
                cmd = line.decode("utf-8", "ignore").strip()
                cmd_u = cmd.upper()

                def _send(data: str):
                    try:
                        if not data.endswith("\n"):
                            data += "\n"
                        conn.sendall(data.encode("utf-8"))
                    except Exception:
                        pass

                if cmd_u == "PING":
                    _send("PONG")
                    continue

                if cmd_u == "STATUS":
                    try:
                        _send(json.dumps(self._ipc_status_payload(), ensure_ascii=False))
                    except Exception as e:
                        _send(json.dumps({"ok": False, "error": str(e)}))
                    continue

                if cmd_u == "ACL_HEAL":
                    # Unelevated GUI → SYSTEM motor restores Users RX on _internal
                    try:
                        from client_install_acl import ensure_motor_runtime_user_rx
                        ok = bool(ensure_motor_runtime_user_rx(log=log))
                        _send(json.dumps({"ok": ok}, ensure_ascii=False))
                    except Exception as e:
                        log(f"[CTRL] ACL_HEAL error: {e}")
                        _send(json.dumps({"ok": False, "error": str(e)}, ensure_ascii=False))
                    continue

                if cmd_u == "CLEAR_FIREWALL":
                    # GUI (unelevated) → SYSTEM motor purges HP-BLOCK-* + API sync
                    try:
                        cm = getattr(self, "cleanup_manager", None)
                        if cm is None:
                            _send(json.dumps({
                                "ok": False,
                                "error": "no_cleanup_manager",
                            }, ensure_ascii=False))
                            continue
                        out = cm.clear_firewall(sync_dashboard=True)
                        payload = {"ok": True}
                        if isinstance(out, dict):
                            payload.update(out)
                        if out.get("error"):
                            payload["ok"] = False
                        _send(json.dumps(payload, ensure_ascii=False))
                    except Exception as e:
                        log(f"[CTRL] CLEAR_FIREWALL error: {e}")
                        _send(json.dumps({"ok": False, "error": str(e)}, ensure_ascii=False))
                    continue

                if cmd_u in ("NG_MAINT_START", "NG_MAINT_END", "NG_MAINT_END_SNAPSHOT",
                             "NG_SNAPSHOT", "NG_ACCEPT_SURFACE"):
                    try:
                        ng = getattr(self, "network_guard", None)
                        if ng is None:
                            _send(json.dumps({
                                "ok": False, "error": "no_network_guard",
                            }, ensure_ascii=False))
                            continue
                        if cmd_u == "NG_MAINT_START":
                            out = ng.enter_maintenance(
                                reason="gui_maintenance", paused_by="gui",
                            )
                        elif cmd_u == "NG_MAINT_END_SNAPSHOT":
                            out = ng.exit_maintenance(
                                snapshot=True, paused_by="gui",
                            )
                        elif cmd_u == "NG_MAINT_END":
                            out = ng.exit_maintenance(
                                snapshot=False, paused_by="gui",
                            )
                        elif cmd_u == "NG_ACCEPT_SURFACE":
                            out = ng.accept_surface()
                        else:
                            saved = ng.snapshot_now()
                            out = {
                                "ok": True,
                                "version": saved.get("version"),
                                "captured_at": saved.get("captured_at"),
                            }
                        if "ok" not in out:
                            out = {"ok": True, **out}
                        _send(json.dumps(out, ensure_ascii=False))
                    except Exception as e:
                        log(f"[CTRL] NG_MAINT error: {e}")
                        _send(json.dumps({"ok": False, "error": str(e)}, ensure_ascii=False))
                    continue

                if cmd_u.startswith("BLOCK_IP ") or cmd_u.startswith("UNBLOCK_IP "):
                    try:
                        parts = cmd.split()
                        op = parts[0].upper()
                        ip = parts[1] if len(parts) > 1 else ""
                        reason = parts[2] if len(parts) > 2 else "gui_ipc"
                        ar = getattr(self, "auto_response", None)
                        if not ip:
                            _send(json.dumps({"ok": False, "error": "missing_ip"}))
                            continue
                        if ar is None:
                            _send(json.dumps({"ok": False, "error": "no_auto_response"}))
                            continue
                        if op == "BLOCK_IP":
                            ok = bool(ar.block_ip(ip, reason=reason or "gui_ipc"))
                        else:
                            ok = bool(ar.unblock_ip(ip))
                        _send(json.dumps({"ok": ok, "ip": ip, "op": op.lower()}, ensure_ascii=False))
                    except Exception as e:
                        log(f"[CTRL] BLOCK/UNBLOCK error: {e}")
                        _send(json.dumps({"ok": False, "error": str(e)}, ensure_ascii=False))
                    continue

                if cmd_u in ("RS_UNLOCK", "UNLOCK_RS_QUARANTINE"):
                    try:
                        rs = getattr(self, "ransomware_shield", None)
                        if rs is None:
                            _send(json.dumps({"ok": False, "error": "no_ransomware_shield"}))
                            continue
                        out = rs.unlock_quarantine(reason="gui_ipc")
                        _send(json.dumps({"ok": True, **out}, ensure_ascii=False))
                    except Exception as e:
                        log(f"[CTRL] RS_UNLOCK error: {e}")
                        _send(json.dumps({"ok": False, "error": str(e)}, ensure_ascii=False))
                    continue

                if cmd_u == "THREAT_TOP":
                    try:
                        _send(json.dumps(self._ipc_threat_top_payload(), ensure_ascii=False))
                    except Exception as e:
                        log(f"[CTRL] THREAT_TOP error: {e}")
                        _send(json.dumps({"ok": False, "error": str(e)}, ensure_ascii=False))
                    continue

                if cmd_u == "SELF_UPDATE":
                    # GUI "Check for updates" → silent install (same path as dashboard).
                    try:
                        if getattr(self, "_gui_self_update_running", False):
                            _send(json.dumps({
                                "ok": True,
                                "started": False,
                                "busy": True,
                                "error": "update_busy",
                            }, ensure_ascii=False))
                            continue
                        self._gui_self_update_running = True

                        def _gui_self_update_worker():
                            try:
                                from client_updater import run_self_update_command
                                api = getattr(self, "api_client", None)
                                result = run_self_update_command(
                                    {
                                        "force": False,
                                        "triggered_by": "gui_check_updates",
                                    },
                                    api_client=api,
                                ) or {}
                                log(
                                    f"[CTRL] SELF_UPDATE done ok={result.get('ok')} "
                                    f"err={result.get('error')} restart={result.get('restart_required')}"
                                )
                                if result.get("restart_required"):
                                    time.sleep(1.2)
                                    try:
                                        from client_self_protection import disarm_for_update
                                        disarm_for_update(reason="gui_self_update")
                                    except Exception:
                                        pass
                                    os._exit(0)
                            except Exception as exc:
                                log(f"[CTRL] SELF_UPDATE worker error: {exc}")
                                try:
                                    from client_update_ui import set_update_ui_status
                                    from client_constants import VERSION as _ver
                                    set_update_ui_status(
                                        "failed",
                                        from_version=str(_ver),
                                        detail=str(exc),
                                        error=str(exc),
                                    )
                                except Exception:
                                    pass
                            finally:
                                try:
                                    self._gui_self_update_running = False
                                except Exception:
                                    pass

                        import threading
                        threading.Thread(
                            target=_gui_self_update_worker,
                            name="gui-self-update",
                            daemon=True,
                        ).start()
                        try:
                            from client_update_ui import set_update_ui_status
                            from client_constants import VERSION as _cur
                            set_update_ui_status(
                                "accepted",
                                from_version=str(_cur),
                                detail="gui_check_updates",
                            )
                        except Exception:
                            pass
                        _send(json.dumps({
                            "ok": True,
                            "started": True,
                            "message": "update_accepted",
                        }, ensure_ascii=False))
                    except Exception as e:
                        log(f"[CTRL] SELF_UPDATE error: {e}")
                        try:
                            self._gui_self_update_running = False
                        except Exception:
                            pass
                        _send(json.dumps({"ok": False, "error": str(e), "started": False}, ensure_ascii=False))
                    continue

                if cmd_u == "IP_TABLE":
                    try:
                        _send(json.dumps(self._ipc_ip_table_payload(), ensure_ascii=False))
                    except Exception as e:
                        log(f"[CTRL] IP_TABLE error: {e}")
                        _send(json.dumps({"ok": False, "error": str(e)}, ensure_ascii=False))
                    continue

                if cmd_u == "SHARES_LIST":
                    try:
                        from client_threat_local import list_smb_shares
                        _send(json.dumps(list_smb_shares(), ensure_ascii=False))
                    except Exception as e:
                        log(f"[CTRL] SHARES_LIST error: {e}")
                        _send(json.dumps({"ok": False, "error": str(e), "shares": []}, ensure_ascii=False))
                    continue

                if cmd_u.startswith("SHARE_REMOVE "):
                    try:
                        from client_threat_local import remove_smb_share
                        share = cmd.split(None, 1)[1].strip() if " " in cmd else ""
                        _send(json.dumps(remove_smb_share(share), ensure_ascii=False))
                    except Exception as e:
                        log(f"[CTRL] SHARE_REMOVE error: {e}")
                        _send(json.dumps({"ok": False, "error": str(e)}, ensure_ascii=False))
                    continue

                if cmd_u == "SVC_LIST":
                    try:
                        from client_threat_local import list_third_party_services
                        _send(json.dumps(list_third_party_services(), ensure_ascii=False))
                    except Exception as e:
                        log(f"[CTRL] SVC_LIST error: {e}")
                        _send(json.dumps({"ok": False, "error": str(e), "services": []}, ensure_ascii=False))
                    continue

                if cmd_u.startswith("SVC_STOP "):
                    try:
                        from client_threat_local import stop_windows_service
                        svc = cmd.split(None, 1)[1].strip() if " " in cmd else ""
                        _send(json.dumps(stop_windows_service(svc), ensure_ascii=False))
                    except Exception as e:
                        log(f"[CTRL] SVC_STOP error: {e}")
                        _send(json.dumps({"ok": False, "error": str(e)}, ensure_ascii=False))
                    continue

                if cmd_u in ("RS_STATUS", "RS_QUARANTINE"):
                    try:
                        rs = getattr(self, "ransomware_shield", None)
                        if rs is None:
                            _send(json.dumps({"ok": False, "error": "no_ransomware_shield"}))
                            continue
                        _send(json.dumps({
                            "ok": True,
                            "stats": rs.get_stats(),
                            "quarantine": rs.get_quarantine(),
                            "detections": rs.get_detections()[-20:],
                        }, ensure_ascii=False))
                    except Exception as e:
                        log(f"[CTRL] RS_STATUS error: {e}")
                        _send(json.dumps({"ok": False, "error": str(e)}, ensure_ascii=False))
                    continue

                if cmd_u.startswith("HONEYPOT "):
                    # HONEYPOT START SVC PORT | HONEYPOT STOP SVC | HONEYPOT LIST
                    try:
                        parts = cmd.split()
                        op = (parts[1] if len(parts) > 1 else "").upper()
                        if op == "LIST":
                            _send(json.dumps({
                                "ok": True,
                                "services": list(self.service_manager.running_services or []),
                            }, ensure_ascii=False))
                        elif op == "START" and len(parts) >= 4:
                            svc = parts[2].upper()
                            port = int(parts[3])
                            ok = bool(self.service_manager.start_service(svc, port))
                            if ok:
                                try:
                                    self._on_service_started(svc, port)
                                except Exception:
                                    pass
                            _send(json.dumps({"ok": ok, "service": svc, "port": port}, ensure_ascii=False))
                        elif op == "STOP" and len(parts) >= 3:
                            svc = parts[2].upper()
                            ok = False
                            try:
                                if hasattr(self.service_manager, "stop_service"):
                                    ok = bool(self.service_manager.stop_service(svc))
                                else:
                                    # fallback: shutdown matching honeypot
                                    hp = getattr(self.service_manager, "_honeypots", {}).get(svc)
                                    if hp:
                                        hp.stop()
                                        ok = True
                            except Exception as e:
                                _send(json.dumps({"ok": False, "error": str(e)}))
                                continue
                            if ok:
                                try:
                                    self.write_status(self._active_rows_from_services(), running=True)
                                except Exception:
                                    pass
                            _send(json.dumps({"ok": ok, "service": svc}, ensure_ascii=False))
                        else:
                            _send(json.dumps({"ok": False, "error": "bad_honeypot_cmd"}))
                    except Exception as e:
                        _send(json.dumps({"ok": False, "error": str(e)}))
                    continue

                if cmd_u == "SHOW":
                    if is_session_zero() or getattr(self, "_is_daemon_motor", False):
                        log("[CTRL] SHOW received on daemon/Session0 — NOGUI")
                        _send("NOGUI")
                        continue
                    has_gui = bool(
                        self.show_cb
                        and getattr(self, "root", None) is not None
                    )
                    if has_gui:
                        try:
                            if not self.root.winfo_exists():
                                has_gui = False
                        except Exception:
                            has_gui = False
                    if has_gui:
                        log("[CTRL] SHOW received — bringing GUI to front")
                        self._gui_safe(self.show_cb)
                        _send("OK")
                    else:
                        log("[CTRL] SHOW received — no GUI window (NOGUI)")
                        _send("NOGUI")
                    continue

                if cmd_u in ("QUIT", "EXIT", "STOP", "SHUTDOWN"):
                    updating = False
                    try:
                        from client_utils import is_update_in_progress
                        updating = bool(is_update_in_progress())
                    except Exception:
                        updating = False

                    protect_until = float(getattr(self, "_quit_protect_until", 0) or 0)
                    if (not updating) and time.time() < protect_until:
                        log("[CTRL] QUIT ignored — GUI startup grace active")
                        _send("BUSY")
                        continue

                    # Motor (≥4.6.0): honour QUIT only with update-lock or signed PIN stop
                    if getattr(self, "_is_daemon_motor", False) and not updating:
                        try:
                            from client_operator_stop import is_operator_stop_active
                            allowed = is_operator_stop_active()
                        except Exception:
                            allowed = False
                        if not allowed:
                            log("[CTRL] QUIT rejected — no operator_stop token (tamper)")
                            try:
                                from client_tamper import report_tamper
                                report_tamper(
                                    reason="terminate_attempt",
                                    leg="daemon",
                                    resurrected=False,
                                    resurrect_ms=0,
                                )
                            except Exception:
                                pass
                            _send("DENIED")
                            continue

                    self._quit_protect_until = 0.0
                    try:
                        from client_self_protection import disarm_for_update
                        disarm_for_update(reason="ctrl_quit")
                    except Exception:
                        pass

                    log("[CTRL] QUIT received — graceful exit for install/update")
                    try:
                        from client_lifecycle import report_now
                        report_now(
                            "gui_quit",
                            "control_socket_quit",
                            {"cmd": cmd_u, "daemon": bool(getattr(self, "_is_daemon_motor", False))},
                            severity="warning",
                            log_func=log,
                        )
                    except Exception:
                        pass
                    try:
                        from client_utils import write_watchdog_token
                        write_watchdog_token("stop", WATCHDOG_TOKEN_FILE)
                    except Exception:
                        pass
                    _send("OK")
                    threading.Thread(
                        target=lambda: (time.sleep(0.2), self.graceful_exit(0)),
                        daemon=True,
                    ).start()
                    continue

            except Exception as e:
                msg = str(e)
                if "10038" not in msg and "10004" not in msg:
                    log(f"Control server loop error: {e}")
                time.sleep(0.05)
            finally:
                if conn is not None:
                    try:
                        conn.close()
                    except Exception:
                        pass

    def start_single_instance_server(self):
        """Bind control socket — ONLY Session-0 daemon motor. GUI never binds."""
        if not getattr(self, "_is_daemon_motor", False):
            # Frontend / tray must never own :58632 (fake PING broke command poll)
            try:
                from client_daemon_ipc import is_motor_healthy, ping
                if is_motor_healthy(timeout=0.5):
                    self.frontend_only = True
                    self.daemon_is_active = True
                    log("[IPC] Motor healthy — frontend skips control bind")
                    return
                if ping(timeout=0.4):
                    log(
                        "[IPC] Stale PING without motor_ok — not binding; "
                        "Background daemon will own commands/pending"
                    )
                else:
                    log("[IPC] No control listener — frontend will not bind (daemon owns port)")
            except Exception as e:
                log(f"[IPC] frontend bind skip: {e}")
            self.frontend_only = True
            return

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        except Exception:
            pass
        try:
            s.bind((CONTROL_HOST, CONTROL_PORT))
        except OSError:
            log(
                "[IPC] ERROR: Daemon cannot bind control port — another listener? "
                "Motor continues (commands/pending still run)"
            )
            return

        s.listen(8)
        self.state["ctrl_sock"] = s
        log(f"[IPC] Control server listening on {CONTROL_HOST}:{CONTROL_PORT}")
        threading.Thread(target=self.control_server_loop, args=(s,), daemon=True).start()

    # ---------- Watchdog & Persistence ---------- #

    def write_status(self, active_rows, running: bool = True):
        """Write current status to persistent storage"""
        self.state["selected_rows"] = [(str(a[0]), str(a[1])) for a in active_rows]
        data = self._read_status_raw()
        data.update({"active_ports": self.state["selected_rows"], "running": running, "fresh_install": False})
        self._write_status_raw(data)

    def read_status(self):
        """Read status from persistent storage (machine-wide, legacy fallback)."""
        path = STATUS_FILE
        try:
            from client_constants import STATUS_FILE_LEGACY
            if not os.path.exists(path) and os.path.exists(STATUS_FILE_LEGACY):
                path = STATUS_FILE_LEGACY
        except Exception:
            pass
        if not os.path.exists(path):
            self.write_status([], running=False)
            return [], False
        try:
            data = json.load(open(path, "r", encoding="utf-8"))
            if data.get("fresh_install", False):
                self.write_status([], running=False)
                return [], False
            rows = data.get("active_ports", [])
            running = bool(data.get("running", False))
            norm = []
            for r in rows:
                if len(r) >= 3:
                    norm.append((str(r[0]), str(r[2])))
                elif len(r) == 2:
                    norm.append((str(r[0]), str(r[1])))
            return norm, running
        except Exception as e:
            log(f"read_status error: {e}")
            return [], False

    # ---------- Consent ---------- #
    def read_consent(self):
        try:
            if os.path.exists(CONSENT_FILE):
                with open(CONSENT_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        return {
                            "accepted": bool(data.get("accepted", False)),
                            "rdp_move": bool(data.get("rdp_move", True)),
                            "autostart": bool(data.get("autostart", False)),
                        }
        except Exception as e:
            log(f"read_consent error: {e}")
        return {"accepted": False, "rdp_move": True, "autostart": False}

    def write_consent(self, accepted: bool, rdp_move: bool, autostart: bool):
        """Write consent data to storage"""
        try:
            data = {"accepted": bool(accepted), "rdp_move": bool(rdp_move), 
                   "autostart": bool(autostart), "ts": int(time.time()), "app": "AsteriaClient"}
            with open(CONSENT_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False)
        except Exception as e:
            log(f"write_consent error: {e}")

    # ---------- UI Helpers ---------- #
    # ---------- Update Management ---------- #
    def check_updates_and_prompt(self):
        """Check for updates and prompt user - delegated to update manager"""
        return self.update_manager.check_for_updates_interactive(self)

    def check_updates_and_apply_silent(self):
        """Silent update - delegated to update manager"""
        return self.update_manager.check_for_updates_silent()



    # ---------- RDP Management UI ---------- #
    def rdp_move_popup(self, mode: str, on_confirm):
        """Show RDP port change confirmation popup using modular RDP system"""
        # mode: "secure" (3389->53389) or "rollback" (53389->3389)
        with self.reconciliation_lock:
            self.service_manager.reconciliation_paused = True
            log("RDP işlemi için uzlaştırma döngüsü duraklatıldı.")
        
        def on_confirm_wrapped():
            """Wrapper for confirmation callback with additional handling"""
            try:
                log("✅ Kullanıcı RDP geçişini onayladı, işlem tamamlanıyor...")
                
                # Callback'i çağır (servisleri başlat vs.)
                on_confirm()
                
                # Update internal state
                self.state["running"] = True
                self.sync_gui_with_service_state()
                
                log("✅ RDP geçiş süreci kullanıcı onayı ile tamamlandı")
                    
            except Exception as e:
                log(f"❌ RDP geçiş callback hatası: {e}")
            finally:
                # Resume reconciliation
                with self.reconciliation_lock:
                    self.service_manager.reconciliation_paused = False
                log("RDP işlemi tamamlandı, uzlaştırma döngüsü devam ettiriliyor.")
        
        # Use RDP popup manager from module
        self.rdp_popup_manager.show_rdp_popup(mode, on_confirm_wrapped)

    # ---------- Application Control ---------- #
    def apply_services(self, selected_rows):
        """Apply selected service configurations via ServiceManager"""
        started = 0
        clean_rows = []
        for (listen_port, service) in selected_rows:
            port = int(listen_port)
            svc = str(service).upper()
            if self.service_manager.start_service(svc, port):
                clean_rows.append((str(listen_port), str(service)))
                self._update_row_ui(str(listen_port), str(service), True)
                started += 1

        if started == 0:
            try: messagebox.showerror(self.t("error"), "Ports are busy or cannot be listened.")
            except: pass
            return False

        self.write_status(clean_rows, running=True)
        self.state["running"] = True
        self.update_tray_icon()
        self.send_heartbeat_once("online")
        
        # GUI buton durumunu güncelle
        self.sync_gui_with_service_state()
        return True

    def remove_services(self):
        """Stop all running honeypot services"""
        self.service_manager.shutdown()
        self.state["running"] = False
        
        # GUI'deki tüm satırları pasif olarak güncelle
        for (p1, svc) in self.PORT_TABLOSU:
            self._update_row_ui(str(p1), str(svc), False)
        
        self.update_tray_icon()
        try:
            self.write_status(self.state.get("selected_rows", []), running=False)
        except: pass
        self.send_heartbeat_once("offline")
        
        # GUI buton durumunu güncelle
        self.sync_gui_with_service_state()
    
    def toggle_rdp_protection(self):
        """RDP koruma durumunu tersine çevir - popup ile onay alır"""
        try:
            is_protected, current_port = self.rdp_manager.get_rdp_protection_status()
            
            if is_protected:
                # Korumalı -> Normal (3389'a geri dön) - Pop-up göster
                log("🔄 RDP 3389'a dönüş için popup açılıyor...")
                
                def on_rdp_confirm_rollback():
                    """RDP 3389'a dönüş onaylandığında"""
                    log("✅ RDP 3389'a dönüş onaylandı, geçiş başlatılıyor...")
                    
                    # GUI'yi güncelle
                    self.update_rdp_button()
                    self.sync_gui_with_service_state()
                    self.update_tray_icon()
                    
                    # Heartbeat gönder
                    self.send_heartbeat_once("online")
                
                # Popup göster - 10 saniye sonra onay butonu aktif olacak
                self.rdp_move_popup(mode="rollback", on_confirm=on_rdp_confirm_rollback)
                
            else:
                # Normal -> Korumalı (güvenli porta taşı) - Pop-up göster
                log("🔄 RDP güvenli porta taşıma için popup açılıyor...")
                
                def on_rdp_confirm():
                    """RDP güvenli porta taşıma onaylandığında"""
                    log("✅ RDP güvenli porta taşıma onaylandı, geçiş başlatılıyor...")
                    
                    # GUI'yi güncelle
                    self.update_rdp_button()
                    self.sync_gui_with_service_state()
                    self.update_tray_icon()
                    
                    # Heartbeat gönder
                    self.send_heartbeat_once("online")
                
                # Popup göster - 10 saniye sonra onay butonu aktif olacak
                self.rdp_move_popup(mode="secure", on_confirm=on_rdp_confirm)
            
        except Exception as e:
            log(f"❌ RDP toggle hatası: {e}")
    
    def update_rdp_button(self):
        """RDP butonunun metnini güncel duruma göre güncelle"""
        try:
            # Delegate to ModernGUI if available
            if hasattr(self, 'gui') and self.gui:
                self.gui.update_rdp_button()
                self.update_tray_icon()
                return
            # Fallback: legacy row_controls
            rdp_control = self.row_controls.get(("3389", "RDP"))
            if rdp_control and "rdp_button" in rdp_control:
                rdp_btn = rdp_control["rdp_button"]
                is_protected, current_port = self.rdp_manager.get_rdp_protection_status()
                target_port = 3389 if is_protected else RDP_SECURE_PORT
                new_text = f"RDP Taşı : {target_port}"
                if is_protected:
                    rdp_btn.config(text=new_text, bg="#FF9800", fg="white")
                else:
                    rdp_btn.config(text=new_text, bg="#2196F3", fg="white")
                self.update_tray_icon()
        except Exception as e:
            log(f"❌ RDP buton güncelleme hatası: {e}")

    def _restore_saved_services(self):
        """Önceki oturumda çalışan servisleri otomatik geri yükle."""
        try:
            cons = self.read_consent()
            if not cons.get("accepted"):
                log("[RESTORE] Kullanıcı onayı yok, servisler geri yüklenmeyecek.")
                self.state["running"] = False
                self.state["selected_rows"] = []
                return

            saved_rows, saved_running = self.read_status()
            if not saved_rows or not saved_running:
                log("[RESTORE] Kaydedilmiş aktif servis yok, temiz başlangıç.")
                self.state["running"] = False
                self.state["selected_rows"] = []
                return

            log(f"[RESTORE] Önceki oturumdan {len(saved_rows)} servis geri yükleniyor: {saved_rows}")

            def _restore_worker():
                """Servisleri arka plan thread'inde başlat (GUI donmasın)."""
                try:
                    started = 0
                    for (listen_port, service) in saved_rows:
                        port = int(listen_port)
                        svc = str(service).upper()
                        if self.service_manager.start_service(svc, port):
                            self._update_row_ui(str(listen_port), str(service), True)
                            started += 1
                            log(f"[RESTORE] ✅ {svc}:{port} başarıyla geri yüklendi")
                        else:
                            log(f"[RESTORE] ❌ {svc}:{port} başlatılamadı")

                    if started > 0:
                        self.state["running"] = True
                        self.state["selected_rows"] = [(str(a[0]), str(a[1])) for a in saved_rows]
                        self.write_status(saved_rows, running=True)
                        self.send_heartbeat_once("online")
                        log(f"[RESTORE] {started}/{len(saved_rows)} servis geri yüklendi")
                    else:
                        self.state["running"] = False
                        self.state["selected_rows"] = []
                        self.write_status([], running=False)
                        log("[RESTORE] Hiçbir servis başlatılamadı")

                    # GUI senkronizasyonu (thread-safe)
                    self._gui_safe(lambda: self.sync_gui_with_service_state())
                except Exception as e:
                    log(f"[RESTORE] Servis geri yükleme hatası: {e}")

            threading.Thread(target=_restore_worker, daemon=True, name="ServiceRestorer").start()

        except Exception as e:
            log(f"[RESTORE] Hata: {e}")
            self.state["running"] = False
            self.state["selected_rows"] = []

    def sync_gui_with_service_state(self):
        """GUI buton durumunu gerçek servis durumu ile senkronize et"""
        try:
            self.update_rdp_button()
            self.update_tray_icon()
            # Update header badge (threat monitoring ≠ honeypot bait)
            if hasattr(self, 'gui') and self.gui:
                self.gui.update_header_status(self.get_protection_mode())
        except Exception as e:
            log(f"[GUI_SYNC] Senkronizasyon hatası: {e}")
            import traceback
            log(f"[GUI_SYNC] Traceback: {traceback.format_exc()}")

    # ---------- Servis Durum Yönetimi ---------- #
    def is_threat_monitoring_active(self) -> bool:
        """EventLog + ThreatEngine — or SYSTEM daemon motor online (frontend)."""
        if getattr(self, "frontend_only", False):
            try:
                from client_daemon_ipc import ping
                return bool(ping(timeout=0.8))
            except Exception:
                return bool(getattr(self, "daemon_is_active", False))
        if not ENABLE_THREAT_DETECTION:
            return False
        ew = getattr(self, "event_watcher", None)
        te = getattr(self, "threat_engine", None)
        ew_ok = bool(ew and getattr(ew, "is_running", False))
        te_ok = bool(te and getattr(te, "is_running", False))
        return ew_ok or te_ok

    def get_protection_mode(self) -> str:
        """'full' | 'monitoring' | 'inactive' — never blocks UI with IPC."""
        if getattr(self, "frontend_only", False):
            cached = getattr(self, "_protection_mode_cache", None)
            if cached in ("full", "monitoring", "inactive"):
                return cached
            return "monitoring" if getattr(self, "daemon_is_active", False) else "inactive"
        return self._compute_local_protection_mode()

    def _compute_local_protection_mode(self) -> str:
        bait = False
        try:
            bait = len(self.service_manager.running_services) > 0
        except Exception:
            bait = False
        monitoring = self.is_threat_monitoring_active()
        if bait:
            return "full"
        if monitoring:
            return "monitoring"
        return "inactive"

    def _fetch_protection_mode_ipc(self, timeout: float = 0.6) -> str:
        """Background-only: query daemon STATUS (may block up to timeout)."""
        try:
            from client_daemon_ipc import get_status
            st = get_status(timeout=timeout)
            if st.get("ok"):
                mode = st.get("protection_mode")
                if mode in ("full", "monitoring", "inactive"):
                    return mode
                if st.get("running_services"):
                    return "full"
                return "monitoring" if st.get("daemon") else "inactive"
        except Exception:
            pass
        return "monitoring" if getattr(self, "daemon_is_active", False) else "inactive"

    def refresh_protection_mode_cache(self, timeout: float = 0.6) -> str:
        """Update cache from IPC or local motors. Safe for background threads."""
        t0 = time.time()
        if getattr(self, "frontend_only", False):
            mode = self._fetch_protection_mode_ipc(timeout=timeout)
        else:
            mode = self._compute_local_protection_mode()
        prev = getattr(self, "_protection_mode_cache", None)
        self._protection_mode_cache = mode
        self._protection_mode_ts = time.time()
        ms = (time.time() - t0) * 1000
        if mode != prev:
            log(f"[PERF] protection_mode {prev}→{mode} {ms:.0f}ms")
        elif ms > 200:
            log(f"[PERF] protection_mode ipc_slow {ms:.0f}ms mode={mode}")
        return mode

    def start_protection_mode_poller(self, interval_sec: float = 5.0):
        """Poll protection mode off the UI thread (IPC must never run on Tk)."""
        if getattr(self, "_protection_poller_started", False):
            return
        self._protection_poller_started = True

        def _loop():
            while True:
                try:
                    self.refresh_protection_mode_cache(timeout=0.5)
                    # Push header update without doing IPC on UI thread
                    gui = getattr(self, "gui", None)
                    if gui and getattr(self, "root", None):
                        mode = self._protection_mode_cache

                        def _ui(m=mode):
                            try:
                                gui.update_header_status(m)
                            except Exception:
                                pass

                        try:
                            self.root.after(0, _ui)
                        except Exception:
                            pass
                except Exception:
                    pass
                time.sleep(interval_sec)

        threading.Thread(target=_loop, daemon=True, name="ProtModePoll").start()
        log(f"[PERF] protection_mode poller started ({interval_sec:.0f}s)")

    def is_protection_active(self) -> bool:
        """Tray/header: port izleme veya honeypot bait aktifse koruma var sayılır."""
        return self.get_protection_mode() != "inactive"

    # ---------- Per-row helpers ---------- #

    def _update_row_ui(self, listen_port: str, service_name: str, active: bool):
        # Delegate to ModernGUI if available
        if hasattr(self, 'gui') and self.gui:
            self.gui.update_row_ui(listen_port, service_name, active)
            return
        # Fallback for headless / legacy
        def apply():
            try:
                key = (str(listen_port), str(service_name).upper())
                rc = getattr(self, 'row_controls', {}).get(key)
                if rc:
                    btn = rc.get("button"); fr = rc.get("frame"); st = rc.get("status")
                    log(f"[UI] Updating row UI for {key}: {'Active' if active else 'Inactive'}")
                    if active:
                        if btn: btn.config(text=self.t('btn_row_stop'), bg="#E53935")
                        if fr: fr.configure(bg="#EEF7EE")
                        if st: st.config(text=f"{self.t('status')}: {self.t('status_running')}")
                    else:
                        if btn: btn.config(text=self.t('btn_row_start'), bg="#4CAF50")
                        if fr: fr.configure(bg="#ffffff")
                        if st: st.config(text=f"{self.t('status')}: {self.t('status_stopped')}")
            except Exception:
                pass
        self._gui_safe(apply)

    def _active_rows_from_services(self):
        """Build active rows list from ServiceManager (or daemon IPC in frontend)."""
        rows = []
        try:
            running = list(self.service_manager.running_services or [])
            if getattr(self, "frontend_only", False) and not running:
                try:
                    from client_daemon_ipc import honeypot_list
                    running = list(honeypot_list().get("services") or [])
                except Exception:
                    running = []
            for (p1, svc) in self.PORT_TABLOSU:
                if str(svc).upper() in [str(x).upper() for x in running]:
                    rows.append((str(p1), str(svc)))
        except Exception as e:
            log(f"Exception: {e}")
        return rows

    def start_single_row(self, p1: str, service: str, manual_action: bool = False) -> bool:
        """Tek bir honeypot servisini ServiceManager üzerinden başlatır.
        
        Args:
            p1: Dinleme portu
            service: Servis adı
            manual_action: Kullanıcı tarafından tetiklenip tetiklenmediği
        """
        service_upper = str(service).upper()
        listen_port = int(p1)
        
        # RDP özel durumu — port 3389 honeypot başlatmadan önce RDP'nin güvenli porta taşınması gerekir
        if service_upper == 'RDP':
            listen_port = 3389  # RDP honeypot her zaman 3389 dinler
            
            # Reconciliation'ı duraklat
            self.service_manager.reconciliation_paused = True
            
            current_rdp_port = ServiceController.get_rdp_port()
            port_in_use = is_port_in_use(3389)
            
            log(f"🔍 RDP DURUM: current_port={current_rdp_port}, secure_port={RDP_SECURE_PORT}, 3389_in_use={port_in_use}, manual_action={manual_action}")
            
            if current_rdp_port == RDP_SECURE_PORT:
                # RDP güvenli portta — 3389 boşsa honeypot başlat
                if not port_in_use:
                    log(f"✅ RDP güvenli portta ({RDP_SECURE_PORT}), 3389 boş - honeypot başlatılıyor...")
                    if self._engine_start_service("RDP", 3389):
                        self._on_service_started("RDP", 3389)
                        self.service_manager.reconciliation_paused = False
                        return True
                    else:
                        log("❌ RDP honeypot başlatılamadı!")
                        self.service_manager.reconciliation_paused = False
                        return False
                else:
                    # Windows Terminal Services bug workaround
                    log("⚠️ RDP Registry'de güvenli portta ama 3389 hala dolu")
                    if manual_action:
                        self._show_rdp_port_conflict_warning()
                    self.service_manager.reconciliation_paused = False
                    return False
            
            elif current_rdp_port == 3389:
                # RDP standart portta — port taşıma gerekli
                if port_in_use:
                    log("⚠️ RDP standart portta (3389) ve port dolu - taşıma gerekli")
                    if manual_action:
                        self._show_rdp_move_prompt()
                    self.service_manager.reconciliation_paused = False
                    return False
                else:
                    log("⚠️ RDP 3389'da ama port boş - beklenmeyen durum")
                    self.service_manager.reconciliation_paused = False
                    return False
            else:
                log(f"⚠️ RDP beklenmeyen portta: {current_rdp_port}")
                self.service_manager.reconciliation_paused = False
                return False
        
        # Non-RDP honeypot başlatma
        if is_port_in_use(listen_port):
            try:
                if not messagebox.askyesno(self.t("warn"), self.t("port_in_use").format(port=listen_port)):
                    return False
            except Exception as e:
                log(f"Port-in-use dialog failed for port {listen_port}: {e}")
        
        # ServiceManager üzerinden honeypot başlat (frontend → SYSTEM daemon IPC)
        if self._engine_start_service(service_upper, listen_port):
            self._on_service_started(service_upper, listen_port)
            return True
        
        try: messagebox.showerror(self.t("error"), self.t("port_busy_error"))
        except: pass
        return False

    def _engine_start_service(self, service_upper: str, listen_port: int) -> bool:
        """Start honeypot on SYSTEM motor (IPC) or local ServiceManager."""
        if getattr(self, "frontend_only", False):
            try:
                from client_daemon_ipc import honeypot_start
                resp = honeypot_start(service_upper, listen_port)
                if not resp.get("ok"):
                    log(f"[IPC] honeypot START failed: {resp}")
                return bool(resp.get("ok"))
            except Exception as e:
                log(f"[IPC] honeypot START error: {e}")
                return False
        return bool(self.service_manager.start_service(service_upper, listen_port))

    def _engine_stop_service(self, service_upper: str) -> bool:
        if getattr(self, "frontend_only", False):
            try:
                from client_daemon_ipc import honeypot_stop
                resp = honeypot_stop(service_upper)
                if not resp.get("ok"):
                    log(f"[IPC] honeypot STOP failed: {resp}")
                return bool(resp.get("ok"))
            except Exception as e:
                log(f"[IPC] honeypot STOP error: {e}")
                return False
        return bool(self.service_manager.stop_service(service_upper))

    def stop_single_row(self, p1: str, service: str, manual_action: bool = False) -> bool:
        """Tek bir honeypot servisini ServiceManager üzerinden durdurur."""
        service_upper = str(service).upper()
        listen_port = 3389 if service_upper == 'RDP' else int(p1)

        if service_upper == 'RDP':
            # RDP durdurulduğunda rollback popup göster
            self._engine_stop_service("RDP")
            
            if manual_action:
                def on_rdp_confirm_rollback():
                    self._on_service_stopped("RDP", 3389)
                self.rdp_move_popup(mode="rollback", on_confirm=on_rdp_confirm_rollback)
            else:
                # API-driven RDP stop
                if not self.start_rdp_transition("rollback"):
                    log("❌ API akışı: RDP 3389'a geri alınamadı.")
                self._on_service_stopped("RDP", 3389)
            return True

        # Non-RDP stop
        self._engine_stop_service(service_upper)
        self._on_service_stopped(service_upper, listen_port)
        return True

    def _on_service_started(self, service_name: str, port: int):
        """Servis başarıyla başlatıldığında çağrılır — GUI ve state güncelleme."""
        self.write_status(self._active_rows_from_services(), running=True)
        self.state["running"] = True
        self.update_tray_icon()
        self.send_heartbeat_once("online")
        self._update_row_ui(str(port), service_name, True)
        self.sync_gui_with_service_state()

    def _on_service_stopped(self, service_name: str, port: int):
        """Servis durdurulduğunda çağrılır — GUI ve state güncelleme."""
        running_services = self.service_manager.running_services
        self.write_status(self._active_rows_from_services(), running=len(running_services) > 0)
        if not running_services:
            self.state["running"] = False
            self.send_heartbeat_once("offline")
        self.update_tray_icon()
        self._update_row_ui(str(port), service_name, False)
        self.sync_gui_with_service_state()

    def _show_rdp_port_conflict_warning(self):
        """RDP port çakışması uyarısı göster"""
        def show_warning():
            import tkinter as tk
            from tkinter import messagebox as mb
            root = tk.Tk()
            root.withdraw()
            message = (
                f"RDP portu güvenli porta ({RDP_SECURE_PORT}) taşınmış\n"
                "ancak 3389 portunda hala bir uygulama dinliyor.\n\n"
                "Çözüm: Cihazı yeniden başlatın."
            )
            result = mb.askyesno("Port Çakışması", message, icon='warning')
            root.destroy()
            if result:
                subprocess.run(
                    ['shutdown', '/r', '/t', '30', '/c',
                     'RDP port cakismasi icin yeniden baslatiliyor...'],
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000),
                )
        threading.Thread(target=show_warning, daemon=True).start()

    def _show_rdp_move_prompt(self):
        """RDP port taşıma uyarısı göster"""
        def show_warning():
            import tkinter as tk
            from tkinter import messagebox as mb
            root = tk.Tk()
            root.withdraw()
            message = (
                "RDP honeypot başlatmak için 3389 portu boş olmalıdır.\n"
                "Şu anda RDP servisi 3389 portunda çalışıyor.\n\n"
                f"'RDP Taşı' butonu ile portu {RDP_SECURE_PORT}'a taşıyın.\n\n"
                "RDP portunu şimdi taşımak istiyor musunuz?"
            )
            result = mb.askyesno("RDP Port Uyarısı", message, icon='warning')
            root.destroy()
            if result:
                self.toggle_rdp_protection()
        threading.Thread(target=show_warning, daemon=True).start()

    def report_service_status_once(self):
        """Güncel servis durumlarını API'ye bildirir — ServiceManager'a delege eder."""
        try:
            self.service_manager._report_statuses()
        except Exception as e:
            log(f"Servis durumu raporlanırken hata: {e}")

    def start_rdp_transition(self, transition_mode: str = "secure") -> bool:
        """Use RDP Manager for port transitions"""
        return self.rdp_manager.start_rdp_transition(transition_mode)

# ---------- Remote management helpers ---------- #
    def _collect_open_ports_windows(self):
        items = []
        # Güvenlik riski oluşturabilecek yaygın portlar
        risky_ports = {
            20: "FTP Data",
            21: "FTP Control",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            135: "RPC",
            137: "NetBIOS",
            139: "NetBIOS",
            443: "HTTPS",
            445: "SMB",
            1433: "MSSQL",
            1434: "MSSQL Browser",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            5900: "VNC",
            53389: "RDP Alternative"
        }
        
        try:
            # Sadece TCP portlarını kontrol et
            cmd = ["netstat", "-ano", "-p", "TCP"]
            res = run_cmd(cmd, timeout=10, suppress_rc_log=True)
            if not res or res.returncode != 0:
                return items
                
            for line in (res.stdout or "").splitlines():
                L = line.split()
                if not L or len(L) < 5:
                    continue
                    
                # Sadece TCP dinleme portlarını işle
                if L[0].upper() == "TCP":
                    local = L[1]
                    state = L[3]
                    pid = L[4] if len(L) >= 5 else None
                    
                    # Sadece LISTEN durumundaki portları al
                    if state.upper() not in ("LISTEN", "LISTENING"):
                        continue
                        
                    try:
                        addr, port = local.rsplit(":", 1)
                        port = int(port) if port.isdigit() else None
                        
                        # Port numarası geçerli ve risk listesinde ise ekle
                        if port and (port in risky_ports or port < 1024):
                            proc_name = None
                            if pid and pid.isdigit():
                                try:
                                    import psutil
                                    proc_name = psutil.Process(int(pid)).name()
                                except Exception:
                                    proc_name = None
                            items.append({
                                "port": port,
                                "proto": "TCP",
                                "addr": addr,
                                "state": state.upper(),
                                "service": risky_ports.get(port, "Unknown"),
                                "pid": int(pid) if (pid and pid.isdigit()) else None,
                                "process": proc_name or "",
                            })
                    except Exception:
                        continue
        except Exception as e:
            log(f"collect_open_ports error: {e}")
        # Keep only listening-like entries and with valid port
        out = []
        for it in items:
            try:
                if it.get("port") and (it.get("state") in ("LISTEN", "LISTENING", "LISTEN-DRAIN", "ESTABLISHED") or it.get("proto")=="UDP"):
                    out.append(it)
            except Exception:
                pass
        return out

    def report_open_ports_once(self):
        token = self.state.get("token")
        if token:
            ports = self._collect_open_ports_windows() if os.name == 'nt' else []
            self.api_client.report_open_ports(token, ports)

    def report_open_ports_loop(self):
        while True:
            try:
                self.report_open_ports_once()
            except Exception as e:
                log(f"report_open_ports_loop err: {e}")
            time.sleep(600)

    # ---------- Tray Management (Modularized) ---------- #
    def initialize_tray_manager(self):
        """Initialize tray management system"""
        try:
            self.tray_manager = TrayManager(self, self.t)
            return self.tray_manager.start_tray_system()
        except Exception as e:
            log(f"Tray manager initialization error: {e}")
            return False
    
    def update_tray_icon(self):
        """Update tray icon - delegated to tray manager"""
        if hasattr(self, 'tray_manager') and self.tray_manager:
            self.tray_manager.update_tray_icon()

    def on_close(self):
        """Handle window close event - delegated to tray manager"""
        try:
            if hasattr(self, 'tray_manager') and self.tray_manager:
                self.tray_manager.on_window_close()
            else:
                if self.state.get("running", False):
                    messagebox.showwarning(self.t("warn"), "Please stop services first")
                    return
                self.graceful_exit(0)
        except Exception as e:
            log(f"[EXIT] Kapanış hatası: {e}")
            sys.exit(1)

    def graceful_exit(self, code: int = 0, *, goodbye_reason: str = "shutdown"):
        """Merkezi temiz çıkış — tüm kaynakları serbest bırakır"""
        try:
            log(f"[EXIT] Graceful exit başlatılıyor (code={code})")
            self._exiting = True
            self._quit_protect_until = 0.0
            # Presence goodbye before tearing down WS (daemon motor only)
            if getattr(self, "_is_daemon_motor", False) and goodbye_reason:
                try:
                    reason = goodbye_reason
                    try:
                        from client_operator_stop import is_operator_stop_active
                        if is_operator_stop_active() and reason in ("shutdown", ""):
                            reason = "operator_stop"
                    except Exception:
                        pass
                    try:
                        from client_utils import is_update_in_progress
                        if is_update_in_progress() and reason in ("shutdown", "operator_stop"):
                            reason = "update"
                    except Exception:
                        try:
                            from client_updater import is_update_in_progress as _uip
                            if _uip() and reason in ("shutdown", "operator_stop"):
                                reason = "update"
                        except Exception:
                            pass
                    from client_presence import emit_lifecycle_mirror, signal_goodbye
                    signal_goodbye(reason, http_fallback=True, close_after=False)
                    emit_lifecycle_mirror("daemon_stopping", reason)
                except Exception:
                    pass
            if getattr(self, "_is_daemon_motor", False):
                try:
                    from client_tamper import mark_graceful_motor_shutdown, stop_deadman_beacon
                    mark_graceful_motor_shutdown()
                    stop_deadman_beacon()
                except Exception:
                    pass
            try:
                from client_self_protection import disarm_for_update
                disarm_for_update(reason="graceful_exit")
            except Exception:
                pass
            if getattr(self, "process_protection", None):
                try:
                    self.process_protection.mark_graceful_shutdown()
                except Exception:
                    pass
            if hasattr(self, 'monitoring_manager'): self.monitoring_manager.stop_heartbeat_system()
            # Stop threat detection pipeline (v4.0)
            if getattr(self, 'event_watcher', None):
                try: self.event_watcher.stop()
                except Exception: pass
            if getattr(self, 'threat_engine', None):
                try: self.threat_engine.stop()
                except Exception: pass
            if getattr(self, 'alert_pipeline', None):
                try: self.alert_pipeline.stop()
                except Exception: pass
            # Stop Faz 4 modules (v4.0)
            if getattr(self, 'perf_optimizer', None):
                try: self.perf_optimizer.stop()
                except Exception: pass
            if getattr(self, 'fp_tuner', None):
                try: self.fp_tuner.stop()
                except Exception: pass
            if getattr(self, 'memory_guard', None):
                try: self.memory_guard.stop()
                except Exception: pass
            # Stop Faz 3 modules (v4.0)
            if getattr(self, 'ransomware_shield', None):
                try: self.ransomware_shield.stop()
                except Exception: pass
            if getattr(self, 'health_monitor', None):
                try: self.health_monitor.stop()
                except Exception: pass
            # Stop Faz 2 modules (v4.0) — goodbye already sent; skip duplicate
            if getattr(self, 'remote_commands', None):
                try: self.remote_commands.stop(goodbye_reason=None)
                except Exception: pass
            if getattr(self, 'auto_response', None):
                try: self.auto_response.stop()
                except Exception: pass
            if getattr(self, 'cleanup_manager', None):
                try: self.cleanup_manager.stop()
                except Exception: pass
            # Tray cleanup
            if hasattr(self, 'tray_manager') and self.tray_manager:
                try: self.tray_manager.stop_tray_system()
                except Exception: pass
            # Socket cleanup
            self.stop_single_instance_server()
            # GUI cleanup
            if self.root:
                try: self.root.destroy()
                except Exception: pass
        except Exception as e:
            log(f"[EXIT] Cleanup hatası: {e}")
        finally:
            sys.exit(code)

    def stop_single_instance_server(self):
        s = self.state.get("ctrl_sock")
        if s:
            try: s.close()
            except: pass
            self.state["ctrl_sock"] = None

    # ---------- Update Watchdog (hourly) - Modularized ---------- #
    def start_update_watchdog(self):
        """Start update watchdog through update manager
        
        NOTE: Skipped in UI-only mode when daemon is running.
        """
        # Skip if daemon is handling this
        if getattr(self, 'daemon_is_active', False):
            log("🔄 UI-only mode: Skipping update watchdog (daemon handles this)")
            return
        return self.update_manager.start_update_watchdog(auto_update=True)

    def _ensure_motor_stack(self) -> bool:
        """Guarantee RemoteCommandExecutor (+ AutoResponse) exists for Session-0 motor.

        Frontend-only __init__ may have skipped construction; daemon must still poll
        commands/pending and open remote WS.
        """
        self._is_daemon_motor = True
        self.frontend_only = False
        ok = True
        try:
            if self.auto_response is None:
                self.auto_response = AutoResponse(
                    api_client=self.api_client,
                    token_getter=lambda: self.state.get("token", ""),
                )
                self.auto_response.alert_pipeline = self.alert_pipeline
                log("[MOTOR] AutoResponse constructed (daemon ensure)")
            elif self.alert_pipeline and not getattr(
                self.auto_response, "alert_pipeline", None
            ):
                self.auto_response.alert_pipeline = self.alert_pipeline
            if self.remote_commands is None:
                self.remote_commands = RemoteCommandExecutor(
                    api_client=self.api_client,
                    token_getter=lambda: self.state.get("token", ""),
                    auto_response=self.auto_response,
                    service_manager=getattr(self, "service_manager", None),
                    on_threat_config_updated=lambda _data: self._sync_threat_config(),
                )
                if getattr(self, "cleanup_manager", None) is not None:
                    self.remote_commands.cleanup_manager = self.cleanup_manager
                if getattr(self, "health_monitor", None) is not None:
                    self.remote_commands.health_monitor = self.health_monitor
                    self.health_monitor.remote_commands = self.remote_commands
                    if getattr(self, "event_watcher", None) is not None:
                        self.health_monitor.event_watcher = self.event_watcher
                    self.health_monitor.service_manager = getattr(
                        self, "service_manager", None
                    )
                if getattr(self, "ransomware_shield", None) is not None:
                    self.remote_commands.ransomware_shield = self.ransomware_shield
                log("[MOTOR] RemoteCommandExecutor constructed (daemon ensure)")
            # Always keep honeypot manager wired (executor may already exist)
            if self.remote_commands is not None:
                if getattr(self, "service_manager", None) is not None:
                    self.remote_commands.service_manager = self.service_manager
                try:
                    self.remote_commands._gui_bump = lambda: self._bump_status_generation()
                except Exception:
                    pass
        except Exception as e:
            log(f"[MOTOR] ensure construct failed: {e}")
            ok = False
        # Keep shield wired even if executor already existed
        try:
            if (
                self.remote_commands is not None
                and getattr(self, "ransomware_shield", None) is not None
            ):
                self.remote_commands.ransomware_shield = self.ransomware_shield
        except Exception:
            pass
        return ok and self.remote_commands is not None

    def _start_emergency_command_bridge(self, reason: str = "") -> None:
        """When SYSTEM daemon is down, GUI/tray must still poll commands + heartbeat.

        Otherwise dashboard shows offline / "poll yok" while the UI card says API Connected
        (auth check only). Used after silent update if Background failed to come up.
        """
        if getattr(self, "_emergency_bridge_active", False):
            rc = getattr(self, "remote_commands", None)
            if rc is not None and getattr(rc, "_running", False):
                return
        try:
            from client_daemon_ipc import is_motor_healthy
            if is_motor_healthy(timeout=0.8):
                return
        except Exception:
            pass

        log(f"[MOTOR] EMERGENCY command bridge starting ({reason})")
        try:
            if not self._ensure_motor_stack():
                log("[MOTOR] EMERGENCY bridge: motor stack construct failed")
                return
            if self.remote_commands and not getattr(self.remote_commands, "_running", False):
                self.remote_commands.start()
            # Heartbeat so dashboard online status recovers
            if not getattr(self, "_emergency_heartbeat_started", False):
                threading.Thread(
                    target=self.heartbeat_loop, daemon=True, name="EmergencyHeartbeat"
                ).start()
                self._emergency_heartbeat_started = True
            self._emergency_bridge_active = True
            log(
                "[MOTOR] EMERGENCY bridge active — commands/pending + heartbeat "
                "in this process until Background daemon recovers"
            )
        except Exception as e:
            log(f"[MOTOR] EMERGENCY bridge failed: {e}")

    def _start_threat_and_health_services(self, source: str = "gui") -> None:
        """Start v4 threat pipeline + health/sessions reporter (daemon owns these when tray is UI-only)."""
        if not ENABLE_THREAT_DETECTION:
            # Remote commands still required for RD / self_update even if threat off
            if source == "daemon":
                self._ensure_motor_stack()
                try:
                    if self.remote_commands:
                        self.remote_commands.start()
                        log(f"[MOTOR] RemoteCommands started ({source}, threat disabled)")
                except Exception as e:
                    log(f"[MOTOR] RemoteCommands start failed: {e}")
            return

        # Threat pipeline
        if getattr(self, "event_watcher", None):
            try:
                if self.alert_pipeline:
                    self.alert_pipeline.start()
                if self.threat_engine:
                    self.threat_engine.start()
                self.event_watcher.start()
                log(f"🛡️ Threat detection pipeline started ({source})")
                log(
                    "[THREAT] Port monitoring (EventLog) is independent of honeypot bait — "
                    "block rules apply to real RDP/SSH/… even when tunnels are stopped"
                )
            except Exception as e:
                log(f"⚠️ Threat detection start failed ({source}): {e}")

        # Remote commands + auto-response (list_sessions / list_processes / logoff / RD / self_update)
        try:
            if source == "daemon":
                self._ensure_motor_stack()
            if getattr(self, "remote_commands", None):
                if getattr(self, "health_monitor", None):
                    self.remote_commands.health_monitor = self.health_monitor
                self.remote_commands.start()
                log(
                    f"[MOTOR] RemoteCommands polling + control WS "
                    f"({source}, running={getattr(self.remote_commands, '_running', False)})"
                )
            else:
                log(f"[MOTOR] ERROR: remote_commands is None ({source}) — RD/self_update dead")
            if getattr(self, "auto_response", None):
                self.auto_response.start()
            try:
                self._sync_threat_config()
            except Exception:
                pass
            log(f"🛡️ Faz 2 started ({source}: AutoResponse + RemoteCommands)")
        except Exception as e:
            log(f"⚠️ Faz 2 start failed ({source}): {e}")

        # Health monitor — active_sessions + top_processes → POST /api/health/report
        try:
            if getattr(self, "ransomware_shield", None):
                self.ransomware_shield.start()
            if getattr(self, "network_guard", None):
                self.network_guard.start()
            if getattr(self, "system_recovery", None):
                self.system_recovery.start()
            if getattr(self, "health_monitor", None):
                self.health_monitor.start()
                # Push sessions/processes immediately so dashboard is not empty for ~60s
                try:
                    self.health_monitor.force_report(refresh=True)
                except Exception as e:
                    log(f"[HEALTH] initial force_report failed: {e}")
            if getattr(self, "process_protection", None):
                self.process_protection.setup()
            if getattr(self, "threat_intel", None):
                try:
                    self.threat_intel.start()
                except Exception as e:
                    log(f"[THREAT-INTEL] start failed: {e}")
            # REV-104: observe-only runtime self-integrity → resilience snapshot.
            try:
                from client_integrity import check_async
                check_async(delay_sec=2.0)
            except Exception as e:
                log(f"[INTEGRITY] check skipped: {e}")
            log(f"🛡️ Faz 3 started ({source}: HealthMonitor + sessions/processes)")
        except Exception as e:
            log(f"⚠️ Faz 3 start failed ({source}): {e}")

    # ---------- Daemon ---------- #
    def run_daemon(self):
        """Session-0 SYSTEM motor — owns protection, RD, API, honeypots. Never exits on logon."""
        self._is_daemon_motor = True
        self.frontend_only = False
        self.state["token"] = self.token_manager.load_token()
        self.state["public_ip"] = ClientHelpers.get_public_ip()

        # Self-heal over-locked onedir ACL (Users must RX python312.dll).
        try:
            from client_install_acl import ensure_motor_runtime_user_rx
            ensure_motor_runtime_user_rx(log=log)
        except Exception as e:
            log(f"[ACL] motor runtime heal skipped: {e}")

        # RES-101: ABOVE_NORMAL (never REALTIME) so commands stay responsive under host load
        try:
            from client_process_priority import apply_motor_priority, start_priority_guard
            apply_motor_priority()
            start_priority_guard()
        except Exception as e:
            log(f"[PRIORITY] init failed: {e}")

        # Contract 1.4.12: sleep/hibernate/shutdown → dashboard presence within ~2s
        try:
            from client_power_presence import start_power_presence_watcher
            start_power_presence_watcher()
        except Exception as e:
            log(f"[POWER] presence watcher failed: {e}")

        # One-shot: legacy heal failures were counted as guardian_restarts_24h.
        try:
            from client_resilience import reset_inflated_guardian_restart_counters
            reset_inflated_guardian_restart_counters()
        except Exception:
            pass

        try:
            from client_tamper import (
                start_motor_session,
                check_previous_session_on_boot,
                start_deadman_beacon,
            )
            start_motor_session(os.getpid(), str(getattr(self, "version", "") or __version__ or ""))
            check_previous_session_on_boot()
            start_deadman_beacon(60.0)
        except Exception as e:
            log(f"[MOTOR] tamper/session init: {e}")

        def _guardian_cross_watch():
            while True:
                try:
                    from client_operator_stop import is_operator_stop_active
                    if is_operator_stop_active():
                        time.sleep(30)
                        continue
                    try:
                        from client_resilience import ensure_guardian_with_backoff
                        ensure_guardian_with_backoff()
                    except Exception:
                        from client_guardian_service import (
                            ensure_guardian_service_running,
                        )
                        ensure_guardian_service_running()
                except Exception:
                    pass
                time.sleep(30)

        threading.Thread(target=_guardian_cross_watch, name="GuardianEnsure", daemon=True).start()

        # Always construct command poller before IPC (STATUS must report motor_ok)
        try:
            self._ensure_motor_stack()
        except Exception as e:
            log(f"[MOTOR] pre-IPC ensure failed: {e}")

        # Control IPC first so GUIs can PING/STATUS while motor boots
        try:
            self.start_single_instance_server()
        except Exception as e:
            log(f"[IPC] daemon control server failed: {e}")

        threading.Thread(target=self.heartbeat_loop, daemon=True).start()
        
        # Soft tray handoff only — do NOT exit when users log on
        threading.Thread(target=self.monitor_user_sessions, daemon=True).start()
        try:
            threading.Thread(target=self.report_open_ports_loop, daemon=True).start()
        except Exception as e:
            log(f"open ports reporter start failed: {e}")
        try:
            self.service_manager.start()
            log("ServiceManager başlatıldı (daemon mode)")
        except Exception as e:
            log(f"ServiceManager start failed: {e}")
        try:
            self.start_firewall_agent()
        except Exception as e:
            log(f"firewall agent start failed (daemon): {e}")
        try:
            self._start_threat_and_health_services(source="daemon")
        except Exception as e:
            log(f"threat/health start failed (daemon): {e}")
        # Hard guarantee: command loop must be up for RD / self_update
        try:
            if self.remote_commands and not getattr(self.remote_commands, "_running", False):
                self.remote_commands.start()
                log("[MOTOR] RemoteCommands re-started after threat init")
            st = self._ipc_status_payload()
            log(
                f"[MOTOR] STATUS motor_ok={st.get('motor_ok')} "
                f"remote_commands_running={st.get('remote_commands_running')} "
                f"pid={st.get('pid')}"
            )
        except Exception as e:
            log(f"[MOTOR] post-start verify failed: {e}")
        try:
            start_watchdog_if_needed(WATCHDOG_TOKEN_FILE, log)
        except Exception as e:
            log(f"watchdog start error: {e}")
        try:
            from client_utils import heal_update_machinery
            heal_update_machinery(log_func=log)
        except Exception as e:
            log(f"update heal error: {e}")
        try:
            self.start_update_watchdog()
        except Exception as e:
            log(f"update watchdog thread error: {e}")

        cons = self.read_consent()
        if not cons.get("accepted"):
            log("Daemon: consent yok — motor idle (API/threat/RD aktif, honeypot bait bekliyor)")
            while True:
                time.sleep(30)

        saved_rows, saved_running = self.read_status()
        rows = saved_rows if saved_rows else []
        self.state["selected_rows"] = [(str(a[0]), str(a[1])) for a in rows]

        if not rows:
            log("Daemon: aktif port yok, beklemede (motor ayakta).")

        while True:
            try:
                if rows and not self.state.get("running"):
                    ok = self.apply_services(rows)
                    if ok:
                        log("Daemon: Servisler aktif (arka plan).")
                # Keep command poller alive (watchdog)
                rc = getattr(self, "remote_commands", None)
                if rc is None:
                    self._ensure_motor_stack()
                    rc = self.remote_commands
                if rc:
                    thr = getattr(rc, "_poll_thread", None)
                    alive = bool(thr is not None and thr.is_alive())
                    if not alive:
                        log("[MOTOR] RemoteCommands poll thread dead — restarting")
                        try:
                            rc._running = False
                            rc.start()
                        except Exception as e:
                            log(f"[MOTOR] RemoteCommands restart failed: {e}")
                time.sleep(5)
            except KeyboardInterrupt:
                break
            except Exception as e:
                log(f"Daemon loop err: {e}")
        try:
            self.remove_services()
        except Exception as e:
            log(f"Exception: {e}")
        
        try:
            if hasattr(self, 'monitoring_manager'):
                self.monitoring_manager.stop_heartbeat_system()
        except Exception as e:
            log(f"Daemon heartbeat cleanup error: {e}")
            
        log("Daemon: durduruldu.")


    # ---------- Firewall Agent ---------- #
    def start_firewall_agent(self):
        """Start firewall agent with updated client_firewall module
        
        NOTE: Skipped in UI-only mode when daemon is running.
        """
        # Skip if daemon is handling this
        if getattr(self, 'daemon_is_active', False):
            log("🔄 UI-only mode: Skipping firewall agent (daemon handles this)")
            return
            
        try:
            # FirewallAgent already imported at top level
            pass
        except ImportError:
            log("client_firewall module not available; skipping.")
            return
            
        token = self.state.get("token")
        if not token:
            log("No token; firewall agent not started.")
            return
            
        # Derive API base root (strip trailing /api if present)
        base = str(API_URL or "").strip().rstrip('/')
        if base.lower().endswith('/api'):
            api_base_root = base[:-4]
        else:
            api_base_root = base
        cidr_feed = os.environ.get("CIDR_FEED_BASE", "https://www.ipdeny.com/ipblocks/data/countries")

        def agent_thread():
            try:
                agent = FirewallAgent(
                    api_base=api_base_root,
                    token=token,
                    refresh_interval=int(
                        os.environ.get("REFRESH_INTERVAL_SEC", str(BLOCK_POLL_INTERVAL))
                    ),
                    cidr_feed_base=cidr_feed,
                    logger=LOGGER,
                    auto_response=getattr(self, 'auto_response', None),
                    threat_engine=getattr(self, 'threat_engine', None),
                )
                log(f"Firewall agent starting; API_BASE={api_base_root}, FEED={cidr_feed}")
                agent.run_forever()
            except Exception as e:
                log(f"Firewall agent error: {e}")

        # Start once; keep reference if needed
        if not self.state.get("fw_agent_started"):
            threading.Thread(target=agent_thread, daemon=True).start()
            self.state["fw_agent_started"] = True

    # ---------- GUI ---------- #
    def build_gui(self, minimized=None):
        # Basit startup mode belirleme
        startup_mode = "gui"  # default
        
        # Minimized parametresi varsa onu kullan
        if minimized is not None:
            startup_mode = "minimized" if minimized else "gui"
            
        # Ensure root window exists (CTk)
        if not self.root:
            self.root = ctk.CTk()
            self.root.withdraw()  # Start hidden — will be configured below

        self.start_single_instance_server()

        # Prefer frontend only if SYSTEM motor is healthy (not mere PING)
        if not getattr(self, "frontend_only", False) and not getattr(self, "daemon_is_active", False):
            try:
                from client_daemon_ipc import is_motor_healthy, ensure_daemon_running
                _t = time.time()
                if is_motor_healthy(timeout=0.4):
                    self.frontend_only = True
                    self.daemon_is_active = True
                    self._protection_mode_cache = "monitoring"
                    log(
                        f"[PERF] build_gui motor_ok "
                        f"{(time.time() - _t) * 1000:.0f}ms — frontend_only"
                    )
                else:
                    # Kick Background so commands/pending + RD WS come back
                    threading.Thread(
                        target=lambda: ensure_daemon_running(log_func=log, wait_sec=12.0),
                        daemon=True,
                        name="EnsureMotor",
                    ).start()
            except Exception:
                pass

        # Protection mode: cache via background poller (never IPC on Tk thread)
        try:
            self.start_protection_mode_poller(interval_sec=5.0)
            threading.Thread(
                target=lambda: self.refresh_protection_mode_cache(timeout=0.4),
                daemon=True,
                name="ProtModeKick",
            ).start()
        except Exception as e:
            log(f"[PERF] protection poller start: {e}")

        # Background services - skip if daemon is running (UI-only mode)
        ui_only = bool(
            getattr(self, "frontend_only", False) or getattr(self, "daemon_is_active", False)
        )
        if not ui_only:
            threading.Thread(target=self.heartbeat_loop, daemon=True).start()
            try:
                threading.Thread(target=self.report_open_ports_loop, daemon=True).start()
            except Exception as e:
                log(f"open ports reporter start failed: {e}")
            try:
                self.start_firewall_agent()
            except Exception as e:
                log(f"firewall agent start failed (gui): {e}")
        else:
            log("🔄 UI-only mode: Skipping background threads (heartbeat, open ports, services, firewall)")
        
        # Start external watchdog
        try:
            start_watchdog_if_needed(WATCHDOG_TOKEN_FILE, log)
        except Exception as e:
            log(f"watchdog start error: {e}")
        # Hourly update checker — daemon owns this in frontend mode
        if not ui_only:
            try:
                self.start_update_watchdog()
            except Exception as e:
                log(f"update watchdog thread error: {e}")
        else:
            log("🔄 UI-only mode: Skipping update watchdog (daemon handles this)")

        # Language from Windows UI (first run) or saved user preference
        self.lang = resolve_app_language()

        # Token'ı yükle
        token = self.token_manager.load_token(self.root, self.t)
        self.state["token"] = token
        # Never block UI on ipify — use cache only, refresh async
        try:
            self.state["public_ip"] = ClientHelpers.get_public_ip(allow_network=False) or ""
            def _async_ip():
                try:
                    ip = ClientHelpers.get_public_ip(force_refresh=True, allow_network=True)
                    self.state["public_ip"] = ip
                except Exception:
                    pass
            threading.Thread(target=_async_ip, daemon=True, name="PublicIP").start()
        except Exception:
            self.state["public_ip"] = ""

        # row_controls — ModernGUI populates this
        self.row_controls = {}

        # ── Modern GUI ── #
        self.gui = ModernGUI(self)

        # Consent dialog (modern) — skip in debug/test mode
        try:
            from client_constants import DEBUG_MODE, TEST_MODE
            from client_utils import get_from_config
            skip_consent = DEBUG_MODE or TEST_MODE or get_from_config("debug.skip_consent_dialog", False)
            if not skip_consent:
                self.gui.show_consent_dialog()
            else:
                log("[DEBUG] Consent dialog skipped")
        except Exception as e:
            log(f"consent ui error: {e}")

        # Build the full interface
        self.gui.build(self.root, startup_mode)

        # Wire threat detection GUI toast (v4.0)
        if self.alert_pipeline and self.gui:
            self.alert_pipeline.gui_toast_func = self.gui.show_toast

        # Attack count polling (async only — never block paint)
        self.poll_attack_count()
        if token:
            self.refresh_attack_count(async_thread=True)

        # Optional silent auto-update on startup if configured and no active services
        try:
            if os.environ.get('AUTO_UPDATE_SILENT') == '1':
                if not self.service_manager.running_services:
                    self.check_updates_and_apply_silent()
        except Exception as e:
            log(f"auto-update silent error: {e}")

        # Tray AFTER first paint opportunity — schedule so deiconify is not blocked
        if TRY_TRAY:
            def _start_tray_soon():
                try:
                    self.initialize_tray_manager()
                    if self.alert_pipeline and hasattr(self, 'tray_manager') and self.tray_manager:
                        self.alert_pipeline.tray_notify_func = self.tray_manager.notify
                    try:
                        self.update_tray_icon()
                    except Exception:
                        pass
                except Exception as e:
                    log(f"Tray start error: {e}")
            try:
                self.root.after(50, _start_tray_soon)
            except Exception:
                _start_tray_soon()

        # Önceki oturumdan kalan servisleri geri yükle (bg)
        self._restore_saved_services()

        # show_cb is used by single-instance control server to bring window to front
        def _show_window():
            try:
                if hasattr(self, 'tray_manager') and self.tray_manager:
                    self.tray_manager.show_window()
                else:
                    self._tray_mode.clear()
                    self.root.deiconify(); self.root.lift(); self.root.focus_force()
            except: pass
        self.show_cb = _show_window

        # Second launch (--mode=tray / desktop shortcut) pulses Local show-event
        try:
            from client_instance import start_gui_show_watcher

            def _show_from_event():
                try:
                    # Second launch / handoff — also revive a dead tray icon
                    if hasattr(self, "tray_manager") and self.tray_manager:
                        try:
                            self.tray_manager.ensure_tray_alive()
                        except Exception:
                            pass
                    self._gui_safe(self.show_cb)
                except Exception:
                    try:
                        self.show_cb()
                    except Exception:
                        pass

            start_gui_show_watcher(_show_from_event)
        except Exception as e:
            log(f"[SINGLETON] GUI show watcher not started: {e}")
        
        # GUI sağlık durumu izleme başlat
        self.root.after(self.gui_health['health_check_interval'] * 1000, self.check_gui_health)



# ===================== MAIN ===================== #
if __name__ == "__main__":
    # Fix TLS CA before any HTTPS (PyInstaller _MEI path can go stale)
    try:
        from client_security_utils import ensure_ca_bundle
        ensure_ca_bundle()
    except Exception:
        pass

    # Parse arguments first to check for non-GUI modes
    parser = argparse.ArgumentParser(add_help=True, description="Asteria Client - Advanced Honeypot Management System")
    
    # Simplified mode system
    parser.add_argument("--mode", choices=["daemon", "tray", "watchdog", "gui", "frontend", "guardian"], help="Operation mode: daemon (SYSTEM motor), guardian (watchdog service), tray/gui/frontend (UI), watchdog. Default is GUI mode.")
    parser.add_argument("--minimized", action="store_true", help="Start GUI minimized to tray")
    parser.add_argument("--daemon", action="store_true", help="Run as a daemon service")
    parser.add_argument("--silent", action="store_true", help="Silent mode - no user dialogs")
    parser.add_argument("--watchdog", action="store_true", help="Run watchdog mode - ensure app is running")
    parser.add_argument("--watchdog-pid", type=int, default=None, help="Watchdog process ID")
    parser.add_argument("--healthcheck", action="store_true", help="Perform health check and exit")
    parser.add_argument(
        "--uninstall-gate",
        action="store_true",
        help="PIN/lifecycle gate for Control Panel uninstall (NSIS); exit 0=allow",
    )
    parser.add_argument("--pin", default="", help=argparse.SUPPRESS)
    parser.add_argument("--silent-update-check", action="store_true", help="Silent update check mode - check for updates and install automatically")
    parser.add_argument("--create-tasks", action="store_true", help="Create Task Scheduler tasks and exit (for installer)")
    parser.add_argument("--show-gui", action="store_true", help="Force show GUI window (used by installer launch)")
    parser.add_argument("--rd-capture-once", metavar="PATH", default=None,
                        help="Capture one desktop JPEG to PATH and exit (Session 0 helper)")
    parser.add_argument("--rd-session-helper", action="store_true",
                        help=argparse.SUPPRESS)
    parser.add_argument("--rd-helper-host", default="127.0.0.1", help=argparse.SUPPRESS)
    parser.add_argument("--rd-helper-port", type=int, default=0, help=argparse.SUPPRESS)
    parser.add_argument("--rd-helper-secret", default="", help=argparse.SUPPRESS)
    parser.add_argument("--rd-helper-session", type=int, default=0, help=argparse.SUPPRESS)
    parser.add_argument("--debug", action="store_true", help="Debug mode: verbose logs, skip consent, optional no admin")
    args = parser.parse_args()
    
    # Debug mode overrides
    if args.debug:
        import client_constants
        client_constants.DEBUG_MODE = True
        client_constants.VERBOSE_LOGGING = True
        client_constants.TEST_MODE = True
        client_constants.SKIP_ADMIN_ELEVATION = True
        log("[DEBUG] Debug mode enabled via --debug")
    
    # Set global silent mode if requested
    if args.silent:
        import client_constants
        # Override config for silent deployment
        client_constants.SILENT_ADMIN_ELEVATION = True
        client_constants.SKIP_USER_DIALOGS = True

    # Handle watchdog mode — immortality of SYSTEM motor (not mere GUI presence)
    if args.watchdog:
        from client_helpers import ClientHelpers
        helper = ClientHelpers()
        
        log("Watchdog mode activated — checking SYSTEM motor (Session 0)...")
        
        try:
            from client_helpers import (
                has_interactive_user_session,
                interactive_frontend_running,
                launch_interactive_tray_gui,
            )
            try:
                from client_resilience import is_legitimate_stand_down, note_stand_down
                if is_legitimate_stand_down():
                    note_stand_down("update_or_operator_stop")
                    log("Watchdog stand-down — update/PIN active, skip resurrect")
                    sys.exit(0)
            except Exception:
                pass

            motor_alive = False
            try:
                motor_alive = bool(helper.is_system_motor_alive(timeout=0.9))
            except Exception as e:
                log(f"Watchdog motor probe failed: {e}")
                motor_alive = False

            if not motor_alive:
                # Prefer the shared ensure path (Background task + stand-down).
                log("SYSTEM motor unhealthy/missing — ensure_daemon_running")
                try:
                    from client_daemon_ipc import ensure_daemon_running
                    ensure_daemon_running(log_func=log, wait_sec=15.0)
                except Exception as e:
                    log(f"Watchdog ensure_daemon_running failed: {e}")
                log("Watchdog motor recovery triggered")
            else:
                log("SYSTEM motor healthy (motor_ok / Session 0)")

            if has_interactive_user_session() and not interactive_frontend_running():
                log("Interactive session without tray — launching Tray task")
                launch_interactive_tray_gui()
                
        except Exception as e:
            log(f"Watchdog error: {e}")
        
        sys.exit(0)
    
    # One-shot desktop capture for Session 0 → interactive helper
    if getattr(args, "rd_capture_once", None):
        try:
            from client_remote_desktop import capture_once_to_file
            ok = capture_once_to_file(args.rd_capture_once)
            sys.exit(0 if ok else 1)
        except Exception as e:
            try:
                log(f"--rd-capture-once failed: {e}")
            except Exception:
                pass
            sys.exit(1)

    if getattr(args, "rd_session_helper", False):
        try:
            from client_rd_session_helper import run_session_helper
            ok = run_session_helper(
                args.rd_helper_host,
                args.rd_helper_port,
                args.rd_helper_secret,
                args.rd_helper_session,
            )
            sys.exit(0 if ok else 1)
        except Exception as e:
            try:
                log(f"--rd-session-helper failed: {e}")
            except Exception:
                pass
            sys.exit(1)

    # Handle silent update check mode
    if args.silent_update_check:
        log("Silent update check mode activated - checking for updates...")
        try:
            from client_utils import heal_update_machinery
            heal_update_machinery(log_func=log)
        except Exception:
            pass
        try:
            # Import update manager
            from client_updater import UpdateManager
            
            # Set silent mode
            import client_constants
            client_constants.SILENT_ADMIN_ELEVATION = True
            client_constants.SKIP_USER_DIALOGS = True
            
            # Initialize update manager
            update_mgr = UpdateManager()
            
            # Perform silent update check and install
            result = update_mgr.check_for_updates_silent()
            
            if result:
                log("Silent update completed successfully - application will restart")
                # Note: If update was installed, check_for_updates_silent() calls os._exit(0)
            else:
                log("No updates available or silent update failed")
                
        except Exception as e:
            log(f"Silent update check error: {e}")
        
        sys.exit(0)
    
    # Handle task creation mode (for installer)
    if args.create_tasks:
        log("Task creation mode activated - setting up Task Scheduler tasks...")
        try:
            # Import task scheduler
            from client_task_scheduler import install_all_tasks
            
            # Set silent mode
            import client_constants
            client_constants.SILENT_ADMIN_ELEVATION = True
            client_constants.SKIP_USER_DIALOGS = True
            
            # Create all tasks including silent updater
            result = install_all_tasks(include_silent_updater=True)
            
            if result:
                log("Task Scheduler tasks created successfully")
            else:
                log("Task Scheduler task creation failed")
                
        except Exception as e:
            log(f"Task creation error: {e}")
        
        sys.exit(0)
    
    # Handle special cases that don't need GUI (deprecated watchdog-pid)
    if args.watchdog_pid is not None:
        watchdog_main(args.watchdog_pid)
        sys.exit(0)
    
    # Health check mode (for monitoring)
    if args.healthcheck:
        perform_health_check()
        sys.exit(0)

    # Uninstall PIN gate (Control Panel / Uninstall.exe) — no GUI motor
    if getattr(args, "uninstall_gate", False):
        from client_uninstall_gate import main as uninstall_gate_main
        extra = []
        if getattr(args, "silent", False):
            extra.append("--silent")
        pin = (getattr(args, "pin", None) or "").strip()
        if pin:
            extra.extend(["--pin", pin])
        sys.exit(uninstall_gate_main(extra))

    # Determine operation mode
    operation_mode = get_operation_mode(args)
    log(f"=== ASTERIA CLIENT STARTUP ===")
    log(f"Operation mode: {operation_mode}")
    log(f"Process PID: {os.getpid()}")
    log(f"Command line: {' '.join(sys.argv)}")
    
    # Architecture v4.5:
    #   SYSTEM daemon = sole motor (threat/RD/honeypot/API)
    #   GUI/--show-gui = frontend only (multi-user OK, never steals daemon)
    want_tray = getattr(args, "mode", None) == "tray"
    want_show_gui = bool(getattr(args, "show_gui", False))
    want_frontend = (
        want_show_gui
        or operation_mode in (GUI_MODE, "frontend")
        or getattr(args, "mode", None) == "frontend"
    ) and not (operation_mode == DAEMON_MODE or args.daemon)

    if operation_mode == DAEMON_MODE or args.daemon:
        from client_instance import try_acquire_daemon_mutex
        if not try_acquire_daemon_mutex():
            log("Daemon already running (DAEMON mutex held) — exiting")
            sys.exit(0)
        # Soft legacy singleton so old tools still see a holder (optional)
        try:
            from client_instance import try_acquire_mutex_soft
            try_acquire_mutex_soft()
        except Exception:
            pass
    elif want_frontend or want_tray:
        # One tray/GUI per Windows session — never spawn a second Security window
        from client_instance import try_acquire_gui_mutex, handoff_to_existing_gui
        if not try_acquire_gui_mutex():
            log("GUI/tray already running in this session — handing off SHOW and exiting")
            try:
                handoff_to_existing_gui()
            except Exception as e:
                log(f"GUI handoff error: {e}")
            sys.exit(0)
    else:
        if not check_singleton(operation_mode, allow_steal=False):
            log("ERROR: Cannot start - another instance is running or mutex failed")
            sys.exit(2)

    # ===== SIMPLIFIED MODE-BASED EXECUTION =====
    
    if operation_mode == GUI_MODE or want_frontend:
        # ===== GUI MODE - Normal GUI application with tray functionality =====
        if os.environ.get("ASTERIA_MOTOR_ONLY") == "1":
            gui_exe = os.path.join(os.path.dirname(sys.executable), "asteria-gui.exe")
            if os.path.isfile(gui_exe):
                gui_args = ["--tray"] if want_tray and not want_show_gui else []
                subprocess.Popen(
                    [gui_exe, *gui_args],
                    close_fds=True,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
                log(f"[GUI] Motor-only handoff -> {gui_exe} {' '.join(gui_args)}")
                sys.exit(0)
            log("[GUI] Motor-only build has no asteria-gui.exe sibling")
            sys.exit(3)

        # Session 0 (SYSTEM) cannot show a visible desktop window
        if is_session_zero():
            log(
                "Refusing GUI in Session 0 (invisible to user). "
                "Handing off to Asteria-Tray in interactive session."
            )
            try:
                launch_interactive_tray_gui()
            except Exception as e:
                log(f"Session-0 GUI handoff failed: {e}")
            sys.exit(0)
        
        # Initialize basic logging FIRST
        from client_paths import ensure_machine_data_dir

        log_dir = ensure_machine_data_dir()
        os.makedirs(log_dir, exist_ok=True)
        setup_logging()
        
        log("=== GUI MODE STARTUP - Normal interface startup ===")
        
        try:
            # Language: Windows UI on first run; keep user override after manual change
            selected_language = resolve_app_language()
            
            # Create app instance
            app = CloudHoneypotClient()
            app.lang = selected_language
            # Prefer frontend if SYSTEM motor already healthy; otherwise ensure in background
            try:
                from client_daemon_ipc import is_motor_healthy
                if is_motor_healthy(timeout=0.8):
                    app.frontend_only = True
                    app.daemon_is_active = True
                    log("[IPC] Confirmed motor_ok — forcing frontend_only")
            except Exception:
                pass

            def _bg_ensure_daemon():
                try:
                    from client_daemon_ipc import ensure_daemon_running, is_motor_healthy
                    ok = ensure_daemon_running(log_func=log, wait_sec=12.0)
                    if ok or is_motor_healthy(timeout=0.8):
                        app.frontend_only = True
                        app.daemon_is_active = True
                    log(f"[IPC] Background daemon ensure: {'ok' if ok else 'failed (GUI continues)'}")
                except Exception as e:
                    log(f"[IPC] ensure_daemon failed: {e}")

            if want_frontend or want_tray:
                threading.Thread(
                    target=_bg_ensure_daemon, daemon=True, name="EnsureDaemon"
                ).start()

            if want_show_gui:
                # Installer/desktop launch: ignore QUIT for a few seconds (kill race)
                app._quit_protect_until = time.time() + 20.0
                try:
                    from client_utils import release_update_lock
                    release_update_lock(resume_updaters=True)
                except Exception:
                    pass
            log(f"Application initialized with language: {selected_language}")
            
            # Task Scheduler management handled by modular system in __init__
            if ctypes.windll.shell32.IsUserAnAdmin():
                log("Admin yetkisi mevcut - Task Scheduler yönetimi __init__ tarafından halledildi")
            else:
                log("Normal user mode - Task Scheduler will be configured later")
            
            # --show-gui: show this session. Onboarding flag only from installer / no-token.
            from client_utils import should_force_gui_visible
            has_token = bool(app.get_token() or app.state.get("token"))
            # Token present → clear stale flag and allow tray; no-token → force visible
            force_gui = want_show_gui or should_force_gui_visible(has_token)
            # Tray-minimized ONLY for explicit --mode=tray AND not onboarding
            tray_mode = want_tray and not force_gui
            if force_gui:
                log("Onboarding/GUI required — starting visible (not tray-minimized)")
            else:
                log("Token present — tray minimize allowed")
            
            # Build GUI in both cases
            log("Building main GUI...")
            t0 = time.time()
            app.build_gui(minimized=tray_mode)  # Pass tray_mode as minimized flag
            log(f"GUI build completed successfully in {time.time() - t0:.2f}s")
            
            # Show window ASAP — RDP/sync in background (was blocking paint)
            if not tray_mode:
                if hasattr(app, "root") and app.root:
                    app._tray_mode.clear()
                    try:
                        app.root.deiconify()
                        app.root.lift()
                        app.root.focus_force()
                    except Exception:
                        pass

            def _post_show_sync():
                try:
                    is_protected, current_port = app.rdp_manager.get_rdp_protection_status()
                    if is_protected:
                        log(f"🛡️ RDP koruması aktif (port: {current_port})")

                    def _ui():
                        try:
                            app.sync_gui_with_service_state()
                            app.update_tray_icon()
                        except Exception as e:
                            log(f"post-show UI sync: {e}")

                    if hasattr(app, "root") and app.root:
                        app.root.after(0, _ui)
                    else:
                        _ui()
                except Exception as e:
                    log(f"post-show sync: {e}")
            try:
                if hasattr(app, "root") and app.root:
                    app.root.after(100, lambda: threading.Thread(
                        target=_post_show_sync, daemon=True, name="PostShowSync"
                    ).start())
                else:
                    threading.Thread(target=_post_show_sync, daemon=True).start()
            except Exception:
                pass
            
            # Start API synchronization in background after GUI is ready
            app.start_delayed_api_sync()
            
            # If tray mode, immediately hide to tray after GUI is built
            # Never hide during onboarding / first registration
            if tray_mode and not force_gui:
                log("Tray mode: Minimizing to tray...")
                if hasattr(app, 'root') and app.root:
                    app._tray_mode.set()  # Mark as intentionally in tray
                    app.root.withdraw()  # Hide the window
                    app.root.update()
                    log("Tray mode: Window hidden successfully")
            else:
                # Default / installer / onboarding: window must stay visible
                if hasattr(app, "root") and app.root:
                    app._tray_mode.clear()
                    try:
                        app.root.deiconify()
                        app.root.lift()
                        app.root.focus_force()
                        # Re-assert visibility after tray icon init / consent (timing races)
                        app.root.after(400, lambda: (
                            app._tray_mode.clear(),
                            app.root.deiconify(),
                            app.root.lift(),
                        ))
                    except Exception:
                        pass
            
            # Run main loop
            if hasattr(app, 'root') and app.root:
                app.root.mainloop()
            
        except Exception as gui_error:
            log(f"GUI Mode Error: {gui_error}")
            import traceback
            log(f"GUI Error traceback: {traceback.format_exc()}")
            sys.exit(1)
    

    elif operation_mode == DAEMON_MODE or args.daemon:
        # DAEMON MODE - Background operation, no GUI
        import subprocess
        import ctypes
        import time
        def is_user_logged_on():
            try:
                from client_helpers import has_interactive_user_session
                return has_interactive_user_session()
            except Exception as e:
                log(f"User session check error: {e}")
            return False

        if is_user_logged_on():
            # CRITICAL: Background task runs as SYSTEM (Session 0).
            # Building a Tk GUI here is invisible on the user desktop.
            if is_session_zero():
                log(
                    "Active user session detected, but we are in Session 0 (SYSTEM). "
                    "Keeping headless daemon and launching interactive Tray/GUI."
                )
                try:
                    from client_helpers import launch_interactive_tray_gui
                    launch_interactive_tray_gui()
                except Exception as e:
                    log(f"Interactive tray launch failed: {e}")
                # Fall through to normal headless daemon (do NOT build GUI here)
            else:
                # CRITICAL: never convert interactive --mode=daemon into a GUI motor.
                # Security motor must live in Session 0 via Background task.
                log(
                    "Daemon argv in interactive session — ensuring Session-0 Background "
                    "motor (will NOT build Tk as motor), then hand off tray and exit"
                )
                try:
                    from client_task_scheduler import TASK_NAME_BACKGROUND
                    from client_winproc import run_hidden
                    run_hidden(
                        ["schtasks", "/change", "/tn", TASK_NAME_BACKGROUND, "/enable"],
                        timeout=10,
                    )
                    run_hidden(
                        ["schtasks", "/run", "/tn", TASK_NAME_BACKGROUND],
                        timeout=15,
                    )
                except Exception as e:
                    log(f"Background ensure from interactive daemon failed: {e}")
                try:
                    from client_helpers import launch_interactive_tray_gui
                    launch_interactive_tray_gui()
                except Exception as e:
                    log(f"Tray handoff failed: {e}")
                sys.exit(0)

        # Headless daemon (no interactive session, or Session 0 with tray handoff)
        app = None
        try:
            log("=== DAEMON MODE STARTUP ===")
            log_dir = os.path.join(os.environ.get('PROGRAMDATA', ''), 'Asteria', 'logs')
            os.makedirs(log_dir, exist_ok=True)
            setup_logging()
            log("Setting up daemon mode application...")
            app = CloudHoneypotClient()
            log("Starting daemon mode...")
            app.run_daemon()
        except KeyboardInterrupt:
            log("Daemon interrupted by user signal")
            sys.exit(0)
        except Exception as daemon_error:
            log(f"DAEMON CRITICAL ERROR: {daemon_error}")
            import traceback
            log(f"Daemon traceback: {traceback.format_exc()}")
            try:
                if app and hasattr(app, 'heartbeat_path'):
                    if hasattr(app, 'monitoring_manager'):
                        app.monitoring_manager.stop_heartbeat_system()
            except Exception:
                pass
            sys.exit(1)  # Exit code 1 = Unhandled exception
        sys.exit(0)
    
    elif operation_mode == "guardian":
        try:
            log("=== GUARDIAN MODE STARTUP ===")
            setup_logging()
            from client_guardian_service import run_guardian_mode
            run_guardian_mode()
        except Exception as e:
            log(f"GUARDIAN CRITICAL ERROR: {e}")
            sys.exit(1)
        sys.exit(0)

    elif operation_mode == "watchdog":
        # ===== WATCHDOG MODE — same motor_ok + stand-down path as --watchdog =====
        try:
            log("=== WATCHDOG MODE STARTUP ===")
            from client_helpers import ClientHelpers
            from client_lifecycle import report_now, flush_queue_to_api
            from client_daemon_ipc import ensure_daemon_running, is_motor_healthy

            try:
                from client_resilience import is_legitimate_stand_down, note_stand_down
                if is_legitimate_stand_down():
                    note_stand_down("update_or_operator_stop")
                    log("Watchdog mode stand-down — update/PIN active")
                    sys.exit(0)
            except Exception:
                pass

            helper = ClientHelpers()
            is_running = bool(is_motor_healthy(timeout=0.9)) or helper.is_daemon_running()

            if not is_running:
                log("No healthy SYSTEM motor, ensure_daemon_running...")
                report_now(
                    "watchdog_restart",
                    "client_not_running",
                    {"action": "start_daemon"},
                    severity="warning",
                    log_func=log,
                )

                ok = ensure_daemon_running(log_func=log, wait_sec=15.0)
                if not ok:
                    report_now(
                        "watchdog_restart_failed",
                        "daemon_not_alive_after_start",
                        {},
                        severity="error",
                        log_func=log,
                    )
                else:
                    report_now(
                        "watchdog_restart_ok",
                        "daemon_running",
                        {},
                        severity="info",
                        log_func=log,
                    )
            else:
                log("SYSTEM motor healthy - watchdog check passed")

            # Logon session without tray/GUI frontend → resurrect tray (same as --watchdog)
            try:
                from client_helpers import (
                    has_interactive_user_session,
                    interactive_frontend_running,
                    launch_interactive_tray_gui,
                )
                if has_interactive_user_session() and not interactive_frontend_running():
                    log("Watchdog mode: interactive session without tray — launching Tray task")
                    launch_interactive_tray_gui()
            except Exception as e:
                log(f"Watchdog mode tray check failed: {e}")

            try:
                flush_queue_to_api(log_func=log)
            except Exception:
                pass

        except Exception as e:
            log(f"Watchdog error: {e}")
            try:
                from client_lifecycle import report_now
                report_now(
                    "watchdog_error",
                    str(e),
                    {},
                    severity="error",
                    log_func=log,
                )
            except Exception:
                pass

        sys.exit(0)
    
    else:
        # Fallback - should not happen with current logic
        log(f"ERROR: Unknown operation mode: {operation_mode}")
        sys.exit(1)


