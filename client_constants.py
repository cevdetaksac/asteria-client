#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Asteria Client - Constants and Configuration
Tum uygulama sabitlerinin merkezi yonetimi

Version: Defined as VERSION constant below (single source of truth)

Key Intervals (optimized for performance):
- FILE_HEARTBEAT_INTERVAL: 60s (server heartbeat interval)
- API_HEARTBEAT_INTERVAL: 60s (server heartbeat)
- ATTACK_COUNT_REFRESH: 15s (GUI attack counter)
- SERVICE_SYNC_INTERVAL: 45s (honeypot service sync with dashboard)
- BLOCK_POLL_INTERVAL: 30s (firewall block rule polling)
- PORT_REPORT_INTERVAL: 300s (open port reporting)

Notes:
- Intervals are tuned to reduce CPU/network usage
- All intervals can be overridden in client_config.json
- Wire identities: ProgramData\\Asteria, Asteria-* tasks, AsteriaGuardian;
  legacy YesNext / CloudHoneypot-* cleaned on install/update. Signing
  context emits ``asteria-chp-v1`` / ``asteria-heartbeat-v1`` (contract ≥1.4.32).
  Verify still accepts legacy ``yesnext-*`` during fleet cutover until the
  dual-brand sunset target **2026-10-01** (PRODUCT_BRANDING.md §Sunset).
  per contract agent/rebrand-asteria.md — display brand is Asteria.
"""

import os
import socket
from client_utils import get_from_config, load_config, get_resource_path

# ===================== APPLICATION METADATA ===================== #

# Initialize configuration early
_CONFIG = None

def get_app_config():
    """Get application configuration, loading it if needed"""
    global _CONFIG
    if _CONFIG is None:
        _CONFIG = load_config()
    return _CONFIG

# Application information
VERSION = "4.9.70"  # Fleet console lab: Winlogon C-RD-CON + dashboard C-RD-VIEW 1.4.47



CLIENT_VERSION = VERSION  # Main version constant
__version__ = VERSION  # Export for compatibility

BRAND_NAME = "Asteria"
APP_NAME = get_from_config("application.name", "Asteria Client")
VENDOR_NAME = get_from_config("application.author", "Asteria")

# Process / install identity (new primary + legacy aliases for fleet migrate)
CLIENT_EXE_NAME = "asteria-client.exe"
CLIENT_EXE_ALIASES = ("asteria-client.exe", "honeypot-client.exe")
INSTALL_DIR_NAME = "Asteria Client"
INSTALL_VENDOR_DIR = "Asteria"
LEGACY_INSTALL_VENDOR_DIR = "YesNext"
LEGACY_INSTALL_DIR_NAME = "Cloud Honeypot Client"

# GitHub repository information (Asteria; legacy slug still redirects)
GITHUB_OWNER = "cevdetaksac"
GITHUB_REPO = "asteria-client"
GITHUB_REPO_LEGACY = "yesnext-cloud-honeypot-client"

# Release installer asset names. Agents <= 4.9.40 hardcode the legacy name as
# their fallback download URL, so every release must keep publishing both until
# the fleet has moved past that build.
INSTALLER_ASSET_NAME = "asteria-client-installer.exe"
INSTALLER_ASSET_NAME_LEGACY = "cloud-client-installer.exe"
INSTALLER_FILE_PREFIXES = ("asteria-client-installer", "cloud-client-installer")

# ===================== NETWORK CONFIGURATION ===================== #

# API Configuration — primary asteria.run; legacy YesNext host for failover
API_URL = get_from_config("api.base_url", "https://asteria.run/api")
API_URL_LEGACY = get_from_config(
    "api.legacy_base_url", "https://honeypot.yesnext.com.tr/api"
)

# Local control server for single instance
CONTROL_HOST = "127.0.0.1"
CONTROL_PORT = 58632

# Network settings
SERVER_NAME = socket.gethostname()
CONNECT_TIMEOUT = 8

# ===================== SECURITY CONFIGURATION ===================== #

# Admin elevation control - TEST MODE
SKIP_ADMIN_ELEVATION = get_from_config("debug.skip_admin_elevation", False)
TEST_MODE = get_from_config("debug.test_mode", False)
FORCE_NO_EXIT = True  # Prevent any early exits during testing

# RDP secure port configuration
RDP_SECURE_PORT = get_from_config("services.rdp_port", 43389)

# Windows Defender compatibility metadata
DEFENDER_MARKERS = {
    "software_category": "Network Security Monitoring",
    "legitimate_purpose": "Intrusion Detection and Response", 
    "vendor": "Asteria",
    "certificate_subject": "Asteria",
    "installation_method": "Microsoft Signed Installer",
    "behavioral_patterns": [
        "Network monitoring and analysis",
        "Security event logging", 
        "Remote security management",
        "System integrity monitoring"
    ]
}

# ===================== FILE PATHS ===================== #

def _is_system_profile_context() -> bool:
    """True for SYSTEM / Session 0 — Roaming APPDATA under systemprofile is fragile."""
    try:
        appdata = (os.environ.get("APPDATA") or "").lower()
        if "systemprofile" in appdata:
            return True
        userprofile = (os.environ.get("USERPROFILE") or "").lower()
        if "systemprofile" in userprofile:
            return True
        username = (os.environ.get("USERNAME") or os.environ.get("USER") or "").upper()
        if username in ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"):
            return True
    except Exception:
        pass
    try:
        import ctypes
        from ctypes import wintypes
        sid = wintypes.DWORD()
        if ctypes.windll.kernel32.ProcessIdToSessionId(
            ctypes.windll.kernel32.GetCurrentProcessId(), ctypes.byref(sid)
        ):
            if int(sid.value) == 0:
                return True
    except Exception:
        pass
    return False


def _ensure_directory(path: str) -> bool:
    """Create directory; tolerate WinError 183 (path exists as file / race)."""
    try:
        if os.path.isdir(path):
            return True
        if os.path.isfile(path):
            # Broken install left a FILE where a directory should be
            try:
                os.replace(path, path + ".bak_file")
            except OSError:
                path = path + "_data"
        os.makedirs(path, exist_ok=True)
        return os.path.isdir(path)
    except OSError as e:
        # WinError 183: cannot create a file when that file already exists
        if os.path.isdir(path):
            return True
        # Parent component may be a file — try sibling name
        try:
            alt = path + "_dir"
            os.makedirs(alt, exist_ok=True)
            if os.path.isdir(alt):
                return False  # caller should not use alt via this bool alone
        except OSError:
            pass
        # Last resort: ignore — caller picks fallback path
        _ = e
        return os.path.isdir(path)


def get_app_directory() -> str:
    """Application data directory — always %ProgramData%\\Asteria (brand SoT).

    SYSTEM daemon and interactive GUI share one machine-wide tree so token,
    consent, logs, and lock state stay aligned. Legacy YesNext trees are
    migrated on first use (see client_paths.migrate_legacy_programdata).
    """
    try:
        from client_paths import MACHINE_DATA_DIR, ensure_machine_data_dir, migrate_legacy_programdata

        ensure_machine_data_dir()
        try:
            migrate_legacy_programdata()
        except Exception:
            pass
        return MACHINE_DATA_DIR
    except Exception:
        program_data = os.environ.get("ProgramData", r"C:\ProgramData")
        machine_dir = os.path.join(program_data, "Asteria")
        if _ensure_directory(machine_dir):
            return machine_dir
        return program_data

# Application directories
APP_DIR = get_app_directory()

# Machine-wide identity (SYSTEM daemon + user GUI share the same token)
try:
    from client_paths import MACHINE_DATA_DIR as _MACHINE_DATA_DIR

    MACHINE_DATA_DIR = _MACHINE_DATA_DIR
except Exception:
    MACHINE_DATA_DIR = os.path.join(
        os.environ.get("ProgramData", r"C:\ProgramData"),
        "Asteria",
    )
try:
    _ensure_directory(MACHINE_DATA_DIR)
except Exception:
    pass
TOKEN_FILE = os.path.join(MACHINE_DATA_DIR, "token.dat")

# Application files
LOG_FILE = os.path.join(APP_DIR, "client.log")
CONSENT_FILE = os.path.join(APP_DIR, "consent.json")
# Machine-wide status so SYSTEM daemon + all user GUIs share one source of truth
STATUS_FILE = os.path.join(MACHINE_DATA_DIR, "status.json")
STATUS_FILE_LEGACY = os.path.join(APP_DIR, "status.json")
WATCHDOG_TOKEN_FILE = os.path.join(APP_DIR, "watchdog.token")
TASK_STATE_FILE = os.path.join(APP_DIR, "task_state.json")

# ===================== GUI CONFIGURATION ===================== #

def get_window_dimensions():
    """Get window dimensions from config"""
    config = get_app_config()
    width = config.get("ui", {}).get("window_width", 900)
    height = config.get("ui", {}).get("window_height", 700)
    return width, height

# Window configuration
WINDOW_WIDTH, WINDOW_HEIGHT = get_window_dimensions()
WINDOW_TITLE = APP_NAME

# Tray configuration
TRY_TRAY = get_from_config("advanced.minimize_to_tray", True)

# ===================== HONEYPOT SERVICE CONFIGURATION ===================== #

# Honeypot bind address (0.0.0.0 = all interfaces)
HONEYPOT_BIND_ADDRESS = get_from_config("services.bind_address", "0.0.0.0")

# Service definitions — each honeypot service the client can run locally
HONEYPOT_SERVICES = {
    "RDP":   {"port": 3389, "protocol": "tcp", "description": "Remote Desktop Protocol"},
    "SSH":   {"port": 22,   "protocol": "tcp", "description": "Secure Shell"},
    "FTP":   {"port": 21,   "protocol": "tcp", "description": "File Transfer Protocol"},
    "MYSQL": {"port": 3306, "protocol": "tcp", "description": "MySQL Database"},
    "MSSQL": {"port": 1433, "protocol": "tcp", "description": "Microsoft SQL Server"},
    "HTTP":  {"port": 80,   "protocol": "tcp", "description": "HTTP Web Login Decoy"},
    "SMB":   {"port": 445,  "protocol": "tcp", "description": "SMB File Share Probe"},
}

# Honeypot service banners (realistic decoys)
SSH_BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"
FTP_BANNER = "220 (vsFTPd 3.0.5)"
MYSQL_VERSION = "5.7.38-0ubuntu0.22.04.2"
MSSQL_VERSION = "Microsoft SQL Server 2019 (RTM-CU18)"
RDP_CERT_CN = "WIN-HONEYPOT"
HTTP_SERVER_BANNER = "Microsoft-IIS/10.0"
SMB_SERVER_NAME = "WIN-HONEYPOT"

# Credential capture limits (anti-abuse / rate limiting)
MAX_CREDENTIAL_LENGTH = 256           # Max length for captured username / short passwords
MAX_HASH_CREDENTIAL_LENGTH = 2048     # NetNTLMv2 / long hash lines (hashcat 5600)
MAX_ATTEMPTS_PER_IP_PER_MIN = 10      # Rate limit: max reports per IP+service per minute
CREDENTIAL_BATCH_SIZE = 10            # Send credentials in batches of this size
CREDENTIAL_BATCH_INTERVAL = 5         # Seconds between batch sends
HONEYPOT_AUTO_RESTART_MAX = 3         # Max auto-restart attempts for crashed services
HONEYPOT_RESTART_BACKOFF = [5, 15, 60]  # Seconds: exponential backoff for restarts

def get_default_services():
    """Get default service configuration from config file"""
    config = get_app_config()
    services_cfg = config.get("services", {}).get("honeypots", [])
    services = {}
    for svc_cfg in services_cfg:
        service = svc_cfg["service"].upper()
        services[service] = {"listen_port": svc_cfg["port"]}
    return services

def get_service_table():
    """Get service table for GUI display"""
    config = get_app_config()
    services_cfg = config.get("services", {}).get("honeypots", [])
    table = []
    for svc_cfg in services_cfg:
        port = str(svc_cfg["port"])
        service = svc_cfg["service"]
        table.append((port, service))
    return table

# Service configurations (loaded from config)
DEFAULT_SERVICES = get_default_services()
SERVICE_TABLE = get_service_table()

# ===================== WINDOWS INTEGRATION ===================== #

# Registry
APP_STARTUP_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"

# ===================== APPLICATION MODES ===================== #

# Operation modes
GUI_MODE = "gui"        # Interactive frontend (prefers SYSTEM daemon motor)
DAEMON_MODE = "daemon"  # Session-0 SYSTEM motor — owns protection/RD/API
FRONTEND_MODE = "frontend"  # Explicit UI-only alias of gui

# ===================== HEARTBEAT CONFIGURATION ===================== #

HEARTBEAT_FILE = "heartbeat.json"
FILE_HEARTBEAT_INTERVAL = 60  # File heartbeat interval (was 10s, optimized to 60s for performance)

# Singleton mutex — DAEMON only (GUI frontends do not take this)
SINGLETON_MUTEX_NAME = "Global\\AsteriaClient_Singleton"
DAEMON_MUTEX_NAME = "Global\\AsteriaClient_Daemon"
# Per-session GUI/tray singleton. Global\\ + session id crosses integrity levels
# (Highest tray task vs Medium WTS spawn) so two frontends cannot both "own" a
# Local\\ mutex in the same interactive session.
GUI_MUTEX_NAME_PREFIX = "Global\\AsteriaClient_GUI_s"
GUI_SHOW_EVENT_NAME_PREFIX = "Global\\AsteriaClient_ShowGUI_s"
# Compatibility aliases (tests / callers that expect a constant string shape).
# Prefer gui_mutex_name() / gui_show_event_name() at runtime.
GUI_MUTEX_NAME = GUI_MUTEX_NAME_PREFIX + "0"
GUI_SHOW_EVENT_NAME = GUI_SHOW_EVENT_NAME_PREFIX + "0"
# Pre-4.9.64 Local names + pre-4.9.41 CloudHoneypot names (handoff / kill)
LEGACY_SINGLETON_MUTEX_NAME = "Global\\CloudHoneypotClient_Singleton"
LEGACY_DAEMON_MUTEX_NAME = "Global\\CloudHoneypotClient_Daemon"
LEGACY_GUI_MUTEX_NAME = "Local\\AsteriaClient_GUI"
LEGACY_GUI_SHOW_EVENT_NAME = "Local\\AsteriaClient_ShowGUI"
LEGACY_GUI_MUTEX_NAME_V1 = "Local\\CloudHoneypotClient_GUI"
LEGACY_GUI_SHOW_EVENT_NAME_V1 = "Local\\CloudHoneypotClient_ShowGUI"
LEGACY_GUI_MUTEX_WEBVIEW = "Local\\AsteriaGuiWebView"
LEGACY_GUI_SHOW_EVENT_WEBVIEW = "Local\\AsteriaGuiWebViewShow"


def current_windows_session_id() -> int:
    """Windows session id for this process (0 = Session-0 / services)."""
    try:
        import ctypes
        from ctypes import wintypes

        sid = wintypes.DWORD()
        if ctypes.windll.kernel32.ProcessIdToSessionId(  # type: ignore[attr-defined]
            os.getpid(), ctypes.byref(sid)
        ):
            return int(sid.value)
    except Exception:
        pass
    return 0


def gui_mutex_name(session_id: int | None = None) -> str:
    """Named mutex for one interactive frontend per Windows session."""
    sid = current_windows_session_id() if session_id is None else int(session_id)
    return f"{GUI_MUTEX_NAME_PREFIX}{sid}"


def gui_show_event_name(session_id: int | None = None) -> str:
    """Named event: second launch pulses this so the live tray raises the window."""
    sid = current_windows_session_id() if session_id is None else int(session_id)
    return f"{GUI_SHOW_EVENT_NAME_PREFIX}{sid}"

# ===================== TIMING CONFIGURATION ===================== #

# API and sync intervals (in seconds)
API_RETRY_INTERVAL = 60              # API connection retry interval
API_HEARTBEAT_INTERVAL = 60          # API heartbeat send interval
ATTACK_COUNT_REFRESH = 15            # Attack count refresh interval
SERVICE_SYNC_INTERVAL = 15           # Desired honeypot state reconcile (was 45s)
SERVICE_SYNC_CHECK = 5               # Sync loop wake frequency (was 10s)
BLOCK_POLL_INTERVAL = 30             # Firewall block rule polling interval
PORT_REPORT_INTERVAL = 300           # Open port reporting interval
API_STARTUP_DELAY = 5                # API startup delay
RDP_TRANSITION_TIMEOUT = 120         # RDP transition timeout
SERVICE_WATCHDOG_INTERVAL = 15       # Service watchdog check interval (was WATCHDOG_INTERVAL)

# ===================== LOGGING CONFIGURATION ===================== #

# Log file settings
LOG_MAX_BYTES = 10 * 1024 * 1024    # 10 MB
LOG_BACKUP_COUNT = 5                 # Number of backup files
LOG_RETENTION_DAYS = 7               # Daily logs: today + previous 6 days
LOG_ENCODING = "utf-8"

# Log format
LOG_TIME_FORMAT = '%Y-%m-%d %H:%M:%S.%f'  # With milliseconds

# ===================== SECURITY SETTINGS ===================== #

# Security metadata for Windows Defender compatibility
SECURITY_METADATA = {
    "product_name": "Asteria",
    "product_version": __version__,
    "vendor_name": "Asteria",
    "product_state": "Enabled and Up-to-date",
    # Honest until SUP-001 production signing is active — do not claim verified.
    "signature_status": "authenticode_unknown",
    "installation_source": "Legitimate software distribution",
}

# Registry security markers
# RDP registry key path (without HKEY_LOCAL_MACHINE prefix for reg add command)
RDP_REGISTRY_KEY_PATH = r"HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
# App registry key path (wire identity — do not relocate)
REGISTRY_KEY_PATH = r"SOFTWARE\Asteria"

# Legitimate domains for network behavior
LEGITIMATE_DOMAINS = [
    "asteria.run",
    "www.asteria.run",
    "honeypot.yesnext.com.tr",
    "api.yesnext.com.tr",
    "github.com",
    "raw.githubusercontent.com",
]

# Restricted paths for security compliance
RESTRICTED_PATHS = [
    os.environ.get("SYSTEMROOT", "C:\\Windows"),
    os.environ.get("PROGRAMFILES", "C:\\Program Files"),
    os.environ.get("PROGRAMFILES(X86)", "C:\\Program Files (x86)")
]

# ===================== API CONFIGURATION ===================== #

# API retry settings
API_MAX_QUICK_RETRIES = 3
API_QUICK_RETRY_DELAY = 5
API_SLOW_RETRY_DELAY = 60
API_REQUEST_TIMEOUT = 8

# ===================== FEATURE FLAGS ===================== #

# Feature toggles from configuration
ENABLE_AUTO_UPDATE = get_from_config("advanced.auto_update", True)
ENABLE_TRAY_ICON = get_from_config("advanced.minimize_to_tray", True)
ENABLE_ADMIN_ELEVATION = get_from_config("advanced.request_admin_privileges", True)

# GUI refresh — dashboard tick interval (milliseconds)
GUI_DASHBOARD_REFRESH_MS = int(get_from_config("ui.dashboard_refresh_seconds", 10)) * 1000

# Debug and development flags
DEBUG_MODE = get_from_config("debug.enabled", get_from_config("logging.debug_mode", False))
VERBOSE_LOGGING = get_from_config("debug.verbose_logging", DEBUG_MODE)

# Production deployment flags
SILENT_ADMIN_ELEVATION = get_from_config("deployment.silent_admin", True)  # Auto-elevate without asking
SKIP_USER_DIALOGS = get_from_config("deployment.skip_dialogs", False)  # Skip all user confirmations

# ===================== THREAT DETECTION (v4.0) ===================== #

# Enable/disable threat detection engine
ENABLE_THREAT_DETECTION = get_from_config("threat_detection.enabled", True)

# EventLog Watcher — refresh & watchdog intervals
EVENTLOG_WATCHDOG_INTERVAL = 60           # Check subscription health every 60s

# Threat Engine — scoring & correlation
THREAT_SCORE_DECAY_INTERVAL = 300         # Decay scores every 5 min
THREAT_CONTEXT_MAX_AGE = 86400            # Remove IP context after 24h inactivity
THREAT_ALERT_MIN_SCORE = 31              # Minimum score to generate an alert

# Alert Pipeline — batch & rate limiting
ALERT_BATCH_FLUSH_INTERVAL = 120          # Flush batch buffer every 2 min (V4)
ALERT_BATCH_MAX_SIZE = 500                # Force flush at 500 buffered events
ALERT_URGENT_COOLDOWN = 300               # Same threat_type+IP: max 1 urgent / 5 min
ALERT_URGENT_RETRY_DELAY = 30             # Retry failed urgent after 30s
ALERT_URGENT_MAX_RETRIES = 3
ALERT_THREAT_LOG_FILE = "threats.log"     # Local threat log filename
ALERT_THREAT_LOG_MAX_BYTES = 5 * 1024 * 1024  # 5 MB
ALERT_THREAT_LOG_BACKUP_COUNT = 3

# Dashboard refresh for threat data
THREAT_DASHBOARD_REFRESH = 5000           # ms — refresh threat cards every 5s

# Auto-Response Engine — rate limits & safety
AUTO_RESPONSE_MAX_BLOCKS_PER_HOUR = 50    # Max firewall blocks per hour
AUTO_RESPONSE_MAX_BLOCKS_PER_DAY = 200    # Max firewall blocks per day
AUTO_RESPONSE_DEFAULT_BLOCK_HOURS = 24    # Default block duration (hours)

# Remote Command Executor — polling & security
# IR (kill/logoff/block): sub-second poll — dashboard must feel instant
REMOTE_CMD_POLL_INTERVAL = max(1, int(get_from_config(
    "threat_detection.command_poll_interval", 1)))
REMOTE_CMD_IR_POLL_INTERVAL = 0.5         # Fast poll while IR / after IR burst
REMOTE_CMD_IR_STICKY_SECONDS = 45         # Stay on IR cadence after urgent cmd
REMOTE_CMD_EXPIRY_SECONDS = 300           # Commands expire after 5 minutes
REMOTE_CMD_MAX_PER_MINUTE = 30            # Rate limit for non-IR cmds (IR exempt)

# Silent Hours — defaults (OFF; alert-only when enabled — never auto-disable)
SILENT_HOURS_ENABLED = get_from_config("silent_hours.enabled", False)
SILENT_HOURS_DEFAULT_MODE = "night_only"  # night_only | outside_working | always | custom
SILENT_HOURS_NIGHT_START = "00:00"
SILENT_HOURS_NIGHT_END = "07:00"
SILENT_HOURS_WORK_START = "08:00"
SILENT_HOURS_WORK_END = "18:00"
SILENT_HOURS_WEEKEND_SILENT = False       # Was True → weekend false positives

# Config sync — pull threat/silent hours config from backend
THREAT_CONFIG_SYNC_INTERVAL = 300         # Re-fetch threat config every 5 min (V4)

# Ransomware Shield — canary & detection intervals
RANSOMWARE_CANARY_CHECK_INTERVAL = 30     # Canary integrity check (seconds)
# Soft single-file MODIFIED debounce (all paths) — hygiene §3 / 30 dk loop
CANARY_SOFT_DEBOUNCE_SEC = 1800

RANSOMWARE_PROCESS_CHECK_INTERVAL = 2     # Suspicious process poll (VSS wipe race)
RANSOMWARE_VSS_CHECK_INTERVAL = 120       # Check VSS shadow copies every 2min
ENABLE_RANSOMWARE_SHIELD = get_from_config("ransomware_shield.enabled", True)

# System Health Monitor — collection & reporting
HEALTH_COLLECT_INTERVAL = 10              # Collect metrics every 10s
HEALTH_REPORT_INTERVAL = 60               # Report to API every 60s (V4)
HEALTH_ANOMALY_Z_THRESHOLD = 3.0          # Z-score threshold for anomaly

# Self-Protection — last breath & DACL
ENABLE_SELF_PROTECTION = get_from_config("self_protection.enabled", True)
LAST_BREATH_THREAT_WINDOW = 60            # Consider threats within 60s
LAST_BREATH_MIN_SCORE = 70                # Min threat score to trigger block

# Performance Optimizer — adaptive throttling (v4.0 Faz 4)
PERF_ADAPTIVE_CHECK_INTERVAL = 30         # Re-evaluate resource usage every 30s
PERF_CPU_HIGH_THRESHOLD = 85              # Start throttling above 85% CPU
PERF_CPU_CRITICAL_THRESHOLD = 95          # Aggressive throttling above 95%
PERF_MAX_EVENTS_PER_SECOND = 50           # Event processing rate limit
ENABLE_PERFORMANCE_OPTIMIZER = get_from_config("performance_optimizer.enabled", True)

# False Positive Tuner — cooldown & whitelist learning (v4.0 Faz 4)
FP_AUTO_WHITELIST_MIN_EVENTS = 50         # Min events before auto-whitelist
FP_AUTO_WHITELIST_MAX_SCORE = 10          # Max score for auto-whitelist
FP_COOLDOWN_CLEANUP_INTERVAL = 3600       # Clean stale cooldowns every hour
ENABLE_FALSE_POSITIVE_TUNER = get_from_config("false_positive_tuner.enabled", True)

# Threat Summary — periodic fetch (v4.0 Faz 4)
THREAT_SUMMARY_FETCH_INTERVAL = 300       # Fetch threat summary every 5 min


def iter_install_dirs() -> list:
    """Primary Asteria install dir first, then legacy YesNext path(s)."""
    roots = []
    for key in ("ProgramFiles", "ProgramFiles(x86)"):
        root = os.environ.get(key)
        if root:
            roots.append(root)
    if not roots:
        roots = [r"C:\Program Files"]
    dirs = []
    for root in roots:
        dirs.append(os.path.join(root, INSTALL_VENDOR_DIR, INSTALL_DIR_NAME))
        dirs.append(os.path.join(root, LEGACY_INSTALL_VENDOR_DIR, LEGACY_INSTALL_DIR_NAME))
        dirs.append(os.path.join(root, LEGACY_INSTALL_VENDOR_DIR, "CloudHoneypotClient"))
    # stable unique order
    seen = set()
    out = []
    for d in dirs:
        if d not in seen:
            seen.add(d)
            out.append(d)
    return out


def resolve_client_exe_path(preferred: str = "") -> str:
    """Find asteria-client.exe (or legacy honeypot-client.exe) on disk."""
    candidates = []
    if preferred:
        candidates.append(preferred)
    try:
        import sys
        if getattr(sys, "frozen", False):
            candidates.append(sys.executable)
    except Exception:
        pass
    for d in iter_install_dirs():
        for name in CLIENT_EXE_ALIASES:
            candidates.append(os.path.join(d, name))
    for path in candidates:
        try:
            if path and os.path.isfile(path):
                return path
        except OSError:
            continue
    # Default new-install expectation even if not yet present
    pf = os.environ.get("ProgramFiles", r"C:\Program Files")
    return os.path.join(pf, INSTALL_VENDOR_DIR, INSTALL_DIR_NAME, CLIENT_EXE_NAME)


# ===================== EXPORT ALL CONSTANTS ===================== #

# For easy importing: from client_constants import *
__all__ = [
    # Application metadata
    '__version__', 'APP_NAME', 'BRAND_NAME', 'VENDOR_NAME',
    'GITHUB_OWNER', 'GITHUB_REPO', 'GITHUB_REPO_LEGACY',
    'INSTALLER_ASSET_NAME', 'INSTALLER_ASSET_NAME_LEGACY', 'INSTALLER_FILE_PREFIXES',
    'CLIENT_EXE_NAME', 'CLIENT_EXE_ALIASES',
    
    # Network configuration  
    'API_URL', 'API_URL_LEGACY', 'CONTROL_HOST', 'CONTROL_PORT', 'SERVER_NAME', 'CONNECT_TIMEOUT',
    
    # Honeypot service definitions
    'HONEYPOT_SERVICES', 'SSH_BANNER', 'FTP_BANNER', 'MYSQL_VERSION', 'MSSQL_VERSION', 'RDP_CERT_CN',
    'MAX_CREDENTIAL_LENGTH', 'MAX_ATTEMPTS_PER_IP_PER_MIN',
    'CREDENTIAL_BATCH_SIZE', 'CREDENTIAL_BATCH_INTERVAL',
    'HONEYPOT_AUTO_RESTART_MAX', 'HONEYPOT_RESTART_BACKOFF',
    
    # Service configuration (loaded from config)
    'DEFAULT_SERVICES', 'SERVICE_TABLE',
    
    # Security
    'RDP_SECURE_PORT', 'DEFENDER_MARKERS', 'SECURITY_METADATA', 'LEGITIMATE_DOMAINS', 'RESTRICTED_PATHS',
    
    # File paths
    'APP_DIR', 'MACHINE_DATA_DIR', 'TOKEN_FILE',
    'LOG_FILE', 'CONSENT_FILE', 'STATUS_FILE', 'WATCHDOG_TOKEN_FILE', 'TASK_STATE_FILE',
    
    # GUI configuration
    'WINDOW_WIDTH', 'WINDOW_HEIGHT', 'WINDOW_TITLE', 'TRY_TRAY', 'GUI_DASHBOARD_REFRESH_MS',
    
    # Windows integration
    'APP_STARTUP_KEY', 'REGISTRY_KEY_PATH',
    
    # Timing
    'API_RETRY_INTERVAL', 'API_HEARTBEAT_INTERVAL', 'FILE_HEARTBEAT_INTERVAL',
    'ATTACK_COUNT_REFRESH',
    'SERVICE_SYNC_INTERVAL', 'SERVICE_SYNC_CHECK', 'SERVICE_WATCHDOG_INTERVAL',
    'BLOCK_POLL_INTERVAL', 'PORT_REPORT_INTERVAL',
    'API_STARTUP_DELAY', 'RDP_TRANSITION_TIMEOUT',
    
    # Logging
    'LOG_MAX_BYTES', 'LOG_BACKUP_COUNT', 'LOG_RETENTION_DAYS', 'LOG_ENCODING', 'LOG_TIME_FORMAT',
    
    # API settings
    'API_MAX_QUICK_RETRIES', 'API_QUICK_RETRY_DELAY', 'API_SLOW_RETRY_DELAY', 'API_REQUEST_TIMEOUT',
    
    # Feature flags
    'ENABLE_AUTO_UPDATE', 'ENABLE_TRAY_ICON', 'ENABLE_ADMIN_ELEVATION',
    'DEBUG_MODE', 'VERBOSE_LOGGING', 'SILENT_ADMIN_ELEVATION', 'SKIP_USER_DIALOGS',
    
    # Threat detection (v4.0)
    'ENABLE_THREAT_DETECTION',
    'EVENTLOG_WATCHDOG_INTERVAL',
    'THREAT_SCORE_DECAY_INTERVAL', 'THREAT_CONTEXT_MAX_AGE', 'THREAT_ALERT_MIN_SCORE',
    'ALERT_BATCH_FLUSH_INTERVAL', 'ALERT_BATCH_MAX_SIZE',
    'ALERT_THREAT_LOG_FILE', 'ALERT_THREAT_LOG_MAX_BYTES', 'ALERT_THREAT_LOG_BACKUP_COUNT',
    'THREAT_DASHBOARD_REFRESH',

    # Auto-response & remote commands (v4.0 Faz 2)
    'AUTO_RESPONSE_MAX_BLOCKS_PER_HOUR', 'AUTO_RESPONSE_MAX_BLOCKS_PER_DAY',
    'AUTO_RESPONSE_DEFAULT_BLOCK_HOURS',
    'REMOTE_CMD_POLL_INTERVAL', 'REMOTE_CMD_IR_POLL_INTERVAL',
    'REMOTE_CMD_IR_STICKY_SECONDS',
    'REMOTE_CMD_EXPIRY_SECONDS', 'REMOTE_CMD_MAX_PER_MINUTE',
    'SILENT_HOURS_ENABLED', 'SILENT_HOURS_DEFAULT_MODE',
    'SILENT_HOURS_NIGHT_START', 'SILENT_HOURS_NIGHT_END',
    'SILENT_HOURS_WORK_START', 'SILENT_HOURS_WORK_END',
    'SILENT_HOURS_WEEKEND_SILENT',
    'THREAT_CONFIG_SYNC_INTERVAL',

    # Ransomware shield & system health & self-protection (v4.0 Faz 3)
    'RANSOMWARE_CANARY_CHECK_INTERVAL', 'RANSOMWARE_PROCESS_CHECK_INTERVAL',
    'RANSOMWARE_VSS_CHECK_INTERVAL', 'ENABLE_RANSOMWARE_SHIELD',
    'HEALTH_COLLECT_INTERVAL', 'HEALTH_REPORT_INTERVAL', 'HEALTH_ANOMALY_Z_THRESHOLD',
    'ENABLE_SELF_PROTECTION', 'LAST_BREATH_THREAT_WINDOW', 'LAST_BREATH_MIN_SCORE',

    # Performance optimizer & false positive tuner (v4.0 Faz 4)
    'PERF_ADAPTIVE_CHECK_INTERVAL', 'PERF_CPU_HIGH_THRESHOLD', 'PERF_CPU_CRITICAL_THRESHOLD',
    'PERF_MAX_EVENTS_PER_SECOND', 'ENABLE_PERFORMANCE_OPTIMIZER',
    'FP_AUTO_WHITELIST_MIN_EVENTS', 'FP_AUTO_WHITELIST_MAX_SCORE',
    'FP_COOLDOWN_CLEANUP_INTERVAL', 'ENABLE_FALSE_POSITIVE_TUNER',
    'THREAT_SUMMARY_FETCH_INTERVAL',
    
    # Helper functions
    'get_app_config', 'get_app_directory', 'get_window_dimensions',
    'get_default_services', 'get_service_table',
]
