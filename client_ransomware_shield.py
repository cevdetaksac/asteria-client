#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Asteria Client — Ransomware Shield (v4.0 Faz 3)

Çok katmanlı ransomware algılama ve savunma sistemi.

Katmanlar:
  1. Canary Files — Stratejik konumlara tuzak dosyalar yerleştirilir.
     Herhangi bir değişiklik/silme/rename → Skor 100 → Anlık alert.
  2. File System Watchdog — Toplu dosya operasyonlarını izler.
     Kısa sürede çok fazla rename/modify → ransomware göstergesi.
  3. Suspicious Process Detector — vssadmin delete shadows,
     bcdedit /set recoveryenabled no, cipher /w gibi komutları tespit eder.
  4. VSS Monitor — Shadow Copy sayısı azaldıysa → ransomware.

Akış:
  - Her katman bağımsız çalışır ve ThreatEngine'e skor besler.
  - Canary/VSS hit → süreç öldür + IFEO karantina (dashboard/app unlock).
  - Skor 100'e ulaşırsa AutoResponse.emergency_lockdown() tetiklenebilir.
  - API'ye "ransomware_detected" tipinde urgent alert gönderilir.

Gizleme dengesi: ADS / aşırı obscure path ransomware enum'undan kaçar
→ canary işe yaramaz. Hidden+System + erken sort (!000_) doğru denge.

NOT: System Health "disk full" / IDE disk I/O kapasite veya performans
uyarılarıdır — ransomware DEĞİLDİR. Gerçek ransomware sinyalleri:
canary, VSS silme, toplu rename, şüpheli process (vssadmin/bcdedit).

Exports:
  RansomwareShield — ana sınıf (start / stop / get_stats / unlock_quarantine)
"""

import ctypes
import hashlib
import json
import os
import re
import secrets
import subprocess
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set

from client_helpers import log

# ── Constants ─────────────────────────────────────────────────────

CREATE_NO_WINDOW = 0x08000000

# Hidden+System + sort-bait names (early in ransomware FindFirstFile walk).
# Admin notice → ProgramData only (not inside bait tree).
CANARY_ROOT_FOLDER = ".cloud-honeypot-canary"


def is_forbidden_canary_path(path: str) -> bool:
    """True for Desktop (any profile) — contract forbids Desktop canaries."""
    if not path:
        return True
    parts = os.path.normpath(str(path)).replace("/", "\\").lower().split("\\")
    return "desktop" in parts

CANARY_SUBFOLDER_NAMES = [
    "!000_reports",
    "!000_finance",
    "!000_archive",
]

_LEGACY_CANARY_SUBFOLDERS = ["reports", "finance", "archive"]

CANARY_FILES = [
    ("!000_quarterly_report.xlsx", 4096),
    ("!000_employee_list.csv", 3072),
    ("!000_contract_draft.pdf", 5120),
    ("!000_credentials_backup.docx", 2048),
    ("!000_recovery_keys.txt", 1024),
]

_LEGACY_CANARY_FILES = [
    ("quarterly_report.xlsx", 4096),
    ("employee_list.csv", 3072),
    ("contract_draft.pdf", 5120),
    ("credentials_backup.docx", 2048),
    ("recovery_keys.txt", 1024),
]

CANARY_README_CONTENT = """Asteria Client — koruma dosyalari (yonetici)

Bu dosyalar arka planda ransomware erken tespiti icindir.
Explorer'da gizli + sistem ozelliklidir; normal kullanicida gorunmez.

Silmeyin. Destek: destek@yesnext.com.tr
"""

_QUARANTINE_FILE = "ransomware_quarantine.json"
_PROTECTED_IMAGES = {
    "system", "smss.exe", "csrss.exe", "wininit.exe",
    "services.exe", "lsass.exe", "svchost.exe", "explorer.exe",
    "asteria-client.exe", "honeypot-client.exe", "winlogon.exe", "dwm.exe",
    # Benign scanners / sync / indexers — never IFEO-kill (UX + false positive)
    "searchindexer.exe", "searchprotocolhost.exe", "searchfilterhost.exe",
    "msmpeng.exe", "mpcmdrun.exe", "nissrv.exe", "securityhealthservice.exe",
    "onedrive.exe", "onedriveupdater.exe", "filecoauth.exe",
    "backup.exe", "sdclt.exe", "dllhost.exe", "runtimebroker.exe",
    "taskhostw.exe", "sihost.exe", "ctfmon.exe", "shellexperiencehost.exe",
    "startmenuexperiencehost.exe", "textinputhost.exe",
}

# Admin tools used in VSS wipe TTPs — kill + quarantine arm OK; NEVER IFEO
# (would break our own `vssadmin list shadows` / recovery tooling).
_NO_IFEO_ADMIN_TOOLS = {
    "vssadmin.exe", "wmic.exe", "powershell.exe", "pwsh.exe",
    "cmd.exe", "wbadmin.exe", "diskshadow.exe", "conhost.exe",
}

# Suspicious file extensions commonly used by ransomware
SUSPICIOUS_EXTENSIONS: Set[str] = {
    ".encrypted", ".locked", ".crypted", ".crypt",
    ".crypto", ".enc", ".locky", ".cerber", ".zepto",
    ".thor", ".aaa", ".abc", ".xyz", ".zzz",
    ".micro", ".fun", ".gws", ".btc", ".gryphon",
    ".pay", ".ransom", ".wncry", ".wcry",
}

# FS watchdog thresholds
FS_RENAMES_PER_MINUTE = 20
FS_MODIFICATIONS_PER_MINUTE = 50
FS_NEW_EXTENSION_RATIO = 0.3

# Processes that are suspicious when spawned.
# NOTE: vssadmin.exe is intentionally omitted — inventory `list shadows` is
# benign (agent VSS poll). Delete/wipe is caught via SUSPICIOUS_CMD_PATTERNS.
SUSPICIOUS_PROCESSES: Dict[str, str] = {
    "bcdedit.exe": "Boot config manipulation",
    "wbadmin.exe": "Backup deletion",
    "cipher.exe": "File encryption / disk wipe",
    "certutil.exe": "Certificate utility (download abuse)",
    "bitsadmin.exe": "BITS transfer (download abuse)",
    "mshta.exe": "HTML Application execution",
}

# Benign VSS inventory (agent poll / admin browse) — never ransomware_process
_VSS_LIST_SHADOWS_RE = re.compile(
    r"vssadmin(?:\.exe)?(?:\s+.+)?:\s*list\s+shadows|"
    r"vssadmin(?:\.exe)?\s+list\s+shadows",
    re.I,
)
_VSS_DELETE_CMD_RE = re.compile(
    r"vssadmin(?:\.exe)?\s+delete\s+shadows|"
    r"wmic\s+shadowcopy\s+delete|"
    r"wbadmin\s+delete|"
    r"Win32_ShadowCopy.*Delete\(",
    re.I,
)

# Command-line patterns that indicate ransomware activity
SUSPICIOUS_CMD_PATTERNS = [
    (re.compile(r"vssadmin\s+delete\s+shadows", re.I), "VSS shadow delete", 100),
    (re.compile(r"wmic\s+shadowcopy\s+delete", re.I), "VSS WMIC delete", 100),
    (re.compile(r"Get-WmiObject\s+Win32_ShadowCopy", re.I), "VSS WMI PowerShell", 95),
    (re.compile(r"Win32_ShadowCopy.*Delete\(\)", re.I), "VSS WMI delete", 100),
    (re.compile(r"bcdedit\s+/set\s+.*recoveryenabled\s+no", re.I), "Recovery disabled", 90),
    (re.compile(r"wbadmin\s+delete\s+catalog", re.I), "Backup catalog delete", 95),
    (re.compile(r"wbadmin\s+delete\s+systemstatebackup", re.I), "System state backup delete", 95),
    (re.compile(r"wbadmin\s+delete\s+backup", re.I), "Backup delete", 95),
    (re.compile(r"cipher\s+/w:", re.I), "Disk wipe via cipher", 80),
    (re.compile(r"fsutil\s+usn\s+deletejournal", re.I), "USN journal wipe", 90),
    (re.compile(r"wevtutil\s+cl\s+", re.I), "Event log clear", 70),
    (re.compile(r"net\s+stop\s+.*sql", re.I), "SQL service stop", 60),
    (re.compile(r"net\s+stop\s+.*backup", re.I), "Backup service stop", 70),
    (re.compile(r"net\s+stop\s+.*vss", re.I), "VSS service stop", 85),
    (re.compile(r"icacls\s+.*/grant\s+Everyone", re.I), "Permission broadening", 50),
    (re.compile(r"attrib\s+\+h\s+\+s", re.I), "File attribute hiding", 40),
]

# VSS check interval
VSS_CHECK_INTERVAL = 120  # seconds

# Canary hygiene (CLIENT_ALERT_SIGNAL_HYGIENE.md)
CANARY_SELF_TOUCH_GRACE_SEC = 90
CANARY_SYNC_DEBOUNCE_SEC = 1800  # ≥30 min for OneDrive / backup paths
CANARY_SOFT_DEBOUNCE_SEC = 1800  # ≥30 min soft single-file MODIFIED (any path)
CANARY_SOFT_CLUSTER_WINDOW_SEC = 120


def is_vss_inventory_cmdline(cmdline: str) -> bool:
    """True for `vssadmin list shadows` (agent inventory / admin browse)."""
    cl = (cmdline or "").strip()
    if not cl:
        # Empty cmdline on vssadmin.exe — treat as inventory, not delete.
        return True
    low = cl.lower()
    if "vssadmin" not in low:
        return False
    if is_vss_delete_cmdline(cl):
        return False
    if _VSS_LIST_SHADOWS_RE.search(cl):
        return True
    # Any non-delete vssadmin invocation (list, query, /?) is inventory noise.
    return "delete" not in low


def is_vss_delete_cmdline(cmdline: str) -> bool:
    return bool(_VSS_DELETE_CMD_RE.search(cmdline or ""))


def classify_shadow_copy_severity(
    deleted_count: int,
    remaining: int,
    *,
    delete_cmd_seen: bool = False,
) -> tuple:
    """Return (severity, threat_score) for shadow_copy_deleted hygiene."""
    if delete_cmd_seen or deleted_count >= 3 or remaining <= 0:
        return "critical", 100
    if deleted_count <= 2 and remaining >= 3:
        return "warning", 35
    return "warning", 45


# ── Dataclasses ───────────────────────────────────────────────────

@dataclass
class CanaryState:
    """Tracks a deployed canary file's fingerprint."""
    path: str
    sha256: str
    size: int
    deployed_at: float = field(default_factory=time.time)


# ── Ransomware Shield ────────────────────────────────────────────

class RansomwareShield:
    """
    Multi-layered ransomware detection and defence.

    Usage:
        shield = RansomwareShield(
            on_alert=threat_engine.process_event,
            auto_response=auto_response,
        )
        shield.start()
    """

    def __init__(
        self,
        on_alert: Optional[Callable] = None,
        auto_response=None,
        alert_pipeline=None,
        threat_engine=None,
    ):
        self.on_alert = on_alert
        self.auto_response = auto_response
        self.alert_pipeline = alert_pipeline
        self.threat_engine = threat_engine

        self._running = False
        self.canary_enabled = True

        # Canary state
        self._canaries: List[CanaryState] = []
        self._canary_dir: Optional[str] = None

        # FS watchdog counters (sliding 60-second window)
        self._fs_renames: deque = deque(maxlen=500)
        self._fs_modifications: deque = deque(maxlen=500)

        # VSS baseline
        self._vss_count: Optional[int] = None
        # Set when a delete-shadows cmdline is observed (forces critical VSS delta)
        self._vss_delete_cmd_until: float = 0.0

        # Process monitoring
        self._seen_pids: Set[int] = set()

        # Canary hygiene: self-touch grace + sync-path debounce + soft cluster
        self._canary_self_touch_until: Dict[str, float] = {}
        self._canary_path_alert_at: Dict[str, float] = {}
        self._canary_recent_hits: deque = deque(maxlen=32)

        # Stats
        self._stats = {
            "canary_alerts": 0,
            "fs_alerts": 0,
            "process_alerts": 0,
            "vss_alerts": 0,
            "total_detections": 0,
        }

        # Recent detections log
        self._detections: deque = deque(maxlen=50)

        # Cloud threat-intel merges (docs/CLOUD_THREAT_INTEL_API.md)
        self._cloud_extensions: Set[str] = set()
        self._cloud_processes: Dict[str, str] = {}
        self._cloud_cmdline_patterns: List = []

        # Quarantine / lockdown after canary or VSS hit
        self._quarantine_lock = threading.RLock()
        self._quarantine: Dict = {
            "active": False,
            "locked_at": "",
            "trigger": "",
            "entries": [],
        }
        self._quarantine_images: Set[str] = set()
        self._load_quarantine()
        self._stats["quarantine_active"] = bool(self._quarantine.get("active"))
        self._stats["quarantine_entries"] = len(self._quarantine.get("entries") or [])
        self._stats["quarantine_kills"] = 0

    # ── Lifecycle ─────────────────────────────────────────────────

    def start(self):
        """Start all ransomware protection layers."""
        if self._running:
            return
        self._running = True

        # Deploy canary files
        self._deploy_canaries()

        # Start monitoring threads
        threading.Thread(
            target=self._canary_watch_loop,
            name="RansomShield-Canary",
            daemon=True,
        ).start()

        threading.Thread(
            target=self._process_monitor_loop,
            name="RansomShield-Process",
            daemon=True,
        ).start()

        threading.Thread(
            target=self._vss_monitor_loop,
            name="RansomShield-VSS",
            daemon=True,
        ).start()

        threading.Thread(
            target=self._quarantine_enforce_loop,
            name="RansomShield-Quarantine",
            daemon=True,
        ).start()

        log("[RANSOMWARE-SHIELD] Started (canary + process + VSS + quarantine)")
        self._disarm_empty_quarantine("start_empty")
        if self._quarantine.get("active"):
            log(
                f"[RANSOMWARE-SHIELD] Quarantine STILL ACTIVE "
                f"({len(self._quarantine_images)} image(s)) — unlock via dashboard/app"
            )

    def stop(self):
        """Stop all monitoring."""
        self._running = False
        log("[RANSOMWARE-SHIELD] ✅ Stopped")

    def get_stats(self) -> dict:
        s = dict(self._stats)
        s["running"] = self._running
        s["canary_files"] = len(self._canaries)
        # DEC-201/202 bounded coverage inventory; no user paths leave host.
        intact = 0
        covered_roots = set()
        for canary in self._canaries:
            try:
                if os.path.isfile(canary.path):
                    intact += 1
                marker = canary.path.lower().split(
                    CANARY_ROOT_FOLDER.lower(), 1
                )[0]
                covered_roots.add(marker)
            except Exception:
                pass
        s["canary_coverage"] = {
            "mode": "observe",
            "configured": bool(self.canary_enabled),
            "files_total": len(self._canaries),
            "files_intact": intact,
            "files_missing": max(0, len(self._canaries) - intact),
            "roots_covered": len(covered_roots),
            "coverage_ok": bool(self._canaries) and intact == len(self._canaries),
        }
        s["alerts_total"] = (
            s.get("canary_alerts", 0)
            + s.get("fs_alerts", 0)
            + s.get("process_alerts", 0)
            + s.get("vss_alerts", 0)
        )
        with self._quarantine_lock:
            s["quarantine_active"] = bool(self._quarantine.get("active"))
            s["quarantine_entries"] = len(self._quarantine.get("entries") or [])
            s["quarantine_trigger"] = self._quarantine.get("trigger") or ""
            s["quarantine_locked_at"] = self._quarantine.get("locked_at") or ""
        return s

    def get_detections(self) -> list:
        return list(self._detections)

    def get_quarantine(self) -> dict:
        with self._quarantine_lock:
            return dict(self._quarantine)

    def unlock_quarantine(self, reason: str = "manual") -> dict:
        """Clear IFEO blocks + quarantine flag (dashboard / GUI / IPC)."""
        removed = []
        with self._quarantine_lock:
            for entry in list(self._quarantine.get("entries") or []):
                image = (entry.get("image") or "").strip()
                if image and self._clear_ifeo(image):
                    removed.append(image)
            self._quarantine = {
                "active": False,
                "locked_at": "",
                "trigger": "",
                "entries": [],
                "unlocked_at": datetime.now().isoformat(),
                "unlock_reason": reason,
            }
            self._quarantine_images.clear()
            self._stats["quarantine_active"] = False
            self._stats["quarantine_entries"] = 0
            self._persist_quarantine()
        log(f"[RANSOMWARE-SHIELD] Quarantine unlocked ({reason}); cleared={removed}")
        return {"ok": True, "cleared": removed, "reason": reason}

    # ── Katman 1: Canary Files ────────────────────────────────────

    def _deploy_canaries(self):
        """Create sort-bait canaries (Hidden+System) in non-Desktop locations.

        Strategy:
        - NEVER use Desktop
        - Root: .cloud-honeypot-canary (H+S)
        - Subfolders/files prefixed !000_ so ransomware enum hits them early
        - Admin README only in ProgramData (not inside bait tree)
        - Still fingerprint legacy plain-named canaries if present
        """
        try:
            self._write_admin_canary_notice()

            user_profile = os.environ.get("USERPROFILE", "C:\\Users\\Public")
            base_dirs = [
                os.path.join("C:\\Users\\Public", "Documents"),
                os.path.join(os.environ.get("ProgramData", "C:\\ProgramData")),
            ]
            # SYSTEM profile Documents only if not a confusing path
            sys_docs = os.path.join(user_profile, "Documents")
            if not self._is_onedrive_path(sys_docs):
                base_dirs.insert(0, sys_docs)

            # Interactive users' Documents — skip OneDrive-backed (sync scare + quota)
            for up in self._interactive_user_profiles():
                docs = os.path.join(up, "Documents")
                if self._is_onedrive_path(docs):
                    log(f"[RANSOMWARE-SHIELD] skip OneDrive Documents canary: {docs}")
                    continue
                if docs not in base_dirs:
                    base_dirs.append(docs)

            self._canaries = []
            for base_dir in base_dirs:
                canary_root = os.path.join(base_dir, CANARY_ROOT_FOLDER)
                try:
                    os.makedirs(canary_root, exist_ok=True)
                except OSError:
                    continue

                # Remove bait-tree README if older builds left one (sorts early as R*)
                for noise in ("README.txt", "README.md"):
                    try:
                        noise_path = os.path.join(canary_root, noise)
                        if os.path.isfile(noise_path):
                            os.remove(noise_path)
                    except OSError:
                        pass

                self._set_hidden_attribute(canary_root)

                for subfolder in CANARY_SUBFOLDER_NAMES:
                    canary_dir = os.path.join(canary_root, subfolder)
                    try:
                        os.makedirs(canary_dir, exist_ok=True)
                    except OSError:
                        continue
                    self._set_hidden_attribute(canary_dir)

                    for filename, target_size in CANARY_FILES:
                        filepath = os.path.join(canary_dir, filename)
                        try:
                            if not os.path.exists(filepath):
                                content = secrets.token_bytes(target_size)
                                with open(filepath, "wb") as f:
                                    f.write(content)
                                self._note_canary_self_touch(filepath)
                            self._set_hidden_attribute(filepath)
                            file_hash = self._file_hash(filepath)
                            if file_hash:
                                self._note_canary_self_touch(filepath)
                                self._canaries.append(CanaryState(
                                    path=filepath,
                                    sha256=file_hash,
                                    size=os.path.getsize(filepath),
                                ))
                        except OSError:
                            continue

                # Keep watching legacy names if still on disk (pre-4.5.62)
                for subfolder in _LEGACY_CANARY_SUBFOLDERS:
                    canary_dir = os.path.join(canary_root, subfolder)
                    if not os.path.isdir(canary_dir):
                        continue
                    self._set_hidden_attribute(canary_dir)
                    for filename, _sz in _LEGACY_CANARY_FILES:
                        filepath = os.path.join(canary_dir, filename)
                        if not os.path.isfile(filepath):
                            continue
                        self._set_hidden_attribute(filepath)
                        file_hash = self._file_hash(filepath)
                        if file_hash:
                            self._canaries.append(CanaryState(
                                path=filepath,
                                sha256=file_hash,
                                size=os.path.getsize(filepath),
                            ))

            self._cleanup_legacy_canaries()
            self._register_existing_canary_trees()

            log(
                f"[RANSOMWARE-SHIELD] Deployed {len(self._canaries)} canary files "
                f"(sort-bait + Hidden+System)"
            )

            try:
                from client_utils import get_from_config
                extra = get_from_config("threat_detection.canary_file_paths", None)
                if not extra:
                    extra = get_from_config("canary_file_paths", [])
                for filepath in (extra or []):
                    try:
                        if is_forbidden_canary_path(filepath):
                            log(
                                "[RANSOMWARE-SHIELD] skip Desktop/config canary "
                                f"(forbidden): {filepath}"
                            )
                            try:
                                if os.path.isfile(filepath):
                                    os.remove(filepath)
                            except OSError:
                                pass
                            continue
                        d = os.path.dirname(filepath)
                        if d:
                            os.makedirs(d, exist_ok=True)
                        if not os.path.exists(filepath):
                            with open(filepath, "wb") as f:
                                f.write(secrets.token_bytes(4096))
                            self._note_canary_self_touch(filepath)
                        self._set_hidden_attribute(filepath)
                        file_hash = self._file_hash(filepath)
                        if file_hash:
                            self._note_canary_self_touch(filepath)
                            self._canaries.append(CanaryState(
                                path=filepath,
                                sha256=file_hash,
                                size=os.path.getsize(filepath),
                            ))
                    except OSError:
                        continue
            except Exception as e:
                log(f"[RANSOMWARE-SHIELD] Config canary paths error: {e}")
        except Exception as e:
            log(f"[RANSOMWARE-SHIELD] Canary deploy error: {e}")

    def _write_admin_canary_notice(self):
        """Admin-facing notice outside bait tree (ProgramData)."""
        try:
            from client_utils import _programdata_client_dir
            base = _programdata_client_dir()
        except Exception:
            base = os.path.join(
                os.environ.get("ProgramData", r"C:\ProgramData"),
                "Asteria",
            )
        try:
            os.makedirs(base, exist_ok=True)
            path = os.path.join(base, "CANARY_README.txt")
            if not os.path.exists(path):
                with open(path, "w", encoding="utf-8") as f:
                    f.write(CANARY_README_CONTENT)
        except OSError:
            pass

    @staticmethod
    def _interactive_user_profiles() -> List[str]:
        """Return interactive user profile dirs (exclude Default/Public/system)."""
        out: List[str] = []
        skip = {
            "public", "default", "default user", "all users",
            "defaultuser0", "wdagutilityaccount", "systemprofile",
        }
        # Preferred: ProfileList (works under SYSTEM)
        try:
            import winreg
            key_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as root:
                i = 0
                while True:
                    try:
                        sid = winreg.EnumKey(root, i)
                        i += 1
                    except OSError:
                        break
                    if not sid.startswith("S-1-5-21-"):
                        continue
                    try:
                        with winreg.OpenKey(root, sid) as sk:
                            profile, _ = winreg.QueryValueEx(sk, "ProfileImagePath")
                    except OSError:
                        continue
                    profile = os.path.expandvars(str(profile or "")).strip()
                    if not profile or not os.path.isdir(profile):
                        continue
                    name = os.path.basename(profile).lower()
                    if name in skip:
                        continue
                    out.append(profile)
        except Exception:
            pass

        # Fallback: C:\Users\*
        if not out:
            users_root = os.path.join(os.environ.get("SystemDrive", "C:"), "Users")
            try:
                for name in os.listdir(users_root):
                    if name.lower() in skip:
                        continue
                    path = os.path.join(users_root, name)
                    if os.path.isdir(path):
                        out.append(path)
            except OSError:
                pass
        return out

    def _register_existing_canary_trees(self) -> None:
        """Watch any .cloud-honeypot-canary trees under Users (even if deploy skipped)."""
        users_root = os.path.join(os.environ.get("SystemDrive", "C:"), "Users")
        known = {c.path.lower() for c in self._canaries}
        try:
            names = os.listdir(users_root)
        except OSError:
            return
        for name in names:
            root = os.path.join(users_root, name, "Documents", CANARY_ROOT_FOLDER)
            if not os.path.isdir(root):
                continue
            if self._is_onedrive_path(root):
                continue
            self._set_hidden_attribute(root)
            for dirpath, _dns, fns in os.walk(root):
                for fn in fns:
                    if not (fn.startswith("!000_") or fn in {x[0] for x in _LEGACY_CANARY_FILES}):
                        continue
                    filepath = os.path.join(dirpath, fn)
                    key = filepath.lower()
                    if key in known:
                        continue
                    try:
                        self._set_hidden_attribute(filepath)
                        file_hash = self._file_hash(filepath)
                        if not file_hash:
                            continue
                        self._canaries.append(CanaryState(
                            path=filepath,
                            sha256=file_hash,
                            size=os.path.getsize(filepath),
                        ))
                        known.add(key)
                    except OSError:
                        continue

    @staticmethod
    def _is_onedrive_path(path: str) -> bool:
        """True if path is under OneDrive (sync would expose bait to user cloud UI)."""
        p = (path or "").lower().replace("/", "\\")
        if "onedrive" in p:
            return True
        try:
            # Resolve junctions (Documents → OneDrive\Documents)
            real = os.path.realpath(path).lower().replace("/", "\\")
            if "onedrive" in real:
                return True
        except OSError:
            pass
        return False

    @staticmethod
    def _set_hidden_attribute(folder_path: str):
        """Hidden + System + NotContentIndexed — invisible in normal Explorer, skip Search."""
        try:
            FILE_ATTRIBUTE_HIDDEN = 0x02
            FILE_ATTRIBUTE_SYSTEM = 0x04
            FILE_ATTRIBUTE_NOT_CONTENT_INDEXED = 0x2000
            ctypes.windll.kernel32.SetFileAttributesW(
                str(folder_path),
                FILE_ATTRIBUTE_HIDDEN
                | FILE_ATTRIBUTE_SYSTEM
                | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED,
            )
        except Exception:
            pass  # Non-Windows or permission issue, silently skip

    def _cleanup_legacy_canaries(self):
        """Remove old-style canary folders from Desktop (pre-v4.0.2).

        Previous versions placed highly visible folders on the Desktop
        which alarmed administrators.  Clean them up silently.
        """
        import shutil

        legacy_folder_names = ["IMPORTANT_DOCUMENTS", "Financial_Reports", "Company_Data"]
        user_profile = os.environ.get("USERPROFILE", "")
        if not user_profile:
            return

        legacy_bases = [
            os.path.join(user_profile, "Desktop"),
            os.path.join(user_profile, "Documents"),
            os.path.join("C:\\Users\\Public", "Documents"),
        ]

        for base in legacy_bases:
            for folder_name in legacy_folder_names:
                legacy_path = os.path.join(base, folder_name)
                if os.path.isdir(legacy_path):
                    try:
                        shutil.rmtree(legacy_path)
                        log(f"[RANSOMWARE-SHIELD] 🧹 Cleaned legacy canary: {legacy_path}")
                    except OSError:
                        pass

    def _note_canary_self_touch(self, path: str, grace_sec: float = CANARY_SELF_TOUCH_GRACE_SEC):
        """Agent wrote/refreshed this canary — suppress alerts briefly."""
        key = os.path.normcase(os.path.abspath(path)) if path else ""
        if key:
            self._canary_self_touch_until[key] = time.time() + float(grace_sec)

    def _is_canary_self_touch(self, path: str) -> bool:
        key = os.path.normcase(os.path.abspath(path)) if path else ""
        until = self._canary_self_touch_until.get(key, 0.0)
        return bool(key) and time.time() < until

    def _is_sync_canary_path(self, path: str) -> bool:
        p = (path or "").lower().replace("/", "\\")
        if self._is_onedrive_path(path):
            return True
        markers = (
            "\\backup\\", "\\backups\\", "\\dropbox\\", "\\google drive\\",
            "\\box\\", "\\icloud\\",
        )
        return any(m in p for m in markers)

    def _canary_watch_loop(self):
        """Periodically check canary file integrity (default 30s)."""
        while self._running:
            try:
                if getattr(self, "canary_enabled", True):
                    for canary in self._canaries:
                        if not os.path.exists(canary.path):
                            # DELETED — ransomware indicator!
                            self._on_canary_triggered(canary, "DELETED")
                            continue

                        current_hash = self._file_hash(canary.path)
                        current_size = None
                        try:
                            current_size = os.path.getsize(canary.path)
                        except OSError:
                            current_size = None

                        hash_changed = bool(
                            current_hash and current_hash != canary.sha256
                        )
                        size_changed = (
                            current_size is not None and current_size != canary.size
                        )

                        if hash_changed or size_changed:
                            if self._is_canary_self_touch(canary.path):
                                # Agent own write / hash refresh — silent resync
                                if current_hash:
                                    canary.sha256 = current_hash
                                if current_size is not None:
                                    canary.size = current_size
                                continue

                            change = "MODIFIED" if hash_changed else "SIZE_CHANGED"
                            self._on_canary_triggered(canary, change)
                            if current_hash:
                                canary.sha256 = current_hash
                            if current_size is not None:
                                canary.size = current_size
            except Exception as e:
                log(f"[RANSOMWARE-SHIELD] Canary check error: {e}")

            try:
                from client_constants import RANSOMWARE_CANARY_CHECK_INTERVAL
                interval = int(RANSOMWARE_CANARY_CHECK_INTERVAL)
            except Exception:
                interval = 30
            time.sleep(interval)

    def _on_canary_triggered(self, canary: CanaryState, change_type: str):
        """Canary file was tampered with — severity depends on confidence."""
        if self._is_canary_self_touch(canary.path):
            log(
                f"[RANSOMWARE-SHIELD] canary self-touch suppressed: "
                f"{os.path.basename(canary.path)}"
            )
            return

        now = time.time()
        path_key = os.path.normcase(os.path.abspath(canary.path))
        if self._is_sync_canary_path(canary.path):
            last = self._canary_path_alert_at.get(path_key, 0.0)
            if now - last < CANARY_SYNC_DEBOUNCE_SEC:
                log(
                    f"[RANSOMWARE-SHIELD] canary sync debounce: "
                    f"{os.path.basename(canary.path)}"
                )
                try:
                    h = self._file_hash(canary.path)
                    if h:
                        canary.sha256 = h
                    canary.size = os.path.getsize(canary.path)
                except OSError:
                    pass
                return

        self._canary_recent_hits.append((now, path_key))
        recent_paths = {
            p for (ts, p) in self._canary_recent_hits
            if now - ts <= CANARY_SOFT_CLUSTER_WINDOW_SEC
        }
        multi_canary = len(recent_paths) >= 2
        vss_ok = self._vss_count is None or int(self._vss_count) >= 1

        self._stats["canary_alerts"] += 1
        self._stats["total_detections"] += 1

        filename = os.path.basename(canary.path)
        log(f"[RANSOMWARE-SHIELD] 🚨 CANARY TRIGGERED: {filename} — {change_type}")

        detection = {
            "type": "canary_triggered",
            "file": canary.path,
            "change": change_type,
            "threat_score": 100,
            "timestamp": datetime.now().isoformat(),
        }
        self._detections.append(detection)

        containment = {
            "trigger": f"canary {change_type}: {canary.path}",
            "suspects": [],
            "actions": [],
            "quarantine": {"active": False, "entries": 0, "kills": 0},
        }
        plan = {"action": "kill_quarantine", "contain": True, "kill": True,
                "alert_only": False, "force_urgent": True}
        try:
            from client_defense_policy import process_action_plan
            plan = process_action_plan("canary_write")
        except Exception:
            pass

        if plan.get("contain") and not plan.get("alert_only"):
            try:
                containment = self._contain_after_hit(
                    trigger=containment["trigger"],
                    focus_path=canary.path,
                    mode="suspend" if plan.get("suspend") and not plan.get("kill") else "kill",
                )
            except Exception as e:
                log(f"[RANSOMWARE-SHIELD] containment error before urgent: {e}")
        else:
            # observe / alert_only — find suspects for context but do not kill
            try:
                suspects_only = self._find_suspect_processes(canary.path)
                containment["suspects"] = suspects_only
                containment["actions"] = ["alert_only"]
            except Exception:
                pass
            log(
                f"[RANSOMWARE-SHIELD] canary matrix action={plan.get('action')} "
                f"— skip kill/quarantine"
            )

        suspects = list(containment.get("suspects") or [])
        has_suspect = bool(suspects)
        # Single-file MODIFIED + healthy VSS + no writer → warning (sync/AV noise)
        soft = (
            change_type in ("MODIFIED", "SIZE_CHANGED")
            and not multi_canary
            and not has_suspect
            and vss_ok
        )
        if soft:
            severity = "warning"
            threat_score = 40
            recommended = "review_canary"
            try:
                from client_constants import CANARY_SOFT_DEBOUNCE_SEC as _soft_sec
            except Exception:
                _soft_sec = CANARY_SOFT_DEBOUNCE_SEC
            last_soft = self._canary_path_alert_at.get(path_key, 0.0)
            if now - last_soft < float(_soft_sec):
                log(
                    f"[RANSOMWARE-SHIELD] canary soft debounce "
                    f"({int(_soft_sec)}s): {filename}"
                )
                self._disarm_empty_quarantine("canary_soft_debounce")
                return
            self._disarm_empty_quarantine("canary_soft")
        else:
            severity = "critical"
            threat_score = 100
            # Anti-bait: never recommend isolate_host from single canary (P0)
            if plan.get("alert_only"):
                recommended = "review_canary"
            elif plan.get("suspend"):
                recommended = "resume_or_allow_process"
            else:
                recommended = "review_quarantine"

        detection["threat_score"] = threat_score
        ransomware_context = {
            "trigger": containment.get("trigger") or (
                f"canary {change_type}: {canary.path}"
            ),
            "file": canary.path,
            "change_type": change_type,
            "suspects": suspects,
            "quarantine": dict(containment.get("quarantine") or {}),
            "soft": soft,
            "multi_canary": multi_canary,
        }
        raw_events = [{
            "event_type": "canary_file_tampered",
            "file": canary.path,
            "full_path": canary.path,
            "change_type": change_type,
            "timestamp": detection["timestamp"],
        }]
        raw_events.extend(
            {
                "event_type": "ransomware_suspect_process",
                "process_name": suspect.get("image") or "",
                "image": suspect.get("image") or "",
                "process_path": suspect.get("path") or "",
                "path": suspect.get("path") or "",
                "pid": suspect.get("pid") or 0,
                "cmdline": suspect.get("cmdline") or "",
                "command_line": suspect.get("cmdline") or "",
                "sha256": suspect.get("sha256") or "",
            }
            for suspect in suspects
            if isinstance(suspect, dict)
        )

        self._canary_path_alert_at[path_key] = now

        urgent = {
            "event_type": "canary_file_tampered",
            "severity": severity,
            "threat_type": "ransomware_canary_triggered",
            "title": (
                f"Canary dosya {change_type} (inceleme)"
                if soft
                else f"Ransomware Tespiti — Canary dosya {change_type}!"
            ),
            "description": (
                (
                    f"Tek canary {change_type} — VSS saglam, supheli surec yok. "
                    f"Sync/AV/self-touch olasi. Dosya: {canary.path}"
                )
                if soft
                else (
                    f"Tuzak dosya '{filename}' degistirildi/silindi. "
                    f"Bu, aktif bir ransomware saldirisinin guclu gostergesidir.\n\n"
                    f"Dosya: {canary.path}\n"
                    f"Degisiklik: {change_type}\n\n"
                    f"Acil mudahale onerilir!"
                )
            ),
            "threat_score": threat_score,
            "target_service": "SYSTEM",
            "recommended_action": recommended,
            "auto_response_taken": (
                (["alert_only"] if soft else ["emergency_alert"])
                + ([f"matrix:{plan.get('action')}"] if plan.get("action") else [])
                + list(containment.get("actions") or [])
            ),
            "raw_events": raw_events,
            "system_context": {"ransomware": ransomware_context},
            "details": {
                "file": filename,
                "change_type": change_type,
                "full_path": canary.path,
                "soft": soft,
                "defense_action": plan.get("action"),
            },
            "suppress_local_notify": True,
            "force_urgent": (not soft) and bool(plan.get("force_urgent", True)),
        }
        try:
            if not soft and plan.get("contain"):
                from client_defense_policy import maybe_capture_session_snapshot
                maybe_capture_session_snapshot("canary_write", alert_attach=urgent)
        except Exception:
            pass
        try:
            if soft or plan.get("alert_only"):
                # Soft / observe: never hit /api/alerts/urgent (30 dk loop spam)
                if self.on_alert:
                    self.on_alert(urgent)
                elif self.alert_pipeline and hasattr(
                    self.alert_pipeline, "handle_alert"
                ):
                    self.alert_pipeline.handle_alert(urgent)
            elif self.alert_pipeline:
                self.alert_pipeline.send_urgent(urgent)
            elif self.on_alert:
                self.on_alert(urgent)
        except Exception as e:
            log(f"[RANSOMWARE-SHIELD] urgent alert delivery error: {e}")

        if not soft and not plan.get("alert_only"):
            self._block_suspicious_ips(f"canary {change_type}: {filename}")

    # ── Katman 3: Suspicious Process Detection ────────────────────
    def _process_monitor_loop(self):
        """Monitor for suspicious process spawns (every 5s)."""
        while self._running:
            try:
                self._check_suspicious_processes()
            except Exception as e:
                log(f"[RANSOMWARE-SHIELD] Process monitor error: {e}")
            time.sleep(5)

    def _check_suspicious_processes(self):
        """Check for newly spawned suspicious processes and command patterns."""
        try:
            import psutil
        except ImportError:
            return

        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'create_time']):
            try:
                info = proc.info
                pid = info.get('pid', 0)

                # Skip already-seen processes
                if pid in self._seen_pids:
                    continue
                self._seen_pids.add(pid)

                pname = (info.get('name') or '').lower()
                cmdline_parts = info.get('cmdline') or []
                cmdline = ' '.join(cmdline_parts)

                # VSS inventory (agent poll / list shadows) — never ransomware_process
                if pname == "vssadmin.exe" and is_vss_inventory_cmdline(cmdline):
                    continue
                if is_vss_delete_cmdline(cmdline):
                    self._vss_delete_cmd_until = time.time() + 300.0

                # Check process name (builtin + cloud intel)
                if pname in SUSPICIOUS_PROCESSES:
                    reason = SUSPICIOUS_PROCESSES[pname]
                    self._on_suspicious_process(pname, pid, cmdline, reason, 50)
                elif pname in self._cloud_processes:
                    if pname == "vssadmin.exe" and is_vss_inventory_cmdline(cmdline):
                        continue
                    reason = self._cloud_processes[pname]
                    self._on_suspicious_process(pname, pid, cmdline, reason, 55)

                # Check command-line patterns (builtin + cloud)
                matched = False
                for pattern, desc, score in SUSPICIOUS_CMD_PATTERNS:
                    if pattern.search(cmdline):
                        self._on_suspicious_process(pname, pid, cmdline, desc, score)
                        matched = True
                        break
                if not matched:
                    for pattern, desc, score in self._cloud_cmdline_patterns:
                        try:
                            if pattern.search(cmdline):
                                if (
                                    pname == "vssadmin.exe"
                                    and is_vss_inventory_cmdline(cmdline)
                                ):
                                    break
                                self._on_suspicious_process(
                                    pname, pid, cmdline, desc, score
                                )
                                break
                        except Exception:
                            continue

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # Prune seen PIDs set (keep only active)
        if len(self._seen_pids) > 5000:
            try:
                active_pids = {p.pid for p in psutil.process_iter(['pid'])}
                self._seen_pids &= active_pids
            except Exception:
                self._seen_pids.clear()

    def merge_cloud_intel(self, ransomware_layer: dict) -> int:
        """Merge cloud threat-intel ransomware layer (extensions / processes / cmdline).

        Does NOT trigger lockdown by itself — local canary/VSS remain authoritative.
        """
        if not isinstance(ransomware_layer, dict):
            return 0
        n = 0
        exts = ransomware_layer.get("extensions") or []
        if isinstance(exts, list):
            for x in exts:
                s = str(x or "").strip().lower()
                if not s:
                    continue
                if not s.startswith("."):
                    s = "." + s
                self._cloud_extensions.add(s)
                n += 1

        procs = ransomware_layer.get("process_names") or []
        if isinstance(procs, list):
            for p in procs:
                name = str(p or "").strip().lower()
                if not name:
                    continue
                if not name.endswith(".exe"):
                    name = name + ".exe"
                self._cloud_processes[name] = "cloud_threat_intel"
                n += 1

        patterns = ransomware_layer.get("cmdline_patterns") or []
        compiled = []
        if isinstance(patterns, list):
            for item in patterns:
                if not isinstance(item, dict):
                    continue
                pat = str(item.get("pattern") or "").strip()
                if not pat:
                    continue
                flags = re.I if "i" in str(item.get("flags") or "i").lower() else 0
                try:
                    rx = re.compile(pat, flags)
                except re.error:
                    continue
                desc = str(item.get("id") or item.get("description") or "cloud_cmdline")
                score = 90 if str(item.get("severity") or "").lower() == "critical" else 70
                compiled.append((rx, desc, score))
                n += 1
        if compiled:
            self._cloud_cmdline_patterns = compiled

        if n:
            log(f"[RANSOMWARE-SHIELD] merged cloud intel rules={n}")
        return n

    def get_cloud_extensions(self) -> Set[str]:
        return set(self._cloud_extensions) | set(SUSPICIOUS_EXTENSIONS)

    def _on_suspicious_process(
        self, pname: str, pid: int, cmdline: str, reason: str, score: int
    ):
        """Handle detection of a suspicious process."""
        self._stats["process_alerts"] += 1
        self._stats["total_detections"] += 1

        log(f"[RANSOMWARE-SHIELD] Suspicious process: {pname} (PID {pid}) — {reason}")

        detection = {
            "type": "suspicious_process",
            "process": pname,
            "pid": pid,
            "cmdline": cmdline[:200],
            "reason": reason,
            "threat_score": score,
            "timestamp": datetime.now().isoformat(),
        }
        self._detections.append(detection)

        if self.on_alert:
            self.on_alert({
                "event_type": "suspicious_process_detected",
                "threat_type": "ransomware_process",
                "severity": "critical" if score >= 90 else "high",
                "threat_score": score,
                "details": {
                    "process": pname,
                    "pid": pid,
                    "cmdline": cmdline[:200],
                    "reason": reason,
                },
                "description": (
                    f"Şüpheli süreç tespit edildi: {pname} (PID: {pid})\n"
                    f"Sebep: {reason}\n"
                    f"Komut: {cmdline[:200]}"
                ),
            })

        # VSS wipe intent (delete shadows / WMI delete) — kill + quarantine NOW.
        # Do NOT wait for shadow-count drop (≤120s) and do NOT IFEO vssadmin.exe.
        # HP-BLOCK (firewall IP) is separate; it does not "block VSS delete".
        if score >= 95 and (
            is_vss_delete_cmdline(cmdline)
            or "shadow" in (reason or "").lower()
            or "vss" in (reason or "").lower()
            or "backup deletion" in (reason or "").lower()
        ):
            try:
                from client_defense_policy import (
                    is_process_allowed,
                    process_action_plan,
                )
                plan = process_action_plan("vss_deletion")
            except Exception:
                plan = {"action": "kill_quarantine", "contain": True, "kill": True,
                        "alert_only": False}
                is_process_allowed = lambda **_kw: False  # type: ignore

            if is_process_allowed(image=pname, path=""):
                log(
                    f"[RANSOMWARE-SHIELD] VSS intent skipped — allowlisted "
                    f"image={pname}"
                )
                return

            if plan.get("alert_only") or not plan.get("contain"):
                log(
                    f"[DEFENSE-POLICY] VSS intent matrix={plan.get('action')} "
                    f"— alert only (no kill)"
                )
                if self.on_alert:
                    self.on_alert({
                        "event_type": "vss_delete_intent",
                        "threat_type": "ransomware_vss_delete_intent",
                        "severity": "high",
                        "threat_score": min(100, max(int(score), 95)),
                        "force_urgent": False,
                        "recommended_action": "review_process",
                        "auto_response_taken": [f"matrix:{plan.get('action')}"],
                        "details": {
                            "process": pname,
                            "pid": pid,
                            "cmdline": (cmdline or "")[:300],
                            "reason": reason,
                            "defense_action": plan.get("action"),
                        },
                        "description": (
                            f"VSS silme girişimi gözlemlendi (policy="
                            f"{plan.get('action')}). Süreç: {pname} PID={pid}."
                        ),
                    })
                return

            try:
                self._respond_vss_delete_intent(
                    pname, pid, cmdline, reason, score,
                    mode="suspend" if plan.get("suspend") and not plan.get("kill") else "kill",
                )
            except Exception as e:
                log(f"[RANSOMWARE-SHIELD] VSS intent response error: {e}")
            return

        # Non-VSS critical ransomware process — matrix may suspend
        try:
            from client_defense_policy import (
                is_process_allowed,
                is_protected_image,
                process_action_plan,
            )
            if score >= 90 and not is_vss_delete_cmdline(cmdline):
                plan = process_action_plan("ransomware_critical_process")
                if is_protected_image(pname) or is_process_allowed(image=pname):
                    pass
                elif plan.get("suspend") or plan.get("kill"):
                    self._apply_matrix_process_action(
                        pname, pid, cmdline, reason, score, plan
                    )
                elif score >= 95 and plan.get("alert_only"):
                    pass
                elif score >= 95:
                    # Legacy fallback when matrix missing — kill only
                    try:
                        subprocess.run(
                            ["taskkill", "/F", "/PID", str(pid)],
                            capture_output=True, timeout=5,
                            creationflags=CREATE_NO_WINDOW,
                        )
                    except Exception:
                        pass
        except Exception as e:
            log(f"[RANSOMWARE-SHIELD] critical process matrix error: {e}")

        # Yüksek skorlu tespit — aktif şüpheli IP'leri engelle (firewall HP-BLOCK)
        if score >= 90:
            self._block_suspicious_ips(f"suspicious process: {pname} — {reason}")

    def _apply_matrix_process_action(
        self,
        pname: str,
        pid: int,
        cmdline: str,
        reason: str,
        score: int,
        plan: dict,
    ) -> None:
        """Suspend or kill a non-VSS critical process per defense matrix."""
        try:
            from client_defense_policy import is_protected_image
            if is_protected_image(pname):
                return
        except Exception:
            pass
        actions = [f"matrix:{plan.get('action')}"]
        suspended = False
        killed = False
        if plan.get("suspend") and not plan.get("kill"):
            try:
                import psutil
                psutil.Process(int(pid)).suspend()
                suspended = True
                actions.append(f"suspend:{pid}")
            except Exception as e:
                log(f"[RANSOMWARE-SHIELD] suspend failed pid={pid}: {e}")
        elif plan.get("kill"):
            try:
                r = subprocess.run(
                    ["taskkill", "/F", "/PID", str(pid)],
                    capture_output=True, timeout=5,
                    creationflags=CREATE_NO_WINDOW,
                )
                killed = r.returncode == 0
                if killed:
                    actions.append(f"kill:{pid}")
            except Exception:
                pass
        alert = {
            "event_type": "ransomware_critical_process",
            "threat_type": "ransomware_process",
            "severity": "critical" if score >= 90 else "high",
            "threat_score": score,
            "force_urgent": bool(plan.get("force_urgent", True)),
            "recommended_action": (
                "resume_or_allow_process" if suspended else "review_quarantine"
            ),
            "auto_response_taken": actions,
            "details": {
                "process": pname,
                "pid": pid,
                "cmdline": (cmdline or "")[:300],
                "reason": reason,
                "suspended": suspended,
                "killed": killed,
                "defense_action": plan.get("action"),
            },
            "description": (
                f"Kritik ransomware süreci — matrix={plan.get('action')}. "
                f"{pname} PID={pid}. suspended={suspended} killed={killed}."
            ),
        }
        try:
            from client_defense_policy import maybe_capture_session_snapshot
            maybe_capture_session_snapshot(
                "ransomware_critical_process", alert_attach=alert
            )
        except Exception:
            pass
        if self.on_alert:
            self.on_alert(alert)

    def _respond_vss_delete_intent(
        self,
        pname: str,
        pid: int,
        cmdline: str,
        reason: str,
        score: int,
        mode: str = "kill",
    ) -> None:
        """Immediate response to VSS wipe TTP — contract ≥1.4.16.

        1) taskkill (or suspend) the delete process
        2) arm ransomware quarantine (dashboard/GUI) without waiting for count drop
        3) never IFEO admin tools (vssadmin/wmic/powershell/cmd/wbadmin)
        """
        killed = False
        suspended = False
        if mode == "suspend":
            try:
                import psutil
                psutil.Process(int(pid)).suspend()
                suspended = True
            except Exception:
                suspended = False
        if not suspended:
            try:
                r = subprocess.run(
                    ["taskkill", "/F", "/PID", str(pid)],
                    capture_output=True, timeout=5,
                    creationflags=CREATE_NO_WINDOW,
                )
                killed = r.returncode == 0
            except Exception:
                killed = False

        image = (pname or "").lower()
        allow_ifeo = (
            bool(image)
            and image not in _PROTECTED_IMAGES
            and image not in _NO_IFEO_ADMIN_TOOLS
            and mode != "suspend"
        )

        with self._quarantine_lock:
            entries = list(self._quarantine.get("entries") or [])
            self._quarantine = {
                "active": True,
                "locked_at": self._quarantine.get("locked_at")
                or datetime.now().isoformat(),
                "trigger": "vss_delete_intent",
                "entries": entries,
            }
            known = {
                (e.get("image") or "").lower()
                for e in entries
                if e.get("image")
            }
            if image and image not in known:
                ifeo_ok = False
                if allow_ifeo:
                    ifeo_ok = bool(self._apply_ifeo(image))
                    if ifeo_ok:
                        self._quarantine_images.add(image)
                entries.append({
                    "image": image,
                    "path": "",
                    "pid": pid,
                    "cmdline": (cmdline or "")[:300],
                    "sha256": "",
                    "ifeo": bool(ifeo_ok),
                    "at": datetime.now().isoformat(),
                    "trigger": "vss_delete_intent",
                    "reason": reason,
                    "killed": bool(killed),
                })
                self._quarantine["entries"] = entries
            self._stats["quarantine_active"] = True
            self._stats["quarantine_entries"] = len(self._quarantine.get("entries") or [])
            if killed:
                self._stats["quarantine_kills"] = (
                    int(self._stats.get("quarantine_kills") or 0) + 1
                )
            self._persist_quarantine()

        log(
            f"[RANSOMWARE-SHIELD] VSS delete intent: kill={killed} "
            f"suspend={suspended} pid={pid} image={image} "
            f"quarantine=armed ifeo={allow_ifeo}"
        )

        alert = {
            "event_type": "vss_delete_intent",
            "threat_type": "ransomware_vss_delete_intent",
            "severity": "critical",
            "threat_score": min(100, max(int(score), 95)),
            "force_urgent": True,
            "suppress_local_notify": False,
            "recommended_action": (
                "resume_or_allow_process" if suspended else "review_quarantine"
            ),
            "auto_response_taken": (
                (["suspend"] if suspended else ["taskkill"])
                + ["quarantine_arm"]
                + (["ifeo"] if allow_ifeo else [])
            ),
            "details": {
                "process": pname,
                "pid": pid,
                "cmdline": (cmdline or "")[:300],
                "reason": reason,
                "killed": bool(killed),
                "suspended": bool(suspended),
                "quarantine_active": True,
            },
            "description": (
                f"VSS silme girişimi (intent) — gölge kopya sayısı beklenmeden "
                f"müdahale. Süreç: {pname} PID={pid}. Sebep: {reason}. "
                f"killed={killed} suspended={suspended}."
            ),
            "system_context": {
                "ransomware": {
                    "trigger": "vss_delete_intent",
                    "suspects": [{
                        "pid": pid,
                        "image": pname,
                        "cmdline": (cmdline or "")[:300],
                        "state": (
                            "suspended" if suspended
                            else ("killed" if killed else "observed")
                        ),
                    }],
                }
            },
        }
        try:
            from client_defense_policy import maybe_capture_session_snapshot
            maybe_capture_session_snapshot("vss_deletion", alert_attach=alert)
        except Exception:
            pass
        if self.on_alert:
            self.on_alert(alert)

    # ── Katman 4: VSS Monitor ─────────────────────────────────────

    def _vss_monitor_loop(self):
        """Monitor Volume Shadow Copy count for deletions."""
        # Get initial baseline
        self._vss_count = self._get_vss_count()
        if self._vss_count is not None:
            log(f"[RANSOMWARE-SHIELD] VSS baseline: {self._vss_count} shadow copies")

        while self._running:
            time.sleep(VSS_CHECK_INTERVAL)
            try:
                current = self._get_vss_count()
                if current is None:
                    continue

                if self._vss_count is not None and current < self._vss_count:
                    # Shadow copies were deleted!
                    deleted_count = self._vss_count - current
                    self._on_vss_deletion(deleted_count, current)

                self._vss_count = current
            except Exception as e:
                log(f"[RANSOMWARE-SHIELD] VSS check error: {e}")

    def _get_vss_count(self) -> Optional[int]:
        """Get current number of Volume Shadow Copies."""
        try:
            result = subprocess.run(
                ["vssadmin", "list", "shadows"],
                capture_output=True, text=True, timeout=15,
                creationflags=CREATE_NO_WINDOW,
            )
            if result.returncode != 0:
                return 0

            # Count "Shadow Copy ID:" lines
            count = result.stdout.lower().count("shadow copy id:")
            return count
        except Exception:
            return None

    def _on_vss_deletion(self, deleted_count: int, remaining: int):
        """Shadow copies decreased — severity from delta / remaining / delete cmd."""
        self._stats["vss_alerts"] += 1
        self._stats["total_detections"] += 1

        delete_cmd_seen = time.time() < float(getattr(self, "_vss_delete_cmd_until", 0.0) or 0.0)
        severity, threat_score = classify_shadow_copy_severity(
            deleted_count, remaining, delete_cmd_seen=delete_cmd_seen
        )
        critical = severity == "critical"

        log(
            f"[RANSOMWARE-SHIELD] VSS DELETION: "
            f"{deleted_count} deleted ({remaining} remaining) "
            f"severity={severity} delete_cmd={delete_cmd_seen}"
        )

        detection = {
            "type": "vss_deletion",
            "deleted_count": deleted_count,
            "remaining": remaining,
            "threat_score": threat_score,
            "severity": severity,
            "timestamp": datetime.now().isoformat(),
        }
        self._detections.append(detection)

        # Single emit (avoid TR+empty/EN duplicate via on_alert + send_urgent).
        vss_alert = {
            "event_type": "vss_shadow_deleted",
            "threat_type": "shadow_copy_deleted",
            "severity": severity,
            "threat_score": threat_score,
            "title": (
                "🚨 VSS Shadow Copy Silindi — Ransomware Şüphesi!"
                if critical
                else "🟠 VSS shadow sayısı azaldı (inceleme)"
            ),
            "description": (
                f"{deleted_count} adet Volume Shadow Copy silindi.\n"
                f"Kalan shadow copy sayısı: {remaining}\n"
                + (
                    "\nBu, aktif bir ransomware saldırısının güçlü göstergesidir."
                    if critical
                    else "\nKüçük azalma — OS shadow rotasyonu olabilir."
                )
            ),
            "details": {
                "deleted_count": deleted_count,
                "remaining": remaining,
                "delete_cmd_seen": delete_cmd_seen,
            },
            "auto_response_taken": (
                ["emergency_alert"] if critical else ["alert_only"]
            ),
        }
        try:
            if critical and self.alert_pipeline:
                self.alert_pipeline.send_urgent(vss_alert)
            elif self.on_alert:
                self.on_alert(vss_alert)
            elif self.alert_pipeline:
                self.alert_pipeline.send_urgent(vss_alert)
        except Exception as e:
            log(f"[RANSOMWARE-SHIELD] VSS alert delivery error: {e}")

        if critical:
            self._block_suspicious_ips(
                f"VSS deletion: {deleted_count} shadows deleted"
            )
            self._contain_after_hit(
                trigger=f"vss_deletion:{deleted_count}",
                focus_path="",
            )

    # ── Helpers ────────────────────────────────────────────────────

    def _block_suspicious_ips(self, trigger_reason: str):
        """Ransomware tespit edildiğinde ThreatEngine'deki aktif şüpheli IP'leri engelle.

        Mantık:
          - ThreatEngine'deki tüm IP bağlamlarını al
          - Whitelist'te olanları atla
          - Threat score'u >= 30 olanları auto_response ile engelle
          - Bu sayede ransomware'i deploy etmiş olabilecek ağ saldırganları kesilir
        """
        if not self.auto_response or not self.threat_engine:
            return

        try:
            whitelist = getattr(self.threat_engine, '_whitelist_ips', set())
            contexts = self.threat_engine.get_all_contexts()
            blocked_count = 0

            for ip, ctx in contexts.items():
                if ip in whitelist:
                    continue
                # Sadece gerçekten şüpheli olanları engelle
                if ctx.threat_score < 30:
                    continue
                try:
                    self.auto_response.block_ip(
                        ip,
                        reason=f"Ransomware alert — {trigger_reason}",
                        duration_hours=24,
                    )
                    blocked_count += 1
                except Exception:
                    pass

            if blocked_count:
                log(
                    f"[RANSOMWARE-SHIELD] 🔒 Blocked {blocked_count} suspicious IP(s) "
                    f"after ransomware detection ({trigger_reason})"
                )
        except Exception as e:
            log(f"[RANSOMWARE-SHIELD] IP block error: {e}")

    # ── Quarantine / containment ─────────────────────────────────

    def _quarantine_path(self) -> str:
        try:
            from client_utils import _programdata_client_dir
            base = _programdata_client_dir()
        except Exception:
            base = os.path.join(
                os.environ.get("ProgramData", r"C:\ProgramData"),
                "Asteria",
            )
        return os.path.join(base, _QUARANTINE_FILE)

    def _load_quarantine(self) -> None:
        path = self._quarantine_path()
        try:
            if not os.path.isfile(path):
                return
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, dict):
                return
            self._quarantine = data
            images = set()
            for e in data.get("entries") or []:
                img = (e.get("image") or "").strip().lower()
                if img:
                    images.add(img)
            self._quarantine_images = images
            # Stuck lock with no IFEO/targets — heal on boot (persisted).
            self._disarm_empty_quarantine("load_empty")
        except Exception as e:
            log(f"[RANSOMWARE-SHIELD] quarantine load error: {e}")

    def _persist_quarantine(self) -> None:
        path = self._quarantine_path()
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self._quarantine, f, indent=2, ensure_ascii=False)
        except Exception as e:
            log(f"[RANSOMWARE-SHIELD] quarantine persist error: {e}")

    def _disarm_empty_quarantine(self, reason: str = "auto_heal_empty") -> bool:
        """Clear active=true with zero enforceable entries (no IFEO images)."""
        prior = ""
        try:
            with self._quarantine_lock:
                entries = list(self._quarantine.get("entries") or [])
                images = {
                    (e.get("image") or "").strip().lower()
                    for e in entries
                    if (e.get("image") or "").strip()
                }
                if self._quarantine_images:
                    images |= {str(x).lower() for x in self._quarantine_images}
                if not self._quarantine.get("active"):
                    return False
                if entries or images:
                    return False
                prior = self._quarantine.get("trigger") or ""
                self._quarantine = {
                    "active": False,
                    "locked_at": "",
                    "trigger": "",
                    "entries": [],
                    "unlocked_at": datetime.now().isoformat(),
                    "unlock_reason": reason,
                    "prior_trigger": prior,
                }
                self._quarantine_images.clear()
                self._stats["quarantine_active"] = False
                self._stats["quarantine_entries"] = 0
                self._persist_quarantine()
            log(
                f"[RANSOMWARE-SHIELD] Quarantine auto-disarmed "
                f"({reason}); prior_trigger={prior}"
            )
            return True
        except Exception as e:
            log(f"[RANSOMWARE-SHIELD] empty quarantine heal error: {e}")
            return False

    def _contain_after_hit(
        self, trigger: str, focus_path: str = "", mode: str = "kill"
    ) -> dict:
        """Kill or suspend writers of canary path + IFEO-block their images until unlock.

        Arms quarantine immediately (STATUS/GUI), then best-effort attribution.
        Full open_files() scans can take tens of seconds on busy hosts — must not
        delay the lockdown flag.
        """
        # 1) Arm lock immediately (skip arm when observe already decided alert_only upstream)
        with self._quarantine_lock:
            entries = list(self._quarantine.get("entries") or [])
            self._quarantine = {
                "active": True,
                "locked_at": self._quarantine.get("locked_at")
                or datetime.now().isoformat(),
                "trigger": trigger,
                "entries": entries,
            }
            self._stats["quarantine_active"] = True
            self._stats["quarantine_entries"] = len(entries)
            self._persist_quarantine()
        log(f"[RANSOMWARE-SHIELD] Quarantine ARMED trigger={trigger} mode={mode}")

        # 2) Attribute writers (time-boxed)
        suspects: List[dict] = []
        try:
            holder: List[List[dict]] = [[]]

            def _scan():
                try:
                    holder[0] = self._find_suspect_processes(focus_path)
                except Exception as e:
                    log(f"[RANSOMWARE-SHIELD] suspect scan error: {e}")

            th = threading.Thread(target=_scan, name="RS-SuspectScan", daemon=True)
            th.start()
            th.join(timeout=4.0)
            if th.is_alive():
                log("[RANSOMWARE-SHIELD] suspect scan timeout — quarantine stays armed")
            else:
                suspects = holder[0] or []
        except Exception as e:
            log(f"[RANSOMWARE-SHIELD] suspect scan setup error: {e}")

        # Filter allowlisted / protected before action
        try:
            from client_defense_policy import is_process_allowed, is_protected_image
        except Exception:
            def is_process_allowed(**_kw):
                return False

            def is_protected_image(image):
                return (image or "").lower() in _PROTECTED_IMAGES

        filtered = []
        for s in suspects:
            image = (s.get("image") or "").lower()
            path = s.get("path") or ""
            sha = s.get("sha256") or ""
            if is_protected_image(image):
                continue
            if is_process_allowed(path=path, image=image, sha256=sha):
                log(f"[RANSOMWARE-SHIELD] skip allowlisted suspect {image}")
                continue
            filtered.append(s)
        suspects = filtered

        actions = []
        with self._quarantine_lock:
            if not self._quarantine.get("active"):
                # Operator unlocked while we scanned
                log("[RANSOMWARE-SHIELD] Containment skipped — already unlocked")
                return {
                    "trigger": trigger,
                    "suspects": suspects,
                    "actions": [],
                    "quarantine": {
                        "active": False,
                        "entries": 0,
                        "kills": int(
                            self._stats.get("quarantine_kills") or 0
                        ),
                    },
                }
            entries = list(self._quarantine.get("entries") or [])
            known = {
                (e.get("image") or "").lower()
                for e in entries
                if e.get("image")
            }
            for s in suspects:
                image = (s.get("image") or "").lower()
                if not image or image in _PROTECTED_IMAGES:
                    continue
                pid = s.get("pid")
                if image in _NO_IFEO_ADMIN_TOOLS:
                    # Kill/suspend only — never IFEO admin VSS tools
                    if pid:
                        if mode == "suspend":
                            if self._suspend_pid(int(pid)):
                                actions.append(f"suspend:{pid}:{image}")
                        elif self._kill_pid(int(pid)):
                            actions.append(f"kill:{pid}:{image}")
                            self._stats["quarantine_kills"] = (
                                int(self._stats.get("quarantine_kills") or 0) + 1
                            )
                    continue
                if pid:
                    if mode == "suspend":
                        if self._suspend_pid(int(pid)):
                            actions.append(f"suspend:{pid}:{image}")
                    elif self._kill_pid(int(pid)):
                        actions.append(f"kill:{pid}:{image}")
                        self._stats["quarantine_kills"] = (
                            int(self._stats.get("quarantine_kills") or 0) + 1
                        )
                if mode != "suspend" and image not in known:
                    ifeo_ok = self._apply_ifeo(image)
                    entries.append({
                        "image": image,
                        "path": s.get("path") or "",
                        "pid": pid,
                        "cmdline": s.get("cmdline") or "",
                        "sha256": s.get("sha256") or "",
                        "ifeo": bool(ifeo_ok),
                        "at": datetime.now().isoformat(),
                        "trigger": trigger,
                    })
                    known.add(image)
                    self._quarantine_images.add(image)
                    actions.append(f"ifeo:{image}")
                elif mode == "suspend" and image not in known:
                    entries.append({
                        "image": image,
                        "path": s.get("path") or "",
                        "pid": pid,
                        "cmdline": s.get("cmdline") or "",
                        "sha256": s.get("sha256") or "",
                        "ifeo": False,
                        "suspended": True,
                        "at": datetime.now().isoformat(),
                        "trigger": trigger,
                    })
                    known.add(image)
                    actions.append(f"track_suspend:{image}")
            self._quarantine["entries"] = entries
            self._quarantine["trigger"] = trigger
            self._stats["quarantine_entries"] = len(entries)
            # No attributed writer → empty lockdown is noise; disarm + persist.
            if not entries and not self._quarantine_images:
                prior = trigger
                self._quarantine = {
                    "active": False,
                    "locked_at": "",
                    "trigger": "",
                    "entries": [],
                    "unlocked_at": datetime.now().isoformat(),
                    "unlock_reason": "auto_disarm_no_writer",
                    "prior_trigger": prior,
                }
                self._stats["quarantine_active"] = False
                self._stats["quarantine_entries"] = 0
            self._persist_quarantine()

        if actions:
            log(f"[RANSOMWARE-SHIELD] Containment: {', '.join(actions[:12])}")
        else:
            log(
                f"[RANSOMWARE-SHIELD] Containment complete (no live writer) "
                f"trigger={trigger} — empty lock disarmed"
            )

        detection = {
            "type": "quarantine_lock",
            "trigger": trigger,
            "actions": actions[:20],
            "threat_score": 100,
            "timestamp": datetime.now().isoformat(),
        }
        self._detections.append(detection)
        return {
            "trigger": trigger,
            "suspects": suspects,
            "actions": actions[:20],
            "quarantine": {
                "active": True,
                "entries": len(entries),
                "kills": int(self._stats.get("quarantine_kills") or 0),
            },
        }

    def _suspend_pid(self, pid: int) -> bool:
        try:
            import psutil
            psutil.Process(int(pid)).suspend()
            return True
        except Exception:
            return False

    def _find_suspect_processes(self, focus_path: str) -> List[dict]:
        """Best-effort: processes with open handles under canary root / file.

        Bounded: skip protected images, cap process count, ignore AccessDenied fast.
        """
        out: List[dict] = []
        try:
            import psutil
        except ImportError:
            return out

        focus = (focus_path or "").lower().replace("/", "\\")
        roots = set()
        if focus:
            roots.add(focus)
            parent = os.path.dirname(focus)
            if parent:
                roots.add(parent.lower())
            parts = focus.split("\\")
            for i, p in enumerate(parts):
                if p == CANARY_ROOT_FOLDER.lower() and i > 0:
                    roots.add("\\".join(parts[: i + 1]))
                    break

        my_pid = os.getpid()
        checked = 0
        deadline = time.time() + 3.5
        for proc in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
            if time.time() > deadline:
                break
            try:
                info = proc.info
                pid = int(info.get("pid") or 0)
                if pid in (0, 4, my_pid):
                    continue
                pname = (info.get("name") or "").lower()
                if pname in _PROTECTED_IMAGES:
                    continue
                checked += 1
                if checked > 250:
                    break
                exe = info.get("exe") or ""
                cmdline_raw = info.get("cmdline") or []
                cmdline = (
                    " ".join(str(part) for part in cmdline_raw)
                    if isinstance(cmdline_raw, (list, tuple))
                    else str(cmdline_raw)
                )
                matched = False
                try:
                    for of in proc.open_files() or []:
                        pth = (of.path or "").lower().replace("/", "\\")
                        if not pth:
                            continue
                        if focus and (pth == focus or focus in pth):
                            matched = True
                            break
                        for root in roots:
                            if root and (pth.startswith(root) or root in pth):
                                matched = True
                                break
                        if matched:
                            break
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    continue
                if not matched:
                    continue
                sha = ""
                if exe and os.path.isfile(exe):
                    sha = self._file_hash(exe) or ""
                out.append({
                    "pid": pid,
                    "image": pname,
                    "path": exe,
                    "cmdline": cmdline,
                    "sha256": sha,
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return out

    def _quarantine_enforce_loop(self) -> None:
        """While quarantine active, kill matching image names if they respawn."""
        while self._running:
            try:
                with self._quarantine_lock:
                    active = bool(self._quarantine.get("active"))
                    images = set(self._quarantine_images)
                if active and images:
                    self._kill_quarantined_images(images)
            except Exception as e:
                log(f"[RANSOMWARE-SHIELD] quarantine enforce error: {e}")
            time.sleep(3)

    def _kill_quarantined_images(self, images: Set[str]) -> None:
        try:
            import psutil
        except ImportError:
            return
        my_pid = os.getpid()
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                pid = int(proc.info.get("pid") or 0)
                if pid in (0, 4, my_pid):
                    continue
                name = (proc.info.get("name") or "").lower()
                if name in images and name not in _PROTECTED_IMAGES:
                    if self._kill_pid(pid):
                        self._stats["quarantine_kills"] = (
                            int(self._stats.get("quarantine_kills") or 0) + 1
                        )
                        log(f"[RANSOMWARE-SHIELD] Quarantine re-kill {name} PID {pid}")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    @staticmethod
    def _kill_pid(pid: int) -> bool:
        try:
            r = subprocess.run(
                ["taskkill", "/F", "/PID", str(pid)],
                capture_output=True, timeout=5,
                creationflags=CREATE_NO_WINDOW,
            )
            return r.returncode == 0
        except Exception:
            return False

    @staticmethod
    def _apply_ifeo(image: str) -> bool:
        """IFEO Debugger stub — process fails to start (reversible on unlock)."""
        image = (image or "").strip()
        if not image or image.lower() in _PROTECTED_IMAGES:
            return False
        if image.lower() in _NO_IFEO_ADMIN_TOOLS:
            return False
        try:
            import winreg
            key_path = (
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
                r"\Image File Execution Options\\" + image
            )
            with winreg.CreateKeyEx(
                winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_SET_VALUE
            ) as k:
                winreg.SetValueEx(k, "Debugger", 0, winreg.REG_SZ, "nyan")
            return True
        except Exception as e:
            log(f"[RANSOMWARE-SHIELD] IFEO apply failed for {image}: {e}")
            return False

    @staticmethod
    def _clear_ifeo(image: str) -> bool:
        image = (image or "").strip()
        if not image:
            return False
        try:
            import winreg
            key_path = (
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
                r"\Image File Execution Options\\" + image
            )
            try:
                with winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_SET_VALUE
                ) as k:
                    try:
                        winreg.DeleteValue(k, "Debugger")
                    except FileNotFoundError:
                        pass
            except FileNotFoundError:
                return True
            # Remove empty IFEO key if possible
            try:
                winreg.DeleteKey(winreg.HKEY_LOCAL_MACHINE, key_path)
            except OSError:
                pass
            return True
        except Exception as e:
            log(f"[RANSOMWARE-SHIELD] IFEO clear failed for {image}: {e}")
            return False

    @staticmethod
    def _file_hash(filepath: str) -> Optional[str]:
        """Compute SHA-256 hash of a file."""
        try:
            h = hashlib.sha256()
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
            return h.hexdigest()
        except OSError:
            return None
