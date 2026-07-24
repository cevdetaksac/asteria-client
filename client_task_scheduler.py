#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Client Task Scheduler — Windows Task Scheduler integration.

6-task system: Background (boot), Tray (logon), Watchdog (2m),
Updater (weekly), SilentUpdater (15m), MemoryRestart (8h).
XML-based schtasks creation, admin-optional activation.

Key exports:
  perform_comprehensive_task_management() — startup task check/activate
  ensure_tasks_installed()                — install missing tasks (admin)
  check_tasks_status()                    — verify all task states
  install_tasks() / uninstall_tasks()     — full install/remove
  get_task_status/enable_task/disable_task/run_task — per-task control
"""

import os
import sys
import subprocess
import ctypes
import json
import time
from datetime import datetime

from client_constants import TASK_STATE_FILE

# Configuration
TASK_NAME_BACKGROUND = "CloudHoneypot-Background"
TASK_NAME_TRAY = "CloudHoneypot-Tray"
TASK_NAME_WATCHDOG = "CloudHoneypot-Watchdog"
TASK_NAME_UPDATER = "CloudHoneypot-Updater"
TASK_NAME_SILENT_UPDATER = "CloudHoneypot-SilentUpdater"
TASK_NAME_MEMORY_RESTART = "CloudHoneypot-MemoryRestart"

def get_client_exe_path():
    """Get the current executable path dynamically"""
    if hasattr(sys, '_MEIPASS'):
        # Running as PyInstaller bundle
        return sys.executable
    else:
        # Running as script, try to find honeypot-client.exe
        script_dir = os.path.dirname(os.path.abspath(__file__))
        exe_path = os.path.join(script_dir, "honeypot-client.exe")
        if os.path.exists(exe_path):
            return exe_path
        # Fallback to installed location
        return os.path.join(r"C:\Program Files\YesNext\Cloud Honeypot Client", "honeypot-client.exe")

CLIENT_EXE = get_client_exe_path()

TASK_CACHE_MAX_AGE = 1800  # seconds


"""Task state persistence helpers"""
def _log_or_print(log_func, message):
    if callable(log_func):
        try:
            log_func(message)
            return
        except Exception:
            pass
    print(message)


def load_task_state():
    return _load_raw_task_state()


def _load_raw_task_state():
    try:
        with open(TASK_STATE_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}
    except Exception as exc:
        print(f"[TaskState] load error: {exc}")
        return {}


def save_task_state(state):
    data = dict(state or {})
    data['updated_at'] = int(time.time())
    try:
        os.makedirs(os.path.dirname(TASK_STATE_FILE), exist_ok=True)
        with open(TASK_STATE_FILE, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    except Exception as exc:
        print(f"[TaskState] save error: {exc}")


def _should_trust_cache(state, max_age):
    if not state or not isinstance(state, dict):
        return False
    timestamp = state.get('updated_at') or state.get('last_verified')
    if not timestamp:
        return False
    try:
        timestamp = int(timestamp)
    except (TypeError, ValueError):
        return False
    return (time.time() - timestamp) <= max_age


def ensure_tasks_installed(log_func=None, force=False, max_age=TASK_CACHE_MAX_AGE):
    # First check admin status
    admin_rights = is_admin()
    
    state = load_task_state()
    if not force and _should_trust_cache(state, max_age) and (state.get('all_installed') or state.get('both_installed')):
        cached_status = check_tasks_status(update_cache=True)
        if cached_status.get('all_installed') or cached_status.get('both_installed'):
            _log_or_print(log_func, "[OK] Task Scheduler tasks verified (cached)")
            return {'success': True, 'action': 'cache', 'status': cached_status}

    status = check_tasks_status(update_cache=True)
    if (status.get('all_installed') or status.get('both_installed')) and not force:
        _log_or_print(log_func, "[OK] Task Scheduler tasks verified (installed)")
        return {'success': True, 'action': 'verified', 'status': status}

    # Tasks missing - check admin rights
    if not admin_rights:
        _log_or_print(log_func, "[WARN] Task Scheduler tasks missing but no admin rights - will be installed when run as admin")
        return {'success': False, 'action': 'needs_admin', 'status': status, 'admin_required': True}
    
    _log_or_print(log_func, "[SETUP] Installing missing Task Scheduler tasks...")
    success = install_tasks()
    if not success:
        failure_status = check_tasks_status(update_cache=False)
        return {'success': False, 'action': 'install_failed', 'status': failure_status}

    status_after = check_tasks_status(update_cache=True)
    if status_after.get('all_installed') or status_after.get('both_installed'):
        _log_or_print(log_func, "[OK] Task Scheduler tasks successfully installed")
        return {'success': True, 'action': 'installed', 'status': status_after}
    return {'success': False, 'action': 'verification_failed', 'status': status_after}


def is_admin():
    """Check if script is running with admin privileges"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

# ===================== CENTRALIZED TASK XML GENERATOR ===================== #

# Task configuration registry — all 6 tasks defined declaratively
TASK_CONFIGS = {
    TASK_NAME_BACKGROUND: {
        "description": "Cloud Honeypot Client - Background Service",
        "trigger": "<BootTrigger><Enabled>true</Enabled><Delay>PT30S</Delay></BootTrigger>",
        "principal": "<UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel>",
        "args": "--mode=daemon --silent",
        "multi_instance": "IgnoreNew",
        "hidden": False, "wake": False, "network_required": False,
        "exec_limit": "PT0S", "priority": 7,
    },
    TASK_NAME_TRAY: {
        "description": "Cloud Honeypot Client - Interactive Tray",
        "trigger": "<LogonTrigger><Enabled>true</Enabled><Delay>PT5S</Delay></LogonTrigger>",
        # S-1-5-11 = Authenticated Users (includes local Administrator; Users group often does not).
        # Do NOT set LogonType=Group — schtasks rejects it on current Windows
        # ("Task XML ... incorrect value (LogonType:Group)") and leaves Tray missing.
        "principal": (
            "<GroupId>S-1-5-11</GroupId>"
            "<RunLevel>HighestAvailable</RunLevel>"
        ),
        # Logon → tray icon (not forced window); onboarding still forces GUI via should_force_gui_visible
        "args": "--mode=tray",
        # IgnoreNew: multi-user RDP — second logon must NOT kill first user's GUI
        "multi_instance": "IgnoreNew",
        "hidden": False, "wake": False, "network_required": False,
        "exec_limit": "PT0S", "priority": 7,
    },
    TASK_NAME_WATCHDOG: {
        "description": "Cloud Honeypot Client - Watchdog Process Recovery (every 2 min)",
        "trigger": (
            '<CalendarTrigger><StartBoundary>2025-01-01T00:00:00</StartBoundary>'
            '<Enabled>true</Enabled><ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay>'
            '<Repetition><Interval>PT2M</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition>'
            '</CalendarTrigger>'
        ),
        "principal": "<UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel>",
        "args": "--mode=watchdog",
        "multi_instance": "IgnoreNew",
        "hidden": True, "wake": True, "network_required": False,
        "exec_limit": "PT5M", "priority": 7,
    },
    TASK_NAME_UPDATER: {
        "description": "Cloud Honeypot Client - Weekly Update Check and Auto-Install",
        "trigger": (
            '<CalendarTrigger><StartBoundary>2025-01-01T02:00:00</StartBoundary>'
            '<Enabled>true</Enabled><ScheduleByWeek><DaysOfWeek><Sunday /></DaysOfWeek>'
            '<WeeksInterval>1</WeeksInterval></ScheduleByWeek></CalendarTrigger>'
        ),
        "principal": "<UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel>",
        "args": "--silent-update-check",
        "multi_instance": "IgnoreNew",
        "hidden": True, "wake": True, "network_required": True,
        "exec_limit": "PT30M", "priority": 7,
    },
    TASK_NAME_SILENT_UPDATER: {
        "description": "Cloud Honeypot Client - Silent Update Check and Auto-Install (Every 15 minutes)",
        "trigger": (
            '<CalendarTrigger><StartBoundary>2025-01-01T00:05:00</StartBoundary>'
            '<Enabled>true</Enabled><ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay>'
            '<Repetition><Interval>PT15M</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition>'
            '</CalendarTrigger>'
        ),
        "principal": "<UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel>",
        "args": "--silent-update-check",
        "multi_instance": "IgnoreNew",
        "hidden": True, "wake": False, "network_required": False,
        "exec_limit": "PT45M", "priority": 6,
    },
    TASK_NAME_MEMORY_RESTART: {
        "description": "Cloud Honeypot Client - Memory Restart (Every 8 hours for memory cleanup)",
        "trigger": (
            '<TimeTrigger><Repetition><Interval>PT8H</Interval>'
            '<StopAtDurationEnd>false</StopAtDurationEnd></Repetition>'
            '<StartBoundary>2025-01-01T08:00:00</StartBoundary><Enabled>true</Enabled></TimeTrigger>'
        ),
        "principal": "<UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel>",
        "command": "powershell",  # override: runs PowerShell script instead of CLIENT_EXE
        "multi_instance": "IgnoreNew",
        "hidden": False, "wake": False, "network_required": False,
        "exec_limit": "PT30M", "priority": 7,
        "extra_settings": (
            "<DisallowStartOnRemoteAppSession>false</DisallowStartOnRemoteAppSession>"
            "<UseUnifiedSchedulingEngine>true</UseUnifiedSchedulingEngine>"
        ),
    },
}

def ensure_memory_restart_script_on_disk() -> str:
    """Copy memory_restart.ps1 next to the installed exe (stable path, not _MEIPASS)."""
    exe_dir = os.path.dirname(CLIENT_EXE)
    scripts_dir = os.path.join(exe_dir, "scripts")
    dest = os.path.join(scripts_dir, "memory_restart.ps1")
    sources = []
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        sources.append(os.path.join(meipass, "memory_restart.ps1"))
    sources.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "memory_restart.ps1"))
    sources.append(os.path.join(exe_dir, "memory_restart.ps1"))

    src = next((p for p in sources if p and os.path.isfile(p)), None)
    try:
        os.makedirs(scripts_dir, exist_ok=True)
        # Remove installer-only helpers if an older build left them world-readable.
        for name in ("kill-honeypot.ps1", "prepare-install-dir.ps1", "update-and-install.ps1"):
            try:
                stale = os.path.join(scripts_dir, name)
                if os.path.isfile(stale):
                    os.remove(stale)
            except OSError:
                pass
        if src:
            need_copy = True
            if os.path.isfile(dest):
                try:
                    need_copy = os.path.getsize(dest) != os.path.getsize(src)
                except OSError:
                    need_copy = True
            if need_copy:
                import shutil
                shutil.copy2(src, dest)
        _harden_scripts_dir_acl(scripts_dir)
        return dest if os.path.isfile(dest) else (src or dest)
    except Exception:
        return src or dest


def _harden_scripts_dir_acl(scripts_dir: str) -> None:
    """SYSTEM + Administrators only — block standard Users from running helpers."""
    if not scripts_dir or not os.path.isdir(scripts_dir):
        return
    try:
        subprocess.run(
            [
                "icacls",
                scripts_dir,
                "/inheritance:r",
                "/grant:r",
                "NT AUTHORITY\\SYSTEM:(OI)(CI)F",
                "/grant:r",
                "BUILTIN\\Administrators:(OI)(CI)F",
                "/remove:g",
                "BUILTIN\\Users",
                "/remove:g",
                "Everyone",
                "/remove:g",
                "NT AUTHORITY\\Authenticated Users",
                "/T",
                "/C",
                "/Q",
            ],
            capture_output=True,
            timeout=20,
            creationflags=0x08000000,
        )
    except Exception:
        pass


def _build_memory_restart_action() -> str:
    """Build <Actions> block for memory restart task (PowerShell script)."""
    script_path = ensure_memory_restart_script_on_disk()
    install_path = os.path.dirname(CLIENT_EXE)
    work_dir = os.path.dirname(script_path) if script_path else install_path
    return (
        f'<Actions Context="Author"><Exec>'
        f'<Command>PowerShell.exe</Command>'
        f'<Arguments>-WindowStyle Hidden -ExecutionPolicy Bypass -File &quot;{script_path}&quot; '
        f'-InstallPath &quot;{install_path}&quot;</Arguments>'
        f'<WorkingDirectory>{work_dir}</WorkingDirectory>'
        f'</Exec></Actions>'
    )

def _build_task_xml(cfg: dict) -> str:
    """Generate schtasks-compatible XML from a task config dict."""
    # Idle settings
    idle_extra = cfg.get("idle_settings", "")
    idle_block = (
        f"<IdleSettings>{idle_extra}"
        "<StopOnIdleEnd>false</StopOnIdleEnd>"
        "<RestartOnIdle>false</RestartOnIdle>"
        "</IdleSettings>"
    )

    # Extra settings (e.g. UseUnifiedSchedulingEngine)
    extra = cfg.get("extra_settings", "")

    # Action block
    if cfg.get("command") == "powershell":
        actions = _build_memory_restart_action()
    else:
        actions = (
            f'<Actions Context="Author"><Exec>'
            f'<Command>"{CLIENT_EXE}"</Command>'
            f'<Arguments>{cfg["args"]}</Arguments>'
            f'<WorkingDirectory>{os.path.dirname(CLIENT_EXE)}</WorkingDirectory>'
            f'</Exec></Actions>'
        )

    return f'''<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>{datetime.now().isoformat()}</Date>
    <Author>Cloud Honeypot Client</Author>
    <Description>{cfg["description"]}</Description>
  </RegistrationInfo>
  <Triggers>
    {cfg["trigger"]}
  </Triggers>
  <Principals>
    <Principal id="Author">
      {cfg["principal"]}
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>{cfg["multi_instance"]}</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>{"true" if cfg["network_required"] else "false"}</RunOnlyIfNetworkAvailable>
    {idle_block}
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>{"true" if cfg["hidden"] else "false"}</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    {extra}
    <WakeToRun>{"true" if cfg["wake"] else "false"}</WakeToRun>
    <ExecutionTimeLimit>{cfg["exec_limit"]}</ExecutionTimeLimit>
    <Priority>{cfg["priority"]}</Priority>
  </Settings>
  {actions}
</Task>'''

def create_task_xml(task_name: str) -> str:
    """Create XML for any registered task by name."""
    if task_name not in TASK_CONFIGS:
        raise ValueError(f"Unknown task: {task_name}")
    return _build_task_xml(TASK_CONFIGS[task_name])

# Backward-compatible wrappers (one-liner delegates)
def create_background_task_xml():     return create_task_xml(TASK_NAME_BACKGROUND)
def create_tray_task_xml():           return create_task_xml(TASK_NAME_TRAY)
def create_watchdog_task_xml():       return create_task_xml(TASK_NAME_WATCHDOG)
def create_updater_task_xml():        return create_task_xml(TASK_NAME_UPDATER)
def create_silent_updater_task_xml(): return create_task_xml(TASK_NAME_SILENT_UPDATER)
def create_memory_restart_task_xml(): return create_task_xml(TASK_NAME_MEMORY_RESTART)

def install_task(task_name: str, xml_content: str) -> bool:
    """Install a scheduled task using schtasks command.

    Uses /F overwrite only — never delete-then-create (a failed create after
    delete left CloudHoneypot-Tray missing permanently on this host).
    """
    try:
        print(f"Installing task: {task_name}")
        
        # Create temporary XML file
        temp_xml = os.path.join(os.environ['TEMP'], f"{task_name}.xml")
        
        with open(temp_xml, 'w', encoding='utf-16') as f:
            f.write(xml_content)
        
        # Create/overwrite in one step (/F). Do NOT pre-delete — if create fails
        # the previous working task must remain.
        result = subprocess.run([
            'schtasks', '/Create', '/TN', task_name, '/XML', temp_xml, '/F'
        ], capture_output=True, text=True, encoding='utf-8', errors='ignore',
        creationflags=subprocess.CREATE_NO_WINDOW)
        
        # Clean up temporary file
        try:
            os.remove(temp_xml)
        except Exception:
            pass
        
        if result.returncode == 0:
            print(f"[OK] Task {task_name} installed successfully")
            return True
        else:
            err = (result.stderr or result.stdout or "").strip()
            print(f"[X] Failed to install task {task_name}: {err}")
            return False
            
    except Exception as e:
        print(f"[X] Error installing task {task_name}: {e}")
        return False


def uninstall_task(task_name: str) -> bool:
    """Uninstall a scheduled task"""
    try:
        print(f"Uninstalling task: {task_name}")
        
        result = subprocess.run([
            'schtasks', '/Delete', '/TN', task_name, '/F'
        ], capture_output=True, text=True, encoding='utf-8', errors='ignore',
        creationflags=subprocess.CREATE_NO_WINDOW)
        
        if result.returncode == 0:
            print(f"[OK] Task {task_name} uninstalled successfully")
            return True
        else:
            print(f"[INFO] Task {task_name} was not found (already uninstalled)")
            return True  # Not found is OK for uninstall
            
    except Exception as e:
        print(f"[X] Error uninstalling task {task_name}: {e}")
        return False

def verify_task_exists(task_name):
    """Check if a specific task exists"""
    try:
        result = subprocess.run([
            'schtasks', '/Query', '/TN', task_name
        ], capture_output=True, text=True, encoding='utf-8', errors='ignore',
        creationflags=subprocess.CREATE_NO_WINDOW)
        return result.returncode == 0
    except Exception:
        return False

def verify_tasks():
    """Verify that tasks are installed and configured correctly"""
    print("\n=== Task Verification ===")
    
    for task_name in [TASK_NAME_BACKGROUND, TASK_NAME_TRAY, TASK_NAME_WATCHDOG]:
        try:
            result = subprocess.run([
                'schtasks', '/Query', '/TN', task_name, '/FO', 'LIST'
            ], capture_output=True, text=True, encoding='utf-8', errors='ignore',
            creationflags=subprocess.CREATE_NO_WINDOW)
            
            if result.returncode == 0:
                print(f"[OK] Task {task_name} found and configured")
                # Parse status from output
                for line in result.stdout.split('\n'):
                    if 'Status:' in line:
                        status = line.split(':', 1)[1].strip()
                        print(f"  Status: {status}")
                        break
            else:
                print(f"[X] Task {task_name} not found")
                
        except Exception as e:
            print(f"[X] Error checking task {task_name}: {e}")

def install_all_tasks(include_silent_updater: bool = False) -> bool:
    """Install all Task Scheduler tasks - used by installer and updates"""
    try:
        print("Installing Task Scheduler tasks...")
        success = True
        for name in TASK_CONFIGS:
            if name == TASK_NAME_SILENT_UPDATER and not include_silent_updater:
                continue
            xml = create_task_xml(name)
            success &= install_task(name, xml)
        try:
            from client_guardian_service import install_guardian_service
            if install_guardian_service(CLIENT_EXE):
                print("[OK] CloudHoneypotGuardian service installed")
            else:
                print("[WARN] Guardian service install failed (non-fatal)")
        except Exception as ge:
            print(f"[WARN] Guardian service: {ge}")
        return success
    except Exception as e:
        print(f"[X] install_all_tasks error: {e}")
        return False

def main():
    print("Cloud Honeypot Client - Task Scheduler Setup")
    print("=" * 50)
    
    if len(sys.argv) > 1 and sys.argv[1] == "uninstall":
        # Uninstall mode
        print("UNINSTALL MODE")
        print("Removing scheduled tasks...")
        
        success = True
        success &= uninstall_task(TASK_NAME_BACKGROUND)
        success &= uninstall_task(TASK_NAME_TRAY)
        success &= uninstall_task(TASK_NAME_WATCHDOG)
        
        if success:
            print("\n[OK] All tasks uninstalled successfully")
            sys.exit(0)
        else:
            print("\n[X] Some tasks could not be uninstalled")
            sys.exit(1)
    
    # Install mode (default)
    if not is_admin():
        print("ERROR: Administrator privileges required")
        print("Please run this script as Administrator")
        return False
    
    if not os.path.exists(CLIENT_EXE):
        print(f"ERROR: Client executable not found: {CLIENT_EXE}")
        print("Please ensure Cloud Honeypot Client is properly installed")
        return False
    
    print("Setting up scheduled tasks for Cloud Honeypot Client...")
    print(f"Client executable: {CLIENT_EXE}")
    
    success = install_all_tasks(include_silent_updater=True)
    
    if success:
        print("\n[OK] All tasks installed successfully")
        verify_tasks()
        status_summary = check_tasks_status(update_cache=True)
        
        print("\nTask Scheduler setup completed!")
        print("- Background task will start honeypot at boot time")
        print("- Tray task will start GUI when user logs in")
        print("- Watchdog task will check and restart services hourly")
        print("- All tasks have automatic restart on failure")
        print(f"- Verification summary: {status_summary}")
        
        return True
    else:
        print("\n[WARN] Some tasks could not be installed")
        check_tasks_status(update_cache=True)
        return False

def install_tasks():
    """Install Task Scheduler tasks - Main entry point for client.py"""
    return main()

def uninstall_tasks():
    """Uninstall all CloudHoneypot Task Scheduler tasks using PowerShell wildcard"""
    if not is_admin():
        print("Please run as Administrator to uninstall tasks")
        return False
    
    print("Removing all CloudHoneypot scheduled tasks...")
    
    try:
        # Use PowerShell to remove all CloudHoneypot* tasks
        powershell_cmd = [
            'powershell', '-ExecutionPolicy', 'Bypass', '-Command',
            'Get-ScheduledTask | Where-Object { $_.TaskName -like "CloudHoneypot*" } | ForEach-Object { Write-Host "Removing task: $($_.TaskName)"; Unregister-ScheduledTask -TaskName $_.TaskName -Confirm:$false -ErrorAction SilentlyContinue }'
        ]
        
        result = subprocess.run(powershell_cmd, capture_output=True, text=True, encoding='utf-8', errors='ignore',
                                creationflags=subprocess.CREATE_NO_WINDOW)
        
        if result.returncode == 0:
            print("[OK] All CloudHoneypot tasks removed successfully")
            
            # Also check if any tasks still exist
            remaining = check_remaining_tasks()
            if remaining:
                print(f"⚠ Some tasks may still exist: {remaining}")
                return False
            return True
        else:
            print(f"⚠ PowerShell removal had issues: {result.stderr}")
            # Fallback to individual removal
            return fallback_individual_removal()
            
    except Exception as e:
        print(f"[X] PowerShell removal failed: {e}")
        # Fallback to individual removal
        return fallback_individual_removal()

def fallback_individual_removal():
    """Fallback method - remove tasks individually"""
    print("Using fallback method - removing tasks individually...")
    success = True
    success &= uninstall_task(TASK_NAME_BACKGROUND)
    success &= uninstall_task(TASK_NAME_TRAY)
    success &= uninstall_task(TASK_NAME_WATCHDOG)
    
    if success:
        print("[OK] Individual task removal completed")
        return True
    else:
        print("[X] Some tasks could not be removed")
        return False

def check_remaining_tasks():
    """Check if any CloudHoneypot tasks still exist"""
    try:
        result = subprocess.run([
            'powershell', '-ExecutionPolicy', 'Bypass', '-Command',
            'Get-ScheduledTask | Where-Object { $_.TaskName -like "CloudHoneypot*" } | Select-Object -ExpandProperty TaskName'
        ], capture_output=True, text=True, encoding='utf-8', errors='ignore',
        creationflags=subprocess.CREATE_NO_WINDOW)
        
        if result.returncode == 0 and result.stdout.strip():
            remaining_tasks = [task.strip() for task in result.stdout.strip().split('\n') if task.strip()]
            return remaining_tasks
        return []
    except:
        return []

def check_tasks_status(update_cache=False):
    """Check if tasks are installed and running"""
    bg_status = verify_task_exists(TASK_NAME_BACKGROUND)
    tray_status = verify_task_exists(TASK_NAME_TRAY)
    watchdog_status = verify_task_exists(TASK_NAME_WATCHDOG)
    updater_status = verify_task_exists(TASK_NAME_UPDATER)
    silent_updater_status = verify_task_exists(TASK_NAME_SILENT_UPDATER)
    memory_restart_status = verify_task_exists(TASK_NAME_MEMORY_RESTART)

    status = {
        'background_task': bg_status,
        'tray_task': tray_status,
        'watchdog_task': watchdog_status,
        'updater_task': updater_status,
        'silent_updater_task': silent_updater_status,
        'memory_restart_task': memory_restart_status,
        'all_installed': bg_status and tray_status and watchdog_status and updater_status and silent_updater_status and memory_restart_status,
        'both_installed': bg_status and tray_status,  # backward compatibility
        'last_verified': int(time.time())
    }

    if update_cache:
        save_task_state(status)

    return status


def get_task_status(task_name: str) -> dict:
    """Get detailed status of a specific task"""
    try:
        # Check if task exists and get basic info
        result = subprocess.run([
            'schtasks', '/Query', '/TN', task_name, '/FO', 'LIST'
        ], capture_output=True, text=True, encoding='utf-8', errors='ignore',
        creationflags=subprocess.CREATE_NO_WINDOW)
        
        if result.returncode != 0:
            return {'exists': False, 'enabled': False, 'status': 'Not Found'}
        
        # Parse task details from output
        task_info = {'exists': True, 'enabled': False, 'status': 'Unknown'}
        
        for line in result.stdout.split('\n'):
            line = line.strip()
            if 'Status:' in line or 'Durum:' in line:  # Handle Turkish locale
                status = line.split(':', 1)[1].strip()
                task_info['status'] = status
                # Task is enabled if status is Ready, Running, or similar active states
                task_info['enabled'] = status.lower() not in ['disabled', 'devre dışı', 'could not start']
        
        return task_info
        
    except Exception as e:
        return {'exists': False, 'enabled': False, 'status': f'Error: {e}'}


def enable_task(task_name: str) -> bool:
    """Enable a task (activate it)"""
    try:
        # Use schtasks /Change to enable the task
        result = subprocess.run([
            'schtasks', '/Change', '/TN', task_name, '/ENABLE'
        ], capture_output=True, text=True, encoding='utf-8', errors='ignore',
        creationflags=subprocess.CREATE_NO_WINDOW)
        
        return result.returncode == 0
        
    except Exception:
        return False


def disable_task(task_name: str) -> bool:
    """Disable a task (deactivate it)"""
    try:
        # Use schtasks /Change to disable the task  
        result = subprocess.run([
            'schtasks', '/Change', '/TN', task_name, '/DISABLE'
        ], capture_output=True, text=True, encoding='utf-8', errors='ignore',
        creationflags=subprocess.CREATE_NO_WINDOW)
        
        return result.returncode == 0
        
    except Exception:
        return False


def run_task(task_name: str) -> bool:
    """Manually run a task"""
    try:
        # Use schtasks /Run to start the task immediately
        result = subprocess.run([
            'schtasks', '/Run', '/TN', task_name
        ], capture_output=True, text=True, encoding='utf-8', errors='ignore',
        creationflags=subprocess.CREATE_NO_WINDOW)
        
        return result.returncode == 0
        
    except Exception:
        return False


def refresh_silent_updater_schedule(log_func=None) -> bool:
    """Re-register SilentUpdater with current interval (e.g. 15m). Admin only."""
    if not is_admin():
        return False
    try:
        xml = create_task_xml(TASK_NAME_SILENT_UPDATER)
        ok = install_task(TASK_NAME_SILENT_UPDATER, xml)
        if ok:
            _log_or_print(log_func, "[OK] SilentUpdater schedule refreshed (15 min)")
        return ok
    except Exception as e:
        _log_or_print(log_func, f"[WARN] SilentUpdater refresh failed: {e}")
        return False


def refresh_watchdog_and_memory_restart(log_func=None) -> bool:
    """Re-register Watchdog (2m) + Tray (IgnoreNew) + MemoryRestart. Admin only."""
    if not is_admin():
        return False
    ok_all = True
    try:
        ensure_memory_restart_script_on_disk()
        for name, label in (
            (TASK_NAME_WATCHDOG, "Watchdog 2m"),
            (TASK_NAME_TRAY, "Tray Authenticated Users logon"),
            (TASK_NAME_MEMORY_RESTART, "MemoryRestart path fix"),
        ):
            xml = create_task_xml(name)
            ok = install_task(name, xml)
            ok_all = ok_all and ok
            if ok:
                _log_or_print(log_func, f"[OK] {label} schedule refreshed")
            else:
                _log_or_print(log_func, f"[WARN] Failed to refresh {name}")
    except Exception as e:
        _log_or_print(log_func, f"[WARN] Watchdog/MemoryRestart refresh failed: {e}")
        return False
    return ok_all


def _task_refresh_marker_path() -> str:
    return os.path.join(
        os.environ.get("ProgramData", r"C:\ProgramData"),
        "YesNext",
        "CloudHoneypotClient",
        "tasks_refresh_version.txt",
    )


def _should_refresh_task_schedules() -> bool:
    """Only re-create schtasks XML when client VERSION changes (not every GUI start)."""
    try:
        from client_constants import VERSION
        marker = _task_refresh_marker_path()
        if os.path.isfile(marker):
            with open(marker, "r", encoding="utf-8") as fh:
                if fh.read().strip() == str(VERSION):
                    return False
        return True
    except Exception:
        return True


def _mark_task_schedules_refreshed() -> None:
    try:
        from client_constants import VERSION
        path = _task_refresh_marker_path()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(str(VERSION))
    except Exception:
        pass


def perform_comprehensive_task_management(log_func=None, app_state=None, *, light: bool = False):
    """
    Comprehensive Task Scheduler management for application startup
    
    This function handles the complete task lifecycle:
    1. Check and install missing tasks (requires admin for installation)
    2. Verify and activate existing tasks (works without admin)
    3. Update application state with task information

    light=True: skip schedule XML refresh + skip per-task enable loop (fast GUI path).
    """
    if log_func is None: log_func = print
    try:
        log_func("🔧 Performing comprehensive Task Scheduler management...")
        
        # Step 1: Check and install missing tasks
        result = ensure_tasks_installed(log_func=log_func, force=False)

        # Keep schedules in sync with this build — ONLY when VERSION changed
        if is_admin() and not light and _should_refresh_task_schedules():
            refresh_silent_updater_schedule(log_func=log_func)
            refresh_watchdog_and_memory_restart(log_func=log_func)
            _mark_task_schedules_refreshed()
        elif is_admin() and not light:
            log_func("[OK] Task schedules already match this version (skip refresh)")
        
        if result.get('success'):
            log_func("✅ All Task Scheduler tasks are registered")
        elif result.get('admin_required'):
            # Detaylı durum bilgisi ver
            status = result.get('status', {})
            missing_tasks = []
            
            if not status.get('tray_task', False):
                missing_tasks.append("Tray (user startup)")
            if not status.get('background_task', False):
                missing_tasks.append("Background (system service)")
            if not status.get('watchdog_task', False):
                missing_tasks.append("Watchdog (monitoring)")
            if not status.get('updater_task', False):
                missing_tasks.append("Updater (maintenance)")
            if not status.get('silent_updater_task', False):
                missing_tasks.append("SilentUpdater (auto-update)")
            if not status.get('memory_restart_task', False):
                missing_tasks.append("MemoryRestart (8h cleanup)")
            
            if missing_tasks:
                log_func(f"⚠️ Missing task(s): {', '.join(missing_tasks)} - requires admin installation")
                # Update application state if provided
                if app_state is not None:
                    app_state["missing_tasks"] = missing_tasks
            else:
                log_func("✅ All Task Scheduler tasks are registered")
        
        # Step 2: Verify and enable existing tasks (works without admin)
        # Skip on light/GUI path — disable→enable loop is multi-second schtasks spam
        if light:
            log_func("🎯 Task management (light) complete — activation deferred")
            return result

        log_func("🔧 Checking task activation status...")
        task_names = [
            TASK_NAME_BACKGROUND,
            TASK_NAME_TRAY, 
            TASK_NAME_WATCHDOG,
            TASK_NAME_UPDATER,
            TASK_NAME_SILENT_UPDATER,
            TASK_NAME_MEMORY_RESTART
        ]
        
        activated_count = 0
        activation_results = {}
        
        for task_name in task_names:
            try:
                task_status = get_task_status(task_name)
                if task_status.get('exists', False):
                    if not task_status.get('enabled', False):
                        log_func(f"📋 Activating task: {task_name}")
                        if enable_task(task_name):
                            activated_count += 1
                            activation_results[task_name] = "activated"
                            log_func(f"✅ Task activated: {task_name}")
                        else:
                            activation_results[task_name] = "activation_failed"
                            log_func(f"⚠️ Could not activate task: {task_name}")
                    else:
                        activation_results[task_name] = "already_active"
                        log_func(f"✅ Task already active: {task_name}")
                        activated_count += 1
                else:
                    activation_results[task_name] = "not_found"
                    
            except Exception as task_error:
                activation_results[task_name] = f"error: {task_error}"
                log_func(f"⚠️ Task check error for {task_name}: {task_error}")
        
        if activated_count > 0:
            log_func(f"🎯 Task management complete - {activated_count} tasks active")
        else:
            log_func("⚠️ No tasks could be activated - may need admin privileges")
        
        return {
            'success': True,
            'activated_count': activated_count,
            'activation_results': activation_results,
            'installation_result': result
        }
        
    except Exception as e:
        log_func(f"Task Scheduler management error: {e}")
        return {
            'success': False,
            'error': str(e),
            'activated_count': 0,
            'activation_results': {},
            'installation_result': {}
        }


# For backwards compatibility when run as standalone script
if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "uninstall":
        success = uninstall_tasks()
    else:
        success = install_tasks()
    
    sys.exit(0 if success else 1)