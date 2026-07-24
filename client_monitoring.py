#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Client Monitoring — Heartbeat & health-check system.

JSON heartbeat file updated every FILE_HEARTBEAT_INTERVAL seconds,
atomic writes via temp+rename. Health check exits with code 0/3.

Key exports:
  MonitoringManager             — start/stop heartbeat, get path
  perform_health_check()        — CLI health probe (exit 0 OK, 3 fail)
  create/update/cleanup_heartbeat_file()  — low-level heartbeat I/O
"""

import os
import sys
import json
import time
import threading
import datetime as dt
import ctypes
import tempfile
from typing import Optional, Dict, Any

from client_constants import HEARTBEAT_FILE, FILE_HEARTBEAT_INTERVAL, __version__
from client_helpers import log

# ===================== HEARTBEAT SYSTEM ===================== #

def create_heartbeat_file(app_dir: str) -> str:
    """Create initial heartbeat file and return path"""
    heartbeat_path = os.path.join(app_dir, HEARTBEAT_FILE)
    try:
        heartbeat_data = {
            "application": "Asteria Client",
            "version": __version__ if '__version__' in globals() else "1.0.0",
            "pid": os.getpid(),
            "executable": sys.executable if getattr(sys, 'frozen', False) else os.path.abspath(sys.argv[0]),
            "working_directory": os.getcwd(),
            "started_at": dt.datetime.now().isoformat(),
            "last_heartbeat": dt.datetime.now().isoformat(),
            "status": "initializing",
            "admin_privileges": ctypes.windll.shell32.IsUserAnAdmin() if os.name == 'nt' else False,
            "active_services": 0,
            "api_connected": False
        }
        
        with open(heartbeat_path, 'w', encoding='utf-8') as f:
            json.dump(heartbeat_data, f, indent=2, ensure_ascii=False)
        
        log(f"Heartbeat sistemi başlatıldı: {heartbeat_path}")
        return heartbeat_path
    except Exception as e:
        log(f"Heartbeat dosyası oluşturulamadı: {e}")
        return ""

def _atomic_write_json(filepath: str, data: dict):
    """Atomik JSON yazma — temp dosyaya yaz, sonra rename et"""
    dir_name = os.path.dirname(filepath)
    fd, tmp_path = tempfile.mkstemp(dir=dir_name, suffix='.tmp')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        os.replace(tmp_path, filepath)  # atomic on same filesystem
    except Exception:
        try: os.unlink(tmp_path)
        except OSError: pass
        raise

def update_heartbeat_file(heartbeat_path: str, app_instance=None) -> bool:
    """Update heartbeat file with current timestamp and status (atomic write)"""
    if not heartbeat_path or not os.path.exists(heartbeat_path): return False
    try:
        # Read existing data
        with open(heartbeat_path, 'r', encoding='utf-8') as f:
            heartbeat_data = json.load(f)
        
        # Update timestamp and status
        heartbeat_data["last_heartbeat"] = dt.datetime.now().isoformat()
        
        # Update status information if app instance is available
        if app_instance:
            heartbeat_data["status"] = "running"
            # ServiceManager üzerinden aktif servis sayısını al
            if hasattr(app_instance, 'service_manager'):
                heartbeat_data["active_services"] = len(app_instance.service_manager.running_services)
            else:
                heartbeat_data["active_services"] = 0
            heartbeat_data["api_connected"] = bool(app_instance.state.get("token"))
        else:
            heartbeat_data["status"] = "running"
        
        # Atomic write — çökme anında dosya bozulmaz
        _atomic_write_json(heartbeat_path, heartbeat_data)
        
        return True
    except Exception as e:
        log(f"Heartbeat güncelleme hatası: {e}")
        return False

def heartbeat_worker(heartbeat_path: str, app_instance=None):
    """Background worker for heartbeat updates"""
    log(f"Heartbeat worker başlatıldı (her {FILE_HEARTBEAT_INTERVAL} saniye)")
    
    while True:
        try:
            if update_heartbeat_file(heartbeat_path, app_instance):
                pass  # Successful update, no logging needed to avoid spam
            else:
                log("Heartbeat güncellenemedi")
            
            time.sleep(FILE_HEARTBEAT_INTERVAL)
        except Exception as e:
            log(f"Heartbeat worker hatası: {e}")
            time.sleep(FILE_HEARTBEAT_INTERVAL)

def cleanup_heartbeat_file(heartbeat_path: str):
    """Clean up heartbeat file on application exit"""
    try:
        if heartbeat_path and os.path.exists(heartbeat_path):
            # Update final status
            with open(heartbeat_path, 'r', encoding='utf-8') as f:
                heartbeat_data = json.load(f)
            
            heartbeat_data["status"] = "stopped"
            heartbeat_data["stopped_at"] = dt.datetime.now().isoformat()
            
            with open(heartbeat_path, 'w', encoding='utf-8') as f:
                json.dump(heartbeat_data, f, indent=2, ensure_ascii=False)
            
            log("Heartbeat sistemi durduruldu")
    except Exception as e:
        log(f"Heartbeat temizlik hatası: {e}")

# ===================== HEALTH CHECK SYSTEM ===================== #

def perform_health_check():
    """Perform health check and return status"""
    try:
        log("=== HEALTH CHECK STARTED ===")
        
        # Check if process is running
        pid = os.getpid()
        log(f"Current PID: {pid}")
        
        # Check heartbeat file if exists
        import sys
        app_dir = os.path.dirname(sys.executable if getattr(sys, 'frozen', False) else os.path.abspath(sys.argv[0]))
        heartbeat_path = os.path.join(app_dir, HEARTBEAT_FILE)
        
        if os.path.exists(heartbeat_path):
            try:
                with open(heartbeat_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                last_heartbeat_str = data.get('last_heartbeat')
                if last_heartbeat_str:
                    last_heartbeat = dt.datetime.fromisoformat(last_heartbeat_str)
                    now = dt.datetime.now()
                    time_diff = (now - last_heartbeat).total_seconds()
                    
                    log(f"Heartbeat age: {time_diff:.1f} seconds")
                    
                    if time_diff > 60:  # More than 1 minute old
                        log("WARNING: Heartbeat is stale")
                        sys.exit(3)  # Exit code 3 = Health fail
                else:
                    log("WARNING: No heartbeat timestamp found")
                    sys.exit(3)
                    
            except Exception as e:
                log(f"WARNING: Could not read heartbeat file: {e}")
                sys.exit(3)
        else:
            log("INFO: No heartbeat file found (normal for fresh start)")
        
        log("=== HEALTH CHECK PASSED ===")
        
    except Exception as e:
        log(f"HEALTH CHECK ERROR: {e}")
        sys.exit(3)

class MonitoringManager:
    """Central monitoring manager for heartbeat and health checks"""
    
    def __init__(self, app_dir: str):
        self.app_dir = app_dir
        self.heartbeat_path = None
        self.heartbeat_thread = None
        
    def start_heartbeat_system(self, app_instance=None):
        """Start heartbeat monitoring system"""
        try:
            self.heartbeat_path = create_heartbeat_file(self.app_dir)
            if self.heartbeat_path:
                # Start heartbeat worker thread
                self.heartbeat_thread = threading.Thread(
                    target=heartbeat_worker, 
                    args=(self.heartbeat_path, app_instance),
                    daemon=True,
                    name="HeartbeatWorker"
                )
                self.heartbeat_thread.start()
                log("Heartbeat monitoring başlatıldı")
                return True
        except Exception as e:
            log(f"Heartbeat sistem başlatma hatası: {e}")
        return False
    
    def stop_heartbeat_system(self):
        """Stop heartbeat monitoring system"""
        try:
            if self.heartbeat_path:
                cleanup_heartbeat_file(self.heartbeat_path)
            log("Heartbeat monitoring durduruldu")
        except Exception as e:
            log(f"Heartbeat sistem durdurma hatası: {e}")
    
    def get_heartbeat_path(self) -> str:
        """Get current heartbeat file path"""
        return self.heartbeat_path or ""