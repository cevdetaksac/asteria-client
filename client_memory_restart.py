#!/usr/bin/env python3
"""
🔄 Memory Restart Registry Helper
Task Scheduler tabanlı memory restart için registry helper fonksiyonları
"""

import os
import sys
import time
import json

# Safe import for logging
try:
    from client_helpers import log
except ImportError:
    def log(msg):
        print(f"[{time.strftime('%H:%M:%S')}] {msg}")

def check_previous_restart_state():
    """Startup'da önceki restart'ı kontrol et (Task Scheduler için)"""
    try:
        # Task Scheduler approach için basit state kontrolü
        # Registry'den mode alınacak, bu sadece log için
        appdata = os.environ.get('APPDATA', '')
        if appdata:
            state_file = os.path.join(appdata, 'Asteria', 'restart_mode.json')
        else:
            state_file = 'restart_mode.json'
            
        if os.path.exists(state_file):
            with open(state_file, 'r') as f:
                data = json.load(f)
            
            # Dosyayı temizle
            os.remove(state_file)
            
            mode = data.get('mode', 'unknown')
            elapsed = time.time() - data.get('time', 0)
            log(f"🔄 Task Scheduler restart detected: {elapsed:.0f}s ago, mode: {mode}")
            
            return data
            
    except Exception as e:
        log(f"⚠️ Restart state check failed: {e}")
    
    return None

def get_current_memory_mb():
    """Compatibility function - memory bilgisi al"""
    try:
        import psutil
        return psutil.Process().memory_info().rss / 1024 / 1024
    except Exception:
        return 0

# Compatibility functions (artık Task Scheduler kullanıyoruz)
def enable_simple_memory_restart(restart_hours=8):
    """Compatibility function - artık Task Scheduler kullanıyor"""
    log(f"🔄 Memory restart now managed by Task Scheduler (every {restart_hours}h)")
    return True