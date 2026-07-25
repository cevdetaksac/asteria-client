# -*- mode: python ; coding: utf-8 -*-
"""
onedir package — python312.dll lives under $INSTDIR\\_internal (no _MEI unpack).

IMPORTANT: Never put our client_*.py modules in ``datas``. That copies plain
source next to the exe. Application code must enter PYZ via Analysis/imports
(and ``hiddenimports``) as bytecode only.
"""
import os

# rd6 WebRTC is opt-in because aiortc/av add native binaries and substantial
# size. Build with HONEYPOT_WEBRTC=1 after installing requirements-webrtc.txt.
_webrtc_hidden = []
_webrtc_enabled = os.environ.get('HONEYPOT_WEBRTC') == '1'
_webrtc_excludes = [] if _webrtc_enabled else ['aiortc', 'av', 'dxcam']
if _webrtc_enabled:
    try:
        from PyInstaller.utils.hooks import collect_submodules
        _webrtc_hidden = (
            collect_submodules('aiortc')
            + collect_submodules('av')
            + collect_submodules('dxcam')
        )
    except Exception:
        _webrtc_hidden = []

try:
    import certifi as _certifi
    _cacert = _certifi.where()
    _certifi_datas = [(_cacert, 'certifi')] if _cacert and os.path.isfile(_cacert) else []
except Exception:
    _certifi_datas = []

# Non-code assets only — JSON/icons/ps1 helpers. NO client_*.py here.
_datas = [
    ('certs/*.ico', 'certs'),
    ('certs/*.png', 'certs'),
    ('certs/*.bmp', 'certs'),
    ('logo_set/*.png', 'logo_set'),
    ('client_config.json', '.'),
    ('client_lang.json', '.'),
    ('memory_restart.ps1', '.'),
    ('scripts/update-and-install.ps1', 'scripts'),
] + _certifi_datas

# Ensure optional/lazy modules are collected into PYZ (bytecode), not datas.
_hidden = [
    'client_memory_restart',
    'client_presence',
    'client_power_presence',
    'client_process_priority',
    'client_resources',
    'client_control_ws',
    'client_daemon_ipc',
    'client_lifecycle',
    'client_update_ui',
    'client_winproc',
    'client_remote_session',
    'client_rdp_nla',
    'client_honeypots',
    'client_service_manager',
    'client_gui_lock',
    'client_uninstall_gate',
    'client_logon_challenge',
    'client_eventlog',
    'client_threat_engine',
    'client_threat_intel',
    'client_alerts',
    'client_auto_response',
    'client_brick_guard',
    'client_remote_commands',
    'client_remote_desktop',
    'client_rd_adaptive',
    'client_rd_media',
    'client_rd_session_helper',
    'client_rd_encoder',
    'client_rd_winlogon',
    'client_server_management',
    'client_silent_hours',
    'client_ransomware_shield',
    'client_system_health',
    'client_system_recovery',
    'client_self_protection',
    'client_performance',
    'client_guardian_service',
    'client_operator_stop',
    'client_tamper',
    'client_autologon',
    'client_network_guard',
    'client_defense_policy',
    'client_integrity',
    'client_command_envelope',
    'client_resilience',
    'client_resilience_p1',
    'client_offline_queue',
    'client_identity_correlation',
    'client_device_identity',
    'client_operator_keys',
    'client_firewall',
    'client_cleanup',
    'client_block_store',
    'client_protection_store',
    'client_settings_util',
    'client_security_utils',
    'client_security',
    'client_authenticode',
    'client_etw_shadow',
    'client_logging',
    'client_log_retention',
    'client_api',
    'client_tokens',
    'client_helpers',
    'client_instance',
    'client_install_acl',
    'client_threat_local',
    'client_update_hardening',
    'client_updater',
    'client_utils',
    'client_constants',
    'client_task_scheduler',
    'client_monitoring',
    'client_rdp',
    'paramiko',
    'psutil',
    'websocket',
    'win32event',
    'win32api',
    'winerror',
    'win32security',
    'ntsecuritycon',
    'win32serviceutil',
    'win32service',
    'servicemanager',
    'certifi',
    'cryptography',
] + _webrtc_hidden

a = Analysis(
    ['client.py'],
    pathex=[],
    binaries=[],
    datas=_datas,
    hiddenimports=_hidden,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=['rthook_ssl_certs.py', 'rthook_motor_only.py'],
    excludes=_webrtc_excludes + [
        'client_gui',
        'client_gui_theme',
        'client_tray',
        'customtkinter',
        'pystray',
        'darkdetect',
    ],
    noarchive=False,
    optimize=1,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='asteria-client',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['certs\\asteria_256.ico'],
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name='asteria-client',
)
