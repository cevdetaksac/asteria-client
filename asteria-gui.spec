# -*- mode: python ; coding: utf-8 -*-
"""Onefile Asteria GUI host; the SYSTEM motor remains a separate artifact."""

from pathlib import Path

root = Path(SPECPATH)
ui_dist = root / "ui" / "dist"
logo_set = root / "logo_set"
if not (ui_dist / "index.html").is_file():
    raise SystemExit("ui/dist missing; run `npm run build` in ui/")

datas = [(str(ui_dist), "ui")]
if logo_set.is_dir():
    datas.append((str(logo_set), "logo_set"))
certs = root / "certs"
if certs.is_dir():
    datas.append((str(certs), "certs"))

a = Analysis(
    ["asteria_gui.py"],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=[
        "webview",
        "webview.platforms.edgechromium",
        "clr",
        "pythonnet",
        "client_daemon_ipc",
        "client_constants",
        "client_gui_lock",
        "client_api",
        "client_utils",
        "client_security_utils",
        "client_settings_util",
        "client_winproc",
        "client_update_ui",
        "client_updater",
        "client_remote_session",
        "client_windows_tools",
        "client_logging",
        "client_log_retention",
        "requests",
        "urllib3",
        "certifi",
        "pystray",
        "PIL.Image",
        "PIL.ImageDraw",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "customtkinter",
        # Keep Tk out of the WebView host; client_helpers is provided by a
        # runtime shim in asteria_gui.py (avoids No module named client_helpers).
        "tkinter",
        "client_helpers",
        "aiortc",
        "av",
        "dxcam",
    ],
    noarchive=False,
    optimize=1,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="asteria-gui",
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
    icon=["certs\\asteria_256.ico"],
    # Unpack beside a durable user-writable tree — never Windows\TEMP\_MEI*
    # (AV / execute-from-TEMP policies → Failed to load Python DLL).
    runtime_tmpdir="%LOCALAPPDATA%\\Asteria\\runtime\\gui",
)
