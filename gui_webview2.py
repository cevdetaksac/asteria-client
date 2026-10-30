"""WebView2 runtime detection / silent install / missing-runtime prompt (split from asteria_gui)."""
from __future__ import annotations

import logging
import os
import sys
import time
from pathlib import Path
from typing import Optional


def _local_stamp(name: str) -> Path:
    return Path(os.environ.get("LOCALAPPDATA", "") or ".") / "Asteria" / name


def _stamp_age(path: Path) -> Optional[float]:
    """Seconds since the stamp was written, None if missing/unreadable."""
    try:
        return time.time() - path.stat().st_mtime if path.is_file() else None
    except OSError:
        return None


def _touch(path: Path) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(str(time.time()), encoding="utf-8")
    except OSError:
        pass


def _webview2_runtime_present() -> bool:
    """Best-effort check for Edge WebView2 Evergreen Runtime (blank white UI without it)."""
    if os.name != "nt":
        return True
    try:
        import winreg

        keys = (
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"),
        )
        for hive, path in keys:
            try:
                with winreg.OpenKey(hive, path) as key:
                    ver, _ = winreg.QueryValueEx(key, "pv")
                    if ver and str(ver) not in ("", "0.0.0.0"):
                        return True
            except OSError:
                continue
    except Exception:
        pass
    # Filesystem fallback — registry can lag right after silent install.
    for base in (
        os.environ.get("ProgramFiles", r"C:\Program Files"),
        os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
    ):
        try:
            exe = Path(base) / "Microsoft" / "EdgeWebView" / "Application" / "msedgewebview2.exe"
            if exe.is_file():
                return True
        except OSError:
            continue
    return False


def _install_root() -> Path:
    try:
        return Path(sys.executable).resolve().parent
    except Exception:
        return Path(".")


def _webview2_payload_path() -> Path | None:
    """Prefer offline standalone installer; bootstrapper is network fallback only."""
    names = (
        "MicrosoftEdgeWebView2RuntimeInstallerX64.exe",
        "MicrosoftEdgeWebview2Setup.exe",
    )
    roots: list[Path] = []
    try:
        roots.append(_install_root())
    except Exception:
        pass
    try:
        mei = getattr(sys, "_MEIPASS", None)
        if mei:
            roots.append(Path(mei))
    except Exception:
        pass
    for root in roots:
        for name in names:
            try:
                path = root / name
                if not path.is_file():
                    continue
                # Standalone ~150MB; bootstrapper ~1.5MB
                min_size = 40_000_000 if "RuntimeInstaller" in name else 100_000
                if path.stat().st_size >= min_size:
                    return path
            except OSError:
                continue
    return None


def _try_silent_webview2_install(logger: logging.Logger) -> bool:
    """Run bundled offline/standalone installer once; return True if runtime appears."""
    payload = _webview2_payload_path()
    if payload is None:
        return False
    stamp = _local_stamp("webview2_auto_install.stamp")
    age = _stamp_age(stamp)
    # Don't thrash UAC / installer on every tray launch.
    if age is not None and age < 3600:
        logger.info("WebView2 auto-install skipped (recent attempt %.0fs ago)", age)
        return _webview2_runtime_present()
    logger.info("Attempting silent WebView2 install from %s", payload)
    try:
        import ctypes
        import subprocess

        # Prefer elevated silent install (per-machine).
        rc = int(
            ctypes.windll.shell32.ShellExecuteW(
                None,
                "runas",
                str(payload),
                "/silent /install",
                str(payload.parent),
                1,  # SW_SHOWNORMAL — installer may flash briefly
            )
        )
        if rc <= 32:
            logger.warning("ShellExecute WebView2 install failed rc=%s — trying CreateProcess", rc)
            subprocess.run(
                [str(payload), "/silent", "/install"],
                timeout=600,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        else:
            # ShellExecuteW does not wait — poll for runtime up to ~3 min.
            for _ in range(36):
                time.sleep(5)
                if _webview2_runtime_present():
                    break
        _touch(stamp)
    except Exception as exc:
        logger.warning("WebView2 silent install error: %s", exc)
        return False
    ok = _webview2_runtime_present()
    logger.info("WebView2 after silent install present=%s", ok)
    return ok


def _warn_missing_webview2(logger: logging.Logger, *, allow_prompt: bool = True) -> None:
    payload = _webview2_payload_path()
    url = "https://developer.microsoft.com/microsoft-edge/webview2/"
    # Rate-limit modal spam (tray relaunch / failed webview.start loops).
    nag = _local_stamp("webview2_nag.stamp")
    age = _stamp_age(nag)
    if allow_prompt and age is not None and age < 1800:
        logger.error("WebView2 Runtime missing — suppressing repeat alert")
        return
    if payload is not None:
        msg = (
            "Microsoft Edge WebView2 Runtime bulunamadı.\n\n"
            "Asteria Control Center boş/beyaz pencere gösterir.\n"
            "Evet = paketlenen offline kurucuyu şimdi çalıştır.\n"
            "Hayır = iptal.\n\n"
            f"Manuel: {url}\n"
            "Log: %LOCALAPPDATA%\\Asteria\\logs\\asteria-gui.log"
        )
    else:
        msg = (
            "Microsoft Edge WebView2 Runtime bulunamadı.\n\n"
            "Asteria Control Center boş/beyaz pencere gösterir.\n"
            f"Evet = indirme sayfasını aç ({url}).\n"
            "Hayır = iptal.\n\n"
            "Asteria kurucusunu yeniden çalıştırın (WebView2 gömülü).\n"
            "Log: %LOCALAPPDATA%\\Asteria\\logs\\asteria-gui.log"
        )
    logger.error("WebView2 Runtime missing — GUI will be blank")
    if not allow_prompt:
        return
    try:
        import ctypes

        _touch(nag)
        # MB_YESNO | MB_ICONERROR
        choice = int(ctypes.windll.user32.MessageBoxW(0, msg, "Asteria — WebView2 gerekli", 0x14))
        if choice == 6:  # IDYES
            if payload is not None:
                logger.info("Launching WebView2 payload: %s", payload)
                ctypes.windll.shell32.ShellExecuteW(
                    None, "runas", str(payload), "/silent /install", str(payload.parent), 1
                )
            else:
                ctypes.windll.shell32.ShellExecuteW(None, "open", url, None, None, 1)
    except Exception:
        pass
