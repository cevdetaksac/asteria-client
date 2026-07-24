#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Client Updater — Installer-based update system via GitHub releases.

Interactive & silent update modes with progress dialogs.
Hourly watchdog loop for automatic background updates.

Key exports:
  UpdateManager                    — start_update_watchdog(), interactive/silent checks
  check_updates_and_prompt(app)    — interactive update with UI dialogs
  check_updates_and_apply_silent() — background NSIS silent install
  update_watchdog_loop()           — hourly update check (daemon thread)
"""

import os
import sys
import time
import threading
from typing import Optional, Dict, Any, Callable, Tuple

from client_constants import GITHUB_OWNER, GITHUB_REPO
from client_helpers import log

def _updater_t(key: str, **kwargs) -> str:
    """i18n helper for updater dialogs (no app instance required)."""
    try:
        from client_utils import load_i18n, resolve_app_language
        lang = resolve_app_language()
        i18n = load_i18n(language=lang)
        if isinstance(i18n, dict) and lang in i18n:
            table = i18n[lang]
        elif isinstance(i18n, dict):
            table = i18n.get("tr") or i18n.get("en") or {}
        else:
            table = {}
        text = table.get(key) or (i18n.get("en", {}) or {}).get(key) or key
        if kwargs:
            try:
                return text.format(**kwargs)
            except Exception:
                return text
        return text
    except Exception:
        return key

# ===================== UPDATE MANAGEMENT ===================== #

def show_completion_dialog(installer_path: str, version: str, parent=None):
    """After download: offer install now (primary) with reliable elevated launch."""
    import tkinter as tk
    import tkinter.ttk as ttk
    from tkinter import messagebox

    def _exit_for_update():
        """Quit quickly so NSIS can overwrite the onefile EXE."""
        try:
            from client_self_protection import disarm_for_update
            disarm_for_update(reason="gui_update_exit")
        except Exception:
            pass
        try:
            import socket as _sock
            try:
                with _sock.create_connection(("127.0.0.1", 58632), timeout=0.4) as s:
                    s.sendall(b"QUIT\n")
            except Exception:
                pass
            threading.Thread(
                target=lambda: (time.sleep(0.8), os._exit(0)),
                daemon=True,
            ).start()
        except Exception:
            os._exit(0)

    def _start_install(dialog_widget=None):
        """Open NSIS installer visibly first; exit client after it starts."""
        from client_utils import (
            launch_interactive_installer_and_exit_prep,
            launch_safe_update_install,
            release_update_lock,
        )
        try:
            if not installer_path or not os.path.isfile(installer_path):
                messagebox.showerror(
                    _updater_t("error"),
                    _updater_t("update_download_fail"),
                )
                return False

            log(f"[UPDATER] Starting interactive installer: {installer_path}")

            # Primary: open the NSIS wizard NOW (what the user expects after Yes)
            ok = launch_interactive_installer_and_exit_prep(installer_path)
            if ok:
                log("[UPDATER] Installer process started (visible)")
                if dialog_widget is not None:
                    try:
                        dialog_widget.destroy()
                    except Exception:
                        pass
                # Exit immediately — NSIS is already visible; do not block on messagebox
                _exit_for_update()
                return True

            # Secondary: elevated helper (silent-style orchestrator)
            log("[UPDATER] Direct installer launch failed — trying safe helper")
            ok = launch_safe_update_install(
                installer_path,
                silent=False,
                show_gui_after=True,
                expect_exit_pid=os.getpid(),
                elevate=True,
                grace_wait_sec=15,
            )
            if ok:
                if dialog_widget is not None:
                    try:
                        dialog_widget.destroy()
                    except Exception:
                        pass
                _exit_for_update()
                return True

            release_update_lock()
            messagebox.showerror(
                _updater_t("error"),
                _updater_t("update_helper_failed"),
            )
            # Last resort: open Downloads folder
            try:
                os.startfile(os.path.dirname(installer_path))
            except Exception:
                pass
            return False
        except Exception as e:
            log(f"[UPDATER] start install error: {e}")
            try:
                release_update_lock()
            except Exception:
                pass
            messagebox.showerror(
                _updater_t("error"),
                _updater_t("update_installer_fail", err=str(e)),
            )
            return False

    try:
        # Primary path: ask immediately after download (installer must start on Yes)
        if messagebox.askyesno(
            _updater_t("update_ready"),
            _updater_t("update_ready_ask", version=version, path=installer_path),
            parent=parent,
        ):
            _start_install(None)
            return

        dialog = tk.Toplevel(parent) if parent is not None else tk.Toplevel()
        dialog.title(_updater_t("update_done_title"))
        dialog.resizable(False, False)
        try:
            dialog.transient(parent)
        except Exception:
            pass
        dialog.grab_set()

        main_frame = ttk.Frame(dialog, padding="15")
        main_frame.grid(row=0, column=0, sticky="nsew")
        dialog.grid_rowconfigure(0, weight=1)
        dialog.grid_columnconfigure(0, weight=1)

        ttk.Label(
            main_frame,
            text=f"✅ {_updater_t('update_download_done')}",
            font=("Arial", 16, "bold"),
        ).grid(row=0, column=0, columnspan=2, pady=(0, 12))

        ttk.Label(
            main_frame,
            text=_updater_t(
                "update_download_info",
                version=version,
                filename=os.path.basename(installer_path),
            ),
            justify="left",
            wraplength=420,
        ).grid(row=1, column=0, columnspan=2, pady=(0, 12), sticky="ew")

        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=2, column=0, columnspan=2, pady=(5, 0), sticky="ew")

        def run_installer():
            _start_install(dialog)

        def open_downloads():
            try:
                from client_utils import release_update_lock
                release_update_lock()
                os.startfile(os.path.dirname(installer_path))
                messagebox.showinfo(
                    _updater_t("folder_opened_title"),
                    _updater_t(
                        "update_folder_opened",
                        filename=os.path.basename(installer_path),
                    ),
                )
            except Exception as e:
                messagebox.showerror(
                    _updater_t("error"),
                    _updater_t("update_folder_fail", err=str(e)),
                )

        def open_github():
            import webbrowser
            try:
                github_url = f"https://github.com/{GITHUB_OWNER}/{GITHUB_REPO}/releases/tag/v{version}"
                webbrowser.open(github_url)
            except Exception as e:
                messagebox.showerror(
                    _updater_t("error"),
                    _updater_t("update_github_fail", err=str(e)),
                )

        def close_dialog():
            try:
                from client_utils import release_update_lock
                release_update_lock()
            except Exception:
                pass
            dialog.destroy()

        install_btn = ttk.Button(
            button_frame,
            text=f"🚀 {_updater_t('update_run_installer')}",
            command=run_installer,
            width=28,
        )
        install_btn.grid(row=0, column=0, columnspan=2, pady=(5, 3), sticky="ew")

        ttk.Button(
            button_frame,
            text=f"📁 {_updater_t('update_open_downloads')}",
            command=open_downloads,
            width=20,
        ).grid(row=1, column=0, padx=(0, 3), pady=3, sticky="ew")

        ttk.Button(
            button_frame,
            text=f"🌐 {_updater_t('update_open_github_alt')}",
            command=open_github,
            width=20,
        ).grid(row=1, column=1, padx=(3, 0), pady=3, sticky="ew")

        ttk.Button(
            button_frame,
            text=f"❌ {_updater_t('update_not_now')}",
            command=close_dialog,
            width=28,
        ).grid(row=2, column=0, columnspan=2, pady=(8, 5), sticky="ew")

        main_frame.columnconfigure(0, weight=1)
        button_frame.columnconfigure(0, weight=1)
        button_frame.columnconfigure(1, weight=1)

        dialog.update_idletasks()
        req_width = max(main_frame.winfo_reqwidth() + 30, 450)
        req_height = max(main_frame.winfo_reqheight() + 30, 280)
        x = (dialog.winfo_screenwidth() // 2) - (req_width // 2)
        y = (dialog.winfo_screenheight() // 2) - (req_height // 2)
        dialog.geometry(f"{req_width}x{req_height}+{x}+{y}")

        try:
            dialog.lift()
            dialog.attributes("-topmost", True)
            dialog.after(400, lambda: dialog.attributes("-topmost", False))
        except Exception:
            pass

        install_btn.focus_set()
        dialog.bind("<Return>", lambda _e: run_installer())
        dialog.wait_window()

    except Exception as e:
        log(f"[UPDATE] Dialog error: {e}")
        result = messagebox.askyesno(
            _updater_t("update_ready"),
            _updater_t("update_ready_ask", version=version, path=installer_path),
        )
        if result:
            _start_install(None)


def check_updates_and_prompt(app_instance) -> bool:
    """Check for updates with immediate progress UI; then download + install start."""
    import threading
    import tkinter.messagebox as messagebox
    from client_utils import (
        create_update_manager,
        UpdateProgressDialog,
        acquire_update_lock,
        release_update_lock,
        pause_competing_updaters,
    )

    root = getattr(app_instance, "root", None)
    gui_safe = getattr(app_instance, "_gui_safe", lambda fn: fn())

    progress_dialog = UpdateProgressDialog(root, _updater_t("update_title"))
    if not progress_dialog.create_dialog():
        messagebox.showerror(_updater_t("update_title"), _updater_t("update_progress_fail"))
        return False

    progress_dialog.update_progress(5, _updater_t("update_checking"))
    update_mgr = create_update_manager(GITHUB_OWNER, GITHUB_REPO, log)

    def _close_progress():
        progress_dialog.close_dialog()

    def _start_download(latest_ver: str, update_info: dict):
        acquire_update_lock("interactive-download")
        pause_competing_updaters()
        progress_dialog.update_progress(10, _updater_t("update_downloading", version=latest_ver))

        def _download_worker():
            try:
                def _progress(percent, message):
                    gui_safe(lambda p=percent, m=message: progress_dialog.update_progress(p, m))

                def _download_progress(percent):
                    _progress(
                        15 + int(percent * 0.8),
                        _updater_t("update_downloading_pct", percent=percent),
                    )

                installer_path = update_mgr.download_installer(
                    update_info["installer_url"],
                    _download_progress,
                )

                def _on_download_done():
                    _close_progress()
                    if installer_path:
                        log(f"[UPDATER] Download complete: {installer_path}")
                        show_completion_dialog(installer_path, latest_ver, parent=root)
                    else:
                        release_update_lock()
                        messagebox.showerror(
                            _updater_t("update_title"),
                            _updater_t("update_download_fail"),
                        )

                gui_safe(_on_download_done)
            except Exception as exc:
                log(f"[UPDATER] Download error: {exc}")
                release_update_lock()
                gui_safe(lambda: (
                    _close_progress(),
                    messagebox.showerror(_updater_t("update_title"), str(exc)),
                ))

        threading.Thread(target=_download_worker, daemon=True, name="UpdateDownload").start()

    def _check_worker():
        try:
            from client_security_utils import ensure_ca_bundle
            try:
                ensure_ca_bundle()
            except Exception:
                pass
            update_info = update_mgr.check_for_updates()
            # One retry after CA bootstrap (stale _MEI path)
            err0 = str(update_info.get("error") or "")
            if err0 and ("cacert" in err0.lower() or "tls" in err0.lower() or "sertifika" in err0.lower()):
                try:
                    ensure_ca_bundle()
                except Exception:
                    pass
                update_info = update_mgr.check_for_updates()

            def _on_check_done():
                if update_info.get("error"):
                    _close_progress()
                    messagebox.showerror(
                        _updater_t("update_title"),
                        _updater_t("update_error_fmt", err=update_info["error"]),
                    )
                    return

                if not update_info.get("has_update"):
                    _close_progress()
                    messagebox.showinfo(
                        _updater_t("update_title"),
                        _updater_t("update_uptodate"),
                    )
                    return

                latest_ver = update_info["latest_version"]
                _close_progress()
                if messagebox.askyesno(
                    _updater_t("update_title"),
                    _updater_t("update_found_ask", version=latest_ver),
                ):
                    if not progress_dialog.create_dialog():
                        messagebox.showerror(
                            _updater_t("update_title"),
                            _updater_t("update_progress_fail"),
                        )
                        return
                    _start_download(latest_ver, update_info)

            gui_safe(_on_check_done)
        except Exception as exc:
            log(f"update prompt error: {exc}")
            gui_safe(lambda: (
                _close_progress(),
                messagebox.showerror(_updater_t("update_title"), str(exc)),
            ))

    threading.Thread(target=_check_worker, daemon=True, name="UpdateCheck").start()
    return True

def check_updates_and_apply_silent() -> bool:
    """Silent update with installer-based system - SERVER SAFE VERSION"""
    try:
        from client_utils import (
            create_update_manager,
            is_update_in_progress,
            acquire_update_lock,
            release_update_lock,
            touch_update_lock,
            pause_competing_updaters,
            heal_update_machinery,
            stage_installer_for_update,
        )
        import tempfile
        import subprocess
        import shutil
        import time
        
        log("[SILENT UPDATE] Starting server-safe silent update process...")
        try:
            heal_update_machinery(log_func=log)
        except Exception:
            pass

        if is_update_in_progress():
            log("[SILENT UPDATE] Skipped — another update download/install in progress")
            return False
        
        # Update manager oluştur
        update_mgr = create_update_manager(GITHUB_OWNER, GITHUB_REPO, log)
        
        # Güncelleme kontrolü
        update_info = update_mgr.check_for_updates()
        
        if update_info.get("error") or not update_info.get("has_update"):
            if update_info.get("error"):
                log(f"[SILENT UPDATE] Check error: {update_info.get('error')}")
            else:
                log("[SILENT UPDATE] No updates available")
            return False
            
        log(f"[SILENT UPDATE] New version found: {update_info['latest_version']}")

        # Claim machine-wide lock BEFORE download so GUI download cannot be killed
        acquire_update_lock("silent-download")
        pause_competing_updaters()
        
        # Create temp directory for update files
        temp_dir = tempfile.mkdtemp(prefix="honeypot_update_")
        log(f"[SILENT UPDATE] Using temp directory: {temp_dir}")
        staged_installer = None
        
        try:
            # Download installer to temp directory
            installer_path = os.path.join(temp_dir, "honeypot-installer.exe")
            
            # Get download URL
            download_url = update_info.get('installer_url') or update_info.get('download_url')
            if not download_url:
                log("[SILENT UPDATE] No download URL found in update info")
                return False
            
            # Download the installer (heartbeat via touch inside loop)
            def _silent_progress(pct):
                if pct % 10 == 0:
                    touch_update_lock()
                    log(f"[SILENT UPDATE] Download {pct}%")

            # Prefer UpdateManager download with progress when possible
            downloaded_path = update_mgr.download_installer(download_url, _silent_progress)
            if downloaded_path and os.path.isfile(downloaded_path):
                try:
                    shutil.copy2(downloaded_path, installer_path)
                except Exception:
                    installer_path = downloaded_path
            else:
                download_success = download_installer_file(download_url, installer_path)
                if not download_success:
                    log("[SILENT UPDATE] Installer download failed")
                    return False
                
            log(f"[SILENT UPDATE] Installer downloaded to: {installer_path}")
            touch_update_lock()

            # ALWAYS stage under ProgramData — TEMP vanishes when this process dies
            staged_installer = stage_installer_for_update(
                installer_path, version=str(update_info.get("latest_version") or "latest")
            )
            if not staged_installer or not os.path.isfile(staged_installer):
                log("[SILENT UPDATE] Failed to stage installer under ProgramData")
                return False
            log(f"[SILENT UPDATE] Staged installer: {staged_installer}")

            # Drop TEMP scratch now — helper uses ProgramData copy; os._exit skips finally.
            try:
                if temp_dir and os.path.isdir(temp_dir):
                    shutil.rmtree(temp_dir, ignore_errors=True)
            except Exception:
                pass
            try:
                if (
                    downloaded_path
                    and os.path.isfile(downloaded_path)
                    and os.path.abspath(downloaded_path)
                    != os.path.abspath(staged_installer)
                ):
                    from client_utils import _is_our_installer_filename
                    if _is_our_installer_filename(os.path.basename(downloaded_path)):
                        os.remove(downloaded_path)
            except Exception:
                pass

            # Detached elevated helper waits for THIS process to exit, then kills leftovers,
            # runs installer, recreates tasks. Never overwrite a live onefile EXE.
            from client_utils import launch_safe_update_install, release_update_lock

            # Detect interactive desktop → show GUI after; else daemon
            show_gui = False
            try:
                import ctypes
                show_gui = bool(ctypes.windll.user32.GetForegroundWindow())
            except Exception:
                show_gui = False

            ok = launch_safe_update_install(
                staged_installer,
                silent=True,
                show_gui_after=show_gui,
                expect_exit_pid=os.getpid(),
                # SYSTEM daemon is already elevated; force admin path (breakaway
                # Popen / UpdateOnce). elevate=True + Session-0 ShellExecute runas
                # is a no-op when IsUserAnAdmin, but keep explicit False for clarity.
                elevate=False,
            )
            if not ok:
                log("[SILENT UPDATE] Failed to launch update helper — falling back to inline install")
                from client_utils import prepare_client_for_installer
                prepare_client_for_installer(kill_processes=True)
                time.sleep(3)
                cmd = [staged_installer, "/S", "/NCRC"]
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=300,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                )
                if result.returncode == 0:
                    release_update_lock(resume_updaters=False)
                    return True
                log(f"[SILENT UPDATE] Fallback installer failed: {result.returncode}")
                return False

            # Wait for helper to open update-install.log before we exit (schtasks can lag)
            log_path = os.path.join(
                os.environ.get("ProgramData", r"C:\ProgramData"),
                "YesNext", "CloudHoneypotClient", "update-install.log",
            )
            helper_alive = False
            for _ in range(40):  # ~12s
                time.sleep(0.3)
                try:
                    if os.path.isfile(log_path):
                        with open(log_path, "r", encoding="utf-8", errors="ignore") as fh:
                            tail = fh.read()[-1200:]
                        if "update-and-install start" in tail:
                            helper_alive = True
                            break
                except Exception:
                    pass
            if not helper_alive:
                log("[SILENT UPDATE] WARNING: helper log not seen — retrying breakaway launch")
                ok2 = launch_safe_update_install(
                    staged_installer,
                    silent=True,
                    show_gui_after=show_gui,
                    expect_exit_pid=os.getpid(),
                    elevate=False,
                    grace_wait_sec=25,
                )
                if ok2:
                    for _ in range(30):
                        time.sleep(0.3)
                        try:
                            if os.path.isfile(log_path):
                                with open(log_path, "r", encoding="utf-8", errors="ignore") as fh:
                                    if "update-and-install start" in fh.read()[-1200:]:
                                        helper_alive = True
                                        break
                        except Exception:
                            pass
            if not helper_alive:
                log("[SILENT UPDATE] helper log missing after retries — aborting (will not exit into fake install)")
                try:
                    release_update_lock(resume_updaters=True)
                except Exception:
                    pass
                try:
                    from client_update_ui import set_update_ui_status
                    set_update_ui_status(
                        "failed",
                        detail="helper_log_missing",
                        error="helper_log_missing",
                    )
                except Exception:
                    pass
                return False

            log("[SILENT UPDATE] Helper launched — exiting so install can overwrite EXE safely")
            # Keep update lock; helper clears it after install. Do NOT resume tasks yet.
            try:
                from client_self_protection import disarm_for_update
                disarm_for_update(reason="silent_update_exit")
            except Exception:
                pass
            try:
                from client_presence import signal_goodbye
                signal_goodbye("update", http_fallback=True, close_after=False)
            except Exception:
                pass
            # Ask any sibling GUI/daemon to exit cleanly (this process may be updater-only)
            try:
                import socket as _sock
                with _sock.create_connection(("127.0.0.1", 58632), timeout=0.6) as s:
                    s.sendall(b"QUIT\n")
            except Exception:
                pass
            time.sleep(1.5)
            os._exit(0)
                
        except Exception as e:
            log(f"[SILENT UPDATE] Update process error: {e}")
            return False
            
        finally:
            try:
                # Success path uses os._exit (skips finally). Failure → unlock + resume.
                if is_update_in_progress():
                    release_update_lock(resume_updaters=True)
            except Exception:
                pass
            try:
                # Safe to remove TEMP copy; ProgramData staged installer is what helper uses
                if os.path.exists(temp_dir):
                    shutil.rmtree(temp_dir, ignore_errors=True)
            except Exception:
                pass
            
    except Exception as e:
        log(f"[SILENT UPDATE] Silent update error: {e}")
        return False
    
    return True

# Download completion is size/stream based — never "timeout expired ⇒ done".
# connect timeout: TCP/TLS only. stall timeout: max idle between chunks.
_DOWNLOAD_CONNECT_TIMEOUT_SEC = 30
_DOWNLOAD_STALL_TIMEOUT_SEC = 90
_DOWNLOAD_MAX_ATTEMPTS = 5
_DOWNLOAD_MIN_BYTES = 1_000_000  # reject HTML/error pages posing as installers
_DOWNLOAD_RETRY_BACKOFF_SEC = (2, 4, 8, 16, 32)


def _unlink_quiet(path: str) -> None:
    try:
        if path and os.path.isfile(path):
            os.remove(path)
    except OSError:
        pass


def _installer_looks_complete(
    path: str,
    *,
    bytes_written: int,
    content_length: Optional[int],
    expected_size: Optional[int] = None,
) -> Tuple[bool, str]:
    """Return (ok, detail). Completion ≠ wall-clock timeout."""
    if bytes_written <= 0 or not path or not os.path.isfile(path):
        return False, "empty_download"
    try:
        on_disk = os.path.getsize(path)
    except OSError:
        return False, "stat_failed"
    if on_disk != bytes_written:
        return False, f"size_mismatch_disk={on_disk}_written={bytes_written}"
    # Authoritative completeness: Content-Length when the server sends it.
    if content_length is not None and content_length > 0:
        if bytes_written != int(content_length):
            return False, (
                f"incomplete_content_length got={bytes_written} "
                f"expected={content_length}"
            )
    # expected_size is only a cloud hint — never treat timeout/hint as success;
    # do not reject a CL-verified PE solely because the dashboard size is stale.
    if bytes_written < _DOWNLOAD_MIN_BYTES:
        return False, f"too_small={bytes_written}"
    try:
        with open(path, "rb") as fh:
            magic = fh.read(2)
        if magic != b"MZ":
            return False, "not_pe_mz"
    except OSError as exc:
        return False, f"magic_read:{exc}"
    if (
        expected_size is not None
        and int(expected_size) > 0
        and (content_length is None or content_length <= 0)
    ):
        exp = int(expected_size)
        if abs(bytes_written - exp) > max(1024 * 64, int(exp * 0.02)):
            return False, f"size_hint_mismatch got={bytes_written} hint={exp}"
    return True, "complete"


def download_installer_complete(
    url: str,
    local_path: str,
    *,
    expected_size: Optional[int] = None,
    expected_sha256: str = "",
    progress_callback: Optional[Callable[[int], None]] = None,
    max_attempts: int = _DOWNLOAD_MAX_ATTEMPTS,
    log_func=None,
) -> Tuple[bool, str]:
    """Download installer until the transfer is complete, then verify.

    Success criteria (all must hold):
      - HTTP 2xx
      - response body fully consumed (stream ended)
      - bytes written == Content-Length (when header present)
      - PE MZ header + minimum size
      - optional SHA-256 when configured

    ``timeout`` is only connect + per-chunk stall detection — never a total
    download deadline. Incomplete / stalled attempts are deleted and retried
    up to ``max_attempts`` (default 5).
    """
    import hashlib
    import requests
    from client_security_utils import resolve_tls_verify, ensure_ca_bundle
    from client_utils import get_from_config

    _log = log_func or log
    verify_checksum = bool(get_from_config("updates.verify_checksum", True))
    attempts = max(1, min(int(max_attempts or _DOWNLOAD_MAX_ATTEMPTS), 8))
    last_detail = "download_not_started"
    timeout = (_DOWNLOAD_CONNECT_TIMEOUT_SEC, _DOWNLOAD_STALL_TIMEOUT_SEC)

    parent = os.path.dirname(local_path) or "."
    try:
        os.makedirs(parent, exist_ok=True)
    except OSError:
        pass

    for attempt in range(1, attempts + 1):
        _unlink_quiet(local_path)
        partial = local_path + ".partial"
        _unlink_quiet(partial)
        try:
            try:
                ensure_ca_bundle()
            except Exception:
                pass
            _log(
                f"[UPDATE-DL] attempt {attempt}/{attempts} url={url[:120]} "
                f"stall_timeout={_DOWNLOAD_STALL_TIMEOUT_SEC}s"
            )
            try:
                response = requests.get(
                    url, stream=True, timeout=timeout, verify=resolve_tls_verify()
                )
                response.raise_for_status()
            except Exception as first_err:
                err_l = str(first_err).lower()
                if any(x in err_l for x in ("cacert", "ssl", "tls", "certificate", "cert")):
                    try:
                        ensure_ca_bundle()
                    except Exception:
                        pass
                    response = requests.get(
                        url, stream=True, timeout=timeout, verify=resolve_tls_verify()
                    )
                    response.raise_for_status()
                else:
                    raise

            cl_raw = response.headers.get("Content-Length") or response.headers.get(
                "content-length"
            )
            content_length: Optional[int] = None
            try:
                if cl_raw is not None and str(cl_raw).strip():
                    content_length = int(cl_raw)
            except (TypeError, ValueError):
                content_length = None

            sha = hashlib.sha256()
            written = 0
            last_touch = time.time()
            with open(partial, "wb") as fh:
                for chunk in response.iter_content(chunk_size=256 * 1024):
                    if not chunk:
                        continue
                    fh.write(chunk)
                    sha.update(chunk)
                    written += len(chunk)
                    now = time.time()
                    if now - last_touch >= 15:
                        last_touch = now
                        try:
                            from client_utils import touch_update_lock
                            touch_update_lock()
                        except Exception:
                            pass
                    if progress_callback and content_length and content_length > 0:
                        pct = int(min(99, (written / float(content_length)) * 100))
                        try:
                            progress_callback(pct)
                        except Exception:
                            pass

            ok_complete, detail = _installer_looks_complete(
                partial,
                bytes_written=written,
                content_length=content_length,
                expected_size=expected_size,
            )
            if not ok_complete:
                last_detail = detail
                _log(f"[UPDATE-DL] incomplete attempt={attempt}: {detail}")
                _unlink_quiet(partial)
                raise RuntimeError(detail)

            digest = sha.hexdigest()
            if verify_checksum and expected_sha256:
                if digest.lower() != str(expected_sha256).lower():
                    last_detail = "checksum_mismatch"
                    _unlink_quiet(partial)
                    raise RuntimeError(last_detail)

            # Promote partial → final only after completion checks pass
            _unlink_quiet(local_path)
            os.replace(partial, local_path)

            try:
                from client_authenticode import (
                    AuthenticodeError,
                    assert_update_authenticode,
                )
                auth = assert_update_authenticode(local_path)
                if auth.get("trusted"):
                    _log(
                        "[UPDATE-DL] Authenticode OK "
                        f"publisher={(auth.get('publisher') or '')[:80]}"
                    )
                elif auth.get("skipped"):
                    _log("[UPDATE-DL] Authenticode soft-skip (not required)")
            except AuthenticodeError as exc:
                last_detail = f"authenticode:{exc}"
                _unlink_quiet(local_path)
                raise RuntimeError(last_detail)
            except Exception as exc:
                _log(f"[UPDATE-DL] Authenticode check error: {exc}")

            if progress_callback:
                try:
                    progress_callback(100)
                except Exception:
                    pass
            _log(
                f"[UPDATE-DL] complete bytes={written} "
                f"sha256={digest[:16]}… attempts={attempt}"
            )
            return True, "complete"

        except Exception as exc:
            last_detail = str(exc)[:180] or "download_error"
            _log(f"[UPDATE-DL] attempt {attempt}/{attempts} failed: {last_detail}")
            _unlink_quiet(partial)
            _unlink_quiet(local_path)
            if attempt >= attempts:
                break
            delay = _DOWNLOAD_RETRY_BACKOFF_SEC[
                min(attempt - 1, len(_DOWNLOAD_RETRY_BACKOFF_SEC) - 1)
            ]
            time.sleep(delay)

    return False, last_detail or "download_failed"


def download_installer_file(url: str, local_path: str, expected_sha256: str = "") -> bool:
    """Download installer file from URL with optional SHA-256 verification."""
    ok, detail = download_installer_complete(
        url,
        local_path,
        expected_sha256=expected_sha256 or "",
        max_attempts=_DOWNLOAD_MAX_ATTEMPTS,
    )
    if not ok:
        log(f"[SILENT UPDATE] Download failed: {detail}")
    return bool(ok)



def update_watchdog_loop():
    """Periodic silent update checker.

    First check after a short startup delay, then every N minutes (config).
    A "no update" poll is only a small GitHub API GET — safe at 5–15 min.
    """
    from client_utils import get_from_config

    # Quick first check so a just-released version is picked up soon after launch
    try:
        startup_delay = max(30, int(get_from_config("updates.startup_check_delay_seconds", 90) or 90))
    except Exception:
        startup_delay = 90
    for _ in range(max(1, startup_delay // 10)):
        time.sleep(10)

    while True:
        try:
            if not bool(get_from_config("updates.auto_check", True)):
                time.sleep(60)
                continue
            try:
                from client_utils import is_update_in_progress
                if is_update_in_progress():
                    log("[UPDATE WATCHDOG] Skipped — update already in progress")
                else:
                    check_updates_and_apply_silent()
            except Exception:
                check_updates_and_apply_silent()

            # Prefer minutes; fall back to hours (legacy config). Floor 5 min.
            minutes = get_from_config("updates.check_interval_minutes", None)
            if minutes is None:
                hours = float(get_from_config("updates.check_interval_hours", 0.25) or 0.25)
                minutes = max(5, int(hours * 60))
            else:
                minutes = max(5, int(minutes))
            # Sleep in 10s slices so lock / shutdown stay responsive
            for _ in range(max(1, minutes * 6)):
                time.sleep(10)
        except Exception as e:
            log(f"update_watchdog_loop error: {e}")
            time.sleep(60)

class UpdateManager:
    """Central update management"""
    
    def __init__(self):
        self.update_thread = None
        self.auto_update_enabled = False
        
    def start_update_watchdog(self, auto_update: bool = False):
        """Start background update monitoring"""
        try:
            self.auto_update_enabled = auto_update
            
            if not self.update_thread or not self.update_thread.is_alive():
                self.update_thread = threading.Thread(
                    target=update_watchdog_loop,
                    daemon=True,
                    name="UpdateWatchdog"
                )
                self.update_thread.start()
                log("Update watchdog started")
                return True
        except Exception as e:
            log(f"Update watchdog start error: {e}")
        return False
    
    def check_for_updates_interactive(self, app_instance) -> bool:
        """Check for updates with user interaction"""
        return check_updates_and_prompt(app_instance)
    
    def check_for_updates_silent(self) -> bool:
        """Check for updates silently"""
        return check_updates_and_apply_silent()
    
    def stop_update_watchdog(self):
        """Stop update monitoring"""
        try:
            if self.update_thread and self.update_thread.is_alive():
                # Since it's a daemon thread, it will stop when main process exits
                log("Update watchdog will stop with main process")
        except Exception as e:
            log(f"Update watchdog stop error: {e}")


# ── Dashboard remote command: self_update / check_update ───────────

_ALLOWED_UPDATE_HOST_SUFFIXES = (
    "github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
)


def _normalize_version_tag(tag: str) -> str:
    return str(tag or "").strip().lstrip("vV").strip()


def _is_allowed_update_url(url: str) -> bool:
    """Only official GitHub release hosts for this repo."""
    try:
        from urllib.parse import urlparse
        from client_constants import GITHUB_OWNER, GITHUB_REPO
        p = urlparse(str(url or "").strip())
        if p.scheme not in ("https",):
            return False
        host = (p.hostname or "").lower()
        if not any(host == s or host.endswith("." + s) for s in _ALLOWED_UPDATE_HOST_SUFFIXES):
            return False
        path = (p.path or "").lower()
        # github.com/.../releases/download/... or CDN object URLs
        if "github.com" in host:
            needle = f"/{GITHUB_OWNER.lower()}/{GITHUB_REPO.lower()}/"
            if needle not in path:
                return False
        return True
    except Exception:
        return False


def _current_installed_version() -> str:
    try:
        from client_constants import VERSION
        return _normalize_version_tag(VERSION)
    except Exception:
        return ""


def check_update_availability(params: Optional[dict] = None, api_client=None) -> dict:
    """Compare installed vs latest (no install). For remote `check_update`."""
    params = params or {}
    installed = _current_installed_version()
    latest = _normalize_version_tag(params.get("tag") or "")
    download_url = (params.get("download_url") or "").strip()

    try:
        from client_utils import create_update_manager
        mgr = create_update_manager(GITHUB_OWNER, GITHUB_REPO, log)
        info = mgr.check_for_updates()
        if not latest:
            latest = _normalize_version_tag(info.get("latest_version") or "")
        if not download_url:
            download_url = (info.get("installer_url") or info.get("download_url") or "").strip()
        if info.get("error") and not latest:
            return {
                "success": False,
                "ok": False,
                "error": "check_failed",
                "detail": str(info.get("error")),
                "update_available": False,
                "installed": installed,
                "latest": latest or "",
            }
    except Exception as e:
        if not latest:
            return {
                "success": False,
                "ok": False,
                "error": "check_failed",
                "detail": str(e),
                "update_available": False,
                "installed": installed,
                "latest": "",
            }

    # Optional cloud public endpoint fallback
    if not latest or not download_url:
        try:
            cloud = _resolve_latest_from_cloud(api_client)
            if cloud:
                latest = latest or _normalize_version_tag(cloud.get("tag") or cloud.get("version"))
                download_url = download_url or (cloud.get("download_url") or "").strip()
        except Exception:
            pass

    available = False
    if latest and installed:
        try:
            from client_utils import create_update_manager
            mgr = create_update_manager(GITHUB_OWNER, GITHUB_REPO, log)
            available = mgr._compare_versions(latest, installed) > 0
        except Exception:
            available = latest != installed
    elif latest and not installed:
        available = True

    return {
        "success": True,
        "ok": True,
        "update_available": bool(available),
        "installed": installed,
        "latest": latest,
        "tag": f"v{latest}" if latest else "",
        "download_url": download_url if available else "",
        "message": "update_available" if available else "already_current",
    }


def _resolve_latest_from_cloud(api_client=None) -> Optional[dict]:
    """Best-effort GET /api/public/latest-release."""
    try:
        import requests
        from client_constants import API_URL
        from client_security_utils import resolve_tls_verify
        base = str(API_URL).rstrip("/")
        url = f"{base}/public/latest-release"
        if api_client and hasattr(api_client, "api_request"):
            resp = api_client.api_request("GET", "public/latest-release", timeout=8)
            if isinstance(resp, dict) and (resp.get("download_url") or resp.get("tag")):
                return resp
        r = requests.get(url, timeout=8, verify=resolve_tls_verify())
        if r.status_code == 200:
            data = r.json()
            if isinstance(data, dict):
                return data
    except Exception as e:
        log(f"[SELF-UPDATE] cloud latest-release: {e}")
    return None


def _default_installer_url(tag: str) -> str:
    """Build official GitHub release asset URL when API/cloud omit download_url."""
    t = _normalize_version_tag(tag)
    if not t:
        return ""
    try:
        from client_constants import GITHUB_OWNER, GITHUB_REPO
        return (
            f"https://github.com/{GITHUB_OWNER}/{GITHUB_REPO}"
            f"/releases/download/v{t}/cloud-client-installer.exe"
        )
    except Exception:
        return ""


def run_self_update_command(params: Optional[dict] = None, api_client=None) -> dict:
    """
    Dashboard `self_update` — immediate silent install (independent of schedule).

    Returns result dict for POST /api/commands/result.
    May set restart_required=True after helper is launched (caller should exit).
    """
    params = dict(params or {})
    force = bool(params.get("force", False))
    tag = _normalize_version_tag(params.get("tag") or "")
    download_url = (params.get("download_url") or "").strip()
    expected_size = params.get("size")
    try:
        expected_size = int(expected_size) if expected_size is not None else None
    except (TypeError, ValueError):
        expected_size = None
    installer_name = (params.get("installer_name") or "cloud-client-installer.exe").strip()
    from_version = _current_installed_version()

    log(
        f"[SELF-UPDATE] begin force={force} tag={tag or '?'} "
        f"from={from_version} triggered_by={params.get('triggered_by', '')}"
    )

    try:
        from client_update_ui import set_update_ui_status
        set_update_ui_status(
            "accepted",
            from_version=from_version,
            to_version=tag,
            detail="self_update_begin",
        )
    except Exception:
        pass

    try:
        from client_lifecycle import report_now
        report_now(
            "self_update_begin",
            "dashboard_self_update",
            {"from_version": from_version, "tag": tag, "force": force},
            severity="info",
            api_client=api_client,
            token=None,
            log_func=log,
        )
    except Exception:
        pass

    # Resolve URL/tag if cloud omitted them
    if not download_url or not tag:
        try:
            from client_utils import create_update_manager
            mgr = create_update_manager(GITHUB_OWNER, GITHUB_REPO, log)
            info = mgr.check_for_updates()
            if not tag:
                tag = _normalize_version_tag(info.get("latest_version") or "")
            if not download_url:
                download_url = (info.get("installer_url") or info.get("download_url") or "").strip()
            if expected_size is None:
                try:
                    expected_size = int(info.get("installer_size") or 0) or None
                except Exception:
                    pass
        except Exception as e:
            log(f"[SELF-UPDATE] GitHub resolve failed: {e}")

    if not download_url or not tag:
        cloud = _resolve_latest_from_cloud(api_client)
        if cloud:
            tag = tag or _normalize_version_tag(cloud.get("tag") or cloud.get("version"))
            download_url = download_url or (cloud.get("download_url") or "").strip()
            if expected_size is None:
                try:
                    expected_size = int(cloud.get("size") or 0) or None
                except Exception:
                    pass

    # Last resort: known tag → canonical release asset (no GitHub API needed)
    if tag and not download_url:
        download_url = _default_installer_url(tag)
        if download_url:
            log(f"[SELF-UPDATE] using constructed release URL for v{tag}")

    if not tag and download_url:
        # Try parse .../download/vX.Y.Z/... from URL
        try:
            import re
            m = re.search(r"/download/v?(\d+\.\d+\.\d+)/", download_url, re.I)
            if m:
                tag = m.group(1)
        except Exception:
            pass

    if not download_url:
        try:
            from client_update_ui import set_update_ui_status
            set_update_ui_status(
                "failed", from_version=from_version, to_version=tag,
                detail="download_url_missing", error="download_url_missing",
            )
        except Exception:
            pass
        _lifecycle_fail(api_client, "download_url_missing", from_version, tag)
        return {
            "success": False,
            "ok": False,
            "error": "download_failed",
            "detail": "download_url_missing",
            "from_version": from_version,
            "to_version": tag,
            "tag": f"v{tag}" if tag else "",
        }

    if not _is_allowed_update_url(download_url):
        try:
            from client_update_ui import set_update_ui_status
            set_update_ui_status(
                "failed", from_version=from_version, to_version=tag,
                detail="url_not_allowed", error="url_not_allowed",
            )
        except Exception:
            pass
        _lifecycle_fail(api_client, "url_not_allowed", from_version, tag)
        return {
            "success": False,
            "ok": False,
            "error": "download_failed",
            "detail": "url_not_allowed",
            "from_version": from_version,
            "to_version": tag,
            "tag": f"v{tag}" if tag else "",
        }

    # Skip if already on target (unless force)
    if tag and from_version and tag == from_version and not force:
        log(f"[SELF-UPDATE] already_current {from_version}")
        try:
            from client_update_ui import clear_update_ui_status
            clear_update_ui_status()
        except Exception:
            pass
        return {
            "success": True,
            "ok": True,
            "message": "already_current",
            "from_version": from_version,
            "to_version": from_version,
            "tag": f"v{from_version}",
        }

    from client_utils import (
        is_update_in_progress,
        acquire_update_lock,
        release_update_lock,
        touch_update_lock,
        pause_competing_updaters,
        heal_update_machinery,
        stage_installer_for_update,
        launch_safe_update_install,
    )
    import tempfile
    import shutil

    try:
        heal_update_machinery(log_func=log)
    except Exception:
        pass

    if is_update_in_progress():
        if force:
            log("[SELF-UPDATE] force=1 — clearing stale update lock")
            try:
                release_update_lock(resume_updaters=False)
            except Exception:
                pass
        else:
            try:
                from client_update_ui import set_update_ui_status
                set_update_ui_status(
                    "failed", from_version=from_version, to_version=tag,
                    detail="another_update_in_progress", error="busy",
                )
            except Exception:
                pass
            _lifecycle_fail(api_client, "busy", from_version, tag)
            return {
                "success": False,
                "ok": False,
                "error": "busy",
                "detail": "another_update_in_progress",
                "from_version": from_version,
                "to_version": tag,
                "tag": f"v{tag}" if tag else "",
            }

    acquire_update_lock("dashboard-self-update")
    pause_competing_updaters()

    try:
        from client_update_ui import set_update_ui_status
        set_update_ui_status(
            "downloading",
            from_version=from_version,
            to_version=tag,
            detail="download_starting",
            progress=0,
        )
    except Exception:
        pass

    temp_dir = None
    try:
        from client_utils import _update_helper_staging_dir
        staging_root = _update_helper_staging_dir()
        installer_path = os.path.join(
            staging_root,
            f"cloud-client-installer-v{tag or 'pending'}.exe",
        )
    except Exception:
        temp_dir = tempfile.mkdtemp(prefix="honeypot_self_update_")
        installer_path = os.path.join(temp_dir, installer_name or "cloud-client-installer.exe")
    staged = None

    try:
        urls_to_try = []
        for u in (download_url, _default_installer_url(tag) if tag else ""):
            u = (u or "").strip()
            if not u or not _is_allowed_update_url(u):
                continue
            if u not in urls_to_try:
                urls_to_try.append(u)
        if not urls_to_try:
            release_update_lock(resume_updaters=True)
            _lifecycle_fail(api_client, "url_not_allowed", from_version, tag)
            return {
                "success": False,
                "ok": False,
                "error": "download_failed",
                "detail": "url_not_allowed",
                "from_version": from_version,
                "to_version": tag,
                "tag": f"v{tag}" if tag else "",
            }

        downloaded = None
        last_dl_err = ""
        # Up to 5 completion-verified attempts; rotate URLs between tries.
        for attempt in range(1, _DOWNLOAD_MAX_ATTEMPTS + 1):
            attempt_url = urls_to_try[(attempt - 1) % len(urls_to_try)]
            log(
                f"[SELF-UPDATE] download attempt {attempt}/{_DOWNLOAD_MAX_ATTEMPTS} "
                f"→ {attempt_url[:100]}"
            )
            try:
                from client_update_ui import set_update_ui_status as _set_ui
            except Exception:
                _set_ui = None

            def _prog(pct, _attempt=attempt):
                if pct % 10 == 0:
                    touch_update_lock()
                    log(f"[SELF-UPDATE] download {_attempt} {pct}%")
                if _set_ui and (pct % 5 == 0 or pct >= 99):
                    try:
                        _set_ui(
                            "downloading",
                            from_version=from_version,
                            to_version=tag,
                            detail=f"download_{pct}",
                            progress=pct,
                        )
                    except Exception:
                        pass

            ok, detail = download_installer_complete(
                attempt_url,
                installer_path,
                expected_size=expected_size,
                progress_callback=_prog,
                max_attempts=1,  # outer loop owns retries
                log_func=log,
            )
            if ok and os.path.isfile(installer_path):
                downloaded = installer_path
                download_url = attempt_url
                break
            last_dl_err = detail or "installer_download_failed"
            log(f"[SELF-UPDATE] attempt {attempt} incomplete: {last_dl_err}")
            if attempt < _DOWNLOAD_MAX_ATTEMPTS:
                delay = _DOWNLOAD_RETRY_BACKOFF_SEC[
                    min(attempt - 1, len(_DOWNLOAD_RETRY_BACKOFF_SEC) - 1)
                ]
                time.sleep(delay)

        if not (downloaded and os.path.isfile(downloaded)):
            release_update_lock(resume_updaters=True)
            detail = (last_dl_err or "installer_download_failed")[:180]
            try:
                from client_update_ui import set_update_ui_status
                set_update_ui_status(
                    "failed", from_version=from_version, to_version=tag,
                    detail=detail, error="download_failed",
                )
            except Exception:
                pass
            _lifecycle_fail(api_client, "download_failed", from_version, tag)
            return {
                "success": False,
                "ok": False,
                "error": "download_failed",
                "detail": detail,
                "from_version": from_version,
                "to_version": tag,
                "tag": f"v{tag}" if tag else "",
                "download_url": download_url,
            }
        installer_path = downloaded
        touch_update_lock()
        actual_size = os.path.getsize(installer_path) if os.path.isfile(installer_path) else 0
        if expected_size and expected_size > 0 and actual_size > 0:
            # Soft check — wrong dashboard size must not block fleet updates
            if abs(actual_size - expected_size) > max(1024 * 64, int(expected_size * 0.02)):
                log(
                    f"[SELF-UPDATE] size warn expected={expected_size} got={actual_size} — continuing"
                )

        try:
            from client_update_ui import set_update_ui_status
            set_update_ui_status(
                "staging",
                from_version=from_version,
                to_version=tag,
                detail="staging_installer",
                progress=100,
            )
        except Exception:
            pass

        staged = stage_installer_for_update(installer_path, version=tag or "latest")
        if not staged or not os.path.isfile(staged):
            release_update_lock(resume_updaters=True)
            try:
                from client_update_ui import set_update_ui_status
                set_update_ui_status(
                    "failed", from_version=from_version, to_version=tag,
                    detail="stage_failed", error="stage_failed",
                )
            except Exception:
                pass
            _lifecycle_fail(api_client, "stage_failed", from_version, tag)
            return {
                "success": False,
                "ok": False,
                "error": "install_failed",
                "detail": "stage_failed",
                "from_version": from_version,
                "to_version": tag,
                "tag": f"v{tag}" if tag else "",
            }

        # Helper uses ProgramData copy — drop TEMP scratch immediately.
        try:
            if temp_dir and os.path.isdir(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)
                temp_dir = ""
        except Exception:
            pass

        # Soft GUI: if interactive session, show after; else daemon-only
        show_gui = False
        try:
            from client_helpers import has_interactive_user_session
            show_gui = bool(has_interactive_user_session())
        except Exception:
            show_gui = False

        ok = launch_safe_update_install(
            staged,
            silent=True,
            show_gui_after=show_gui,
            expect_exit_pid=os.getpid(),
            # True → auto-clears when IsUserAnAdmin (SYSTEM daemon). Keeps UAC for rare non-admin callers.
            elevate=True,
        )
        if not ok:
            release_update_lock(resume_updaters=True)
            try:
                from client_update_ui import set_update_ui_status
                set_update_ui_status(
                    "failed", from_version=from_version, to_version=tag,
                    detail="launch_helper_failed", error="launch_helper_failed",
                )
            except Exception:
                pass
            _lifecycle_fail(api_client, "launch_helper_failed", from_version, tag)
            log("[SELF-UPDATE] helper did NOT start (no update-install.log) — aborting exit")
            return {
                "success": False,
                "ok": False,
                "error": "install_failed",
                "detail": "launch_helper_failed",
                "from_version": from_version,
                "to_version": tag,
                "tag": f"v{tag}" if tag else "",
            }

        # Double-check log — never claim success / exit without a live helper
        try:
            log_path = os.path.join(
                os.environ.get("ProgramData", r"C:\ProgramData"),
                "YesNext", "CloudHoneypotClient", "update-install.log",
            )
            helper_ok = False
            if os.path.isfile(log_path):
                with open(log_path, "r", encoding="utf-8", errors="ignore") as fh:
                    tail = fh.read()[-2400:]
                helper_ok = "update-and-install start" in tail
            if not helper_ok:
                release_update_lock(resume_updaters=True)
                from client_update_ui import set_update_ui_status
                set_update_ui_status(
                    "failed", from_version=from_version, to_version=tag,
                    detail="helper_log_missing", error="helper_log_missing",
                )
                _lifecycle_fail(api_client, "helper_log_missing", from_version, tag)
                log("[SELF-UPDATE] helper_log_missing after launch — aborting")
                return {
                    "success": False,
                    "ok": False,
                    "error": "install_failed",
                    "detail": "helper_log_missing",
                    "from_version": from_version,
                    "to_version": tag,
                    "tag": f"v{tag}" if tag else "",
                }
        except Exception as e:
            log(f"[SELF-UPDATE] helper log verify error: {e}")

        try:
            from client_update_ui import set_update_ui_status
            set_update_ui_status(
                "installing",
                from_version=from_version,
                to_version=tag,
                detail="helper_launched",
            )
        except Exception:
            pass

        try:
            from client_lifecycle import report_now
            report_now(
                "self_update_ok",
                "helper_launched",
                {"from_version": from_version, "to_version": tag, "show_gui": show_gui},
                severity="info",
                api_client=api_client,
                token=None,
                log_func=log,
            )
        except Exception:
            pass

        log(f"[SELF-UPDATE] helper launched → {tag} (restart_required)")
        return {
            "success": True,
            "ok": True,
            "message": "update_started",
            "from_version": from_version,
            "to_version": tag,
            "tag": f"v{tag}" if tag else "",
            "restart_required": True,
            "download_url": download_url,
        }

    except Exception as e:
        try:
            release_update_lock(resume_updaters=True)
        except Exception:
            pass
        try:
            from client_update_ui import set_update_ui_status
            set_update_ui_status(
                "failed", from_version=from_version, to_version=tag,
                detail=str(e), error=str(e),
            )
        except Exception:
            pass
        _lifecycle_fail(api_client, str(e), from_version, tag)
        return {
            "success": False,
            "ok": False,
            "error": "install_failed",
            "detail": str(e),
            "from_version": from_version,
            "to_version": tag,
            "tag": f"v{tag}" if tag else "",
        }
    finally:
        try:
            if temp_dir and os.path.isdir(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)
        except Exception:
            pass


def _lifecycle_fail(api_client, reason: str, from_version: str, tag: str) -> None:
    try:
        from client_lifecycle import report_now
        report_now(
            "self_update_failed",
            reason,
            {"from_version": from_version, "to_version": tag},
            severity="error",
            api_client=api_client,
            token=None,
            log_func=log,
        )
    except Exception:
        pass
