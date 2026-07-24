#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Uninstall PIN gate — block casual Control Panel removal (contract lifecycle).

Exit codes for NSIS / scripts:
  0 — authorized, uninstall may proceed
  1 — aborted (wrong PIN, cancel, silent without PIN when required)
  2 — unexpected error

Lifecycle events (POST /api/alerts/lifecycle, queued+flushed):
  uninstall_requested | uninstall_pin_failed | uninstall_aborted
  uninstall_authorized  (PIN ok / no-PIN confirm — removal about to start)

Never logs the PIN. Windows interactive username is included in details.
"""

from __future__ import annotations

import os
import sys
from typing import Optional, Tuple

from client_helpers import log


def _windows_user() -> str:
    for key in ("USERNAME", "USER", "LOGNAME"):
        val = (os.environ.get(key) or "").strip()
        if val:
            return val
    try:
        import getpass
        return (getpass.getuser() or "").strip()
    except Exception:
        return ""


def _is_silent(argv: Optional[list] = None) -> bool:
    argv = argv if argv is not None else sys.argv[1:]
    if "--silent" in argv or "/S" in argv or "/s" in argv:
        return True
    # NSIS quiet often leaves no console interaction
    if os.environ.get("HONEYPOT_UNINSTALL_SILENT", "").strip() in ("1", "true", "yes"):
        return True
    return False


def _pin_from_argv_or_env(argv: Optional[list] = None) -> str:
    argv = list(argv if argv is not None else sys.argv[1:])
    for i, arg in enumerate(argv):
        if arg == "--pin" and i + 1 < len(argv):
            return str(argv[i + 1] or "")
        if arg.startswith("--pin="):
            return arg.split("=", 1)[1]
    return (os.environ.get("HONEYPOT_UNINSTALL_PIN") or "").strip()


def _emit(event_type: str, reason: str, *, severity: str, details: dict) -> None:
    try:
        from client_lifecycle import report_now, flush_queue_to_api
        report_now(
            event_type,
            reason,
            details,
            severity=severity,
            log_func=log,
        )
        # Critical before files disappear — best-effort flush
        flush_queue_to_api(log_func=log)
    except Exception as exc:
        log(f"[UNINSTALL-GATE] lifecycle emit failed: {exc}")


def _arm_uninstall_stand_down() -> None:
    """Stop Guardian/motor respawn while NSIS deletes files."""
    try:
        from client_operator_stop import arm_operator_stop
        arm_operator_stop()
    except Exception as exc:
        log(f"[UNINSTALL-GATE] operator_stop arm: {exc}")
    try:
        from client_resilience import note_stand_down
        note_stand_down("uninstall")
    except Exception:
        pass
    try:
        # Marker for post-mortem / next boot (optional)
        from client_constants import MACHINE_DATA_DIR
        path = os.path.join(MACHINE_DATA_DIR, "uninstall_authorized.flag")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("1\n")
    except Exception:
        pass


def _prompt_pin_interactive() -> Optional[str]:
    """Show PIN dialog (no full GUI app). Returns PIN or None if cancelled."""
    try:
        import tkinter as tk
        from client_gui_lock import prompt_pin_dialog, dashboard_pin_hint
    except Exception as exc:
        log(f"[UNINSTALL-GATE] PIN UI unavailable: {exc}")
        return None

    root = tk.Tk()
    root.withdraw()
    try:
        root.attributes("-topmost", True)
    except Exception:
        pass
    try:
        pin = prompt_pin_dialog(
            root,
            "Asteria — Uninstall",
            "Kaldırmak için PIN girin",
            confirm=False,
            hint=dashboard_pin_hint(None),
        )
        return pin
    finally:
        try:
            root.destroy()
        except Exception:
            pass


def _confirm_no_pin_interactive() -> bool:
    try:
        import tkinter as tk
        from tkinter import messagebox
        root = tk.Tk()
        root.withdraw()
        try:
            root.attributes("-topmost", True)
        except Exception:
            pass
        ok = bool(messagebox.askyesno(
            "Asteria — Uninstall",
            "PIN tanımlı değil.\n\n"
            "Kaldırmaya devam edilsin mi?\n"
            "(Öneri: dashboard veya Ayarlar üzerinden PIN tanımlayın.)",
            parent=root,
        ))
        root.destroy()
        return ok
    except Exception:
        return False


def run_uninstall_gate(argv: Optional[list] = None) -> int:
    """Interactive/silent uninstall authorization. Return process exit code."""
    argv = list(argv if argv is not None else sys.argv[1:])
    silent = _is_silent(argv)
    user = _windows_user()
    base = {
        "windows_user": user,
        "silent": silent,
        "pid": os.getpid(),
    }

    _emit(
        "uninstall_requested",
        "control_panel_or_uninstaller",
        severity="warning",
        details=dict(base),
    )

    try:
        from client_gui_lock import GuiLock
        lock = GuiLock.instance()
        has_pin = bool(lock.has_pin())
    except Exception as exc:
        log(f"[UNINSTALL-GATE] GuiLock error: {exc}")
        _emit(
            "uninstall_aborted",
            "gate_error",
            severity="error",
            details={**base, "error": str(exc)[:200]},
        )
        return 2

    if not has_pin:
        if silent:
            # No PIN — silent uninstall allowed but audited
            _emit(
                "uninstall_authorized",
                "no_pin_silent",
                severity="warning",
                details={**base, "pin_required": False},
            )
            _arm_uninstall_stand_down()
            return 0
        if not _confirm_no_pin_interactive():
            _emit(
                "uninstall_aborted",
                "user_cancelled_no_pin",
                severity="info",
                details={**base, "pin_required": False},
            )
            return 1
        _emit(
            "uninstall_authorized",
            "no_pin_confirmed",
            severity="warning",
            details={**base, "pin_required": False},
        )
        _arm_uninstall_stand_down()
        try:
            from client_presence import signal_goodbye
            signal_goodbye("uninstall", http_fallback=True, close_after=False)
        except Exception:
            pass
        return 0

    # PIN required
    pin = _pin_from_argv_or_env(argv)
    if not pin and not silent:
        pin = _prompt_pin_interactive() or ""
    if not pin:
        _emit(
            "uninstall_aborted",
            "pin_missing" if silent else "user_cancelled",
            severity="warning",
            details={**base, "pin_required": True},
        )
        return 1

    ok, err = lock.verify_pin(pin, unlock_on_success=False)
    # Scrub
    pin = ""
    if not ok:
        _emit(
            "uninstall_pin_failed",
            err or "wrong_pin",
            severity="warning",
            details={**base, "pin_required": True, "fail_reason": err},
        )
        if not silent:
            try:
                import tkinter as tk
                from tkinter import messagebox
                root = tk.Tk()
                root.withdraw()
                messagebox.showerror(
                    "Asteria — Uninstall",
                    "PIN hatalı veya kilitli. Kaldırma iptal edildi.\n"
                    "PIN unuttuysanız dashboard → GUI PIN sıfırlama kullanın.",
                    parent=root,
                )
                root.destroy()
            except Exception:
                pass
        return 1

    _emit(
        "uninstall_authorized",
        "pin_ok",
        severity="warning",
        details={**base, "pin_required": True, "pin_verified": True},
    )
    _arm_uninstall_stand_down()
    try:
        from client_presence import signal_goodbye
        signal_goodbye("uninstall", http_fallback=True, close_after=False)
    except Exception:
        pass
    return 0


def main(argv: Optional[list] = None) -> int:
    try:
        return run_uninstall_gate(argv)
    except Exception as exc:
        log(f"[UNINSTALL-GATE] fatal: {exc}")
        try:
            _emit(
                "uninstall_aborted",
                "gate_exception",
                severity="error",
                details={"error": str(exc)[:200], "windows_user": _windows_user()},
            )
        except Exception:
            pass
        return 2


if __name__ == "__main__":
    sys.exit(main())
