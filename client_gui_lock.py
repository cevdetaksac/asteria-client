#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GUI PIN lock — local anti-tamper for tray/settings (not OS root-proof).

PIN hash stored under ProgramData (survives updates). Session unlock clears
when the window is minimized to tray.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from typing import Optional, Tuple

if os.environ.get("ASTERIA_GUI_HOST") == "1":
    # The WebView host deliberately excludes Tk/client_helpers. Keep PIN
    # verification independent from the legacy GUI dependency graph.
    import logging

    def log(message):
        logging.getLogger("asteria-gui").info("%s", message)
else:
    from client_helpers import log

_PBKDF2_ITERATIONS = 120_000
_SALT_BYTES = 16
_MAX_ATTEMPTS = 5
_LOCKOUT_SECONDS = 60
_MIN_PIN_LEN = 4
_MAX_PIN_LEN = 12


def _programdata_dir() -> str:
    try:
        from client_utils import _programdata_client_dir
        return _programdata_client_dir()
    except Exception:
        base = os.path.join(
            os.environ.get("ProgramData", r"C:\ProgramData"),
            "Asteria",
        )
        os.makedirs(base, exist_ok=True)
        return base


def _lock_path() -> str:
    return os.path.join(_programdata_dir(), "gui_lock.json")


def _hash_pin(pin: str, salt: bytes, iterations: int = _PBKDF2_ITERATIONS) -> str:
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        pin.encode("utf-8"),
        salt,
        iterations,
    )
    return dk.hex()


class GuiLock:
    """Singleton-style PIN store + session unlock state."""

    _instance: Optional["GuiLock"] = None
    _instance_lock = threading.Lock()

    def __init__(self):
        self._lock = threading.RLock()
        self._unlocked = False
        self._fail_count = 0
        self._lockout_until = 0.0
        self._data: dict = {}
        self._mtime = 0.0
        self._prompt_active = False
        self._prompt_window = None
        self.reload()

    @classmethod
    def instance(cls) -> "GuiLock":
        with cls._instance_lock:
            if cls._instance is None:
                cls._instance = GuiLock()
            return cls._instance

    def reload(self) -> None:
        path = _lock_path()
        data = {}
        mtime = 0.0
        try:
            if os.path.isfile(path):
                mtime = os.path.getmtime(path)
                with open(path, "r", encoding="utf-8") as fh:
                    raw = json.load(fh)
                if isinstance(raw, dict):
                    data = raw
        except Exception as e:
            log(f"[GUI-LOCK] load error: {e}")
        with self._lock:
            self._data = data
            self._mtime = mtime

    def _maybe_reload(self) -> None:
        """Pick up out-of-process PIN changes (dashboard set/reset via daemon).

        The SYSTEM daemon writes gui_lock.json when the cloud sends
        set_gui_pin/clear_gui_pin; the GUI process must notice without restart.
        """
        path = _lock_path()
        try:
            mtime = os.path.getmtime(path) if os.path.isfile(path) else 0.0
        except OSError:
            mtime = 0.0
        with self._lock:
            if mtime == self._mtime:
                return
        self.reload()
        with self._lock:
            # PIN changed externally — force re-auth on next protected action
            self._unlocked = False
            self._fail_count = 0
            self._lockout_until = 0.0
        log("[GUI-LOCK] PIN store changed externally — reloaded")

    def _save(self) -> bool:
        path = _lock_path()
        try:
            tmp = path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(self._data, fh, indent=2)
            os.replace(tmp, path)
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
            try:
                self._mtime = os.path.getmtime(path)
            except OSError:
                pass
            return True
        except Exception as e:
            log(f"[GUI-LOCK] save error: {e}")
            return False

    def has_pin(self) -> bool:
        self._maybe_reload()
        with self._lock:
            return bool(self._data.get("pin_hash") and self._data.get("salt"))

    def is_enabled(self) -> bool:
        """PIN enforced when a hash exists (feature on by presence)."""
        return self.has_pin()

    def is_session_unlocked(self) -> bool:
        with self._lock:
            return bool(self._unlocked)

    def lock_session(self) -> None:
        with self._lock:
            self._unlocked = False

    def unlock_session(self) -> None:
        with self._lock:
            self._unlocked = True
            self._fail_count = 0
            self._lockout_until = 0.0

    def lockout_remaining(self) -> float:
        with self._lock:
            return max(0.0, self._lockout_until - time.time())

    def set_pin(self, pin: str, source: str = "local") -> Tuple[bool, str]:
        pin = (pin or "").strip()
        if not pin.isdigit():
            return False, "pin_digits_only"
        if len(pin) < _MIN_PIN_LEN or len(pin) > _MAX_PIN_LEN:
            return False, "pin_length"
        salt = secrets.token_bytes(_SALT_BYTES)
        digest = _hash_pin(pin, salt)
        with self._lock:
            self._data = {
                "version": 1,
                "algo": "pbkdf2_sha256",
                "iterations": _PBKDF2_ITERATIONS,
                "salt": salt.hex(),
                "pin_hash": digest,
                "updated_at": time.time(),
                "source": source,
            }
            ok = self._save()
            if ok:
                self._unlocked = True
                self._fail_count = 0
            return (ok, "ok" if ok else "save_failed")

    def change_pin(self, old_pin: str, new_pin: str) -> Tuple[bool, str]:
        ok, err = self.verify_pin(old_pin, unlock_on_success=False)
        if not ok:
            return False, err
        return self.set_pin(new_pin)

    def clear_pin_unverified(self) -> Tuple[bool, str]:
        """Dashboard-initiated PIN reset — no local PIN required.

        Only callable from the SYSTEM daemon remote-command path; the cloud
        already authenticated the operator (account + server confirm).
        """
        with self._lock:
            self._data = {}
            path = _lock_path()
            try:
                if os.path.isfile(path):
                    os.remove(path)
            except OSError as e:
                log(f"[GUI-LOCK] remote clear error: {e}")
                return False, "save_failed"
            self._mtime = 0.0
            self._unlocked = False
            return True, "ok"

    def clear_pin(self, pin: str) -> Tuple[bool, str]:
        ok, err = self.verify_pin(pin, unlock_on_success=False)
        if not ok:
            return False, err
        with self._lock:
            self._data = {}
            path = _lock_path()
            try:
                if os.path.isfile(path):
                    os.remove(path)
            except OSError as e:
                log(f"[GUI-LOCK] clear error: {e}")
                return False, "save_failed"
            self._mtime = 0.0
            self._unlocked = True
            return True, "ok"

    def verify_pin(self, pin: str, unlock_on_success: bool = True) -> Tuple[bool, str]:
        pin = (pin or "").strip()
        self._maybe_reload()
        with self._lock:
            remaining = self._lockout_until - time.time()
            if remaining > 0:
                return False, "locked_out"
            if not self.has_pin():
                if unlock_on_success:
                    self._unlocked = True
                return True, "ok"

            salt_hex = self._data.get("salt", "")
            expected = self._data.get("pin_hash", "")
            iterations = int(self._data.get("iterations") or _PBKDF2_ITERATIONS)
            try:
                salt = bytes.fromhex(salt_hex)
            except ValueError:
                return False, "corrupt"

            got = _hash_pin(pin, salt, iterations)
            if not hmac.compare_digest(got, expected):
                self._fail_count += 1
                if self._fail_count >= _MAX_ATTEMPTS:
                    self._lockout_until = time.time() + _LOCKOUT_SECONDS
                    self._fail_count = 0
                    log("[GUI-LOCK] too many failures — temporary lockout")
                    return False, "locked_out"
                return False, "wrong_pin"

            if unlock_on_success:
                self._unlocked = True
            self._fail_count = 0
            self._lockout_until = 0.0
            return True, "ok"


def dashboard_pin_hint(translator=None) -> str:
    """Hint shown on PIN dialogs when this client is linked to an account.

    Dashboard can set/reset the PIN remotely (set_gui_pin / clear_gui_pin),
    so a linked user who forgot the PIN has a recovery path.
    """
    try:
        from client_utils import is_account_linked
        if not is_account_linked():
            return ""
    except Exception:
        return ""
    default = (
        "Hesabınız bağlı — PIN kodunuzu dashboard üzerinden "
        "tanımlayabilir veya sıfırlayabilirsiniz."
    )
    if callable(translator):
        try:
            val = translator("pin_dashboard_hint")
            if val and val != "pin_dashboard_hint":
                return str(val)
        except Exception:
            pass
    return default


def prompt_pin_dialog(parent, title: str, prompt: str, confirm: bool = False,
                      hint: str = "") -> Optional[str]:
    """Modal PIN entry on Tk thread. Returns PIN string or None if cancelled.

    Re-entrant safe: tray clicks while wait_window runs would otherwise open
    stacked dialogs — if one is already open, focus it and return None.
    """
    lock = GuiLock.instance()
    if lock._prompt_active:
        try:
            win = lock._prompt_window
            if win is not None:
                try:
                    win.lift()
                    win.focus_force()
                    win.attributes("-topmost", True)
                except Exception:
                    pass
        except Exception:
            pass
        log("[GUI-LOCK] PIN dialog already open — ignoring duplicate prompt")
        return None

    try:
        import customtkinter as ctk
        from client_gui_theme import COLORS
    except Exception:
        return _prompt_pin_fallback(parent, title, prompt, confirm)

    result: dict = {"pin": None}
    win = ctk.CTkToplevel(parent)
    win.title(title)
    base_h = 220 if not confirm else 280
    if hint:
        base_h += 44
    win.geometry(f"360x{base_h}")
    win.configure(fg_color=COLORS.get("bg", "#0b1120"))
    win.transient(parent)
    try:
        win.grab_set()
    except Exception:
        pass
    win.attributes("-topmost", True)
    win.focus_force()

    lock._prompt_active = True
    lock._prompt_window = win

    ctk.CTkLabel(
        win, text=prompt,
        font=ctk.CTkFont(size=13),
        text_color=COLORS.get("text_bright", "#f8fafc"),
        wraplength=320,
    ).pack(padx=16, pady=(16, 8))

    if hint:
        ctk.CTkLabel(
            win, text=f"☁ {hint}",
            font=ctk.CTkFont(size=11),
            text_color=COLORS.get("blue", "#3b82f6"),
            wraplength=320, justify="left",
        ).pack(padx=16, pady=(0, 6))

    entry1 = ctk.CTkEntry(win, show="•", width=200, justify="center")
    entry1.pack(pady=6)
    entry1.focus_set()

    entry2 = None
    if confirm:
        ctk.CTkLabel(
            win, text="Confirm PIN",
            font=ctk.CTkFont(size=11),
            text_color=COLORS.get("text_dim", "#64748b"),
        ).pack()
        entry2 = ctk.CTkEntry(win, show="•", width=200, justify="center")
        entry2.pack(pady=6)

    err_lbl = ctk.CTkLabel(
        win, text="",
        font=ctk.CTkFont(size=11),
        text_color=COLORS.get("red", "#f43f5e"),
    )
    err_lbl.pack(pady=4)

    def _cleanup():
        lock._prompt_active = False
        lock._prompt_window = None

    def _submit(_event=None):
        p1 = entry1.get().strip()
        if confirm and entry2 is not None:
            p2 = entry2.get().strip()
            if p1 != p2:
                err_lbl.configure(text="PINs do not match")
                return
        if not p1.isdigit() or not (_MIN_PIN_LEN <= len(p1) <= _MAX_PIN_LEN):
            err_lbl.configure(text=f"PIN: {_MIN_PIN_LEN}-{_MAX_PIN_LEN} digits")
            return
        result["pin"] = p1
        _cleanup()
        win.destroy()

    def _cancel():
        result["pin"] = None
        _cleanup()
        win.destroy()

    row = ctk.CTkFrame(win, fg_color="transparent")
    row.pack(pady=10)
    ctk.CTkButton(
        row, text="OK", width=90, command=_submit,
        fg_color=COLORS.get("blue", "#3b82f6"),
    ).pack(side="left", padx=6)
    ctk.CTkButton(
        row, text="Cancel", width=90, command=_cancel,
        fg_color=COLORS.get("card", "#1e293b"),
    ).pack(side="left", padx=6)

    entry1.bind("<Return>", _submit)
    if entry2 is not None:
        entry2.bind("<Return>", _submit)

    win.protocol("WM_DELETE_WINDOW", _cancel)

    try:
        win.wait_window()
    finally:
        _cleanup()
    return result["pin"]


def _prompt_pin_fallback(parent, title: str, prompt: str, confirm: bool) -> Optional[str]:
    try:
        from tkinter import simpledialog
        p1 = simpledialog.askstring(title, prompt, show="*", parent=parent)
        if p1 is None:
            return None
        if confirm:
            p2 = simpledialog.askstring(title, "Confirm PIN", show="*", parent=parent)
            if p2 is None or p1 != p2:
                return None
        return p1.strip()
    except Exception:
        return None


def require_gui_unlock(app, reason: str = "unlock") -> bool:
    """
    Ensure PIN unlocked for protected UI actions.
    If no PIN set: optionally prompt to create (settings/exit) or allow (show).
    Returns True if action may proceed.
    """
    lock = GuiLock.instance()
    root = getattr(app, "root", None)

    def _t(key: str, default: str = "") -> str:
        fn = getattr(app, "t", None)
        if callable(fn):
            try:
                val = fn(key)
                if val and val != key:
                    return str(val)
            except Exception:
                pass
        return default or key

    if lock.lockout_remaining() > 0:
        try:
            from tkinter import messagebox
            secs = int(lock.lockout_remaining())
            messagebox.showwarning(
                _t("pin_title", "PIN"),
                _t("pin_locked_out", "Locked out ({seconds}s)").format(seconds=secs),
                parent=root,
            )
        except Exception:
            pass
        return False

    if lock.is_session_unlocked():
        return True

    hint = dashboard_pin_hint(getattr(app, "t", None))

    if not lock.has_pin():
        if reason in ("exit", "settings", "mutate", "set"):
            pin = prompt_pin_dialog(
                root,
                _t("pin_set_title", "Set PIN"),
                _t("pin_set_prompt", "Create a PIN (4-12 digits)"),
                confirm=True,
                hint=hint,
            )
            if not pin:
                return False
            ok, err = lock.set_pin(pin)
            if not ok:
                log(f"[GUI-LOCK] set_pin failed: {err}")
                return False
            return True
        lock.unlock_session()
        return True

    pin = prompt_pin_dialog(
        root,
        _t("pin_title", "PIN"),
        _t("pin_unlock_prompt", "Enter PIN to continue"),
        confirm=False,
        hint=hint,
    )
    if pin is None:
        return False
    ok, err = lock.verify_pin(pin, unlock_on_success=True)
    if not ok:
        try:
            from tkinter import messagebox
            if err == "locked_out":
                msg = _t("pin_locked_out", "Locked out").format(
                    seconds=int(lock.lockout_remaining())
                )
            else:
                msg = _t("pin_wrong", "Wrong PIN")
            messagebox.showerror(_t("pin_title", "PIN"), msg, parent=root)
        except Exception:
            pass
        return False
    return True
