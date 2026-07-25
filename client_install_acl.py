#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Install-dir ACL helpers (SYSTEM daemon self-heal)."""

from __future__ import annotations

import os
import subprocess
import sys
from typing import Optional


CREATE_NO_WINDOW = 0x08000000


def _install_dir() -> Optional[str]:
    """Program Files\\Asteria\\Asteria Client when frozen."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return None


def ensure_motor_runtime_user_rx(log=None) -> bool:
    """Guarantee BUILTIN\\Users can Read+Execute motor onedir ``_internal``.

    Over-locked ACLs (SYSTEM/Admin only) cause interactive launches to fail with:
      Failed to load Python DLL '...\\_internal\\python312.dll'
      LoadLibrary: Erişim engellendi

    Users stay RX-only (no Modify) so DLLs cannot be replaced by a standard account.
    Safe to call repeatedly from the SYSTEM daemon.
    """
    def _log(msg: str) -> None:
        if log:
            try:
                log(msg)
            except Exception:
                pass

    root = _install_dir()
    if not root:
        return False
    internal = os.path.join(root, "_internal")
    if not os.path.isdir(internal):
        return False

    # Already readable by this process is not enough — heal for interactive Users.
    try:
        flags = CREATE_NO_WINDOW if os.name == "nt" else 0
        r1 = subprocess.run(
            [
                "icacls",
                internal,
                "/inheritance:r",
                "/grant:r",
                "NT AUTHORITY\\SYSTEM:(OI)(CI)F",
                "/grant:r",
                "BUILTIN\\Administrators:(OI)(CI)F",
                "/grant:r",
                "BUILTIN\\Users:(OI)(CI)RX",
                "/remove:g",
                "Everyone",
                "/remove:g",
                "NT AUTHORITY\\Authenticated Users",
                "/C",
                "/Q",
            ],
            capture_output=True,
            timeout=60,
            creationflags=flags,
        )
        r2 = subprocess.run(
            [
                "icacls",
                os.path.join(internal, "*"),
                "/inheritance:e",
                "/T",
                "/C",
                "/Q",
            ],
            capture_output=True,
            timeout=120,
            creationflags=flags,
        )
        ok = (r1.returncode == 0) and (r2.returncode == 0)
        _log(
            f"[ACL] motor _internal Users RX "
            f"root_rc={r1.returncode} child_rc={r2.returncode}"
        )
        return ok
    except Exception as e:
        _log(f"[ACL] motor _internal heal failed: {e}")
        return False
