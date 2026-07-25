#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Canonical machine data paths + YesNext → Asteria ProgramData migration.

Contract / brand: all durable client state lives under::

    %ProgramData%\\Asteria\\

Legacy trees (copied once, never overwrite newer Asteria files)::

    %ProgramData%\\YesNext\\CloudHoneypotClient\\
    %ProgramData%\\YesNext\\CloudHoneypot\\
    %APPDATA%\\YesNext\\CloudHoneypotClient\\
"""

from __future__ import annotations

import os
import shutil
import time
from typing import Iterable, List, Optional, Tuple

_PROGRAMDATA = os.environ.get("ProgramData", r"C:\ProgramData")

# Canonical (Asteria brand)
MACHINE_DATA_DIR = os.path.join(_PROGRAMDATA, "Asteria")

# Legacy YesNext trees
LEGACY_MACHINE_CLIENT = os.path.join(_PROGRAMDATA, "YesNext", "CloudHoneypotClient")
LEGACY_MACHINE_VENDOR = os.path.join(_PROGRAMDATA, "YesNext", "CloudHoneypot")
LEGACY_USER_CLIENT = os.path.join(
    os.environ.get("APPDATA", ""),
    "YesNext",
    "CloudHoneypotClient",
)

_MIGRATE_MARKER = ".migrated_from_yesnext"
_SKIP_NAMES = frozenset({".", "..", _MIGRATE_MARKER})


def ensure_machine_data_dir() -> str:
    """Create %ProgramData%\\Asteria if needed; return the path."""
    try:
        os.makedirs(MACHINE_DATA_DIR, exist_ok=True)
    except OSError:
        pass
    return MACHINE_DATA_DIR


def legacy_data_roots() -> List[str]:
    roots = [LEGACY_MACHINE_CLIENT, LEGACY_MACHINE_VENDOR]
    if LEGACY_USER_CLIENT and os.path.isdir(LEGACY_USER_CLIENT):
        roots.append(LEGACY_USER_CLIENT)
    return roots


def _copy_file(src: str, dst: str) -> bool:
    try:
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        if os.path.exists(dst):
            # Keep newer / already-present Asteria copy
            try:
                if os.path.getmtime(dst) >= os.path.getmtime(src):
                    return False
            except OSError:
                return False
        shutil.copy2(src, dst)
        return True
    except OSError:
        return False


def _iter_files(root: str) -> Iterable[Tuple[str, str]]:
    """Yield (absolute_src, relative_posix) under root."""
    if not root or not os.path.isdir(root):
        return
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            if name in _SKIP_NAMES:
                continue
            abs_src = os.path.join(dirpath, name)
            rel = os.path.relpath(abs_src, root)
            yield abs_src, rel


def migrate_legacy_programdata(*, force: bool = False) -> dict:
    """Copy legacy YesNext state into %ProgramData%\\Asteria.

    Idempotent: skips when marker exists (unless force=True). Never deletes
    legacy trees (uninstall / next major can purge).
    """
    dest = ensure_machine_data_dir()
    marker = os.path.join(dest, _MIGRATE_MARKER)
    result = {
        "ok": True,
        "dest": dest,
        "copied": 0,
        "skipped": 0,
        "sources": [],
        "already_done": False,
        "error": "",
    }
    if not force and os.path.isfile(marker):
        result["already_done"] = True
        return result

    try:
        for root in legacy_data_roots():
            if not os.path.isdir(root):
                continue
            result["sources"].append(root)
            for abs_src, rel in _iter_files(root):
                dst = os.path.join(dest, rel)
                if _copy_file(abs_src, dst):
                    result["copied"] += 1
                else:
                    result["skipped"] += 1
        # Also pull systemprofile token if present and dest missing
        windir = os.environ.get("WINDIR", r"C:\Windows")
        for profile_token in (
            os.path.join(
                windir,
                "System32",
                "config",
                "systemprofile",
                "AppData",
                "Roaming",
                "YesNext",
                "CloudHoneypotClient",
                "token.dat",
            ),
            os.path.join(
                windir,
                "SysWOW64",
                "config",
                "systemprofile",
                "AppData",
                "Roaming",
                "YesNext",
                "CloudHoneypotClient",
                "token.dat",
            ),
        ):
            if os.path.isfile(profile_token):
                if _copy_file(profile_token, os.path.join(dest, "token.dat")):
                    result["copied"] += 1
                    result["sources"].append(profile_token)
                else:
                    result["skipped"] += 1

        with open(marker, "w", encoding="utf-8") as fh:
            fh.write(
                "migrated_at=%s\ncopied=%s\nskipped=%s\nsources=%s\n"
                % (
                    time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    result["copied"],
                    result["skipped"],
                    ";".join(result["sources"]),
                )
            )
    except Exception as exc:
        result["ok"] = False
        result["error"] = str(exc)
    return result


def programdata_client_dir() -> str:
    """Public helper used across modules (alias of MACHINE_DATA_DIR)."""
    ensure_machine_data_dir()
    try:
        migrate_legacy_programdata()
    except Exception:
        pass
    return MACHINE_DATA_DIR
