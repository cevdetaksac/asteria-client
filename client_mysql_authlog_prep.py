#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Ensure MySQL/MariaDB logs failed logins for AuthLogWatcher (C-ATK-2).

MySQL 8 defaults ``log_error_verbosity=2`` (errors+warnings). Access denied is a
**Note** and only appears at verbosity **3**. Without this, AuthLog finds the
``.err`` path but never emits MYSQL Attacks.

Idempotent host prep (install / daemon boot):
  - Locate ``my.ini`` / ``my.cnf`` under common MySQL/MariaDB paths
  - Set ``log_error_verbosity=3`` under ``[mysqld]`` (backup ``.asteria.bak``)
  - Restart matching MySQL/MariaDB Windows services **only if** the file changed

Opt-out: ``ASTERIA_SKIP_MYSQL_AUTHLOG_PREP=1``
"""

from __future__ import annotations

import glob
import os
import re
import shutil
import subprocess
import time
from typing import Any, Dict, List, Optional, Tuple

_FLAG_NAME = "mysql_authlog_prep.flag"
_FLAG_TTL_SEC = 6 * 3600
_TARGET_VERBOSITY = 3

_INI_GLOBS = (
    r"C:\ProgramData\MySQL\MySQL Server *\my.ini",
    r"C:\ProgramData\MySQL\MySQL Server *\my.cnf",
    r"C:\Program Files\MySQL\MySQL Server *\my.ini",
    r"C:\Program Files\MariaDB *\my.ini",
    r"C:\Program Files\MariaDB *\data\my.ini",
    r"C:\xampp\mysql\bin\my.ini",
    r"C:\laragon\bin\mysql\mysql*\my.ini",
)

_VERBOSITY_RE = re.compile(
    r"^\s*log[-_]error[-_]verbosity\s*=\s*(\d+)\s*$",
    re.IGNORECASE,
)
_SECTION_RE = re.compile(r"^\s*\[([^\]]+)\]\s*$")


def _programdata_asteria() -> str:
    pd = os.environ.get("ProgramData") or r"C:\ProgramData"
    return os.path.join(pd, "Asteria")


def _flag_path() -> str:
    return os.path.join(_programdata_asteria(), _FLAG_NAME)


def _log(msg: str) -> None:
    try:
        from client_helpers import log

        log(f"[MYSQL-AUTHLOG-PREP] {msg}")
    except Exception:
        pass


def _should_skip(force: bool = False) -> bool:
    if force:
        return False
    if (os.environ.get("ASTERIA_SKIP_MYSQL_AUTHLOG_PREP") or "").strip() in (
        "1",
        "true",
        "yes",
    ):
        return True
    path = _flag_path()
    try:
        age = time.time() - os.path.getmtime(path)
        if age < _FLAG_TTL_SEC:
            return True
    except OSError:
        pass
    return False


def _mark_done(summary: str) -> None:
    root = _programdata_asteria()
    try:
        os.makedirs(root, exist_ok=True)
        with open(_flag_path(), "w", encoding="utf-8") as fh:
            fh.write(f"ok {int(time.time())} {summary}\n")
    except OSError:
        pass


def _list_ini_files(extra: Optional[Tuple[str, ...]] = None) -> List[str]:
    patterns = list(_INI_GLOBS)
    if extra:
        patterns.extend(extra)
    found: List[str] = []
    seen = set()
    for pattern in patterns:
        try:
            hits = glob.glob(pattern)
        except Exception:
            hits = []
        for p in hits:
            if not os.path.isfile(p):
                continue
            rp = os.path.normcase(os.path.normpath(p))
            if rp in seen:
                continue
            seen.add(rp)
            found.append(p)
    return found


def _ensure_verbosity_in_text(text: str, target: int = _TARGET_VERBOSITY) -> Tuple[str, bool, str]:
    """Return (new_text, changed, detail)."""
    lines = text.splitlines(keepends=True)
    if not lines and text == "":
        lines = []

    # Track newlines style
    def _eol(sample: str) -> str:
        if "\r\n" in sample:
            return "\r\n"
        return "\n"

    eol = _eol(text) if text else "\n"
    # Strip keepends for editing, rejoin later
    raw_lines = text.splitlines()
    section = ""
    mysqld_idx: Optional[int] = None
    verbosity_idxs: List[Tuple[int, str]] = []  # (line_idx, section)

    for i, line in enumerate(raw_lines):
        msec = _SECTION_RE.match(line)
        if msec:
            section = msec.group(1).strip().lower()
            if section in ("mysqld", "mysqld_safe", "server", "mariadbd"):
                if mysqld_idx is None:
                    mysqld_idx = i
            continue
        if section in ("mysqld", "mysqld_safe", "server", "mariadbd"):
            if _VERBOSITY_RE.match(line):
                verbosity_idxs.append((i, section))

    changed = False
    detail = "already_ok"

    if verbosity_idxs:
        for idx, _sec in verbosity_idxs:
            m = _VERBOSITY_RE.match(raw_lines[idx])
            cur = int(m.group(1)) if m else -1
            if cur != target:
                # Preserve indent / key spelling if possible
                key = "log_error_verbosity"
                km = re.match(r"^(\s*)(log[-_]error[-_]verbosity)\s*=", raw_lines[idx], re.I)
                indent = km.group(1) if km else ""
                if km:
                    key = km.group(2)
                raw_lines[idx] = f"{indent}{key}={target}"
                changed = True
                detail = f"updated_line={cur}->{target}"
    else:
        insert_at = None
        if mysqld_idx is not None:
            insert_at = mysqld_idx + 1
            # Skip blank / comment lines right after section header for nicer placement
            j = insert_at
            while j < len(raw_lines) and (
                not raw_lines[j].strip() or raw_lines[j].lstrip().startswith(("#", ";"))
            ):
                j += 1
            insert_at = j
        else:
            # Append a [mysqld] block
            if raw_lines and raw_lines[-1].strip():
                raw_lines.append("")
            raw_lines.append("[mysqld]")
            insert_at = len(raw_lines)
            changed = True
        raw_lines.insert(insert_at, f"log_error_verbosity={target}")
        changed = True
        detail = "inserted"

    if not changed:
        return text, False, detail

    # Rebuild with original newline style
    new_text = eol.join(raw_lines)
    if text.endswith(("\n", "\r\n")) and not new_text.endswith(("\n", "\r\n")):
        new_text += eol
    return new_text, True, detail


def ensure_ini_verbosity(path: str, target: int = _TARGET_VERBOSITY) -> Dict[str, Any]:
    """Patch one my.ini. Returns status dict."""
    result: Dict[str, Any] = {"path": path, "changed": False, "detail": "", "error": ""}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            original = fh.read()
    except OSError as exc:
        result["error"] = f"read:{exc}"
        return result

    new_text, changed, detail = _ensure_verbosity_in_text(original, target=target)
    result["detail"] = detail
    if not changed:
        return result

    bak = path + ".asteria.bak"
    try:
        if not os.path.isfile(bak):
            shutil.copy2(path, bak)
    except OSError as exc:
        result["error"] = f"backup:{exc}"
        return result

    try:
        with open(path, "w", encoding="utf-8", newline="") as fh:
            fh.write(new_text)
        result["changed"] = True
    except OSError as exc:
        result["error"] = f"write:{exc}"
        # try restore
        try:
            if os.path.isfile(bak):
                shutil.copy2(bak, path)
        except OSError:
            pass
    return result


def _mysql_service_names() -> List[str]:
    names: List[str] = []
    try:
        r = subprocess.run(
            ["sc.exe", "query", "type=", "service", "state=", "all"],
            capture_output=True,
            text=True,
            timeout=30,
            errors="replace",
        )
        blob = r.stdout or ""
    except Exception:
        blob = ""
    for line in blob.splitlines():
        line = line.strip()
        if not line.upper().startswith("SERVICE_NAME:"):
            continue
        name = line.split(":", 1)[1].strip()
        low = name.lower()
        if low.startswith("mysql") or low.startswith("maria"):
            names.append(name)
    # Fallbacks common on lab hosts
    for fb in ("MySQL804", "MySQL80", "MySQL57", "MySQL", "MariaDB"):
        if fb not in names:
            names.append(fb)
    return names


def _service_state(name: str) -> str:
    try:
        r = subprocess.run(
            ["sc.exe", "query", name],
            capture_output=True,
            text=True,
            timeout=15,
            errors="replace",
        )
        out = (r.stdout or "").upper()
        if "RUNNING" in out:
            return "RUNNING"
        if "STOPPED" in out:
            return "STOPPED"
        if r.returncode != 0:
            return "MISSING"
    except Exception:
        return "ERROR"
    return "UNKNOWN"


def restart_mysql_services() -> List[str]:
    """Restart running MySQL/MariaDB services. Returns action tags."""
    actions: List[str] = []
    for name in _mysql_service_names():
        st = _service_state(name)
        if st == "MISSING":
            continue
        if st != "RUNNING":
            actions.append(f"{name}:skip_{st.lower()}")
            continue
        try:
            subprocess.run(
                ["sc.exe", "stop", name],
                capture_output=True,
                text=True,
                timeout=60,
                errors="replace",
            )
            # wait up to ~30s for stop
            for _ in range(15):
                time.sleep(2)
                if _service_state(name) == "STOPPED":
                    break
            subprocess.run(
                ["sc.exe", "start", name],
                capture_output=True,
                text=True,
                timeout=60,
                errors="replace",
            )
            for _ in range(20):
                time.sleep(2)
                if _service_state(name) == "RUNNING":
                    actions.append(f"{name}:restarted")
                    break
            else:
                actions.append(f"{name}:start_timeout")
        except Exception as exc:
            actions.append(f"{name}:err:{exc}")
    return actions


def ensure_mysql_authlog_prep(
    *,
    force: bool = False,
    restart: bool = True,
    extra_ini: Optional[Tuple[str, ...]] = None,
) -> Dict[str, Any]:
    """Apply MySQL auth-log verbosity prep. Safe to call at boot."""
    summary: Dict[str, Any] = {
        "skipped": False,
        "ini_files": [],
        "changed_files": [],
        "restarts": [],
        "errors": [],
    }
    if _should_skip(force=force):
        summary["skipped"] = True
        return summary

    inis = _list_ini_files(extra=extra_ini)
    summary["ini_files"] = list(inis)
    if not inis:
        _log("no my.ini found — skip (MySQL not installed or non-standard path)")
        _mark_done("no_ini")
        return summary

    any_changed = False
    for path in inis:
        res = ensure_ini_verbosity(path)
        if res.get("error"):
            summary["errors"].append(f"{path}:{res['error']}")
            _log(f"ini patch failed {path}: {res['error']}")
            continue
        if res.get("changed"):
            any_changed = True
            summary["changed_files"].append(path)
            _log(f"set log_error_verbosity={_TARGET_VERBOSITY} in {path} ({res.get('detail')})")
        else:
            _log(f"ok {path} ({res.get('detail')})")

    if any_changed and restart:
        actions = restart_mysql_services()
        summary["restarts"] = actions
        _log("service actions: " + (", ".join(actions) if actions else "none"))
    elif any_changed:
        _log("ini changed; restart skipped (caller)")
    else:
        _log("no ini changes needed")

    _mark_done(
        "changed="
        + str(len(summary["changed_files"]))
        + ";errs="
        + str(len(summary["errors"]))
    )
    return summary


def ensure_mysql_authlog_prep_on_boot() -> Dict[str, Any]:
    """Boot/install entry — same TTL pattern as RD host prep."""
    return ensure_mysql_authlog_prep(force=False, restart=True)
