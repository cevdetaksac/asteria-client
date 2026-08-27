# -*- coding: utf-8 -*-
"""Durable Remote Desktop capture-fail dumps for rare-host forensics.

When only 1–2 servers hit ``gdi+flat`` / LogonUI-present-but-flat, cloud scalars
are not enough. Persist a ring of JSON (+ optional JPEG) under
``%ProgramData%\\Asteria\\rd_capture_diag\\`` so support can pull evidence after
the fact. Never stores passwords or dashboard tokens.
"""

from __future__ import annotations

import json
import os
import time
from typing import Any, Dict, List, Optional

from client_helpers import log

_MAX_DUMPS = 8
_MAX_JPEG_BYTES = 280_000
_SUBDIR = "rd_capture_diag"


def dump_dir() -> str:
    try:
        from client_constants import MACHINE_DATA_DIR
        root = MACHINE_DATA_DIR
    except Exception:
        root = os.path.join(
            os.environ.get("ProgramData", r"C:\ProgramData"),
            "Asteria",
        )
    path = os.path.join(root, _SUBDIR)
    try:
        os.makedirs(path, exist_ok=True)
    except Exception:
        pass
    return path


def _prune(dir_path: str, keep: int = _MAX_DUMPS) -> None:
    try:
        files = [
            os.path.join(dir_path, n)
            for n in os.listdir(dir_path)
            if n.endswith(".json")
        ]
        files.sort(key=lambda p: os.path.getmtime(p), reverse=True)
        for old in files[keep:]:
            try:
                os.remove(old)
            except Exception:
                pass
            jpg = old[:-5] + ".jpg"
            try:
                if os.path.isfile(jpg):
                    os.remove(jpg)
            except Exception:
                pass
    except Exception:
        pass


def write_capture_fail_dump(
    *,
    reason: str,
    diag: Optional[dict] = None,
    extra: Optional[dict] = None,
    jpeg: Optional[bytes] = None,
    stream_id: str = "",
) -> Dict[str, Any]:
    """Write fail artifact. Returns ``{ok, path, jpeg_path}`` (paths may be empty)."""
    out: Dict[str, Any] = {"ok": False, "path": "", "jpeg_path": "", "reason": reason}
    try:
        folder = dump_dir()
        stamp = time.strftime("%Y%m%d_%H%M%S", time.gmtime())
        sid = "".join(c for c in str(stream_id or "") if c.isalnum())[:16] or "nostream"
        base = f"fail_{stamp}_{sid}_{str(reason or 'fail')[:40]}"
        base = "".join(c if c.isalnum() or c in "_-" else "_" for c in base)
        json_path = os.path.join(folder, base + ".json")
        payload: Dict[str, Any] = {
            "reason": str(reason or ""),
            "written_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "stream_id": str(stream_id or ""),
            "capture_diag": diag if isinstance(diag, dict) else {},
            "extra": extra if isinstance(extra, dict) else {},
        }
        # Strip accidental secrets
        for key in ("password", "token", "secret", "authorization"):
            payload["extra"].pop(key, None)
            payload["capture_diag"].pop(key, None)
        with open(json_path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2, default=str)
        out["path"] = json_path
        out["ok"] = True
        if jpeg and len(jpeg) >= 128:
            blob = bytes(jpeg[:_MAX_JPEG_BYTES])
            if blob[:2] == b"\xff\xd8":
                jpg_path = os.path.join(folder, base + ".jpg")
                with open(jpg_path, "wb") as fh:
                    fh.write(blob)
                out["jpeg_path"] = jpg_path
                payload["jpeg_bytes"] = len(blob)
                # refresh json with jpeg size
                with open(json_path, "w", encoding="utf-8") as fh:
                    json.dump(payload, fh, ensure_ascii=False, indent=2, default=str)
        _prune(folder)
        log(
            f"[REMOTE-DESKTOP] capture fail dump → {json_path}"
            + (f" jpeg={out['jpeg_path']}" if out.get("jpeg_path") else "")
        )
    except Exception as exc:
        out["error"] = str(exc)[:200]
        log(f"[REMOTE-DESKTOP] capture fail dump error: {exc}")
    return out


def recent_dump_paths(limit: int = 5) -> List[str]:
    folder = dump_dir()
    try:
        files = [
            os.path.join(folder, n)
            for n in os.listdir(folder)
            if n.endswith(".json")
        ]
        files.sort(key=lambda p: os.path.getmtime(p), reverse=True)
        return files[: max(1, int(limit))]
    except Exception:
        return []
