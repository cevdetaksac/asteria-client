"""Yeniden başlatma sonrası güncelleme sonucu → cloud (uzaktan teşhis).

Billur (Server 2016) 4.9.146→4.9.147: helper başladı, ajan ~30 sn sonra eski sürümle
döndü ve cloud'a HİÇBİR hata gitmedi ('sessiz başarısız'). Bu modül, açılışta durum
dosyası hâlâ 'installing/…' iken sürüm hedefin altındaysa bir kez
`self_update_failed` (reason=post_restart_still_old) olayı + helper log kuyruğunu gönderir.
"""
from __future__ import annotations

import json
import os
import re
import time
from typing import Callable, Optional

_ACTIVE = ("accepted", "downloading", "staging", "installing")
_MAX_AGE_SEC = 6 * 3600
_SECRET_RE = re.compile(r"[A-Za-z0-9+/_\-=]{32,}")


def _pd() -> str:
    return os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "Asteria")


def _marker_path() -> str:
    return os.path.join(_pd(), "update_outcome_reported.json")


def helper_log_tail(max_lines: int = 40, max_line: int = 220) -> list:
    path = os.path.join(_pd(), "update-install.log")
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            lines = fh.read()[-20000:].splitlines()
    except OSError:
        return []
    out = []
    for ln in lines[-max_lines:]:
        ln = _SECRET_RE.sub("[redacted]", ln.strip())[:max_line]
        if ln:
            out.append(ln)
    return out


def detect_post_restart_failure(current_version: str, now: Optional[float] = None) -> Optional[dict]:
    from client_update_ui import _read_raw, _norm_ver, _ver_tuple
    st = _read_raw() or {}
    phase = str(st.get("phase") or "")
    target = _norm_ver(str(st.get("to_version") or ""))
    cur = _norm_ver(current_version or "")
    if phase not in _ACTIVE or not target or not cur:
        return None
    if _ver_tuple(cur) >= _ver_tuple(target):
        return None
    updated = float(st.get("updated_at") or 0)
    now = time.time() if now is None else now
    if not updated or (now - updated) > _MAX_AGE_SEC:
        return None
    key = f"{target}@{int(updated)}"
    try:
        with open(_marker_path(), "r", encoding="utf-8") as fh:
            if json.load(fh).get("key") == key:
                return None
    except Exception:
        pass
    return {
        "key": key,
        "from_version": str(st.get("from_version") or ""),
        "to_version": target,
        "running_version": cur,
        "phase": phase,
        "detail": str(st.get("detail") or "")[:120],
        "age_sec": int(now - updated),
        "helper_log_tail": helper_log_tail(),
    }


def report_post_restart_failure(current_version: str, api_client=None, token: str = "",
                                log_func: Optional[Callable[[str], None]] = None) -> bool:
    try:
        info = detect_post_restart_failure(current_version)
        if not info:
            return False
        key = info.pop("key")
        from client_lifecycle import report_now
        report_now("self_update_failed", "post_restart_still_old", info, severity="error",
                   api_client=api_client, token=token or None, log_func=log_func)
        try:
            os.makedirs(_pd(), exist_ok=True)
            with open(_marker_path(), "w", encoding="utf-8") as fh:
                json.dump({"key": key, "ts": time.time()}, fh)
        except OSError:
            pass
        if log_func:
            log_func(f"[UPDATE-OUTCOME] post-restart still {current_version} (target {info['to_version']}) reported")
        return True
    except Exception as e:
        if log_func:
            log_func(f"[UPDATE-OUTCOME] error: {e}")
        return False
