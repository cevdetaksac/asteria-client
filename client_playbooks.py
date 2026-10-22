"""IR scenario packs (contract features/containment.md).

Each playbook runs a fixed sequence of existing admin commands. One operator
confirm on the cloud; every step is reported; a single undo_id reverses what
was applied (best-effort, reverse order).
"""
from __future__ import annotations

import time
import uuid
from typing import Callable, Dict, List, Optional

from client_admin_ops import std, step


PLAYBOOK_DEFS: Dict[str, dict] = {
    "rdp_attack": {
        "title": "RDP saldırısı",
        "description": "Oturumları kapat, şüpheli hesabı pasifleştir, kaynak IP'yi engelle",
        "steps": [
            {"command": "logoff_all_sessions", "params": {"include_console": False}},
            {"command": "disable_account", "params_from": ["username"], "optional": True},
            {"command": "block_ip", "params_from": ["ip", "remote_ip"], "optional": True},
        ],
    },
    "compromised_admin": {
        "title": "Ele geçirilmiş yönetici",
        "description": "Yönetici hesabını contain et (logoff + şifre + opsiyonel disable)",
        "steps": [
            {"command": "contain_user", "params_from": ["username", "new_password", "disable", "session_id"]},
            {"command": "disable_account", "params_from": ["username"], "when": "disable_extra"},
        ],
    },
    "malicious_process": {
        "title": "Kötü niyetli süreç",
        "description": "Süreci dondur + outbound kes + kalıcılığı kapat; opsiyonel IFEO",
        "steps": [
            {
                "command": "contain_process",
                "params_from": [
                    "pid", "expected_image", "process_name", "process_start_time",
                    "expected_path", "net_block", "persistence", "suspend", "ifeo",
                ],
                "defaults": {"net_block": True, "persistence": True, "suspend": True},
            },
            {
                "command": "block_process",
                "params_from": ["expected_image", "process_name", "path", "expected_path"],
                "when": "ifeo",
                "optional": True,
            },
        ],
    },
}


def list_playbooks() -> dict:
    items = [
        {"id": k, "title": v["title"], "description": v["description"],
         "step_count": len(v["steps"])}
        for k, v in PLAYBOOK_DEFS.items()
    ]
    return std(True, "PLAYBOOKS", f"{len(items)} playbook", playbooks=items)


def _pick(params: dict, keys: List[str]) -> dict:
    out = {}
    for k in keys:
        if k in params and params[k] not in (None, ""):
            # normalize aliases
            if k in ("ip", "remote_ip"):
                out["ip"] = params[k]
            elif k == "process_name" and "expected_image" not in out:
                out.setdefault("expected_image", params[k])
                out["process_name"] = params[k]
            elif k in ("path", "expected_path"):
                out.setdefault("path", params[k])
                out.setdefault("expected_path", params[k])
            else:
                out[k] = params[k]
    return out


def run_playbook(
    playbook_id: str,
    params: Optional[dict],
    *,
    execute: Callable[[str, dict], dict],
    dry_run: bool = False,
    save_state: Optional[Callable[[str, dict], None]] = None,
) -> dict:
    pid = (playbook_id or "").strip()
    spec = PLAYBOOK_DEFS.get(pid)
    if not spec:
        return std(False, "UNKNOWN_PLAYBOOK", f"Bilinmeyen playbook: {pid}")
    params = dict(params or {})
    steps_out: List[dict] = []
    applied: List[dict] = []
    undo_id = str(uuid.uuid4())

    for i, sdef in enumerate(spec["steps"]):
        when = sdef.get("when")
        if when and not params.get(when):
            steps_out.append(step(f"skip_{sdef['command']}", True, "condition false"))
            continue
        cmd = sdef["command"]
        p = dict(sdef.get("defaults") or {})
        p.update(_pick(params, list(sdef.get("params_from") or [])))
        # merge explicit params that match command
        for k, v in params.items():
            if k.startswith("_"):
                continue
            if k in ("playbook", "playbook_id", "dry_run", "ifeo", "disable_extra"):
                continue
            if k not in p and k in (
                "username", "new_password", "disable", "session_id", "ip",
                "pid", "expected_image", "process_start_time", "net_block",
                "persistence", "suspend", "path", "expected_path", "process_name",
            ):
                p[k] = v
        if dry_run or params.get("dry_run"):
            steps_out.append(step(cmd, True, "dry_run", index=i, params_keys=sorted(p.keys())))
            continue
        # Skip optional steps missing required identity
        if sdef.get("optional"):
            if cmd == "disable_account" and not p.get("username"):
                steps_out.append(step(cmd, True, "skipped_no_username", index=i))
                continue
            if cmd == "block_ip" and not p.get("ip"):
                steps_out.append(step(cmd, True, "skipped_no_ip", index=i))
                continue
            if cmd == "block_process" and not (
                p.get("expected_image") or p.get("process_name") or p.get("path")
            ):
                steps_out.append(step(cmd, True, "skipped_no_image", index=i))
                continue
        try:
            res = execute(cmd, p) or {}
        except Exception as e:
            res = {"ok": False, "success": False, "code": "STEP_ERROR", "message": str(e)[:200]}
        ok = bool(res.get("ok") if "ok" in res else res.get("success"))
        steps_out.append(step(
            cmd, ok, res.get("message") or res.get("code") or "",
            index=i, code=res.get("code"),
            undo_id=(res.get("data") or {}).get("undo_id") or res.get("undo_id"),
        ))
        applied.append({
            "command": cmd, "params": p, "result": {
                "ok": ok, "code": res.get("code"),
                "undo_id": (res.get("data") or {}).get("undo_id") or res.get("undo_id"),
                "image": (res.get("data") or {}).get("image"),
            },
        })
        if not ok and not sdef.get("optional"):
            # stop on hard failure
            break

    if dry_run or params.get("dry_run"):
        return std(True, "DRY_RUN", f"playbook {pid} plan", steps_out,
                   playbook=pid, title=spec["title"])

    state = {
        "kind": "playbook", "undo_id": undo_id, "playbook": pid,
        "created_at": time.time(), "applied": applied,
    }
    if save_state:
        save_state(undo_id, state)
    else:
        try:
            from client_contain import _save_state
            _save_state(undo_id, state)
        except Exception:
            pass
    failed = [s for s in steps_out if not s.get("ok")]
    ok = not failed
    return std(
        ok,
        "PLAYBOOK_DONE" if ok else "PLAYBOOK_PARTIAL",
        f"{spec['title']}: {len(applied)} adım" + ("" if ok else f", {len(failed)} hata"),
        steps_out,
        undo_id=undo_id, playbook=pid, title=spec["title"], applied_count=len(applied),
    )


def undo_playbook(undo_id: str, *, execute: Callable[[str, dict], dict]) -> dict:
    undo_id = (undo_id or "").strip()
    if not undo_id:
        return std(False, "MISSING_UNDO_ID", "undo_id gerekli")
    try:
        from client_contain import _load_state, _drop_state
    except Exception as e:
        return std(False, "STATE_UNAVAILABLE", str(e)[:200])
    state = _load_state(undo_id)
    if not state or state.get("kind") != "playbook":
        return std(False, "UNDO_NOT_FOUND", f"playbook kaydı yok: {undo_id}")
    steps_out = []
    for item in reversed(state.get("applied") or []):
        cmd = item.get("command")
        res_meta = item.get("result") or {}
        uid = res_meta.get("undo_id")
        image = res_meta.get("image")
        params = item.get("params") or {}
        try:
            if cmd == "contain_process" and uid:
                r = execute("release_process", {"undo_id": uid})
            elif cmd == "block_process" and (image or params.get("expected_image") or params.get("process_name")):
                img = image or params.get("expected_image") or params.get("process_name")
                r = execute("unblock_process", {"process_name": img, "name": img})
            elif cmd == "disable_account" and params.get("username"):
                r = execute("enable_account", {"username": params["username"]})
            elif cmd == "block_ip" and params.get("ip"):
                r = execute("unblock_ip", {"ip": params["ip"]})
            elif cmd == "contain_user" and params.get("username"):
                # best-effort: re-enable account
                r = execute("enable_account", {"username": params["username"]})
            else:
                steps_out.append(step(f"undo_{cmd}", True, "no_inverse"))
                continue
        except Exception as e:
            r = {"ok": False, "message": str(e)[:200]}
        ok = bool(r.get("ok") if "ok" in r else r.get("success"))
        steps_out.append(step(f"undo_{cmd}", ok, r.get("message") or r.get("code") or ""))
    _drop_state(undo_id)
    return std(True, "PLAYBOOK_UNDONE", f"playbook geri alındı ({undo_id[:8]})",
               steps_out, undo_id=undo_id)
