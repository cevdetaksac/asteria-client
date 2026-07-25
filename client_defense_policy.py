# -*- coding: utf-8 -*-
"""Tiered Defense Policy — rule matrix, signed cache, anti-bait hard safety.

Contract: honeypot-contract 1.4.18 · ROADMAP_TIERED_DEFENSE P0 · cloud/DEFENSE_POLICY.md
Client target: ≥4.9.16

Invariants (never violate):
  - observe/balanced → never apply auto_isolate_network
  - tamper / bad sig → LKG or observe (never escalate / never isolate)
  - protected images never suspend/kill via matrix
  - single canary ≠ network isolate
  - N alerts ≠ auto-escalate to isolate
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import shutil
import threading
import time
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

try:
    from client_constants import MACHINE_DATA_DIR, TOKEN_FILE
except Exception:  # pragma: no cover
    MACHINE_DATA_DIR = os.path.join(
        os.environ.get("ProgramData", os.path.expanduser("~")),
        "YesNext",
        "CloudHoneypotClient",
    )
    TOKEN_FILE = os.path.join(MACHINE_DATA_DIR, "token.dat")

try:
    from client_helpers import log
except Exception:  # pragma: no cover
    def log(msg: str) -> None:
        print(msg)


POLICY_FILE = os.path.join(MACHINE_DATA_DIR, "defense_policy.json")
POLICY_LKG_FILE = os.path.join(MACHINE_DATA_DIR, "defense_policy.lkg.json")
ALLOWLIST_FILE = os.path.join(MACHINE_DATA_DIR, "defense_allowlist.json")
SNAPSHOT_DIR = os.path.join(MACHINE_DATA_DIR, "session_snapshots")

POLICY_NAMES = ("observe", "balanced", "paranoid")

ACTIONS = (
    "alert_only",
    "inform_only",
    "ask_operator",
    "suspend_process",
    "kill_quarantine",
    "auto_isolate_network",
)

# Event keys in the wire matrix
EVENT_CANARY_WRITE = "canary_write"
EVENT_VSS_DELETION = "vss_deletion"
EVENT_RANSOMWARE_CRITICAL = "ransomware_critical_process"
EVENT_SUSPICIOUS_RDP = "suspicious_rdp"
EVENT_HIGH_IO = "high_io_rate"
EVENT_MASS_PASSWORD = "mass_password_change"
EVENT_SURFACE_ADDITIVE = "network_surface_additive"

PRESET_RULES: Dict[str, Dict[str, str]] = {
    "observe": {
        EVENT_CANARY_WRITE: "alert_only",
        EVENT_VSS_DELETION: "alert_only",
        EVENT_RANSOMWARE_CRITICAL: "alert_only",
        EVENT_SUSPICIOUS_RDP: "alert_only",
        EVENT_HIGH_IO: "alert_only",
        EVENT_MASS_PASSWORD: "alert_only",
        EVENT_SURFACE_ADDITIVE: "inform_only",
    },
    "balanced": {
        EVENT_CANARY_WRITE: "kill_quarantine",
        EVENT_VSS_DELETION: "kill_quarantine",
        EVENT_RANSOMWARE_CRITICAL: "suspend_process",
        EVENT_SUSPICIOUS_RDP: "alert_only",
        EVENT_HIGH_IO: "alert_only",
        EVENT_MASS_PASSWORD: "alert_only",
        EVENT_SURFACE_ADDITIVE: "inform_only",
    },
    "paranoid": {
        EVENT_CANARY_WRITE: "kill_quarantine",
        EVENT_VSS_DELETION: "kill_quarantine",
        EVENT_RANSOMWARE_CRITICAL: "kill_quarantine",
        EVENT_SUSPICIOUS_RDP: "ask_operator",
        EVENT_HIGH_IO: "alert_only",
        EVENT_MASS_PASSWORD: "alert_only",
        EVENT_SURFACE_ADDITIVE: "inform_only",
    },
}

# Images that matrix actions must never touch (blast radius hard deny)
PROTECTED_IMAGES: Set[str] = {
    "system", "system idle process", "smss.exe", "csrss.exe", "wininit.exe",
    "winlogon.exe", "services.exe", "lsass.exe", "svchost.exe", "explorer.exe",
    "dwm.exe", "fontdrvhost.exe", "spoolsv.exe", "taskhostw.exe",
    "honeypot-client.exe", "python.exe", "pythonw.exe",
    "msmpeng.exe", "mssense.exe", "sense.exe",
    "vssvc.exe", "wbengine.exe",
}

SNAPSHOT_DEDUPE_SEC = 300.0  # ≥5 min per trigger family

_lock = threading.RLock()
_state: Dict[str, Any] = {
    "policy_name": "observe",
    "policy_version": "",
    "isolate_armed": False,
    "rules": dict(PRESET_RULES["observe"]),
    "sig_ok": True,
    "source": "builtin_observe",
    "updated_at": "",
    "tamper_alerted": False,
    "observe_started_at": "",
    "observe_auto_promote_days": 3,
    "observe_auto_promote_enabled": True,
    "defense_policy_locked": False,
    "policy_user_set": False,
    "cta_dismissed": False,
}

MODE_EDUCATION = {
    "observe": {
        "tr": {
            "title": "İzleme",
            "blurb": (
                "Tüm uyarıları görürsünüz; süreç otomatik öldürülmez ve ağ "
                "kesilmez. Kurulum sonrası önerilen ilk moddur."
            ),
        },
        "en": {
            "title": "Observe",
            "blurb": (
                "You see every alert; processes are not auto-killed and the "
                "network stays up. Recommended first mode after install."
            ),
        },
    },
    "balanced": {
        "tr": {
            "title": "Denge",
            "blurb": (
                "Kırmızı tehditte şüpheli süreç durdurulur veya karantinaya "
                "alınır; RDP ve internet ayakta kalır. Çoğu sunucu için önerilir."
            ),
        },
        "en": {
            "title": "Balanced",
            "blurb": (
                "On confirmed red threats the suspect process is stopped or "
                "quarantined; RDP and internet stay up. Recommended for most hosts."
            ),
        },
    },
    "paranoid": {
        "tr": {
            "title": "Tetikte",
            "blurb": (
                "Daha agresif süreç tepkisi. Ağ izolasyonu ayrı onay ister "
                "(RDP kesilebilir — brick riski)."
            ),
        },
        "en": {
            "title": "Paranoid",
            "blurb": (
                "More aggressive process response. Network isolation needs a "
                "separate arm (RDP may drop — brick risk)."
            ),
        },
    },
}

DEFAULT_PROMOTE_DAYS = 3

_allowlist: Dict[str, Any] = {"entries": []}
_snapshot_last: Dict[str, float] = {}
_on_tamper_alert: Optional[Callable[[dict], None]] = None


def set_tamper_alert_callback(cb: Optional[Callable[[dict], None]]) -> None:
    global _on_tamper_alert
    _on_tamper_alert = cb


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _read_token() -> str:
    try:
        with open(TOKEN_FILE, "r", encoding="utf-8") as f:
            return (f.read() or "").strip()
    except Exception:
        return ""


_DEFENSE_SIGNING_CONTEXT = "asteria-chp-v1"
_DEFENSE_SIGNING_LEGACY = "yesnext-chp-v1"


def _signing_secret(token: Optional[str] = None, context: str = _DEFENSE_SIGNING_CONTEXT) -> bytes:
    token = _read_token() if token is None else (token or "")
    machine = os.environ.get("COMPUTERNAME", "unknown")
    material = f"{token}|{machine}|{context}"
    return hashlib.sha256(material.encode("utf-8")).digest()


def _strip_sig(payload: dict) -> dict:
    return {k: v for k, v in payload.items() if k not in ("sig", "defense_rules_sig")}


def sign_payload(payload: dict, token: Optional[str] = None) -> str:
    body = json.dumps(_strip_sig(payload), sort_keys=True, ensure_ascii=False)
    return hmac.new(
        _signing_secret(token), body.encode("utf-8"), hashlib.sha256
    ).hexdigest()


def verify_payload(payload: dict, token: Optional[str] = None) -> bool:
    if not isinstance(payload, dict):
        return False
    sig = payload.get("sig") or payload.get("defense_rules_sig") or ""
    if not sig:
        return False
    try:
        body = json.dumps(_strip_sig(payload), sort_keys=True, ensure_ascii=False).encode(
            "utf-8"
        )
        for context in (_DEFENSE_SIGNING_CONTEXT, _DEFENSE_SIGNING_LEGACY):
            expected = hmac.new(
                _signing_secret(token, context), body, hashlib.sha256
            ).hexdigest()
            if hmac.compare_digest(str(sig), expected):
                return True
        return False
    except Exception:
        return False


def _normalize_action(raw: Any) -> Optional[str]:
    s = str(raw or "").strip().lower()
    if s in ACTIONS:
        return s
    # aliases
    aliases = {
        "kill": "kill_quarantine",
        "quarantine": "kill_quarantine",
        "suspend": "suspend_process",
        "alert": "alert_only",
        "inform": "inform_only",
        "ask": "ask_operator",
        "isolate": "auto_isolate_network",
        "auto_isolate": "auto_isolate_network",
    }
    return aliases.get(s)


def _normalize_rules(raw: Any, policy_name: str) -> Dict[str, str]:
    base = dict(PRESET_RULES.get(policy_name) or PRESET_RULES["balanced"])
    if not isinstance(raw, dict):
        return base
    out = dict(base)
    for key, val in raw.items():
        k = str(key or "").strip()
        act = _normalize_action(val)
        if k and act:
            out[k] = act
    return out


def _hard_safety_rules(
    rules: Dict[str, str],
    policy_name: str,
    isolate_armed: bool,
) -> Tuple[Dict[str, str], List[str]]:
    """Strip / rewrite unsafe actions. Returns (safe_rules, warnings)."""
    out = dict(rules)
    warnings: List[str] = []
    allow_isolate = (
        policy_name == "paranoid" and bool(isolate_armed)
    )
    for key, act in list(out.items()):
        if act == "auto_isolate_network" and not allow_isolate:
            # Balanced/observe (and unarmed paranoid) — process-first fallback
            fallback = PRESET_RULES.get(policy_name, PRESET_RULES["balanced"]).get(
                key, "alert_only"
            )
            if fallback == "auto_isolate_network":
                fallback = "kill_quarantine"
            out[key] = fallback
            warnings.append(
                f"stripped auto_isolate_network for {key} "
                f"(policy={policy_name} armed={isolate_armed}) -> {fallback}"
            )
        # High-FP signals never auto-suspend/kill even if custom override
        if key in (EVENT_HIGH_IO, EVENT_SURFACE_ADDITIVE) and act in (
            "suspend_process",
            "kill_quarantine",
            "auto_isolate_network",
        ):
            out[key] = "alert_only" if key == EVENT_HIGH_IO else "inform_only"
            warnings.append(f"forced soft action for bait-prone {key}")
    return out, warnings


def build_effective(
    *,
    policy_name: str = "observe",
    policy_version: str = "",
    rules: Optional[dict] = None,
    isolate_armed: bool = False,
    source: str = "",
    observe_started_at: str = "",
    observe_auto_promote_days: int = DEFAULT_PROMOTE_DAYS,
    observe_auto_promote_enabled: bool = True,
    defense_policy_locked: bool = False,
    policy_user_set: bool = False,
) -> dict:
    name = str(policy_name or "observe").strip().lower()
    if name not in POLICY_NAMES:
        name = "observe"
    armed = bool(isolate_armed) if name == "paranoid" else False
    norm = _normalize_rules(rules, name)
    safe, warnings = _hard_safety_rules(norm, name, armed)
    try:
        days = int(observe_auto_promote_days)
    except (TypeError, ValueError):
        days = DEFAULT_PROMOTE_DAYS
    days = max(0, min(14, days))
    payload = {
        "policy_name": name,
        "policy_version": str(policy_version or ""),
        "isolate_armed": armed,
        "rules": safe,
        "updated_at": _utc_now(),
        "source": source or "local",
        "warnings": warnings,
        "observe_started_at": str(observe_started_at or ""),
        "observe_auto_promote_days": days,
        "observe_auto_promote_enabled": bool(observe_auto_promote_enabled),
        "defense_policy_locked": bool(defense_policy_locked),
        "policy_user_set": bool(policy_user_set),
    }
    return payload


def education_for(policy_name: str, lang: str = "tr") -> dict:
    name = str(policy_name or "observe").lower()
    block = MODE_EDUCATION.get(name) or MODE_EDUCATION["observe"]
    loc = block.get(lang) or block.get("tr") or {}
    return {"policy": name, "title": loc.get("title") or name, "blurb": loc.get("blurb") or ""}


def all_education(lang: str = "tr") -> List[dict]:
    return [education_for(n, lang) for n in POLICY_NAMES]


def extract_from_config(config: Optional[dict]) -> Optional[dict]:
    """Pull defense fields from threats/config or nested protection{}."""
    if not isinstance(config, dict):
        return None
    prot = config.get("protection") if isinstance(config.get("protection"), dict) else {}
    name = (
        prot.get("defense_policy")
        or config.get("defense_policy")
        or ""
    )
    version = (
        prot.get("defense_policy_version")
        or config.get("defense_policy_version")
        or prot.get("policy_version")
        or ""
    )
    rules = prot.get("defense_rules") or config.get("defense_rules") or prot.get("rules")
    armed = prot.get("isolate_armed")
    if armed is None:
        armed = config.get("isolate_armed")
    sig = ""
    # Only explicit defense signatures — never bare config.sig (other modules)
    if prot.get("defense_rules_sig"):
        sig = str(prot.get("defense_rules_sig") or "")
    elif config.get("defense_rules_sig"):
        sig = str(config.get("defense_rules_sig") or "")
    elif isinstance(rules, dict) and prot.get("sig"):
        sig = str(prot.get("sig") or "")
    onboard_keys = (
        "observe_started_at",
        "observe_auto_promote_days",
        "observe_auto_promote_enabled",
        "defense_policy_locked",
        "policy_user_set",
    )
    has_onboard = any((k in prot) or (k in config) for k in onboard_keys)
    if not name and not version and not isinstance(rules, dict) and not sig and not has_onboard:
        return None
    if not name:
        name = get_state().get("policy_name") or "observe"
    out = {
        "policy_name": name,
        "policy_version": str(version or ""),
        "isolate_armed": bool(armed) if armed is not None else False,
        "rules": rules if isinstance(rules, dict) else None,
        "sig": str(sig or ""),
    }
    for k in onboard_keys:
        if k in prot:
            out[k] = prot.get(k)
        elif k in config:
            out[k] = config.get(k)
    return out


def _atomic_write_json(path: str, payload: dict) -> bool:
    try:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        return True
    except Exception as e:
        log(f"[DEFENSE-POLICY] write error {path}: {e}")
        return False


def _read_json(path: str) -> Optional[dict]:
    try:
        if not os.path.isfile(path):
            return None
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else None
    except Exception as e:
        log(f"[DEFENSE-POLICY] read error {path}: {e}")
        return None


def save_signed_cache(effective: dict, *, promote_lkg: bool = True) -> dict:
    """Sign + persist cache; optionally promote previous good file to LKG."""
    payload = dict(effective)
    payload.pop("warnings", None)
    payload["sig"] = sign_payload(payload)
    if promote_lkg and os.path.isfile(POLICY_FILE):
        try:
            prev = _read_json(POLICY_FILE)
            if prev and verify_payload(prev):
                shutil.copy2(POLICY_FILE, POLICY_LKG_FILE)
        except Exception:
            pass
    _atomic_write_json(POLICY_FILE, payload)
    return payload


def _emit_tamper(reason: str) -> None:
    global _state
    with _lock:
        if _state.get("tamper_alerted"):
            return
        _state["tamper_alerted"] = True
    log(f"[DEFENSE-POLICY] tamper/fail-safe: {reason}")
    cb = _on_tamper_alert
    if not cb:
        return
    try:
        cb({
            "event_type": "defense_policy_tamper",
            "threat_type": "defense_policy_tamper",
            "severity": "high",
            "threat_score": 70,
            "force_urgent": True,
            "title": "Defense policy cache integrity failure",
            "description": (
                f"İmzalı savunma politikası doğrulanamadı ({reason}). "
                "LKG/observe fail-safe uygulandı — ağ kesilmedi, escalate yok."
            ),
            "recommended_action": "review_policy",
            "auto_response_taken": ["fail_safe_observe_or_lkg"],
            "details": {"reason": reason, "isolate": False},
            "suppress_local_notify": False,
        })
    except Exception as e:
        log(f"[DEFENSE-POLICY] tamper alert error: {e}")


def _apply_state(effective: dict, *, sig_ok: bool, source: str) -> dict:
    with _lock:
        _state["policy_name"] = effective["policy_name"]
        _state["policy_version"] = effective.get("policy_version") or ""
        _state["isolate_armed"] = bool(effective.get("isolate_armed"))
        _state["rules"] = dict(effective.get("rules") or {})
        _state["sig_ok"] = bool(sig_ok)
        _state["source"] = source
        _state["updated_at"] = effective.get("updated_at") or _utc_now()
        if "observe_started_at" in effective:
            _state["observe_started_at"] = str(effective.get("observe_started_at") or "")
        if "observe_auto_promote_days" in effective:
            try:
                _state["observe_auto_promote_days"] = max(
                    0, min(14, int(effective.get("observe_auto_promote_days")))
                )
            except (TypeError, ValueError):
                pass
        if "observe_auto_promote_enabled" in effective:
            _state["observe_auto_promote_enabled"] = bool(
                effective.get("observe_auto_promote_enabled")
            )
        if "defense_policy_locked" in effective:
            _state["defense_policy_locked"] = bool(effective.get("defense_policy_locked"))
        if "policy_user_set" in effective:
            _state["policy_user_set"] = bool(effective.get("policy_user_set"))
        if _state["policy_name"] == "observe" and not _state.get("observe_started_at"):
            _state["observe_started_at"] = _utc_now()
        if sig_ok and source not in ("tamper_observe", "tamper_lkg"):
            _state["tamper_alerted"] = False
        return dict(_state)


def get_state() -> dict:
    with _lock:
        return {
            "policy_name": _state["policy_name"],
            "policy_version": _state["policy_version"],
            "isolate_armed": _state["isolate_armed"],
            "rules": dict(_state["rules"]),
            "sig_ok": _state["sig_ok"],
            "source": _state["source"],
            "updated_at": _state["updated_at"],
            "observe_started_at": _state.get("observe_started_at") or "",
            "observe_auto_promote_days": int(
                _state.get("observe_auto_promote_days") or 0
            ),
            "observe_auto_promote_enabled": bool(
                _state.get("observe_auto_promote_enabled", True)
            ),
            "defense_policy_locked": bool(_state.get("defense_policy_locked")),
            "policy_user_set": bool(_state.get("policy_user_set")),
            "cta_dismissed": bool(_state.get("cta_dismissed")),
        }


def status_summary() -> dict:
    st = get_state()
    due = promote_due_info()
    return {
        "present": True,
        "defense_policy": st["policy_name"],
        "defense_policy_version": st["policy_version"],
        "isolate_armed": st["isolate_armed"],
        "sig_ok": st["sig_ok"],
        "source": st["source"],
        "updated_at": st["updated_at"],
        "rules": dict(st["rules"]),
        "allowlist_entries": len(load_allowlist().get("entries") or []),
        "observe_started_at": st["observe_started_at"],
        "observe_auto_promote_days": st["observe_auto_promote_days"],
        "observe_auto_promote_enabled": st["observe_auto_promote_enabled"],
        "defense_policy_locked": st["defense_policy_locked"],
        "policy_user_set": st["policy_user_set"],
        "promote_due": bool(due.get("due")),
        "promote_in_sec": due.get("in_sec"),
        "education": all_education("tr"),
    }


def action_for(event_type: str) -> str:
    """Lookup matrix action with hard safety already applied in state."""
    key = str(event_type or "").strip()
    with _lock:
        name = _state["policy_name"]
        rules = _state["rules"]
        armed = _state["isolate_armed"]
    act = rules.get(key) or PRESET_RULES.get(name, PRESET_RULES["balanced"]).get(
        key, "alert_only"
    )
    if act == "auto_isolate_network" and not (
        name == "paranoid" and armed
    ):
        return "kill_quarantine"
    return act


def allows_network_isolate() -> bool:
    st = get_state()
    return (
        st["policy_name"] == "paranoid"
        and bool(st["isolate_armed"])
        and "auto_isolate_network" in (st["rules"] or {}).values()
    )


def reject_auto_isolate(reason: str = "") -> dict:
    """Standard rejection for isolate attempts under unsafe policy."""
    st = get_state()
    return {
        "success": False,
        "error": "isolate_rejected_policy",
        "message": (
            "auto_isolate_network rejected — observe/balanced never isolate; "
            "paranoid requires isolate_armed"
        ),
        "data": {
            "defense_policy": st["policy_name"],
            "isolate_armed": st["isolate_armed"],
            "reason": reason or "hard_safety",
        },
    }


def is_protected_image(image: str) -> bool:
    name = (image or "").strip().lower()
    if not name:
        return True
    if not name.endswith(".exe") and " " not in name:
        # bare name — still check
        pass
    base = os.path.basename(name)
    return base in PROTECTED_IMAGES or name in PROTECTED_IMAGES


# ── Allowlist (resume / allow_process exit door) ───────────────────

def load_allowlist() -> dict:
    global _allowlist
    with _lock:
        data = _read_json(ALLOWLIST_FILE)
        if isinstance(data, dict) and isinstance(data.get("entries"), list):
            _allowlist = data
        return deepcopy(_allowlist)


def save_allowlist(data: dict) -> bool:
    global _allowlist
    payload = {
        "entries": list(data.get("entries") or []),
        "updated_at": _utc_now(),
    }
    ok = _atomic_write_json(ALLOWLIST_FILE, payload)
    if ok:
        with _lock:
            _allowlist = payload
    return ok


def allow_process(
    *,
    path: str = "",
    image: str = "",
    sha256: str = "",
    reason: str = "",
) -> dict:
    """Add path and/or image (+ optional hash) to process allowlist."""
    path_n = os.path.normpath(path).lower() if path else ""
    image_n = (image or (os.path.basename(path_n) if path_n else "")).lower()
    sha = (sha256 or "").strip().lower()
    if not path_n and not image_n and not sha:
        return {"success": False, "error": "path_or_image_required"}
    if image_n and is_protected_image(image_n):
        return {"success": False, "error": f"protected_image:{image_n}"}
    data = load_allowlist()
    entries = list(data.get("entries") or [])
    for e in entries:
        if path_n and (e.get("path") or "").lower() == path_n:
            return {
                "success": True,
                "message": "already_allowed",
                "data": e,
            }
        if sha and (e.get("sha256") or "").lower() == sha:
            return {
                "success": True,
                "message": "already_allowed",
                "data": e,
            }
    entry = {
        "path": path_n,
        "image": image_n,
        "sha256": sha,
        "reason": (reason or "")[:200],
        "at": _utc_now(),
    }
    entries.append(entry)
    # Cap growth
    if len(entries) > 200:
        entries = entries[-200:]
    save_allowlist({"entries": entries})
    log(f"[DEFENSE-POLICY] allow_process image={image_n} path={path_n[:80]}")
    return {"success": True, "message": "allowed", "data": entry}


def is_process_allowed(
    *,
    path: str = "",
    image: str = "",
    sha256: str = "",
) -> bool:
    path_n = os.path.normpath(path).lower() if path else ""
    image_n = (image or "").lower()
    sha = (sha256 or "").strip().lower()
    for e in (load_allowlist().get("entries") or []):
        if not isinstance(e, dict):
            continue
        if sha and (e.get("sha256") or "").lower() == sha:
            return True
        if path_n and (e.get("path") or "").lower() == path_n:
            return True
        if image_n and (e.get("image") or "").lower() == image_n and not e.get("path"):
            # image-only allow is intentional for known-good tools
            return True
        if image_n and path_n and (e.get("image") or "").lower() == image_n:
            ep = (e.get("path") or "").lower()
            if not ep or ep == path_n:
                return True
    return False


# ── Session snapshot (P0-4) ────────────────────────────────────────

def maybe_capture_session_snapshot(
    trigger_family: str,
    *,
    alert_attach: Optional[dict] = None,
) -> Optional[dict]:
    """Capture ≤1 JPEG / 5 min / trigger family. Best-effort; never raises."""
    family = str(trigger_family or "red").strip().lower() or "red"
    now = time.time()
    with _lock:
        last = float(_snapshot_last.get(family) or 0.0)
        if now - last < SNAPSHOT_DEDUPE_SEC:
            return None
        _snapshot_last[family] = now
    try:
        os.makedirs(SNAPSHOT_DIR, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = os.path.join(SNAPSHOT_DIR, f"{family}_{stamp}.jpg")
        from client_remote_desktop import capture_once_to_file
        ok = capture_once_to_file(path)
        if not ok or not os.path.isfile(path):
            return None
        meta = {
            "path": path,
            "family": family,
            "at": _utc_now(),
            "bytes": int(os.path.getsize(path)),
        }
        if isinstance(alert_attach, dict):
            ctx = alert_attach.setdefault("system_context", {})
            if not isinstance(ctx, dict):
                ctx = {}
                alert_attach["system_context"] = ctx
            ctx["session_snapshot"] = {
                "family": family,
                "path": path,
                "bytes": meta["bytes"],
                "at": meta["at"],
            }
        log(f"[DEFENSE-POLICY] session snapshot {family} -> {path}")
        return meta
    except Exception as e:
        log(f"[DEFENSE-POLICY] session snapshot skipped: {e}")
        return None


# ── Apply / hydrate ────────────────────────────────────────────────

def apply_from_config(config: Optional[dict], *, token: Optional[str] = None) -> dict:
    """Apply threats/config defense fields; persist signed cache.

    Cloud may omit sig until C-P0-4 ships — client then locally resigns for integrity.
    If cloud sends sig and it fails verification → keep LKG/observe (anti-bait).
    """
    extracted = extract_from_config(config)
    if extracted is None:
        return get_state()

    prev = get_state()
    cloud_sig = extracted.get("sig") or ""
    started = extracted.get("observe_started_at")
    if started is None:
        started = prev.get("observe_started_at") or ""
    days = extracted.get("observe_auto_promote_days")
    if days is None:
        days = prev.get("observe_auto_promote_days", DEFAULT_PROMOTE_DAYS)
    enabled = extracted.get("observe_auto_promote_enabled")
    if enabled is None:
        enabled = prev.get("observe_auto_promote_enabled", True)
    locked = extracted.get("defense_policy_locked")
    if locked is None:
        locked = prev.get("defense_policy_locked", False)
    user_set = extracted.get("policy_user_set")
    if user_set is None:
        user_set = prev.get("policy_user_set", False)

    effective = build_effective(
        policy_name=extracted.get("policy_name") or "observe",
        policy_version=extracted.get("policy_version") or "",
        rules=extracted.get("rules"),
        isolate_armed=bool(extracted.get("isolate_armed")),
        source="threats/config",
        observe_started_at=str(started or ""),
        observe_auto_promote_days=int(days) if days is not None else DEFAULT_PROMOTE_DAYS,
        observe_auto_promote_enabled=bool(enabled),
        defense_policy_locked=bool(locked),
        policy_user_set=bool(user_set),
    )
    for w in effective.get("warnings") or []:
        log(f"[DEFENSE-POLICY] hard-safety: {w}")

    verify_body = {
        "policy_name": effective["policy_name"],
        "policy_version": effective["policy_version"],
        "isolate_armed": effective["isolate_armed"],
        "rules": effective["rules"],
    }
    if cloud_sig:
        candidates = [
            {**verify_body, "sig": cloud_sig},
            {
                "policy_version": effective["policy_version"],
                "policy_name": effective["policy_name"],
                "rules": effective["rules"],
                "sig": cloud_sig,
            },
            {
                "defense_policy": effective["policy_name"],
                "defense_policy_version": effective["policy_version"],
                "defense_rules": effective["rules"],
                "isolate_armed": effective["isolate_armed"],
                "sig": cloud_sig,
            },
        ]
        ok = any(verify_payload(c, token=token) for c in candidates)
        if not ok:
            # Pre-cloud / foreign sig: do NOT fail-safe escalate; apply unsigned
            log(
                "[DEFENSE-POLICY] cloud defense sig verify failed — "
                "apply unsigned with hard-safety (no tamper escalate)"
            )
            effective["source"] = "threats/config_unsigned"
            cloud_sig = ""
        else:
            effective["source"] = "threats/config_signed"
    if not cloud_sig:
        effective["source"] = effective.get("source") or "threats/config_unsigned"

    saved = save_signed_cache(effective, promote_lkg=True)
    return _apply_state(effective, sig_ok=True, source=saved.get("source") or effective["source"])


def fail_safe_load(*, reason: str = "unknown") -> dict:
    """Tamper path: LKG if valid, else observe. Never isolate / never escalate."""
    _emit_tamper(reason)
    lkg = _read_json(POLICY_LKG_FILE)
    if lkg and verify_payload(lkg):
        effective = build_effective(
            policy_name=lkg.get("policy_name") or "observe",
            policy_version=lkg.get("policy_version") or "",
            rules=lkg.get("rules"),
            isolate_armed=False,
            source="tamper_lkg",
            observe_started_at=lkg.get("observe_started_at") or _utc_now(),
            observe_auto_promote_days=int(
                lkg.get("observe_auto_promote_days") or DEFAULT_PROMOTE_DAYS
            ),
            observe_auto_promote_enabled=bool(
                lkg.get("observe_auto_promote_enabled", True)
            ),
            defense_policy_locked=False,
            policy_user_set=False,
        )
        save_signed_cache(effective, promote_lkg=False)
        return _apply_state(effective, sig_ok=True, source="tamper_lkg")

    effective = build_effective(
        policy_name="observe",
        policy_version="",
        rules=PRESET_RULES["observe"],
        isolate_armed=False,
        source="tamper_observe",
        observe_started_at=_utc_now(),
    )
    save_signed_cache(effective, promote_lkg=False)
    return _apply_state(effective, sig_ok=False, source="tamper_observe")


def hydrate_from_disk() -> dict:
    """Boot: load signed cache or first-boot observe."""
    load_allowlist()
    data = _read_json(POLICY_FILE)
    if data:
        if verify_payload(data):
            effective = build_effective(
                policy_name=data.get("policy_name") or "observe",
                policy_version=data.get("policy_version") or "",
                rules=data.get("rules"),
                isolate_armed=bool(data.get("isolate_armed")),
                source="programdata",
                observe_started_at=data.get("observe_started_at") or "",
                observe_auto_promote_days=int(
                    data.get("observe_auto_promote_days") or DEFAULT_PROMOTE_DAYS
                ),
                observe_auto_promote_enabled=bool(
                    data.get("observe_auto_promote_enabled", True)
                ),
                defense_policy_locked=bool(data.get("defense_policy_locked")),
                policy_user_set=bool(data.get("policy_user_set")),
            )
            st = _apply_state(effective, sig_ok=True, source="programdata")
            if st.get("observe_started_at") and not data.get("observe_started_at"):
                effective["observe_started_at"] = st["observe_started_at"]
                save_signed_cache(effective, promote_lkg=False)
            return st
        # Token race / first-boot: structure OK but sig was made with empty token
        name = str(data.get("policy_name") or "").lower()
        if name in POLICY_NAMES and isinstance(data.get("rules"), dict):
            log("[DEFENSE-POLICY] cache sig mismatch — re-sign with current token")
            effective = build_effective(
                policy_name=name,
                policy_version=data.get("policy_version") or "",
                rules=data.get("rules"),
                isolate_armed=bool(data.get("isolate_armed")),
                source="programdata_resign",
                observe_started_at=data.get("observe_started_at") or _utc_now(),
                observe_auto_promote_days=int(
                    data.get("observe_auto_promote_days") or DEFAULT_PROMOTE_DAYS
                ),
                observe_auto_promote_enabled=bool(
                    data.get("observe_auto_promote_enabled", True)
                ),
                defense_policy_locked=bool(data.get("defense_policy_locked")),
                policy_user_set=bool(data.get("policy_user_set")),
            )
            save_signed_cache(effective, promote_lkg=False)
            return _apply_state(effective, sig_ok=True, source="programdata_resign")
        return fail_safe_load(reason="cache_sig_invalid")
    # First boot — observe defaults (contract 1.4.19)
    effective = build_effective(
        policy_name="observe",
        policy_version="",
        rules=PRESET_RULES["observe"],
        isolate_armed=False,
        source="builtin_observe",
        observe_started_at=_utc_now(),
        observe_auto_promote_days=DEFAULT_PROMOTE_DAYS,
        observe_auto_promote_enabled=True,
        defense_policy_locked=False,
        policy_user_set=False,
    )
    save_signed_cache(effective, promote_lkg=False)
    return _apply_state(effective, sig_ok=True, source="builtin_observe")


def process_action_plan(event_type: str) -> dict:
    """Convenience for RS/NG: what to do for this event."""
    act = action_for(event_type)
    st = get_state()
    return {
        "event": event_type,
        "action": act,
        "policy_name": st["policy_name"],
        "alert": True,
        "force_urgent": act in ("kill_quarantine", "suspend_process", "auto_isolate_network"),
        "contain": act in ("kill_quarantine", "suspend_process"),
        "kill": act == "kill_quarantine",
        "suspend": act == "suspend_process",
        "isolate_network": act == "auto_isolate_network" and allows_network_isolate(),
        "inform_only": act == "inform_only",
        "ask_operator": act == "ask_operator",
        "alert_only": act == "alert_only",
    }


def _parse_iso(ts: str) -> Optional[float]:
    if not ts:
        return None
    try:
        s = str(ts).strip().replace("Z", "+00:00")
        return datetime.fromisoformat(s).timestamp()
    except Exception:
        return None


def promote_due_info() -> dict:
    st = get_state()
    if st["policy_name"] != "observe":
        return {"due": False, "reason": "not_observe"}
    if st.get("defense_policy_locked"):
        return {"due": False, "reason": "locked"}
    if not st.get("observe_auto_promote_enabled", True):
        return {"due": False, "reason": "disabled"}
    days = int(st.get("observe_auto_promote_days") or 0)
    if days <= 0:
        return {"due": False, "reason": "days_zero"}
    started = _parse_iso(st.get("observe_started_at") or "")
    if started is None:
        return {"due": False, "reason": "no_start", "in_sec": None}
    deadline = started + (days * 86400)
    remaining = deadline - time.time()
    return {
        "due": remaining <= 0,
        "in_sec": max(0, int(remaining)),
        "days": days,
        "reason": "elapsed" if remaining <= 0 else "waiting",
    }


def set_observe_locked(locked: bool = True) -> dict:
    st = get_state()
    effective = build_effective(
        policy_name=st["policy_name"],
        policy_version=st.get("policy_version") or "",
        rules=st.get("rules"),
        isolate_armed=bool(st.get("isolate_armed")),
        source="user_lock",
        observe_started_at=st.get("observe_started_at") or _utc_now(),
        observe_auto_promote_days=int(
            st.get("observe_auto_promote_days") or DEFAULT_PROMOTE_DAYS
        ),
        observe_auto_promote_enabled=not locked if locked else st.get(
            "observe_auto_promote_enabled", True
        ),
        defense_policy_locked=bool(locked),
        policy_user_set=True,
    )
    if locked:
        effective["observe_auto_promote_enabled"] = False
    save_signed_cache(effective, promote_lkg=True)
    return _apply_state(effective, sig_ok=True, source="user_lock")


def set_policy_user(
    policy_name: str,
    *,
    isolate_armed: bool = False,
) -> dict:
    """Operator/GUI chose a preset explicitly."""
    name = str(policy_name or "observe").lower()
    if name not in POLICY_NAMES:
        name = "observe"
    st = get_state()
    effective = build_effective(
        policy_name=name,
        policy_version=st.get("policy_version") or "",
        rules=PRESET_RULES[name],
        isolate_armed=bool(isolate_armed) if name == "paranoid" else False,
        source="user_set",
        observe_started_at=(
            st.get("observe_started_at") or _utc_now()
            if name == "observe"
            else st.get("observe_started_at") or ""
        ),
        observe_auto_promote_days=int(
            st.get("observe_auto_promote_days") or DEFAULT_PROMOTE_DAYS
        ),
        observe_auto_promote_enabled=False if name != "observe" else st.get(
            "observe_auto_promote_enabled", True
        ),
        defense_policy_locked=bool(st.get("defense_policy_locked")),
        policy_user_set=True,
    )
    save_signed_cache(effective, promote_lkg=True)
    return _apply_state(effective, sig_ok=True, source="user_set")


def promote_to_balanced(*, source: str = "auto_promote") -> dict:
    """Observe → balanced only. Never paranoid / never isolate_armed."""
    st = get_state()
    if st["policy_name"] != "observe":
        return st
    effective = build_effective(
        policy_name="balanced",
        policy_version=st.get("policy_version") or "",
        rules=PRESET_RULES["balanced"],
        isolate_armed=False,
        source=source,
        observe_started_at=st.get("observe_started_at") or "",
        observe_auto_promote_days=int(
            st.get("observe_auto_promote_days") or DEFAULT_PROMOTE_DAYS
        ),
        observe_auto_promote_enabled=False,
        defense_policy_locked=False,
        policy_user_set=False,
    )
    save_signed_cache(effective, promote_lkg=True)
    st2 = _apply_state(effective, sig_ok=True, source=source)
    log(f"[DEFENSE-POLICY] promoted observe -> balanced ({source})")
    cb = _on_tamper_alert  # reuse alert pipeline callback
    if cb:
        try:
            cb({
                "event_type": "defense_policy_promoted",
                "threat_type": "defense_policy_promoted",
                "severity": "info",
                "threat_score": 10,
                "force_urgent": False,
                "title": "Savunma dengesi açıldı",
                "description": (
                    "İzleme süresi doldu — Denge moduna geçildi. "
                    "Kırmızı tehditlerde süreç korunur; ağ kesilmez."
                ),
                "recommended_action": "none",
                "auto_response_taken": ["auto_promote_balanced"],
                "details": {"from": "observe", "to": "balanced", "source": source},
            })
        except Exception:
            pass
    return st2


def maybe_auto_promote() -> Optional[dict]:
    """If observe window elapsed, promote to balanced. Returns new state or None."""
    info = promote_due_info()
    if not info.get("due"):
        return None
    return promote_to_balanced(source="client_auto_promote")


def cloud_promote_patch() -> dict:
    """Body for POST /api/threats/config when client backups cloud job."""
    return {
        "protection": {
            "defense_policy": "balanced",
            "isolate_armed": False,
            "observe_auto_promote_enabled": False,
            "defense_rules": dict(PRESET_RULES["balanced"]),
        }
    }
