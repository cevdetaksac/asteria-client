"""Signed operator stop token (contract ≥4.6.0 — agent/persistence-and-tamper.md).

When the user enters the correct PIN and chooses Exit, a signed
`operator_stop.json` is written. Motor + Guardian honour this token and
stand down (no resurrection) until the token is cleared manually.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from datetime import datetime, timezone

try:
    from client_constants import MACHINE_DATA_DIR, TOKEN_FILE
except Exception:
    MACHINE_DATA_DIR = os.path.join(
        os.environ.get("ProgramData", r"C:\ProgramData"),
        "Asteria",
    )
    TOKEN_FILE = os.path.join(MACHINE_DATA_DIR, "token.dat")

OPERATOR_STOP_FILE = os.path.join(MACHINE_DATA_DIR, "operator_stop.json")


def _read_token() -> str:
    try:
        with open(TOKEN_FILE, "r", encoding="utf-8") as f:
            return (f.read() or "").strip()
    except Exception:
        return ""


def _signing_secret(token: str, context: str = "asteria-chp-v1") -> bytes:
    machine = os.environ.get("COMPUTERNAME", "unknown")
    material = f"{token}|{machine}|{context}"
    return hashlib.sha256(material.encode("utf-8")).digest()


def sign_operator_stop(token: str, issued_at: str, host: str) -> str:
    msg = f"operator_pin|{issued_at}|{host}".encode("utf-8")
    return hmac.new(_signing_secret(token), msg, hashlib.sha256).hexdigest()


def verify_operator_stop(payload: dict) -> bool:
    if not isinstance(payload, dict):
        return False
    if not payload.get("pin_verified"):
        return False
    token = _read_token()
    if not token:
        return False
    issued_at = str(payload.get("issued_at") or "")
    host = str(payload.get("host") or "")
    sig = str(payload.get("sig") or "")
    if not issued_at or not sig:
        return False
    msg = f"operator_pin|{issued_at}|{host}".encode("utf-8")
    for context in ("asteria-chp-v1", "yesnext-chp-v1"):
        expected = hmac.new(
            _signing_secret(token, context), msg, hashlib.sha256
        ).hexdigest()
        if hmac.compare_digest(sig, expected):
            return True
    return False


def arm_operator_stop() -> bool:
    """Write signed operator_stop.json after PIN verification."""
    token = _read_token()
    if not token:
        return False
    host = os.environ.get("COMPUTERNAME", "")
    issued_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    payload = {
        "reason": "operator_pin",
        "pin_verified": True,
        "issued_at": issued_at,
        "host": host,
        "sig": sign_operator_stop(token, issued_at, host),
    }
    try:
        os.makedirs(MACHINE_DATA_DIR, exist_ok=True)
        with open(OPERATOR_STOP_FILE, "w", encoding="utf-8") as f:
            json.dump(payload, f)
        return True
    except Exception:
        return False


def clear_operator_stop() -> None:
    try:
        if os.path.exists(OPERATOR_STOP_FILE):
            os.remove(OPERATOR_STOP_FILE)
    except Exception:
        pass


def is_operator_stop_active() -> bool:
    try:
        if not os.path.exists(OPERATOR_STOP_FILE):
            return False
        with open(OPERATOR_STOP_FILE, "r", encoding="utf-8") as f:
            payload = json.load(f)
        return verify_operator_stop(payload)
    except Exception:
        return False


def read_operator_stop_payload() -> dict:
    try:
        if not os.path.exists(OPERATOR_STOP_FILE):
            return {}
        with open(OPERATOR_STOP_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}
