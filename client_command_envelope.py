#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Command envelope v2 — observe-only parse/verify (contract api/12, ≥1.4.37).

Normative schema is locked. Production wire remains v1 HMAC (``asteria-chp-v1``).

This module:
- canonicalizes with RFC 8785 JCS over the envelope **excluding** ``signature``;
- may Ed25519-verify when a public key is supplied (observe / CI fixtures);
- **must not** emit ``version:2`` and **must not** hard-fail v1 commands.

``caps.command_envelope_v2`` is ``off`` | ``observe`` only — never ``enforce``.
"""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Mapping, Optional, Union

# Capability values: "off" (default), "observe" (classify/verify log only).
CAPABILITY_OFF = "off"
CAPABILITY_OBSERVE = "observe"

ENVELOPE_VERSION = 2

# CI-only fixture seed from api/12 (never production keys).
FIXTURE_SEED_HEX = (
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
)

_REQUIRED_FIELDS = (
    "version",
    "tenant_id",
    "device_id",
    "command_id",
    "command_type",
    "params_hash",
    "issued_at",
    "expires_at",
    "nonce",
    "signature",
)


def capability() -> str:
    """Truthful capability; ``off`` unless config opts into observe.

    Config: ``security.command_envelope_v2`` in {"off","observe"} (default off).
    ``enforce`` is never advertised — emit/enforce stay gated by PROMOTION_GATES.
    """
    try:
        from client_utils import get_from_config
        val = str(get_from_config("security.command_envelope_v2", "off")).lower()
    except Exception:
        val = "off"
    return CAPABILITY_OBSERVE if val == "observe" else CAPABILITY_OFF


def jcs_bytes(obj: Any) -> bytes:
    """RFC 8785 JCS (canonical JSON) as UTF-8 bytes.

    For the envelope/params shapes we use (objects, strings, ints, empty
    arrays) ``json.dumps(sort_keys=True, separators=(',', ':'),
    ensure_ascii=False)`` matches JCS. Floats/exotic Unicode are out of
    scope for current fixtures.
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


# Back-compat alias used by older tests / callers.
canonical_bytes = jcs_bytes


def params_hash(params: Optional[Mapping[str, Any]]) -> str:
    """``sha256:<lowercase-hex>`` over JCS(params) or JCS({})."""
    digest = hashlib.sha256(jcs_bytes(params or {})).hexdigest()
    return f"sha256:{digest}"


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64url_decode(text: str) -> bytes:
    pad = "=" * ((4 - (len(text) % 4)) % 4)
    return base64.urlsafe_b64decode(str(text) + pad)


def _parse_iso(value: str) -> Optional[datetime]:
    if not value:
        return None
    try:
        txt = str(value).strip().replace("Z", "+00:00")
        dt = datetime.fromisoformat(txt)
    except Exception:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def signable_body(envelope: Mapping[str, Any]) -> dict:
    """Envelope object excluding ``signature`` (signing input)."""
    return {k: v for k, v in dict(envelope).items() if k != "signature"}


def observe_verify_ed25519(
    envelope: Mapping[str, Any],
    public_key: Union[bytes, Any],
) -> bool:
    """Observe-only Ed25519 verify of ``signature`` over JCS(signable body).

    Returns True on valid signature. Never used to accept/reject production
    commands (verify_enabled / enforce remain false).
    """
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )
    except Exception:
        return False
    sig_b64 = str(envelope.get("signature") or "")
    if not sig_b64:
        return False
    try:
        sig = _b64url_decode(sig_b64)
        body = jcs_bytes(signable_body(envelope))
        if isinstance(public_key, Ed25519PublicKey):
            pub = public_key
        else:
            pub = Ed25519PublicKey.from_public_bytes(bytes(public_key))
        pub.verify(sig, body)
        return True
    except Exception:
        return False


def fixture_keypair():
    """Return (private_key, public_raw_32) for api/12 CI seed."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )
    from cryptography.hazmat.primitives import serialization

    seed = bytes.fromhex(FIXTURE_SEED_HEX)
    priv = Ed25519PrivateKey.from_private_bytes(seed)
    pub = priv.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return priv, pub


def fixture_sign(envelope_without_sig: Mapping[str, Any]) -> str:
    """Sign minimal envelope with fixture seed; returns base64url signature."""
    priv, _ = fixture_keypair()
    sig = priv.sign(jcs_bytes(dict(envelope_without_sig)))
    return _b64url_encode(sig)


def inspect_envelope_v2(
    envelope: Mapping[str, Any],
    *,
    params: Optional[Mapping[str, Any]] = None,
    now: Optional[datetime] = None,
    public_key: Optional[Union[bytes, Any]] = None,
) -> dict:
    """Classify a candidate v2 envelope for observe telemetry (no enforce).

    Verdicts (never used alone to hard-fail v1 production commands):
    - ``not_v2`` / ``malformed`` / ``expired`` / ``params_mismatch``
    - ``sig_invalid`` — key present but signature fails
    - ``unverified_no_key`` — structurally ok, no key to verify
    - ``sig_ok`` — structurally ok + Ed25519 verified (observe only)
    """
    result = {
        "verdict": "not_v2",
        "has_signature": bool(envelope.get("signature")),
        "expired": None,
        "params_match": None,
        "sig_ok": None,
        "error_code": None,
    }
    if not isinstance(envelope, Mapping):
        result["verdict"] = "malformed"
        result["error_code"] = "envelope_version_unsupported"
        return result
    try:
        ver = int(envelope.get("version", 0) or 0)
    except (TypeError, ValueError):
        ver = 0
    if ver != ENVELOPE_VERSION:
        result["verdict"] = "not_v2"
        result["error_code"] = "envelope_version_unsupported"
        return result

    for field in _REQUIRED_FIELDS:
        if field not in envelope or envelope.get(field) in (None, ""):
            result["verdict"] = "malformed"
            result["error_code"] = "envelope_version_unsupported"
            return result

    expires = _parse_iso(str(envelope.get("expires_at", "")))
    ref = now or datetime.now(timezone.utc)
    if expires is not None:
        result["expired"] = ref > expires
        if result["expired"]:
            result["verdict"] = "expired"
            result["error_code"] = "envelope_expired"
            return result

    if params is not None:
        expected = params_hash(params)
        result["params_match"] = expected == str(envelope.get("params_hash"))
        if not result["params_match"]:
            result["verdict"] = "params_mismatch"
            result["error_code"] = "envelope_params_mismatch"
            return result

    if public_key is not None:
        ok = observe_verify_ed25519(envelope, public_key)
        result["sig_ok"] = ok
        if not ok:
            result["verdict"] = "sig_invalid"
            result["error_code"] = "envelope_sig_invalid"
            return result
        result["verdict"] = "sig_ok"
        return result

    result["verdict"] = "unverified_no_key"
    return result


def observe_command(
    cmd: Mapping[str, Any],
    *,
    public_key: Optional[Union[bytes, Any]] = None,
) -> Optional[dict]:
    """If command carries a v2 envelope, classify it for logs. Else None.

    Looks for top-level ``version:2`` or nested ``envelope`` / ``command_envelope``.
    """
    if capability() != CAPABILITY_OBSERVE:
        return None
    env = None
    if int(cmd.get("version", 0) or 0) == ENVELOPE_VERSION:
        env = cmd
    else:
        for key in ("envelope", "command_envelope", "envelope_v2"):
            cand = cmd.get(key)
            if isinstance(cand, Mapping) and int(cand.get("version", 0) or 0) == 2:
                env = cand
                break
    if env is None:
        return None
    params = cmd.get("params") if isinstance(cmd.get("params"), Mapping) else None
    if params is None and isinstance(cmd.get("payload"), Mapping):
        params = cmd.get("payload")
    return inspect_envelope_v2(env, params=params, public_key=public_key)
