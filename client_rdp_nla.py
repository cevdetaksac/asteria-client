#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""RDP NLA / CredSSP — NetNTLMv2 hash capture (no plaintext password).

Flow after X.224 selected PROTOCOL_HYBRID:
  TCP → TLS (self-signed) → CredSSP TSRequest ↔ NTLMSSP Type1/2/3
  → report hashcat-mode-5600 / John netntlmv2 string.

No Windows SSPI — we never authenticate against real accounts.
Stdlib + cryptography (ephemeral cert). ASN.1 TSRequest is hand-built (MS-CSSP).
"""

from __future__ import annotations

import os
import ssl
import struct
import tempfile
import threading
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

# NTLMSSP message types
_NTLM_NEGOTIATE = 1
_NTLM_CHALLENGE = 2
_NTLM_AUTHENTICATE = 3

_NTLMSSP_SIG = b"NTLMSSP\x00"

# CredSSP / RDP negotiation
PROTOCOL_HYBRID = 0x00000002
PROTOCOL_HYBRID_EX = 0x00000008

MAX_TSREQUEST_LEN = 65536

_cert_lock = threading.Lock()
_cert_cache: dict = {}  # cn -> (cert_path, key_path)


def wants_nla(requested_protocols: int) -> bool:
    return bool(requested_protocols & (PROTOCOL_HYBRID | PROTOCOL_HYBRID_EX))


def selected_nla_protocol(requested_protocols: int) -> int:
    """Prefer HYBRID_EX when client offers it, else HYBRID."""
    if requested_protocols & PROTOCOL_HYBRID_EX:
        return PROTOCOL_HYBRID_EX
    return PROTOCOL_HYBRID


# -------------------- DER helpers -------------------- #

def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    if n < 0x100:
        return bytes([0x81, n])
    if n < 0x10000:
        return bytes([0x82, (n >> 8) & 0xFF, n & 0xFF])
    raise ValueError("DER length too large")


def _read_der_len(buf: bytes, off: int) -> Tuple[int, int]:
    if off >= len(buf):
        return 0, off
    first = buf[off]
    off += 1
    if first < 0x80:
        return first, off
    n = first & 0x7F
    if n == 0 or off + n > len(buf):
        return 0, off
    val = int.from_bytes(buf[off : off + n], "big")
    return val, off + n


def find_ntlmssp(blob: bytes) -> int:
    return blob.find(_NTLMSSP_SIG)


def ntlm_message_type(blob: bytes, offset: int = 0) -> int:
    if offset < 0 or offset + 12 > len(blob):
        return 0
    if blob[offset : offset + 8] != _NTLMSSP_SIG:
        return 0
    return struct.unpack_from("<I", blob, offset + 8)[0]


# -------------------- NTLMSSP -------------------- #

def build_ntlmssp_type2(challenge: bytes, target_name: str = "WORKGROUP") -> bytes:
    """Minimal CHALLENGE_MESSAGE (MS-NLMP). challenge must be 8 bytes."""
    if len(challenge) != 8:
        raise ValueError("NTLM challenge must be 8 bytes")
    target = target_name.encode("utf-16-le")
    av_name = target_name.encode("utf-16-le")
    # AvId NbDomainName=2 or NbComputerName=1 — use Domain (2)
    target_info = struct.pack("<HH", 2, len(av_name)) + av_name + struct.pack("<HH", 0, 0)
    # UNICODE | NTLM | TARGET_INFO | ALWAYS_SIGN | TARGET_TYPE_DOMAIN | 128 | 56
    flags = 0xE2888215
    target_off = 56
    info_off = target_off + len(target)
    return (
        _NTLMSSP_SIG
        + struct.pack("<I", _NTLM_CHALLENGE)
        + struct.pack("<HHI", len(target), len(target), target_off)
        + struct.pack("<I", flags)
        + challenge
        + b"\x00" * 8
        + struct.pack("<HHI", len(target_info), len(target_info), info_off)
        + b"\x00" * 8
        + target
        + target_info
    )


def _read_ntlm_field(buf: bytes, offset: int) -> bytes:
    """Read a security buffer (len, maxLen, offset) from NTLM message header."""
    if offset + 8 > len(buf):
        return b""
    length, _maxlen, field_off = struct.unpack_from("<HHI", buf, offset)
    if field_off + length > len(buf) or length < 0:
        return b""
    return buf[field_off : field_off + length]


def parse_ntlmssp_type3(blob: bytes, server_challenge: bytes) -> Optional[dict]:
    """Parse AUTHENTICATE_MESSAGE → NetNTLMv1/v2 hash fields.

    Returns dict with keys: username, domain, workstation, hash_line, kind
    hash_line is hashcat 5600 (v2) or 5500-style (v1) string.
    """
    idx = find_ntlmssp(blob)
    if idx < 0:
        return None
    msg = blob[idx:]
    if ntlm_message_type(msg) != _NTLM_AUTHENTICATE:
        return None
    if len(msg) < 64:
        return None

    lm_resp = _read_ntlm_field(msg, 12)
    nt_resp = _read_ntlm_field(msg, 20)
    domain_raw = _read_ntlm_field(msg, 28)
    user_raw = _read_ntlm_field(msg, 36)
    workstation_raw = _read_ntlm_field(msg, 44)

    def _utf16(b: bytes) -> str:
        try:
            return b.decode("utf-16-le", errors="replace").strip("\x00")
        except Exception:
            return ""

    username = _utf16(user_raw)
    domain = _utf16(domain_raw)
    workstation = _utf16(workstation_raw)
    if not username:
        return None
    if len(server_challenge) != 8:
        return None

    chal_hex = server_challenge.hex()

    if len(nt_resp) == 24:
        # NTLMv1: LM + NT responses (24 each typically)
        kind = "netntlmv1"
        hash_line = (
            f"{username}::{domain}:{lm_resp.hex()}:{nt_resp.hex()}:{chal_hex}"
        )
    elif len(nt_resp) >= 16:
        # NTLMv2: 16-byte NTProofStr + client blob
        kind = "netntlmv2"
        nt_proof = nt_resp[:16].hex()
        blob_hex = nt_resp[16:].hex()
        hash_line = f"{username}::{domain}:{chal_hex}:{nt_proof}:{blob_hex}"
    else:
        return None

    return {
        "username": username,
        "domain": domain,
        "workstation": workstation,
        "kind": kind,
        "hash_line": hash_line,
    }


# -------------------- CredSSP TSRequest -------------------- #

def build_tsrequest_with_token(version: int, ntlm_blob: bytes) -> bytes:
    """CredSSP TSRequest with one negoToken (MS-CSSP §2.2.1)."""
    version_bytes = version.to_bytes(1, "big") if version < 256 else version.to_bytes(2, "big")
    version_field = b"\x02" + _der_len(len(version_bytes)) + version_bytes
    version_tagged = b"\xa0" + _der_len(len(version_field)) + version_field

    octet = b"\x04" + _der_len(len(ntlm_blob)) + ntlm_blob
    negotoken_tagged = b"\xa0" + _der_len(len(octet)) + octet
    inner_seq = b"\x30" + _der_len(len(negotoken_tagged)) + negotoken_tagged
    outer_seq = b"\x30" + _der_len(len(inner_seq)) + inner_seq
    negotokens_tagged = b"\xa1" + _der_len(len(outer_seq)) + outer_seq

    body = version_tagged + negotokens_tagged
    return b"\x30" + _der_len(len(body)) + body


def parse_tsrequest_version(blob: bytes) -> int:
    """Best-effort CredSSP version (default 6)."""
    try:
        if not blob or blob[0] != 0x30:
            return 6
        # Look for INTEGER after context tag a0
        idx = blob.find(b"\xa0")
        if idx < 0:
            return 6
        # naive: find 0x02 near start of version field
        for i in range(idx, min(idx + 16, len(blob) - 2)):
            if blob[i] == 0x02:
                ln = blob[i + 1]
                if ln == 1:
                    return blob[i + 2]
                if ln == 2:
                    return int.from_bytes(blob[i + 2 : i + 4], "big")
    except Exception:
        pass
    return 6


def read_one_tsrequest(sock, *, max_len: int = MAX_TSREQUEST_LEN) -> bytes:
    """Read one DER SEQUENCE (TSRequest) from a (TLS) socket."""
    tag = _recv_exact(sock, 1)
    if not tag or tag != b"\x30":
        return b""
    first = _recv_exact(sock, 1)
    if not first:
        return b""
    lb = first[0]
    if lb < 0x80:
        length = lb
        header = tag + first
    else:
        n = lb & 0x7F
        if n == 0 or n > 3:
            return b""
        rest = _recv_exact(sock, n)
        if len(rest) != n:
            return b""
        length = int.from_bytes(rest, "big")
        header = tag + first + rest
    if length <= 0 or length > max_len:
        return b""
    body = _recv_exact(sock, length)
    if len(body) != length:
        return b""
    return header + body


def _recv_exact(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


# -------------------- TLS cert -------------------- #

def ensure_tls_cert_files(cert_cn: str = "WIN-HONEYPOT") -> Tuple[str, str]:
    """Create (or reuse) a self-signed cert for CredSSP TLS. Returns (cert, key) paths."""
    cn = (cert_cn or "WIN-HONEYPOT").strip() or "WIN-HONEYPOT"
    with _cert_lock:
        cached = _cert_cache.get(cn)
        if cached and all(os.path.isfile(p) for p in cached):
            return cached

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "YesNext Honeypot"),
        ])
        now = datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(key, hashes.SHA256())
        )

        base = os.path.join(
            os.environ.get("ProgramData", r"C:\ProgramData"),
            "Asteria",
            "rdp_nla",
        )
        try:
            os.makedirs(base, exist_ok=True)
        except OSError:
            base = tempfile.gettempdir()

        cert_path = os.path.join(base, f"{cn}.crt")
        key_path = os.path.join(base, f"{cn}.key")
        with open(cert_path, "wb") as fh:
            fh.write(cert.public_bytes(serialization.Encoding.PEM))
        with open(key_path, "wb") as fh:
            fh.write(
                key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
        _cert_cache[cn] = (cert_path, key_path)
        return cert_path, key_path


def wrap_socket_tls_server(sock, cert_cn: str = "WIN-HONEYPOT"):
    """Upgrade connected TCP socket to TLS server side for CredSSP."""
    cert_path, key_path = ensure_tls_cert_files(cert_cn)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1
    except Exception:
        pass
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # Some RDP clients use weak ciphers; keep broad set
    try:
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    except Exception:
        try:
            ctx.set_ciphers("DEFAULT")
        except Exception:
            pass
    ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
    return ctx.wrap_socket(sock, server_side=True, do_handshake_on_connect=True)


def run_credssp_ntlm_capture(tls_sock, *, target_name: str = "WORKGROUP") -> Optional[dict]:
    """Drive CredSSP until NTLM Type3; return parse_ntlmssp_type3 result or None."""
    challenge = os.urandom(8)
    type2 = build_ntlmssp_type2(challenge, target_name=target_name)

    # Up to a few TSRequest round-trips (Type1 → Type2 → Type3)
    for _ in range(4):
        req = read_one_tsrequest(tls_sock)
        if not req:
            return None
        idx = find_ntlmssp(req)
        if idx < 0:
            continue
        mtype = ntlm_message_type(req, idx)
        version = parse_tsrequest_version(req)

        if mtype == _NTLM_NEGOTIATE:
            resp = build_tsrequest_with_token(version, type2)
            tls_sock.sendall(resp)
            continue

        if mtype == _NTLM_AUTHENTICATE:
            return parse_ntlmssp_type3(req[idx:], challenge)

    return None
