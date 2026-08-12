#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Persistent interactive-session bridge for remote desktop capture and input.

The SYSTEM daemon owns a loopback listener and launches exactly one helper in
the selected WTS session.  A random capability authenticates the connection;
all subsequent messages are length framed and HMAC authenticated.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import socket
import struct
import threading
import time
from typing import Callable, Optional, Tuple


MAX_HEADER = 64 * 1024
# Raw RGB @ 1280×720 ≈ 2.7 MB; allow 1080p headroom over loopback.
MAX_PAYLOAD = 8 * 1024 * 1024
_PREFIX = struct.Struct("!4sBIIQ")
_MAGIC = b"RDH1"
_MAC_SIZE = hashlib.sha256().digest_size


class ProtocolError(Exception):
    pass


def _read_exact(sock, size: int) -> bytes:
    chunks = []
    remaining = size
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise EOFError("helper connection closed")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


class SecureFramedSocket:
    """Small binary framing layer with ordered HMAC authentication."""

    def __init__(self, sock, secret: bytes):
        if len(secret) < 32:
            raise ValueError("helper secret must contain at least 32 bytes")
        self.sock = sock
        self.secret = secret
        self._send_seq = 0
        self._recv_seq = 0
        self._send_lock = threading.Lock()

    def send(self, kind: str, header: Optional[dict] = None, payload: bytes = b"") -> None:
        kind_b = kind.encode("ascii")
        if len(kind_b) != 1:
            raise ValueError("message kind must be one ASCII character")
        header_b = json.dumps(
            header or {}, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        payload = bytes(payload or b"")
        if len(header_b) > MAX_HEADER or len(payload) > MAX_PAYLOAD:
            raise ValueError("helper message too large")
        with self._send_lock:
            seq = self._send_seq
            prefix = _PREFIX.pack(_MAGIC, kind_b[0], len(header_b), len(payload), seq)
            mac = hmac.new(self.secret, prefix + header_b + payload, hashlib.sha256).digest()
            self.sock.sendall(prefix + header_b + payload + mac)
            self._send_seq += 1

    def recv(self) -> Tuple[str, dict, bytes]:
        prefix = _read_exact(self.sock, _PREFIX.size)
        magic, kind_i, header_len, payload_len, seq = _PREFIX.unpack(prefix)
        if magic != _MAGIC:
            raise ProtocolError("invalid helper protocol magic")
        if header_len > MAX_HEADER or payload_len > MAX_PAYLOAD:
            raise ProtocolError("helper message exceeds limits")
        if seq != self._recv_seq:
            raise ProtocolError("out-of-order helper message")
        body = _read_exact(self.sock, header_len + payload_len)
        supplied_mac = _read_exact(self.sock, _MAC_SIZE)
        expected_mac = hmac.new(self.secret, prefix + body, hashlib.sha256).digest()
        if not hmac.compare_digest(supplied_mac, expected_mac):
            raise ProtocolError("invalid helper message authentication")
        self._recv_seq += 1
        header_b = body[:header_len]
        payload = body[header_len:]
        try:
            header = json.loads(header_b.decode("utf-8")) if header_b else {}
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ProtocolError("invalid helper JSON header") from exc
        if not isinstance(header, dict):
            raise ProtocolError("helper header must be an object")
        return chr(kind_i), header, payload

    def close(self) -> None:
        # Half-close the write side first so any buffered final frame (e.g. the
        # "S"top message) is delivered before the peer sees EOF, instead of an
        # abrupt RST that can abort the peer's in-flight recv.
        try:
            self.sock.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass


class PersistentSessionHelper:
    """Daemon-side lifecycle and mailbox for one target-session helper."""

    def __init__(
        self,
        session_id: int,
        launch: Callable[[int, str], bool],
        command_builder: Callable[[str, int, str], str],
        log: Callable[[str], None],
    ):
        self.session_id = int(session_id)
        self._launch = launch
        self._command_builder = command_builder
        self._log = log
        self._listener = None
        self._channel: Optional[SecureFramedSocket] = None
        self._reader = None
        self._stop = threading.Event()
        self._condition = threading.Condition()
        self._latest = None
        self._frame_id = 0
        self._pending = {}
        self._request_id = 0
        self._error = ""
        self._config = {}

    @property
    def connected(self) -> bool:
        return self._channel is not None and not self._stop.is_set()

    @property
    def error(self) -> str:
        return self._error

    def start(self, config: dict, timeout: float = 12.0) -> bool:
        self.stop()
        self._stop.clear()
        self._error = ""
        self._config = dict(config)
        with self._condition:
            self._latest = None
            self._frame_id = 0
            self._pending.clear()
        secret = os.urandom(32)
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        accept_timeout = max(0.2, float(timeout))
        listener.settimeout(accept_timeout)
        self._listener = listener
        port = int(listener.getsockname()[1])
        command = self._command_builder(secret.hex(), port, json.dumps(config, separators=(",", ":")))
        launch_t0 = time.monotonic()
        if not self._launch(self.session_id, command):
            self._error = "CreateProcessAsUser failed"
            self.stop()
            return False
        try:
            raw, address = listener.accept()
            accept_ms = int((time.monotonic() - launch_t0) * 1000)
            if address[0] not in ("127.0.0.1", "::1"):
                raw.close()
                raise ProtocolError("non-loopback helper peer")
            raw.settimeout(max(0.5, float(timeout)))
            channel = SecureFramedSocket(raw, secret)
            kind, hello, _ = channel.recv()
            if kind != "H" or int(hello.get("session_id", -1)) != self.session_id:
                channel.close()
                raise ProtocolError("helper identity mismatch")
            channel.send("C", config)
            raw.settimeout(None)
            self._channel = channel
            self._reader = threading.Thread(
                target=self._read_loop, name=f"RDHelperReader-{self.session_id}", daemon=True
            )
            self._reader.start()
            self._log(
                f"[REMOTE-DESKTOP] helper hello ok session={self.session_id} "
                f"accept_ms={accept_ms}"
            )
            return True
        except socket.timeout:
            self._error = (
                f"helper_accept_timeout after {accept_timeout:.1f}s "
                f"(spawn→connect never completed)"
            )
            self.stop()
            return False
        except Exception as exc:
            self._error = str(exc)
            self.stop()
            return False
        finally:
            try:
                listener.close()
            except OSError:
                pass
            self._listener = None

    def wait_frame(self, after_id: int = 0, timeout: float = 2.0):
        deadline = time.monotonic() + max(0.0, timeout)
        with self._condition:
            while self._frame_id <= after_id and self.connected:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                self._condition.wait(remaining)
            if self._frame_id <= after_id or self._latest is None:
                return None
            return (self._frame_id,) + self._latest

    def send_input(self, event: dict, timeout: float = 0.08, wait: bool = False) -> bool:
        """Forward an input event to the helper. True when delivered/acked ok."""
        result = self.send_input_result(event, timeout=timeout, wait=wait)
        return bool(result.get("ok"))

    def send_input_result(
        self, event: dict, timeout: float = 0.08, wait: bool = False
    ) -> dict:
        """Forward input; return ACK fields (inputs_applied / last_input_event).

        wait=False (moves): fire-and-forget.
        wait=True (critical): wait for ACK; on timeout assume queued if pipe live.
        """
        channel = self._channel
        if channel is None:
            return {"ok": False, "detail": "helper_not_connected"}
        if not wait:
            try:
                channel.send("I", {"id": 0, "event": event})
                return {"ok": True, "detail": "fire_and_forget"}
            except Exception as exc:
                self._error = str(exc)
                return {"ok": False, "detail": str(exc)}
        with self._condition:
            self._request_id += 1
            request_id = self._request_id
            self._pending[request_id] = None
        try:
            channel.send("I", {"id": request_id, "event": event})
        except Exception as exc:
            self._error = str(exc)
            with self._condition:
                self._pending.pop(request_id, None)
            return {"ok": False, "detail": str(exc)}
        deadline = time.monotonic() + max(0.0, timeout)
        with self._condition:
            while self._pending.get(request_id) is None and self.connected:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                self._condition.wait(remaining)
            acked = self._pending.pop(request_id, None)
        if acked is None:
            return {
                "ok": True,
                "detail": "ack_timeout_assumed_queued",
                "inputs_applied": 0,
                "last_input_event": "",
            }
        if isinstance(acked, dict):
            return {
                "ok": bool(acked.get("ok")),
                "detail": str(acked.get("detail") or ""),
                "event": str(acked.get("event") or ""),
                "inputs_applied": int(acked.get("inputs_applied") or 0),
                "last_input_event": str(acked.get("last_input_event") or ""),
            }
        return {"ok": bool(acked), "detail": ""}

    def send_sas(self, timeout: float = 4.0) -> dict:
        """Ask the in-session helper to call SendSAS + report UI effect (C-RD-CAD-*)."""
        channel = self._channel
        if channel is None:
            return {"ok": False, "detail": "helper_not_connected", "path": "helper"}
        with self._condition:
            self._request_id += 1
            request_id = self._request_id
            self._pending[request_id] = None
        try:
            channel.send("D", {"id": request_id, "action": "sas"})
        except Exception as exc:
            self._error = str(exc)
            with self._condition:
                self._pending.pop(request_id, None)
            return {"ok": False, "detail": str(exc), "path": "helper"}
        deadline = time.monotonic() + max(0.5, float(timeout))
        with self._condition:
            while self._pending.get(request_id) is None and self.connected:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                self._condition.wait(remaining)
            acked = self._pending.pop(request_id, None)
        if not isinstance(acked, dict):
            return {"ok": False, "detail": "sas_ack_timeout", "path": "helper"}
        return {
            "ok": bool(acked.get("ok")),
            "effect": bool(acked.get("effect")),
            "detail": str(acked.get("detail") or ""),
            "ui_before": str(acked.get("ui_before") or ""),
            "ui_after": str(acked.get("ui_after") or ""),
            "as_user": bool(acked.get("as_user")),
            "flat": bool(acked.get("flat")),
            "chrome_detected": bool(acked.get("chrome_detected")),
            "frame_variance": float(acked.get("frame_variance") or 0.0),
            "path": "helper",
        }

    def query_ui_state(self, timeout: float = 2.0) -> dict:
        """Sample secure-attention UI on the helper's attached desktop."""
        channel = self._channel
        if channel is None:
            return {"ok": False, "detail": "helper_not_connected"}
        with self._condition:
            self._request_id += 1
            request_id = self._request_id
            self._pending[request_id] = None
        try:
            channel.send("D", {"id": request_id, "action": "ui"})
        except Exception as exc:
            self._error = str(exc)
            with self._condition:
                self._pending.pop(request_id, None)
            return {"ok": False, "detail": str(exc)}
        deadline = time.monotonic() + max(0.3, float(timeout))
        with self._condition:
            while self._pending.get(request_id) is None and self.connected:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                self._condition.wait(remaining)
            acked = self._pending.pop(request_id, None)
        if not isinstance(acked, dict):
            return {"ok": False, "detail": "ui_ack_timeout"}
        return {
            "ok": bool(acked.get("ok")),
            "ui": str(acked.get("ui") or acked.get("ui_after") or "unknown"),
            "fp": str(acked.get("fp") or ""),
            "flat": bool(acked.get("flat")),
            "chrome_detected": bool(acked.get("chrome_detected")),
            "frame_variance": float(acked.get("frame_variance") or 0.0),
            "detail": str(acked.get("detail") or ""),
        }

    def force_desktop_reattach(self, timeout: float = 2.5) -> dict:
        """C-RD-CHROME-4: ask helper to rebind Winlogon and sample chrome."""
        channel = self._channel
        if channel is None:
            return {"ok": False, "detail": "helper_not_connected"}
        with self._condition:
            self._request_id += 1
            request_id = self._request_id
            self._pending[request_id] = None
        try:
            channel.send("D", {"id": request_id, "action": "reattach"})
        except Exception as exc:
            self._error = str(exc)
            with self._condition:
                self._pending.pop(request_id, None)
            return {"ok": False, "detail": str(exc)}
        deadline = time.monotonic() + max(0.5, float(timeout))
        with self._condition:
            while self._pending.get(request_id) is None and self.connected:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                self._condition.wait(remaining)
            acked = self._pending.pop(request_id, None)
        if not isinstance(acked, dict):
            return {"ok": False, "detail": "reattach_ack_timeout"}
        return {
            "ok": bool(acked.get("ok")),
            "ui": str(acked.get("ui") or acked.get("ui_after") or "unknown"),
            "flat": bool(acked.get("flat")),
            "chrome_detected": bool(acked.get("chrome_detected")),
            "frame_variance": float(acked.get("frame_variance") or 0.0),
            "detail": str(acked.get("detail") or ""),
        }

    def update_config(self, config: dict) -> bool:
        channel = self._channel
        if channel is None:
            return False
        try:
            self._config.update(config)
            channel.send("C", dict(self._config))
            return True
        except Exception as exc:
            self._error = str(exc)
            return False

    def _read_loop(self) -> None:
        channel = self._channel
        try:
            while not self._stop.is_set() and channel is not None:
                kind, header, payload = channel.recv()
                with self._condition:
                    if kind in ("F", "R"):
                        self._frame_id += 1
                        # R = raw RGB for WebRTC; F = JPEG fallback.
                        if kind == "R" and isinstance(header, dict):
                            header = dict(header)
                            header.setdefault("format", "rgb")
                        self._latest = (payload, header)
                    elif kind == "A":
                        rid = int(header.get("id", 0))
                        # Store full ACK header (ok/detail) for SAS + input.
                        self._pending[rid] = header if isinstance(header, dict) else {
                            "ok": bool(header)
                        }
                    elif kind == "E":
                        self._error = str(header.get("error") or "helper error")
                    self._condition.notify_all()
        except Exception as exc:
            if not self._stop.is_set():
                self._error = str(exc)
                self._log(f"[REMOTE-DESKTOP] persistent helper disconnected: {exc}")
        finally:
            if self._channel is channel:
                self._channel = None
            with self._condition:
                self._condition.notify_all()

    def stop(self) -> None:
        self._stop.set()
        channel = self._channel
        self._channel = None
        reader = self._reader
        if channel is not None:
            try:
                channel.send("S", {})
            except Exception:
                pass
            # Half-close writes so the pending "S" + FIN reach the peer, then let
            # the reader drain remaining inbound bytes to EOF so the final close
            # is graceful rather than an RST that could discard the "S".
            try:
                channel.sock.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            if reader is not None and reader is not threading.current_thread():
                reader.join(timeout=1.0)
            channel.close()
        # A helper that never receives "S" (abrupt teardown) still stops on its
        # own recv error and releases held buttons — see run_session_helper.
        listener = self._listener
        self._listener = None
        if listener is not None:
            try:
                listener.close()
            except OSError:
                pass
        with self._condition:
            self._condition.notify_all()


def run_session_helper(
    host: str,
    port: int,
    secret_hex: str,
    session_id: int,
    *,
    winlogon: bool = False,
) -> bool:
    """Interactive-process entry point. Capture stays in memory."""
    secret = bytes.fromhex(secret_hex)
    if host not in ("127.0.0.1", "localhost"):
        raise ValueError("remote desktop helper only permits loopback")
    raw = socket.create_connection((host, int(port)), timeout=12)
    channel = SecureFramedSocket(raw, secret)
    channel.send("H", {"session_id": int(session_id), "pid": os.getpid()})
    kind, config, _ = channel.recv()
    if kind != "C":
        raise ProtocolError("missing helper configuration")
    raw.settimeout(None)

    from client_remote_desktop import RemoteDesktopStreamer

    rd = RemoteDesktopStreamer()
    rd._running = True
    # Already inside the target session process — never spawn nested helpers.
    rd._in_session_helper = True
    rd._target_session_id = int(session_id or 0) or None
    # Winlogon / lock UI: stay on named Winlogon desktop (C-RD-CON-4).
    rd._winlogon_mode = bool(winlogon or config.get("winlogon"))
    # WebRTC-first: parent may request raw RGB over loopback (prefer_raw).
    prefer_raw = bool(config.get("prefer_raw"))
    # JPEG fallback normally stays lower; WebRTC/media can request 30–60 fps.
    rd._fps = max(1.0, min(float(config.get("fps", 6.0)), 60.0))
    rd._quality = max(20, min(int(config.get("quality", 35)), 85))
    rd._max_width = max(800, min(int(config.get("max_width", 1280)), 1920))
    rd._monitor_index = max(0, int(config.get("monitor", 0)))
    stop = threading.Event()

    def capture_loop():
        nonlocal prefer_raw
        while not stop.is_set():
            started = time.monotonic()
            try:
                sent = False
                if prefer_raw:
                    img, method = rd._capture_screen_image()
                    if (
                        img is not None
                        and "+black" not in (method or "")
                        and "+flat" not in (method or "")
                        and img.width > 0
                        and img.height > 0
                    ):
                        rgb = img.convert("RGB").tobytes()
                        if len(rgb) <= MAX_PAYLOAD:
                            captured_mono = time.monotonic()
                            channel.send("R", {
                                "format": "rgb",
                                "width": int(img.width),
                                "height": int(img.height),
                                "native_width": int(rd._screen_w or img.width),
                                "native_height": int(rd._screen_h or img.height),
                                "origin_x": int(rd._screen_x),
                                "origin_y": int(rd._screen_y),
                                "capture_ms": round((captured_mono - started) * 1000.0, 3),
                                "capture_mono_ms": int(captured_mono * 1000),
                                "method": method or "gdi",
                                "flat_frame": False,
                                "frame_variance": float(
                                    getattr(rd, "_last_frame_variance", 0.0) or 0.0
                                ),
                                "chrome_detected": bool(
                                    getattr(rd, "_chrome_detected", False)
                                ),
                                "hwnd": int(
                                    getattr(rd, "_logonui_hwnd_count", 0) or 0
                                ),
                                "desktop": str(
                                    getattr(rd, "_desktop_name", "") or ""
                                ),
                            }, rgb)
                            sent = True
                    elif img is not None and (
                        "+flat" in (method or "") or "+black" in (method or "")
                    ):
                        # Re-grab may recover chrome — header must reflect *post-grab*
                        # method (4.9.90 lab: JPEG had chrome while meta stayed +flat).
                        jpeg, width, height = rd._grab_jpeg()
                        if jpeg and width > 0 and height > 0:
                            method_now = str(rd._capture_method or method or "gdi")
                            flat_now = "+flat" in method_now
                            black_now = "+black" in method_now
                            captured_mono = time.monotonic()
                            channel.send("F", {
                                "format": "jpeg",
                                "width": width,
                                "height": height,
                                "native_width": int(rd._screen_w or width),
                                "native_height": int(rd._screen_h or height),
                                "origin_x": int(rd._screen_x),
                                "origin_y": int(rd._screen_y),
                                "capture_ms": round((captured_mono - started) * 1000.0, 3),
                                "capture_mono_ms": int(captured_mono * 1000),
                                "method": method_now,
                                "flat_frame": bool(flat_now),
                                "frame_variance": float(
                                    getattr(rd, "_last_frame_variance", 0.0) or 0.0
                                ),
                                "chrome_detected": bool(
                                    getattr(rd, "_chrome_detected", False)
                                    and not flat_now
                                    and not black_now
                                ),
                                "hwnd": int(
                                    getattr(rd, "_logonui_hwnd_count", 0) or 0
                                ),
                                "desktop": str(
                                    getattr(rd, "_desktop_name", "") or ""
                                ),
                            }, jpeg)
                            sent = True
                if not sent:
                    jpeg, width, height = rd._grab_jpeg()
                    if jpeg and width > 0 and height > 0:
                        captured_mono = time.monotonic()
                        channel.send("F", {
                            "format": "jpeg",
                            "width": width,
                            "height": height,
                            "native_width": int(rd._screen_w or width),
                            "native_height": int(rd._screen_h or height),
                            "origin_x": int(rd._screen_x),
                            "origin_y": int(rd._screen_y),
                            "capture_ms": round((captured_mono - started) * 1000.0, 3),
                            "capture_mono_ms": int(captured_mono * 1000),
                            "method": rd._capture_method,
                            "flat_frame": "+flat" in (rd._capture_method or ""),
                            "frame_variance": float(
                                getattr(rd, "_last_frame_variance", 0.0) or 0.0
                            ),
                            "chrome_detected": bool(
                                getattr(rd, "_chrome_detected", False)
                            ),
                            "hwnd": int(
                                getattr(rd, "_logonui_hwnd_count", 0) or 0
                            ),
                            "desktop": str(
                                getattr(rd, "_desktop_name", "") or ""
                            ),
                        }, jpeg)
            except Exception as exc:
                try:
                    channel.send("E", {"error": str(exc)})
                except Exception:
                    stop.set()
            stop.wait(max(0.02, (1.0 / rd._fps) - (time.monotonic() - started)))

    capture_thread = threading.Thread(target=capture_loop, name="RDHelperCapture", daemon=True)
    capture_thread.start()
    try:
        while not stop.is_set():
            kind, header, _ = channel.recv()
            if kind == "S":
                break
            if kind == "C":
                prefer_raw = bool(header.get("prefer_raw", prefer_raw))
                rd._winlogon_mode = bool(header.get("winlogon", rd._winlogon_mode))
                rd._fps = max(1.0, min(float(header.get("fps", rd._fps)), 60.0))
                rd._quality = max(20, min(int(header.get("quality", rd._quality)), 85))
                try:
                    from client_remote_desktop import MIN_ENCODE_WIDTH
                    floor_w = int(MIN_ENCODE_WIDTH)
                except Exception:
                    floor_w = 800
                new_max_w = max(
                    floor_w, min(int(header.get("max_width", rd._max_width)), 1920)
                )
                if new_max_w != int(rd._max_width):
                    # Explicit dashboard width change only — keep size locked otherwise.
                    rd._locked_encode_w = 0
                    rd._locked_encode_h = 0
                rd._max_width = new_max_w
                rd._monitor_index = max(
                    0, int(header.get("monitor", rd._monitor_index))
                )
                continue
            if kind == "I":
                request_id = int(header.get("id", 0))
                event = header.get("event") or {}
                ok = False
                detail = ""
                ev = ""
                try:
                    if isinstance(event, dict):
                        # C-RD-IN-WL-1: inject on this Winlogon desktop — never
                        # recurse into apply_input (that tries to spawn another
                        # helper and never reaches SendInput).
                        params = rd._normalize_input_envelope(event)
                        ev = (params.get("event") or "").strip().lower()
                        if not ev:
                            detail = "empty_event"
                        else:
                            ok = bool(rd._inject_local(ev, params))
                            if ok:
                                rd._stats["inputs_applied"] = (
                                    int(rd._stats.get("inputs_applied") or 0) + 1
                                )
                                rd._last_input_event = ev
                                try:
                                    from client_helpers import log as _hlog
                                    _hlog(
                                        f"[remote-input] helper-inject ok event={ev} "
                                        f"path=local-sendinput "
                                        f"desk={rd._desktop_name or '?'} "
                                        f"applied={rd._stats['inputs_applied']}"
                                    )
                                except Exception:
                                    pass
                            else:
                                key_l = str(params.get("key") or "").strip().lower()
                                if key_l in (
                                    "ctrl+alt+del",
                                    "ctrl-alt-del",
                                    "ctrl+alt+delete",
                                    "cad",
                                ):
                                    detail = "cad_key_ignored"
                                else:
                                    detail = f"inject_failed event={ev}"
                    else:
                        detail = "event_not_dict"
                except Exception as exc:
                    detail = str(exc)
                    ok = False
                channel.send(
                    "A",
                    {
                        "id": request_id,
                        "ok": bool(ok),
                        "detail": detail,
                        "action": "input",
                        "event": ev,
                        "inputs_applied": int(
                            rd._stats.get("inputs_applied") or 0
                        ),
                        "last_input_event": str(
                            getattr(rd, "_last_input_event", "") or ""
                        ),
                    },
                )
                continue
            if kind == "D":
                request_id = int(header.get("id", 0))
                action = str(header.get("action") or "sas").strip().lower()
                try:
                    from client_rd_winlogon import (
                        attach_console_desktop,
                        desktop_surface_fingerprint,
                        desktop_surface_is_flat,
                        run_send_sas_on_attached_desktop,
                        visible_surface_signature,
                    )
                    prefer_wl = bool(rd._winlogon_mode)

                    def _sample_chrome() -> dict:
                        # Attach on THIS (command) thread for UI/HWND sample only.
                        # Always invalidate afterward so the capture thread rebinds
                        # via SetThreadDesktop (per-thread; 4.9.89 gdi+flat).
                        try:
                            rd._invalidate_desktop_bind()
                            attach_console_desktop(
                                prefer_winlogon=prefer_wl,
                                strict_winlogon=prefer_wl,
                            )
                            state, _tok, n = visible_surface_signature()
                            img, method = rd._capture_screen_image()
                            flat = bool(
                                "+flat" in (method or "")
                                or desktop_surface_is_flat()
                            )
                            if state == "sas_ui" and flat:
                                state = "other"
                            return {
                                "ui": state,
                                "flat": flat,
                                "chrome_detected": bool(
                                    getattr(rd, "_chrome_detected", False) and not flat
                                ),
                                "frame_variance": float(
                                    getattr(rd, "_last_frame_variance", 0.0) or 0.0
                                ),
                                "method": method or "",
                                "fp": desktop_surface_fingerprint(),
                                "hwnd": int(n),
                                "detail": (
                                    f"chrome={n} method={method} "
                                    f"desk={getattr(rd, '_desktop_name', '') or '?'}"
                                ),
                            }
                        finally:
                            rd._invalidate_desktop_bind()

                    if action == "ui":
                        sample = _sample_chrome()
                        channel.send(
                            "A",
                            {
                                "id": request_id,
                                "ok": True,
                                "action": "ui",
                                "ui": sample["ui"],
                                "ui_after": sample["ui"],
                                "fp": sample["fp"],
                                "flat": sample["flat"],
                                "chrome_detected": sample["chrome_detected"],
                                "frame_variance": sample["frame_variance"],
                                "detail": sample["detail"],
                                "hwnd": sample.get("hwnd", 0),
                            },
                        )
                    elif action == "reattach":
                        # Invalidate only — do not SetThreadDesktop on command thread.
                        rd._invalidate_desktop_bind()
                        channel.send(
                            "A",
                            {
                                "id": request_id,
                                "ok": True,
                                "action": "reattach",
                                "ui": "unknown",
                                "ui_after": "unknown",
                                "flat": False,
                                "chrome_detected": False,
                                "frame_variance": 0.0,
                                "detail": "bind_invalidated",
                            },
                        )
                    else:
                        result = run_send_sas_on_attached_desktop(
                            prefer_winlogon=prefer_wl,
                            timeout_sec=2.0,
                            try_as_user=True,
                        )
                        # C-RD-CHROME-4: after SAS, recapture secure desktop pixels.
                        sample = {"flat": True, "ui": result.get("ui_after"), "chrome_detected": False}
                        for _attempt in range(8):
                            sample = _sample_chrome()
                            if not sample["flat"]:
                                break
                            time.sleep(0.12)
                        ui_after = str(sample.get("ui") or result.get("ui_after") or "unknown")
                        flat = bool(sample.get("flat"))
                        effect = bool(result.get("effect")) and not flat
                        if flat and ui_after == "sas_ui":
                            ui_after = "other"
                            effect = False
                        if flat:
                            effect = False
                        channel.send(
                            "A",
                            {
                                "id": request_id,
                                "ok": bool(result.get("invoked")),
                                "effect": effect,
                                "detail": str(result.get("detail") or ""),
                                "ui_before": str(result.get("ui_before") or ""),
                                "ui_after": ui_after,
                                "as_user": bool(result.get("as_user")),
                                "flat": flat,
                                "chrome_detected": bool(sample.get("chrome_detected")),
                                "frame_variance": float(
                                    sample.get("frame_variance") or 0.0
                                ),
                                "action": "sas",
                            },
                        )
                except Exception as exc:
                    channel.send(
                        "A",
                        {
                            "id": request_id,
                            "ok": False,
                            "effect": False,
                            "detail": str(exc),
                            "ui_before": "unknown",
                            "ui_after": "unknown",
                            "flat": True,
                            "action": action or "sas",
                        },
                    )
                continue
    except (EOFError, OSError, ProtocolError):
        pass
    finally:
        stop.set()
        # Release any buttons held mid-drag before the session loses its input.
        try:
            rd._release_all_buttons()
        except Exception:
            pass
        rd._running = False
        channel.close()
        capture_thread.join(timeout=2)
    return True
