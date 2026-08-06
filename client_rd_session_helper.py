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
MAX_PAYLOAD = 3 * 1024 * 1024
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
        listener.settimeout(max(0.2, float(timeout)))
        self._listener = listener
        port = int(listener.getsockname()[1])
        command = self._command_builder(secret.hex(), port, json.dumps(config, separators=(",", ":")))
        if not self._launch(self.session_id, command):
            self._error = "CreateProcessAsUser failed"
            self.stop()
            return False
        try:
            raw, address = listener.accept()
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
            return True
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
        """Forward an input event to the helper.

        wait=False (moves): fire-and-forget, returns as soon as the frame is
        written to the socket — never blocks the caller (e.g. the WS thread).
        wait=True (critical edges): waits up to ``timeout`` for a short ACK, but
        still returns True on timeout if the pipe is alive (assume queued), so a
        slow ACK never turns a real keypress into a spurious failure.
        """
        channel = self._channel
        if channel is None:
            return False
        if not wait:
            try:
                channel.send("I", {"id": 0, "event": event})
                return True
            except Exception as exc:
                self._error = str(exc)
                return False
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
            return False
        deadline = time.monotonic() + max(0.0, timeout)
        with self._condition:
            while self._pending.get(request_id) is None and self.connected:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                self._condition.wait(remaining)
            acked = self._pending.pop(request_id, None)
        return True if acked is None else bool(acked)

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
                    if kind == "F":
                        self._frame_id += 1
                        self._latest = (payload, header)
                    elif kind == "A":
                        self._pending[int(header.get("id", 0))] = bool(header.get("ok"))
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
    # Winlogon / lock UI: stay on named Winlogon desktop (C-RD-CON-4).
    rd._winlogon_mode = bool(winlogon or config.get("winlogon"))
    # JPEG fallback normally stays <=10 fps; WebRTC media mode can request
    # 30-60 fps independently through update_config.
    rd._fps = max(1.0, min(float(config.get("fps", 6.0)), 60.0))
    rd._quality = max(20, min(int(config.get("quality", 35)), 85))
    rd._max_width = max(800, min(int(config.get("max_width", 1280)), 1920))
    rd._monitor_index = max(0, int(config.get("monitor", 0)))
    stop = threading.Event()

    def capture_loop():
        while not stop.is_set():
            started = time.monotonic()
            try:
                jpeg, width, height = rd._grab_jpeg()
                if jpeg and width > 0 and height > 0:
                    captured_mono = time.monotonic()
                    channel.send("F", {
                        "width": width,
                        "height": height,
                        "native_width": int(rd._screen_w or width),
                        "native_height": int(rd._screen_h or height),
                        "origin_x": int(rd._screen_x),
                        "origin_y": int(rd._screen_y),
                        "capture_ms": round((captured_mono - started) * 1000.0, 3),
                        "capture_mono_ms": int(captured_mono * 1000),
                        "method": rd._capture_method,
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
                result = rd.apply_input(event) if isinstance(event, dict) else {"success": False}
                channel.send("A", {"id": request_id, "ok": bool(result.get("success"))})
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
