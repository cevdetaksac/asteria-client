#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Optional remote-desktop media transports.

The default client does not import aiortc or av.  When the optional packages
are installed, :func:`create_optional_media_transport` probes them by actually
constructing a peer connection before WebRTC capability is advertised.

Signaling uses the existing agent WebSocket and non-trickle ICE: offers and
answers contain complete SDP after ICE gathering. Incoming standalone ICE is
validated but rejected with ``reason=non_trickle_ice``.
"""

from __future__ import annotations

import asyncio
import io
import json
import re
import threading
import time
from typing import Callable, Optional


MAX_ICE_SERVERS = 8
MAX_ICE_URLS_PER_SERVER = 8
MAX_ICE_URL_LENGTH = 512
MAX_ICE_USERNAME_LENGTH = 256
MAX_ICE_CREDENTIAL_LENGTH = 512
_ICE_SCHEME = re.compile(r"^(stun|turn|turns):", re.IGNORECASE)


class IceServerValidationError(ValueError):
    """Safe validation error whose message never includes supplied values."""


def _safe_ice_string(value, field: str, max_length: int, *, allow_empty=False):
    if not isinstance(value, str):
        raise IceServerValidationError(f"{field} must be a string")
    if (not value and not allow_empty) or len(value) > max_length:
        raise IceServerValidationError(f"{field} length is invalid")
    if any(ord(ch) < 0x20 or ch.isspace() for ch in value):
        raise IceServerValidationError(f"{field} contains unsafe characters")
    return value


def validate_ice_servers(value) -> list:
    """Validate untrusted signaling ICE configuration without logging secrets."""
    if value is None:
        return []
    if not isinstance(value, list):
        raise IceServerValidationError("ice_servers must be a list")
    if len(value) > MAX_ICE_SERVERS:
        raise IceServerValidationError("too many ice_servers")
    validated = []
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise IceServerValidationError(f"ice_servers[{index}] must be an object")
        if set(item) - {"urls", "username", "credential"}:
            raise IceServerValidationError(f"ice_servers[{index}] has unknown fields")
        urls_value = item.get("urls")
        if isinstance(urls_value, str):
            urls = [urls_value]
            output_urls = "single"
        elif isinstance(urls_value, list):
            if not urls_value or len(urls_value) > MAX_ICE_URLS_PER_SERVER:
                raise IceServerValidationError(
                    f"ice_servers[{index}].urls count is invalid"
                )
            urls = list(urls_value)
            output_urls = "list"
        else:
            raise IceServerValidationError(
                f"ice_servers[{index}].urls must be string or list"
            )
        safe_urls = []
        for url in urls:
            safe = _safe_ice_string(
                url,
                f"ice_servers[{index}].urls",
                MAX_ICE_URL_LENGTH,
            )
            if not _ICE_SCHEME.match(safe):
                raise IceServerValidationError(
                    f"ice_servers[{index}].urls scheme is not allowed"
                )
            if not safe.split(":", 1)[1]:
                raise IceServerValidationError(
                    f"ice_servers[{index}].urls endpoint is missing"
                )
            safe_urls.append(safe)
        server = {
            "urls": safe_urls[0] if output_urls == "single" else safe_urls,
        }
        if "username" in item:
            server["username"] = _safe_ice_string(
                item["username"],
                f"ice_servers[{index}].username",
                MAX_ICE_USERNAME_LENGTH,
                allow_empty=True,
            )
        if "credential" in item:
            server["credential"] = _safe_ice_string(
                item["credential"],
                f"ice_servers[{index}].credential",
                MAX_ICE_CREDENTIAL_LENGTH,
                allow_empty=True,
            )
        validated.append(server)
    return validated


def build_ice_configuration(validated: list, runtime: dict):
    """Convert validated dictionaries to lazy-loaded aiortc configuration."""
    if not validated:
        return None
    servers = []
    for item in validated:
        kwargs = {"urls": item["urls"]}
        if "username" in item:
            kwargs["username"] = item["username"]
        if "credential" in item:
            kwargs["credential"] = item["credential"]
        servers.append(runtime["RTCIceServer"](**kwargs))
    return runtime["RTCConfiguration"](iceServers=servers)


class NewestFrameMailbox:
    """One-slot thread-safe mailbox; publishing coalesces stale frames.

    Payload kinds:
      - \"jpeg\": bytes JPEG
      - \"raw\": dict {\"rgb\": bytes|bytearray, \"width\": int, \"height\": int}
    """

    def __init__(self):
        self._condition = threading.Condition()
        self._generation = 0
        self._latest = None
        self._last_taken_generation = 0
        self.coalesced = 0
        self.closed = False

    def publish(self, jpeg: bytes, metadata: Optional[dict] = None) -> int:
        return self._publish("jpeg", bytes(jpeg), metadata)

    def publish_raw(
        self,
        rgb,
        width: int,
        height: int,
        metadata: Optional[dict] = None,
    ) -> int:
        if hasattr(rgb, "tobytes"):
            payload = {
                "rgb": rgb.tobytes(),
                "width": int(width),
                "height": int(height),
            }
        else:
            payload = {
                "rgb": bytes(rgb),
                "width": int(width),
                "height": int(height),
            }
        return self._publish("raw", payload, metadata)

    def _publish(self, kind: str, payload, metadata: Optional[dict] = None) -> int:
        with self._condition:
            if self.closed:
                return self._generation
            if self._latest is not None and self._generation > self._last_taken_generation:
                self.coalesced += 1
            self._generation += 1
            self._latest = (
                self._generation,
                kind,
                payload,
                dict(metadata or {}),
            )
            self._condition.notify_all()
            return self._generation

    def latest(self, after_generation: int = 0):
        with self._condition:
            if self._latest is None or self._generation <= after_generation:
                return None
            self._last_taken_generation = self._generation
            return self._latest

    def wait_latest(self, after_generation: int = 0, timeout: float = 0.2):
        deadline = time.monotonic() + max(0.0, timeout)
        with self._condition:
            while (
                not self.closed
                and (
                    self._latest is None
                    or self._generation <= after_generation
                )
            ):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                self._condition.wait(remaining)
            if self._latest is None or self._generation <= after_generation:
                return None
            self._last_taken_generation = self._generation
            return self._latest

    def close(self):
        with self._condition:
            self.closed = True
            self._condition.notify_all()

    def clear(self):
        with self._condition:
            self._latest = None
            self._last_taken_generation = self._generation


def codec_name(codec) -> str:
    mime = str(getattr(codec, "mimeType", "") or "").lower()
    return mime.split("/", 1)[-1] if "/" in mime else mime


def prefer_h264_codecs(codecs: list) -> list:
    """Stable H264-first codec order for RTCRtpTransceiver preferences."""
    h264 = [codec for codec in codecs if codec_name(codec) == "h264"]
    other = [codec for codec in codecs if codec_name(codec) != "h264"]
    return h264 + other


def _load_aiortc_runtime():
    """Lazy optional imports. Kept in one function for deterministic tests."""
    from aiortc import (  # type: ignore
        RTCConfiguration,
        RTCIceServer,
        RTCPeerConnection,
        RTCSessionDescription,
        RTCRtpSender,
        VideoStreamTrack,
    )
    from av import VideoFrame  # type: ignore
    from PIL import Image

    return {
        "RTCPeerConnection": RTCPeerConnection,
        "RTCConfiguration": RTCConfiguration,
        "RTCIceServer": RTCIceServer,
        "RTCSessionDescription": RTCSessionDescription,
        "RTCRtpSender": RTCRtpSender,
        "VideoStreamTrack": VideoStreamTrack,
        "VideoFrame": VideoFrame,
        "Image": Image,
    }


def probe_aiortc_runtime(loader: Callable = _load_aiortc_runtime) -> dict:
    """Return truthful runtime capabilities after real PC construction."""
    try:
        runtime = loader()

        async def probe():
            pc = runtime["RTCPeerConnection"]()
            try:
                capabilities = runtime["RTCRtpSender"].getCapabilities("video")
                codecs = []
                for codec in getattr(capabilities, "codecs", []) or []:
                    name = codec_name(codec)
                    if name and name not in codecs:
                        codecs.append(name)
                return codecs
            finally:
                await pc.close()

        codecs = asyncio.run(probe())
        if not codecs:
            return {"available": False, "codecs": [], "error": "no video codecs"}
        return {"available": True, "codecs": codecs, "runtime": runtime, "error": ""}
    except Exception as exc:
        return {"available": False, "codecs": [], "error": str(exc)}


class OptionalMediaTransport:
    """No-op transport used when optional WebRTC runtime is absent."""

    available = False
    active = False

    def capabilities(self) -> dict:
        return {
            "webrtc": False,
            "webrtc_signaling": 1,
            "ice": "non-trickle",
            "ice_server_config": False,
            "codecs": [],
        }

    def publish_frame(self, _jpeg: bytes, _metadata: Optional[dict] = None) -> bool:
        return False

    def publish_raw(self, _rgb, _width: int, _height: int, _metadata: Optional[dict] = None) -> bool:
        return False

    def handle_signal(self, _message: dict) -> dict:
        return {"accepted": False, "error": "webrtc runtime unavailable"}

    def status(self) -> dict:
        return {
            "available": False,
            "active": False,
            "connection_state": "unavailable",
            "ice_state": "unavailable",
            "codec": "",
            "error": "",
        }

    def stop(self) -> None:
        return None


class AiortcMediaTransport(OptionalMediaTransport):
    """aiortc video transport hosted on a dedicated asyncio thread."""

    ICE_CHECKING_TIMEOUT_SEC = 15.0
    # C-RD-P0-ICE-3: after ICE fail/timeout, JPEG-WS must resume within 2s.
    JPEG_FALLBACK_MAX_SEC = 2.0
    _CONNECTED_ICE_STATES = frozenset(("connected", "completed"))

    def __init__(
        self,
        probe: dict,
        *,
        signal_sender: Callable[[dict], None],
        input_handler: Callable[[dict], object],
        fallback_handler: Callable[[str], None],
    ):
        self._runtime = probe["runtime"]
        self._codecs = list(probe["codecs"])
        self._signal_sender = signal_sender
        self._input_handler = input_handler
        self._fallback_handler = fallback_handler
        self.mailbox = NewestFrameMailbox()
        self.available = True
        self.active = False
        self._loop = None
        self._thread = None
        self._ready = threading.Event()
        self._pc = None
        self._session_id = ""
        self._stream_id = ""
        self._state_lock = threading.Lock()
        self._pc_connection_state = "new"
        self._connection_state = "new"
        self._ice_state = "new"
        self._ice_checking_task = None
        self._offer_lock = None
        self._codec = ""
        self._preferred_codec = ""
        self._encoder_label = ""
        self._target_bitrate_bps = 12_000_000
        self._error = ""
        self._closing = False
        self._start_thread()

    def capabilities(self) -> dict:
        return {
            "webrtc": True,
            "webrtc_signaling": 1,
            "ice": "non-trickle",
            "ice_server_config": True,
            "codecs": list(self._codecs),
        }

    def status(self) -> dict:
        try:
            from client_rd_encoder import encoder_info
            enc = encoder_info().get("label") or "aiortc"
        except Exception:
            enc = "aiortc"
        with self._state_lock:
            media_ready = bool(
                self.active
                and self._pc_connection_state == "connected"
                and self._ice_state in self._CONNECTED_ICE_STATES
            )
            return {
                "available": True,
                "active": bool(self.active),
                "connection_state": self._connection_state,
                "ice_state": self._ice_state,
                "codec": self._codec,
                "preferred_codec": self._preferred_codec,
                "encoder": getattr(self, "_encoder_label", None) or enc,
                "target_bitrate_bps": getattr(self, "_target_bitrate_bps", None),
                "error": self._error,
                "mailbox_coalesced": self.mailbox.coalesced,
                "session_id": self._session_id,
                "stream_id": self._stream_id,
                "raw_path": True,
                # C-RD-P0-ICE-3: JPEG path while ICE+DTLS not verified.
                "jpeg_fallback_active": not media_ready,
            }

    def publish_frame(self, jpeg: bytes, metadata: Optional[dict] = None) -> bool:
        if not self.available:
            return False
        with self._state_lock:
            media_ready = bool(
                self.active
                and self._pc_connection_state == "connected"
                and self._ice_state in self._CONNECTED_ICE_STATES
            )
        if not media_ready:
            return False
        self.mailbox.publish(jpeg, metadata)
        return True

    def publish_raw(self, rgb, width: int, height: int, metadata: Optional[dict] = None) -> bool:
        if not self.available:
            return False
        with self._state_lock:
            media_ready = bool(
                self.active
                and self._pc_connection_state == "connected"
                and self._ice_state in self._CONNECTED_ICE_STATES
            )
        if not media_ready:
            return False
        self.mailbox.publish_raw(rgb, width, height, metadata)
        return True

    def handle_signal(self, message: dict) -> dict:
        action = str(message.get("action") or "").lower()
        if action == "ice":
            return {"accepted": False, "reason": "non_trickle_ice"}
        safe_message = dict(message)
        if action == "offer" and "ice_servers" in safe_message:
            try:
                validated = validate_ice_servers(safe_message.get("ice_servers"))
                configuration = build_ice_configuration(validated, self._runtime)
            except IceServerValidationError as exc:
                return {"accepted": False, "error": str(exc)}
            except Exception:
                # Never expose constructor messages: they may render credentials.
                return {"accepted": False, "error": "invalid ice server configuration"}
            safe_message.pop("ice_servers", None)
            safe_message["_rtc_configuration"] = configuration
        if not self._loop or not self._ready.is_set():
            return {"accepted": False, "error": "media loop unavailable"}
        future = asyncio.run_coroutine_threadsafe(
            self._handle_signal_async(safe_message), self._loop
        )

        def completed(done):
            try:
                result = done.result()
                if not result.get("accepted"):
                    self._fail(str(result.get("error") or "signaling rejected"))
            except Exception as exc:
                # aiortc exception text can contain RTCConfiguration reprs.
                self._fail("peer setup failed")

        future.add_done_callback(completed)
        return {"accepted": True, "action": action, "queued": True}

    def stop(self) -> None:
        self.active = False
        self.mailbox.clear()
        loop = self._loop
        if loop and loop.is_running():
            future = asyncio.run_coroutine_threadsafe(self._close_pc(), loop)
            try:
                future.result(timeout=2.0)
            except Exception:
                pass
        self._session_id = ""
        self._stream_id = ""

    def _start_thread(self):
        self._thread = threading.Thread(
            target=self._thread_main, name="RDWebRTC", daemon=True
        )
        self._thread.start()
        self._ready.wait(2.0)

    def _thread_main(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        self._loop = loop
        self._ready.set()
        try:
            loop.run_forever()
        finally:
            try:
                loop.run_until_complete(self._close_pc())
            except Exception:
                pass
            loop.close()

    async def _handle_signal_async(self, message: dict) -> dict:
        action = str(message.get("action") or "").lower()
        if action == "offer":
            if self._offer_lock is None:
                self._offer_lock = asyncio.Lock()
            async with self._offer_lock:
                session_id = str(message["session_id"])
                stream_id = str(message["stream_id"])
                try:
                    # Synchronous teardown inside the serialized offer section:
                    # no old peer callback can overwrite the new peer state.
                    await self._create_peer(
                        session_id,
                        stream_id,
                        configuration=message.get("_rtc_configuration"),
                    )
                    description = self._runtime["RTCSessionDescription"](
                        sdp=str(message.get("sdp") or ""), type="offer"
                    )
                    await self._pc.setRemoteDescription(description)
                    self._prefer_h264()
                    answer = await self._pc.createAnswer()
                    await self._pc.setLocalDescription(answer)
                    local = self._pc.localDescription
                    self._signal_sender({
                        "t": "webrtc_signal",
                        "action": "answer",
                        "protocol": 1,
                        "session_id": self._session_id,
                        "stream_id": self._stream_id,
                        "sdp": local.sdp,
                        "type": local.type,
                        "ice": "non-trickle",
                    })
                    return {"accepted": True, "action": "offer"}
                except Exception:
                    await self._close_pc()
                    self._send_reject(
                        session_id, stream_id, "peer_setup_failed"
                    )
                    self._fail("peer setup failed")
                    return {
                        "accepted": False,
                        "error": "peer setup failed",
                    }
        if action == "answer":
            if self._pc is None:
                return {"accepted": False, "error": "no local offer"}
            description = self._runtime["RTCSessionDescription"](
                sdp=str(message.get("sdp") or ""), type="answer"
            )
            await self._pc.setRemoteDescription(description)
            return {"accepted": True, "action": "answer"}
        return {"accepted": False, "error": f"unsupported signal: {action}"}

    def _send_reject(
        self, session_id: str, stream_id: str, reason: str
    ) -> None:
        try:
            self._signal_sender({
                "t": "webrtc_signal",
                "action": "webrtc_reject",
                "protocol": 1,
                "session_id": str(session_id),
                "stream_id": str(stream_id),
                "reason": str(reason)[:80],
            })
        except Exception:
            pass

    async def _create_peer(
        self, session_id: str, stream_id: str, configuration=None
    ):
        await self._close_pc()
        with self._state_lock:
            self._pc_connection_state = "new"
            self._connection_state = "new"
            self._ice_state = "new"
            self._codec = ""
            self._preferred_codec = ""
            self._error = ""
            self.active = False
        if configuration is None:
            pc = self._runtime["RTCPeerConnection"]()
        else:
            pc = self._runtime["RTCPeerConnection"](
                configuration=configuration
            )
        self._pc = pc
        self._session_id = session_id
        self._stream_id = stream_id
        try:
            from client_rd_encoder import ensure_aiortc_h264_patched
            self._encoder_label = ensure_aiortc_h264_patched()
        except Exception:
            self._encoder_label = self._encoder_label or "aiortc"
        track_class = self._make_track_class()
        sender = pc.addTrack(track_class(self.mailbox))
        try:
            params = sender.getParameters()
            encodings = list(getattr(params, "encodings", None) or [{}])
            if not encodings:
                encodings = [{}]
            encodings[0]["maxBitrate"] = int(self._target_bitrate_bps)
            encodings[0]["maxFramerate"] = 60
            params.encodings = encodings
            set_params = getattr(sender, "setParameters", None)
            if callable(set_params):
                maybe = set_params(params)
                if asyncio.iscoroutine(maybe):
                    await maybe
        except Exception:
            pass

        @pc.on("connectionstatechange")
        async def connection_state_change():
            await self._handle_connection_state(pc, str(pc.connectionState))

        @pc.on("iceconnectionstatechange")
        async def ice_state_change():
            await self._handle_ice_state(pc, str(pc.iceConnectionState))

        @pc.on("datachannel")
        def data_channel(channel):
            # Prefer low-latency input: drain promptly; ordered delivery retained.
            try:
                channel.bufferedAmountLowThreshold = 0
            except Exception:
                pass

            @channel.on("message")
            def message(payload):
                self.route_data_channel_input(payload)

    async def _handle_connection_state(self, pc, state: str):
        if pc is not self._pc:
            return
        became_active = False
        with self._state_lock:
            was_active = bool(self.active)
            self._pc_connection_state = str(state)
            self._recompute_media_state_locked()
            became_active = self.active and not was_active
        if became_active:
            await self._refresh_chosen_codec()
            asyncio.create_task(self._refresh_chosen_codec_after_delay())
        if state in ("failed", "disconnected") or (
            state == "closed" and not self._closing
        ):
            self._cancel_ice_checking_timeout()
            self._fail(f"peer connection {state}")

    async def _handle_ice_state(self, pc, state: str):
        if pc is not self._pc:
            return
        became_active = False
        with self._state_lock:
            was_active = bool(self.active)
            self._ice_state = str(state)
            self._recompute_media_state_locked()
            became_active = self.active and not was_active
        if state == "checking":
            self._start_ice_checking_timeout(pc)
        else:
            self._cancel_ice_checking_timeout()
        if became_active:
            await self._refresh_chosen_codec()
            asyncio.create_task(self._refresh_chosen_codec_after_delay())
        if state in ("failed", "disconnected") or (
            state == "closed" and not self._closing
        ):
            self._fail(f"ICE {state}")

    def _recompute_media_state_locked(self):
        ice_ready = self._ice_state in self._CONNECTED_ICE_STATES
        self.active = bool(
            self._pc_connection_state == "connected" and ice_ready
        )
        if self._pc_connection_state == "connected" and not ice_ready:
            # aiortc may expose aggregate connectionState=connected before the
            # separately observed ICE callback settles. Never advertise media
            # readiness early; surface the actual ICE progress instead.
            self._connection_state = (
                self._ice_state
                if self._ice_state in (
                    "new", "checking", "failed", "disconnected", "closed"
                )
                else "connecting"
            )
        else:
            self._connection_state = self._pc_connection_state

    def _start_ice_checking_timeout(self, pc):
        task = self._ice_checking_task
        if task is not None and not task.done():
            return
        self._ice_checking_task = asyncio.create_task(
            self._ice_checking_timeout(pc)
        )

    def _cancel_ice_checking_timeout(self):
        task = getattr(self, "_ice_checking_task", None)
        self._ice_checking_task = None
        if task is None or task.done():
            return
        try:
            current = asyncio.current_task()
        except RuntimeError:
            current = None
        if task is not current:
            task.cancel()

    async def _ice_checking_timeout(self, pc):
        try:
            await asyncio.sleep(float(self.ICE_CHECKING_TIMEOUT_SEC))
        except asyncio.CancelledError:
            return
        if pc is not self._pc:
            return
        with self._state_lock:
            timed_out = bool(
                not self.active and self._ice_state == "checking"
            )
            if timed_out:
                self._pc_connection_state = "failed"
                self._ice_state = "failed"
                self._recompute_media_state_locked()
        if not timed_out:
            return
        self._fail("ICE checking timeout")
        await self._close_pc()

    def route_data_channel_input(self, payload) -> bool:
        try:
            if isinstance(payload, bytes):
                payload = payload.decode("utf-8")
            data = json.loads(payload) if isinstance(payload, str) else payload
            if not isinstance(data, dict):
                return False
            self._input_handler(data)
            return True
        except Exception as exc:
            with self._state_lock:
                self._error = f"data channel input: {exc}"
            return False

    def _prefer_h264(self):
        capabilities = self._runtime["RTCRtpSender"].getCapabilities("video")
        ordered = prefer_h264_codecs(list(getattr(capabilities, "codecs", []) or []))
        h264 = [codec for codec in ordered if codec_name(codec) == "h264"]
        for transceiver in self._pc.getTransceivers():
            if getattr(transceiver, "kind", "") == "video" and ordered:
                # Prefer H264, but retain negotiated fallback codecs.
                transceiver.setCodecPreferences(ordered)
        with self._state_lock:
            self._preferred_codec = (
                "h264" if h264 else (codec_name(ordered[0]) if ordered else "")
            )

    async def _refresh_chosen_codec(self):
        try:
            stats = await self._pc.getStats()
            codec_by_id = {}
            outbound_codec_ids = []
            for stat in stats.values():
                stat_type = str(getattr(stat, "type", "") or "")
                if stat_type == "codec":
                    codec_by_id[str(getattr(stat, "id", ""))] = codec_name(stat)
                elif stat_type == "outbound-rtp" and getattr(stat, "kind", "") == "video":
                    codec_id = getattr(stat, "codecId", None)
                    if codec_id:
                        outbound_codec_ids.append(str(codec_id))
            chosen = next(
                (codec_by_id[item] for item in outbound_codec_ids if item in codec_by_id),
                "",
            )
            with self._state_lock:
                self._codec = chosen
        except Exception:
            pass

    async def _refresh_chosen_codec_after_delay(self):
        await asyncio.sleep(0.5)
        if self._pc is not None and self.active:
            await self._refresh_chosen_codec()

    def _make_track_class(self):
        runtime = self._runtime

        class LatestFrameTrack(runtime["VideoStreamTrack"]):
            """Prefer raw RGB mailbox frames; JPEG only as helper/fallback."""

            def __init__(self, mailbox):
                super().__init__()
                self.mailbox = mailbox
                self.generation = 0
                self.last_frame = None

            async def recv(self):
                pts, time_base = await self.next_timestamp()
                item = self.mailbox.latest(self.generation)
                if item is None:
                    await asyncio.sleep(0.005)
                    item = self.mailbox.latest(self.generation)
                if item is not None:
                    # New mailbox: (gen, kind, payload, meta)
                    # Legacy tests may still publish 3-tuples — tolerate.
                    if len(item) == 4:
                        self.generation, kind, payload, _metadata = item
                    else:
                        self.generation, payload, _metadata = item
                        kind = "jpeg"
                    try:
                        if kind == "raw" and isinstance(payload, dict):
                            import numpy as np  # type: ignore
                            w = int(payload.get("width") or 0)
                            h = int(payload.get("height") or 0)
                            rgb = payload.get("rgb") or b""
                            if w > 0 and h > 0 and len(rgb) >= w * h * 3:
                                arr = np.frombuffer(rgb, dtype=np.uint8).reshape(
                                    (h, w, 3)
                                ).copy()
                                self.last_frame = runtime["VideoFrame"].from_ndarray(
                                    arr, format="rgb24"
                                )
                        else:
                            image = runtime["Image"].open(
                                io.BytesIO(payload)
                            ).convert("RGB")
                            self.last_frame = runtime["VideoFrame"].from_image(image)
                    except Exception:
                        pass
                if self.last_frame is None:
                    image = runtime["Image"].new("RGB", (800, 600), "black")
                    self.last_frame = runtime["VideoFrame"].from_image(image)
                frame = self.last_frame
                frame.pts = pts
                frame.time_base = time_base
                return frame

        return LatestFrameTrack

    async def _close_pc(self):
        self._cancel_ice_checking_timeout()
        pc, self._pc = self._pc, None
        with self._state_lock:
            self.active = False
        if pc is not None:
            self._closing = True
            try:
                await pc.close()
            finally:
                self._closing = False

    def _fail(self, error: str):
        # C-RD-P0-ICE-5: clear connected UI signals; JPEG fallback is immediate.
        with self._state_lock:
            self._error = str(error)
            self.active = False
            # Defensive: constructed via __new__ in unit tests may lack attrs.
            if getattr(self, "_connection_state", "") == "connected":
                self._connection_state = "failed"
            ice = getattr(self, "_ice_state", "")
            if ice in getattr(self, "_CONNECTED_ICE_STATES", ()):
                self._ice_state = "failed"
        try:
            self._fallback_handler(str(error))
        except Exception:
            pass


def create_optional_media_transport(
    *,
    signal_sender: Callable[[dict], None],
    input_handler: Callable[[dict], object],
    fallback_handler: Callable[[str], None],
    loader: Callable = _load_aiortc_runtime,
):
    probe = probe_aiortc_runtime(loader)
    if not probe.get("available"):
        return OptionalMediaTransport()
    try:
        return AiortcMediaTransport(
            probe,
            signal_sender=signal_sender,
            input_handler=input_handler,
            fallback_handler=fallback_handler,
        )
    except Exception:
        return OptionalMediaTransport()
