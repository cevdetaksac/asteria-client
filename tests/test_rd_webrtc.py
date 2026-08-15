#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Deterministic rd6 tests; no aiortc install, network, or browser required."""

import json
import asyncio
import threading
import unittest

from client_rd_media import (
    AiortcMediaTransport,
    IceServerValidationError,
    NewestFrameMailbox,
    build_ice_configuration,
    codec_name,
    prefer_h264_codecs,
    probe_aiortc_runtime,
    validate_ice_servers,
)
from client_remote_desktop import RemoteDesktopStreamer


JPEG = b"\xff\xd8" + (b"x" * 2000) + b"\xff\xd9"


class Codec:
    def __init__(self, mime):
        self.mimeType = mime


class FakeMedia:
    def __init__(self, *, available=True, active=False, codecs=None):
        self.active = active
        self.available = available
        self.codecs = list(codecs or [])
        self.signals = []
        self.frames = []
        self.stopped = 0

    def capabilities(self):
        return {
            "webrtc": self.available,
            "webrtc_signaling": 1,
            "ice": "non-trickle",
            "ice_server_config": self.available,
            "codecs": self.codecs if self.available else [],
        }

    def status(self):
        return {
            "available": self.available,
            "active": self.active,
            "connection_state": "connected" if self.active else "new",
            "ice_state": "connected" if self.active else "new",
            "codec": "h264" if self.active and "h264" in self.codecs else "",
            "error": "",
        }

    def publish_frame(self, jpeg, metadata=None):
        self.frames.append((jpeg, metadata))
        return self.active

    def publish_raw(self, rgb, width, height, metadata=None):
        self.frames.append(("raw", width, height, metadata))
        return self.active

    def handle_signal(self, message):
        self.signals.append(message)
        return {"accepted": True, "action": message["action"]}

    def stop(self):
        self.active = False
        self.stopped += 1


class FakeApi:
    def __init__(self):
        self.uploads = 0

    def upload_remote_frame(self, **_kwargs):
        self.uploads += 1
        return True


class TestCapabilities(unittest.TestCase):
    def test_absent_runtime_never_advertises_webrtc_or_h264(self):
        media = FakeMedia(available=False, codecs=["h264"])
        rd = RemoteDesktopStreamer(media_transport=media)
        capabilities = rd._hello_payload()["capabilities"]
        self.assertFalse(capabilities["webrtc"]["available"])
        self.assertNotIn("webrtc", capabilities["transports"])
        self.assertEqual(capabilities["codecs"], ["jpeg"])
        self.assertEqual(capabilities["fallback"], "jpeg-ws")
        self.assertTrue(capabilities["input_v2"])
        self.assertTrue(capabilities["winlogon"])
        self.assertTrue(capabilities["pre_logon"])

    def test_runtime_codecs_are_additive_and_truthful(self):
        media = FakeMedia(available=True, codecs=["h264", "vp8"])
        rd = RemoteDesktopStreamer(media_transport=media)
        hello = rd._hello_payload()
        self.assertEqual(hello["protocol"], 2)
        self.assertIn("webrtc", hello["capabilities"]["transports"])
        self.assertEqual(
            hello["capabilities"]["codecs"], ["jpeg", "h264", "vp8"]
        )
        self.assertEqual(
            hello["capabilities"]["webrtc"]["signaling"], 1
        )
        self.assertTrue(
            hello["capabilities"]["webrtc"]["ice_server_config"]
        )
        self.assertTrue(hello["capabilities"]["webrtc"]["needs_turn"])
        self.assertEqual(hello["capabilities"]["smoothness"]["jpeg_fallback_fps"], 30.0)

    def test_probe_requires_real_peer_instantiation(self):
        class GoodPc:
            async def close(self):
                return None

        class Sender:
            @staticmethod
            def getCapabilities(_kind):
                return type("Caps", (), {"codecs": [Codec("video/H264")]})()

        probe = probe_aiortc_runtime(lambda: {
            "RTCPeerConnection": GoodPc,
            "RTCRtpSender": Sender,
        })
        self.assertTrue(probe["available"])
        self.assertEqual(probe["codecs"], ["h264"])

        class BadPc:
            def __init__(self):
                raise RuntimeError("native runtime broken")

        bad = probe_aiortc_runtime(lambda: {
            "RTCPeerConnection": BadPc,
            "RTCRtpSender": Sender,
        })
        self.assertFalse(bad["available"])
        self.assertEqual(bad["codecs"], [])


class TestSignalingValidation(unittest.TestCase):
    def make(self):
        media = FakeMedia(available=True, codecs=["h264"])
        rd = RemoteDesktopStreamer(media_transport=media)
        rd._running = True
        rd._stream_id = "stream-current"
        return rd, media

    def test_offer_requires_exact_stream_and_session_ids(self):
        rd, media = self.make()
        stale = rd._handle_webrtc_signal({
            "t": "webrtc_offer",
            "protocol": 1,
            "stream_id": "stream-old",
            "session_id": "peer-a",
            "sdp": "offer",
            "ice_servers": "malformed-but-identity-is-checked-first",
        })
        self.assertFalse(stale["accepted"])
        self.assertEqual(media.signals, [])

        accepted = rd._handle_webrtc_signal({
            "t": "webrtc_offer",
            "protocol": 1,
            "stream_id": "stream-current",
            "session_id": "peer-a",
            "sdp": "offer",
        })
        self.assertTrue(accepted["accepted"])
        self.assertEqual(media.signals[-1]["action"], "offer")

    def test_rejects_stale_session_answer_and_ice(self):
        rd, media = self.make()
        rd._media_session_id = "peer-current"
        for action in ("answer", "ice"):
            result = rd._handle_webrtc_signal({
                "t": "webrtc_signal",
                "action": action,
                "protocol": 1,
                "stream_id": "stream-current",
                "session_id": "peer-old",
            })
            self.assertFalse(result["accepted"])
        self.assertEqual(media.signals, [])

    def test_omitted_signaling_protocol_on_offer_is_accepted(self):
        rd, media = self.make()
        result = rd._handle_webrtc_signal({
            "action": "offer",
            "stream_id": "stream-current",
            "session_id": "peer-a",
            "sdp": "offer",
        })
        self.assertTrue(result["accepted"])
        self.assertEqual(media.signals[-1]["action"], "offer")

    def test_unknown_action_wrong_protocol_is_rejected(self):
        rd, _media = self.make()
        result = rd._handle_webrtc_signal({
            "action": "foo",
            "protocol": 2,
            "stream_id": "stream-current",
            "session_id": "peer-a",
        })
        self.assertFalse(result["accepted"])


class TestReofferFailure(unittest.TestCase):
    def test_failed_reoffer_sends_immediate_reject(self):
        sent = []
        fallback = []
        transport = AiortcMediaTransport.__new__(AiortcMediaTransport)
        transport._offer_lock = None
        transport._state_lock = threading.Lock()
        transport._error = ""
        transport.active = False
        transport._signal_sender = sent.append
        transport._fallback_handler = fallback.append

        async def fail_create(*_args, **_kwargs):
            raise RuntimeError("sensitive setup detail")

        async def close():
            return None

        transport._create_peer = fail_create
        transport._close_pc = close
        result = asyncio.run(transport._handle_signal_async({
            "action": "offer",
            "session_id": "peer-new",
            "stream_id": "stream-new",
            "sdp": "offer",
        }))
        self.assertFalse(result["accepted"])
        self.assertEqual(sent[-1]["action"], "webrtc_reject")
        self.assertEqual(sent[-1]["session_id"], "peer-new")
        self.assertEqual(sent[-1]["stream_id"], "stream-new")
        self.assertEqual(sent[-1]["reason"], "peer_setup_failed")
        self.assertNotIn("sensitive", str(sent))


class TestFallbackAndMailbox(unittest.TestCase):
    def test_webrtc_active_then_automatic_jpeg_fallback(self):
        media = FakeMedia(available=True, active=True, codecs=["h264"])
        api = FakeApi()
        rd = RemoteDesktopStreamer(
            api_client=api,
            token_getter=lambda: "token",
            media_transport=media,
        )
        rd._running = True
        rd._ws_ok = True
        rd._last_capture_mono = 5.0
        rd._dispatch_frame("token", JPEG, 1280, 720, 1)
        self.assertEqual(rd._transport, "webrtc")
        self.assertIsNone(rd._pending_frame)

        media.active = False
        rd._dispatch_frame("token", JPEG, 1280, 720, 2)
        self.assertEqual(rd._transport, "websocket")
        self.assertEqual(rd._pending_frame, JPEG)
        self.assertEqual(api.uploads, 0)

    def test_newest_frame_mailbox_never_builds_backlog(self):
        mailbox = NewestFrameMailbox()
        first = mailbox.publish(b"one", {"seq": 1})
        mailbox.publish(b"two", {"seq": 2})
        latest = mailbox.latest()
        self.assertEqual(latest[1], "jpeg")
        self.assertEqual(latest[2], b"two")
        self.assertEqual(latest[3]["seq"], 2)
        self.assertEqual(mailbox.coalesced, 1)
        self.assertIsNone(mailbox.latest(latest[0]))
        mailbox.publish(b"three", {"seq": 3})
        self.assertEqual(mailbox.coalesced, 1)  # previous frame was consumed
        self.assertGreater(latest[0], first)

    def test_raw_mailbox_payload_kind(self):
        mailbox = NewestFrameMailbox()
        mailbox.publish_raw(b"\x00" * 12, 2, 2, {"seq": 9})
        latest = mailbox.latest()
        self.assertEqual(latest[1], "raw")
        self.assertEqual(latest[2]["width"], 2)
        self.assertEqual(latest[2]["height"], 2)
        self.assertEqual(latest[3]["seq"], 9)


class TestMediaReadiness(unittest.TestCase):
    @staticmethod
    def make_transport():
        transport = AiortcMediaTransport.__new__(AiortcMediaTransport)
        transport.available = True
        transport.active = False
        transport.mailbox = NewestFrameMailbox()
        transport._state_lock = threading.Lock()
        transport._pc_connection_state = "new"
        transport._connection_state = "new"
        transport._ice_state = "new"
        transport._ice_checking_task = None
        transport._codec = ""
        transport._preferred_codec = ""
        transport._error = ""
        transport._session_id = ""
        transport._stream_id = ""
        transport._closing = False
        transport._pc = None
        transport._fallback_handler = lambda _error: None
        return transport

    def test_frame_enters_media_mailbox_only_after_ice_and_dtls_ready(self):
        transport = self.make_transport()
        transport._pc_connection_state = "connected"
        transport._ice_state = "checking"
        with transport._state_lock:
            transport._recompute_media_state_locked()

        self.assertFalse(transport.publish_frame(JPEG, {"seq": 1}))
        self.assertIsNone(transport.mailbox.latest())
        self.assertFalse(transport.status()["active"])
        self.assertEqual(transport.status()["connection_state"], "checking")

        transport._ice_state = "connected"
        with transport._state_lock:
            transport._recompute_media_state_locked()
        self.assertTrue(transport.publish_frame(JPEG, {"seq": 2}))
        self.assertEqual(transport.mailbox.latest()[3]["seq"], 2)
        self.assertTrue(transport.status()["active"])
        self.assertEqual(transport.status()["connection_state"], "connected")

    def test_raw_enters_mailbox_when_media_ready(self):
        transport = self.make_transport()
        transport._pc_connection_state = "connected"
        transport._ice_state = "connected"
        with transport._state_lock:
            transport._recompute_media_state_locked()
        rgb = b"\x01\x02\x03" * (4 * 3)
        self.assertTrue(transport.publish_raw(rgb, 4, 3, {"seq": 7}))
        latest = transport.mailbox.latest()
        self.assertEqual(latest[1], "raw")
        self.assertEqual(latest[2]["width"], 4)
        self.assertEqual(latest[3]["seq"], 7)

    def test_ice_checking_timeout_falls_back_and_closes_peer(self):
        fallback_errors = []

        class Peer:
            def __init__(self):
                self.closed = False

            async def close(self):
                self.closed = True

        async def scenario():
            transport = self.make_transport()
            transport.ICE_CHECKING_TIMEOUT_SEC = 0.01
            transport._fallback_handler = fallback_errors.append
            peer = Peer()
            transport._pc = peer
            await transport._handle_connection_state(peer, "connected")
            await transport._handle_ice_state(peer, "checking")
            self.assertFalse(transport.active)
            self.assertEqual(transport.status()["connection_state"], "checking")
            await asyncio.sleep(0.04)
            self.assertTrue(peer.closed)
            self.assertIsNone(transport._pc)
            self.assertFalse(transport.active)
            self.assertEqual(transport.status()["connection_state"], "failed")
            self.assertEqual(transport.status()["ice_state"], "failed")

        asyncio.run(scenario())
        self.assertEqual(fallback_errors, ["ICE checking timeout"])


class TestDataChannelAndCodec(unittest.TestCase):
    def test_data_channel_routes_full_input_v2_envelope(self):
        received = []
        transport = AiortcMediaTransport.__new__(AiortcMediaTransport)
        transport._input_handler = received.append
        transport._state_lock = threading.Lock()
        transport._error = ""
        payload = {
            "t": "input",
            "protocol": 2,
            "id": "dc-1",
            "input": {"event": "tap", "x": 0.2, "y": 0.4},
        }
        self.assertTrue(transport.route_data_channel_input(json.dumps(payload)))
        self.assertEqual(received, [payload])
        self.assertFalse(transport.route_data_channel_input("not-json"))

    def test_h264_codec_preference_is_stable(self):
        codecs = [
            Codec("video/VP8"),
            Codec("video/H264"),
            Codec("video/rtx"),
            Codec("video/H264"),
        ]
        ordered = prefer_h264_codecs(codecs)
        self.assertEqual([codec_name(item) for item in ordered], [
            "h264", "h264", "vp8", "rtx",
        ])


class TestIceServerConfiguration(unittest.TestCase):
    class FakeIceServer:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

    class FakeConfiguration:
        def __init__(self, iceServers):
            self.iceServers = iceServers

    @classmethod
    def runtime(cls):
        return {
            "RTCIceServer": cls.FakeIceServer,
            "RTCConfiguration": cls.FakeConfiguration,
        }

    def test_validates_and_converts_stun_turn_and_turns(self):
        validated = validate_ice_servers([
            {"urls": "stun:stun.example.test:3478"},
            {
                "urls": [
                    "turn:turn.example.test:3478?transport=udp",
                    "turns:turn.example.test:5349?transport=tcp",
                ],
                "username": "agent-user",
                "credential": "top-secret",
            },
        ])
        config = build_ice_configuration(validated, self.runtime())
        self.assertEqual(len(config.iceServers), 2)
        self.assertEqual(
            config.iceServers[0].kwargs["urls"],
            "stun:stun.example.test:3478",
        )
        self.assertEqual(
            config.iceServers[1].kwargs["credential"], "top-secret"
        )

    def test_rejects_malformed_oversized_and_unsafe_values(self):
        invalid = [
            "not-a-list",
            [{"urls": "https://unsafe.example.test"}],
            [{"urls": "turn:"}],
            [{"urls": []}],
            [{"urls": ["stun:ok"] * 9}],
            [{"urls": "stun:bad host"}],
            [{"urls": "stun:ok", "unknown": "x"}],
            [{"urls": "stun:ok"}] * 9,
            [{"urls": "stun:" + ("x" * 600)}],
            [{"urls": "turn:ok", "username": "u" * 257}],
            [{"urls": "turn:ok", "credential": "c" * 513}],
        ]
        for value in invalid:
            with self.subTest(value=type(value).__name__):
                with self.assertRaises(IceServerValidationError):
                    validate_ice_servers(value)

    def test_validation_errors_never_echo_credentials(self):
        secret = "credential-do-not-echo"
        try:
            validate_ice_servers([{
                "urls": "https://unsafe.example.test",
                "credential": secret,
            }])
        except IceServerValidationError as exc:
            self.assertNotIn(secret, str(exc))
        else:
            self.fail("unsafe ICE URL accepted")

        class ExplodingConfiguration:
            def __init__(self, iceServers):
                raise RuntimeError(repr(iceServers[0].kwargs))

        transport = AiortcMediaTransport.__new__(AiortcMediaTransport)
        transport._runtime = {
            "RTCIceServer": self.FakeIceServer,
            "RTCConfiguration": ExplodingConfiguration,
        }
        transport._loop = None
        transport._ready = threading.Event()
        result = transport.handle_signal({
            "action": "offer",
            "ice_servers": [{
                "urls": "turn:turn.example.test",
                "username": "u",
                "credential": secret,
            }],
        })
        self.assertFalse(result["accepted"])
        self.assertNotIn(secret, json.dumps(result))

    def test_validated_configuration_reaches_fake_peer(self):
        created = []

        class FakePeer:
            def __init__(self, **kwargs):
                self.configuration = kwargs.get("configuration")
                self.connectionState = "new"
                self.iceConnectionState = "new"
                created.append(self)

            async def close(self):
                return None

            def addTrack(self, _track):
                return None

            def on(self, _event):
                return lambda callback: callback

        class FakeVideoTrack:
            def __init__(self):
                return None

        validated = validate_ice_servers([{
            "urls": "turns:turn.example.test:5349",
            "username": "user",
            "credential": "secret",
        }])
        runtime = {
            **self.runtime(),
            "RTCPeerConnection": FakePeer,
            "VideoStreamTrack": FakeVideoTrack,
        }
        configuration = build_ice_configuration(validated, runtime)
        transport = AiortcMediaTransport.__new__(AiortcMediaTransport)
        transport._runtime = runtime
        transport._pc = None
        transport._closing = False
        transport.active = False
        transport.mailbox = NewestFrameMailbox()
        transport._state_lock = threading.Lock()
        transport._connection_state = "new"
        transport._ice_state = "new"
        transport._session_id = ""
        transport._stream_id = ""
        transport._error = ""
        transport._codec = ""
        transport._preferred_codec = ""
        transport._fallback_handler = lambda _error: None
        asyncio.run(transport._create_peer(
            "peer-a", "stream-a", configuration=configuration
        ))
        self.assertIs(created[-1].configuration, configuration)
        self.assertEqual(
            created[-1].configuration.iceServers[0].kwargs["username"],
            "user",
        )

    def test_absent_ice_servers_uses_default_peer_configuration(self):
        calls = []

        class FakePeer:
            def __init__(self, **kwargs):
                calls.append(kwargs)
                self.connectionState = "new"
                self.iceConnectionState = "new"

            async def close(self):
                return None

            def addTrack(self, _track):
                return None

            def on(self, _event):
                return lambda callback: callback

        class FakeVideoTrack:
            pass

        transport = AiortcMediaTransport.__new__(AiortcMediaTransport)
        transport._runtime = {
            "RTCPeerConnection": FakePeer,
            "VideoStreamTrack": FakeVideoTrack,
        }
        transport._pc = None
        transport._closing = False
        transport.active = False
        transport.mailbox = NewestFrameMailbox()
        transport._state_lock = threading.Lock()
        transport._session_id = ""
        transport._stream_id = ""
        transport._fallback_handler = lambda _error: None
        asyncio.run(transport._create_peer("peer-a", "stream-a"))
        self.assertEqual(calls[-1], {})


if __name__ == "__main__":
    unittest.main()
