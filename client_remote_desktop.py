#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Asteria Client — Remote Desktop Screen Mirror

Dashboard “Uzak Masaüstü” — akıcı WebSocket + HTTP fallback.

Primary:
  wss://…/ws/remote/agent  + Authorization: Bearer …  → binary JPEG + JSON meta/input
  (legacy: ?token= only if api.legacy_token_query=true)
Fallback:
  POST /api/remote/frame (+ frame-json) — ACK may include inputs[] (primary input path)
  GET  /api/remote/inputs (200–500 ms) backup when queue not drained via frame ACK

Commands:
  remote_stream_start / remote_stream_stop / remote_input
"""

from __future__ import annotations

import io
import json
import threading
import time
import uuid
from collections import deque
from typing import Callable, Optional, Tuple
from urllib.parse import urlencode

from client_helpers import log
from client_rd_adaptive import AdaptiveStreamController

# Defaults tuned for smooth dashboard viewing (prompt: 5–10 fps, q~30–40)
DEFAULT_FPS = 6.0
DEFAULT_QUALITY = 35
DEFAULT_MAX_WIDTH = 1280
MIN_ENCODE_WIDTH = 800
MIN_ENCODE_HEIGHT = 600
TARGET_FRAME_BYTES = 320 * 1024       # aim ≤ ~320 KB
MAX_FRAME_BYTES = 2 * 1024 * 1024
IDLE_STOP_SECONDS = 300
INPUT_RATE_LIMIT = 60                 # legacy alias (kept for backward compat)
INPUT_RATE_WINDOW = 1.0
MOVE_RATE_LIMIT = 120                 # absolute/relative pointer moves per window
MOVE_RATE_WINDOW = 1.0
CRIT_RATE_LIMIT = 240                 # critical edges: tracked but never rejected
HTTP_INPUT_POLL_SEC = 0.30            # WS down → poll fast (primary input path)
HTTP_INPUT_POLL_SEC_WS = 2.0          # WS healthy → poll slowly (compat backup only)
CRIT_ACK_TIMEOUT = 0.08              # short synchronous ACK for critical edges only
OUT_TEXT_MAXLEN = 32                  # retained control/meta frames (latest-frame queue)
WS_RECONNECT_SEC = 3.0
META_EVERY_N_FRAMES = 5
BLACK_MEAN_THRESHOLD = 6.0            # nearly-black capture → skip send
HTTP_KEYFRAME_EVERY = 6               # also POST HTTP every N frames (dashboard cache)
MIN_JPEG_BYTES = 1500                 # API rejects tinier frames ("Frame too small")
MIN_GOOD_JPEG_BYTES = 5 * 1024        # healthy 1280q35 frame is usually ≥5KB
CAPTURE_FAIL_SECONDS = 10.0           # no frames in this window → fail stream
WINLOGON_BLACK_FAIL_SECONDS = 2.0     # C-RD-P0-WL-4: unbroken black → fail
PROBE_TIMEOUT_SEC = 12.0              # SYSTEM→user CreateProcessAsUser needs cold-start room

# Absolute pointer moves (normalized 0..1). Subject to the move budget only.
ABS_MOVE_EVENTS = frozenset({"move", "mousemove"})
# Relative pointer moves (dx/dy). Subject to the move budget only.
REL_MOVE_EVENTS = frozenset({
    "move_relative", "mousemove_relative", "rmove", "trackpad_move",
})


def _is_relative_pointer(event: str, params: dict) -> bool:
    if event in REL_MOVE_EVENTS:
        return True
    if event == "pointer" and str(params.get("mode") or "").lower() == "relative":
        return True
    if event == "drag_move" and str(params.get("mode") or "").lower() in (
        "relative", "trackpad",
    ):
        return True
    return False


def _is_move_event(event: str, params: dict) -> bool:
    if event in ABS_MOVE_EVENTS:
        return True
    if event == "pointer":
        return True
    if event == "drag_move":
        return True
    return _is_relative_pointer(event, params)


def _api_to_ws_agent_url(api_base: str, token: str = "") -> str:
    """https://host/api → wss://host/ws/remote/agent (Bearer via header).

    If api.legacy_token_query is enabled, appends ?token= for old servers.
    """
    base = (api_base or "").strip().rstrip("/")
    if base.lower().endswith("/api"):
        origin = base[:-4]
    else:
        origin = base
    if origin.startswith("https://"):
        ws = "wss://" + origin[len("https://"):]
    elif origin.startswith("http://"):
        ws = "ws://" + origin[len("http://"):]
    else:
        ws = "wss://" + origin.lstrip("/")
    url = f"{ws}/ws/remote/agent"
    try:
        from client_security_utils import use_legacy_token_query
        if token and use_legacy_token_query():
            return f"{url}?{urlencode({'token': token})}"
    except Exception:
        pass
    return url


class RemoteDesktopStreamer:
    """Captures primary screen; streams via WebSocket (preferred) or HTTP."""

    def __init__(
        self,
        api_client=None,
        token_getter: Optional[Callable[[], str]] = None,
        media_transport=None,
    ):
        self.api_client = api_client
        self.token_getter = token_getter or (lambda: "")

        self._lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._ws_thread: Optional[threading.Thread] = None
        self._input_poll_thread: Optional[threading.Thread] = None
        self._stop = threading.Event()

        self._fps = DEFAULT_FPS
        self._quality = DEFAULT_QUALITY
        self._max_width = DEFAULT_MAX_WIDTH
        self._requested_fps = DEFAULT_FPS
        self._requested_quality = DEFAULT_QUALITY
        self._requested_max_width = DEFAULT_MAX_WIDTH
        # WebRTC capture pacing is independent from JPEG-era stream knobs.
        self._media_fps = 45.0
        self._media_quality = 78
        self._media_mode_applied = False
        self._dxcam = None
        self._last_raw_hash = b""
        self._idle_skip_streak = 0
        self._adaptive = AdaptiveStreamController(
            DEFAULT_FPS, DEFAULT_QUALITY, DEFAULT_MAX_WIDTH
        )
        self._seq = 0
        self._last_activity = 0.0
        self._screen_w = 0
        self._screen_h = 0
        self._screen_x = 0
        self._screen_y = 0
        self._capture_w = 0
        self._capture_h = 0
        # Session-locked encode size — adaptive must not thrash dashboard WxH.
        self._locked_encode_w = 0
        self._locked_encode_h = 0
        self._last_capture_mono = 0.0
        self._last_send_mono = 0.0
        self._last_helper_capture_ms = 0.0
        self._stream_id = ""
        self._media_session_id = ""
        # Contract 1.4.39 — agent → viewer stage honesty (C-RD-PROG-*)
        self._command_id = ""
        self._progress_times: deque = deque(maxlen=16)
        self._progress_last_emit = 0.0
        self._progress_last_phase = ""
        self._progress_live_emitted = False
        self._control_progress_send = None  # Optional[Callable[[dict], bool]]

        self._ws = None
        self._ws_ok = False
        self._transport = "idle"  # idle | websocket | http
        # Latest-frame outbound semantics: control/meta retained in order,
        # only the newest JPEG kept (stale frames coalesced away).
        self._out_lock = threading.Lock()
        self._pending_text: deque = deque(maxlen=OUT_TEXT_MAXLEN)
        self._pending_frame: Optional[bytes] = None
        self._ws_send_lock = threading.Lock()
        self._black_warn_ts = 0.0
        self._black_streak_started = 0.0
        self._winlogon_black_retried = False
        self._last_stream_error = ""
        self._capture_method = "none"
        self._stream_started_at = 0.0
        self._use_user_helper = False  # Session 0 / other session → CreateProcessAsUser helper
        self._session_helper = None     # persistent authenticated loopback bridge
        self._helper_frame_id = 0
        self._helper_frame_misses = 0
        self._input_desktop = None
        self._desktop_attached = False
        self._desktop_name = ""
        self._winlogon_mode = False
        self._desktop_reattach_every = 45  # frames — pick up Default after logon
        self._tscon_attempted = False
        self._last_good_jpeg: Optional[bytes] = None
        self._last_good_wh: Tuple[int, int] = (0, 0)
        # Dashboard session picker (AGENT_REMOTE_SESSION_SELECT_PROMPT)
        self._target_session_id: Optional[int] = None
        self._target_username: str = ""
        self._monitor_index: int = 0

        # Separate budgets so pointer floods never starve critical edges.
        self._move_ts: deque = deque(maxlen=MOVE_RATE_LIMIT * 4)
        self._crit_ts: deque = deque(maxlen=CRIT_RATE_LIMIT * 2)
        # Pressed mouse buttons on the injecting side (stuck-button guard).
        self._pressed_buttons: set = set()
        self._drag_active = False
        self._drag_button = "left"
        self._drag_mode = "direct"
        self._last_px = 0
        self._last_py = 0
        self._stats = {
            "frames_sent": 0,            # actual transmissions (WS send or HTTP upload)
            "frames_failed": 0,
            "bytes_sent": 0,
            "frames_coalesced": 0,       # stale JPEGs dropped from outbound queue
            "moves_coalesced": 0,        # pointer moves folded before apply/forward
            "inputs_applied": 0,
            "inputs_piggyback": 0,
            "inputs_rate_limited": 0,
            "ws_reconnects": 0,
            "http_fallbacks": 0,
            "black_frames": 0,
            "capture_method": "none",
        }

        if media_transport is None:
            try:
                from client_rd_media import create_optional_media_transport
                media_transport = create_optional_media_transport(
                    signal_sender=self._send_media_signal,
                    input_handler=self._ingest_data_channel_input,
                    fallback_handler=self._on_media_fallback,
                )
            except Exception:
                media_transport = None
        if media_transport is None:
            from client_rd_media import OptionalMediaTransport
            media_transport = OptionalMediaTransport()
        self._media = media_transport

        self._ensure_dpi_aware()

    # ── Public API ────────────────────────────────────────────────

    def set_control_progress_sender(self, fn) -> None:
        """Optional control-WS fallback when RD agent socket is not up yet."""
        self._control_progress_send = fn if callable(fn) else None

    def emit_stream_progress(
        self,
        phase: str,
        message: str = "",
        *,
        error: str = "",
        command_id: Optional[str] = None,
        force: bool = False,
    ) -> bool:
        """Emit ``t: stream_progress`` on RD agent WS (queue) ± control WS.

        C-RD-PROG-1/3 · rate-limit ≤4/s · coalesce noisy repeats.
        """
        phase_l = str(phase or "").strip().lower()
        if not phase_l:
            return False
        # C-RD-PROG-4: never advertise live for black-fill-only capture
        if phase_l in ("live", "connected") and "+black" in (self._capture_method or ""):
            return False
        if phase_l in ("live", "connected") and self._progress_live_emitted and not force:
            return False

        now = time.time()
        # Drop oldest outside the 1s window
        while self._progress_times and (now - self._progress_times[0]) > 1.0:
            self._progress_times.popleft()
        if not force and len(self._progress_times) >= 4:
            return False
        # Coalesce identical phase spam (ICE ticks etc.) unless message/error changed
        if (
            not force
            and phase_l == self._progress_last_phase
            and not error
            and (now - self._progress_last_emit) < 0.4
        ):
            return False

        cid = str(command_id if command_id is not None else (self._command_id or "")).strip()
        payload = {
            "t": "stream_progress",
            "protocol": 1,
            "stream_id": str(self._stream_id or ""),
            "command_id": cid,
            "phase": phase_l,
            "message": str(message or "")[:240],
            "ts": int(now * 1000),
        }
        if error:
            payload["error"] = str(error)[:120]

        sent = False
        try:
            raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
            # Queue for RD agent WS flush (cloud relays /ws/remote/agent → viewers).
            self._q_put_text(raw)
            sent = True
        except Exception as exc:
            log(f"[REMOTE-DESKTOP] stream_progress queue error: {exc}")

        # Fallback: control WS (may not be relayed to viewers today — still useful)
        if self._control_progress_send is not None:
            try:
                if self._control_progress_send(payload):
                    sent = True
            except Exception:
                pass

        if sent:
            self._progress_times.append(now)
            self._progress_last_emit = now
            self._progress_last_phase = phase_l
            if phase_l in ("live", "connected"):
                self._progress_live_emitted = True
            if phase_l in ("failed", "error"):
                self._last_stream_error = str(error or message or phase_l)[:160]
        return sent

    def _progress_heartbeat_tick(self) -> None:
        """C-RD-PROG-2: never silent >3s while start/capture is still in flight."""
        if not self._running:
            return
        if self._progress_live_emitted:
            return
        if (time.time() - float(self._progress_last_emit or 0)) < 2.5:
            return
        frames = int(self._stats.get("frames_sent") or 0)
        if frames <= 0:
            self.emit_stream_progress(
                "capturing",
                "Waiting for first real frame…",
            )
        else:
            self.emit_stream_progress("streaming", f"frames_sent={frames}")

    def start(self, fps: float = DEFAULT_FPS, quality: int = DEFAULT_QUALITY,
              max_width: int = DEFAULT_MAX_WIDTH,
              session_id: Optional[int] = None,
              username: Optional[str] = None,
              monitor: int = 0,
              prefer: Optional[str] = None,
              desktop: Optional[str] = None,
              pre_logon: Optional[bool] = None,
              command_id: Optional[str] = None) -> dict:
        """Start capture + WS (with HTTP fallback).

        Honest start: resolve WTS session_id, probe desktop first.
        No interactive sessions → NO_INTERACTIVE_SESSION.
        screen/capture 0×0 → CAPTURE_NO_DESKTOP.

        ``prefer=winlogon`` / ``desktop=winlogon`` / ``pre_logon=true`` selects
        the console Logon/Lock surface even when a user session shares the id.
        """
        prefer_l = str(prefer or "").strip().lower()
        desktop_l = str(desktop or "").strip().lower()
        want_winlogon = bool(
            prefer_l in ("winlogon", "console", "pre_logon", "pre-logon")
            or desktop_l in ("winlogon",)
            or pre_logon is True
        )
        with self._lock:
            self._command_id = str(command_id or "").strip()
            self._stream_id = uuid.uuid4().hex
            self._progress_live_emitted = False
            self._progress_last_phase = ""
            self._progress_last_emit = 0.0
            self._progress_times.clear()
            self._drain_out_q()
            self.emit_stream_progress(
                "running",
                "remote_stream_start received",
                force=True,
            )
            self._requested_fps = max(1.0, min(float(fps or DEFAULT_FPS), 30.0))
            self._requested_quality = max(20, min(int(quality or DEFAULT_QUALITY), 85))
            self._requested_max_width = max(
                MIN_ENCODE_WIDTH, min(int(max_width or DEFAULT_MAX_WIDTH), 1920)
            )
            if self._running:
                self._adaptive.update_requested(
                    self._requested_fps,
                    self._requested_quality,
                    self._requested_max_width,
                )
            else:
                self._adaptive.reset(
                    self._requested_fps,
                    self._requested_quality,
                    self._requested_max_width,
                )
                self._locked_encode_w = 0
                self._locked_encode_h = 0
            self._apply_effective_settings(self._adaptive.effective, notify_helper=False)
            try:
                self._monitor_index = max(0, int(monitor or 0))
            except (TypeError, ValueError):
                self._monitor_index = 0
            self._seq = 0
            self._last_activity = time.time()
            self._stop.clear()
            self._stats["frames_sent"] = 0
            self._stats["bytes_sent"] = 0
            self._stats["frames_failed"] = 0
            self._stats["black_frames"] = 0
            self._desktop_attached = False
            self._desktop_name = ""
            self._winlogon_mode = False
            self._tscon_attempted = False
            self._black_streak_started = 0.0
            self._winlogon_black_retried = False
            self._last_stream_error = ""
            self._last_good_jpeg = None
            self._last_good_wh = (0, 0)
            self._use_user_helper = False
            self._helper_frame_id = 0
            self._helper_frame_misses = 0
            self._media_mode_applied = False
            self._drag_active = False

            # ── Resolve target WTS session (dashboard picker) ──
            sessions = self._enumerate_sessions()
            interactive = [
                s for s in sessions
                if int(s.get("session_id") or 0) > 0
                and str(s.get("protocol") or "").lower() != "services"
            ]
            if not interactive:
                # Pre-logon: query user is empty, but console Winlogon still exists.
                try:
                    from client_rd_winlogon import synthesize_console_session
                    synth = synthesize_console_session(sessions)
                    if synth:
                        interactive = [synth]
                        sessions = list(sessions) + [synth]
                except Exception as exc:
                    log(f"[REMOTE-DESKTOP] console synthesize failed: {exc}")
            if not interactive:
                err = "NO_INTERACTIVE_SESSION"
                msg = "No interactive desktop to mirror"
                log(f"[REMOTE-DESKTOP] ✖ {err}: {msg}")
                self._running = False
                self._transport = "idle"
                self._target_session_id = None
                self._target_username = ""
                self.emit_stream_progress("failed", msg, error=err, force=True)
                return {
                    "success": False,
                    "error": err,
                    "message": msg,
                    "data": self.get_status(),
                }

            # C-RD-CON-3: Winlogon / Logon path never binds a username (Default stick).
            bind_username = None if want_winlogon else username

            resolved_sid: Optional[int] = None
            if session_id is not None:
                try:
                    resolved_sid = int(session_id)
                except (TypeError, ValueError):
                    resolved_sid = None
            if resolved_sid is not None:
                same_sid = [
                    s for s in interactive
                    if int(s.get("session_id") or 0) == resolved_sid
                ]
                match = self._select_session_row(
                    same_sid, want_winlogon=want_winlogon, username=bind_username
                )
                if match is None:
                    err = "NO_INTERACTIVE_SESSION"
                    msg = f"Requested session_id={resolved_sid} not in interactive session list"
                    log(f"[REMOTE-DESKTOP] ✖ {err}: {msg}")
                    self.emit_stream_progress("failed", msg, error=err, force=True)
                    return {
                        "success": False,
                        "error": err,
                        "message": msg,
                        "data": self.get_status(),
                    }
                self._target_session_id = resolved_sid
                if want_winlogon or match.get("pre_logon"):
                    self._target_username = ""
                else:
                    self._target_username = (
                        (bind_username or "").strip()
                        or str(match.get("username") or "")
                    )
            else:
                # C-RD-CON-2: omit session_id → WTSGetActiveConsoleSessionId (never SID=1).
                if want_winlogon:
                    try:
                        from client_rd_winlogon import console_session_id
                        csid = int(console_session_id() or 0)
                    except Exception:
                        csid = 0
                    if csid > 0:
                        same_sid = [
                            s for s in interactive
                            if int(s.get("session_id") or 0) == csid
                        ]
                        if not same_sid:
                            same_sid = [
                                s for s in interactive if s.get("pre_logon")
                            ] or interactive
                        picked = self._select_session_row(
                            same_sid, want_winlogon=True, username=None
                        ) or same_sid[0]
                        self._target_session_id = csid
                        self._target_username = ""
                        match = picked
                        log(
                            f"[REMOTE-DESKTOP] winlogon omit-sid → console "
                            f"WTSGetActiveConsoleSessionId={csid}"
                        )
                    else:
                        pre_rows = [s for s in interactive if s.get("pre_logon")]
                        pool = pre_rows or interactive
                        picked = self._pick_default_session(pool)
                        self._target_session_id = int(picked["session_id"])
                        self._target_username = ""
                        match = picked
                else:
                    picked = self._pick_default_session(interactive)
                    self._target_session_id = int(picked["session_id"])
                    self._target_username = (
                        (bind_username or "").strip()
                        or str(picked.get("username") or "")
                    )
                    match = picked

            match_meta = match if isinstance(match, dict) else {}
            self._winlogon_mode = bool(
                want_winlogon
                or match_meta.get("pre_logon")
                or (
                    not str(self._target_username or "").strip()
                    and str(match_meta.get("desktop") or "").lower() == "winlogon"
                )
                or str(match_meta.get("desktop") or "").lower() == "winlogon"
            )
            if self._winlogon_mode:
                self._target_username = ""

            pid_sid, csid = self._session_ids()
            # Capture other user's desktop via helper when not already in that session.
            # Pre-logon / Winlogon must stay in-process (WinSta0 attach) — no user helper.
            need_helper = (
                not self._winlogon_mode
                and self._target_session_id is not None
                and (pid_sid is None or int(pid_sid) != int(self._target_session_id))
            )
            log(
                f"[REMOTE-DESKTOP] start — target_session={self._target_session_id} "
                f"user={self._target_username!r} monitor={self._monitor_index} "
                f"pid_session={pid_sid} console={csid} helper={need_helper} "
                f"winlogon={self._winlogon_mode}"
            )
            self.emit_stream_progress(
                "capture_start",
                (
                    "Attaching Winlogon desktop…"
                    if self._winlogon_mode
                    else f"Attaching session {self._target_session_id}…"
                ),
                force=True,
            )

            if self._running and self._thread and self._thread.is_alive():
                st = self.get_status()
                same_sid = st.get("session_id") == self._target_session_id
                if same_sid and (st.get("screen") or {}).get("w", 0) > 0:
                    if self._persistent_helper_connected():
                        self._session_helper.update_config({
                            "fps": self._fps,
                            "quality": self._quality,
                            "max_width": self._max_width,
                            "monitor": self._monitor_index,
                        })
                    log(f"[REMOTE-DESKTOP] Already streaming — params updated "
                        f"(fps={self._fps} q={self._quality} w={self._max_width})")
                    return {
                        "success": True,
                        "message": "stream already active; params updated",
                        "data": st,
                    }
                # Different session or dead capture — restart
                self._running = False
                self._stop.set()

            sid, csid = pid_sid, csid
            self._stop_persistent_helper()
            state = self._session_connect_state(self._target_session_id)
            log(f"[REMOTE-DESKTOP] start probe — target={self._target_session_id} "
                f"state={state} pid_session={sid}")

            jpeg, w, h = None, 0, 0
            helper_err = ""
            if need_helper:
                t_helper = time.time()
                persistent_started = self._start_persistent_helper()
                if persistent_started:
                    jpeg, w, h = self._grab_via_persistent_helper(PROBE_TIMEOUT_SEC)
                if (
                    not persistent_started
                    or not jpeg
                    or w <= 0
                    or h <= 0
                    or len(jpeg) < MIN_JPEG_BYTES
                ):
                    self._stop_persistent_helper()
                    log(
                        "[REMOTE-DESKTOP] persistent helper failed start/probe; "
                        "falling back to legacy one-shot capture"
                    )
                    jpeg, w, h = self._grab_via_user_helper()
                took = time.time() - t_helper
                log(f"[REMOTE-DESKTOP] helper probe took {took:.1f}s "
                    f"jpeg={0 if not jpeg else len(jpeg)}B {w}x{h}")
                if not jpeg or w <= 0 or h <= 0 or len(jpeg) < MIN_JPEG_BYTES:
                    helper_err = (
                        f"user-helper failed for session={self._target_session_id} "
                        f"(jpeg={0 if not jpeg else len(jpeg)}B, {took:.1f}s). "
                        "Agent is Session 0 — capture requires WTSQueryUserToken/"
                        "CreateProcessAsUser into the selected RDP/console session."
                    )
                    # Do NOT fall back to Session-0 BitBlt (always black for other sessions)
                    err = "CAPTURE_NO_DESKTOP"
                    msg = helper_err
                    log(f"[REMOTE-DESKTOP] ✖ {err}: {msg}")
                    self._running = False
                    self._transport = "idle"
                    self.emit_stream_progress("failed", msg, error=err, force=True)
                    return {
                        "success": False,
                        "error": err,
                        "message": msg,
                        "data": self.get_status(),
                    }
            else:
                # Capture thread-less probe: attach input desktop first (RDP/elevated)
                self._attach_input_desktop()
                self.emit_stream_progress("prepare", "Input desktop attach / probe")
                if state in ("Disconnected", "Down", "Init"):
                    self._try_reconnect_session_to_console(self._target_session_id)

                # Probe BEFORE advertising streaming=true
                jpeg, w, h = self._grab_jpeg()
                blackish = "+black" in (self._capture_method or "")
                if blackish or not jpeg:
                    # One more attempt after forced console reconnect
                    if not self._tscon_attempted:
                        self._try_reconnect_session_to_console(self._target_session_id)
                        time.sleep(0.4)
                        self._desktop_attached = False
                        self._attach_input_desktop()
                        jpeg, w, h = self._grab_jpeg()
                        blackish = "+black" in (self._capture_method or "")
                if self._winlogon_mode and (
                    blackish or not jpeg or w <= 0 or h <= 0
                    or (jpeg and len(jpeg) < MIN_JPEG_BYTES)
                ):
                    self._desktop_attached = False
                    self._attach_input_desktop()
                    jpeg, w, h = self._grab_jpeg()
                    blackish = "+black" in (self._capture_method or "")
                    if (
                        blackish
                        or not jpeg
                        or w <= 0
                        or h <= 0
                        or len(jpeg) < MIN_JPEG_BYTES
                    ):
                        err = "winlogon_capture_black"
                        msg = (
                            "Winlogon/GDI capture returned unbroken black "
                            f"(method={self._capture_method})"
                        )
                        log(f"[REMOTE-DESKTOP] ✖ {err}: {msg}")
                        self._last_stream_error = err
                        self._running = False
                        self._transport = "idle"
                        self.emit_stream_progress("failed", msg, error=err, force=True)
                        return {
                            "success": False,
                            "error": err,
                            "message": msg,
                            "data": self.get_status(),
                        }
                elif not jpeg or w <= 0 or h <= 0 or len(jpeg) < MIN_JPEG_BYTES or blackish:
                    jpeg2, w2, h2 = self._grab_via_user_helper()
                    if jpeg2 and w2 > 0 and h2 > 0 and len(jpeg2) >= MIN_JPEG_BYTES:
                        jpeg, w, h = jpeg2, w2, h2

            if not jpeg or w <= 0 or h <= 0 or len(jpeg) < MIN_JPEG_BYTES:
                err = "CAPTURE_NO_DESKTOP"
                msg = (
                    "No interactive desktop bitmap "
                    f"(session={self._target_session_id}, size={w}x{h}, "
                    f"jpeg={0 if not jpeg else len(jpeg)}B)."
                )
                log(f"[REMOTE-DESKTOP] ✖ {err}: {msg}")
                self._running = False
                self._transport = "idle"
                self.emit_stream_progress("failed", msg, error=err, force=True)
                return {
                    "success": False,
                    "error": err,
                    "message": msg,
                    "data": self.get_status(),
                }

            if need_helper or self._use_user_helper:
                self._use_user_helper = True

            self._screen_w = self._screen_w or w
            self._screen_h = self._screen_h or h
            self._capture_w, self._capture_h = w, h
            log(f"[REMOTE-DESKTOP] probe ok — screen={self._screen_w}x{self._screen_h} "
                f"capture={w}x{h} jpeg={len(jpeg)}B method={self._capture_method} "
                f"session={self._target_session_id}")
            self.emit_stream_progress(
                "capturing",
                f"Probe frame ready {w}x{h}",
                force=True,
            )

            # stream_id already assigned at start() entry for progress correlation
            self._media_session_id = ""
            self._running = True
            self._transport = "http"
            self._stream_started_at = time.time()
            if self._use_user_helper:
                if not self._persistent_helper_connected():
                    # Legacy CreateProcessAsUser-per-frame fallback is expensive.
                    self._fps = min(self._fps, 2.0)

            self._thread = threading.Thread(
                target=self._capture_loop,
                name="RemoteDesktopCapture",
                daemon=True,
            )
            self._thread.start()
            self._ws_thread = threading.Thread(
                target=self._ws_loop,
                name="RemoteDesktopWS",
                daemon=True,
            )
            self._ws_thread.start()
            self._input_poll_thread = threading.Thread(
                target=self._http_input_poll_loop,
                name="RemoteDesktopHttpInput",
                daemon=True,
            )
            self._input_poll_thread.start()

            # Push probe frame immediately so dashboard is not blank for 1s
            try:
                token = self.token_getter()
                if token and jpeg:
                    self._last_good_jpeg = jpeg
                    self._last_good_wh = (w, h)
                    self._enqueue_ws_frame(jpeg, w, h, 0)
                    if self._http_send_frame(token, jpeg, w, h, 0):
                        self._stats["frames_sent"] = 1
                        self._stats["bytes_sent"] = len(jpeg)
                        self._last_activity = time.time()
                    if "+black" not in (self._capture_method or ""):
                        self.emit_stream_progress(
                            "live",
                            "First real frame on the wire",
                            force=True,
                        )
            except Exception:
                pass

            log(f"[REMOTE-DESKTOP] ▶ Stream started "
                f"(fps={self._fps} q={self._quality} max_w={self._max_width} "
                f"session={self._target_session_id} ws+http)")
            return {
                "success": True,
                "message": "remote stream started (websocket preferred)",
                "data": self.get_status(),
            }

    def stop(self, reason: str = "user") -> dict:
        """Stop capture + websocket."""
        with self._lock:
            was = self._running
            self._running = False
            self._stop.set()
        # Release any locally-held buttons so a drag can't leave one stuck.
        try:
            self._release_all_buttons()
        except Exception:
            pass
        try:
            self._media.stop()
        except Exception:
            pass
        try:
            if self._dxcam is not None:
                self._dxcam.stop()
        except Exception:
            pass
        self._dxcam = None
        self._media_session_id = ""
        self._last_raw_hash = b""
        self._idle_skip_streak = 0
        self._locked_encode_w = 0
        self._locked_encode_h = 0
        self._stop_persistent_helper()
        self._close_ws()
        self._transport = "idle"
        if was:
            log(f"[REMOTE-DESKTOP] ⏹ Stream stopped ({reason})")
        return {
            "success": True,
            "message": f"remote stream stopped ({reason})",
            "data": self.get_status(),
        }

    def is_streaming(self) -> bool:
        return self._running

    def get_status(self) -> dict:
        media = self._media.status()
        media_ready = self._media_ready()
        media["effective_capture_fps"] = (
            self._media_fps if media_ready else self._fps
        )
        media["capture_quality"] = (
            self._media_quality if media_ready else self._quality
        )
        media.setdefault("encoder", "aiortc" if media.get("available") else "")
        media.setdefault("target_bitrate_bps", None)
        # C-RD-P0-ICE-3: JPEG-WS stays active until ICE+DTLS verified.
        media["jpeg_fallback_active"] = bool(not media_ready)
        return {
            "streaming": self._running,
            "transport": self._transport,
            "websocket": self._ws_ok,
            "fps": self._fps,
            "quality": self._quality,
            "max_width": self._max_width,
            "requested": {
                "fps": self._requested_fps,
                "quality": self._requested_quality,
                "max_width": self._requested_max_width,
            },
            "effective": {
                "fps": self._media_fps if media_ready else self._fps,
                "quality": self._media_quality if media_ready else self._quality,
                "max_width": self._max_width,
            },
            "seq": self._seq,
            "session_id": self._target_session_id,
            "stream_id": self._stream_id,
            "username": self._target_username or "",
            "monitor": self._monitor_index,
            "capture_method": self._capture_method,
            "black_frame": bool(
                "+black" in (self._capture_method or "")
                or self._black_streak_started > 0
            ),
            "desktop": self._desktop_name or "",
            "winlogon_mode": bool(self._winlogon_mode),
            "last_error": self._last_stream_error or "",
            "screen": {
                "x": self._screen_x,
                "y": self._screen_y,
                "w": self._screen_w,
                "h": self._screen_h,
            },
            "capture": {"w": self._capture_w, "h": self._capture_h},
            "telemetry": {
                **self._adaptive.snapshot()["metrics"],
                "last_capture_mono_ms": int(self._last_capture_mono * 1000),
                "last_send_mono_ms": int(self._last_send_mono * 1000),
            },
            "media": media,
            "capabilities": self._capabilities(),
            "stats": dict(self._stats),
        }

    def apply_input(self, params: dict) -> dict:
        """Apply one remote input event (WS message, command, or coalesced batch).

        Move events draw from a dedicated move budget; critical edge events
        (button/wheel/key/SAS) are never rejected by move rate limiting.
        """
        params = self._normalize_input_envelope(params)

        def result(value: dict) -> dict:
            if params.get("_input_id") is not None:
                value["id"] = params["_input_id"]
            if params.get("_protocol") == 2:
                value["protocol"] = 2
            return value

        if not self._running:
            return result({"success": False, "error": "stream not active"})

        event = (params.get("event") or "").strip().lower()
        move_like = _is_move_event(event, params)
        if move_like:
            if not self._check_move_rate():
                self._stats["inputs_rate_limited"] += 1
                return result({"success": False, "error": "move rate limited"})
        else:
            # Critical edge — tracked for stats but never dropped.
            self._note_critical()

        self._touch_activity()

        try:
            if not move_like:
                # Self-check log (AGENT_REMOTE_KEYBOARD_PROMPT); moves stay quiet.
                log(
                    f"[remote-input] t=input event={event or '?'} "
                    f"key_present={bool(params.get('key'))} "
                    f"text_len={len(str(params.get('text') or ''))} "
                    f"session={self._target_session_id}"
                )
            if self._persistent_helper_connected():
                # Forward over the full-duplex helper channel. Moves are async
                # (fire-and-forget); critical edges use a very short ACK only.
                ok = bool(
                    self._session_helper.send_input(
                        dict(params),
                        wait=not move_like,
                        timeout=CRIT_ACK_TIMEOUT,
                    )
                )
                if ok:
                    self._stats["inputs_applied"] += 1
                    return result({"success": True, "message": f"input {event} forwarded"})
                return result({"success": False, "error": f"input {event} not forwarded"})
            if self._use_user_helper and not self._winlogon_mode:
                # Never inject from Session 0 after a cross-session helper failure.
                return result({"success": False, "error": "target session helper is unavailable"})

            ok = self._inject_local(event, params)
            if ok:
                self._stats["inputs_applied"] += 1
                return result({"success": True, "message": f"input {event} applied"})
            return result({"success": False, "error": f"input {event} failed"})
        except Exception as e:
            log(f"[REMOTE-DESKTOP] Input error: {e}")
            return result({"success": False, "error": str(e)})

    @staticmethod
    def _normalize_input_envelope(params: dict) -> dict:
        """Accept protocol-2 envelopes while preserving legacy flat events."""
        if not isinstance(params, dict):
            return {"event": ""}
        outer = dict(params)
        protocol = outer.get("protocol")
        nested = outer.get("input")
        if not isinstance(nested, dict):
            nested = outer.get("payload")
        if protocol == 2 and isinstance(nested, dict):
            normalized = dict(nested)
            for key in ("id", "ts"):
                if key in outer and key not in normalized:
                    normalized[key] = outer[key]
        else:
            normalized = outer
        if protocol == 2:
            normalized["_protocol"] = 2
        if normalized.get("id") is not None:
            normalized["_input_id"] = normalized.get("id")
        if not normalized.get("event"):
            normalized["event"] = (
                normalized.get("gesture")
                or normalized.get("type")
                or normalized.get("name")
                or normalized.get("action")
                or ""
            )
        event = str(normalized.get("event") or "").strip().lower().replace("-", "_")
        aliases = {
            "doubletap": "double_tap",
            "longpress": "long_press",
            "rightclick": "right_click",
            "dragstart": "drag_start",
            "dragmove": "drag_move",
            "dragend": "drag_end",
            "twofingerscroll": "two_finger_scroll",
            "trackpadmove": "trackpad_move",
        }
        normalized["event"] = aliases.get(event, event)
        return normalized

    def _inject_local(self, event: str, params: dict) -> bool:
        # Ensure CAD/key/mouse land on Winlogon when pre-logon.
        self._attach_input_desktop()
        return self._inject_local_after_attach(event, params)

    def _inject_local_after_attach(self, event: str, params: dict) -> bool:
        """Local SendInput/SetCursorPos injection (same session or helper side)."""
        mode = str(params.get("mode") or params.get("pointer_mode") or "direct").lower()
        if event == "tap":
            return self._do_click(
                float(params.get("x", 0.5)), float(params.get("y", 0.5)), "left"
            )
        if event == "double_tap":
            return self._do_click(
                float(params.get("x", 0.5)),
                float(params.get("y", 0.5)),
                "left",
                double=True,
            )
        if event in ("long_press", "right_click"):
            return self._do_click(
                float(params.get("x", 0.5)), float(params.get("y", 0.5)), "right"
            )
        if event == "drag_start":
            if self._drag_active:
                # Duplicate start is idempotent; update position without another down.
                return self._gesture_move(params, mode)
            self._drag_active = True
            self._drag_button = str(params.get("button") or "left").lower()
            self._drag_mode = mode
            if mode in ("relative", "trackpad"):
                self._gesture_move(params, mode)
                return self._do_mouse_button_at_current(self._drag_button, down=True)
            return self._do_mouse_button(
                float(params.get("x", 0.5)),
                float(params.get("y", 0.5)),
                self._drag_button,
                down=True,
            )
        if event == "drag_move":
            return self._gesture_move(params, mode or self._drag_mode)
        if event == "drag_end":
            if not self._drag_active:
                return True
            try:
                self._gesture_move(params, mode or self._drag_mode)
                return self._do_mouse_button_at_current(self._drag_button, down=False)
            finally:
                self._drag_active = False
        if event in ("two_finger_scroll", "scroll"):
            dx, dy = self._normalized_scroll_deltas(params)
            return self._do_wheel(
                float(params.get("x", 0.5)),
                float(params.get("y", 0.5)),
                dy,
                horizontal_delta=dx,
            )
        if event in ("click", "dblclick"):
            return self._do_click(
                float(params.get("x", 0)),
                float(params.get("y", 0)),
                str(params.get("button", "left") or "left"),
                double=(event == "dblclick"),
            )
        if event == "mousedown":
            return self._do_mouse_button(
                float(params.get("x", 0)),
                float(params.get("y", 0)),
                str(params.get("button", "left") or "left"),
                down=True,
            )
        if event == "mouseup":
            return self._do_mouse_button(
                float(params.get("x", 0)),
                float(params.get("y", 0)),
                str(params.get("button", "left") or "left"),
                down=False,
            )
        if _is_relative_pointer(event, params):
            return self._do_move_relative(
                int(float(params.get("dx", 0) or 0)),
                int(float(params.get("dy", 0) or 0)),
            )
        if event in ("move", "mousemove") or event == "pointer":
            return self._do_move(
                float(params.get("x", 0)),
                float(params.get("y", 0)),
            )
        if event == "wheel":
            dx, delta = self._normalized_scroll_deltas(params)
            return self._do_wheel(
                float(params.get("x", 0.5)),
                float(params.get("y", 0.5)),
                delta,
                horizontal_delta=dx,
            )
        if event == "type_text":
            return self._do_type_text(str(params.get("text", "") or ""))
        if event == "key":
            return self._do_key(
                str(params.get("key", "") or ""),
                code=str(params.get("code", "") or ""),
            )
        raise ValueError(f"unknown event: {event}")

    def _gesture_move(self, params: dict, mode: str) -> bool:
        if mode in ("relative", "trackpad"):
            return self._do_move_relative(
                int(float(params.get("dx", 0) or 0)),
                int(float(params.get("dy", 0) or 0)),
            )
        if "x" not in params and "y" not in params:
            return True
        return self._do_move(
            float(params.get("x", 0.5)), float(params.get("y", 0.5))
        )

    @staticmethod
    def _normalized_scroll_deltas(params: dict) -> Tuple[int, int]:
        """Return Windows wheel deltas (positive=up/right).

        Browser/mobile deltaX/deltaY are positive down/right, so both axes are
        inverted. Legacy `delta`/`key` values remain Windows-oriented.
        """
        if (
            "deltaY" in params
            or "deltaX" in params
            or (
                str(params.get("event") or "").lower()
                in ("two_finger_scroll", "scroll")
                and ("dx" in params or "dy" in params)
            )
        ):
            try:
                vertical = -int(float(
                    params.get("deltaY", params.get("dy", 0)) or 0
                ))
            except (TypeError, ValueError):
                vertical = 0
            try:
                horizontal = -int(float(
                    params.get("deltaX", params.get("dx", 0)) or 0
                ))
            except (TypeError, ValueError):
                horizontal = 0
            return horizontal, vertical
        raw = params.get("key", params.get("delta", -120))
        try:
            return 0, int(float(raw))
        except (TypeError, ValueError):
            return 0, -120

    # ── Capture loop ──────────────────────────────────────────────

    def _media_ready(self) -> bool:
        try:
            status = self._media.status()
            return bool(
                status.get("active")
                and status.get("connection_state") == "connected"
                and status.get("ice_state") in ("connected", "completed")
            )
        except Exception:
            return False

    def _effective_capture_settings(self) -> Tuple[float, int, int]:
        if self._media_ready():
            return self._media_fps, self._media_quality, self._max_width
        return self._fps, self._quality, self._max_width

    def _sync_media_capture_mode(self) -> None:
        ready = self._media_ready()
        if ready == self._media_mode_applied:
            return
        self._media_mode_applied = ready
        if self._persistent_helper_connected():
            fps, quality, max_width = self._effective_capture_settings()
            self._session_helper.update_config({
                "fps": fps, "quality": quality, "max_width": max_width,
            })
        if ready:
            # Drop any JPEG captured before DTLS/ICE became ready.
            with self._out_lock:
                self._pending_frame = None
            self.emit_stream_progress("webrtc", "WebRTC media path connected")
        self._enqueue_meta(force=True)

    def _capture_loop(self):
        while self._running and not self._stop.is_set():
            t0 = time.time()
            try:
                if time.time() - self._last_activity > IDLE_STOP_SECONDS:
                    log("[REMOTE-DESKTOP] Idle timeout — auto stop")
                    self.stop(reason="idle_timeout")
                    break
                # Honest fail: streaming but no frames for 10s
                if (
                    self._stats.get("frames_sent", 0) <= 0
                    and self._stream_started_at
                    and (time.time() - self._stream_started_at) >= CAPTURE_FAIL_SECONDS
                ):
                    log("[REMOTE-DESKTOP] ✖ CAPTURE_NO_DESKTOP — "
                        f"no frames in {CAPTURE_FAIL_SECONDS:.0f}s (screen still empty)")
                    self.emit_stream_progress(
                        "failed",
                        f"No frames in {CAPTURE_FAIL_SECONDS:.0f}s",
                        error="CAPTURE_NO_DESKTOP",
                        force=True,
                    )
                    self.stop(reason="CAPTURE_NO_DESKTOP")
                    break
                self._sync_media_capture_mode()
                self._progress_heartbeat_tick()
                self._capture_and_send()
            except Exception as e:
                self._stats["frames_failed"] += 1
                log(f"[REMOTE-DESKTOP] Frame error: {e}")
            effective_fps, _quality, _width = self._effective_capture_settings()
            interval = 1.0 / max(effective_fps, 0.5)
            elapsed = time.time() - t0
            self._stop.wait(max(0.02, interval - elapsed))

    def _capture_and_send(self):
        token = self.token_getter()
        if not token:
            return
        capture_started = time.monotonic()

        # WebRTC connected + in-process capture: raw RGB → H.264 (no JPEG).
        if self._media_ready() and not self._use_user_helper:
            raw = self._grab_raw_rgb()
            self._last_capture_mono = time.monotonic()
            capture_elapsed = self._last_capture_mono - capture_started
            self._adaptive.observe_capture(capture_elapsed)
            self._adaptive_tick()
            if raw is not None:
                rgb, w, h = raw
                if self._should_skip_unchanged_frame(rgb):
                    return
                self._seq += 1
                seq = self._seq
                if self._dispatch_raw_frame(rgb, w, h, seq):
                    return
                # Media publish failed — fall through to JPEG for WS/HTTP.

        if self._use_user_helper:
            if not self._persistent_helper_connected():
                if not self._start_persistent_helper():
                    jpeg, w, h = self._grab_via_user_helper()
                else:
                    effective_fps, _quality, _width = self._effective_capture_settings()
                    jpeg, w, h = self._grab_via_persistent_helper(
                        max(0.08, 2.0 / max(effective_fps, 1.0))
                    )
            else:
                effective_fps, _quality, _width = self._effective_capture_settings()
                jpeg, w, h = self._grab_via_persistent_helper(
                    max(0.08, 2.0 / max(effective_fps, 1.0))
                )
        else:
            jpeg, w, h = self._grab_jpeg()
            pid_sid, _ = self._session_ids()
            if (
                (not jpeg or w <= 0 or h <= 0)
                and self._target_session_id
                and (pid_sid is None or int(pid_sid) != int(self._target_session_id))
            ):
                jpeg, w, h = self._grab_via_user_helper()
        self._last_capture_mono = time.monotonic()
        capture_elapsed = self._last_capture_mono - capture_started
        if self._last_helper_capture_ms > 0 and self._use_user_helper:
            capture_elapsed = self._last_helper_capture_ms / 1000.0
            self._last_helper_capture_ms = 0.0
        self._adaptive.observe_capture(capture_elapsed)
        self._adaptive_tick()
        if not jpeg or w <= 0 or h <= 0:
            self._stats["frames_failed"] += 1
            return
        # API rejects tiny frames; black frames look like "live" black desktop
        if len(jpeg) < MIN_JPEG_BYTES:
            self._stats["frames_failed"] += 1
            self._stats["black_frames"] += 1
            return
        if jpeg[:2] != b"\xff\xd8" or jpeg[-2:] != b"\xff\xd9":
            self._stats["frames_failed"] += 1
            log("[REMOTE-DESKTOP] Invalid JPEG magic — skip frame")
            return
        if "+black" in (self._capture_method or ""):
            # Disconnected RDP / wrong desktop → re-attach + optional tscon
            now = time.time()
            if self._black_streak_started <= 0:
                self._black_streak_started = now
            self._desktop_attached = False
            self._attach_input_desktop()
            sid = self._target_session_id
            if not self._tscon_attempted:
                if self._try_reconnect_session_to_console(sid):
                    time.sleep(0.35)
                    self._desktop_attached = False
                    self._attach_input_desktop()
                    jpeg2, w2, h2 = self._grab_jpeg()
                    if jpeg2 and "+black" not in (self._capture_method or ""):
                        jpeg, w, h = jpeg2, w2, h2
                        self._black_streak_started = 0.0
                    else:
                        self._stats["frames_failed"] += 1
                        self._stats["black_frames"] += 1
                        self._maybe_fail_winlogon_black()
                        return
                else:
                    self._stats["frames_failed"] += 1
                    self._stats["black_frames"] += 1
                    self._maybe_fail_winlogon_black()
                    return
            else:
                self._stats["frames_failed"] += 1
                self._stats["black_frames"] += 1
                self._maybe_fail_winlogon_black()
                return
        else:
            self._black_streak_started = 0.0

        # Helper JPEG while WebRTC live: decode once → raw mailbox (no double encode).
        if self._media_ready() and self._use_user_helper:
            try:
                from PIL import Image
                rgb_img = Image.open(io.BytesIO(jpeg)).convert("RGB")
                if self._should_skip_unchanged_frame(rgb_img.tobytes()):
                    return
                self._seq += 1
                seq = self._seq
                if self._dispatch_raw_frame(
                    rgb_img.tobytes(), rgb_img.width, rgb_img.height, seq
                ):
                    return
            except Exception:
                pass

        self._seq += 1
        seq = self._seq
        self._last_good_jpeg = jpeg
        self._last_good_wh = (w, h)
        self._dispatch_frame(token, jpeg, w, h, seq)
        if not self._progress_live_emitted:
            self.emit_stream_progress(
                "live",
                "First real frame on the wire",
                force=True,
            )

    def _maybe_fail_winlogon_black(self) -> None:
        """C-RD-P0-WL-4: sustained GDI black in winlogon → retry once, then fail."""
        if not self._winlogon_mode or self._black_streak_started <= 0:
            return
        elapsed = time.time() - self._black_streak_started
        if elapsed < WINLOGON_BLACK_FAIL_SECONDS:
            return
        if not self._winlogon_black_retried:
            self._winlogon_black_retried = True
            self._desktop_attached = False
            self._attach_input_desktop()
            jpeg, w, h = self._grab_jpeg()
            if jpeg and w > 0 and h > 0 and "+black" not in (self._capture_method or ""):
                self._black_streak_started = 0.0
                return
            # Reset streak clock after the one allowed retry.
            self._black_streak_started = time.time()
            return
        self._last_stream_error = "winlogon_capture_black"
        log(
            "[REMOTE-DESKTOP] ✖ winlogon_capture_black — "
            f"unbroken black for ≥{WINLOGON_BLACK_FAIL_SECONDS:.0f}s "
            f"(method={self._capture_method})"
        )
        self.emit_stream_progress(
            "failed",
            f"Unbroken black for ≥{WINLOGON_BLACK_FAIL_SECONDS:.0f}s",
            error="winlogon_capture_black",
            force=True,
        )
        self.stop(reason="winlogon_capture_black")

    def _dispatch_raw_frame(self, rgb, w: int, h: int, seq: int) -> bool:
        """Publish raw RGB into WebRTC mailbox. True if media accepted it."""
        media_metadata = {
            "seq": int(seq),
            "width": int(w),
            "height": int(h),
            "capture_mono_ms": int(self._last_capture_mono * 1000),
            "path": "raw",
        }
        try:
            if self._media.publish_raw(rgb, w, h, media_metadata):
                self._transport = "webrtc"
                self._capture_w, self._capture_h = int(w), int(h)
                self._last_activity = time.time()
                self._stats["frames_sent"] += 1
                with self._out_lock:
                    self._pending_frame = None
                if self._seq % META_EVERY_N_FRAMES == 0:
                    self._enqueue_meta(force=True)
                return True
        except Exception as exc:
            self._on_media_fallback(str(exc))
        return False

    def _should_skip_unchanged_frame(self, rgb) -> bool:
        """Skip publish when desktop is static so encoder stays near-idle."""
        import hashlib
        try:
            if hasattr(rgb, "tobytes"):
                data = rgb.tobytes()
            else:
                data = bytes(rgb) if not isinstance(rgb, (bytes, bytearray)) else rgb
            # Sample stride keeps hash cheap on 1080p RGB.
            step = max(1, len(data) // 65536)
            digest = hashlib.blake2b(data[::step], digest_size=16).digest()
        except Exception:
            return False
        if digest == self._last_raw_hash and self._idle_skip_streak < 90:
            self._idle_skip_streak += 1
            self._stats["frames_coalesced"] = (
                int(self._stats.get("frames_coalesced") or 0) + 1
            )
            return True
        self._last_raw_hash = digest
        self._idle_skip_streak = 0
        return False

    def _dispatch_frame(self, token: str, jpeg: bytes, w: int, h: int, seq: int) -> None:
        """Route one frame. WS healthy → WS only (sent + counted on WS thread).

        HTTP upload is used only while WS is unavailable/unhealthy, so a healthy
        stream never pays for a duplicate synchronous HTTP POST per frame.
        """
        media_metadata = {
            "seq": int(seq),
            "width": int(w),
            "height": int(h),
            "capture_mono_ms": int(self._last_capture_mono * 1000),
        }
        try:
            if self._media.publish_frame(jpeg, media_metadata):
                self._transport = "webrtc"
                self._last_activity = time.time()
                # A stale JPEG may already be waiting from pre-connect. Remove
                # it so the WS sender cannot compete with connected WebRTC.
                with self._out_lock:
                    self._pending_frame = None
                return
        except Exception as exc:
            self._on_media_fallback(str(exc))

        # Always buffer for the WS thread (latest-frame semantics); this also
        # ensures a frame is ready the moment WS (re)connects.
        self._enqueue_ws_frame(jpeg, w, h, seq)

        if self._ws_ok:
            # WS thread performs the actual send and increments frames_sent.
            self._transport = "websocket"
            self._last_activity = time.time()
            return

        # WS down/unhealthy → HTTP fallback (frame ACK also drains inputs[]).
        send_started = time.monotonic()
        try:
            http_ok = self._http_send_frame(token, jpeg, w, h, seq)
        except Exception as e:
            http_ok = False
            log(f"[REMOTE-DESKTOP] HTTP frame upload failed: {e}")
        send_elapsed = time.monotonic() - send_started
        self._adaptive.observe_send(send_elapsed, transport="http", ok=http_ok)
        self._adaptive_tick()
        if http_ok:
            self._transport = "http"
            self._stats["frames_sent"] += 1
            self._stats["bytes_sent"] += len(jpeg)
            self._stats["http_fallbacks"] += 1
            self._last_activity = time.time()
            self._last_send_mono = time.monotonic()
            if self._stats["frames_sent"] == 1 or seq == 1:
                log(f"[REMOTE-DESKTOP] frame ok (http) — {w}x{h} {len(jpeg)}B "
                    f"method={self._capture_method}")
        else:
            self._stats["frames_failed"] += 1

    def _adaptive_tick(self) -> None:
        changed = self._adaptive.evaluate()
        if changed:
            # While WebRTC is live, keep local JPEG knobs warm for fallback but
            # do not thrash the session helper with JPEG quality/fps churn.
            notify = not self._media_ready()
            self._apply_effective_settings(changed, notify_helper=notify)

    def _apply_effective_settings(
        self, settings: dict, *, notify_helper: bool = True
    ) -> None:
        self._fps = float(settings["fps"])
        self._quality = int(settings["quality"])
        self._max_width = int(settings["max_width"])
        if notify_helper and self._persistent_helper_connected():
            self._session_helper.update_config({
                "fps": self._fps,
                "quality": self._quality,
                "max_width": self._max_width,
                "monitor": self._monitor_index,
            })

    def _http_send_frame(self, token: str, jpeg: bytes, w: int, h: int, seq: int) -> bool:
        if not self.api_client or not hasattr(self.api_client, "upload_remote_frame"):
            return False
        result = self.api_client.upload_remote_frame(
            token=token,
            jpeg_bytes=jpeg,
            width=w,
            height=h,
            seq=seq,
            fps=self._fps,
        )
        # Backward compatible: older callers returned bool
        if isinstance(result, dict):
            ok = bool(result.get("ok"))
            self._apply_input_batch(result.get("inputs") or [])
            return ok
        return bool(result)

    def _apply_input_batch(self, events) -> None:
        """Apply piggybacked / polled remote input events (frame ACK primary path)."""
        applied = self._ingest_events(events)
        if applied:
            self._stats["inputs_piggyback"] = int(self._stats.get("inputs_piggyback") or 0) + applied

    def _ingest_events(self, events, emit_ack: bool = False) -> int:
        """Normalize → coalesce moves → apply, preserving edge ordering."""
        if not events:
            return 0
        normalized = []
        for ev in events:
            if not isinstance(ev, dict):
                continue
            normalized.append(self._normalize_input_envelope(ev))
        coalesced = self._coalesce_events(normalized)
        dropped = len(normalized) - len(coalesced)
        if dropped > 0:
            self._stats["moves_coalesced"] += dropped
        applied = 0
        for params in coalesced:
            try:
                r = self.apply_input(params)
                if emit_ack:
                    ack_ids = params.get("_ack_ids") or [params.get("_input_id")]
                    for ack_id in ack_ids:
                        if ack_id is not None:
                            self._queue_input_ack(r, ack_id=ack_id)
                if isinstance(r, dict) and r.get("success"):
                    applied += 1
            except Exception as e:
                log(f"[REMOTE-DESKTOP] input apply error: {e}")
        return applied

    def _queue_input_ack(self, result: dict, ack_id=None) -> None:
        """Best-effort protocol-2 result over the existing WS text channel."""
        ack_id = result.get("id") if ack_id is None else ack_id
        if ack_id is None:
            return
        ack = {
            "t": "input_ack",
            "protocol": 2,
            "id": ack_id,
            "success": bool(result.get("success")),
        }
        if not ack["success"] and result.get("error"):
            ack["error"] = str(result["error"])[:200]
        self._q_put_text(json.dumps(ack, separators=(",", ":")))

    @staticmethod
    def _coalesce_events(events) -> list:
        """Fold consecutive high-frequency moves; keep edge ordering intact.

        Absolute move runs collapse to the last position. Relative move runs
        accumulate dx/dy. Any button/wheel/key/other event flushes the pending
        move first, so the cursor position is correct at the moment of the edge.
        """
        out = []
        pending = None  # ("abs", params) | ("rel", params)

        def flush():
            nonlocal pending
            if pending is not None:
                out.append(pending[1])
                pending = None

        for params in events:
            event = (params.get("event") or "").strip().lower()
            if _is_relative_pointer(event, params):
                dx = int(float(params.get("dx", 0) or 0))
                dy = int(float(params.get("dy", 0) or 0))
                if pending is not None and pending[0] == "rel":
                    pending[1]["dx"] = int(pending[1].get("dx", 0)) + dx
                    pending[1]["dy"] = int(pending[1].get("dy", 0)) + dy
                    if params.get("_input_id") is not None:
                        pending[1].setdefault("_ack_ids", []).append(
                            params["_input_id"]
                        )
                else:
                    flush()
                    merged = dict(params)
                    merged["dx"], merged["dy"] = dx, dy
                    if merged.get("_input_id") is not None:
                        merged["_ack_ids"] = [merged["_input_id"]]
                    pending = ("rel", merged)
            elif event in ABS_MOVE_EVENTS or event in ("pointer", "drag_move"):
                if pending is not None and pending[0] == "abs":
                    ack_ids = list(pending[1].get("_ack_ids") or [])
                    merged = dict(params)  # keep only the latest position
                    if merged.get("_input_id") is not None:
                        ack_ids.append(merged["_input_id"])
                    if ack_ids:
                        merged["_ack_ids"] = ack_ids
                    pending = ("abs", merged)
                else:
                    flush()
                    merged = dict(params)
                    if merged.get("_input_id") is not None:
                        merged["_ack_ids"] = [merged["_input_id"]]
                    pending = ("abs", merged)
            else:
                flush()
                out.append(params)
        flush()
        return out

    def _compute_encode_size(
        self, src_w: int, src_h: int, max_width: int
    ) -> Tuple[int, int]:
        """Downscale for encode: respect max_width, keep ≥800×600 when source allows."""
        src_w = max(1, int(src_w))
        src_h = max(1, int(src_h))
        max_width = max(MIN_ENCODE_WIDTH, min(int(max_width or DEFAULT_MAX_WIDTH), 1920))

        scale = 1.0
        if src_w > max_width:
            scale = min(scale, max_width / float(src_w))
        # Prefer not to go below the UX floor when the desktop is large enough.
        if src_w >= MIN_ENCODE_WIDTH and src_h >= MIN_ENCODE_HEIGHT:
            tw = max(1, int(round(src_w * scale)))
            th = max(1, int(round(src_h * scale)))
            if tw < MIN_ENCODE_WIDTH or th < MIN_ENCODE_HEIGHT:
                # Raise scale to meet the floor without exceeding max_width/native.
                need = max(
                    MIN_ENCODE_WIDTH / float(src_w),
                    MIN_ENCODE_HEIGHT / float(src_h),
                )
                scale = min(1.0, max_width / float(src_w), max(scale, need))
        tw = max(1, int(round(src_w * scale)))
        th = max(1, int(round(src_h * scale)))
        # Final clamp: never exceed max_width; never upscale past native.
        if tw > max_width:
            ratio = max_width / float(tw)
            tw = max_width
            th = max(1, int(round(th * ratio)))
        return tw, th

    def _resolve_encode_size(
        self, src_w: int, src_h: int, max_width: int
    ) -> Optional[Tuple[int, int]]:
        """Lock encode WxH for the stream session so dashboard size stays stable."""
        if src_w <= 0 or src_h <= 0:
            return None
        if self._locked_encode_w > 0 and self._locked_encode_h > 0:
            return self._locked_encode_w, self._locked_encode_h
        tw, th = self._compute_encode_size(src_w, src_h, max_width)
        self._locked_encode_w = tw
        self._locked_encode_h = th
        log(
            f"[REMOTE-DESKTOP] encode size locked {tw}x{th} "
            f"(src={src_w}x{src_h} max_w={max_width})"
        )
        return tw, th

    def _capture_screen_image(self):
        """Capture primary screen → PIL RGB Image (no encode). Returns (img, method)."""
        try:
            from PIL import Image
        except ImportError:
            log("[REMOTE-DESKTOP] Pillow (PIL) not available")
            return None, "none"

        # Ensure this thread is on the interactive input desktop (RDP black-BitBlt fix)
        self._attach_input_desktop()
        origin_x, origin_y, native_w, native_h = self._get_capture_rect()
        self._screen_x, self._screen_y = origin_x, origin_y
        self._screen_w, self._screen_h = native_w, native_h

        img = None
        method = "none"
        # WebRTC media mode: prefer Desktop Duplication (dirty/present driven)
        # when the optional dxcam runtime is packaged. Falls back safely.
        if self._media_ready():
            try:
                import dxcam  # type: ignore
                if self._dxcam is None:
                    self._dxcam = dxcam.create(output_color="RGB")
                frame = self._dxcam.grab(region=(
                    origin_x,
                    origin_y,
                    origin_x + native_w,
                    origin_y + native_h,
                ))
                if frame is not None:
                    img = Image.fromarray(frame)
                    method = "dxgi-desktop-duplication"
            except Exception:
                # Optional capability: no warning spam on hosts without dxcam.
                self._dxcam = None
        # Prefer GDI BitBlt (more reliable than ImageGrab under elevation / DPI)
        if img is None:
            try:
                img = self._grab_gdi()
                if img is not None:
                    method = "gdi"
            except Exception as e:
                log(f"[REMOTE-DESKTOP] GDI grab failed: {e}")

        if img is None or self._is_mostly_black(img):
            try:
                from PIL import ImageGrab
                candidates = []
                if native_w > 0 and native_h > 0:
                    try:
                        candidates.append((
                            "imagegrab-bbox",
                            ImageGrab.grab(bbox=(
                                origin_x,
                                origin_y,
                                origin_x + native_w,
                                origin_y + native_h,
                            )),
                        ))
                    except Exception as e:
                        log(f"[REMOTE-DESKTOP] imagegrab-bbox failed: {e}")
                for label, alt in candidates:
                    if alt is None:
                        continue
                    if img is None or self._mean_brightness(alt) > self._mean_brightness(img):
                        img = alt
                        method = label
            except Exception as e:
                log(f"[REMOTE-DESKTOP] ImageGrab variants failed: {e}")

        # Optional mss (if installed) — often works when GDI is black on RDP
        if img is None or self._is_mostly_black(img):
            try:
                alt = self._grab_mss()
                if alt is not None and (
                    img is None
                    or self._mean_brightness(alt) > self._mean_brightness(img)
                ):
                    img = alt
                    method = "mss"
            except Exception as e:
                log(f"[REMOTE-DESKTOP] mss grab failed: {e}")

        if img is None:
            log("[REMOTE-DESKTOP] all in-process capture methods returned None")
            return None, "none"

        if self._is_mostly_black(img):
            self._stats["black_frames"] += 1
            now = time.time()
            if now - self._black_warn_ts > 10:
                self._black_warn_ts = now
                sid, csid = self._session_ids()
                state = self._session_connect_state(sid)
                log(f"[REMOTE-DESKTOP] ⚠ Nearly-black frame "
                    f"(mean={self._mean_brightness(img):.1f}) "
                    f"session={sid}/{csid} state={state} method={method}")
            method = method + "+black"

        self._capture_method = method
        self._stats["capture_method"] = method
        # Keep the selected monitor's native rectangle separate from encoded size.
        if native_w <= 0 or native_h <= 0:
            self._screen_w, self._screen_h = img.size

        _fps, _effective_quality, effective_max_width = (
            self._effective_capture_settings()
        )
        target = self._resolve_encode_size(
            img.width, img.height, effective_max_width
        )
        if target and (img.width, img.height) != target:
            resample = (
                Image.Resampling.BILINEAR
                if hasattr(Image, "Resampling")
                else Image.BILINEAR
            )
            img = img.resize(target, resample)

        self._capture_w, self._capture_h = img.size
        return img.convert("RGB"), method

    def _grab_raw_rgb(self):
        """Capture → resized RGB bytes for WebRTC (no JPEG). Returns (bytes,w,h) or None."""
        img, method = self._capture_screen_image()
        if img is None or "+black" in (method or ""):
            return None
        return img.tobytes(), img.width, img.height

    def _grab_jpeg(self):
        """Capture primary screen → resize → JPEG. Avoids Session-0 black frames."""
        img, method = self._capture_screen_image()
        if img is None:
            return None, 0, 0
        if "+black" in (method or ""):
            # Preserve prior behavior: still return a JPEG so black-recovery logic runs.
            pass

        _fps, effective_quality, _effective_max_width = (
            self._effective_capture_settings()
        )
        quality = effective_quality
        jpeg = None
        for _ in range(6):
            buf = io.BytesIO()
            img.save(buf, format="JPEG", quality=quality, optimize=False, subsampling=2)
            data = buf.getvalue()
            if len(data) <= TARGET_FRAME_BYTES or quality <= 22:
                if len(data) <= MAX_FRAME_BYTES:
                    jpeg = data
                break
            quality = max(22, quality - 5)
        if jpeg is None:
            log("[REMOTE-DESKTOP] Frame still too large after quality reduce")
            return None, 0, 0
        return jpeg, self._capture_w, self._capture_h

    def _grab_gdi(self):
        """BitBlt full virtual screen → PIL Image (RGB). Always frees GDI objects."""
        import ctypes
        from ctypes import wintypes
        from PIL import Image

        user32 = ctypes.windll.user32
        gdi32 = ctypes.windll.gdi32

        left, top, width, height = self._get_capture_rect()
        if width <= 0 or height <= 0:
            return None

        hdc = None
        memdc = None
        bmp = None
        old = None
        release_hwnd = 0

        try:
            hdc = user32.GetDC(0)
            if not hdc:
                log("[REMOTE-DESKTOP] GDI GetDC(0) failed")
                return None
            memdc = gdi32.CreateCompatibleDC(hdc)
            bmp = gdi32.CreateCompatibleBitmap(hdc, width, height)
            old = gdi32.SelectObject(memdc, bmp)
            ok = gdi32.BitBlt(memdc, 0, 0, width, height, hdc, left, top, 0x00CC0020)
            if not ok:
                log(f"[REMOTE-DESKTOP] GDI BitBlt failed {width}x{height}")
                # Release primary and try desktop window DC
                if old:
                    gdi32.SelectObject(memdc, old)
                if bmp:
                    gdi32.DeleteObject(bmp)
                if memdc:
                    gdi32.DeleteDC(memdc)
                user32.ReleaseDC(0, hdc)
                hdc = memdc = bmp = old = None

                hwnd = user32.GetDesktopWindow()
                hdc = user32.GetWindowDC(hwnd) if hwnd else None
                if not hdc:
                    return None
                release_hwnd = hwnd
                memdc = gdi32.CreateCompatibleDC(hdc)
                bmp = gdi32.CreateCompatibleBitmap(hdc, width, height)
                old = gdi32.SelectObject(memdc, bmp)
                ok = gdi32.BitBlt(memdc, 0, 0, width, height, hdc, left, top, 0x00CC0020)
                if not ok:
                    return None

            class BITMAPINFOHEADER(ctypes.Structure):
                _fields_ = [
                    ("biSize", wintypes.DWORD),
                    ("biWidth", wintypes.LONG),
                    ("biHeight", wintypes.LONG),
                    ("biPlanes", wintypes.WORD),
                    ("biBitCount", wintypes.WORD),
                    ("biCompression", wintypes.DWORD),
                    ("biSizeImage", wintypes.DWORD),
                    ("biXPelsPerMeter", wintypes.LONG),
                    ("biYPelsPerMeter", wintypes.LONG),
                    ("biClrUsed", wintypes.DWORD),
                    ("biClrImportant", wintypes.DWORD),
                ]

            bi = BITMAPINFOHEADER()
            bi.biSize = ctypes.sizeof(BITMAPINFOHEADER)
            bi.biWidth = width
            bi.biHeight = -height  # top-down
            bi.biPlanes = 1
            bi.biBitCount = 32
            bi.biCompression = 0
            buf_size = width * height * 4
            buf = (ctypes.c_char * buf_size)()
            gdi32.GetDIBits(memdc, bmp, 0, height, buf, ctypes.byref(bi), 0)

            img = Image.frombuffer("RGB", (width, height), bytes(buf), "raw", "BGRX", 0, 1)
            # Avoid double-copy; brightness check on a tiny resize only when probing
            now = time.time()
            if now - getattr(self, "_gdi_log_ts", 0) > 30:
                self._gdi_log_ts = now
                br = self._mean_brightness(img)
                log(f"[REMOTE-DESKTOP] GDI capture {width}x{height} brightness={br:.1f}")
            return img.copy()
        finally:
            try:
                if old is not None and memdc:
                    gdi32.SelectObject(memdc, old)
            except Exception:
                pass
            try:
                if bmp:
                    gdi32.DeleteObject(bmp)
            except Exception:
                pass
            try:
                if memdc:
                    gdi32.DeleteDC(memdc)
            except Exception:
                pass
            try:
                if hdc:
                    user32.ReleaseDC(release_hwnd, hdc)
            except Exception:
                pass

    @staticmethod
    def _mean_brightness(img) -> float:
        try:
            small = img.resize((48, 27)).convert("L")
            data = list(small.getdata())
            return float(sum(data)) / max(1, len(data))
        except Exception:
            return 255.0

    def _is_mostly_black(self, img) -> bool:
        return self._mean_brightness(img) < BLACK_MEAN_THRESHOLD

    def _attach_input_desktop(self) -> bool:
        """Bind capture/input thread to the interactive (or Winlogon) desktop.

        Elevated / tray processes often BitBlt a black screen when not on
        the input desktop. Pre-logon requires WinSta0 + Winlogon attach.
        """
        # Periodically re-open so we pick up Default after a successful logon.
        force = False
        try:
            if (
                self._winlogon_mode
                and self._seq
                and int(self._seq) % max(1, int(self._desktop_reattach_every)) == 0
            ):
                force = True
        except Exception:
            force = False
        if self._desktop_attached and not force:
            return True
        try:
            from client_rd_winlogon import attach_console_desktop
            # C-RD-CON-4: start / steady Winlogon attach is strict named Winlogon.
            # C-RD-CON-6: periodic reattach follows OpenInputDesktop (Default after logon).
            if force and self._winlogon_mode:
                ok, name, hdesk = attach_console_desktop(
                    follow_input=True,
                    close_previous=self._input_desktop,
                )
            elif self._winlogon_mode:
                ok, name, hdesk = attach_console_desktop(
                    prefer_winlogon=True,
                    strict_winlogon=True,
                    close_previous=None,
                )
            else:
                ok, name, hdesk = attach_console_desktop(
                    prefer_winlogon=False,
                    close_previous=self._input_desktop if force else None,
                )
            if ok and hdesk:
                self._input_desktop = hdesk
                self._desktop_attached = True
                self._desktop_name = name
                if name.lower() == "default" and self._winlogon_mode:
                    # User completed interactive logon — switch to normal desktop path.
                    self._winlogon_mode = False
                    log("[REMOTE-DESKTOP] desktop switched Winlogon→Default (post-logon)")
                return True
            if self._winlogon_mode and not force:
                # C-RD-CON-4: do not silently capture Default while claiming Winlogon.
                log(f"[REMOTE-DESKTOP] strict Winlogon attach failed: {name}")
                return False
        except Exception as e:
            log(f"[REMOTE-DESKTOP] winlogon attach error: {e}")
            if self._winlogon_mode and not force:
                return False

        # Legacy fallback (same session / already on WinSta0)
        if self._winlogon_mode and not force:
            return False
        try:
            import ctypes
            user32 = ctypes.windll.user32
            kernel32 = ctypes.windll.kernel32
            kernel32.SetLastError(0)
            GENERIC_ALL = 0x10000000
            hdesk = user32.OpenInputDesktop(0, False, GENERIC_ALL)
            if not hdesk:
                err = kernel32.GetLastError()
                log(f"[REMOTE-DESKTOP] OpenInputDesktop failed err={err}")
                return False
            if not user32.SetThreadDesktop(hdesk):
                err = kernel32.GetLastError()
                log(f"[REMOTE-DESKTOP] SetThreadDesktop failed err={err}")
                try:
                    user32.CloseDesktop(hdesk)
                except Exception:
                    pass
                return False
            # Resolve real name; reject Default while still in strict winlogon start.
            try:
                from client_rd_winlogon import desktop_name as _desk_name
                resolved = (_desk_name(hdesk) or "Input").strip()
            except Exception:
                resolved = "Input"
            if self._winlogon_mode and resolved.lower() not in ("winlogon", "input"):
                log(
                    f"[REMOTE-DESKTOP] legacy input desktop={resolved} "
                    "rejected under winlogon_mode"
                )
                try:
                    user32.CloseDesktop(hdesk)
                except Exception:
                    pass
                return False
            self._input_desktop = hdesk
            self._desktop_attached = True
            self._desktop_name = resolved
            if resolved.lower() == "default" and self._winlogon_mode:
                self._winlogon_mode = False
                log("[REMOTE-DESKTOP] desktop switched Winlogon→Default (post-logon)")
            log(f"[REMOTE-DESKTOP] attached to input desktop name={resolved}")
            return True
        except Exception as e:
            log(f"[REMOTE-DESKTOP] desktop attach error: {e}")
            return False

    def _session_connect_state(self, session_id: Optional[int]) -> str:
        """Return WTS connect state name for logging (Active/Disconnected/…)."""
        if session_id is None:
            return "unknown"
        try:
            import ctypes
            from ctypes import wintypes
            WTSConnectState = 8
            states = {
                0: "Active", 1: "Connected", 2: "ConnectQuery",
                3: "Shadow", 4: "Disconnected", 5: "Idle",
                6: "Listen", 7: "Reset", 8: "Down", 9: "Init",
            }
            wts = ctypes.windll.wtsapi32
            buf = ctypes.c_void_p()
            length = wintypes.DWORD()
            if not wts.WTSQuerySessionInformationW(
                0, int(session_id), WTSConnectState,
                ctypes.byref(buf), ctypes.byref(length),
            ):
                return "query_failed"
            try:
                # Value is a ULONG / DWORD at buf
                val = ctypes.cast(buf, ctypes.POINTER(wintypes.DWORD)).contents.value
                return states.get(int(val), f"state_{val}")
            finally:
                wts.WTSFreeMemory(buf)
        except Exception:
            return "unknown"

    def _try_reconnect_session_to_console(self, session_id: Optional[int]) -> bool:
        """Disconnected RDP sessions don't render → BitBlt is black.

        `tscon <sid> /dest:console` forces the session onto the console so
        the desktop is drawn again (may switch physical console briefly).
        """
        if self._tscon_attempted or session_id is None or session_id <= 0:
            return False
        self._tscon_attempted = True
        try:
            import subprocess
            r = subprocess.run(
                ["tscon", str(int(session_id)), "/dest:console"],
                capture_output=True, text=True, timeout=8,
                creationflags=0x08000000,
            )
            ok = r.returncode == 0
            log(f"[REMOTE-DESKTOP] tscon session={session_id} → console "
                f"rc={r.returncode} out={(r.stdout or r.stderr or '').strip()[:200]}")
            # Reset desktop attach so next grab re-opens input desktop
            self._desktop_attached = False
            return ok
        except Exception as e:
            log(f"[REMOTE-DESKTOP] tscon failed: {e}")
            return False

    def _grab_mss(self):
        """Optional mss capture (if package present)."""
        try:
            import mss
            from PIL import Image
            with mss.mss() as sct:
                target = self._get_capture_rect()
                physical = list(sct.monitors[1:])
                mon = next(
                    (
                        item for item in physical
                        if (
                            int(item.get("left", 0)),
                            int(item.get("top", 0)),
                            int(item.get("width", 0)),
                            int(item.get("height", 0)),
                        ) == target
                    ),
                    physical[0] if physical else sct.monitors[0],
                )
                self._screen_x = int(mon.get("left", 0))
                self._screen_y = int(mon.get("top", 0))
                self._screen_w = int(mon.get("width", 0))
                self._screen_h = int(mon.get("height", 0))
                shot = sct.grab(mon)
                return Image.frombytes("RGB", shot.size, shot.bgra, "raw", "BGRX")
        except ImportError:
            return None

    @staticmethod
    def _session_ids() -> Tuple[Optional[int], Optional[int]]:
        try:
            import ctypes
            from ctypes import wintypes
            console = int(ctypes.windll.kernel32.WTSGetActiveConsoleSessionId())
            sid = wintypes.DWORD()
            pid = ctypes.windll.kernel32.GetCurrentProcessId()
            if ctypes.windll.kernel32.ProcessIdToSessionId(pid, ctypes.byref(sid)):
                return int(sid.value), console
            return None, console
        except Exception:
            return None, None

    @staticmethod
    def _enumerate_sessions() -> list:
        """List WTS sessions (Active + Disconnected). Mirrors health active_sessions shape."""
        import subprocess
        out = []
        try:
            r = subprocess.run(
                ["query", "user"],
                capture_output=True, text=True, timeout=8,
                creationflags=0x08000000,
            )
            for line in (r.stdout or "").splitlines()[1:]:
                parts = line.split()
                if len(parts) < 3:
                    continue
                if parts[0].startswith(">"):
                    parts[0] = parts[0][1:]
                username = parts[0]
                session_name = ""
                id_idx = None
                for i, p in enumerate(parts[1:], 1):
                    if p.isdigit():
                        id_idx = i
                        break
                if id_idx is None:
                    continue
                if id_idx > 1:
                    session_name = parts[1]
                session_id = int(parts[id_idx])
                status_raw = parts[id_idx + 1] if len(parts) > id_idx + 1 else ""
                status = {
                    "active": "Active",
                    "disc": "Disconnected",
                    "listen": "Listen",
                }.get(status_raw.lower(), status_raw or "Unknown")
                sn = (session_name or "").lower()
                if sn.startswith("rdp") or "tcp#" in sn:
                    protocol = "RDP"
                elif sn in ("services",):
                    protocol = "Services"
                else:
                    protocol = "Console"
                if session_id <= 0:
                    continue
                out.append({
                    "username": username,
                    "session_id": session_id,
                    "session_name": session_name or protocol,
                    "status": status,
                    "protocol": protocol,
                })
        except Exception as e:
            log(f"[REMOTE-DESKTOP] enumerate sessions failed: {e}")
        try:
            from client_rd_winlogon import synthesize_console_session
            synth = synthesize_console_session(out)
            if synth:
                out.append(synth)
        except Exception:
            pass
        return out

    @staticmethod
    def _select_session_row(
        rows: list,
        *,
        want_winlogon: bool = False,
        username: Optional[str] = None,
    ) -> Optional[dict]:
        """Pick among rows sharing a session_id (user vs pre_logon sibling)."""
        if not rows:
            return None
        if want_winlogon:
            for s in rows:
                if s.get("pre_logon") or str(s.get("desktop") or "").lower() == "winlogon":
                    return s
            for s in rows:
                if not str(s.get("username") or "").strip():
                    return s
        uname = (username or "").strip().lower()
        if uname:
            for s in rows:
                if str(s.get("username") or "").strip().lower() == uname and not s.get("pre_logon"):
                    return s
        # Prefer real user session over pre_logon sibling for default start.
        for s in rows:
            if str(s.get("username") or "").strip() and not s.get("pre_logon"):
                return s
        return rows[0]

    @staticmethod
    def _pick_default_session(sessions: list) -> dict:
        """Console Active (user) → Console → Active RDP → first; pre_logon last."""
        if not sessions:
            raise ValueError("no sessions")

        def _rank(s: dict) -> tuple:
            if s.get("pre_logon") or (
                not str(s.get("username") or "").strip()
                and str(s.get("desktop") or "").lower() == "winlogon"
            ):
                return (9, int(s.get("session_id") or 0))
            proto = str(s.get("protocol") or "").lower()
            status = str(s.get("status") or "").lower()
            active = status == "active"
            if proto == "console" and active:
                return (0, int(s.get("session_id") or 0))
            if proto == "console":
                return (1, int(s.get("session_id") or 0))
            if proto == "rdp" and active:
                return (2, int(s.get("session_id") or 0))
            if active:
                return (3, int(s.get("session_id") or 0))
            return (4, int(s.get("session_id") or 0))

        return min(sessions, key=_rank)

    def _persistent_helper_connected(self) -> bool:
        helper = self._session_helper
        return bool(helper is not None and helper.connected)

    def _helper_command(self, secret_hex: str, port: int, _config_json: str) -> str:
        """Build a safely quoted command for source and frozen distributions."""
        import os
        import subprocess
        import sys

        argv = [sys.executable]
        if not getattr(sys, "frozen", False):
            argv.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "client.py"))
        argv.extend([
            "--rd-session-helper",
            "--rd-helper-host", "127.0.0.1",
            "--rd-helper-port", str(int(port)),
            "--rd-helper-secret", secret_hex,
            "--rd-helper-session", str(int(self._target_session_id or 0)),
            "--silent",
        ])
        return subprocess.list2cmdline(argv)

    def _start_persistent_helper(self) -> bool:
        target = self._target_session_id
        if not target:
            return False
        if self._persistent_helper_connected():
            return True
        self._stop_persistent_helper()
        try:
            from client_rd_session_helper import PersistentSessionHelper

            helper = PersistentSessionHelper(
                int(target),
                launch=lambda sid, cmd: self._launch_in_session(sid, cmd, wait=False),
                command_builder=self._helper_command,
                log=log,
            )
            config = {
                "fps": self._fps,
                "quality": self._quality,
                "max_width": self._max_width,
                "monitor": self._monitor_index,
            }
            if not helper.start(config, timeout=PROBE_TIMEOUT_SEC):
                log(f"[REMOTE-DESKTOP] persistent helper start failed: {helper.error}")
                helper.stop()
                return False
            self._session_helper = helper
            self._helper_frame_id = 0
            self._helper_frame_misses = 0
            self._capture_method = "persistent-user-helper"
            self._stats["capture_method"] = self._capture_method
            log(f"[REMOTE-DESKTOP] persistent helper connected session={target}")
            return True
        except Exception as e:
            log(f"[REMOTE-DESKTOP] persistent helper error: {e}")
            self._stop_persistent_helper()
            return False

    def _grab_via_persistent_helper(
        self, timeout: float = 2.0
    ) -> Tuple[Optional[bytes], int, int]:
        helper = self._session_helper
        if helper is None or not helper.connected:
            return None, 0, 0
        frame = helper.wait_frame(after_id=self._helper_frame_id, timeout=timeout)
        if not frame:
            self._helper_frame_misses += 1
            if self._helper_frame_misses >= 3:
                log("[REMOTE-DESKTOP] persistent helper frame timeout; scheduling restart")
                self._stop_persistent_helper()
            return None, 0, 0
        self._helper_frame_misses = 0
        frame_id, jpeg, meta = frame
        self._helper_frame_id = int(frame_id)
        width = int(meta.get("width") or 0)
        height = int(meta.get("height") or 0)
        native_width = int(meta.get("native_width") or width)
        native_height = int(meta.get("native_height") or height)
        self._screen_x = int(meta.get("origin_x") or 0)
        self._screen_y = int(meta.get("origin_y") or 0)
        self._last_helper_capture_ms = float(meta.get("capture_ms") or 0.0)
        if meta.get("capture_mono_ms"):
            self._last_capture_mono = float(meta["capture_mono_ms"]) / 1000.0
        self._screen_w, self._screen_h = native_width, native_height
        self._capture_w, self._capture_h = width, height
        method = str(meta.get("method") or "capture")
        self._capture_method = f"persistent-user-helper:{method}"
        self._stats["capture_method"] = self._capture_method
        return jpeg, width, height

    def _stop_persistent_helper(self) -> None:
        helper = self._session_helper
        self._session_helper = None
        self._helper_frame_id = 0
        self._helper_frame_misses = 0
        if helper is not None:
            try:
                helper.stop()
            except Exception:
                pass

    def _grab_via_user_helper(self) -> Tuple[Optional[bytes], int, int]:
        """Capture via CreateProcessAsUser into the target WTS session.

        Used when agent runs in Session 0 or a different session than the
        dashboard-selected session_id.
        """
        import os
        import sys
        import tempfile

        sid, csid = self._session_ids()
        target = self._target_session_id
        if not target:
            sessions = self._enumerate_sessions()
            interactive = [
                s for s in sessions
                if int(s.get("session_id") or 0) > 0
                and str(s.get("protocol") or "").lower() != "services"
            ]
            if interactive:
                target = int(self._pick_default_session(interactive)["session_id"])
            else:
                target = csid if csid not in (None, 0, 0xFFFFFFFF) else None
        if not target:
            log("[REMOTE-DESKTOP] No interactive session for helper capture")
            return None, 0, 0

        # Already in the requested session — caller should use in-process grab
        if sid is not None and sid > 0 and int(sid) == int(target):
            log(f"[REMOTE-DESKTOP] skip token-helper — already in target session={sid}")
            return None, 0, 0

        out_path = os.path.join(
            tempfile.gettempdir(), f"honeypot_rd_capture_{os.getpid()}.jpg"
        )
        try:
            if os.path.isfile(out_path):
                os.remove(out_path)
        except OSError:
            pass

        exe = sys.executable
        cmd = f'"{exe}" --rd-capture-once "{out_path}"'

        launched = self._launch_in_session(int(target), cmd)
        if not launched:
            # Session-0 subprocess cannot see another user's desktop — do not fake it
            log(
                f"[REMOTE-DESKTOP] helper launch failed for session={target} "
                "(no Session-0 fallback — would capture black)"
            )
            return None, 0, 0

        deadline = time.time() + PROBE_TIMEOUT_SEC + 2
        while time.time() < deadline:
            if os.path.isfile(out_path) and os.path.getsize(out_path) >= MIN_JPEG_BYTES:
                break
            time.sleep(0.15)
        else:
            log("[REMOTE-DESKTOP] helper capture timed out (no JPEG file)")
            return None, 0, 0

        try:
            with open(out_path, "rb") as fh:
                data = fh.read()
            if len(data) < MIN_JPEG_BYTES or data[:2] != b"\xff\xd8":
                return None, 0, 0
            try:
                from PIL import Image
                import io as _io
                im = Image.open(_io.BytesIO(data))
                w, h = im.size
            except Exception:
                w = self._max_width
                h = int(self._max_width * 9 / 16)
            self._capture_method = "user-helper"
            self._stats["capture_method"] = "user-helper"
            self._use_user_helper = True
            self._screen_w, self._screen_h = w, h
            self._capture_w, self._capture_h = w, h
            log(f"[REMOTE-DESKTOP] helper capture ok — {w}x{h} {len(data)}B session={target}")
            return data, w, h
        except Exception as e:
            log(f"[REMOTE-DESKTOP] helper read failed: {e}")
            return None, 0, 0
        finally:
            try:
                os.remove(out_path)
            except OSError:
                pass

    @staticmethod
    def _find_active_session_id() -> Optional[int]:
        """Legacy helper — prefer Console Active via enumerate."""
        try:
            sessions = RemoteDesktopStreamer._enumerate_sessions()
            interactive = [
                s for s in sessions
                if int(s.get("session_id") or 0) > 0
                and str(s.get("protocol") or "").lower() != "services"
            ]
            if not interactive:
                return None
            return int(RemoteDesktopStreamer._pick_default_session(interactive)["session_id"])
        except Exception:
            return None

    def _launch_in_session(self, session_id: int, command: str, wait: bool = True) -> bool:
        """CreateProcessAsUser in target WTS session (requires SYSTEM / SeTcbPrivilege)."""
        try:
            import ctypes
            from ctypes import wintypes
            import subprocess

            wts = ctypes.windll.wtsapi32
            adv = ctypes.windll.advapi32
            kernel = ctypes.windll.kernel32

            h_token = wintypes.HANDLE()
            if not wts.WTSQueryUserToken(session_id, ctypes.byref(h_token)):
                err = kernel.GetLastError()
                log(f"[REMOTE-DESKTOP] WTSQueryUserToken({session_id}) failed err={err}")
                return False

            class STARTUPINFO(ctypes.Structure):
                _fields_ = [
                    ("cb", wintypes.DWORD),
                    ("lpReserved", wintypes.LPWSTR),
                    ("lpDesktop", wintypes.LPWSTR),
                    ("lpTitle", wintypes.LPWSTR),
                    ("dwX", wintypes.DWORD),
                    ("dwY", wintypes.DWORD),
                    ("dwXSize", wintypes.DWORD),
                    ("dwYSize", wintypes.DWORD),
                    ("dwXCountChars", wintypes.DWORD),
                    ("dwYCountChars", wintypes.DWORD),
                    ("dwFillAttribute", wintypes.DWORD),
                    ("dwFlags", wintypes.DWORD),
                    ("wShowWindow", wintypes.WORD),
                    ("cbReserved2", wintypes.WORD),
                    ("lpReserved2", ctypes.POINTER(ctypes.c_byte)),
                    ("hStdInput", wintypes.HANDLE),
                    ("hStdOutput", wintypes.HANDLE),
                    ("hStdError", wintypes.HANDLE),
                ]

            class PROCESS_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("hProcess", wintypes.HANDLE),
                    ("hThread", wintypes.HANDLE),
                    ("dwProcessId", wintypes.DWORD),
                    ("dwThreadId", wintypes.DWORD),
                ]

            si = STARTUPINFO()
            si.cb = ctypes.sizeof(STARTUPINFO)
            si.lpDesktop = "winsta0\\default"
            pi = PROCESS_INFORMATION()
            CREATE_NO_WINDOW = 0x08000000
            cmd_buf = ctypes.create_unicode_buffer(command)

            ok = adv.CreateProcessAsUserW(
                h_token,
                None,
                cmd_buf,
                None,
                None,
                False,
                CREATE_NO_WINDOW,
                None,
                None,
                ctypes.byref(si),
                ctypes.byref(pi),
            )
            kernel.CloseHandle(h_token)
            if not ok:
                log(f"[REMOTE-DESKTOP] CreateProcessAsUser failed err={kernel.GetLastError()}")
                return False
            if wait:
                # Legacy one-shot helper must finish before its JPEG is read.
                kernel.WaitForSingleObject(pi.hProcess, int((PROBE_TIMEOUT_SEC + 2) * 1000))
            kernel.CloseHandle(pi.hThread)
            kernel.CloseHandle(pi.hProcess)
            return True
        except Exception as e:
            log(f"[REMOTE-DESKTOP] launch_in_session error: {e}")
            return False

    # ── Optional media transport / signaling ─────────────────────

    def _capabilities(self) -> dict:
        media = self._media.capabilities()
        codecs = ["jpeg"]
        for codec in media.get("codecs") or []:
            name = str(codec).lower()
            if name and name not in codecs:
                codecs.append(name)
        transports = ["jpeg-ws", "jpeg-http"]
        if media.get("webrtc"):
            transports.insert(0, "webrtc")
        return {
            "input_protocols": [1, 2],
            "input_v2": True,
            "winlogon": True,
            "pre_logon": True,
            "transports": transports,
            "fallback": "jpeg-ws",
            "codecs": codecs,
            "webrtc": {
                "available": bool(media.get("webrtc")),
                "signaling": int(media.get("webrtc_signaling") or 1),
                "ice": str(media.get("ice") or "non-trickle"),
                "ice_server_config": bool(
                    media.get("webrtc") and media.get("ice_server_config")
                ),
            },
        }

    def _hello_payload(self) -> dict:
        return {
            "t": "hello",
            "role": "agent",
            "protocol": 2,
            "stream_id": self._stream_id,
            "capabilities": self._capabilities(),
        }

    def _send_media_signal(self, message: dict) -> None:
        payload = dict(message)
        payload.setdefault("stream_id", self._stream_id)
        payload.setdefault("session_id", self._media_session_id)
        self._q_put_text(json.dumps(payload, separators=(",", ":")))

    def _on_media_fallback(self, error: str) -> None:
        self._media_session_id = ""
        if self._transport == "webrtc":
            self._transport = "websocket" if self._ws_ok else "http"
        log(f"[REMOTE-DESKTOP] WebRTC fallback to JPEG: {str(error)[:160]}")

    def _ingest_data_channel_input(self, envelope: dict):
        """WebRTC data channel and WS share the same input-v2 validator."""
        return self._ingest_events([envelope], emit_ack=False)

    def _handle_webrtc_signal(self, message: dict) -> dict:
        """Validate signaling identity before crossing into the media thread."""
        action = str(message.get("action") or "").lower()
        if not action:
            t = str(message.get("t") or message.get("type") or "").lower()
            action = {
                "webrtc_offer": "offer",
                "webrtc_answer": "answer",
                "webrtc_ice": "ice",
            }.get(t, "")
        stream_id = str(message.get("stream_id") or "")
        session_id = str(message.get("session_id") or "")
        if int(message.get("protocol") or 0) != 1:
            return {"accepted": False, "error": "unsupported signaling protocol"}
        if not self._running or not self._stream_id:
            return {"accepted": False, "error": "stream not active"}
        if not stream_id or stream_id != self._stream_id:
            return {"accepted": False, "error": "stale or mismatched stream_id"}
        if not session_id:
            return {"accepted": False, "error": "missing session_id"}
        if self._media_session_id and session_id != self._media_session_id:
            return {"accepted": False, "error": "stale or mismatched session_id"}
        if action not in ("offer", "answer", "ice"):
            return {"accepted": False, "error": "unsupported signaling action"}
        if not self._media.capabilities().get("webrtc"):
            return {"accepted": False, "error": "webrtc runtime unavailable"}

        establishing = not self._media_session_id and action == "offer"
        if not self._media_session_id and not establishing:
            return {"accepted": False, "error": "offer required before signal"}
        if establishing:
            self._media_session_id = session_id
        normalized = dict(message)
        normalized["action"] = action
        try:
            result = self._media.handle_signal(normalized)
        except Exception as exc:
            result = {"accepted": False, "error": str(exc)}
        if not result.get("accepted") and establishing:
            self._media_session_id = ""
        return result

    def _drain_out_q(self):
        with self._out_lock:
            self._pending_text.clear()
            self._pending_frame = None

    # ── WebSocket transport (single-thread send+recv) ─────────────

    def _ws_loop(self):
        """Dedicated WS thread: create_connection + drain outbound queue + recv input."""
        while self._running and not self._stop.is_set():
            token = self.token_getter()
            if not token or not self.api_client:
                self._stop.wait(WS_RECONNECT_SEC)
                continue
            try:
                import websocket
            except ImportError:
                log("[REMOTE-DESKTOP] websocket-client missing — HTTP only")
                self._transport = "http"
                return

            api_base = getattr(self.api_client, "base_url", "") or ""
            url = _api_to_ws_agent_url(api_base, token)
            log(f"[REMOTE-DESKTOP] WS connecting… {url.split('?')[0]} (Bearer)")

            ws = None
            try:
                verify = True
                try:
                    from client_security_utils import resolve_tls_verify
                    verify = bool(resolve_tls_verify())
                except Exception:
                    pass
                sslopt = None
                if not verify:
                    import ssl
                    sslopt = {"cert_reqs": ssl.CERT_NONE}

                ws_headers = [f"Authorization: Bearer {token}"]
                ws = websocket.create_connection(
                    url,
                    timeout=12,
                    sslopt=sslopt,
                    enable_multithread=True,
                    header=ws_headers,
                )
                self._ws = ws
                self._ws_ok = True
                self._transport = "websocket"
                ws.send(json.dumps(self._hello_payload()))
                self._enqueue_meta(force=True)
                self.emit_stream_progress("ws", "Agent media WS up", force=True)
                # Re-push last good frame so viewer is not blank while waiting
                if (
                    not self._media_ready()
                    and self._last_good_jpeg
                    and self._last_good_wh[0] > 0
                ):
                    self._enqueue_ws_frame(
                        self._last_good_jpeg,
                        self._last_good_wh[0],
                        self._last_good_wh[1],
                        max(1, self._seq),
                    )
                log("[REMOTE-DESKTOP] WS connected")

                ws.settimeout(0.15)
                while self._running and not self._stop.is_set():
                    # Drain outbound (meta + binary JPEG) on THIS thread
                    self._ws_flush_out(ws)
                    try:
                        msg = ws.recv()
                        if msg is not None:
                            self._on_ws_message(msg)
                    except websocket.WebSocketTimeoutException:
                        pass
                    except Exception as e:
                        log(f"[REMOTE-DESKTOP] WS recv error: {e}")
                        self._adaptive.note_ws_failure()
                        self._adaptive_tick()
                        break
            except Exception as e:
                log(f"[REMOTE-DESKTOP] WS connect/loop error: {e}")
                self._adaptive.note_ws_failure()
                self._adaptive_tick()
            finally:
                self._ws_ok = False
                self._ws = None
                if self._running:
                    self._transport = "http"
                    self._stats["ws_reconnects"] += 1
                if ws is not None:
                    try:
                        ws.close()
                    except Exception:
                        pass
                log("[REMOTE-DESKTOP] WS closed")

            if self._running and not self._stop.is_set():
                self._stop.wait(WS_RECONNECT_SEC)

    def _enqueue_meta(self, force: bool = False):
        if not force and self._seq % META_EVERY_N_FRAMES != 0:
            return
        media = self._media.status()
        media["effective_capture_fps"] = (
            self._media_fps if self._media_ready() else self._fps
        )
        media["capture_quality"] = (
            self._media_quality if self._media_ready() else self._quality
        )
        media.setdefault("encoder", "aiortc" if media.get("available") else "")
        media.setdefault("target_bitrate_bps", None)
        meta = {
            "t": "meta",
            "protocol": 2,
            "stream_id": self._stream_id,
            "capabilities": self._capabilities(),
            "width": int(self._capture_w or self._max_width),
            "height": int(self._capture_h or 720),
            "native_width": int(self._screen_w or self._capture_w or self._max_width),
            "native_height": int(self._screen_h or self._capture_h or 720),
            "origin_x": int(self._screen_x),
            "origin_y": int(self._screen_y),
            "seq": int(self._seq),
            "fps": float(self._fps),
            "quality": int(self._quality),
            "max_width": int(self._max_width),
            "requested_fps": float(self._requested_fps),
            "requested_quality": int(self._requested_quality),
            "requested_max_width": int(self._requested_max_width),
            "capture_mono_ms": int(self._last_capture_mono * 1000),
            "last_send_mono_ms": int(self._last_send_mono * 1000),
            "session_id": self._target_session_id,
            "username": self._target_username or "",
            "media": media,
        }
        self._q_put_text(json.dumps(meta))

    def _enqueue_ws_frame(self, jpeg: bytes, w: int, h: int, seq: int) -> bool:
        """Buffer latest JPEG + meta for the WS thread. Queueing is NOT a send.

        Only the newest frame is retained; a superseded frame is coalesced away
        so the viewer never receives a backlog of stale JPEGs.
        """
        self._capture_w, self._capture_h = w, h
        # Additive JSON metadata remains legacy-compatible while giving every
        # binary JPEG a preceding seq + monotonic capture timestamp.
        self._enqueue_meta(force=True)
        self._q_put_frame(jpeg)
        return True

    def _q_put_text(self, payload: str) -> None:
        """Retain a control/meta message in order (never coalesced)."""
        with self._out_lock:
            self._pending_text.append(payload)

    def _q_put_frame(self, jpeg: bytes) -> None:
        """Keep only the newest JPEG; drop (coalesce) any unsent prior frame."""
        with self._out_lock:
            if self._pending_frame is not None:
                self._stats["frames_coalesced"] += 1
                self._adaptive.note_coalesced()
            self._pending_frame = jpeg

    def _ws_binary_opcode(self):
        try:
            import websocket
            return websocket.ABNF.OPCODE_BINARY
        except Exception:
            return 0x2

    def _ws_flush_out(self, ws) -> None:
        """Send retained control/meta first, then the single latest frame.

        Frame accounting happens here (actual socket send), so the queue depth
        is never mistaken for transmission.
        """
        bin_opcode = self._ws_binary_opcode()
        while True:
            payload = None
            frame = None
            with self._out_lock:
                if self._pending_text:
                    payload = self._pending_text.popleft()
                elif self._pending_frame is not None and not self._media_ready():
                    frame = self._pending_frame
                    self._pending_frame = None
                elif self._pending_frame is not None:
                    # Connected WebRTC owns video. Drop stale JPEG rather than
                    # queueing/sending duplicate bandwidth.
                    self._pending_frame = None
                    self._stats["frames_coalesced"] += 1
                    continue
                else:
                    break
            try:
                if payload is not None:
                    ws.send(payload)
                else:
                    send_started = time.monotonic()
                    ws.send(frame, opcode=bin_opcode)
                    send_elapsed = time.monotonic() - send_started
                    self._adaptive.observe_send(
                        send_elapsed, transport="websocket", ok=True
                    )
                    self._adaptive_tick()
                    self._stats["frames_sent"] += 1
                    self._stats["bytes_sent"] += len(frame)
                    self._last_activity = time.time()
                    self._last_send_mono = time.monotonic()
            except Exception as e:
                log(f"[REMOTE-DESKTOP] WS send failed: {e}")
                self._ws_ok = False
                raise

    def _close_ws(self):
        self._ws_ok = False
        ws = self._ws
        self._ws = None
        self._drain_out_q()
        if ws is not None:
            try:
                ws.close()
            except Exception:
                pass

    def _on_ws_message(self, message):
        try:
            if isinstance(message, bytes):
                # Ignore unexpected binary from server
                try:
                    message = message.decode("utf-8", errors="replace")
                except Exception:
                    return
            data = json.loads(message)
        except Exception:
            return
        if not isinstance(data, dict):
            return
        t = (data.get("t") or data.get("type") or "").lower()
        if t in (
            "webrtc_signal",
            "webrtc_offer",
            "webrtc_answer",
            "webrtc_ice",
        ):
            result = self._handle_webrtc_signal(data)
            if not result.get("accepted"):
                self._q_put_text(json.dumps({
                    "t": "webrtc_reject",
                    "protocol": 1,
                    "stream_id": data.get("stream_id"),
                    "session_id": data.get("session_id"),
                    "error": str(result.get("error") or result.get("reason") or "rejected")[:200],
                }, separators=(",", ":")))
            return
        if t in ("input", "remote_input", ""):
            params = dict(data)
            params.pop("t", None)
            params.pop("type", None)
            # Server may batch several events under inputs[]/events[].
            batch = params.get("inputs") or params.get("events")
            if isinstance(batch, list) and batch:
                self._ingest_events(batch, emit_ack=True)
            elif (
                "event" in params
                or "gesture" in params
                or "input" in params
                or "text" in params
                or "key" in params
                or params.get("protocol") == 2
            ):
                self._ingest_events([params], emit_ack=True)

    # ── HTTP input poll (backup alongside frame ACK / WS) ─────────

    def _http_input_poll_loop(self):
        """Compatibility backup drain via GET /api/remote/inputs.

        Primary input path is WS (or frame-ACK inputs[] while on HTTP). When WS
        is healthy this poll runs slowly to avoid redundant round-trips.
        """
        while self._running and not self._stop.is_set():
            try:
                token = self.token_getter()
                if token and self.api_client and hasattr(self.api_client, "fetch_remote_inputs"):
                    events = self.api_client.fetch_remote_inputs(token, limit=80) or []
                    if events:
                        self._apply_input_batch(events)
            except Exception as e:
                log(f"[REMOTE-DESKTOP] HTTP input poll error: {e}")
            interval = HTTP_INPUT_POLL_SEC_WS if self._ws_ok else HTTP_INPUT_POLL_SEC
            self._stop.wait(interval)

    # ── Input helpers ─────────────────────────────────────────────

    def _check_move_rate(self) -> bool:
        """Move budget only — never gates critical edges."""
        now = time.time()
        while self._move_ts and now - self._move_ts[0] > MOVE_RATE_WINDOW:
            self._move_ts.popleft()
        if len(self._move_ts) >= MOVE_RATE_LIMIT:
            return False
        self._move_ts.append(now)
        return True

    def _note_critical(self) -> None:
        """Record a critical edge for stats; critical edges are never rejected."""
        now = time.time()
        while self._crit_ts and now - self._crit_ts[0] > MOVE_RATE_WINDOW:
            self._crit_ts.popleft()
        self._crit_ts.append(now)

    # Backward-compatible shim (older callers / tests).
    def _check_input_rate(self, soft: bool = False) -> bool:
        return self._check_move_rate()

    def _touch_activity(self):
        self._last_activity = time.time()

    def _release_all_buttons(self) -> None:
        """Release any buttons still held on the injecting side (anti-stuck).

        Applies where injection is local (same session or helper process). On
        the daemon forwarding side no buttons are held locally, so this is a
        no-op there; the helper releases its own on disconnect.
        """
        if not self._pressed_buttons:
            return
        up_flags = {"left": 0x0004, "right": 0x0010, "middle": 0x0040}
        for btn in list(self._pressed_buttons):
            try:
                self._emit_mouse_button(self._last_px, self._last_py, up_flags.get(btn, 0x0004))
            except Exception as e:
                log(f"[remote-input] release button {btn} failed: {e}")
            self._pressed_buttons.discard(btn)
        self._drag_active = False
        log("[remote-input] released held buttons on stop/disconnect")

    def _norm_to_px(self, x: float, y: float):
        sw = self._screen_w or self._get_screen_size()[0]
        sh = self._screen_h or self._get_screen_size()[1]
        self._screen_w, self._screen_h = sw, sh
        x = max(0.0, min(1.0, float(x)))
        y = max(0.0, min(1.0, float(y)))
        self._last_px = int(self._screen_x + x * (sw - 1))
        self._last_py = int(self._screen_y + y * (sh - 1))
        return self._last_px, self._last_py

    # ── Low-level injection primitives (overridable in tests) ──────

    def _emit_set_cursor(self, px: int, py: int) -> None:
        import ctypes
        ctypes.windll.user32.SetCursorPos(int(px), int(py))
        self._last_px, self._last_py = int(px), int(py)

    def _emit_mouse_button(self, px: int, py: int, flag: int) -> None:
        import ctypes
        user32 = ctypes.windll.user32
        user32.SetCursorPos(int(px), int(py))
        user32.mouse_event(int(flag), 0, 0, 0, 0)
        self._last_px, self._last_py = int(px), int(py)

    def _emit_mouse_wheel(self, px: int, py: int, delta: int) -> None:
        import ctypes
        user32 = ctypes.windll.user32
        user32.SetCursorPos(int(px), int(py))
        user32.mouse_event(0x0800, 0, 0, int(delta), 0)  # MOUSEEVENTF_WHEEL

    def _emit_mouse_hwheel(self, px: int, py: int, delta: int) -> None:
        import ctypes
        user32 = ctypes.windll.user32
        user32.SetCursorPos(int(px), int(py))
        user32.mouse_event(0x01000, 0, 0, int(delta), 0)  # MOUSEEVENTF_HWHEEL

    def _emit_mouse_move_relative(self, dx: int, dy: int) -> None:
        # MOUSEEVENTF_MOVE (relative) via SendInput mouse struct.
        self._send_mouse_input(int(dx), int(dy), 0x0001, 0)

    def _do_move(self, x: float, y: float) -> bool:
        px, py = self._norm_to_px(x, y)
        self._emit_set_cursor(px, py)
        return True

    def _do_move_relative(self, dx: int, dy: int) -> bool:
        if dx == 0 and dy == 0:
            return True
        self._emit_mouse_move_relative(int(dx), int(dy))
        return True

    def _do_mouse_button(self, x: float, y: float, button: str, down: bool) -> bool:
        px, py = self._norm_to_px(x, y)
        return self._do_mouse_button_at(px, py, button, down)

    def _do_mouse_button_at_current(self, button: str, down: bool) -> bool:
        return self._do_mouse_button_at(self._last_px, self._last_py, button, down)

    def _do_mouse_button_at(
        self, px: int, py: int, button: str, down: bool
    ) -> bool:
        btn = (button or "left").lower()
        if btn == "right":
            flag = 0x0008 if down else 0x0010
        elif btn == "middle":
            flag = 0x0020 if down else 0x0040
        else:
            btn = "left"
            flag = 0x0002 if down else 0x0004
        self._emit_mouse_button(px, py, flag)
        if down:
            self._pressed_buttons.add(btn)
        else:
            self._pressed_buttons.discard(btn)
        return True

    def _do_wheel(
        self, x: float, y: float, delta: int, horizontal_delta: int = 0
    ) -> bool:
        px, py = self._norm_to_px(x, y)
        if int(horizontal_delta):
            self._emit_mouse_hwheel(px, py, int(horizontal_delta))
        if int(delta):
            self._emit_mouse_wheel(px, py, int(delta))
        return True

    def _do_click(self, x: float, y: float, button: str, double: bool = False) -> bool:
        self._do_mouse_button(x, y, button, down=True)
        time.sleep(0.02)
        self._do_mouse_button(x, y, button, down=False)
        if double:
            time.sleep(0.04)
            self._do_mouse_button(x, y, button, down=True)
            time.sleep(0.02)
            self._do_mouse_button(x, y, button, down=False)
        return True

    def _do_type_text(self, text: str) -> bool:
        """Inject Unicode string via SendInput KEYEVENTF_UNICODE (layout-independent)."""
        if not text:
            return True
        ok = True
        for ch in text[:500]:
            if not self._send_unicode_char(ch):
                ok = False
            time.sleep(0.003)
        return ok

    @staticmethod
    def _send_input_structs(inputs) -> int:
        """SendInput with correctly sized INPUT union (64-bit safe)."""
        import ctypes
        from ctypes import wintypes

        user32 = ctypes.windll.user32
        ULONG_PTR = ctypes.c_ulonglong if ctypes.sizeof(ctypes.c_void_p) == 8 else ctypes.c_ulong

        class MOUSEINPUT(ctypes.Structure):
            _fields_ = [
                ("dx", wintypes.LONG),
                ("dy", wintypes.LONG),
                ("mouseData", wintypes.DWORD),
                ("dwFlags", wintypes.DWORD),
                ("time", wintypes.DWORD),
                ("dwExtraInfo", ULONG_PTR),
            ]

        class KEYBDINPUT(ctypes.Structure):
            _fields_ = [
                ("wVk", wintypes.WORD),
                ("wScan", wintypes.WORD),
                ("dwFlags", wintypes.DWORD),
                ("time", wintypes.DWORD),
                ("dwExtraInfo", ULONG_PTR),
            ]

        class HARDWAREINPUT(ctypes.Structure):
            _fields_ = [
                ("uMsg", wintypes.DWORD),
                ("wParamL", wintypes.WORD),
                ("wParamH", wintypes.WORD),
            ]

        class INPUT_UNION(ctypes.Union):
            _fields_ = [("mi", MOUSEINPUT), ("ki", KEYBDINPUT), ("hi", HARDWAREINPUT)]

        class INPUT(ctypes.Structure):
            _fields_ = [("type", wintypes.DWORD), ("u", INPUT_UNION)]

        n = len(inputs)
        arr = (INPUT * n)()
        for i, (vk, scan, flags) in enumerate(inputs):
            arr[i].type = 1  # INPUT_KEYBOARD
            arr[i].u.ki = KEYBDINPUT(vk, scan, flags, 0, 0)
        sent = int(user32.SendInput(n, ctypes.byref(arr), ctypes.sizeof(INPUT)))
        return sent

    @staticmethod
    def _send_mouse_input(dx: int, dy: int, flags: int, mouse_data: int) -> int:
        """SendInput one MOUSEINPUT (relative move uses MOUSEEVENTF_MOVE)."""
        import ctypes
        from ctypes import wintypes

        user32 = ctypes.windll.user32
        ULONG_PTR = ctypes.c_ulonglong if ctypes.sizeof(ctypes.c_void_p) == 8 else ctypes.c_ulong

        class MOUSEINPUT(ctypes.Structure):
            _fields_ = [
                ("dx", wintypes.LONG),
                ("dy", wintypes.LONG),
                ("mouseData", wintypes.DWORD),
                ("dwFlags", wintypes.DWORD),
                ("time", wintypes.DWORD),
                ("dwExtraInfo", ULONG_PTR),
            ]

        class INPUT(ctypes.Structure):
            _fields_ = [("type", wintypes.DWORD), ("mi", MOUSEINPUT)]

        inp = INPUT()
        inp.type = 0  # INPUT_MOUSE
        inp.mi = MOUSEINPUT(int(dx), int(dy), int(mouse_data) & 0xFFFFFFFF, int(flags), 0, 0)
        return int(user32.SendInput(1, ctypes.byref(inp), ctypes.sizeof(INPUT)))

    def _send_unicode_char(self, ch: str) -> bool:
        """KEYEVENTF_UNICODE down+up for one character (ğ, @, €, …)."""
        if not ch:
            return True
        KEYEVENTF_UNICODE = 0x0004
        KEYEVENTF_KEYUP = 0x0002
        code = ord(ch)
        # Surrogate pairs not needed for BMP; for >U+FFFF skip gracefully
        if code > 0xFFFF:
            log(f"[remote-input] skip non-BMP char U+{code:X}")
            return False
        sent = self._send_input_structs([
            (0, code, KEYEVENTF_UNICODE),
            (0, code, KEYEVENTF_UNICODE | KEYEVENTF_KEYUP),
        ])
        return sent == 2

    def _send_vk(self, vk: int, down: bool) -> bool:
        KEYEVENTF_KEYUP = 0x0002
        flags = 0 if down else KEYEVENTF_KEYUP
        sent = self._send_input_structs([(int(vk) & 0xFF, 0, flags)])
        return sent == 1

    def _do_key(self, key: str, code: str = "") -> bool:
        """Apply dashboard key event.

        - Single printable char → Unicode SendInput (never QWERTY scancode map)
        - Named keys / ctrl+c → virtual-key SendInput
        """
        raw = (key or "").strip()
        if not raw and not code:
            return False

        VK_NAMED = {
            "enter": 0x0D, "return": 0x0D,
            "esc": 0x1B, "escape": 0x1B,
            "tab": 0x09,
            "backspace": 0x08,
            "delete": 0x2E, "del": 0x2E,
            "up": 0x26, "down": 0x28, "left": 0x25, "right": 0x27,
            "home": 0x24, "end": 0x23,
            "f5": 0x74, "win": 0x5B, "meta": 0x5B,
            "space": 0x20,
            "pageup": 0x21, "pagedown": 0x22,
            "insert": 0x2D,
        }
        MOD = {
            "ctrl": 0x11, "control": 0x11,
            "alt": 0x12,
            "shift": 0x10,
            "win": 0x5B, "meta": 0x5B,
        }

        key_l = raw.lower()
        if key_l in ("ctrl+alt+del", "ctrl-alt-del", "ctrl+alt+delete", "cad"):
            # Real SAS requires remote_send_sas / SendSAS — not synthetic key events
            log("[remote-input] ctrl+alt+del ignored — use remote_send_sas / SendSAS")
            return False

        # Single character (including Turkish / AltGr results like @ € ğ) → Unicode
        # Do NOT lowercase before inject — preserve İ vs i etc.
        if len(raw) == 1 and key_l not in VK_NAMED and key_l not in MOD:
            return self._send_unicode_char(raw)

        # Space as literal
        if raw == " " or key_l == "space":
            return self._tap_vk(0x20)

        parts = [p for p in key_l.replace("-", "+").split("+") if p]
        if not parts:
            return False

        mods = []
        main = None
        for p in parts:
            if p in MOD:
                mods.append(MOD[p])
            elif p in VK_NAMED:
                main = VK_NAMED[p]
            elif len(p) == 1 and p.isascii() and p.isalnum():
                # ASCII letter/digit shortcut chord (ctrl+c) — VK equals uppercase ord
                main = ord(p.upper())
            elif len(p) == 1:
                # Unusual: modifier + unicode char → type unicode after mods
                main = ("unicode", p)

        if main is None and len(parts) == 1 and parts[0] in MOD:
            main = MOD[parts[0]]
            mods = []

        if main is None:
            # Optional physical code fallback (KeyQ) — still prefer failing honestly
            log(f"[remote-input] unmapped key={raw!r} code={code!r}")
            return False

        for m in mods:
            self._send_vk(m, down=True)
        try:
            if isinstance(main, tuple) and main[0] == "unicode":
                ok = self._send_unicode_char(main[1])
            else:
                ok = self._tap_vk(int(main))
        finally:
            for m in reversed(mods):
                self._send_vk(m, down=False)
        return ok

    def _tap_vk(self, vk: int) -> bool:
        ok1 = self._send_vk(vk, down=True)
        ok2 = self._send_vk(vk, down=False)
        return ok1 and ok2

    # ── Screen / DPI ──────────────────────────────────────────────

    @staticmethod
    def _ensure_dpi_aware():
        try:
            import ctypes
            try:
                ctypes.windll.shcore.SetProcessDpiAwareness(2)
            except Exception:
                ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass

    @staticmethod
    def _get_screen_size():
        try:
            import ctypes
            user32 = ctypes.windll.user32
            return int(user32.GetSystemMetrics(0)), int(user32.GetSystemMetrics(1))
        except Exception:
            return 1920, 1080

    def _get_capture_rect(self) -> Tuple[int, int, int, int]:
        """Selected monitor rectangle in virtual-desktop coordinates."""
        try:
            import ctypes
            from ctypes import wintypes

            user32 = ctypes.windll.user32

            class RECT(ctypes.Structure):
                _fields_ = [
                    ("left", wintypes.LONG),
                    ("top", wintypes.LONG),
                    ("right", wintypes.LONG),
                    ("bottom", wintypes.LONG),
                ]

            monitors = []
            callback_type = getattr(ctypes, "WINFUNCTYPE", ctypes.CFUNCTYPE)

            @callback_type(
                wintypes.BOOL,
                wintypes.HANDLE,
                wintypes.HDC,
                ctypes.POINTER(RECT),
                wintypes.LPARAM,
            )
            def callback(_monitor, _hdc, rect_ptr, _data):
                rect = rect_ptr.contents
                monitors.append((
                    int(rect.left),
                    int(rect.top),
                    int(rect.right - rect.left),
                    int(rect.bottom - rect.top),
                ))
                return True

            user32.EnumDisplayMonitors(0, None, callback, 0)
            if monitors:
                # Dashboard monitor=0 historically means primary. Keep the
                # monitor containing (0,0) first, then stable enumeration order.
                monitors.sort(
                    key=lambda r: (
                        0 if r[0] <= 0 < r[0] + r[2] and r[1] <= 0 < r[1] + r[3] else 1
                    )
                )
                idx = min(max(0, int(self._monitor_index)), len(monitors) - 1)
                return monitors[idx]
        except Exception:
            pass
        width, height = self._get_screen_size()
        return 0, 0, int(width), int(height)


def capture_once_to_file(path: str, max_width: int = DEFAULT_MAX_WIDTH, quality: int = DEFAULT_QUALITY) -> bool:
    """CLI helper: grab desktop JPEG to path (runs in interactive session)."""
    import os
    rd = RemoteDesktopStreamer()
    rd._max_width = max_width
    rd._quality = quality
    jpeg, w, h = rd._grab_jpeg()
    if not jpeg or w <= 0 or h <= 0 or len(jpeg) < MIN_JPEG_BYTES:
        log(f"[REMOTE-DESKTOP] capture_once failed — {w}x{h} bytes={0 if not jpeg else len(jpeg)}")
        return False
    if "+black" in (rd._capture_method or ""):
        log("[REMOTE-DESKTOP] capture_once nearly-black — refuse write")
        return False
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(jpeg)
    log(f"[REMOTE-DESKTOP] capture_once wrote {path} ({w}x{h} {len(jpeg)}B)")
    return True
