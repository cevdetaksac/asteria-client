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

# Defaults: JPEG-WS must stay video-like when WebRTC UDP is blocked (Cloudflare 443).
DEFAULT_FPS = 30.0
DEFAULT_QUALITY = 72
DEFAULT_MAX_WIDTH = 1920
MIN_ENCODE_WIDTH = 1280
MIN_ENCODE_HEIGHT = 720
TARGET_FRAME_BYTES = 700 * 1024
MAX_FRAME_BYTES = 2 * 1024 * 1024
MEDIA_CAPTURE_FPS = 60.0
MEDIA_CAPTURE_QUALITY = 85
JPEG_FALLBACK_FPS_WHILE_NEGOTIATING = 30.0
TARGET_VIDEO_BITRATE_BPS = 12_000_000
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
WS_KEEPALIVE_SEC = 25.0
META_EVERY_N_FRAMES = 5
BLACK_MEAN_THRESHOLD = 6.0            # nearly-black capture → skip send
# C-RD-CHROME-2: near-zero luma variance + no bright glyphs → solid fill (blue/grey)
FLAT_VARIANCE_THRESHOLD = 12.0
FLAT_BRIGHT_RATIO_MAX = 0.005         # <0.5% bright pixels → no clock/text glyphs
HTTP_KEYFRAME_EVERY = 6               # also POST HTTP every N frames (dashboard cache)
MIN_JPEG_BYTES = 1500                 # API rejects tinier frames ("Frame too small")
MIN_GOOD_JPEG_BYTES = 5 * 1024        # healthy 1280q35 frame is usually ≥5KB
CAPTURE_FAIL_SECONDS = 10.0           # no frames in this window → fail stream
WINLOGON_BLACK_FAIL_SECONDS = 2.0     # C-RD-P0-WL-4: unbroken black → fail
WINLOGON_FLAT_FAIL_SECONDS = 4.0      # C-RD-PIX: settle PrintWindow then fail
WINLOGON_FLAT_SETTLE_SECONDS = 4.0    # soft-degraded window even with hwnd≥1
PROBE_TIMEOUT_SEC = 12.0              # legacy one-shot cold-start room
# Logon/Winlogon start budgets.
# 4.9.88/89 lab: mid-probe force_desktop_reattach SetThreadDesktop on the *command*
# thread left capture thread thinking it was attached → solid-blue BitBlt (gdi+flat).
# 4.9.90: per-thread desktop bind; invalidate-only reattach; soft-degraded if chrome late.
WINLOGON_HELPER_ACCEPT_SEC = 5.0
WINLOGON_HELPER_FRAME_SEC = 5.0       # first non-flat chrome frame (C-RD-CHROME-1 ≤3–5s)
WINLOGON_HELPER_RETRY = 1             # one re-spawn; no command-thread attach storm
WINLOGON_ONESHOT_WAIT_SEC = 3.0
WINLOGON_HELPER_SETTLE_SEC = 0.35     # brief LogonUI paint; capture thread owns attach
FOLLOW_ACCEPT_SEC = 8.0               # C-RD-FOLLOW helper respawn after logon (Welcome)
FOLLOW_DEFAULT_PROBE_SEC = 10.0       # wait for healthy Default pixels after switch
FOLLOW_HELPER_RETRIES = 3             # spawn retries before DXGI in-process fallback
FOLLOW_CHECK_SEC = 0.25
# Post-logon Default can paint gdi+black while Welcome/DWM settles (Derin lab).
DEFAULT_BLACK_RECOVER_SEC = 1.5
# Local rd_capture_diag: dump after sustained empty frames (Ninety Default no_frame).
DIAG_NO_FRAME_DUMP_SEC = 2.0
DIAG_DUMP_COOLDOWN_SEC = 25.0
HELPER_ACCEPT_SEC = 5.0               # non-winlogon helper accept (was 12s → 23s stacks)
HELPER_FRAME_SEC = 5.0
HELPER_ONESHOT_WAIT_SEC = 4.0

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


def normalize_stream_knobs(fps, quality, max_width) -> tuple:
    """Dashboard Start still examples fps=12/q=40/w=1280 — that is a slideshow.

    Gigabit JPEG-WS and 1080p60 H.264 need a video floor even when the command
    still carries the old contract sample knobs.
    """
    try:
        dash_fps = float(fps if fps is not None else DEFAULT_FPS)
    except (TypeError, ValueError):
        dash_fps = DEFAULT_FPS
    if dash_fps < 24.0:
        dash_fps = 30.0
    try:
        dash_q = int(quality if quality is not None else DEFAULT_QUALITY)
    except (TypeError, ValueError):
        dash_q = DEFAULT_QUALITY
    if dash_q < 55:
        dash_q = DEFAULT_QUALITY
    try:
        dash_w = int(max_width if max_width is not None else DEFAULT_MAX_WIDTH)
    except (TypeError, ValueError):
        dash_w = DEFAULT_MAX_WIDTH
    if dash_w < 1280:
        dash_w = DEFAULT_MAX_WIDTH
    return (
        max(24.0, min(dash_fps, 60.0)),
        max(55, min(dash_q, 90)),
        max(1280, min(dash_w, 1920)),
    )


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
        self._agent_ws_enabled = False
        self._thread: Optional[threading.Thread] = None
        self._ws_thread: Optional[threading.Thread] = None
        self._input_poll_thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._ws_thread_stop = threading.Event()
        self._last_ws_keepalive = 0.0

        self._fps = DEFAULT_FPS
        self._quality = DEFAULT_QUALITY
        self._max_width = DEFAULT_MAX_WIDTH
        self._requested_fps = DEFAULT_FPS
        self._requested_quality = DEFAULT_QUALITY
        self._requested_max_width = DEFAULT_MAX_WIDTH
        # Cloud Start preferred_transport (default websocket / JPEG-WS primary).
        self._preferred_transport = "websocket"
        # WebRTC capture pacing is independent from JPEG-era stream knobs.
        self._media_fps = MEDIA_CAPTURE_FPS
        self._media_quality = MEDIA_CAPTURE_QUALITY
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
        self._last_helper_raw: Optional[Tuple[bytes, int, int]] = None
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
        self._flat_warn_ts = 0.0
        self._flat_streak_started = 0.0
        self._winlogon_flat_retried = False
        self._last_frame_variance = 0.0
        self._last_frame_bright_ratio = 0.0
        self._chrome_detected = False
        self._last_helper_token_source = ""
        self._last_helper_fail_phase = ""
        self._last_helper_fail_detail = ""
        self._last_stream_error = ""
        self._last_unhealthy_jpeg_bytes = 0
        self._last_diag_emit_mono = 0.0
        self._capture_recovery_steps: list = []
        self._last_diag_dump_path = ""
        self._last_hwnd_classes: list = []
        self._last_diag_dump_mono = 0.0
        self._last_diag_dump_reason = ""
        self._diag_dump_reasons_this_stream: set = set()
        self._no_frame_streak_started = 0.0
        self._last_diag_was_healthy = False
        self._capture_method = "none"
        self._stream_started_at = 0.0
        self._use_user_helper = False  # Session 0 / other session → CreateProcessAsUser helper
        self._in_session_helper = False  # True inside --rd-session-helper process
        self._session_helper = None     # persistent authenticated loopback bridge
        self._helper_spawned_winlogon = None
        self._helper_frame_id = 0
        self._helper_frame_misses = 0
        self._input_desktop = None
        self._desktop_attached = False
        # SetThreadDesktop is per-thread — only skip re-bind for *this* thread id.
        self._desktop_attach_tid: Optional[int] = None
        self._desktop_name = ""
        self._winlogon_mode = False
        self._follow_console = False  # omit session_id → physical console (C-RD-FOLLOW-6)
        self._force_secure_desktop = False
        self._follow_lock = threading.Lock()
        self._follow_busy = False
        self._last_follow_check = 0.0
        self._helper_spawn_session_id = 0
        self._prefer_dxgi = False
        self._desktop_reattach_every = 3  # C-RD-FOLLOW-3: Default before next frames
        self._logonui_hwnd_count = 0
        self._chrome_diag_logged = False
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
        self._last_input_event = ""
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
            "flat_frames": 0,
            "capture_method": "none",
            "frame_variance": 0.0,
            "bright_ratio": 0.0,
            "chrome_detected": False,
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
        # C-RD-PROG-4 / C-RD-CHROME-2: never advertise live for black/flat-only capture
        method = self._capture_method or ""
        if phase_l in ("live", "connected") and (
            "+black" in method or "+flat" in method
        ):
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
              topology: Optional[str] = None,
              preferred_transport: Optional[str] = None,
              command_id: Optional[str] = None) -> dict:
        """Start capture + WS (with HTTP fallback).

        Honest start: resolve WTS session_id, probe desktop first.
        No interactive sessions → NO_INTERACTIVE_SESSION.
        screen/capture 0×0 → CAPTURE_NO_DESKTOP.

        ``topology=follow`` (default Connect, omit session_id): live Default
        skips Winlogon helper. ``topology=winlogon`` (lock/logon row) forces it.
        Legacy ``prefer=winlogon`` without SID is treated as follow (1.4.59).

        ``preferred_transport=websocket`` (cloud default): keep JPEG-WS alive
        even while WebRTC ICE connects. ``webrtc`` may suppress JPEG only after
        media is truly ready (healthy frame + ICE/DTLS connected).
        """
        prefer_l = str(prefer or "").strip().lower()
        desktop_l = str(desktop or "").strip().lower()
        from client_rd_winlogon import resolve_start_topology
        topo_mode, force_secure = resolve_start_topology(
            topology=str(topology or ""),
            prefer=prefer_l,
            desktop=desktop_l,
            pre_logon=pre_logon,
            session_id_omitted=session_id is None,
        )
        # Only lock/logon topology forces Winlogon. ``topology=follow`` must NOT
        # set this — otherwise we pick the pre_logon sibling and Session-0 GDI
        # paints gdi+black while Default is live (dashboard P0 warning).
        want_winlogon = bool(force_secure)
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
            self._preferred_transport = self._normalize_preferred_transport(
                preferred_transport
            )
            self._requested_fps, self._requested_quality, self._requested_max_width = (
                normalize_stream_knobs(fps, quality, max_width)
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
            self._stats["flat_frames"] = 0
            self._stats["frame_variance"] = 0.0
            self._stats["bright_ratio"] = 0.0
            self._stats["chrome_detected"] = False
            # Per-stream input proof (C-RD-IN-WL-3). 4.9.91 used max(parent
            # lifetime, helper-process tally) → stuck at 260 while bullets worked.
            self._stats["inputs_applied"] = 0
            self._last_input_event = ""
            self._desktop_attached = False
            self._desktop_attach_tid = None
            self._desktop_name = ""
            self._winlogon_mode = False
            self._follow_console = False
            self._force_secure_desktop = bool(force_secure)
            self._follow_busy = False
            self._last_follow_check = 0.0
            self._helper_spawn_session_id = 0
            self._prefer_dxgi = False
            self._tscon_attempted = False
            self._active_rdp_fallback_attempted = False
            self._default_black_recover_attempted = False
            self._default_dxgi_retry_this_streak = False
            self._logonui_hwnd_count = 0
            self._chrome_diag_logged = False
            self._black_streak_started = 0.0
            self._winlogon_black_retried = False
            self._flat_streak_started = 0.0
            self._winlogon_flat_retried = False
            self._last_frame_variance = 0.0
            self._last_frame_bright_ratio = 0.0
            self._chrome_detected = False
            self._last_helper_token_source = ""
            self._last_helper_fail_phase = ""
            self._last_helper_fail_detail = ""
            self._last_stream_error = ""
            self._last_unhealthy_jpeg_bytes = 0
            self._last_diag_emit_mono = 0.0
            self._capture_recovery_steps = []
            self._last_diag_dump_path = ""
            self._last_hwnd_classes = []
            self._last_diag_dump_mono = 0.0
            self._last_diag_dump_reason = ""
            self._diag_dump_reasons_this_stream = set()
            self._no_frame_streak_started = 0.0
            self._last_diag_was_healthy = False
            self._last_good_jpeg = None
            self._last_good_wh = (0, 0)
            self._use_user_helper = False
            self._in_session_helper = False
            self._helper_spawned_winlogon = None
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

            # C-RD-CON-3 / TOPO-1: omit-sid and Winlogon never bind Start username.
            bind_username = None if (want_winlogon or session_id is None) else username

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
                # C-RD-FOLLOW-6 / C-RD-S0-1: omit session_id → console only.
                # Never bind the first Active SID from list_sessions.
                self._follow_console = True
                try:
                    from client_rd_winlogon import console_session_id
                    csid = int(console_session_id() or 0)
                except Exception:
                    csid = 0
                if csid <= 0:
                    err = "NO_CONSOLE_SESSION"
                    msg = (
                        "WTSGetActiveConsoleSessionId returned 0 — "
                        "refusing to invent session_id (C-RD-S0-1)"
                    )
                    log(f"[REMOTE-DESKTOP] ✖ {err}: {msg}")
                    self._running = False
                    self._transport = "idle"
                    self._target_session_id = None
                    self.emit_stream_progress("failed", msg, error=err, force=True)
                    return {
                        "success": False,
                        "error": err,
                        "message": msg,
                        "data": self.get_status(),
                    }
                same_sid = [
                    s for s in interactive
                    if int(s.get("session_id") or 0) == csid
                ]
                if want_winlogon and not same_sid:
                    same_sid = [
                        s for s in interactive if s.get("pre_logon")
                    ]
                picked = None
                if same_sid:
                    picked = self._select_session_row(
                        same_sid, want_winlogon=want_winlogon, username=bind_username
                    ) or same_sid[0]
                self._target_session_id = csid
                if want_winlogon:
                    self._target_username = ""
                    match = picked or {
                        "session_id": csid,
                        "pre_logon": True,
                        "desktop": "winlogon",
                        "username": "",
                    }
                else:
                    self._target_username = (
                        (bind_username or "").strip()
                        or str((picked or {}).get("username") or "")
                    )
                    match = picked or {
                        "session_id": csid,
                        "username": self._target_username,
                    }
                log(
                    f"[REMOTE-DESKTOP] omit-sid → console "
                    f"WTSGetActiveConsoleSessionId={csid} winlogon={want_winlogon}"
                )

            match_meta = match if isinstance(match, dict) else {}
            self._winlogon_mode = bool(force_secure)
            if self._winlogon_mode:
                self._target_username = ""
            elif (
                match_meta.get("pre_logon")
                and not str(self._target_username or "").strip()
            ):
                self._winlogon_mode = True
            else:
                # Follow **and** SID Start: decide from input desktop / lock /
                # LogonUI — not from WTS username alone (lab 4.9.103 SID FAIL).
                # Password / explicit SID+user: unknown lock → Default (not Winlogon).
                session_bound = bool(
                    not force_secure
                    and session_id is not None
                    and str(self._target_username or "").strip()
                )
                self._apply_follow_secure_or_default(
                    prefer_default_on_unknown=session_bound
                )
            # C-RD-FOLLOW: omit-sid live Default must not spawn Winlogon helper.
            if self._follow_console and not self._force_secure_desktop:
                self._maybe_skip_winlogon_for_live_console()

            pid_sid, csid = self._session_ids()
            # Cross-session capture MUST use CreateProcessAsUser helper.
            # Session-0 OpenWindowStation("WinSta0") opens *Session 0's* WinSta0 —
            # named Winlogon attach there yields desktop=Winlogon + gdi+black (C-RD-P0-WL).
            # Launch helper into the console session with lpDesktop=winsta0\Winlogon.
            need_helper = (
                self._target_session_id is not None
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
                self._last_helper_fail_phase = ""
                self._last_helper_fail_detail = ""
                blackish = False
                flattish = False
                persistent_started = False
                accept_timeout = (
                    WINLOGON_HELPER_ACCEPT_SEC
                    if self._winlogon_mode
                    else HELPER_ACCEPT_SEC
                )
                frame_budget = (
                    WINLOGON_HELPER_FRAME_SEC
                    if self._winlogon_mode
                    else HELPER_FRAME_SEC
                )
                retries = (
                    WINLOGON_HELPER_RETRY if self._winlogon_mode else 1
                )

                def _probe_persistent_frames(deadline: float) -> tuple:
                    nonlocal blackish, flattish
                    local_jpeg, local_w, local_h = None, 0, 0
                    last_invalidate = 0.0
                    while time.time() < deadline:
                        local_jpeg, local_w, local_h = self._grab_via_persistent_helper(
                            0.35
                        )
                        if (
                            (not local_jpeg or len(local_jpeg) < MIN_JPEG_BYTES)
                            and self._last_helper_raw
                        ):
                            local_jpeg, local_w, local_h = self._encode_helper_raw_jpeg()
                        blackish = "+black" in (self._capture_method or "")
                        flattish = "+flat" in (self._capture_method or "")
                        if (
                            local_jpeg
                            and local_w > 0
                            and local_h > 0
                            and len(local_jpeg) >= MIN_JPEG_BYTES
                            and not blackish
                            and not flattish
                        ):
                            return local_jpeg, local_w, local_h
                        # Invalidate bind only — never SetThreadDesktop on parent/command
                        # path during probe (poisoned capture thread → gdi+flat).
                        now = time.time()
                        if (
                            self._winlogon_mode
                            and (flattish or blackish)
                            and self._persistent_helper_connected()
                            and (now - last_invalidate) >= 0.9
                        ):
                            last_invalidate = now
                            try:
                                self._session_helper.force_desktop_reattach(timeout=0.8)
                            except Exception:
                                pass
                        time.sleep(0.08)
                    return local_jpeg, local_w, local_h

                for attempt in range(retries + 1):
                    if attempt:
                        self._stop_persistent_helper()
                        time.sleep(0.35)
                        log(
                            f"[REMOTE-DESKTOP] winlogon helper retry "
                            f"{attempt}/{retries} token={self._last_helper_token_source}"
                        )
                    persistent_started = self._start_persistent_helper(
                        accept_timeout=accept_timeout
                    )
                    if not persistent_started:
                        phase = self._last_helper_fail_phase or "spawn"
                        log(
                            f"[REMOTE-DESKTOP] persistent helper start failed "
                            f"phase={phase} token={self._last_helper_token_source} "
                            f"detail={self._last_helper_fail_detail}"
                        )
                        continue
                    # Brief settle only — capture thread must own SetThreadDesktop.
                    if self._winlogon_mode:
                        time.sleep(WINLOGON_HELPER_SETTLE_SEC)
                    jpeg, w, h = _probe_persistent_frames(time.time() + frame_budget)
                    if (
                        jpeg
                        and w > 0
                        and h > 0
                        and len(jpeg) >= MIN_JPEG_BYTES
                        and not blackish
                        and not flattish
                    ):
                        break
                    self._last_helper_fail_phase = (
                        self._last_helper_fail_phase
                        or ("flat" if flattish else "no_frame")
                    )
                    self._last_helper_fail_detail = (
                        f"method={self._capture_method} "
                        f"jpeg={0 if not jpeg else len(jpeg)}B "
                        f"black={blackish} flat={flattish} "
                        f"var={self._last_frame_variance:.1f}"
                    )

                took = time.time() - t_helper
                good = bool(
                    jpeg
                    and w > 0
                    and h > 0
                    and len(jpeg) >= MIN_JPEG_BYTES
                    and not blackish
                    and not flattish
                )
                if not good:
                    # Short legacy oneshot only when persistent never connected —
                    # avoid stacking another 14s wait after accept_timeout.
                    oneshot_wait = (
                        WINLOGON_ONESHOT_WAIT_SEC
                        if self._winlogon_mode
                        else HELPER_ONESHOT_WAIT_SEC
                    )
                    if not persistent_started:
                        log(
                            "[REMOTE-DESKTOP] persistent helper never connected; "
                            f"short oneshot ≤{oneshot_wait:.0f}s "
                            f"(token={self._last_helper_token_source})"
                        )
                        oneshot_t0 = time.time()
                        jpeg, w, h = self._grab_via_user_helper(wait_sec=oneshot_wait)
                        took = time.time() - t_helper
                        if (
                            (not jpeg or len(jpeg) < MIN_JPEG_BYTES)
                            and (time.time() - oneshot_t0) < 0.35
                        ):
                            self._last_helper_fail_phase = (
                                self._last_helper_fail_phase or "spawn"
                            )
                    else:
                        # Keep helper for soft-degraded flat settle (chrome may appear).
                        soft_keep = (
                            self._winlogon_mode
                            and flattish
                            and not blackish
                            and jpeg
                            and w > 0
                            and h > 0
                            and len(jpeg) >= MIN_JPEG_BYTES
                        )
                        if not soft_keep:
                            self._stop_persistent_helper()

                took = time.time() - t_helper
                log(
                    f"[REMOTE-DESKTOP] helper probe took {took:.1f}s "
                    f"jpeg={0 if not jpeg else len(jpeg)}B {w}x{h} "
                    f"token={self._last_helper_token_source or '?'} "
                    f"phase={self._last_helper_fail_phase or 'ok'} "
                    f"method={self._capture_method}"
                )
                if not jpeg or w <= 0 or h <= 0 or len(jpeg) < MIN_JPEG_BYTES:
                    helper_err = (
                        f"user-helper failed for session={self._target_session_id} "
                        f"(jpeg={0 if not jpeg else len(jpeg)}B, {took:.1f}s, "
                        f"token={self._last_helper_token_source or 'none'}, "
                        f"phase={self._last_helper_fail_phase or 'unknown'}). "
                        "Agent is Session 0 — capture requires WTSQueryUserToken/"
                        "CreateProcessAsUser (or Winlogon/LogonUI token) into the "
                        "console session on winsta0\\Winlogon."
                    )
                    phase = (self._last_helper_fail_phase or "").lower()
                    # Fail-fast reason codes (lab 4.9.87 mislabeled 23s as black).
                    if phase in ("spawn", "accept", "token", "create"):
                        err = "SESSION0_HELPER_SPAWN_FAILED"
                        msg = (
                            "Session-0 helper spawn/accept failed "
                            f"(session={self._target_session_id}, "
                            f"desktop={self._helper_desktop()}, "
                            f"token={self._last_helper_token_source or 'none'}, "
                            f"phase={phase}, "
                            f"jpeg={0 if not jpeg else len(jpeg)}B, {took:.1f}s). "
                            f"{helper_err}"
                        )
                    elif phase in ("no_frame",) or took >= (
                        accept_timeout + frame_budget - 0.5
                    ):
                        err = "SESSION0_HELPER_NO_FRAME"
                        msg = (
                            "Winlogon helper connected but produced no JPEG "
                            f"(session={self._target_session_id}, "
                            f"token={self._last_helper_token_source or 'none'}, "
                            f"{took:.1f}s). {helper_err}"
                        )
                    elif self._winlogon_mode:
                        err = "winlogon_capture_black"
                        msg = (
                            "Winlogon helper failed to capture logon UI pixels "
                            f"(session={self._target_session_id}, "
                            f"desktop={self._helper_desktop()}, "
                            f"token={self._last_helper_token_source or 'none'}). "
                            f"{helper_err}"
                        )
                    else:
                        err = "CAPTURE_NO_DESKTOP"
                        msg = helper_err
                    self._capture_method = "none"
                    self._stats["capture_method"] = "none"
                    fb = self._fallback_winlogon_helper_to_default(
                        jpeg=jpeg, w=w, h=h, phase=phase
                    )
                    if fb:
                        jpeg, w, h = fb
                    else:
                        log(f"[REMOTE-DESKTOP] ✖ {err}: {msg}")
                        self._persist_capture_fail_dump(
                            reason=err,
                            jpeg=jpeg,
                            detail=msg,
                            force=True,
                        )
                        self._running = False
                        self._transport = "idle"
                        self.emit_stream_progress("failed", msg, error=err, force=True)
                        return {
                            "success": False,
                            "error": err,
                            "message": msg,
                            "data": self.get_status(),
                        }
                # Connected but only black/flat after retries.
                if (blackish or flattish) and self._winlogon_mode:
                    hwnd_n = int(getattr(self, "_logonui_hwnd_count", 0) or 0)
                    # Soft-degraded: keep helper while PrintWindow settle runs —
                    # hwnd≥1 + attached still gets a settle window (Derin class).
                    allow_settle = bool(
                        flattish
                        and not blackish
                        and persistent_started
                        and jpeg
                        and w > 0
                        and h > 0
                        and len(jpeg) >= MIN_JPEG_BYTES
                        and (
                            hwnd_n <= 0
                            or bool(self._desktop_attached)
                        )
                    )
                    if allow_settle:
                        # One more PrintWindow burst before declaring degraded.
                        try:
                            self._note_recovery("start_settle_printwindow")
                            self.force_winlogon_recapture()
                            jpeg2, w2, h2 = self._grab_via_persistent_helper(0.8)
                            method2 = self._capture_method or ""
                            if (
                                jpeg2
                                and w2 > 0
                                and h2 > 0
                                and "+flat" not in method2
                                and "+black" not in method2
                            ):
                                jpeg, w, h = jpeg2, w2, h2
                                flattish = False
                                blackish = False
                        except Exception:
                            pass
                    if allow_settle and flattish:
                        log(
                            "[REMOTE-DESKTOP] ⚠ winlogon start soft-degraded: "
                            f"flat settle method={self._capture_method} "
                            f"var={self._last_frame_variance:.1f} "
                            f"hwnd={hwnd_n} attached={bool(self._desktop_attached)} "
                            f"desk={self._desktop_name or '?'} — keep streaming "
                            f"≤{WINLOGON_FLAT_SETTLE_SECONDS:.0f}s"
                        )
                        self._last_helper_fail_phase = ""
                        if self._flat_streak_started <= 0:
                            self._flat_streak_started = time.time()
                        self.emit_stream_progress(
                            "degraded",
                            "Winlogon settle flat; waiting for LogonUI chrome",
                            error="",
                            force=True,
                        )
                    elif flattish or blackish:
                        # C-RD-HOST-2: console Winlogon flat on Server → Active RDP Default.
                        fb_rdp = None
                        try:
                            self._note_recovery("try:active_rdp_fallback")
                            fb_rdp = self._fallback_flat_winlogon_to_active_rdp()
                        except Exception as exc:
                            self._note_recovery(f"fail:active_rdp_fallback:{exc}")
                            fb_rdp = None
                        if fb_rdp:
                            jpeg, w, h = fb_rdp
                            flattish = False
                            blackish = False
                            self._note_recovery("ok:active_rdp_fallback")
                            self.emit_stream_progress(
                                "capturing",
                                "Active RDP session fallback after console flat",
                                force=True,
                            )
                        else:
                            err = (
                                "winlogon_capture_flat"
                                if flattish and not blackish
                                else "winlogon_capture_black"
                            )
                            msg = (
                                "Winlogon/GDI capture returned unbroken "
                                f"{'flat/blue' if err.endswith('flat') else 'black'} "
                                f"after retry (method={self._capture_method}, "
                                f"hwnd={hwnd_n}, "
                                f"attached={bool(self._desktop_attached)}, "
                                f"token={self._last_helper_token_source or 'none'})"
                            )
                            self._capture_method = self._capture_method or "none"
                            log(f"[REMOTE-DESKTOP] ✖ {err}: {msg}")
                            self._persist_capture_fail_dump(
                                reason=err,
                                jpeg=jpeg,
                                detail=msg,
                                force=True,
                            )
                            self._running = False
                            self._transport = "idle"
                            self.emit_stream_progress("failed", msg, error=err, force=True)
                            return {
                                "success": False,
                                "error": err,
                                "message": msg,
                                "data": self.get_status(),
                            }
                wrong_secure = (
                    not self._winlogon_mode
                    and "winlogon" in str(self._desktop_name or "").lower()
                )
                if (blackish or flattish or wrong_secure) and not self._winlogon_mode:
                    fb = self._fallback_user_helper_to_winlogon(
                        jpeg=jpeg, w=w, h=h, phase="gdi_black"
                    )
                    if fb:
                        jpeg, w, h = fb
                        blackish = "+black" in (self._capture_method or "")
                        flattish = "+flat" in (self._capture_method or "")
                    elif blackish:
                        # PIX-4: unlocked Default + gdi black → retry DXGI / Active RDP.
                        recovered = self._recover_default_black_capture()
                        if recovered:
                            jpeg, w, h = recovered
                            blackish = "+black" in (self._capture_method or "")
                        if blackish or not jpeg:
                            err = "winlogon_capture_black"
                            msg = (
                                "Follow Default helper painted gdi+black "
                                f"(method={self._capture_method}, "
                                f"desk={self._desktop_name or '?'}); "
                                "DXGI/Active recovery also failed"
                            )
                            log(f"[REMOTE-DESKTOP] ✖ {err}: {msg}")
                            self._persist_capture_fail_dump(
                                reason=err,
                                jpeg=jpeg,
                                detail=msg,
                                force=True,
                            )
                            self._running = False
                            self._transport = "idle"
                            self.emit_stream_progress(
                                "failed", msg, error=err, force=True
                            )
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
                flattish = "+flat" in (self._capture_method or "")
                if blackish or flattish or not jpeg:
                    # One more attempt after forced console reconnect
                    if not self._tscon_attempted:
                        self._try_reconnect_session_to_console(self._target_session_id)
                        time.sleep(0.4)
                        self._desktop_attached = False
                        self._attach_input_desktop()
                        jpeg, w, h = self._grab_jpeg()
                        blackish = "+black" in (self._capture_method or "")
                        flattish = "+flat" in (self._capture_method or "")
                if self._winlogon_mode and (
                    blackish or flattish or not jpeg or w <= 0 or h <= 0
                    or (jpeg and len(jpeg) < MIN_JPEG_BYTES)
                ):
                    self._desktop_attached = False
                    self._attach_input_desktop()
                    jpeg, w, h = self._grab_jpeg()
                    blackish = "+black" in (self._capture_method or "")
                    flattish = "+flat" in (self._capture_method or "")
                    if (
                        blackish
                        or flattish
                        or not jpeg
                        or w <= 0
                        or h <= 0
                        or len(jpeg) < MIN_JPEG_BYTES
                    ):
                        err = (
                            "winlogon_capture_flat"
                            if flattish and not blackish
                            else "winlogon_capture_black"
                        )
                        msg = (
                            "Winlogon/GDI capture returned unbroken "
                            f"{'flat/blue' if err.endswith('flat') else 'black'} "
                            f"(method={self._capture_method})"
                        )
                        log(f"[REMOTE-DESKTOP] ✖ {err}: {msg}")
                        self._last_stream_error = err
                        self._persist_capture_fail_dump(
                            reason=err,
                            jpeg=jpeg,
                            detail=msg,
                            force=True,
                        )
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
                self._persist_capture_fail_dump(
                    reason=err,
                    jpeg=jpeg,
                    detail=msg,
                    force=True,
                )
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
            if self._use_user_helper and self._persistent_helper_connected():
                # JPEG-WS is the live video path until WebRTC ICE actually connects.
                # Prefer JPEG encode in-helper (no RGB loopback tax during ICE wait).
                cfg = {
                    "fps": max(
                        float(self._requested_fps),
                        JPEG_FALLBACK_FPS_WHILE_NEGOTIATING,
                    ),
                    "quality": max(int(self._requested_quality), DEFAULT_QUALITY),
                    "max_width": max(int(self._requested_max_width), 1280),
                    "monitor": self._monitor_index,
                    "prefer_raw": False,
                    "winlogon": bool(self._winlogon_mode),
                }
                self._session_helper.update_config(cfg)

            self._thread = threading.Thread(
                target=self._capture_loop,
                name="RemoteDesktopCapture",
                daemon=True,
            )
            self._thread.start()
            self.ensure_agent_ws()
            self._input_poll_thread = threading.Thread(
                target=self._http_input_poll_loop,
                name="RemoteDesktopHttpInput",
                daemon=True,
            )
            self._input_poll_thread.start()

            # Push first frame only when it is real chrome (never solid black).
            try:
                token = self.token_getter()
                method_now = str(self._capture_method or "")
                healthy_probe = bool(
                    jpeg
                    and w > 0
                    and h > 0
                    and "+black" not in method_now
                    and "+flat" not in method_now
                )
                if token and healthy_probe:
                    self._last_good_jpeg = jpeg
                    self._last_good_wh = (w, h)
                    self._enqueue_ws_frame(jpeg, w, h, 0)
                    if self._http_send_frame(token, jpeg, w, h, 0):
                        self._stats["frames_sent"] = 1
                        self._stats["bytes_sent"] = len(jpeg)
                        self._last_activity = time.time()
                    self.emit_stream_progress(
                        "live",
                        "First real frame on the wire",
                        force=True,
                    )
                elif jpeg and ("+black" in method_now or "+flat" in method_now):
                    log(
                        "[REMOTE-DESKTOP] probe JPEG withheld "
                        f"(method={method_now} {w}x{h}) — not Live"
                    )
                    self._maybe_emit_unhealthy_diag(
                        reason="probe_unhealthy",
                        detail=f"method={method_now} {w}x{h} jpeg={len(jpeg)}B",
                        force=True,
                        jpeg_len=len(jpeg),
                    )
            except Exception:
                pass

            log(
                f"[REMOTE-DESKTOP] ▶ Stream started "
                f"(fps={self._fps} q={self._quality} max_w={self._max_width} "
                f"session={self._target_session_id} "
                f"prefer={self._preferred_transport} "
                f"webrtc_avail={self._webrtc_available()} ws={self._ws_ok})"
            )
            return {
                "success": True,
                "message": (
                    "remote stream started (jpeg-ws primary; webrtc optional)"
                    if self._jpeg_ws_primary()
                    else "remote stream started (webrtc preferred; jpeg-ws fallback)"
                ),
                "data": self.get_status(),
            }

    def ensure_agent_ws(self) -> None:
        """Keep ``wss://…/ws/remote/agent`` up so cloud status shows websocket:true."""
        self._agent_ws_enabled = True
        if self._ws_thread is not None and self._ws_thread.is_alive():
            return
        self._ws_thread_stop.clear()
        self._ws_thread = threading.Thread(
            target=self._ws_loop,
            name="RemoteDesktopWS",
            daemon=True,
        )
        self._ws_thread.start()

    def stop(self, reason: str = "user") -> dict:
        """Stop capture; leave agent WS connected (cloud wants websocket:true)."""
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
        # Keep agent WS — only drain stale video frames.
        with self._out_lock:
            self._pending_frame = None
        if self._ws_ok:
            self._transport = "websocket"
        else:
            self._transport = "idle"
        if was:
            log(f"[REMOTE-DESKTOP] ⏹ Stream stopped ({reason}); agent WS kept up")
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
        # Websocket-primary: JPEG is the live path (not a "fallback").
        media["jpeg_fallback_active"] = bool(
            self._jpeg_ws_primary() or not media_ready
        )
        media["jpeg_primary"] = bool(self._jpeg_ws_primary())
        media["healthy_frame"] = bool(self._frame_is_healthy())
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
            "flat_frame": bool(
                "+flat" in (self._capture_method or "")
                or self._flat_streak_started > 0
            ),
            "frame_variance": float(self._last_frame_variance or 0.0),
            "bright_ratio": float(self._last_frame_bright_ratio or 0.0),
            "chrome_detected": bool(self._chrome_detected),
            "logonui_hwnd_count": int(getattr(self, "_logonui_hwnd_count", 0) or 0),
            "helper_token": self._last_helper_token_source or "",
            "helper_fail_phase": self._last_helper_fail_phase or "",
            "desktop": self._desktop_name or "",
            "winlogon_mode": bool(self._winlogon_mode),
            "inputs_applied": int(self._stats.get("inputs_applied") or 0),
            "last_input_event": getattr(self, "_last_input_event", "") or "",
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
            "capture_diag": self._capture_diag_snapshot(),
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
            event_name = event or "?"
            if not move_like:
                # Self-check log (AGENT_REMOTE_KEYBOARD_PROMPT); moves stay quiet.
                log(
                    f"[remote-input] t=input event={event_name} "
                    f"key_present={bool(params.get('key'))} "
                    f"text_len={len(str(params.get('text') or ''))} "
                    f"session={self._target_session_id}"
                )
            # C-RD-IN-WL-1: in-session helper process injects locally (never nest).
            if getattr(self, "_in_session_helper", False):
                ok = self._inject_local(event, params)
                if ok:
                    self._note_input_applied(event_name, params)
                    return result({"success": True, "message": f"input {event} applied"})
                key_l = str(params.get("key") or "").strip().lower()
                if key_l in ("ctrl+alt+del", "ctrl-alt-del", "ctrl+alt+delete", "cad"):
                    return result({
                        "success": False,
                        "error": "cad_key_ignored",
                        "message": "use remote_send_sas for Secure Attention Sequence",
                    })
                return result({"success": False, "error": f"input {event} failed"})
            # C-RD-IN-WL-1: Winlogon stream inject must use the same helper as capture.
            if self._winlogon_mode and not self._persistent_helper_connected():
                if not self._start_persistent_helper():
                    return result({
                        "success": False,
                        "error": "winlogon helper unavailable for input",
                    })
            if self._persistent_helper_connected():
                # Forward over the full-duplex helper channel. Moves are async
                # (fire-and-forget); critical edges use a very short ACK only.
                timeout = (
                    max(float(CRIT_ACK_TIMEOUT), 0.45)
                    if self._winlogon_mode and not move_like
                    else CRIT_ACK_TIMEOUT
                )
                if hasattr(self._session_helper, "send_input_result"):
                    ack = self._session_helper.send_input_result(
                        dict(params),
                        wait=not move_like,
                        timeout=timeout,
                    )
                else:
                    ok_legacy = bool(
                        self._session_helper.send_input(
                            dict(params),
                            wait=not move_like,
                            timeout=timeout,
                        )
                    )
                    ack = {"ok": ok_legacy, "inputs_applied": 0}
                if ack.get("ok"):
                    self._note_input_applied(event_name, params, ack=ack)
                    return result({"success": True, "message": f"input {event} forwarded"})
                return result({"success": False, "error": f"input {event} not forwarded"})
            if self._use_user_helper:
                # Never inject from Session 0 after a cross-session helper failure
                # (includes Winlogon — Session-0 SendInput cannot reach console Winlogon).
                return result({"success": False, "error": "target session helper is unavailable"})

            ok = self._inject_local(event, params)
            if ok:
                self._note_input_applied(event_name, params)
                return result({"success": True, "message": f"input {event} applied"})
            # C-RD-CAD-6: synthetic CAD keys are ignored — not a silent success.
            key_l = str(params.get("key") or "").strip().lower()
            if key_l in ("ctrl+alt+del", "ctrl-alt-del", "ctrl+alt+delete", "cad"):
                return result({
                    "success": False,
                    "error": "cad_key_ignored",
                    "message": "use remote_send_sas for Secure Attention Sequence",
                })
            return result({"success": False, "error": f"input {event} failed"})
        except Exception as e:
            log(f"[REMOTE-DESKTOP] Input error: {e}")
            return result({"success": False, "error": str(e)})

    def _note_input_applied(
        self, event_name: str, params: Optional[dict] = None, ack: Optional[dict] = None
    ) -> None:
        """Parent-stream tally on every successful apply (never max with helper PID).

        Helper ``inputs_applied`` is a *new process* counter (starts at 0 each
        spawn). Mixing it with a parent lifetime total via ``max()`` froze lab
        at 260 while JPEG bullets still appeared.
        """
        params = params if isinstance(params, dict) else {}
        ack = ack if isinstance(ack, dict) else {}
        event_name = str(event_name or "").strip().lower()
        if event_name == "type_text":
            bump = max(1, len(str(params.get("text") or "")))
        elif not _is_move_event(event_name, params):
            bump = 1
        else:
            bump = 1
        self._stats["inputs_applied"] = int(self._stats.get("inputs_applied") or 0) + bump
        ack_last = str(ack.get("last_input_event") or ack.get("event") or "").strip().lower()
        # Keep original type_text; cloud key-expand must not clobber last_input_event.
        if event_name == "type_text" or ack_last == "type_text":
            self._last_input_event = "type_text"
            return
        if self._last_input_event == "type_text" and event_name == "key":
            return
        chosen = event_name or ack_last
        if chosen:
            self._last_input_event = chosen

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

    def _normalize_preferred_transport(self, value) -> str:
        raw = str(value or "").strip().lower()
        if raw in ("webrtc", "rtc"):
            return "webrtc"
        # websocket | jpeg-ws | ws | omitted → JPEG-WS primary (cloud 1.4.77+)
        return "websocket"

    def _jpeg_ws_primary(self) -> bool:
        return self._preferred_transport != "webrtc"

    def _should_send_jpeg_ws(self) -> bool:
        """Keep JPEG-WS when websocket-primary, or until WebRTC media is ready."""
        if self._jpeg_ws_primary():
            return True
        return not self._media_ready()

    def _webrtc_available(self) -> bool:
        try:
            return bool(self._media.capabilities().get("webrtc"))
        except Exception:
            return False

    def _frame_is_healthy(self) -> bool:
        """C-RD-PIX-1: JPEG size alone is not health."""
        method = str(self._capture_method or "")
        if "+black" in method or "+flat" in method:
            return False
        if self._black_streak_started > 0:
            return False
        if self._winlogon_mode and not self._chrome_detected:
            if float(self._last_frame_variance or 0.0) < FLAT_VARIANCE_THRESHOLD:
                return False
        return True

    def _media_ready(self) -> bool:
        if not self._frame_is_healthy():
            return False
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
        if self._media_ready() and not self._jpeg_ws_primary():
            return self._media_fps, self._media_quality, self._max_width
        # Tunnel video = JPEG-WS at Start knobs (≥30). Do not burn CPU on raw RGB
        # while WebRTC ICE is still negotiating (or when websocket-primary).
        return (
            max(float(self._fps or DEFAULT_FPS), JPEG_FALLBACK_FPS_WHILE_NEGOTIATING),
            max(int(self._quality or DEFAULT_QUALITY), DEFAULT_QUALITY),
            self._max_width,
        )

    def _sync_media_capture_mode(self) -> None:
        ready = self._media_ready() and not self._jpeg_ws_primary()
        if ready == self._media_mode_applied:
            return
        self._media_mode_applied = ready
        if self._persistent_helper_connected():
            fps, quality, max_width = self._effective_capture_settings()
            cfg = {
                "fps": fps,
                "quality": quality,
                "max_width": max_width,
                "prefer_raw": bool(ready),
                "winlogon": bool(self._winlogon_mode),
            }
            if ready:
                cfg["fps"] = self._media_fps
                cfg["quality"] = self._media_quality
                cfg["prefer_raw"] = True
            self._session_helper.update_config(cfg)
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
                self._maybe_follow_console_desktop()
                self._maybe_promote_follow_lock_capture()
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
                    if self._frame_is_healthy():
                        self._note_healthy_wire_frame(
                            detail=f"raw {w}x{h} method={self._capture_method}"
                        )
                    return
                # Media publish failed — fall through to JPEG for WS/HTTP.

        self._last_helper_raw = None
        if self._use_user_helper:
            if not self._persistent_helper_connected():
                if not self._start_persistent_helper(accept_timeout=FOLLOW_ACCEPT_SEC):
                    # Post-logon Default: keep JPEG-WS alive via in-process DXGI/GDI
                    # instead of dropping every frame (FOLLOW-4 freeze).
                    if not self._winlogon_mode:
                        self._note_recovery("capture_dxgi_after_helper_miss")
                        jpeg, w, h = self._grab_jpeg()
                    else:
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
            # Helper connected but empty/black during Welcome → bridge with DXGI.
            method_bridge = str(self._capture_method or "")
            if (
                not self._winlogon_mode
                and (
                    not jpeg
                    or w <= 0
                    or h <= 0
                    or len(jpeg or b"") < MIN_JPEG_BYTES
                    or "+black" in method_bridge
                    or "+flat" in method_bridge
                )
            ):
                alt = self._grab_jpeg()
                alt_method = str(self._capture_method or "")
                if (
                    alt[0]
                    and alt[1] > 0
                    and alt[2] > 0
                    and "+black" not in alt_method
                    and "+flat" not in alt_method
                ):
                    jpeg, w, h = alt
                    self._note_recovery("capture_dxgi_bridge")
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

        # Helper raw RGB → WebRTC mailbox (no JPEG decode/re-encode).
        method_now = self._capture_method or ""
        if (
            self._media_ready()
            and self._last_helper_raw
            and "+black" not in method_now
            and "+flat" not in method_now
        ):
            rgb, rw, rh = self._last_helper_raw
            self._last_helper_raw = None
            if rgb and rw > 0 and rh > 0:
                if self._should_skip_unchanged_frame(rgb):
                    return
                self._seq += 1
                seq = self._seq
                if self._dispatch_raw_frame(rgb, rw, rh, seq):
                    if self._frame_is_healthy():
                        self._note_healthy_wire_frame(
                            detail=f"helper-raw {rw}x{rh} method={self._capture_method}"
                        )
                    return
                # Publish failed — keep bytes for JPEG-WS fallthrough.
                self._last_helper_raw = (rgb, rw, rh)

        if not jpeg or w <= 0 or h <= 0:
            # Raw-only helper frame without JPEG and without media — encode for WS.
            encoded = self._encode_helper_raw_jpeg()
            if encoded[0]:
                jpeg, w, h = encoded
                self._clear_no_frame_streak()
            else:
                self._stats["frames_failed"] += 1
                self._last_helper_fail_phase = (
                    self._last_helper_fail_phase or "no_frame"
                )
                self._last_helper_fail_detail = (
                    self._last_helper_fail_detail
                    or f"method={self._capture_method} jpeg=0B"
                )
                self._maybe_emit_unhealthy_diag(
                    reason="no_frame",
                    detail=str(self._last_helper_fail_detail or "")[:240],
                )
                self._maybe_dump_no_frame_streak(
                    detail=(
                        f"empty frame method={self._capture_method} "
                        f"helper={self._persistent_helper_connected()} "
                        f"misses={getattr(self, '_helper_frame_misses', 0)}"
                    ),
                )
                return
        # API rejects tiny frames; black frames look like "live" black desktop
        if len(jpeg) < MIN_JPEG_BYTES:
            self._stats["frames_failed"] += 1
            self._stats["black_frames"] += 1
            self._maybe_dump_no_frame_streak(
                jpeg=jpeg,
                detail=f"tiny jpeg={len(jpeg)}B method={self._capture_method}",
            )
            return
        if jpeg[:2] != b"\xff\xd8" or jpeg[-2:] != b"\xff\xd9":
            self._stats["frames_failed"] += 1
            log("[REMOTE-DESKTOP] Invalid JPEG magic — skip frame")
            return
        self._clear_no_frame_streak()
        if "+black" in (self._capture_method or "") or "+flat" in (self._capture_method or ""):
            # Disconnected RDP / wrong desktop / flat accent fill → re-attach
            bad_flat = "+flat" in (self._capture_method or "")
            now = time.time()
            if bad_flat:
                if self._flat_streak_started <= 0:
                    self._flat_streak_started = now
                self._stats["flat_frames"] = int(self._stats.get("flat_frames") or 0) + 1
            else:
                if self._black_streak_started <= 0:
                    self._black_streak_started = now
            self._maybe_emit_unhealthy_diag(
                reason="flat_frame" if bad_flat else "black_frame",
                jpeg_len=len(jpeg) if jpeg else 0,
            )
            # Session-0 BitBlt cannot recover Winlogon chrome — re-pull helper.
            if self._use_user_helper and self._persistent_helper_connected():
                try:
                    self.force_winlogon_recapture()
                except Exception:
                    pass
                jpeg2, w2, h2 = self._grab_via_persistent_helper(0.55)
                method2 = self._capture_method or ""
                if (
                    jpeg2
                    and w2 > 0
                    and h2 > 0
                    and "+black" not in method2
                    and "+flat" not in method2
                ):
                    jpeg, w, h = jpeg2, w2, h2
                    self._black_streak_started = 0.0
                    self._flat_streak_started = 0.0
                elif self._last_helper_raw and "+flat" not in method2 and "+black" not in method2:
                    encoded = self._encode_helper_raw_jpeg()
                    if encoded[0]:
                        jpeg, w, h = encoded
                        self._black_streak_started = 0.0
                        self._flat_streak_started = 0.0
                    else:
                        self._stats["frames_failed"] += 1
                        if bad_flat:
                            self._maybe_fail_winlogon_flat()
                        else:
                            self._stats["black_frames"] += 1
                            self._maybe_fail_winlogon_black()
                            self._maybe_recover_default_black_streak()
                        return
                else:
                    # Default post-logon: helper stays black — DXGI once, then streak recover.
                    if not self._winlogon_mode and not bad_flat:
                        recovered = None
                        if not bool(
                            getattr(self, "_default_dxgi_retry_this_streak", False)
                        ):
                            self._default_dxgi_retry_this_streak = True
                            recovered = self._retry_unlocked_dxgi_capture()
                        if recovered:
                            jpeg, w, h = recovered
                            self._black_streak_started = 0.0
                            self._flat_streak_started = 0.0
                            self._default_dxgi_retry_this_streak = False
                        else:
                            self._stats["frames_failed"] += 1
                            self._stats["black_frames"] += 1
                            self._maybe_recover_default_black_streak()
                            return
                    else:
                        self._stats["frames_failed"] += 1
                        if bad_flat:
                            self._maybe_fail_winlogon_flat()
                        else:
                            self._stats["black_frames"] += 1
                            self._maybe_fail_winlogon_black()
                        return
            else:
                self._invalidate_desktop_bind()
                self._attach_input_desktop()
                sid = self._target_session_id
                if not self._tscon_attempted:
                    if self._try_reconnect_session_to_console(sid):
                        time.sleep(0.35)
                        self._invalidate_desktop_bind()
                        self._attach_input_desktop()
                        jpeg2, w2, h2 = self._grab_jpeg()
                        method2 = self._capture_method or ""
                        if (
                            jpeg2
                            and "+black" not in method2
                            and "+flat" not in method2
                        ):
                            jpeg, w, h = jpeg2, w2, h2
                            self._black_streak_started = 0.0
                            self._flat_streak_started = 0.0
                        else:
                            self._stats["frames_failed"] += 1
                            if bad_flat:
                                self._maybe_fail_winlogon_flat()
                            else:
                                self._stats["black_frames"] += 1
                                self._maybe_fail_winlogon_black()
                            return
                    else:
                        self._stats["frames_failed"] += 1
                        if bad_flat:
                            self._maybe_fail_winlogon_flat()
                        else:
                            self._stats["black_frames"] += 1
                            self._maybe_fail_winlogon_black()
                        return
                else:
                    self._stats["frames_failed"] += 1
                    if bad_flat:
                        self._maybe_fail_winlogon_flat()
                    else:
                        self._stats["black_frames"] += 1
                        self._maybe_fail_winlogon_black()
                    return
        else:
            self._black_streak_started = 0.0
            self._flat_streak_started = 0.0
            self._default_dxgi_retry_this_streak = False

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
        # Flat/black must never claim Live (cloud: gdi+flat ≠ Live).
        if self._frame_is_healthy():
            self._note_healthy_wire_frame(
                detail=f"{w}x{h} method={self._capture_method}"
            )
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
            method = self._capture_method or ""
            if (
                jpeg
                and w > 0
                and h > 0
                and "+black" not in method
                and "+flat" not in method
            ):
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
        try:
            jpeg_dump = None
            if self._use_user_helper and self._persistent_helper_connected():
                jpeg_dump, _, _ = self._grab_via_persistent_helper(0.4)
            self._persist_capture_fail_dump(
                reason="winlogon_capture_black",
                jpeg=jpeg_dump,
                detail=(
                    f"streak≥{WINLOGON_BLACK_FAIL_SECONDS:.0f}s "
                    f"method={self._capture_method}"
                ),
                force=True,
            )
        except Exception:
            pass
        self._maybe_emit_unhealthy_diag(
            reason="winlogon_capture_black",
            force=True,
        )
        self.emit_stream_progress(
            "failed",
            f"Unbroken black for ≥{WINLOGON_BLACK_FAIL_SECONDS:.0f}s",
            error="winlogon_capture_black",
            force=True,
        )
        self.stop(reason="winlogon_capture_black")

    def _maybe_fail_winlogon_flat(self) -> None:
        """C-RD-CHROME-2: sustained flat solid fill in winlogon → retry, then fail."""
        if not self._winlogon_mode or self._flat_streak_started <= 0:
            return
        elapsed = time.time() - self._flat_streak_started
        if elapsed < WINLOGON_FLAT_FAIL_SECONDS:
            return
        if not self._winlogon_flat_retried:
            self._winlogon_flat_retried = True
            self._desktop_attached = False
            self._attach_input_desktop()
            try:
                alt = self._grab_printwindow_chrome()
                if alt is not None and not self._is_mostly_flat(alt):
                    self._flat_streak_started = 0.0
                    return
            except Exception:
                pass
            jpeg, w, h = self._grab_jpeg()
            method = self._capture_method or ""
            if (
                jpeg
                and w > 0
                and h > 0
                and "+black" not in method
                and "+flat" not in method
            ):
                self._flat_streak_started = 0.0
                return
            self._flat_streak_started = time.time()
            return
        self._last_stream_error = "winlogon_capture_flat"
        log(
            "[REMOTE-DESKTOP] ✖ winlogon_capture_flat — "
            f"unbroken solid fill for ≥{WINLOGON_FLAT_FAIL_SECONDS:.0f}s "
            f"(var={self._last_frame_variance:.1f} method={self._capture_method})"
        )
        try:
            jpeg_dump = None
            if self._use_user_helper and self._persistent_helper_connected():
                jpeg_dump, _, _ = self._grab_via_persistent_helper(0.4)
            self._persist_capture_fail_dump(
                reason="winlogon_capture_flat",
                jpeg=jpeg_dump,
                detail=(
                    f"streak≥{WINLOGON_FLAT_FAIL_SECONDS:.0f}s "
                    f"var={self._last_frame_variance:.1f} "
                    f"method={self._capture_method}"
                ),
                force=True,
            )
        except Exception:
            pass
        self._maybe_emit_unhealthy_diag(
            reason="winlogon_capture_flat",
            force=True,
        )
        self.emit_stream_progress(
            "failed",
            f"Unbroken flat/blue for ≥{WINLOGON_FLAT_FAIL_SECONDS:.0f}s",
            error="winlogon_capture_flat",
            force=True,
        )
        self.stop(reason="winlogon_capture_flat")

    def _note_recovery(self, step: str) -> None:
        try:
            msg = str(step or "").strip()[:120]
            if not msg:
                return
            steps = list(getattr(self, "_capture_recovery_steps", []) or [])
            steps.append(f"{time.strftime('%H:%M:%S')}:{msg}")
            self._capture_recovery_steps = steps[-24:]
        except Exception:
            pass

    def _persist_capture_fail_dump(
        self,
        *,
        reason: str,
        jpeg: Optional[bytes] = None,
        detail: str = "",
        force: bool = False,
    ) -> None:
        """Rare-host forensics: JSON (+JPEG) under ProgramData\\Asteria\\rd_capture_diag.

        Terminal Start/Stop fails use ``force=True``. Streaming degraded paths
        dump once per reason per stream (plus cooldown) so Default ``no_frame``
        leaves evidence without flooding the ring.
        """
        try:
            reason_s = str(reason or "fail").strip()[:80] or "fail"
            now = time.monotonic()
            dumped = getattr(self, "_diag_dump_reasons_this_stream", None)
            if not isinstance(dumped, set):
                dumped = set()
                self._diag_dump_reasons_this_stream = dumped
            if not force:
                if reason_s in dumped:
                    return
                last_mono = float(getattr(self, "_last_diag_dump_mono", 0.0) or 0.0)
                if (now - last_mono) < float(DIAG_DUMP_COOLDOWN_SEC):
                    return
            from client_rd_capture_diag_dump import write_capture_fail_dump
            hwnd_meta = {}
            try:
                from client_rd_winlogon import visible_surface_signature
                state, tokens, count = visible_surface_signature()
                hwnd_meta = {
                    "ui_state": state,
                    "tokens": sorted(list(tokens))[:40],
                    "visible_count": int(count),
                }
            except Exception:
                hwnd_meta = {}
            if getattr(self, "_last_hwnd_classes", None):
                hwnd_meta["classes"] = list(self._last_hwnd_classes)[:20]
            diag = self._capture_diag_snapshot()
            dump = write_capture_fail_dump(
                reason=reason_s,
                diag=diag,
                extra={
                    "detail": str(detail or "")[:400],
                    "recovery_steps": list(
                        getattr(self, "_capture_recovery_steps", []) or []
                    ),
                    "hwnd_meta": hwnd_meta,
                    "desktop_attached": bool(self._desktop_attached),
                    "desktop_name": str(self._desktop_name or ""),
                    "helper_token": str(self._last_helper_token_source or ""),
                    "helper_fail_phase": str(self._last_helper_fail_phase or ""),
                    "helper_fail_detail": str(
                        self._last_helper_fail_detail or ""
                    )[:320],
                    "prefer_dxgi": bool(self._prefer_dxgi),
                    "winlogon_mode": bool(self._winlogon_mode),
                    "force_secure": bool(self._force_secure_desktop),
                    "follow_console": bool(self._follow_console),
                    "use_user_helper": bool(self._use_user_helper),
                    "helper_connected": bool(self._persistent_helper_connected()),
                    "helper_frame_misses": int(
                        getattr(self, "_helper_frame_misses", 0) or 0
                    ),
                    "capture_method": str(self._capture_method or ""),
                    "target_session_id": int(self._target_session_id or 0),
                    "target_username": str(self._target_username or "")[:64],
                    "force": bool(force),
                },
                jpeg=jpeg,
                stream_id=str(self._stream_id or ""),
            )
            if dump.get("ok") and dump.get("path"):
                self._last_diag_dump_path = str(dump.get("path") or "")
                self._last_diag_dump_mono = now
                self._last_diag_dump_reason = reason_s
                dumped.add(reason_s)
                self._note_recovery(f"dump:{reason_s}")
                # Push path into Capture health immediately.
                try:
                    self._enqueue_capture_diag(
                        phase="degraded",
                        reason=f"dump:{reason_s}",
                        detail=str(dump.get("path") or "")[:320],
                    )
                except Exception:
                    pass
        except Exception as exc:
            log(f"[REMOTE-DESKTOP] persist capture dump failed: {exc}")

    def _maybe_dump_no_frame_streak(
        self,
        *,
        jpeg: Optional[bytes] = None,
        detail: str = "",
    ) -> None:
        """After sustained empty Default/capture frames, write one local dump."""
        now = time.time()
        if self._no_frame_streak_started <= 0:
            self._no_frame_streak_started = now
            return
        if (now - self._no_frame_streak_started) < float(DIAG_NO_FRAME_DUMP_SEC):
            return
        reason = (
            "winlogon_no_frame"
            if self._winlogon_mode or self._force_secure_desktop
            else "default_no_frame"
        )
        phase = str(self._last_helper_fail_phase or "")
        if phase == "no_frame" or "no_frame" in str(
            self._last_helper_fail_detail or ""
        ):
            reason = f"{reason}_helper"
        self._persist_capture_fail_dump(
            reason=reason,
            jpeg=jpeg,
            detail=detail
            or (
                f"streak≥{DIAG_NO_FRAME_DUMP_SEC:.0f}s "
                f"method={self._capture_method} "
                f"phase={phase or '-'} "
                f"var={self._last_frame_variance:.1f}"
            ),
            force=False,
        )

    def _clear_no_frame_streak(self) -> None:
        self._no_frame_streak_started = 0.0

    def _clear_stale_helper_fail(self) -> None:
        """Drop probe miss tags once healthy pixels are on the wire (C-RD-DIAG)."""
        phase = str(self._last_helper_fail_phase or "").lower()
        if phase in ("", "no_frame", "flat", "black"):
            self._last_helper_fail_phase = ""
            self._last_helper_fail_detail = ""
        if str(self._last_stream_error or "").lower() in (
            "",
            "no_frame",
            "follow_no_default_frame",
            "winlogon_capture_black",
            "winlogon_capture_flat",
        ):
            # Only clear soft miss errors — keep hard spawn/token codes.
            if phase in ("", "no_frame", "flat", "black"):
                self._last_stream_error = ""

    def _pixels_currently_healthy(self) -> bool:
        """True when latest chrome telemetry says real pixels (not black/flat)."""
        method = str(self._capture_method or "")
        if "+black" in method or "+flat" in method:
            return False
        if float(self._last_frame_variance or 0.0) >= float(FLAT_VARIANCE_THRESHOLD):
            return True
        return bool(self._chrome_detected and self._frame_is_healthy())

    def _note_healthy_wire_frame(self, *, detail: str = "") -> None:
        """Healthy JPEG on wire: clear stale no_frame and refresh Capture health."""
        was_unhealthy = not bool(getattr(self, "_last_diag_was_healthy", False))
        stale_fail = bool(self._last_helper_fail_phase)
        self._clear_no_frame_streak()
        self._clear_stale_helper_fail()
        self._black_streak_started = 0.0
        self._flat_streak_started = 0.0
        self._last_diag_was_healthy = True
        now = time.monotonic()
        # Transition or periodic refresh so cloud replaces FAIL · no_frame banner.
        if was_unhealthy or stale_fail or (
            now - float(self._last_diag_emit_mono or 0.0)
        ) >= 3.0:
            self._last_diag_emit_mono = now
            try:
                self._enqueue_capture_diag(
                    phase="live",
                    reason="healthy_frame",
                    detail=str(detail or self._capture_method or "")[:240],
                )
            except Exception:
                pass

    def force_winlogon_recapture(self) -> None:
        """C-RD-CHROME-4: drop desktop bind so next grab reattaches after CAD."""
        self._invalidate_desktop_bind()
        self._flat_streak_started = 0.0
        try:
            if self._persistent_helper_connected():
                self._session_helper.force_desktop_reattach(timeout=1.2)
        except Exception as exc:
            log(f"[REMOTE-DESKTOP] helper force reattach after CAD: {exc}")

    def _invalidate_desktop_bind(self) -> None:
        """Clear per-thread desktop affinity; next grab must SetThreadDesktop."""
        self._desktop_attached = False
        self._desktop_attach_tid = None

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
                # WebRTC-primary only: drop JPEG so dual bandwidth stops.
                # Websocket-primary keeps JPEG-WS alive (cloud Live MUST).
                if not self._jpeg_ws_primary():
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
            if self._frame_is_healthy() and self._media.publish_frame(
                jpeg, media_metadata
            ):
                self._transport = "webrtc"
                self._last_activity = time.time()
                if not self._jpeg_ws_primary():
                    # WebRTC-primary: drop stale JPEG so WS cannot compete.
                    with self._out_lock:
                        self._pending_frame = None
                    return
                # Websocket-primary: also push JPEG-WS (viewer paints this path).
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
            if (
                not self._winlogon_mode
                and src_w >= MIN_ENCODE_WIDTH
                and src_w > int(self._locked_encode_w)
            ):
                self._locked_encode_w = 0
                self._locked_encode_h = 0
            else:
                return self._locked_encode_w, self._locked_encode_h
        tw, th = self._compute_encode_size(src_w, src_h, max_width)
        self._locked_encode_w = tw
        self._locked_encode_h = th
        log(
            f"[REMOTE-DESKTOP] encode size locked {tw}x{th} "
            f"(src={src_w}x{src_h} max_w={max_width})"
        )
        return tw, th

    def _grab_dxgi(self):
        """Desktop Duplication in the helper session (C-RD-PIX-4 / FOLLOW-5)."""
        try:
            import dxcam  # type: ignore
            from PIL import Image
        except Exception as exc:
            now = time.time()
            if now - float(getattr(self, "_dxgi_warn_ts", 0) or 0) > 8:
                self._dxgi_warn_ts = now
                log(f"[REMOTE-DESKTOP] DXGI unavailable: {exc}")
            return None
        idx = max(0, int(self._monitor_index or 0))
        cam = self._dxcam
        try:
            if cam is None:
                cam = dxcam.create(
                    output_idx=idx, output_color="RGB"
                ) or dxcam.create(output_color="RGB")
                self._dxcam = cam
                if cam is not None:
                    try:
                        # Some dxcam builds need an explicit start for first frames.
                        start = getattr(cam, "start", None)
                        if callable(start):
                            start(target_fps=max(30, int(self._fps or 30)), video_mode=True)
                    except TypeError:
                        try:
                            cam.start()
                        except Exception:
                            pass
                    except Exception:
                        pass
            if cam is None:
                return None
            frame = None
            # Unlocked Default can take a few duplication ticks after helper spawn.
            for _ in range(16):
                frame = cam.grab()
                if frame is not None:
                    break
                time.sleep(0.02)
            if frame is None:
                return None
            img = Image.fromarray(frame)
            # Reject solid-black DXGI (wrong output / secure desktop).
            if self._is_mostly_black(img):
                return None
            return img
        except Exception as exc:
            self._dxcam = None
            now = time.time()
            if now - float(getattr(self, "_dxgi_warn_ts", 0) or 0) > 8:
                self._dxgi_warn_ts = now
                log(f"[REMOTE-DESKTOP] DXGI grab failed: {exc}")
            return None

    def _frame_usable(self, img) -> bool:
        """True when pixels look like real chrome (not black/flat fill)."""
        if img is None:
            return False
        try:
            return not self._is_mostly_black(img) and not self._is_mostly_flat(img)
        except Exception:
            return False

    def _capture_screen_image(self):
        """Capture primary screen → PIL RGB Image (no encode). Returns (img, method)."""
        try:
            from PIL import Image
        except ImportError:
            log("[REMOTE-DESKTOP] Pillow (PIL) not available")
            return None, "none"

        # C-RD-PIX-1: Winlogon capture must bind winsta0\\Winlogon before any BitBlt.
        attached = bool(self._attach_input_desktop())
        if self._winlogon_mode and not attached:
            log(
                "[REMOTE-DESKTOP] Winlogon capture skipped — desktop not attached "
                f"(desk={self._desktop_name or '?'})"
            )
            self._desktop_attached = False
            return None, "none"

        origin_x, origin_y, native_w, native_h = self._get_capture_rect()
        self._screen_x, self._screen_y = origin_x, origin_y
        self._screen_w, self._screen_h = native_w, native_h

        img = None
        method = "none"
        # C-RD-PIX-2: LogonUI / LockApp paint via DWM — BitBlt desktop DC is often
        # a solid accent fill. Prefer PrintWindow / HWND BitBlt first on Winlogon.
        if self._winlogon_mode:
            for label, grabber in (
                ("printwindow-logonui", self._grab_printwindow_chrome),
                ("hwnd-bitblt-logonui", self._grab_hwnd_bitblt_chrome),
            ):
                try:
                    self._note_recovery(f"try:{label}")
                    alt = grabber()
                except Exception as exc:
                    log(f"[REMOTE-DESKTOP] {label} failed: {exc}")
                    self._note_recovery(f"fail:{label}:{exc}")
                    alt = None
                if self._frame_usable(alt):
                    img = alt
                    method = label
                    self._note_recovery(f"ok:{label}")
                    break

        # DXGI: Default first. On Winlogon, also try after PrintWindow/HWND fail —
        # some Server SKUs compose LogonUI into Desktop Duplication while GDI is flat.
        try_dxgi_default = (not self._winlogon_mode) and (
            str(self._desktop_name or "").lower() != "winlogon"
        ) and (
            self._prefer_dxgi
            or self._in_session_helper
            or self._media_ready()
        )
        try_dxgi_winlogon = bool(
            self._winlogon_mode
            and (
                img is None
                or not self._frame_usable(img)
            )
        )
        if img is None and try_dxgi_default:
            img = self._grab_dxgi()
            if img is not None:
                method = "dxgi-desktop-duplication"
            else:
                # Welcome / mid-follow: first DXGI tick often empty — reset once.
                self._reset_dxgi_camera()
                img = self._grab_dxgi()
                if img is not None:
                    method = "dxgi-desktop-duplication"
                    self._note_recovery("ok:dxgi-default-retry")
        elif try_dxgi_winlogon:
            try:
                self._note_recovery("try:dxgi-winlogon")
                dx = self._grab_dxgi()
                if self._frame_usable(dx):
                    img = dx
                    method = "dxgi-winlogon"
                    self._note_recovery("ok:dxgi-winlogon")
            except Exception as exc:
                self._note_recovery(f"fail:dxgi-winlogon:{exc}")
        # Prefer GDI BitBlt (more reliable than ImageGrab under elevation / DPI)
        if img is None or (
            self._winlogon_mode and not self._frame_usable(img)
        ):
            try:
                gdi_img = self._grab_gdi()
                if self._frame_usable(gdi_img):
                    img = gdi_img
                    method = "gdi"
                elif img is None and gdi_img is not None:
                    img = gdi_img
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
        elif self._is_mostly_flat(img):
            # C-RD-CHROME-1/2: reattach + PrintWindow / HWND before declaring solid fill.
            recovered = False
            if self._winlogon_mode:
                try:
                    self._desktop_attached = False
                    if self._attach_input_desktop():
                        for label, grabber in (
                            ("printwindow-logonui", self._grab_printwindow_chrome),
                            ("hwnd-bitblt-logonui", self._grab_hwnd_bitblt_chrome),
                            ("gdi-reattach", self._grab_gdi),
                        ):
                            alt = grabber()
                            if self._frame_usable(alt):
                                img = alt
                                method = label
                                recovered = True
                                break
                except Exception as exc:
                    log(f"[REMOTE-DESKTOP] flat recovery failed: {exc}")
            if not recovered:
                self._stats["flat_frames"] = int(self._stats.get("flat_frames") or 0) + 1
                now = time.time()
                if now - getattr(self, "_flat_warn_ts", 0) > 10:
                    self._flat_warn_ts = now
                    _m, var, bright = self._frame_luma_stats(img)
                    log(
                        f"[REMOTE-DESKTOP] ⚠ Flat Winlogon frame "
                        f"(var={var:.1f} bright={bright:.4f} "
                        f"desk={self._desktop_name or '?'} "
                        f"attached={self._desktop_attached}) method={method}"
                    )
                method = method + "+flat"
                # Keep attach flag honest — flat pixels ≠ detach; helper may still
                # be bound while GDI paints accent fill.

        self._remember_frame_chrome(img, method)
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
        if img is None or "+black" in (method or "") or "+flat" in (method or ""):
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
            # SRCCOPY|CAPTUREBLT — LogonUI / lock layered windows often missing without CAPTUREBLT.
            SRCCOPY_CAPTUREBLT = 0x40CC0020
            ok = gdi32.BitBlt(memdc, 0, 0, width, height, hdc, left, top, SRCCOPY_CAPTUREBLT)
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
                ok = gdi32.BitBlt(memdc, 0, 0, width, height, hdc, left, top, SRCCOPY_CAPTUREBLT)
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

    @staticmethod
    def _frame_luma_stats(img) -> tuple:
        """Return (mean, variance, bright_ratio) on a tiny L luma grid."""
        try:
            small = img.resize((64, 36)).convert("L")
            data = list(small.getdata())
            n = max(1, len(data))
            mean = float(sum(data)) / n
            var = float(sum((x - mean) ** 2 for x in data)) / n
            bright = float(sum(1 for x in data if x >= 200)) / n
            return mean, var, bright
        except Exception:
            return 255.0, 999.0, 1.0

    def _is_mostly_black(self, img) -> bool:
        return self._mean_brightness(img) < BLACK_MEAN_THRESHOLD

    def _is_mostly_flat(self, img) -> bool:
        """C-RD-CHROME-2: solid blue/grey fill without glyphs/wallpaper texture."""
        if img is None:
            return True
        if self._is_mostly_black(img):
            return False  # black path owns near-black
        _mean, var, bright = self._frame_luma_stats(img)
        return bool(var < FLAT_VARIANCE_THRESHOLD and bright < FLAT_BRIGHT_RATIO_MAX)

    def _remember_frame_chrome(self, img, method: str = "") -> None:
        """Update variance / chrome telemetry for hello/meta (C-RD-CHROME-5)."""
        if img is None:
            self._last_frame_variance = 0.0
            self._last_frame_bright_ratio = 0.0
            self._chrome_detected = False
            self._stats["frame_variance"] = 0.0
            self._stats["bright_ratio"] = 0.0
            self._stats["chrome_detected"] = False
            return
        _mean, var, bright = self._frame_luma_stats(img)
        # Wallpaper often has high variance but glyph bright_ratio≈0. Expose a
        # content/spread ratio so cloud "degraded" banners don't fire on healthy
        # lock wallpaper (C-RD-CHROME-5).
        try:
            small = img.resize((64, 36)).convert("L")
            data = list(small.getdata())
            n = max(1, len(data))
            spread = float(sum(1 for x in data if abs(x - _mean) >= 8)) / n
        except Exception:
            spread = 0.0
        report_bright = max(float(bright), float(spread) if var >= FLAT_VARIANCE_THRESHOLD else 0.0)
        self._last_frame_variance = float(var)
        self._last_frame_bright_ratio = float(report_bright)
        chrome = bool(
            "+black" not in (method or "")
            and "+flat" not in (method or "")
            and (
                var >= FLAT_VARIANCE_THRESHOLD
                or bright >= FLAT_BRIGHT_RATIO_MAX
                or spread >= 0.08
            )
        )
        self._chrome_detected = chrome
        self._stats["frame_variance"] = float(var)
        self._stats["bright_ratio"] = float(report_bright)
        self._stats["chrome_detected"] = bool(chrome)
        if chrome:
            # Healthy PrintWindow/DXGI must not keep a prior black/flat streak
            # (Ninety flicker: var high while Capture health still said black).
            self._black_streak_started = 0.0
            self._flat_streak_started = 0.0
        if self._winlogon_mode and not self._chrome_diag_logged:
            self._chrome_diag_logged = True
            # Only enum HWND on the in-session helper desktop; Session-0 parent
            # enum is empty/wrong and must not clobber helper-supplied hwnd.
            if getattr(self, "_in_session_helper", False):
                hwnd_n = 0
                try:
                    from client_rd_winlogon import visible_surface_signature
                    _st, _tok, hwnd_n = visible_surface_signature()
                except Exception:
                    hwnd_n = 0
                self._logonui_hwnd_count = int(hwnd_n)
            try:
                from client_helpers import log as _clog
                _clog(
                    f"[REMOTE-DESKTOP] winlogon chrome diag "
                    f"desk={self._desktop_name or '?'} "
                    f"hwnd={getattr(self, '_logonui_hwnd_count', 0)} "
                    f"var={var:.1f} bright={report_bright:.4f} "
                    f"chrome={chrome} method={method or '?'} "
                    f"tid={threading.get_ident()}"
                )
            except Exception:
                pass

    def _enum_capture_hwnd_candidates(self, min_side: int = 80):
        """Visible top-level HWNDs on the current thread desktop (LogonUI boost)."""
        import ctypes
        from ctypes import wintypes

        user32 = ctypes.windll.user32
        candidates = []

        @ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
        def _cb(hwnd, _lp):
            try:
                if not user32.IsWindowVisible(hwnd):
                    return True
                rect = wintypes.RECT()
                if not user32.GetWindowRect(hwnd, ctypes.byref(rect)):
                    return True
                ww = int(rect.right - rect.left)
                hh = int(rect.bottom - rect.top)
                if ww < int(min_side) or hh < int(min_side):
                    return True
                area = ww * hh
                cbuf = ctypes.create_unicode_buffer(256)
                user32.GetClassNameW(hwnd, cbuf, 256)
                cname = (cbuf.value or "").lower()
                tbuf = ctypes.create_unicode_buffer(512)
                user32.GetWindowTextW(hwnd, tbuf, 512)
                title = (tbuf.value or "").lower()
                boost = 0
                for hint in (
                    "logonui", "lockapp", "immersive", "authui", "credential",
                    "windows.ui", "applicationframe", "statusview",
                ):
                    if hint in cname or hint in title:
                        boost = 10_000_000
                        break
                candidates.append(
                    (area + boost, hwnd, ww, hh, int(rect.left), int(rect.top), cname)
                )
            except Exception:
                pass
            return True

        try:
            EnumDesktopWindows = getattr(user32, "EnumDesktopWindows", None)
            hdesk = user32.GetThreadDesktop(ctypes.windll.kernel32.GetCurrentThreadId())
            if EnumDesktopWindows and hdesk:
                EnumDesktopWindows(hdesk, _cb, 0)
            else:
                user32.EnumWindows(_cb, 0)
        except Exception:
            try:
                user32.EnumWindows(_cb, 0)
            except Exception:
                return []

        # Server LogonUI often paints chrome on child HWNDs; include them.
        child_extra = []
        for score, hwnd, _ww, _hh, _wx, _wy, _cname in list(candidates)[:6]:
            if score < 10_000_000:
                continue
            try:
                @ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
                def _child_cb(ch, _lp, _parent=hwnd):
                    try:
                        if not user32.IsWindowVisible(ch):
                            return True
                        rect = wintypes.RECT()
                        if not user32.GetWindowRect(ch, ctypes.byref(rect)):
                            return True
                        ww = int(rect.right - rect.left)
                        hh = int(rect.bottom - rect.top)
                        if ww < int(min_side) or hh < int(min_side):
                            return True
                        cbuf = ctypes.create_unicode_buffer(256)
                        user32.GetClassNameW(ch, cbuf, 256)
                        cname = (cbuf.value or "").lower()
                        child_extra.append(
                            (
                                ww * hh + 5_000_000,
                                ch,
                                ww,
                                hh,
                                int(rect.left),
                                int(rect.top),
                                cname,
                            )
                        )
                    except Exception:
                        pass
                    return True

                user32.EnumChildWindows(hwnd, _child_cb, 0)
            except Exception:
                pass
        candidates.extend(child_extra)
        candidates.sort(key=lambda x: x[0], reverse=True)
        try:
            self._last_hwnd_classes = [
                c[-1] for c in candidates[:12] if c[-1]
            ]
        except Exception:
            self._last_hwnd_classes = []
        return candidates

    def _printwindow_hwnd_to_image(self, hwnd, ww: int, hh: int):
        """PrintWindow one HWND → PIL RGB (PW_RENDERFULLCONTENT, then flags=0)."""
        import ctypes
        from ctypes import wintypes
        try:
            from PIL import Image
        except ImportError:
            return None
        if ww <= 0 or hh <= 0 or not hwnd:
            return None
        user32 = ctypes.windll.user32
        gdi32 = ctypes.windll.gdi32
        PW_RENDERFULLCONTENT = 0x00000002
        RDW_INVALIDATE = 0x0001
        RDW_UPDATENOW = 0x0100
        RDW_ALLCHILDREN = 0x0080
        hdc = memdc = bmp = old = None
        try:
            try:
                user32.RedrawWindow(
                    hwnd,
                    None,
                    None,
                    RDW_INVALIDATE | RDW_UPDATENOW | RDW_ALLCHILDREN,
                )
            except Exception:
                pass
            # Prefer window DC; fall back to GetDC for some Server LogonUI surfaces.
            hdc = user32.GetWindowDC(hwnd) or user32.GetDC(hwnd)
            if not hdc:
                return None
            memdc = gdi32.CreateCompatibleDC(hdc)
            bmp = gdi32.CreateCompatibleBitmap(hdc, ww, hh)
            old = gdi32.SelectObject(memdc, bmp)
            ok = user32.PrintWindow(hwnd, memdc, PW_RENDERFULLCONTENT)
            if not ok:
                ok = user32.PrintWindow(hwnd, memdc, 0)
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
            bi.biWidth = ww
            bi.biHeight = -hh
            bi.biPlanes = 1
            bi.biBitCount = 32
            buf = (ctypes.c_char * (ww * hh * 4))()
            gdi32.GetDIBits(memdc, bmp, 0, hh, buf, ctypes.byref(bi), 0)
            return Image.frombuffer(
                "RGB", (ww, hh), bytes(buf), "raw", "BGRX", 0, 1
            ).copy()
        except Exception:
            return None
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
                    user32.ReleaseDC(hwnd, hdc)
            except Exception:
                pass

    def _grab_printwindow_chrome(self):
        """PrintWindow visible HWNDs (PW_RENDERFULLCONTENT) for LogonUI.

        BitBlt of the desktop DC often yields a solid accent fill while LogonUI /
        LockApp still paint real chrome. PrintWindow can recover those pixels.
        Server class: RedrawWindow + child HWND enum + short retry.
        """
        try:
            from PIL import Image
        except ImportError:
            return None

        left, top, width, height = self._get_capture_rect()
        if width <= 0 or height <= 0:
            return None

        for attempt in range(2):
            candidates = self._enum_capture_hwnd_candidates(min_side=48)
            if not candidates:
                if attempt == 0:
                    time.sleep(0.08)
                    continue
                return None

            canvas = Image.new("RGB", (width, height), (0, 0, 0))
            painted = False
            for _score, hwnd, ww, hh, wx, wy, _cname in candidates[:12]:
                try:
                    piece = self._printwindow_hwnd_to_image(hwnd, ww, hh)
                    if piece is None:
                        continue
                    # LogonUI-boosted surfaces: accept slightly softer flat so
                    # partial chrome still composes (Derin/Ninety Server).
                    soft = _score >= 5_000_000
                    if self._is_mostly_black(piece):
                        continue
                    if self._is_mostly_flat(piece) and not soft:
                        continue
                    if soft and self._is_mostly_flat(piece):
                        _m, var, bright = self._frame_luma_stats(piece)
                        if var < max(4.0, FLAT_VARIANCE_THRESHOLD * 0.35) and bright < 0.002:
                            continue
                    canvas.paste(piece, (int(wx - left), int(wy - top)))
                    painted = True
                    if _score >= 10_000_000 and self._frame_usable(piece):
                        break
                except Exception:
                    continue
            if painted and not (
                self._is_mostly_black(canvas) or self._is_mostly_flat(canvas)
            ):
                return canvas
            if painted and self._frame_usable(canvas):
                return canvas
            if attempt == 0:
                time.sleep(0.12)
        return None

    def _grab_hwnd_bitblt_chrome(self):
        """BitBlt each LogonUI-like HWND window DC (PrintWindow alternative)."""
        import ctypes
        from ctypes import wintypes
        try:
            from PIL import Image
        except ImportError:
            return None

        user32 = ctypes.windll.user32
        gdi32 = ctypes.windll.gdi32
        SRCCOPY_CAPTUREBLT = 0x40CC0020
        left, top, width, height = self._get_capture_rect()
        if width <= 0 or height <= 0:
            return None

        candidates = self._enum_capture_hwnd_candidates(min_side=64)
        if not candidates:
            return None

        canvas = Image.new("RGB", (width, height), (0, 0, 0))
        painted = False

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

        for _score, hwnd, ww, hh, wx, wy, _cname in candidates[:8]:
            hdc = memdc = bmp = old = None
            try:
                hdc = user32.GetWindowDC(hwnd)
                if not hdc:
                    continue
                memdc = gdi32.CreateCompatibleDC(hdc)
                bmp = gdi32.CreateCompatibleBitmap(hdc, ww, hh)
                old = gdi32.SelectObject(memdc, bmp)
                if not gdi32.BitBlt(memdc, 0, 0, ww, hh, hdc, 0, 0, SRCCOPY_CAPTUREBLT):
                    continue
                bi = BITMAPINFOHEADER()
                bi.biSize = ctypes.sizeof(BITMAPINFOHEADER)
                bi.biWidth = ww
                bi.biHeight = -hh
                bi.biPlanes = 1
                bi.biBitCount = 32
                buf = (ctypes.c_char * (ww * hh * 4))()
                gdi32.GetDIBits(memdc, bmp, 0, hh, buf, ctypes.byref(bi), 0)
                piece = Image.frombuffer("RGB", (ww, hh), bytes(buf), "raw", "BGRX", 0, 1).copy()
                if self._is_mostly_black(piece) or self._is_mostly_flat(piece):
                    continue
                canvas.paste(piece, (int(wx - left), int(wy - top)))
                painted = True
                if _score >= 10_000_000:
                    break
            except Exception:
                continue
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
                        user32.ReleaseDC(hwnd, hdc)
                except Exception:
                    pass
        if not painted:
            return None
        if self._is_mostly_black(canvas) or self._is_mostly_flat(canvas):
            return None
        return canvas

    def _attach_input_desktop(self) -> bool:
        """Bind capture/input thread to the interactive (or Winlogon) desktop.

        Elevated / tray processes often BitBlt a black screen when not on
        the input desktop. Pre-logon requires WinSta0 + Winlogon attach.

        SetThreadDesktop is per-thread: a bind on the helper command thread
        must never satisfy the capture thread (4.9.89 gdi+flat regression).
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
        tid = threading.get_ident()
        if (
            self._desktop_attached
            and not force
            and self._desktop_attach_tid == tid
        ):
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
                # Never bind named Default while input is Winlogon (BitBlt black).
                # Follow OpenInputDesktop like Chrome Remote Desktop.
                ok, name, hdesk = attach_console_desktop(
                    follow_input=True,
                    close_previous=self._input_desktop if force else None,
                )
            if ok and hdesk:
                self._input_desktop = hdesk
                self._desktop_attached = True
                self._desktop_attach_tid = tid
                self._desktop_name = name
                if name.lower() == "default" and self._winlogon_mode:
                    # User completed interactive logon — switch to normal desktop path.
                    self._winlogon_mode = False
                    self._prefer_dxgi = True
                    log("[REMOTE-DESKTOP] desktop switched Winlogon→Default (post-logon)")
                elif name.lower() == "winlogon" and not self._winlogon_mode:
                    # Spawned as user/Default helper but console input is secure.
                    # Parent must respawn with winlogon token — do not claim Default.
                    self._prefer_dxgi = False
                    log(
                        "[REMOTE-DESKTOP] input desktop=Winlogon while "
                        "helper mode=Default — need secure respawn"
                    )
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
            self._desktop_attach_tid = tid
            self._desktop_name = resolved
            if resolved.lower() == "default" and self._winlogon_mode:
                self._winlogon_mode = False
                self._prefer_dxgi = True
                log("[REMOTE-DESKTOP] desktop switched Winlogon→Default (post-logon)")
            log(f"[REMOTE-DESKTOP] attached to input desktop name={resolved}")
            return True
        except Exception as e:
            log(f"[REMOTE-DESKTOP] desktop attach error: {e}")
            return False

    def _console_interactive_username(self) -> str:
        sid = int(self._target_session_id or 0)
        user = ""
        try:
            from client_rd_winlogon import session_username
            user = session_username(sid)
        except Exception:
            user = ""
        if user:
            return user
        try:
            for row in self._enumerate_sessions() or []:
                try:
                    if int(row.get("session_id") or 0) != sid:
                        continue
                except (TypeError, ValueError):
                    continue
                if row.get("pre_logon"):
                    continue
                name = str(row.get("username") or "").strip()
                if name:
                    return name
        except Exception:
            pass
        return str(self._target_username or "").strip()

    def _apply_follow_secure_or_default(
        self, *, prefer_default_on_unknown: bool = False
    ) -> None:
        """Follow / SID Start: Winlogon unless Default input desktop is proven live."""
        sid = int(self._target_session_id or 0)
        user = self._console_interactive_username()
        logonui = False
        locked = None
        explorer = None
        desk_hint = ""
        try:
            from client_rd_winlogon import (
                console_start_secure_desktop,
                session_has_logonui,
                session_has_process,
                session_lock_state,
            )
            logonui = bool(session_has_logonui(sid)) if sid > 0 else False
            locked = session_lock_state(sid) if sid > 0 else None
            explorer = (
                session_has_process(sid, "explorer.exe") if sid > 0 else None
            )
            # Proven unlock/lock beats a stale Start desktop stamp (FOLLOW-4 / Derin).
            if logonui or locked is True:
                desk_hint = "winlogon"
            elif locked is False and not logonui:
                desk_hint = "default"
            secure = bool(
                console_start_secure_desktop(
                    username=user,
                    logonui_present=logonui,
                    session_locked=locked,
                    explorer_present=explorer,
                    input_desktop=desk_hint,
                    prefer_default_on_unknown=bool(prefer_default_on_unknown),
                )
            )
        except Exception as exc:
            log(f"[REMOTE-DESKTOP] follow desktop probe: {exc}")
            secure = not prefer_default_on_unknown
        if secure:
            self._winlogon_mode = True
            self._prefer_dxgi = False
            self._target_username = ""
            self._desktop_name = "Winlogon"
            log(
                f"[REMOTE-DESKTOP] secure desktop -> Winlogon "
                f"(logonui={logonui} locked={locked} explorer={explorer} "
                f"user={user!r} session={sid} desk={desk_hint or '?'} "
                f"prefer_default_unknown={prefer_default_on_unknown})"
            )
            return
        self._winlogon_mode = False
        self._prefer_dxgi = True
        # Keep follow_console if already set; SID Start also gets DXGI Default.
        if not self._force_secure_desktop:
            self._follow_console = True
        if user:
            self._target_username = user
        self._desktop_name = "Default"
        log(
            f"[REMOTE-DESKTOP] unlocked Default -> DXGI "
            f"session={sid} user={user!r} locked={locked} "
            f"prefer_default_unknown={prefer_default_on_unknown} — skip Winlogon helper"
        )

    def _maybe_skip_winlogon_for_live_console(self) -> None:
        """If console already has a user Default desktop, skip Winlogon helper."""
        if not self._winlogon_mode or self._force_secure_desktop:
            return
        sid = int(self._target_session_id or 0)
        if sid <= 0:
            return
        try:
            from client_rd_winlogon import (
                console_start_secure_desktop,
                session_has_logonui,
                session_has_process,
                session_lock_state,
            )
            user = self._console_interactive_username()
            logonui = bool(session_has_logonui(sid))
            locked = session_lock_state(sid)
            explorer = session_has_process(sid, "explorer.exe")
            if console_start_secure_desktop(
                username=user,
                logonui_present=logonui,
                session_locked=locked,
                explorer_present=explorer,
                input_desktop=str(self._desktop_name or ""),
            ):
                return
        except Exception as exc:
            log(f"[REMOTE-DESKTOP] console desktop probe: {exc}")
            return
        self._winlogon_mode = False
        self._prefer_dxgi = True
        self._follow_console = True
        self._target_username = user
        self._desktop_name = "Default"
        log(
            f"[REMOTE-DESKTOP] C-RD-FOLLOW live console Default "
            f"session={sid} user={user!r} — skip Winlogon helper"
        )

    def _fallback_winlogon_helper_to_default(
        self,
        *,
        jpeg,
        w: int,
        h: int,
        phase: str,
    ):
        """jpeg=0B / accept timeout on Winlogon while Default is open → Default helper."""
        if not self._winlogon_mode or not self._follow_console:
            return None
        phase_l = str(phase or "").lower()
        if phase_l not in ("spawn", "accept", "token", "create", "no_frame", ""):
            if jpeg and w > 0 and h > 0:
                return None
        sid = int(self._target_session_id or 0)
        user = self._console_interactive_username()
        logonui = False
        try:
            from client_rd_winlogon import session_has_logonui
            logonui = bool(session_has_logonui(sid))
        except Exception:
            logonui = False
        if logonui:
            return None
        try:
            from client_rd_winlogon import session_lock_state
            if session_lock_state(sid) is True:
                return None
        except Exception:
            pass
        if not user:
            return None
        log(
            f"[REMOTE-DESKTOP] C-RD-FOLLOW fallback Winlogon→Default "
            f"phase={phase_l or 'empty'} jpeg={0 if not jpeg else len(jpeg)}B "
            f"session={sid} user={user!r}"
        )
        self.emit_stream_progress(
            "switching",
            f"Winlogon helper failed; attaching Default session {sid}",
            force=True,
        )
        self._winlogon_mode = False
        self._prefer_dxgi = True
        self._follow_console = True
        if user:
            self._target_username = user
        self._desktop_name = "Default"
        self._stop_persistent_helper()
        if not self._start_persistent_helper(accept_timeout=FOLLOW_ACCEPT_SEC):
            log(
                "[REMOTE-DESKTOP] Default helper spawn also failed "
                f"phase={self._last_helper_fail_phase}"
            )
            return None
        jpeg2, w2, h2 = self._grab_via_persistent_helper(0.8)
        if (not jpeg2 or len(jpeg2) < MIN_JPEG_BYTES) and self._last_helper_raw:
            jpeg2, w2, h2 = self._encode_helper_raw_jpeg()
        if jpeg2 and w2 > 0 and h2 > 0 and len(jpeg2) >= MIN_JPEG_BYTES:
            self._last_helper_fail_phase = ""
            return jpeg2, w2, h2
        return None

    def _reset_dxgi_camera(self) -> None:
        """Drop dxcam so the next grab re-creates Desktop Duplication."""
        try:
            if self._dxcam is not None:
                try:
                    self._dxcam.stop()
                except Exception:
                    pass
            self._dxcam = None
        except Exception:
            self._dxcam = None

    def _fallback_flat_winlogon_to_active_rdp(self, *, allow_default: bool = False):
        """C-RD-HOST-2: flat/black → Active RDP/Console user Default.

        Console Winlogon flat (Derin/Ninety PrintWindow miss) and post-logon
        Default ``gdi+black`` / ``no_frame`` (allow_default) both use this path.
        Prefer Active RDP; Active Console is allowed. Same-SID Console still
        hard-respawns the Default helper with DXGI prefer after Welcome.
        """
        if not self._winlogon_mode and not allow_default:
            return None
        if bool(getattr(self, "_active_rdp_fallback_attempted", False)):
            return None
        self._active_rdp_fallback_attempted = True
        console_sid = int(self._target_session_id or 0)
        try:
            sessions = self._enumerate_sessions()
        except Exception:
            return None
        ranked = []
        for s in sessions or []:
            if s.get("pre_logon"):
                continue
            sid = int(s.get("session_id") or 0)
            if sid <= 0:
                continue
            user = str(s.get("username") or "").strip()
            if not user:
                continue
            status = str(s.get("status") or "").lower()
            if status != "active":
                continue
            proto = str(s.get("protocol") or "").lower()
            # Prefer Active RDP; allow Active Console with a real user as well.
            if proto == "rdp":
                rank = 0
            elif proto == "console":
                rank = 2 if sid == console_sid else 1
            else:
                rank = 3
            ranked.append((rank, sid, user, proto))
        if not ranked:
            log("[REMOTE-DESKTOP] active-rdp fallback: no Active user session")
            return None
        ranked.sort()
        sid, user, proto = ranked[0][1], ranked[0][2], ranked[0][3]
        log(
            f"[REMOTE-DESKTOP] C-RD-HOST-2 active-rdp fallback "
            f"console={console_sid} → session={sid} user={user!r} proto={proto} "
            f"allow_default={bool(allow_default)}"
        )
        self.emit_stream_progress(
            "switching",
            (
                f"Default black; respawning Active {proto} session {sid}"
                if allow_default and not self._winlogon_mode
                else f"Console Winlogon flat; attaching Active {proto} session {sid}"
            ),
            force=True,
        )
        self._winlogon_mode = False
        self._force_secure_desktop = False
        self._prefer_dxgi = True
        self._follow_console = False
        self._target_session_id = int(sid)
        self._target_username = user
        self._desktop_name = "Default"
        self._use_user_helper = True
        self._capture_method = f"active-rdp-fallback:{proto}"
        self._stats["capture_method"] = self._capture_method
        self._reset_dxgi_camera()
        self._locked_encode_w = 0
        self._locked_encode_h = 0
        self._stop_persistent_helper()
        if not self._start_persistent_helper(accept_timeout=FOLLOW_ACCEPT_SEC):
            log(
                "[REMOTE-DESKTOP] active-rdp helper spawn failed "
                f"phase={self._last_helper_fail_phase}"
            )
            # In-process DXGI on Default may still paint after Welcome.
            self._use_user_helper = False
            jpeg2, w2, h2 = self._grab_jpeg()
            method = str(self._capture_method or "")
            if (
                jpeg2
                and w2 > 0
                and h2 > 0
                and len(jpeg2) >= MIN_JPEG_BYTES
                and "+flat" not in method
                and "+black" not in method
            ):
                self._capture_method = f"active-rdp-fallback:dxgi:{proto}"
                self._stats["capture_method"] = self._capture_method
                return jpeg2, w2, h2
            return None
        jpeg2, w2, h2 = self._grab_via_persistent_helper(1.0)
        if (not jpeg2 or len(jpeg2) < MIN_JPEG_BYTES) and self._last_helper_raw:
            jpeg2, w2, h2 = self._encode_helper_raw_jpeg()
        method = str(self._capture_method or "")
        if (
            jpeg2
            and w2 > 0
            and h2 > 0
            and len(jpeg2) >= MIN_JPEG_BYTES
            and "+flat" not in method
            and "+black" not in method
        ):
            self._last_helper_fail_phase = ""
            if "active-rdp-fallback" not in method:
                self._capture_method = f"active-rdp-fallback:{method or proto}"
                self._stats["capture_method"] = self._capture_method
            return jpeg2, w2, h2
        # Helper still black — one in-process DXGI pass on Default.
        self._use_user_helper = False
        self._prefer_dxgi = True
        jpeg3, w3, h3 = self._grab_jpeg()
        method3 = str(self._capture_method or "")
        if (
            jpeg3
            and w3 > 0
            and h3 > 0
            and len(jpeg3) >= MIN_JPEG_BYTES
            and "+flat" not in method3
            and "+black" not in method3
        ):
            self._capture_method = f"active-rdp-fallback:dxgi:{proto}"
            self._stats["capture_method"] = self._capture_method
            return jpeg3, w3, h3
        return None

    def _should_promote_follow_to_winlogon(self) -> bool:
        """Lock/LogonUI with a listed username → user-helper GDI black (C-RD-PIX-3).

        Unlocked Default (WTS unlocked; explorer optional during Welcome) is PIX-4:
        do **not** jump to Winlogon because GDI was black — retry DXGI instead.
        Applies to follow **and** SID Start (lab 4.9.103 Active username FAIL).

        Exception: if LogonUI is present, prefer Winlogon even when explorer is
        listed Active (Derin: Default+user-helper black while lock UI is live).
        """
        if self._winlogon_mode or self._force_secure_desktop:
            return False
        try:
            from client_rd_winlogon import (
                session_has_logonui,
                session_has_process,
                session_lock_state,
            )
            sid = int(self._target_session_id or 0)
            logonui = bool(session_has_logonui(sid)) if sid > 0 else False
            locked = session_lock_state(sid) if sid > 0 else None
            explorer = (
                session_has_process(sid, "explorer.exe") if sid > 0 else None
            )
            if logonui or locked is True:
                return True
            if (
                locked is False
                and not logonui
            ):
                # Welcome / getting-ready: explorer may still be False — stay Default.
                return False
            if (
                explorer is True
                and locked is False
                and not logonui
            ):
                return False
        except Exception:
            pass
        method = str(self._capture_method or "").lower()
        desk = str(self._desktop_name or "").lower()
        if "winlogon" in desk:
            return True
        if "+black" not in method and "+flat" not in method:
            return False
        if "dxgi" in method or "nvenc" in method:
            return False
        return "gdi" in method or "helper" in method

    def _retry_unlocked_dxgi_capture(self):
        """PIX-4: reset DXGI and re-grab Default; never treat as Winlogon success.

        Explorer is **optional** — post-password Welcome often has no explorer yet
        while WTS is already unlocked (FOLLOW-10 / Derin Hoş Geldiniz freeze).
        """
        if self._winlogon_mode or self._force_secure_desktop:
            return None
        try:
            from client_rd_winlogon import (
                session_has_logonui,
                session_lock_state,
            )
            sid = int(self._target_session_id or 0)
            if sid > 0 and (
                session_has_logonui(sid)
                or session_lock_state(sid) is True
            ):
                return None
        except Exception:
            pass
        log(
            "[REMOTE-DESKTOP] PIX-4 DXGI retry after gdi+black "
            f"method={self._capture_method} desk={self._desktop_name}"
        )
        self._prefer_dxgi = True
        self._desktop_name = "Default"
        self._desktop_attached = False
        self._reset_dxgi_camera()
        # Drop encode lock so 1024×768 black does not stick.
        self._locked_encode_w = 0
        self._locked_encode_h = 0
        self._attach_input_desktop()
        if self._persistent_helper_connected():
            try:
                self._session_helper.update_config({
                    "fps": max(float(self._fps or DEFAULT_FPS), 30.0),
                    "quality": max(int(self._quality or DEFAULT_QUALITY), 72),
                    "max_width": max(int(self._max_width or DEFAULT_MAX_WIDTH), 1920),
                    "monitor": self._monitor_index,
                    "winlogon": False,
                    "prefer_raw": bool(
                        self._media_ready() and not self._jpeg_ws_primary()
                    ),
                })
            except Exception:
                pass
            jpeg, w, h = self._grab_via_persistent_helper(1.2)
            if (not jpeg or len(jpeg) < MIN_JPEG_BYTES) and self._last_helper_raw:
                jpeg, w, h = self._encode_helper_raw_jpeg()
            method = str(self._capture_method or "")
            if (
                jpeg
                and w > 0
                and h > 0
                and len(jpeg) >= MIN_JPEG_BYTES
                and "+black" not in method
                and "+flat" not in method
            ):
                if "dxgi" not in method.lower():
                    self._capture_method = f"dxgi:{method or 'desktop-duplication'}"
                    self._stats["capture_method"] = self._capture_method
                return jpeg, w, h
            # Helper still black — bridge with in-process DXGI.
            jpeg, w, h = self._grab_jpeg()
        else:
            jpeg, w, h = self._grab_jpeg()
        method = str(self._capture_method or "")
        if (
            jpeg
            and w > 0
            and h > 0
            and len(jpeg) >= MIN_JPEG_BYTES
            and "+black" not in method
            and "+flat" not in method
        ):
            if "dxgi" not in method.lower():
                self._capture_method = f"dxgi:{method or 'desktop-duplication'}"
                self._stats["capture_method"] = self._capture_method
            return jpeg, w, h
        return None

    def _recover_default_black_capture(self):
        """DXGI retry then Active-session Default respawn after post-logon black."""
        if self._winlogon_mode or self._force_secure_desktop:
            return None
        retried = self._retry_unlocked_dxgi_capture()
        if retried:
            return retried
        try:
            return self._fallback_flat_winlogon_to_active_rdp(allow_default=True)
        except Exception as exc:
            self._note_recovery(f"fail:default_black_active_rdp:{exc}")
            return None

    def _maybe_recover_default_black_streak(self) -> None:
        """After sustained Default black, attempt one recovery wave (FOLLOW-4)."""
        if self._winlogon_mode or self._force_secure_desktop:
            return
        if bool(getattr(self, "_default_black_recover_attempted", False)):
            return
        started = float(getattr(self, "_black_streak_started", 0) or 0)
        if started <= 0:
            return
        if time.time() - started < float(DEFAULT_BLACK_RECOVER_SEC):
            return
        self._default_black_recover_attempted = True
        self._note_recovery("try:default_black_streak_recover")
        out = self._recover_default_black_capture()
        if out:
            jpeg, w, h = out
            self._black_streak_started = 0.0
            self._default_dxgi_retry_this_streak = False
            self._note_recovery("ok:default_black_streak_recover")
            try:
                self._seq += 1
                self._enqueue_ws_frame(jpeg, w, h, self._seq)
                self._last_activity = time.time()
            except Exception:
                pass
            self.emit_stream_progress(
                "live",
                "Default capture recovered after black streak",
                force=True,
            )
        else:
            self._note_recovery("fail:default_black_streak_recover")
            self._persist_capture_fail_dump(
                reason="default_black_recover_fail",
                detail=(
                    f"streak≥{DEFAULT_BLACK_RECOVER_SEC:.1f}s "
                    f"method={self._capture_method} "
                    f"var={self._last_frame_variance:.1f}"
                ),
                force=True,
            )
            self.emit_stream_progress(
                "degraded",
                "Default still black after DXGI/Active recovery",
                error="FOLLOW_NO_DEFAULT_FRAME",
                force=True,
            )

    def _fallback_user_helper_to_winlogon(
        self,
        *,
        jpeg,
        w: int,
        h: int,
        phase: str,
        force: bool = False,
    ):
        """Follow + listed user but lock screen: switch to Winlogon helper."""
        if not force and not self._should_promote_follow_to_winlogon():
            return None
        sid = int(self._target_session_id or 0)
        log(
            f"[REMOTE-DESKTOP] C-RD-PIX-3 fallback Default→Winlogon "
            f"phase={phase} jpeg={0 if not jpeg else len(jpeg)}B "
            f"method={self._capture_method} desk={self._desktop_name} session={sid}"
        )
        self.emit_stream_progress(
            "switching",
            "Lock/LogonUI detected; attaching Winlogon helper",
            force=True,
        )
        self._winlogon_mode = True
        self._target_username = ""
        self._desktop_name = "Winlogon"
        self._prefer_dxgi = False
        self._follow_console = True
        self._stop_persistent_helper()
        if not self._start_persistent_helper(accept_timeout=WINLOGON_HELPER_ACCEPT_SEC):
            log(
                "[REMOTE-DESKTOP] Winlogon helper spawn failed after Default black "
                f"phase={self._last_helper_fail_phase}"
            )
            self._winlogon_mode = False
            return None
        time.sleep(WINLOGON_HELPER_SETTLE_SEC)
        deadline = time.time() + WINLOGON_HELPER_FRAME_SEC
        jpeg2, w2, h2 = None, 0, 0
        while time.time() < deadline:
            jpeg2, w2, h2 = self._grab_via_persistent_helper(0.35)
            if (not jpeg2 or len(jpeg2) < MIN_JPEG_BYTES) and self._last_helper_raw:
                jpeg2, w2, h2 = self._encode_helper_raw_jpeg()
            blackish = "+black" in (self._capture_method or "")
            flattish = "+flat" in (self._capture_method or "")
            if (
                jpeg2
                and w2 > 0
                and h2 > 0
                and len(jpeg2) >= MIN_JPEG_BYTES
                and not blackish
                and not flattish
            ):
                self._last_helper_fail_phase = ""
                return jpeg2, w2, h2
            time.sleep(0.08)
        if jpeg2 and w2 > 0 and h2 > 0 and len(jpeg2) >= MIN_JPEG_BYTES:
            if "+black" not in (self._capture_method or ""):
                self._last_helper_fail_phase = ""
                return jpeg2, w2, h2
        return None

    def _maybe_promote_follow_lock_capture(self) -> None:
        if not self._running or self._follow_busy:
            return
        if not self._should_promote_follow_to_winlogon():
            return
        self._fallback_user_helper_to_winlogon(
            jpeg=None, w=0, h=0, phase="live"
        )

    def _maybe_follow_console_desktop(self) -> None:
        """Chrome Remote Desktop model: always match console input desktop.

        Lock/logoff → Winlogon helper. Unlock/logon → Default DXGI. Same stream_id.
        Runs for follow, SID Start, **and** lock-row (`force_secure`) after
        credentials — otherwise the viewer freezes on Welcome (FOLLOW-4).
        """
        if self._follow_busy or not self._running:
            return
        now = time.time()
        # Poll faster while still on Winlogon so post-password switch ≤2s.
        min_gap = 0.12 if self._winlogon_mode else FOLLOW_CHECK_SEC
        stale = False
        try:
            if self._winlogon_mode and self._last_send_mono > 0:
                stale = (time.monotonic() - float(self._last_send_mono)) >= 1.2
        except Exception:
            stale = False
        if not stale and (now - float(self._last_follow_check or 0)) < min_gap:
            return
        self._last_follow_check = now
        try:
            from client_rd_winlogon import (
                console_session_id,
                decide_console_follow,
                resolve_console_capture_mode,
                session_has_logonui,
                session_has_process,
                session_lock_state,
                session_username,
            )
            csid = int(console_session_id() or 0)
            target = int(self._target_session_id or 0)
            # After any Start that can unlock, follow the physical console.
            sid = csid if (self._follow_console or self._force_secure_desktop or target <= 0) else target
            if sid <= 0:
                sid = csid or target
            if sid <= 0:
                return
            user = session_username(sid) if sid else ""
            logonui = bool(session_has_logonui(sid)) if sid else False
            locked = session_lock_state(sid) if sid else None
            explorer = session_has_process(sid, "explorer.exe") if sid else None
            reported = str(self._desktop_name or "").strip().lower()
            # Live OpenInputDesktop name when known; do NOT sticky-force Winlogon
            # from a stale _desktop_name (that froze post-logon streams).
            input_desk = reported if reported in ("winlogon", "default") else ""
            desired = resolve_console_capture_mode(sid, input_desktop=input_desk)
            follow_reason = decide_console_follow(
                follow_console=True,
                winlogon_mode=bool(self._winlogon_mode),
                spawn_session_id=int(
                    self._helper_spawn_session_id
                    or self._target_session_id
                    or 0
                ),
                console_sid=sid,
                console_username=user,
                helper_desktop=reported,
                logonui_hwnd=int(getattr(self, "_logonui_hwnd_count", 0) or 0),
                chrome_detected=bool(self._chrome_detected),
                session_locked=locked,
                explorer_present=explorer,
                logonui_present=logonui,
            )
            if follow_reason:
                desired = "default"
            want_wl = desired == "winlogon"
            black = "+black" in str(self._capture_method or "")
            helper_wl = bool(self._helper_spawned_winlogon)
            connected = bool(self._persistent_helper_connected())
            mode_mismatch = bool(self._winlogon_mode) != want_wl
            helper_mismatch = connected and (helper_wl != want_wl)
            need_black_fix = black and (
                (want_wl and not self._winlogon_mode)
                or (not want_wl and self._winlogon_mode)
                or helper_mismatch
            )
            need_stale_unlock = bool(
                stale and self._winlogon_mode and not want_wl
            )
            if not (
                mode_mismatch
                or helper_mismatch
                or need_black_fix
                or need_stale_unlock
                or follow_reason
            ):
                return
            if want_wl:
                if self._winlogon_mode and connected and helper_wl and not black:
                    return
                self._follow_console = True
                self._fallback_user_helper_to_winlogon(
                    jpeg=None, w=0, h=0, phase=f"auto_{desired}", force=True
                )
                return
            # Desired Default (unlocked / post-logon shell)
            self._follow_console = True
            reason = follow_reason or f"auto_{desired}"
            if need_stale_unlock:
                reason = f"stale_{reason}"
            self._execute_console_follow(reason, sid, user)
        except Exception as exc:
            log(f"[REMOTE-DESKTOP] auto desktop sync error: {exc}")
            return

    def _execute_console_follow(self, reason: str, new_sid: int, username: str) -> None:
        """Tear Winlogon helper, rebind Default, keep stream_id (C-RD-FOLLOW-1/2/4)."""
        if not self._follow_lock.acquire(blocking=False):
            return
        self._follow_busy = True
        prev_sid = self._target_session_id
        stream_id = self._stream_id
        try:
            log(
                f"[REMOTE-DESKTOP] C-RD-FOLLOW {reason} "
                f"sid {prev_sid}→{new_sid} user={username!r} "
                f"stream={stream_id}"
            )
            self._progress_live_emitted = False
            self._last_activity = time.time()
            self.emit_stream_progress(
                "switching",
                f"Following console to Default (session {new_sid})",
                force=True,
            )
            self._enqueue_capture_diag(
                phase="switching",
                reason=str(reason or "follow"),
                detail=f"sid {prev_sid}→{new_sid}",
            )
            self._last_raw_hash = b""
            self._idle_skip_streak = 0
            self._black_streak_started = 0.0
            self._flat_streak_started = 0.0
            spawn = int(
                self._helper_spawn_session_id
                or (self._session_helper.session_id if self._session_helper else 0)
                or (prev_sid or 0)
            )
            same_sid = int(new_sid) == int(spawn)
            # Always leave Winlogon helper after unlock — stale desk name must not skip respawn.
            respawn = (not same_sid) or bool(self._winlogon_mode) or bool(
                self._helper_spawned_winlogon
            ) or str(self._desktop_name or "").lower() != "default"
            self._winlogon_mode = False
            self._force_secure_desktop = False  # unlock clears lock-row pin
            self._prefer_dxgi = True
            # Allow HOST-2 again on Default black after a Winlogon-start attempt.
            self._active_rdp_fallback_attempted = False
            self._default_black_recover_attempted = False
            self._target_session_id = int(new_sid)
            self._target_username = str(username or "").strip()
            self._desktop_name = "Default"
            self._use_user_helper = True
            self._note_recovery(f"follow:{reason}")
            self._reset_dxgi_camera()
            self._locked_encode_w = 0
            self._locked_encode_h = 0

            started = False
            if respawn or not self._persistent_helper_connected():
                for attempt in range(1, int(FOLLOW_HELPER_RETRIES) + 1):
                    self._stop_persistent_helper()
                    self._note_recovery(f"follow_spawn_try:{attempt}")
                    started = self._start_persistent_helper(
                        accept_timeout=FOLLOW_ACCEPT_SEC
                    )
                    if started:
                        self._note_recovery(f"follow_spawn_ok:{attempt}")
                        break
                    log(
                        "[REMOTE-DESKTOP] C-RD-FOLLOW helper respawn failed "
                        f"try={attempt}/{FOLLOW_HELPER_RETRIES} "
                        f"phase={self._last_helper_fail_phase} "
                        f"detail={self._last_helper_fail_detail}"
                    )
                    time.sleep(0.35 * attempt)
                if not started:
                    self.emit_stream_progress(
                        "degraded",
                        "Post-logon Default helper spawn failed — DXGI fallback",
                        error="FOLLOW_HELPER_SPAWN_FAILED",
                        force=True,
                    )
                    self._enqueue_capture_diag(
                        phase="degraded",
                        reason="follow_spawn_failed",
                        detail=str(self._last_helper_fail_detail or ""),
                    )
                    # Keep stream alive: in-process DXGI/GDI on Default.
                    self._use_user_helper = False
                    self._prefer_dxgi = True
                    self._note_recovery("follow_dxgi_fallback")
            elif self._persistent_helper_connected():
                started = True
                fps, quality, max_width = self._effective_capture_settings()
                self._session_helper.update_config({
                    "winlogon": False,
                    "prefer_raw": bool(
                        self._media_ready() and not self._jpeg_ws_primary()
                    ),
                    "fps": max(float(fps), 15.0),
                    "quality": quality,
                    "max_width": max_width,
                    "monitor": self._monitor_index,
                })
            self._stream_id = stream_id
            # Probe Default pixels — Welcome can take several seconds (FOLLOW-4).
            jpeg2, w2, h2 = None, 0, 0
            dxgi_retried = False
            deadline = time.time() + float(FOLLOW_DEFAULT_PROBE_SEC)
            while time.time() < deadline:
                if self._use_user_helper and self._persistent_helper_connected():
                    jpeg2, w2, h2 = self._grab_via_persistent_helper(0.4)
                    if (not jpeg2 or len(jpeg2) < MIN_JPEG_BYTES) and self._last_helper_raw:
                        jpeg2, w2, h2 = self._encode_helper_raw_jpeg()
                else:
                    try:
                        self._desktop_attached = False
                        self._attach_input_desktop()
                    except Exception:
                        pass
                    jpeg2, w2, h2 = self._grab_jpeg()
                method = str(self._capture_method or "")
                if (
                    jpeg2
                    and w2 > 0
                    and h2 > 0
                    and len(jpeg2) >= MIN_JPEG_BYTES
                    and "+black" not in method
                    and "+flat" not in method
                ):
                    break
                # Mid-Welcome black: one DXGI reset mid-probe (not every tick).
                if (
                    not dxgi_retried
                    and (
                        "+black" in method
                        or "+flat" in method
                        or not jpeg2
                    )
                ):
                    dxgi_retried = True
                    recovered = self._retry_unlocked_dxgi_capture()
                    if recovered:
                        jpeg2, w2, h2 = recovered
                        method = str(self._capture_method or "")
                        if "+black" not in method and "+flat" not in method:
                            break
                # Helper died mid-Welcome — respawn once more then DXGI.
                if self._use_user_helper and not self._persistent_helper_connected():
                    self._note_recovery("follow_helper_drop_mid_probe")
                    if self._start_persistent_helper(accept_timeout=FOLLOW_ACCEPT_SEC):
                        continue
                    self._use_user_helper = False
                    self._prefer_dxgi = True
                time.sleep(0.12)
            self._enqueue_meta(force=True)
            method = str(self._capture_method or "")
            healthy = bool(
                jpeg2
                and w2 > 0
                and h2 > 0
                and len(jpeg2) >= MIN_JPEG_BYTES
                and "+black" not in method
                and "+flat" not in method
            )
            if not healthy:
                # Last chance: DXGI + Active Console/RDP Default respawn.
                recovered = self._recover_default_black_capture()
                if recovered:
                    jpeg2, w2, h2 = recovered
                    method = str(self._capture_method or "")
                    healthy = bool(
                        jpeg2
                        and w2 > 0
                        and h2 > 0
                        and len(jpeg2) >= MIN_JPEG_BYTES
                        and "+black" not in method
                        and "+flat" not in method
                    )
                    if healthy:
                        self._note_recovery("follow_default_black_recover")
            if healthy:
                try:
                    self._seq += 1
                    self._enqueue_ws_frame(jpeg2, w2, h2, self._seq)
                    self._last_activity = time.time()
                except Exception:
                    pass
                self.emit_stream_progress(
                    "live",
                    f"Console follow complete desktop=Default session={new_sid}",
                    force=True,
                )
                self._enqueue_capture_diag(
                    phase="live",
                    reason=str(reason or "follow"),
                    detail=f"default {w2}x{h2} method={method}",
                )
            else:
                # Do not stop the stream — keep capturing; Welcome may still paint.
                self._use_user_helper = bool(self._persistent_helper_connected())
                if not self._use_user_helper:
                    self._prefer_dxgi = True
                self.emit_stream_progress(
                    "degraded",
                    "Switched to Default — waiting for desktop pixels",
                    error="FOLLOW_NO_DEFAULT_FRAME",
                    force=True,
                )
                self._enqueue_capture_diag(
                    phase="degraded",
                    reason="follow_no_frame",
                    detail=f"method={method} jpeg={0 if not jpeg2 else len(jpeg2)}B",
                )
                self._note_recovery("follow_no_frame_keep_streaming")
                self._persist_capture_fail_dump(
                    reason="follow_no_frame",
                    jpeg=jpeg2,
                    detail=f"method={method} jpeg={0 if not jpeg2 else len(jpeg2)}B",
                    force=True,
                )
        except Exception as exc:
            log(f"[REMOTE-DESKTOP] C-RD-FOLLOW error: {exc}")
        finally:
            self._follow_busy = False
            self._follow_lock.release()

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
        if self._winlogon_mode:
            argv.append("--rd-helper-winlogon")
        return subprocess.list2cmdline(argv)

    def _helper_desktop(self) -> str:
        """lpDesktop for CreateProcessAsUser — Winlogon for logon/lock UI."""
        if self._winlogon_mode:
            return r"winsta0\Winlogon"
        return r"winsta0\default"

    def _persistent_helper_matches_mode(self) -> bool:
        if not self._persistent_helper_connected():
            return False
        spawned = self._helper_spawned_winlogon
        if spawned is None:
            return False
        return bool(spawned) == bool(self._winlogon_mode)

    def _start_persistent_helper(self, accept_timeout: Optional[float] = None) -> bool:
        target = self._target_session_id
        if not target:
            self._last_helper_fail_phase = "token"
            self._last_helper_fail_detail = "no_target_session"
            return False
        if self._persistent_helper_matches_mode():
            return True
        self._stop_persistent_helper()
        self._last_helper_token_source = ""
        self._last_helper_fail_phase = ""
        self._last_helper_fail_detail = ""
        try:
            from client_rd_session_helper import PersistentSessionHelper

            desktop = self._helper_desktop()
            timeout = float(
                accept_timeout
                if accept_timeout is not None
                else PROBE_TIMEOUT_SEC
            )

            def _launch(sid, cmd):
                ok = self._launch_in_session(
                    sid, cmd, wait=False, desktop=desktop
                )
                if not ok and not self._last_helper_fail_phase:
                    self._last_helper_fail_phase = "spawn"
                    self._last_helper_fail_detail = (
                        f"CreateProcessAsUser failed "
                        f"token={self._last_helper_token_source or 'none'}"
                    )
                return ok

            helper = PersistentSessionHelper(
                int(target),
                launch=_launch,
                command_builder=self._helper_command,
                log=log,
            )
            config = {
                "fps": max(
                    float(self._requested_fps or self._fps),
                    JPEG_FALLBACK_FPS_WHILE_NEGOTIATING,
                    30.0,
                ),
                "quality": max(
                    int(self._requested_quality or self._quality),
                    DEFAULT_QUALITY,
                    72,
                ),
                "max_width": max(
                    int(self._requested_max_width or self._max_width),
                    DEFAULT_MAX_WIDTH,
                    1920,
                ),
                "monitor": self._monitor_index,
                "winlogon": bool(self._winlogon_mode),
                # JPEG-WS primary until ICE/DTLS ready — no raw RGB tax during connect.
                "prefer_raw": False,
            }
            if self._media_ready() and not self._jpeg_ws_primary():
                config["fps"] = self._media_fps
                config["quality"] = max(int(self._media_quality), DEFAULT_QUALITY)
                config["prefer_raw"] = True
            if not helper.start(config, timeout=timeout):
                err = str(helper.error or "helper start failed")
                self._last_helper_fail_detail = err
                low = err.lower()
                if "accept" in low or "timed out" in low or "timeout" in low:
                    self._last_helper_fail_phase = "accept"
                elif "createprocess" in low or "launch" in low:
                    self._last_helper_fail_phase = "spawn"
                elif not self._last_helper_fail_phase:
                    self._last_helper_fail_phase = "spawn"
                log(
                    f"[REMOTE-DESKTOP] persistent helper start failed: {err} "
                    f"phase={self._last_helper_fail_phase} "
                    f"token={self._last_helper_token_source or 'none'}"
                )
                helper.stop()
                return False
            self._session_helper = helper
            self._helper_spawned_winlogon = bool(self._winlogon_mode)
            self._helper_frame_id = 0
            self._helper_frame_misses = 0
            self._helper_spawn_session_id = int(target)
            self._last_helper_fail_phase = ""
            # Honest provisional method — never advertise dxgi:pending (lab Derin stall).
            if self._winlogon_mode:
                method = "persistent-winlogon-helper"
            else:
                method = "helper"
            self._capture_method = method
            self._stats["capture_method"] = self._capture_method
            log(
                f"[REMOTE-DESKTOP] persistent helper connected session={target} "
                f"desktop={desktop} token={self._last_helper_token_source or '?'} "
                f"accept≤{timeout:.1f}s method={method}"
            )
            return True
        except Exception as e:
            log(f"[REMOTE-DESKTOP] persistent helper error: {e}")
            self._last_helper_fail_phase = "spawn"
            self._last_helper_fail_detail = str(e)
            self._stop_persistent_helper()
            return False

    def _encode_helper_raw_jpeg(self) -> Tuple[Optional[bytes], int, int]:
        """Encode last helper raw RGB into JPEG for probe / JPEG-WS fallback."""
        if not self._last_helper_raw:
            return None, 0, 0
        rgb, width, height = self._last_helper_raw
        self._last_helper_raw = None
        try:
            from PIL import Image
            img = Image.frombytes("RGB", (int(width), int(height)), rgb)
            buf = io.BytesIO()
            img.save(
                buf,
                format="JPEG",
                quality=max(22, int(self._quality or DEFAULT_QUALITY)),
                optimize=False,
                subsampling=2,
            )
            data = buf.getvalue()
            return data, int(width), int(height)
        except Exception as exc:
            log(f"[REMOTE-DESKTOP] helper raw→jpeg encode failed: {exc}")
            return None, 0, 0

    def _sync_helper_frame_telemetry(
        self,
        meta: dict,
        *,
        payload: Optional[bytes] = None,
        width: int = 0,
        height: int = 0,
        fmt: str = "jpeg",
    ) -> None:
        """Mirror helper chrome/method/variance into parent live status.

        Soft-start may leave gdi+flat / chrome=false; settle frames must refresh
        these even when JPEG already shows LogonUI (4.9.90 residual).
        """
        meta = meta if isinstance(meta, dict) else {}
        method = str(meta.get("method") or "capture")
        method_l = method.lower()
        if self._winlogon_mode:
            prefix = "persistent-winlogon-helper"
        elif "dxgi" in method_l or "nvenc" in method_l:
            prefix = "dxgi"
        else:
            prefix = "persistent-user-helper"
        prev_method = self._capture_method or ""
        var = meta.get("frame_variance")
        chrome_meta = meta.get("chrome_detected")
        hwnd = meta.get("hwnd")
        desk = str(meta.get("desktop") or "").strip()
        if desk:
            self._desktop_name = desk
        # Parent never attaches when helper owns capture — mirror helper bind.
        if "desktop_attached" in meta:
            try:
                self._desktop_attached = bool(meta.get("desktop_attached"))
            except Exception:
                pass
        elif desk.lower() == "winlogon" and self._winlogon_mode:
            # Helper reported named Winlogon desktop ⇒ treat as attached for diag.
            self._desktop_attached = True

        img = None
        if payload and width > 0 and height > 0:
            try:
                from PIL import Image
                if str(fmt).lower() == "rgb" and len(payload) >= width * height * 3:
                    img = Image.frombytes("RGB", (width, height), bytes(payload))
                elif str(fmt).lower() != "rgb":
                    img = Image.open(io.BytesIO(payload)).convert("RGB")
            except Exception:
                img = None

        bad_tag = ""
        if "+black" in method:
            bad_tag = "+black"
        elif "+flat" in method:
            bad_tag = "+flat"

        if img is not None:
            # Pixel truth overrides a stale +flat tag from an earlier settle grab.
            if self._is_mostly_black(img):
                bad_tag = "+black"
            elif self._is_mostly_flat(img):
                bad_tag = "+flat"
            else:
                bad_tag = ""
            base_m = method.split("+")[0] if method else "capture"
            self._remember_frame_chrome(img, f"{prefix}:{base_m}{bad_tag}")
        else:
            if var is not None:
                try:
                    self._last_frame_variance = float(var)
                    self._stats["frame_variance"] = float(var)
                except (TypeError, ValueError):
                    pass
            if chrome_meta is not None:
                chrome = bool(chrome_meta) and bad_tag == ""
                self._chrome_detected = chrome
                self._stats["chrome_detected"] = chrome
            elif bad_tag:
                self._chrome_detected = False
                self._stats["chrome_detected"] = False

        # Helper hwnd/desktop wins over Session-0 enum inside _remember_frame_chrome.
        if hwnd is not None:
            try:
                self._logonui_hwnd_count = int(hwnd)
            except (TypeError, ValueError):
                pass
        if desk:
            self._desktop_name = desk

        base = method.split("+")[0] if method else "capture"
        if str(fmt).lower() == "rgb":
            self._capture_method = f"{prefix}:raw{bad_tag}"
        elif "dxgi" in method.lower() and not bad_tag:
            # Honest live method for PIX-4 / SMOOTH dashboards.
            enc = "nvenc" if self._media_ready() else "desktop-duplication"
            self._capture_method = f"dxgi+{enc}"
        else:
            self._capture_method = f"{prefix}:{base}{bad_tag}"
        self._stats["capture_method"] = self._capture_method

        if bad_tag == "":
            self._flat_streak_started = 0.0
            self._black_streak_started = 0.0
            # One more hwnd/var diag after soft-start flat → real chrome.
            if "+flat" in prev_method and self._chrome_detected:
                self._chrome_diag_logged = False
                if img is not None:
                    self._remember_frame_chrome(img, self._capture_method)
                if hwnd is not None:
                    try:
                        self._logonui_hwnd_count = int(hwnd)
                    except (TypeError, ValueError):
                        pass
                if desk:
                    self._desktop_name = desk

    def _grab_via_persistent_helper(
        self, timeout: float = 2.0
    ) -> Tuple[Optional[bytes], int, int]:
        helper = self._session_helper
        self._last_helper_raw = None
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
        frame_id, payload, meta = frame
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
        fmt = str(meta.get("format") or "jpeg").lower()
        if fmt == "rgb" and payload and width > 0 and height > 0:
            if len(payload) < width * height * 3:
                self._stats["frames_failed"] += 1
                return None, 0, 0
            self._sync_helper_frame_telemetry(
                meta, payload=payload, width=width, height=height, fmt="rgb"
            )
            self._last_helper_raw = (bytes(payload), width, height)
            return None, width, height
        self._sync_helper_frame_telemetry(
            meta,
            payload=payload if payload else None,
            width=width,
            height=height,
            fmt="jpeg",
        )
        return payload, width, height

    def _stop_persistent_helper(self) -> None:
        helper = self._session_helper
        self._session_helper = None
        self._helper_spawned_winlogon = None
        self._helper_frame_id = 0
        self._helper_frame_misses = 0
        if helper is not None:
            try:
                helper.stop()
            except Exception:
                pass

    def _grab_via_user_helper(
        self, wait_sec: Optional[float] = None
    ) -> Tuple[Optional[bytes], int, int]:
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
            self._last_helper_fail_phase = "token"
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
        winlogon_flag = " --rd-capture-winlogon" if self._winlogon_mode else ""
        cmd = f'"{exe}" --rd-capture-once "{out_path}"{winlogon_flag}'

        launched = self._launch_in_session(
            int(target), cmd, desktop=self._helper_desktop()
        )
        if not launched:
            # Session-0 subprocess cannot see another user's desktop — do not fake it
            log(
                f"[REMOTE-DESKTOP] helper launch failed for session={target} "
                f"desktop={self._helper_desktop()} "
                f"token={self._last_helper_token_source or 'none'} "
                "(no Session-0 fallback — would capture black)"
            )
            if not self._last_helper_fail_phase:
                self._last_helper_fail_phase = "spawn"
            return None, 0, 0

        wait_for = float(
            wait_sec
            if wait_sec is not None
            else (PROBE_TIMEOUT_SEC + 2)
        )
        deadline = time.time() + max(0.5, wait_for)
        while time.time() < deadline:
            if os.path.isfile(out_path) and os.path.getsize(out_path) >= MIN_JPEG_BYTES:
                break
            time.sleep(0.12)
        else:
            log(
                f"[REMOTE-DESKTOP] helper capture timed out "
                f"(no JPEG file ≤{wait_for:.1f}s, "
                f"token={self._last_helper_token_source or 'none'})"
            )
            self._last_helper_fail_phase = self._last_helper_fail_phase or "no_frame"
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
            self._capture_method = (
                "winlogon-helper" if self._winlogon_mode else "user-helper"
            )
            self._stats["capture_method"] = self._capture_method
            self._use_user_helper = True
            self._screen_w, self._screen_h = w, h
            self._capture_w, self._capture_h = w, h
            log(
                f"[REMOTE-DESKTOP] helper capture ok — {w}x{h} {len(data)}B "
                f"session={target} token={self._last_helper_token_source or '?'}"
            )
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

    def _open_session_token(self, session_id: int):
        """Interactive-session token for CreateProcessAsUser (C-RD-S0-4).

        Chain: WTSQueryUserToken → winlogon/LogonUI process token →
        SYSTEM+TokenSessionId. Returns ``(HANDLE|None, source_tag)``.
        """
        try:
            from client_rd_winlogon import open_session_interactive_token
            return open_session_interactive_token(
                int(session_id),
                for_secure_desktop=bool(self._winlogon_mode),
            )
        except Exception as exc:
            log(f"[REMOTE-DESKTOP] open_session_token error: {exc}")
            return None, "no_token"

    def _launch_in_session(
        self,
        session_id: int,
        command: str,
        wait: bool = True,
        desktop: Optional[str] = None,
    ) -> bool:
        """CreateProcessAsUser in target WTS session (requires SYSTEM / SeTcbPrivilege).

        ``desktop`` defaults to ``winsta0\\default``; Winlogon path uses
        ``winsta0\\Winlogon`` so LogonUI pixels are in-process for the helper.
        """
        try:
            import ctypes
            from ctypes import wintypes

            from client_rd_winlogon import enable_process_privileges

            enable_process_privileges(
                "SeDebugPrivilege",
                "SeTcbPrivilege",
                "SeAssignPrimaryTokenPrivilege",
                "SeIncreaseQuotaPrivilege",
            )

            adv = ctypes.windll.advapi32
            kernel = ctypes.windll.kernel32

            h_token, token_src = self._open_session_token(int(session_id))
            self._last_helper_token_source = str(token_src or "")
            if not h_token:
                self._last_helper_fail_phase = "token"
                self._last_helper_fail_detail = str(token_src or "no_token")
                log(
                    f"[REMOTE-DESKTOP] no interactive token for session={session_id} "
                    f"({token_src})"
                )
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

            desk = (desktop or r"winsta0\default").strip() or r"winsta0\default"
            winlogon_desk = "winlogon" in desk.lower()
            si = STARTUPINFO()
            si.cb = ctypes.sizeof(STARTUPINFO)
            si.lpDesktop = desk
            pi = PROCESS_INFORMATION()
            CREATE_UNICODE_ENVIRONMENT = 0x00000400
            # Do NOT use CREATE_NO_WINDOW — DXGI/DWM need a real desktop process.
            # CREATE_UNICODE_ENVIRONMENT requires a non-NULL environment block;
            # passing None with that flag yields a broken helper env (black GDI).
            flags = 0
            env_block = None
            try:
                if not winlogon_desk:
                    CreateEnvironmentBlock = adv.CreateEnvironmentBlock
                    CreateEnvironmentBlock.argtypes = [
                        ctypes.POINTER(ctypes.c_void_p),
                        wintypes.HANDLE,
                        wintypes.BOOL,
                    ]
                    CreateEnvironmentBlock.restype = wintypes.BOOL
                    DestroyEnvironmentBlock = adv.DestroyEnvironmentBlock
                    DestroyEnvironmentBlock.argtypes = [ctypes.c_void_p]
                    DestroyEnvironmentBlock.restype = wintypes.BOOL
                    env_ptr = ctypes.c_void_p()
                    if CreateEnvironmentBlock(ctypes.byref(env_ptr), h_token, False):
                        env_block = env_ptr
                        flags |= CREATE_UNICODE_ENVIRONMENT
            except Exception:
                env_block = None
                flags = 0
            cmd_buf = ctypes.create_unicode_buffer(command)

            ok = adv.CreateProcessAsUserW(
                h_token,
                None,
                cmd_buf,
                None,
                None,
                False,
                flags,
                env_block.value if env_block else None,
                None,
                ctypes.byref(si),
                ctypes.byref(pi),
            )
            last_err = int(kernel.GetLastError() or 0)
            if env_block and env_block.value:
                try:
                    adv.DestroyEnvironmentBlock(env_block)
                except Exception:
                    pass
            kernel.CloseHandle(h_token)
            if not ok:
                self._last_helper_fail_phase = "create"
                self._last_helper_fail_detail = f"CreateProcessAsUser err={last_err}"
                log(
                    f"[REMOTE-DESKTOP] CreateProcessAsUser failed "
                    f"err={last_err} desktop={desk} token={token_src}"
                )
                return False
            log(
                f"[REMOTE-DESKTOP] CreateProcessAsUser ok session={session_id} "
                f"desktop={desk} token={token_src} pid={pi.dwProcessId}"
            )
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
            if self._jpeg_ws_primary():
                transports.append("webrtc")
            else:
                transports.insert(0, "webrtc")
        return {
            "input_protocols": [1, 2],
            "input_v2": True,
            "winlogon": True,
            "pre_logon": True,
            "preferred_transport": (
                "websocket" if self._jpeg_ws_primary() else "webrtc"
            ),
            "preferred_codec": "jpeg" if self._jpeg_ws_primary() else "h264",
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
                "needs_turn": True,
                "preferred_ice": "turns",
            },
            "smoothness": {
                "capture_fps": MEDIA_CAPTURE_FPS,
                "jpeg_fallback_fps": JPEG_FALLBACK_FPS_WHILE_NEGOTIATING,
                "max_width": DEFAULT_MAX_WIDTH,
                "target_bitrate_bps": TARGET_VIDEO_BITRATE_BPS,
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
        prev = self._transport
        ice = ""
        try:
            snap = self._media.status() if hasattr(self._media, "status") else {}
            if isinstance(snap, dict):
                ice = str(snap.get("ice_state") or "")
        except Exception:
            ice = ""
        self._media_session_id = ""
        # Peer fail must not tear down JPEG-WS (especially websocket-primary).
        self._media_mode_applied = False
        if self._transport == "webrtc":
            self._transport = "websocket" if self._ws_ok else "http"
        err_s = str(error or "")[:160]
        log(
            f"[REMOTE-DESKTOP] WebRTC peer failed — JPEG-WS continues: {err_s} "
            f"(prev={prev} ice={ice or '?'} primary={self._preferred_transport})"
        )
        try:
            if self._jpeg_ws_primary():
                self.emit_stream_progress(
                    "ws",
                    f"WebRTC optional failed; JPEG-WS continues ({err_s[:80]})",
                    force=True,
                )
            else:
                self.emit_stream_progress(
                    "webrtc",
                    f"WebRTC failed → JPEG-WS ({err_s[:80]})",
                    error="WEBRTC_FALLBACK",
                    force=True,
                )
        except Exception:
            pass
        try:
            self._sync_media_capture_mode()
        except Exception:
            pass

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
        has_ice_servers = "ice_servers" in (message or {})
        log(
            f"[REMOTE-DESKTOP] WebRTC signal action={action or '?'} "
            f"stream_match={bool(stream_id and stream_id == self._stream_id)} "
            f"has_session={bool(session_id)} ice_servers={has_ice_servers} "
            f"media_sid={'set' if self._media_session_id else 'empty'}"
        )
        proto = int(message.get("protocol") or 0)
        if proto != 1:
            if action in ("offer", "answer", "ice"):
                proto = 1
            else:
                log("[REMOTE-DESKTOP] WebRTC reject: unsupported signaling protocol")
                return {"accepted": False, "error": "unsupported signaling protocol"}
        if not self._running or not self._stream_id:
            log("[REMOTE-DESKTOP] WebRTC reject: stream not active")
            return {"accepted": False, "error": "stream not active"}
        if not stream_id or stream_id != self._stream_id:
            log("[REMOTE-DESKTOP] WebRTC reject: stale or mismatched stream_id")
            return {"accepted": False, "error": "stale or mismatched stream_id"}
        if not session_id:
            log("[REMOTE-DESKTOP] WebRTC reject: missing session_id")
            return {"accepted": False, "error": "missing session_id"}
        if self._media_session_id and session_id != self._media_session_id:
            log("[REMOTE-DESKTOP] WebRTC reject: mismatched media session_id")
            return {"accepted": False, "error": "stale or mismatched session_id"}
        if action not in ("offer", "answer", "ice"):
            log(f"[REMOTE-DESKTOP] WebRTC reject: unsupported action={action}")
            return {"accepted": False, "error": "unsupported signaling action"}
        if not self._media.capabilities().get("webrtc"):
            log("[REMOTE-DESKTOP] WebRTC reject: runtime unavailable")
            return {"accepted": False, "error": "webrtc runtime unavailable"}

        establishing = not self._media_session_id and action == "offer"
        if not self._media_session_id and not establishing:
            log("[REMOTE-DESKTOP] WebRTC reject: offer required before signal")
            return {"accepted": False, "error": "offer required before signal"}
        if establishing:
            self._media_session_id = session_id
            log(
                f"[REMOTE-DESKTOP] WebRTC offer accepted → establishing "
                f"session_id={session_id[:12]}…"
            )
        normalized = dict(message)
        normalized["action"] = action
        try:
            result = self._media.handle_signal(normalized)
        except Exception as exc:
            result = {"accepted": False, "error": str(exc)}
            log(f"[REMOTE-DESKTOP] WebRTC handle_signal raised: {exc}")
        if not result.get("accepted"):
            log(
                f"[REMOTE-DESKTOP] WebRTC signal not accepted "
                f"action={action} err={result.get('error') or result.get('reason')}"
            )
        if not result.get("accepted") and establishing:
            self._media_session_id = ""
        return result

    def _drain_out_q(self):
        with self._out_lock:
            self._pending_text.clear()
            self._pending_frame = None

    # ── WebSocket transport (single-thread send+recv) ─────────────

    def _ws_loop(self):
        """Dedicated WS thread: create_connection + drain outbound queue + recv input.

        Stays up for the agent lifetime (``ensure_agent_ws``) so cloud sees
        ``websocket:true`` even between streams.
        """
        while self._agent_ws_enabled and not self._ws_thread_stop.is_set():
            token = self.token_getter()
            if not token or not self.api_client:
                self._ws_thread_stop.wait(WS_RECONNECT_SEC)
                continue
            try:
                import websocket
            except ImportError:
                log("[REMOTE-DESKTOP] websocket-client missing — HTTP only")
                if self._running:
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
                if self._running:
                    self._enqueue_meta(force=True)
                    self.emit_stream_progress("ws", "Agent media WS up", force=True)
                    # Re-push last good frame so viewer is not blank while waiting
                    if (
                        not self._media_ready()
                        and self._last_good_jpeg
                        and self._last_good_wh[0] > 0
                        and self._frame_is_healthy()
                    ):
                        self._enqueue_ws_frame(
                            self._last_good_jpeg,
                            self._last_good_wh[0],
                            self._last_good_wh[1],
                            max(1, self._seq),
                        )
                self._last_ws_keepalive = time.time()
                log("[REMOTE-DESKTOP] WS connected (persistent agent channel)")

                ws.settimeout(0.15)
                while self._agent_ws_enabled and not self._ws_thread_stop.is_set():
                    # Drain outbound (meta + binary JPEG) on THIS thread
                    self._ws_flush_out(ws)
                    now = time.time()
                    if (
                        not self._running
                        and (now - float(self._last_ws_keepalive or 0.0))
                        >= WS_KEEPALIVE_SEC
                    ):
                        self._last_ws_keepalive = now
                        try:
                            ws.send(json.dumps({
                                "t": "ping",
                                "protocol": 2,
                                "role": "agent",
                            }, separators=(",", ":")))
                        except Exception:
                            break
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
                elif self._agent_ws_enabled:
                    self._transport = "idle"
                    self._stats["ws_reconnects"] += 1
                if ws is not None:
                    try:
                        ws.close()
                    except Exception:
                        pass
                log("[REMOTE-DESKTOP] WS closed (will reconnect if enabled)")
            if self._agent_ws_enabled and not self._ws_thread_stop.is_set():
                self._ws_thread_stop.wait(WS_RECONNECT_SEC)

    def _enqueue_meta(self, force: bool = False):
        if not force and self._seq % META_EVERY_N_FRAMES != 0:
            return
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
        media["jpeg_fallback_active"] = bool(
            self._jpeg_ws_primary() or not media_ready
        )
        media["jpeg_primary"] = bool(self._jpeg_ws_primary())
        media["healthy_frame"] = bool(self._frame_is_healthy())
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
            "capture_method": self._capture_method or "",
            "chrome_detected": bool(self._chrome_detected),
            "black_frame": bool(
                "+black" in (self._capture_method or "")
                or self._black_streak_started > 0
            ),
            "flat_frame": bool("+flat" in (self._capture_method or "")),
            "frame_variance": float(self._last_frame_variance or 0.0),
            "bright_ratio": float(self._last_frame_bright_ratio or 0.0),
            "logonui_hwnd_count": int(getattr(self, "_logonui_hwnd_count", 0) or 0),
            "desktop": self._desktop_name or "",
            "inputs_applied": int(self._stats.get("inputs_applied") or 0),
            "last_input_event": getattr(self, "_last_input_event", "") or "",
            "follow_console": bool(self._follow_console),
            "force_secure_desktop": bool(self._force_secure_desktop),
            "capture_diag": self._capture_diag_snapshot(),
        }
        self._q_put_text(json.dumps(meta))

    def _capture_diag_snapshot(self) -> dict:
        """Structured capture health for dashboard host comparison (Derin vs PASS)."""
        method = str(self._capture_method or "")
        env = {}
        try:
            from client_rd_winlogon import console_capture_env
            env = console_capture_env(int(self._target_session_id or 0))
        except Exception:
            env = {}
        media = {}
        try:
            media = dict(self._media.status() or {})
        except Exception:
            media = {}
        # Method tags are ground truth. Stale black/flat streaks must not mark
        # healthy printwindow-logonui as black (Ninety Live flicker).
        flat = bool("+flat" in method)
        black = bool("+black" in method)
        if self._flat_streak_started > 0 and (
            flat or not self._chrome_detected
        ):
            flat = True
        if self._black_streak_started > 0 and (
            black or not self._chrome_detected
        ):
            black = True
        frames_sent = int(self._stats.get("frames_sent") or 0)
        var_ok = float(self._last_frame_variance or 0.0) >= float(
            FLAT_VARIANCE_THRESHOLD
        )
        healthy = bool(
            not flat
            and not black
            and frames_sent > 0
            and (self._chrome_detected or var_ok)
        )
        # Healthy wire must not keep advertising probe no_frame to Capture health.
        if healthy:
            self._clear_stale_helper_fail()
        analysis = self._analyze_capture_faults(
            method=method,
            env=env if isinstance(env, dict) else {},
            flat=flat,
            black=black,
            media=media,
            healthy_pixels=healthy,
        )
        flat_sec = (
            max(0.0, time.time() - self._flat_streak_started)
            if self._flat_streak_started > 0
            else 0.0
        )
        black_sec = (
            max(0.0, time.time() - self._black_streak_started)
            if self._black_streak_started > 0
            else 0.0
        )
        try:
            from client_constants import VERSION as _VER
            agent_ver = str(_VER)
        except Exception:
            agent_ver = ""
        return {
            "desktop": str(self._desktop_name or ""),
            "capture_method": method,
            "winlogon_mode": bool(self._winlogon_mode),
            "helper_winlogon": bool(self._helper_spawned_winlogon),
            "helper_connected": bool(self._persistent_helper_connected()),
            "helper_token": str(self._last_helper_token_source or ""),
            "helper_fail_phase": str(self._last_helper_fail_phase or ""),
            "helper_fail_detail": str(self._last_helper_fail_detail or "")[:320],
            "session_id": int(self._target_session_id or 0),
            "username": str(self._target_username or ""),
            "black_frame": black,
            "flat_frame": flat,
            "frame_variance": float(self._last_frame_variance or 0.0),
            "bright_ratio": float(self._last_frame_bright_ratio or 0.0),
            "logonui_hwnd_count": int(getattr(self, "_logonui_hwnd_count", 0) or 0),
            "chrome_detected": bool(self._chrome_detected),
            "follow_console": bool(self._follow_console),
            "force_secure": bool(self._force_secure_desktop),
            "seq": int(self._seq or 0),
            "frames_sent": int(self._stats.get("frames_sent") or 0),
            "frames_failed": int(self._stats.get("frames_failed") or 0),
            "black_frames": int(self._stats.get("black_frames") or 0),
            "flat_frames": int(self._stats.get("flat_frames") or 0),
            "unhealthy_jpeg_bytes": int(self._last_unhealthy_jpeg_bytes or 0),
            "flat_streak_sec": round(float(flat_sec), 2),
            "black_streak_sec": round(float(black_sec), 2),
            "healthy": bool(healthy),
            "layer": analysis["layer"],
            "faults": analysis["faults"],
            "root_cause": analysis["root_cause"],
            "advice": analysis["advice"],
            "blame": analysis["blame"],
            "agent_version": agent_ver,
            "preferred_transport": str(self._preferred_transport or ""),
            "transport": str(self._transport or ""),
            "ws_ok": bool(self._ws_ok),
            "prefer_dxgi": bool(self._prefer_dxgi),
            "use_user_helper": bool(self._use_user_helper),
            "in_session_helper": bool(self._in_session_helper),
            "desktop_attached": bool(self._desktop_attached),
            "desktop_attach_tid": int(self._desktop_attach_tid or 0) or None,
            "healthy_frame": bool(healthy),
            "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "updated_mono": round(time.monotonic(), 3),
            "recovery_steps": list(
                getattr(self, "_capture_recovery_steps", []) or []
            )[-12:],
            "hwnd_classes": list(getattr(self, "_last_hwnd_classes", []) or [])[:12],
            "local_dump_path": str(getattr(self, "_last_diag_dump_path", "") or ""),
            "error": str(getattr(self, "_last_stream_error", "") or ""),
            "media": {
                "available": bool(media.get("available")),
                "active": bool(media.get("active")),
                "connection_state": str(media.get("connection_state") or ""),
                "ice_state": str(media.get("ice_state") or ""),
                "error": str(media.get("error") or "")[:200],
                "jpeg_fallback_active": bool(media.get("jpeg_fallback_active", True)),
            },
            "env": env,
        }

    def _analyze_capture_faults(
        self,
        *,
        method: str,
        env: dict,
        flat: bool,
        black: bool,
        media: dict,
        healthy_pixels: bool = False,
    ) -> dict:
        """Classify unhealthy Live so cloud can separate client vs cloud blame."""
        faults: list = []
        helper_ok = bool(self._persistent_helper_connected())
        phase = str(self._last_helper_fail_phase or "")
        logonui = bool(env.get("logonui"))
        hwnd = int(getattr(self, "_logonui_hwnd_count", 0) or 0)
        frames_sent = int(self._stats.get("frames_sent") or 0)
        pixel_ok = bool(
            healthy_pixels
            or (
                not flat
                and not black
                and (
                    self._chrome_detected
                    or float(self._last_frame_variance or 0.0)
                    >= float(FLAT_VARIANCE_THRESHOLD)
                )
                and frames_sent > 0
            )
        )

        if phase in ("spawn", "accept", "token", "create"):
            faults.append(f"HELPER_{phase.upper()}")
        # Stale no_frame after healthy PrintWindow must not stay as a fault.
        if phase == "no_frame" and not pixel_ok:
            faults.append("HELPER_NO_FRAME")
        if self._use_user_helper and not helper_ok and not phase and not pixel_ok:
            faults.append("HELPER_DISCONNECTED")
        if black:
            faults.append("PIXEL_BLACK")
        if flat:
            faults.append("PIXEL_FLAT")
        if flat and (logonui or hwnd > 0):
            faults.append("LOGONUI_PRESENT_BUT_FLAT")
        if helper_ok and (flat or black) and not self._chrome_detected:
            faults.append("HELPER_CONNECTED_NO_CHROME")
        if (
            self._winlogon_mode
            and (flat or black)
            and not bool(self._desktop_attached)
            and not self._in_session_helper
        ):
            # Parent flag — helper may still be attached; see desktop_attached after sync.
            faults.append("DESKTOP_ATTACH_FALSE")
        if frames_sent <= 0 and self._running and (flat or black):
            faults.append("NO_HEALTHY_FRAMES_ON_WIRE")
        if bool(env.get("headless_hint")):
            faults.append("HEADLESS_OR_ZERO_SCREEN")
        if (
            str(env.get("resolve_mode") or "") == "default"
            and self._winlogon_mode
            and not self._force_secure_desktop
        ):
            faults.append("RESOLVE_DEFAULT_BUT_WINLOGON_MODE")
        if (
            str(env.get("resolve_mode") or "") == "winlogon"
            and not self._winlogon_mode
            and str(self._desktop_name or "").lower() == "default"
        ):
            faults.append("RESOLVE_WINLOGON_BUT_DEFAULT_CAPTURE")
        media_err = str(media.get("error") or "")
        # JPEG-WS primary + healthy pixels: WebRTC peer noise must not own FAIL.
        if media_err and not (self._jpeg_ws_primary() and pixel_ok):
            faults.append("WEBRTC_PEER_ERROR")
        if not self._ws_ok and self._running:
            faults.append("AGENT_WS_DOWN")

        # Primary root cause (client system layer first — matches Derin lab).
        if pixel_ok and not any(
            f.startswith("HELPER_") and f != "HELPER_NO_FRAME" for f in faults
        ) and not black and not flat and "AGENT_WS_DOWN" not in faults:
            layer = "ok"
            root = ""
            advice = ""
            blame = "none"
        elif "HELPER_SPAWN" in " ".join(faults) or "HELPER_ACCEPT" in " ".join(faults) or "HELPER_TOKEN" in " ".join(faults) or "HELPER_CREATE" in " ".join(faults):
            layer = "client_helper"
            root = (
                f"Session helper failed phase={phase or '?'} "
                f"detail={str(self._last_helper_fail_detail or '')[:160]}"
            )
            advice = "Check SYSTEM privileges, WTS token, CreateProcessAsUser, lpDesktop=winsta0\\Winlogon"
            blame = "client"
        elif "LOGONUI_PRESENT_BUT_FLAT" in faults or (
            flat and self._winlogon_mode and helper_ok
        ):
            layer = "client_capture"
            root = (
                "Winlogon/LogonUI is present but capture pixels are a solid fill "
                f"(method={method or '?'}, var={float(self._last_frame_variance or 0):.1f}, "
                f"hwnd={hwnd}, token={self._last_helper_token_source or '?'}). "
                "GDI/BitBlt (or helper GDI) is not painting LogonUI chrome."
            )
            advice = (
                "Client capture stack: reattach Winlogon desktop, PrintWindow LogonUI, "
                "or DXGI on correct input desktop — not a Cloudflare/viewer issue"
            )
            blame = "client"
        elif black and helper_ok:
            layer = "client_capture"
            root = (
                f"Helper connected but frames are black (method={method or '?'} "
                f"token={self._last_helper_token_source or '?'})"
            )
            advice = "Wrong desktop bind or Session-0 GDI; force Winlogon helper + input desktop"
            blame = "client"
        elif black or flat:
            layer = "client_capture"
            root = f"Unhealthy pixels method={method or '?'} flat={flat} black={black}"
            advice = "Inspect desktop attach and capture path on the agent host"
            blame = "client"
        elif "HELPER_NO_FRAME" in faults:
            layer = "client_helper"
            root = (
                f"Helper produced no JPEG (phase=no_frame "
                f"detail={str(self._last_helper_fail_detail or '')[:160]})"
            )
            advice = "Inspect helper capture on the target desktop; pull rd_capture_diag dump"
            blame = "client"
        elif "AGENT_WS_DOWN" in faults:
            layer = "agent_ws"
            root = "Agent remote WS is down; JPEG-WS cannot reach the viewer"
            advice = "Check agent outbound wss://asteria.run connectivity"
            blame = "network_or_cloud"
        elif "WEBRTC_PEER_ERROR" in faults and self._jpeg_ws_primary():
            layer = "webrtc"
            root = f"WebRTC peer error (non-fatal with websocket-primary): {media_err[:160]}"
            advice = "Ignore for Live if JPEG-WS healthy; fix TURN/ICE only for WebRTC upgrade"
            blame = "webrtc_optional"
        else:
            layer = "ok" if self._chrome_detected else "unknown"
            root = ""
            advice = ""
            blame = "none" if layer == "ok" else "client"

        return {
            "layer": layer,
            "faults": faults,
            "root_cause": root[:480],
            "advice": advice[:320],
            "blame": blame,
        }

    def _maybe_emit_unhealthy_diag(
        self,
        *,
        reason: str,
        detail: str = "",
        force: bool = False,
        jpeg_len: int = 0,
    ) -> None:
        """Push full fault taxonomy to cloud while Live is degraded."""
        if jpeg_len > 0:
            self._last_unhealthy_jpeg_bytes = int(jpeg_len)
        now = time.monotonic()
        if not force and (now - float(self._last_diag_emit_mono or 0.0)) < 2.0:
            return
        snap = self._capture_diag_snapshot()
        if snap.get("healthy") and not force:
            return
        self._last_diag_emit_mono = now
        self._last_diag_was_healthy = False
        # Keep helper_fail_detail informative for Capture health banner.
        if not self._last_helper_fail_detail and snap.get("root_cause"):
            self._last_helper_fail_detail = str(snap.get("root_cause") or "")[:240]
        self._enqueue_capture_diag(
            phase="degraded" if not snap.get("healthy") else "live",
            reason=str(reason or "unhealthy"),
            detail=str(detail or snap.get("root_cause") or "")[:320],
        )

    def _enqueue_capture_diag(
        self,
        *,
        phase: str = "",
        reason: str = "",
        detail: str = "",
    ) -> None:
        """Emit ``t:capture_diag`` so cloud can show Capture health without SSH."""
        try:
            snap = self._capture_diag_snapshot()
            payload = {
                "t": "capture_diag",
                "protocol": 2,
                "stream_id": self._stream_id,
                "phase": str(phase or ""),
                "reason": str(reason or ""),
                "detail": str(detail or "")[:320],
                **snap,
            }
            self._q_put_text(json.dumps(payload))
            log(
                f"[REMOTE-DESKTOP] capture_diag phase={phase} reason={reason} "
                f"blame={payload.get('blame')} layer={payload.get('layer')} "
                f"faults={payload.get('faults')} "
                f"desk={payload.get('desktop')} method={payload.get('capture_method')} "
                f"token={payload.get('helper_token')} var={payload.get('frame_variance')} "
                f"root={str(payload.get('root_cause') or '')[:120]}"
            )
        except Exception as exc:
            log(f"[REMOTE-DESKTOP] capture_diag emit failed: {exc}")

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
                elif self._pending_frame is not None and self._should_send_jpeg_ws():
                    frame = self._pending_frame
                    self._pending_frame = None
                elif self._pending_frame is not None:
                    # WebRTC-primary owns video. Drop stale JPEG rather than
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


def capture_once_to_file(
    path: str,
    max_width: int = DEFAULT_MAX_WIDTH,
    quality: int = DEFAULT_QUALITY,
    *,
    winlogon: bool = False,
) -> bool:
    """CLI helper: grab desktop JPEG to path (runs in interactive session)."""
    import os
    rd = RemoteDesktopStreamer()
    rd._max_width = max_width
    rd._quality = quality
    rd._winlogon_mode = bool(winlogon)
    jpeg, w, h = rd._grab_jpeg()
    if not jpeg or w <= 0 or h <= 0 or len(jpeg) < MIN_JPEG_BYTES:
        log(f"[REMOTE-DESKTOP] capture_once failed — {w}x{h} bytes={0 if not jpeg else len(jpeg)}")
        return False
    if "+black" in (rd._capture_method or "") or "+flat" in (rd._capture_method or ""):
        log(
            f"[REMOTE-DESKTOP] capture_once "
            f"{'flat' if '+flat' in (rd._capture_method or '') else 'nearly-black'} "
            "— refuse write"
        )
        return False
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(jpeg)
    log(
        f"[REMOTE-DESKTOP] capture_once wrote {path} ({w}x{h} {len(jpeg)}B "
        f"method={rd._capture_method} winlogon={winlogon})"
    )
    return True
