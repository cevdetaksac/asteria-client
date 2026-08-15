# -*- coding: utf-8 -*-
"""WebRTC H.264 encoder selection — prefer NVENC/QSV/AMF, else x264 zerolatency.

Patches aiortc's H264Encoder._encode_frame once per process so peer connections
use hardware encode when FFmpeg exposes the codec (WebRTC build).
"""

from __future__ import annotations

import fractions
import threading
from typing import Optional, Tuple

_lock = threading.Lock()
_patched = False
_encoder_ffmpeg = "libx264"
_encoder_label = "x264"
_probe_done = False


def _probe_codecs() -> Tuple[str, str]:
    """Return (ffmpeg_codec_name, short_label)."""
    try:
        import av  # type: ignore
    except Exception:
        return "libx264", "x264"
    candidates = (
        ("h264_nvenc", "nvenc"),
        ("h264_qsv", "qsv"),
        ("h264_amf", "amf"),
        ("libx264", "x264"),
    )
    for name, label in candidates:
        try:
            av.Codec(name, "w")
            return name, label
        except Exception:
            continue
    return "libx264", "x264"


def encoder_info() -> dict:
    global _probe_done, _encoder_ffmpeg, _encoder_label
    with _lock:
        if not _probe_done:
            _encoder_ffmpeg, _encoder_label = _probe_codecs()
            _probe_done = True
        return {
            "ffmpeg": _encoder_ffmpeg,
            "label": _encoder_label,
        }


def _codec_options(ffmpeg_name: str) -> dict:
    if ffmpeg_name == "libx264":
        return {
            "preset": "ultrafast",
            "tune": "zerolatency",
            "profile": "baseline",
            "level": "31",
        }
    if ffmpeg_name == "h264_nvenc":
        return {
            "preset": "p1",
            "tune": "ll",
            "zerolatency": "1",
            "delay": "0",
            "rc": "cbr",
        }
    if ffmpeg_name == "h264_qsv":
        return {
            "look_ahead": "0",
            "async_depth": "1",
        }
    if ffmpeg_name == "h264_amf":
        return {
            "usage": "ultralowlatency",
            "quality": "speed",
        }
    return {"tune": "zerolatency"}


def ensure_aiortc_h264_patched() -> str:
    """Monkey-patch aiortc H264Encoder for HW / zerolatency. Returns label."""
    global _patched, _encoder_ffmpeg, _encoder_label, _probe_done
    # Probe outside the patch lock — encoder_info() also takes _lock (non-reentrant).
    info = encoder_info()
    with _lock:
        if _patched:
            return info["label"]
        try:
            import av  # type: ignore
            import aiortc.codecs.h264 as h264_mod  # type: ignore
        except Exception:
            return info["label"]

        ffmpeg_name = info["ffmpeg"]
        label = info["label"]
        options = _codec_options(ffmpeg_name)
        max_rate = 60

        def _encode_frame(self, frame, force_keyframe: bool):
            if int(getattr(self, "target_bitrate", 0) or 0) < 8_000_000:
                self.target_bitrate = 12_000_000
            if self.codec and (
                frame.width != self.codec.width
                or frame.height != self.codec.height
                or abs(self.target_bitrate - self.codec.bit_rate) / max(
                    self.codec.bit_rate, 1
                )
                > 0.1
            ):
                self.buffer_data = b""
                self.buffer_pts = None
                self.codec = None

            if force_keyframe:
                frame.pict_type = av.video.frame.PictureType.I
            else:
                frame.pict_type = av.video.frame.PictureType.NONE

            if self.codec is None:
                try:
                    self.codec = av.CodecContext.create(ffmpeg_name, "w")
                except Exception:
                    self.codec = av.CodecContext.create("libx264", "w")
                    options_local = _codec_options("libx264")
                else:
                    options_local = options
                self.codec.width = frame.width
                self.codec.height = frame.height
                self.codec.bit_rate = self.target_bitrate
                self.codec.pix_fmt = "yuv420p"
                self.codec.framerate = fractions.Fraction(max_rate, 1)
                self.codec.time_base = fractions.Fraction(1, max_rate)
                try:
                    self.codec.options = dict(options_local)
                except Exception:
                    pass
                try:
                    self.codec.profile = "Baseline"
                except Exception:
                    pass

            data_to_send = b""
            for package in self.codec.encode(frame):
                data_to_send += bytes(package)
            if data_to_send:
                yield from self._split_bitstream(data_to_send)

        h264_mod.H264Encoder._encode_frame = _encode_frame
        _patched = True
        _encoder_ffmpeg = ffmpeg_name
        _encoder_label = label
        return label
