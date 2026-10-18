"""Phase 4 HW sidecar supervisor (C-RD-HW-SUP).

Spawns asteria-encode.exe --agent, speaks JSON-lines, falls back to JPEG on failure.
Feature-gated: only used when stream params request webrtc_hw / auto and the binary exists.
"""
from __future__ import annotations

import json
import logging
import os
import queue
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

log = logging.getLogger("asteria.rd_hw")

JsonHandler = Callable[[dict], None]


def sidecar_path() -> Optional[Path]:
    """Resolve asteria-encode.exe next to the agent / in sidecar/ build tree."""
    candidates: List[Path] = []
    if getattr(sys, "frozen", False):
        candidates.append(Path(sys.executable).resolve().parent / "asteria-encode.exe")
        candidates.append(Path(sys.executable).resolve().parent / "bin" / "asteria-encode.exe")
    here = Path(__file__).resolve().parent
    candidates.extend(
        [
            here / "asteria-encode.exe",
            here / "bin" / "asteria-encode.exe",
            here / "sidecar" / "asteria-encode" / "target" / "x86_64-pc-windows-gnullvm" / "release" / "asteria-encode.exe",
            here / "sidecar" / "asteria-encode" / "target" / "release" / "asteria-encode.exe",
        ]
    )
    env = os.environ.get("ASTERIA_ENCODE")
    if env:
        candidates.insert(0, Path(env))
    for p in candidates:
        if p.is_file():
            return p
    return None


def selftest(timeout: float = 15.0) -> Dict[str, Any]:
    p = sidecar_path()
    if not p:
        return {"available": False, "reason": "binary_missing"}
    try:
        r = subprocess.run(
            [str(p), "--selftest"],
            capture_output=True,
            text=True,
            timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        line = (r.stdout or "").strip().splitlines()[-1] if r.stdout else ""
        data = json.loads(line) if line.startswith("{") else {"raw": line}
        data["available"] = r.returncode == 0
        data["path"] = str(p)
        data["exit"] = r.returncode
        return data
    except Exception as e:
        return {"available": False, "reason": str(e), "path": str(p)}


class HwSidecar:
    """One streaming session backed by asteria-encode --agent."""

    def __init__(self, on_msg: JsonHandler):
        self._on_msg = on_msg
        self._proc: Optional[subprocess.Popen] = None
        self._lock = threading.Lock()
        self._alive = False
        self._last_stats_at = 0.0
        self._reader: Optional[threading.Thread] = None
        self._path = sidecar_path()
        self.fallback_reason: Optional[str] = None

    @property
    def available(self) -> bool:
        return self._path is not None and self._path.is_file()

    def start(
        self,
        *,
        fps: int = 60,
        bitrate: int = 3_000_000,
        monitor: int = 0,
        session_id: Optional[int] = None,
        notify_user: bool = False,
        ice_servers: Optional[list] = None,
    ) -> bool:
        if not self._path:
            self.fallback_reason = "binary_missing"
            return False
        with self._lock:
            self.stop_locked("restart")
            try:
                self._proc = subprocess.Popen(
                    [str(self._path), "--agent"],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    bufsize=0,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
            except Exception as e:
                self.fallback_reason = f"spawn:{e}"
                return False
            self._alive = True
            self._reader = threading.Thread(target=self._read_loop, name="ae-stdout", daemon=True)
            self._reader.start()
            threading.Thread(target=self._read_stderr, name="ae-stderr", daemon=True).start()
            ok = self._send(
                {
                    "t": "start",
                    "fps": int(fps),
                    "bitrate": int(bitrate),
                    "monitor": int(monitor),
                    "session_id": session_id,
                    "notify_user": bool(notify_user),
                    "ice_servers": ice_servers or [],
                }
            )
            if not ok:
                self.fallback_reason = "stdin_failed"
                self.stop_locked("stdin_failed")
                return False
            return True

    def stop(self, reason: str = "user") -> None:
        with self._lock:
            self.stop_locked(reason)

    def stop_locked(self, reason: str) -> None:
        self._alive = False
        proc = self._proc
        self._proc = None
        if not proc:
            return
        try:
            if proc.stdin:
                proc.stdin.write((json.dumps({"t": "stop", "reason": reason}) + "\n").encode("utf-8"))
                proc.stdin.flush()
        except Exception:
            pass
        try:
            proc.wait(timeout=2)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass

    def send_answer(self, sdp: str) -> None:
        self._send({"t": "answer", "sdp": sdp})

    def send_ice(self, candidate: str, sdp_mid: Any = None, sdp_mline_index: Any = None) -> None:
        self._send(
            {
                "t": "ice",
                "candidate": candidate,
                "sdpMid": sdp_mid,
                "sdpMLineIndex": sdp_mline_index,
            }
        )

    def request_keyframe(self) -> None:
        self._send({"t": "kf"})

    def healthy(self, max_silence: float = 5.0) -> bool:
        if not self._alive or not self._proc or self._proc.poll() is not None:
            return False
        if self._last_stats_at and (time.time() - self._last_stats_at) > max_silence:
            return False
        return True

    def _send(self, obj: dict) -> bool:
        proc = self._proc
        if not proc or not proc.stdin:
            return False
        try:
            proc.stdin.write((json.dumps(obj, separators=(",", ":")) + "\n").encode("utf-8"))
            proc.stdin.flush()
            return True
        except Exception as e:
            log.warning("sidecar stdin write failed: %s", e)
            return False

    def _read_loop(self) -> None:
        proc = self._proc
        if not proc or not proc.stdout:
            return
        try:
            for raw in iter(proc.stdout.readline, b""):
                if not raw:
                    break
                try:
                    msg = json.loads(raw.decode("utf-8", errors="replace").strip())
                except Exception:
                    continue
                if msg.get("t") == "stats":
                    self._last_stats_at = time.time()
                try:
                    self._on_msg(msg)
                except Exception:
                    log.exception("sidecar on_msg")
        finally:
            self._alive = False
            try:
                self._on_msg({"t": "sidecar_exit", "code": proc.poll()})
            except Exception:
                pass

    def _read_stderr(self) -> None:
        proc = self._proc
        if not proc or not proc.stderr:
            return
        for raw in iter(proc.stderr.readline, b""):
            if not raw:
                break
            log.debug("ae: %s", raw.decode("utf-8", errors="replace").rstrip())


def caps_from_selftest() -> Dict[str, Any]:
    st = selftest()
    if not st.get("available"):
        return {"webrtc_hw": False, "reason": st.get("reason") or st.get("raw")}
    return {
        "webrtc_hw": True,
        "encoders": st.get("encoders") or [],
        "outputs": len(st.get("outputs") or []),
        "path": st.get("path"),
    }
