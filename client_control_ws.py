#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Agent control WebSocket — dashboard command push channel.

  wss://host/ws/agent/control  + Authorization: Bearer <token>

Separate from Remote Desktop (/ws/remote/agent).
HTTP GET /api/commands/pending remains the fallback while WS is down.
"""

from __future__ import annotations

import json
import os
import random
import socket
import threading
import time
from datetime import datetime, timezone
from typing import Callable, Optional
from urllib.parse import urlencode

from client_helpers import log

PROTOCOL_V = 1
PING_INTERVAL_SEC = 25.0
RECV_TIMEOUT_SEC = 0.5
RECONNECT_MIN = 1.0
RECONNECT_MAX = 30.0
# Cloud idle_timeout ≈ 90s — force reconnect before dashboard goes gray on a zombie TCP.
STALE_RX_SEC = 75.0


def api_base_to_control_ws_url(api_base: str, token: str = "") -> str:
    """https://host/api → wss://host/ws/agent/control"""
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
    url = f"{ws}/ws/agent/control"
    try:
        from client_security_utils import use_legacy_token_query
        if token and use_legacy_token_query():
            return f"{url}?{urlencode({'token': token})}"
    except Exception:
        pass
    return url


class AgentControlWebSocket:
    """Persistent control channel for push commands (daemon only)."""

    def __init__(
        self,
        api_client=None,
        token_getter: Optional[Callable[[], str]] = None,
        on_command: Optional[Callable[[dict], None]] = None,
        on_config_hint: Optional[Callable[[dict], None]] = None,
        on_threat_intel_updated: Optional[Callable[[dict], None]] = None,
        on_threat_config_updated: Optional[Callable[[dict], None]] = None,
        on_connected: Optional[Callable[[], None]] = None,
    ):
        self.api_client = api_client
        self.token_getter = token_getter or (lambda: "")
        self.on_command = on_command
        self.on_config_hint = on_config_hint
        self.on_threat_intel_updated = on_threat_intel_updated
        self.on_threat_config_updated = on_threat_config_updated
        self.on_connected = on_connected

        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._ws = None
        self._ws_lock = threading.Lock()
        self._connected = False
        self._connected_since = 0.0
        self._last_rx = 0.0
        self._backoff = RECONNECT_MIN
        self._poll_fallback_sec = 5.0
        self._stats = {
            "connects": 0,
            "disconnects": 0,
            "commands_pushed": 0,
            "results_sent": 0,
            "send_errors": 0,
            "threat_intel_pushes": 0,
        }

    @property
    def connected(self) -> bool:
        return bool(self._connected and self._ws is not None)

    def poll_interval_hint(self) -> Optional[float]:
        """When WS healthy, recommend slower HTTP poll (safety net)."""
        if self.connected and (time.time() - self._connected_since) > 5.0:
            return float(self._poll_fallback_sec)
        return None

    def get_stats(self) -> dict:
        st = dict(self._stats)
        st["connected"] = self.connected
        st["poll_fallback_sec"] = self._poll_fallback_sec
        return st

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._loop,
            name="AgentControl-WS",
            daemon=True,
        )
        self._thread.start()
        log("[CONTROL-WS] starting (wss …/ws/agent/control)")

    def stop(self, *, goodbye_reason: Optional[str] = None):
        if goodbye_reason:
            try:
                self.send_goodbye(goodbye_reason)
            except Exception:
                pass
        self._running = False
        self._connected = False
        with self._ws_lock:
            ws = self._ws
            self._ws = None
        if ws is not None:
            try:
                ws.close()
            except Exception:
                pass
        log("[CONTROL-WS] stopped")

    def send_json(self, payload: dict) -> bool:
        if not self.connected:
            return False
        try:
            raw = json.dumps(payload, ensure_ascii=False, default=str)
        except Exception:
            return False
        with self._ws_lock:
            ws = self._ws
            if ws is None:
                return False
            try:
                ws.send(raw)
                return True
            except Exception as e:
                self._stats["send_errors"] += 1
                log(f"[CONTROL-WS] send error: {e}")
                return False

    def send_ack(self, command_id: str, state: str = "received") -> bool:
        return self.send_json({
            "v": PROTOCOL_V,
            "t": "ack",
            "command_id": command_id,
            "state": state,
            "ts": datetime.now(timezone.utc).isoformat(),
        })

    def send_presence(self, state: str, reason: str = "") -> bool:
        """Contract api/11-presence-realtime.md — sleep/wake/offline pulse."""
        payload = {
            "v": PROTOCOL_V,
            "t": "presence",
            "state": str(state or "").strip().lower(),
            "ts": datetime.now(timezone.utc).isoformat(),
        }
        if reason:
            payload["reason"] = str(reason).strip().lower()
        ok = self.send_json(payload)
        if ok:
            self._stats["presence_sent"] = int(self._stats.get("presence_sent") or 0) + 1
        return ok

    def send_goodbye(self, reason: str = "shutdown") -> bool:
        """Planned stop — cloud marks offline immediately (no 12s debounce)."""
        ok = self.send_json({
            "v": PROTOCOL_V,
            "t": "goodbye",
            "reason": str(reason or "shutdown").strip().lower(),
            "ts": datetime.now(timezone.utc).isoformat(),
        })
        if ok:
            self._stats["goodbye_sent"] = int(self._stats.get("goodbye_sent") or 0) + 1
            try:
                time.sleep(0.05)
            except Exception:
                pass
        return ok

    def request_reconnect(self) -> None:
        """Force socket close so the loop reconnects (post-sleep zombie TCP)."""
        with self._ws_lock:
            ws = self._ws
            self._ws = None
        self._connected = False
        if ws is not None:
            try:
                ws.close()
            except Exception:
                pass
        log("[CONTROL-WS] reconnect requested")

    def send_command_result(
        self,
        *,
        command_id: str,
        command_type: str,
        status: str,
        result: dict,
        executed_at: str = "",
        signature: str = "",
    ) -> bool:
        payload = {
            "v": PROTOCOL_V,
            "t": "command_result",
            "command_id": command_id,
            "command_type": command_type,
            "status": status,
            "result": result or {},
            "executed_at": executed_at or datetime.now(timezone.utc).isoformat(),
        }
        if signature:
            payload["signature"] = signature
        ok = self.send_json(payload)
        if ok:
            self._stats["results_sent"] += 1
        return ok

    def _loop(self):
        while self._running:
            token = (self.token_getter() or "").strip()
            api_base = ""
            if self.api_client is not None:
                api_base = getattr(self.api_client, "base_url", "") or ""
            if not token or not api_base:
                time.sleep(2.0)
                continue

            try:
                import websocket
            except ImportError:
                # Never exit the worker permanently — HTTP poll remains primary
                # until the package is available again (contract: reconnect forever).
                log("[CONTROL-WS] websocket-client missing — HTTP poll only; retry in 60s")
                time.sleep(60.0)
                continue

            url = api_base_to_control_ws_url(api_base, token)
            log(f"[CONTROL-WS] connecting… {url.split('?')[0]}")

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

                ws = websocket.create_connection(
                    url,
                    timeout=15,
                    sslopt=sslopt,
                    enable_multithread=True,
                    header=[f"Authorization: Bearer {token}"],
                )
                with self._ws_lock:
                    self._ws = ws
                self._connected = True
                self._connected_since = time.time()
                self._last_rx = time.time()
                self._backoff = RECONNECT_MIN
                self._stats["connects"] += 1

                hello = {
                    "v": PROTOCOL_V,
                    "t": "hello",
                    "role": "agent",
                    "version": self._version(),
                    "hostname": socket.gethostname(),
                    "pid": os.getpid(),
                    "mode": "daemon",
                    "ts": datetime.now(timezone.utc).isoformat(),
                }
                # ZT-601: truthful envelope-v2 capability (off unless configured
                # to observe). Never advertises enforce; design gate not promoted.
                try:
                    from client_command_envelope import capability as _env_cap
                    hello["caps"] = {"command_envelope_v2": _env_cap()}
                except Exception:
                    hello["caps"] = {"command_envelope_v2": "off"}
                ws.send(json.dumps(hello))
                log("[CONTROL-WS] connected + hello sent")
                # OOB-501 (contract 1.4.7): drain after control WS, same as heartbeat.
                try:
                    if callable(self.on_connected):
                        self.on_connected()
                except Exception as exc:
                    log(f"[CONTROL-WS] on_connected hook error: {exc}")
                try:
                    from client_presence import on_control_ws_connected
                    on_control_ws_connected()
                except Exception:
                    pass

                ws.settimeout(RECV_TIMEOUT_SEC)
                last_ping = time.time()
                while self._running and self._connected:
                    now = time.time()
                    if self._last_rx and (now - self._last_rx) >= STALE_RX_SEC:
                        log(
                            f"[CONTROL-WS] stale RX {now - self._last_rx:.0f}s "
                            f"(>{STALE_RX_SEC:.0f}s) — forcing reconnect"
                        )
                        self._stats["stale_reconnects"] = int(
                            self._stats.get("stale_reconnects") or 0
                        ) + 1
                        break
                    if now - last_ping >= PING_INTERVAL_SEC:
                        ping_ok = self.send_json({
                            "v": PROTOCOL_V,
                            "t": "ping",
                            "ts": datetime.now(timezone.utc).isoformat(),
                        })
                        if not ping_ok:
                            log("[CONTROL-WS] ping send failed — reconnecting")
                            break
                        last_ping = now
                    try:
                        msg = ws.recv()
                        if msg is None:
                            break
                        if isinstance(msg, bytes):
                            # Control channel is text-only; ignore binary
                            continue
                        self._last_rx = time.time()
                        self._on_message(msg)
                    except websocket.WebSocketTimeoutException:
                        continue
                    except Exception as e:
                        log(f"[CONTROL-WS] recv error: {e}")
                        break
            except Exception as e:
                log(f"[CONTROL-WS] connect/session error: {e}")
            finally:
                was = self._connected
                self._connected = False
                with self._ws_lock:
                    if self._ws is ws:
                        self._ws = None
                if ws is not None:
                    try:
                        ws.close()
                    except Exception:
                        pass
                if was:
                    self._stats["disconnects"] += 1
                    log("[CONTROL-WS] disconnected")

            if not self._running:
                break
            sleep_for = self._backoff + random.uniform(0, 0.5)
            log(f"[CONTROL-WS] reconnect in {sleep_for:.1f}s")
            time.sleep(sleep_for)
            self._backoff = min(RECONNECT_MAX, self._backoff * 2.0)

    def _on_message(self, raw: str):
        try:
            data = json.loads(raw)
        except Exception:
            return
        if not isinstance(data, dict):
            return
        t = str(data.get("t") or "").strip().lower()
        if t == "ping":
            self.send_json({
                "v": PROTOCOL_V,
                "t": "pong",
                "ts": datetime.now(timezone.utc).isoformat(),
            })
            return
        if t == "pong":
            # Successful cloud pong refreshes last_seen — count for diagnostics.
            self._stats["pongs"] = int(self._stats.get("pongs") or 0) + 1
            return
        if t == "presence_ack":
            log(
                f"[CONTROL-WS] presence_ack accepted={data.get('accepted')} "
                f"presence={data.get('presence')}"
            )
            return
        if t in ("hello", "hello_ack"):
            # Contract accepts hello_ack or hello as session confirm.
            log(
                f"[CONTROL-WS] {t} protocol={data.get('protocol')} "
                f"presence={((data.get('server') or {}) if isinstance(data.get('server'), dict) else {}).get('presence')}"
            )
            return
        if t == "config_hint":
            try:
                sec = data.get("poll_fallback_sec")
                if sec is not None:
                    self._poll_fallback_sec = max(5.0, float(sec))
            except Exception:
                pass
            if self.on_config_hint:
                try:
                    self.on_config_hint(data)
                except Exception:
                    pass
            return
        if t == "threat_intel_updated":
            # Contract api/09-threat-intel.md — push → immediate GET sync
            self._stats["threat_intel_pushes"] = int(
                self._stats.get("threat_intel_pushes") or 0
            ) + 1
            ver = data.get("bundle_version") or data.get("version") or ""
            log(f"[CONTROL-WS] ← threat_intel_updated bundle={ver}")
            cb = self.on_threat_intel_updated
            if cb:
                try:
                    cb(data)
                except Exception as e:
                    log(f"[CONTROL-WS] threat_intel_updated handler error: {e}")
            return
        if t == "threat_config_updated":
            # A settings change must reach the daemon immediately; HTTP polling
            # remains the fallback if this push is missed.
            log("[CONTROL-WS] ← threat_config_updated")
            cb = self.on_threat_config_updated
            if cb:
                try:
                    cb(data)
                except Exception as e:
                    log(f"[CONTROL-WS] threat_config_updated handler error: {e}")
            return
        if t == "command":
            cmd = data.get("command")
            if not isinstance(cmd, dict):
                # Allow flat command fields on envelope
                cmd = {k: v for k, v in data.items() if k not in ("v", "t", "id", "ts")}
            if not cmd.get("command_type") and not cmd.get("type"):
                return
            # Normalize type field
            if "command_type" not in cmd and cmd.get("type"):
                cmd["command_type"] = cmd.get("type")
            if "command_id" not in cmd and cmd.get("id"):
                cmd["command_id"] = cmd.get("id")
            self._stats["commands_pushed"] += 1
            cid = cmd.get("command_id", "?")
            ctype = cmd.get("command_type", "?")
            log(f"[CONTROL-WS] ← command {ctype} id={cid}")
            if self.on_command:
                try:
                    self.on_command(cmd)
                except Exception as e:
                    log(f"[CONTROL-WS] on_command error: {e}")
            return

    @staticmethod
    def _version() -> str:
        try:
            from client_constants import VERSION
            return str(VERSION)
        except Exception:
            return ""
