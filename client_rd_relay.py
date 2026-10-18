"""Embedded remote desktop (C-RD-PROD-1 / C-RD-SESS-1): supervise asteria-encode --relay.

The SYSTEM service starts one `asteria-encode.exe --session console --relay wss://<host>/ws/rd/agent`.
The exe hops into the console session (re-hops on logout / session change) and follows the input
desktop itself. Machine credential travels in the child environment (ASTERIA_RD_TOKEN), never argv/logs.
Restart on exit with backoff 2 s .. 60 s; reset after 5 min healthy. Debug: ASTERIA_RD_DEBUG=1.
"""
from __future__ import annotations
import os, subprocess, threading, time
from typing import Callable, Optional

try:
    from client_helpers import log
except Exception:  # pragma: no cover
    def log(msg: str) -> None:
        print(msg)


def relay_url(api_base: str) -> str:
    base = (api_base or "").strip().rstrip("/")
    if base.endswith("/api"):
        base = base[:-4]
    if base.startswith("https://"):
        return "wss://" + base[8:] + "/ws/rd/agent"
    if base.startswith("http://"):
        return "ws://" + base[7:] + "/ws/rd/agent"
    return ""


class RdRelaySupervisor:
    def __init__(self, api_client, token_getter: Callable[[], str]):
        self.api_client, self.token_getter = api_client, token_getter
        self._stop = threading.Event()
        self._proc: Optional[subprocess.Popen] = None
        self._t: Optional[threading.Thread] = None

    def start(self) -> None:
        if os.name != "nt" or self._t:
            return
        self._t = threading.Thread(target=self._loop, name="RD-Relay", daemon=True)
        self._t.start()

    def stop(self) -> None:
        self._stop.set()
        p = self._proc
        if p and p.poll() is None:
            try:
                p.terminate()
            except Exception:
                pass

    def _cmd(self, exe, url):
        cmd = [str(exe), "--session", "console", "--relay", url]
        if os.environ.get("ASTERIA_RD_DEBUG") == "1":
            cmd.append("--debug")
        return cmd

    def _loop(self) -> None:
        from client_rd_hw_sidecar import sidecar_path
        try:  # Ctrl+Alt+Del: SendSAS from the SYSTEM parent needs SoftwareSASGeneration 1|3 (no reboot)
            from client_rd_winlogon import ensure_software_sas_generation
            pol, note = ensure_software_sas_generation()
            if note != "policy_ok":
                log(f"[RD] WARN SoftwareSASGeneration -> {pol} ({note})")
        except Exception as e:
            log(f"[RD] WARN SAS policy check failed: {e}")
        delay = 2.0
        while not self._stop.is_set():
            exe = sidecar_path()
            token = (self.token_getter() or "").strip()
            url = relay_url(getattr(self.api_client, "base_url", "") or "")
            if not exe or not token or not url:
                if not exe:
                    log("[RD] asteria-encode.exe missing - remote desktop unavailable")
                self._stop.wait(60.0)
                continue
            env = dict(os.environ, ASTERIA_RD_TOKEN=token)
            t0 = time.time()
            try:
                self._proc = subprocess.Popen(self._cmd(exe, url), env=env, cwd=str(exe.parent),
                                              stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                              creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
                rc = self._proc.wait()
            except Exception as e:
                rc = f"spawn: {e}"
            if self._stop.is_set():
                break
            delay = 2.0 if time.time() - t0 > 300 else min(60.0, delay * 2)
            log(f"[RD] asteria-encode exited ({rc}); restart in {int(delay)}s")
            self._stop.wait(delay)
