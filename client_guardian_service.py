"""CloudHoneypotGuardian — Windows service watchdog (contract ≥4.6.0).

Runs as LocalSystem. Does NOT duplicate the motor — only ensures the Session 0
daemon (CloudHoneypot-Background task / :58632 motor_ok) stays alive.

Cross-watchdog: motor also ensures this service exists and is running.

Entry: asteria-client.exe --mode=guardian (legacy: honeypot-client.exe)
"""

from __future__ import annotations

import os
import subprocess
import sys
import threading
import time

CREATE_NO_WINDOW = 0x08000000
SERVICE_NAME = "CloudHoneypotGuardian"
SERVICE_DISPLAY = "Asteria Guardian"
SERVICE_DESC = (
    "Asteria watchdog — keeps the SYSTEM security motor alive. "
    "Does not replace the motor process."
)


def is_guardian_argv(argv=None) -> bool:
    """True when process was started as the Windows Guardian service host."""
    import sys
    av = list(argv if argv is not None else sys.argv[1:])
    for i, a in enumerate(av):
        if a == "--mode=guardian":
            return True
        if a == "--mode" and i + 1 < len(av) and av[i + 1] == "guardian":
            return True
    return False


try:
    from client_helpers import log
except Exception:  # pragma: no cover
    def log(*_a, **_k):
        pass

try:
    from client_task_scheduler import TASK_NAME_BACKGROUND
except Exception:
    TASK_NAME_BACKGROUND = "CloudHoneypot-Background"


def _exe_path() -> str:
    if getattr(sys, "frozen", False):
        return sys.executable
    return os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "asteria-client.exe",
        "honeypot-client.exe",
    )


def is_guardian_service_running() -> bool:
    state = query_guardian_service_state()
    return state == "RUNNING"


def query_guardian_service_state() -> str:
    """Return RUNNING|START_PENDING|STOP_PENDING|STOPPED|UNKNOWN|MISSING."""
    try:
        r = subprocess.run(
            ["sc", "query", SERVICE_NAME],
            capture_output=True, text=True, timeout=8,
            creationflags=CREATE_NO_WINDOW,
        )
        if r.returncode != 0:
            return "MISSING"
        text = (r.stdout or "").upper()
        for tag in ("START_PENDING", "STOP_PENDING", "RUNNING", "STOPPED"):
            if tag in text:
                return tag
        return "UNKNOWN"
    except Exception:
        return "UNKNOWN"


def is_guardian_service_installed() -> bool:
    return query_guardian_service_state() != "MISSING"


def install_guardian_service(exe_path: str = None) -> bool:
    """Create Guardian service if missing. Never delete a healthy install."""
    exe = exe_path or _exe_path()
    if not os.path.isfile(exe):
        log(f"[GUARDIAN] install failed — exe not found: {exe}")
        return False
    binpath = f'"{exe}" --mode=guardian'
    try:
        state = query_guardian_service_state()
        if state == "RUNNING":
            return True
        if state in ("START_PENDING", "STOP_PENDING"):
            # Let SCM finish; do not delete/recreate (caused 7045 install storms).
            return False
        if state != "MISSING":
            # Already registered — just start (and refresh failure actions).
            try:
                subprocess.run(
                    ["sc", "config", SERVICE_NAME, f"binPath={binpath}", "start=auto"],
                    capture_output=True, timeout=15, creationflags=CREATE_NO_WINDOW,
                )
            except Exception:
                pass
            subprocess.run(
                ["sc", "failure", SERVICE_NAME, "reset=86400",
                 "actions=restart/5000/restart/10000/restart/30000"],
                capture_output=True, timeout=10, creationflags=CREATE_NO_WINDOW,
            )
            subprocess.run(
                ["sc", "start", SERVICE_NAME],
                capture_output=True, timeout=20, creationflags=CREATE_NO_WINDOW,
            )
            time.sleep(2.0)
            return is_guardian_service_running()

        r = subprocess.run(
            ["sc", "create", SERVICE_NAME, f"binPath={binpath}", "start=auto",
             f"DisplayName={SERVICE_DISPLAY}"],
            capture_output=True, text=True, timeout=20, creationflags=CREATE_NO_WINDOW,
        )
        if r.returncode != 0 and "1073" not in (r.stderr or "") and "EXISTS" not in (
            (r.stderr or "") + (r.stdout or "")
        ).upper():
            log(f"[GUARDIAN] sc create failed: {(r.stderr or r.stdout or '').strip()}")
            return False
        subprocess.run(["sc", "description", SERVICE_NAME, SERVICE_DESC],
                         capture_output=True, timeout=10, creationflags=CREATE_NO_WINDOW)
        subprocess.run(["sc", "failure", SERVICE_NAME, "reset=86400",
                        "actions=restart/5000/restart/10000/restart/30000"],
                       capture_output=True, timeout=10, creationflags=CREATE_NO_WINDOW)
        subprocess.run(["sc", "start", SERVICE_NAME],
                         capture_output=True, timeout=20, creationflags=CREATE_NO_WINDOW)
        time.sleep(2.0)
        ok = is_guardian_service_running()
        log(f"[GUARDIAN] service installed + start ok={ok}")
        return ok
    except Exception as e:
        log(f"[GUARDIAN] install error: {e}")
        return False


def uninstall_guardian_service() -> bool:
    try:
        subprocess.run(["sc", "stop", SERVICE_NAME],
                       capture_output=True, timeout=20, creationflags=CREATE_NO_WINDOW)
        time.sleep(1.0)
        r = subprocess.run(["sc", "delete", SERVICE_NAME],
                             capture_output=True, timeout=15, creationflags=CREATE_NO_WINDOW)
        log(f"[GUARDIAN] service removed ok={r.returncode == 0}")
        return r.returncode == 0
    except Exception as e:
        log(f"[GUARDIAN] uninstall error: {e}")
        return False


def ensure_guardian_service_running(exe_path: str = None) -> bool:
    state = query_guardian_service_state()
    if state == "RUNNING":
        return True
    if state in ("START_PENDING", "STOP_PENDING"):
        # Wait briefly for transition; do not stack another start.
        for _ in range(6):
            time.sleep(0.5)
            state = query_guardian_service_state()
            if state == "RUNNING":
                return True
            if state not in ("START_PENDING", "STOP_PENDING"):
                break
        return state == "RUNNING"
    if state == "MISSING":
        return install_guardian_service(exe_path)
    try:
        subprocess.run(["sc", "start", SERVICE_NAME],
                       capture_output=True, timeout=20, creationflags=CREATE_NO_WINDOW)
        for _ in range(8):
            time.sleep(0.5)
            if is_guardian_service_running():
                return True
        return False
    except Exception:
        return False


def _legitimate_stand_down() -> bool:
    try:
        from client_utils import is_update_in_progress
        if is_update_in_progress():
            return True
    except Exception:
        pass
    try:
        from client_operator_stop import is_operator_stop_active
        if is_operator_stop_active():
            return True
    except Exception:
        pass
    return False


def is_motor_healthy(timeout: float = 0.9) -> bool:
    try:
        from client_helpers import ClientHelpers
        return bool(ClientHelpers().is_system_motor_alive(timeout=timeout))
    except Exception:
        return False


def observe_motor_heartbeat_proof() -> dict:
    """RES-103 soft-check of motor deadman proof. Never gates resurrect.

    Returns a small observe dict for tests/logs. Missing flag or file is not
    an error. Invalid/stale proofs are logged only.
    """
    result = {
        "checked": False,
        "ok": None,
        "reason": "disabled",
        "enforce": False,
    }
    try:
        from client_utils import get_from_config
        if not bool(get_from_config("security.signed_heartbeat_observe", False)):
            return result
    except Exception:
        return result
    try:
        from client_tamper import HEARTBEAT_FILE, _read_token
        import json
        if not os.path.isfile(HEARTBEAT_FILE):
            result["reason"] = "no_file"
            return result
        with open(HEARTBEAT_FILE, "r", encoding="utf-8") as handle:
            doc = json.load(handle)
        proof = doc.get("heartbeat_proof")
        if not isinstance(proof, dict):
            result["reason"] = "no_proof"
            return result
        from client_resilience_p1 import verify_heartbeat_proof
        check = verify_heartbeat_proof(
            _read_token() or "",
            proof,
            hostname=str(doc.get("hostname") or ""),
            status=str(doc.get("status") or "online"),
            running=bool(doc.get("running", True)),
        )
        result["checked"] = True
        result["ok"] = bool(check.get("ok"))
        result["reason"] = str(check.get("reason") or "")
        if result["ok"]:
            log("[GUARDIAN] heartbeat_proof observe ok")
        else:
            log(f"[GUARDIAN] heartbeat_proof observe fail reason={result['reason']}")
    except Exception as exc:
        result["reason"] = f"error:{exc}"
        log(f"[GUARDIAN] heartbeat_proof observe error: {exc}")
    return result


def resurrect_motor() -> bool:
    if _legitimate_stand_down():
        return False
    try:
        subprocess.run(["schtasks", "/change", "/tn", TASK_NAME_BACKGROUND, "/enable"],
                       capture_output=True, timeout=10, creationflags=CREATE_NO_WINDOW)
        subprocess.run(["schtasks", "/run", "/tn", TASK_NAME_BACKGROUND],
                       capture_output=True, timeout=15, creationflags=CREATE_NO_WINDOW)
        for _ in range(12):
            time.sleep(0.5)
            if is_motor_healthy(timeout=0.8):
                log("[GUARDIAN] motor resurrected via Background task")
                return True
    except Exception as e:
        log(f"[GUARDIAN] task resurrect failed: {e}")
    try:
        exe = _exe_path()
        subprocess.Popen(
            [exe, "--mode=daemon", "--silent"],
            creationflags=CREATE_NO_WINDOW | subprocess.DETACHED_PROCESS,
            close_fds=True,
        )
        for _ in range(15):
            time.sleep(0.5)
            if is_motor_healthy(timeout=0.8):
                log("[GUARDIAN] motor resurrected via direct spawn")
                return True
    except Exception as e:
        log(f"[GUARDIAN] spawn resurrect failed: {e}")
    return False


def guardian_watch_loop(stop_event=None, interval_sec: float = 10.0) -> None:
    log("[GUARDIAN] watch loop started")
    while stop_event is None or not stop_event.is_set():
        sleep_for = float(interval_sec)
        try:
            if _legitimate_stand_down():
                try:
                    from client_resilience import note_stand_down
                    note_stand_down("update_or_operator_stop")
                except Exception:
                    pass
                if stop_event is not None:
                    stop_event.wait(sleep_for)
                else:
                    time.sleep(sleep_for)
                continue
            # Observe-only RES-103 soft-check; never skips resurrect.
            try:
                observe_motor_heartbeat_proof()
            except Exception:
                pass
            if not is_motor_healthy(timeout=0.9):
                try:
                    from client_resilience import (
                        record_recovery_attempt,
                        should_attempt_recovery,
                    )
                    allowed, wait = should_attempt_recovery("daemon")
                except Exception:
                    allowed, wait = True, 0
                if not allowed:
                    log(f"[GUARDIAN] motor recovery deferred backoff={wait}s")
                    sleep_for = max(sleep_for, float(wait))
                else:
                    log("[GUARDIAN] motor unhealthy — resurrecting")
                    t0 = time.monotonic()
                    ok = resurrect_motor()
                    ms = int((time.monotonic() - t0) * 1000)
                    try:
                        from client_resilience import record_recovery_attempt
                        record_recovery_attempt(
                            "daemon", ok=ok, duration_ms=ms
                        )
                    except Exception:
                        pass
                    if not ok:
                        try:
                            from client_tamper import report_tamper
                            report_tamper(
                                reason="motor_down",
                                leg="service",
                                resurrected=False,
                                resurrect_ms=ms,
                            )
                        except Exception:
                            pass
        except Exception as e:
            log(f"[GUARDIAN] watch error: {e}")
        if stop_event is not None:
            stop_event.wait(sleep_for)
        else:
            time.sleep(sleep_for)


def run_guardian_mode():
    """CLI entry: --mode=guardian — Windows service host or foreground fallback."""
    try:
        import win32serviceutil
        import servicemanager
        import win32service
        import win32event

        class _GuardianSvc(win32serviceutil.ServiceFramework):
            _svc_name_ = SERVICE_NAME
            _svc_display_name_ = SERVICE_DISPLAY
            _svc_description_ = SERVICE_DESC

            def __init__(self, args):
                win32serviceutil.ServiceFramework.__init__(self, args)
                self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
                self._stop = threading.Event()

            def SvcStop(self):
                self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
                self._stop.set()
                win32event.SetEvent(self.hWaitStop)

            def SvcDoRun(self):
                self.ReportServiceStatus(win32service.SERVICE_RUNNING)
                log("[GUARDIAN] Windows service running")
                t = threading.Thread(
                    target=guardian_watch_loop,
                    args=(self._stop, 10.0),
                    name="GuardianWatch",
                    daemon=True,
                )
                t.start()
                win32event.WaitForSingleObject(self.hWaitStop, win32event.INFINITE)

        if len(sys.argv) > 1 and sys.argv[1] in (
            "install", "remove", "start", "stop", "restart", "debug",
        ):
            win32serviceutil.HandleCommandLine(_GuardianSvc)
            return

        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(_GuardianSvc)
        servicemanager.StartServiceCtrlDispatcher()
        return
    except Exception as e:
        log(f"[GUARDIAN] SCM host unavailable ({e}) — foreground loop")
    stop = threading.Event()
    guardian_watch_loop(stop, 10.0)
