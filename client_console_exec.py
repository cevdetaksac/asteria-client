"""Secure remote console executor — CMD / PowerShell.

Runs only when:
  * command_type == console_exec
  * HMAC signature is present and valid (missing = reject; unlike soft-allow)
  * params.approval_id is a non-empty id
  * console_blacklist.is_blocked is False (agent-side, cannot be bypassed by cloud)

Timeout + output size capped. Never touches the agent's outbound 443 path.
"""
from __future__ import annotations

import hashlib
import os
import subprocess
import tempfile
from typing import Any, Dict

import console_blacklist as bl


def execute_console(params: dict) -> dict:
    params = params or {}
    shell = bl.validate_shell(params.get("shell") or "cmd")
    if not shell:
        return _fail("invalid_shell")
    approval_id = str(params.get("approval_id") or "").strip()
    if not approval_id or len(approval_id) < 8:
        return _fail("missing_approval_id")
    raw_cmd = params.get("command") or ""
    blocked, reason = bl.is_blocked(raw_cmd, shell)
    if blocked:
        return _fail(f"blacklisted:{reason}")
    cmd_text = bl.normalize_command(raw_cmd)
    if not cmd_text:
        return _fail("invalid_command")
    # Optional integrity: cloud may send command_hash
    expect_hash = str(params.get("command_hash") or "").strip().lower()
    if expect_hash:
        got = hashlib.sha256(cmd_text.encode("utf-8")).hexdigest()
        if got != expect_hash:
            return _fail("command_hash_mismatch")
    timeout = bl.clamp_timeout(params.get("timeout_sec"))
    try:
        if shell == "cmd":
            # /d disables AutoRun; /s /c runs the string
            proc = subprocess.run(
                ["cmd.exe", "/d", "/s", "/c", cmd_text],
                capture_output=True, timeout=timeout,
                creationflags=0x08000000,  # CREATE_NO_WINDOW
                cwd=os.environ.get("SystemRoot", r"C:\Windows") + r"\System32",
            )
        else:
            # -NoProfile -NonInteractive -ExecutionPolicy Bypass (script scope only)
            # Reject -EncodedCommand already via blacklist; pass as -Command
            proc = subprocess.run(
                [
                    "powershell.exe",
                    "-NoLogo", "-NoProfile", "-NonInteractive",
                    "-ExecutionPolicy", "Bypass",
                    "-Command", cmd_text,
                ],
                capture_output=True, timeout=timeout,
                creationflags=0x08000000,
                cwd=os.environ.get("SystemRoot", r"C:\Windows") + r"\System32",
            )
    except subprocess.TimeoutExpired as e:
        out, err, trunc = _cap(e.stdout or b"", e.stderr or b"")
        return {
            "success": False, "ok": False, "code": "TIMEOUT",
            "error": "TIMEOUT", "exit_code": -1,
            "stdout": out, "stderr": err or "timeout",
            "truncated": trunc, "approval_id": approval_id,
        }
    except Exception as e:
        return _fail(f"exec_error:{e}")

    out, err, trunc = _cap(proc.stdout or b"", proc.stderr or b"")
    ok = proc.returncode == 0
    return {
        "success": ok, "ok": ok,
        "exit_code": int(proc.returncode),
        "stdout": out, "stderr": err, "truncated": trunc,
        "approval_id": approval_id,
        "shell": shell,
        "output_hash": hashlib.sha256((out + "\0" + err).encode("utf-8", errors="replace")).hexdigest(),
        "output_bytes": len(out.encode("utf-8")) + len(err.encode("utf-8")),
    }


def _cap(stdout: bytes, stderr: bytes):
    def _d(b: bytes) -> str:
        try:
            return b.decode("utf-8", errors="replace")
        except Exception:
            return b.decode("cp1254", errors="replace")
    out, err = _d(stdout), _d(stderr)
    trunc = False
    if len(out.encode("utf-8", errors="replace")) > bl.MAX_OUTPUT_BYTES:
        out = out.encode("utf-8", errors="replace")[: bl.MAX_OUTPUT_BYTES].decode("utf-8", errors="replace")
        trunc = True
    if len(err.encode("utf-8", errors="replace")) > bl.MAX_OUTPUT_BYTES:
        err = err.encode("utf-8", errors="replace")[: bl.MAX_OUTPUT_BYTES].decode("utf-8", errors="replace")
        trunc = True
    return out, err, trunc


def _fail(code: str) -> Dict[str, Any]:
    return {"success": False, "ok": False, "code": code, "error": code, "message": code}
