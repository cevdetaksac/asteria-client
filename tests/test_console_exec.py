"""Agent-side console blacklist + signature gate."""
from __future__ import annotations
import unittest
from unittest import mock

import console_blacklist as bl


class AgentBlacklistParity(unittest.TestCase):
    def test_blocks_agent_self_harm(self):
        for c in (
            "sc stop asteria-client",
            "taskkill /F /IM honeypot-client.exe",
            "Remove-Item -Recurse C:\\ProgramData\\Asteria",
            "schtasks /Delete /TN Asteria",
        ):
            blocked, _ = bl.is_blocked(c, "cmd")
            self.assertTrue(blocked, c)

    def test_execute_requires_approval(self):
        from client_console_exec import execute_console
        r = execute_console({"shell": "cmd", "command": "echo hi"})
        self.assertFalse(r.get("success"))
        self.assertIn("approval", r.get("code", ""))

    def test_execute_blocks_blacklisted(self):
        from client_console_exec import execute_console
        r = execute_console({
            "shell": "cmd", "command": "shutdown /r /t 0",
            "approval_id": "00000000-0000-0000-0000-000000000001",
        })
        self.assertFalse(r.get("success"))
        self.assertTrue(str(r.get("code", "")).startswith("blacklisted"))

    def test_signature_required_in_validate(self):
        from client_remote_commands import RemoteCommandExecutor
        # Minimal stub
        class E(RemoteCommandExecutor):
            def __init__(self):
                pass
        e = E.__new__(E)
        e.token_getter = lambda: "tok"
        e._stats = {}
        # missing signature on console_exec
        reason = RemoteCommandExecutor._validate(e, {
            "command_type": "console_exec",
            "command_id": "x",
            "params": {"shell": "cmd", "command": "echo hi", "approval_id": "abcd1234"},
        })
        self.assertIsNotNone(reason)
        self.assertIn("signature", reason.lower())


if __name__ == "__main__":
    unittest.main()
