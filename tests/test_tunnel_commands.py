#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tunnel_start / tunnel_stop — dashboard honeypot bait commands."""

import time
import unittest
from unittest.mock import MagicMock

from client_remote_commands import ALLOWED_COMMANDS, RemoteCommandExecutor, _IR_URGENT_COMMANDS


class TunnelCommandTests(unittest.TestCase):
    def test_allowed(self):
        self.assertIn("tunnel_start", ALLOWED_COMMANDS)
        self.assertIn("tunnel_stop", ALLOWED_COMMANDS)
        self.assertIn("tunnel_start", _IR_URGENT_COMMANDS)
        self.assertIn("tunnel_stop", _IR_URGENT_COMMANDS)

    def test_tunnel_start_stop(self):
        sm = MagicMock()
        sm.start_service.return_value = True
        sm.stop_service.return_value = True
        ex = RemoteCommandExecutor(service_manager=sm)

        start = ex._cmd_tunnel_start({"service": "HTTP", "port": 80})
        self.assertTrue(start["success"])
        sm.start_service.assert_called_once_with("HTTP", 80)

        stop = ex._cmd_tunnel_stop({"service": "http"})
        self.assertTrue(stop["success"])
        sm.stop_service.assert_called_once_with("HTTP")

    def test_validate_accepts_tunnel_types(self):
        ex = RemoteCommandExecutor()
        self.assertIsNone(
            ex._validate({
                "command_type": "tunnel_stop",
                "issued_at": "2099-01-01T00:00:00+00:00",
            })
        )
        self.assertIsNone(
            ex._validate({
                "command_type": "tunnel_start",
                "issued_at": "2099-01-01T00:00:00+00:00",
            })
        )

    def test_forget_allows_retry_after_rate_limit(self):
        ex = RemoteCommandExecutor()
        self.assertFalse(ex._remember_command_id("abc-1"))
        self.assertTrue(ex._remember_command_id("abc-1"))
        ex._forget_command_id("abc-1")
        self.assertFalse(ex._remember_command_id("abc-1"))
        # keep time import used for future timing asserts
        self.assertGreater(time.time(), 0)


if __name__ == "__main__":
    unittest.main()
