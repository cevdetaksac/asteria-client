"""Unit tests for HW cross-session attach (C-RD-HW-CON / SES)."""
from __future__ import annotations

import unittest
from unittest.mock import patch, MagicMock


class ResolveHwTarget(unittest.TestCase):
    def test_explicit_session(self):
        from client_rd_hw_session import resolve_hw_target
        with patch("client_rd_hw_session.console_session_id", return_value=1):
            sid, desk, reason = resolve_hw_target(
                {"kind": "session", "session_id": 3}, winlogon=False
            )
        self.assertEqual(sid, 3)
        self.assertIn("default", desk.lower())
        self.assertEqual(reason, "session")

    def test_console_winlogon_when_no_user(self):
        from client_rd_hw_session import resolve_hw_target
        with patch("client_rd_hw_session.console_session_id", return_value=1), patch(
            "client_rd_winlogon.session_username", return_value=""
        ), patch("client_rd_winlogon.session_has_logonui", return_value=True):
            sid, desk, reason = resolve_hw_target({"kind": "console"}, winlogon=False)
        self.assertEqual(sid, 1)
        self.assertIn("winlogon", desk.lower())

    def test_refuses_session_zero(self):
        from client_rd_hw_session import resolve_hw_target
        with patch("client_rd_hw_session.console_session_id", return_value=0):
            with self.assertRaises(ValueError):
                resolve_hw_target({"kind": "console"})


class NeedsCrossSession(unittest.TestCase):
    def test_session0_to_interactive(self):
        from client_rd_hw_session import needs_cross_session
        with patch("client_rd_hw_session.current_process_session_id", return_value=0):
            self.assertTrue(needs_cross_session(1))

    def test_same_session_local(self):
        from client_rd_hw_session import needs_cross_session
        with patch("client_rd_hw_session.current_process_session_id", return_value=2):
            self.assertFalse(needs_cross_session(2))


class HwSidecarSpawn(unittest.TestCase):
    def test_local_popens_when_same_session(self):
        import client_rd_hw_sidecar as hw
        sc = hw.HwSidecar(lambda m: None)
        sc._path = __file__  # any existing path
        fake = MagicMock()
        fake.stdin = MagicMock()
        fake.stdout = MagicMock()
        fake.stderr = MagicMock()
        fake.poll.return_value = None
        with patch.object(hw, "needs_cross_session", return_value=False), patch(
            "subprocess.Popen", return_value=fake
        ) as popen, patch.object(hw, "_ensure_gpu_preference"):
            # bypass send by making stdin write succeed then stop immediately
            fake.stdin.write = MagicMock()
            fake.stdin.flush = MagicMock()
            ok = sc.start(session_id=1, session_target={"kind": "session", "session_id": 1})
            self.assertTrue(ok)
            popen.assert_called_once()
            sc.stop_locked("test")

    def test_cross_session_uses_spawn_in_session(self):
        import client_rd_hw_sidecar as hw
        sc = hw.HwSidecar(lambda m: None)
        sc._path = __file__
        fake = MagicMock()
        fake.stdin = MagicMock()
        fake.stdout = MagicMock()
        fake.stderr = MagicMock()
        fake.poll.return_value = None
        with patch.object(hw, "needs_cross_session", return_value=True), patch.object(
            hw, "resolve_hw_target", return_value=(3, r"winsta0\default", "session")
        ), patch.object(hw, "spawn_in_session", return_value=fake) as spawn, patch.object(
            hw, "_ensure_gpu_preference"
        ), patch("subprocess.Popen") as popen:
            fake.stdin.write = MagicMock()
            fake.stdin.flush = MagicMock()
            ok = sc.start(session_id=3, session_target={"kind": "session", "session_id": 3})
            self.assertTrue(ok)
            spawn.assert_called_once()
            popen.assert_not_called()
            sc.stop_locked("test")


if __name__ == "__main__":
    unittest.main()
