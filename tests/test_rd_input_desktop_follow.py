"""C-RD-IN-WL-4 (follow input desktop) + C-RD-VIEW-3 (session-correct cursor)."""
import json
import sys
import types
import unittest
from unittest import mock

from client_remote_desktop import RemoteDesktopStreamer


class FollowInputDesktop(unittest.TestCase):
    def _fake_winlogon(self, calls, name="Default"):
        mod = types.ModuleType("client_rd_winlogon")

        def attach_console_desktop(**kw):
            calls.append(kw)
            return True, name, 1234

        mod.attach_console_desktop = attach_console_desktop
        return mod

    def test_helper_winlogon_mode_follows_input_not_strict(self):
        rd = RemoteDesktopStreamer()
        rd._in_session_helper = True
        rd._winlogon_mode = True
        rd._helper_secure_token = True
        calls = []
        with mock.patch.dict(sys.modules, {"client_rd_winlogon": self._fake_winlogon(calls, "Default")}):
            self.assertTrue(rd._attach_input_desktop())
        self.assertTrue(calls and calls[0].get("follow_input") is True)
        self.assertNotIn("strict_winlogon", calls[0])
        # lock curtain on Default -> helper leaves Winlogon mode
        self.assertFalse(rd._winlogon_mode)

    def test_parent_winlogon_mode_still_strict(self):
        rd = RemoteDesktopStreamer()
        rd._winlogon_mode = True
        calls = []
        with mock.patch.dict(sys.modules, {"client_rd_winlogon": self._fake_winlogon(calls, "Winlogon")}):
            rd._attach_input_desktop()
        self.assertTrue(calls[0].get("strict_winlogon"))

    def test_secure_token_helper_switches_to_winlogon(self):
        rd = RemoteDesktopStreamer()
        rd._in_session_helper = True
        rd._winlogon_mode = False
        rd._helper_secure_token = True
        calls = []
        with mock.patch.dict(sys.modules, {"client_rd_winlogon": self._fake_winlogon(calls, "Winlogon")}):
            rd._attach_input_desktop()
        self.assertTrue(rd._winlogon_mode)

    def test_input_thread_reattaches_when_input_desktop_differs(self):
        rd = RemoteDesktopStreamer()
        rd._helper_secure_token = True
        rd._winlogon_mode = True
        calls = []
        with mock.patch.object(rd, "_input_desktop_name", return_value="Default"), \
             mock.patch.object(rd, "_thread_desktop_name", return_value="Winlogon"), \
             mock.patch.dict(sys.modules, {"client_rd_winlogon": self._fake_winlogon(calls, "Default")}):
            rd._ensure_input_thread_on_input_desktop()
        self.assertEqual(len(calls), 1)
        self.assertFalse(rd._winlogon_mode)

    def test_input_thread_no_reattach_when_same(self):
        rd = RemoteDesktopStreamer()
        calls = []
        with mock.patch.object(rd, "_input_desktop_name", return_value="Default"), \
             mock.patch.object(rd, "_thread_desktop_name", return_value="Default"), \
             mock.patch.dict(sys.modules, {"client_rd_winlogon": self._fake_winlogon(calls)}):
            rd._ensure_input_thread_on_input_desktop()
        self.assertEqual(calls, [])


class SessionCursor(unittest.TestCase):
    def test_parent_with_helper_never_reports_session0_cursor(self):
        rd = RemoteDesktopStreamer()
        rd._session_helper = object()
        rd._helper_cursor = None
        self.assertEqual(rd._cursor_meta_fields(), {})

    def test_helper_cursor_used_and_pushed(self):
        rd = RemoteDesktopStreamer()
        rd._session_helper = object()
        sent = []
        rd._q_put_text = lambda s: sent.append(json.loads(s))
        rd._note_helper_cursor({"cursor_nx": 0.25, "cursor_ny": 0.5, "cursor_visible": True})
        out = rd._cursor_meta_fields()
        self.assertEqual(out["cursor_nx"], 0.25)
        self.assertEqual(out["cursor_ny"], 0.5)
        self.assertEqual(sent[0]["t"], "cursor")
        self.assertEqual(sent[0]["nx"], 0.25)


if __name__ == "__main__":
    unittest.main()