"""C-RD-IN-WL-4 / 4.9.138: no Default↔Winlogon helper thrash on lock curtain."""
import time
import unittest
from unittest import mock

from client_remote_desktop import RemoteDesktopStreamer, DESKTOP_SWITCH_MIN_SEC
from client_rd_winlogon import console_start_secure_desktop, resolve_console_capture_mode


class LockCurtainNoThrash(unittest.TestCase):
    def _rd(self):
        rd = RemoteDesktopStreamer(api_client=None, token_getter=lambda: "")
        rd._running = True
        rd._target_session_id = 1
        return rd

    def test_secure_false_when_live_default_even_with_logonui(self):
        self.assertFalse(
            console_start_secure_desktop(
                username="caksac",
                logonui_present=True,
                session_locked=True,
                explorer_present=True,
                input_desktop="default",
            )
        )

    def test_secure_true_when_live_winlogon(self):
        self.assertTrue(
            console_start_secure_desktop(
                username="caksac",
                logonui_present=True,
                session_locked=True,
                input_desktop="winlogon",
            )
        )

    def test_resolve_default_when_input_default(self):
        with mock.patch("client_rd_winlogon.session_username", return_value="u"), mock.patch(
            "client_rd_winlogon.session_has_logonui", return_value=True
        ), mock.patch(
            "client_rd_winlogon.session_lock_state", return_value=True
        ), mock.patch(
            "client_rd_winlogon.session_has_process", return_value=True
        ):
            self.assertEqual(resolve_console_capture_mode(1, input_desktop="default"), "default")

    def test_promote_false_on_default_desk_despite_logonui(self):
        rd = self._rd()
        rd._winlogon_mode = False
        rd._desktop_name = "Default"
        rd._capture_method = "persistent-user-helper:gdi"
        with mock.patch("client_rd_winlogon.session_has_logonui", return_value=True), mock.patch(
            "client_rd_winlogon.session_lock_state", return_value=True
        ), mock.patch(
            "client_rd_winlogon.session_has_process", return_value=True
        ):
            self.assertFalse(rd._should_promote_follow_to_winlogon())

    def test_promote_true_on_winlogon_desk_with_logonui(self):
        rd = self._rd()
        rd._winlogon_mode = False
        rd._desktop_name = "Winlogon"
        rd._capture_method = "persistent-user-helper:gdi+black"
        with mock.patch("client_rd_winlogon.session_has_logonui", return_value=True), mock.patch(
            "client_rd_winlogon.session_lock_state", return_value=True
        ), mock.patch(
            "client_rd_winlogon.session_has_process", return_value=True
        ):
            self.assertTrue(rd._should_promote_follow_to_winlogon())

    def test_pix3_fallback_noop_when_desk_default(self):
        rd = self._rd()
        rd._winlogon_mode = False
        rd._desktop_name = "Default"
        called = []
        rd._stop_persistent_helper = lambda: called.append("stop")
        rd._start_persistent_helper = lambda **k: called.append("start") or True
        out = rd._fallback_user_helper_to_winlogon(jpeg=None, w=0, h=0, phase="live", force=True)
        self.assertIsNone(out)
        self.assertEqual(called, [])

    def test_hysteresis_blocks_rapid_opposite_switch(self):
        rd = self._rd()
        self.assertTrue(rd._desktop_switch_allowed("default"))
        rd._note_desktop_switch("default", reason="test")
        self.assertFalse(rd._desktop_switch_allowed("winlogon"))
        rd._last_desktop_switch_mono = time.monotonic() - (DESKTOP_SWITCH_MIN_SEC + 0.1)
        self.assertTrue(rd._desktop_switch_allowed("winlogon"))

    def test_execute_follow_noop_when_already_default(self):
        rd = self._rd()
        rd._winlogon_mode = False
        rd._desktop_name = "Default"
        rd._helper_spawned_winlogon = False

        class H:
            connected = True

        rd._session_helper = H()
        called = []
        rd._stop_persistent_helper = lambda: called.append("stop")
        rd._start_persistent_helper = lambda **k: called.append("start") or True
        rd._execute_console_follow("desktop_default", 1, "caksac")
        self.assertEqual(called, [])


if __name__ == "__main__":
    unittest.main()
