#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GUI singleton / handoff smoke tests (mutex names + helpers)."""

import unittest
import uuid
from unittest import mock


class TestGuiSingletonConstants(unittest.TestCase):
    def test_gui_mutex_is_global_session_scoped(self):
        from client_constants import (
            GUI_MUTEX_NAME_PREFIX,
            GUI_SHOW_EVENT_NAME_PREFIX,
            DAEMON_MUTEX_NAME,
            gui_mutex_name,
            gui_show_event_name,
        )

        self.assertTrue(GUI_MUTEX_NAME_PREFIX.startswith("Global\\"))
        self.assertTrue(GUI_SHOW_EVENT_NAME_PREFIX.startswith("Global\\"))
        self.assertTrue(DAEMON_MUTEX_NAME.startswith("Global\\"))
        name = gui_mutex_name(session_id=7)
        self.assertEqual(name, "Global\\AsteriaClient_GUI_s7")
        self.assertEqual(
            gui_show_event_name(session_id=7), "Global\\AsteriaClient_ShowGUI_s7"
        )
        self.assertNotEqual(name, DAEMON_MUTEX_NAME)


class TestHandoffHelpers(unittest.TestCase):
    def test_signal_show_creates_named_event(self):
        import win32api
        import win32event
        from client_constants import gui_show_event_name
        from client_instance import signal_existing_gui_show

        self.assertTrue(signal_existing_gui_show())
        h = win32event.CreateEvent(None, False, False, gui_show_event_name())
        self.assertIsNotNone(h)
        win32api.CloseHandle(h)

    def test_gui_mutex_exclusive(self):
        import win32api
        import client_instance as ci

        if ci._GUI_MUTEX_HANDLE:
            try:
                win32api.CloseHandle(ci._GUI_MUTEX_HANDLE)
            except Exception:
                pass
            ci._GUI_MUTEX_HANDLE = None

        test_mutex_name = f"Global\\AsteriaGuiTest-{uuid.uuid4()}"
        with mock.patch.object(ci, "gui_mutex_name", return_value=test_mutex_name):
            self.assertTrue(ci.try_acquire_gui_mutex())
            self.assertFalse(ci.try_acquire_gui_mutex())

        try:
            win32api.CloseHandle(ci._GUI_MUTEX_HANDLE)
        except Exception:
            pass
        ci._GUI_MUTEX_HANDLE = None


if __name__ == "__main__":
    unittest.main()
