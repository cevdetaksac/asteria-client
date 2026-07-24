#!/usr/bin/env python3
"""Tray close prefers minimize; ensure_tray_alive restarts dead thread."""

import unittest
from unittest import mock

import client_tray as tray


class _App:
    def __init__(self):
        self.state = {"running": False}
        self._exiting = False
        self.root = None
        self.exited = False

    def graceful_exit(self, code=0):
        self.exited = True


class TestTrayResilience(unittest.TestCase):
    def test_close_minimizes_when_tray_starting(self):
        app = _App()
        tm = tray.TrayManager(app, lambda k: k)
        tm._tray_starting = True
        tm.minimize_callback = mock.Mock()
        with mock.patch.object(tray, "TRY_TRAY", True):
            tm.on_window_close()
        tm.minimize_callback.assert_called_once()
        self.assertFalse(app.exited)

    def test_ensure_restarts_dead_thread(self):
        app = _App()
        tm = tray.TrayManager(app, lambda k: k)
        dead = mock.Mock()
        dead.is_alive.return_value = False
        tm.tray_thread = dead
        with mock.patch.object(tray, "TRY_TRAY", True), \
                mock.patch.object(tm, "start_tray_system", return_value=True) as start:
            ok = tm.ensure_tray_alive()
        self.assertTrue(ok)
        start.assert_called_once()


if __name__ == "__main__":
    unittest.main()
