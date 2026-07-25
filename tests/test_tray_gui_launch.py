"""Interactive tray must prefer asteria-gui.exe over motor --mode=tray."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from unittest import mock


class ResolveInteractiveTrayCommandTests(unittest.TestCase):
    def test_prefers_sibling_asteria_gui(self):
        from client_helpers import resolve_interactive_tray_command

        with tempfile.TemporaryDirectory() as folder:
            motor = os.path.join(folder, "asteria-client.exe")
            gui = os.path.join(folder, "asteria-gui.exe")
            open(motor, "wb").close()
            open(gui, "wb").close()
            with mock.patch.object(sys, "frozen", True, create=True), mock.patch.object(
                sys, "executable", motor
            ):
                exe, cmdline = resolve_interactive_tray_command()
            self.assertEqual(exe, gui)
            self.assertEqual(cmdline, f'"{gui}" --tray')
            self.assertNotIn("--mode=tray", cmdline)

    def test_falls_back_to_motor_tray_when_gui_missing(self):
        from client_helpers import resolve_interactive_tray_command

        with tempfile.TemporaryDirectory() as folder:
            motor = os.path.join(folder, "asteria-client.exe")
            open(motor, "wb").close()
            with mock.patch.object(sys, "frozen", True, create=True), mock.patch.object(
                sys, "executable", motor
            ):
                exe, cmdline = resolve_interactive_tray_command()
            self.assertEqual(exe, motor)
            self.assertEqual(cmdline, f'"{motor}" --mode=tray')


if __name__ == "__main__":
    unittest.main()
