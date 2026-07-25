import os
import tempfile
import unittest
from unittest import mock

import client_task_scheduler as scheduler


class TrayTaskSplitTests(unittest.TestCase):
    def test_tray_task_uses_separate_gui_when_present(self):
        with tempfile.TemporaryDirectory() as folder:
            gui = os.path.join(folder, "asteria-gui.exe")
            with open(gui, "wb") as handle:
                handle.write(b"MZ")
            with mock.patch.object(scheduler, "GUI_EXE", gui):
                xml = scheduler._build_task_xml(
                    scheduler.TASK_CONFIGS[scheduler.TASK_NAME_TRAY]
                )
        self.assertIn("asteria-gui.exe", xml)
        self.assertIn("<Arguments>--tray</Arguments>", xml)
        self.assertNotIn("--mode=tray", xml)

    def test_tray_task_falls_back_during_legacy_upgrade(self):
        missing = os.path.join(tempfile.gettempdir(), "missing-asteria-gui.exe")
        with mock.patch.object(scheduler, "GUI_EXE", missing):
            xml = scheduler._build_task_xml(
                scheduler.TASK_CONFIGS[scheduler.TASK_NAME_TRAY]
            )
        self.assertIn(scheduler.CLIENT_EXE, xml)
        self.assertIn("<Arguments>--mode=tray</Arguments>", xml)


if __name__ == "__main__":
    unittest.main()
