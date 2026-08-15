import unittest
from unittest import mock

from client_remote_commands import (
    ALLOWED_COMMANDS,
    REQUIRES_CONFIRMATION,
    RemoteCommandExecutor,
)


class TestProcessContainmentCatalog(unittest.TestCase):
    def test_suspend_and_resume_are_supported(self):
        self.assertIn("suspend_process", ALLOWED_COMMANDS)
        self.assertIn("resume_process", ALLOWED_COMMANDS)
        self.assertIn("suspend_process", REQUIRES_CONFIRMATION)
        self.assertNotIn("resume_process", REQUIRES_CONFIRMATION)
        self.assertIn("inspect_process", ALLOWED_COMMANDS)
        self.assertNotIn("inspect_process", REQUIRES_CONFIRMATION)

    def test_exact_identity_is_required(self):
        executor = RemoteCommandExecutor()
        self.assertEqual(
            executor._validate({
                "command_type": "suspend_process",
                "params": {"pid": 123},
            }),
            "missing_expected_image",
        )
        self.assertEqual(
            executor._validate({
                "command_type": "suspend_process",
                "params": {"pid": 123, "expected_image": "sample.exe"},
            }),
            "missing_process_start_time",
        )


class TestProcessContainmentExecution(unittest.TestCase):
    def setUp(self):
        self.executor = RemoteCommandExecutor()
        self.process = mock.Mock()
        self.process.pid = 4242
        self.process.name.return_value = "sample.exe"
        self.process.exe.return_value = r"C:\Users\Public\sample.exe"
        self.process.create_time.return_value = 1721550000.25
        self.params = {
            "pid": 4242,
            "expected_image": "sample.exe",
            "expected_path": r"C:\Users\Public\sample.exe",
            "process_start_time": 1721550000.25,
        }

    @mock.patch("psutil.Process")
    def test_suspend_exact_process(self, process_cls):
        process_cls.return_value = self.process
        result = self.executor._cmd_suspend_process(self.params)
        self.process.suspend.assert_called_once_with()
        self.assertTrue(result["success"])
        self.assertEqual(result["data"]["state"], "suspended")

    @mock.patch("psutil.Process")
    def test_resume_exact_process(self, process_cls):
        process_cls.return_value = self.process
        result = self.executor._cmd_resume_process(self.params)
        self.process.resume.assert_called_once_with()
        self.assertTrue(result["success"])
        self.assertEqual(result["data"]["state"], "running")

    @mock.patch("psutil.Process")
    def test_rejects_pid_reuse(self, process_cls):
        process_cls.return_value = self.process
        self.process.create_time.return_value = 1721559999.0
        with self.assertRaisesRegex(RuntimeError, "PID was reused"):
            self.executor._cmd_suspend_process(self.params)
        self.process.suspend.assert_not_called()

    @mock.patch("psutil.Process")
    def test_rejects_image_mismatch(self, process_cls):
        process_cls.return_value = self.process
        self.process.name.return_value = "notepad.exe"
        with self.assertRaisesRegex(RuntimeError, "expected image"):
            self.executor._cmd_suspend_process(self.params)
        self.process.suspend.assert_not_called()


if __name__ == "__main__":
    unittest.main()
