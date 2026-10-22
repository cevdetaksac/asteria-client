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
        self.assertIn("contain_process", ALLOWED_COMMANDS)
        self.assertIn("suspend_process", REQUIRES_CONFIRMATION)
        self.assertIn("contain_process", REQUIRES_CONFIRMATION)
        self.assertNotIn("resume_process", REQUIRES_CONFIRMATION)
        self.assertIn("inspect_process", ALLOWED_COMMANDS)


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

    @mock.patch("client_contain.suspend_process")
    def test_suspend_exact_process(self, sus):
        sus.return_value = {
            "ok": True, "success": True, "code": "SUSPENDED", "message": "ok",
            "steps": [], "data": {"state": "suspended", "pid": 4242, "image": "sample.exe"},
        }
        result = self.executor._cmd_suspend_process(self.params)
        self.assertTrue(result["ok"] or result["success"])
        self.assertEqual(result["data"]["state"], "suspended")

    @mock.patch("client_contain.resume_process")
    def test_resume_exact_process(self, res):
        res.return_value = {
            "ok": True, "success": True, "code": "RESUMED", "message": "ok",
            "steps": [], "data": {"state": "running", "pid": 4242, "image": "sample.exe"},
        }
        result = self.executor._cmd_resume_process(self.params)
        self.assertTrue(result["ok"] or result["success"])
        self.assertEqual(result["data"]["state"], "running")

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


if __name__ == "__main__":
    unittest.main()
