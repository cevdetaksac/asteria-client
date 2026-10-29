"""Console blacklist: protected deletes, normalization bypasses, format false-positive."""
import os, sys, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import console_blacklist as bl

BLOCKED = [
    "format c:", "FORMAT.COM D: /q", "cmd /c format c:", "echo x & format c:",
    "vssadmin delete shadows /all", "powershell -EncodedCommand ZQBjAGgAbwA=",
    "Remove-Item C:\\ -Recurse -Force", "ri c:\\* -r -fo", "rm -r -fo 'C:\\'",
    "del /s /q C:\\*", "erase /f /s /q c:\\*.*", "rd /s /q C:\\Windows", "r^d /s c:\\",
    'd^el /s /q "C:\\Program Files"', "del /q %SystemRoot%\\System32\\*",
    "Remove-Item $env:windir -Recurse", "Remove-Item ${env:ProgramData}\\Asteria -Recurse",
    "rmdir C:\\Users", "del /q %FOO%\\x", 'Remove-Item -Path "C:/Windows/System32" -Recurse',
    "rm -Recurse -Force *", "Remove-Item C:\\ProgramData\\Asteria\\x.log",
    "Remove-Item \\\\?\\C:\\ -Recurse", "REMOVE-ITEM 'C:\\PROGRAM FILES (X86)' -RECURSE",
    "del /s /q \"%ProgramFiles%\"", "Remove-Item `C:\\Windows -Recurse",
]
ALLOWED = [
    "hostname", "whoami", "Get-PSDrive C", "Get-Process | Format-Table -AutoSize",
    "Get-Service | Format-List", "Get-ChildItem C:\\ -Recurse -File -Include *.bak | Format-Table",
    "[math]::Round(1.5)", "Remove-Item C:\\temp\\old.log", "del C:\\temp\\x.txt",
    "rm -r C:\\temp\\build", "dir C:\\Windows", "Get-ChildItem C:\\", "ipconfig /all",
]


class TestBlacklistPaths(unittest.TestCase):
    def test_blocked(self):
        for c in BLOCKED:
            with self.subTest(c=c):
                self.assertTrue(bl.is_blocked(c, "powershell")[0], c)
                self.assertTrue(bl.is_blocked(c, "cmd")[0], c)

    def test_allowed(self):
        for c in ALLOWED:
            with self.subTest(c=c):
                self.assertFalse(bl.is_blocked(c, "powershell")[0], (c, bl.is_blocked(c)))

    def test_normalize_does_not_change_exec_text_quotes(self):
        self.assertEqual(bl.normalize_command('echo "a b"'), 'echo "a b"')


if __name__ == "__main__":
    unittest.main()