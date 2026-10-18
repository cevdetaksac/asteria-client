"""Regression: HW fields in __init__ must not reference undefined names."""
import unittest
import ast
from pathlib import Path

class InitNoNameError(unittest.TestCase):
    def test_init_does_not_use_bare_viewer_backend(self):
        src = Path("client_remote_desktop.py").read_text(encoding="utf-8")
        tree = ast.parse(src)
        for node in tree.body:
            if isinstance(node, ast.ClassDef) and node.name == "RemoteDesktopStreamer":
                for item in node.body:
                    if isinstance(item, ast.FunctionDef) and item.name == "__init__":
                        names = {n.id for n in ast.walk(item) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)}
                        # params of __init__ are fine; bare viewer_backend must not appear
                        argnames = {a.arg for a in item.args.args}
                        self.assertNotIn("viewer_backend", names - argnames)
                        self.assertNotIn("notify_user", names - argnames)
                        self.assertNotIn("session_target", names - argnames)
                        # defaults assigned
                        self.assertIn('self._viewer_backend = "auto"', src) or self.assertIn("self._viewer_backend = 'auto'", src)
                        return
        self.fail("__init__ not found")

if __name__ == "__main__":
    unittest.main()
