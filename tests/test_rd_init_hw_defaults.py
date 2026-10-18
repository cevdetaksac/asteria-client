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
                        argnames = {a.arg for a in item.args.args}
                        bare = names - argnames
                        self.assertNotIn("viewer_backend", bare)
                        self.assertNotIn("notify_user", bare)
                        self.assertNotIn("session_target", bare)
                        self.assertTrue(
                            'self._viewer_backend = "auto"' in src
                            or "self._viewer_backend = 'auto'" in src
                        )
                        return
        self.fail("__init__ not found")

if __name__ == "__main__":
    unittest.main()
