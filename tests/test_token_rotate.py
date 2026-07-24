#!/usr/bin/env python3
"""Contract 1.4.29 — rotate-token before disk; no bare register while old known."""

import json
import os
import tempfile
import unittest
from unittest import mock

import client_tokens as tokens


class TestRotateInPlace(unittest.TestCase):
    def setUp(self):
        tokens._FP_CACHE = None
        self.tmp = tempfile.TemporaryDirectory()
        self.pd = self.tmp.name
        self.token_path = os.path.join(self.pd, "token.dat")

    def tearDown(self):
        self.tmp.cleanup()
        tokens._FP_CACHE = None

    def test_schema_v2_uses_rotate_not_bare_register(self):
        bind = {"schema": 1, "fingerprint": "fp-now", "token_prefix": "oldtok12"}
        os.makedirs(self.pd, exist_ok=True)
        with open(os.path.join(self.pd, "device_binding.json"), "w", encoding="utf-8") as fh:
            json.dump(bind, fh)

        rotate_calls = []

        def _rotate(api_url, old, new, **kw):
            rotate_calls.append((old, new, kw.get("reason"), kw.get("machine_id")))
            return {
                "ok": True,
                "status_code": 200,
                "token": new,
                "client_id": 57,
                "rotated": True,
                "idempotent": False,
            }

        with mock.patch.object(tokens, "_programdata_client_dir", return_value=self.pd), \
                mock.patch.object(tokens, "get_canonical_token_path", return_value=self.token_path), \
                mock.patch.object(tokens, "get_device_fingerprint", return_value="fp-now"), \
                mock.patch.object(tokens, "get_windows_machine_guid", return_value="GUID"), \
                mock.patch.object(tokens, "get_legacy_token_paths", return_value=[]), \
                mock.patch.object(tokens.TokenStore, "load_meta", return_value=("old-token-uuid", "fp-now")), \
                mock.patch.object(tokens, "rotate_token_api", side_effect=_rotate), \
                mock.patch.object(tokens.TokenManager, "register_client") as reg, \
                mock.patch.object(tokens.TokenManager, "_persist_token") as persist:
            tm = tokens.TokenManager("https://example/api", "HOST", self.token_path, "token.txt")
            out = tm.ensure_hardware_binding()

        self.assertTrue(out)
        self.assertEqual(len(rotate_calls), 1)
        self.assertEqual(rotate_calls[0][0], "old-token-uuid")
        self.assertEqual(rotate_calls[0][2], "identity_v2")
        reg.assert_not_called()
        persist.assert_called_once()
        # Disk write only via persist after rotate ok — first arg is new uuid
        self.assertNotEqual(persist.call_args[0][0], "old-token-uuid")

    def test_rotate_409_retries_new_uuid(self):
        calls = {"n": 0}

        def _rotate(api_url, old, new, **kw):
            calls["n"] += 1
            if calls["n"] == 1:
                return {"ok": False, "status_code": 409, "detail": "new_token_in_use"}
            return {
                "ok": True, "status_code": 200, "token": new,
                "client_id": 1, "rotated": True, "idempotent": False,
            }

        with mock.patch.object(tokens, "get_device_fingerprint", return_value="fp"), \
                mock.patch.object(tokens, "get_windows_machine_guid", return_value="G"), \
                mock.patch.object(tokens, "rotate_token_api", side_effect=_rotate), \
                mock.patch.object(tokens.TokenManager, "_persist_token") as persist:
            tm = tokens.TokenManager("https://example/api", "HOST", self.token_path, "token.txt")
            out = tm._rotate_in_place("old-token", "identity_v2")
        self.assertTrue(out)
        self.assertGreaterEqual(calls["n"], 2)
        persist.assert_called_once()

    def test_rotate_fail_keeps_register_until_quarantine(self):
        """Failed rotate must not call register while old token still loaded."""
        with mock.patch.object(tokens, "get_device_fingerprint", return_value="fp"), \
                mock.patch.object(tokens, "get_windows_machine_guid", return_value="G"), \
                mock.patch.object(
                    tokens, "rotate_token_api",
                    return_value={"ok": False, "status_code": 500, "detail": "boom"},
                ), \
                mock.patch.object(tokens, "quarantine_local_identity") as quar, \
                mock.patch.object(tokens.TokenManager, "get_token", return_value="old-token"), \
                mock.patch.object(tokens.TokenManager, "register_client", return_value="fresh") as reg:
            tm = tokens.TokenManager("https://example/api", "HOST", self.token_path, "token.txt")
            out = tm._reenroll("identity_v2")
        # 500 → rotate returns None → quarantine then register
        quar.assert_called_once()
        reg.assert_called_once()
        self.assertEqual(out, "fresh")


class TestRotateTokenApiHelper(unittest.TestCase):
    def test_payload_and_bearer(self):
        from client_api import rotate_token_api

        class _Resp:
            status_code = 200
            content = b"{}"
            text = "{}"

            def json(self):
                return {
                    "status": "ok", "token": "new-uuid", "client_id": 9,
                    "rotated": True, "idempotent": False,
                }

        captured = {}

        def _post(url, json=None, headers=None, **kw):
            captured["url"] = url
            captured["json"] = json
            captured["headers"] = headers
            return _Resp()

        with mock.patch("requests.post", side_effect=_post), \
                mock.patch("client_api.resolve_tls_verify", return_value=True):
            out = rotate_token_api(
                "https://honeypot.yesnext.com.tr/api",
                "old-uuid",
                "new-uuid",
                machine_id="fp123",
                reason="identity_v2",
            )
        self.assertTrue(out["ok"])
        self.assertIn("/agent/rotate-token", captured["url"])
        self.assertEqual(captured["json"]["old_token"], "old-uuid")
        self.assertEqual(captured["json"]["new_token"], "new-uuid")
        self.assertEqual(captured["json"]["machine_id"], "fp123")
        self.assertTrue(captured["headers"]["Authorization"].startswith("Bearer old-uuid"))


if __name__ == "__main__":
    unittest.main()
