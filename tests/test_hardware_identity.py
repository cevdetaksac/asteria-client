#!/usr/bin/env python3
"""Hardware-bound agent identity (MAC + MachineGuid fingerprint)."""

import hashlib
import json
import os
import tempfile
import unittest
from unittest import mock

import client_tokens as tokens


class TestDeviceFingerprint(unittest.TestCase):
    def setUp(self):
        tokens._FP_CACHE = None

    def tearDown(self):
        tokens._FP_CACHE = None

    def test_fingerprint_changes_when_mac_changes(self):
        with mock.patch.object(tokens, "get_windows_machine_guid", return_value="GUID-A"), \
                mock.patch.object(tokens, "get_smbios_uuid", return_value="SMB-1"), \
                mock.patch.object(tokens, "get_volume_serial_fallback", return_value="vol1"), \
                mock.patch.object(tokens, "get_nic_macs", return_value=["aabbccddeeff"]):
            tokens._FP_CACHE = None
            fp1 = tokens.get_device_fingerprint(force_refresh=True)
        with mock.patch.object(tokens, "get_windows_machine_guid", return_value="GUID-A"), \
                mock.patch.object(tokens, "get_smbios_uuid", return_value="SMB-1"), \
                mock.patch.object(tokens, "get_volume_serial_fallback", return_value="vol1"), \
                mock.patch.object(tokens, "get_nic_macs", return_value=["112233445566"]):
            tokens._FP_CACHE = None
            fp2 = tokens.get_device_fingerprint(force_refresh=True)
        self.assertNotEqual(fp1, fp2)
        self.assertEqual(len(fp1), 64)

    def test_same_inputs_same_fingerprint(self):
        with mock.patch.object(tokens, "get_windows_machine_guid", return_value="G"), \
                mock.patch.object(tokens, "get_smbios_uuid", return_value="S"), \
                mock.patch.object(tokens, "get_volume_serial_fallback", return_value="V"), \
                mock.patch.object(tokens, "get_nic_macs", return_value=["aa", "bb"]):
            tokens._FP_CACHE = None
            a = tokens.get_device_fingerprint(force_refresh=True)
            tokens._FP_CACHE = None
            b = tokens.get_device_fingerprint(force_refresh=True)
        self.assertEqual(a, b)
        raw = "v2|G|aa,bb|S|V"
        self.assertEqual(a, hashlib.sha256(raw.encode()).hexdigest())


class TestHardwareBinding(unittest.TestCase):
    def setUp(self):
        tokens._FP_CACHE = None
        self.tmp = tempfile.TemporaryDirectory()
        self.pd = self.tmp.name
        self.token_path = os.path.join(self.pd, "token.dat")

    def tearDown(self):
        self.tmp.cleanup()
        tokens._FP_CACHE = None

    def test_fingerprint_mismatch_triggers_reenroll(self):
        with mock.patch.object(tokens, "_programdata_client_dir", return_value=self.pd), \
                mock.patch.object(tokens, "get_canonical_token_path", return_value=self.token_path), \
                mock.patch.object(tokens, "get_device_fingerprint", return_value="fp-now"), \
                mock.patch.object(tokens, "get_windows_machine_guid", return_value="G"), \
                mock.patch.object(tokens, "get_legacy_token_paths", return_value=[]), \
                mock.patch.object(tokens.TokenStore, "load_meta", return_value=("old-token-uuid", "fp-old")), \
                mock.patch.object(
                    tokens, "rotate_token_api",
                    return_value={
                        "ok": True, "status_code": 200, "token": "rotated-uuid",
                        "client_id": 1, "rotated": True, "idempotent": False,
                    },
                ), \
                mock.patch.object(tokens.TokenManager, "_persist_token") as persist, \
                mock.patch.object(tokens.TokenManager, "register_client") as reg:
            tm = tokens.TokenManager("https://example", "HOST", self.token_path, "token.txt")
            out = tm.ensure_hardware_binding()
        self.assertEqual(out, "rotated-uuid")
        persist.assert_called_once()
        reg.assert_not_called()

    def test_schema_v2_upgrade_reenrolls_once(self):
        bind = {
            "schema": 1,
            "fingerprint": "fp-now",
            "token_prefix": "oldtok12",
        }
        os.makedirs(self.pd, exist_ok=True)
        with open(os.path.join(self.pd, "device_binding.json"), "w", encoding="utf-8") as fh:
            json.dump(bind, fh)

        with mock.patch.object(tokens, "_programdata_client_dir", return_value=self.pd), \
                mock.patch.object(tokens, "get_canonical_token_path", return_value=self.token_path), \
                mock.patch.object(tokens, "get_device_fingerprint", return_value="fp-now"), \
                mock.patch.object(tokens, "get_windows_machine_guid", return_value="G"), \
                mock.patch.object(tokens, "get_legacy_token_paths", return_value=[]), \
                mock.patch.object(tokens.TokenStore, "load_meta", return_value=("old-token-uuid", "fp-now")), \
                mock.patch.object(
                    tokens, "rotate_token_api",
                    return_value={
                        "ok": True, "status_code": 200, "token": "fresh-token",
                        "client_id": 57, "rotated": True, "idempotent": False,
                    },
                ), \
                mock.patch.object(tokens.TokenManager, "_persist_token") as persist, \
                mock.patch.object(tokens.TokenManager, "register_client") as reg:
            tm = tokens.TokenManager("https://example", "HOST", self.token_path, "token.txt")
            out = tm.ensure_hardware_binding()
        self.assertEqual(out, "fresh-token")
        persist.assert_called_once()
        reg.assert_not_called()


if __name__ == "__main__":
    unittest.main()
