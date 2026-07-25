#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ZT-600 observe: local counters + deterministic v1 vectors (no wire fields)."""

import os
import unittest
from unittest import mock

from client_security_utils import (
    inspect_command_signature,
    sign_command,
    verify_command_signature,
)


# Fixed vector material — cloud must match COMPUTERNAME + issued_at verbatim.
_VECTOR_HOST = "TESTHOST"
_VECTOR_TOKEN = "vector-token-0001"
_VECTOR_ID = "cmd-vector-1"
_VECTOR_TYPE = "block_ip"
_VECTOR_ISSUED = "2026-07-22T00:00:00+00:00"
# Precomputed with COMPUTERNAME=TESTHOST (regenerate if algorithm changes).
_VECTOR_SIG = (
    "90a4879eecc999c6e4002669a70624487e659a11d691552ac7b1ba924d504d38"
)


def _with_host(name: str):
    return mock.patch.dict(os.environ, {"COMPUTERNAME": name}, clear=False)


class TestInspectCommandSignature(unittest.TestCase):
    def test_missing_soft_allows_but_reports_missing(self):
        with _with_host(_VECTOR_HOST):
            cmd = {
                "id": _VECTOR_ID,
                "type": _VECTOR_TYPE,
                "issued_at": _VECTOR_ISSUED,
            }
            self.assertEqual(
                inspect_command_signature(_VECTOR_TOKEN, cmd), "missing"
            )
            self.assertTrue(verify_command_signature(_VECTOR_TOKEN, cmd))

    def test_invalid_rejects(self):
        with _with_host(_VECTOR_HOST):
            cmd = {
                "id": _VECTOR_ID,
                "type": _VECTOR_TYPE,
                "issued_at": _VECTOR_ISSUED,
                "signature": "deadbeef",
            }
            self.assertEqual(
                inspect_command_signature(_VECTOR_TOKEN, cmd), "invalid"
            )
            self.assertFalse(verify_command_signature(_VECTOR_TOKEN, cmd))

    def test_ok_round_trip_under_fixed_hostname(self):
        with _with_host(_VECTOR_HOST):
            sig = sign_command(
                _VECTOR_TOKEN, _VECTOR_ID, _VECTOR_TYPE, _VECTOR_ISSUED
            )
            self.assertEqual(sig, _VECTOR_SIG)
            cmd = {
                "id": _VECTOR_ID,
                "type": _VECTOR_TYPE,
                "issued_at": _VECTOR_ISSUED,
                "signature": sig,
            }
            self.assertEqual(inspect_command_signature(_VECTOR_TOKEN, cmd), "ok")
            self.assertTrue(verify_command_signature(_VECTOR_TOKEN, cmd))
            self.assertEqual(len(sig), 64)
            self.assertRegex(sig, r"^[0-9a-f]{64}$")

    def test_command_type_alias_alone_does_not_match_type_field(self):
        """Verifier prefers type/command — not command_type (contract alias trap)."""
        with _with_host(_VECTOR_HOST):
            sig = sign_command(
                _VECTOR_TOKEN, _VECTOR_ID, _VECTOR_TYPE, _VECTOR_ISSUED
            )
            cmd = {
                "command_id": _VECTOR_ID,
                "command_type": _VECTOR_TYPE,
                "issued_at": _VECTOR_ISSUED,
                "signature": sig,
            }
            # Empty preferred type → digest mismatch → invalid
            self.assertEqual(
                inspect_command_signature(_VECTOR_TOKEN, cmd), "invalid"
            )

    def test_no_token_and_disabled(self):
        with _with_host(_VECTOR_HOST):
            cmd = {
                "id": _VECTOR_ID,
                "type": _VECTOR_TYPE,
                "issued_at": _VECTOR_ISSUED,
                "signature": "abcd",
            }
            self.assertEqual(inspect_command_signature("", cmd), "no_token")
            with mock.patch(
                "client_security_utils.command_signing_enabled",
                return_value=False,
            ):
                self.assertEqual(
                    inspect_command_signature(_VECTOR_TOKEN, cmd), "disabled"
                )
                self.assertTrue(verify_command_signature(_VECTOR_TOKEN, cmd))


class TestRemoteCommandObserveCounters(unittest.TestCase):
    def _make_executor(self, token="tok"):
        from client_remote_commands import RemoteCommandExecutor

        return RemoteCommandExecutor(
            api_client=None,
            token_getter=lambda: token,
        )

    def test_missing_signature_increments_observe_and_still_validates_other_rules(self):
        ex = self._make_executor()
        with _with_host(_VECTOR_HOST):
            rejection = ex._validate({
                "command_id": "c1",
                "command_type": "block_ip",
                "issued_at": _VECTOR_ISSUED,
                "parameters": {"ip": "203.0.113.10"},
            })
        # Missing sig is observed but not rejected; may still pass whitelist checks
        self.assertNotEqual(rejection, "Invalid command signature")
        self.assertEqual(ex.get_stats()["signature_missing"], 1)
        self.assertEqual(ex.get_stats()["signature_ok"], 0)

    def test_invalid_signature_rejects_and_counts(self):
        ex = self._make_executor()
        with _with_host(_VECTOR_HOST):
            rejection = ex._validate({
                "command_id": "c1",
                "command_type": "block_ip",
                "type": "block_ip",
                "id": "c1",
                "issued_at": _VECTOR_ISSUED,
                "signature": "00" * 32,
                "parameters": {"ip": "203.0.113.10"},
            })
        self.assertEqual(rejection, "Invalid command signature")
        self.assertEqual(ex.get_stats()["signature_invalid"], 1)


if __name__ == "__main__":
    unittest.main()
