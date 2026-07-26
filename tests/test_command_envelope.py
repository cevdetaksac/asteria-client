#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Command envelope v2 observe tests (contract api/12, ≥1.4.37)."""

import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

import client_command_envelope as env


def _minimal_signable(**overrides):
    base = {
        "version": 2,
        "tenant_id": "00000000-0000-4000-8000-000000000001",
        "device_id": "00000000-0000-4000-8000-000000000002",
        "command_id": "00000000-0000-4000-8000-000000000003",
        "command_type": "ping",
        "params_hash": env.params_hash({}),
        "issued_at": "2026-07-22T00:00:00.000000Z",
        # Fixture doc uses +5m from issued_at; tests use a far-future expiry so
        # observe-verify still exercises sig/params after wall-clock moves on.
        "expires_at": "2999-01-01T00:00:00.000000Z",
        "nonce": "AAAAAAAAAAAAAAAAAAAAAA",
        "operator_id": "00000000-0000-4000-8000-000000000004",
        "key_id": "test-key-1",
        "policy_version": "test-policy-1",
        "approvals": [],
    }
    base.update(overrides)
    return base


def _valid_envelope(**overrides):
    body = _minimal_signable(**{
        k: v for k, v in overrides.items() if k != "signature"
    })
    if "signature" in overrides:
        body["signature"] = overrides["signature"]
    else:
        body["signature"] = env.fixture_sign(
            {k: v for k, v in body.items() if k != "signature"}
        )
    return body


class TestParamsHash(unittest.TestCase):
    def test_empty_object_matches_api12_vector(self):
        self.assertEqual(
            env.params_hash({}),
            "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
        )

    def test_hash_is_deterministic_and_order_independent(self):
        h1 = env.params_hash({"a": 1, "b": 2})
        h2 = env.params_hash({"b": 2, "a": 1})
        self.assertEqual(h1, h2)
        self.assertTrue(h1.startswith("sha256:"))


class TestCapability(unittest.TestCase):
    def test_default_is_off(self):
        with mock.patch("client_utils.get_from_config", return_value="off"):
            self.assertEqual(env.capability(), env.CAPABILITY_OFF)

    def test_observe_opt_in(self):
        with mock.patch("client_utils.get_from_config", return_value="observe"):
            self.assertEqual(env.capability(), env.CAPABILITY_OBSERVE)

    def test_enforce_is_never_advertised(self):
        with mock.patch("client_utils.get_from_config", return_value="enforce"):
            self.assertEqual(env.capability(), env.CAPABILITY_OFF)


class TestEnvelopeInspection(unittest.TestCase):
    def test_non_v2_is_not_v2(self):
        self.assertEqual(env.inspect_envelope_v2({"version": 1})["verdict"], "not_v2")

    def test_missing_required_field_is_malformed(self):
        bad = _valid_envelope()
        del bad["nonce"]
        self.assertEqual(env.inspect_envelope_v2(bad)["verdict"], "malformed")

    def test_expired_envelope(self):
        past = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
        e = _valid_envelope(expires_at=past)
        self.assertEqual(env.inspect_envelope_v2(e)["verdict"], "expired")

    def test_params_mismatch(self):
        e = _valid_envelope(params_hash=env.params_hash({"a": 1}))
        out = env.inspect_envelope_v2(e, params={"a": 999})
        self.assertEqual(out["verdict"], "params_mismatch")

    def test_unverified_without_key(self):
        e = _valid_envelope()
        out = env.inspect_envelope_v2(e, params={})
        self.assertEqual(out["verdict"], "unverified_no_key")

    def test_fixture_ed25519_observe_verify(self):
        _, pub = env.fixture_keypair()
        e = _valid_envelope()
        out = env.inspect_envelope_v2(e, params={}, public_key=pub)
        self.assertEqual(out["verdict"], "sig_ok")
        self.assertTrue(out["sig_ok"])

    def test_bad_signature_observe(self):
        _, pub = env.fixture_keypair()
        e = _valid_envelope(signature="AAAA")
        out = env.inspect_envelope_v2(e, params={}, public_key=pub)
        self.assertEqual(out["verdict"], "sig_invalid")

    def test_no_emit_api(self):
        for forbidden in ("emit_v2", "sign_envelope", "accept_command"):
            self.assertFalse(hasattr(env, forbidden))


if __name__ == "__main__":
    unittest.main()
