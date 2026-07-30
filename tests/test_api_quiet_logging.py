#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""API request logging must not dump high-frequency poll bodies."""

import inspect
import unittest
from unittest import mock

from client_api import AsteriaAPIClient


class TestApiRequestQuietDefaults(unittest.TestCase):
    def test_premium_tunnel_status_is_quiet(self):
        api = AsteriaAPIClient.__new__(AsteriaAPIClient)
        api.base_url = "https://asteria.run/api"
        api.session = mock.Mock()
        api._auth_token = "tok"
        api.log = mock.Mock()
        api._activate_legacy_failover = mock.Mock(return_value=False)
        api._prepare_request = mock.Mock(return_value=(None, None, {}))

        resp = mock.Mock()
        resp.status_code = 200
        resp.json.return_value = {"services": {"RDP": {"listen_port": 3389}}}
        api.session.request.return_value = resp

        with mock.patch("client_api.resolve_tls_verify", return_value=True):
            out = api.api_request("GET", "premium/tunnel-status")

        self.assertEqual(out["services"]["RDP"]["listen_port"], 3389)
        self.assertFalse(api.log.called)

    def test_default_verbose_logging_is_false(self):
        sig = inspect.signature(AsteriaAPIClient.api_request)
        self.assertFalse(sig.parameters["verbose_logging"].default)


if __name__ == "__main__":
    unittest.main()
