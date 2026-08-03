#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Account claim / unlink mail helpers."""

import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from client_api import request_unlink_confirmation, unlink_account_with_credentials  # noqa: E402
from client_utils import should_force_gui_visible  # noqa: E402


class TestUnlinkMail(unittest.TestCase):
    @mock.patch("client_api.resolve_tls_verify", return_value=True)
    @mock.patch("requests.post")
    def test_request_marks_mail_unavailable_on_404(self, mocked_post, _verify):
        resp = mock.Mock()
        resp.status_code = 404
        resp.content = b""
        mocked_post.return_value = resp
        out = request_unlink_confirmation("a@b.c", "pw", "tok", api_url="https://example.test/api")
        self.assertFalse(out.get("ok"))
        self.assertEqual(out.get("error"), "unlink_mail_unavailable")
        self.assertIs(out.get("mail_confirm"), False)

    @mock.patch("client_api.resolve_tls_verify", return_value=True)
    @mock.patch("requests.post")
    def test_unlink_maps_missing_confirm_not_invalid(self, mocked_post, _verify):
        resp = mock.Mock()
        resp.status_code = 422
        resp.content = b'{"detail":"missing_confirm_code"}'
        resp.json.return_value = {"detail": "missing_confirm_code"}
        resp.text = '{"detail":"missing_confirm_code"}'
        mocked_post.return_value = resp
        out = unlink_account_with_credentials("a@b.c", "pw", "tok")
        self.assertFalse(out.get("ok"))
        self.assertEqual(out.get("error"), "missing_confirm_code")


class TestForceGuiUntilClaim(unittest.TestCase):
    def test_token_without_link_keeps_gui_forced(self):
        with mock.patch("client_utils.is_account_linked", return_value=False), mock.patch(
            "client_utils.clear_force_gui_onboarding"
        ) as cleared, tempfile.TemporaryDirectory() as tmp:
            flag = os.path.join(tmp, "force_gui_onboarding.flag")
            with mock.patch("client_utils.onboarding_flag_path", return_value=flag):
                self.assertTrue(should_force_gui_visible(True))
                cleared.assert_not_called()

    def test_linked_clears_force_flag(self):
        with mock.patch("client_utils.is_account_linked", return_value=True), mock.patch(
            "client_utils.clear_force_gui_onboarding"
        ) as cleared:
            self.assertFalse(should_force_gui_visible(True))
            cleared.assert_called_once()


if __name__ == "__main__":
    unittest.main()
