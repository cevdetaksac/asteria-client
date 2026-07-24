#!/usr/bin/env python3
"""has_interactive_user_session must honor query session stdout even when rc!=0."""

import unittest
from unittest import mock

import client_helpers as h


_SAMPLE = (
    " SESSIONNAME               USERNAME                 ID  STATE   TYPE        DEVICE \r\n"
    " services                                            0  Disc                        \r\n"
    ">console                   caksac                    2  Active                      \r\n"
)


class TestInteractiveSessionDetect(unittest.TestCase):
    def test_rc1_with_active_stdout_is_true(self):
        with mock.patch("client_winproc.run_hidden", return_value=(1, _SAMPLE, "")):
            self.assertTrue(h.has_interactive_user_session())

    def test_parse_sample(self):
        self.assertTrue(h._stdout_has_active_interactive(_SAMPLE))

    def test_empty_rc1_falls_back_user(self):
        calls = [
            (1, "", ""),
            (0, " USERNAME              SESSIONNAME        ID  STATE\r\n caksac                console             2  Active\r\n", ""),
        ]

        def _rh(*_a, **_k):
            return calls.pop(0)

        with mock.patch("client_winproc.run_hidden", side_effect=_rh):
            self.assertTrue(h.has_interactive_user_session())


if __name__ == "__main__":
    unittest.main()
