#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Sleep/wake resume grace must not report false persistence dead-man."""

import unittest
from unittest import mock

import client_power_presence as power
import client_tamper as tamper


class TestResumeGrace(unittest.TestCase):
    def tearDown(self):
        power._resume_grace_until = 0.0

    def test_note_and_in_grace(self):
        power.note_resume_grace(30)
        self.assertTrue(power.in_resume_grace())
        power._resume_grace_until = 0.0
        self.assertFalse(power.in_resume_grace())

    def test_persistence_optimistic_during_grace(self):
        power.note_resume_grace(60)
        with mock.patch.object(
            tamper, "get_persistence_status", wraps=tamper.get_persistence_status
        ):
            pass
        with mock.patch(
            "client_guardian_service.is_guardian_service_running",
            return_value=False,
        ), mock.patch(
            "client_guardian_service.is_guardian_service_installed",
            return_value=True,
        ), mock.patch(
            "client_daemon_ipc.is_motor_healthy",
            return_value=False,
        ), mock.patch(
            "client_operator_stop.is_operator_stop_active",
            return_value=False,
        ), mock.patch(
            "client_resilience.snapshot",
            return_value={},
        ):
            st = tamper.get_persistence_status()
        self.assertTrue(st.get("resume_grace"))
        self.assertTrue(st.get("daemon_ok"))
        self.assertFalse(st.get("daemon_ok_raw"))
        self.assertTrue(st.get("service_ok"))


if __name__ == "__main__":
    unittest.main()
