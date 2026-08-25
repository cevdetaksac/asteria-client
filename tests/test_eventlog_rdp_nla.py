#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""RDP NLA LogonType-3 must classify as RDP (not Network)."""

import unittest

from client_eventlog import EventLogWatcher, note_rdp_source_ip


class TestEventLogRdpNla(unittest.TestCase):
    def test_logon_type_10_is_rdp(self):
        svc = EventLogWatcher._detect_service(
            4625, "Security", {"LogonType": "10", "IpAddress": "203.0.113.1"}
        )
        self.assertEqual(svc, "RDP")
        self.assertEqual(
            EventLogWatcher._detect_port(4625, {"LogonType": "10"}), 3389
        )

    def test_nla_negotiate_type3_is_rdp(self):
        data = {
            "LogonType": "3",
            "IpAddress": "203.0.113.2",
            "AuthenticationPackageName": "Negotiate",
            "LogonProcessName": "User32",
        }
        self.assertEqual(EventLogWatcher._detect_service(4625, "Security", data), "RDP")
        self.assertEqual(EventLogWatcher._detect_port(4625, data), 3389)

    def test_ntlmssp_type3_is_network(self):
        data = {
            "LogonType": "3",
            "IpAddress": "203.0.113.3",
            "AuthenticationPackageName": "NTLM",
            "LogonProcessName": "NtLmSsp",
            "WorkstationName": "SCANNER",
        }
        self.assertEqual(
            EventLogWatcher._detect_service(4625, "Security", data), "Network"
        )
        self.assertEqual(EventLogWatcher._detect_port(4625, data), 445)

    def test_1149_hint_promotes_type3(self):
        ip = "203.0.113.99"
        note_rdp_source_ip(ip)
        data = {
            "LogonType": "3",
            "IpAddress": ip,
            "AuthenticationPackageName": "NTLM",
            "LogonProcessName": "Unknown",
            "WorkstationName": "BOX",
        }
        self.assertEqual(EventLogWatcher._detect_service(4625, "Security", data), "RDP")


if __name__ == "__main__":
    unittest.main()
