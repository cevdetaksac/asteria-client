#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""RDP NLA LogonType-3 must classify as RDP (not Network)."""

import unittest

from client_eventlog import EventLogWatcher, note_rdp_source_ip, _RDP_IP_HINTS


class TestEventLogRdpNla(unittest.TestCase):
    def setUp(self):
        _RDP_IP_HINTS.clear()

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

    def test_ntlmssp_with_workstation_is_network(self):
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

    def test_ntlm_empty_workstation_is_rdp_before_ntlmssp(self):
        """mstsc NLA often NTLM+NtLmSsp with WorkstationName '-'."""
        data = {
            "LogonType": "3",
            "IpAddress": "203.0.113.8",
            "AuthenticationPackageName": "NTLM",
            "LogonProcessName": "NtLmSsp",
            "WorkstationName": "-",
        }
        self.assertEqual(EventLogWatcher._detect_service(4625, "Security", data), "RDP")
        self.assertEqual(EventLogWatcher._detect_port(4625, data), 3389)

    def test_1149_hint_promotes_type3(self):
        ip = "203.0.113.99"
        note_rdp_source_ip(ip)
        data = {
            "LogonType": "3",
            "IpAddress": ip,
            "AuthenticationPackageName": "NTLM",
            "LogonProcessName": "NtLmSsp",
            "WorkstationName": "BOX",
        }
        self.assertEqual(EventLogWatcher._detect_service(4625, "Security", data), "RDP")

    def test_131_hint_promotes_ntlmssp_fail(self):
        """Pre-auth RdpCoreTS 131 seeds hint — wrong-password spray never gets 1149."""
        ip = "203.0.113.50"
        note_rdp_source_ip(f"{ip}:54321")
        data = {
            "LogonType": "3",
            "IpAddress": ip,
            "AuthenticationPackageName": "NTLM",
            "LogonProcessName": "NtLmSsp",
            "WorkstationName": "DESKTOP-LAB",
        }
        self.assertEqual(EventLogWatcher._detect_service(4625, "Security", data), "RDP")
        self.assertEqual(EventLogWatcher._detect_port(4625, data), 3389)

    def test_131_extract_ip_from_clientip_port(self):
        ip = EventLogWatcher._extract_ip({"ClientIP": "198.51.100.7:49812"}, 131)
        self.assertEqual(ip, "198.51.100.7")

    def test_131_channel_is_rdp(self):
        self.assertEqual(
            EventLogWatcher._detect_service(
                131,
                "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational",
                {"ClientIP": "198.51.100.9:1"},
            ),
            "RDP",
        )


if __name__ == "__main__":
    unittest.main()
