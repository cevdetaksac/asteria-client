#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Real-port auth: OpenSSH Operational + MySQL error log + listen ports."""

import unittest
from unittest import mock

from client_eventlog import EventLogWatcher
from client_auth_log_watchers import AuthLogWatcher, _MYSQL_DENIED
from client_service_ports import (
    get_listen_port,
    set_listen_port,
    update_from_open_ports,
)


class TestOpenSshParse(unittest.TestCase):
    def test_failed_password(self):
        msg = "sshd: Failed password for admin from 203.0.113.9 port 51234 ssh2"
        parsed = EventLogWatcher._parse_openssh_message(msg)
        self.assertEqual(parsed["event_type"], "failed_logon")
        self.assertEqual(parsed["username"], "admin")
        self.assertEqual(parsed["source_ip"], "203.0.113.9")
        self.assertEqual(parsed["port"], 51234)

    def test_invalid_user(self):
        msg = "sshd: Invalid user root from 198.51.100.2 port 22"
        parsed = EventLogWatcher._parse_openssh_message(msg)
        self.assertEqual(parsed["event_type"], "failed_logon")
        self.assertEqual(parsed["username"], "root")

    def test_noise_ignored(self):
        self.assertIsNone(
            EventLogWatcher._parse_openssh_message("sshd: Server listening on 0.0.0.0 port 22.")
        )

    def test_detect_service_openssh_channel(self):
        self.assertEqual(
            EventLogWatcher._detect_service(4, "OpenSSH/Operational", {}),
            "SSH",
        )


class TestListenPorts(unittest.TestCase):
    def test_rdp_relocate_port_used(self):
        set_listen_port("RDP", 43389)
        self.assertEqual(get_listen_port("RDP", 3389), 43389)
        port = EventLogWatcher._detect_port(
            4625,
            {
                "LogonType": "10",
                "IpAddress": "1.2.3.4",
            },
            "",
        )
        self.assertEqual(port, 43389)
        set_listen_port("RDP", 3389)

    def test_open_ports_sshd(self):
        update_from_open_ports(
            [{"port": 40022, "process": "sshd.exe", "state": "LISTEN"}]
        )
        self.assertEqual(get_listen_port("SSH", 22), 40022)
        set_listen_port("SSH", 22)


class TestMysqlAuthLog(unittest.TestCase):
    def test_regex(self):
        line = "2026-08-26T12:00:00 Access denied for user 'root'@'203.0.113.50' (using password: YES)"
        m = _MYSQL_DENIED.search(line)
        self.assertTrue(m)
        self.assertEqual(m.group(1), "root")
        self.assertEqual(m.group(2), "203.0.113.50")

    def test_emit_to_callback(self):
        events = []
        w = AuthLogWatcher(on_event=events.append, interval_sec=2.0)
        w._emit_mysql_line(
            "Access denied for user 'bob'@'203.0.113.77' (using password: YES)"
        )
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["target_service"], "MYSQL")
        self.assertEqual(events[0]["source_ip"], "203.0.113.77")
        self.assertEqual(events[0]["event_type"], "sql_failed_logon")


class TestFtpAuthLog(unittest.TestCase):
    def test_w3c_530(self):
        events = []
        w = AuthLogWatcher(on_event=events.append, interval_sec=2.0)
        path = r"C:\inetpub\logs\LogFiles\FTPSVC1\u_ex.test.log"
        w._emit_ftp_line(
            path,
            "#Fields: date time c-ip cs-username cs-method sc-status s-port",
        )
        w._emit_ftp_line(
            path,
            "2026-08-26 12:00:01 203.0.113.88 administrator PASS 530 21",
        )
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["target_service"], "FTP")
        self.assertEqual(events[0]["source_ip"], "203.0.113.88")
        self.assertEqual(events[0]["username"], "administrator")
        self.assertEqual(events[0]["status"], "530")


if __name__ == "__main__":
    unittest.main()
