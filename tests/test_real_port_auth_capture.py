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


class TestMssqlAuthLog(unittest.TestCase):
    def test_errorlog_client_ip(self):
        events = []
        w = AuthLogWatcher(on_event=events.append, interval_sec=2.0)
        w._emit_mssql_line(
            "2026-09-09 18:00:00.12 Logon       Error: 18456, Severity: 14, State: 8.\n"
            "Login failed for user 'sa'. Reason: Password did not match "
            "[CLIENT: 203.0.113.44]"
        )
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["target_service"], "MSSQL")
        self.assertEqual(events[0]["source_ip"], "203.0.113.44")
        self.assertEqual(events[0]["username"], "sa")
        self.assertEqual(events[0]["channel"], "mssql_errorlog")

    def test_skips_localhost(self):
        events = []
        w = AuthLogWatcher(on_event=events.append, interval_sec=2.0)
        w._emit_mssql_line(
            "Login failed for user 'sa'. Reason: Password did not match [CLIENT: 127.0.0.1]"
        )
        self.assertEqual(len(events), 0)


class TestAuthLogFileScan(unittest.TestCase):
    def test_scan_probe_files(self):
        import os
        import tempfile

        events = []
        with tempfile.TemporaryDirectory() as td:
            mysql_p = os.path.join(td, "mysql.err")
            ftp_p = os.path.join(td, "u_exftp.log")
            mssql_p = os.path.join(td, "ERRORLOG")
            with open(mysql_p, "w", encoding="utf-8") as fh:
                fh.write("seed\n")
            with open(ftp_p, "w", encoding="utf-8") as fh:
                fh.write("#Fields: date time c-ip cs-username cs-method sc-status s-port\n")
            with open(mssql_p, "w", encoding="utf-8") as fh:
                fh.write("seed\n")
            w = AuthLogWatcher(
                on_event=events.append,
                interval_sec=2.0,
                extra_globs=(
                    os.path.join(td, "mysql.err"),
                    os.path.join(td, "u_exftp.log"),
                    os.path.join(td, "ERRORLOG"),
                ),
            )
            # Prime offsets at EOF
            w._scan_file(mysql_p, kind="mysql")
            w._scan_file(ftp_p, kind="ftp")
            w._scan_file(mssql_p, kind="mssql")
            with open(mysql_p, "a", encoding="utf-8") as fh:
                fh.write(
                    "Access denied for user 'lab'@'198.51.100.9' (using password: YES)\n"
                )
            with open(ftp_p, "a", encoding="utf-8") as fh:
                fh.write("2026-09-09 12:00:01 198.51.100.10 ftpuser PASS 530 21\n")
            with open(mssql_p, "a", encoding="utf-8") as fh:
                fh.write(
                    "Login failed for user 'sa'. Reason: Password did not match "
                    "[CLIENT: 198.51.100.11]\n"
                )
            w._scan_file(mysql_p, kind="mysql")
            w._scan_file(ftp_p, kind="ftp")
            w._scan_file(mssql_p, kind="mssql")
            services = {e["target_service"] for e in events}
            self.assertEqual(services, {"MYSQL", "FTP", "MSSQL"})
            ips = {e["source_ip"] for e in events}
            self.assertEqual(ips, {"198.51.100.9", "198.51.100.10", "198.51.100.11"})

    def test_get_health_shape(self):
        w = AuthLogWatcher(on_event=lambda _e: None, interval_sec=2.0)
        h = w.get_health()
        self.assertIn("mysql_count", h)
        self.assertIn("ftp_count", h)
        self.assertIn("mssql_count", h)
        self.assertFalse(h["running"])


if __name__ == "__main__":
    unittest.main()
