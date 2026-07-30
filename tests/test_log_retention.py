import datetime as dt
import logging
import os
import tempfile
import unittest
from unittest import mock

from client_log_retention import (
    DailyRetentionFileHandler,
    cleanup_daily_logs,
    daily_log_path,
)


class TestDailyLogRetention(unittest.TestCase):
    def test_daily_path_contains_calendar_date(self):
        with tempfile.TemporaryDirectory() as tmp:
            logical = os.path.join(tmp, "client.log")
            path = daily_log_path(logical, dt.date(2026, 7, 21))
            self.assertEqual(path, os.path.join(tmp, "client-2026-07-21.log"))

    def test_cleanup_keeps_exactly_seven_calendar_days(self):
        with tempfile.TemporaryDirectory() as tmp:
            logical = os.path.join(tmp, "client.log")
            today = dt.date(2026, 7, 21)
            for offset in range(9):
                path = daily_log_path(logical, today - dt.timedelta(days=offset))
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(str(offset))

            removed = cleanup_daily_logs(logical, 7, today=today)
            self.assertEqual(removed, 2)
            for offset in range(7):
                self.assertTrue(os.path.exists(
                    daily_log_path(logical, today - dt.timedelta(days=offset))
                ))
            self.assertFalse(os.path.exists(
                daily_log_path(logical, today - dt.timedelta(days=7))
            ))

    def test_handler_switches_file_when_day_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            logical = os.path.join(tmp, "client.log")
            day_one = dt.date(2026, 7, 21)
            day_two = day_one + dt.timedelta(days=1)
            with mock.patch(
                "client_log_retention.current_local_date",
                return_value=day_one,
            ):
                handler = DailyRetentionFileHandler(logical, retention_days=7)
                handler.setFormatter(logging.Formatter("%(message)s"))
                handler.emit(logging.LogRecord(
                    "test", logging.INFO, "", 0, "first", (), None
                ))
                with mock.patch(
                    "client_log_retention.current_local_date",
                    return_value=day_two,
                ):
                    handler.emit(logging.LogRecord(
                        "test", logging.INFO, "", 0, "second", (), None
                    ))
                handler.close()

            with open(daily_log_path(logical, day_one), encoding="utf-8") as fh:
                self.assertIn("first", fh.read())
            with open(daily_log_path(logical, day_two), encoding="utf-8") as fh:
                self.assertIn("second", fh.read())

    def test_handler_rolls_within_day_when_max_bytes_exceeded(self):
        with tempfile.TemporaryDirectory() as tmp:
            logical = os.path.join(tmp, "client.log")
            day = dt.date(2026, 7, 30)
            with mock.patch(
                "client_log_retention.current_local_date",
                return_value=day,
            ):
                handler = DailyRetentionFileHandler(
                    logical,
                    retention_days=7,
                    max_bytes=64,
                    backup_count=2,
                )
                handler.setFormatter(logging.Formatter("%(message)s"))
                for i in range(20):
                    handler.emit(logging.LogRecord(
                        "test", logging.INFO, "", 0, ("x" * 40) + str(i), (), None
                    ))
                handler.close()

            primary = daily_log_path(logical, day)
            part1 = primary.replace(".log", ".1.log")
            self.assertTrue(os.path.exists(primary))
            self.assertTrue(os.path.exists(part1))
            self.assertLessEqual(os.path.getsize(primary), 64 + 80)


if __name__ == "__main__":
    unittest.main()
