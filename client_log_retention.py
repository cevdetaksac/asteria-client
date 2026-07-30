#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Calendar-day log files with bounded retention.

Daily files are opened directly (no midnight rename), which avoids rotation
races when the SYSTEM daemon and Guardian append to the same log family.

Optional ``max_bytes`` caps a single day's file; oversized content rolls to
``stem-YYYY-MM-DD.N.ext`` (kept within the same retention window).
"""

from __future__ import annotations

import datetime as dt
import logging
import os
import re
from typing import Optional


DEFAULT_RETENTION_DAYS = 7


def current_local_date() -> dt.date:
    return dt.datetime.now().astimezone().date()


def daily_log_path(logical_path: str, day: Optional[dt.date] = None) -> str:
    """Map ``client.log`` to ``client-YYYY-MM-DD.log``."""
    day = day or current_local_date()
    directory, filename = os.path.split(os.path.abspath(logical_path))
    stem, ext = os.path.splitext(filename)
    ext = ext or ".log"
    return os.path.join(directory, f"{stem}-{day.isoformat()}{ext}")


def cleanup_daily_logs(
    logical_path: str,
    retention_days: int = DEFAULT_RETENTION_DAYS,
    *,
    today: Optional[dt.date] = None,
    cleanup_legacy: bool = True,
) -> int:
    """Delete dated and legacy rotated logs older than the retention window."""
    today = today or current_local_date()
    retention_days = max(1, int(retention_days))
    cutoff = today - dt.timedelta(days=retention_days - 1)
    directory, filename = os.path.split(os.path.abspath(logical_path))
    stem, ext = os.path.splitext(filename)
    ext = ext or ".log"
    # Primary day files + within-day size parts: client-2026-07-30.1.log
    dated_re = re.compile(
        rf"^{re.escape(stem)}-(\d{{4}}-\d{{2}}-\d{{2}})(?:\.\d+)?{re.escape(ext)}$"
    )
    legacy_re = re.compile(rf"^{re.escape(filename)}(?:\.\d+)?$")
    removed = 0

    try:
        names = os.listdir(directory)
    except OSError:
        return 0

    for name in names:
        path = os.path.join(directory, name)
        remove = False
        match = dated_re.match(name)
        if match:
            try:
                remove = dt.date.fromisoformat(match.group(1)) < cutoff
            except ValueError:
                remove = False
        elif cleanup_legacy and legacy_re.match(name):
            try:
                modified = dt.datetime.fromtimestamp(
                    os.path.getmtime(path)
                ).astimezone().date()
                remove = modified < cutoff
            except OSError:
                remove = False

        if remove:
            try:
                os.remove(path)
                removed += 1
            except OSError:
                pass
    return removed


class DailyRetentionFileHandler(logging.FileHandler):
    """Append to a date-named file and switch safely at local midnight."""

    def __init__(
        self,
        logical_path: str,
        *,
        retention_days: int = DEFAULT_RETENTION_DAYS,
        encoding: str = "utf-8",
        max_bytes: int = 0,
        backup_count: int = 5,
    ):
        self.logical_path = os.path.abspath(logical_path)
        self.retention_days = max(1, int(retention_days))
        self.max_bytes = max(0, int(max_bytes or 0))
        self.backup_count = max(0, int(backup_count or 0))
        self._current_day = current_local_date()
        os.makedirs(os.path.dirname(self.logical_path) or ".", exist_ok=True)
        cleanup_daily_logs(
            self.logical_path,
            self.retention_days,
            today=self._current_day,
        )
        super().__init__(
            daily_log_path(self.logical_path, self._current_day),
            mode="a",
            encoding=encoding,
            delay=True,
        )

    @property
    def current_path(self) -> str:
        return daily_log_path(self.logical_path, self._current_day)

    def _rollover_by_size(self) -> None:
        """Rename current day file to .N and open a fresh day file."""
        if self.stream:
            try:
                self.flush()
            except Exception:
                pass
            try:
                self.stream.close()
            except Exception:
                pass
            self.stream = None

        base = os.path.abspath(self.baseFilename)
        directory, filename = os.path.split(base)
        stem, ext = os.path.splitext(filename)
        # Shift existing parts upward (highest first).
        for idx in range(self.backup_count, 0, -1):
            src = os.path.join(directory, f"{stem}.{idx}{ext}")
            if idx == self.backup_count:
                try:
                    if os.path.exists(src):
                        os.remove(src)
                except OSError:
                    pass
                continue
            dst = os.path.join(directory, f"{stem}.{idx + 1}{ext}")
            try:
                if os.path.exists(src):
                    os.replace(src, dst)
            except OSError:
                pass
        part1 = os.path.join(directory, f"{stem}.1{ext}")
        try:
            if os.path.exists(base):
                os.replace(base, part1)
        except OSError:
            try:
                os.remove(base)
            except OSError:
                pass
        self.baseFilename = base

    def emit(self, record: logging.LogRecord) -> None:
        day = current_local_date()
        if day != self._current_day:
            if self.stream:
                try:
                    self.flush()
                finally:
                    self.stream.close()
                self.stream = None
            self._current_day = day
            self.baseFilename = os.path.abspath(daily_log_path(self.logical_path, day))
            cleanup_daily_logs(
                self.logical_path,
                self.retention_days,
                today=day,
            )
        if self.max_bytes > 0:
            try:
                size = 0
                if self.stream is not None:
                    self.stream.seek(0, os.SEEK_END)
                    size = self.stream.tell()
                elif os.path.exists(self.baseFilename):
                    size = os.path.getsize(self.baseFilename)
                if size >= self.max_bytes:
                    self._rollover_by_size()
            except Exception:
                pass
        super().emit(record)
