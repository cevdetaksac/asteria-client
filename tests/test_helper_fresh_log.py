# -*- coding: utf-8 -*-
"""Billur silent self_update: stale log must not count as helper_ok; no /end suicide."""
from pathlib import Path
from unittest import mock

import client_utils as cu


def _pd(tmp: Path):
    pd = tmp / "Asteria"
    pd.mkdir(parents=True, exist_ok=True)
    return pd


def test_archive_stale_log_removes_old_start(tmp_path, monkeypatch):
    pd = _pd(tmp_path)
    monkeypatch.setenv("ProgramData", str(tmp_path))
    log = pd / "update-install.log"
    log.write_text(
        "[2026-09-10 18:35:38] === update-and-install start ===\n"
        "[2026-10-18 02:05:24] preflight_fail detail=disk_low:C:\\ProgramData:115339264\n",
        encoding="utf-8",
    )
    assert cu.archive_stale_update_install_log(reason="unit") is True
    body = log.read_text(encoding="utf-8")
    assert "2026-09-10" not in body
    assert "disk_low" not in body
    assert "log_rotated" in body
    assert "update-and-install start" not in body


def test_fresh_helper_started_rejects_stale_tail(tmp_path, monkeypatch):
    pd = _pd(tmp_path)
    monkeypatch.setenv("ProgramData", str(tmp_path))
    log = pd / "update-install.log"
    log.write_text(
        "[2026-09-10 18:35:38] === update-and-install start ===\n"
        "[2026-10-18 02:05:24] preflight_fail detail=disk_low:C:\\ProgramData:1\n",
        encoding="utf-8",
    )
    off = log.stat().st_size
    assert "update-and-install start" in log.read_text(encoding="utf-8")[-2400:]
    assert cu.fresh_helper_started(off) is False
    with log.open("a", encoding="utf-8") as fh:
        fh.write("[2026-10-29 18:00:00] === update-and-install start ===\n")
    assert cu.fresh_helper_started(off) is True


def test_extract_preflight_fail_detail(tmp_path, monkeypatch):
    pd = _pd(tmp_path)
    monkeypatch.setenv("ProgramData", str(tmp_path))
    (pd / "update-install.log").write_text(
        "[2026-10-18 02:05:24] preflight_fail detail=disk_low:C:\\ProgramData:115339264\n"
        "[2026-10-29 12:00:00] launch_helper_failed detail=methods_exhausted\n",
        encoding="utf-8",
    )
    assert cu.extract_update_fail_detail() == "methods_exhausted"


def test_prepare_client_no_end_when_not_killing(monkeypatch, tmp_path):
    calls = []

    def fake_run(args, **kw):
        calls.append(list(args))
        class R:
            returncode = 0
        return R()

    import subprocess
    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(
        "client_self_protection.disarm_for_update",
        lambda **k: None,
    )
    # Avoid writing stop flags into real TEMP
    monkeypatch.setenv("TEMP", str(tmp_path))
    monkeypatch.setenv("APPDATA", str(tmp_path))
    monkeypatch.setenv("ProgramData", str(tmp_path))

    cu.prepare_client_for_installer(kill_processes=False)
    ends = [c for c in calls if len(c) >= 2 and c[0] == "schtasks" and c[1] == "/end"]
    disables = [c for c in calls if len(c) >= 2 and c[0] == "schtasks" and c[1] == "/change"]
    assert ends == [], f"must not /end when kill_processes=False, got {ends}"
    assert any("Asteria-Background" in c for c in disables)
