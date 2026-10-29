"""helper_log_missing false alarm: log rotation shrinks the file below the saved offset."""
import datetime as dt
import os
import client_utils as cu


def _setup(tmp_path, monkeypatch, content):
    p = tmp_path / "update-install.log"
    p.write_text(content, encoding="utf-8")
    monkeypatch.setattr(cu, "update_install_log_path", lambda: str(p))
    return p


def test_appended_marker_detected(tmp_path, monkeypatch):
    p = _setup(tmp_path, monkeypatch, "[2026-09-01 10:00:00] old line\n")
    off = os.path.getsize(p)
    with open(p, "a", encoding="utf-8") as fh:
        fh.write("[2026-10-29 20:00:00] helper_boot pid=1 ps=5.1\n")
    assert cu.fresh_helper_started(off, now=dt.datetime(2026, 10, 29, 20, 0, 5))


def test_rotation_shrink_still_detected(tmp_path, monkeypatch):
    big = "".join(f"[2026-09-01 10:00:{i%60:02d}] update-and-install start old\n" for i in range(500))
    p = _setup(tmp_path, monkeypatch, big)
    off = os.path.getsize(p)
    # helper rotates: old-day lines archived, file rewritten small, then new marker
    p.write_text("[2026-10-29 20:00:01] helper_boot pid=9\n[2026-10-29 20:00:02] update-and-install start\n", encoding="utf-8")
    assert os.path.getsize(p) < off
    assert cu.fresh_helper_started(off, now=dt.datetime(2026, 10, 29, 20, 0, 10))


def test_rotation_shrink_stale_markers_rejected(tmp_path, monkeypatch):
    big = "x" * 50000
    p = _setup(tmp_path, monkeypatch, big)
    off = os.path.getsize(p)
    p.write_text("[2026-09-01 10:00:00] update-and-install start (stale)\n", encoding="utf-8")
    assert not cu.fresh_helper_started(off, now=dt.datetime(2026, 10, 29, 20, 0, 10))


def test_no_new_bytes_false(tmp_path, monkeypatch):
    p = _setup(tmp_path, monkeypatch, "[2026-10-29 20:00:00] update-and-install start\n")
    assert not cu.fresh_helper_started(os.path.getsize(p))


def test_read_since_after_shrink_returns_all(tmp_path, monkeypatch):
    p = _setup(tmp_path, monkeypatch, "short\n")
    assert cu.read_update_log_since(10_000) == "short\n"