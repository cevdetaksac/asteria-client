# -*- coding: utf-8 -*-
"""4.9.150 never-stuck updater: TLS, resume/retry, hash mismatch, rollback, stale state."""
import hashlib
import os
import subprocess
import time
from pathlib import Path

import pytest

import client_update_robust as R

ROOT = Path(__file__).resolve().parent.parent
HELPER = ROOT / "scripts" / "update-and-install.ps1"


class FakeResp:
    def __init__(self, code, body=b"", headers=None, fail_after=None):
        self.status_code = code
        self._body = body
        self.headers = headers or {"Content-Length": str(len(body))}
        self._fail_after = fail_after
        self.content = body

    def iter_content(self, chunk_size=1):
        sent = 0
        for i in range(0, len(self._body), 1024):
            if self._fail_after is not None and sent >= self._fail_after:
                raise ConnectionError("stall")
            c = self._body[i:i + 1024]
            sent += len(c)
            yield c


BODY = b"MZ" + os.urandom(64 * 1024)
SHA = hashlib.sha256(BODY).hexdigest()


# ---- TLS forced ----
def test_tls_forced_in_helper_and_all_scripts():
    t = HELPER.read_text(encoding="utf-8-sig")
    assert "Tls12" in t and "SecurityProtocol" in t
    assert "$ProgressPreference = 'SilentlyContinue'" in t or '$ProgressPreference = "SilentlyContinue"' in t
    # helper_boot is logged before the elevation check
    assert t.index("helper_boot") < t.index("IsInRole")
    for f in (ROOT / "scripts").glob("*.ps1"):
        if f.name in ("release.ps1", "rename-repo-folder.ps1", "seed_fake_blocks.ps1"):
            continue
        assert "SecurityProtocol" in f.read_text(encoding="utf-8-sig"), f.name


def test_preamble_inserted_after_param_block():
    src = "param(\n  [int]$a = 1,\n  [string]$b = (Get-Date)\n)\nWrite-Host hi\n"
    out = R.ensure_ps_preamble(src)
    assert out.index("param(") < out.index("SecurityProtocol") < out.index("Write-Host")
    assert R.ensure_ps_preamble(out) == out  # idempotent


def test_emergency_bootstrap_and_launchers_force_tls():
    from client_update_hardening import EMERGENCY_UPDATE_BOOTSTRAP_PS1
    assert "SecurityProtocol" in EMERGENCY_UPDATE_BOOTSTRAP_PS1
    utils = (ROOT / "client_utils.py").read_text(encoding="utf-8-sig")
    assert utils.count("SecurityProtocol -bor 3072") >= 4


# ---- download retry / resume ----
def test_download_resumes_after_stall(tmp_path):
    calls = []

    def get(url, headers=None, **kw):
        calls.append(dict(headers or {}))
        if len(calls) == 1:
            return FakeResp(200, BODY, fail_after=20 * 1024)
        rng = headers.get("Range", "")
        start = int(rng.split("=")[1].rstrip("-"))
        rest = BODY[start:]
        return FakeResp(206, rest, {"Content-Length": str(len(rest))})

    dest = str(tmp_path / "i.exe")
    ok, det = R.download_resumable(["https://m/x"], dest, expected_sha256=SHA,
                                   expected_size=len(BODY), http_get=get, sleep=lambda s: None)
    assert ok, det
    assert "Range" in calls[1]
    assert Path(dest).read_bytes() == BODY


def test_download_falls_back_to_next_url(tmp_path):
    def get(url, headers=None, **kw):
        if "mirror" in url:
            return FakeResp(502, b"")
        return FakeResp(200, BODY)
    ok, det = R.download_resumable(["https://mirror/x", "https://github/x"], str(tmp_path / "i.exe"),
                                   expected_sha256=SHA, http_get=get, sleep=lambda s: None)
    assert ok, det


def test_hash_mismatch_rejected_and_next_url_used(tmp_path):
    bad = b"MZ" + b"\x00" * len(BODY[2:])
    seen = []

    def get(url, headers=None, **kw):
        seen.append(url)
        return FakeResp(200, bad if "poisoned" in url else BODY)

    dest = tmp_path / "i.exe"
    ok, _ = R.download_resumable(["https://poisoned/x", "https://good/x"], str(dest),
                                 expected_sha256=SHA, http_get=get, sleep=lambda s: None)
    assert ok and dest.read_bytes() == BODY
    assert seen.count("https://poisoned/x") == 1  # no retry on poisoned source

    ok2, det2 = R.download_resumable(["https://poisoned/x"], str(tmp_path / "j.exe"),
                                     expected_sha256=SHA, http_get=get, sleep=lambda s: None)
    assert not ok2 and det2.startswith("hash_mismatch")
    assert not (tmp_path / "j.exe").exists()


def test_size_check(tmp_path):
    ok, det = R.download_resumable(["https://x"], str(tmp_path / "i.exe"),
                                   expected_size=len(BODY) + 10,
                                   http_get=lambda u, **k: FakeResp(200, BODY), sleep=lambda s: None,
                                   attempts_per_url=1)
    assert not ok and "incomplete" in det


def test_mirror_url_first_and_allowed():
    urls = R.asset_urls("4.9.150", R.INSTALLER_ASSET)
    assert urls[0].startswith("https://asteria.run/api/agent/releases/v4.9.150/")
    assert "github.com" in urls[1]
    assert R.is_mirror_url(urls[0]) and not R.is_mirror_url("https://evil.com/api/agent/releases/x")
    import client_updater as cu
    assert cu._is_allowed_update_url(urls[0])


def test_fresh_helper_requires_manifest_sha(tmp_path):
    assert R.fetch_fresh_helper("4.9.150", str(tmp_path), None) is None
    body = b"param()\nWrite-Host ok\n"
    man = {"assets": {R.HELPER_ASSET: {"sha256": hashlib.sha256(body).hexdigest(), "size": len(body) + 1024}}}
    # size too small vs manifest -> rejected
    p = R.fetch_fresh_helper("4.9.150", str(tmp_path), man,
                             http_get=lambda u, **k: FakeResp(200, body))
    assert p is None


# ---- timeout rollback ----
def test_helper_has_trap_and_rollback():
    t = HELPER.read_text(encoding="utf-8-sig")
    assert "trap {" in t and "Fail-Update 99" in t
    assert "installer_timeout" in t
    fail = t[t.index("function Fail-Update"):t.index("function Send-QuitCommand")]
    assert "Ensure-DaemonMotor" in fail and "AsteriaGuardian" in fail and "Clear-UpdateLock" in fail
    assert "Asteria-UpdateRescue-" in t  # disarm on success


def test_rescue_script_restores_agent():
    s = R.RESCUE_PS1
    assert "Stop-Process" in s and "asteria-client-installer" in s  # installer timeout kill
    assert "schtasks /run /tn 'Asteria-Background'" in s
    assert "/enable" in s and "update_in_progress.lock" in s
    assert all(ord(c) < 128 for c in s)


@pytest.mark.skipif(os.name != "nt", reason="PowerShell parser")
def test_ps_scripts_parse(tmp_path):
    rescue = tmp_path / "r.ps1"
    rescue.write_text(R.RESCUE_PS1, encoding="ascii")
    for f in [HELPER, rescue]:
        cmd = ("$e=$null;[void][System.Management.Automation.Language.Parser]::ParseFile('%s',[ref]$null,[ref]$e);"
               "if($e.Count){$e[0].Message;exit 1}" % str(f).replace("'", "''"))
        r = subprocess.run(["powershell", "-NoProfile", "-Command", cmd], capture_output=True, text=True)
        assert r.returncode == 0, (f, r.stdout, r.stderr)


def test_arm_rescue_task_builds_short_tr(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(R, "_schtasks", lambda a: calls.append(a) or 0)
    monkeypatch.setenv("ProgramData", str(tmp_path))
    name = R.arm_rescue_task(str(tmp_path), 4242, delay_min=20)
    assert name == "Asteria-UpdateRescue-4242"
    tr = calls[0][calls[0].index("/TR") + 1]
    assert len(tr) < 261 and "update-rescue.ps1" in tr
    assert "'Asteria-UpdateRescue-4242'" in (tmp_path / "update-rescue.ps1").read_text()


# ---- stale lock ----
def test_stale_state_expires(tmp_path, monkeypatch):
    monkeypatch.setenv("ProgramData", str(tmp_path))
    d = tmp_path / "Asteria"; d.mkdir()
    lock = d / "update_in_progress.lock"; lock.write_text("installing\n1\n")
    fresh = d / "last_update_fail.txt"; fresh.write_text("x")
    old = time.time() - 7200
    os.utime(lock, (old, old))
    removed = R.expire_stale_update_state(3600)
    assert str(lock) in removed and not lock.exists()
    assert fresh.exists()


def test_preflight_reports_perm_and_disk(tmp_path, monkeypatch):
    from client_update_hardening import preflight_update_ready
    inst = tmp_path / "i.exe"; inst.write_bytes(b"MZ" + b"0" * 2_000_000)
    monkeypatch.setenv("ProgramData", str(tmp_path))
    ok, det = preflight_update_ready(str(inst))
    assert ok, det
    import shutil as _sh
    monkeypatch.setattr(_sh, "disk_usage", lambda p: type("U", (), {"free": 10})())
    ok2, det2 = preflight_update_ready(str(inst))
    assert not ok2 and det2.startswith("disk_low")
