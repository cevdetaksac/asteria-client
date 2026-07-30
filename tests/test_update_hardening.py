#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Update immortality / PS 5.1 hardening tests."""

import os
import tempfile
import time
import unittest
from unittest import mock

from client_update_hardening import (
    EMERGENCY_UPDATE_BOOTSTRAP_PS1,
    assert_file_is_ascii,
    detect_launcher_only_storm,
    normalize_ps1_to_ascii,
    preflight_update_ready,
    validate_powershell_parse,
    write_ascii_ps1,
    write_emergency_bootstrap,
)


class TestNormalizeAscii(unittest.TestCase):
    def test_strips_emdash(self):
        raw = "waiting \u2014 up to 10s"
        out = normalize_ps1_to_ascii(raw)
        self.assertNotIn("\u2014", out)
        self.assertIn("-", out)
        self.assertTrue(all(ord(c) < 128 for c in out))

    def test_smart_quotes(self):
        raw = "\u201chello\u201d \u2018x\u2019"
        out = normalize_ps1_to_ascii(raw)
        self.assertEqual(out, '"hello" \'x\'')

    def test_emergency_bootstrap_is_ascii(self):
        self.assertTrue(all(ord(c) < 128 for c in EMERGENCY_UPDATE_BOOTSTRAP_PS1))
        self.assertIn("=== update-and-install start ===", EMERGENCY_UPDATE_BOOTSTRAP_PS1)

    def test_emergency_kills_asteria_and_guardian(self):
        body = EMERGENCY_UPDATE_BOOTSTRAP_PS1
        self.assertIn("asteria-client.exe", body)
        self.assertIn("asteria-gui.exe", body)
        self.assertIn("AsteriaGuardian", body)
        # Must not only watch legacy honeypot-client for "gone"
        self.assertIn('Get-Process -Name "asteria-client","asteria-gui","honeypot-client"', body)

    def test_method6_style_tr_stays_under_261(self):
        """Regression: embedding -InstallerPath on schtasks /TR exceeded 261 chars."""
        staging = r"C:\ProgramData\Asteria\update"
        nsis = os.path.join(staging, "run-nsis-12345.ps1")
        tr = (
            f'powershell.exe -NoProfile -ExecutionPolicy Bypass '
            f'-WindowStyle Hidden -File "{nsis}"'
        )
        self.assertLess(len(tr), 260, f"TR too long: {len(tr)} {tr}")
        # Old broken form for contrast
        inst = os.path.join(staging, "asteria-client-installer-4.9.65.exe")
        broken = (
            f'powershell.exe -NoProfile -ExecutionPolicy Bypass '
            f'-WindowStyle Hidden -File "{nsis}" '
            f'-InstallerPath "{inst}" -ExpectExitPid 12345 '
            f'-GraceWaitSec 20 -KillRounds 4 -Silent'
        )
        self.assertGreaterEqual(len(broken), 260)

class TestWriteAndParse(unittest.TestCase):
    def setUp(self):
        self._tdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tdir, ignore_errors=True)

    def test_write_rejects_non_ascii_payload(self):
        path = os.path.join(self._tdir, "bad.ps1")
        # write_ascii_ps1 normalizes — so result must be ascii
        self.assertTrue(write_ascii_ps1(path, "try { } catch { } # \u2014 dash"))
        self.assertTrue(assert_file_is_ascii(path))
        with open(path, "rb") as fh:
            data = fh.read()
        self.assertNotIn(b"\xe2\x80\x94", data)

    def test_broken_utf8_emdash_file_fails_ascii_gate(self):
        path = os.path.join(self._tdir, "broken.ps1")
        # Simulate old staged helper: UTF-8 em-dash, no BOM
        body = b'try {\n  Write-Host "hi \xe2\x80\x94 there"\n} catch {}\n'
        with open(path, "wb") as fh:
            fh.write(body)
        self.assertFalse(assert_file_is_ascii(path))

    def test_repo_helper_stages_and_parses(self):
        src = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "..",
            "scripts",
            "update-and-install.ps1",
        )
        src = os.path.normpath(src)
        self.assertTrue(os.path.isfile(src), f"missing {src}")
        with open(src, "r", encoding="utf-8", errors="replace") as fh:
            raw = fh.read()
        dst = os.path.join(self._tdir, "update-and-install.ps1")
        self.assertTrue(write_ascii_ps1(dst, raw))
        ok, detail = validate_powershell_parse(dst)
        self.assertTrue(ok, detail)

    def test_update_lock_survives_until_new_daemon_is_ready(self):
        src = os.path.normpath(os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "..", "scripts", "update-and-install.ps1",
        ))
        with open(src, "r", encoding="utf-8", errors="replace") as fh:
            raw = fh.read()
        ensure_idx = raw.rfind("Ensure-DaemonMotor -ExePath $exe")
        clear_idx = raw.rfind("Clear-UpdateLock")
        self.assertGreater(ensure_idx, 0)
        self.assertGreater(
            clear_idx,
            ensure_idx,
            "update lock must be cleared only after the new daemon is ready",
        )

    def test_update_log_retention_runs_before_first_main_log_line(self):
        src = os.path.normpath(os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "..", "scripts", "update-and-install.ps1",
        ))
        with open(src, "r", encoding="utf-8", errors="replace") as fh:
            raw = fh.read()
        main_idx = raw.index("# -- Main --")
        main = raw[main_idx:]
        retention_idx = main.index("Initialize-UpLogRetention")
        first_log_idx = main.index('Write-UpLog "=== update-and-install start ==="')
        self.assertLess(retention_idx, first_log_idx)

    def test_emergency_bootstrap_parses(self):
        dst = os.path.join(self._tdir, "emergency.ps1")
        path = write_emergency_bootstrap(dst)
        self.assertIsNotNone(path)
        ok, detail = validate_powershell_parse(path)
        self.assertTrue(ok, detail)

    def test_stage_update_install_helper_api(self):
        # Import after path setup — uses real scripts/
        import client_utils as cu

        # Point staging at temp via monkeypatch of helper dir
        orig = cu._update_helper_staging_dir
        cu._update_helper_staging_dir = lambda: self._tdir
        try:
            path = cu.stage_update_install_helper(allow_emergency=True)
            self.assertIsNotNone(path)
            self.assertTrue(assert_file_is_ascii(path))
            ok, detail = validate_powershell_parse(path)
            self.assertTrue(ok, detail)
        finally:
            cu._update_helper_staging_dir = orig

    def test_prefer_emergency_param_exists(self):
        import inspect
        import client_utils as cu
        self.assertIn(
            "prefer_emergency",
            inspect.signature(cu.launch_safe_update_install).parameters,
        )


class TestSelfUpdateHelperRetry(unittest.TestCase):
    def test_launch_helper_failed_retries_emergency(self):
        from client_updater import run_self_update_command

        calls = []

        def _launch(*args, **kwargs):
            calls.append(dict(kwargs))
            # First attempt fails; emergency retry succeeds enough to pass launch
            # but then helper_log check may still fail — return True on prefer_emergency
            if kwargs.get("prefer_emergency"):
                return True
            return False

        with mock.patch("client_updater._current_installed_version", return_value="4.9.54"), \
             mock.patch("client_utils.heal_update_machinery"), \
             mock.patch("client_utils.is_update_in_progress", return_value=False), \
             mock.patch("client_utils.acquire_update_lock"), \
             mock.patch("client_utils.pause_competing_updaters"), \
             mock.patch("client_utils.release_update_lock"), \
             mock.patch("client_utils.stage_installer_for_update", return_value=r"C:\tmp\inst.exe"), \
             mock.patch("client_updater._is_allowed_update_url", return_value=True), \
             mock.patch(
                 "client_updater.download_installer_complete",
                 return_value=(True, "complete"),
             ), \
             mock.patch("os.path.isfile", return_value=True), \
             mock.patch("os.path.getsize", return_value=1000), \
             mock.patch("client_utils.launch_safe_update_install", side_effect=_launch), \
             mock.patch("client_updater._lifecycle_fail"), \
             mock.patch("client_update_ui.set_update_ui_status"), \
             mock.patch("client_helpers.has_interactive_user_session", return_value=False):
            # helper log verify may fail — open mock
            with mock.patch("builtins.open", mock.mock_open(read_data="update-and-install start\n")):
                out = run_self_update_command(
                    {
                        "tag": "4.9.63",
                        "download_url": (
                            "https://github.com/cevdetaksac/asteria-client/"
                            "releases/download/v4.9.63/cloud-client-installer.exe"
                        ),
                        "force": True,
                        "size": 1000,
                    },
                    api_client=None,
                )
        self.assertGreaterEqual(len(calls), 2)
        self.assertFalse(calls[0].get("prefer_emergency"))
        self.assertTrue(calls[1].get("prefer_emergency"))
        self.assertTrue(out.get("restart_required") or out.get("ok") or out.get("error") == "install_failed")


class TestPreflightAndStorm(unittest.TestCase):
    def setUp(self):
        self._tdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tdir, ignore_errors=True)

    def test_preflight_missing(self):
        ok, detail = preflight_update_ready(os.path.join(self._tdir, "nope.exe"))
        self.assertFalse(ok)
        self.assertEqual(detail, "installer_missing")

    def test_preflight_too_small(self):
        path = os.path.join(self._tdir, "tiny.exe")
        with open(path, "wb") as fh:
            fh.write(b"MZ" + b"\0" * 100)
        ok, detail = preflight_update_ready(path)
        self.assertFalse(ok)
        self.assertTrue(detail.startswith("installer_too_small"), detail)

    def test_launcher_storm(self):
        log_path = os.path.join(self._tdir, "update-install.log")
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        lines = [f"[{now}] launcher start launch-{i}-x pid={i}\n" for i in range(6)]
        with open(log_path, "w", encoding="utf-8") as fh:
            fh.writelines(lines)
        self.assertTrue(detect_launcher_only_storm(log_path, min_hits=4))

    def test_no_storm_when_helper_started(self):
        log_path = os.path.join(self._tdir, "update-install.log")
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        with open(log_path, "w", encoding="utf-8") as fh:
            for i in range(6):
                fh.write(f"[{now}] launcher start launch-{i}-x pid={i}\n")
            fh.write(f"[{now}] === update-and-install start ===\n")
        self.assertFalse(detect_launcher_only_storm(log_path, min_hits=4))


class TestRealStagedRegression(unittest.TestCase):
    """Reproduce the production bug: UTF-8 em-dash without BOM breaks PS 5.1 parse."""

    def setUp(self):
        self._tdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tdir, ignore_errors=True)

    def test_emdash_script_fails_parse_gate_ascii(self):
        path = os.path.join(self._tdir, "uai.ps1")
        # Minimal try/catch with em-dash inside a double-quoted string (the real failure mode)
        broken = (
            'try {\n'
            '  Write-Host "Installer PID=$($p.Id) \u2014 waiting"\n'
            '} catch {\n'
            '  exit 1\n'
            '}\n'
        )
        # Write as UTF-8 without BOM (what broke production)
        with open(path, "wb") as fh:
            fh.write(broken.encode("utf-8"))
        self.assertFalse(assert_file_is_ascii(path))
        # After normalize+rewrite, parse must succeed
        fixed = os.path.join(self._tdir, "fixed.ps1")
        self.assertTrue(write_ascii_ps1(fixed, broken))
        ok, detail = validate_powershell_parse(fixed)
        self.assertTrue(ok, detail)


if __name__ == "__main__":
    unittest.main()
