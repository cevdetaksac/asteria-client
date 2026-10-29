"""Billur sessiz kurulum hatası: açılışta sürüm hedefin altındaysa cloud'a bir kez rapor."""
import json
import os
import time
from unittest import mock

import client_update_outcome as uo


def _status(tmp, **kw):
    d = {"phase": "installing", "from_version": "4.9.146", "to_version": "4.9.147",
         "detail": "helper_launched", "updated_at": time.time() - 60}
    d.update(kw)
    (tmp / "update_ui_status.json").write_text(json.dumps(d), encoding="utf-8")


def _env(tmp):
    return mock.patch.dict(os.environ, {"ProgramData": str(tmp.parent)})


def test_reports_once_when_still_old(tmp_path):
    pd = tmp_path / "Asteria"; pd.mkdir()
    _status(pd)
    (pd / "update-install.log").write_text("update-and-install start\ninstaller exit=2 token=" + "A" * 40 + "\n",
                                           encoding="utf-8")
    with _env(pd), mock.patch("client_lifecycle.report_now") as rn:
        assert uo.report_post_restart_failure("4.9.146") is True
        args, kw = rn.call_args
        assert args[0] == "self_update_failed" and args[1] == "post_restart_still_old"
        info = args[2]
        assert info["to_version"] == "4.9.147" and info["running_version"] == "4.9.146"
        assert any("installer exit=2" in l for l in info["helper_log_tail"])
        assert not any("A" * 40 in l for l in info["helper_log_tail"])  # sır maskelenir
        rn.reset_mock()
        assert uo.report_post_restart_failure("4.9.146") is False  # tekrar yok
        rn.assert_not_called()


def test_no_report_when_on_target_or_stale(tmp_path):
    pd = tmp_path / "Asteria"; pd.mkdir()
    _status(pd)
    with _env(pd), mock.patch("client_lifecycle.report_now") as rn:
        assert uo.report_post_restart_failure("4.9.147") is False
        _status(pd, updated_at=time.time() - 7 * 3600)
        assert uo.report_post_restart_failure("4.9.146") is False
        _status(pd, phase="done")
        assert uo.report_post_restart_failure("4.9.146") is False
        rn.assert_not_called()
