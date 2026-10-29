"""Testler canli cloud'a lifecycle olayi sizdirmamali (client 60 hayalet self_update_begin)."""
import os
from unittest import mock

import client_lifecycle as cl


def test_isolation_env_set_by_conftest():
    assert os.environ.get("ASTERIA_TEST_ISOLATION") == "1"


def test_queue_not_written_under_isolation(tmp_path):
    q = tmp_path / "q.jsonl"
    with mock.patch.object(cl, "LIFECYCLE_QUEUE", str(q)):
        cl._append_queue({"event_type": "x"})
    assert not q.exists()


def test_load_token_empty_under_isolation():
    with mock.patch("client_utils.TokenStore.load", return_value="REAL-TOKEN"):
        assert cl.load_token() == ""


def test_report_now_never_posts_under_isolation():
    with mock.patch("client_utils.TokenStore.load", return_value="REAL-TOKEN"), \
         mock.patch("client_api.AsteriaAPIClient") as api:
        assert cl.report_now("self_update_begin", "dashboard_self_update",
                             {"tag": "4.9.62"}) is False
        api.assert_not_called()
