#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""C-BRICK-1 / C-BRICK-6 / command-result wire guards."""

import time
import unittest
from unittest import mock


class TestBrickLinkGate(unittest.TestCase):
    def test_fail_closed_when_unlinked(self):
        from client_brick_guard import account_linked_for_auto

        with mock.patch(
            "client_utils.load_account_link_pref",
            return_value={"linked": False, "updated_at": time.time()},
        ), mock.patch(
            "client_utils.refresh_account_link_status",
            return_value=False,
        ):
            self.assertFalse(account_linked_for_auto(token="t"))

    def test_fresh_linked_allows(self):
        from client_brick_guard import account_linked_for_auto

        with mock.patch(
            "client_utils.load_account_link_pref",
            return_value={"linked": True, "updated_at": time.time()},
        ):
            self.assertTrue(account_linked_for_auto(token=""))

    def test_stale_linked_fail_closed_without_refresh(self):
        from client_brick_guard import (
            ACCOUNT_LINK_CACHE_MAX_AGE_SEC,
            account_linked_for_auto,
        )

        stale = time.time() - ACCOUNT_LINK_CACHE_MAX_AGE_SEC - 60
        with mock.patch(
            "client_utils.load_account_link_pref",
            return_value={"linked": True, "updated_at": stale},
        ), mock.patch(
            "client_utils.refresh_account_link_status",
            return_value=None,
        ):
            self.assertFalse(account_linked_for_auto(token="t"))

    def test_stale_linked_refresh_true(self):
        from client_brick_guard import (
            ACCOUNT_LINK_CACHE_MAX_AGE_SEC,
            account_linked_for_auto,
        )

        stale = time.time() - ACCOUNT_LINK_CACHE_MAX_AGE_SEC - 60
        with mock.patch(
            "client_utils.load_account_link_pref",
            return_value={"linked": True, "updated_at": stale},
        ), mock.patch(
            "client_utils.refresh_account_link_status",
            return_value=True,
        ):
            self.assertTrue(account_linked_for_auto(token="t"))


class TestLifecycleStatusWire(unittest.TestCase):
    def test_sam_status_not_used_as_command_status(self):
        from client_brick_guard import lifecycle_status_from_result

        # Bug that bricked cloud UI: disable_account put status=disabled at top
        self.assertEqual(
            lifecycle_status_from_result(
                {"success": True, "ok": True, "status": "disabled"}
            ),
            "completed",
        )
        self.assertEqual(
            lifecycle_status_from_result(
                {"success": True, "ok": True, "status": "active"}
            ),
            "completed",
        )
        self.assertEqual(
            lifecycle_status_from_result(
                {"success": False, "ok": False, "status": "disabled"}
            ),
            "failed",
        )
        self.assertEqual(
            lifecycle_status_from_result(
                {"success": False, "ok": False, "status": "failed"}
            ),
            "failed",
        )
        self.assertEqual(
            lifecycle_status_from_result(
                {"success": True, "ok": True, "status": "completed"}
            ),
            "completed",
        )


class TestAccountMutateResultShape(unittest.TestCase):
    def test_no_top_level_sam_status(self):
        from client_remote_commands import RemoteCommandExecutor

        ex = RemoteCommandExecutor(api_client=None, token_getter=lambda: "")
        with mock.patch(
            "client_remote_session.find_local_user",
            return_value={
                "username": "bob",
                "enabled": False,
                "status": "disabled",
                "is_admin": False,
            },
        ):
            out = ex._account_mutate_result(
                "bob", want_enabled=False, ok=True, action="disabled"
            )
        self.assertNotIn("status", out)  # lifecycle must not collide
        self.assertEqual(out["data"]["status"], "disabled")
        self.assertEqual(out["data"]["account_status"], "disabled")
        self.assertTrue(out["success"])


class TestLastAdminGuard(unittest.TestCase):
    def test_would_close_last_admin(self):
        from client_brick_guard import would_close_last_admin

        with mock.patch(
            "client_brick_guard.is_enabled_local_admin", return_value=True
        ), mock.patch(
            "client_brick_guard.count_enabled_local_admins", return_value=1
        ):
            self.assertTrue(would_close_last_admin("Administrator"))
        with mock.patch(
            "client_brick_guard.is_enabled_local_admin", return_value=True
        ), mock.patch(
            "client_brick_guard.count_enabled_local_admins", return_value=2
        ):
            self.assertFalse(would_close_last_admin("bob"))

    def test_disable_refuses_last_admin(self):
        from client_auto_response import AutoResponse

        ar = AutoResponse()
        with mock.patch(
            "client_brick_guard.would_close_last_admin", return_value=True
        ), mock.patch.object(ar, "_run_system_cmd") as run:
            ok = ar.disable_account("Administrator", allow_privileged=True)
        self.assertFalse(ok)
        self.assertEqual(ar._last_disable_error, "LAST_ADMIN")
        run.assert_not_called()

    def test_auto_disable_requires_link(self):
        from client_auto_response import AutoResponse

        ar = AutoResponse(token_getter=lambda: "tok")
        with mock.patch(
            "client_brick_guard.account_linked_for_auto", return_value=False
        ), mock.patch(
            "client_brick_guard.emit_skipped_unlinked"
        ) as emit, mock.patch.object(ar, "_run_system_cmd") as run:
            ok = ar.disable_account("bob", allow_privileged=False)
        self.assertFalse(ok)
        self.assertEqual(ar._last_disable_error, "SKIPPED_UNLINKED")
        emit.assert_called()
        run.assert_not_called()


class TestSilentHoursDefaults(unittest.TestCase):
    def test_defaults_off(self):
        from client_silent_hours import SilentHoursConfig

        cfg = SilentHoursConfig()
        self.assertFalse(cfg.enabled)
        self.assertFalse(cfg.auto_disable_account)
        self.assertFalse(cfg.auto_logoff)
        self.assertFalse(cfg.weekend_all_day_silent)

        forced = SilentHoursConfig.from_dict({
            "enabled": True,
            "auto_disable_account": True,
            "auto_logoff": True,
        })
        self.assertTrue(forced.enabled)
        self.assertFalse(forced.auto_disable_account)
        self.assertFalse(forced.auto_logoff)


if __name__ == "__main__":
    unittest.main()
