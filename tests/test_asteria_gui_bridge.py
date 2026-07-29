import unittest
from unittest import mock

import asteria_gui


class MotorBridgeTests(unittest.TestCase):
    def setUp(self):
        self.bridge = asteria_gui.MotorBridge()
        self.bridge._gui_lock = mock.Mock()
        self.bridge._gui_lock.has_pin.return_value = False
        self.bridge._gui_lock.is_session_unlocked.return_value = False

    @mock.patch.object(asteria_gui, "ping", return_value=True)
    def test_ping_exposes_only_health(self, mocked_ping):
        self.assertEqual(
            self.bridge.ping(),
            {"ok": True, "motor": "online"},
        )
        mocked_ping.assert_called_once_with(timeout=1.5)

    @mock.patch.object(
        asteria_gui,
        "get_status",
        return_value={"ok": True, "version": "4.10.0", "opaque": object()},
    )
    def test_status_is_json_serializable(self, _mocked_status):
        result = self.bridge.status()
        self.assertTrue(result["ok"])
        self.assertIsInstance(result["opaque"], str)

    def test_locked_session_blocks_status(self):
        self.bridge._gui_lock.has_pin.return_value = True
        self.bridge._gui_lock.is_session_unlocked.return_value = False
        self.assertEqual(
            self.bridge.status(),
            {"ok": False, "error": "gui_locked"},
        )

    def test_session_exposes_account_link_while_locked(self):
        self.bridge._gui_lock.has_pin.return_value = True
        self.bridge._gui_lock.is_session_unlocked.return_value = False
        with mock.patch("client_utils.is_account_linked", return_value=True), mock.patch(
            "client_utils.get_linked_account_email", return_value="ops@asteria.run"
        ), mock.patch.object(
            self.bridge,
            "_agent_identity",
            return_value={
                "server_name": "DESKTOP-X",
                "token_present": True,
                "token_preview": "abcd1234efgh5678…",
                "client_id": "9",
            },
        ):
            result = self.bridge.session()
        self.assertTrue(result["ok"])
        self.assertTrue(result["locked"])
        self.assertTrue(result["pin_enabled"])
        self.assertTrue(result["account_linked"])
        self.assertEqual(result["account_email"], "ops@asteria.run")
        self.assertEqual(result["server_name"], "DESKTOP-X")
        self.assertEqual(result["token_preview"], "abcd1234efgh5678…")
        self.assertTrue(result["token_present"])
        self.assertEqual(result["client_id"], "9")

    def test_agent_identity_masks_token(self):
        with mock.patch.object(
            self.bridge, "_load_token", return_value="abcdefghijklmnopqrstuvwxyz"
        ), mock.patch(
            "client_utils.load_account_link_pref",
            return_value={"client_id": 42},
        ), mock.patch(
            "client_constants.SERVER_NAME", "BOX-1"
        ):
            ident = self.bridge._agent_identity()
        self.assertEqual(ident["server_name"], "BOX-1")
        self.assertTrue(ident["token_present"])
        self.assertEqual(ident["token_preview"], "abcdefghijklmnop…")
        self.assertNotIn("abcdefghijklmnopqrstuvwxyz", ident["token_preview"])
        self.assertEqual(ident["client_id"], "42")

    def test_unlock_uses_existing_rate_limited_pin_store(self):
        self.bridge._gui_lock.verify_pin.return_value = (True, "ok")
        self.bridge._gui_lock.lockout_remaining.return_value = 0
        result = self.bridge.unlock("123456")
        self.assertTrue(result["ok"])
        self.bridge._gui_lock.verify_pin.assert_called_once_with(
            "123456", unlock_on_success=True
        )

    def test_ipc_allowlist_denies_unknown(self):
        result = self.bridge.ipc("QUIT")
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "ipc_denied")

    @mock.patch.object(asteria_gui, "block_ip", return_value={"ok": True})
    def test_ipc_block_ip(self, mocked):
        result = self.bridge.ipc("BLOCK_IP", {"ip": "1.2.3.4", "reason": "test"})
        self.assertTrue(result["ok"])
        mocked.assert_called_once_with("1.2.3.4", "test")

    def test_shell_allowlist_denies_unknown(self):
        result = self.bridge.shell("format_disk")
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "shell_denied")

    @mock.patch.object(asteria_gui.MotorBridge, "_load_token", return_value="tok-uuid-1")
    @mock.patch("asteria_gui.webbrowser.open")
    def test_shell_open_dashboard_allowlisted_path(self, mocked_open, _tok):
        result = self.bridge.shell("open_dashboard", "blocks_auto")
        self.assertTrue(result["ok"], result)
        mocked_open.assert_called_once_with(
            "https://asteria.run/dashboard/blocks?token=tok-uuid-1#tab-auto"
        )

    @mock.patch.object(asteria_gui.MotorBridge, "_load_token", return_value="tok-uuid-1")
    @mock.patch("asteria_gui.webbrowser.open")
    def test_shell_open_dashboard_home_with_token(self, mocked_open, _tok):
        result = self.bridge.shell("open_dashboard", "")
        self.assertTrue(result["ok"], result)
        mocked_open.assert_called_once_with(
            "https://asteria.run/dashboard?token=tok-uuid-1"
        )

    @mock.patch("asteria_gui.webbrowser.open")
    def test_shell_open_dashboard_denies_unknown_path(self, mocked_open):
        result = self.bridge.shell("open_dashboard", "javascript:alert(1)")
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "dashboard_path_denied")
        mocked_open.assert_not_called()

    def test_cloud_allowlist_denies_unknown(self):
        result = self.bridge.cloud("DELETE", "agents/me")
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "cloud_denied")

    @mock.patch.object(asteria_gui.MotorBridge, "_load_token", return_value="tok-test")
    @mock.patch("client_api.AsteriaAPIClient")
    def test_cloud_fetch_threat_config(self, mocked_cls, _tok):
        fake = mocked_cls.return_value
        fake.fetch_threat_config.return_value = {"auto_block_enabled": True}
        result = self.bridge.cloud("GET", "threats/config")
        self.assertTrue(result.get("ok"), result)
        self.assertEqual(result["data"]["auto_block_enabled"], True)
        fake.fetch_threat_config.assert_called_once_with("tok-test")

    def test_load_token_uses_token_store(self):
        with mock.patch("client_utils.TokenStore.load", return_value="abc"), mock.patch(
            "client_utils._programdata_client_dir", return_value="C:\\pd"
        ):
            self.assertEqual(self.bridge._load_token(), "abc")

    def test_account_status(self):
        with mock.patch("client_utils.is_account_linked", return_value=True), mock.patch(
            "client_utils.get_linked_account_email", return_value="a@b.c"
        ):
            result = self.bridge.account("status")
        self.assertTrue(result["ok"])
        self.assertTrue(result["linked"])
        self.assertEqual(result["email"], "a@b.c")

    def test_account_change_requires_configured_pin(self):
        self.bridge._gui_lock.has_pin.return_value = False
        result = self.bridge.account("unlink", "a@b.c", "secret", "1234")
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "pin_required")

    @mock.patch.object(asteria_gui.MotorBridge, "_load_token", return_value="tok-test")
    @mock.patch("client_api.unlink_account_with_credentials")
    def test_account_unlink_reverifies_pin(self, mocked_unlink, _token):
        self.bridge._gui_lock.has_pin.return_value = True
        self.bridge._gui_lock.is_session_unlocked.return_value = True
        self.bridge._gui_lock.verify_pin.return_value = (True, "ok")
        mocked_unlink.return_value = {"ok": True, "account_linked": False}
        result = self.bridge.account("unlink", "a@b.c", "secret", "2468")
        self.assertTrue(result["ok"])
        self.bridge._gui_lock.verify_pin.assert_called_once_with(
            "2468", unlock_on_success=False
        )
        mocked_unlink.assert_called_once()

    def test_i18n_returns_strings(self):
        with mock.patch("client_utils.resolve_app_language", return_value="tr"), mock.patch(
            "client_utils.load_i18n", return_value={"tr": {"app_title": "Asteria"}}
        ):
            result = self.bridge.i18n()
        self.assertTrue(result["ok"])
        self.assertEqual(result["lang"], "tr")
        self.assertEqual(result["strings"]["app_title"], "Asteria")

    def test_update_banner_status(self):
        with mock.patch(
            "client_update_ui.get_update_ui_status",
            return_value={"phase": "downloading", "progress": 10},
        ), mock.patch("client_constants.VERSION", "4.9.35"):
            result = self.bridge.update_banner("status")
        self.assertTrue(result["ok"])
        self.assertEqual(result["status"]["phase"], "downloading")

    def test_shell_about_returns_metadata(self):
        with mock.patch("client_constants.VERSION", "4.9.35"), mock.patch(
            "client_constants.GITHUB_OWNER", "cevdetaksac"
        ), mock.patch("client_constants.GITHUB_REPO", "asteria-client"):
            result = self.bridge.shell("about")
        self.assertTrue(result["ok"])
        self.assertEqual(result["version"], "4.9.35")
        self.assertIn("github.com/cevdetaksac/asteria-client", result["github"])

    def test_shell_check_updates(self):
        with mock.patch(
            "client_updater.check_update_availability",
            return_value={
                "ok": True,
                "update_available": False,
                "installed": "4.9.35",
                "latest": "4.9.35",
                "message": "already_current",
            },
        ):
            result = self.bridge.shell("check_updates")
        self.assertTrue(result["ok"])
        self.assertFalse(result["update_available"])
        self.assertFalse(result.get("started"))

    def test_shell_check_updates_starts_silent_motor_update(self):
        with mock.patch(
            "client_updater.check_update_availability",
            return_value={
                "ok": True,
                "update_available": True,
                "installed": "4.9.47",
                "latest": "4.9.48",
                "tag": "v4.9.48",
                "download_url": "https://example.test/installer.exe",
                "message": "update_available",
            },
        ), mock.patch(
            "asteria_gui.self_update",
            return_value={"ok": True, "started": True, "message": "update_accepted"},
        ) as ipc_upd, mock.patch(
            "client_update_ui.set_update_ui_status"
        ) as set_ui, mock.patch("asteria_gui.webbrowser.open") as browser:
            result = self.bridge.shell("check_updates")
        self.assertTrue(result["ok"])
        self.assertTrue(result["update_available"])
        self.assertTrue(result["started"])
        ipc_upd.assert_called_once()
        set_ui.assert_called()
        browser.assert_not_called()

    def test_ir_requires_username(self):
        result = self.bridge.ir("logoff", "")
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "username_required")

    def test_ir_list_users_marks_self(self):
        fake = [
            {
                "username": "ops",
                "enabled": True,
                "status": "active",
                "protected": False,
                "can_enable": False,
                "can_disable": True,
                "is_admin": True,
                "groups": ["Administrators"],
                "has_session": True,
                "session_status": "Active",
                "last_logon": None,
            },
            {
                "username": "bob",
                "enabled": True,
                "status": "active",
                "protected": False,
                "can_enable": False,
                "can_disable": True,
                "is_admin": False,
                "groups": ["Users"],
                "has_session": False,
                "session_status": None,
                "last_logon": None,
            },
        ]
        with mock.patch(
            "client_remote_session.list_local_users", return_value=fake
        ), mock.patch.object(self.bridge, "_ir_current_username", return_value="ops"):
            result = self.bridge.ir("list")
        self.assertTrue(result["ok"])
        by_name = {u["username"]: u for u in result["users"]}
        self.assertTrue(by_name["ops"]["is_self"])
        self.assertFalse(by_name["ops"]["can_disable"])
        self.assertFalse(by_name["ops"]["can_logoff"])
        self.assertTrue(by_name["bob"]["can_disable"])

    def test_ir_blocks_self_disable(self):
        with mock.patch.object(self.bridge, "_ir_current_username", return_value="ops"):
            result = self.bridge.ir("disable", "ops")
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "self_account")

    def test_rdp_begin_sets_pending_confirm_window(self):
        store = {}

        def _save(payload):
            store.update(payload)

        def _load():
            return dict(store) if store.get("mode") else None

        def _clear():
            store.clear()

        with mock.patch("client_utils.is_admin", return_value=True), mock.patch(
            "client_utils.ServiceController.get_rdp_port", return_value=3389
        ), mock.patch.object(self.bridge, "_rdp_transition", return_value=True), mock.patch.object(
            self.bridge, "_rdp_save_pending", side_effect=_save
        ), mock.patch.object(
            self.bridge, "_rdp_load_pending", side_effect=_load
        ), mock.patch.object(
            self.bridge, "_rdp_clear_pending", side_effect=_clear
        ), mock.patch.object(
            self.bridge, "_rdp_arm_expire_timer"
        ), mock.patch.object(
            self.bridge, "_rdp_expire_pending_if_needed", return_value=False
        ):
            began = self.bridge.rdp("begin", "secure")
            self.assertTrue(began["ok"])
            self.assertTrue(began["pending"])
            self.assertEqual(began["to_port"], 43389)
            self.assertGreater(began["seconds_left"], 0)
            self.assertEqual(store.get("mode"), "secure")
            confirmed = self.bridge.rdp("confirm")
            self.assertTrue(confirmed["ok"])
            self.assertTrue(confirmed["confirmed"])
            self.assertFalse(bool(store))


if __name__ == "__main__":
    unittest.main()
