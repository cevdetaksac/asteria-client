import unittest
from client_api import AsteriaAPIClient
import client_constants as cc


class RetiredLegacyHostTests(unittest.TestCase):
    def test_constants_have_no_retired_host(self):
        self.assertNotIn("yesnext", cc.API_URL.lower())
        self.assertNotIn("yesnext", (cc.API_URL_LEGACY or "").lower())
        self.assertFalse(any("yesnext" in d for d in cc.LEGITIMATE_DOMAINS))

    def test_client_ignores_retired_legacy_and_disables_failover(self):
        c = AsteriaAPIClient("https://asteria.run/api", log_func=lambda *_: None,
                             legacy_base_url="https://honeypot.yesnext.com.tr/api")
        self.assertEqual(c.legacy_base_url, "")
        self.assertFalse(c._activate_legacy_failover("test"))
        self.assertEqual(c.base_url, "https://asteria.run/api")

    def test_retired_primary_rewritten_to_asteria(self):
        c = AsteriaAPIClient("https://honeypot.yesnext.com.tr/api", log_func=lambda *_: None)
        self.assertEqual(c.base_url, "https://asteria.run/api")

    def test_sanitize(self):
        self.assertEqual(cc._sanitize_api_url("https://honeypot.yesnext.com.tr/api", "x"), "x")
        self.assertEqual(cc._sanitize_api_url("https://asteria.run/api"), "https://asteria.run/api")


if __name__ == "__main__":
    unittest.main()
