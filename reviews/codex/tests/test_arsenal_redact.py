"""Regression tests for a proposed replacement of Codex arsenal output cleaner.

Uses fake token strings only. Never reads credentials or invokes installers.
"""
import importlib.util
from pathlib import Path
import unittest

PATH = Path(__file__).resolve().parents[1] / "arsenal_redact.py"
spec = importlib.util.spec_from_file_location("mitr3_arsenal_redact", PATH)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class RedactionTests(unittest.TestCase):
    def assert_redacted(self, template, token="FAKE_CREDENTIAL_VALUE_123456789012345"):
        output = module.clean(template.format(token=token))
        self.assertNotIn(token, output)
        self.assertIn("<redacted", output)

    def test_authorization_bearer(self):
        self.assert_redacted("Authorization: Bearer {token}")

    def test_authorization_basic(self):
        self.assert_redacted("Authorization: Basic {token}")

    def test_api_key_header(self):
        self.assert_redacted("X-API-Key: {token}")

    def test_env_secret_assignment(self):
        for key in ("GOOGLE_API_KEY", "GEMINI_API_KEY", "AWS_SECRET_ACCESS_KEY", "HF_KEY"):
            with self.subTest(key=key):
                self.assert_redacted(key + "={token}")

    def test_query_string(self):
        self.assert_redacted("https://api.invalid/path?token={token}&limit=12")

    def test_cli_argument(self):
        self.assert_redacted("run something --token {token} --version")

    def test_url_userinfo(self):
        self.assert_redacted("https://example:{token}@api.invalid/v1")

    def test_known_key_shapes_even_without_assignment(self):
        samples = [
            "sk-" + "a" * 33,
            "ghp_" + "b" * 35,
            "github_pat_" + "c" * 45,
            "AIza" + "d" * 35,
            "AQ." + "e" * 35,
        ]
        for token in samples:
            with self.subTest(prefix=token[:4]):
                text = module.clean("Unexpected output " + token)
                self.assertNotIn(token, text)

    def test_versions_and_safe_messages_remain_intact(self):
        cases = ["aws-cli/2.37.9 Python/3.14.8", "pip --version", "Installed 10 packages", "HTTP 405"]
        for text in cases:
            with self.subTest(text=text):
                self.assertEqual(module.clean(text), text)

    def test_ansi_strip(self):
        self.assertEqual(module.clean("\x1b[31mFailed\x1b[0m"), "Failed")

    def test_idempotent(self):
        original = "Authorization: Bearer FAKE_CREDENTIAL_VALUE_123456789012345"
        once = module.clean(original)
        twice = module.clean(once)
        self.assertEqual(once, twice)


if __name__ == "__main__":
    unittest.main()
