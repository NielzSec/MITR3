"""Pure unit tests: no live network, no running JobHunter process."""
import os
import unittest
from unittest.mock import patch

from proxy_safety import (
    authenticated,
    proxy_secret_from_environment,
    safe_forward_headers,
    safe_ollama_path,
)


class ProxySafetyTests(unittest.TestCase):
    def test_known_ollama_routes(self):
        self.assertEqual(safe_ollama_path("api/tags", "GET"), "/api/tags")
        self.assertEqual(safe_ollama_path("api/chat", "POST"), "/api/chat")

    def test_rejects_other_routes_and_methods(self):
        for path, method in (
            ("api/delete", "DELETE"), ("api/tags", "POST"), ("../admin", "GET"),
            ("//other.invalid/x", "GET"), ("http://other.invalid/x", "GET"),
            ("%2e%2e/api/tags", "GET"), ("api%2ftags", "GET"),
            ("api/%252e%252e/", "GET"), ("api\\tags", "GET")
        ):
            with self.subTest(path=path, method=method):
                with self.assertRaises(ValueError):
                    safe_ollama_path(path, method)

    def test_no_token_fails_closed(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(ValueError):
                proxy_secret_from_environment()

    def test_low_entropy_token_fails_closed(self):
        with patch.dict(os.environ, {"PROXY_TOKEN": "a" * 64}, clear=True):
            with self.assertRaises(ValueError):
                proxy_secret_from_environment()

    def test_strong_token_loaded(self):
        key = "abcdefghABCD1234" * 3
        with patch.dict(os.environ, {"PROXY_TOKEN": key}, clear=True):
            self.assertEqual(proxy_secret_from_environment(), key)

    def test_auth_headers(self):
        key = "abcdefghABCD1234" * 3
        self.assertTrue(authenticated({"authorization": "Bearer " + key}, key))
        self.assertTrue(authenticated({"x-api-key": key}, key))
        self.assertFalse(authenticated({"authorization": "Bearer bad"}, key))
        self.assertFalse(authenticated({}, key))
        self.assertFalse(authenticated({"x-api-key": key}, ""))

    def test_headers_are_stripped(self):
        original = {
            "Authorization": "Bearer dummy", "X-API-Key": "dummy",
            "Cookie": "s=1", "Host": "gateway", "Connection": "keep-alive",
            "Content-Type": "application/json", "Accept": "application/json",
        }
        self.assertEqual(
            safe_forward_headers(original),
            {"Content-Type": "application/json", "Accept": "application/json"}
        )


if __name__ == "__main__":
    unittest.main()
