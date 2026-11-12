# language: python, file: test_opsec_tools.py, target: Linux, stdlib only
# Testes offline (sem rede) das novas ferramentas BlackOps: slack-auditor e opsec-scan.
import contextlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

BIN = Path(__file__).resolve().parent.parent / "bin"

def load(name):
    spec = importlib.util.spec_from_file_location(name, BIN / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

slack_audit = load("mitr3-slack-audit")
opsec_scan = load("mitr3-opsec-scan")


class SecretsAudit(unittest.TestCase):
    secrets_audit = load("mitr3-secrets-audit")

    def _write(self, text):
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8") as fh:
            fh.write(text)
            return fh.name

    def _audit(self, path):
        # main() always returns 0; findings live in the printed JSON
        buf = io.StringIO()
        with unittest.mock.patch.object(sys, "argv", ["mitr3-secrets-audit", path]), \
                contextlib.redirect_stdout(buf):
            self.secrets_audit.main()
        return json.loads(buf.getvalue())["hits"]

    def test_benign_stdlib_token_not_flagged(self):
        # the exact false positive seen in tools/mitr3_live_browser.py (engine marker generation)
        path = self._write("    token = secrets.token_hex(8)\n    other = secrets.token_urlsafe(16)\n")
        self.assertEqual(self._audit(path), [])

    def test_real_shaped_secret_still_flagged(self):
        # synthetic AWS-like shape assembled at runtime so this test file stays audit-clean
        key = "AKIA" + "B" * 16
        path = self._write(f"aws_access_key_id = {key}\n")
        self.assertEqual(len(self._audit(path)), 1)

class SlackAudit(unittest.TestCase):
    def _dump(self, text):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as fh:
            json.dump({"results": [{"response": {"data": {"messages": [{"text": text, "ts": "1", "user": "U1"}]}}}]}, fh)
            return fh.name

    def test_finds_and_masks_token(self):
        # token montado em runtime: forma sintética (só T/0) que exercita o regex
        # do slack-auditor sem deixar literal parecido com credencial no arquivo
        # (o mitr3-secrets-audit.py escanearia o literal).
        token = "xox" + "b-" + "T" * 12 + "-0000"
        path = self._dump(f"olá {token} fim")
        self.assertEqual(slack_audit.main([path]), 1)

    def test_clean_is_clean(self):
        path = self._dump("apenas texto normal do canal")
        self.assertEqual(slack_audit.main([path]), 0)

    def test_masks_value(self):
        synthetic_key = "AKIA" + "Z" * 16
        m = slack_audit.mask(synthetic_key)
        self.assertNotIn("Z" * 16, m)
        self.assertTrue(m.startswith("AKI") and m.endswith("ZZ"))

class OpsecScan(unittest.TestCase):
    def _with_headers(self, headers):
        orig = opsec_scan.fetch
        opsec_scan.fetch = lambda url, head=False: (200, headers, b"") if url.startswith("http://x/") else (404, {}, b"")
        try:
            return opsec_scan.scan("http://x/")
        finally:
            opsec_scan.fetch = orig

    def test_missing_headers_flagged(self):
        findings, meta = self._with_headers({})
        self.assertTrue(meta["reachable"])
        self.assertIn("header", {f["check"] for f in findings})

    def test_hardened_site_only_probes(self):
        headers = {k.upper(): "v" for k in opsec_scan.HEADER_CHECKS}
        findings, _ = self._with_headers(headers)
        self.assertFalse([f for f in findings if f["check"] == "header"])

    def test_sensitive_cookie_without_secure(self):
        findings, _ = self._with_headers({"Set-Cookie": "sessionid=abc; Path=/"})
        self.assertIn("cookie", {f["check"] for f in findings})

if __name__ == "__main__":
    unittest.main()
