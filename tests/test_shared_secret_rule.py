"""Tests for MITR3 secret-pattern coverage without handling real credentials."""
from pathlib import Path
import runpy
import tempfile
import unittest

AUDIT = runpy.run_path(str(Path(__file__).resolve().parents[1] / "bin/mitr3-secrets-audit.py"))
scan = AUDIT["scan"]


class SharedTokenTests(unittest.TestCase):
    def test_oauth_like_token_detected_without_storing_value(self):
        dummy = "AQ." + "Z8y6DummyExampleKey" * 3
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "note.md"
            p.write_text("token marker below:\n" + dummy + "\n")
            findings = []
            scan(p, findings)
            self.assertTrue(any(h["rule"] == "google_oauth_like" for h in findings))
            for finding in findings:
                self.assertNotIn(dummy, str(finding))

    def test_no_credential_in_clean_note(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "board.md"
            p.write_text("MITR3: usar arquivo privado em ~/.config/mitr3-secrets/robin-google.token")
            findings = []
            scan(p, findings)
            self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
