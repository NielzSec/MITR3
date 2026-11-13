"""Tests for MITR3 secret-pattern coverage without handling real credentials."""
import json
import runpy
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

AUDIT_PATH = Path(__file__).resolve().parents[1] / "bin/mitr3-secrets-audit.py"
AUDIT = runpy.run_path(str(AUDIT_PATH))
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

    def test_cli_report_omits_secret_and_fails_closed(self):
        dummy = "AQ." + "Z8y6DummyExampleKey" * 3
        with tempfile.TemporaryDirectory() as td:
            noted = Path(td) / "note.md"
            noted.write_text("token marker below:\n" + dummy + "\n")
            found = subprocess.run(
                [sys.executable, str(AUDIT_PATH), str(noted), "--json"],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(found.returncode, 2)
            report = json.loads(found.stdout)
            self.assertEqual(report["files_scanned"], 1)
            self.assertTrue(any(hit["rule"] == "google_oauth_like" for hit in report["hits"]))
            self.assertNotIn(dummy, found.stdout)
            self.assertNotIn(dummy, found.stderr)
            for hit in report["hits"]:
                self.assertEqual(set(hit), {"path", "line", "rule", "file_mode"})

            clean = Path(td) / "clean.md"
            clean.write_text("refer only to ~/.config/mitr3-secrets/robin-google.token\n")
            empty = subprocess.run(
                [sys.executable, str(AUDIT_PATH), str(clean), "--json"],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(empty.returncode, 0)
            self.assertEqual(json.loads(empty.stdout)["hits"], [])


if __name__ == "__main__":
    unittest.main()
