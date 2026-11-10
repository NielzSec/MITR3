"""Regression tests for the MITR3 CodeQL SARIF report renderer."""
import json
import runpy
import tempfile
import unittest
from pathlib import Path

MOD = runpy.run_path(str(Path(__file__).resolve().parents[1] / "bin/mitr3-codeql-report.py"))
write_report = MOD["write_report"]
severity = MOD["severity"]


class ReportTests(unittest.TestCase):
    def test_empty_sarif_has_zero_counts(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            sarif = root / "empty.sarif"
            out = root / "out.md"
            sarif.write_text(json.dumps({"version": "2.1.0", "runs": [{"results": []}]}))
            write_report(sarif, out, "/repo", "python", "/tmp/db", "2.27.2")
            txt = out.read_text()
            self.assertIn("Resultados totais: **0**", txt)
            self.assertIn("| CRITICAL | 0 |", txt)
            self.assertEqual(out.stat().st_mode & 0o777, 0o600)

    def test_security_severity_and_relative_location(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            sarif = root / "result.sarif"
            out = root / "out.md"
            sarif.write_text(json.dumps({
                "version": "2.1.0",
                "runs": [{
                    "tool": {"driver": {"rules": [
                        {"id": "py/sql-injection", "properties": {"security-severity": "8.1"},
                         "shortDescription": {"text": "Potential SQL injection"}},
                        {"id": "py/use-of-eval", "properties": {"security-severity": "9.3"},
                         "shortDescription": {"text": "Unsafe eval"}}
                    ]}},
                    "results": [
                        {"ruleId": "py/sql-injection", "level": "warning",
                         "locations": [{"physicalLocation": {
                             "artifactLocation": {"uri": "src/db.py"},
                             "region": {"startLine": 17}
                         }}]},
                        {"ruleId": "py/use-of-eval", "level": "error",
                         "locations": [{"physicalLocation": {
                             "artifactLocation": {"uri": "src/service.py"},
                             "region": {"startLine": 9}
                         }}]}
                    ]
                }]
            }))
            write_report(sarif, out, "/repo", "python", "/tmp/db", "2.27.2")
            txt = out.read_text()
            self.assertIn("| CRITICAL | 1 |", txt)
            self.assertIn("| HIGH | 1 |", txt)
            self.assertIn("py/sql-injection", txt)
            self.assertIn("src/db.py:17", txt)
            self.assertIn("src/service.py:9", txt)
            self.assertLess(txt.index("py/use-of-eval"), txt.index("py/sql-injection"))

    def test_fallback_level_without_rule_metadata(self):
        self.assertEqual(severity({"ruleId": "x", "level": "warning"}, {}), "MEDIUM")
        self.assertEqual(severity({"ruleId": "x", "level": "note"}, {}), "LOW")


if __name__ == "__main__":
    unittest.main()
