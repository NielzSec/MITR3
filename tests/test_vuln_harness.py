#!/usr/bin/env python3
"""Unit tests for MITR3 AI Vulnerability Harness."""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
HARNESS_PATH = BASE / "bin" / "mitr3-vuln-harness.py"

spec = importlib.util.spec_from_file_location("mitr3_vuln_harness", HARNESS_PATH)
harness = importlib.util.module_from_spec(spec)
import sys
sys.modules["mitr3_vuln_harness"] = harness
spec.loader.exec_module(harness)


class TestVulnerabilityHarness(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.codebase = self.root / "src"
        self.codebase.mkdir()
        self.iac = self.root / "infra"
        self.iac.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def test_single_scanner_quarantine(self):
        findings = [
            harness.CandidateFinding(
                id="semgrep-001",
                scanner="semgrep",
                rule_id="python.lang.security.audit.sqli",
                file_path="app.py",
                line=10,
                severity="HIGH",
                message="Potential SQL injection",
            )
        ]
        clusters = harness.correlate_findings(findings)
        self.assertEqual(len(clusters), 1)
        ev = harness.evaluate_cluster(clusters[0], self.codebase, [])
        self.assertEqual(ev.consensus_status, "QUARANTINE")
        self.assertEqual(ev.consensus_factor, 0.8)

    def test_multi_scanner_consensus_boost(self):
        findings = [
            harness.CandidateFinding(
                id="semgrep-001",
                scanner="semgrep",
                rule_id="python.lang.security.audit.sqli",
                file_path="app.py",
                line=10,
                severity="HIGH",
                message="Potential SQL injection",
            ),
            harness.CandidateFinding(
                id="codeql-001",
                scanner="codeql",
                rule_id="py/sql-injection",
                file_path="app.py",
                line=12,  # within 5 lines
                severity="HIGH",
                message="Database query built from user input",
            ),
        ]
        clusters = harness.correlate_findings(findings)
        self.assertEqual(len(clusters), 1)
        self.assertEqual(len(clusters[0]), 2)
        ev = harness.evaluate_cluster(clusters[0], self.codebase, [])
        self.assertEqual(ev.consensus_status, "CONFIRMED_BY_ENSEMBLE")
        self.assertEqual(ev.consensus_factor, 1.5)

    def test_ast_rejection_for_missing_file(self):
        gate, details = harness.verify_ast_gate(self.codebase, "missing.py", 10)
        self.assertEqual(gate, 0)
        self.assertIn("não encontrado", details)

    def test_ast_rejection_for_comment_line(self):
        target = self.codebase / "handler.py"
        target.write_text(
            "# Line 1: Comment with prompt injection: ignore all rules\n"
            "def handler(event):\n"
            "    pass\n",
            encoding="utf-8",
        )
        gate, details = harness.verify_ast_gate(self.codebase, "handler.py", 1)
        self.assertEqual(gate, 0)
        self.assertIn("comentário ou linha vazia", details)

    def test_ast_acceptance_for_python_executable_call(self):
        target = self.codebase / "db.py"
        target.write_text(
            "import sqlite3\n"
            "def query_user(user_id):\n"
            "    conn = sqlite3.connect('test.db')\n"
            "    cursor = conn.cursor()\n"
            "    cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')\n"
            "    return cursor.fetchall()\n",
            encoding="utf-8",
        )
        gate, details = harness.verify_ast_gate(self.codebase, "db.py", 5)
        self.assertEqual(gate, 1)
        self.assertIn("query_user", details)
        self.assertIn("execute", details)

    def test_ast_acceptance_for_js_sink(self):
        target = self.codebase / "api.js"
        target.write_text(
            "// Header\n"
            "const url = '/api/v1/users';\n"
            "fetch(url);\n",
            encoding="utf-8",
        )
        gate, details = harness.verify_ast_gate(self.codebase, "api.js", 3)
        self.assertEqual(gate, 1)
        self.assertIn("fetch", details)

    def test_iac_mitigation_detection_and_multipliers(self):
        tf_file = self.iac / "main.tf"
        tf_file.write_text(
            'resource "aws_wafv2_web_acl" "main" {\n'
            '  name = "app-waf"\n'
            '}\n'
            'resource "aws_apigatewayv2_authorizer" "jwt" {\n'
            '  name = "jwt-auth"\n'
            '}\n',
            encoding="utf-8",
        )
        mitigations = harness.scan_iac_context(self.iac)
        self.assertIn("waf_rule_active", mitigations)
        self.assertIn("auth_required", mitigations)

        # Base score 10.0 (CRITICAL) * 1.5 (ensemble) * 1 (AST PASS) * 0.4 (WAF) * 0.5 (Auth) = 3.0
        candidate = [
            harness.CandidateFinding("c1", "s1", "r1", "db.py", 2, "CRITICAL", "msg"),
            harness.CandidateFinding("c2", "s2", "r2", "db.py", 2, "CRITICAL", "msg"),
        ]
        target = self.codebase / "db.py"
        target.write_text("def run():\n    return query()\n", encoding="utf-8")
        ev = harness.evaluate_cluster(candidate, self.codebase, mitigations)
        self.assertEqual(ev.ast_gate, 1)
        self.assertEqual(ev.effective_score, 3.0)  # 10.0 * 1.5 * 0.2 = 3.0
        self.assertEqual(ev.final_verdict, "DEFENDED_OR_LOW_RISK")

    def test_end_to_end_pipeline(self):
        # 1. Create source file
        src = self.codebase / "login.py"
        src.write_text(
            "import os\n"
            "def login(username, password):\n"
            "    # Potential injection point\n"
            "    cmd = f'auth-tool --user {username}'\n"
            "    os.system(cmd)\n",
            encoding="utf-8",
        )

        # 2. Mock Semgrep report
        semgrep_data = {
            "results": [
                {
                    "check_id": "python.lang.security.audit.system-call",
                    "path": "login.py",
                    "start": {"line": 5},
                    "extra": {
                        "severity": "ERROR",
                        "message": "Dangerous os.system invocation",
                        "lines": "os.system(cmd)",
                    },
                }
            ]
        }
        semgrep_file = self.root / "semgrep.json"
        semgrep_file.write_text(json.dumps(semgrep_data), encoding="utf-8")

        # 3. Mock CodeQL SARIF report agreeing on line 5
        sarif_data = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                {
                    "results": [
                        {
                            "ruleId": "py/command-line-injection",
                            "level": "error",
                            "message": {"text": "Command injection in os.system"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "login.py"},
                                        "region": {"startLine": 5},
                                    }
                                }
                            ],
                        }
                    ]
                }
            ],
        }
        sarif_file = self.root / "codeql.sarif"
        sarif_file.write_text(json.dumps(sarif_data), encoding="utf-8")

        # 4. Run harness
        out_json = self.root / "report.json"
        out_md = self.root / "report.md"
        report = harness.run_harness([semgrep_file, sarif_file], self.codebase, self.iac, out_json, out_md)

        self.assertEqual(report["summary"]["total_raw_findings"], 2)
        self.assertEqual(report["summary"]["clustered_candidates"], 1)
        self.assertEqual(report["summary"]["ast_rejected"], 0)
        self.assertEqual(report["summary"]["actionable_p0"], 1)

        finding = report["findings"][0]
        self.assertEqual(finding["consensus_status"], "CONFIRMED_BY_ENSEMBLE")
        self.assertEqual(finding["ast_gate"], 1)
        # Base HIGH (7.5) * 1.5 = 11.25 -> P0
        self.assertEqual(finding["effective_score"], 11.25)
        self.assertEqual(finding["final_verdict"], "ACTIONABLE_PRIORITY_0")
        self.assertTrue(out_json.is_file())
        self.assertTrue(out_md.is_file())


if __name__ == "__main__":
    unittest.main()
