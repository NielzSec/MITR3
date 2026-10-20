"""Unit tests of independent, redacted arsenal QA metadata (no installations)."""
from __future__ import annotations
import datetime as dt
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

MODULE = Path(__file__).resolve().parents[1] / "arsenal_qa.py"
spec = importlib.util.spec_from_file_location("mitr3_arsenal_qa", MODULE)
arsenal_qa = importlib.util.module_from_spec(spec)
spec.loader.exec_module(arsenal_qa)


NOW = dt.datetime(2026, 10, 19, 19, 0, tzinfo=dt.timezone.utc)

def source(rows, action="install", when="2026-10-19T18:55:00+00:00"):
    return {"timestamp": when, "action": action, "selector": "all", "tools": rows}


class ArsenalQATests(unittest.TestCase):
    def test_network_dns_error_not_arch_incompatibility(self):
        item = {"status": "missing", "install_error": "go install: lookup proxy.golang.org on 127.0.0.53:53: dial udp: socket: operation not permitted"}
        self.assertEqual(arsenal_qa.failure_type(item), "network")

    def test_sudo_no_new_privileges_is_permission(self):
        item = {"status": "failed", "install_error": "sudo: The no new privileges flag is set"}
        self.assertEqual(arsenal_qa.failure_type(item), "permissions")

    def test_pip_resolution_is_package_resolution(self):
        item = {"status": "failed", "install_error": "No matching distribution found for example"}
        self.assertEqual(arsenal_qa.failure_type(item), "package_resolution")

    def test_success_has_no_blocker(self):
        item = {"status": "validated", "install_error": "past unrelated error"}
        self.assertEqual(arsenal_qa.failure_type(item), "none")

    def test_counts_by_status_and_blocker(self):
        rows = [
            {"name": "aws", "phase": 3, "status": "missing", "install_error": "sudo: no new privileges", "version": None},
            {"name": "impacket", "phase": 2, "status": "validated", "version": "0.13.1"},
            {"name": "gcloud", "phase": 3, "status": "missing", "install_error": "Could not resolve host"},
        ]
        report = arsenal_qa.assess(source(rows), NOW)
        self.assertEqual(report["total"], 3)
        self.assertEqual(report["counts"], {"missing": 2, "validated": 1})
        self.assertEqual(report["blockers"], {"permissions": 1, "network": 1})

    def test_sensitive_raw_logs_never_appear_in_summary(self):
        marker = "FAKE_SECRET_NEVER_EXPOSE_IN_REPORT"
        rows = [{
            "name": "aws", "phase": 3, "status": "missing", "version": None,
            "source": "https://token:" + marker + "@example.invalid/x",
            "evidence": "Authorization: Bearer " + marker,
            "install_error": "No matching distribution found: " + marker,
            "install_log": "/home/secret/" + marker,
            "probe": ["aws", "--token", marker],
        }]
        report = arsenal_qa.assess(source(rows), NOW)
        output = arsenal_qa.markdown(report) + json.dumps(report)
        self.assertNotIn(marker, output)
        self.assertNotIn("Authorization", output)
        self.assertNotIn("install_log", output)

    def test_markdown_name_and_version_are_validated(self):
        rows = [{"name": "bad|row\nsecret", "phase": 3, "status": "validated",
                 "version": "0.1|SECRET", "command": "/some/tool"}]
        report = arsenal_qa.assess(source(rows), NOW)
        output = arsenal_qa.markdown(report)
        self.assertIn("invalid-name", output)
        self.assertIn("invalid-version", output)
        self.assertNotIn("bad|row", output)
        self.assertNotIn("0.1|SECRET", output)

    def test_duplicate_tool_names_rejected(self):
        rows = [{"name": "aws", "phase": 3}, {"name": "aws", "phase": 3}]
        with self.assertRaises(ValueError):
            arsenal_qa.assess(source(rows), NOW)

    def test_stale_report_warns(self):
        report = arsenal_qa.assess(source([], when="2026-10-19T17:00:00+00:00"), NOW)
        self.assertTrue(any("older than" in msg for msg in report["notes"]))

    def test_invalid_source_rejected(self):
        with self.assertRaises(ValueError):
            arsenal_qa.assess({"tools": None}, NOW)

    def test_report_is_safe_on_disk(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "test.json"
            p.write_text(json.dumps(source([{"name": "aws", "phase": 3, "status": "validated", "version": "2.3.1"}])))
            # QA functions may be called with a fixture without changing original file
            original = p.read_bytes()
            report = arsenal_qa.assess(json.loads(p.read_text()), NOW)
            self.assertEqual(report["counts"], {"validated": 1})
            self.assertEqual(p.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
