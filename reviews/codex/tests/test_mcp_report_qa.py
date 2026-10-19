"""Contract tests for independent MCP diagnostic QA, no network or subprocesses."""
import datetime as dt
import importlib.util
from pathlib import Path
import unittest

p = Path(__file__).resolve().parents[1] / "mcp_report_qa.py"
spec = importlib.util.spec_from_file_location("mitr3_mcp_report_qa", p)
qa = importlib.util.module_from_spec(spec)
spec.loader.exec_module(qa)


def report(rows, error=None):
    return {"timestamp": "2026-10-19T18:23:53+00:00",
            "opencode_list_error": error,
            "servers": rows}


class MCPQATests(unittest.TestCase):
    def setUp(self):
        self.now = dt.datetime(2026, 10, 19, 18, 25, tzinfo=dt.timezone.utc)

    def test_http_405_406_are_not_handshakes(self):
        rows = [{"name": "megabrain", "type": "remote", "boot": "pass",
                 "boot_detail": "HTTP 406", "issues": [], "opencode": "unavailable (exit 1)"},
                {"name": "context7", "type": "remote", "boot": "pass",
                 "boot_detail": "HTTP 405", "issues": [], "opencode": "unavailable (exit 1)"}]
        data = qa.assess(report(rows, "unavailable (exit 1)"), self.now)
        self.assertEqual(data["client_confirmed"], 0)
        self.assertEqual(data["counts"]["unverified_http_reachable"], 2)
        self.assertTrue(any("405" in w for w in data["warnings"]))

    def test_local_smoke_pass_is_not_mcp_connected(self):
        rows = [{"name": "apisec-ng", "type": "local", "boot": "pass",
                 "boot_detail": "alive after 5s", "issues": [],
                 "opencode": "unavailable (exit 1)"}]
        data = qa.assess(report(rows, "unavailable (exit 1)"), self.now)
        self.assertEqual(data["counts"]["unverified_process_stable"], 1)

    def test_launch_failure_is_needs_review(self):
        rows = [{"name": "rea", "type": "local", "boot": "fail",
                 "boot_detail": "exit 1 before 5s", "issues": [],
                 "opencode": "unavailable (exit 1)"}]
        data = qa.assess(report(rows, "unavailable (exit 1)"), self.now)
        self.assertEqual(data["counts"]["launch_failure_review"], 1)
        self.assertEqual(data["client_confirmed"], 0)

    def test_client_confirmed_takes_priority_over_smoke(self):
        rows = [{"name": "rea", "type": "local", "boot": "fail",
                 "boot_detail": "exit 1 before 5s", "issues": [],
                 "opencode": "connected"}]
        data = qa.assess(report(rows), self.now)
        self.assertEqual(data["counts"]["client_reported_connected"], 1)
        self.assertEqual(data["client_confirmed"], 1)

    def test_config_issue_is_not_silently_ignored(self):
        rows = [{"name": "mitr3-nexus", "type": "local", "boot": "pass",
                 "boot_detail": "alive after 5s", "issues": ["workspace missing"],
                 "opencode": "connected"}]
        data = qa.assess(report(rows), self.now)
        self.assertEqual(data["counts"]["configuration_review"], 1)

    def test_stale_data_warns(self):
        data = qa.assess(report([]), dt.datetime(2026, 10, 19, 19, 10, tzinfo=dt.timezone.utc))
        self.assertTrue(any("stale" in w for w in data["warnings"]))

    def test_invalid_name_cannot_inject_markdown(self):
        row = qa.assess_server({"name": "| Sensitive\nsecret", "type": "local",
                                "boot": "pass", "issues": []}, True)
        self.assertEqual(row["name"], "invalid-name")

    def test_no_remote_endpoint_or_error_body_in_output(self):
        src = report([{"name": "mcp", "type": "remote", "boot": "pass",
                       "boot_detail": "HTTP 406 secret_value_should_not_print",
                       "issues": [], "opencode": "unknown"}], "unavailable")
        text = qa.markdown(qa.assess(src, self.now))
        self.assertNotIn("secret_value_should_not_print", text)

    def test_bad_schema_rejected(self):
        with self.assertRaises(ValueError):
            qa.assess({"servers": None}, self.now)


if __name__ == "__main__":
    unittest.main()
