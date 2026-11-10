"""Round 5: real offline worker integration tests; no LLM, internet or JS execution."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile
import unittest
from unittest.mock import patch

from hackbots.runner import runner, sandbox

ROOT = Path(__file__).resolve().parents[3]
FIXTURE_ROOT = ROOT / "hackbots/runner/tests/fixtures"


class PureRunnerTests(unittest.TestCase):
    def test_oracle_respects_byte_lines_not_splitlines(self):
        from hackbots.runner.snapshot import Snapshot
        for payload, expected in ((b"", 0), (b"a\n", 1),
                                  (b"a\nb", 2), (b"a\r\nb\r\n", 2),
                                  ("é\nñ".encode(), 2)):
            with self.subTest(payload=payload):
                snap = Snapshot(payload, hashlib.sha256(payload).hexdigest())
                self.assertEqual(runner.expected_observation(snap)["physical_lines"], expected)

    def test_numeric_oracle_rejects_boolean_substitution(self):
        expected = {"artifact_bytes": 1, "physical_lines": 1}
        self.assertTrue(runner.matches_observation(dict(expected), expected))
        self.assertFalse(runner.matches_observation(
            {"artifact_bytes": True, "physical_lines": 1}, expected))
        self.assertFalse(runner.matches_observation(
            {"artifact_bytes": 1, "physical_lines": 1.0}, expected))
        self.assertFalse(runner.matches_observation(
            {"artifact_bytes": 1, "physical_lines": 1, "extra": 0}, expected))

    def test_worker_source_is_pinned_and_blocks_links(self):
        with tempfile.TemporaryDirectory(prefix="worker-source-") as directory:
            temp = Path(directory)
            original = temp / "source.py"
            original.write_text("print('offline')\\n".replace("\\n", "\n"))
            with patch.object(runner, "WORKER", original):
                self.assertEqual(runner.trusted_worker_source(), original.read_text())
                link = temp / "alias.py"
                link.symlink_to(original)
                with patch.object(runner, "WORKER", link):
                    with self.assertRaises(runner.RunnerError):
                        runner.trusted_worker_source()
                os.link(original, temp / "hardlink.py")
                with self.assertRaises(runner.RunnerError):
                    runner.trusted_worker_source()
                (temp / "hardlink.py").unlink()
                os.chmod(original, 0o666)
                with self.assertRaises(runner.RunnerError):
                    runner.trusted_worker_source()

    def test_trace_serialization_respects_verifier_one_mb_limit(self):
        class FakeSession:
            def __init__(self, data):
                self.data = data

            def trace(self):
                return self.data
        self.assertTrue(runner.trace_fits_verifier_input_budget(
            FakeSession({"schema_version": 1, "events": []})))
        # Broker's event count can stay below 10k while JSON exceeds 1 MB.
        one = {"seq": 1, "start": 0, "end": 1, "sha256": "a" * 64}
        huge = {"schema_version": 1, "events": [one] * 10_000}
        self.assertFalse(runner.trace_fits_verifier_input_budget(FakeSession(huge)))

    def test_root_cannot_launch_mission(self):
        with patch.object(runner.os, "geteuid", return_value=0):
            with self.assertRaises(runner.RunnerError):
                runner.run_offline("hackbots/examples/sample.js", "0" * 64)

    def test_reviewer_pin_required(self):
        with self.assertRaises(runner.RunnerError):
            runner.verifier_check("../../etc/passwd", "0" * 64)

    def test_cli_sanitizes_unexpected_args(self):
        with self.assertRaises(SystemExit) as error:
            runner.main(["run", "--unexpected-sensitive-argument"])
        self.assertEqual(error.exception.code, 2)


class LiveSandboxRunnerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.geteuid() == 0:
            raise unittest.SkipTest("NOT_RUN: unprivileged user required")
        if not sandbox.ready(sandbox.doctor()):
            raise unittest.SkipTest("NOT_RUN: host sandbox unavailable")
        FIXTURE_ROOT.mkdir(parents=True, exist_ok=True)

    def cleanup_run(self, report):
        root = ROOT / "hackbots/private/runs"
        run_id = report["run_id"]
        if len(run_id) == 32 and all(c in "0123456789abcdef" for c in run_id):
            shutil.rmtree(root / run_id)

    def test_complete_synthetic_mission_and_private_snapshot(self):
        fixture = ROOT / "hackbots/examples/sample.js"
        sha = hashlib.sha256(fixture.read_bytes()).hexdigest()
        report = runner.run_offline(fixture.relative_to(ROOT).as_posix(), sha)
        self.addCleanup(self.cleanup_run, report)
        self.assertEqual(report["state"], "REVIEW")
        self.assertEqual(report["trace_gate"], "PASS")
        self.assertEqual(report["coverage_gate"], "PASS")
        self.assertEqual(report["deterministic_oracle"], "PASS")
        self.assertEqual(report["output_gate"], "NOT_RUN")
        self.assertEqual(report["behavioral_gate"], "NOT_RUN")
        self.assertFalse(report["promotable"])
        evidence = ROOT / "hackbots/private/runs" / report["run_id"]
        self.assertEqual(stat.S_IMODE(evidence.stat().st_mode), 0o700)
        self.assertEqual((evidence / "snapshot.bin").read_bytes(), fixture.read_bytes())
        manifest = json.loads((evidence / "manifest.json").read_text())
        self.assertEqual(manifest["files_sha256"]["snapshot.bin"], sha)
        self.assertFalse(manifest["human_approved"])
        outcome = json.loads((evidence / "outcome.json").read_text())
        self.assertEqual(outcome["status"], "VERIFIED")
        self.assertEqual(outcome["deterministic_oracle"], "PASS")
        self.assertFalse(outcome["promotable"])
        from hackbots.runner import inspect
        self.assertEqual(inspect.inspect_one("complete", report["run_id"])["state"],
                         "RECORDED_LOCAL_VERIFIED_NOT_APPROVED")
        for name in ("snapshot.bin", "trace.json", "result.json", "manifest.json"):
            self.assertEqual(stat.S_IMODE((evidence/name).stat().st_mode), 0o600)

    def test_empty_fixture_remains_not_applicable(self):
        with tempfile.TemporaryDirectory(prefix="r5-", dir=FIXTURE_ROOT) as temp:
            fixture = Path(temp) / "empty.js"
            fixture.write_bytes(b"")
            sha = hashlib.sha256(b"").hexdigest()
            report = runner.run_offline(fixture.relative_to(ROOT).as_posix(), sha)
            self.addCleanup(self.cleanup_run, report)
            self.assertEqual(report["trace_gate"], "PASS")
            self.assertEqual(report["coverage_gate"], "NOT_APPLICABLE")
            self.assertEqual(report["units_covered"], 0)
            self.assertEqual(report["deterministic_oracle"], "PASS")
            self.assertEqual(report["behavioral_gate"], "NOT_RUN")

    def test_manifest_pins_staged_bytes_separately_from_installed_worker(self):
        fixture = ROOT / "hackbots/examples/sample.js"
        source = runner.trusted_worker_source() + "\n# synthetic staged build variant\n"
        with patch.object(runner, "trusted_worker_source", return_value=source):
            report = runner.run_offline(fixture.relative_to(ROOT).as_posix(),
                                        hashlib.sha256(fixture.read_bytes()).hexdigest())
        self.addCleanup(self.cleanup_run, report)
        manifest = json.loads((ROOT / "hackbots/private/runs" / report["run_id"] / "manifest.json").read_text())
        self.assertEqual(manifest["staged_worker_sha256"], hashlib.sha256(source.encode()).hexdigest())
        self.assertEqual(manifest["staged_worker_sha256"], report["worker_sha256"])
        self.assertNotEqual(manifest["staged_worker_sha256"], manifest["modules_sha256"]["workers/deterministic_js.py"])
        self.assertEqual(manifest["trace_authenticity"], "NOT_VERIFIED")

    def test_wrong_pin_blocks_before_worker(self):
        with self.assertRaises(Exception):
            runner.run_offline("hackbots/examples/sample.js", "0" * 64)

    def test_more_than_10000_physical_lines_blocks_before_any_run_record(self):
        with tempfile.TemporaryDirectory(prefix="f04-lines-", dir=FIXTURE_ROOT) as tmp:
            fixture = Path(tmp) / "too-many-lines.js"
            raw = bytes([10]) * 10001
            fixture.write_bytes(raw)
            complete = ROOT / "hackbots/private/runs"
            before = set(complete.iterdir()) if complete.exists() else set()
            with self.assertRaises(runner.RunnerError):
                runner.run_offline(fixture.relative_to(ROOT).as_posix(),
                                   hashlib.sha256(raw).hexdigest())
            self.assertEqual(set(complete.iterdir()) - before, set())

    def test_verifier_blocked_creates_separate_final_outcome_not_approval(self):
        fixture = ROOT / "hackbots/examples/sample.js"
        complete = ROOT / "hackbots/private/runs"
        previous = set(complete.iterdir()) if complete.exists() else set()
        with patch.object(runner, "verifier_check",
                          side_effect=runner.RunnerError("synthetic verifier error")):
            with self.assertRaises(runner.RunnerError):
                runner.run_offline(fixture.relative_to(ROOT).as_posix(),
                                   hashlib.sha256(fixture.read_bytes()).hexdigest())
        created = set(complete.iterdir()) - previous
        self.assertEqual(len(created), 1)
        folder = created.pop()
        self.addCleanup(shutil.rmtree, folder)
        outcome = json.loads((folder / "outcome.json").read_text())
        self.assertEqual(outcome["status"], "BLOCKED")
        self.assertEqual(outcome["reason_code"], "E_VERIFY")
        from hackbots.runner import inspect
        result = inspect.inspect_one("complete", folder.name)
        self.assertEqual(result["state"], "RECORDED_LOCAL_VERIFICATION_BLOCKED")
        self.assertFalse(result["promotable"])

    def test_timeout_worker_creates_only_incomplete_private_record(self):
        from hackbots.runner.policies import Policy
        fixture = ROOT / "hackbots/examples/sample.js"
        sha = hashlib.sha256(fixture.read_bytes()).hexdigest()
        failures = ROOT / "hackbots/private/failures"
        before = set(failures.iterdir()) if failures.exists() else set()
        with patch.object(runner, "trusted_worker_source",
                          return_value="import time\ntime.sleep(15)\n"):
            with self.assertRaises(TimeoutError):
                runner.run_offline(fixture.relative_to(ROOT).as_posix(), sha,
                                   policy=Policy(timeout_s=2, request_timeout_s=1))
        created = set(failures.iterdir()) - before
        self.assertEqual(len(created), 1)
        folder = created.pop()
        self.addCleanup(shutil.rmtree, folder)
        manifest = json.loads((folder / "manifest.json").read_text())
        self.assertEqual(manifest["state"], "TIMEOUT")
        self.assertEqual(manifest["reason_code"], "E_TIMEOUT")
        self.assertFalse(manifest["promotable"])
        self.assertEqual(manifest["behavioral_gate"], "NOT_RUN")
        self.assertFalse((folder / "result.json").exists())

    def test_malformed_untrusted_worker_is_blocked(self):
        fixture = ROOT / "hackbots/examples/sample.js"
        sha = hashlib.sha256(fixture.read_bytes()).hexdigest()
        failures = ROOT / "hackbots/private/failures"
        previous = set(failures.iterdir()) if failures.exists() else set()
        # Injected source is staged only inside the temporary isolated worker.
        with patch.object(runner, "trusted_worker_source",
                          return_value='import os\nos.write(1, b"BADFRAME")\n'):
            with self.assertRaises(Exception):
                runner.run_offline(fixture.relative_to(ROOT).as_posix(), sha)
        created = set(failures.iterdir()) - previous
        self.assertEqual(len(created), 1)
        folder = created.pop()
        self.addCleanup(shutil.rmtree, folder)
        manifest = json.loads((folder / "manifest.json").read_text())
        self.assertEqual(manifest["state"], "BLOCKED")
        self.assertEqual(manifest["phase"], "IPC_READ")
        self.assertEqual(manifest["behavioral_gate"], "NOT_RUN")
        self.assertEqual(manifest["trace_gate"], "NOT_VERIFIED")
        self.assertFalse(manifest["promotable"])
        self.assertFalse((folder / "result.json").exists())
        self.assertFalse((folder / "trace.json").exists())


if __name__ == "__main__":
    unittest.main()
