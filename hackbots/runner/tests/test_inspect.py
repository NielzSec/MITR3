"""Rodada 7: metadata-only inspector cannot leak artifacts or promote gates."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from hackbots.runner import inspect, trace_store, failure_store
from hackbots.runner.broker import BrokerSession
from hackbots.runner.snapshot import Snapshot


class InspectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="mitr3-inspect-")
        self.addCleanup(self.temp.cleanup)
        self.project = Path(self.temp.name)
        (self.project / "hackbots").mkdir()
        self.override = patch.object(trace_store, "PROJECT", self.project)
        self.override.start()
        self.addCleanup(self.override.stop)
        data = b"const secret = \"should-not-leak\";\n"
        self.session = BrokerSession(Snapshot(data, hashlib.sha256(data).hexdigest()))

    def make_success(self):
        fd_read, fd_write = os.pipe()
        os.set_blocking(fd_write, False)
        try:
            self.session.handle({"v": 1, "type": "request", "request_id": "done",
                                 "operation": "submit_result",
                                 "result": {"sensitive": "private-canary"}}, fd_write)
            os.read(fd_read, 4096)
        finally:
            os.close(fd_read)
            os.close(fd_write)
        return trace_store.persist(self.session)

    def make_failure(self):
        return failure_store.persist_failure(self.session, phase="IPC_READ", reason="E_TIMEOUT")

    def folder(self, kind, identifier):
        return self.project / "hackbots/private" / inspect.KINDS[kind] / identifier

    def test_complete_run_integrity_and_no_content_leak(self):
        ident = self.make_success()
        result = inspect.inspect_one("complete", ident)
        self.assertEqual(result["inspection"], "CONSISTENT_LOCAL_HASHES_NOT_AUTHENTICATED")
        self.assertEqual(result["state"], "RECORDED_SESSION_AWAITING_OUTCOME")
        self.assertEqual(result["local_verification_outcome"], "NOT_RECORDED")
        self.assertEqual(result["artifact_count"], 4)
        self.assertEqual(result["behavioral_gate"], "NOT_RUN")
        self.assertFalse(result["promotable"])
        self.assertNotIn("private-canary", json.dumps(result))
        self.assertNotIn("should-not-leak", json.dumps(result))
        self.assertNotIn("artifact_sha256", result)

    def test_failure_manifest_never_claims_approval(self):
        ident = self.make_failure()
        record = inspect.inspect_one("failed", ident)
        self.assertEqual(record["state"], "RECORDED_BLOCKED_OR_TIMEOUT")
        self.assertEqual(record["declared_outcome"], "TIMEOUT")
        self.assertEqual(record["artifact_count"], 3)
        self.assertFalse(record["human_approved"])

    def test_summary_samples_only_and_never_discloses_identifiers(self):
        ident = self.make_failure()
        counts = inspect.summary("failed")
        self.assertEqual(counts["total_opaque_run_directories"], 1)
        self.assertEqual(counts["consistent_local_hashes"], 1)
        self.assertNotIn(ident, json.dumps(counts))
        self.assertNotIn("secret", json.dumps(counts))
        self.assertEqual(counts["sampling"], "LEXICOGRAPHIC_OPAQUE_IDS_NOT_RECENCY")

    def test_tamper_snapshot_blocks(self):
        ident = self.make_failure()
        file = self.folder("failed", ident) / "snapshot.bin"
        file.write_bytes(b"different")
        with self.assertRaises(inspect.InspectionBlocked):
            inspect.inspect_one("failed", ident)
        self.assertEqual(inspect.summary("failed")["blocked_or_inconsistent"], 1)

    def test_reject_symlink_and_extra_files(self):
        ident = self.make_failure()
        folder = self.folder("failed", ident)
        (folder / "extra-secret").write_text("do not read me")
        with self.assertRaises(inspect.InspectionBlocked):
            inspect.inspect_one("failed", ident)
        (folder / "extra-secret").unlink()
        snapshot = folder / "snapshot.bin"
        snapshot.unlink()
        snapshot.symlink_to("/etc/passwd")
        with self.assertRaises(inspect.InspectionBlocked):
            inspect.inspect_one("failed", ident)

    def test_reject_bad_mode_and_fake_promotion(self):
        ident = self.make_failure()
        folder = self.folder("failed", ident)
        artifact = folder / "journal.json"
        os.chmod(artifact, 0o644)
        with self.assertRaises(inspect.InspectionBlocked):
            inspect.inspect_one("failed", ident)
        os.chmod(artifact, 0o600)
        manifest = folder / "manifest.json"
        obj = json.loads(manifest.read_text())
        obj["promotable"] = True
        manifest.write_text(json.dumps(obj))
        with self.assertRaises(inspect.InspectionBlocked):
            inspect.inspect_one("failed", ident)

    def test_invalid_identifiers_never_reach_filesystem(self):
        for invalid in ("../foo", "/etc/passwd", "1"*33, "b"*31, "", "ABC"*10, None):
            with self.subTest(invalid=invalid), self.assertRaises(inspect.InspectionBlocked):
                inspect.inspect_one("failed", invalid)

    def test_missing_record_does_not_leak_directory_descriptors(self):
        self.make_failure()
        before = len(os.listdir("/proc/self/fd"))
        for _ in range(50):
            with self.assertRaises(inspect.InspectionBlocked):
                inspect.inspect_one("failed", "0" * 32)
        after = len(os.listdir("/proc/self/fd"))
        self.assertEqual(before, after)

    def test_manifest_duplicate_keys_block(self):
        ident = self.make_failure()
        folder = self.folder("failed", ident)
        manifest = folder / "manifest.json"
        raw = manifest.read_text()
        manifest.write_text(raw[:-1] + ', "promotable": true}')
        with self.assertRaises(inspect.InspectionBlocked):
            inspect.inspect_one("failed", ident)

    def test_cli_result_is_bounded_non_sensitive(self):
        ident = self.make_success()
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = inspect.main(["inspect", "--kind", "complete", "--run-id", ident])
        self.assertEqual(code, 0)
        obj = json.loads(output.getvalue())
        self.assertEqual(obj["run_id"], ident)
        self.assertNotIn("private-canary", output.getvalue())
        self.assertNotIn("should-not-leak", output.getvalue())

    def test_cli_bad_target_does_not_echo_path(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            rc = inspect.main(["inspect", "--kind", "failed",
                               "--run-id", "../../PRIVATE_SECRET_CANARY"])
        self.assertEqual(rc, 2)
        self.assertNotIn("PRIVATE_SECRET_CANARY", output.getvalue())
        self.assertEqual(json.loads(output.getvalue())["inspection"], "BLOCKED")

    def test_summary_rejects_unsafe_budget(self):
        for limit in (0, -1, 101, 1.5, True, "5"):
            with self.assertRaises(inspect.InspectionBlocked):
                inspect.summary("failed", limit)

    def test_symlinked_record_dir_blocks(self):
        ident = self.make_failure()
        folder = self.folder("failed", ident)
        fake_id = "f" * 32
        (folder.parent / fake_id).symlink_to(folder)
        with self.assertRaises(inspect.InspectionBlocked):
            inspect.inspect_one("failed", fake_id)

    def test_unknown_manifest_version_and_forged_output_gate_block(self):
        ident = self.make_success()
        path = self.folder("complete", ident) / "manifest.json"
        original = json.loads(path.read_text())
        for overrides in ({"version": 999}, {"version": True}, {"output_gate": "PASS"}):
            with self.subTest(overrides=overrides):
                path.write_text(json.dumps({**original, **overrides}))
                with self.assertRaises(inspect.InspectionBlocked):
                    inspect.inspect_one("complete", ident)

    def test_summary_stops_enumeration_at_budget(self):
        self.make_failure()
        # Lazy hostile directory stream: consuming more than the budget is itself a failure.
        from types import SimpleNamespace
        def entries():
            for _ in range(10001):
                yield SimpleNamespace(name="0" * 32)
            self.fail("directory enumeration continued beyond budget")
        with patch.object(inspect.os, "scandir", return_value=contextlib.nullcontext(entries())):
            with self.assertRaises(inspect.InspectionBlocked):
                inspect.summary("failed")


if __name__ == "__main__":
    unittest.main()
