"""F04 regression: persisted session != locally verified final outcome.

All synthetic, no agent or target. Same-UID attacks remain an open P0.
"""
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from hackbots.runner import inspect, outcome_store, trace_store
from hackbots.runner.broker import BrokerError, BrokerSession
from hackbots.runner.snapshot import Snapshot


def final_session(data=b"example\n"):
    session = BrokerSession(Snapshot(data, hashlib.sha256(data).hexdigest()))
    r, w = os.pipe()
    os.set_blocking(w, False)
    try:
        session.handle({"v": 1, "type": "request", "request_id": "done",
                        "operation": "submit_result", "result": {"ok": True}}, w)
        os.read(r, 4096)
    finally:
        os.close(r)
        os.close(w)
    return session


class OutcomeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="outcome-test-")
        self.addCleanup(self.tmp.cleanup)
        self.project = Path(self.tmp.name)
        (self.project / "hackbots").mkdir()
        self.patch = patch.object(trace_store, "PROJECT", self.project)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.identifier = trace_store.persist(final_session())
        self.folder = self.project / "hackbots/private/runs" / self.identifier

    def record(self, **kwargs):
        base = dict(status="VERIFIED", trace_gate="PASS",
                    coverage_gate="PASS", deterministic_oracle="PASS")
        base.update(kwargs)
        return outcome_store.persist_outcome(self.identifier, **base)

    def test_session_only_remains_pending_and_historical_files_are_unchanged(self):
        original = (self.folder / "manifest.json").read_bytes()
        self.assertEqual(json.loads(original)["state"], "SESSION_RECORDED")
        pending = inspect.inspect_one("complete", self.identifier)
        self.assertEqual(pending["state"], "RECORDED_SESSION_AWAITING_OUTCOME")
        self.assertEqual(pending["local_verification_outcome"], "NOT_RECORDED")
        self.assertEqual(self.record(), "VERIFIED")
        final = inspect.inspect_one("complete", self.identifier)
        self.assertEqual(final["state"], "RECORDED_LOCAL_VERIFIED_NOT_APPROVED")
        self.assertEqual(final["local_verification_outcome"], "VERIFIED")
        self.assertEqual(final["artifact_count"], 5)
        self.assertFalse(final["promotable"])
        self.assertEqual((self.folder / "manifest.json").read_bytes(), original)
        self.assertEqual(stat.S_IMODE((self.folder / "outcome.json").stat().st_mode), 0o600)

    def test_failed_and_blocked_outcomes_cannot_be_promoted(self):
        options = [
            dict(status="FAILED", trace_gate="PASS", coverage_gate="PASS",
                 deterministic_oracle="FAIL"),
            dict(status="BLOCKED", trace_gate="NOT_VERIFIED",
                 coverage_gate="NOT_RUN", deterministic_oracle="NOT_RUN",
                 reason_code="E_VERIFY"),
        ]
        for fields in options:
            with self.subTest(status=fields["status"]):
                with tempfile.TemporaryDirectory(prefix="sample-", dir=self.project):
                    identifier = trace_store.persist(final_session())
                    outcome_store.persist_outcome(identifier, **fields)
                    state = inspect.inspect_one("complete", identifier)
                    self.assertEqual(state["local_verification_outcome"], fields["status"])
                    self.assertFalse(state["human_approved"])

    def test_forged_outcome_and_ambiguity_block(self):
        self.record()
        p = self.folder / "outcome.json"
        raw = json.loads(p.read_text())
        raw["human_approved"] = True
        p.write_text(json.dumps(raw))
        with self.assertRaises(inspect.InspectionBlocked):
            inspect.inspect_one("complete", self.identifier)
        raw["human_approved"] = False
        p.write_text(json.dumps(raw)[:-1] + ', "status": "BLOCKED"}')
        with self.assertRaises(inspect.InspectionBlocked):
            inspect.inspect_one("complete", self.identifier)

    def test_binding_to_session_manifest_and_unique_creation(self):
        self.record()
        with self.assertRaises(BrokerError):
            self.record()
        orig = self.folder / "manifest.json"
        orig.write_bytes(orig.read_bytes() + b" ")
        with self.assertRaises(inspect.InspectionBlocked):
            inspect.inspect_one("complete", self.identifier)

    def test_invalid_state_combinations_fail_closed(self):
        bad = [
            dict(status="VERIFIED", trace_gate="FAIL"),
            dict(status="VERIFIED", deterministic_oracle="FAIL"),
            dict(status="FAILED", deterministic_oracle="PASS"),
            dict(status="BLOCKED", reason_code=None),
            dict(status="BLOCKED", reason_code="E_UNLISTED"),
            dict(status="VERIFIED", reason_code="E_VERIFY"),
            dict(status=True),
        ]
        for item in bad:
            with self.subTest(item=item), self.assertRaises(BrokerError):
                self.record(**item)
        self.assertFalse((self.folder / "outcome.json").exists())

    def test_outcome_symlink_and_directory_mode_block(self):
        (self.folder / "outcome.json").symlink_to(self.folder / "result.json")
        with self.assertRaises(BrokerError):
            self.record()
        (self.folder / "outcome.json").unlink()
        os.chmod(self.folder, 0o755)
        with self.assertRaises(BrokerError):
            self.record()


if __name__ == "__main__":
    unittest.main()
