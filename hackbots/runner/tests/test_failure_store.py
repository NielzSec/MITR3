"""Failure custody tests. Failure evidence must NEVER look like an approved run."""
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from hackbots.runner.broker import BrokerSession, BrokerError
from hackbots.runner import failure_store, trace_store
from hackbots.runner.snapshot import Snapshot


class FailureStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="mitr3-failure-")
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        (self.base / "hackbots").mkdir()
        self.patch = patch.object(trace_store, "PROJECT", self.base)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        data = b"line-one\nline-two\n"
        self.snapshot = Snapshot(data, hashlib.sha256(data).hexdigest())
        self.session = BrokerSession(self.snapshot)

    def test_partial_trace_separate_with_strict_nonpromotion(self):
        r, w = os.pipe()
        os.set_blocking(w, False)
        try:
            self.session.handle({"v":1,"type":"request","request_id":"r1",
                                 "operation":"read_interval","start":0,"end":9}, w)
            os.read(r, 10000)
        finally:
            os.close(r)
            os.close(w)
        self.assertEqual(self.session.trace()["event_count"], 1)
        run_id = failure_store.persist_failure(self.session, phase="IPC_READ", reason="E_PROTOCOL")
        folder = self.base / "hackbots/private/failures" / run_id
        self.assertEqual(stat.S_IMODE(folder.stat().st_mode), 0o700)
        self.assertFalse((folder/"result.json").exists())
        self.assertFalse((folder/"trace.json").exists())
        manifest = json.loads((folder/"manifest.json").read_text())
        self.assertEqual(manifest["state"], "BLOCKED")
        self.assertEqual(manifest["phase"], "IPC_READ")
        self.assertEqual(manifest["events_delivered_to_channel"], 1)
        self.assertEqual(manifest["coverage_gate"], "NOT_RUN")
        self.assertEqual(manifest["trace_gate"], "NOT_VERIFIED")
        self.assertEqual(manifest["behavioral_gate"], "NOT_RUN")
        self.assertFalse(manifest["worker_exit_verified"])
        self.assertFalse(manifest["promotable"])
        self.assertFalse(manifest["human_approved"])
        for name, expected_hash in manifest["files_sha256"].items():
            artifact = folder/name
            self.assertEqual(stat.S_IMODE(artifact.stat().st_mode), 0o600)
            self.assertEqual(hashlib.sha256(artifact.read_bytes()).hexdigest(), expected_hash)
        self.assertEqual((folder/"snapshot.bin").read_bytes(), self.snapshot.data)
        self.assertEqual(stat.S_IMODE((folder/"manifest.json").stat().st_mode), 0o600)
        self.assertEqual(json.loads((folder/"partial-trace.json").read_text())["event_count"], 1)

    def test_timeout_is_not_success_and_invalid_enums_block(self):
        ident = failure_store.persist_failure(self.session, phase="WORKER_EXIT", reason="E_TIMEOUT")
        manifest = json.loads(
            (self.base/"hackbots/private/failures"/ident/"manifest.json").read_text())
        self.assertEqual(manifest["state"], "TIMEOUT")
        self.assertEqual(manifest["events_delivered_to_channel"], 0)
        for phase, code in (("../../etc", "E_TIMEOUT"),
                            ("IPC_READ", "made-up"),
                            (True, "E_TIMEOUT")):
            with self.subTest(phase=phase, code=code), self.assertRaises(BrokerError):
                failure_store.persist_failure(self.session, phase=phase, reason=code)

    def test_symlinked_failure_tree_blocks_and_does_not_escape(self):
        private = self.base / "hackbots/private"
        private.mkdir(mode=0o700)
        other = self.base/"elsewhere"
        other.mkdir(mode=0o700)
        (private/"failures").symlink_to(other)
        with self.assertRaises(BrokerError):
            failure_store.persist_failure(self.session, phase="IPC_INIT", reason="E_IO")
        self.assertEqual(list(other.iterdir()), [])

    def test_hostile_private_directory_mode_blocks(self):
        (self.base/"hackbots/private").mkdir(mode=0o755)
        with self.assertRaises(BrokerError):
            failure_store.persist_failure(self.session, phase="IPC_READ", reason="E_BROKER")


if __name__ == "__main__":
    unittest.main()
