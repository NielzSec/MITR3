"""Offline broker tests. No subprocess, model, target requests, or worker execution."""
import base64
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from hackbots.runner import trace_store
from hackbots.runner.broker import BrokerError, BrokerSession, write_frame
from hackbots.runner.policies import Policy
from hackbots.runner.protocol import decode_message, ProtocolViolation
from hackbots.runner.snapshot import Snapshot, SnapshotError, load_snapshot


ROOT = Path(__file__).resolve().parents[3]
FIXTURES = ROOT / "hackbots/runner/tests/fixtures"


def pinned(data=b'const a = fetch("/demo");\n'):
    return Snapshot(data, hashlib.sha256(data).hexdigest())


def message(rid="r1", **fields):
    return {"v": 1, "type": "request", "request_id": rid,
            "operation": "read_interval", "start": 0, "end": 4, **fields}


class BrokerTests(unittest.TestCase):
    def setUp(self):
        self.session = BrokerSession(pinned())
        self.r, self.w = os.pipe()
        os.set_blocking(self.w, False)
        self.addCleanup(os.close, self.r)
        self.addCleanup(os.close, self.w)

    def decoded(self, frame):
        size = struct.unpack("!I", frame[:4])[0]
        self.assertEqual(len(frame), size + 4)
        return decode_message(frame[4:])

    def test_successful_delivery_commits_real_interval(self):
        pending = self.session.prepare(message())
        self.assertEqual(self.session.trace()["event_count"], 0)
        self.session.send(pending, self.w)
        frame = os.read(self.r, 4096)
        response = self.decoded(frame)
        self.assertEqual(base64.b64decode(response["data"]["bytes"]), b"cons")
        self.assertEqual(self.session.trace()["events"][0], {
            "seq": 1, "start": 0, "end": 4,
            "sha256": hashlib.sha256(b"cons").hexdigest()})
        self.assertEqual(self.session.status()["behavioral_gate"], "NOT_RUN")

    def test_submit_only_after_ack_and_is_terminal(self):
        self.session.prepare(message("r1"))
        with self.assertRaises(BrokerError):
            self.session.prepare(message("r2"))
        self.session.send(self.session.pending, self.w)
        os.read(self.r, 4096)
        self.session.handle({"v": 1, "type": "request", "request_id": "s1",
                             "operation": "submit_result", "result": {"ok": True}}, self.w)
        self.assertEqual(self.session.result_bytes, b'{"ok":true}')
        self.assertTrue(self.session.finished)
        self.assertFalse(self.session.status()["promotable"])
        with self.assertRaises(BrokerError):
            self.session.prepare(message("r3"))

    def test_duplicate_request_id_blocked(self):
        self.session.handle(message(), self.w)
        os.read(self.r, 4096)
        with self.assertRaises(ProtocolViolation):
            self.session.prepare(message())
        self.assertTrue(self.session.failed)

    def test_rejected_requests_counted_and_limit_enforced(self):
        session = BrokerSession(pinned(), Policy(max_rejected=2))
        for i in range(2):
            invalid = {**message(f"r{i}"), "end": 0}
            pending = session.prepare(invalid)
            self.assertEqual(self.decoded(pending.framed)["ok"], False)
            session.send(pending, self.w)
            os.read(self.r, 4096)
        with self.assertRaises(ProtocolViolation):
            session.prepare({**message("r3"), "end": 0})
        self.assertTrue(session.failed)
        self.assertEqual(session.trace()["event_count"], 0)

    def test_bounds_and_cumulative_budget(self):
        session = BrokerSession(pinned(b"abcdefgh"), Policy(max_total_bytes=5, max_read_bytes=5))
        session.handle(message(), self.w)
        os.read(self.r, 4096)
        pending = session.prepare({**message("r2"), "start": 4, "end": 6})
        self.assertEqual(self.decoded(pending.framed)["error"], "E_READ_BUDGET")
        session.send(pending, self.w)
        os.read(self.r, 4096)
        self.assertEqual(session.total_read_bytes, 4)
        self.assertEqual(session.trace()["event_count"], 1)

    def test_out_of_snapshot_bounds_rejected(self):
        s = BrokerSession(pinned(b"abcd"))
        p = s.prepare({**message(), "end": 5})
        self.assertEqual(self.decoded(p.framed)["error"], "E_RANGE")
        self.assertEqual(s.trace()["event_count"], 0)

    def test_event_limit_enforced(self):
        s = BrokerSession(pinned(), Policy(max_events=1))
        s.handle(message(), self.w)
        os.read(self.r, 4096)
        p = s.prepare(message("r2"))
        self.assertEqual(self.decoded(p.framed)["error"], "E_READ_BUDGET")

    def test_broken_pipe_never_commits_delivery(self):
        r, w = os.pipe()
        os.close(r)
        os.set_blocking(w, False)
        try:
            p = self.session.prepare(message())
            with self.assertRaises(BrokerError):
                self.session.send(p, w)
            self.assertEqual(self.session.trace()["event_count"], 0)
            self.assertTrue(self.session.failed)
        finally:
            os.close(w)

    def test_blocking_pipe_is_rejected(self):
        r, w = os.pipe()
        try:
            p = self.session.prepare(message())
            with self.assertRaises(BrokerError):
                self.session.send(p, w)
            self.assertFalse(self.session.delivered)
        finally:
            os.close(r); os.close(w)

    def test_response_write_deadline(self):
        readfd, writefd = os.pipe()
        os.set_blocking(writefd, False)
        try:
            with self.assertRaises(TimeoutError):
                write_frame(writefd, b"x", time.monotonic() - 1)
        finally:
            os.close(readfd); os.close(writefd)

    def test_reading_multiple_and_replay_offsets(self):
        s = BrokerSession(pinned(b"a\nb\n"))
        for i in range(2):
            s.handle({**message(f"r{i}"), "end": 4}, self.w)
            os.read(self.r, 4096)
        self.assertEqual(s.total_read_bytes, 8)
        self.assertEqual([x["seq"] for x in s.trace()["events"]], [1, 2])

    def test_result_decimal_remains_exact(self):
        from decimal import Decimal
        s = BrokerSession(pinned())
        payload = {"v":1,"type":"request","request_id":"s1",
                   "operation":"submit_result","result":{"n":Decimal("1.0000000000000001")}}
        p = s.prepare(payload)
        self.assertIsNone(s.result_bytes)
        s.send(p, self.w)
        self.assertIn(b"1.0000000000000001",s.result_bytes)

    def test_partial_large_response_times_out_without_committed_trace(self):
        session = BrokerSession(pinned(b"z"*65_536),
                                Policy(timeout_s=1, request_timeout_s=0.03))
        pending = session.prepare({**message(), "end": 65_536})
        r, w = os.pipe()
        os.set_blocking(w, False)
        try:
            with self.assertRaises(TimeoutError):
                session.send(pending, w)
            self.assertTrue(session.failed)
            self.assertEqual(session.trace()["event_count"], 0)
        finally:
            os.close(r); os.close(w)

    def test_trace_passes_existing_execution_verifier_without_auto_approval(self):
        import subprocess, sys
        with tempfile.TemporaryDirectory(prefix="ev-", dir=FIXTURES) as tmp:
            original = Path(tmp)/"fixture.js"
            original.write_bytes(b"aa\nbb\n")
            snap = load_snapshot(original.relative_to(ROOT).as_posix(),
                                 hashlib.sha256(original.read_bytes()).hexdigest())
            session = BrokerSession(snap)
            r, w = os.pipe()
            os.set_blocking(w, False)
            try:
                for n,start,end in ((1,0,3),(2,3,6)):
                    session.handle({"v":1,"type":"request","request_id":f"r{n}",
                                    "operation":"read_interval","start":start,"end":end}, w)
                    os.read(r,4096)
            finally:
                os.close(r);os.close(w)
            trace = Path(tmp)/"trace.json"
            trace.write_text(json.dumps(session.trace()))
            runner = ROOT/"hackbots/skill-builder/execution_verifier.py"
            done = subprocess.run(
                [sys.executable,str(runner),"verify",
                 original.relative_to(ROOT).as_posix(),trace.relative_to(ROOT).as_posix(),
                 "--artifact-sha256",snap.sha256],
                cwd=ROOT,capture_output=True,text=True,timeout=5)
            self.assertEqual(done.returncode,0,done.stderr)
            report=json.loads(done.stdout)
            self.assertEqual(report["coverage_gate"],"PASS")
            self.assertEqual(report["trace_authenticity"],"NOT_VERIFIED")
            self.assertEqual(report["behavioral_gate"],"NOT_RUN")
            self.assertFalse(report["promotable"])

    def test_state_is_not_auto_approved(self):
        s=BrokerSession(pinned())
        self.assertEqual(s.status()["trace_authenticity"], "NOT_VERIFIED")
        self.assertEqual(s.status()["output_gate"], "NOT_RUN")
        self.assertFalse(s.status()["human_approved"])


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        FIXTURES.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix="sb-", dir=FIXTURES)
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "sample.js"
        self.path.write_bytes(b'fetch("/api/test");\n')
        self.rel = self.path.relative_to(ROOT).as_posix()
        self.sha = hashlib.sha256(self.path.read_bytes()).hexdigest()

    def test_immutable_snapshot_and_external_sha(self):
        snap = load_snapshot(self.rel, self.sha)
        self.path.write_bytes(b'fetch("/changed");\n')
        self.assertEqual(snap.data, b'fetch("/api/test");\n')
        with self.assertRaises(SnapshotError):
            load_snapshot(self.rel, self.sha)

    def test_fake_snapshot_rejected(self):
        with self.assertRaises(SnapshotError):
            Snapshot(b"wrong", hashlib.sha256(b"other").hexdigest())

    def test_path_escape_symlink_and_secret_tree_rejected(self):
        for invalid in ("/etc/passwd","../x","hackbots/private/secret"):
            with self.assertRaises(SnapshotError):
                load_snapshot(invalid, self.sha)
        link = self.path.parent / "linked.js"
        link.symlink_to(self.path)
        with self.assertRaises(SnapshotError):
            load_snapshot(link.relative_to(ROOT).as_posix(), self.sha)

    def test_oversized_and_invalid_inputs(self):
        with self.assertRaises(SnapshotError):
            load_snapshot(self.rel, "0"*64)
        with self.assertRaises(SnapshotError):
            load_snapshot(self.rel, self.sha, Policy(max_fixture_bytes=3))
        with self.assertRaises(SnapshotError):
            load_snapshot(self.rel, "invalid")
        with self.assertRaises(SnapshotError):
            load_snapshot(self.rel, self.sha, Policy(max_fixture_bytes=1))

    def test_hardlink_file_rejected(self):
        linked = self.path.parent / "hardlinked.js"
        os.link(self.path, linked)
        with self.assertRaises(SnapshotError):
            load_snapshot(linked.relative_to(ROOT).as_posix(), self.sha)

    def test_pipe_file_rejected(self):
        fifo = self.path.parent / "special"
        os.mkfifo(fifo)
        with self.assertRaises(SnapshotError):
            load_snapshot(fifo.relative_to(ROOT).as_posix(), self.sha)


class PrivateStoreTests(unittest.TestCase):
    def test_store_private_modes_and_preserves_trace(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "hackbots").mkdir()
            session = BrokerSession(pinned())
            r, w = os.pipe()
            try:
                os.set_blocking(w, False)
                session.handle(message(), w)
                os.read(r, 4096)
                session.handle({"v":1,"type":"request","request_id":"s1",
                                "operation":"submit_result","result":{"ok":True}},w)
                os.read(r, 4096)
            finally:
                os.close(r); os.close(w)
            with patch.object(trace_store, "PROJECT", base):
                rid = trace_store.persist(session)
            private = base / "hackbots/private"
            folder = private / "runs" / rid
            self.assertEqual(stat.S_IMODE(private.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(folder.stat().st_mode), 0o700)
            for name in ("trace.json","result.json","journal.json","manifest.json"):
                self.assertEqual(stat.S_IMODE((folder/name).stat().st_mode), 0o600)
            data=json.loads((folder/"trace.json").read_text())
            self.assertEqual(data["events"][0]["sha256"], hashlib.sha256(b"cons").hexdigest())
            manifest=json.loads((folder/"manifest.json").read_text())
            self.assertFalse(manifest["promotable"])
            self.assertEqual(set(manifest["files_sha256"]), {"trace.json", "result.json", "journal.json", "snapshot.bin"})
            for name, digest in manifest["files_sha256"].items():
                self.assertEqual(digest, hashlib.sha256((folder/name).read_bytes()).hexdigest())
            journal=json.loads((folder/"journal.json").read_text())
            self.assertEqual(journal[0]["state"], "requested")
            self.assertEqual(journal[1]["state"], "mediated")
            self.assertEqual(journal[2]["state"], "delivered")

    def test_refuse_incomplete(self):
        with self.assertRaises(BrokerError):
            trace_store.persist(BrokerSession(pinned()))

    def test_bad_private_permissions_block(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "hackbots").mkdir()
            (root / "hackbots/private").mkdir(mode=0o755)
            with patch.object(trace_store,"PROJECT",root):
                r,w=os.pipe();os.set_blocking(w,False)
                session=BrokerSession(pinned())
                try:
                    session.handle({"v":1,"type":"request","request_id":"s1",
                                    "operation":"submit_result","result":{}},w)
                    os.read(r,4096)
                finally:
                    os.close(r);os.close(w)
                with self.assertRaises(BrokerError):
                    trace_store.persist(session)


if __name__=="__main__":
    unittest.main()
