"""Broker traces vs the REAL execution_verifier.py, plus evidence-store hardening.

Offline only: the single subprocess runs execution_verifier.py on synthetic bytes.
A PASS here proves trace consistency/coverage of broker-delivered bytes. It does
NOT prove isolation, worker behavior, trace authenticity or output correctness.
"""
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from hackbots.runner import trace_store
from hackbots.runner.broker import BrokerError, BrokerSession
from hackbots.runner.snapshot import Snapshot

ROOT = Path(__file__).resolve().parents[3]
FIXTURES = ROOT / "hackbots/runner/tests/fixtures"
VERIFIER = ROOT / "hackbots/skill-builder/execution_verifier.py"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def deliver(data, ranges):
    """Run real read_interval requests through BrokerSession; return its trace."""
    session = BrokerSession(Snapshot(data, sha(data)))
    r, w = os.pipe()
    os.set_blocking(w, False)
    try:
        for i, (start, end) in enumerate(ranges):
            session.handle({"v": 1, "type": "request", "request_id": f"r{i}",
                            "operation": "read_interval", "start": start, "end": end}, w)
            os.read(r, 1 << 17)
    finally:
        os.close(r)
        os.close(w)
    return session.trace()


class VerifierMatrix(unittest.TestCase):
    def setUp(self):
        FIXTURES.mkdir(parents=True, exist_ok=True)
        tmp = tempfile.TemporaryDirectory(prefix="tm-", dir=FIXTURES)
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)

    def verify(self, data, trace, pin=None, raw_trace=None):
        artifact = self.dir / "fixture.js"
        artifact.write_bytes(data)
        trace_path = self.dir / "trace.json"
        trace_path.write_bytes(raw_trace if raw_trace is not None else json.dumps(trace).encode())
        done = subprocess.run(
            [sys.executable, str(VERIFIER), "verify", artifact.relative_to(ROOT).as_posix(),
             trace_path.relative_to(ROOT).as_posix(), "--artifact-sha256", pin or sha(data)],
            cwd=ROOT, capture_output=True, text=True, timeout=10)
        report = json.loads(done.stdout) if done.stdout.strip() else None
        return done.returncode, report

    def assertCoverage(self, data, ranges, expected, rc, units=None):
        code, report = self.verify(data, deliver(data, ranges))
        self.assertEqual(code, rc, report)
        self.assertEqual(report["coverage_gate"], expected)
        self.assertEqual(report["trace_authenticity"], "NOT_VERIFIED")
        self.assertEqual(report["behavioral_gate"], "NOT_RUN")
        self.assertFalse(report["promotable"])
        if units is not None:
            self.assertEqual(report["units_expected"], units)
        return report

    def test_b1_omitted_line_fails(self):
        r = self.assertCoverage(b"aa\nbb\ncc\n", [(0, 3), (6, 9)], "FAIL", 1, 3)
        self.assertEqual(r["units_covered"], 2)

    def test_b2_omitted_single_byte_fails(self):
        self.assertCoverage(b"aa\nbb\ncc\n", [(0, 5), (6, 9)], "FAIL", 1, 3)

    def test_b3_overlapping_intervals_pass(self):
        self.assertCoverage(b"aa\nbb\ncc\n", [(0, 5), (3, 9)], "PASS", 0, 3)

    def test_b4_rereads_pass_and_are_counted(self):
        r = self.assertCoverage(b"aa\nbb\ncc\n", [(0, 9), (0, 9), (3, 6)], "PASS", 0)
        self.assertEqual(r["events_checked"], 3)

    def test_b5_empty_file_has_no_units_and_no_reads(self):
        data = b""
        session = BrokerSession(Snapshot(data, sha(data)))
        pending = session.prepare({"v": 1, "type": "request", "request_id": "r0",
                                   "operation": "read_interval", "start": 0, "end": 1})
        self.assertEqual(pending.operation, "rejected")
        code, report = self.verify(data, session.trace())
        self.assertEqual(report["units_expected"], 0)
        self.assertEqual(report["coverage_gate"], "NOT_APPLICABLE")
        self.assertEqual(code, 1)  # verifier exits nonzero unless coverage is PASS

    def test_b6_crlf_keeps_cr_in_unit(self):
        r = self.assertCoverage(b"a\r\nb\r\n", [(0, 6)], "PASS", 0, 2)
        self.assertEqual(r["bytes_covered"], 6)
        self.assertCoverage(b"a\r\nb\r\n", [(0, 3), (3, 5)], "FAIL", 1, 2)  # last LF missing

    def test_b7_last_line_without_lf_is_a_unit(self):
        self.assertCoverage(b"a\nb", [(0, 3)], "PASS", 0, 2)
        self.assertCoverage(b"a\nb", [(0, 2)], "FAIL", 1, 2)

    def test_b8_multibyte_utf8_is_byte_exact(self):
        data = "é\nñ\n".encode()  # c3 a9 0a c3 b1 0a
        self.assertCoverage(data, [(0, 6)], "PASS", 0, 2)
        self.assertCoverage(data, [(0, 1), (1, 6)], "PASS", 0, 2)  # split inside a character
        self.assertCoverage(data, [(0, 1), (2, 6)], "FAIL", 1, 2)  # one byte omitted

    def test_e_tampered_traces_are_blocked_not_passed(self):
        data = b"aa\nbb\ncc\n"
        good = deliver(data, [(0, 3), (3, 6), (6, 9)])
        cases = {}
        dup = json.loads(json.dumps(good)); dup["events"][1] = dict(dup["events"][0])
        cases["E4 duplicate"] = (dup, None)
        swapped = json.loads(json.dumps(good)); swapped["events"].reverse()
        cases["E5 out of order"] = (swapped, None)
        bad_hash = json.loads(json.dumps(good)); bad_hash["events"][0]["sha256"] = "0" * 64
        cases["E6 bad hash"] = (bad_hash, None)
        short = json.loads(json.dumps(good)); short["events"].pop()
        cases["E3 count mismatch"] = (short, None)
        cases["E3 truncated json"] = (None, json.dumps(good).encode()[:-15])
        for label, (trace, raw) in cases.items():
            with self.subTest(label):
                code, report = self.verify(data, trace, raw_trace=raw)
                self.assertEqual(code, 2)
                self.assertIsNone(report)  # BLOCKED goes to stderr, never a PASS report

    def test_e1_wrong_pin_is_blocked(self):
        data = b"aa\n"
        code, _ = self.verify(data, deliver(data, [(0, 3)]), pin="1" * 64)
        self.assertEqual(code, 2)


class StoreHardening(unittest.TestCase):
    def finished_session(self, data=b"x\n"):
        s = BrokerSession(Snapshot(data, sha(data)))
        r, w = os.pipe()
        os.set_blocking(w, False)
        try:
            s.handle({"v": 1, "type": "request", "request_id": "s1",
                      "operation": "submit_result", "result": {}}, w)
            os.read(r, 4096)
        finally:
            os.close(r)
            os.close(w)
        return s

    def test_symlinked_private_dir_is_refused_and_nothing_escapes(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "hackbots").mkdir()
            (base / "elsewhere").mkdir(mode=0o700)
            (base / "hackbots/private").symlink_to(base / "elsewhere")
            with patch.object(trace_store, "PROJECT", base):
                with self.assertRaises(BrokerError):
                    trace_store.persist(self.finished_session())
            self.assertEqual(list((base / "elsewhere").iterdir()), [])

    def test_exclusive_file_never_overwrites_or_follows_symlinks(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            victim = base / "victim.txt"
            victim.write_bytes(b"original")
            (base / "trace.json").symlink_to(victim)
            fd = os.open(base, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with self.assertRaises(FileExistsError):
                    trace_store._exclusive_file(fd, "trace.json", b"forged")
                trace_store._exclusive_file(fd, "new.json", b"one")
                with self.assertRaises(FileExistsError):
                    trace_store._exclusive_file(fd, "new.json", b"two")
            finally:
                os.close(fd)
            self.assertEqual(victim.read_bytes(), b"original")
            self.assertEqual((base / "new.json").read_bytes(), b"one")
            self.assertEqual(stat.S_IMODE((base / "new.json").stat().st_mode), 0o600)

    def test_each_run_gets_a_distinct_private_directory_and_pinned_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "hackbots").mkdir()
            with patch.object(trace_store, "PROJECT", base):
                one = trace_store.persist(self.finished_session())
                two = trace_store.persist(self.finished_session())
            self.assertNotEqual(one, two)
            manifest = json.loads((base / "hackbots/private/runs" / one / "manifest.json").read_text())
            self.assertEqual(manifest["artifact_sha256"], sha(b"x\n"))
            self.assertEqual(manifest["artifact_bytes"], 2)
            self.assertEqual(manifest["policy_configured"]["timeout_s"], 10.0)
            self.assertEqual(manifest["trace_authenticity"], "NOT_VERIFIED")
            self.assertEqual(manifest["behavioral_gate"], "NOT_RUN")
            self.assertFalse(manifest["promotable"])
            self.assertFalse(manifest["human_approved"])

    def test_failed_session_is_never_persisted_as_complete(self):
        s = self.finished_session()
        s.failed = True
        with self.assertRaises(BrokerError):
            trace_store.persist(s)


if __name__ == "__main__":
    unittest.main()
