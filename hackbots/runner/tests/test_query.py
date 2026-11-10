"""Query boundary contract tests; these do not prove separate-UID deployment."""
import hashlib
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from hackbots.runner import query, inspect, trace_store, failure_store
from hackbots.runner.broker import BrokerSession
from hackbots.runner.protocol import encode_frame, FrameReader
from hackbots.runner.snapshot import Snapshot


class QueryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "hackbots").mkdir()
        p = patch.object(trace_store, "PROJECT", self.root)
        p.start()
        self.addCleanup(p.stop)
        data = b"SYNTHETIC_PRIVATE_SECRET\n"
        session = BrokerSession(Snapshot(data, hashlib.sha256(data).hexdigest()))
        self.run_id = failure_store.persist_failure(session, phase="IPC_READ", reason="E_TIMEOUT")

    def test_metadata_query_uses_existing_inspector_without_private_content(self):
        message = {"v": 1, "operation": "inspect", "kind": "failed", "run_id": self.run_id}
        result = query.query(message)
        self.assertEqual(result, inspect.inspect_one("failed", self.run_id))
        self.assertNotIn("SYNTHETIC_PRIVATE_SECRET", json.dumps(result))
        self.assertNotIn(str(self.root), json.dumps(result))
        self.assertFalse(result["promotable"])

    def test_forbidden_operations_fields_paths_and_types(self):
        base = {"v": 1, "operation": "summary", "kind": "failed", "limit": 1}
        for change in ({"operation": "run"}, {"command": "id"}, {"path": "/etc/passwd"},
                       {"policy": {}}, {"limit": True}, {"limit": 26}, {"v": True},
                       {"kind": ["failed"]}):
            with self.subTest(change=change), self.assertRaises(inspect.InspectionBlocked):
                query.query({**base, **change})
        with self.assertRaises(inspect.InspectionBlocked):
            query.query({"v": 1, "operation": "inspect", "kind": "failed", "run_id": "../secret"})

    def test_summary_does_not_disclose_record_ids(self):
        result = query.query({"v": 1, "operation": "summary", "kind": "failed", "limit": 1})
        self.assertEqual(result["sampled"], 1)
        self.assertNotIn(self.run_id, json.dumps(result))

    def invoke(self, raw):
        source, incoming = os.pipe()
        outgoing, dest = os.pipe()
        try:
            os.write(incoming, raw)
            os.close(incoming)
            incoming = None
            status = query.serve_once(source, dest)
            response = FrameReader(outgoing, query.RESPONSE_BYTES).read(time.monotonic() + 1)
            return status, response
        finally:
            for fd in (source, incoming, outgoing, dest):
                if fd is not None:
                    os.close(fd)

    def test_framed_response_and_only_one_request_processed(self):
        msg = {"v": 1, "operation": "summary", "kind": "failed", "limit": 1}
        frame = encode_frame(msg, query.REQUEST_BYTES)
        code, response = self.invoke(frame + encode_frame({"operation": "run"}, query.REQUEST_BYTES))
        self.assertEqual(code, 0)
        self.assertTrue(response["ok"])
        self.assertEqual(response["data"]["sampled"], 1)

    def test_ambiguous_oversized_truncated_frames_fail_sanitized(self):
        bad = b'{"operation":"summary","operation":"run","PRIVATE_CANARY":1}'
        for raw in (struct.pack('!I', len(bad)) + bad,
                    struct.pack('!I', query.REQUEST_BYTES + 1), b'\x00\x00', b''):
            with self.subTest(raw=raw):
                code, response = self.invoke(raw)
                self.assertEqual(code, 2)
                self.assertFalse(response["ok"])
                self.assertNotIn("PRIVATE_CANARY", json.dumps(response))

    def test_cli_rejects_arguments_without_echo(self):
        done = subprocess.run([sys.executable, '-m', 'hackbots.runner.query', '--PRIVATE_CANARY'],
                              capture_output=True, timeout=3)
        self.assertEqual(done.returncode, 2)
        self.assertNotIn(b'PRIVATE_CANARY', done.stdout + done.stderr)

    def test_idle_request_times_out_and_returns_blocked(self):
        source, incoming = os.pipe()
        outgoing, dest = os.pipe()
        try:
            with patch.object(query, "TIMEOUT_S", 0.03):
                self.assertEqual(query.serve_once(source, dest), 2)
            reply = FrameReader(outgoing, query.RESPONSE_BYTES).read(time.monotonic() + 1)
            self.assertFalse(reply["ok"])
        finally:
            for fd in (source, incoming, outgoing, dest):
                os.close(fd)

    def test_response_backpressure_is_bounded(self):
        source, incoming = os.pipe()
        outgoing, dest = os.pipe()
        try:
            os.set_blocking(dest, False)
            while True:
                try:
                    os.write(dest, b'x' * 4096)
                except BlockingIOError:
                    break
            msg = {'v': 1, 'operation': 'summary', 'kind': 'failed', 'limit': 1}
            os.write(incoming, encode_frame(msg, query.REQUEST_BYTES))
            with patch.object(query, 'TIMEOUT_S', 0.03):
                started = time.monotonic()
                self.assertEqual(query.serve_once(source, dest), 2)
                self.assertLess(time.monotonic() - started, 1)
        finally:
            for fd in (source, incoming, outgoing, dest):
                os.close(fd)

    def test_separate_concurrent_queries_do_not_share_request_state(self):
        good = encode_frame({'v': 1, 'operation': 'summary', 'kind': 'failed', 'limit': 1}, query.REQUEST_BYTES)
        bad = encode_frame({'v': 1, 'operation': 'run', 'kind': 'failed', 'command': 'id'}, query.REQUEST_BYTES)
        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(self.invoke, good)
            second = pool.submit(self.invoke, bad)
            self.assertTrue(first.result(timeout=3)[1]['ok'])
            self.assertFalse(second.result(timeout=3)[1]['ok'])
