import dataclasses
from decimal import Decimal
import json
import os
from pathlib import Path
import struct
import sys
import threading
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from hackbots.runner.policies import HARD_MAX, Policy, PolicyError, resolve_policy
from hackbots.runner.protocol import (FrameReader, ProtocolViolation, RequestRejected,
    RequestParser, decode_message, encode_frame, parse_request, validate_result_payload)


def request(**changes):
    return dict(v=1, type='request', request_id='r1', operation='read_interval', start=0, end=4, **changes)


class PolicyTests(unittest.TestCase):
    def test_defaults_match_existing_verifier(self):
        self.assertEqual(Policy().max_fixture_bytes, 1_000_000)
        self.assertEqual(Policy().max_total_bytes, 16_000_000)
        self.assertEqual(resolve_policy({'timeout_s': 20}).timeout_s, 20)
        self.assertEqual(HARD_MAX.timeout_s, 60)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            HARD_MAX.timeout_s = 100

    def test_all_limits_reject_wrong_types_and_overflow(self):
        for key, value in dataclasses.asdict(HARD_MAX).items():
            for bad in (True, False, None, '1', 0, -1, value + 1, float('nan'), float('inf'), 10 ** 1000):
                with self.subTest(key=key, bad=bad), self.assertRaises(PolicyError):
                    resolve_policy({key: bad})
        for bad in ({'unknown': 1}, [], {'timeout_s': 1}, {'max_total_bytes': 1}):
            with self.subTest(bad=bad), self.assertRaises(PolicyError):
                resolve_policy(bad)
        with self.assertRaises(PolicyError):
            Policy(max_events=1.0)


class ProtocolTests(unittest.TestCase):
    def pipe(self):
        r, w = os.pipe()
        self.addCleanup(os.close, r)
        return r, w

    def test_fragmented_and_multiple_frames(self):
        r, w = self.pipe()
        frame = encode_frame(request(), 65536)
        def writer():
            try:
                for byte in frame + frame:
                    os.write(w, bytes([byte]))
            finally:
                os.close(w)
        thread = threading.Thread(target=writer)
        thread.start()
        self.addCleanup(thread.join, 2)
        reader = FrameReader(r)
        self.assertEqual(reader.read(time.monotonic() + 2), request())
        self.assertEqual(reader.read(time.monotonic() + 2), request())
        self.assertIsNone(reader.read(time.monotonic() + 2))

    def test_high_numbered_fd_reads_valid_pipe(self):
        # select.select would misclassify this valid Linux descriptor as protocol corruption.
        import fcntl
        r, w = self.pipe()
        try:
            high_fd = fcntl.fcntl(r, fcntl.F_DUPFD, 1024)
        except OSError:
            os.close(w)
            self.skipTest('test host has a low file-descriptor limit')
        self.addCleanup(os.close, high_fd)
        try:
            os.write(w, encode_frame(request(), 65536))
        finally:
            os.close(w)
        reader = FrameReader(high_fd)
        self.assertEqual(reader.read(time.monotonic() + 1), request())
        self.assertIsNone(reader.read(time.monotonic() + 1))

    def test_truncated_oversized_zero_frames_fail_closed(self):
        for data in (b'x', struct.pack('!I', 0), struct.pack('!I', 65537),
                     struct.pack('!I', 4) + b'{}'):
            with self.subTest(data=data):
                r, w = self.pipe()
                os.write(w, data)
                os.close(w)
                reader = FrameReader(r)
                with self.assertRaises(ProtocolViolation):
                    reader.read(time.monotonic() + 1)
                with self.assertRaises(ProtocolViolation):
                    reader.read(time.monotonic() + 1)

    def test_idle_and_partial_frame_timeout(self):
        for data in (b'', b'\x00', struct.pack('!I', 8) + b'{'):
            r, w = self.pipe()
            try:
                os.write(w, data)
                reader = FrameReader(r)
                with self.assertRaises(TimeoutError):
                    reader.read(time.monotonic() + .02)
                with self.assertRaises(ProtocolViolation):
                    reader.read(time.monotonic() + 1)
            finally:
                os.close(w)

    def test_json_rejects_ambiguity_nonfinite_unicode_and_depth(self):
        for raw in (b'{"v":1,"v":1}', b'{"x":{"a":1,"a":2}}', b'{"x":NaN}',
                    b'{"x":Infinity}', b'{"x":"\\ud800"}', b'\xff', b'[]',
                    b'{"a":' + b'[' * 1000 + b'0' + b']' * 1000 + b'}'):
            with self.subTest(raw=raw[:30]), self.assertRaises(ProtocolViolation):
                decode_message(raw)

    def test_decimal_roundtrip_preserves_oracle_precision(self):
        for token in ('9007199254740993.0', '1e-999', '1e999', '1.00000000000000001', '1e0', '0e0', '-0e0'):
            raw = ('{"x":' + token + '}').encode()
            decoded = decode_message(raw)
            self.assertIs(type(decoded['x']), Decimal)
            self.assertEqual(decoded['x'], Decimal(token))
            result = validate_result_payload(decoded, Policy())
            self.assertIs(type(result['x']), Decimal)
            encoded = encode_frame(result, 65536)
            roundtrip = decode_message(encoded[4:])['x']
            self.assertIs(type(roundtrip), Decimal)
            self.assertEqual(roundtrip, Decimal(token))
        with self.assertRaises(ProtocolViolation):
            encode_frame({'x': Decimal('NaN')}, 65536)

    def test_frame_limits_use_utf8_bytes(self):
        msg = {'x': 'é'}
        size = len(json.dumps(msg, ensure_ascii=False, separators=(',', ':')).encode())
        self.assertEqual(len(encode_frame(msg, size)), size + 4)
        with self.assertRaises(ProtocolViolation):
            encode_frame(msg, size - 1)
        for limit in (True, 0, 131073):
            with self.assertRaises(ProtocolViolation):
                encode_frame(msg, limit)

    def test_request_schemas_are_strict(self):
        original = request()
        for changes in ({'v': True}, {'v': 2}, {'type': 'other'}, {'extra': 1},
                        {'request_id': 'a' * 33}, {'request_id': '../path'}, {'operation': 'shell'}):
            with self.subTest(changes=changes), self.assertRaises(ProtocolViolation):
                parse_request({**original, **changes}, Policy())
        self.assertEqual(parse_request(original, Policy()).end, 4)

    def test_invalid_intervals_are_recoverable_not_clamped(self):
        for changes, code in [({'start': True}, 'E_RANGE'), ({'end': 1.0}, 'E_RANGE'),
                              ({'start': -1}, 'E_RANGE'), ({'end': 0}, 'E_RANGE'),
                              ({'end': 65537}, 'E_TOO_LARGE_READ')]:
            with self.subTest(changes=changes), self.assertRaises(RequestRejected) as cm:
                parse_request({**request(), **changes}, Policy())
            self.assertEqual(cm.exception.code, code)

    def test_request_ids_are_unique_even_after_rejection(self):
        parser = RequestParser()
        with self.assertRaises(RequestRejected):
            parser.parse({**request(), 'end': 0})
        with self.assertRaises(ProtocolViolation):
            parser.parse(request())
        with self.assertRaises(ProtocolViolation):
            parser.parse({**request(), 'request_id': 'new'})

    def test_session_budget_and_independent_sessions(self):
        parser = RequestParser(Policy(max_ipc_messages=1))
        parser.parse(request())
        with self.assertRaises(ProtocolViolation):
            parser.parse({**request(), 'request_id': 'new'})
        self.assertEqual(RequestParser().parse(request()).request_id, 'r1')

    def test_result_shape_size_depth_and_mutation(self):
        policy = Policy(max_result_bytes=10)
        self.assertEqual(validate_result_payload({'x': 'é'}, policy), {'x': 'é'})
        for obj in ([], {'x': 'éé'}, {'x': float('inf')}, {'x': '\ud800'}, {1: 'x'}):
            with self.subTest(obj=repr(obj)), self.assertRaises(RequestRejected):
                validate_result_payload(obj, policy)
        obj = {}
        for _ in range(9):
            obj = {'x': obj}
        with self.assertRaises(RequestRejected):
            validate_result_payload(obj, Policy())
        original = {'x': []}
        frozen = validate_result_payload(original, Policy())
        original['x'].append('changed')
        self.assertEqual(frozen, {'x': []})
        msg = {'v': 1, 'type': 'request', 'request_id': 's1',
               'operation': 'submit_result', 'result': {'ok': True}}
        self.assertEqual(RequestParser().parse(msg).result, {'ok': True})


if __name__ == '__main__':
    unittest.main()
