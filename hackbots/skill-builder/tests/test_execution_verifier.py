import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))
try:
    spec = importlib.util.spec_from_file_location('execution_verifier_tests', BASE / 'execution_verifier.py')
    ev = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ev)
finally:
    sys.path.remove(str(BASE))


class ExecutionVerifierTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=BASE / 'drafts')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.artifact = self.root / 'synthetic.js'
        self.trace = self.root / 'trace.json'
        self.raw = b'// synthetic\r\n\nlast line'
        self.artifact.write_bytes(self.raw)
        self.pin = ev.sb.digest(self.raw)
        self.data = self.bundle([(0, len(self.raw))])

    def relative(self, path):
        return str(path.relative_to(ev.sb.PROJECT))

    def bundle(self, spans):
        return {'schema_version': 1, 'artifact_sha256': self.pin,
                'event_count': len(spans), 'events': [
                    {'seq': n, 'start': start, 'end': end,
                     'sha256': ev.sb.digest(self.raw[start:end])}
                    for n, (start, end) in enumerate(spans, 1)]}

    def verify(self):
        self.trace.write_text(json.dumps(self.data))
        return ev.verify(self.relative(self.artifact), self.relative(self.trace), self.pin)

    def test_full_coverage_is_not_behavioral_execution(self):
        result = self.verify()
        self.assertEqual(result['coverage_gate'], 'PASS')
        self.assertEqual(result['trace_gate'], 'PASS')
        self.assertEqual(result['units_covered'], 3)
        self.assertEqual(result['trace_authenticity'], 'NOT_VERIFIED')
        self.assertEqual(result['behavioral_gate'], 'NOT_RUN')
        self.assertEqual(result['output_gate'], 'NOT_RUN')
        self.assertFalse(result['human_approved'])
        self.assertFalse(result['promotable'])

    def test_physical_line_boundaries(self):
        for raw, expected in [(b'', []), (b'\n', [(0, 1)]),
                              (b'a\r\n\nlast', [(0, 3), (3, 4), (4, 8)]),
                              (b'a\rb', [(0, 3)]), (b'a\n', [(0, 2)]),
                              ('é\n尾'.encode(), [(0, 3), (3, 6)])]:
            with self.subTest(raw=raw):
                units = ev.line_units(raw)
                self.assertEqual([(u['start'], u['end']) for u in units], expected)
                self.assertEqual(len({u['id'] for u in units}), len(units))
                for u in units:
                    self.assertEqual(u['sha256'], ev.sb.digest(raw[u['start']:u['end']]))

    def test_union_does_not_double_count_repeated_overlapping_reads(self):
        self.data = self.bundle([(5, len(self.raw)), (0, 5), (0, 10), (0, 5)])
        result = self.verify()
        self.assertEqual(result['coverage_gate'], 'PASS')
        self.assertEqual(result['bytes_covered'], len(self.raw))
        self.assertEqual(result['units_covered'], 3)

    def test_one_missing_byte_invalidates_its_line(self):
        self.data = self.bundle([(0, 2), (3, len(self.raw))])
        result = self.verify()
        self.assertEqual(result['coverage_gate'], 'FAIL')
        self.assertEqual(result['units_covered'], 2)
        self.assertEqual(result['missing_unit_ids'], [ev.line_units(self.raw)[0]['id']])

    def test_no_events_and_empty_artifact(self):
        self.data = self.bundle([])
        self.assertEqual(self.verify()['coverage_gate'], 'FAIL')
        self.raw = b''
        self.artifact.write_bytes(self.raw)
        self.pin = ev.sb.digest(self.raw)
        self.data = self.bundle([])
        result = self.verify()
        self.assertEqual(result['coverage_gate'], 'NOT_APPLICABLE')
        self.assertEqual(result['state'], 'INCONCLUSIVE')
        self.assertEqual(result['units_expected'], 0)

    def test_invalid_event_contracts_block(self):
        original = copy.deepcopy(self.data)
        for mutation in ({'seq': 2}, {'seq': True}, {'start': True}, {'start': -1},
                         {'end': 0}, {'end': len(self.raw) + 1}, {'end': 1.0},
                         {'sha256': '0' * 64}, {'unit_id': 'invented'}, {'seq': None}):
            with self.subTest(mutation=mutation):
                self.data = copy.deepcopy(original)
                self.data['events'][0].update(mutation)
                with self.assertRaises(ev.sb.GateError):
                    self.verify()
        self.data = self.bundle([(0, 3), (3, len(self.raw))])
        self.data['events'][1]['seq'] = 1
        with self.assertRaises(ev.sb.GateError):
            self.verify()

    def test_truncated_and_invalid_trace_contracts_block(self):
        original = copy.deepcopy(self.data)
        for data in ([], None, {**original, 'schema_version': True},
                     {**original, 'event_count': 2}, {**original, 'event_count': True},
                     {**original, 'events': {}}, {**original, 'events': [None]},
                     {**original, 'artifact_sha256': '0' * 64},
                     {**original, 'human_approved': True}):
            with self.subTest(data=data), self.assertRaises(ev.sb.GateError):
                self.data = data
                self.verify()

    def test_changed_fixture_and_wrong_external_pin_block(self):
        self.artifact.write_bytes(self.raw + b'changed')
        with self.assertRaises(ev.sb.GateError):
            self.verify()
        for pin in ('0' * 64, '', True):
            with self.subTest(pin=pin), self.assertRaises(ev.sb.GateError):
                ev.inventory(self.relative(self.artifact), pin)

    def test_limits_and_unsafe_files_block(self):
        with patch.object(ev, 'MAX_UNITS', 2), self.assertRaises(ev.sb.GateError):
            self.verify()
        with patch.object(ev, 'MAX_EVENTS', 0), self.assertRaises(ev.sb.GateError):
            self.verify()
        with patch.object(ev.sb, 'MAX_BYTES', 1), self.assertRaises(ev.sb.GateError):
            self.verify()
        self.artifact.unlink()
        self.artifact.symlink_to(BASE / 'execution_verifier.py')
        with self.assertRaises(ev.sb.GateError):
            self.verify()

    def test_repeated_reads_respect_cumulative_hash_budget(self):
        self.data = self.bundle([(0, len(self.raw)), (0, len(self.raw))])
        with patch.object(ev, 'MAX_HASH_BYTES', len(self.raw) * 2):
            self.assertEqual(self.verify()['coverage_gate'], 'PASS')
        with patch.object(ev, 'MAX_HASH_BYTES', len(self.raw) * 2 - 1):
            with self.assertRaises(ev.sb.GateError):
                self.verify()

    def test_inventory_does_not_claim_trace_coverage(self):
        result = ev.inventory(self.relative(self.artifact), self.pin)
        self.assertEqual(result['units_expected'], 3)
        self.assertEqual(result['coverage_gate'], 'NOT_RUN')
        self.assertEqual(result['trace_gate'], 'NOT_RUN')
        self.assertNotIn('artifact', result)

    def test_cli_codes_and_safe_diagnostics(self):
        def invoke(*extra):
            return subprocess.run([sys.executable, str(BASE / 'execution_verifier.py'),
                                   'verify', self.relative(self.artifact), self.relative(self.trace),
                                   '--artifact-sha256', self.pin, *extra],
                                  capture_output=True, text=True, timeout=3)
        self.verify()
        result = invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.data = self.bundle([])
        self.verify()
        self.assertEqual(invoke().returncode, 1)
        for raw in (b'{', b'{"private":"SYNTHETIC_SECRET", "private":1}', b'NaN'):
            self.trace.write_bytes(raw)
            result = invoke()
            self.assertEqual(result.returncode, 2)
            self.assertEqual(json.loads(result.stderr)['state'], 'BLOCKED')
            self.assertNotIn('SYNTHETIC_SECRET', result.stderr)
            self.assertNotIn('Traceback', result.stderr)
        result = invoke('--SYNTHETIC_SECRET')
        self.assertEqual(result.returncode, 2)
        self.assertNotIn('SYNTHETIC_SECRET', result.stderr)
        self.trace.unlink()
        os.mkfifo(self.trace)
        self.assertEqual(invoke().returncode, 2)


if __name__ == '__main__':
    unittest.main()
