"""Synthetic ten-item data only; no blind fixtures and no network."""
import importlib.util
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('blind_runner', ROOT / 'bin/mitr3-blind-run.py')
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class BlindRunnerTests(unittest.TestCase):
    def fixture(self, folder):
        path = Path(folder) / 'synthetic-dev.json'
        path.write_text(json.dumps([{'id': f'dev-{i}', 'question': 'PUBLIC_DEV_QUESTION',
                                    'expected_answer': 'NEVER_LOG_GOLD'} for i in range(10)]))
        return path

    def test_parallel_bounded_ordered_and_no_gold(self):
        active, peak = 0, 0
        lock = threading.Lock()
        def call(q, m, timeout):
            nonlocal active, peak
            with lock:
                active += 1
                peak = max(active, peak)
            time.sleep(.02)
            with lock:
                active -= 1
            return runner.failed('MODEL_ABSTAIN')
        with tempfile.TemporaryDirectory() as td, mock.patch.object(runner, 'call_answer', side_effect=call):
            path = self.fixture(td)
            report = runner.run_set(path, 'provider/model', workers=3)
        self.assertEqual(peak, 3)
        self.assertEqual([r['id'] for r in report['rows']], [f'dev-{i}' for i in range(10)])
        self.assertEqual(set(report), {'at_utc', 'set', 'sha256', 'model', 'pass', 'rows'})
        self.assertNotIn('NEVER_LOG_GOLD', json.dumps(report))
        self.assertNotIn('PUBLIC_DEV_QUESTION', json.dumps(report))

    def test_retry_once_transient_only(self):
        item = {'id': 'dev', 'question': 'public'}
        for code, count in [('MODEL_TIMEOUT', 2), ('MODEL_FAILED', 2), ('MODEL_ABSTAIN', 1), ('QUOTE_NOT_LITERAL', 1)]:
            with mock.patch.object(runner, 'call_answer', return_value=runner.failed(code)) as call:
                row = runner.run_item(item, 'provider/model', 90)
            self.assertEqual(call.call_count, count)
            self.assertEqual(len(row['attempts']), count)

    def test_transient_then_success(self):
        success = runner.metadata({'abstain': False, 'claims': [], 'error_code': None})
        with mock.patch.object(runner, 'call_answer', side_effect=[runner.failed('MODEL_FAILED'), success]):
            self.assertFalse(runner.run_item({'id': 'dev', 'question': 'public'}, 'provider/model', 90)['abstain'])

    def test_logs_are_metadata_only(self):
        data = {'abstain': False, 'claims': [{'text': 'PRIVATE_BODY', 'citations': [
            {'id': 'CVE-2020-1472', 'quote': 'RAW_QUOTE'}, {'id': 'PRIVATE_ID', 'quote': 'SECRET'}]}]}
        text = json.dumps(runner.metadata(data))
        self.assertIn('CVE-2020-1472', text)
        for forbidden in ('PRIVATE_BODY', 'PRIVATE_ID', 'RAW_QUOTE', 'SECRET'):
            self.assertNotIn(forbidden, text)
        self.assertEqual(runner.metadata({'abstain': True, 'claims': [], 'error_code': 'SECRET'})['error'], 'UNRECOGNIZED_ERROR')

    def test_timeout_kills_local_child_and_closes_pipes(self):
        with tempfile.TemporaryDirectory() as td:
            script = Path(td) / 'slow.py'
            script.write_text('import time\ntime.sleep(20)\n')
            with mock.patch.object(runner, 'ANSWER', script):
                started = time.monotonic()
                result = runner.call_answer('public', 'provider/model', .05)
        self.assertEqual(result['error'], 'MODEL_TIMEOUT')
        self.assertLess(time.monotonic() - started, 2)

    def test_existing_output_is_not_overwritten_or_run(self):
        with tempfile.TemporaryDirectory() as td:
            fixture = self.fixture(td)
            output = Path(td) / 'frozen.json'
            output.write_text('preserve')
            with mock.patch.object(runner, 'run_set') as run:
                self.assertEqual(runner.main([str(fixture), '--model', 'provider/model', '--output', str(output)]), 1)
                run.assert_not_called()
            self.assertEqual(output.read_text(), 'preserve')

    def test_requires_ten_unique_items_and_worker_bounds(self):
        with tempfile.TemporaryDirectory() as td:
            path = self.fixture(td)
            for workers in (1, 5):
                with self.assertRaises(runner.RunError):
                    runner.run_set(path, 'provider/model', workers=workers)
            path.write_text('[]')
            with self.assertRaises(runner.RunError):
                runner.load_questions(path)
