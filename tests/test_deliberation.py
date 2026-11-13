"""Deliberation protocol and phantom board. No network."""
from contextlib import redirect_stderr, redirect_stdout
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.phantom.board import BoardError, FileBoard, self_test as board_self_test
from tools.phantom.deliberate import Protocol, ProtocolError, load_catalog, self_test as protocol_self_test
from tools.phantom import swarm

CATALOG = load_catalog()


class BoardTests(unittest.TestCase):
    def test_self_test_passes(self):
        board_self_test()

    def test_post_tail_order_and_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'board.jsonl'
            board = FileBoard(path)
            board.post({'kind': 'note', 'agent': 'morfeus', 'body': 'alpha'})
            board.post({'kind': 'note', 'agent': 'specter', 'body': 'beta'})
            self.assertEqual([row['body'] for row in board.tail(10)], ['alpha', 'beta'])
            self.assertEqual(board.tail(1)[0]['body'], 'beta')
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_corrupt_line_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'board.jsonl'
            board = FileBoard(path)
            board.post({'kind': 'note', 'agent': 'morfeus', 'body': 'alpha'})
            with path.open('a', encoding='utf-8') as handle:
                handle.write('{not json}\n')
            with self.assertRaises(BoardError) as caught:
                board.tail(5)
            self.assertEqual(caught.exception.code, 'CORRUPT_LINE')


class DeliberationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / 'board.jsonl'
        self.protocol = Protocol(FileBoard(self.path), CATALOG)

    def tearDown(self):
        self.tmp.cleanup()

    def _ready(self, impact='low', phase='js-inventory'):
        opened = self.protocol.open(
            topic='Review the local fixture inventory',
            phase=phase,
            impact=impact,
            agents=['glyph', 'ward'],
        )
        self.protocol.propose(
            topic_id=opened['topic_id'], agent='glyph', stance='proceed',
            body='Glyph recommends proceed on the local fixture only.',
        )
        self.protocol.propose(
            topic_id=opened['topic_id'], agent='ward', stance='hold',
            body='Ward recommends hold until the fixture hash is cited.',
        )
        self.protocol.critique(
            topic_id=opened['topic_id'], agent='ward', target_agent='glyph',
            body='Proceed is early. No procedure offered.',
        )
        return opened['topic_id']

    def test_decision_id_is_stable_on_requery(self):
        topic_id = self._ready()
        first = self.protocol.decide(
            topic_id=topic_id, outcome='hold', rationale='Ward dissented; hold the recommendation.',
        )
        second = self.protocol.show(topic_id)
        reread = Protocol(FileBoard(self.path), CATALOG)
        found = reread.find_decision(first['decision_id'])
        self.assertEqual(first['decision_id'], second['decision_id'])
        self.assertEqual(second['decision_id'], found['decision_id'])
        self.assertEqual(found['participants'], ['glyph', 'ward'])
        self.assertEqual(found['outcome'], 'hold')
        self.assertFalse(found['executes'])
        self.assertFalse(found['human_approved'])
        self.assertEqual(found['dissent'][0]['agent'], 'glyph')
        kinds = [event['kind'] for event in found['events']]
        self.assertEqual(kinds, [
            'deliberation.open', 'deliberation.propose', 'deliberation.propose',
            'deliberation.critique', 'deliberation.decide',
        ])

    def test_decide_rejects_fewer_than_two_proposers(self):
        opened = self.protocol.open(topic='Needs a second voice', agents=['specter', 'cipher'])
        self.protocol.propose(
            topic_id=opened['topic_id'], agent='specter', stance='hold', body='Specter alone is not a quorum.',
        )
        with self.assertRaises(ProtocolError) as caught:
            self.protocol.decide(topic_id=opened['topic_id'], outcome='hold', rationale='Should not record.')
        self.assertEqual(caught.exception.code, 'QUORUM')
        self.assertIsNone(self.protocol.show(opened['topic_id'])['decision_id'])

    def test_same_agent_twice_does_not_make_quorum(self):
        opened = self.protocol.open(topic='Duplicate voice', agents=['specter', 'cipher'])
        self.protocol.propose(
            topic_id=opened['topic_id'], agent='specter', stance='abort', body='Stop.',
        )
        with self.assertRaises(ProtocolError) as caught:
            self.protocol.propose(
                topic_id=opened['topic_id'], agent='specter', stance='hold', body='Again.',
            )
        self.assertEqual(caught.exception.code, 'ALREADY_PROPOSED')

    def test_second_decide_keeps_the_original_id(self):
        topic_id = self._ready()
        first = self.protocol.decide(topic_id=topic_id, outcome='hold', rationale='Hold after Ward.')
        with self.assertRaises(ProtocolError) as caught:
            self.protocol.decide(topic_id=topic_id, outcome='proceed', rationale='Try to replace it.')
        self.assertEqual(caught.exception.code, 'CLOSED')
        self.assertEqual(caught.exception.detail['decision_id'], first['decision_id'])
        self.assertEqual(self.protocol.show(topic_id)['decision_id'], first['decision_id'])

    def test_unknown_agent_and_secret_material_rejected(self):
        with self.assertRaises(ProtocolError) as caught:
            self.protocol.open(topic='Nope', agents=['glyph', 'not-a-real-agent'])
        self.assertEqual(caught.exception.code, 'UNKNOWN_AGENT')
        with self.assertRaises(ProtocolError) as caught:
            self.protocol.open(topic='api_key=supersecretvalue should not land on the board')
        self.assertEqual(caught.exception.code, 'SECRET_MATERIAL')
        self.assertFalse(self.path.exists())

    def test_stub_round_low_impact_and_forced_high_impact(self):
        low = self.protocol.run_round(
            topic='Passive inventory of the local fixture',
            agents=['glyph', 'ward'],
            phase='js-inventory',
            impact='low',
        )
        self.assertEqual(low['outcome'], 'proceed')
        self.assertEqual(low['participants'], ['glyph', 'ward'])
        self.assertFalse(low['executes'])
        high = self.protocol.run_round(
            topic='Request to treat web-exploit as low impact',
            agents=['specter', 'cipher'],
            phase='web-exploit',
            impact='low',
        )
        self.assertEqual(high['impact'], 'high')
        self.assertEqual(high['outcome'], 'hold')
        with self.assertRaises(ProtocolError) as caught:
            self.protocol.run_round(
                topic='Override attempt',
                agents=['specter', 'cipher'],
                phase='web-exploit',
                stances={'specter': 'proceed', 'cipher': 'proceed'},
            )
        self.assertEqual(caught.exception.code, 'HIGH_IMPACT_STUB')

    def test_split_stub_records_rebuttal_and_dissent(self):
        shown = self.protocol.run_round(
            topic='Split recommendation on a local review',
            agents=['specter', 'ward'],
            phase='review',
            impact='low',
            rebuttal=False,
            stances={'specter': 'proceed', 'ward': 'hold'},
        )
        self.assertEqual(shown['outcome'], 'hold')
        self.assertEqual([item['agent'] for item in shown['dissent']], ['specter'])
        self.assertIn('deliberation.critique', [event['kind'] for event in shown['events']])

    def test_tampered_outcome_fails_closed(self):
        topic_id = self._ready()
        shown = self.protocol.decide(topic_id=topic_id, outcome='hold', rationale='Hold after Ward.')
        raw = self.path.read_text(encoding='utf-8').replace('"outcome":"hold"', '"outcome":"proceed"', 1)
        self.path.write_text(raw, encoding='utf-8')
        with self.assertRaises(ProtocolError) as caught:
            Protocol(FileBoard(self.path), CATALOG).find_decision(shown['decision_id'])
        self.assertEqual(caught.exception.code, 'TAMPERED')

    def test_protocol_self_test(self):
        protocol_self_test()


class SwarmHookTests(unittest.TestCase):
    def _run(self, argv):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = swarm.main(argv)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_exec_without_deliberation_writes_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'board.jsonl'
            code, _out, err = self._run(['run', '--phase', 'web-exploit', '--exec', '--board', str(path)])
            self.assertEqual(code, 2)
            self.assertIn('DELIBERATION_REQUIRED', err)
            self.assertFalse(path.exists())

    def test_deliberate_then_exec_records_hold_and_does_not_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'board.jsonl'
            code, out, _err = self._run([
                'run', '--phase', 'web-exploit', '--deliberate', '--exec',
                '--board', str(path), '--agents', 'specter,cipher',
            ])
            self.assertEqual(code, 3)
            self.assertEqual(json.loads(out)['code'], 'EXEC_NOT_IMPLEMENTED')
            rows = FileBoard(path).read()
            decision = [row for row in rows if row['kind'] == 'deliberation.decide']
            self.assertEqual(len(decision), 1)
            self.assertEqual(decision[0]['outcome'], 'hold')
            self.assertFalse(decision[0]['executes'])
            self.assertFalse(any(str(row['kind']).startswith('swarm.exec') for row in rows))

    def test_dry_run_does_not_create_board(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'board.jsonl'
            code, out, _err = self._run([
                'run', '--phase', 'js-inventory', '--deliberate', '--dry-run',
                '--board', str(path), '--agents', 'glyph,ward',
            ])
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(out)['outcome'], 'proceed')
            self.assertFalse(path.exists())


class CliTests(unittest.TestCase):
    def test_cli_dry_run_and_requery(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'board.jsonl'
            script = ROOT / 'bin' / 'mitr3-deliberate.py'
            dry = subprocess.run(
                [sys.executable, str(script), '--dry-run', 'run',
                 '--topic', 'Review the local fixture',
                 '--phase', 'js-inventory', '--impact', 'low', '--agents', 'glyph,ward',
                 '--board', str(path)],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(dry.returncode, 0, dry.stderr)
            self.assertFalse(path.exists())
            payload = json.loads(dry.stdout)
            self.assertEqual(payload['outcome'], 'proceed')
            self.assertTrue(payload['decision_id'].startswith('dec-'))
            live = subprocess.run(
                [sys.executable, str(script), 'run',
                 '--topic', 'Review the local fixture',
                 '--phase', 'js-inventory', '--impact', 'low', '--agents', 'glyph,ward',
                 '--board', str(path)],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(live.returncode, 0, live.stderr)
            written = json.loads(live.stdout)
            shown = subprocess.run(
                [sys.executable, str(script), 'show', '--decision-id', written['decision_id'],
                 '--board', str(path)],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(shown.returncode, 0, shown.stderr)
            self.assertEqual(json.loads(shown.stdout)['decision_id'], written['decision_id'])
            board = subprocess.run(
                [sys.executable, str(ROOT / 'tools' / 'phantom' / 'board.py'), '--self-test'],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(board.returncode, 0, board.stderr)
            self.assertEqual(board.stdout.strip(), 'ok')
            phases = subprocess.run(
                [sys.executable, str(ROOT / 'tools' / 'phantom' / 'swarm.py'), 'phases'],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(phases.returncode, 0, phases.stderr)
            self.assertIn('web-exploit', phases.stdout)
            protocol = subprocess.run(
                [sys.executable, str(ROOT / 'tools' / 'phantom' / 'deliberate.py'), 'self-test'],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(protocol.returncode, 0, protocol.stderr)
            self.assertEqual(protocol.stdout.strip(), 'ok')


if __name__ == '__main__':
    unittest.main()
