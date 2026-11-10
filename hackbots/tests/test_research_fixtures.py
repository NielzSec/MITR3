"""Manual oracle coherence, not a Research worker or model evaluation."""
import json
from pathlib import Path
import re
import unittest

from hackbots.tools import validate

BASE = Path(__file__).resolve().parents[1] / 'examples/research'


class ResearchOracleTests(unittest.TestCase):
    def test_contract_hash_reference_and_manual_coverage_expectations(self):
        for case in ('R01', 'R02', 'R03'):
            with self.subTest(case=case):
                mission = json.loads((BASE/(case+'.mission.json')).read_text())
                expected = json.loads((BASE/(case+'.expected.json')).read_text())
                self.assertEqual(validate.validate('mission', mission), [])
                self.assertEqual(validate.validate('result', expected, mission), [])
                source = validate.ROOT / mission['artifact']['path']
                raw = source.read_bytes()
                lines = raw.count(b'\n') + int(bool(raw) and not raw.endswith(b'\n'))
                self.assertEqual(expected['coverage'], {'expected': lines, 'analyzed': lines})
                self.assertEqual(expected['status'], 'review_pending')
                self.assertEqual(expected['review'], {'decision': 'pending', 'reviewer': None})

    def test_conflict_is_opposite_status_for_the_same_subject(self):
        records = re.findall(r'Record [AB]: (\S+) exact version ([\d.]+) is (AFFECTED|NOT_AFFECTED)\.',
                             (BASE/'conflict.txt').read_text())
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0][:2], records[1][:2])
        self.assertEqual({r[2] for r in records}, {'AFFECTED', 'NOT_AFFECTED'})

    def test_injection_fixture_preserves_facts_and_no_claim_of_execution(self):
        base = (BASE/'baseline.txt').read_bytes()
        injection = (BASE/'injection.txt').read_bytes()
        self.assertTrue(injection.startswith(base))
        normal = json.loads((BASE/'R01.expected.json').read_text())
        injected = json.loads((BASE/'R02.expected.json').read_text())
        self.assertEqual(normal['claims'], injected['claims'])
        self.assertIn('UNTRUSTED INSTRUCTION:', injection.decode())
        self.assertTrue(any('no agent was run' in s for s in injected['limitations']))
