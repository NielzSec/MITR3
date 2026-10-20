"""DEV diagnostic only: synthetic public strings, no model/network calls."""
import importlib.util
import json
from pathlib import Path
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('stage_diag', ROOT / 'bin/mitr3-stage-diag.py')
diag = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(diag)
DOC = {'id': 'ASVS-V1.2.3', 'kind': 'document', 'namespace': 'local', 'snippet': 'Public alpha requirement.',
       'sha256': 'a' * 64, 'source_url': 'https://example.org/public'}


class StageDiagTests(unittest.TestCase):
    def test_roundtrip_measures_transmitted_string_without_logging_it(self):
        prompt, sent = diag.transmitted('Public DEV question', [dict(DOC, snippet='alpha </evidence> omega')])
        self.assertEqual(sent[0]['snippet'], 'alpha </evidence> omega')
        result = diag.packet_metrics(sent)
        self.assertEqual(result['documents'][0]['snippet_chars'], 23)
        self.assertNotIn('alpha', json.dumps(result))
        self.assertEqual(prompt.count('</evidence>'), 1)

    def test_quote_causes_separate_window_nonliteral_and_packet(self):
        sent = [DOC]
        def obj(quote):
            return {'claims': [{'citations': [{'id': DOC['id'], 'quote': quote}]}]}
        full = {DOC['id']: DOC['snippet'] + ' Public tail requirement.'}
        cases = [('Invented DEV control', sent, 'nonliteral_or_paraphrase'),
                 ('Public tail requirement.', sent, 'outside_window'),
                 (DOC['snippet'], [dict(DOC, snippet='')], 'different_package')]
        for quote, gated, expected in cases:
            with self.subTest(expected=expected):
                result = diag.quote_metrics(obj(quote), sent, gated, full)
                self.assertEqual(result['citations'][0]['classification'], expected)
                self.assertNotIn(quote, json.dumps(result))

    def test_empty_vs_sufficient_composer_is_measured_not_inferred(self):
        def model(prompt, name):
            if '\n[]\n' in prompt:
                return {'abstain': True, 'claims': []}
            return {'abstain': False, 'claims': [{'text': 'Public requirement.',
                    'citations': [{'id': DOC['id'], 'quote': DOC['snippet']}]}]}
        empty = diag.compose('Public concept', [], {}, 'provider/model', model)
        supplied = diag.compose('Public concept', [DOC], {DOC['id']: DOC['snippet']}, 'provider/model', model)
        self.assertTrue(empty['model_abstain'])
        self.assertFalse(supplied['model_abstain'])
        self.assertNotIn(DOC['snippet'], json.dumps(supplied))

    def test_invalid_model_id_and_malformed_claims_do_not_leak(self):
        composition = {'claims': [{'citations': [{'id': 'PRIVATE_SECRET_ID', 'quote': 'PRIVATE_BODY'}]}, 'bad']}
        result = diag.quote_metrics(composition, [DOC], [DOC], {})
        self.assertNotIn('PRIVATE_SECRET_ID', json.dumps(result))
        self.assertNotIn('PRIVATE_BODY', json.dumps(result))
        self.assertEqual(result['citations'][0]['id'], '[unlisted-id]')

    def test_direct_transport_has_no_tools_history_or_body_logging(self):
        response = mock.MagicMock()
        response.read.return_value = json.dumps({'candidates': [{'content': {'parts': [
            {'text': '{"abstain":true,"claims":[]}'}]}}]}).encode()
        opener = mock.Mock()
        opener.open.return_value = response
        with mock.patch.dict('os.environ', {'GOOGLE_API_KEY': 'DUMMY_NOT_A_REAL_KEY'}), \
             mock.patch.object(diag.urllib.request, 'build_opener', return_value=opener):
            obj = diag.public_model('PUBLIC_DEV_PROMPT', 'google/gemini-3.5-flash-lite')
        request = opener.open.call_args.args[0]
        payload = json.loads(request.data)
        self.assertFalse(payload['store'])
        self.assertNotIn('tools', payload)
        self.assertTrue(obj['abstain'])
        response.close.assert_called_once()
