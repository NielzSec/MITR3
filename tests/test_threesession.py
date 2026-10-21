"""Onda 10: synthetic transport only; sockets/DNS forbidden for every test."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import socket
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('threesession', ROOT/'bin/mitr3-threesession.py')
T = importlib.util.module_from_spec(spec)
spec.loader.exec_module(T)
TEMPLATES = ROOT/'engagements/burp_lane/h1_meli_onda10/templates'
FILES = {'C1': 'C1_comprador-A-le-pedido.req', 'C2': 'C2_vendedor-C-le-venda.req',
         'X1': 'X1_terceiro-B-le-pedido-de-A.req'}


def reply(obj, status=200):
    return status, json.dumps(obj, sort_keys=True).encode()


class ThreeSessionTests(unittest.TestCase):
    def setUp(self):
        for function in ('socket', 'create_connection', 'getaddrinfo'):
            patcher = mock.patch.object(socket, function, side_effect=AssertionError('NETWORK_FORBIDDEN'))
            patcher.start()
            self.addCleanup(patcher.stop)
        self.identities = {'A': T.BUYER, 'C': 'fixture-new-seller-c', 'B': T.THIRD_PARTY}
        self.sessions = {who: 'fixture-token-'+who for who in self.identities}
        self.order = {'id': 'fixture-order-a-c', 'buyer': {'id': T.BUYER},
                      'seller': {'id': self.identities['C']},
                      'order_items': [{'item': {'id': 'fixture-item-c'}, 'quantity': 1}],
                      'total_amount': 19.75, 'status': 'paid',
                      'shipping': {'receiver_address': {'street_name': 'SYNTHETIC_PRIVATE_STREET'}}}
        self.calls = []

    def responses(self, cross=None):
        identities = [reply({'id': self.identities[who], 'test_user': True,
                             'new_test_user': who == 'C'}) for who in ('A', 'C', 'B')]
        return identities + [reply(self.order), reply(self.order),
                             cross if cross is not None else reply({'error': 'not_owned_order'}, 403)]

    def runner(self, responses, resource=''):
        pending = iter(responses)
        def send(method, url, headers, body):
            self.calls.append((method, url, dict(headers), body))
            return next(pending)
        return T.Runner(self.identities, self.sessions, self.order['id'], send, resource=resource)

    def subresource(self, resource, who='A'):
        # Normalized fixture envelopes, not claimed production response schemas.
        obj = {'order_id': self.order['id'], 'buyer': self.order['buyer'], 'seller': self.order['seller']}
        obj.update({
            'shipments': {'shipments': [{'id': 'fixture-shipment-ac',
                                        'receiver_address': 'SYNTHETIC_SHIPMENT_ADDRESS'}]},
            'billing_info': {'billing_info': {'id': 'fixture-billing-ac',
                                              'tax_document': 'SYNTHETIC_TAX_DOCUMENT'}},
            'notes': {'notes': [{'id': 'fixture-shared-note', 'text': 'SYNTHETIC_SHARED_NOTE'}]},
        }[resource])
        if resource == 'notes' and who == 'C':
            obj['seller_notes'] = [{'id': 'fixture-seller-note', 'text': 'SYNTHETIC_SELLER_PRIVATE_NOTE'}]
        return copy.deepcopy(obj)

    def subresource_responses(self, resource, cross):
        return self.responses()[:3] + [reply(self.subresource(resource, who)) for who in ('A', 'C')] + [cross]

    def test_subresources_200_controls_and_strict_denials(self):
        for resource in ('shipments', 'billing_info', 'notes'):
            for status in (403, 404):
                with self.subTest(resource=resource, status=status):
                    self.calls.clear()
                    result = self.runner(self.subresource_responses(resource, reply({'error': 'forbidden'}, status)), resource).run()
                    self.assertEqual(result['verdict'], 'NEGATIVE')
                    self.assertEqual([row['status'] for row in result['cases']], [200, 200, status])
                    self.assertEqual([row['verdict'] for row in result['cases'][:2]], ['POSITIVE_CONTROL']*2)
                    self.assertEqual([e['session'] for e in result['requests']], ['A', 'C', 'B']*2)
                    self.assertEqual(len(self.calls), 6)
                    for method, url, headers, body in self.calls[3:]:
                        self.assertEqual(url, T.ORIGIN+'/orders/'+self.order['id']+'/'+resource)
                        self.assertEqual(method, 'GET')
                        self.assertIsNone(body)

    def test_subresource_authorization_decoupled_from_secure_parent(self):
        self.assertEqual(self.runner(self.responses()).run()['verdict'], 'NEGATIVE')
        for resource in ('shipments', 'billing_info', 'notes'):
            with self.subTest(resource=resource):
                leak = reply(self.subresource(resource, 'C'))
                result = self.runner(self.subresource_responses(resource, leak), resource).run()
                self.assertEqual(result['verdict'], 'BOLA_CANDIDATE')
                self.assertEqual(result['resource'], resource)

    def test_subresource_denials_with_data_never_negative(self):
        for resource in ('shipments', 'billing_info', 'notes'):
            for status in (403, 404):
                with self.subTest(resource=resource, status=status):
                    leak = reply(self.subresource(resource, 'C'), status)
                    self.assertEqual(self.runner(self.subresource_responses(resource, leak), resource).run()['verdict'],
                                     'BOLA_CANDIDATE')

    def test_notes_seller_only_data_is_not_exposed_to_buyer_and_is_checked_for_b(self):
        buyer, seller = self.subresource('notes'), self.subresource('notes', 'C')
        self.assertNotIn('seller_notes', buyer)
        self.assertIn('seller_notes', seller)
        leak = {k: v for k, v in seller.items() if k != 'notes'}
        result = self.runner(self.subresource_responses('notes', reply(leak)), 'notes').run()
        self.assertEqual(result['verdict'], 'BOLA_CANDIDATE')
        responses = self.subresource_responses('notes', reply({}, 403))
        responses[3] = reply(seller)
        self.calls.clear()
        result = self.runner(responses, 'notes').run()
        self.assertEqual(result['reason'], 'RESOURCE_SCOPE_FAILED')
        self.assertEqual(len(self.calls), 4)

    def test_subresource_wrong_order_or_actor_is_not_bound_evidence(self):
        for resource in ('shipments', 'billing_info', 'notes'):
            for key, value in (('order_id', 'fixture-other-order'), ('buyer', {'id': T.THIRD_PARTY}),
                               ('seller', {'id': T.THIRD_PARTY})):
                with self.subTest(resource=resource, key=key):
                    obj = self.subresource(resource)
                    obj[key] = value
                    result = self.runner(self.subresource_responses(resource, reply(obj)), resource).run()
                    self.assertEqual(result['verdict'], 'INCONCLUSIVE')
                    responses = self.subresource_responses(resource, reply({}, 403))
                    responses[4] = reply(obj)
                    self.calls.clear()
                    result = self.runner(responses, resource).run()
                    self.assertEqual(result['reason'], 'POSITIVE_CONTROL_FAILED')
                    self.assertEqual(len(self.calls), 5)

    def test_subresource_200_shell_and_unrecognized_denial_are_inconclusive(self):
        for resource in ('shipments', 'billing_info', 'notes'):
            for cross in (reply({}), reply({'order_id': self.order['id']}),
                          reply({'error': 'forbidden', 'data': self.subresource(resource)}, 403)):
                with self.subTest(resource=resource, cross=cross):
                    result = self.runner(self.subresource_responses(resource, cross), resource).run()
                    self.assertEqual(result['verdict'], 'INCONCLUSIVE')

    def test_subresource_malformed_or_missing_positive_data_stops(self):
        for resource in ('shipments', 'billing_info', 'notes'):
            for invalid in (None, '', {}, [], 'not a resource', [None]):
                with self.subTest(resource=resource, invalid=invalid):
                    responses = self.subresource_responses(resource, reply({}, 403))
                    obj = self.subresource(resource)
                    obj[resource] = invalid
                    responses[3] = reply(obj)
                    result = self.runner(responses, resource).run()
                    self.assertEqual(result['reason'], 'POSITIVE_CONTROL_FAILED')

    def test_subresource_metadata_has_no_private_fixture_values(self):
        for resource in ('shipments', 'billing_info', 'notes'):
            responses = self.subresource_responses(resource, reply(self.subresource(resource, 'C')))
            result = self.runner(responses, resource).run()
            text = json.dumps(result)
            for private in ('SYNTHETIC_SHIPMENT_ADDRESS', 'SYNTHETIC_TAX_DOCUMENT',
                            'SYNTHETIC_SHARED_NOTE', 'SYNTHETIC_SELLER_PRIVATE_NOTE',
                            self.order['id'], *self.sessions.values()):
                self.assertNotIn(private, text)
            self.assertEqual([e['response_sha256'] for e in result['requests']],
                             [hashlib.sha256(raw).hexdigest() for _, raw in responses])

    def test_subresource_selector_cannot_change_host_or_expand_scope(self):
        for resource in ('../notes', '/shipments', 'notes?other=1', 'https://example.test', 'cancel', None):
            with self.subTest(resource=resource), self.assertRaisesRegex(T.HarnessError, 'SUBRESOURCE_NOT_ALLOWED'):
                T.Runner(self.identities, self.sessions, self.order['id'], mock.Mock(), resource=resource)

    def test_c1_c2_200_x1_403_is_negative(self):
        result = self.runner(self.responses()).run()
        self.assertEqual(result['state'], 'DONE')
        self.assertEqual(result['verdict'], 'NEGATIVE')
        self.assertEqual([r['status'] for r in result['cases']], [200, 200, 403])
        self.assertEqual([r['verdict'] for r in result['cases']],
                         ['POSITIVE_CONTROL', 'POSITIVE_CONTROL', 'NEGATIVE'])

    def test_x1_404_is_negative_with_no_private_fields(self):
        result = self.runner(self.responses(reply({'error': 'not_found', 'status': 404}, 404))).run()
        self.assertEqual(result['verdict'], 'NEGATIVE')

    def test_empty_403_and_404_are_negative(self):
        for status in (403, 404):
            result = self.runner(self.responses((status, b''))).run()
            self.assertEqual(result['verdict'], 'NEGATIVE')

    def test_x1_200_with_bound_private_order_is_bola_candidate(self):
        result = self.runner(self.responses(reply(self.order))).run()
        self.assertEqual(result['verdict'], 'BOLA_CANDIDATE')
        self.assertEqual(result['reason'], 'BOUND_PRIVATE_ORDER_FIELDS')
        self.assertEqual(result['cases'][-1]['status'], 200)
        self.assertTrue(result['offline'])

    def test_each_private_field_can_discriminate_when_order_ownership_is_bound(self):
        for field in T.PRIVATE_FIELDS:
            with self.subTest(field=field):
                body = {k: self.order[k] for k in ('id', 'buyer', 'seller', field)}
                result = self.runner(self.responses(reply(body))).run()
                self.assertEqual(result['verdict'], 'BOLA_CANDIDATE')

    def test_denial_status_with_private_order_data_is_never_safe(self):
        for status in (403, 404):
            with self.subTest(status=status):
                result = self.runner(self.responses(reply(self.order, status))).run()
                self.assertEqual(result['verdict'], 'BOLA_CANDIDATE')

    def test_nested_private_body_or_message_on_denial_is_inconclusive(self):
        for body in ({'error': 'forbidden', 'data': self.order},
                     {'message': self.order}, {'message': 'SYNTHETIC_PRIVATE_STREET'},
                     {'cause': [self.order]}, {'error': 'forbidden', 'status': 200}):
            with self.subTest(body=body):
                result = self.runner(self.responses(reply(body, 403))).run()
                self.assertEqual(result['verdict'], 'INCONCLUSIVE')

    def test_200_shell_or_order_id_alone_is_not_bola(self):
        for body in ({}, {'message': 'OK'}, {'id': self.order['id']},
                     {k: self.order[k] for k in ('id', 'buyer', 'seller')}):
            with self.subTest(body=body):
                result = self.runner(self.responses(reply(body))).run()
                self.assertEqual(result['verdict'], 'INCONCLUSIVE')

    def test_b_own_order_or_unrelated_fields_do_not_prove_bola(self):
        for field, value in (('id', 'fixture-other-order'), ('buyer', {'id': T.THIRD_PARTY}),
                             ('seller', {'id': T.THIRD_PARTY})):
            body = copy.deepcopy(self.order)
            body[field] = value
            result = self.runner(self.responses(reply(body))).run()
            self.assertEqual(result['verdict'], 'INCONCLUSIVE')
        body = {k: self.order[k] for k in ('id', 'buyer', 'seller')}
        body['shipping'] = {'receiver_address': 'different fixture'}
        self.assertEqual(self.runner(self.responses(reply(body))).run()['verdict'], 'INCONCLUSIVE')

    def test_sequence_is_a_c_b_identity_then_c1_c2_x1_same_order(self):
        result = self.runner(self.responses()).run()
        self.assertEqual([r['session'] for r in result['requests']], ['A', 'C', 'B', 'A', 'C', 'B'])
        self.assertEqual([r['state'] for r in result['requests']], ['IDENTITIES']*3 + ['C1', 'C2', 'X1'])
        self.assertEqual(len(self.calls), 6)
        self.assertLessEqual(len(self.calls), 10)
        for method, url, headers, body in self.calls:
            self.assertEqual(method, 'GET')
            self.assertTrue(url.startswith('https://meli.example.test/'))
            self.assertEqual(headers['Host'], 'meli.example.test')
            self.assertIsNone(body)
        self.assertEqual(len({call[1] for call in self.calls[3:]}), 1)
        stable_headers = []
        for index, who in enumerate(('A', 'C', 'B')):
            headers = dict(self.calls[index+3][2])
            self.assertEqual(headers.pop('Authorization'), 'Bearer '+self.sessions[who])
            stable_headers.append(headers)
        self.assertEqual(stable_headers, [stable_headers[0]]*3)

    def test_bad_positive_controls_stop_before_next_case(self):
        for index in (3, 4):
            for response in (reply({}, 403), reply({}), reply({'id': 'fixture-other-order'})):
                with self.subTest(index=index, response=response):
                    self.calls.clear()
                    responses = self.responses()
                    responses[index] = response
                    result = self.runner(responses).run()
                    self.assertEqual(result['state'], 'STOPPED')
                    self.assertEqual(result['reason'], 'POSITIVE_CONTROL_FAILED')
                    self.assertEqual(result['verdict'], 'INCONCLUSIVE')
                    self.assertEqual(len(self.calls), index+1)
                    self.assertEqual(result['cases'][-1]['verdict'], 'NOT_RUN')
                    self.assertEqual(result['cases'][index-3]['verdict'], 'INCONCLUSIVE')

    def test_c2_disagreeing_with_c1_stops_before_x1(self):
        responses = self.responses()
        body = {k: self.order[k] for k in ('id', 'buyer', 'seller')}
        body['shipping'] = {'receiver_address': 'different fixture'}
        responses[4] = reply(body)
        result = self.runner(responses).run()
        self.assertEqual(result['reason'], 'CONTROLS_DISAGREE')
        self.assertEqual(len(self.calls), 5)

    def test_c2_conflicting_amount_stops_even_when_status_matches(self):
        responses = self.responses()
        body = copy.deepcopy(self.order)
        body['total_amount'] += 1
        responses[4] = reply(body)
        self.assertEqual(self.runner(responses).run()['reason'], 'CONTROLS_DISAGREE')
        self.assertEqual(len(self.calls), 5)

    def test_b_cannot_be_buyer_or_seller_and_c_must_be_new(self):
        for who, wrong in (('A', T.THIRD_PARTY), ('B', T.BUYER), ('C', T.THIRD_PARTY)):
            identities = dict(self.identities)
            identities[who] = wrong
            with self.assertRaises(T.HarnessError):
                T.Runner(identities, self.sessions, self.order['id'], mock.Mock())
        responses = self.responses()
        responses[1] = reply({'id': self.identities['C'], 'test_user': True, 'new_test_user': False})
        result = self.runner(responses).run()
        self.assertEqual(result['reason'], 'NEW_TEST_SELLER_REQUIRED')
        self.assertEqual(len(self.calls), 2)

    def test_identity_swaps_and_non_test_users_stop_before_order_reads(self):
        for index in range(3):
            for field, value in (('id', 'fixture-unexpected-user'), ('test_user', False)):
                self.calls.clear()
                responses = self.responses()
                body = json.loads(responses[index][1])
                body[field] = value
                responses[index] = reply(body)
                result = self.runner(responses).run()
                self.assertEqual(result['reason'], 'IDENTITY_NOT_CONFIRMED')
                self.assertEqual(len(self.calls), index+1)
                self.assertFalse(any('/orders/' in call[1] for call in self.calls))

    def test_duplicate_or_real_sessions_and_real_order_rejected(self):
        for value in (self.sessions['A'], 'Bearer REAL_VALUE', 'fixture-x\r\nInjected: yes'):
            sessions = dict(self.sessions)
            sessions['B'] = value
            with self.assertRaises(T.HarnessError):
                T.Runner(self.identities, sessions, self.order['id'], mock.Mock())
        with self.assertRaises(T.HarnessError):
            T.Runner(self.identities, self.sessions, '2000000000000001', mock.Mock())
        with self.assertRaises(T.HarnessError):
            T.Runner(self.identities, self.sessions, self.order['id'], None)

    def test_waf_billing_rate_limit_redirect_and_5xx_stop_without_retry(self):
        cases = [reply({}, 429), reply({}, 500), reply({}, 302), reply({'waf': True}, 403),
                 reply({'message': 'captcha'}), reply({'real_charge': True})]
        for index in (0, 3, 4, 5):
            for response in cases:
                with self.subTest(index=index, response=response):
                    self.calls.clear()
                    responses = self.responses()
                    responses[index] = response
                    result = self.runner(responses).run()
                    self.assertEqual(result['state'], 'STOPPED')
                    self.assertEqual(result['verdict'], 'INCONCLUSIVE')
                    self.assertEqual(len(self.calls), index+1)

    def test_non_json_duplicate_keys_and_invalid_constants_are_not_findings(self):
        for raw in (b'<html>login</html>', b'{"id":1,"id":2}', b'{"total_amount":NaN}', b'[]'):
            result = self.runner(self.responses((200, raw))).run()
            self.assertEqual(result['state'], 'STOPPED')
            self.assertEqual(result['verdict'], 'INCONCLUSIVE')

    def test_transport_errors_and_oversized_responses_are_sanitized(self):
        for error in (RuntimeError('SYNTHETIC_PRIVATE_STREET'), T.HarnessError('fixture-token-A')):
            runner = T.Runner(self.identities, self.sessions, self.order['id'], mock.Mock(side_effect=error))
            result = runner.run()
            self.assertEqual(result['reason'], 'TRANSPORT_FAILED')
            self.assertNotIn(str(error), json.dumps(result))
        with mock.patch.object(T, 'MAX_BYTES', 10):
            self.assertEqual(self.runner(self.responses()).run()['reason'], 'RESPONSE_LIMIT')

    def test_metadata_only_output_and_response_hashes(self):
        responses = self.responses(reply(self.order))
        result = self.runner(responses).run()
        text = json.dumps(result)
        for private in (*self.identities.values(), *self.sessions.values(), self.order['id'],
                        'SYNTHETIC_PRIVATE_STREET', '19.75'):
            self.assertNotIn(private, text)
        self.assertEqual([r['response_sha256'] for r in result['requests']],
                         [hashlib.sha256(raw).hexdigest() for _, raw in responses])

    def test_runner_cannot_replay_after_completion_or_stop(self):
        for responses in (self.responses(), [reply({}, 429)]):
            runner = self.runner(responses)
            runner.run()
            count = len(self.calls)
            with self.assertRaisesRegex(T.HarnessError, 'SINGLE_USE_RUNNER'):
                runner.run()
            self.assertEqual(len(self.calls), count)

    def test_network_guard_is_active(self):
        with self.assertRaisesRegex(AssertionError, 'NETWORK_FORBIDDEN'):
            socket.create_connection(('meli.example.test', 443))

    def test_templates_exact_read_only_matrix_and_token_separation(self):
        stable = []
        # Audit the original trio; other lanes may stage additional subresource templates.
        self.assertTrue(set(FILES.values()).issubset(p.name for p in TEMPLATES.glob('*.req')))
        for case, who in T.CASES:
            raw = (TEMPLATES/FILES[case]).read_text()
            head, body = raw.split('\n\n', 1)
            self.assertEqual(body, '')
            first, *headers = head.splitlines()
            self.assertEqual(first, 'GET /orders/$ORDER_ID HTTP/1.1')
            pairs = [line.split(': ', 1) for line in headers]
            parsed = dict(pairs)
            self.assertEqual(len(parsed), len(pairs))
            self.assertEqual(set(parsed), {'Host', 'User-Agent', 'Accept', 'Authorization'})
            self.assertEqual(parsed['Host'], 'api.mercadolibre.com')
            self.assertEqual(parsed['Accept'], 'application/json')
            self.assertEqual(parsed['User-Agent'], T.USER_AGENT)
            self.assertEqual(parsed.pop('Authorization'), 'Bearer $AUTH_TOKEN_'+who)
            stable.append((first, parsed))
        self.assertEqual(stable, [stable[0]]*3)


if __name__ == '__main__':
    unittest.main()
