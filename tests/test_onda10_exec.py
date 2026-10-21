"""Offline tests: synthetic credentials/responses; sockets and DNS forbidden."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('onda10_exec', ROOT / 'bin/mitr3-onda10-exec.py')
E = importlib.util.module_from_spec(spec)
spec.loader.exec_module(E)


class Onda10Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.output = self.root / 'output'
        self.tokens = self.root / 'tokens'
        self.tokens.mkdir(mode=0o700)
        self.ids = {'A': E.H.BUYER, 'B': E.H.THIRD_PARTY, 'C': '99112233'}
        for actor, identity in self.ids.items():
            p = self.tokens / f'token_{actor}.json'
            p.write_text(json.dumps({'access_token': 'SYNTHETIC_SECRET_' + actor, 'user_id': identity}))
            p.chmod(0o600)
        self.lane = self.root / 'lane'
        (self.lane / 'templates').mkdir(parents=True)
        for name, actor, resource in E.G.FILES.values():
            route = '/orders/$ORDER_ID' + ('/' + resource if resource else '')
            (self.lane / 'templates' / name).write_bytes(('\r\n'.join([
                f'GET {route} HTTP/1.1', 'Host: api.mercadolibre.com',
                'User-Agent: Mozilla/5.0 Test', 'Accept: application/json',
                'Authorization: Bearer $AUTH_TOKEN_' + actor, '', ''])).encode())
        (self.lane / 'README.md').write_text('Offline fixture\n')
        self.ledger = self.root / 'rate.jsonl'
        p = patch.object(E.L, 'LEDGER', str(self.ledger)); p.start(); self.addCleanup(p.stop)
        for name in ('socket', 'create_connection', 'getaddrinfo'):
            p = patch.object(socket, name, side_effect=AssertionError('NETWORK_FORBIDDEN'))
            p.start(); self.addCleanup(p.stop)
        self.requests, self.identities = E.prepare(self.lane, self.tokens)
        self.sleep = Mock()

    def order(self, resource=''):
        result = {'order_id' if resource else 'id': E.ORDER_ID,
                  'buyer': {'id': self.ids['A']}, 'seller': {'id': self.ids['C']}}
        if resource == 'shipments':
            result['shipments'] = [{'address': 'SYNTHETIC_PRIVATE'}]
        elif resource == 'billing_info':
            result['billing_info'] = {'document': 'SYNTHETIC_PRIVATE'}
        else:
            result['order_items'] = [{'item': {'id': 'SYNTHETIC_PRIVATE'}}]
            result['total_amount'] = 19.75
        return result

    def response(self, obj=None, status=200):
        return status, [('Content-Type', 'application/json')], json.dumps(obj if obj is not None else self.order()).encode()

    def run_fake(self, responses=None, suite='base'):
        if responses is None:
            responses = [self.response(), self.response(), self.response({'error': 'forbidden'}, 403)]
        transport = Mock(side_effect=responses)
        result = E.execute(self.requests, self.identities, suite, self.output, transport, self.sleep)
        return result, transport

    def seed_rate(self, count=0, status=200, **extra):
        rec = {'ts': E.utc(), 'host': E.HOST, 'method': 'GET', 'path': '/setup', 'count': count, 'status': status}
        rec.update(extra)
        self.ledger.write_text(json.dumps(rec) + '\n')

    def seed_session(self, count=0, stopped=False):
        E.private_dir(self.output)
        E.G.write_private(self.output / 'session_ledger.json', {'count': count, 'events': [], 'stopped': stopped})

    def test_prepare_all_nine_exact_bytes(self):
        self.assertEqual(len(self.requests), 9)
        for case, raw in self.requests.items():
            actor = E.G.FILES[case][1]
            self.assertIn(('Bearer SYNTHETIC_SECRET_' + actor).encode(), raw)
            self.assertIn(E.ORDER_ID.encode(), raw)
            self.assertNotIn(b'$', raw)
            self.assertEqual(len(raw.split(b'\r\n')), 7)

    def test_default_and_explicit_dry_run_never_dispatch(self):
        for argv in ([], ['--dry-run'], ['--dry-run', '--suite', 'all']):
            with self.subTest(argv=argv), patch.object(E, 'prepare', return_value=(self.requests, self.identities)), patch.object(E, 'execute') as execute:
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    self.assertEqual(E.main(argv), 0)
                execute.assert_not_called()
                self.assertNotIn('SYNTHETIC_SECRET', out.getvalue())
                self.assertFalse(self.ledger.exists())

    def test_cli_live_dispatch_and_failure_code(self):
        with patch.object(E, 'prepare', return_value=(self.requests, self.identities)), patch.object(E, 'execute', return_value={'state': 'STOPPED'}) as execute, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(E.main(['--live', '--suite', 'all']), 2)
            self.assertEqual(execute.call_args.args[2], 'all')

    def test_cli_modes_are_exclusive(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            E.main(['--live', '--dry-run'])

    def test_order_id_cli_dry_run_interpolates_all_templates(self):
        prepare = E.prepare
        for order_id in ('12345678', '9000015638831799'):
            with self.subTest(order_id=order_id):
                def fixture_prepare(*, order_id):
                    requests, identities = prepare(self.lane, self.tokens, order_id=order_id)
                    for case, raw in requests.items():
                        resource = E.G.FILES[case][2]
                        route = '/orders/' + order_id + ('/' + resource if resource else '')
                        self.assertEqual(raw.split(b'\r\n')[0], f'GET {route} HTTP/1.1'.encode())
                        self.assertNotIn(E.ORDER_ID.encode(), raw)
                    return requests, identities
                out = io.StringIO()
                with patch.object(E, 'prepare', side_effect=fixture_prepare), patch.object(E, 'execute') as execute, contextlib.redirect_stdout(out):
                    self.assertEqual(E.main(['--dry-run', '--order-id', order_id]), 0)
                execute.assert_not_called()
                self.assertIn('DRY_RUN_PASS templates=9 network_calls=0', out.getvalue())

    def test_invalid_order_ids_rejected_before_credentials_or_network(self):
        values = ('', '1234567', '1234567a', '12345678/shipments', '../12345678',
                  '12345678?x=1', '12345678\r\nHost: evil', '12345678\n',
                  ' 12345678', '+12345678', '-12345678', '１２３４５６７８', '١٢٣٤٥٦٧٨')
        for order_id in values:
            with self.subTest(order_id=order_id), patch.object(E, 'read_private') as read, patch.object(E, 'execute') as execute:
                with self.assertRaisesRegex(E.Stop, '^INVALID_ORDER_ID$'):
                    E.prepare(self.lane, self.tokens, order_id=order_id)
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    self.assertEqual(E.main(['--order-id=' + order_id]), 2)
                self.assertEqual(out.getvalue(), 'ONDA10 BLOCK INVALID_ORDER_ID\n')
                read.assert_not_called()
                execute.assert_not_called()

    def test_custom_order_id_reaches_execution_and_ownership_for_all_resources(self):
        order_id = '9000015638831799'
        requests, identities = E.prepare(self.lane, self.tokens, order_id=order_id)
        replies = []
        for resource in ('', 'shipments', 'billing_info'):
            key = 'order_id' if resource else 'id'
            obj = self.order(resource)
            obj[key] = order_id
            replies.extend([self.response(obj), self.response(obj), self.response({}, 404)])
            baseline = E.H.private_values(obj, resource)
            self.assertEqual(E.classify('X1', resource, *self.response(obj), identities,
                                       baseline, order_id=order_id), 'BOLA_CANDIDATE')
            obj[key] = E.ORDER_ID
            with self.assertRaisesRegex(E.Stop, 'POSITIVE_CONTROL_FAILED'):
                E.classify('C1', resource, *self.response(obj), identities, {}, order_id=order_id)
            with self.assertRaisesRegex(E.Stop, 'INCONCLUSIVE_RESPONSE'):
                E.classify('X1', resource, *self.response(obj), identities, baseline, order_id=order_id)
        transport = Mock(side_effect=replies)
        execute = E.execute
        def fake_execute(requests, identities, suite, *, order_id):
            self.assertEqual(order_id, '9000015638831799')
            return execute(requests, identities, suite, self.output, transport, self.sleep, order_id=order_id)
        with patch.object(E, 'prepare', return_value=(requests, identities)), patch.object(E, 'execute', side_effect=fake_execute), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(E.main(['--live', '--suite', 'all', '--order-id', order_id]), 0)
        self.assertEqual(transport.call_count, 9)

    def test_bad_tokens_fail_without_values(self):
        for value in ('secret\r\nInjected: yes', '', '$AUTH_TOKEN_A', None):
            with self.subTest(value=value):
                p = self.tokens / 'token_A.json'
                p.write_text(json.dumps({'access_token': value, 'user_id': self.ids['A']}))
                with self.assertRaisesRegex(E.Stop, '^TOKEN_FORMAT$'):
                    E.prepare(self.lane, self.tokens)

    def test_world_readable_token_rejected(self):
        (self.tokens / 'token_B.json').chmod(0o644)
        with self.assertRaisesRegex(E.Stop, 'PRIVATE_FILE_REQUIRED'):
            E.prepare(self.lane, self.tokens)

    def test_symlink_token_rejected(self):
        path = self.tokens / 'token_B.json'
        path.unlink(); path.symlink_to(self.tokens / 'token_A.json')
        with self.assertRaises(OSError):
            E.prepare(self.lane, self.tokens)

    def test_duplicate_identity_rejected(self):
        p = self.tokens / 'token_C.json'
        p.write_text(json.dumps({'access_token': 'C', 'user_id': self.ids['A']}))
        with self.assertRaisesRegex(E.Stop, 'IDENTITIES_NOT_ISOLATED'):
            E.prepare(self.lane, self.tokens)

    def test_bad_crlf_in_any_template_rejected(self):
        for name, _, _ in E.G.FILES.values():
            path = self.lane / 'templates' / name
            raw = path.read_bytes(); path.write_bytes(raw.replace(b'\r\n', b'\n'))
            with self.subTest(file=name), self.assertRaisesRegex(E.Stop, 'STAGING_GATE_BLOCK'):
                E.prepare(self.lane, self.tokens)
            path.write_bytes(raw)

    def test_base_sequence_delays_and_hashes(self):
        result, transport = self.run_fake()
        self.assertEqual(result['state'], 'COMPLETE')
        self.assertEqual([c['case'] for c in result['cases']], ['C1', 'C2', 'X1'])
        self.assertEqual([c.args[0] for c in transport.call_args_list], [self.requests[c] for c in ('C1', 'C2', 'X1')])
        self.assertEqual([c.args for c in self.sleep.call_args_list], [(1.5,), (1.5,)])
        self.assertEqual(result['cases'][-1]['verdict'], 'NEGATIVE')
        run = next(p for p in self.output.iterdir() if p.is_dir())
        for line in (run / 'SHA256SUMS').read_text().splitlines():
            checksum, name = line.split('  ')
            self.assertEqual(checksum, hashlib.sha256((run / name).read_bytes()).hexdigest())
        for path in run.iterdir():
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(run.stat().st_mode & 0o777, 0o700)
        self.assertNotIn('SYNTHETIC_PRIVATE', (run / 'summary.json').read_text())
        self.assertNotIn('SYNTHETIC_SECRET', str(result))
        records = E.L.load()
        self.assertEqual(sum(r['count'] for r in records), 3)
        self.assertEqual([r['note'] for r in records if r['count']], ['onda10-C1', 'onda10-C2', 'onda10-X1'])
        self.assertTrue(records[-1]['expected_403'])

    def test_all_suite_serial_nine(self):
        replies = []
        for resource in ('', 'shipments', 'billing_info'):
            replies.extend([self.response(self.order(resource)), self.response(self.order(resource)), self.response({}, 404)])
        result, transport = self.run_fake(replies, 'all')
        self.assertEqual(result['state'], 'COMPLETE')
        self.assertEqual(transport.call_count, 9)
        self.assertEqual(self.sleep.call_count, 8)
        self.assertEqual(json.loads((self.output / 'session_ledger.json').read_text())['count'], 9)

    def test_host_budget_blocks_before_socket(self):
        self.seed_rate(60)
        result, transport = self.run_fake()
        self.assertEqual(result['reason'], 'HOST_BUDGET_EXHAUSTED')
        transport.assert_not_called()

    def test_host_budget_rechecked_before_each_request(self):
        self.seed_rate(59)
        result, transport = self.run_fake()
        self.assertEqual(transport.call_count, 1)
        self.assertEqual(result['reason'], 'HOST_BUDGET_EXHAUSTED')

    def test_session_budget_includes_seeded_setup_and_persists(self):
        self.seed_session(9)
        result, transport = self.run_fake()
        self.assertEqual(transport.call_count, 1)
        self.assertEqual(result['reason'], 'WAVE_BUDGET_EXHAUSTED')
        result, transport = self.run_fake()
        self.assertEqual(result['reason'], 'WAVE_BUDGET_EXHAUSTED')
        transport.assert_not_called()

    def test_wave_ten_blocks(self):
        self.seed_session(10)
        result, transport = self.run_fake()
        self.assertEqual(result['reason'], 'WAVE_BUDGET_EXHAUSTED')
        transport.assert_not_called()

    def test_corrupt_rate_ledger_blocks(self):
        self.ledger.write_text('{corrupt\n')
        result, transport = self.run_fake()
        self.assertEqual(result['state'], 'STOPPED')
        transport.assert_not_called()

    def test_recent_rate_stop_blocks(self):
        for status in (429, 403):
            with self.subTest(status=status):
                self.seed_rate(1, status)
                result, transport = self.run_fake()
                self.assertEqual(result['reason'], 'RATE_LEDGER_STOP')
                transport.assert_not_called()

    def test_fail_closed_controls_waf_and_server_errors(self):
        cases = [self.response({}, 403), self.response({}, 429), self.response({}, 500),
                 self.response({}, 302), self.response({'captcha': True}), self.response({})]
        for index, bad in enumerate(cases):
            with self.subTest(index=index):
                self.output = self.root / f'output{index}'
                self.ledger.unlink(missing_ok=True)
                result, transport = self.run_fake([bad])
                self.assertEqual(result['state'], 'STOPPED')
                self.assertEqual(transport.call_count, 1)
                self.assertTrue(json.loads((self.output / 'session_ledger.json').read_text())['stopped'])

    def test_c2_failure_does_not_send_x1(self):
        result, transport = self.run_fake([self.response(), self.response({}, 403)])
        self.assertEqual(transport.call_count, 2)
        self.assertEqual(result['state'], 'STOPPED')

    def test_transport_failure_counts_and_blocks_replay(self):
        result, transport = self.run_fake([OSError('SYNTHETIC_SECRET_A')])
        self.assertEqual(result['reason'], 'EXECUTION_FAILED')
        self.assertNotIn('SYNTHETIC_SECRET', str(result))
        self.assertEqual(sum(r['count'] for r in E.L.load()), 1)
        with self.assertRaisesRegex(E.Stop, 'SESSION_STOPPED'):
            self.run_fake()

    def test_candidate_stops_all_suite_and_seals(self):
        result, transport = self.run_fake([self.response(), self.response(), self.response()], 'all')
        self.assertEqual(transport.call_count, 3)
        self.assertEqual(result['cases'][-1]['verdict'], 'BOLA_CANDIDATE')
        self.assertEqual(result['reason'], 'CANDIDATE_REQUIRES_REVIEW')

    def test_denial_with_private_data_never_negative(self):
        for status in (403, 404):
            with self.subTest(status=status):
                self.output = self.root / f'output{status}'
                self.ledger.unlink(missing_ok=True)
                result, _ = self.run_fake([self.response(), self.response(), self.response(status=status)])
                self.assertEqual(result['cases'][-1]['verdict'], 'BOLA_CANDIDATE')

    def test_empty_shell_is_negative(self):
        result, _ = self.run_fake([self.response(), self.response(), self.response({})])
        self.assertEqual(result['cases'][-1]['verdict'], 'NEGATIVE_SHELL')

    def test_unknown_or_wrong_order_never_negative_or_candidate(self):
        for index, obj in enumerate(({'nested': {'pii': 'SYNTHETIC_PRIVATE'}}, dict(self.order(), id='OTHER'))):
            with self.subTest(index=index):
                self.output = self.root / f'output{index}'
                self.ledger.unlink(missing_ok=True)
                result, _ = self.run_fake([self.response(), self.response(), self.response(obj)])
                self.assertEqual(result['reason'], 'INCONCLUSIVE_RESPONSE')

    def test_controls_must_agree(self):
        obj = self.order(); obj['total_amount'] = 1
        result, transport = self.run_fake([self.response(), self.response(obj)])
        self.assertEqual(result['reason'], 'CONTROLS_DISAGREE')
        self.assertEqual(transport.call_count, 2)

    def test_concurrent_runner_blocked(self):
        with E.session_lock(self.output), self.assertRaisesRegex(E.Stop, 'RUNNER_ALREADY_ACTIVE'):
            self.run_fake()

    def test_duplicate_token_rejected(self):
        p = self.tokens / 'token_C.json'
        p.write_text(json.dumps({'access_token': 'SYNTHETIC_SECRET_A', 'user_id': self.ids['C']}))
        with self.assertRaisesRegex(E.Stop, 'IDENTITIES_NOT_ISOLATED'):
            E.prepare(self.lane, self.tokens)

    def test_wrong_a_identity_rejected(self):
        p = self.tokens / 'token_A.json'
        p.write_text(json.dumps({'access_token': 'SYNTHETIC_SECRET_A', 'user_id': '999'}))
        with self.assertRaisesRegex(E.Stop, 'IDENTITY_MAPPING'):
            E.prepare(self.lane, self.tokens)

    def test_malformed_session_and_symlink_output_rejected(self):
        self.seed_session()
        (self.output / 'session_ledger.json').write_text('not-json')
        with self.assertRaises(E.H.HarnessError):
            self.run_fake()
        other = self.root / 'link'
        other.symlink_to(self.output)
        with self.assertRaisesRegex(E.Stop, 'PRIVATE_DIRECTORY_REQUIRED'):
            E.execute(self.requests, self.identities, 'base', other, Mock(), self.sleep)

    def test_failed_control_keeps_status_and_sealed_body(self):
        result, _ = self.run_fake([self.response({}, 403)])
        self.assertEqual(result['cases'][0]['status'], 403)
        self.assertEqual(result['cases'][0]['verdict'], 'INCONCLUSIVE')
        run = next(p for p in self.output.iterdir() if p.is_dir())
        self.assertEqual((run / 'C1.body.raw').read_bytes(), b'{}')
        self.assertTrue((run / 'SHA256SUMS.sha256').exists())
        self.assertEqual(E.L.load()[-1]['status'], 403)

    def test_oversized_response_and_duplicate_json_stop(self):
        for index, raw in enumerate((b'x' * (E.LIMIT + 1), b'{"id":1,"id":2}')):
            with self.subTest(index=index):
                self.output = self.root / f'output{index}'
                self.ledger.unlink(missing_ok=True)
                result, transport = self.run_fake([(200, [], raw)])
                self.assertEqual(result['state'], 'STOPPED')
                self.assertEqual(transport.call_count, 1)

    def test_ledger_append_failure_prevents_send(self):
        with patch.object(E.L, 'append', side_effect=OSError('DISK_FULL')):
            result, transport = self.run_fake()
        transport.assert_not_called()
        self.assertEqual(result['state'], 'STOPPED')
        self.assertTrue(json.loads((self.output / 'session_ledger.json').read_text())['stopped'])

    def test_rate_other_hosts_and_old_window(self):
        self.seed_rate(60, host='other.example.test')
        result, _ = self.run_fake()
        self.assertEqual(result['state'], 'COMPLETE')
        self.seed_rate(60, ts='2020-01-01T00:00:00+00:00')
        result, _ = self.run_fake()
        self.assertEqual(result['state'], 'COMPLETE')

    def test_socket_guard_active(self):
        with self.assertRaisesRegex(AssertionError, 'NETWORK_FORBIDDEN'):
            E.send(self.requests['C1'])

    def test_tls_transport_exact_request_no_retry(self):
        conn = Mock(); response = Mock()
        response.status = 200; response.getheaders.return_value = [('Content-Type', 'application/json')]
        response.read.return_value = b'{}'
        with patch.object(E.http.client, 'HTTPSConnection', return_value=conn) as ctor, patch.object(E.http.client, 'HTTPResponse', return_value=response):
            self.assertEqual(E.send(self.requests['C1'])[2], b'{}')
        ctor.assert_called_once_with(E.HOST, timeout=20)
        conn.connect.assert_called_once(); conn.sock.sendall.assert_called_once_with(self.requests['C1'])
        conn.close.assert_called_once(); response.read.assert_called_once_with(E.LIMIT + 1)


if __name__ == '__main__':
    unittest.main()
