"""OSINT connector policy and transports: every network boundary is mocked."""
import contextlib
import datetime as dt
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('mitr3_osint', ROOT / 'bin/mitr3-osint.py')
osint = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(osint)


class Response(io.BytesIO):
    def __init__(self, url, payload, status=200, headers=None):
        super().__init__(json.dumps(payload).encode())
        self.url, self.status, self.headers = url, status, headers or {}

    def geturl(self):
        return self.url


class OsintConnectorTests(unittest.TestCase):
    def setUp(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.reports = Path(td.name) / 'reports'
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(osint, 'REPORTS', self.reports).start()
        mock.patch.dict(os.environ, {}, clear=True).start()
        self.open = mock.patch.object(osint, 'urlopen', side_effect=AssertionError('unexpected network')).start()
        mock.patch.object(osint.socket, 'create_connection', side_effect=AssertionError('network forbidden')).start()

    def permit(self, key='HIBP'):
        os.environ[key] = 'dummy-fixture-key-only'
        os.environ['MITR3_OSINT_ALLOW_BROKERS'] = '1'

    def respond(self, url, payload, status=200, headers=None):
        response = Response(url, payload, status, headers)
        self.open.side_effect = None
        self.open.return_value = response
        return response

    def test_catalog_ids_categories_risks_and_no_secret_values(self):
        public = {'crt.sh', 'rdap.org', 'urlscan.io', 'openarchive-status'}
        paid = {'virustotal', 'shodan', 'censys', 'greynoise', 'haveibeenpwned'}
        brokers = {'dehashed', 'leakcheck', 'intelligencex', 'openarchive'}
        self.assertTrue(public | paid | brokers <= osint.CATALOG.keys())
        for ident in public | paid | brokers:
            expected = 'public' if ident in public else 'paid' if ident in paid else 'broker'
            self.assertEqual(osint.CATALOG[ident]['risk'], expected)
        os.environ['MITR3_OSINT_VIRUSTOTAL_KEY'] = 'secret-must-never-print'
        listing = osint.sources()
        self.assertTrue(next(r for r in listing if r['id'] == 'virustotal')['key_configured'])
        self.assertNotIn('secret-must-never-print', json.dumps(listing))
        self.assertEqual(len([r for r in listing if r['category'] == 'manual']), 2)
        self.open.assert_not_called()

    def test_plan_has_no_network_even_with_keys_and_unenabled_brokers(self):
        self.permit('OPENARCHIVE')
        os.environ.pop('MITR3_OSINT_ALLOW_BROKERS')
        result = osint.plan('openarchive', 'email', 'john@domain.com')
        raw = json.dumps(result)
        self.assertTrue(result['dry_run'])
        self.assertFalse(result['sent'])
        self.assertNotIn('john@domain.com', raw)
        self.assertNotIn('john%40domain.com', raw)
        self.assertNotIn('dummy-fixture-key-only', raw)
        self.assertIn('jo***@do***.com', raw)
        self.open.assert_not_called()
        self.assertFalse(self.reports.exists())

    def test_all_connector_plans_are_dry_and_pinned(self):
        values = {'domain': 'example.org', 'ip': '192.0.2.1', 'url': 'https://example.org/page',
                  'email': 'john@domain.com', 'username': 'lab_user', 'hash': 'a' * 64, 'phone': '+5511999999999'}
        for ident, spec in osint.CATALOG.items():
            for kind in spec['types']:
                with self.subTest(source=ident, kind=kind):
                    result = osint.plan(ident, kind, values[kind])
                    self.assertIn(result['request']['method'], ('GET', 'POST'))
                    osint.check_destination(result['request']['url'], spec)
                    if kind in {'email', 'phone', 'username'}:
                        self.assertNotIn(values[kind], json.dumps(result))
        self.open.assert_not_called()

    def test_query_without_confirmation_blocks_first(self):
        with self.assertRaisesRegex(osint.PolicyError, '^CONFIRM_REQUIRED$'):
            osint.query('openarchive', 'email', 'john@domain.com', 'audit')
        self.open.assert_not_called()

    def test_broker_needs_env_and_eight_character_purpose(self):
        for ident in ('dehashed', 'leakcheck', 'intelligencex', 'openarchive'):
            with self.subTest(source=ident):
                with self.assertRaisesRegex(osint.PolicyError, '^BROKER_BLOCKED$'):
                    osint.query(ident, 'email', 'john@domain.com', 'personal audit', allow_send=True, subject='self')
        self.permit()
        with self.assertRaisesRegex(osint.PolicyError, '^BROKER_BLOCKED$'):
            osint.query('openarchive', 'email', 'john@domain.com', 'short', allow_send=True, subject='self')
        self.open.assert_not_called()

    def test_email_without_subject_blocks_before_key_or_network(self):
        with self.assertRaisesRegex(osint.PolicyError, '^SUBJECT_REQUIRED$'):
            osint.query('haveibeenpwned', 'email', 'john@domain.com', 'self audit', allow_send=True)
        self.permit('OPENARCHIVE')
        with self.assertRaisesRegex(osint.PolicyError, '^SUBJECT_REQUIRED$'):
            osint.query('openarchive', 'phone', '+5511999999999', 'self audit', allow_send=True)
        self.open.assert_not_called()

    def test_name_and_openarchive_non_pii_selectors_require_subject(self):
        self.permit('OPENARCHIVE')
        for kind, value in (('name', 'John Doe'), ('domain', 'example.org')):
            with self.assertRaisesRegex(osint.PolicyError, '^SUBJECT_REQUIRED$'):
                osint.enforce('openarchive', kind, value, 'self lab research', None, True)
        self.open.assert_not_called()

    def test_masking_query_purpose_response_and_credentials(self):
        self.assertEqual(osint.mask_value('email', 'john@domain.com'), 'jo***@do***.com')
        self.assertEqual(osint.mask_value('phone', '+5511999999999'), '+55**...')
        value = {'query': 'john@domain.com', 'purpose': 'Check john@domain.com',
                 'response': {'name': 'John Doe', 'phone': '+5511999999999',
                              'password': 'must-not-print', 'url': 'https://example.org/john%40domain.com'},
                 'key': 'opaque-key', 'echo': 'secret-value'}
        result = json.dumps(osint.sanitize(value, 'email', 'john@domain.com', secrets=['secret-value']))
        for forbidden in ('john@domain.com', 'John Doe', '+5511999999999', 'must-not-print', 'opaque-key', 'secret-value'):
            self.assertNotIn(forbidden, result)

    def test_host_scheme_port_credentials_and_fragment_are_rejected(self):
        spec = osint.CATALOG['crt.sh']
        for url in ('https://other.example/', 'https://crt.sh.evil.example/', 'http://crt.sh/',
                    'https://user:pass@crt.sh/', 'https://crt.sh:8443/', 'https://crt.sh/#x'):
            with self.subTest(url=url), self.assertRaisesRegex(osint.PolicyError, '^HOST_BLOCKED$'):
                osint.check_destination(url, spec)
        with self.assertRaisesRegex(osint.PolicyError, '^HOST_BLOCKED$'):
            osint.transmit({'url': 'https://other.example/', 'method': 'GET', 'headers': {}, 'body': None}, spec)
        self.open.assert_not_called()

    def test_confirmed_mock_request_writes_masked_report_with_warning(self):
        self.permit()
        response = self.respond('https://haveibeenpwned.com/api/v3/breachedaccount/john%40domain.com',
                                {'email': 'john@domain.com', 'password': 'secret-returned-password'})
        result = osint.query('haveibeenpwned', 'email', 'john@domain.com', 'self audit john@domain.com',
                             allow_send=True, subject='self')
        self.open.assert_called_once()
        self.assertTrue(response.closed)
        request = self.open.call_args.args[0]
        self.assertIn('john%40domain.com', request.full_url)  # Actual wire selector stays literal.
        self.assertEqual(self.open.call_args.kwargs['timeout'], 15)
        self.assertEqual(result['notice'], 'unverified_lead_not_evidence')
        self.assertFalse(result['rag_eligible'])
        path = Path(result['report'])
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        log = json.loads(path.read_text())
        self.assertEqual(log['query']['value'], 'jo***@do***.com')
        for text in (json.dumps(result), path.read_text()):
            self.assertNotIn('john@domain.com', text)
            self.assertNotIn('secret-returned-password', text)
            self.assertNotIn('dummy-fixture-key-only', text)
        self.assertEqual(log['status'], 200)
        self.assertIn('elapsed', log)
        self.assertIn('never imported into RAG', log['policy'])

    def test_reveal_only_affects_stdout_log_remains_masked_and_secrets_hidden(self):
        self.permit()
        self.respond('https://haveibeenpwned.com/', {'email': 'john@domain.com', 'echo': 'dummy-fixture-key-only'})
        result = osint.query('hibp', 'email', 'john@domain.com', 'self audit',
                             allow_send=True, subject='self', reveal=True)
        self.assertEqual(result['query']['value'], 'john@domain.com')
        self.assertEqual(result['response']['email'], 'john@domain.com')
        self.assertNotIn('dummy-fixture-key-only', json.dumps(result))
        self.assertNotIn('john@domain.com', Path(result['report']).read_text())

    def test_429_is_saved_no_retry_and_cooldown_applies_to_next_call(self):
        self.respond('https://crt.sh/', {'error': 'slow down'}, 429, {'Retry-After': '60'})
        result = osint.query('crt.sh', 'domain', 'example.org', 'lab audit', allow_send=True)
        self.assertEqual(result['error_code'], 'RATE_LIMITED')
        self.assertEqual(result['retry_after']['seconds'], 60)
        self.open.assert_called_once()
        with self.assertRaisesRegex(osint.PolicyError, '^RETRY_AFTER_ACTIVE$'):
            osint.query('crt.sh', 'domain', 'example.org', 'lab audit', allow_send=True)
        self.open.assert_called_once()
        self.assertEqual(len(list(self.reports.glob('*.json'))), 1)

    def test_retry_after_http_date_and_invalid_value(self):
        stamp = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=120)).strftime('%a, %d %b %Y %H:%M:%S GMT')
        self.assertGreater(osint.retry_after(stamp)['seconds'], 110)
        self.assertIsNone(osint.retry_after('not a date'))

    def test_http_error_body_is_closed_and_reported(self):
        body = io.BytesIO(b'{"error":"access denied"}')
        error = urllib.error.HTTPError('https://crt.sh/', 403, 'Forbidden', {}, body)
        self.open.side_effect = error
        result = osint.query('crt.sh', 'domain', 'example.org', 'lab audit', allow_send=True)
        self.assertTrue(body.closed)
        self.assertEqual(result['status'], 403)
        self.assertEqual(result['error_code'], 'HTTP_ERROR')
        self.assertTrue(Path(result['report']).exists())
        self.open.assert_called_once()

    def test_redirect_handler_closes_response_and_never_follows(self):
        fp = io.BytesIO()
        for target in ('https://crt.sh/other', 'https://other.example/', 'http://crt.sh/'):
            with self.subTest(target=target):
                fp = io.BytesIO()
                with self.assertRaisesRegex(osint.PolicyError, '^REDIRECT_BLOCKED$'):
                    osint.NoRedirect().redirect_request(urllib.request.Request('https://crt.sh/'), fp, 302, '', {}, target)
                self.assertTrue(fp.closed)
        self.open.assert_not_called()

    def test_follow_redirects_flag_only_on_rdap(self):
        for ident, spec in osint.CATALOG.items():
            with self.subTest(ident=ident):
                self.assertEqual(bool(spec['follow_redirects']), ident == 'rdap.org')

    def test_follow_handler_allows_https_capped_and_carries_request(self):
        handler = osint.FollowRedirect()
        fp = io.BytesIO()
        req = urllib.request.Request('https://rdap.org/domain/example.com')
        nxt = handler.redirect_request(req, fp, 302, 'Found', {},
                                       'https://rdap.verisign.com/com/v1/domain/example.com')
        self.assertEqual(nxt.full_url, 'https://rdap.verisign.com/com/v1/domain/example.com')
        self.assertTrue(fp.closed)
        with self.assertRaisesRegex(osint.PolicyError, '^REDIRECT_LOOP$'):
            for _ in range(osint.FollowRedirect.MAX_HOPS + 1):
                handler.redirect_request(req, io.BytesIO(), 302, '', {}, 'https://example.net/next')

    def test_follow_handler_blocks_non_https_and_credentials(self):
        handler = osint.FollowRedirect()
        for bad in ('http://example.com/x', 'https://user:pass@example.com/x', 'https://example.com/x#frag'):
            with self.subTest(url=bad), self.assertRaisesRegex(osint.PolicyError, '^HOST_BLOCKED$'):
                handler.redirect_request(urllib.request.Request('https://rdap.org/x'), io.BytesIO(), 302, '', {}, bad)

    def test_check_destination_relaxed_only_when_follow(self):
        follow_spec = {'base_url': 'https://rdap.org', 'follow_redirects': True}
        strict_spec = {'base_url': 'https://rdap.org', 'follow_redirects': False}
        osint.check_destination('https://rdap.verisign.com/com/v1/domain/example.com', follow_spec)
        with self.assertRaisesRegex(osint.PolicyError, '^HOST_BLOCKED$'):
            osint.check_destination('https://rdap.verisign.com/com/v1/domain/example.com', strict_spec)
        with self.assertRaisesRegex(osint.PolicyError, '^HOST_BLOCKED$'):
            osint.check_destination('http://rdap.verisign.com/x', follow_spec)


    def test_response_changed_host_is_not_read(self):
        response = self.respond('https://other.example/', {'email': 'private@domain.com'})
        result = osint.query('crt.sh', 'domain', 'example.org', 'lab audit', allow_send=True)
        self.assertTrue(response.closed)
        self.assertEqual(result['error_code'], 'HOST_BLOCKED')
        self.assertIsNone(result['response'])
        self.open.assert_called_once()

    def test_ping_only_designated_public_health_no_keys(self):
        for source in ('virustotal', 'crt.sh', 'telegram-manual', 'openarchive'):
            with self.assertRaisesRegex(osint.PolicyError, '^HEALTH_UNAVAILABLE$'):
                osint.ping(source)
        response = self.respond('https://status.openarchivex.net/', {'status': 'ok'})
        result = osint.ping('status.openarchivex.net')
        self.assertEqual(result['status'], 200)
        self.assertTrue(response.closed)
        self.open.assert_called_once()
        self.assertEqual(self.open.call_args.args[0].full_url, 'https://status.openarchivex.net/')
        self.assertNotIn('Authorization', self.open.call_args.args[0].headers)

    def test_manual_health_only_bad_type_invalid_value_and_missing_keys_block(self):
        for ident, kind, value, error in (
            ('telegram-manual', 'username', 'lab_user', 'MANUAL_ONLY'),
            ('openarchive-status', 'domain', 'example.org', 'HEALTH_ONLY'),
            ('crt.sh', 'email', 'john@domain.com', 'TYPE_UNSUPPORTED'),
            ('shodan', 'ip', 'not-an-ip', 'INVALID_VALUE'),
            ('shodan', 'ip', '192.0.2.1', 'KEY_REQUIRED')):
            with self.subTest(source=ident), self.assertRaisesRegex(osint.PolicyError, '^' + error + '$'):
                osint.query(ident, kind, value, 'lab audit', allow_send=True, subject='self')
        self.open.assert_not_called()

    def test_cli_error_is_fixed_code_never_selector_or_exception(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = osint.main(['query', 'hibp', '--type', 'email', '--value', 'john@domain.com', '--purpose', 'self audit'])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(output.getvalue())['error_code'], 'CONFIRM_REQUIRED')
        self.assertNotIn('john@domain.com', output.getvalue())
        self.open.assert_not_called()


    def test_extended_sources_register_and_never_echo_keys(self):
        expected = {'censys-platform', 'otx', 'fofa', 'zoomeye', 'leakix', 'ipinfo',
                    'abuseipdb', 'whoisxmlapi', 'bevigil', 'github'}
        self.assertTrue(expected <= osint.CATALOG.keys())
        for ident in expected:
            self.assertTrue(osint.CATALOG[ident]['keys'])
            self.assertEqual(osint.resolve(ident)[0], ident)
        self.assertEqual(osint.resolve('alienvault')[0], 'otx')
        os.environ['MITR3_OSINT_FOFA_KEY'] = 'fofa-fixture-key'
        listing = osint.sources()
        self.assertTrue(next(r for r in listing if r['id'] == 'fofa')['key_configured'])
        self.assertNotIn('fofa-fixture-key', json.dumps(listing))

    def test_extended_requests_place_auth_correctly_and_redact(self):
        cases = (
            ('censys-platform', 'domain', 'example.org', 'POST',
             'https://api.platform.censys.io/v3/global/search/query', 'Authorization', 'Bearer '),
            ('zoomeye', 'ip', '192.0.2.1', 'POST', 'https://api.zoomeye.ai/v2/search', 'API-KEY', ''),
            ('leakix', 'domain', 'example.org', 'GET', 'https://leakix.net/search', 'api-key', ''),
            ('abuseipdb', 'ip', '192.0.2.1', 'GET', 'https://api.abuseipdb.com/api/v2/check', 'Key', ''),
            ('bevigil', 'domain', 'example.org', 'GET',
             'https://osint.bevigil.com/api/example.org/subdomains/', 'X-Access-Token', ''),
        )
        for ident, kind, value, method, url, header, prefix in cases:
            with self.subTest(source=ident):
                for name, _ in osint.CATALOG[ident]['keys']:
                    os.environ[name] = 'fixture-' + ident
                self.respond(url, {'ok': True})
                result = osint.query(ident, kind, value, 'authorized lab validation', allow_send=True)
                request = self.open.call_args.args[0]
                self.assertEqual(request.get_method(), method)
                self.assertTrue(request.full_url.startswith(url))
                sent = {name.lower(): value for name, value in request.headers.items()}
                self.assertEqual(sent[header.lower()], prefix + 'fixture-' + ident)
                self.assertNotIn('fixture-' + ident, json.dumps(result))
                self.assertNotIn('fixture-' + ident, Path(result['report']).read_text())
                self.open.reset_mock()


if __name__ == '__main__':
    unittest.main()
