"""Offline HackerOne fixtures only: never real credentials or network."""
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock
from urllib.error import HTTPError

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('h1',ROOT/'bin/mitr3-h1.py')
H=importlib.util.module_from_spec(spec);spec.loader.exec_module(H)
FIX=ROOT/'tests/fixtures/h1'


def fixture(name):return json.loads((FIX/name).read_bytes())


class Response(io.BytesIO):
    status=200
    def __init__(self,obj,url='https://api.hackerone.com/v1/hackers/programs/public-dev/structured_scopes'):
        super().__init__(json.dumps(obj).encode());self.url=url
    def geturl(self):return self.url


class H1Tests(unittest.TestCase):
    def setUp(self):
        self.opener=mock.Mock()
        self.client=H.Client('synthetic-user','SYNTHETIC-SECRET-CANARY',self.opener)

    def snapshot(self,obj=None):
        self.opener.open.return_value=Response(obj or fixture('scopes-before.json'))
        return self.client.fetch('scopes','public-dev')

    def report(self):return fixture('report.json')

    def test_get_only_and_auth_not_persisted(self):
        out=self.snapshot()
        request=self.opener.open.call_args.args[0]
        self.assertEqual(request.get_method(),'GET')
        self.assertIsNone(request.data)
        self.assertTrue(request.get_header('Authorization').startswith('Basic '))
        self.assertEqual(self.opener.open.call_args.kwargs,{'timeout':15})
        for marker in ['SYNTHETIC-SECRET-CANARY','Authorization','Basic ']:self.assertNotIn(marker,json.dumps(out))
        self.assertEqual(out['sha256'],H.sha({k:v for k,v in out.items() if k!='sha256'}))

    def test_program_listing_and_detail_routes(self):
        self.opener.open.return_value=Response(fixture('programs.json'),'https://api.hackerone.com/v1/hackers/programs')
        self.assertEqual(len(self.client.fetch('programs')['data']),1)
        obj={'data':fixture('programs.json')['data'][0]}
        self.opener.open.return_value=Response(obj,'https://api.hackerone.com/v1/hackers/programs/public-dev')
        self.assertEqual(self.client.fetch('program','public-dev')['data'][0]['id'],'dev-1')

    def test_scope_exclusions_get(self):
        self.opener.open.return_value=Response({'data':[]},'https://api.hackerone.com/v1/hackers/programs/public-dev/scope_exclusions')
        self.assertEqual(self.client.fetch('exclusions','public-dev')['data'],[])

    def test_paginated_scopes_all_pages(self):
        first=fixture('scopes-before.json');second={'data':[first['data'].pop()],'links':{}}
        first['links']['next']='/v1/hackers/programs/public-dev/structured_scopes?page%5Bnumber%5D=2'
        self.opener.open.side_effect=[Response(first),Response(second)]
        out=self.client.fetch('scopes','public-dev')
        self.assertEqual(len(out['data']),2)
        self.assertEqual(len(out['pages_sha256']),2)

    def test_disallowed_urls_before_request(self):
        for url in ['http://api.hackerone.com/v1/hackers/programs','https://evil.test/v1/hackers/programs',
                    'https://api.hackerone.com:443/v1/hackers/programs','https://api.hackerone.com/v1/reports',
                    'https://api.hackerone.com/v1/hackers/programs?token=canary','https://api.hackerone.com/v1/hackers/programs#fragment']:
            with self.subTest(url=url),self.assertRaises(H.H1Error):self.client.get(url)
        self.opener.open.assert_not_called()

    def test_malicious_pagination_and_endpoint_switch_blocked(self):
        for next_url in ['https://evil.test/steal','/v1/hackers/programs/other/structured_scopes','/v1/hackers/me/reports']:
            obj=fixture('scopes-before.json');obj['links']['next']=next_url
            self.opener.open.reset_mock();self.opener.open.return_value=Response(obj)
            with self.assertRaises(H.H1Error):self.client.fetch('scopes','public-dev')
            self.assertEqual(self.opener.open.call_count,1)

    def test_redirects_blocked(self):
        with self.assertRaises(H.H1Error):H.NoRedirect().redirect_request(None,None,None,None,None,None)
        self.opener.open.return_value=Response({'data':[]},'https://evil.test/steal')
        with self.assertRaises(H.H1Error):self.client.fetch('scopes','public-dev')

    def test_redirect_closes_response_without_following(self):
        for code in (301,302,303,307,308):
            fp=io.BytesIO(b'private redirect body')
            with self.assertRaises(H.H1Error):
                getattr(H.NoRedirect(),'http_error_'+str(code))(None,fp,code,'redirect',{})
            self.assertTrue(fp.closed)

    def test_rate_limit_no_retry_no_response_body_leak(self):
        error=HTTPError('https://api.hackerone.com/',429,'CANARY',{'Retry-After':'120'},io.BytesIO(b'PRIVATE_BODY'))
        self.opener.open.side_effect=error
        with self.assertRaises(H.H1Error) as exc:self.client.fetch('scopes','public-dev')
        self.assertEqual(exc.exception.code,'HTTP_429')
        self.assertEqual(exc.exception.retry_after,120)
        self.assertNotIn('PRIVATE_BODY',str(exc.exception))
        self.assertEqual(self.opener.open.call_count,1)
        self.assertTrue(error.fp.closed)

    def test_size_caps_pagination_limit_and_token_echo(self):
        self.opener.open.return_value=Response({'data':['x'*100]})
        with mock.patch.object(H,'BYTE_LIMIT',20),self.assertRaises(H.H1Error):self.client.fetch('scopes','public-dev')
        obj=fixture('scopes-before.json');obj['links']['next']='/v1/hackers/programs/public-dev/structured_scopes'
        self.opener.open.return_value=Response(obj)
        with self.assertRaises(H.H1Error):self.client.fetch('scopes','public-dev')
        self.opener.open.return_value=Response({'data':[],'echo':'SYNTHETIC-SECRET-CANARY'})
        with self.assertRaises(H.H1Error) as exc:self.client.fetch('scopes','public-dev')
        self.assertEqual(exc.exception.code,'CREDENTIAL_ECHO_BLOCKED')

    def test_credentials_formats_without_real_token_file(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/'token';path.touch(mode=0o600)
            for contents in ['synthetic-user:SYNTHETIC-CREDENTIAL',json.dumps({'username':'synthetic-user','token':'SYNTHETIC-CREDENTIAL'}),'SYNTHETIC-CREDENTIAL']:
                path.write_text(contents)
                with mock.patch.dict(os.environ,{'MITR3_H1_USERNAME':'synthetic-user'}):
                    self.assertEqual(H.credentials(path),('synthetic-user','SYNTHETIC-CREDENTIAL'))
            path.chmod(0o644)
            with self.assertRaises(H.H1Error):H.credentials(path)
            link=Path(td)/'link';link.symlink_to(path)
            with self.assertRaises(H.H1Error):H.credentials(link)

    def test_missing_username_and_duplicate_json_fail(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/'token';path.write_text('SYNTHETIC-CREDENTIAL');path.chmod(0o600)
            with mock.patch.dict(os.environ,{},clear=True),self.assertRaises(H.H1Error):H.credentials(path)
        with self.assertRaises(H.H1Error):H.strict_json('{"token":1,"token":2}')

    def test_scope_diff_added_removed_changed_and_hashes(self):
        before=self.snapshot();after=self.snapshot(fixture('scopes-after.json'))
        out=H.scope_diff(before,after)
        self.assertEqual([r['id'] for r in out['added']],['3'])
        self.assertEqual([r['id'] for r in out['removed']],['2'])
        self.assertEqual([r['id'] for r in out['changed']],['1'])
        self.assertFalse(out['changed'][0]['after']['attributes']['eligible_for_submission'])
        self.assertEqual(out['sha256'],H.sha({k:v for k,v in out.items() if k!='sha256'}))

    def test_scope_order_dedup_and_conflicts(self):
        obj=fixture('scopes-before.json');a=self.snapshot(obj)
        obj['data'].reverse();obj['data'].append(copy.deepcopy(obj['data'][0]));b=self.snapshot(obj)
        self.assertEqual(a['scope_sha256'],b['scope_sha256'])
        out=H.scope_diff(a,b)
        self.assertEqual([len(out[k]) for k in ['added','removed','changed']],[0,0,0])
        obj['data'][-1]['attributes']['eligible_for_submission']=False
        with self.assertRaises(H.H1Error):self.snapshot(obj)

    def test_snapshot_tamper_and_program_mismatch(self):
        a=self.snapshot();b=copy.deepcopy(a);b['data'][0]['attributes']['asset_identifier']='changed'
        with self.assertRaises(H.H1Error):H.scope_diff(a,b)
        b=copy.deepcopy(a);b['program']='other';b['sha256']=H.sha({k:v for k,v in b.items() if k!='sha256'})
        with self.assertRaises(H.H1Error):H.scope_diff(a,b)

    def test_valid_report_and_template_is_incomplete(self):
        self.assertTrue(H.validate_report(self.report())['valid'])
        self.assertFalse(H.validate_report(H.template('public-dev'))['valid'])
        self.assertFalse(H.validate_report(self.report())['submission_implemented'])

    def test_required_fields_and_evidence_metadata(self):
        for key in H.template():
            r=self.report();r.pop(key)
            with self.subTest(field=key):self.assertFalse(H.validate_report(r)['valid'])
        for field,value in [('redacted',False),('at_utc','2026-10-20T12:00:00'),('sha256','bad')]:
            r=self.report();r['evidence'][0][field]=value
            self.assertFalse(H.validate_report(r)['valid'])

    def test_redaction_flag_not_sufficient(self):
        for text in ['Authorization: Bearer CANARY','Cookie: session=CANARY','Set-Cookie: session=CANARY',
                     'person@example.test','access_token=CANARY','password=CANARY','+55 11 99999-1111',
                     '"authorization":"Bearer CANARY"','session=CANARY']:
            r=self.report();r['evidence'][0]['request']=text
            self.assertIn('SENSITIVE_CONTENT',H.validate_report(r)['errors'])
        self.assertFalse(H.unsafe('Authorization: [REDACTED]\nCookie: [REDACTED:COOKIE]'))

    def test_redacted_evidence_hash_binding(self):
        r=self.report();r['evidence'][0]['response']+=' modified'
        self.assertIn('EVIDENCE_HASH_MISMATCH',H.validate_report(r)['errors'])

    def test_cvss_vectors_and_base_scores(self):
        for vector,expected in [('AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',9.8),
                                ('AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H',8.8),
                                ('AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H',9.9),
                                ('AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H',7.2),
                                ('AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N',0)]:
            self.assertEqual(H.cvss31('CVSS:3.1/'+vector)[0],expected)
        for vector in ['CVSS:3.0/AV:N','CVSS:3.1/AV:N','CVSS:3.1/AV:N/AV:N',
                       self.report()['cvss']['vector']+'/ZZ:X',self.report()['cvss']['vector'].replace('AC:L','AC:Z')]:
            with self.assertRaises(H.H1Error):H.cvss31(vector)

    def test_optional_cvss_metrics_and_nonstandard_order(self):
        base=self.report()['cvss']['vector']
        self.assertEqual(H.cvss31(base+'/E:F/RL:X/RC:C/CR:H/MS:C')[0],9.8)
        reordered='CVSS:3.1/'+ '/'.join(reversed(base.split('/')[1:]))
        self.assertEqual(H.cvss31(reordered)[0],9.8)
        with self.assertRaises(H.H1Error):H.cvss31(base+'/E:Z')

    def test_inconsistent_score_and_meli_test_user_rule(self):
        r=self.report();r['cvss']['base_score']=1
        self.assertIn('CVSS_SCORE_MISMATCH',H.validate_report(r)['errors'])
        r=self.report();r.update(program='mercadolibre',test_users=True)
        self.assertIn('MELI_TEST_USERS_PR_HIGH',H.validate_report(r)['errors'])
        r['cvss']['vector']=r['cvss']['vector'].replace('PR:N','PR:H');r['cvss']['base_score']=7.2
        self.assertTrue(H.validate_report(r)['valid'])

    def test_optional_scope_validation_exact_declared_asset_and_hash(self):
        scope=self.snapshot();r=self.report();r['policy']['scope_sha256']=scope['scope_sha256']
        self.assertTrue(H.validate_report(r,scope)['valid'])
        r['asset']['identifier']='https://invented.example.test'
        self.assertIn('ASSET_NOT_DECLARED_ELIGIBLE',H.validate_report(r,scope)['errors'])
        r=self.report();self.assertIn('SCOPE_HASH_MISMATCH',H.validate_report(r,scope)['errors'])

    def test_private_output_mode_no_overwrite_and_git_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'scope.json';sha=H.save(p,{'synthetic':True})
            self.assertEqual(sha,hashlib.sha256(p.read_bytes()).hexdigest())
            self.assertEqual(stat.S_IMODE(p.stat().st_mode),0o600)
            with self.assertRaises(H.H1Error):H.save(p,{'twice':True})
        with self.assertRaises(H.H1Error):H.save(ROOT/'reports/private-h1.json',{})

    def test_local_commands_never_load_credentials_or_network(self):
        with mock.patch.object(H,'credentials',side_effect=AssertionError('no real credentials')),mock.patch.object(H,'Client',side_effect=AssertionError('no network')):
            with mock.patch('sys.stdout',new_callable=io.StringIO):
                self.assertEqual(H.main(['validate',str(FIX/'report.json')]),0)
                self.assertEqual(H.main(['template']),0)

    def test_no_submit_route(self):
        with mock.patch('sys.stderr',new_callable=io.StringIO),self.assertRaises(SystemExit):H.main(['submit'])
        with self.assertRaises(H.H1Error):self.client.fetch('submit','public-dev')
        self.opener.open.assert_not_called()

    def test_failure_output_does_not_print_secret_or_private_response(self):
        with tempfile.TemporaryDirectory() as td:
            out=Path(td)/'new.json'
            with mock.patch.object(H,'credentials',side_effect=RuntimeError('SECRET_PRIVATE_BODY')),mock.patch('sys.stdout',new_callable=io.StringIO) as stdout:
                self.assertEqual(H.main(['scopes','public-dev','--output',str(out)]),1)
            self.assertNotIn('SECRET_PRIVATE_BODY',stdout.getvalue())
            self.assertFalse(out.exists())


if __name__=='__main__':unittest.main()
