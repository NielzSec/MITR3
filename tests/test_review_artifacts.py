"""Offline escrow tests, using only our synthetic public DEV fixture."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('review_candidate_runner',ROOT/'bin/mitr3-candidate-run.py')
R=importlib.util.module_from_spec(spec);spec.loader.exec_module(R)
E=R.REVIEW


class ReviewArtifactTests(unittest.TestCase):
    def demo(self,path):
        report=R.dev_demo(path)
        finals=[json.loads(p.read_bytes()) for p in path.glob('*-final.json')]
        return report,finals

    def test_both_arms_have_readable_true_and_false_claims_after_run(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/'private'
            report,finals=self.demo(path)
            self.assertEqual(len(finals),4)
            for arm in R.ARMS:
                values=[v for v in finals if v['arm']==arm]
                self.assertEqual(len(values),2)
                texts=[v['claims'][0]['text'] for v in values]
                self.assertTrue(any('HTTP 200' in text for text in texts))
                self.assertTrue(any('control service is alive' in text for text in texts))
                for v in values:
                    self.assertTrue(v['question'])
                    self.assertEqual(v['gate']['verdict'],'accepted')
                    self.assertEqual(v['gate']['error'],None)
                    cite=v['claims'][0]['citations'][0]
                    doc=next(d for d in v['package'] if d['id']==cite['id'])
                    self.assertIn(cite['quote'],doc['snippet'])
                    self.assertIn('not tested',doc['snippet'])
                    self.assertEqual(len(doc['sha256']),64)
                    self.assertTrue(doc['source_url'].startswith('https://'))
                    self.assertEqual(v['evidence_package_sha256'],E.digest(v['package']))
            self.assertTrue(E.verify(path,report['private_manifest_sha256'],report)['review_ready'])

    def test_public_report_contains_only_hashes_and_metadata(self):
        with tempfile.TemporaryDirectory() as td:
            report,_=self.demo(Path(td)/'private')
        raw=json.dumps(report)
        for marker in ['What does','control service is alive','the panel returned','example.org/dev-review',td,
                       'expected_answer','expected_ids','forbidden_ids','rubric']:
            self.assertNotIn(marker,raw)
        self.assertTrue(all(len(r['private_artifacts'][0]['artifact_sha256'])==64 for r in report['rows']))

    def test_files_0600_directory_0700_manifest_matches_every_file(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/'private';report,_=self.demo(path)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode),0o700)
            manifest=json.loads((path/'manifest.json').read_bytes())
            self.assertEqual(len(manifest['files']),len(list(path.iterdir()))-1)
            for entry in manifest['files']:
                file=path/entry['file']
                self.assertEqual(stat.S_IMODE(file.stat().st_mode),0o600)
                self.assertEqual(entry['sha256'],hashlib.sha256(file.read_bytes()).hexdigest())
            self.assertEqual(stat.S_IMODE((path/'manifest.json').stat().st_mode),0o600)
            self.assertEqual(report['private_manifest_sha256'],hashlib.sha256((path/'manifest.json').read_bytes()).hexdigest())

    def test_git_tree_rejected_even_if_ignored(self):
        for path in [ROOT/'reports/private-review-test',ROOT/'state/private-review-test']:
            with self.assertRaises(E.EscrowError):E.Store(path)
            self.assertFalse(path.exists())
        with tempfile.TemporaryDirectory() as td:
            repo=Path(td)/'other-repo';repo.mkdir();(repo/'.git').mkdir()
            with self.assertRaises(E.EscrowError):E.Store(repo/'private')

    def test_artifacts_outside_git_cannot_be_added(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/'private';self.demo(path)
            file=next(path.glob('*-final.json'))
            p=subprocess.run(['git','add','--',str(file)],cwd=ROOT,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            self.assertNotEqual(p.returncode,0)

    def test_no_overwrite_directory_or_file_or_manifest(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/'private';store=E.Store(path)
            with self.assertRaises(FileExistsError):E.Store(path)
            name='a'*24+'-0000.json'
            store.write(name,{'once':1});before=(path/name).read_bytes()
            with self.assertRaises(FileExistsError):store.write(name,{'twice':2})
            self.assertEqual((path/name).read_bytes(),before)
            store.manifest()
            with self.assertRaises(E.EscrowError):store.manifest()

    def test_gold_values_never_persisted_from_projected_set_both_arms(self):
        with tempfile.TemporaryDirectory() as td:
            base=Path(td);source=base/'dev-input.json'
            source.write_text(json.dumps([{'id':f'dev-{i}','question':f'Public DEV question {i}',
                'expected_answer':'GOLD_CANARY','expected_ids':['GOLD_ID_CANARY'],
                'forbidden_ids':['GOLD_FORBIDDEN_CANARY'],'rubric':{'secret':'GOLD_RUBRIC_CANARY'}} for i in range(10)]))
            for arm in R.ARMS:
                path=base/arm
                R.run_set(source,arm,private_dir=path,call_fn=lambda *args:R.BLIND.failed('MODEL_ABSTAIN'))
                for file in path.iterdir():
                    raw=file.read_text()
                    for marker in ['GOLD_','expected_answer','expected_ids','forbidden_ids','rubric']:
                        self.assertNotIn(marker,raw)

    def test_minimization_excludes_extra_model_fields(self):
        obj={'claims':[{'text':'Public claim','citations':[{'id':'CASE-dev','quote':'Public quote','expected_ids':['CANARY']}],
                       'expected_answer':'CANARY'}],'forbidden_ids':['CANARY']}
        self.assertNotIn('CANARY',json.dumps(E.claims_view(obj)))
        self.assertNotIn('expected_',json.dumps(E.claims_view(obj)))

    def test_sensitive_data_redacted_and_review_not_shareable(self):
        with tempfile.TemporaryDirectory() as td:
            store=E.Store(Path(td)/'private');token='a'*24
            value=E.new_review('Contact person@example.org; password=canary','baseline',R.DEFAULT_MODEL,'dev')
            store.write(token+'-0000.json',E.snapshot(value))
            ref=store.finish(token,value,'NO_EVIDENCE',True)
            sha=store.manifest()
            self.assertTrue(ref['redacted'])
            self.assertFalse(E.verify(store.path,sha)['review_ready'])
            for p in store.path.iterdir():
                self.assertNotIn('person@example.org',p.read_text())
                self.assertNotIn('password=canary',p.read_text())

    def test_tampered_file_manifest_and_public_reference_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/'private';report,_=self.demo(path)
            with self.assertRaises(E.EscrowError):E.verify(path,'0'*64)
            changed=copy.deepcopy(report);changed['rows'][0]['private_artifacts'][0]['artifact_sha256']='0'*64
            with self.assertRaises(E.EscrowError):E.verify(path,report['private_manifest_sha256'],changed)
            file=next(path.glob('*-final.json'));file.write_bytes(file.read_bytes()+b' ')
            with self.assertRaises(E.EscrowError):E.verify(path,report['private_manifest_sha256'])

    def test_wrong_permissions_symlinks_unlisted_files_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            base=Path(td);path=base/'private';report,_=self.demo(path)
            file=next(path.glob('*-final.json'));file.chmod(0o644)
            with self.assertRaises(E.EscrowError):E.verify(path,report['private_manifest_sha256'])
            file.chmod(0o600);(path/'unlisted').write_text('public')
            with self.assertRaises(E.EscrowError):E.verify(path,report['private_manifest_sha256'])
            link=base/'link';link.symlink_to(path,target_is_directory=True)
            with self.assertRaises(E.EscrowError):E.Store(link,create=False)

    def test_rejected_final_quote_remains_reviewable(self):
        case=json.loads((ROOT/'tests/fixtures/review-artifacts-dev-v1.json').read_bytes())[0]
        for arm in R.ARMS:
            with tempfile.TemporaryDirectory() as td:
                store=E.Store(Path(td)/'private');token='a'*24
                review=E.new_review(case['question'],arm,R.DEFAULT_MODEL,'dev')
                composition=copy.deepcopy(case['composition']);composition['claims'][0]['citations'][0]['quote']='invented quote'
                outputs=iter([case['plan']]+([case['extract']] if arm=='candidate' else [])+[composition])
                out,_=R.pipeline(case['question'],arm,model_fn=lambda *args:next(outputs),retrieve_fn=lambda *args:case['documents'],
                                 review=review,checkpoint=store.checkpoint(token))
                store.finish(token,review,out['error_code'],out['abstain']);sha=store.manifest()
                value=json.loads((store.path/(token+'-final.json')).read_bytes())
                self.assertEqual(value['gate']['verdict'],'blocked')
                self.assertEqual(value['gate']['error'],'QUOTE_NOT_LITERAL')
                self.assertEqual(value['claims'][0]['citations'][0]['quote'],'invented quote')
                self.assertTrue(E.verify(store.path,sha)['verified'])

    def worker_script(self,path,hang=False):
        source='''import importlib.util,json,sys,time,argparse
from pathlib import Path
root=Path(ROOT_LITERAL)
spec=importlib.util.spec_from_file_location('worker_runner',root/'bin/mitr3-candidate-run.py')
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)
p=argparse.ArgumentParser();p.add_argument('--arm');p.add_argument('--model');p.add_argument('--private-dir');p.add_argument('--_token');p.add_argument('--_item-id');p.add_argument('--_worker',action='store_true');a=p.parse_args()
q=json.loads(sys.stdin.read())['question']
case=json.loads((root/'tests/fixtures/review-artifacts-dev-v1.json').read_bytes())[0]
outputs=iter([case['plan']]+([case['extract']] if a.arm=='candidate' else [])+[case['composition']])
count=0
def model(*args):
 global count
 count+=1
 if HANG_LITERAL and count==2:time.sleep(30)
 return next(outputs)
review=r.REVIEW.new_review(q,a.arm,a.model,a._item_id)
store=r.REVIEW.Store(a.private_dir,create=False)
value,stage=r.pipeline(q,a.arm,a.model,model_fn=model,retrieve_fn=lambda *args:case['documents'],review=review,checkpoint=store.checkpoint(a._token))
print(json.dumps({'result':value,'stages':stage}))
'''
        path.write_text(source.replace('ROOT_LITERAL',repr(str(ROOT))).replace('HANG_LITERAL',repr(hang)))

    def test_real_parent_worker_protocol_both_arms_offline(self):
        with tempfile.TemporaryDirectory() as td:
            base=Path(td);script=base/'worker.py';self.worker_script(script)
            for arm in R.ARMS:
                store=E.Store(base/arm)
                with mock.patch.object(R,'SELF',script):
                    row=R.run_item({'id':'dev','question':'Public lab question'},R.DEFAULT_MODEL,3,arm,private_store=store)
                self.assertEqual(row['category'],'answered_gate')
                sha=store.manifest()
                self.assertTrue(E.verify(store.path,sha)['review_ready'])

    def test_timeout_preserves_transmitted_window_and_records_both_attempts(self):
        with tempfile.TemporaryDirectory() as td:
            base=Path(td);script=base/'worker.py';self.worker_script(script,hang=True)
            for arm in R.ARMS:
                store=E.Store(base/arm)
                with mock.patch.object(R,'SELF',script):
                    row=R.run_item({'id':'dev','question':'Public lab question'},R.DEFAULT_MODEL,.5,arm,private_store=store)
                self.assertEqual(row['error'],'MODEL_TIMEOUT')
                self.assertEqual(len(row['private_artifacts']),2)
                values=[json.loads(p.read_bytes()) for p in store.path.glob('*-final.json')]
                self.assertEqual(len(values),2)
                for v in values:
                    self.assertEqual(v['gate']['verdict'],'not_reached')
                    self.assertEqual(v['terminal']['error'],'MODEL_TIMEOUT')
                    self.assertTrue(v['package'])
                    self.assertTrue(v['sent_to'])
                self.assertTrue(E.verify(store.path,store.manifest())['verified'])

    def test_provider_failure_is_reviewable_without_exception_body(self):
        case=json.loads((ROOT/'tests/fixtures/review-artifacts-dev-v1.json').read_bytes())[0]
        for arm in R.ARMS:
            with tempfile.TemporaryDirectory() as td:
                api=R.load_module('failure_answer',ROOT/'bin/mitr3-answer.py')
                outputs=iter([case['plan']])
                def model(*args):
                    try:return next(outputs)
                    except StopIteration:raise api.AnswerError('MODEL_FAILED')
                store=E.Store(Path(td)/'private');token='a'*24
                review=E.new_review(case['question'],arm,R.DEFAULT_MODEL,'dev')
                with mock.patch.object(R,'load_module',return_value=api):
                    out,_=R.pipeline(case['question'],arm,model_fn=model,retrieve_fn=lambda *args:case['documents'],
                                     review=review,checkpoint=store.checkpoint(token))
                self.assertEqual(out['error_code'],'MODEL_FAILED')
                store.finish(token,review,out['error_code'],True)
                value=json.loads((store.path/(token+'-final.json')).read_bytes())
                self.assertEqual(value['gate']['error'],'MODEL_FAILED')
                self.assertTrue(value['package'])
                self.assertTrue(E.verify(store.path,store.manifest())['verified'])

    def test_demo_existing_public_output_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as td:
            output=Path(td)/'frozen.json';output.write_text('preserve')
            with mock.patch.object(R,'dev_demo') as run:
                code=R.main(['--dev-review-demo','--private-dir',str(Path(td)/'private'),'--output',str(output)])
                run.assert_not_called()
            self.assertEqual(code,1)
            self.assertEqual(output.read_text(),'preserve')
            self.assertFalse((Path(td)/'private').exists())

    def test_success_without_private_claims_refused(self):
        with tempfile.TemporaryDirectory() as td:
            store=E.Store(Path(td)/'private')
            with self.assertRaises(E.EscrowError):
                store.finish('a'*24,E.new_review('Public question','baseline',R.DEFAULT_MODEL),None,False)

    def test_verifier_cli_emits_no_raw_content(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/'private';report,_=self.demo(path)
            p=subprocess.run([sys.executable,str(ROOT/'bin/mitr3-review-artifacts.py'),str(path),
                              '--manifest-sha256',report['private_manifest_sha256']],capture_output=True,text=True)
            self.assertEqual(p.returncode,0)
            self.assertEqual(json.loads(p.stdout)['items_attempts'],4)
            self.assertNotIn('control service',p.stdout+p.stderr)


if __name__=='__main__':unittest.main()
