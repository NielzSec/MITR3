"""Independent synthetic DEV only. All model/retrieval/transport calls are offline."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('candidate_runner',ROOT/'bin/mitr3-candidate-run.py')
R=importlib.util.module_from_spec(spec)
spec.loader.exec_module(R)


class CandidateRunTests(unittest.TestCase):
    def setUp(self):
        self.doc={'id':'CASE-public-dev','snippet':'The public lab endpoint returned status 200.',
                  'namespace':'local','source_url':'https://example.org/dev','sha256':'a'*64}
        self.plan={'language':'en','intent':'artifact','entities':[],'queries':['public lab']}
        self.extract={'extracts':[{'id':self.doc['id'],'quote':'returned status 200'}]}
        self.composition={'abstain':False,'claims':[{'text':'The endpoint returned status 200.',
                           'citations':copy.deepcopy(self.extract['extracts'])}]}

    def pipeline(self,arm,outputs,package=None):
        calls=[]
        def model_fn(prompt,model):
            calls.append((prompt,model))
            return outputs.pop(0)
        retrieve=mock.Mock(return_value=[self.doc] if package is None else package)
        result,stage=R.pipeline('What response did the public lab endpoint return?',arm,
                                model_fn=model_fn,retrieve_fn=retrieve)
        self.assertFalse(outputs)
        return result,stage,calls,retrieve

    def fixture(self,folder):
        p=Path(folder)/'public-dev.json'
        p.write_text(json.dumps([{'id':f'dev-{i}','question':'PUBLIC_QUESTION_CANARY',
                                 'expected_answer':{'nested':['GOLD_TRIPWIRE',17]},
                                 'expected_ids':['GOLD_IDS_TRIPWIRE'],'forbidden_ids':['GOLD_FORBIDDEN_TRIPWIRE']}
                                for i in range(10)]))
        return p

    def test_arms_same_output_interface_and_plan_retrieval(self):
        b,bs,bc,br=self.pipeline('baseline',[self.plan,self.composition])
        c,cs,cc,cr=self.pipeline('candidate',[self.plan,self.extract,self.composition])
        self.assertEqual(b,c)
        self.assertEqual(bc[0],cc[0])
        self.assertEqual(br.call_args,cr.call_args)
        self.assertEqual(br.call_args.args,(['public lab'],5,False))
        self.assertEqual(len(bc),2)
        self.assertEqual(len(cc),3)
        self.assertIn('MUST include a literal quote',cc[-1][0])
        self.assertIn('UNTRUSTED DATA',cc[-1][0])
        self.assertEqual(cs['extract_count'],1)
        self.assertEqual(cs['quote_count'],1)
        self.assertEqual(bs['evidence_state'],'unobserved_baseline')

    def test_baseline_exact_transport_delegation(self):
        with mock.patch.object(R.BLIND,'call_answer',return_value=R.BLIND.failed('MODEL_ABSTAIN')) as call:
            result=R.call_arm('public','provider/model',90,'baseline')
        call.assert_called_once_with('public','provider/model',90)
        self.assertEqual(result['error'],'MODEL_ABSTAIN')

    def test_loader_decodes_no_gold_values(self):
        decode=json.loads
        decoded=[]
        def guard(raw,*args,**kwargs):
            if 'GOLD_' in raw:
                raise AssertionError('Gold value reached JSON decoder')
            decoded.append(raw)
            return decode(raw,*args,**kwargs)
        with tempfile.TemporaryDirectory() as td:
            path=self.fixture(td)
            raw=path.read_bytes()
            with mock.patch.object(R.json,'loads',side_effect=guard):
                rows,sha=R.load_questions(path)
        self.assertEqual(sha,hashlib.sha256(raw).hexdigest())
        self.assertEqual(len(rows),10)
        self.assertTrue(all(set(row)=={'id','question'} for row in rows))
        self.assertNotIn('GOLD_',repr(decoded))

    def test_ignored_fields_are_not_forwarded_or_recorded(self):
        seen=[]
        def call(q,m,t,arm):
            seen.append(q)
            return R.BLIND.failed('MODEL_ABSTAIN')
        with tempfile.TemporaryDirectory() as td:
            report=R.run_set(self.fixture(td),'candidate',call_fn=call)
        self.assertEqual(seen,['PUBLIC_QUESTION_CANARY']*10)
        for marker in ['GOLD_','PUBLIC_QUESTION_CANARY','expected_answer','forbidden_ids']:
            self.assertNotIn(marker,json.dumps(report))

    def test_projection_rejects_malformed_or_duplicate_input(self):
        for raw in ['[]','[{}]','[NaN]','[{},]','[', '[{"id":"x","id":"y","question":"public"}]',
                    '[{"id":7,"question":"public"}]', '[{"id":"x","question":"public","unused":{bad}}]']:
            with self.subTest(raw=raw),self.assertRaises(R.RunError):
                R.QuestionProjection(raw).rows()

    def test_projection_nested_escaped_ignored_values_and_unicode(self):
        rows=[{'id':f'dev-{i}','question':'Pergunta pública?','unused':{'nested':[None,True,False,1.2e8,'{}[]\\"\n']}} for i in range(10)]
        out=R.QuestionProjection(json.dumps(rows)).rows()
        self.assertEqual(out,[{'id':r['id'],'question':r['question']} for r in rows])
        rows[1]['id']=rows[0]['id']
        with self.assertRaises(R.RunError):R.QuestionProjection(json.dumps(rows)).rows()

    def test_all_rejected_extracts_stop_before_synthesis(self):
        extraction={'extracts':[{'id':self.doc['id'],'quote':'NON_LITERAL_CANARY'}]}
        out,stage,calls,_=self.pipeline('candidate',[self.plan,extraction])
        self.assertEqual(out['error_code'],'NO_VERIFIED_EXTRACTS')
        self.assertEqual(stage['rejected_extract_count'],1)
        self.assertEqual(len(calls),2)
        self.assertTrue(out['abstain'])

    def test_empty_extraction_never_promoted(self):
        out,stage,_,_=self.pipeline('candidate',[self.plan,{'extracts':[]}])
        self.assertEqual(out['error_code'],'NO_VERIFIED_EXTRACTS')
        self.assertEqual(stage['extract_count'],0)

    def test_mixed_extraction_only_verified_pairs_in_extract_envelope(self):
        extract={'extracts':self.extract['extracts']+[{'id':'ABSENT','quote':'REJECTED_CANARY'}]}
        out,stage,calls,_=self.pipeline('candidate',[self.plan,extract,self.composition])
        self.assertFalse(out['abstain'])
        self.assertEqual(stage['rejected_extract_count'],1)
        self.assertNotIn('REJECTED_CANARY',calls[-1][0])

    def test_nonliteral_final_quote_is_blocked_by_unchanged_gate(self):
        self.composition['claims'][0]['citations'][0]['quote']='PARAPHRASED_CANARY'
        out,stage,_,_=self.pipeline('candidate',[self.plan,self.extract,self.composition])
        self.assertEqual(out['error_code'],'QUOTE_NOT_LITERAL')
        self.assertTrue(out['abstain'])
        self.assertEqual(stage['quote_count'],1)
        self.assertEqual(stage['literal_quote_count'],0)

    def test_final_gate_namespace_and_required_quote(self):
        for mutation,code in [('namespace','NAMESPACE_MIX'),('quote','CITATION_SCHEMA')]:
            composition=copy.deepcopy(self.composition)
            if mutation=='namespace':composition['claims'][0]['text']='T1059.001 establishes a CVE link.'
            else:composition['claims'][0]['citations'][0].pop('quote')
            out,_,_,_=self.pipeline('candidate',[self.plan,self.extract,composition])
            self.assertEqual(out['error_code'],code)

    def test_no_evidence_does_not_call_extraction(self):
        out,stage,calls,_=self.pipeline('candidate',[self.plan],[])
        self.assertEqual(out['error_code'],'NO_EVIDENCE')
        self.assertEqual(stage['evidence_state'],'empty')
        self.assertEqual(len(calls),1)

    def test_model_abstention_preserved(self):
        out,stage,_,_=self.pipeline('candidate',[self.plan,self.extract,{'abstain':True,'claims':[]}])
        self.assertEqual(out['error_code'],'MODEL_ABSTAIN')
        self.assertEqual(stage['evidence_state'],'nonempty')

    def test_retry_exactly_once_only_transient_errors_both_arms(self):
        for arm in R.ARMS:
            for code,count in [('MODEL_TIMEOUT',2),('MODEL_FAILED',2),('MODEL_ABSTAIN',1),('QUOTE_NOT_LITERAL',1),('NO_VERIFIED_EXTRACTS',1)]:
                with self.subTest(arm=arm,code=code):
                    call=mock.Mock(return_value={**R.BLIND.failed('MODEL_ABSTAIN'),'error':code})
                    row=R.run_item({'id':'dev','question':'public'},R.DEFAULT_MODEL,90,arm,call)
                    self.assertEqual(call.call_count,count)
                    self.assertEqual(len(row['attempts']),count)

    def test_timeout_cleanup_both_arms_no_network(self):
        with tempfile.TemporaryDirectory() as td:
            slow=Path(td)/'slow.py';slow.write_text('import time\ntime.sleep(30)\n')
            for arm in R.ARMS:
                with mock.patch.object(R,'SELF',slow),mock.patch.object(R.BLIND,'ANSWER',slow):
                    start=time.monotonic()
                    out=R.call_arm('public',R.DEFAULT_MODEL,.05,arm)
                self.assertEqual(out['error'],'MODEL_TIMEOUT')
                self.assertLess(time.monotonic()-start,2)

    def test_parallel_workers_and_stable_order(self):
        lock=threading.Lock();active=peak=0
        def call(*_):
            nonlocal active,peak
            with lock:active+=1;peak=max(peak,active)
            time.sleep(.02)
            with lock:active-=1
            return R.BLIND.failed('MODEL_ABSTAIN')
        with tempfile.TemporaryDirectory() as td:
            report=R.run_set(self.fixture(td),'candidate',workers=3,call_fn=call)
        self.assertEqual(peak,3)
        self.assertEqual([r['id'] for r in report['rows']],[f'dev-{i}' for i in range(10)])
        self.assertEqual(report['totals']['abstained'],10)
        self.assertEqual(report['model'],R.DEFAULT_MODEL)

    def test_existing_output_never_overwritten_or_run(self):
        with tempfile.TemporaryDirectory() as td:
            fixture=self.fixture(td);out=Path(td)/'frozen.json';out.write_text('preserve')
            sha=hashlib.sha256(fixture.read_bytes()).hexdigest()
            with mock.patch.object(R,'run_set') as run:
                code=R.main([str(fixture),'--arm','candidate','--output',str(out),'--operator-approved','--expected-set-sha256',sha])
                run.assert_not_called()
            self.assertEqual(code,1)
            self.assertEqual(out.read_text(),'preserve')

    def test_approval_and_hash_required_before_calls(self):
        with tempfile.TemporaryDirectory() as td:
            fixture=self.fixture(td);out=Path(td)/'new.json'
            for flags in [[],['--operator-approved'],['--operator-approved','--expected-set-sha256','0'*64]]:
                with mock.patch.object(R,'run_set') as run:
                    self.assertEqual(R.main([str(fixture),'--arm','baseline','--output',str(out),*flags]),1)
                    run.assert_not_called()
                self.assertFalse(out.exists())

    def test_set_hash_mismatch_rejected_before_any_call(self):
        with tempfile.TemporaryDirectory() as td:
            call=mock.Mock()
            with self.assertRaises(R.RunError):
                R.run_set(self.fixture(td),'candidate',call_fn=call,expected_sha256='0'*64)
            call.assert_not_called()

    def test_worker_metadata_strips_raw_result_and_stage_text(self):
        with tempfile.TemporaryDirectory() as td:
            script=Path(td)/'fake-worker.py'
            result={'result':self.composition,'stages':{'query_count':1,'snippet_lengths':[42],'evidence_state':'nonempty','raw':'PRIVATE_CANARY'}}
            script.write_text('import json\nprint('+repr(json.dumps(result))+')\n')
            with mock.patch.object(R,'SELF',script):
                out=R.call_arm('public',R.DEFAULT_MODEL,1,'candidate')
        self.assertFalse(out['abstain'])
        for marker in ['The endpoint','returned status','PRIVATE_CANARY']:
            self.assertNotIn(marker,json.dumps(out))

    def test_artifacts_hashes_and_no_production_changes(self):
        hashes=R.artifacts()
        self.assertEqual(hashes['bin/mitr3-answer.py'],R.sha_file(ROOT/'bin/mitr3-answer.py'))
        self.assertEqual(len(hashes['required_synthesis_prompt']),64)
        self.assertEqual(len(hashes['extraction_prompt_source']),64)
        source=(ROOT/'bin/mitr3-candidate-run.py').read_text()
        self.assertNotIn('blind-answers-robin-v5.json',source)

    def test_report_reprojects_untrusted_worker_fields(self):
        def call(*_):
            return {'abstain':False,'error':None,'claim_count':1,'citation_ids':['CASE-public-dev','PRIVATE_CANARY'],
                    'raw_answer':'RAW_ANSWER_CANARY','question':'RAW_QUESTION_CANARY',
                    'stages':{'query_count':1,'snippet_lengths':[24],'secret':'PRIVATE_BODY_CANARY','evidence_state':'PRIVATE_STATE'}}
        row=R.run_item({'id':'dev','question':'public'},R.DEFAULT_MODEL,90,'candidate',call)
        for marker in ['PRIVATE_CANARY','RAW_ANSWER_CANARY','RAW_QUESTION_CANARY','PRIVATE_BODY_CANARY','PRIVATE_STATE']:
            self.assertNotIn(marker,json.dumps(row))
        self.assertEqual(row['category'],'answered_gate')

    def test_transient_then_success_and_operational_category(self):
        success={'abstain':False,'error':None,'claim_count':1,'citation_ids':[]}
        call=mock.Mock(side_effect=[R.BLIND.failed('MODEL_TIMEOUT'),success])
        out=R.run_item({'id':'dev','question':'public'},R.DEFAULT_MODEL,90,'candidate',call)
        self.assertEqual(out['category'],'answered_gate')
        self.assertEqual(len(out['attempts']),2)
        call=mock.Mock(return_value=R.BLIND.failed('MODEL_TIMEOUT'))
        self.assertEqual(R.run_item({'id':'dev','question':'public'},R.DEFAULT_MODEL,90,'candidate',call)['category'],'failed')


if __name__=='__main__':unittest.main()
