#!/usr/bin/env python3
"""DEV-only stage metrics. Never writes prompts, quotes, bodies or gold answers.

Fixed independent public fixture; not a blind runner or a production adapter.
"""
import argparse
from collections import Counter
from contextlib import closing
import copy
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / 'tests/fixtures/answer-stage-dev-v1.json'
SPEC = importlib.util.spec_from_file_location('stage_answer', ROOT / 'bin/mitr3-answer.py')
answer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(answer)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        fp.close()
        answer.fail('MODEL_FAILED')


def public_model(prompt, model):
    """Stateless Google call: no OpenCode sessions, no request/body logging."""
    if not re.fullmatch(r'google/[a-zA-Z0-9_.-]+', model):
        answer.fail('MODEL_COMMAND')
    key = os.environ.get('GOOGLE_API_KEY') or os.environ.get('GEMINI_API_KEY')
    if not key:
        answer.fail('MODEL_COMMAND')
    payload = {'contents': [{'role': 'user', 'parts': [{'text': prompt}]}], 'store': False}
    url = 'https://generativelanguage.googleapis.com/v1beta/models/' + model.split('/', 1)[1] + ':generateContent'
    request = urllib.request.Request(url, data=json.dumps(payload).encode(), method='POST',
                                    headers={'Content-Type': 'application/json', 'x-goog-api-key': key})
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        with closing(opener.open(request, timeout=90)) as response:
            raw = response.read(200_001)
        if len(raw) > 200_000:
            answer.fail('MODEL_OUTPUT_LIMIT')
        data = json.loads(raw)
        texts = [part['text'] for candidate in data.get('candidates', [])
                 for part in candidate.get('content', {}).get('parts', [])
                 if isinstance(part.get('text'), str) and not part.get('thought')]
        return answer.strict_json('\n'.join(texts))
    except urllib.error.HTTPError as exc:
        exc.close()  # Never print/store provider error bodies, URLs or headers.
        answer.fail('MODEL_FAILED')
    except TimeoutError:
        answer.fail('MODEL_TIMEOUT')
    except (OSError, ValueError, KeyError):
        answer.fail('MODEL_FAILED')


def transmitted(question, package):
    prompt = answer.composition_prompt(question, package)
    # Measure the decoded strings actually serialized into the C prompt.
    payload = json.loads(prompt.split('<evidence>\n', 1)[1].split('\n</evidence>', 1)[0])
    return prompt, payload


def packet_metrics(package):
    return {'sha256': digest(package), 'documents': [
        {'id': doc['id'], 'namespace': doc['namespace'], 'kind': doc['kind'],
         'snippet_chars': len(doc['snippet']), 'snippet_utf8_bytes': len(doc['snippet'].encode())}
        for doc in package]}


def quote_metrics(composition, sent, gated, full_text):
    before, after = {d['id']: d for d in sent}, {d['id']: d for d in gated}
    changed = digest(sent) != digest(gated)
    rows = []
    claims = composition.get('claims', [])
    if not isinstance(claims, list):
        claims = []
    for claim in claims:
        citations = claim.get('citations', []) if isinstance(claim, dict) else []
        if not isinstance(citations, list):
            continue
        for cite in citations:
            if not isinstance(cite, dict):
                continue
            ident, quote = cite.get('id'), cite.get('quote')
            if not isinstance(ident, str) or not isinstance(quote, str):
                continue
            q = answer.normalized(quote)
            in_sent = bool(q) and q in answer.normalized(before.get(ident, {}).get('snippet', ''))
            in_gate = bool(q) and q in answer.normalized(after.get(ident, {}).get('snippet', ''))
            in_full = bool(q) and q in answer.normalized(full_text.get(ident, ''))
            cause = ('literal' if in_gate else 'different_package' if changed and in_sent else
                     'outside_window' if in_full and not in_sent else 'nonliteral_or_paraphrase')
            # No quote strings or claim strings leave this function.
            rows.append({'id': ident if ident in before or ident in after else '[unlisted-id]', 'quote_chars': len(quote), 'in_transmitted': in_sent,
                         'in_gate': in_gate, 'in_full_public_document': in_full, 'classification': cause})
    return {'same_package': not changed, 'citations': rows}


def compose(question, package, full_text, model, model_fn=public_model):
    prompt, sent = transmitted(question, package)
    result = {'packet': packet_metrics(sent)}
    try:
        obj = model_fn(prompt, model)
        result['model_abstain'] = obj.get('abstain') if type(obj.get('abstain')) is bool else None
        result['gate_quotes'] = quote_metrics(obj, sent, package, full_text)
        final = answer.gate(obj, package)
        result.update(error=final['error_code'], abstain=final['abstain'], claim_count=len(final['claims']))
    except answer.AnswerError as exc:
        result.update(error=str(exc), abstain=True, claim_count=0)
    return result


def gate_controls(document, full):
    """Synthetic controls, not evidence of failures in live model responses."""
    doc = copy.deepcopy(document)
    def composition(quote):
        return {'abstain': False, 'claims': [{'text': 'Public DEV control.', 'citations': [{'id': doc['id'], 'quote': quote}]}]}
    tests = [('nonliteral', composition('SYNTHETIC_NONLITERAL_DEV_CONTROL'), [doc])]
    if len(full) > len(doc['snippet']):
        tests.append(('window', composition(full[-40:]), [doc]))
    tests.append(('changed_package', composition(doc['snippet'][:40]), [dict(doc, snippet='')]))
    results = []
    for name, obj, gated in tests:
        metrics = quote_metrics(obj, [doc], gated, {doc['id']: full})
        try:
            final = answer.gate(obj, gated)
            code = final['error_code']
        except answer.AnswerError as exc:
            code = str(exc)
        results.append({'control': name, 'error': code, **metrics})
    return results


def run(model, model_fn=public_model):
    fixture = json.loads(FIXTURE.read_text())
    rows = []
    for item in fixture:
        row = {'id': item['id']}
        try:
            plan = answer.plan_gate(model_fn(answer.plan_prompt(item['question']), model), item['question'])
            queries = plan['queries']
            row['A'] = {'query_count': len(queries), 'unique_query_count': len(set(queries)), 'error': None}
        except answer.AnswerError as exc:
            queries = []
            row['A'] = {'query_count': 0, 'unique_query_count': 0, 'error': str(exc)}
        retrieval = []
        for query in dict.fromkeys(queries):
            indexed = answer.local_json(answer.INTEL, ['search', query, '--json', '--limit', '5'])
            bridged = answer.local_json(answer.BRIDGE, [query, '--json', '--limit', '5'])
            retrieval.append({'index_ids': [d['id'] for d in indexed],
                              'bridge_ids': [d['id'] for d in bridged['local']['matches']]})
        actual = answer.evidence_package(queries, 5) if queries else []
        reference = answer.evidence_package([item['reference_document']], 5)
        full_text = {}
        for doc in actual + reference:
            if doc['kind'] == 'document' and doc['namespace'] == 'local':
                got = answer.local_json(answer.INTEL, ['search', doc['id'], '--json', '--limit', '1'])[0]
                if got.get('sha256') != doc['sha256']:
                    answer.fail('DOCUMENT_SHA256')
                full_text[doc['id']] = got['summary'] + '\n' + got['lesson']
        row['B'] = {'queries': retrieval, 'transmitted': packet_metrics(transmitted(item['question'], actual)[1])}
        row['C'] = {condition: compose(item['question'], packet, full_text, model, model_fn)
                    for condition, packet in [('retrieved', actual), ('empty', []), ('reference', reference)]}
        doc = next(d for d in reference if d['kind'] == 'document')
        row['D_controls'] = gate_controls(doc, full_text[doc['id']])
        rows.append(row)
    aggregate = {}
    for condition in ('retrieved', 'empty', 'reference'):
        values = [r['C'][condition] for r in rows]
        aggregate[condition] = {'calls': len(values), 'model_abstain': sum(v.get('model_abstain') is True for v in values),
            'valid_compositions': sum(type(v.get('model_abstain')) is bool for v in values),
            'codes': dict(Counter(v['error'] or 'PROPOSAL' for v in values))}
    return {'at_utc': dt.datetime.now(dt.timezone.utc).isoformat(), 'fixture': FIXTURE.name,
            'fixture_sha256': hashlib.sha256(FIXTURE.read_bytes()).hexdigest(), 'model': model,
            'transport': 'stateless_google_generateContent_store_false_no_tools',
            'note': 'DEV only, not v4 score or semantic validation; metadata only.',
            'aggregate': aggregate, 'rows': rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--model', default='google/gemini-3.5-flash-lite')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    # Exclusive output opened before paid work; never overwrite a frozen report.
    args.output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        fd = os.open(args.output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, 'w') as stream:
            report = run(args.model)
            json.dump(report, stream, ensure_ascii=False, indent=2)
            stream.write('\n')
        print(json.dumps(report['aggregate']))
    except Exception:
        print(json.dumps({'error': 'DEV_DIAG_FAILED'}))
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
