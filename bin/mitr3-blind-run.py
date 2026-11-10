#!/usr/bin/env python3
"""Parallel answer runner. Writes metadata only, never questions, quotes or gold.

No scoring against expected answers; --pass is a run number, not a verdict.
Existing outputs are never overwritten. No blind set is selected automatically.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
ANSWER = ROOT / 'bin/mitr3-answer.py'
RETRY = {'MODEL_TIMEOUT', 'MODEL_FAILED'}
ERRORS = RETRY | set('MODEL_JSON MODEL_COMMAND MODEL_OUTPUT_LIMIT PLAN_SCHEMA PLAN_REDACTED PLAN_NEW_IDENTIFIER QUESTION_INVALID EVIDENCE_LIMIT NO_EVIDENCE MODEL_ABSTAIN COMPOSITION_SCHEMA ABSTAIN_WITH_CLAIMS EMPTY_CLAIMS CLAIM_SCHEMA UNCITED_CLAIM UNSAFE_CLAIM INSTRUCTION_CLAIM CITATION_SCHEMA UNKNOWN_CITATION REMOTE_NOT_EVIDENCE QUOTE_NOT_LITERAL INSTRUCTION_QUOTE NAMESPACE_MIX PIPELINE_ERROR EVIDENCE_COMMAND EVIDENCE_TIMEOUT BRIDGE_SCHEMA DOCUMENT_IDENTITY DOCUMENT_SCHEMA DOCUMENT_SHA256 EDGE_SHA256 EDGE_PROOF EVIDENCE_CONFLICT'.split())
PUBLIC_ID = re.compile(r'(?:CVE-\d{4}-\d{4,}|CWE-\d+|ASVS-V?\d+(?:\.\d+){2}|CASE-[a-zA-Z0-9._-]{1,100}|T\d{4}(?:\.\d{3})?|TA\d{4}|[GSM]\d{4}|relationship--[a-f0-9-]{36}|local-edge:[A-Za-z0-9_.:-]{1,160})\Z')


class RunError(Exception):
    pass


def load_questions(path):
    raw = path.read_bytes()
    data = json.loads(raw)
    if not isinstance(data, list) or len(data) != 10:
        raise RunError('TEN_ITEMS_REQUIRED')
    rows, seen = [], set()
    for row in data:
        if (not isinstance(row, dict) or not isinstance(row.get('id'), str)
                or not re.fullmatch(r'[A-Za-z0-9._-]{1,100}', row['id']) or row['id'] in seen
                or not isinstance(row.get('question'), str) or not row['question'].strip()
                or len(row['question']) > 4000):
            raise RunError('INPUT_SCHEMA')
        seen.add(row['id'])
        # Gold/expected/forbidden fields are neither forwarded nor recorded.
        rows.append({'id': row['id'], 'question': row['question']})
    return rows, hashlib.sha256(raw).hexdigest()


def metadata(value):
    if (not isinstance(value, dict) or type(value.get('abstain')) is not bool
            or not isinstance(value.get('claims'), list)):
        return {'abstain': True, 'error': 'MODEL_JSON', 'status': 'abstained', 'claim_count': 0, 'citation_ids': []}
    error = value.get('error_code')
    if error is not None and error not in ERRORS:
        error = 'UNRECOGNIZED_ERROR'
    claims = value['claims']
    ids = set()
    for claim in claims:
        if not isinstance(claim, dict) or not isinstance(claim.get('citations'), list):
            continue
        for cite in claim['citations']:
            ident = cite.get('id') if isinstance(cite, dict) else None
            if isinstance(ident, str) and PUBLIC_ID.fullmatch(ident):
                ids.add(ident)
    return {'abstain': value['abstain'], 'error': error,
            'status': 'abstained' if value['abstain'] else 'evidence_attached_proposal',
            'claim_count': len(claims), 'citation_ids': sorted(ids)}


def failed(code):
    return metadata({'abstain': True, 'claims': [], 'error_code': code})


def call_answer(question, model, timeout):
    proc = None
    try:
        proc = subprocess.Popen([sys.executable, str(ANSWER), question, '--json', '--model', model],
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, text=True, start_new_session=True)
        stdout, _ = proc.communicate(timeout=timeout)
        if proc.returncode:
            return failed('MODEL_FAILED')
        if len(stdout) > 200_000:
            return failed('MODEL_OUTPUT_LIMIT')
        try:
            return metadata(json.loads(stdout))
        except (ValueError, TypeError):
            return failed('MODEL_JSON')
    except subprocess.TimeoutExpired:
        return failed('MODEL_TIMEOUT')
    except (OSError, ValueError):
        return failed('MODEL_FAILED')
    finally:
        if proc is not None:
            if proc.poll() is None:
                # Kill CLI descendants too; do not leave local provider children.
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            proc.communicate()  # Reap and close pipes, without logging their contents.


def run_item(item, model, timeout):
    attempts = []
    started = time.monotonic()
    for _ in range(2):
        tick = time.monotonic()
        result = call_answer(item['question'], model, timeout)
        attempts.append({'error': result['error'], 'elapsed': round(time.monotonic() - tick, 3)})
        if result['error'] not in RETRY:
            break
    return dict(id=item['id'], **result, attempts=attempts, elapsed=round(time.monotonic() - started, 3))


def run_set(path, model, workers=4, timeout=90, pass_number=1):
    if workers not in (2, 3, 4) or not 0 < timeout <= 120 or pass_number < 1:
        raise RunError('RUN_OPTIONS')
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.:/#-]+', model):
        raise RunError('MODEL_NAME')
    if not re.fullmatch(r'[A-Za-z0-9._-]+', path.stem):
        raise RunError('SET_NAME')
    questions, digest = load_questions(path)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        rows = list(pool.map(lambda item: run_item(item, model, timeout), questions))
    return {'at_utc': dt.datetime.now(dt.timezone.utc).isoformat(), 'set': path.stem,
            'sha256': digest, 'model': model, 'pass': pass_number, 'rows': rows}


def reserve_output(path, input_path):
    # Refuse existing/frozen outputs BEFORE any model calls, including symlinks.
    if path.resolve() == input_path.resolve() or (ROOT / 'evals').resolve() in path.resolve().parents:
        raise RunError('OUTPUT_PROTECTED')
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    return os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('set', type=Path)
    parser.add_argument('--model', required=True)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--workers', type=int, choices=(2, 3, 4), default=4)
    parser.add_argument('--timeout', type=float, default=90)
    parser.add_argument('--pass', dest='pass_number', type=int, default=1)
    args = parser.parse_args(argv)
    fd = None
    try:
        # Validate the input before reserving output; no dataset is printed.
        load_questions(args.set)
        fd = reserve_output(args.output, args.set)
        with os.fdopen(fd, 'w', encoding='utf8') as stream:
            fd = None
            report = run_set(args.set, args.model, args.workers, args.timeout, args.pass_number)
            json.dump(report, stream, ensure_ascii=False, indent=2)
            stream.write('\n')
        print(json.dumps({'status': 'complete', 'rows': len(report['rows'])}))
        return 0
    except (RunError, OSError, ValueError, TypeError):
        print(json.dumps({'status': 'failed', 'error': 'RUNNER_ERROR'}))
        return 1
    finally:
        if fd is not None:
            os.close(fd)


if __name__ == '__main__':
    raise SystemExit(main())
