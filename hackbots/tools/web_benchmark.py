"""Offline v0.2 synthetic HTTP oracle. Never fetch URLs or execute corpus content."""
import argparse
import hashlib
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import re
import stat

from .web_evidence import EvidenceRejected, ID, HEX, _unique, _reject_constant

MAX_FILE = 65_536
MAX_SUITE = 32_768
MAX_DEPTH = 16
MAX_IDS = 500
MAX_CASES = 32


def read_local(root, relative, maximum):
    """Descriptor walk: reject links in all ancestors, non-files and hardlinks."""
    if (type(relative) is not str or not relative or len(relative) > 200
            or any(not re.fullmatch(r'[A-Za-z0-9_.-]+', part) or part in ('.', '..')
                   for part in relative.split('/'))):
        raise EvidenceRejected('UNSAFE_FILE')
    path = Path(root).absolute() / relative
    parent = fd = None
    try:
        parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
        for part in path.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent)
            parent = child
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or not 0 < info.st_size <= maximum):
            raise EvidenceRejected('UNSAFE_FILE')
        with os.fdopen(fd, 'rb', closefd=False) as source:
            raw = source.read(maximum + 1)
        if len(raw) > maximum:
            raise EvidenceRejected('UNSAFE_FILE')
        return raw
    except (OSError, TypeError):
        raise EvidenceRejected('UNSAFE_FILE') from None
    finally:
        if fd is not None:
            os.close(fd)
        if parent is not None:
            os.close(parent)


class InventoryParser(HTMLParser):
    """Deliberately small synthetic profile, not browser HTML error recovery."""
    TAGS = {'html', 'head', 'title', 'body', 'main', 'article', 'a', 'p', 'span'}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack = []
        self.ids = []
        self.roots = 0
        self.bodies = 0
        self.doctypes = 0

    def handle_starttag(self, tag, attrs):
        if tag not in self.TAGS or len(self.stack) >= MAX_DEPTH:
            raise EvidenceRejected('HTML_PROFILE')
        if not self.stack:
            if tag != 'html' or self.roots:
                raise EvidenceRejected('HTML_PROFILE')
            self.roots += 1
        elif tag == 'html':
            raise EvidenceRejected('HTML_PROFILE')
        if tag == 'body':
            if self.stack != ['html'] or self.bodies:
                raise EvidenceRejected('HTML_PROFILE')
            self.bodies += 1
        if tag == 'article':
            if 'body' not in self.stack or len(attrs) != 1 or attrs[0][0] != 'data-product-id':
                raise EvidenceRejected('HTML_PROFILE')
            value = attrs[0][1]
            if (type(value) is not str or ID.fullmatch(value) is None
                    or value in self.ids or len(self.ids) >= MAX_IDS):
                raise EvidenceRejected('INVALID_INVENTORY')
            self.ids.append(value)
        elif attrs:
            raise EvidenceRejected('HTML_PROFILE')
        self.stack.append(tag)

    def handle_endtag(self, tag):
        if not self.stack or self.stack.pop() != tag:
            raise EvidenceRejected('HTML_PROFILE')

    def handle_startendtag(self, tag, attrs):
        raise EvidenceRejected('HTML_PROFILE')

    def handle_data(self, data):
        if (not self.stack and data.strip()) or '<' in data or '>' in data:
            raise EvidenceRejected('HTML_PROFILE')

    def handle_decl(self, decl):
        if decl.lower() != 'doctype html' or self.roots or self.doctypes:
            raise EvidenceRejected('HTML_PROFILE')

        self.doctypes += 1

    def unknown_decl(self, data):
        raise EvidenceRejected('HTML_PROFILE')

    def handle_pi(self, data):
        raise EvidenceRejected('HTML_PROFILE')

    def inventory(self, body):
        try:
            text = body.decode('utf-8', errors='strict')
            if any(ord(c) < 32 and c not in '\t\r\n' for c in text):
                raise EvidenceRejected('HTML_PROFILE')
            # HTMLParser may discard an unfinished comment when close() is called.
            position = 0
            while True:
                opening = text.find('<', position)
                if opening < 0:
                    break
                comment = text.startswith('<!--', opening)
                end = text.find('-->' if comment else '>', opening + (4 if comment else 1))
                if end < 0 or (not comment and '<' in text[opening + 1:end]):
                    raise EvidenceRejected('HTML_PROFILE')
                position = end + (3 if comment else 1)
            self.feed(text)
            self.close()
        except (UnicodeError, RecursionError, ValueError) as exc:
            if isinstance(exc, EvidenceRejected):
                raise
            raise EvidenceRejected('HTML_PROFILE') from None
        if self.stack or self.roots != 1 or self.bodies != 1:
            raise EvidenceRejected('HTML_PROFILE')
        return sorted(self.ids, key=int)


def parse_response(raw):
    head, sep, body = raw.partition(b'\r\n\r\n')
    if not sep or len(head) > 4096:
        raise EvidenceRejected('HTTP_PROFILE')
    try:
        lines = head.decode('ascii').split('\r\n')
        status = re.fullmatch(r'HTTP/1\.1 ([1-5][0-9]{2}) [A-Za-z ]{1,40}', lines[0])
        headers = {}
        for line in lines[1:]:
            key, value = line.split(': ', 1)
            key = key.lower()
            if key in headers:
                raise ValueError()
            headers[key] = value
        if (status is None or set(headers) != {'content-length', 'content-type'}
                or headers['content-type'] != 'text/html; charset=utf-8'
                or not re.fullmatch(r'0|[1-9][0-9]{0,5}', headers['content-length'])
                or int(headers['content-length']) != len(body)):
            raise ValueError()
    except (UnicodeError, ValueError, IndexError):
        raise EvidenceRejected('HTTP_PROFILE') from None
    return int(status[1]), InventoryParser().inventory(body)


def check_ids(ids):
    if (type(ids) is not list or len(ids) > MAX_IDS
            or any(type(x) is not str or ID.fullmatch(x) is None for x in ids)
            or len(ids) != len(set(ids))):
        raise EvidenceRejected('INVALID_OBSERVED_INVENTORY')
    return sorted(ids, key=int)


def response(root, reference):
    if (type(reference) is not dict or set(reference) != {'file', 'sha256'}
            or type(reference['sha256']) is not str or HEX.fullmatch(reference['sha256']) is None):
        raise EvidenceRejected('INVALID_REFERENCE')
    raw = read_local(root, reference['file'], MAX_FILE)
    digest = hashlib.sha256(raw).hexdigest()
    if digest != reference['sha256']:
        raise EvidenceRejected('DIGEST_MISMATCH')
    status, ids = parse_response(raw)
    return status, ids, digest


def evaluate_case(case, root):
    result = {'state': 'BLOCKED', 'reason': 'INVALID_CASE',
              'baseline_ids': [], 'candidate_ids': [], 'response_sha256': [],
              'trace_authenticity': 'NOT_VERIFIED', 'behavioral_gate': 'NOT_RUN',
              'independent_review': 'PENDING', 'human_approved': False, 'promotable': False}
    try:
        if (type(case) is not dict or set(case) - {'id', 'baseline', 'candidate', 'observed_product_ids', 'expected'}
                or not {'id', 'baseline', 'candidate'} <= set(case)
                or type(case['id']) is not str or not re.fullmatch(r'W[0-9]{2}', case['id'])):
            raise EvidenceRejected('INVALID_CASE')
        left, normal, left_sha = response(root, case['baseline'])
        right, candidate, right_sha = response(root, case['candidate'])
        result.update(baseline_ids=normal, candidate_ids=candidate, response_sha256=[left_sha, right_sha])
        if 'observed_product_ids' in case:
            observed = case['observed_product_ids']
            if (type(observed) is not dict or set(observed) != {'baseline', 'candidate'}
                    or check_ids(observed['baseline']) != normal or check_ids(observed['candidate']) != candidate):
                raise EvidenceRejected('OBSERVED_INVENTORY_MISMATCH')
        if left != 200 or right != 200:
            state, reason = 'INCONCLUSIVE', 'RESPONSE_STATUS'
        elif not normal or not candidate:
            state, reason = 'INCONCLUSIVE', 'MISSING_IDS'
        elif not set(normal) <= set(candidate):
            state, reason = 'INCONCLUSIVE', 'NON_MONOTONIC'
        elif set(candidate) - set(normal):
            state, reason = 'POSSIBLE_DIFFERENTIAL', 'EXPANDED_INVENTORY_NOT_SQLI_PROOF'
        else:
            state, reason = 'CONSISTENT', 'NO_INVENTORY_DIFFERENTIAL'
        result.update(state=state, reason=reason)
    except EvidenceRejected as exc:
        result.update(state='BLOCKED', reason=str(exc))
    return result


def run_suite(path, expected_sha256):
    path = Path(path).absolute()
    raw = read_local(path.parent, path.name, MAX_SUITE)
    digest = hashlib.sha256(raw).hexdigest()
    if type(expected_sha256) is not str or HEX.fullmatch(expected_sha256) is None or digest != expected_sha256:
        raise EvidenceRejected('SUITE_PIN_MISMATCH')
    try:
        suite = json.loads(raw.decode('utf-8'), object_pairs_hook=_unique, parse_constant=_reject_constant)
    except (ValueError, UnicodeError, RecursionError):
        raise EvidenceRejected('INVALID_SUITE') from None
    if (type(suite) is not dict or set(suite) != {'schema_version', 'source_kind', 'cases'}
            or type(suite['schema_version']) is not int or suite['schema_version'] != 2
            or suite['source_kind'] != 'SYNTHETIC_HTTP'
            or type(suite['cases']) is not list or not 1 <= len(suite['cases']) <= MAX_CASES):
        raise EvidenceRejected('INVALID_SUITE')
    rows = []; seen = set()
    for case in suite['cases']:
        if (type(case) is not dict or type(case.get('id')) is not str or not re.fullmatch(r'W[0-9]{2}', case['id']) or case['id'] in seen
                or type(case.get('expected')) is not dict
                or set(case['expected']) != {'state', 'reason', 'baseline_ids', 'candidate_ids'}):
            raise EvidenceRejected('INVALID_SUITE')
        expected = case['expected']
        if (expected['state'] not in ('CONSISTENT', 'INCONCLUSIVE', 'BLOCKED', 'POSSIBLE_DIFFERENTIAL')
                or type(expected['reason']) is not str or not re.fullmatch(r'[A-Z_]{1,64}', expected['reason'])):
            raise EvidenceRejected('INVALID_SUITE')
        check_ids(expected['baseline_ids'])
        check_ids(expected['candidate_ids'])
        seen.add(case['id'])
        output = evaluate_case(case, path.parent)
        matched = {key: output[key] for key in case['expected']} == case['expected']
        rows.append({'id': case['id'], 'oracle_match': matched, 'output': output})
    return {'schema_version': 2, 'suite_sha256': digest,
            'benchmark_state': 'BENCHMARK_READY_FOR_INDEPENDENT_REVIEW' if all(r['oracle_match'] for r in rows) else 'FAILED',
            'cases': rows, 'passed': sum(r['oracle_match'] for r in rows), 'total': len(rows),
            'oracle_authenticity': 'LOCAL_HASH_PIN_ONLY_NOT_INDEPENDENTLY_AUTHENTICATED',
            'skill_evaluator_integration': 'NOT_RUN', 'web_worker_enabled': False,
            'trace_authenticity': 'NOT_VERIFIED', 'behavioral_gate': 'NOT_RUN',
            'independent_review': 'PENDING', 'human_approved': False, 'promotable': False}


class SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, 'BLOCKED: invalid benchmark arguments; use --help\n')


def main(argv=None):
    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument('suite')
    parser.add_argument('--suite-sha256', required=True)
    args = parser.parse_args(argv)
    try:
        result = run_suite(args.suite, args.suite_sha256)
    except EvidenceRejected:
        print(json.dumps({'benchmark_state': 'BLOCKED', 'promotable': False}))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0 if result['benchmark_state'] == 'BENCHMARK_READY_FOR_INDEPENDENT_REVIEW' else 2


if __name__ == '__main__':
    raise SystemExit(main())
