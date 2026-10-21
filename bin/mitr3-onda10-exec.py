#!/usr/bin/env python3
"""Onda 10 runner. Default: offline dry-run of all nine templates.

--live is for OpenCode after external QA/JEV authorization. No retries/redirects.
Session ledger persists across invocations; operator must include prior setup
traffic in its count before live use. Never reset it to bypass the wave budget.
Raw response artifacts are PRIVATE and must be redacted before sharing.
"""
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
ORDER_ID = '2000015638831799'
HOST = 'api.mercadolibre.com'
OUTPUT = ROOT / 'reports/onda10_execution'
TOKENS = Path('/tmp/opencode')
LIMIT = 2_000_000


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    obj = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj


G = module('onda10_gate', ROOT / 'reviews/gpt6/h1_meli_onda10/staging_gate.py')
H = module('onda10_model', ROOT / 'bin/mitr3-threesession.py')
L = module('onda10_rate', ROOT / 'tools/h1_rate_ledger.py')


class Stop(Exception):
    """Only fixed public reason codes, never credentials or response values."""


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def utc():
    return datetime.now(timezone.utc).isoformat()


def private_dir(path):
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise Stop('PRIVATE_DIRECTORY_REQUIRED')


def read_private(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise Stop('PRIVATE_FILE_REQUIRED')
        raw = stream.read(LIMIT + 1)
        if len(raw) > LIMIT:
            raise Stop('FILE_LIMIT')
        return raw


def write_new(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def prepare(lane=G.LANE, token_dir=TOKENS, *, order_id=ORDER_ID):
    if not isinstance(order_id, str) or not re.fullmatch(r'[0-9]{8,}', order_id):
        raise Stop('INVALID_ORDER_ID')
    checked = G.evaluate(lane)
    if checked['status'] != 'PASS_STRUCTURAL_ONLY':
        raise Stop('STAGING_GATE_BLOCK')
    tokens, identities = {}, {}
    for actor in 'ACB':
        obj = H.parse(read_private(token_dir / f'token_{actor}.json'))
        token = obj.get('access_token')
        identity = obj.get('user_id')
        if not isinstance(token, str) or not re.fullmatch(r'[A-Za-z0-9._~+/=-]{1,2048}', token):
            raise Stop('TOKEN_FORMAT')
        if type(identity) not in (str, int) or not re.fullmatch(r'[0-9]+', str(identity)):
            raise Stop('TOKEN_IDENTITY_MISSING')
        tokens[actor], identities[actor] = token, str(identity)
    if len(set(tokens.values())) != 3 or len(set(identities.values())) != 3:
        raise Stop('IDENTITIES_NOT_ISOLATED')
    if identities['A'] != H.BUYER or identities['B'] != H.THIRD_PARTY:
        raise Stop('IDENTITY_MAPPING')
    requests = {}
    for case, (filename, actor, resource) in G.FILES.items():
        raw = (lane / 'templates' / filename).read_bytes()
        if digest(raw) != checked['files'][case]['sha256']:
            raise Stop('TEMPLATE_CHANGED')
        raw = raw.replace(b'$ORDER_ID', order_id.encode()).replace(
            ('$AUTH_TOKEN_' + actor).encode(), tokens[actor].encode())
        route = '/orders/' + order_id + ('/' + resource if resource else '')
        lines = raw.split(b'\r\n')
        if (len(raw) > G.MAX_BYTES or len(lines) != 7 or lines[-2:] != [b'', b'']
                or lines[0] != f'GET {route} HTTP/1.1'.encode()
                or b'$' in raw or b'\n' in raw.replace(b'\r\n', b'')
                or b'\r' in raw.replace(b'\r\n', b'')):
            raise Stop('INTERPOLATED_FRAMING')
        requests[case] = raw
    return requests, identities


@contextmanager
def session_lock(output):
    private_dir(output)
    path = output / '.runner.lock'
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Stop('RUNNER_ALREADY_ACTIVE') from None
        yield
    finally:
        os.close(fd)


class Budget:
    def __init__(self, output):
        self.path = output / 'session_ledger.json'
        if not self.path.exists():
            G.write_private(self.path, {'count': 0, 'events': [], 'stopped': False})
        self.state = H.parse(read_private(self.path))
        if (type(self.state.get('count')) is not int or self.state['count'] < 0
                or not isinstance(self.state.get('events'), list)
                or self.state['count'] < len(self.state.get('events', []))
                or type(self.state.get('stopped')) is not bool):
            raise Stop('SESSION_LEDGER_INVALID')
        if self.state['stopped']:
            raise Stop('SESSION_STOPPED')

    def reserve(self, case):
        # The legacy loader skips corrupt lines: validate first, then use its window.
        ledger = Path(L.LEDGER)
        records = []
        if ledger.exists():
            for line in ledger.read_bytes().splitlines():
                if not line.strip():
                    continue
                rec = H.parse(line)
                try:
                    timestamp = datetime.fromisoformat(rec['ts'])
                    valid = (timestamp.tzinfo is not None and isinstance(rec['host'], str)
                             and type(rec.get('count', 1)) is int and rec.get('count', 1) >= 0
                             and type(rec['status']) is int)
                except (KeyError, TypeError, ValueError):
                    valid = False
                if not valid:
                    raise Stop('RATE_LEDGER_INVALID')
                records.append(rec)
        recent = L.window(records)
        if any(r['status'] == 429 or (r['status'] == 403 and not r.get('expected_403', False)) for r in recent):
            raise Stop('RATE_LEDGER_STOP')
        if sum(r.get('count', 1) for r in recent if r['host'] == HOST) >= 60:
            raise Stop('HOST_BUDGET_EXHAUSTED')
        if self.state['count'] >= 10:
            raise Stop('WAVE_BUDGET_EXHAUSTED')
        self.state['count'] += 1
        self.state['events'].append({'case': case, 'ts': utc(), 'state': 'RESERVED'})
        # Persist before touching network, counting uncertain/failed sends conservatively.
        self.state['stopped'] = True
        G.write_private(self.path, self.state)
        self.append_rate({'ts': utc(), 'actor': 'opencode', 'host': HOST, 'method': 'GET',
                  'path': '/orders/$ORDER_ID', 'status': 0, 'count': 1,
                  'note': 'onda10-' + case, 'estimated': True, 'expected_403': False})

    @staticmethod
    def append_rate(record):
        L.append(record)
        with open(L.LEDGER, 'rb') as stream:
            os.fsync(stream.fileno())

    def observe(self, case, status):
        self.append_rate({'ts': utc(), 'actor': 'opencode', 'host': HOST, 'method': 'GET',
                  'path': '/orders/$ORDER_ID', 'status': status, 'count': 0,
                  'note': 'onda10-' + case, 'estimated': False,
                  'expected_403': case.startswith('X1') and status == 403})

    def finish(self, status, stop):
        self.state['events'][-1].update(status=status, state='STOPPED' if stop else 'RECORDED')
        self.state['stopped'] = stop
        G.write_private(self.path, self.state)


def send(raw):
    """Single verified-TLS request, exact staged bytes; no proxy/retry/redirect."""
    conn = http.client.HTTPSConnection(HOST, timeout=20)
    try:
        conn.connect()
        conn.sock.sendall(raw)
        response = http.client.HTTPResponse(conn.sock)
        response.begin()
        body = response.read(LIMIT + 1)
        headers = response.getheaders()
        return response.status, headers, body
    finally:
        conn.close()


def classify(case, resource, status, headers, raw, identities, baseline, *, order_id=ORDER_ID):
    scan = raw.lower() + json.dumps(headers).lower().encode()
    if status == 429 or status >= 500 or 300 <= status < 400:
        raise Stop('HTTP_SAFETY_STOP')
    if any(marker in scan for marker in (b'captcha', b'cloudflare', b'"waf"', b'real_charge', b'access denied', b'cf-mitigated')):
        raise Stop('WAF_OR_CHARGE_STOP')
    if len(raw) > LIMIT:
        raise Stop('RESPONSE_LIMIT')
    obj = {} if not raw and status in (403, 404) else H.parse(raw)
    key = 'order_id' if resource else 'id'
    def ident(value):
        return str(value) if type(value) in (int, str) else ''
    buyer, seller = obj.get('buyer'), obj.get('seller')
    owned = (ident(obj.get(key)) == order_id and isinstance(buyer, dict) and isinstance(seller, dict)
             and ident(buyer.get('id')) == identities['A'] and ident(seller.get('id')) == identities['C'])
    values = H.private_values(obj, resource)
    if case != 'X1':
        if status != 200 or not owned or not values:
            raise Stop('POSITIVE_CONTROL_FAILED')
        if case == 'C2':
            shared = values.keys() & baseline.keys()
            if not shared or any(H.encoded(values[k]) != H.encoded(baseline[k]) for k in shared):
                raise Stop('CONTROLS_DISAGREE')
        baseline.update(values)
        return 'POSITIVE_CONTROL'
    matched = any(k in baseline and H.encoded(v) == H.encoded(baseline[k]) for k, v in values.items())
    if owned and matched and status in (200, 403, 404):
        return 'BOLA_CANDIDATE'
    if status in (403, 404) and not values and not owned and H.safe_denial(obj, status):
        return 'NEGATIVE'
    # Only a known empty/metadata shell is a demonstrated no-data response.
    if status == 200 and not values and set(obj) <= {key, 'status'} and not obj.get('status'):
        return 'NEGATIVE_SHELL'
    raise Stop('INCONCLUSIVE_RESPONSE')


def execute(requests, identities, suite, output=OUTPUT, transport=send, sleep=time.sleep, *, order_id=ORDER_ID):
    with session_lock(output):
        budget = Budget(output)
        run = output / datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
        private_dir(run)
        summary = {'started': utc(), 'suite': suite, 'state': 'STOPPED', 'cases': []}
        resources = ('',) if suite == 'base' else ('', 'shipments', 'billing_info')
        try:
            for resource in resources:
                baseline = {}
                for case in ('C1', 'C2', 'X1'):
                    label = case + ('_' + resource if resource else '')
                    if summary['cases']:
                        sleep(1.5)
                    budget.reserve(label)
                    status, headers, raw = transport(requests[label])
                    write_new(run / (label + '.body.raw'), raw)
                    # Header values are preserved in JSON; body is undecoded response bytes.
                    write_new(run / (label + '.headers.json'), H.encoded({'status': status, 'headers': headers, 'ts': utc()}))
                    budget.observe(label, status)
                    row = {'case': label, 'status': status, 'verdict': 'INCONCLUSIVE'}
                    summary['cases'].append(row)
                    verdict = classify(case, resource, status, headers, raw, identities, baseline, order_id=order_id)
                    row['verdict'] = verdict
                    budget.finish(status, verdict == 'BOLA_CANDIDATE')
                    if verdict == 'BOLA_CANDIDATE':
                        raise Stop('CANDIDATE_REQUIRES_REVIEW')
            summary['state'] = 'COMPLETE'
        except Stop as exc:
            summary['reason'] = str(exc)
        except Exception:
            summary['reason'] = 'EXECUTION_FAILED'
        finally:
            summary['finished'] = utc()
            G.write_private(run / 'summary.json', summary)
            lines = [f'{digest(p.read_bytes())}  {p.name}\n' for p in sorted(run.iterdir()) if p.is_file()]
            write_new(run / 'SHA256SUMS', ''.join(lines).encode())
            write_new(run / 'SHA256SUMS.sha256',
                      (digest((run / 'SHA256SUMS').read_bytes()) + '  SHA256SUMS\n').encode())
        return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--dry-run', action='store_true')
    mode.add_argument('--live', action='store_true')
    parser.add_argument('--suite', choices=('base', 'all'), default='base')
    parser.add_argument('--order-id', default=ORDER_ID)
    args = parser.parse_args(argv)
    try:
        requests, identities = prepare(order_id=args.order_id)
        if not args.live:
            print('DRY_RUN_PASS templates=9 network_calls=0 suite=' + args.suite)
            return 0
        result = execute(requests, identities, args.suite, order_id=args.order_id)
        print('ONDA10', result['state'], result.get('reason', 'COMPLETE'))
        return 0 if result['state'] == 'COMPLETE' else 2
    except Stop as exc:
        print('ONDA10 BLOCK', str(exc))
    except Exception:
        print('ONDA10 BLOCK PREFLIGHT_FAILED')
    return 2


if __name__ == '__main__':
    sys.exit(main())
