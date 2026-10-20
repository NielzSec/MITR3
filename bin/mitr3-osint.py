#!/usr/bin/env python3
"""OSINT connectors: explicit send policy, dry-run and redacted local reports.

Returned material is unverified lead data, never RAG content or evidence.
"""
from __future__ import annotations

import argparse
import base64
from contextlib import closing
import datetime as dt
from email.utils import parsedate_to_datetime
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / 'reports/osint'
TIMEOUT = 15
MAX_BYTES = 2_000_000
NOTICE = 'unverified_lead_not_evidence'
EMAIL = re.compile(r'[A-Za-z0-9.!#$%&\'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+')
PHONE = re.compile(r'(?<!\w)\+\d[\d ()-]{6,}\d(?!\w)')
SENSITIVE_KEYS = re.compile(r'password|passwd|secret|token|authorization|api.?key|credential|cookie|^key$', re.I)
PII_FIELDS = {'email': 'email', 'email_address': 'email', 'phone': 'phone', 'phone_number': 'phone',
              'name': 'name', 'first_name': 'name', 'last_name': 'name', 'full_name': 'name'}


def source(base_url, category, risk, types, keys=(), *, optional_key=False, health=None, manual=(), follow=False):
    return dict(base_url=base_url, category=category, risk=risk, types=types, keys=keys,
                optional_key=optional_key, health=health, manual=manual, follow_redirects=follow)


# Each key tuple contains a canonical name and the user's short env alias.
CATALOG = {
    'crt.sh': source('https://crt.sh', 'public', 'public', ['domain']),
    # Redirector by design: serves via per-registry redirects (e.g. verisign, afrinic).
    'rdap.org': source('https://rdap.org', 'public', 'public', ['domain', 'ip'], follow=True),
    'urlscan.io': source('https://urlscan.io', 'public', 'public', ['domain', 'ip', 'url'],
                         [('MITR3_OSINT_URLSCAN_KEY', 'URLSCAN')], optional_key=True),
    'openarchive-status': source('https://status.openarchivex.net', 'public', 'public', [], health='/'),
    'virustotal': source('https://www.virustotal.com', 'paid', 'paid', ['ip', 'domain', 'hash'],
                         [('MITR3_OSINT_VIRUSTOTAL_KEY', 'VIRUSTOTAL')]),
    'shodan': source('https://api.shodan.io', 'paid', 'paid', ['ip', 'domain'],
                     [('MITR3_OSINT_SHODAN_KEY', 'SHODAN')]),
    'censys': source('https://search.censys.io', 'paid', 'paid', ['ip', 'domain'],
                     [('MITR3_OSINT_CENSYS_ID', 'CENSYS_ID'), ('MITR3_OSINT_CENSYS_SECRET', 'CENSYS_SECRET')]),
    'greynoise': source('https://api.greynoise.io', 'paid', 'paid', ['ip'],
                        [('MITR3_OSINT_GREYNOISE_KEY', 'GREYNOISE')]),
    'haveibeenpwned': source('https://haveibeenpwned.com', 'paid', 'paid', ['email'],
                            [('MITR3_OSINT_HIBP_KEY', 'HIBP')]),
    'dehashed': source('https://api.dehashed.com', 'paid', 'broker', ['email', 'username', 'ip', 'hash'],
                       [('MITR3_OSINT_DEHASHED_KEY', 'DEHASHED')]),
    'leakcheck': source('https://leakcheck.io', 'paid', 'broker', ['email', 'username'],
                        [('MITR3_OSINT_LEAKCHECK_KEY', 'LEAKCHECK')]),
    'intelligencex': source('https://2.intelx.io', 'paid', 'broker', ['email', 'domain', 'ip'],
                            [('MITR3_OSINT_INTELX_KEY', 'INTELX')]),
    'openarchive': source('https://api.openarchivex.net/api/v2', 'paid', 'broker',
                          ['email', 'username', 'ip', 'hash', 'domain', 'phone'],
                          [('MITR3_OSINT_OPENARCHIVE_KEY', 'OPENARCHIVE')]),
    'telegram-manual': source('https://t.me', 'manual', 'public', [], manual=[
        {'name': 'UserInfoBot', 'url': 'https://t.me/userinfobot'},
        {'name': 'Bellingcat', 'url': 'https://t.me/bellingcat'}]),
    'forums-manual': source('https://osint.team', 'manual', 'public', [], manual=[
        {'name': 'OSINT Team', 'url': 'https://osint.team'},
        {'name': 'r/OSINT', 'url': 'https://www.reddit.com/r/OSINT/'}]),
}
ALIASES = {'crtsh': 'crt.sh', 'rdap': 'rdap.org', 'urlscan': 'urlscan.io',
           'hibp': 'haveibeenpwned', 'intelx': 'intelligencex',
           'status.openarchivex.net': 'openarchive-status'}


class PolicyError(Exception):
    """Fixed error code only, never provider text or credentials."""


def fail(code):
    raise PolicyError(code)


def resolve(identifier):
    identifier = ALIASES.get(identifier, identifier)
    if identifier not in CATALOG:
        fail('UNKNOWN_SOURCE')
    return identifier, CATALOG[identifier]


def credentials(spec):
    return [next((os.environ[name] for name in names if os.environ.get(name)), '') for names in spec['keys']]


def sources():
    return [dict(id=ident, category=spec['category'], risk=spec['risk'], types=spec['types'],
                 key_configured=bool(spec['keys']) and all(credentials(spec)),
                 key_required=bool(spec['keys']) and not spec['optional_key'],
                 key_env=[list(names) for names in spec['keys']], base_url=spec['base_url'],
                 health_only=bool(spec['health']), manual=list(spec['manual']))
            for ident, spec in CATALOG.items()]


def mask_value(kind, value):
    if kind == 'email':
        local, _, domain = value.partition('@')
        head, dot, suffix = domain.rpartition('.')
        return local[:2] + '***@' + (head or domain)[:2] + '***' + (dot + suffix if dot else '')
    if kind == 'phone':
        digits = re.sub(r'\D', '', value)
        return ('+' if value.startswith('+') else '') + digits[:2] + '**...'
    if kind in {'name', 'username'}:
        return value[:2] + '***'
    return value


def sanitize(value, kind='', query='', *, reveal=False, secrets=()):
    """Redact recursively, including echoed queries, purpose, keys and encodings.

    Credentials are never revealed; --reveal affects personal data on stdout only.
    """
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            safe_key = sanitize(str(key), kind, query, reveal=reveal, secrets=secrets)
            if SENSITIVE_KEYS.search(str(key)):
                result[safe_key] = '[REDACTED:SECRET]'
                continue
            pii = PII_FIELDS.get(str(key).lower())
            if pii and not reveal and isinstance(item, str):
                item = mask_value(pii, item)
            result[safe_key] = sanitize(item, kind, query, reveal=reveal, secrets=secrets)
        return result
    if isinstance(value, list):
        return [sanitize(v, kind, query, reveal=reveal, secrets=secrets) for v in value]
    if not isinstance(value, str):
        return value
    for secret in sorted((s for s in secrets if s), key=len, reverse=True):
        for encoded in {secret, urllib.parse.quote(secret, safe=''), urllib.parse.quote_plus(secret)}:
            value = value.replace(encoded, '[REDACTED:SECRET]')
    if reveal:
        return value
    if query and kind in {'email', 'phone', 'name', 'username'}:
        for original in {query, urllib.parse.quote(query, safe=''), urllib.parse.quote_plus(query)}:
            value = value.replace(original, mask_value(kind, query))
    value = EMAIL.sub(lambda m: mask_value('email', m[0]), value)
    value = PHONE.sub(lambda m: mask_value('phone', m[0]), value)
    return value


def validate_value(kind, value):
    if not isinstance(value, str) or not value or len(value) > 2048 or any(ord(c) < 32 or ord(c) == 127 for c in value):
        fail('INVALID_VALUE')
    if kind == 'ip':
        try:
            ipaddress.ip_address(value)
        except ValueError:
            fail('INVALID_VALUE')
    elif kind == 'domain':
        try:
            ascii_domain = value.encode('idna').decode('ascii')
        except UnicodeError:
            fail('INVALID_VALUE')
        if len(ascii_domain) > 253 or not re.fullmatch(r'(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}', ascii_domain):
            fail('INVALID_VALUE')
    elif kind == 'email' and not EMAIL.fullmatch(value):
        fail('INVALID_VALUE')
    elif kind == 'phone' and not re.fullmatch(r'\+?[0-9 ()-]{7,25}', value):
        fail('INVALID_VALUE')
    elif kind == 'hash' and not re.fullmatch(r'(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}|[a-fA-F0-9]{128})', value):
        fail('INVALID_VALUE')
    elif kind == 'username' and not re.fullmatch(r'[\w.-]{1,128}', value):
        fail('INVALID_VALUE')
    elif kind == 'url':
        try:
            url = urllib.parse.urlsplit(value)
            if url.scheme not in {'http', 'https'} or not url.hostname or url.username or url.password:
                fail('INVALID_VALUE')
        except ValueError:
            fail('INVALID_VALUE')


def check_destination(url, spec):
    follow = bool(spec.get('follow_redirects'))
    try:
        actual, base = urllib.parse.urlsplit(url), urllib.parse.urlsplit(spec['base_url'])
        if (actual.scheme != 'https' or base.scheme != 'https' or not actual.hostname
                or (not follow and actual.hostname != base.hostname) or actual.port not in (None, 443)
                or actual.username or actual.password or actual.fragment
                or any(ord(c) < 32 for c in url)):
            fail('HOST_BLOCKED')
    except ValueError:
        fail('HOST_BLOCKED')


def build_request(identifier, kind, value, *, wire=False):
    ident, spec = resolve(identifier)
    if spec['category'] == 'manual':
        fail('MANUAL_ONLY')
    if spec['health']:
        fail('HEALTH_ONLY')
    if kind not in spec['types']:
        fail('TYPE_UNSUPPORTED')
    validate_value(kind, value)
    keys = credentials(spec) if wire else ['${' + names[0] + '}' for names in spec['keys']]
    headers = {'Accept': 'application/json', 'User-Agent': 'MITR3-OSINT/1.0'}
    params, body, path = {}, None, ''
    quoted = urllib.parse.quote(value, safe='')
    if ident == 'crt.sh':
        path, params = '/', {'q': value, 'output': 'json'}
    elif ident == 'rdap.org':
        path = '/' + kind + '/' + quoted
    elif ident == 'urlscan.io':
        field = {'domain': 'domain', 'ip': 'ip', 'url': 'page.url'}[kind]
        path, params = '/api/v1/search/', {'q': field + ':' + json.dumps(value), 'size': 20}
        if keys and (not wire or keys[0]):
            headers['api-key'] = keys[0]
    elif ident == 'virustotal':
        path = '/api/v3/' + {'ip': 'ip_addresses', 'domain': 'domains', 'hash': 'files'}[kind] + '/' + quoted
        headers['x-apikey'] = keys[0]
    elif ident == 'shodan':
        path = ('/shodan/host/' if kind == 'ip' else '/dns/domain/') + quoted
        params = {'key': keys[0]}
    elif ident == 'censys':
        path = '/api/v2/hosts/' + quoted if kind == 'ip' else '/api/v2/hosts/search'
        if kind == 'domain':
            params = {'q': 'services.tls.certificates.leaf_data.names:' + json.dumps(value), 'per_page': 20}
        headers['Authorization'] = ('Basic ' + base64.b64encode(':'.join(keys).encode()).decode()) if wire else 'Basic ${MITR3_OSINT_CENSYS_ID:MITR3_OSINT_CENSYS_SECRET}'
    elif ident == 'greynoise':
        path, headers['key'] = '/v3/community/' + quoted, keys[0]
    elif ident == 'haveibeenpwned':
        path, headers['hibp-api-key'] = '/api/v3/breachedaccount/' + quoted, keys[0]
    elif ident == 'dehashed':
        path, headers['Dehashed-Api-Key'] = '/v2/search', keys[0]
        field = {'ip': 'ip_address', 'hash': 'hashed_password'}.get(kind, kind)
        body = {'query': field + ':' + json.dumps(value), 'page': 1, 'size': 20, 'regex': False, 'wildcard': False}
    elif ident == 'leakcheck':
        path, params, headers['X-API-Key'] = '/api/v2/query/' + quoted, {'type': kind, 'limit': 20}, keys[0]
    elif ident == 'intelligencex':
        path, headers['x-key'] = '/intelligent/search', keys[0]
        body = {'term': value, 'maxresults': 20, 'timeout': 5, 'sort': 2, 'media': 0}
    elif ident == 'openarchive':
        path, params, headers['Authorization'] = '/search', {'query': value, 'type': kind}, 'Bearer ' + keys[0]
    if body is not None:
        headers['Content-Type'] = 'application/json'
    url = spec['base_url'].rstrip('/') + path
    if params:
        url += '?' + urllib.parse.urlencode(params)
    check_destination(url, spec)
    return {'url': url, 'method': 'POST' if body is not None else 'GET', 'headers': headers, 'body': body}


def plan(identifier, kind, value):
    ident, spec = resolve(identifier)
    # Build with a masked personal selector: neither URL nor body can expose it.
    request = build_request(ident, kind, value)
    masked = mask_value(kind, value)
    # Sanitize both selector encodings; placeholders never contain actual keys.
    if masked != value:
        request['url'] = request['url'].replace(urllib.parse.quote(value, safe=''), urllib.parse.quote(masked, safe=''))
    return dict(source=ident, risk=spec['risk'], dry_run=True, sent=False,
                query={'type': kind, 'value': masked}, request=sanitize(request, kind, value),
                key_configured=bool(spec['keys']) and all(credentials(spec)), notice=NOTICE, rag_eligible=False)


def enforce(identifier, kind, value, purpose, subject, allow_send):
    if not allow_send:
        fail('CONFIRM_REQUIRED')
    ident, spec = resolve(identifier)
    if spec['risk'] == 'broker' and (os.environ.get('MITR3_OSINT_ALLOW_BROKERS') != '1' or len(purpose.strip()) < 8):
        fail('BROKER_BLOCKED')
    if (kind in {'email', 'phone', 'name'} or EMAIL.search(value) or PHONE.search(value) or ident == 'openarchive') and subject not in {'self', 'authorized'}:
        fail('SUBJECT_REQUIRED')
    if not purpose.strip():
        fail('PURPOSE_REQUIRED')
    return ident, spec


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        fp.close()
        error = PolicyError('REDIRECT_BLOCKED')
        error.http_status = code
        raise error


class FollowRedirect(urllib.request.HTTPRedirectHandler):
    """Per-hop validated follow for redirector-by-design sources (rdap.org):
    https only, no credentials, capped hops; destination host may differ
    from base_url because the redirector's purpose is delegating to registries."""

    MAX_HOPS = 3

    def __init__(self):
        self.hops = 0

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        fp.close()
        self.hops += 1
        if self.hops > self.MAX_HOPS:
            error = PolicyError('REDIRECT_LOOP')
            error.http_status = code
            raise error
        try:
            parts = urllib.parse.urlsplit(newurl)
            bad = (parts.scheme != 'https' or parts.port not in (None, 443)
                   or parts.username or parts.password or not parts.hostname
                   or parts.fragment or any(ord(c) < 32 for c in newurl))
        except ValueError:
            bad = True
        if bad:
            error = PolicyError('HOST_BLOCKED')
            error.http_status = code
            raise error
        return urllib.request.Request(newurl, data=req.data, headers=req.headers, method=req.get_method())


def urlopen(request, timeout=TIMEOUT, follow=False):
    # Dedicated opener, no global mutation; redirects/auth retries never send again.
    handler = FollowRedirect() if follow else NoRedirect()
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), handler).open(request, timeout=timeout)


def retry_after(raw):
    if not raw:
        return None
    raw = str(raw).strip()
    try:
        seconds = max(0, int(raw))
    except ValueError:
        try:
            stamp = parsedate_to_datetime(raw)
            if stamp.tzinfo is None:
                return None
            seconds = max(0, int((stamp - dt.datetime.now(dt.timezone.utc)).total_seconds()) + 1)
        except (ValueError, TypeError, OverflowError):
            return None
    return {'seconds': seconds, 'not_before_utc': (dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=min(seconds, 315360000))).isoformat()}


def transmit(request, spec):
    check_destination(request['url'], spec)
    data = None if request['body'] is None else json.dumps(request['body']).encode()
    req = urllib.request.Request(request['url'], data=data, headers=request['headers'], method=request['method'])
    started = time.monotonic()
    response = None
    status, code, payload, retry = None, None, None, None
    try:
        try:
            response = urlopen(req, timeout=TIMEOUT, follow=spec.get('follow_redirects', False))
        except urllib.error.HTTPError as exc:
            response = exc  # A response too: close it and save redacted status/body.
        with closing(response):
            check_destination(response.geturl(), spec)
            status = response.status if hasattr(response, 'status') else response.code
            if 300 <= status < 400:
                code = 'REDIRECT_BLOCKED'
            if status == 429:
                code, retry = 'RATE_LIMITED', retry_after(response.headers.get('Retry-After'))
            raw = response.read(MAX_BYTES + 1)
            if len(raw) > MAX_BYTES:
                code = 'RESPONSE_TOO_LARGE'
            elif not code:
                try:
                    payload = json.loads(raw)
                except (ValueError, UnicodeError):
                    payload = raw.decode('utf-8', errors='replace')
            if status >= 400 and code is None:
                code = 'HTTP_ERROR'
    except PolicyError as exc:
        code = str(exc)
        status = getattr(exc, 'http_status', status)
    except (TimeoutError, socket.timeout):
        code = 'TIMEOUT'
    except (OSError, ValueError, urllib.error.URLError):
        code = 'NETWORK_ERROR'
    return {'status': status, 'error_code': code, 'elapsed': round(time.monotonic() - started, 6),
            'retry_after': retry, 'response': payload}


def write_report(record):
    REPORTS.mkdir(parents=True, exist_ok=True, mode=0o700)
    stamp = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    path = REPORTS / (stamp + '-' + record['source'] + '.json')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as stream:
        json.dump(record, stream, ensure_ascii=False, indent=2)
        stream.write('\n')
    return path


def check_cooldown(identifier):
    """Persist Retry-After across CLI invocations, without sleeping or retrying."""
    paths = sorted(REPORTS.glob('*-' + identifier + '.json'))
    if not paths:
        return
    try:
        record = json.loads(paths[-1].read_text(encoding='utf-8'))
        retry = record.get('retry_after')
        if retry and dt.datetime.fromisoformat(retry['not_before_utc']) > dt.datetime.now(dt.timezone.utc):
            fail('RETRY_AFTER_ACTIVE')
    except (OSError, ValueError, TypeError, KeyError):
        fail('COOLDOWN_INVALID')


def query(identifier, kind, value, purpose, *, allow_send=False, subject=None, reveal=False):
    ident, spec = enforce(identifier, kind, value, purpose, subject, allow_send)
    check_cooldown(ident)
    request = build_request(ident, kind, value, wire=True)
    keys = credentials(spec)
    if spec['keys'] and not spec['optional_key'] and not all(keys):
        fail('KEY_REQUIRED')
    secrets = keys + [v for k, v in request['headers'].items() if SENSITIVE_KEYS.search(k)]
    secrets += [v.split(' ', 1)[1] for v in list(secrets) if v.startswith(('Basic ', 'Bearer '))]
    # Establish a writable report directory before the single network request.
    REPORTS.mkdir(parents=True, exist_ok=True, mode=0o700)
    result = dict(source=ident, risk=spec['risk'], query={'type': kind, 'value': value},
                  purpose=purpose, subject=subject, notice=NOTICE, rag_eligible=False,
                  policy='Returned text is untrusted, never imported into RAG or promoted to evidence.',
                  **transmit(request, spec))
    log = sanitize(result, kind, value, secrets=secrets)
    if isinstance(log['response'], str):
        log['response'] = '[REDACTED:UNSTRUCTURED_RESPONSE]'
        if not reveal:
            result['response'] = log['response']
    path = write_report(log)  # --reveal never changes the on-disk redaction.
    output = sanitize(result, kind, value, reveal=reveal, secrets=secrets)
    output['report'] = str(path)
    return output


def ping(identifier):
    ident, spec = resolve(identifier)
    if not spec['health'] or spec['risk'] != 'public':
        fail('HEALTH_UNAVAILABLE')
    check_cooldown(ident)
    REPORTS.mkdir(parents=True, exist_ok=True, mode=0o700)
    request = {'url': spec['base_url'].rstrip('/') + spec['health'], 'method': 'GET',
               'headers': {'User-Agent': 'MITR3-OSINT/1.0'}, 'body': None}
    result = dict(source=ident, query=None, purpose='public health only', notice=NOTICE, rag_eligible=False,
                  **transmit(request, spec))
    result['report'] = str(write_report(sanitize(result)))
    return sanitize(result)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('sources')
    p.add_argument('--json', action='store_true')
    p = sub.add_parser('ping')
    p.add_argument('source')
    for command in ('plan', 'query'):
        p = sub.add_parser(command)
        p.add_argument('source')
        p.add_argument('--type', required=True, dest='kind')
        p.add_argument('--value', required=True)
        if command == 'query':
            p.add_argument('--purpose', required=True)
            p.add_argument('--allow-send', action='store_true')
            p.add_argument('--subject', choices=['self', 'authorized'])
            p.add_argument('--reveal', action='store_true')
    args = parser.parse_args(argv)
    try:
        if args.command == 'sources':
            result = sources()
        elif args.command == 'plan':
            result = plan(args.source, args.kind, args.value)
        elif args.command == 'query':
            result = query(args.source, args.kind, args.value, args.purpose,
                           allow_send=args.allow_send, subject=args.subject, reveal=args.reveal)
        else:
            result = ping(args.source)
    except PolicyError as exc:
        result = {'error_code': str(exc), 'sent': False, 'notice': NOTICE}
    except Exception:
        result = {'error_code': 'LOCAL_ERROR', 'notice': NOTICE}
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 1 if isinstance(result, dict) and result.get('error_code') else 0


if __name__ == '__main__':
    raise SystemExit(main())
