#!/usr/bin/env python3
"""Offline Onda 10 model: injected transport only, synthetic order/C/tokens.

No HTTP transport, CLI execution option, cookie loading, purchase or mutation.
BOLA_CANDIDATE is a fixture classification, never a finding against a real host.
"""
import hashlib
import json
import re

BUYER = '3780339606'
THIRD_PARTY = '3780339608'
ORIGIN = 'https://meli.example.test'
USER_AGENT = ('Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 '
              '(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36')
CASES = (('C1', 'A'), ('C2', 'C'), ('X1', 'B'))
PRIVATE_FIELDS = ('order_items', 'total_amount', 'status', 'shipping')
RESOURCE_FIELDS = {'': PRIVATE_FIELDS, 'shipments': ('shipments',),
                   'billing_info': ('billing_info',), 'notes': ('notes', 'seller_notes')}
MAX_BYTES = 2_000_000


class HarnessError(Exception):
    """Fixed reason codes; no response/token values in errors."""


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def parse(raw):
    def pairs(items):
        obj = {}
        for key, value in items:
            if key in obj:
                raise HarnessError('DUPLICATE_KEY')
            obj[key] = value
        return obj
    def constant(_):
        raise HarnessError('INVALID_JSON')
    try:
        obj = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, UnicodeError):
        raise HarnessError('NON_JSON') from None
    if not isinstance(obj, dict):
        raise HarnessError('RESPONSE_SCHEMA')
    return obj


def private_values(obj, resource=''):
    values = {}
    for key in RESOURCE_FIELDS[resource]:
        value = obj.get(key)
        if value in (None, '', [], {}) or type(value) is bool:
            continue
        if key == 'status' and not isinstance(value, str):
            continue
        if resource:
            if key == 'billing_info':
                if not isinstance(value, dict):
                    continue
            elif not isinstance(value, list) or not all(isinstance(item, dict) and item for item in value):
                continue
        values[key] = value
    return values


def safe_denial(obj, status):
    codes = {'forbidden', 'not_found', 'not_owned_order', 'caller.id.invalid',
             'Forbidden', 'Not Found', 'Not owned order'}
    return (set(obj) <= {'error', 'message', 'status', 'cause'}
            and all(isinstance(obj[k], str) and obj[k] in codes for k in ('error', 'message') if k in obj)
            and ('status' not in obj or type(obj['status']) is int and obj['status'] == status)
            and ('cause' not in obj or obj['cause'] == []))


class Runner:
    def __init__(self, identities, sessions, order_id, send, *, resource=''):
        if not isinstance(resource, str) or resource not in RESOURCE_FIELDS:
            raise HarnessError('SUBRESOURCE_NOT_ALLOWED')
        if (set(identities) != {'A', 'C', 'B'} or identities['A'] != BUYER
                or identities['B'] != THIRD_PARTY
                or not isinstance(identities['C'], str) or not identities['C'].startswith('fixture-')
                or len(set(identities.values())) != 3):
            raise HarnessError('THREE_TEST_IDENTITIES_REQUIRED')
        if (set(sessions) != {'A', 'C', 'B'} or any(not isinstance(v, str)
                or not re.fullmatch(r'fixture-[A-Za-z0-9_-]+', v) for v in sessions.values())
                or len(set(sessions.values())) != 3):
            raise HarnessError('THREE_SYNTHETIC_SESSIONS_REQUIRED')
        if not isinstance(order_id, str) or not re.fullmatch(r'fixture-[A-Za-z0-9_-]+', order_id):
            raise HarnessError('SYNTHETIC_ORDER_REQUIRED')
        if not callable(send):
            raise HarnessError('FAKE_TRANSPORT_REQUIRED')
        self.identities, self.sessions = dict(identities), dict(sessions)
        self.order_id, self.send = order_id, send
        self.resource = resource
        self.events = []
        self.state = 'NEW'

    def request(self, who, path):
        # A fake response is (status, bytes). No default network-capable implementation.
        status, raw = self.send('GET', ORIGIN + path,
                                {'Authorization': 'Bearer ' + self.sessions[who],
                                 'Accept': 'application/json', 'Host': 'meli.example.test',
                                 'User-Agent': USER_AGENT}, None)
        if type(status) is not int or not 100 <= status <= 599 or not isinstance(raw, bytes):
            raise HarnessError('TRANSPORT_SCHEMA')
        if len(raw) > MAX_BYTES:
            raise HarnessError('RESPONSE_LIMIT')
        self.events.append({'session': who, 'status': status, 'state': self.state,
                            'response_sha256': hashlib.sha256(raw).hexdigest()})
        if status == 429 or status >= 500:
            raise HarnessError('RATE_LIMIT_OR_SERVER_ERROR')
        if 300 <= status < 400:
            raise HarnessError('REDIRECT_STOP')
        if any(marker in raw.lower() for marker in (b'captcha', b'cloudflare', b'"waf":true',
                                                     b'"waf": true', b'"real_charge":true',
                                                     b'"real_charge": true')):
            raise HarnessError('SAFETY_STOP')
        return status, {} if not raw and status in (403, 404) else parse(raw)

    def owned_order(self, obj):
        return (obj.get('order_id' if self.resource else 'id') == self.order_id
                and obj.get('buyer', {}).get('id') == BUYER
                and obj.get('seller', {}).get('id') == self.identities['C'])

    def run(self):
        if self.state != 'NEW':
            raise HarnessError('SINGLE_USE_RUNNER')
        rows = [{'case': label, 'session': who, 'verdict': 'NOT_RUN'} for label, who in CASES]
        outcome, reason = 'INCONCLUSIVE', 'INCOMPLETE'
        active_case = None
        try:
            self.state = 'IDENTITIES'
            for who in ('A', 'C', 'B'):
                status, obj = self.request(who, '/users/me')
                if status != 200 or obj.get('id') != self.identities[who] or obj.get('test_user') is not True:
                    raise HarnessError('IDENTITY_NOT_CONFIRMED')
                if who == 'C' and obj.get('new_test_user') is not True:
                    raise HarnessError('NEW_TEST_SELLER_REQUIRED')
            baseline = None
            for index, (label, who) in enumerate(CASES):
                active_case = index
                self.state = label
                path = '/orders/' + self.order_id + ('/' + self.resource if self.resource else '')
                status, obj = self.request(who, path)
                rows[index]['status'] = status
                values = private_values(obj, self.resource)
                if label != 'X1':
                    if self.resource == 'notes' and who == 'A' and obj.get('seller_notes'):
                        raise HarnessError('RESOURCE_SCOPE_FAILED')
                    if status != 200 or not self.owned_order(obj) or not values:
                        raise HarnessError('POSITIVE_CONTROL_FAILED')
                    if label == 'C1':
                        baseline = values
                    else:
                        shared = values.keys() & baseline.keys()
                        if not shared or any(encoded(values[k]) != encoded(baseline[k]) for k in shared):
                            raise HarnessError('CONTROLS_DISAGREE')
                        baseline.update(values)  # Include C-only private fields in the B comparison.
                    rows[index]['verdict'] = 'POSITIVE_CONTROL'
                    continue
                matched = any(k in baseline and encoded(v) == encoded(baseline[k]) for k, v in values.items())
                if self.owned_order(obj) and matched and status in (200, 403, 404):
                    outcome, reason = 'BOLA_CANDIDATE', 'BOUND_PRIVATE_ORDER_FIELDS'
                elif status in (403, 404) and not values and not self.owned_order(obj):
                    # Unknown/nested body data is not a demonstrated safe denial.
                    if safe_denial(obj, status):
                        outcome, reason = 'NEGATIVE', 'DENIED_WITHOUT_ORDER_DATA'
                    else:
                        outcome, reason = 'INCONCLUSIVE', 'UNRECOGNIZED_DENIAL_BODY'
                else:
                    outcome, reason = 'INCONCLUSIVE', 'NO_BOUND_PRIVATE_ORDER_DATA'
                rows[index]['verdict'] = outcome
            self.state = 'DONE'
        except HarnessError as exc:
            # Only local fixed codes are allowed; transport exceptions are sanitized below.
            allowed = {'DUPLICATE_KEY', 'INVALID_JSON', 'NON_JSON', 'RESPONSE_SCHEMA',
                       'TRANSPORT_SCHEMA', 'RESPONSE_LIMIT', 'RATE_LIMIT_OR_SERVER_ERROR',
                       'REDIRECT_STOP', 'SAFETY_STOP', 'IDENTITY_NOT_CONFIRMED',
                       'NEW_TEST_SELLER_REQUIRED', 'POSITIVE_CONTROL_FAILED', 'CONTROLS_DISAGREE'}
            allowed.add('RESOURCE_SCOPE_FAILED')
            reason = str(exc) if str(exc) in allowed else 'TRANSPORT_FAILED'
            self.state = 'STOPPED'
        except Exception:
            reason = 'TRANSPORT_FAILED'
            self.state = 'STOPPED'
        if self.state == 'STOPPED' and active_case is not None:
            rows[active_case]['verdict'] = 'INCONCLUSIVE'
        return {'schema': 'mitr3-three-session-offline-v1', 'offline': True, 'state': self.state,
                'resource': self.resource or 'order',
                'verdict': outcome, 'reason': reason, 'cases': rows, 'requests': list(self.events),
                'note': 'Synthetic fixture result only; no live authorization or vulnerability claim.'}
