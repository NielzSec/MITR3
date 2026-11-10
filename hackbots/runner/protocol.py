"""Bounded framed JSON over a single-reader pipe; no subprocess or fixture execution."""
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
import json
import math
import os
import re
import select
import struct
import time

from .policies import Policy

PROTOCOL_VERSION = 1
REQUEST_FRAME_BYTES = 65_536
RESPONSE_FRAME_BYTES = 131_072
MAX_DEPTH = 8
REQUEST_ID = re.compile(r'[A-Za-z0-9_-]{1,32}\Z')


class ProtocolViolation(ValueError):
    def __init__(self, code='E_PROTOCOL'):
        self.code = code
        super().__init__(code)


class RequestRejected(ValueError):
    """Recoverable only while the future broker's rejection budget permits."""
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _validate_json(value, depth=0, max_depth=MAX_DEPTH):
    if depth > max_depth:
        raise ProtocolViolation()
    if type(value) is dict:
        for key, item in value.items():
            if type(key) is not str:
                raise ProtocolViolation()
            key.encode('utf-8')
            _validate_json(item, depth + 1, max_depth)
    elif type(value) is list:
        for item in value:
            _validate_json(item, depth + 1, max_depth)
    elif type(value) is str:
        value.encode('utf-8')
    elif type(value) is Decimal:
        if not value.is_finite():
            raise ProtocolViolation()
    elif type(value) is float:
        if not math.isfinite(value):
            raise ProtocolViolation()
    elif value is not None and type(value) not in (int, bool):
        raise ProtocolViolation()


def _serialize(obj, max_depth=MAX_DEPTH):
    try:
        _validate_json(obj, max_depth=max_depth)
        def emit(value):
            if type(value) is Decimal:
                token = str(value)
                # Preserve JSON decimal type even when Decimal normalizes 1e0 to 1.
                return token if any(c in token for c in '.eE') else token + '.0' 
            if type(value) is dict:
                return '{' + ','.join(json.dumps(k, ensure_ascii=False) + ':' + emit(v)
                                      for k, v in value.items()) + '}'
            if type(value) is list:
                return '[' + ','.join(emit(v) for v in value) + ']'
            return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(',', ':'))
        return emit(obj).encode('utf-8')
    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError, InvalidOperation):
        raise ProtocolViolation() from None


def _unique(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ProtocolViolation()
        obj[key] = value
    return obj


def _invalid_constant(value):
    raise ProtocolViolation()


def decode_message(raw):
    try:
        msg = json.loads(raw.decode('utf-8'), object_pairs_hook=_unique,
                         parse_constant=_invalid_constant, parse_float=Decimal)
        # Result nesting sits one level below the message envelope.
        _validate_json(msg, max_depth=MAX_DEPTH + 1)
        if type(msg) is not dict:
            raise ProtocolViolation()
        return msg
    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError, InvalidOperation):
        raise ProtocolViolation() from None


def _frame_limit(value):
    if type(value) is not int or not 0 < value <= RESPONSE_FRAME_BYTES:
        raise ProtocolViolation()


def encode_frame(msg, max_bytes):
    _frame_limit(max_bytes)
    if type(msg) is not dict:
        raise ProtocolViolation()
    raw = _serialize(msg, max_depth=MAX_DEPTH + 1)
    if not 0 < len(raw) <= max_bytes:
        raise ProtocolViolation()
    return struct.pack('!I', len(raw)) + raw


class FrameReader:
    """Exclusive pipe reader. After timeout/violation the session is permanently unusable."""
    def __init__(self, fd, max_bytes=REQUEST_FRAME_BYTES):
        _frame_limit(max_bytes)
        self.fd = fd
        self.max_bytes = max_bytes
        self.closed = False

    def _exact(self, count, deadline, clean_eof=False):
        data = bytearray()
        poller = select.poll()
        poller.register(self.fd, select.POLLIN | select.POLLHUP | select.POLLERR)
        while len(data) < count:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('E_TIMEOUT')
            # select.select() fails for valid Linux FDs >= FD_SETSIZE (usually 1024).
            # poll() supports them; always re-check the absolute deadline.
            ready = poller.poll(max(1, math.ceil(remaining * 1000)))
            if not ready:
                raise TimeoutError('E_TIMEOUT')
            chunk = os.read(self.fd, count - len(data))
            if not chunk:
                if clean_eof and not data:
                    return None
                raise ProtocolViolation()
            data.extend(chunk)
        return bytes(data)

    def read(self, deadline):
        if self.closed:
            raise ProtocolViolation()
        try:
            if type(deadline) not in (int, float) or not math.isfinite(deadline):
                raise ProtocolViolation()
            header = self._exact(4, deadline, clean_eof=True)
            if header is None:
                self.closed = True
                return None
            length = struct.unpack('!I', header)[0]
            if not 0 < length <= self.max_bytes:
                raise ProtocolViolation()
            return decode_message(self._exact(length, deadline))
        except (ProtocolViolation, TimeoutError):
            self.closed = True
            raise
        except (OSError, ValueError, OverflowError):
            self.closed = True
            raise ProtocolViolation() from None


@dataclass(frozen=True)
class ReadInterval:
    request_id: str
    start: int
    end: int


@dataclass(frozen=True)
class SubmitResult:
    request_id: str
    result: dict


def validate_result_payload(obj, policy):
    try:
        if type(obj) is not dict:
            raise ProtocolViolation()
        raw = _serialize(obj)
        if len(raw) > policy.max_result_bytes:
            raise ProtocolViolation()
        # A snapshot, so later mutation of the caller's dict cannot change the result.
        return json.loads(raw, parse_float=Decimal)
    except ProtocolViolation:
        raise RequestRejected('E_RESULT_INVALID') from None


def parse_request(msg, policy):
    if type(msg) is not dict:
        raise ProtocolViolation()
    if type(msg.get('v')) is not int or msg['v'] != 1 or msg.get('type') != 'request':
        raise ProtocolViolation()
    rid = msg.get('request_id')
    if type(rid) is not str or not REQUEST_ID.fullmatch(rid):
        raise ProtocolViolation()
    base = {'v', 'type', 'request_id', 'operation'}
    operation = msg.get('operation')
    if operation == 'read_interval':
        if set(msg) != base | {'start', 'end'}:
            raise ProtocolViolation()
        start, end = msg['start'], msg['end']
        if type(start) is not int or type(end) is not int or not 0 <= start < end:
            raise RequestRejected('E_RANGE')
        if end - start > policy.max_read_bytes:
            raise RequestRejected('E_TOO_LARGE_READ')
        # end <= snapshot.size belongs to the broker, which owns the snapshot.
        return ReadInterval(rid, start, end)
    if operation == 'submit_result':
        if set(msg) != base | {'result'}:
            raise ProtocolViolation()
        return SubmitResult(rid, validate_result_payload(msg['result'], policy))
    raise ProtocolViolation('E_OPERATION')


class RequestParser:
    """Session state: IDs are consumed even by recoverably rejected requests."""
    def __init__(self, policy=None):
        self.policy = policy if policy is not None else Policy()
        self.seen = set()
        self.failed = False

    def parse(self, msg):
        if self.failed:
            raise ProtocolViolation()
        try:
            rid = msg.get('request_id') if type(msg) is dict else None
            if type(rid) is not str or not REQUEST_ID.fullmatch(rid) or rid in self.seen:
                raise ProtocolViolation()
            if len(self.seen) >= self.policy.max_ipc_messages:
                raise ProtocolViolation('E_EVENT_LIMIT')
            self.seen.add(rid)
            return parse_request(msg, self.policy)
        except ProtocolViolation:
            self.failed = True
            raise
