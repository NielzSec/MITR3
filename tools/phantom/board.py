#!/usr/bin/env python3
"""Append-only JSONL board for MITR3 agent messages.

Post and tail are the whole storage contract. Deliberation lives beside
this module and writes the same file. Nothing here opens a socket.
"""
from __future__ import annotations

import argparse
import copy
import datetime as dt
import fcntl
import json
import os
from pathlib import Path
import re
import sys
import uuid

ROOT = Path(__file__).resolve().parents[2]
MAX_LINE = 12_000
AGENT_RE_TEXT = r'^[a-z][a-z0-9_-]{0,31}\Z'
KIND_RE_TEXT = r'^[a-z][a-z0-9._-]{0,63}\Z'
EVENT_ID_TEXT = r'^evt-[0-9a-f]{12}\Z'
TS_TEXT = r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z'

AGENT_RE = re.compile(AGENT_RE_TEXT)
KIND_RE = re.compile(KIND_RE_TEXT)
EVENT_ID = re.compile(EVENT_ID_TEXT)
TS_RE = re.compile(TS_TEXT)


class BoardError(Exception):
    def __init__(self, code, **detail):
        super().__init__(code)
        self.code = code
        self.detail = {key: value for key, value in detail.items() if type(value) in (str, int)}


def default_board_path():
    """Operational checkout uses ~/MITR3; this tree uses state/offensive."""
    override = os.environ.get('MITR3_BOARD')
    if override:
        return Path(override)
    home_root = Path.home() / 'MITR3'
    if home_root.is_dir():
        return home_root / 'state' / 'offensive' / 'board.jsonl'
    return ROOT / 'state' / 'offensive' / 'board.jsonl'


def now_iso():
    return dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _json_safe(value, depth=0):
    if depth > 6:
        raise BoardError('BAD_RECORD')
    if value is None or type(value) is bool:
        return
    if type(value) is int:
        if abs(value) > 10**12:
            raise BoardError('BAD_RECORD')
        return
    if type(value) is str:
        if len(value) > 4000:
            raise BoardError('RECORD_TOO_LARGE')
        return
    if type(value) is list:
        if len(value) > 32:
            raise BoardError('BAD_RECORD')
        for item in value:
            _json_safe(item, depth + 1)
        return
    if type(value) is dict:
        if len(value) > 40:
            raise BoardError('BAD_RECORD')
        for key, item in value.items():
            if type(key) is not str or not 1 <= len(key) <= 40:
                raise BoardError('BAD_RECORD')
            _json_safe(item, depth + 1)
        return
    raise BoardError('BAD_RECORD')


def prepare(record):
    if type(record) is not dict:
        raise BoardError('BAD_RECORD')
    stored = copy.deepcopy(record)
    for reserved in ('id', 'ts', 'v'):
        stored.pop(reserved, None)
    _json_safe(stored)
    agent = stored.get('agent')
    kind = stored.get('kind')
    body = stored.get('body')
    if type(agent) is not str or not AGENT_RE.match(agent):
        raise BoardError('BAD_AGENT')
    if type(kind) is not str or not KIND_RE.match(kind):
        raise BoardError('BAD_KIND')
    if type(body) is not str:
        raise BoardError('BAD_RECORD')
    stored['v'] = 1
    stored['ts'] = now_iso()
    stored['id'] = 'evt-' + uuid.uuid4().hex[:12]
    line = json.dumps(stored, ensure_ascii=False, separators=(',', ':'), sort_keys=True)
    if '\n' in line or len(line.encode('utf-8')) > MAX_LINE:
        raise BoardError('RECORD_TOO_LARGE')
    return stored


def _reject_duplicate_keys(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise BoardError('CORRUPT_LINE')
        obj[key] = value
    return obj


def _reject_bad_number(_value):
    raise BoardError('CORRUPT_LINE')


def parse_line(line, lineno):
    if len(line.encode('utf-8')) > MAX_LINE:
        raise BoardError('CORRUPT_LINE', line=lineno)
    try:
        record = json.loads(
            line,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_bad_number,
            parse_float=_reject_bad_number,
        )
    except BoardError:
        raise
    except (json.JSONDecodeError, UnicodeError, ValueError):
        raise BoardError('CORRUPT_LINE', line=lineno) from None
    if type(record) is not dict or record.get('v') != 1:
        raise BoardError('CORRUPT_LINE', line=lineno)
    if type(record.get('agent')) is not str or not AGENT_RE.match(record['agent']):
        raise BoardError('CORRUPT_LINE', line=lineno)
    if type(record.get('kind')) is not str or not KIND_RE.match(record['kind']):
        raise BoardError('CORRUPT_LINE', line=lineno)
    if type(record.get('id')) is not str or not EVENT_ID.match(record['id']):
        raise BoardError('CORRUPT_LINE', line=lineno)
    if type(record.get('ts')) is not str or not TS_RE.match(record['ts']):
        raise BoardError('CORRUPT_LINE', line=lineno)
    if type(record.get('body')) is not str:
        raise BoardError('CORRUPT_LINE', line=lineno)
    return record


def _refuse_symlinks(path):
    """Refuse a symlinked board file or a symlinked parent directory."""
    if Path(path).is_symlink() or Path(path).parent.is_symlink():
        raise BoardError('SYMLINK_BOARD')


class FileBoard:
    def __init__(self, path):
        self.path = Path(path)

    def post(self, record):
        stored = prepare(record)
        line = json.dumps(stored, ensure_ascii=False, separators=(',', ':'), sort_keys=True) + '\n'
        self._append(line.encode('utf-8'))
        return copy.deepcopy(stored)

    def read(self):
        if not self.path.exists():
            return []
        _refuse_symlinks(self.path)
        fd = os.open(self.path, os.O_RDONLY)
        try:
            fcntl.flock(fd, fcntl.LOCK_SH)
            chunks = []
            while True:
                block = os.read(fd, 65536)
                if not block:
                    break
                chunks.append(block)
        finally:
            os.close(fd)
        try:
            text = b''.join(chunks).decode('utf-8')
        except UnicodeError:
            raise BoardError('CORRUPT_LINE') from None
        rows = []
        for lineno, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            rows.append(parse_line(line, lineno))
        return rows

    def tail(self, n=20, topic_id=None):
        if type(n) is not int or not 1 <= n <= 1000:
            raise BoardError('BAD_LIMIT')
        rows = self.read()
        if topic_id is not None:
            rows = [row for row in rows if row.get('topic_id') == topic_id]
        return rows[-n:]

    def _append(self, data):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        _refuse_symlinks(self.path)
        fd = os.open(self.path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
        try:
            os.fchmod(fd, 0o600)
            fcntl.flock(fd, fcntl.LOCK_EX)
            os.write(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)


class MemoryBoard:
    """In-process board for dry-run rounds. Same post/read/tail contract."""

    def __init__(self):
        self._rows = []

    def post(self, record):
        stored = prepare(record)
        self._rows.append(stored)
        return copy.deepcopy(stored)

    def read(self):
        return [copy.deepcopy(row) for row in self._rows]

    def tail(self, n=20, topic_id=None):
        if type(n) is not int or not 1 <= n <= 1000:
            raise BoardError('BAD_LIMIT')
        rows = self.read()
        if topic_id is not None:
            rows = [row for row in rows if row.get('topic_id') == topic_id]
        return rows[-n:]


def self_test():
    """Post/tail round-trip on a temporary file. No network and no default board."""
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / 'board.jsonl'
        board = FileBoard(path)
        first = board.post({'kind': 'note', 'agent': 'morfeus', 'body': 'alpha'})
        second = board.post({'kind': 'note', 'agent': 'specter', 'body': 'beta'})
        rows = board.tail(10)
        if [row['body'] for row in rows] != ['alpha', 'beta']:
            raise AssertionError('tail order')
        if rows[0]['id'] != first['id'] or board.tail(1)[0]['id'] != second['id']:
            raise AssertionError('tail id')
        if (path.stat().st_mode & 0o777) != 0o600:
            raise AssertionError('board mode')
        with path.open('a', encoding='utf-8') as handle:
            handle.write('not-json\n')
        try:
            board.tail(10)
        except BoardError as exc:
            if exc.code != 'CORRUPT_LINE':
                raise AssertionError('corrupt code') from exc
        else:
            raise AssertionError('corrupt line accepted')
        link = Path(tmp) / 'linked.jsonl'
        link.symlink_to(path)
        try:
            FileBoard(link).post({'kind': 'note', 'agent': 'morfeus', 'body': 'nope'})
        except BoardError as exc:
            if exc.code != 'SYMLINK_BOARD':
                raise AssertionError('symlink code') from exc
        else:
            raise AssertionError('symlink accepted')


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == 'deliberate':
        root = str(ROOT)
        if root not in sys.path:
            sys.path.insert(0, root)
        from tools.phantom.deliberate import main as deliberate_main
        return deliberate_main(argv[1:])
    if argv == ['--self-test']:
        self_test()
        print('ok')
        return 0
    parser = argparse.ArgumentParser(prog='board.py', description='Append-only MITR3 agent board')
    parser.add_argument('--board', type=Path, default=None)
    sub = parser.add_subparsers(dest='cmd', required=True)
    post = sub.add_parser('post')
    post.add_argument('--agent', required=True)
    post.add_argument('--kind', default='note')
    post.add_argument('--body', required=True)
    tail = sub.add_parser('tail')
    tail.add_argument('-n', type=int, default=20)
    tail.add_argument('--topic-id', default=None)
    args = parser.parse_args(argv)
    board = FileBoard(args.board or default_board_path())
    try:
        if args.cmd == 'post':
            record = board.post({'kind': args.kind, 'agent': args.agent, 'body': args.body})
            print(json.dumps(record, ensure_ascii=False, sort_keys=True))
            return 0
        for record in board.tail(args.n, topic_id=args.topic_id):
            print(json.dumps(record, ensure_ascii=False, sort_keys=True))
        return 0
    except BoardError as exc:
        detail = ' '.join(f'{key}={value}' for key, value in exc.detail.items())
        print(f'error: {exc.code}' + (f' {detail}' if detail else ''), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
