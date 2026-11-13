#!/usr/bin/env python3
"""Phase gate in front of high-impact work.

`before_exec` opens a stub deliberation and returns the recommendation.
This module has no executor: `--exec` records that refusal and does not
start a child process, browser, or network client.

A future swarm must call `before_exec` and then stop unless a separate
human accept exists outside this file. `outcome=proceed` is not that accept.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.phantom.board import BoardError, default_board_path
from tools.phantom.deliberate import HIGH_IMPACT_PHASES, ProtocolError, before_exec_round, parse_agents

PHASES = (
    {'id': 'review', 'impact': 'low'},
    {'id': 'js-inventory', 'impact': 'low'},
    {'id': 'evidence-qa', 'impact': 'low'},
    {'id': 'web-exploit', 'impact': 'high'},
    {'id': 'exec', 'impact': 'high'},
    {'id': 'network-active', 'impact': 'high'},
    {'id': 'auth-test', 'impact': 'high'},
)


def before_exec(*, phase, agents, board_path=None, topic='', scope_ref='', dry_run=False, catalog_path=None):
    """Deliberate before a phase. Returns the recommendation and never executes it."""
    return before_exec_round(
        phase=phase,
        agents=agents,
        board_path=board_path,
        topic=topic,
        scope_ref=scope_ref,
        dry_run=dry_run,
        catalog_path=catalog_path,
    )


def _emit(payload):
    print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog='swarm.py',
        description='Deliberation gate. Does not execute phases.',
    )
    sub = parser.add_subparsers(dest='cmd', required=True)
    sub.add_parser('phases')
    run = sub.add_parser('run')
    run.add_argument('--phase', default='review')
    run.add_argument('--deliberate', action='store_true')
    run.add_argument('--exec', action='store_true')
    run.add_argument('--dry-run', action='store_true')
    run.add_argument('--agents', default='specter,cipher')
    run.add_argument('--topic', default='')
    run.add_argument('--scope-ref', default='')
    run.add_argument('--board', type=Path, default=None)
    run.add_argument('--catalog', type=Path, default=None)
    args = parser.parse_args(list(sys.argv[1:] if argv is None else argv))
    if args.cmd == 'phases':
        _emit({
            'executor': 'absent',
            'high_impact': sorted(HIGH_IMPACT_PHASES),
            'phases': list(PHASES),
        })
        return 0
    if args.exec and not args.deliberate:
        print('error: DELIBERATION_REQUIRED', file=sys.stderr)
        return 2
    if not args.deliberate and not args.exec:
        print('error: NOTHING_TO_DO', file=sys.stderr)
        return 2
    try:
        shown = before_exec(
            phase=args.phase,
            agents=parse_agents(args.agents),
            board_path=args.board or default_board_path(),
            topic=args.topic,
            scope_ref=args.scope_ref,
            dry_run=args.dry_run,
            catalog_path=args.catalog,
        )
    except (ProtocolError, BoardError) as exc:
        detail = ' '.join(f'{key}={value}' for key, value in exc.detail.items())
        print(f'error: {exc.code}' + (f' {detail}' if detail else ''), file=sys.stderr)
        return 2
    if args.exec:
        _emit({
            'code': 'EXEC_NOT_IMPLEMENTED',
            'decision_id': shown['decision_id'],
            'executes': False,
            'executor': 'absent',
            'human_approved': False,
            'outcome': shown['outcome'],
            'phase': shown['phase'],
            'topic_id': shown['topic_id'],
        })
        return 3
    _emit(shown)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
