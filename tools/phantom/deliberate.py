#!/usr/bin/env python3
"""Multi-agent deliberation on the phantom board.

Morfeus opens a topic. At least two catalog agents each post a stance
before a decision id can be recorded. Critiques are optional. The
decision is a recommendation: executes is always false and
human_approved is always false. No LLM and no network calls.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import uuid

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.phantom.board import BoardError, FileBoard, MemoryBoard, default_board_path, self_test as board_self_test

DEFAULT_CATALOG = ROOT / 'hackbots' / 'bots.json'
STANCES = ('abort', 'hold', 'proceed')
_RANK = {'abort': 0, 'hold': 1, 'proceed': 2}
HIGH_IMPACT_PHASES = frozenset({'web-exploit', 'exec', 'network-active', 'auth-test'})
MIN_PROPOSERS = 2
MAX_PANEL = 8
TOPIC_ID = re.compile(r'^tpc-[0-9a-f]{12}\Z')
DECISION_ID = re.compile(r'^dec-[0-9a-f]{16}\Z')
PHASE_RE = re.compile(r'^[a-z][a-z0-9-]{0,40}\Z')
SCOPE_REF = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._:-]{0,79}\Z')
SECRET = re.compile(
    r'(?i)(?:api[_-]?key|secret|password|authorization|bearer)\s*[:=]\s*\S{6,}'
    r'|\bAKIA[0-9A-Z]{16}\b|-----BEGIN [A-Z ]*PRIVATE KEY-----'
)
BINDING_KEYS = (
    'authority', 'coordinator', 'dissent', 'executes', 'human_approved',
    'impact', 'outcome', 'participants', 'phase', 'rationale', 'scope_ref',
    'topic', 'topic_id',
)


class ProtocolError(Exception):
    def __init__(self, code, **detail):
        super().__init__(code)
        self.code = code
        self.detail = {key: value for key, value in detail.items() if type(value) in (str, int)}


def load_catalog(path=None):
    catalog_path = Path(path or DEFAULT_CATALOG)
    data = json.loads(catalog_path.read_text(encoding='utf-8'))
    agents = {}
    for row in data.get('agents') or []:
        agent_id = row.get('id')
        if type(agent_id) is not str or agent_id in agents:
            raise ProtocolError('CATALOG')
        agents[agent_id] = {
            'id': agent_id,
            'name': row.get('name') or agent_id,
            'role': row.get('role') or '',
            'category': row.get('category') or '',
        }
    coordinator = data.get('coordinator')
    if coordinator not in agents or agents[coordinator].get('category') != 'coordinator':
        raise ProtocolError('CATALOG')
    return {'coordinator': coordinator, 'agents': agents, 'path': str(catalog_path)}


def phase_impact(phase, requested):
    if type(phase) is not str or not PHASE_RE.match(phase):
        raise ProtocolError('BAD_PHASE')
    if phase in HIGH_IMPACT_PHASES:
        return 'high'
    if requested not in ('low', 'medium', 'high'):
        raise ProtocolError('BAD_IMPACT')
    return requested


def clean_text(value, limit, code):
    if type(value) is not str:
        raise ProtocolError(code)
    value = value.strip()
    if not value or len(value) > limit:
        raise ProtocolError(code)
    if any(ord(ch) < 32 and ch not in '\n\t' for ch in value):
        raise ProtocolError(code)
    if SECRET.search(value):
        raise ProtocolError('SECRET_MATERIAL')
    return value


def parse_agents(text):
    if type(text) is not str:
        raise ProtocolError('BAD_AGENTS')
    parts = [part.strip() for part in text.split(',') if part.strip()]
    if len(parts) != len(set(parts)):
        raise ProtocolError('DUPLICATE_AGENT')
    return parts


def parse_stances(pairs):
    found = {}
    for item in pairs or []:
        if type(item) is not str or '=' not in item:
            raise ProtocolError('BAD_STANCE')
        agent, stance = item.split('=', 1)
        agent, stance = agent.strip(), stance.strip()
        if not agent or agent in found:
            raise ProtocolError('DUPLICATE_AGENT')
        if stance not in STANCES:
            raise ProtocolError('BAD_STANCE')
        found[agent] = stance
    return found


def conservative(stances):
    return min(stances, key=lambda stance: _RANK[stance])


def decision_id_for(binding):
    blob = json.dumps(binding, ensure_ascii=False, sort_keys=True, separators=(',', ':'))
    return 'dec-' + hashlib.sha256(blob.encode('utf-8')).hexdigest()[:16]


def _binding(record):
    missing = [key for key in BINDING_KEYS if key not in record]
    if missing:
        raise ProtocolError('TAMPERED')
    return {key: record[key] for key in BINDING_KEYS}


def stub_body(agent, stance):
    return (
        f"{agent['name']} ({agent['role']}) recommends {stance}. "
        'Stub round: no procedure, no payload, and no tool launch.'
    )


class Protocol:
    def __init__(self, board, catalog=None):
        self.board = board
        self.catalog = catalog or load_catalog()

    @property
    def coordinator(self):
        return self.catalog['coordinator']

    def _agent(self, agent_id):
        agent = self.catalog['agents'].get(agent_id)
        if agent is None:
            raise ProtocolError('UNKNOWN_AGENT')
        return agent

    def _check_panel(self, agents):
        if type(agents) is not list or len(agents) > MAX_PANEL:
            raise ProtocolError('PANEL_TOO_LARGE' if type(agents) is list else 'BAD_AGENTS')
        if len(agents) != len(set(agents)):
            raise ProtocolError('DUPLICATE_AGENT')
        if self.coordinator in agents:
            raise ProtocolError('COORDINATOR_IN_PANEL')
        for agent_id in agents:
            self._agent(agent_id)
        if agents and len(agents) < MIN_PROPOSERS:
            raise ProtocolError('QUORUM')
        return agents

    def _events(self, topic_id):
        if type(topic_id) is not str or not TOPIC_ID.match(topic_id):
            raise ProtocolError('BAD_TOPIC_ID')
        rows = []
        for record in self.board.read():
            if record.get('topic_id') == topic_id and str(record.get('kind', '')).startswith('deliberation.'):
                rows.append(record)
        return rows

    def _opened(self, topic_id):
        events = self._events(topic_id)
        opened = [event for event in events if event.get('kind') == 'deliberation.open']
        if not opened:
            raise ProtocolError('TOPIC_NOT_FOUND')
        if len(opened) != 1:
            raise ProtocolError('TOPIC_AMBIGUOUS')
        return opened[0], events

    def _panel(self, opened):
        agents = opened.get('agents')
        if type(agents) is not list:
            raise ProtocolError('TAMPERED')
        return agents

    def _require_open(self, topic_id):
        opened, events = self._opened(topic_id)
        if any(event.get('kind') == 'deliberation.decide' for event in events):
            decision = next(event for event in events if event.get('kind') == 'deliberation.decide')
            raise ProtocolError('CLOSED', decision_id=decision.get('decision_id', ''))
        return opened, events

    def _must_be_invited(self, opened, agent_id):
        self._agent(agent_id)
        panel = self._panel(opened)
        if panel and agent_id not in panel:
            raise ProtocolError('NOT_INVITED')

    def _proposers(self, events):
        found = []
        for event in events:
            if event.get('kind') != 'deliberation.propose':
                continue
            agent = event.get('agent')
            if agent not in found:
                found.append(agent)
        return sorted(found)

    def _latest_proposals(self, events):
        latest = {}
        for event in events:
            if event.get('kind') == 'deliberation.propose':
                latest[event['agent']] = event
        return latest

    def open(self, *, topic, phase='review', impact='low', agents=None, scope_ref='', body=''):
        topic = clean_text(topic, 400, 'BAD_TOPIC')
        impact = phase_impact(phase, impact)
        agents = self._check_panel(list(agents or []))
        if scope_ref:
            if type(scope_ref) is not str or not SCOPE_REF.match(scope_ref):
                raise ProtocolError('BAD_SCOPE_REF')
        else:
            scope_ref = ''
        body = clean_text(body, 2000, 'BAD_BODY') if body else 'Topic opened for a multi-agent recommendation.'
        record = self.board.post({
            'kind': 'deliberation.open',
            'agent': self.coordinator,
            'topic_id': 'tpc-' + uuid.uuid4().hex[:12],
            'topic': topic,
            'phase': phase,
            'impact': impact,
            'agents': list(agents),
            'scope_ref': scope_ref,
            'body': body,
        })
        return record

    def propose(self, *, topic_id, agent, stance, body):
        if stance not in STANCES:
            raise ProtocolError('BAD_STANCE')
        body = clean_text(body, 2000, 'BAD_BODY')
        opened, events = self._require_open(topic_id)
        self._must_be_invited(opened, agent)
        if any(event.get('kind') == 'deliberation.propose' and event.get('agent') == agent for event in events):
            raise ProtocolError('ALREADY_PROPOSED')
        return self.board.post({
            'kind': 'deliberation.propose',
            'agent': agent,
            'topic_id': topic_id,
            'stance': stance,
            'body': body,
        })

    def critique(self, *, topic_id, agent, body, target_agent=''):
        body = clean_text(body, 2000, 'BAD_BODY')
        opened, events = self._require_open(topic_id)
        self._must_be_invited(opened, agent)
        if any(event.get('kind') == 'deliberation.critique' and event.get('agent') == agent for event in events):
            raise ProtocolError('ALREADY_CRITIQUED')
        if target_agent:
            self._agent(target_agent)
            if not any(event.get('kind') == 'deliberation.propose' and event.get('agent') == target_agent for event in events):
                raise ProtocolError('TARGET_HAS_NO_PROPOSAL')
        else:
            target_agent = ''
        return self.board.post({
            'kind': 'deliberation.critique',
            'agent': agent,
            'topic_id': topic_id,
            'target_agent': target_agent,
            'body': body,
        })

    def _dissent(self, events, outcome):
        dissent = []
        for agent, proposal in sorted(self._latest_proposals(events).items()):
            if proposal.get('stance') == outcome:
                continue
            note = proposal.get('body')
            if type(note) is not str:
                raise ProtocolError('TAMPERED')
            dissent.append({'agent': agent, 'stance': proposal.get('stance'), 'note': note})
        return dissent

    def _verify(self, opened, events, decision):
        binding = _binding(decision)
        if decision.get('kind') != 'deliberation.decide':
            raise ProtocolError('TAMPERED')
        if opened.get('agent') != self.coordinator or decision.get('agent') != self.coordinator:
            raise ProtocolError('TAMPERED')
        if binding['coordinator'] != self.coordinator:
            raise ProtocolError('TAMPERED')
        if binding['executes'] is not False or binding['human_approved'] is not False:
            raise ProtocolError('TAMPERED')
        if binding['authority'] != 'recommendation-only':
            raise ProtocolError('TAMPERED')
        if binding['topic_id'] != opened.get('topic_id') or binding['topic'] != opened.get('topic'):
            raise ProtocolError('TAMPERED')
        if binding['phase'] != opened.get('phase') or binding['impact'] != opened.get('impact'):
            raise ProtocolError('TAMPERED')
        if binding['scope_ref'] != (opened.get('scope_ref') or ''):
            raise ProtocolError('TAMPERED')
        proposers = self._proposers(events)
        panel = self._panel(opened)
        if panel and any(agent not in panel for agent in proposers):
            raise ProtocolError('TAMPERED')
        if len(proposers) < MIN_PROPOSERS or binding['participants'] != proposers:
            raise ProtocolError('TAMPERED')
        if binding['outcome'] not in STANCES:
            raise ProtocolError('TAMPERED')
        if binding['dissent'] != self._dissent(events, binding['outcome']):
            raise ProtocolError('TAMPERED')
        if decision.get('decision_id') != decision_id_for(binding):
            raise ProtocolError('TAMPERED')
        return binding

    def decide(self, *, topic_id, outcome, rationale):
        if outcome not in STANCES:
            raise ProtocolError('BAD_OUTCOME')
        rationale = clean_text(rationale, 2000, 'BAD_RATIONALE')
        opened, events = self._require_open(topic_id)
        if opened.get('agent') != self.coordinator:
            raise ProtocolError('NOT_COORDINATOR')
        proposers = self._proposers(events)
        if len(proposers) < MIN_PROPOSERS:
            raise ProtocolError('QUORUM')
        dissent = self._dissent(events, outcome)
        binding = {
            'authority': 'recommendation-only',
            'coordinator': self.coordinator,
            'dissent': dissent,
            'executes': False,
            'human_approved': False,
            'impact': opened['impact'],
            'outcome': outcome,
            'participants': proposers,
            'phase': opened['phase'],
            'rationale': rationale,
            'scope_ref': opened.get('scope_ref') or '',
            'topic': opened['topic'],
            'topic_id': topic_id,
        }
        record = {
            'kind': 'deliberation.decide',
            'agent': self.coordinator,
            'body': rationale,
            'decision_id': decision_id_for(binding),
        }
        record.update(binding)
        self.board.post(record)
        return self.show(topic_id)

    def show(self, topic_id):
        opened, events = self._opened(topic_id)
        decisions = [event for event in events if event.get('kind') == 'deliberation.decide']
        decision = None
        if len(decisions) > 1:
            raise ProtocolError('DECISION_AMBIGUOUS')
        if decisions:
            decision = decisions[0]
            self._verify(opened, events, decision)
        return {
            'topic_id': topic_id,
            'topic': opened.get('topic'),
            'phase': opened.get('phase'),
            'impact': opened.get('impact'),
            'coordinator': opened.get('agent'),
            'scope_ref': opened.get('scope_ref') or '',
            'events': events,
            'decision_id': None if decision is None else decision['decision_id'],
            'outcome': None if decision is None else decision['outcome'],
            'participants': self._proposers(events) if decision is None else decision['participants'],
            'dissent': [] if decision is None else decision['dissent'],
            'executes': False,
            'human_approved': False,
            'decision': decision,
        }

    def find_decision(self, decision_id):
        if type(decision_id) is not str or not DECISION_ID.match(decision_id):
            raise ProtocolError('BAD_DECISION_ID')
        found = []
        for record in self.board.read():
            if record.get('kind') == 'deliberation.decide' and record.get('decision_id') == decision_id:
                found.append(record)
        if not found:
            raise ProtocolError('DECISION_NOT_FOUND')
        if len(found) != 1:
            raise ProtocolError('DECISION_AMBIGUOUS')
        shown = self.show(found[0]['topic_id'])
        if shown['decision_id'] != decision_id:
            raise ProtocolError('TAMPERED')
        return shown

    def run_round(self, *, topic, agents, phase='review', impact='low', scope_ref='', body='', rebuttal=False, stances=None):
        agents = self._check_panel(list(agents))
        if len(agents) < MIN_PROPOSERS:
            raise ProtocolError('QUORUM')
        impact = phase_impact(phase, impact)
        overrides = dict(stances or {})
        for agent_id, stance in overrides.items():
            if agent_id not in agents:
                raise ProtocolError('NOT_INVITED')
            if stance not in STANCES:
                raise ProtocolError('BAD_STANCE')
            if stance == 'proceed' and (impact != 'low' or phase in HIGH_IMPACT_PHASES):
                raise ProtocolError('HIGH_IMPACT_STUB')
        opened = self.open(
            topic=topic, phase=phase, impact=impact, agents=agents, scope_ref=scope_ref, body=body,
        )
        chosen = {}
        for agent_id in agents:
            stance = overrides.get(agent_id) or ('hold' if impact != 'low' or phase in HIGH_IMPACT_PHASES else 'proceed')
            self.propose(
                topic_id=opened['topic_id'],
                agent=agent_id,
                stance=stance,
                body=stub_body(self._agent(agent_id), stance),
            )
            chosen[agent_id] = stance
        disagree = len(set(chosen.values())) > 1
        if disagree or rebuttal:
            for index, agent_id in enumerate(agents):
                if disagree:
                    target = next(other for other in agents if chosen[other] != chosen[agent_id])
                    note = 'Different stance; keep the phase gated. No procedure offered.'
                else:
                    target = agents[(index + 1) % len(agents)]
                    note = 'No extra objection in this stub round.'
                self.critique(topic_id=opened['topic_id'], agent=agent_id, target_agent=target, body=note)
        outcome = conservative(chosen.values())
        rationale = (
            f'Stub round for phase {phase} ({impact}). {len(agents)} proposers. '
            'Outcome is the most conservative stance. This record is a recommendation only: '
            'it does not approve scope, does not execute a phase, and does not replace human accept.'
        )
        return self.decide(topic_id=opened['topic_id'], outcome=outcome, rationale=rationale)


def before_exec_round(*, phase, agents, board_path=None, topic='', scope_ref='', dry_run=False, catalog_path=None):
    """Stub deliberation for a phase gate. Dry-run does not touch the board file."""
    if type(phase) is not str or not PHASE_RE.match(phase):
        raise ProtocolError('BAD_PHASE')
    impact = 'high' if phase in HIGH_IMPACT_PHASES else 'low'
    board = MemoryBoard() if dry_run else FileBoard(board_path or default_board_path())
    protocol = Protocol(board, load_catalog(catalog_path))
    question = topic or (
        f'Before phase {phase}: should the coordinator recommend any action beyond recording this gate?'
    )
    shown = protocol.run_round(
        topic=question,
        agents=list(agents),
        phase=phase,
        impact=impact,
        scope_ref=scope_ref,
    )
    shown['dry_run'] = True if dry_run else False
    shown['executor'] = 'absent'
    return shown


def _emit(payload):
    print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))


def _fail(exc):
    detail = ' '.join(f'{key}={value}' for key, value in exc.detail.items())
    print(f'error: {exc.code}' + (f' {detail}' if detail else ''), file=sys.stderr)
    return 2


def self_test():
    board_self_test()
    board = MemoryBoard()
    protocol = Protocol(board, load_catalog())
    try:
        opened = protocol.open(topic='Quorum probe', agents=['specter', 'ward'])
        protocol.propose(topic_id=opened['topic_id'], agent='specter', stance='hold', body='One voice is not a panel.')
        protocol.decide(topic_id=opened['topic_id'], outcome='hold', rationale='Should fail closed.')
    except ProtocolError as exc:
        if exc.code != 'QUORUM':
            raise AssertionError('quorum code') from exc
    else:
        raise AssertionError('single proposer recorded a decision')
    shown = protocol.run_round(
        topic='Offline fixture review',
        agents=['glyph', 'ward'],
        phase='js-inventory',
        impact='low',
    )
    again = Protocol(board, protocol.catalog).find_decision(shown['decision_id'])
    if shown['decision_id'] != again['decision_id'] or not shown['decision_id'].startswith('dec-'):
        raise AssertionError('decision id')
    if shown['participants'] != ['glyph', 'ward'] or shown['executes'] is not False:
        raise AssertionError('participants')
    held = protocol.run_round(
        topic='Gate before a high-impact phase',
        agents=['specter', 'cipher'],
        phase='web-exploit',
        impact='low',
    )
    if held['impact'] != 'high' or held['outcome'] != 'hold' or held['executes'] is not False:
        raise AssertionError('high-impact stub')


def build_parser():
    parser = argparse.ArgumentParser(
        prog='mitr3-deliberate',
        description='Record a multi-agent recommendation. Does not execute a phase.',
    )
    parser.add_argument('--board', type=Path, default=None)
    parser.add_argument('--dry-run', action='store_true', help='run only: print the round, do not append')
    parser.add_argument('--catalog', type=Path, default=None)
    sub = parser.add_subparsers(dest='cmd', required=True)

    opened = sub.add_parser('open')
    opened.add_argument('--topic', required=True)
    opened.add_argument('--phase', default='review')
    opened.add_argument('--impact', default='low', choices=['low', 'medium', 'high'])
    opened.add_argument('--agents', default='')
    opened.add_argument('--scope-ref', default='')
    opened.add_argument('--body', default='')

    propose = sub.add_parser('propose')
    propose.add_argument('--topic-id', required=True)
    propose.add_argument('--agent', required=True)
    propose.add_argument('--stance', required=True, choices=list(STANCES))
    propose.add_argument('--body', required=True)

    critique = sub.add_parser('critique')
    critique.add_argument('--topic-id', required=True)
    critique.add_argument('--agent', required=True)
    critique.add_argument('--body', required=True)
    critique.add_argument('--target-agent', default='')

    decide = sub.add_parser('decide')
    decide.add_argument('--topic-id', required=True)
    decide.add_argument('--outcome', required=True, choices=list(STANCES))
    decide.add_argument('--rationale', required=True)

    show = sub.add_parser('show')
    show.add_argument('--topic-id', default='')
    show.add_argument('--decision-id', default='')

    tail = sub.add_parser('tail')
    tail.add_argument('-n', type=int, default=20)
    tail.add_argument('--topic-id', default=None)

    run = sub.add_parser('run', help='stub round: open, propose, optional critique, decide')
    run.add_argument('--topic', required=True)
    run.add_argument('--agents', required=True, help='comma-separated catalog ids, at least two')
    run.add_argument('--phase', default='review')
    run.add_argument('--impact', default='low', choices=['low', 'medium', 'high'])
    run.add_argument('--scope-ref', default='')
    run.add_argument('--body', default='')
    run.add_argument('--rebuttal', action='store_true')
    run.add_argument('--stance', action='append', default=[], metavar='AGENT=STANCE')

    sub.add_parser('self-test')
    return parser


def _hoist_globals(argv):
    """Allow --board/--catalog/--dry-run before or after the subcommand."""
    hoisted = []
    rest = []
    index = 0
    while index < len(argv):
        arg = argv[index]
        if arg == '--dry-run':
            hoisted.append(arg)
        elif arg in ('--board', '--catalog') and index + 1 < len(argv):
            hoisted.extend((arg, argv[index + 1]))
            index += 1
        elif arg.startswith('--board=') or arg.startswith('--catalog='):
            hoisted.append(arg)
        else:
            rest.append(arg)
        index += 1
    return hoisted + rest


def main(argv=None):
    raw = list(sys.argv[1:] if argv is None else argv)
    args = build_parser().parse_args(_hoist_globals(raw))
    if args.cmd == 'self-test':
        self_test()
        print('ok')
        return 0
    if args.dry_run and args.cmd != 'run':
        print('error: DRY_RUN_RUN_ONLY', file=sys.stderr)
        return 2
    try:
        catalog = load_catalog(args.catalog)
        if args.cmd == 'run' and args.dry_run:
            board = MemoryBoard()
        else:
            board = FileBoard(args.board or default_board_path())
        protocol = Protocol(board, catalog)
        if args.cmd == 'open':
            _emit(protocol.open(
                topic=args.topic,
                phase=args.phase,
                impact=args.impact,
                agents=parse_agents(args.agents),
                scope_ref=args.scope_ref,
                body=args.body,
            ))
            return 0
        if args.cmd == 'propose':
            _emit(protocol.propose(topic_id=args.topic_id, agent=args.agent, stance=args.stance, body=args.body))
            return 0
        if args.cmd == 'critique':
            _emit(protocol.critique(
                topic_id=args.topic_id, agent=args.agent, body=args.body, target_agent=args.target_agent,
            ))
            return 0
        if args.cmd == 'decide':
            _emit(protocol.decide(topic_id=args.topic_id, outcome=args.outcome, rationale=args.rationale))
            return 0
        if args.cmd == 'show':
            if bool(args.topic_id) == bool(args.decision_id):
                print('error: NEED_TOPIC_OR_DECISION', file=sys.stderr)
                return 2
            shown = protocol.find_decision(args.decision_id) if args.decision_id else protocol.show(args.topic_id)
            _emit(shown)
            return 0
        if args.cmd == 'tail':
            for record in board.tail(args.n, topic_id=args.topic_id):
                print(json.dumps(record, ensure_ascii=False, sort_keys=True))
            return 0
        shown = protocol.run_round(
            topic=args.topic,
            agents=parse_agents(args.agents),
            phase=args.phase,
            impact=args.impact,
            scope_ref=args.scope_ref,
            body=args.body,
            rebuttal=args.rebuttal,
            stances=parse_stances(args.stance),
        )
        shown['dry_run'] = True if args.dry_run else False
        _emit(shown)
        return 0
    except (ProtocolError, BoardError) as exc:
        return _fail(exc)


if __name__ == '__main__':
    raise SystemExit(main())
