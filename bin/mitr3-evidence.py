#!/usr/bin/env python3
"""Verify-before-claim ledger for finding bulletins.

``report`` is the CLI bulletin. It prints FINDING CONFIRMED only when the
store has a verified record whose saved reproduction still matches its
hashes. A claim with no verified bundle is an unverified lead. A missing
record is rejected. This command does not run the stored steps.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from evidence.gate import report, render_bulletin
from evidence.store import MAX_ARTIFACT, MAX_OUTPUT, EvidenceError, EvidenceStore

DEFAULT_STORE = ROOT / "state" / "evidence-store"
EXIT_CODE = {"accepted": 0, "downgraded": 2, "rejected": 3}


def _print(payload: dict) -> None:
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True))


def _read_bytes(path: Path, limit: int, code: str) -> bytes:
    try:
        blob = path.read_bytes()
    except OSError:
        raise EvidenceError(code) from None
    if not blob or len(blob) > limit:
        raise EvidenceError(code)
    return blob


def _artifacts(values: list[str]) -> list[tuple[str, bytes]]:
    items = []
    for value in values:
        if "=" not in value:
            raise EvidenceError("invalid_artifact")
        name, raw_path = value.split("=", 1)
        items.append((name, _read_bytes(Path(raw_path), MAX_ARTIFACT, "invalid_artifact")))
    return items


def _output(args) -> str:
    if args.output is not None and args.output_file is not None:
        raise EvidenceError("invalid_output")
    if args.output_file is not None:
        blob = _read_bytes(args.output_file, MAX_OUTPUT, "invalid_output")
        try:
            return blob.decode("utf-8")
        except UnicodeError:
            raise EvidenceError("invalid_output") from None
    return args.output or ""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--store", type=Path, default=DEFAULT_STORE)
    commands = parser.add_subparsers(dest="cmd", required=True)

    claim = commands.add_parser("claim", help="record a finding hypothesis")
    claim.add_argument("--category", required=True)
    claim.add_argument("--summary", required=True)
    claim.add_argument("--target", default="")

    save = commands.add_parser("save", help="attach a saved reproduction bundle")
    save.add_argument("id")
    save.add_argument("--step", action="append", default=[])
    save.add_argument("--command", default="")
    save.add_argument("--output", default=None)
    save.add_argument("--output-file", type=Path, default=None)
    save.add_argument("--artifact", action="append", default=[], metavar="NAME=PATH")

    verify = commands.add_parser("verify", help="accept a complete saved bundle")
    verify.add_argument("id")

    reject = commands.add_parser("reject", help="withdraw a finding")
    reject.add_argument("id")
    reject.add_argument("--reason", required=True)

    bulletin = commands.add_parser("report", help="bulletin gated by a verified record")
    bulletin.add_argument("id")
    bulletin.add_argument("--json", action="store_true")

    args = parser.parse_args(argv)
    try:
        store = EvidenceStore(args.store)
        if args.cmd == "claim":
            result = store.claim(category=args.category, summary=args.summary, target=args.target)
            _print({"deduped": result.deduped, "id": result.record.id, "status": result.record.status})
            return 0
        if args.cmd == "save":
            record = store.save_reproduction(
                args.id, steps=args.step, command=args.command, output=_output(args),
                artifacts=_artifacts(args.artifact),
            )
            _print({"id": record.id, "status": record.status})
            return 0
        if args.cmd == "verify":
            record = store.verify(args.id)
            _print({"id": record.id, "status": record.status})
            return 0
        if args.cmd == "reject":
            record = store.reject(args.id, args.reason)
            _print({"id": record.id, "status": record.status})
            return 0
        decision = report(store, args.id)
        if args.json:
            _print(decision)
        else:
            sys.stdout.write(render_bulletin(decision))
        return EXIT_CODE[decision["disposition"]]
    except EvidenceError as exc:
        print(json.dumps({"error": str(exc)}, sort_keys=True), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
