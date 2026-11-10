#!/usr/bin/env python3
"""Inventory physical byte lines and check offline trace coverage, without authenticating execution."""
import argparse
import json
import sys

import skill_builder as sb

MAX_UNITS = 10_000
MAX_EVENTS = 10_000
MAX_HASH_BYTES = 16_000_000


def require_digest(value):
    if not isinstance(value, str) or not sb.HEX.fullmatch(value):
        raise sb.GateError("invalid SHA256")
    return value


def load_artifact(path, expected_sha256):
    require_digest(expected_sha256)
    raw = sb.read_bytes(sb.within_project(path))
    if sb.digest(raw) != expected_sha256:
        raise sb.GateError("artifact differs from reviewer pin")
    return raw


def line_units(raw):
    """LF terminates a unit; CR stays in that unit and a final empty tail is not a line."""
    artifact_hash = sb.digest(raw)
    units = []
    start = 0
    while start < len(raw):
        if len(units) >= MAX_UNITS:
            raise sb.GateError("too many physical lines")
        newline = raw.find(b"\n", start)
        end = len(raw) if newline == -1 else newline + 1
        number = len(units) + 1
        units.append({"id": f"{artifact_hash}:L{number}:{start}:{end}",
                      "line": number, "start": start, "end": end,
                      "sha256": sb.digest(raw[start:end])})
        start = end
    return units


def gates():
    return {"trace_authenticity": "NOT_VERIFIED", "behavioral_gate": "NOT_RUN",
            "output_gate": "NOT_RUN", "independent_review": "NOT_RUN",
            "human_approved": False, "promotable": False}


def verifier_hashes():
    return {path.name: sb.digest(sb.read_bytes(path)) for path in
            (sb.BASE / "skill_builder.py", sb.BASE / "execution_verifier.py")}


def inventory(artifact, artifact_sha256):
    raw = load_artifact(artifact, artifact_sha256)
    units = line_units(raw)
    return {"schema_version": 1, "state": "REVIEW", "artifact_sha256": sb.digest(raw),
            "artifact_bytes": len(raw), "units_expected": len(units), "units": units,
            "unit_kind": "physical-byte-line-lf-v1", "artifact_pin": "MATCH",
            "verifier_sha256": verifier_hashes(), "trace_gate": "NOT_RUN",
            "coverage_gate": "NOT_RUN", **gates()}


def verify(artifact, trace_path, artifact_sha256):
    raw = load_artifact(artifact, artifact_sha256)
    units = line_units(raw)
    trace_raw = sb.read_bytes(sb.within_project(trace_path))
    trace = sb.parse_json(trace_raw)
    sb.require_keys(trace, {"schema_version", "artifact_sha256", "event_count", "events"}, "trace")
    if type(trace["schema_version"]) is not int or trace["schema_version"] != 1:
        raise sb.GateError("unsupported trace version")
    if require_digest(trace["artifact_sha256"]) != artifact_sha256:
        raise sb.GateError("trace refers to another artifact")
    events = trace["events"]
    if not isinstance(events, list) or len(events) > MAX_EVENTS:
        raise sb.GateError("invalid event list")
    if type(trace["event_count"]) is not int or trace["event_count"] != len(events):
        raise sb.GateError("event count mismatch")
    intervals = []
    hash_bytes = 0
    for sequence, event in enumerate(events, 1):
        sb.require_keys(event, {"seq", "start", "end", "sha256"}, "read event")
        if type(event["seq"]) is not int or event["seq"] != sequence:
            raise sb.GateError("duplicate or out-of-order sequence")
        start, end = event["start"], event["end"]
        if type(start) is not int or type(end) is not int or not 0 <= start < end <= len(raw):
            raise sb.GateError("invalid byte interval")
        hash_bytes += end - start
        if hash_bytes > MAX_HASH_BYTES:
            raise sb.GateError("cumulative read budget exceeded")
        if require_digest(event["sha256"]) != sb.digest(raw[start:end]):
            raise sb.GateError("delivered byte hash mismatch")
        intervals.append((start, end))
    merged = []
    for start, end in sorted(intervals):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
        else:
            merged.append((start, end))
    missing = []
    index = 0
    for unit in units:
        while index < len(merged) and merged[index][1] <= unit["start"]:
            index += 1
        if (index == len(merged) or merged[index][0] > unit["start"]
                or merged[index][1] < unit["end"]):
            missing.append(unit["id"])
    coverage = "NOT_APPLICABLE" if not units else "FAIL" if missing else "PASS"
    return {"schema_version": 1, "state": "REVIEW" if coverage == "PASS" else "INCONCLUSIVE",
            "artifact_sha256": sb.digest(raw), "artifact_pin": "MATCH",
            "artifact_bytes": len(raw), "trace_sha256": sb.digest(trace_raw),
            "verifier_sha256": verifier_hashes(), "unit_kind": "physical-byte-line-lf-v1",
            "events_checked": len(events), "bytes_covered": sum(end - start for start, end in merged),
            "units_expected": len(units), "units_covered": len(units) - len(missing),
            "missing_unit_ids": missing, "trace_gate": "PASS", "coverage_gate": coverage,
            **gates(),
            "limitations": "Trace consistency and declared byte coverage only. Events may be fabricated. "
                           "No runner, trace custody, isolation, agent execution or output correctness verified."}


class SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, "BLOCKED: invalid command-line arguments; use --help\n")


def main():
    parser = SafeArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for command in ("inventory", "verify"):
        sub = commands.add_parser(command)
        sub.add_argument("artifact", help="project-relative synthetic artifact")
        if command == "verify":
            sub.add_argument("trace", help="project-relative JSON trace (not authenticated)")
        sub.add_argument("--artifact-sha256", required=True, help="digest previously pinned by reviewer")
    args = parser.parse_args()
    try:
        if args.command == "inventory":
            report = inventory(args.artifact, args.artifact_sha256)
        else:
            report = verify(args.artifact, args.trace, args.artifact_sha256)
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return int(args.command == "verify" and report["coverage_gate"] != "PASS")
    except (sb.GateError, OSError, ValueError, UnicodeError, RecursionError):
        print(json.dumps({"state": "BLOCKED", "trace_gate": "BLOCKED", "coverage_gate": "BLOCKED",
                          **gates(), "error": "Invalid, unsafe or inconsistent verification inputs"}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
