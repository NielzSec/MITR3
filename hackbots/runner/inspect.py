"""Read-only, bounded, metadata-only MITR3 evidence inspection for agent handoffs.

Never exposes artifact contents, source paths, error text, journals, worker stdout,
prompts, private hashes or private filenames. This is NOT a security principal:
agents with generic shell/filesystem permissions can bypass this interface.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

from . import trace_store, outcome_store

HEX32 = re.compile(r"[0-9a-f]{32}\Z")
KINDS = {"complete": "runs", "failed": "failures"}
FILES = {
    "complete": {"manifest.json", "snapshot.bin", "trace.json", "journal.json", "result.json"},
    "failed": {"manifest.json", "snapshot.bin", "partial-trace.json", "journal.json"},
}
CAPS = {
    "manifest.json": 131072, "snapshot.bin": 1000000,
    "trace.json": 2000000, "partial-trace.json": 2000000,
    "journal.json": 4000000, "result.json": 32768, "outcome.json": 4096,
}


class InspectionBlocked(ValueError):
    pass


def _directory(parent, name):
    """Refuse unsafe ownership, modes and symlinks at every private level."""
    fd = None
    try:
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        st = os.fstat(fd)
        if st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) != 0o700:
            raise InspectionBlocked("unsafe directory")
        return fd
    except (OSError, InspectionBlocked):
        if fd is not None:
            os.close(fd)
        raise InspectionBlocked("private inspection blocked") from None


def _open_evidence_dir(kind, identifier=None):
    if kind not in KINDS:
        raise InspectionBlocked("invalid kind")
    if identifier is not None and (
            type(identifier) is not str or HEX32.fullmatch(identifier) is None):
        raise InspectionBlocked("invalid identifier")
    # project root and hackbots are trusted installation paths, never user input
    root = private = category = None
    try:
        root = os.open(trace_store.PROJECT / "hackbots",
                       os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        private = _directory(root, "private")
        category = _directory(private, KINDS[kind])
        if identifier is None:
            owned_fd = category
            category = None
            return owned_fd
        return _directory(category, identifier)
    except OSError:
        raise InspectionBlocked("private inspection unavailable") from None
    finally:
        if category is not None:
            os.close(category)
        if private is not None:
            os.close(private)
        if root is not None:
            os.close(root)


def _read_file(folder_fd, name):
    if name not in CAPS:
        raise InspectionBlocked("unapproved evidence file")
    fd = None
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=folder_fd)
        st = os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1
                or st.st_uid != os.getuid()
                or stat.S_IMODE(st.st_mode) != 0o600
                or st.st_size > CAPS[name]):
            raise InspectionBlocked("unsafe evidence file")
        with os.fdopen(fd, "rb", closefd=False) as file:
            raw = file.read(CAPS[name] + 1)
        if len(raw) > CAPS[name]:
            raise InspectionBlocked("oversize evidence file")
        return raw
    except (OSError, InspectionBlocked):
        raise InspectionBlocked("private inspection blocked") from None
    finally:
        if fd is not None:
            os.close(fd)


def _parse_manifest(raw):
    def object_pairs(pairs):
        obj = {}
        for key, value in pairs:
            if key in obj:
                raise InspectionBlocked("ambiguous manifest")
            obj[key] = value
        return obj
    try:
        record = json.loads(raw.decode("utf-8"), object_pairs_hook=object_pairs,
                            parse_constant=lambda _: (_ for _ in ()).throw(
                                InspectionBlocked("invalid manifest number")))
    except (UnicodeError, ValueError, RecursionError):
        raise InspectionBlocked("invalid evidence manifest") from None
    if type(record) is not dict:
        raise InspectionBlocked("invalid evidence manifest")
    return record


def _outcome_status(outcome, raw_manifest, identifier):
    """Only local consistency: no independent identity, attestation or promotion."""
    expected = {"version", "run_id", "manifest_sha256", "status", "reason_code",
                "trace_gate", "coverage_gate", "deterministic_oracle",
                "output_gate", "behavioral_gate", "trace_authenticity",
                "human_approved", "promotable"}
    if (set(outcome) != expected or type(outcome["version"]) is not int
            or outcome["version"] != 1 or outcome["run_id"] != identifier
            or outcome["manifest_sha256"] != hashlib.sha256(raw_manifest).hexdigest()
            or outcome["output_gate"] != "NOT_RUN"
            or outcome["behavioral_gate"] != "NOT_RUN"
            or outcome["trace_authenticity"] != "NOT_VERIFIED"
            or outcome["human_approved"] is not False
            or outcome["promotable"] is not False):
        raise InspectionBlocked("invalid local outcome")
    status = outcome["status"]
    if type(status) is not str or status not in outcome_store._ALLOWED:
        raise InspectionBlocked("invalid local outcome state")
    want_trace, allowed_coverage, want_oracle, reasons = outcome_store._ALLOWED[status]
    if (outcome["trace_gate"] != want_trace
            or outcome["coverage_gate"] not in allowed_coverage
            or outcome["deterministic_oracle"] != want_oracle
            or (outcome["reason_code"] is not None if reasons is None
                else outcome["reason_code"] not in reasons)):
        raise InspectionBlocked("inconsistent local outcome")
    return {"VERIFIED": "RECORDED_LOCAL_VERIFIED_NOT_APPROVED",
            "FAILED": "RECORDED_LOCAL_ORACLE_FAILED",
            "BLOCKED": "RECORDED_LOCAL_VERIFICATION_BLOCKED"}[status]


def inspect_one(kind, identifier):
    """Fail closed and return ONLY selected safe schema fields."""
    fd = _open_evidence_dir(kind, identifier)
    try:
        names = set(os.listdir(fd))
        has_outcome = kind == "complete" and "outcome.json" in names
        allowed = FILES[kind] | ({"outcome.json"} if has_outcome else set())
        if names != allowed:
            raise InspectionBlocked("evidence set incomplete or unexpected")
        raw_manifest = _read_file(fd, "manifest.json")
        manifest = _parse_manifest(raw_manifest)
        expected = FILES[kind] - {"manifest.json"}
        digests = manifest.get("files_sha256")
        if (manifest.get("run_id") != identifier or type(digests) is not dict
                or set(digests) != expected):
            raise InspectionBlocked("invalid evidence binding")
        for name in sorted(expected):
            want = digests[name]
            if type(want) is not str or re.fullmatch(r"[0-9a-f]{64}", want) is None:
                raise InspectionBlocked("invalid artifact digest")
            if hashlib.sha256(_read_file(fd, name)).hexdigest() != want:
                raise InspectionBlocked("evidence changed")

        # Check the envelope, not execution: matching local hashes do not authenticate gates.
        if (type(manifest.get("version")) is not int or manifest["version"] != 1
                or manifest.get("output_gate") != "NOT_RUN"
                or manifest.get("promotable") is not False
                or manifest.get("human_approved") is not False
                or manifest.get("behavioral_gate") != "NOT_RUN"
                or manifest.get("trace_authenticity") != "NOT_VERIFIED"):
            raise InspectionBlocked("unapproved promotion claim")
        local_outcome = "NOT_RECORDED"
        if kind == "complete":
            if (manifest.get("state") not in ("REVIEW", "SESSION_RECORDED") or manifest.get("result_submitted") is not True):
                raise InspectionBlocked("inconsistent success envelope")
            # Historical records have no outcome; treat as session-only, never
            # verified. A crash between persistence and verification is the same.
            state = "RECORDED_SESSION_AWAITING_OUTCOME"
            if has_outcome:
                outcome = _parse_manifest(_read_file(fd, "outcome.json"))
                state = _outcome_status(outcome, raw_manifest, identifier)
                local_outcome = outcome["status"]
        else:
            if (manifest.get("state") not in ("BLOCKED", "TIMEOUT")
                    or manifest.get("trace_gate") != "NOT_VERIFIED"
                    or manifest.get("coverage_gate") != "NOT_RUN"
                    or manifest.get("worker_exit_verified") is not False):
                raise InspectionBlocked("inconsistent failure envelope")
            state = "RECORDED_BLOCKED_OR_TIMEOUT"
        return {
            "inspection": "CONSISTENT_LOCAL_HASHES_NOT_AUTHENTICATED",
            "kind": kind,
            "run_id": identifier,
            "state": state,
            "declared_outcome": manifest["state"],
            "local_verification_outcome": local_outcome,
            "artifact_count": len(expected) + int(has_outcome),
            "behavioral_gate": "NOT_RUN",
            "trace_authenticity": "NOT_VERIFIED",
            "human_approved": False,
            "promotable": False,
        }
    finally:
        os.close(fd)


def summary(kind, limit=25):
    if type(limit) is not int or not 1 <= limit <= 100:
        raise InspectionBlocked("invalid sample limit")
    fd = _open_evidence_dir(kind)
    try:
        names = []
        with os.scandir(fd) as entries:
            for entry in entries:
                if len(names) >= 10000:
                    raise InspectionBlocked("too many private entries")
                names.append(entry.name)
        identifiers = sorted(name for name in names if HEX32.fullmatch(name))
        invalid_names = len(names) - len(identifiers)
    finally:
        os.close(fd)
    sampled = identifiers[:limit]  # deterministic sample, NOT newest chronological runs
    checked = blocked = 0
    for identifier in sampled:
        try:
            inspect_one(kind, identifier)
            checked += 1
        except InspectionBlocked:
            blocked += 1
    return {
        "kind": kind,
        "total_opaque_run_directories": len(identifiers),
        "unexpected_names": invalid_names,
        "sampled": len(sampled),
        "consistent_local_hashes": checked,
        "blocked_or_inconsistent": blocked,
        "remaining_unchecked": len(identifiers) - len(sampled),
        "sampling": "LEXICOGRAPHIC_OPAQUE_IDS_NOT_RECENCY",
        "trace_authenticity": "NOT_VERIFIED",
        "behavioral_gate": "NOT_RUN",
        "promotable": False,
    }


class SafeParser(argparse.ArgumentParser):
    def error(self, _):
        self.exit(2, "BLOCKED: invalid inspection request\n")


def main(argv=None):
    parser = SafeParser(description="MITR3 safe metadata-only evidence reader")
    sub = parser.add_subparsers(dest="command", required=True, parser_class=SafeParser)
    show = sub.add_parser("inspect")
    show.add_argument("--kind", choices=tuple(KINDS), required=True)
    show.add_argument("--run-id", required=True)
    overview = sub.add_parser("summary")
    overview.add_argument("--kind", choices=tuple(KINDS), required=True)
    overview.add_argument("--limit", type=int, default=25)
    args = parser.parse_args(argv)
    try:
        outcome = inspect_one(args.kind, args.run_id) if args.command == "inspect" else summary(
            args.kind, args.limit)
        print(json.dumps(outcome, sort_keys=True))
        return 0
    except (InspectionBlocked, OSError, ValueError, TypeError):
        print(json.dumps({
            "inspection": "BLOCKED",
            "behavioral_gate": "NOT_RUN", "promotable": False,
            "error": "private evidence unavailable, inconsistent or unsafe",
        }))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
