"""MITR3 Web Hackerbot: strict *offline* differential observation validator.

No HTTP requests, shell, JavaScript execution or claims of authenticating raw
responses. Observations recorded by the operator are evidence *metadata* only.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

HEX = re.compile(r"[0-9a-f]{64}\Z")
DOMAIN = re.compile(r"[a-z0-9][a-z0-9.-]{1,253}\Z")
ID = re.compile(r"[1-9][0-9]{0,8}\Z")
MAX_FILE = 32_768
EXPECTED = {"schema_version", "case_id", "source_kind", "target_domain",
            "operator_reported_lab_solved", "responses"}
PHASE_FIELDS = {"phase", "http_status", "body_sha256", "body_bytes", "product_ids"}
PHASES = ("baseline", "poc")


class EvidenceRejected(ValueError):
    pass


def _check_type_bool(v):
    return type(v) is bool


def _unique(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise EvidenceRejected("duplicate JSON key")
        obj[key] = value
    return obj


def _reject_constant(_):
    raise EvidenceRejected("non-finite JSON number")


def load_record(file):
    """Read bounded JSON without following symlinks or hardlinks."""
    fd = None
    try:
        fd = os.open(file, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        st = os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1
                or not 0 < st.st_size <= MAX_FILE):
            raise EvidenceRejected("invalid observation file")
        with os.fdopen(fd, "rb", closefd=False) as src:
            raw = src.read(MAX_FILE + 1)
        if len(raw) > MAX_FILE:
            raise EvidenceRejected("observation file oversized")
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_unique,
                          parse_constant=_reject_constant)
    except (OSError, UnicodeError, ValueError, RecursionError, TypeError):
        raise EvidenceRejected("invalid observation file") from None
    finally:
        if fd is not None:
            os.close(fd)


def _phase(item):
    if type(item) is not dict or set(item) != PHASE_FIELDS:
        raise EvidenceRejected("invalid phase shape")
    if item["phase"] not in PHASES or type(item["phase"]) is not str:
        raise EvidenceRejected("invalid phase label")
    status = item["http_status"]
    size = item["body_bytes"]
    if (type(status) is not int or not 100 <= status <= 599
            or type(size) is not int or not 0 < size <= 2_000_000
            or type(item["body_sha256"]) is not str
            or HEX.fullmatch(item["body_sha256"]) is None):
        raise EvidenceRejected("invalid response metadata")
    identifiers = item["product_ids"]
    if (type(identifiers) is not list or len(identifiers) > 500
            or any(type(k) is not str or ID.fullmatch(k) is None for k in identifiers)
            or len(set(identifiers)) != len(identifiers)):
        raise EvidenceRejected("invalid product ID inventory")
    return status, set(identifiers)


def evaluate(record):
    if (type(record) is not dict or set(record) != EXPECTED
            or type(record["schema_version"]) is not int
            or record["schema_version"] != 1
            or type(record["case_id"]) is not str
            or not re.fullmatch(r"[A-Z0-9][A-Z0-9_-]{2,50}", record["case_id"])
            or record["source_kind"] != "MANUAL_RECORDED_METADATA"
            or type(record["target_domain"]) is not str
            or DOMAIN.fullmatch(record["target_domain"]) is None
            or not _check_type_bool(record["operator_reported_lab_solved"])
            or type(record["responses"]) is not list
            or len(record["responses"]) != 2):
        raise EvidenceRejected("invalid observation envelope")
    entries = record["responses"]
    if [x.get("phase") if type(x) is dict else None for x in entries] != list(PHASES):
        raise EvidenceRejected("unexpected or repeated phases")
    normal_status, normal = _phase(entries[0])
    proof_status, proof = _phase(entries[1])
    new_ids = sorted(proof - normal, key=lambda s: int(s))
    lost_ids = sorted(normal - proof, key=lambda s: int(s))
    if (entries[0]["body_sha256"] == entries[1]["body_sha256"]
            and normal != proof):
        raise EvidenceRejected("same response digest with inconsistent inventories")
    if normal_status != 200 or proof_status != 200:
        state = "INCONCLUSIVE_RESPONSE_STATUS"
    elif lost_ids:
        state = "INCONCLUSIVE_NON_MONOTONIC_INVENTORY"
    elif new_ids:
        state = "DIFFERENTIAL_RECORDED_NOT_AUTHENTICATED"
    else:
        state = "NO_DIFFERENTIAL_RECORDED"
    return {
        "schema_version": 1,
        "case_id": record["case_id"],
        "evidence_state": state,
        "baseline_count": len(normal),
        "poc_count": len(proof),
        "additional_id_count": len(new_ids),
        "missing_baseline_id_count": len(lost_ids),
        "baseline_subset_of_poc": not lost_ids,
        "operator_reported_lab_solved": record["operator_reported_lab_solved"],
        "source_authenticity": "NOT_VERIFIED_RAW_BODIES_UNAVAILABLE",
        "trace_gate": "NOT_RUN",
        "behavioral_gate": "NOT_RUN",
        "independent_review": "NOT_RUN",
        "human_approved_for_skill": False,
        "promotable": False,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="MITR3 web evidence (offline only)")
    parser.add_argument("record", help="local, manually recorded JSON observation")
    args = parser.parse_args(argv)
    try:
        result = evaluate(load_record(args.record))
        print(json.dumps(result, sort_keys=True))
        return 0
    except EvidenceRejected:
        print(json.dumps({"evidence_state": "BLOCKED", "promotable": False,
                          "error": "invalid or unsafe observation"}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
