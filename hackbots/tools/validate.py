#!/usr/bin/env python3
"""MITR3 Hackbots: offline, stdlib-only contract and evidence validator."""
import argparse
import hashlib
import json
import math
import os
import re
import stat
import sys
from decimal import Decimal, InvalidOperation
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class ContractError(ValueError):
    pass


def read_local(path, limit):
    """Open every component once; bound reads even if a file grows after fstat."""
    path = Path(path)
    if ".." in path.parts:
        raise ContractError("path traversal forbidden")
    path = path.absolute()
    parent = fd = None
    try:
        parent = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        for part in path.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent)
            parent = child
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > limit:
            raise ContractError("unsafe file type, link count or size")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(limit + 1)
        if len(raw) > limit:
            raise ContractError("file exceeds limit")
        return raw
    except (OSError, ValueError):
        raise ContractError("local input unavailable or unsafe") from None
    finally:
        if fd is not None:
            os.close(fd)
        if parent is not None:
            os.close(parent)


def parse_json(raw, *, exact_numbers=False):
    def unique(pairs):
        obj = {}
        for key, value in pairs:
            if key in obj:
                raise ContractError("ambiguous JSON")
            obj[key] = value
        return obj

    def number(token):
        value = Decimal(token) if exact_numbers else float(token)
        if not (value.is_finite() if exact_numbers else math.isfinite(value)):
            raise ContractError("nonfinite JSON")
        return value

    try:
        return json.loads(raw.decode("utf-8"),
                          object_pairs_hook=unique, parse_float=number, parse_constant=number)
    except (OSError, ValueError, InvalidOperation, RecursionError):
        raise ContractError("invalid or unsafe JSON input") from None


def load_json(path):
    return parse_json(read_local(path, 1_000_000))

def check_schema(data, schema, where="$"):
    errors = []
    types = schema.get("type")
    if types is not None:
        choices = types if isinstance(types, list) else [types]
        matchers = {
            "object": lambda v: isinstance(v, dict),
            "array": lambda v: isinstance(v, list),
            "string": lambda v: isinstance(v, str),
            "integer": lambda v: type(v) is int,
            "boolean": lambda v: type(v) is bool,
            "null": lambda v: v is None,
        }
        if not any(matchers[t](data) for t in choices):
            return [f"{where}: expected type {types}"]
    if "const" in schema and data != schema["const"]:
        errors.append(f"{where}: does not match required constant")
    if "enum" in schema and data not in schema["enum"]:
        errors.append(f"{where}: invalid enum choice")
    if isinstance(data, str):
        if len(data) < schema.get("minLength", 0):
            errors.append(f"{where}: too short")
        if "pattern" in schema and not re.fullmatch(schema["pattern"], data):
            errors.append(f"{where}: invalid format")
    if type(data) is int and data < schema.get("minimum", -1):
        errors.append(f"{where}: below minimum")
    if isinstance(data, dict):
        for field in schema.get("required", []):
            if field not in data:
                errors.append(f"{where}.{field}: missing required field")
        props = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            for key in data.keys() - props.keys():
                errors.append(f"{where}.{key}: unknown field")
        for key, value in data.items():
            if key in props:
                errors += check_schema(value, props[key], f"{where}.{key}")
    if isinstance(data, list):
        if len(data) < schema.get("minItems", 0):
            errors.append(f"{where}: too few items")
        if schema.get("uniqueItems") and len({repr(i) for i in data}) != len(data):
            errors.append(f"{where}: duplicate values")
        for i, value in enumerate(data):
            errors += check_schema(value, schema.get("items", {}), f"{where}[{i}]")
    return errors


def artifact(relative, digest):
    p = Path(relative)
    if p.is_absolute() or not p.parts or ".." in p.parts:
        return ["artifact path must be project-relative without traversal"]
    try:
        raw = read_local(ROOT / p, 25 * 1024 * 1024)
    except ContractError:
        return ["artifact missing, unsafe or oversized"]
    if hashlib.sha256(raw).hexdigest() != digest:
        return ["artifact SHA256 mismatch"]
    return []


def validate(kind, obj, related=None):
    schema = load_json(Path(__file__).resolve().parents[1] / "contracts" / f"{kind}.schema.json")
    errors = check_schema(obj, schema)
    if errors:
        return errors
    if kind == "mission":
        return artifact(obj["artifact"]["path"], obj["artifact"]["sha256"])
    if related is not None:
        if (obj["mission_id"], obj["skill"]) != (related["mission_id"], related["skill"]):
            errors.append("result references a different mission or skill")
    coverage = obj["coverage"]
    if coverage["analyzed"] > coverage["expected"]:
        errors.append("analyzed exceeds expected")
    ids = [e["id"] for e in obj["evidence"]]
    if len(ids) != len(set(ids)):
        errors.append("duplicate evidence IDs")
    for ev in obj["evidence"]:
        if not re.fullmatch(r"[a-f0-9]{64}", ev["sha256"]):
            errors.append(f"invalid evidence digest: {ev['id']}")
        errors += artifact(ev["source"], ev["sha256"])
    for i, claim in enumerate(obj["claims"]):
        for ref in claim["evidence_ids"]:
            if ref not in ids:
                errors.append(f"claims[{i}] cites absent evidence {ref}")
    review = obj["review"]
    if obj["status"] == "accepted":
        if review["decision"] != "approved" or not review["reviewer"]:
            errors.append("accepted result must have named human reviewer and approved decision")
        if not all(obj["checklist"].values()):
            errors.append("accepted result requires complete checklist")
        if coverage["analyzed"] != coverage["expected"]:
            errors.append("accepted result requires complete coverage")
        if not obj["evidence"]:
            errors.append("accepted result requires evidence")
    if obj["status"] == "review_pending" and review["decision"] != "pending":
        errors.append("review_pending result must have pending review decision")
    return errors


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, "FAIL: invalid contract arguments; use --help\n")


def main():
    parser = SafeParser(description=__doc__)
    parser.add_argument("kind", choices=["mission", "result"])
    parser.add_argument("file")
    parser.add_argument("--mission", help="Mission file when validating a related result")
    args = parser.parse_args()
    try:
        obj = load_json(args.file)
        related = load_json(args.mission) if args.mission else None
        if related is not None:
            mission_errors = validate("mission", related)
            if mission_errors:
                raise ContractError("related mission invalid: " + "; ".join(mission_errors))
        errors = validate(args.kind, obj, related)
    except (ContractError, ValueError, RecursionError):
        errors = ["invalid or unsafe contract input"]
    if errors:
        # Schema paths may contain attacker-controlled keys or identifiers.
        print("FAIL: invalid contract or inconsistent local evidence", file=sys.stderr)
        return 1
    print("PASS: structural contract and local evidence checks (NOT human authorization/claim truth)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
