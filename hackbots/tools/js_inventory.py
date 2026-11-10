#!/usr/bin/env python3
"""Extract literal fetch/axios endpoint references from one offline JS artifact.

Conservative string matching only; not a JavaScript parser or vulnerability detector.
"""
import argparse
import hashlib
import json
import os
import re
import secrets
import stat
import sys
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[2]
MAX_BYTES = 5_000_000
PATTERN = re.compile(
    r"""\b(?P<call>fetch|axios\.(?:get|post|put|patch|delete|request))\s*\(\s*['"](?P<url>[^'"\n]{1,2048})['"]""",
    re.MULTILINE,
)
VALID_PREFIX = ("/", "http://", "https://")


def read_artifact(relative):
    if not isinstance(relative, str) or not relative or "\x00" in relative:
        raise ValueError("invalid artifact path")
    rel = Path(relative)
    if rel.is_absolute() or not rel.parts or ".." in rel.parts:
        raise ValueError("only safe paths relative to MITR3 root are permitted")
    # Walk descriptors without resolving links, including links to files inside ROOT.
    parent = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in rel.parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent)
            parent = child
        fd = os.open(rel.parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    finally:
        os.close(parent)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_BYTES:
            raise ValueError("input must be a regular file of at most 5 MB")
        raw = stream.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise ValueError("file exceeds offline pilot 5 MB limit")
    return rel, raw


def save_private_report(report):
    """Persist the correlation map locally; never overwrite an existing report."""
    parent = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in ("hackbots", "private"):
            if part == "private":
                try:
                    os.mkdir(part, 0o700, dir_fd=parent)
                except FileExistsError:
                    pass
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent)
            parent = child
        info = os.fstat(parent)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise ValueError("private directory must be owned by the operator and mode 0700")
        fd = os.open(report["report_id"] + ".json",
                     os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=parent)
    finally:
        os.close(parent)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def scan(relative, *, save_private=False):
    rel, raw = read_artifact(relative)
    content = raw.decode("utf-8")
    # Match the verifier convention: only LF advances a physical line.
    lines = content.split("\n")
    result = []
    routes = {}
    for line_no, line in enumerate(lines, 1):
        for m in PATTERN.finditer(line):
            url = m.group("url")
            if not url.startswith(VALID_PREFIX):
                continue
            parts = urlsplit(url)
            # Strip URL credentials, queries and fragments; paths still need privacy review.
            location = parts.path if parts.path else "/"
            if not location.startswith("/"):
                continue
            route_id = routes.setdefault(location, f"route-{len(routes) + 1}")
            result.append({
                "line": line_no, "call": m.group("call"),
                "evidence_id": f"E{len(result) + 1:06d}", "route_id": route_id,
                "path": location, "classification": "literal-reference",
            })
    report = {
        "schema_version": 2, "visibility": "private", "report_id": secrets.token_hex(16),
        "artifact": rel.as_posix(), "sha256": hashlib.sha256(raw).hexdigest(),
        "references": result,
        "limitations": [
            "Static regex match: dynamic templates, aliases and other HTTP clients may be missed.",
            "References do not imply that endpoints exist or are vulnerable.",
            "Query strings, URL credentials and fragments are intentionally discarded.",
            "Opaque route IDs correlate only within this report; all route text is hidden in the shared view.",
            "Line numbers, call types and occurrence counts remain visible; review metadata before sharing.",
        ]
    }
    if save_private:
        save_private_report(report)
    return {"schema_version": 2, "visibility": "shared", "report_id": report["report_id"],
            "references": [{**row, "path": "/{" + row["route_id"] + "}"} for row in result],
            "limitations": report["limitations"]}


class SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, "FAIL: invalid command-line arguments; use --help\n")


def main():
    p = SafeArgumentParser(description=__doc__)
    p.add_argument("artifact", help="JS file path relative to MITR3 root")
    p.add_argument("--save-private", action="store_true",
                   help="save original routes and provenance to hackbots/private/<report_id>.json (0600)")
    args = p.parse_args()
    try:
        print(json.dumps(scan(args.artifact, save_private=args.save_private), indent=2, ensure_ascii=False))
        return 0
    except (ValueError, OSError, UnicodeError):
        print("FAIL: invalid, unsafe or unreadable local artifact", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
