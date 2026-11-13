#!/usr/bin/env python3
"""High-confidence secret scan. Matched values are never printed or stored.

Exit 0 when the scan finishes clean, 2 when a pattern matches, 1 on usage
or read errors. Stdout is always a JSON report so existing callers can parse
``.hits`` (path, line, rule, file_mode) and ``files_scanned``.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

MAX_BYTES = 2_000_000
SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".tox",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    "venv",
}

# Indicators only. The capture is never copied into the report.
RULES = (
    ("google_oauth_like", re.compile(r"AQ\.[A-Za-z0-9_\-]{20,}")),
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b")),
    ("github_fine_grained_pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}")),
    ("slack_webhook", re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("private_key", re.compile(r"-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----")),
    ("npm_token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
)


def _scan_file(path: Path, findings: list) -> int:
    if path.is_symlink():
        return 0
    try:
        info = path.stat()
    except OSError:
        return 0
    if not path.is_file() or info.st_size > MAX_BYTES:
        return 0
    try:
        data = path.read_bytes()
    except OSError:
        return 0
    if b"\0" in data[:8192]:
        return 0
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return 0
    mode = f"{info.st_mode & 0o777:04o}"
    location = str(path)
    for lineno, line in enumerate(text.splitlines(), 1):
        for rule, pattern in RULES:
            if pattern.search(line):
                findings.append({
                    "path": location,
                    "line": lineno,
                    "rule": rule,
                    "file_mode": mode,
                })
    return 1


def scan(path, findings) -> int:
    """Append hits for ``path`` (file or directory). Return files examined."""
    target = Path(path)
    if target.is_symlink() and target.is_file():
        return 0
    if target.is_file():
        return _scan_file(target, findings)
    if not target.is_dir():
        raise FileNotFoundError(str(target))
    total = 0
    for dirpath, dirnames, filenames in os.walk(target, followlinks=False):
        dirnames[:] = sorted(name for name in dirnames if name not in SKIP_DIRS)
        for name in sorted(filenames):
            total += _scan_file(Path(dirpath) / name, findings)
    return total


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="+", help="Files or directories to scan")
    parser.add_argument(
        "--json",
        action="store_true",
        help="Accepted for callers. Stdout is always the JSON report.",
    )
    args = parser.parse_args(argv)
    findings: list[dict] = []
    files = 0
    try:
        for raw in args.paths:
            files += scan(raw, findings)
    except OSError as exc:
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    report = {
        "files_scanned": files,
        "hits": findings,
        "notes": "Regex detection is heuristic; values are never printed, persisted or transferred.",
    }
    json.dump(report, sys.stdout, ensure_ascii=False)
    sys.stdout.write("\n")
    print(f"files_scanned={files} hits={len(findings)}", file=sys.stderr)
    return 2 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
