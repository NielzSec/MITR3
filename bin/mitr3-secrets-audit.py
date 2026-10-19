#!/usr/bin/env python3
"""MITR3 secret-surface audit (metadata only).

Scans a set of local paths for credential-shaped strings and reports
path/line/pattern/rule/permissions. Values are never printed or stored:
only the matched rule name and the length of the match.

usage: mitr3-secrets-audit.py PATH [PATH ...] [--json]
exit: 0 always (report is the product)
"""
from __future__ import annotations

import json
import os
import re
import stat
import sys
from pathlib import Path

SKIP_DIRS = {
    "node_modules", ".git", ".venv", "venv", "__pycache__", "site-packages",
    ".cache", ".npm", ".cargo", "target", "dist", "build", ".mypy_cache",
    ".pytest_cache", "go", "pkg", "Trash", "cache", "logs", "scratch",
}
SKIP_SUFFIX = {".pyc", ".so", ".o", ".a", ".jar", ".zip", ".tar", ".gz", ".xz",
               ".png", ".jpg", ".jpeg", ".webp", ".gif", ".mp4", ".pdf", ".woff", ".woff2"}

# name, compiled pattern, family
RULES = [
    ("openai_like_key",   re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}\b")),
    ("anthropic_key",     re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b")),
    ("github_pat",        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")),
    ("github_fine_pat",   re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,}\b")),
    ("aws_access_key",    re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("google_api_key",    re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("google_oauth_like", re.compile(r"(?<![A-Za-z0-9_])AQ\.[A-Za-z0-9_\-]{25,}")),
    ("slack_token",       re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b")),
    ("private_key_block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("bearer_literal",    re.compile(r"Bearer\s+[A-Za-z0-9_\-\.]{24,}")),
    ("jwt_literal",       re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")),
    ("db_url_with_pass",  re.compile(r"\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:@/]+:[^\s:@/]{6,}@")),
    ("assigned_secret",   re.compile(
        r"""(?i)\b(?:api[_-]?key|apikey|secret|token|passwd|password|passphrase|private[_-]?key)\b\s*[:=]\s*["']?([A-Za-z0-9_\-\.\+\*/=]{16,})""")),
]

MAX_BYTES = 2 * 1024 * 1024  # skip huge files


def mode_of(p: Path) -> str:
    try:
        return oct(stat.S_IMODE(p.stat().st_mode))
    except OSError:
        return "?"


def owner_of(p: Path) -> str:
    try:
        st = p.stat()
        import pwd
        return pwd.getpwuid(st.st_uid).pw_name
    except Exception:
        return "?"


def iter_files(root: Path):
    if root.is_file():
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".venv")]
        for fn in filenames:
            p = Path(dirpath) / fn
            if p.suffix.lower() in SKIP_SUFFIX:
                continue
            try:
                if p.stat().st_size > MAX_BYTES:
                    continue
            except OSError:
                continue
            yield p


def scan(path: Path, hits: list) -> None:
    try:
        text = path.read_text(errors="ignore")
    except (OSError, UnicodeError):
        return
    for lineno, line in enumerate(text.splitlines(), 1):
        if len(line) > 4000:
            continue
        for name, rx in RULES:
            m = rx.search(line)
            if not m:
                continue
            hits.append({
                "path": str(path),
                "line": lineno,
                "rule": name,
                "match_len": len(m.group(0)),
                "file_mode": mode_of(path),
                "owner": owner_of(path),
            })


def main() -> int:
    args = [a for a in sys.argv[1:] if a != "--json"]
    if not args:
        print(__doc__.strip())
        return 2
    hits: list[dict] = []
    scanned = 0
    for a in args:
        root = Path(os.path.expanduser(a)).resolve()
        if not root.exists():
            continue
        for f in iter_files(root):
            scanned += 1
            scan(f, hits)
    out = {
        "roots": [str(Path(os.path.expanduser(a)).resolve()) for a in args],
        "files_scanned": scanned,
        "hits": hits,
        "counts_by_rule": {},
        "exposed_modes": sorted({h["file_mode"] for h in hits}),
    }
    for h in hits:
        out["counts_by_rule"][h["rule"]] = out["counts_by_rule"].get(h["rule"], 0) + 1
    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
