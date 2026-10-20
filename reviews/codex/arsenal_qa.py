#!/usr/bin/env python3
"""Independent, read-only QA of MITR3 Arsenal phase2/3 snapshots.

No package installation, command execution, cloud authentication or network.
Only allowlisted metadata is written to this QA report. Raw installer output,
commands, tokens, endpoints and tool arguments are never copied into output.
"""
from __future__ import annotations

import argparse
from collections import Counter
import datetime as dt
import json
import os
from pathlib import Path
import re
import sys

SAFE_NAME = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
SAFE_VERSION = re.compile(r"^[0-9]+(?:[.][0-9A-Za-z+-]+){0,6}$")

def failure_type(row: dict) -> str:
    if row.get("status") in ("validated", "smoke_ok"):
        return "none"
    raw = str(row.get("install_error") or "").lower()
    if any(term in raw for term in ("could not resolve", "name resolution", "dns", "proxy.golang.org", "network is unreachable", "lookup proxy.golang.org")):
        return "network"
    if any(term in raw for term in ("no new privileges", "permission denied", "sudo:", "not permitted")):
        return "permissions"
    if any(term in raw for term in ("no matching distribution found", "could not find a version", "package not found")):
        return "package_resolution"
    if row.get("status") == "missing":
        return "not_installed"
    return "other"

def assess(snapshot: dict, now: dt.datetime | None = None) -> dict:
    if not isinstance(snapshot, dict) or not isinstance(snapshot.get("tools"), list):
        raise ValueError("invalid arsenal snapshot")
    now = now or dt.datetime.now(dt.timezone.utc)
    timestamp = snapshot.get("timestamp")
    try:
        when = dt.datetime.fromisoformat(str(timestamp).replace("Z", "+00:00"))
        if when.tzinfo is None:
            raise ValueError
        age_minutes = round(max(0, (now - when).total_seconds()/60), 1)
    except (ValueError, AttributeError):
        age_minutes = None
    rows = []
    seen = set()
    for raw in snapshot["tools"]:
        if not isinstance(raw, dict):
            continue
        name = raw.get("name")
        if not isinstance(name, str) or not SAFE_NAME.fullmatch(name):
            name = "invalid-name"
        if name in seen:
            raise ValueError("duplicate tool entry")
        seen.add(name)
        status = str(raw.get("status", "unknown"))
        if status not in ("validated", "smoke_ok", "missing", "failed"):
            status = "unknown"
        phase = raw.get("phase")
        phase = phase if phase in (2, 3) else "invalid"
        version = raw.get("version")
        if version is not None and (not isinstance(version, str) or not SAFE_VERSION.fullmatch(version)):
            version = "invalid-version"
        rows.append(dict(name=name, phase=phase, status=status,
                         version=version, blocker=failure_type(raw)))
    counts = dict(Counter(row["status"] for row in rows))
    blockers = dict(Counter(row["blocker"] for row in rows if row["blocker"] != "none"))
    notes = []
    if age_minutes is None or age_minutes > 30:
        notes.append("Snapshot is older than 30 minutes or timestamp invalid; rerun the owner check when appropriate.")
    if any(row["blocker"] == "permissions" for row in rows):
        notes.append("Privilege errors may reflect execution sandbox and not the actual Arch host; do not modify system ownership or sudo rules blindly.")
    if any(row["blocker"] in ("network", "package_resolution") for row in rows):
        notes.append("Network/package failures need DNS and upstream package verification before diagnosing compatibility.")
    if snapshot.get("action") == "install":
        notes.append("A recorded installation attempt is not proof of successful installation; use validated/smoke_ok status only.")
    return dict(timestamp=str(timestamp), age_minutes=age_minutes,
                source_action=str(snapshot.get("action")),
                total=len(rows), counts=counts, blockers=blockers,
                tools=rows, notes=notes)

def markdown(data: dict) -> str:
    lines = [
        "# MITR3 — Codex Arsenal independent QA", "",
        "Source snapshot timestamp: " + data["timestamp"],
        "Age (minutes): " + str(data["age_minutes"]),
        "Snapshot action: " + data["source_action"],
        "Total tools: " + str(data["total"]),
        "Status summary: " + ", ".join(f"{k}={v}" for k,v in sorted(data["counts"].items())),
        "", "| Tool | Phase | Status | Version | Blocker |",
        "|---|---:|---|---|---|",
    ]
    for row in data["tools"]:
        lines.append("| {name} | {phase} | {status} | {version} | {blocker} |".format(
            name=row["name"], phase=row["phase"], status=row["status"],
            version=row["version"] or "—", blocker=row["blocker"]))
    lines.extend(["", "## Caveats"])
    lines.extend("- " + x for x in data["notes"])
    lines.extend(["", "## Actionable QA checklist",
                  "1. Distinguish installed, CLI-smoke-verified and real protocol/network-functional.",
                  "2. Preserve install logs only in private directories; sanitize error messages before adding to shared docs/RAG.",
                  "3. Retry network/privilege installation solely from approved host session; never run installers against live targets.",
                  "4. Check native pacman package availability and exact upstream package path; pin versions or record hashes.",
                  "5. Check wrapper idempotence and do not overwrite unrelated executables.",
                  "", "Security: this report only reproduces allowlisted status metadata, not raw stdout, commands or secrets.",
                  ""])
    return "\n".join(lines)

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", type=Path, default=Path.home()/"MITR3/reports/arsenal-phase23-latest.json")
    ap.add_argument("--out", type=Path, default=Path.home()/"MITR3/reviews/codex/reports/arsenal-qa-latest")
    args = ap.parse_args()
    try:
        data = assess(json.loads(args.input.read_text(encoding="utf-8")))
    except (ValueError, OSError, TypeError):
        print('Arsenal QA unavailable: invalid or missing input', file=sys.stderr)
        return 2
    args.out.parent.mkdir(parents=True, exist_ok=True)
    os.umask(0o077)
    md = args.out.with_suffix(".md")
    js = args.out.with_suffix(".json")
    md.write_text(markdown(data), encoding="utf-8")
    js.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    md.chmod(0o600)
    js.chmod(0o600)
    print(f"Arsenal QA: {data['total']} tools, {data['counts']}; report: {md}")
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
