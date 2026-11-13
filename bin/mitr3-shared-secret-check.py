#!/usr/bin/env python3
"""Read-only MITR3 shared surface secret check. No credential values printed/stored.
Checks Maestri live notes and MITR3 documentation, not the private secret vault.
Exit 2 if potential secret exposure is found, 0 if clean, 1 on tool error.
"""
import datetime as dt
import json
import os
from pathlib import Path
import subprocess
import sys


def check(base: Path, include_all_workspaces: bool = True) -> dict:
    paths = [base / "MITR3/docs", base / "MITR3/skills"]
    if include_all_workspaces:
        paths.extend(sorted((base / ".maestri/workspaces").glob("*/notes")))
    paths = [p for p in paths if p.exists()]
    audit = base / "MITR3/bin/mitr3-secrets-audit.py"
    if not audit.is_file():
        raise FileNotFoundError(str(audit))
    result = subprocess.run(
        [sys.executable, str(audit), *[str(p) for p in paths], "--json"],
        capture_output=True, text=True, timeout=40, check=False,
    )
    # 0 = clean scan, 2 = findings (the report is still on stdout). Other
    # statuses mean the auditor did not produce a usable report.
    if result.returncode not in (0, 2):
        raise RuntimeError("secret auditor returned nonzero status")
    source = json.loads(result.stdout)
    hits = [
        {"path": h["path"], "line": h["line"], "rule": h["rule"],
         "file_mode": h["file_mode"]}
        for h in source.get("hits", [])
    ]
    return {
        "checked_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "status": "warn" if hits else "ok",
        "files_scanned": source.get("files_scanned", 0),
        "potential_exposures": len(hits),
        "hits": hits,
        "notes": "Regex detection is heuristic; values are never printed, persisted or transferred.",
    }


def main():
    base = Path.home()
    try:
        report = check(base)
    except Exception as exc:
        print(json.dumps({"status": "error", "type": type(exc).__name__}))
        return 1
    location = base / "MITR3/state/shared-secret-check-latest.json"
    location.parent.mkdir(parents=True, exist_ok=True)
    os.umask(0o077)
    location.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    location.chmod(0o600)
    print(json.dumps(report, ensure_ascii=False))
    return 2 if report["status"] == "warn" else 0


if __name__ == "__main__":
    raise SystemExit(main())
