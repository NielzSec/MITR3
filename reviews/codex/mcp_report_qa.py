#!/usr/bin/env python3
"""Read-only semantic QA of Codex MCP check. Never starts MCP servers."""
from __future__ import annotations
import argparse
import datetime as dt
import json
import os
from pathlib import Path
import re
import sys

SAFE_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,80}$")

def assess_server(row: dict, client_error: bool) -> dict:
    name = row.get("name", "unknown")
    if not isinstance(name, str) or not SAFE_NAME.fullmatch(name):
        name = "invalid-name"
    kind = row.get("type") if row.get("type") in ("local", "remote") else "unknown"
    client = row.get("opencode", "")
    boot = row.get("boot", "")
    issues = row.get("issues", [])
    if not isinstance(issues, list):
        issues = ["invalid issues field"]
    if issues:
        grade, reason = "configuration_review", "Configuration diagnostics reported an issue"
    elif not client_error and client == "connected":
        grade, reason = "client_reported_connected", "OpenCode reports connected, but tools/list not verified independently"
    elif not client_error and client in ("failed", "disconnected", "disabled"):
        grade, reason = "client_reported_unavailable", "OpenCode reported unavailable"
    elif boot == "pass" and kind == "remote":
        grade, reason = "unverified_http_reachable", "HTTP response only; no MCP protocol handshake"
    elif boot == "pass" and kind == "local":
        grade, reason = "unverified_process_stable", "Separate process survived 5 seconds; MCP handshake not verified"
    elif boot == "fail":
        grade, reason = "launch_failure_review", "Separate launch failed; actual active MCP connection not confirmed"
    else:
        grade, reason = "unknown", "Insufficient evidence"
    detail = str(row.get("boot_detail", ""))
    if kind == "remote":
        match = re.fullmatch(r"HTTP (\d{3})", detail)
        signal = "HTTP " + match.group(1) if match else "remote response unclassified"
    elif boot == "pass":
        signal = "local process survived smoke window"
    elif boot == "fail":
        signal = "local launch failure"
    else:
        signal = "no transport evidence"
    return dict(name=name, transport=kind, assessment=grade,
                transport_signal=signal, reason=reason,
                configuration_issues=len(issues))

def assess(source: dict, now: dt.datetime | None = None) -> dict:
    if not isinstance(source, dict) or not isinstance(source.get("servers"), list):
        raise ValueError("invalid diagnostic schema")
    now = now or dt.datetime.now(dt.timezone.utc)
    raw_time = source.get("timestamp")
    try:
        timestamp = dt.datetime.fromisoformat(raw_time.replace("Z", "+00:00"))
        if timestamp.tzinfo is None:
            raise ValueError("timezone missing")
        age = max(0, round((now - timestamp).total_seconds() / 60, 1))
    except (ValueError, TypeError, AttributeError):
        age = None
    cli_error = bool(source.get("opencode_list_error"))
    servers = [assess_server(row, cli_error) for row in source["servers"] if isinstance(row, dict)]
    counts = {}
    for row in servers:
        counts[row["assessment"]] = counts.get(row["assessment"], 0) + 1
    warnings = []
    if cli_error:
        warnings.append("OpenCode status unavailable; zero connections confirmed via its CLI")
    if age is None or age > 30:
        warnings.append("Original status snapshot is stale or timestamp invalid")
    if counts.get("launch_failure_review"):
        warnings.append("Separate smoke launch failures do not prove that live client MCP sessions are down")
    if counts.get("unverified_http_reachable"):
        warnings.append("HTTP GET 405 or 406 is not an MCP initialize/tools/list success")
    return dict(source_time=raw_time if isinstance(raw_time, str) else "unknown",
                age_minutes=age, configured=len(servers),
                client_status_available=not cli_error,
                client_confirmed=counts.get("client_reported_connected", 0),
                counts=counts, warnings=warnings, servers=servers)

def markdown(report: dict) -> str:
    lines = [
        "# MITR3 — independent QA for Codex MCP check", "",
        "Original timestamp: " + str(report["source_time"]),
        "Age in minutes: " + str(report["age_minutes"]),
        "Configured servers: " + str(report["configured"]),
        "OpenCode client-confirmed connections: " + str(report["client_confirmed"]),
        "This QA tool performs zero process launches and zero network requests.", "",
        "| Server | QA grade | Limited transport evidence |",
        "|---|---|---|"
    ]
    for row in report["servers"]:
        lines.append("| " + row["name"] + " | " + row["assessment"] + " | " + row["transport_signal"] + " |")
    lines.extend(["", "## Caveats"])
    lines.extend("- " + item for item in report["warnings"])
    lines.extend(["", "## Recommendations to Codex and OpenCode",
                  "1. Separate process health, HTTP reachability, protocol handshake and client-connected state.",
                  "2. To verify an MCP server, use JSON-RPC initialize and tools/list over stdio or Streamable HTTP.",
                  "3. GET HTTP 405/406 does not prove MCP works and is not necessarily a server failure.",
                  "4. A 5-second subprocess test may fail while the real persistent client works.",
                  "5. Diagnose OpenCode HTTP 500 without restarting active agent sessions.",
                  "6. Never persist raw stderr, credentials, Authorization headers or private tool responses.",
                  "",
                  "MCP specification: https://modelcontextprotocol.io/specification/2025-11-25/basic/transports",
                  ""])
    return "\n".join(lines)

def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--input", type=Path,
                   default=Path.home() / "MITR3/reports/mcp-check-latest.json")
    p.add_argument("--out", type=Path,
                   default=Path.home() / "MITR3/reviews/codex/reports/mcp-qa-latest")
    args = p.parse_args()
    try:
        report = assess(json.loads(args.input.read_text(encoding="utf-8")))
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print("QA unavailable: " + type(exc).__name__, file=sys.stderr)
        return 2
    args.out.parent.mkdir(parents=True, exist_ok=True)
    os.umask(0o077)
    json_path, md_path = args.out.with_suffix(".json"), args.out.with_suffix(".md")
    json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    md_path.write_text(markdown(report), encoding="utf-8")
    json_path.chmod(0o600)
    md_path.chmod(0o600)
    print("Review: " + str(md_path))
    print("Configured: %s; client-confirmed: %s; warnings: %s" %
          (report["configured"], report["client_confirmed"], len(report["warnings"])))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
