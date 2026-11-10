#!/usr/bin/env bash
# Scaffold a MITR3 case workspace.
# usage: new-case.sh <case_name> [purpose]
# purpose: ctf | bug_bounty | authorized_pentest | internal_audit | reverse_research | appsec
set -euo pipefail

name="${1:?usage: new-case.sh <case_name> [purpose]}"
purpose="${2:-reverse_research}"
root="$HOME/MITR3/engagements/$name"

case "$purpose" in
  ctf|bug_bounty|authorized_pentest|internal_audit|reverse_research|appsec) ;;
  *) echo "invalid purpose: $purpose" >&2; exit 2 ;;
esac

if [[ -e "$root" ]]; then echo "case already exists: $root" >&2; exit 1; fi

mkdir -p "$root"/{evidence,logs,artifacts}
chmod 700 "$root"

cat > "$root/case.md" <<EOF
# Case: $name

- purpose: $purpose
- opened: $(date -Iseconds)
- operator: nielz
- state: open

## Objective

## Assets in scope

| asset | type | authorization |
|---|---|---|

## Out of scope

## Rules of engagement

- rate / intensity:
- window:
- test accounts:
- emergency contact:

## Hypotheses

| # | hypothesis | method | result |
|---|---|---|---|

## Evidence index

| id | file | sha256 | note |
|---|---|---|---|

## Findings

| severity | title | asset | status |
|---|---|---|---|

## Timeline

- $(date -Iseconds) case opened
EOF

cat > "$root/report.md" <<'EOF'
# Technical report

## Executive summary

## Scope and method

## Findings

### F-01 — <title>

- severity:
- asset:
- reproduction:
- impact:
- evidence:
- remediation:

## Remediation plan

## Retest log

## Unknowns
EOF

echo "created $root"
echo
echo "Nexus contract (run it yourself, interactive TTY):"
echo "  cd ~/Documents/MegaBrain-OSINT4ALL/mitr3-nexus-re"
echo "  python authorize_scope.py --workspace $name --target <absolute-artifact> --purpose $purpose --operator nielz"
echo
echo "Next: put raw output in evidence/, logs in logs/, keep sha256sum in case.md."
