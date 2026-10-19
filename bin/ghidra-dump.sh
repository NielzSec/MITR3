#!/usr/bin/env bash
# MITR3 — Ghidra headless function-dossier dumper (PyGhidra path).
#
# Why this exists: the stock `analyzeHeadless -postScript foo.py` refuses .py
# scripts unless Ghidra was started with PyGhidra ("Ghidra was not started with
# PyGhidra. Python is not available"). The working path on this host is the
# `pyghidra` CLI from its own venv, pointed at the same Ghidra install.
#
# usage: ghidra-dump.sh <binary> <out.json> [fast_mode:true|false]
set -euo pipefail

GHIDRA_DIR="${GHIDRA_DIR:-$HOME/Tools/ghidra}"
PYGHIDRA_BIN="${PYGHIDRA_BIN:-$HOME/.local/share/pyghidra-venv/bin/pyghidra}"
DUMPER="${DUMPER:-$HOME/Documents/MegaBrain-OSINT4ALL/mitr3-nexus-re/scripts/ghidra_headless_dumper.py}"

if [ $# -lt 2 ]; then
    echo "usage: $0 <binary> <out.json> [fast_mode:true|false]" >&2
    exit 2
fi
BIN="$(readlink -f "$1")"
OUT="$2"
FAST="${3:-false}"

for f in "$BIN" "$PYGHIDRA_BIN" "$DUMPER"; do
    [ -e "$f" ] || { echo "missing: $f" >&2; exit 2; }
done

export GHIDRA_INSTALL_DIR="$GHIDRA_DIR"
echo "[ghidra-dump] target: $BIN"
echo "[ghidra-dump] out:    $OUT"
timeout 900 "$PYGHIDRA_BIN" --install-dir "$GHIDRA_DIR" "$BIN" "$DUMPER" "$OUT" "$FAST"

[ -s "$OUT" ] || { echo "[ghidra-dump] FAILED: output empty/absent" >&2; exit 1; }
python3 - "$OUT" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
fn = d["function_dossiers"]
print("[ghidra-dump] ok | %s %s | %d functions | %d bytes" % (
    d["binary_name"], d["architecture"], len(fn), len(json.dumps(d))))
PY
