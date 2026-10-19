#!/usr/bin/env bash
# MITR3 static scan pipeline — one command per engagement.
# usage: mitr3-scan.sh <case-name> <target-dir> [label]
# writes: ~/MITR3/engagements/<case>/{evidence,logs}/findings.md
# requires: semgrep, trivy, osv-scanner (PATH or ~/.local/bin), jq
set -uo pipefail
umask 077

CASE="${1:?case name}"; TARGET_ARG="${2:?target dir}"; LABEL="${3:-static}"
[ -d "$TARGET_ARG" ] || { echo "not a dir: $TARGET_ARG" >&2; exit 2; }
TARGET="$(realpath "$TARGET_ARG")"
CASE_DIR="$HOME/MITR3/engagements/$CASE"
EVID="$CASE_DIR/evidence"; LOGS="$CASE_DIR/logs"
mkdir -p "$EVID" "$LOGS"

export PATH="$HOME/.local/bin:$PATH"
need() { command -v "$1" >/dev/null || { echo "missing: $1" >&2; exit 3; }; }
need semgrep; need trivy; need osv-scanner; need jq

STAMP="$(date +%Y%m%dT%H%M%S)"
run() {  # run <label> <outfile> <cmd...>
  local label="$1" out="$2"; shift 2
  local t0; t0=$(date +%s)
  "$@" >"$out" 2>"$LOGS/${label}_${STAMP}.err"
  local rc=$?; local dt=$(( $(date +%s) - t0 ))
  printf '%-10s rc=%s %ss %s\n' "$label" "$rc" "$dt" "$out" | tee -a "$LOGS/pipeline_${STAMP}.log"
}

echo "[+] case=$CASE target=$TARGET label=$LABEL"
run semgrep  "$EVID/semgrep.json"  semgrep --json --metrics=off --config=p/python --config=p/secrets "$TARGET"
run trivy    "$EVID/trivy.json"    trivy fs --quiet --format json --scanners vuln,secret,misconfig "$TARGET"
run osv      "$EVID/osv.json"      osv-scanner scan source -r "$TARGET" --format json
run secrets  "$EVID/secrets.json"  "$HOME/MITR3/bin/mitr3-secrets-audit.py" "$TARGET"

( cd "$EVID" && sha256sum ./*.json > "SHA256SUMS.$STAMP" )

# ---- summary ----
SEM=$(jq -r '[.results[]?]|length' "$EVID/semgrep.json" 2>/dev/null || echo 0)
TRIVY_V=$(jq -r '[.Results[]?.Vulnerabilities[]?]|length' "$EVID/trivy.json" 2>/dev/null || echo 0)
TRIVY_M=$(jq -r '[.Results[]?.Misconfigurations[]?|select(.Status=="FAIL")]|length' "$EVID/trivy.json" 2>/dev/null || echo 0)
TRIVY_S=$(jq -r '[.Results[]?.Secrets[]?]|length' "$EVID/trivy.json" 2>/dev/null || echo 0)
OSV_N=$(jq -r '[.results[]?.packages[]?.vulnerabilities[]?]|length' "$EVID/osv.json" 2>/dev/null || echo 0)
SEC_N=$(jq -r '.hits|length' "$EVID/secrets.json" 2>/dev/null || echo 0)

OUT="$CASE_DIR/findings.md"
{
  echo "# Findings — $CASE ($LABEL)"
  echo
  echo "Target: \`$TARGET\`  ·  $(date -Is)  ·  scan \`$STAMP\`"
  echo
  echo "| scanner | signal |"
  echo "|---|---|"
  echo "| semgrep | $SEM resultados |"
  echo "| trivy vuln | $TRIVY_V |"
  echo "| trivy misconfig (FAIL) | $TRIVY_M |"
  echo "| trivy secret | $TRIVY_S |"
  echo "| osv-scanner | $OSV_N |"
  echo "| secrets-audit | $SEC_N |"
  echo
  echo "## Trivy misconfigurations"
  echo
  jq -r '.Results[]? | .Target as $t | .Misconfigurations[]? | select(.Status=="FAIL")
         | "- `\(.ID)` **\(.Severity)** \(.Title) — `\($t|split(" (")[0])`"' "$EVID/trivy.json" 2>/dev/null | head -40
  echo
  echo "## Trivy vulnerabilities by severity"
  echo
  jq -r '[.Results[]?.Vulnerabilities[]?|.Severity] | group_by(.) | map({(.[0]): length}) | add // {}' "$EVID/trivy.json" 2>/dev/null
  echo
  echo "## Semgrep (top rules)"
  echo
  jq -r '[.results[]?|.check_id] | group_by(.) | map({rule:.[0], n:length}) | sort_by(-.n) | .[:10][] | "- `\(.rule)` ×\(.n)"' "$EVID/semgrep.json" 2>/dev/null
  echo
  echo "## osv-scanner packages"
  echo
  echo "Aviso: para requirements sem pin, o osv-scanner resolve a **versao minima** da faixa;"
  echo "versões antigas e seus advisories podem ser artefato. Confirme contra o ambiente instalado."
  echo
  jq -r '"| pacote | versao resolvida | vulns |\n|---|---|---|", (.results[]?.packages[]? | "| \(.package.name) | \(.package.version) | \((.vulnerabilities//[])|length) |")' "$EVID/osv.json" 2>/dev/null | head -20
  echo
  echo "## Secrets audit (paths only, values never stored)"
  echo
  jq -r '.hits[:20][]? | "- `\(.path|sub("/home/nielz";"~")):\(.line)` \(.rule) mode=\(.file_mode)"' "$EVID/secrets.json" 2>/dev/null
  echo
  echo "## Artifacts"
  echo
  echo '```'
  ls -1 "$EVID" | sed 's/^/evidence\//'
  echo '```'
} > "$OUT"

echo "[+] $OUT"
sed -n '1,14p' "$OUT"
