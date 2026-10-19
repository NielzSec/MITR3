#!/usr/bin/env bash
# MITR3 CodeQL — versioned security-extended scan without altering repository files.
# Usage: mitr3-codeql.sh <repo> [python|javascript|go]
# Go cannot use build-mode=none (upstream restriction). Explicit opt-in is required:
# MITR3_CODEQL_ALLOW_GO_BUILD=1 mitr3-codeql.sh <go-repo> go
set -Eeuo pipefail
umask 077

usage() {
  echo "Uso: $0 <repo> [python|javascript|go]"
  echo "Go requer autobuild (executa compilação). Habilite MITR3_CODEQL_ALLOW_GO_BUILD=1 para Go."
}

[[ "${1:-}" != "--help" && "${1:-}" != "-h" ]] || { usage; exit 0; }
(( $# >= 1 && $# <= 2 )) || { usage >&2; exit 2; }
REPO_ARG="$1"
LANG="${2:-python}"
case "$LANG" in python|javascript|go) ;; *) usage >&2; exit 2 ;; esac
[[ -d "$REPO_ARG" ]] || { echo "Repositório inexistente: $REPO_ARG" >&2; exit 2; }
REPO="$(realpath "$REPO_ARG")"
[[ "$REPO" != "/" && "$REPO" != "/home" ]] || { echo "Selecione um repositório, não uma raiz global" >&2; exit 2; }
[[ -d "$HOME/MITR3" ]] || { echo "Workspace MITR3 não encontrado" >&2; exit 3; }

CODEQL="$HOME/Tools/codeql/codeql/codeql"
[[ -x "$CODEQL" ]] || CODEQL="$HOME/.local/bin/codeql"
[[ -x "$CODEQL" ]] || { echo "CodeQL não localizado (CLI não será baixada)" >&2; exit 3; }

if [[ "$LANG" == "go" ]]; then
  if [[ "${MITR3_CODEQL_ALLOW_GO_BUILD:-0}" != "1" ]]; then
    echo "CodeQL não oferece --build-mode=none para Go. Autobuild pode executar código do projeto." >&2
    echo "Para um repositório autorizado/confiável: MITR3_CODEQL_ALLOW_GO_BUILD=1 $0 '$REPO' go" >&2
    exit 4
  fi
  BUILD_MODE="autobuild"
else
  BUILD_MODE="none"
fi

# Deterministic repo identity, collision-safe run directories, no database deletion.
NAME="$(printf '%s' "$(basename "$REPO")" | tr -c '[:alnum:]_.-' '_' | cut -c 1-38)"
HASH="$(printf '%s' "$REPO" | sha256sum | cut -c 1-10)"
STAMP="$(date -u +%Y%m%dT%H%M%S%N)"
RUN="$HOME/MITR3/engagements/codeql_${NAME}_${HASH}/runs/${STAMP}_${LANG}"
EVID="$RUN/evidence"
LOGS="$RUN/logs"
DB_PARENT="/tmp/opencode"
DB="$DB_PARENT/codeql-db-${NAME}-${LANG}-${STAMP}"
mkdir -p "$EVID" "$LOGS"
if [[ ! -d "$DB_PARENT" ]]; then mkdir -m 700 "$DB_PARENT"; fi
[[ -w "$DB_PARENT" && ! -e "$DB" ]] || { echo "Diretório temporário sem permissão ou DB já existente" >&2; exit 3; }
chmod 700 "$RUN" "$EVID" "$LOGS"
VERSION="$("$CODEQL" version | head -1)"
SUITE="codeql/${LANG}-queries:codeql-suites/${LANG}-security-extended.qls"
SARIF="$EVID/codeql-${LANG}.sarif"
REPORT="$RUN/codeql-findings.md"

# These commands don't execute the target in Python/JS. Go requires explicit build opt-in.
echo "[MITR3] repo=$REPO language=$LANG build_mode=$BUILD_MODE"
echo "[MITR3] codeql=$VERSION"
echo "[MITR3] database=$DB"
echo "[MITR3] suite=$SUITE"
echo "[MITR3] report=$REPORT"
"$CODEQL" resolve queries "$SUITE" > "$LOGS/suite-resolve.txt" 2>&1 || {
  echo "Suite ausente/incompatível; verifique query pack. $LOGS/suite-resolve.txt" >&2; exit 5;
}

THREADS="${MITR3_CODEQL_THREADS:-2}"
RAM="${MITR3_CODEQL_RAM_MB:-2048}"
echo "[MITR3] database create..."
if ! "$CODEQL" database create "$DB" --language="$LANG" --build-mode="$BUILD_MODE" \
  --source-root="$REPO" --threads="$THREADS" --ram="$RAM" \
  >"$LOGS/database-create.log" 2>&1; then
  echo "Falha na criação do banco: $LOGS/database-create.log" >&2
  exit 6
fi
echo "[MITR3] database analyze..."
if ! "$CODEQL" database analyze "$DB" "$SUITE" --format=sarif-latest \
  --sarif-category="mitr3-${NAME}-${LANG}" --threads="$THREADS" --ram="$RAM" --output="$SARIF" \
  >"$LOGS/database-analyze.log" 2>&1; then
  echo "Falha ao analisar: $LOGS/database-analyze.log" >&2
  exit 7
fi
python3 "$HOME/MITR3/bin/mitr3-codeql-report.py" "$SARIF" "$REPORT" \
  --repo "$REPO" --lang "$LANG" --database "$DB" --version "$VERSION" \
  > "$LOGS/report-summary.json"
(
 cd "$RUN"
 sha256sum evidence/*.sarif codeql-findings.md > evidence/SHA256SUMS
)
echo "[MITR3] OK: $REPORT"
echo "[MITR3] SARIF: $SARIF"
echo "[MITR3] SHA256: $EVID/SHA256SUMS"
cat "$LOGS/report-summary.json"
