#!/usr/bin/env bash
# MITR3 — Burp Suite Professional launcher (loader agent + JDK 21).
#
# License mechanics: -javaagent injects BurpLoaderKeygen v1.18 at runtime and
# retransforms the license check; activation was done once via the keygen GUI
# (2026-10-19). The keygen window is NOT needed for daily launches — this command
# is byte-equivalent to the one the keygen's "Run" button executes.
#
# usage: burp.sh [burp args...]
#   burp.sh --version                      # smoke test, no GUI
#   burp.sh --project-file case.burp       # per-case project
#   burp.sh --config-file scan-config.json # scanner config (e.g. unpause spider/scanner)
set -euo pipefail

BURP_DIR="${BURP_DIR:-$HOME/Tools/burp}"
JAVA="${JAVA:-$BURP_DIR/jdk/bin/java}"
AGENT="$BURP_DIR/BurpLoaderKeygen_v1.18.jar"
JAR="$(ls -1 "$BURP_DIR"/burpsuite_pro_v*.jar 2>/dev/null | sort -V | tail -1)"

[ -x "$JAVA" ] || { echo "burp.sh: missing java at $JAVA" >&2; exit 2; }
[ -f "$AGENT" ] || { echo "burp.sh: missing keygen agent $AGENT" >&2; exit 2; }
[ -n "$JAR" ]   || { echo "burp.sh: no burpsuite_pro_v*.jar in $BURP_DIR" >&2; exit 2; }

exec "$JAVA" \
  --add-opens=java.desktop/javax.swing=ALL-UNNAMED \
  --add-opens=java.base/java.lang=ALL-UNNAMED \
  -javaagent:"$AGENT" -noverify \
  -jar "$JAR" "$@"
