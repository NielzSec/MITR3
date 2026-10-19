#!/usr/bin/env bash
# Rebuild ~/MITR3/engagements/INDEX.md from case.md frontmatter.
set -euo pipefail
ROOT="$HOME/MITR3/engagements"
OUT="$ROOT/INDEX.md"
{
  echo "# Engagements"
  echo
  echo "Gerado por \`bin/mitr3-index.sh\` em $(date -Is)."
  echo
  echo "| case | tipo | estado | abertura |"
  echo "|---|---|---|---|"
  for d in "$ROOT"/*/; do
    f="$d/case.md"
    [ -f "$f" ] || continue
    id=$(sed -n 's/^- id: //p' "$f" | head -1)
    type=$(sed -n 's/^- type: //p' "$f" | head -1)
    state=$(sed -n 's/^- state: //p' "$f" | head -1)
    opened=$(sed -n 's/^- opened: //p' "$f" | head -1)
    printf '| [%s](%s/) | %s | %s | %s |\n' "${id:-$(basename "$d")}" "$(basename "$d")" "${type:--}" "${state:--}" "${opened:--}"
  done
} > "$OUT"
echo "$OUT"
