#!/usr/bin/env bash
# MITR3 recon wrapper: one policy-gated request per source for a single selector.
# Each call keeps the connector's own --allow-send, purpose and 0600 report.
# Usage: mitr3-recon.sh <domain|ip> <value> <purpose> [source ...]
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
CONNECTOR="$ROOT/bin/mitr3-osint.py"

if [ $# -lt 3 ]; then
    echo "usage: mitr3-recon.sh <domain|ip> <value> <purpose> [source ...]" >&2
    exit 2
fi
kind=$1 value=$2 purpose=$3
shift 3

case "$kind" in
    domain) default_sources="crt.sh rdap.org urlscan.io virustotal censys-platform otx fofa zoomeye leakix bevigil whoisxmlapi" ;;
    ip)     default_sources="ipinfo abuseipdb virustotal censys-platform otx fofa zoomeye leakix urlscan.io" ;;
    *)      echo "unknown selector type: $kind" >&2; exit 2 ;;
esac
sources=${*:-$default_sources}

for id in $sources; do
    out=$("$CONNECTOR" query "$id" --type "$kind" --value "$value" --purpose "$purpose" --allow-send 2>&1)
    printf '%-16s %s\n' "$id" "$(printf '%s' "$out" | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
    code = d.get("error_code") or "ok"
    print("status=%s %s %s" % (d.get("status"), code, d.get("report", "")))
except Exception:
    print("unparsed output")
')"
done
