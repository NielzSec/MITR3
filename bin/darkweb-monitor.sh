#!/usr/bin/env bash
# MITR3 / Robin — monitor diário passivo das 3 fontes (rotina 09:30)
# uso: ~/MITR3/bin/darkweb-monitor.sh   (3 GETs, ≤50 s cada, sem login/paralelismo)
set -uo pipefail
export LC_ALL=C
Q=/tmp/opencode/darkquarantine
LOGDIR="$HOME/MITR3/docs/monitor"
mkdir -p "$LOGDIR" "$Q"
LOG="$LOGDIR/$(date -u +%Y-%m-%d).log"
MAN="$LOGDIR/MANIFEST.sha256"
UA="Mozilla/5.0 (Windows NT 10.0; rv:115.0) Gecko/20100101 Firefox/115.0"
TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)

targets=(
  "wgruul|http://wgruul6cmayc2k2i7gx4nucia2fxgm3kqq4wsapt3pnaqz2x7azcx3yd.onion/"
  "archive-db|http://e3y5vky4v7snefqyhbn6kcmyl5fo4cnk3a2irh2ttvwua46ww5ubl6qd.onion/"
  "dread-current|http://dreadytu5e57d2xyx2fdgpvqnaf7zxhwr65k5vozpfbotulgv46lc7id.onion/"
)

[ -f "$LOG" ] || printf 'timestamp\tname\thttp\trc\ttime_s\tsize\ttitle\tsha256\n' >> "$LOG"
printf '# monitor run %s\n' "$TS"
for spec in "${targets[@]}"; do
  name="${spec%%|*}"; url="${spec#*|}"
  f="$Q/mon-${name}-$(date -u +%Y%m%dT%H%M%SZ).html"
  meta=$(curl -sS --socks5-hostname 127.0.0.1:9050 --max-time 50 --connect-timeout 35 \
        -L -A "$UA" -o "$f" -w '%{http_code}|%{time_total}' "$url" 2>/dev/null); rc=$?
  code="${meta%%|*}"; dt="${meta#*|}"
  sz=0; sha="-"; title="-"
  if [ -f "$f" ]; then
    sz=$(wc -c < "$f"); sha=$(sha256sum "$f" | cut -d' ' -f1); echo "$sha  $f" >> "$MAN"
    title=$(python3 - "$f" <<'EOF'
import re,sys,html
try: raw=open(sys.argv[1],encoding='utf-8',errors='replace').read()
except: print('-'); raise SystemExit
m=re.search(r'<title[^>]*>(.*?)</title>',raw,re.S|re.I)
print(html.unescape(re.sub(r'\s+',' ',m.group(1))).strip()[:90].replace('\t',' ') if m else '-')
EOF
)
  fi
  [ "$code" = "000" ] && code="TIMEOUT"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$TS" "$name" "$code" "$rc" "${dt:-0}" "$sz" "$title" "$sha" >> "$LOG"
  printf '%-14s %-8s %7.1fs %9s B  %s\n' "$name" "$code" "${dt:-0}" "$sz" "$title"
  sleep 2
done
echo "log: $LOG"
