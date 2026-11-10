#!/usr/bin/env bash
# MITR3 — Tor fetch/search helper (SOCKS 127.0.0.1:9050; tor systemd service).
#
# usage:
#   darkweb.sh fetch  <url> [curl flags...]   # GET via Tor
#   darkweb.sh head   <url> [curl flags...]   # headers only (reachability check)
#   darkweb.sh search <query> [onionsearch flags...]
#   darkweb.sh status                         # recent tor service log
set -euo pipefail

SOCKS="${MITR3_TOR_SOCKS:-127.0.0.1:9050}"
cmd="${1:-}"
shift || true

case "$cmd" in
  fetch)  exec curl -sS --socks5-hostname "$SOCKS" --max-time 120 "$@" ;;
  head)   exec curl -sSI --socks5-hostname "$SOCKS" --max-time 120 "$@" ;;
  search) exec onionsearch --proxy "$SOCKS" "$@" ;;
  status) exec journalctl -u tor --since "5 min ago" --no-pager | tail -3 ;;
  *) echo "uso: darkweb.sh fetch|head <url> | search <query> | status" >&2; exit 2 ;;
esac
