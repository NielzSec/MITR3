#!/usr/bin/env bash
# MITR3 environment health — fast, read-only.
# usage: mitr3-health.sh [--json]
set -uo pipefail

JSON=0
[[ "${1:-}" == "--json" ]] && JSON=1

PATH="$HOME/MITR3/bin:$HOME/.local/bin:$HOME/go/bin:$PATH"
declare -a OK=() BAD=() WARN=()
have() { command -v "$1" >/dev/null 2>&1; }

# --- host ---
mem_avail=$(free -m | awk '/^Mem/{print $NF}')
disk_free=$(df -Pm / | awk 'NR==2{print $4}')
load=$(cut -d' ' -f1 /proc/loadavg)
sudo_ok=N
sudo -n true 2>/dev/null && sudo_ok=Y

# --- core toolchain (name:command) ---
tools=(
  "ghidra:/usr/bin/ghidra" "ghidra-headless:$HOME/Tools/ghidra/support/analyzeHeadless"
  "r2:r2" "rizin:rizin" "gdb:gdb" "jadx:jadx" "apktool:apktool" "java:java"
  "python3:python3" "go:go" "rustc:rustc" "node:node" "docker:docker"
  "nmap:nmap" "masscan:masscan" "sqlmap:sqlmap" "ffuf:ffuf" "nuclei:nuclei"
  "httpx:httpx" "subfinder:subfinder" "katana:katana" "dnsx:dnsx" "gau:gau"
  "amass:amass" "trivy:trivy" "semgrep:semgrep" "osv-scanner:osv-scanner"
  "checksec:checksec" "ropper:ropper" "pwntools:pwn" "frida:frida"
  "impacket:smbclient.py" "netexec:nxc" "chisel:chisel" "mitmproxy:mitmproxy"
  "upx:upx" "afl-fuzz:afl-fuzz" "gh:gh" "msfconsole:msfconsole" "hashcat:hashcat"
  "hydra:hydra" "burpsuite:$HOME/MITR3/bin/burp.sh" "codeql:codeql" "tor:tor" "onionsearch:$HOME/.local/bin/onionsearch" "darkweb:$HOME/MITR3/bin/darkweb.sh"
  "feroxbuster:feroxbuster" "naabu:naabu" "sslscan:sslscan" "testssl:testssl.sh" "wpscan:wpscan"
  "graphql-cop:graphql-cop" "gopherus:gopherus" "ysoserial:ysoserial"
  "radar-syft:$HOME/MITR3/bin/mitr3-radar-syft" "radar-scorecard:$HOME/MITR3/bin/mitr3-radar-scorecard"
  "radar-zizmor:$HOME/MITR3/bin/mitr3-radar-zizmor" "radar-skillspector:$HOME/MITR3/bin/mitr3-radar-skillspector"
  "radar-graphify:$HOME/MITR3/bin/mitr3-radar-graphify" "radar-inspector:$HOME/MITR3/bin/mitr3-radar-inspector"
  "radar-promptfoo:$HOME/MITR3/bin/mitr3-radar-promptfoo"
  "bloodhound-python:bloodhound-python" "kerbrute:kerbrute" "responder:responder"
  "aws:aws" "gcloud:gcloud" "az:az" "prowler:prowler" "scoutsuite:scout"
  "cloudfox:cloudfox" "pacu:pacu" "trufflehog:trufflehog"
)
for entry in "${tools[@]}"; do
  name=${entry%%:*}; cmd=${entry#*:}
  if [[ "$cmd" == /* ]]; then [[ -x "$cmd" ]] && OK+=("$name") || BAD+=("$name")
  else have "$cmd" && OK+=("$name") || BAD+=("$name"); fi
done

# --- services / MCP ---
mb=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 https://nielz-aspire-a315-53.tailb82a64.ts.net/mcp 2>/dev/null)
[[ "$mb" == "200" || "$mb" == "202" ]] && OK+=("megabrain-http") || WARN+=("megabrain-http")
if docker info >/dev/null 2>&1; then OK+=("docker-daemon")
elif sudo -n docker info >/dev/null 2>&1; then OK+=("docker-daemon(sudo)")
else WARN+=("docker-daemon"); fi
have ollama >/dev/null 2>&1 && OK+=("ollama") || true

# --- configured MCP servers ---
mcp_json=$($HOME/MITR3/bin/mitr3-mcp-check.sh --json 2>/dev/null) || mcp_json='null'
if [[ "$mcp_json" != null ]]; then
  mcp_pass=$(jq '[.servers[] | select(.boot == "pass" and (.issues | length) == 0)] | length' <<<"$mcp_json")
  mcp_fail=$(jq '[.servers[] | select(.boot != "pass" or (.issues | length) > 0)] | length' <<<"$mcp_json")
  (( mcp_fail > 0 )) && WARN+=("mcp:${mcp_fail}-problems")
else
  WARN+=("mcp:check-unavailable")
  mcp_pass=0; mcp_fail=0
fi

# --- workspace tooling ---
WS=()
for s in mitr3-scan.sh mitr3-secrets-audit.py mitr3-index.sh; do
  [[ -x "$HOME/MITR3/bin/$s" ]] && WS+=("$s") || BAD+=("ws:$s")
done
timer_state=$(systemctl --user is-active mitr3-health.timer 2>/dev/null || echo inactive)

# --- thresholds ---
(( mem_avail < 2000 )) && WARN+=("low-mem:${mem_avail}MB")
(( disk_free < 20480 )) && WARN+=("low-disk:${disk_free}MB")

arr() { if (( $# == 0 )); then echo '[]'; else printf '%s\n' "$@" | jq -R . | jq -s -c .; fi; }

if (( JSON )); then
  printf '{"ok":%s,"missing":%s,"warn":%s,"workspace":%s,"mcp":%s,"timer":"%s","mem_avail_mb":%d,"disk_free_mb":%d,"load":%s,"sudo_cached":%s}\n' \
    "$(arr "${OK[@]}")" "$(arr "${BAD[@]}")" "$(arr "${WARN[@]}")" "$(arr "${WS[@]}")" \
    "$mcp_json" "$timer_state" "$mem_avail" "$disk_free" "$load" "$([[ $sudo_ok == Y ]] && echo true || echo false)"
  exit 0
fi

printf '\nMITR3 — environment health\n'
printf 'load %-6s mem free %-6sMB disk free %-7sMB\n\n' "$load" "$mem_avail" "$disk_free"
printf '  ok      %2d  %s\n' "${#OK[@]}"  "$(printf '%s ' "${OK[@]}" | fold -s -w 100 | sed '2,$s/^/              /')"
printf '  missing %2d  %s\n' "${#BAD[@]}" "$(printf '%s ' "${BAD[@]}" | fold -s -w 100 | sed '2,$s/^/              /')"
printf '  workspace %2d  %s · timer %s\n' "${#WS[@]}" "$(printf '%s ' "${WS[@]}")" "$timer_state"
printf '  mcp     %2d passed, %2d problems · details: %s\n' "$mcp_pass" "$mcp_fail" "$HOME/MITR3/reports/mcp-check-latest.json"
if ((${#WARN[@]})); then
  printf '  warn    %2d  %s\n' "${#WARN[@]}" "$(printf '%s ' "${WARN[@]}" | fold -s -w 100 | sed '2,$s/^/              /')"
fi
echo
