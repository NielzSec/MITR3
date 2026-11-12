#!/usr/bin/env python3
# language: python, file: mitr3-opsec-scan.py, target: Linux, stdlib only
# BlackOps (opsec) — varredura PASSIVA de cabeçalhos e exposição de paths de um host próprio.
# Só GET; não ataca, não força, não envia payload. O alvo é sempre declarado em argv:
# nenhuma varredura sem alvo explícito do operador.
"""uso:
  python3 bin/mitr3-opsec-scan.py https://mitr3-web.zgordola1.workers.dev
  python3 bin/mitr3-opsec-scan.py https://mitr3-web... --json
código de saída: 0 = sem achados, 1 = achados, 2 = erro
verifica: headers de segurança ausentes, cookies sem flags, Server expondo versão,
paths sensíveis acessíveis (/.git/HEAD, /.env, /package.json, /server-status, /.git/config).
"""
import hashlib
import json
import re
import socket
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

TIMEOUT = 15
UA = "MITR3-OpsecScan/1.0 (BlackOps; passive; operator-approved)"
PROBE_PATHS = ("/.git/HEAD", "/.env", "/package.json", "/server-status", "/.git/config")
HEADER_CHECKS = {
    "content-security-policy": "high",
    "strict-transport-security": "medium",
    "x-content-type-options": "medium",
    "x-frame-options": "medium",
    "referrer-policy": "low",
    "permissions-policy": "low",
}
SENSITIVE_COOKIES = re.compile(r"(?i)\b(session|auth|token|sid)\w*\b")
VERSION_HINT = re.compile(r"(?i)(server|x-powered-by)\s*:\s*.*\d")

def fetch(url: str, head: bool = False):
    req = urllib.request.Request(url, method="HEAD" if head else "GET",
                                 headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return resp.getcode(), dict(resp.getheaders()), resp.read()
    except urllib.error.HTTPError as err:
        return err.code, dict(err.headers or {}), b""
    except (urllib.error.URLError, socket.timeout, OSError) as err:
        return None, {}, str(err).encode()

def base_url(url: str) -> str:
    return url.rstrip("/")

def scan(target: str):
    findings = []
    code, headers, body = fetch(target)
    if code is None:
        return findings, {"reachable": False, "error": headers.get("content-length", body.decode()[:200])}
    headers_l = {k.lower(): v for k, v in headers.items()}

    for name, sev in HEADER_CHECKS.items():
        if name not in headers_l:
            findings.append({"check": "header", "severity": sev,
                             "detail": f"ausente: {name}"})
    for name in ("server", "x-powered-by"):
        if VERSION_HINT.search(name + ": " + headers_l.get(name, "")):
            findings.append({"check": "banner", "severity": "low",
                             "detail": f"{name} expõe versão: {headers_l[name][:60]}"})
    for c in headers_l.get("set-cookie", "").split(",") if "set-cookie" in headers_l else []:
        if not SENSITIVE_COOKIES.search(c.split("=")[0]):
            continue
        flags = c.lower()
        missing = [f for f in ("secure", "httponly") if f not in flags]
        if missing:
            findings.append({"check": "cookie", "severity": "medium",
                             "detail": f"cookie sensível sem {'/'.join(missing)}: {c.split('=')[0].strip()}"})

    exposed = []
    for path in PROBE_PATHS:
        pcode, _, _ = fetch(base_url(target) + path)
        if pcode == 200:
            exposed.append({"path": path, "code": pcode})
    if exposed:
        findings.append({"check": "path_exposure", "severity": "high", "detail": exposed})
    return findings, {"reachable": True, "status": code}

def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    as_json = "--json" in argv
    argv = [a for a in argv if a != "--json"]
    if len(argv) != 1 or not argv[0].startswith("http"):
        print(__doc__, file=sys.stderr)
        return 2
    findings, meta = scan(argv[0])
    report = {
        "tool": "mitr3-opsec-scan", "target": argv[0],
        "at": datetime.now(timezone.utc).isoformat(),
        "meta": meta, "findings": findings,
        "report_sha256": None,
    }
    blob = json.dumps(report, ensure_ascii=False, sort_keys=True, indent=1).encode()
    digest = hashlib.sha256(blob).hexdigest()
    report["report_sha256"] = digest
    if as_json:
        print(json.dumps(report, ensure_ascii=False, indent=1))
    else:
        print(f"alvo={argv[0]} alcançado={meta['reachable']} achados={len(findings)}")
        for f in findings:
            print(f"[{f['severity']:6}] {f['check']:14} {f['detail']}")
        print(f"relatório sha256: {digest}")
    return 1 if findings else 0

if __name__ == "__main__":
    sys.exit(main())
