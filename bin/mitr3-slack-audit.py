#!/usr/bin/env python3
# language: python, file: mitr3-slack-audit.py, target: Linux, stdlib only
# BlackOps (opsec) — auditoria OPSEC de mensagens Slack exportadas (dump Composio/Slack).
# Leitura somente: nenhuma mensagem é enviada, nenhum canal é escrito.
# Detecta segredos/exposição em textos publicados: tokens, chaves, credenciais em URL,
# contatos privados, IPs/hosts internos. Saída mascarada; nunca ecoa o valor completo.
"""uso:
  python3 bin/mitr3-slack-audit.py dump.json            # dump do Composio (results[].response.data.messages) ou {"messages":[]} ou lista
  python3 bin/mitr3-slack-audit.py dump.json --json     # relatório JSON (para o Maestro)
código de saída: 0 = limpo, 1 = achados, 2 = erro de entrada
"""
import base64
import hashlib
import json
import re
import sys

# padrões: (id, regex, gravidade) — valores mascarados na saída
PATTERNS = [
    ("slack_token", r"xox[bpasr]-[A-Za-z0-9-]{10,}", "high"),
    ("aws_key", r"AKIA[0-9A-Z]{16}", "high"),
    ("github_pat", r"gh[pousr]_[A-Za-z0-9]{20,}", "high"),
    ("generic_bearer", r"(?i)bearer\s+[A-Za-z0-9._~+/=-]{20,}", "high"),
    ("openai_key", r"sk-(?:proj-)?[A-Za-z0-9_-]{20,}", "high"),
    ("jwt", r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}", "high"),
    ("private_key", r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", "critical"),
    ("url_creds", r"[a-z][a-z0-9+.-]*://[^\s:/@#]+:[^\s/@#]+@", "high"),
    ("password_field", r"(?i)\b(?:password|senha|secret|token)\s*[:=]\s*[^\s'\"<>]{6,}", "medium"),
    ("internal_ip", r"\b(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)\d+\.\d+\b", "low"),
    ("email", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "low"),
    ("thm_flag", r"THM\{[^}]{4,90}\}", "medium"),
]
MASK = re.compile(r"[A-Za-z0-9_-]")

def mask(value: str) -> str:
    if len(value) <= 8:
        return "***"
    head, tail = value[:3], value[-2:]
    return head + "*" * (len(value) - 5) + tail

def load_messages(path: str):
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    if isinstance(doc, dict) and "results" in doc:
        msgs = []
        for result in doc["results"]:  # shape do COMPOSIO_MULTI_EXECUTE_TOOL
            data = result.get("response", {}).get("data", {})
            msgs.extend(data.get("messages", []))
        return msgs
    if isinstance(doc, list) and doc and isinstance(doc[0], dict) and "response" in doc[0]:
        msgs = []
        for result in doc:  # shape do COMPOSIO_MULTI_EXECUTE_TOOL
            data = result.get("response", {}).get("data", {})
            msgs.extend(data.get("messages", []))
        return msgs
    if isinstance(doc, dict):
        return doc.get("messages", [])
    return doc if isinstance(doc, list) else []

def audit(messages):
    findings = []
    for m in messages:
        text = m.get("text") or ""
        ts, user = m.get("ts", "?"), m.get("user") or m.get("bot_id") or "?"
        for pid, pattern, sev in PATTERNS:
            for match in re.finditer(pattern, text):
                raw = match.group(0)
                findings.append({
                    "id": pid, "severity": sev, "ts": ts, "user": user,
                    "sample": mask(raw),
                    "sha256": hashlib.sha256(raw.encode()).hexdigest()[:16],
                })
    return findings

def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    as_json = "--json" in argv
    argv = [a for a in argv if a != "--json"]
    if len(argv) != 1:
        print(__doc__, file=sys.stderr)
        return 2
    try:
        messages = load_messages(argv[0])
    except (OSError, ValueError) as err:
        print(f"entrada inválida: {err}", file=sys.stderr)
        return 2
    findings = audit(messages)
    if as_json:
        print(json.dumps({"messages_scanned": len(messages), "findings": findings},
                         ensure_ascii=False, indent=1))
    else:
        print(f"{len(messages)} mensagens, {len(findings)} achados")
        for f in findings:
            print(f"[{f['severity']:8}] {f['id']:14} ts={f['ts']} user={f['user']} sample={f['sample']}")
    return 1 if findings else 0

if __name__ == "__main__":
    sys.exit(main())
