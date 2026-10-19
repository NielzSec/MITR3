#!/usr/bin/env python3
"""Turn CodeQL SARIF into a brief, credential-safe MITR3 report."""
import argparse
import collections
import json
from pathlib import Path
from urllib.parse import unquote, urlparse


def clean(value: object) -> str:
    return str(value or "").replace("|", r"\|").replace("`", "'").replace("\n", " ").replace("\r", " ")[:180]


def severity(result: dict, rules: dict) -> str:
    props = rules.get(result.get("ruleId"), {}).get("properties", {})
    try:
        score = float(props.get("security-severity"))
    except (TypeError, ValueError):
        score = -1
    if score >= 9:
        return "CRITICAL"
    if score >= 7:
        return "HIGH"
    if score >= 4:
        return "MEDIUM"
    if score >= 0:
        return "LOW"
    return {"error": "HIGH", "warning": "MEDIUM", "note": "LOW", "none": "INFO"}.get(
        result.get("level", "warning"), "MEDIUM"
    )


def location(result: dict) -> str:
    places = result.get("locations") or []
    if not places:
        return "sem localização"
    p = places[0].get("physicalLocation") or {}
    uri = (p.get("artifactLocation") or {}).get("uri", "?")
    if uri.startswith("file://"):
        uri = urlparse(uri).path
    line = (p.get("region") or {}).get("startLine", "?")
    return f"{unquote(uri)}:{line}"


def write_report(sarif: Path, output: Path, repository: str, language: str, db: str, cli_version: str):
    data = json.loads(sarif.read_text(encoding="utf-8"))
    findings = []
    counts = collections.Counter()
    for run in data.get("runs") or []:
        rule_map = {r.get("id"): r for r in (run.get("tool", {}).get("driver", {}).get("rules") or [])}
        for result in run.get("results") or []:
            sev = severity(result, rule_map)
            counts[sev] += 1
            rid = str(result.get("ruleId") or "?")
            title = (rule_map.get(rid, {}).get("shortDescription") or {}).get("text") or rid
            findings.append((sev, rid, location(result), title))
    findings.sort(key=lambda x: ({"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}[x[0]], x[1], x[2]))
    lines = [
        "# CodeQL — MITR3 findings",
        "",
        f"- Repositório: `{clean(repository)}`",
        f"- Linguagem: `{clean(language)}`",
        f"- CodeQL CLI: `{clean(cli_version)}`",
        f"- Banco local temporário: `{clean(db)}`",
        "- Suite: `security-extended`",
        f"- Resultados totais: **{len(findings)}**",
        "",
        "## Contagem por severidade",
        "",
        "| Severidade | Resultados |",
        "|---|---:|",
    ]
    for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        lines.append(f"| {level} | {counts[level]} |")
    lines.extend(["", "A severidade considera `security-severity` quando disponível; caso contrário usa o nível SARIF.", "", "## Principais achados", "",
                  "| Severidade | Query ID | Arquivo:linha | Regra |", "|---|---|---|---|"])
    for sev, rid, path, title in findings[:25]:
        lines.append(f"| {sev} | `{clean(rid)}` | `{clean(path)}` | {clean(title)} |")
    if not findings:
        lines.append("| — | — | — | Nenhum finding retornado pela suite. |")
    lines.extend(["", "Resultados de análise estática requerem triagem humana. 0 findings não garante ausência de vulnerabilidades.",
                  "Evite publicar SARIF bruto em bases de conhecimento compartilhadas sem saneamento.", ""])
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(lines), encoding="utf-8")
    output.chmod(0o600)
    print(json.dumps({"total": len(findings), "by_severity": dict(counts), "report": str(output)}))


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("sarif", type=Path)
    p.add_argument("output", type=Path)
    p.add_argument("--repo", required=True)
    p.add_argument("--lang", required=True)
    p.add_argument("--database", required=True)
    p.add_argument("--version", required=True)
    a = p.parse_args()
    write_report(a.sarif, a.output, a.repo, a.lang, a.database, a.version)


if __name__ == "__main__":
    main()
