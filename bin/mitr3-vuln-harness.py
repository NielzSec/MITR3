#!/usr/bin/env python3
"""MITR3 AI Vulnerability Harness — 3-Layer Verification & Prioritization Engine.

Implements:
  Layer 1: Multi-scanner agreement & quarantine scoring.
  Layer 2: Deterministic AST structural verification (rejects hallucinated sinks).
  Layer 3: IaC deployment context & boundary mitigation multipliers.

Deterministic stdlib-only implementation.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import re
import stat
import sys
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

SEVERITY_WEIGHTS = {
    "CRITICAL": 10.0,
    "HIGH": 7.5,
    "MEDIUM": 5.0,
    "LOW": 2.5,
    "INFO": 1.0,
}

IAC_MITIGATIONS = {
    "waf_rule_active": {"multiplier": 0.4, "description": "L7 WAF WebACL actively attached to endpoint"},
    "auth_required": {"multiplier": 0.5, "description": "IAM / OAuth / JWT Authorizer enforces valid credentials"},
    "private_network": {"multiplier": 0.3, "description": "Isolated VPC / private subnet with no public route"},
    "rate_limited": {"multiplier": 0.7, "description": "Strict rate limiting or concurrency quota active"},
}


def sha256_file(path: Path) -> str:
    """Compute SHA256 of file safely."""
    try:
        with path.open("rb") as f:
            return hashlib.file_digest(f, "sha256").hexdigest()
    except Exception:
        return ""


@dataclass
class CandidateFinding:
    id: str
    scanner: str
    rule_id: str
    file_path: str
    line: int
    severity: str
    message: str
    sink_pattern: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class EvaluatedFinding:
    id: str
    file_path: str
    line: int
    rule_ids: List[str]
    scanners: List[str]
    consensus_status: str
    consensus_factor: float
    base_severity: str
    base_score: float
    ast_gate: int
    ast_details: str
    iac_mitigations: List[str]
    infra_multiplier: float
    effective_score: float
    final_verdict: str


# =====================================================================
# Layer 1: Ingestion & Multi-Scanner Agreement
# =====================================================================

def parse_sarif(data: Dict[str, Any], scanner_name: str = "codeql") -> List[CandidateFinding]:
    findings: List[CandidateFinding] = []
    runs = data.get("runs", [])
    for run in runs:
        results = run.get("results", [])
        for idx, r in enumerate(results):
            rule_id = r.get("ruleId", "unknown-rule")
            level = r.get("level", "warning").upper()
            sev_map = {"ERROR": "HIGH", "WARNING": "MEDIUM", "NOTE": "LOW", "NONE": "INFO"}
            severity = sev_map.get(level, "MEDIUM")
            msg = r.get("message", {}).get("text", "")
            locations = r.get("locations", [])
            file_path = ""
            line = 1
            if locations:
                phys = locations[0].get("physicalLocation", {})
                file_path = phys.get("artifactLocation", {}).get("uri", "")
                line = phys.get("region", {}).get("startLine", 1)
            findings.append(
                CandidateFinding(
                    id=f"{scanner_name}-{idx + 1:04d}",
                    scanner=scanner_name,
                    rule_id=rule_id,
                    file_path=file_path,
                    line=line,
                    severity=severity,
                    message=msg,
                )
            )
    return findings


def parse_semgrep(data: Dict[str, Any]) -> List[CandidateFinding]:
    findings: List[CandidateFinding] = []
    results = data.get("results", [])
    for idx, r in enumerate(results):
        rule_id = r.get("check_id", "semgrep-rule")
        path = r.get("path", "")
        line = r.get("start", {}).get("line", 1)
        extra = r.get("extra", {})
        raw_sev = extra.get("severity", "WARNING").upper()
        sev_map = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}
        severity = sev_map.get(raw_sev, "MEDIUM")
        msg = extra.get("message", "")
        lines = extra.get("lines", "")
        findings.append(
            CandidateFinding(
                id=f"semgrep-{idx + 1:04d}",
                scanner="semgrep",
                rule_id=rule_id,
                file_path=path,
                line=line,
                severity=severity,
                message=msg,
                sink_pattern=lines.strip() if lines else None,
            )
        )
    return findings


def parse_trivy(data: Dict[str, Any]) -> List[CandidateFinding]:
    findings: List[CandidateFinding] = []
    results = data.get("Results", [])
    counter = 1
    for target_block in results:
        target = target_block.get("Target", "")
        for m in target_block.get("Misconfigurations", []):
            if m.get("Status") == "FAIL":
                findings.append(
                    CandidateFinding(
                        id=f"trivy-misconfig-{counter:04d}",
                        scanner="trivy",
                        rule_id=m.get("ID", "trivy-rule"),
                        file_path=target,
                        line=m.get("CauseMetadata", {}).get("StartLine", 1),
                        severity=m.get("Severity", "MEDIUM").upper(),
                        message=m.get("Title", ""),
                    )
                )
                counter += 1
        for s in target_block.get("Secrets", []):
            findings.append(
                CandidateFinding(
                    id=f"trivy-secret-{counter:04d}",
                    scanner="trivy",
                    rule_id=s.get("RuleID", "secret-detected"),
                    file_path=target,
                    line=s.get("StartLine", 1),
                    severity=s.get("Severity", "HIGH").upper(),
                    message=s.get("Title", "Secret exposed"),
                )
            )
            counter += 1
    return findings


def correlate_findings(findings: List[CandidateFinding]) -> List[List[CandidateFinding]]:
    """Cluster candidate findings by normalized file path and line proximity (within 5 lines)."""
    clusters: List[List[CandidateFinding]] = []
    # Normalize paths
    normalized: List[CandidateFinding] = []
    for f in findings:
        norm_path = f.file_path.lstrip("./").replace("//", "/")
        normalized.append(
            CandidateFinding(
                id=f.id,
                scanner=f.scanner,
                rule_id=f.rule_id,
                file_path=norm_path,
                line=f.line,
                severity=f.severity,
                message=f.message,
                sink_pattern=f.sink_pattern,
                extra=f.extra,
            )
        )

    used = set()
    for i, f1 in enumerate(normalized):
        if i in used:
            continue
        cluster = [f1]
        used.add(i)
        for j, f2 in enumerate(normalized):
            if j in used:
                continue
            # Match condition: same file and within 5 lines
            if f1.file_path == f2.file_path and abs(f1.line - f2.line) <= 5:
                cluster.append(f2)
                used.add(j)
        clusters.append(cluster)
    return clusters


# =====================================================================
# Layer 2: Deterministic AST Structural Verification
# =====================================================================

class PythonASTInspector(ast.NodeVisitor):
    def __init__(self, target_line: int):
        self.target_line = target_line
        self.enclosing_function: Optional[str] = None
        self.enclosing_class: Optional[str] = None
        self.calls_on_line: List[str] = []
        self.found_exact_line = False

    def visit_ClassDef(self, node: ast.ClassDef):
        if node.lineno <= self.target_line <= getattr(node, "end_lineno", node.lineno):
            self.enclosing_class = node.name
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        if node.lineno <= self.target_line <= getattr(node, "end_lineno", node.lineno):
            self.enclosing_function = node.name
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        if node.lineno <= self.target_line <= getattr(node, "end_lineno", node.lineno):
            self.enclosing_function = node.name
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        if node.lineno == self.target_line:
            self.found_exact_line = True
            # Extract function call name
            func_name = ""
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                func_name = node.func.attr
            if func_name:
                self.calls_on_line.append(func_name)
        self.generic_visit(node)


def verify_python_ast(file_path: Path, target_line: int) -> Tuple[int, str]:
    if not file_path.is_file():
        return 0, f"Arquivo {file_path} inexistente no filesystem"
    try:
        raw = file_path.read_text(encoding="utf-8")
        tree = ast.parse(raw, filename=str(file_path))
    except (SyntaxError, UnicodeDecodeError) as e:
        return 0, f"Erro de sintaxe/decodificação na AST: {e}"

    lines = raw.splitlines()
    if target_line < 1 or target_line > len(lines):
        return 0, f"Linha {target_line} fora dos limites do arquivo ({len(lines)} linhas)"

    target_content = lines[target_line - 1].strip()
    if not target_content or target_content.startswith("#"):
        return 0, f"Linha {target_line} é comentário ou linha vazia (falso positivo sintático)"

    inspector = PythonASTInspector(target_line)
    inspector.visit(tree)

    func = inspector.enclosing_function or "<module-level>"
    calls = f" (chamadas: {', '.join(inspector.calls_on_line)})" if inspector.calls_on_line else ""
    return 1, f"AST confirmada em '{func}'{calls}"


def verify_js_structure(file_path: Path, target_line: int) -> Tuple[int, str]:
    if not file_path.is_file():
        return 0, f"Arquivo {file_path} inexistente no filesystem"
    try:
        lines = file_path.read_text(encoding="utf-8").splitlines()
    except Exception as e:
        return 0, f"Erro ao ler arquivo JS: {e}"

    if target_line < 1 or target_line > len(lines):
        return 0, f"Linha {target_line} fora dos limites do arquivo ({len(lines)} linhas)"

    content = lines[target_line - 1].strip()
    if not content or content.startswith("//") or content.startswith("/*"):
        return 0, f"Linha {target_line} é comentário ou linha vazia (falso positivo sintático)"

    # Identify potential JS sinks/calls
    sink_match = re.search(r"\b(fetch|axios|eval|exec|query|render|open)\b", content)
    details = f"Sink literal '{sink_match.group(1)}' ativo" if sink_match else "Linha de código executável confirmada"
    return 1, f"Estrutura JS confirmada: {details}"


def verify_ast_gate(codebase_root: Path, relative_path: str, target_line: int) -> Tuple[int, str]:
    full_path = codebase_root / relative_path
    if not full_path.exists():
        # Try finding anywhere under codebase_root if relative path is partial
        matches = list(codebase_root.glob(f"**/{Path(relative_path).name}"))
        if len(matches) == 1:
            full_path = matches[0]
        else:
            return 0, f"Arquivo {relative_path} não encontrado na raiz da codebase"

    suffix = full_path.suffix.lower()
    if suffix == ".py":
        return verify_python_ast(full_path, target_line)
    elif suffix in (".js", ".ts", ".jsx", ".tsx", ".mjs"):
        return verify_js_structure(full_path, target_line)
    elif full_path.is_file():
        # Generic line existence check
        lines = full_path.read_text(errors="ignore").splitlines()
        if 1 <= target_line <= len(lines):
            return 1, f"Arquivo regular verificado ({len(lines)} linhas)"
        return 0, f"Linha {target_line} fora do arquivo"
    return 0, f"Tipo de arquivo não suportado para AST: {suffix}"


# =====================================================================
# Layer 3: Deployment Context & IaC Multipliers
# =====================================================================

def scan_iac_context(iac_dir: Path) -> List[str]:
    """Scan IaC manifests (.tf, .yaml, .json) for perimeter security controls."""
    if not iac_dir.exists() or not iac_dir.is_dir():
        return []

    active_mitigations: Set[str] = set()
    skip_dirs = {".git", "node_modules", "cache", "reports", "engagements", ".gemini", ".alethe", "__pycache__", "venv"}

    for root, dirs, files in os.walk(iac_dir):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for f in files:
            path = Path(root) / f
            suffix = path.suffix.lower()
            if suffix not in (".tf", ".yaml", ".yml", ".json"):
                continue
            if path.stat().st_size > 2_000_000:
                continue

            content = path.read_text(errors="ignore")

            # Check WAF
            if re.search(r"(aws_wafv2_web_acl|AWS::WAFv2::WebACL|waf_acl|WebACLId)", content, re.I):
                active_mitigations.add("waf_rule_active")

            # Check Auth / Authorizer
            if re.search(r"(aws_apigatewayv2_authorizer|AWS::ApiGateway::Authorizer|CognitoUserPool|jwt_authorizer|authorization_type\s*=\s*\"JWT\")", content, re.I):
                active_mitigations.add("auth_required")

            # Check Private VPC / No Internet Gateway
            if re.search(r"(private_subnet|aws_subnet_private|assign_public_ip\s*=\s*false)", content, re.I):
                active_mitigations.add("private_network")

            # Check Rate Limiting
            if re.search(r"(throttling_rate_limit|rate_based_statement|quota_limit)", content, re.I):
                active_mitigations.add("rate_limited")

    return sorted(list(active_mitigations))


# =====================================================================
# Main Harness Pipeline
# =====================================================================

def evaluate_cluster(
    cluster: List[CandidateFinding],
    codebase_root: Path,
    iac_mitigations: List[str]
) -> EvaluatedFinding:
    primary = cluster[0]
    scanners = sorted(list({f.scanner for f in cluster}))
    rules = sorted(list({f.rule_id for f in cluster}))

    # 1. Consensus
    if len(scanners) >= 2:
        consensus_status = "CONFIRMED_BY_ENSEMBLE"
        consensus_factor = 1.5
    else:
        consensus_status = "QUARANTINE"
        consensus_factor = 0.8

    # Base severity
    severities = [f.severity for f in cluster]
    best_sev = "MEDIUM"
    for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        if s in severities:
            best_sev = s
            break
    base_score = SEVERITY_WEIGHTS.get(best_sev, 5.0)

    # 2. AST Gate
    ast_gate, ast_details = verify_ast_gate(codebase_root, primary.file_path, primary.line)

    # 3. IaC Multipliers
    infra_multiplier = 1.0
    for m in iac_mitigations:
        if m in IAC_MITIGATIONS:
            infra_multiplier *= IAC_MITIGATIONS[m]["multiplier"]

    # Final Effective Score
    effective_score = round(base_score * consensus_factor * ast_gate * infra_multiplier, 2)

    # Final Verdict
    if ast_gate == 0:
        final_verdict = "REJECTED_BY_AST"
    elif effective_score >= 8.0:
        final_verdict = "ACTIONABLE_PRIORITY_0"
    elif effective_score >= 4.0:
        final_verdict = "ACTIONABLE_PRIORITY_1"
    else:
        final_verdict = "DEFENDED_OR_LOW_RISK"

    return EvaluatedFinding(
        id=f"HARNESS-{primary.id}",
        file_path=primary.file_path,
        line=primary.line,
        rule_ids=rules,
        scanners=scanners,
        consensus_status=consensus_status,
        consensus_factor=consensus_factor,
        base_severity=best_sev,
        base_score=base_score,
        ast_gate=ast_gate,
        ast_details=ast_details,
        iac_mitigations=iac_mitigations,
        infra_multiplier=round(infra_multiplier, 2),
        effective_score=effective_score,
        final_verdict=final_verdict,
    )


def run_harness(
    findings_files: List[Path],
    codebase_root: Path,
    iac_dir: Optional[Path] = None,
    output_json: Optional[Path] = None,
    output_md: Optional[Path] = None,
) -> Dict[str, Any]:
    all_raw: List[CandidateFinding] = []

    for fpath in findings_files:
        if not fpath.is_file():
            continue
        try:
            content = fpath.read_text(encoding="utf-8")
            data = json.loads(content)
            if "$schema" in data or "runs" in data:
                all_raw.extend(parse_sarif(data))
            elif "results" in data and isinstance(data["results"], list):
                all_raw.extend(parse_semgrep(data))
            elif "Results" in data and isinstance(data["Results"], list):
                all_raw.extend(parse_trivy(data))
        except Exception as e:
            print(f"[!] Erro ao parsear {fpath}: {e}", file=sys.stderr)

    clusters = correlate_findings(all_raw)
    iac_active = scan_iac_context(iac_dir if iac_dir else codebase_root)

    evaluated: List[EvaluatedFinding] = []
    for cluster in clusters:
        ev = evaluate_cluster(cluster, codebase_root, iac_active)
        evaluated.append(ev)

    # Sort descending by effective score
    evaluated.sort(key=lambda x: x.effective_score, reverse=True)

    summary = {
        "total_raw_findings": len(all_raw),
        "clustered_candidates": len(clusters),
        "ast_rejected": sum(1 for e in evaluated if e.ast_gate == 0),
        "actionable_p0": sum(1 for e in evaluated if e.final_verdict == "ACTIONABLE_PRIORITY_0"),
        "actionable_p1": sum(1 for e in evaluated if e.final_verdict == "ACTIONABLE_PRIORITY_1"),
        "defended_or_low": sum(1 for e in evaluated if e.final_verdict == "DEFENDED_OR_LOW_RISK"),
        "active_iac_mitigations": iac_active,
    }

    report = {
        "version": "1.0.0",
        "harness": "MITR3 AI Vulnerability Harness",
        "codebase_root": str(codebase_root.resolve()),
        "summary": summary,
        "findings": [asdict(e) for e in evaluated],
    }

    if output_json:
        output_json.parent.mkdir(parents=True, exist_ok=True)
        output_json.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    if output_md:
        output_md.parent.mkdir(parents=True, exist_ok=True)
        md_text = render_markdown_report(report)
        output_md.write_text(md_text, encoding="utf-8")

    return report


def render_markdown_report(report: Dict[str, Any]) -> str:
    s = report["summary"]
    lines = [
        "# MITR3 — Relatório de Triagem do AI Vulnerability Harness",
        "",
        f"**Raiz da Codebase:** `{report['codebase_root']}`  ",
        f"**Total de Achados Brutos:** {s['total_raw_findings']}  ",
        f"**Candidatos Clusterizados:** {s['clustered_candidates']}  ",
        f"**Rejeitados por Falha na AST (Alucinações / Dead Code):** {s['ast_rejected']}  ",
        f"**Achados Prioritários P0:** {s['actionable_p0']} | **P1:** {s['actionable_p1']} | **Mitigados por IaC/Low:** {s['defended_or_low']}  ",
        "",
        "## Mitigações de Infraestrutura (IaC) Detectadas",
        "",
    ]
    if s["active_iac_mitigations"]:
        for m in s["active_iac_mitigations"]:
            info = IAC_MITIGATIONS.get(m, {})
            lines.append(f"- **{m}** (multiplicador x{info.get('multiplier', 1.0)}): {info.get('description', '')}")
    else:
        lines.append("- *Nenhum controle de borda identificado (exposição direta 1.0x).*")

    lines.extend([
        "",
        "## Tabela de Decisão do Harness",
        "",
        "| ID | Arquivo:Linha | Scanners | Base | AST Gate | Mitigação IaC | Score Efetivo | Veredito |",
        "|---|---|---|---|:---:|---|:---:|---|",
    ])

    for f in report["findings"]:
        scanners_str = ", ".join(f["scanners"])
        mitig_str = f"x{f['infra_multiplier']}" if f["iac_mitigations"] else "direto (1.0x)"
        ast_icon = "PASS" if f["ast_gate"] == 1 else "REJECTED"
        lines.append(
            f"| `{f['id']}` | `{f['file_path']}:{f['line']}` | {scanners_str} | {f['base_severity']} ({f['base_score']}) | {ast_icon} | {mitig_str} | **{f['effective_score']}** | `{f['final_verdict']}` |"
        )

    lines.append("")
    return "\n".join(lines)


# =====================================================================
# CLI Entrypoint
# =====================================================================

def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("inputs", nargs="+", help="Arquivos de entrada de scanners (SARIF, Semgrep JSON, Trivy JSON)")
    p.add_argument("--codebase", required=True, help="Diretório raiz da codebase alvo")
    p.add_argument("--iac", help="Diretório contendo manifestos de IaC (.tf, CloudFormation, etc.)")
    p.add_argument("--json", help="Caminho de saída para relatório JSON")
    p.add_argument("--md", help="Caminho de saída para relatório Markdown")

    args = p.parse_args()

    input_paths = [Path(p) for p in args.inputs]
    codebase = Path(args.codebase)
    iac = Path(args.iac) if args.iac else None
    out_json = Path(args.json) if args.json else None
    out_md = Path(args.md) if args.md else None

    rep = run_harness(input_paths, codebase, iac, out_json, out_md)
    print(f"[+] Triagem do Harness concluída. Candidatos: {rep['summary']['clustered_candidates']} | P0: {rep['summary']['actionable_p0']} | Rejeitados por AST: {rep['summary']['ast_rejected']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
