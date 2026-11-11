#!/usr/bin/env python3
"""MITR3 CTF Evidence & State Graph Manager (Guardiã MEI).

Deterministic manager for recording evidence, computing artifact SHA256 hashes,
validating referential integrity, and advancing state transitions throughout
CTF operations.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional, Tuple

DIR = Path(__file__).resolve().parent
GRAPH_PATH = DIR / "state_graph.json"
LEDGER_PATH = DIR / "ledger.json"

CANONICAL_STAGES = [
    "PREPARATION",
    "INITIAL_ACCESS_SSH",
    "VERSION_CVE_RECON",
    "SURFACE_IDENTIFICATION",
    "USER_FLAG",
    "PRIVILEGE_ESCALATION",
    "ROOT_FLAG",
]

STAGE_DIRS = {
    "INITIAL_ACCESS_SSH": "01-initial-access",
    "VERSION_CVE_RECON": "02-recon",
    "SURFACE_IDENTIFICATION": "03-surface",
    "USER_FLAG": "04-user-flag",
    "PRIVILEGE_ESCALATION": "05-priv-esc",
    "ROOT_FLAG": "06-root-flag",
}


def now_utc() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def compute_sha256(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def save_json(path: Path, data: Dict[str, Any]) -> None:
    temp_path = path.with_suffix(".tmp")
    with temp_path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")
    temp_path.replace(path)


def cmd_status() -> None:
    graph = load_json(GRAPH_PATH)
    ledger = load_json(LEDGER_PATH)

    print("==================================================================")
    print(" MITR3 — Grafo de Estados e Registro de Evidências CTF")
    print("==================================================================")
    target = graph.get("lab_target", {})
    print(f" Interface VPN:   {target.get('network_interface')} ({target.get('local_vpn_ip')})")
    print(f" Máquina Alvo:    {target.get('machine_ip')}")
    print(f" Credenciais:     {target.get('initial_credentials', {}).get('username')} / {target.get('initial_credentials', {}).get('password')}")
    print(f" Estado Atual:    [{graph.get('current_state')}]")
    print("------------------------------------------------------------------")
    print(" Progresso dos Estados:")
    for name, st in graph.get("states", {}).items():
        symbol = "✓" if st.get("status") == "COMPLETED" else ("⏳" if st.get("status") == "IN_PROGRESS" else "○")
        print(f"   [{symbol}] {st.get('order', 0)}. {name:<24} | Status: {st.get('status'):<11} | Evidências: {len(st.get('required_evidence', []))}")

    print("------------------------------------------------------------------")
    print(f" Total de Evidências no Ledger: {len(ledger.get('evidences', []))}")
    for ev in ledger.get("evidences", []):
        print(f"   - {ev.get('evidence_id')}: [{ev.get('stage')}] {ev.get('claim')[:60]}... (SHA256: {ev.get('evidence_sha256')[:12]}...)")
    print("==================================================================")


def cmd_set_target(ip: str) -> None:
    graph = load_json(GRAPH_PATH)
    ledger = load_json(LEDGER_PATH)

    graph["lab_target"]["machine_ip"] = ip
    graph["lab_target"]["status"] = "TARGET_ACQUIRED"
    save_json(GRAPH_PATH, graph)

    ledger["target"]["machine_ip"] = ip
    save_json(LEDGER_PATH, ledger)

    print(f"[+] Alvo atualizado para MACHINE_IP: {ip}")


def cmd_add_evidence(
    stage: str,
    tool: str,
    claim: str,
    raw_text: Optional[str] = None,
    raw_file: Optional[Path] = None,
    confidence: str = "HIGH",
) -> str:
    if stage not in CANONICAL_STAGES:
        raise ValueError(f"Estágio inválido: {stage}. Deve ser um de {CANONICAL_STAGES}")

    ledger = load_json(LEDGER_PATH)
    count = len(ledger.get("evidences", [])) + 1
    ev_id = f"EV-CTF-{count:04d}"

    artifact_content = ""
    if raw_file and raw_file.exists():
        artifact_bytes = raw_file.read_bytes()
        ev_hash = compute_sha256(artifact_bytes)
        try:
            artifact_content = artifact_bytes.decode("utf-8")
        except UnicodeDecodeError:
            artifact_content = f"<binary artifact {len(artifact_bytes)} bytes>"
    elif raw_text:
        artifact_content = raw_text
        ev_hash = compute_sha256(raw_text)
    else:
        artifact_content = claim
        ev_hash = compute_sha256(claim)

    # Persist in stage folder if meaningful
    if stage in STAGE_DIRS:
        sub = DIR / STAGE_DIRS[stage]
        sub.mkdir(parents=True, exist_ok=True)
        art_path = sub / f"{ev_id}.txt"
        art_path.write_text(artifact_content, encoding="utf-8")

    new_ev = {
        "evidence_id": ev_id,
        "stage": stage,
        "timestamp": now_utc(),
        "source_tool": tool,
        "claim": claim,
        "raw_artifact": artifact_content[:500],
        "evidence_sha256": ev_hash,
        "confidence": confidence.upper(),
    }

    ledger["evidences"].append(new_ev)
    ledger["summary"]["total_evidences"] = len(ledger["evidences"])
    ledger["updated_at"] = now_utc()
    save_json(LEDGER_PATH, ledger)

    print(f"[+] Evidência registrada: {ev_id} | Stage: {stage} | Hash: {ev_hash}")
    return ev_id


def cmd_advance(next_state: str) -> None:
    if next_state not in CANONICAL_STAGES:
        raise ValueError(f"Estado inválido: {next_state}. Deve ser um de {CANONICAL_STAGES}")

    graph = load_json(GRAPH_PATH)
    current = graph.get("current_state")

    # Validate transition
    valid_transitions = [
        (t["from"], t["to"]) for t in graph.get("transitions", [])
    ]
    if (current, next_state) not in valid_transitions and current != next_state:
        allowed = [t[1] for t in valid_transitions if t[0] == current]
        raise ValueError(f"Transição inválida de {current} para {next_state}. Transições permitidas a partir de {current}: {allowed}")

    # Mark current completed
    if current in graph["states"]:
        graph["states"][current]["status"] = "COMPLETED"
        graph["states"][current]["completed_at"] = now_utc()

    # Mark next active
    graph["states"][next_state]["status"] = "IN_PROGRESS"
    graph["states"][next_state]["unlocked_at"] = now_utc()
    graph["current_state"] = next_state
    save_json(GRAPH_PATH, graph)

    ledger = load_json(LEDGER_PATH)
    ledger["summary"]["current_stage"] = next_state
    if next_state == "USER_FLAG":
        ledger["summary"]["flags_captured"]["user"] = True
    elif next_state == "ROOT_FLAG":
        ledger["summary"]["flags_captured"]["root"] = True
    save_json(LEDGER_PATH, ledger)

    print(f"[+] Grafo de estados avançado: {current} -> {next_state}")


def cmd_validate() -> bool:
    graph = load_json(GRAPH_PATH)
    ledger = load_json(LEDGER_PATH)
    errors = []

    current = graph.get("current_state")
    if current not in CANONICAL_STAGES:
        errors.append(f"current_state '{current}' não é canônico.")

    # Referential check on states
    for name, st in graph.get("states", {}).items():
        if name not in CANONICAL_STAGES:
            errors.append(f"Estado desconhecido: {name}")

    # Ledger check
    ev_ids = set()
    for ev in ledger.get("evidences", []):
        eid = ev.get("evidence_id")
        if eid in ev_ids:
            errors.append(f"ID de evidência duplicado: {eid}")
        ev_ids.add(eid)
        if len(ev.get("evidence_sha256", "")) != 64:
            errors.append(f"Hash SHA256 inválido na evidência {eid}")

    if errors:
        print(f"[!] Falha na validação do grafo ({len(errors)} erros):")
        for e in errors:
            print(f"    - {e}")
        return False

    print("[✓] Integridade do Grafo de Estados e Ledger de Evidências: 100% VÁLIDA.")
    return True


def main():
    parser = argparse.ArgumentParser(description="MITR3 CTF Evidence & State Graph Manager")
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("status", help="Exibe status atual do grafo e ledger")
    subparsers.add_parser("validate", help="Valida integridade do grafo e hashes")

    p_target = subparsers.add_parser("set-target", help="Define o IP da máquina alvo")
    p_target.add_argument("ip", help="Endereço IP da máquina alvo")

    p_ev = subparsers.add_parser("add-evidence", help="Adiciona uma evidência ao ledger")
    p_ev.add_argument("--stage", required=True, choices=CANONICAL_STAGES)
    p_ev.add_argument("--tool", required=True, help="Ferramenta de origem")
    p_ev.add_argument("--claim", required=True, help="Descrição/conclusão da evidência")
    p_ev.add_argument("--text", help="Texto bruto do artefato")
    p_ev.add_argument("--file", type=Path, help="Arquivo do artefato")

    p_adv = subparsers.add_parser("advance", help="Avança o grafo para o próximo estado")
    p_adv.add_argument("state", choices=CANONICAL_STAGES)

    args = parser.parse_args()
    if args.command == "status":
        cmd_status()
    elif args.command == "validate":
        ok = cmd_validate()
        sys.exit(0 if ok else 1)
    elif args.command == "set-target":
        cmd_set_target(args.ip)
    elif args.command == "add-evidence":
        cmd_add_evidence(args.stage, args.tool, args.claim, args.text, args.file)
    elif args.command == "advance":
        cmd_advance(args.state)
    else:
        cmd_status()


if __name__ == "__main__":
    main()
