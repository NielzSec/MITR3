#!/usr/bin/env python3
"""
MITR3 — Graph Ingestion / Normalizer (Layer 2)
Deterministic normalization of scanner findings, SARIF v2.1, and AST reachability
into canonical property graph entities and directional attack edges.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass, field, replace
import datetime as dt
import hashlib
import json
import math
import os
from pathlib import Path
import sqlite3
import stat
import sys
from typing import Any, Dict, List, Optional, Set, Tuple


VALID_NODE_TYPES = frozenset({"SOURCE", "FINDING", "SINK", "MITIGATION", "ATTACK_TECHNIQUE"})
VALID_EDGE_TYPES = frozenset({"FLOWS_TO", "CALLS", "MITIGATED_BY", "MAPS_TO"})


def compute_sha256(data: Any) -> str:
    """Compute stable SHA256 over serialized data or raw bytes/str."""
    if isinstance(data, (bytes, bytearray)):
        return hashlib.sha256(data).hexdigest()
    if isinstance(data, str):
        return hashlib.sha256(data.encode("utf-8")).hexdigest()
    raw = json.dumps(data, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def stable_slug(text: str) -> str:
    """Generate a clean URL/identifier-safe slug."""
    clean = "".join(c if c.isalnum() or c in ("-", "_", ".") else "_" for c in text.strip())
    while "__" in clean:
        clean = clean.replace("__", "_")
    return clean.strip("_")


@dataclass(frozen=True)
class GraphNode:
    id: str
    type: str
    name: str
    file: Optional[str] = None
    line: Optional[int] = None
    severity: Optional[str] = None
    confidence: Optional[str] = None
    evidence_sha256: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if self.type not in VALID_NODE_TYPES:
            raise ValueError(f"Invalid node type: {self.type}. Must be one of {sorted(VALID_NODE_TYPES)}")
        if not self.id:
            raise ValueError("Node id cannot be empty")


@dataclass(frozen=True)
class GraphEdge:
    id: str
    type: str
    source_id: str
    target_id: str
    weight: float = 1.0
    evidence_sha256: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if self.type not in VALID_EDGE_TYPES:
            raise ValueError(f"Invalid edge type: {self.type}. Must be one of {sorted(VALID_EDGE_TYPES)}")
        if (isinstance(self.weight, bool) or not isinstance(self.weight, (int, float))
                or not math.isfinite(self.weight) or not 0 <= self.weight <= 1):
            raise ValueError("Edge weight/multiplier must be finite and within [0, 1]")
        if not self.source_id or not self.target_id:
            raise ValueError("Edge source_id and target_id cannot be empty")


class AttackGraphNormalizer:
    """Ingests heterogeneous scanner and harness outputs into a canonical attack graph."""

    def __init__(self, strict: bool = False):
        self.nodes: Dict[str, GraphNode] = {}
        self.edges: Dict[str, GraphEdge] = {}
        self.strict: bool = strict
        self.evidence_artifacts: Dict[str, bytes] = {}
        self.input_artifact_hashes: Set[str] = set()

    def record_evidence(self, data: Any) -> str:
        """Stage exact input snapshot bytes; exports materialize them beside the graph."""
        if isinstance(data, bytes):
            raw = data
        else:
            text = data if isinstance(data, str) else json.dumps(data, sort_keys=True, ensure_ascii=False, allow_nan=False)
            raw = text.encode("utf-8")
        digest = compute_sha256(raw)
        self.evidence_artifacts[digest] = raw
        return digest

    def input_evidence(self, data: Any, artifact_path: Optional[Path]) -> str:
        if artifact_path is None:
            return self.record_evidence(data)
        raw = artifact_path.read_bytes()
        document = json.loads(raw)
        matches = document == data
        if isinstance(data, dict) and isinstance(document, list):
            matches = data in document
        elif isinstance(data, dict) and isinstance(document, dict) and isinstance(document.get("findings"), list):
            matches = matches or data in document["findings"]
        if not matches:
            raise ValueError("Input data does not match the physical artifact")
        digest = self.record_evidence(raw)
        self.input_artifact_hashes.add(digest)
        return digest

    def materialize_evidence(self, parent: Path) -> None:
        for record in (*self.nodes.values(), *self.edges.values()):
            digest = record.evidence_sha256
            if not digest and record.type == "ATTACK_TECHNIQUE":
                continue
            if digest not in self.evidence_artifacts:
                raise ValueError(f"No physical input snapshot available for {record.id}")
        parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            parent_stat = os.fstat(parent_fd)
            if parent_stat.st_uid != os.geteuid() or parent_stat.st_mode & 0o022:
                raise ValueError(f"Untrusted evidence parent directory: {parent}")
            try:
                os.mkdir("evidence", mode=0o700, dir_fd=parent_fd)
            except FileExistsError:
                pass
            try:
                directory_fd = os.open("evidence", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
            except OSError as exc:
                raise ValueError(f"Untrusted evidence directory: {parent / 'evidence'}") from exc
            try:
                directory_stat = os.fstat(directory_fd)
                if (directory_stat.st_uid != os.geteuid() or stat.S_IMODE(directory_stat.st_mode) != 0o700):
                    raise ValueError(f"Untrusted evidence directory: {parent / 'evidence'}")
                for digest, raw in self.evidence_artifacts.items():
                    try:
                        fd = os.open(digest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                     0o600, dir_fd=directory_fd)
                    except FileExistsError:
                        try:
                            fd = os.open(digest, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd)
                        except OSError as exc:
                            raise ValueError(f"Untrusted evidence artifact: {parent / 'evidence' / digest}") from exc
                        artifact_stat = os.fstat(fd)
                        if (not stat.S_ISREG(artifact_stat.st_mode) or artifact_stat.st_uid != os.geteuid()
                                or stat.S_IMODE(artifact_stat.st_mode) != 0o600):
                            os.close(fd)
                            raise ValueError(f"Untrusted evidence artifact: {parent / 'evidence' / digest}")
                        with os.fdopen(fd, "rb") as artifact:
                            if artifact.read() != raw:
                                raise ValueError(f"Evidence artifact changed: {parent / 'evidence' / digest}")
                    except OSError as exc:
                        raise ValueError(f"Could not create evidence artifact: {parent / 'evidence' / digest}") from exc
                    else:
                        with os.fdopen(fd, "wb") as artifact:
                            artifact.write(raw)
            finally:
                os.close(directory_fd)
        finally:
            os.close(parent_fd)

    def provenance(self, record):
        if record.evidence_sha256 in self.evidence_artifacts:
            return replace(record, metadata={**record.metadata,
                "evidence_kind": "C2_INPUT_ARTIFACT" if record.evidence_sha256 in self.input_artifact_hashes else "C2_INPUT_SNAPSHOT",
                "evidence_artifact": f"evidence/{record.evidence_sha256}"})
        return record

    def add_node(self, node: GraphNode) -> GraphNode:
        node = self.provenance(node)
        if node.id in self.nodes:
            existing = self.nodes[node.id]
            if node.type in {"SOURCE", "SINK"}:
                if existing != node:
                    raise ValueError(f"Conflicting shared endpoint: {node.id}")
                return existing
            merged_meta = dict(existing.metadata)
            merged_meta.update(node.metadata)
            node = GraphNode(
                id=node.id,
                type=node.type,
                name=node.name or existing.name,
                file=node.file or existing.file,
                line=node.line or existing.line,
                severity=node.severity or existing.severity,
                confidence=node.confidence or existing.confidence,
                evidence_sha256=node.evidence_sha256 or existing.evidence_sha256,
                metadata=merged_meta
            )
        self.nodes[node.id] = node
        return node

    def add_edge(self, edge: GraphEdge, strict: Optional[bool] = None) -> GraphEdge:
        edge = self.provenance(edge)
        is_strict = self.strict if strict is None else strict
        if is_strict:
            if edge.source_id not in self.nodes:
                raise ValueError(f"Referential integrity violation: source {edge.source_id} not found in nodes")
            if edge.target_id not in self.nodes:
                raise ValueError(f"Referential integrity violation: target {edge.target_id} not found in nodes")
        self.edges[edge.id] = edge
        return edge

    def validate_integrity(self) -> Tuple[bool, List[str]]:
        """Validate that all edges have existing source and target nodes."""
        errors = []
        for edge in self.edges.values():
            if edge.source_id not in self.nodes:
                errors.append(f"Orphan edge {edge.id}: source {edge.source_id} not found in nodes")
            if edge.target_id not in self.nodes:
                errors.append(f"Orphan edge {edge.id}: target {edge.target_id} not found in nodes")
        return len(errors) == 0, errors

    def ingest_harness_finding(self, finding: Dict[str, Any], *, artifact_path: Optional[Path] = None) -> str:
        """
        Normalize a finding from mitr3-vuln-harness.py into:
        - SOURCE node (if entrypoint present)
        - FINDING node
        - SINK node (if sink/function present)
        - MITIGATION nodes (if active mitigations present)
        - Connected FLOWS_TO, CALLS, MITIGATED_BY edges.
        """
        rule_id = finding.get("rule_id")
        if not rule_id:
            rule_ids = finding.get("rule_ids")
            if isinstance(rule_ids, list) and rule_ids:
                rule_id = str(rule_ids[0])
            else:
                rule_id = "unknown_rule"

        file_path = finding.get("file") or finding.get("file_path", "unknown_file")
        line = finding.get("line", 1)
        finding_id = f"fnd:{stable_slug(rule_id)}:{stable_slug(file_path)}:{line}"
        ev_hash = self.input_evidence(finding, artifact_path)

        # 1. Register FINDING node
        severity = str(finding.get("severity") or finding.get("base_severity", "MEDIUM")).upper()
        confidence = str(finding.get("confidence") or finding.get("consensus_status", "MEDIUM")).upper()

        fnd_node = GraphNode(
            id=finding_id,
            type="FINDING",
            name=f"{rule_id} @ {file_path}:{line}",
            file=file_path,
            line=line,
            severity=severity,
            confidence=confidence,
            evidence_sha256=ev_hash,
            metadata={
                "agreement_ratio": finding.get("agreement_ratio", 1.0),
                "ast_gate": finding.get("ast_gate", "PASS"),
                "ast_details": finding.get("ast_details", ""),
                "scanner_count": finding.get("scanner_count", len(finding.get("scanners", [])) or 1),
                "scanners": finding.get("scanners", []),
                "effective_score": finding.get("effective_score"),
                "final_verdict": finding.get("final_verdict"),
            }
        )
        self.add_node(fnd_node)

        # 2. Register SOURCE node if entrypoint is defined
        source_name = finding.get("source_entrypoint") or finding.get("source") or finding.get("entrypoint")
        if source_name:
            source_id = f"src:{stable_slug(file_path)}:{stable_slug(str(source_name))}"
            self.add_node(GraphNode(
                id=source_id,
                type="SOURCE",
                name=str(source_name),
                file=file_path,
                evidence_sha256=self.record_evidence(source_name),
                metadata={"entrypoint_type": finding.get("entrypoint_type", "HTTP_ROUTE")}
            ))
            edge_id = f"edge:flows_to:{source_id}->{finding_id}"
            self.add_edge(GraphEdge(
                id=edge_id,
                type="FLOWS_TO",
                source_id=source_id,
                target_id=finding_id,
                evidence_sha256=ev_hash
            ))

        # 3. Only explicit sink fields describe a sink; snippets/enclosing functions do not.
        sink_target = (finding.get("sink_function") or finding.get("sink"))
        if sink_target:
            sink_id = f"snk:{stable_slug(file_path)}:{stable_slug(str(sink_target))}"
            self.add_node(GraphNode(
                id=sink_id,
                type="SINK",
                name=str(sink_target),
                file=file_path,
                evidence_sha256=self.record_evidence(sink_target),
                metadata={"sink_type": finding.get("sink_type", "EXECUTION_SINK")}
            ))
            edge_id = f"edge:calls:{finding_id}->{sink_id}"
            self.add_edge(GraphEdge(
                id=edge_id,
                type="CALLS",
                source_id=finding_id,
                target_id=sink_id,
                evidence_sha256=ev_hash
            ))

        # 4. Register MITIGATION nodes if IaC mitigations present
        mitigations = finding.get("mitigations") or finding.get("iac_mitigations") or []
        for mit in mitigations:
            if isinstance(mit, dict):
                mit_id_raw = mit.get("resource_id") or mit.get("id") or mit.get("control", "unknown_mit")
                control_name = str(mit.get("control", mit_id_raw))
                status = mit.get("status", "ACTIVE")
                provider = mit.get("provider", "iac")
                raw_multiplier = mit.get("multiplier", 0.5)
                if isinstance(raw_multiplier, bool):
                    raise ValueError("Mitigation multiplier must be finite and within [0, 1]")
                multiplier = float(raw_multiplier)
            else:
                mit_id_raw = str(mit)
                control_name = str(mit)
                status = "ACTIVE"
                provider = "iac"
                multiplier = 0.5

            mit_id = f"mit:{stable_slug(str(mit_id_raw))}"
            self.add_node(GraphNode(
                id=mit_id,
                type="MITIGATION",
                name=control_name,
                evidence_sha256=self.record_evidence(mit),
                metadata={
                    "resource_id": str(mit_id_raw),
                    "status": status,
                    "provider": provider
                }
            ))
            edge_id = f"edge:mitigated_by:{finding_id}->{mit_id}"
            self.add_edge(GraphEdge(
                id=edge_id,
                type="MITIGATED_BY",
                source_id=finding_id,
                target_id=mit_id,
                evidence_sha256=ev_hash,
                weight=multiplier
            ))

        # 5. Register ATTACK_TECHNIQUE if technique is mapped
        attack_tech = finding.get("attack_technique") or finding.get("technique_id")
        if attack_tech:
            tech_id = str(attack_tech).upper()
            if not tech_id.startswith("T"):
                tech_id = f"T{tech_id}"
            self.add_node(GraphNode(
                id=tech_id,
                type="ATTACK_TECHNIQUE",
                name=f"MITRE ATT&CK {tech_id}",
                metadata={"catalog": "enterprise-attack"}
            ))
            edge_id = f"edge:maps_to:{finding_id}->{tech_id}"
            self.add_edge(GraphEdge(
                id=edge_id,
                type="MAPS_TO",
                source_id=finding_id,
                target_id=tech_id,
                evidence_sha256=ev_hash
            ))

        return finding_id

    def ingest_sarif(self, sarif_data: Dict[str, Any], *, artifact_path: Optional[Path] = None) -> List[str]:
        """Normalize standard SARIF v2.1 log into graph finding nodes."""
        artifact_hash = self.input_evidence(sarif_data, artifact_path) if artifact_path else None
        ingested_ids = []
        for run in sarif_data.get("runs", []):
            tool_name = run.get("tool", {}).get("driver", {}).get("name", "scanner")
            for result in run.get("results", []):
                rule_id = result.get("ruleId", "sarif_rule")
                locations = result.get("locations", [])
                file_path = "unknown"
                line = 1
                if locations:
                    phys = locations[0].get("physicalLocation", {})
                    file_path = phys.get("artifactLocation", {}).get("uri", "unknown")
                    line = phys.get("region", {}).get("startLine", 1)

                finding_id = f"fnd:{stable_slug(tool_name)}:{stable_slug(rule_id)}:{stable_slug(file_path)}:{line}"
                ev_hash = artifact_hash or self.record_evidence(result)

                node = GraphNode(
                    id=finding_id,
                    type="FINDING",
                    name=f"[{tool_name}] {rule_id} @ {file_path}:{line}",
                    file=file_path,
                    line=line,
                    severity=str(result.get("level", "warning")).upper(),
                    evidence_sha256=ev_hash,
                    metadata={"message": result.get("message", {}).get("text", ""), "tool": tool_name}
                )
                self.add_node(node)
                ingested_ids.append(finding_id)
        return ingested_ids

    def export_jsonl(self, out_path: Path) -> int:
        """Stream export of canonical nodes and edges to JSON-L format."""
        valid, errors = self.validate_integrity()
        if not valid:
            raise ValueError(f"Integrity check failed: {'; '.join(errors)}")

        out_path.parent.mkdir(parents=True, exist_ok=True)
        self.materialize_evidence(out_path.parent)
        count = 0
        with out_path.open("w", encoding="utf-8") as f:
            for node in self.nodes.values():
                record = {"entity": "node", **asdict(node)}
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
                count += 1
            for edge in self.edges.values():
                record = {"entity": "edge", **asdict(edge)}
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
                count += 1
        return count

    def persist_sqlite(self, db_path: Path) -> Tuple[int, int]:
        """Persist normalized nodes and edges into SQLite with referential integrity."""
        valid, errors = self.validate_integrity()
        if not valid:
            raise ValueError(f"Integrity check failed: {'; '.join(errors)}")

        db_path.parent.mkdir(parents=True, exist_ok=True)
        con = sqlite3.connect(db_path)
        try:
            tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if tables and ("c2_graph_meta" not in tables or
                           con.execute("SELECT version FROM c2_graph_meta").fetchall() != [(1,)]):
                raise ValueError("Refusing existing database without C2 schema version 1; use a new staging database")
            self.materialize_evidence(db_path.parent)
            con.execute("PRAGMA foreign_keys = ON")
            con.execute("BEGIN")
            with con:
                con.execute("CREATE TABLE IF NOT EXISTS c2_graph_meta (version INTEGER PRIMARY KEY CHECK(version=1))")
                con.execute("INSERT INTO c2_graph_meta VALUES (1) ON CONFLICT DO NOTHING")
                con.execute("""
                    CREATE TABLE IF NOT EXISTS attack_nodes (
                        id TEXT PRIMARY KEY NOT NULL CHECK(length(id)>0),
                        type TEXT NOT NULL CHECK(type IN ('SOURCE','FINDING','SINK','MITIGATION','ATTACK_TECHNIQUE')),
                        name TEXT NOT NULL CHECK(length(name)>0),
                        file TEXT,
                        line INTEGER CHECK(line IS NULL OR (typeof(line)='integer' AND line>=1)),
                        severity TEXT,
                        confidence TEXT,
                        evidence_sha256 TEXT NOT NULL CHECK((type='ATTACK_TECHNIQUE' AND evidence_sha256='') OR
                            (length(evidence_sha256)=64 AND evidence_sha256 NOT GLOB '*[^0-9a-f]*')),
                        metadata TEXT NOT NULL CHECK(json_valid(metadata))
                    )
                """)
                con.execute("""
                    CREATE TABLE IF NOT EXISTS attack_edges (
                        id TEXT PRIMARY KEY NOT NULL CHECK(length(id)>0),
                        type TEXT NOT NULL CHECK(type IN ('FLOWS_TO','CALLS','MITIGATED_BY','MAPS_TO')),
                        source_id TEXT NOT NULL REFERENCES attack_nodes(id),
                        target_id TEXT NOT NULL REFERENCES attack_nodes(id),
                        weight REAL NOT NULL CHECK(typeof(weight) IN ('integer','real') AND weight>=0 AND weight<=1),
                        evidence_sha256 TEXT NOT NULL CHECK(length(evidence_sha256)=64 AND evidence_sha256 NOT GLOB '*[^0-9a-f]*'),
                        metadata TEXT NOT NULL CHECK(json_valid(metadata))
                    )
                """)
                con.execute("CREATE INDEX IF NOT EXISTS idx_attack_edges_src ON attack_edges(source_id)")
                con.execute("CREATE INDEX IF NOT EXISTS idx_attack_edges_tgt ON attack_edges(target_id)")
                for action in ("INSERT", "UPDATE"):
                    con.execute(f"""
                        CREATE TRIGGER IF NOT EXISTS check_edge_endpoints_{action.lower()} BEFORE {action} ON attack_edges
                        WHEN NOT EXISTS (SELECT 1 FROM attack_nodes s, attack_nodes t
                          WHERE s.id=NEW.source_id AND t.id=NEW.target_id AND (
                            (NEW.type='FLOWS_TO' AND s.type='SOURCE' AND t.type='FINDING') OR
                            (NEW.type='CALLS' AND s.type='FINDING' AND t.type='SINK') OR
                            (NEW.type='MITIGATED_BY' AND s.type='FINDING' AND t.type='MITIGATION') OR
                            (NEW.type='MAPS_TO' AND s.type='FINDING' AND t.type='ATTACK_TECHNIQUE')))
                        BEGIN SELECT RAISE(ABORT, 'Invalid or missing graph node endpoint'); END
                    """)
                con.execute("""
                    CREATE TRIGGER IF NOT EXISTS c2_node_delete BEFORE DELETE ON attack_nodes
                    WHEN EXISTS (SELECT 1 FROM attack_edges WHERE source_id=OLD.id OR target_id=OLD.id)
                    BEGIN SELECT RAISE(ABORT, 'Node still referenced'); END
                """)
                con.execute("""
                    CREATE TRIGGER IF NOT EXISTS c2_node_identity BEFORE UPDATE OF id,type ON attack_nodes
                    WHEN NEW.id<>OLD.id OR NEW.type<>OLD.type
                    BEGIN SELECT RAISE(ABORT, 'Node identity is immutable'); END
                """)
                for n in self.nodes.values():
                    con.execute("""
                        INSERT INTO attack_nodes VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(id) DO UPDATE SET type=excluded.type,name=excluded.name,file=excluded.file,
                        line=excluded.line,severity=excluded.severity,confidence=excluded.confidence,
                        evidence_sha256=excluded.evidence_sha256,metadata=excluded.metadata
                    """, (n.id, n.type, n.name, n.file, n.line, n.severity, n.confidence, n.evidence_sha256, json.dumps(n.metadata)))
                for e in self.edges.values():
                    con.execute("""
                        INSERT INTO attack_edges VALUES (?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(id) DO UPDATE SET type=excluded.type,source_id=excluded.source_id,
                        target_id=excluded.target_id,weight=excluded.weight,
                        evidence_sha256=excluded.evidence_sha256,metadata=excluded.metadata
                    """, (e.id, e.type, e.source_id, e.target_id, e.weight, e.evidence_sha256, json.dumps(e.metadata)))
            return len(self.nodes), len(self.edges)
        finally:
            con.close()


def main():
    parser = argparse.ArgumentParser(description="MITR3 Graph Ingestion / Normalizer (Layer 2)")
    parser.add_argument("inputs", nargs="+", help="Input JSON or SARIF finding files")
    parser.add_argument("--jsonl", type=Path, help="Export normalized graph to JSON-L file")
    parser.add_argument("--sqlite", type=Path, help="Persist normalized graph to SQLite database")
    args = parser.parse_args()

    normalizer = AttackGraphNormalizer()
    for input_file in args.inputs:
        path = Path(input_file)
        if not path.exists():
            print(f"Error: input file {path} not found", file=sys.stderr)
            sys.exit(1)
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict) and data.get("version") == "2.1.0" and "runs" in data:
            normalizer.ingest_sarif(data, artifact_path=path)
        elif isinstance(data, dict) and "findings" in data and isinstance(data["findings"], list):
            for item in data["findings"]:
                if isinstance(item, dict):
                    normalizer.ingest_harness_finding(item, artifact_path=path)
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    normalizer.ingest_harness_finding(item, artifact_path=path)
        elif isinstance(data, dict):
            normalizer.ingest_harness_finding(data, artifact_path=path)

    valid, errors = normalizer.validate_integrity()
    if not valid:
        print(f"Graph validation failed with {len(errors)} errors:", file=sys.stderr)
        for err in errors:
            print(f" - {err}", file=sys.stderr)
        sys.exit(2)

    print(f"Graph normalized successfully: {len(normalizer.nodes)} nodes, {len(normalizer.edges)} edges.")
    if args.jsonl:
        count = normalizer.export_jsonl(args.jsonl)
        print(f"Exported {count} records to {args.jsonl}")
    if args.sqlite:
        nodes_cnt, edges_cnt = normalizer.persist_sqlite(args.sqlite)
        print(f"Persisted {nodes_cnt} nodes and {edges_cnt} edges to {args.sqlite}")


if __name__ == "__main__":
    main()
