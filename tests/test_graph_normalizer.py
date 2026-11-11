#!/usr/bin/env python3
"""Unit tests for MITR3 Graph Ingestion / Normalizer (Layer 2).

Tests compliance with:
1. Canonical node and edge normalization from mitr3-vuln-harness.py findings.
2. SARIF v2.1 normalization into FINDING nodes with immutable SHA256 evidence.
3. Referential integrity validation (rejecting orphan edges).
4. JSON-L export and SQLite persistence with relational constraints.
"""
from dataclasses import FrozenInstanceError
import importlib.util
import json
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import tempfile
import unittest

BASE = Path(__file__).resolve().parents[1]
NORMALIZER_PATH = BASE / "bin" / "mitr3-graph-normalizer.py"

spec = importlib.util.spec_from_file_location("mitr3_graph_normalizer", NORMALIZER_PATH)
normalizer_mod = importlib.util.module_from_spec(spec)
sys.modules["mitr3_graph_normalizer"] = normalizer_mod
spec.loader.exec_module(normalizer_mod)

AttackGraphNormalizer = normalizer_mod.AttackGraphNormalizer
GraphNode = normalizer_mod.GraphNode
GraphEdge = normalizer_mod.GraphEdge
compute_sha256 = normalizer_mod.compute_sha256
stable_slug = normalizer_mod.stable_slug


class TestHarnessFindingNormalization(unittest.TestCase):
    """Test 1: Normalização de findings de mitr3-vuln-harness.py em nós e arestas canônicos."""

    def setUp(self):
        self.normalizer = AttackGraphNormalizer()

    def test_normalize_full_canonical_chain(self):
        """Verify full chain produces SOURCE, FINDING, SINK, MITIGATION, ATTACK_TECHNIQUE nodes

        and FLOWS_TO, CALLS, MITIGATED_BY, MAPS_TO edges.
        """
        finding = {
            "rule_id": "python.fastapi.security.sqli",
            "file": "app/api/v1/users.py",
            "line": 42,
            "severity": "CRITICAL",
            "confidence": "HIGH",
            "source_entrypoint": "/api/v1/users/search",
            "entrypoint_type": "HTTP_ROUTE",
            "sink_function": "db.session.execute",
            "sink_type": "DATABASE_EXEC",
            "iac_mitigations": [
                {
                    "resource_id": "sg-09a1c807",
                    "control": "ingress_deny_public",
                    "status": "ACTIVE",
                    "provider": "terraform",
                    "multiplier": 0.3,
                }
            ],
            "attack_technique": "T1190",
        }

        fnd_id = self.normalizer.ingest_harness_finding(finding)

        # 1. FINDING node verification
        self.assertIn(fnd_id, self.normalizer.nodes)
        fnd_node = self.normalizer.nodes[fnd_id]
        self.assertEqual(fnd_node.type, "FINDING")
        self.assertEqual(fnd_node.file, "app/api/v1/users.py")
        self.assertEqual(fnd_node.line, 42)
        self.assertEqual(fnd_node.severity, "CRITICAL")
        self.assertEqual(fnd_node.confidence, "HIGH")
        self.assertTrue(re.fullmatch(r"[0-9a-f]{64}", fnd_node.evidence_sha256))

        # 2. SOURCE node verification
        src_id = f"src:app_api_v1_users.py:{stable_slug('/api/v1/users/search')}"
        self.assertIn(src_id, self.normalizer.nodes)
        src_node = self.normalizer.nodes[src_id]
        self.assertEqual(src_node.type, "SOURCE")
        self.assertEqual(src_node.name, "/api/v1/users/search")
        self.assertEqual(src_node.metadata.get("entrypoint_type"), "HTTP_ROUTE")

        # 3. SINK node verification
        snk_id = f"snk:app_api_v1_users.py:db.session.execute"
        self.assertIn(snk_id, self.normalizer.nodes)
        snk_node = self.normalizer.nodes[snk_id]
        self.assertEqual(snk_node.type, "SINK")
        self.assertEqual(snk_node.name, "db.session.execute")

        # 4. MITIGATION node verification
        mit_id = "mit:sg-09a1c807"
        self.assertIn(mit_id, self.normalizer.nodes)
        mit_node = self.normalizer.nodes[mit_id]
        self.assertEqual(mit_node.type, "MITIGATION")
        self.assertEqual(mit_node.name, "ingress_deny_public")
        self.assertEqual(mit_node.metadata.get("provider"), "terraform")

        # 5. ATTACK_TECHNIQUE node verification
        tech_id = "T1190"
        self.assertIn(tech_id, self.normalizer.nodes)
        tech_node = self.normalizer.nodes[tech_id]
        self.assertEqual(tech_node.type, "ATTACK_TECHNIQUE")

        # 6. Edges verification: FLOWS_TO, CALLS, MITIGATED_BY, MAPS_TO
        edge_flows = f"edge:flows_to:{src_id}->{fnd_id}"
        self.assertIn(edge_flows, self.normalizer.edges)
        self.assertEqual(self.normalizer.edges[edge_flows].type, "FLOWS_TO")
        self.assertEqual(self.normalizer.edges[edge_flows].source_id, src_id)
        self.assertEqual(self.normalizer.edges[edge_flows].target_id, fnd_id)

        edge_calls = f"edge:calls:{fnd_id}->{snk_id}"
        self.assertIn(edge_calls, self.normalizer.edges)
        self.assertEqual(self.normalizer.edges[edge_calls].type, "CALLS")
        self.assertEqual(self.normalizer.edges[edge_calls].source_id, fnd_id)
        self.assertEqual(self.normalizer.edges[edge_calls].target_id, snk_id)

        edge_mit = f"edge:mitigated_by:{fnd_id}->{mit_id}"
        self.assertIn(edge_mit, self.normalizer.edges)
        self.assertEqual(self.normalizer.edges[edge_mit].type, "MITIGATED_BY")
        self.assertEqual(self.normalizer.edges[edge_mit].source_id, fnd_id)
        self.assertEqual(self.normalizer.edges[edge_mit].target_id, mit_id)
        self.assertAlmostEqual(self.normalizer.edges[edge_mit].weight, 0.3)

        edge_maps = f"edge:maps_to:{fnd_id}->{tech_id}"
        self.assertIn(edge_maps, self.normalizer.edges)
        self.assertEqual(self.normalizer.edges[edge_maps].type, "MAPS_TO")

        # Validate total counts and integrity
        valid, errors = self.normalizer.validate_integrity()
        self.assertTrue(valid)
        self.assertEqual(errors, [])
        self.assertEqual(len(self.normalizer.nodes), 5)
        self.assertEqual(len(self.normalizer.edges), 4)

    def test_normalize_vuln_harness_evaluated_finding_format(self):
        """Verify normalization of native mitr3-vuln-harness EvaluatedFinding dictionary format."""
        evaluated = {
            "id": "HARNESS-codeql-0001",
            "file_path": "services/auth.py",
            "line": 88,
            "rule_ids": ["py/sql-injection", "python.lang.sqli"],
            "scanners": ["codeql", "semgrep"],
            "consensus_status": "CONFIRMED_BY_ENSEMBLE",
            "consensus_factor": 1.5,
            "base_severity": "HIGH",
            "base_score": 7.5,
            "ast_gate": 1,
            "ast_details": "valid call to cursor.execute",
            "iac_mitigations": ["waf_rule_active", "auth_required"],
            "infra_multiplier": 0.2,
            "effective_score": 11.25,
            "final_verdict": "ACTIONABLE_PRIORITY_0",
            "sink_function": "cursor.execute",
            "source": "login_handler",
        }

        fnd_id = self.normalizer.ingest_harness_finding(evaluated)
        fnd_node = self.normalizer.nodes[fnd_id]

        self.assertEqual(fnd_node.type, "FINDING")
        self.assertEqual(fnd_node.file, "services/auth.py")
        self.assertEqual(fnd_node.line, 88)
        self.assertEqual(fnd_node.severity, "HIGH")
        self.assertEqual(fnd_node.confidence, "CONFIRMED_BY_ENSEMBLE")
        self.assertEqual(fnd_node.metadata.get("effective_score"), 11.25)
        self.assertEqual(fnd_node.metadata.get("final_verdict"), "ACTIONABLE_PRIORITY_0")

        # String mitigations normalized properly
        self.assertIn("mit:waf_rule_active", self.normalizer.nodes)
        self.assertIn("mit:auth_required", self.normalizer.nodes)

        # FLOWS_TO from source 'login_handler'
        src_nodes = [n for n in self.normalizer.nodes.values() if n.type == "SOURCE"]
        self.assertEqual(len(src_nodes), 1)
        self.assertEqual(src_nodes[0].name, "login_handler")

        # SINK from explicit sink_function
        snk_nodes = [n for n in self.normalizer.nodes.values() if n.type == "SINK"]
        self.assertEqual(len(snk_nodes), 1)
        self.assertEqual(snk_nodes[0].name, "cursor.execute")

        valid, errors = self.normalizer.validate_integrity()
        self.assertTrue(valid)
        self.assertEqual(errors, [])

    def test_isolated_finding_without_source_or_sink(self):
        """Verify an isolated finding without entrypoint or sink creates only a FINDING node."""
        finding = {
            "rule_id": "generic.secret.detected",
            "file": "config/settings.py",
            "line": 15,
            "severity": "HIGH",
        }
        fnd_id = self.normalizer.ingest_harness_finding(finding)

        self.assertEqual(len(self.normalizer.nodes), 1)
        self.assertEqual(len(self.normalizer.edges), 0)
        self.assertEqual(self.normalizer.nodes[fnd_id].type, "FINDING")

    def test_node_deduplication_and_metadata_merge(self):
        """Verify adding existing node ID merges metadata rather than overwriting blindly."""
        node1 = GraphNode(id="test:1", type="FINDING", name="Test Finding", metadata={"scanner": "codeql"})
        node2 = GraphNode(id="test:1", type="FINDING", name="Test Finding", metadata={"verified": True})

        self.normalizer.add_node(node1)
        self.normalizer.add_node(node2)

        merged = self.normalizer.nodes["test:1"]
        self.assertEqual(merged.metadata["scanner"], "codeql")
        self.assertTrue(merged.metadata["verified"])


class TestSarifNormalization(unittest.TestCase):
    """Test 2: Normalização de SARIF v2.1 em nós FINDING com hash SHA256 imutável de evidência."""

    def setUp(self):
        self.normalizer = AttackGraphNormalizer()
        self.sample_sarif = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "CodeQL",
                            "semanticVersion": "2.15.0"
                        }
                    },
                    "results": [
                        {
                            "ruleId": "py/path-injection",
                            "level": "error",
                            "message": {
                                "text": "Uncontrolled data used in path expression."
                            },
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {
                                            "uri": "src/utils/filesystem.py"
                                        },
                                        "region": {
                                            "startLine": 104,
                                            "startColumn": 9
                                        }
                                    }
                                }
                            ]
                        },
                        {
                            "ruleId": "py/clear-text-logging",
                            "level": "warning",
                            "message": {
                                "text": "Sensitive data logged in cleartext."
                            },
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {
                                            "uri": "src/auth/session.py"
                                        },
                                        "region": {
                                            "startLine": 29
                                        }
                                    }
                                }
                            ]
                        }
                    ]
                }
            ]
        }

    def test_normalize_sarif_v21_basic(self):
        """Verify SARIF results are converted to canonical FINDING nodes."""
        ingested_ids = self.normalizer.ingest_sarif(self.sample_sarif)
        self.assertEqual(len(ingested_ids), 2)
        self.assertEqual(len(self.normalizer.nodes), 2)

        node1 = self.normalizer.nodes[ingested_ids[0]]
        self.assertEqual(node1.type, "FINDING")
        self.assertEqual(node1.file, "src/utils/filesystem.py")
        self.assertEqual(node1.line, 104)
        self.assertEqual(node1.severity, "ERROR")
        self.assertEqual(node1.metadata.get("tool"), "CodeQL")
        self.assertIn("Uncontrolled data used in path expression", node1.metadata.get("message", ""))

        node2 = self.normalizer.nodes[ingested_ids[1]]
        self.assertEqual(node2.type, "FINDING")
        self.assertEqual(node2.file, "src/auth/session.py")
        self.assertEqual(node2.line, 29)
        self.assertEqual(node2.severity, "WARNING")

    def test_sarif_evidence_sha256_deterministic_and_immutable(self):
        """Verify evidence SHA256 is exactly 64 hex characters, deterministic, and immutable."""
        ingested_ids = self.normalizer.ingest_sarif(self.sample_sarif)
        node = self.normalizer.nodes[ingested_ids[0]]

        # SHA256 format check
        self.assertTrue(re.fullmatch(r"[0-9a-f]{64}", node.evidence_sha256))

        # Expected SHA256 matches exact hash of result object
        expected_hash = compute_sha256(self.sample_sarif["runs"][0]["results"][0])
        self.assertEqual(node.evidence_sha256, expected_hash)

        # Immutability verification (frozen dataclass prevents attribute mutation)
        with self.assertRaises(FrozenInstanceError):
            node.evidence_sha256 = "tampered_hash_00000000000000000000000000000000000000000000000000000000"

        with self.assertRaises(FrozenInstanceError):
            node.name = "Tampered Name"

        # Determinism check across independent normalizer instance
        another_normalizer = AttackGraphNormalizer()
        another_ids = another_normalizer.ingest_sarif(self.sample_sarif)
        another_node = another_normalizer.nodes[another_ids[0]]
        self.assertEqual(node.evidence_sha256, another_node.evidence_sha256)

    def test_sarif_fallback_for_missing_optional_locations(self):
        """Verify handling of results with missing or empty locations."""
        minimal_sarif = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "Trivy"}},
                    "results": [
                        {
                            "ruleId": "CVE-2026-9999",
                            "level": "note",
                            "message": {"text": "Dependency vulnerability"}
                            # No locations
                        }
                    ]
                }
            ]
        }
        ingested_ids = self.normalizer.ingest_sarif(minimal_sarif)
        self.assertEqual(len(ingested_ids), 1)
        node = self.normalizer.nodes[ingested_ids[0]]
        self.assertEqual(node.file, "unknown")
        self.assertEqual(node.line, 1)
        self.assertEqual(node.severity, "NOTE")
        self.assertTrue(re.fullmatch(r"[0-9a-f]{64}", node.evidence_sha256))


class TestReferentialIntegrity(unittest.TestCase):
    """Test 3: Validação de integridade referencial (rejeição de arestas com nós inexistentes)."""

    def setUp(self):
        self.normalizer = AttackGraphNormalizer()

    def test_integrity_validation_success_on_clean_graph(self):
        """Verify validate_integrity passes when all endpoints exist."""
        n1 = GraphNode(id="n1", type="SOURCE", name="Source 1")
        n2 = GraphNode(id="n2", type="FINDING", name="Finding 2")
        e1 = GraphEdge(id="e1", type="FLOWS_TO", source_id="n1", target_id="n2")

        self.normalizer.add_node(n1)
        self.normalizer.add_node(n2)
        self.normalizer.add_edge(e1)

        valid, errors = self.normalizer.validate_integrity()
        self.assertTrue(valid)
        self.assertEqual(errors, [])

    def test_integrity_validation_detects_orphan_source(self):
        """Verify validate_integrity detects edge whose source_id does not exist."""
        n2 = GraphNode(id="n2", type="FINDING", name="Finding 2")
        orphan_edge = GraphEdge(id="e_orphan_src", type="FLOWS_TO", source_id="ghost_node", target_id="n2")

        self.normalizer.add_node(n2)
        self.normalizer.add_edge(orphan_edge)

        valid, errors = self.normalizer.validate_integrity()
        self.assertFalse(valid)
        self.assertEqual(len(errors), 1)
        self.assertIn("source ghost_node not found", errors[0])

    def test_integrity_validation_detects_orphan_target(self):
        """Verify validate_integrity detects edge whose target_id does not exist."""
        n1 = GraphNode(id="n1", type="SOURCE", name="Source 1")
        orphan_edge = GraphEdge(id="e_orphan_tgt", type="CALLS", source_id="n1", target_id="ghost_sink")

        self.normalizer.add_node(n1)
        self.normalizer.add_edge(orphan_edge)

        valid, errors = self.normalizer.validate_integrity()
        self.assertFalse(valid)
        self.assertEqual(len(errors), 1)
        self.assertIn("target ghost_sink not found", errors[0])

    def test_strict_mode_rejects_orphan_edges_immediately(self):
        """Verify strict mode raises ValueError immediately on add_edge."""
        strict_normalizer = AttackGraphNormalizer(strict=True)
        orphan_edge = GraphEdge(id="e_strict", type="FLOWS_TO", source_id="node_a", target_id="node_b")

        with self.assertRaises(ValueError) as ctx:
            strict_normalizer.add_edge(orphan_edge)
        self.assertIn("Referential integrity violation", str(ctx.exception))

        # Also verify strict flag passed directly to add_edge
        with self.assertRaises(ValueError):
            self.normalizer.add_edge(orphan_edge, strict=True)

    def test_invalid_node_and_edge_types_rejected_by_dataclass(self):
        """Verify unknown node and edge types are rejected at instantiation."""
        with self.assertRaises(ValueError):
            GraphNode(id="bad_node", type="INVALID_TYPE", name="Bad")

        with self.assertRaises(ValueError):
            GraphEdge(id="bad_edge", type="INVALID_EDGE", source_id="a", target_id="b")

    def test_empty_identifiers_rejected(self):
        """Verify empty id or edge endpoints raise ValueError."""
        with self.assertRaises(ValueError):
            GraphNode(id="", type="FINDING", name="Empty ID")

        with self.assertRaises(ValueError):
            GraphEdge(id="e", type="CALLS", source_id="", target_id="target")

        with self.assertRaises(ValueError):
            GraphEdge(id="e", type="CALLS", source_id="source", target_id="")


class TestExportAndPersistence(unittest.TestCase):
    """Test 4: Exportação JSON-L e persistência em SQLite."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp.name)
        self.normalizer = AttackGraphNormalizer()

        # Seed realistic graph
        self.finding_data = {
            "rule_id": "sqli_test",
            "file": "db.py",
            "line": 50,
            "severity": "HIGH",
            "source": "api_entrypoint",
            "sink": "raw_exec",
            "iac_mitigations": [{"resource_id": "waf-1", "control": "waf_block"}],
        }
        self.normalizer.ingest_harness_finding(self.finding_data)

    def tearDown(self):
        self.tmp.cleanup()

    def test_export_jsonl_format_and_content(self):
        """Verify streaming export to JSON-L creates valid records with all fields."""
        jsonl_path = self.tmp_path / "graph.jsonl"
        exported_count = self.normalizer.export_jsonl(jsonl_path)

        self.assertTrue(jsonl_path.exists())
        lines = jsonl_path.read_text(encoding="utf-8").strip().splitlines()
        self.assertEqual(len(lines), exported_count)
        self.assertEqual(exported_count, len(self.normalizer.nodes) + len(self.normalizer.edges))

        nodes_found = 0
        edges_found = 0
        for line in lines:
            record = json.loads(line)
            self.assertIn("entity", record)
            if record["entity"] == "node":
                nodes_found += 1
                self.assertIn("id", record)
                self.assertIn("type", record)
                self.assertIn("evidence_sha256", record)
            elif record["entity"] == "edge":
                edges_found += 1
                self.assertIn("source_id", record)
                self.assertIn("target_id", record)
                self.assertIn("type", record)

        self.assertEqual(nodes_found, len(self.normalizer.nodes))
        self.assertEqual(edges_found, len(self.normalizer.edges))

    def test_export_jsonl_aborts_on_corrupt_graph(self):
        """Verify export_jsonl raises ValueError if graph has integrity violations."""
        orphan = GraphEdge(id="orphan_edge", type="FLOWS_TO", source_id="unknown_src", target_id="unknown_tgt")
        self.normalizer.add_edge(orphan)

        jsonl_path = self.tmp_path / "corrupt.jsonl"
        with self.assertRaises(ValueError) as ctx:
            self.normalizer.export_jsonl(jsonl_path)
        self.assertIn("Integrity check failed", str(ctx.exception))
        self.assertFalse(jsonl_path.exists())

    def test_persist_sqlite_schema_and_records(self):
        """Verify persistence into SQLite creates tables, indices, and exact rows."""
        db_path = self.tmp_path / "attack.sqlite3"
        nodes_cnt, edges_cnt = self.normalizer.persist_sqlite(db_path)

        self.assertTrue(db_path.exists())
        self.assertEqual(nodes_cnt, len(self.normalizer.nodes))
        self.assertEqual(edges_cnt, len(self.normalizer.edges))

        con = sqlite3.connect(db_path)
        try:
            # Check table existence
            tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
            self.assertIn("attack_nodes", tables)
            self.assertIn("attack_edges", tables)

            # Check index existence
            indices = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='index'").fetchall()}
            self.assertIn("idx_attack_edges_src", indices)
            self.assertIn("idx_attack_edges_tgt", indices)

            # Check counts
            db_node_count = con.execute("SELECT count(*) FROM attack_nodes").fetchone()[0]
            db_edge_count = con.execute("SELECT count(*) FROM attack_edges").fetchone()[0]
            self.assertEqual(db_node_count, len(self.normalizer.nodes))
            self.assertEqual(db_edge_count, len(self.normalizer.edges))

            # Check sample node fidelity
            sample_node = next(iter(self.normalizer.nodes.values()))
            row = con.execute("SELECT id, type, name, evidence_sha256, metadata FROM attack_nodes WHERE id=?", (sample_node.id,)).fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(row[0], sample_node.id)
            self.assertEqual(row[1], sample_node.type)
            self.assertEqual(row[2], sample_node.name)
            self.assertEqual(row[3], sample_node.evidence_sha256)
            self.assertEqual(json.loads(row[4]), sample_node.metadata)
        finally:
            con.close()

    def test_persist_sqlite_idempotency(self):
        """Verify calling persist_sqlite multiple times does not raise primary key collision errors."""
        db_path = self.tmp_path / "idempotent.sqlite3"
        self.normalizer.persist_sqlite(db_path)
        # Second run should replace cleanly
        nodes_cnt, edges_cnt = self.normalizer.persist_sqlite(db_path)
        self.assertEqual(nodes_cnt, len(self.normalizer.nodes))
        self.assertEqual(edges_cnt, len(self.normalizer.edges))

    def test_sqlite_trigger_enforces_foreign_key_integrity(self):
        """Verify SQLite trigger and foreign key reject inserting orphan edges directly."""
        db_path = self.tmp_path / "integrity_test.sqlite3"
        self.normalizer.persist_sqlite(db_path)

        con = sqlite3.connect(db_path)
        con.execute("PRAGMA foreign_keys = ON;")
        try:
            with self.assertRaises(sqlite3.IntegrityError):
                with con:
                    con.execute(
                        "INSERT INTO attack_edges VALUES (?, ?, ?, ?, ?, ?, ?)",
                        ("bad_edge", "FLOWS_TO", "ghost_node_1", "ghost_node_2", 1.0, "sha256", "{}")
                    )
        finally:
            con.close()


class TestCLIIntegration(unittest.TestCase):
    """Test 5: Execução via CLI do script mitr3-graph-normalizer.py."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_cli_ingest_sarif_and_export_both(self):
        """Verify CLI can ingest SARIF, output JSON-L, and persist to SQLite."""
        sarif_file = self.tmp_path / "input.sarif"
        sarif_content = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "Semgrep"}},
                    "results": [
                        {
                            "ruleId": "security.audit.sqli",
                            "level": "error",
                            "message": {"text": "Potential SQL injection"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "backend/db.py"},
                                        "region": {"startLine": 12}
                                    }
                                }
                            ]
                        }
                    ]
                }
            ]
        }
        sarif_file.write_text(json.dumps(sarif_content), encoding="utf-8")

        jsonl_out = self.tmp_path / "out.jsonl"
        sqlite_out = self.tmp_path / "out.sqlite3"

        cmd = [
            sys.executable,
            str(NORMALIZER_PATH),
            str(sarif_file),
            "--jsonl",
            str(jsonl_out),
            "--sqlite",
            str(sqlite_out),
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)

        self.assertEqual(res.returncode, 0, f"CLI error: {res.stderr}")
        self.assertIn("Graph normalized successfully", res.stdout)
        self.assertTrue(jsonl_out.exists())
        self.assertTrue(sqlite_out.exists())

    def test_cli_ingest_harness_findings_report(self):
        """Verify CLI can ingest full harness report containing 'findings' list."""
        report_file = self.tmp_path / "harness_report.json"
        report_data = {
            "version": "1.0.0",
            "harness": "MITR3 AI Vulnerability Harness",
            "findings": [
                {
                    "rule_id": "vuln_rule_1",
                    "file": "app.py",
                    "line": 10,
                    "severity": "CRITICAL",
                    "source": "api_v1_search",
                    "sink": "cursor_exec"
                }
            ]
        }
        report_file.write_text(json.dumps(report_data), encoding="utf-8")
        sqlite_out = self.tmp_path / "harness.sqlite3"

        cmd = [
            sys.executable,
            str(NORMALIZER_PATH),
            str(report_file),
            "--sqlite",
            str(sqlite_out),
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)

        self.assertEqual(res.returncode, 0, f"CLI error: {res.stderr}")
        self.assertIn("Graph normalized successfully: 3 nodes, 2 edges", res.stdout)
        self.assertTrue(sqlite_out.exists())


class TestC2Corrections(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def graph(self):
        graph = AttackGraphNormalizer()
        graph.ingest_harness_finding({"rule_id": "sql", "file": "app.py", "line": 7,
                                      "source": "request", "sink": "execute",
                                      "mitigations": [{"id": "waf", "multiplier": 0.4}]})
        return graph

    def test_shared_sink_is_independent_of_ingestion_order(self):
        records = [{"rule_id": "a", "file": "app.py", "line": 10, "sink": "execute"},
                   {"rule_id": "b", "file": "app.py", "line": 20, "sink": "execute"}]
        graphs = []
        for sequence in (records, list(reversed(records))):
            graph = AttackGraphNormalizer()
            for record in sequence:
                graph.ingest_harness_finding(record)
            graphs.append(graph)
        self.assertEqual(graphs[0].nodes, graphs[1].nodes)
        self.assertEqual(graphs[0].edges, graphs[1].edges)
        self.assertIsNone(graphs[0].nodes["snk:app.py:execute"].line)
        self.assertEqual({n.line for n in graphs[0].nodes.values() if n.type == "FINDING"}, {10, 20})

    def test_conflicting_shared_sink_fails_closed(self):
        graph = self.graph()
        with self.assertRaisesRegex(ValueError, "Conflicting shared endpoint"):
            graph.ingest_harness_finding({"rule_id": "b", "file": "app.py", "sink": "execute", "sink_type": "OTHER"})

    def test_rejects_invalid_multipliers_without_clamping(self):
        for value in (-0.01, 1.01, float("nan"), float("inf"), float("-inf"), "NaN", True):
            with self.subTest(value=value), self.assertRaises(ValueError):
                AttackGraphNormalizer().ingest_harness_finding({"mitigations": [{"id": "x", "multiplier": value}]})
        for value in (0, 1):
            graph = AttackGraphNormalizer()
            graph.ingest_harness_finding({"mitigations": [{"id": "x", "multiplier": value}]})
            self.assertEqual(next(iter(graph.edges.values())).weight, value)
        for value in (-1, 2, float("nan"), True):
            with self.subTest(edge_weight=value), self.assertRaises(ValueError):
                GraphEdge(id="x", type="CALLS", source_id="a", target_id="b", weight=value)

    def test_native_c1_output_stays_unanchored(self):
        from dataclasses import asdict
        spec = importlib.util.spec_from_file_location("c2_harness_contract", BASE / "bin" / "mitr3-vuln-harness.py")
        harness = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = harness
        spec.loader.exec_module(harness)
        (self.root / "app.py").write_text("def handler(value):\n    execute(value)\n", encoding="utf-8")
        candidate = harness.CandidateFinding(id="test", scanner="semgrep", rule_id="sql", file_path="app.py",
                                             line=2, severity="HIGH", message="fixture", sink_pattern="execute(value)")
        record = asdict(harness.evaluate_cluster([candidate], self.root, []))
        self.assertEqual(record["ast_gate"], 1)
        graph = AttackGraphNormalizer()
        graph.ingest_harness_finding(record)
        self.assertEqual({node.type for node in graph.nodes.values()}, {"FINDING"})
        self.assertEqual(graph.edges, {})

    def test_diagnostic_fields_do_not_invent_sink(self):
        graph = AttackGraphNormalizer()
        graph.ingest_harness_finding({"sink_pattern": "execute(value)", "enclosing_function": "handler",
                                      "ast_details": "AST confirmada em handler (chamadas: execute)", "ast_gate": 1})
        self.assertEqual({node.type for node in graph.nodes.values()}, {"FINDING"})

    def test_export_materializes_exact_snapshot_bytes(self):
        import hashlib
        graph = self.graph()
        output = self.root / "graph.jsonl"
        graph.export_jsonl(output)
        for line in output.read_text().splitlines():
            record = json.loads(line)
            path = self.root / record["metadata"]["evidence_artifact"]
            self.assertTrue(path.is_file())
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), record["evidence_sha256"])
            self.assertEqual(record["metadata"]["evidence_kind"], "C2_INPUT_SNAPSHOT")
        first = next(n for n in graph.nodes.values() if n.type == "FINDING")
        self.assertEqual(json.loads((self.root / first.metadata["evidence_artifact"]).read_bytes())["line"], 7)

    def test_physical_input_hash_uses_exact_bytes_and_checks_binding(self):
        import hashlib
        record = {"rule_id": "physical", "file": "app.py"}
        artifact = self.root / "report.json"
        raw = (json.dumps({"findings": [record]}, indent=4) + "\n").encode()
        artifact.write_bytes(raw)
        graph = AttackGraphNormalizer()
        node_id = graph.ingest_harness_finding(record, artifact_path=artifact)
        graph.export_jsonl(self.root / "graph.jsonl")
        node = graph.nodes[node_id]
        self.assertEqual(node.evidence_sha256, hashlib.sha256(raw).hexdigest())
        self.assertEqual(node.metadata["evidence_kind"], "C2_INPUT_ARTIFACT")
        self.assertEqual((self.root / node.metadata["evidence_artifact"]).read_bytes(), raw)
        with self.assertRaisesRegex(ValueError, "does not match"):
            graph.ingest_harness_finding({"rule_id": "different"}, artifact_path=artifact)

    def test_sarif_cli_preserves_raw_artifact_provenance(self):
        import hashlib
        artifact = self.root / "input.sarif"
        raw = b'{"version":"2.1.0", "runs":[{"results":[{"ruleId":"x"}]}]}\n'
        artifact.write_bytes(raw)
        output = self.root / "graph.jsonl"
        result = subprocess.run([sys.executable, str(NORMALIZER_PATH), str(artifact), "--jsonl", str(output)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        node = json.loads(output.read_text())
        self.assertEqual(node["evidence_sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual((self.root / node["metadata"]["evidence_artifact"]).read_bytes(), raw)

    def test_changed_evidence_is_never_overwritten(self):
        graph = self.graph()
        graph.export_jsonl(self.root / "first.jsonl")
        digest = next(iter(graph.evidence_artifacts))
        path = self.root / "evidence" / digest
        path.write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "Evidence artifact changed"):
            graph.export_jsonl(self.root / "second.jsonl")
        self.assertEqual(path.read_bytes(), b"changed")
        self.assertFalse((self.root / "second.jsonl").exists())

    def test_export_refuses_evidence_directory_symlink(self):
        graph = self.graph()
        outside = self.root / "outside"
        outside.mkdir(mode=0o700)
        sentinel = outside / "keep"
        sentinel.write_bytes(b"untouched")
        (self.root / "evidence").symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "Untrusted evidence directory"):
            graph.export_jsonl(self.root / "graph.jsonl")
        self.assertEqual(sentinel.read_bytes(), b"untouched")
        self.assertEqual(sorted(p.name for p in outside.iterdir()), ["keep"])
        self.assertFalse((self.root / "graph.jsonl").exists())

    def test_export_refuses_evidence_file_symlink(self):
        graph = self.graph()
        digest = next(iter(graph.evidence_artifacts))
        outside = self.root / "outside"
        outside.mkdir(mode=0o700)
        sentinel = outside / "keep"
        sentinel.write_bytes(b"untouched")
        evidence = self.root / "evidence"
        evidence.mkdir(mode=0o700)
        (evidence / digest).symlink_to(sentinel)
        with self.assertRaisesRegex(ValueError, "Untrusted evidence artifact"):
            graph.export_jsonl(self.root / "graph.jsonl")
        self.assertEqual(sentinel.read_bytes(), b"untouched")
        self.assertFalse((self.root / "graph.jsonl").exists())

    def test_sqlite_partial_upsert_preserves_unrelated_edges(self):
        graph = self.graph()
        db = self.root / "graph.sqlite3"
        graph.persist_sqlite(db)
        subset = AttackGraphNormalizer()
        subset.ingest_harness_finding({"rule_id": "other", "file": "app.py", "line": 99, "sink": "execute"})
        subset.persist_sqlite(db)
        with sqlite3.connect(db) as con:
            self.assertEqual(con.execute("SELECT count(*) FROM attack_edges").fetchone()[0], len(graph.edges) + 1)
            self.assertEqual(con.execute("PRAGMA foreign_key_check").fetchall(), [])
        for record in subset.nodes.values():
            self.assertTrue((self.root / record.metadata["evidence_artifact"]).is_file())

    def test_sqlite_guards_work_with_foreign_keys_off_and_on(self):
        for fk in (0, 1):
            with self.subTest(foreign_keys=fk):
                db = self.root / f"guards-{fk}.sqlite3"
                graph = self.graph()
                graph.persist_sqlite(db)
                with sqlite3.connect(db) as con:
                    con.execute(f"PRAGMA foreign_keys={fk}")
                    source = next(n.id for n in graph.nodes.values() if n.type == "SOURCE")
                    edge = next(e.id for e in graph.edges.values() if e.type == "CALLS")
                    sink = next(n.id for n in graph.nodes.values() if n.type == "SINK")
                    finding = next(n.id for n in graph.nodes.values() if n.type == "FINDING")
                    invalid = [
                        ("UPDATE attack_edges SET target_id='ghost' WHERE id=?", (edge,)),
                        ("UPDATE attack_edges SET type='FLOWS_TO' WHERE id=?", (edge,)),
                        ("UPDATE attack_edges SET weight=1.1 WHERE id=?", (edge,)),
                        ("UPDATE attack_nodes SET id='renamed' WHERE id=?", (source,)),
                        ("UPDATE attack_nodes SET type='SINK' WHERE id=?", (source,)),
                        ("DELETE FROM attack_nodes WHERE id=?", (source,)),
                        ("DELETE FROM attack_nodes WHERE id=?", (sink,)),
                        ("INSERT INTO attack_edges VALUES ('bad-weight','CALLS',?,?,-0.1,?,'{}')", (finding, sink, "a" * 64)),
                        ("UPDATE attack_edges SET metadata='not-json' WHERE id=?", (edge,)),
                        ("INSERT INTO attack_edges VALUES ('bad','CALLS','ghost','ghost',1,?,'{}')", ("a" * 64,)),
                        ("UPDATE attack_nodes SET evidence_sha256='bad' WHERE id=?", (source,)),
                    ]
                    for sql, args in invalid:
                        with self.subTest(sql=sql), self.assertRaises(sqlite3.IntegrityError):
                            con.execute(sql, args)
                    con.execute("UPDATE attack_edges SET weight=0.7 WHERE id=?", (edge,))
                    con.execute("UPDATE attack_nodes SET name='new name' WHERE id=?", (source,))
                    con.execute("DELETE FROM attack_edges WHERE source_id=? OR target_id=?", (source, source))
                    con.execute("DELETE FROM attack_nodes WHERE id=?", (source,))
                    self.assertEqual(con.execute("PRAGMA foreign_key_check").fetchall(), [])

    def test_sqlite_failure_rolls_back_node_updates(self):
        from dataclasses import replace
        graph = self.graph()
        db = self.root / "rollback.sqlite3"
        graph.persist_sqlite(db)
        finding = next(n for n in graph.nodes.values() if n.type == "FINDING")
        graph.nodes[finding.id] = replace(finding, severity="CRITICAL")
        source = next(n.id for n in graph.nodes.values() if n.type == "SOURCE")
        graph.add_edge(GraphEdge(id="bad-shape", type="CALLS", source_id=source, target_id=finding.id,
                                 evidence_sha256=finding.evidence_sha256))
        with self.assertRaises(sqlite3.IntegrityError):
            graph.persist_sqlite(db)
        with sqlite3.connect(db) as con:
            self.assertEqual(con.execute("SELECT severity FROM attack_nodes WHERE id=?", (finding.id,)).fetchone()[0], finding.severity)
            self.assertEqual(con.execute("SELECT count(*) FROM attack_edges WHERE id='bad-shape'").fetchone()[0], 0)

    def test_manual_digest_without_artifact_cannot_be_exported(self):
        graph = AttackGraphNormalizer()
        graph.add_node(GraphNode(id="manual", type="FINDING", name="manual", evidence_sha256="a" * 64))
        with self.assertRaisesRegex(ValueError, "No physical input snapshot"):
            graph.export_jsonl(self.root / "missing.jsonl")
        self.assertFalse((self.root / "missing.jsonl").exists())

    def test_sqlite_rejects_legacy_database_without_migrating(self):
        db = self.root / "legacy.sqlite3"
        with sqlite3.connect(db) as con:
            con.execute("CREATE TABLE attack_nodes (id TEXT PRIMARY KEY)")
            con.execute("INSERT INTO attack_nodes VALUES ('preserve')")
        before = db.read_bytes()
        with self.assertRaisesRegex(ValueError, "without C2 schema version"):
            self.graph().persist_sqlite(db)
        self.assertEqual(db.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
