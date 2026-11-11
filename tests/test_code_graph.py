"""Layer 3 (code/attack-chain graph): ingest contract with Layer 2, schema guards, hashes, STIX separation.

Only new behaviour is tested here. Layer 1 and Layer 2 suites are not repeated; Layer 2 is used as the
real producer of the JSON-L so the Layer 2 -> Layer 3 contract is exercised on its true output.
"""
from contextlib import closing
import hashlib
import importlib.util
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import uuid

ROOT = Path(__file__).resolve().parents[1]


def load_module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "bin" / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


normalizer = load_module("l3_normalizer", "mitr3-graph-normalizer.py")
code = load_module("l3_code_graph", "mitr3-code-graph.py")
attack = load_module("l3_attack_graph", "mitr3-attack-graph.py")
STAMP = "2026-10-01T00:00:00.000Z"
CLI = ROOT / "bin" / "mitr3-code-graph.py"


def finding(**over):
    base = {"rule_id": "sqli", "file": "app/users.py", "line": 42, "severity": "high", "confidence": "high",
            "source_entrypoint": "GET /api/v1/user/search", "sink_function": "sqlite3.execute",
            "mitigations": [{"resource_id": "sg-09a1c807", "control": "ingress_deny", "multiplier": 0.5}],
            "attack_technique": "T1190"}
    base.update(over)
    return base


def export(directory, name, *findings):
    graph = normalizer.AttackGraphNormalizer()
    for item in findings:
        graph.ingest_harness_finding(item)
    path = Path(directory) / name
    graph.export_jsonl(path)
    return path


def rows(db, sql, *params):
    with closing(sqlite3.connect(db)) as con:  # foreign_keys deliberately left at SQLite's default (off)
        return con.execute(sql, params).fetchall()


class Base(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.dir = Path(self.temp.name)
        self.db = self.dir / "graph.sqlite3"
        self.export = export(self.dir, "one.jsonl", finding())


class IngestContractTests(Base):
    def test_real_layer2_export_lands_with_exact_counts(self):
        result = code.ingest([self.export], self.db)
        self.assertEqual(result["nodes"], {"inserted": 5, "updated": 0, "unchanged": 0})
        self.assertEqual(result["edges"], {"inserted": 4, "updated": 0, "unchanged": 0})
        stats = code.stats(self.db)
        self.assertEqual(stats["nodes_by_type"], {"ATTACK_TECHNIQUE": 1, "FINDING": 1, "MITIGATION": 1, "SINK": 1, "SOURCE": 1})
        self.assertEqual(stats["edges_by_type"], {"CALLS": 1, "FLOWS_TO": 1, "MAPS_TO": 1, "MITIGATED_BY": 1})
        self.assertEqual(stats["edges_by_verification_state"], {"STRUCTURAL_HYPOTHESIS": 4})
        self.assertEqual(stats["orphan_edges"], 0)

    def test_reingest_is_idempotent_and_snapshot_is_stable(self):
        first = code.ingest([self.export], self.db)
        second = code.ingest([self.export], self.db)
        self.assertEqual(second["nodes"], {"inserted": 0, "updated": 0, "unchanged": 5})
        self.assertEqual(second["edges"], {"inserted": 0, "updated": 0, "unchanged": 4})
        self.assertEqual(first["snapshot_sha256"], second["snapshot_sha256"])
        self.assertEqual(code.stats(self.db)["snapshots"], 1)
        self.assertEqual(code.stats(self.db)["revisions"], 0)

    def test_snapshot_is_independent_of_input_order_and_database(self):
        a = export(self.dir, "a.jsonl", finding())
        b = export(self.dir, "b.jsonl", finding(rule_id="xss", file="app/page.py", line=7, sink_function="render", mitigations=[], attack_technique=None))
        one, other = self.dir / "one.sqlite3", self.dir / "other.sqlite3"
        self.assertEqual(code.ingest([a, b], one)["snapshot_sha256"], code.ingest([b, a], other)["snapshot_sha256"])

    def test_snapshot_changes_when_evidence_changes(self):
        base = code.ingest([self.export], self.db)["snapshot_sha256"]
        changed = export(self.dir, "two.jsonl", finding(severity="critical"))
        self.assertNotEqual(code.ingest([changed], self.db)["snapshot_sha256"], base)

    def test_changed_content_is_revisioned_and_verification_resets(self):
        code.ingest([self.export], self.db)
        with closing(sqlite3.connect(self.db)) as con, con:
            con.execute("UPDATE attack_edges SET verification_state='PROVEN'")
        code.ingest([self.export], self.db)  # unchanged input must not downgrade Layer 4 results
        self.assertEqual(code.stats(self.db)["edges_by_verification_state"], {"PROVEN": 4})
        changed = export(self.dir, "two.jsonl", finding(severity="critical"))
        result = code.ingest([changed], self.db)
        self.assertGreaterEqual(result["nodes"]["updated"], 1)
        self.assertGreaterEqual(result["edges"]["updated"], 1)
        self.assertEqual(code.stats(self.db)["edges_by_verification_state"], {"STRUCTURAL_HYPOTHESIS": 4})
        kinds = {row[0] for row in rows(self.db, "SELECT kind FROM attack_revisions")}
        self.assertEqual(kinds, {"node", "edge"})

    def test_bad_record_aborts_everything_and_creates_nothing(self):
        bad = self.dir / "bad.jsonl"
        bad.write_text(self.export.read_text() + '{"entity":"node","id":"x","type":"BOGUS","name":"n"}\n')
        with self.assertRaisesRegex(ValueError, r"bad\.jsonl:\d+: Invalid node type"):
            code.ingest([bad], self.db)
        self.assertFalse(self.db.exists())

    def test_orphan_edge_rolls_back_all_rows(self):
        lines = [json.loads(l) for l in self.export.read_text().splitlines()]
        orphan = next(r for r in lines if r["entity"] == "edge" and r["type"] == "CALLS")
        orphan["id"], orphan["target_id"] = "edge:calls:orphan", "snk:missing"
        path = self.dir / "orphan.jsonl"
        path.write_text("\n".join(json.dumps(r) for r in lines + [orphan]) + "\n")
        with self.assertRaisesRegex(ValueError, "Orphan edge edge:calls:orphan"):
            code.ingest([path], self.db)
        self.assertEqual(rows(self.db, "SELECT count(*) FROM attack_nodes"), [(0,)])
        self.assertEqual(rows(self.db, "SELECT count(*) FROM attack_edges"), [(0,)])

    def test_wrong_edge_shape_is_rejected_before_writing(self):
        lines = [json.loads(l) for l in self.export.read_text().splitlines()]
        edge = next(r for r in lines if r["entity"] == "edge" and r["type"] == "MITIGATED_BY")
        edge["type"] = "FLOWS_TO"  # FINDING -> MITIGATION is not a FLOWS_TO shape
        path = self.dir / "shape.jsonl"
        path.write_text("\n".join(json.dumps(r) for r in lines) + "\n")
        with self.assertRaisesRegex(ValueError, "must connect SOURCE -> FINDING"):
            code.ingest([path], self.db)
        self.assertEqual(rows(self.db, "SELECT count(*) FROM attack_nodes"), [(0,)])

    def test_field_validation_rejects_unsafe_values(self):
        cases = {
            "weight over 1 (Layer 2 multiplier can exceed it)": ({"entity": "edge", "weight": 1.5}, "weight"),
            "non-hex edge evidence": ({"entity": "edge", "evidence_sha256": "G" * 64}, "evidence_sha256"),
            "missing edge evidence": ({"entity": "edge", "evidence_sha256": ""}, "evidence_sha256"),
        }
        base = [json.loads(l) for l in self.export.read_text().splitlines()]
        edge = next(r for r in base if r["entity"] == "edge")
        for label, (patch, message) in cases.items():
            with self.subTest(label):
                record = dict(edge, **patch)
                path = self.dir / "case.jsonl"
                path.write_text(json.dumps(record) + "\n")
                with self.assertRaisesRegex(ValueError, message):
                    code.load([path])
        for text_value in ('{"entity":"node","id":"n","type":"SOURCE","name":"n","evidence_sha256":"' + "a" * 64 + '","line":0}',
                           '{"entity":"node","id":"T1","type":"ATTACK_TECHNIQUE","name":"n"}',
                           '{"entity":"node","id":"s","type":"SOURCE","name":"n","evidence_sha256":""}',
                           '{"entity":"node","id":"s","type":"SOURCE","name":"n","evidence_sha256":"' + "a" * 64 + '","metadata":{"x":NaN}}'):
            with self.subTest(text_value):
                path = self.dir / "node.jsonl"
                path.write_text(text_value + "\n")
                with self.assertRaises(ValueError):
                    code.load([path])

    def test_conflicting_duplicate_across_inputs_is_rejected(self):
        other = export(self.dir, "two.jsonl", finding(severity="critical"))
        with self.assertRaisesRegex(ValueError, "Conflicting duplicate id"):
            code.load([self.export, other])

    def test_shared_sink_with_different_lines_fails_closed(self):
        """Layer 2 stores the finding's line on the shared SINK node, so one sink hit by two findings in a
        file has order-dependent content. Layer 3 must refuse it rather than pick a winner."""
        other = export(self.dir, "two.jsonl", finding(rule_id="rce", line=9))
        with self.assertRaisesRegex(ValueError, "Conflicting duplicate id snk:app_users.py:sqlite3.execute"):
            code.load([self.export, other])

    def test_foreign_unmarked_tables_are_never_reused(self):
        graph = normalizer.AttackGraphNormalizer()
        graph.ingest_harness_finding(finding())
        graph.persist_sqlite(self.db)  # Layer 2's own weaker schema, no Layer 3 marker
        with self.assertRaisesRegex(ValueError, "without a Layer 3 marker"):
            code.ingest([self.export], self.db)


class SchemaGuardTests(Base):
    def setUp(self):
        super().setUp()
        code.ingest([self.export], self.db)
        self.source = rows(self.db, "SELECT id FROM attack_nodes WHERE type='SOURCE'")[0][0]
        self.sink = rows(self.db, "SELECT id FROM attack_nodes WHERE type='SINK'")[0][0]
        self.finding = rows(self.db, "SELECT id FROM attack_nodes WHERE type='FINDING'")[0][0]

    def insert_edge(self, kind, source, target, edge_id="edge:test"):
        with closing(sqlite3.connect(self.db)) as con, con:
            con.execute("INSERT INTO attack_edges(id,type,source_id,target_id,weight,content_sha256,evidence_sha256,metadata) "
                        "VALUES(?,?,?,?,1.0,?,?,'{}')", (edge_id, kind, source, target, "a" * 64, "b" * 64))

    def test_edge_shape_and_endpoints_enforced_without_fk_pragma(self):
        with self.assertRaisesRegex(sqlite3.IntegrityError, "Invalid or missing graph edge endpoint"):
            self.insert_edge("CALLS", self.source, self.sink)  # SOURCE -> SINK skips the finding
        with self.assertRaisesRegex(sqlite3.IntegrityError, "Invalid or missing graph edge endpoint"):
            self.insert_edge("CALLS", self.finding, "snk:missing")
        with self.assertRaisesRegex(sqlite3.IntegrityError, "Invalid or missing graph edge endpoint"):
            with closing(sqlite3.connect(self.db)) as con, con:
                con.execute("UPDATE attack_edges SET target_id='snk:missing' WHERE type='CALLS'")

    def test_node_delete_and_identity_guards(self):
        with closing(sqlite3.connect(self.db)) as con:
            with self.assertRaisesRegex(sqlite3.IntegrityError, "Node still referenced"):
                con.execute("DELETE FROM attack_nodes WHERE id=?", (self.finding,))
            with self.assertRaisesRegex(sqlite3.IntegrityError, "Node identity is immutable"):
                con.execute("UPDATE attack_nodes SET type='SINK' WHERE id=?", (self.finding,))
            with self.assertRaisesRegex(sqlite3.IntegrityError, "Node identity is immutable"):
                con.execute("UPDATE attack_nodes SET id='renamed' WHERE id=?", (self.finding,))

    def test_hash_and_range_checks_are_in_the_database(self):
        with closing(sqlite3.connect(self.db)) as con:
            with self.assertRaises(sqlite3.IntegrityError):
                con.execute("UPDATE attack_nodes SET evidence_sha256='nothex' WHERE id=?", (self.finding,))
            with self.assertRaises(sqlite3.IntegrityError):
                con.execute("UPDATE attack_edges SET weight=2 WHERE type='CALLS'")
            with self.assertRaises(sqlite3.IntegrityError):
                con.execute("UPDATE attack_edges SET verification_state='TRUE_POSITIVE' WHERE type='CALLS'")


def stix_id(kind, label):
    return kind + "--" + str(uuid.uuid5(uuid.NAMESPACE_URL, kind + label))


def stix_bundle():
    technique = {"type": "attack-pattern", "id": stix_id("attack-pattern", "T1190"), "name": "Exploit Public-Facing Application",
                 "modified": STAMP, "external_references": [{"source_name": "mitre-attack", "external_id": "T1190"}]}
    malware = {"type": "malware", "id": stix_id("malware", "m"), "name": "Sample", "modified": STAMP}
    uses = {"type": "relationship", "id": stix_id("relationship", "uses"), "relationship_type": "uses",
            "source_ref": malware["id"], "target_ref": technique["id"], "modified": STAMP}
    return {"type": "bundle", "id": stix_id("bundle", "b"), "objects": [technique, malware, uses]}


def stix_snapshot(db):
    return {table: rows(db, "SELECT * FROM %s ORDER BY 1" % table) for table in ("entities", "edges", "metadata")}


class StixSeparationTests(Base):
    def build_stix(self):
        """Real ATT&CK build into the same file Layer 3 will use."""
        patcher = mock.patch.multiple(attack, DB=self.db, CACHE=self.dir / "feed.json", MANIFEST=self.dir / "manifest.json")
        patcher.start()
        self.addCleanup(patcher.stop)
        bundle = stix_bundle()
        sha = hashlib.sha256(json.dumps(bundle).encode()).hexdigest()
        return bundle, {"source_id": attack.SOURCE, "url": attack.URL, "sha256": sha, "bytes": 1, "checked_at": attack.now()}

    def test_techniques_link_to_stix_without_touching_stix_tables(self):
        bundle, metadata = self.build_stix()
        attack.build(bundle, metadata)
        before = stix_snapshot(self.db)
        other = export(self.dir, "two.jsonl", finding(rule_id="rce", line=9, sink_function="os.system", attack_technique="T9999"))
        result = code.ingest([self.export, other], self.db)
        self.assertEqual(result["techniques"], {"RESOLVED": 1, "UNRESOLVED": 1})
        links = dict(rows(self.db, "SELECT node_id,status FROM technique_links"))
        self.assertEqual(links, {"T1190": "RESOLVED", "T9999": "UNRESOLVED"})
        self.assertEqual(rows(self.db, "SELECT stix_id,bundle_sha256 FROM technique_links WHERE node_id='T1190'"),
                         [(stix_id("attack-pattern", "T1190"), metadata["sha256"])])
        self.assertEqual(stix_snapshot(self.db), before)
        self.assertEqual(rows(self.db, "SELECT count(*) FROM attack_nodes WHERE id IN (SELECT stix_id FROM entities)"), [(0,)])

    def test_relink_picks_up_stix_loaded_later(self):
        code.ingest([self.export], self.db)
        self.assertEqual(code.stats(self.db)["technique_links"], {"UNRESOLVED": 1})
        bundle, metadata = self.build_stix()
        with mock.patch.object(attack, "carry_code_graph", wraps=attack.carry_code_graph):
            attack.build(bundle, metadata)  # also proves the rebuild kept the Layer 3 rows
        self.assertEqual(code.relink(self.db), {"techniques": {"RESOLVED": 1, "UNRESOLVED": 0}})

    def test_attack_rebuild_preserves_layer3_rows_triggers_and_snapshot(self):
        bundle, metadata = self.build_stix()
        attack.build(bundle, metadata)
        code.ingest([self.export], self.db)
        with closing(sqlite3.connect(self.db)) as con, con:
            con.execute("UPDATE attack_edges SET verification_state='FEASIBLE_PATH' WHERE type='CALLS'")
        before = code.stats(self.db)
        names = lambda: rows(self.db, "SELECT type,name FROM sqlite_master WHERE tbl_name IN %s ORDER BY type,name" % (code.LAYER3_TABLES,))
        schema_before = names()
        report = attack.build(bundle, metadata)
        self.assertEqual(report["code_graph_carried"]["attack_nodes"], 5)
        self.assertEqual(report["code_graph_carried"]["attack_edges"], 4)
        self.assertEqual(code.stats(self.db), before)
        self.assertEqual(names(), schema_before)
        with closing(sqlite3.connect(self.db)) as con:
            with self.assertRaisesRegex(sqlite3.IntegrityError, "Node still referenced"):
                con.execute("DELETE FROM attack_nodes WHERE type='FINDING'")
        self.assertEqual(rows(self.db, "SELECT count(*) FROM entities"), [(2,)])

    def test_rebuild_without_layer3_reports_nothing_extra(self):
        bundle, metadata = self.build_stix()
        self.assertNotIn("code_graph_carried", attack.build(bundle, metadata))


class PathTests(Base):
    def setUp(self):
        super().setUp()
        self.other = export(self.dir, "two.jsonl", finding(rule_id="xss", file="app/page.py", line=7, sink_function="render",
                                                           source_entrypoint="GET /page", mitigations=[], attack_technique=None))
        orphan = normalizer.AttackGraphNormalizer()
        orphan.ingest_harness_finding({"rule_id": "hardcoded", "file": "app/cfg.py", "line": 3})  # no source, no sink
        self.orphan = self.dir / "orphan.jsonl"
        orphan.export_jsonl(self.orphan)
        code.ingest([self.export, self.other, self.orphan], self.db)

    def test_chains_carry_mitigations_as_annotations_never_pruned(self):
        result = code.paths(self.db)
        self.assertEqual(len(result["chains"]), 2)
        chain = next(c for c in result["chains"] if c["finding"]["id"].startswith("fnd:sqli"))
        self.assertFalse(chain["pruned"])
        self.assertEqual([m["effect"] for m in chain["mitigations"]], ["ANNOTATION_ONLY"])
        self.assertEqual(chain["mitigations"][0]["weight"], 0.5)
        self.assertEqual(chain["verification_state"], "STRUCTURAL_HYPOTHESIS")
        self.assertEqual(chain["techniques"], [{"id": "T1190", "link": "UNRESOLVED"}])
        plain = next(c for c in result["chains"] if c["finding"]["id"].startswith("fnd:xss"))
        self.assertEqual(plain["mitigations"], [])

    def test_findings_without_source_or_sink_are_reported_not_invented(self):
        result = code.paths(self.db)
        self.assertEqual(result["unanchored_findings"], [{"finding": "fnd:hardcoded:app_cfg.py:3", "missing": ["SOURCE", "SINK"]}])
        self.assertEqual(rows(self.db, "SELECT count(*) FROM attack_edges WHERE source_id='fnd:hardcoded:app_cfg.py:3' OR target_id='fnd:hardcoded:app_cfg.py:3'"), [(0,)])

    def test_filters_limit_and_weakest_edge_state(self):
        with closing(sqlite3.connect(self.db)) as con, con:
            con.execute("UPDATE attack_edges SET verification_state='PROVEN' WHERE type='FLOWS_TO'")
            con.execute("UPDATE attack_edges SET verification_state='FEASIBLE_PATH' WHERE type='CALLS'")
        one = code.paths(self.db, source=next(r[0] for r in rows(self.db, "SELECT id FROM attack_nodes WHERE name='GET /page'")))
        self.assertEqual([c["finding"]["id"] for c in one["chains"]], ["fnd:xss:app_page.py:7"])
        self.assertEqual(one["chains"][0]["verification_state"], "FEASIBLE_PATH")
        limited = code.paths(self.db, limit=1)
        self.assertTrue(limited["truncated"])
        self.assertEqual(len(limited["chains"]), 1)

    def test_read_only_connection_cannot_write(self):
        with closing(code.connect_ro(self.db)) as con:
            with self.assertRaises(sqlite3.OperationalError):
                con.execute("DELETE FROM attack_edges")


class CliTests(Base):
    def run_cli(self, *args):
        return subprocess.run([sys.executable, str(CLI), "--db", str(self.db), *map(str, args)], capture_output=True, text=True, timeout=60)

    def test_ingest_stats_paths_json(self):
        ingest = self.run_cli("ingest", self.export)
        self.assertEqual(ingest.returncode, 0, ingest.stderr)
        self.assertEqual(json.loads(ingest.stdout)["nodes"]["inserted"], 5)
        self.assertEqual(json.loads(self.run_cli("stats").stdout)["orphan_edges"], 0)
        self.assertEqual(len(json.loads(self.run_cli("paths").stdout)["chains"]), 1)

    def test_errors_exit_2_without_traceback(self):
        bad = self.dir / "bad.jsonl"
        bad.write_text("not json\n")
        result = self.run_cli("ingest", bad)
        self.assertEqual(result.returncode, 2)
        self.assertIn("Error:", result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertEqual(self.run_cli("stats").returncode, 2)  # database does not exist yet


if __name__ == "__main__":
    unittest.main()
