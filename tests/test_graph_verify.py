"""Layer 4 only: isolated real Layer 3 databases, local artifacts, and CLI subprocesses."""
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

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "bin/mitr3-graph-verify.py"
spec = importlib.util.spec_from_file_location("graph_verify_tests", CLI)
verify = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify)
L3 = verify.L3


class Base(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.db = self.root / "graph.sqlite3"
        self.artifact = self.root / "analysis.txt"
        self.artifact.write_text("offline analysis fixture\n", encoding="utf-8")
        self.input = self.root / "evidence.json"
        self.context = dict(environment="test", flow="HTTP to SQL", identity="anonymous", condition="deny ingress")
        records = []
        for node_id, kind in (("s", "SOURCE"), ("f", "FINDING"), ("k", "SINK"), ("m", "MITIGATION"),
                              ("m2", "MITIGATION"), ("other-s", "SOURCE"), ("other-k", "SINK"), ("other-m", "MITIGATION")):
            meta = {"scanner_count": 3, "agreement_ratio": 1.0, "ast_gate": "PASS"} if kind == "FINDING" else {}
            if node_id == "s":
                meta = {"authenticated": False}
            records.append(dict(entity="node", id=node_id, type=kind, name=node_id,
                                evidence_sha256="a" * 64, metadata=meta))
        for edge_id, kind, src, dst in (("sf", "FLOWS_TO", "s", "f"), ("fk", "CALLS", "f", "k"),
                                        ("fm", "MITIGATED_BY", "f", "m"), ("fm2", "MITIGATED_BY", "f", "m2")):
            records.append(dict(entity="edge", id=edge_id, type=kind, source_id=src, target_id=dst,
                                weight=0.9, evidence_sha256="b" * 64))
        graph = self.root / "graph.jsonl"
        graph.write_text("".join(json.dumps(r) + "\n" for r in records), encoding="utf-8")
        L3.ingest([graph], self.db)
        with closing(L3.connect_rw(self.db)) as con:
            verify.ensure_schema(con)

    def rows(self, sql, params=()):
        with closing(sqlite3.connect(self.db)) as con:
            return con.execute(sql, params).fetchall()

    def raw(self, **over):
        raw = dict(kind="AST_REACHABILITY", finding_id="f", source_id="s", sink_id="k", verdict="REACHABLE",
                   artifact="analysis.txt", analyzer="fixture analyzer", justification="offline fixture", recorded_by="unit-test")
        raw.update(over)
        return raw

    def record(self, **over):
        self.input.write_text(json.dumps(self.raw(**over)), encoding="utf-8")
        return verify.record_evidence(self.input, self.db, self.root)

    def control(self, verdict="BLOCKS", strength=1.0, **over):
        return self.record(**dict(dict(kind="IAC_CONTROL", mitigation_id="m", verdict=verdict,
                                       strength=strength, applies_to=self.context), **over))

    def result(self, **kwargs):
        return verify.verify(self.db, self.root, **kwargs)

    def chain(self):
        return self.result()["chains"][0]

    def metadata(self, node_id, **patch):
        meta = json.loads(self.rows("SELECT metadata FROM attack_nodes WHERE id=?", (node_id,))[0][0])
        meta.update(patch)
        with closing(L3.connect_rw(self.db)) as con:
            con.execute("UPDATE attack_nodes SET metadata=? WHERE id=?", (json.dumps(meta), node_id))

    def cli(self, *args, code=0):
        proc = subprocess.run([sys.executable, str(CLI), "--db", str(self.db), "--evidence-root", str(self.root), *args],
                              capture_output=True, text=True, timeout=15)
        self.assertEqual(proc.returncode, code, proc.stderr)
        return proc


class SchemaTests(Base):
    def test_schema_is_complete_and_idempotent(self):
        with closing(L3.connect_rw(self.db)) as con:
            verify.ensure_schema(con)
            self.assertTrue(set(verify.VERIFY_TABLES) <= L3.table_names(con))
            self.assertEqual(con.execute("SELECT value FROM verify_meta WHERE key='schema_version'").fetchone(), ("1",))
            names = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='trigger'")}
            self.assertTrue({"verification_evidence_scope", "verify_nodes_delete_guard"} <= names)

    def test_uninitialised_foreign_partial_and_unsupported_schemas_are_rejected(self):
        for setup, message in (("", "Layer 3"),
                               ("CREATE TABLE code_graph_meta(key TEXT); CREATE TABLE verification_evidence(x);", "without a Layer 4 marker"),
                               ("CREATE TABLE code_graph_meta(key TEXT); CREATE TABLE verify_meta(key TEXT,value TEXT);", "incomplete")):
            with self.subTest(setup=setup), closing(sqlite3.connect(":memory:")) as con:
                con.executescript(setup)
                with self.assertRaisesRegex(ValueError, message):
                    verify.ensure_schema(con)
        with closing(L3.connect_rw(self.db)) as con:
            con.execute("UPDATE verify_meta SET value='99'")
            with self.assertRaisesRegex(ValueError, "Unsupported"):
                verify.ensure_schema(con)

    def test_read_requires_layer4_and_does_not_initialise_it(self):
        with closing(L3.connect_rw(self.db)) as con:
            for table in reversed(verify.VERIFY_TABLES):
                con.execute("DROP TABLE " + table)
        for call in (lambda: self.result(), lambda: verify.list_evidence(self.db, self.root)):
            with self.assertRaisesRegex(ValueError, "Layer 4 not initialised"):
                call()
        self.assertEqual(self.rows("SELECT name FROM sqlite_master WHERE name='verify_meta'"), [])

    def test_reads_reject_unknown_or_incomplete_schema(self):
        with closing(L3.connect_rw(self.db)) as con:
            con.execute("UPDATE verify_meta SET value='99'")
        for call in (lambda: self.result(), lambda: verify.list_evidence(self.db, self.root)):
            with self.assertRaisesRegex(ValueError, "Unsupported"):
                call()
        with closing(L3.connect_rw(self.db)) as con:
            con.execute("UPDATE verify_meta SET value='1'")
            con.execute("DROP TABLE path_verdicts")
        with self.assertRaisesRegex(ValueError, "incomplete"):
            self.result()

    def test_evidence_revocations_and_verdicts_are_append_only(self):
        eid = self.record()["evidence_id"]
        self.result(write=True)
        verify.revoke_evidence(eid, "retired", "reviewer", self.db)
        # Deliberately use SQLite with foreign_keys off: append-only must still hold.
        for table in ("verification_evidence", "evidence_revocations", "path_verdicts"):
            for sql in ("DELETE FROM " + table, "UPDATE " + table + " SET " +
                        {"verification_evidence": "justification='changed'", "evidence_revocations": "reason='changed'",
                         "path_verdicts": "confidence=0"}[table]):
                with self.subTest(sql=sql), closing(sqlite3.connect(self.db)) as con:
                    with self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
                        con.execute(sql)

    def test_scope_trigger_checks_graph_links(self):
        for patch in (dict(finding_id="s"), dict(source_id="other-s"), dict(sink_id="other-k"),
                      dict(kind="IAC_CONTROL", verdict="REDUCES", strength=0.5, mitigation_id="other-m",
                           applies_to={"environment": "test"})):
            with self.subTest(patch=patch), self.assertRaisesRegex(ValueError, "scope"):
                self.record(**patch)

    def test_database_checks_hashes_and_iac_context(self):
        self.record()
        columns = [r[1] for r in self.rows("PRAGMA table_info(verification_evidence)")]
        original = dict(zip(columns, self.rows("SELECT * FROM verification_evidence")[0]))
        for patch in (dict(evidence_id="z" * 64), dict(artifact_sha256="bad"), dict(verdict="PROVEN"),
                      dict(kind="IAC_CONTROL", mitigation_id="m", verdict="BLOCKS", strength=1.0, applies_to="{}"),
                      dict(strength=0.4), dict(applies_to="not json")):
            values = dict(original, evidence_id="c" * 64, **patch) if "evidence_id" not in patch else dict(original, **patch)
            with self.subTest(patch=patch), closing(L3.connect_rw(self.db)) as con:
                with self.assertRaises(sqlite3.IntegrityError):
                    con.execute("INSERT INTO verification_evidence VALUES(" + ",".join("?" for _ in columns) + ")",
                                [values[c] for c in columns])

    def test_verification_node_delete_guard_survives_edge_removal(self):
        self.record()
        with closing(L3.connect_rw(self.db)) as con:
            con.execute("DELETE FROM attack_edges")
            with self.assertRaisesRegex(sqlite3.IntegrityError, "verification records"):
                con.execute("DELETE FROM attack_nodes WHERE id='f'")


class EvidenceTests(Base):
    def test_record_hash_provenance_and_idempotency(self):
        first = self.record()
        self.assertEqual(first["status"], "recorded")
        self.assertEqual(first["artifact_sha256"], hashlib.sha256(self.artifact.read_bytes()).hexdigest())
        self.assertEqual(len(first["evidence_id"]), 64)
        second = self.record(recorded_by="another reviewer")
        self.assertEqual(second["status"], "already_recorded")
        self.assertEqual(first["evidence_id"], second["evidence_id"])
        item = verify.list_evidence(self.db, self.root)[0]
        self.assertEqual(item["recorded_by"], "unit-test")
        self.assertTrue(item["counts"])
        self.assertEqual(item["artifact_status"], "VERIFIED")

    def test_invalid_records_rejected_without_inserting(self):
        cases = [None, [], {}, self.raw(unexpected="field"), self.raw(kind="bogus"), self.raw(kind=[]),
                 self.raw(verdict={}), self.raw(verdict="BLOCKS"),
                 self.raw(strength=0.1), self.raw(mitigation_id="m"), self.raw(applies_to=[]),
                 self.raw(applies_to={"flow": 1}), self.raw(artifact="missing"), self.raw(analyzer=""),
                 self.raw(recorded_by=""), self.raw(finding_id="missing"),
                 self.raw(kind="IAC_CONTROL", verdict="REDUCES", mitigation_id="m", strength=True),
                 self.raw(kind="IAC_CONTROL", verdict="REDUCES", mitigation_id="m", strength=1.0),
                 self.raw(kind="IAC_CONTROL", verdict="REDUCES", mitigation_id="m", strength=-0.1),
                 self.raw(kind="IAC_CONTROL", verdict="REDUCES", mitigation_id="m", strength=0.4),
                 self.raw(kind="IAC_CONTROL", verdict="BLOCKS", mitigation_id="m", strength=0.9, applies_to=self.context),
                 self.raw(kind="IAC_CONTROL", verdict="BLOCKS", mitigation_id="m", strength=1.0, applies_to={}),
                 self.raw(kind="IAC_CONTROL", verdict="BLOCKS", mitigation_id="m", strength=1.0,
                          applies_to=self.context, source_id=None)]
        for raw in cases:
            with self.subTest(raw=raw):
                self.input.write_text(json.dumps(raw))
                with self.assertRaises(ValueError):
                    verify.record_evidence(self.input, self.db, self.root)
        self.input.write_text('{"strength":NaN}')
        with self.assertRaisesRegex(ValueError, "Non-finite"):
            verify.record_evidence(self.input, self.db, self.root)
        self.assertEqual(self.rows("SELECT count(*) FROM verification_evidence"), [(0,)])

    def test_blocks_requires_each_context_field(self):
        for key in verify.CONTEXT_KEYS:
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, key):
                self.control(applies_to=dict(self.context, **{key: "  "}))

    def test_live_hash_mismatch_and_missing_artifact_do_not_count(self):
        self.record()
        self.artifact.write_text("modified")
        self.assertEqual(verify.list_evidence(self.db, self.root)[0]["artifact_status"], "HASH_MISMATCH")
        self.assertEqual(self.chain()["verification_state"], "STRUCTURAL_HYPOTHESIS")
        self.assertEqual(self.result()["evidence"]["counting"], 0)
        self.artifact.unlink()
        self.assertEqual(self.result()["evidence"]["not_counting"][0]["status"], "MISSING")

    def test_artifact_boundary_git_symlink_and_size_checks(self):
        outside = self.root.parent / "outside-evidence"
        self.assertEqual(verify.check_artifact(self.root, outside)[0], "OUTSIDE_ROOT")
        self.assertEqual(verify.check_artifact(self.root, "../outside-evidence")[0], "OUTSIDE_ROOT")
        self.assertEqual(verify.check_artifact(self.root, ".git/config")[0], "FORBIDDEN_PATH")
        self.assertEqual(verify.check_artifact(self.root, ".")[0], "MISSING")
        link = self.root / "link"
        link.symlink_to(self.root.parent)
        self.assertEqual(verify.check_artifact(self.root, "link/outside-evidence")[0], "OUTSIDE_ROOT")
        with mock.patch.object(verify, "MAX_ARTIFACT_BYTES", 1):
            self.assertEqual(verify.check_artifact(self.root, self.artifact)[0], "TOO_LARGE")

    def test_live_symlink_escape_invalidates_previously_recorded_evidence(self):
        self.record()
        self.artifact.unlink()
        self.artifact.symlink_to(self.root.parent / "outside-evidence")
        item = verify.list_evidence(self.db, self.root)[0]
        self.assertFalse(item["counts"])
        self.assertEqual(item["artifact_status"], "OUTSIDE_ROOT")

    def test_revocation_retains_evidence_and_cannot_be_reversed_by_record(self):
        eid = self.record()["evidence_id"]
        verify.revoke_evidence(eid, "analysis superseded", "reviewer", self.db)
        self.assertEqual(self.record()["status"], "already_recorded")
        item = verify.list_evidence(self.db, self.root)[0]
        self.assertTrue(item["revoked"])
        self.assertFalse(item["counts"])
        self.assertEqual(self.result()["evidence"]["not_counting"], [{"evidence_id": eid, "status": "REVOKED"}])
        self.assertEqual(self.rows("SELECT reason,revoked_by FROM evidence_revocations"), [("analysis superseded", "reviewer")])
        for evidence_id, reason, by in ((eid, "again", "reviewer"), ("d" * 64, "unknown", "reviewer"),
                                        (eid, "", "reviewer"), (eid, "retire", "")):
            with self.subTest(evidence_id=evidence_id, reason=reason, by=by), self.assertRaises(ValueError):
                verify.revoke_evidence(evidence_id, reason, by, self.db)


class EvaluateTests(Base):
    def test_active_claim_alone_does_not_suppress_or_reduce(self):
        chain = self.chain()
        self.assertEqual(chain["outcome"], "ACTIVE")
        self.assertEqual(chain["verification_state"], "STRUCTURAL_HYPOTHESIS")
        self.assertEqual(chain["mitigation_strength"], 0)
        self.assertEqual(chain["confidence"], 0.55)
        self.assertEqual(len(chain["basis"]["iac"]["claimed_only"]), 2)

    def test_reachable_promotes_only_active_to_feasible(self):
        self.record()
        chain = self.chain()
        self.assertEqual(chain["outcome"], "ACTIVE")
        self.assertEqual(chain["verification_state"], "FEASIBLE_PATH")
        self.assertEqual(chain["confidence"], 1.0)
        self.assertEqual(chain["exploitability"], 1.0)
        self.control()
        self.assertEqual(self.chain()["verification_state"], "STRUCTURAL_HYPOTHESIS")

    def test_blocks_suppresses_only_while_artifact_is_live(self):
        self.control()
        chain = self.chain()
        self.assertEqual(chain["outcome"], "SUPPRESSED_BY_IAC")
        self.assertEqual(chain["mitigation_strength"], 1.0)
        self.assertEqual(chain["exploitability"], 0.0)
        self.assertEqual(len(chain["basis"]["iac"]["suppressed_by"]), 1)
        self.artifact.write_text("changed")
        self.assertEqual(self.chain()["outcome"], "ACTIVE")
        self.assertEqual(self.chain()["mitigation_strength"], 0.0)

    def test_blocks_applies_only_to_exact_source_and_sink(self):
        with closing(L3.connect_rw(self.db)) as con:
            for edge_id, kind, src, dst in (("other-sf", "FLOWS_TO", "other-s", "f"),
                                            ("f-other-k", "CALLS", "f", "other-k")):
                con.execute("INSERT INTO attack_edges(id,type,source_id,target_id,weight,content_sha256,evidence_sha256,metadata) "
                            "VALUES(?,?,?,?,1,?,?,'{}')", (edge_id, kind, src, dst, "c" * 64, "d" * 64))
        self.control()
        chains = self.result()["chains"]
        self.assertEqual(len(chains), 4)
        for chain in chains:
            exact = chain["source"]["id"] == "s" and chain["sink"]["id"] == "k"
            with self.subTest(source=chain["source"], sink=chain["sink"]):
                self.assertEqual(chain["outcome"], "SUPPRESSED_BY_IAC" if exact else "ACTIVE")
                self.assertEqual(chain["mitigation_strength"], 1.0 if exact else 0.0)

    def test_ast_gate_accepts_integer_and_string_forms(self):
        for gate, outcome in ((0, "AST_UNREACHABLE"), ("FAIL", "AST_UNREACHABLE"),
                              (1, "ACTIVE"), ("PASS", "ACTIVE"), (None, "ACTIVE")):
            self.metadata("f", ast_gate=gate)
            with self.subTest(gate=gate):
                self.assertEqual(self.chain()["outcome"], outcome)

    def test_unreachable_evidence_and_conflicting_reachability(self):
        self.record(verdict="UNREACHABLE")
        self.assertEqual(self.chain()["outcome"], "AST_UNREACHABLE")
        self.assertEqual(self.chain()["basis"]["ast"]["decided_by"], "EVIDENCE")
        eid = self.record()["evidence_id"]
        self.assertEqual(self.chain()["outcome"], "CONFLICT")
        self.assertEqual(self.chain()["exploitability"], 0.0)
        self.assertEqual(self.chain()["verification_state"], "STRUCTURAL_HYPOTHESIS")
        verify.revoke_evidence(eid, "conflicting analysis retired", "reviewer", self.db)
        self.assertEqual(self.chain()["outcome"], "AST_UNREACHABLE")

    def test_failed_gate_and_reachable_evidence_is_conflict_even_with_blocks(self):
        self.metadata("f", ast_gate=0)
        self.record()
        self.control()
        self.assertEqual(self.chain()["outcome"], "CONFLICT")

    def test_reductions_take_max_per_control_then_combine(self):
        self.record()
        self.control("REDUCES", 0.2)
        self.control("REDUCES", 0.5)
        self.control("REDUCES", 0.4, mitigation_id="m2")
        chain = self.chain()
        self.assertEqual(chain["outcome"], "ACTIVE")
        self.assertEqual(chain["mitigation_strength"], 0.7)
        self.assertEqual(chain["exploitability"], 0.3)
        self.assertEqual(len(chain["basis"]["iac"]["applied"]), 2)

    def test_exposure_filter_and_write_restriction(self):
        for flag, label in ((False, "UNAUTHENTICATED"), (True, "AUTHENTICATED"), (None, "UNKNOWN")):
            self.metadata("s", authenticated=flag)
            with self.subTest(flag=flag):
                self.assertEqual(self.chain()["exposure"], label)
                self.assertEqual(self.result(exposure=label)["summary"]["chains"], 1)
        self.assertEqual(self.result(exposure="unauthenticated")["chains"], [])
        for args in (dict(exposure="bogus"), dict(exposure="unknown", write=True)):
            with self.assertRaises(ValueError):
                self.result(**args)

    def test_unanchored_finding_has_no_invented_path(self):
        with closing(L3.connect_rw(self.db)) as con:
            con.execute("DELETE FROM attack_edges WHERE type='CALLS'")
        result = self.result()
        self.assertEqual(result["chains"], [])
        self.assertEqual(result["unanchored_findings"], [{"finding": "f", "missing": ["SINK"]}])

    def test_read_only_verify_does_not_modify_database(self):
        self.record()
        before = self.db.read_bytes()
        result = self.result()
        self.assertNotIn("_edges", result["chains"][0])
        self.assertEqual(before, self.db.read_bytes())
        self.assertEqual(self.rows("SELECT count(*) FROM path_verdicts"), [(0,)])

    def test_persist_is_idempotent_demotes_revoked_and_never_sets_proven(self):
        eid = self.record()["evidence_id"]
        first = self.result(write=True)
        self.assertEqual(first["written"]["edges_promoted"], 2)
        self.assertEqual(self.result(write=True)["written"]["verdicts_inserted"], 0)
        self.assertEqual(self.rows("SELECT DISTINCT verification_state FROM path_verdicts"), [("FEASIBLE_PATH",)])
        verify.revoke_evidence(eid, "retired", "reviewer", self.db)
        next_result = self.result(write=True)
        self.assertEqual(next_result["written"]["edges_demoted"], 2)
        self.assertEqual(self.rows("SELECT count(*) FROM path_verdicts"), [(2,)])
        self.assertEqual(self.rows("SELECT count(*) FROM attack_edges WHERE verification_state='PROVEN'"), [(0,)])
        self.assertEqual(first["graph_snapshot_sha256"], next_result["graph_snapshot_sha256"])

    def test_existing_proven_edges_are_preserved(self):
        with closing(L3.connect_rw(self.db)) as con:
            con.execute("UPDATE attack_edges SET verification_state='PROVEN' WHERE id='sf'")
        self.record()
        self.result(write=True)
        self.assertEqual(self.rows("SELECT verification_state FROM attack_edges WHERE id='sf'"), [("PROVEN",)])
        self.artifact.unlink()
        self.result(write=True)
        self.assertEqual(self.rows("SELECT verification_state FROM attack_edges WHERE id='sf'"), [("PROVEN",)])

    def test_write_rolls_back_verdicts_and_edges_on_failure(self):
        self.record()
        original = verify.persist

        def fail(con, result):
            original(con, result)
            raise ValueError("injected failure")

        with mock.patch.object(verify, "persist", side_effect=fail), self.assertRaisesRegex(ValueError, "injected"):
            self.result(write=True)
        self.assertEqual(self.rows("SELECT count(*) FROM path_verdicts"), [(0,)])
        self.assertEqual(self.rows("SELECT count(*) FROM attack_edges WHERE verification_state='FEASIBLE_PATH'"), [(0,)])


class RebuildTests(Base):
    def setUp(self):
        super().setUp()
        spec = importlib.util.spec_from_file_location("attack_rebuild_tests", ROOT / "bin/mitr3-attack-graph.py")
        self.attack = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.attack)
        patch = mock.patch.object(self.attack, "DB", self.db)
        patch.start()
        self.addCleanup(patch.stop)
        self.bundle = {"objects": [{"type": "attack-pattern", "id": "attack-pattern--00000000-0000-0000-0000-000000000001",
                                    "name": "fixture", "modified": "2026-11-10T00:00:00Z"}]}
        self.meta = {"sha256": "a" * 64}

    def rebuild(self):
        return self.attack.build(self.bundle, self.meta)

    def assert_refused(self, message):
        before = hashlib.sha256(self.db.read_bytes()).hexdigest()
        with mock.patch.object(self.attack.os, "replace") as replace:
            with self.assertRaisesRegex((ValueError, sqlite3.Error), message):
                self.rebuild()
            replace.assert_not_called()
        self.assertEqual(hashlib.sha256(self.db.read_bytes()).hexdigest(), before)
        self.assertEqual(list(self.root.glob(".attack-*")), [])

    def test_preserves_history_schema_and_snapshot_but_requires_fresh_promotion(self):
        eid = self.record()["evidence_id"]
        self.result(write=True)
        verify.revoke_evidence(eid, "retired", "reviewer", self.db)
        graph = self.root / "graph.jsonl"
        records = [json.loads(line) for line in graph.read_text().splitlines()]
        next(r for r in records if r["id"] == "f")["name"] = "revised finding"
        graph.write_text("".join(json.dumps(r) + "\n" for r in records))
        L3.ingest([graph], self.db)
        self.record(justification="new analysis")
        self.result(write=True)
        with closing(L3.connect_rw(self.db)) as con:
            con.execute("CREATE INDEX evidence_finding ON verification_evidence(finding_id)")
            con.execute("UPDATE attack_edges SET verification_state='PROVEN' WHERE id='fm'")
        tables = (*self.attack.CODE_GRAPH_TABLES, *verify.VERIFY_TABLES)
        before = {t: self.rows("SELECT * FROM " + t + " ORDER BY 1") for t in tables if t != "attack_edges"}
        schema = self.rows("SELECT type,name,tbl_name,sql FROM sqlite_master WHERE tbl_name IN (%s) ORDER BY name" %
                           ",".join("?" * len(tables)), tables)
        snapshot = self.result()["graph_snapshot_sha256"]
        self.assertEqual(len(before["attack_revisions"]), 1)
        self.assertEqual(len(before["graph_snapshots"]), 2)
        for _ in range(2):
            report = self.rebuild()
            self.assertTrue(set(tables) <= report["code_graph_carried"].keys())
            self.assertEqual({t: self.rows("SELECT * FROM " + t + " ORDER BY 1") for t in before}, before)
            self.assertEqual(self.rows("SELECT type,name,tbl_name,sql FROM sqlite_master WHERE tbl_name IN (%s) ORDER BY name" %
                                      ",".join("?" * len(tables)), tables), schema)
            self.assertEqual(self.rows("PRAGMA foreign_key_check"), [])
            self.assertEqual(self.rows("PRAGMA integrity_check"), [("ok",)])
            self.assertEqual(self.rows("SELECT count(*) FROM attack_edges WHERE verification_state='FEASIBLE_PATH'"), [(0,)])
            self.assertEqual(self.rows("SELECT verification_state FROM attack_edges WHERE id='fm'"), [("PROVEN",)])
            self.assertEqual(self.result()["graph_snapshot_sha256"], snapshot)
        with closing(L3.connect_rw(self.db)) as con:
            for table in ("verification_evidence", "evidence_revocations", "path_verdicts"):
                with self.subTest(table=table), self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
                    con.execute("DELETE FROM " + table)
            with self.assertRaisesRegex(sqlite3.IntegrityError, "verification records"):
                con.execute("DELETE FROM attack_nodes WHERE id='other-k' OR id='f'")
        self.assertEqual(self.result(write=True)["written"]["edges_promoted"], 2)
        self.assertEqual(self.rows("SELECT count(*) FROM entities"), [(1,)])

    def test_missing_artifact_does_not_leave_feasible_edges_after_rebuild(self):
        self.record()
        self.result(write=True)
        self.artifact.unlink()
        self.rebuild()
        self.assertEqual(self.rows("SELECT count(*) FROM path_verdicts"), [(1,)])
        self.assertEqual(self.rows("SELECT count(*) FROM attack_edges WHERE verification_state='FEASIBLE_PATH'"), [(0,)])
        self.assertEqual(self.chain()["verification_state"], "STRUCTURAL_HYPOTHESIS")

    def test_incomplete_or_unsupported_schemas_fail_before_replace(self):
        for sql, message in (("UPDATE verify_meta SET value='99'", "unsupported Layer 4"),
                             ("DROP TABLE verify_meta", "incomplete Layer 4"),
                             ("DROP TABLE code_graph_meta", "incomplete Layer 3"),
                             ("DROP TRIGGER verification_evidence_no_delete", "missing Layer 4")):
            with self.subTest(sql=sql):
                original = self.db.read_bytes()
                with closing(sqlite3.connect(self.db)) as con, con:
                    con.execute(sql)
                self.assert_refused(message)
                self.db.write_bytes(original)

    def test_orphan_revocation_fails_before_replace(self):
        with closing(sqlite3.connect(self.db)) as con, con:
            con.execute("INSERT INTO evidence_revocations VALUES(?,?,?,?)", ("d" * 64, "bad", "fixture", "now"))
        self.assert_refused("source database integrity")

    def test_feasible_edges_without_c4_fail_before_replace(self):
        with closing(sqlite3.connect(self.db)) as con, con:
            for (name,) in con.execute("SELECT name FROM sqlite_master WHERE type='trigger' AND (tbl_name IN "
                                      "('verification_evidence','evidence_revocations','path_verdicts') OR name='verify_nodes_delete_guard')").fetchall():
                con.execute("DROP TRIGGER " + name)
            for table in reversed(verify.VERIFY_TABLES):
                con.execute("DROP TABLE " + table)
            con.execute("UPDATE attack_edges SET verification_state='FEASIBLE_PATH' WHERE id='sf'")
        self.assert_refused("FEASIBLE_PATH without Layer 4")

    def test_wal_database_is_refused_before_replace(self):
        with closing(sqlite3.connect(self.db)) as con:
            con.execute("PRAGMA journal_mode=WAL")
        self.assert_refused("WAL database")

    def test_destination_schema_failure_is_explicit_and_preserves_old_database(self):
        with closing(sqlite3.connect(self.db)) as con:
            con.execute("CREATE INDEX entities_external ON verification_evidence(finding_id)")
        self.assert_refused("Unsafe rebuild: index entities_external already exists; old database preserved")

    def test_source_writer_lock_is_held_until_replace(self):
        replace = self.attack.os.replace

        def guarded_replace(source, target):
            with closing(sqlite3.connect(self.db, timeout=0)) as writer:
                with self.assertRaisesRegex(sqlite3.OperationalError, "locked"):
                    writer.execute("BEGIN IMMEDIATE")
            replace(source, target)

        with mock.patch.object(self.attack.os, "replace", side_effect=guarded_replace):
            self.rebuild()


class ConfidenceTests(unittest.TestCase):
    def test_explicit_weights_and_non_probability_bounds(self):
        for meta, reachable, expected in (({}, False, 0.0), ({}, True, 0.45),
                                          ({"scanner_count": 1, "agreement_ratio": 1, "ast_gate": 1}, False, 0.35),
                                          ({"scanner_count": 3, "agreement_ratio": 1, "ast_gate": "PASS"}, True, 1.0),
                                          ({"scanner_count": 99, "agreement_ratio": 1}, False, 0.3),
                                          ({"scanner_count": True, "agreement_ratio": 2, "ast_gate": "FAIL"}, False, 0.0),
                                          ({"agreement_ratio": float("nan")}, False, 0.0)):
            with self.subTest(meta=meta, reachable=reachable):
                score, parts = verify.confidence(meta, reachable)
                self.assertEqual(score, expected)
                self.assertEqual(set(parts), set(verify.CONFIDENCE_WEIGHTS))


class CliTests(Base):
    def test_record_list_verify_and_revoke_round_trip(self):
        self.input.write_text(json.dumps(self.raw()))
        eid = json.loads(self.cli("record", str(self.input)).stdout)["evidence_id"]
        self.assertEqual(json.loads(self.cli("list").stdout)[0]["evidence_id"], eid)
        read = json.loads(self.cli("verify", "--json").stdout)
        self.assertEqual(read["chains"][0]["verification_state"], "FEASIBLE_PATH")
        self.assertNotIn("written", read)
        written = json.loads(self.cli("verify", "--write", "--json").stdout)
        self.assertEqual(written["written"]["edges_promoted"], 2)
        self.assertIn("FEASIBLE_PATH", self.cli("verify").stdout)
        self.assertIn("Written:", self.cli("verify", "--write").stdout)
        self.assertEqual(json.loads(self.cli("verify", "--exposure", "AUTHENTICATED", "--json").stdout)["chains"], [])
        revoked = json.loads(self.cli("revoke", eid, "--reason", "retired", "--by", "reviewer").stdout)
        self.assertEqual(revoked["status"], "revoked")
        self.assertFalse(json.loads(self.cli("list").stdout)[0]["counts"])
        self.assertEqual(json.loads(self.cli("verify", "--json").stdout)["chains"][0]["verification_state"], "STRUCTURAL_HYPOTHESIS")

    def test_errors_have_nonzero_exit_and_no_traceback(self):
        self.input.write_text("{bad json")
        for args in (("record", str(self.input)), ("record", str(self.root / "missing.json")),
                     ("revoke", "d" * 64, "--reason", "unknown", "--by", "reviewer"),
                     ("verify", "--write", "--exposure", "unknown")):
            with self.subTest(args=args):
                proc = self.cli(*args, code=2)
                self.assertTrue(proc.stderr.startswith("Error:"))
                self.assertNotIn("Traceback", proc.stderr)
                self.assertEqual(proc.stdout, "")

    def test_parser_requires_subcommand_revocation_attribution_and_valid_exposure(self):
        for args in ((), ("revoke", "e" * 64), ("revoke", "e" * 64, "--reason", "retire"),
                     ("verify", "--exposure", "public")):
            with self.subTest(args=args):
                self.assertIn("usage:", self.cli(*args, code=2).stderr)
        self.assertIn("offline", self.cli("--help").stdout)

    def test_invalid_json_field_types_are_controlled_errors(self):
        for patch in (dict(kind=[]), dict(verdict={})):
            self.input.write_text(json.dumps(self.raw(**patch)))
            with self.subTest(patch=patch):
                proc = self.cli("record", str(self.input), code=2)
                self.assertIn("Invalid kind/verdict pair", proc.stderr)
                self.assertNotIn("Traceback", proc.stderr)


if __name__ == "__main__":
    unittest.main()
