"""ATT&CK graph provenance, endpoint integrity and offline/memory boundaries."""
from contextlib import closing
import copy
import datetime as dt
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest import mock
import uuid

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("attack_graph_tests", ROOT / "bin/mitr3-attack-graph.py")
graph = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(graph)
STAMP = "2026-10-01T00:00:00.000Z"


def obj(kind, label, **fields):
    return {"type": kind, "id": kind + "--" + str(uuid.uuid5(uuid.NAMESPACE_URL, kind + label)),
            "name": label, "modified": STAMP, **fields}


def relationship(label, kind, source, target, **fields):
    return obj("relationship", label, relationship_type=kind,
               source_ref=source["id"], target_ref=target["id"], **fields)


def fixture():
    technique = obj("attack-pattern", "Shared text", external_references=[
        {"source_name": "mitre-attack", "external_id": "T1000"},
        {"source_name": "capec", "external_id": "CAPEC-100"}])
    sub = obj("attack-pattern", "Subtechnique")
    malware = obj("malware", "Shared text")  # co-occurrence/name is not a link
    tool = obj("tool", "Test tool")
    group = obj("intrusion-set", "Test group")
    campaign = obj("campaign", "Test campaign")
    mitigation = obj("course-of-action", "Test mitigation")
    revoked = obj("malware", "Revoked malware", revoked=True)
    deprecated = obj("tool", "Deprecated tool", x_mitre_deprecated=True)
    identity = obj("identity", "Not an entity")
    edges = [relationship("uses", "uses", malware, technique),
             relationship("tool uses", "uses", tool, technique),
             relationship("mitigates", "mitigates", mitigation, technique),
             relationship("sub", "subtechnique-of", sub, technique),
             relationship("attribution", "attributed-to", campaign, group),
             relationship("detect", "detects", tool, technique),
             relationship("revoke", "revoked-by", revoked, malware),
             relationship("inactive", "uses", revoked, technique),
             relationship("missing", "uses", tool, obj("malware", "Absent")),
             relationship("deprecated edge", "uses", tool, technique, x_mitre_deprecated=True)]
    return {"type": "bundle", "id": "bundle--" + str(uuid.uuid4()), "objects":
            [technique, sub, malware, tool, group, campaign, mitigation, revoked, deprecated, identity] + edges}


class GraphTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        self.patch = mock.patch.multiple(graph, CACHE=base / "feed.json", MANIFEST=base / "manifest.json", DB=base / "graph.sqlite3")
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.bundle = fixture()
        raw = json.dumps(self.bundle).encode()
        graph.CACHE.write_bytes(raw)
        self.metadata = {"source_id": graph.SOURCE, "url": graph.URL, "sha256": hashlib.sha256(raw).hexdigest(),
                         "bytes": len(raw), "checked_at": graph.now()}
        graph.MANIFEST.write_text(json.dumps(self.metadata))
        graph.build()

    def logical_rows(self):
        with closing(graph.connect()) as con:
            return {table: con.execute("SELECT * FROM " + table + " ORDER BY stix_id").fetchall()
                    for table in ("entities", "edges")}

    def test_counts_revoked_and_no_orphans(self):
        stats = graph.stats()
        self.assertEqual(stats["entities"], 7)
        self.assertEqual(stats["edges_by_type"], {"uses": 2, "mitigates": 1, "subtechnique-of": 1, "attributed-to": 1})
        with closing(graph.connect()) as con:
            self.assertEqual(con.execute("PRAGMA foreign_key_check").fetchall(), [])
            entities = {r[0] for r in con.execute("SELECT stix_id FROM entities")}
        self.assertTrue(all(o["id"] not in entities for o in self.bundle["objects"] if not graph.active(o)))

    def test_every_edge_matches_a_real_relationship_exactly(self):
        entities = {o["id"] for o in self.bundle["objects"] if o["type"] in graph.ENTITY_TYPES and graph.active(o)}
        expected = {(o["id"], o["relationship_type"], o["source_ref"], o["target_ref"], o["modified"], self.metadata["sha256"])
                    for o in self.bundle["objects"] if o["type"] == "relationship"
                    and o["relationship_type"] in graph.EDGE_TYPES and graph.active(o)
                    and o["source_ref"] in entities and o["target_ref"] in entities}
        self.assertEqual(set(self.logical_rows()["edges"]), expected)
        # Equal names alone cannot create a second invented technique/malware edge.
        self.assertEqual(len(expected), 5)

    def test_insert_and_update_reject_missing_endpoint_even_without_fk_pragma(self):
        with closing(sqlite3.connect(graph.DB)) as con, con:
            row = con.execute("SELECT * FROM edges LIMIT 1").fetchone()
            for index in (2, 3):
                broken = list(row)
                broken[0] = "relationship--" + str(uuid.uuid4())
                broken[index] = "malware--" + str(uuid.uuid4())
                with self.assertRaisesRegex(sqlite3.IntegrityError, "Missing STIX endpoint"):
                    con.execute("INSERT INTO edges VALUES(?,?,?,?,?,?)", broken)
                with self.assertRaisesRegex(sqlite3.IntegrityError, "Missing STIX endpoint"):
                    con.execute("UPDATE edges SET " + ("source_ref" if index == 2 else "target_ref") + "=? WHERE stix_id=?",
                                (broken[index], row[0]))

    def test_rebuild_idempotent_and_duplicate_failure_preserves_graph(self):
        before = self.logical_rows()
        graph.build()
        self.assertEqual(self.logical_rows(), before)
        broken = copy.deepcopy(self.bundle)
        broken["objects"].append(broken["objects"][0])
        with self.assertRaisesRegex(ValueError, "Duplicate STIX"):
            graph.build(broken, self.metadata)
        self.assertEqual(self.logical_rows(), before)

    def test_query_exact_name_id_directions_and_unknown(self):
        by_id = graph.query("T1000", limit=2)
        technique = self.bundle["objects"][0]
        self.assertEqual(by_id["entities"][0]["name"], "Shared text")
        self.assertEqual(graph.query(technique["id"])["entities"], by_id["entities"])
        self.assertEqual(len(graph.query("shared TEXT")["entities"]), 2)  # no guessing an ambiguous name
        self.assertGreater(by_id["counts"]["inbound"], len(by_id["inbound"]))
        self.assertEqual(len(by_id["inbound"]), 2)
        for edge in by_id["inbound"]:
            self.assertEqual(edge["origin"]["bundle_sha256"], self.metadata["sha256"])
            self.assertEqual(edge["origin"]["url"], graph.URL)
            self.assertEqual(edge["origin"]["modified"], STAMP)
        for identifier in ("unknown", "CVE-2023-23397", "CWE-79", "CAPEC-100"):
            result = graph.query(identifier)
            self.assertEqual((result["entities"], result["outbound"], result["inbound"]), ([], [], []))

    def test_cache_hash_mismatch_fails_closed(self):
        original = graph.DB.read_bytes()
        graph.CACHE.write_bytes(graph.CACHE.read_bytes() + b" ")
        with self.assertRaisesRegex(ValueError, "changed or corrupted"):
            graph.build()
        self.assertEqual(graph.DB.read_bytes(), original)

    def test_monthly_cache_does_not_fetch_again_and_boundary_is_calendar_month(self):
        with mock.patch.object(graph.urllib.request, "build_opener", side_effect=AssertionError("unexpected network")):
            bundle, metadata = graph.sync_bundle()
        self.assertEqual(bundle, self.bundle)
        self.assertEqual(metadata, self.metadata)
        self.assertFalse(graph.due_this_month(self.metadata))
        self.assertTrue(graph.due_this_month({"checked_at": "2020-01-01T00:00:00+00:00"}))
        self.assertTrue(graph.due_this_month({"checked_at": "invalid"}))
        self.assertTrue(graph.due_this_month({"checked_at": "2026-01-01"}))

    def test_download_fixed_host_size_cap_and_manifest(self):
        self.metadata["checked_at"] = "2020-01-01T00:00:00+00:00"
        graph.MANIFEST.write_text(json.dumps(self.metadata))
        raw = graph.CACHE.read_bytes()
        def response(url=graph.URL):
            stream = io.BytesIO(raw)
            stream.geturl = lambda: url
            return stream
        opener = mock.Mock()
        opener.open.return_value = response()
        with mock.patch.object(graph.urllib.request, "build_opener", return_value=opener):
            _, manifest = graph.sync_bundle()
        self.assertEqual(opener.open.call_args.args[0].full_url, graph.URL)
        self.assertEqual(manifest["sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(manifest["bytes"], len(raw))
        # Oversize refresh cannot replace the prior, valid cache/manifest.
        graph.MANIFEST.write_text(json.dumps(self.metadata))
        opener.open.return_value = response()
        with mock.patch.object(graph.urllib.request, "build_opener", return_value=opener):
            with mock.patch.object(graph, "MAX_SIZE", len(raw) - 1):
                with self.assertRaisesRegex(ValueError, "over size limit"):
                    graph.sync_bundle()
        self.assertEqual(graph.CACHE.read_bytes(), raw)
        self.assertEqual(json.loads(graph.MANIFEST.read_text()), self.metadata)
        for bad in ("http://raw.githubusercontent.com/file", "https://example.org/file",
                    "https://raw.githubusercontent.com:8443/file", "https://user@raw.githubusercontent.com/file"):
            with self.subTest(url=bad):
                with self.assertRaises(ValueError):
                    graph.pinned_url(bad)
        with self.assertRaises(ValueError):
            graph.PinnedRedirect().redirect_request(None, None, 302, "", {}, "https://example.org/file")


@unittest.skipUnless(graph.CACHE.exists() and graph.MANIFEST.exists(), "Offline ATT&CK cache absent: run graph-refresh")
class CachedAttackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bundle, cls.metadata = graph.load_cached()
        cls.temp = tempfile.TemporaryDirectory()
        cls.patch = mock.patch.object(graph, "DB", Path(cls.temp.name) / "graph.sqlite3")
        cls.patch.start()
        cls.addClassCleanup(cls.patch.stop)
        cls.addClassCleanup(cls.temp.cleanup)
        graph.build(cls.bundle, cls.metadata)

    @classmethod
    def tearDownClass(cls):
        del cls.bundle

    def test_real_counts_by_type_with_release_tolerance(self):
        stats = graph.stats()
        expected_entities = {"attack-pattern": 706, "malware": 747, "tool": 95,
                             "intrusion-set": 178, "campaign": 57, "course-of-action": 44}
        expected_edges = {"uses": 18975, "mitigates": 1477, "subtechnique-of": 479, "attributed-to": 26}
        self.assertEqual(set(stats["entities_by_type"]), set(expected_entities))
        self.assertEqual(set(stats["edges_by_type"]), set(expected_edges))
        for expected, actual in ((expected_entities, stats["entities_by_type"]), (expected_edges, stats["edges_by_type"])):
            for kind, count in expected.items():
                with self.subTest(type=kind):
                    self.assertLessEqual(abs(actual[kind] - count), max(5, count * 0.25))

    def test_real_graph_exactly_equals_active_stix_relationships(self):
        # Independent raw declaration set, not edges obtained from the importer.
        entities = {o["id"] for o in self.bundle["objects"] if o["type"] in
                    {"attack-pattern", "malware", "tool", "intrusion-set", "campaign", "course-of-action"}
                    and not o.get("revoked") and not o.get("x_mitre_deprecated")}
        expected = {(o["id"], o["relationship_type"], o["source_ref"], o["target_ref"], o["modified"], self.metadata["sha256"])
                    for o in self.bundle["objects"] if o["type"] == "relationship"
                    and o["relationship_type"] in {"uses", "mitigates", "subtechnique-of", "attributed-to"}
                    and not o.get("revoked") and not o.get("x_mitre_deprecated")
                    and o["source_ref"] in entities and o["target_ref"] in entities}
        with closing(graph.connect()) as con:
            self.assertEqual({r[0] for r in con.execute("SELECT stix_id FROM entities")}, entities)
            self.assertEqual(set(con.execute("SELECT * FROM edges")), expected)
            self.assertEqual(con.execute("PRAGMA foreign_key_check").fetchall(), [])
            before = con.execute("SELECT * FROM edges ORDER BY stix_id").fetchall()
        graph.build(self.bundle, self.metadata)
        with closing(graph.connect()) as con:
            self.assertEqual(con.execute("SELECT * FROM edges ORDER BY stix_id").fetchall(), before)

    def test_reference_audit_has_no_cve_cwe_bridge(self):
        refs = [r for o in self.bundle["objects"] for r in o.get("external_references", [])]
        for prefix in ("CVE", "CWE"):
            self.assertFalse(any(str(r.get("source_name", "")).casefold() == prefix.casefold()
                                 or str(r.get("external_id", "")).upper().startswith(prefix + "-") for r in refs))
        capec = sum(r.get("source_name", "").casefold() == "capec" for r in refs)
        self.assertGreater(capec, 0)
        self.assertLessEqual(capec, 60)  # 36 in the measured bundle; no CAPEC edges imported


if __name__ == "__main__":
    unittest.main()
