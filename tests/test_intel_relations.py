"""Source-declared edges, evidence integrity, and no inferred graph links."""
import contextlib
import hashlib
import importlib.util
import io
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("intel_relations", ROOT / "bin/mitr3-rag-intel.py")
intel = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(intel)


def write_json(path, data):
    raw = json.dumps(data).encode()
    path.write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()


class RelationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        self.cache = base / "cache"
        self.cache.mkdir()
        self.source = base / "catalog.json"
        self.db = base / "index.sqlite3"
        self.kev = {"vulnerabilities": [
            {"cveID": f"CVE-2026-{10000+i}", "shortDescription": "CWE-999 is prose only",
             "cwes": ["CWE-79", "CWE-79", "invalid"] if i == 0 else []}
            for i in range(100)]}
        self.asvs = {"Version": "5.0.0", "Requirements": [
            {"Name": "Chapter", "Items": [{"Name": "Section", "Items": [
                {"Shortcode": "V1.1.1", "Description": "Explicit mapping", "CWE": ["CWE-79", "CWE-79", 79]},
                {"Shortcode": "V1.1.2", "Description": "CWE-89 mentioned in prose",
                 "CWE_Mapping": ["CWE-999"]}]}]}] + [{} for _ in range(9)]}
        case = json.loads(intel.SOURCE.read_text())[0]
        self.cases = [dict(case, id="case-a", related=[
            "CVE-2026-10000", "CVE-2026-10000", "ASVS-V1.1.1", "CASE-case-b",
            "CWE-89", "CVE-2099-999999", "not-an-id"]), dict(case, id="case-b", related=[])]
        self.hashes = {
            "cisa-kev": write_json(self.cache / "cisa-kev.json", self.kev),
            "owasp-asvs-5.0.0": write_json(self.cache / "owasp-asvs-5.0.0.json", self.asvs),
            "public-cases": write_json(self.source, self.cases)}
        self.manifest = self.cache / "manifest.json"
        write_json(self.manifest, {name: {"sha256": sha} for name, sha in self.hashes.items()
                                   if name != "public-cases"})
        self.patch = mock.patch.multiple(intel, DB=self.db, CACHE=self.cache,
                                         MANIFEST=self.manifest, SOURCE=self.source)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        with contextlib.redirect_stdout(io.StringIO()):
            intel.create()

    def edges(self):
        with contextlib.closing(sqlite3.connect(self.db)) as con, con:
            return con.execute("SELECT doc_id,target_id,relation,evidence FROM related").fetchall()

    def test_missing_or_invalid_evidence_never_enters(self):
        for evidence in (None, {}, {"source_id": "cisa-kev"},
                         {"source_id": "cisa-kev", "sha256": "no"},
                         {"source_id": "public-cases", "sha256": "a" * 64}):
            with self.subTest(evidence=evidence):
                self.assertEqual(intel.declared_relations(["CWE-79"], "cwe_of", evidence), [])
                with contextlib.closing(sqlite3.connect(self.db)) as con, con:
                    with self.assertRaises(sqlite3.IntegrityError):
                        con.execute("INSERT INTO related VALUES(?,?,?,?)",
                                    ("CVE-2026-10000", "CWE-80", "cwe_of",
                                     json.dumps(evidence) if evidence is not None else None))
        records = intel.gather()
        for row in records:
            for edge in row["relations"]:
                edge.pop("evidence")
        with mock.patch.object(intel, "gather", return_value=records):
            with contextlib.redirect_stdout(io.StringIO()):
                intel.create()
        self.assertEqual(self.edges(), [])  # legacy related[] alone is not evidence
        with contextlib.redirect_stdout(io.StringIO()) as output:
            intel.stats()
        self.assertEqual(json.loads(output.getvalue())["relations_by_type"],
                         {"cwe_of": 0, "asvs_maps_cwe": 0, "case_references": 0})

    def test_dedup_and_counts_by_type(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            intel.stats()
        counts = json.loads(output.getvalue())
        self.assertEqual(counts["relations_by_type"],
                         {"cwe_of": 1, "asvs_maps_cwe": 1, "case_references": 4})
        self.assertEqual(counts["relations"], 6)
        rows = self.edges()
        self.assertEqual(len(rows), len({r[:3] for r in rows}))
        for _, _, relation, evidence in rows:
            evidence = json.loads(evidence)
            self.assertEqual(evidence["source_id"], intel.RELATION_SOURCES[relation])
            self.assertEqual(evidence["sha256"], self.hashes[evidence["source_id"]])

    def test_inbound_outbound_external_cwe_and_unknown(self):
        cve = intel.relations(" cve-2026-10000 ", emit=False)
        self.assertEqual([e["target_id"] for e in cve["outbound"]], ["CWE-79"])
        self.assertEqual([e["doc_id"] for e in cve["inbound"]], ["CASE-case-a"])
        external = intel.relations("CWE-79", emit=False)
        self.assertEqual(external["outbound"], [])
        self.assertEqual({e["doc_id"] for e in external["inbound"]},
                         {"CVE-2026-10000", "ASVS-V1.1.1"})
        for identifier in ("CVE-2099-999999", "ASVS-V99.99.99", "CWE-999", "CASE-absent"):
            result = intel.relations(identifier, emit=False)
            self.assertEqual(result["outbound"], [])
            self.assertEqual(result["inbound"], [])

    def test_exact_declarations_no_transitive_or_self_edges(self):
        # An independent expected set from this fixture, not from the extractor.
        expected = {("CVE-2026-10000", "CWE-79", "cwe_of"),
                    ("ASVS-V1.1.1", "CWE-79", "asvs_maps_cwe"),
                    *(('CASE-case-a', target, 'case_references') for target in
                      ('CVE-2026-10000', 'ASVS-V1.1.1', 'CASE-case-b', 'CWE-89'))}
        self.assertEqual({row[:3] for row in self.edges()}, expected)
        with contextlib.closing(sqlite3.connect(self.db)) as con, con:
            documents = {r[0] for r in con.execute("SELECT id FROM documents")}
        for doc, target, relation, _ in self.edges():
            self.assertIn(doc, documents)
            self.assertTrue(target in documents or target in {"CWE-79", "CWE-89"})
        # Sharing CWE-79 never invents CVE->ASVS or a reverse stored edge.
        self.assertNotIn(("CVE-2026-10000", "ASVS-V1.1.1", "case_references"), expected)

    def test_structured_asvs_fields_only(self):
        evidence = {"source_id": "owasp-asvs-5.0.0", "sha256": "a" * 64}
        for field in ("CWE", "CWEs", "cwes"):
            feed = {"Requirements": [{"Items": [{"Items": [
                {"Shortcode": "V1.1.1", "Description": "Check", field: ["CWE-89"]}]}]}]}
            row = list(intel.asvs_rows(feed, evidence))[0]
            self.assertEqual([edge["target_id"] for edge in row["relations"]], ["CWE-89"])
        for shape in ("CWE-89", 89, {"id": "CWE-89"}):
            self.assertEqual(intel.asvs_cwes({"CWE": shape, "Description": "CWE-89"}), [])

    def test_full_declared_list_not_fts_tag_limit(self):
        feed = {"vulnerabilities": [{"cveID": "CVE-2026-10000",
                                    "cwes": [f"CWE-{i}" for i in range(1, 15)]}]}
        row = list(intel.cisa_rows(feed, {"source_id": "cisa-kev", "sha256": "a" * 64}))[0]
        self.assertEqual(len(row["related"]), 12)  # existing search tags are unchanged
        self.assertEqual(len(row["relations"]), 14)

    def test_cli_json_and_legacy_schema_error(self):
        with mock.patch("sys.argv", ["mitr3-rag-intel.py", "relations", "CVE-2026-10000", "--json"]):
            with contextlib.redirect_stdout(io.StringIO()) as output:
                intel.main()
        result = json.loads(output.getvalue())
        self.assertEqual(result, intel.relations("CVE-2026-10000", emit=False))
        with contextlib.closing(sqlite3.connect(self.db)) as con, con:
            con.execute("DROP TABLE related")
            con.execute("CREATE TABLE related(doc_id,target_id,relation)")
        with self.assertRaisesRegex(ValueError, "run build"):
            intel.relations("CVE-2026-10000", emit=False)

    def test_evidence_hash_cannot_describe_different_feed(self):
        # A changed feed with a stale manifest aborts before publishing any index.
        original = self.db.read_bytes()
        self.kev["vulnerabilities"][0]["cwes"] = ["CWE-89"]
        write_json(self.cache / "cisa-kev.json", self.kev)
        with self.assertRaisesRegex(ValueError, "changed or corrupted"):
            intel.create()
        self.assertEqual(self.db.read_bytes(), original)


class CachedRelationTests(unittest.TestCase):
    def test_all_cached_pairs_are_declared_and_resolve(self):
        # Independently enumerate raw structured sources; exact equality catches
        # both invented links and silent loss of declared links to known nodes.
        kev = json.loads((intel.CACHE / "cisa-kev.json").read_bytes())
        asvs = json.loads((intel.CACHE / "owasp-asvs-5.0.0.json").read_bytes())
        cases = json.loads(intel.SOURCE.read_bytes())
        with tempfile.TemporaryDirectory() as td:
            with mock.patch.object(intel, "DB", Path(td) / "index.sqlite3"):
                with contextlib.redirect_stdout(io.StringIO()):
                    intel.create()
                with contextlib.closing(sqlite3.connect(intel.DB)) as con, con:
                    docs = {r[0] for r in con.execute("SELECT id FROM documents")}
                    rows = con.execute("SELECT doc_id,target_id,relation,evidence FROM related").fetchall()
        expected = set()
        for row in kev["vulnerabilities"]:
            for cwe in row.get("cwes", []):
                if isinstance(cwe, str) and intel.CWE_RE.fullmatch(cwe):
                    expected.add((row["cveID"].upper(), cwe, "cwe_of"))
        for chapter in asvs["Requirements"]:
            for section in chapter.get("Items", []):
                for item in section.get("Items", []):
                    doc = "ASVS-" + item.get("Shortcode", "")
                    for field in ("CWE", "CWEs", "cwes"):
                        targets = item.get(field, [])
                        if not isinstance(targets, list):
                            continue
                        for cwe in targets:
                            if doc in docs and isinstance(cwe, str) and intel.CWE_RE.fullmatch(cwe):
                                expected.add((doc, cwe, "asvs_maps_cwe"))
        for case in cases:
            for target in case.get("related", []):
                if isinstance(target, str) and (target in docs or intel.CWE_RE.fullmatch(target)):
                    expected.add(("CASE-" + case["id"], target, "case_references"))
        self.assertEqual({row[:3] for row in rows}, expected)
        paths = {"cisa-kev": intel.CACHE / "cisa-kev.json",
                 "owasp-asvs-5.0.0": intel.CACHE / "owasp-asvs-5.0.0.json", "public-cases": intel.SOURCE}
        hashes = {source: hashlib.sha256(path.read_bytes()).hexdigest() for source, path in paths.items()}
        for doc, target, relation, raw in rows:
            self.assertIn(doc, docs)
            self.assertTrue(target in docs or intel.CWE_RE.fullmatch(target))
            evidence = json.loads(raw)
            self.assertEqual(evidence["source_id"], intel.RELATION_SOURCES[relation])
            self.assertEqual(evidence["sha256"], hashes[evidence["source_id"]])


if __name__ == "__main__":
    unittest.main()
