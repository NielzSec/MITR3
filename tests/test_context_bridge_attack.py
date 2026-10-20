"""ATT&CK bridge evidence is atomic, complete, and namespace-isolated."""
from contextlib import closing
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("attack_context_bridge", ROOT / "bin/mitr3-context-bridge.py")
bridge = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bridge)
TECH = "attack-pattern--970a3432-3237-47ad-bcca-7d8cbb217736"
PARENT = "attack-pattern--7385dfaf-6886-4229-9ecd-6fd678040830"
MITIGATION = "course-of-action--00000000-0000-4000-8000-000000000001"
MALWARE = "malware--00000000-0000-4000-8000-000000000002"
STAMP = "2026-04-29T14:23:06.176Z"


def node(ident, name, external_id=""):
    return {"stix_id": ident, "type": ident.split("--")[0], "name": name, "external_id": external_id}


def payload(sha):
    def edge(index, predicate, source, target):
        return {"stix_id": f"relationship--00000000-0000-4000-8000-{index:012d}", "type": predicate,
                "source": source, "target": target, "origin": {"source_id": bridge.ATTACK_SOURCE,
                    "url": bridge.ATTACK_URL, "bundle_sha256": sha, "modified": STAMP}}
    tech = node(TECH, "PowerShell", "T1059.001")
    return {"entities": [tech], "metadata": {"sha256": sha, "source_id": bridge.ATTACK_SOURCE, "url": bridge.ATTACK_URL},
            "outbound": [edge(1, "subtechnique-of", tech, node(PARENT, "Command and Scripting Interpreter"))],
            "inbound": [edge(2, "mitigates", node(MITIGATION, "Test mitigation"), tech),
                        edge(3, "uses", node(MALWARE, "Test malware"), tech)],
            "counts": {"outbound": 1, "inbound": 2}}


class AttackBridgeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.cache = root / "knowledge/reference-datasets/cache"
        self.cache.mkdir(parents=True)
        # Deliberately not STIX JSON: the bridge hashes bytes, never parses prose.
        raw = b"opaque bundle bytes; no prose may create a relationship"
        self.sha = hashlib.sha256(raw).hexdigest()
        (self.cache / "enterprise-attack.json").write_bytes(raw)
        self.manifest = {"source_id": bridge.ATTACK_SOURCE, "url": bridge.ATTACK_URL, "sha256": self.sha}
        self.manifest_path = self.cache / "enterprise-attack-manifest.json"
        self.manifest_path.write_text(json.dumps(self.manifest))
        self.patch = mock.patch.object(bridge, "ROOT", root)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.payload = payload(self.sha)

    def test_attack_envelope_and_no_cve_namespace(self):
        with mock.patch.object(bridge, "command_json", return_value=self.payload) as command:
            result = bridge.read_local("t1059.001")
        command.assert_called_once_with(["graph", "T1059.001", "--json", "--all"])
        self.assertEqual(result["source_declared_relations"], [])
        self.assertEqual(result["matches"], [])
        self.assertEqual(result["relation_count"], 0)
        self.assertEqual(result["attack_relations_by_type"], {"uses": 1, "mitigates": 1, "subtechnique-of": 1})
        for edge in result["attack_relations"]:
            self.assertEqual(edge["sha256"], self.sha)
            self.assertEqual(edge["namespace"], "attack")
            self.assertEqual(edge["assertion_type"], "source_declared_only")
            self.assertEqual(edge["modified"], STAMP)
            self.assertTrue(edge["stix_id"].startswith("relationship--"))
        self.assertEqual(result["attack_entities"][0]["namespace"], "attack")

    def test_routes_each_attack_identifier_without_fts_fallback(self):
        empty = copy.deepcopy(self.payload)
        empty.update(entities=[], outbound=[], inbound=[], counts={"outbound": 0, "inbound": 0})
        for identifier in ("T1059", "T1059.001", "TA0002", "G0007", "S0002", "M1049", "T9999"):
            with self.subTest(identifier=identifier):
                with mock.patch.object(bridge, "command_json", return_value=empty) as command:
                    result = bridge.read_local(identifier)
                command.assert_called_once_with(["graph", identifier, "--json", "--all"])
                self.assertEqual(result["attack_relations"], [])
                self.assertEqual(result["source_declared_relations"], [])

    def test_manifest_tampered_on_disk_refuses_all_before_command(self):
        self.manifest["sha256"] = "b" * 64
        self.manifest_path.write_text(json.dumps(self.manifest))
        with mock.patch.object(bridge, "command_json") as command:
            with self.assertRaises(bridge.LocalError):
                bridge.read_local("T1059.001")
        command.assert_not_called()

    def test_bundle_bytes_cannot_disagree_with_manifest(self):
        (self.cache / "enterprise-attack.json").write_bytes(b"tampered")
        with self.assertRaises(bridge.LocalError):
            bridge.read_local("T1059.001")

    def test_database_metadata_digest_mismatch_refuses_all(self):
        self.payload["metadata"]["sha256"] = "b" * 64
        with mock.patch.object(bridge, "command_json", return_value=self.payload):
            with self.assertRaises(bridge.LocalError):
                bridge.read_local("T1059.001")

    def test_last_edge_digest_mismatch_is_atomic_and_remote_cannot_rescue(self):
        self.payload["inbound"][-1]["origin"]["bundle_sha256"] = "b" * 64
        with mock.patch.object(bridge, "command_json", return_value=self.payload):
            with mock.patch("sys.argv", ["bridge", "T1059.001", "--remote", "--json"]):
                with mock.patch.object(bridge, "fetch_remote") as remote:
                    with mock.patch("sys.stdout", new_callable=io.StringIO) as stdout:
                        with self.assertRaises(bridge.LocalError):
                            bridge.main()
                        self.assertEqual(stdout.getvalue(), "")
                remote.assert_not_called()

    def test_unsupported_predicate_is_not_promoted(self):
        for predicate in ("detects", "revoked-by", "cwe_of", "probably-related"):
            with self.subTest(predicate=predicate):
                bad = copy.deepcopy(self.payload)
                bad["outbound"][0]["type"] = predicate
                edges = bridge.verified_attack_edges(bad, self.sha)
                self.assertEqual({edge["predicate"] for edge in edges}, {"mitigates", "uses"})

    def test_missing_proof_or_cross_namespace_node_is_denied(self):
        for field in ("stix_id", "modified", "origin", "source"):
            with self.subTest(field=field):
                bad = copy.deepcopy(self.payload)
                edge = bad["outbound"][0]
                if field == "modified":
                    edge["origin"].pop(field)
                elif field == "source":
                    edge[field]["stix_id"] = "CVE-2023-23397"
                else:
                    edge.pop(field)
                with self.assertRaises(bridge.LocalError):
                    bridge.verified_attack_edges(bad, self.sha)

    def test_missing_metadata_or_truncated_page_is_denied(self):
        for field in ("metadata", "counts"):
            bad = copy.deepcopy(self.payload)
            bad.pop(field)
            with self.assertRaises(bridge.LocalError):
                bridge.verified_attack_edges(bad, self.sha)
        bad = copy.deepcopy(self.payload)
        bad["counts"]["inbound"] = 243
        with self.assertRaises(bridge.LocalError):
            bridge.verified_attack_edges(bad, self.sha)

    def test_edge_must_be_incident_to_resolved_entity(self):
        self.payload["entities"] = []
        with mock.patch.object(bridge, "command_json", return_value=self.payload):
            with self.assertRaises(bridge.LocalError):
                bridge.read_local("T1059.001")

    def test_cve_never_gains_attack_edges_and_remote_never_validates_either(self):
        cve_edge = {"doc_id": "CVE-2023-23397", "target_id": "CWE-294", "relation": "cwe_of",
                    "evidence": {"source_id": "cisa-kev", "sha256": "a" * 64}}
        calls = []
        def command(args):
            calls.append(args[0])
            if args[0] == "search":
                return [{"id": "CVE-2023-23397", "title": "Outlook", "source_url": "https://www.cisa.gov/"}]
            self.assertEqual(args[0], "relations")
            cross_namespace = {**cve_edge, "target_id": "T1059.001"}
            return {"outbound": [cve_edge, cross_namespace, self.payload["outbound"][0]], "inbound": []}
        with mock.patch.object(bridge, "command_json", side_effect=command):
            with mock.patch.object(bridge, "local_digest_map", return_value={"cisa-kev": "a" * 64}):
                cve = bridge.read_local("CVE-2023-23397")
        self.assertNotIn("graph", calls)
        self.assertEqual(cve["attack_relations"], [])
        self.assertEqual(len(cve["source_declared_relations"]), 1)
        self.assertEqual(cve["source_declared_relations"][0]["predicate"], "cwe_of")
        with mock.patch.object(bridge, "command_json", return_value=self.payload):
            attack = bridge.read_local("T1059.001")
        remote = bridge.summarize_megabrain({"status": "context_available", "context": "Prose says CVE maps to ATT&CK",
            "citations": [{"origin": "attack:T1059.001", "relation_validated": True, "predicate": "uses"}]})
        for query, local in (("CVE-2023-23397", cve), ("T1059.001", attack)):
            output = bridge.build(query, local, remote)
            self.assertFalse(output["megabrain"]["citations"][0]["relation_validated"])
            self.assertEqual(output["local"], local)
            self.assertIn("ATT&CK edges do not prove CVE/CWE/ASVS/CASE", output["note"])
            self.assertNotIn("Prose says", json.dumps(output))


@unittest.skipUnless((ROOT / "state/mitr3-attack.sqlite3").exists(), "Offline ATT&CK graph missing")
class CachedAttackBridgeTests(unittest.TestCase):
    def test_powershell_complete_outbound_and_inbound_with_sha(self):
        result = bridge.read_local("T1059.001")
        graph = bridge.command_json(["graph", "T1059.001", "--json", "--all"])
        self.assertEqual(result["attack_relation_count"], sum(graph["counts"].values()))
        self.assertGreater(result["attack_relation_count"], 200)  # catches default graph truncation
        expected = bridge.attack_digest()
        with closing(sqlite3.connect("file:" + str(ROOT / "state/mitr3-attack.sqlite3") + "?mode=ro", uri=True)) as con:
            self.assertEqual(json.loads(con.execute("SELECT value FROM metadata WHERE key='sha256'").fetchone()[0]), expected)
        self.assertTrue(any(e["direction"] == "outbound" and e["predicate"] == "subtechnique-of" for e in result["attack_relations"]))
        self.assertTrue(any(e["direction"] == "inbound" and e["predicate"] == "mitigates" for e in result["attack_relations"]))
        self.assertTrue(all(e["sha256"] == expected and e["namespace"] == "attack" for e in result["attack_relations"]))
        self.assertEqual(result["source_declared_relations"], [])
        cve = bridge.read_local("CVE-2023-23397")
        self.assertEqual(cve["attack_relations"], [])
        self.assertTrue(cve["source_declared_relations"])

    def test_unknown_attack_identifier_is_empty_without_error(self):
        result = bridge.read_local("T9999")
        self.assertEqual(result["status"], "no_local_document")
        self.assertEqual(result["attack_relations"], [])
        self.assertEqual(result["attack_entities"], [])
        self.assertEqual(result["source_declared_relations"], [])


if __name__ == "__main__":
    unittest.main()
