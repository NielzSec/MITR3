"""Automatic routing is a ranking bias; actor roles differ from artifacts."""
import contextlib
import importlib.util
import io
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("intel_routing_intent", ROOT / "bin/mitr3-rag-intel.py")
intel = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(intel)


def record(identifier, text, source="public-cases"):
    # Synthetic retrieval documents only; never added to the reviewed catalog.
    return {"id": identifier, "kind": "test", "source": source, "title": text,
            "summary": "", "lesson": "", "tags": "", "source_url": "https://example.org/test",
            "published_at": "", "validation": "synthetic_test_only", "relations": []}


@contextlib.contextmanager
def index(records):
    with tempfile.TemporaryDirectory() as td:
        with mock.patch.object(intel, "DB", Path(td) / "index.sqlite3"):
            with mock.patch.object(intel, "gather", return_value=records):
                with contextlib.redirect_stdout(io.StringIO()):
                    intel.create()
            yield


def ids(query, **kwargs):
    return [row["id"] for row in intel.search(query, limit=5, emit=False, **kwargs)]


class RoutingIntentTests(unittest.TestCase):
    def test_sap_cve_survives_automatic_public_cases_route(self):
        for query in ("SAP HTTP request smuggling", "HTTP request smuggling SAP",
                      "HTTP request smuggling CVE-2022-22536"):
            with self.subTest(query=query):
                self.assertIn("CVE-2022-22536", ids(query))

    def test_cache_poisoning_keeps_two_cases_without_asvs_filler(self):
        self.assertEqual(ids("cache poisoning"),
                         ["CASE-ps-practical-cache-poisoning-2018", "CASE-ps-cache-2024"])

    def test_three_unsupported_queries_abstain_despite_lexical_matches(self):
        queries = ("esxi encryptor", "LockBit ESXi encryptor", "ransomware campaign participant")
        with index([record(f"CASE-negative-{i}", q) for i, q in enumerate(queries)]):
            for query in queries:
                with self.subTest(query=query):
                    self.assertIsNotNone(intel.is_unsupported_intent(query))
                    self.assertEqual(ids(query), [])
        for query in queries:
            with self.subTest(live_query=query):
                self.assertEqual(ids(query), [])

    def test_three_supported_queries_return_when_documents_exist(self):
        # Source/builder documents do not exist in today's catalog. A temporary
        # index proves that the intent gate permits them when evidence exists.
        queries = ("cache poisoning", "ransomware source", "lockbit builder")
        with index([record(f"CASE-artifact-{i}", q) for i, q in enumerate(queries)]):
            for i, query in enumerate(queries):
                with self.subTest(query=query):
                    self.assertIsNone(intel.is_unsupported_intent(query))
                    self.assertEqual(ids(query), [f"CASE-artifact-{i}"])

    def test_actor_roles_and_attribution_in_both_languages(self):
        queries = ("ransomware campaign participant", "ransomware participants",
                   "ransomware affiliates", "afiliadas de ransomware", "operador de ransomware",
                   "operadoras de ransomware", "participantes da campanha", "ransomware partner",
                   "membros da campanha", "ransomware criminal associate", "actor attribution",
                   "C2 attribution", "atribuição de ator", "atribuição de campanha de ransomware",
                   "quem está por trás da campanha", "responsável pela campanha",
                   "who is involved in the ransomware campaign")
        for query in queries:
            with self.subTest(query=query):
                self.assertIsNotNone(intel.is_unsupported_intent(query))
                self.assertEqual(ids(query), [])

    def test_campaign_word_alone_is_not_actor_role_or_artifact_exemption(self):
        for query in ("cache poisoning", "ransomware source", "lockbit builder",
                      "ransomware campaign source", "lockbit campaign builder"):
            with self.subTest(artifact=query):
                self.assertIsNone(intel.is_unsupported_intent(query))
        # An artifact word cannot override an explicit request for an actor role.
        for query in ("ransomware source affiliate", "lockbit builder operator",
                      "ransomware campaign source participant"):
            with self.subTest(actor=query):
                self.assertIsNotNone(intel.is_unsupported_intent(query))

    def test_small_route_boost_breaks_ties_but_not_missing_coverage(self):
        case = record("CASE-cache", "cache poisoning")
        cve = record("CVE-2026-10000", "cache poisoning", "cisa-kev")
        # KEV comes first in the input; matching content/BM25 are identical.
        with index([cve, case]):
            self.assertEqual(ids("cache poisoning"), ["CASE-cache", "CVE-2026-10000"])
        cve["title"] = "SAP cache poisoning"
        with index([case, cve]):
            self.assertEqual(ids("SAP cache poisoning")[0], "CVE-2026-10000")
        case["title"] = "cache"
        cve["title"] = "cache poisoning"
        with index([case, cve]):
            self.assertEqual(ids("cache poisoning"), ["CVE-2026-10000"])

    def test_stronger_bm25_can_outweigh_route_bias_at_equal_coverage(self):
        case = record("CASE-cache", "cache poisoning " + "background " * 1000)
        cve = record("CVE-2026-10000", "cache poisoning", "cisa-kev")
        noise = [record(f"CASE-background-{i}", "irrelevant context " * 10) for i in range(50)]
        with index([case, cve] + noise):
            self.assertEqual(ids("cache poisoning")[0], "CVE-2026-10000")

    def test_explicit_source_still_filters_and_standards_are_not_hidden(self):
        rows = intel.search("SAP HTTP request smuggling", source="cisa-kev", limit=5, emit=False)
        self.assertIn("CVE-2022-22536", [row["id"] for row in rows])
        self.assertEqual({row["source"] for row in rows}, {"cisa-kev"})
        self.assertNotIn("CVE-2022-22536", ids("SAP HTTP request smuggling", source="public-cases"))
        self.assertIn("ASVS-V4.2.1", ids("ASVS HTTP request smuggling"))
        self.assertIn("CVE-2026-48710", ids("Starlette HTTP request smuggling"))


if __name__ == "__main__":
    unittest.main()
