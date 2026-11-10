#!/usr/bin/env python3
"""Complementos ao eval/QA do intel: janela de 7 dias do KEV e invariantes do fixture.

O núcleo de delta/roteamento/abstenção já é coberto por tests/test_intel_feedback.py;
aqui ficam só os testes que aquele arquivo não cobre.
"""
import datetime
import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("mitr3_rag_refresh", ROOT / "bin/mitr3-rag-intel-refresh.py")
refresh = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(refresh)

SPEC_INTEL = importlib.util.spec_from_file_location("mitr3_rag_intel_cov", ROOT / "bin/mitr3-rag-intel.py")
intel = importlib.util.module_from_spec(SPEC_INTEL)
SPEC_INTEL.loader.exec_module(intel)


def entry(date_added="2026-10-01"):
    return {"dateAdded": date_added, "vendorProject": "Vendor", "product": "Product",
            "vulnerabilityName": "Example", "knownRansomwareCampaignUse": "Unknown",
            "requiredAction": "Apply updates", "dueDate": "2026-10-20"}


class RecentWindowTests(unittest.TestCase):
    def test_recent_by_date_added_is_bounded(self):
        today = datetime.datetime.now(datetime.timezone.utc).date()
        fresh = (today - datetime.timedelta(days=2)).isoformat()
        stale = (today - datetime.timedelta(days=40)).isoformat()
        current = {"CVE-2026-0001": entry(fresh), "CVE-2026-0002": entry(stale),
                   "CVE-2026-0003": entry("not-a-date")}
        recent = refresh.recent_by_added(current, days=7)
        self.assertEqual([x["cve"] for x in recent], ["CVE-2026-0001"])

    def test_recent_is_sorted_newest_first(self):
        today = datetime.datetime.now(datetime.timezone.utc).date()
        current = {"CVE-2026-0001": entry((today - datetime.timedelta(days=5)).isoformat()),
                   "CVE-2026-0002": entry((today - datetime.timedelta(days=1)).isoformat())}
        recent = refresh.recent_by_added(current, days=7)
        self.assertEqual([x["cve"] for x in recent], ["CVE-2026-0002", "CVE-2026-0001"])


class CoverageRankingTests(unittest.TestCase):
    def test_long_query_keeps_recall(self):
        ids = [r["id"] for r in intel.search("HTTP desync smuggling research", 5, emit=False)]
        self.assertIn("CASE-ps-request-smuggling-research", ids)

    def test_substring_words_do_not_fake_coverage(self):
        # "rat" nao pode casar dentro de "operation"/"integration": sem ficha de Quasar, abstem.
        self.assertEqual(intel.search("quasar rat source", 5, emit=False), [])

    def test_unknown_identifier_still_abstains(self):
        self.assertEqual(intel.search("CVE-2099-999999", 5, emit=False), [])

    def test_document_type_word_does_not_break_coverage(self):
        ids = [r["id"] for r in intel.search("Faultline writeup", 5, emit=False)]
        self.assertIn("CASE-ctfcit-2026-faultline", ids)
        ids = [r["id"] for r in intel.search("cache poisoning report", 5, emit=False)]
        self.assertIn("CASE-ps-practical-cache-poisoning-2018", ids)

    def test_document_type_word_alone_still_abstains(self):
        self.assertEqual(intel.search("writeup", 5, emit=False), [])


class FixtureInvariantTests(unittest.TestCase):
    def test_queries_are_unique_and_sized(self):
        queries = json.loads((ROOT / "tests/fixtures/intel-relevance-v1.json").read_text())
        self.assertEqual(len(queries), 30)
        self.assertEqual(len({q["query"] for q in queries}), 30)

    def test_exact_queries_point_at_themselves(self):
        queries = json.loads((ROOT / "tests/fixtures/intel-relevance-v1.json").read_text())
        for q in queries:
            if q["kind"] == "exact":
                self.assertEqual(q["relevant"], [q["query"]])


if __name__ == "__main__":
    unittest.main()
