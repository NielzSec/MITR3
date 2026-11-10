"""Regression on official KEV delta + typed relevance routing."""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,ROOT/path)
 m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
 return m

delta=load("kev_refresh","bin/mitr3-rag-intel-refresh.py")
intel=load("rag_intel_feedback","bin/mitr3-rag-intel.py")

class DeltaAndRetrievalTests(unittest.TestCase):
 def test_first_run_does_not_claim_all_new(self):
  current={"CVE-2024-1111":{"dateAdded":"2026-10-12"}}
  out=delta.compare(None,current)
  self.assertEqual(out["status"],"initial_baseline")
  self.assertIsNone(out["added"])

 def test_added_removed_and_modified(self):
  old={"CVE-2024-1111":{"dateAdded":"2026-10-01","vendorProject":"A"},
       "CVE-2024-2222":{"dateAdded":"2026-10-01","vendorProject":"B"}}
  new={"CVE-2024-1111":{"dateAdded":"2026-10-01","vendorProject":"A New"},
       "CVE-2024-3333":{"dateAdded":"2026-10-18","vendorProject":"C","product":"P"}}
  d=delta.compare(old,new)
  self.assertEqual(d["counts"],{"added":1,"removed":1,"updated":1})
  self.assertEqual(d["added"][0]["cve"],"CVE-2024-3333")
  self.assertIn("CVE-2024-2222",d["removed"])

 def test_compare_identical(self):
  a={"CVE-2025-1234":{"dateAdded":"2026-02-01"}}
  d=delta.compare(a,a)
  self.assertEqual(d["counts"],{"added":0,"removed":0,"updated":0})

 def test_record_snapshot_contains_only_allowed_summary(self):
  d={"vulnerabilities":[{"cveID":"CVE-2025-1234","dateAdded":"2026-02-01",
      "shortDescription":"DO_NOT_PERSIST_FULL_DESCRIPTION","requiredAction":"Patch",
      "vendorProject":"A"}]}
  s=delta.record_snapshot(d)
  self.assertNotIn("shortDescription",s["CVE-2025-1234"])
  self.assertEqual(s["CVE-2025-1234"]["requiredAction"],"Patch")

 def test_unsupported_actor_attribution(self):
  self.assertIsNotNone(intel.is_unsupported_intent("ESXi encryptor"))
  self.assertIsNone(intel.is_unsupported_intent("cache poisoning"))

 def test_source_route(self):
  self.assertEqual(intel.routed_source("cache poisoning",""),"public-cases")
  self.assertEqual(intel.routed_source("NTLM relay Outlook",""),"cisa-kev")
  self.assertEqual(intel.routed_source("CTF pcap forensics",""),"public-cases")
  self.assertEqual(intel.routed_source("HTTP request smuggling","cisa-kev"),"cisa-kev")

 def test_unknown_identifier_no_fuzzy_fallback(self):
  self.assertEqual(intel.search("CVE-2099-999999",emit=False),[])
  self.assertEqual(intel.search("ASVS-V99.99.99",emit=False),[])

 def test_known_negative_abstains(self):
  self.assertEqual(intel.search("esxi encryptor",emit=False),[])
  self.assertEqual(intel.search("LockBit ESXi encryptor",emit=False),[])

 def test_cache_filler_is_filtered(self):
  rows=intel.search("cache poisoning",emit=False)
  self.assertEqual([r["id"] for r in rows],
      ["CASE-ps-practical-cache-poisoning-2018","CASE-ps-cache-2024"])

 def test_relevance_fixture_has_20_positive_10_negative(self):
  queries=json.loads((ROOT/"tests/fixtures/intel-relevance-v1.json").read_text())
  self.assertEqual(sum(bool(x["relevant"]) for x in queries),20)
  self.assertEqual(sum(not x["relevant"] for x in queries),10)

if __name__=="__main__":unittest.main()

