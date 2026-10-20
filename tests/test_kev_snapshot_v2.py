"""CISA KEV snapshot v2: no false migration deltas, complete field coverage, no prose leaks."""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("refresh_v2",ROOT/"bin/mitr3-rag-intel-refresh.py")
refresh=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(refresh)

def entry():
 return {"cveID":"CVE-2026-10001","dateAdded":"2026-10-18","vendorProject":"A",
   "product":"B","requiredAction":"Apply vendor patches","shortDescription":"Sensitive raw but public text",
   "notes":"Third-party prose to keep out of snapshot","forensicTriage":{"Known":True},
   "cwes":["CWE-79","CWE-89"]}

class KevV2Tests(unittest.TestCase):
 def test_no_plaintext_for_hashed_fields(self):
  snapshot=refresh.record_snapshot({"vulnerabilities":[entry()]})
  row=snapshot["CVE-2026-10001"]
  self.assertEqual(row["cwes"],["CWE-79","CWE-89"])
  for sensitive in ("shortDescription","notes","forensicTriage"):
   self.assertNotIn(sensitive,row)
   self.assertEqual(len(row[sensitive+"_sha256"]),64)
  self.assertNotIn("Third-party prose",str(snapshot))

 def test_description_notes_forensic_triage_change_is_detected(self):
  old=refresh.record_snapshot({"vulnerabilities":[entry()]})
  for field,changed in (("shortDescription","different"),("notes","different"),("forensicTriage",{"Known":False}),("cwes",["CWE-89"])):
   with self.subTest(field=field):
    new=refresh.record_snapshot({"vulnerabilities":[dict(entry(),**{field:changed})]})
    self.assertEqual(refresh.compare(old,new)["updated"],["CVE-2026-10001"])

 def test_order_independent_and_duplicates_normalized(self):
  original=entry()
  new=dict(original,cwes=["CWE-89","CWE-79","CWE-79","notcwe"])
  x=refresh.record_snapshot({"vulnerabilities":[original]})
  y=refresh.record_snapshot({"vulnerabilities":[new]})
  self.assertEqual(refresh.compare(x,y)["counts"],{"added":0,"removed":0,"updated":0})

 def test_duplicate_and_case_insensitive_duplicate_rejected(self):
  one=entry()
  for two in (dict(one),dict(one,cveID="cve-2026-10001")):
   with self.subTest(two=two["cveID"]):
    with self.assertRaises(ValueError):
     refresh.record_snapshot({"vulnerabilities":[one,two]})

 def test_v1_starts_new_baseline(self):
  with tempfile.TemporaryDirectory() as tmp:
   path=Path(tmp)/"s.json"
   path.write_text(json.dumps({"records":{"CVE-2026-10001":{"vendorProject":"A"}}}))
   old,reason=refresh.read_previous_snapshot(path)
   self.assertIsNone(old)
   self.assertEqual(reason,"schema_migration_v1_to_v2")

 def test_unknown_future_schema_does_not_reset(self):
  with tempfile.TemporaryDirectory() as tmp:
   path=Path(tmp)/"s.json"
   path.write_text(json.dumps({"schema_version":900,"records":{}}))
   with self.assertRaises(ValueError):
    refresh.read_previous_snapshot(path)

 def test_v2_stable_snapshot(self):
  with tempfile.TemporaryDirectory() as tmp:
   path=Path(tmp)/"s.json"
   old=refresh.record_snapshot({"vulnerabilities":[entry()]})
   path.write_text(json.dumps({"schema_version":2,"records":old}))
   got,reason=refresh.read_previous_snapshot(path)
   self.assertEqual(reason,"current_v2")
   self.assertEqual(refresh.compare(got,old)["counts"],{"added":0,"removed":0,"updated":0})

 def test_main_migrates_legacy_without_false_updates(self):
  with tempfile.TemporaryDirectory() as tmp:
   base=Path(tmp)
   feed,snapshot,report,history=[base/name for name in ("feed.json","snapshot.json","report.json","history.jsonl")]
   feed.write_text(json.dumps({"vulnerabilities":[entry()]}))
   snapshot.write_text(json.dumps({"records":{"CVE-2026-10001":{"product":"B"}}}))
   fake={"sync":"","build":"","bench":json.dumps({"hits":6,"total":6}),
         "stats":json.dumps({"total":1,"sources":{"cisa-kev":1}})}
   with mock.patch.multiple(refresh,FEED=feed,SNAPSHOT=snapshot,REPORT=report,HISTORY=history):
    with mock.patch.object(refresh,"run",side_effect=lambda action:fake[action]):
     with mock.patch("builtins.print"):refresh.main()
   obj=json.loads(report.read_text())
   self.assertEqual(obj["kev_delta"]["status"],"initial_baseline")
   self.assertIsNone(obj["kev_delta"]["updated"])
   self.assertIn("schema migration",obj["kev_delta"]["note"])
   self.assertEqual(json.loads(snapshot.read_text())["schema_version"],2)

 def test_large_feed_diffs_are_deterministic(self):
  original=[dict(entry(),cveID="CVE-2026-"+str(i+10000)) for i in range(4000)]
  old=refresh.record_snapshot({"vulnerabilities":original})
  new=refresh.record_snapshot({"vulnerabilities":list(reversed(original))})
  self.assertEqual(refresh.compare(old,new)["counts"],{"added":0,"removed":0,"updated":0})

if __name__=="__main__":unittest.main()

