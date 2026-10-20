#!/usr/bin/env python3
"""MITR3 search relevance fixture. A documented test set, not an LLM benchmark.

Metrics: recall@5, precision@5 (fixed denominator 5), hit@5, and strict
negative-query abstention. Fixtures curated independently of original smoke 6.
"""
from __future__ import annotations
import argparse
import importlib.util
import json
import re
import sqlite3
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
TESTS=ROOT/"tests/fixtures/intel-relevance-v1.json"
DB=ROOT/"state/mitr3-intel.sqlite3"
SCRIPT=ROOT/"bin/mitr3-rag-intel.py"

def baseline(db:sqlite3.Connection, query:str, limit:int=5)->list[str]:
 tokens=re.findall(r"[\w]+",query,re.UNICODE)[:15]
 if not tokens:return []
 exact=query.upper()
 if re.fullmatch(r"CVE-\d{4}-\d{4,}",exact) or exact.startswith("ASVS-"):
  return [r[0] for r in db.execute("SELECT id FROM documents WHERE id=?",(exact,))]
 expression=" OR ".join('"'+x.replace('"','')+'"' for x in tokens)
 return [r[0] for r in db.execute(
   "SELECT d.id FROM docs_fts JOIN documents d ON d.id=docs_fts.id "
   "WHERE docs_fts MATCH ? ORDER BY bm25(docs_fts,0,3,1.2,1.2,1.5) LIMIT ?",
   (expression,limit))]

def candidate(query:str,limit:int=5)->list[str]:
 spec=importlib.util.spec_from_file_location("mitr3_intel_eval_import",SCRIPT)
 module=importlib.util.module_from_spec(spec)
 spec.loader.exec_module(module)
 return [r["id"] for r in module.search(query,limit=limit,as_json=True,emit=False)]

def evaluate(queries:list[dict],runner)->dict:
 details=[]
 positives=[x for x in queries if x["relevant"]]
 negatives=[x for x in queries if not x["relevant"]]
 for record in queries:
  got=runner(record["query"])
  relevant=set(record["relevant"])
  tp=len(relevant.intersection(got[:5]))
  details.append({"query":record["query"],"kind":record["kind"],
    "expected":sorted(relevant),"returned":got[:5],
    "hit_at_5":bool(tp),"recall_at_5":round(tp/len(relevant),3) if relevant else None,
    "precision_at_5":round(tp/5,3) if relevant else None,
    "precision_of_returned":round(tp/len(got[:5]),3) if relevant and got else (0.0 if relevant else None),
    "abstained":len(got)==0 if not relevant else None})
 pos=[d for d in details if d["expected"]]
 neg=[d for d in details if not d["expected"]]
 buckets={}
 for category in sorted({d["kind"] for d in pos}):
  subset=[d for d in pos if d["kind"]==category]
  buckets[category]={"n":len(subset),"hit_at_5":round(sum(d["hit_at_5"] for d in subset)/len(subset),3),
    "recall_at_5":round(sum(d["recall_at_5"] for d in subset)/len(subset),3),
    "precision_at_5":round(sum(d["precision_at_5"] for d in subset)/len(subset),3),
    "precision_of_returned":round(sum(d["precision_of_returned"] for d in subset)/len(subset),3)}
 return {"positive_queries":len(pos),"negative_queries":len(neg),
         "hit_at_5":round(sum(d["hit_at_5"] for d in pos)/len(pos),3),
         "macro_recall_at_5":round(sum(d["recall_at_5"] for d in pos)/len(pos),3),
         "macro_precision_at_5":round(sum(d["precision_at_5"] for d in pos)/len(pos),3),
         "macro_precision_of_returned":round(sum(d["precision_of_returned"] for d in pos)/len(pos),3),
         "negative_abstention_rate":round(sum(d["abstained"] for d in neg)/len(neg),3),
         "by_kind":buckets,"details":details}
def main():
 p=argparse.ArgumentParser()
 p.add_argument("--mode",choices=["baseline","candidate"],default="candidate")
 p.add_argument("--reference-index",type=Path,help="Required for baseline: database rebuilt using original code of commit 4bfb4f9. Use archived report for audit.")
 p.add_argument("--save",type=Path)
 a=p.parse_args()
 if a.mode=="baseline" and a.reference_index is None:
  p.error("baseline requires --reference-index pointing at an index rebuilt from commit 4bfb4f9; do not compare OR on a modified index")
 queries=json.loads(TESTS.read_text())
 assert len(queries)==30
 index_path=a.reference_index if a.mode=="baseline" else DB
 db=sqlite3.connect("file:"+str(index_path)+"?mode=ro",uri=True)
 try:
  if a.mode=="baseline":
   result=evaluate(queries,lambda q:baseline(db,q))
  else:
   result=evaluate(queries,candidate)
 finally:db.close()
 result["mode"]=a.mode
 result["fixture"]=str(TESTS)
 result[ "notes"]="Human-curated corpus examples, not blinded. P@5 uses fixed denominator 5. Precision-of-returned is conditional on how many results the system chooses to return, so it can rise by abstaining; NOT an independent semantic correctness measure."
 if a.save:
  a.save.parent.mkdir(parents=True,exist_ok=True)
  a.save.write_text(json.dumps(result,indent=2,ensure_ascii=False)+"\n")
 print(json.dumps({k:v for k,v in result.items() if k!="details"},indent=2,ensure_ascii=False))
 if a.mode=="candidate":
  for row in result["details"]:
   if not row["expected"] and not row["abstained"]:print("NEGATIVE_FALSE_RETURN",row["query"],row["returned"])
if __name__=="__main__":main()

