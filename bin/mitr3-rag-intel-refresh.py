#!/usr/bin/env python3
"""MITR3 scheduled official feed refresh with CISA KEV snapshot delta and QA.

Initial run establishes baseline, never mislabels existing items as new.
A successful refresh updates the previous snapshot only after index and QA succeed.
"""
from __future__ import annotations
import datetime,json,os,pathlib,subprocess,sys,tempfile,hashlib
ROOT=pathlib.Path(__file__).resolve().parents[1]
CLI=ROOT/"bin/mitr3-rag-intel.py"
REPORT=ROOT/"state/mitr3-intel-refresh-latest.json"
SNAPSHOT=ROOT/"state/mitr3-kev-snapshot.json"
FEED=ROOT/"knowledge/reference-datasets/cache/cisa-kev.json"
HISTORY=ROOT/"state/mitr3-kev-delta-history.jsonl"

def write_atomic(path:pathlib.Path,blob:bytes):
 path.parent.mkdir(exist_ok=True,parents=True)
 fd,tmp=tempfile.mkstemp(dir=path.parent,prefix=".intel-refresh-")
 try:
  with os.fdopen(fd,"wb") as f:
   f.write(blob);f.flush();os.fsync(f.fileno())
  os.chmod(tmp,0o600)
  os.replace(tmp,path)
 finally:
  if os.path.exists(tmp):os.unlink(tmp)

def record_snapshot(feed:dict)->dict:
 assert isinstance(feed,dict) and isinstance(feed.get("vulnerabilities"),list)
 return {v["cveID"].upper():{
  "dateAdded":v.get("dateAdded",""),
  "vendorProject":v.get("vendorProject",""),
  "product":v.get("product",""),
  "vulnerabilityName":v.get("vulnerabilityName",""),
  "knownRansomwareCampaignUse":v.get("knownRansomwareCampaignUse",""),
  "requiredAction":v.get("requiredAction",""),
  "dueDate":v.get("dueDate",""),
 } for v in feed["vulnerabilities"]}

def compare(previous:dict|None,current:dict)->dict:
 if previous is None:
  return {"status":"initial_baseline","added":None,"removed":None,"updated":None,
    "note":"No previous checkpoint; cannot infer new catalog additions from this snapshot."}
 added=sorted(set(current)-set(previous))
 removed=sorted(set(previous)-set(current))
 updated=sorted(k for k in set(current)&set(previous) if current[k]!=previous[k])
 return {"status":"compared","added":[{"cve":k,"dateAdded":current[k]["dateAdded"],
   "vendor":current[k]["vendorProject"],"product":current[k]["product"]} for k in added],
  "removed":removed,"updated":updated,
  "counts":{"added":len(added),"removed":len(removed),"updated":len(updated)}}

def recent_by_added(current:dict,days:int=7):
 today=datetime.datetime.now(datetime.timezone.utc).date()
 entries=[]
 for k,v in current.items():
  try:
   added=datetime.date.fromisoformat(v["dateAdded"])
  except (ValueError,TypeError):continue
  if 0<=(today-added).days<days:entries.append({"cve":k,"dateAdded":v["dateAdded"],"vendor":v["vendorProject"],"product":v["product"]})
 return sorted(entries,key=lambda x:(x["dateAdded"],x["cve"]),reverse=True)

def run(action):
 r=subprocess.run([sys.executable,str(CLI),action],capture_output=True,text=True,timeout=110,check=False)
 print(action.upper(),"exit",r.returncode,flush=True)
 if r.returncode:
  print((r.stderr or r.stdout)[:280],file=sys.stderr)
  raise SystemExit(r.returncode)
 return r.stdout

def main():
 previous=json.loads(SNAPSHOT.read_text())["records"] if SNAPSHOT.exists() else None
 run("sync")
 run("build")
 bench=json.loads(run("bench"))
 stats=json.loads(run("stats"))
 feed=json.loads(FEED.read_text())
 current=record_snapshot(feed)
 if len(current)!=stats["sources"]["cisa-kev"]:raise ValueError("KEV duplicate entries or feed count mismatch")
 delta=compare(previous,current)
 new_recent=recent_by_added(current)
 timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat()
 digest=hashlib.sha256(FEED.read_bytes()).hexdigest()
 state={"at":timestamp,"stats":stats,
        "legacy_smoke_benchmark":{"hits":bench["hits"],"total":bench["total"],
                                 "note":"Legacy six-item plumbing test; NOT search quality benchmark"},
        "kev_delta":delta,"kev_recent_by_date_added_last_7_days":new_recent,
        "kev_snapshot_sha256":digest}
 write_atomic(REPORT,(json.dumps(state,ensure_ascii=False,indent=2)+"\n").encode())
 write_atomic(SNAPSHOT,(json.dumps({"taken_at":timestamp,"sha256":digest,"records":current},ensure_ascii=False)+"\n").encode())
 # Append compact per-refresh delta, not entire list.
 H= {"at":timestamp,"snapshot_sha256":digest,"status":delta["status"],
     "counts":delta.get("counts"),"recent_count":len(new_recent)}
 with open(HISTORY,"a",encoding="utf8") as f:
  os.chmod(HISTORY,0o600)
  f.write(json.dumps(H,ensure_ascii=False)+"\n")
 print("REFRESH_OK",stats["total"],"kev_delta",delta["status"],
       "added",len(delta["added"]) if delta["added"] is not None else "unknown_baseline",
       "recent_dateAdded_7d",len(new_recent))

if __name__=="__main__":main()

