#!/usr/bin/env python3
"""Manual approval gate for RAG case proposals; agents cannot self-approve with flags."""
from __future__ import annotations
import argparse, getpass, hashlib, importlib.util, json, os, re, subprocess, sys, tempfile
from datetime import datetime, timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
CATALOG=ROOT/"knowledge/public-cases/catalog.json"
QUEUE=ROOT/"knowledge/public-cases/queue"
ARCHIVE=QUEUE/"reviewed"
SOURCE=ROOT/"bin/mitr3-rag-public.py"
spec=importlib.util.spec_from_file_location("mitr3_public_curator",SOURCE)
base=importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)

def utc(): return datetime.now(timezone.utc).isoformat()

def file_for(cid): 
 if not re.fullmatch(r"[a-z0-9-]{5,64}",cid):raise ValueError("Invalid candidate ID")
 return QUEUE/(cid+".json")

def write_atomic(path,data):
 path.parent.mkdir(parents=True,exist_ok=True)
 fd,tmp=tempfile.mkstemp(dir=path.parent,prefix=".proposal-")
 try:
  with os.fdopen(fd,"w",encoding="utf8") as f:
   json.dump(data,f,ensure_ascii=False,indent=2)
   f.write("\n")
   f.flush();os.fsync(f.fileno())
  os.chmod(tmp,0o600)
  os.replace(tmp,path)
 finally:
  if os.path.exists(tmp):os.unlink(tmp)

def ingest(input_path):
 if input_path.stat().st_size>12000:raise ValueError("Oversized candidate")
 item=json.loads(input_path.read_text(encoding="utf8"))
 base.validate([item])
 cid=item["id"]
 path=file_for(cid)
 old=json.loads(CATALOG.read_text(encoding="utf8"))
 canon=item["source_url"].rstrip("/").lower()
 if any(x["id"]==cid or x["source_url"].rstrip("/").lower()==canon for x in old):
  raise ValueError("Already in approved catalog")
 if path.exists() or (ARCHIVE/path.name).exists():
  raise ValueError("Candidate already exists in queue")
 # No fetching and no dynamic execution of externally supplied commands.
 entry={"status":"pending_human_review","submitted_at":utc(),"record":item,
        "sha256":hashlib.sha256(json.dumps(item,sort_keys=True,ensure_ascii=False).encode()).hexdigest()}
 write_atomic(path,entry)
 print("QUEUED",cid,"for human review only")

def list_queue():
 QUEUE.mkdir(parents=True,exist_ok=True)
 entries=[]
 for p in sorted(QUEUE.glob("*.json")):
  if not p.is_file():continue
  try:
   e=json.loads(p.read_text(encoding="utf8"))
   entries.append({"id":e["record"]["id"],"status":e["status"],
      "title":e["record"]["title"],"source_url":e["record"]["source_url"]})
  except (OSError,KeyError,ValueError):continue
 print(json.dumps(entries,indent=2,ensure_ascii=False))

def review(cid,decision):
 p=file_for(cid)
 if not p.is_file():raise ValueError("Not in pending queue")
 e=json.loads(p.read_text(encoding="utf8"))
 if e.get("status")!="pending_human_review":raise ValueError("Not pending")
 item=e.get("record")
 base.validate([item])
 if not sys.stdin.isatty():
  raise PermissionError("Review requires a real interactive TTY; agents must not self-approve")
 print("Candidate:",cid)
 print("Title:",item["title"])
 print("Source:",item["source_url"])
 print("Validation:",item["validation"])
 print("License:",item["license"])
 print("Summary:",item["summary"][:800])
 phrase=f"{decision.upper()} {cid}"
 if input(f"Operator approval: type exactly '{phrase}' to continue: ").strip()!=phrase:
  raise ValueError("Human confirmation mismatch")
 existing=json.loads(CATALOG.read_text(encoding="utf8"))
 if decision=="approve":
  base.validate(existing+[item])
  write_atomic(CATALOG,existing+[item])
  for action in ("mitr3-rag-public.py","mitr3-rag-intel.py"):
   outcome=subprocess.run([sys.executable,str(ROOT/"bin"/action),"build"],check=False)
   if outcome.returncode:
    raise RuntimeError("Index rebuild failed; inspect before publishing")
 e["status"]="approved" if decision=="approve" else "rejected"
 e["reviewed_at"]=utc()
 e["reviewer"]=getpass.getuser()
 write_atomic(ARCHIVE/p.name,e)
 p.unlink()
 print("REVIEWED",cid,e["status"],"remote sync separate; use dry-run first")

def main():
 a=argparse.ArgumentParser()
 sub=a.add_subparsers(dest="cmd",required=True)
 p=sub.add_parser("propose");p.add_argument("--input",required=True,type=Path)
 sub.add_parser("queue")
 p=sub.add_parser("review");p.add_argument("id");p.add_argument("--decision",required=True,choices=["approve","reject"])
 args=a.parse_args()
 if args.cmd=="propose":ingest(args.input)
 elif args.cmd=="queue":list_queue()
 else:review(args.id,args.decision)

if __name__=="__main__":
 try:main()
 except (OSError,ValueError,TypeError,KeyError) as e:
  print("ERROR",type(e).__name__,str(e)[:250],file=sys.stderr)
  sys.exit(1)

