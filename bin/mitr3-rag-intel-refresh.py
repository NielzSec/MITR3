#!/usr/bin/env python3
"""Official-source refresh and QA; no scanning or remote mass ingestion."""
import datetime,json,os,pathlib,subprocess,sys,tempfile
ROOT=pathlib.Path(__file__).resolve().parents[1]
CLI=ROOT/"bin/mitr3-rag-intel.py"
REPORT=ROOT/"state/mitr3-intel-refresh-latest.json"
def run(action):
 r=subprocess.run([sys.executable,str(CLI),action],capture_output=True,text=True,timeout=110,check=False)
 print(action.upper(),"exit",r.returncode,flush=True)
 if r.returncode:
  print((r.stderr or r.stdout)[:280],file=sys.stderr)
  raise SystemExit(r.returncode)
 return r.stdout
def main():
 run("sync");run("build")
 bench=json.loads(run("bench"));stats=json.loads(run("stats"))
 state={"at":datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "stats":stats,"bench":{"hits":bench["hits"],"total":bench["total"],"recall_at_5":bench["recall_at_5"]}}
 fd,p=tempfile.mkstemp(dir=REPORT.parent,prefix=".intel-refresh-")
 try:
  with os.fdopen(fd,"w") as f:json.dump(state,f,indent=2);f.write("\n")
  os.chmod(p,0o600)
  os.replace(p,REPORT)
 finally:
  if os.path.exists(p):os.unlink(p)
 print("REFRESH_OK",stats["total"],"hits",bench["hits"],"of",bench["total"])
if __name__=="__main__":main()

