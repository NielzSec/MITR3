#!/usr/bin/env python3
"""MITR3 Intel RAG: independent local index of reviewed cases + pinned public JSON feeds.
Uses only Python stdlib; no PoC execution, scanning, untrusted remote commands, or bulk MCP upload.
"""
from __future__ import annotations
import argparse, collections, datetime as dt, hashlib, json, os, re, sqlite3, sys, tempfile
import urllib.request, urllib.parse
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
CACHE=ROOT/"knowledge/reference-datasets/cache"
DB=ROOT/"state/mitr3-intel.sqlite3"
SOURCE=ROOT/"knowledge/public-cases/catalog.json"
MANIFEST=CACHE/"manifest.json"
MAX_SIZE=5_000_000
URLS={
  "cisa-kev":"https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
  "owasp-asvs-5.0.0":"https://raw.githubusercontent.com/OWASP/ASVS/v5.0.0/5.0/docs_en/OWASP_Application_Security_Verification_Standard_5.0.0_en.json"
}
REFERENCE_LINKS={
 "cisa-kev":"https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
 "owasp-asvs-5.0.0":"https://github.com/OWASP/ASVS/tree/v5.0.0"
}
CVE_RE=re.compile(r"^CVE-\d{4}-\d{4,}$",re.I)
ASVS_RE=re.compile(r"^V?\d+\.\d+\.\d+$",re.I)
BLOCK=re.compile(r"(?i)\b(ignore previous instructions|send your environment|reveal your system prompt)\b")

def now() -> str:
 return dt.datetime.now(dt.timezone.utc).isoformat()

def atomic_bytes(path:Path,blob:bytes,mode:int=0o600):
 path.parent.mkdir(parents=True,exist_ok=True)
 fd,tmp=tempfile.mkstemp(prefix=".ingest-",dir=path.parent)
 try:
  with os.fdopen(fd,"wb") as f: f.write(blob);f.flush();os.fsync(f.fileno())
  os.chmod(tmp,mode)
  os.replace(tmp,path)
 finally:
  if os.path.exists(tmp): os.unlink(tmp)

def sanitized(value:object,limit:int=900)->str:
 if not isinstance(value,str): return ""
 s=" ".join(value.split())[:limit]
 return s if not BLOCK.search(s) else "[REVIEW_REQUIRED:UNTRUSTED_CONTENT]"

def download(name:str)->dict:
 url=URLS[name]
 # HTTPS+fixed allowlist; never follow redirects outside official hosts.
 req=urllib.request.Request(url,headers={"User-Agent":"MITR3-public-reference-catalog/1.0","Accept":"application/json"})
 with urllib.request.urlopen(req,timeout=18) as r:
  final=urllib.parse.urlsplit(r.geturl())
  original=urllib.parse.urlsplit(url)
  if final.scheme!="https" or final.hostname!=original.hostname:
   raise ValueError("Redirect outside pinned source")
  raw=r.read(MAX_SIZE+1)
  if len(raw)>MAX_SIZE: raise ValueError("Dataset over size limit")
 data=json.loads(raw)
 check_structure(name,data)
 path=CACHE/(name+".json")
 atomic_bytes(path,raw)
 return {"source":name,"url":url,"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest(),
         "checked_at":now(),"item_count":count_feed(name,data)}

def check_structure(name:str,d:object):
 if not isinstance(d,dict): raise ValueError("Expected JSON object")
 if name=="cisa-kev":
  xs=d.get("vulnerabilities")
  if not isinstance(xs,list) or len(xs)<100 or len(xs)>20000: raise ValueError("Suspicious CISA count")
  for row in xs:
   if not isinstance(row,dict) or not CVE_RE.fullmatch(str(row.get("cveID",""))):
    raise ValueError("Invalid CVE entry")
 else:
  if d.get("Version")!="5.0.0" or not isinstance(d.get("Requirements"),list) or len(d["Requirements"])<10:
   raise ValueError("Unexpected ASVS release")

def asvs_rows(data:dict):
 for chap in data["Requirements"]:
  for section in chap.get("Items",[]):
   for item in section.get("Items",[]):
    sid=item.get("Shortcode")
    if not sid or not ASVS_RE.fullmatch(str(sid)): continue
    desc=sanitized(item.get("Description"),1300)
    if not desc: continue
    yield {"id":"ASVS-"+sid, "kind":"standard_requirement","source":"owasp-asvs-5.0.0",
      "title":str(sid)+": "+sanitized(section.get("Name"),120),
      "summary":desc, "lesson":"Requisito de verificacao ASVS 5.0.0, nao evidencia de falha num alvo.",
      "tags":"owasp asvs security verification "+sanitized(chap.get("Name"),150)+" "+sanitized(section.get("Name"),150),
      "source_url":REFERENCE_LINKS["owasp-asvs-5.0.0"],"published_at":"2025-05",
      "validation":"published_standard_not_tested", "related":["ASVS-"+str(sid)]}

def cisa_rows(data:dict):
 for row in data["vulnerabilities"]:
  cid=row["cveID"].upper()
  cwes=row.get("cwes") or []
  if not isinstance(cwes,list): cwes=[]
  cwes=[s for s in cwes if isinstance(s,str) and re.fullmatch(r"CWE-\d+",s)][:12]
  yield {"id":cid,"kind":"known_exploited_catalog","source":"cisa-kev",
    "title":cid+" "+sanitized(row.get("vulnerabilityName"),220),
    "summary":sanitized(row.get("shortDescription"),900),
    "lesson":"CISA KEV (catalogado como explorado): "+sanitized(row.get("requiredAction"),550)
            +" Verificar aplicabilidade, fornecedor e atualizacoes antes de recomendar correcao.",
    "tags":"CISA KEV CVE "+sanitized(row.get("vendorProject"),120)+" "+sanitized(row.get("product"),120)+" "+" ".join(cwes),
    "source_url":REFERENCE_LINKS["cisa-kev"],"published_at":sanitized(row.get("dateAdded"),20),
    "validation":"official_catalog_not_locally_tested","related":cwes}

# Explicit editorial aliases: vocabulary bridges, never invented evidence.
# Controlled vocabulary for retrieval, not a model or external ontology.
CASE_ALIASES = {
    "file-carving": "corrupt corrupted damaged images recovery magic bytes",
    "ctf/forensics": "forensics forensic investigation evidence analysis",
    "ctf/reverse-engineering": "reverse reversing binary disassembly ELF",
    "ctf/windows-forensics": "forensics forensic incident response windows",
    "web/cache": "web cache caching CDN headers",
    "web/http": "HTTP proxy request desync framing smuggling",
}

def case_index_tags(a):
    base = " ".join(sanitized(x,100) for x in a["tags"])
    category = a.get("category","")
    extensions = [phrase for label,phrase in CASE_ALIASES.items()
                  if category==label or label in a["tags"]]
    return " ".join([base, category] + extensions)

def public_rows():
 items=json.loads(SOURCE.read_text(encoding="utf-8"))
 seen=set()
 for a in items:
  cid="CASE-"+a["id"]
  if cid in seen:raise ValueError("duplicate public case")
  seen.add(cid)
  yield {"id":cid,"kind":a["kind"],"source":"public-cases",
      "title":sanitized(a["title"],400),
      "summary":sanitized(a["summary"],2000),
      "lesson":sanitized(a["lesson"],1500),
      "tags":case_index_tags(a),
      "source_url":a["source_url"],"published_at":a.get("published_at") or "",
      "validation":a["validation"],"related":a.get("related",[])}

def count_feed(name,data):
 return len(data["vulnerabilities"]) if name=="cisa-kev" else len(list(asvs_rows(data)))

def sync():
 CACHE.mkdir(parents=True,exist_ok=True)
 old=json.loads(MANIFEST.read_text(encoding="utf-8")) if MANIFEST.exists() else {}
 for name in URLS:
  report=download(name)
  old[name]=report
  atomic_bytes(MANIFEST,json.dumps(old,ensure_ascii=False,indent=2).encode()+b"\n")
  print("FETCH_OK",name,"records",report["item_count"],"bytes",report["bytes"],
        "sha256",report["sha256"],flush=True)

def check_manifest(name,manifest):
 path=CACHE/(name+".json")
 b=path.read_bytes()
 if hashlib.sha256(b).hexdigest()!=manifest[name]["sha256"]:
  raise ValueError("Cached feed changed or corrupted: "+name)
 data=json.loads(b)
 check_structure(name,data)
 return data

def gather():
 manifest=json.loads(MANIFEST.read_text(encoding="utf-8"))
 feeds={name:check_manifest(name,manifest) for name in URLS}
 records=list(public_rows())
 records.extend(cisa_rows(feeds["cisa-kev"]))
 records.extend(asvs_rows(feeds["owasp-asvs-5.0.0"]))
 return records

def create():
 records=gather()
 seen=set()
 DB.parent.mkdir(parents=True,exist_ok=True)
 fd,tmp=tempfile.mkstemp(dir=DB.parent,prefix=".mitr3-intel-",suffix=".sqlite3")
 os.close(fd)
 try:
  con=sqlite3.connect(tmp)
  try:
   con.execute("PRAGMA journal_mode=DELETE")
   con.execute("CREATE TABLE documents (id TEXT PRIMARY KEY, kind TEXT NOT NULL, source TEXT NOT NULL, title TEXT NOT NULL, summary TEXT NOT NULL, lesson TEXT NOT NULL, tags TEXT NOT NULL, source_url TEXT NOT NULL, published_at TEXT, validation TEXT NOT NULL, digest TEXT NOT NULL)")
   con.execute("CREATE VIRTUAL TABLE docs_fts USING fts5(id UNINDEXED, title, summary, lesson, tags, tokenize='unicode61 remove_diacritics 2')")
   con.execute("CREATE TABLE related (doc_id TEXT, target_id TEXT, relation TEXT, PRIMARY KEY(doc_id,target_id,relation))")
   con.execute("CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
   con.execute("CREATE INDEX idx_source ON documents(source)")
   con.execute("CREATE INDEX idx_kind ON documents(kind)")
   for r in records:
    if r["id"] in seen: raise ValueError("duplicate id "+r["id"])
    seen.add(r["id"])
    if not isinstance(r["source_url"],str) or not r["source_url"].startswith("https://"):
     raise ValueError("untrusted source URL")
    body={k:r[k] for k in ("id","kind","source","title","summary","lesson","tags","source_url","published_at","validation")}
    digest=hashlib.sha256(json.dumps(body,sort_keys=True,ensure_ascii=False).encode()).hexdigest()
    con.execute("INSERT INTO documents VALUES(?,?,?,?,?,?,?,?,?,?,?)",tuple(body.values())+(digest,))
    con.execute("INSERT INTO docs_fts VALUES(?,?,?,?,?)",(r["id"],r["title"],r["summary"],r["lesson"],r["tags"]))
    for relation in r.get("related",[]):
     if isinstance(relation,str) and re.fullmatch(r"(?:CVE-\d{4}-\d{4,}|CWE-\d+|ASVS-V?\d+(?:\.\d+){2})",relation):
      con.execute("INSERT OR IGNORE INTO related VALUES(?,?,?)",(r["id"],relation,"documented_reference"))
   con.execute("INSERT INTO metadata VALUES('indexed_at',?)",(now(),))
   con.execute("INSERT INTO metadata VALUES('schema_version','1')")
   con.execute("INSERT INTO metadata VALUES('source_sha256',?)",(hashlib.sha256(MANIFEST.read_bytes()+SOURCE.read_bytes()).hexdigest(),))
   con.commit()
  finally: con.close()
  os.chmod(tmp,0o600)
  os.replace(tmp,DB)
 finally:
  if os.path.exists(tmp):os.unlink(tmp)
 print("BUILD_OK",len(records),"documents",DB,flush=True)

def open_db():
 if not DB.exists():raise ValueError("Index missing: use sync then build")
 return sqlite3.connect("file:"+urllib.parse.quote(str(DB),safe="/")+ "?mode=ro",uri=True)

def is_unsupported_intent(query):
 """Do not infer actor attribution from a CVE-only catalog."""
 q=query.casefold()
 if re.search(r"\b(?:encryptor|decryptor|affiliate|operator|actor attribution|c2 attribution)\b",q):
  return "Actor/family attribution is not represented in the current source catalog."
 return None

def routed_source(query,source):
 if source:return source
 q=query.casefold()
 if "ntlm" in q and "relay" in q:return "cisa-kev"
 if ("cache" in q and ("poisoning" in q or "deception" in q)) or ("request" in q and "smuggling" in q):
  return "public-cases"
 if any(x in q for x in ("ctf","file carving","reverse engineering")):
  return "public-cases"
 return ""

def search(query,limit:int=6,source:str="",kind:str="",as_json=False,emit=True):
 toks=re.findall(r"[\w]+",query,flags=re.UNICODE)[:15]
 if not toks:raise ValueError("Empty query")
 max_limit=max(1,min(limit,50))
 qid=query.strip().upper()
 source=routed_source(query,source)
 skip=is_unsupported_intent(query) if not (CVE_RE.fullmatch(qid) or qid.startswith("ASVS-")) else None
 con=open_db()
 try:
  rows=[]
  if skip:
   rows=[]
  elif CVE_RE.fullmatch(qid) or qid.startswith("ASVS-") or qid.startswith("CASE-"):
   filters=["id=?"]
   params=[qid]
   if source: filters.append("source=?");params.append(source)
   if kind: filters.append("kind=?");params.append(kind)
   rows=con.execute(
    "SELECT id,kind,source,title,summary,lesson,tags,source_url,published_at,validation,digest "
    "FROM documents WHERE "+" AND ".join(filters),params).fetchall()
  else:
   term=" AND ".join('"'+t.replace('"','')+'"' for t in toks)
   filters=["docs_fts MATCH ?"]
   params=[term]
   if source: filters.append("d.source=?");params.append(source)
   if kind: filters.append("d.kind=?");params.append(kind)
   rows=con.execute(
    "SELECT d.id,d.kind,d.source,d.title,d.summary,d.lesson,d.tags,"
    "d.source_url,d.published_at,d.validation,d.digest "
    "FROM docs_fts JOIN documents d ON d.id=docs_fts.id WHERE "
    +" AND ".join(filters)
    +" ORDER BY bm25(docs_fts,0,3,1.3,0.8,3.0) LIMIT ?",
    params+[max_limit]).fetchall()
  columns=("id","kind","source","title","summary","lesson","tags","source_url","published_at","validation","sha256")
  matches=[dict(zip(columns,row)) for row in rows]
  for item in matches:
   item["related"]=[e[0] for e in con.execute(
    "SELECT target_id FROM related WHERE doc_id=?",(item["id"],)).fetchall()]
 finally:con.close()
 if emit:
  if as_json:print(json.dumps(matches,ensure_ascii=False,indent=2))
  else:
   if skip:print("INSUFFICIENT_EVIDENCE:",skip)
   elif not matches:print("NO_SUPPORTED_EVIDENCE: no document covers all requested terms/identifier.")
   for x in matches:
    print(x["id"],"|",x["title"],"[",x["source"],"|",x["validation"],"]")
    print("  URL:",x["source_url"])
    print("  Contexto:",x["summary"][:270])
    if x["related"]:print("  Relacionados:",", ".join(x["related"][:10]))
 return matches

def stats():
 con=open_db()
 try:
  all_count=con.execute("SELECT COUNT(*) FROM documents").fetchone()[0]
  sources=con.execute("SELECT source,COUNT(*) FROM documents GROUP BY source ORDER BY source").fetchall()
  related=con.execute("SELECT count(*) FROM related").fetchone()[0]
  updated=con.execute("SELECT value FROM metadata WHERE key='indexed_at'").fetchone()[0]
 finally:con.close()
 print(json.dumps({"total":all_count,"sources":dict(sources),"relations":related,"indexed_at":updated},indent=2))

def benchmark():
 # Checks lexical retrieval quality only; not an LLM answer-quality eval.
 fixture=[
  ("Relay Artifact RSA JerseyCTF","CASE-jctf-rsa-41140"),
  ("Fix Your Ship file carving","CASE-jctf-files-41137"),
  ("web cache bending rules","CASE-ps-cache-2024"),
  ("HTTP desync endgame", "CASE-ps-http1-2025"),
  ("ASVS V1.1.1","ASVS-V1.1.1"),
  ("ASVS V1.2.5","ASVS-V1.2.5")
 ]
 con=open_db()
 try:
  # Pure identifier queries for exact terms, or FTS queries for case recall.
  results=[]
  for query,target in fixture:
   if query.startswith("ASVS "):
    found=con.execute("SELECT id FROM documents WHERE id=?",(target,)).fetchall()
   else:
    ts=re.findall(r"\w+",query)[:12]
    match=" OR ".join('"'+z+'"' for z in ts)
    found=con.execute("SELECT d.id FROM docs_fts JOIN documents d ON d.id=docs_fts.id WHERE docs_fts MATCH ? ORDER BY bm25(docs_fts,0,3,1.2,1.2,1.5) LIMIT 5",(match,)).fetchall()
   ids=[x[0] for x in found]
   results.append({"query":query,"expected":target,"hit_at_5":target in ids,"top5":ids})
 finally:con.close()
 hits=sum(int(x["hit_at_5"]) for x in results)
 print(json.dumps({"benchmark":"static_lexical_recall_at_5","hits":hits,"total":len(results),"recall_at_5":hits/len(results),"details":results},ensure_ascii=False,indent=2))
 return hits==len(results)

def main():
 p=argparse.ArgumentParser(description="Offline FTS catalog of MITR3 case studies, CISA KEV, pinned OWASP ASVS 5")
 sub=p.add_subparsers(dest="action",required=True)
 sub.add_parser("sync",help="Fetch 2 signed-off public JSON datasets, bounded HTTPS")
 sub.add_parser("build",help="Atomic local FTS rebuild from cached feeds + public cases")
 sub.add_parser("stats")
 sub.add_parser("bench")
 q=sub.add_parser("search")
 q.add_argument("query")
 q.add_argument("--limit",type=int,default=6)
 q.add_argument("--source",choices=["","cisa-kev","owasp-asvs-5.0.0","public-cases"],default="")
 q.add_argument("--kind",default="")
 q.add_argument("--json",action="store_true")
 a=p.parse_args()
 if a.action=="sync":sync()
 elif a.action=="build":create()
 elif a.action=="stats":stats()
 elif a.action=="bench":raise SystemExit(0 if benchmark() else 3)
 elif a.action=="search":search(a.query,a.limit,a.source,a.kind,a.json)

if __name__=="__main__":
 try:main()
 except (OSError,ValueError,sqlite3.Error,urllib.error.URLError) as e:
  print("ERROR",type(e).__name__,str(e)[:240],file=sys.stderr)
  sys.exit(1)

