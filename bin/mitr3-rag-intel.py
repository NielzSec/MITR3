#!/usr/bin/env python3
"""MITR3 Intel RAG: independent local index of reviewed cases + pinned public JSON feeds.
Uses only Python stdlib; no PoC execution, scanning, untrusted remote commands, or bulk MCP upload.
"""
from __future__ import annotations
import argparse, collections, datetime as dt, hashlib, json, os, re, sqlite3, sys, tempfile
import urllib.request, urllib.parse
import unicodedata
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
STOPWORDS=frozenset("a an the of for and or to in on with from by is are was were that this it as at".split())
RELATION_SOURCES={"cwe_of":"cisa-kev", "asvs_maps_cwe":"owasp-asvs-5.0.0",
                  "case_references":"public-cases"}
CWE_RE=re.compile(r"^CWE-\d+$",re.ASCII)
TARGET_RE=re.compile(r"(?:CVE-\d{4}-\d{4,}|CWE-\d+|ASVS-V?\d+(?:\.\d+){2}|CASE-[a-zA-Z0-9._-]+)",re.ASCII)
ROUTED_SOURCE_BOOST=0.15
ACTOR_ROLE_RE=re.compile(r"\b(?:affiliates?|afiliad[oa]s?|operators?|operador(?:es)?|operadoras?|participants?|participantes?)\b")
THREAT_CONTEXT_RE=re.compile(r"\b(?:ransomware|malware|esxi|lockbit|actors?|ator(?:es)?|c2|campaigns?|campanhas?|gangs?|quadrilhas?|criminal|criminos[oa]s?)\b")
ASSOCIATED_ROLE_RE=re.compile(r"\b(?:partners?|parceir[oa]s?|members?|membros?|associates?|associad[oa]s?)\b")
ATTRIBUTION_RE=re.compile(r"\b(?:attributions?|atribuicao|atribuicoes)\b")
CAMPAIGN_RE=re.compile(r"\b(?:campaigns?|campanhas?)\b")
CAMPAIGN_ROLE_RE=re.compile(r"\b(?:who|whom|quem|behind|por tras|responsavel|responsaveis|involved|involvement|envolvid[oa]s?|envolvimento)\b")

def declared_relations(targets,relation,evidence):
 """Accept structured declarations only; no prose extraction or inferred edges."""
 if not isinstance(relation,str) or relation not in RELATION_SOURCES:return []
 if not isinstance(evidence,dict) or evidence.get("source_id")!=RELATION_SOURCES.get(relation):return []
 if not isinstance(evidence.get("sha256"),str) or not re.fullmatch(r"[0-9a-f]{64}",evidence["sha256"]):return []
 if not isinstance(targets,list):return []
 pattern=TARGET_RE if relation=="case_references" else CWE_RE
 return [{"target_id":target,"relation":relation,
          "evidence":{"source_id":evidence["source_id"],"sha256":evidence["sha256"]}}
         for target in sorted({t for t in targets if isinstance(t,str) and pattern.fullmatch(t)})]

def asvs_cwes(item):
 # Only explicit structured fields, never CWE-looking text in Description.
 # The pinned 5.0.0 feed currently has none. These spellings are opt-in fields;
 # unsupported shapes/fields yield no mapping rather than a guessed relation.
 return [target for key in ("CWE","CWEs","cwes")
         for target in (item[key] if isinstance(item.get(key),list) else [])]

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

def asvs_rows(data:dict,evidence=None):
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
      "validation":"published_standard_not_tested", "related":[],
      "relations":declared_relations(asvs_cwes(item),"asvs_maps_cwe",evidence)}

def cisa_rows(data:dict,evidence=None):
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
    "validation":"official_catalog_not_locally_tested","related":cwes,
    "relations":declared_relations(row.get("cwes"),"cwe_of",evidence)}

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

def public_rows(items=None,evidence=None):
 if items is None:items=json.loads(SOURCE.read_text(encoding="utf-8"))
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
      "validation":a["validation"],"related":a.get("related",[]),
      "relations":declared_relations(a.get("related"),"case_references",evidence)}

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
 # Parse and hash the same catalog bytes; feed hashes were verified above.
 catalog=SOURCE.read_bytes()
 records=list(public_rows(json.loads(catalog),{"source_id":"public-cases","sha256":hashlib.sha256(catalog).hexdigest()}))
 records.extend(cisa_rows(feeds["cisa-kev"],{"source_id":"cisa-kev","sha256":manifest["cisa-kev"]["sha256"]}))
 records.extend(asvs_rows(feeds["owasp-asvs-5.0.0"],{"source_id":"owasp-asvs-5.0.0","sha256":manifest["owasp-asvs-5.0.0"]["sha256"]}))
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
   con.execute("PRAGMA foreign_keys=ON")
   con.execute("CREATE TABLE documents (id TEXT PRIMARY KEY, kind TEXT NOT NULL, source TEXT NOT NULL, title TEXT NOT NULL, summary TEXT NOT NULL, lesson TEXT NOT NULL, tags TEXT NOT NULL, source_url TEXT NOT NULL, published_at TEXT, validation TEXT NOT NULL, digest TEXT NOT NULL)")
   con.execute("CREATE VIRTUAL TABLE docs_fts USING fts5(id UNINDEXED, title, summary, lesson, tags, tokenize='unicode61 remove_diacritics 2')")
   con.execute("""CREATE TABLE related (
     doc_id TEXT NOT NULL REFERENCES documents(id), target_id TEXT NOT NULL,
     relation TEXT NOT NULL CHECK(relation IN ('cwe_of','asvs_maps_cwe','case_references')),
     evidence TEXT NOT NULL CHECK(json_valid(evidence)
       AND json_type(evidence,'$.source_id') IS 'text'
       AND json_extract(evidence,'$.source_id')=CASE relation
         WHEN 'cwe_of' THEN 'cisa-kev' WHEN 'asvs_maps_cwe' THEN 'owasp-asvs-5.0.0'
         WHEN 'case_references' THEN 'public-cases' END
       AND json_type(evidence,'$.sha256') IS 'text'
       AND length(json_extract(evidence,'$.sha256'))=64
       AND json_extract(evidence,'$.sha256') NOT GLOB '*[^0-9a-f]*'),
     PRIMARY KEY(doc_id,target_id,relation))""")
   con.execute("CREATE INDEX idx_related_target ON related(target_id)")
   con.execute("""CREATE TRIGGER related_target_exists BEFORE INSERT ON related
     WHEN NOT EXISTS (SELECT 1 FROM documents WHERE id=NEW.target_id)
       AND NOT (NEW.target_id GLOB 'CWE-[0-9]*' AND substr(NEW.target_id,5) NOT GLOB '*[^0-9]*')
     BEGIN SELECT RAISE(ABORT,'Relation target must exist or be a declared external CWE'); END""")
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
   # Targets can be documents appearing later in the input. Never synthesize a
   # missing CVE/ASVS/case node or derive CVE->ASVS from their common CWE.
   for r in records:
    for edge in r.get("relations",[]):
     relation=edge.get("relation")
     if RELATION_SOURCES.get(relation)!=r["source"]:continue
     verified=declared_relations([edge.get("target_id")],relation,edge.get("evidence"))
     for edge in verified:
      if edge["target_id"] not in seen and not CWE_RE.fullmatch(edge["target_id"]):continue
      con.execute("INSERT OR IGNORE INTO related VALUES(?,?,?,?)",
                  (r["id"],edge["target_id"],relation,json.dumps(edge["evidence"],sort_keys=True)))
   con.execute("INSERT INTO metadata VALUES('indexed_at',?)",(now(),))
   con.execute("INSERT INTO metadata VALUES('schema_version','2')")
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

def relations(identifier,as_json=False,emit=True):
 """Return direct declarations in both directions, including external CWE nodes."""
 identifier=identifier.strip()
 identifier=("CASE-"+identifier[5:]) if identifier.upper().startswith("CASE-") else identifier.upper()
 con=open_db()
 try:
  if "evidence" not in {r[1] for r in con.execute("PRAGMA table_info(related)")}:
   raise ValueError("Relation evidence unavailable in legacy index: run build")
  def edges(column):
   return [{"doc_id":doc,"target_id":target,"relation":relation,"evidence":json.loads(evidence)}
           for doc,target,relation,evidence in con.execute(
            "SELECT doc_id,target_id,relation,evidence FROM related WHERE "+column+"=? "
            "ORDER BY doc_id,target_id,relation",(identifier,))]
  result={"id":identifier,"outbound":edges("doc_id"),"inbound":edges("target_id")}
 finally:con.close()
 if emit:
  if as_json:print(json.dumps(result,ensure_ascii=False,indent=2))
  else:
   for direction in ("outbound","inbound"):
    print(direction+":")
    for edge in result[direction]:
     print(" ",edge["doc_id"],"--"+edge["relation"]+"-->",edge["target_id"])
     print("   evidence:",json.dumps(edge["evidence"],sort_keys=True))
 return result

def is_unsupported_intent(query):
 """Actor roles need actor evidence; source code/builders are artifacts, not roles."""
 q="".join(c for c in unicodedata.normalize("NFKD",query.casefold()) if not unicodedata.combining(c))
 if re.search(r"\b(?:encryptor|decryptor)\b",q):
  return "Encryptor/decryptor capability is not represented in the current source catalog."
 if (ACTOR_ROLE_RE.search(q)
     or (THREAT_CONTEXT_RE.search(q) and (ASSOCIATED_ROLE_RE.search(q) or ATTRIBUTION_RE.search(q)))
     or (CAMPAIGN_RE.search(q) and CAMPAIGN_ROLE_RE.search(q))):
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
 raw=[t.lower() for t in re.findall(r"[\w]+",query,flags=re.UNICODE)]
 toks=[t for t in raw if t not in STOPWORDS][:15] or raw[:15]
 if not toks:raise ValueError("Empty query")
 max_limit=max(1,min(limit,50))
 qid=query.strip().upper()
 # Only an explicit --source constrains retrieval. Automatic routing is a small
 # ranking preference; a product/CVE/standard in another corpus must survive it.
 preferred_source=routed_source(query,"") if not source else ""
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
   # Qualquer termo entra como candidato; a cobertura decide o corte. AND estrito
   # quebra consulta real de 4+ termos; OR puro enche de filler. Meio-termo: exige
   # >=60% dos termos distintos (arredonda para cima). Cobertura tem prioridade;
   # bm25 e o pequeno vies de fonte ordenam dentro da mesma cobertura.
   uniq=sorted(set(toks))
   need=max(1,-(-len(uniq)*3//5))
   term=" OR ".join('"'+t.replace('"','')+'"' for t in uniq)
   filters=["docs_fts MATCH ?"]
   params=[term]
   if source: filters.append("d.source=?");params.append(source)
   if kind: filters.append("d.kind=?");params.append(kind)
   rows=con.execute(
    "SELECT d.id,d.kind,d.source,d.title,d.summary,d.lesson,d.tags,"
    "d.source_url,d.published_at,d.validation,d.digest,bm25(docs_fts,0,3,1.3,0.8,3.0) "
    "FROM docs_fts JOIN documents d ON d.id=docs_fts.id WHERE "
    +" AND ".join(filters)
    +" ORDER BY bm25(docs_fts,0,3,1.3,0.8,3.0) LIMIT ?",
    params+[max(60,max_limit*12)]).fetchall()
   ranked=[]
   for candidate in rows:
    row,bm25=candidate[:-1],candidate[-1]
    words=set(re.findall(r"[\w]+"," ".join(str(x).lower() for x in row[3:7])))
    cover=sum(1 for t in uniq if t in words)
    # BM25 is negative (lower is better). Its bounded bonus preserves coverage
    # priority: BM25 (<0.5) + source (0.15) cannot replace a missing query term.
    score=cover+0.5*(-bm25)/(1+abs(bm25))
    if row[2]==preferred_source:score+=ROUTED_SOURCE_BOOST
    if cover>=need: ranked.append((score,row))
   ranked.sort(key=lambda x:-x[0])
   rows=[row for _,row in ranked[:max_limit]]
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
  relation_types={relation:0 for relation in RELATION_SOURCES}
  relation_types.update(con.execute("SELECT relation,count(*) FROM related GROUP BY relation ORDER BY relation"))
  updated=con.execute("SELECT value FROM metadata WHERE key='indexed_at'").fetchone()[0]
 finally:con.close()
 print(json.dumps({"total":all_count,"sources":dict(sources),"relations":related,"relations_by_type":relation_types,"indexed_at":updated},indent=2))

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
 r=sub.add_parser("relations",help="Direct outbound/inbound source declarations with feed evidence")
 r.add_argument("id")
 r.add_argument("--json",action="store_true")
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
 elif a.action=="relations":relations(a.id,a.json)
 elif a.action=="search":search(a.query,a.limit,a.source,a.kind,a.json)

if __name__=="__main__":
 try:main()
 except (OSError,ValueError,sqlite3.Error,urllib.error.URLError) as e:
  print("ERROR",type(e).__name__,str(e)[:240],file=sys.stderr)
  sys.exit(1)

