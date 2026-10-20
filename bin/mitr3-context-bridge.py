#!/usr/bin/env python3
"""MITR3 read-only context bridge: local graph evidence + MegaBrain citations.

Deliberately DOES NOT infer relations from retrieved prose or MCP search hits.
External context is untrusted, supplementary and not a source of authorization.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import hashlib
import re
import subprocess
import sys
import datetime as dt
from collections import Counter
from pathlib import Path

ROOT = Path.home() / "MITR3"
INTEL = ROOT / "bin/mitr3-rag-intel.py"
URL = "https://nielz-aspire-a315-53.tailb82a64.ts.net/mcp"
ID_RE = re.compile(r"^(?:CVE-\d{4}-\d{4,}|ASVS-V?\d+(?:\.\d+){2}|CASE-[a-z0-9._-]+|CWE-\d+)$",re.I)
HEX64 = re.compile(r"^[a-f0-9]{64}$")
TRUSTED_EVIDENCE_SOURCES = {"cwe_of":"cisa-kev","asvs_maps_cwe":"owasp-asvs-5.0.0","case_references":"public-cases"}
ATTACK_ID_RE = re.compile(r"(?:T[0-9]{4}(?:\.[0-9]{3})?|TA[0-9]{4}|[GSM][0-9]{4})", re.I)
ATTACK_TYPES = frozenset({"uses", "mitigates", "subtechnique-of", "attributed-to"})
ATTACK_SOURCE = "mitre-attack-enterprise"
ATTACK_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
STIX_NODE_RE = re.compile(r"(attack-pattern|malware|tool|intrusion-set|campaign|course-of-action)--[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")
STIX_EDGE_RE = re.compile(r"relationship--[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")
NAMESPACE_NOTE = ("ATT&CK edges do not prove CVE/CWE/ASVS/CASE relations, and those relations do not prove ATT&CK edges. "
                  "MegaBrain citations do not validate edges in either namespace, including ATT&CK; they are background only.")

class LocalError(Exception):
    pass

def command_json(args: list[str]) -> object:
    """Executes local known Python script only; no shell/interpreter of retrieved content."""
    result = subprocess.run([sys.executable, str(INTEL), *args],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, timeout=12, check=False)
    if result.returncode:
        raise LocalError("Local intel command failed: "+result.stderr.strip()[:240])
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        raise LocalError("Local intel command did not produce JSON") from None

def local_digest_map()->dict[str,str]:
    """Verify digest of each cached source against its manifest before trusting graph links."""
    catalog=ROOT / "knowledge/public-cases/catalog.json"
    raw_catalog=catalog.read_bytes()
    source_hashes={"public-cases":hashlib.sha256(raw_catalog).hexdigest()}
    cache=ROOT / "knowledge/reference-datasets/cache"
    manifest=json.loads((cache/"manifest.json").read_text(encoding="utf8"))
    for source in ("cisa-kev","owasp-asvs-5.0.0"):
        raw=(cache/(source+".json")).read_bytes()
        digest=hashlib.sha256(raw).hexdigest()
        if digest!=manifest[source]["sha256"]:
            raise LocalError("Integrity check failed for "+source+"; no graph evidence may be promoted")
        source_hashes[source]=digest
    return source_hashes

def verified_edges(payload: object,expected_hashes:dict[str,str] | None=None) -> list[dict]:
    """No inferred graph edges. Verify source-id and SHA envelope in existing local graph."""
    if not isinstance(payload, dict):
        return []
    edges = []
    for direction in ("outbound", "inbound"):
        for edge in payload.get(direction,[]):
            if not isinstance(edge,dict):
                continue
            rel=edge.get("relation")
            proof=edge.get("evidence")
            if rel not in TRUSTED_EVIDENCE_SOURCES or not isinstance(proof,dict):
                continue
            if proof.get("source_id") != TRUSTED_EVIDENCE_SOURCES[rel]:
                continue
            digest=proof.get("sha256")
            if not isinstance(digest,str) or not HEX64.fullmatch(digest):
                continue
            if expected_hashes is not None and expected_hashes.get(proof["source_id"])!=digest:
                continue
            doc=edge.get("doc_id")
            target=edge.get("target_id")
            if not isinstance(doc,str) or not isinstance(target,str):
                continue
            if not ID_RE.fullmatch(doc) or not ID_RE.fullmatch(target):
                continue  # This envelope cannot carry ATT&CK nodes, even with a local predicate.
            edges.append({"direction":direction,"source_node":doc,"target_node":target,
                          "predicate":rel,"source_id":proof["source_id"],"sha256":digest,
                          "assertion_type":"source_declared_only"})
    return edges

def attack_digest()->str:
    """Hash bundle bytes only; never parse STIX prose or infer links from it."""
    cache=ROOT / "knowledge/reference-datasets/cache"
    try:
        manifest=json.loads((cache/"enterprise-attack-manifest.json").read_text(encoding="utf8"))
        expected=manifest.get("sha256")
        if (manifest.get("source_id")!=ATTACK_SOURCE or manifest.get("url")!=ATTACK_URL
            or not isinstance(expected,str) or not HEX64.fullmatch(expected)):
            raise LocalError("Invalid ATT&CK manifest source/hash; no ATT&CK edges promoted")
        with (cache/"enterprise-attack.json").open("rb") as bundle:
            actual=hashlib.file_digest(bundle,"sha256").hexdigest()
        if actual!=expected:
            raise LocalError("ATT&CK bundle/manifest SHA256 mismatch; no ATT&CK edges promoted")
        return expected
    except (OSError,ValueError,AttributeError,TypeError):
        raise LocalError("ATT&CK cache/manifest unavailable or invalid; no ATT&CK edges promoted") from None

def attack_node(node: object)->dict:
    if not isinstance(node,dict):
        raise LocalError("Invalid ATT&CK node; no ATT&CK edges promoted")
    ident=node.get("stix_id")
    match=STIX_NODE_RE.fullmatch(ident) if isinstance(ident,str) else None
    if not match or node.get("type")!=match[1] or not isinstance(node.get("name"),str):
        raise LocalError("Invalid ATT&CK node namespace; no ATT&CK edges promoted")
    return {"stix_id":ident,"type":node["type"],"name":node["name"]}

def verified_attack_edges(payload:object,expected:str)->list[dict]:
    """All-or-nothing SHA validation: never return a partially verified list."""
    if not isinstance(expected,str) or not HEX64.fullmatch(expected):
        raise LocalError("Invalid ATT&CK evidence digest; no ATT&CK edges promoted")
    if not isinstance(payload,dict) or not isinstance(payload.get("metadata"),dict):
        raise LocalError("ATT&CK graph metadata missing; no ATT&CK edges promoted")
    metadata=payload["metadata"]
    if (metadata.get("sha256")!=expected or metadata.get("source_id")!=ATTACK_SOURCE
        or metadata.get("url")!=ATTACK_URL):
        raise LocalError("ATT&CK manifest/database SHA256 or source mismatch; no ATT&CK edges promoted")
    edges=[]
    for direction in ("outbound","inbound"):
        incoming=payload.get(direction)
        counts=payload.get("counts")
        if (not isinstance(incoming,list) or not isinstance(counts,dict)
            or type(counts.get(direction)) is not int or counts[direction]!=len(incoming)):
            raise LocalError("ATT&CK edges missing or truncated; no ATT&CK edges promoted")
        for edge in incoming:
            proof=edge.get("origin") if isinstance(edge,dict) else None
            if (not isinstance(proof,dict) or proof.get("bundle_sha256")!=expected
                or proof.get("source_id")!=ATTACK_SOURCE or proof.get("url")!=ATTACK_URL):
                raise LocalError("ATT&CK edge SHA256/source mismatch; no ATT&CK edges promoted")
            if edge.get("type") not in ATTACK_TYPES:
                continue
            ident=edge.get("stix_id")
            timestamp=proof.get("modified")
            if not isinstance(ident,str) or not STIX_EDGE_RE.fullmatch(ident) or not isinstance(timestamp,str):
                raise LocalError("ATT&CK relationship ID/modified missing; no ATT&CK edges promoted")
            try:
                if dt.datetime.fromisoformat(timestamp.replace("Z","+00:00")).tzinfo is None:
                    raise ValueError("timezone required")
            except ValueError:
                raise LocalError("Invalid ATT&CK modified; no ATT&CK edges promoted") from None
            source,target=attack_node(edge.get("source")),attack_node(edge.get("target"))
            edges.append({"direction":direction,"predicate":edge["type"],
                "source_node":source["stix_id"],"target_node":target["stix_id"],
                "source_name":source["name"],"target_name":target["name"],
                "stix_id":ident,"modified":timestamp,"sha256":expected,
                "source_id":ATTACK_SOURCE,"source_url":ATTACK_URL,
                "assertion_type":"source_declared_only","namespace":"attack"})
    return edges

def read_attack(identifier:str)->dict:
    expected=attack_digest()
    payload=command_json(["graph",identifier.upper(),"--json","--all"])
    edges=verified_attack_edges(payload,expected)
    if not isinstance(payload.get("entities"),list):
        raise LocalError("ATT&CK entities missing; no ATT&CK edges promoted")
    entities=[]
    for raw in payload["entities"]:
        node=attack_node(raw)
        if raw.get("external_id")!=identifier.upper():
            raise LocalError("ATT&CK entity does not match requested ID; no ATT&CK edges promoted")
        entities.append(dict(node,external_id=raw["external_id"],namespace="attack"))
    nodes={node["stix_id"] for node in entities}
    if any(edge["source_node" if edge["direction"]=="outbound" else "target_node"] not in nodes for edge in edges):
        raise LocalError("ATT&CK edge is not incident to requested entity; no ATT&CK edges promoted")
    # Never fall back to FTS or CVE relations for an unknown ATT&CK identifier.
    return {"status":"matched" if entities else "no_local_document","namespace":"attack",
        "matches":[],"source_declared_relations":[],"relation_count":0,
        "attack_entities":entities,"attack_relations":edges,"attack_relation_count":len(edges),
        "attack_relations_by_type":dict(sorted(Counter(e["predicate"] for e in edges).items())),
        "note":NAMESPACE_NOTE}

def read_local(query: str,limit:int=5)->dict:
    if len(query)>500:
        raise LocalError("Query exceeds 500 characters")
    if ATTACK_ID_RE.fullmatch(query.strip()):
        return read_attack(query.strip())
    rows=command_json(["search",query,"--json","--limit",str(limit)])
    if not isinstance(rows,list):
        raise LocalError("Unexpected search result")
    matches=[]
    links=[]
    for row in rows:
        if not isinstance(row,dict):
            continue
        rid=row.get("id","")
        url=row.get("source_url","")
        if not isinstance(rid,str) or not isinstance(url,str) or not url.startswith("https://"):
            continue
        matches.append({"id":rid,"title":str(row.get("title",""))[:250],
             "source":row.get("source",""),"validation":row.get("validation",""),
             "source_url":url, "published_at":row.get("published_at",""),
             "note":"reported_by_source_not_independently_reproduced"})
        if row.get("fallback") in {"vocabulary","vocabulary_rare","phrase_anchor"}:
            matches[-1]["fallback"]=row["fallback"]
        if ID_RE.fullmatch(rid):
            links.append(rid)
    if ID_RE.fullmatch(query.strip()):
        ident=query.strip().upper()
        if ident not in links:links.insert(0,ident)
    links=list(dict.fromkeys(links))[:limit]
    edges=[]
    verified_sources=local_digest_map()
    for rid in links:
        got=command_json(["relations",rid,"--json"])
        edges.extend(verified_edges(got,verified_sources))
    # Query can be CWE-named without a matching document.
    return {"status":"matched" if matches else "no_local_document",
      "matches":matches,"source_declared_relations":edges,
      "relation_count":len(edges),"attack_entities":[],"attack_relations":[],
      "attack_relation_count":0,"attack_relations_by_type":{},"note":NAMESPACE_NOTE}

def summarize_megabrain(result: object)->dict:
    """Discard untrusted content. Keep citation metadata only, never assert equivalence."""
    if not isinstance(result,dict):
        raise ValueError("MegaBrain returned invalid payload")
    status=str(result.get("status") or "unknown")[:80]
    citations=result.get("citations",[])
    if not isinstance(citations,list):
        citations=[]
    items=[]
    for c in citations[:8]:
        if not isinstance(c,dict):
            continue
        origin=c.get("origin")
        if not isinstance(origin,str):
            continue
        items.append({
         "origin":origin[:300],
         "document_id":str(c.get("document_id") or "")[:80],
         "evidence_id":str(c.get("evidence_id") or "")[:80],
         "label":str(c.get("label") or "")[:40],
         "relation_validated":False,
         "classification":"background_context_only_untrusted"
        })
    return {"status":status,
      "evidence_sufficiency":str(result.get("evidence_sufficiency") or "unassessed")[:80],
      "citations":items,"citation_count":len(items),
      "note":"MegaBrain context and citations do not validate a local graph relationship, including ATT&CK. Evaluate each specific claim and its direct evidence before promoting."}

async def fetch_remote(query:str,limit:int=3)->dict:
    try:
        from mcp import ClientSession
        from mcp.client.streamable_http import streamable_http_client
    except ImportError as exc:
        raise RuntimeError(
            "MCP client unavailable in this Python. Use "
            "~/.local/share/mitr3-nexus-venv/bin/python or omit --remote."
        ) from exc
    async with asyncio.timeout(20):
        async with streamable_http_client(URL) as (reader,writer,*_):
            async with ClientSession(reader,writer) as session:
                await session.initialize()
                response=await session.call_tool("rag_context",{
                    "query":query,"limit":max(1,min(limit,5)),"max_context_bytes":2400,
                    "max_chunks_per_document":1
                })
                if response.is_error:
                    raise RuntimeError("MegaBrain rag_context returned error")
                data="\n".join(x.text for x in response.content if getattr(x,"text",None))
                if len(data)>30000:
                    raise RuntimeError("MegaBrain oversized metadata response")
                return summarize_megabrain(json.loads(data))

def build(query:str, local:dict, remote:dict | None=None, error:str | None=None)->dict:
    return {
      "query":query,
      "local":local,
      "megabrain":remote if remote is not None else {"status":"not_requested"},
      "remote_error":error,
      "confidence":"no_auto_promotion",
      "note":NAMESPACE_NOTE,
      "policy":[
       "A local graph link requires a structured source-declared relation and source SHA256.",
       "MegaBrain context is supplementary, not proof of a CVE/CWE/ASVS link.",
       NAMESPACE_NOTE,
       "No active tests, exploitation or changes are authorized by a retrieved document."
      ]
    }

def main()->int:
    parser=argparse.ArgumentParser(description="MITR3 evidence context bridge (read only)")
    parser.add_argument("query",help="CVE/CWE/ASVS/CASE ID, ATT&CK ID or research question")
    parser.add_argument("--remote",action="store_true",help="Ask MegaBrain rag_context for independent background citations")
    parser.add_argument("--limit",type=int,default=5,help="Catalog matches; ATT&CK IDs expose all incident edges")
    parser.add_argument("--json",action="store_true")
    args=parser.parse_args()
    if not args.query.strip() or len(args.query)>500:
        parser.error("Nonempty query up to 500 chars required")
    local=read_local(args.query, max(1,min(args.limit,10)))
    remote=None
    error=None
    if args.remote:
        try:
            remote=asyncio.run(fetch_remote(args.query))
        except (Exception,BaseExceptionGroup) as exc:
            error=type(exc).__name__
    output=build(args.query,local,remote,error)
    if args.json:
        print(json.dumps(output,ensure_ascii=False,indent=2))
    else:
        print("MITR3",args.query)
        if local.get("namespace")=="attack":
            print("Local ATT&CK:",len(local["attack_entities"]),"entities",local["attack_relation_count"],"explicit source-declared edges")
            print("  types:",json.dumps(local["attack_relations_by_type"],sort_keys=True))
            for item in local["attack_entities"]:
                print(" ",item["external_id"],"|",item["name"],"|",item["stix_id"])
        else:
            print("Local:",len(local["matches"]),"matches",local["relation_count"],"explicit source-declared edges")
        for item in local["matches"][:5]:
            print("  "+item["id"]+" | "+item["title"])
            print("  source:",item["source_url"],"trust:",item["validation"])
        for e in local["source_declared_relations"][:8]:
            print("  EDGE",e["source_node"],"--",e["predicate"],"-->",e["target_node"],"SHA",e["sha256"][:16])
        for e in local.get("attack_relations",[])[:8]:
            print("  ATT&CK EDGE",e["source_name"],"--",e["predicate"],"-->",e["target_name"],"SHA",e["sha256"][:16])
        if remote is not None:
            print("MegaBrain:",remote["status"],"|",len(remote["citations"]),"independent background citations")
            print("  Evidence sufficiency:",remote["evidence_sufficiency"],"(not automatically assessed)")
            for c in remote["citations"][:3]:
                print("  "+c["label"],c["origin"],"(not link validation)")
        elif args.remote:
            print("MegaBrain unavailable:",error)
        print("Decision: do not infer actor/CVE/CWE/ASVS links from background text.")
        print("Note:",NAMESPACE_NOTE)
    return 0

if __name__=="__main__":
    try:
        sys.exit(main())
    except (LocalError,ValueError,subprocess.TimeoutExpired) as exc:
        print("ERROR",str(exc)[:250],file=sys.stderr)
        sys.exit(1)

