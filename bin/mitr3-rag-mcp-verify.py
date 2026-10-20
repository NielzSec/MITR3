#!/usr/bin/env python3
"""Validate remote MegaBrain readback, never print/restore secret-bearing text."""
import asyncio
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
RECEIPTS=ROOT/"state/public-rag-mcp-receipts.json"
CATALOG=ROOT/"knowledge/public-cases/catalog.json"
OUT=ROOT/"state/public-rag-mcp-qa.json"
URL="https://nielz-aspire-a315-53.tailb82a64.ts.net/mcp"

def classify_readback(obj:dict,expected_url:str,record_id:str,tool_error:bool=False)->dict:
    """Metadata-only redaction QA; never store or print source document body."""
    body=obj.get("safe_content")
    redacted=isinstance(body,str) and body.startswith("[REDACTED:") and body.endswith("]")
    reported=obj.get("content_redacted")
    accessible=(not tool_error and obj.get("found") is True and isinstance(body,str)
                and not redacted and expected_url in body and record_id in body)
    if accessible:
        reason="readable"
    elif redacted:
        reason="redacted_by_server"
    else:
        reason="missing_metadata_or_body"
    return {
      "readback_ok":bool(accessible),
      "reason":reason,
      "safe_content_placeholder":bool(redacted),
      "server_content_redacted":reported if isinstance(reported,bool) else None,
      "redaction_flag_mismatch":bool(redacted and reported is False),
      "index_status":str(obj.get("index_status","unknown"))[:40],
      "found":obj.get("found") is True,
      "indexed_chunks":obj.get("indexed_chunks") if isinstance(obj.get("indexed_chunks"),int) else None
    }

async def main():
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client
    receipts=json.loads(RECEIPTS.read_text())
    records={x["id"]:x for x in json.loads(CATALOG.read_text())}
    results=[]
    async with asyncio.timeout(120):
        async with streamable_http_client(URL) as (r,w,*_):
            async with ClientSession(r,w) as c:
                await c.initialize()
                for origin,receipt in receipts.items():
                    docid=receipt.get("document_id")
                    detail={"readback_ok":False,"reason":"not_checked","safe_content_placeholder":False,
                            "server_content_redacted":None,"redaction_flag_mismatch":False,
                            "index_status":"unknown","found":False,"indexed_chunks":None}
                    try:
                        if not docid:
                            detail["reason"]="no_document_id"
                        else:
                            out=await c.call_tool("knowledge_read",{"document_id":docid,"max_chars":12000})
                            payload="\n".join(x.text for x in out.content if getattr(x,"text",None))
                            obj=json.loads(payload)
                            detail=classify_readback(obj,records[receipt["id"]]["source_url"],receipt["id"],out.is_error)
                    except Exception:
                        detail["reason"]="read_error"
                    reason=detail["reason"]
                    results.append({"id":receipt["id"],"origin":origin,**detail})
                    print(receipt["id"],reason,flush=True)
    summary={"at_utc":datetime.now(timezone.utc).isoformat(),"total":len(results),
             "readable":sum(x["readback_ok"] for x in results),
             "needs_review":sum(not x["readback_ok"] for x in results),
             "redacted_count":sum(x["safe_content_placeholder"] for x in results),
             "redaction_flag_mismatches":sum(x["redaction_flag_mismatch"] for x in results),
             "records":results}
    fd,p=tempfile.mkstemp(prefix=".public-rag-qa-",dir=OUT.parent)
    try:
        with os.fdopen(fd,"w") as f: json.dump(summary,f,indent=2)
        os.chmod(p,0o600)
        os.replace(p,OUT)
    finally:
        if os.path.exists(p): os.unlink(p)
    print("QA_TOTAL",summary["total"],"READABLE",summary["readable"],"NEEDS_REVIEW",summary["needs_review"])

if __name__=="__main__":
    asyncio.run(main())

