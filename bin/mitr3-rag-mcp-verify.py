#!/usr/bin/env python3
"""Validate remote MegaBrain readback, never print/restore secret-bearing text."""
import asyncio
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

ROOT=Path(__file__).resolve().parents[1]
RECEIPTS=ROOT/"state/public-rag-mcp-receipts.json"
CATALOG=ROOT/"knowledge/public-cases/catalog.json"
OUT=ROOT/"state/public-rag-mcp-qa.json"
URL="https://nielz-aspire-a315-53.tailb82a64.ts.net/mcp"

async def main():
    receipts=json.loads(RECEIPTS.read_text())
    records={x["id"]:x for x in json.loads(CATALOG.read_text())}
    results=[]
    async with asyncio.timeout(120):
        async with streamable_http_client(URL) as (r,w,*_):
            async with ClientSession(r,w) as c:
                await c.initialize()
                for origin,receipt in receipts.items():
                    docid=receipt.get("document_id")
                    ok=False
                    reason="not_checked"
                    try:
                        if not docid:
                            reason="no_document_id"
                        else:
                            out=await c.call_tool("knowledge_read",{"document_id":docid,"max_chars":12000})
                            payload="\n".join(x.text for x in out.content if getattr(x,"text",None))
                            obj=json.loads(payload)
                            body=obj.get("safe_content","")
                            expected=records[receipt["id"]]["source_url"]
                            ok=(not out.is_error and obj.get("found") and isinstance(body,str)
                                and expected in body and receipt["id"] in body)
                            reason="readable" if ok else ("redacted_by_server" if "REDACTED" in body else "missing_metadata_or_body")
                    except Exception:
                        reason="read_error"
                    results.append({"id":receipt["id"],"origin":origin,"readback_ok":bool(ok),"reason":reason})
                    print(receipt["id"],reason,flush=True)
    summary={"at_utc":datetime.now(timezone.utc).isoformat(),"total":len(results),
             "readable":sum(x["readback_ok"] for x in results),
             "needs_review":sum(not x["readback_ok"] for x in results),
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

