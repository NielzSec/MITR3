#!/usr/bin/env python3
"""Idempotent, source-linked original card sync to private MegaBrain MCP.

Use the existing trusted Tailscale endpoint; outputs never include document text.
"""
from __future__ import annotations
import argparse
import asyncio
import hashlib
import json
import os
import re
import tempfile
from pathlib import Path
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

ROOT = Path(__file__).resolve().parents[1]
READY = ROOT / "knowledge/public-cases/ready"
MANIFEST = READY / "manifest.json"
RECEIPTS = ROOT / "state/public-rag-mcp-receipts.json"
URL = "https://nielz-aspire-a315-53.tailb82a64.ts.net/mcp"
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)

def save_receipts(data: dict) -> None:
    RECEIPTS.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(dir=RECEIPTS.parent, prefix=".public-rag-receipts-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            json.dump(data, out, ensure_ascii=False, indent=2)
            out.write("\n")
            out.flush()
            os.fsync(out.fileno())
        os.chmod(name, 0o600)
        os.replace(name, RECEIPTS)
    finally:
        if os.path.exists(name): os.unlink(name)

def get_text(result) -> str:
    if getattr(result, "is_error", False):
        raise RuntimeError("Remote MCP returned tool error")
    return "\n".join(x.text for x in result.content if getattr(x, "text", None))

async def publish(limit: int, dry_run: bool) -> None:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    prev = json.loads(RECEIPTS.read_text(encoding="utf-8")) if RECEIPTS.exists() else {}
    entries = []
    for item in manifest:
        path = Path(item["path"]).resolve()
        if path.parent != READY.resolve() or path.name != item["id"] + ".md":
            raise ValueError("Unexpected manifest path")
        contents = path.read_bytes()
        digest = hashlib.sha256(contents).hexdigest()
        if digest != item["sha256"]:
            raise ValueError("Checksum mismatch: " + item["id"])
        if prev.get(item["origin"], {}).get("sha256") == digest:
            continue
        if len(contents) > 7000:
            raise ValueError("Too large for original summary: " + item["id"])
        entries.append((item, contents.decode("utf-8"), digest))
    if dry_run:
        print("DRY_RUN pending:", len(entries), "skipped existing:", len(manifest) - len(entries))
        return
    print("PENDING",len(entries),"already synced",len(manifest)-len(entries),flush=True)
    async with asyncio.timeout(175):
        async with streamable_http_client(URL) as (r, w, *_):
            async with ClientSession(r, w) as client:
                await client.initialize()
                count = 0
                for item, body, digest in entries:
                    if count >= limit: break
                    result = await client.call_tool("knowledge_store", {
                        "text": body, "title": "MITR3 Public RAG — " + item["title"],
                        "origin": item["origin"]
                    })
                    response = get_text(result)
                    if any(x in response.lower() for x in ('"error"', '"status":"error"', "permission denied", "internal server error")):
                        raise RuntimeError("MCP rejected " + item["id"])
                    ids = UUID.findall(response)
                    prev[item["origin"]] = {"id":item["id"], "sha256":digest, "document_id":ids[0] if ids else None}
                    save_receipts(prev)
                    count += 1
                    print("STORED", item["id"], "id", ids[0] if ids else "not_returned", flush=True)
                print("SYNC_DONE",count,"total_receipts",len(prev),flush=True)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=16)
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    asyncio.run(publish(max(0, min(a.limit, 50)), a.dry_run))

if __name__ == "__main__":
    try: main()
    except BaseException as e:
        def show(error):
            if isinstance(error, BaseExceptionGroup):
                for inner in error.exceptions: show(inner)
            else:
                print("ERROR",type(error).__name__,str(error)[:160],flush=True)
        show(e)
        raise SystemExit(1)

