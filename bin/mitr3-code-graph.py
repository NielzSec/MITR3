#!/usr/bin/env python3
"""MITR3 Attack Graph, Layer 3: code and attack-chain graph in the unified SQLite file.

Consumes the Layer 2 JSON-L export (bin/mitr3-graph-normalizer.py --jsonl) and stores it in
state/mitr3-attack.sqlite3 next to, never inside, the STIX ATT&CK tables
(entities/edges/metadata). Deterministic and offline: no network, no LLM.

Layer 3 records structure only. Every edge it writes is a STRUCTURAL_HYPOTHESIS; promotion to
FEASIBLE_PATH or PROVEN belongs to Layer 4 (Evidence & Verification). MITIGATED_BY is an
annotation on a finding, never a deletion and never an automatic suppression.

Three different hashes, never mixed:
  content_sha256   canonical hash of the row's own fields (detects change of the row)
  evidence_sha256  provenance hash supplied by Layer 2 (what the row was derived from)
  snapshot sha256  hash over every node and edge id/type/content/evidence (reproducible graph state)
"""
from __future__ import annotations

import argparse
from contextlib import closing
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import sys
import urllib.parse

ROOT = Path(__file__).resolve().parents[1]
DB = ROOT / "state/mitr3-attack.sqlite3"
SCHEMA_VERSION = "1"
MAX_INPUT_BYTES = 64_000_000
MAX_RECORDS = 500_000
MAX_TEXT = 4096
MAX_ID = 2048
MAX_EDGE_ID = 4400
NODE_TYPES = frozenset({"SOURCE", "FINDING", "SINK", "MITIGATION", "ATTACK_TECHNIQUE"})
EDGE_SHAPE = {"FLOWS_TO": ("SOURCE", "FINDING"), "CALLS": ("FINDING", "SINK"),
              "MITIGATED_BY": ("FINDING", "MITIGATION"), "MAPS_TO": ("FINDING", "ATTACK_TECHNIQUE")}
STATE_RANK = {"STRUCTURAL_HYPOTHESIS": 0, "FEASIBLE_PATH": 1, "PROVEN": 2}
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
TECHNIQUE_ID = re.compile(r"T\d{4}(?:\.\d{3})?\Z")
LAYER3_TABLES = ("code_graph_meta", "attack_nodes", "attack_edges", "technique_links",
                 "graph_snapshots", "attack_revisions")

_HEX = "length({c})=64 AND {c} NOT GLOB '*[^0-9a-f]*'"
DDL = """
BEGIN;
CREATE TABLE code_graph_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE attack_nodes (
  id TEXT PRIMARY KEY CHECK(length(id) BETWEEN 1 AND 2048),
  type TEXT NOT NULL CHECK(type IN ('SOURCE','FINDING','SINK','MITIGATION','ATTACK_TECHNIQUE')),
  name TEXT NOT NULL CHECK(length(name)>0),
  file TEXT,
  line INTEGER CHECK(line IS NULL OR line>=1),
  severity TEXT,
  confidence TEXT,
  content_sha256 TEXT NOT NULL CHECK(%(content)s),
  evidence_sha256 TEXT NOT NULL CHECK((type='ATTACK_TECHNIQUE' AND evidence_sha256='') OR (%(evidence)s)),
  metadata TEXT NOT NULL CHECK(json_valid(metadata)));
CREATE TABLE attack_edges (
  id TEXT PRIMARY KEY CHECK(length(id) BETWEEN 1 AND 4400),
  type TEXT NOT NULL CHECK(type IN ('FLOWS_TO','CALLS','MITIGATED_BY','MAPS_TO')),
  source_id TEXT NOT NULL REFERENCES attack_nodes(id),
  target_id TEXT NOT NULL REFERENCES attack_nodes(id),
  weight REAL NOT NULL CHECK(weight>=0.0 AND weight<=1.0),
  content_sha256 TEXT NOT NULL CHECK(%(content)s),
  evidence_sha256 TEXT NOT NULL CHECK(%(evidence)s),
  verification_state TEXT NOT NULL DEFAULT 'STRUCTURAL_HYPOTHESIS'
    CHECK(verification_state IN ('STRUCTURAL_HYPOTHESIS','FEASIBLE_PATH','PROVEN')),
  metadata TEXT NOT NULL CHECK(json_valid(metadata)));
CREATE INDEX attack_edges_source ON attack_edges(source_id, type);
CREATE INDEX attack_edges_target ON attack_edges(target_id, type);
CREATE TABLE technique_links (
  node_id TEXT PRIMARY KEY REFERENCES attack_nodes(id),
  external_id TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('RESOLVED','UNRESOLVED')),
  stix_id TEXT,
  bundle_sha256 TEXT,
  linked_at TEXT NOT NULL,
  CHECK((status='RESOLVED' AND stix_id IS NOT NULL AND bundle_sha256 IS NOT NULL)
     OR (status='UNRESOLVED' AND stix_id IS NULL)));
CREATE TABLE graph_snapshots (
  snapshot_sha256 TEXT PRIMARY KEY CHECK(%(snapshot)s),
  created_at TEXT NOT NULL,
  node_count INTEGER NOT NULL,
  edge_count INTEGER NOT NULL,
  inputs TEXT NOT NULL CHECK(json_valid(inputs)));
CREATE TABLE attack_revisions (
  rev INTEGER PRIMARY KEY AUTOINCREMENT,
  kind TEXT NOT NULL CHECK(kind IN ('node','edge')),
  item_id TEXT NOT NULL,
  previous_content_sha256 TEXT NOT NULL,
  previous_evidence_sha256 TEXT NOT NULL,
  new_content_sha256 TEXT NOT NULL,
  new_evidence_sha256 TEXT NOT NULL,
  revised_at TEXT NOT NULL);
CREATE TRIGGER attack_edges_shape_insert BEFORE INSERT ON attack_edges
  WHEN NOT EXISTS(SELECT 1 FROM attack_nodes s, attack_nodes t WHERE s.id=NEW.source_id AND t.id=NEW.target_id AND (
       (NEW.type='FLOWS_TO' AND s.type='SOURCE' AND t.type='FINDING')
    OR (NEW.type='CALLS' AND s.type='FINDING' AND t.type='SINK')
    OR (NEW.type='MITIGATED_BY' AND s.type='FINDING' AND t.type='MITIGATION')
    OR (NEW.type='MAPS_TO' AND s.type='FINDING' AND t.type='ATTACK_TECHNIQUE')))
  BEGIN SELECT RAISE(ABORT,'Invalid or missing graph edge endpoint'); END;
CREATE TRIGGER attack_edges_shape_update BEFORE UPDATE OF type,source_id,target_id ON attack_edges
  WHEN NOT EXISTS(SELECT 1 FROM attack_nodes s, attack_nodes t WHERE s.id=NEW.source_id AND t.id=NEW.target_id AND (
       (NEW.type='FLOWS_TO' AND s.type='SOURCE' AND t.type='FINDING')
    OR (NEW.type='CALLS' AND s.type='FINDING' AND t.type='SINK')
    OR (NEW.type='MITIGATED_BY' AND s.type='FINDING' AND t.type='MITIGATION')
    OR (NEW.type='MAPS_TO' AND s.type='FINDING' AND t.type='ATTACK_TECHNIQUE')))
  BEGIN SELECT RAISE(ABORT,'Invalid or missing graph edge endpoint'); END;
CREATE TRIGGER attack_nodes_delete_guard BEFORE DELETE ON attack_nodes
  WHEN EXISTS(SELECT 1 FROM attack_edges WHERE source_id=OLD.id OR target_id=OLD.id)
    OR EXISTS(SELECT 1 FROM technique_links WHERE node_id=OLD.id)
  BEGIN SELECT RAISE(ABORT,'Node still referenced'); END;
CREATE TRIGGER attack_nodes_identity_update BEFORE UPDATE OF id,type ON attack_nodes
  WHEN NEW.id<>OLD.id OR NEW.type<>OLD.type
  BEGIN SELECT RAISE(ABORT,'Node identity is immutable'); END;
CREATE TRIGGER attack_nodes_revision AFTER UPDATE ON attack_nodes
  WHEN NEW.content_sha256<>OLD.content_sha256 OR NEW.evidence_sha256<>OLD.evidence_sha256
  BEGIN INSERT INTO attack_revisions(kind,item_id,previous_content_sha256,previous_evidence_sha256,
      new_content_sha256,new_evidence_sha256,revised_at)
    VALUES('node',OLD.id,OLD.content_sha256,OLD.evidence_sha256,NEW.content_sha256,NEW.evidence_sha256,
      strftime('%%Y-%%m-%%dT%%H:%%M:%%fZ','now')); END;
CREATE TRIGGER attack_edges_revision AFTER UPDATE ON attack_edges
  WHEN NEW.content_sha256<>OLD.content_sha256 OR NEW.evidence_sha256<>OLD.evidence_sha256
  BEGIN INSERT INTO attack_revisions(kind,item_id,previous_content_sha256,previous_evidence_sha256,
      new_content_sha256,new_evidence_sha256,revised_at)
    VALUES('edge',OLD.id,OLD.content_sha256,OLD.evidence_sha256,NEW.content_sha256,NEW.evidence_sha256,
      strftime('%%Y-%%m-%%dT%%H:%%M:%%fZ','now')); END;
INSERT INTO code_graph_meta VALUES('schema_version','%(version)s');
COMMIT;
""" % {"content": _HEX.format(c="content_sha256"), "evidence": _HEX.format(c="evidence_sha256"),
       "snapshot": _HEX.format(c="snapshot_sha256"), "version": SCHEMA_VERSION}


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def file_sha256(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def reject_constant(name):
    raise ValueError("Non-finite JSON number: " + name)


def text(value, field, limit=MAX_TEXT, required=False):
    if value is None and not required:
        return None
    if not isinstance(value, str) or len(value) > limit or (required and not value):
        raise ValueError("Invalid " + field)
    return value


def check_node(rec):
    node_id = text(rec.get("id"), "node id", MAX_ID, True)
    kind = rec.get("type")
    if kind not in NODE_TYPES:
        raise ValueError("Invalid node type")
    line = rec.get("line")
    if line is not None and (isinstance(line, bool) or not isinstance(line, int) or line < 1):
        raise ValueError("Invalid node line")
    evidence = rec.get("evidence_sha256", "")
    if not isinstance(evidence, str) or not (HEX64.fullmatch(evidence) or (kind == "ATTACK_TECHNIQUE" and evidence == "")):
        raise ValueError("Node evidence_sha256 must be 64 hex chars (empty only for ATTACK_TECHNIQUE)")
    if kind == "ATTACK_TECHNIQUE" and not TECHNIQUE_ID.fullmatch(node_id):
        raise ValueError("ATTACK_TECHNIQUE id must look like T1190 or T1190.001")
    metadata = rec.get("metadata", {})
    if not isinstance(metadata, dict):
        raise ValueError("Node metadata must be an object")
    content = {"id": node_id, "type": kind, "name": text(rec.get("name"), "node name", required=True),
               "file": text(rec.get("file"), "node file"), "line": line,
               "severity": text(rec.get("severity"), "severity", 64),
               "confidence": text(rec.get("confidence"), "confidence", 64), "metadata": metadata}
    return {**content, "evidence_sha256": evidence, "content_sha256": digest(content)}


def check_edge(rec):
    edge_id = text(rec.get("id"), "edge id", MAX_EDGE_ID, True)
    kind = rec.get("type")
    if kind not in EDGE_SHAPE:
        raise ValueError("Invalid edge type")
    weight = rec.get("weight", 1.0)
    if isinstance(weight, bool) or not isinstance(weight, (int, float)) or not 0.0 <= weight <= 1.0:
        raise ValueError("Edge weight must be a number between 0 and 1")
    evidence = rec.get("evidence_sha256")
    if not isinstance(evidence, str) or not HEX64.fullmatch(evidence):
        raise ValueError("Edge evidence_sha256 must be 64 hex chars")
    metadata = rec.get("metadata", {})
    if not isinstance(metadata, dict):
        raise ValueError("Edge metadata must be an object")
    content = {"id": edge_id, "type": kind, "source_id": text(rec.get("source_id"), "edge source", MAX_ID, True),
               "target_id": text(rec.get("target_id"), "edge target", MAX_ID, True),
               "weight": float(weight), "metadata": metadata}
    return {**content, "evidence_sha256": evidence, "content_sha256": digest(content)}


def load(paths):
    """Parse and validate Layer 2 JSON-L. Any bad record aborts the whole load."""
    nodes, edges, inputs, total = {}, {}, [], 0
    for raw in paths:
        path = Path(raw)
        size = path.stat().st_size
        if size > MAX_INPUT_BYTES:
            raise ValueError(path.name + ": input over size limit")
        inputs.append({"name": path.name, "sha256": file_sha256(path), "bytes": size})
        with path.open(encoding="utf-8") as stream:
            for number, line in enumerate(stream, 1):
                if not line.strip():
                    continue
                total += 1
                if total > MAX_RECORDS:
                    raise ValueError("Too many records")
                try:
                    rec = json.loads(line, parse_constant=reject_constant)
                    if not isinstance(rec, dict):
                        raise ValueError("Record must be an object")
                    if rec.get("entity") == "node":
                        item, bucket = check_node(rec), nodes
                    elif rec.get("entity") == "edge":
                        item, bucket = check_edge(rec), edges
                    else:
                        raise ValueError("Unknown entity")
                    old = bucket.get(item["id"])
                    if old and (old["content_sha256"], old["evidence_sha256"]) != (item["content_sha256"], item["evidence_sha256"]):
                        raise ValueError("Conflicting duplicate id " + item["id"])
                    bucket[item["id"]] = item
                except ValueError as exc:  # JSONDecodeError is a ValueError
                    raise ValueError("%s:%d: %s" % (path.name, number, exc)) from None
    return nodes, edges, inputs


def connect_rw(db):
    db = Path(db)
    db.parent.mkdir(parents=True, exist_ok=True)
    created = not db.exists()
    con = sqlite3.connect(db, isolation_level=None, timeout=30)
    if created:
        os.chmod(db, 0o600)
    con.execute("PRAGMA foreign_keys=ON")
    return con


def connect_ro(db):
    if not Path(db).exists():
        raise ValueError("Attack graph database missing: " + str(db))
    con = sqlite3.connect("file:" + urllib.parse.quote(str(db), safe="/") + "?mode=ro", uri=True)
    con.execute("PRAGMA query_only=ON")
    return con


def table_names(con):
    return {row[0] for row in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}


def ensure_schema(con):
    """Create the Layer 3 schema once; refuse to build on tables it did not create."""
    names = table_names(con)
    present = names & set(LAYER3_TABLES)
    if not present:
        con.executescript(DDL)
        return
    if "code_graph_meta" not in present:
        raise ValueError("attack_nodes/attack_edges exist without a Layer 3 marker (written by another tool); refusing to reuse them")
    version = con.execute("SELECT value FROM code_graph_meta WHERE key='schema_version'").fetchone()
    if not version or version[0] != SCHEMA_VERSION or present != set(LAYER3_TABLES):
        raise ValueError("Unsupported or incomplete Layer 3 schema; migrate explicitly")


def require_schema(con):
    if "code_graph_meta" not in table_names(con):
        raise ValueError("Layer 3 graph not initialised: run ingest first")


def snapshot_hash(con):
    nodes = con.execute("SELECT id,type,content_sha256,evidence_sha256 FROM attack_nodes ORDER BY id").fetchall()
    edges = con.execute("SELECT id,type,source_id,target_id,content_sha256,evidence_sha256 FROM attack_edges ORDER BY id").fetchall()
    return digest({"schema": SCHEMA_VERSION, "nodes": nodes, "edges": edges})


def record_snapshot(con, inputs):
    sha = snapshot_hash(con)
    nodes = con.execute("SELECT count(*) FROM attack_nodes").fetchone()[0]
    edges = con.execute("SELECT count(*) FROM attack_edges").fetchone()[0]
    con.execute("INSERT OR IGNORE INTO graph_snapshots VALUES(?,?,?,?,?)", (sha, now(), nodes, edges, canonical(inputs)))
    return sha


def resolve_techniques(con):
    """Link ATTACK_TECHNIQUE nodes to STIX attack-patterns by MITRE id. Never writes STIX tables."""
    names = table_names(con)
    bundle = None
    if "entities" in names and "metadata" in names:
        row = con.execute("SELECT value FROM metadata WHERE key='sha256'").fetchone()
        bundle = json.loads(row[0]) if row else None
    counts = {"RESOLVED": 0, "UNRESOLVED": 0}
    for (node_id,) in con.execute("SELECT id FROM attack_nodes WHERE type='ATTACK_TECHNIQUE' ORDER BY id").fetchall():
        matches = con.execute("SELECT stix_id FROM entities WHERE type='attack-pattern' AND external_id=?", (node_id,)).fetchall() \
            if bundle and "entities" in names else []
        if len(matches) == 1:
            status, stix, sha = "RESOLVED", matches[0][0], bundle
        else:
            status, stix, sha = "UNRESOLVED", None, None
        con.execute("INSERT INTO technique_links VALUES(?,?,?,?,?,?) ON CONFLICT(node_id) DO UPDATE SET "
                    "external_id=excluded.external_id,status=excluded.status,stix_id=excluded.stix_id,"
                    "bundle_sha256=excluded.bundle_sha256,linked_at=excluded.linked_at",
                    (node_id, node_id, status, stix, sha, now()))
        counts[status] += 1
    return counts


NODE_SQL = ("INSERT INTO attack_nodes(id,type,name,file,line,severity,confidence,content_sha256,evidence_sha256,metadata) "
            "VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,file=excluded.file,"
            "line=excluded.line,severity=excluded.severity,confidence=excluded.confidence,"
            "content_sha256=excluded.content_sha256,evidence_sha256=excluded.evidence_sha256,metadata=excluded.metadata")
EDGE_SQL = ("INSERT INTO attack_edges(id,type,source_id,target_id,weight,content_sha256,evidence_sha256,metadata) "
            "VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET weight=excluded.weight,"
            "content_sha256=excluded.content_sha256,evidence_sha256=excluded.evidence_sha256,metadata=excluded.metadata,"
            "verification_state='STRUCTURAL_HYPOTHESIS'")


def write_items(con, table, items, sql, row):
    summary = {"inserted": 0, "updated": 0, "unchanged": 0}
    for item in items:
        old = con.execute("SELECT content_sha256,evidence_sha256 FROM %s WHERE id=?" % table, (item["id"],)).fetchone()
        if old and old == (item["content_sha256"], item["evidence_sha256"]):
            summary["unchanged"] += 1
            continue
        con.execute(sql, row(item))
        summary["updated" if old else "inserted"] += 1
    return summary


def ingest(paths, db=DB):
    """All-or-nothing ingest of Layer 2 JSON-L into the unified database."""
    nodes, edges, inputs = load(paths)
    with closing(connect_rw(db)) as con:
        ensure_schema(con)
        con.execute("BEGIN IMMEDIATE")
        try:
            known = {}
            for node in nodes.values():
                row = con.execute("SELECT type FROM attack_nodes WHERE id=?", (node["id"],)).fetchone()
                if row and row[0] != node["type"]:
                    raise ValueError("Node %s changes type %s -> %s" % (node["id"], row[0], node["type"]))
                known[node["id"]] = node["type"]
            for edge in edges.values():
                for end in (edge["source_id"], edge["target_id"]):
                    if end not in known:
                        row = con.execute("SELECT type FROM attack_nodes WHERE id=?", (end,)).fetchone()
                        if not row:
                            raise ValueError("Orphan edge %s: endpoint %s not found" % (edge["id"], end))
                        known[end] = row[0]
                want = EDGE_SHAPE[edge["type"]]
                if (known[edge["source_id"]], known[edge["target_id"]]) != want:
                    raise ValueError("Edge %s (%s) must connect %s -> %s" % (edge["id"], edge["type"], want[0], want[1]))
            result = {"nodes": write_items(con, "attack_nodes", nodes.values(), NODE_SQL, lambda n: (
                n["id"], n["type"], n["name"], n["file"], n["line"], n["severity"], n["confidence"],
                n["content_sha256"], n["evidence_sha256"], canonical(n["metadata"])))}
            result["edges"] = write_items(con, "attack_edges", edges.values(), EDGE_SQL, lambda e: (
                e["id"], e["type"], e["source_id"], e["target_id"], e["weight"],
                e["content_sha256"], e["evidence_sha256"], canonical(e["metadata"])))
            result["techniques"] = resolve_techniques(con)
            result["snapshot_sha256"] = record_snapshot(con, inputs)
            if con.execute("PRAGMA foreign_key_check").fetchall():
                raise ValueError("Orphan references after ingest")
            con.execute("COMMIT")
        except BaseException:
            con.execute("ROLLBACK")
            raise
    result["inputs"] = inputs
    return result


def relink(db=DB):
    with closing(connect_rw(db)) as con:
        require_schema(con)
        con.execute("BEGIN IMMEDIATE")
        try:
            counts = resolve_techniques(con)
            con.execute("COMMIT")
        except BaseException:
            con.execute("ROLLBACK")
            raise
    return {"techniques": counts}


def snapshot(db=DB):
    with closing(connect_rw(db)) as con:
        require_schema(con)
        con.execute("BEGIN IMMEDIATE")
        try:
            sha = record_snapshot(con, [])
            con.execute("COMMIT")
        except BaseException:
            con.execute("ROLLBACK")
            raise
    return {"snapshot_sha256": sha}


def stats(db=DB):
    with closing(connect_ro(db)) as con:
        require_schema(con)
        con.execute("BEGIN")
        return {
            "nodes": con.execute("SELECT count(*) FROM attack_nodes").fetchone()[0],
            "nodes_by_type": dict(con.execute("SELECT type,count(*) FROM attack_nodes GROUP BY type")),
            "edges": con.execute("SELECT count(*) FROM attack_edges").fetchone()[0],
            "edges_by_type": dict(con.execute("SELECT type,count(*) FROM attack_edges GROUP BY type")),
            "edges_by_verification_state": dict(con.execute("SELECT verification_state,count(*) FROM attack_edges GROUP BY verification_state")),
            "technique_links": dict(con.execute("SELECT status,count(*) FROM technique_links GROUP BY status")),
            "snapshots": con.execute("SELECT count(*) FROM graph_snapshots").fetchone()[0],
            "revisions": con.execute("SELECT count(*) FROM attack_revisions").fetchone()[0],
            "orphan_edges": con.execute("SELECT count(*) FROM attack_edges e WHERE NOT EXISTS(SELECT 1 FROM attack_nodes WHERE id=e.source_id) "
                                        "OR NOT EXISTS(SELECT 1 FROM attack_nodes WHERE id=e.target_id)").fetchone()[0],
            "current_snapshot_sha256": snapshot_hash(con)}


def paths(db=DB, source=None, sink=None, limit=200):
    """SOURCE -FLOWS_TO-> FINDING -CALLS-> SINK chains, structural only.

    Mitigations are reported on each chain as annotations (pruned is always False): whether a control
    really blocks the flow needs Layer 4 evidence for that environment, identity and condition.
    """
    limit = max(1, min(int(limit), 1000))
    with closing(connect_ro(db)) as con:
        require_schema(con)
        con.execute("BEGIN")
        where, params = "", []
        if source:
            where += " AND s.id=?"
            params.append(source)
        if sink:
            where += " AND k.id=?"
            params.append(sink)
        rows = con.execute(
            "SELECT s.id,s.name,f.id,f.name,f.severity,f.confidence,k.id,k.name,a.verification_state,b.verification_state "
            "FROM attack_edges a JOIN attack_nodes s ON s.id=a.source_id JOIN attack_nodes f ON f.id=a.target_id "
            "JOIN attack_edges b ON b.source_id=f.id AND b.type='CALLS' JOIN attack_nodes k ON k.id=b.target_id "
            "WHERE a.type='FLOWS_TO'" + where + " ORDER BY s.id,f.id,k.id LIMIT ?", params + [limit + 1]).fetchall()
        chains = []
        for sid, sname, fid, fname, severity, confidence, kid, kname, state_a, state_b in rows[:limit]:
            mitigations = [{"id": m, "name": n, "weight": w, "edge_verification_state": st, "effect": "ANNOTATION_ONLY",
                            "status": json.loads(meta).get("status")}
                           for m, n, w, st, meta in con.execute(
                               "SELECT m.id,m.name,e.weight,e.verification_state,m.metadata FROM attack_edges e "
                               "JOIN attack_nodes m ON m.id=e.target_id WHERE e.source_id=? AND e.type='MITIGATED_BY' ORDER BY m.id", (fid,))]
            techniques = [{"id": t, "link": status or "UNRESOLVED"} for t, status in con.execute(
                "SELECT e.target_id,l.status FROM attack_edges e LEFT JOIN technique_links l ON l.node_id=e.target_id "
                "WHERE e.source_id=? AND e.type='MAPS_TO' ORDER BY e.target_id", (fid,))]
            chains.append({"source": {"id": sid, "name": sname}, "finding": {"id": fid, "name": fname, "severity": severity, "confidence": confidence},
                           "sink": {"id": kid, "name": kname}, "mitigations": mitigations, "techniques": techniques,
                           "verification_state": min((state_a, state_b), key=STATE_RANK.__getitem__), "pruned": False})
        unanchored = [{"finding": fid, "missing": [name for name, ok in (("SOURCE", has_source), ("SINK", has_sink)) if not ok]}
                      for fid, has_source, has_sink in con.execute(
                          "SELECT id,has_source,has_sink FROM (SELECT f.id AS id,"
                          "EXISTS(SELECT 1 FROM attack_edges WHERE target_id=f.id AND type='FLOWS_TO') AS has_source,"
                          "EXISTS(SELECT 1 FROM attack_edges WHERE source_id=f.id AND type='CALLS') AS has_sink "
                          "FROM attack_nodes f WHERE f.type='FINDING') WHERE NOT (has_source AND has_sink) ORDER BY id")]
        return {"chains": chains, "truncated": len(rows) > limit, "limit": limit, "unanchored_findings": unanchored,
                "note": "Structural hypotheses only; Layer 4 decides feasibility and proof."}


def main(argv=None):
    parser = argparse.ArgumentParser(description="MITR3 Attack Graph, Layer 3 (code/attack-chain graph)")
    parser.add_argument("--db", type=Path, default=DB, help="SQLite database (default: state/mitr3-attack.sqlite3)")
    sub = parser.add_subparsers(dest="action", required=True)
    add = sub.add_parser("ingest", help="Ingest Layer 2 JSON-L exports (all-or-nothing)")
    add.add_argument("inputs", nargs="+", type=Path)
    sub.add_parser("stats")
    sub.add_parser("snapshot", help="Record the current graph snapshot hash")
    sub.add_parser("relink", help="Re-resolve ATT&CK technique links against the STIX tables")
    query = sub.add_parser("paths", help="List SOURCE->FINDING->SINK chains (structural hypotheses)")
    query.add_argument("--source")
    query.add_argument("--sink")
    query.add_argument("--limit", type=int, default=200)
    args = parser.parse_args(argv)
    try:
        if args.action == "ingest":
            result = ingest(args.inputs, args.db)
        elif args.action == "stats":
            result = stats(args.db)
        elif args.action == "snapshot":
            result = snapshot(args.db)
        elif args.action == "relink":
            result = relink(args.db)
        else:
            result = paths(args.db, args.source, args.sink, args.limit)
    except (ValueError, sqlite3.Error, OSError) as exc:
        print("Error: %s" % exc, file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
