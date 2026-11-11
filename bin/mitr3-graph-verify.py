#!/usr/bin/env python3
"""MITR3 Attack Graph, Layer 4: evidence and verification of attack paths.

Reads the Layer 3 graph (bin/mitr3-code-graph.py) and decides, per SOURCE -> FINDING -> SINK chain,
what is actually supported. Deterministic and offline: no network, no LLM, no traffic to any target.

Rules this layer enforces:
  * Layer 2 mitigations (MITIGATED_BY) are claims. They count only when backed by recorded evidence
    whose artifact still exists on disk with the recorded SHA-256 (re-hashed on every verify).
  * A chain is suppressed only by evidence that names environment, flow, identity and condition and the
    exact source and sink. Suppression never deletes graph rows; justification and provenance stay.
  * The harness ast_gate is a syntactic line check, not a reachability proof. Reachability needs evidence.
  * The engine never emits PROVEN. The highest state it can set is FEASIBLE_PATH. Proof stays with a
    human-approved process, not with a JSON file this layer reads.
  * Evidence and verdicts are append-only. Evidence is retired by revocation, never edited.
"""
from __future__ import annotations

import argparse
from contextlib import closing
import importlib.util
import json
from pathlib import Path
import sqlite3
import sys

ROOT = Path(__file__).resolve().parents[1]


def _layer3():
    spec = importlib.util.spec_from_file_location("mitr3_code_graph_layer3", ROOT / "bin/mitr3-code-graph.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


L3 = _layer3()
DB = L3.DB
SCHEMA_VERSION = "1"
VERIFY_TABLES = ("verify_meta", "verification_evidence", "evidence_revocations", "path_verdicts")
MAX_ARTIFACT_BYTES = 256_000_000
CONFIDENCE_WEIGHTS = {"scanner_agreement": 0.30, "harness_ast_gate": 0.25, "verified_ast_reachable": 0.45}
CONTEXT_KEYS = ("environment", "flow", "identity", "condition")
RECORD_KEYS = frozenset({"kind", "finding_id", "mitigation_id", "source_id", "sink_id", "verdict", "strength",
                         "applies_to", "artifact", "analyzer", "justification", "recorded_by"})
OUTCOMES = ("ACTIVE", "SUPPRESSED_BY_IAC", "AST_UNREACHABLE", "CONFLICT")
EXPOSURES = ("UNAUTHENTICATED", "AUTHENTICATED", "UNKNOWN")

_HEX = "length({c})=64 AND {c} NOT GLOB '*[^0-9a-f]*'"
_CONTEXT = " AND ".join("COALESCE(json_extract(applies_to,'$.%s'),'')<>''" % key for key in CONTEXT_KEYS)
DDL = """
BEGIN;
CREATE TABLE verify_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE verification_evidence (
  evidence_id TEXT PRIMARY KEY CHECK(%(eid)s),
  kind TEXT NOT NULL CHECK(kind IN ('AST_REACHABILITY','IAC_CONTROL')),
  finding_id TEXT NOT NULL REFERENCES attack_nodes(id),
  mitigation_id TEXT REFERENCES attack_nodes(id),
  source_id TEXT REFERENCES attack_nodes(id),
  sink_id TEXT REFERENCES attack_nodes(id),
  verdict TEXT NOT NULL CHECK(verdict IN ('REACHABLE','UNREACHABLE','BLOCKS','REDUCES')),
  strength REAL CHECK(strength IS NULL OR (strength>=0.0 AND strength<=1.0)),
  applies_to TEXT NOT NULL CHECK(json_valid(applies_to)),
  artifact_path TEXT NOT NULL CHECK(length(artifact_path) BETWEEN 1 AND 4096),
  artifact_sha256 TEXT NOT NULL CHECK(%(asha)s),
  analyzer TEXT NOT NULL CHECK(length(analyzer)>0),
  justification TEXT NOT NULL CHECK(length(justification)>0),
  recorded_by TEXT NOT NULL CHECK(length(recorded_by)>0),
  recorded_at TEXT NOT NULL,
  CHECK((kind='AST_REACHABILITY' AND verdict IN ('REACHABLE','UNREACHABLE') AND mitigation_id IS NULL AND strength IS NULL)
     OR (kind='IAC_CONTROL' AND mitigation_id IS NOT NULL AND strength IS NOT NULL AND (
          (verdict='REDUCES' AND strength<1.0 AND COALESCE(json_extract(applies_to,'$.environment'),'')<>'')
       OR (verdict='BLOCKS' AND strength=1.0 AND source_id IS NOT NULL AND sink_id IS NOT NULL AND %(context)s)))));
CREATE TABLE evidence_revocations (
  evidence_id TEXT PRIMARY KEY REFERENCES verification_evidence(evidence_id),
  reason TEXT NOT NULL CHECK(length(reason)>0),
  revoked_by TEXT NOT NULL CHECK(length(revoked_by)>0),
  revoked_at TEXT NOT NULL);
CREATE TABLE path_verdicts (
  snapshot_sha256 TEXT NOT NULL REFERENCES graph_snapshots(snapshot_sha256),
  source_id TEXT NOT NULL REFERENCES attack_nodes(id),
  finding_id TEXT NOT NULL REFERENCES attack_nodes(id),
  sink_id TEXT NOT NULL REFERENCES attack_nodes(id),
  outcome TEXT NOT NULL CHECK(outcome IN ('ACTIVE','SUPPRESSED_BY_IAC','AST_UNREACHABLE','CONFLICT')),
  verification_state TEXT NOT NULL CHECK(verification_state IN ('STRUCTURAL_HYPOTHESIS','FEASIBLE_PATH','PROVEN')),
  confidence REAL NOT NULL CHECK(confidence>=0.0 AND confidence<=1.0),
  mitigation_strength REAL NOT NULL CHECK(mitigation_strength>=0.0 AND mitigation_strength<=1.0),
  exploitability REAL NOT NULL CHECK(exploitability>=0.0 AND exploitability<=1.0),
  exposure TEXT NOT NULL CHECK(exposure IN ('UNAUTHENTICATED','AUTHENTICATED','UNKNOWN')),
  evidence_fingerprint TEXT NOT NULL CHECK(%(fp)s),
  basis TEXT NOT NULL CHECK(json_valid(basis)),
  verified_at TEXT NOT NULL,
  PRIMARY KEY(snapshot_sha256, source_id, finding_id, sink_id, evidence_fingerprint));
CREATE TRIGGER verification_evidence_scope BEFORE INSERT ON verification_evidence
  WHEN NOT EXISTS(SELECT 1 FROM attack_nodes WHERE id=NEW.finding_id AND type='FINDING')
    OR (NEW.mitigation_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM attack_edges e JOIN attack_nodes m ON m.id=e.target_id
         WHERE e.source_id=NEW.finding_id AND e.type='MITIGATED_BY' AND e.target_id=NEW.mitigation_id AND m.type='MITIGATION'))
    OR (NEW.source_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM attack_edges WHERE type='FLOWS_TO' AND source_id=NEW.source_id AND target_id=NEW.finding_id))
    OR (NEW.sink_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM attack_edges WHERE type='CALLS' AND source_id=NEW.finding_id AND target_id=NEW.sink_id))
  BEGIN SELECT RAISE(ABORT,'Evidence scope does not match graph structure'); END;
CREATE TRIGGER verification_evidence_no_update BEFORE UPDATE ON verification_evidence
  BEGIN SELECT RAISE(ABORT,'Evidence is append-only; revoke it instead'); END;
CREATE TRIGGER verification_evidence_no_delete BEFORE DELETE ON verification_evidence
  BEGIN SELECT RAISE(ABORT,'Evidence is append-only; revoke it instead'); END;
CREATE TRIGGER evidence_revocations_no_update BEFORE UPDATE ON evidence_revocations
  BEGIN SELECT RAISE(ABORT,'Revocations are append-only'); END;
CREATE TRIGGER evidence_revocations_no_delete BEFORE DELETE ON evidence_revocations
  BEGIN SELECT RAISE(ABORT,'Revocations are append-only'); END;
CREATE TRIGGER path_verdicts_no_update BEFORE UPDATE ON path_verdicts
  BEGIN SELECT RAISE(ABORT,'Verdicts are append-only'); END;
CREATE TRIGGER path_verdicts_no_delete BEFORE DELETE ON path_verdicts
  BEGIN SELECT RAISE(ABORT,'Verdicts are append-only'); END;
CREATE TRIGGER verify_nodes_delete_guard BEFORE DELETE ON attack_nodes
  WHEN EXISTS(SELECT 1 FROM verification_evidence WHERE finding_id=OLD.id OR mitigation_id=OLD.id OR source_id=OLD.id OR sink_id=OLD.id)
    OR EXISTS(SELECT 1 FROM path_verdicts WHERE source_id=OLD.id OR finding_id=OLD.id OR sink_id=OLD.id)
  BEGIN SELECT RAISE(ABORT,'Node referenced by verification records'); END;
INSERT INTO verify_meta VALUES('schema_version','%(version)s');
COMMIT;
""" % {"eid": _HEX.format(c="evidence_id"), "asha": _HEX.format(c="artifact_sha256"), "fp": _HEX.format(c="evidence_fingerprint"),
       "context": _CONTEXT, "version": SCHEMA_VERSION}


def ensure_schema(con):
    names = L3.table_names(con)
    if "code_graph_meta" not in names:
        raise ValueError("Layer 3 graph not initialised: run mitr3-code-graph.py ingest first")
    present = names & set(VERIFY_TABLES)
    if not present:
        con.executescript(DDL)
        return
    if "verify_meta" not in present:
        raise ValueError("Verification tables exist without a Layer 4 marker (written by another tool); refusing to reuse them")
    require_schema(con)


def require_schema(con):
    names = L3.table_names(con)
    if "verify_meta" not in names:
        raise ValueError("Layer 4 not initialised: record evidence first (verify of a graph with no evidence still needs the schema)")
    version = con.execute("SELECT value FROM verify_meta WHERE key='schema_version'").fetchone()
    if not version or version[0] != SCHEMA_VERSION or not set(VERIFY_TABLES) <= names:
        raise ValueError("Unsupported or incomplete Layer 4 schema; migrate explicitly")


def check_artifact(root, relative):
    """Return (status, resolved_relative_path, sha256). Status VERIFIED only when the file is inside root."""
    base = Path(root).resolve()
    given = Path(relative)
    resolved = (given if given.is_absolute() else base / given).resolve()
    if resolved != base and base not in resolved.parents:
        return "OUTSIDE_ROOT", None, None
    rel = resolved.relative_to(base)
    if ".git" in rel.parts:
        return "FORBIDDEN_PATH", rel.as_posix(), None
    if not resolved.is_file():
        return "MISSING", rel.as_posix(), None
    if resolved.stat().st_size > MAX_ARTIFACT_BYTES:
        return "TOO_LARGE", rel.as_posix(), None
    return "VERIFIED", rel.as_posix(), L3.file_sha256(resolved)


def build_record(raw, root):
    if not isinstance(raw, dict) or set(raw) - RECORD_KEYS:
        raise ValueError("Evidence record must be an object with only: " + ", ".join(sorted(RECORD_KEYS)))
    kind, verdict = raw.get("kind"), raw.get("verdict")
    if not isinstance(kind, str) or not isinstance(verdict, str) or (kind, verdict) not in {("AST_REACHABILITY", "REACHABLE"), ("AST_REACHABILITY", "UNREACHABLE"),
                               ("IAC_CONTROL", "BLOCKS"), ("IAC_CONTROL", "REDUCES")}:
        raise ValueError("Invalid kind/verdict pair")
    strength = raw.get("strength")
    if kind == "AST_REACHABILITY":
        if strength is not None or raw.get("mitigation_id"):
            raise ValueError("AST evidence takes no strength or mitigation_id")
    else:
        if isinstance(strength, bool) or not isinstance(strength, (int, float)):
            raise ValueError("IAC evidence needs a numeric strength")
        if (verdict == "BLOCKS" and strength != 1.0) or (verdict == "REDUCES" and not 0.0 <= strength < 1.0):
            raise ValueError("BLOCKS needs strength 1.0; REDUCES needs 0 <= strength < 1")
        L3.text(raw.get("mitigation_id"), "mitigation_id", L3.MAX_ID, True)
    applies = raw.get("applies_to", {})
    if not isinstance(applies, dict) or any(not isinstance(k, str) or not isinstance(v, str) or len(v) > L3.MAX_TEXT for k, v in applies.items()):
        raise ValueError("applies_to must be an object of strings")
    if verdict == "BLOCKS":
        if not raw.get("source_id") or not raw.get("sink_id"):
            raise ValueError("BLOCKS must name source_id and sink_id")
        missing = [k for k in CONTEXT_KEYS if not applies.get(k, "").strip()]
        if missing:
            raise ValueError("BLOCKS needs applies_to for: " + ", ".join(missing))
    if verdict == "REDUCES" and not applies.get("environment", "").strip():
        raise ValueError("REDUCES needs applies_to.environment")
    status, rel, sha = check_artifact(root, L3.text(raw.get("artifact"), "artifact", 4096, True))
    if status != "VERIFIED":
        raise ValueError("Artifact not usable as evidence: " + status)
    record = {"kind": kind, "finding_id": L3.text(raw.get("finding_id"), "finding_id", L3.MAX_ID, True),
              "mitigation_id": raw.get("mitigation_id") or None, "source_id": raw.get("source_id") or None,
              "sink_id": raw.get("sink_id") or None, "verdict": verdict,
              "strength": None if strength is None else float(strength), "applies_to": applies,
              "artifact_path": rel, "artifact_sha256": sha,
              "analyzer": L3.text(raw.get("analyzer"), "analyzer", 256, True),
              "justification": L3.text(raw.get("justification"), "justification", L3.MAX_TEXT, True)}
    record["evidence_id"] = L3.digest(record)  # identity excludes who/when, so the same finding recorded twice is one row
    record["recorded_by"] = L3.text(raw.get("recorded_by"), "recorded_by", 256, True)
    return record


def record_evidence(source, db=DB, evidence_root=ROOT):
    raw = json.loads(Path(source).read_text(encoding="utf-8"), parse_constant=L3.reject_constant)
    record = build_record(raw, evidence_root)
    with closing(L3.connect_rw(db)) as con:
        ensure_schema(con)
        try:
            cursor = con.execute(
                "INSERT OR IGNORE INTO verification_evidence(evidence_id,kind,finding_id,mitigation_id,source_id,sink_id,verdict,strength,"
                "applies_to,artifact_path,artifact_sha256,analyzer,justification,recorded_by,recorded_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (record["evidence_id"], record["kind"], record["finding_id"], record["mitigation_id"], record["source_id"], record["sink_id"],
                 record["verdict"], record["strength"], L3.canonical(record["applies_to"]), record["artifact_path"], record["artifact_sha256"],
                 record["analyzer"], record["justification"], record["recorded_by"], L3.now()))
        except sqlite3.IntegrityError as exc:
            raise ValueError("Evidence rejected by database: %s" % exc) from None
    return {"evidence_id": record["evidence_id"], "artifact_path": record["artifact_path"],
            "artifact_sha256": record["artifact_sha256"], "status": "recorded" if cursor.rowcount else "already_recorded"}


def revoke_evidence(evidence_id, reason, by, db=DB):
    reason, by = L3.text(reason, "reason", L3.MAX_TEXT, True), L3.text(by, "revoked_by", 256, True)
    with closing(L3.connect_rw(db)) as con:
        ensure_schema(con)
        try:
            con.execute("INSERT INTO evidence_revocations VALUES(?,?,?,?)", (evidence_id, reason, by, L3.now()))
        except sqlite3.IntegrityError:
            raise ValueError("Unknown or already revoked evidence id") from None
    return {"evidence_id": evidence_id, "status": "revoked"}


def load_evidence(con, root):
    """All recorded evidence with a live artifact check. Revoked evidence is kept in the list, flagged."""
    revoked = {row[0] for row in con.execute("SELECT evidence_id FROM evidence_revocations")}
    cache, items = {}, []
    columns = ("evidence_id", "kind", "finding_id", "mitigation_id", "source_id", "sink_id", "verdict", "strength", "applies_to",
               "artifact_path", "artifact_sha256", "analyzer", "justification", "recorded_by", "recorded_at")
    for row in con.execute("SELECT %s FROM verification_evidence ORDER BY evidence_id" % ",".join(columns)):
        item = dict(zip(columns, row))
        item["applies_to"] = json.loads(item["applies_to"])
        if item["artifact_path"] not in cache:
            cache[item["artifact_path"]] = check_artifact(root, item["artifact_path"])
        status, _, sha = cache[item["artifact_path"]]
        item["revoked"] = item["evidence_id"] in revoked
        item["artifact_status"] = "HASH_MISMATCH" if status == "VERIFIED" and sha != item["artifact_sha256"] else status
        item["counts"] = item["artifact_status"] == "VERIFIED" and not item["revoked"]
        items.append(item)
    return items


def summarize(item):
    keys = ("evidence_id", "kind", "verdict", "strength", "mitigation_id", "analyzer", "justification",
            "artifact_path", "artifact_sha256", "recorded_by", "applies_to")
    return {key: item[key] for key in keys}


def gate_value(value):
    if isinstance(value, str):
        value = value.upper()
    if value in (1, True, "PASS"):
        return 1
    if value in (0, False, "FAIL"):
        return 0
    return None


def number(value, low=0.0, high=1.0, default=0.0):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not low <= value <= high:
        return default
    return float(value)


def confidence(meta, reachable_verified):
    """Deterministic 0..1 ordering score from explicit components. It is not a probability of exploitation."""
    count = meta.get("scanner_count")
    count = count if isinstance(count, int) and not isinstance(count, bool) and count >= 1 else 1
    parts = {"scanner_agreement": round(number(meta.get("agreement_ratio")) * min(count, 3) / 3, 4),
             "harness_ast_gate": 1.0 if gate_value(meta.get("ast_gate")) == 1 else 0.0,
             "verified_ast_reachable": 1.0 if reachable_verified else 0.0}
    return round(sum(CONFIDENCE_WEIGHTS[name] * value for name, value in parts.items()), 4), parts


def exposure_of(meta):
    flag = meta.get("authenticated")
    return "AUTHENTICATED" if flag is True else "UNAUTHENTICATED" if flag is False else "UNKNOWN"


CHAIN_SQL = ("SELECT s.id,s.name,s.metadata,f.id,f.name,f.file,f.line,f.severity,f.metadata,k.id,k.name,a.id,b.id "
             "FROM attack_edges a JOIN attack_nodes s ON s.id=a.source_id JOIN attack_nodes f ON f.id=a.target_id "
             "JOIN attack_edges b ON b.source_id=f.id AND b.type='CALLS' JOIN attack_nodes k ON k.id=b.target_id "
             "WHERE a.type='FLOWS_TO' ORDER BY s.id,f.id,k.id")


def evaluate(con, root, exposure="any"):
    evidence = load_evidence(con, root)
    claimed = {}
    for finding_id, mitigation_id, weight in con.execute("SELECT e.source_id,e.target_id,e.weight FROM attack_edges e WHERE e.type='MITIGATED_BY' ORDER BY 1,2"):
        claimed.setdefault(finding_id, []).append((mitigation_id, weight))
    chains = []
    for sid, sname, smeta, fid, fname, ffile, fline, fsev, fmeta, kid, kname, flows_edge, calls_edge in con.execute(CHAIN_SQL).fetchall():
        smeta, fmeta = json.loads(smeta), json.loads(fmeta)
        scoped = [e for e in evidence if e["finding_id"] == fid and e["source_id"] in (None, sid) and e["sink_id"] in (None, kid)]
        live = [e for e in scoped if e["counts"]]
        reach = [e for e in live if e["verdict"] == "REACHABLE"]
        unreach = [e for e in live if e["verdict"] == "UNREACHABLE"]
        blocks = [e for e in live if e["verdict"] == "BLOCKS" and e["source_id"] == sid and e["sink_id"] == kid]
        strongest = {}
        for e in live:
            if e["kind"] == "IAC_CONTROL" and (e["mitigation_id"] not in strongest or e["strength"] > strongest[e["mitigation_id"]]["strength"]):
                strongest[e["mitigation_id"]] = e
        gate = gate_value(fmeta.get("ast_gate"))
        if (reach and unreach) or (gate == 0 and reach):
            outcome = "CONFLICT"
        elif unreach or gate == 0:
            outcome = "AST_UNREACHABLE"
        elif blocks:
            outcome = "SUPPRESSED_BY_IAC"
        else:
            outcome = "ACTIVE"
        remaining = 1.0
        for e in strongest.values():
            remaining *= 1.0 - e["strength"]  # independence between controls is assumed, and documented as an assumption
        strength = round(1.0 - remaining, 4)
        score, parts = confidence(fmeta, bool(reach))
        feasible = outcome == "ACTIVE" and bool(reach)
        chain_exposure = exposure_of(smeta)
        applied = {e["mitigation_id"] for e in strongest.values()}
        chains.append({
            "source": {"id": sid, "name": sname}, "finding": {"id": fid, "name": fname, "file": ffile, "line": fline, "severity": fsev},
            "sink": {"id": kid, "name": kname}, "outcome": outcome,
            "verification_state": "FEASIBLE_PATH" if feasible else "STRUCTURAL_HYPOTHESIS",
            "confidence": score, "confidence_components": parts, "mitigation_strength": strength,
            "exploitability": round(score * (1.0 - strength), 4) if outcome == "ACTIVE" else 0.0, "exposure": chain_exposure,
            "basis": {
                "ast": {"harness_ast_gate": gate, "harness_ast_gate_note": "syntactic line check, not reachability",
                        "harness_ast_details": fmeta.get("ast_details"),
                        "decided_by": ("EVIDENCE" if unreach else "HARNESS_AST_GATE") if outcome == "AST_UNREACHABLE" else None,
                        "evidence": [summarize(e) for e in reach + unreach]},
                "iac": {"suppressed_by": [summarize(e) for e in blocks],
                        "applied": [summarize(e) for e in strongest.values() if e["verdict"] == "REDUCES"],
                        "claimed_only": [{"mitigation_id": m, "claimed_weight": w, "note": "claim without verified evidence; not counted"}
                                         for m, w in claimed.get(fid, []) if m not in applied]},
                "problems": [{"evidence_id": e["evidence_id"], "status": "REVOKED" if e["revoked"] else e["artifact_status"]}
                             for e in scoped if not e["counts"]]},
            "evidence_fingerprint": L3.digest(sorted((e["evidence_id"], e["artifact_sha256"]) for e in live)),
            "_edges": (flows_edge, calls_edge)})
    if exposure != "any":
        chains = [c for c in chains if c["exposure"] == exposure.upper()]
    problems = [{"evidence_id": e["evidence_id"], "status": "REVOKED" if e["revoked"] else e["artifact_status"]} for e in evidence if not e["counts"]]
    unanchored = [{"finding": fid, "missing": [n for n, ok in (("SOURCE", src), ("SINK", snk)) if not ok]} for fid, src, snk in con.execute(
        "SELECT id,has_source,has_sink FROM (SELECT f.id AS id,EXISTS(SELECT 1 FROM attack_edges WHERE target_id=f.id AND type='FLOWS_TO') AS has_source,"
        "EXISTS(SELECT 1 FROM attack_edges WHERE source_id=f.id AND type='CALLS') AS has_sink FROM attack_nodes f WHERE f.type='FINDING') "
        "WHERE NOT (has_source AND has_sink) ORDER BY id")]
    count = lambda key, values: {v: sum(1 for c in chains if c[key] == v) for v in values}
    return {"chains": chains, "unanchored_findings": unanchored,
            "evidence": {"total": len(evidence), "counting": sum(1 for e in evidence if e["counts"]), "not_counting": problems},
            "summary": {"chains": len(chains), "outcomes": count("outcome", OUTCOMES), "exposure": count("exposure", EXPOSURES),
                        "states": count("verification_state", ("STRUCTURAL_HYPOTHESIS", "FEASIBLE_PATH"))},
            "limits": ["PROVEN is never set by this layer", "confidence is an ordering score, not a probability",
                       "mitigation strength combines controls as independent (assumption)"]}


def persist(con, result):
    snapshot = L3.record_snapshot(con, [])
    inserted = 0
    for c in result["chains"]:
        inserted += con.execute(
            "INSERT OR IGNORE INTO path_verdicts VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (snapshot, c["source"]["id"], c["finding"]["id"], c["sink"]["id"], c["outcome"], c["verification_state"], c["confidence"],
             c["mitigation_strength"], c["exploitability"], c["exposure"], c["evidence_fingerprint"], L3.canonical(c["basis"]), L3.now())).rowcount
    con.execute("CREATE TEMP TABLE feasible_edges(id TEXT PRIMARY KEY)")
    con.executemany("INSERT OR IGNORE INTO feasible_edges VALUES(?)",
                    [(edge,) for c in result["chains"] if c["verification_state"] == "FEASIBLE_PATH" for edge in c["_edges"]])
    promoted = con.execute("UPDATE attack_edges SET verification_state='FEASIBLE_PATH' WHERE verification_state='STRUCTURAL_HYPOTHESIS' "
                           "AND id IN (SELECT id FROM feasible_edges)").rowcount
    demoted = con.execute("UPDATE attack_edges SET verification_state='STRUCTURAL_HYPOTHESIS' WHERE verification_state='FEASIBLE_PATH' "
                          "AND type IN ('FLOWS_TO','CALLS') AND id NOT IN (SELECT id FROM feasible_edges)").rowcount
    con.execute("DROP TABLE feasible_edges")
    return {"snapshot_sha256": snapshot, "verdicts_inserted": inserted, "edges_promoted": promoted, "edges_demoted": demoted}


def verify(db=DB, evidence_root=ROOT, exposure="any", write=False):
    if exposure != "any" and exposure.upper() not in EXPOSURES:
        raise ValueError("exposure must be any, unauthenticated, authenticated or unknown")
    if write and exposure != "any":
        raise ValueError("--write needs the full graph; do not combine it with --exposure")
    if not write:
        with closing(L3.connect_ro(db)) as con:
            L3.require_schema(con)
            require_schema(con)
            con.execute("BEGIN")
            result = evaluate(con, evidence_root, exposure)
            result["graph_snapshot_sha256"] = L3.snapshot_hash(con)
    else:
        with closing(L3.connect_rw(db)) as con:
            ensure_schema(con)
            con.execute("BEGIN IMMEDIATE")
            try:
                result = evaluate(con, evidence_root)
                result["written"] = persist(con, result)
                result["graph_snapshot_sha256"] = result["written"]["snapshot_sha256"]
                con.execute("COMMIT")
            except BaseException:
                con.execute("ROLLBACK")
                raise
    for chain in result["chains"]:
        chain.pop("_edges", None)
    return result


def list_evidence(db=DB, evidence_root=ROOT):
    with closing(L3.connect_ro(db)) as con:
        L3.require_schema(con)
        require_schema(con)
        con.execute("BEGIN")
        return [dict(summarize(e), finding_id=e["finding_id"], source_id=e["source_id"], sink_id=e["sink_id"], revoked=e["revoked"],
                     artifact_status=e["artifact_status"], counts=e["counts"]) for e in load_evidence(con, evidence_root)]


def main(argv=None):
    parser = argparse.ArgumentParser(description="MITR3 Attack Graph, Layer 4 (offline evidence and verification)")
    parser.add_argument("--db", type=Path, default=DB, help="Layer 3 SQLite database")
    parser.add_argument("--evidence-root", type=Path, default=ROOT, help="Root containing evidence artifacts")
    sub = parser.add_subparsers(dest="action", required=True)
    record = sub.add_parser("record", help="Record evidence backed by a local artifact")
    record.add_argument("input", type=Path, help="Evidence JSON file")
    revoke = sub.add_parser("revoke", help="Retire evidence without deleting it")
    revoke.add_argument("evidence_id")
    revoke.add_argument("--reason", required=True)
    revoke.add_argument("--by", required=True)
    sub.add_parser("list", help="List evidence with live artifact checks")
    query = sub.add_parser("verify", help="Evaluate SOURCE->FINDING->SINK chains")
    query.add_argument("--exposure", type=str.lower, choices=("any", "unauthenticated", "authenticated", "unknown"), default="any")
    query.add_argument("--write", action="store_true", help="Persist verdicts and update feasible edges")
    query.add_argument("--json", action="store_true", help="Print the complete verification result as JSON")
    args = parser.parse_args(argv)
    try:
        if args.action == "record":
            result = record_evidence(args.input, args.db, args.evidence_root)
        elif args.action == "revoke":
            result = revoke_evidence(args.evidence_id, args.reason, args.by, args.db)
        elif args.action == "list":
            result = list_evidence(args.db, args.evidence_root)
        else:
            result = verify(args.db, args.evidence_root, args.exposure, args.write)
    except (ValueError, sqlite3.Error, OSError) as exc:
        print("Error: %s" % exc, file=sys.stderr)
        return 2
    if args.action != "verify" or args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print("Chains: %d | Evidence: %d/%d counting" %
              (result["summary"]["chains"], result["evidence"]["counting"], result["evidence"]["total"]))
        for chain in result["chains"]:
            print("%s -> %s -> %s: %s (%s, confidence=%.4f, exposure=%s)" %
                  (chain["source"]["id"], chain["finding"]["id"], chain["sink"]["id"], chain["outcome"],
                   chain["verification_state"], chain["confidence"], chain["exposure"]))
        print("Unanchored findings: %d | Evidence problems: %d" %
              (len(result["unanchored_findings"]), len(result["evidence"]["not_counting"])))
        if args.write:
            print("Written: " + json.dumps(result["written"], sort_keys=True))
        for limit in result["limits"]:
            print("Limit: " + limit)
    return 0


if __name__ == "__main__":
    sys.exit(main())
