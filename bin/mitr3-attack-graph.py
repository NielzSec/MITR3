#!/usr/bin/env python3
"""Offline ATT&CK graph: only active STIX entities and explicit relationships.

Separate from the CVE/CWE/ASVS database. No text-derived or cross-catalog edges.
"""
from __future__ import annotations
import collections
from contextlib import closing, ExitStack
import datetime as dt
import hashlib
import io
import json
import os
from pathlib import Path
import re
import resource
import sqlite3
import tempfile
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
CACHE = ROOT / "knowledge/reference-datasets/cache/enterprise-attack.json"
MANIFEST = CACHE.with_name("enterprise-attack-manifest.json")
DB = ROOT / "state/mitr3-attack.sqlite3"
URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
SOURCE = "mitre-attack-enterprise"
MAX_SIZE = 80_000_000
ADDRESS_SPACE_LIMIT = 1_200_000_000
ENTITY_TYPES = frozenset({"attack-pattern", "malware", "tool", "intrusion-set", "campaign", "course-of-action"})
EDGE_TYPES = frozenset({"uses", "mitigates", "subtechnique-of", "attributed-to"})
STIX_ID = re.compile(r"([a-z-]+)--[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def limit_memory():
    """Never raise an existing limit. Apply before any ingestion/parsing work."""
    soft, hard = resource.getrlimit(resource.RLIMIT_AS)
    limit = min([ADDRESS_SPACE_LIMIT] + [v for v in (soft, hard) if v != resource.RLIM_INFINITY])
    resource.setrlimit(resource.RLIMIT_AS, (limit, limit))
    return limit


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def atomic_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=".attack-")
    try:
        with os.fdopen(fd, "w", encoding="utf8") as stream:
            json.dump(data, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def pinned_url(url):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname != "raw.githubusercontent.com" or parsed.port not in (None, 443) or parsed.username or parsed.password:
        raise ValueError("ATT&CK redirect outside pinned HTTPS host")


class PinnedRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        pinned_url(newurl)  # Check before following, not just after contacting it.
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def load_bundle(path, metadata=None):
    # Hold one descriptor across verification and parsing, so a concurrent atomic
    # cache refresh cannot make the parsed bundle differ from the verified file.
    with path.open("rb") as binary:
        size = os.fstat(binary.fileno()).st_size
        if size > MAX_SIZE:
            raise ValueError("ATT&CK bundle over size limit")
        if metadata and (size != metadata.get("bytes") or hashlib.file_digest(binary, "sha256").hexdigest() != metadata["sha256"]):
            raise ValueError("ATT&CK cache changed or corrupted")
        binary.seek(0)
        with io.TextIOWrapper(binary, encoding="utf8") as stream:
            bundle = json.load(stream)
    if not isinstance(bundle, dict) or bundle.get("type") != "bundle" or not isinstance(bundle.get("objects"), list):
        raise ValueError("Expected STIX bundle with objects list")
    if not bundle["objects"] or len(bundle["objects"]) > 100_000:
        raise ValueError("Suspicious ATT&CK object count")
    if any(not isinstance(obj, dict) or not isinstance(obj.get("type"), str) for obj in bundle["objects"]):
        raise ValueError("Invalid STIX object")
    return bundle


def load_cached():
    metadata = json.loads(MANIFEST.read_text(encoding="utf8"))
    if metadata.get("source_id") != SOURCE or metadata.get("url") != URL or not SHA256.fullmatch(str(metadata.get("sha256", ""))):
        raise ValueError("Invalid ATT&CK manifest source/hash")
    return load_bundle(CACHE, metadata), metadata


def due_this_month(metadata):
    try:
        checked = dt.datetime.fromisoformat(metadata["checked_at"])
        if checked.tzinfo is None:
            return True
        checked = checked.astimezone(dt.timezone.utc)
        return (checked.year, checked.month) != (dt.datetime.now(dt.timezone.utc).year, dt.datetime.now(dt.timezone.utc).month)
    except (KeyError, ValueError, TypeError):
        return True


def sync_bundle():
    """Refresh at most once per UTC calendar month; return the parsed bundle once."""
    if MANIFEST.exists() and CACHE.exists():
        metadata = json.loads(MANIFEST.read_text(encoding="utf8"))
        if not due_this_month(metadata):
            return load_cached()
    CACHE.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(dir=CACHE.parent, prefix=".attack-download-")
    try:
        request = urllib.request.Request(URL, headers={"User-Agent": "MITR3-ATTACK-graph/1.0", "Accept": "application/json"})
        opener = urllib.request.build_opener(PinnedRedirect())
        size = 0
        with os.fdopen(fd, "wb") as stream:
            with opener.open(request, timeout=45) as response:
                pinned_url(response.geturl())
                while chunk := response.read(65536):
                    size += len(chunk)
                    if size > MAX_SIZE:
                        raise ValueError("ATT&CK bundle over size limit")
                    stream.write(chunk)
            stream.flush()
            os.fsync(stream.fileno())
        bundle = load_bundle(Path(temporary))
        metadata = {"source_id": SOURCE, "url": URL, "sha256": digest(Path(temporary)),
                    "bytes": size, "checked_at": now(), "bundle_id": bundle.get("id"),
                    "object_count": len(bundle["objects"])}
        os.chmod(temporary, 0o600)
        os.replace(temporary, CACHE)
        atomic_json(MANIFEST, metadata)
        return bundle, metadata
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def active(obj):
    return not obj.get("revoked", False) and not obj.get("x_mitre_deprecated", False)


def checked_id(obj):
    identifier = obj.get("id", "")
    match = STIX_ID.fullmatch(identifier) if isinstance(identifier, str) else None
    if not match or match[1] != obj["type"]:
        raise ValueError("Invalid/mismatched STIX ID")
    return identifier


def modified(obj):
    value = obj.get("modified")
    if not isinstance(value, str):
        raise ValueError("STIX modified timestamp missing")
    if dt.datetime.fromisoformat(value.replace("Z", "+00:00")).tzinfo is None:
        raise ValueError("STIX modified timestamp needs timezone")
    return value


def external_id(obj):
    # MITRE identifiers only, not CAPEC/CVE/CWE links or text-derived aliases.
    refs = [r.get("external_id", "") for r in obj.get("external_references", [])
            if r.get("source_name") == "mitre-attack" and isinstance(r.get("external_id"), str)]
    return refs[0] if refs else ""


def schema(con):
    con.execute("PRAGMA foreign_keys=ON")
    con.executescript("""
      CREATE TABLE entities (
        stix_id TEXT PRIMARY KEY, type TEXT NOT NULL CHECK(type IN
          ('attack-pattern','malware','tool','intrusion-set','campaign','course-of-action')),
        name TEXT NOT NULL, name_fold TEXT NOT NULL, external_id TEXT NOT NULL, modified TEXT NOT NULL);
      CREATE INDEX entities_name ON entities(name_fold);
      CREATE INDEX entities_external ON entities(external_id);
      CREATE TABLE edges (
        stix_id TEXT PRIMARY KEY CHECK(stix_id GLOB 'relationship--*'),
        type TEXT NOT NULL CHECK(type IN ('uses','mitigates','subtechnique-of','attributed-to')),
        source_ref TEXT NOT NULL REFERENCES entities(stix_id),
        target_ref TEXT NOT NULL REFERENCES entities(stix_id),
        modified TEXT NOT NULL CHECK(length(modified)>0),
        bundle_sha256 TEXT NOT NULL CHECK(length(bundle_sha256)=64 AND bundle_sha256 NOT GLOB '*[^0-9a-f]*'));
      CREATE INDEX edges_source ON edges(source_ref);
      CREATE INDEX edges_target ON edges(target_ref);
      CREATE TRIGGER edges_endpoints_insert BEFORE INSERT ON edges
        WHEN NOT EXISTS(SELECT 1 FROM entities WHERE stix_id=NEW.source_ref)
          OR NOT EXISTS(SELECT 1 FROM entities WHERE stix_id=NEW.target_ref)
        BEGIN SELECT RAISE(ABORT,'Missing STIX endpoint'); END;
      CREATE TRIGGER edges_endpoints_update BEFORE UPDATE OF source_ref,target_ref ON edges
        WHEN NOT EXISTS(SELECT 1 FROM entities WHERE stix_id=NEW.source_ref)
          OR NOT EXISTS(SELECT 1 FROM entities WHERE stix_id=NEW.target_ref)
        BEGIN SELECT RAISE(ABORT,'Missing STIX endpoint'); END;
      CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
    """)


# C3/C4 share this database with STIX; replacement must carry their history and guards.
CODE_GRAPH_TABLES = ("code_graph_meta", "attack_nodes", "attack_edges", "technique_links",
                     "graph_snapshots", "attack_revisions")
VERIFY_TABLES = ("verify_meta", "verification_evidence", "evidence_revocations", "path_verdicts")
VERIFY_TRIGGERS = {"verification_evidence_scope", "verification_evidence_no_update", "verification_evidence_no_delete",
                   "evidence_revocations_no_update", "evidence_revocations_no_delete", "path_verdicts_no_update",
                   "path_verdicts_no_delete", "verify_nodes_delete_guard", "verification_evidence_snapshot"}


def carry_code_graph(new, old=None):
    """Copy C3 then C4, preserving history and schema objects; refuse incomplete schemas."""
    if not DB.exists():
        return {}
    with ExitStack() as stack:
        if old is None:
            old = stack.enter_context(closing(connect()))
            old.execute("BEGIN")
        names = {r[0] for r in old.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        present = [t for t in (*CODE_GRAPH_TABLES, *VERIFY_TABLES) if t in names]
        if not present:
            return {}
        for tables, marker, layer in ((CODE_GRAPH_TABLES, "code_graph_meta", "3"), (VERIFY_TABLES, "verify_meta", "4")):
            if not names.intersection(tables) and layer == "4":
                continue
            if not set(tables) <= names:
                raise ValueError("Unsafe rebuild: incomplete Layer " + layer + " schema; old database preserved")
            version = old.execute("SELECT value FROM " + marker + " WHERE key='schema_version'").fetchone()
            supported = {("1",)} if layer == "3" else {("1",), ("2",)}
            if version not in supported:
                raise ValueError("Unsafe rebuild: unsupported Layer " + layer + " schema; migrate explicitly")
        if "verify_meta" in names:
            triggers = {r[0] for r in old.execute("SELECT name FROM sqlite_master WHERE type='trigger'")}
            version = old.execute("SELECT value FROM verify_meta WHERE key='schema_version'").fetchone()
            required_triggers = VERIFY_TRIGGERS if version == ("2",) else VERIFY_TRIGGERS - {"verification_evidence_snapshot"}
            if not required_triggers <= triggers:
                raise ValueError("Unsafe rebuild: missing Layer 4 integrity triggers; old database preserved")
        if old.execute("PRAGMA integrity_check").fetchall() != [("ok",)] or old.execute("PRAGMA foreign_key_check").fetchall():
            raise ValueError("Unsafe rebuild: source database integrity failure; old database preserved")
        marks = ",".join("?" * len(present))
        ddl = {kind: old.execute("SELECT sql FROM sqlite_master WHERE type=? AND sql IS NOT NULL AND tbl_name IN (%s) ORDER BY name" % marks,
                                 (kind, *present)).fetchall() for kind in ("table", "index", "trigger")}
        for (sql,) in ddl["table"]:
            new.execute(sql)
        carried = {}
        for table in present:  # fixed tuple order: parents before children
            cursor = old.execute("SELECT * FROM " + table)
            width = len(cursor.description)
            new.executemany("INSERT INTO %s VALUES(%s)" % (table, ",".join("?" * width)), cursor)
            carried[table] = new.execute("SELECT count(*) FROM " + table).fetchone()[0]
        if "verify_meta" not in names and new.execute(
                "SELECT 1 FROM attack_edges WHERE verification_state='FEASIBLE_PATH' LIMIT 1").fetchone():
            raise ValueError("Unsafe rebuild: FEASIBLE_PATH without Layer 4 history; old database preserved")
        # Rebuild cannot revalidate artifacts; retain verdict history, require fresh verify --write.
        new.execute("UPDATE attack_edges SET verification_state='STRUCTURAL_HYPOTHESIS' WHERE verification_state='FEASIBLE_PATH'")
        for kind in ("index", "trigger"):  # triggers last, so copying rows does not fire them
            for (sql,) in ddl[kind]:
                new.execute(sql)
        return carried


def build(bundle=None, metadata=None):
    if bundle is None:
        bundle, metadata = load_cached()
    if not metadata or not SHA256.fullmatch(str(metadata.get("sha256", ""))):
        raise ValueError("Bundle evidence hash missing")
    objects = bundle["objects"]
    entities = {}
    # Reject duplicate IDs rather than make feed order choose a version.
    seen = set()
    for obj in objects:
        identifier = checked_id(obj)
        if identifier in seen:
            raise ValueError("Duplicate STIX ID: " + identifier)
        seen.add(identifier)
        if obj["type"] in ENTITY_TYPES and active(obj):
            entities[identifier] = obj
    DB.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(dir=DB.parent, prefix=".attack-", suffix=".sqlite3")
    os.close(fd)
    rejected = collections.Counter()
    try:
        with ExitStack() as stack:
            old = None
            if DB.exists():
                old = stack.enter_context(closing(sqlite3.connect(
                    "file:" + urllib.parse.quote(str(DB), safe="/") + "?mode=rw", uri=True)))
                if old.execute("PRAGMA journal_mode").fetchone()[0] == "wal":
                    raise ValueError("Unsafe rebuild: WAL database; stop writers and migrate to DELETE journal mode first")
                old.execute("BEGIN IMMEDIATE")  # hold writer exclusion through replacement
            con = stack.enter_context(closing(sqlite3.connect(temporary)))
            schema(con)
            for identifier, obj in entities.items():
                name = obj.get("name")
                if not isinstance(name, str) or not name.strip():
                    raise ValueError("STIX entity name missing")
                con.execute("INSERT INTO entities VALUES(?,?,?,?,?,?)",
                            (identifier, obj["type"], name, name.casefold(), external_id(obj), modified(obj)))
            for obj in objects:
                if obj["type"] != "relationship":
                    continue
                if obj.get("relationship_type") not in EDGE_TYPES:
                    rejected["unsupported_type"] += 1
                    continue
                if not active(obj):
                    rejected["inactive_relationship"] += 1
                    continue
                if obj.get("source_ref") not in entities or obj.get("target_ref") not in entities:
                    rejected["inactive_or_missing_endpoint"] += 1
                    continue
                con.execute("INSERT INTO edges VALUES(?,?,?,?,?,?)",
                            (obj["id"], obj["relationship_type"], obj["source_ref"], obj["target_ref"], modified(obj), metadata["sha256"]))
            stored = dict(metadata, built_at=now(), schema_version=1, rejected=dict(rejected))
            for key, value in stored.items():
                con.execute("INSERT INTO metadata VALUES(?,?)", (key, json.dumps(value)))
            carried = carry_code_graph(con, old)
            con.commit()
            if con.execute("PRAGMA foreign_key_check").fetchall():
                raise ValueError("Unsafe rebuild: orphan references; old database preserved")
            if con.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
                raise ValueError("Unsafe rebuild: destination integrity failure; old database preserved")
            report = graph_stats(con)
            if carried:
                report["code_graph_carried"] = carried
            con.close()
            os.chmod(temporary, 0o600)
            os.replace(temporary, DB)
    except sqlite3.Error as exc:
        raise ValueError("Unsafe rebuild: %s; old database preserved" % exc) from exc
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    report["peak_rss_kib"] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    report["rlimit_as_bytes"] = resource.getrlimit(resource.RLIMIT_AS)[0]
    return report


def connect():
    if not DB.exists():
        raise ValueError("ATT&CK graph missing: run graph-refresh (or graph-build offline)")
    con = sqlite3.connect("file:" + urllib.parse.quote(str(DB), safe="/") + "?mode=ro", uri=True)
    return con


def graph_stats(con):
    return {"entities": con.execute("SELECT count(*) FROM entities").fetchone()[0],
            "entities_by_type": dict(con.execute("SELECT type,count(*) FROM entities GROUP BY type")),
            "edges": con.execute("SELECT count(*) FROM edges").fetchone()[0],
            "edges_by_type": dict(con.execute("SELECT type,count(*) FROM edges GROUP BY type")),
            "metadata": {k: json.loads(v) for k, v in con.execute("SELECT key,value FROM metadata ORDER BY key")}}


def stats():
    with closing(connect()) as con:
        return graph_stats(con)


def query(identifier, limit=50, all_edges=False):
    identifier = identifier.strip()
    limit = max(1, min(limit, 200))
    with closing(connect()) as con:
        con.execute("BEGIN")  # Metadata, entities and edges share one read snapshot.
        nodes = con.execute("SELECT stix_id,type,name,external_id FROM entities WHERE stix_id=? OR external_id=? OR name_fold=? ORDER BY stix_id",
                            (identifier, identifier.upper(), identifier.casefold())).fetchall()
        entity_columns = ("stix_id", "type", "name", "external_id")
        metadata = {key: json.loads(value) for key, value in con.execute(
            "SELECT key,value FROM metadata WHERE key IN ('sha256','source_id','url')")}
        result = {"query": identifier, "entities": [dict(zip(entity_columns, n)) for n in nodes],
                  "metadata": metadata, "outbound": [], "inbound": [], "counts": {}}
        for direction, column in (("outbound", "source_ref"), ("inbound", "target_ref")):
            # Match nodes in SQL rather than interpolate IDs or produce 1000s of placeholders.
            where = "e." + column + " IN (SELECT stix_id FROM entities WHERE stix_id=? OR external_id=? OR name_fold=?)"
            params = (identifier, identifier.upper(), identifier.casefold())
            total = con.execute("SELECT count(*) FROM edges e WHERE " + where, params).fetchone()[0]
            result["counts"][direction] = total
            rows = con.execute("SELECT e.stix_id,e.type,e.modified,e.bundle_sha256,s.stix_id,s.name,s.type,t.stix_id,t.name,t.type "
                               "FROM edges e JOIN entities s ON s.stix_id=e.source_ref JOIN entities t ON t.stix_id=e.target_ref WHERE " + where +
                               " ORDER BY e.type,s.name,t.name,e.stix_id" + ("" if all_edges else " LIMIT ?"),
                               params if all_edges else params + (limit,))
            for edge_id, edge_type, timestamp, sha, sid, sname, stype, tid, tname, ttype in rows:
                result[direction].append({"stix_id": edge_id, "type": edge_type,
                    "source": {"stix_id": sid, "name": sname, "type": stype},
                    "target": {"stix_id": tid, "name": tname, "type": ttype},
                    "origin": {"source_id": SOURCE, "url": URL, "modified": timestamp, "bundle_sha256": sha}})
        result["limit_per_direction"] = None if all_edges else limit
        return result


def run(action, identifier="", limit=50, as_json=False, all_edges=False):
    if all_edges and not as_json:
        raise ValueError("--all requires --json")
    if action in ("graph-sync", "graph-build", "graph-refresh"):
        limit_memory()
    if action == "graph-sync":
        _, result = sync_bundle()
    elif action == "graph-build":
        result = build()
    elif action == "graph-refresh":
        bundle, metadata = sync_bundle()
        result = build(bundle, metadata)
    elif action == "graph-stats":
        result = stats()
    else:
        result = query(identifier, limit, all_edges)
    if as_json or action != "graph":
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        for node in result["entities"]:
            print(node["external_id"], node["name"], "|", node["type"], "|", node["stix_id"])
        for direction in ("outbound", "inbound"):
            print(direction + ":", len(result[direction]), "of", result["counts"][direction])
            for edge in result[direction]:
                print(" ", edge["source"]["name"], "--" + edge["type"] + "-->", edge["target"]["name"])
                print("   origin:", edge["stix_id"], edge["origin"]["modified"], edge["origin"]["bundle_sha256"], URL)
    return result
