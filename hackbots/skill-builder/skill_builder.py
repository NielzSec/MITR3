#!/usr/bin/env python3
"""MITR3 Skill Builder v0.2: generate/audit offline drafts; never execute or promote skills."""
import argparse
import hashlib
import json
import os
import re
import stat
import sys
from decimal import Decimal, InvalidOperation
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[2]
BASE = Path(__file__).resolve().parent
DRAFTS = BASE / "drafts"
NAME = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
STEP = re.compile(r"M[0-9]{2}\Z")
CASE = re.compile(r"E[0-9]{2}\Z")
HEX = re.compile(r"[a-f0-9]{64}\Z")
MAX_BYTES = 1_000_000


class GateError(ValueError):
    pass


def digest(data):
    return hashlib.sha256(data).hexdigest()


def within_project(relative):
    """Restrict source inputs to local non-symlink files under the MITR3 project."""
    if not isinstance(relative, str) or not relative or "\x00" in relative:
        raise GateError("invalid file path")
    p = Path(relative)
    if p.is_absolute() or not p.parts or any(part in (".", "..") for part in p.parts):
        raise GateError("file path must be project-relative without traversal")
    cur = PROJECT
    for part in p.parts:
        cur = cur / part
        if cur.is_symlink():
            raise GateError("symlink files or parents forbidden")
    try:
        full = cur.resolve(strict=True)
        full.relative_to(PROJECT.resolve())
    except (OSError, ValueError) as exc:
        raise GateError("source missing or outside project") from exc
    if not full.is_file() or full.stat().st_size > MAX_BYTES:
        raise GateError("source must be a regular file of at most 1 MB")
    return full


def read_bytes(path):
    """Walk directory descriptors so symlink swaps cannot redirect the read."""
    try:
        parts = Path(path).relative_to(PROJECT).parts
        if not parts or any(part in (".", "..") for part in parts):
            raise GateError("file must be inside project")
        parent = os.open(PROJECT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for part in parts[:-1]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                os.close(parent)
                parent = child
            fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        finally:
            os.close(parent)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_BYTES:
                raise GateError("input must be a regular file of at most 1 MB")
            raw = stream.read(MAX_BYTES + 1)
            if len(raw) > MAX_BYTES:
                raise GateError("input exceeds 1 MB")
            return raw
    except (OSError, ValueError) as exc:
        raise GateError("local file missing, unsafe, oversized or unreadable") from exc


def parse_json(raw):
    def unique_object(pairs):
        obj = {}
        for key, value in pairs:
            if key in obj:
                raise GateError("duplicate JSON key")
            obj[key] = value
        return obj

    def invalid_constant(_):
        raise GateError("non-finite JSON number")

    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object,
                          parse_constant=invalid_constant, parse_float=Decimal)
    except (UnicodeError, ValueError, InvalidOperation, RecursionError) as exc:
        raise GateError("invalid JSON input") from exc


def read_json(path):
    return parse_json(read_bytes(path))


def require_keys(obj, keys, label):
    if not isinstance(obj, dict) or set(obj) != set(keys):
        raise GateError(f"invalid {label} object or fields")


def single_line(val, maxlen):
    return (isinstance(val, str) and bool(val.strip()) and len(val) <= maxlen
            and not any(ord(c) < 32 or 127 <= ord(c) <= 159 or c in "\u2028\u2029"
                        or 0xD800 <= ord(c) <= 0xDFFF for c in val))


def field(obj, key, kind=str, maxlen=500):
    val = obj.get(key) if isinstance(obj, dict) else None
    if type(val) is not kind or (kind is str and not single_line(val, maxlen)):
        raise GateError(f"invalid or missing {key}")
    return val


def items(obj, key, maxitems=30):
    val = obj.get(key)
    if not isinstance(val, list) or not (1 <= len(val) <= maxitems):
        raise GateError(f"{key} must contain 1..{maxitems} items")
    return val


def validate_spec(data):
    if not isinstance(data, dict):
        raise GateError("methodology must be an object")
    required = {"name", "description", "goal", "inputs", "output", "steps", "stop_conditions", "allowed_tools", "evals", "source"}
    if set(data) != required:
        raise GateError("methodology keys missing or unexpected")
    name = field(data, "name", maxlen=64)
    if not NAME.fullmatch(name) or name.startswith("mitr3-hb-maestro"):
        raise GateError("invalid or reserved skill name")
    field(data, "description", maxlen=1024)
    field(data, "goal", maxlen=250)
    field(data, "output", maxlen=250)
    for key in ("inputs", "stop_conditions"):
        seq = items(data, key, 12)
        if any(not single_line(v, 230) for v in seq):
            raise GateError("invalid input/stop text")
    tools = items(data, "allowed_tools", 12)
    if any(not isinstance(t, str) or t not in ("read_local","python_readonly","megabrain_read") for t in tools) or len(set(tools)) != len(tools):
        raise GateError("tool names must be from offline read-only allowlist")
    seen = set()
    for row in items(data, "steps", 16):
        if not isinstance(row, dict) or set(row) != {"id", "instruction", "evidence"}:
            raise GateError("every step requires id, instruction, evidence")
        sid = field(row, "id", maxlen=3)
        if not STEP.fullmatch(sid) or sid in seen:
            raise GateError("duplicate or invalid step ID")
        seen.add(sid)
        field(row, "instruction", maxlen=240)
        field(row, "evidence", maxlen=200)
    kinds = set()
    seen = set()
    for row in items(data, "evals", 16):
        if not isinstance(row, dict) or set(row) != {"id","kind","input","expected"}:
            raise GateError("eval must have id, kind, input, expected")
        eid = field(row, "id", maxlen=3)
        if not CASE.fullmatch(eid) or eid in seen:
            raise GateError("duplicate or invalid eval ID")
        seen.add(eid)
        kind = field(row, "kind")
        if kind not in ("positive", "negative"):
            raise GateError("unknown eval kind")
        kinds.add(kind)
        field(row, "input", maxlen=350)
        field(row, "expected", maxlen=350)
    if kinds != {"positive", "negative"}:
        raise GateError("at least one positive and one negative evaluation required")
    src = data["source"]
    if not isinstance(src, dict) or set(src) != {"path","sha256","approved_by_operator"}:
        raise GateError("source needs path, sha256, approved_by_operator")
    path = field(src, "path", maxlen=300)
    sh = field(src, "sha256", maxlen=64)
    if not HEX.fullmatch(sh):
        raise GateError("bad source SHA256")
    # Approval is a statement in a method file, never authorization; this flag must remain false
    # until an independent operator-controlled approval workflow exists.
    if src["approved_by_operator"] is not False:
        raise GateError("operator approval cannot be set by the builder")
    actual = digest(read_bytes(within_project(path)))
    if actual != sh:
        raise GateError("source SHA256 mismatch")
    return data


def render(data):
    out = [
        "---",
        f"name: {data['name']}",
        f"description: {json.dumps(data['description'], ensure_ascii=False)}",
        'compatibility: "MITR3 Hackbots offline pilot; candidate only; no target network access"',
        "metadata:",
        '  version: "0.1.0-draft"',
        '  state: "review-required"',
        "---",
        f"# {data['name']} — RASCUNHO / NÃO APROVADO",
        "",
        "**Tarefa única:** " + data["goal"],
        "**Limite:** skill candidata; não permite operações ativas nem ingestão automática no MegaBrain.",
        "",
        "## Entradas",
    ]
    out += ["- " + x for x in data["inputs"]]
    out += ["", "## Procedimento obrigatório (IDs verificáveis)"]
    for row in data["steps"]:
        out.append(f"- **[{row['id']}]** {row['instruction']} **Evidência exigida:** {row['evidence']}")
    out += ["", "## Ferramentas previstas (não são permissões técnicas)"]
    out += ["- " + x for x in data["allowed_tools"]]
    out += ["", "## Condições de parada"]
    out += ["- " + x for x in data["stop_conditions"]]
    out += ["", "## Entregável", data["output"], "",
            "## Testes comportamentais ainda não executados"]
    for e in data["evals"]:
        out.append(f"- **[{e['id']}] {e['kind'].upper()}** — entrada: {e['input']}; esperado: {e['expected']}")
    out += ["", "**GATE:** formato e passos podem ser auditados offline; conformidade comportamental e validade de evidências requerem avaliação independente e aprovação humana.",
            f"**Fonte original (hash fixado):** `{data['source']['path']}` (SHA256: {data['source']['sha256']})"]
    txt = "\n".join(out) + "\n"
    if len(txt.splitlines()) > 200:
        raise GateError("generated SKILL.md exceeds 200 lines")
    return txt


def check_draft_root():
    try:
        parts = DRAFTS.relative_to(PROJECT).parts
    except ValueError as exc:
        raise GateError("draft root must be inside project") from exc
    current = PROJECT
    for part in parts:
        current = current / part
        if part == ".." or current.is_symlink():
            raise GateError("symlink/traversal in draft root")
    if not DRAFTS.is_dir():
        raise GateError("draft root missing")


def new_draft(file):
    original = within_project(file)
    method_bytes = read_bytes(original)
    data = validate_spec(parse_json(method_bytes))
    name = data["name"]
    check_draft_root()
    dest = DRAFTS / name
    if dest.exists() or dest.is_symlink():
        raise GateError("draft already exists; overwriting is forbidden")
    rendered = render(data)
    dest.mkdir(parents=True, exist_ok=False)
    (dest / "methodology.json").write_bytes(method_bytes)
    (dest / "SKILL.md").write_text(rendered, encoding="utf-8")
    manifest = {
        "state": "PENDING", "name": name, "method_sha256": digest(method_bytes),
        "skill_sha256": digest(rendered.encode("utf-8")),
        "step_ids": [s["id"] for s in data["steps"]],
        "eval_ids": [e["id"] for e in data["evals"]],
        "human_approval": None, "eval_runs": 0
    }
    (dest / "manifest.json").write_text(json.dumps(manifest, indent=2,ensure_ascii=False)+"\n", encoding="utf-8")
    return audit(name)


def inspect_draft(name):
    if not isinstance(name, str) or len(name) > 64 or not NAME.fullmatch(name):
        raise GateError("invalid name")
    check_draft_root()
    directory = DRAFTS / name
    if directory.is_symlink() or not directory.is_dir():
        raise GateError("draft directory missing/unsafe")
    expected_files = {"methodology.json","SKILL.md","manifest.json"}
    if {p.name for p in directory.iterdir()} != expected_files:
        raise GateError("unexpected or missing files in draft")
    for file in expected_files:
        if (directory / file).is_symlink():
            raise GateError("symlink in draft")
    method_bytes = read_bytes(directory / "methodology.json")
    data = validate_spec(parse_json(method_bytes))
    manifest = read_json(directory / "manifest.json")
    require_keys(manifest, {"state", "name", "method_sha256", "skill_sha256", "step_ids",
                            "eval_ids", "human_approval", "eval_runs"}, "manifest")
    skill_bytes = read_bytes(directory / "SKILL.md")
    expected_skill = render(data).encode("utf-8")
    step_ids = [s["id"] for s in data["steps"]]
    eval_ids = [e["id"] for e in data["evals"]]
    failures = []
    if data["name"] != name or manifest.get("name") != name:
        failures.append("name mismatch")
    if digest(method_bytes) != manifest.get("method_sha256"):
        failures.append("method changed since generation")
    if digest(skill_bytes) != manifest.get("skill_sha256") or skill_bytes != expected_skill:
        failures.append("draft skill modified or missing required instructions")
    if step_ids != manifest.get("step_ids") or eval_ids != manifest.get("eval_ids"):
        failures.append("required units differ from manifest")
    if manifest["human_approval"] is not None or type(manifest["eval_runs"]) is not int or manifest["eval_runs"] != 0:
        failures.append("manual state changes are not recognized as approvals/evals")
    if manifest.get("state") != "PENDING":
        failures.append("only PENDING draft state is supported")
    return data, {
        "name": name, "state": "FAILED" if failures else "REVIEW",
        "method_sha256": digest(method_bytes), "skill_sha256": digest(skill_bytes),
        "structural_gate": "FAIL" if failures else "PASS",
        "checks_required": len(step_ids), "checks_present": 0 if failures else len(step_ids),
        "evals_required": len(eval_ids), "evals_executed": 0,
        "human_approved": False, "promotable": False,
        "failures": failures,
        "limitations": "Checks prove internal consistency, not authenticity, authorized edits, worker execution or claim truth."
    }


def audit(name):
    return inspect_draft(name)[1]


def main():
    p=argparse.ArgumentParser(description=__doc__)
    commands=p.add_subparsers(dest="command",required=True)
    n=commands.add_parser("new",help="generate a new review-required draft from methodology JSON")
    n.add_argument("methodology",help="project-relative JSON file path")
    a=commands.add_parser("audit",help="read-only structural audit of one draft")
    a.add_argument("name")
    args=p.parse_args()
    try:
        result=new_draft(args.methodology) if args.command=="new" else audit(args.name)
        print(json.dumps(result,ensure_ascii=False,indent=2))
        return int(result["structural_gate"] != "PASS")
    except (GateError,OSError,ValueError,UnicodeError) as exc:
        print(json.dumps({"state":"BLOCKED","error":str(exc)},ensure_ascii=False), file=sys.stderr)
        return 2


if __name__=="__main__":
    sys.exit(main())
