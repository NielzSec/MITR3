"""Version diff between two firmware inventories."""
from __future__ import annotations

import json


def _index(inv: dict) -> dict:
    return {e["path"]: e for e in inv.get("entries", [])}


def diff(old: dict, new: dict) -> dict:
    a, b = _index(old), _index(new)
    added = sorted(set(b) - set(a))
    removed = sorted(set(a) - set(b))
    modified = []
    for path in sorted(set(a) & set(b)):
        ea, eb = a[path], b[path]
        if ea.get("sha256") != eb.get("sha256"):
            change = {"path": path, "old_sha256": ea.get("sha256"), "new_sha256": eb.get("sha256")}
            if ea.get("elf") or eb.get("elf"):
                change["elf_old"] = ea.get("elf")
                change["elf_new"] = eb.get("elf")
            modified.append(change)
    return {
        "old_root": old.get("root"),
        "new_root": new.get("root"),
        "added": added,
        "removed": removed,
        "modified": modified,
        "counts": {
            "added": len(added),
            "removed": len(removed),
            "modified": len(modified),
            "old_files": old.get("files"),
            "new_files": new.get("files"),
        },
    }


def diff_files(old_json: str, new_json: str) -> dict:
    with open(old_json) as fh:
        old = json.load(fh)
    with open(new_json) as fh:
        new = json.load(fh)
    return diff(old, new)
