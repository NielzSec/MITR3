"""Markdown evidence report built from inspect/inventory/diff artifacts."""
from __future__ import annotations

import datetime


def _table(rows, header):
    out = ["| " + " | ".join(header) + " |", "|" + "|".join(["---"] * len(header)) + "|"]
    for r in rows:
        out.append("| " + " | ".join(str(c) for c in r) + " |")
    return "\n".join(out)


def build(title: str, inspect: dict | None = None, inv: dict | None = None,
          queue: list[dict] | None = None, delta: dict | None = None) -> str:
    lines = [f"# {title}", "", f"_generated {datetime.datetime.now().isoformat(timespec='seconds')}_", ""]

    if inspect:
        lines += [
            "## Container", "",
            _table(
                [[inspect.get("path"), inspect.get("type"), inspect.get("size"),
                  inspect.get("confidence"), inspect.get("entropy"), inspect.get("note", "")]],
                ["path", "type", "size", "confidence", "entropy", "note"],
            ), "",
        ]

    if inv:
        top = list(inv.get("by_ext", {}).items())[:8]
        lines += [
            "## Inventory", "",
            f"- root: `{inv.get('root')}`",
            f"- files: **{inv.get('files')}**",
            f"- ELF binaries: **{inv.get('elf_count')}**",
            "- extensions: " + ", ".join(f"`{k}`×{v}" for k, v in top),
            "",
        ]
        interesting = [e for e in inv.get("entries", []) if e.get("interesting_name")][:15]
        if interesting:
            lines += ["### Names worth reading", ""]
            for e in interesting:
                lines.append(f"- `{e['path']}` ({e['size']} B)")
            lines.append("")

    if queue:
        lines += ["## Ghidra queue", ""]
        lines.append(_table(
            [[q["score"], f"`{q['path']}`", q["arch"], q["class"], "stripped" if q["stripped"] else "symbols", ", ".join(q["reasons"])]
             for q in queue[:20]],
            ["score", "binary", "arch", "bits", "state", "reasons"],
        ))
        lines.append("")

    if delta:
        c = delta["counts"]
        lines += [
            "## Version delta", "",
            f"- added: **{c['added']}**",
            f"- removed: **{c['removed']}**",
            f"- modified: **{c['modified']}**",
            "",
        ]
        for m in delta.get("modified", [])[:20]:
            lines.append(f"- `{m['path']}`")
        if delta.get("modified"):
            lines.append("")

    return "\n".join(lines) + "\n"
