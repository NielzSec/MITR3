"""Ghidra work queue: rank binaries worth reversing first.

The score is explainable (each rule adds points and a reason), because a queue
nobody can justify is a queue nobody trusts.
"""
from __future__ import annotations

import json
import os
import shutil

RULES = [
    ("in_web_root", 30, lambda p: any(k in p.lower() for k in ("cgi-bin", "/www", "/htdocs", "/web/"))),
    ("init_or_service", 25, lambda p: any(k in p.lower() for k in ("init.d", "rcs", "systemd", "lighttpd", "nginx", "httpd", "dropbear"))),
    ("auth_strings", 25, lambda p: False),  # filled from inventory strings below
    ("spawn_strings", 15, lambda p: False),
    ("setuid", 20, lambda p: False),
    ("elf_exec", 10, lambda p: False),
]

AUTH_HINTS = {"strcmp", "strncmp", "session", "token", "password", "admin", "X-", "Authorization"}
SPAWN_HINTS = {"system", "popen", "execve", "/bin/sh"}


def score_entry(entry: dict) -> tuple[int, list[str]]:
    path = entry["path"]
    score = 0
    reasons = []
    for name, pts, fn in RULES:
        if name == "elf_exec" and entry.get("elf") and entry.get("exec"):
            score += pts
            reasons.append(name)
        elif name == "setuid" and entry.get("setuid"):
            score += pts
            reasons.append(name)
        elif name == "auth_strings":
            hits = set((entry.get("strings") or {}).get("hits", []))
            if hits & AUTH_HINTS:
                score += pts
                reasons.append(name + ":" + ",".join(sorted(hits & AUTH_HINTS))[:60])
        elif name == "spawn_strings":
            hits = set((entry.get("strings") or {}).get("hits", []))
            if hits & SPAWN_HINTS:
                score += pts
                reasons.append(name + ":" + ",".join(sorted(hits & SPAWN_HINTS))[:60])
        elif fn(path):
            score += pts
            reasons.append(name)
    return score, reasons


def build_queue(inv: dict, min_score: int = 20) -> list[dict]:
    queue = []
    for entry in inv.get("entries", []):
        if not entry.get("elf"):
            continue
        score, reasons = score_entry(entry)
        if score < min_score:
            continue
        queue.append({
            "path": entry["path"],
            "sha256": entry["sha256"],
            "size": entry["size"],
            "arch": entry["elf"].get("machine"),
            "class": entry["elf"].get("class"),
            "endian": entry["elf"].get("endian"),
            "stripped": entry["elf"].get("stripped"),
            "score": score,
            "reasons": reasons,
        })
    queue.sort(key=lambda q: (-q["score"], q["path"]))
    return queue


def write_queue(queue: list[dict], out_path: str) -> str:
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with open(out_path, "w") as fh:
        for item in queue:
            fh.write(json.dumps(item, sort_keys=True) + "\n")
    return out_path


def headless_command(project_dir: str, project_name: str, binary: str, script: str, out_dir: str) -> list[str]:
    analyze = shutil.which("analyzeHeadless") or "/opt/ghidra/support/analyzeHeadless"
    return [
        analyze,
        project_dir,
        project_name,
        "-import", binary,
        "-scriptPath", os.path.dirname(os.path.abspath(script)),
        "-postScript", os.path.basename(script), out_dir,
        "-deleteProject",
    ]