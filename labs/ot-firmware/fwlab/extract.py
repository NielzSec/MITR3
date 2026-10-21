"""Bounded, path-safe extraction of firmware containers.

Rules:
  * never follow symlinks/hardlinks out of the destination
  * reject absolute paths and `..` components
  * cap file count, total bytes and recursion depth
  * extraction writes data only; nothing is executed
"""
from __future__ import annotations

import gzip
import lzma
import os
import shutil
import tarfile
import zipfile

from . import formats

DEFAULT_LIMITS = {
    "max_files": 20000,
    "max_bytes": 2 * 1024 ** 3,
    "max_depth": 4,
}


class ExtractError(RuntimeError):
    pass


def _safe_join(root: str, member: str) -> str:
    member = member.replace("\\", "/").lstrip("/")
    parts = [p for p in member.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        raise ExtractError(f"path traversal rejected: {member!r}")
    target = os.path.normpath(os.path.join(root, *parts))
    root_abs = os.path.abspath(root)
    if not os.path.abspath(target).startswith(root_abs + os.sep) and os.path.abspath(target) != root_abs:
        raise ExtractError(f"escape rejected: {member!r}")
    return target


def _is_safe_dest(dest: str, target: str) -> bool:
    root_real = os.path.realpath(dest)
    rel = os.path.relpath(target, dest)
    curr = dest
    for part in rel.split(os.sep):
        if part in ("", "."):
            continue
        curr = os.path.join(curr, part)
        if os.path.islink(curr):
            link_real = os.path.realpath(curr)
            if not (link_real == root_real or link_real.startswith(root_real + os.sep)):
                return False
        elif os.path.exists(curr):
            real = os.path.realpath(curr)
            if not (real == root_real or real.startswith(root_real + os.sep)):
                return False
    return True


def _check_path_conflict(target: str) -> None:
    parent = os.path.dirname(target)
    while parent and parent != os.path.dirname(parent):
        if os.path.isfile(parent):
            raise ExtractError(f"path conflict: parent is file: {parent}")
        parent = os.path.dirname(parent)
    if os.path.isdir(target):
        raise ExtractError(f"path conflict: target is directory: {target}")


class Budget:
    def __init__(self, limits=None):
        merged = dict(DEFAULT_LIMITS)
        merged.update(limits or {})
        self.max_files = merged["max_files"]
        self.max_bytes = merged["max_bytes"]
        self.max_depth = merged["max_depth"]
        self.files = 0
        self.bytes = 0

    def spend(self, nbytes: int):
        self.files += 1
        self.bytes += nbytes
        if self.files > self.max_files:
            raise ExtractError(f"file budget exceeded ({self.max_files})")
        if self.bytes > self.max_bytes:
            raise ExtractError(f"byte budget exceeded ({self.max_bytes})")


def _extract_tar(path: str, dest: str, budget: Budget) -> list[str]:
    written = []
    with tarfile.open(path, "r:*") as tf:
        for member in tf.getmembers():
            target = _safe_join(dest, member.name)
            if member.isdir():
                if not _is_safe_dest(dest, target):
                    continue
                _check_path_conflict(target)
                os.makedirs(target, exist_ok=True)
                continue
            if member.issym() or member.islnk():
                link_target = member.linkname
                if os.path.isabs(link_target):
                    continue
                member_dir = os.path.dirname(target)
                resolved = os.path.normpath(os.path.join(member_dir, link_target))
                root_abs = os.path.abspath(dest)
                if not (resolved == root_abs or resolved.startswith(root_abs + os.sep)):
                    continue
                continue
            if not member.isfile():
                continue
            if not _is_safe_dest(dest, target):
                continue
            _check_path_conflict(target)
            budget.spend(member.size)
            os.makedirs(os.path.dirname(target), exist_ok=True)
            src = tf.extractfile(member)
            if src is None:
                continue
            with open(target, "wb") as out:
                shutil.copyfileobj(src, out, length=1024 * 64)
            mode = member.mode & 0o777
            os.chmod(target, mode or 0o644)
            written.append(target)
    return written


def _extract_zip(path: str, dest: str, budget: Budget) -> list[str]:
    written = []
    with zipfile.ZipFile(path) as zf:
        for info in zf.infolist():
            target = _safe_join(dest, info.filename)
            if not _is_safe_dest(dest, target):
                continue
            _check_path_conflict(target)
            if info.is_dir():
                os.makedirs(target, exist_ok=True)
                continue
            mode = (info.external_attr >> 16) & 0o777
            if (info.external_attr >> 16) & 0o170000 == 0o120000:
                continue  # symlink entry, skip
            budget.spend(info.file_size)
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with zf.open(info) as src, open(target, "wb") as out:
                shutil.copyfileobj(src, out, length=1024 * 64)
            if mode:
                os.chmod(target, mode)
            written.append(target)
    return written


def _extract_stream(path: str, dest: str, kind: str, budget: Budget) -> list[str]:
    base = os.path.basename(path)
    for suffix in (".gz", ".gzip", ".xz", ".lzma"):
        if base.lower().endswith(suffix):
            base = base[: -len(suffix)]
            break
    target = _safe_join(dest, base or "payload.bin")
    if not _is_safe_dest(dest, target):
        return []
    _check_path_conflict(target)
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(path, "rb") as src, open(target, "wb") as out:
        if kind == "gzip":
            data = gzip.GzipFile(fileobj=src)
        else:
            data = lzma.LZMAFile(src)
        while True:
            chunk = data.read(1024 * 64)
            if not chunk:
                break
            budget.spend(len(chunk))
            out.write(chunk)
    return [target]


def extract(path: str, dest: str, budget: Budget | None = None, depth: int = 0) -> dict:
    """Extract *path* into *dest*. Returns a manifest of what happened."""
    budget = budget or Budget()
    os.makedirs(dest, exist_ok=True)
    info = formats.detect(path)
    fmt = info["type"]
    if depth > budget.max_depth:
        return {"skip": "max depth", "format": fmt, "written": []}

    try:
        if fmt == "tar":
            written = _extract_tar(path, dest, budget)
        elif fmt == "zip":
            written = _extract_zip(path, dest, budget)
        elif fmt in ("gzip", "xz"):
            written = _extract_stream(path, dest, fmt, budget)
        elif fmt in ("squashfs", "cramfs", "ubi", "ubifs", "jffs2", "spk"):
            return {
                "format": fmt,
                "written": [],
                "skip": f"{fmt} needs an external extractor (see docs/METHOD.md)",
            }
        else:
            return {"format": fmt, "written": [], "skip": "not an archive"}
    except ExtractError as exc:
        return {"format": fmt, "written": [], "error": str(exc)}
    except Exception as exc:
        return {"format": fmt, "written": [], "error": f"{fmt}: {exc}"}

    nested = []
    for w in list(written):
        child = formats.detect(w)
        if child["type"] in ("tar", "zip", "gzip", "xz"):
            nested_dir = w + ".extracted"
            res = extract(w, nested_dir, budget, depth + 1)
            nested.append({"container": w, "format": child["type"], "result": res})

    return {
        "format": fmt,
        "dest": dest,
        "written": written,
        "count": len(written),
        "nested": nested,
        "budget": {"files": budget.files, "bytes": budget.bytes},
    }


def tree_roots(result: dict) -> list[str]:
    """Deepest extraction directories of a recursive extract() result."""
    roots: list[str] = []

    def walk(node: dict) -> None:
        children = [n.get("result", {}) for n in (node.get("nested") or [])]
        if not children:
            if node.get("dest") and os.path.isdir(node["dest"]):
                roots.append(node["dest"])
            return
        for child in children:
            walk(child)

    walk(result)
    return roots


def effective_root(root: str) -> str:
    """Descend through a single wrapper directory (fw-v1/fw-v1/...)."""
    current = root
    for _ in range(3):
        try:
            entries = os.listdir(current)
        except OSError:
            return current
        dirs = [e for e in entries if os.path.isdir(os.path.join(current, e))]
        files = [e for e in entries if os.path.isfile(os.path.join(current, e))]
        if len(dirs) == 1 and (not files or dirs[0].endswith(".extracted")):
            current = os.path.join(current, dirs[0])
        else:
            return current
    return current


def _count_files(root: str) -> int:
    total = 0
    for _, _, files in os.walk(root):
        total += len(files)
    return total


def primary_root(result: dict) -> str | None:
    """The extraction root that actually holds the firmware tree.

    Recursive extraction produces several directories (each container's dest).
    The primary root is the effective root holding the most files.
    """
    dests: list[str] = []

    def walk(node: dict) -> None:
        if node.get("dest"):
            dests.append(node["dest"])
        for child in node.get("nested") or []:
            walk(child.get("result", {}))

    walk(result)
    candidates = []
    for dest in dests:
        if not os.path.isdir(dest):
            continue
        eff = effective_root(dest)
        candidates.append((_count_files(eff), -len(eff), eff))
    if not candidates:
        return None
    candidates.sort(reverse=True)
    return candidates[0][2]
