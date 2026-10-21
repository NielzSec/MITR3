"""Inventory of an extracted firmware tree.

Produces evidence-ready facts: hashes, ELF/PE headers, interpreters, setuid
files, init scripts, web roots and strings that matter for auth review.
"""
from __future__ import annotations

import hashlib
import os
import stat
import struct

ELF_MACHINES = {
    3: "x86",
    8: "mips",
    20: "ppc",
    21: "ppc64",
    40: "arm",
    62: "x86_64",
    183: "aarch64",
    243: "riscv",
}

INTERESTING_STRINGS = (
    b"strcmp", b"strncmp", b"system", b"popen", b"execve", b"Authorization",
    b"X-", b"admin", b"password", b"token", b"session", b"setuid", b"/bin/sh",
    b"openssl", b"curl", b"wget", b"/etc/passwd", b"/etc/shadow", b"sqlite",
    b"upgrade", b"firmware", b"debug",
)

INTERESTING_NAMES = (
    "rcS", "init.d", "lighttpd", "nginx", "httpd", "busybox", "passwd", "shadow",
    "cgi-bin", "web", "www", "htdocs", "dropbear", "ssh", "telnet", "startup",
    "upgrade", "update", "spk", "cert", "key",
)


def sha256_file(path: str, chunk: int = 1024 * 256) -> str | None:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            while True:
                data = fh.read(chunk)
                if not data:
                    break
                h.update(data)
        return h.hexdigest()
    except (PermissionError, OSError):
        return None


def elf_header(path: str) -> dict | None:
    try:
        with open(path, "rb") as fh:
            ident = fh.read(20)
            if len(ident) < 20 or ident[:4] != b"\x7fELF":
                return None
            ei_class = ident[4]
            ei_data = ident[5]
            e_type = struct.unpack("<H", ident[16:18])[0]
            machine = struct.unpack("<H", ident[18:20])[0]
            if ei_data == 2:
                e_type = struct.unpack(">H", ident[16:18])[0]
                machine = struct.unpack(">H", ident[18:20])[0]
            return {
                "class": {1: "32", 2: "64"}.get(ei_class, "?"),
                "endian": {1: "little", 2: "big"}.get(ei_data, "?"),
                "type": {1: "rel", 2: "exec", 3: "dyn", 4: "core"}.get(e_type, str(e_type)),
                "machine": ELF_MACHINES.get(machine, f"machine_{machine}"),
                "stripped": _elf_stripped(path),
            }
    except (OSError, struct.error):
        return None


def _elf_stripped(path: str) -> bool:
    """True when the ELF carries no .symtab (linker already stripped it)."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(64)
            if len(head) < 52 or head[:4] != b"\x7fELF":
                return True
            is64 = head[4] == 2
            big = head[5] == 2
            end = ">" if big else "<"
            if is64:
                e_shoff = struct.unpack_from(end + "Q", head, 0x28)[0]
                e_shentsize = struct.unpack_from(end + "H", head, 0x3A)[0]
                e_shnum = struct.unpack_from(end + "H", head, 0x3C)[0]
                e_shstrndx = struct.unpack_from(end + "H", head, 0x3E)[0]
            else:
                e_shoff = struct.unpack_from(end + "I", head, 0x20)[0]
                e_shentsize = struct.unpack_from(end + "H", head, 0x2E)[0]
                e_shnum = struct.unpack_from(end + "H", head, 0x30)[0]
                e_shstrndx = struct.unpack_from(end + "H", head, 0x32)[0]
            if e_shoff == 0 or e_shnum == 0 or e_shstrndx >= e_shnum:
                return True
            fh.seek(e_shoff + e_shstrndx * e_shentsize)
            strtab_hdr = fh.read(e_shentsize)
            if len(strtab_hdr) < e_shentsize:
                return True
            if is64:
                sh_offset = struct.unpack_from(end + "Q", strtab_hdr, 0x18)[0]
                sh_size = struct.unpack_from(end + "Q", strtab_hdr, 0x20)[0]
            else:
                sh_offset = struct.unpack_from(end + "I", strtab_hdr, 0x10)[0]
                sh_size = struct.unpack_from(end + "I", strtab_hdr, 0x14)[0]
            if sh_offset == 0 or sh_size == 0 or sh_size > 8 * 1024 * 1024:
                return True
            fh.seek(sh_offset)
            names = fh.read(sh_size)
            return b".symtab\x00" not in names
    except (OSError, struct.error):
        return True


def _scan_strings(path: str, limit: int = 512 * 1024) -> dict:
    found = set()
    try:
        with open(path, "rb") as fh:
            data = fh.read(limit)
    except OSError:
        return {"hits": [], "truncated": False}
    for needle in INTERESTING_STRINGS:
        if needle in data:
            found.add(needle.decode("utf-8", "replace"))
    return {"hits": sorted(found), "truncated": os.path.getsize(path) > limit}


def _is_script(path: str) -> bool:
    try:
        with open(path, "rb") as fh:
            return fh.read(2) == b"#!"
    except OSError:
        return False


def inventory(root: str, limits: dict | None = None) -> dict:
    limits = limits or {}
    max_files = limits.get("max_files", 50000)
    max_string_scan = limits.get("max_string_scan", 2048)

    entries = []
    by_ext: dict[str, int] = {}
    elf_count = 0
    scanned = 0

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root)
            try:
                st = os.lstat(full)
            except OSError:
                continue
            if stat.S_ISLNK(st.st_mode):
                entries.append({"path": rel, "type": "symlink", "target": os.readlink(full)})
                continue
            if not stat.S_ISREG(st.st_mode):
                continue
            if len(entries) >= max_files:
                break
            ext = os.path.splitext(name)[1].lower() or "(none)"
            by_ext[ext] = by_ext.get(ext, 0) + 1
            hval = sha256_file(full)
            rec = {
                "path": rel,
                "size": st.st_size,
                "mode": oct(st.st_mode & 0o777),
                "exec": bool(st.st_mode & 0o111),
                "setuid": bool(st.st_mode & stat.S_ISUID),
                "sha256": hval,
            }
            if hval is None:
                rec["unreadable"] = True
            eh = elf_header(full)
            if eh:
                elf_count += 1
                rec["elf"] = eh
            elif _is_script(full):
                rec["script"] = True
            if rec["exec"] and scanned < max_string_scan:
                rec["strings"] = _scan_strings(full)
                scanned += 1
            if any(k in rel.lower() for k in INTERESTING_NAMES):
                rec["interesting_name"] = True
            entries.append(rec)

    return {
        "root": os.path.abspath(root),
        "files": len(entries),
        "elf_count": elf_count,
        "by_ext": dict(sorted(by_ext.items(), key=lambda kv: -kv[1])[:20]),
        "entries": entries,
    }
