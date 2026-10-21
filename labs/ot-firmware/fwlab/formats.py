"""Container/format detection by magic bytes.

Returns a dict so callers can log the evidence (offset, magic, confidence)
instead of a bare string. Unknown containers are reported, never guessed.
"""
from __future__ import annotations

import math
import os
import tarfile
from collections import Counter

# (name, magic, offset, family, note)
SIGNATURES = [
    (b"PK\x03\x04", 0, "zip", "zip local file header"),
    (b"PK\x05\x06", 0, "zip", "empty zip"),
    (b"\x37\x7a\xbc\xaf\x27\x1c", 0, "7z", "7-zip"),
    (b"Rar!\x1a\x07", 0, "rar", "rar archive"),
    (b"\xfd7zXZ\x00", 0, "xz", "xz stream"),
    (b"BZh", 0, "bzip2", "bzip2 stream"),
    (b"\x1f\x8b\x08", 0, "gzip", "gzip stream"),
    (b"hsqs", 0, "squashfs", "squashfs, little endian"),
    (b"sqsh", 0, "squashfs", "squashfs, big endian"),
    (b"UBI#", 0, "ubi", "UBI eraseblock"),
    (b"\x31\x18\x10\x06", 0, "ubifs", "UBIFS superblock"),
    (b"\x7fELF", 0, "elf", "ELF object"),
    (b"MZ", 0, "pe", "DOS/PE image"),
    (b"\x27\x05\x19\x56", 0, "uimage", "u-boot legacy image"),
    (b"\xd0\x0d\xfe\xed", 0, "fdt", "flattened device tree"),
    (b"\x28\xcd\x3d\x45", 0, "cramfs", "cramfs, little endian"),
    (b"\x45\x3d\xcd\x28", 0, "cramfs", "cramfs, big endian"),
    (b"\x85\x19\x03\x20", 0, "jffs2", "JFFS2"),
    (b"ANDROID!", 0, "android_boot", "Android boot image"),
    (b"\x00\x00\x00\x00\x00\x00\x00\x00", 0, "zeroes", "all-zero header"),
]

TAR_MAGIC = b"ustar"


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _looks_like_tar(head: bytes) -> bool:
    return len(head) >= 262 and head[257:262] == TAR_MAGIC


def _looks_like_spk(head: bytes) -> bool:
    # Danfoss AK-SM packages ship as .spk; observed samples start with a
    # textual header block. Treat as heuristic, never as proof.
    lowered = head[:64].lower()
    return lowered.startswith(b"spk") or b"danfoss" in lowered or b"ak-sm" in lowered


def detect(path: str) -> dict:
    """Detect the container type of *path* from its leading bytes."""
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as fh:
            head = fh.read(4096)
    except (PermissionError, OSError):
        return {
            "path": path,
            "size": 0,
            "type": "unreadable",
            "note": "file cannot be opened for reading",
            "confidence": "none",
            "entropy": 0.0,
        }

    if _looks_like_tar(head):
        return {
            "path": path,
            "size": size,
            "type": "tar",
            "note": "ustar magic at offset 257",
            "confidence": "magic",
            "entropy": round(_entropy(head[:512]), 3),
        }

    if (path.endswith(".tar") or path.endswith(".tar.gz")) and tarfile.is_tarfile(path):
        return {
            "path": path,
            "size": size,
            "type": "tar",
            "note": "empty or valid tar archive",
            "confidence": "heuristic",
            "entropy": round(_entropy(head[:512]), 3),
        }

    for magic, offset, name, note in SIGNATURES:
        if head[offset:offset + len(magic)] == magic:
            return {
                "path": path,
                "size": size,
                "type": name,
                "note": note,
                "confidence": "magic",
                "entropy": round(_entropy(head[:512]), 3),
            }

    if _looks_like_spk(head):
        return {
            "path": path,
            "size": size,
            "type": "spk",
            "note": "Danfoss-style header heuristic; container layout unknown",
            "confidence": "heuristic",
            "entropy": round(_entropy(head[:512]), 3),
        }

    printable = sum(1 for b in head[:256] if 32 <= b < 127) / max(1, min(len(head), 256))
    return {
        "path": path,
        "size": size,
        "type": "unknown",
        "note": "no known signature; first bytes: " + head[:16].hex(),
        "confidence": "none",
        "entropy": round(_entropy(head[:512]), 3),
        "printable_ratio": round(printable, 3),
    }
