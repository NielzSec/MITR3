"""Immutable, externally pinned offline fixture bytes. No paths sent to the worker."""
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import stat

from .policies import Policy

ROOT = Path(__file__).resolve().parents[2]
SHA256 = re.compile(r"[a-f0-9]{64}\Z")
# v0.1 only accepts known synthetic fixture subtrees.
FIXTURE_PREFIXES = (
    ("hackbots", "examples"),
    ("hackbots", "skill-builder", "examples", "evaluator"),
    ("hackbots", "runner", "tests", "fixtures"),
)


class SnapshotError(ValueError):
    pass


@dataclass(frozen=True)
class Snapshot:
    data: bytes
    sha256: str

    def __post_init__(self):
        if (type(self.data) is not bytes or len(self.data) > 1_000_000
                or type(self.sha256) is not str or not SHA256.fullmatch(self.sha256)
                or hashlib.sha256(self.data).hexdigest() != self.sha256):
            raise SnapshotError("invalid or unpinned snapshot")

    @property
    def size(self):
        return len(self.data)

    def read(self, start, end):
        if type(start) is not int or type(end) is not int or not 0 <= start < end <= self.size:
            raise SnapshotError("invalid snapshot range")
        return self.data[start:end]


def load_snapshot(relative, expected_sha256, policy=None):
    policy = policy if policy is not None else Policy()
    if (type(relative) is not str or not relative or "\x00" in relative
            or type(expected_sha256) is not str or not SHA256.fullmatch(expected_sha256)):
        raise SnapshotError("invalid fixture reference")
    p = Path(relative)
    if (p.is_absolute() or any(part in (".", "..") for part in p.parts)
            or not any(p.parts[:len(prefix)] == prefix for prefix in FIXTURE_PREFIXES)):
        raise SnapshotError("fixture outside synthetic allowlist")
    parent = None
    fd = None
    try:
        parent = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        for part in p.parts[:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent)
            parent = next_fd
        fd = os.open(p.parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        with os.fdopen(fd, "rb") as source:
            fd = None
            st = os.fstat(source.fileno())
            if (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1
                    or st.st_size > policy.max_fixture_bytes):
                raise SnapshotError("invalid fixture type, link count or size")
            raw = source.read(policy.max_fixture_bytes + 1)
            if len(raw) > policy.max_fixture_bytes:
                raise SnapshotError("fixture grew past size limit")
    except OSError as exc:
        raise SnapshotError("fixture unavailable or unsafe") from None
    finally:
        if fd is not None:
            os.close(fd)
        if parent is not None:
            os.close(parent)
    got = hashlib.sha256(raw).hexdigest()
    if got != expected_sha256:
        raise SnapshotError("fixture differs from reviewer SHA256")
    return Snapshot(data=raw, sha256=got)
