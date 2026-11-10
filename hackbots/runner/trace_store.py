"""Explicit private, no-overwrite evidence store. No autonomous persistence."""
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat

from .broker import BrokerError, BrokerSession
from .protocol import _serialize

PROJECT = Path(__file__).resolve().parents[2]


def _checked_private_dir(parent_fd, name):
    try:
        try:
            os.mkdir(name, 0o700, dir_fd=parent_fd)
        except FileExistsError:
            pass
        child_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
    except OSError:
        raise BrokerError("private evidence directory unavailable or unsafe") from None
    st = os.fstat(child_fd)
    if st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) != 0o700:
        os.close(child_fd)
        raise BrokerError("private evidence directory has unsafe permissions")
    return child_fd


def _exclusive_file(parent, name, data):
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 0o600, dir_fd=parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=False) as file:
            file.write(data)
            file.flush()
            os.fsync(file.fileno())
    finally:
        os.close(fd)


def persist(session, *, staged_worker_sha256=None):
    """Parent-only call. Store only after broker session is complete and not failed.

    This does NOT prove isolated custody until the worker is actually sandboxed.
    """
    if not isinstance(session, BrokerSession) or session.failed or not session.finished:
        raise BrokerError("cannot persist incomplete or failed session as complete")
    if staged_worker_sha256 is not None and (
            type(staged_worker_sha256) is not str or len(staged_worker_sha256) != 64
            or any(c not in "0123456789abcdef" for c in staged_worker_sha256)):
        raise BrokerError("invalid staged worker digest")
    root = os.open(PROJECT / "hackbots", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    private_fd = runs_fd = run_fd = None
    try:
        private_fd = _checked_private_dir(root, "private")
        runs_fd = _checked_private_dir(private_fd, "runs")
        run_id = secrets.token_hex(16)
        os.mkdir(run_id, 0o700, dir_fd=runs_fd)
        run_fd = _checked_private_dir(runs_fd, run_id)
        trace = json.dumps(session.trace(), separators=(",", ":")).encode()
        journal = json.dumps(session.journal, separators=(",", ":")).encode()
        # The manifest is written last; missing manifest = incomplete persistence.
        # Pin the precise broker snapshot for independent verification; never reopen original.
        written = {"trace.json": trace, "result.json": session.result_bytes,
                   "journal.json": journal, "snapshot.bin": session.snapshot.data}
        digests = {name: hashlib.sha256(raw).hexdigest() for name, raw in written.items()}
        modules = ("broker.py", "snapshot.py", "trace_store.py", "protocol.py",
                   "policies.py", "sandbox.py", "runner.py", "outcome_store.py",
                   "workers/deterministic_js.py")
        code_digests = {name: hashlib.sha256((Path(__file__).parent / name).read_bytes()).hexdigest()
                        for name in modules}
        manifest = json.dumps({**session.status(), "version": 1, "state": "SESSION_RECORDED", "run_id": run_id,
                               "persisted_at": datetime.now(timezone.utc).isoformat(),
                               "artifact_sha256": session.snapshot.sha256,
                               "artifact_bytes": session.snapshot.size,
                               # Bytes supplied to staging, not a same-UID execution attestation.
                               "staged_worker_sha256": staged_worker_sha256,
                               # Configured limits only; NOT proof of runtime enforcement.
                               "policy_configured": asdict(session.policy),
                               "files_sha256": digests, "modules_sha256": code_digests},
                              separators=(",", ":")).encode()
        for filename, raw in written.items():
            _exclusive_file(run_fd, filename, raw)
        _exclusive_file(run_fd, "manifest.json", manifest)
        os.fsync(run_fd)
        os.fsync(runs_fd)
        return run_id  # no host path emitted to workers
    finally:
        if run_fd is not None:
            os.close(run_fd)
        if runs_fd is not None:
            os.close(runs_fd)
        if private_fd is not None:
            os.close(private_fd)
        os.close(root)
