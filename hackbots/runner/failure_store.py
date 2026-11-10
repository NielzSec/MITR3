"""Store an incomplete run as a failure, not as verified execution evidence.

Only the trusted supervisor calls this. No data or error strings from the worker
become paths, filenames, states or diagnostics. No success-result artifact exists.
"""
from datetime import datetime, timezone
import hashlib
import json
import os
import secrets

from .broker import BrokerSession, BrokerError
from . import trace_store

PHASES = frozenset({"IPC_INIT", "IPC_READ", "WORKER_EXIT", "CLEANUP", "VERIFICATION"})
REASONS = frozenset({"E_TIMEOUT", "E_PROTOCOL", "E_RUNNER", "E_SANDBOX", "E_BROKER", "E_IO", "E_VERIFY"})


def persist_failure(session, *, phase, reason):
    """Best-effort failure custody. The manifest is last; absence means incomplete IO."""
    if (not isinstance(session, BrokerSession) or type(phase) is not str
            or type(reason) is not str or phase not in PHASES or reason not in REASONS):
        raise BrokerError("invalid failure evidence metadata")

    trace = json.dumps(session.trace(), separators=(",", ":")).encode("utf-8")
    journal = json.dumps(session.journal, separators=(",", ":")).encode("utf-8")
    snapshot = session.snapshot.data
    written = {"partial-trace.json": trace, "journal.json": journal, "snapshot.bin": snapshot}
    digests = {k: hashlib.sha256(data).hexdigest() for k, data in written.items()}

    root = private_fd = failures_fd = run_fd = None
    try:
        root = os.open(trace_store.PROJECT / "hackbots",
                       os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        private_fd = trace_store._checked_private_dir(root, "private")
        failures_fd = trace_store._checked_private_dir(private_fd, "failures")
        run_id = secrets.token_hex(16)
        os.mkdir(run_id, 0o700, dir_fd=failures_fd)
        run_fd = trace_store._checked_private_dir(failures_fd, run_id)

        manifest = {
            "version": 1, "run_id": run_id, "state": "TIMEOUT" if reason == "E_TIMEOUT" else "BLOCKED",
            "phase": phase, "reason_code": reason,
            "persisted_at": datetime.now(timezone.utc).isoformat(),
            "artifact_sha256": session.snapshot.sha256,
            "events_delivered_to_channel": len(session.delivered),
            "files_sha256": digests,
            "session_completed": bool(session.finished),
            "worker_exit_verified": False,
            "sandbox_cleanup": "NOT_VERIFIED",
            "trace_gate": "NOT_VERIFIED",
            "coverage_gate": "NOT_RUN",
            "trace_authenticity": "NOT_VERIFIED",
            "behavioral_gate": "NOT_RUN",
            "output_gate": "NOT_RUN",
            "independent_review": "NOT_RUN",
            "human_approved": False,
            "promotable": False,
            "limitations": "Incomplete attempt; no verified success, full coverage, or worker consumption claimed."
        }
        for name, data in written.items():
            trace_store._exclusive_file(run_fd, name, data)
        trace_store._exclusive_file(
            run_fd, "manifest.json",
            json.dumps(manifest, separators=(",", ":")).encode("utf-8"))
        os.fsync(run_fd)
        os.fsync(failures_fd)
        return run_id
    except OSError:
        raise BrokerError("could not persist private failure evidence") from None
    finally:
        for fd in (run_fd, failures_fd, private_fd, root):
            if fd is not None:
                os.close(fd)
