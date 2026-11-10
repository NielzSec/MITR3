"""Append-only local outcome after verifying a persisted broker session.

An outcome is *not* independent attestation, a skill output gate, or human approval.
A missing outcome always means no verified result was recorded. Historic session
manifests stay unchanged. Only a future separate-UID custodian closes F01.
"""
import hashlib
import json
import os
import re
import stat

from . import trace_store
from .broker import BrokerError

_ID = re.compile(r"[0-9a-f]{32}\Z")
_ALLOWED = {
    "VERIFIED": ("PASS", ("PASS", "NOT_APPLICABLE"), "PASS", None),
    "FAILED": ("PASS", ("PASS", "NOT_APPLICABLE"), "FAIL", None),
    "BLOCKED": ("NOT_VERIFIED", ("NOT_RUN",), "NOT_RUN", ("E_VERIFY", "E_RESULT")),
}


def _read_manifest(run_fd):
    fd = None
    try:
        fd = os.open("manifest.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                     dir_fd=run_fd)
        st = os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid()
                or st.st_nlink != 1 or stat.S_IMODE(st.st_mode) != 0o600
                or st.st_size > 131072):
            raise BrokerError("unsafe session manifest")
        with os.fdopen(fd, "rb", closefd=False) as fh:
            raw = fh.read(131073)
        if len(raw) > 131072:
            raise BrokerError("oversize session manifest")
        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise BrokerError("duplicate manifest key")
                result[key] = value
            return result
        manifest = json.loads(raw, object_pairs_hook=unique)
        if not isinstance(manifest, dict):
            raise BrokerError("invalid session manifest")
        return raw, manifest
    except (OSError, ValueError, UnicodeError):
        raise BrokerError("session manifest unavailable") from None
    finally:
        if fd is not None:
            os.close(fd)


def persist_outcome(run_id, *, status, trace_gate, coverage_gate,
                    deterministic_oracle, reason_code=None):
    """Exclusive outcome marker, never overwriting the original session manifest."""
    if type(run_id) is not str or _ID.fullmatch(run_id) is None:
        raise BrokerError("invalid run id")
    if type(status) is not str or status not in _ALLOWED:
        raise BrokerError("invalid outcome")
    expected_trace, coverages, expected_oracle, reasons = _ALLOWED[status]
    if (trace_gate != expected_trace or coverage_gate not in coverages
            or deterministic_oracle != expected_oracle
            or ((reason_code is not None) if reasons is None else
                reason_code not in reasons)):
        raise BrokerError("inconsistent outcome gates")
    root = private_fd = runs_fd = run_fd = None
    try:
        root = os.open(trace_store.PROJECT / "hackbots",
                       os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        private_fd = trace_store._checked_private_dir(root, "private")
        runs_fd = trace_store._checked_private_dir(private_fd, "runs")
        run_fd = trace_store._checked_private_dir(runs_fd, run_id)
        manifest_bytes, manifest = _read_manifest(run_fd)
        if (type(manifest.get("version")) is not int or manifest["version"] != 1
                or manifest.get("run_id") != run_id
                or manifest.get("state") not in ("REVIEW", "SESSION_RECORDED")
                or manifest.get("result_submitted") is not True
                or manifest.get("behavioral_gate") != "NOT_RUN"
                or manifest.get("promotable") is not False):
            raise BrokerError("unverified or invalid session")
        record = {
            "version": 1, "run_id": run_id,
            "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
            "status": status,
            "reason_code": reason_code,
            "trace_gate": trace_gate,
            "coverage_gate": coverage_gate,
            "deterministic_oracle": deterministic_oracle,
            "output_gate": "NOT_RUN",
            "behavioral_gate": "NOT_RUN",
            "trace_authenticity": "NOT_VERIFIED",
            "human_approved": False, "promotable": False,
        }
        data = json.dumps(record, separators=(",", ":")).encode("utf-8")
        trace_store._exclusive_file(run_fd, "outcome.json", data)
        os.fsync(run_fd)
        os.fsync(runs_fd)
        return status
    except OSError:
        raise BrokerError("outcome persistence unavailable") from None
    finally:
        for fd in (run_fd, runs_fd, private_fd, root):
            if fd is not None:
                os.close(fd)
