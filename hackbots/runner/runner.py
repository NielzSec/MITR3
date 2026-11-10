"""MITR3 offline pilot: one deterministic worker inside an isolated sandbox.

Does not execute fixture JavaScript or use an LLM. Gate values are conservative.
No API key or user-supplied command reaches the worker.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time

from . import sandbox, trace_store, failure_store, outcome_store
from .broker import BrokerSession, BrokerError, write_frame
from .policies import Policy
from .protocol import FrameReader, ProtocolViolation, encode_frame
from .snapshot import load_snapshot, SnapshotError

ROOT = Path(__file__).resolve().parents[2]
WORKER = Path(__file__).parent / "workers" / "deterministic_js.py"
VERIFIER = ROOT / "hackbots" / "skill-builder" / "execution_verifier.py"


class RunnerError(RuntimeError):
    pass


def trusted_worker_source():
    """Pin bytes through one validated descriptor, not lstat(path) then reopen(path)."""
    fd = parent_fd = None
    try:
        parent_fd = os.open(WORKER.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        parent_info = os.fstat(parent_fd)
        if parent_info.st_uid != os.getuid() or parent_info.st_mode & 0o022:
            raise RunnerError("unsafe worker directory")
        fd = os.open(WORKER.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                     dir_fd=parent_fd)
        os.close(parent_fd)
        parent_fd = None
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_uid != os.getuid() or before.st_mode & 0o022
                or not 0 < before.st_size <= 100_000):
            raise RunnerError("unsafe worker code")
        with os.fdopen(fd, "rb", closefd=False) as src:
            data = src.read(100_001)
        after = os.fstat(fd)
        if (len(data) > 100_000 or before.st_size != len(data)
                or before.st_size != after.st_size
                or before.st_mtime_ns != after.st_mtime_ns
                or before.st_ino != after.st_ino
                or before.st_dev != after.st_dev):
            raise RunnerError("worker changed during load")
        return data.decode("utf-8")
    except (OSError, UnicodeError):
        raise RunnerError("worker unavailable or unsafe") from None
    finally:
        if fd is not None:
            os.close(fd)
        if parent_fd is not None:
            os.close(parent_fd)


def verifier_check(run_id, expected_sha256):
    if type(run_id) is not str or len(run_id) != 32 or any(c not in "0123456789abcdef" for c in run_id):
        raise RunnerError("invalid private run identifier")
    prefix = "hackbots/private/runs/" + run_id
    command = [sys.executable, str(VERIFIER), "verify",
               prefix + "/snapshot.bin", prefix + "/trace.json",
               "--artifact-sha256", expected_sha256]
    try:
        done = subprocess.run(
            command, cwd=ROOT, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env={"PATH": "/usr/bin", "PYTHONDONTWRITEBYTECODE": "1", "LANG": "C.UTF-8"},
            timeout=5, check=False)
        if len(done.stdout) > 3_000_000 or len(done.stderr) > 1_000_000:
            raise RunnerError("verifier output exceeded limits")
        if done.returncode not in (0, 1):
            raise RunnerError("verifier blocked the run")
        report = json.loads(done.stdout.decode("utf-8"))
        if (type(report) is not dict or report.get("artifact_sha256") != expected_sha256
                or report.get("trace_gate") != "PASS"
                or report.get("coverage_gate") not in ("PASS", "NOT_APPLICABLE")
                or report.get("behavioral_gate") != "NOT_RUN"):
            raise RunnerError("verifier disagrees with expected contract")
        return report
    except (OSError, subprocess.TimeoutExpired, ValueError, UnicodeError) as exc:
        raise RunnerError("verifier could not validate run") from None


def expected_observation(snapshot):
    data = snapshot.data
    lines = data.count(b"\n") + (1 if data and not data.endswith(b"\n") else 0)
    return {"artifact_sha256": snapshot.sha256,
            "artifact_bytes": snapshot.size, "physical_lines": lines}


def matches_observation(observed, expected):
    """Strict equality: Python bool must never satisfy an integer oracle."""
    return (type(observed) is dict and set(observed) == set(expected)
            and all(type(observed[key]) is type(expected[key])
                    and observed[key] == expected[key] for key in expected))


def trace_fits_verifier_input_budget(session):
    """Verifier reads at most 1,000,000 bytes of JSON (including the frame)."""
    raw = json.dumps(session.trace(), separators=(",", ":")).encode("utf-8")
    return len(raw) <= 1_000_000


def run_offline(relative, reviewer_sha256, policy=None):
    """Performs one authorized *synthetic* fixture run; blocks on any missing control."""
    if os.geteuid() == 0:
        raise RunnerError("unprivileged user required")
    policy = policy if policy is not None else Policy()
    if type(policy) is not Policy:
        raise RunnerError("invalid policy")
    snapshot = load_snapshot(relative, reviewer_sha256, policy)
    source = trusted_worker_source()
    worker_sha256 = hashlib.sha256(source.encode("utf-8")).hexdigest()

    # Match the existing verifier LF-unit contract before launching a worker.
    # Even a valid 1 MB fixture may contain over 10,000 physical lines.
    if expected_observation(snapshot)["physical_lines"] > 10_000:
        raise RunnerError("fixture exceeds verifier line budget")

    # Never rely on an old/stale selftest or merely declared limits.
    if not sandbox.ready(sandbox.doctor(policy)):
        raise RunnerError("sandbox doctor blocked")
    if not sandbox.ready(sandbox.selftest(policy)):
        raise RunnerError("sandbox selftest blocked")

    session = BrokerSession(snapshot, policy)
    phase = "IPC_INIT"
    try:
        with sandbox._staged(source) as worker_path:
            with sandbox.launch(sandbox.SandboxSpec(worker_path, policy)) as proc:
                init = {"v": 1, "type": "init", "bytes": snapshot.size,
                        "sha256": snapshot.sha256}
                write_frame(proc.stdin_fd, encode_frame(init, 65_536),
                            min(session.run_deadline, time.monotonic() + policy.request_timeout_s))
                reader = FrameReader(proc.stdout_fd)
                phase = "IPC_READ"
                while not session.finished:
                    request = reader.read(min(session.run_deadline,
                                              time.monotonic() + policy.request_timeout_s))
                    if request is None:
                        raise RunnerError("worker closed before final result")
                    session.handle(request, proc.stdin_fd)
                phase = "WORKER_EXIT"
                remaining = session.run_deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("E_TIMEOUT")
                rc = proc.wait(min(remaining, 2.0))
                if rc is None:
                    raise TimeoutError("E_TIMEOUT")
                if rc != 0:
                    raise RunnerError("worker did not exit cleanly")
                if reader.read(time.monotonic() + 0.2) is not None:
                    raise RunnerError("worker sent unmediated trailing output")
                phase = "CLEANUP"
                if not proc.kill_tree():
                    raise RunnerError("sandbox process cleanup not verified")
    except (RunnerError, BrokerError, sandbox.SandboxError, ProtocolViolation,
            OSError, TimeoutError, ValueError, UnicodeError) as exc:
        # Persist a separate, explicitly incomplete evidence record; never
        # represent a failed execution as verified coverage or a completed run.
        if isinstance(exc, TimeoutError):
            reason = "E_TIMEOUT"
        elif isinstance(exc, ProtocolViolation):
            reason = "E_PROTOCOL"
        elif isinstance(exc, sandbox.SandboxError):
            reason = "E_SANDBOX"
        elif isinstance(exc, BrokerError):
            reason = "E_BROKER"
        elif isinstance(exc, OSError):
            reason = "E_IO"
        else:
            reason = "E_RUNNER"
        try:
            failure_store.persist_failure(session, phase=phase, reason=reason)
        except (BrokerError, OSError):
            pass  # Do not conceal the original failure; the CLI stays BLOCKED.
        raise
    if session.failed or not session.finished or session.result_bytes is None:
        raise RunnerError("incomplete broker session")
    # The verifier reader has a 1 MB JSON cap. Refuse oversized traces BEFORE
    # storing a successful-session record, even if broker budgets allow them.
    if not trace_fits_verifier_input_budget(session):
        try:
            failure_store.persist_failure(session, phase="VERIFICATION", reason="E_VERIFY")
        except (BrokerError, OSError):
            pass
        raise RunnerError("trace exceeds verifier input budget")

    # A SESSION_RECORDED manifest means only the broker session was persisted.
    # The verifier/oracle must create an independent, append-only outcome.json.
    run_id = trace_store.persist(session, staged_worker_sha256=worker_sha256)
    try:
        report = verifier_check(run_id, snapshot.sha256)
    except (RunnerError, OSError, TimeoutError, ValueError):
        outcome_store.persist_outcome(
            run_id, status="BLOCKED", trace_gate="NOT_VERIFIED",
            coverage_gate="NOT_RUN", deterministic_oracle="NOT_RUN",
            reason_code="E_VERIFY")
        raise
    try:
        observed = json.loads(session.result_bytes.decode("utf-8"))
    except (ValueError, UnicodeError):
        outcome_store.persist_outcome(
            run_id, status="BLOCKED", trace_gate="NOT_VERIFIED",
            coverage_gate="NOT_RUN", deterministic_oracle="NOT_RUN",
            reason_code="E_RESULT")
        raise RunnerError("result payload cannot be decoded") from None
    expected = expected_observation(snapshot)
    equal = matches_observation(observed, expected)
    outcome_store.persist_outcome(
        run_id, status="VERIFIED" if equal else "FAILED",
        trace_gate=report["trace_gate"], coverage_gate=report["coverage_gate"],
        deterministic_oracle="PASS" if equal else "FAIL")
    return {
        "state": "REVIEW" if equal else "FAILED",
        "run_id": run_id,
        "worker_sha256": worker_sha256,
        "sandbox_gate": "SELFTEST_OK",
        "trace_gate": report["trace_gate"],
        "coverage_gate": report["coverage_gate"],
        "units_expected": report["units_expected"],
        "units_covered": report["units_covered"],
        "deterministic_oracle": "PASS" if equal else "FAIL",
        "output_gate": "NOT_RUN",
        "trace_authenticity": "NOT_VERIFIED",
        "behavioral_gate": "NOT_RUN",
        "independent_review": "NOT_RUN",
        "human_approved": False,
        "promotable": False,
    }


class SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, "BLOCKED: invalid runner arguments; use --help\n")


def main(argv=None):
    parser = SafeArgumentParser(description="MITR3 synthetic offline runner (no LLM)")
    parser.add_argument("command", choices=("doctor", "selftest", "run"))
    parser.add_argument("--fixture")
    parser.add_argument("--artifact-sha256")
    args = parser.parse_args(argv)
    try:
        if args.command in ("doctor", "selftest"):
            if args.fixture is not None or args.artifact_sha256 is not None:
                raise RunnerError("unexpected diagnostic arguments")
            checks = sandbox.doctor() if args.command == "doctor" else sandbox.selftest()
            result = {"state": "REVIEW" if sandbox.ready(checks) else "BLOCKED",
                      "ready": sandbox.ready(checks),
                      "checks": [vars(check) for check in checks],
                      "behavioral_gate": "NOT_RUN", "promotable": False}
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 0 if sandbox.ready(checks) else 2
        if args.fixture is None or args.artifact_sha256 is None:
            raise RunnerError("fixture and external SHA256 required")
        result = run_offline(args.fixture, args.artifact_sha256)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result["state"] == "REVIEW" else 1
    except (RunnerError, SnapshotError, sandbox.SandboxError, BrokerError,
            ProtocolViolation, OSError, TimeoutError, ValueError, UnicodeError):
        print(json.dumps({
            "state": "BLOCKED", "sandbox_gate": "NOT_VERIFIED",
            "trace_authenticity": "NOT_VERIFIED", "behavioral_gate": "NOT_RUN",
            "output_gate": "NOT_RUN", "human_approved": False, "promotable": False,
            "error": "offline runner failed safely"
        }), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
