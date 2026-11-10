"""Trusted offline broker state machine. No worker creation, sandbox, or network.

A trace event is committed only when the entire response frame was written to a
nonblocking, exclusively owned pipe. This is *delivery to the channel*, not
proof of reads by a worker. Until sandbox/custody tests, behavioral_gate=NOT_RUN.
"""
import base64
from dataclasses import dataclass
import hashlib
import json
import math
import os
import select
import time

from .policies import Policy
from .protocol import (ProtocolViolation, RequestRejected, RequestParser,
                       ReadInterval, SubmitResult, RESPONSE_FRAME_BYTES,
                       encode_frame, _serialize)
from .snapshot import Snapshot


class BrokerError(ValueError):
    pass


@dataclass(frozen=True)
class Pending:
    operation: str
    request_id: str
    framed: bytes
    start: int = 0
    end: int = 0
    digest: str = ""
    result_bytes: bytes = b""


def write_frame(fd, frame, deadline):
    """Send a whole framed response to an owned O_NONBLOCK pipe; fail closed."""
    import fcntl
    if type(fd) is not int or type(deadline) not in (int, float) or not math.isfinite(deadline):
        raise ProtocolViolation()
    try:
        if not fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_NONBLOCK:
            raise BrokerError("response pipe must be nonblocking")
        poller = select.poll()
        poller.register(fd, select.POLLOUT | select.POLLERR | select.POLLHUP)
        sent = 0
        while sent < len(frame):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("E_TIMEOUT")
            states = poller.poll(max(1, math.ceil(remaining * 1000)))
            if not states:
                raise TimeoutError("E_TIMEOUT")
            if states[0][1] & (select.POLLERR | select.POLLHUP | select.POLLNVAL):
                raise BrokerError("response pipe closed")
            try:
                n = os.write(fd, frame[sent:])
            except BlockingIOError:
                continue
            if n <= 0:
                raise BrokerError("response pipe write failed")
            sent += n
    except TimeoutError:
        raise
    except (OSError, ValueError, OverflowError):
        raise BrokerError("response delivery failed") from None


class BrokerSession:
    """Single-threaded/single-writer state machine; NOT callable by untrusted workers.

    Only the future parent runner may own this object. All responses must pass
    through send() so that delivered events cannot be asserted by a worker.
    """
    def __init__(self, snapshot, policy=None):
        if not isinstance(snapshot, Snapshot):
            raise BrokerError("a pinned snapshot is required")
        self.policy = policy if policy is not None else Policy()
        if type(self.policy) is not Policy:
            raise BrokerError("validated Policy required")
        if snapshot.size > self.policy.max_fixture_bytes:
            raise BrokerError("snapshot exceeds policy")
        self.snapshot = snapshot
        self.parser = RequestParser(self.policy)
        self.run_deadline = time.monotonic() + self.policy.timeout_s
        self.pending = None
        self.failed = False
        self.finished = False
        self.rejections = 0
        self.total_read_bytes = 0
        self.delivered = []
        self.journal = []  # metadata only, never fixture bytes or result contents
        self.result_bytes = None

    def _assert_active(self):
        if self.failed or self.finished or self.pending is not None:
            raise BrokerError("broker session inactive")
        if time.monotonic() >= self.run_deadline:
            self.failed = True
            raise TimeoutError("E_TIMEOUT")

    def prepare(self, message):
        """Validate an untrusted request and reserve one pending reply."""
        self._assert_active()
        try:
            op = self.parser.parse(message)
            rid = op.request_id
            self.journal.append({"request_id": rid, "state": "requested"})
            if isinstance(op, ReadInterval):
                if op.end > self.snapshot.size:
                    raise RequestRejected("E_RANGE")
                n = op.end - op.start
                if (len(self.delivered) >= self.policy.max_events
                        or self.total_read_bytes + n > self.policy.max_total_bytes):
                    raise RequestRejected("E_READ_BUDGET")
                raw = self.snapshot.read(op.start, op.end)
                digest = hashlib.sha256(raw).hexdigest()
                data = {"start": op.start, "end": op.end, "encoding": "base64",
                        "bytes": base64.b64encode(raw).decode("ascii")}
                reply = {"v": 1, "type": "response", "request_id": rid, "ok": True, "data": data}
                pending = Pending("read_interval", rid, encode_frame(reply, RESPONSE_FRAME_BYTES),
                                  op.start, op.end, digest)
            elif isinstance(op, SubmitResult):
                raw_result = _serialize(op.result)
                reply = {"v": 1, "type": "response", "request_id": rid, "ok": True, "data": {}}
                pending = Pending("submit_result", rid, encode_frame(reply, RESPONSE_FRAME_BYTES),
                                  result_bytes=raw_result)
            else:
                raise ProtocolViolation()
            self.journal.append({"request_id": rid, "state": "mediated"})
        except RequestRejected as err:
            self.rejections += 1
            if self.rejections > self.policy.max_rejected:
                self.failed = True
                raise ProtocolViolation("E_REJECTION_LIMIT") from None
            rid = message["request_id"]  # RequestParser checked format and consumed it.
            self.journal.append({"request_id": rid, "state": "rejected", "reason": err.code})
            reply = {"v": 1, "type": "response", "request_id": rid, "ok": False, "error": err.code}
            pending = Pending("rejected", rid, encode_frame(reply, RESPONSE_FRAME_BYTES))
        except (ProtocolViolation, BrokerError):
            self.failed = True
            raise
        self.pending = pending
        return pending

    def send(self, pending, response_fd):
        """Commit read event only after full response was sent into the channel."""
        if self.failed or self.finished or pending is None or pending is not self.pending:
            self.failed = True
            raise BrokerError("pending response mismatch")
        try:
            deadline = min(self.run_deadline, time.monotonic() + self.policy.request_timeout_s)
            write_frame(response_fd, pending.framed, deadline)
        except (BrokerError, ProtocolViolation, TimeoutError, OSError):
            self.failed = True
            self.journal.append({"request_id": pending.request_id, "state": "delivery_failed"})
            raise
        finally:
            self.pending = None
        if pending.operation == "read_interval":
            self.total_read_bytes += pending.end - pending.start
            self.delivered.append({"seq": len(self.delivered) + 1, "start": pending.start,
                                   "end": pending.end, "sha256": pending.digest})
            self.journal.append({"request_id": pending.request_id, "state": "delivered"})
        elif pending.operation == "submit_result":
            self.result_bytes = pending.result_bytes
            self.finished = True
            self.journal.append({"request_id": pending.request_id, "state": "result_received"})
        return True

    def handle(self, message, response_fd):
        self.send(self.prepare(message), response_fd)

    def trace(self):
        """Matches existing execution_verifier trace schema, but is NOT authenticated."""
        return {"schema_version": 1, "artifact_sha256": self.snapshot.sha256,
                "event_count": len(self.delivered), "events": [dict(e) for e in self.delivered]}

    def status(self):
        return {
            "state": "BLOCKED" if self.failed else "REVIEW" if self.finished else "INCOMPLETE",
            "read_events": len(self.delivered),
            "bytes_delivered_to_channel": self.total_read_bytes,
            "rejections": self.rejections,
            "result_submitted": self.result_bytes is not None,
            "trace_authenticity": "NOT_VERIFIED",
            "behavioral_gate": "NOT_RUN",
            "output_gate": "NOT_RUN",
            "human_approved": False, "promotable": False,
        }
