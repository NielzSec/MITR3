"""One bounded metadata query over framed stdin/stdout. No mission or command execution.

Deployment must supply the identity boundary: this module does not authenticate
the writer of a pipe and cannot protect against a caller sharing its UID.
"""
import argparse
import os
import sys
import time

from . import inspect
from .broker import write_frame, BrokerError
from .protocol import FrameReader, ProtocolViolation, encode_frame

REQUEST_BYTES = 4096
RESPONSE_BYTES = 8192
TIMEOUT_S = 3.0


def query(message):
    """Allow only read-only operations; never interpret caller input as a path or command."""
    if (type(message) is not dict or type(message.get("v")) is not int
            or message["v"] != 1 or message.get("kind") not in ("complete", "failed")):
        raise inspect.InspectionBlocked("invalid query")
    operation = message.get("operation")
    if operation == "inspect":
        if set(message) != {"v", "operation", "kind", "run_id"}:
            raise inspect.InspectionBlocked("invalid inspect fields")
        return inspect.inspect_one(message["kind"], message["run_id"])
    if operation == "summary":
        if (set(message) != {"v", "operation", "kind", "limit"}
                or type(message["limit"]) is not int or not 1 <= message["limit"] <= 25):
            raise inspect.InspectionBlocked("invalid summary fields")
        return inspect.summary(message["kind"], message["limit"])
    raise inspect.InspectionBlocked("operation forbidden")


def serve_once(input_fd, output_fd):
    deadline = time.monotonic() + TIMEOUT_S
    try:
        message = FrameReader(input_fd, REQUEST_BYTES).read(deadline)
        if message is None:
            raise ProtocolViolation()
        result = {"v": 1, "ok": True, "data": query(message)}
        status = 0
    except (inspect.InspectionBlocked, ProtocolViolation, OSError, ValueError, TypeError, TimeoutError):
        result = {"v": 1, "ok": False, "error": "QUERY_BLOCKED",
                  "trace_authenticity": "NOT_VERIFIED", "behavioral_gate": "NOT_RUN",
                  "human_approved": False, "promotable": False}
        status = 2
    try:
        os.set_blocking(output_fd, False)
        write_frame(output_fd, encode_frame(result, RESPONSE_BYTES), time.monotonic() + TIMEOUT_S)
    except (ProtocolViolation, BrokerError, OSError, ValueError, TimeoutError):
        return 2
    return status


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, "BLOCKED: query accepts no arguments\n")


def main(argv=None):
    SafeParser(description=__doc__, allow_abbrev=False).parse_args(argv)
    if os.geteuid() == 0:
        print("BLOCKED: run the query helper without root privileges", file=sys.stderr)
        return 2
    return serve_once(sys.stdin.fileno(), sys.stdout.fileno())


if __name__ == "__main__":
    raise SystemExit(main())
