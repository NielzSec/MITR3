#!/usr/bin/env python3
"""Standalone offline worker. Reads a synthetic fixture only via broker IPC.

Never opens an artifact, executes JavaScript, invokes a shell or makes network calls.
"""
import base64
import binascii
import hashlib
import json
import os
import struct

MAX_FRAME = 131072
CHUNK = 32768
MAX_BYTES = 1000000


def exact(n):
    output = bytearray()
    while len(output) < n:
        fragment = os.read(0, n - len(output))
        if not fragment:
            raise ValueError("broker disconnected")
        output.extend(fragment)
    return bytes(output)


def receive():
    length = struct.unpack("!I", exact(4))[0]
    if not 0 < length <= MAX_FRAME:
        raise ValueError("invalid frame")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result
    return json.loads(exact(length).decode("utf-8"), object_pairs_hook=unique)


def send(message):
    raw = json.dumps(message, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if not 0 < len(raw) <= 65536:
        raise ValueError("invalid message")
    framed = struct.pack("!I", len(raw)) + raw
    while framed:
        written = os.write(1, framed)
        if written <= 0:
            raise ValueError("transport failed")
        framed = framed[written:]


def call(request_id, operation, **arguments):
    send({"v": 1, "type": "request", "request_id": request_id,
          "operation": operation, **arguments})
    response = receive()
    if (type(response) is not dict
            or set(response) != {"v", "type", "request_id", "ok", "data"}
            or response["v"] != 1 or response["type"] != "response"
            or response["request_id"] != request_id or response["ok"] is not True
            or type(response["data"]) is not dict):
        raise ValueError("invalid broker response")
    return response["data"]


def main():
    init = receive()
    if (type(init) is not dict or set(init) != {"v", "type", "bytes", "sha256"}
            or init["v"] != 1 or init["type"] != "init"
            or type(init["bytes"]) is not int or not 0 <= init["bytes"] <= MAX_BYTES
            or type(init["sha256"]) is not str or len(init["sha256"]) != 64):
        raise ValueError("invalid initialization")
    size = init["bytes"]
    observed = hashlib.sha256()
    raw_all = bytearray()
    count = 0
    while count < size:
        end = min(size, count + CHUNK)
        reply = call("r" + str(count), "read_interval", start=count, end=end)
        if (set(reply) != {"start", "end", "encoding", "bytes"}
                or type(reply["start"]) is not int or reply["start"] != count
                or type(reply["end"]) is not int or reply["end"] != end
                or reply["encoding"] != "base64" or type(reply["bytes"]) is not str):
            raise ValueError("invalid read reply")
        try:
            fragment = base64.b64decode(reply["bytes"], validate=True)
        except (ValueError, binascii.Error) as exc:
            raise ValueError("invalid encoding") from exc
        if len(fragment) != end - count:
            raise ValueError("invalid byte range")
        observed.update(fragment)
        raw_all.extend(fragment)
        count = end
    if observed.hexdigest() != init["sha256"]:
        raise ValueError("snapshot mismatch")
    lines = raw_all.count(b"\n") + (1 if raw_all and not raw_all.endswith(b"\n") else 0)
    result = {"artifact_sha256": observed.hexdigest(),
              "artifact_bytes": size, "physical_lines": lines}
    if call("done", "submit_result", result=result):
        raise ValueError("unexpected ack")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, UnicodeError, KeyError, TypeError):
        raise SystemExit(3)
