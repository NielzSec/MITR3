#!/usr/bin/env python3
"""Safely test MCP stdio initialize and tools/list using a private child process.

Only launches explicitly requested, configured local MCP server, and terminates
the process group created by this probe (never running agent processes).
No tools/call, no secret or stdout logging, no persistent config changes.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import time

VERSION = "2025-11-25"


class ProbeError(Exception):
    pass


class MCPStdio:
    def __init__(self, proc: subprocess.Popen, timeout: float):
        self.proc = proc
        self.timeout = timeout
        self.buffer = bytearray()
        self.sel = selectors.DefaultSelector()
        self.sel.register(proc.stdout, selectors.EVENT_READ)

    def send(self, obj: dict) -> None:
        data = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"
        try:
            self.proc.stdin.write(data)
            self.proc.stdin.flush()
        except (BrokenPipeError, OSError):
            raise ProbeError("stdio write failed") from None

    def receive(self, expected_id: int) -> dict:
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            while b"\n" in self.buffer:
                raw, _, rest = self.buffer.partition(b"\n")
                self.buffer = bytearray(rest)
                if not raw.strip():
                    continue
                try:
                    msg = json.loads(raw)
                except (ValueError, UnicodeDecodeError):
                    raise ProbeError("server sent non-JSON stdout") from None
                if isinstance(msg, dict) and msg.get("id") == expected_id:
                    if msg.get("error") is not None:
                        raise ProbeError("server returned JSON-RPC error")
                    return msg
            if len(self.buffer) > 1048576:
                raise ProbeError("server response exceeded size limit")
            if self.proc.poll() is not None:
                raise ProbeError("server exited before JSON-RPC response")
            ready = self.sel.select(min(0.5, max(0, deadline - time.monotonic())))
            if ready:
                chunk = os.read(self.proc.stdout.fileno(), 65536)
                if not chunk:
                    raise ProbeError("server closed stdout")
                self.buffer.extend(chunk)
        raise ProbeError("server response timeout")

    def initialize(self) -> dict:
        self.send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                   "params": {"protocolVersion": VERSION, "capabilities": {},
                              "clientInfo": {"name": "mitr3-codex-qa", "version": "1.0.0"}}})
        msg = self.receive(1)
        result = msg.get("result")
        if not isinstance(result, dict) or "protocolVersion" not in result:
            raise ProbeError("invalid initialize result")
        self.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        self.send({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        tool_msg = self.receive(2)
        data = tool_msg.get("result")
        if not isinstance(data, dict) or not isinstance(data.get("tools"), list):
            raise ProbeError("tools/list did not contain tools array")
        count = len(data["tools"])
        cursor = data.get("nextCursor")
        for request_id in range(3, 23):
            if not cursor:
                break
            self.send({"jsonrpc": "2.0", "id": request_id, "method": "tools/list",
                       "params": {"cursor": cursor}})
            page = self.receive(request_id).get("result")
            if not isinstance(page, dict) or not isinstance(page.get("tools"), list):
                raise ProbeError("tools/list pagination failed")
            count += len(page["tools"])
            cursor = page.get("nextCursor")
        else:
            if cursor:
                raise ProbeError("tools/list pagination limit exceeded")
        return {"protocol_version": str(result["protocolVersion"]),
                "tools_count": count}


def run_probe(cfg: dict, timeout: float = 25.0) -> dict:
    if cfg.get("type") != "local":
        raise ProbeError("only local stdio MCP servers are supported")
    cmd = cfg.get("command")
    if not isinstance(cmd, list) or not cmd or not all(isinstance(x, str) for x in cmd):
        raise ProbeError("invalid configured command")
    cwd = Path(cfg.get("cwd") or Path.home()).expanduser()
    if not cwd.is_dir():
        raise ProbeError("configured working directory does not exist")
    env = os.environ.copy()
    override = cfg.get("environment", {})
    if not isinstance(override, dict):
        raise ProbeError("invalid environment configuration")
    for key, value in override.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise ProbeError("invalid environment field")
    env.update(override)
    env["PATH"] = str(Path.home() / ".local/bin") + os.pathsep + env.get("PATH", "")
    proc = None
    try:
        proc = subprocess.Popen(cmd, cwd=cwd, env=env, start_new_session=True,
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL)
        return MCPStdio(proc, timeout).initialize()
    except (FileNotFoundError, PermissionError) as exc:
        raise ProbeError("cannot launch MCP: " + type(exc).__name__) from None
    finally:
        if proc is not None:
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                proc.wait(timeout=2)
            for stream in (proc.stdin, proc.stdout):
                if stream is not None:
                    stream.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", required=True)
    parser.add_argument("--config", type=Path,
                        default=Path.home() / ".config/opencode/opencode.json")
    parser.add_argument("--timeout", type=float, default=25.0)
    args = parser.parse_args()
    if not 1 <= args.timeout <= 40:
        parser.error("--timeout must be 1..40 seconds")
    try:
        data = json.loads(args.config.read_text(encoding="utf-8"))
        cfg = data["mcp"]["servers"][args.server]
        result = run_probe(cfg, args.timeout)
    except (OSError, KeyError, TypeError, ValueError, ProbeError) as exc:
        print(json.dumps({"server": args.server, "status": "fail",
                          "reason": type(exc).__name__ if not isinstance(exc, ProbeError) else str(exc)}))
        return 1
    print(json.dumps({"server": args.server, "status": "pass", **result}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
