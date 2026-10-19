"""Offline tests of the MCP stdio protocol probe. All child processes are mocks."""
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import textwrap
import unittest

module_path = Path(__file__).resolve().parents[1] / "mcp_stdio_probe.py"
spec = importlib.util.spec_from_file_location("mcp_stdio_probe", module_path)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class StdioProtocolTests(unittest.TestCase):
    def make_script(self, root, content):
        path = root / "server.py"
        path.write_text(textwrap.dedent(content))
        return {"type": "local", "command": [sys.executable, str(path)], "cwd": str(root)}

    def test_initialize_tools_list_count(self):
        with tempfile.TemporaryDirectory() as temp:
            cfg = self.make_script(Path(temp), """
                import sys, json
                for line in sys.stdin:
                    msg = json.loads(line)
                    if msg.get("id") == 1:
                        print(json.dumps({"jsonrpc":"2.0","id":1,"result":{
                            "protocolVersion":"2025-11-25", "capabilities":{"tools":{}},
                            "serverInfo":{"name":"mock","version":"1.0"}}}), flush=True)
                    elif msg.get("id") == 2:
                        print(json.dumps({"jsonrpc":"2.0","id":2,"result":{
                            "tools":[{"name":"a"},{"name":"b"}]}}), flush=True)
                """)
            result = probe.run_probe(cfg, timeout=2)
            self.assertEqual(result["tools_count"], 2)
            self.assertEqual(result["protocol_version"], "2025-11-25")

    def test_paginated_tool_listing(self):
        with tempfile.TemporaryDirectory() as temp:
            cfg = self.make_script(Path(temp), """
                import sys, json
                for line in sys.stdin:
                    msg = json.loads(line)
                    if msg.get("id") == 1:
                        print(json.dumps({"jsonrpc":"2.0","id":1,"result":{
                            "protocolVersion":"2025-11-25", "capabilities":{"tools":{}},
                            "serverInfo":{"name":"mock","version":"1.0"}}}), flush=True)
                    elif msg.get("id") == 2:
                        print(json.dumps({"jsonrpc":"2.0","id":2,"result":{
                            "tools":[{"name":"a"}],"nextCursor":"next"}}), flush=True)
                    elif msg.get("id") == 3:
                        print(json.dumps({"jsonrpc":"2.0","id":3,"result":{
                            "tools":[{"name":"b"},{"name":"c"}]}}), flush=True)
                """)
            result = probe.run_probe(cfg, timeout=2)
            self.assertEqual(result["tools_count"], 3)

    def test_server_rpc_error(self):
        with tempfile.TemporaryDirectory() as temp:
            cfg = self.make_script(Path(temp), """
                import sys, json
                for line in sys.stdin:
                    msg=json.loads(line)
                    if msg.get("id") == 1:
                        print(json.dumps({"jsonrpc":"2.0","id":1,
                            "error":{"code":-32600,"message":"bad request"}}), flush=True)
                """)
            with self.assertRaises(probe.ProbeError):
                probe.run_probe(cfg, timeout=2)

    def test_invalid_stdout_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            cfg = self.make_script(Path(temp), """
                import sys
                sys.stdout.write("NOT JSON\\n")
                sys.stdout.flush()
                sys.stdin.readline()
                """)
            with self.assertRaises(probe.ProbeError):
                probe.run_probe(cfg, timeout=2)

    def test_remote_refused_without_side_effects(self):
        with self.assertRaises(probe.ProbeError):
            probe.run_probe({"type": "remote", "url": "https://invalid.example/mcp"})

    def test_bad_cwd_refused(self):
        with self.assertRaises(probe.ProbeError):
            probe.run_probe({"type": "local", "cwd": "/no_such_mitr3_workdir",
                             "command": [sys.executable, "--version"]})

    def test_timeout_is_bounded(self):
        with tempfile.TemporaryDirectory() as temp:
            cfg = self.make_script(Path(temp), """
                import time
                time.sleep(5)
                """)
            with self.assertRaises(probe.ProbeError):
                probe.run_probe(cfg, timeout=0.2)


if __name__ == "__main__":
    unittest.main()
