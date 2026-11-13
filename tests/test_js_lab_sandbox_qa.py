"""Independent offline sandbox QA. No external addresses or JS are executed."""
import errno
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import Mock, patch

from test_js_lab import ROOT, entry, lab, scope_data

HELPER = ROOT / "tools/js_lab_sandbox.py"
BWRAP = Path("/usr/bin/bwrap")
BWRAP_REASON = "NOT_RUN: /usr/bin/bwrap is not installed; real sandbox isolation was not executed"
SPEC = importlib.util.spec_from_file_location("sandbox_qa_subject", HELPER)
sandbox = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sandbox)


class SandboxIndependentQA(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.scope_file = self.directory / "scope.json"
        self.scope_file.write_bytes(lab.packed(scope_data()))
        self.har = self.directory / "capture.har"
        self.har.write_bytes(lab.packed({"log": {"entries": [entry("/a.js", "const value=1;")]}}))

    def arguments(self, out=None):
        return ["import-har", str(self.har), "--scope", str(self.scope_file),
                "--out", str(out or self.directory / "output")]

    def package(self, out=None):
        out = out or self.directory / "package"
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(lab.main(self.arguments(out)), 0)
        return out

    def replace_manifest(self, out, change):
        manifest = json.loads((out / "manifest.json").read_bytes())
        change(manifest)
        raw = lab.packed(manifest)
        (out / "manifest.json").write_bytes(raw)
        checks = (out / "SHA256SUMS").read_text().splitlines()
        (out / "SHA256SUMS").write_text("\n".join(
            lab.digest(raw) + "  manifest.json" if line.endswith("  manifest.json") else line
            for line in checks) + "\n")

    def test_kernel_filter_ab_unix_socketpair_and_exec_are_denied(self):
        probe = f'''
import importlib.util, json, os, socket
from pathlib import Path
s = importlib.util.spec_from_file_location("guard", {str(HELPER)!r})
g = importlib.util.module_from_spec(s)
s.loader.exec_module(g)
def count():
    return int(next(x.split(":")[1] for x in Path("/proc/self/status").read_text().splitlines() if x.startswith("Seccomp_filters:")))
def denied(call):
    try:
        result = call()
        if hasattr(result, "close"): result.close()
        if isinstance(result, tuple):
            for x in result: x.close()
        return 0
    except OSError as exc:
        return exc.errno
baseline_socket = socket.socket(socket.AF_UNIX); baseline_socket.close()
pair = socket.socketpair(); pair[0].close(); pair[1].close()
before = count()
g.restrict_worker()
after = count()
result = {{"before": before, "after": after,
          "socket": denied(lambda: socket.socket(socket.AF_UNIX)),
          "socketpair": denied(socket.socketpair),
          "exec": denied(lambda: os.execv("/usr/bin/false", ["false"]))}}
print(json.dumps(result))
'''
        result = subprocess.run([sys.executable, "-I", "-S", "-B", "-c", probe],
                                capture_output=True, text=True, timeout=10,
                                env={"PATH": "/usr/bin", "LANG": "C.UTF-8"})
        self.assertEqual(result.returncode, 0, result.stderr)
        observed = json.loads(result.stdout)
        self.assertGreater(observed["after"], observed["before"])
        self.assertEqual([observed[x] for x in ("socket", "socketpair", "exec")], [errno.EPERM] * 3)

    @unittest.skipUnless(BWRAP.is_file() and os.access(BWRAP, os.X_OK), BWRAP_REASON)
    def test_real_bwrap_hides_canary_and_keeps_input_tmp_root_readonly(self):
        canary = self.directory / "host-only-canary"
        canary.write_text("SYNTHETIC_CANARY_NEVER_PRINTED")
        self.assertTrue(canary.read_bytes())
        inputs = self.directory / "inputs"
        inputs.mkdir()
        (inputs / "input.txt").write_text("synthetic")
        output = self.directory / "sandbox-output"
        output.mkdir()
        probe = f'''
import errno, importlib.util, json, os
from pathlib import Path
s = importlib.util.spec_from_file_location("guard", "/app/tools/js_lab_sandbox.py")
g = importlib.util.module_from_spec(s); s.loader.exec_module(g)
g.restrict_worker()
def attempt(path):
    try:
        Path(path).write_text("synthetic")
        return 0
    except OSError as exc: return exc.errno
try:
    Path({str(canary)!r}).read_bytes()
    canary_hidden = False
except OSError: canary_hidden = True
print(json.dumps({{"canary_hidden": canary_hidden, "home_hidden": not Path("/home").exists(),
 "input": attempt("/input/input.txt"), "tmp": attempt("/tmp/qa-write"),
 "root": attempt("/qa-write"), "output": attempt("/output/qa-write")}}))
'''
        command = sandbox.sandbox_argv(ROOT / "bin/mitr3-js-lab.py", HELPER, inputs, output, [])
        command = command[:command.index("/usr/bin/python3")] + ["/usr/bin/python3", "-I", "-S", "-B", "-c", probe]
        result = subprocess.run(command, capture_output=True, text=True, timeout=10,
                                stdin=subprocess.DEVNULL, close_fds=True,
                                env={"PATH": "/usr/bin", "LANG": "C.UTF-8"})
        self.assertEqual(result.returncode, 0, result.stderr)
        observed = json.loads(result.stdout)
        self.assertTrue(observed["canary_hidden"])
        self.assertTrue(observed["home_hidden"])
        self.assertEqual([observed[x] for x in ("input", "tmp", "root")], [errno.EROFS] * 3)
        self.assertEqual(observed["output"], 0)

    def test_filter_load_failure_has_no_core_fallback(self):
        fake_core = Mock(__file__="/app/bin/mitr3-js-lab.py")
        with patch.object(sandbox, "restrict_worker", side_effect=OSError("synthetic filter failure")):
            with redirect_stdout(io.StringIO()):
                self.assertEqual(sandbox.launch(fake_core, ["--offline-worker", "import-har"]), 2)
        fake_core.main.assert_not_called()

    def test_missing_bwrap_has_no_core_fallback(self):
        with patch.object(sandbox.subprocess, "Popen", side_effect=FileNotFoundError("synthetic bwrap missing")):
            with patch.object(lab, "main") as main, redirect_stdout(io.StringIO()):
                self.assertEqual(sandbox.launch(lab, self.arguments()), 2)
            main.assert_not_called()
        self.assertFalse((self.directory / "output/evidence/SHA256SUMS").exists())

    def test_verifier_rejects_tampered_artifact_and_unlisted_file(self):
        out = self.package()
        artifact = next((out / "raw").iterdir())
        artifact.chmod(0o600)
        artifact.write_bytes(b"tampered")
        with self.assertRaises(lab.LabError):
            lab.verify_package(out)
        out = self.package(self.directory / "other-package")
        (out / "unlisted.txt").write_text("synthetic")
        with self.assertRaises(lab.LabError):
            lab.verify_package(out)

    def test_verifier_rejects_negative_input_body_count_even_with_rehashed_manifest(self):
        out = self.package()
        self.replace_manifest(out, lambda m: m.update(input_body_bytes=-1))
        with self.assertRaises(lab.LabError):
            lab.verify_package(out)

    def test_verifier_rejects_unknown_artifact_kind_with_rehashed_manifest(self):
        out = self.package()
        self.replace_manifest(out, lambda m: m["artifacts"][0].update(kind="unknown"))
        with self.assertRaises(lab.LabError):
            lab.verify_package(out)

    def test_verifier_checks_declared_aggregate_budget_before_reading_artifacts(self):
        self.scope_file.write_bytes(lab.packed(scope_data(limits={"max_bytes": 1000})))
        out = self.package()

        def exceed_budget(manifest):
            manifest["artifacts"][0]["bytes"] = 1001
            manifest["bytes_written"] = 1001

        self.replace_manifest(out, exceed_budget)
        read = lab.read_local

        def deny_artifact_read(path, limit):
            if path.parent.name in {"raw", "derived"}:
                self.fail("verifier read artifact before rejecting declared aggregate quota")
            return read(path, limit)

        with patch.object(lab, "read_local", side_effect=deny_artifact_read):
            with self.assertRaises(lab.LabError):
                lab.verify_package(out)

    @unittest.skipUnless(BWRAP.is_file() and os.access(BWRAP, os.X_OK), BWRAP_REASON)
    def test_public_contained_cli_generates_independently_verified_package(self):
        out = self.directory / "contained-cli"
        result = subprocess.run([sys.executable, str(ROOT / "bin/mitr3-js-lab.py"), *self.arguments(out)],
                                capture_output=True, text=True, timeout=15,
                                stdin=subprocess.DEVNULL, close_fds=True,
                                env={"PATH": "/usr/bin", "LANG": "C.UTF-8"})
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        observed = json.loads(result.stdout)
        self.assertEqual(observed["isolation"], "bwrap+seccomp-offline")
        manifest = lab.verify_package(out / "evidence", expected_scope=lab.Scope(self.scope_file.read_bytes()),
                                      expected_har_sha256=lab.digest(self.har.read_bytes()), expected_maps=False)
        self.assertEqual(len(manifest["artifacts"]), 1)
        self.assertEqual(manifest["network_requests"], 0)

    def test_parent_rejects_worker_policy_escalation_even_with_valid_checksums(self):
        original_policy = scope_data(limits={"max_bytes": 1000})
        self.scope_file.write_bytes(lab.packed(original_policy))
        output = self.directory / "output"

        def fake_worker(command, **kwargs):
            captured = io.StringIO()
            with redirect_stdout(captured), redirect_stderr(io.StringIO()):
                self.assertEqual(lab.main(self.arguments(output / "evidence")), 0)
            self.replace_manifest(output / "evidence", lambda m: m["limits"].update(max_bytes=2000))
            kwargs["stdout"].write(captured.getvalue().encode())
            kwargs["stdout"].flush()
            return Mock(returncode=0, wait=Mock(return_value=0))

        with patch.object(sandbox.subprocess, "Popen", side_effect=fake_worker), redirect_stdout(io.StringIO()):
            self.assertEqual(sandbox.launch(lab, self.arguments(output)), 2)

    @unittest.skipUnless(BWRAP.is_file() and os.access(BWRAP, os.X_OK), BWRAP_REASON)
    def test_external_supervisor_reaps_real_stalled_bwrap_child(self):
        self.scope_file.write_bytes(lab.packed(scope_data(limits={"max_seconds": 1})))
        real_argv = sandbox.sandbox_argv
        real_popen = subprocess.Popen
        children = []

        def stalled_worker(*args):
            command = real_argv(*args)
            probe = '''import importlib.util, time
s = importlib.util.spec_from_file_location("guard", "/app/tools/js_lab_sandbox.py")
g = importlib.util.module_from_spec(s); s.loader.exec_module(g)
g.restrict_worker()
time.sleep(30)
'''
            return command[:command.index("/usr/bin/python3")] + ["/usr/bin/python3", "-I", "-S", "-B", "-c", probe]

        def record_child(*args, **kwargs):
            child = real_popen(*args, **kwargs)
            children.append(child)
            return child

        started = time.monotonic()
        with patch.object(sandbox, "sandbox_argv", side_effect=stalled_worker):
            with patch.object(sandbox.subprocess, "Popen", side_effect=record_child), redirect_stdout(io.StringIO()):
                self.assertEqual(sandbox.launch(lab, self.arguments()), 2)
        self.assertLess(time.monotonic() - started, 10)
        self.assertEqual(len(children), 1)
        self.assertIsNotNone(children[0].returncode)
        self.assertLess(children[0].returncode, 0)
        self.assertFalse((self.directory / "output/evidence/SHA256SUMS").exists())


if __name__ == "__main__":
    unittest.main()
