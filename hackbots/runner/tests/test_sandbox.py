"""Sandbox tests. Part 1 is pure (any user). Part 2 really tries to violate isolation.

Host tests need an unprivileged user with bwrap + a user systemd scope. When the
host cannot support them the tests are SKIPPED with a NOT_RUN reason and must be
read as NOT_RUN, never as PASS. They never touch the network beyond host loopback
canaries, and never start a model or the analyzed JavaScript.
"""
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from hackbots.runner import sandbox
from hackbots.runner.policies import Policy

ROOT = Path(__file__).resolve().parents[3]


def staged_file(directory, mode=0o600):
    path = os.path.join(directory, "worker.py")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    os.close(fd)
    return path


class ArgvAndSpecTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="sbx-")
        self.addCleanup(self.tmp.cleanup)
        self.script = staged_file(self.tmp.name)
        self.argv = sandbox.build_argv(sandbox.SandboxSpec(self.script, Policy(memory_mb=128, tasks_max=9)))

    def test_argv_is_an_explicit_str_list_with_absolute_binaries(self):
        self.assertIsInstance(self.argv, list)
        self.assertTrue(all(type(a) is str for a in self.argv))
        for binary in (self.argv[0], sandbox.PRLIMIT, sandbox.BWRAP, sandbox.PYTHON):
            self.assertTrue(binary.startswith("/usr/bin/"))
        self.assertNotIn("sh", [os.path.basename(a) for a in self.argv])

    def test_required_isolation_flags_present(self):
        for flag in ("--unshare-user", "--unshare-pid", "--unshare-net", "--unshare-ipc",
                     "--unshare-uts", "--unshare-cgroup", "--disable-userns", "--die-with-parent",
                     "--new-session", "--clearenv", "--remount-ro"):
            self.assertIn(flag, self.argv)
        self.assertEqual(self.argv[self.argv.index("--cap-drop") + 1], "ALL")
        self.assertLess(self.argv.index("--tmpfs"), self.argv.index("--remount-ro"))

    def test_no_writable_binds_and_no_host_trees(self):
        self.assertNotIn("--bind", self.argv)
        self.assertNotIn("--bind-try", self.argv)
        self.assertNotIn("--dev-bind", self.argv)
        sources = [self.argv[i + 1] for i, a in enumerate(self.argv) if a == "--ro-bind"]
        self.assertEqual(sources, ["/usr", self.script])
        for forbidden in ("/home", "/etc", "/run", "/var", str(ROOT)):
            self.assertFalse(any(a == forbidden or a.startswith(forbidden + "/") for a in self.argv
                                 if a != self.script), forbidden)

    def test_limits_come_from_policy(self):
        self.assertIn("MemoryMax=128M", self.argv)
        self.assertIn("TasksMax=9", self.argv)
        self.assertIn("MemorySwapMax=0", self.argv)
        self.assertIn("CPUQuota=100%", self.argv)
        self.assertIn("--core=0", self.argv)

    def test_only_allowlisted_env_is_set(self):
        keys = [self.argv[i + 1] for i, a in enumerate(self.argv) if a == "--setenv"]
        self.assertEqual(set(keys), set(k for k, _ in sandbox.WORKER_ENV))

    def test_spec_rejects_unsafe_staged_workers(self):
        with self.assertRaises(sandbox.SandboxError):
            sandbox.SandboxSpec("relative.py", Policy())
        link = os.path.join(self.tmp.name, "link.py")
        os.symlink(self.script, link)
        with self.assertRaises(sandbox.SandboxError):
            sandbox.SandboxSpec(link, Policy())
        hard = os.path.join(self.tmp.name, "hard.py")
        os.link(self.script, hard)
        with self.assertRaises(sandbox.SandboxError):
            sandbox.SandboxSpec(self.script, Policy())  # nlink != 1 now
        os.unlink(hard)
        os.chmod(self.script, 0o666)
        with self.assertRaises(sandbox.SandboxError):
            sandbox.SandboxSpec(self.script, Policy())
        os.chmod(self.script, 0o600)
        with self.assertRaises(sandbox.SandboxError):
            sandbox.SandboxSpec(self.script, Policy(), unit="evil; rm -rf /")
        with self.assertRaises(sandbox.SandboxError):
            sandbox.SandboxSpec(self.script, "not-a-policy")


class FailClosedTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="sbx-")
        self.addCleanup(self.tmp.cleanup)
        self.spec = sandbox.SandboxSpec(staged_file(self.tmp.name), Policy())

    def test_launch_refuses_root_and_spawns_nothing(self):
        with patch.object(sandbox.os, "geteuid", return_value=0), \
                patch.object(sandbox.subprocess, "Popen") as popen:
            with self.assertRaises(sandbox.SandboxUnavailable):
                sandbox.launch(self.spec)
            popen.assert_not_called()

    def test_d8_missing_bwrap_blocks_and_spawns_nothing(self):
        with patch.object(sandbox, "BWRAP", "/nonexistent/bwrap"), \
                patch.object(sandbox.subprocess, "Popen") as popen:
            with self.assertRaises(sandbox.SandboxUnavailable):
                sandbox.launch(self.spec)
            popen.assert_not_called()

    def test_launch_requires_validated_spec(self):
        with self.assertRaises(sandbox.SandboxUnavailable):
            sandbox.launch(["/bin/sh", "-c", "id"])

    def test_doctor_as_root_runs_nothing_and_is_not_ready(self):
        with patch.object(sandbox.os, "geteuid", return_value=0), \
                patch.object(sandbox.subprocess, "run") as run:
            checks = sandbox.doctor()
            run.assert_not_called()
        self.assertFalse(sandbox.ready(checks))
        self.assertEqual(checks[0].status, "FAIL")
        self.assertTrue(all(c.status == "NOT_RUN" for c in checks[1:]))
        self.assertIn("cpu_limit", [c.name for c in checks])

    def test_cpu_quota_missing_blocks_doctor_even_with_other_limits(self):
        from unittest.mock import patch
        with (patch.object(sandbox.os, "geteuid", return_value=1000),
              patch.object(sandbox, "host_env",
                           return_value={"XDG_RUNTIME_DIR": "/run/user/1000"}),
              patch.object(sandbox.os.path, "isdir", return_value=True),
              patch.object(sandbox, "_run",
                           side_effect=[(0, b"bubblewrap 0.13.1", b""),
                                        (0, " ".join(sandbox.REQUIRED_FLAGS).encode(), b""),
                                        (0, b"", b"")]),
              patch.object(sandbox, "_limits_check",
                           return_value=(False, "cpu quota missing", False))):
            checks = sandbox.doctor()
        self.assertFalse(sandbox.ready(checks))
        cpu = next(c for c in checks if c.name == "cpu_limit")
        self.assertTrue(cpu.required)
        self.assertEqual(cpu.status, "FAIL")

    def test_diagnostics_cli_as_root_does_not_mark_ready(self):
        import io
        import json
        from contextlib import redirect_stdout
        output = io.StringIO()
        with patch.object(sandbox.os, "geteuid", return_value=0), redirect_stdout(output):
            code = sandbox.main(["doctor"])
        result = json.loads(output.getvalue())
        self.assertEqual(code, 1)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(result["sandbox_gate"], "NOT_VERIFIED")
        self.assertFalse(result["promotable"])

    def test_ready_never_accepts_not_run_required_checks(self):
        self.assertFalse(sandbox.ready([sandbox.Check("x", True, "NOT_RUN", "")]))
        self.assertFalse(sandbox.ready([]))
        self.assertTrue(sandbox.ready([sandbox.Check("x", False, "NOT_RUN", "")]
                                      + [sandbox.Check("y", True, "OK", "")]))


def host_reason():
    if os.geteuid() == 0:
        return "NOT_RUN: running as root; isolation must be tested unprivileged"
    checks = sandbox.doctor()
    if not sandbox.ready(checks):
        failed = [f"{c.name}={c.status}" for c in checks if c.required and c.status != "OK"]
        return "NOT_RUN: host cannot support the sandbox (" + ", ".join(failed) + ")"
    return None


class HostTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        reason = host_reason()
        if reason:
            raise unittest.SkipTest(reason)

    def probe(self, source, **kw):
        return sandbox.run_probe(source, kw.pop("policy", Policy(timeout_s=10, request_timeout_s=5)), **kw)

    def assertClean(self, result):
        self.assertTrue(result.residual_free)
        self.assertFalse(sandbox.scope_has_processes(result.unit))

    def test_selftest_every_control_blocks_the_violation(self):
        checks = sandbox.selftest()
        self.assertTrue(sandbox.ready(checks), [c for c in checks if c.status != "OK"])
        names = {c.name for c in checks}
        for expected in ("sandbox_fs_read", "sandbox_fs_write", "sandbox_net", "sandbox_env",
                         "sandbox_caps", "sandbox_nested_userns", "sandbox_tmp_quota",
                         "sandbox_canaries_intact", "sandbox_cleanup"):
            self.assertIn(expected, names)

    def test_c10_credentials_in_parent_env_never_reach_the_worker(self):
        secrets_env = {"OPENAI_API_KEY": "canary-openai", "ANTHROPIC_API_KEY": "canary-anthropic",
                       "GITHUB_TOKEN": "canary-github", "GEMINI_API_KEY": "canary-gemini",
                       "MEGABRAIN_TOKEN": "canary-megabrain", "DAHL_API_KEY": "canary-dahl",
                       "SSH_AUTH_SOCK": "/tmp/canary-ssh"}
        source = ("import os\nprint(dict(os.environ))\n"
                  "print(open('/proc/self/environ','rb').read())\n")
        with patch.dict(os.environ, secrets_env):
            result = self.probe(source)
        text = result.stdout.decode()
        self.assertIn("PYTHONHASHSEED", text)  # the probe did run
        self.assertNotIn("canary", text)
        for key in secrets_env:
            self.assertNotIn(key, text)
        self.assertClean(result)

    def test_c5_host_tcp_udp_and_abstract_unix_sockets_are_unreachable(self):
        tcp = socket.socket(); tcp.bind(("127.0.0.1", 0)); tcp.listen(1); tcp.setblocking(False)
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); udp.bind(("127.0.0.1", 0)); udp.setblocking(False)
        name = "\0mitr3-canary-" + os.urandom(6).hex()
        unix = socket.socket(socket.AF_UNIX); unix.bind(name); unix.listen(1); unix.setblocking(False)
        for s in (tcp, udp, unix):
            self.addCleanup(s.close)
        source = (
            "import socket\nres = {}\n"
            "def t(n, f):\n"
            "    try: f(); res[n] = 'CONNECTED'\n"
            "    except OSError as e: res[n] = type(e).__name__\n"
            "def tcp():\n    s = socket.socket(); s.settimeout(1); s.connect(('127.0.0.1', %d)); s.send(b'x')\n"
            "def udp():\n    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.sendto(b'x', ('127.0.0.1', %d))\n"
            "def unix():\n    s = socket.socket(socket.AF_UNIX); s.connect(%r)\n"
            "t('tcp', tcp); t('udp', udp); t('unix', unix)\nprint(res)\n"
            % (tcp.getsockname()[1], udp.getsockname()[1], name))
        result = self.probe(source)
        import ast
        report = ast.literal_eval(result.stdout.decode().strip())
        self.assertNotEqual(report["tcp"], "CONNECTED", report)
        self.assertNotEqual(report["unix"], "CONNECTED", report)
        # UDP sendto "succeeds" locally: bwrap brings up the sandbox's OWN loopback, so the
        # datagram stays in that namespace. The proof is host-side non-receipt, asserted below.
        with self.assertRaises(BlockingIOError):
            tcp.accept()
        with self.assertRaises(BlockingIOError):
            unix.accept()
        with self.assertRaises(BlockingIOError):
            udp.recv(10)
        self.assertClean(result)

    def test_d1_hung_worker_times_out_and_whole_tree_dies(self):
        source = ("import subprocess, time\nsubprocess.Popen(['/usr/bin/sleep', '60'])\n"
                  "subprocess.Popen(['/usr/bin/sleep', '60'])\ntime.sleep(60)\n")
        started = time.monotonic()
        result = self.probe(source, timeout_s=1.0)
        self.assertTrue(result.timed_out)
        self.assertLess(time.monotonic() - started, 9)
        self.assertClean(result)

    def test_d2_failing_worker_reports_its_exit_code(self):
        result = self.probe("import sys\nsys.exit(7)\n")
        self.assertEqual(result.returncode, 7)
        self.assertFalse(result.timed_out)
        self.assertClean(result)

    def test_d5_excess_stdout_is_cut_and_killed(self):
        source = "import sys\nwhile True:\n    sys.stdout.write('x' * 65536); sys.stdout.flush()\n"
        result = self.probe(source, max_output=200_000)
        self.assertTrue(result.output_exceeded)
        self.assertLess(len(result.stdout), 400_000)
        self.assertClean(result)

    def test_d5_excess_stderr_is_bounded(self):
        source = "import sys\nsys.stderr.write('e' * 5_000_000)\nsys.stderr.flush()\n"
        result = self.probe(source)
        self.assertLessEqual(len(result.stderr), sandbox.MAX_STDERR_BYTES)
        self.assertClean(result)

    def test_memory_limit_kills_an_oversized_worker(self):
        source = "x = b'x' * 400_000_000\nprint('SURVIVED', len(x))\n"
        result = self.probe(source, policy=Policy(memory_mb=64, timeout_s=10, request_timeout_s=5))
        self.assertNotIn("SURVIVED", result.stdout.decode())
        self.assertNotEqual(result.returncode, 0)
        self.assertClean(result)

    def test_d6_process_limit_stops_a_fork_flood(self):
        source = (
            "import os, time\nok = fail = 0\n"
            "for _ in range(60):\n"
            "    try: pid = os.fork()\n"
            "    except OSError: fail += 1; continue\n"
            "    if pid == 0:\n        os.close(1); os.close(2); time.sleep(30); os._exit(0)\n"
            "    ok += 1\nprint('FORKS', ok, fail, flush=True)\nos._exit(0)\n")
        result = self.probe(source, policy=Policy(tasks_max=8, timeout_s=10, request_timeout_s=5))
        line = [l for l in result.stdout.decode().splitlines() if l.startswith("FORKS")]
        self.assertTrue(line, (result.stdout, result.stderr))
        _, ok, fail = line[0].split()
        self.assertLessEqual(int(ok), 8)
        self.assertGreaterEqual(int(fail), 1)
        self.assertClean(result)

    def test_d8_broken_bwrap_means_the_worker_never_runs(self):
        with patch.object(sandbox, "BWRAP", "/usr/bin/false"):
            result = self.probe("print('WORKER-RAN')\n", timeout_s=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(b"WORKER-RAN", result.stdout)
        self.assertClean(result)

    def test_d7_runner_death_leaves_no_orphans(self):
        code = ("import os, time\nfrom hackbots.runner import sandbox\n"
                "with sandbox._staged('import time\\ntime.sleep(60)\\n') as script:\n"
                "    p = sandbox.launch(sandbox.SandboxSpec(script, sandbox.Policy()))\n"
                "    print(p.spec.unit, os.path.dirname(script), flush=True)\n    time.sleep(60)\n")
        parent = subprocess.Popen([sys.executable, "-B", "-c", code], cwd=ROOT, stdout=subprocess.PIPE,
                                  env={"PATH": "/usr/bin", "HOME": os.environ.get("HOME", "/tmp")})
        unit, stage = parent.stdout.readline().decode().split()
        # SIGKILL stops the parent's own cleanup, so the test removes the staging dir itself.
        self.addCleanup(shutil.rmtree, stage, True)
        self.assertRegex(unit, sandbox.UNIT_RE.pattern)
        deadline = time.monotonic() + 3
        while not sandbox.scope_has_processes(unit) and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertTrue(sandbox.scope_has_processes(unit), "worker never started")
        os.kill(parent.pid, signal.SIGKILL)
        parent.wait()
        parent.stdout.close()
        deadline = time.monotonic() + 5
        while sandbox.scope_has_processes(unit) and time.monotonic() < deadline:
            time.sleep(0.1)
        left = sandbox.scope_has_processes(unit)
        if left:
            sandbox._run([sandbox.SYSTEMCTL, "--user", "kill", "--signal=SIGKILL", unit + ".scope"])
        self.assertFalse(left, "orphaned worker survived the runner")


if __name__ == "__main__":
    unittest.main()
