"""Bubblewrap launcher for the offline worker. Fail closed: there is NO unconfined fallback.

Chain (one exec chain, one PID, so a failure at any link means the worker never runs):
    systemd-run --user --scope (cgroup: MemoryMax, MemorySwapMax=0, TasksMax)
      -> prlimit (RLIMIT_CORE/FSIZE/NOFILE, per process only)
        -> bwrap (user/pid/net/ipc/uts/cgroup namespaces, no caps, cleared env)
          -> python3 -I -B /worker/worker.py

Passing a doctor()/selftest() run on one host at one time is evidence about THAT
run only. Bubblewrap shares the host kernel and is not a VM. Never runs as root.
"""
from contextlib import contextmanager
from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import shutil
import signal
import socket
import stat
import subprocess
import tempfile
import threading
import time

from .policies import Policy

BWRAP = "/usr/bin/bwrap"
SYSTEMD_RUN = "/usr/bin/systemd-run"
SYSTEMCTL = "/usr/bin/systemctl"
PRLIMIT = "/usr/bin/prlimit"
PYTHON = "/usr/bin/python3"
WORKER_PATH = "/worker/worker.py"
WORKER_ENV = (("PATH", "/usr/bin"), ("LANG", "C.UTF-8"), ("PYTHONHASHSEED", "0"), ("HOME", "/tmp"))
ALLOWED_ENV_KEYS = frozenset(key for key, _ in WORKER_ENV) | {"PWD"}  # bwrap --chdir adds PWD
REQUIRED_FLAGS = ("--unshare-user", "--unshare-pid", "--unshare-net", "--unshare-ipc",
                  "--unshare-uts", "--unshare-cgroup", "--disable-userns", "--cap-drop",
                  "--new-session", "--die-with-parent", "--clearenv", "--size", "--tmpfs",
                  "--ro-bind", "--setenv", "--chdir", "--remount-ro")
EXPECTED_ROOT = frozenset({"bin", "dev", "lib", "lib64", "proc", "tmp", "usr", "worker"})
MAX_STDERR_BYTES = 65_536
NOFILE_LIMIT = 64
UNIT_RE = re.compile(r"mitr3-[a-f0-9]{16}\Z")
CGROUP_ROOT = "/sys/fs/cgroup"


class SandboxError(RuntimeError):
    pass


class SandboxUnavailable(SandboxError):
    """Isolation cannot be established; the caller must report BLOCKED, never run unconfined."""


@dataclass(frozen=True)
class Check:
    name: str
    required: bool
    status: str  # OK | FAIL | NOT_RUN
    detail: str


def ready(checks):
    return bool(checks) and all(c.status == "OK" for c in checks if c.required)


def summarize(checks):
    return {"ready": ready(checks), "checks": [vars(c) | {} for c in checks]}


def _new_unit():
    return "mitr3-" + secrets.token_hex(8)


@dataclass(frozen=True)
class SandboxSpec:
    staged_worker: str
    policy: Policy
    unit: str = field(default_factory=_new_unit)

    def __post_init__(self):
        if type(self.policy) is not Policy or type(self.unit) is not str or not UNIT_RE.fullmatch(self.unit):
            raise SandboxError("invalid sandbox spec")
        _check_staged(self.staged_worker)


def _check_staged(path):
    """The worker script must be a private regular file owned by us (no symlink/hardlink tricks)."""
    if type(path) is not str or not os.path.isabs(path) or "\x00" in path:
        raise SandboxError("invalid staged worker path")
    try:
        st = os.lstat(path)
        parent = os.lstat(os.path.dirname(path))
    except OSError:
        raise SandboxError("staged worker unavailable") from None
    if (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_uid != os.getuid()
            or st.st_mode & 0o022 or not stat.S_ISDIR(parent.st_mode)
            or parent.st_uid != os.getuid() or parent.st_mode & 0o022):
        raise SandboxError("unsafe staged worker")


def host_env():
    """Minimal environment for the host-side chain; no inherited secrets."""
    uid = os.getuid()
    runtime = os.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{uid}"
    bus = os.environ.get("DBUS_SESSION_BUS_ADDRESS") or f"unix:path={runtime}/bus"
    return {"PATH": "/usr/bin", "XDG_RUNTIME_DIR": runtime, "DBUS_SESSION_BUS_ADDRESS": bus}


def build_argv(spec):
    """Pure function: explicit argv list, never a shell string."""
    p = spec.policy
    scope = [SYSTEMD_RUN, "--user", "--scope", "--quiet", "--collect", f"--unit={spec.unit}",
             "-p", f"MemoryMax={p.memory_mb}M", "-p", "MemorySwapMax=0",
             "-p", f"TasksMax={p.tasks_max}", "-p", "CPUQuota=100%", "--"]
    limits = [PRLIMIT, "--core=0", f"--fsize={p.tmp_bytes}", f"--nofile={NOFILE_LIMIT}", "--"]
    bwrap = [BWRAP,
             "--unshare-user", "--unshare-pid", "--unshare-net", "--unshare-ipc",
             "--unshare-uts", "--unshare-cgroup", "--disable-userns",
             "--die-with-parent", "--new-session", "--cap-drop", "ALL", "--clearenv"]
    for key, value in WORKER_ENV:
        bwrap += ["--setenv", key, value]
    bwrap += ["--ro-bind", "/usr", "/usr", "--symlink", "usr/lib", "/lib",
              "--symlink", "usr/lib", "/lib64", "--symlink", "usr/bin", "/bin",
              "--proc", "/proc", "--dev", "/dev",
              "--size", str(p.tmp_bytes), "--tmpfs", "/tmp",
              "--ro-bind", spec.staged_worker, WORKER_PATH,
              # The root tmpfs is writable (and outside the /tmp --size quota) unless remounted;
              # the selftest caught this. Submounts (/tmp, /proc, /dev) are unaffected.
              "--remount-ro", "/",
              "--chdir", "/tmp", "--", PYTHON, "-I", "-B", WORKER_PATH]
    argv = scope + limits + bwrap
    if not all(type(item) is str for item in argv):
        raise SandboxError("non-string argv element")
    return argv


def _run(cmd, timeout=5.0):
    try:
        done = subprocess.run(cmd, capture_output=True, timeout=timeout, env=host_env(), cwd="/",
                              stdin=subprocess.DEVNULL, check=False)
        return done.returncode, done.stdout, done.stderr
    except (OSError, subprocess.SubprocessError, ValueError):
        return None, b"", b""


def scope_has_processes(unit):
    """Independent of systemd: any host process whose cgroup names this scope?"""
    needle = (unit + ".scope").encode()
    try:
        names = os.listdir("/proc")
    except OSError:
        return True  # cannot prove absence
    for name in names:
        if name.isdigit():
            try:
                with open(f"/proc/{name}/cgroup", "rb") as handle:
                    if needle in handle.read():
                        return True
            except OSError:
                continue
    return False


def _scope_cgroup_dir(unit):
    code, out, _ = _run([SYSTEMCTL, "--user", "show", "--value", "-p", "ControlGroup", unit + ".scope"])
    path = out.decode("ascii", "replace").strip()
    if code != 0 or not path.startswith("/") or ".." in path:
        return None
    return CGROUP_ROOT + path


class SandboxProcess:
    """Owns the whole process tree of one worker. Only the trusted runner may hold this."""

    def __init__(self, spec, popen):
        self.spec = spec
        self._p = popen
        self.pgid = popen.pid
        self.stderr = bytearray()
        self.stderr_truncated = False
        self._killed = False
        self._residual_free = None
        self._drain = threading.Thread(target=self._drain_stderr, daemon=True)
        self._drain.start()

    @property
    def stdin_fd(self):
        return self._p.stdin.fileno()

    @property
    def stdout_fd(self):
        return self._p.stdout.fileno()

    @property
    def returncode(self):
        return self._p.returncode

    def _drain_stderr(self):
        try:
            while True:
                chunk = os.read(self._p.stderr.fileno(), 4096)
                if not chunk:
                    return
                room = MAX_STDERR_BYTES - len(self.stderr)
                if room > 0:
                    self.stderr += chunk[:room]
                if len(chunk) > max(room, 0):
                    self.stderr_truncated = True
        except (OSError, ValueError):
            return

    def poll(self):
        return self._p.poll()

    def wait(self, timeout):
        try:
            return self._p.wait(timeout)
        except subprocess.TimeoutExpired:
            return None

    def kill_tree(self):
        """SIGKILL the whole cgroup and process group; True only if no residue is observed."""
        if self._killed:
            return self._residual_free
        self._killed = True
        _run([SYSTEMCTL, "--user", "kill", "--signal=SIGKILL", "--kill-whom=all",
              self.spec.unit + ".scope"])
        try:
            os.killpg(self.pgid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        self.wait(5.0)
        self._drain.join(2.0)
        for pipe in (self._p.stdin, self._p.stdout, self._p.stderr):
            try:
                pipe.close()
            except (OSError, ValueError):
                pass
        group_gone = False
        try:
            os.killpg(self.pgid, 0)
        except ProcessLookupError:
            group_gone = True
        except PermissionError:
            pass
        deadline = time.monotonic() + 2.0
        while scope_has_processes(self.spec.unit) and time.monotonic() < deadline:
            time.sleep(0.05)
        self._residual_free = group_gone and not scope_has_processes(self.spec.unit)
        return self._residual_free

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.kill_tree()


def _require_launchable():
    if os.geteuid() == 0:
        raise SandboxUnavailable("refusing to run as root")
    for binary in (BWRAP, SYSTEMD_RUN, PRLIMIT, PYTHON):
        if not os.access(binary, os.X_OK):
            raise SandboxUnavailable("required isolation binary missing")
    env = host_env()
    if not os.path.isdir(env["XDG_RUNTIME_DIR"]):
        raise SandboxUnavailable("user systemd runtime unavailable")


def launch(spec):
    """Start the worker inside the full chain. Any failure raises SandboxUnavailable."""
    if not isinstance(spec, SandboxSpec):
        raise SandboxUnavailable("a validated SandboxSpec is required")
    _require_launchable()
    try:
        popen = subprocess.Popen(build_argv(spec), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, bufsize=0, close_fds=True,
                                 start_new_session=True, env=host_env(), cwd="/", shell=False)
    except (OSError, ValueError):
        raise SandboxUnavailable("cannot start sandbox chain") from None
    os.set_blocking(popen.stdin.fileno(), False)
    return SandboxProcess(spec, popen)


@contextmanager
def _staged(source):
    directory = tempfile.mkdtemp(prefix="mitr3-stage-")  # 0700, ours
    try:
        script = os.path.join(directory, "worker.py")
        fd = os.open(script, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(source.encode("utf-8"))
        yield script
    finally:
        shutil.rmtree(directory, ignore_errors=True)


@dataclass
class ProbeResult:
    returncode: object
    stdout: bytes
    stderr: bytes
    timed_out: bool
    output_exceeded: bool
    residual_free: bool
    unit: str


def run_probe(source, policy=None, timeout_s=None, max_output=1 << 20):
    """Run a trusted diagnostic script through the SAME chain; stdout/time are bounded."""
    policy = policy if policy is not None else Policy()
    timeout = float(timeout_s if timeout_s is not None else policy.timeout_s)
    out = bytearray()
    timed_out = exceeded = False
    with _staged(source) as script:
        proc = launch(SandboxSpec(script, policy))
        selector = selectors.DefaultSelector()
        selector.register(proc.stdout_fd, selectors.EVENT_READ)
        deadline = time.monotonic() + timeout
        try:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    timed_out = True
                    break
                if selector.select(min(remaining, 0.2)):
                    chunk = os.read(proc.stdout_fd, 65_536)
                    if not chunk:
                        break
                    out += chunk
                    if len(out) > max_output:
                        exceeded = True
                        break
        finally:
            selector.close()
            if not timed_out and not exceeded:
                proc.wait(2.0)
            residual_free = proc.kill_tree()
    return ProbeResult(proc.returncode, bytes(out), bytes(proc.stderr), timed_out, exceeded,
                       bool(residual_free), proc.spec.unit)


_HOLD = 'import sys\nprint("READY", flush=True)\nsys.stdin.read()\n'


def _limits_check(policy):
    with _staged(_HOLD) as script:
        with launch(SandboxSpec(script, policy)) as proc:
            selector = selectors.DefaultSelector()
            selector.register(proc.stdout_fd, selectors.EVENT_READ)
            try:
                if not selector.select(5.0) or b"READY" not in os.read(proc.stdout_fd, 64):
                    return False, "probe did not start"
            finally:
                selector.close()
            cgroup = _scope_cgroup_dir(proc.spec.unit)
            if cgroup is None:
                return False, "scope cgroup not found"
            expected = {"memory.max": str(policy.memory_mb * 1024 * 1024),
                        "memory.swap.max": "0", "pids.max": str(policy.tasks_max)}
            seen = {}
            for name in (*expected, "cpu.max"):
                try:
                    seen[name] = Path(cgroup, name).read_text().strip()
                except OSError:
                    seen[name] = "unreadable"
            cpu_ok = False
            parts = seen["cpu.max"].split()
            if len(parts) == 2 and all(part.isascii() and part.isdecimal() for part in parts):
                quota, period = (int(part) for part in parts)
                cpu_ok = period > 0 and 0 < quota <= period
            return (all(seen[name] == value for name, value in expected.items()) and cpu_ok,
                    f"kernel values {seen}; expected memory/pids={expected}, cpu quota <= 1 core",
                    cpu_ok)


def doctor(policy=None):
    """Environment capability checks. Starts no worker mission and no model."""
    policy = policy if policy is not None else Policy()
    checks = []

    def add(name, ok, detail, required=True):
        checks.append(Check(name, required, "OK" if ok else "FAIL", detail))

    add("not_root", os.geteuid() != 0, f"euid={os.geteuid()}; isolation is only meaningful unprivileged")
    if os.geteuid() == 0:
        for name in ("bwrap_binary", "bwrap_flags", "systemd_user_scope", "cgroup_limits",
                     "cpu_limit"):
            checks.append(Check(name, True, "NOT_RUN", "refusing to probe as root"))
        return checks
    code, out, _ = _run([BWRAP, "--version"])
    version = re.match(rb"bubblewrap (\d+\.\d+\.\d+)", out or b"")
    add("bwrap_binary", code == 0 and version is not None,
        version.group(1).decode() if version else "bwrap missing or unreadable")
    code, out, err = _run([BWRAP, "--help"])
    text = (out + err).decode("utf-8", "replace")
    missing = [flag for flag in REQUIRED_FLAGS if flag not in text]
    add("bwrap_flags", code in (0, 1) and not missing, f"missing: {missing}" if missing else "all required flags")
    env = host_env()
    bus_ok = os.path.isdir(env["XDG_RUNTIME_DIR"])
    code, _, _ = _run([SYSTEMD_RUN, "--user", "--scope", "--quiet", "--collect", "--", "/usr/bin/true"], 8.0)
    add("systemd_user_scope", bus_ok and code == 0, "user scope created" if code == 0 else "systemd-run --user --scope failed")
    try:
        ok, detail, cpu_ok = _limits_check(policy)
    except (SandboxError, OSError, ValueError) as err2:
        ok, cpu_ok, detail = False, False, "cgroup verification unavailable"
    add("cgroup_limits", ok, detail)
    add("cpu_limit", cpu_ok, "cpu.max quota verified" if cpu_ok else "CPUQuota not enforced")
    return checks


PROBE_TEMPLATE = """
import json, os, socket
P = json.loads(__PARAMS__)
out = {"attempts": {}}
def attempt(name, fn):
    try:
        out["attempts"][name] = {"blocked": False, "detail": str(fn())[:60]}
    except BaseException as exc:
        out["attempts"][name] = {"blocked": True, "detail": type(exc).__name__}
for i, path in enumerate(P["canaries"]):
    attempt("read_%d" % i, lambda p=path: open(p, "rb").read())
    attempt("write_%d" % i, lambda p=path: open(p, "ab").write(b"X"))
attempt("write_usr", lambda: open("/usr/mitr3_probe", "wb").write(b"X"))
attempt("write_worker", lambda: open("/worker/worker.py", "ab").write(b"X"))
attempt("mkdir_root", lambda: os.mkdir("/mitr3_probe"))
attempt("proc_root_escape", lambda: open("/proc/1/root" + P["canaries"][0], "rb").read())
attempt("nested_userns", lambda: os.unshare(os.CLONE_NEWUSER))
def net():
    s = socket.socket(); s.settimeout(1.0); s.connect(("127.0.0.1", P["port"])); s.send(b"x")
attempt("net_host_loopback", net)
written = [0]
def fill():
    chunk = b"x" * 65536
    with open("/tmp/fill", "wb") as f:
        while written[0] < P["tmp_bytes"] * 4:
            f.write(chunk); f.flush(); written[0] += len(chunk)
attempt("tmp_quota", fill)
out["tmp_written"] = written[0]
status = dict(l.split(":\\t", 1) for l in open("/proc/self/status").read().splitlines() if ":\\t" in l)
out["caps"] = [status["CapPrm"], status["CapEff"], status["CapBnd"], status["NoNewPrivs"]]
out["env"] = sorted(os.environ)
out["root"] = sorted(os.listdir("/"))
out["procs"] = sorted(x for x in os.listdir("/proc") if x.isdigit())
out["ifaces"] = [l.split(":")[0].strip() for l in open("/proc/net/dev").read().split("\\n")[2:] if l]
out["host_sockets"] = [p for p in ("/var/run/docker.sock", "/run/docker.sock", "/run/user/%d/bus" % os.getuid(), "/run/user/%d" % os.getuid()) if os.path.exists(p)]
out["ssh_agent_env"] = "SSH_AUTH_SOCK" in os.environ
print(json.dumps(out))
"""


def _sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def selftest(policy=None):
    """Try to violate each control from inside the sandbox; OK means the OS blocked it."""
    policy = policy if policy is not None else Policy()
    if os.geteuid() == 0:
        return [Check("not_root", True, "FAIL", "selftest refused: running as root")]
    checks = []

    def add(name, ok, detail):
        checks.append(Check(name, True, "OK" if ok else "FAIL", detail))

    base = tempfile.mkdtemp(prefix=".mitr3-canary-", dir=str(Path.home()))
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.setblocking(False)
        canaries, before = [], {}
        for name in ("secret.txt", "repo_module.py", "oracle.json", "trace.json"):
            path = os.path.join(base, name)
            Path(path).write_bytes(("CANARY:" + name).encode())
            canaries.append(path)
            before[path] = _sha(path)
        params = {"canaries": canaries, "port": listener.getsockname()[1], "tmp_bytes": policy.tmp_bytes}
        result = run_probe(PROBE_TEMPLATE.replace("__PARAMS__", repr(json.dumps(params))), policy)
        try:
            report = json.loads(result.stdout.decode("utf-8").strip().splitlines()[-1])
            attempts = report["attempts"]
        except (ValueError, IndexError, KeyError, UnicodeError):
            add("probe_ran", False, f"probe produced no valid report (rc={result.returncode})")
            return checks
        blocked = lambda names: all(attempts[n]["blocked"] for n in names)
        add("sandbox_fs_read", blocked([f"read_{i}" for i in range(len(canaries))]), "host canaries unreadable")
        add("sandbox_fs_write", blocked([f"write_{i}" for i in range(len(canaries))]
                                        + ["write_usr", "write_worker", "mkdir_root"]), "no writes outside /tmp")
        add("sandbox_proc_escape", blocked(["proc_root_escape"]), "no escape via /proc root")
        try:
            listener.accept()
            reached = True
        except BlockingIOError:
            reached = False
        add("sandbox_net", blocked(["net_host_loopback"]) and not reached and report["ifaces"] == ["lo"],
            f"ifaces={report['ifaces']}, host listener reached={reached}")
        add("sandbox_env", set(report["env"]) == ALLOWED_ENV_KEYS, f"env keys={report['env']}")
        add("sandbox_caps", report["caps"][:3] == ["0000000000000000"] * 3 and report["caps"][3] == "1",
            f"CapPrm/Eff/Bnd/NoNewPrivs={report['caps']}")
        add("sandbox_nested_userns", blocked(["nested_userns"]), attempts["nested_userns"]["detail"])
        add("sandbox_tmp_quota", blocked(["tmp_quota"]) and report["tmp_written"] <= policy.tmp_bytes,
            f"wrote {report['tmp_written']} of {policy.tmp_bytes}")
        add("sandbox_root_layout", set(report["root"]) == EXPECTED_ROOT, f"root={report['root']}")
        add("sandbox_host_sockets", not report["host_sockets"] and not report["ssh_agent_env"],
            f"visible={report['host_sockets']}")
        add("sandbox_proc_view", len(report["procs"]) <= 3, f"pids={report['procs']}")
        add("sandbox_canaries_intact", all(_sha(p) == before[p] for p in canaries), "host canaries unchanged")
        add("sandbox_cleanup", result.residual_free and not scope_has_processes(result.unit),
            "no process left in scope")
    finally:
        listener.close()
        shutil.rmtree(base, ignore_errors=True)
    return checks


def main(argv=None):
    """Explicit diagnostics only. No general-purpose command runner or worker mission."""
    import argparse
    parser = argparse.ArgumentParser(description="MITR3 offline Bubblewrap sandbox diagnostics")
    parser.add_argument("command", choices=("doctor", "selftest"))
    args = parser.parse_args(argv)
    try:
        checks = doctor() if args.command == "doctor" else selftest()
        result = {"status": "READY_FOR_REVIEW" if ready(checks) else "BLOCKED",
                  "sandbox_gate": "SELFTEST_OK" if args.command == "selftest" and ready(checks)
                  else "NOT_VERIFIED", "behavioral_gate": "NOT_RUN",
                  "human_approved": False, "promotable": False,
                  **summarize(checks)}
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if ready(checks) else 1
    except (SandboxError, OSError, ValueError, TimeoutError):
        print(json.dumps({"status": "BLOCKED", "sandbox_gate": "NOT_VERIFIED",
                          "behavioral_gate": "NOT_RUN", "human_approved": False,
                          "promotable": False, "error": "sandbox diagnostic failed"}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
