"""Linux offline launcher. Fail closed; no network-capable fallback."""
import ctypes
import errno
import json
import os
from pathlib import Path
import resource
import signal
import subprocess
import sys
import tempfile


def restrict_worker():
    resource.setrlimit(resource.RLIMIT_AS, (384 * 1024 ** 2,) * 2)
    resource.setrlimit(resource.RLIMIT_CPU, (30, 30))
    resource.setrlimit(resource.RLIMIT_FSIZE, (64 * 1024 ** 2,) * 2)
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    resource.setrlimit(resource.RLIMIT_NPROC, (0, 0))
    lib = ctypes.CDLL("libseccomp.so.2", use_errno=True)
    lib.seccomp_init.argtypes = [ctypes.c_uint32]
    lib.seccomp_init.restype = ctypes.c_void_p
    lib.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    lib.seccomp_syscall_resolve_name.restype = ctypes.c_int
    lib.seccomp_rule_add.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint]
    lib.seccomp_load.argtypes = [ctypes.c_void_p]
    lib.seccomp_release.argtypes = [ctypes.c_void_p]
    ctx = lib.seccomp_init(0x00050000 | errno.EPERM)
    if not ctx:
        raise OSError("seccomp-init-failed")
    try:
        # Native architecture only. All unlisted syscalls/ABIs fail; no socket/exec/clone/io_uring.
        allowed = """read write close fstat newfstatat statx lseek openat readlink readlinkat
        getcwd getdents64 fcntl dup dup2 dup3 access faccessat faccessat2
        mkdir mkdirat chmod fchmod fchmodat fchmodat2 fsync fdatasync
        mmap munmap mprotect brk mremap madvise futex futex_time64
        clock_gettime clock_gettime64 clock_nanosleep clock_nanosleep_time64 nanosleep
        rt_sigaction rt_sigprocmask rt_sigreturn sigaltstack setitimer getitimer
        getpid getppid gettid getuid geteuid getgid getegid getrandom uname
        sched_getaffinity sched_yield restart_syscall exit exit_group""".split()
        for name in allowed:
            number = lib.seccomp_syscall_resolve_name(name.encode())
            if number >= 0 and lib.seccomp_rule_add(ctx, 0x7FFF0000, number, 0) != 0:
                raise OSError("seccomp-rule-failed")
        if lib.seccomp_load(ctx) != 0:
            raise OSError("seccomp-load-failed")
    finally:
        lib.seccomp_release(ctx)


def sandbox_argv(code, helper, inputs, output, worker_args):
    return ["/usr/bin/bwrap", "--unshare-all", "--share-net", "--die-with-parent",
            "--new-session", "--cap-drop", "ALL", "--clearenv",
            "--setenv", "PATH", "/usr/bin", "--setenv", "LANG", "C.UTF-8",
            "--ro-bind", "/usr", "/usr", "--ro-bind", "/lib", "/lib",
            "--ro-bind", "/lib64", "/lib64", "--proc", "/proc", "--remount-ro", "/proc",
            "--dir", "/dev", "--ro-bind", "/dev/null", "/dev/null", "--dir", "/tmp",
            "--dir", "/app", "--dir", "/app/bin", "--dir", "/app/tools",
            "--ro-bind", str(code), "/app/bin/mitr3-js-lab.py",
            "--ro-bind", str(helper), "/app/tools/js_lab_sandbox.py",
            "--ro-bind", str(inputs), "/input", "--bind", str(output), "/output",
            "--remount-ro", "/", "--chdir", "/app",
            "/usr/bin/python3", "-I", "-S", "-B", "/app/bin/mitr3-js-lab.py",
            "--offline-worker", *worker_args]


def launch(core, argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] == ["--offline-worker"]:
        if Path(core.__file__).resolve() != Path("/app/bin/mitr3-js-lab.py"):
            print('{"status":"BLOCKED","reason":"worker-requires-sandbox"}')
            return 2
        try:
            restrict_worker()
        except (OSError, ValueError):
            print('{"status":"BLOCKED","reason":"offline-guard-unavailable"}')
            return 2
        return core.main(argv[1:])
    args = core.arguments(argv)
    if args.command == "verify":
        try:
            core.verify_package(args.evidence)
            print('{"status":"PASS","verification":"package-integrity-only"}')
            return 0
        except (OSError, core.LabError, ValueError, UnicodeError):
            print('{"status":"FAIL","reason":"package-integrity-failure"}')
            return 2
    if args.command == "collect":
        print('{"status":"BLOCKED","reason":"independent-egress-not-certified"}')
        return 2
    process = None
    try:
        policy_raw = core.read_local(args.scope, core.MIB)
        policy = core.Scope(policy_raw)
        har_raw = core.read_local(Path(args.har), 64 * core.MIB)
        # Scope inputs and output ancestors cannot be symbolic links.
        for selected in (args.scope.absolute(), Path(args.har).absolute(), args.out.absolute().parent):
            if any(p.is_symlink() for p in (selected, *selected.parents)):
                raise OSError("symlink-path-denied")
        args.out.mkdir(mode=0o700, exist_ok=False)
        with tempfile.TemporaryDirectory(prefix="mitr3-js-input-") as tmp:
            inputs = Path(tmp)
            for name, data in (("scope.json", policy_raw), ("capture.har", har_raw)):
                (inputs / name).write_bytes(data)
                (inputs / name).chmod(0o400)
            worker_args = ["import-har", "/input/capture.har", "--scope", "/input/scope.json",
                           "--out", "/output/evidence"] + (["--maps"] if args.maps else [])
            command = sandbox_argv(Path(core.__file__).resolve(), Path(__file__).resolve(), inputs,
                                   args.out.resolve(), worker_args)
            with tempfile.TemporaryFile() as output_stream, tempfile.TemporaryFile() as error_stream:
                process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=output_stream,
                                           stderr=error_stream, close_fds=True, start_new_session=True,
                                           env={"PATH": "/usr/bin", "LANG": "C.UTF-8"})
                try:
                    process.wait(timeout=policy.limits["max_seconds"] + 5)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
                    print('{"status":"FAIL","reason":"supervisor-timeout"}')
                    return 2
                output_stream.seek(0)
                stdout = output_stream.read(4097)
                if len(stdout) > 4096:
                    raise core.LabError("worker-output-quota")
        if process.returncode not in (0, 1):
            print('{"status":"BLOCKED","reason":"sandbox-or-worker-failure"}')
            return 2
        result = core.verify_package(args.out / "evidence", expected_scope=policy,
                                     expected_har_sha256=core.digest(har_raw), expected_maps=args.maps)
        if (process.returncode == 0) != (result["status"] == "complete-within-v0.2-limits"):
            raise core.LabError("worker-status-mismatch")
        print(json.dumps({"status": result["status"], "artifacts": len(result["artifacts"]),
                          "gaps": len(result["gaps"]), "isolation": "bwrap+seccomp-offline"}))
        return process.returncode
    except (OSError, core.LabError, ValueError, UnicodeError, MemoryError):
        print('{"status":"FAIL","reason":"launch-or-integrity-failure"}')
        return 2
