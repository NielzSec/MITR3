"""Preparation checks only: no account creation, service activation or UID migration."""
import importlib.util
import fcntl
import os
import contextlib
import io
import json
from pathlib import Path
import socket
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ENTRY = Path(__file__).resolve().parents[2] / "deploy/query_entry.py"
entry = None
if ENTRY.is_file():
    spec = importlib.util.spec_from_file_location("staged_query_entry", ENTRY)
    entry = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(entry)


@unittest.skipUnless(
    ENTRY.is_file(),
    "hackbots/deploy/query_entry.py is not in this checkout; deployment preparation tests skipped",
)
class DeploymentPreparationTests(unittest.TestCase):
    def test_peer_credentials_reject_same_uid_root_and_wrong_caller(self):
        client, server = socket.socketpair()
        self.addCleanup(client.close)
        self.addCleanup(server.close)
        actual = os.getuid()
        for agent, custodian in ((actual, actual), (0, actual), (True, actual)):
            with self.subTest(agent=agent, custodian=custodian), self.assertRaises(ValueError):
                entry.authenticate_peer(server.fileno(), agent, custodian)
        # Exercise real SO_PEERCRED; only the server identity is simulated here.
        with patch.object(entry.os, "getuid", return_value=actual + 1), \
                patch.object(entry.os, "geteuid", return_value=actual + 1):
            self.assertEqual(entry.authenticate_peer(server.fileno(), actual, actual + 1), actual)
            with self.assertRaises(ValueError):
                entry.authenticate_peer(server.fileno(), actual + 2, actual + 1)

    def test_non_socket_input_rejected_without_leaking_duplicate_fds(self):
        actual = os.getuid()
        r, w = os.pipe()
        self.addCleanup(os.close, r)
        self.addCleanup(os.close, w)
        before = len(os.listdir('/proc/self/fd'))
        with patch.object(entry.os, "getuid", return_value=actual + 1), \
                patch.object(entry.os, "geteuid", return_value=actual + 1):
            for _ in range(10):
                with self.assertRaises(OSError):
                    entry.authenticate_peer(r, actual, actual + 1)
        self.assertEqual(len(os.listdir('/proc/self/fd')), before)

    def test_other_socket_families_and_types_are_rejected(self):
        actual = os.getuid()
        with patch.object(entry.os, 'getuid', return_value=actual+1), \
                patch.object(entry.os, 'geteuid', return_value=actual+1):
            for family, kind in ((socket.AF_UNIX, socket.SOCK_DGRAM),
                                 (socket.AF_UNIX, socket.SOCK_SEQPACKET),
                                 (socket.AF_INET, socket.SOCK_STREAM)):
                with socket.socket(family, kind) as sock, self.subTest(family=family, kind=kind):
                    with self.assertRaises(ValueError):
                        entry.authenticate_peer(sock.fileno(), actual, actual+1)

    def test_root_owned_file_check_rejects_workspace(self):
        with self.assertRaises(ValueError):
            entry.check_root_file(ENTRY)

    def test_uninstalled_launcher_blocks_without_echoing_arguments(self):
        done = subprocess.run([sys.executable, '-I', '-B', str(ENTRY), 'PRIVATE_CANARY'],
                              capture_output=True, timeout=3)
        self.assertEqual(done.returncode, 2)
        self.assertEqual(done.stdout, b'')
        self.assertNotIn(b'PRIVATE_CANARY', done.stderr)

    def test_output_is_bound_to_the_authenticated_connection(self):
        client, server = socket.socketpair()
        other, other_server = socket.socketpair()
        r, w = os.pipe()
        duplicate = os.dup(server.fileno())
        try:
            entry.check_output_channel(server.fileno(), duplicate)
            for fd in (other_server.fileno(), w):
                with self.subTest(fd=fd), self.assertRaises(ValueError):
                    entry.check_output_channel(server.fileno(), fd)
        finally:
            for sock in (client, server, other, other_server):
                sock.close()
            for fd in (r, w, duplicate):
                os.close(fd)

    def test_identity_group_profile_rejects_admin_and_supplementary_groups(self):
        agent = SimpleNamespace(pw_name='mitr3-agent', pw_gid=4001)
        custodian = SimpleNamespace(pw_name='mitr3-custodian', pw_gid=4002)
        groups = {4001: agent.pw_name, 4002: custodian.pw_name}
        with (patch.object(entry.grp, 'getgrgid', side_effect=lambda gid: SimpleNamespace(gr_name=groups[gid])),
              patch.object(entry.os, 'getgrouplist', side_effect=lambda name, gid: [gid]) as nss,
              patch.object(entry.os, 'getgid', return_value=4002),
              patch.object(entry.os, 'getegid', return_value=4002),
              patch.object(entry.os, 'getgroups', return_value=[4002]) as process_groups):
            entry.check_identity_groups(agent, custodian)
            nss.side_effect = lambda name, gid: [gid, 964] if name == agent.pw_name else [gid]
            with self.assertRaises(ValueError):
                entry.check_identity_groups(agent, custodian)
            nss.side_effect = lambda name, gid: [gid]
            process_groups.return_value = [4002, 964]
            with self.assertRaises(ValueError):
                entry.check_identity_groups(agent, custodian)
            process_groups.return_value = [4002]
            groups[4001] = 'docker'
            with self.assertRaises(ValueError):
                entry.check_identity_groups(agent, custodian)

    def test_nnp_and_capabilities_are_checked(self):
        profile = {'NoNewPrivs': '1', **{name: '0000000000000000' for name in
                   ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb')}}
        for changes, allowed in (({}, True), ({'NoNewPrivs': '0'}, False),
                                  ({'CapAmb': '1'}, False), ({'CapBnd': 'not-hex'}, False)):
            text = '\n'.join(f'{k}:\t{v}' for k,v in {**profile, **changes}.items())
            with self.subTest(changes=changes), patch('builtins.open', return_value=io.StringIO(text)):
                if allowed:
                    entry.check_process_profile()
                else:
                    with self.assertRaises(ValueError):
                        entry.check_process_profile()

    def test_inherited_descriptors_closed_in_subprocess(self):
        r, w = os.pipe()
        inherited = fcntl.fcntl(r, fcntl.F_DUPFD_CLOEXEC, 128)
        try:
            script = """import importlib.util, os, resource, sys
s = importlib.util.spec_from_file_location('entry', sys.argv[1])
e = importlib.util.module_from_spec(s)
s.loader.exec_module(e)
soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
resource.setrlimit(resource.RLIMIT_NOFILE, (min(64, soft), hard))
e.close_extra_fds()
try:
    os.fstat(int(sys.argv[2]))
    raise RuntimeError('FD survived')
except OSError:
    pass
"""
            done = subprocess.run([sys.executable, '-I', '-B', '-c', script, str(ENTRY), str(inherited)],
                                  pass_fds=(inherited,), capture_output=True, timeout=3)
            self.assertEqual(done.returncode, 0, done.stderr)
        finally:
            os.close(r)
            os.close(w)
            os.close(inherited)

    def test_peercred_on_separately_accepted_unix_connections(self):
        with tempfile.TemporaryDirectory() as tmp:
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(str(Path(tmp)/'query.sock'))
            listener.listen(2)
            self.addCleanup(listener.close)
            actual = os.getuid()
            with patch.object(entry.os, 'getuid', return_value=actual+1), \
                    patch.object(entry.os, 'geteuid', return_value=actual+1):
                for expected_uid, allowed in ((actual, True), (actual+2, False)):
                    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                        client.connect(listener.getsockname())
                        accepted, _ = listener.accept()
                        with accepted:
                            if allowed:
                                self.assertEqual(entry.authenticate_peer(accepted.fileno(), expected_uid, actual+1), actual)
                            else:
                                with self.assertRaises(ValueError):
                                    entry.authenticate_peer(accepted.fileno(), expected_uid, actual+1)

    def test_unexpected_exception_is_sanitized_even_before_auth(self):
        stderr = io.StringIO()
        with patch.object(entry.secrets, 'token_hex', side_effect=RuntimeError('PRIVATE_CANARY')), \
                contextlib.redirect_stderr(stderr):
            self.assertEqual(entry.main(), 2)
        event = json.loads(stderr.getvalue())
        self.assertEqual(event['event'], 'query_entry_blocked')
        self.assertNotIn('PRIVATE_CANARY', stderr.getvalue())
        self.assertNotIn('Traceback', stderr.getvalue())

    def test_source_only_install_rejects_cached_or_shadow_imports(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            runner = root/'hackbots/runner'; deploy = root/'hackbots/deploy'
            runner.mkdir(parents=True); deploy.mkdir()
            (root/'hackbots/private').mkdir()
            (root/'hackbots/__init__.py').write_text('')
            (deploy/'query_entry.py').write_text('')
            for name in entry.MODULES:
                (runner/name).write_text('')
            # Only ownership checks are simulated; layout checks use actual filesystem entries.
            with (patch.object(entry, 'INSTALL_ROOT', root), patch.object(entry, 'check_root_file'),
                  patch.object(entry.sys, 'modules', {})):
                entry.check_installation()
                for path in (runner/'__pycache__', runner/'query.pyc', root/'hackbots.py'):
                    path.write_text('SYNTHETIC')
                    with self.subTest(path=path), self.assertRaises(ValueError):
                        entry.check_installation()
                    path.unlink()

    def test_checked_files_reject_symlink_hardlink_mode_and_owner(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); target = root/'source.py'; target.write_text('pass')
            real_fstat = os.fstat
            overrides = {}
            def synthetic_root_view(fd):
                info = real_fstat(fd)
                values = {'st_uid': 0, 'st_nlink': info.st_nlink,
                          'st_mode': (stat.S_IFDIR | 0o755) if stat.S_ISDIR(info.st_mode) else info.st_mode}
                values.update(overrides.get(os.readlink(f'/proc/self/fd/{fd}'), {}))
                return SimpleNamespace(**values)
            with patch.object(entry.os, 'fstat', side_effect=synthetic_root_view):
                entry.check_root_file(target)
                for path, changed in ((target, {'st_uid': 1000}),
                                      (target, {'st_mode': stat.S_IFREG | 0o664}),
                                      (root, {'st_uid': 1000}),
                                      (root, {'st_mode': stat.S_IFDIR | 0o775})):
                    overrides[str(path)] = changed
                    with self.subTest(path=path, changed=changed), self.assertRaises(ValueError):
                        entry.check_root_file(target)
                    overrides.clear()
                link=root/'link.py';link.symlink_to(target)
                with self.assertRaises(OSError):
                    entry.check_root_file(link)
                alias=root/'alias';alias.symlink_to(root)
                with self.assertRaises(OSError):
                    entry.check_root_file(alias/'source.py')
                os.link(target, root/'hard.py')
                with self.assertRaises(ValueError):
                    entry.check_root_file(target)
