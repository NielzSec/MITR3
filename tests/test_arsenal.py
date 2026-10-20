import importlib.util
import os
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / 'bin/mitr3-arsenal.py'
spec = importlib.util.spec_from_file_location('arsenal', SCRIPT)
arsenal = importlib.util.module_from_spec(spec)
spec.loader.exec_module(arsenal)


class ArsenalTests(unittest.TestCase):
    def test_alias_requires_backend_and_preserves_existing_program(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / 'backend'
            with patch.object(arsenal, 'BIN', root / 'bin'):
                self.assertFalse(arsenal.alias('tool', target))
                target.write_text('#!/bin/sh\nexit 0\n')
                target.chmod(0o755)
                self.assertTrue(arsenal.alias('tool', target))
                installed = root / 'bin/tool'
                installed.write_text('existing program')
                self.assertFalse(arsenal.alias('tool', target))
                self.assertEqual(installed.read_text(), 'existing program')

    def test_check_only_invokes_version_command(self):
        with patch.object(arsenal, 'locate', return_value='/fake/aws'), \
                patch.object(arsenal, 'execute', return_value=(0, 'aws-cli/2.37.9 Python/3.14')) as run:
            row = arsenal.check('aws')
            self.assertEqual(row['version'], '2.37.9')
            self.assertEqual(row['status'], 'validated')
            run.assert_called_once_with(['/fake/aws', '--version'])

    def test_official_package_privilege_failure_does_not_fall_back_to_pip(self):
        calls = []
        def run(argv, *args, **kwargs):
            calls.append([str(x) for x in argv])
            if argv[:2] == ['pacman', '-Si']:
                return 0, 'package available'
            return 1, 'sudo: no new privileges'
        with tempfile.TemporaryDirectory() as tmp, \
                patch.object(arsenal, 'check', return_value=dict(status='missing')), \
                patch.object(arsenal, 'execute', side_effect=run):
            row = arsenal.install('az', Path(tmp))
        self.assertEqual(row['install'], 'failed')
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[1][:3], ['sudo', '-n', 'pacman'])

    def test_run_forwards_flags_and_space_containing_arguments(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake = Path(tmp) / 'aws'
            fake.write_text('#!/bin/sh\nprintf "<%s>\\n" "$@"\n')
            fake.chmod(0o755)
            env = dict(os.environ, PATH=tmp, HOME=tmp)
            result = subprocess.run([sys.executable, str(SCRIPT), 'run', 'aws',
                                     '--help', '--json', 'two words'], env=env,
                                    text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.splitlines(), ['<--help>', '<--json>', '<two words>'])

    def test_health_json_includes_cloud_commands_without_network(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            fakebin = home / '.local/bin'
            fakebin.mkdir(parents=True)
            for name in ['sudo', 'docker', 'curl', 'systemctl', 'aws']:
                path = fakebin / name
                path.write_text('#!/bin/sh\nexit 1\n')
                path.chmod(0o755)
            mcp = home / 'MITR3/bin/mitr3-mcp-check.sh'
            mcp.parent.mkdir(parents=True)
            mcp.write_text('#!/bin/sh\necho \'{"servers":[]}\'\n')
            mcp.chmod(0o755)
            env = dict(os.environ, HOME=tmp)
            result = subprocess.run(['bash', str(SCRIPT.with_name('mitr3-health.sh')), '--json'],
                                    env=env, text=True, capture_output=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)
            self.assertIn('aws', report['ok'])
            self.assertEqual(report['mcp'], {'servers': []})


if __name__ == '__main__':
    unittest.main()
