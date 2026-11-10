#!/usr/bin/env bash
# Diagnose configured OpenCode MCP servers. No credentials or raw server output are saved.
set -euo pipefail
exec python3 - "$@" <<'PY'
import datetime as dt
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

config_path = Path.home() / '.config/opencode/opencode.json'
report_dir = Path.home() / 'MITR3/reports'
report_path = report_dir / 'mcp-check-latest.json'
json_only = sys.argv[1:] == ['--json']
if sys.argv[1:] and not json_only:
    sys.exit('usage: mitr3-mcp-check.sh [--json]')

def cli_status():
    try:
        result = subprocess.run(['opencode', 'mcp', 'list'], capture_output=True,
                                text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return '', f'unavailable ({type(exc).__name__})'
    if result.returncode:
        message = result.stderr + result.stdout
        if 'EPERM' in message or 'operation not permitted' in message:
            return '', 'unavailable (OpenCode cannot bind in this environment)'
        return '', f'unavailable (exit {result.returncode})'
    return re.sub(r'\x1b\[[0-9;]*m', '', result.stdout), None

def process_alive(command):
    # Inspect argv directly; never match the diagnostic shell's command string.
    needle = next((x for x in command[1:] if '/' in x or '-mcp@' in x or 'rea-agents@' in x), None)
    if not needle:
        return False
    for proc in Path('/proc').iterdir():
        if not proc.name.isdigit() or int(proc.name) == os.getpid():
            continue
        try:
            args = (proc / 'cmdline').read_bytes().split(b'\0')
            decoded = [x.decode(errors='replace') for x in args if x]
            if needle in decoded:
                return True
        except (OSError, PermissionError):
            continue
    return False

def boot_local(cfg):
    command = cfg.get('command')
    if not isinstance(command, list) or not command or not all(isinstance(x, str) for x in command):
        return 'fail', 'invalid command'
    cwd = Path(cfg.get('cwd') or Path.home()).expanduser()
    if not cwd.is_dir():
        return 'fail', 'cwd missing'
    env = os.environ.copy()
    env.update({str(k): str(v) for k, v in cfg.get('environment', {}).items()})
    env['PATH'] = str(Path.home() / '.local/bin') + os.pathsep + env.get('PATH', '')
    with tempfile.TemporaryFile() as err:
        try:
            process = subprocess.Popen(command, cwd=cwd, env=env,
                                       stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                                       stderr=err, start_new_session=True)
        except (OSError, ValueError) as exc:
            return 'fail', f'launch error ({type(exc).__name__})'
        try:
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                code = process.poll()
                if code is not None:
                    err.seek(0)
                    detail = err.read(16384).decode(errors='replace')
                    if 'EPERM' in detail or 'operation not permitted' in detail:
                        return 'fail', f'exit {code} (sandbox permission denied)'
                    return 'fail', f'exit {code} before 5s'
                time.sleep(0.1)
            return 'pass', 'alive after 5s'
        finally:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
            if process.stdin:
                process.stdin.close()

def boot_remote(cfg):
    url = cfg.get('url')
    if not isinstance(url, str) or not url.startswith(('https://', 'http://')):
        return 'fail', 'invalid URL'
    try:
        with urllib.request.urlopen(urllib.request.Request(url, method='GET'), timeout=5) as response:
            code = response.status
    except urllib.error.HTTPError as exc:
        code = exc.code
    except Exception as exc:
        return 'fail', f'connection failed ({type(exc).__name__})'
    return ('pass', f'HTTP {code}') if code < 500 else ('fail', f'HTTP {code}')

def known_issues(name, cfg):
    issues = []
    command = cfg.get('command') or []
    if name == 'mitr3-nexus':
        workspace = cfg.get('environment', {}).get('MITR3_WORKSPACE', 'default_case')
        root = Path.home() / '.local/share/mitr3-nexus/workspaces'
        if not isinstance(workspace, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]*', workspace):
            issues.append('nexus workspace name invalid')
        elif not (root / workspace).is_dir():
            issues.append(f'nexus workspace missing: {root / workspace}')
    if name == 'apisec-ng':
        launcher = next((Path(x) for x in command if x.endswith('launch_apisec_mcp.py')), None)
        if launcher is None or not launcher.is_file():
            issues.append('apisec launcher missing')
        else:
            try:
                source = launcher.read_text()
                if 'secbolt:' not in source or 'os.execve' not in source:
                    issues.append('apisec launcher lacks token prefix handling or exec')
            except OSError:
                issues.append('apisec launcher unreadable')
    if name == 'chrome-devtools':
        try:
            i = command.index('--executablePath')
            browser = command[i + 1]
        except (ValueError, IndexError):
            issues.append('chrome-devtools browser path missing')
        else:
            if not Path(browser).is_file() or not os.access(browser, os.X_OK):
                issues.append(f'chrome-devtools browser not executable: {browser}')
    return issues

try:
    config = json.loads(config_path.read_text())
    servers = config['mcp']['servers']
    if not isinstance(servers, dict):
        raise ValueError('mcp.servers must be an object')
except (OSError, ValueError, KeyError) as exc:
    sys.exit(f'cannot read {config_path}: {type(exc).__name__}: {exc}')

listing, listing_error = cli_status()
rows = []
for name, cfg in servers.items():
    kind = cfg.get('type', 'local')
    match = re.search(r'(?m)^.*\b' + re.escape(name) + r'\b.*$', listing)
    if listing_error:
        status = listing_error
    elif not match:
        status = 'not listed'
    else:
        line = match.group(0).lower()
        status = next((word for word in ('connected', 'failed', 'disabled', 'disconnected') if word in line), 'listed')
    if kind == 'local':
        live = process_alive(cfg.get('command') or [])
        boot, detail = boot_local(cfg)
    elif kind == 'remote':
        live = None
        boot, detail = boot_remote(cfg)
    else:
        live = None
        boot, detail = 'fail', f'unknown type: {kind}'
    rows.append({'name': name, 'type': kind, 'opencode': status,
                 'process_alive': live, 'boot': boot, 'boot_detail': detail,
                 'issues': known_issues(name, cfg)})

report = {'timestamp': dt.datetime.now(dt.timezone.utc).isoformat(),
          'config': str(config_path), 'opencode_list_error': listing_error,
          'servers': rows}
report_dir.mkdir(parents=True, exist_ok=True)
report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + '\n')
os.chmod(report_path, 0o600)
if json_only:
    print(json.dumps(report, ensure_ascii=False))
else:
    print(f'MITR3 MCP check — {len(rows)} configured — {report_path}')
    print(f'{"SERVER":<18} {"TYPE":<7} {"OPENCODE":<49} {"PROCESS":<8} BOOT')
    for row in rows:
        live = 'n/a' if row['process_alive'] is None else ('yes' if row['process_alive'] else 'no')
        print(f"{row['name']:<18} {row['type']:<7} {row['opencode']:<49} {live:<8} {row['boot']} ({row['boot_detail']})")
        for issue in row['issues']:
            print(f'  ! {issue}')
PY
