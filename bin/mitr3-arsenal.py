#!/usr/bin/env python3
"""Install and inspect MITR3 phases 2/3; check never starts scans or login flows."""
import argparse
import datetime as dt
import json
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
TOOLS = Path.home() / 'Tools'
BIN = Path.home() / '.local/bin'
ENV = dict(os.environ, PATH=str(BIN) + os.pathsep + os.environ.get('PATH', ''),
           AWS_EC2_METADATA_DISABLED='true', AZURE_CORE_COLLECT_TELEMETRY='false',
           CLOUDSDK_CORE_DISABLE_USAGE_REPORTING='true', PIP_DISABLE_PIP_VERSION_CHECK='1')

# package = official Arch repo candidate; fallback is used only if it is absent.
REGISTRY = {
    'impacket': dict(phase=2, commands=['impacket-smbclient', 'smbclient.py'], package='impacket',
                     pip='impacket', probe=['-h'], source='https://github.com/fortra/impacket'),
    'bloodhound-python': dict(phase=2, commands=['bloodhound-python'], package='bloodhound-python',
                              pip='bloodhound', probe=['--version'], source='https://github.com/dirkjanm/BloodHound.py'),
    'kerbrute': dict(phase=2, commands=['kerbrute'], package='kerbrute',
                     go='github.com/ropnop/kerbrute@latest', probe=['version'], source='https://github.com/ropnop/kerbrute'),
    'responder': dict(phase=2, commands=['responder', 'Responder.py'], package='responder',
                      repo='https://github.com/lgandx/Responder.git', probe=['--version'],
                      source='https://github.com/lgandx/Responder'),
    'aws': dict(phase=3, commands=['aws'], package='aws-cli-v2', probe=['--version'],
                source='https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html'),
    'gcloud': dict(phase=3, commands=['gcloud'], package='google-cloud-cli', archive=True,
                   probe=['--version'], source='https://docs.cloud.google.com/sdk/docs/install-sdk'),
    'az': dict(phase=3, commands=['az'], package='azure-cli', pip='azure-cli', probe=['--version'],
               source='https://learn.microsoft.com/cli/azure/install-azure-cli-linux'),
    'prowler': dict(phase=3, commands=['prowler'], package='prowler', pip='prowler', probe=['--version'],
                    source='https://github.com/prowler-cloud/prowler'),
    'scoutsuite': dict(phase=3, commands=['scout'], package='scoutsuite', pip='ScoutSuite', probe=['--version'],
                       source='https://github.com/nccgroup/ScoutSuite'),
    'cloudfox': dict(phase=3, commands=['cloudfox'], package='cloudfox',
                     go='github.com/BishopFox/cloudfox@latest', probe=['--version'],
                     source='https://github.com/BishopFox/cloudfox'),
    'pacu': dict(phase=3, commands=['pacu'], package='pacu', pip='pacu', probe=['--version'],
                 source='https://github.com/RhinoSecurityLabs/pacu'),
    'trufflehog': dict(phase=3, commands=['trufflehog'], package='trufflehog',
                       go='github.com/trufflesecurity/trufflehog/v3@latest', probe=['--version'],
                       source='https://github.com/trufflesecurity/trufflehog'),
}


def clean(text):
    text = re.sub(r'\x1b\[[0-9;]*m', '', text)
    return re.sub(r'(https?://)[^/\s@]+:[^/\s@]+@', r'\1<redacted>@', text)


def execute(argv, timeout=20, cwd=None, env=None):
    """Bound the whole child process group, including Go/pip descendants."""
    try:
        p = subprocess.Popen([str(x) for x in argv], cwd=cwd, env=env or ENV,
                             stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             text=True, start_new_session=True)
    except OSError as exc:
        return 127, str(exc)
    try:
        out, _ = p.communicate(timeout=timeout)
        return p.returncode, clean(out)
    except subprocess.TimeoutExpired:
        os.killpg(p.pid, signal.SIGKILL)
        out, _ = p.communicate()
        return 124, clean(out) + '\nTimed out.'


def locate(cfg):
    return next((p for cmd in cfg['commands'] if (p := shutil.which(cmd, path=ENV['PATH']))), None)


def version_from(text):
    match = re.search(r'(?<![\d.])v?(\d+\.\d+(?:\.\d+)?(?:[-+][\w.]+)?)', text)
    return match.group(1) if match else None


def metadata_version(name, cfg, executable):
    if not cfg.get('pip'):
        return None
    interpreter = TOOLS / name / '.venv/bin/python'
    if not interpreter.is_file():
        interpreter = Path(sys.executable)
        try:
            first = Path(executable).read_bytes()[:300].splitlines()[0].decode()
            if first.startswith('#!') and 'python' in first and Path(first[2:].strip()).is_file():
                interpreter = Path(first[2:].strip())
        except (OSError, UnicodeError, IndexError):
            pass
    code, output = execute([interpreter, '-c',
                            'import importlib.metadata,sys; print(importlib.metadata.version(sys.argv[1]))',
                            cfg['pip']])
    return output.strip() if code == 0 else None


def check(name):
    cfg = REGISTRY[name]
    path = locate(cfg)
    row = dict(name=name, phase=cfg['phase'], command=path, source=cfg['source'],
               status='missing', version=None, evidence='command -v: absent')
    if not path:
        return row
    flags = cfg['probe']
    code, output = execute([path, *flags])
    version = metadata_version(name, cfg, path) or version_from(output)
    if code != 0:
        # Some tools (BloodHound/Pacu) have no version flag. Help is the safe fallback.
        flags = ['--help']
        code, output = execute([path, *flags])
    row.update(status=('validated' if version else 'smoke_ok') if code == 0 else 'failed',
               version=version, probe=[path, *flags], exit_code=code,
               evidence=output.strip()[:1600])
    return row


def alias(name, target, cwd=None, interpreter=None):
    """Only expose an existing backend; never overwrite another program."""
    target = Path(target).absolute()
    if (not target.is_file() or (not interpreter and not os.access(target, os.X_OK))
            or (interpreter and not os.access(interpreter, os.X_OK))):
        return False
    BIN.mkdir(parents=True, exist_ok=True)
    link = BIN / name
    content = '#!/usr/bin/env bash\n# Managed by mitr3-arsenal.py\nset -euo pipefail\n'
    if cwd:
        content += f'cd {shlex.quote(str(cwd))}\n'
    command = ([str(interpreter)] if interpreter else []) + [str(target)]
    content += 'exec ' + shlex.join(command) + ' "$@"\n'
    if link.exists() or link.is_symlink():
        try:
            if link.read_text() != content:
                return False
        except (OSError, UnicodeError):
            return False
        return True
    link.write_text(content)
    link.chmod(0o755)
    return True


def expose(name):
    cfg = REGISTRY[name]
    base = TOOLS / name
    target = base / '.venv/bin' / cfg['commands'][0]
    if cfg.get('go'):
        target = base / 'bin' / cfg['commands'][0]
    if cfg.get('archive'):
        target = base / 'google-cloud-sdk/bin/gcloud'
    if cfg.get('repo'):
        return [cfg['commands'][0]] if alias('responder', base / 'src/Responder.py',
                                            base / 'src', base / '.venv/bin/python') else []
    exposed = [cfg['commands'][0]] if alias(cfg['commands'][0], target) else []
    if name == 'impacket':
        for stem in ('smbclient', 'secretsdump', 'wmiexec', 'psexec', 'GetNPUsers', 'ntlmrelayx'):
            backend = shutil.which(stem + '.py', path=ENV['PATH'])
            if not backend:
                backend = base / '.venv/bin' / (stem + '.py')
            if alias('impacket-' + stem, backend):
                exposed.append('impacket-' + stem)
    return list(dict.fromkeys(exposed))


def install(name, logdir):
    cfg = REGISTRY[name]
    row = check(name)
    if row['status'] in ('validated', 'smoke_ok'):
        row.update(install='already present', wrappers=expose(name))
        return row
    base = TOOLS / name
    log = []

    def step(argv, cwd=None, env=None, timeout=900):
        code, out = execute(argv, timeout, cwd, env)
        log.append('$ ' + shlex.join([str(x) for x in argv]) + '\n' + out)
        if code:
            raise RuntimeError(f'exit {code}: ' + out.strip()[-800:])

    try:
        code, _ = execute(['pacman', '-Si', cfg['package']])
        if code == 0:
            step(['sudo', '-n', 'pacman', '-S', '--needed', '--noconfirm', cfg['package']])
        elif cfg.get('go'):
            (base / 'bin').mkdir(parents=True, exist_ok=True)
            step(['go', 'install', cfg['go']], env=dict(ENV, GOBIN=str(base / 'bin')))
        elif cfg.get('pip') or cfg.get('repo'):
            base.mkdir(parents=True, exist_ok=True)
            interpreter = os.environ.get('MITR3_PYTHON', sys.executable)
            if not (base / '.venv/bin/python').is_file():
                step([interpreter, '-m', 'venv', str(base / '.venv')])
            pip = [base / '.venv/bin/python', '-m', 'pip', '--isolated', 'install',
                   '--index-url', 'https://pypi.org/simple', '--retries', '0', '--timeout', '10']
            if cfg.get('repo'):
                src = base / 'src'
                if not src.exists():
                    step(['git', 'clone', '--depth', '1', cfg['repo'], src])
                else:
                    code, remote = execute(['git', '-C', src, 'remote', 'get-url', 'origin'])
                    if code or remote.strip() != cfg['repo']:
                        raise RuntimeError('existing source directory is not the configured upstream')
                step([*pip, '-r', src / 'requirements.txt'])
            else:
                step([*pip, cfg['pip']])
        elif cfg.get('archive'):
            arch = {'x86_64': 'x86_64', 'aarch64': 'arm'}.get(platform.machine())
            if not arch:
                raise RuntimeError('unsupported gcloud architecture')
            base.mkdir(parents=True, exist_ok=True)
            if not (base / 'google-cloud-sdk/bin/gcloud').is_file():
                with tempfile.TemporaryDirectory(dir=base) as tmp:
                    archive = Path(tmp) / 'gcloud.tar.gz'
                    url = f'https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/google-cloud-cli-linux-{arch}.tar.gz'
                    step(['curl', '--fail', '--location', '--connect-timeout', '10',
                          '--max-time', '300', '--output', archive, url])
                    with tarfile.open(archive) as tar:
                        tar.extractall(tmp, filter='data')
                    destination = base / 'google-cloud-sdk'
                    if destination.exists():
                        raise RuntimeError('incomplete SDK directory exists; inspect before replacing')
                    shutil.move(str(Path(tmp) / 'google-cloud-sdk'), destination)
        else:
            raise RuntimeError('official Arch package unavailable; no fallback configured')
        wrappers = expose(name)
        row = check(name)
        row.update(install='completed', wrappers=wrappers)
    except (RuntimeError, OSError, tarfile.TarError) as exc:
        row = check(name)
        row.update(install='failed', install_error=clean(str(exc)), wrappers=[])
    logpath = logdir / f'{name}.log'
    logpath.write_text('\n'.join(log))
    logpath.chmod(0o600)
    row['install_log'] = str(logpath)
    return row


def selected(selector):
    if selector in ('all', 'phase2', 'phase3'):
        return [name for name, cfg in REGISTRY.items()
                if selector == 'all' or cfg['phase'] == int(selector[-1])]
    if selector not in REGISTRY:
        raise ValueError('unknown tool: ' + selector)
    return [selector]


def document(rows):
    path = ROOT / 'docs/ARSENAL.md'
    start, end = '<!-- MITR3_PHASE23_STATUS_START -->', '<!-- MITR3_PHASE23_STATUS_END -->'
    body = [start, '### Validação automatizada das Fases 2/3', '',
            f'Atualizado: {dt.datetime.now(dt.timezone.utc).isoformat()}. Comandos de versão/ajuda apenas; sem login ou coleta.', '',
            '| Ferramenta | Fase | Status | Versão | Evidência |', '|---|---|---|---|---|']
    for row in rows:
        status = {'validated': 'instalado/validado', 'smoke_ok': 'smoke OK; versão pendente',
                  'missing': 'ausente', 'failed': 'falhou'}.get(row['status'], row['status'])
        if row.get('install_error'):
            status += '; instalação bloqueada/falhou'
        evidence = ('`' + str(row['command']) + '`; ' + shlex.join(row.get('probe', []))) if row['command'] else 'command -v: ausente'
        if row.get('install_log'):
            evidence += '; log: `' + row['install_log'] + '`'
        body.append(f"| [{row['name']}]({row['source']}) | {row['phase']} | {status} | {row['version'] or '—'} | {evidence} |")
    body += ['', 'Relatório detalhado: `reports/arsenal-phase23-latest.json`.', end]
    text = path.read_text()
    if start in text and end in text:
        text = text[:text.index(start)] + '\n'.join(body) + text[text.index(end) + len(end):]
    else:
        anchor = '## Fase 4'
        pos = text.index(anchor)
        text = text[:pos] + '\n'.join(body) + '\n\n' + text[pos:]
    path.write_text(text)


def main():
    # Parse dispatch before argparse so tool flags (--help, --json, etc.) remain intact.
    if sys.argv[1:2] == ['run']:
        if len(sys.argv) < 3 or sys.argv[2] not in REGISTRY:
            sys.exit('run requires one registered tool name')
        name = sys.argv[2]
        path = locate(REGISTRY[name])
        if not path:
            sys.exit(f'{name} is not installed; use: mitr3-arsenal.sh install {name}')
        extra = sys.argv[3:]
        if extra[:1] == ['--']:
            extra = extra[1:]
        os.execve(path, [path, *extra], ENV)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['check', 'install', 'run'])
    parser.add_argument('selector', nargs='?', default='all')
    parser.add_argument('--json', action='store_true')
    parser.add_argument('--update-docs', action='store_true')
    args, extra = parser.parse_known_args()
    try:
        names = selected(args.selector)
    except ValueError as exc:
        parser.error(str(exc))
    if extra:
        parser.error('unrecognized arguments: ' + ' '.join(extra))
    if args.update_docs and args.selector != 'all':
        parser.error('--update-docs requires all to preserve the complete table')
    now = dt.datetime.now(dt.timezone.utc)
    logdir = ROOT / 'reports' / ('arsenal-install-' + now.strftime('%Y%m%dT%H%M%S%fZ'))
    if args.action == 'install':
        logdir.mkdir(parents=True, mode=0o700)
        rows = []
        for name in names:
            print(f'Installing/checking {name}…', file=sys.stderr, flush=True)
            rows.append(install(name, logdir))
    else:
        rows = [check(name) for name in names]
    report = dict(timestamp=now.isoformat(), action=args.action, selector=args.selector, tools=rows)
    path = ROOT / 'reports/arsenal-phase23-latest.json'
    path.parent.mkdir(parents=True, exist_ok=True)
    # A phase-specific check must not erase the complete health snapshot.
    if args.selector != 'all':
        path = path.with_name(f'arsenal-{args.selector}-latest.json')
    fd = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(report, stream, indent=2, ensure_ascii=False)
        stream.write('\n')
    if args.update_docs:
        document(rows)
    if args.json:
        print(json.dumps(report, ensure_ascii=False))
    else:
        print(f'{"TOOL":<20} {"PHASE":<6} {"STATUS":<12} {"VERSION":<18} COMMAND')
        for row in rows:
            print(f"{row['name']:<20} {row['phase']:<6} {row['status']:<12} {(row['version'] or '—'):<18} {row['command'] or '—'}")
            if row.get('install_error'):
                print('  ' + row['install_error'].splitlines()[0][:180])
        print('Report:', path)
    return int(any(r['status'] not in ('validated', 'smoke_ok') or r.get('install') == 'failed' for r in rows))


if __name__ == '__main__':
    sys.exit(main())
