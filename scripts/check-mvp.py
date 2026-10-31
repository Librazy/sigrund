#!/usr/bin/python3
"""Run unprivileged Phase 6 build/regression checks and retain their evidence."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import traceback

REPO = Path(__file__).resolve().parent.parent


def source_digest():
    files = [REPO / 'Cargo.toml', REPO / 'Cargo.lock']
    for name in ('crates', 'scripts', 'config', 'packaging'):
        files.extend(p for p in (REPO / name).rglob('*') if p.is_file() and '__pycache__' not in p.parts)
    digest = hashlib.sha256()
    for path in sorted(files):
        digest.update(str(path.relative_to(REPO)).encode() + b'\0' + path.read_bytes() + b'\0')
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifacts', type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() == 0:
        parser.error('run the build/regression checks as an unprivileged workspace user')
    args.artifacts.mkdir(parents=True, exist_ok=False)
    manifest = {'result': 'incomplete', 'kernel': platform.release(), 'source_sha256': source_digest(), 'checks': []}
    def save():
        (args.artifacts / 'checks.json').write_text(json.dumps(manifest, indent=2) + '\n')
    save()
    checks = [
        ('build', ['cargo', 'build', '--workspace', '--locked']),
        ('tests', ['cargo', 'test', '--workspace', '--locked', '--', '--test-threads=1']),
        ('clippy', ['cargo', 'clippy', '--workspace', '--all-targets', '--locked', '--', '-D', 'warnings']),
        ('format', ['cargo', 'fmt', '--all', '--', '--check']),
        ('diff', ['git', 'diff', '--check']),
        ('python', [sys.executable, '-c', "from pathlib import Path; [compile(p.read_bytes(), str(p), 'exec') for p in Path('scripts').glob('*.py')]"]),
        ('harness-tests', [sys.executable, '-m', 'unittest', 'discover', '-s', 'scripts/tests', '-v']),
        ('platform-build', ['cargo', 'test', '-p', 'sigrund', '--test', 'phase5_platform', '--locked', '--no-run', '--message-format=json']),
    ]
    try:
        for name, command in checks:
            print('Checking ' + name, flush=True)
            with open(args.artifacts / (name + '.log'), 'wb') as log:
                result = subprocess.run(command, cwd=REPO, stdout=log, stderr=subprocess.STDOUT)
            manifest['checks'].append({'name': name, 'command': command, 'exit': result.returncode, 'log': name + '.log'})
            save()
            if result.returncode:
                raise RuntimeError(name + ' failed; inspect ' + str(args.artifacts / (name + '.log')))
        for line in (args.artifacts / 'platform-build.log').read_text().splitlines():
            if line.startswith('{'):
                value = json.loads(line)
                if value.get('reason') == 'compiler-artifact' and value['target']['name'] == 'phase5_platform' and value.get('executable'):
                    manifest['platform_binary'] = value['executable']
        if 'platform_binary' not in manifest:
            raise RuntimeError('Cargo did not report the phase5_platform executable')
        if source_digest() != manifest['source_sha256']:
            raise RuntimeError('source changed during verification; repeat against a stable snapshot')
        manifest['binaries'] = {name: hashlib.sha256((REPO / 'target/debug' / name).read_bytes()).hexdigest()
                                for name in ('sigrund', 'sigrun', 'sigrundctl', 'sigrund-approve')}
        manifest['result'] = 'passed'
        print('Checks passed: ' + str(args.artifacts / 'checks.json'), flush=True)
    except BaseException:
        manifest['result'] = 'failed'
        manifest['error'] = traceback.format_exc()
        raise
    finally:
        save()


if __name__ == '__main__':
    main()
