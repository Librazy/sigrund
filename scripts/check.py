#!/usr/bin/python3
"""Run unprivileged build and regression checks with temporary run artifacts."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import traceback

REPO = Path(__file__).resolve().parent.parent


def source_digest():
    files = [REPO / 'Cargo.toml', REPO / 'Cargo.lock', REPO / 'rust-toolchain.toml']
    for name in ('crates', 'scripts', 'config', 'packaging'):
        files.extend(p for p in (REPO / name).rglob('*') if p.is_file() and '__pycache__' not in p.parts)
    digest = hashlib.sha256()
    for path in sorted(files):
        digest.update(str(path.relative_to(REPO)).encode() + b'\0' + path.read_bytes() + b'\0')
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--release', action='store_true', help='build and test the release profile')
    parser.add_argument('--strip-binaries', action='store_true', help='stage stripped release binaries for package/host acceptance')
    parser.add_argument('--rpm-binaries', action='store_true', help='also apply RPM comment/nonallocated-note stripping')
    args = parser.parse_args()
    if args.rpm_binaries:
        args.strip_binaries = True
    if args.strip_binaries and not args.release:
        parser.error('--strip-binaries requires --release')
    if os.geteuid() == 0:
        parser.error('run the build/regression checks as an unprivileged workspace user')
    args.artifacts.mkdir(parents=True, exist_ok=False)
    manifest = {'result': 'incomplete', 'kernel': platform.release(), 'source_sha256': source_digest(),
                'rustc': subprocess.check_output(['rustc', '--version'], text=True).strip(),
                'cargo': subprocess.check_output(['cargo', '--version'], text=True).strip(), 'checks': []}
    def save():
        (args.artifacts / 'checks.json').write_text(json.dumps(manifest, indent=2) + '\n')
    save()
    profile = ['--release'] if args.release else []
    checks = [
        ('build', ['cargo', 'build', '--workspace', *profile, '--locked']),
        ('tests', ['cargo', 'test', '--workspace', *profile, '--locked', '--', '--test-threads=1']),
        ('clippy', ['cargo', 'clippy', '--workspace', '--all-targets', *profile, '--locked', '--', '-D', 'warnings']),
        ('format', ['cargo', 'fmt', '--all', '--', '--check']),
        ('diff', ['git', 'diff', '--check']),
        ('python', [sys.executable, '-c', "from pathlib import Path; [compile(p.read_bytes(), str(p), 'exec') for p in Path('scripts').rglob('*.py')]"]),
        ('harness-tests', [sys.executable, '-m', 'unittest', 'discover', '-s', 'scripts/tests', '-v']),
        ('host-vectors', [sys.executable, 'scripts/verify-host-vectors.py']),
        ('namespace-vectors', [sys.executable, 'scripts/namespace-phase0/verify-vectors.py']),
        ('privileged-build', ['cargo', 'test', '-p', 'sigrund', '--lib', '--test', 'daemon', '--test', 'client', *profile, '--locked', '--no-run', '--message-format=json']),
        ('platform-build', ['cargo', 'test', '-p', 'sigrund', '--test', 'cgroup', *profile, '--locked', '--no-run', '--message-format=json']),
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
                if value.get('reason') == 'compiler-artifact' and value['target']['name'] == 'cgroup' and value.get('executable'):
                    manifest['platform_binary'] = value['executable']
        manifest['privileged_test_binaries'] = {}
        manifest['privileged_test_sha256'] = {}
        for line in (args.artifacts / 'privileged-build.log').read_text().splitlines():
            if not line.startswith('{'):
                continue
            value = json.loads(line)
            if value.get('reason') != 'compiler-artifact' or not value.get('executable') or not value.get('profile', {}).get('test'):
                continue
            name = value['target']['name']
            if name not in ('daemon', 'sigrund', 'client'):
                continue
            label = 'library' if name == 'sigrund' else name
            path = Path(value['executable'])
            manifest['privileged_test_binaries'][label] = str(path)
            manifest['privileged_test_sha256'][label] = hashlib.sha256(path.read_bytes()).hexdigest()
        if set(manifest['privileged_test_binaries']) != {'daemon', 'library', 'client'}:
            raise RuntimeError('Cargo did not report all privileged test executables')
        if 'platform_binary' not in manifest:
            raise RuntimeError('Cargo did not report the cgroup executable')
        if source_digest() != manifest['source_sha256']:
            raise RuntimeError('source changed during verification; repeat against a stable snapshot')
        binaries = REPO / 'target' / ('release' if args.release else 'debug')
        names = ('sigrund', 'sigrun', 'sigrundctl', 'sigrund-approve', 'sigrund-collector', 'sigrund-anchor')
        manifest['build_profile'] = 'release' if args.release else 'debug'
        manifest['unstripped_binaries'] = {name: hashlib.sha256((binaries / name).read_bytes()).hexdigest() for name in names}
        if args.strip_binaries:
            staged = args.artifacts / 'binaries'
            staged.mkdir()
            for name in names:
                shutil.copyfile(binaries / name, staged / name)
                (staged / name).chmod(0o755)
                subprocess.run(['strip', '--strip-unneeded', str(staged / name)], check=True)
                if args.rpm_binaries:
                    sections = subprocess.check_output(['objdump', '-h', str(staged / name)], text=True).splitlines()
                    allocated_note = any(len(line.split()) > 1 and line.split()[1] == '.note'
                                         and index + 1 < len(sections) and 'ALLOC' in sections[index + 1]
                                         for index, line in enumerate(sections))
                    subprocess.run(['strip', '-R', '.comment', *([] if allocated_note else ['-R', '.note']), str(staged / name)], check=True)
            binaries = staged
            manifest['binary_transform'] = ['strip', '--strip-unneeded']
            manifest['rpm_comment_note_stripping'] = args.rpm_binaries
        manifest['binary_directory'] = str(binaries.resolve())
        manifest['binaries'] = {name: hashlib.sha256((binaries / name).read_bytes()).hexdigest() for name in names}
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
