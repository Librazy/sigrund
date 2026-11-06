#!/usr/bin/env python3
"""Kill a disposable SELinux test service after its permissive transaction.

Exercise the same host-side recovery used by verify-namespace-phase0.py after
service termination. This is a separate native regression, not a workload case.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import runpy
import shutil
import stat
import sys
import time
import traceback
import uuid

REPO = Path(__file__).resolve().parent.parent
RUNNER_PATH = REPO / 'scripts/verify-namespace-phase0.py'
RUNNER = runpy.run_path(str(RUNNER_PATH))
run = RUNNER['run']
recover_policy = RUNNER['recover_policy']
stop_service_and_recover_policy = RUNNER['stop_service_and_recover_policy']


def modules():
    return {line.split()[0] for line in run(['semodule', '-l'], capture_output=True, text=True).stdout.splitlines()
            if line.split()}


def permissive_domains():
    return run(['semanage', 'permissive', '-l'], capture_output=True, text=True).stdout.split()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifacts', required=True, type=Path)
    parser.add_argument('--disposable-host', action='store_true')
    parser.add_argument('--stop-timeout-regression', action='store_true',
                        help='force a real stop-client timeout with a slow ExecStop and verify forced cleanup')
    parser.add_argument('--inside-service', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if os.geteuid() != 0 or not args.disposable_host:
        parser.error('requires root and --disposable-host on a disposable SELinux host')
    artifacts = args.artifacts
    if not artifacts.is_absolute() or artifacts != artifacts.resolve():
        parser.error('--artifacts must be an absolute canonical path')
    if args.inside_service:
        # The parent owns the test module and lock. Stop only after semanage
        # committed, so the kill lands before normal permissive deletion.
        (artifacts / 'domain-permissive-owned').write_text('sigrund_phase0_t\n')
        run(['semanage', 'permissive', '-a', 'sigrund_phase0_t'], capture_output=True)
        run(['setenforce', '0'], capture_output=True)
        (artifacts / 'permissive-ready').touch()
        while True:
            time.sleep(1)

    artifacts.mkdir(mode=0o755, parents=False, exist_ok=False)
    manifest = {
        'schema': 'sigrund.phase0-recovery-evidence.v1', 'result': 'incomplete',
        'kernel': platform.release(), 'architecture': platform.machine(),
        'source_sha256': {str(path.relative_to(REPO)): hashlib.sha256(path.read_bytes()).hexdigest()
                          for path in [Path(__file__), RUNNER_PATH, REPO / 'scripts/namespace-phase0/sigrund_phase0.te']},
        'command': sys.argv,
    }
    lock = os.open('/run/sigrund-phase0.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    unit = None
    try:
        info = os.fstat(lock)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600:
            raise RuntimeError('unsafe Phase 0 host lock')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if run(['getenforce'], capture_output=True, text=True).stdout.strip() != 'Enforcing':
            raise RuntimeError('start with SELinux enforcing')
        if 'sigrund_phase0' in modules():
            raise RuntimeError('refusing to replace an existing test module')
        policy = artifacts / 'policy'
        policy.mkdir()
        shutil.copyfile(REPO / 'scripts/namespace-phase0/sigrund_phase0.te', policy / 'sigrund_phase0.te')
        run(['make', '-f', '/usr/share/selinux/devel/Makefile', 'sigrund_phase0.pp'], cwd=policy, capture_output=True)
        (artifacts / 'policy-owned').write_text('sigrund_phase0\n')
        run(['semodule', '-i', policy / 'sigrund_phase0.pp'], capture_output=True)
        unit = 'sigrund-phase0-recovery-' + uuid.uuid4().hex + '.service'
        manifest['unit'] = unit
        stop_properties = (['--property=ExecStop=/usr/bin/sleep 60', '--property=TimeoutStopSec=60']
                           if args.stop_timeout_regression else ['--property=TimeoutStopSec=5'])
        run(['systemd-run', '--unit=' + unit, '--service-type=exec', '--property=KillMode=control-group',
             '--property=RuntimeMaxSec=180', *stop_properties,
             '--property=SELinuxContext=' + Path('/proc/self/attr/current').read_text().rstrip('\0\n'), sys.executable,
             Path(__file__).resolve(), '--inside-service', '--disposable-host', '--artifacts', artifacts], capture_output=True)
        deadline = time.monotonic() + 150
        while not (artifacts / 'permissive-ready').exists():
            if time.monotonic() >= deadline:
                raise RuntimeError('service did not commit the permissive transaction')
            time.sleep(0.1)
        if 'sigrund_phase0_t' not in permissive_domains():
            raise RuntimeError('test domain did not become permissive')
        manifest['permissive_before_kill'] = True
        manifest['globally_permissive_before_cleanup'] = run(['getenforce'], capture_output=True, text=True).stdout.strip() == 'Permissive'
        if not manifest['globally_permissive_before_cleanup']:
            raise RuntimeError('test host did not become globally permissive')
        if args.stop_timeout_regression:
            manifest['stop_outcome'] = stop_service_and_recover_policy(unit, artifacts, stop_timeout=0.2)
            if not manifest['stop_outcome']['stop_timed_out'] or not manifest['stop_outcome']['forced_kill']:
                raise RuntimeError('stop timeout did not exercise forced cleanup')
        else:
            run(['systemctl', 'kill', '--kill-whom=all', '--signal=SIGKILL', unit], capture_output=True)
            stop_service_and_recover_policy(unit, artifacts)
        manifest['service_after_kill'] = run(['systemctl', 'show', unit, '--property=ActiveState', '--property=Result'],
                                             capture_output=True, text=True).stdout.strip()
        recover_policy(artifacts)  # Repeated outer cleanup must also succeed.
        manifest['enforcing_after_recovery'] = run(['getenforce'], capture_output=True, text=True).stdout.strip() == 'Enforcing'
        manifest['permissive_removed'] = 'sigrund_phase0_t' not in permissive_domains()
        manifest['module_removed'] = 'sigrund_phase0' not in modules()
        manifest['ownership_markers_removed'] = not any((artifacts / name).exists() for name in
                                                       ['policy-owned', 'domain-permissive-owned'])
        if not all(manifest[key] for key in ['enforcing_after_recovery', 'permissive_removed',
                                            'module_removed', 'ownership_markers_removed']):
            raise RuntimeError('host policy was not completely recovered')
        manifest['result'] = 'passed'
    except BaseException:
        manifest['result'] = 'failed'
        manifest['error'] = traceback.format_exc()
        raise
    finally:
        try:
            stop_service_and_recover_policy(unit, artifacts, stop_timeout=15)
        except BaseException:
            manifest['result'] = 'failed'
            manifest['cleanup_error'] = traceback.format_exc()
            raise
        finally:
            os.close(lock)
            (artifacts / 'recovery.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print('Interrupted permissive recovery passed: ' + str(artifacts / 'recovery.json'))


if __name__ == '__main__':
    main()
