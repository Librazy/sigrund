#!/usr/bin/env python3
"""Verify finite stdin transfer under enforcing SELinux on a disposable host.

Requires the installed service, lab/requester UID in its host rules, a root-TTY
approver identity, and /usr/bin/cat in the executable roots. Optionally repeat
from a prepared local Podman image containing sigrun and its shared libraries.
The admin-self case also requires namespace-admin-v1 in daemon and signer rules.
Does not load policy or change configuration. Run as trusted host root.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import subprocess
import time

HERE = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--owner', default='lab')
    parser.add_argument('--identity', type=Path, required=True)
    parser.add_argument('--podman-image', help='local disposable image, run with Distrobox-style spc_t')
    parser.add_argument('--admin-self', action='store_true', help='also check container self with namespace-admin-v1')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('trusted host root required')
    if subprocess.check_output(['getenforce'], text=True).strip() != 'Enforcing':
        parser.error('enforcing SELinux required')
    if args.admin_self and not args.podman_image:
        parser.error('--admin-self requires --podman-image')
    args.artifacts.mkdir(mode=0o700)
    spec = importlib.util.spec_from_file_location('installed', HERE / 'verify-installed.py')
    api = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(api)
    payload = b'finite stdin from another SELinux domain\x00\xff\n'
    account = pwd.getpwnam(args.owner)
    assert account.pw_uid != 0
    client = ['/usr/bin/sigrun', '--socket', api.SOCKET, '--target', 'host',
              '--security-profile', 'host-baseline', '--target-uid', '0', '--target-gid', '0',
              '--cwd', '/', '--stdin', 'sha256', '--', '/usr/bin/cat']
    routes = [('requester', ['systemd-run', '--quiet', '--wait', '--pipe', '--collect',
               '--unit=sigrund-stdin-requester', '--uid=' + args.owner,
               '--property=SELinuxContext=system_u:system_r:sigrund_requester_t:s0',
               '--property=RuntimeMaxSec=60s', *client])]
    if args.podman_image:
        container = ['podman', 'run', '--rm', '-i', '--pull=never',
            '--name=sigrund-stdin-container', '--user=' + str(account.pw_uid) + ':' + str(account.pw_gid),
            '--security-opt=label=type:spc_t', '--security-opt=label=level:s0',
            '-v', '/run/sigrund:/run/sigrund:ro',
            '-v', '/sys/fs/selinux:/sys/fs/selinux:rw', args.podman_image]
        routes.append(('container', [*container, *client]))
        if args.admin_self:
            admin = client.copy()
            admin[admin.index('--target') + 1] = 'self'
            admin[admin.index('--security-profile') + 1] = 'namespace-admin-v1'
            # Self capture requires a single-threaded, unfiltered connector.
            # Keep Podman's default seccomp for the container-to-host case.
            routes.append(('container-self', [*container[:-1],
                '--security-opt=seccomp=unconfined', container[-1], *admin]))
    result = {'passed': False, 'kernel': os.uname().release, 'enforcing': True,
              'stdin_sha256': hashlib.sha256(payload).hexdigest(), 'cases': [],
              'client_sha256': hashlib.sha256(Path('/usr/bin/sigrun').read_bytes()).hexdigest(),
              'daemon_sha256': hashlib.sha256(Path('/usr/libexec/sigrund/sigrund').read_bytes()).hexdigest()}
    if args.podman_image:
        result['podman_image_id'] = subprocess.check_output(
            ['podman', 'image', 'inspect', '--format={{.Id}}', args.podman_image], text=True).strip()
    approver = api.Approver(args.identity)
    started = str(int(time.time()))
    try:
        for name, invocation in routes:
            case = {'name': name, 'passed': False}
            result['cases'].append(case)
            process = subprocess.Popen(invocation, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                process.stdin.write(payload)
                process.stdin.close()
                process.stdin = None
                review = approver.confirm(process)
                execution = api.execution_id(review)
                stdout, stderr = process.communicate(timeout=20)
                rows = api.assert_execution(execution, namespace=False)
                committed = next(row for row in rows if row['event_type'] == 'AUTH_COMMIT')
                ready = next(row for row in rows if row['event_type'] == 'EXEC_READY_TO_EXEC')
                case.update(exec_id=execution, returncode=process.returncode,
                    stdout_hex=stdout.hex(), stderr=stderr.decode(errors='replace'),
                    stdin_sha256=committed['stdin_sha256'],
                    execution_observed=ready.get('execution_observed'),
                    consumption_count=api.consumed(execution),
                    audit_events=[row['event_type'] for row in rows],
                    job_cgroup_removed=not api.job(execution).exists())
                case['passed'] = (process.returncode == 0 and stdout == payload
                                  and committed['stdin_sha256'] == result['stdin_sha256'])
                assert case['passed'], case
            except Exception as error:
                case['error'] = str(error)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate(timeout=5)
                if name == 'requester':
                    subprocess.run(['systemctl', 'stop', 'sigrund-stdin-requester.service'], capture_output=True)
                else:
                    subprocess.run(['podman', 'rm', '-f', 'sigrund-stdin-container'], capture_output=True)
        result['passed'] = all(case['passed'] for case in result['cases'])
    finally:
        (args.artifacts / 'approver.log').write_bytes(approver.transcript)
        approver.close()
        journal = subprocess.check_output(['journalctl', '-b', '_TRANSPORT=audit', '--since=@' + started,
                                            '-o', 'cat', '--no-pager'])
        (args.artifacts / 'audit.log').write_bytes(journal)
        (args.artifacts / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
    if not result['passed']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
