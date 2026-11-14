#!/usr/bin/env python3
"""Verify opt-in workload tiers on an explicitly provisioned disposable host.

Requires workload-profiles.toml.example and matching signer rules for --owner,
including signer capability ceilings, a compiled workload-profile-probe.c at
/usr/bin/sigrund-workload-probe, and /srv/sigrund-workloads/data labeled
sigrund_workload_data_t. The optional local image needs matching sigrun/probe,
libraries and requester credentials. Does not provision or load policy.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import pwd
import subprocess
import time
import tomllib

HERE = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--identity', type=Path, required=True)
    parser.add_argument('--owner', default='lab')
    parser.add_argument('--podman-image')
    parser.add_argument('--package-rpm', action='store_true', help='also install/remove the data-only sigrund-workload-fixture RPM at /srv/sigrund-workloads/fixture.rpm')
    args = parser.parse_args()
    if os.geteuid() != 0 or subprocess.check_output(['getenforce'], text=True).strip() != 'Enforcing':
        parser.error('trusted root on an enforcing disposable host required')
    args.artifacts.mkdir(mode=0o700)
    spec = importlib.util.spec_from_file_location('installed', HERE / 'verify-installed.py')
    api = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(api)
    config = tomllib.loads(Path('/etc/sigrund/config.toml').read_text())
    account = pwd.getpwnam(args.owner)
    assert account.pw_uid != 0
    started = str(int(time.time()))
    if args.package_rpm and not Path('/srv/sigrund-workloads/fixture.rpm').is_file():
        parser.error('data-only fixture RPM must be staged before testing')
    result = {'passed': False, 'enforcing': True, 'kernel': os.uname().release, 'cases': []}
    if args.podman_image:
        result['podman_image_id'] = subprocess.check_output(
            ['podman', 'image', 'inspect', '--format={{.Id}}', args.podman_image], text=True).strip()
    approver = api.Approver(args.identity)
    cases = []
    for scope in ['host'] + (['namespace'] if args.podman_image else []):
        for tier in ['data', 'network', 'maintenance', 'root']:
            cases.append((scope, tier, 'probe', ['/usr/bin/sigrund-workload-probe', tier, scope + '-' + tier + '-v1']))
            if args.package_rpm and tier in ['maintenance', 'root']:
                install = ['/usr/bin/dnf5', '-y', '--disablerepo=*', '--nogpgcheck', 'install', '/srv/sigrund-workloads/fixture.rpm'] if scope == 'host' else ['/usr/bin/rpm', '--dbpath', '/var/lib/rpm', '--noplugins', '--nodeps', '-i', '/srv/sigrund-workloads/fixture.rpm']
                remove = ['/usr/bin/dnf5', '-y', '--disablerepo=*', 'remove', 'sigrund-workload-fixture'] if scope == 'host' else ['/usr/bin/rpm', '--dbpath', '/var/lib/rpm', '--noplugins', '--nodeps', '-e', 'sigrund-workload-fixture']
                # Keep namespace installs/removals in one disposable container.
                if scope == 'namespace':
                    cases.append((scope, tier, 'package', ['/usr/bin/sh', '-c', ' '.join(install) + ' && test -f /usr/share/sigrund-workload-fixture/installed.txt && ' + ' '.join(remove) + ' && test ! -e /usr/share/sigrund-workload-fixture/installed.txt']))
                else:
                    cases.append((scope, tier, 'install', install))
                    cases.append((scope, tier, 'remove', remove))
    try:
        for scope, tier, operation, program in cases:
            name = scope + '-' + tier + '-v1'
            profile = next(p for p in config[scope + '_profiles'] if p['profile_id'] == name)
            client = ['/usr/bin/sigrun', '--socket', api.SOCKET, '--target', 'host' if scope == 'host' else 'self',
                      '--security-profile', name, '--target-uid', '0', '--target-gid', '0', '--cwd', '/']
            for capability in profile['capabilities']:
                client += ['--capability', capability]
            client += ['--', *program]
            if scope == 'host':
                invocation = ['systemd-run', '--quiet', '--wait', '--pipe', '--collect',
                    '--unit=sigrund-workload-client', '--uid=' + args.owner,
                    '--property=SELinuxContext=system_u:system_r:sigrund_requester_t:s0',
                    '--property=RuntimeMaxSec=120s', *client]
            else:
                invocation = ['podman', 'run', '--rm', '--pull=never', '--network=none', '--name=sigrund-workload-container',
                    '--user=' + str(account.pw_uid) + ':' + str(account.pw_gid),
                    '--security-opt=label=type:spc_t', '--security-opt=label=level:s0',
                    '--security-opt=seccomp=unconfined',
                    '-v', '/run/sigrund:/run/sigrund:ro', '-v', '/sys/fs/selinux:/sys/fs/selinux:rw',
                    '-v', '/srv/sigrund-workloads:/srv/sigrund-workloads:rw', args.podman_image, *client]
            case = {'name': name, 'operation': operation, 'passed': False}
            result['cases'].append(case)
            process = subprocess.Popen(invocation, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                review = approver.confirm(process, timeout=60)
                execution = api.execution_id(review)
                stdout, stderr = process.communicate(timeout=30)
                case.update(exec_id=execution, returncode=process.returncode,
                            stdout=stdout.decode(errors='replace'), stderr=stderr.decode(errors='replace'))
                api.assert_execution(execution, namespace=False)
                case.update(consumption_count=api.consumed(execution), job_cgroup_removed=not api.job(execution).exists())
                assert process.returncode == 0, case
                if tier == 'root':
                    assert 'FULL HOST ROOT AUTHORITY' in review, review
                if operation == 'probe':
                    case['observed'] = json.loads(stdout)
                elif scope == 'host':
                    assert Path('/usr/share/sigrund-workload-fixture/installed.txt').exists() == (operation == 'install')
                case['passed'] = True
            except Exception as error:
                case['error'] = str(error)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate(timeout=5)
                subprocess.run(['systemctl', 'stop', 'sigrund-workload-client.service'], capture_output=True)
                if scope == 'namespace':
                    subprocess.run(['podman', 'rm', '-f', 'sigrund-workload-container'], capture_output=True)
        result['passed'] = all(case['passed'] for case in result['cases'])
    finally:
        (args.artifacts / 'approver.log').write_bytes(approver.transcript)
        approver.close()
        journal = subprocess.check_output(['journalctl', '-b', '_TRANSPORT=audit', '--since=@' + started, '-o', 'cat', '--no-pager'])
        (args.artifacts / 'audit.log').write_bytes(journal)
        (args.artifacts / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
    if not result['passed']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
