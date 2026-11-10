#!/usr/bin/env python3
"""Check installed producer isolation with namespace profiles disabled.

Use the disposable Fedora deployment from the operator recipe. Stop the daemon
first. Configuration bytes and the inactive service state are restored on exit.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import subprocess
import tomllib

HERE = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--owner', default='lab', help='existing trusted host administrator login')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('host root required')
    if subprocess.run(['systemctl', 'is-active', '--quiet', 'sigrund.service']).returncode == 0:
        parser.error('stop sigrund.service and drain its jobs first')
    args.artifacts.mkdir(mode=0o700)
    spec = importlib.util.spec_from_file_location('installed', HERE / 'verify-installed.py')
    api = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(api)
    paths = [Path('/etc/sigrund/config.toml'), Path('/etc/sigrund/signers.toml')]
    original = [path.read_bytes() for path in paths]
    approver = None
    result = {'passed': False, 'cases': []}
    try:
        requester_uid = pwd.getpwnam(args.owner).pw_uid
        assert requester_uid != 0
        context = Path('/proc/self/attr/current').read_text().rstrip('\0\n')
        assert context.split(':')[2] == 'unconfined_t', 'run from the trusted host administrator context'
        for path, data, marker in zip(paths, original, (b'[[namespace_profiles]]', b'[[signers.namespace_rules]]')):
            host = data.split(marker, 1)[0]
            host = re.sub(rb'(?m)^((?:allowed_)?requester_uids\s*=\s*)\[[^\n]*\]',
                          lambda match: match[1] + str([requester_uid]).encode(), host)
            path.write_bytes(host)
        config, signers = [tomllib.loads(path.read_text()) for path in paths]
        assert not config.get('namespace_profiles') and not config.get('namespace_rules')
        assert all(not signer.get('namespace_rules') for signer in signers['signers'])
        probe = '/usr/local/libexec/sigrund-phase4/security-probe'
        subprocess.run(['cc', '-O2', '-Wall', '-Wextra', '-Werror', str(HERE / 'security-probe.c'), '-o', probe], check=True)
        subprocess.run(['restorecon', probe], check=True)
        subprocess.run(['systemctl', 'start', 'sigrund.service'], check=True)
        approver = api.Approver(Path('/var/lib/sigrund-phase4-qualification/approver'))
        for uid in (65534, 0):
            for name, command in (('context', [api.TOOL]), ('forgery', [probe, 'forgery'])):
                # No namespace sockets are exposed during this host-only test.
                # Use the existing trusted administrator's ordinary UID/domain,
                # without changing the confined source account or its policy.
                invocation = ['systemd-run', '--quiet', '--collect', '--wait', '--pipe',
                    '--unit=sigrund-phase4-host-only-client', '--uid=' + args.owner,
                    '--property=SELinuxContext=' + context, '--property=RuntimeMaxSec=60s',
                    '/usr/bin/sigrun', '--socket', api.SOCKET, '--target', 'host',
                     '--security-profile', 'host-baseline', '--target-uid', str(uid), '--target-gid', str(uid),
                     '--cwd', '/', '--', *command]
                process = subprocess.Popen(invocation, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                try:
                    review = approver.confirm(process)
                    execution = api.execution_id(review)
                    stdout, stderr = process.communicate(timeout=15)
                    rows = api.assert_execution(execution, namespace=False)
                    passed = process.returncode == 0 and (
                        b'context=system_u:system_r:sigrund_host_workload_t:s0' in stdout
                        if name == 'context' else b'producer-entry=denied' in stdout)
                    result['cases'].append({'name': name, 'target_uid': uid, 'passed': passed,
                        'exec_id': execution, 'returncode': process.returncode,
                        'stdout': stdout.decode(), 'stderr': stderr.decode(),
                        'consumption_count': api.consumed(execution),
                        'job_cgroup_removed': not api.job(execution).exists(),
                        'audit_events': [row['event_type'] for row in rows]})
                finally:
                    if process.poll() is None:
                        subprocess.run(['systemctl', 'stop', 'sigrund-phase4-host-only-client.service'], capture_output=True)
                        process.kill()
                        process.communicate(timeout=5)
        assert all(case['passed'] for case in result['cases']), result['cases']
        result['passed'] = True
    finally:
        try:
            if approver:
                (args.artifacts / 'approver.log').write_bytes(approver.transcript)
                approver.close()
        finally:
            stopped = subprocess.run(['systemctl', 'stop', 'sigrund.service'])
            for path, data in zip(paths, original):
                path.write_bytes(data)
            result['service_stopped'] = stopped.returncode == 0
            result['passed'] &= result['service_stopped']
            (args.artifacts / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
            assert result['service_stopped']


if __name__ == '__main__':
    main()
