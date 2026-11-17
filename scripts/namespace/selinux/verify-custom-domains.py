#!/usr/bin/env python3
"""Qualify provisioned custom profiles on a disposable enforcing SELinux host.

Requires matching daemon/signer rules, a registered acme_backup_job_t descriptor,
labeled /srv/acme-backup/{source,archive,secret}, and the real root-TTY approver.
--policy-changes additionally reloads policy, commits a boolean change and
switches global enforcement; never run on a shared production host.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tomllib

HERE = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--identity', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--owner', default='lab')
    parser.add_argument('--policy-changes', action='store_true')
    parser.add_argument('--registration-checks', action='store_true')
    parser.add_argument('--podman-image', help='Run namespace cases in this local rootful image')
    args = parser.parse_args()
    assert os.geteuid() == 0
    assert subprocess.check_output(['getenforce'], text=True).strip() == 'Enforcing'
    args.artifacts.mkdir(mode=0o700)
    spec = importlib.util.spec_from_file_location('installed', HERE / 'verify-installed.py')
    api = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(api)
    config = tomllib.loads(Path('/etc/sigrund/config.toml').read_text())
    result = {'passed': False, 'kernel': os.uname().release, 'cases': []}

    def execute(scope, operation, program, expected, payload=None):
        profile = next(p for p in config[scope + '_profiles'] if p.get('custom_domain'))
        command = ['/usr/bin/sigrun', '--target', 'host' if scope == 'host' else 'self',
                   '--security-profile', profile['profile_id'], '--target-uid', '0', '--target-gid', '0', '--cwd', '/']
        if payload is not None:
            command += ['--stdin', 'sha256']
        command += ['--', *program]
        approver = api.Approver(args.identity)
        unit = 'sigrund-custom-domain-client'
        invocation = api.requester(args.owner, unit, command)
        if scope == 'namespace' and args.podman_image:
            import pwd
            owner = pwd.getpwnam(args.owner)
            invocation = ['podman', 'run', '--rm', '-i', '--pull=never', '--network=none', '--name=custom-domain-container',
                          '--user=' + str(owner.pw_uid) + ':' + str(owner.pw_gid),
                          '--security-opt=label=type:spc_t', '--security-opt=label=level:s0', '--security-opt=seccomp=unconfined',
                          '-v', '/run/sigrund:/run/sigrund:ro', '-v', '/sys/fs/selinux:/sys/fs/selinux:rw',
                          '-v', '/srv/acme-backup:/srv/acme-backup:rw', args.podman_image, *command]
        process = subprocess.Popen(invocation,
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            # Keep the pipe live until systemd-run has transferred it. Closing
            # before transient-unit creation can lose finite input on Fedora.
            if scope == 'namespace' and args.podman_image:
                api.wait_for(lambda: subprocess.run(['podman', 'inspect', '--format={{.State.Running}}', 'custom-domain-container'], capture_output=True, text=True).stdout.strip() == 'true', 'container requester input handoff')
            else:
                api.wait_for(lambda: subprocess.check_output(['systemctl', 'show', '-p', 'MainPID', '--value', unit + '.service'], text=True).strip() not in ('', '0'), 'requester input handoff')
            process.stdin.write(payload or b'')
            process.stdin.flush()
            process.stdin.close()
            process.stdin = None
            review = approver.confirm(process, timeout=60)
            assert profile['custom_domain']['context'] in review
            assert profile['custom_domain']['policy_sha256'] in review
            stdout, stderr = process.communicate(timeout=30)
            case = dict(scope=scope, operation=operation, returncode=process.returncode,
                        stdout=stdout.decode(errors='replace'), stderr=stderr.decode(errors='replace'))
            result['cases'].append(case)
            assert process.returncode == expected, case
            if payload is not None:
                assert stdout == payload, case
                assert Path('/srv/acme-backup/archive/output').read_bytes() == payload, case
            case['passed'] = True
        finally:
            (args.artifacts / (scope + '-' + operation + '-approval.log')).write_bytes(approver.transcript)
            if process.poll() is None:
                process.kill()
                process.communicate()
            approver.close()

    try:
        for scope in ['host', 'namespace']:
            execute(scope, 'read', ['/usr/bin/cat', '/srv/acme-backup/source/input'], 0)
            execute(scope, 'denied', ['/usr/bin/cat', '/srv/acme-backup/secret/input'], 1)
            execute(scope, 'finite-input', ['/usr/bin/tee', '/srv/acme-backup/archive/output'], 0, b'archive payload\n')
        if args.registration_checks:
            profile = next(p for p in config['host_profiles'] if p.get('custom_domain'))
            descriptor = profile['custom_domain']
            registration = Path('/etc/sigrund/selinux-domains.d') / (descriptor['id'] + '.toml')
            original = registration.read_bytes()
            original_mode = registration.stat().st_mode & 0o777
            def reject_start(name):
                subprocess.run(['systemctl', 'reset-failed', 'sigrund'], capture_output=True)
                started = subprocess.run(['systemctl', 'start', 'sigrund'], capture_output=True)
                subprocess.run(['systemctl', 'stop', 'sigrund'], check=True)
                assert started.returncode != 0, name
                result['cases'].append(dict(operation=name, passed=True))
            subprocess.run(['systemctl', 'stop', 'sigrund'], check=True)
            try:
                registration.unlink()
                reject_start('missing-registration')
                registration.write_bytes(original)
                registration.chmod(0o666)
                reject_start('unsafe-registration-permissions')
                registration.chmod(original_mode)
                text = original.decode().replace(descriptor['summary'], descriptor['summary'] + ' changed')
                registration.write_text(text)
                reject_start('changed-registration')
            finally:
                registration.write_bytes(original)
                registration.chmod(original_mode)
                subprocess.run(['restorecon', str(registration)], check=True)
                subprocess.run(['systemctl', 'reset-failed', 'sigrund'], capture_output=True)
                subprocess.run(['systemctl', 'start', 'sigrund'], check=True)
        if args.policy_changes:
            profile = next(p for p in config['host_profiles'] if p.get('custom_domain'))
            boolean = 'httpd_can_network_connect'
            before = subprocess.check_output(['getsebool', boolean], text=True).strip().endswith('on')
            for change in ['boolean', 'reload', 'enforcement']:
                subprocess.run(['systemctl', 'restart', 'sigrund'], check=True)
                approver = api.Approver(args.identity)
                command = ['/usr/bin/sigrun', '--target', 'host', '--security-profile', profile['profile_id'],
                           '--target-uid', '0', '--target-gid', '0', '--cwd', '/', '--', '/usr/bin/sleep', '300']
                process = subprocess.Popen(api.requester(args.owner, 'sigrund-custom-domain-client', command), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                try:
                    review = approver.confirm(process, timeout=60)
                    process.stdin.close()
                    process.stdin = None
                    execution = api.execution_id(review)
                    api.wait_for(lambda: any(r['event_type'] == 'EXEC_READY_TO_EXEC' for r in api.audit(execution)), 'custom workload execution')
                    subprocess.run(['setsebool', boolean, 'off' if before else 'on'] if change == 'boolean' else ['semodule', '-B'] if change == 'reload' else ['setenforce', '0'], check=True)
                    process.communicate(timeout=10)
                    rows = api.assert_execution(execution, namespace=False)
                    exit_record = next(r for r in rows if r['event_type'] == 'EXEC_EXIT')
                    assert exit_record['signal'] == 9, exit_record
                    result['cases'].append(dict(operation=change, passed=True))
                    if change == 'boolean':
                        subprocess.run(['systemctl', 'stop', 'sigrund'], check=True)
                        started = subprocess.run(['systemctl', 'start', 'sigrund'], capture_output=True)
                        assert started.returncode != 0, 'stale policy fingerprint accepted after restart'
                        result['cases'].append(dict(operation='stale-policy-restart', passed=True))
                finally:
                    subprocess.run(['setenforce', '1'], check=True)
                    subprocess.run(['setsebool', boolean, 'on' if before else 'off'], check=True)
                    if process.poll() is None:
                        process.kill()
                        process.communicate()
                    approver.close()
                    subprocess.run(['systemctl', 'stop', 'sigrund'], check=True)
                    subprocess.run(['systemctl', 'reset-failed', 'sigrund'], capture_output=True)
        result['passed'] = True
    finally:
        (args.artifacts / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
