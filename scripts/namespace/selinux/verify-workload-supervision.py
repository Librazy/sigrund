#!/usr/bin/env python3
"""Verify host workload cancellation after policy reload or enforcement loss.

Run as trusted root on a disposable, enforcing Fedora host with the workload
examples provisioned for --owner and a test-only TTY approver identity. Drain
and stop sigrund first. This test reloads the installed policy and temporarily
disables enforcement; it restores enforcement and leaves the daemon stopped.
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
    parser.add_argument('--profile', default='host-data-v1')
    parser.add_argument('--change', choices=['reload', 'enforcement'], action='append')
    args = parser.parse_args()
    if os.geteuid() != 0 or subprocess.check_output(['getenforce'], text=True).strip() != 'Enforcing':
        parser.error('trusted root on an enforcing disposable host required')
    if subprocess.run(['systemctl', 'is-active', '--quiet', 'sigrund.service']).returncode == 0:
        parser.error('drain jobs and stop sigrund.service first')
    args.artifacts.mkdir(mode=0o700)
    spec = importlib.util.spec_from_file_location('installed', HERE / 'verify-installed.py')
    api = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(api)
    config = tomllib.loads(Path('/etc/sigrund/config.toml').read_text())
    profile = next(p for p in config['host_profiles'] if p['profile_id'] == args.profile)
    assert profile.get('workload') is not None, 'an explicit host workload is required'
    result = {'passed': False, 'kernel': os.uname().release, 'profile': args.profile, 'cases': []}
    try:
        for change in args.change or ['reload', 'enforcement']:
            case = {'change': change, 'passed': False}
            result['cases'].append(case)
            process = approver = None
            try:
                subprocess.run(['systemctl', 'start', 'sigrund.service'], check=True)
                daemon_pid = subprocess.check_output(['systemctl', 'show', '-p', 'MainPID', '--value', 'sigrund.service'])
                approver = api.Approver(args.identity)
                command = ['/usr/bin/sigrun', '--target', 'host', '--security-profile', args.profile,
                           '--target-uid', '0', '--target-gid', '0', '--cwd', '/']
                for cap in profile['capabilities']:
                    command += ['--capability', cap]
                command += ['--', '/usr/bin/sleep', '300']
                process = subprocess.Popen(api.requester(args.owner, 'sigrund-workload-supervision', command),
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                review = approver.confirm(process, timeout=60)
                execution = api.execution_id(review)
                case['exec_id'] = execution
                api.wait_for(lambda: any(row['event_type'] == 'EXEC_READY_TO_EXEC' for row in api.audit(execution)),
                             'running host workload before policy change')
                assert process.poll() is None and api.job(execution).exists()
                subprocess.run(['semodule', '-B'] if change == 'reload' else ['setenforce', '0'], check=True)
                try:
                    stdout, stderr = process.communicate(timeout=5)
                except subprocess.TimeoutExpired as error:
                    raise AssertionError('host workload survived the policy change') from error
                rows = api.assert_execution(execution, namespace=False)
                exit_record = next(row for row in rows if row['event_type'] == 'EXEC_EXIT')
                assert exit_record['signal'] == 9 and exit_record['disconnected'], exit_record
                assert subprocess.check_output(['systemctl', 'show', '-p', 'MainPID', '--value', 'sigrund.service']) == daemon_pid
                subprocess.run(['systemctl', 'is-active', '--quiet', 'sigrund.service'], check=True)
                case.update(passed=True, signal=exit_record['signal'], consumption_count=api.consumed(execution),
                            job_cgroup_removed=not api.job(execution).exists(),
                            stdout=stdout.decode(errors='replace'), stderr=stderr.decode(errors='replace'))
            except Exception as error:
                case['error'] = str(error)
            finally:
                subprocess.run(['setenforce', '1'], check=True)
                subprocess.run(['systemctl', 'stop', 'sigrund-workload-supervision.service'], capture_output=True)
                if process is not None and process.poll() is None:
                    process.kill()
                    process.communicate(timeout=5)
                if approver is not None:
                    (args.artifacts / (change + '-approver.log')).write_bytes(approver.transcript)
                    approver.close()
                subprocess.run(['systemctl', 'stop', 'sigrund.service'], check=True)
        result['passed'] = all(case['passed'] for case in result['cases'])
    finally:
        (args.artifacts / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
    if not result['passed']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
