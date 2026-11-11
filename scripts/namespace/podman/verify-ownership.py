#!/usr/bin/env python3
"""Qualify managed target ownership through cancellation and quota pressure."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import select
import subprocess
import time

HERE = Path(__file__).resolve().parent
SECOND_UNIT = 'sigrund-podman-quota-anchor.service'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def cancelled(api, harness, approver, artifacts, cases, running):
    harness.anchor(api)
    harness.pace()
    process = subprocess.Popen(api.client('host-b', 'nsrequester') + (['wait'] if running else []),
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    descriptors = []
    name = 'client-cancellation-' + ('running' if running else 'review')
    try:
        review = approver.confirm(process, approve=running)
        execution = api.execution_id(review)
        (artifacts / (name + '.review')).write_text(review)
        if running:
            assert select.select([process.stdout], [], [], 10)[0]
            assert b'destination=Podman-B' in os.read(process.stdout.fileno(), 4096)
            descriptors = [os.pidfd_open(int(pid)) for pid in api.workload_descendants(execution)]
            assert len(descriptors) >= 2
        started = time.monotonic()
        harness.run('systemctl', 'kill', '--signal=KILL', '--kill-whom=all', 'sigrund-namespace-host-client.service')
        if not running:
            os.write(approver.fd, b'yes\n')
        process.communicate(timeout=12)
        assert process.returncode != 0
        if running:
            rows = api.assert_execution(execution)
            assert all(select.select([fd], [], [], 0)[0] for fd in descriptors)
        else:
            # Allow the canceled authorization's fixed deadline to pass before
            # testing absence of commit, consumption and spawn.
            time.sleep(5.2)
            rows = api.audit(execution)
            assert not any(row['event_type'] in ('AUTH_COMMIT', 'EXEC_READY_TO_EXEC') for row in rows)
        assert api.consumed(execution) == int(running)
        api.wait_for(lambda: not api.job(execution).exists(), 'canceled managed job cleanup')
        elapsed = time.monotonic() - started
        assert elapsed < 6
        cases.append({'name': name, 'passed': True, 'exec_id': execution,
                      'consumption_count': int(running), 'descendant_exit_count': len(descriptors),
                      'job_cgroup_removed': True, 'elapsed_seconds': elapsed,
                      'audit_events': [row['event_type'] for row in rows]})
    finally:
        if process.poll() is None:
            process.kill(); process.communicate(timeout=5)
        for descriptor in descriptors:
            os.close(descriptor)
    # Request lifetime must not dispose the shared registration or its monitor.
    harness.positive(api, approver, artifacts, cases, label=name + '-same-binding-survives')


def quota(api, harness, approver, artifacts, cases):
    harness.anchor(api)
    binding = json.loads(subprocess.check_output(['python3', str(HERE / 'register-podman.py'),
                        '--unit', SECOND_UNIT, '--launch-only'], timeout=15))
    try:
        command = ['sigrundctl', 'target', 'register-podman', 'second-container',
                   '--pid', str(binding['anchor_pid']), '--owner-uid', '0',
                   '--security-profile', 'namespace-selinux-v1', '--socket', api.SOCKET,
                   '--podman-endpoint', harness.ENDPOINT, '--podman-owner-uid', '0',
                   '--podman-namespace', 'default', '--podman-container', harness.NAME]
        for attempt in range(3):
            reply = subprocess.run(command, capture_output=True, timeout=12)
            assert reply.returncode != 0 and b'operation would block' in reply.stderr, reply.stderr
            cases.append({'name': 'retained-helper-quota-' + str(attempt + 1), 'passed': True,
                          'reply': reply.stderr.decode()})
    finally:
        subprocess.run(['systemctl', 'stop', SECOND_UNIT], capture_output=True, timeout=10)
    harness.positive(api, approver, artifacts, cases, label='quota-failure-preserves-existing-binding')
    harness.anchor(api)
    harness.positive(api, approver, artifacts, cases, label='actual-disposal-releases-helper-quota')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifacts', type=Path, required=True)
    args = parser.parse_args()
    assert os.geteuid() == 0
    args.artifacts.mkdir(mode=0o700)
    api = load('namespace_installed', HERE.parent / 'selinux/verify-installed.py')
    harness = load('podman_installed', HERE / 'verify-installed.py')
    result = {'passed': False, 'cases': []}
    approver = api.Approver(Path('/var/lib/sigrund-namespace-lab/approver'))
    try:
        for running in (False, True):
            cancelled(api, harness, approver, args.artifacts, result['cases'], running)
        quota(api, harness, approver, args.artifacts, result['cases'])
        result['passed'] = True
    finally:
        subprocess.run(['systemctl', 'stop', SECOND_UNIT], capture_output=True, timeout=10)
        (args.artifacts / 'approver.log').write_bytes(approver.transcript)
        approver.close()
        (args.artifacts / 'result.json').write_text(json.dumps(result, indent=2) + '\n')


if __name__ == '__main__':
    main()
