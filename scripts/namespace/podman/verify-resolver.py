#!/usr/bin/env python3
"""Installed manager fault acceptance against a real Podman destination.

Uses the root-only forwarding fault injector, native registration, actual client
and private TTY approval. Synthetic responses supplement real lifecycle cases.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import select
import subprocess
import time

HERE = Path(__file__).resolve().parent
DIRECTORY = Path('/run/sigrund-podman-proxy')
PROXY_UNIT = 'sigrund-podman-fault-proxy.service'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    api = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(api)
    return api


def total():
    import sqlite3
    with sqlite3.connect('file:/var/lib/sigrund/state.sqlite?mode=ro', uri=True) as connection:
        return connection.execute('SELECT count(*) FROM consumed_grants').fetchone()[0]


def mode(value):
    (DIRECTORY / 'mode').write_text(value)


def invalid_acquisition(api, harness, result, fault):
    harness.run('sigrundctl', 'target', 'revoke', 'container-b', '--socket', api.SOCKET)
    subprocess.run(['systemctl', 'stop', harness.UNIT], capture_output=True, timeout=10)
    time.sleep(.25)
    # Launch from the authentic manager/rootfs before injecting bad resolver data.
    binding = json.loads(subprocess.check_output(['python3', str(HERE / 'register-podman.py'), '--launch-only'], timeout=15))
    before = total()
    mode(fault)
    try:
        command = ['sigrundctl', 'target', 'register-podman', 'container-b', '--pid', str(binding['anchor_pid']),
            '--owner-uid', '0', '--security-profile', 'namespace-selinux-v1', '--socket', api.SOCKET,
            '--podman-endpoint', harness.ENDPOINT, '--podman-owner-uid', '0',
            '--podman-namespace', 'default', '--podman-container', harness.NAME]
        reply = subprocess.run(command, capture_output=True, timeout=12)
        assert reply.returncode != 0 and b'operation would block' not in reply.stderr, reply.stderr
        assert total() == before
        result.append({'name': 'acquisition-rejects-' + fault, 'passed': True,
            'reply': reply.stderr.decode(), 'consumption_delta': 0})
    finally:
        mode('pass')
        subprocess.run(['systemctl', 'stop', harness.UNIT], capture_output=True, timeout=10)


def lost_evidence(api, harness, approver, artifacts, result, fault, running):
    binding = harness.anchor(api)
    harness.pace()
    requested = time.monotonic()
    process = subprocess.Popen(api.client('host-b', 'nsrequester') + (['wait'] if running else []),
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    descriptors = []
    init = os.pidfd_open(binding['init_pid'])
    name = fault + ('-running' if running else '-review')
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
        mode(fault)
        if not running:
            # Attempt the old approval, rather than allowing an unsigned request
            # to time out trivially. The retained dependency must veto commit.
            os.write(approver.fd, b'yes\n')
        output, error = process.communicate(timeout=12)
        if running:
            rows = api.assert_execution(execution)
            assert api.consumed(execution) == 1
            assert all(select.select([fd], [], [], 0)[0] for fd in descriptors)
            assert time.monotonic() - started < 6
        else:
            assert process.returncode != 0 and not output and b'TIMEOUT' in error, (output, error)
            assert 4.5 <= time.monotonic() - requested <= 7.5, 'thin disclosure deadline changed'
            rows = api.audit(execution)
            assert api.consumed(execution) == 0
            assert all(row['event_type'] not in ('AUTH_COMMIT', 'EXEC_READY_TO_EXEC') for row in rows)
        api.wait_for(lambda: not api.job(execution).exists(), 'resolver-failure job cleanup')
        assert not select.select([init], [], [], 0)[0], 'real manager init must survive the injected fault'
        result.append({'name': name, 'passed': True, 'exec_id': execution,
            'consumption_count': api.consumed(execution), 'job_cgroup_removed': True,
            'descendant_exit_count': len(descriptors), 'elapsed_seconds': time.monotonic() - started,
            'manager_init_alive': True, 'audit_events': [row['event_type'] for row in rows]})
    finally:
        mode('pass')
        if process.poll() is None:
            process.kill(); process.communicate(timeout=5)
        for fd in [init, *descriptors]:
            os.close(fd)
    harness.stale_rejected(api, approver)
    result[-1]['no_private_review_after_recovery'] = True
    harness.anchor(api)
    harness.positive(api, approver, artifacts, result, label=name + '-fresh-recovery')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--fault', action='append', choices=('event-gap', 'malformed-event', 'configuration', 'missing-state', 'duplicate-json', 'stall', 'wrong-version'))
    args = parser.parse_args()
    assert os.geteuid() == 0
    args.artifacts.mkdir(mode=0o700)
    api = load('namespace_installed', HERE.parent / 'selinux/verify-installed.py')
    harness = load('podman_installed', HERE / 'verify-installed.py')
    context = Path('/proc/self/attr/current').read_text().strip('\0\n')
    result = {'passed': False, 'cases': []}
    approver = None
    try:
        harness.run('systemd-run', '--quiet', '--collect', '--unit=' + PROXY_UNIT,
            '--property=SELinuxContext=' + context, '--property=KillMode=control-group',
            '--property=RuntimeMaxSec=3600s', 'python3', HERE / 'fault-proxy.py', '--directory', DIRECTORY)
        api.wait_for(lambda: (DIRECTORY / 'podman.sock').exists(), 'root fault proxy')
        harness.ENDPOINT = str(DIRECTORY / 'podman.sock')
        approver = api.Approver(Path('/var/lib/sigrund-namespace-lab/approver'))
        harness.anchor(api)
        harness.positive(api, approver, args.artifacts, result['cases'], label='genuine-forwarded-manager')
        if not args.fault:
            for fault in ('wrong-pid', 'wrong-id', 'wrong-name', 'wrong-namespace', 'missing-state', 'duplicate-json', 'wrong-version'):
                invalid_acquisition(api, harness, result['cases'], fault)
                harness.anchor(api)
            # User-owned labels are bound metadata, never target policy. A
            # purported host-root owner cannot authorize forbidden credentials.
            harness.run('sigrundctl', 'target', 'revoke', 'container-b', '--socket', api.SOCKET)
            mode('configuration')
            harness.anchor(api)
            invocation = api.client('host-b', 'nsrequester')
            index = invocation.index('--account')
            invocation[index:index + 2] = ['--target-uid', '0', '--target-gid', '0']
            before = total(); harness.pace()
            denied = subprocess.run(invocation, capture_output=True, timeout=12)
            assert denied.returncode != 0 and not denied.stdout and b'TIMEOUT' in denied.stderr
            assert total() == before
            result['cases'].append({'name': 'dishonest-owner-labels-cannot-authorize-root', 'passed': True, 'consumption_delta': 0})
            mode('pass')
        for fault in args.fault or ('event-gap', 'malformed-event', 'configuration', 'missing-state', 'duplicate-json', 'stall', 'wrong-version'):
            for running in (False, True):
                lost_evidence(api, harness, approver, args.artifacts, result['cases'], fault, running)
                print('passed', result['cases'][-2]['name'], flush=True)
        result['passed'] = True
    finally:
        if (DIRECTORY / 'mode').exists():
            mode('pass')
        subprocess.run(['sigrundctl', 'target', 'revoke', 'container-b', '--socket', api.SOCKET], capture_output=True, timeout=10)
        if approver:
            (args.artifacts / 'approver.log').write_bytes(approver.transcript)
            approver.close()
        subprocess.run(['systemctl', 'stop', PROXY_UNIT], capture_output=True, timeout=10)
        (args.artifacts / 'result.json').write_text(json.dumps(result, indent=2) + '\n')


if __name__ == '__main__':
    main()
