#!/usr/bin/env python3
"""Installed Podman acceptance using the real client, private TTY and manager.

Requires the independently provisioned read-only Podman destination and source A
from IMPLEMENTATION_NOTES.md#optional-podman-lifecycle-binding. Uses only the disposable named deployment.
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
ROOT = Path('/var/lib/sigrund-podman-rootfs')
NAME = 'sigrund-podman-b'
UNIT = 'sigrund-podman-b-anchor.service'
ENDPOINT = '/run/podman/podman.sock'
_NEXT_REQUEST = time.monotonic() + 61


def pace():
    global _NEXT_REQUEST
    delay = _NEXT_REQUEST - time.monotonic()
    if delay > 0:
        print('waiting %.1fs for the independent public-context budget' % delay, flush=True)
        time.sleep(delay)
    _NEXT_REQUEST = time.monotonic() + 8


def stale_rejected(api, approver):
    pace()
    process = subprocess.Popen(api.client('host-b', 'nsrequester'), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        try:
            approver.confirm(process, approve=False)
        except RuntimeError as error:
            assert 'request ended before review' in str(error), str(error)
        else:
            raise AssertionError('old registration reached private review after recovery')
        output, error = process.communicate(timeout=12)
        assert process.returncode != 0 and not output and b'TIMEOUT' in error, (output, error)
    finally:
        if process.poll() is None:
            process.kill(); process.communicate(timeout=5)


def run(*args, **kwargs):
    return subprocess.run(list(map(str, args)), check=True, timeout=15, **kwargs)


def inspect(name=NAME):
    return json.loads(subprocess.check_output(['podman', 'inspect', name], timeout=10))[0]


def create():
    run('podman', 'run', '--detach', '--name', NAME, '--rootfs', '--read-only',
        '--network', 'none', '--security-opt', 'label=level:s0',
        '--volume', '/run/sigrund:/run/sigrund', ROOT, '/usr/bin/sleep', 'infinity',
        stdout=subprocess.DEVNULL)


def anchor(api):
    subprocess.run(['sigrundctl', 'target', 'revoke', 'container-b', '--socket', api.SOCKET], capture_output=True, timeout=10)
    subprocess.run(['systemctl', 'stop', UNIT], capture_output=True, timeout=10)
    command = ['python3', str(HERE / 'register-podman.py'), '--endpoint', ENDPOINT]
    return json.loads(subprocess.check_output(command, timeout=15))


def positive(api, approver, artifacts, cases, route='host-b', label=None):
    label = label or route
    pace()
    process = subprocess.Popen(api.client(route, 'nsrequester'), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        review = approver.confirm(process)
        output, error = process.communicate(timeout=15)
        execution = api.execution_id(review)
        (artifacts / (label + '.review')).write_text(review)
        assert process.returncode == 0, (output, error)
        for expected in (b'destination=Podman-B', b'uid=12001 gid=12001 groups=0',
                         b'context=system_u:system_r:sigrund_workload_t:s0:c1,c2',
                         b'getppid=-1 errno=13', b'secret=-1 secret_errno=13'):
            assert expected in output, (expected, output)
        rows = api.assert_execution(execution)
        commit = next(row for row in rows if row['event_type'] == 'AUTH_COMMIT')
        manager = commit['approved_target']['manager']
        assert manager['container_id'] == inspect()['Id']
        assert manager['selector']['endpoint'] == ENDPOINT
        assert manager['container_id'] in review and 'configuration_sha256' in review
        cases.append({'name': label, 'passed': True, 'exec_id': execution,
            'stdout': output.decode(), 'consumption_count': api.consumed(execution),
            'job_cgroup_removed': not api.job(execution).exists(), 'manager': manager,
            'audit_events': [row['event_type'] for row in rows]})
    finally:
        if process.poll() is None:
            process.kill(); process.communicate(timeout=5)


def action(kind, api):
    if kind == 'replacement':
        run('podman', 'rename', NAME, NAME + '-old')
        create()
    elif kind == 'stop':
        run('podman', 'stop', '-t0', NAME, stdout=subprocess.DEVNULL)
    elif kind == 'delete':
        run('podman', 'rm', '-f', '-t0', NAME, stdout=subprocess.DEVNULL)
    elif kind == 'configuration':
        run('podman', 'update', '--pids-limit', '64', '--health-timeout', '30s', NAME, stdout=subprocess.DEVNULL)
    elif kind == 'pause':
        run('podman', 'pause', NAME, stdout=subprocess.DEVNULL)
    elif kind == 'resolver-loss':
        run('systemctl', 'stop', 'podman.service')
    else:
        raise AssertionError(kind)


def restore(kind):
    if kind == 'replacement':
        run('podman', 'rm', '-f', '-t0', NAME, stdout=subprocess.DEVNULL)
        run('podman', 'rename', NAME + '-old', NAME)
    elif kind == 'stop':
        run('podman', 'start', NAME, stdout=subprocess.DEVNULL)
    elif kind == 'delete':
        create()
    elif kind == 'configuration':
        run('podman', 'update', '--pids-limit', '2048', '--health-timeout', '30s', NAME, stdout=subprocess.DEVNULL)
    elif kind == 'pause':
        run('podman', 'unpause', NAME, stdout=subprocess.DEVNULL)
    elif kind == 'resolver-loss':
        run('systemctl', 'start', 'podman.service')


def lifecycle(api, approver, artifacts, cases, kind, running):
    binding = anchor(api)
    invocation = api.client('host-b', 'nsrequester') + (['wait'] if running else [])
    pace()
    requested = time.monotonic()
    process = subprocess.Popen(invocation, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    descriptors = []
    init = os.pidfd_open(binding['init_pid'])
    old_anchor = os.pidfd_open(binding['anchor_pid'])
    daemon = int(subprocess.check_output(['systemctl', 'show', '-p', 'MainPID', '--value', 'sigrund.service']))
    suspended = False
    changed = False
    name = kind + ('-running' if running else '-review')
    try:
        review = approver.confirm(process, approve=running)
        execution = api.execution_id(review)
        (artifacts / (name + '.review')).write_text(review)
        if running:
            assert select.select([process.stdout], [], [], 10)[0]
            output = os.read(process.stdout.fileno(), 4096)
            assert b'destination=Podman-B' in output, output
            descriptors = [os.pidfd_open(int(pid)) for pid in api.workload_descendants(execution)]
            assert len(descriptors) >= 2
        # Freeze only the controller briefly to prove both the original init
        # and captured anchor survive the actual same-name replacement. The
        # policy/watchdog remain enabled; manager work stays bounded by them.
        if kind == 'replacement':
            run('systemctl', 'kill', '--signal=STOP', '--kill-whom=main', 'sigrund.service'); suspended = True
        started = time.monotonic()
        action(kind, api); changed = True
        anchor_alive_at_replacement = None
        if kind == 'replacement':
            anchor_alive_at_replacement = not select.select([old_anchor], [], [], 0)[0]
            assert anchor_alive_at_replacement and not select.select([init], [], [], 0)[0]
            run('systemctl', 'kill', '--signal=CONT', '--kill-whom=main', 'sigrund.service'); suspended = False
            assert int(subprocess.check_output(['systemctl', 'show', '-p', 'MainPID', '--value', 'sigrund.service'])) == daemon, 'watchdog/restart is not manager generation evidence'
        if not running:
            os.write(approver.fd, b'yes\n')
        output, error = process.communicate(timeout=12)
        if running:
            rows = api.assert_execution(execution)
            assert api.consumed(execution) == 1
            for fd in descriptors:
                assert select.select([fd], [], [], 0)[0], 'supervised descendant survived'
        else:
            assert process.returncode != 0 and not output and b'TIMEOUT' in error, (output, error)
            assert 4.5 <= time.monotonic() - requested <= 7.5, 'thin outcome did not retain its fixed deadline'
            assert api.consumed(execution) == 0
            rows = api.audit(execution)
            assert all(row['event_type'] != 'AUTH_COMMIT' for row in rows)
            assert all(row['event_type'] != 'EXEC_READY_TO_EXEC' for row in rows)
        api.wait_for(lambda: not api.job(execution).exists(), 'managed job cleanup')
        elapsed = time.monotonic() - started
        if running:
            assert elapsed < 6, elapsed
        if kind in ('replacement', 'configuration', 'pause', 'resolver-loss'):
            assert not select.select([init], [], [], 0)[0], 'manager init is the live negative control'
        cases.append({'name': name, 'passed': True, 'exec_id': execution,
            'consumption_count': api.consumed(execution), 'elapsed_seconds': elapsed,
            'job_cgroup_removed': True, 'descendant_exit_count': len(descriptors),
            'old_anchor_alive_at_replacement': anchor_alive_at_replacement,
            'audit_events': [row['event_type'] for row in rows]})
    finally:
        if suspended:
            run('systemctl', 'kill', '--signal=CONT', '--kill-whom=main', 'sigrund.service')
        if process.poll() is None:
            subprocess.run(['systemctl', 'stop', 'sigrund-namespace-host-client.service'], capture_output=True)
            process.kill(); process.communicate(timeout=5)
        for fd in [init, old_anchor, *descriptors]:
            os.close(fd)
        if changed:
            restore(kind)
    # Restoring manager state cannot revive the old registration. A public
    # request still times out without review, consumption or output.
    stale_rejected(api, approver)
    cases[-1]['stale_registration_rejected_after_recovery'] = True
    anchor(api)
    positive(api, approver, artifacts, cases, label=name + '-fresh-recovery')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--case', action='append', choices=('replacement', 'stop', 'delete', 'configuration', 'pause', 'resolver-loss'))
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('initial-userns host root required')
    args.artifacts.mkdir(mode=0o700)
    spec = importlib.util.spec_from_file_location('namespace_installed', HERE.parent / 'selinux/verify-installed.py')
    api = importlib.util.module_from_spec(spec); spec.loader.exec_module(api)
    result = {'passed': False, 'cases': []}
    approver = api.Approver(Path('/var/lib/sigrund-namespace-lab/approver'))
    try:
        anchor(api)
        for route in ('host-b', 'a-b'):
            positive(api, approver, args.artifacts, result['cases'], route)
        for kind in args.case or ('replacement', 'stop', 'delete', 'configuration', 'pause', 'resolver-loss'):
            for running in (False, True):
                lifecycle(api, approver, args.artifacts, result['cases'], kind, running)
                print('passed', result['cases'][-2]['name'], flush=True)
        result['passed'] = True
    finally:
        (args.artifacts / 'approver.log').write_bytes(approver.transcript)
        approver.close()
        (args.artifacts / 'result.json').write_text(json.dumps(result, indent=2) + '\n')


if __name__ == '__main__':
    main()
