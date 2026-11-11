#!/usr/bin/env python3
"""Verify the installed, explicitly provisioned SELinux namespace deployment.

This runner uses the real root-TTY approver and installed requester tools.
Create A/B with environment.py and register container-b before running it.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pty
import pwd
import re
import select
import signal
import shutil
import sqlite3
import struct
import subprocess
import termios
import time
import tomllib
import uuid
from contextlib import closing

HERE = Path(__file__).resolve().parent
SOCKET = '/run/sigrund/client.sock'
TOOL = '/usr/local/libexec/sigrund-namespace/tool'


class Approver:
    def __init__(self, identity):
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            os.execv('/usr/bin/sigrund-approve', ['sigrund-approve', '--socket', '/run/sigrund/approve.sock',
                     '--epoch-file', '/var/lib/sigrund-v3/host-epoch.json', '--identity', str(identity)])
        self.transcript = bytearray()
        fcntl.ioctl(self.fd, termios.TIOCPKT, struct.pack('i', 1))
        self.connections = 0
        self.invocation = None
        self.wait_connected()

    def wait_connected(self):
        invocation = subprocess.check_output(['systemctl', 'show', '-p', 'InvocationID', '--value', 'sigrund.service'], text=True).strip()
        previous = self.connections if invocation == self.invocation else 0
        def connected():
            log = subprocess.check_output(['journalctl', '-u', 'sigrund.service', '_SYSTEMD_INVOCATION_ID=' + invocation,
                                           '-o', 'cat', '--no-pager'], text=True)
            count = 0
            for line in log.splitlines():
                try:
                    event = json.loads(line)
                except ValueError:
                    continue
                if event.get('event') == 'SOCKET_ADMITTED' and event.get('broker') and event.get('requester_pid') == self.pid:
                    count += 1
            return count if count > previous else None
        self.connections = wait_for(connected, 'installed approver admission')
        self.invocation = invocation
        # Reconnection discards prior confirmation input before admission.
        # Drain that older flush notification before submitting another request.
        while select.select([self.fd], [], [], 0)[0]:
            packet = os.read(self.fd, 65536)
            if not packet:
                raise RuntimeError('approver ended after admission')
            if packet[0] == 0:
                self.transcript.extend(packet[1:])

    def confirm(self, process, approve=True):
        deadline = time.monotonic() + 15
        pending = bytearray()
        flushed = False
        while time.monotonic() < deadline:
            if select.select([self.fd], [], [], 0.05)[0]:
                packet = os.read(self.fd, 65536)
                if not packet:
                    raise RuntimeError('approver ended before review')
                if packet[0] == 0:
                    self.transcript.extend(packet[1:])
                    pending.extend(packet[1:])
                else:
                    flushed |= bool(packet[0] & termios.TIOCPKT_FLUSHREAD)
                if flushed and b'Approve and sign? [y/yes/n/no] ' in pending:
                    if approve:
                        os.write(self.fd, b'yes\n')
                    return pending.decode()
            if process.poll() is not None:
                out, err = process.communicate()
                raise RuntimeError('request ended before review: ' + repr((process.returncode, out, err)))
        raise RuntimeError('no private review: ' + pending.decode(errors='replace'))

    def close(self):
        os.kill(self.pid, signal.SIGTERM)
        os.waitpid(self.pid, 0)
        os.close(self.fd)


def client(route, owner):
    target = 'self' if route == 'a-self' else ('host' if route == 'a-host' else 'registered:container-b')
    args = ['--target', target, '--security-profile', 'host-baseline' if target == 'host' else 'namespace-selinux-v1']
    if target == 'host':
        args += ['--target-uid', '65534', '--target-gid', '65534', '--cwd', '/']
    else:
        args += ['--account', 'ns_service', '--cwd', '/srv/service']
    args += ['--', TOOL]
    if route == 'host-b':
        return ['systemd-run', '--quiet', '--wait', '--pipe', '--collect', '--unit=sigrund-namespace-host-client',
                '--property=User=' + owner,
                '--property=SELinuxContext=system_u:system_r:sigrund_requester_t:s0',
                '/usr/bin/sigrun', '--socket', SOCKET, *args]
    return ['python3', str(HERE / 'environment.py'), 'client', 'a', '--', *args]


def records():
    return [json.loads(line) for line in Path('/var/log/sigrund-v3/audit.jsonl').read_text().splitlines()]


def wait_for(predicate, description):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.02)
    raise AssertionError('timed out: ' + description)


def execution_id(review):
    return re.search(r'exec_id = "([0-9a-f-]+)"', review).group(1)


def audit(execution):
    return [row for row in records() if row.get('exec_id') == execution]


def consumed(execution):
    with closing(sqlite3.connect('file:/var/lib/sigrund-v3/state.sqlite?mode=ro', uri=True)) as connection:
        return connection.execute('SELECT count(*) FROM consumed_grants WHERE exec_id=?', (execution,)).fetchone()[0]


def job(execution):
    return Path('/sys/fs/cgroup/system.slice/sigrund.service/jobs/job-' + execution)


def workload_descendants(execution):
    ready = wait_for(lambda: next((row for row in audit(execution) if row['event_type'] == 'EXEC_READY_TO_EXEC'), None),
                     'primary child identity')
    primary = ready['child_pid']
    def forked():
        pids = (job(execution) / 'cgroup.procs').read_text().split()
        for pid in pids:
            try:
                descriptor = os.pidfd_open(int(pid))
                try:
                    # PIDFD_GET_INFO with the published 64-byte v0 prefix.
                    # Unlike proc status, this does not need producer-domain
                    # procfs read permissions in the administrative harness.
                    info = bytearray(64)
                    struct.pack_into('=Q', info, 0, 1)  # PIDFD_INFO_PID
                    fcntl.ioctl(descriptor, 0xc040ff0b, info, True)
                finally:
                    os.close(descriptor)
                assert struct.unpack_from('=Q', info)[0] & 1
                if struct.unpack_from('=I', info, 24)[0] == primary:
                    return pids
            except ProcessLookupError:
                pass
    return wait_for(forked, 'actual workload forked descendant')


def assert_execution(execution, namespace=True):
    rows = wait_for(lambda: audit(execution) if any(row['event_type'] == 'EXEC_EXIT' for row in audit(execution)) else None,
                    'durable execution exit')
    types = [row['event_type'] for row in rows]
    assert types.index('AUTH_COMMIT') < types.index('EXEC_READY_TO_EXEC') < types.index('EXEC_EXIT'), types
    assert consumed(execution) == 1
    ready = next(row for row in rows if row['event_type'] == 'EXEC_READY_TO_EXEC')
    if namespace:
        facts = ready['execution_observed']
        assert facts['exact_seccomp_program_verified'] and facts['private_run_verified']
        assert facts['ambient_lsm']['context'] == 'system_u:system_r:sigrund_workload_t:s0:c1,c2'
        assert all(not values for values in ready['observed_post_exec_capabilities'].values())
    wait_for(lambda: not job(execution).exists(), 'whole-job cgroup removal')
    return rows


def register_b(restart_environment=False):
    subprocess.run(['systemctl', 'stop', 'sigrund-namespace-b-anchor.service'], capture_output=True)
    if restart_environment:
        subprocess.run(['systemctl', 'stop', 'sigrund-namespace-b-init.service'], capture_output=True)
    if subprocess.run(['systemctl', 'is-active', '--quiet', 'sigrund-namespace-b-init.service']).returncode:
        subprocess.run(['python3', str(HERE / 'environment.py'), 'init', 'b'], check=True)
        wait_for(lambda: Path('/sys/fs/cgroup/system.slice/sigrund-namespace-b-init.service/cgroup.procs').exists(), 'running B')
    subprocess.run(['python3', str(HERE / 'environment.py'), 'anchor', 'b', '--registration', 'container-b'], check=True)


def requester(owner, unit, command, *, wait=True):
    return ['systemd-run', '--quiet', '--collect', '--unit=' + unit,
            '--property=User=' + owner, '--property=KillMode=control-group',
            '--property=RuntimeMaxSec=60s',
            '--property=SELinuxContext=system_u:system_r:sigrund_requester_t:s0',
            *(['--wait', '--pipe'] if wait else []), *command]


def handoffs(result):
    directory = Path('/var/lib/sigrund-namespace-lab/handoffs')
    directory.mkdir(mode=0o700, exist_ok=True)
    probe = '/usr/local/libexec/sigrund-namespace/handoff-probe'
    subprocess.run(['cc', '-static', '-O2', '-Wall', '-Wextra', '-Werror', '-I', str(HERE),
                    str(HERE / 'handoff-probe.c'), '-o', probe], check=True)
    subprocess.run(['chcon', 'system_u:object_r:sigrund_daemon_exec_t:s0', probe], check=True)
    profile = tomllib.loads(Path('/etc/sigrund/config.toml').read_text())['namespace_profiles'][0]
    # The ABI version is shared with the compiled launcher, never duplicated.
    version = int(re.search(r'#define SG_PAYLOAD_VERSION (\d+)', (HERE / 'launcher_abi.h').read_text()).group(1))
    base = {'version': version, 'uid': 12001, 'gid': 12001, 'mask': 63,
            'last_cap': int(Path('/proc/sys/kernel/cap_last_cap').read_text()),
            'enter_mask': 1, 'cwd': '/', 'argv': ['/unreachable'], 'envp': [], 'constraints': profile, 'producer_guard': True}
    try:
        for case in ('unsealed', 'truncated', 'wrong-version', 'missing-producer-guard', 'missing-fds', 'bad-bootstrap', 'bad-namespace'):
            payload = dict(base)
            if case == 'wrong-version':
                payload['version'] += 1
            if case == 'missing-producer-guard':
                del payload['producer_guard']
            path = directory / (case + '.json')
            path.write_text('{' if case == 'truncated' else json.dumps(payload))
            test = subprocess.run(['systemd-run', '--quiet', '--wait', '--pipe', '--collect',
                                   '--unit=sigrund-namespace-handoff', '--property=RuntimeMaxSec=10s',
                                   '--property=KillMode=control-group', probe, str(path), case], capture_output=True, timeout=15)
            assert test.returncode == 0, (case, test.stdout, test.stderr)
            group = Path('/sys/fs/cgroup/system.slice/sigrund-namespace-handoff.service')
            wait_for(lambda: not group.exists(), 'malformed native handoff cleanup')
            result['cases'].append({'name': 'production-native-handoff-' + case, 'result': 'passed', 'stdout': test.stdout.decode()})
    finally:
        # Retain the source and evidence, without leaving an extra producer entry.
        Path(probe).unlink()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def exclusions(args, result):
    directory = Path('/usr/local/libexec/sigrund-namespace/raw-cases')
    directory.mkdir(mode=0o755, exist_ok=True)
    script = directory / 'raw-client.py'
    shutil.copyfile(HERE / 'raw-client.py', script)
    script.chmod(0o644)
    latest = next(row for row in reversed(records()) if row['event_type'] == 'EXEC_READY_TO_EXEC'
                  and row['target_binding']['kind'] == 'process_environment')
    account = pwd.getpwnam(args.owner)
    command = {'allow_interpreted_script': False, 'argv': [TOOL], 'cwd': '/srv/service',
               'executable_path': TOOL, 'stdin_policy': 'null', 'tty_mode': 'stdio'}
    context = {'caller_env_allowlist': [], 'capabilities': [],
               'env_exact': {'LANG': 'C.UTF-8', 'PATH': '/usr/sbin:/usr/bin'}, 'umask': 63}
    intent = {'account': {'kind': 'numeric', 'uid': 12001, 'gid': 12001, 'supplementary_gids': []},
              'caller_env': {}, 'command': command, 'execution_context': context,
              'policy': {'mode': 'one_time', 'ttl_secs': 900}, 'security_profile': 'namespace-selinux-v1',
              'target': {'kind': 'registered', 'id': 'container-b'}}
    now = int(time.time())
    grant = subprocess.check_output(['sigrundctl', 'uuidv7'], text=True).strip()
    warrant = {'version': '3.0', 'approval_exec_id': None, 'caller_env': {}, 'request_origin': 'client_full',
               'command': {**command, 'executable_trust': latest['executable_trust'], 'stdin_sha256': None},
               'execution_context': {**context, 'target_uid': 12001, 'target_gid': 12001, 'supplementary_gids': [],
                                     'post_exec_capabilities': {key: [] for key in ('ambient', 'bounding', 'effective', 'inheritable', 'permitted')}},
               'grant_id': grant, 'host_id': latest['host_id'], 'intent': intent,
               'intent_sha256': hashlib.sha256(canonical(intent)).hexdigest(),
               'policy': {'mode': 'one_time', 'not_before': now, 'not_after': now + 900},
               'requester_uid': account.pw_uid, 'requester_gid': account.pw_gid,
               'target_binding': latest['target_binding'], 'security_constraints': latest['security_constraints']}
    csr = args.artifacts / 'excluded.csr'
    csr.write_bytes(canonical(warrant))
    pae = args.artifacts / 'excluded.pae'
    subprocess.run(['sigrundctl', 'csr-pae', '--csr', str(csr), '--pae', str(pae)], check=True)
    subprocess.run(['ssh-keygen', '-Y', 'sign', '-f', str(args.identity), '-n', 'sigrun.warrant.v3', str(pae)], check=True, capture_output=True)
    envelope_path = args.artifacts / 'excluded-envelope.json'
    subprocess.run(['sigrundctl', 'pack-warrant', '--csr', str(csr), '--signature', str(pae) + '.sig',
                    '--signer-id', 'namespace-root', '--output', str(envelope_path)], check=True)
    envelope = json.loads(envelope_path.read_text())
    for mode in ('full_csr', 'signed'):
        body = {'version': '3.0', 'mode': mode, 'tty_mode': 'stdio', 'caller_env': {}}
        body.update({'csr_payload': csr.read_text()} if mode == 'full_csr' else {'dsse_envelope': envelope})
        path = directory / (grant + '-' + mode + '.json')
        path.write_bytes(canonical(body))
        path.chmod(0o644)
        test = subprocess.run(requester(args.owner, 'sigrund-namespace-excluded', ['/usr/bin/python3', str(script), str(path)]), capture_output=True, timeout=12)
        assert test.returncode == 0, (test.stdout, test.stderr)
        observed = json.loads(test.stdout)
        execution = observed['decision']['exec_id']
        rows = wait_for(lambda: audit(execution), 'namespace exclusion private diagnosis')
        assert consumed(execution) == 0 and all(row['event_type'] != 'AUTH_COMMIT' for row in rows)
        assert any('thin intent' in row.get('reason', '') for row in rows), rows
        result['cases'].append({'name': 'raw-namespace-' + mode + '-scheduled-timeout-without-consumption',
                                'result': 'passed', 'public': observed, 'audit': rows})
    for option in ('--full-only', '--export-csr'):
        output = args.artifacts / 'must-not-be-exported.csr'
        command = ['/usr/bin/sigrun', '--socket', '/nonexistent/no-submission', '--target', 'registered:container-b',
                   '--security-profile', 'namespace-selinux-v1', '--account', 'ns_service', option,
                   *([str(output)] if option == '--export-csr' else []), '--', TOOL]
        test = subprocess.run(command, capture_output=True)
        assert test.returncode == 64 and not output.exists(), (test.stdout, test.stderr)
        result['cases'].append({'name': 'namespace-local-rejection-' + option[2:], 'result': 'passed'})
    counterfeit = directory / 'counterfeit.py'
    shutil.copyfile(HERE / 'counterfeit.py', counterfeit)
    counterfeit.chmod(0o644)
    test = subprocess.run(requester(args.owner, 'sigrund-namespace-counterfeit', ['/usr/bin/unshare', '--map-auto', '--map-root-user',
                          '/usr/bin/python3', str(counterfeit), str(directory / (grant + '-signed.json'))]), capture_output=True, timeout=20)
    assert test.returncode == 0, (test.stdout, test.stderr)
    result['cases'].append({'name': 'qualified-rootless-source-counterfeit-peers-disclose-no-data-or-rights',
                            'result': 'passed', 'observed': json.loads(test.stdout)})


def security(args, approver, result):
    handoffs(result)
    probe = '/usr/local/libexec/sigrund-namespace/security-probe'
    subprocess.run(['cc', '-O2', '-Wall', '-Wextra', '-Werror', str(HERE / 'security-probe.c'), '-o', probe], check=True)
    subprocess.run(['restorecon', probe], check=True)
    test = subprocess.run(requester(args.owner, 'sigrund-namespace-forgery',
                          ['/usr/bin/unshare', '--map-auto', '--map-root-user', probe, 'forgery']), capture_output=True)
    assert test.returncode == 0 and b'producer-entry=denied' in test.stdout, (test.stdout, test.stderr)
    result['cases'].append({'name': 'rootless-requester-cannot-forge-reserved-labels-or-enter-init',
                            'result': 'passed', 'stdout': test.stdout.decode()})
    command = client('a-host', args.owner)
    command[-1] = probe
    process = subprocess.Popen([*command, 'forgery'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    review = approver.confirm(process)
    stdout, stderr = process.communicate(timeout=15)
    assert process.returncode == 0 and b'producer-entry=denied' in stdout, (stdout, stderr)
    execution = execution_id(review)
    rows = assert_execution(execution, namespace=False)
    result['cases'].append({'name': 'nonroot-host-workload-cannot-forge-reserved-labels-or-enter-producer',
                            'result': 'passed', 'exec_id': execution, 'stdout': stdout.decode(), 'audit': rows})
    control = 'sigrund-namespace-trace-control'
    subprocess.run(requester(args.owner, control, ['/usr/bin/unshare', '--map-auto', '--map-root-user', '--fork',
                   '/usr/bin/setpriv', '--reuid=12001', '--regid=12001', '--clear-groups', '/usr/bin/sleep', '50'], wait=False), check=True)
    try:
        def control_pid():
            directory = Path('/sys/fs/cgroup/system.slice/' + control + '.service/cgroup.procs')
            for pid in directory.read_text().split() if directory.exists() else []:
                try:
                    if os.readlink('/proc/' + pid + '/exe') == '/usr/bin/sleep':
                        return pid
                except FileNotFoundError:
                    pass
        pid = wait_for(control_pid, 'different-UID control task')
        test = subprocess.run(requester(args.owner, 'sigrund-namespace-trace-positive', [probe, 'trace', pid]), capture_output=True)
        assert test.returncode == 0 and b'attach=0' in test.stdout, (test.stdout, test.stderr)
        result['cases'].append({'name': 'namespace-owner-can-trace-different-UID-without-workload-guard',
                                'result': 'passed', 'stdout': test.stdout.decode(),
                                'target_status': Path('/proc/' + pid + '/status').read_text()})
    finally:
        subprocess.run(['systemctl', 'stop', control], check=True)
    process = subprocess.Popen([*client('a-self', args.owner), 'wait'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        review = approver.confirm(process)
        execution = execution_id(review)
        assert select.select([process.stdout], [], [], 10)[0]
        prefix = os.read(process.stdout.fileno(), 4096)
        assert b'destination=A' in prefix, prefix
        ready = wait_for(lambda: next((row for row in audit(execution) if row['event_type'] == 'EXEC_READY_TO_EXEC'), None), 'exec-stop audit')
        test = subprocess.run(requester(args.owner, 'sigrund-namespace-trace-denied',
                              [probe, 'trace', str(ready['child_pid'])]), capture_output=True)
        assert test.returncode == 1 and b'attach=-1 errno=1' in test.stdout, (test.stdout, test.stderr)
        result['cases'].append({'name': 'namespace-owner-injection-denied-after-self-release',
                                'result': 'passed', 'exec_id': execution, 'stdout': test.stdout.decode()})
        subprocess.run(['semodule', '-B'], check=True)
        process.communicate(timeout=10)
        rows = assert_execution(execution)
        result['cases'].append({'name': 'policy-reload-terminates-live-job-retains-consumption',
                                'result': 'passed', 'exec_id': execution, 'audit': rows})
    finally:
        if process.poll() is None:
            subprocess.run(['systemctl', 'stop', 'sigrund-namespace-a-client.service'], capture_output=True)
            process.kill()
            process.communicate(timeout=5)
    setup_module = Path('/var/lib/sigrund-namespace-lab/sigrund_namespace_setup_failure.cil')
    setup_module.write_text('(deny sigrund_daemon_t sigrund_daemon_t (cap_userns (sys_admin)))\n')
    subprocess.run(['systemctl', 'stop', 'sigrund.service'], check=True)
    subprocess.run(['semodule', '-i', str(setup_module)], check=True)
    try:
        subprocess.run(['systemctl', 'start', 'sigrund.service'], check=True)
        approver.wait_connected()
        register_b(restart_environment=True)
        process = subprocess.Popen(client('host-b', args.owner), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        review = approver.confirm(process)
        execution = execution_id(review)
        stdout, stderr = process.communicate(timeout=10)
        assert process.returncode != 0 and not stdout, (stdout, stderr)
        rows = wait_for(lambda: audit(execution) if any(row['event_type'] != 'AUTH_COMMIT' for row in audit(execution)) else None,
                        'production setup failure')
        assert consumed(execution) == 1 and any(row['event_type'] == 'AUTH_COMMIT' for row in rows), rows
        assert all(row['event_type'] != 'EXEC_READY_TO_EXEC' for row in rows), rows
        wait_for(lambda: not job(execution).exists(), 'failed production setup cleanup')
        result['cases'].append({'name': 'production-namespace-entry-failure-retains-consumption-without-output',
                                'result': 'passed', 'exec_id': execution, 'audit': rows})
    finally:
        subprocess.run(['systemctl', 'stop', 'sigrund.service'], check=True)
        subprocess.run(['semodule', '-r', setup_module.stem], check=True)
    subprocess.run(['systemctl', 'stop', 'sigrund-namespace-b-init.service'], capture_output=True)
    for domain in ('sigrund_requester_t', 'sigrund_daemon_t', 'sigrund_host_workload_t', 'sigrund_workload_t'):
        subprocess.run(['systemctl', 'restart', 'sigrund.service'], check=True)
        subprocess.run(['semanage', 'permissive', '-a', domain], check=True)
        try:
            if domain in ('sigrund_requester_t', 'sigrund_daemon_t', 'sigrund_host_workload_t', 'sigrund_workload_t'):
                command = ['/usr/bin/unshare', '--map-auto', '--map-root-user', '/usr/bin/sigrun', '--socket', SOCKET,
                           '--target', 'registered:container-b', '--security-profile', 'namespace-selinux-v1',
                           '--account', 'ns_service', '--cwd', '/srv/service', '--', TOOL]
                test = subprocess.run(requester(args.owner, 'sigrund-namespace-permissive-peer', command), capture_output=True, timeout=10)
                assert test.returncode != 0 and b'authenticate host daemon' in test.stderr, (test.stdout, test.stderr)
            subprocess.run(['systemctl', 'stop', 'sigrund.service'], check=True)
            subprocess.run(['systemctl', 'reset-failed', 'sigrund.service'], capture_output=True)
            test = subprocess.run(['systemctl', 'start', 'sigrund.service'], capture_output=True)
            assert test.returncode != 0
            status = subprocess.check_output(['systemctl', 'show', '-p', 'ExecMainStatus', '--value', 'sigrund.service'], text=True).strip()
            assert status == '78', status
            result['cases'].append({'name': 'startup-rejects-permissive-' + domain, 'result': 'passed'})
        finally:
            subprocess.run(['systemctl', 'stop', 'sigrund.service'], check=True)
            subprocess.run(['semanage', 'permissive', '-d', domain], check=True)
    subprocess.run(['systemctl', 'reset-failed', 'sigrund.service'], capture_output=True)
    subprocess.run(['systemctl', 'start', 'sigrund.service'], check=True)
    subprocess.run(['setenforce', '0'], check=True)
    try:
        command = ['/usr/bin/unshare', '--map-auto', '--map-root-user', '/usr/bin/sigrun', '--socket', SOCKET,
                   '--target', 'registered:container-b', '--security-profile', 'namespace-selinux-v1',
                   '--account', 'ns_service', '--cwd', '/srv/service', '--', TOOL]
        test = subprocess.run(requester(args.owner, 'sigrund-namespace-disabled-peer', command), capture_output=True, timeout=10)
        assert test.returncode != 0 and b'authenticate host daemon' in test.stderr, (test.stdout, test.stderr)
        subprocess.run(['systemctl', 'stop', 'sigrund.service'], check=True)
        test = subprocess.run(['systemctl', 'start', 'sigrund.service'], capture_output=True)
        assert test.returncode != 0
        result['cases'].append({'name': 'disabled-enforcement-rejects-client-authentication-and-daemon-startup', 'result': 'passed'})
    finally:
        subprocess.run(['systemctl', 'stop', 'sigrund.service'], check=True)
        subprocess.run(['setenforce', '1'], check=True)
    subprocess.run(['systemctl', 'reset-failed', 'sigrund.service'], capture_output=True)
    subprocess.run(['systemctl', 'start', 'sigrund.service'], check=True)
    # Exercise unreadable kernel state while keeping both domains enforcing.
    module = Path('/var/lib/sigrund-namespace-lab/sigrund_namespace_unreadable.cil')
    module.write_text('(deny sigrund_daemon_t security_t (file (open)))\n'
                      '(deny sigrund_requester_t security_t (security (compute_av)))\n')
    subprocess.run(['semodule', '-i', str(module)], check=True)
    try:
        test = subprocess.run(requester(args.owner, 'sigrund-namespace-unreadable-peer', command), capture_output=True, timeout=10)
        assert test.returncode != 0 and b'authenticate host daemon' in test.stderr, (test.stdout, test.stderr)
        subprocess.run(['systemctl', 'stop', 'sigrund.service'], check=True)
        test = subprocess.run(['systemctl', 'start', 'sigrund.service'], capture_output=True)
        assert test.returncode != 0
        status = subprocess.check_output(['systemctl', 'show', '-p', 'ExecMainStatus', '--value', 'sigrund.service'], text=True).strip()
        assert status == '78', status
        result['cases'].append({'name': 'unreadable-enforcement-rejects-client-authentication-and-startup', 'result': 'passed'})
    finally:
        subprocess.run(['systemctl', 'stop', 'sigrund.service'], check=True)
        subprocess.run(['semodule', '-r', module.stem], check=True)
    # Run the actual service image in the administrator's unconfined context.
    # Its own startup check must reject this, before publishing listeners.
    dropin = Path('/run/systemd/system/sigrund.service.d') / ('namespace-context-' + uuid.uuid4().hex + '.conf')
    dropin.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    context = Path('/proc/self/attr/current').read_text().strip('\0\n')
    dropin.write_text('[Service]\nSELinuxContext=' + context + '\nExecStart=\n'
                      "ExecStart=/usr/bin/sh -c 'exec /usr/libexec/sigrund/sigrund --foreground "
                      '--state-dir /var/lib/sigrund-v3 --log-path /var/log/sigrund-v3/audit.jsonl '
                      "--socket /run/sigrund/client.sock --approval-socket /run/sigrund/approve.sock'\n")
    try:
        subprocess.run(['systemctl', 'daemon-reload'], check=True)
        subprocess.run(['systemctl', 'reset-failed', 'sigrund.service'], capture_output=True)
        test = subprocess.run(['systemctl', 'start', 'sigrund.service'], capture_output=True)
        assert test.returncode != 0
        status = subprocess.check_output(['systemctl', 'show', '-p', 'ExecMainStatus', '--value', 'sigrund.service'], text=True).strip()
        assert status == '78', status
        result['cases'].append({'name': 'unconfined-daemon-context-rejected-before-listeners', 'result': 'passed'})
    finally:
        subprocess.run(['systemctl', 'stop', 'sigrund.service'], check=True)
        dropin.unlink()
        subprocess.run(['systemctl', 'daemon-reload'], check=True)
    subprocess.run(['systemctl', 'reset-failed', 'sigrund.service'], capture_output=True)
    subprocess.run(['systemctl', 'start', 'sigrund.service'], check=True)
    approver.wait_connected()
    register_b(restart_environment=True)


def lifecycle(args, approver, result):
    invocation = client('host-b', args.owner)
    process = subprocess.Popen(invocation, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    review = approver.confirm(process, approve=False)
    execution = execution_id(review)
    subprocess.run(['sigrundctl', 'target', 'revoke', 'container-b', '--socket', SOCKET], check=True)
    stdout, stderr = process.communicate(timeout=10)
    assert process.returncode != 0 and b'TIMEOUT' in stderr and not stdout, (stdout, stderr)
    assert consumed(execution) == 0
    rows = wait_for(lambda: audit(execution), 'review-revocation private outcome')
    assert all(row['event_type'] != 'AUTH_COMMIT' for row in rows)
    result['cases'].append({'name': 'revocation-during-review', 'result': 'passed', 'exec_id': execution, 'audit': rows})
    assert subprocess.run(['systemctl', 'is-active', '--quiet', 'sigrund-namespace-b-init.service']).returncode == 0
    register_b()
    approver.wait_connected()
    invocation += ['wait']
    process = subprocess.Popen(invocation, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        review = approver.confirm(process)
        execution = execution_id(review)
        assert select.select([process.stdout], [], [], 10)[0], 'workload did not start'
        prefix = os.read(process.stdout.fileno(), 4096)
        assert b'destination=B' in prefix, prefix
        pids = workload_descendants(execution)
        descriptors = [os.pidfd_open(int(pid)) for pid in pids]
        try:
            subprocess.run(['sigrundctl', 'target', 'revoke', 'container-b', '--socket', SOCKET], check=True)
            process.communicate(timeout=10)
            rows = assert_execution(execution)
            for descriptor in descriptors:
                assert select.select([descriptor], [], [], 0)[0], 'descendant survived revocation'
        finally:
            for descriptor in descriptors:
                os.close(descriptor)
        result['cases'].append({'name': 'revocation-after-release-kills-descendants-retains-consumption',
                                'result': 'passed', 'exec_id': execution, 'audit': rows})
        assert subprocess.run(['systemctl', 'is-active', '--quiet', 'sigrund-namespace-b-init.service']).returncode == 0
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=5)
    subprocess.run(['systemctl', 'restart', 'sigrund.service'], check=True)
    approver.wait_connected()
    # The old registered name has no binding in the new epoch.
    process = subprocess.run(client('host-b', args.owner), capture_output=True, timeout=15)
    assert process.returncode != 0 and b'TIMEOUT' in process.stderr and not process.stdout
    result['cases'].append({'name': 'restart-retires-old-registration', 'result': 'passed'})
    register_b(restart_environment=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--owner', default='nsrequester')
    parser.add_argument('--identity', type=Path, default=Path('/var/lib/sigrund-namespace-lab/approver'))
    parser.add_argument('--route', action='append', choices=('host-b', 'a-b', 'a-self', 'a-host'))
    parser.add_argument('--lifecycle', action='store_true')
    parser.add_argument('--security', action='store_true')
    parser.add_argument('--exclusions', action='store_true')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('host root required')
    args.artifacts.mkdir(mode=0o700)
    result = {'cases': [], 'passed': False}
    approver = Approver(args.identity)
    try:
        for route in args.route or ('host-b', 'a-b', 'a-host', 'a-self'):
            invocation = client(route, args.owner)
            process = subprocess.Popen(invocation, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                review = approver.confirm(process)
                stdout, stderr = process.communicate(timeout=15)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate(timeout=5)
            (args.artifacts / (route + '.review')).write_text(review)
            (args.artifacts / (route + '.stdout')).write_bytes(stdout)
            (args.artifacts / (route + '.stderr')).write_bytes(stderr)
            assert process.returncode == 0, (route, process.returncode, stdout, stderr)
            expected = 'host' if route == 'a-host' else ('A' if route == 'a-self' else 'B')
            assert b'destination=' + expected.encode() in stdout, (route, stdout)
            if route != 'a-host':
                assert 'Namespace execution request' in review, review
                assert b'uid=12001 gid=12001 groups=0' in stdout, stdout
                assert b'nnp=1 seccomp=2' in stdout, stdout
                assert b'context=system_u:system_r:sigrund_workload_t:s0:c1,c2' in stdout, stdout
                assert b'getppid=-1 errno=13' in stdout, stdout
                assert b'secret=-1 secret_errno=13' in stdout, stdout
            else:
                assert b'context=system_u:system_r:sigrund_host_workload_t:s0' in stdout, stdout
            execution = execution_id(review)
            rows = assert_execution(execution, route != 'a-host')
            result['cases'].append({'name': route, 'result': 'passed', 'command': invocation,
                                    'stdout': stdout.decode(), 'stderr': stderr.decode(), 'exec_id': execution,
                                    'audit': rows})
            print('passed ' + route, flush=True)
        if args.lifecycle:
            lifecycle(args, approver, result)
        if args.security:
            security(args, approver, result)
        if args.exclusions:
            exclusions(args, result)
        if args.lifecycle or args.security:
            process = subprocess.Popen(client('host-b', args.owner), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            review = approver.confirm(process)
            stdout, stderr = process.communicate(timeout=15)
            assert process.returncode == 0 and b'destination=B' in stdout, (stdout, stderr)
            execution = execution_id(review)
            rows = assert_execution(execution)
            result['cases'].append({'name': 'fresh-registration-success-after-restart-and-policy-restoration',
                                    'result': 'passed', 'exec_id': execution, 'audit': rows})
        result['passed'] = True
    finally:
        (args.artifacts / 'approver.log').write_bytes(approver.transcript)
        approver.close()
        (args.artifacts / 'result.json').write_text(json.dumps(result, indent=2) + '\n')


if __name__ == '__main__':
    main()
