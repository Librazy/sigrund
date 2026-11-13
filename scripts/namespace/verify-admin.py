#!/usr/bin/env python3
"""Compare host and initial-userns admin execution on a disposable systemd host.

--producer also requires the packaged SELinux modules and daemon entrypoint at
/usr/libexec/sigrund/sigrund. It verifies the unchanged host workload policy.
"""
import argparse
import array
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import pwd
import runpy
import secrets
import shutil
import socket
import struct
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
EX = runpy.run_path(str(HERE / 'verify-execution.py'))
REVIEW, API, REPO = EX['REVIEW'], EX['API'], EX['REPO']


class RootContainer(EX['ExecutionContainer']):
    def start(self, *, user_namespace=False):
        self.process = subprocess.Popen(['unshare', *(['--user', '--map-root-user'] if user_namespace else []), '--mount', '--cgroup', '--ipc', '--net',
            '--uts', '--time', '--pid', '--fork', '--kill-child', str(self.root / 'anchor'),
            'init', str(self.root), '/run/client.sock.anchor'], stderr=self.error)
        def connected():
            if self.process.poll() is not None:
                raise AssertionError(self.error.name)
            first = Path(f'/proc/{self.process.pid}/task/{self.process.pid}/children').read_text().split()
            if len(first) != 1:
                return False
            second = Path(f'/proc/{first[0]}/task/{first[0]}/children').read_text().split()
            if len(second) != 1:
                return False
            self.pid = int(second[0])
            fields = Path(f'/proc/{self.pid}/syscall').read_text().split()
            return len(fields) > 1 and fields[0] == '0' and os.readlink(
                f'/proc/{self.pid}/fd/{int(fields[1], 0)}').startswith('socket:')
        API['wait_for'](connected, 'rootful container anchor')
        return self.pid


class ProducerFixture(API['Fixture']):
    def launch(self, **kwargs):
        self.original_group = self.group
        self.unit = 'sigrund-admin-producer-' + secrets.token_hex(6) + '.service'
        for path, label in ((self.base, 'sigrund_runtime_t'), (self.state, 'sigrund_state_t'),
                            (self.log.parent, 'sigrund_log_t'), (self.client.parent, 'sigrund_runtime_t')):
            subprocess.run(['chcon', '-R', '-t', label, str(path)], check=True)
        for path in (self.base / 'config', self.base / 'signers'):
            subprocess.run(['chcon', '-t', 'sigrund_etc_t', str(path)], check=True)
        self.journal = subprocess.Popen(['journalctl', '--follow', '--no-pager', '--output=cat',
            '--unit=' + self.unit], stdout=self.stderr, stderr=subprocess.DEVNULL)
        self.process = subprocess.Popen(['systemd-run', '--quiet', '--wait', '--collect',
            '--unit=' + self.unit, '--property=Delegate=yes',
            '--property=StandardError=journal', '--property=StandardOutput=journal', '--property=KillMode=control-group',
            '--property=RuntimeMaxSec=300s', '--property=SELinuxContext=system_u:system_r:sigrund_daemon_t:s0',
            '/usr/libexec/sigrund/sigrund', '--foreground', '--config', str(self.base / 'config'),
            '--signers', str(self.base / 'signers'), '--state-dir', str(self.state), '--log-path', str(self.log),
            '--socket', str(self.client), '--approval-socket', str(self.approval)],
            stdout=self.stdout, stderr=self.stderr)
        def ready():
            if self.process.poll() is not None:
                raise AssertionError(self.diagnostics.read_text())
            return self.client.exists() and 'DAEMON_READY' in self.diagnostics.read_text()
        API['wait_for'](ready, 'packaged producer startup')
        self.group = Path('/sys/fs/cgroup' + subprocess.check_output(
            ['systemctl', 'show', self.unit, '-p', 'ControlGroup', '--value'], text=True).strip())
        return self

    def cleanup(self):
        if hasattr(self, 'unit'):
            REVIEW['SUPPORT']['stop_service'](self.unit)
            if self.process:
                self.process.wait(timeout=10)
            self.journal.terminate()
            self.journal.wait(timeout=5)
            self.group = self.original_group
        super().cleanup()


def producer_submit(peer, body):
    # This regular stderr sink must be writable by the packaged daemon. The
    # ordinary unconfined fixture's user_tmp_t memfd is deliberately denied.
    read, write = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
    regular = os.memfd_create('admin-output-observation', os.MFD_CLOEXEC)
    os.setxattr(regular, 'security.selinux', b'system_u:object_r:sigrund_runtime_t:s0')
    peer.sendmsg([API['frame'](1, body)], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
        array.array('i', [write, regular]))])
    os.close(write)
    return read, regular


def reviewed_request(f, body):
    import time
    approver, peer = API['broker'](f), API['requester_socket'](f)
    started = time.monotonic()
    endpoints = API['submit'](peer, body)
    return approver, peer, endpoints, started, API['review'](approver)


def configure(f, profiles):
    for profile in profiles:
        rule = {'requester_uids': [65534], 'target_scope': 'registered:container-b',
                'target_uids': [0, 33], 'target_gids': [0, 33], 'supplementary_gids': [104],
                'profile_sha256': hashlib.sha256(API['canonical'](profile)).hexdigest(), 'cross_owner': True}
        with (f.base / 'config').open('a') as output:
            output.write(REVIEW['table']('namespace_profiles', profile))
            for scope in ('registered:container-b', 'self'):
                output.write(REVIEW['table']('namespace_rules', {**rule, 'target_scope': scope}))
        with (f.base / 'signers').open('a') as output:
            for scope in ('registered:container-b', 'self'):
                output.write(REVIEW['table']('signers.namespace_rules', {**rule, 'target_scope': scope}))


def request(f, profile, uid=0, groups=(), caps=(), args=()):
    body = API['hello'](API['payload'](f))
    body['intent'].update(target={'kind': 'registered', 'id': 'container-b'},
        account={'kind': 'numeric', 'uid': uid, 'gid': uid, 'supplementary_gids': list(groups)},
        security_profile=profile['profile_id'])
    body['intent']['execution_context']['capabilities'] = list(caps)
    body['intent']['command'].update(executable_path=str(f.commands / 'tool'),
        argv=[str(f.commands / 'tool'), *args], cwd='/')
    return body


def denied(f, body, *, refuse=False):
    operator = API['broker'](f)
    peer = API['requester_socket'](f)
    endpoints = API['submit'](peer, body)
    import time
    started = time.monotonic()
    try:
        if refuse:
            API['refuse'](operator, API['review'](operator))
        API['timeout'](peer, endpoints, started)
    finally:
        operator.close()


def inside(args):
    parent = Path('/sys/fs/cgroup' + Path('/proc/self/cgroup').read_text().strip().split('::')[1])
    assert parent.name.startswith('sigrund-admin-')
    (parent / 'runner').mkdir()
    (parent / 'runner/cgroup.procs').write_text(str(os.getpid()))
    (parent / 'cgroup.subtree_control').write_text('+memory +pids')
    tempfile.tempdir = '/usr/local'
    work = Path(tempfile.mkdtemp(prefix='sigrund-admin-container-', dir='/run'))
    work.chmod(0o755)
    fixture = (ProducerFixture if args.producer else API['Fixture'])(parent, args.binaries, authorization_timeout_ms=15000)
    # Runtime qualification uses the same bounded deadline in both modes;
    # tiny admission fault-test deadlines are sensitive to VM fsync latency.
    def with_timeout(connect):
        def connected(*args, **kwargs):
            peer = connect(*args, **kwargs)
            peer.settimeout(30)
            return peer
        return connected
    for name in ('broker', 'requester_socket'):
        API[name] = with_timeout(API[name])
    if args.producer:
        API['submit'] = producer_submit
    containers, cases = [], []
    result = {'passed': False, 'producer': args.producer, 'cases': cases}
    try:
        anchor = work / 'anchor'
        subprocess.run(['cc', '-static', '-O2', str(REPO / 'crates/sigrund/tests/fixtures/namespace/anchor-execution.c'),
                        '-o', str(anchor)], check=True)
        container = RootContainer(work, 'B', anchor, pwd.getpwnam('root'), fixture)
        containers.append(container)
        fixture.client = container.root / 'run/client.sock'
        probe = fixture.commands / 'tool'
        subprocess.run(['cc', '-static', '-O2', '-Wall', '-Wextra', '-Werror',
                        str(REPO / 'crates/sigrund/tests/fixtures/namespace/admin.c'), '-o', str(probe)], check=True)
        shutil.copyfile(probe, container.root / probe.relative_to('/'))
        profiles = [json.loads((REPO / 'crates/sigrund-core/tests/fixtures/namespace/admin-constraints.json').read_bytes())]
        cap_profile = copy.deepcopy(profiles[0])
        cap_profile.update(profile_id='namespace-admin-cap', capabilities=['CAP_NET_BIND_SERVICE'])
        profiles.append(cap_profile)
        configure(fixture, profiles)
        fixture.launch()
        container.start()
        REVIEW['management'](args, fixture, 'register', container, profiles[0])
        for uid, groups, caps in ((0, (), ()), (0, (104,), ()), (33, (104,), ()),
                                   (0, (104,), ('CAP_NET_BIND_SERVICE',))):
            profile = profiles[bool(caps)]
            if caps:
                REVIEW['management'](args, fixture, 'revoke')
                container.close()
                container.error = open(work / 'B-cap.stderr', 'wb')
                container.start()
                REVIEW['management'](args, fixture, 'register', container, profile)
            body = request(fixture, profile, uid, groups, caps)
            execution, output = EX['execute'](fixture, body)
            host = copy.deepcopy(body)
            host['intent'].update(target={'kind': 'host'}, security_profile=fixture.profile_id('digest_memfd', caps))
            _, expected = EX['execute'](fixture, host)
            assert output == expected and b'securebits=47 nnp=1' in output, (output, expected)
            API['wait_for'](fixture.empty, 'admin job cleanup')
            ready = next(r for r in fixture.records() if r.get('exec_id') == execution and r['event_type'] == 'EXEC_READY_TO_EXEC')
            if args.producer:
                assert ready['execution_observed']['ambient_lsm']['context'] == 'system_u:system_r:sigrund_host_workload_t:s0'
            cases.append({'name': 'credential-capability-parity', 'uid': uid, 'groups': groups, 'caps': caps, 'output': output.decode()})
        denied(fixture, request(fixture, profiles[1], groups=(105,), caps=('CAP_NET_BIND_SERVICE',)))
        denied(fixture, request(fixture, profiles[1], caps=('CAP_CHOWN',)))
        denied(fixture, request(fixture, profiles[1], caps=('CAP_NET_BIND_SERVICE',)), refuse=True)
        cases.append({'name': 'unauthorized-groups-capabilities-and-refusal'})
        saved_probe = probe.read_bytes()
        source = EX['SourceContainer'](work, anchor, pwd.getpwnam('nobody'), fixture)
        containers.append(source)
        probe.write_bytes(saved_probe)
        shutil.copyfile(probe, source.root / probe.relative_to('/'))
        EX['execute_cli'](fixture, source.command('self', profiles[0]['profile_id'], 0, '/'),
            b'uid=0 gid=0 securebits=47 nnp=1 caps=0000000000000000 groups=\n', source=source)
        cases.append({'name': 'rootful-self-as-root'})
        # Owner permission alone must suffice, without granting DAC override.
        target = container.root / 'srv/service/root-owned'
        target.write_text('before\n'); target.chmod(0o600)
        body = request(fixture, profiles[1], caps=('CAP_NET_BIND_SERVICE',), args=('write', '/srv/service/root-owned'))
        EX['execute'](fixture, body)
        assert target.read_text() == 'approved\n'
        cases.append({'name': 'root-owner-file-write'})
        os.chown(target, 0, 104); target.chmod(0o660)
        EX['execute'](fixture, request(fixture, profiles[1], uid=33, groups=(104,),
            caps=('CAP_NET_BIND_SERVICE',), args=('write', '/srv/service/root-owned')))
        cases.append({'name': 'supplementary-group-file-write'})
        if args.producer:
            forgery = fixture.commands / 'security-probe'
            subprocess.run(['cc', '-static', '-O2', '-Wall', '-Wextra', '-Werror',
                str(HERE / 'selinux/security-probe.c'), '-o', str(forgery)], check=True)
            shutil.copyfile(forgery, container.root / forgery.relative_to('/'))
            forgery_body = request(fixture, profiles[1], caps=('CAP_NET_BIND_SERVICE',))
            forgery_body['intent']['command'].update(executable_path=str(forgery), argv=[str(forgery), 'forgery'])
            _, output = EX['execute'](fixture, forgery_body)
            assert b'producer-entry=denied' in output
            cases.append({'name': 'reserved-socket-labels-and-producer-entry-denied'})
        body['intent']['command']['argv'] = [str(probe), 'hold']
        peer, endpoints, _ = EX['start_execution'](fixture, body)
        peer.close()
        for descriptor in endpoints:
            os.close(descriptor)
        API['wait_for'](fixture.empty, 'cancelled admin descendants')
        cases.append({'name': 'disconnect-cancels-descendants'})
        # An already consumed signed approval cannot authorize a fresh exec ID.
        old = next(json.loads(path.read_bytes()) for path in fixture.base.glob('warrant-*.json')
                   if json.loads(base64.b64decode(json.loads(path.read_bytes())['payload'])).get('approval_exec_id') == execution)
        body['intent']['command']['argv'] = [str(probe)]
        pending = reviewed_request(fixture, body)
        response = API['canonical']({'exec_id': pending[4]['exec_id'], 'status': 'approved', 'dsse_envelope': old})
        pending[0].sendall(struct.pack('>I', len(response)) + response)
        REVIEW['finished_request'](fixture, pending)
        assert not any(r.get('exec_id') == pending[4]['exec_id'] and r['event_type'] == 'AUTH_COMMIT'
                       for r in fixture.records())
        cases.append({'name': 'consumed-approval-cannot-authorize-another-execution'})
        pending = reviewed_request(fixture, body)
        REVIEW['management'](args, fixture, 'revoke')
        REVIEW['stale_approval'](fixture, pending[0], pending[4])
        REVIEW['finished_request'](fixture, pending)
        assert not any(r.get('exec_id') == pending[4]['exec_id'] and r['event_type'] == 'AUTH_COMMIT'
                       for r in fixture.records())
        cases.append({'name': 'destination-revocation-invalidates-pending-approval'})
        container.close()
        container.error = open(work / 'B-child-userns.stderr', 'wb')
        container.start(user_namespace=True)
        REVIEW['management'](args, fixture, 'register', container, profiles[0], succeeds=False)
        cases.append({'name': 'child-user-namespace-registration-rejected'})
        result['passed'] = True
    finally:
        (args.artifacts / 'audit.jsonl').write_bytes(fixture.log.read_bytes())
        (args.artifacts / 'diagnostics').write_bytes(fixture.diagnostics.read_bytes())
        for container in reversed(containers):
            container.close()
        fixture.cleanup()
        shutil.rmtree(work)
        (args.artifacts / 'result.json').write_text(json.dumps(result, indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--binaries', type=Path, required=True)
    parser.add_argument('--producer', action='store_true')
    parser.add_argument('--inside', action='store_true')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('root on a disposable systemd host required')
    args.binaries = args.binaries.resolve(strict=True)
    if args.inside:
        inside(args)
        return
    REVIEW['trusted_directory'](args.artifacts.parent)
    args.artifacts.mkdir(mode=0o700)
    unit = 'sigrund-admin-' + secrets.token_hex(6) + '.service'
    try:
        subprocess.run(['systemd-run', '--quiet', '--unit=' + unit, '--wait', '--collect',
            '--property=Delegate=yes', '--property=KillMode=control-group', '--property=RuntimeMaxSec=300s',
            *(['--property=SELinuxContext=' + Path('/proc/self/attr/current').read_text().strip('\0\n')]
              if Path('/sys/fs/selinux/enforce').exists() else []),
            '/usr/bin/python3', str(Path(__file__).resolve()), '--inside', '--artifacts', str(args.artifacts),
            '--binaries', str(args.binaries), *(['--producer'] if args.producer else [])], check=True)
    finally:
        REVIEW['SUPPORT']['stop_service'](unit)


if __name__ == '__main__':
    main()
