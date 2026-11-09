#!/usr/bin/env python3
"""Qualify production Phase 2 on a disposable delegated systemd host."""
import argparse
import array
import socket
import copy
import hashlib
import json
import os
from pathlib import Path
import platform
import pwd
import pty
import select
import fcntl
import termios
import runpy
import secrets
import shutil
import sqlite3
import struct
import stat as filetype
import subprocess
import time
import traceback
from types import SimpleNamespace

REPO = Path(__file__).resolve().parent.parent
API = runpy.run_path(str(REPO / 'scripts/verify-v3.py'))
P15 = runpy.run_path(str(REPO / 'scripts/verify-namespace-phase15.py'))
canonical, wait_for = API['canonical'], API['wait_for']


def toml(value):
    if isinstance(value, dict):
        return '{' + ', '.join(k + ' = ' + toml(v) for k, v in value.items()) + '}'
    if isinstance(value, bool):
        return str(value).lower()
    return json.dumps(value)


def table(name, fields):
    return '\n[[' + name + ']]\n' + '\n'.join(k + ' = ' + toml(v) for k, v in fields.items()) + '\n'


def write(path, value):
    with open(path, 'xb') as output:
        os.fchmod(output.fileno(), 0o600)
        output.write(canonical(value))


def finish_evidence(artifacts, manifest):
    write(artifacts / 'evidence.json', manifest)
    if manifest['result'] != 'passed':
        raise RuntimeError('Phase 2 qualification or cleanup failed')


class Faults:
    """Faults affect only the daemon; production helpers clear this environment."""
    def __init__(self, f):
        self.arm = f.base / 'namespace-fault-arm'
        self.entered, self.worker_entered = socket.socketpair()
        self.release, self.worker_release = socket.socketpair()
        library = f.base / 'namespace-faults.so'
        subprocess.run(['cc', '-shared', '-fPIC', '-O2', '-Wall', '-Wextra', '-Werror',
                        str(REPO / 'crates/sigrund/tests/fixtures/namespace/faults.c'),
                        '-o', str(library)], check=True, capture_output=True, timeout=30)
        env = dict(os.environ, LD_PRELOAD=str(library), SIGRUND_NAMESPACE_ARM=str(self.arm),
                   SIGRUND_NAMESPACE_ENTERED=str(self.worker_entered.fileno()),
                   SIGRUND_NAMESPACE_RELEASE=str(self.worker_release.fileno()))
        f.launch(env=env, pass_fds=(self.worker_entered.fileno(), self.worker_release.fileno()))
        self.worker_entered.close()
        self.worker_release.close()

    def arrive(self, expected):
        assert select.select([self.entered], [], [], 6)[0], 'fault point was not reached'
        assert self.entered.recv(1) == expected

    def close(self):
        self.entered.close()
        self.release.close()


class Container:
    def __init__(self, work, name, anchor, account, f):
        self.root = work / name
        self.root.mkdir(mode=0o755)
        for directory in ('run', 'proc', 'etc', 'usr/bin', 'srv/service'):
            (self.root / directory).mkdir(parents=True, exist_ok=True, mode=0o755)
        (self.root / f.commands.relative_to('/')).mkdir(parents=True, mode=0o755)
        shutil.copyfile(anchor, self.root / 'anchor')
        (self.root / 'anchor').chmod(0o755)
        (self.root / 'etc/passwd').write_text('root:x:0:0::/:/anchor\nphase2_service:x:12001:12001::/srv/service:/anchor\n')
        (self.root / 'etc/group').write_text('root:x:0:\nphase2_service:x:12001:\n')
        (self.root / 'srv/service/identity').write_text('container B cwd\n')
        source = REPO / 'scripts/namespace-phase1-5/command.c'
        for label, output in (('host', f.commands / 'tool'), (name, self.root / (f.commands / 'tool').relative_to('/'))):
            subprocess.run(['cc', '-static', '-O2', '-DDESTINATION="' + label + '"', str(source), '-o', str(output)],
                           check=True, capture_output=True, timeout=30)
        self.error = open(work / (name + '.stderr'), 'wb')
        self.process = None
        self.account = account

    def start(self, *, time_namespace=True, mode=""):
        command = ['setpriv', '--reuid=' + str(self.account.pw_uid), '--regid=' + str(self.account.pw_gid),
                   '--clear-groups', 'unshare', '--map-auto', '--map-root-user', '--mount', '--cgroup',
                   '--ipc', '--net', '--uts', *(['--time'] if time_namespace else []), '--pid', '--fork', '--kill-child', '--mount-proc',
                   '--root', str(self.root), '/anchor', 'init', '/run/client.sock.anchor']
        self.process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=self.error, env=dict(os.environ, SIGRUND_TEST_ANCHOR=mode))
        selected = []
        def found():
            children = Path('/proc', str(self.process.pid), 'task', str(self.process.pid), 'children')
            if not children.exists():
                raise AssertionError('container exited: ' + self.error.name)
            first = children.read_text().split()
            if len(first) != 1:
                return False
            descendants = Path('/proc', first[0], 'task', first[0], 'children').read_text().split()
            if len(descendants) != 1:
                return False
            pid = int(descendants[0])
            if mode == 'delay':
                if Path('/proc', str(pid), 'comm').read_text().strip() != 'phase2-delay':
                    return False
                selected[:] = [pid]
                return True
            # Fork visibility precedes socket connection. Synchronize on the
            # anchor's actual read of the G-01 handshake, not an elapsed sleep.
            fields = Path('/proc', str(pid), 'syscall').read_text().split()
            if len(fields) < 2 or fields[0] != '0':
                return False
            descriptor = int(fields[1], 0)
            try:
                endpoint = os.readlink(Path('/proc', str(pid), 'fd', str(descriptor)))
            except FileNotFoundError:
                return False
            if not endpoint.startswith('socket:'):
                return False
            selected[:] = [pid]
            return True
        wait_for(found, 'dedicated container anchor')
        self.pid = selected[0]
        return self.pid

    def close(self):
        if self.process:
            if self.process.poll() is None:
                self.process.kill()
            self.process.wait(timeout=6)
        self.error.close()


def approve(f, peer, request):
    _, envelope = f.sign_payload(request['csr_payload'].encode())
    response = canonical({'exec_id': request['exec_id'], 'status': 'approved', 'dsse_envelope': envelope})
    peer.sendall(struct.pack('>I', len(response)) + response)


def stale_approval(f, peer, request):
    try:
        approve(f, peer, request)
    except (BrokenPipeError, ConnectionResetError):
        # Revocation cancels the broker exchange as soon as the worker observes
        # the invalidated owner. A response already in flight still cannot grant.
        pass


def invalidated(f, execution_id):
    return any(r.get('exec_id') == execution_id and (
        r.get('status') == 'POLICY_VIOLATION'
        or r.get('reason_code') == 'TARGET_INVALIDATED'
        or ('target registration revoked' in r.get('reason', ''))
        or ('target anchor or capture worker exited' in r.get('reason', ''))
    ) for r in f.records())


def requester_socket_as(f, uid):
    parent, child = socket.socketpair()
    pid = os.fork()
    if pid == 0:
        try:
            parent.close()
            os.setgroups([])
            os.setgid(uid)
            os.setuid(uid)
            peer = socket.socket(socket.AF_UNIX)
            peer.connect(str(f.client))
            child.sendmsg([b'x'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [peer.fileno()]))])
            os._exit(0)
        except BaseException:
            os._exit(1)
    child.close()
    _, controls, _, _ = parent.recvmsg(1, socket.CMSG_SPACE(4))
    _, status = os.waitpid(pid, 0)
    assert status == 0 and len(controls) == 1
    descriptors = array.array('i')
    descriptors.frombytes(controls[0][2])
    parent.close()
    peer = socket.socket(fileno=descriptors[0])
    peer.settimeout(6)
    return peer


def reviewed_request(f, body, uid=65534):
    approver = API['broker'](f)
    peer = requester_socket_as(f, uid)
    started = time.monotonic()
    endpoints = API['submit'](peer, body)
    request = API['review'](approver)
    return approver, peer, endpoints, started, request


def finished_request(f, case):
    approver, peer, endpoints, started, request = case
    API['timeout'](peer, endpoints, started)
    approver.close()
    return request['exec_id']


def management(args, f, operation, container=None, profile=None, *, succeeds=True):
    command = [str(args.binaries / 'sigrundctl'), 'target', operation, 'container-b', '--socket', str(f.client)]
    if operation == 'register':
        command += ['--pid', str(container.pid), '--owner-uid', str(container.account.pw_uid),
                    '--security-profile', profile['profile_id']]
    result = subprocess.run(command, capture_output=True, timeout=15)
    assert (result.returncode == 0) == succeeds, result.stderr.decode()
    return result


def tty_review(args, f, profile, artifacts):
    master, slave = pty.openpty()
    API['SHARED']['enable_confirmation_packets'](master)
    operator = client = None
    rendered = bytearray()
    def controlling_tty():
        os.setsid()
        fcntl.ioctl(0, termios.TIOCSCTTY, 0)
    try:
        before = f.diagnostics.read_text().count('"broker":true')
        operator = subprocess.Popen([
            str(args.binaries / 'sigrund-approve'), '--socket', str(f.approval),
            '--signers', str(f.base / 'signers'), '--identity', str(f.key),
            '--epoch-file', str(f.state / 'host-epoch.json')],
            stdin=slave, stdout=slave, stderr=subprocess.PIPE, preexec_fn=controlling_tty)
        wait_for(lambda: f.diagnostics.read_text().count('"broker":true') > before, 'real root TTY approver admission')
        started = time.monotonic()
        client = subprocess.Popen([
            str(f.client_binary), '--socket', str(f.client), '--target', 'registered:container-b',
            '--security-profile', profile['profile_id'], '--account', 'phase2_service',
            '--cwd', '/srv/service', '--ttl-secs', '120', '--', str(f.commands / 'tool')],
            preexec_fn=API['SHARED']['unprivileged'], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        rendered.extend(API['SHARED']['read_confirmation_prompt'](master, timeout=2))
        review = json.loads((f.state / 'host-epoch.json').read_bytes())['process_review']
        for fragment in (b'Phase 2 private review', b'phase2_service', b'12001',
                         b'verified_acquisition', b'mapped_host_credentials', b'security_constraints',
                         b'daemon_expanded_thin', b'container-b'):
            assert fragment in rendered, fragment
        os.write(master, b'yes\n')
        stdout, stderr = client.communicate(timeout=6)
        assert client.returncode == 255 and not stdout, (client.returncode, stdout, stderr)
        assert time.monotonic() - started >= 2.3
        wait_for(lambda: any(r.get('exec_id') == review['exec_id']
                             and r.get('status') == 'PHASE2_EXECUTION_DISABLED' for r in f.records()),
                 'real TTY signature reaches the private Phase 2 gate')
        with open(artifacts / 'approval-display.private.txt', 'xb') as output:
            os.fchmod(output.fileno(), 0o600)
            output.write(rendered)
    finally:
        for process in (client, operator):
            if process and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
        os.close(master)
        os.close(slave)


def inside(args):
    membership = Path('/proc/self/cgroup').read_text().strip().split('::')[1]
    parent = Path('/sys/fs/cgroup' + membership)
    if not parent.name.startswith('sigrund-phase2-'):
        raise RuntimeError('a bounded Phase 2 supervisor is required')
    runner = parent / 'runner'
    runner.mkdir()
    (runner / 'cgroup.procs').write_text(str(os.getpid()))
    (parent / 'cgroup.subtree_control').write_text('+memory +pids')
    work = Path('/run') / ('sigrund-phase2-' + secrets.token_hex(6))
    work.mkdir(mode=0o755)
    f = API['Fixture'](parent, args.binaries, models=['digest_memfd', 'digest_direct'])
    containers = []
    faults = None
    manifest = {'schema': 'sigrund.phase2-evidence.v1', 'result': 'incomplete',
                'source_sha256': runpy.run_path(str(REPO / 'scripts/check.py'))['source_digest'](),
                'command': ['python3', 'scripts/verify-namespace-phase2.py', '--binaries', str(args.binaries),
                            '--artifacts', str(args.artifacts), '--owner', args.owner],
                'kernel': platform.release(), 'selinux_enforcing': Path('/sys/fs/selinux/enforce').read_text().strip(),
                'os_release': Path('/etc/os-release').read_text(),
                'binaries_sha256': {name: hashlib.sha256((args.binaries / name).read_bytes()).hexdigest()
                                    for name in ('sigrund', 'sigrun', 'sigrundctl', 'sigrund-approve', 'sigrund-collector')},
                'cases': []}
    try:
        anchor = work / 'anchor'
        subprocess.run(['cc', '-std=gnu11', '-static', '-O2', '-Wall', '-Wextra', '-Werror', '-pthread',
                        str(REPO / 'crates/sigrund/tests/fixtures/namespace/anchor-review.c'), '-o', str(anchor)],
                       check=True, capture_output=True, timeout=60)
        account = pwd.getpwnam(args.owner)
        assert account.pw_uid != 0, 'choose an unprivileged container owner'
        try:
            pwd.getpwnam('phase2_service')
        except KeyError:
            pass
        else:
            raise RuntimeError('fixture destination account must be absent from the host')

        b = Container(work, 'B1', anchor, account, f)
        containers.append(b)
        f.client = b.root / 'run/client.sock'
        profile = json.loads((REPO / 'crates/sigrund-phase0/tests/fixtures/constraints.json').read_bytes())
        rule = {'requester_uids': [0, 65534], 'target_scope': 'registered:container-b',
                'target_uids': [12001], 'target_gids': [12001], 'supplementary_gids': [12002],
                'profile_sha256': hashlib.sha256(canonical(profile)).hexdigest(), 'cross_owner': True}
        direct_profile = copy.deepcopy(profile)
        direct_profile.update(profile_id='namespace-direct', executable_model='digest_direct')
        direct_rule = copy.deepcopy(rule)
        direct_rule['profile_sha256'] = hashlib.sha256(canonical(direct_profile)).hexdigest()
        same_owner_rule = copy.deepcopy(rule)
        same_owner_rule.update(requester_uids=[account.pw_uid], target_uids=[0, 12001],
                               target_gids=[0, 12001], cross_owner=False)
        equal_local_rule = copy.deepcopy(rule)
        equal_local_rule.update(requester_uids=[12001])
        config = f.base / 'config'
        config.write_text(config.read_text() + table('namespace_profiles', profile) + table('namespace_rules', rule)
                          + table('namespace_profiles', direct_profile) + table('namespace_rules', direct_rule)
                          + table('namespace_rules', same_owner_rule) + table('namespace_rules', equal_local_rule))
        signers = f.base / 'signers'
        signers.write_text(signers.read_text().replace('allowed_requester_uids = [0, 65534]',
                                                     'allowed_requester_uids = ' + json.dumps(sorted({0, account.pw_uid, 12001, 65534})))
                           + table('signers.namespace_rules', rule)
                           + table('signers.namespace_rules', direct_rule)
                           + table('signers.namespace_rules', same_owner_rule) + table('signers.namespace_rules', equal_local_rule))
        faults = Faults(f)
        anchor_endpoint = SimpleNamespace(client=Path(str(f.client) + '.anchor'))
        flood = [requester_socket_as(anchor_endpoint, 65534) for _ in range(16)]
        wait_for(lambda: len(select.select(flood, [], [], 0)[0]) >= 12, 'per-UID rendezvous limit')
        assert len(select.select(flood, [], [], 0)[0]) == 12
        b.start()
        register = [str(args.binaries / 'sigrundctl'), 'target', 'register', 'container-b',
                    '--pid', str(b.pid), '--owner-uid', str(account.pw_uid),
                    '--security-profile', profile['profile_id'], '--socket', str(f.client)]
        result = subprocess.run(register, capture_output=True, timeout=15)
        assert result.returncode == 0, result.stderr.decode()
        manifest['cases'].append({'name': 'production-register-live-rootless-B', 'result': 'passed'})
        for pending_socket in flood:
            pending_socket.close()
        manifest['cases'].append({'name': 'per-UID-rendezvous-limit-preserves-other-owner-registration', 'result': 'passed'})
        body = API['hello'](API['payload'](f))
        body['intent']['target'] = {'kind': 'registered', 'id': 'container-b'}
        body['intent']['account'] = {'kind': 'name', 'name': 'phase2_service'}
        body['intent']['security_profile'] = profile['profile_id']
        body['intent']['command'].update(executable_path=str(f.commands / 'tool'),
                                          argv=[str(f.commands / 'tool')], cwd='/srv/service')
        approver = API['broker'](f)
        peer = API['requester_socket'](f)
        started = time.monotonic()
        endpoints = API['submit'](peer, body)
        request = API['review'](approver)
        csr = json.loads(request['csr_payload'])
        private = json.loads((f.state / 'host-epoch.json').read_bytes())['process_review']
        assert csr['execution_context']['target_uid'] == 12001
        assert csr['execution_context']['target_gid'] == 12001
        assert csr['execution_context']['supplementary_gids'] == []
        assert csr['intent'] == body['intent']
        context_record = {'schema': 'sigrund.process-context.v1', 'acquisition': private['acquisition'],
                          'executable_roots': private['executable_roots']}
        assert csr['target_binding']['context_sha256'] == hashlib.sha256(canonical(context_record)).hexdigest()

        destination = (b.root / (f.commands / 'tool').relative_to('/')).read_bytes()
        assert destination != (f.commands / 'tool').read_bytes()
        assert csr['command']['executable_trust']['sha256'] == hashlib.sha256(destination).hexdigest()
        assert csr['command']['cwd'] == '/srv/service'
        write(args.artifacts / 'review.private.json', private)
        write(args.artifacts / 'csr.private.json', csr)
        _, envelope = f.sign_payload(request['csr_payload'].encode())
        response = canonical({'exec_id': request['exec_id'], 'status': 'approved', 'dsse_envelope': envelope})
        approver.sendall(struct.pack('>I', len(response)) + response)
        API['timeout'](peer, endpoints, started)
        approver.close()
        wait_for(lambda: any(r.get('status') == 'PHASE2_EXECUTION_DISABLED' for r in f.records()),
                 'private final authorization gate')
        gate = next(r for r in f.records() if r.get('exec_id') == request['exec_id']
                    and r.get('status') == 'PHASE2_EXECUTION_DISABLED')
        assert gate['source_authenticated']['uid'] == 65534
        assert gate['approved_target']['numeric_credentials']['uid'] == 12001
        assert gate['execution_observed'] is None
        binding = {'target_binding': csr['target_binding'], 'security_constraints': csr['security_constraints']}
        assert gate['approved_target']['execution_binding_sha256'] == hashlib.sha256(canonical(binding)).hexdigest()
        assert not any(r.get('event_type') == 'AUTH_COMMIT' for r in f.records())
        assert f.empty()
        with sqlite3.connect(f.state / 'state.sqlite') as database:
            assert database.execute('select count(*) from consumed_grants').fetchone()[0] == 0
        manifest['cases'].append({'name': 'destination-only-account-bytes-cwd-and-private-approval', 'result': 'passed'})

        # Finite stdin is consumed before any private target lookup. Keep the
        # original read endpoint to inspect the actual kernel pipe occupancy.
        content = b'phase2 finite input' * 200
        for exists in (True, False):
            finite = copy.deepcopy(body)
            finite['intent']['command']['stdin_policy'] = 'sha256'
            if not exists:
                finite['intent']['target']['id'] = 'absent-registration'
            stdin_read, stdin_write = os.pipe2(os.O_CLOEXEC)
            output_read, output_write = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
            error = os.memfd_create('phase2-output', os.MFD_CLOEXEC)
            broker = API['broker'](f)
            peer = API['requester_socket'](f)
            started = time.monotonic()
            try:
                peer.sendmsg([API['SHARED']['frame'](1, finite)],
                             [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                               array.array('i', [stdin_read, output_write, error]))])
                os.close(output_write)
                assert not select.select([broker], [], [], 0.1)[0], 'target lookup preceded input EOF'
                assert os.write(stdin_write, content) == len(content)
                os.close(stdin_write)
                stdin_write = -1
                if exists:
                    request = API['review'](broker)
                    assert json.loads(request['csr_payload'])['command']['stdin_sha256'] == hashlib.sha256(content).hexdigest()
                    approve(f, broker, request)
                API['timeout'](peer, (output_read, error), started)
                remaining = array.array('i', [0])
                fcntl.ioctl(stdin_read, termios.FIONREAD, remaining)
                assert remaining[0] == 0, 'private lookup stopped reading requester input'
                if not exists:
                    assert not select.select([broker], [], [], 0)[0]
            finally:
                os.close(stdin_read)
                if stdin_write >= 0:
                    os.close(stdin_write)
                broker.close()
                peer.close()
        manifest['cases'].append({'name': 'finite-stdin-is-bound-and-drained-before-private-target-lookup', 'result': 'passed'})

        # Numeric selection and daemon-scope process selection share the same
        # retained registration and scope, including exact empty group selection.
        for selector in ({'kind': 'registered', 'id': 'container-b'},
                         {'kind': 'process', 'pid': b.pid, 'pid_scope': 'daemon'}):
            numeric = copy.deepcopy(body)
            numeric['intent']['target'] = selector
            groups = [12002] if selector['kind'] == 'registered' else []
            numeric['intent']['account'] = {'kind': 'numeric', 'uid': 12001, 'gid': 12001, 'supplementary_gids': groups}
            case = reviewed_request(f, numeric)
            expanded = json.loads(case[4]['csr_payload'])
            assert expanded['intent'] == numeric['intent']
            assert expanded['execution_context']['supplementary_gids'] == groups
            approve(f, case[0], case[4])
            execution_id = finished_request(f, case)
            wait_for(lambda: any(r.get('exec_id') == execution_id and r.get('status') == 'PHASE2_EXECUTION_DISABLED'
                                 for r in f.records()), 'numeric process authorization')
        manifest['cases'].append({'name': 'numeric-and-daemon-process-selectors-use-retained-owner', 'result': 'passed'})

        for field in ('account', 'target', 'profile'):
            denied = copy.deepcopy(body)
            if field == 'account':
                denied['intent']['account']['name'] = 'absent_destination_account'
            elif field == 'target':
                denied['intent']['target']['id'] = 'absent-registration'
            else:
                denied['intent']['security_profile'] = 'absent-profile'
            broker = API['broker'](f)
            peer = API['requester_socket'](f)
            started = time.monotonic()
            endpoints = API['submit'](peer, denied)
            API['timeout'](peer, endpoints, started)
            assert not __import__('select').select([broker], [], [], 0)[0]
            broker.close()
        case = reviewed_request(f, body)
        API['refuse'](case[0], case[4])
        finished_request(f, case)
        manifest['cases'].append({'name': 'private-target-account-profile-denial-and-refusal-have-scheduled-timeout', 'result': 'passed'})

        # A partial response, a disconnected broker and a late valid signature
        # all keep the same public deadline and cannot commit or spawn.
        for fault in ('partial', 'broker-disconnect', 'late'):
            case = reviewed_request(f, body)
            if fault == 'partial':
                case[0].sendall(struct.pack('>I', 1024) + b'{"exec_id":')
            elif fault == 'broker-disconnect':
                case[0].close()
            API['timeout'](case[1], case[2], case[3])
            if fault == 'late':
                stale_approval(f, case[0], case[4])
            case[0].close()
        case = reviewed_request(f, body)
        case[1].close()
        for descriptor in case[2]:
            os.close(descriptor)
        stale_approval(f, case[0], case[4])
        case[0].close()
        wait_for(lambda: any(r.get('exec_id') == case[4]['exec_id'] for r in f.records()),
                 'requester disconnect finishes privately')
        manifest['cases'].append({'name': 'partial-disconnected-and-late-approval-never-grant', 'result': 'passed'})

        # Corrupt the real destination helper's rights message, then prove that
        # every delivered descriptor was closed and a healthy retry succeeds.
        def fd_count():
            return len(list(Path('/proc', str(f.process.pid), 'fd').iterdir()))
        wait_for(lambda: f.empty(), 'idle namespace preparation')
        baseline_fds = fd_count()
        faults.arm.write_text('truncate')
        broker = API['broker'](f)
        peer = API['requester_socket'](f)
        started = time.monotonic()
        endpoints = API['submit'](peer, body)
        faults.arrive(b't')
        API['timeout'](peer, endpoints, started)
        assert not select.select([broker], [], [], 0)[0]
        broker.close()
        wait_for(lambda: fd_count() <= baseline_fds, 'malformed helper IPC closes received rights')
        case = reviewed_request(f, body)
        API['refuse'](case[0], case[4])
        finished_request(f, case)
        manifest['cases'].append({'name': 'malformed-helper-IPC-closes-rights-and-preserves-healthy-retry', 'result': 'passed'})

        cached = b.root / f.commands.relative_to('/')
        old_root = cached.with_name(cached.name + '-original')
        replacement_root = cached.with_name(cached.name + '-replacement')
        cached.rename(old_root)
        cached.mkdir(mode=0o755)
        shutil.copyfile(f.commands / 'tool', cached / 'tool')
        (cached / 'tool').chmod(0o755)
        try:
            case = reviewed_request(f, body)
            expanded = json.loads(case[4]['csr_payload'])
            assert expanded['command']['executable_trust']['sha256'] == hashlib.sha256(destination).hexdigest()
            assert expanded['target_binding']['context_sha256'] == csr['target_binding']['context_sha256']
            approve(f, case[0], case[4])
            execution_id = finished_request(f, case)
            wait_for(lambda: any(r.get('exec_id') == execution_id and r.get('status') == 'PHASE2_EXECUTION_DISABLED'
                                 for r in f.records()), 'pinned executable root survives pathname replacement')
        finally:
            cached.rename(replacement_root)
            old_root.rename(cached)
        manifest['cases'].append({'name': 'executable-root-objects-are-fixed-for-the-target-generation', 'result': 'passed'})

        for uid in (account.pw_uid, 12001):
            case = reviewed_request(f, body, uid=uid)
            assert json.loads(case[4]['csr_payload'])['requester_uid'] == uid
            approve(f, case[0], case[4])
            execution_id = finished_request(f, case)
            wait_for(lambda: any(r.get('exec_id') == execution_id and r.get('status') == 'PHASE2_EXECUTION_DISABLED'
                                 for r in f.records()), 'mapped source/target identity policy')
        collision = copy.deepcopy(body)
        collision['intent']['account'] = {'kind': 'numeric', 'uid': 0, 'gid': 0, 'supplementary_gids': []}
        broker = API['broker'](f)
        peer = requester_socket_as(f, account.pw_uid)
        started = time.monotonic()
        endpoints = API['submit'](peer, collision)
        API['timeout'](peer, endpoints, started)
        assert not select.select([broker], [], [], 0)[0]
        broker.close()
        manifest['cases'].append({'name': 'same-owner-and-equal-local-UID-policy-use-composed-host-identities', 'result': 'passed'})

        tty_review(args, f, profile, args.artifacts)
        manifest['cases'].append({'name': 'real-client-and-root-TTY-display-signature-private-gate', 'result': 'passed'})

        case = reviewed_request(f, body)
        passwd = b.root / 'etc/passwd'
        original_passwd = passwd.read_text()
        groups_path = b.root / 'etc/group'
        original_groups = groups_path.read_text()
        passwd.write_text(original_passwd.replace(':12001:12001:', ':12002:12002:'))
        groups_path.write_text(original_groups + 'late:x:12002:phase2_service\n')
        approve(f, case[0], case[4])
        execution_id = finished_request(f, case)
        wait_for(lambda: any(r.get('exec_id') == execution_id and r.get('status') == 'PHASE2_EXECUTION_DISABLED'
                             for r in f.records()), 'resolved credentials survive account edit')
        passwd.write_text(original_passwd)
        groups_path.write_text(original_groups)
        manifest['cases'].append({'name': 'account-edits-do-not-redirect-approved-numeric-credentials', 'result': 'passed'})

        case = reviewed_request(f, body)
        old = json.loads(case[4]['csr_payload'])['target_binding']
        second = Container(work, 'B2', anchor, account, f)
        containers.append(second)
        # The fixture operator exposes the same anchor rendezvous inode to B2.
        # Production management never inserts a socket into an existing target.
        os.link(str(f.client) + '.anchor', second.root / 'run/client.sock.anchor')
        second.start()
        management(args, f, 'register', second, direct_profile)
        assert Path('/proc', str(b.pid)).exists(), 'old anchor must still be held by its pending lease'
        stale_approval(f, case[0], case[4])
        execution_id = finished_request(f, case)
        wait_for(lambda: invalidated(f, execution_id), 'old revision fails final authorization')
        b.process.wait(timeout=6)
        changed_profile = copy.deepcopy(body)
        changed_profile['intent']['security_profile'] = direct_profile['profile_id']
        fresh = reviewed_request(f, changed_profile)
        fresh_csr = json.loads(fresh[4]['csr_payload'])
        assert fresh_csr['security_constraints'] != csr['security_constraints']
        new = fresh_csr['target_binding']
        assert new['instance_id'] != old['instance_id']
        assert new['context_sha256'] != old['context_sha256']
        API['refuse'](fresh[0], fresh[4])
        finished_request(f, fresh)
        manifest['cases'].append({'name': 'pending-review-replacement-retains-old-owner-and-rejects-old-revision', 'result': 'passed'})

        case = reviewed_request(f, changed_profile)
        management(args, f, 'revoke')
        stale_approval(f, case[0], case[4])
        execution_id = finished_request(f, case)
        wait_for(lambda: invalidated(f, execution_id), 'revocation fails final authorization')
        second.process.wait(timeout=6)
        manifest['cases'].append({'name': 'revocation-invalidates-pending-approval', 'result': 'passed'})

        third = Container(work, 'B3', anchor, account, f)
        containers.append(third)
        os.link(str(f.client) + '.anchor', third.root / 'run/client.sock.anchor')
        third.start()
        management(args, f, 'register', third, profile)
        case = reviewed_request(f, body)
        os.kill(third.pid, __import__('signal').SIGKILL)
        stale_approval(f, case[0], case[4])
        execution_id = finished_request(f, case)
        wait_for(lambda: invalidated(f, execution_id), 'dead anchor fails final authorization')
        third.process.wait(timeout=6)
        manifest['cases'].append({'name': 'anchor-death-invalidates-pending-approval', 'result': 'passed'})
        assert not any(r.get('event_type') == 'AUTH_COMMIT' for r in f.records())
        assert f.empty()
        with sqlite3.connect(f.state / 'state.sqlite') as database:
            assert database.execute('select count(*) from consumed_grants').fetchone()[0] == 0
        fourth = Container(work, 'B4', anchor, account, f)
        containers.append(fourth)
        os.link(str(f.client) + '.anchor', fourth.root / 'run/client.sock.anchor')
        fourth.start()
        management(args, f, 'register', fourth, direct_profile)
        direct_source = fourth.root / (f.commands / 'tool').relative_to('/')
        # Compose through the actual initialized mapping, independently of Rust.
        mapping = Path('/proc', str(fourth.pid), 'uid_map').read_text().splitlines()
        target_host_uid = next(int(outside) + 12001 - int(inside)
                               for inside, outside, count in (line.split() for line in mapping)
                               if int(inside) <= 12001 < int(inside) + int(count))
        gid_mapping = Path('/proc', str(fourth.pid), 'gid_map').read_text().splitlines()
        target_host_gid = next(int(outside) + 12001 - int(inside)
                               for inside, outside, count in (line.split() for line in gid_mapping)
                               if int(inside) <= 12001 < int(inside) + int(count))
        os.chown(direct_source, target_host_uid, target_host_gid)
        direct_source.chmod(0o700)
        direct = copy.deepcopy(body)
        direct['intent']['security_profile'] = direct_profile['profile_id']
        case = reviewed_request(f, direct)
        expanded = json.loads(case[4]['csr_payload'])
        assert expanded['command']['executable_trust']['model'] == 'digest_direct'
        assert expanded['command']['executable_trust']['sha256'] == hashlib.sha256(
            (fourth.root / (f.commands / 'tool').relative_to('/')).read_bytes()).hexdigest()
        approve(f, case[0], case[4])
        execution_id = finished_request(f, case)
        wait_for(lambda: any(r.get('exec_id') == execution_id and r.get('status') == 'PHASE2_EXECUTION_DISABLED'
                             for r in f.records()), 'destination direct digest approval')
        manifest['cases'].append({'name': 'destination-direct-digest-preserves-profile-and-uses-mapped-credentials', 'result': 'passed'})
        host = f.cli(f.commands / 'true')
        stdout, stderr = host.communicate(timeout=6)
        assert host.returncode == 0 and not stdout and stderr == b'sigrun: waiting for authorization\n', (host.returncode, stdout, stderr)
        wait_for(f.empty, 'host workload cleanup with a retained capture worker')
        commits = [r for r in f.records() if r.get('event_type') == 'AUTH_COMMIT']
        assert len(commits) == 1 and commits[0]['target_binding']['kind'] == 'host'
        manifest['cases'].append({'name': 'host-execution-and-reaping-work-with-live-container-registration', 'result': 'passed'})
        # A destination observation stalled after approval must not occupy the
        # durable sequencer. A separate signed host job still commits/exits.
        case = reviewed_request(f, direct)
        cwd_stat = (fourth.root / 'srv/service').stat()
        faults.arm.write_text('stat ' + str(cwd_stat.st_dev) + ' ' + str(cwd_stat.st_ino))
        approve(f, case[0], case[4])
        faults.arrive(b's')
        host = f.cli(f.commands / 'true')
        stdout, stderr = host.communicate(timeout=6)
        assert host.returncode == 0 and not stdout, (host.returncode, stdout, stderr)
        faults.release.sendall(b'x')
        finished_request(f, case)
        manifest['cases'].append({'name': 'blocked-final-destination-stat-does-not-stall-host-authorization', 'result': 'passed'})

        # Even an unparsed expired/rejected anchor socket needs off-loop final
        # close ownership: queued rights can block its kernel final release.
        before = {}
        for descriptor in Path('/proc', str(f.process.pid), 'fd').iterdir():
            try:
                before[descriptor] = descriptor.stat().st_ino
            except FileNotFoundError:
                pass
        pending_peer = requester_socket_as(anchor_endpoint, 65534)
        selected_fd = []
        def accepted_pending():
            added = []
            for descriptor in Path('/proc', str(f.process.pid), 'fd').iterdir():
                try:
                    status = descriptor.stat()
                except FileNotFoundError:
                    continue
                if filetype.S_ISSOCK(status.st_mode) and before.get(descriptor) != status.st_ino:
                    added.append(descriptor)
            if len(added) != 1:
                return False
            selected_fd[:] = added
            return True
        wait_for(accepted_pending, 'pending anchor descriptor')
        descriptor_stat = selected_fd[0].stat()
        faults.arm.write_text('close ' + str(descriptor_stat.st_dev) + ' ' + str(descriptor_stat.st_ino))
        pending_peer.close()
        faults.arrive(b'c')
        probe = subprocess.run([str(args.binaries / 'sigrundctl'), 'target', 'revoke',
                                'unregistered-probe', '--socket', str(f.client)], capture_output=True, timeout=2)
        assert probe.returncode != 0 and b'target unavailable' in probe.stderr, probe
        faults.release.sendall(b'x')
        manifest['cases'].append({'name': 'blocked-pending-anchor-close-keeps-management-responsive', 'result': 'passed'})

        # Keep the last capture's real root close blocked after its original
        # helper/anchor exit. A replacement may occupy the second helper slot;
        # a third acquisition cannot refund the blocked owner's charge.
        case = reviewed_request(f, direct)
        root_stat = fourth.root.stat()
        faults.arm.write_text('close ' + str(root_stat.st_dev) + ' ' + str(root_stat.st_ino))
        management(args, f, 'revoke')
        stale_approval(f, case[0], case[4])
        finished_request(f, case)
        faults.arrive(b'c')
        fourth.process.wait(timeout=6)
        fifth = Container(work, 'B5', anchor, account, f)
        containers.append(fifth)
        os.link(str(f.client) + '.anchor', fifth.root / 'run/client.sock.anchor')
        fifth.start()
        management(args, f, 'register', fifth, profile)
        sixth = Container(work, 'B6', anchor, account, f)
        containers.append(sixth)
        os.link(str(f.client) + '.anchor', sixth.root / 'run/client.sock.anchor')
        sixth.start()
        command = [str(args.binaries / 'sigrundctl'), 'target', 'register', 'container-b',
                   '--pid', str(sixth.pid), '--owner-uid', str(account.pw_uid),
                   '--security-profile', profile['profile_id'], '--socket', str(f.client)]
        denied = subprocess.run(command, capture_output=True, timeout=15)
        assert denied.returncode != 0, 'blocked cleanup refunded a still-owned helper'
        faults.release.sendall(b'x')
        # Synchronize on the actual retained daemon root descriptor disappearing.
        def old_root_closed():
            for descriptor in Path('/proc', str(f.process.pid), 'fd').iterdir():
                try:
                    status = descriptor.stat()
                except FileNotFoundError:
                    continue
                if (status.st_dev, status.st_ino) == (root_stat.st_dev, root_stat.st_ino):
                    return False
            return True
        wait_for(old_root_closed, 'actual retained root close')
        management(args, f, 'register', sixth, profile)
        fifth.process.wait(timeout=6)
        manifest['cases'].append({'name': 'blocked-actual-close-retains-helper-quota-until-release', 'result': 'passed'})
        f.stop()
        sixth.process.wait(timeout=6)
        assert not Path(str(f.client) + '.management').exists()
        assert not Path(str(f.client) + '.anchor').exists()
        manifest['cases'].append({'name': 'shutdown-reaps-retained-anchor-and-closes-management-listeners', 'result': 'passed'})
        # A new daemon epoch publishes no recovered namespace registrations.
        old_epoch = csr['target_binding']['daemon_epoch']
        f.launch()
        restarted = json.loads((f.state / 'host-epoch.json').read_bytes())
        assert restarted['bundles'][0]['acquisition']['daemon_epoch'] != old_epoch
        for message in (body, API['hello'](csr, 'full_csr'),
                        {'version': '3.0', 'mode': 'signed', 'tty_mode': 'stdio', 'caller_env': {},
                         'dsse_envelope': envelope}):
            broker = API['broker'](f)
            peer = API['requester_socket'](f)
            started = time.monotonic()
            endpoints = API['submit'](peer, message)
            API['timeout'](peer, endpoints, started)
            assert not select.select([broker], [], [], 0)[0], 'stale input changed target/model or fell back'
            broker.close()
        manifest['cases'].append({'name': 'restart-discards-registrations-and-rejects-full-and-signed-namespace-input', 'result': 'passed'})

        for mode in ('delay', 'spoof'):
            probe = Container(work, mode, anchor, account, f)
            containers.append(probe)
            os.link(str(f.client) + '.anchor', probe.root / 'run/client.sock.anchor')
            probe.start(mode=mode)
            management(args, f, 'register', probe, profile, succeeds=mode == 'delay')
            if mode == 'delay':
                management(args, f, 'revoke')
            probe.process.wait(timeout=6)
        manifest['cases'].append({'name': 'delayed-handshake-succeeds-and-spoofed-seccomp-anchor-is-rejected', 'result': 'passed'})

        for name in ('mixed-time', 'missing-executable-root'):
            negative = Container(work, name, anchor, account, f)
            containers.append(negative)
            os.link(str(f.client) + '.anchor', negative.root / 'run/client.sock.anchor')
            if name == 'missing-executable-root':
                shutil.rmtree(negative.root / f.commands.relative_to('/'))
            negative.start(time_namespace=name != 'mixed-time')
            management(args, f, 'register', negative, profile, succeeds=False)
            negative.process.wait(timeout=6)
        manifest['cases'].append({'name': 'production-acquisition-rejects-mixed-ownership-and-missing-roots', 'result': 'passed'})
        f.stop()
        # The permission-denial fixture deliberately uses memfd-only host
        # profiles: direct-exec host checkpoints themselves require ptrace.
        previous = config.read_text()
        f.models = ['digest_memfd']
        host_profiles, host_rules = f.profile_config()
        prefix = previous.split('\n[[host_profiles]]', 1)[0].replace(
            'executable_trust_models = ["digest_memfd", "digest_direct"]',
            'executable_trust_models = ["digest_memfd"]')
        config.write_text(prefix + host_profiles + host_rules + '\n[mvp]\napproval_signer_id = "'
                          + API['SHARED']['SIGNER'] + '"\n'
                          + previous[previous.index('\n[[namespace_profiles]]'):])
        previous_signers = signers.read_text()
        signers.write_text(previous_signers.split('\n[[signers.host_rules]]', 1)[0]
                           + f.profile_config(signer=True)[1]
                           + previous_signers[previous_signers.index('\n[[signers.namespace_rules]]'):])
        f.launch(env=dict(os.environ, LD_PRELOAD=str(f.base / 'namespace-faults.so'),
                          SIGRUND_NAMESPACE_NO_PTRACE='1'))
        forbidden = Container(work, 'ptrace-denied', anchor, account, f)
        containers.append(forbidden)
        os.link(str(f.client) + '.anchor', forbidden.root / 'run/client.sock.anchor')
        forbidden.start()
        management(args, f, 'register', forbidden, profile, succeeds=False)
        forbidden.process.wait(timeout=6)
        assert 'PTRACE_SEIZE' in f.diagnostics.read_text() and 'Operation not permitted' in f.diagnostics.read_text()
        f.stop()
        manifest['cases'].append({'name': 'production-acquisition-without-ptrace-capability-fails-closed', 'result': 'passed'})
        assert len([r for r in f.records() if r.get('event_type') == 'AUTH_COMMIT']) == 2
        with sqlite3.connect(f.state / 'state.sqlite') as database:
            assert database.execute('select count(*) from consumed_grants').fetchone()[0] == 2
        manifest['result'] = 'passed'
    except BaseException:
        manifest['result'] = 'failed'
        manifest['error'] = traceback.format_exc()
        raise
    finally:
        for container in containers:
            try:
                container.close()
            except BaseException:
                manifest['cleanup_error'] = traceback.format_exc()
                manifest['result'] = 'failed'
        shutil.copyfile(f.diagnostics, args.artifacts / 'daemon.private.log')
        if f.log.exists():
            shutil.copyfile(f.log, args.artifacts / 'audit.private.jsonl')
        f.cleanup()
        if faults:
            faults.close()
        for path in work.glob('*.stderr'):
            shutil.copyfile(path, args.artifacts / path.name)
        shutil.rmtree(work)
        for artifact in args.artifacts.iterdir():
            if artifact.is_file():
                artifact.chmod(0o600)
        finish_evidence(args.artifacts, manifest)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--binaries', type=Path, required=True)
    parser.add_argument('--owner', required=True)
    parser.add_argument('--inside', action='store_true')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('run as root on a disposable systemd host')
    trusted = P15['trusted_directory']
    trusted(args.artifacts.parent)
    args.binaries = args.binaries.resolve(strict=True)
    if args.inside:
        trusted(args.artifacts)
        inside(args)
        return
    args.artifacts.mkdir(mode=0o700)
    unit = 'sigrund-phase2-' + secrets.token_hex(8) + '.service'
    command = ['systemd-run', '--unit=' + unit, '--service-type=exec', '--wait', '--collect',
               '--property=Delegate=yes', '--property=KillMode=control-group', '--property=RuntimeMaxSec=180s',
               '--property=TimeoutStopSec=10s', '--property=MemoryMax=1G', '--property=TasksMax=128']
    if Path('/sys/fs/selinux/enforce').exists():
        label = Path('/proc/self/attr/current').read_text().strip('\0\n')
        command += ['--property=SELinuxContext=' + label]
    command += ['/usr/bin/python3', str(Path(__file__).resolve()), '--inside',
                '--artifacts', str(args.artifacts), '--binaries', str(args.binaries), '--owner', args.owner]
    try:
        subprocess.run(command, check=True, timeout=200)
    finally:
        P15['PHASE0']['stop_service_and_recover_policy'](unit, args.artifacts)
    print('Phase 2 qualification: ' + str(args.artifacts / 'evidence.json'))


if __name__ == '__main__':
    main()
