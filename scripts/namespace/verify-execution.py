#!/usr/bin/env python3
"""Exercise production namespace execution on a disposable delegated Linux host."""
import argparse
import array
import hashlib
import fcntl
import json
import os
from pathlib import Path
import platform
import pwd
import pty
import runpy
import secrets
import select
import copy
import sqlite3
from contextlib import closing
import shutil
import signal
import socket
import subprocess
import time
import traceback
import tempfile
import termios

REPO = Path(__file__).resolve().parents[2]
REVIEW = runpy.run_path(str(REPO / 'scripts/namespace/verify-review.py'))
API = REVIEW['API']


class ExecutionContainer(REVIEW['Container']):
    def start(self):
        # Mount the root before chroot so the retained root references the bind
        # mount itself. Mounting over an existing chroot leaves its old fs root.
        command = ['setpriv', '--reuid=' + str(self.account.pw_uid), '--regid=' + str(self.account.pw_gid),
                   '--clear-groups', 'unshare', '--map-auto', '--map-root-user', '--mount', '--cgroup',
                   '--ipc', '--net', '--uts', '--time', '--pid', '--fork', '--kill-child',
                   str(self.root / 'anchor'), 'init', str(self.root), '/run/client.sock.anchor']
        self.process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=self.error)
        def connected():
            if self.process.poll() is not None:
                raise AssertionError('container exited: ' + self.error.name)
            children = Path('/proc', str(self.process.pid), 'task', str(self.process.pid), 'children').read_text().split()
            if len(children) != 1:
                return False
            descendants = Path('/proc', children[0], 'task', children[0], 'children').read_text().split()
            if len(descendants) != 1:
                return False
            pid = int(descendants[0])
            syscall = Path('/proc', str(pid), 'syscall').read_text().split()
            if len(syscall) < 2 or syscall[0] != '0':
                return False
            descriptor = int(syscall[1], 0)
            if not os.readlink(Path('/proc', str(pid), 'fd', str(descriptor))).startswith('socket:'):
                return False
            self.pid = pid
            return True
        API['wait_for'](connected, 'connected execution anchor')
        return self.pid


class SourceContainer(REVIEW['Container']):
    """A private source tree whose namespaces belong to the initial userns."""
    def __init__(self, work, anchor, account, fixture):
        super().__init__(work, 'A', anchor, account, fixture)
        shutil.copyfile(fixture.client_binary, self.root / 'sigrun')
        (self.root / 'sigrun').chmod(0o755)
        # The fixture runs the actual dynamically linked CLI, with its loader
        # and libraries copied from this disposable host into the source tree.
        dependencies = subprocess.check_output(['ldd', str(fixture.client_binary)], text=True)
        for word in dependencies.split():
            if word.startswith('/'):
                destination = self.root / word.lstrip('/')
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(word, destination)
                destination.chmod(0o755)
        (self.root / fixture.client.parent.relative_to('/')).mkdir(parents=True, exist_ok=True)
        self.fixture = fixture

    def command(self, selection, profile, uid, cwd):
        return ['unshare', '--mount', '--cgroup', '--ipc', '--net', '--uts', '--time', '--pid',
                '--fork', '--kill-child', str(self.root / 'anchor'), 'source', str(self.root),
                str(self.fixture.client.parent), '/sigrun', '--socket', str(self.fixture.client),
                '--target', selection, '--target-uid', str(uid), '--target-gid', str(uid),
                '--security-profile', profile, '--cwd', cwd, '--', str(self.fixture.commands / 'tool')]


def execute_cli(fixture, command, expected, *, source=None):
    operator = API['broker'](fixture)
    client = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        try:
            review = API['review'](operator)
        except BaseException:
            if client.poll() is not None:
                stdout, stderr = client.communicate(timeout=1)
                raise AssertionError((client.returncode, stdout, stderr))
            raise
        warrant = json.loads(review['csr_payload'])
        assert warrant['requester_uid'] == 65534
        if source:
            evidence = json.loads((fixture.state / 'host-epoch.json').read_bytes())['process_review']
            assert evidence['schema'] == 'sigrund.self-review.v1' and evidence['registration'] is None
            assert evidence['authenticated_source']['uid'] == 65534
            assert evidence['acquisition']['root']['inode'] == str(source.root.stat().st_ino)
        REVIEW['approve'](fixture, operator, review)
        stdout, stderr = client.communicate(timeout=10)
        assert client.returncode == 0 and stdout == expected, (client.returncode, stdout, stderr)
        verify_binding(fixture, review, review['exec_id'])
        API['wait_for'](fixture.empty, 'source-route job cleanup')
    finally:
        operator.close()
        if client.poll() is None:
            client.kill()
            client.communicate(timeout=5)


def output_bytes(descriptor):
    data = bytearray()
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if not select.select([descriptor], [], [], 0.1)[0]:
            continue
        chunk = os.read(descriptor, 4096)
        if not chunk:
            return bytes(data)
        data.extend(chunk)
        assert len(data) <= 65536, 'unexpected workload output'
    raise AssertionError('workload output did not close')


def output_prefix(descriptor, expected):
    observed = bytearray()
    deadline = time.monotonic() + 5
    while len(observed) < len(expected):
        assert time.monotonic() < deadline, 'missing workload output prefix'
        if select.select([descriptor], [], [], 0.1)[0]:
            chunk = os.read(descriptor, len(expected) - len(observed))
            assert chunk, 'short workload output'
            observed.extend(chunk)
    assert observed == expected, observed


def stdin_cases(fixture, profile, workload, manifest):
    body = registered_body(fixture, profile)
    body['intent']['command']['executable_path'] = str(workload)
    body['intent']['command']['argv'] = [str(workload), 'stdin']
    _, stdout = execute(fixture, body)
    assert stdout == b'stdin-bytes=0\n', stdout
    manifest['cases'].append({'name': 'namespace-null-stdin-is-EOF-with-normal-write-only-output', 'result': 'passed'})
    for finite in (False, True):
        operator = API['broker'](fixture)
        peer = API['requester_socket'](fixture)
        output = os.memfd_create('readable-stdout', os.MFD_CLOEXEC)
        error = os.memfd_create('stderr', os.MFD_CLOEXEC)
        source = os.memfd_create('finite-input', os.MFD_CLOEXEC)
        try:
            os.write(output, b'unapproved')
            os.lseek(output, 0, os.SEEK_SET)
            rights = [output, error]
            request = copy.deepcopy(body)
            if finite:
                request['intent']['command']['stdin_policy'] = 'sha256'
                os.write(source, b'approved')
                os.lseek(source, 0, os.SEEK_SET)
                rights.insert(0, source)
            peer.sendmsg([API['SHARED']['frame'](1, request)],
                         [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', rights))])
            review = API['review'](operator)
            REVIEW['approve'](fixture, operator, review)
            decision = API['SHARED']['ready'](peer)
            assert API['SHARED']['exited'](peer) == {'exit_code': 0, 'signal': None}
            expected = b'stdin-bytes=8\napproved' if finite else b'stdin-bytes=0\n'
            assert os.pread(output, 4096, 0) == expected
            verify_binding(fixture, review, decision['exec_id'])
        finally:
            operator.close()
            peer.close()
            for descriptor in (output, error, source):
                os.close(descriptor)
        manifest['cases'].append({'name': 'namespace-' + ('signed-finite-stdin-control' if finite else 'readable-output-cannot-supply-unsigned-stdin'), 'result': 'passed'})


def unsafe_preparation_cases(fixture, profile, container, manifest):
    (container.root / 'run/subdir').mkdir()
    for cwd in ('/run', '/run/subdir'):
        body = registered_body(fixture, profile)
        body['intent']['command']['cwd'] = cwd
        operator = API['broker'](fixture)
        peer = API['requester_socket'](fixture)
        started = time.monotonic()
        endpoints = API['submit'](peer, body)
        API['timeout'](peer, endpoints, started)
        assert not select.select([operator], [], [], 0)[0], 'covered cwd reached private approval'
        operator.close()
    manifest['cases'].append({'name': 'covered-runtime-cwd-and-descendant-denied-before-approval', 'result': 'passed'})
    setting = Path('/proc/sys/fs/suid_dumpable')
    original = setting.read_text()
    try:
        setting.write_text('1')
        operator = API['broker'](fixture)
        peer = API['requester_socket'](fixture)
        started = time.monotonic()
        endpoints = API['submit'](peer, registered_body(fixture, profile))
        API['timeout'](peer, endpoints, started)
        assert not select.select([operator], [], [], 0)[0], 'unsafe dumpability reached private approval'
        operator.close()
    finally:
        setting.write_text(original)
    manifest['cases'].append({'name': 'unsafe-credential-dumpability-denied-before-approval', 'result': 'passed'})


def memory_contains(pid, sentinel):
    # Only writable private mappings can contain live daemon keys/request data.
    # Bound reads, preserve no memory contents in evidence, and require a live
    # daemon positive control before testing the fresh-exec launcher.
    with open('/proc/' + str(pid) + '/mem', 'rb', buffering=0) as memory:
        total = 0
        maps = Path('/proc', str(pid), 'maps').read_text().splitlines()
        maps.sort(key=lambda line: '[stack]' not in line)
        for line in maps:
            fields = line.split()
            if fields[1] != 'rw-p':
                continue
            start, end = (int(value, 16) for value in fields[0].split('-'))
            length = end - start
            total += length
            assert total <= 134217728, 'memory inspection exceeded bound'
            if sentinel in os.pread(memory.fileno(), length, start):
                return True
    return False


def verify_binding(fixture, review, execution_id):
    payload = review['csr_payload'].encode()
    value = json.loads(payload)
    digest = hashlib.sha256(API['canonical']({key: value[key] for key in ('target_binding', 'security_constraints')})).digest()
    with closing(sqlite3.connect(fixture.state / 'state.sqlite')) as db:
        stored = db.execute('select execution_binding_sha256,payload_sha256 from consumed_grants where exec_id=?', (execution_id,)).fetchone()
    assert stored and type(stored[0]) is bytes and len(stored[0]) == 32 and stored[0] == digest, stored
    assert stored[1] == hashlib.sha256(payload).digest()
    commit = next(record for record in fixture.records() if record.get('exec_id') == execution_id and record.get('event_type') == 'AUTH_COMMIT')
    assert commit['execution_binding_sha256'] == digest.hex()
    fields = ('execution_binding_sha256', 'request_origin', 'intent_sha256', 'approval_exec_id',
              'exec_id', 'grant_id', 'host_id', 'not_after', 'not_before', 'payload_sha256', 'policy_mode', 'signer_id')
    target = {key: commit[key] for key in fields}
    target['auth_commit_seq'] = commit['seq']
    batch = {'first_seq': commit['seq'], 'last_seq': commit['seq'], 'host_id': commit['host_id'],
             'records_jcs': [API['canonical'](commit).decode()], 'target_auth': target}
    path = fixture.base / 'namespace-collector-batch.json'
    path.write_bytes(API['canonical'](batch))
    subprocess.run([str(fixture.binaries / 'sigrund-collector'), '--validate-batch', str(path)], check=True, capture_output=True)
    batch['target_auth']['execution_binding_sha256'] = 'f' * 64
    path.write_bytes(API['canonical'](batch))
    result = subprocess.run([str(fixture.binaries / 'sigrund-collector'), '--validate-batch', str(path)], capture_output=True)
    assert result.returncode == 65, result


def start_execution(fixture, body):
    approver = API['broker'](fixture)
    peer = API['requester_socket'](fixture)
    endpoints = API['submit'](peer, body)
    try:
        review = API['review'](approver)
        REVIEW['approve'](fixture, approver, review)
        decision = API['SHARED']['ready'](peer)
        verify_binding(fixture, review, decision['exec_id'])
        return peer, endpoints, decision
    except BaseException:
        peer.close()
        for descriptor in endpoints:
            os.close(descriptor)
        raise
    finally:
        approver.close()


def execute(fixture, body):
    peer, endpoints, decision = start_execution(fixture, body)
    try:
        result = API['SHARED']['exited'](peer)
        assert result == {'exit_code': 0, 'signal': None}, result
        stdout = output_bytes(endpoints[0])
        assert os.fstat(endpoints[1]).st_size == 0
        return decision['exec_id'], stdout
    finally:
        peer.close()
        for descriptor in endpoints:
            os.close(descriptor)


def passed_self(fixture, body, connector_binary):
    """A root writer receives an unprivileged connector's public stream."""
    parent, control = socket.socketpair()
    connector = os.fork()
    if connector == 0:
        try:
            parent.close()
            API['SHARED']['unprivileged']()
            os.chdir('/usr')
            os.set_inheritable(control.fileno(), True)
            os.execv(connector_binary, [str(connector_binary), str(fixture.client), str(control.fileno())])
        except BaseException:
            os._exit(2)
    control.close()
    peer = operator = None
    endpoints = ()
    try:
        assert select.select([parent], [], [], 5)[0]
        data, ancillary, flags, _ = parent.recvmsg(1, socket.CMSG_SPACE(4))
        assert data == b'S' and not flags and len(ancillary) == 1
        rights = array.array('i')
        rights.frombytes(ancillary[0][2])
        assert len(rights) == 1
        peer = socket.socket(fileno=rights[0])
        peer.settimeout(6)
        operator = API['broker'](fixture)
        endpoints = API['submit'](peer, body)
        review = API['review'](operator)
        warrant = json.loads(review['csr_payload'])
        assert warrant['requester_uid'] == 65534
        evidence = json.loads((fixture.state / 'host-epoch.json').read_bytes())['process_review']
        assert evidence['authenticated_source']['pid'] == connector
        assert evidence['authenticated_source']['uid'] == 65534
        REVIEW['approve'](fixture, operator, review)
        decision = API['SHARED']['ready'](peer)
        assert API['SHARED']['exited'](peer) == {'exit_code': 0, 'signal': None}
        assert output_bytes(endpoints[0]) == b'destination=host uid=12001 gid=12001 cwd=/\n'
        verify_binding(fixture, review, decision['exec_id'])
        API['wait_for'](fixture.empty, 'passed self stream cleanup')
    finally:
        parent.close()
        for descriptor in endpoints:
            os.close(descriptor)
        if operator:
            operator.close()
        if peer:
            peer.close()
        try:
            os.kill(connector, 9)
        except ProcessLookupError:
            pass
        API['wait_for'](lambda: os.waitpid(connector, os.WNOHANG)[0] == connector, 'connector reap')


def configure_namespace(fixture, profile):
    rule = {'requester_uids': [0, 65534], 'target_scope': 'registered:container-b',
            'target_uids': [12001], 'target_gids': [12001], 'supplementary_gids': [],
            'profile_sha256': hashlib.sha256(API['canonical'](profile)).hexdigest(), 'cross_owner': True}
    self_rule = {**rule, 'target_scope': 'self', 'cross_owner': False}
    config, signers = fixture.base / 'config', fixture.base / 'signers'
    config.write_text(config.read_text() + REVIEW['table']('namespace_profiles', profile)
                      + REVIEW['table']('namespace_rules', rule) + REVIEW['table']('namespace_rules', self_rule))
    signers.write_text(signers.read_text() + REVIEW['table']('signers.namespace_rules', rule)
                       + REVIEW['table']('signers.namespace_rules', self_rule))


def registered_body(fixture, profile):
    body = API['hello'](API['payload'](fixture))
    body['intent'].update(target={'kind': 'registered', 'id': 'container-b'},
                          account={'kind': 'name', 'name': 'ns_service'}, security_profile=profile['profile_id'])
    body['intent']['command'].update(executable_path=str(fixture.commands / 'tool'),
                                     argv=[str(fixture.commands / 'tool')], cwd='/srv/service')
    return body


def tty_self(args, fixture, profile):
    master, slave = pty.openpty()
    API['SHARED']['enable_confirmation_packets'](master)
    operator = client = None
    rendered = bytearray()
    def controlling_tty():
        os.setsid()
        fcntl.ioctl(0, termios.TIOCSCTTY, 0)
    try:
        before = fixture.diagnostics.read_text().count('"broker":true')
        operator = subprocess.Popen([str(args.binaries / 'sigrund-approve'), '--socket', str(fixture.approval),
            '--signers', str(fixture.base / 'signers'), '--identity', str(fixture.key),
            '--epoch-file', str(fixture.state / 'host-epoch.json')], stdin=slave, stdout=slave,
            stderr=subprocess.PIPE, preexec_fn=controlling_tty)
        API['wait_for'](lambda: fixture.diagnostics.read_text().count('"broker":true') > before,
                        'experimental root TTY approver admission')
        client = subprocess.Popen([str(fixture.client_binary), '--socket', str(fixture.client),
            '--target', 'self', '--target-uid', '12001', '--target-gid', '12001',
            '--security-profile', profile['profile_id'], '--cwd', '/', '--', str(fixture.commands / 'tool')],
            preexec_fn=API['SHARED']['unprivileged'], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd='/usr')
        rendered.extend(API['SHARED']['read_confirmation_prompt'](master, timeout=2))
        for fragment in (b'Experimental execution', b'Authenticated connector', b'authenticated_source',
                         b'12001', b'verified_acquisition', b'mapped_host_credentials',
                         b'security_constraints', b'ambient LSM', b'daemon_expanded_thin'):
            assert fragment in rendered, fragment
        os.write(master, b'yes\n')
        stdout, stderr = client.communicate(timeout=6)
        assert client.returncode == 0 and stdout == b'destination=host uid=12001 gid=12001 cwd=/\n', (stdout, stderr)
        API['wait_for'](fixture.empty, 'root TTY self execution cleanup')
        with open(args.artifacts / 'self-approval-display.private.txt', 'xb') as output:
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


def self_connector_death(fixture, profile, workload):
    operator = API['broker'](fixture)
    client = subprocess.Popen([str(fixture.client_binary), '--socket', str(fixture.client),
        '--target', 'self', '--target-uid', '12001', '--target-gid', '12001',
        '--security-profile', profile['profile_id'], '--cwd', '/', '--', str(workload), 'fork'],
        preexec_fn=API['SHARED']['unprivileged'], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    reference = None
    try:
        review = API['review'](operator)
        evidence = json.loads((fixture.state / 'host-epoch.json').read_bytes())['process_review']
        reference = os.pidfd_open(evidence['authenticated_source']['pid'])
        REVIEW['approve'](fixture, operator, review)
        assert select.select([client.stdout], [], [], 5)[0]
        assert client.stdout.readline() == b'workload-ready\n'
        # Keep the relay and public connection alive while killing only the
        # captured source. Its lifecycle must tear down both workload processes.
        signal.pidfd_send_signal(reference, signal.SIGKILL)
        API['wait_for'](fixture.empty, 'self connector death kills all descendants')
        stdout, _ = client.communicate(timeout=6)
        assert client.returncode != 0 and not stdout
        verify_binding(fixture, review, review['exec_id'])
    finally:
        if reference is not None:
            os.close(reference)
        operator.close()
        if client.poll() is None:
            client.kill()
            client.communicate(timeout=5)


def private_failure_cases(fixture, body, manifest):
    for mutation in ('root', 'groups'):
        denied = copy.deepcopy(body)
        denied['intent']['target'] = {'kind': 'self'}
        denied['intent']['account'] = {'kind': 'numeric', 'uid': 0 if mutation == 'root' else 12001,
                                      'gid': 12001, 'supplementary_gids': [104] if mutation == 'groups' else []}
        operator = API['broker'](fixture)
        peer = API['requester_socket'](fixture)
        started = time.monotonic()
        endpoints = API['submit'](peer, denied)
        API['timeout'](peer, endpoints, started)
        assert not select.select([operator], [], [], 0)[0]
        operator.close()
    manifest['cases'].append({'name': 'experimental-root-and-groups-denied-before-self-acquisition', 'result': 'passed'})
    for fault in ('partial', 'broker-disconnect', 'late'):
        case = REVIEW['reviewed_request'](fixture, body)
        if fault == 'partial':
            case[0].sendall(b'\x00\x00\x04\x00{"exec_id":')
        elif fault == 'broker-disconnect':
            case[0].close()
        API['timeout'](case[1], case[2], case[3])
        if fault == 'late':
            REVIEW['stale_approval'](fixture, case[0], case[4])
        case[0].close()
        assert not any(r.get('exec_id') == case[4]['exec_id'] and r.get('event_type') == 'AUTH_COMMIT'
                       for r in fixture.records())
    manifest['cases'].append({'name': 'experimental-partial-disconnected-and-late-approval-never-consume-or-spawn', 'result': 'passed'})


def account_edit(fixture, container, body, manifest):
    case = REVIEW['reviewed_request'](fixture, body)
    path = container.root / 'etc/passwd'
    original = path.read_text()
    try:
        path.write_text(original.replace(':12001:12001:', ':12002:12002:'))
        REVIEW['approve'](fixture, case[0], case[4])
        decision = API['SHARED']['ready'](case[1])
        assert API['SHARED']['exited'](case[1]) == {'exit_code': 0, 'signal': None}
        assert output_bytes(case[2][0]) == b'destination=B uid=12001 gid=12001 cwd=/srv/service\n'
        verify_binding(fixture, case[4], decision['exec_id'])
        API['wait_for'](fixture.empty, 'account edit job cleanup')
    finally:
        path.write_text(original)
        case[0].close()
        case[1].close()
        for descriptor in case[2]:
            os.close(descriptor)
    manifest['cases'].append({'name': 'prepared-named-account-edit-keeps-approved-numeric-credentials', 'result': 'passed'})


def fault_cases(args, parent, work, anchor, account, profile, manifest):
    modes = ['namespace-bootstrap-memory', 'namespace-setns', 'namespace-root', 'namespace-private', 'namespace-run', 'namespace-covered-cwd',
             'namespace-final-clone', 'namespace-short-ready', 'namespace-short-handoff',
             'namespace-ready-deadline', 'step-4', 'step-6', 'step-9', 'step-11',
             'namespace-partial-approved', 'wal-after', 'cleanup-before']
    for mode in modes:
        directory = work / mode
        directory.mkdir()
        fixture = API['Fixture'](parent, args.binaries)
        container = gate = operator = peer = None
        endpoints = ()
        try:
            container = ExecutionContainer(directory, 'B', anchor, account, fixture)
            fixture.client = container.root / 'run/client.sock'
            configure_namespace(fixture, profile)
            if mode == 'cleanup-before':
                config = fixture.base / 'config'
                config.write_text(config.read_text() + '\n[host_limits.global]\ntargets=64\ntarget_fds=2048\nhelpers=16\nreviews=16\n'
                                  '[host_limits.per_uid]\ntargets=4\ntarget_fds=128\nhelpers=1\nreviews=2\n')
            sentinel = secrets.token_hex(64).encode()
            gate = API['SHARED']['Gate'](fixture, mode, durable=mode == 'wal-after',
                                         extra_env={'SIGRUND_MEMORY_SENTINEL': sentinel.decode()} if mode == 'namespace-bootstrap-memory' else None)
            container.start()
            REVIEW['management'](args, fixture, 'register', container, profile)
            gate.arm()
            operator = API['broker'](fixture)
            peer = API['requester_socket'](fixture)
            started = time.monotonic()
            endpoints = API['submit'](peer, registered_body(fixture, profile))
            review = API['review'](operator)
            assert not select.select([endpoints[0]], [], [], 0)[0], 'output before approval'
            REVIEW['approve'](fixture, operator, review)
            if mode == 'namespace-bootstrap-memory':
                decision = API['SHARED']['authorized'](peer)
                entered = gate.arm_path.with_name(gate.arm_path.name + '.entered')
                API['wait_for'](entered.exists, 'fresh-exec launcher memory checkpoint')
                launcher = int(entered.read_text())
                assert b'--internal-namespace-launcher' in Path('/proc', str(launcher), 'cmdline').read_bytes()
                assert memory_contains(fixture.process.pid, sentinel), 'missing daemon positive control'
                assert not memory_contains(launcher, sentinel), 'daemon memory survived launcher exec'
                gate.arm_path.with_name(gate.arm_path.name + '.release').write_text('release')
                progress = API['SHARED']['receive'](peer, 8)
                assert progress == {'exec_id': decision['exec_id'], 'exec_outcome': 'exec_event_observed'}, progress
                assert API['SHARED']['exited'](peer) == {'exit_code': 0, 'signal': None}
                assert b'destination=B uid=12001' in output_bytes(endpoints[0])
                verify_binding(fixture, review, decision['exec_id'])
                manifest['cases'].append({'name': 'fresh-exec-launcher-discards-live-daemon-memory-before-userns', 'result': 'passed'})
                continue
            if mode == 'wal-after':
                gate.arrive()
                API['timeout'](peer, endpoints, started)
                endpoints = ()
                gate.unblock()
                API['wait_for'](lambda: any(r.get('event_type') == 'AUTH_COMMIT' and r.get('exec_id') == review['exec_id']
                                           for r in fixture.records()), 'late durable namespace consumption')
                verify_binding(fixture, review, review['exec_id'])
                assert not any(r.get('event_type') == 'EXEC_READY_TO_EXEC' and r.get('exec_id') == review['exec_id']
                               for r in fixture.records())
                manifest['cases'].append({'name': 'namespace-late-commit-keeps-consumption-without-spawn', 'result': 'passed'})
                continue
            if mode == 'namespace-partial-approved':
                assert peer.recv(1) == b'\x02'
                assert peer.recv(1) == b''
                assert time.monotonic() - started >= 2.0
                assert output_bytes(endpoints[0]) == b'' and os.fstat(endpoints[1]).st_size == 0
                verify_binding(fixture, review, review['exec_id'])
                assert fixture.empty()
                assert not any(r.get('event_type') == 'EXEC_READY_TO_EXEC' for r in fixture.records())
                manifest['cases'].append({'name': 'namespace-partial-approved-delivery-keeps-consumption-and-zero-spawn', 'result': 'passed'})
                continue
            if mode == 'cleanup-before':
                decision = API['SHARED']['ready'](peer)
                output_prefix(endpoints[0], b'destination=B uid=12001 gid=12001 cwd=/srv/service\n')
                operator.close()
                operator = None
                gate.arrive()
                assert not fixture.empty()
                retry_operator = API['broker'](fixture)
                retry = API['requester_socket'](fixture)
                started = time.monotonic()
                retry_endpoints = API['submit'](retry, registered_body(fixture, profile))
                API['timeout'](retry, retry_endpoints, started)
                assert not select.select([retry_operator], [], [], 0)[0], 'blocked owner refunded its helper'
                retry_operator.close()
                host_operator = API['broker'](fixture)
                host_peer = REVIEW['requester_socket_as'](fixture, 0)
                host_endpoints = API['submit'](host_peer, API['hello'](API['payload'](fixture)))
                host_review = API['review'](host_operator)
                REVIEW['approve'](fixture, host_operator, host_review)
                API['SHARED']['ready'](host_peer)
                assert API['SHARED']['exited'](host_peer) == {'exit_code': 0, 'signal': None}
                host_peer.close()
                host_operator.close()
                for descriptor in host_endpoints:
                    os.close(descriptor)
                assert not fixture.empty(), 'blocked cleanup unexpectedly completed'
                gate.unblock()
                assert API['SHARED']['exited'](peer) == {'exit_code': 0, 'signal': None}
                API['wait_for'](fixture.empty, 'namespace cleanup released by fixture')
                verify_binding(fixture, review, decision['exec_id'])
                _, stdout = execute(fixture, registered_body(fixture, profile))
                assert b'destination=B uid=12001' in stdout
                API['wait_for'](fixture.empty, 'namespace retry after actual cleanup')
                manifest['cases'].append({'name': 'blocked-namespace-cleanup-retains-helper-through-timeout-and-preserves-host-execution', 'result': 'passed'})
                continue
            decision = API['SHARED']['authorized'](peer)
            failure = API['SHARED']['receive'](peer, 5)
            assert failure['status'] in ('SETUP_FAILED', 'EXEC_FAILED'), failure
            assert peer.recv(1) == b''
            assert output_bytes(endpoints[0]) == b'' and os.fstat(endpoints[1]).st_size == 0
            API['wait_for'](fixture.empty, 'failed namespace job cleanup: ' + mode)
            verify_binding(fixture, review, decision['exec_id'])
            records = [record for record in fixture.records() if record.get('exec_id') == decision['exec_id']]
            assert [record['event_type'] for record in records] == [
                'AUTH_COMMIT', 'AUTH_ABORTED_POST_COMMIT', 'EXEC_SPAWN_FAILED'], records
            manifest['cases'].append({'name': 'namespace-fault-' + mode, 'result': 'passed',
                                      'consumption_retained': True, 'workload_output': False})
        finally:
            if gate and mode == 'cleanup-before':
                try:
                    gate.unblock()
                except BrokenPipeError:
                    pass
            if peer:
                peer.close()
            if operator:
                operator.close()
            for descriptor in endpoints:
                os.close(descriptor)
            fixture.stop()
            if container:
                container.close()
            if gate:
                gate.close()
            if fixture.log.exists():
                shutil.copyfile(fixture.log, args.artifacts / (mode + '.audit.private.jsonl'))
            if fixture.diagnostics.exists():
                shutil.copyfile(fixture.diagnostics, args.artifacts / (mode + '.daemon.private.log'))
            fixture.cleanup()


def inside(args):
    membership = Path('/proc/self/cgroup').read_text().strip().split('::')[1]
    parent = Path('/sys/fs/cgroup' + membership)
    if not parent.name.startswith('sigrund-namespace-execution-'):
        raise RuntimeError('bounded namespace execution service required')
    runner = parent / 'runner'
    runner.mkdir()
    (runner / 'cgroup.procs').write_text(str(os.getpid()))
    (parent / 'cgroup.subtree_control').write_text('+memory +pids')
    work = Path('/run') / ('sigrund-namespace-execution-' + secrets.token_hex(6))
    work.mkdir(mode=0o755)
    # Keep executable roots on the host root mount for the declared NO_XDEV
    # preparation domain. Fedora mounts /tmp and /var separately.
    tempfile.tempdir = '/usr/local'
    fixture = API['Fixture'](parent, args.binaries)
    container = source = None
    containers = []
    manifest = {'schema': 'sigrund.namespace-execution-results.v1', 'result': 'incomplete',
                'source_sha256': runpy.run_path(str(REPO / 'scripts/check.py'))['source_digest'](),
                'kernel': platform.release(), 'architecture': platform.machine(),
                'os_release': Path('/etc/os-release').read_text(),
                'binaries_sha256': {name: hashlib.sha256((args.binaries / name).read_bytes()).hexdigest()
                                    for name in ('sigrund', 'sigrun', 'sigrundctl', 'sigrund-approve', 'sigrund-collector')},
                'cases': []}
    try:
        anchor = work / 'anchor'
        subprocess.run(['cc', '-std=gnu11', '-static', '-O2', '-Wall', '-Wextra', '-Werror', '-pthread',
                        str(REPO / 'crates/sigrund/tests/fixtures/namespace/anchor-execution.c'), '-o', str(anchor)],
                       check=True, capture_output=True, timeout=60)
        connector_binary = work / 'passed-connector'
        subprocess.run(['cc', '-std=gnu11', '-static', '-O2', '-Wall', '-Wextra', '-Werror',
                        str(REPO / 'crates/sigrund/tests/fixtures/namespace/passed-connector.c'), '-o', str(connector_binary)],
                       check=True, capture_output=True, timeout=60)
        account = pwd.getpwnam(args.owner)
        assert account.pw_uid != 0
        container = ExecutionContainer(work, 'B', anchor, account, fixture)
        containers.append(container)
        hold = fixture.commands / 'hold'
        subprocess.run(['cc', '-static', '-O2', str(REPO / 'crates/sigrund/tests/fixtures/namespace/workload.c'), '-o', str(hold)], check=True, capture_output=True)
        destination_hold = container.root / hold.relative_to('/')
        shutil.copyfile(hold, destination_hold)
        destination_hold.chmod(0o755)
        fixture.client = container.root / 'run/client.sock'
        profile = json.loads((REPO / 'crates/sigrund-core/tests/fixtures/namespace/experimental-constraints.json').read_bytes())
        configure_namespace(fixture, profile)
        fixture.launch()
        container.start()
        REVIEW['management'](args, fixture, 'register', container, profile)
        manifest['cases'].append({'name': 'capture-rootless-B-and-pin-execution-resources', 'result': 'passed'})
        body = registered_body(fixture, profile)
        execution_id, stdout = execute(fixture, body)
        assert stdout == b'destination=B uid=12001 gid=12001 cwd=/srv/service\n', stdout
        API['wait_for'](fixture.empty, 'namespace job cleanup')
        records = fixture.records()
        ready = next(record for record in records if record.get('exec_id') == execution_id and record.get('event_type') == 'EXEC_READY_TO_EXEC')
        assert ready['exec_outcome'] == 'exec_event_observed', ready
        assert ready['execution_observed']['child_pid'] == ready['child_pid']
        assert ready['execution_observed']['job_placement_verified']
        manifest['cases'].append({'name': 'host-to-B-approved-final-child-checkpoint-and-output', 'result': 'passed', 'exec_id': execution_id})
        stdin_cases(fixture, profile, hold, manifest)
        unsafe_preparation_cases(fixture, profile, container, manifest)
        body['intent']['target'] = {'kind': 'process', 'pid': container.pid, 'pid_scope': 'daemon'}
        _, stdout = execute(fixture, body)
        assert b'destination=B uid=12001 gid=12001' in stdout
        API['wait_for'](fixture.empty, 'process-selector job cleanup')
        manifest['cases'].append({'name': 'process-selector-runs-the-same-retained-instance', 'result': 'passed'})
        operator = API['broker'](fixture)
        client = subprocess.Popen([str(fixture.client_binary), '--socket', str(fixture.client),
            '--target', 'self', '--target-uid', '12001', '--target-gid', '12001',
            '--security-profile', profile['profile_id'], '--cwd', '/', '--', str(fixture.commands / 'tool')],
            preexec_fn=API['SHARED']['unprivileged'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd='/usr')
        try:
            review = API['review'](operator)
            private = json.loads((fixture.state / 'host-epoch.json').read_bytes())['process_review']
            assert private['schema'] == 'sigrund.self-review.v1' and private['registration'] is None
            assert private['acquisition']['root'] != private['acquisition']['cwd']
            REVIEW['approve'](fixture, operator, review)
            stdout, stderr = client.communicate(timeout=10)
            assert client.returncode == 0 and stdout == b'destination=host uid=12001 gid=12001 cwd=/\n', (client.returncode, stdout, stderr)
            verify_binding(fixture, review, review['exec_id'])
            API['wait_for'](fixture.empty, 'self job cleanup')
            manifest['cases'].append({'name': 'CLI-self-connector-capture-relay-and-distinct-source-cwd', 'result': 'passed'})
        finally:
            operator.close()
            if client.poll() is None:
                client.kill()
                client.communicate(timeout=5)
        manifest['cases'].append({'name': 'namespace-database-audit-collector-binding-equality', 'result': 'passed'})
        tty_self(args, fixture, profile)
        manifest['cases'].append({'name': 'actual-root-TTY-self-evidence-signature-and-execution', 'result': 'passed'})
        own = copy.deepcopy(body)
        own['intent'].update(target={'kind': 'self'},
                             account={'kind': 'numeric', 'uid': 12001, 'gid': 12001, 'supplementary_gids': []})
        own['intent']['command']['cwd'] = '/'
        passed_self(fixture, own, connector_binary)
        manifest['cases'].append({'name': 'passed-self-stream-binds-connector-despite-root-writer', 'result': 'passed'})
        self_connector_death(fixture, profile, hold)
        manifest['cases'].append({'name': 'self-connector-death-kills-primary-and-session-detached-descendant-with-live-relay', 'result': 'passed'})
        source = SourceContainer(work, anchor, account, fixture)
        execute_cli(fixture, source.command('host', 'host-digest_memfd', 33, '/'),
                    b'destination=host uid=33 gid=33 cwd=/\n')
        manifest['cases'].append({'name': 'A-to-host-actual-CLI-through-exposed-public-endpoints', 'result': 'passed'})
        execute_cli(fixture, source.command('self', profile['profile_id'], 12001, '/srv/service'),
                    b'destination=A uid=12001 gid=12001 cwd=/srv/service\n', source=source)
        manifest['cases'].append({'name': 'A-to-self-initial-userns-connector-and-destination-A-bytes', 'result': 'passed'})
        execute_cli(fixture, source.command('registered:container-b', profile['profile_id'], 12001, '/srv/service'),
                    b'destination=B uid=12001 gid=12001 cwd=/srv/service\n')
        manifest['cases'].append({'name': 'A-to-B-independent-source-and-destination', 'result': 'passed'})
        body['intent']['target'] = {'kind': 'registered', 'id': 'container-b'}
        private_failure_cases(fixture, body, manifest)
        account_edit(fixture, container, body, manifest)
        pending = REVIEW['reviewed_request'](fixture, body)
        old_binding = json.loads(pending[4]['csr_payload'])['target_binding']
        replacement = ExecutionContainer(work, 'B2', anchor, account, fixture)
        containers.append(replacement)
        shutil.copyfile(hold, replacement.root / hold.relative_to('/'))
        (replacement.root / hold.relative_to('/')).chmod(0o755)
        os.link(str(fixture.client) + '.anchor', replacement.root / 'run/client.sock.anchor')
        replacement.start()
        REVIEW['management'](args, fixture, 'register', replacement, profile)
        assert Path('/proc', str(container.pid)).exists(), 'pending lease lost its old anchor'
        REVIEW['stale_approval'](fixture, pending[0], pending[4])
        API['timeout'](pending[1], pending[2], pending[3])
        pending[0].close()
        assert not any(r.get('exec_id') == pending[4]['exec_id'] and r.get('event_type') == 'AUTH_COMMIT'
                       for r in fixture.records())
        container.process.wait(timeout=6)
        container = replacement
        fresh = REVIEW['reviewed_request'](fixture, body)
        assert json.loads(fresh[4]['csr_payload'])['target_binding']['instance_id'] != old_binding['instance_id']
        REVIEW['approve'](fixture, fresh[0], fresh[4])
        API['SHARED']['ready'](fresh[1])
        assert API['SHARED']['exited'](fresh[1]) == {'exit_code': 0, 'signal': None}
        assert output_bytes(fresh[2][0]) == b'destination=B2 uid=12001 gid=12001 cwd=/srv/service\n'
        fresh[0].close()
        fresh[1].close()
        for descriptor in fresh[2]:
            os.close(descriptor)
        API['wait_for'](fixture.empty, 'replacement job cleanup')
        manifest['cases'].append({'name': 'pending-experimental-review-replacement-zero-spawn-and-fresh-instance-executes', 'result': 'passed'})
        held = copy.deepcopy(body)
        held['intent']['target'] = {'kind': 'registered', 'id': 'container-b'}
        held['intent']['command'].update(executable_path=str(hold), argv=[str(hold), 'fork'])
        for action in ('disconnect', 'revoke'):
            peer, endpoints, decision = start_execution(fixture, held)
            try:
                API['wait_for'](lambda: bool(select.select([endpoints[0]], [], [], 0)[0]), 'forking workload ready')
                assert os.read(endpoints[0], 4096) == b'workload-ready\n'
                if action == 'disconnect':
                    peer.close()
                else:
                    REVIEW['management'](args, fixture, 'revoke')
                API['wait_for'](fixture.empty, 'all supervised descendants removed after ' + action)
                assert output_bytes(endpoints[0]) == b''
                manifest['cases'].append({'name': action + '-kills-primary-and-session-detached-descendant', 'result': 'passed', 'exec_id': decision['exec_id']})
            finally:
                peer.close()
                for descriptor in endpoints:
                    os.close(descriptor)
        fixture.stop()
        container.close()
        container = None
        source.close()
        source = None
        fault_cases(args, parent, work, anchor, account, profile, manifest)
        manifest['result'] = 'passed'
    except BaseException:
        manifest['result'] = 'failed'
        manifest['error'] = traceback.format_exc()
        raise
    finally:
        try:
            fixture.stop()
            for captured in containers:
                captured.close()
            if source:
                source.close()
        except BaseException:
            manifest['result'] = 'failed'
            manifest['cleanup_error'] = traceback.format_exc()
        if fixture.diagnostics.exists():
            shutil.copyfile(fixture.diagnostics, args.artifacts / 'daemon.private.log')
        if fixture.log.exists():
            shutil.copyfile(fixture.log, args.artifacts / 'audit.private.jsonl')
        for path in work.glob('*.stderr'):
            shutil.copyfile(path, args.artifacts / path.name)
        try:
            fixture.cleanup()
            shutil.rmtree(work)
        except BaseException:
            manifest['result'] = 'failed'
            manifest['disposal_error'] = traceback.format_exc()
        REVIEW['write'](args.artifacts / 'evidence.json', manifest)
        for artifact in args.artifacts.iterdir():
            artifact.chmod(0o600)
        if manifest['result'] != 'passed':
            raise RuntimeError('namespace execution execution or cleanup failed')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--binaries', type=Path, required=True)
    parser.add_argument('--owner', required=True)
    parser.add_argument('--inside', action='store_true')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('run as root on a disposable systemd host')
    REVIEW['trusted_directory'](args.artifacts.parent)
    args.binaries = args.binaries.resolve(strict=True)
    if args.inside:
        inside(args)
        return
    args.artifacts.mkdir(mode=0o700)
    unit = 'sigrund-namespace-execution-' + secrets.token_hex(8) + '.service'
    command = ['systemd-run', '--unit=' + unit, '--service-type=exec', '--wait', '--collect',
               '--property=Delegate=yes', '--property=KillMode=control-group', '--property=RuntimeMaxSec=180s',
               '--property=TimeoutStopSec=10s', '--property=MemoryMax=1G', '--property=TasksMax=128']
    if Path('/sys/fs/selinux/enforce').exists():
        command += ['--property=SELinuxContext=' + Path('/proc/self/attr/current').read_text().strip('\0\n')]
    command += ['/usr/bin/python3', str(Path(__file__).resolve()), '--inside', '--artifacts', str(args.artifacts),
                '--binaries', str(args.binaries), '--owner', args.owner]
    try:
        subprocess.run(command, check=True, timeout=200)
    finally:
        REVIEW['SUPPORT']['stop_service'](unit)


if __name__ == '__main__':
    main()
