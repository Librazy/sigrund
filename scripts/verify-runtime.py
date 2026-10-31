#!/usr/bin/python3
"""Runtime integration gate inside a dedicated delegated supervising service.

The parent must already delegate memory/pids. This script creates only fresh
subgroups beneath it, launches real production binaries, and kills/removes its
subgroups on all paths. The enclosing service must enforce a final deadline
and whole-service cleanup, including when the Python supervisor is killed.
"""
import argparse
import base64
import hashlib
import json
import os
import fcntl
import select
from pathlib import Path
import shutil
import signal
import socket
import struct
import subprocess
import tempfile
import time
import uuid

REPO = Path(__file__).resolve().parent.parent
SIGNER = 'mandator-alice-yubikey'
CLIENT_PROGRESS = b'sigrun: waiting for authorization\n'


def command_source(name):
    # Some distributions ship hardened multicall tools that reject a memfd's
    # executable name. Prefer their standalone GNU alternatives when present.
    # Check the actual copied bytes through the same sealed-execution boundary.
    for candidate in (Path('/usr/bin', 'gnu' + name), Path('/usr/bin', name)):
        if not candidate.exists():
            continue
        fd = os.memfd_create('sigrun-fixture-preflight', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING | 0x10)
        try:
            with open(candidate.resolve(), 'rb') as source:
                with os.fdopen(os.dup(fd), 'wb') as target:
                    shutil.copyfileobj(source, target)
            os.fchmod(fd, 0o111)
            fcntl.fcntl(fd, fcntl.F_ADD_SEALS, fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW |
                        fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL | 0x20)
            args = {'id': ['-u'], 'sleep': ['0']}.get(name, [])
            result = subprocess.run([name, *args], executable='/proc/self/fd/' + str(fd), pass_fds=(fd,),
                                    input=b'', capture_output=True, timeout=3)
            if result.returncode == (1 if name == 'false' else 0) and not result.stderr:
                return candidate.resolve()
        finally:
            os.close(fd)
    raise RuntimeError('no memfd-compatible standalone fixture tool: ' + name)


def wait_for(condition, description, timeout=6):
    deadline = time.monotonic() + timeout
    while not condition():
        if time.monotonic() >= deadline:
            raise AssertionError('timed out: ' + description)
        time.sleep(0.01)


def uuid7():
    bits = (int(time.time() * 1000) << 80) | (7 << 76)
    bits |= (uuid.uuid4().int & ((1 << 76) - 1))
    bits = (bits & ~(3 << 62)) | (2 << 62)
    return str(uuid.UUID(int=bits))


def canonical(value):
    # All fixture values are ASCII strings and bounded integers, for which
    # this representation is identical to the required JCS encoding.
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def frame(kind, value):
    payload = canonical(value)
    return bytes([kind]) + struct.pack('>I', len(payload)) + payload


def receive(stream, kind):
    def exact(count):
        data = b''
        while len(data) < count:
            chunk = stream.recv(count - len(data))
            if not chunk:
                raise AssertionError('unexpected control EOF')
            data += chunk
        return data
    header = exact(5)
    assert header[0] == kind, header
    size = struct.unpack('>I', header[1:])[0]
    assert 0 < size <= (524288 if kind == 2 else 128)
    return json.loads(exact(size))


def unprivileged():
    os.setgroups([])
    os.setgid(65534)
    os.setuid(65534)


class Fixture:
    def __init__(self, parent, binaries):
        self.parent = parent
        self.binaries = binaries
        self.directory = tempfile.TemporaryDirectory(prefix='sigrund-runtime-')
        self.base = Path(self.directory.name)
        self.base.chmod(0o755)
        self.client_binary = self.base / 'sigrun'
        shutil.copyfile(binaries / 'sigrun', self.client_binary)
        self.client_binary.chmod(0o755)
        self.state = self.base / 'state'
        self.log = self.base / 'log' / 'audit.jsonl'
        self.client = self.base / 'client.sock'
        self.approval = self.base / 'approval.sock'
        self.key = self.base / 'signer'
        self.group = parent / ('sigrund-runtime-' + uuid.uuid4().hex)
        self.group.mkdir()
        self.process = None
        self.group_fd = os.open(self.group / 'cgroup.procs', os.O_WRONLY | os.O_CLOEXEC)
        self.diagnostics = self.base / 'diagnostics'
        self.stdout = open(self.base / 'daemon.stdout', 'wb')
        self.stderr = open(self.diagnostics, 'ab', buffering=0)
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(self.key)], check=True)
        root = self.base / 'commands'
        root.mkdir()
        self.commands = root
        for name in ('id', 'true', 'sleep', 'false', 'cat'):
            shutil.copyfile(command_source(name), root / name)
            (root / name).chmod(0o755)
        roots = json.dumps(sorted(['/usr/bin', str(root)]))
        config = (REPO / 'config/sigrund.toml.example').read_text()
        config = config.replace('["/usr/bin", "/usr/sbin"]', roots)
        config = config.replace('<strict-padded-base64-32-byte-ed25519-key>', base64.b64encode(bytes(32)).decode())
        config = config.replace('shutdown_grace_ms = 10000', 'shutdown_grace_ms = 500')
        config = config.replace('request_admissions_per_uid = 16', 'request_admissions_per_uid = 256')
        for name in ('collector-ca.pem', 'collector-client.crt', 'collector-client.key'):
            path = self.base / name
            path.write_text('no network use in local-audit gate\n')
            config = config.replace('/etc/sigrund/' + name, str(path))
        config += '\n[mvp]\n'
        (self.base / 'config').write_text(config)
        signer = (REPO / 'config/signers.toml.example').read_text()
        signer = signer.replace('type = "sk-ssh-ed25519"', 'type = "ssh-ed25519"')
        signer = signer.replace('sk-ssh-ed25519@openssh.com AAAA...', self.key.with_suffix('.pub').read_text().strip())
        signer = signer.replace('require_user_presence = true', 'require_user_presence = false')
        signer = signer.replace('allowed_requester_uids = [1001]', 'allowed_requester_uids = [0, 65534]')
        signer = signer.replace('["/usr/bin", "/usr/sbin"]', roots)
        (self.base / 'signers').write_text(signer)
        subprocess.run([str(binaries / 'sigrund'), '--check-config', '--config', str(self.base / 'config'),
                        '--signers', str(self.base / 'signers')], check=True)
        subprocess.run([str(binaries / 'sigrundctl'), 'init-host', '--state-dir', str(self.state), '--log-path', str(self.log)], check=True, capture_output=True)

    def launch(self, env=None, pass_fds=(), expect_ready=True):
        # Stale socket entries are an operator/supervisor responsibility after
        # forced death; normal shutdown must remove them itself.
        entry_fd = self.group_fd
        supervisor = self.group / 'supervisor' / 'cgroup.procs'
        if supervisor.exists():
            entry_fd = os.open(supervisor, os.O_WRONLY | os.O_CLOEXEC)
        def enter():
            os.write(entry_fd, str(os.getpid()).encode())
        log_offset = self.diagnostics.stat().st_size if self.diagnostics.exists() else 0
        try:
            self.process = subprocess.Popen([
                str(self.binaries / 'sigrund'), '--foreground', '--config', str(self.base / 'config'),
                '--signers', str(self.base / 'signers'), '--state-dir', str(self.state),
                '--log-path', str(self.log), '--socket', str(self.client), '--approval-socket', str(self.approval),
            ], preexec_fn=enter, env=env, pass_fds=pass_fds, stdout=self.stdout, stderr=self.stderr)
        finally:
            if entry_fd != self.group_fd:
                os.close(entry_fd)
        if not expect_ready:
            return self
        def ready():
            if self.process.poll() is not None:
                raise AssertionError(self.diagnostics.read_text())
            return self.client.exists() and 'DAEMON_READY' in self.diagnostics.read_text()[log_offset:]
        wait_for(ready, 'daemon startup')
        return self

    def signed(self, command, args=(), uid=65534, target_uid=33,
               capabilities=(), env_exact=None, input_bytes=None,
               supplementary_gids=(33,)):
        genesis = json.loads(self.log.read_text().splitlines()[0])
        payload = canonical({
            'version': '1.0', 'grant_id': uuid7(), 'host_id': genesis['host_id'],
            'requester_uid': uid, 'requester_gid': uid,
            'command': {'allow_interpreted_script': False, 'argv': [str(command), *args], 'cwd': '/',
                        'executable_path': str(command), 'executable_sha256': hashlib.sha256(Path(command).read_bytes()).hexdigest(),
                        'stdin_policy': 'null' if input_bytes is None else 'sha256',
                        'stdin_sha256': None if input_bytes is None else hashlib.sha256(input_bytes).hexdigest(),
                        'tty_mode': 'stdio'},
            'execution_context': {'target_uid': target_uid, 'target_gid': target_uid,
                                  'supplementary_gids': list(supplementary_gids),
                                  'capabilities': list(capabilities), 'env_exact': env_exact or {},
                                  'caller_env_allowlist': [], 'umask': 0o027},
            'policy': {'mode': 'one_time', 'not_before': int(time.time()) - 1, 'not_after': int(time.time()) + 120},
        })
        kind = b'application/vnd.sigrun.warrant.v1+json'
        pae = b'DSSEv1 ' + str(len(kind)).encode() + b' ' + kind + b' ' + str(len(payload)).encode() + b' ' + payload
        signed = subprocess.run(['ssh-keygen', '-Y', 'sign', '-n', 'sigrun.warrant.v1', '-O', 'hashalg=sha512', '-f', str(self.key)], input=pae, capture_output=True, check=True).stdout
        signature = base64.b64decode(b''.join(signed.splitlines()[1:-1]))
        envelope = {'payloadType': kind.decode(), 'payload': base64.b64encode(payload).decode(),
                    'signatures': [{'keyid': SIGNER, 'sig': base64.b64encode(signature).decode()}]}
        path = self.base / ('warrant-' + uuid.uuid4().hex + '.json')
        path.write_bytes(canonical(envelope))
        path.chmod(0o644)
        return path, envelope

    def cli(self, command, args=()):
        warrant, _ = self.signed(command, args)
        return subprocess.Popen([str(self.client_binary), '--socket', str(self.client), '--warrant', str(warrant)],
                                preexec_fn=unprivileged, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def socket(self, command, args=()):
        _, envelope = self.signed(command, args, uid=0)
        stream = socket.socket(socket.AF_UNIX)
        stream.settimeout(6)
        stream.connect(str(self.client))
        hello = frame(1, {'mode': 'signed', 'tty_mode': 'stdio', 'caller_env': {}, 'dsse_envelope': envelope})
        with open('/dev/null', 'r+b') as null:
            import array
            stream.sendmsg([hello[:1]], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [null.fileno(), null.fileno()]))])
        stream.sendall(hello[1:])
        return stream

    def records(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def empty(self):
        return not list((self.group / 'jobs').glob('job-*'))

    def stop(self, sig=signal.SIGTERM):
        self.process.send_signal(sig)
        self.process.wait(timeout=6)
        assert self.process.returncode == 0, self.diagnostics.read_text()
        assert not self.client.exists() and not self.approval.exists()
        assert self.empty()

    def cleanup(self):
        (self.group / 'cgroup.kill').write_text('1\n')
        if self.process:
            self.process.wait(timeout=6)
        wait_for(lambda: 'populated 0' in (self.group / 'cgroup.events').read_text(), 'fixture cgroup empty')
        for path in sorted(self.group.rglob('*'), key=lambda p: len(p.parts), reverse=True):
            if path.is_dir():
                path.rmdir()
        os.close(self.group_fd)
        self.group.rmdir()
        self.stdout.close()
        self.stderr.close()
        self.directory.cleanup()


class Gate:
    def __init__(self, fixture, mode, durable=False):
        self.fixture = fixture
        self.entered, self.worker_entered = socket.socketpair()
        self.release, self.worker_release = socket.socketpair()
        self.arm_path = fixture.base / 'armed'
        self.durable = durable
        library = fixture.base / 'gate.so'
        name = 'storage/durable.c' if durable else 'execution/faults.c'
        subprocess.run(['cc', '-shared', '-fPIC', '-Wall', '-Werror', '-o', str(library),
                        str(REPO / 'crates/sigrund/tests/fixtures' / name), '-ldl'], check=True)
        prefix = 'SIGRUND_DURABLE_' if durable else 'SIGRUND_EXEC_'
        env = dict(os.environ, LD_PRELOAD=str(library))
        env[prefix + ('POINT' if durable else 'MODE')] = mode
        env[prefix + 'ARM'] = str(self.arm_path)
        env[prefix + 'ENTERED'] = str(self.worker_entered.fileno())
        env[prefix + 'RELEASE'] = str(self.worker_release.fileno())
        fixture.launch(env, (self.worker_entered.fileno(), self.worker_release.fileno()))
        self.worker_entered.close()
        self.worker_release.close()

    def arm(self):
        self.arm_path.write_text('armed')

    def arrive(self):
        assert select.select([self.entered], [], [], 6)[0], self.fixture.diagnostics.read_text()
        size = 8 if self.durable else 16
        data = b''
        while len(data) < size:
            data += self.entered.recv(size - len(data))
        tid = struct.unpack('=Q', data[:8])[0]
        assert tid != self.fixture.process.pid, 'blocking operation ran on coordinator'
        return struct.unpack('=Q', data[8:])[0] if size == 16 else 0

    def unblock(self):
        self.release.sendall(b'x')

    def close(self):
        self.entered.close()
        self.release.close()


def assert_lock_held(fixture):
    with open(fixture.state / 'daemon.lock', 'rb') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return
        raise AssertionError('instance lock released before reconciliation')


def registration_shutdown(parent, binaries):
    f = Fixture(parent, binaries)
    gate = None
    try:
        gate = Gate(f, 'clone-after')
        known = f.socket(f.commands / 'sleep', ('0.4',))
        decision = receive(known, 2)
        assert decision['status'] == 'READY_TO_EXEC'
        known_pid = next(r['child_pid'] for r in f.records() if r.get('event_type') == 'EXEC_READY_TO_EXEC' and r['exec_id'] == decision['exec_id'])
        gate.arm()
        pending = f.socket(f.commands / 'sleep', ('0.05',))
        pending_pid = gate.arrive()
        wait_for(lambda: not Path('/proc', str(known_pid)).exists(), 'registered primary reaped during barrier')
        wait_for(lambda: Path('/proc', str(pending_pid), 'stat').read_text().split(') ')[1].startswith('Z'), 'unpublished child exits but remains waitable')
        gate.unblock()
        assert receive(pending, 2)['status'] == 'READY_TO_EXEC'
        assert receive(pending, 5) == {'exit_code': 0, 'signal': None}
        assert receive(known, 5) == {'exit_code': 0, 'signal': None}
        assert pending.recv(1) == b'' and known.recv(1) == b''
        pending.close()
        known.close()
        wait_for(f.empty, 'both concurrent cgroups removed')
        gate.arm()
        pending = f.socket(f.commands / 'sleep', ('30',))
        gate.arrive()
        f.process.send_signal(signal.SIGTERM)
        assert pending.recv(1) == b''
        assert f.process.poll() is None
        assert_lock_held(f)
        gate.unblock()
        f.process.wait(timeout=6)
        assert f.process.returncode == 0, f.diagnostics.read_text()
        pending.close()
        assert f.empty()
        print(json.dumps({'gate': 'runtime-registration-shutdown', 'result': 'passed'}), flush=True)
    finally:
        if gate:
            gate.close()
        f.cleanup()


def commit_shutdown(parent, binaries):
    for point in ('predicate-before', 'wal-before', 'wal-after'):
        f = Fixture(parent, binaries)
        gate = None
        try:
            gate = Gate(f, point, durable=True)
            gate.arm()
            client = f.socket(f.commands / 'true')
            gate.arrive()
            f.process.send_signal(signal.SIGTERM)
            assert client.recv(1) == b''
            assert f.process.poll() is None
            assert_lock_held(f)
            gate.unblock()
            f.process.wait(timeout=6)
            assert f.process.returncode == 0, f.diagnostics.read_text()
            assert f.empty()
            records = f.records()
            if point == 'predicate-before':
                assert not any(r.get('event_type') == 'AUTH_COMMIT' for r in records)
            else:
                assert any(r.get('event_type') == 'AUTH_ABORTED_POST_COMMIT' for r in records)
            assert not any(r.get('event_type') == 'EXEC_READY_TO_EXEC' for r in records)
            client.close()
            print(json.dumps({'gate': 'runtime-commit-shutdown', 'point': point, 'result': 'passed'}), flush=True)
        finally:
            if gate:
                gate.close()
            f.cleanup()


def cleanup_shutdown(parent, binaries):
    f = Fixture(parent, binaries)
    gate = None
    try:
        gate = Gate(f, 'cleanup-before')
        client = f.socket(f.commands / 'sleep', ('30',))
        assert receive(client, 2)['status'] == 'READY_TO_EXEC'
        gate.arm()
        client.close()
        gate.arrive()
        f.process.send_signal(signal.SIGINT)
        wait_for(lambda: 'SHUTDOWN_CLEANUP_STALLED' in f.diagnostics.read_text(), 'bounded stalled-cleanup diagnostic')
        assert f.process.poll() is None
        assert_lock_held(f)
        gate.unblock()
        f.process.wait(timeout=6)
        assert f.process.returncode == 0, f.diagnostics.read_text()
        assert f.empty()
        print(json.dumps({'gate': 'runtime-blocked-cleanup-shutdown', 'result': 'passed'}), flush=True)
    finally:
        if gate:
            gate.close()
        f.cleanup()


def poisoned_shutdown(parent, binaries):
    f = Fixture(parent, binaries)
    gate = None
    try:
        gate = Gate(f, 'state-fail', durable=True)
        running = f.socket(f.commands / 'sleep', ('30',))
        assert receive(running, 2)['status'] == 'READY_TO_EXEC'
        gate.arm()
        pending = f.socket(f.commands / 'true')
        gate.arrive()
        gate.unblock()
        f.process.wait(timeout=6)
        assert f.process.returncode == 78, f.diagnostics.read_text()
        assert running.recv(1) == b'' and pending.recv(1) == b''
        running.close()
        pending.close()
        assert f.empty()
        # A poisoned writer must not append any post-failure execution records.
        records = f.records()
        assert records[-1]['event_type'] == 'AUTH_COMMIT', records[-1]
        f.launch()
        f.stop()
        assert any(r.get('event_type') == 'RATCHET_FORWARD_RECOVERY' for r in f.records())
        print(json.dumps({'gate': 'runtime-poisoned-shutdown', 'result': 'passed'}), flush=True)
    finally:
        if gate:
            gate.close()
        f.cleanup()


def runtime_lifecycle(parent, binaries):
    f = Fixture(parent, binaries)
    try:
        f.launch()
        baseline = len(list(Path('/proc', str(f.process.pid), 'fd').iterdir()))
        for executable, args, expected in [(f.commands / 'id', (), 0), (f.commands / 'false', (), 1), (f.commands / 'true', (), 0)]:
            cli = f.cli(executable, args)
            out, err = cli.communicate(timeout=6)
            assert cli.returncode == expected, (cli.returncode, out, err, f.diagnostics.read_text())
            if executable == f.commands / 'id':
                assert b'uid=33' in out and b'gid=33' in out, out
            wait_for(f.empty, 'normal cgroup teardown')
            wait_for(lambda: len(list(Path('/proc', str(f.process.pid), 'fd').iterdir())) == baseline, 'request FD/pidfd disposal')
        client = f.socket(f.commands / 'sleep', ('30',))
        assert receive(client, 2)['status'] == 'READY_TO_EXEC'
        client.sendall(frame(3, {'signal': signal.SIGTERM}))
        assert receive(client, 5) == {'exit_code': None, 'signal': signal.SIGTERM}
        client.close()
        wait_for(f.empty, 'signalled cgroup teardown')
        client = f.socket(f.commands / 'sleep', ('30',))
        assert receive(client, 2)['status'] == 'READY_TO_EXEC'
        client.close()
        wait_for(f.empty, 'disconnect cgroup teardown')
        wait_for(lambda: any(r.get('event_type') == 'EXEC_EXIT' and r.get('disconnected') for r in f.records()), 'disconnect audit')
        client = f.socket(f.commands / 'sleep', ('30',))
        assert receive(client, 2)['status'] == 'READY_TO_EXEC'
        f.stop(signal.SIGINT)
        assert client.recv(1) == b''
        client.close()
        f.launch()
        f.stop()
        print(json.dumps({'gate': 'runtime-runtime', 'result': 'passed', 'observed_uid': 33, 'fd_baseline': baseline}), flush=True)
    finally:
        f.cleanup()


def orphan_recovery(parent, binaries):
    f = Fixture(parent, binaries)
    try:
        f.launch()
        running = f.socket(f.commands / 'sleep', ('30',))
        decision = receive(running, 2)
        assert decision['status'] == 'READY_TO_EXEC'
        f.process.kill()
        f.process.wait(timeout=6)
        assert f.process.returncode == -signal.SIGKILL
        assert not f.empty(), 'forced death unexpectedly performed cooperative cleanup'
        # The enclosing supervising service remains responsible for final
        # cleanup if restart cannot reconcile these prior-instance cgroups.
        f.client.unlink()
        f.approval.unlink()
        f.launch()
        assert f.empty()
        records = f.records()
        assert any(r.get('event_type') == 'ORPHAN_CLEANUP' and r.get('cgroups') == 1 for r in records)
        assert not any(r.get('event_type') == 'EXEC_EXIT' and r.get('exec_id') == decision['exec_id'] for r in records), 'new daemon fabricated a prior-instance wait status'
        f.stop()
        running.close()
        print(json.dumps({'gate': 'runtime-prior-instance-orphan-recovery', 'result': 'passed'}), flush=True)
    finally:
        f.cleanup()


def pre_spawn_shutdown(parent, binaries):
    for mode in ('prepare-before', 'stop-before-ready'):
        f = Fixture(parent, binaries)
        gate = None
        try:
            gate = Gate(f, mode)
            gate.arm()
            client = f.socket(f.commands / 'sleep', ('30',))
            if mode == 'prepare-before':
                gate.arrive()
                assert not list((f.group / 'jobs').glob('job-*/cgroup.procs')) or all(
                    not path.read_text().strip() for path in (f.group / 'jobs').glob('job-*/cgroup.procs'))
            else:
                def stopped():
                    for path in (f.group / 'jobs').glob('job-*/cgroup.procs'):
                        for pid in path.read_text().split():
                            status = Path('/proc', pid, 'stat')
                            if status.exists() and status.read_text().split(') ')[1].startswith('T'):
                                return True
                    return False
                wait_for(stopped, 'child stopped before writing readiness')
            f.process.send_signal(signal.SIGTERM)
            assert client.recv(1) == b'', 'readiness published after shutdown began'
            if mode == 'prepare-before':
                assert_lock_held(f)
                gate.unblock()
            f.process.wait(timeout=6)
            assert f.process.returncode == 0, f.diagnostics.read_text()
            assert f.empty()
            assert not any(r.get('event_type') == 'EXEC_READY_TO_EXEC' for r in f.records())
            assert any(r.get('event_type') == ('AUTH_ABORTED_POST_COMMIT' if mode == 'prepare-before'
                                             else 'EXEC_SPAWN_FAILED') for r in f.records())
            client.close()
            print(json.dumps({'gate': 'runtime-pre-spawn-readiness-shutdown', 'point': mode, 'result': 'passed'}), flush=True)
        finally:
            if gate:
                gate.close()
            f.cleanup()


def restart_trust(parent, binaries):
    f = Fixture(parent, binaries)
    try:
        f.launch()
        f.stop()
        hooks = f.group / 'hooks'
        hooks.chmod(0o777)
        try:
            f.launch(expect_ready=False)
            f.process.wait(timeout=6)
            assert f.process.returncode == 78
            assert not f.client.exists() and not f.approval.exists()
        finally:
            hooks.chmod(0o755)
        f.launch()
        f.stop()
        print(json.dumps({'gate': 'runtime-retained-layout-trust', 'result': 'passed'}), flush=True)
    finally:
        f.cleanup()


class SystemService:
    """A fresh real service with an independent final cleanup deadline."""
    def __init__(self, fixture, env=None):
        from gi.repository import Gio, GLib
        self.Gio, self.GLib = Gio, GLib
        self.bus = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)
        self.unit = 'sigrund-runtime-service-' + uuid.uuid4().hex + '.service'
        self.path = None
        self.fixture = fixture
        self.group = Path('/sys/fs/cgroup/system.slice') / self.unit
        self.original_group = fixture.group
        command = ['/usr/bin/nsenter', '--mount=/proc/' + str(os.getpid()) + '/ns/mnt',
                   '--root=/proc/' + str(os.getpid()) + '/root', '--',
                   str(fixture.binaries / 'sigrund'), '--foreground',
                   '--config', str(fixture.base / 'config'), '--signers', str(fixture.base / 'signers'),
                   '--state-dir', str(fixture.state), '--log-path', str(fixture.log),
                   '--socket', str(fixture.client), '--approval-socket', str(fixture.approval)]
        variant = GLib.Variant
        descriptors = Gio.UnixFDList.new()
        output = descriptors.append(fixture.stderr.fileno())
        props = [('Description', variant('s', 'sigrund stop/restart and escalation fixture')),
                 ('Type', variant('s', 'notify')), ('NotifyAccess', variant('s', 'main')),
                 ('Delegate', variant('b', True)), ('KillMode', variant('s', 'control-group')),
                 ('SendSIGKILL', variant('b', True)), ('TimeoutStartUSec', variant('t', 10000000)),
                 ('TimeoutStopUSec', variant('t', 3000000)), ('WatchdogUSec', variant('t', 2000000)),
                 ('RuntimeMaxUSec', variant('t', 20000000)),
                 ('StandardOutputFileDescriptor', variant('h', output)),
                 ('StandardErrorFileDescriptor', variant('h', output)),
                 ('Environment', variant('as', ['PATH=/usr/sbin:/usr/bin:/sbin:/bin'] + [k + '=' + v for k, v in (env or {}).items()])),
                 ('ExecStart', variant('a(sasb)', [(command[0], command, False)]))]
        self.bus.call_with_unix_fd_list_sync('org.freedesktop.systemd1', '/org/freedesktop/systemd1',
            'org.freedesktop.systemd1.Manager', 'StartTransientUnit',
            variant('(ssa(sv)a(sa(sv)))', (self.unit, 'fail', props, [])), None,
            Gio.DBusCallFlags.NONE, 10000, descriptors, None)
        self.path = self.call('/org/freedesktop/systemd1', 'org.freedesktop.systemd1.Manager',
                              'GetUnit', variant('(s)', (self.unit,)))[0]
        fixture.group = self.group
        wait_for(lambda: self.properties()['SubState'] == 'running', 'notify service readiness')
        print(json.dumps({'event': 'RUNTIME_SERVICE_READY', 'unit': self.unit}), flush=True)

    def call(self, path, interface, method, args):
        return self.bus.call_sync('org.freedesktop.systemd1', path, interface, method, args,
                                 None, self.Gio.DBusCallFlags.NONE, 10000, None).unpack()

    def properties(self, interface='org.freedesktop.systemd1.Unit'):
        return self.call(self.path, 'org.freedesktop.DBus.Properties', 'GetAll',
                         self.GLib.Variant('(s)', (interface,)))[0]

    def dead(self):
        try:
            return self.properties()['ActiveState'] in ('inactive', 'failed')
        except self.GLib.Error:
            return True

    def stop(self):
        self.call('/org/freedesktop/systemd1', 'org.freedesktop.systemd1.Manager', 'StopUnit',
                  self.GLib.Variant('(ss)', (self.unit, 'replace')))
        wait_for(self.dead, 'systemd service stop', timeout=8)
        self.check_empty()

    def check_empty(self):
        assert not self.group.exists() or 'populated 0' in (self.group / 'cgroup.events').read_text()

    def close(self):
        try:
            if not self.dead():
                self.stop()
            self.check_empty()
            try:
                self.call('/org/freedesktop/systemd1', 'org.freedesktop.systemd1.Manager', 'ResetFailedUnit',
                          self.GLib.Variant('(s)', (self.unit,)))
            except self.GLib.Error:
                pass
        finally:
            self.fixture.group = self.original_group


def service_lifecycle(parent, binaries):
    f = Fixture(parent, binaries)
    service = None
    try:
        service = SystemService(f)
        running = f.socket(f.commands / 'sleep', ('30',))
        assert receive(running, 2)['status'] == 'READY_TO_EXEC'
        service.stop()
        assert running.recv(1) == b''
        running.close()
        service.close()
        service = SystemService(f)
        running = f.socket(f.commands / 'sleep', ('30',))
        assert receive(running, 2)['status'] == 'READY_TO_EXEC'
        pid = service.properties('org.freedesktop.systemd1.Service')['MainPID']
        os.kill(pid, signal.SIGKILL)
        wait_for(service.dead, 'whole-service cleanup after forced daemon death')
        service.check_empty()
        running.close()
        service.close()
        # Operator-owned transient socket cleanup after abrupt death.
        f.client.unlink(missing_ok=True)
        f.approval.unlink(missing_ok=True)
        service = SystemService(f)
        cli = f.cli(f.commands / 'id')
        out, err = cli.communicate(timeout=6)
        assert cli.returncode == 0 and b'uid=33' in out, (out, err)
        service.stop()
        print(json.dumps({'gate': 'runtime-systemd-stop-restart-death', 'result': 'passed'}), flush=True)
    finally:
        if service:
            service.close()
        f.cleanup()

    f = Fixture(parent, binaries)
    service = None
    try:
        library = f.base / 'execution.so'
        subprocess.run(['cc', '-shared', '-fPIC', '-Wall', '-Werror', '-o', str(library),
                        str(REPO / 'crates/sigrund/tests/fixtures/execution/faults.c'), '-ldl'], check=True)
        arm = f.base / 'armed'
        service = SystemService(f, {'LD_PRELOAD': str(library), 'SIGRUND_EXEC_MODE': 'cleanup-fail', 'SIGRUND_EXEC_ARM': str(arm)})
        running = f.socket(f.commands / 'sleep', ('30',))
        assert receive(running, 2)['status'] == 'READY_TO_EXEC'
        arm.write_text('armed')
        running.close()
        # The cleanup owner parks after its failed kill. Fatal shutdown stops
        # watchdog heartbeats, so systemd must escalate without an operator stop.
        wait_for(service.dead, 'automatic escalation of internally initiated fatal shutdown', timeout=9)
        service.check_empty()
        assert 'SHUTDOWN_CLEANUP_STALLED' in f.diagnostics.read_text(), f.diagnostics.read_text()
        with open(f.state / 'daemon.lock', 'rb') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        print(json.dumps({'gate': 'runtime-systemd-fatal-escalation', 'result': 'passed'}), flush=True)
    finally:
        if service:
            service.close()
        f.cleanup()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cgroup-parent', type=Path, required=True)
    parser.add_argument('--systemd', action='store_true', help='also create bounded transient services for stop/restart/escalation tests')
    parser.add_argument('--binaries', type=Path, default=REPO / 'target/debug')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('root required')
    assert {'memory', 'pids'} <= set((args.cgroup_parent / 'cgroup.subtree_control').read_text().split())
    runtime_lifecycle(args.cgroup_parent, args.binaries)
    registration_shutdown(args.cgroup_parent, args.binaries)
    commit_shutdown(args.cgroup_parent, args.binaries)
    pre_spawn_shutdown(args.cgroup_parent, args.binaries)
    cleanup_shutdown(args.cgroup_parent, args.binaries)
    poisoned_shutdown(args.cgroup_parent, args.binaries)
    orphan_recovery(args.cgroup_parent, args.binaries)
    restart_trust(args.cgroup_parent, args.binaries)
    if args.systemd:
        service_lifecycle(args.cgroup_parent, args.binaries)


if __name__ == '__main__':
    main()
