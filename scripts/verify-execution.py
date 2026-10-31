#!/usr/bin/python3
"""Real-execution failure/race gate; run in a supervised root service.

Uses the disposable runtime fixture and production daemon/client. Faults are
injected only by the separately compiled native test interposer. A successful
run requires a real strace attachment and retains observations in --artifacts.
The parent must already delegate memory/pids and have a final service deadline
and whole-service cleanup. This script never changes an unrelated cgroup.
"""
import argparse
import array
import hashlib
import json
import os
from pathlib import Path
import platform
import pty
import runpy
import select
import signal
import socket
import subprocess
import termios
import time

SHARED = runpy.run_path(str(Path(__file__).with_name('verify-runtime.py')))
Fixture, Gate = SHARED['Fixture'], SHARED['Gate']
canonical, frame, receive = SHARED['canonical'], SHARED['frame'], SHARED['receive']
wait_for, unprivileged, REPO = SHARED['wait_for'], SHARED['unprivileged'], SHARED['REPO']
CLIENT_PROGRESS = SHARED['CLIENT_PROGRESS']


class Evidence:
    def __init__(self, root):
        root.mkdir(parents=True, exist_ok=True)
        self.root = root
        self.results = []
        self.manifest = {'suite': 'execution', 'kernel': platform.release(),
                         'machine': platform.machine(), 'command': list(os.sys.argv),
                         'binaries': {}, 'gates': self.results, 'result': 'incomplete'}
        self.save()

    def save(self):
        (self.root / 'manifest.json').write_text(json.dumps(self.manifest, indent=2) + '\n')

    def capture(self, fixture, label):
        directory = self.root / label
        directory.mkdir(exist_ok=True)
        (directory / 'audit.jsonl').write_bytes(fixture.log.read_bytes())
        (directory / 'diagnostics.jsonl').write_bytes(fixture.diagnostics.read_bytes())
        (directory / 'observation.json').write_text(json.dumps({
            'daemon_command': fixture.process.args if fixture.process else None,
            'daemon_status': fixture.process.poll() if fixture.process else None,
            'cgroup': str(fixture.group), 'jobs': [p.name for p in (fixture.group / 'jobs').glob('job-*')],
        }, indent=2) + '\n')
        return directory

    def passed(self, name, **observations):
        record = {'gate': name, 'result': 'passed', **observations}
        self.results.append(record)
        self.save()
        print(json.dumps(record), flush=True)


def connect_envelope(fixture, envelope):
    stream = socket.socket(socket.AF_UNIX)
    stream.settimeout(6)
    stream.connect(str(fixture.client))
    hello = frame(1, {'mode': 'signed', 'tty_mode': 'stdio', 'caller_env': {}, 'dsse_envelope': envelope})
    with open('/dev/null', 'r+b') as null:
        stream.sendmsg([hello[:1]], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                                    array.array('i', [null.fileno(), null.fileno()]))])
    stream.sendall(hello[1:])
    return stream


def records_for(fixture, decision):
    return [r for r in fixture.records() if r.get('exec_id') == decision['exec_id']]


def run_cli(fixture, command, args=(), input_bytes=None, **settings):
    warrant, _ = fixture.signed(command, args, input_bytes=input_bytes, **settings)
    status = fixture.base / ('status-' + warrant.stem)
    with open(status, 'w+b') as output:
        client = subprocess.Popen([str(fixture.client_binary), '--socket', str(fixture.client),
                                   '--warrant', str(warrant), '--status-fd', str(output.fileno())],
                                  preexec_fn=unprivileged, pass_fds=(output.fileno(),),
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            stdout, stderr = client.communicate(input=input_bytes, timeout=8)
        finally:
            if client.poll() is None:
                client.kill()
                client.communicate(timeout=6)
        output.seek(0)
        events = [json.loads(line) for line in output]
    return client.returncode, stdout, stderr, events


def failed_request(fixture, envelope, evidence, name, reason=None, minimum_duration=0):
    start = time.monotonic()
    stream = connect_envelope(fixture, envelope)
    decision = receive(stream, 2)
    assert decision['status'] == 'SPAWN_FAILED', decision
    assert stream.recv(1) == b'', 'setup failure sent a terminal frame'
    stream.close()
    wait_for(fixture.empty, 'failed-job cleanup')
    records = records_for(fixture, decision)
    assert [r['event_type'] for r in records] == ['AUTH_COMMIT', 'EXEC_SPAWN_FAILED'], records
    if reason is not None:
        assert reason in records[-1]['reason'], records[-1]
    # Every post-commit failure consumes the very same signed bytes permanently.
    replay = connect_envelope(fixture, envelope)
    assert receive(replay, 2)['status'] == 'REPLAY_DETECTED'
    assert replay.recv(1) == b''
    replay.close()
    duration = time.monotonic() - start
    assert duration >= minimum_duration, (name, duration)
    evidence.passed(name, duration_secs=round(duration, 3),
                    decision=decision['status'], reason=records[-1]['reason'], replay='REPLAY_DETECTED')
    return records[-1]['reason']


def transition_failures(parent, binaries, evidence):
    modes = [(f'step-{step}', f'SetupFailed {{ step: {step}, errno: 5 }}') for step in range(1, 11)]
    modes += [('step-11', 'ExecFailed { errno: 5 }')]
    modes += [('fd-exhaust', 'errno: 24'), ('clone-fail', 'child clone failed'),
              ('kill-before-ready', 'SpawnFailed'), ('partial-ready', 'SpawnFailed'),
              ('excess-ready', 'SpawnFailed'), ('stop-before-ready', 'SpawnFailed'),
              ('stop-after-ready', 'SpawnFailed')]
    for mode, reason in modes:
        fixture = Fixture(parent, binaries)
        gate = None
        try:
            gate = Gate(fixture, mode)
            gate.arm()
            _, envelope = fixture.signed(fixture.commands / 'true', uid=0)
            failed_request(fixture, envelope, evidence, mode, reason,
                           minimum_duration=1.8 if mode.startswith('stop-') else 0)
            fixture.stop()
        finally:
            evidence.capture(fixture, mode)
            if gate:
                gate.close()
            fixture.cleanup()


def kernel_exec_error(parent, binaries, evidence):
    fixture = Fixture(parent, binaries)
    try:
        malformed = fixture.commands / 'malformed-elf'
        malformed.write_bytes(b'\x7fELF' + bytes(124))
        malformed.chmod(0o755)
        fixture.launch()
        _, envelope = fixture.signed(malformed, uid=0)
        # Snapshot shape accepts ELF magic; the real kernel rejects its header.
        failed_request(fixture, envelope, evidence, 'kernel-exec-error', 'ExecFailed { errno: 8 }')
        fixture.stop()
    finally:
        evidence.capture(fixture, 'kernel-exec-error')
        fixture.cleanup()


def post_token_death(parent, binaries, evidence):
    fixture = Fixture(parent, binaries)
    gate = None
    try:
        gate = Gate(fixture, 'kill-after-ready')
        gate.arm()
        stream = fixture.socket(fixture.commands / 'true')
        decision = receive(stream, 2)
        assert decision['status'] == 'READY_TO_EXEC', decision
        assert receive(stream, 5) == {'exit_code': None, 'signal': signal.SIGKILL}
        assert stream.recv(1) == b''
        stream.close()
        wait_for(fixture.empty, 'post-token killed child cleanup')
        records = records_for(fixture, decision)
        assert [r['event_type'] for r in records] == ['AUTH_COMMIT', 'EXEC_READY_TO_EXEC', 'EXEC_EXIT'], records
        assert records[1]['exec_outcome'] == 'unknown'
        assert records[2]['signal'] == signal.SIGKILL and records[2]['exit_code'] is None
        fixture.stop()
        evidence.passed('post-token-pre-exec-death', decision='READY_TO_EXEC', exec_outcome='unknown', signal=9)
    finally:
        evidence.capture(fixture, 'post-token-pre-exec-death')
        if gate:
            gate.close()
        fixture.cleanup()


def startup_failures(parent, binaries, evidence):
    for mode in ('swap-unavailable', 'clone-fail', 'mount-unavailable'):
        fixture = Fixture(parent, binaries)
        try:
            library = fixture.base / 'gate.so'
            subprocess.run(['cc', '-shared', '-fPIC', '-Wall', '-Werror', '-o', str(library),
                            str(REPO / 'crates/sigrund/tests/fixtures/execution/faults.c'), '-ldl'], check=True)
            arm = fixture.base / 'armed'
            arm.write_text('armed')
            env = dict(os.environ, LD_PRELOAD=str(library), SIGRUND_EXEC_MODE=mode, SIGRUND_EXEC_ARM=str(arm))
            fixture.launch(env, expect_ready=False)
            fixture.process.wait(timeout=6)
            assert fixture.process.returncode == 78, fixture.diagnostics.read_text()
            assert not fixture.client.exists() and not fixture.approval.exists(), 'failed startup published listeners'
            assert 'DAEMON_READY' not in fixture.diagnostics.read_text()
            assert fixture.empty()
            evidence.passed('startup-' + mode, daemon_status=78, listeners=False,
                            diagnostics=fixture.diagnostics.read_text().strip())
        finally:
            evidence.capture(fixture, 'startup-' + mode)
            fixture.cleanup()


def root_tty_workflow(parent, binaries, evidence):
    """An actual unsigned CLI request, foreground root prompt, SSH sign and exec."""
    fixture = Fixture(parent, binaries)
    approver, client = None, None
    master, slave = pty.openpty()
    directory = evidence.root / 'root-tty-workflow'
    directory.mkdir(exist_ok=True)
    try:
        config = fixture.base / 'config'
        config.write_text(config.read_text() + 'approval_signer_id = "' + SHARED['SIGNER'] + '"\n')
        fixture.launch()
        def controlling_tty():
            import fcntl
            os.setsid()
            fcntl.ioctl(0, termios.TIOCSCTTY, 0)
        with open(directory / 'approver.stderr', 'wb') as errors:
            approver = subprocess.Popen([str(binaries / 'sigrund-approve'), '--socket', str(fixture.approval),
                                         '--tty', '/dev/tty', '--signers', str(fixture.base / 'signers'),
                                         '--identity', str(fixture.key)], stdin=slave, stdout=slave,
                                        stderr=errors, preexec_fn=controlling_tty)
        wait_for(lambda: any('SOCKET_ADMITTED' in line and '"broker":true' in line
                            for line in fixture.diagnostics.read_text().splitlines()), 'root approver attachment')
        for approve in (False, True):
            status_path = directory / ('approved.status.jsonl' if approve else 'refused.status.jsonl')
            with open(status_path, 'w+b') as status:
                command = [str(fixture.client_binary), '--socket', str(fixture.client),
                           '--cwd', '/', '--status-fd', str(status.fileno()), '--', str(fixture.commands / 'id'), '-u']
                client = subprocess.Popen(command, preexec_fn=unprivileged, pass_fds=(status.fileno(),),
                                          cwd='/', stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                prompt = b''
                deadline = time.monotonic() + 6
                while b'Approve and sign? [y/N] ' not in prompt:
                    assert time.monotonic() < deadline, prompt
                    assert select.select([master], [], [], 0.1)[0] or approver.poll() is None
                    if select.select([master], [], [], 0)[0]:
                        prompt += os.read(master, 4096)
                    assert len(prompt) <= 1048576
                (directory / ('approved.prompt.txt' if approve else 'refused.prompt.txt')).write_bytes(prompt)
                for field in (b'requester_uid', b'target_uid', b'argv', b'executable_sha256', b'host_id', b'grant_id'):
                    assert field in prompt, (field, prompt)
                assert b'65534' in prompt and b'id' in prompt
                os.write(master, b'yes\n' if approve else b'no\n')
                stdout, stderr = client.communicate(timeout=8)
                status.seek(0)
                events = [json.loads(line) for line in status]
            if approve:
                assert client.returncode == 0 and stdout == b'0\n' and stderr == CLIENT_PROGRESS, (client.returncode, stdout, stderr, events)
                assert [e.get('status') for e in events] == ['READY_TO_EXEC', None], events
                assert events[1] == {'exit_code': 0, 'signal': None}
                records = records_for(fixture, events[0])
                assert [r['event_type'] for r in records] == ['AUTH_COMMIT', 'EXEC_READY_TO_EXEC', 'EXEC_EXIT'], records
                assert records[0]['requester_uid'] == 65534 and records[0]['target_uid'] == 0
            else:
                assert client.returncode == 255 and not stdout, (client.returncode, stdout, stderr, events)
                assert len(events) == 1 and events[0]['status'] == 'REJECTED', events
                assert not any(r.get('event_type') == 'AUTH_COMMIT' for r in fixture.records())
            wait_for(fixture.empty, 'root-TTY workflow cleanup')
        fixture.stop()
        evidence.passed('root-tty-workflow', requester_uid=65534, approver_uid=0, target_uid=0,
                        signature='ssh-ed25519', refusal_exit=255, approved_exit=0, approved_stdout='0\n')
    finally:
        if client and client.poll() is None:
            client.kill()
            client.communicate(timeout=6)
        if approver and approver.poll() is None:
            approver.terminate()
            approver.wait(timeout=6)
        os.close(master)
        os.close(slave)
        evidence.capture(fixture, 'root-tty-workflow')
        fixture.cleanup()


def controls_and_races(parent, binaries, evidence):
    fixture = Fixture(parent, binaries)
    try:
        fixture.launch()
        baseline = len(list(Path('/proc', str(fixture.process.pid), 'fd').iterdir()))
        for batch in range(4):
            streams = [(fixture.socket(fixture.commands / name), expected)
                       for name, expected in [('true', 0), ('false', 1)]]
            for stream, expected in streams:
                assert receive(stream, 2)['status'] == 'READY_TO_EXEC'
                assert receive(stream, 5) == {'exit_code': expected, 'signal': None}
                assert stream.recv(1) == b''
                stream.close()
            wait_for(fixture.empty, 'concurrent exact exit cleanup')
        for sig in (signal.SIGHUP, signal.SIGINT, signal.SIGUSR1, signal.SIGUSR2, signal.SIGTERM):
            stream = fixture.socket(fixture.commands / 'sleep', ('30',))
            decision = receive(stream, 2)
            assert decision['status'] == 'READY_TO_EXEC'
            stream.sendall(frame(3, {'signal': sig}))
            assert receive(stream, 5) == {'exit_code': None, 'signal': sig}
            assert stream.recv(1) == b''
            stream.close()
            assert records_for(fixture, decision)[-1]['signal'] == sig
            wait_for(fixture.empty, 'signalled job cleanup')
        for kind in ('bad-signal', 'wrong-type', 'ancillary', 'partial-timeout'):
            stream = fixture.socket(fixture.commands / 'sleep', ('30',))
            decision = receive(stream, 2)
            assert decision['status'] == 'READY_TO_EXEC'
            if kind == 'bad-signal':
                stream.sendall(frame(3, {'signal': 9}))
            elif kind == 'wrong-type':
                stream.sendall(b'\x04')
            elif kind == 'ancillary':
                with open('/dev/null', 'rb') as null:
                    stream.sendmsg([b'\x03'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [null.fileno()]))])
            else:
                stream.sendall(b'\x03')
            assert stream.recv(1) == b'', 'malformed control did not close promptly'
            stream.close()
            wait_for(fixture.empty, 'invalid-control teardown')
            wait_for(lambda: any(r.get('event_type') == 'EXEC_EXIT' and r.get('disconnected')
                                for r in records_for(fixture, decision)), 'invalid-control exit audit')
        # No frame means no frame deadline, even after more than five seconds.
        stream = fixture.socket(fixture.commands / 'sleep', ('30',))
        assert receive(stream, 2)['status'] == 'READY_TO_EXEC'
        time.sleep(5.2)
        stream.sendall(frame(3, {'signal': 15}))
        assert receive(stream, 5) == {'exit_code': None, 'signal': 15}
        stream.close()
        wait_for(fixture.empty, 'idle-control teardown')
        wait_for(lambda: len(list(Path('/proc', str(fixture.process.pid), 'fd').iterdir())) == baseline,
                 'all runtime pidfds and request descriptors disposed')
        fixture.stop()
        evidence.passed('control-and-exit-races', concurrent_pairs=4, forwarded_signals=[1, 2, 10, 12, 15],
                        invalid_controls=['bad-signal', 'wrong-type', 'ancillary', 'partial-timeout'], idle_secs=5.2,
                        fd_baseline=baseline)
    finally:
        evidence.capture(fixture, 'control-and-exit-races')
        fixture.cleanup()


def observed_execution(parent, binaries, evidence, strace):
    fixture = Fixture(parent, binaries)
    tracer = None
    label = 'post-exec-observations'
    directory = evidence.root / label
    directory.mkdir(exist_ok=True)
    try:
        policy = fixture.base / 'signers'
        policy.write_text(policy.read_text().replace('allowed_supplementary_gids = [33, 104]',
                                                     'allowed_supplementary_gids = [0, 33, 104]'))
        probe = fixture.commands / 'probe'
        subprocess.run(['cc', '-std=gnu11', '-O2', '-Wall', '-Werror', '-o', str(probe),
                        str(REPO / 'crates/sigrund/tests/fixtures/execution/setup.c')], check=True)
        fixture.launch()
        trace_types = ('clone3,execveat,waitid,pidfd_send_signal,kill,unshare,mount,mount_setattr,close_range,'
                       'dup3,prctl,setgroups,setresuid,setresgid,capset,capget,getresuid,getresgid,getgroups,'
                       'rt_sigaction,rt_sigprocmask,setsid,chdir,umask,memfd_create,fcntl,inotify_add_watch')
        with open(directory / 'strace.stderr', 'wb') as errors:
            tracer = subprocess.Popen([str(strace), '-f', '-ff', '-tt', '-s', '128', '-e', 'trace=' + trace_types,
                                       '-o', str(directory / 'syscalls'), '-p', str(fixture.process.pid)],
                                      stdout=subprocess.DEVNULL, stderr=errors)
        def attached():
            if tracer.poll() is not None:
                raise AssertionError((directory / 'strace.stderr').read_text())
            return 'TracerPid:\t' + str(tracer.pid) in Path('/proc', str(fixture.process.pid), 'status').read_text()
        wait_for(attached, 'real syscall tracer attachment')
        observations = []
        for uid in (0, 33):
            for caps in ((), ('CAP_NET_BIND_SERVICE',)):
                code, out, err, status = run_cli(fixture, probe, ('--observe',), target_uid=uid,
                                               capabilities=caps, supplementary_gids=(uid,),
                                               env_exact={'P5_UID': str(uid), 'P5_CAPS': '1024' if caps else '0', 'P5_ISOLATED': '1'})
                assert code == 0 and err == CLIENT_PROGRESS, (code, out, err, status)
                observed = json.loads(out)
                assert observed['uid'] == [uid] * 3 and observed['gid'] == [uid] * 3, observed
                assert observed['groups'] == [uid]
                for field in ('cap_effective', 'cap_permitted', 'cap_inheritable', 'cap_bounding', 'cap_ambient'):
                    assert observed[field] == (1024 if caps else 0), observed
                assert observed['securebits'] == 47 and observed['no_new_privs'] == 1, observed
                assert observed['umask'] == 0o027 and observed['cwd'] == '/', observed
                assert observed['session'] == observed['pid'] and observed['fd_signal_checks'], observed
                assert [s.get('status') for s in status] == ['READY_TO_EXEC', None], status
                assert status[1] == {'exit_code': 0, 'signal': None}
                observations.append({'target_uid': uid, 'capabilities': list(caps), 'observed': observed, 'status': status})
                wait_for(fixture.empty, 'post-exec probe cleanup')
        content = bytes(range(256)) * 4096
        code, out, err, status = run_cli(fixture, fixture.commands / 'cat', input_bytes=content)
        assert code == 0 and out == content and err == CLIENT_PROGRESS, (code, len(out), err, status)
        assert status[1] == {'exit_code': 0, 'signal': None}
        for name, expected in [('id', 0), ('true', 0), ('false', 1)]:
            code, out, err, status = run_cli(fixture, fixture.commands / name)
            assert code == expected and err == CLIENT_PROGRESS, (code, out, err, status)
            if name == 'id':
                assert b'uid=33' in out and b'gid=33' in out, out
            assert status[1] == {'exit_code': expected, 'signal': None}
        fixture.stop()
        tracer.wait(timeout=6)
        assert tracer.returncode == 0, (directory / 'strace.stderr').read_text()
        traces = list(directory.glob('syscalls.*'))
        trace = '\n'.join(path.read_text() for path in traces)
        for operation in ('CLONE_INTO_CGROUP', 'CLONE_PIDFD', 'execveat(', 'waitid(P_PIDFD',
                          'mount_setattr(', 'setresuid(', 'capset(', 'PR_SET_NO_NEW_PRIVS'):
            assert operation in trace, operation + ' absent from syscall trace'
        (directory / 'observed.json').write_text(json.dumps(observations, indent=2) + '\n')
        evidence.passed(label, combinations=observations, hashed_stdin_bytes=len(content),
                        hashed_stdin_sha256=hashlib.sha256(content).hexdigest(), trace_files=len(traces))
    finally:
        if tracer and tracer.poll() is None:
            tracer.send_signal(signal.SIGINT)
            tracer.wait(timeout=6)
        evidence.capture(fixture, label)
        fixture.cleanup()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cgroup-parent', type=Path, required=True)
    parser.add_argument('--binaries', type=Path, default=REPO / 'target/debug')
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--strace', type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('root required in a dedicated delegated service')
    for path in (args.cgroup_parent, args.binaries, args.artifacts, args.strace):
        if not path.is_absolute():
            parser.error('all supplied paths must be absolute')
    assert {'memory', 'pids'} <= set((args.cgroup_parent / 'cgroup.subtree_control').read_text().split())
    subprocess.run([str(args.strace), '--version'], check=True, capture_output=True)
    evidence = Evidence(args.artifacts)
    evidence.manifest['binaries'] = {name: hashlib.sha256((args.binaries / name).read_bytes()).hexdigest()
                                    for name in ('sigrund', 'sigrun', 'sigrundctl')}
    evidence.save()
    startup_failures(args.cgroup_parent, args.binaries, evidence)
    transition_failures(args.cgroup_parent, args.binaries, evidence)
    kernel_exec_error(args.cgroup_parent, args.binaries, evidence)
    post_token_death(args.cgroup_parent, args.binaries, evidence)
    root_tty_workflow(args.cgroup_parent, args.binaries, evidence)
    controls_and_races(args.cgroup_parent, args.binaries, evidence)
    observed_execution(args.cgroup_parent, args.binaries, evidence, args.strace)
    evidence.manifest['result'] = 'passed'
    evidence.save()


if __name__ == '__main__':
    main()
