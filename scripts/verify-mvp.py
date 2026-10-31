#!/usr/bin/python3
"""Phase 6 acceptance entry point for a disposable, real systemd Linux host.

Build and run ordinary regressions as the unprivileged workspace user first.
This root entry point launches a fresh delegated service with an overall time
limit and whole-service cleanup, then repeats the platform/runtime/fault gates
and additional operator-facing scenarios. No local elevation is performed.
"""
import argparse
import array
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import platform
import pty
import runpy
import select
import signal
import shutil
import socket
import sqlite3
import subprocess
import sys
import termios
import time
import traceback
import uuid

REPO = Path(__file__).resolve().parent.parent
SHARED = runpy.run_path(str(Path(__file__).with_name('verify-phase5-runtime.py')))
FAILURES = runpy.run_path(str(Path(__file__).with_name('verify-phase5-failures.py')))
Fixture, wait_for, receive = SHARED['Fixture'], SHARED['wait_for'], SHARED['receive']
canonical, unprivileged = SHARED['canonical'], SHARED['unprivileged']
Evidence = FAILURES['Evidence']


def run(command, *, log=None, **kwargs):
    result = subprocess.run([str(a) for a in command], check=True, **kwargs)
    if log is not None:
        log.write_text(json.dumps({'command': [str(a) for a in command], 'exit': result.returncode}) + '\n')
    return result


def cli(fixture, warrant, *, input_bytes=None, stdout=subprocess.PIPE, stderr=subprocess.PIPE):
    status = fixture.base / ('status-' + uuid.uuid4().hex)
    output = open(status, 'w+b')
    command = [str(fixture.client_binary), '--socket', str(fixture.client), '--warrant', str(warrant),
               '--status-fd', str(output.fileno())]
    child = subprocess.Popen(command, preexec_fn=unprivileged, pass_fds=(output.fileno(),),
                             stdin=subprocess.PIPE, stdout=stdout, stderr=stderr)
    return child, output, status


def finish(client, output, input_bytes=None):
    try:
        out, err = client.communicate(input_bytes, timeout=10)
        output.seek(0)
        events = [json.loads(line) for line in output]
        return client.returncode, out, err, events
    finally:
        if client.poll() is None:
            client.kill()
            client.communicate(timeout=5)
        output.close()


def deny(f, warrant, status, input_bytes=None):
    client, output, _ = cli(f, warrant)
    code, out, err, events = finish(client, output, input_bytes)
    assert code == 255 and out == b'' and len(events) == 1 and events[0]['status'] == status, (code, out, err, events)
    return events[0]


def count(f):
    with sqlite3.connect(f.state / 'state.sqlite') as db:
        return db.execute('select count(*) from consumed_grants').fetchone()[0]


def package_workflow(parent, binaries, evidence):
    """Use the shipped offline helper on a daemon-generated CSR, never a rebuilt payload."""
    f = Fixture(parent, binaries)
    try:
        f.launch()
        status = f.base / 'capture.status'
        with open(status, 'w+b') as output:
            client = subprocess.Popen([str(f.client_binary), '--socket', str(f.client), '--status-fd', str(output.fileno()),
                                       '--cwd', '/', '--', str(f.commands / 'id'), '-u'],
                                      preexec_fn=unprivileged, pass_fds=(output.fileno(),),
                                      stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            out, err = client.communicate(timeout=8)
        assert client.returncode == 255 and not out, (client.returncode, out, err)
        assert count(f) == 0
        csr, pae = f.base / 'request.csr', f.base / 'request.pae'
        ctl = binaries / 'sigrundctl'
        run([ctl, 'csr-pae', '--status', status, '--csr', csr, '--pae', pae])
        original = json.loads(status.read_bytes())['csr_payload'].encode()
        assert csr.read_bytes() == original
        signed = run(['ssh-keygen', '-Y', 'sign', '-n', 'sigrun.warrant.v1', '-O', 'hashalg=sha512',
                      '-f', f.key, pae], capture_output=True)
        envelope = f.base / 'packaged.json'
        run([ctl, 'pack-warrant', '--csr', csr, '--signature', str(pae) + '.sig', '--signer-id', SHARED['SIGNER'],
             '--output', envelope])
        envelope.chmod(0o644)
        assert base64.b64decode(json.loads(envelope.read_bytes())['payload']) == original
        client, output, status_path = cli(f, envelope)
        code, out, err, events = finish(client, output)
        assert code == 0 and out == b'0\n' and err == SHARED['CLIENT_PROGRESS'], (code, out, err, events)
        assert events[-1] == {'exit_code': 0, 'signal': None}
        assert count(f) == 1
        deny(f, envelope, 'REPLAY_DETECTED')
        directory = evidence.root / 'offline-workflow'
        directory.mkdir(exist_ok=True)
        for source in (status, csr, pae, Path(str(pae) + '.sig'), envelope, status_path):
            (directory / source.name).write_bytes(source.read_bytes())
        evidence.passed('offline-workflow', csr_sha256=hashlib.sha256(original).hexdigest(), output='0\n', replay='REPLAY_DETECTED')
        f.stop()
    finally:
        evidence.capture(f, 'offline-workflow')
        f.cleanup()


def binding_and_replay(parent, binaries, evidence):
    f = Fixture(parent, binaries)
    try:
        f.launch()
        warrant, envelope = f.signed(f.commands / 'true')
        changed = copy.deepcopy(envelope)
        value = json.loads(base64.b64decode(changed['payload']))
        value['command']['argv'].append('changed-after-signing')
        changed['payload'] = base64.b64encode(canonical(value)).decode()
        altered = f.base / 'altered.json'
        altered.write_bytes(canonical(changed))
        altered.chmod(0o644)
        # A changed CSR with the original signature cannot authorize.
        denied = deny(f, altered, 'POLICY_VIOLATION')
        assert count(f) == 0 and f.empty()
        wrong_uid, _ = f.signed(f.commands / 'true', uid=0)
        deny(f, wrong_uid, 'POLICY_VIOLATION')
        content = b'\x00binary\xff\n' * 64
        hashed, _ = f.signed(f.commands / 'cat', input_bytes=content)
        deny(f, hashed, 'STDIN_HASH_MISMATCH', b'different')
        assert count(f) == 0
        # Same exact signed bytes and peer UID/GID; one child and one commit.
        clients = [cli(f, warrant) for _ in range(2)]
        results = [finish(c, out) for c, out, _ in clients]
        assert sorted(r[0] for r in results) == [0, 255], results
        assert sorted(r[3][0]['status'] for r in results) == ['READY_TO_EXEC', 'REPLAY_DETECTED'], results
        assert count(f) == 1
        commits = [r for r in f.records() if r.get('event_type') == 'AUTH_COMMIT']
        assert len(commits) == 1
        wait_for(f.empty, 'concurrent replay job cleanup')
        f.stop()
        f.launch()
        deny(f, warrant, 'REPLAY_DETECTED')
        assert count(f) == 1
        f.stop()
        evidence.passed('binding-and-concurrent-replay', mutation=denied['status'], commits=1, replay_after_restart=True,
                        stdin_mismatch='STDIN_HASH_MISMATCH', wrong_uid='POLICY_VIOLATION')
    finally:
        evidence.capture(f, 'binding-and-concurrent-replay')
        f.cleanup()


def output_and_limits(parent, binaries, evidence):
    f = Fixture(parent, binaries)
    gate = None
    try:
        probe = f.commands / 'mvp-probe'
        run(['cc', '-O2', '-Wall', '-Werror', REPO / 'crates/sigrund/tests/fixtures/mvp_probe.c', '-o', probe])
        gate = SHARED['Gate'](f, 'cleanup-before')
        warrant, _ = f.signed(probe, ('output',))
        client, output, _ = cli(f, warrant)
        code, out, err, events = finish(client, output)
        expected = bytes(range(256)) * (2097152 // 256)
        assert code == 23 and out == expected and err == SHARED['CLIENT_PROGRESS'] + expected, (code, len(out), len(err), events)
        assert events[-1] == {'exit_code': 23, 'signal': None}
        # A genuinely blocked local sink must not prevent a signal cancellation.
        blocked, _ = f.signed(probe, ('output',))
        client, output, _ = cli(f, blocked)
        try:
            wait_for(lambda: any(r.get('event_type') == 'EXEC_READY_TO_EXEC' and r.get('grant_id') ==
                                json.loads(base64.b64decode(json.loads(blocked.read_bytes())['payload']))['grant_id']
                                for r in f.records()), 'blocked output readiness')
            client.send_signal(signal.SIGINT)
            code, _, _, events = finish(client, output)
        finally:
            if client.poll() is None:
                client.kill()
                client.wait(timeout=5)
            if not output.closed:
                output.close()
        wait_for(f.empty, 'blocked-output cancellation cleanup')
        # Memory and pids are actually enforced, beyond control read-back.
        memory, _ = f.signed(probe, ('memory',))
        gate.arm()
        client, output, _ = cli(f, memory)
        gate.arrive()
        memory_events = dict(line.split() for line in next((f.group / 'jobs').glob('job-*/memory.events')).read_text().splitlines())
        assert int(memory_events['oom_kill']) >= 1, memory_events
        gate.unblock()
        code, out, err, events = finish(client, output)
        assert code == 137 and events[-1] == {'exit_code': None, 'signal': 9}, (code, out, err, events)
        wait_for(f.empty, 'OOM job cleanup')
        pids, _ = f.signed(probe, ('pids',))
        gate.arm()
        client, output, _ = cli(f, pids)
        gate.arrive()
        pids_events = dict(line.split() for line in next((f.group / 'jobs').glob('job-*/pids.events')).read_text().splitlines())
        assert int(pids_events['max']) >= 1, pids_events
        gate.unblock()
        code, out, err, events = finish(client, output)
        assert code == 0 and out.startswith(b'pids-denied:'), (code, out, err, events)
        denied_at = int(out.strip().split(b':')[1])
        assert 0 < denied_at < 128
        wait_for(f.empty, 'background descendants cleaned with job')
        f.stop()
        evidence.passed('output-and-enforced-limits', stdout_bytes=len(expected), stderr_bytes=len(expected),
                        oom_signal=9, fork_denied_after=denied_at, descendants_cleaned=True, memory_events=memory_events, pids_events=pids_events)
    finally:
        evidence.capture(f, 'output-and-enforced-limits')
        if gate:
            gate.close()
        f.cleanup()


def failed_job_limit(parent, binaries, evidence):
    f = Fixture(parent, binaries)
    gate = None
    try:
        gate = SHARED['Gate'](f, 'limit-fail')
        gate.arm()
        warrant, _ = f.signed(f.commands / 'true')
        deny(f, warrant, 'SPAWN_FAILED')
        assert count(f) == 1
        wait_for(f.empty, 'failed cgroup setup cleanup')
        assert not any(r.get('event_type') == 'EXEC_READY_TO_EXEC' for r in f.records())
        deny(f, warrant, 'REPLAY_DETECTED')
        f.stop()
        evidence.passed('failed-job-limit', no_readiness=True, consumed=True, replay='REPLAY_DETECTED')
    finally:
        evidence.capture(f, 'failed-job-limit')
        if gate:
            gate.close()
        f.cleanup()


def local_recovery(parent, binaries, evidence):
    f = Fixture(parent, binaries)
    try:
        f.launch()
        warrant, _ = f.signed(f.commands / 'true')
        client, output, _ = cli(f, warrant)
        assert finish(client, output)[0] == 0
        f.stop()
        identity = (f.state / 'host_identity.key').read_bytes()
        with open(f.log, 'ab') as log:
            log.write(b'{"partial":')
            log.flush()
            os.fsync(log.fileno())
        f.launch()
        deny(f, warrant, 'REPLAY_DETECTED')
        f.stop()
        assert any(r.get('event_type') == 'RATCHET_PARTIAL_WRITE_TRUNCATED' for r in f.records()), f.records()
        assert (f.state / 'host_identity.key').read_bytes() == identity and count(f) == 1
        # Forward recovery and poison/restart are exercised by Phase 5C's real
        # state-fail gate; this case covers a synchronized partial tail.
        evidence.passed('synchronized-partial-tail-recovery', identity_preserved=True, consumption_preserved=True)
    finally:
        evidence.capture(f, 'synchronized-partial-tail-recovery')
        f.cleanup()


def operator_workflow(binaries, requester, evidence):
    """Exercise both shipped service recipes with a real requester terminal."""
    import fcntl
    import pwd
    import shutil
    account = pwd.getpwnam(requester)
    base = Path('/var/lib') / ('sigrund-mvp-fixture-' + uuid.uuid4().hex[:12])
    lab = REPO / 'scripts/mvp-lab.py'
    approver = None
    child = None
    foreground = None
    masters = []
    try:
        run([sys.executable, lab, 'prepare', '--directory', base, '--binaries', binaries, '--requester', requester],
            capture_output=True)
        manifest = json.loads((base / 'lab.json').read_text())
        tools = base / 'bin'
        runtime = Path(manifest['runtime'])
        run([sys.executable, lab, 'start', '--directory', base], capture_output=True)
        run([sys.executable, lab, 'status', '--directory', base], capture_output=True)
        master, slave = pty.openpty()
        masters.extend([master, slave])
        def operator_tty():
            os.setsid()
            fcntl.ioctl(0, termios.TIOCSCTTY, 0)
        approver = subprocess.Popen([str(tools / 'sigrund-approve'), '--socket', str(runtime / 'approve.sock'),
                                     '--signers', str(base / 'signers.toml'), '--identity', str(base / 'signer')],
                                    stdin=slave, stdout=slave, stderr=subprocess.PIPE, preexec_fn=operator_tty)
        def requester_ids():
            os.setgroups([])
            os.setgid(account.pw_gid)
            os.setuid(account.pw_uid)
        # Give the broker event a chance to run before submitting; readiness of
        # the process alone is not an approval-attachment barrier.
        group = subprocess.check_output(['systemctl', 'show', '--property=ControlGroup', '--value', manifest['unit']], text=True).strip()
        main_pid = int(subprocess.check_output(['systemctl', 'show', '--property=MainPID', '--value', manifest['unit']], text=True))
        def broker_attached():
            records = subprocess.check_output(['journalctl', '-u', manifest['unit'], '--no-pager', '-o', 'cat'], text=True)
            return any('SOCKET_ADMITTED' in line and '"broker":true' in line for line in records.splitlines())
        wait_for(broker_attached, 'approver broker registration')
        # The acceptance script owns only these new terminals and disposable key.
        for index, (answer, target, stdin_bytes) in enumerate(((b'\n', 0, None), (b'yes\n', 0, None),
                                                            (b'yes\n', 33, b'\x00reviewed\xff\n'))):
            rm, rs = pty.openpty()
            masters.extend([rm, rs])
            attrs = termios.tcgetattr(rs)
            attrs[1] &= ~termios.OPOST
            termios.tcsetattr(rs, termios.TCSANOW, attrs)
            command = base / 'commands' / ('id' if stdin_bytes is None else 'cat')
            status_path = base / ('terminal-' + str(index) + '.status')
            with open(status_path, 'w+b') as status:
                args = [str(tools / 'sigrun'), '--socket', str(runtime / 'client.sock'), '--target-uid', str(target),
                        '--target-gid', str(target), '--cwd', '/', '--status-fd', str(status.fileno())]
                if stdin_bytes is not None:
                    args.extend(['--stdin', 'sha256'])
                args.extend(['--', str(command)] + (['-u'] if stdin_bytes is None else []))
                child = subprocess.Popen(args, preexec_fn=requester_ids, pass_fds=(status.fileno(),),
                                         stdin=subprocess.PIPE, stdout=rs, stderr=rs)
                if stdin_bytes is not None:
                    child.stdin.write(stdin_bytes)
                child.stdin.close()
                prompt = b''
                deadline = time.monotonic() + 8
                while b'Approve and sign? [y/N] ' not in prompt:
                    assert time.monotonic() < deadline and child.poll() is None, prompt
                    if select.select([master], [], [], 0.1)[0]:
                        prompt += os.read(master, 8192)
                    assert len(prompt) < 1048576
                assert str(account.pw_uid).encode() in prompt
                if stdin_bytes is not None:
                    assert hashlib.sha256(stdin_bytes).hexdigest().encode() in prompt
                # The approved executable must come from the retained snapshot
                # even if its pathname changes while root reviews the request.
                if index == 1:
                    command.write_bytes((base / 'commands/false').read_bytes())
                os.write(master, answer)
                child.wait(timeout=8)
                terminal = b''
                while select.select([rm], [], [], 0.05)[0]:
                    terminal += os.read(rm, 65536)
                status.seek(0)
                events = [json.loads(line) for line in status]
            if answer == b'\n':
                assert child.returncode == 255 and events[0]['status'] == 'REJECTED', (terminal, events)
            else:
                assert child.returncode == 0 and events[-1] == {'exit_code': 0, 'signal': None}, (terminal, events)
                assert terminal == SHARED['CLIENT_PROGRESS'] + (b'0\n' if stdin_bytes is None else stdin_bytes), terminal
            directory = evidence.root / 'operator-workflow'
            directory.mkdir(exist_ok=True)
            (directory / (str(index) + '.prompt')).write_bytes(prompt)
            (directory / (str(index) + '.terminal')).write_bytes(terminal)
            (directory / (str(index) + '.status.jsonl')).write_bytes(status_path.read_bytes())
        approver.terminate()
        approver.wait(timeout=5)
        approver = None
        run([sys.executable, lab, 'stop', '--directory', base], capture_output=True)
        assert not runtime.exists()
        # Start the exact foreground recipe against the retained state. It is
        # supervised independently of this harness and must remove its sockets.
        foreground = subprocess.Popen([sys.executable, str(lab), 'foreground', '--directory', str(base)],
                                      stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        wait_for(lambda: (runtime / 'client.sock').exists(), 'foreground recipe startup')
        run([sys.executable, lab, 'status', '--directory', base], capture_output=True)
        run(['systemctl', 'stop', manifest['unit']])
        foreground.communicate(timeout=8)
        assert foreground.returncode == 0 and not runtime.exists()
        directory = evidence.root / 'operator-workflow'
        (directory / 'audit.jsonl').write_bytes((base / 'log/audit.jsonl').read_bytes())
        (directory / 'daemon.service').write_bytes((base / 'daemon.service').read_bytes())
        evidence.passed('operator-workflow', requester_uid=account.pw_uid, root_uid=0, service_uid=33,
                        requester_tty=True, root_tty=True, blank_confirmation='REJECTED',
                        hashed_stdin=True, packaged_and_foreground=True, group=group, daemon_pid=main_pid)
    finally:
        if child and child.poll() is None:
            child.kill()
            child.wait(timeout=5)
        if approver and approver.poll() is None:
            approver.kill()
            approver.wait(timeout=5)
        if (base / 'lab.json').exists():
            manifest = json.loads((base / 'lab.json').read_text())
            subprocess.run(['systemctl', 'stop', manifest['unit']], capture_output=True)
            target = Path('/run/systemd/system') / manifest['unit']
            target.unlink(missing_ok=True)
            subprocess.run(['systemctl', 'reset-failed', manifest['unit']], capture_output=True)
            subprocess.run(['systemctl', 'daemon-reload'], capture_output=True)
        if foreground and foreground.poll() is None:
            foreground.kill()
            foreground.communicate(timeout=5)
        for fd in masters:
            os.close(fd)
        if base.exists():
            shutil.rmtree(base)


def prerequisites(binaries, platform_binary):
    problems = []
    if os.geteuid() != 0:
        problems.append('run this entry point as root in the disposable VM')
    for command in ('systemd-run', 'systemctl', 'cc', 'ssh-keygen', 'strace'):
        import shutil
        if shutil.which(command) is None:
            problems.append('missing command: ' + command)
    if not Path('/run/systemd/system').is_dir() or not Path('/sys/fs/cgroup/cgroup.controllers').is_file():
        problems.append('requires booted systemd and unified cgroup v2')
    for name in ('sigrund', 'sigrun', 'sigrundctl', 'sigrund-approve'):
        if not os.access(binaries / name, os.X_OK):
            problems.append('build executable: ' + str(binaries / name))
    if not os.access(platform_binary, os.X_OK):
        problems.append('supply the built phase5_platform test executable')
    try:
        from gi.repository import Gio  # noqa: F401
    except ImportError:
        problems.append('install python3-gi for the existing real-service gate')
    if problems:
        raise RuntimeError('\n'.join(problems))


def inside(args):
    membership = Path('/proc/self/cgroup').read_text().strip()
    if not membership.startswith('0::/') or 'sigrund-mvp-gate-' not in membership:
        raise RuntimeError('inside entry point requires its dedicated delegated service')
    parent = Path('/sys/fs/cgroup' + membership.split('::', 1)[1])
    # Move only this harness into a leaf before enabling domain controllers.
    runner = parent / 'runner'
    runner.mkdir()
    (runner / 'cgroup.procs').write_text(str(os.getpid()))
    (parent / 'cgroup.subtree_control').write_text('+memory +pids')
    evidence = Evidence(args.artifacts)
    evidence.manifest['phase'] = '6'
    evidence.manifest['ordinary_checks'] = json.loads(args.checks.read_bytes())
    evidence.manifest['delegated_parent'] = str(parent)
    evidence.manifest['binaries'] = {name: hashlib.sha256((args.binaries / name).read_bytes()).hexdigest()
                                     for name in ('sigrund', 'sigrun', 'sigrundctl', 'sigrund-approve')}
    evidence.save()
    try:
        strace = shutil.which('strace')
        if strace is None:
            raise RuntimeError('strace disappeared after prerequisite validation')
        for label, command in (
            ('platform', [sys.executable, REPO / 'scripts/verify-phase5.py', args.platform_binary, '--cgroup-parent', parent]),
            ('runtime', [sys.executable, REPO / 'scripts/verify-phase5-runtime.py', '--cgroup-parent', parent,
                         '--binaries', args.binaries, '--systemd']),
            ('failures', [sys.executable, REPO / 'scripts/verify-phase5-failures.py', '--cgroup-parent', parent,
                          '--binaries', args.binaries, '--artifacts', args.artifacts / 'phase5d',
                          '--strace', strace]),
        ):
            with open(args.artifacts / (label + '.log'), 'wb') as log:
                run(command, stdout=log, stderr=subprocess.STDOUT)
            evidence.passed(label, log=label + '.log', command=[str(a) for a in command])
        package_workflow(parent, args.binaries, evidence)
        binding_and_replay(parent, args.binaries, evidence)
        output_and_limits(parent, args.binaries, evidence)
        failed_job_limit(parent, args.binaries, evidence)
        local_recovery(parent, args.binaries, evidence)
        operator_workflow(args.binaries, args.requester, evidence)
        evidence.manifest['result'] = 'passed'
    except BaseException:
        evidence.manifest['result'] = 'failed'
        evidence.manifest['error'] = traceback.format_exc()
        raise
    finally:
        evidence.save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binaries', type=Path, default=REPO / 'target/debug')
    parser.add_argument('--checks', type=Path, required=True, help='checks.json from check-mvp.py for this source/build')
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--requester', default='mvp-requester', help='existing unprivileged login, distinct from UID 0/33/65534')
    parser.add_argument('--inside', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    args.binaries = args.binaries.resolve(strict=True)
    args.checks = args.checks.resolve(strict=True)
    checks = json.loads(args.checks.read_bytes())
    digest = runpy.run_path(str(Path(__file__).with_name('check-mvp.py')))['source_digest']()
    if checks.get('result') != 'passed' or checks.get('source_sha256') != digest:
        parser.error('ordinary checks must pass against the current source snapshot')
    args.platform_binary = Path(checks['platform_binary']).resolve(strict=True)
    for name, expected in checks['binaries'].items():
        if hashlib.sha256((args.binaries / name).read_bytes()).hexdigest() != expected:
            parser.error('binary changed after ordinary checks: ' + name)
    args.artifacts = args.artifacts.absolute()
    prerequisites(args.binaries, args.platform_binary)
    if args.inside:
        inside(args)
        return
    args.artifacts.mkdir(parents=True, exist_ok=False)
    unit = 'sigrund-mvp-gate-' + uuid.uuid4().hex
    command = ['systemd-run', '--unit=' + unit, '--wait', '--pipe', '--collect', '--service-type=exec',
               '--property=Delegate=yes', '--property=KillMode=control-group', '--property=SendSIGKILL=yes',
               '--property=RuntimeMaxSec=600s', '--property=TimeoutStopSec=15s',
               sys.executable, str(Path(__file__).resolve()), '--inside', '--binaries', str(args.binaries),
               '--checks', str(args.checks), '--artifacts', str(args.artifacts), '--requester', args.requester]
    try:
        run(command)
    finally:
        subprocess.run(['systemctl', 'stop', unit], capture_output=True)
        observation = subprocess.run(['systemctl', 'show', '--property=ControlGroup', '--value', unit],
                                     capture_output=True, text=True)
        group = Path('/sys/fs/cgroup/system.slice') / (unit + '.service')
        cleaned = not group.exists()
        (args.artifacts / 'supervisor.json').write_text(json.dumps({'unit': unit, 'command': command,
                'cgroup_removed': cleaned, 'unit_query': observation.stdout.strip()}, indent=2) + '\n')
        if not cleaned:
            raise RuntimeError('supervisor cgroup retained: ' + str(group))


if __name__ == '__main__':
    main()
