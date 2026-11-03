#!/usr/bin/python3
"""Real filesystem/execution trust gates inside the delegated acceptance service."""
import argparse
import errno
import json
import os
from pathlib import Path
import runpy
import select
import signal
import struct
import subprocess
import time

REPO = Path(__file__).resolve().parent.parent
SHARED = runpy.run_path(str(Path(__file__).with_name('verify-runtime.py')))
Fixture, Gate = SHARED['Fixture'], SHARED['Gate']
canonical, wait_for, unprivileged = SHARED['canonical'], SHARED['wait_for'], SHARED['unprivileged']
DEFAULT_MODELS = ['fs_verity', 'ctime', 'digest_memfd']


def request(f, *, warrant=None, command=None, target=0, args=(), capabilities=()):
    status = f.base / ('trust-status-' + str(time.monotonic_ns()))
    output = open(status, 'w+b')
    argv = [str(f.client_binary), '--socket', str(f.client), '--status-fd', str(output.fileno())]
    if warrant is not None:
        argv += ['--warrant', str(warrant)]
    else:
        argv += ['--target-uid', str(target), '--target-gid', str(target), '--cwd', '/']
        for capability in capabilities:
            argv += ['--capability', capability]
        argv += ['--', str(command), *map(str, args)]
    child = subprocess.Popen(argv, preexec_fn=unprivileged, pass_fds=(output.fileno(),),
                             stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return child, output


def finish(child, output):
    try:
        stdout, stderr = child.communicate(timeout=10)
        output.seek(0)
        events = [json.loads(line) for line in output]
        return child.returncode, stdout, stderr, events
    finally:
        if child.poll() is None:
            child.kill()
            child.communicate(timeout=5)
        output.close()


def csr(f, program, **kwargs):
    code, stdout, stderr, events = finish(*request(f, command=program, **kwargs))
    assert code == 255 and not stdout and events[0]['status'] == 'TIMEOUT_CSR', (code, stdout, stderr, events)
    payload = events[0]['csr_payload'].encode()
    return payload, json.loads(payload)


def approved(f, payload, expected):
    path, _ = f.sign_payload(payload)
    code, stdout, stderr, events = finish(*request(f, warrant=path))
    assert code == 0 and stdout == expected, (code, stdout, stderr, events, f.diagnostics.read_text())
    assert [event.get('status') for event in events] == ['READY_TO_EXEC', None], events
    wait_for(f.empty, 'trust job cleanup')
    records = [r for r in f.records() if r.get('exec_id') == events[0]['exec_id']]
    return records


def denied(f, payload, status='EXECUTABLE_MUTATED_OR_TOO_LARGE'):
    path, _ = f.sign_payload(payload)
    code, stdout, stderr, events = finish(*request(f, warrant=path))
    assert code == 255 and not stdout and events[0]['status'] == status, (code, stdout, stderr, events)
    wait_for(f.empty, 'rejected trust job cleanup')


def program(f, name='native', large=True, pause=False):
    source = f.base / 'native.c'
    source.write_text('#include <unistd.h>\n#include <stdio.h>\n#include <fcntl.h>\n#include <signal.h>\n'
                      'int main(int argc,char**argv){if(argc>1){int f=open(argv[1],O_WRONLY|O_CREAT,0600);'
                      'if(f<0)return 91;close(f);}' + ('raise(SIGSTOP);' if pause else '') +
                      'printf("%u\\n",(unsigned)geteuid());return 0;}\n')
    path = f.commands / name
    subprocess.run(['cc', '-O2', str(source), '-o', str(path)], check=True)
    if large:
        with path.open('r+b') as output:
            output.truncate(67_108_865)
    path.chmod(0o755)
    return path


def configure(f, models=None):
    path = f.base / 'config'
    text = path.read_text().replace('max_executable_bytes = 67108864', 'max_executable_bytes = 65536')
    if models is not None:
        text = text.replace('executable_trust_models = ' + json.dumps(DEFAULT_MODELS),
                            'executable_trust_models = ' + json.dumps(models))
    path.write_text(text)


def cleanup(f, mounted=False):
    if mounted:
        (f.group / 'cgroup.kill').write_text('1\n')
        if f.process:
            f.process.wait(timeout=6)
        wait_for(lambda: 'populated 0' in (f.group / 'cgroup.events').read_text(), 'verity fixture stopped')
        subprocess.run(['umount', str(f.commands)], check=True)
    f.cleanup()


def ctime_gate(parent, binaries):
    f = Fixture(parent, binaries, DEFAULT_MODELS)
    try:
        native = program(f)
        configure(f)
        f.launch()
        for target, caps in [(0, ()), (33, ()), (33, ('CAP_NET_BIND_SERVICE',))]:
            payload, value = csr(f, native, target=target, capabilities=caps)
            assert value['version'] == '1.1' and value['command']['executable_sha256'] is None
            trust = value['command']['executable_trust']
            assert trust['model'] == 'ctime' and int(trust['size']) == 67_108_865, trust
            records = approved(f, payload, f'{target}\n'.encode())
            assert records[1]['exec_outcome'] == 'exec_event_observed', records
            assert records[0]['executable_trust'] == trust, records
        # A detached ctime job may suspend normally and resume without being
        # mistaken for an unexpected ptrace stop by the coordinator.
        suspend = program(f, 'suspend', large=False, pause=True)
        marker = f.base / 'suspended'
        payload, value = csr(f, suspend, args=(marker,))
        assert value['command']['executable_trust']['model'] == 'ctime'
        path, _ = f.sign_payload(payload)
        child, output = request(f, warrant=path)
        try:
            wait_for(marker.exists, 'suspend program entry')
            pids = [int(pid) for group in (f.group / 'jobs').glob('job-*/cgroup.procs')
                    for pid in group.read_text().split()]
            assert len(pids) == 1, pids
            status = Path(f'/proc/{pids[0]}/status')
            wait_for(lambda: '\nState:\tT (stopped)\n' in status.read_text(), 'ordinary SIGSTOP')
            time.sleep(0.15)  # Let the coordinator poll the stopped child.
            assert child.poll() is None and status.exists(), f.diagnostics.read_text()
            os.kill(pids[0], signal.SIGCONT)
            code, stdout, stderr, events = finish(child, output)
            assert code == 0 and stdout == b'0\n', (code, stdout, stderr, events)
            wait_for(f.empty, 'resumed ctime job cleanup')
        finally:
            if child.poll() is None:
                child.kill()
                child.communicate(timeout=5)
            output.close()
        # A signed legacy digest may not silently use either direct model.
        old, _ = f.signed(native)
        code, out, _, events = finish(*request(f, warrant=old))
        assert code == 255 and not out and events[0]['status'] == 'EXECUTABLE_MUTATED_OR_TOO_LARGE', events
        payload, value = csr(f, native)
        value['command']['executable_trust']['inode'] = '1'
        denied(f, canonical(value))
        # An already-open writer prevents exec, regardless of unchanged ctime.
        marker = f.base / 'must-not-exist'
        payload, _ = csr(f, native, args=(marker,))
        with native.open('r+b'):
            denied(f, payload, 'SPAWN_FAILED')
        assert not marker.exists()
        # Unsafe permissions fall through to the original snapshot path.
        unsafe = program(f, 'unsafe', large=False)
        unsafe.chmod(0o777)
        payload, value = csr(f, unsafe)
        assert value['version'] == '1.0' and 'executable_trust' not in value['command']
        approved(f, payload, b'0\n')
        # UID 0 is capability-stripped and must satisfy its owner execute bit.
        owner_noexec = program(f, 'owner-noexec', large=False)
        owner_noexec.chmod(0o655)
        payload, value = csr(f, owner_noexec)
        assert value['version'] == '1.0' and 'executable_trust' not in value['command']
        approved(f, payload, b'0\n')
        # Removing a model rejects outstanding warrants instead of downgrading.
        payload, _ = csr(f, native)
        f.stop()
        configure(f, ['digest_memfd'])
        f.launch()
        denied(f, payload)
        f.stop()
    finally:
        cleanup(f)


def mutation_gate(parent, binaries):
    f = Fixture(parent, binaries, DEFAULT_MODELS)
    gate = None
    child = output = None
    try:
        native = program(f)
        configure(f)
        gate = Gate(f, 'clone-after')
        marker = f.base / 'mutation-must-not-run'
        payload, _ = csr(f, native, args=(marker,))
        path, _ = f.sign_payload(payload)
        gate.arm()
        child, output = request(f, warrant=path)
        gate.arrive()
        before = native.stat()
        with native.open('r+b') as writer:
            writer.seek(-1, os.SEEK_END)
            writer.write(b'X')
        assert native.stat().st_size == before.st_size
        assert native.stat().st_ctime_ns != before.st_ctime_ns
        gate.unblock()
        code, out, err, events = finish(child, output)
        child = output = None
        assert code == 255 and not out and events[0]['status'] == 'SPAWN_FAILED', (code, out, err, events)
        assert not marker.exists()
        wait_for(f.empty, 'mutated exec stopped and cleaned')
        assert any('exec checkpoint failed' in r.get('reason', '') for r in f.records()), f.records()
        f.stop()
    finally:
        if child and child.poll() is None:
            child.kill()
            child.communicate(timeout=5)
        if output:
            output.close()
        if gate:
            gate.close()
        cleanup(f)


def noexec_gate(parent, binaries):
    f = Fixture(parent, binaries, DEFAULT_MODELS)
    mounted = False
    try:
        subprocess.run(['mount', '-t', 'tmpfs', '-o', 'nosuid,nodev,mode=0755', 'tmpfs', str(f.commands)], check=True)
        mounted = True
        native = program(f, large=False)
        configure(f)
        f.launch()
        payload, value = csr(f, native)
        assert value['command']['executable_trust']['model'] == 'ctime'
        f.stop()
        subprocess.run(['mount', '-o', 'remount,noexec,nosuid,nodev', str(f.commands)], check=True)
        f.launch()
        # Previously signed direct evidence cannot be executed or downgraded.
        denied(f, payload)
        payload, value = csr(f, native)
        assert value['version'] == '1.0' and 'executable_trust' not in value['command']
        approved(f, payload, b'0\n')
        f.stop()
    finally:
        cleanup(f, mounted)


def tracer_death_gate(parent, binaries):
    f = Fixture(parent, binaries, DEFAULT_MODELS)
    gate = child = output = None
    pidfd = None
    try:
        native = program(f)
        configure(f)
        gate = Gate(f, 'exec-detach')
        marker = f.base / 'tracer-death-must-not-run'
        payload, _ = csr(f, native, args=(marker,))
        path, _ = f.sign_payload(payload)
        gate.arm()
        child, output = request(f, warrant=path)
        assert select.select([gate.entered], [], [], 6)[0], f.diagnostics.read_text()
        message = b''
        while len(message) < 16:
            message += gate.entered.recv(16 - len(message))
        tid, pid = struct.unpack('=QQ', message)
        assert tid == f.process.pid, (tid, f.process.pid)
        assert not marker.exists()
        pidfd = os.pidfd_open(pid)
        f.process.kill()
        f.process.wait(timeout=5)
        assert select.select([pidfd], [], [], 5)[0], 'EXITKILL did not kill the stopped tracee'
        assert not marker.exists()
        code, out, _, _ = finish(child, output)
        child = output = None
        assert code != 0 and not out
    finally:
        if pidfd is not None:
            os.close(pidfd)
        if child and child.poll() is None:
            child.kill()
            child.communicate(timeout=5)
        if output:
            output.close()
        if gate:
            gate.close()
        cleanup(f)


def verity_gate(parent, binaries):
    f = Fixture(parent, binaries, DEFAULT_MODELS)
    mounted = False
    try:
        image = f.base / 'verity.img'
        with image.open('wb') as output:
            output.truncate(268_435_456)
        subprocess.run(['mkfs.ext4', '-q', '-F', '-O', 'verity', str(image)], check=True)
        subprocess.run(['mount', '-o', 'loop', str(image), str(f.commands)], check=True)
        mounted = True
        for algorithm in ['sha256', 'sha512']:
            native = program(f, algorithm)
            subprocess.run(['fsverity', 'enable', '--hash-alg', algorithm, str(native)], check=True)
            try:
                native.open('r+b')
            except OSError as error:
                assert error.errno == errno.EPERM, error
            else:
                raise AssertionError('verity file accepted a writer')
        small = program(f, 'small', large=False)
        subprocess.run(['fsverity', 'enable', str(small)], check=True)
        configure(f)
        f.launch()
        for algorithm in ['sha256', 'sha512']:
            native = f.commands / algorithm
            payload, value = csr(f, native)
            evidence = value['command']['executable_trust']
            measured = subprocess.check_output(['fsverity', 'measure', str(native)], text=True).split()[0]
            assert evidence == {'model': 'fs_verity', 'algorithm': algorithm, 'digest': measured.split(':')[1]}, evidence
            assert value['version'] == '1.1' and value['command']['executable_sha256'] is None
            approved(f, payload, b'0\n')
            payload, value = csr(f, native)
            value['command']['executable_trust']['digest'] = '00' * (32 if algorithm == 'sha256' else 64)
            denied(f, canonical(value))
        f.stop()
        subprocess.run(['mount', '-o', 'remount,noexec', str(f.commands)], check=True)
        f.launch()
        payload, value = csr(f, small)
        assert value['version'] == '1.0' and 'executable_trust' not in value['command']
        approved(f, payload, b'0\n')
        f.stop()
        subprocess.run(['mount', '-o', 'remount,exec', str(f.commands)], check=True)
        small.chmod(0o655)
        f.launch()
        payload, value = csr(f, small)
        assert value['version'] == '1.0' and 'executable_trust' not in value['command']
        approved(f, payload, b'0\n')
        small.chmod(0o755)
        payload, value = csr(f, small)
        assert value['command']['executable_trust']['model'] == 'fs_verity'
        approved(f, payload, b'0\n')
        f.stop()
    finally:
        cleanup(f, mounted)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cgroup-parent', type=Path, required=True)
    parser.add_argument('--binaries', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('run in the dedicated root acceptance service')
    args.artifacts.mkdir(parents=True, exist_ok=True)
    results = []
    for name, gate in [('ctime', ctime_gate), ('mutation', mutation_gate), ('noexec', noexec_gate), ('tracer-death', tracer_death_gate), ('fs-verity', verity_gate)]:
        gate(args.cgroup_parent, args.binaries)
        results.append({'gate': name, 'result': 'passed'})
        print(json.dumps(results[-1]), flush=True)
        (args.artifacts / 'results.json').write_text(json.dumps(results, indent=2) + '\n')


if __name__ == '__main__':
    main()
