#!/usr/bin/python3
"""Real filesystem/execution trust gates inside the delegated acceptance service."""
import argparse
import errno
import hashlib
import socket
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
Gate = SHARED['Gate']
canonical, wait_for, unprivileged = SHARED['canonical'], SHARED['wait_for'], SHARED['unprivileged']
DEFAULT_MODELS = ['fs_verity', 'ctime', 'digest_direct', 'digest_memfd']
SNAPSHOT_MAX_BYTES = 1_048_576


class Fixture(SHARED['Fixture']):
    def __init__(self, parent, binaries, models=None):
        # Allow the independent five-second direct hashing budget within the
        # authorization deadline; the confidentiality fixture uses only 2.5s.
        super().__init__(parent, binaries, models, authorization_timeout_ms=8000)
        config = self.base / 'config'
        # Repeated offline exports intentionally cross the production context
        # query rate; shorten this fixture's window while retaining its ceilings.
        config.write_text(config.read_text().replace('admission_window_secs = 60',
                                                    'admission_window_secs = 1'))

ready, authorized, exited, exit_fields = (SHARED[k] for k in ('ready','authorized','exited','exit_fields'))


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
    payload = f.export(program, **kwargs).read_bytes()
    return payload, json.loads(payload)


def approved(f, payload, expected):
    path, _ = f.sign_payload(payload)
    code, stdout, stderr, events = finish(*request(f, warrant=path))
    assert code == 0 and stdout == expected, (code, stdout, stderr, events, f.diagnostics.read_text(), f.records())
    assert [event.get('status') for event in events] == ['APPROVED', None, 'EXITED'], events
    wait_for(f.empty, 'trust job cleanup')
    records = [r for r in f.records() if r.get('exec_id') == events[0]['exec_id']]
    return records


def denied(f, payload, status='EXECUTABLE_MUTATED_OR_TOO_LARGE'):
    path, _ = f.sign_payload(payload)
    code, stdout, stderr, events = finish(*request(f, warrant=path))
    assert code == (254 if status == 'SPAWN_FAILED' else 255) and not stdout and events[-1]['status'] in (('SETUP_FAILED','EXEC_FAILED') if status == 'SPAWN_FAILED' else ('TIMEOUT',)), (code, stdout, stderr, events)
    wait_for(f.empty, 'rejected trust job cleanup')


def program(f, name='native', size=67_108_865, pause=False):
    source = f.base / 'native.c'
    source.write_text('#include <unistd.h>\n#include <stdio.h>\n#include <fcntl.h>\n#include <signal.h>\n'
                      'int main(int argc,char**argv){if(argc>1){int f=open(argv[1],O_WRONLY|O_CREAT,0600);'
                      'if(f<0)return 91;close(f);}' + ('raise(SIGSTOP);' if pause else '') +
                      'printf("%u\\n",(unsigned)geteuid());return 0;}\n')
    path = f.commands / name
    subprocess.run(['cc', '-O2', str(source), '-o', str(path)], check=True)
    if size is not None:
        assert path.stat().st_size <= size, ('compiled ELF exceeds requested fixture size', path, size)
        with path.open('r+b') as output:
            output.truncate(size)
    path.chmod(0o755)
    return path


def configure(f, models=None):
    path = f.base / 'config'
    # Native ARM64 ELFs can exceed 64 KiB even before padding. Keep ordinary
    # fallback programs within the snapshot limit on every tested architecture.
    text = path.read_text().replace('max_executable_bytes = 67108864',
                                    f'max_executable_bytes = {SNAPSHOT_MAX_BYTES}')
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
            assert value['version'] == '2.0' and 'executable_sha256' not in value['command']
            trust = value['command']['executable_trust']
            assert trust['model'] == 'ctime' and int(trust['size']) == 67_108_865, trust
            records = approved(f, payload, f'{target}\n'.encode())
            assert records[1]['exec_outcome'] == 'exec_event_observed', records
            assert records[0]['executable_trust'] == trust, records
        # A detached ctime job may suspend normally and resume without being
        # mistaken for an unexpected ptrace stop by the coordinator.
        suspend = program(f, 'suspend', size=None, pause=True)
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
        assert code == 255 and not out and events[0]['status'] == 'TIMEOUT', events
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
        unsafe = program(f, 'unsafe', size=None)
        unsafe.chmod(0o777)
        payload, value = csr(f, unsafe)
        assert value['version'] == '2.0' and value['command']['executable_trust']['model'] == 'digest_direct'
        approved(f, payload, b'0\n')
        # UID 0 is capability-stripped and must satisfy its owner execute bit.
        owner_noexec = program(f, 'owner-noexec', size=None)
        owner_noexec.chmod(0o655)
        payload, value = csr(f, owner_noexec)
        assert value['version'] == '2.0' and value['command']['executable_trust']['model'] == 'digest_memfd'
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
        assert code == 254 and not out and events[0]['status'] == 'APPROVED' and events[-1]['status'] in ('SETUP_FAILED','EXEC_FAILED'), (code, out, err, events)
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


def digest_direct_gate(parent, binaries):
    f = Fixture(parent, binaries, ['digest_direct', 'digest_memfd'])
    gate = child = output = None
    try:
        # Exceed the configured snapshot bound without turning this model
        # selection test into a debug-build SHA-256 throughput requirement.
        native = program(f, size=SNAPSHOT_MAX_BYTES + 1)
        native.chmod(0o777)
        os.chown(native, 65534, 65534)
        configure(f)
        gate = Gate(f, 'clone-after')
        payload, value = csr(f, native, target=33)
        assert value['version'] == '2.0'
        with native.open('rb') as source:
            digest = hashlib.file_digest(source, 'sha256').hexdigest()
        assert value['command']['executable_trust'] == {'model': 'digest_direct', 'sha256': digest}
        assert 'executable_sha256' not in value['command']
        approved(f, payload, b'33\n')
        # A metadata-only change is accepted after revalidation and rehashing.
        payload, _ = csr(f, native)
        native.chmod(0o755)
        approved(f, payload, b'0\n')
        # Content mutation after durable consumption is caught at the exec stop.
        marker = f.base / 'digest-must-not-run'
        payload, _ = csr(f, native, args=(marker,))
        path, _ = f.sign_payload(payload)
        gate.arm()
        child, output = request(f, warrant=path)
        gate.arrive()
        with native.open('r+b') as writer:
            writer.seek(-1, os.SEEK_END)
            writer.write(b'X')
        gate.unblock()
        code, out, err, events = finish(child, output)
        child = output = None
        assert code == 254 and not out and events[0]['status'] == 'APPROVED' and events[-1]['status'] in ('SETUP_FAILED','EXEC_FAILED'), (code, out, err, events)
        assert not marker.exists()
        wait_for(f.empty, 'digest mismatch cleanup')
        # The failed post-commit checkpoint consumed the one-time grant.
        with native.open('r+b') as writer:
            writer.seek(-1, os.SEEK_END)
            writer.write(b'\0')
        denied(f, payload, 'REPLAY_DETECTED')
        # Independent direct size bounds reject before signing; a small source
        # can still use memfd if only that candidate fits its configured bound.
        f.stop()
        config = f.base / 'config'
        config.write_text(config.read_text().replace('max_direct_digest_bytes = 268435456', 'max_direct_digest_bytes = 4'))
        f.launch()
        small = program(f, 'small', size=None)
        payload, value = csr(f, small)
        assert value['version'] == '2.0' and value['command']['executable_trust']['model'] == 'digest_memfd'
        approved(f, payload, b'0\n')
        code, out, err, events = finish(*request(f, command=native))
        assert code == 255 and not out and events[0]['status'] == 'TIMEOUT', (code, out, err, events)
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


def file_capabilities_gate(parent, binaries):
    f = Fixture(parent, binaries, ['digest_direct', 'digest_memfd'])
    mounted = False
    gate = child = output = None
    try:
        # The service's /tmp may itself be nosuid. Use an owned mount whose
        # capability semantics satisfy the direct model's eligibility rule.
        subprocess.run(['mount', '-t', 'tmpfs', '-o', 'nodev,mode=0755', 'tmpfs', str(f.commands)], check=True)
        mounted = True
        source = f.base / 'self.c'
        source.write_text('#include <sys/stat.h>\n#include <stdio.h>\n#include <unistd.h>\n'
                          'int main(void){struct stat s;FILE*f=fopen("/proc/self/exe","rb");'
                          'if(!f||fgetc(f)!=127||stat("/proc/self/exe",&s))return 91;'
                          'printf("%llu\\n",(unsigned long long)s.st_ino);return 0;}\n')
        native = f.commands / 'self'
        subprocess.run(['cc', '-O2', str(source), '-o', str(native)], check=True)
        native.chmod(0o755)
        configure(f)
        f.launch()
        cap = 'CAP_NET_BIND_SERVICE'
        for flags in [None, 'p', 'ep', 'i', 'eip']:
            if flags is not None:
                subprocess.run(['setcap', 'cap_net_bind_service=' + flags, str(native)], check=True)
            payload, value = csr(f, native, target=33, capabilities=(cap,))
            assert value['command'].get('executable_trust', {}).get('model') == 'digest_direct', (flags, value)
            expected = value['execution_context']['post_exec_capabilities']
            assert expected['bounding'] == expected['inheritable'] == [cap], expected
            assert expected['ambient'] == ([cap] if flags is None else []), expected
            assert expected['permitted'] == [cap], expected
            assert expected['effective'] == ([cap] if flags is None or 'e' in flags else []), expected
            records = approved(f, payload, f'{native.stat().st_ino}\n'.encode())
            assert records[1]['observed_post_exec_capabilities'] == expected, records
        # The child namespace alias may not substitute a different inode.
        f.stop()
        gate = Gate(f, 'clone-after')
        payload, _ = csr(f, native, target=33, capabilities=(cap,))
        path, _ = f.sign_payload(payload)
        gate.arm()
        child, output = request(f, warrant=path)
        gate.arrive()
        replacement = program(f, 'replacement', size=None)
        os.replace(replacement, native)
        gate.unblock()
        code, out, err, events = finish(child, output)
        child = output = None
        assert code == 254 and not out and events[0]['status'] == 'APPROVED' and events[-1]['status'] in ('SETUP_FAILED','EXEC_FAILED'), (code, out, err, events)
        wait_for(f.empty, 'file capability alias replacement cleanup')
        subprocess.run(['setcap', 'cap_net_bind_service=ep', str(native)], check=True)
        # Capabilities outside explicitly requested authority must use memfd.
        payload, value = csr(f, native, target=33)
        assert value['version'] == '2.0' and value['command']['executable_trust']['model'] == 'digest_memfd', value
        # The snapshot strips file capabilities, preserving the legacy contract.
        subprocess.run(['setcap', '-r', str(native)], check=True)
        f.stop()
    finally:
        if child and child.poll() is None:
            child.kill()
            child.communicate(timeout=5)
        if output:
            output.close()
        if gate:
            gate.close()
        cleanup(f, mounted)


def metadata_approval_gate(f, native):
    """Mutate verity's unprotected metadata while its CSR awaits approval."""
    config = f.base / 'config'
    assert 'approval_signer_id' in config.read_text()
    f.launch()
    for change, restore, caps in [
        (lambda: native.chmod(0o644), lambda: native.chmod(0o755), ()),
        (lambda: subprocess.run(['setcap', 'cap_net_bind_service=ep', str(native)], check=True),
         lambda: subprocess.run(['setcap', '-r', str(native)], check=True), ('CAP_NET_BIND_SERVICE',)),
    ]:
        with socket.socket(socket.AF_UNIX) as broker:
            broker.settimeout(6)
            before = f.diagnostics.read_text().count('"broker":true')
            broker.connect(str(f.approval))
            wait_for(lambda: f.diagnostics.read_text().count('"broker":true') > before, 'metadata broker registered')
            child, output = request(f, command=native, target=33, capabilities=caps)
            def exact(n):
                result = b''
                while len(result) < n:
                    data = broker.recv(n - len(result))
                    assert data, 'approval EOF'
                    result += data
                return result
            length = struct.unpack('>I', exact(4))[0]
            approval = json.loads(exact(length))
            change()
            _, envelope = f.sign_payload(approval['csr_payload'].encode())
            response = canonical({'status': 'approved', 'exec_id': approval['exec_id'], 'dsse_envelope': envelope})
            broker.sendall(struct.pack('>I', len(response)) + response)
            code, out, err, events = finish(child, output)
            assert code == 255 and not out and events[0]['status'] == 'TIMEOUT', (code, out, err, events)
            restore()
            # Rejection happened before consumption: the same signed grant is
            # still redeemable after restoring an eligible credential transition.
            approved(f, approval['csr_payload'].encode(), b'33\n')
    f.stop()


def noexec_gate(parent, binaries):
    f = Fixture(parent, binaries, DEFAULT_MODELS)
    mounted = False
    try:
        subprocess.run(['mount', '-t', 'tmpfs', '-o', 'nosuid,nodev,mode=0755', 'tmpfs', str(f.commands)], check=True)
        mounted = True
        native = program(f, size=None)
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
        assert value['version'] == '2.0' and value['command']['executable_trust']['model'] == 'digest_memfd'
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
        small = program(f, 'small', size=None)
        subprocess.run(['fsverity', 'enable', str(small)], check=True)
        configure(f)
        f.launch()
        for algorithm in ['sha256', 'sha512']:
            native = f.commands / algorithm
            payload, value = csr(f, native)
            evidence = value['command']['executable_trust']
            measured = subprocess.check_output(['fsverity', 'measure', str(native)], text=True).split()[0]
            assert evidence == {'model': 'fs_verity', 'algorithm': algorithm, 'digest': measured.split(':')[1]}, evidence
            assert value['version'] == '2.0' and 'executable_sha256' not in value['command']
            approved(f, payload, b'0\n')
            payload, value = csr(f, native)
            value['command']['executable_trust']['digest'] = '00' * (32 if algorithm == 'sha256' else 64)
            denied(f, canonical(value))
        f.stop()
        subprocess.run(['mount', '-o', 'remount,noexec', str(f.commands)], check=True)
        f.launch()
        payload, value = csr(f, small)
        assert value['version'] == '2.0' and value['command']['executable_trust']['model'] == 'digest_memfd'
        approved(f, payload, b'0\n')
        f.stop()
        subprocess.run(['mount', '-o', 'remount,exec', str(f.commands)], check=True)
        small.chmod(0o655)
        f.launch()
        payload, value = csr(f, small)
        assert value['version'] == '2.0' and value['command']['executable_trust']['model'] == 'digest_memfd'
        approved(f, payload, b'0\n')
        small.chmod(0o755)
        payload, value = csr(f, small)
        assert value['command']['executable_trust']['model'] == 'fs_verity'
        approved(f, payload, b'0\n')
        f.stop()
        metadata_approval_gate(f, small)
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
    for name, gate in [('digest-direct', digest_direct_gate), ('file-capabilities', file_capabilities_gate), ('ctime', ctime_gate), ('mutation', mutation_gate), ('noexec', noexec_gate), ('tracer-death', tracer_death_gate), ('fs-verity', verity_gate)]:
        gate(args.cgroup_parent, args.binaries)
        results.append({'gate': name, 'result': 'passed'})
        print(json.dumps(results[-1]), flush=True)
        (args.artifacts / 'results.json').write_text(json.dumps(results, indent=2) + '\n')


if __name__ == '__main__':
    main()
