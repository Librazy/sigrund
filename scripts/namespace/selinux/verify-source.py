#!/usr/bin/env python3
"""Qualify passed-stream attribution and self-connector death using installed tools.

Run as host root after the installed operator recipe. The raw protocol probe
uses a root writer in the requester domain and a real rootless source with a
different host UID. It tests daemon attribution, not client authentication.
"""
import argparse
import array
import importlib.util
import json
import os
from pathlib import Path
import pwd
import select
import signal
import socket
import struct
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent


def receive(peer, kind):
    def exact(size):
        data = bytearray()
        while len(data) < size:
            chunk = peer.recv(size - len(data))
            assert chunk, 'unexpected control EOF'
            data.extend(chunk)
        return bytes(data)
    tag, size = struct.unpack('>BI', exact(5))
    assert tag == kind and 0 < size <= 512, (tag, size)
    return json.loads(exact(size))


def connect(fd):
    control = socket.socket(fileno=fd)
    peer = socket.socket(socket.AF_UNIX)
    peer.connect('/run/sigrund/client.sock')
    control.sendmsg([b'S'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [peer.fileno()]))])
    peer.close()
    assert control.recv(1) == b'F'


def writer(owner, body):
    assert os.getuid() == 0
    account = pwd.getpwnam(owner)
    parent, control = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    parent.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    parent.settimeout(10)
    def credentials():
        os.setgroups([])
        os.setgid(account.pw_gid)
        os.setuid(account.pw_uid)
    source = subprocess.Popen(['/usr/bin/unshare', '--map-auto', '--map-root-user', '--mount', '--mount-proc',
                               '--cgroup', '--ipc', '--net', '--uts', '--time', '--pid', '--fork', '--kill-child',
                               sys.executable, str(Path(__file__).resolve()), '--connect', str(control.fileno())],
                              preexec_fn=credentials, pass_fds=(control.fileno(),), stdout=subprocess.DEVNULL)
    control.close()
    peer = None
    outputs = []
    try:
        data, ancillary, flags, _ = parent.recvmsg(1, socket.CMSG_SPACE(4) + socket.CMSG_SPACE(12))
        assert data == b'S' and not flags
        rights = array.array('i')
        observed = None
        for level, kind, value in ancillary:
            assert level == socket.SOL_SOCKET
            if kind == socket.SCM_RIGHTS:
                rights.frombytes(value)
            elif kind == socket.SCM_CREDENTIALS:
                observed = struct.unpack('3i', value)
            else:
                raise AssertionError('unexpected ancillary type')
        assert len(rights) == 1 and observed and observed[0] > 0 and observed[1:] == (account.pw_uid, account.pw_gid), observed
        peer = socket.socket(fileno=rights[0])
        peer.settimeout(15)
        payload = body.read_bytes()
        pipes = [os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK) for _ in range(2)]
        outputs = [read for read, write in pipes]
        try:
            peer.sendmsg([b'\x01' + struct.pack('>I', len(payload)) + payload],
                         [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [write for read, write in pipes]))])
        finally:
            for read, write in pipes:
                os.close(write)
        decision = receive(peer, 2)
        assert decision['status'] == 'APPROVED', decision
        ready = receive(peer, 8)
        assert ready == {'exec_id': decision['exec_id'], 'exec_outcome': 'exec_event_observed'}, ready
        result = receive(peer, 5)
        assert result == {'exec_id': decision['exec_id'], 'status': 'EXITED', 'exit_code': 0, 'signal': None}, result
        # Control completion can precede the last stdio relay write. Drain the
        # same pipe kind used by the installed CLI until the producer closes it.
        output = []
        for fd in outputs:
            data = bytearray()
            deadline = time.monotonic() + 10
            while True:
                assert select.select([fd], [], [], max(0, deadline - time.monotonic()))[0], 'stdio EOF deadline'
                chunk = os.read(fd, 65536)
                if not chunk:
                    break
                data.extend(chunk)
                assert len(data) <= 65536
            output.append(data.decode())
        assert 'destination=B' in output[0] and not output[1], output
        print(json.dumps({'writer_uid': os.getuid(), 'connector_pid': observed[0], 'connector_uid': observed[1],
                          'connector_gid': observed[2], 'exec_id': decision['exec_id'], 'stdout': output[0]}))
        parent.send(b'F')
        assert source.wait(timeout=5) == 0
    finally:
        if source.poll() is None:
            source.kill()
            source.wait(timeout=5)
        if peer:
            peer.close()
        for fd in outputs:
            os.close(fd)
        parent.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifacts', type=Path)
    parser.add_argument('--owner', default='nsrequester')
    parser.add_argument('--connect', type=int, help=argparse.SUPPRESS)
    parser.add_argument('--writer', type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.connect is not None:
        connect(args.connect)
        return
    if args.writer:
        writer(args.owner, args.writer)
        return
    if os.geteuid() != 0 or not args.artifacts:
        parser.error('host root and a new --artifacts directory required')
    args.artifacts.mkdir(mode=0o700)
    spec = importlib.util.spec_from_file_location('installed', HERE / 'verify-installed.py')
    api = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(api)
    result = {'passed': False, 'cases': []}
    approver = api.Approver(Path('/var/lib/sigrund-namespace-lab/approver'))
    try:
        intent = {'account': {'kind': 'name', 'name': 'ns_service'}, 'caller_env': {},
                  'command': {'allow_interpreted_script': False, 'argv': [api.TOOL], 'cwd': '/srv/service',
                              'executable_path': api.TOOL, 'stdin_policy': 'null', 'tty_mode': 'stdio'},
                  'execution_context': {'caller_env_allowlist': [], 'capabilities': [], 'umask': 63,
                                        'env_exact': {'LANG': 'C.UTF-8', 'PATH': '/usr/sbin:/usr/bin'}},
                  'policy': {'mode': 'one_time', 'ttl_secs': 900}, 'security_profile': 'namespace-selinux-v1',
                  'target': {'kind': 'registered', 'id': 'container-b'}}
        body = args.artifacts / 'passed-stream.json'
        body.write_text(json.dumps({'version': '3.0', 'mode': 'thin_csr', 'tty_mode': 'stdio', 'caller_env': {}, 'intent': intent}))
        process = subprocess.Popen(api.requester('root', 'sigrund-namespace-root-writer',
                    [sys.executable, str(Path(__file__).resolve()), '--owner', args.owner, '--writer', str(body)]),
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            review = approver.confirm(process)
            execution = api.execution_id(review)
            stdout, stderr = process.communicate(timeout=20)
            assert process.returncode == 0, (stdout, stderr)
            observed = json.loads(stdout)
            rows = api.assert_execution(execution)
            commit = next(row for row in rows if row['event_type'] == 'AUTH_COMMIT')
            assert observed['writer_uid'] == 0 and commit['requester_uid'] == observed['connector_uid'] == pwd.getpwnam(args.owner).pw_uid
            result['cases'].append({'name': 'passed-rootless-stream-retains-original-connector-despite-root-writer',
                                    'result': 'passed', 'exec_id': execution, 'observed': observed, 'audit': rows})
        finally:
            if process.poll() is None:
                subprocess.run(['systemctl', 'stop', 'sigrund-namespace-root-writer.service'], capture_output=True)
                process.kill()
                process.communicate(timeout=5)
        process = subprocess.Popen([*api.client('a-self', args.owner), 'wait'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        descriptors = []
        connector = None
        try:
            review = approver.confirm(process)
            execution = api.execution_id(review)
            assert select.select([process.stdout], [], [], 10)[0]
            assert b'destination=A' in os.read(process.stdout.fileno(), 4096)
            evidence = json.loads(Path('/var/lib/sigrund/host-epoch.json').read_text())['process_review']
            connector = os.pidfd_open(evidence['authenticated_source']['pid'])
            pids = api.workload_descendants(execution)
            descriptors = [os.pidfd_open(int(pid)) for pid in pids]
            signal.pidfd_send_signal(connector, signal.SIGKILL)
            stdout, stderr = process.communicate(timeout=15)
            assert process.returncode != 0 and not stdout, (stdout, stderr)
            rows = api.assert_execution(execution)
            assert all(select.select([fd], [], [], 1)[0] for fd in descriptors), 'self descendant survived connector death'
            result['cases'].append({'name': 'self-connector-death-kills-primary-and-descendant-with-live-relay',
                                    'result': 'passed', 'exec_id': execution, 'pidfd_exit_count': len(descriptors), 'audit': rows})
        finally:
            for fd in descriptors + ([connector] if connector is not None else []):
                os.close(fd)
            if process.poll() is None:
                subprocess.run(['systemctl', 'stop', 'sigrund-namespace-a-client.service'], capture_output=True)
                process.kill()
                process.communicate(timeout=5)
        result['passed'] = True
    finally:
        (args.artifacts / 'approver.log').write_bytes(approver.transcript)
        approver.close()
        (args.artifacts / 'result.json').write_text(json.dumps(result, indent=2) + '\n')


if __name__ == '__main__':
    main()
