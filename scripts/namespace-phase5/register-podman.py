#!/usr/bin/env python3
"""Start/register a dedicated anchor in the prepared, trusted Podman rootfs.

Host-administrator tool for the declared disposable rootful deployment. It pins
namespace/root handles before launch; a manager-returned PID is not execution
or authorization authority. The daemon independently acquires and validates it.
"""
import argparse
import http.client
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct
import subprocess
import sys
import time

ROOT = Path('/var/lib/sigrund-phase5b-rootfs')
UNIT = 'sigrund-phase5b-b-anchor.service'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--unit', default=UNIT, help='dedicated sigrund-phase5b anchor unit')
    parser.add_argument('--container', default='sigrund-phase5b-b')
    parser.add_argument('--endpoint', type=Path, default=Path('/run/podman/podman.sock'))
    parser.add_argument('--registration', default='container-b')
    parser.add_argument('--launch-only', action='store_true', help='start a disposable anchor without registering it')
    parser.add_argument('--socket', type=Path, default=Path('/run/sigrund/client.sock'))
    args = parser.parse_args()
    if os.geteuid() != 0 or Path('/proc/self/uid_map').read_text().split() != ['0', '0', '4294967295']:
        parser.error('initial-userns host root required')
    for name in (args.container, args.registration):
        if not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', name):
            parser.error('invalid container/registration identifier')
    for path in (args.endpoint, args.socket):
        if not path.is_absolute() or any(part in ('.', '..') for part in path.parts):
            parser.error('canonical absolute endpoint paths required')
    context = Path('/proc/self/attr/current').read_text().strip('\0\n')
    if context.split(':')[2] != 'unconfined_t':
        parser.error('use the trusted host administrator context')
    unit = args.unit
    if not re.fullmatch(r'sigrund-phase5b-[A-Za-z0-9_.-]+-anchor\.service', unit):
        parser.error('invalid dedicated anchor unit')
    handles = []
    started = False
    try:
        parent = os.open(args.endpoint.parent, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        handles.append(parent)
        metadata = os.fstat(parent)
        assert metadata.st_uid == metadata.st_gid == 0 and not metadata.st_mode & 0o022
        endpoint = '/proc/self/fd/' + str(parent) + '/' + args.endpoint.name
        metadata = os.stat(endpoint, follow_symlinks=False)
        assert stat.S_ISSOCK(metadata.st_mode) and metadata.st_uid == metadata.st_gid == 0 and not metadata.st_mode & 0o007
        connection = socket.socket(socket.AF_UNIX)
        connection.settimeout(2)
        connection.connect(endpoint)
        _, uid, gid = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        assert uid == gid == 0
        connection.sendall(('GET /v5.0.0/libpod/containers/' + args.container + '/json HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n').encode())
        response = http.client.HTTPResponse(connection)
        response.begin()
        assert response.status == 200
        body = response.read(1_048_577)
        assert len(body) <= 1_048_576
        response.close(); connection.close()
        info = json.loads(body)
        assert info['Name'] == args.container and info['Namespace'] == ''
        assert info['Rootfs'] == str(ROOT) and info['HostConfig']['ReadonlyRootfs']
        assert info['HostConfig']['CgroupManager'] == 'systemd' and info['HostConfig']['PidMode'] == 'private'
        assert info['State']['Running'] and not info['State']['Paused']
        pid = info['State']['Pid']
        assert type(pid) is int and 0 < pid <= 2_147_483_647
        pidfd = os.pidfd_open(pid); handles.append(pidfd)
        proc = os.open('/proc/' + str(pid), os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
        handles.append(proc)
        procpath = '/proc/self/fd/' + str(proc)
        assert Path(procpath + '/cgroup').read_text() == '0::/machine.slice/libpod-' + info['Id'] + '.scope/container\n'
        expected = ROOT.stat()
        root = os.open(procpath + '/root', os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
        handles.append(root)
        actual = os.fstat(root)
        assert (actual.st_dev, actual.st_ino) == (expected.st_dev, expected.st_ino)
        nsargs = []
        for name, flag in (('user', 'user'), ('cgroup', 'cgroup'), ('ipc', 'ipc'), ('mnt', 'mount'), ('net', 'net'), ('pid', 'pid'), ('time', 'time'), ('uts', 'uts')):
            fd = os.open(procpath + '/ns/' + name, os.O_RDONLY | os.O_CLOEXEC)
            handles.append(fd)
            namespace = os.fstat(fd); own = os.stat('/proc/self/ns/' + name)
            if (namespace.st_dev, namespace.st_ino) != (own.st_dev, own.st_ino):
                assert name != 'user', 'this recipe qualifies the initial user namespace only'
                nsargs.append('--' + flag + '=/proc/' + str(os.getpid()) + '/fd/' + str(fd))
        import select
        assert not select.select([pidfd], [], [], 0)[0], 'init exited during acquisition'
        command = ['systemd-run', '--quiet', '--collect', '--unit=' + unit,
            '--property=SELinuxContext=' + context, '--property=KillMode=control-group',
            '--property=RuntimeMaxSec=3600s', 'nsenter', *nsargs,
            '--root=/proc/' + str(os.getpid()) + '/fd/' + str(root), '--wdns=/',
            '/usr/bin/sigrund-anchor', '--socket', str(args.socket) + '.anchor']
        subprocess.run(command, check=True, timeout=5)
        started = True
        tasks = Path('/sys/fs/cgroup/system.slice') / unit / 'cgroup.procs'
        deadline = time.monotonic() + 5
        anchor = None
        while time.monotonic() < deadline and anchor is None:
            for task in tasks.read_text().split() if tasks.exists() else []:
                try:
                    if os.readlink('/proc/' + task + '/exe').endswith('/sigrund-anchor'):
                        anchor = int(task); break
                except FileNotFoundError:
                    pass
            if anchor is None:
                time.sleep(.02)
        assert anchor is not None, 'dedicated anchor did not exec'
        if args.launch_only:
            print(json.dumps({'init_pid': pid, 'anchor_pid': anchor, 'container_id': info['Id'], 'unit': unit}))
            return
        command = ['sigrundctl', 'target', 'register-podman', args.registration, '--pid', str(anchor),
            '--owner-uid', '0', '--security-profile', 'namespace-selinux-v1', '--socket', str(args.socket),
            '--podman-endpoint', str(args.endpoint), '--podman-owner-uid', '0',
            '--podman-namespace', 'default', '--podman-container', args.container]
        while True:
            result = subprocess.run(command, capture_output=True, timeout=12)
            if result.returncode == 0:
                break
            if b'operation would block' in result.stderr:
                # Resource ownership can outlive revoke's acknowledgment. This
                # attempt may have consumed the rendezvous, so use a fresh
                # anchor after actual disposal rather than retrying that PID.
                attempt = int(os.environ.get('SIGRUND_PHASE5B_REGISTER_RETRY', '0'))
                assert attempt < 3, result.stderr.decode()
                subprocess.run(['systemctl', 'stop', unit], capture_output=True, timeout=10)
                time.sleep(.2)
                os.environ['SIGRUND_PHASE5B_REGISTER_RETRY'] = str(attempt + 1)
                os.execv(sys.executable, [sys.executable, str(Path(__file__).resolve()), *sys.argv[1:]])
            assert b'matching dedicated anchor has not connected' in result.stderr, result.stderr.decode()
            assert time.monotonic() < deadline, result.stderr.decode()
            time.sleep(.02)
        print(json.dumps({'init_pid': pid, 'anchor_pid': anchor, 'container_id': info['Id'], 'unit': unit}))
    except BaseException:
        if started:
            subprocess.run(['systemctl', 'stop', unit], capture_output=True, timeout=10)
        raise
    finally:
        for fd in reversed(handles):
            os.close(fd)


if __name__ == '__main__':
    main()
