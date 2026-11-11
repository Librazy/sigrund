#!/usr/bin/env python3
"""Create and enter a disposable rootless environment using installed tools.

Run as host root on the disposable SELinux test host. The owner must be a locked
account with no login or sudo access. All its processes must use the packaged
sigrund_requester_t domain; unconfined host accounts remain trusted admins.
"""
import argparse
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import subprocess
import time

BASE = Path('/var/lib/sigrund-namespace-environments')
CONTEXT = 'system_u:system_r:sigrund_requester_t:s0'


def run(*command, **kwargs):
    return subprocess.run(list(map(str, command)), check=True, **kwargs)


def copy_binary(root, path):
    path = Path(path)
    destination = root / path.relative_to('/')
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(path, destination)
    destination.chmod(0o755)
    dependencies = subprocess.check_output(['ldd', str(path)], text=True)
    for dependency in dependencies.split():
        if dependency.startswith('/'):
            source = Path(dependency)
            target = root / source.relative_to('/')
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
            target.chmod(0o755)


def owner(name):
    account = pwd.getpwnam(name)
    if account.pw_uid == 0 or account.pw_gid == 0 or account.pw_shell not in ('/sbin/nologin', '/usr/sbin/nologin'):
        raise ValueError('owner must be a nonroot account with a nologin shell')
    for kind in ('subuid', 'subgid'):
        entries = [line.split(':') for line in Path('/etc/' + kind).read_text().splitlines()]
        if not any(key in (name, str(account.pw_uid)) and int(count) >= 65536 for key, start, count in entries):
            raise ValueError('owner needs at least 65536 subordinate ' + kind + ' IDs')
    return account


def create(args):
    account = owner(args.owner)
    BASE.mkdir(mode=0o755, exist_ok=True)
    BASE.chmod(0o755)
    root = BASE / args.name
    root.mkdir(mode=0o755)
    for directory in ('run/sigrund', 'proc', 'sys/fs/selinux', 'dev', 'etc', 'srv/service', 'usr/local/libexec/sigrund-namespace'):
        (root / directory).mkdir(parents=True, exist_ok=True, mode=0o755)
    for binary in ('/usr/bin/sigrun', '/usr/bin/sigrund-anchor', '/usr/bin/sh', '/usr/bin/cat', '/usr/bin/sleep'):
        copy_binary(root, binary)
    (root / 'etc/passwd').write_text('root:x:0:0::/:/usr/bin/sh\nns_service:x:12001:12001::/srv/service:/usr/bin/sh\n')
    (root / 'etc/group').write_text('root:x:0:\nns_service:x:12001:\n')
    # The workload is supplied explicitly; this tool neither builds nor approves it.
    tool = root / 'usr/local/libexec/sigrund-namespace/tool'
    shutil.copyfile(args.workload, tool)
    tool.chmod(0o755)
    secret = root / 'srv/secret'
    secret.write_text('namespace denial sentinel\n')
    secret.chmod(0o644)
    run('chcon', 'system_u:object_r:sigrund_workload_secret_t:s0', secret)
    # Keep provisioning and mount points under host-root ownership. The owner
    # may replace mounts inside its private namespace, but cannot race this
    # administrative process by replacing host mount-point paths.
    # Host-owned manifest is outside the root controlled by the namespace owner.
    manifest = BASE / (args.name + '.json')
    with manifest.open('x') as output:
        os.fchmod(output.fileno(), 0o644)
        json.dump({'root': str(root), 'owner': account.pw_name, 'uid': account.pw_uid,
                   'gid': account.pw_gid, 'context': CONTEXT}, output)
    # Only genuine kernel filesystems and the installed socket directory are exposed.
    run('mount', '--bind', '/run/sigrund', root / 'run/sigrund')
    run('mount', '--bind', '/sys/fs/selinux', root / 'sys/fs/selinux')
    # The read-only AV query is implemented by selinuxfs as a write/read
    # transaction on /access. SELinux grants this domain compute_av, without
    # granting enforcement changes or policy loading.
    run('mount', '-o', 'remount,bind,rw,nosuid,nodev,noexec', root / 'sys/fs/selinux')
    (root / 'dev/null').touch()
    run('mount', '--bind', '/dev/null', root / 'dev/null')
    print(manifest)


def command(args):
    manifest = json.loads((BASE / (args.name + '.json')).read_text())
    account = owner(manifest['owner'])
    root = BASE / args.name
    if manifest['root'] != str(root) or manifest['uid'] != account.pw_uid or manifest['context'] != CONTEXT:
        raise ValueError('environment identity changed')
    # systemd recreates RuntimeDirectory on restart. A previous bind still
    # refers to its retired inode; expose the current directory to each new
    # environment, while already-running sources retain their old binding.
    if args.action != 'anchor':
        endpoint = root / 'run/sigrund'
        if os.path.ismount(endpoint):
            run('umount', endpoint)
        run('mount', '--bind', '/run/sigrund', endpoint)
    unit = 'sigrund-namespace-' + args.name + '-' + args.action
    invocation = ['systemd-run', '--quiet', '--collect', '--unit=' + unit,
                  '--property=User=' + account.pw_name, '--property=SELinuxContext=' + CONTEXT,
                  '--property=KillMode=control-group', '--property=RuntimeMaxSec=600s']
    if args.action == 'client':
        invocation += ['--wait', '--pipe']
    else:
        invocation += ['--property=StandardOutput=journal', '--property=StandardError=journal']
    if args.action == 'anchor':
        tasks = Path('/sys/fs/cgroup/system.slice/sigrund-namespace-' + args.name + '-init.service/cgroup.procs')
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            for pid in tasks.read_text().split() if tasks.exists() else []:
                try:
                    if os.readlink('/proc/' + pid + '/exe').endswith('/usr/bin/sleep'):
                        return [*invocation, '/usr/bin/nsenter', '--target', pid, '--all', '--root', '--wdns=/',
                                '/usr/bin/sigrund-anchor', '--socket', '/run/sigrund/client.sock.anchor']
                except FileNotFoundError:
                    pass
            time.sleep(0.02)
        raise ValueError('start the environment init before its disposable anchor')
    # This shell runs after entering the new user namespace. The retained root
    # must reference the bind mount itself, rather than the path beneath it.
    setup = 'mount --make-rprivate /; mount --rbind "$1" "$1"; mount -t proc proc "$1/proc"; shift; exec chroot "$@"'
    invocation += ['/usr/bin/unshare', '--map-auto', '--map-root-user', '--mount', '--cgroup',
                   '--ipc', '--net', '--uts', '--time', '--pid', '--fork', '--kill-child',
                   '/usr/bin/sh', '-ec', setup, 'namespace', str(root), str(root)]
    if args.action == 'init':
        invocation += ['/usr/bin/sleep', '600']
    else:
        invocation += ['/usr/bin/sigrun', '--socket', '/run/sigrund/client.sock', *args.arguments]
    return invocation


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('create', 'init', 'anchor', 'client'))
    parser.add_argument('name')
    parser.add_argument('--owner')
    parser.add_argument('--workload', type=Path)
    parser.add_argument('--registration')
    args, rest = parser.parse_known_args()
    if os.geteuid() != 0 or not re.fullmatch('[ab]', args.name):
        parser.error('host root and environment name a or b required')
    if subprocess.check_output(['getenforce'], text=True).strip() != 'Enforcing':
        parser.error('enforcing SELinux required')
    if args.action == 'create':
        if not args.owner or not args.workload or rest:
            parser.error('create needs --owner and --workload')
        create(args)
    else:
        args.arguments = rest[1:] if rest[:1] == ['--'] else rest
        run(*command(args))
        if args.action == 'anchor' and args.registration:
            manifest = json.loads((BASE / (args.name + '.json')).read_text())
            processes = Path('/sys/fs/cgroup/system.slice/sigrund-namespace-' + args.name + '-anchor.service/cgroup.procs')
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                for pid in processes.read_text().split() if processes.exists() else []:
                    try:
                        executable = os.readlink('/proc/' + pid + '/exe')
                        if not executable.endswith('/usr/bin/sigrund-anchor'):
                            continue
                        result = subprocess.run(['sigrundctl', 'target', 'register', args.registration,
                                                 '--pid', pid, '--owner-uid', str(manifest['uid']),
                                                 '--security-profile', 'namespace-selinux-v1',
                                                 '--socket', '/run/sigrund/client.sock'], capture_output=True)
                        if result.returncode == 0:
                            print(result.stdout.decode(), end='')
                            return
                    except FileNotFoundError:
                        pass
                time.sleep(0.02)
            raise RuntimeError('anchor did not register within its bounded rendezvous window')


if __name__ == '__main__':
    main()
