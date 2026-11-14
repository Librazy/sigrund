#!/usr/bin/env python3
"""Qualify admin digest_direct in real rootful Podman/Docker on a disposable host.

Builds a local scratch image from test binaries; no registry images are pulled.
The runtime starts a privileged, unfiltered fixture anchor. This is test setup,
not a recommended container policy or a claim of runtime exec-policy equivalence.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import platform
import pwd
import re
import runpy
import secrets
import shutil
import subprocess
import tarfile
import tempfile

HERE = Path(__file__).resolve().parent
ADMIN = runpy.run_path(str(HERE / 'verify-admin.py'))
EX, API, REVIEW, REPO = (ADMIN[name] for name in ('EX', 'API', 'REVIEW', 'REPO'))


class RuntimeContainer:
    def __init__(self, runtime, stage, fixture, image):
        self.runtime, self.stage, self.fixture, self.image = runtime, stage, fixture, image
        self.name = 'sigrund-overlay-' + secrets.token_hex(6)
        self.account = pwd.getpwnam('root')
        self.pid = None
        self.root = None
        self.exposed_cgroup = False

    def command(self, *args, **kwargs):
        return subprocess.run([self.runtime, *args], check=True, capture_output=True, text=True, **kwargs)

    def start(self):
        self.command('run', '--detach', '--name', self.name, '--privileged', '--network=none',
            '--security-opt=label=disable', '--security-opt=seccomp=unconfined',
            '--mount', f'type=bind,source={self.fixture.base},destination={self.fixture.base}',
            *(['--mount', 'type=bind,source=/sys/fs/cgroup,destination=/unsafe-cgroup']
              if self.exposed_cgroup else []),
            self.image, '/anchor', 'idle', '/', str(self.fixture.client) + '.anchor')
        self.init = int(self.command('inspect', '--format', '{{.State.Pid}}', self.name).stdout)
        self.root = Path(f'/proc/{self.init}/root')

    def start_anchor(self):
        self.command('exec', '--detach', self.name, '/anchor', 'anchor', str(self.fixture.client) + '.anchor')
        def connected():
            for entry in Path('/proc').iterdir():
                if not entry.name.isdecimal():
                    continue
                try:
                    if not (entry / 'cmdline').read_bytes().startswith(b'/anchor\0anchor\0'):
                        continue
                    if (entry / 'ns/mnt').stat().st_ino != Path(f'/proc/{self.init}/ns/mnt').stat().st_ino:
                        continue
                    fields = (entry / 'syscall').read_text().split()
                    if len(fields) > 1 and fields[0] == '0' and os.readlink(entry / 'fd' / str(int(fields[1], 0))).startswith('socket:'):
                        self.pid = int(entry.name)
                        return True
                except (FileNotFoundError, PermissionError):
                    # The packaged producer deliberately hides its proc files
                    # even from the unconfined harness. It is not our anchor.
                    continue
            return False
        API['wait_for'](connected, 'runtime anchor connection')

    def close(self):
        subprocess.run([self.runtime, 'rm', '--force', self.name], capture_output=True)


class DistroboxContainer(RuntimeContainer):
    """Use an already initialized, disposable rootful Podman Distrobox."""
    def __init__(self, name, stage, fixture):
        super().__init__('podman', stage, fixture, None)
        self.name, self.created = name, []

    def start(self):
        labels = json.loads(self.command('inspect', '--format', '{{json .Config.Labels}}', self.name).stdout)
        assert labels.get('manager') == 'distrobox', labels
        self.init = int(self.command('inspect', '--format', '{{.State.Pid}}', self.name).stdout)
        assert self.init > 0, 'initialize the disposable Distrobox before running this harness'
        self.root = Path(f'/proc/{self.init}/root')
        for source, name in ((self.stage / 'anchor', 'anchor'), (self.stage / 'sigrun', 'sigrun'),
                             (self.stage / 'usr/bin/sigrund-admin-probe', 'usr/bin/sigrund-admin-probe')):
            destination = self.root / name
            assert not destination.exists(), destination
            shutil.copyfile(source, destination)
            destination.chmod(0o755)
            self.created.append(destination)
        socket_directory = self.root / self.fixture.base.relative_to('/')
        assert not socket_directory.exists(), socket_directory
        socket_directory.symlink_to('/run/host' + str(self.fixture.base))
        self.created.append(socket_directory)

    def close(self):
        for path in reversed(self.created):
            path.unlink(missing_ok=True)
        self.created.clear()


def evidence(fixture):
    review = json.loads((fixture.state / 'host-epoch.json').read_bytes())['process_review']
    storage = review['executable_storage']
    assert storage['kind'] == 'admin_trusted_overlayfs' and storage['administrator_maintained']
    return review


def storage_state(container):
    command = container.root / 'usr/bin/sigrund-admin-probe'
    with command.open('rb') as source:
        mount_id = re.search(r'^mnt_id:\s*(\d+)$', Path(f'/proc/self/fdinfo/{source.fileno()}').read_text(), re.M)[1]
    record = next(line for line in Path(f'/proc/{container.init}/mountinfo').read_text().splitlines()
                  if line.split()[0] == mount_id)
    match = re.search(r'(?:^|,)upperdir=([^,]+)', record.split(' - ')[1].split()[2])
    assert match, record
    upper = Path(re.sub(r'\\([0-7]{3})', lambda m: chr(int(m[1], 8)), match[1])) / 'usr/bin/sigrund-admin-probe'
    if not upper.exists():
        return 'lower'
    try:
        os.getxattr(upper, 'trusted.overlay.metacopy')
        return 'metacopy'
    except OSError as error:
        import errno
        assert error.errno == errno.ENODATA, error
        return 'upper'


def mutation_case(fixture, container, body, state):
    pending = ADMIN['reviewed_request'](fixture, copy.deepcopy(body))
    command = container.root / 'usr/bin/sigrund-admin-probe'
    if state == 'lower':
        command.chmod(0o555)
    elif state == 'metacopy':
        with command.open('r+b') as writer:
            writer.write(b'\x7f')
    else:
        saved = command.with_suffix('.saved')
        command.rename(saved)
        shutil.copyfile(saved, command)
        command.chmod(0o755)
        saved.unlink()
    REVIEW['approve'](fixture, pending[0], pending[4])
    execution = REVIEW['finished_request'](fixture, pending)
    assert not any(r.get('exec_id') == execution and r['event_type'] in ('AUTH_COMMIT', 'EXEC_READY_TO_EXEC')
                   for r in fixture.records())
    API['wait_for'](fixture.empty, 'mutated approval cleanup')


def inside(args):
    parent = Path('/sys/fs/cgroup' + Path('/proc/self/cgroup').read_text().strip().split('::')[1])
    assert parent.name.startswith('sigrund-overlay-')
    (parent / 'runner').mkdir()
    (parent / 'runner/cgroup.procs').write_text(str(os.getpid()))
    (parent / 'cgroup.subtree_control').write_text('+memory +pids')
    tempfile.tempdir = '/usr/local'
    fixture = (ADMIN['ProducerFixture'] if args.producer else API['Fixture'])(parent, args.binaries,
        models=['digest_direct', 'digest_memfd'], authorization_timeout_ms=15000)
    fixture.runtime_max_sec = 600  # match the enclosing runtime qualification unit
    # Every test command lives in /usr/bin. Avoid pinning the ordinary harness's
    # extra command root: a Distrobox reaches that socket tree through /run/host,
    # while executable roots must be real directories without symlink traversal.
    roots = json.dumps(sorted(['/usr/bin', str(fixture.commands)]))
    for path in (fixture.base / 'config', fixture.base / 'signers'):
        path.write_text(path.read_text().replace(roots, json.dumps(['/usr/bin'])))
    if args.producer:
        API['submit'] = ADMIN['producer_submit']
    # Both nested harness modules reference these same API functions.
    for name in ('broker', 'requester_socket'):
        original = API[name]
        def connect(*args, _original=original, **kwargs):
            sock = _original(*args, **kwargs)
            sock.settimeout(30)
            return sock
        API[name] = connect
    cases, containers, images = [], [], []
    result = {'passed': False, 'kernel': platform.release(), 'producer': args.producer,
              'source_sha256': runpy.run_path(str(REPO / 'scripts/check.py'))['source_digest'](),
              'binaries': {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in args.binaries.iterdir() if p.is_file()},
              'runtimes': {}, 'cases': cases}
    work = Path(tempfile.mkdtemp(prefix='sigrund-overlay-', dir='/run'))
    try:
        profile = json.loads((REPO / 'crates/sigrund-core/tests/fixtures/namespace/admin-direct-constraints.json').read_bytes())
        cap_profile = copy.deepcopy(profile)
        cap_profile.update(profile_id='namespace-admin-direct-cap', capabilities=['CAP_NET_BIND_SERVICE'])
        ADMIN['configure'](fixture, [profile, cap_profile])
        fixture.launch()
        anchor = work / 'anchor'
        subprocess.run(['cc', '-static', '-O2', str(REPO / 'crates/sigrund/tests/fixtures/namespace/anchor-execution.c'), '-o', str(anchor)], check=True)
        seed = REVIEW['Container'](work, 'image', anchor, pwd.getpwnam('root'), fixture)
        # Store test commands in the image outside the bind-mounted socket tree.
        # The configured executable-root allowlists already include /usr/bin.
        workload = seed.root / 'usr/bin/sigrund-admin-probe'
        subprocess.run(['cc', '-static', '-O2', str(REPO / 'crates/sigrund/tests/fixtures/namespace/admin.c'), '-o', str(workload)], check=True)
        shutil.copyfile(fixture.client_binary, seed.root / 'sigrun')
        (seed.root / 'sigrun').chmod(0o755)
        for word in subprocess.check_output(['ldd', str(fixture.client_binary)], text=True).split():
            if word.startswith('/'):
                destination = seed.root / word.lstrip('/')
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(word, destination)
                destination.chmod(0o755)
        archive = work / 'image.tar'
        with tarfile.open(archive, 'w') as tar:
            for item in seed.root.iterdir():
                tar.add(item, arcname=item.name)
        seed.close()
        for runtime in [*args.runtime, *(['distrobox'] if args.distrobox else [])]:
            engine = 'podman' if runtime == 'distrobox' else runtime
            image = 'sigrund-overlay-test:' + secrets.token_hex(6)
            if runtime != 'distrobox':
                subprocess.run([engine, 'import', str(archive), image], check=True, capture_output=True)
                images.append((engine, image))
            result['runtimes'][runtime] = {
                'version': subprocess.check_output([engine, '--version'], text=True).strip(),
                'info': json.loads(subprocess.check_output([engine, 'info', '--format', 'json' if engine == 'podman' else '{{json .}}'], text=True)),
            }
            if runtime == 'distrobox':
                result['runtimes'][runtime]['distrobox_version'] = subprocess.check_output(['distrobox', 'version'], text=True).strip()
            for state in (('upper',) if runtime == 'distrobox' else ('lower', 'metacopy', 'upper', 'capabilities', 'exposed-cgroup')):
                selected = cap_profile if state == 'capabilities' else profile
                caps = selected['capabilities']
                capability_hex = '0000000000000400' if caps else '0000000000000000'
                container = DistroboxContainer(args.distrobox, seed.root, fixture) if runtime == 'distrobox' else RuntimeContainer(engine, seed.root, fixture, image)
                container.exposed_cgroup = state == 'exposed-cgroup'
                containers.append(container)
                container.start()
                # chmod drives metadata copy-up when metacopy is enabled; write
                # opens drive full copy-up. Record actual mount options below.
                if state == 'metacopy':
                    container.command('exec', container.name, '/sigrun', '--help')  # real CLI availability
                    os.chmod(container.root / 'usr/bin/sigrund-admin-probe', 0o555)
                elif state == 'upper':
                    with (container.root / 'usr/bin/sigrund-admin-probe').open('r+b') as output:
                        output.write(workload.read_bytes()[:1])
                actual_state = storage_state(container)
                if state in ('lower', 'upper'):
                    assert actual_state == state, (state, actual_state)
                if state == 'metacopy':
                    # Do not label a full copy-up as metacopy qualification.
                    result['runtimes'][runtime]['metacopy_observed'] = actual_state == 'metacopy'
                # The CLI's own connector supplies the authenticated self target.
                operator = API['broker'](fixture)
                client = subprocess.Popen([engine, 'exec', '--user', '65534:65534', container.name,
                    '/sigrun', '--socket', str(fixture.client), '--target', 'self', '--security-profile', selected['profile_id'],
                    '--target-uid', '0', '--target-gid', '0', '--cwd', '/',
                    *(['--capability', 'CAP_NET_BIND_SERVICE'] if caps else []), '--', '/usr/bin/sigrund-admin-probe'],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                try:
                    request = API['review'](operator)
                    evidence(fixture)
                    REVIEW['approve'](fixture, operator, request)
                    stdout, stderr = client.communicate(timeout=30)
                    if container.exposed_cgroup:
                        assert client.returncode == 254 and not stdout, (client.returncode, stdout, stderr)
                        records = [r for r in fixture.records() if r.get('exec_id') == request['exec_id']]
                        assert any(r.get('reason') == 'exec checkpoint failed: child cgroup mount is insufficiently restricted' for r in records)
                        assert not any(r['event_type'] == 'EXEC_READY_TO_EXEC' for r in records)
                        cases.append({'runtime': runtime, 'name': 'exposed-writable-cgroup-rejected'})
                    else:
                        assert client.returncode == 0 and stdout == f'uid=0 gid=0 securebits=47 nnp=1 caps={capability_hex} groups=\n'.encode(), (client.returncode, stdout, stderr)
                        cases.append({'runtime':runtime, 'state':state, 'route':'self'})
                finally:
                    operator.close()
                    if client.poll() is None:
                        client.kill(); client.communicate()
                API['wait_for'](fixture.empty, 'self job cleanup')
                if container.exposed_cgroup:
                    container.close()
                    containers.remove(container)
                    continue
                container.start_anchor()
                REVIEW['management'](args, fixture, 'register', container, selected)
                for uid, groups in ((0, ()), (33, (104,))):
                    body = ADMIN['request'](fixture, selected, uid=uid, groups=groups, caps=caps)
                    body['intent']['command'].update(executable_path='/usr/bin/sigrund-admin-probe', argv=['/usr/bin/sigrund-admin-probe'])
                    execution, output = EX['execute'](fixture, body)
                    expected = f'uid={uid} gid={uid} securebits=47 nnp=1 caps={capability_hex} groups=' + ','.join(map(str,groups)) + '\n'
                    assert output == expected.encode(), output
                    review = evidence(fixture)
                    record = next(r for r in fixture.records() if r.get('exec_id') == execution and r['event_type'] == 'AUTH_COMMIT')
                    assert record['executable_storage'] == review['executable_storage']
                    if args.producer:
                        ready = next(r for r in fixture.records() if r.get('exec_id') == execution and r['event_type'] == 'EXEC_READY_TO_EXEC')
                        assert ready['execution_observed']['ambient_lsm']['context'] == 'system_u:system_r:sigrund_host_workload_t:s0'
                    cases.append({'runtime': runtime, 'state': actual_state, 'uid': uid, 'route': 'registered', 'storage': review['executable_storage']})
                (args.artifacts / f'{runtime}-{state}-mountinfo').write_text(Path(f'/proc/{container.pid}/mountinfo').read_text())
                if state == 'upper':
                    held = copy.deepcopy(body)
                    held['intent']['command']['argv'].append('hold')
                    peer, endpoints, _ = EX['start_execution'](fixture, held)
                    peer.close()
                    for descriptor in endpoints:
                        os.close(descriptor)
                    API['wait_for'](fixture.empty, 'cancelled runtime descendants')
                    cases.append({'runtime': runtime, 'name': 'disconnect-cancels-descendants'})
                if runtime != 'distrobox' and state in ('lower', 'metacopy', 'upper'):
                    mutation_case(fixture, container, body, actual_state)
                    cases.append({'runtime': runtime, 'name': 'approval-copyup-or-replacement-rejected', 'state': actual_state})
                REVIEW['management'](args, fixture, 'revoke')
                container.close()
                containers.remove(container)
                API['wait_for'](fixture.empty, 'runtime job cleanup')
        result['passed'] = True
    finally:
        (args.artifacts / 'audit.jsonl').write_bytes(fixture.log.read_bytes() if fixture.log.exists() else b'')
        (args.artifacts / 'diagnostics').write_bytes(fixture.diagnostics.read_bytes())
        for container in reversed(containers):
            container.close()
        for runtime, image in reversed(images):
            subprocess.run([runtime, 'image', 'rm', '--force', image], capture_output=True)
        fixture.cleanup()
        shutil.rmtree(work)
        (args.artifacts / 'result.json').write_text(json.dumps(result, indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binaries', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--runtime', action='append', choices=['podman', 'docker'], default=[])
    parser.add_argument('--distrobox', help='also qualify this already initialized disposable rootful Podman Distrobox')
    parser.add_argument('--producer', action='store_true')
    parser.add_argument('--inside', action='store_true')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('root on a disposable systemd host required')
    args.runtime = args.runtime or ([] if args.distrobox else ['podman', 'docker'])
    args.binaries = args.binaries.resolve(strict=True)
    if args.inside:
        inside(args)
        return
    REVIEW['trusted_directory'](args.artifacts.parent)
    args.artifacts.mkdir(mode=0o700)
    unit = 'sigrund-overlay-' + secrets.token_hex(6) + '.service'
    command = ['systemd-run', '--quiet', '--unit='+unit, '--wait', '--collect', '--property=Delegate=yes',
        '--property=KillMode=control-group', '--property=RuntimeMaxSec=600s',
        *(['--property=SELinuxContext=' + Path('/proc/self/attr/current').read_text().strip('\0\n')]
          if Path('/sys/fs/selinux/enforce').exists() else []),
        '/usr/bin/python3', str(Path(__file__).resolve()), '--inside', '--binaries', str(args.binaries), '--artifacts', str(args.artifacts)]
    for runtime in args.runtime:
        command.extend(['--runtime',runtime])
    if args.distrobox:
        command.extend(['--distrobox', args.distrobox])
    if args.producer:
        command.append('--producer')
    try:
        subprocess.run(command, check=True)
    finally:
        REVIEW['SUPPORT']['stop_service'](unit)


if __name__ == '__main__':
    main()
