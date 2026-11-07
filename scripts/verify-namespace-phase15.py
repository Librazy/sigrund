#!/usr/bin/env python3
"""Exercise Phase 1.5 on a disposable host, under one bounded systemd service.

The registry below is a fixture of the frozen G-05 contract. Production clients
continue to accept only host targets. No container workload is authorized here.
"""
import argparse
import copy
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import platform
import pwd
import runpy
import secrets
import select
import shutil
import subprocess
import time
import traceback

REPO = Path(__file__).resolve().parent.parent
PHASE0 = runpy.run_path(str(REPO / 'scripts/verify-namespace-phase0.py'))
trusted_directory = runpy.run_path(str(REPO / 'scripts/operator-lab.py'))['trusted']
def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def sha(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def write(path, value):
    with open(path, 'xb') as output:
        os.fchmod(output.fileno(), 0o600)
        output.write(canonical(value))


@dataclass(frozen=True)
class PendingReview:
    registration_id: str
    revision: str
    instance: str
    acquisition_sha256: str
    registration_sha256: str


class FixtureRegistry:
    """Identity-based live ownership; labels never repair a pending binding."""
    def __init__(self):
        self.entries = {}

    def register(self, label, owner, profile_sha256, declared_owner):
        if not owner.live():
            raise ValueError('registration requires the retained live owner')
        revision = secrets.token_hex(32)
        acquisition = copy.deepcopy(owner.acquisition)
        acquisition['lifecycle'].update(registration_id=label, registration_revision=revision)
        registration = {'schema': 'sigrund.registration.phase0.v1', 'id': label,
                        'revision': revision, 'daemon_pid': acquisition['pid'],
                        'owner_uid': declared_owner, 'profile_sha256': profile_sha256}
        self.entries[label] = (owner, copy.deepcopy(registration), copy.deepcopy(acquisition))
        return registration, acquisition

    def pending(self, label):
        _, registration, acquisition = self.entries[label]
        return PendingReview(label, registration['revision'], acquisition['instance_id'], sha(acquisition), sha(registration))

    def permits(self, pending):
        current = self.entries.get(pending.registration_id)
        if current is None:
            return False
        owner, registration, acquisition = current
        return (registration['revision'] == pending.revision
                and acquisition['instance_id'] == pending.instance
                and sha(acquisition) == pending.acquisition_sha256
                and sha(registration) == pending.registration_sha256 and owner.live())

    def revoke(self, label):
        self.entries.pop(label)


def read_line(process, timeout=15):
    if not select.select([process.stdout], [], [], timeout)[0]:
        raise TimeoutError('fixture did not reach its next barrier')
    line = process.stdout.readline(65_537)
    if not line or len(line) > 65_536:
        raise RuntimeError('fixture closed its control channel or exceeded the record ceiling')
    return json.loads(line)


class Captured:
    def __init__(self, work, name, binary, account, epoch, instance, *, denied=False, shared_time=False):
        self.process = self.container = None
        self.error = self.container_error = None
        self.disposed = False
        self.root = work / name
        self.root.mkdir(mode=0o755)
        # Host-root ownership prevents the container owner from replacing paths.
        for directory in ('run', 'proc', 'etc'):
            (self.root / directory).mkdir(mode=0o755)
        shutil.copyfile(binary, self.root / 'anchor')
        (self.root / 'anchor').chmod(0o755)
        (self.root / 'etc/passwd').write_text('root:x:0:0::/:/anchor\nphase15_service:x:12001:12001::/srv/service:/anchor\n')
        (self.root / 'etc/group').write_text('root:x:0:\nphase15_service:x:12001:\n')
        self.error = open(work / (name + '.capture.stderr'), 'wb')
        self.container_error = open(work / (name + '.container.stderr'), 'wb')
        environment = {**os.environ, 'PHASE0_DAEMON_EPOCH': epoch, 'PHASE0_TARGET_INSTANCE': instance,
                       'PHASE15_OWNER_UID': str(account.pw_uid)}
        command = [str(binary), 'capture', str(self.root / 'run/capture.sock')]
        if denied:
            command = ['setpriv', '--bounding-set=-sys_ptrace', *command]
        try:
            self.process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                            stderr=self.error, env=environment, bufsize=0)
            assert read_line(self.process) == {'event': 'listening'}
            self.command = [
                'setpriv', '--reuid=' + str(account.pw_uid), '--regid=' + str(account.pw_gid), '--clear-groups',
                'unshare', '--map-auto', '--map-root-user', '--mount', '--cgroup',
                '--ipc', '--net', '--uts', '--time', '--pid', '--fork', '--kill-child', '--mount-proc',
                '--root', str(self.root), '/anchor', 'init', '/run/capture.sock',
            ]
            if shared_time:
                self.command.remove('--time')
            self.container = subprocess.Popen(self.command, stdout=subprocess.DEVNULL, stderr=self.container_error)
            if denied or shared_time:
                assert self.process.wait(timeout=15) != 0
                return
            self.acquisition = read_line(self.process)
            assert self.acquisition['capture'] == 'traced_private_fs_v1'
            assert self.acquisition['anchor']['host_uid'] == account.pw_uid
        except BaseException:
            self.close()
            raise

    def live(self):
        if self.disposed:
            return False
        self.process.stdin.write(b'L')
        return read_line(self.process)['live']

    def kill_anchor(self):
        self.process.stdin.write(b'K')
        assert read_line(self.process) == {'anchor_exited': True}
        assert not self.live()

    def close(self):
        observation = None
        try:
            if self.process and self.process.poll() is None:
                if hasattr(self, 'acquisition'):
                    self.process.stdin.write(b'D')
                    observation = read_line(self.process)
                    assert observation == {'cleanup_complete': True, 'fd_count_restored': True}
                    assert self.process.wait(timeout=5) == 0
                else:
                    self.process.kill()
                    self.process.wait(timeout=5)
            if self.container:
                # PID 1 exits after the tracer kills and reaps its dedicated anchor.
                self.container.wait(timeout=5)
            return observation
        finally:
            self.disposed = True
            for process in (self.process, self.container):
                if process:
                    for stream in (process.stdin, process.stdout):
                        if stream:
                            stream.close()
            for stream in (self.error, self.container_error):
                if stream:
                    stream.close()


def host_outcomes(parent, binaries, artifacts):
    api = runpy.run_path(str(REPO / 'scripts/verify-v3.py'))
    fixture = api['Fixture'](parent, binaries)
    try:
        fixture.launch()
        examples = []
        for mode in ('thin_csr', 'full_csr'):
            approver = api['broker'](fixture)
            peer = api['requester_socket'](fixture)
            body = api['hello'](api['payload'](fixture), mode)
            submitted = time.monotonic()
            endpoints = api['submit'](peer, body)
            try:
                request = api['review'](approver)
                started = time.monotonic()
                api['refuse'](approver, request)
                decision = api['receive'](peer, 2)
                elapsed = time.monotonic() - started
                elapsed_submission = time.monotonic() - submitted
                expected = 'TIMEOUT' if mode == 'thin_csr' else 'REJECTED'
                assert decision == {'exec_id': request['exec_id'], 'status': expected}
                assert elapsed_submission >= 2.3 if mode == 'thin_csr' else elapsed < 1
                api['wait_for'](lambda: select.select([endpoints[0]], [], [], 0)[0], 'actual output endpoint close')
                assert os.read(endpoints[0], 1) == b'' and os.fstat(endpoints[1]).st_size == 0
                api['wait_for'](lambda: any(r.get('event_type') == 'PRIVATE_OUTCOME'
                                           and r.get('exec_id') == decision['exec_id'] for r in fixture.records()),
                                'private outcome by execution ID')
                private = [r for r in fixture.records() if r.get('exec_id') == decision['exec_id']]
                examples.append({'request_mode': mode, 'public_decision': decision,
                                 'elapsed_after_refusal_secs': elapsed, 'elapsed_from_submission_secs': elapsed_submission,
                                 'private_audit_by_exec_id': private})
            finally:
                peer.close()
                approver.close()
                for descriptor in endpoints:
                    os.close(descriptor)
        assert not any(r.get('event_type') == 'AUTH_COMMIT' for r in fixture.records())
        write(artifacts / 'host-outcomes.private.json', examples)
        return fixture.binding()['host_id']
    finally:
        fixture.stop()


def run_inside(args):
    artifacts = args.artifacts
    manifest = {'schema': 'sigrund.phase15-evidence.v1', 'result': 'incomplete',
                'kernel': platform.release(), 'os_release': Path('/etc/os-release').read_text(),
                'topology': 'native rootless container; initial userns parent; util-linux unshare',
                'production_container_execution': False, 'cases': []}
    work = Path('/run') / ('sigrund-p15-' + secrets.token_hex(4))
    work.mkdir(mode=0o755)
    owners = []
    try:
        group = PHASE0['current_cgroup']()
        if not group.name.startswith('sigrund-phase15-') or not group.name.endswith('.service'):
            raise RuntimeError('runner requires its independently bounded supervisor')
        control, jobs = group / 'control', group / 'jobs'
        control.mkdir()
        (control / 'cgroup.procs').write_text(str(os.getpid()))
        (group / 'cgroup.subtree_control').write_text('+memory +pids')
        jobs.mkdir()
        (jobs / 'cgroup.subtree_control').write_text('+memory +pids')
        account = pwd.getpwnam(args.owner)
        assert account.pw_uid != 0
        try:
            pwd.getpwnam('phase15_service')
        except KeyError:
            pass
        else:
            raise RuntimeError('fixture account must be absent from host NSS')
        binary = work / 'anchor'
        source = REPO / 'scripts/namespace-phase1-5/anchor.c'
        build = ['cc', '-std=gnu11', '-static', '-O2', '-Wall', '-Wextra', '-Werror', '-pthread', str(source), '-o', str(binary)]
        subprocess.run(build, check=True, capture_output=True, timeout=60)
        manifest['build'] = build
        manifest['sources_sha256'] = {str(p.relative_to(REPO)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in (Path(__file__), source, REPO / 'scripts/namespace-phase1-5/command.c', REPO / 'scripts/namespace-phase0/probe.c')}
        manifest['anchor_sha256'] = hashlib.sha256(binary.read_bytes()).hexdigest()
        stale = subprocess.run([str(binary), 'stale-peer'], check=True, capture_output=True, timeout=10)
        assert json.loads(stale.stdout) == {'stale_peer_rejected': True, 'unrelated_process_survived': True}
        manifest['cases'].append({'name': 'stale-peer-cannot-kill-reused-pid', 'result': 'passed'})
        epoch = PHASE0['uuid7']()
        registry = FixtureRegistry()
        constraints = json.loads((REPO / 'crates/sigrund-phase0/tests/fixtures/constraints.json').read_bytes())
        profile_hash = sha(constraints)
        write(artifacts / 'constraints.json', constraints)
        authority = host_outcomes(jobs, args.binaries, artifacts)
        manifest['cases'].append({'name': 'host-timeout-private-diagnosis-full-refusal', 'result': 'passed'})
        first = Captured(work, 'B1', binary, account, epoch, PHASE0['uuid7']())
        owners.append(first)
        # B is already running before the administrator creates this registration.
        reg1, acq1 = registry.register('container-b', first, profile_hash, account.pw_uid)
        pending = registry.pending('container-b')
        assert registry.permits(pending)
        tool = work / 'command'
        cwd = work / 'destination-cwd'
        cwd.mkdir()
        (cwd / 'identity').write_text('host cwd\n')
        destination_tool = first.root / tool.relative_to('/')
        destination_tool.parent.mkdir(parents=True)
        # Distinct actual ELF bytes at an identical absolute pathname.
        command_source = REPO / 'scripts/namespace-phase1-5/command.c'
        for name, output in (('host', tool), ('B', destination_tool)):
            subprocess.run(['cc', '-static', '-O2', '-Wall', '-Wextra', '-Werror',
                            '-DDESTINATION=\"' + name + '\"', str(command_source), '-o', str(output)],
                           check=True, capture_output=True, timeout=30)
        destination_cwd = first.root / cwd.relative_to('/')
        destination_cwd.mkdir()
        (destination_cwd / 'identity').write_text('container B cwd\n')
        retained_root = Path('/proc') / str(acq1['pid']) / 'root'
        destination_bytes = (retained_root / tool.relative_to('/')).read_bytes()
        host_bytes = tool.read_bytes()
        assert destination_bytes != host_bytes
        assert (retained_root / cwd.relative_to('/') / 'identity').read_text() == 'container B cwd\n'
        assert 'phase15_service:x:12001:12001:' in (retained_root / 'etc/passwd').read_text()
        write(artifacts / 'registration.json', reg1)
        write(artifacts / 'acquisition.json', acq1)
        review = subprocess.run([str(args.binaries / 'sigrund-phase15-review'), authority,
                                str(artifacts / 'registration.json'), str(artifacts / 'acquisition.json'),
                                str(artifacts / 'constraints.json')], check=True, capture_output=True, timeout=10)
        write(artifacts / 'review.private.json', json.loads(review.stdout))
        manifest['fixture'] = {'owner_uid': account.pw_uid, 'daemon_epoch': epoch,
            'instance': acq1['instance_id'], 'setgroups': acq1['mappings'][0]['setgroups'], 'requested_account': 'phase15_service',
            'resolved_uid': 12001, 'resolved_gid': 12001, 'supplementary_gids': [],
            'executable_path': str(tool), 'host_executable_sha256': hashlib.sha256(host_bytes).hexdigest(),
            'destination_executable_sha256': hashlib.sha256(destination_bytes).hexdigest(),
            'cwd': str(cwd), 'destination_cwd_marker': 'container B cwd', 'launch_command': first.command}
        sample = json.loads((artifacts / 'review.private.json').read_bytes())
        sample['fixture_observed_files'] = {key: manifest['fixture'][key] for key in
            ('executable_path', 'host_executable_sha256', 'destination_executable_sha256', 'cwd', 'destination_cwd_marker')}
        (artifacts / 'review.private.json').write_bytes(canonical(sample))
        # Review rendering must close on evidence/profile substitution.
        for name, mutate in (
            ('revision', lambda r: r.update(revision=secrets.token_hex(32))),
            ('profile', lambda r: r.update(profile_sha256='f' * 64)),
            ('pid', lambda r: r.update(daemon_pid=r['daemon_pid'] + 1)),
        ):
            altered = copy.deepcopy(reg1)
            mutate(altered)
            path = artifacts / (name + '-substitution.json')
            write(path, altered)
            result = subprocess.run([str(args.binaries / 'sigrund-phase15-review'), authority, str(path),
                                     str(artifacts / 'acquisition.json'), str(artifacts / 'constraints.json')],
                                    capture_output=True, timeout=10)
            assert result.returncode != 0 and result.stdout == b''
        manifest['cases'].append({'name': 'live-capture-private-review-and-substitution', 'result': 'passed'})
        # A name change without a lifecycle signal leaves the original anchor live.
        second = Captured(work, 'B2', binary, account, epoch, PHASE0['uuid7']())
        owners.append(second)
        assert registry.permits(pending) and first.live() and second.live()
        registry.revoke('container-b')
        assert not registry.permits(pending) and first.live()
        reg2, acq2 = registry.register('container-b', second, profile_hash, account.pw_uid)
        assert reg2['revision'] != reg1['revision'] and acq2['instance_id'] != acq1['instance_id']
        assert not registry.permits(pending) and registry.permits(registry.pending('container-b'))
        write(artifacts / 'replacement-registration.json', reg2)
        write(artifacts / 'replacement-acquisition.json', acq2)
        manifest['cases'].append({'name': 'same-name-replacement-surviving-anchor-revoke-reregister', 'result': 'passed'})
        new_pending = registry.pending('container-b')
        second.kill_anchor()
        assert not registry.permits(new_pending) and not registry.permits(pending)
        third = Captured(work, 'B3', binary, account, epoch, PHASE0['uuid7']())
        owners.append(third)
        registry.revoke('container-b')
        reg3, acq3 = registry.register('container-b', third, profile_hash, account.pw_uid)
        assert reg3['revision'] != reg2['revision'] and acq3['instance_id'] != acq2['instance_id']
        assert not registry.permits(new_pending) and registry.permits(registry.pending('container-b'))
        write(artifacts / 'after-death-registration.json', reg3)
        write(artifacts / 'after-death-acquisition.json', acq3)
        manifest['cases'].append({'name': 'dead-anchor-invalidates-pending-review', 'result': 'passed'})
        for owner in owners:
            assert owner.close()['cleanup_complete']
        owners.clear()
        denied = Captured(work, 'denied', binary, account, epoch, PHASE0['uuid7'](), denied=True)
        owners.append(denied)
        diagnostic = (work / 'denied.capture.stderr').read_text()
        assert 'PTRACE_SEIZE' in diagnostic and 'Operation not permitted' in diagnostic, diagnostic
        denied.close()
        owners.clear()
        manifest['cases'].append({'name': 'attachment-without-host-ptrace-permission-denied', 'result': 'passed'})
        mixed = Captured(work, 'mixed-time-owner', binary, account, epoch, PHASE0['uuid7'](), shared_time=True)
        owners.append(mixed)
        diagnostic = (work / 'mixed-time-owner.capture.stderr').read_text()
        assert 'same(target->owner[i], target->ns[6])' in diagnostic, diagnostic
        mixed.close()
        owners.clear()
        manifest['cases'].append({'name': 'mixed-namespace-ownership-rejected', 'result': 'passed'})
        manifest['cases'].append({'name': 'retained-fds-closed-tracees-reaped-containers-exited', 'result': 'passed'})
        manifest['result'] = 'passed'
    except BaseException:
        manifest['result'] = 'failed'
        manifest['error'] = traceback.format_exc()
        raise
    finally:
        for owner in owners:
            try:
                owner.close()
            except BaseException:
                manifest['result'] = 'failed'
                manifest['cleanup_error'] = traceback.format_exc()
        # Preserve diagnostics before removing only this run's private fixture.
        for path in work.glob('*.stderr'):
            shutil.copyfile(path, artifacts / path.name)
        if manifest['result'] == 'passed':
            shutil.rmtree(work)
            manifest['fixture_paths_removed'] = not work.exists()
        write(artifacts / 'evidence.json', manifest)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--binaries', type=Path, required=True)
    parser.add_argument('--owner', required=True)
    parser.add_argument('--inside', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('run as root on a disposable systemd host')
    if not args.artifacts.is_absolute() or args.artifacts != args.artifacts.resolve():
        parser.error('--artifacts must be an absolute canonical path')
    trusted_directory(args.artifacts.parent)
    args.binaries = args.binaries.resolve(strict=True)
    if args.inside:
        trusted_directory(args.artifacts)
        run_inside(args)
        return
    args.artifacts.mkdir(mode=0o700, exist_ok=False)
    unit = 'sigrund-phase15-' + secrets.token_hex(8) + '.service'
    command = ['systemd-run', '--unit=' + unit, '--service-type=exec', '--wait', '--collect',
               '--property=Delegate=yes', '--property=KillMode=control-group', '--property=RuntimeMaxSec=180s',
               '--property=TimeoutStopSec=10s', '--property=MemoryMax=1G', '--property=TasksMax=128']
    if Path('/sys/fs/selinux/enforce').exists():
        label = Path('/proc/self/attr/current').read_text().strip('\0\n')
        command += ['--property=SELinuxContext=' + label]
    command += ['/usr/bin/python3', str(Path(__file__).resolve()), '--inside', '--artifacts', str(args.artifacts),
                '--binaries', str(args.binaries), '--owner', args.owner]
    try:
        subprocess.run(command, check=True, timeout=200)
    finally:
        PHASE0['stop_service_and_recover_policy'](unit, args.artifacts)
        journal = subprocess.run(['journalctl', '-u', unit, '--no-pager'], capture_output=True, timeout=10)
        with open(args.artifacts / 'supervisor.private.log', 'xb') as output:
            os.fchmod(output.fileno(), 0o600)
            output.write(journal.stdout)
    evidence = json.loads((args.artifacts / 'evidence.json').read_bytes())
    evidence['supervisor_stopped_and_empty'] = True
    (args.artifacts / 'evidence.json').write_bytes(canonical(evidence))
    print('Phase 1.5 fixture passed: ' + str(args.artifacts / 'evidence.json'))


if __name__ == '__main__':
    main()
