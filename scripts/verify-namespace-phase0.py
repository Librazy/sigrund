#!/usr/bin/env python3
"""Reproducible Phase 0 experiments on a disposable x86-64 systemd/SELinux host.

Run as root. Results qualify individual prototypes only, never production v3.
The outer systemd service owns every descendant even if a probe/runner dies.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import secrets
import select
import shutil
import stat
import subprocess
import sys
import time
import traceback
import uuid

REPO = Path(__file__).resolve().parent.parent
SOURCES = REPO / 'scripts/namespace-phase0'


def uuid7():
    return str(uuid.UUID(int=(int(time.time() * 1000) << 80) | (7 << 76)
                         | (secrets.randbits(12) << 64) | (2 << 62) | secrets.randbits(62)))


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command, **kwargs):
    # SELinux module transactions rebuild the host policy and can be slow on
    # shared storage. The enclosing service still has a hard overall deadline.
    return subprocess.run([str(v) for v in command], check=True, timeout=120, **kwargs)


def current_cgroup():
    line, = Path('/proc/self/cgroup').read_text().splitlines()
    if not line.startswith('0::/') or '..' in Path(line[3:]).parts:
        raise RuntimeError('requires a real host with a host-visible unified cgroup hierarchy')
    return Path('/sys/fs/cgroup') / line[4:]


def prepare_cgroups():
    base = current_cgroup()
    if not base.name.startswith('sigrund-phase0-') or not base.name.endswith('.service'):
        raise RuntimeError('internal runner must run in its dedicated delegated service')
    control, jobs = base / 'control', base / 'jobs'
    control.mkdir()
    (control / 'cgroup.procs').write_text(str(os.getpid()))
    (base / 'cgroup.subtree_control').write_text('+memory +pids')
    jobs.mkdir()
    (jobs / 'cgroup.subtree_control').write_text('+memory +pids')
    return jobs


def job_group(jobs, name):
    group = jobs / name
    group.mkdir()
    for file, value in [('memory.max', '268435456'), ('memory.swap.max', '0'), ('pids.max', '32')]:
        (group / file).write_text(value)
    return group


def cleanup_group(group):
    (group / 'cgroup.kill').write_text('1')
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if 'populated 0' in (group / 'cgroup.events').read_text():
            group.rmdir()
            return
        time.sleep(0.02)
    raise RuntimeError('job remains populated after kill; reservation cannot be released')


def build(artifacts):
    probe, workload = artifacts / 'probe', artifacts / 'workload'
    flags = ['cc', '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror', '-pthread']
    run(flags + [SOURCES / 'probe.c', '-o', probe], capture_output=True)
    run(flags + ['-nostdlib', '-static', '-fno-stack-protector', '-fno-builtin', '-fno-pie', '-no-pie',
                 SOURCES / 'workload.c', '-o', workload], capture_output=True)
    return probe, workload


def reload_policy():
    # Reload exactly the installed policy, keeping the policy store coherent.
    # This triggers the kernel policyload token without rebuilding the module
    # store while a tracee is held at the bounded exec-stop barrier.
    policy = Path('/sys/fs/selinux/policy').read_bytes()
    with open('/sys/fs/selinux/load', 'wb', buffering=0) as output:
        if output.write(policy) != len(policy):
            raise RuntimeError('short SELinux policy reload')


def remove_owned_permissive(artifacts):
    marker = artifacts / 'domain-permissive-owned'
    if marker.exists():
        # The intent marker precedes semanage: interruption may occur before,
        # during or after the transaction. Deletion must therefore be idempotent.
        domains = run(['semanage', 'permissive', '-l'], capture_output=True, text=True).stdout.split()
        if 'sigrund_phase0_t' in domains:
            run(['semanage', 'permissive', '-d', 'sigrund_phase0_t'], capture_output=True)
        marker.unlink()


def recover_policy(artifacts):
    marker = artifacts / 'policy-owned'
    if marker.exists():
        run(['setenforce', '1'], capture_output=True)
        # A global enforcing state does not override a permissive domain. Its
        # generated module also references our test type and must be removed first.
        remove_owned_permissive(artifacts)
        run(['restorecon', '-RF', artifacts], capture_output=True)
        modules = run(['semodule', '-l'], capture_output=True, text=True).stdout
        if any(line.split()[0] == 'sigrund_phase0' for line in modules.splitlines() if line.split()):
            run(['semodule', '-r', 'sigrund_phase0'], capture_output=True)
        marker.unlink()


def stop_service_and_recover_policy(unit, artifacts, stop_timeout=30):
    outcome = {'stop_timed_out': False, 'forced_kill': False}
    if unit:
        try:
            subprocess.run(['systemctl', 'stop', unit], check=True, capture_output=True, timeout=stop_timeout)
        except (subprocess.SubprocessError, OSError) as error:
            outcome['stop_timed_out'] = isinstance(error, subprocess.TimeoutExpired)
            outcome['forced_kill'] = True
            print(f'{unit}: stop failed ({error}); killing all service processes', file=sys.stderr)
            try:
                subprocess.run(['systemctl', 'kill', '--kill-whom=all', '--signal=SIGKILL', unit],
                               check=True, capture_output=True, timeout=10)
            except (subprocess.SubprocessError, OSError) as kill_error:
                # A collected/already empty unit can make kill fail. Verify the
                # actual state below instead of letting this bypass recovery.
                print(f'{unit}: kill failed ({kill_error}); checking service state', file=sys.stderr)
        deadline = time.monotonic() + 30
        while True:
            status = subprocess.run(['systemctl', 'show', unit, '--property=LoadState',
                                     '--property=ActiveState', '--property=ControlGroup'],
                                    capture_output=True, text=True, timeout=10)
            properties = dict(line.split('=', 1) for line in status.stdout.splitlines() if '=' in line)
            if status.returncode and properties.get('LoadState') != 'not-found':
                raise RuntimeError(f'cannot verify {unit} stopped; policy recovery markers retained')
            group = properties.get('ControlGroup')
            empty = group == ''
            if group:
                if not group.startswith('/') or group == '/' or '..' in Path(group).parts:
                    raise RuntimeError('unsafe service cgroup path; policy recovery markers retained')
                try:
                    events = (Path('/sys/fs/cgroup') / group[1:] / 'cgroup.events').read_text()
                    empty = 'populated 0' in events.splitlines()
                except FileNotFoundError:
                    empty = True
            if properties.get('ActiveState') in {'inactive', 'failed'} and empty:
                break
            if time.monotonic() >= deadline:
                raise RuntimeError(f'{unit} still active or populated; policy recovery markers retained')
            time.sleep(0.05)
    # Never race cleanup against a surviving semanage/semodule transaction.
    # A stop-client timeout alone must not prevent this run's policy recovery.
    recover_policy(artifacts)
    return outcome


def validate_result(value):
    if not isinstance(value, dict) or value.get('result') != 'passed' or not isinstance(value.get('case'), str):
        raise ValueError('probe did not provide a passing structured observation')
    return value


def inside(artifacts):
    descriptor = os.open('/run/sigrund-phase0.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600:
            raise RuntimeError('unsafe Phase 0 host lock')
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return run_inside(artifacts)
    finally:
        os.close(descriptor)


def validate_manifest(manifest, required):
    cases = manifest.get('cases', [])
    names = [case['name'] for case in cases]
    return (len(names) == len(required) and set(names) == set(required)
            and all(case.get('result') == 'passed' for case in cases))


def run_inside(artifacts):
    audit_start = int(time.time())
    manifest = {
        'schema': 'sigrund.phase0-evidence.v1', 'result': 'incomplete',
        'kernel': platform.release(), 'architecture': platform.machine(),
        'os_release': Path('/etc/os-release').read_text(),
        'source_sha256': {p.name: digest(p) for p in sorted(SOURCES.iterdir()) if p.is_file()},
        'runner_sha256': digest(Path(__file__)), 'cases': [],
        'qualification': 'isolated prototypes; no integrated v3 support',
    }

    def save():
        temporary = artifacts / 'evidence.json.tmp'
        temporary.write_text(json.dumps(manifest, indent=2) + '\n')
        temporary.replace(artifacts / 'evidence.json')

    save()
    epoch = uuid7()
    manifest['daemon_epoch'] = epoch
    if platform.machine() != 'x86_64':
        raise RuntimeError('Phase 0 native helper is qualified only for x86-64')
    jobs = prepare_cgroups()
    probe, workload = build(artifacts)
    manifest['compiler'] = run(['cc', '--version'], capture_output=True, text=True).stdout.splitlines()[0]
    manifest['binaries'] = {p.name: digest(p) for p in [probe, workload]}
    manifest['delegation'] = {name: (jobs / name).read_text() for name in ['cgroup.controllers', 'cgroup.subtree_control']}
    manifest['supervisor_context'] = Path('/proc/self/attr/current').read_text().rstrip('\0\n')
    manifest['lsm'] = Path('/sys/kernel/security/lsm').read_text().strip()

    def case(name, command, extra_env=None, reload_at_stop=False, required_observation=None):
        entry = {'name': name, 'command': [str(v) for v in command], 'result': 'failed'}
        manifest['cases'].append(entry)
        try:
            environment = dict(os.environ, PHASE0_DAEMON_EPOCH=epoch, PHASE0_TARGET_INSTANCE=uuid7())
            # No inherited experimental execution settings may alter a fixture.
            environment.pop('PHASE0_EXEC_CONTEXT', None)
            environment.pop('PHASE0_MEMFD', None)
            environment.pop('PHASE0_POLICY_CASE', None)
            environment.update(extra_env or {})
            ready = b''
            if reload_at_stop:
                with subprocess.Popen([str(v) for v in command], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE, env=environment) as child:
                    try:
                        if not select.select([child.stdout], [], [], 10)[0]:
                            raise RuntimeError('probe did not reach exec-stop reload barrier')
                        ready = child.stdout.readline()
                        if json.loads(ready) != {'ready': 'policy-reload-at-exec-stop'}:
                            raise RuntimeError('invalid reload barrier')
                        reload_policy()
                        output, error = child.communicate(b'R', timeout=30)
                        completed = subprocess.CompletedProcess(command, child.returncode, output, error)
                    finally:
                        if child.poll() is None:
                            child.kill()
                            child.communicate(timeout=10)
            else:
                completed = subprocess.run([str(v) for v in command], capture_output=True, timeout=40, env=environment)
            (artifacts / (name + '.stdout')).write_bytes(ready + completed.stdout)
            (artifacts / (name + '.stderr')).write_bytes(completed.stderr)
            entry['exit'] = completed.returncode
            if completed.returncode:
                raise RuntimeError(f'{name} exited {completed.returncode}; see {name}.stderr')
            entry['observations'] = validate_result(json.loads(completed.stdout))
            if required_observation and entry['observations'].get(required_observation) is not True:
                raise RuntimeError('missing required observation: ' + required_observation)
            if 'observed_target' in entry['observations']:
                record = entry['observations']['observed_target']
                canonical = json.dumps(record, sort_keys=True, separators=(',', ':')).encode()
                (artifacts / (name + '.acquisition.json')).write_bytes(canonical)
                entry['acquisition_sha256'] = hashlib.sha256(canonical).hexdigest()
            entry['result'] = 'passed'
        except Exception as error:
            entry['error'] = str(error)
        finally:
            save()

    case('peer', [probe, 'peer', artifacts / 'peer.sock'])
    for exhaust in [0, 1]:
        name = 'pids-exhaustion' if exhaust else 'launcher-death'
        group = job_group(jobs, name)
        if exhaust:
            (group / 'pids.max').write_text('8')
        try:
            case(name, [probe, 'lifecycle', group, exhaust])
        finally:
            cleanup_group(group)
    group = job_group(jobs, 'tracer-death')
    try:
        case('tracer-death', [probe, 'tracer-death', group])
    finally:
        cleanup_group(group)
    combinations = [(r, 0, f) for r in [0, 1] for f in range(10)]
    combinations += [(r, rejected, 0) for r in [0, 1] for rejected in range(1, 6)]
    for rootless, filtered, fault in combinations:
        name = f'namespace-r{rootless}-filtered{filtered}-fault{fault}'
        root = artifacts / name
        for directory in [root, root / 'proc', root / 'run', root / 'alternate']:
            directory.mkdir(mode=0o755)
        (root / 'marker').write_text(name + '\n')
        group = job_group(jobs, name)
        try:
            case(name, [probe, 'namespace', root, root / 'run/client.sock', group, workload, rootless, filtered, fault])
        finally:
            try:
                cleanup_group(group)
            except Exception as error:
                manifest['cases'][-1]['cleanup_error'] = str(error)
                manifest['cases'][-1]['result'] = 'failed'
                save()

    for rootless in [0, 1]:
        for route in range(4):
            name = f'route-r{rootless}-{route}'
            roots = [artifacts / (name + '-' + letter) for letter in ['A', 'B']]
            for root in roots:
                for directory in [root, root / 'proc', root / 'run']:
                    directory.mkdir(mode=0o755)
                (root / 'marker').write_text(root.name + '\n')
            group = job_group(jobs, name)
            try:
                case(name, [probe, 'route', *roots, group, workload, rootless, route])
            finally:
                cleanup_group(group)

    module = artifacts / 'policy'
    module.mkdir()
    shutil.copyfile(SOURCES / 'sigrund_phase0.te', module / 'sigrund_phase0.te')
    policy_installed = False
    try:
        run(['make', '-f', '/usr/share/selinux/devel/Makefile', 'sigrund_phase0.pp'], cwd=module, capture_output=True)
        # Refuse to replace a policy not owned by this run.
        modules = run(['semodule', '-l'], capture_output=True, text=True).stdout
        if any(line.split()[0] == 'sigrund_phase0' for line in modules.splitlines() if line.split()):
            raise RuntimeError('sigrund_phase0 policy already installed; refusing to replace it')
        (artifacts / 'policy-owned').write_text('sigrund_phase0\n')
        run(['semodule', '-i', module / 'sigrund_phase0.pp'], capture_output=True)
        policy_installed = True
        run(['chcon', '-t', 'sigrund_phase0_supervisor_exec_t', probe], capture_output=True)
        run(['chcon', '-t', 'sigrund_phase0_exec_t', workload], capture_output=True)
        secret = artifacts / 'secret'
        secret.write_text('must never be read by workload\n')
        secret.chmod(0o644)
        run(['chcon', '-t', 'sigrund_phase0_secret_t', secret], capture_output=True)
        source_context = Path('/proc/self/attr/current').read_text().rstrip('\0\n').split(':', 3)
        context = ':'.join([source_context[0], source_context[1], 'sigrund_phase0_t', 's0:c1,c2'])
        supervisor_context = ':'.join([source_context[0], source_context[1], 'sigrund_phase0_supervisor_t', source_context[3]])
        def lsm_command(mode):
            return ['runcon', supervisor_context, probe, 'selinux', workload, secret, context, mode]
        manifest['selinux_context'] = context
        for model in ['direct', 'memfd']:
            case('selinux-' + model, lsm_command(int(model == 'memfd')))
            if manifest['cases'][-1]['result'] == 'passed' and manifest['cases'][-1]['observations']['supervisor_label'] != supervisor_context:
                manifest['cases'][-1]['result'] = 'failed'
        def namespace_lsm_case(rootless, model, policy_case=None):
            name = f'selinux-namespace-r{rootless}-{model}' + ('-' + policy_case if policy_case else '')
            root = artifacts / name
            for directory in [root, root / 'proc', root / 'run']:
                directory.mkdir(mode=0o755)
            shutil.copyfile(secret, root / 'secret')
            (root / 'secret').chmod(0o644)
            run(['chcon', '-t', 'sigrund_phase0_secret_t', root / 'secret'], capture_output=True)
            environment = {'PHASE0_EXEC_CONTEXT': context, 'PHASE0_MEMFD': str(int(model == 'memfd'))}
            if policy_case:
                environment['PHASE0_POLICY_CASE'] = policy_case
            group = job_group(jobs, name)
            try:
                case(name, ['runcon', supervisor_context, probe, 'namespace', root, root / 'run/client.sock', group, workload, rootless, 0, 0],
                     environment, reload_at_stop=policy_case == 'reload',
                     required_observation=('policy_rejected_at_exec_stop' if policy_case == 'reload'
                                           else 'policy_rejected_before_spawn' if policy_case else 'private_mount_verified'))
            finally:
                cleanup_group(group)
        for rootless in [0, 1]:
            for model in ['direct', 'memfd']:
                namespace_lsm_case(rootless, model)
                namespace_lsm_case(rootless, model, 'reload')
        manifest['selinux_policy_sha256'] = digest(Path('/sys/fs/selinux/policy'))
        case('selinux-context-mismatch', lsm_command(2), required_observation='context_rejected_at_exec_stop')
        case('selinux-reload-at-exec-stop', lsm_command(3), reload_at_stop=True,
             required_observation='rejected_at_exec_stop')
        try:
            (artifacts / 'domain-permissive-owned').write_text('sigrund_phase0_t\n')
            run(['semanage', 'permissive', '-a', 'sigrund_phase0_t'], capture_output=True)
            case('selinux-domain-permissive', lsm_command(4))
            for rootless in [0, 1]:
                namespace_lsm_case(rootless, 'direct', 'domain-permissive')
        finally:
            remove_owned_permissive(artifacts)
        try:
            run(['setenforce', '0'], capture_output=True)
            case('selinux-global-permissive', lsm_command(5))
            for rootless in [0, 1]:
                namespace_lsm_case(rootless, 'direct', 'global-permissive')
        finally:
            run(['setenforce', '1'], capture_output=True)
        before = json.loads(run([probe, 'selinux-status'], capture_output=True).stdout)
        reload_policy()
        after = json.loads(run([probe, 'selinux-status'], capture_output=True).stdout)
        changed = before['policyload'] != after['policyload'] and before['sequence'] != after['sequence']
        manifest['cases'].append({'name': 'selinux-policy-reload', 'result': 'passed' if changed else 'failed', 'before': before, 'after': after})
        run(['journalctl', '--sync'], capture_output=True)
        audit = run(['journalctl', '--since=@' + str(audit_start), '--no-pager', '-o', 'cat'], capture_output=True, text=True).stdout
        denials = '\n'.join(line for line in audit.splitlines() if 'sigrund_phase0_t' in line and 'sigrund_phase0_secret_t' in line)
        (artifacts / 'selinux-denials.log').write_text(denials + '\n')
        positive_lsm = ['selinux-direct', 'selinux-memfd'] + [f'selinux-namespace-r{r}-{m}' for r in [0, 1] for m in ['direct', 'memfd']]
        expected = {c['observations']['workload_pid'] for c in manifest['cases']
                    if c['name'] in positive_lsm
                    if c['result'] == 'passed'}
        observed = {int(match.group(1)) for line in denials.splitlines()
                    if 'denied' in line and 'tclass=file' in line and 'permissive=0' in line
                    if (match := re.search(r'\bpid=(\d+)\b', line))}
        manifest['cases'].append({'name': 'selinux-secret-avc', 'result': 'passed' if len(expected) == 6 and expected <= observed else 'failed',
                                  'expected_pids': sorted(expected), 'observed_pids': sorted(observed)})
    except Exception:
        manifest['cases'].append({'name': 'selinux-policy', 'result': 'failed', 'error': traceback.format_exc()})
    finally:
        if policy_installed:
            try:
                recover_policy(artifacts)
            except Exception:
                manifest['cases'].append({'name': 'policy-cleanup', 'result': 'failed', 'error': traceback.format_exc()})
        save()

    required = json.loads((SOURCES / 'required-cases.json').read_bytes())
    unchanged = manifest['source_sha256'] == {p.name: digest(p) for p in sorted(SOURCES.iterdir()) if p.is_file()}
    unchanged = unchanged and manifest['runner_sha256'] == digest(Path(__file__))
    manifest['source_unchanged'] = unchanged
    manifest['result'] = 'passed' if unchanged and validate_manifest(manifest, required) else 'failed'
    save()
    return 0 if manifest['result'] == 'passed' else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifacts', required=True, type=Path)
    parser.add_argument('--disposable-host', action='store_true', help='acknowledge this host is disposable; installs/removes a test SELinux module')
    parser.add_argument('--inside-service', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('run as root on a disposable host')
    if not args.disposable_host:
        parser.error('--disposable-host is required')
    artifacts = args.artifacts
    if not artifacts.is_absolute() or artifacts != artifacts.resolve():
        parser.error('--artifacts must be an absolute canonical path')
    if args.inside_service:
        return inside(artifacts)
    if run(['getenforce'], capture_output=True, text=True).stdout.strip() != 'Enforcing':
        parser.error('start with SELinux enforcing; initial state will be restored after negative cases')
    artifacts.mkdir(mode=0o755, parents=False, exist_ok=False)
    unit = 'sigrund-phase0-' + uuid.uuid4().hex
    command = ['systemd-run', '--unit=' + unit, '--service-type=exec', '--wait', '--collect',
               '--property=Delegate=yes', '--property=KillMode=control-group', '--property=RuntimeMaxSec=600',
               '--property=TimeoutStopSec=10', '--property=UMask=0022',
               '--property=SELinuxContext=' + Path('/proc/self/attr/current').read_text().rstrip('\0\n'),
               sys.executable, Path(__file__).resolve(), '--inside-service', '--disposable-host', '--artifacts', artifacts]
    try:
        return subprocess.run([str(v) for v in command], timeout=630).returncode
    finally:
        # Recover host policy even if the service deadline killed Python during
        # a negative enforcement test. Only clean this run's own transaction.
        stop_service_and_recover_policy(unit + '.service', artifacts)
        subprocess.run(['journalctl', '-u', unit + '.service', '--no-pager', '-n', '40'], timeout=30)


if __name__ == '__main__':
    sys.exit(main())
