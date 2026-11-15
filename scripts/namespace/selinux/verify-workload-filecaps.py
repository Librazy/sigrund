#!/usr/bin/env python3
"""Verify root workload direct execution with authorized file capabilities.

Requires the workload examples for --owner, exactly one test signer, a TTY
approver identity and a native C compiler. Run as trusted root on a disposable
enforcing Fedora host, with the daemon drained and stopped. Temporarily adds a
direct root profile and native probe; restores config and leaves the daemon
stopped. No policy is loaded or changed.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tomllib

HERE = Path(__file__).resolve().parent


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')


def table(name, value):
    return '\n[[' + name + ']]\n' + ''.join(key + ' = ' + json.dumps(item) + '\n' for key, item in value.items())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--identity', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--owner', default='lab')
    args = parser.parse_args()
    if os.geteuid() != 0 or subprocess.check_output(['getenforce'], text=True).strip() != 'Enforcing':
        parser.error('trusted root on an enforcing disposable host required')
    if subprocess.run(['systemctl', 'is-active', '--quiet', 'sigrund.service']).returncode == 0:
        parser.error('drain jobs and stop sigrund.service first')
    args.artifacts.mkdir(mode=0o700)
    spec = importlib.util.spec_from_file_location('installed', HERE / 'verify-installed.py')
    api = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(api)
    paths = [Path('/etc/sigrund/config.toml'), Path('/etc/sigrund/signers.toml')]
    original = [path.read_bytes() for path in paths]
    config, signers = [tomllib.loads(data.decode()) for data in original]
    assert len(signers['signers']) == 1, 'exactly one disposable test signer required'
    root = next(p for p in config['host_profiles'] if p.get('workload') == 'root')
    old_digest = hashlib.sha256(canonical(root)).hexdigest()
    profile = dict(root, profile_id='host-root-filecaps-test', executable_model='digest_direct', verify_exec_stop=True)
    digest = hashlib.sha256(canonical(profile)).hexdigest()
    rule = next(r for r in config['host_rules'] if r['profile_sha256'] == old_digest)
    signer_rule = next(r for r in signers['signers'][0]['host_rules'] if r['profile_sha256'] == old_digest)
    probe = Path('/usr/bin/sigrund-workload-filecap-probe')
    assert not probe.exists(), 'refuse to replace an existing probe'
    result = {'passed': False, 'kernel': os.uname().release, 'cases': []}
    approver = process = None
    try:
        paths[0].write_bytes(original[0] + (table('host_profiles', profile)
                            + table('host_rules', dict(rule, profile_sha256=digest))).encode())
        paths[1].write_bytes(original[1] + table('signers.host_rules', dict(signer_rule, profile_sha256=digest)).encode())
        subprocess.run(['/usr/libexec/sigrund/sigrund', '--check-config'], check=True)
        native = args.artifacts / 'probe'
        subprocess.run(['cc', '-O2', '-Wall', '-Wextra', '-Werror', str(HERE / 'workload-filecap-probe.c'), '-o', str(native)], check=True)
        subprocess.run(['install', '-m755', str(native), str(probe)], check=True)
        subprocess.run(['restorecon', str(probe)], check=True)
        subprocess.run(['systemctl', 'start', 'sigrund.service'], check=True)
        approver = api.Approver(args.identity)
        for flags in [None, 'p', 'ep', 'eip']:
            case = {'file_capabilities': flags, 'passed': False}
            result['cases'].append(case)
            if flags is not None:
                subprocess.run(['setcap', 'cap_net_bind_service=' + flags, str(probe)], check=True)
            command = ['/usr/bin/sigrun', '--target', 'host', '--security-profile', profile['profile_id'],
                       '--target-uid', '0', '--target-gid', '0', '--cwd', '/']
            for cap in profile['capabilities']:
                command += ['--capability', cap]
            command += ['--', str(probe)]
            try:
                process = subprocess.Popen(api.requester(args.owner, 'sigrund-workload-filecaps', command),
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                review = approver.confirm(process, timeout=60)
                execution = api.execution_id(review)
                stdout, stderr = process.communicate(timeout=15)
                case.update(exec_id=execution, returncode=process.returncode, stdout=stdout.decode(errors='replace'),
                            stderr=stderr.decode(errors='replace'))
                assert process.returncode == 0, case
                rows = api.assert_execution(execution, namespace=False)
                ready = next(row for row in rows if row['event_type'] == 'EXEC_READY_TO_EXEC')
                all_caps = (1 << 41) - 1
                one_cap = 1 << 10  # CAP_NET_BIND_SERVICE
                expected = dict(bounding=all_caps, inheritable=all_caps, ambient=all_caps if flags is None else 0,
                                permitted=all_caps if flags is None else one_cap,
                                effective=all_caps if flags is None else one_cap if 'e' in flags else 0)
                observed = json.loads(stdout)
                assert observed['uid'] == 0 and observed['inode'] == probe.stat().st_ino, observed
                assert observed['context'] == 'system_u:system_r:sigrund_root_workload_t:s0', observed
                for key, bits in expected.items():
                    assert observed[key] == bits, (key, observed, expected)
                    assert len(ready['observed_post_exec_capabilities'][key]) == bits.bit_count(), ready
                assert ready['exec_outcome'] == 'exec_event_observed', ready
                case.update(passed=True, observed=observed, consumption_count=api.consumed(execution),
                            job_cgroup_removed=not api.job(execution).exists())
            except Exception as error:
                case['error'] = str(error)
            finally:
                subprocess.run(['systemctl', 'stop', 'sigrund-workload-filecaps.service'], capture_output=True)
                if process is not None and process.poll() is None:
                    process.kill()
                    process.communicate(timeout=5)
        result['passed'] = all(case['passed'] for case in result['cases'])
    finally:
        if approver is not None:
            (args.artifacts / 'approver.log').write_bytes(approver.transcript)
            approver.close()
        stopped = subprocess.run(['systemctl', 'stop', 'sigrund.service'])
        for path, data in zip(paths, original):
            path.write_bytes(data)
        probe.unlink(missing_ok=True)
        result['service_stopped'] = stopped.returncode == 0
        result['passed'] &= result['service_stopped']
        (args.artifacts / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
    if not result['passed']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
