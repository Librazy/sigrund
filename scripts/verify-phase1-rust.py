#!/usr/bin/env python3
"""Run the initial-userns root Rust gates under an external lifetime supervisor."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys

DAEMON_GATES = [
    'authorization::exit_gate',
    'approver::exit_gate',
    'daemon_gate_in_user_namespace',
    'startup::stale_audit_temporary_gate',
    'startup::v3_provisioning_set_gate',
    'storage::exit_gate',
    'v3::confidentiality_gate',
]
LIBRARY_GATES = ['preparation::tests::final_authorization_rechecks_retained_policy_and_identity',
                 'host_registry::tests::epoch_registry_requires_live_owner_and_exact_private_review']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--daemon-tests', type=Path, required=True)
    parser.add_argument('--library-tests', type=Path, required=True)
    parser.add_argument('--client-tests', type=Path, help='initial-userns client relay gates')
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--gate', action='append', choices=DAEMON_GATES + LIBRARY_GATES + ['client_host_fixture'], help='run selected gates for a targeted retry; default runs all')
    args = parser.parse_args()
    if os.geteuid() != 0 or Path('/proc/self/uid_map').read_text().split() != ['0', '0', '4294967295']:
        parser.error('root in the initial user namespace is required')
    if any(not path.is_absolute() for path in (args.daemon_tests, args.library_tests, args.artifacts)):
        parser.error('all paths must be absolute')
    if args.client_tests is not None and not args.client_tests.is_absolute():
        parser.error('client test path must be absolute')
    os.umask(0o077)
    args.artifacts.mkdir(parents=True, exist_ok=False)
    manifest = {'suite': 'phase1-privileged-rust', 'result': 'incomplete',
                'kernel': platform.release(), 'machine': platform.machine(), 'command': sys.argv,
                'uid_map': Path('/proc/self/uid_map').read_text(), 'gid_map': Path('/proc/self/gid_map').read_text(),
                'binaries': {}, 'gates': []}
    def save():
        (args.artifacts / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    save()
    try:
        groups = [(args.daemon_tests, DAEMON_GATES), (args.library_tests, LIBRARY_GATES)]
        if args.client_tests is not None:
            groups.append((args.client_tests, ['client_host_fixture']))
        elif args.gate and 'client_host_fixture' in args.gate:
            raise ValueError('--client-tests is required for client_host_fixture')
        for binary, names in groups:
            manifest['binaries'][str(binary)] = hashlib.sha256(binary.read_bytes()).hexdigest()
            for name in names:
                if args.gate is not None and name not in args.gate:
                    continue
                command = [str(binary), '--exact', name, '--ignored', '--nocapture', '--test-threads=1']
                log = args.artifacts / (name.replace('::', '-') + '.log')
                record = {'gate': name, 'command': command, 'log': log.name, 'result': 'incomplete'}
                manifest['gates'].append(record)
                save()
                with log.open('wb') as output:
                    result = subprocess.run(command, stdout=output, stderr=subprocess.STDOUT, timeout=300)
                record['exit_code'] = result.returncode
                record['result'] = 'passed' if result.returncode == 0 and b'test result: ok. 1 passed;' in log.read_bytes() else 'failed'
                save()
                print(json.dumps(record), flush=True)
                if record['result'] != 'passed':
                    raise RuntimeError('privileged Rust gate failed: ' + name + '; inspect ' + str(log))
        manifest['result'] = 'passed'
    except BaseException:
        manifest['result'] = 'failed'
        raise
    finally:
        save()


if __name__ == '__main__':
    main()
