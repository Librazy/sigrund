#!/usr/bin/env python3
"""Qualify equal names in independent real Podman endpoint/namespace scopes."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import time

HERE = Path(__file__).resolve().parent
BASE = Path('/var/lib/sigrund-podman-alt-engine')
RUNTIME = Path('/run/podman/sigrund-podman-alt-engine')
SERVICE = 'sigrund-podman-alt-api.service'
SOCKET = 'sigrund-podman-alt-api.socket'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifacts', type=Path, required=True)
    args = parser.parse_args()
    assert os.geteuid() == 0
    args.artifacts.mkdir(mode=0o700)
    BASE.mkdir(mode=0o700)
    RUNTIME.mkdir(mode=0o700)
    api = load('namespace_installed', HERE.parent / 'selinux/verify-installed.py')
    harness = load('podman_installed', HERE / 'verify-installed.py')
    prefix = ['podman', '--root', str(BASE / 'storage'), '--runroot', str(RUNTIME / 'runroot'), '--storage-driver', 'vfs']
    endpoint = RUNTIME / 'podman.sock'
    service_file = Path('/run/systemd/system') / SERVICE
    socket_file = Path('/run/systemd/system') / SOCKET
    assert not service_file.exists() and not socket_file.exists()
    command = '/usr/bin/' + ' '.join(prefix) + ' system service --time=0'
    def service(namespace=''):
        selected = command if not namespace else command.replace(' system service', ' --namespace ' + namespace + ' system service')
        service_file.write_text('[Unit]\nRequires=' + SOCKET + '\nAfter=' + SOCKET + '\n[Service]\nType=exec\nExecStart=' + selected + '\nKillMode=control-group\n')
        harness.run('systemctl', 'daemon-reload')
    def ctl(*parts):
        reply = subprocess.run([*prefix, *parts], timeout=15, capture_output=True)
        assert reply.returncode == 0, reply.stderr.decode()
        return reply
    def create(namespace=''):
        options = ['--namespace', namespace] if namespace else []
        return ctl(*options, 'run', '--detach', '--name', harness.NAME, '--rootfs', '--read-only',
                   '--network', 'none', '--security-opt', 'label=level:s0', '--volume', '/run/sigrund:/run/sigrund',
                   str(harness.ROOT), '/usr/bin/sleep', 'infinity')
    def reject_endpoint(label):
        subprocess.run(['sigrundctl', 'target', 'revoke', 'container-b', '--socket', api.SOCKET], capture_output=True, timeout=10)
        subprocess.run(['systemctl', 'stop', harness.UNIT], capture_output=True, timeout=10)
        time.sleep(.25)
        # The dedicated anchor is from main B; the equal-name object returned
        # by the alternate service is a different real manager generation.
        binding = json.loads(subprocess.check_output(['python3', str(HERE / 'register-podman.py'), '--launch-only'], timeout=15))
        command = ['sigrundctl', 'target', 'register-podman', 'container-b', '--pid', str(binding['anchor_pid']),
                   '--owner-uid', '0', '--security-profile', 'namespace-selinux-v1', '--socket', api.SOCKET,
                   '--podman-endpoint', str(endpoint), '--podman-owner-uid', '0', '--podman-namespace', 'default',
                   '--podman-container', harness.NAME]
        reply = subprocess.run(command, capture_output=True, timeout=12)
        assert reply.returncode != 0 and b'operation would block' not in reply.stderr, reply.stderr
        result['cases'].append({'name': label, 'passed': True, 'reply': reply.stderr.decode()})
        subprocess.run(['systemctl', 'stop', harness.UNIT], capture_output=True, timeout=10)
    socket_file.write_text('[Socket]\nListenStream=' + str(endpoint) + '\nSocketMode=0660\nDirectoryMode=0700\nService=' + SERVICE + '\n')
    result = {'passed': False, 'cases': []}
    approver = None
    try:
        approver = api.Approver(Path('/var/lib/sigrund-namespace-lab/approver'))
        harness.anchor(api)
        harness.run('chcon', '-t', 'container_var_lib_t', BASE)
        create()
        service()
        harness.run('chcon', 'system_u:object_r:container_var_run_t:s0', RUNTIME)
        harness.run('systemctl', 'start', SOCKET)
        harness.run('chcon', 'system_u:object_r:container_var_run_t:s0', RUNTIME, endpoint)
        main_id = harness.inspect()['Id']
        alternate = json.loads(ctl('inspect', harness.NAME).stdout)[0]
        assert alternate['Name'] == harness.NAME and alternate['Id'] != main_id
        # Journald events may include other local engines. Equal names must not
        # invalidate a retained binding whose full ID and endpoint are stable.
        harness.positive(api, approver, args.artifacts, result['cases'], label='other-engine-equal-name-preserves-main-binding')
        reject_endpoint('equal-name-wrong-endpoint-anchor-rejected')
        harness.ENDPOINT = str(endpoint)
        harness.anchor(api)
        original_inspect = harness.inspect
        harness.inspect = lambda name=harness.NAME: json.loads(ctl('inspect', name).stdout)[0]
        harness.positive(api, approver, args.artifacts, result['cases'], label='equal-name-correct-alternate-endpoint')
        harness.inspect = original_inspect
        # positive() checks the named metadata source; compare the exact
        # alternate generation rather than the default engine's equal name.
        assert result['cases'][-1]['manager']['container_id'] == alternate['Id']
        subprocess.run(['sigrundctl', 'target', 'revoke', 'container-b', '--socket', api.SOCKET], capture_output=True, timeout=10)
        subprocess.run(['systemctl', 'stop', harness.UNIT], capture_output=True, timeout=10)
        harness.run('systemctl', 'stop', SERVICE)
        # Podman 5.8.1 exposes --namespace but Libpod rejects it as unimplemented.
        # Record the native exclusion, then exercise our own scope rejection.
        unsupported = subprocess.run([*prefix, '--namespace', 'tenant-b', 'ps'], capture_output=True, timeout=15)
        assert unsupported.returncode != 0 and b'namespaces are not supported' in unsupported.stderr, unsupported.stderr
        result['cases'].append({'name': 'native-libpod-namespace-unavailable', 'passed': True,
                                'disposition': 'unsupported', 'reply': unsupported.stderr.decode()})
        binding = json.loads(subprocess.check_output(['python3', str(HERE / 'register-podman.py'), '--launch-only'], timeout=15))
        for owner, namespace, label in (('0', 'tenant-b', 'nondefault-manager-namespace-rejected'),
                                         ('1200', 'default', 'nonroot-manager-owner-rejected')):
            reply = subprocess.run(['sigrundctl', 'target', 'register-podman', 'container-b',
                '--pid', str(binding['anchor_pid']), '--owner-uid', '0',
                '--security-profile', 'namespace-selinux-v1', '--socket', api.SOCKET,
                '--podman-endpoint', str(endpoint), '--podman-owner-uid', owner,
                '--podman-namespace', namespace, '--podman-container', harness.NAME], capture_output=True, timeout=12)
            assert reply.returncode != 0 and b'unsupported Podman selector scope' in reply.stderr, reply.stderr
            result['cases'].append({'name': label, 'passed': True, 'reply': reply.stderr.decode()})
        result['passed'] = True
    finally:
        subprocess.run(['sigrundctl', 'target', 'revoke', 'container-b', '--socket', api.SOCKET], capture_output=True, timeout=10)
        subprocess.run(['systemctl', 'stop', harness.UNIT, SERVICE, SOCKET], capture_output=True, timeout=15)
        for namespace in ('', 'tenant-b'):
            options = ['--namespace', namespace] if namespace else []
            subprocess.run([*prefix, *options, 'rm', '-f', '-t0', harness.NAME], capture_output=True, timeout=15)
        for path in (service_file, socket_file):
            path.unlink(missing_ok=True)
        subprocess.run(['systemctl', 'daemon-reload'], check=True, timeout=15)
        if approver:
            (args.artifacts / 'approver.log').write_bytes(approver.transcript)
            approver.close()
        (args.artifacts / 'result.json').write_text(json.dumps(result, indent=2) + '\n')


if __name__ == '__main__':
    main()
