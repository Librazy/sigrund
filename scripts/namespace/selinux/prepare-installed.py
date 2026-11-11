#!/usr/bin/env python3
"""Provision the installed SELinux namespace deployment on a fresh disposable Fedora host.

This deliberately uses the packaged service paths. Existing or partial config,
state or logs are refused. Installation never invokes this script automatically.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import pwd
import shutil
import subprocess

ROOT = Path('/var/lib/sigrund-namespace-lab')
CONFIG = Path('/etc/sigrund')
DOCS = Path('/usr/share/doc/sigrund')


def run(*args, **kwargs):
    return subprocess.run(list(map(str, args)), check=True, **kwargs)


def write(path, text, mode=0o600):
    with path.open('x') as output:
        os.fchmod(output.fileno(), mode)
        output.write(text)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state-dir', type=Path, required=True)
    parser.add_argument('--log-path', type=Path, required=True)
    parser.add_argument('--requester', default='nsrequester')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('root required on a fresh disposable Fedora host')
    if args.state_dir != Path('/var/lib/sigrund-v3') or args.log_path != Path('/var/log/sigrund-v3/audit.jsonl'):
        parser.error('paths must match the installed sigrund.service provisioning set')
    if subprocess.check_output(['getenforce'], text=True).strip() != 'Enforcing':
        parser.error('enforcing SELinux is required')
    if any(path.exists() for path in (ROOT, CONFIG / 'config.toml', CONFIG / 'signers.toml', args.state_dir, args.log_path.parent)):
        parser.error('refusing an existing or partial installed provisioning set')
    account = pwd.getpwnam(args.requester)
    if account.pw_uid == 0 or account.pw_gid == 0 or account.pw_shell not in ('/sbin/nologin', '/usr/sbin/nologin'):
        parser.error('the requester must be a locked nonroot account with a nologin shell')
    for name in ('sigrun', 'sigrund'):
        run('rpm', '-q', name)
    os.umask(0o077)
    ROOT.mkdir(mode=0o700)
    write(ROOT / 'status.json', json.dumps({'stage': 'preparing', 'requester_uid': account.pw_uid}) + '\n')
    policy = ROOT / 'policy'
    shutil.copytree(DOCS / 'selinux', policy)
    run('make', '-C', policy)
    run('semodule', '-i', policy / 'sigrund_daemon.pp', policy / 'sigrund_workload.pp', policy / 'sigrund_requester.pp')
    run('ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', ROOT / 'approver')
    key = (ROOT / 'approver.pub').read_text().strip()
    roots = '["/usr/bin", "/usr/local/libexec/sigrund-namespace"]'
    config = (DOCS / 'examples/sigrund.toml.example').read_text()
    for old, new in (
        ('["/usr/bin", "/usr/sbin"]', roots),
        ('<strict-padded-base64-32-byte-ed25519-key>', base64.b64encode(bytes(32)).decode()),
        ('requester_uids = [1001]', f'requester_uids = [{account.pw_uid}]'),
        ('target_uids = [0, 33]', 'target_uids = [0, 65534]'),
        ('target_gids = [0, 33]', 'target_gids = [0, 65534]'),
        ('authorization_timeout_ms = 120000', 'authorization_timeout_ms = 5000'),
    ):
        config = config.replace(old, new)
    config += '\n[mvp]\napproval_signer_id = "namespace-root"\n'
    config += (DOCS / 'examples/namespace-selinux-profiles.toml.example').read_text().replace(
        'requester_uids = [1000]', f'requester_uids = [{account.pw_uid}]')
    signers = (DOCS / 'examples/signers.toml.example').read_text()
    for old, new in (
        ('mandator-alice-yubikey', 'namespace-root'),
        ('type = "sk-ssh-ed25519"', 'type = "ssh-ed25519"'),
        ('sk-ssh-ed25519@openssh.com AAAA...', key),
        ('require_user_presence = true', 'require_user_presence = false'),
        ('allowed_requester_uids = [1001]', f'allowed_requester_uids = [{account.pw_uid}]'),
        ('requester_uids = [1001]', f'requester_uids = [{account.pw_uid}]'),
        ('allowed_target_uids = [0, 33]', 'allowed_target_uids = [0, 65534]'),
        ('allowed_target_gids = [0, 33]', 'allowed_target_gids = [0, 65534]'),
        ('target_uids = [0, 33]', 'target_uids = [0, 65534]'),
        ('target_gids = [0, 33]', 'target_gids = [0, 65534]'),
        ('allowed_modes = ["one_time", "time_range"]', 'allowed_modes = ["one_time"]'),
        ('["/usr/bin", "/usr/sbin"]', roots),
    ):
        signers = signers.replace(old, new)
    signers += (DOCS / 'examples/namespace-selinux-signers.toml.example').read_text().replace(
        'requester_uids = [1000]', f'requester_uids = [{account.pw_uid}]')
    write(CONFIG / 'config.toml', config)
    write(CONFIG / 'signers.toml', signers)
    for name in ('collector-ca.pem', 'collector-client.crt', 'collector-client.key'):
        write(CONFIG / name, 'INACTIVE local-audit candidate; not TLS credentials\n')
    Path('/usr/local/libexec/sigrund-namespace').mkdir(mode=0o755)
    Path('/usr/local/libexec/sigrund-namespace').chmod(0o755)
    run('/usr/libexec/sigrund/sigrund', '--check-config', '--config', CONFIG / 'config.toml', '--signers', CONFIG / 'signers.toml')
    with (ROOT / 'provisioning.private.json').open('xb') as output:
        os.fchmod(output.fileno(), 0o600)
        run('sigrundctl', 'init-host', '--state-dir', args.state_dir, '--log-path', args.log_path, stdout=output)
    run('restorecon', '-RF', CONFIG, args.state_dir, args.log_path.parent, '/usr/libexec/sigrund/sigrund')
    record = {'stage': 'provisioned', 'requester_uid': account.pw_uid, 'requester_gid': account.pw_gid,
              'state_dir': str(args.state_dir), 'log_path': str(args.log_path),
              'policy_sha256': {name: hashlib.sha256((policy / name).read_bytes()).hexdigest()
                                for name in ('sigrund_daemon.pp', 'sigrund_workload.pp', 'sigrund_requester.pp')}}
    temporary = ROOT / 'status.new'
    write(temporary, json.dumps(record, indent=2) + '\n')
    temporary.replace(ROOT / 'status.json')
    print('Fresh installed candidate provisioned. Start explicitly with systemctl start sigrund.service.')


if __name__ == '__main__':
    main()
