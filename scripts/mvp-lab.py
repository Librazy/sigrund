#!/usr/bin/python3
"""Prepare an isolated manual MVP lab; never installs over production paths.

Run prepare/start/stop as root on a disposable systemd host. prepare prints a
shell environment shared by the root operator and a separate requester login.
stop preserves keys, host identity, audit history and consumed grants.
"""
import argparse
import base64
import json
import os
from pathlib import Path
import pwd
import re
import runpy
import shlex
import shutil
import stat
import subprocess
import sys
import uuid

REPO = Path(__file__).resolve().parent.parent
SHARED = runpy.run_path(str(Path(__file__).with_name('verify-phase5-runtime.py')))


def trusted(path):
    if not path.is_absolute() or str(path) != os.path.normpath(path) or not re.fullmatch(r'/[A-Za-z0-9_./-]+', str(path)):
        raise ValueError('lab paths must be absolute canonical paths using letters, digits, _, ., / and -')
    for part in reversed((path, *path.parents)):
        info = part.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 or info.st_mode & 0o022:
            raise ValueError('lab directory/ancestor must be root:root, non-symlink and not group/other writable: ' + str(part))


def write(path, text, mode=0o600):
    with open(path, 'x', encoding='utf-8') as output:
        os.fchmod(output.fileno(), mode)
        output.write(text)


def prepare(base, binaries, requester):
    trusted(base.parent)
    binaries = binaries.resolve(strict=True)
    account = pwd.getpwnam(requester)
    if account.pw_uid in (0, 33, 65534) or account.pw_gid == 0:
        raise ValueError('choose a real unprivileged requester account distinct from root and service UID 33')
    base.mkdir(mode=0o755)
    base.chmod(0o755)
    trusted(base)
    tools = base / 'bin'
    tools.mkdir(mode=0o755)
    tools.chmod(0o755)
    for name in ('sigrund', 'sigrundctl', 'sigrund-approve', 'sigrun'):
        shutil.copyfile(binaries / name, tools / name)
        (tools / name).chmod(0o755)
    commands = base / 'commands'
    commands.mkdir(mode=0o755)
    commands.chmod(0o755)
    for name in ('id', 'true', 'false', 'cat', 'sleep'):
        shutil.copyfile(SHARED['command_source'](name), commands / name)
        (commands / name).chmod(0o755)
    key = base / 'signer'
    subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key)], check=True)
    # These required files are deliberately inactive in the local-audit profile.
    # They must be replaced by actual registered collector credentials before
    # remote audit can be enabled; no collector network request occurs here.
    config = (REPO / 'config/sigrund.toml.example').read_text()
    config = config.replace('["/usr/bin", "/usr/sbin"]', json.dumps([str(commands)]))
    config = config.replace('<strict-padded-base64-32-byte-ed25519-key>', base64.b64encode(bytes(32)).decode())
    for name in ('collector-ca.pem', 'collector-client.crt', 'collector-client.key'):
        path = base / name
        write(path, 'INACTIVE local-audit MVP fixture; not TLS credentials\n')
        config = config.replace('/etc/sigrund/' + name, str(path))
    config += '\n[mvp]\napproval_signer_id = "mvp-root"\n'
    write(base / 'config.toml', config)
    signer = (REPO / 'config/signers.toml.example').read_text()
    for old, new in (
        ('mandator-alice-yubikey', 'mvp-root'),
        ('type = "sk-ssh-ed25519"', 'type = "ssh-ed25519"'),
        ('sk-ssh-ed25519@openssh.com AAAA...', key.with_suffix('.pub').read_text().strip()),
        ('require_user_presence = true', 'require_user_presence = false'),
        ('allowed_requester_uids = [1001]', f'allowed_requester_uids = [{account.pw_uid}]'),
        ('allowed_modes = ["one_time", "time_range"]', 'allowed_modes = ["one_time"]'),
        ('["/usr/bin", "/usr/sbin"]', json.dumps([str(commands)])),
    ):
        signer = signer.replace(old, new)
    write(base / 'signers.toml', signer)
    subprocess.run([str(tools / 'sigrund'), '--check-config', '--config', str(base / 'config.toml'),
                    '--signers', str(base / 'signers.toml')], check=True)
    # init-host prints an anchor key; retain it privately, never in the manifest.
    with open(base / 'provisioning.private.json', 'xb') as output:
        os.fchmod(output.fileno(), 0o600)
        subprocess.run([str(tools / 'sigrundctl'), 'init-host', '--state-dir', str(base / 'state'),
                        '--log-path', str(base / 'log/audit.jsonl')], stdout=output, check=True)
    label = 'sigrund-mvp-' + uuid.uuid4().hex[:12]
    runtime = Path('/run') / label
    command = [str(tools / 'sigrund'), '--foreground', '--config', str(base / 'config.toml'),
               '--signers', str(base / 'signers.toml'), '--state-dir', str(base / 'state'),
               '--log-path', str(base / 'log/audit.jsonl'), '--socket', str(runtime / 'client.sock'),
               '--approval-socket', str(runtime / 'approve.sock')]
    unit = (REPO / 'packaging/sigrund.service').read_text()
    unit = unit.replace('/etc/sigrund/config.toml', str(base / 'config.toml'))
    unit = unit.replace('/etc/sigrund/signers.toml', str(base / 'signers.toml'))
    unit = re.sub(r'^ExecStart=.*$', 'ExecStart=' + ' '.join(command), unit, flags=re.M)
    unit = unit.replace('RuntimeDirectory=sigrund', 'RuntimeDirectory=' + label)
    unit = unit.replace('StateDirectory=sigrund\n', '').replace('LogsDirectory=sigrund\n', '')
    write(base / 'daemon.service', unit, 0o644)
    manifest = {'version': 1, 'base': str(base), 'unit': label + '.service', 'runtime': str(runtime),
                'command': command, 'requester': requester, 'requester_uid': account.pw_uid,
                'requester_gid': account.pw_gid, 'signer_id': 'mvp-root'}
    write(base / 'lab.json', json.dumps(manifest, indent=2) + '\n', 0o644)
    variables = {'TEST_BASE': base, 'TEST_CONFIG': base / 'config.toml', 'TEST_SIGNERS': base / 'signers.toml',
                 'TEST_STATE': base / 'state', 'TEST_LOG': base / 'log/audit.jsonl',
                 'TEST_SOCKET': runtime / 'client.sock', 'TEST_APPROVAL_SOCKET': runtime / 'approve.sock',
                 'TEST_SSH_IDENTITY': key, 'TEST_SIGNER_ID': 'mvp-root', 'TEST_UNIT': manifest['unit'],
                 'TEST_RUNTIME': runtime, 'TEST_BIN': tools, 'TEST_COMMANDS': commands,
                 'TEST_REQUESTER': requester}
    write(base / 'environment.sh', ''.join('export ' + k + '=' + shlex.quote(str(v)) + '\n'
                                         for k, v in variables.items()), 0o644)
    print('source ' + shlex.quote(str(base / 'environment.sh')))


def load(base):
    trusted(base)
    path = base / 'lab.json'
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError('untrusted lab manifest')
    manifest = json.loads(path.read_text())
    if manifest['base'] != str(base) or not re.fullmatch(r'sigrund-mvp-[0-9a-f]{12}\.service', manifest['unit']):
        raise ValueError('invalid lab identity')
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare', 'start', 'stop', 'status', 'foreground'))
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--binaries', type=Path, default=REPO / 'target/debug')
    parser.add_argument('--requester', default='mvp-requester')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('root required on a disposable test host')
    os.umask(0o077)
    if args.action == 'prepare':
        prepare(args.directory, args.binaries, args.requester)
        return
    manifest = load(args.directory)
    unit = manifest['unit']
    if args.action == 'start':
        target = Path('/run/systemd/system') / unit
        if target.exists():
            raise ValueError('unit already installed; stop the lab before starting it again')
        write(target, (args.directory / 'daemon.service').read_text(), 0o644)
        subprocess.run(['systemctl', 'daemon-reload'], check=True)
        subprocess.run(['systemctl', 'start', unit], check=True)
    elif args.action == 'stop':
        subprocess.run(['systemctl', 'stop', unit], check=True)
        subprocess.run(['systemctl', 'reset-failed', unit], check=False, capture_output=True)
        (Path('/run/systemd/system') / unit).unlink(missing_ok=True)
        subprocess.run(['systemctl', 'daemon-reload'], check=True)
        print('Stopped. Preserved host identity, signing key, audit history and consumed grants in ' + str(args.directory))
    elif args.action == 'foreground':
        # Type=notify still waits for readiness, --pipe keeps diagnostics on this
        # root terminal, and systemd owns cleanup even if this terminal dies.
        command = ['systemd-run', '--unit=' + unit, '--service-type=notify', '--pipe', '--wait', '--collect',
                   '--property=NotifyAccess=main', '--property=Delegate=yes', '--property=KillMode=control-group',
                   '--property=SendSIGKILL=yes', '--property=TimeoutStartSec=30s', '--property=TimeoutStopSec=15s',
                   '--property=WatchdogSec=3s', '--property=RuntimeDirectory=' + Path(manifest['runtime']).name,
                   '--property=RuntimeDirectoryMode=0755', '--property=UMask=0077', *manifest['command']]
        os.execvp(command[0], command)
    else:
        subprocess.run(['systemctl', 'status', '--no-pager', unit], check=False)
        result = subprocess.run(['systemctl', 'show', '--property=ControlGroup', '--value', unit],
                                check=True, capture_output=True, text=True).stdout.strip()
        if not result or not result.startswith('/'):
            raise ValueError('no live delegated cgroup')
        group = Path('/sys/fs/cgroup' + result)
        print('G=' + str(group))
        print('controllers=' + (group / 'cgroup.subtree_control').read_text().strip())
        if not {'memory', 'pids'} <= set((group / 'cgroup.subtree_control').read_text().split()):
            raise ValueError('missing delegated memory/pids controllers')
        for name in ('supervisor', 'jobs', 'hooks'):
            if not (group / name).is_dir():
                raise ValueError('missing daemon cgroup: ' + name)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        sys.exit('mvp-lab: ' + str(error))
