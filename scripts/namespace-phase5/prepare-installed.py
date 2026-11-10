#!/usr/bin/env python3
"""Fresh disposable Podman qualification provisioning; starts no service."""
import argparse
import os
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--requester', default='phase4req')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('host root required')
    subprocess.run(['python3', str(HERE.parent / 'namespace-phase4/prepare-installed.py'),
                    '--requester', args.requester, '--state-dir', '/var/lib/sigrund-v3',
                    '--log-path', '/var/log/sigrund-v3/audit.jsonl'], check=True)
    config = Path('/etc/sigrund/config.toml')
    policy = Path('/var/lib/sigrund-phase4-qualification/policy')
    subprocess.run(['make', '-C', str(policy), 'podman'], check=True)
    subprocess.run(['semodule', '-i', str(policy / 'sigrund_podman.pp')], check=True)
    subprocess.run(['/usr/libexec/sigrund/sigrund', '--check-config', '--config', str(config),
                    '--signers', '/etc/sigrund/signers.toml'], check=True)
    print('Fresh Podman qualification set provisioned; start services explicitly.')


if __name__ == '__main__':
    main()
