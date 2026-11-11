#!/usr/bin/env python3
"""Build a disposable root-owned Podman rootfs from installed host binaries.

This does not create a container, register a target, provision state or start the
service. Follow the installed operator recipe for those independent operations.
"""
import argparse
import importlib.util
import os
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = Path('/var/lib/sigrund-podman-rootfs')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workload', type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or not args.workload.is_absolute():
        parser.error('host root and an absolute workload path required')
    parent = ROOT.parent.stat()
    if parent.st_uid != 0 or parent.st_gid != 0 or parent.st_mode & 0o022:
        parser.error('rootfs parent must be trusted root:root')
    ROOT.mkdir(mode=0o755)  # Refuse existing/partial roots.
    spec = importlib.util.spec_from_file_location('namespace_environment', HERE.parent / 'selinux/environment.py')
    api = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(api)
    for directory in ('run/sigrund', 'proc', 'sys', 'dev', 'etc', 'srv/service', 'usr/local/libexec/sigrund-namespace'):
        (ROOT / directory).mkdir(parents=True, exist_ok=True, mode=0o755)
    for binary in ('/usr/bin/sigrun', '/usr/bin/sigrund-anchor', '/usr/bin/sh', '/usr/bin/cat', '/usr/bin/sleep'):
        api.copy_binary(ROOT, binary)
    (ROOT / 'etc/passwd').write_text('root:x:0:0::/:/usr/bin/sh\nns_service:x:12001:12001::/srv/service:/usr/bin/sh\n')
    (ROOT / 'etc/group').write_text('root:x:0:\nns_service:x:12001:\n')
    import shutil
    command = ROOT / 'usr/local/libexec/sigrund-namespace/tool'
    shutil.copyfile(args.workload, command)
    command.chmod(0o755)
    secret = ROOT / 'srv/secret'
    secret.write_text('Podman denial sentinel\n')
    secret.chmod(0o644)
    subprocess.run(['chcon', '-R', 'system_u:object_r:container_file_t:s0', str(ROOT)], check=True)
    subprocess.run(['chcon', 'system_u:object_r:sigrund_workload_secret_t:s0', str(secret)], check=True)
    print(ROOT)


if __name__ == '__main__':
    main()
