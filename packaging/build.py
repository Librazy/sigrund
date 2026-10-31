#!/usr/bin/env python3
"""Package already-built release binaries using the target distro's native tools."""
import argparse
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
import tomllib

REPO = Path(__file__).resolve().parent.parent


def run(*args, **kwargs):
    return subprocess.run(args, check=True, text=True, **kwargs)


def install(source, destination, mode=0o644):
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    destination.chmod(mode)


def stage(root, package, kind):
    binaries = {'sigrun': ['sigrun'], 'sigrund': ['sigrund', 'sigrundctl', 'sigrund-approve']}
    for binary in binaries[package]:
        path = 'usr/libexec/sigrund/sigrund' if binary == 'sigrund' else 'usr/bin/' + binary
        install(REPO / 'target/release' / binary, root / path, 0o755)
        run('strip', '--strip-unneeded', str(root / path))
    docs = root / 'usr/share/doc' / package
    install(REPO / 'packaging/README.md', docs / 'README.md')
    license_path = docs / 'copyright' if kind == 'deb' else root / 'usr/share/licenses' / package / 'LICENSE'
    install(REPO / 'LICENSE', license_path)
    if package == 'sigrund':
        (root / 'etc/sigrund').mkdir(parents=True, mode=0o755)
        install(REPO / 'packaging/sigrund.service', root / 'usr/lib/systemd/system/sigrund.service')
        for name in ('sigrund.toml.example', 'signers.toml.example'):
            install(REPO / 'config' / name, docs / 'examples' / name)


def deb(work, output, version, release):
    arch = run('dpkg', '--print-architecture', capture_output=True).stdout.strip()
    # dpkg-shlibdeps requires a source control file, even for a binary-only build.
    (work / 'debian').mkdir()
    (work / 'debian/control').write_text('Source: sigrund\n\nPackage: sigrun\nArchitecture: any\n')
    for name in ('sigrun', 'sigrund'):
        root = work / name
        stage(root, name, 'deb')
        executables = sorted(p for p in (root / 'usr').rglob('*') if p.is_file() and os.access(p, os.X_OK))
        result = run('dpkg-shlibdeps', '-O', *(f'-e{p}' for p in executables), cwd=work, capture_output=True)
        dependencies = next(line.removeprefix('shlibs:Depends=') for line in result.stdout.splitlines()
                            if line.startswith('shlibs:Depends='))
        if name == 'sigrund':
            dependencies += ', systemd, openssh-client'
        metadata = root / 'DEBIAN'
        metadata.mkdir()
        description = ('Client for signed command elevation' if name == 'sigrun'
                       else 'Daemon and operator tools for signed command elevation')
        size = sum(p.stat().st_size for p in root.rglob('*') if p.is_file())
        (metadata / 'control').write_text(
            f'Package: {name}\nVersion: {version}-{release}\nArchitecture: {arch}\n'
            'Maintainer: Liqueur Librazy <im@librazy.org>\nSection: admin\nPriority: optional\n'
            f'Depends: {dependencies}\nInstalled-Size: {(size + 1023) // 1024}\n'
            'Homepage: https://github.com/Librazy/sigrund\n'
            f'Description: {description}\n'
            ' Local SSH-backed authorization with one-time grants.\n')
        if name == 'sigrund':
            for script in ('postinst', 'prerm', 'postrm'):
                install(REPO / 'packaging/deb' / script, metadata / script, 0o755)
        run('dpkg-deb', '--root-owner-group', '--build', str(root),
            str(output / f'{name}_{version}-{release}_{arch}.deb'))


def rpm(work, output, version, release):
    payload = work / 'payload'
    for name in ('sigrun', 'sigrund'):
        stage(payload / name, name, 'rpm')
    sources = work / 'SOURCES'
    sources.mkdir()
    with tarfile.open(sources / 'payload.tar.gz', 'w:gz') as archive:
        for name in ('sigrun', 'sigrund'):
            archive.add(payload / name, arcname=name)
    run('rpmbuild', '-bb', '--define', f'_topdir {work}',
        '--define', f'package_version {version}', '--define', f'package_release {release}',
        str(REPO / 'packaging/rpm/sigrun.spec'))
    for package in (work / 'RPMS').rglob('*.rpm'):
        shutil.copyfile(package, output / package.name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--format', choices=('deb', 'rpm'), required=True)
    parser.add_argument('--release', required=True, help='native package revision, e.g. 0.20261031.gitabc123.ubuntu24.04')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    version = tomllib.loads((REPO / 'crates/sigrund/Cargo.toml').read_text())['package']['version']
    if not re.fullmatch(r'\d+\.\d+\.\d+', version) or not re.fullmatch(r'[0-9][a-zA-Z0-9.]*', args.release):
        parser.error('version must be X.Y.Z and release must contain only alphanumerics and dots, starting with a digit')
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        parser.error('output directory must be empty')
    with tempfile.TemporaryDirectory(prefix='sigrund-packages-') as temporary:
        {'deb': deb, 'rpm': rpm}[args.format](Path(temporary), output, version, args.release)
    packages = sorted(output.glob('*.' + args.format))
    if len(packages) != 2:
        raise RuntimeError('expected exactly one client and one daemon package')
    (output / 'SHA256SUMS').write_text(''.join(
        hashlib.sha256(path.read_bytes()).hexdigest() + '  ' + path.name + '\n' for path in packages))


if __name__ == '__main__':
    main()
