#!/usr/bin/env python3
"""Validate a workspace release tag and collect tested package artifacts."""
import argparse
import hashlib
from pathlib import Path
import re
import shutil

from build import workspace_version


def check_tag(tag):
    version = workspace_version()
    if not re.fullmatch(r'\d+\.\d+\.\d+', version) or tag != f'v{version}':
        raise ValueError(f'release tag must be v{version}')
    return version


def prepare_assets(artifacts, output, version):
    directories = sorted(artifacts.glob('packages-*'))
    if not directories:
        raise ValueError('no package artifacts found')
    # Validate every artifact before creating an upload directory.
    assets = {}
    for directory in directories:
        packages = sorted([*directory.glob('*.deb'), *directory.glob('*.rpm')])
        names = set()
        sums = ''.join(hashlib.sha256(path.read_bytes()).hexdigest() + '  ' + path.name + '\n'
                       for path in packages)
        if sums != (directory / 'SHA256SUMS').read_text():
            raise ValueError(f'package checksum mismatch: {directory.name}')
        for package in packages:
            match = re.fullmatch(
                rf'(sigrun|sigrund)(?:_{re.escape(version)}-[0-9A-Za-z.]+_amd64\.deb'
                rf'|-{re.escape(version)}-[0-9A-Za-z.]+\.x86_64\.rpm)', package.name)
            if match is None or package.name in assets:
                raise ValueError(f'unexpected or duplicate package: {package.name}')
            names.add(match[1])
            assets[package.name] = package
        if len(packages) != 2 or names != {'sigrun', 'sigrund'}:
            raise ValueError(f'expected a client and daemon package: {directory.name}')
        info = directory / 'build-info.txt'
        if not info.is_file():
            raise ValueError(f'missing build information: {directory.name}')
        assets[directory.name.removeprefix('packages-') + '-build-info.txt'] = info
    output.mkdir(parents=True, exist_ok=False)
    for name, source in assets.items():
        shutil.copyfile(source, output / name)
    (output / 'SHA256SUMS').write_text(''.join(
        hashlib.sha256((output / name).read_bytes()).hexdigest() + '  ' + name + '\n'
        for name in sorted(assets)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tag', required=True)
    parser.add_argument('--artifacts', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if (args.artifacts is None) != (args.output is None):
        parser.error('--artifacts and --output must be supplied together')
    try:
        version = check_tag(args.tag)
        if args.artifacts is not None:
            prepare_assets(args.artifacts, args.output, version)
    except ValueError as error:
        parser.error(str(error))


if __name__ == '__main__':
    main()
