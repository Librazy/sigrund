"""Release assets must preserve every tested package and reject invalid inputs."""
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib
import unittest


REPO = Path(__file__).resolve().parents[2]
VERSION = tomllib.loads((REPO / 'Cargo.toml').read_text())['workspace']['package']['version']


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.artifacts = self.base / 'artifacts'
        self.output = self.base / 'release'
        self.packages = []
        for distro in ('fedora-44', 'fedora-45', 'ubuntu-24.04', 'ubuntu-26.04'):
            directory = self.artifacts / f'packages-{distro}-x86_64'
            directory.mkdir(parents=True)
            revision = f'1.{distro.replace("-", "")}.1'
            for name in ('sigrun', 'sigrund'):
                filename = (f'{name}-{VERSION}-{revision}.x86_64.rpm' if distro.startswith('fedora')
                            else f'{name}_{VERSION}-{revision}_amd64.deb')
                package = directory / filename
                package.write_text(f'{distro}: {name}')
                self.packages.append(package)
            (directory / 'build-info.txt').write_text(f'image_reference={distro}\n')
            self.checksums(directory)

    def checksums(self, directory):
        packages = sorted([*directory.glob('*.deb'), *directory.glob('*.rpm')])
        (directory / 'SHA256SUMS').write_text(''.join(
            hashlib.sha256(path.read_bytes()).hexdigest() + '  ' + path.name + '\n'
            for path in packages))

    def prepare(self, tag=None):
        return subprocess.run([
            sys.executable, str(REPO / 'packaging/release.py'), '--tag', tag or f'v{VERSION}',
            '--artifacts', str(self.artifacts), '--output', str(self.output),
        ], text=True, capture_output=True)

    def test_collects_all_eight_packages_and_separate_build_information(self):
        result = self.prepare()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(list(self.output.iterdir())), 13)
        for source in self.packages:
            self.assertEqual((self.output / source.name).read_bytes(), source.read_bytes())
        for source in self.artifacts.glob('*/build-info.txt'):
            name = source.parent.name.removeprefix('packages-') + '-build-info.txt'
            self.assertEqual((self.output / name).read_bytes(), source.read_bytes())
        for line in (self.output / 'SHA256SUMS').read_text().splitlines():
            digest, name = line.split('  ')
            self.assertEqual(digest, hashlib.sha256((self.output / name).read_bytes()).hexdigest())

    def test_rejects_a_tag_that_does_not_match_the_workspace(self):
        result = self.prepare('v0.0.0')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(f'release tag must be v{VERSION}', result.stderr)
        self.assertFalse(self.output.exists())

    def test_rejects_modified_packages(self):
        self.packages[-1].write_text('modified after smoke tests')
        result = self.prepare()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('package checksum mismatch', result.stderr)
        self.assertFalse(self.output.exists())

    def test_rejects_a_missing_daemon_package(self):
        package = self.packages[-1]
        package.unlink()
        self.checksums(package.parent)
        result = self.prepare()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('expected a client and daemon package', result.stderr)
        self.assertFalse(self.output.exists())

    def test_rejects_packages_from_another_version(self):
        package = self.packages[-1]
        package.rename(package.with_name(package.name.replace(VERSION, '0.0.0')))
        self.checksums(package.parent)
        result = self.prepare()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('unexpected or duplicate package', result.stderr)
        self.assertFalse(self.output.exists())


if __name__ == '__main__':
    unittest.main()
