"""Clean container builds must supply every executable consumed by packaging."""
from pathlib import Path
import runpy
import shlex
import sys
import tempfile
import unittest
from unittest import mock


REPO = Path(__file__).resolve().parents[2]
PACKAGING = runpy.run_path(str(REPO / 'packaging/build.py'))


class PackageBuildTests(unittest.TestCase):
    def test_native_packages_read_the_workspace_version(self):
        main = PACKAGING['main']
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / 'Cargo.toml').write_text('[workspace.package]\nversion = "9.8.7"\n')

            def build(work, output, version, release):
                self.assertEqual(version, '9.8.7')
                self.assertEqual(release, '1.test.1')
                for name in PACKAGING['package_names'](kind):
                    (output / f'{name}.{kind}').write_text(version)

            for kind in ('deb', 'rpm'):
                with self.subTest(format=kind), mock.patch.dict(main.__globals__, {
                    'REPO': base, 'deb': build, 'rpm': build,
                }), mock.patch.object(sys, 'argv', [
                    'build.py', '--format', kind, '--release', '1.test.1',
                    '--output', str(base / kind),
                ]):
                    main()
                    self.assertEqual(len((base / kind / 'SHA256SUMS').read_text().splitlines()),
                                     4 if kind == 'rpm' else 2)

    def test_clean_container_build_supplies_both_package_payloads(self):
        script = (REPO / 'packaging/build-container.sh').read_text().replace('\\\n', ' ')
        command = shlex.split(next(line for line in script.splitlines() if line.startswith('cargo build ')))
        binaries = [command[index + 1] for index, value in enumerate(command) if value == '--bin']
        if '--bins' in command:
            binaries.extend(path.stem for path in (REPO / 'crates/sigrund/src/bin').glob('*.rs'))
        self.assertTrue(binaries, 'container build must select binaries')
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source = base / 'source'
            release = source / 'target/release'
            release.mkdir(parents=True)
            # Materialize only the outputs selected by the container command.
            # Existing workspace builds must not fill gaps in that selection.
            for binary in binaries:
                (release / binary).write_text(binary)
            for path in REPO.iterdir():
                if path.name not in ('target', '.git'):
                    (source / path.name).symlink_to(path)
            stage = PACKAGING['stage']
            with mock.patch.dict(stage.__globals__, {'REPO': source, 'run': mock.Mock()}):
                for kind in ('deb', 'rpm'):
                    for package in ('sigrun', 'sigrund'):
                        with self.subTest(format=kind, package=package):
                            output = base / kind / package
                            stage(output, package, kind)
                            if package == 'sigrund':
                                anchor = output / 'usr/bin/sigrund-anchor'
                                self.assertEqual(anchor.read_text(), 'sigrund-anchor')
                                self.assertEqual(anchor.stat().st_mode & 0o777, 0o755)
                                examples = output / 'usr/share/doc/sigrund/namespace/selinux'
                                for name in ('acme_backup.te', 'verify-custom-domains.py'):
                                    installed = examples / name
                                    self.assertEqual(installed.read_bytes(),
                                                     (REPO / 'scripts/namespace/selinux' / name).read_bytes())
                                    self.assertEqual(installed.stat().st_mode & 0o777, 0o644)


    def test_policy_payloads_require_built_modules_and_keep_podman_separate(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            policy = base / 'policy'
            policy.mkdir()
            for name in ('sigrund_daemon', 'sigrund_workload', 'sigrund_requester', 'sigrund_podman'):
                (policy / (name + '.pp')).write_bytes(name.encode())
            for package, expected in (
                ('sigrund-selinux', {'sigrund_daemon.pp', 'sigrund_workload.pp', 'sigrund_requester.pp'}),
                ('sigrund-selinux-podman', {'sigrund_podman.pp'}),
            ):
                root = base / package
                PACKAGING['stage'](root, package, 'rpm', policy)
                modules = root / 'usr/share/selinux/packages/targeted'
                self.assertEqual({p.name for p in modules.iterdir()}, expected)
                for module in modules.iterdir():
                    self.assertEqual(module.read_bytes(), (policy / module.name).read_bytes())
                    self.assertEqual(module.stat().st_mode & 0o777, 0o644)
                self.assertFalse((root / 'usr/bin').exists())
            (policy / 'sigrund_workload.pp').unlink()
            with self.assertRaises(FileNotFoundError):
                PACKAGING['stage'](base / 'missing', 'sigrund-selinux', 'rpm', policy)


if __name__ == '__main__':
    unittest.main()
