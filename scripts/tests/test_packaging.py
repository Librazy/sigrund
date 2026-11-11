"""Clean container builds must supply every executable consumed by packaging."""
from pathlib import Path
import runpy
import shlex
import tempfile
import unittest
from unittest import mock


REPO = Path(__file__).resolve().parents[2]
PACKAGING = runpy.run_path(str(REPO / 'packaging/build.py'))


class PackageBuildTests(unittest.TestCase):
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


if __name__ == '__main__':
    unittest.main()
