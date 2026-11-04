"""Check executable trust fixture bounds using real native ELF programs."""
import os
from pathlib import Path
import runpy
import subprocess
import tempfile
import tomllib
from types import SimpleNamespace
import unittest


REPO = Path(__file__).resolve().parents[2]
TRUST = runpy.run_path(str(REPO / 'scripts/verify-trust.py'))


class TrustFixtureTests(unittest.TestCase):
    def test_native_programs_straddle_snapshot_bound_and_remain_executable(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            commands = base / 'commands'
            commands.mkdir()
            fixture = SimpleNamespace(base=base, commands=commands)
            config = base / 'config'
            config.write_text((REPO / 'config/sigrund.toml.example').read_text())
            TRUST['configure'](fixture)
            limits = tomllib.loads(config.read_text())
            snapshot_max = limits['max_executable_bytes']
            small = TRUST['program'](fixture, 'small', size=None)
            direct = TRUST['program'](fixture, 'direct', size=snapshot_max + 1)
            metadata = TRUST['program'](fixture, 'metadata')
            self.assertLessEqual(small.stat().st_size, snapshot_max)
            self.assertEqual(direct.stat().st_size, snapshot_max + 1)
            self.assertLess(direct.stat().st_size, limits['max_direct_digest_bytes'])
            self.assertGreater(metadata.stat().st_size, 67_108_864)
            self.assertEqual(limits['direct_digest_timeout_ms'], 5000)
            for program in (small, direct, metadata):
                with self.subTest(program=program.name):
                    result = subprocess.run([str(program)], capture_output=True, check=True, timeout=5)
                    self.assertEqual(result.stdout, f'{os.geteuid()}\n'.encode())
                    self.assertFalse(result.stderr)


if __name__ == '__main__':
    unittest.main()
