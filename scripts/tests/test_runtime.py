"""Compile runtime fault gates without requiring a privileged daemon."""
from pathlib import Path
import runpy
import tempfile
import unittest
from unittest.mock import Mock


RUNTIME = runpy.run_path(str(Path(__file__).resolve().parents[1] / 'verify-runtime.py'))


class RuntimeGateTests(unittest.TestCase):
    def test_fault_gates_compile_and_are_passed_to_daemon(self):
        for durable, mode in ((False, 'clone-after'), (True, 'commit-before')):
            with self.subTest(durable=durable), tempfile.TemporaryDirectory() as directory:
                fixture = Mock(base=Path(directory))
                gate = RUNTIME['Gate'](fixture, mode, durable=durable)
                try:
                    fixture.launch.assert_called_once()
                    environment, descriptors = fixture.launch.call_args.args
                    self.assertTrue(Path(environment['LD_PRELOAD']).is_file())
                    prefix = 'SIGRUND_DURABLE_' if durable else 'SIGRUND_EXEC_'
                    self.assertEqual(environment[prefix + ('POINT' if durable else 'MODE')], mode)
                    self.assertEqual(len(descriptors), 2)
                finally:
                    gate.close()


if __name__ == '__main__':
    unittest.main()
