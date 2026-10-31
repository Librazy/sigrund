"""Unprivileged regression tests for the acceptance harness's observation order."""
import json
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest


HARNESS = runpy.run_path(str(Path(__file__).resolve().parents[1] / 'verify-acceptance.py'))
CHILD = r'''
import json, os, signal, sys
from pathlib import Path
status, cleaned, mode = sys.argv[1:]
def complete(signum, frame):
    outcome = {'exit_code': None, 'signal': 2} if mode != 'wrong' else {'exit_code': 23, 'signal': None}
    with open(status, 'a') as output:
        output.write(json.dumps(outcome) + '\n')
    if mode != 'retained':
        Path(cleaned).touch()
    sys.exit(130 if mode != 'wrong' else 23)
signal.signal(signal.SIGINT, signal.SIG_IGN if mode == 'ignored' else complete)
with open(status, 'a') as output:
    output.write('{"status":"READY_TO_EXEC"}\n')
# Finite output deliberately reproduces the old false positive if the harness
# starts draining before verifying cancellation.
for _ in range(512):
    os.write(1, b'x' * 4096)
Path(cleaned).touch()
'''


class CancellationTests(unittest.TestCase):
    def exercise(self, mode):
        with tempfile.TemporaryDirectory() as directory:
            status = Path(directory) / 'status'
            cleaned = Path(directory) / 'cleaned'
            with open(status, 'w+b') as output:
                child = subprocess.Popen([sys.executable, '-c', CHILD, str(status), str(cleaned), mode],
                                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                try:
                    return HARNESS['cancel_blocked_output'](child, output, status, cleaned.exists, timeout=0.5)
                finally:
                    if child.poll() is None:
                        child.kill()
                    child.communicate(timeout=5)

    def test_signal_and_cleanup_observed_before_drain(self):
        self.assertEqual(self.exercise('handled'), {'signal': 2, 'exit_code': 130, 'cleanup_before_drain': True})

    def test_ignored_signal_cannot_pass_by_finishing_output(self):
        with self.assertRaisesRegex(AssertionError, 'child signal outcome while output remains blocked'):
            self.exercise('ignored')

    def test_normal_exit_is_not_cancellation(self):
        with self.assertRaises(AssertionError):
            self.exercise('wrong')

    def test_child_exit_without_job_cleanup_fails(self):
        with self.assertRaisesRegex(AssertionError, 'cancellation cleanup without reads'):
            self.exercise('retained')


if __name__ == '__main__':
    unittest.main()
