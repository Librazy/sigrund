"""A timed-out stop must not allow a populated integration service to survive."""
from pathlib import Path
import runpy
import subprocess
import tempfile
import unittest
from unittest import mock

API = runpy.run_path(str(Path(__file__).resolve().parents[1] / 'namespace/support.py'))


class ServiceCleanupTests(unittest.TestCase):
    unit = 'sigrund-namespace-review-test.service'
    stopped = 'LoadState=loaded\nActiveState=inactive\nControlGroup=\n'

    def invoke(self, *, stop_error=None, statuses=None, populated=None, clock=None):
        calls = []
        statuses = iter(statuses or [self.stopped])
        last = self.stopped

        def command(args, **kwargs):
            nonlocal last
            action = args[1]
            calls.append(action)
            if action == 'stop' and stop_error:
                raise stop_error
            if action == 'show':
                last = next(statuses, last)
            return subprocess.CompletedProcess(args, 0, stdout=last if action == 'show' else '')

        helper = API['stop_service']
        with mock.patch.dict(helper.__globals__, {'subprocess': mock.Mock(run=command,
                SubprocessError=subprocess.SubprocessError, TimeoutExpired=subprocess.TimeoutExpired)}), \
                mock.patch('time.sleep'), mock.patch('time.monotonic', side_effect=clock or [0] * 20), \
                mock.patch.object(Path, 'read_text', side_effect=populated):
            return helper(self.unit), calls

    def test_stop_errors_force_kill_and_verify_actual_state(self):
        for error in [subprocess.TimeoutExpired('stop', 30), subprocess.CalledProcessError(1, 'stop'), OSError('stop failed')]:
            with self.subTest(error=type(error).__name__):
                outcome, calls = self.invoke(stop_error=error)
                self.assertEqual(calls, ['stop', 'kill', 'show'])
                self.assertTrue(outcome['forced_kill'])
                self.assertEqual(outcome['stop_timed_out'], isinstance(error, subprocess.TimeoutExpired))

    def test_successful_stop_still_verifies_actual_state(self):
        outcome, calls = self.invoke()
        self.assertEqual(calls, ['stop', 'show'])
        self.assertFalse(outcome['forced_kill'])

    def test_waits_for_failed_service_descendants(self):
        state = 'LoadState=loaded\nActiveState=failed\nControlGroup=/system.slice/' + self.unit + '\n'
        _, calls = self.invoke(statuses=[state, state], populated=['populated 1\n', 'populated 0\n'])
        self.assertEqual(calls, ['stop', 'show', 'show'])

    def test_live_descendants_cannot_qualify_as_stopped(self):
        state = 'LoadState=loaded\nActiveState=failed\nControlGroup=/system.slice/' + self.unit + '\n'
        with self.assertRaisesRegex(RuntimeError, 'still active or populated'):
            self.invoke(statuses=[state], populated=['populated 1\n'], clock=[0, 31])

    def test_active_or_unreadable_service_cannot_qualify_as_stopped(self):
        for state in ['LoadState=loaded\nActiveState=activating\nControlGroup=\n', '']:
            with self.subTest(state=state), self.assertRaisesRegex(RuntimeError, 'still active or populated'):
                self.invoke(statuses=[state], clock=[0, 31])

    def test_untrusted_artifact_ancestor_is_rejected(self):
        trusted = runpy.run_path(str(Path(__file__).resolve().parents[1] / 'operator-lab.py'))['trusted']
        with tempfile.TemporaryDirectory() as directory:
            child = Path(directory) / 'private'
            child.mkdir(mode=0o700)
            with self.assertRaises(ValueError):
                trusted(child)


if __name__ == '__main__':
    unittest.main()
