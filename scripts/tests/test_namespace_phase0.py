"""Evidence qualification must not turn partial runs into passing runs."""
import json
import os
from pathlib import Path
import runpy
import subprocess
import tempfile
import types
import unittest
from unittest import mock

REPO = Path(__file__).resolve().parents[2]
RUNNER = runpy.run_path(str(REPO / 'scripts/verify-namespace-phase0.py'))


class NamespaceEvidenceTests(unittest.TestCase):
    def test_missing_duplicate_failed_or_extra_cases_do_not_qualify(self):
        validate = RUNNER['validate_manifest']
        required = ['acquisition', 'entry']
        passing = [{'name': name, 'result': 'passed'} for name in required]
        self.assertTrue(validate({'cases': passing}, required))
        for cases in [[], passing[:1], passing + passing[:1],
                      passing + [{'name': 'unexpected', 'result': 'passed'}],
                      [passing[0], {'name': 'entry', 'result': 'failed'}]]:
            self.assertFalse(validate({'cases': cases}, required))

    def test_required_cases_cover_routes_faults_and_real_enforcement(self):
        required = json.loads((REPO / 'scripts/namespace-phase0/required-cases.json').read_bytes())
        self.assertEqual(len(required), len(set(required)))
        for rootless in [0, 1]:
            for route in range(4):
                self.assertIn(f'route-r{rootless}-{route}', required)
            for fault in range(10):
                self.assertIn(f'namespace-r{rootless}-filtered0-fault{fault}', required)
            for model in ['direct', 'memfd']:
                self.assertIn(f'selinux-namespace-r{rootless}-{model}', required)
                self.assertIn(f'selinux-namespace-r{rootless}-{model}-reload', required)
            for mode in ['domain-permissive', 'global-permissive']:
                self.assertIn(f'selinux-namespace-r{rootless}-direct-{mode}', required)
        self.assertIn('selinux-reload-at-exec-stop', required)
        self.assertIn('selinux-secret-avc', required)


class PolicyRecoveryTests(unittest.TestCase):
    def recover(self, artifacts, domain, installed=True, fail_delete=False):
        state = {'domain': domain, 'installed': installed}
        calls = []

        def command(args, **kwargs):
            calls.append(args)
            output = ''
            if args == ['semanage', 'permissive', '-l']:
                output = 'Customized Permissive Types\nsigrund_phase0_t\n' if state['domain'] else ''
            elif args == ['semanage', 'permissive', '-d', 'sigrund_phase0_t']:
                if fail_delete:
                    raise RuntimeError('interrupted permissive deletion')
                state['domain'] = False
            elif args == ['semodule', '-l']:
                output = 'sigrund_phase0 1.0\n' if state['installed'] else ''
            elif args == ['semodule', '-r', 'sigrund_phase0']:
                if state['domain']:
                    raise RuntimeError('permissive module still references the test type')
                state['installed'] = False
            return subprocess.CompletedProcess(args, 0, stdout=output)

        with mock.patch.dict(RUNNER['recover_policy'].__globals__, {'run': command}):
            RUNNER['recover_policy'](artifacts)
        return state, calls

    def test_interruption_before_and_after_permissive_transaction_is_recoverable(self):
        for domain, installed in [(False, False), (False, True), (True, True)]:
            with self.subTest(domain=domain, installed=installed), tempfile.TemporaryDirectory() as directory:
                artifacts = Path(directory)
                (artifacts / 'policy-owned').touch()
                (artifacts / 'domain-permissive-owned').touch()
                state, calls = self.recover(artifacts, domain, installed)
                self.assertFalse(state['domain'])
                self.assertFalse(state['installed'])
                self.assertFalse((artifacts / 'domain-permissive-owned').exists())
                self.assertFalse((artifacts / 'policy-owned').exists())
                self.assertEqual(calls[0], ['setenforce', '1'])
                # A second cleanup, including the outer timeout path after an
                # inner successful cleanup, must leave host policy untouched.
                _, calls = self.recover(artifacts, False, False)
                self.assertEqual(calls, [])

    def test_failed_domain_deletion_keeps_recovery_markers_for_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            artifacts = Path(directory)
            (artifacts / 'policy-owned').touch()
            (artifacts / 'domain-permissive-owned').touch()
            with self.assertRaisesRegex(RuntimeError, 'interrupted permissive deletion'):
                self.recover(artifacts, True, fail_delete=True)
            self.assertTrue((artifacts / 'policy-owned').exists())
            self.assertTrue((artifacts / 'domain-permissive-owned').exists())
            state, _ = self.recover(artifacts, True)
            self.assertFalse(state['domain'])
            self.assertFalse(state['installed'])


class ServicePolicyRecoveryTests(unittest.TestCase):
    unit = 'sigrund-phase0-test.service'
    stopped = 'LoadState=loaded\nActiveState=inactive\nControlGroup=\n'

    def invoke(self, stop_error=None, kill_error=None, statuses=None, populated=None, clock=None):
        calls = []
        statuses = iter(statuses or [self.stopped])

        def command(args, **kwargs):
            calls.append(args[1])
            self.assertIn('timeout', kwargs)
            if args[1] == 'stop' and stop_error:
                raise stop_error
            if args[1] == 'kill' and kill_error:
                raise kill_error
            output = next(statuses) if args[1] == 'show' else ''
            return subprocess.CompletedProcess(args, 0, stdout=output)

        helper = RUNNER['stop_service_and_recover_policy']
        with tempfile.TemporaryDirectory() as directory:
            artifacts = Path(directory)
            (artifacts / 'policy-owned').touch()
            (artifacts / 'domain-permissive-owned').touch()

            def recover(path):
                self.assertEqual(path, artifacts)
                calls.append('recover')

            with mock.patch.dict(helper.__globals__, {'recover_policy': recover}), \
                    mock.patch('subprocess.run', side_effect=command), \
                    mock.patch('time.sleep'), \
                    mock.patch('time.monotonic', side_effect=clock) as monotonic, \
                    mock.patch.object(Path, 'read_text', side_effect=populated):
                if clock is None:
                    monotonic.side_effect = None
                    monotonic.return_value = 0
                try:
                    outcome = helper(self.unit, artifacts)
                except RuntimeError:
                    self.assertNotIn('recover', calls)
                    self.assertTrue((artifacts / 'policy-owned').exists())
                    self.assertTrue((artifacts / 'domain-permissive-owned').exists())
                    raise
        return outcome, calls

    def test_stop_timeout_failure_and_oserror_force_kill_before_recovery(self):
        errors = [subprocess.TimeoutExpired(['systemctl', 'stop'], 30),
                  subprocess.CalledProcessError(1, ['systemctl', 'stop']), OSError('stop failed')]
        for error in errors:
            with self.subTest(error=type(error).__name__):
                outcome, calls = self.invoke(stop_error=error)
                self.assertEqual(calls, ['stop', 'kill', 'show', 'recover'])
                self.assertTrue(outcome['forced_kill'])
                self.assertEqual(outcome['stop_timed_out'], isinstance(error, subprocess.TimeoutExpired))

    def test_successful_stop_is_verified_before_recovery(self):
        outcome, calls = self.invoke()
        self.assertEqual(calls, ['stop', 'show', 'recover'])
        self.assertFalse(outcome['forced_kill'])

    def test_policy_transaction_descendants_must_exit_before_recovery(self):
        state = 'LoadState=loaded\nActiveState=failed\nControlGroup=/system.slice/' + self.unit + '\n'
        _, calls = self.invoke(stop_error=subprocess.TimeoutExpired('stop', 30),
                               statuses=[state, state], populated=['populated 1\n', 'populated 0\n'])
        self.assertEqual(calls, ['stop', 'kill', 'show', 'show', 'recover'])

    def test_kill_failure_for_collected_unit_does_not_skip_recovery(self):
        _, calls = self.invoke(stop_error=subprocess.TimeoutExpired('stop', 30),
                               kill_error=subprocess.CalledProcessError(1, 'kill'),
                               statuses=['LoadState=not-found\nActiveState=inactive\nControlGroup=\n'])
        self.assertEqual(calls, ['stop', 'kill', 'show', 'recover'])

    def test_live_descendants_retain_markers_without_racing_policy_cleanup(self):
        state = 'LoadState=loaded\nActiveState=failed\nControlGroup=/system.slice/' + self.unit + '\n'
        with self.assertRaisesRegex(RuntimeError, 'still active or populated'):
            self.invoke(stop_error=subprocess.TimeoutExpired('stop', 30), statuses=[state],
                        populated=['populated 1\n'], clock=[0, 31])

    def test_empty_cgroup_of_active_service_is_not_enough(self):
        with self.assertRaisesRegex(RuntimeError, 'still active or populated'):
            self.invoke(statuses=['LoadState=loaded\nActiveState=activating\nControlGroup=\n'], clock=[0, 31])

    def test_unreadable_status_cannot_qualify_as_stopped(self):
        with self.assertRaisesRegex(RuntimeError, 'still active or populated'):
            self.invoke(statuses=[''], clock=[0, 31])

    def test_main_runner_recovers_after_stop_timeout(self):
        calls = []

        def command(args, **kwargs):
            calls.append(args[0:2])
            if args[:2] == ['systemctl', 'stop']:
                raise subprocess.TimeoutExpired(args, 30)
            output = self.stopped if args[:2] == ['systemctl', 'show'] else ''
            return subprocess.CompletedProcess(args, 0, stdout=output)

        main = RUNNER['main']
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.dict(main.__globals__, {
                    'run': lambda *a, **k: subprocess.CompletedProcess(a, 0, stdout='Enforcing\n'),
                    'recover_policy': lambda path: calls.append('recover'),
                }), mock.patch('os.geteuid', return_value=0), \
                mock.patch('sys.argv', ['runner', '--disposable-host', '--artifacts', directory + '/artifacts']), \
                mock.patch('subprocess.run', side_effect=command):
            self.assertEqual(main(), 0)
        self.assertLess(calls.index(['systemctl', 'kill']), calls.index('recover'))
        self.assertLess(calls.index('recover'), calls.index(['journalctl', '-u']))

    def test_recovery_regression_finally_uses_shared_cleanup_on_startup_failure(self):
        regression = runpy.run_path(str(REPO / 'scripts/verify-namespace-phase0-recovery.py'))

        def command(args, **kwargs):
            if args[0] == 'systemd-run':
                raise RuntimeError('startup interrupted')
            return subprocess.CompletedProcess(args, 0, stdout='Enforcing\n' if args[0] == 'getenforce' else '')

        fake_os = types.SimpleNamespace(**vars(os))
        fake_os.geteuid = mock.Mock(return_value=0)
        fake_os.open = mock.Mock(return_value=42)
        fake_os.fstat = mock.Mock(return_value=types.SimpleNamespace(st_mode=0o100600, st_uid=0))
        fake_os.close = mock.Mock()
        cleanup = mock.Mock()
        main = regression['main']
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.dict(main.__globals__, {'os': fake_os, 'run': command,
                                                  'stop_service_and_recover_policy': cleanup}), \
                mock.patch('fcntl.flock'), \
                mock.patch('sys.argv', ['regression', '--disposable-host', '--artifacts', directory + '/artifacts']):
            with self.assertRaisesRegex(RuntimeError, 'startup interrupted'):
                main()
            unit, artifacts = cleanup.call_args.args
            self.assertTrue(unit.startswith('sigrund-phase0-recovery-'))
            self.assertEqual(artifacts, Path(directory) / 'artifacts')
            self.assertEqual(cleanup.call_args.kwargs, {'stop_timeout': 15})
            self.assertNotIn('cleanup_error', json.loads((artifacts / 'recovery.json').read_text()))
        fake_os.close.assert_called_once_with(42)


if __name__ == '__main__':
    unittest.main()
