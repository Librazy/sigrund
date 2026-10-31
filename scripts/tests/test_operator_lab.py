"""Both operator recipes must share the acceptance supervisor's lifetime."""
import configparser
from pathlib import Path
import runpy
import unittest


REPO = Path(__file__).resolve().parents[2]
LAB = runpy.run_path(str(REPO / 'scripts/operator-lab.py'))
SUPERVISOR = 'sigrund-mvp-gate-' + 'a' * 32 + '.service'


class SupervisionTests(unittest.TestCase):
    def manifest(self, supervisor=SUPERVISOR):
        return {'unit': 'sigrund-mvp-0123456789ab.service', 'runtime': '/run/sigrund-mvp-0123456789ab',
                'supervisor_unit': supervisor, 'command': ['/example/sigrund', '--foreground']}

    def test_packaged_service_binds_lifetime_and_orders_stop(self):
        unit = LAB['bind_supervisor']((REPO / 'packaging/sigrund.service').read_text(), SUPERVISOR)
        # systemd accepts repeated After= and accumulates their dependencies.
        config = configparser.ConfigParser(strict=False, interpolation=None)
        config.read_string(unit)
        self.assertEqual(config['Unit']['BindsTo'], SUPERVISOR)
        self.assertIn('After=' + SUPERVISOR + '\n', unit.split('[Service]')[0])
        self.assertIn('After=local-fs.target\n', unit)
        self.assertEqual(config['Service']['RuntimeMaxSec'], '600s')
        self.assertEqual(config['Service']['KillMode'], 'control-group')
        self.assertEqual(config['Service']['SendSIGKILL'], 'yes')
        self.assertEqual(config['Service']['TimeoutStopSec'], '15s')

    def test_foreground_service_has_same_lifetime_guards(self):
        command = LAB['foreground_command'](self.manifest())
        for property in ('BindsTo=' + SUPERVISOR, 'After=' + SUPERVISOR, 'RuntimeMaxSec=600s',
                         'KillMode=control-group', 'SendSIGKILL=yes', 'TimeoutStopSec=15s'):
            self.assertIn('--property=' + property, command)
        self.assertEqual(command[-2:], ['/example/sigrund', '--foreground'])

    def test_standalone_manual_lab_needs_no_acceptance_supervisor(self):
        template = (REPO / 'packaging/sigrund.service').read_text()
        self.assertEqual(LAB['bind_supervisor'](template, None), template)
        self.assertFalse(any('BindsTo=' in arg or 'RuntimeMaxSec=' in arg
                             for arg in LAB['foreground_command'](self.manifest(None))))

    def test_invalid_supervisor_rejected_for_both_recipes(self):
        for invalid in ('', 'other.service', SUPERVISOR + '\nWants=other.service'):
            with self.subTest(supervisor=invalid):
                with self.assertRaises(ValueError):
                    LAB['bind_supervisor']('[Unit]\n[Service]\n', invalid)
                with self.assertRaises(ValueError):
                    LAB['foreground_command'](self.manifest(invalid))


if __name__ == '__main__':
    unittest.main()
