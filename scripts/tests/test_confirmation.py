"""Confirmation fixtures must observe the security flush before answering."""
import os
from pathlib import Path
import pty
import runpy
import termios
import unittest

SHARED = runpy.run_path(str(Path(__file__).resolve().parents[1] / 'verify-runtime.py'))
PROMPT = b'Approve and sign? [y/yes/n/no] '


class ConfirmationTests(unittest.TestCase):
    def setUp(self):
        self.master, self.slave = pty.openpty()
        SHARED['enable_confirmation_packets'](self.master)

    def tearDown(self):
        os.close(self.master)
        os.close(self.slave)

    def test_prompt_without_flush_cannot_accept_confirmation(self):
        os.write(self.slave, PROMPT)
        with self.assertRaisesRegex(AssertionError, 'post-flush prompt'):
            SHARED['read_confirmation_prompt'](self.master, timeout=0.05)

    def test_flush_without_prompt_cannot_accept_confirmation(self):
        termios.tcflush(self.slave, termios.TCIFLUSH)
        os.write(self.slave, b'preparing evidence')
        with self.assertRaisesRegex(AssertionError, 'post-flush prompt'):
            SHARED['read_confirmation_prompt'](self.master, timeout=0.05)

    def test_control_packet_before_text_and_no_stale_flush_for_next_prompt(self):
        termios.tcflush(self.slave, termios.TCIFLUSH)
        os.write(self.slave, PROMPT)
        self.assertIn(PROMPT, SHARED['read_confirmation_prompt'](self.master))
        os.write(self.master, b'yes\n')
        self.assertEqual(os.read(self.slave, 4), b'yes\n')
        os.write(self.slave, PROMPT)
        with self.assertRaisesRegex(AssertionError, 'post-flush prompt'):
            SHARED['read_confirmation_prompt'](self.master, timeout=0.05)


if __name__ == '__main__':
    unittest.main()
