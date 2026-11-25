"""Qualification must preserve cleanup failures and fail the command."""
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import runpy
import select
import tempfile
import tty
import unittest

API = runpy.run_path(str(Path(__file__).resolve().parents[1] / 'namespace/verify-review.py'))


class QualificationResult(unittest.TestCase):
    def test_cleanup_failure_is_saved_and_raised(self):
        with tempfile.TemporaryDirectory() as directory:
            result = {'result': 'failed', 'cleanup_error': 'container close failed'}
            with self.assertRaises(RuntimeError):
                API['finish_evidence'](Path(directory), result)
            self.assertEqual(json.loads((Path(directory) / 'evidence.json').read_bytes()), result)

    def test_success_returns_only_after_private_evidence_saved(self):
        with tempfile.TemporaryDirectory() as directory:
            API['finish_evidence'](Path(directory), {'result': 'passed'})
            evidence = Path(directory) / 'evidence.json'
            self.assertEqual(evidence.stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(evidence.read_bytes())['result'], 'passed')


class TuiNavigation(unittest.TestCase):
    def test_evidence_selection_retries_when_initial_input_is_drained(self):
        self.check_navigation_retry(b'Approve', b'5', b'Request example-id')

    def test_confirmation_scroll_retries_when_initial_input_is_drained(self):
        self.check_navigation_retry(b'Type yes + Enter', b'\x1b[F', b'Live evidence matched')

    def check_navigation_retry(self, initial_frame, key, changed_frame):
        master, slave = os.openpty()
        self.addCleanup(os.close, master)
        self.addCleanup(os.close, slave)
        tty.setraw(slave)

        def render_after_drain():
            for _ in range(2):
                self.assertTrue(select.select([slave], [], [], 2)[0])
                self.assertEqual(os.read(slave, len(key)), key)
            os.write(slave, changed_frame)

        rendered = bytearray(initial_frame)
        with ThreadPoolExecutor(max_workers=1) as executor:
            operator = executor.submit(render_after_drain)
            API['wait_for_tui_screen'](master, rendered, changed_frame, retry_key=key)
            operator.result()
        self.assertEqual(rendered, initial_frame + changed_frame)
