"""Qualification must preserve cleanup failures and fail the command."""
import json
from pathlib import Path
import runpy
import tempfile
import unittest

API = runpy.run_path(str(Path(__file__).resolve().parents[1] / 'verify-namespace-phase2.py'))


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
