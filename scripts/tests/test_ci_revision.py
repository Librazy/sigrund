"""Verify CI revision selection across PR updates and merge-ref races."""

import importlib.util
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    'ci_revision', Path(__file__).resolve().parents[1] / 'resolve-ci-revision.py',
)
REVISION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REVISION)

REPOSITORY = 'owner/repo'
REF = 'refs/heads/feature'
HEAD = 'a' * 40
BASE = 'b' * 40
MERGE = 'c' * 40


def pull(**changes):
    result = {
        'number': 10, 'state': 'open', 'mergeable': True,
        'merge_commit_sha': MERGE,
        'head': {'sha': HEAD, 'ref': 'feature', 'repo': {'full_name': REPOSITORY}},
        'base': {'sha': BASE},
    }
    result.update(changes)
    return result


def commit(base=BASE, head=HEAD):
    return {'parents': [{'sha': base}, {'sha': head}]}


class RevisionTests(unittest.TestCase):
    def setUp(self):
        self.api = patch.object(REVISION, 'api').start()
        self.sleep = patch.object(REVISION.time, 'sleep').start()
        self.addCleanup(patch.stopall)

    def resolve(self, event='push', ref=REF):
        return REVISION.resolve(REPOSITORY, ref, HEAD, event)

    def test_tag_uses_event_commit_without_querying_prs(self):
        self.assertEqual(self.resolve(ref='refs/tags/v1')[0], HEAD)
        self.api.assert_not_called()

    def test_branch_without_pr_uses_event_commit(self):
        self.api.return_value = [[]]
        self.assertEqual(self.resolve()[0], HEAD)

    def test_filters_foreign_repositories_branches_and_older_heads(self):
        foreign = pull(head={'sha': HEAD, 'ref': 'feature', 'repo': {'full_name': 'fork/repo'}})
        other_branch = pull(head={'sha': HEAD, 'ref': 'other', 'repo': {'full_name': REPOSITORY}})
        older = pull(head={'sha': 'd' * 40, 'ref': 'feature', 'repo': {'full_name': REPOSITORY}})
        self.api.return_value = [[foreign], [older, other_branch]]
        self.assertEqual(self.resolve()[0], HEAD)
        self.assertEqual(self.api.call_count, 1)

    def test_merge_commit_matches_both_current_parents(self):
        self.api.side_effect = [[[pull()]], pull(), commit()]
        self.assertEqual(self.resolve()[0], MERGE)
        self.api.assert_called_with(f'repos/{REPOSITORY}/git/commits/{MERGE}')

    def test_manual_branch_run_can_resolve_merge(self):
        self.api.side_effect = [[[pull()]], pull(), commit()]
        self.assertEqual(self.resolve(event='workflow_dispatch')[0], MERGE)

    def test_conflicting_pr_tests_event_commit(self):
        self.api.side_effect = [[[pull()]], pull(mergeable=False)]
        sha, reason = self.resolve()
        self.assertEqual(sha, HEAD)
        self.assertIn('conflicts', reason)

    def test_closed_or_updated_pr_does_not_test_another_head(self):
        for changed in (pull(state='closed'), pull(head={'sha': 'd' * 40})):
            with self.subTest(changed=changed):
                self.api.side_effect = [[[pull()]], changed]
                self.assertEqual(self.resolve()[0], HEAD)

    def test_waits_for_unknown_mergeability(self):
        self.api.side_effect = [[[pull()]], pull(mergeable=None), pull(), commit()]
        self.assertEqual(self.resolve()[0], MERGE)
        self.sleep.assert_called_once_with(3)

    def test_rejects_stale_merge_parent_until_updated(self):
        for stale in (commit(head='d' * 40), commit(base='d' * 40)):
            with self.subTest(stale=stale):
                self.api.side_effect = [[[pull()]], pull(), stale, pull(), commit()]
                self.assertEqual(self.resolve()[0], MERGE)

    def test_unknown_mergeability_does_not_silently_fall_back(self):
        self.api.side_effect = [[[pull()]]] + [pull(mergeable=None)] * 10
        with self.assertRaisesRegex(RuntimeError, 'no verified merge commit'):
            self.resolve()

    def test_multiple_merge_targets_are_rejected(self):
        self.api.return_value = [[pull(), pull(number=11)]]
        with self.assertRaisesRegex(RuntimeError, 'Multiple open PRs'):
            self.resolve()

    def test_api_failure_does_not_silently_fall_back(self):
        self.api.side_effect = subprocess.CalledProcessError(1, ['gh', 'api'])
        with self.assertRaises(subprocess.CalledProcessError):
            self.resolve()


if __name__ == '__main__':
    unittest.main()
