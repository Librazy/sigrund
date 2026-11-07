"""Regression checks for pending fixture reviews across registration changes."""
import copy
from pathlib import Path
import runpy
from types import SimpleNamespace
import unittest

API = runpy.run_path(str(Path(__file__).resolve().parents[1] / 'verify-namespace-phase15.py'))


def owner(instance):
    value = SimpleNamespace(alive=True, acquisition={
        'pid': 4242, 'instance_id': instance, 'daemon_epoch': 'epoch',
        'lifecycle': {'registration_id': None, 'registration_revision': None},
    })
    value.live = lambda: value.alive
    return value


class PendingReviewTests(unittest.TestCase):
    def test_replacement_cannot_authorize_a_pending_review_for_the_old_owner(self):
        registry = API['FixtureRegistry']()
        old, new = owner('old'), owner('new')
        registry.register('B', old, 'a' * 64, 1000)
        pending = registry.pending('B')
        self.assertTrue(registry.permits(pending))
        registry.register('B', new, 'a' * 64, 1000)
        self.assertTrue(old.alive)
        self.assertFalse(registry.permits(pending))
        self.assertTrue(registry.permits(registry.pending('B')))

    def test_revocation_and_anchor_death_each_invalidate_the_review(self):
        registry = API['FixtureRegistry']()
        retained = owner('one')
        registry.register('B', retained, 'a' * 64, 1000)
        pending = registry.pending('B')
        retained.alive = False
        self.assertFalse(registry.permits(pending))
        with self.assertRaises(ValueError):
            registry.register('B', retained, 'a' * 64, 1000)
        retained.alive = True
        registry.revoke('B')
        self.assertFalse(registry.permits(pending))
        registry.register('B', retained, 'a' * 64, 1000)
        self.assertFalse(registry.permits(pending))

    def test_registration_profile_and_declared_owner_are_bound_to_the_review(self):
        registry = API['FixtureRegistry']()
        registry.register('B', owner('one'), 'a' * 64, 1000)
        pending = registry.pending('B')
        retained, original, acquisition = registry.entries['B']
        for field, value in [('profile_sha256', 'b' * 64), ('owner_uid', 1001)]:
            changed = copy.deepcopy(original)
            changed[field] = value
            registry.entries['B'] = (retained, changed, acquisition)
            self.assertFalse(registry.permits(pending))

    def test_returned_records_cannot_mutate_the_retained_generation(self):
        registry = API['FixtureRegistry']()
        registration, acquisition = registry.register('B', owner('one'), 'a' * 64, 1000)
        pending = registry.pending('B')
        registration['owner_uid'] = 0
        acquisition['instance_id'] = 'substitution'
        self.assertTrue(registry.permits(pending))


if __name__ == '__main__':
    unittest.main()

class ArtifactTrustTests(unittest.TestCase):
    def test_writable_ancestor_is_rejected_even_for_a_private_child(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            child = Path(directory) / 'private'
            child.mkdir(mode=0o700)
            with self.assertRaises(ValueError):
                API['trusted_directory'](child)
