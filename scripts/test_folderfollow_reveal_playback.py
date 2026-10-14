#!/usr/bin/env python3
"""Sequential playback-event tests, not a live concurrency simulation."""

from dataclasses import FrozenInstanceError
from itertools import permutations
import unittest

from folderfollow_reveal_model import Identity, INT_MAX
from folderfollow_reveal_playback import PlaybackPublication


A = Identity('\\SD1\\Slayer\\01.flac', -1)
B = Identity('\\SD1\\Slayer\\02.flac', 17)


class PlaybackPublicationTests(unittest.TestCase):
    def setUp(self):
        self.p = PlaybackPublication()

    def publish(self, value):
        ticket = self.p.begin(value)
        self.assertIsNotNone(ticket)
        self.assertFalse(self.p.ready)
        self.assertIsNone(self.p.identity)
        self.assertTrue(self.p.finish(ticket))
        self.assertTrue(self.p.ready)
        self.assertEqual(self.p.identity, value)
        return ticket

    def assert_poisoned(self):
        self.assertFalse(self.p.ready)
        self.assertIsNone(self.p.identity)
        self.assertIsInstance(self.p.error, str)
        first_error = self.p.error
        self.assertIsNone(self.p.begin(A))
        self.assertFalse(self.p.finish(self.p.revision))
        self.assertFalse(self.p.ready)
        self.assertIsNone(self.p.identity)
        self.assertEqual(self.p.error, first_error)

    def test_initial_state_is_not_a_completed_clear(self):
        self.assertFalse(self.p.ready)
        self.assertIsNone(self.p.identity)
        self.assertEqual(self.p.revision, 0)
        self.assertIsNone(self.p.error)

    def test_begin_withdraws_previous_value_until_exact_completion(self):
        self.assertEqual(self.publish(A), 1)
        ticket = self.p.begin(B)
        self.assertEqual(ticket, 2)
        self.assertEqual(self.p.revision, 2)
        self.assertFalse(self.p.ready)
        self.assertIsNone(self.p.identity)
        self.assertTrue(self.p.finish(ticket))
        self.assertEqual(self.p.identity, B)
        self.assertEqual(self.p.revision, 2)

    def test_aba_same_value_and_clear_restore_have_distinct_revisions(self):
        observed = []
        for value in (A, B, A, A, None, A, None, None):
            observed.append(self.publish(value))
        self.assertEqual(observed, list(range(1, 9)))
        self.assertEqual(self.p.revision, 8)
        self.assertTrue(self.p.ready)
        self.assertIsNone(self.p.identity)
        self.assertIsNone(self.p.error)

    def test_clear_is_not_ready_until_completed(self):
        self.publish(A)
        ticket = self.p.begin(None)
        self.assertIsNone(self.p.identity)
        self.assertFalse(self.p.ready)
        self.assertTrue(self.p.finish(ticket))
        self.assertIsNone(self.p.identity)
        self.assertTrue(self.p.ready)

    def test_copied_before_end_and_independent_of_source_object(self):
        source = Identity(A.path, A.cue)
        ticket = self.p.begin(source)
        # Deliberately bypass the frozen dataclass to prove no source retention.
        object.__setattr__(source, 'path', B.path)
        object.__setattr__(source, 'cue', B.cue)
        self.assertTrue(self.p.finish(ticket))
        self.assertEqual(self.p.identity, A)
        self.assertIsNot(self.p.identity, source)
        object.__setattr__(source, 'path', '')
        self.assertEqual(self.p.identity, A)
        with self.assertRaises(FrozenInstanceError):
            self.p.identity.cue = 99

    def test_overlap_poisoned_for_both_callback_orders(self):
        for order in permutations((1, 2)):
            with self.subTest(order=order):
                self.setUp()
                self.assertEqual(self.p.begin(A), 1)
                self.assertIsNone(self.p.begin(B))
                self.assertEqual(self.p.revision, 2)
                for ticket in order:
                    self.assertFalse(self.p.finish(ticket))
                self.assertEqual(self.p.error, 'overlapping-playback-mutation')
                self.assert_poisoned()

    def test_same_value_or_clear_overlap_is_still_a_fault(self):
        for first, second in ((A, A), (A, None), (None, A), (None, None)):
            with self.subTest(first=first, second=second):
                self.setUp()
                self.p.begin(first)
                self.assertIsNone(self.p.begin(second))
                self.assertFalse(self.p.finish(1))
                self.assert_poisoned()

    def test_completion_without_begin_permanently_poisoned(self):
        for ticket in (1, 0, -1, True, False, None, '1', 1.0, INT_MAX + 1):
            with self.subTest(ticket=ticket):
                self.setUp()
                self.assertFalse(self.p.finish(ticket))
                self.assertEqual(self.p.revision, 0)
                self.assert_poisoned()

    def test_invalid_or_wrong_completion_rejects_later_correct_callback(self):
        for wrong in (0, 2, -1, True, False, None, '1', 1.0, INT_MAX + 1):
            with self.subTest(wrong=wrong):
                self.setUp()
                self.assertEqual(self.p.begin(A), 1)
                self.assertFalse(self.p.finish(wrong))
                self.assertFalse(self.p.finish(1))
                self.assert_poisoned()

    def test_duplicate_end_withdraws_published_value(self):
        ticket = self.publish(A)
        self.assertFalse(self.p.finish(ticket))
        self.assert_poisoned()

    def test_old_end_during_next_write_cannot_republish_either_value(self):
        old = self.publish(A)
        current = self.p.begin(B)
        self.assertFalse(self.p.finish(old))
        self.assertFalse(self.p.finish(current))
        self.assert_poisoned()

    def test_invalid_begin_revokes_and_advances_even_after_publication(self):
        class IdentitySubclass(Identity):
            pass

        class PathSubclass(str):
            pass

        invalid = (object(), True, '', A.path, (A.path, A.cue),
                   Identity('', 0), Identity('x\0y', 0),
                   Identity('x', True), Identity('x', False),
                   Identity('x', INT_MAX + 1), Identity('x', -(1 << 31) - 1),
                   Identity('x', 0.0), Identity(None, 0),
                   Identity('x' * 260, 0), Identity('\ud800', 0),
                   Identity('\U0001F600' * 130, 0),
                   IdentitySubclass(A.path, 0), Identity(PathSubclass('x'), 0))
        for value in invalid:
            with self.subTest(value=repr(value)):
                self.setUp()
                self.publish(A)
                self.assertIsNone(self.p.begin(value))
                self.assertEqual(self.p.revision, 2)
                self.assertEqual(self.p.error, 'unsupported-playback-identity')
                self.assertFalse(self.p.finish(2))
                self.assert_poisoned()

    def test_valid_boundary_cues_and_utf16_units(self):
        for value in (Identity('x', -(1 << 31)), Identity('x', INT_MAX),
                      Identity('x' * 259, 0),
                      Identity('\U0001F600' * 129 + 'x', 0)):
            with self.subTest(value=value):
                self.publish(value)

    def test_exhaustion_revokes_ready_value_and_never_wraps(self):
        self.p = PlaybackPublication(ticket_limit=2)
        self.assertEqual(self.publish(A), 1)
        self.assertEqual(self.publish(B), 2)
        self.assertIsNone(self.p.begin(A))
        self.assertEqual(self.p.revision, 2)
        self.assertEqual(self.p.error, 'revision-exhausted')
        self.assertFalse(self.p.finish(1))
        self.assertFalse(self.p.finish(2))
        for _ in range(3):
            self.assertIsNone(self.p.begin(None))
            self.assertEqual(self.p.revision, 2)
        self.assert_poisoned()

    def test_exhaustion_during_pending_write_prevents_its_completion(self):
        self.p = PlaybackPublication(ticket_limit=1)
        self.assertEqual(self.p.begin(A), 1)
        self.assertIsNone(self.p.begin(B))
        self.assertFalse(self.p.finish(1))
        self.assert_poisoned()

    def test_every_later_begin_attempt_advances_until_saturation(self):
        self.p = PlaybackPublication(ticket_limit=3)
        for revision, value in ((1, False), (2, A), (3, None), (3, B)):
            self.assertIsNone(self.p.begin(value))
            self.assertEqual(self.p.revision, revision)
            self.assertFalse(self.p.ready)
        self.assertEqual(self.p.error, 'unsupported-playback-identity')

    def test_loss_at_idle_loading_or_ready_is_permanent(self):
        for stage in ('idle', 'loading', 'ready', 'cleared'):
            with self.subTest(stage=stage):
                self.setUp()
                if stage == 'loading':
                    self.p.begin(A)
                elif stage in ('ready', 'cleared'):
                    self.publish(A if stage == 'ready' else None)
                self.p.invalidate()
                self.assertEqual(self.p.error, 'lost-or-uncertain-playback')
                self.assertFalse(self.p.finish(1))
                self.assert_poisoned()

    def test_invalid_reason_still_invalidates_and_preserves_first_fault(self):
        for reason in (None, False, 0, ''):
            self.setUp()
            self.publish(A)
            self.p.invalidate(reason)
            self.assertEqual(self.p.error, 'lost-or-uncertain-playback')
            self.p.invalidate('different-reason')
            self.assertEqual(self.p.error, 'lost-or-uncertain-playback')
            self.assert_poisoned()
        self.setUp()
        self.p.invalidate('capture-overflow')
        self.assertEqual(self.p.error, 'capture-overflow')
        self.assert_poisoned()

    def test_invalid_constructor_bound(self):
        for limit in (None, 0, -1, True, False, 1.0, '1', INT_MAX + 1):
            with self.subTest(limit=limit):
                with self.assertRaises(ValueError):
                    PlaybackPublication(limit)
        self.assertEqual(PlaybackPublication(INT_MAX).revision, 0)

    def test_no_public_reset_or_mutable_properties(self):
        self.publish(A)
        for name in ('identity', 'ready', 'revision', 'error'):
            with self.subTest(name=name):
                with self.assertRaises(AttributeError):
                    setattr(self.p, name, None)
        self.assertFalse(hasattr(self.p, 'reset'))
        self.assertFalse(hasattr(self.p, 'activate'))

    def test_deferred_begin_withdraws_until_owned_final_identity(self):
        self.publish(A)
        ticket = self.p.begin_update()
        self.assertEqual(ticket, 2)
        for _ in range(4):
            # Unknown intermediate stock state is not submitted as a clear.
            self.assertFalse(self.p.ready)
            self.assertIsNone(self.p.identity)
            self.assertIsNone(self.p.error)
            self.assertEqual(self.p.revision, ticket)
        self.assertTrue(self.p.finish_update(ticket, B))
        self.assertTrue(self.p.ready)
        self.assertEqual(self.p.identity, B)
        self.assertEqual(self.p.revision, ticket)

    def test_deferred_final_none_is_completed_clear_only_at_end(self):
        self.publish(A)
        ticket = self.p.begin_update()
        self.assertFalse(self.p.ready)
        self.assertIsNone(self.p.identity)
        self.assertTrue(self.p.finish_update(ticket, None))
        self.assertTrue(self.p.ready)
        self.assertIsNone(self.p.identity)
        self.assertIsNone(self.p.error)

    def test_deferred_end_copies_final_value_without_retaining_source(self):
        source = Identity(A.path, A.cue)
        ticket = self.p.begin_update()
        # BEGIN has not retained source: only the coherent END argument counts.
        object.__setattr__(source, 'path', B.path)
        object.__setattr__(source, 'cue', B.cue)
        self.assertTrue(self.p.finish_update(ticket, source))
        self.assertIsNot(self.p.identity, source)
        object.__setattr__(source, 'path', '')
        object.__setattr__(source, 'cue', 999)
        self.assertEqual(self.p.identity, B)

    def test_mixing_completion_modes_permanently_withdraws(self):
        for deferred_begin in (False, True):
            with self.subTest(deferred_begin=deferred_begin):
                self.setUp()
                ticket = (self.p.begin_update() if deferred_begin
                          else self.p.begin(A))
                if deferred_begin:
                    self.assertFalse(self.p.finish(ticket))
                    self.assertFalse(self.p.finish_update(ticket, B))
                else:
                    self.assertFalse(self.p.finish_update(ticket, B))
                    self.assertFalse(self.p.finish(ticket))
                self.assertEqual(self.p.error, 'playback-completion-mode-mismatch')
                self.assert_poisoned()

    def test_deferred_malformed_final_identity_is_permanent(self):
        invalid = (False, '', A.path, (A.path, A.cue), object(),
                   Identity('', 0), Identity('x\0y', 0), Identity(None, 0),
                   Identity('x', True), Identity('x', 1.0),
                   Identity('x', INT_MAX + 1), Identity('x' * 260, 0),
                   Identity('\ud800', 0), Identity('\U0001F600' * 130, 0))
        for value in invalid:
            with self.subTest(value=repr(value)):
                self.setUp()
                self.publish(A)
                ticket = self.p.begin_update()
                self.assertFalse(self.p.finish_update(ticket, value))
                self.assertEqual(self.p.error, 'unsupported-final-playback-identity')
                self.assertFalse(self.p.finish_update(ticket, B))
                self.assert_poisoned()

    def test_deferred_overlap_with_either_begin_mode_never_means_nested(self):
        for first_deferred, second_deferred in ((True, True), (True, False), (False, True)):
            with self.subTest(first=first_deferred, second=second_deferred):
                self.setUp()
                first = self.p.begin_update() if first_deferred else self.p.begin(A)
                second = self.p.begin_update() if second_deferred else self.p.begin(B)
                self.assertIsNone(second)
                self.assertEqual(self.p.revision, 2)
                self.assertEqual(self.p.error, 'overlapping-playback-mutation')
                self.assertFalse(self.p.finish_update(first, A))
                self.assertFalse(self.p.finish(first))
                self.assert_poisoned()

    def test_deferred_invalid_stale_or_duplicate_end_cannot_publish(self):
        for wrong in (0, 2, -1, True, False, None, '1', 1.0, INT_MAX + 1):
            with self.subTest(wrong=wrong):
                self.setUp()
                ticket = self.p.begin_update()
                self.assertFalse(self.p.finish_update(wrong, B))
                self.assertFalse(self.p.finish_update(ticket, B))
                self.assert_poisoned()
        self.setUp()
        old = self.p.begin_update()
        self.assertTrue(self.p.finish_update(old, A))
        current = self.p.begin_update()
        self.assertFalse(self.p.finish_update(old, B))
        self.assertFalse(self.p.finish_update(current, B))
        self.assert_poisoned()
        self.setUp()
        ticket = self.p.begin_update()
        self.assertTrue(self.p.finish_update(ticket, B))
        self.assertFalse(self.p.finish_update(ticket, B))
        self.assert_poisoned()

    def test_deferred_revisions_share_nonwrapping_limit_with_eager_mode(self):
        self.p = PlaybackPublication(ticket_limit=3)
        self.assertEqual(self.publish(A), 1)
        ticket = self.p.begin_update()
        self.assertEqual(ticket, 2)
        self.assertTrue(self.p.finish_update(ticket, A))
        self.assertEqual(self.publish(B), 3)
        self.assertIsNone(self.p.begin_update())
        self.assertEqual(self.p.revision, 3)
        self.assertEqual(self.p.error, 'revision-exhausted')
        self.assertFalse(self.p.finish_update(ticket, A))
        self.assert_poisoned()


if __name__ == '__main__':
    unittest.main()
