"""Host-only two-phase contents lifecycle, not live UI ownership evidence."""

from dataclasses import FrozenInstanceError, replace
from itertools import permutations
import unittest

from folderfollow_reveal_coordinator import ContentChangeHandle, RevealCoordinator, ViewHandle
from folderfollow_reveal_model import Geometry, Identity


FOLDER = '\\SD1\\Slayer\\*'
ROWS = tuple(Identity('\\SD1\\Slayer\\album.flac', cue) for cue in (9, 4, 21, 2, 17))
OTHER_FOLDER = '\\SD1\\Sleep\\*'
OTHER_ROWS = tuple(Identity('\\SD1\\Sleep\\album.flac', cue) for cue in (9, 4, 21, 2, 17))
GEOMETRY = Geometry(0, 80, 260)


class ContentsLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.c = RevealCoordinator()
        self.idle()
        self.view = self.c.activate(FOLDER)
        self.completed_fill = self.fill()
        self.publish(ROWS[0])
        self.assertEqual(self.observe().reason, 'baseline')

    def idle(self):
        self.assertTrue(self.c.interaction(contact=False, animation=False, settled=True))

    def fill(self, rows=ROWS):
        generation = self.c.generation
        handle = self.c.begin_fill(generation, total_count=len(rows), requested_count=512)
        self.assertIsNotNone(handle)
        for ordinal, row in enumerate(rows):
            self.assertTrue(self.c.append(handle, ordinal=ordinal, identity=row,
                                          result=ordinal, list_count=ordinal + 1))
        self.assertTrue(self.c.terminal(handle, result=101, ordinal=len(rows), list_count=len(rows)))
        self.assertIsNotNone(self.c.finish_fill(handle, result=len(rows), list_count=len(rows)))
        return handle

    def publish(self, identity):
        ticket = self.c.playback_begin(identity)
        self.assertIsNotNone(ticket)
        self.assertTrue(self.c.playback_finish(ticket))

    def observe(self):
        return self.c.observe(self.view, GEOMETRY)

    def consume(self, proposal):
        return self.c.consume(proposal, self.view, GEOMETRY)

    def proposal(self, identity=ROWS[4]):
        self.publish(identity)
        self.assertEqual(self.observe().reason, 'await-stable-identity')
        result = self.observe()
        self.assertEqual(result.reason, 'reveal')
        self.assertIsNotNone(result.proposal)
        return result.proposal

    def assert_no_reveal(self):
        for _ in range(4):
            self.assertIsNone(self.observe().proposal)

    def test_begin_revokes_rows_generation_and_proposal_before_completion(self):
        self.assertFalse(self.c.contents_changing)
        old_generation = self.c.generation
        proposal = self.proposal()
        change = self.c.begin_contents_change(self.view)
        self.assertIsInstance(change, ContentChangeHandle)
        self.assertIs(change.view, self.view)
        self.assertTrue(self.c.contents_changing)
        self.assertIsNone(self.c.generation)
        self.assertIsNone(self.c.rows)
        self.assertIsNone(self.consume(proposal))
        self.assertEqual(self.observe().reason, 'await-contents-publication')
        for generation in (None, old_generation):
            self.assertIsNone(self.c.begin_fill(generation, total_count=5, requested_count=512))
        self.assertIsNone(self.c.error)
        with self.assertRaises(FrozenInstanceError):
            change.epoch = 0
        with self.assertRaises(AttributeError):
            self.c.contents_changing = False

    def test_begin_revokes_inflight_fill_and_all_late_fill_callbacks(self):
        old_generation = self.c.replace_contents(self.view)
        old_fill = self.c.begin_fill(old_generation, total_count=5, requested_count=512)
        self.assertTrue(self.c.append(old_fill, ordinal=0, identity=ROWS[0], result=0, list_count=1))
        change = self.c.begin_contents_change(self.view)
        self.assertFalse(self.c.append(old_fill, ordinal=1, identity=ROWS[1], result=1, list_count=2))
        self.assertFalse(self.c.terminal(old_fill, result=101, ordinal=5, list_count=5))
        self.assertIsNone(self.c.finish_fill(old_fill, result=5, list_count=5))
        self.assertIsNotNone(self.c.finish_contents_change(change, FOLDER, succeeded=True))
        self.fill()
        rows = self.c.rows
        self.assertIsNone(self.c.finish_fill(old_fill, result=5, list_count=5))
        self.assertIs(self.c.rows, rows)
        self.assertIsNone(self.c.error)

    def test_success_publishes_new_generation_only_at_end_then_needs_new_fill(self):
        old_generation = self.c.generation
        change = self.c.begin_contents_change(self.view)
        self.assertGreater(change.epoch, old_generation.contents_epoch)
        self.assertIsNone(self.c.generation)
        generation = self.c.finish_contents_change(change, FOLDER, succeeded=True)
        self.assertIs(generation, self.c.generation)
        self.assertEqual(generation.view_epoch, self.view.epoch)
        self.assertEqual(generation.folder, FOLDER)
        self.assertGreater(generation.contents_epoch, change.epoch)
        self.assertFalse(self.c.contents_changing)
        self.assertIsNone(self.c.rows)
        self.assertIsNone(self.c.begin_fill(old_generation, total_count=5, requested_count=512))
        self.fill()
        self.assert_no_reveal()
        proposal = self.proposal()
        self.assertEqual(proposal.action.row, 4)
        self.assertIsNotNone(self.consume(proposal))

    def test_same_owner_can_rebind_folder_and_reveal_only_a_later_track(self):
        change = self.c.begin_contents_change(self.view)
        self.publish(OTHER_ROWS[0])
        self.assertEqual(self.observe().reason, 'await-contents-publication')
        generation = self.c.finish_contents_change(change, OTHER_FOLDER, succeeded=True)
        self.assertEqual(generation.folder, OTHER_FOLDER)
        self.assertEqual(generation.view_epoch, self.view.epoch)
        self.fill(OTHER_ROWS)
        self.assert_no_reveal()
        proposal = self.proposal(OTHER_ROWS[4])
        self.assertEqual(proposal.action.identity, OTHER_ROWS[4])
        self.assertIsNotNone(self.consume(proposal))

    def test_same_path_repeated_changes_never_reuse_or_revive_old_handle(self):
        first = self.c.begin_contents_change(self.view)
        first_generation = self.c.finish_contents_change(first, FOLDER, succeeded=True)
        self.fill()
        second = self.c.begin_contents_change(self.view)
        self.assertGreater(second.epoch, first_generation.contents_epoch)
        self.assertIsNone(self.c.finish_contents_change(first, OTHER_FOLDER, succeeded=True))
        self.assertTrue(self.c.contents_changing)
        second_generation = self.c.finish_contents_change(second, FOLDER, succeeded=True)
        self.assertGreater(second_generation.contents_epoch, second.epoch)
        self.fill()
        proposal = self.proposal()
        # A duplicate completed callback is stale, not a new invalidation.
        self.assertIsNone(self.c.finish_contents_change(second, OTHER_FOLDER, succeeded=False))
        self.assertIs(self.c.generation, second_generation)
        self.assertIsNotNone(self.consume(proposal))
        self.assertIsNone(self.c.error)

    def test_close_cancels_phase_and_late_finish_cannot_reopen_owner(self):
        change = self.c.begin_contents_change(self.view)
        self.assertTrue(self.c.close(self.view))
        self.assertFalse(self.c.contents_changing)
        self.assertIsNone(self.c.finish_contents_change(change, FOLDER, succeeded=True))
        self.assertIsNone(self.c.generation)
        self.assertEqual(self.observe().reason, 'inactive-view')
        self.assertIsNone(self.c.error)
        old_view = self.view
        self.view = self.c.activate(FOLDER)
        self.assertIsNot(self.view, old_view)
        self.fill()
        self.assert_no_reveal()
        self.assertIsNotNone(self.consume(self.proposal()))

    def test_new_owner_cancels_phase_and_stale_bad_outcome_is_ignored(self):
        change = self.c.begin_contents_change(self.view)
        self.view = self.c.activate(FOLDER)
        self.fill()
        generation, rows = self.c.generation, self.c.rows
        proposal = self.proposal()
        self.assertFalse(self.c.contents_changing)
        self.assertIsNone(self.c.finish_contents_change(change, OTHER_FOLDER, succeeded=None))
        self.assertIs(self.c.generation, generation)
        self.assertIs(self.c.rows, rows)
        self.assertIsNone(self.c.error)
        self.assertIsNotNone(self.consume(proposal))

    def test_foreign_begin_handle_is_ignored_even_during_current_phase(self):
        generation, rows = self.c.generation, self.c.rows
        for foreign in (None, object(), ViewHandle(self.view.epoch), replace(self.view)):
            with self.subTest(foreign=type(foreign).__name__):
                self.assertIsNone(self.c.begin_contents_change(foreign))
                self.assertIs(self.c.generation, generation)
                self.assertIs(self.c.rows, rows)
                self.assertFalse(self.c.contents_changing)
        change = self.c.begin_contents_change(self.view)
        self.assertIsNone(self.c.begin_contents_change(replace(self.view)))
        self.assertTrue(self.c.contents_changing)
        self.assertIsNone(self.c.error)
        self.assertIsNotNone(self.c.finish_contents_change(change, FOLDER, succeeded=True))

    def test_forged_completion_is_not_authority_and_does_not_consume_real_handle(self):
        change = self.c.begin_contents_change(self.view)
        forged = (None, object(), replace(change),
                  ContentChangeHandle(self.view, change.epoch),
                  ContentChangeHandle(replace(self.view), change.epoch))
        for handle in forged:
            with self.subTest(handle=type(handle).__name__):
                self.assertIsNone(self.c.finish_contents_change(handle, OTHER_FOLDER, succeeded=None))
                self.assertTrue(self.c.contents_changing)
                self.assertIsNone(self.c.generation)
                self.assertIsNone(self.c.error)
        self.assertIsNotNone(self.c.finish_contents_change(change, FOLDER, succeeded=True))
        self.fill()
        self.assertIsNotNone(self.consume(self.proposal()))

    def test_overlapping_same_owner_change_permanently_disables(self):
        change = self.c.begin_contents_change(self.view)
        self.assertIsNone(self.c.begin_contents_change(self.view))
        self.assertEqual(self.c.error, 'overlapping-contents-change')
        self.assertFalse(self.c.contents_changing)
        self.assertIsNone(self.c.finish_contents_change(change, FOLDER, succeeded=True))
        self.assertIsNone(self.c.activate(FOLDER))
        self.assertEqual(self.observe().reason, 'disabled-or-invalid-publication')

    def test_legacy_replace_during_phase_permanently_disables(self):
        for folder in (None, FOLDER, OTHER_FOLDER):
            with self.subTest(folder=folder):
                self.setUp()
                change = self.c.begin_contents_change(self.view)
                self.assertIsNone(self.c.replace_contents(self.view, folder))
                self.assertEqual(self.c.error, 'mixed-contents-change-protocol')
                self.assertFalse(self.c.contents_changing)
                self.assertIsNone(self.c.finish_contents_change(change, FOLDER, succeeded=True))
                self.assertIsNone(self.c.activate(FOLDER))

    def test_failed_completion_deactivates_owner_without_permanent_fault(self):
        change = self.c.begin_contents_change(self.view)
        self.publish(ROWS[4])
        self.assertIsNone(self.c.finish_contents_change(change, FOLDER, succeeded=False))
        self.assertFalse(self.c.contents_changing)
        self.assertIsNone(self.c.generation)
        self.assertIsNone(self.c.rows)
        self.assertEqual(self.observe().reason, 'inactive-view')
        self.assertIsNone(self.c.error)
        self.assertIsNone(self.c.begin_contents_change(self.view))
        self.assertIsNone(self.c.finish_contents_change(change, FOLDER, succeeded=True))
        self.view = self.c.activate(FOLDER)
        self.fill()
        self.assert_no_reveal()
        self.assertIsNotNone(self.consume(self.proposal(ROWS[3])))

    def test_invalid_final_folder_deactivates_owner_without_publishing_generation(self):
        invalid = (None, '', False, 'no-wildcard', 'x\0y\\*', '\ud800\\*', 'x' * 260 + '\\*')
        for folder in invalid:
            with self.subTest(folder=repr(folder)):
                self.setUp()
                change = self.c.begin_contents_change(self.view)
                self.assertIsNone(self.c.finish_contents_change(change, folder, succeeded=True))
                self.assertFalse(self.c.contents_changing)
                self.assertIsNone(self.c.generation)
                self.assertIsNone(self.c.rows)
                self.assertEqual(self.observe().reason, 'inactive-view')
                self.assertIsNone(self.c.error)
                self.assertIsNone(self.c.finish_contents_change(change, FOLDER, succeeded=True))

    def test_unknown_outcome_is_permanent_not_truthy_success_or_retry(self):
        for outcome in (None, 0, 1, -1, 'success', [], object()):
            with self.subTest(outcome=repr(outcome)):
                self.setUp()
                change = self.c.begin_contents_change(self.view)
                self.assertIsNone(self.c.finish_contents_change(change, FOLDER, succeeded=outcome))
                self.assertIsNotNone(self.c.error)
                self.assertFalse(self.c.contents_changing)
                self.assertIsNone(self.c.generation)
                self.assertIsNone(self.c.finish_contents_change(change, FOLDER, succeeded=True))
                self.assertIsNone(self.c.activate(FOLDER))
                self.assertEqual(self.observe().reason, 'disabled-or-invalid-publication')

    def test_all_completed_playback_during_phase_is_consumed_at_contents_end(self):
        for deferred in (False, True):
            for identities in ((ROWS[4],), (None, ROWS[4]), (ROWS[4], ROWS[0], ROWS[4])):
                with self.subTest(deferred=deferred, identities=identities):
                    self.setUp()
                    change = self.c.begin_contents_change(self.view)
                    for identity in identities:
                        if deferred:
                            ticket = self.c.playback_update_begin()
                            self.assertTrue(self.c.playback_update_finish(ticket, identity, succeeded=True))
                        else:
                            self.publish(identity)
                        self.assertEqual(self.observe().reason, 'await-contents-publication')
                    self.assertIsNotNone(self.c.finish_contents_change(change, FOLDER, succeeded=True))
                    self.fill()
                    self.assert_no_reveal()
                    self.assertIsNotNone(self.consume(self.proposal(ROWS[3])))

    def test_all_logical_playback_contents_orderings_cancel_overlapping_transition(self):
        for order in permutations(('contents-begin', 'contents-end', 'playback-begin', 'playback-end')):
            if (order.index('contents-begin') > order.index('contents-end')
                    or order.index('playback-begin') > order.index('playback-end')):
                continue
            with self.subTest(order=order):
                self.setUp()
                change = ticket = None
                for event in order:
                    if event == 'contents-begin':
                        change = self.c.begin_contents_change(self.view)
                    elif event == 'contents-end':
                        self.assertIsNotNone(self.c.finish_contents_change(change, FOLDER, succeeded=True))
                        self.fill()
                    elif event == 'playback-begin':
                        ticket = self.c.playback_update_begin()
                    else:
                        self.assertTrue(self.c.playback_update_finish(ticket, ROWS[4], succeeded=True))
                self.observe()
                proposal = self.observe().proposal
                allowed = order.index('contents-end') < order.index('playback-begin')
                self.assertEqual(proposal is not None, allowed)
                if allowed:
                    self.assertIsNotNone(self.consume(proposal))
                self.assert_no_reveal()
                self.assertIsNotNone(self.consume(self.proposal(ROWS[3])))

    def test_gesture_and_playback_during_phase_do_not_survive_idle_completion(self):
        for release_before_end in (False, True):
            with self.subTest(release_before_end=release_before_end):
                self.setUp()
                change = self.c.begin_contents_change(self.view)
                self.assertTrue(self.c.interaction(contact=True, animation=False, settled=True))
                self.publish(ROWS[4])
                self.assertEqual(self.observe().reason, 'await-contents-publication')
                if release_before_end:
                    self.idle()
                self.assertIsNotNone(self.c.finish_contents_change(change, FOLDER, succeeded=True))
                self.fill()
                if not release_before_end:
                    self.idle()
                self.assert_no_reveal()
                self.assertIsNotNone(self.consume(self.proposal(ROWS[3])))

    def test_epoch_exhaustion_at_either_boundary_never_reuses_generation(self):
        for limit in (2, 3):
            with self.subTest(limit=limit):
                c = RevealCoordinator(epoch_limit=limit)
                self.assertTrue(c.interaction(contact=False, animation=False, settled=True))
                view = c.activate(FOLDER)
                self.assertEqual(view.epoch, 2)
                change = c.begin_contents_change(view)
                if limit == 2:
                    self.assertIsNone(change)
                else:
                    self.assertEqual(change.epoch, 3)
                    self.assertTrue(c.contents_changing)
                    self.assertIsNone(c.finish_contents_change(change, FOLDER, succeeded=True))
                self.assertEqual(c.error, 'coordinator-epoch-exhausted')
                self.assertFalse(c.contents_changing)
                self.assertIsNone(c.generation)
                self.assertIsNone(c.rows)
                self.assertIsNone(c.activate(FOLDER))
                self.assertEqual(c.observe(view, GEOMETRY).reason, 'disabled-or-invalid-publication')


if __name__ == '__main__':
    unittest.main()
