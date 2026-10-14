"""Serialized event integration tests, not proof of live stock ownership."""
from dataclasses import replace
from itertools import permutations
import unittest

from folderfollow_reveal_coordinator import RevealCoordinator, ViewHandle
from folderfollow_reveal_model import Geometry, Identity, RevealModel, Snapshot


FOLDER = '\\SD1\\Slayer\\*'
ROWS = tuple(Identity('\\SD1\\Slayer\\album.flac', cue) for cue in (9, 4, 21, 2, 17))
GEOMETRY = Geometry(0, 80, 260)


class CoordinatorTests(unittest.TestCase):
    def setUp(self):
        self.c = RevealCoordinator()
        self.idle()
        self.view = self.c.activate(FOLDER)
        self.fill()
        self.publish(ROWS[0])
        self.assertEqual(self.observe().reason, 'baseline')

    def idle(self):
        self.assertTrue(self.c.interaction(contact=False, animation=False, settled=True))

    def fill(self, rows=ROWS):
        generation = self.c.generation
        handle = self.c.begin_fill(generation, total_count=len(rows), requested_count=512)
        self.assertIsNotNone(handle)
        for i, row in enumerate(rows):
            self.assertTrue(self.c.append(handle, ordinal=i, identity=row, result=i, list_count=i + 1))
        self.assertTrue(self.c.terminal(handle, result=101, ordinal=len(rows), list_count=len(rows)))
        self.assertIsNotNone(self.c.finish_fill(handle, result=len(rows), list_count=len(rows)))
        return handle

    def publish(self, identity):
        ticket = self.c.playback_begin(identity)
        self.assertIsNotNone(ticket)
        self.assertTrue(self.c.playback_finish(ticket))
        return ticket

    def observe(self, geometry=GEOMETRY):
        return self.c.observe(self.view, geometry)

    def proposal(self):
        self.publish(ROWS[4])
        self.assertEqual(self.observe().reason, 'await-stable-identity')
        result = self.observe()
        self.assertEqual(result.reason, 'reveal')
        self.assertIsNotNone(result.proposal)
        return result.proposal

    def consume(self, proposal, geometry=GEOMETRY):
        return self.c.consume(proposal, self.view, geometry)

    def test_next_transition_survives_transient_publication_gap(self):
        ticket = self.c.playback_begin(ROWS[4])
        self.assertEqual(self.observe().reason, 'await-playback-publication')
        self.assertTrue(self.c.playback_finish(ticket))
        self.assertEqual(self.observe().reason, 'await-stable-identity')
        proposal = self.observe().proposal
        self.assertEqual(proposal.action.row, 4)  # cue 17 is not row 17.
        self.assertEqual(proposal.action.target_y, 140)
        self.assertEqual(self.consume(proposal), proposal.action)
        self.assertIsNone(self.consume(proposal))
        for _ in range(5):
            self.assertIsNone(self.observe().proposal)

    def test_same_file_cue_pairs_are_distinct_and_visible_rows_do_not_move(self):
        for row in ROWS[1:3]:
            self.publish(row)
            self.assertEqual(self.observe().reason, 'await-stable-identity')
            self.assertEqual(self.observe().reason, 'already-visible')

    def test_playback_begin_revokes_proposal_before_finish(self):
        proposal = self.proposal()
        self.c.playback_begin(ROWS[4])
        self.assertIsNone(self.consume(proposal))
        self.assertEqual(self.observe().reason, 'await-playback-publication')

    def test_playback_aba_between_observations_cannot_revive_proposal(self):
        proposal = self.proposal()
        self.publish(ROWS[0])
        self.publish(ROWS[4])
        self.assertIsNone(self.consume(proposal))
        for _ in range(3):
            self.assertIsNone(self.observe().proposal)

    def test_same_value_mutation_revokes_proposal(self):
        proposal = self.proposal()
        self.publish(ROWS[4])
        self.assertIsNone(self.consume(proposal))
        self.assertIsNone(self.observe().proposal)

    def test_clear_restore_before_observation_is_new_baseline_not_reveal(self):
        proposal = self.proposal()
        self.publish(None)
        self.publish(ROWS[4])
        self.assertIsNone(self.consume(proposal))
        self.assertEqual(self.observe().reason, 'baseline')
        self.assertIsNone(self.observe().proposal)

    def test_clear_observation_then_next_publication_is_baseline(self):
        self.publish(None)
        self.assertEqual(self.observe().reason, 'no-valid-playback')
        self.publish(ROWS[4])
        self.assertEqual(self.observe().reason, 'baseline')

    def test_overlapping_and_late_playback_completions_disable(self):
        proposal = self.proposal()
        old = self.c.playback_begin(ROWS[0])
        self.assertIsNone(self.c.playback_begin(ROWS[1]))
        self.assertFalse(self.c.playback_finish(old))
        self.assertIsNone(self.consume(proposal))
        self.assertEqual(self.observe().reason, 'disabled-or-invalid-publication')
        self.assertIsNone(self.c.playback_begin(ROWS[4]))

    def test_duplicate_completion_revokes_proposal(self):
        self.publish(ROWS[1])
        ticket = self.publish(ROWS[4])
        self.observe()
        proposal = self.observe().proposal
        self.assertIsNotNone(proposal)
        self.assertFalse(self.c.playback_finish(ticket))
        self.assertIsNone(self.consume(proposal))

    def test_manual_contact_begin_and_end_between_observations_cancel(self):
        proposal = self.proposal()
        self.c.interaction(contact=True, animation=False, settled=True)
        self.idle()
        self.assertIsNone(self.consume(proposal))
        self.assertIsNone(self.observe().proposal)

    def test_stationary_contact_and_inertia_both_suppress(self):
        for state in ((True, False, True), (False, True, False), (False, False, False)):
            with self.subTest(state=state):
                self.setUp()
                self.c.interaction(contact=state[0], animation=state[1], settled=state[2])
                self.publish(ROWS[4])
                for _ in range(3):
                    self.assertIsNone(self.observe().proposal)
                self.idle()
                for _ in range(3):
                    self.assertIsNone(self.observe().proposal)

    def test_release_does_not_clear_still_running_animation(self):
        proposal = self.proposal()
        self.c.interaction(contact=True, animation=False, settled=True)
        self.c.interaction(contact=False, animation=True, settled=False)
        self.assertTrue(self.c.manual_active)
        self.assertIsNone(self.consume(proposal))
        self.c.interaction(contact=False, animation=False, settled=False)
        self.assertTrue(self.c.manual_active)
        self.idle()
        self.assertFalse(self.c.manual_active)
        self.assertIsNone(self.observe().proposal)

    def test_contact_between_identity_confirmation_samples_cancels(self):
        self.publish(ROWS[4])
        self.observe()
        self.c.interaction(contact=True, animation=False, settled=True)
        self.idle()
        self.assertIsNone(self.observe().proposal)

    def test_gesture_consumes_unobserved_change_after_owner_or_content_reset(self):
        for reset in ('owner', 'contents'):
            with self.subTest(reset=reset):
                self.setUp()
                if reset == 'owner':
                    self.view = self.c.activate(FOLDER)
                else:
                    self.c.replace_contents(self.view)
                self.fill()
                self.publish(ROWS[4])
                self.c.interaction(contact=True, animation=False, settled=True)
                self.idle()
                for _ in range(4):
                    self.assertIsNone(self.observe().proposal)

    def test_gesture_spanning_any_part_of_publication_consumes_change(self):
        for starts_before_writer in (False, True):
            for observe_before_finish in (False, True):
                with self.subTest(starts_before_writer=starts_before_writer,
                                  observe_before_finish=observe_before_finish):
                    self.setUp()
                    if starts_before_writer:
                        self.c.interaction(contact=True, animation=False, settled=True)
                    ticket = self.c.playback_begin(ROWS[4])
                    if not starts_before_writer:
                        self.c.interaction(contact=True, animation=False, settled=True)
                    self.idle()
                    if observe_before_finish:
                        self.assertEqual(self.observe().reason, 'await-playback-publication')
                    self.assertTrue(self.c.playback_finish(ticket))
                    for _ in range(4):
                        self.assertIsNone(self.observe().proposal)
                    # Cancellation is not a permanent ban on later Next.
                    self.publish(ROWS[3])
                    self.observe()
                    self.assertIsNotNone(self.observe().proposal)

    def test_gesture_finished_before_next_writer_allows_new_transition(self):
        self.c.interaction(contact=True, animation=False, settled=True)
        self.idle()
        self.assertIsNotNone(self.consume(self.proposal()))

    def test_all_valid_writer_gesture_orderings_with_no_observations(self):
        for after_reset in (False, True):
            for order in permutations(('begin', 'finish', 'touch', 'release')):
                if (order.index('begin') > order.index('finish')
                        or order.index('touch') > order.index('release')):
                    continue
                with self.subTest(after_reset=after_reset, order=order):
                    self.setUp()
                    if after_reset:
                        self.c.replace_contents(self.view)
                        self.fill()
                    ticket = None
                    for event in order:
                        if event == 'begin':
                            ticket = self.c.playback_begin(ROWS[4])
                        elif event == 'finish':
                            self.assertTrue(self.c.playback_finish(ticket))
                        elif event == 'touch':
                            self.c.interaction(contact=True, animation=False, settled=True)
                        else:
                            self.idle()
                    self.observe()
                    proposal = self.observe().proposal
                    allowed = order.index('release') < order.index('begin')
                    self.assertEqual(proposal is not None, allowed)
                    if allowed:
                        self.assertIsNotNone(self.consume(proposal))
                    for _ in range(3):
                        self.assertIsNone(self.observe().proposal)

    def test_lifecycle_change_during_publication_consumes_transition(self):
        for change in ('owner', 'contents', 'close-reopen'):
            with self.subTest(change=change):
                self.setUp()
                ticket = self.c.playback_begin(ROWS[4])
                if change == 'contents':
                    self.c.replace_contents(self.view)
                else:
                    if change == 'close-reopen':
                        self.c.close(self.view)
                    self.view = self.c.activate(FOLDER)
                self.fill()
                self.assertTrue(self.c.playback_finish(ticket))
                for _ in range(4):
                    self.assertIsNone(self.observe().proposal)

    def test_contact_while_waiting_for_rows_cancels(self):
        self.c.replace_contents(self.view)
        self.observe()
        self.publish(ROWS[4])
        self.observe()
        self.assertEqual(self.observe().reason, 'await-ready-rows')
        self.c.interaction(contact=True, animation=False, settled=True)
        self.idle()
        self.fill()
        self.assertIsNone(self.observe().proposal)

    def test_unknown_initial_interaction_is_not_idle(self):
        self.c = RevealCoordinator()
        self.view = self.c.activate(FOLDER)
        self.fill()
        self.publish(ROWS[0])
        self.observe()
        self.publish(ROWS[4])
        for _ in range(3):
            self.assertIsNone(self.observe().proposal)
        self.idle()
        self.assertIsNone(self.observe().proposal)

    def test_unknown_input_permanently_disables_even_after_new_owner(self):
        proposal = self.proposal()
        self.assertFalse(self.c.interaction(contact=None, animation=False, settled=True))
        self.assertIsNone(self.consume(proposal))
        self.assertIsNone(self.c.activate(FOLDER))
        self.assertFalse(self.c.interaction(contact=False, animation=False, settled=True))

    def test_close_reopen_same_folder_never_revives_old_owner(self):
        proposal = self.proposal()
        old = self.view
        self.assertTrue(self.c.close(old))
        self.view = self.c.activate(FOLDER)
        self.fill()
        self.assertNotEqual(old.epoch, self.view.epoch)
        self.assertIsNone(self.consume(proposal))
        self.assertFalse(self.c.close(old))
        self.assertIsNone(self.observe().proposal)

    def test_content_epoch_changes_even_same_path_and_same_rows(self):
        proposal = self.proposal()
        old = self.c.generation
        new = self.c.replace_contents(self.view)
        self.assertEqual(new.view_epoch, old.view_epoch)
        self.assertGreater(new.contents_epoch, old.contents_epoch)
        self.fill()
        self.assertIsNone(self.consume(proposal))
        self.assertIsNone(self.observe().proposal)

    def test_late_fill_and_close_do_not_invalidate_current_owner(self):
        old_view = self.view
        old_generation = self.c.generation
        old_fill = self.c.begin_fill(old_generation, total_count=5, requested_count=512)
        self.assertIsNone(old_fill)  # A second fill without a new generation is invalid.
        self.c.replace_contents(self.view)
        old_generation = self.c.generation
        old_fill = self.c.begin_fill(old_generation, total_count=5, requested_count=512)
        self.view = self.c.activate(FOLDER)
        self.fill()
        current = self.c.rows
        self.assertFalse(self.c.append(old_fill, ordinal=0, identity=ROWS[0], result=0, list_count=1))
        self.assertIsNone(self.c.finish_fill(old_fill, result=5, list_count=5))
        self.assertIsNone(self.c.begin_fill(old_generation, total_count=5, requested_count=512))
        self.assertFalse(self.c.close(old_view))
        self.assertIs(self.c.rows, current)
        self.assertIsNone(self.c.error)

    def test_foreign_or_copied_handles_do_not_identify_current_view(self):
        proposal = self.proposal()
        self.assertFalse(self.c.close(ViewHandle(self.view.epoch)))
        self.assertIsNone(self.c.replace_contents(replace(self.view)))
        self.assertIsNone(self.c.consume(proposal, replace(self.view), GEOMETRY))
        self.assertIsNone(self.consume(proposal))

    def test_scope_change_to_other_folder_consumes_old_transition(self):
        proposal = self.proposal()
        self.c.replace_contents(self.view, '\\SD1\\Other\\*')
        self.fill(tuple(Identity('\\SD1\\Other\\album.flac', i) for i in range(5)))
        self.assertIsNone(self.consume(proposal))
        self.assertIsNone(self.observe().proposal)

    def test_playback_change_outside_files_does_not_reveal_on_reentry(self):
        self.c.close(self.view)
        self.publish(ROWS[4])
        self.view = self.c.activate(FOLDER)
        self.fill()
        for _ in range(3):
            self.assertIsNone(self.observe().proposal)

    def test_proposal_is_instance_local_and_copy_is_not_authority(self):
        proposal = self.proposal()
        foreign = RevealCoordinator()
        self.assertIsNone(foreign.consume(proposal, self.view, GEOMETRY))
        self.assertIsNone(self.consume(replace(proposal)))
        self.assertIsNone(self.consume(proposal))

    def test_rejected_geometry_consumes_the_only_attempt(self):
        proposal = self.proposal()
        self.assertIsNone(self.consume(proposal, Geometry(80, 80, 260)))
        self.assertIsNone(self.consume(proposal))
        self.assertIsNone(self.observe().proposal)

    def test_next_observation_expires_previous_proposal(self):
        proposal = self.proposal()
        self.observe()
        self.assertIsNone(self.consume(proposal))

    def test_duplicate_fill_finish_revokes_ready_rows_and_proposal(self):
        self.c.replace_contents(self.view)
        fill = self.fill()
        self.observe()
        proposal = self.proposal()
        self.assertIsNone(self.c.finish_fill(fill, result=5, list_count=5))
        self.assertIsNone(self.c.rows)
        self.assertIsNone(self.consume(proposal))

    def test_invalid_or_incomplete_fill_never_proposes(self):
        self.c.replace_contents(self.view)
        fill = self.c.begin_fill(self.c.generation, total_count=5, requested_count=512)
        self.assertFalse(self.c.append(fill, ordinal=0, identity=ROWS[0], result=-1, list_count=1))
        self.publish(ROWS[4])
        for _ in range(3):
            self.assertIsNone(self.observe().proposal)

    def test_missing_rows_wait_is_bounded_and_cannot_later_revive(self):
        self.c.replace_contents(self.view)
        self.observe()
        self.publish(ROWS[4])
        self.observe()
        for _ in range(7):
            self.assertEqual(self.observe().reason, 'await-ready-rows')
        self.assertEqual(self.observe().reason, 'readiness-expired')
        self.fill()
        self.assertIsNone(self.observe().proposal)

    def test_lost_event_revokes_and_cannot_be_repaired_by_idle(self):
        proposal = self.proposal()
        self.c.uncertain()
        self.assertIsNone(self.consume(proposal))
        self.assertIsNone(self.c.activate(FOLDER))
        self.assertFalse(self.c.playback_finish(1))

    def test_epoch_exhaustion_disables_without_reusing_handles(self):
        c = RevealCoordinator(epoch_limit=2)
        self.assertTrue(c.interaction(contact=False, animation=False, settled=True))
        view = c.activate(FOLDER)
        self.assertEqual(view.epoch, 2)
        self.assertIsNone(c.replace_contents(view))
        self.assertEqual(c.error, 'coordinator-epoch-exhausted')
        self.assertIsNone(c.activate(FOLDER))

    def test_malformed_scope_or_geometry_is_not_accepted(self):
        for value in (None, 7, '', 'a:\\bad', 'x' * 260 + '\\*', '\ud800\\*'):
            with self.subTest(value=repr(value)):
                c = RevealCoordinator()
                self.assertIsNone(c.activate(value))
                self.assertIsNone(c.generation)
        self.assertEqual(self.c.observe(self.view, object()).reason, 'invalid-geometry')
        for limit in (True, 0, -1, 1 << 31):
            with self.assertRaises(ValueError):
                RevealCoordinator(epoch_limit=limit)

    def test_malformed_geometry_consumes_unobserved_publication(self):
        for after_reset in (False, True):
            with self.subTest(after_reset=after_reset):
                self.setUp()
                if after_reset:
                    self.c.replace_contents(self.view)
                    self.fill()
                self.publish(ROWS[4])
                self.assertEqual(self.observe(object()).reason, 'invalid-geometry')
                for _ in range(4):
                    self.assertIsNone(self.observe().proposal)

    def test_malformed_uncertainty_reason_is_still_permanent(self):
        for reason in (None, '', 0, False, []):
            with self.subTest(reason=reason):
                self.setUp()
                proposal = self.proposal()
                self.c.uncertain(reason)
                self.assertEqual(self.c.error, 'lost-or-uncertain-event')
                self.assertIsNone(self.consume(proposal))
                self.assertIsNone(self.c.activate(FOLDER))
                self.assertIsNone(self.c.playback_begin(ROWS[0]))

    def test_observed_thirteen_cue_shape_keeps_cue_separate_from_row(self):
        rows = tuple(Identity('a:\\Slayer\\album.flac', cue) for cue in range(13))
        self.view = self.c.activate('a:\\Slayer\\*')
        self.fill(rows)
        self.publish(rows[0])
        self.observe()
        self.publish(rows[3])
        self.observe()
        proposal = self.observe().proposal
        self.assertEqual(proposal.action.target_y, 60)
        self.assertIsNotNone(self.consume(proposal))
        # The real scroll offsets are scalar fixtures, not ownership evidence.
        for y in (270, 533, 328, 0, 214, 0):
            self.c.interaction(contact=True, animation=False, settled=True)
            self.assertIsNone(self.observe(Geometry(y, 80, 260)).proposal)
        self.idle()
        self.assertIsNone(self.observe().proposal)

    def test_deferred_update_preserves_baseline_across_unknown_intermediate_state(self):
        ticket = self.c.playback_update_begin()
        self.assertIsNotNone(ticket)
        for _ in range(12):
            self.assertEqual(self.observe().reason, 'await-playback-publication')
        self.assertTrue(self.c.playback_update_finish(ticket, ROWS[4], succeeded=True))
        self.assertEqual(self.observe().reason, 'await-stable-identity')
        proposal = self.observe().proposal
        self.assertEqual(proposal.action.row, 4)
        self.assertEqual(proposal.action.target_y, 140)
        self.assertIsNotNone(self.consume(proposal))
        for _ in range(4):
            self.assertIsNone(self.observe().proposal)

    def test_deferred_begin_revokes_issued_action_even_for_same_final_value(self):
        proposal = self.proposal()
        ticket = self.c.playback_update_begin()
        self.assertIsNone(self.consume(proposal))
        self.assertEqual(self.observe().reason, 'await-playback-publication')
        self.assertTrue(self.c.playback_update_finish(ticket, ROWS[4], succeeded=True))
        for _ in range(4):
            self.assertIsNone(self.observe().proposal)

    def test_deferred_actual_final_clear_consumes_transition_and_restore_baselines(self):
        ticket = self.c.playback_update_begin()
        self.assertTrue(self.c.playback_update_finish(ticket, None, succeeded=True))
        self.assertEqual(self.observe().reason, 'no-valid-playback')
        ticket = self.c.playback_update_begin()
        self.assertTrue(self.c.playback_update_finish(ticket, ROWS[4], succeeded=True))
        self.assertEqual(self.observe().reason, 'baseline')
        for _ in range(4):
            self.assertIsNone(self.observe().proposal)

    def test_deferred_failed_outcome_consumes_final_value_not_future_success(self):
        for final in (ROWS[4], ROWS[0], None):
            with self.subTest(final=final):
                self.setUp()
                ticket = self.c.playback_update_begin()
                # True means the protocol completed, not that stock succeeded.
                self.assertTrue(self.c.playback_update_finish(ticket, final, succeeded=False))
                self.assertIsNone(self.c.error)
                for _ in range(4):
                    self.assertIsNone(self.observe().proposal)
                if final is None:
                    # A clear has no previous playback identity to reveal from.
                    self.publish(ROWS[0])
                    self.assertEqual(self.observe().reason, 'baseline')
                ticket = self.c.playback_update_begin()
                self.assertTrue(self.c.playback_update_finish(ticket, ROWS[3], succeeded=True))
                self.assertEqual(self.observe().reason, 'await-stable-identity')
                proposal = self.observe().proposal
                self.assertEqual(proposal.action.row, 3)
                self.assertIsNotNone(self.consume(proposal))

    def test_deferred_malformed_outcome_disables_before_identity_publication(self):
        for outcome in (None, 0, 1, -1, 'success', [], object()):
            with self.subTest(outcome=repr(outcome)):
                self.setUp()
                proposal = self.proposal()
                ticket = self.c.playback_update_begin()
                self.assertFalse(self.c.playback_update_finish(ticket, ROWS[0], succeeded=outcome))
                self.assertEqual(self.c.error, 'unknown-playback-update-outcome')
                self.assertIsNone(self.consume(proposal))
                self.assertIsNone(self.c.playback_update_begin())
                self.assertFalse(self.c.playback_update_finish(ticket, ROWS[4], succeeded=True))
                self.assertEqual(self.observe().reason, 'disabled-or-invalid-publication')

    def test_deferred_malformed_final_identity_disables_even_on_stock_failure(self):
        for succeeded in (False, True):
            for identity in (False, '', ROWS[4].path, Identity('', 0), Identity('x', True)):
                with self.subTest(succeeded=succeeded, identity=repr(identity)):
                    self.setUp()
                    ticket = self.c.playback_update_begin()
                    self.assertFalse(self.c.playback_update_finish(ticket, identity, succeeded=succeeded))
                    self.assertEqual(self.c.error, 'unsupported-final-playback-identity')
                    self.assertIsNone(self.c.playback_update_begin())
                    self.assertEqual(self.observe().reason, 'disabled-or-invalid-publication')

    def test_deferred_wrong_completion_mode_and_duplicate_end_disable(self):
        for deferred_begin in (False, True):
            with self.subTest(deferred_begin=deferred_begin):
                self.setUp()
                ticket = (self.c.playback_update_begin() if deferred_begin
                          else self.c.playback_begin(ROWS[4]))
                if deferred_begin:
                    self.assertFalse(self.c.playback_finish(ticket))
                    self.assertFalse(self.c.playback_update_finish(ticket, ROWS[4], succeeded=True))
                else:
                    self.assertFalse(self.c.playback_update_finish(ticket, ROWS[4], succeeded=True))
                    self.assertFalse(self.c.playback_finish(ticket))
                self.assertEqual(self.c.error, 'playback-completion-mode-mismatch')
                self.assertEqual(self.observe().reason, 'disabled-or-invalid-publication')
        self.setUp()
        ticket = self.c.playback_update_begin()
        self.assertTrue(self.c.playback_update_finish(ticket, ROWS[4], succeeded=True))
        self.observe()
        proposal = self.observe().proposal
        self.assertIsNotNone(proposal)
        self.assertFalse(self.c.playback_update_finish(ticket, ROWS[4], succeeded=True))
        self.assertIsNone(self.consume(proposal))

    def test_deferred_gesture_all_orderings_consume_except_completed_prior_gesture(self):
        for order in permutations(('begin', 'finish', 'touch', 'release')):
            if (order.index('begin') > order.index('finish')
                    or order.index('touch') > order.index('release')):
                continue
            with self.subTest(order=order):
                self.setUp()
                ticket = None
                for event in order:
                    if event == 'begin':
                        ticket = self.c.playback_update_begin()
                    elif event == 'finish':
                        self.assertTrue(self.c.playback_update_finish(ticket, ROWS[4], succeeded=True))
                    elif event == 'touch':
                        self.c.interaction(contact=True, animation=False, settled=True)
                    else:
                        self.idle()
                self.observe()
                proposal = self.observe().proposal
                allowed = order.index('release') < order.index('begin')
                self.assertEqual(proposal is not None, allowed)
                if allowed:
                    self.assertIsNotNone(self.consume(proposal))
                for _ in range(4):
                    self.assertIsNone(self.observe().proposal)
                # Cancellation is local to that transition, not a permanent ban.
                ticket = self.c.playback_update_begin()
                self.assertTrue(self.c.playback_update_finish(ticket, ROWS[3], succeeded=True))
                self.observe()
                self.assertIsNotNone(self.consume(self.observe().proposal))

    def test_deferred_navigation_during_unknown_state_consumes_completed_update(self):
        for change in ('owner', 'contents', 'close-reopen', 'closed-at-end'):
            with self.subTest(change=change):
                self.setUp()
                ticket = self.c.playback_update_begin()
                if change == 'contents':
                    self.c.replace_contents(self.view)
                else:
                    if change in ('close-reopen', 'closed-at-end'):
                        self.c.close(self.view)
                    if change != 'closed-at-end':
                        self.view = self.c.activate(FOLDER)
                if change != 'closed-at-end':
                    self.fill()
                    self.assertEqual(self.observe().reason, 'await-playback-publication')
                self.assertTrue(self.c.playback_update_finish(ticket, ROWS[4], succeeded=True))
                if change == 'closed-at-end':
                    self.view = self.c.activate(FOLDER)
                    self.fill()
                for _ in range(4):
                    self.assertIsNone(self.observe().proposal)
                ticket = self.c.playback_update_begin()
                self.assertTrue(self.c.playback_update_finish(ticket, ROWS[3], succeeded=True))
                self.observe()
                self.assertIsNotNone(self.consume(self.observe().proposal))


class PolicyCancellationTests(unittest.TestCase):
    def test_cancel_pending_preserves_and_eventually_consumes_candidate(self):
        model = RevealModel()
        model.observe(Snapshot(ROWS[0], None, 0))
        model.observe(Snapshot(ROWS[4], None, 0))
        model.cancel_pending()
        self.assertIsNone(model.observe(Snapshot(ROWS[4], None, 0)).action)
        model.reset_baseline(ROWS[0])
        self.assertEqual(model.observe(Snapshot(ROWS[0], None, 0)).reason, 'unchanged-or-cancelled')
        model.reset_baseline(None)
        self.assertEqual(model.observe(Snapshot(ROWS[4], None, 0)).reason, 'baseline')


if __name__ == '__main__':
    unittest.main()
