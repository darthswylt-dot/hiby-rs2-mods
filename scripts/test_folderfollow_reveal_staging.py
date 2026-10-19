"""Bounded host staging checks; no claim of live worker or UI ownership."""

from dataclasses import FrozenInstanceError, replace
from itertools import permutations
import unittest

from folderfollow_reveal_coordinator import RevealCoordinator, StagedFillHandle
from folderfollow_reveal_model import Geometry, Identity, INT_MAX


FOLDER = '\\SD1\\Slayer\\*'
OTHER_FOLDER = '\\SD1\\Sleep\\*'
ROWS = tuple(Identity('\\SD1\\Slayer\\album.flac', cue) for cue in (9, 4, 21, 2, 17))
OTHER = Identity('\\SD1\\Sleep\\album.flac', 17)
GEOMETRY = Geometry(0, 80, 260)


class StagedContentsTests(unittest.TestCase):
    def setUp(self):
        self.c = RevealCoordinator()
        self.idle()
        self.view = self.c.activate(FOLDER)
        self.fill()
        self.publish(ROWS[0])
        self.assertEqual(self.observe().reason, 'baseline')

    def idle(self):
        self.assertTrue(self.c.interaction(contact=False, animation=False, settled=True))

    def fill(self):
        handle = self.c.begin_fill(self.c.generation, total_count=len(ROWS), requested_count=512)
        self.assertIsNotNone(handle)
        for ordinal, identity in enumerate(ROWS):
            self.assertTrue(self.c.append(handle, ordinal=ordinal, identity=identity,
                                          result=ordinal, list_count=ordinal + 1))
        self.assertTrue(self.c.terminal(handle, result=101, ordinal=len(ROWS), list_count=len(ROWS)))
        self.assertIsNotNone(self.c.finish_fill(handle, result=len(ROWS), list_count=len(ROWS)))

    def publish(self, identity):
        ticket = self.c.playback_begin(identity)
        self.assertIsNotNone(ticket)
        self.assertTrue(self.c.playback_finish(ticket))

    def observe(self):
        return self.c.observe(self.view, GEOMETRY)

    def proposal(self, identity=ROWS[4]):
        self.publish(identity)
        self.assertEqual(self.observe().reason, 'await-stable-identity')
        result = self.observe()
        self.assertEqual(result.reason, 'reveal')
        self.assertIsNotNone(result.proposal)
        return result.proposal

    def consume(self, proposal):
        return self.c.consume(proposal, self.view, GEOMETRY)

    def assert_no_reveal(self):
        for _ in range(4):
            self.assertIsNone(self.observe().proposal)

    def begin_stage(self, rows=ROWS):
        change = self.c.begin_contents_change(self.view)
        self.assertIsNotNone(change)
        fill = self.c.begin_staged_fill(change, FOLDER, total_count=len(rows), requested_count=512)
        self.assertIsInstance(fill, StagedFillHandle)
        return change, fill

    def append_rows(self, fill, rows=ROWS):
        for ordinal, identity in enumerate(rows):
            self.assertTrue(self.c.append_staged(fill, ordinal=ordinal, identity=identity,
                                                 result=ordinal, list_count=ordinal + 1))

    def seal(self, fill, rows=ROWS):
        self.assertTrue(self.c.terminal_staged(fill, result=101, ordinal=len(rows), list_count=len(rows)))
        self.assertIs(self.c.finish_staged_fill(fill, result=len(rows), list_count=len(rows)), True)

    def stage(self, rows=ROWS):
        change, fill = self.begin_stage(rows)
        self.append_rows(fill, rows)
        self.seal(fill, rows)
        return change, fill

    def promote(self, change):
        generation = self.c.finish_contents_change(change, FOLDER, succeeded=True)
        self.assertIs(generation, self.c.generation)
        self.assertIsNotNone(generation)
        self.assertIsNotNone(self.c.rows)
        self.assertIs(self.c.rows.generation, generation)
        return generation

    def assert_stage_end_fails_closed(self, change):
        self.assertIsNone(self.c.finish_contents_change(change, FOLDER, succeeded=True))
        self.assertIsNotNone(self.c.error)
        self.assertIsNone(self.c.generation)
        self.assertIsNone(self.c.rows)
        self.assertIsNone(self.c.activate(FOLDER))
        self.assertEqual(self.observe().reason, 'disabled-or-invalid-publication')

    def test_complete_staging_stays_private_until_matching_contents_end(self):
        old_generation = self.c.generation
        old_proposal = self.proposal()
        change, fill = self.begin_stage()
        self.assertIs(fill.change, change)
        self.assertEqual(fill.generation.contents_epoch, change.epoch)
        self.assertEqual(fill.generation.view_epoch, self.view.epoch)
        self.append_rows(fill)
        self.seal(fill)
        self.assertTrue(self.c.contents_changing)
        self.assertIsNone(self.c.rows)
        self.assertIsNone(self.c.generation)
        self.assertIsNone(self.consume(old_proposal))
        self.assertEqual(self.observe().reason, 'await-contents-publication')
        self.assertIsNone(self.c.begin_fill(fill.generation, total_count=5, requested_count=512))
        generation = self.promote(change)
        self.assertGreater(generation.contents_epoch, change.epoch)
        self.assertGreater(generation.contents_epoch, old_generation.contents_epoch)
        self.assertIsNot(generation, fill.generation)
        self.assertEqual(self.c.rows.entries, ROWS)
        self.assert_no_reveal()
        self.assertIsNotNone(self.consume(self.proposal(ROWS[3])))
        with self.assertRaises(FrozenInstanceError):
            fill.ticket = 0

    def test_zero_and_maximum_complete_rows_and_signed_cue_boundaries(self):
        largest = tuple(Identity(ROWS[0].path, cue) for cue in (-(1 << 31), INT_MAX, *range(510)))
        for rows in ((), largest):
            with self.subTest(count=len(rows)):
                self.setUp()
                change, _ = self.stage(rows)
                self.promote(change)
                self.assertEqual(self.c.rows.entries, rows)
                self.assertIsNone(self.c.error)
                self.assert_no_reveal()

    def test_bad_begin_metadata_poisons_without_same_phase_retry_or_fallback(self):
        cases = ({'total_count': 513}, {'requested_count': 4}, {'requested_count': 513},
                 {'total_count': True}, {'requested_count': True}, {'offset': 1},
                 {'initial_count': 1}, {'mode': 1}, {'mode': False})
        for override in cases:
            with self.subTest(override=override):
                self.setUp()
                change = self.c.begin_contents_change(self.view)
                metadata = dict(total_count=5, requested_count=512)
                metadata.update(override)
                self.assertIsNone(self.c.begin_staged_fill(change, FOLDER, **metadata))
                self.assertIsNotNone(self.c.error)
                self.assertIsNone(self.c.rows)
                self.assertIsNone(self.c.generation)
                self.assertIsNone(self.c.begin_staged_fill(change, FOLDER, total_count=5, requested_count=512))
                self.assert_stage_end_fails_closed(change)

    def test_bad_staged_folder_is_an_attempt_and_cannot_be_repaired_in_phase(self):
        for folder in (None, '', False, 'missing-wildcard', 'x\0y\\*', '\ud800\\*', 'x' * 260 + '\\*'):
            with self.subTest(folder=repr(folder)):
                self.setUp()
                change = self.c.begin_contents_change(self.view)
                self.assertIsNone(self.c.begin_staged_fill(change, folder, total_count=5, requested_count=512))
                self.assertIsNotNone(self.c.error)
                self.assertIsNone(self.c.begin_staged_fill(change, FOLDER, total_count=5, requested_count=512))
                self.assert_stage_end_fails_closed(change)

    def test_second_staged_begin_poisons_even_after_first_fill_is_complete(self):
        for completed in (False, True):
            with self.subTest(completed=completed):
                self.setUp()
                change, fill = self.begin_stage()
                if completed:
                    self.append_rows(fill)
                    self.seal(fill)
                self.assertIsNone(self.c.begin_staged_fill(change, FOLDER, total_count=5, requested_count=512))
                self.assertIsNotNone(self.c.error)
                self.assertFalse(self.c.finish_staged_fill(fill, result=5, list_count=5))
                self.assert_stage_end_fails_closed(change)

    def test_invalid_append_representation_order_and_duplicate_identity_poison(self):
        invalid = ({'ordinal': 1}, {'ordinal': True}, {'result': -1}, {'result': True},
                   {'list_count': 0}, {'list_count': True}, {'identity': None},
                   {'identity': Identity(ROWS[0].path, True)},
                   {'identity': Identity(ROWS[0].path, INT_MAX + 1)},
                   {'identity': Identity('\\SD1\\Slayer\\' + 'x' * 260, 0)},
                   {'identity': Identity('\\SD1\\Slayer\\\ud800', 0)})
        for override in invalid:
            with self.subTest(override=repr(override)):
                self.setUp()
                change, fill = self.begin_stage()
                metadata = dict(ordinal=0, identity=ROWS[0], result=0, list_count=1)
                metadata.update(override)
                self.assertFalse(self.c.append_staged(fill, **metadata))
                self.assertIsNotNone(self.c.error)
                self.assert_stage_end_fails_closed(change)
        self.setUp()
        change, fill = self.begin_stage()
        self.assertTrue(self.c.append_staged(fill, ordinal=0, identity=ROWS[0], result=0, list_count=1))
        self.assertFalse(self.c.append_staged(fill, ordinal=1, identity=ROWS[0], result=1, list_count=2))
        self.assert_stage_end_fails_closed(change)

    def test_row_scope_is_exact_not_case_folded_prefix_or_current_folder(self):
        wrong = (OTHER, Identity('\\SD1\\slayer\\album.flac', 17),
                 Identity('\\SD1\\SlayerExtra\\album.flac', 17),
                 Identity('\\SD1\\Slayer\\nested\\album.flac', 17),
                 Identity('\\SD1\\Slayer\\*', 17), Identity('album.flac', 17))
        for identity in wrong:
            with self.subTest(identity=identity):
                self.setUp()
                change, fill = self.begin_stage()
                self.assertFalse(self.c.append_staged(fill, ordinal=0, identity=identity, result=0, list_count=1))
                self.assertIsNotNone(self.c.error)
                self.assert_stage_end_fails_closed(change)

    def test_staging_copies_identity_before_source_mutation(self):
        source = Identity(ROWS[0].path, ROWS[0].cue)
        change, fill = self.begin_stage((source,))
        self.append_rows(fill, (source,))
        object.__setattr__(source, 'path', OTHER.path)
        object.__setattr__(source, 'cue', OTHER.cue)
        self.seal(fill, (source,))
        self.promote(change)
        self.assertEqual(self.c.rows.entries, (ROWS[0],))
        self.assertIsNot(self.c.rows.entries[0], source)
        object.__setattr__(source, 'path', '')
        self.assertEqual(self.c.rows.entries, (ROWS[0],))

    def test_terminal_and_finish_require_original_complete_counts(self):
        for fault in ('missing-terminal', 'wrong-terminal', 'wrong-ordinal', 'wrong-count', 'bad-finish'):
            with self.subTest(fault=fault):
                self.setUp()
                change, fill = self.begin_stage()
                self.append_rows(fill)
                if fault == 'missing-terminal':
                    self.assertFalse(self.c.finish_staged_fill(fill, result=5, list_count=5))
                elif fault == 'bad-finish':
                    self.assertTrue(self.c.terminal_staged(fill, result=101, ordinal=5, list_count=5))
                    self.assertFalse(self.c.finish_staged_fill(fill, result=4, list_count=5))
                else:
                    result = 100 if fault == 'wrong-terminal' else 101
                    ordinal = 4 if fault == 'wrong-ordinal' else 5
                    count = 4 if fault == 'wrong-count' else 5
                    self.assertFalse(self.c.terminal_staged(fill, result=result, ordinal=ordinal, list_count=count))
                self.assertIsNotNone(self.c.error)
                self.assert_stage_end_fails_closed(change)

    def test_contents_success_before_staged_completion_permanently_disables(self):
        for progress in ('begin-only', 'partial', 'all-rows', 'terminal-only'):
            with self.subTest(progress=progress):
                self.setUp()
                change, fill = self.begin_stage()
                if progress == 'partial':
                    self.assertTrue(self.c.append_staged(fill, ordinal=0, identity=ROWS[0], result=0, list_count=1))
                elif progress in ('all-rows', 'terminal-only'):
                    self.append_rows(fill)
                if progress == 'terminal-only':
                    self.assertTrue(self.c.terminal_staged(fill, result=101, ordinal=5, list_count=5))
                self.assert_stage_end_fails_closed(change)
                self.assertFalse(self.c.finish_staged_fill(fill, result=5, list_count=5))

    def test_completed_rows_cannot_be_relabelled_with_different_final_folder(self):
        change, _ = self.stage()
        self.assertIsNone(self.c.finish_contents_change(change, OTHER_FOLDER, succeeded=True))
        self.assertIsNotNone(self.c.error)
        self.assertIsNone(self.c.generation)
        self.assertIsNone(self.c.rows)
        self.assertIsNone(self.c.activate(OTHER_FOLDER))

    def test_duplicate_events_after_seal_before_end_revoke_staged_completion(self):
        for event in ('append', 'terminal', 'finish'):
            with self.subTest(event=event):
                self.setUp()
                change, fill = self.stage()
                if event == 'append':
                    result = self.c.append_staged(fill, ordinal=0, identity=ROWS[0], result=0, list_count=1)
                elif event == 'terminal':
                    result = self.c.terminal_staged(fill, result=101, ordinal=5, list_count=5)
                else:
                    result = self.c.finish_staged_fill(fill, result=5, list_count=5)
                self.assertFalse(result)
                self.assertIsNotNone(self.c.error)
                self.assert_stage_end_fails_closed(change)

    def test_late_current_promoted_events_revoke_rows_and_proposal_until_new_generation(self):
        for event in ('append', 'terminal', 'finish'):
            with self.subTest(event=event):
                self.setUp()
                change, fill = self.stage()
                generation = self.promote(change)
                proposal = self.proposal()
                if event == 'append':
                    result = self.c.append_staged(fill, ordinal=0, identity=ROWS[0], result=0, list_count=1)
                elif event == 'terminal':
                    result = self.c.terminal_staged(fill, result=101, ordinal=5, list_count=5)
                else:
                    result = self.c.finish_staged_fill(fill, result=5, list_count=5)
                self.assertFalse(result)
                self.assertIsNotNone(self.c.error)
                self.assertIsNone(self.c.rows)
                self.assertIsNone(self.consume(proposal))
                self.assertFalse(self.c.finish_staged_fill(fill, result=5, list_count=5))
                replacement = self.c.replace_contents(self.view)
                self.assertGreater(replacement.contents_epoch, generation.contents_epoch)
                self.fill()
                self.assertIsNone(self.c.error)
                self.assert_no_reveal()
                self.assertIsNotNone(self.consume(self.proposal(ROWS[3])))

    def test_forged_phase_and_fill_handles_cannot_mutate_or_finish_real_stage(self):
        change, fill = self.begin_stage()
        for fake_change in (None, object(), replace(change)):
            self.assertIsNone(self.c.begin_staged_fill(fake_change, None, total_count=True, requested_count=0))
            self.assertFalse(self.c.invalidate_staged_fill(fake_change))
        for fake in (None, object(), replace(fill),
                     StagedFillHandle(change, fill.generation, fill.ticket),
                     StagedFillHandle(replace(change), fill.generation, fill.ticket)):
            with self.subTest(fake=type(fake).__name__):
                self.assertFalse(self.c.append_staged(fake, ordinal=-1, identity=None, result=-1, list_count=-1))
                self.assertFalse(self.c.terminal_staged(fake, result=-1, ordinal=-1, list_count=-1))
                self.assertFalse(self.c.finish_staged_fill(fake, result=-1, list_count=-1))
                self.assertIsNone(self.c.error)
        self.append_rows(fill)
        self.seal(fill)
        self.promote(change)
        proposal = self.proposal()
        self.assertFalse(self.c.finish_staged_fill(replace(fill), result=5, list_count=5))
        self.assertIsNotNone(self.consume(proposal))

    def test_old_jobs_are_ignored_after_new_phase_new_owner_or_close(self):
        for boundary in ('new-phase', 'replace', 'new-owner', 'close-reopen'):
            with self.subTest(boundary=boundary):
                self.setUp()
                old_change, old_fill = self.stage()
                self.promote(old_change)
                if boundary == 'replace':
                    self.c.replace_contents(self.view)
                elif boundary == 'new-owner':
                    self.view = self.c.activate(FOLDER)
                elif boundary == 'close-reopen':
                    self.assertTrue(self.c.close(self.view))
                    self.view = self.c.activate(FOLDER)
                change, fill = self.begin_stage()
                self.assertFalse(self.c.append_staged(old_fill, ordinal=0, identity=None, result=0, list_count=1))
                self.assertFalse(self.c.terminal_staged(old_fill, result=101, ordinal=5, list_count=5))
                self.assertFalse(self.c.finish_staged_fill(old_fill, result=5, list_count=5))
                self.assertFalse(self.c.invalidate_staged_fill(old_change))
                self.assertIsNone(self.c.error)
                self.append_rows(fill)
                self.seal(fill)
                self.promote(change)
                self.assertIsNotNone(self.consume(self.proposal()))

    def test_same_folder_aba_keeps_phase_tickets_and_generations_distinct(self):
        first_change, first_fill = self.stage()
        first_generation = self.promote(first_change)
        second_change, second_fill = self.stage()
        self.assertGreater(second_fill.ticket, first_fill.ticket)
        self.assertGreater(second_change.epoch, first_generation.contents_epoch)
        self.assertIsNot(second_fill.change, first_fill.change)
        self.assertEqual(second_fill.generation.folder, first_fill.generation.folder)
        self.assertFalse(self.c.finish_staged_fill(first_fill, result=5, list_count=5))
        self.assertIsNone(self.c.finish_contents_change(first_change, FOLDER, succeeded=True))
        second_generation = self.promote(second_change)
        self.assertGreater(second_generation.contents_epoch, first_generation.contents_epoch)
        self.assertEqual(self.c.rows.entries, ROWS)
        self.assertIsNone(self.c.error)

    def test_promoted_generation_rejects_second_normal_fill(self):
        change, _ = self.stage()
        generation = self.promote(change)
        proposal = self.proposal()
        self.assertIsNone(self.c.begin_fill(generation, total_count=5, requested_count=512))
        self.assertIsNotNone(self.c.error)
        self.assertIsNone(self.c.rows)
        self.assertIsNone(self.consume(proposal))
        self.assertIsNotNone(self.c.replace_contents(self.view))
        self.fill()
        self.assertIsNone(self.c.error)
        self.assertIsNotNone(self.consume(self.proposal(ROWS[3])))

    def test_explicit_loss_or_mutation_invalidates_loading_sealed_and_promoted_stage(self):
        for progress in ('loading', 'sealed', 'promoted'):
            with self.subTest(progress=progress):
                self.setUp()
                change = self.c.begin_contents_change(self.view)
                self.assertFalse(self.c.invalidate_staged_fill(change))
                fill = self.c.begin_staged_fill(change, FOLDER, total_count=5, requested_count=512)
                if progress != 'loading':
                    self.append_rows(fill)
                    self.seal(fill)
                proposal = None
                if progress == 'promoted':
                    self.promote(change)
                    proposal = self.proposal()
                self.assertTrue(self.c.invalidate_staged_fill(change))
                self.assertIsNotNone(self.c.error)
                self.assertIsNone(self.c.rows)
                self.assertIsNone(self.consume(proposal))
                if progress == 'promoted':
                    self.assertIsNotNone(self.c.replace_contents(self.view))
                    self.fill()
                    self.assertFalse(self.c.invalidate_staged_fill(change))
                    self.assertIsNone(self.c.error)
                else:
                    self.assert_stage_end_fails_closed(change)

    def test_failed_contents_outcome_discards_even_poisoned_stage_without_permanent_fault(self):
        for progress in ('loading', 'sealed', 'poisoned'):
            with self.subTest(progress=progress):
                self.setUp()
                change, fill = self.begin_stage()
                if progress == 'sealed':
                    self.append_rows(fill)
                    self.seal(fill)
                elif progress == 'poisoned':
                    self.assertFalse(self.c.append_staged(fill, ordinal=1, identity=ROWS[0], result=1, list_count=2))
                    self.assertIsNotNone(self.c.error)
                self.assertIsNone(self.c.finish_contents_change(change, FOLDER, succeeded=False))
                self.assertIsNone(self.c.error)
                self.assertFalse(self.c.contents_changing)
                self.assertIsNone(self.c.rows)
                self.assertIsNone(self.c.generation)
                self.assertFalse(self.c.finish_staged_fill(fill, result=5, list_count=5))
                self.view = self.c.activate(FOLDER)
                self.fill()
                self.assertIsNotNone(self.consume(self.proposal()))

    def test_unknown_outcome_or_uncertainty_discards_stage_and_permanently_disables(self):
        for outcome in (None, 0, 1, 'success', 'uncertain-event'):
            with self.subTest(outcome=outcome):
                self.setUp()
                change, fill = self.stage()
                if outcome == 'uncertain-event':
                    self.c.uncertain('lost-owner-coverage')
                else:
                    self.assertIsNone(self.c.finish_contents_change(change, FOLDER, succeeded=outcome))
                self.assertIsNotNone(self.c.error)
                self.assertIsNone(self.c.rows)
                self.assertIsNone(self.c.generation)
                self.assertFalse(self.c.finish_staged_fill(fill, result=5, list_count=5))
                self.assertIsNone(self.c.finish_contents_change(change, FOLDER, succeeded=True))
                self.assertIsNone(self.c.activate(FOLDER))

    def test_staging_playback_boundary_orderings_do_not_catch_up_old_transition(self):
        for order in permutations(('contents-begin', 'contents-end', 'playback-begin', 'playback-end')):
            if (order.index('contents-begin') > order.index('contents-end')
                    or order.index('playback-begin') > order.index('playback-end')):
                continue
            with self.subTest(order=order):
                self.setUp()
                change = ticket = None
                for event in order:
                    if event == 'contents-begin':
                        change, _ = self.stage()
                    elif event == 'contents-end':
                        self.promote(change)
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

    def test_gesture_and_playback_aba_during_staging_are_consumed_at_end(self):
        for release_before_end in (False, True):
            with self.subTest(release_before_end=release_before_end):
                self.setUp()
                change, fill = self.begin_stage()
                self.assertTrue(self.c.interaction(contact=True, animation=False, settled=True))
                for identity in (ROWS[4], None, ROWS[0], ROWS[4]):
                    self.publish(identity)
                self.append_rows(fill)
                self.seal(fill)
                if release_before_end:
                    self.idle()
                self.promote(change)
                if not release_before_end:
                    self.idle()
                self.assert_no_reveal()
                self.assertIsNotNone(self.consume(self.proposal(ROWS[3])))

    def test_cancellation_preserves_staging_counters_and_end_epoch_exhaustion_is_closed(self):
        first_change, first_fill = self.begin_stage()
        self.view = self.c.activate(FOLDER)
        second_change, second_fill = self.begin_stage()
        self.assertGreater(second_fill.ticket, first_fill.ticket)
        self.assertGreater(second_change.epoch, first_change.epoch)
        self.assertFalse(self.c.invalidate_staged_fill(first_change))
        self.assertFalse(self.c.finish_staged_fill(first_fill, result=5, list_count=5))
        self.append_rows(second_fill)
        self.seal(second_fill)
        self.promote(second_change)
        c = RevealCoordinator(epoch_limit=3)
        self.assertTrue(c.interaction(contact=False, animation=False, settled=True))
        view = c.activate(FOLDER)
        change = c.begin_contents_change(view)
        fill = c.begin_staged_fill(change, FOLDER, total_count=0, requested_count=512)
        self.assertIsNotNone(fill)
        self.assertTrue(c.terminal_staged(fill, result=101, ordinal=0, list_count=0))
        self.assertTrue(c.finish_staged_fill(fill, result=0, list_count=0))
        self.assertIsNone(c.finish_contents_change(change, FOLDER, succeeded=True))
        self.assertEqual(c.error, 'coordinator-epoch-exhausted')
        self.assertIsNone(c.rows)
        self.assertIsNone(c.generation)
        self.assertIsNone(c.activate(FOLDER))

    def test_no_staging_requested_keeps_generation_only_mode_but_late_stage_is_stale(self):
        change = self.c.begin_contents_change(self.view)
        self.assertFalse(self.c.invalidate_staged_fill(change))
        generation = self.c.finish_contents_change(change, FOLDER, succeeded=True)
        self.assertIsNotNone(generation)
        self.assertIsNone(self.c.rows)
        self.assertIsNone(self.c.begin_staged_fill(change, FOLDER, total_count=5, requested_count=512))
        self.assertFalse(self.c.invalidate_staged_fill(change))
        self.assertIsNone(self.c.error)
        self.fill()
        self.assertIsNotNone(self.consume(self.proposal()))

    def test_job_started_before_change_cannot_be_adopted_by_staged_publication(self):
        generation = self.c.replace_contents(self.view)
        old_job = self.c.begin_fill(generation, total_count=5, requested_count=512)
        self.assertTrue(self.c.append(old_job, ordinal=0, identity=ROWS[0],
                                      result=0, list_count=1))
        change, stage = self.begin_stage()
        self.assertFalse(self.c.append_staged(old_job, ordinal=1, identity=ROWS[1],
                                              result=1, list_count=2))
        self.assertFalse(self.c.append(old_job, ordinal=1, identity=ROWS[1],
                                      result=1, list_count=2))
        self.append_rows(stage)
        self.seal(stage)
        self.promote(change)
        proposal = self.proposal()
        self.assertFalse(self.c.terminal(old_job, result=101, ordinal=5, list_count=5))
        self.assertIsNone(self.c.finish_fill(old_job, result=5, list_count=5))
        self.assertFalse(self.c.finish_staged_fill(old_job, result=5, list_count=5))
        self.assertIsNone(self.c.error)
        self.assertIsNotNone(self.consume(proposal))

    def test_invalid_final_folder_discards_stage_without_changing_legacy_failure_policy(self):
        for folder in (None, '', False, 'no-wildcard', '\ud800\\*'):
            with self.subTest(folder=repr(folder)):
                self.setUp()
                change, fill = self.stage()
                self.assertIsNone(self.c.finish_contents_change(change, folder, succeeded=True))
                self.assertFalse(self.c.contents_changing)
                self.assertIsNone(self.c.rows)
                self.assertIsNone(self.c.generation)
                self.assertIsNone(self.c.error)
                self.assertFalse(self.c.finish_staged_fill(fill, result=5, list_count=5))
                self.assertIsNone(self.c.finish_contents_change(change, FOLDER, succeeded=True))
                self.view = self.c.activate(FOLDER)
                self.fill()
                self.assertIsNone(self.c.error)
                self.assertIsNotNone(self.consume(self.proposal()))


if __name__ == '__main__':
    unittest.main()
