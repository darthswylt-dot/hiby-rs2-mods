#!/usr/bin/env python3
"""Positive host queue protocol checks, not native lifetime/thread evidence."""

from dataclasses import FrozenInstanceError, replace
import unittest

from folderfollow_reveal_model import INT_MAX
from folderfollow_reveal_paint_queue import (
    Cancellation, OwnerHandle, PaintQueue, U32_MAX,
)


RECT = (1, 16, 8, 8)


class PaintQueueTests(unittest.TestCase):
    def setUp(self):
        self.q = PaintQueue(controller_word=0x1000)
        self.owner = self.q.open_owner('explorer', 0x2000)

    def enqueue(self, owner=None, rectangle=RECT, **options):
        return self.q.enqueue(self.owner if owner is None else owner,
                              rectangle, **options)

    def assert_no_authority(self, snapshot):
        for name in ('native_record_lease_proven', 'native_payload_coherence_proven',
                     'native_object_lifetime_proven', 'current_owner_proven',
                     'request_freshness_proven', 'contents_current',
                     'coherent_capture', 'autoscroll_authorized'):
            self.assertIs(getattr(snapshot, name), False, name)

    def test_empty_snapshot_has_no_native_or_ui_authority(self):
        snapshot = PaintQueue().snapshot()
        self.assertEqual((snapshot.pending_ids, snapshot.active_id,
                          snapshot.owner_count, snapshot.serial), ((), None, 0, 0))
        self.assertFalse(snapshot.closed or snapshot.active_cancelled)
        self.assertIsNone(snapshot.error)
        self.assert_no_authority(snapshot)

    def test_payload_preserves_owned_raw_controller_engine_and_metadata(self):
        entry = self.enqueue(metadata=0x12345678)
        claim = self.q.claim()
        self.assertEqual(claim.entry_id, entry)
        self.assertIs(claim.owner, self.owner)
        self.assertEqual((claim.payload.controller_word, claim.payload.engine_word,
                          claim.payload.name, claim.payload.rectangle,
                          claim.payload.metadata),
                         (0x1000, 0x2000, 'explorer', RECT, 0x12345678))

    def test_owner_handle_is_frozen_and_same_values_do_not_equal_generations(self):
        with self.assertRaises(FrozenInstanceError):
            self.owner.ticket = 99
        other = self.q.open_owner('explorer', 0x2000)
        self.assertIsNot(other, self.owner)
        self.assertNotEqual(other, self.owner)
        self.assertEqual(other.ticket, 2)

    def test_claim_and_payload_are_frozen(self):
        self.enqueue()
        claim = self.q.claim()
        for target, field, value in ((claim, 'entry_id', 99),
                                     (claim.payload, 'metadata', 99),
                                     (claim.payload, 'rectangle', (0, 0, 0, 0))):
            with self.assertRaises(FrozenInstanceError):
                setattr(target, field, value)

    def test_enqueue_copies_mutable_rectangle_before_publication(self):
        rectangle = list(RECT)
        self.enqueue(rectangle=rectangle)
        rectangle[:] = [101, 202, 303, 404]
        claim = self.q.claim()
        self.assertIs(type(claim.payload.rectangle), tuple)
        self.assertEqual(claim.payload.rectangle, RECT)

    def test_all_unsigned_word_endpoints_are_supported_as_values_only(self):
        q = PaintQueue(controller_word=U32_MAX)
        owner = q.open_owner('zero-is-not-liveness', 0)
        q.enqueue(owner, (0, U32_MAX, 0, U32_MAX), metadata=U32_MAX)
        payload = q.claim().payload
        self.assertEqual((payload.engine_word, payload.controller_word,
                          payload.rectangle, payload.metadata),
                         (0, U32_MAX, (0, U32_MAX, 0, U32_MAX), U32_MAX))
        self.assert_no_authority(q.snapshot())

    def test_identical_payloads_receive_different_entry_ids(self):
        self.assertEqual((self.enqueue(), self.enqueue()), (2, 3))
        self.assertEqual(self.q.snapshot().pending_ids, (2, 3))

    def test_owner_and_entry_tickets_share_one_persistent_serial(self):
        self.assertEqual(self.enqueue(), 2)
        other = self.q.open_owner('other', 0x2000)
        self.assertEqual(other.ticket, 3)
        self.assertEqual(self.enqueue(other), 4)
        self.assertEqual(self.q.snapshot().serial, 4)

    def test_claim_retains_original_fifo_head_until_ack(self):
        self.enqueue()
        self.enqueue()
        claim = self.q.claim()
        self.assertEqual(claim.entry_id, 2)
        self.assertEqual(self.q.snapshot().pending_ids, (2, 3))
        self.assertEqual(self.q.snapshot().active_id, 2)

    def test_second_consumer_cannot_claim_an_active_head(self):
        self.enqueue()
        self.enqueue()
        self.q.claim()
        before = self.q.snapshot()
        self.assertIsNone(self.q.claim())
        self.assertEqual(self.q.snapshot(), before)

    def test_complete_removes_only_claimed_entry_and_keeps_next_head(self):
        self.enqueue()
        self.enqueue()
        claim = self.q.claim()
        completion = self.q.complete(claim, succeeded=True)
        self.assertEqual((completion.entry_id, completion.outcome), (2, 'completed'))
        self.assertEqual(self.q.snapshot().pending_ids, (3,))
        self.assertIsNone(self.q.snapshot().active_id)

    def test_failed_completion_still_acks_its_exact_entry(self):
        self.enqueue()
        completion = self.q.complete(self.q.claim(), succeeded=False)
        self.assertEqual((completion.entry_id, completion.outcome), (2, 'failed'))
        self.assertEqual(self.q.snapshot().pending_ids, ())

    def test_next_claim_after_ack_follows_fifo(self):
        self.enqueue(rectangle=(1, 2, 3, 4))
        self.enqueue(rectangle=(5, 6, 7, 8))
        self.q.complete(self.q.claim(), succeeded=True)
        second = self.q.claim()
        self.assertEqual((second.entry_id, second.payload.rectangle), (3, (5, 6, 7, 8)))

    def test_duplicate_completion_cannot_remove_next_entry(self):
        self.enqueue()
        self.enqueue()
        old = self.q.claim()
        self.q.complete(old, succeeded=True)
        current = self.q.claim()
        before = self.q.snapshot()
        self.assertIsNone(self.q.complete(old, succeeded=True))
        self.assertEqual(self.q.snapshot(), before)
        self.assertEqual(self.q.complete(current, succeeded=True).entry_id, 3)

    def test_foreign_claim_is_rejected_without_current_mutation(self):
        other = PaintQueue()
        owner = other.open_owner('explorer', 0x2000)
        other.enqueue(owner, RECT)
        foreign = other.claim()
        self.enqueue()
        self.q.claim()
        before = self.q.snapshot()
        self.assertIsNone(self.q.complete(foreign, succeeded=True))
        self.assertEqual(self.q.snapshot(), before)

    def test_copied_claim_with_identical_fields_is_not_the_active_claim(self):
        self.enqueue()
        claim = self.q.claim()
        before = self.q.snapshot()
        self.assertIsNone(self.q.complete(replace(claim), succeeded=True))
        self.assertEqual(self.q.snapshot(), before)
        self.assertEqual(self.q.complete(claim, succeeded=True).outcome, 'completed')

    def test_handles_never_invoke_external_equality_or_hash(self):
        class Hostile:
            def __eq__(self, other):
                raise AssertionError('caller equality was invoked')

            def __hash__(self):
                raise AssertionError('caller hash was invoked')

        hostile = Hostile()
        self.enqueue()
        self.q.claim()
        before = self.q.snapshot()
        self.assertIsNone(self.q.enqueue(hostile, RECT))
        self.assertIsNone(self.q.complete(hostile, succeeded=True))
        self.assertEqual(self.q.retire(hostile), Cancellation())
        self.assertFalse(self.q.release_owner(hostile))
        self.assertEqual(self.q.snapshot(), before)

    def test_copied_or_forged_owner_cannot_enqueue_or_retire_real_owner(self):
        before = self.q.snapshot()
        for handle in (replace(self.owner), OwnerHandle(1, 'explorer', 0x2000),
                       None, 1, True):
            self.assertIsNone(self.q.enqueue(handle, RECT))
            self.assertEqual(self.q.retire(handle), Cancellation())
            self.assertFalse(self.q.release_owner(handle))
        self.assertEqual(self.q.snapshot(), before)

    def test_foreign_owner_with_same_ticket_and_fields_is_rejected(self):
        foreign = PaintQueue().open_owner('explorer', 0x2000)
        self.assertEqual(foreign.ticket, self.owner.ticket)
        self.assertIsNone(self.q.enqueue(foreign, RECT))
        self.assertEqual(self.enqueue(), 2)

    def test_purge_removes_only_matching_queued_entries(self):
        other = self.q.open_owner('other', 0x2000)
        first, second, third = self.enqueue(), self.enqueue(other), self.enqueue()
        cancellation = self.q.purge('explorer')
        self.assertEqual(cancellation.queued_ids, (first, third))
        self.assertEqual(cancellation.retired_owner_ids, (self.owner.ticket,))
        self.assertIsNone(cancellation.claimed_id)
        self.assertEqual(self.q.snapshot().pending_ids, (second,))

    def test_purge_retires_every_same_name_generation(self):
        other = self.q.open_owner('explorer', 0x3000)
        self.enqueue()
        self.enqueue(other)
        cancelled = self.q.purge('explorer')
        self.assertEqual(cancelled.retired_owner_ids, (1, 2))
        self.assertIsNone(self.enqueue())
        self.assertIsNone(self.enqueue(other))
        self.assertEqual(self.q.snapshot().pending_ids, ())

    def test_purge_retains_active_head_cancelled_and_removes_later_matches(self):
        other = self.q.open_owner('other', 0x2000)
        first, second, third = self.enqueue(), self.enqueue(), self.enqueue(other)
        claim = self.q.claim()
        cancelled = self.q.purge('explorer')
        self.assertEqual((cancelled.queued_ids, cancelled.claimed_id), ((second,), first))
        self.assertEqual(self.q.snapshot().pending_ids, (first, third))
        self.assertTrue(self.q.snapshot().active_cancelled)
        self.assertIsNone(self.q.claim())
        self.assertEqual(self.q.complete(claim, succeeded=True).outcome, 'cancelled')
        self.assertEqual(self.q.snapshot().pending_ids, (third,))

    def test_cancelled_ack_never_reports_completed_or_failed(self):
        for succeeded in (False, True):
            q = PaintQueue()
            owner = q.open_owner('a', 0)
            q.enqueue(owner, RECT)
            claim = q.claim()
            q.retire(owner)
            self.assertEqual(q.complete(claim, succeeded=succeeded).outcome, 'cancelled')
            self.assertEqual(q.snapshot().pending_ids, ())

    def test_late_producer_cannot_revive_a_purged_generation(self):
        self.q.purge('explorer')
        before = self.q.snapshot()
        self.assertIsNone(self.enqueue())
        self.assertEqual(self.q.snapshot(), before)

    def test_fresh_generation_can_reuse_identical_raw_words_after_purge(self):
        self.q.purge('explorer')
        fresh = self.q.open_owner('explorer', 0x2000)
        self.assertEqual(fresh.ticket, 2)
        self.assertIsNone(self.enqueue())
        self.assertEqual(self.enqueue(fresh), 3)
        self.assert_no_authority(self.q.snapshot())

    def test_retire_targets_exact_owner_not_same_name_successor(self):
        fresh = self.q.open_owner('explorer', 0x2000)
        old_entry, new_entry = self.enqueue(), self.enqueue(fresh)
        cancelled = self.q.retire(self.owner)
        self.assertEqual(cancelled.queued_ids, (old_entry,))
        self.assertEqual(self.q.snapshot().pending_ids, (new_entry,))
        self.assertIsNotNone(self.enqueue(fresh))

    def test_active_owner_cannot_be_released_without_retirement(self):
        before = self.q.snapshot()
        self.assertFalse(self.q.release_owner(self.owner))
        self.assertEqual(self.q.snapshot(), before)

    def test_retired_claimed_owner_cannot_release_until_exact_ack(self):
        self.enqueue()
        claim = self.q.claim()
        self.q.retire(self.owner)
        self.assertFalse(self.q.release_owner(self.owner))
        self.q.complete(claim, succeeded=True)
        self.assertTrue(self.q.release_owner(self.owner))
        self.assertEqual(self.q.snapshot().owner_count, 0)

    def test_release_owner_is_one_use_and_counter_never_resets(self):
        self.q.retire(self.owner)
        self.assertTrue(self.q.release_owner(self.owner))
        self.assertFalse(self.q.release_owner(self.owner))
        self.assertIsNone(self.enqueue())
        self.assertEqual(self.q.open_owner('explorer', 0x2000).ticket, 2)

    def test_owner_registry_and_pending_entries_have_independent_capacity_bounds(self):
        q = PaintQueue(capacity=1)
        owner = q.open_owner('a', 0)
        self.assertIsNone(q.open_owner('b', 0))
        self.assertEqual(q.enqueue(owner, RECT), 2)
        self.assertIsNone(q.enqueue(owner, RECT))
        self.assertEqual(q.snapshot().serial, 2)

    def test_cancelled_head_still_occupies_capacity_until_ack(self):
        q = PaintQueue(capacity=2)
        first, second = q.open_owner('a', 0), q.open_owner('b', 0)
        a, b = q.enqueue(first, RECT), q.enqueue(second, RECT)
        claim = q.claim()
        q.retire(first)
        self.assertEqual(q.snapshot().pending_ids, (a, b))
        self.assertIsNone(q.enqueue(second, RECT))
        q.complete(claim, succeeded=True)
        self.assertEqual(q.enqueue(second, RECT), 5)

    def test_release_retired_owner_frees_only_owner_registry_capacity(self):
        q = PaintQueue(capacity=1)
        owner = q.open_owner('a', 0)
        q.retire(owner)
        self.assertIsNone(q.open_owner('b', 0))
        self.assertTrue(q.release_owner(owner))
        self.assertEqual(q.open_owner('b', 0).ticket, 2)

    def test_close_cancels_all_and_is_irreversible_but_allows_ack_cleanup(self):
        self.enqueue()
        self.enqueue()
        claim = self.q.claim()
        cancellation = self.q.close()
        self.assertEqual((cancellation.queued_ids, cancellation.claimed_id), ((3,), 2))
        self.assertTrue(self.q.snapshot().closed)
        self.assertIsNone(self.q.open_owner('fresh', 1))
        self.assertIsNone(self.enqueue())
        self.assertIsNone(self.q.claim())
        self.assertEqual(self.q.complete(claim, succeeded=True).outcome, 'cancelled')
        self.assertTrue(self.q.release_owner(self.owner))
        self.q.close()
        self.assertEqual(self.q.snapshot().serial, 3)

    def test_uncertainty_is_terminal_preserves_first_error_and_allows_cleanup(self):
        self.enqueue()
        claim = self.q.claim()
        self.q.uncertain('lost-event')
        self.q.uncertain('later-error')
        self.assertEqual(self.q.snapshot().error, 'lost-event')
        self.assertIsNone(self.q.open_owner('fresh', 1))
        self.assertIsNone(self.enqueue())
        self.assertIsNone(self.q.claim())
        self.assertEqual(self.q.complete(claim, succeeded=True).outcome, 'cancelled')
        self.assertTrue(self.q.release_owner(self.owner))

    def test_exhaustion_cancels_existing_claim_without_wrap_or_new_work(self):
        q = PaintQueue(ticket_limit=2)
        owner = q.open_owner('a', 0)
        q.enqueue(owner, RECT)
        claim = q.claim()
        self.assertIsNone(q.open_owner('b', 0))
        self.assertEqual(q.snapshot().error, 'ticket-exhausted')
        self.assertEqual(q.snapshot().serial, 2)
        self.assertTrue(q.snapshot().active_cancelled)
        self.assertEqual(q.complete(claim, succeeded=True).outcome, 'cancelled')
        self.assertTrue(q.release_owner(owner))
        self.assertIsNone(q.open_owner('a', 0))
        self.assertEqual(q.snapshot().serial, 2)

    def test_exhaustion_survives_prior_owner_release(self):
        q = PaintQueue(ticket_limit=1)
        owner = q.open_owner('a', 0)
        q.retire(owner)
        q.release_owner(owner)
        self.assertIsNone(q.open_owner('a', 0))
        self.assertEqual((q.snapshot().serial, q.snapshot().error), (1, 'ticket-exhausted'))

    def test_capacity_rejection_does_not_consume_tickets_or_mutate_queue(self):
        q = PaintQueue(capacity=1)
        owner = q.open_owner('a', 0)
        self.assertIsNone(q.open_owner('b', 0))
        self.assertEqual(q.enqueue(owner, RECT), 2)
        before = q.snapshot()
        self.assertIsNone(q.enqueue(owner, RECT))
        self.assertEqual(q.snapshot(), before)
        q.complete(q.claim(), succeeded=True)
        self.assertEqual(q.enqueue(owner, RECT), 3)

    def test_invalid_constructor_values_are_rejected(self):
        for argument in ('capacity', 'ticket_limit'):
            for value in (0, -1, True, 1.5, None, INT_MAX + 1):
                with self.subTest(argument=argument, value=value), self.assertRaises(ValueError):
                    PaintQueue(**{argument: value})
        for value in (-1, U32_MAX + 1, True, 1.5, None):
            with self.assertRaises(ValueError):
                PaintQueue(controller_word=value)

    def test_malformed_names_never_corrupt_current_state(self):
        before = self.q.snapshot()
        for name in ('', 'x\0y', '\ud800', 'x' * 256, '\u00e9' * 128, 1, True, None):
            for method in (lambda: self.q.open_owner(name, 0),
                           lambda: self.q.purge(name), lambda: self.q.uncertain(name)):
                with self.assertRaises(ValueError):
                    method()
                self.assertEqual(self.q.snapshot(), before)

    def test_name_limit_is_utf8_bytes_and_matching_is_exact(self):
        owner = self.q.open_owner('\u00e9' * 127 + 'x', 0)
        self.assertIsNotNone(owner)
        self.enqueue()
        self.assertEqual(self.q.purge('Explorer'), Cancellation())
        self.assertEqual(self.q.snapshot().pending_ids, (3,))

    def test_invalid_unsigned_words_are_rejected_without_consuming_ids(self):
        before = self.q.snapshot()
        for value in (-1, U32_MAX + 1, True, 1.5, None, '1'):
            for method in (lambda: self.q.open_owner('bad', value),
                           lambda: self.enqueue(metadata=value),
                           lambda: self.enqueue(rectangle=(1, 2, 3, value))):
                with self.assertRaises(ValueError):
                    method()
                self.assertEqual(self.q.snapshot(), before)

    def test_rectangle_accepts_only_exact_four_element_builtin_list_or_tuple(self):
        class ListSubclass(list):
            pass

        class TupleSubclass(tuple):
            pass

        before = self.q.snapshot()
        for value in ((), (1, 2, 3), (1, 2, 3, 4, 5), '1234',
                      iter(RECT), ListSubclass(RECT), TupleSubclass(RECT), None):
            with self.assertRaises(ValueError):
                self.enqueue(rectangle=value)
            self.assertEqual(self.q.snapshot(), before)

    def test_completion_requires_explicit_boolean_and_keeps_claim_on_bad_input(self):
        self.enqueue()
        claim = self.q.claim()
        before = self.q.snapshot()
        for value in (None, 0, 1, 'yes', object()):
            with self.assertRaises(ValueError):
                self.q.complete(claim, succeeded=value)
            self.assertEqual(self.q.snapshot(), before)
        self.assertEqual(self.q.complete(claim, succeeded=True).outcome, 'completed')

    def test_snapshot_is_immutable_owned_history_not_live_authority(self):
        before = self.q.snapshot()
        with self.assertRaises(FrozenInstanceError):
            before.serial = 50
        self.enqueue()
        self.assertEqual(before.pending_ids, ())
        self.assertEqual(before.serial, 1)
        self.assertEqual(self.q.snapshot().pending_ids, (2,))
        self.assert_no_authority(before)
        self.assert_no_authority(self.q.snapshot())

    def test_completion_and_cancellation_are_immutable(self):
        self.enqueue()
        claim = self.q.claim()
        cancellation = self.q.retire(self.owner)
        completion = self.q.complete(claim, succeeded=True)
        with self.assertRaises(FrozenInstanceError):
            cancellation.claimed_id = 99
        with self.assertRaises(FrozenInstanceError):
            completion.outcome = 'completed'

    def test_lost_ack_blocks_head_without_timeout_takeover_or_owner_release(self):
        other = self.q.open_owner('other', 0x2000)
        first, second = self.enqueue(), self.enqueue(other)
        self.q.claim()
        self.q.retire(self.owner)
        for _ in range(20):
            self.assertIsNone(self.q.claim())
            self.assertFalse(self.q.release_owner(self.owner))
        self.assertEqual(self.q.snapshot().pending_ids, (first, second))
        self.assertEqual(self.q.snapshot().active_id, first)

    def test_release_old_generation_never_mutates_new_raw_alias_generation(self):
        self.enqueue()
        old_claim = self.q.claim()
        self.q.retire(self.owner)
        fresh = self.q.open_owner('explorer', 0x2000)
        new_id = self.enqueue(fresh)
        self.assertFalse(self.q.release_owner(self.owner))
        self.q.complete(old_claim, succeeded=True)
        self.assertTrue(self.q.release_owner(self.owner))
        self.assertEqual(self.q.snapshot().pending_ids, (new_id,))
        self.assertIs(self.q.claim().owner, fresh)
        self.assert_no_authority(self.q.snapshot())


if __name__ == '__main__':
    unittest.main()
