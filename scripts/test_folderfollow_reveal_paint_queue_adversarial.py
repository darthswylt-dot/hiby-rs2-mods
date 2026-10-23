"""Adversarial schedules for the owned HOST paint queue, never native proof.

All inputs are already-owned Python values. The exhaustive schedules and
barrier/Event tests exercise only this model's serialization and exact opaque
handles; they do not establish native mutex coverage, lifetime, currentness,
or an admitted firmware/UI transaction. No device, file image or network I/O.
"""

from dataclasses import FrozenInstanceError, replace
import itertools
import threading
import unittest

from folderfollow_reveal_paint_queue import PaintQueue


RECT = (1, 16, 8, 8)
OTHER = (101, 202, 303, 404)
AUTHORITY = (
    'native_record_lease_proven', 'native_payload_coherence_proven',
    'native_object_lifetime_proven', 'current_owner_proven',
    'request_freshness_proven', 'contents_current', 'coherent_capture',
    'autoscroll_authorized',
)


class PaintQueueAdversarialTests(unittest.TestCase):
    def populated(self, *, capacity=4):
        queue = PaintQueue(controller_word=0x1700000, capacity=capacity)
        first = queue.open_owner('A', 0x1500000)
        second = queue.open_owner('B', 0x1600000)
        a = queue.enqueue(first, RECT)
        b = queue.enqueue(second, OTHER, metadata=5)
        return queue, first, second, a, b

    def invariant(self, queue, *, capacity=4):
        snap = queue.snapshot()
        self.assertIsInstance(snap.pending_ids, tuple)
        self.assertEqual(len(snap.pending_ids), len(set(snap.pending_ids)))
        self.assertLessEqual(len(snap.pending_ids), capacity)
        self.assertLessEqual(snap.owner_count, capacity)
        if snap.active_id is not None:
            self.assertTrue(snap.pending_ids)
            self.assertEqual(snap.active_id, snap.pending_ids[0])
        if snap.active_cancelled:
            self.assertIsNotNone(snap.active_id)
        for flag in AUTHORITY:
            self.assertIs(getattr(snap, flag), False, flag)
        return snap

    def run_threads(self, *functions):
        failures = []

        def guarded(function):
            try:
                function()
            except BaseException as error:
                failures.append(error)

        threads = [threading.Thread(target=guarded, args=(function,), daemon=True)
                   for function in functions]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive(), 'bounded host fixture did not finish')
        if failures:
            raise failures[0]

    def test_value_identical_owner_clone_is_not_an_exact_handle(self):
        queue, owner, _, _, _ = self.populated()
        before = queue.snapshot()
        forged = replace(owner)
        self.assertIsNone(queue.enqueue(forged, RECT))
        self.assertEqual(queue.retire(forged).queued_ids, ())
        self.assertFalse(queue.release_owner(forged))
        self.assertEqual(queue.snapshot(), before)

    def test_foreign_owner_with_equal_ticket_and_native_words_is_rejected(self):
        left, right = PaintQueue(), PaintQueue()
        owner = left.open_owner('A', 5)
        foreign = right.open_owner('A', 5)
        self.assertEqual((owner.ticket, owner.name, owner.engine_word),
                         (foreign.ticket, foreign.name, foreign.engine_word))
        before = left.snapshot()
        self.assertIsNone(left.enqueue(foreign, RECT))
        self.assertEqual(left.retire(foreign).retired_owner_ids, ())
        self.assertEqual(left.snapshot(), before)

    def test_value_identical_claim_clone_cannot_acknowledge_head(self):
        queue, _, _, a, b = self.populated()
        claim = queue.claim()
        before = queue.snapshot()
        self.assertIsNone(queue.complete(replace(claim), succeeded=True))
        self.assertEqual(queue.snapshot(), before)
        self.assertEqual(queue.complete(claim, succeeded=True).entry_id, a)
        self.assertEqual(queue.snapshot().pending_ids, (b,))

    def test_foreign_claim_with_equal_entry_id_cannot_acknowledge_head(self):
        left, right = PaintQueue(), PaintQueue()
        for queue in (left, right):
            queue.enqueue(queue.open_owner('A', 5), RECT)
        claim, foreign = left.claim(), right.claim()
        self.assertEqual(claim.entry_id, foreign.entry_id)
        before = left.snapshot()
        self.assertIsNone(left.complete(foreign, succeeded=True))
        self.assertEqual(left.snapshot(), before)
        self.assertEqual(left.complete(claim, succeeded=True).outcome, 'completed')

    def test_native_value_equal_payloads_keep_distinct_entry_and_claim_identity(self):
        queue = PaintQueue()
        owner = queue.open_owner('A', 5)
        a, b = queue.enqueue(owner, RECT), queue.enqueue(owner, RECT)
        self.assertNotEqual(a, b)
        claim_a = queue.claim()
        queue.complete(claim_a, succeeded=True)
        claim_b = queue.claim()
        self.assertEqual(claim_a.payload, claim_b.payload)
        self.assertIsNone(queue.complete(claim_a, succeeded=False))
        self.assertEqual(queue.snapshot().active_id, b)
        self.assertEqual(queue.complete(claim_b, succeeded=False).outcome, 'failed')

    def test_rectangle_input_is_copied_not_retained_as_a_mutable_source(self):
        queue = PaintQueue(controller_word=9)
        owner = queue.open_owner('A', 5)
        rectangle = list(RECT)
        queue.enqueue(owner, rectangle, metadata=7)
        rectangle[:] = OTHER
        claim = queue.claim()
        self.assertEqual(claim.payload.rectangle, RECT)
        self.assertEqual((claim.payload.controller_word, claim.payload.engine_word,
                          claim.payload.metadata), (9, 5, 7))
        rectangle.clear()
        self.assertEqual(claim.payload.rectangle, RECT)

    def test_busy_head_is_retained_and_never_skipped_for_second_entry(self):
        queue, _, _, a, b = self.populated()
        claim = queue.claim()
        self.assertEqual(claim.entry_id, a)
        for _ in range(10):
            self.assertIsNone(queue.claim())
            self.assertEqual(queue.snapshot().pending_ids, (a, b))
        self.assertEqual(queue.complete(claim, succeeded=True).entry_id, a)
        self.assertEqual(queue.claim().entry_id, b)

    def test_failed_completion_removes_only_selected_entry(self):
        queue, _, _, a, b = self.populated()
        result = queue.complete(queue.claim(), succeeded=False)
        self.assertEqual((result.entry_id, result.outcome), (a, 'failed'))
        self.assertEqual(queue.snapshot().pending_ids, (b,))
        self.assertEqual(queue.claim().entry_id, b)

    def test_duplicate_acknowledgement_cannot_remove_new_head(self):
        queue, _, _, _, b = self.populated()
        old = queue.claim()
        queue.complete(old, succeeded=True)
        current = queue.claim()
        before = queue.snapshot()
        for success in (True, False, True):
            self.assertIsNone(queue.complete(old, succeeded=success))
            self.assertEqual(queue.snapshot(), before)
        self.assertEqual(queue.complete(current, succeeded=True).entry_id, b)

    def test_cancelled_claim_acknowledges_cancelled_regardless_of_work_result(self):
        for success in (False, True):
            with self.subTest(succeeded=success):
                queue, _, _, a, b = self.populated()
                claim = queue.claim()
                cancelled = queue.purge('A')
                self.assertEqual(cancelled.claimed_id, a)
                self.assertEqual(queue.snapshot().pending_ids, (a, b))
                result = queue.complete(claim, succeeded=success)
                self.assertEqual((result.entry_id, result.outcome), (a, 'cancelled'))
                self.assertEqual(queue.snapshot().pending_ids, (b,))

    def test_retired_owner_release_waits_for_retained_cancelled_claim(self):
        queue = PaintQueue()
        owner = queue.open_owner('A', 5)
        a, b = queue.enqueue(owner, RECT), queue.enqueue(owner, OTHER)
        claim = queue.claim()
        cancelled = queue.retire(owner)
        self.assertEqual((cancelled.queued_ids, cancelled.claimed_id), ((b,), a))
        self.assertFalse(queue.release_owner(owner))
        self.assertIsNone(queue.claim())
        self.assertEqual(queue.complete(claim, succeeded=True).outcome, 'cancelled')
        self.assertTrue(queue.release_owner(owner))
        self.assertFalse(queue.release_owner(owner))

    def test_same_name_and_engine_reopen_is_not_owner_aba(self):
        queue = PaintQueue()
        old = queue.open_owner('A', 5)
        a = queue.enqueue(old, RECT)
        claim = queue.claim()
        queue.purge('A')
        new = queue.open_owner('A', 5)
        self.assertGreater(new.ticket, old.ticket)
        b = queue.enqueue(new, RECT)
        self.assertIsNone(queue.enqueue(old, RECT))
        self.assertEqual(queue.snapshot().pending_ids, (a, b))
        self.assertIsNone(queue.claim())
        self.assertFalse(queue.release_owner(old))
        self.assertEqual(queue.complete(claim, succeeded=True).entry_id, a)
        # HOST bookkeeping only; equal native engine words confer no lease
        # or permission to free either real engine/controller allocation.
        self.assertTrue(queue.release_owner(old))
        self.assertFalse(queue.release_owner(old))
        self.assertEqual(queue.claim().entry_id, b)
        self.assertFalse(queue.release_owner(new))

    def test_stale_retire_cannot_cancel_reopened_owner_with_equal_name(self):
        queue = PaintQueue()
        old = queue.open_owner('A', 5)
        queue.retire(old)
        self.assertTrue(queue.release_owner(old))
        new = queue.open_owner('A', 5)
        b = queue.enqueue(new, RECT)
        before = queue.snapshot()
        cancelled = queue.retire(old)
        self.assertEqual((cancelled.queued_ids, cancelled.claimed_id,
                          cancelled.retired_owner_ids), ((), None, ()))
        self.assertEqual(queue.snapshot(), before)
        self.assertEqual(queue.claim().entry_id, b)

    def test_close_retains_cancelled_active_head_but_removes_unclaimed_tail(self):
        queue, owner, other, a, _ = self.populated()
        claim = queue.claim()
        queue.close()
        snap = self.invariant(queue)
        self.assertTrue(snap.closed)
        self.assertEqual((snap.pending_ids, snap.active_id, snap.active_cancelled),
                         ((a,), a, True))
        self.assertFalse(queue.release_owner(owner))
        self.assertTrue(queue.release_owner(other))
        self.assertEqual(queue.complete(claim, succeeded=True).outcome, 'cancelled')
        self.assertTrue(queue.release_owner(owner))

    def test_uncertain_is_terminal_without_reviving_reused_name_or_ticket(self):
        queue, owner, _, a, _ = self.populated()
        claim = queue.claim()
        before_serial = queue.snapshot().serial
        queue.uncertain('missing-handoff')
        snap = self.invariant(queue)
        self.assertEqual(snap.error, 'missing-handoff')
        self.assertEqual(snap.pending_ids, (a,))
        self.assertTrue(snap.active_cancelled)
        self.assertIsNone(queue.open_owner('A', owner.engine_word))
        self.assertIsNone(queue.enqueue(owner, RECT))
        self.assertEqual(queue.complete(claim, succeeded=False).outcome, 'cancelled')
        self.assertEqual(queue.snapshot().serial, before_serial)

    def test_cancelled_active_entry_still_consumes_capacity_until_acknowledged(self):
        queue = PaintQueue(capacity=2)
        old = queue.open_owner('A', 5)
        a = queue.enqueue(old, RECT)
        queue.enqueue(old, OTHER)
        claim = queue.claim()
        queue.purge('A')
        new = queue.open_owner('B', 6)
        b = queue.enqueue(new, OTHER)
        self.assertEqual(queue.snapshot().pending_ids, (a, b))
        before = queue.snapshot()
        self.assertIsNone(queue.enqueue(new, RECT))
        self.assertEqual(queue.snapshot(), before)
        queue.complete(claim, succeeded=True)
        c = queue.enqueue(new, RECT)
        self.assertGreater(c, b)
        self.assertEqual(queue.snapshot().pending_ids, (b, c))

    def test_owner_capacity_is_independent_from_empty_entry_capacity(self):
        queue = PaintQueue(capacity=2)
        first = queue.open_owner('A', 5)
        queue.open_owner('B', 6)
        before = queue.snapshot()
        self.assertEqual(before.pending_ids, ())
        self.assertIsNone(queue.open_owner('C', 7))
        self.assertEqual(queue.snapshot(), before)
        queue.retire(first)
        self.assertIsNone(queue.open_owner('C', 7))
        self.assertTrue(queue.release_owner(first))
        self.assertIsNotNone(queue.open_owner('C', 7))

    def test_backpressure_never_consumes_or_reuses_an_entry_ticket(self):
        queue = PaintQueue(capacity=1)
        owner = queue.open_owner('A', 5)
        a = queue.enqueue(owner, RECT)
        before = queue.snapshot()
        for _ in range(10):
            self.assertIsNone(queue.enqueue(owner, RECT))
            self.assertEqual(queue.snapshot(), before)
        queue.complete(queue.claim(), succeeded=True)
        b = queue.enqueue(owner, RECT)
        self.assertEqual(b, a + 1)

    def test_ticket_exhaustion_cancels_active_without_resetting_serial(self):
        queue = PaintQueue(capacity=4, ticket_limit=3)
        owner = queue.open_owner('A', 5)
        a = queue.enqueue(owner, RECT)
        queue.enqueue(owner, OTHER)
        claim = queue.claim()
        self.assertIsNone(queue.open_owner('B', 6))
        snap = self.invariant(queue)
        self.assertEqual((snap.serial, snap.error), (3, 'ticket-exhausted'))
        self.assertEqual(snap.pending_ids, (a,))
        self.assertTrue(snap.active_cancelled)
        self.assertEqual(queue.complete(claim, succeeded=True).outcome, 'cancelled')
        self.assertTrue(queue.release_owner(owner))
        self.assertIsNone(queue.open_owner('A', 5))
        self.assertEqual(queue.snapshot().serial, 3)

    def test_malformed_inputs_are_rejected_without_mutating_even_stale_state(self):
        queue, owner, _, _, _ = self.populated()
        queue.purge('A')
        for rectangle in ((), (1, 2, 3), (1, 2, 3, True), (1, 2, 3, -1),
                          (1, 2, 3, 0x100000000)):
            with self.subTest(rectangle=rectangle):
                before = queue.snapshot()
                with self.assertRaises(ValueError):
                    queue.enqueue(owner, rectangle)
                self.assertEqual(queue.snapshot(), before)

    def test_invalid_completion_value_is_not_converted_to_truthiness(self):
        queue, _, _, _, _ = self.populated()
        claim = queue.claim()
        for value in (0, 1, None, 'yes', object()):
            for token in (claim, None):
                with self.subTest(value=value, exact_token=token is claim):
                    before = queue.snapshot()
                    with self.assertRaises(ValueError):
                        queue.complete(token, succeeded=value)
                    self.assertEqual(queue.snapshot(), before)

    def test_claim_payload_and_snapshot_are_immutable_host_values(self):
        queue, _, _, _, _ = self.populated()
        claim, snap = queue.claim(), queue.snapshot()
        for value, field, replacement in ((claim, 'entry_id', 0),
                                          (claim.owner, 'ticket', 0),
                                          (claim.payload, 'rectangle', OTHER),
                                          (snap, 'pending_ids', ())):
            with self.subTest(field=field):
                with self.assertRaises(FrozenInstanceError):
                    setattr(value, field, replacement)
        self.assertEqual(queue.snapshot(), snap)

    def test_all_purge_ack_close_permutations_preserve_exact_completion_target(self):
        for order in itertools.permutations(('purge', 'ack', 'close')):
            with self.subTest(order=order):
                queue, _, _, a, _ = self.populated()
                claim = queue.claim()
                acknowledged = None
                cancelled_before_ack = False
                for operation in order:
                    if operation == 'purge':
                        queue.purge('A')
                    elif operation == 'close':
                        queue.close()
                    else:
                        before = queue.snapshot()
                        cancelled_before_ack = before.active_cancelled
                        acknowledged = queue.complete(claim, succeeded=True)
                        after = queue.snapshot()
                        self.assertEqual(after.pending_ids,
                                         tuple(item for item in before.pending_ids if item != a))
                    self.invariant(queue)
                self.assertEqual((acknowledged.entry_id, acknowledged.outcome),
                                 (a, 'cancelled' if cancelled_before_ack else 'completed'))
                self.assertEqual(queue.snapshot().pending_ids, ())

    def test_exhaustive_bounded_host_schedules_preserve_fifo_identity_and_bounds(self):
        operations = ('open', 'enqueue', 'claim', 'ack', 'purge', 'close')
        for order in itertools.product(operations, repeat=4):
            with self.subTest(order=order):
                queue = PaintQueue(capacity=3)
                owner = queue.open_owner('A', 5)
                active = None
                seen_ids = {owner.ticket}
                serial = queue.snapshot().serial
                for operation in order:
                    before = queue.snapshot()
                    if operation == 'open':
                        new = queue.open_owner('A', 5)
                        if new is not None:
                            self.assertNotIn(new.ticket, seen_ids)
                            seen_ids.add(new.ticket)
                            owner = new
                    elif operation == 'enqueue':
                        entry = queue.enqueue(owner, RECT)
                        if entry is not None:
                            self.assertNotIn(entry, seen_ids)
                            seen_ids.add(entry)
                    elif operation == 'claim':
                        new = queue.claim()
                        if new is not None:
                            self.assertIsNone(before.active_id)
                            self.assertEqual(new.entry_id, before.pending_ids[0])
                            active = new
                        elif before.active_id is not None:
                            self.assertEqual(queue.snapshot().active_id, before.active_id)
                    elif operation == 'ack':
                        result = queue.complete(active, succeeded=True)
                        if result is not None:
                            self.assertEqual(result.entry_id, active.entry_id)
                            self.assertEqual(queue.snapshot().pending_ids,
                                             tuple(item for item in before.pending_ids
                                                   if item != active.entry_id))
                    elif operation == 'purge':
                        queue.purge('A')
                    else:
                        queue.close()
                    snap = self.invariant(queue, capacity=3)
                    self.assertGreaterEqual(snap.serial, serial)
                    serial = snap.serial

    def test_host_barrier_simultaneous_claims_have_only_one_exact_winner(self):
        queue, _, _, a, b = self.populated()
        start = threading.Barrier(8)
        results, results_lock = [], threading.Lock()

        def claim_once():
            start.wait(timeout=5)
            result = queue.claim()
            with results_lock:
                results.append(result)

        self.run_threads(*([claim_once] * 8))
        winners = [claim for claim in results if claim is not None]
        self.assertEqual(len(winners), 1)
        self.assertEqual(winners[0].entry_id, a)
        self.assertEqual(queue.snapshot().pending_ids, (a, b))
        queue.complete(winners[0], succeeded=True)
        self.assertEqual(queue.claim().entry_id, b)

    def test_host_barrier_purge_and_ack_linearize_without_removing_other_owner(self):
        for _ in range(20):
            queue, _, _, a, b = self.populated()
            claim = queue.claim()
            start = threading.Barrier(2)
            results = {}

            def purge():
                start.wait(timeout=5)
                results['purge'] = queue.purge('A')

            def complete():
                start.wait(timeout=5)
                results['completion'] = queue.complete(claim, succeeded=True)

            self.run_threads(purge, complete)
            done = results['completion']
            self.assertEqual(done.entry_id, a)
            self.assertIn(done.outcome, ('completed', 'cancelled'))
            self.assertEqual(results['purge'].claimed_id,
                             a if done.outcome == 'cancelled' else None)
            self.assertEqual(queue.snapshot().pending_ids, (b,))
            self.assertEqual(queue.claim().entry_id, b)
            self.invariant(queue)

    def test_host_barrier_close_and_ack_linearize_with_cancelled_tail_removed(self):
        for _ in range(20):
            queue, _, _, a, _ = self.populated()
            claim = queue.claim()
            start = threading.Barrier(2)
            results = []

            def close():
                start.wait(timeout=5)
                queue.close()

            def complete():
                start.wait(timeout=5)
                results.append(queue.complete(claim, succeeded=True))

            self.run_threads(close, complete)
            self.assertEqual(results[0].entry_id, a)
            self.assertIn(results[0].outcome, ('completed', 'cancelled'))
            self.assertEqual(queue.snapshot().pending_ids, ())
            self.assertTrue(queue.snapshot().closed)
            self.invariant(queue)

    def test_host_event_holds_claim_while_purge_cancels_and_next_owner_waits(self):
        queue, owner, _, a, b = self.populated()
        acquired, acknowledge = threading.Event(), threading.Event()
        results = []
        failures = []

        def worker():
            try:
                claim = queue.claim()
                self.assertEqual(claim.entry_id, a)
                acquired.set()
                self.assertTrue(acknowledge.wait(timeout=5))
                results.append(queue.complete(claim, succeeded=True))
            except BaseException as error:
                failures.append(error)
                acquired.set()

        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        try:
            self.assertTrue(acquired.wait(timeout=5))
            if failures:
                raise failures[0]
            self.assertIsNone(queue.claim())
            queue.purge('A')
            self.assertEqual(queue.snapshot().pending_ids, (a, b))
            self.assertIsNone(queue.claim())
            self.assertFalse(queue.release_owner(owner))
        finally:
            acknowledge.set()
            thread.join(timeout=5)
        self.assertFalse(thread.is_alive())
        if failures:
            raise failures[0]
        self.assertEqual((results[0].entry_id, results[0].outcome), (a, 'cancelled'))
        self.assertTrue(queue.release_owner(owner))
        self.assertEqual(queue.claim().entry_id, b)

    def test_same_name_distinct_owners_are_both_retired_but_active_release_is_delayed(self):
        queue = PaintQueue()
        first = queue.open_owner('A', 5)
        second = queue.open_owner('A', 5)
        a = queue.enqueue(first, RECT)
        b = queue.enqueue(second, OTHER)
        claim = queue.claim()
        cancelled = queue.purge('A')
        self.assertEqual(cancelled.queued_ids, (b,))
        self.assertEqual(cancelled.claimed_id, a)
        self.assertEqual(set(cancelled.retired_owner_ids), {first.ticket, second.ticket})
        self.assertFalse(queue.release_owner(first))
        self.assertTrue(queue.release_owner(second))
        queue.complete(claim, succeeded=False)
        self.assertTrue(queue.release_owner(first))

    def test_closed_empty_cleaned_queue_never_reopens_or_resets_its_serial(self):
        queue = PaintQueue()
        owner = queue.open_owner('A', 5)
        queue.enqueue(owner, RECT)
        claim = queue.claim()
        serial = queue.snapshot().serial
        queue.close()
        queue.complete(claim, succeeded=True)
        queue.release_owner(owner)
        queue.close()
        self.assertIsNone(queue.open_owner('A', 5))
        self.assertIsNone(queue.enqueue(owner, RECT))
        self.assertIsNone(queue.claim())
        snap = self.invariant(queue)
        self.assertEqual((snap.serial, snap.pending_ids, snap.owner_count), (serial, (), 0))


if __name__ == '__main__':
    unittest.main()
