#!/usr/bin/env python3
"""Adversarial offline handoff tests; not native lifetime/thread proof.

The helper instructions and actual segmented-list methods execute. Mutations
between operations are explicit fixture interleavings, not hardware scheduling
claims. Uncooperative removal must be refused, not treated as a repaired purge.
"""

import random
import unittest

import reveal_paint_handoff_mips as core
import test_reveal_paint_handoff_mips as fixture


class PaintHandoffAdversarialTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture.HandoffTests.setUpClass()
        cls.image, cls.meta = fixture.HandoffTests.image, fixture.HandoffTests.meta

    def machine(self, **options):
        return fixture.HandoffMachine(self.image, self.meta, **options)

    def pending(self, machine):
        return tuple(machine.words_at(machine.element(machine.paint_list, index), 10)
                     for index in range(machine.count(machine.paint_list)))

    def test_identical_unclassified_payloads_have_distinct_publication_nonces(self):
        m = self.machine()
        payload = (*fixture.PAYLOAD[:-1], 0)
        first, second = m.publish(payload)[0], m.publish(payload)[0]
        entries = self.pending(m)
        self.assertEqual((first, second), (1, 2))
        self.assertEqual(entries[0][:9], entries[1][:9])
        self.assertEqual(entries[0][8], 0)  # Unclassified LALI is not a nonce.
        self.assertEqual((entries[0][9], entries[1][9]), (first, second))

    def test_body_mutation_after_claim_does_not_change_owned_copy(self):
        m = self.machine()
        nonce = m.publish()[0]
        address, claimed = m.claim()
        original = m.owned()
        for index in range(9):
            m.put(m.head() + 4 * index, 0x80000000 + index, 4)
        self.assertEqual(address, fixture.STATE + core.COPY)
        self.assertEqual(claimed, nonce)
        self.assertEqual(m.owned(), original)
        self.assertEqual(m.complete(nonce)[0], 1)
        # The preserved bytes are historical, not a native/current-value proof.
        self.assertEqual(self.pending(m), ())

    def test_actual_raw_removal_reuses_head_address_but_late_ack_cannot_remove_b(self):
        m = self.machine()
        first, second = m.publish()[0], m.publish()[0]
        m.claim()
        old_head = m.head()
        self.assertEqual(m.raw_remove(), 0)
        self.assertEqual(m.head(), old_head)
        before = self.pending(m)
        self.assertEqual(before[0][9], second)
        self.assertEqual(m.complete(first)[0], 0)
        self.assertEqual(self.pending(m), before)
        self.assertEqual(m.state(core.ACTIVE), first)
        self.assertNotEqual(m.state(core.FAULT), 0)

    def test_remove_then_identical_republication_does_not_revive_claim(self):
        m = self.machine()
        first = m.publish()[0]
        m.claim()
        m.raw_remove()
        second = m.publish()[0]
        self.assertEqual(second, first + 1)
        before = self.pending(m)
        self.assertEqual(m.complete(first)[0], 0)
        self.assertEqual(self.pending(m), before)

    def test_head_nonce_mismatch_does_not_delete_or_release_active(self):
        m = self.machine()
        first = m.publish()[0]
        m.claim()
        m.put(m.head() + core.NONCE, first + 7, 4)
        before = self.pending(m)
        self.assertEqual(m.complete(first)[0], 0)
        self.assertEqual(self.pending(m), before)
        self.assertEqual(m.state(core.ACTIVE), first)

    def test_queue_binding_change_denies_before_dereferencing_replacement(self):
        m = self.machine()
        first = m.publish()[0]
        m.claim()
        m.put(fixture.CONTROLLER + 0x128, 0xBAD00000, 4)
        m.read_events.clear()
        self.assertEqual(m.complete(first)[0], 0)
        self.assertFalse(any(0xBAD00000 <= address < 0xBAD01000
                             for _, address, _, _, _ in m.read_events))
        self.assertEqual(m.state(core.ACTIVE), first)
        m.put(fixture.CONTROLLER + 0x128, m.paint_list, 4)
        self.assertEqual(m.complete(first)[0], 3)
        self.assertEqual(m.state(core.ACTIVE), 0)

    def test_empty_list_after_bypass_keeps_claim_and_denies_new_work(self):
        m = self.machine()
        first = m.publish()[0]
        m.claim()
        m.raw_remove()
        self.assertEqual(m.complete(first)[0], 0)
        self.assertEqual(m.state(core.ACTIVE), first)
        self.assertEqual(m.publish()[0], 0)
        self.assertEqual(m.claim(), (0, 0))
        self.assertEqual(self.pending(m), ())

    def test_duplicate_old_ack_cannot_complete_a_new_active_claim(self):
        m = self.machine()
        first, second = m.publish()[0], m.publish()[0]
        m.claim()
        self.assertEqual(m.complete(first)[0], 1)
        self.assertEqual(m.claim()[1], second)
        before = self.pending(m)
        self.assertEqual(m.complete(first)[0], 0)
        self.assertEqual(m.state(core.ACTIVE), second)
        self.assertEqual(self.pending(m), before)
        self.assertEqual(m.complete(second)[0], 1)

    def test_wrong_ack_during_cancellation_cannot_skip_head(self):
        m = self.machine()
        first, second = m.publish()[0], m.publish()[0]
        m.claim()
        self.assertEqual(m.invoke('cancel')[0], first)
        before = self.pending(m)
        self.assertEqual(m.complete(second)[0], 0)
        self.assertEqual(self.pending(m), before)
        self.assertEqual(m.claim(), (0, 0))
        self.assertEqual(m.complete(first)[0], 3)
        self.assertEqual(m.claim()[1], second)

    def test_active_head_counts_towards_explicit_capacity(self):
        m = self.machine(capacity=2)
        first, second = m.publish()[0], m.publish()[0]
        m.claim()
        serial = m.state(core.SERIAL)
        self.assertEqual(m.publish()[0], 0)
        self.assertEqual(m.state(core.SERIAL), serial)
        self.assertEqual(m.complete(first)[0], 1)
        third = m.publish()[0]
        self.assertEqual(third, second + 1)
        self.assertEqual(tuple(entry[9] for entry in self.pending(m)), (second, third))

    def test_cancelled_head_counts_towards_capacity_until_ack(self):
        m = self.machine(capacity=1)
        first = m.publish()[0]
        m.claim()
        m.invoke('cancel')
        self.assertEqual(m.publish()[0], 0)
        self.assertEqual(m.claim(), (0, 0))
        self.assertEqual(m.complete(first, succeeded=0)[0], 3)
        self.assertEqual(m.publish()[0], first + 1)

    def test_exhaustion_with_claim_allows_only_cancelled_ack(self):
        m = self.machine(ticket_limit=1)
        first = m.publish()[0]
        m.claim()
        self.assertEqual(m.publish()[0], 0)
        self.assertNotEqual(m.state(core.FAULT), 0)
        self.assertEqual(m.complete(first)[0], 3)
        self.assertEqual(m.state(core.SERIAL), 1)
        self.assertEqual(m.publish()[0], 0)

    def test_close_preserves_unclaimed_tail_without_free_or_implicit_drain(self):
        m = self.machine()
        first, second = m.publish()[0], m.publish()[0]
        m.claim()
        m.invoke('close')
        self.assertEqual(m.complete(first)[0], 3)
        self.assertEqual(tuple(entry[9] for entry in self.pending(m)), (second,))
        self.assertEqual(m.claim(), (0, 0))
        self.assertEqual(m.publish()[0], 0)

    def test_private_copy_reuse_only_follows_ack(self):
        m = self.machine()
        first = m.publish()[0]
        original = tuple(m.words_at(m.head(), 9))
        changed = tuple(word ^ 0x01010101 for word in original)
        second = m.publish(changed)[0]
        first_address, _ = m.claim()
        self.assertEqual(m.owned(), original)
        self.assertEqual(m.claim(), (0, 0))
        self.assertEqual(m.owned(), original)
        m.complete(first)
        second_address, second_nonce = m.claim()
        self.assertEqual(second_address, first_address)
        self.assertEqual(second_nonce, second)
        self.assertEqual(m.owned(), changed)

    def test_raw_engine_and_geometry_are_never_dereferenced_or_rendered(self):
        m = self.machine()
        payload = (0, 0, 0xBAD10000, 0xBAD20000, 0xBAD30000,
                   0xBAD40000, 0xBAD50000, 0xBAD60000, 0)
        first = m.publish(payload)[0]
        m.claim()
        self.assertEqual(m.owned(), payload)
        self.assertEqual(m.complete(first)[0], 1)
        self.assertFalse(any(0xBAD10000 <= address < 0xBAD70000
                             for _, address, _, _, _ in m.read_events))
        for target in (0x43C900, 0x459840, 0x8B4280, 0x8B4220,
                       0x4395A0, 0x8B0760, 0x43CB20):
            self.assertNotIn(target, m.trace)

    def test_failed_growth_with_held_claim_denies_ack_before_getter(self):
        m = self.machine(capacity=80)
        for _ in range(70):
            m.publish()
        m.claim()
        original = m.owned()
        m.fail_next_heap = True
        self.assertEqual(m.publish(), (0, fixture.MASK))
        self.assertEqual(m.peek(m.paint_list), 0)
        m.trace.clear()
        self.assertEqual(m.complete(1)[0], 0)
        self.assertNotIn(core.GET, m.trace)
        self.assertNotIn(core.REMOVE, m.trace)
        self.assertEqual(m.state(core.ACTIVE), 1)
        self.assertEqual(m.state(core.CANCELLED), 1)
        self.assertEqual(m.owned(), original)
        self.assertEqual(m.count(m.paint_list), 70)

    def test_malformed_list_header_denies_ack_before_native_getter(self):
        cases = ((0, 0), (0, 3), (0x14, 0), (0x14, 1),
                 (0x14, 11), (8, 0), (8, 0x80000000), (0xC, 71))
        for offset, value in cases:
            with self.subTest(offset=offset, value=value):
                m = self.machine()
                m.publish()
                m.claim()
                m.put(m.paint_list + offset, value, 4)
                m.trace.clear()
                self.assertEqual(m.complete(1)[0], 0)
                self.assertNotIn(core.GET, m.trace)
                self.assertNotIn(core.REMOVE, m.trace)
                self.assertEqual(m.state(core.ACTIVE), 1)

    def test_selected_pointer_alias_alignment_and_wrap_denied_before_payload_reads(self):
        for pointer in (0, 1, fixture.MASK - 3, fixture.STATE + core.COPY,
                        fixture.CONTROLLER, fixture.STACK - core.FRAME):
            with self.subTest(pointer=hex(pointer)):
                m = self.machine()
                m.publish()
                table = m.peek(m.paint_list)
                m.put(table, pointer, 4)
                self.assertEqual(m.claim(), (0, 0))
                self.assertEqual(m.state(core.ACTIVE), 0)
                self.assertEqual(m.state(core.FAULT), 1)
                self.assertEqual(m.owned(), (0,) * 9)

    def test_malformed_private_state_never_reaches_native_queue_methods(self):
        cases = ((core.SERIAL, 0x80000000), (core.ACTIVE, 1),
                 (core.CANCELLED, 1), (core.CLOSED, 2),
                 (core.FAULT, 2), (core.RESERVED, 1))
        for offset, value in cases:
            with self.subTest(offset=offset, value=value):
                m = self.machine()
                m.put(fixture.STATE + offset, value, 4)
                self.assertEqual(m.claim(), (0, 0))
                self.assertEqual(m.state(core.FAULT), 1)
                for target in (core.GET, core.APPEND, core.REMOVE):
                    self.assertNotIn(target, m.trace)

    def test_append_across_native_growth_keeps_active_nonce_and_fifo(self):
        m = self.machine(capacity=75)
        first = m.publish()[0]
        m.claim()
        original = m.owned()
        for expected in range(2, 76):
            self.assertEqual(m.publish()[0], expected)
        self.assertGreater(m.peek(m.paint_list + 8), 70)
        self.assertEqual(m.owned(), original)
        self.assertEqual(m.publish()[0], 0)
        self.assertEqual(m.complete(first)[0], 1)
        self.assertEqual(tuple(entry[9] for entry in self.pending(m)), tuple(range(2, 76)))
        for expected in range(2, 76):
            self.assertEqual(m.claim()[1], expected)
            self.assertEqual(m.complete(expected)[0], 1)
        self.assertEqual(self.pending(m), ())

    def test_seeded_operation_sequences_match_retained_head_oracle(self):
        # Cooperative protocol only: unlike bypass cases above, every queue
        # mutation participates. Native lifetime is not part of this oracle.
        for seed in range(12):
            with self.subTest(seed=seed):
                m = self.machine(capacity=3, ticket_limit=8)
                rng = random.Random(seed)
                entries, active, serial, closed, fault, cancelled = [], None, 0, False, False, False
                for _ in range(60):
                    operation = rng.randrange(7)
                    if operation == 0:
                        expected = 0
                        if not closed and not fault and len(entries) < 3:
                            if serial == 8:
                                fault = True
                            else:
                                serial += 1
                                expected = serial
                                entries.append(serial)
                        self.assertEqual(m.publish()[0], expected)
                    elif operation == 1:
                        expected = 0
                        if not closed and not fault and active is None and entries:
                            active, cancelled = entries[0], False
                            expected = active
                        self.assertEqual(m.claim()[1], expected)
                    elif operation == 2:
                        expected = active or 0
                        cancelled = cancelled or active is not None
                        self.assertEqual(m.invoke('cancel')[0], expected)
                    elif operation in (3, 4):
                        succeeded = operation == 3
                        expected = 0
                        if active is not None:
                            expected = 3 if cancelled or closed or fault else 1 if succeeded else 2
                            entries.pop(0)
                            active, cancelled = None, False
                        self.assertEqual(m.complete(m.state(core.ACTIVE), succeeded=int(succeeded))[0], expected)
                    elif operation == 5:
                        before = self.pending(m)
                        self.assertEqual(m.complete(serial + 100)[0], 0)
                        self.assertEqual(self.pending(m), before)
                    else:
                        # Delay close in most sequences to exercise admission,
                        # backpressure and completion before terminal withdrawal.
                        if rng.randrange(5) == 0:
                            m.invoke('close')
                            closed = True
                            cancelled = cancelled or active is not None
                    self.assertEqual(m.state(core.SERIAL), serial)
                    self.assertEqual(m.state(core.ACTIVE), active or 0)
                    self.assertEqual(tuple(entry[9] for entry in self.pending(m)), tuple(entries))
                    self.assertEqual(bool(m.state(core.CLOSED)), closed)
                    self.assertEqual(bool(m.state(core.FAULT)), fault)


if __name__ == '__main__':
    unittest.main()
