#!/usr/bin/env python3
"""Offline owner retirement interleavings, not native free/UI authority.

The emitted helper and actual native list methods execute. Explicit storage
mutations below are bounded fault injections, not scheduler reachability or
proof of all real writers participating in the protocol.
"""

import random
import unittest

import reveal_paint_retirement_mips as core
import test_reveal_paint_retirement_mips as fixture


class PaintRetirementAdversarialTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture.RetirementTests.setUpClass()
        cls.image, cls.meta = fixture.RetirementTests.image, fixture.RetirementTests.meta

    def machine(self, **options):
        return fixture.RetirementMachine(self.image, self.meta, **options)

    def pending(self, machine):
        return tuple(machine.words_at(machine.element(machine.paint_list, index), 11)
                     for index in range(machine.count(machine.paint_list)))

    def owner_pointer(self, machine, ticket):
        for index in range(machine.state(core.OWNER_COUNT)):
            address = fixture.STATE + core.HEADER + index * core.OWNER_BYTES
            if machine.peek(address + core.OWNER_TICKET) == ticket:
                return address
        raise AssertionError('fixture owner ticket is absent')

    def test_retired_generation_cannot_publish_after_same_engine_reopens(self):
        m = self.machine()
        old = m.open_owner()[0]
        m.publish(old)
        self.assertEqual(m.retire(old), (1, 1))
        new = m.open_owner()[0]
        self.assertGreater(new, old)
        serial = m.state(core.SERIAL)
        self.assertEqual(m.publish(old)[0], 0)
        self.assertEqual(m.state(core.SERIAL), serial)
        nonce = m.publish(new)[0]
        self.assertEqual((self.pending(m)[0][9], self.pending(m)[0][10]), (nonce, new))
        self.assertEqual(m.drained(old), (1, 0))
        self.assertEqual(m.drained(new), (0, 0))

    def test_retire_active_owner_removes_only_its_unclaimed_entries(self):
        m = self.machine()
        a, b = m.open_owner()[0], m.open_owner()[0]
        first = m.publish(a)[0]
        second = m.publish(b)[0]
        m.publish(a)
        fourth = m.publish(b)[0]
        m.publish(a)
        m.claim()
        original = m.owned()
        self.assertEqual(m.retire(a), (1, 2))
        self.assertEqual(tuple(row[9] for row in self.pending(m)), (first, second, fourth))
        self.assertEqual(m.state(core.ACTIVE_OWNER), a)
        self.assertEqual(m.state(core.CANCELLED), 1)
        self.assertEqual(m.owned(), original)
        self.assertEqual(m.drained(a), (0, 0))
        self.assertEqual(m.complete(first)[0], 3)
        self.assertEqual(m.drained(a), (1, 0))
        self.assertEqual(m.claim()[1], second)

    def test_retiring_another_owner_preserves_active_copy_and_success(self):
        m = self.machine()
        a, b = m.open_owner()[0], m.open_owner()[0]
        first = m.publish(b)[0]
        m.publish(a)
        third = m.publish(b)[0]
        m.publish(a)
        m.claim()
        original = m.owned()
        self.assertEqual(m.retire(a), (1, 2))
        self.assertEqual(m.state(core.CANCELLED), 0)
        self.assertEqual(m.owned(), original)
        self.assertEqual(tuple(row[9] for row in self.pending(m)), (first, third))
        self.assertEqual(m.complete(first)[0], 1)
        self.assertEqual(m.drained(a), (1, 0))

    def test_repeated_retire_and_drained_do_not_reuse_tickets_or_change_other_owner(self):
        m = self.machine()
        a, b = m.open_owner()[0], m.open_owner()[0]
        m.publish(a)
        survivor = m.publish(b)[0]
        self.assertEqual(m.retire(a), (1, 1))
        serial = m.state(core.SERIAL)
        before = self.pending(m)
        for _ in range(3):
            self.assertEqual(m.retire(a), (1, 0))
            self.assertEqual(m.drained(a), (1, 0))
        self.assertEqual(self.pending(m), before)
        self.assertEqual(m.state(core.SERIAL), serial)
        self.assertEqual(m.claim()[1], survivor)

    def test_close_requires_explicit_retirement_to_drain_tail(self):
        m = self.machine()
        a, b = m.open_owner()[0], m.open_owner()[0]
        first = m.publish(a)[0]
        m.publish(b)
        m.publish(a)
        m.claim()
        m.invoke('close')
        self.assertEqual(len(self.pending(m)), 3)
        self.assertEqual(m.drained(a), (0, 0))
        self.assertEqual(m.open_owner()[0], 0)
        self.assertEqual(m.publish(b)[0], 0)
        self.assertEqual(m.retire(a), (1, 1))
        self.assertEqual(m.retire(b), (1, 1))
        self.assertEqual(m.drained(b), (1, 0))
        self.assertEqual(m.complete(first)[0], 3)
        self.assertEqual(m.drained(a), (1, 0))
        self.assertEqual(self.pending(m), ())

    def test_append_only_owner_capacity_does_not_reclaim_or_burn_serial(self):
        m = self.machine(owner_capacity=2)
        old, live = m.open_owner()[0], m.open_owner()[0]
        self.assertEqual(m.retire(old), (1, 0))
        serial = m.state(core.SERIAL)
        for _ in range(3):
            self.assertEqual(m.open_owner()[0], 0)
            self.assertEqual(m.drained(old), (1, 0))
        self.assertEqual(m.state(core.SERIAL), serial)
        self.assertEqual(m.state(core.OWNER_COUNT), 2)
        self.assertEqual(m.state(core.FAULT), 0)
        self.assertGreater(m.publish(live)[0], serial)

    def test_retirement_and_fault_preclude_positive_drained(self):
        m = self.machine(ticket_limit=2)
        owner = m.open_owner()[0]
        nonce = m.publish(owner)[0]
        m.claim()
        self.assertEqual(m.publish(owner)[0], 0)
        self.assertEqual(m.state(core.FAULT), 1)
        self.assertEqual(m.retire(owner)[0], 0)
        self.assertEqual(m.complete(nonce)[0], 3)
        self.assertEqual(self.pending(m), ())
        self.assertEqual(m.drained(owner), (0, 0))

    def test_retire_cancel_and_tombstone_precede_first_actual_remove(self):
        m = self.machine()
        owner = m.open_owner()[0]
        first = m.publish(owner)[0]
        m.publish(owner)
        m.publish(owner)
        m.claim()
        owner_address = self.owner_pointer(m, owner)
        observed = []

        def inspect(pc):
            if pc == core.REMOVE:
                observed.append((m.paint_locked,
                                 m.peek(owner_address + core.OWNER_RETIRED),
                                 m.state(core.CANCELLED), m.state(core.ACTIVE)))

        m.on_instruction = inspect
        self.assertEqual(m.retire(owner), (1, 2))
        self.assertEqual(observed, [(True, 1, 1, first)] * 2)

    def test_active_owner_mismatch_refuses_all_removals_after_tombstone(self):
        m = self.machine()
        a, b = m.open_owner()[0], m.open_owner()[0]
        first = m.publish(a)[0]
        m.publish(a)
        m.claim()
        m.put(m.head() + core.OWNER, b, 4)
        before = self.pending(m)
        m.trace.clear()
        self.assertEqual(m.retire(a)[0], 0)
        self.assertNotIn(core.REMOVE, m.trace)
        self.assertEqual(self.pending(m), before)
        self.assertEqual(m.state(core.ACTIVE), first)
        self.assertEqual(m.state(core.CANCELLED), 1)
        self.assertEqual(m.peek(self.owner_pointer(m, a) + core.OWNER_RETIRED), 1)
        self.assertEqual(m.drained(a), (0, 0))

    def test_replaced_list_binding_is_rejected_before_foreign_header_reads(self):
        m = self.machine()
        owner = m.open_owner()[0]
        m.publish(owner)
        m.claim()
        m.put(fixture.CONTROLLER + 0x128, 0xBAD00000, 4)
        m.read_events.clear()
        self.assertEqual(m.retire(owner)[0], 0)
        self.assertFalse(any(0xBAD00000 <= address < 0xBAD01000
                             for _, address, _, _, _ in m.read_events))
        self.assertEqual(m.state(core.CANCELLED), 1)
        self.assertEqual(m.peek(self.owner_pointer(m, owner) + core.OWNER_RETIRED), 1)

    def test_later_corruption_after_partial_purge_never_reports_drained(self):
        m = self.machine()
        a, b = m.open_owner()[0], m.open_owner()[0]
        m.publish(a)
        keep = m.publish(b)[0]
        m.publish(a)
        last = m.element(m.paint_list, 2)
        m.put(last + core.OWNER, 0x7FFFFFFF, 4)
        self.assertEqual(m.retire(a)[0], 0)
        self.assertEqual(m.count(m.paint_list), 2)  # Earlier removal is real.
        self.assertEqual(self.pending(m)[0][9], keep)
        self.assertEqual(m.state(core.FAULT), 1)
        self.assertEqual(m.peek(self.owner_pointer(m, a) + core.OWNER_RETIRED), 1)
        self.assertEqual(m.drained(a), (0, 0))
        self.assertEqual(m.publish(a)[0], 0)

    def test_late_retired_producer_denied_before_unmapped_source_read(self):
        m = self.machine()
        owner = m.open_owner()[0]
        m.retire(owner)
        serial = m.state(core.SERIAL)
        m.read_events.clear()
        self.assertEqual(m.invoke('publish', 0xBAD00000, owner)[0], 0)
        self.assertFalse(any(0xBAD00000 <= address < 0xBAD01000
                             for _, address, _, _, _ in m.read_events))
        self.assertEqual(m.state(core.SERIAL), serial)

    def test_raw_remove_failure_preserves_revocation_and_denies_drained(self):
        m = self.machine()
        owner = m.open_owner()[0]
        m.publish(owner)
        injected = []

        def break_count(pc):
            if pc == core.REMOVE and not injected:
                injected.append(pc)
                # Explicit inconsistent-storage injection under148, not a
                # claim that a cooperative second writer can acquire it.
                m.put(m.paint_list + 0xC, 0, 4)

        m.on_instruction = break_count
        self.assertEqual(m.retire(owner)[0], 0)
        self.assertEqual(injected, [core.REMOVE])
        self.assertEqual(m.state(core.FAULT), 1)
        self.assertEqual(m.peek(self.owner_pointer(m, owner) + core.OWNER_RETIRED), 1)
        self.assertEqual(m.drained(owner), (0, 0))

    def test_success_result_with_wrong_post_remove_count_is_terminal(self):
        m = self.machine()
        owner = m.open_owner()[0]
        m.publish(owner)
        m.publish(owner)
        injected = []

        def break_count(pc):
            if pc == 0x45594C and not injected:
                injected.append(pc)
                m.put(m.paint_list + 0xC, m.count(m.paint_list) + 1, 4)

        m.on_instruction = break_count
        self.assertEqual(m.retire(owner)[0], 0)
        self.assertEqual(injected, [0x45594C])
        self.assertEqual(m.state(core.FAULT), 1)
        self.assertEqual(m.drained(owner), (0, 0))

    def test_failed_acquire_does_not_revoke_or_remove(self):
        m = self.machine()
        owner = m.open_owner()[0]
        m.publish(owner)
        before = self.pending(m)
        address = self.owner_pointer(m, owner)
        m.acquire_result = 5
        m.trace.clear()
        self.assertEqual(m.retire(owner)[0], 0)
        self.assertEqual(self.pending(m), before)
        self.assertEqual(m.peek(address + core.OWNER_RETIRED), 0)
        self.assertNotIn(core.UNLOCK, m.trace)

    def test_failed_unlock_denies_retire_without_inventing_rollback(self):
        m = self.machine()
        owner = m.open_owner()[0]
        m.publish(owner)
        address = self.owner_pointer(m, owner)
        m.release_result = 5
        self.assertEqual(m.retire(owner), (0, 0))
        self.assertEqual(m.count(m.paint_list), 0)
        self.assertEqual(m.peek(address + core.OWNER_RETIRED), 1)
        self.assertEqual(m.state(core.FAULT), 1)
        self.assertTrue(m.paint_locked)  # Ownership is deliberately unknown.

    def test_segment_boundaries_and_adjacent_matches_preserve_other_fifo(self):
        m = self.machine(capacity=80)
        target, kept = m.open_owner()[0], m.open_owner()[0]
        selected = {1, 8, 9, 10, 18, 19, 20, 68, 69, 70, 71}
        expected = []
        for index in range(75):
            owner = target if index in selected else kept
            words = (*fixture.PAYLOAD[:7], index, fixture.PAYLOAD[8])
            nonce = m.publish(owner, words)[0]
            if owner == kept:
                expected.append((*words, nonce, owner))
        m.claim()  # Other owner's active head must remain untouched.
        original = m.owned()
        self.assertEqual(m.retire(target), (1, len(selected)))
        self.assertEqual(self.pending(m), tuple(expected))
        self.assertEqual(m.owned(), original)
        self.assertEqual(m.state(core.CANCELLED), 0)
        self.assertEqual(m.drained(target), (1, 0))
        self.assertEqual(m.complete(expected[0][9])[0], 1)

    def test_queued_engine_owner_mismatch_is_not_ignored_as_another_owner(self):
        m = self.machine()
        a, b = m.open_owner()[0], m.open_owner()[0]
        m.publish(b)
        m.put(m.head() + 8, fixture.PAYLOAD[2] ^ 0x100, 4)
        before = self.pending(m)
        self.assertEqual(m.retire(a)[0], 0)
        self.assertEqual(self.pending(m), before)
        self.assertEqual(m.state(core.FAULT), 1)
        self.assertEqual(m.drained(a), (0, 0))

    def test_nonce_must_follow_its_issued_owner_and_fit_shared_serial(self):
        for replacement in (0, 1, 99, fixture.MASK):
            with self.subTest(nonce=replacement):
                m = self.machine()
                owner = m.open_owner()[0]
                m.publish(owner)
                m.put(m.head() + core.NONCE, replacement, 4)
                m.trace.clear()
                self.assertEqual(m.retire(owner)[0], 0)
                self.assertEqual(m.state(core.FAULT), 1)
                self.assertEqual(m.count(m.paint_list), 1)
                self.assertNotIn(core.REMOVE, m.trace)
                self.assertEqual(m.drained(owner), (0, 0))

    def test_duplicate_owner_table_ticket_is_rejected_before_queue_access(self):
        m = self.machine()
        a, b = m.open_owner()[0], m.open_owner()[0]
        m.publish(a)
        second = self.owner_pointer(m, b)
        m.put(second + core.OWNER_TICKET, a, 4)
        m.trace.clear()
        self.assertEqual(m.retire(a)[0], 0)
        self.assertEqual(m.state(core.FAULT), 1)
        self.assertEqual(m.count(m.paint_list), 1)
        self.assertNotIn(core.GET, m.trace)
        self.assertNotIn(core.REMOVE, m.trace)

    def test_drained_is_not_implied_by_empty_live_owner_or_another_owner_retirement(self):
        m = self.machine()
        a, b = m.open_owner()[0], m.open_owner()[0]
        self.assertEqual(m.drained(a), (0, 0))
        self.assertEqual(m.retire(b), (1, 0))
        self.assertEqual(m.drained(b), (1, 0))
        self.assertEqual(m.drained(a), (0, 0))
        self.assertGreater(m.publish(a)[0], b)

    def test_old_ack_cannot_complete_new_same_engine_generation(self):
        m = self.machine()
        old = m.open_owner()[0]
        old_nonce = m.publish(old)[0]
        m.claim()
        m.retire(old)
        new = m.open_owner()[0]
        new_nonce = m.publish(new)[0]
        self.assertEqual(m.complete(old_nonce)[0], 3)
        m.claim()
        before = self.pending(m)
        self.assertEqual(m.complete(old_nonce)[0], 0)
        self.assertEqual(self.pending(m), before)
        self.assertEqual(m.state(core.ACTIVE_OWNER), new)
        self.assertEqual(m.complete(new_nonce)[0], 1)

    def test_raw_engine_words_do_not_trigger_lifecycle_or_ui_calls(self):
        m = self.machine()
        engine = 0xBAD10000
        owner = m.open_owner(engine)[0]
        words = (*fixture.PAYLOAD[:2], engine, *fixture.PAYLOAD[3:])
        nonce = m.publish(owner, words)[0]
        m.claim()
        self.assertEqual(m.retire(owner), (1, 0))
        self.assertEqual(m.complete(nonce)[0], 3)
        self.assertEqual(m.drained(owner), (1, 0))
        self.assertFalse(any(engine <= address < engine + 0x1000
                             for _, address, _, _, _ in m.read_events))
        for target in (0x439780, 0x4395A0, 0x8B0760, 0x4398A0,
                       0x43CB20, 0x459840, 0x8B4280, 0x8B4220):
            self.assertNotIn(target, m.trace)

    def test_seeded_sequences_match_generation_and_retained_head_oracle(self):
        for seed in range(10):
            with self.subTest(seed=seed):
                m = self.machine(capacity=4, owner_capacity=3, ticket_limit=25)
                rng = random.Random(seed)
                owners, retired, entries = {}, set(), []
                serial, active, cancelled, closed, fault = 0, None, False, False, False
                for _ in range(70):
                    operation = rng.randrange(8)
                    if operation == 0:
                        engine = fixture.PAYLOAD[2] ^ (16 * rng.randrange(2))
                        expected = 0
                        if not closed and not fault and len(owners) < 3:
                            if serial == 25:
                                fault = True
                            else:
                                serial += 1
                                owners[serial] = engine
                                expected = serial
                        self.assertEqual(m.open_owner(engine)[0], expected)
                    elif operation == 1:
                        owner = rng.choice([0, *owners])
                        engine = owners.get(owner, fixture.PAYLOAD[2])
                        words = (*fixture.PAYLOAD[:2], engine, *fixture.PAYLOAD[3:])
                        expected = 0
                        if not closed and not fault and owner in owners and owner not in retired and len(entries) < 4:
                            if serial == 25:
                                fault = True
                            else:
                                serial += 1
                                expected = serial
                                entries.append((serial, owner))
                        self.assertEqual(m.publish(owner, words)[0], expected)
                    elif operation == 2:
                        expected = 0
                        if not closed and not fault and active is None and entries:
                            active, cancelled = entries[0], False
                            expected = active[0]
                        self.assertEqual(m.claim()[1], expected)
                    elif operation == 3:
                        owner = rng.choice([0, *owners])
                        expected, removed = 0, 0
                        if owner in owners:
                            retired.add(owner)
                            if active is not None and active[1] == owner:
                                cancelled = True
                            if not fault:
                                kept = [entry for entry in entries if entry[1] != owner or entry == active]
                                removed = len(entries) - len(kept)
                                entries, expected = kept, 1
                        result = m.retire(owner)
                        self.assertEqual(result[0], expected)
                        if expected:
                            self.assertEqual(result[1], removed)
                    elif operation == 4:
                        owner = rng.choice([0, *owners])
                        expected = int(not fault and owner in retired
                                       and all(entry[1] != owner for entry in entries)
                                       and (active is None or active[1] != owner))
                        self.assertEqual(m.drained(owner), (expected, 0))
                    elif operation == 5:
                        succeeded = rng.randrange(2)
                        nonce = 0 if active is None else active[0]
                        expected = 0
                        if active is not None:
                            expected = 3 if cancelled or closed or fault or active[1] in retired else 1 if succeeded else 2
                            entries.pop(0)
                            active, cancelled = None, False
                        self.assertEqual(m.complete(nonce, succeeded)[0], expected)
                    elif operation == 6:
                        self.assertEqual(m.complete(serial + 100)[0], 0)
                    elif rng.randrange(7) == 0:
                        m.invoke('close')
                        closed = True
                        cancelled = cancelled or active is not None
                    if fault and active is not None:
                        cancelled = True
                    self.assertEqual(m.state(core.SERIAL), serial)
                    self.assertEqual(m.state(core.OWNER_COUNT), len(owners))
                    self.assertEqual(m.state(core.ACTIVE), 0 if active is None else active[0])
                    self.assertEqual(m.state(core.ACTIVE_OWNER), 0 if active is None else active[1])
                    self.assertEqual(tuple((row[9], row[10]) for row in self.pending(m)), tuple(entries))
                    self.assertEqual(bool(m.state(core.FAULT)), fault)
                    self.assertEqual(bool(m.state(core.CLOSED)), closed)


if __name__ == '__main__':
    unittest.main()
