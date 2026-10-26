#!/usr/bin/env python3
"""Execute standalone generation retirement against real bounded native lists.

Only this fixture's in-memory constructor width changes to44. Heap, libc and
mutex services remain bounded hostile-ABI stubs; this is not native scheduler,
producer-source coherence, lifecycle coverage, hardware or permission to free.
"""

import unittest

import reveal_paint_retirement_mips as core
import test_reveal_paint_handoff_mips as prior


STATE, CODE, INPUT = prior.STATE, prior.CODE, prior.STATE + 0x10000
STACK, CONTROLLER, RETURN, MASK = prior.STACK, prior.CONTROLLER, prior.RETURN, prior.MASK
PAYLOAD = prior.PAYLOAD


class RetirementMachine(prior.HandoffMachine):
    def __init__(self, image, meta, *, capacity=64, owner_capacity=16,
                 ticket_limit=core.MAX_TICKET, element_bytes=core.ELEMENT_BYTES):
        super().__init__(image, meta, capacity=capacity, ticket_limit=ticket_limit,
                         element_bytes=element_bytes)
        self.regions.pop(prior.INPUT, None)
        self.map(STATE, core.memory_bytes(owner_capacity))
        self.map(INPUT, 0x100)
        self.handoff_code, self.handoff_labels = core.assemble(
            STATE, CONTROLLER, CODE, capacity=capacity,
            owner_capacity=owner_capacity, ticket_limit=ticket_limit)

    def open_owner(self, engine=PAYLOAD[2]):
        return self.invoke('open_owner', engine)

    def open_ticket(self, engine=PAYLOAD[2]):
        return self.open_owner(engine)[0]

    def publish(self, owner, words=PAYLOAD):
        if len(words) != core.PAYLOAD_BYTES // 4:
            raise ValueError('fixture payload must contain nine words')
        for index, word in enumerate(words):
            self.put(INPUT + index * 4, word, 4)
        return self.invoke('publish', INPUT, owner)

    def retire(self, owner):
        return self.invoke('retire', owner)

    def drained(self, owner):
        return self.invoke('drained', owner)

    def owner_address(self, index):
        return STATE + core.HEADER + core.OWNER_BYTES * index

    def owner(self, index):
        return self.words_at(self.owner_address(index), core.OWNER_BYTES // 4)

    def state(self, offset=None):
        if offset is not None:
            return self.peek(STATE + offset)
        return {name: self.peek(STATE + displacement) for name, displacement in (
            ('serial', core.SERIAL), ('active', core.ACTIVE),
            ('cancelled', core.CANCELLED), ('fault', core.FAULT),
            ('closed', core.CLOSED), ('active_list', core.ACTIVE_LIST),
            ('active_owner', core.ACTIVE_OWNER), ('owner_count', core.OWNER_COUNT),
            ('reserved', core.RESERVED))}


class RetirementTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        prior.HandoffTests.setUpClass()
        cls.image, cls.meta = prior.HandoffTests.image, prior.HandoffTests.meta

    def machine(self, **options):
        return RetirementMachine(self.image, self.meta, **options)

    def test_separate44_format_preserves36_and_uses_shared_tickets(self):
        m = self.machine()
        owner = m.open_ticket()
        self.assertEqual(owner, 1)
        self.assertEqual(m.owner(0), (owner, PAYLOAD[2], 0, 0))
        self.assertEqual(m.publish(owner), (2, 0))
        self.assertEqual(m.words_at(m.head(), 11), (*PAYLOAD, 2, owner))
        self.assertEqual(m.claim(), (STATE + core.COPY, 2))
        self.assertEqual(m.state(core.ACTIVE_OWNER), owner)
        self.assertEqual(m.owned(), PAYLOAD)
        self.assertEqual(m.complete(2), (1, 0))
        self.assertEqual(m.state(core.ACTIVE_OWNER), 0)

    def test_registration_and_empty_drain_have_no_native_pointer_dereference(self):
        m = self.machine()
        for index, engine in enumerate((0, MASK, 0x80000000)):
            owner = m.open_ticket(engine)
            self.assertEqual(m.owner(index), (owner, engine, 0, 0))
            self.assertEqual(m.drained(owner), (0, 0))
            self.assertEqual(m.retire(owner), (1, 0))
            self.assertEqual(m.drained(owner), (1, 0))
        self.assertEqual(m.freed, [])

    def test_unknown_retired_or_engine_mismatch_publication_is_denied(self):
        m = self.machine()
        owner = m.open_ticket()
        self.assertEqual(m.publish(0), (0, 0))
        self.assertEqual(m.publish(99), (0, 0))
        self.assertEqual(m.publish(owner, (*PAYLOAD[:2], 0, *PAYLOAD[3:])), (0, 0))
        self.assertEqual(m.state(core.SERIAL), owner)
        self.assertEqual(m.retire(owner), (1, 0))
        self.assertEqual(m.publish(owner), (0, 0))
        self.assertEqual(m.count(m.paint_list), 0)

    def test_retire_unclaimed_removes_only_that_generation_and_preserves_fifo(self):
        m = self.machine()
        old, other = m.open_ticket(), m.open_ticket()
        for owner in (old, other, old, other, old):
            m.publish(owner)
        self.assertEqual(m.retire(old), (1, 3))
        self.assertEqual(m.count(m.paint_list), 2)
        self.assertEqual(m.words_at(m.head(), 11)[-2:], (4, other))
        self.assertEqual(m.claim()[1], 4)
        self.assertEqual(m.complete(4), (1, 0))
        self.assertEqual(m.claim()[1], 6)
        self.assertEqual(m.complete(6), (1, 0))
        self.assertEqual(m.drained(old), (1, 0))
        self.assertEqual(m.drained(other), (0, 0))

    def test_retire_retains_active_head_and_cancels_before_ack(self):
        m = self.machine()
        owner = m.open_ticket()
        m.publish(owner)
        m.publish(owner)
        m.claim()
        self.assertEqual(m.retire(owner), (1, 1))
        self.assertEqual(m.count(m.paint_list), 1)
        self.assertEqual(m.state(core.CANCELLED), 1)
        self.assertEqual(m.state(core.ACTIVE_OWNER), owner)
        self.assertEqual(m.drained(owner), (0, 0))
        self.assertEqual(m.complete(2), (3, 0))
        self.assertEqual(m.drained(owner), (1, 0))

    def test_same_engine_new_generation_does_not_revive_old_producer(self):
        m = self.machine()
        old = m.open_ticket()
        m.publish(old)
        m.claim()
        m.retire(old)
        new = m.open_ticket()
        self.assertNotEqual(old, new)
        self.assertEqual(m.publish(old), (0, 0))
        self.assertEqual(m.publish(new), (4, 1))
        self.assertEqual(m.complete(2), (3, 0))
        self.assertEqual(m.drained(old), (1, 0))
        self.assertEqual(m.claim()[1], 4)
        self.assertEqual(m.state(core.ACTIVE_OWNER), new)
        self.assertEqual(m.complete(2), (0, 0))
        self.assertEqual(m.complete(4), (1, 0))

    def test_owner_table_full_is_backpressure_not_ticket_reuse_or_terminal_fault(self):
        m = self.machine(owner_capacity=1)
        owner = m.open_ticket()
        self.assertEqual(m.open_owner(), (0, 0))
        self.assertEqual(m.state(core.SERIAL), owner)
        self.assertEqual(m.state(core.FAULT), 0)
        self.assertEqual(m.publish(owner), (2, 0))
        self.assertEqual(m.retire(owner), (1, 1))
        self.assertEqual(m.open_owner(), (0, 0))
        self.assertEqual(m.owner(0), (owner, PAYLOAD[2], 1, 0))

    def test_close_is_narrow_but_explicit_retire_and_drain_work_after_close(self):
        m = self.machine()
        owner = m.open_ticket()
        m.publish(owner)
        self.assertEqual(m.invoke('close'), (0, 0))
        self.assertEqual(m.owner(0)[2], 0)
        self.assertEqual(m.count(m.paint_list), 1)
        self.assertEqual(m.open_owner(), (0, 0))
        self.assertEqual(m.publish(owner), (0, 0))
        self.assertEqual(m.claim(), (0, 0))
        self.assertEqual(m.retire(owner), (1, 1))
        self.assertEqual(m.drained(owner), (1, 0))

    def test_global_exhaustion_withdraws_but_exact_claim_can_ack_cancelled(self):
        m = self.machine(ticket_limit=2)
        owner = m.open_ticket()
        m.publish(owner)
        m.claim()
        self.assertEqual(m.open_owner(), (0, 0))
        self.assertEqual(m.state(core.SERIAL), 2)
        self.assertEqual(m.state(core.FAULT), 1)
        self.assertEqual(m.retire(owner), (0, 0))
        self.assertEqual(m.owner(0)[2], 1)
        self.assertEqual(m.complete(2), (3, 0))
        self.assertEqual(m.drained(owner), (0, 0))

    def test_lock_failure_does_not_read_table_or_list_or_attempt_unlock(self):
        m = self.machine()
        m.acquire_result = 7
        m.read_events.clear()
        self.assertEqual(m.open_owner(), (0, 0))
        self.assertFalse(any(STATE <= address < STATE + core.memory_bytes()
                             for _, address, _, _, _ in m.read_events))
        self.assertNotIn(core.UNLOCK, m.trace)

    def test_failed_unlock_denies_success_and_never_reports_drained(self):
        m = self.machine()
        owner = m.open_ticket()
        m.release_result = 1
        self.assertEqual(m.retire(owner), (0, 0))
        self.assertEqual(m.owner(0)[2], 1)
        self.assertEqual(m.state(core.FAULT), 1)

    def test_actual_native_methods_execute_with_only_paint_mutex_held(self):
        m = self.machine()
        owner = m.open_ticket()
        m.publish(owner)
        m.publish(owner)
        m.claim()
        self.assertEqual(m.retire(owner), (1, 1))
        self.assertEqual(m.complete(2), (3, 0))
        for target in (core.APPEND, core.GET, core.REMOVE, core.LOCK, core.UNLOCK):
            self.assertIn(target, m.trace)
        self.assertFalse(m.paint_locked)
        self.assertFalse(m.action_locked)
        self.assertTrue(all(pointer == prior.prior.PAINT_LOCK
                            for _, pointer, _ in m.lock_events))

    def test_callee_saved_register_hi_lo_and_stack_survive_every_entry(self):
        m = self.machine()
        owner = m.open_ticket()
        m.publish(owner)
        for label, args in (('claim', ()), ('cancel', ()), ('retire', (owner,)),
                            ('drained', (owner,)), ('complete', (2, 1)),
                            ('drained', (owner,)), ('close', ())):
            saved = {register: 0x51400000 + register for register in range(16, 24)}
            for register, value in saved.items():
                m.r[register] = value
            m.hi, m.lo = 0x12345678, 0xABCDEF01
            m.invoke(label, *args)
            self.assertEqual({register: m.r[register] for register in saved}, saved)
            self.assertEqual((m.r[29], m.r[31]), (STACK, RETURN))
            self.assertEqual((m.hi, m.lo), (0x12345678, 0xABCDEF01))

    def test_all_source_and_owner_table_reads_are_guarded(self):
        m = self.machine()
        owner = m.open_ticket()
        m.publish(owner)
        m.claim()
        m.retire(owner)
        m.complete(2)
        m.drained(owner)
        reads = [(address, locked) for _, address, _, _, locked in m.read_events
                 if STATE <= address < STATE + core.memory_bytes()
                 or INPUT <= address < INPUT + 36]
        self.assertTrue(reads)
        self.assertTrue(all(locked for _, locked in reads))

    def test_full_owner_extent_is_rejected_as_input_or_stack_alias(self):
        m = self.machine(owner_capacity=1024)
        tail = STATE + core.memory_bytes(1024) - 36
        self.assertEqual(m.invoke('publish', tail, 1), (0, 0))
        aliased_stack = STATE + core.memory_bytes(1024) - 8
        self.assertEqual(m.invoke('open_owner', PAYLOAD[2], stack=aliased_stack), (0, 0))
        self.assertNotIn(core.LOCK, m.trace)

    def test_invalid_controller_stack_or_input_is_denied_before_lock_or_stores(self):
        for label, args, options in (
                ('open_owner', (PAYLOAD[2],), {'controller': 0xBAD00000}),
                ('open_owner', (PAYLOAD[2],), {'stack': 8}),
                ('open_owner', (PAYLOAD[2],), {'stack': STACK + 4}),
                ('publish', (0, 1), {}),
                ('publish', (INPUT + 1, 1), {}),
                ('publish', (0xFFFFFFF0, 1), {}),
                ('publish', (STATE + core.HEADER, 1), {}),
                ('publish', (CONTROLLER + 0x40, 1), {}),
                ('publish', (STACK - 40, 1), {})):
            with self.subTest(label=label, args=args, options=options):
                m = self.machine()
                m.trace.clear()
                m.writes.clear()
                self.assertEqual(m.invoke(label, *args, **options), (0, 0))
                self.assertEqual(m.writes, [])
                self.assertNotIn(core.LOCK, m.trace)

    def test_invalid_complete_outcome_does_not_lock_or_ack(self):
        m = self.machine()
        owner = m.open_ticket()
        nonce = m.publish(owner)[0]
        m.claim()
        m.trace.clear()
        self.assertEqual(m.complete(nonce, 2), (0, 0))
        self.assertEqual(m.state(core.ACTIVE), nonce)
        self.assertEqual(m.count(m.paint_list), 1)
        self.assertNotIn(core.LOCK, m.trace)

    def test_malformed_owner_schema_faults_before_native_queue_calls(self):
        for offset, value in ((core.OWNER_COUNT, 17), (core.RESERVED, 1),
                              (core.HEADER + core.OWNER_TICKET, 0),
                              (core.HEADER + core.OWNER_TICKET, 9),
                              (core.HEADER + core.OWNER_RETIRED, 2),
                              (core.HEADER + core.OWNER_RESERVED, 1)):
            with self.subTest(offset=offset, value=value):
                m = self.machine()
                owner = m.open_ticket()
                m.publish(owner)
                m.put(STATE + offset, value, 4)
                m.trace.clear()
                self.assertEqual(m.retire(owner)[0], 0)
                self.assertEqual(m.state(core.FAULT), 1)
                self.assertNotIn(core.GET, m.trace)
                self.assertNotIn(core.REMOVE, m.trace)

    def test_incompatible_width_or_method_cannot_be_purged(self):
        for offset, value in ((0x10, 40), (0x18, core.APPEND + 4),
                              (0x2C, core.GET + 4), (0x20, core.REMOVE + 4)):
            with self.subTest(offset=offset):
                m = self.machine()
                owner = m.open_ticket()
                m.publish(owner)
                m.put(m.paint_list + offset, value, 4)
                m.trace.clear()
                self.assertEqual(m.retire(owner)[0], 0)
                self.assertEqual(m.owner(0)[2], 1)
                self.assertEqual(m.count(m.paint_list), 1)
                self.assertEqual(m.state(core.FAULT), 1)
                self.assertNotIn(core.GET, m.trace)
                self.assertNotIn(core.REMOVE, m.trace)

    def test_actual_lost_growth_table_blocks_retire_drain_and_ack(self):
        m = self.machine(capacity=80)
        owner = m.open_ticket()
        for _ in range(70):
            m.publish(owner)
        nonce = m.claim()[1]
        m.fail_next_heap = True
        self.assertEqual(m.publish(owner), (0, MASK))
        self.assertEqual(m.peek(m.paint_list), 0)
        self.assertEqual(m.state(core.FAULT), 1)
        self.assertEqual(m.retire(owner), (0, 0))
        self.assertEqual(m.owner(0)[2], 1)
        m.trace.clear()
        self.assertEqual(m.complete(nonce)[0], 0)
        self.assertNotIn(core.GET, m.trace)
        self.assertEqual(m.state(core.ACTIVE), nonce)
        self.assertEqual(m.drained(owner), (0, 0))

    def test_failed_new_chunk_keeps_valid_storage_and_admits_cancelled_ack(self):
        m = self.machine(capacity=80)
        owner = m.open_ticket()
        for _ in range(70):
            m.publish(owner)
        nonce = m.claim()[1]
        m.fail_heap_in = 2
        self.assertEqual(m.publish(owner), (0, MASK))
        self.assertNotEqual(m.peek(m.paint_list), 0)
        self.assertEqual(m.complete(nonce)[0], 3)
        self.assertEqual(m.count(m.paint_list), 69)
        self.assertEqual(m.drained(owner), (0, 0))

    def test_publication_and_registration_also_preserve_extended_callee_saved_set(self):
        m = self.machine()
        for label, args in (('open_owner', (PAYLOAD[2],)), ('publish', (INPUT, 1))):
            for index, value in enumerate(PAYLOAD):
                m.put(INPUT + index * 4, value, 4)
            saved = {register: 0x54700000 + register for register in range(16, 24)}
            for register, value in saved.items():
                m.r[register] = value
            m.hi, m.lo = 0x12345678, 0xABCDEF01
            self.assertGreater(m.invoke(label, *args)[0], 0)
            self.assertEqual({register: m.r[register] for register in saved}, saved)
            self.assertEqual((m.r[29], m.r[31]), (STACK, RETURN))
            self.assertEqual((m.hi, m.lo), (0x12345678, 0xABCDEF01))

    def test_config_extents_and_bounded_owner_capacity(self):
        for bad in (0, -1, 1025, True, '16'):
            with self.subTest(capacity=bad), self.assertRaises(ValueError):
                core.memory_bytes(bad)
        self.assertEqual(core.memory_bytes(), 328)
        self.assertEqual(core.memory_bytes(1024), 16456)
        for name in ('capacity', 'ticket_limit'):
            for bad in (0, -1, True, 0x80000000):
                with self.subTest(name=name, bad=bad), self.assertRaises(ValueError):
                    core.assemble(STATE, CONTROLLER, CODE, **{name: bad})
        for values in ((0, CONTROLLER, CODE), (STATE + 1, CONTROLLER, CODE),
                       (STATE, 0, CODE), (STATE, CONTROLLER, 0),
                       (0xFFFFFFC0, CONTROLLER, CODE), (STATE, STATE, CODE),
                       (STATE, CONTROLLER, STATE), (STATE, CONTROLLER, CONTROLLER),
                       (STATE, CONTROLLER, 0x0FFFFFFC)):
            with self.subTest(values=values), self.assertRaises(ValueError):
                core.assemble(*values)


if __name__ == '__main__':
    unittest.main()
