#!/usr/bin/env python3
"""Execute standalone handoff plus real mutex callbacks and segmented lists.

Only this test instance changes its local constructor element width to40.
Existing builders/images/artifacts stay unchanged. Heap/libc/mutex services
are inherited bounded hostile-ABI fixtures, not a device or scheduler. No
engine/controller lifetime or original producer acquisition is established.
"""

import struct
import unittest

import reveal_paint_handoff_mips as core
import test_reveal_action_link_stage as prior


STATE, CODE, INPUT = 0x1F50000, 0x1E80000, 0x1F51000
STACK, CONTROLLER, RETURN, MASK = (prior.PRODUCER_STACK, prior.CONTROLLER,
                                  prior.RETURN, prior.MASK)
PAYLOAD = (0, 0, prior.NODE, 1, 16, 8, 8, 0x87654321, 0)


class HandoffMachine(prior.ActionLinkMachine):
    """Reusable fixture; integer receipts are NOT native memory capabilities."""

    def __init__(self, image, meta, *, capacity=64, ticket_limit=core.MAX_TICKET,
                 element_bytes=core.ELEMENT_BYTES):
        # Local in-memory fixture only. Do not add this width to any builder.
        local = bytearray(image)
        struct.pack_into('<I', local, 0x439844 - 0x400000,
                         prior.stage.b.addiu(5, 0, element_bytes))
        super().__init__(bytes(local), meta)
        # The predecessor uses this instance attribute only during setup; it
        # would otherwise shadow this fixture's state(offset) accessor.
        self.diagnostic_state = self.state
        del self.state
        self.map(STATE, core.STATE_BYTES)
        self.map(INPUT, 0x100)
        self.handoff_code, self.handoff_labels = core.assemble(
            STATE, CONTROLLER, CODE, capacity=capacity, ticket_limit=ticket_limit)
        self.acquire_result = self.release_result = 0
        self.fail_heap_in = None
        self.on_locked = None
        self.calls.clear()
        self.lock_events.clear()
        self.trace.clear()
        self.read_events.clear()
        self.writes.clear()

    def word(self, pc):
        if hasattr(self, 'handoff_code') and CODE <= pc < CODE + len(self.handoff_code):
            return struct.unpack_from('<I', self.handoff_code, pc - CODE)[0]
        return super().word(pc)

    def external(self, target):
        if target == 0x4669E0 and getattr(self, 'fail_heap_in', None) is not None:
            self.fail_heap_in -= 1
            if not self.fail_heap_in:
                self.fail_heap_in = None
                self.calls.append(target)
                self.hostile_result(0)
                return
        if (target in (0x466DA0, 0x466DC0) and self.r[4] == prior.PAINT_LOCK
                and hasattr(self, 'acquire_result')):
            result = self.acquire_result if target == 0x466DA0 else self.release_result
            if result:
                self.calls.append(target)
                self.hostile_result(result)
                return
            super().external(target)
            if target == 0x466DA0 and self.on_locked is not None:
                self.on_locked(self)
            return
        super().external(target)

    def invoke(self, label, *args, controller=CONTROLLER, stack=STACK):
        self.r[29], self.r[31] = stack, RETURN
        self.r[4:5 + len(args)] = [controller, *args]
        self.run_at(self.handoff_labels[label], RETURN)
        self.pc = None
        return self.r[2], self.r[3]

    def publish(self, words=PAYLOAD):
        if len(words) != core.PAYLOAD_BYTES // 4:
            raise ValueError('fixture payload must contain nine words')
        for index, word in enumerate(words):
            self.put(INPUT + index * 4, word, 4)
        return self.invoke('publish', INPUT)

    def claim(self):
        return self.invoke('claim')

    def complete(self, nonce, succeeded=1):
        return self.invoke('complete', nonce, succeeded)

    def state(self, offset=None):
        if offset is not None:
            return self.peek(STATE + offset)
        return {name: self.peek(STATE + displacement) for name, displacement in (
            ('serial', core.SERIAL), ('active', core.ACTIVE),
            ('cancelled', core.CANCELLED), ('fault', core.FAULT),
            ('closed', core.CLOSED), ('active_list', core.ACTIVE_LIST),
            ('reserved', core.RESERVED))}

    def owned(self):
        return self.words_at(STATE + core.COPY, core.PAYLOAD_BYTES // 4)

    def head(self):
        return self.element(self.paint_list) if self.count(self.paint_list) else 0

    def raw_remove(self, index=0):
        return self.stock(0x439960, CONTROLLER, index)


class HandoffTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        prior.RevealActionLinkStageTests.setUpClass()
        cls.image = prior.RevealActionLinkStageTests.image
        cls.meta = prior.RevealActionLinkStageTests.meta

    def machine(self, **options):
        return HandoffMachine(self.image, self.meta, **options)

    def assert_unlocked(self, machine):
        self.assertFalse(machine.paint_locked)
        self.assertEqual([event[0] for event in machine.lock_events],
                         [index % 2 == 0 for index in range(len(machine.lock_events))])

    def test_actual_append_get_remove_and_mutex_callbacks_execute(self):
        m = self.machine()
        self.assertEqual(m.publish(), (1, 0))  # append index0 IS success
        self.assertEqual(m.words_at(m.head(), 10), (*PAYLOAD, 1))
        self.assertEqual(m.claim(), (STATE + core.COPY, 1))
        self.assertEqual(m.owned(), PAYLOAD)
        self.assertEqual(m.complete(1), (1, 0))
        for pc in (0x437CE0, 0x437D60, core.APPEND, 0x455BC0,
                   core.GET, core.REMOVE):
            self.assertIn(pc, m.trace)
        self.assertEqual(m.count(m.paint_list), 0)
        self.assert_unlocked(m)

    def test_new_format_preserves_all36_bytes_and_independent_lali_tail(self):
        m = self.machine()
        payload = (0xFFFFFFFF, 0x80000000, 0, 0, MASK, 0x80000000, 7, MASK, 0)
        self.assertEqual(m.publish(payload), (1, 0))
        self.assertEqual(m.words_at(m.head(), 10), (*payload, 1))
        self.assertEqual(m.claim(), (STATE + core.COPY, 1))
        self.assertEqual(m.owned(), payload)
        self.assertEqual(m.complete(1, 0), (2, 0))

    def test_head_retained_until_exact_ack_and_second_claim_is_denied(self):
        m = self.machine()
        m.publish()
        m.publish((*PAYLOAD[:-1], 99))
        self.assertEqual(m.claim(), (STATE + core.COPY, 1))
        self.assertEqual(m.count(m.paint_list), 2)
        self.assertEqual(m.claim(), (0, 0))
        self.assertEqual(m.complete(2), (0, 0))
        self.assertEqual(m.complete(0), (0, 0))
        self.assertEqual(m.count(m.paint_list), 2)
        self.assertEqual(m.complete(1), (1, 0))
        self.assertEqual(m.complete(1), (0, 0))
        self.assertEqual(m.claim(), (STATE + core.COPY, 2))
        self.assertEqual(m.owned()[-1], 99)

    def test_failed_outcome_removes_only_acknowledged_head(self):
        m = self.machine()
        m.publish()
        m.publish()
        m.claim()
        self.assertEqual(m.complete(1, 0), (2, 0))
        self.assertEqual(m.count(m.paint_list), 1)
        self.assertEqual(m.peek(m.head() + core.NONCE), 2)

    def test_cancel_retains_head_and_owned_copy_until_cancelled_ack(self):
        m = self.machine()
        m.publish()
        m.claim()
        self.assertEqual(m.invoke('cancel'), (1, 0))
        self.assertEqual(m.invoke('cancel'), (1, 0))
        self.assertEqual(m.state(core.CANCELLED), 1)
        self.assertEqual(m.count(m.paint_list), 1)
        self.assertEqual(m.owned(), PAYLOAD)
        self.assertEqual(m.claim(), (0, 0))
        self.assertEqual(m.complete(1), (3, 0))
        self.assertEqual(m.state(core.ACTIVE), 0)

    def test_cancel_without_active_does_not_close_or_remove_unclaimed(self):
        m = self.machine()
        self.assertEqual(m.invoke('cancel'), (0, 0))
        m.publish()
        self.assertEqual(m.invoke('cancel'), (0, 0))
        self.assertEqual(m.count(m.paint_list), 1)
        self.assertEqual(m.state(core.CLOSED), 0)
        self.assertEqual(m.claim()[1], 1)

    def test_close_denies_new_work_but_exact_cancelled_ack_remains(self):
        m = self.machine()
        m.publish()
        m.claim()
        self.assertEqual(m.invoke('close'), (1, 0))
        self.assertEqual(m.publish(), (0, 0))
        self.assertEqual(m.claim(), (0, 0))
        self.assertEqual(m.complete(1), (3, 0))
        self.assertEqual(m.invoke('close'), (0, 0))
        self.assertEqual(m.state(core.CLOSED), 1)
        self.assertEqual(m.state(core.SERIAL), 1)

    def test_capacity_backpressure_does_not_burn_ticket_or_evict_head(self):
        m = self.machine(capacity=1)
        self.assertEqual(m.publish(), (1, 0))
        self.assertEqual(m.publish(), (0, 0))
        m.claim()
        m.invoke('cancel')
        self.assertEqual(m.publish(), (0, 0))
        self.assertEqual(m.state(core.SERIAL), 1)
        self.assertEqual(m.complete(1), (3, 0))
        self.assertEqual(m.publish(), (2, 0))

    def test_exhaustion_is_terminal_nonwrapping_and_allows_cancelled_ack(self):
        m = self.machine(ticket_limit=1)
        m.publish()
        m.claim()
        self.assertEqual(m.publish(), (0, 0))
        self.assertEqual(m.state(core.SERIAL), 1)
        self.assertEqual(m.state(core.FAULT), 1)
        self.assertEqual(m.state(core.CANCELLED), 1)
        self.assertEqual(m.complete(1), (3, 0))
        self.assertEqual(m.publish(), (0, 0))
        self.assertEqual(m.claim(), (0, 0))

    def test_empty_claim_never_calls_getter_or_mutates_private_copy(self):
        m = self.machine()
        self.assertEqual(m.claim(), (0, 0))
        self.assertNotIn(core.GET, m.trace)
        self.assertEqual(m.owned(), (0,) * 9)

    def test_actual_failed_table_growth_burns_nonce_and_withdraws_terminally(self):
        m = self.machine(capacity=80)
        for nonce in range(1, 71):
            self.assertEqual(m.publish(), (nonce, nonce - 1))
        self.assertEqual(m.peek(m.paint_list + 8), 70)
        m.fail_next_heap = True  # actual466B20 -> actual4669E0 service failure
        self.assertEqual(m.publish(), (0, MASK))
        self.assertEqual(m.peek(m.paint_list), 0)  # actual455A08 failure effect
        self.assertEqual(m.count(m.paint_list), 70)
        self.assertEqual(m.state(core.SERIAL), 71)
        self.assertEqual(m.state(core.FAULT), 1)
        m.trace.clear()
        self.assertEqual(m.publish(), (0, 0))
        self.assertEqual(m.claim(), (0, 0))
        self.assertNotIn(core.GET, m.trace)
        self.assert_unlocked(m)

    def test_failed_new_chunk_preserves_ack_only_when_old_storage_is_intact(self):
        m = self.machine(capacity=80)
        for _ in range(70):
            m.publish()
        m.claim()
        m.fail_heap_in = 2  # grow's table realloc succeeds; new chunk fails
        self.assertEqual(m.publish(), (0, MASK))
        self.assertNotEqual(m.peek(m.paint_list), 0)
        self.assertEqual(m.count(m.paint_list), 70)
        self.assertEqual(m.state(core.FAULT), 1)
        self.assertEqual(m.complete(1), (3, 0))
        self.assertEqual(m.count(m.paint_list), 69)
        self.assertEqual(m.state(core.ACTIVE), 0)
        self.assert_unlocked(m)

    def test_wrong_controller_denied_before_lock_state_or_source_reads(self):
        m = self.machine()
        m.read_events.clear()
        self.assertEqual(m.invoke('publish', 0xBAD00000,
                                  controller=CONTROLLER + 4), (0, 0))
        self.assertEqual(m.calls, [])
        self.assertEqual(m.read_events, [])

    def test_invalid_input_extents_aliases_rejected_before_any_save_or_lock(self):
        for source in (0, INPUT + 1, MASK - 3, MASK - 31,
                       STATE, STATE - 32, STATE + core.COPY,
                       STACK - core.FRAME, STACK - 4, CONTROLLER):
            with self.subTest(source=hex(source)):
                m = self.machine()
                m.read_events.clear()
                m.writes.clear()
                self.assertEqual(m.invoke('publish', source), (0, 0))
                self.assertEqual(m.calls, [])
                self.assertEqual(m.writes, [])
                self.assertEqual(m.read_events, [])

    def test_input_adjacent_to_prospective_frame_is_allowed(self):
        m = self.machine()
        source = STACK
        for offset, value in enumerate(PAYLOAD):
            m.put(source + 4 * offset, value, 4)
        self.assertEqual(m.invoke('publish', source), (1, 0))
        m.claim()
        self.assertEqual(m.owned(), PAYLOAD)

    def test_malformed_stack_rejected_before_stores_or_native_calls(self):
        for stack in (0, core.FRAME - 8, STACK + 4, STATE + core.FRAME,
                      CONTROLLER + core.FRAME):
            m = self.machine()
            m.writes.clear()
            self.assertEqual(m.invoke('claim', stack=stack), (0, 0))
            self.assertEqual(m.calls, [])
            self.assertEqual(m.writes, [])

    def test_invalid_explicit_outcome_does_not_take_lock_or_ack(self):
        m = self.machine()
        m.publish()
        m.claim()
        m.calls.clear()
        for outcome in (2, MASK, 0x80000000):
            self.assertEqual(m.complete(1, outcome), (0, 0))
        self.assertEqual(m.calls, [])
        self.assertEqual(m.state(core.ACTIVE), 1)

    def test_incompatible_record_width_is_terminal_before_raw_method(self):
        m = self.machine(element_bytes=36)
        self.assertEqual(m.publish(), (0, 0))
        self.assertEqual(m.state(core.FAULT), 1)
        self.assertNotIn(core.APPEND, m.trace)
        self.assert_unlocked(m)

    def test_incompatible_native_method_binding_is_denied(self):
        for offset in (0x18, 0x20, 0x2C):
            m = self.machine()
            m.put(m.paint_list + offset, 0xBAD00000, 4)
            self.assertEqual(m.publish(), (0, 0))
            self.assertEqual(m.state(core.FAULT), 1)
            self.assertNotIn(core.APPEND, m.trace)
            self.assert_unlocked(m)

    def test_lock_failure_reads_no_state_or_list_and_does_not_unlock(self):
        m = self.machine()
        m.acquire_result = 5
        self.assertEqual(m.publish(), (0, 0))
        self.assertNotIn(0x437D60, m.trace)
        self.assertFalse(any(STATE <= address < STATE + core.STATE_BYTES
                             or m.paint_list <= address < m.paint_list + core.LIST_BYTES
                             for _, address, *_ in m.read_events))
        self.assertEqual(m.state(core.SERIAL), 0)

    def test_unlock_failure_denies_success_and_publishes_monotonic_fault_only(self):
        m = self.machine()
        m.release_result = 5
        self.assertEqual(m.publish(), (0, 0))
        self.assertEqual(m.count(m.paint_list), 1)  # no fictitious rollback
        self.assertEqual(m.state(core.SERIAL), 1)
        self.assertEqual(m.state(core.FAULT), 1)
        # Fixture service intentionally leaves ownership unknown/held. This
        # test does not attempt another native operation or claim safe unlock.
        self.assertTrue(m.paint_locked)

    def test_callee_saved_register_stack_and_hi_lo_survive_hostile_calls(self):
        m = self.machine()
        for label, args in (('publish', (INPUT,)), ('claim', ()),
                            ('cancel', ()), ('complete', (1, 1)), ('close', ())):
            for offset, value in enumerate(PAYLOAD):
                m.put(INPUT + offset * 4, value, 4)
            before = {register: m.r[register] for register in range(16, 29)}
            m.hi, m.lo = 0x12345678, 0xABCDEF01
            m.invoke(label, *args)
            self.assertEqual({register: m.r[register] for register in range(16, 29)}, before)
            self.assertEqual((m.r[29], m.r[31]), (STACK, RETURN))
            self.assertEqual((m.hi, m.lo), (0x12345678, 0xABCDEF01))
        self.assert_unlocked(m)

    def test_payload_reads_are_under148_and_only_owned36_bytes(self):
        m = self.machine()
        m.publish()
        reads = [(address, size, locked) for _, address, size, _, locked in m.read_events
                 if INPUT <= address < INPUT + 0x100]
        self.assertEqual(reads, [(INPUT + offset, 4, True)
                                 for offset in range(0, core.PAYLOAD_BYTES, 4)])

    def test_late_duplicate_cannot_remove_new_head_even_equal_payload(self):
        m = self.machine()
        m.publish()
        m.claim()
        m.complete(1)
        m.publish()
        self.assertEqual(m.claim()[1], 2)
        self.assertEqual(m.complete(1), (0, 0))
        self.assertEqual(m.state(core.ACTIVE), 2)
        self.assertEqual(m.count(m.paint_list), 1)
        self.assertEqual(m.complete(2), (1, 0))

    def test_config_validation_and_nonoverlap(self):
        for name in ('capacity', 'ticket_limit'):
            for value in (0, -1, True, 0x80000000, '64'):
                with self.subTest(name=name, value=value):
                    with self.assertRaises(ValueError):
                        core.assemble(STATE, CONTROLLER, CODE, **{name: value})
        for values in ((0, CONTROLLER, CODE), (STATE + 1, CONTROLLER, CODE),
                       (STATE, 0, CODE), (STATE, CONTROLLER + 1, CODE),
                       (STATE, CONTROLLER, 0), (STATE, CONTROLLER, CODE + 1),
                       (0xFFFFFFE0, CONTROLLER, CODE), (STATE, 0xFFFFFF00, CODE),
                       (STATE, STATE, CODE), (STATE, CONTROLLER, STATE),
                       (STATE, CONTROLLER, CONTROLLER),
                       (STATE, CONTROLLER, 0x0FFFFFFC),
                       (STATE, CONTROLLER, 0xFFFFFFFC)):
            with self.subTest(values=values):
                with self.assertRaises(ValueError):
                    core.assemble(*values)


if __name__ == '__main__':
    unittest.main()
