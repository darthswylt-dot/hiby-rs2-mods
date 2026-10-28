#!/usr/bin/env python3
"""Fail-closed boundaries of optional one-shot CINT48 request preparation.

Raw failures leave gate effects in place and isolate the whole instance; no
retry, guessed unlock, native lifetime claim or native destruction is modeled.
Controlled barrier outcomes test export postconditions, not native atomicity.
"""

import unittest

import reveal_paint_retirement_mips as paint
import reveal_registry_receipt_mips as receipt
import reveal_retained_operations_mips as core
import test_reveal_cleanup_intent_mips as fixture
from test_reveal_cleanup_intent_mips import (
    INTENT, CLEANUP_OUTPUT, SECOND_OUTPUT, LEDGER, RETAINED_MUTEX,
    HEADER_BYTES, OP_BYTES, DONE)
from test_reveal_deferred_queue_mips import TRANSPORT_MUTEX, FAULT
from test_reveal_registry_owner_mips import (
    STATE, BIND_STATE, OWNER_STATE, CODE, CONTROLLER, REGISTRY_MUTEX,
    PAINT_MUTEX, RAW_LOCK, RAW_UNLOCK, STACK, RETURN, MASK)


class CleanupIntentAdversarialTests(unittest.TestCase):
    setUpClass = classmethod(fixture.CleanupIntentTests.setUpClass.__func__)
    machine = fixture.CleanupIntentTests.machine
    prepared = fixture.CleanupIntentTests.prepared
    publish_one = fixture.CleanupIntentTests.publish_one
    closed_empty = fixture.CleanupIntentTests.closed_empty
    assert_no_barrier = fixture.CleanupIntentTests.assert_no_barrier

    def test_each_initial_dirty_output_word_refuses_before_save_or_gate_access(self):
        for offset in range(0, 48, 4):
            with self.subTest(offset=offset):
                m = self.machine()
                self.closed_empty(m)
                m.put(CLEANUP_OUTPUT + offset, 0xA55A0000 + offset, 4)
                expected = m.cleanup_output()
                m.clear_events()
                self.assertEqual(m.prepare_cleanup(), (0, 0))
                self.assertEqual(m.cleanup_output(), expected)
                self.assertEqual(m.peek(INTENT), 0)
                self.assertEqual(m.raw_events, [])
                self.assertEqual(m.writes, [])
                self.assertEqual(m.intent_accesses, [])
                self.assert_no_barrier(m)

    def test_each_late_dirty_output_word_consumes_attempt_without_any_output_store(self):
        for offset in range(0, 48, 4):
            with self.subTest(offset=offset):
                m = self.machine()
                self.closed_empty(m)

                def dirty(machine, pc):
                    if pc == machine.retained_labels['after_cleanup_intent_barrier']:
                        machine.put(CLEANUP_OUTPUT + offset, 0xA55A0000 + offset, 4)

                m.on_instruction = dirty
                self.assertEqual(m.prepare_cleanup(), (0, 0))
                expected = tuple(0xA55A0000 + offset if i == offset else 0
                                 for i in range(0, 48, 4))
                self.assertEqual(m.cleanup_output(), expected)
                writes = [e for e in m.writes
                          if CLEANUP_OUTPUT <= e[0] < CLEANUP_OUTPUT + 48]
                self.assertEqual(writes, [(CLEANUP_OUTPUT + offset,
                                           0xA55A0000 + offset, 4)])
                self.assertEqual(m.peek(INTENT), 1)
                m.on_instruction = None
                m.clear_events()
                self.assertEqual(m.prepare_cleanup(SECOND_OUTPUT), (0, 0))
                self.assert_no_barrier(m)

    def test_raw_initial_m_acquire_failure_has_no_gate_or_ledger_effects(self):
        for status, held in ((22, False), (MASK, True)):
            with self.subTest(status=status, held=held):
                m = self.machine()
                self.closed_empty(m)
                expected = m.ledger_header()
                m.retained_acquire = status
                m.retained_acquire_failure_holds = held
                m.clear_events()
                self.assertEqual(m.prepare_cleanup(), (0, status))
                self.assertEqual(m.peek(INTENT), 0)
                self.assertEqual(m.ledger_header(), expected)
                self.assertEqual(m.retained_accesses, [])
                self.assertEqual(m.intent_accesses, [])
                self.assertEqual(m.cleanup_output(), (0,) * 12)
                self.assertEqual([(e[0], e[1]) for e in m.raw_events],
                                 [(RAW_LOCK, RETAINED_MUTEX)])
                self.assertEqual(m.retained_held, held)
                self.assert_no_barrier(m)

    def test_raw_initial_m_release_failure_leaves_reservation_and_stops(self):
        for released in (False, True):
            with self.subTest(released=released):
                m = self.machine()
                self.closed_empty(m)
                m.retained_release = 0x82
                m.retained_release_failure_releases = released
                boundaries = []

                def observe(machine, target):
                    if target == RAW_UNLOCK and machine.r[4] == RETAINED_MUTEX:
                        boundaries.append((len(machine.retained_accesses),
                                           len(machine.intent_accesses)))

                m.on_service = observe
                self.assertEqual(m.prepare_cleanup(), (0, 0x82))
                self.assertEqual(m.peek(INTENT), 1)
                self.assertEqual(boundaries, [(len(m.retained_accesses),
                                               len(m.intent_accesses))])
                self.assertEqual(m.cleanup_output(), (0,) * 12)
                self.assertEqual([e[0] for e in m.retained_events],
                                 [RAW_LOCK, RAW_UNLOCK])
                self.assertEqual(m.retained_held, not released)
                self.assert_no_barrier(m)

    def test_raw_barrier_m_acquire_failure_never_releases_or_enters_paint(self):
        for held in (False, True):
            with self.subTest(held=held):
                m = self.machine()
                self.closed_empty(m)

                def fail(machine, pc):
                    if pc == machine.retained_labels['before_cleanup_intent_barrier']:
                        machine.retained_acquire = 22
                        machine.retained_acquire_failure_holds = held

                m.on_instruction = fail
                self.assertEqual(m.prepare_cleanup(), (0, 22))
                self.assertEqual(m.peek(INTENT), 1)
                self.assertEqual(m.cleanup_output(), (0,) * 12)
                self.assertEqual([(e[0], e[1]) for e in m.raw_events],
                                 [(RAW_LOCK, RETAINED_MUTEX),
                                  (RAW_UNLOCK, RETAINED_MUTEX),
                                  (RAW_LOCK, RETAINED_MUTEX)])
                self.assertNotIn(m.owner_labels['retire'], m.trace)
                self.assertEqual(m.retained_held, held)

    def test_raw_barrier_m_release_failure_never_enters_paint_or_reads_gate_again(self):
        for released in (False, True):
            with self.subTest(released=released):
                m = self.machine()
                self.closed_empty(m)
                boundaries = []

                def fail(machine, pc):
                    if pc == machine.retained_labels['quiescent_before_release']:
                        machine.retained_release = 0x82
                        machine.retained_release_failure_releases = released

                def observe(machine, target):
                    if (target == RAW_UNLOCK and machine.r[4] == RETAINED_MUTEX
                            and machine.retained_release):
                        boundaries.append((len(machine.retained_accesses),
                                           len(machine.intent_accesses)))

                m.on_instruction, m.on_service = fail, observe
                self.assertEqual(m.prepare_cleanup(), (0, 0x82))
                self.assertEqual(m.peek(INTENT), 1)
                self.assertEqual(boundaries, [(len(m.retained_accesses),
                                               len(m.intent_accesses))])
                self.assertEqual(m.cleanup_output(), (0,) * 12)
                self.assertNotIn(m.owner_labels['retire'], m.trace)
                self.assertEqual(m.retained_held, not released)

    def test_raw_paint_retire_acquire_or_release_failure_never_exports_or_drains(self):
        for field, held_flag in (('paint_acquire_result', 'paint_acquire_failure_holds'),
                                 ('paint_release_result', 'paint_release_failure_releases')):
            for uncertain_held in (False, True):
                with self.subTest(field=field, held=uncertain_held):
                    m = self.machine()
                    self.closed_empty(m)
                    setattr(m, field, 22)
                    setattr(m, held_flag, uncertain_held if field.startswith('paint_acquire')
                            else not uncertain_held)
                    boundaries = []

                    def observe(machine, target):
                        if machine.r[4] == PAINT_MUTEX:
                            if ((field == 'paint_acquire_result' and target == RAW_LOCK)
                                    or (field == 'paint_release_result' and target == RAW_UNLOCK)):
                                boundaries.append((len(machine.retained_accesses),
                                                   len(machine.intent_accesses),
                                                   len(machine.raw_events)))

                    m.on_service = observe
                    self.assertEqual(m.prepare_cleanup(), (0, 22))
                    self.assertEqual(m.peek(INTENT), 1)
                    self.assertEqual(m.cleanup_output(), (0,) * 12)
                    self.assertNotIn(m.owner_labels['drained'], m.trace)
                    self.assertEqual(boundaries, [(len(m.retained_accesses),
                                                   len(m.intent_accesses),
                                                   len(m.raw_events))])
                    self.assertEqual(m.paint_held, uncertain_held)

    def test_raw_paint_drained_acquire_and_release_failure_do_not_export(self):
        for field in ('paint_acquire_result', 'paint_release_result'):
            with self.subTest(field=field):
                m = self.machine()
                self.closed_empty(m)

                def fail(machine, pc):
                    if pc == machine.retained_labels['before_drained']:
                        setattr(machine, field, 22)

                m.on_instruction = fail
                self.assertEqual(m.prepare_cleanup(), (0, 22))
                self.assertEqual(m.peek(INTENT), 1)
                self.assertEqual(m.cleanup_output(), (0,) * 12)
                self.assertEqual(m.owner_record()[2], 1)
                self.assertEqual([e[0] for e in m.retained_events],
                                 [RAW_LOCK, RAW_UNLOCK, RAW_LOCK, RAW_UNLOCK])

    def test_ordinary_paint_fault_consumes_attempt_without_cleanup_request(self):
        m = self.machine()
        self.closed_empty(m)
        m.put(OWNER_STATE + paint.FAULT, 1, 4)
        m.clear_events()
        self.assertEqual(m.prepare_cleanup(), (0, 0))
        self.assertEqual(m.peek(INTENT), 1)
        self.assertEqual(m.cleanup_output(), (0,) * 12)
        self.assertIn(m.owner_labels['retire'], m.trace)
        self.assertNotIn(m.owner_labels['drained'], m.trace)
        m.clear_events()
        self.assertEqual(m.prepare_cleanup(SECOND_OUTPUT), (0, 0))
        self.assert_no_barrier(m)

    def test_only_exact_barrier_one_zero_can_commit_output(self):
        for result in ((0, 0), (2, 0), (1, 22), (MASK, 0)):
            with self.subTest(result=result):
                m = self.machine()
                self.closed_empty(m)

                def replace(machine, pc):
                    if pc == machine.retained_labels['after_cleanup_intent_barrier']:
                        machine.r[2:4] = result

                m.on_instruction = replace
                self.assertEqual(m.prepare_cleanup(), (0, result[1]))
                self.assertEqual(m.peek(INTENT), 1)
                self.assertEqual(m.cleanup_output(), (0,) * 12)
                self.assertNotIn(m.retained_labels['before_cleanup_intent_output'], m.trace)

    def test_corrupt_ledger_schema_refuses_before_reserving_any_attempt(self):
        for offset, value in ((0, 3), (8, 17), (12, 1), (60, 1),
                              (HEADER_BYTES, 9), (HEADER_BYTES + 4, 7),
                              (HEADER_BYTES + 8, 1), (HEADER_BYTES + 12, 1)):
            with self.subTest(offset=offset, value=value):
                m = self.machine()
                self.closed_empty(m)
                m.put(LEDGER + offset, value, 4)
                m.clear_events()
                self.assertEqual(m.prepare_cleanup(), (0, 0))
                self.assertEqual(m.peek(INTENT), 0)
                self.assertNotEqual(m.ledger_header()[1], 0)
                self.assert_no_barrier(m)

    def test_dirty_unused_last_operation_row_cannot_be_ignored_by_preparation(self):
        m = self.machine()
        self.closed_empty(m)
        m.put(m.operation_address(m.operation_capacity - 1) + 12, 1, 4)
        m.clear_events()
        self.assertEqual(m.prepare_cleanup(), (0, 0))
        self.assertEqual(m.ledger_header()[1], 2)
        self.assertEqual(m.peek(INTENT), 0)
        self.assert_no_barrier(m)

    def test_corrupt_native_queue_header_cannot_be_accepted_as_empty(self):
        for offset, value in ((16, 68), (20, 9), (8, 0), (8, 20),
                              (12, 41), (0, 0), (0, 1)):
            with self.subTest(offset=offset, value=value):
                m = self.machine()
                self.closed_empty(m)
                m.put(m.retained_list + offset, value, 4)
                m.clear_events()
                self.assertEqual(m.prepare_cleanup(), (0, 0))
                self.assertEqual(m.peek(INTENT), 0)
                self.assertEqual(m.ledger_header()[1], 1)
                self.assert_no_barrier(m)

    def test_preexisting_nonzero_intent_is_never_reset_or_reused(self):
        for value in (1, 2, MASK):
            with self.subTest(value=value):
                m = self.machine()
                self.closed_empty(m)
                m.put(INTENT, value, 4)
                m.clear_events()
                self.assertEqual(m.prepare_cleanup(), (0, 0))
                self.assertEqual(m.peek(INTENT), value)
                self.assert_no_barrier(m)
                self.assertFalse(any(e[0] == 'write' for e in m.intent_accesses))

    def test_acking_operation_stays_outstanding_and_cannot_consume_intent(self):
        m = self.machine()
        self.publish_one(m)
        self.assertEqual(m.complete(2), (0, 0))  # no actual claim: ambiguous
        self.assertEqual(m.close(), (1, 0))
        m.clear_events()
        self.assertEqual(m.prepare_cleanup(), (0, 0))
        self.assertEqual(m.peek(INTENT), 0)
        self.assert_no_barrier(m)

    def test_full_output_guards_exclude_every_fixed_extent_and_full_rx(self):
        m = self.machine()
        spans = ((STATE, m.composition['receipt_memory_bytes']),
                 (BIND_STATE, m.composition['binding_memory_bytes']),
                 (OWNER_STATE, m.composition['owner_memory_bytes']),
                 (CONTROLLER, receipt.CONTROLLER_BYTES),
                 (REGISTRY_MUTEX, 24), (PAINT_MUTEX, 24),
                 (m.deferred_list, 56), (TRANSPORT_MUTEX, 24), (FAULT, 4),
                 (LEDGER, HEADER_BYTES + OP_BYTES * m.operation_capacity),
                 (m.retained_list, 56), (RETAINED_MUTEX, 24), (INTENT, 4),
                 (receipt.NATIVE_RX[0], receipt.NATIVE_RX[1] - receipt.NATIVE_RX[0]),
                 (CODE, len(m.code)))
        bad = [0, 1, MASK - 3, 0xFFFFFFD4, STACK - core.FRAME, STACK - 4]
        for start, length in spans:
            bad.extend((start, start - 44, start + length - 4))
        for pointer in bad:
            with self.subTest(pointer=hex(pointer)):
                m.clear_events()
                self.assertEqual(m.prepare_cleanup(pointer), (0, 0))
                self.assertEqual(m.raw_events, [])
                self.assertEqual(m.reads, [])
                self.assertEqual(m.writes, [])

    def test_unsigned_last_byte_and_signed_boundary_outputs_are_supported(self):
        for pointer in (0x100000000 - 48, 0x7FFFFFF0):
            with self.subTest(pointer=hex(pointer)):
                m = self.machine()
                self.closed_empty(m)
                m.map(pointer, 48)
                expected = m.ledger_header()[4:15]
                self.assertEqual(m.prepare_cleanup(pointer), (pointer, 0))
                self.assertEqual(m.cleanup_output(pointer),
                                 (core.CLEANUP_INTENT_MAGIC, *expected))

    def test_foreign_controller_and_invalid_frame_refuse_before_all_memory_access(self):
        m = self.machine()
        for options in ({'controller': 0}, {'controller': CONTROLLER + 4},
                        {'stack': 0}, {'stack': STACK + 4},
                        {'stack': core.FRAME - 8},
                        {'stack': LEDGER + core.FRAME},
                        {'stack': RETAINED_MUTEX + core.FRAME},
                        {'stack': INTENT + core.FRAME},
                        {'stack': CODE + core.FRAME}):
            with self.subTest(options=options):
                m.clear_events()
                self.assertEqual(m.prepare_cleanup(**options), (0, 0))
                self.assertEqual(m.raw_events, [])
                self.assertEqual(m.reads, [])
                self.assertEqual(m.writes, [])

    def test_preexisting_ledger_fault_refuses_without_gate_or_paint_work(self):
        m = self.machine()
        self.closed_empty(m)
        m.put(LEDGER + 4, 0xDEAD, 4)
        m.clear_events()
        self.assertEqual(m.prepare_cleanup(), (0, 0))
        self.assertEqual(m.peek(INTENT), 0)
        self.assertEqual(m.ledger_header()[1], 0xDEAD)
        self.assertEqual(m.intent_accesses, [])
        self.assert_no_barrier(m)

    def test_saved_registers_stack_return_and_hilo_survive_hostile_raw_services(self):
        m = self.machine()
        self.closed_empty(m)
        saved = {reg: 0x77200000 + reg for reg in (*range(16, 24), 28, 30)}
        for reg, value in saved.items():
            m.r[reg] = value
        m.hi, m.lo = 0x12345678, 0xABCDEF01
        self.assertEqual(m.prepare_cleanup(), (CLEANUP_OUTPUT, 0))
        self.assertEqual({reg: m.r[reg] for reg in saved}, saved)
        self.assertEqual((m.r[29], m.r[31]), (STACK, RETURN))
        self.assertEqual((m.hi, m.lo), (0x12345678, 0xABCDEF01))


if __name__ == '__main__':
    unittest.main()
