#!/usr/bin/env python3
"""Fault/ABI boundaries for emitted retained-operation accounting.

Controlled replacement native results exercise wrapper postconditions, not
native failure atomicity. Raw errors isolate the whole fixture immediately;
neither apparent queue emptiness nor an ambiguous mutex result permits retry,
ledger repair, native destruction or release of externally retained storage.
"""

import unittest

from build_reveal_bridge_diag import b
import reveal_creation_capture_mips as capture
import reveal_paint_retirement_mips as paint
import reveal_retained_operations_mips as core
import test_reveal_retained_operations_mips as fixture
from test_reveal_retained_operations_mips import (
    LEDGER, RETAINED_MUTEX, BUNDLE, HEADER_BYTES, OP_BYTES,
    OPEN, CLOSED, RESERVED, QUEUED, EXTRACTED, PUBLISHED, ACKING, DONE)
from test_reveal_constructor_capture_mips import OUTPUT
from test_reveal_deferred_envelope_mips import ENVELOPE, APPEND, GET, REMOVE
from test_reveal_deferred_queue_mips import TRANSPORT_MUTEX, FAULT
from test_reveal_registry_owner_mips import (
    STATE, BIND_STATE, OWNER_STATE, CODE, CONTROLLER, REGISTRY_MUTEX,
    PAINT_MUTEX, RAW_LOCK, RAW_UNLOCK, STACK, RETURN, MASK)


class RetainedOperationsAdversarialTests(unittest.TestCase):
    setUpClass = classmethod(fixture.RetainedOperationsTests.setUpClass.__func__)
    machine = fixture.RetainedOperationsTests.machine
    prepared = fixture.RetainedOperationsTests.prepared
    publish_one = fixture.RetainedOperationsTests.publish_one
    assert_guarded = fixture.RetainedOperationsTests.assert_guarded

    def setup_operation(self, operation):
        m = self.machine()
        if operation == 'complete':
            self.publish_one(m)
            m.claim()
        else:
            self.prepared(m, bind=operation != 'bind')
            if operation == 'pop_dispatch':
                self.assertEqual(m.enqueue(), (1, 0))
            if operation == 'quiescent':
                self.assertEqual(m.close(), (1, 0))
        return m

    def invoke_operation(self, m, operation, **options):
        return (m.complete(2, **options) if operation == 'complete'
                else getattr(m, operation)(**options))

    def test_raw_mutex_acquire_error_never_touches_ledger_queue_or_other_mutex(self):
        for operation in ('bind', 'enqueue', 'pop_dispatch', 'complete',
                          'close', 'quiescent'):
            for status, held in ((22, False), (MASK, True)):
                with self.subTest(operation=operation, status=status, held=held):
                    m = self.setup_operation(operation)
                    before = m.ledger_header(), m.operation(), m.retained_count()
                    m.retained_acquire = status
                    m.retained_acquire_failure_holds = held
                    m.clear_events()
                    self.assertEqual(self.invoke_operation(m, operation), (0, status))
                    self.assertEqual(m.retained_accesses, [])
                    self.assertEqual(m.ledger_header(), before[0])
                    self.assertEqual(m.operation(), before[1])
                    self.assertEqual(m.retained_count(), before[2])
                    self.assertEqual([(e[0], e[1]) for e in m.raw_events],
                                     [(RAW_LOCK, RETAINED_MUTEX)])
                    self.assertEqual(m.retained_held, held)

    def test_raw_mutex_release_error_stops_after_effects_without_guessing_unlock(self):
        expected_state = {'bind': None, 'enqueue': QUEUED,
                          'pop_dispatch': EXTRACTED, 'complete': ACKING,
                          'close': None, 'quiescent': None}
        for operation in expected_state:
            for released in (False, True):
                with self.subTest(operation=operation, released=released):
                    m = self.setup_operation(operation)
                    m.retained_release = 0x82
                    m.retained_release_failure_releases = released
                    boundaries = []

                    def at_unlock(machine, target):
                        if target == RAW_UNLOCK and machine.r[4] == RETAINED_MUTEX:
                            boundaries.append(len(machine.retained_accesses))

                    m.on_service = at_unlock
                    m.clear_events()
                    self.assertEqual(self.invoke_operation(m, operation), (0, 0x82))
                    self.assertEqual(boundaries, [len(m.retained_accesses)])
                    self.assertEqual([(e[0], e[1]) for e in m.raw_events],
                                     [(RAW_LOCK, RETAINED_MUTEX),
                                      (RAW_UNLOCK, RETAINED_MUTEX)])
                    self.assertEqual(m.retained_held, not released)
                    state = expected_state[operation]
                    if state is not None:
                        self.assertEqual(m.operation()[1], state)
                    self.assertNotIn(m.envelope_labels['dispatch'], m.trace)
                    self.assertNotIn(m.owner_labels['complete'], m.trace)
                    self.assertNotIn(m.owner_labels['retire'], m.trace)

    def test_raw_publisher_errors_leave_extracted_outstanding_without_rebinding(self):
        for field in ('acquire', 'release', 'paint_acquire_result',
                      'paint_release_result'):
            with self.subTest(field=field):
                m = self.machine()
                self.prepared(m)
                self.assertEqual(m.enqueue(), (1, 0))
                setattr(m, field, 22)
                m.clear_events()
                self.assertEqual(m.pop_dispatch(), (0, 22))
                self.assertEqual(m.operation(), (1, EXTRACTED, 0, 0))
                self.assertEqual(m.retained_count(), 0)
                self.assertEqual([e[0] for e in m.retained_events],
                                 [RAW_LOCK, RAW_UNLOCK])
                self.assertEqual(m.ledger_header()[1], 0)
                self.assertNotIn(m.retained_labels['pop_rebind_before_lock'], m.trace)

    def test_raw_paint_complete_error_leaves_acking_and_never_reacquires_ledger(self):
        for field in ('paint_acquire_result', 'paint_release_result'):
            with self.subTest(field=field):
                m = self.machine()
                self.publish_one(m)
                m.claim()
                setattr(m, field, 22)
                m.clear_events()
                self.assertEqual(m.complete(2), (0, 22))
                self.assertEqual(m.operation(), (1, ACKING, 2, 0))
                self.assertEqual([e[0] for e in m.retained_events],
                                 [RAW_LOCK, RAW_UNLOCK])
                self.assertNotIn(m.retained_labels['complete_rebind_before_lock'], m.trace)

    def test_publish_rebind_acquire_error_does_not_forget_already_visible_paint(self):
        m = self.machine()
        self.prepared(m)
        self.assertEqual(m.enqueue(), (1, 0))

        def fail_rebind(machine, pc):
            if pc == machine.retained_labels['pop_rebind_before_lock']:
                machine.retained_acquire = 22

        m.on_instruction = fail_rebind
        m.clear_events()
        self.assertEqual(m.pop_dispatch(), (0, 22))
        self.assertEqual(m.count(), 1)
        self.assertEqual(m.operation(), (1, EXTRACTED, 0, 0))
        self.assertEqual([e[0] for e in m.retained_events],
                         [RAW_LOCK, RAW_UNLOCK, RAW_LOCK])
        self.assertEqual(m.ledger_header()[1], 0)

    def test_complete_rebind_acquire_error_keeps_acking_after_actual_removal(self):
        m = self.machine()
        self.publish_one(m)
        m.claim()

        def fail_rebind(machine, pc):
            if pc == machine.retained_labels['complete_rebind_before_lock']:
                machine.retained_acquire = 22

        m.on_instruction = fail_rebind
        m.clear_events()
        self.assertEqual(m.complete(2), (0, 22))
        self.assertEqual(m.count(), 0)
        self.assertEqual(m.operation(), (1, ACKING, 2, 0))
        self.assertEqual([e[0] for e in m.retained_events],
                         [RAW_LOCK, RAW_UNLOCK, RAW_LOCK])

    def test_unclaimed_complete_zero_zero_is_permanently_acking_not_retryable(self):
        m = self.machine()
        self.publish_one(m)
        self.assertEqual(m.complete(2), (0, 0))
        self.assertEqual(m.operation(), (1, ACKING, 2, 0))
        self.assertEqual(m.claim()[1], 2)
        m.clear_events()
        self.assertEqual(m.complete(2), (0, 0))
        self.assertNotIn(m.owner_labels['complete'], m.trace)
        self.assertEqual(m.close(), (1, 0))
        self.assertEqual(m.quiescent(), (0, 0))

    def test_paint_post_remove_fault_does_not_turn_zero_zero_into_terminal_ack(self):
        m = self.machine()
        self.publish_one(m)
        m.claim()
        # The fixture substitutes the actual native REMOVE result rather
        # than assuming a successful zero alone means the queue changed.
        m.patches[REMOVE] = b.r_type(31, 0, 0, 8)
        m.patches[REMOVE + 4] = b.addiu(2, 0, 0)
        self.assertEqual(m.complete(2), (0, 0))
        self.assertEqual(m.operation(), (1, ACKING, 2, 0))
        self.assertNotEqual(m.peek(OWNER_STATE + paint.FAULT), 0)
        self.assertEqual(m.close(), (1, 0))
        self.assertEqual(m.quiescent(), (0, 0))

    def test_ordinary_publish_denial_still_requires_healthy_paint_drain_barrier(self):
        m = self.machine()
        self.prepared(m)
        self.assertEqual(m.enqueue(), (1, 0))
        # Existing paint fault is an ordinary publisher denial, not raw error.
        m.put(OWNER_STATE + paint.FAULT, 1, 4)
        self.assertEqual(m.pop_dispatch(), (0, 0))
        self.assertEqual(m.operation(), (1, DONE, 0, 0))
        self.assertEqual(m.close(), (1, 0))
        m.clear_events()
        self.assertEqual(m.quiescent(), (0, 0))
        self.assertIn(m.owner_labels['retire'], m.trace)
        self.assertEqual(m.freed, [])

    def test_raw_paint_retire_error_never_calls_drained_or_reenters_ledger(self):
        for field in ('paint_acquire_result', 'paint_release_result'):
            with self.subTest(field=field):
                m = self.machine()
                self.prepared(m)
                self.assertEqual(m.close(), (1, 0))
                setattr(m, field, 22)
                m.clear_events()
                self.assertEqual(m.quiescent(), (0, 22))
                self.assertNotIn(m.owner_labels['drained'], m.trace)
                self.assertEqual([e[0] for e in m.retained_events],
                                 [RAW_LOCK, RAW_UNLOCK])

    def test_raw_paint_drained_error_stops_after_retire_without_ledger_access(self):
        m = self.machine()
        self.prepared(m)
        self.assertEqual(m.close(), (1, 0))
        boundaries = []

        def fail_drained(machine, pc):
            if pc == machine.retained_labels['before_drained']:
                machine.paint_acquire_result = 22
                boundaries.append(len(machine.retained_accesses))

        m.on_instruction = fail_drained
        m.clear_events()
        self.assertEqual(m.quiescent(), (0, 22))
        self.assertEqual(boundaries, [len(m.retained_accesses)])
        self.assertEqual(m.owner_record()[2], 1)
        self.assertEqual([e[0] for e in m.retained_events], [RAW_LOCK, RAW_UNLOCK])

    def test_rebind_release_error_preserves_effects_without_late_shared_access(self):
        for operation, label, expected, paint_count in (
                ('pop_dispatch', 'pop_rebind_before_release', PUBLISHED, 1),
                ('complete', 'complete_rebind_before_release', DONE, 0)):
            for released in (False, True):
                with self.subTest(operation=operation, released=released):
                    m = self.setup_operation(operation)
                    m.retained_release_failure_releases = released
                    boundaries = []

                    def fail_release(machine, pc):
                        if pc == machine.retained_labels[label]:
                            machine.retained_release = 0x82

                    def observe(machine, target):
                        if (target == RAW_UNLOCK and machine.r[4] == RETAINED_MUTEX
                                and machine.retained_release):
                            boundaries.append(len(machine.retained_accesses))

                    m.on_instruction, m.on_service = fail_release, observe
                    m.clear_events()
                    self.assertEqual(self.invoke_operation(m, operation), (0, 0x82))
                    self.assertEqual(boundaries, [len(m.retained_accesses)])
                    self.assertEqual(m.operation(), (1, expected, 2, 0))
                    self.assertEqual(m.count(), paint_count)
                    self.assertEqual(m.retained_held, not released)

    def test_bind_requires_actual_checked_gcap_schema_before_mutex(self):
        for offset, value in ((capture.MAGIC, 0), (capture.FLAGS, 1),
                              (capture.CONTROLLER, CONTROLLER + 4),
                              (capture.BINDING_SEQUENCE, 0), (capture.OWNER, 0),
                              (capture.RECEIPT_SEQUENCE, 17), (capture.RESULT, 1)):
            with self.subTest(offset=offset, value=value):
                m = self.machine()
                self.prepared(m, bind=False)
                m.put(BUNDLE + offset, value, 4)
                m.clear_events()
                self.assertEqual(m.bind(), (0, 0))
                self.assertEqual(m.raw_events, [])
                self.assertEqual(m.retained_accesses, [])
                self.assertEqual(m.ledger_header(), (0,) * 16)

    def test_enqueue_rejects_valid_but_different_creation_capture(self):
        m = self.machine()
        self.prepared(m)
        second_output, second_envelope = OUTPUT + 48, ENVELOPE + 68
        engine, output = m.construct(output=second_output)
        self.assertEqual(output, second_output)
        self.assertEqual(m.pack_payload(m.positive_payload(engine),
                                       captured=second_output, output=second_envelope),
                         (second_envelope, 0))
        m.clear_events()
        self.assertEqual(m.enqueue(second_envelope), (0, 0))
        self.assertEqual(m.ledger_header()[2], 0)
        self.assertNotIn(APPEND, m.trace)
        self.assertEqual(m.retained_count(), 0)

    def test_corrupt_native72_header_faults_before_list_methods(self):
        for offset, value in ((16, 68), (20, 9), (8, 0), (8, 20),
                              (12, 41), (0, 0), (0, 1)):
            with self.subTest(offset=offset, value=value):
                m = self.machine()
                self.prepared(m)
                m.put(m.retained_list + offset, value, 4)
                m.clear_events()
                self.assertEqual(m.enqueue(), (0, 0))
                self.assertEqual(m.ledger_header()[1], 1)
                self.assertNotIn(APPEND, m.trace)
                self.assertNotIn(GET, m.trace)
                self.assert_guarded(m)

    def test_corrupt_ledger_schema_never_reports_quiescence(self):
        for offset, value in ((0, 3), (8, 17), (12, 1), (60, 1),
                              (HEADER_BYTES, 9), (HEADER_BYTES + 4, 7),
                              (HEADER_BYTES + 8, 1), (HEADER_BYTES + 12, 1)):
            with self.subTest(offset=offset, value=value):
                m = self.machine()
                self.prepared(m)
                self.assertEqual(m.enqueue(), (1, 0))
                self.assertEqual(m.close(), (1, 0))
                m.put(LEDGER + offset, value, 4)
                m.clear_events()
                self.assertEqual(m.quiescent(), (0, 0))
                self.assertNotEqual(m.ledger_header()[1], 0)
                self.assertNotIn(m.owner_labels['retire'], m.trace)
                self.assert_guarded(m)

    def test_dirty_unused_last_row_denies_bind_or_enqueue_before_overwrite(self):
        for operation in ('bind', 'enqueue'):
            with self.subTest(operation=operation):
                m = self.machine()
                self.prepared(m, bind=operation != 'bind')
                dirty_tail = m.operation_address(m.operation_capacity - 1) + 12
                m.put(dirty_tail, 0xA55A, 4)
                expected = m.operation(m.operation_capacity - 1)
                before = m.ledger_header()
                m.clear_events()
                self.assertEqual(self.invoke_operation(m, operation), (0, 0))
                self.assertEqual(m.ledger_header()[1], 2)
                self.assertEqual(m.ledger_header()[0], before[0])
                self.assertEqual(m.ledger_header()[2:], before[2:])
                self.assertEqual(m.operation(m.operation_capacity - 1), expected)
                self.assertNotIn(APPEND, m.trace)
                self.assertEqual(m.retained_count(), 0)
                self.assert_guarded(m)

    def test_duplicate_historical_done_and_published_nonce_faults_before_drain(self):
        m = self.machine()
        self.prepared(m)
        self.assertEqual(m.enqueue(), (1, 0))
        self.assertEqual(m.enqueue(), (2, 0))
        self.assertEqual(m.pop_dispatch(), (2, 0))
        self.assertEqual(m.pop_dispatch(), (3, 1))
        m.claim()
        self.assertEqual(m.complete(2), (1, 0))
        self.assertEqual(m.close(), (1, 0))
        m.put(m.operation_address(1) + 8, 2, 4)
        m.clear_events()
        self.assertEqual(m.quiescent(), (0, 0))
        self.assertEqual(m.ledger_header()[1], 2)
        self.assertEqual(m.operation(0), (1, DONE, 2, 0))
        self.assertEqual(m.operation(1), (2, PUBLISHED, 2, 0))
        self.assertNotIn(m.owner_labels['retire'], m.trace)
        self.assertNotIn(m.owner_labels['drained'], m.trace)
        self.assert_guarded(m)

    def test_full_owned_source_unsigned_endpoints_fixed_crossings_and_frame_adjacency(self):
        # Inclusive last-byte arithmetic accepts end==2**32, but rejects a
        # four-byte overflow before even reading an unmapped source.
        for operation, size in (('bind', 44), ('enqueue', 68)):
            for pointer in (0x100000000 - size, 0x7FFFFFF0):
                with self.subTest(operation=operation, accepted_source=hex(pointer)):
                    m = self.machine()
                    self.prepared(m, bind=operation != 'bind')
                    m.map(pointer, size)
                    if operation == 'bind':
                        m.copy_bundle(pointer=pointer)
                    else:
                        data, offset = m.region(ENVELOPE, size)
                        m.bytes(pointer, bytes(data[offset:offset + size]))
                    invoke = m.bind if operation == 'bind' else m.enqueue
                    self.assertEqual(invoke(pointer), (1, 0))

            m = self.machine()
            invoke = m.bind if operation == 'bind' else m.enqueue
            spans = ((LEDGER, HEADER_BYTES + OP_BYTES * m.operation_capacity),
                     (m.retained_list, 56), (RETAINED_MUTEX, 24),
                     (CODE, len(m.code)))
            bad_sources = [0x100000004 - size]
            for start, length in spans:
                bad_sources.extend((start - size + 4, start + length - 4))
            for pointer in bad_sources:
                with self.subTest(operation=operation, source=hex(pointer)):
                    m.clear_events()
                    self.assertEqual(invoke(pointer), (0, 0))
                    self.assertEqual(m.raw_events, [])
                    self.assertEqual(m.reads, [])
                    self.assertEqual(m.writes, [])

            # Misplaced frames overlap the beginning or final word of each
            # new fixed extent, including the full generated RX tail.
            for start, length in spans:
                for stack in (((start + 15) & -8),
                              (((start + length - 4) & -8) + core.FRAME)):
                    with self.subTest(operation=operation, stack=hex(stack)):
                        m.clear_events()
                        self.assertEqual(invoke(stack=stack), (0, 0))
                        self.assertEqual(m.raw_events, [])
                        self.assertEqual(m.reads, [])
                        self.assertEqual(m.writes, [])

        # Exact disjoint adjacency is allowed, not broadened to an arbitrary
        # no-neighbour rule. Only the needed outer bind frame is mapped here.
        for side in ('before', 'after'):
            with self.subTest(frame_adjacent_to_ledger=side):
                m = self.machine()
                self.prepared(m, bind=False)
                frame = (LEDGER - core.FRAME if side == 'before'
                         else LEDGER + HEADER_BYTES + OP_BYTES * m.operation_capacity)
                m.map(frame, core.FRAME)
                self.assertEqual(m.bind(stack=frame + core.FRAME), (1, 0))
                self.assertEqual(m.ledger_header()[0], OPEN)

    def test_invalid_head_token_capture_or_payload_faults_without_remove_or_publish(self):
        for offset, value in ((0, 0), (0, 17), (4, 0),
                              (4 + capture.FLAGS, 1),
                              (4 + capture.CONTROLLER, 0),
                              (4 + capture.BINDING_SEQUENCE, 2),
                              (4 + capture.OWNER, 2),
                              (4 + capture.RECEIPT_SEQUENCE, 2),
                              (4 + capture.OUTPUT_BYTES + 8, 0)):
            with self.subTest(offset=offset, value=value):
                m = self.machine()
                self.prepared(m)
                self.assertEqual(m.enqueue(), (1, 0))
                m.put(m.retained_element() + offset, value, 4)
                m.clear_events()
                self.assertEqual(m.pop_dispatch(), (0, 0))
                self.assertEqual(m.ledger_header()[1], 3)
                self.assertEqual(m.retained_count(), 1)
                self.assertEqual(m.operation(), (1, QUEUED, 0, 0))
                self.assertNotIn(REMOVE, m.trace)
                self.assertNotIn(m.envelope_labels['dispatch'], m.trace)

    def test_controlled_get_null_fixed_alias_or_frame_result_is_denied_before_read(self):
        for pointer in (0, 1, LEDGER, RETAINED_MUTEX, CONTROLLER, STATE,
                        BIND_STATE, OWNER_STATE, TRANSPORT_MUTEX, FAULT, CODE,
                        STACK - core.FRAME, 0xFFFFFFFC):
            with self.subTest(pointer=pointer):
                m = self.machine()
                self.prepared(m)
                self.assertEqual(m.enqueue(), (1, 0))
                m.patches[GET] = b.r_type(31, 0, 0, 8)
                m.patches[GET + 4] = 0

                def replace(machine, pc):
                    if pc == machine.retained_labels['after_get']:
                        machine.r[2] = pointer

                m.on_instruction = replace
                m.clear_events()
                self.assertEqual(m.pop_dispatch(), (0, 0))
                self.assertEqual(m.ledger_header()[1], 3)
                self.assertNotIn(m.envelope_labels['pack'], m.trace)
                self.assertNotIn(REMOVE, m.trace)

    def test_controlled_append_failure_retains_nonterminal_reservation_and_latches_fault(self):
        for result in (0, 1, 22, MASK):
            with self.subTest(result=result):
                m = self.machine()
                self.prepared(m)
                m.patches[APPEND] = b.r_type(31, 0, 0, 8)
                m.patches[APPEND + 4] = b.addiu(2, 0, result & 0xFFFF)
                m.clear_events()
                self.assertEqual(m.enqueue(), (0, 0))
                self.assertEqual(m.ledger_header()[1:3], (4, 1))
                self.assertEqual(m.operation(), (1, RESERVED, 0, 0))
                self.assertEqual(m.retained_count(), 0)
                self.assertEqual(m.trace.count(APPEND), 1)

    def test_actual_append_sees_a_reserved_nonreused_token_before_native_copy(self):
        m = self.machine()
        self.prepared(m)
        observed = []

        def at_append(machine, pc):
            if pc == machine.retained_labels['before_append']:
                observed.append((machine.operation(), machine.ledger_header()[2],
                                 machine.retained_held))

        m.on_instruction = at_append
        self.assertEqual(m.enqueue(), (1, 0))
        self.assertEqual(observed, [((1, RESERVED, 0, 0), 1, True)])
        self.assertEqual(m.operation(), (1, QUEUED, 0, 0))

    def test_actual_append_then_wrong_count_is_fault_not_rollback_or_token_reuse(self):
        m = self.machine()
        self.prepared(m)

        def corrupt_count(machine, pc):
            if pc == machine.retained_labels['after_append']:
                machine.put(machine.retained_list + 12, 2, 4)

        m.on_instruction = corrupt_count
        self.assertEqual(m.enqueue(), (0, 0))
        self.assertEqual(m.ledger_header()[1:3], (4, 1))
        self.assertEqual(m.operation(), (1, RESERVED, 0, 0))
        self.assertEqual(m.retained_count(), 2)

    def test_controlled_remove_failure_keeps_token_outstanding_and_never_publishes(self):
        for result in (0, 22, MASK):
            with self.subTest(result=result):
                m = self.machine()
                self.prepared(m)
                self.assertEqual(m.enqueue(), (1, 0))
                m.patches[REMOVE] = b.r_type(31, 0, 0, 8)
                m.patches[REMOVE + 4] = b.addiu(2, 0, result & 0xFFFF)
                m.clear_events()
                self.assertEqual(m.pop_dispatch(), (0, 0))
                self.assertEqual(m.ledger_header()[1], 5)
                self.assertEqual(m.operation(), (1, QUEUED, 0, 0))
                self.assertEqual(m.retained_count(), 1)
                self.assertNotIn(m.envelope_labels['dispatch'], m.trace)

    def test_actual_remove_then_wrong_count_keeps_operation_nonterminal(self):
        m = self.machine()
        self.prepared(m)
        self.assertEqual(m.enqueue(), (1, 0))

        def corrupt_count(machine, pc):
            if pc == machine.retained_labels['after_remove']:
                machine.put(machine.retained_list + 12, 1, 4)

        m.on_instruction = corrupt_count
        m.clear_events()
        self.assertEqual(m.pop_dispatch(), (0, 0))
        self.assertEqual(m.ledger_header()[1], 5)
        self.assertEqual(m.operation(), (1, QUEUED, 0, 0))
        self.assertNotIn(m.envelope_labels['dispatch'], m.trace)

    def test_bind_and_enqueue_snapshots_precede_source_mutation_at_raw_mutex(self):
        for operation, pointer, size in (('bind', BUNDLE, 44),
                                         ('enqueue', ENVELOPE, 68)):
            with self.subTest(operation=operation):
                m = self.machine()
                self.prepared(m, bind=operation != 'bind')
                expected = m.words_at(pointer, size // 4)

                def mutate(machine, target):
                    if target == RAW_LOCK and machine.r[4] == RETAINED_MUTEX:
                        for offset in range(0, size, 4):
                            machine.put(pointer + offset, MASK, 4)

                m.on_service = mutate
                self.assertEqual(self.invoke_operation(m, operation), (1, 0))
                actual = (m.ledger_header()[4:15] if operation == 'bind'
                          else m.words_at(m.retained_element() + 4, 17))
                self.assertEqual(actual, expected)

    def test_preexisting_fault_prevents_queue_methods_and_retire_barrier(self):
        m = self.machine()
        self.prepared(m)
        m.put(LEDGER + 4, 0xDEAD, 4)
        for operation in ('enqueue', 'pop_dispatch', 'close', 'quiescent'):
            m.clear_events()
            self.assertEqual(self.invoke_operation(m, operation), (0, 0))
            self.assertEqual(m.ledger_header()[1], 0xDEAD)
            self.assertNotIn(APPEND, m.trace)
            self.assertNotIn(GET, m.trace)
            self.assertNotIn(m.owner_labels['retire'], m.trace)

    def test_owned_bind_and_enqueue_alias_guards_precede_all_reads_and_stores(self):
        for operation in ('bind', 'enqueue'):
            for pointer in (0, 1, 0xFFFFFFFC, LEDGER, RETAINED_MUTEX,
                            CONTROLLER, REGISTRY_MUTEX, PAINT_MUTEX, STATE,
                            BIND_STATE, OWNER_STATE, TRANSPORT_MUTEX, FAULT,
                            CODE, STACK - core.FRAME, STACK - 4):
                with self.subTest(operation=operation, pointer=pointer):
                    m = self.machine()
                    m.clear_events()
                    result = (m.bind(pointer) if operation == 'bind'
                              else m.enqueue(pointer))
                    self.assertEqual(result, (0, 0))
                    self.assertEqual(m.raw_events, [])
                    self.assertEqual(m.reads, [])
                    self.assertEqual(m.writes, [])

    def test_foreign_controller_or_invalid_stack_is_rejected_by_every_entry(self):
        for operation in ('bind', 'enqueue', 'pop_dispatch', 'complete',
                          'close', 'quiescent'):
            m = self.machine()
            for options in ({'controller': 0}, {'controller': CONTROLLER + 4},
                            {'stack': 0}, {'stack': STACK + 4},
                            {'stack': core.FRAME - 8},
                            {'stack': LEDGER + core.FRAME},
                            {'stack': RETAINED_MUTEX + core.FRAME},
                            {'stack': CODE + core.FRAME}):
                with self.subTest(operation=operation, options=options):
                    m.clear_events()
                    self.assertEqual(self.invoke_operation(m, operation, **options), (0, 0))
                    self.assertEqual(m.raw_events, [])
                    self.assertEqual(m.reads, [])
                    self.assertEqual(m.writes, [])

    def test_preserves_saved_registers_stack_return_and_hilo_under_hostile_raw_services(self):
        for operation in ('bind', 'enqueue', 'pop_dispatch', 'complete',
                          'close', 'quiescent'):
            with self.subTest(operation=operation):
                m = self.setup_operation(operation)
                saved = {reg: 0x77200000 + reg for reg in (*range(16, 24), 28, 30)}
                for reg, value in saved.items():
                    m.r[reg] = value
                m.hi, m.lo = 0x12345678, 0xABCDEF01
                result = self.invoke_operation(m, operation)
                self.assertGreater(result[0], 0)
                self.assertEqual({reg: m.r[reg] for reg in saved}, saved)
                self.assertEqual((m.r[29], m.r[31]), (STACK, RETURN))
                self.assertEqual((m.hi, m.lo), (0x12345678, 0xABCDEF01))


if __name__ == '__main__':
    unittest.main()
