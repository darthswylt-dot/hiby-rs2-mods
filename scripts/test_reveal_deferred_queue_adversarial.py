#!/usr/bin/env python3
"""Adversarial checks for the bounded checked-T transport composition.

Controlled replacement return/count tests are wrapper branch coverage, not
proof of the native list's failure atomicity. Raw errors deliberately retire
the whole test instance; neither ambiguous ownership outcome licenses retry.
The list table/chunks and all cooperating users remain retained/trusted.
"""

import hashlib
import unittest

from build_reveal_bridge_diag import b
import reveal_creation_capture_mips as capture
import reveal_deferred_envelope_mips as envelopes
import reveal_deferred_envelope_stage as envelope_stage
import reveal_deferred_queue_mips as core
import reveal_deferred_queue_stage as stage
import reveal_paint_retirement_mips as owners
import reveal_registry_receipt_mips as receipts
import test_reveal_deferred_queue_mips as fixture
from test_reveal_deferred_queue_mips import TRANSPORT_MUTEX, FAULT
from test_reveal_deferred_envelope_mips import ENVELOPE, APPEND, GET, REMOVE
from test_reveal_owner_carrier_mips import OWNED_INPUT, PAYLOAD
from test_reveal_registry_release_mips import OUTPUT
from test_reveal_registry_owner_mips import (
    STATE, BIND_STATE, OWNER_STATE, CODE, CONTROLLER, REGISTRY_MUTEX,
    PAINT_MUTEX, RAW_LOCK, RAW_UNLOCK, STACK, RETURN, MASK)


class DeferredQueueAdversarialTests(unittest.TestCase):
    setUpClass = classmethod(fixture.DeferredQueueTests.setUpClass.__func__)
    machine = fixture.DeferredQueueTests.machine
    prepared = fixture.DeferredQueueTests.prepared

    def accesses(self, machine):
        return [event for event in machine.guard_events if event[0] == 'access']

    def test_raw_transport_acquire_errors_never_touch_queue_or_fault_or_guess_unlock(self):
        for operation in ('enqueue', 'pop'):
            for status in (1, 22, 0x82, MASK):
                for held in (False, True):
                    with self.subTest(operation=operation, status=status, held=held):
                        m = self.machine()
                        self.prepared(m)
                        if operation == 'pop':
                            self.assertEqual(m.enqueue(), (1, 0))
                        m.transport_acquire = status
                        m.transport_acquire_failure_holds = held
                        m.clear_events()
                        result = m.enqueue() if operation == 'enqueue' else m.pop_dispatch()
                        self.assertEqual(result, (0, status))
                        self.assertEqual(self.accesses(m), [])
                        self.assertEqual([event[0] for event in m.transport_events], [RAW_LOCK])
                        self.assertEqual(m.paint_events, [])
                        self.assertEqual(m.binding_accesses, [])
                        self.assertEqual(m.owner_accesses, [])
                        self.assertEqual(m.transport_held, held)
                        # No further call: the entire ambiguous instance is
                        # externally isolated, even when the fake lock held.

    def test_raw_transport_release_errors_preserve_status_and_stop_after_partial_effects(self):
        for operation in ('enqueue', 'pop'):
            for status in (1, 22, 0x82, MASK):
                for released in (False, True):
                    with self.subTest(operation=operation, status=status, released=released):
                        m = self.machine()
                        self.prepared(m)
                        if operation == 'pop':
                            self.assertEqual(m.enqueue(), (1, 0))
                        m.transport_release = status
                        m.transport_release_failure_releases = released
                        boundaries = []

                        def at_unlock(machine, target):
                            if target == RAW_UNLOCK and machine.r[4] == TRANSPORT_MUTEX:
                                boundaries.append((len(self.accesses(machine)),
                                                   len(machine.envelope_accesses)))

                        m.on_service = at_unlock
                        m.clear_events()
                        result = m.enqueue() if operation == 'enqueue' else m.pop_dispatch()
                        self.assertEqual(result, (0, status))
                        self.assertEqual(boundaries, [(len(self.accesses(m)),
                                                       len(m.envelope_accesses))])
                        self.assertEqual(m.transport_count(), 1 if operation == 'enqueue' else 0)
                        self.assertEqual(m.count(), 0)
                        self.assertEqual(m.peek(FAULT), 0)
                        self.assertEqual(m.binding_accesses, [])
                        self.assertEqual(m.owner_accesses, [])
                        self.assertEqual([event[0] for event in m.transport_events],
                                         [RAW_LOCK, RAW_UNLOCK])
                        self.assertEqual(m.transport_held, not released)
                        self.assertNotIn(m.envelope_labels['dispatch'], m.trace)
                        # Lost/uncertain append or removal is not retried.

    def test_existing_fault_denies_before_any_queue_header_or_source_head_read(self):
        for operation in ('enqueue', 'pop'):
            for fault in (1, 2, 3, 4, MASK):
                with self.subTest(operation=operation, fault=fault):
                    m = self.machine()
                    self.prepared(m)
                    m.put(FAULT, fault, 4)
                    m.clear_events()
                    self.assertEqual(m.enqueue() if operation == 'enqueue'
                                     else m.pop_dispatch(), (0, 0))
                    self.assertEqual([(event[1], event[3]) for event in self.accesses(m)],
                                     [('read', FAULT)])
                    self.assertEqual(m.peek(FAULT), fault)
                    self.assertNotIn(APPEND, m.trace)
                    self.assertNotIn(GET, m.trace)
                    self.assertEqual([event[0] for event in m.transport_events],
                                     [RAW_LOCK, RAW_UNLOCK])

    def test_corrupt_checked_header_fields_set_fault_one_under_transport_guard(self):
        corruptions = ((0x10, 44), (0x10, 0), (0x14, 0), (0x14, 9),
                       (8, 20), (8, 0), (0xC, 41), (0xC, MASK),
                       (0, 0), (0, 1))
        for operation in ('enqueue', 'pop'):
            for offset, value in corruptions:
                with self.subTest(operation=operation, offset=offset, value=value):
                    m = self.machine()
                    self.prepared(m)
                    m.put(m.deferred_list + offset, value, 4)
                    m.clear_events()
                    self.assertEqual(m.enqueue() if operation == 'enqueue'
                                     else m.pop_dispatch(), (0, 0))
                    self.assertEqual(m.peek(FAULT), 1)
                    writes = [event for event in self.accesses(m) if event[1] == 'write']
                    self.assertEqual([(event[3], event[5]) for event in writes], [(FAULT, True)])
                    self.assertNotIn(APPEND, m.trace)
                    self.assertNotIn(GET, m.trace)
                    self.assertEqual([event[0] for event in m.transport_events],
                                     [RAW_LOCK, RAW_UNLOCK])

    def test_invalid_head_schema_is_fault_two_without_remove_or_dispatch(self):
        for offset, value in ((0, 0), (capture.FLAGS, 1),
                              (capture.CONTROLLER, CONTROLLER + 4),
                              (capture.BINDING_SEQUENCE, 0),
                              (capture.OWNER, 0), (capture.RECEIPT_SEQUENCE, 17),
                              (capture.RESULT, 1), (capture.OUTPUT_BYTES + 8, 0)):
            with self.subTest(offset=offset, value=value):
                m = self.machine()
                self.prepared(m)
                self.assertEqual(m.enqueue(), (1, 0))
                m.put(m.transport_element() + offset, value, 4)
                m.clear_events()
                self.assertEqual(m.pop_dispatch(), (0, 0))
                self.assertEqual(m.peek(FAULT), 2)
                self.assertEqual(m.transport_count(), 1)
                self.assertIn(GET, m.trace)
                self.assertNotIn(REMOVE, m.trace)
                self.assertNotIn(m.envelope_labels['dispatch'], m.trace)

    def test_controlled_null_or_fixed_alias_get_return_faults_without_pack(self):
        # These intentionally substituted GET bodies cover the wrapper's
        # pointer gate; they do not describe native GET failure atomicity.
        for pointer in (0, 1, FAULT, TRANSPORT_MUTEX, CONTROLLER, STATE,
                        BIND_STATE, OWNER_STATE, CODE,
                        STACK - core.FRAME + core.PRIVATE, 0xFFFFFFFC):
            with self.subTest(pointer=pointer):
                m = self.machine()
                self.prepared(m)
                self.assertEqual(m.enqueue(), (1, 0))
                m.patches[GET] = b.r_type(31, 0, 0, 8)
                m.patches[GET + 4] = 0

                def replace_result(machine, pc):
                    if pc == machine.queue_labels['after_get']:
                        machine.r[2] = pointer

                m.on_instruction = replace_result
                m.clear_events()
                self.assertEqual(m.pop_dispatch(), (0, 0))
                self.assertEqual(m.peek(FAULT), 2)
                self.assertNotIn(m.envelope_labels['pack'], m.trace)
                self.assertNotIn(REMOVE, m.trace)

    def test_controlled_append_index_mismatch_sets_fault_three_without_retry(self):
        # Replacing the real method is explicit branch coverage only.
        for status in (1, 22, MASK):
            with self.subTest(status=status):
                m = self.machine()
                self.prepared(m)
                m.patches[APPEND] = b.r_type(31, 0, 0, 8)
                m.patches[APPEND + 4] = b.addiu(2, 0, status & 0xFFFF)
                m.clear_events()
                self.assertEqual(m.enqueue(), (0, 0))
                self.assertEqual(m.peek(FAULT), 3)
                self.assertEqual(m.transport_count(), 0)
                self.assertEqual(m.trace.count(APPEND), 1)
                self.assertEqual([event[0] for event in m.transport_events],
                                 [RAW_LOCK, RAW_UNLOCK])

    def test_controlled_append_expected_index_without_increment_is_fault_three(self):
        m = self.machine()
        self.prepared(m)
        m.patches[APPEND] = b.r_type(31, 0, 0, 8)
        m.patches[APPEND + 4] = b.addiu(2, 0, 0)
        self.assertEqual(m.enqueue(), (0, 0))
        self.assertEqual(m.peek(FAULT), 3)
        self.assertEqual(m.transport_count(), 0)

    def test_controlled_post_append_count_corruption_is_fault_three(self):
        m = self.machine()
        self.prepared(m)

        def corrupt(machine, pc):
            if pc == machine.queue_labels['after_append']:
                machine.put(machine.deferred_list + 0xC, 2, 4)

        m.on_instruction = corrupt
        self.assertEqual(m.enqueue(), (0, 0))
        self.assertEqual(m.peek(FAULT), 3)
        self.assertEqual(m.transport_count(), 2)  # no guessed rollback

    def test_controlled_remove_error_sets_fault_four_and_never_dispatches(self):
        for status in (1, 22, MASK):
            with self.subTest(status=status):
                m = self.machine()
                self.prepared(m)
                self.assertEqual(m.enqueue(), (1, 0))
                m.patches[REMOVE] = b.r_type(31, 0, 0, 8)
                m.patches[REMOVE + 4] = b.addiu(2, 0, status & 0xFFFF)
                m.clear_events()
                self.assertEqual(m.pop_dispatch(), (0, 0))
                self.assertEqual(m.peek(FAULT), 4)
                self.assertEqual(m.transport_count(), 1)
                self.assertNotIn(m.envelope_labels['dispatch'], m.trace)
                self.assertEqual(m.count(), 0)

    def test_controlled_remove_zero_without_decrement_is_fault_four(self):
        m = self.machine()
        self.prepared(m)
        self.assertEqual(m.enqueue(), (1, 0))
        m.patches[REMOVE] = b.r_type(31, 0, 0, 8)
        m.patches[REMOVE + 4] = b.addiu(2, 0, 0)
        m.clear_events()
        self.assertEqual(m.pop_dispatch(), (0, 0))
        self.assertEqual(m.peek(FAULT), 4)
        self.assertEqual(m.transport_count(), 1)
        self.assertNotIn(m.envelope_labels['dispatch'], m.trace)

    def test_controlled_post_remove_count_corruption_is_fault_four(self):
        m = self.machine()
        self.prepared(m)
        self.assertEqual(m.enqueue(), (1, 0))

        def corrupt(machine, pc):
            if pc == machine.queue_labels['after_remove']:
                machine.put(machine.deferred_list + 0xC, 1, 4)

        m.on_instruction = corrupt
        m.clear_events()
        self.assertEqual(m.pop_dispatch(), (0, 0))
        self.assertEqual(m.peek(FAULT), 4)
        self.assertNotIn(m.envelope_labels['dispatch'], m.trace)
        self.assertEqual(m.count(), 0)

    def test_schema_invalid_enqueue_never_enters_transport_mutex_or_queue(self):
        for offset, value in ((0, 0), (capture.FLAGS, 0),
                              (capture.CONTROLLER, 0),
                              (capture.BINDING_SEQUENCE, 0),
                              (capture.OWNER, 0), (capture.RECEIPT_SEQUENCE, 17),
                              (capture.RESULT, 1), (capture.OUTPUT_BYTES + 8, 0)):
            with self.subTest(offset=offset, value=value):
                m = self.machine()
                self.prepared(m)
                m.put(ENVELOPE + offset, value, 4)
                m.clear_events()
                self.assertEqual(m.enqueue(), (0, 0))
                self.assertEqual(m.transport_events, [])
                self.assertEqual(self.accesses(m), [])
                self.assertEqual(m.peek(FAULT), 0)

    def test_enqueue_rejects_fixed_extent_or_own_frame_input_alias_before_reads(self):
        for pointer in (0, 1, 0xFFFFFFFC, STATE, BIND_STATE, OWNER_STATE,
                        CONTROLLER, REGISTRY_MUTEX, PAINT_MUTEX,
                        TRANSPORT_MUTEX, FAULT, CODE,
                        STACK - core.FRAME, STACK - 4):
            with self.subTest(pointer=pointer):
                m = self.machine()
                m.clear_events()
                self.assertEqual(m.enqueue(pointer), (0, 0))
                self.assertEqual(m.raw_events, [])
                self.assertEqual(m.reads, [])
                self.assertEqual(m.writes, [])

    def test_foreign_controller_and_invalid_stack_deny_both_public_entries(self):
        m = self.machine()
        for operation in ('enqueue', 'pop'):
            for options in ({'controller': 0}, {'controller': CONTROLLER + 4},
                            {'stack': 1}, {'stack': 0},
                            {'stack': core.FRAME - 8},
                            {'stack': CODE + core.FRAME},
                            {'stack': FAULT + core.FRAME},
                            {'stack': TRANSPORT_MUTEX + core.FRAME},
                            {'stack': m.deferred_list + core.FRAME}):
                with self.subTest(operation=operation, options=options):
                    m.clear_events()
                    self.assertEqual(m.enqueue(**options) if operation == 'enqueue'
                                     else m.pop_dispatch(**options), (0, 0))
                    self.assertEqual(m.raw_events, [])
                    self.assertEqual(m.reads, [])
                    self.assertEqual(m.writes, [])

    def test_no_transport_or_envelope_access_after_successful_raw_release(self):
        for operation in ('enqueue', 'pop'):
            with self.subTest(operation=operation):
                m = self.machine()
                self.prepared(m)
                if operation == 'pop':
                    self.assertEqual(m.enqueue(), (1, 0))
                boundary = []

                def observe(machine, target):
                    if target == RAW_UNLOCK and machine.r[4] == TRANSPORT_MUTEX:
                        boundary.append((len(self.accesses(machine)),
                                         len(machine.envelope_accesses)))

                m.on_service = observe
                m.clear_events()
                self.assertEqual(m.enqueue() if operation == 'enqueue'
                                 else m.pop_dispatch(), (1, 0) if operation == 'enqueue'
                                 else (2, 0))
                self.assertEqual(boundary, [(len(self.accesses(m)),
                                             len(m.envelope_accesses))])

    def test_publisher_raw_errors_propagate_after_transport_unlock_without_transport_retry(self):
        for field in ('acquire', 'release', 'paint_acquire_result', 'paint_release_result'):
            with self.subTest(field=field):
                m = self.machine()
                self.prepared(m)
                self.assertEqual(m.enqueue(), (1, 0))
                setattr(m, field, 22)
                m.clear_events()
                self.assertEqual(m.pop_dispatch(), (0, 22))
                self.assertEqual(m.transport_count(), 0)
                self.assertFalse(m.transport_held)
                self.assertEqual([event[0] for event in m.transport_events],
                                 [RAW_LOCK, RAW_UNLOCK])
                self.assertEqual(m.peek(FAULT), 0)

    def test_copied_private_head_is_consumed_before_publisher_guard(self):
        m = self.machine()
        self.prepared(m)
        self.assertEqual(m.enqueue(), (1, 0))
        observations = []

        def before_registry(machine, target):
            if target == RAW_LOCK and machine.r[4] == REGISTRY_MUTEX:
                observations.append((machine.peek(machine.private()), machine.transport_held))

        m.on_service = before_registry
        self.assertEqual(m.pop_dispatch(), (2, 0))
        self.assertEqual(observations, [(envelopes.CONSUMED_MAGIC, False)])

    def test_all_earlier_outer_bulk_guards_cover_queue_code_tail(self):
        for operation in ('register_descriptor', 'register_output', 'publish',
                          'pack_input', 'pack_output', 'dispatch'):
            with self.subTest(operation=operation):
                m = self.machine()
                tail = CODE + m.composition['envelope_prefix_code_bytes']
                m.payload()
                m.clear_events()
                if operation == 'register_descriptor':
                    result = m.invoke_register(descriptor=tail)
                elif operation == 'register_output':
                    result = m.invoke_register(output=tail)
                elif operation == 'publish':
                    result = m.invoke_adapter(tail, 1, 1)
                elif operation == 'pack_input':
                    result = m.invoke_pack(captured=tail)
                elif operation == 'pack_output':
                    result = m.invoke_pack(output=tail)
                else:
                    result = m.invoke_dispatch(tail)
                self.assertEqual(result, (MASK, 0) if operation.startswith('register') else (0, 0))
                self.assertEqual(m.raw_events, [])
                self.assertEqual(m.reads, [])
                self.assertEqual(m.writes, [])

    def test_envelope_following_zero_preserves_old_golden_and_descriptor_validation(self):
        args = (STATE, BIND_STATE, OWNER_STATE, CONTROLLER,
                REGISTRY_MUTEX, PAINT_MUTEX, CODE)
        implicit = envelope_stage.assemble(*args)
        self.assertEqual(implicit, envelope_stage.assemble(*args, following_code_bytes=0))
        self.assertEqual(len(implicit['code']), 30224)
        self.assertEqual(hashlib.sha256(implicit['code']).hexdigest(),
                         '49687ac90583cc610cbca3bb1c12dc96c6bbed02fe4ba67ad64d2deaa8410df3')
        for length in (True, False, -4, 1, 2, 3, 1.0, '4', None,
                       0x10000000, 0x100000000):
            with self.subTest(length=length), self.assertRaises(ValueError):
                envelope_stage.assemble(*args, following_code_bytes=length)

    def test_composer_exact_extent_metadata_and_configuration_rejections(self):
        m = self.machine()
        meta = m.composition
        self.assertEqual(meta['queue_address'], m.deferred_list)
        self.assertEqual(meta['transport_mutex_address'], TRANSPORT_MUTEX)
        self.assertEqual(meta['fault_address'], FAULT)
        self.assertEqual(meta['transport_capacity'], 40)
        self.assertEqual(meta['envelope_prefix_code_bytes'], 30224)
        self.assertEqual(meta['protected_code_extent'], (CODE, len(m.code)))
        self.assertEqual(meta['queue_code_bytes'], len(m.code) - 30224)
        args = (STATE, BIND_STATE, OWNER_STATE, CONTROLLER,
                REGISTRY_MUTEX, PAINT_MUTEX, CODE,
                m.deferred_list, TRANSPORT_MUTEX, FAULT)
        for capacity in (False, True, 0, -10, 1, 9, 11, 1.0, '40', MASK):
            with self.subTest(capacity=capacity), self.assertRaises(ValueError):
                stage.assemble(*args, transport_capacity=capacity)
        for index, pointer in ((7, CODE), (7, TRANSPORT_MUTEX), (7, FAULT),
                               (8, REGISTRY_MUTEX), (8, PAINT_MUTEX),
                               (8, FAULT), (9, TRANSPORT_MUTEX),
                               (9, OWNER_STATE), (9, CODE)):
            varied = list(args)
            varied[index] = pointer
            with self.subTest(index=index, pointer=pointer), self.assertRaises(ValueError):
                stage.assemble(*varied)

    def test_all_fixed_extent_starts_and_tails_deny_source_and_frame_before_access(self):
        m = self.machine()
        extents = (
            ('receipt', STATE, m.composition['receipt_memory_bytes']),
            ('bindings', BIND_STATE, m.composition['binding_memory_bytes']),
            ('owners', OWNER_STATE, m.composition['owner_memory_bytes']),
            ('controller', CONTROLLER, receipts.CONTROLLER_BYTES),
            ('registry', REGISTRY_MUTEX, 24), ('paint', PAINT_MUTEX, 24),
            ('transport', m.deferred_list, core.QUEUE_BYTES),
            ('transport_mutex', TRANSPORT_MUTEX, core.MUTEX_BYTES),
            ('fault', FAULT, 4),
            ('native', receipts.NATIVE_RX[0],
             receipts.NATIVE_RX[1] - receipts.NATIVE_RX[0]),
            ('generated', CODE, len(m.code)),
        )
        for name, start, size in extents:
            for pointer in (start, start + size - 4):
                with self.subTest(extent=name, pointer=hex(pointer), operation='source'):
                    m.clear_events()
                    self.assertEqual(m.enqueue(pointer), (0, 0))
                    self.assertEqual(m.raw_events, [])
                    self.assertEqual(m.reads, [])
                    self.assertEqual(m.writes, [])
                # An aligned outer frame beginning at this first/last word
                # must be denied before any save or source dereference.
                stack = (pointer & ~7) + core.FRAME
                for operation in ('enqueue', 'pop'):
                    with self.subTest(extent=name, pointer=hex(pointer), operation=operation):
                        m.clear_events()
                        result = (m.enqueue(stack=stack) if operation == 'enqueue'
                                  else m.pop_dispatch(stack=stack))
                        self.assertEqual(result, (0, 0))
                        self.assertEqual(m.raw_events, [])
                        self.assertEqual(m.reads, [])
                        self.assertEqual(m.writes, [])

    def test_controlled_get_tail_aliases_fault_before_borrowed_head_pack(self):
        # Deliberate GET substitution covers the outer pointer gate, not the
        # native list's failure paths or an arbitrary dangling table pointer.
        m = self.machine()
        self.prepared(m)
        self.assertEqual(m.enqueue(), (1, 0))
        pointers = (m.deferred_list + core.QUEUE_BYTES - 4,
                    TRANSPORT_MUTEX + core.MUTEX_BYTES - 4, FAULT,
                    CODE + len(m.code) - 4, STACK - 4)
        for pointer in pointers:
            with self.subTest(pointer=hex(pointer)):
                # Each substituted case has a separate externally retained
                # healthy instance; faulted instances are never reset/reused.
                m = self.machine()
                self.prepared(m)
                self.assertEqual(m.enqueue(), (1, 0))
                m.patches[GET] = b.r_type(31, 0, 0, 8)
                m.patches[GET + 4] = 0

                def replace_result(machine, pc):
                    if pc == machine.queue_labels['after_get']:
                        machine.r[2] = pointer

                m.on_instruction = replace_result
                m.clear_events()
                self.assertEqual(m.pop_dispatch(), (0, 0))
                self.assertEqual(m.peek(FAULT), 2)
                self.assertNotIn(m.envelope_labels['pack'], m.trace)
                self.assertNotIn(REMOVE, m.trace)
                self.assertEqual(m.transport_count(), 1)
                self.assertEqual(m.count(), 0)

    def direct_arguments(self, machine):
        return (STATE, BIND_STATE, OWNER_STATE, CONTROLLER,
                REGISTRY_MUTEX, PAINT_MUTEX,
                CODE + machine.composition['envelope_prefix_code_bytes'],
                machine.deferred_list, TRANSPORT_MUTEX, FAULT,
                machine.envelope_labels['pack'], machine.envelope_labels['dispatch'])

    def test_core_protected_descriptor_rejects_malformed_and_incomplete_extents(self):
        m = self.machine()
        args = self.direct_arguments(m)
        valid = (CODE, len(m.code))
        self.assertEqual(core.assemble(*args, protected_code=valid)[0],
                         m.code[m.composition['envelope_prefix_code_bytes']:])
        invalid = (False, True, 1, 'RX', [], list(valid), (), (*valid, 0),
                   (True, valid[1]), (valid[0], True),
                   (CODE, 0), (CODE, -4), (CODE, 3),
                   (CODE + 2, valid[1]), (0, valid[1]), (-4, valid[1]),
                   (CODE, 0x10000000),
                   (args[6], m.composition['queue_code_bytes']),
                   (CODE, valid[1] - 4),
                   (CODE, args[6] - CODE),
                   (receipts.NATIVE_RX[0], valid[1]),
                   (CODE, FAULT + 4 - CODE))
        for descriptor in invalid:
            with self.subTest(descriptor=descriptor), self.assertRaises(ValueError):
                core.assemble(*args, protected_code=descriptor)
        # A supplied entry outside the declared RX cannot be blessed merely
        # because the queue fragment itself fits completely inside it.
        for index in (10, 11):
            varied = list(args)
            varied[index] = CODE - 4
            with self.subTest(entry=index), self.assertRaises(ValueError):
                core.assemble(*varied, protected_code=valid)

    def test_core_strict_address_domains_native_region_and_aliases(self):
        m = self.machine()
        args = self.direct_arguments(m)
        for index in range(len(args)):
            for pointer in (False, True, 0, -4, 'pointer', 1.0, 1, 0x100000000):
                varied = list(args)
                varied[index] = pointer
                with self.subTest(index=index, pointer=pointer), self.assertRaises(ValueError):
                    core.assemble(*varied)
            varied = list(args)
            varied[index] = receipts.NATIVE_RX[0]
            with self.subTest(index=index, pointer='native'), self.assertRaises(ValueError):
                core.assemble(*varied)
        fixed_indices = (*range(6), 7, 8, 9)
        for position, first in enumerate(fixed_indices):
            for second in fixed_indices[position + 1:]:
                varied = list(args)
                varied[second] = args[first]
                with self.subTest(first=first, second=second), self.assertRaises(ValueError):
                    core.assemble(*varied)
        for entry_index in (6, 10, 11):
            for pointer in (0x10000000, 0xFFFFFFFC):
                varied = list(args)
                varied[entry_index] = pointer
                with self.subTest(index=entry_index, pointer=pointer), self.assertRaises(ValueError):
                    core.assemble(*varied)
        for entry_index in (10, 11):
            for fixed_index in fixed_indices:
                varied = list(args)
                varied[entry_index] = args[fixed_index]
                with self.subTest(entry=entry_index, fixed=fixed_index), self.assertRaises(ValueError):
                    core.assemble(*varied)
        varied = list(args)
        varied[11] = varied[10]
        with self.assertRaises(ValueError):
            core.assemble(*varied)
        varied = list(args)
        varied[6] = 0x0FFFF800
        with self.assertRaises(ValueError):
            core.assemble(*varied)

    def test_core_capacity_and_ticket_domains_include_both_emission_boundaries(self):
        args = self.direct_arguments(self.machine())
        for capacity in (10, 10240):
            with self.subTest(capacity=capacity):
                emitted, labels = core.assemble(*args, transport_capacity=capacity)
                self.assertTrue(emitted)
                self.assertIn('enqueue', labels)
                self.assertIn('pop_dispatch', labels)
        for capacity in (False, True, None, '40', 40.0, -10, 0, 1, 9,
                         11, 10239, 10241, 10250, MASK):
            with self.subTest(capacity=capacity), self.assertRaises(ValueError):
                core.assemble(*args, transport_capacity=capacity)
        for option in ('capacity', 'owner_capacity'):
            for capacity in (False, True, None, '16', 16.0, -1, 0, 1025):
                with self.subTest(option=option, capacity=capacity), self.assertRaises(ValueError):
                    core.assemble(*args, **{option: capacity})
        for ticket in (False, True, None, '1', 1.0, -1, 0, owners.MAX_TICKET + 1):
            with self.subTest(ticket=ticket), self.assertRaises(ValueError):
                core.assemble(*args, ticket_limit=ticket)

    def test_exact_word_boundary_at_two_to_32_is_valid_owned_enqueue_input(self):
        m = self.machine()
        pointer = 0x100000000 - envelopes.ENVELOPE_BYTES
        m.map(pointer, envelopes.ENVELOPE_BYTES)
        self.assertEqual(m.invoke_register(), (0, OUTPUT))
        self.assertEqual(m.pack_payload(output=pointer), (pointer, 0))
        self.assertEqual(m.enqueue(pointer), (1, 0))
        self.assertEqual(m.pop_dispatch(), (2, 0))
        self.assertEqual(m.words_at(m.head(), 9), PAYLOAD)

    def test_owned_source_immediately_adjacent_to_generated_rx_is_not_overlap(self):
        for side in ('before', 'after'):
            with self.subTest(side=side):
                m = self.machine()
                pointer = (CODE - envelopes.ENVELOPE_BYTES if side == 'before'
                           else CODE + len(m.code))
                m.map(pointer, envelopes.ENVELOPE_BYTES)
                self.assertEqual(m.invoke_register(), (0, OUTPUT))
                self.assertEqual(m.pack_payload(output=pointer), (pointer, 0))
                self.assertEqual(m.enqueue(pointer), (1, 0))
                self.assertEqual(m.pop_dispatch(), (2, 0))
                self.assertEqual(m.words_at(m.head(), 9), PAYLOAD)


if __name__ == '__main__':
    unittest.main()
