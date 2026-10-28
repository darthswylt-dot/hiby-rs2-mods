#!/usr/bin/env python3
"""Fail-closed limits of a diagnostic, not a native incarnation/free oracle."""

import unittest

import reveal_registry_identity_mips as core
import reveal_registry_owner_mips as binding
import reveal_registry_receipt_mips as receipt
import test_reveal_registry_identity_mips as fixture
from test_reveal_cleanup_intent_mips import (
    INTENT, CLEANUP_OUTPUT, SECOND_OUTPUT, LEDGER, RETAINED_MUTEX)
from test_reveal_constructor_capture_mips import OUTPUT
from test_reveal_deferred_queue_mips import TRANSPORT_MUTEX, FAULT
from test_reveal_registry_identity_mips import AUDIT_OUTPUT, SECOND_AUDIT_OUTPUT
from test_reveal_registry_owner_mips import (
    STATE, BIND_STATE, OWNER_STATE, CODE, CONTROLLER, REGISTRY_MUTEX,
    PAINT_MUTEX, RAW_LOCK, RAW_UNLOCK, STACK, MASK)


class RegistryIdentityAdversarialTests(unittest.TestCase):
    setUpClass = classmethod(fixture.RegistryIdentityTests.setUpClass.__func__)
    machine = fixture.RegistryIdentityTests.machine
    prepared = fixture.RegistryIdentityTests.prepared
    ready = fixture.RegistryIdentityTests.ready
    assert_result = fixture.RegistryIdentityTests.assert_result

    def assert_denied_after_consume(self, machine):
        self.assertEqual(machine.audit(), (0, 0))
        self.assertEqual(machine.peek(CLEANUP_OUTPUT), core.CONSUMED_MAGIC)
        self.assertEqual(machine.audit_output(), (0,) * 16)
        self.assertEqual([(e[0], e[1]) for e in machine.raw_events],
                         [(RAW_LOCK, REGISTRY_MUTEX), (RAW_UNLOCK, REGISTRY_MUTEX)])

    def test_each_initial_dirty_output_word_refuses_before_saves_consumption_or_r(self):
        for offset in range(0, 64, 4):
            with self.subTest(offset=offset):
                m = self.machine()
                self.ready(m)
                m.put(AUDIT_OUTPUT + offset, 0xA55A0000 + offset, 4)
                expected = m.audit_output()
                original = m.cleanup_output()
                m.clear_events()
                self.assertEqual(m.audit(), (0, 0))
                self.assertEqual(m.audit_output(), expected)
                self.assertEqual(m.cleanup_output(), original)
                self.assertEqual(m.writes, [])
                self.assertEqual(m.raw_events, [])
                self.assertFalse(any(CLEANUP_OUTPUT <= address < CLEANUP_OUTPUT + 48
                                     for address, _ in m.reads))

    def test_each_late_dirty_output_word_prevents_all_emitted_output_stores(self):
        for offset in range(0, 64, 4):
            with self.subTest(offset=offset):
                m = self.machine()
                self.ready(m)

                def dirty(machine, pc):
                    if pc == machine.identity_labels['output_recheck']:
                        machine.put(AUDIT_OUTPUT + offset, 0xA55A0000 + offset, 4)

                m.on_instruction = dirty
                self.assertEqual(m.audit(), (0, 0))
                self.assertEqual(m.peek(CLEANUP_OUTPUT), core.CONSUMED_MAGIC)
                self.assertEqual(m.audit_output(), tuple(
                    0xA55A0000 + offset if i == offset else 0
                    for i in range(0, 64, 4)))
                self.assertEqual([e for e in m.writes
                                  if AUDIT_OUTPUT <= e[0] < AUDIT_OUTPUT + 64],
                                 [(AUDIT_OUTPUT + offset, 0xA55A0000 + offset, 4)])

    def test_malformed_intent_schema_refuses_without_consumption_or_raw_services(self):
        corruptions = ((0, 0), (4, 0), (8, 1), (8, 3), (12, CONTROLLER + 4),
                       (16, 0), (20, 0), (20, 17), (24, 0),
                       (24, 0x80000000), (28, 0), (28, 17), (32, 1))
        for offset, value in corruptions:
            with self.subTest(offset=offset, value=value):
                m = self.machine()
                self.ready(m)
                m.put(CLEANUP_OUTPUT + offset, value, 4)
                expected = m.cleanup_output()
                m.clear_events()
                self.assertEqual(m.audit(), (0, 0))
                self.assertEqual(m.cleanup_output(), expected)
                self.assertEqual(m.raw_events, [])
                self.assertEqual(m.ring_accesses, [])
                self.assertEqual(m.audit_output(), (0,) * 16)

    def test_wrong_bounded_capture_pair_or_receipt_is_denied_before_live_ring_reads(self):
        for offset, value in ((16, 0x87654321), (20, 2), (24, 2), (28, 2)):
            with self.subTest(offset=offset):
                m = self.machine()
                self.ready(m)
                m.put(CLEANUP_OUTPUT + offset, value, 4)
                m.clear_events()
                self.assert_denied_after_consume(m)
                self.assertEqual(m.ring_accesses, [])

    def test_corrupt_binding_header_or_selected_row_denies_before_live_ring_reads(self):
        corruptions = ((0, 17), (4, 1), (8, 22), (12, 1),
                       (16, 0), (20, 2), (24, 0), (28, CONTROLLER + 4),
                       (32, REGISTRY_MUTEX + 4), (52, 0x438A60), (56, 1),
                       (60, 0))
        for offset, value in corruptions:
            with self.subTest(offset=offset, value=value):
                m = self.machine()
                self.ready(m)
                m.put(BIND_STATE + offset, value, 4)
                m.clear_events()
                self.assert_denied_after_consume(m)
                self.assertEqual(m.ring_accesses, [])

    def test_next_unused_binding_row_cannot_contain_uncommitted_fields(self):
        for offset in (0, 20, 44):
            with self.subTest(offset=offset):
                m = self.machine()
                self.ready(m)
                m.put(BIND_STATE + 16 + 48 + offset, 1, 4)
                m.clear_events()
                self.assert_denied_after_consume(m)
                self.assertEqual(m.ring_accesses, [])

    def test_corrupt_later_committed_binding_is_not_hidden_by_early_selected_row(self):
        for offset, value in ((4, 1), (8, 1), (44, 1)):
            with self.subTest(offset=offset):
                m = self.machine()
                self.ready(m)
                m.construct(output=OUTPUT + 48)
                m.put(BIND_STATE + 16 + 48 + offset, value, 4)
                m.clear_events()
                self.assert_denied_after_consume(m)
                self.assertEqual(m.ring_accesses, [])

    def test_pinned_registry_route_fields_are_checked_under_r_before_ring_access(self):
        for offset, value in ((0x13C, REGISTRY_MUTEX + 4),
                              (0x274, 0x437CE0), (0x278, 0x437D60)):
            with self.subTest(offset=offset):
                m = self.machine()
                self.ready(m)
                m.put(CONTROLLER + offset, value, 4)
                m.clear_events()
                self.assert_denied_after_consume(m)
                self.assertEqual(m.ring_accesses, [])
                self.assertEqual(m.binding_accesses, [])

    def test_raw_r_acquire_error_consumes_owned_intent_but_has_no_native_or_output_access_afterward(self):
        for status in (1, 22, 0x82, MASK):
            with self.subTest(status=status):
                m = self.machine()
                self.ready(m)
                m.acquire = status
                boundaries = []

                def observe(machine, target):
                    if target == RAW_LOCK:
                        boundaries.append(len(machine.identity_accesses))

                m.on_service = observe
                self.assertEqual(m.audit(), (0, status))
                self.assertEqual(m.peek(CLEANUP_OUTPUT), core.CONSUMED_MAGIC)
                self.assertEqual(m.audit_output(), (0,) * 16)
                self.assertEqual([(e[0], e[1]) for e in m.raw_events],
                                 [(RAW_LOCK, REGISTRY_MUTEX)])
                self.assertEqual(m.binding_accesses, [])
                self.assertEqual(m.ring_accesses, [])
                self.assertTrue(all(STACK - core.FRAME <= e[2]
                                    and e[2] + e[3] <= STACK
                                    for e in m.identity_accesses[boundaries[0]:]))

    def test_raw_r_release_error_never_exports_or_touches_shared_storage_again(self):
        for released in (False, True):
            with self.subTest(released=released):
                m = self.machine()
                self.ready(m)
                m.release = 0x82
                m.registry_release_failure_releases = released
                boundaries = []

                def observe(machine, target):
                    if target == RAW_UNLOCK:
                        boundaries.append(len(machine.identity_accesses))

                m.on_service = observe
                self.assertEqual(m.audit(), (0, 0x82))
                self.assertEqual(m.peek(CLEANUP_OUTPUT), core.CONSUMED_MAGIC)
                self.assertEqual(m.audit_output(), (0,) * 16)
                self.assertTrue(all(STACK - core.FRAME <= e[2]
                                    and e[2] + e[3] <= STACK
                                    for e in m.identity_accesses[boundaries[0]:]))
                self.assertEqual(m.registry_held, not released)
                self.assertEqual(len(m.raw_events), 2)

    def test_broken_previous_link_or_tail_refuses_even_after_engine_match(self):
        for at_tail in (False, True):
            with self.subTest(at_tail=at_tail):
                m = self.machine()
                _, node, _ = self.ready(m)
                m.put(CONTROLLER + 0x38 if at_tail else node + 4,
                      CONTROLLER + 0x34 if at_tail else node, 4)
                m.clear_events()
                self.assert_denied_after_consume(m)

    def test_empty_head_with_nonempty_tail_is_malformed_not_absent(self):
        m = self.machine()
        _, node, _ = self.ready(m)
        m.put(CONTROLLER + 0x34, CONTROLLER + 0x34, 4)
        self.assertEqual(m.peek(CONTROLLER + 0x38), node)
        m.clear_events()
        self.assert_denied_after_consume(m)

    def test_self_cycle_and_non_sentinel_cycle_cannot_export_partial_match(self):
        for two_nodes in (False, True):
            with self.subTest(two_nodes=two_nodes):
                m = self.machine(max_nodes=3)
                _, node, _ = self.ready(m)
                if two_nodes:
                    m.construct(output=OUTPUT + 48)
                    last = m.binding_record(1)[5]
                    m.put(last, node, 4)
                else:
                    m.put(node, node, 4)
                m.clear_events()
                self.assert_denied_after_consume(m)

    def test_walk_budget_is_a_full_walk_limit_not_permission_on_first_match(self):
        m = self.machine(max_nodes=1)
        self.ready(m)
        m.construct(output=OUTPUT + 48)
        second_node = m.binding_record(1)[5]
        m.clear_events()
        self.assert_denied_after_consume(m)
        self.assertFalse(any(second_node <= address < second_node + 28
                             for address, _ in m.reads))

    def test_exact_node_budget_allows_a_complete_well_formed_ring(self):
        m = self.machine(max_nodes=2)
        engine, node, expected = self.ready(m)
        m.construct(output=OUTPUT + 48)
        m.clear_events()
        self.assertEqual(m.audit(), (AUDIT_OUTPUT, 0))
        self.assert_result(m, expected, node, engine, 2)

    def test_invalid_live_node_full_extent_is_rejected_before_any_node_read(self):
        m = self.machine()
        _, node, _ = self.ready(m)
        # The first eight bytes could be safely before the fixed extent;
        # guarding all 28 bytes must still reject before reading either link.
        invalid = [0, 1, MASK - 23, 0xFFFFFFEC,
                   STATE - 24, BIND_STATE - 24, OWNER_STATE - 24,
                   CONTROLLER - 24, REGISTRY_MUTEX - 24, PAINT_MUTEX - 24,
                   LEDGER - 24, RETAINED_MUTEX - 24, INTENT - 24,
                   SECOND_OUTPUT - 24, AUDIT_OUTPUT - 24,
                   STACK - core.FRAME - 24,
                   receipt.NATIVE_RX[0] - 24, CODE - 24]
        for pointer in invalid:
            with self.subTest(pointer=hex(pointer)):
                # Fresh exclusively owned intent per independent attempt.
                m.copy_intent(SECOND_OUTPUT)
                # CLEANUP_OUTPUT remains the untouched CINT source; the audit
                # consumes only this separate, freshly copied owned record.
                m.put(CONTROLLER + 0x34, pointer, 4)
                m.put(CONTROLLER + 0x38, pointer, 4)
                m.clear_events()
                self.assertEqual(m.audit(SECOND_OUTPUT), (0, 0))
                self.assertEqual(m.peek(SECOND_OUTPUT), core.CONSUMED_MAGIC)
                self.assertNotIn(m.identity_labels['node_read'], m.trace)
                self.assertEqual(m.audit_output(), (0,) * 16)

    def test_invalid_later_live_node_after_matching_head_is_still_denied(self):
        for pointer in (0, 1, CODE, LEDGER, CLEANUP_OUTPUT, AUDIT_OUTPUT):
            with self.subTest(pointer=hex(pointer)):
                m = self.machine()
                _, node, _ = self.ready(m)
                m.put(node, pointer, 4)
                m.clear_events()
                self.assert_denied_after_consume(m)

    def test_historical_node_is_guarded_but_never_read_unless_reached_from_live_ring(self):
        m = self.machine()
        _, node, _ = self.ready(m)
        unknown = 0x1D00000  # unmapped but arithmetically valid scalar address
        m.put(BIND_STATE + 16 + binding.NODE, unknown, 4)
        m.clear_events()
        self.assertEqual(m.audit(), (AUDIT_OUTPUT, 0))
        self.assertEqual(m.audit_output()[1], core.NODE_ABSENT)
        self.assertEqual(m.audit_output()[13:], (unknown, 0, 1))
        self.assertFalse(any(unknown <= address < unknown + 28 for address, _ in m.reads))

    def test_invalid_historical_node_alias_cannot_be_turned_into_absent_evidence(self):
        for pointer in (0, 1, CODE - 24, LEDGER - 24,
                        CLEANUP_OUTPUT - 24, AUDIT_OUTPUT - 24):
            with self.subTest(pointer=hex(pointer)):
                m = self.machine()
                self.ready(m)
                m.put(BIND_STATE + 16 + binding.NODE, pointer, 4)
                m.clear_events()
                self.assert_denied_after_consume(m)
                self.assertEqual(m.ring_accesses, [])

    def test_owned_source_snapshot_survives_external_mutation_before_r(self):
        m = self.machine()
        engine, node, expected = self.ready(m)

        def mutate(machine, target):
            if target == RAW_LOCK:
                for offset in range(4, 48, 4):
                    machine.put(CLEANUP_OUTPUT + offset, MASK, 4)

        m.on_service = mutate
        self.assertEqual(m.audit(), (AUDIT_OUTPUT, 0))
        self.assert_result(m, expected, node, engine, 1)

    def test_confirmed_release_exports_private_observation_not_new_live_node_fields(self):
        m = self.machine()
        engine, node, expected = self.ready(m)

        def mutate(machine, target):
            if target == RAW_UNLOCK:
                machine.put(node + 8, MASK, 4)

        m.on_service = mutate
        self.assertEqual(m.audit(), (AUDIT_OUTPUT, 0))
        self.assert_result(m, expected, node, engine, 1)

    def test_source_and_output_full_guards_exclude_every_fixed_extent_and_full_rx(self):
        m = self.machine()
        spans = ((STATE, m.composition['receipt_memory_bytes']),
                 (BIND_STATE, m.composition['binding_memory_bytes']),
                 (OWNER_STATE, m.composition['owner_memory_bytes']),
                 (CONTROLLER, receipt.CONTROLLER_BYTES),
                 (REGISTRY_MUTEX, 24), (PAINT_MUTEX, 24),
                 (m.deferred_list, 56), (TRANSPORT_MUTEX, 24), (FAULT, 4),
                 (LEDGER, 64 + 16 * m.operation_capacity),
                 (m.retained_list, 56), (RETAINED_MUTEX, 24), (INTENT, 4),
                 (receipt.NATIVE_RX[0], receipt.NATIVE_RX[1] - receipt.NATIVE_RX[0]),
                 (CODE, len(m.code)))
        for source_pointer in (False, True):
            size = 48 if source_pointer else 64
            invalid = [0, 1, 0x100000000 - size + 4, MASK - 3,
                       STACK - core.FRAME, STACK - 4]
            for start, length in spans:
                invalid.extend((start, start - size + 4, start + length - 4))
            invalid.append(AUDIT_OUTPUT if source_pointer else CLEANUP_OUTPUT)
            for pointer in invalid:
                with self.subTest(source=source_pointer, pointer=hex(pointer)):
                    m.clear_events()
                    args = (pointer, AUDIT_OUTPUT) if source_pointer else (CLEANUP_OUTPUT, pointer)
                    self.assertEqual(m.audit(*args), (0, 0))
                    self.assertEqual(m.reads, [])
                    self.assertEqual(m.writes, [])
                    self.assertEqual(m.raw_events, [])

    def test_foreign_controller_and_invalid_frame_refuse_before_all_memory_access(self):
        m = self.machine()
        for options in ({'controller': 0}, {'controller': CONTROLLER + 4},
                        {'stack': 0}, {'stack': STACK + 4},
                        {'stack': core.FRAME - 8},
                        {'stack': LEDGER + core.FRAME},
                        {'stack': RETAINED_MUTEX + core.FRAME},
                        {'stack': INTENT + core.FRAME},
                        {'stack': CODE + core.FRAME},
                        {'stack': CLEANUP_OUTPUT + core.FRAME},
                        {'stack': AUDIT_OUTPUT + core.FRAME}):
            with self.subTest(options=options):
                m.clear_events()
                self.assertEqual(m.audit(**options), (0, 0))
                self.assertEqual(m.reads, [])
                self.assertEqual(m.writes, [])
                self.assertEqual(m.raw_events, [])

    def test_unsigned_last_byte_and_signed_boundary_outputs_are_supported(self):
        for pointer in (0x100000000 - 64, 0x7FFFFFF0):
            with self.subTest(pointer=hex(pointer)):
                m = self.machine()
                engine, node, expected = self.ready(m)
                m.map(pointer, 64)
                self.assertEqual(m.audit(output=pointer), (pointer, 0))
                self.assert_result(m, expected, node, engine, 1, output=pointer)

    def test_unsigned_last_byte_and_signed_boundary_intents_are_supported(self):
        for pointer in (0x100000000 - 48, 0x7FFFFFF0):
            with self.subTest(pointer=hex(pointer)):
                m = self.machine()
                engine, node, expected = self.ready(m)
                m.map(pointer, 48)
                m.copy_intent(pointer)
                self.assertEqual(m.audit(pointer), (AUDIT_OUTPUT, 0))
                self.assertEqual(m.peek(pointer), core.CONSUMED_MAGIC)
                self.assertEqual(m.audit_output(),
                                 (core.OUTPUT_MAGIC, 1, *expected, node, engine, 1))


if __name__ == '__main__':
    unittest.main()
