#!/usr/bin/env python3
"""Adverse diagnostic constructor capture, not admission/error isolation.

Native constructor and registration execute. Damaged private tags and bounded
service/argument substitutions test scope/schema gates, not authentication or
arbitrary corruption recovery. Native UI continuation after raw error remains
explicitly visible; no later exact generation is reconstructed in Python.
"""

import hashlib
import unittest

import reveal_constructor_capture_mips as core
import reveal_creation_capture_mips as capture
import reveal_deferred_queue_stage as queues
import reveal_registry_receipt_mips as receipt
import test_folderfollow_reveal_static_contract as source
from test_reveal_constructor_capture_mips import (
    ConstructorCaptureMachine, REQUEST, DESCRIPTOR,
    OUTPUT, RESOURCE, OUTPUT_BYTES, DIAGNOSTIC_MAGIC, REQUEST_CALLBACK,
    REQUEST_CONTEXT, NATIVE_CONSTRUCTOR, NATIVE_REGISTRATION_RETURN,
    UI_CONTINUATION)
from test_reveal_deferred_queue_mips import TRANSPORT_MUTEX, FAULT
from test_reveal_registry_owner_mips import (
    STATE, BIND_STATE, OWNER_STATE, CODE, CONTROLLER, REGISTRY_MUTEX,
    PAINT_MUTEX, INPUT, RAW_LOCK, RAW_UNLOCK, STACK, RETURN, MASK)


class ConstructorCaptureAdversarialTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = source.SOURCE.read_bytes()
        digest = hashlib.sha256(cls.image).hexdigest()
        if digest != source.SOURCE_SHA256 or len(cls.image) != source.SOURCE_SIZE:
            raise AssertionError(f'unrecognized reference: {digest}')

    def machine(self, **options):
        return ConstructorCaptureMachine(self.image, **options)

    def assert_refused_without_native(self, machine, **options):
        machine.clear_events()
        self.assertEqual(machine.construct(**options), (MASK, 0))
        self.assertEqual(machine.constructor_entries, [])
        self.assertEqual(machine.calls, [])
        self.assertEqual([e for e in machine.constructor_output_accesses
                          if e[0] == 'write'], [])

    def fixed_extents(self, machine):
        return ((STATE, machine.composition['receipt_memory_bytes']),
                (BIND_STATE, machine.composition['binding_memory_bytes']),
                (OWNER_STATE, machine.composition['owner_memory_bytes']),
                (CONTROLLER, receipt.CONTROLLER_BYTES), (REGISTRY_MUTEX, 24),
                (PAINT_MUTEX, 24), (machine.deferred_list, 56),
                (TRANSPORT_MUTEX, 24), (FAULT, 4),
                (CODE, len(machine.code)), receipt.NATIVE_RX)

    def test_invalid_controller_null_alignment_and_unsigned_wrapping_extents(self):
        cases = [dict(controller=value) for value in (0, CONTROLLER + 4, MASK)]
        cases += [dict(request=value) for value in (0, REQUEST + 1, 0xFFFFFFF8)]
        cases += [dict(output=value) for value in (0, OUTPUT + 2, 0xFFFFFFD4)]
        cases += [dict(stack=value) for value in (0, 0xF8, STACK + 4)]
        for options in cases:
            with self.subTest(options=options):
                self.assert_refused_without_native(self.machine(), **options)

    def test_request_output_and_outer_frame_are_disjoint_before_any_native_call(self):
        cases = (dict(request=OUTPUT), dict(request=OUTPUT + 44),
                 dict(output=REQUEST + 8), dict(request=STACK - 8),
                 dict(output=STACK - 48))
        for options in cases:
            with self.subTest(options=options):
                self.assert_refused_without_native(self.machine(), **options)

    def test_named_fixed_states_and_complete_generated_rx_are_excluded(self):
        m = self.machine()
        # For native RX the second tuple word is its end, unlike sized states.
        extents = self.fixed_extents(m)[:-1] + ((receipt.NATIVE_RX[0],
                                               receipt.NATIVE_RX[1] - receipt.NATIVE_RX[0]),)
        for start, size in extents:
            for pointer in (start, start + size - 4):
                for field in ('request', 'output'):
                    with self.subTest(pointer=hex(pointer), field=field):
                        self.assert_refused_without_native(self.machine(), **{field: pointer})
                with self.subTest(pointer=hex(pointer), field='outer frame'):
                    candidate = self.machine()
                    self.assert_refused_without_native(
                        candidate, stack=(pointer & ~7) + core.FRAME)
                    self.assertEqual(candidate.reads, [])
                    self.assertEqual(candidate.writes, [])

    def test_every_dirty_output_word_refuses_before_descriptor_read_or_native_call(self):
        for offset in range(0, OUTPUT_BYTES, 4):
            with self.subTest(offset=offset):
                m = self.machine()
                m.put(OUTPUT + offset, 1, 4)
                self.assert_refused_without_native(m)
                self.assertNotIn((REQUEST, 4), m.reads)
                self.assertFalse(any(DESCRIPTOR <= p < DESCRIPTOR + 104 for p, _ in m.reads))

    def test_descriptor_pointer_null_alignment_wrap_and_dynamic_aliases_are_refused(self):
        for pointer in (0, DESCRIPTOR + 1, 0xFFFFFF9C, REQUEST, OUTPUT,
                        STACK - 104, STACK - core.FRAME - 100):
            with self.subTest(pointer=hex(pointer)):
                m = self.machine()
                m.put(REQUEST, pointer, 4)
                self.assert_refused_without_native(m)

    def test_descriptor_full_extent_excludes_all_fixed_states_and_code_tail(self):
        m = self.machine()
        extents = self.fixed_extents(m)[:-1] + ((receipt.NATIVE_RX[0],
                                               receipt.NATIVE_RX[1] - receipt.NATIVE_RX[0]),)
        for start, size in extents:
            for pointer in (start, start + size - 4):
                with self.subTest(pointer=hex(pointer)):
                    candidate = self.machine()
                    candidate.put(REQUEST, pointer, 4)
                    self.assert_refused_without_native(candidate)

    def test_nonterminated_first64_name_bytes_refuse_without_stack_save(self):
        m = self.machine()
        m.bytes(DESCRIPTOR, b'A' * 64)
        m.clear_events()
        self.assertEqual(m.construct(), (MASK, 0))
        self.assertEqual(m.constructor_entries, [])
        self.assertEqual(m.writes, [])
        self.assertEqual([p for p, size in m.reads
                          if DESCRIPTOR <= p < DESCRIPTOR + 104],
                         list(range(DESCRIPTOR, DESCRIPTOR + 64)))

    def test_empty_native_name_is_bounded_not_rejected_by_invented_policy(self):
        m = self.machine()
        m.bytes(DESCRIPTOR, b'\0')
        engine, output = m.construct()
        self.assertNotEqual(engine, 0)
        self.assertEqual(output, OUTPUT)
        self.assertEqual(m.constructor_output()[0], capture.OUTPUT_MAGIC)

    def test_descriptor_exact_unsigned_end_is_accepted_without_wrapping(self):
        m = self.machine()
        endpoint = 0x100000000 - 104
        m.map(endpoint, 104)
        m.set_descriptor(b'Edge\0', address=endpoint)
        m.put(REQUEST, endpoint, 4)
        engine, output = m.construct()
        self.assertNotEqual(engine, 0)
        self.assertEqual(output, OUTPUT)
        self.assertEqual(m.constructor_entries[0][-1][1], endpoint)

    def test_output_exact_unsigned_end_is_accepted(self):
        m = self.machine()
        endpoint = 0x100000000 - OUTPUT_BYTES
        m.map(endpoint, OUTPUT_BYTES)
        engine, output = m.construct(output=endpoint)
        self.assertEqual(output, endpoint)
        self.assertEqual(m.constructor_output(endpoint)[3], engine)

    def test_guarded_descriptor_pointer_is_not_reread_from_mutated_request(self):
        m = self.machine()

        def mutate(machine, pc):
            if pc == machine.constructor_labels['name_terminated']:
                machine.put(REQUEST, CODE, 4)

        m.on_instruction = mutate
        engine, output = m.construct()
        self.assertEqual(output, OUTPUT)
        self.assertEqual(m.constructor_entries[0][-1][1], DESCRIPTOR)
        self.assertEqual(m.constructor_output()[3], engine)

    def test_private_three_word_request_survives_mutation_before_native_call(self):
        m = self.machine()

        def mutate(machine, pc):
            if pc == machine.constructor_labels['native_call']:
                for offset in (0, 4, 8):
                    machine.put(REQUEST + offset, MASK, 4)

        m.on_instruction = mutate
        m.construct()
        self.assertEqual(m.constructor_entries[0][-1],
                         (CONTROLLER, DESCRIPTOR, REQUEST_CALLBACK, REQUEST_CONTEXT))

    def test_dirty_output_during_native_work_suppresses_whole_export(self):
        for offset in range(0, OUTPUT_BYTES, 4):
            with self.subTest(offset=offset):
                m = self.machine()

                def mutate(machine, pc):
                    if pc == machine.constructor_labels['native_return']:
                        machine.put(OUTPUT + offset, 0xFACEC000 + offset, 4)

                m.on_instruction = mutate
                engine, output = m.construct()
                self.assertNotEqual(engine, 0)
                self.assertEqual(output, 0)
                expected = [0] * 12
                expected[offset // 4] = 0xFACEC000 + offset
                self.assertEqual(m.constructor_output(), tuple(expected))
                self.assertEqual(m.captured_carriers, [])

    def test_matching_output_requires_each_exact_checked_gcap_field(self):
        substitutions = ((capture.MAGIC, 0), (capture.FLAGS, 1),
                         (capture.CONTROLLER, CONTROLLER + 4),
                         (capture.ENGINE, 0x87654321),
                         (capture.BINDING_SEQUENCE, 0),
                         (capture.BINDING_SEQUENCE, 17),
                         (capture.OWNER, 0), (capture.OWNER, 0x80000000),
                         (capture.RECEIPT_SEQUENCE, 0),
                         (capture.RECEIPT_SEQUENCE, 17), (capture.RESULT, 1))
        for offset, value in substitutions:
            with self.subTest(offset=offset, value=hex(value)):
                m = self.machine()

                def mutate(machine, pc):
                    if pc == machine.constructor_labels['native_return']:
                        machine.put(STACK - core.FRAME + core.CAPTURE + offset, value, 4)

                m.on_instruction = mutate
                engine, output = m.construct()
                self.assertEqual(output, OUTPUT)
                self.assertEqual(m.constructor_output()[:8],
                                 (DIAGNOSTIC_MAGIC, *([0] * 7)))
                self.assertEqual(m.constructor_output()[8], engine)
                self.assertEqual(m.constructor_output()[11], 1)

    def test_wrong_observed_registration_return_pointer_cannot_export_positive(self):
        m = self.machine()

        def mutate(machine, pc):
            if pc == machine.constructor_labels['bridge_return']:
                machine.r[3] = OUTPUT

        m.on_instruction = mutate
        engine, output = m.construct()
        self.assertEqual(output, OUTPUT)
        self.assertEqual(m.constructor_output(), (
            DIAGNOSTIC_MAGIC, 0, 0, 0, 0, 0, 0, 0, engine, 0, OUTPUT, 1))

    def test_outer_tag_changed_while_register_runs_is_not_repaired(self):
        m = self.machine()

        def mutate(machine, pc):
            if pc == machine.constructor_labels['bridge_return']:
                machine.put(STACK - core.FRAME + core.TAG, 0, 4)

        m.on_instruction = mutate
        _, output = m.construct()
        self.assertEqual(output, OUTPUT)
        self.assertEqual(m.constructor_output()[0], DIAGNOSTIC_MAGIC)
        self.assertEqual(m.peek(STACK - core.FRAME + core.TAG), core.INVALID)
        self.assertEqual(m.constructor_output()[-1], 1)

    def test_stale_outer_tag_cannot_reuse_previous_capture_or_registration_status(self):
        for stale in (core.RETURNED, core.ENTERED, MASK):
            with self.subTest(stale=hex(stale)):
                m = self.machine()

                def mutate(machine, pc):
                    if pc == machine.constructor_labels['register_bridge']:
                        machine.put(STACK - core.FRAME + core.TAG, stale, 4)

                m.on_instruction = mutate
                engine, output = m.construct()
                self.assertEqual(output, OUTPUT)
                self.assertEqual(m.constructor_output(), (
                    DIAGNOSTIC_MAGIC, 0, 0, 0, 0, 0, 0, 0, engine, 0, 0, 0))
                self.assertNotIn(m.capture_labels['register'], m.trace)
                self.assertEqual(m.captured_carriers, [])

    def test_native_saved_return_is_checked_before_any_outer_frame_load(self):
        m = self.machine()

        def mutate(machine, pc):
            if pc == machine.constructor_labels['register_bridge']:
                machine.put(machine.r[29] + core.NATIVE_SAVED_RA, RETURN, 4)
            elif pc == machine.constructor_labels['native_forward']:
                # Restore the real native continuation only after the emitted
                # gate already selected fallback; do not redirect execution.
                machine.put(machine.r[29] + core.NATIVE_SAVED_RA,
                            machine.constructor_labels['native_return'], 4)

        m.on_instruction = mutate
        engine, output = m.construct()
        self.assertEqual(output, OUTPUT)
        self.assertEqual(m.constructor_output(), (
            DIAGNOSTIC_MAGIC, 0, 0, 0, 0, 0, 0, 0, engine, 0, 0, 0))
        self.assertNotIn(m.capture_labels['register'], m.trace)
        self.assertEqual(m.native_entries[0][2], STACK - core.FRAME - core.NATIVE_FRAME)
        self.assertEqual(m.native_entries[0][1], NATIVE_REGISTRATION_RETURN)

    def test_unrelated_bridge_call_uses_unchanged_legacy_stack_and_return(self):
        m = self.machine()
        m.r[29], m.r[31] = STACK, RETURN
        m.r[4], m.r[5] = CONTROLLER, INPUT
        m.run_at(m.constructor_labels['register_bridge'], RETURN)
        self.assertEqual(m.r[2], 0)
        self.assertEqual(m.native_entries[0][1:3], (RETURN, STACK))
        self.assertNotIn(m.capture_labels['register'], m.trace)
        self.assertEqual(m.constructor_output(), (0,) * 12)

    def test_genuine_legacy_constructor_rejects_scope_before_outer_context_read(self):
        m = self.machine()
        engine = m.stock(NATIVE_CONSTRUCTOR, CONTROLLER, DESCRIPTOR,
                         REQUEST_CALLBACK, REQUEST_CONTEXT)
        self.assertNotEqual(engine, 0)
        self.assertNotIn(m.capture_labels['register'], m.trace)
        self.assertEqual(m.native_entries[0][1:3],
                         (NATIVE_REGISTRATION_RETURN, STACK - core.NATIVE_FRAME))
        self.assertEqual(m.constructor_output(), (0,) * 12)
        bridge_start = m.constructor_labels['register_bridge']
        bridge_end = m.constructor_labels['native_forward']
        bridge_accesses = [e for e in m.constructor_accesses
                           if bridge_start <= e[1] < bridge_end]
        self.assertEqual([(e[2], e[3]) for e in bridge_accesses],
                         [(STACK - core.NATIVE_FRAME + core.NATIVE_SAVED_RA, 4)])

    def test_foreign_controller_bridge_forwards_legacy_without_foreign_outer_read(self):
        m = self.machine()
        foreign = CONTROLLER + 0x1000
        m.map(foreign, receipt.CONTROLLER_BYTES)
        m.configure_controller(foreign)
        m.clear_events()
        m.r[29], m.r[31] = STACK, NATIVE_REGISTRATION_RETURN
        m.r[4], m.r[5] = foreign, INPUT
        m.run_at(m.constructor_labels['register_bridge'], NATIVE_REGISTRATION_RETURN)
        self.assertEqual(m.native_entries[0][1:3], (NATIVE_REGISTRATION_RETURN, STACK))
        self.assertEqual(m.native_entries[0][-1][0], foreign)
        self.assertNotIn(m.capture_labels['register'], m.trace)
        bridge_start = m.constructor_labels['register_bridge']
        bridge_end = m.constructor_labels['native_forward']
        self.assertEqual([e for e in m.constructor_accesses
                          if bridge_start <= e[1] < bridge_end], [])
        self.assertEqual(m.binding_header()[0], 0)
        self.assertEqual(m.constructor_output(), (0,) * 12)

    def test_duplicate_bridge_invalidates_outer_capture_instead_of_reissuing_it(self):
        m = self.machine()
        duplicated = []

        def duplicate(machine, pc):
            if pc == NATIVE_REGISTRATION_RETURN and not duplicated:
                duplicated.append(pc)
                machine.r[4], machine.r[5] = (
                    CONTROLLER, machine.r[29] + core.NATIVE_DESCRIPTOR)
                machine.r[31] = NATIVE_REGISTRATION_RETURN
                machine.run_at(machine.constructor_labels['register_bridge'],
                               NATIVE_REGISTRATION_RETURN)

        m.on_instruction = duplicate
        engine, output = m.construct()
        self.assertEqual(output, OUTPUT)
        self.assertEqual(m.constructor_output()[0], DIAGNOSTIC_MAGIC)
        self.assertEqual(m.constructor_output()[8], engine)
        self.assertEqual(m.constructor_output()[-1], 1)
        self.assertEqual(m.peek(STACK - core.FRAME + core.TAG), core.INVALID)
        self.assertEqual(len(m.native_entries), 2)  # native fallback effects remain
        self.assertEqual(m.captured_carriers, [])

    def test_missing_release_observer_is_not_replaced_with_current_binding_lookup(self):
        for missing in ('release_call', 'raw_release_call', 'raw_release_return'):
            with self.subTest(missing=missing):
                m = self.machine()
                m.remove_release_hook(missing)
                engine, output = m.construct()
                self.assertEqual(output, OUTPUT)
                self.assertEqual(m.constructor_output(), (
                    DIAGNOSTIC_MAGIC, 0, 0, 0, 0, 0, 0, 0, engine, MASK, 0, 1))
                self.assertEqual(m.binding_header()[0], 1)
                self.assertEqual(m.captured_carriers, [])

    def test_ambiguous_raw_release_still_reaches_original_unsafe_native_continuation(self):
        for status in (1, 0x82, MASK):
            for released in (False, True):
                with self.subTest(status=hex(status), released=released):
                    m = self.machine(release=status)
                    m.registry_release_failure_releases = released
                    engine, output = m.construct()
                    self.assertEqual(output, OUTPUT)
                    self.assertEqual(m.constructor_output(), (
                        DIAGNOSTIC_MAGIC, 0, 0, 0, 0, 0, 0, 0,
                        engine, MASK, status, 1))
                    self.assertEqual(len(m.native_continuations), 1)
                    self.assertEqual(m.native_continuations[0][0], UI_CONTINUATION)
                    self.assertEqual(m.native_continuations[0][-2], not released)
                    self.assertEqual(m.registry_held, not released)
                    self.assertIn(0x437EE0, m.calls)
                    self.assertEqual(m.freed, [])
                    self.assertEqual(m.captured_carriers, [])

    def test_native_validation_failure_has_real_null_dereference_not_fake_success(self):
        m = self.machine(validation_result=0)
        with self.assertRaisesRegex(AssertionError, r'^unmapped access 0x0, size 4$'):
            m.construct()
        self.assertEqual(m.constructor_output(), (0,) * 12)
        self.assertEqual(m.native_entries, [])
        self.assertTrue(m.native_continuations)

    def test_native_name_allocation_failure_faults_without_output_or_registration(self):
        m = self.machine()
        m.name_allocation_failure = True
        with self.assertRaisesRegex(AssertionError, r'^unmapped access 0x0, size 14$'):
            m.construct()
        self.assertEqual(m.constructor_output(), (0,) * 12)
        self.assertEqual(m.native_entries, [])

    def test_full_composition_metadata_covers_exact_appended_constructor_rx(self):
        m = self.machine()
        metadata = m.composition
        self.assertEqual(metadata['protected_code_extent'], (CODE, len(m.code)))
        self.assertEqual(metadata['queue_prefix_code_bytes'] +
                         metadata['constructor_code_bytes'], len(m.code))
        self.assertEqual(metadata['constructor_hooks'], core.hook_words(m.constructor_labels))
        self.assertTrue(metadata['registry_release_checked'])
        self.assertEqual(m.constructor_labels['construct'],
                         CODE + metadata['queue_prefix_code_bytes'])

    def test_after_constructor_return_accesses_only_private_frame_and_owned_output(self):
        m = self.machine()
        m.construct()
        start, end = (m.constructor_labels['native_return'],
                      m.constructor_labels['register_bridge'])
        late = [e for e in m.constructor_accesses if start <= e[1] < end]
        self.assertTrue(late)
        self.assertTrue(all(
            STACK - core.FRAME <= e[2] and e[2] + e[3] <= STACK
            or OUTPUT <= e[2] and e[2] + e[3] <= OUTPUT + OUTPUT_BYTES
            for e in late), late)

    def test_queue_prefix_zero_following_default_preserves_exact_previous_bytes(self):
        args = (STATE, BIND_STATE, OWNER_STATE, CONTROLLER, REGISTRY_MUTEX,
                PAINT_MUTEX, CODE, 0x1FF0000, TRANSPORT_MUTEX, FAULT)
        implicit = queues.assemble(*args)
        explicit = queues.assemble(*args, following_code_bytes=0)
        self.assertEqual(implicit, explicit)
        self.assertEqual(len(implicit['code']), 34200)
        self.assertEqual(hashlib.sha256(implicit['code']).hexdigest(),
                         '27c7d0fbad229b65ca81d4b0f9caf3d0581f8ba8a6ba599cf77f574dcc6fdd8b')
        for value in (True, -4, 1, 4.0, '4', 0x10000000):
            with self.subTest(following=value):
                with self.assertRaises(ValueError):
                    queues.assemble(*args, following_code_bytes=value)

    def test_hook_target_validation_rejects_bool_alignment_wrap_and_foreign_jump_region(self):
        for value in (None, True, 0, 1, MASK, 0x10000000):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    core.hook_words({'register_bridge': value})

    def test_assembler_rejects_malformed_extra_exclusions_and_protected_rx(self):
        m = self.machine()
        args = (STATE, BIND_STATE, OWNER_STATE, CONTROLLER, REGISTRY_MUTEX,
                PAINT_MUTEX, m.constructor_labels['construct'],
                m.capture_labels['register'])
        bad_data = ([], ([],), ((True, 4),), ((FAULT, True),),
                    ((FAULT, 0),), ((FAULT + 1, 4),), ((FAULT, -4),),
                    ((FAULT, 4), (FAULT, 4)))
        for value in bad_data:
            with self.subTest(protected_data=value):
                with self.assertRaises(ValueError):
                    core.assemble(*args, protected_data=value)
        for value in ([], (CODE, True), (CODE, 0), (CODE + 1, len(m.code)),
                      (CODE, len(m.code) - 4), (CODE, 0x100000000)):
            with self.subTest(protected_code=value):
                with self.assertRaises(ValueError):
                    core.assemble(*args, protected_code=value, protected_data=(
                        (m.deferred_list, 56), (TRANSPORT_MUTEX, 24), (FAULT, 4)))


if __name__ == '__main__':
    unittest.main()
