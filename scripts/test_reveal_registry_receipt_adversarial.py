#!/usr/bin/env python3
"""Fail-closed receipt gates with native publication left unchanged.

Instruction-boundary mutations are bounded counterexamples, not a scheduler,
native lifetime proof, stack authentication scheme or permission to free an
engine. Only this local interpreter's instruction fetch is redirected.
"""

import unittest

import reveal_registry_receipt_mips as core
import test_reveal_registry_receipt_mips as fixture


class RegistryReceiptAdversarialTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture.RegistryReceiptTests.setUpClass()
        cls.image = fixture.RegistryReceiptTests.image

    def machine(self, **options):
        return fixture.RegistryReceiptMachine(self.image, **options)

    def seed(self, m, offset, value):
        m.put(fixture.STATE + offset, value, 4)

    def clear_observation(self, m):
        m.journal_accesses.clear()
        m.writes.clear()

    def journal_snapshot(self, m):
        return m.words_at(fixture.STATE, core.memory_bytes(m.capacity) // 4)

    def journal_writes(self, m):
        end = fixture.STATE + core.memory_bytes(m.capacity)
        return [(address, value, size) for address, value, size in m.writes
                if fixture.STATE <= address < end]

    def assert_no_journal_touch(self, m, before=None):
        self.assertEqual(m.journal_accesses, [])
        if before is not None:
            self.assertEqual(self.journal_snapshot(m), before)

    def assert_fault_only(self, m):
        self.assertEqual(self.journal_writes(m),
                         [(fixture.STATE + core.FAULT, 1, 4)])
        self.assertTrue(m.journal_accesses)
        self.assertTrue(all(event[-1] for event in m.journal_accesses))
        self.assertEqual(m.header()[core.FAULT // 4], 1)

    def test_begin_resets_all_carriers_before_a_failed_acquisition(self):
        m = self.machine(acquire=22)
        frame = fixture.STACK - 0x28
        for offset, value in ((core.TAG, core.CAPTURED),
                              (core.PTR, fixture.REGISTRY_MUTEX),
                              (core.RAW_STATUS, 0)):
            m.put(frame + offset, value, 4)
        self.clear_observation(m)
        self.assertEqual(m.register(), 0)
        self.assertEqual(m.carrier(), (0, fixture.REGISTRY_MUTEX, 22))
        self.assert_no_journal_touch(m)

    def test_missing_begin_cannot_reuse_stale_captured_success(self):
        m = self.machine()
        pc = core.HOOKS['begin'][0]
        for address in (pc, pc + 4):
            del m.patches[address]
        frame = fixture.STACK - 0x28
        for offset, value in ((core.TAG, core.CAPTURED),
                              (core.PTR, fixture.REGISTRY_MUTEX),
                              (core.RAW_STATUS, 0)):
            m.put(frame + offset, value, 4)
        self.assertEqual(m.register(), 0)
        self.assertEqual(m.carrier()[0], 0)
        self.assert_no_journal_touch(m)

    def test_wrong_callback_or_native_return_or_controller_cannot_enter_capture(self):
        for variant in ('callback_return', 'native_return', 'controller'):
            with self.subTest(variant=variant):
                m = self.machine()

                def mutate(machine, pc):
                    if pc == core.HOOKS['raw_call'][0]:
                        if variant == 'callback_return':
                            machine.put(machine.r[29] + 0x1C, 0x437CF0, 4)
                        elif variant == 'native_return':
                            machine.put(machine.r[29] + 0x3C, 0x438A18, 4)
                        else:
                            machine.r[16] = fixture.CONTROLLER + 0x1000
                    elif pc == core.HOOKS['raw_return'][0]:
                        # Restore continuation, not the invalidated carrier.
                        machine.put(machine.r[29] + 0x1C, 0x437D30, 4)
                        machine.put(machine.r[29] + 0x3C, 0x438A10, 4)
                        machine.r[16] = fixture.CONTROLLER

                m.on_instruction = mutate
                self.assertEqual(m.register(), 0)
                self.assertEqual(m.carrier()[0], 0)
                self.assert_no_journal_touch(m)

    def test_actual_raw_mutex_changed_after_begin_is_not_a_receipt(self):
        m = self.machine()

        def mutate(machine, pc):
            if pc == core.HOOKS['raw_call'][0]:
                machine.r[4] = fixture.REGISTRY_MUTEX + 0x100

        m.on_instruction = mutate
        self.assertEqual(m.register(), 0)
        self.assertEqual(m.raw_events[0][1], fixture.REGISTRY_MUTEX + 0x100)
        self.assert_no_journal_touch(m)

    def test_changed_return_scope_after_service_cannot_complete_capture(self):
        for variant in ('callback_return', 'native_return', 'controller'):
            with self.subTest(variant=variant):
                m = self.machine()

                def mutate(machine, pc):
                    if pc == core.HOOKS['raw_return'][0]:
                        self.assertEqual(machine.carrier()[0], core.ENTERED)
                        if variant == 'callback_return':
                            machine.put(machine.r[29] + 0x1C, 0x437CF0, 4)
                        elif variant == 'native_return':
                            machine.put(machine.r[29] + 0x3C, 0x438A18, 4)
                        else:
                            machine.r[16] = fixture.CONTROLLER + 0x1000
                    elif pc == 0x466DB8:
                        # Preserve the native continuation after denying capture.
                        machine.r[31] = 0x437D30
                        machine.put(machine.r[29] + 0x3C, 0x438A10, 4)
                        machine.r[16] = fixture.CONTROLLER

                m.on_instruction = mutate
                self.assertEqual(m.register(), 0)
                self.assertEqual(m.carrier()[0], 0)
                self.assert_no_journal_touch(m)

    def test_changed_bound_fields_after_raw_zero_deny_journal(self):
        for offset, value in ((0x13C, fixture.REGISTRY_MUTEX + 0x100),
                              (0x274, 0x437CE0), (0x278, 0x437D60)):
            with self.subTest(offset=hex(offset)):
                m = self.machine()

                def mutate(machine, target):
                    if target == fixture.RAW_LOCK:
                        machine.put(fixture.CONTROLLER + offset, value, 4)

                m.on_service = mutate
                self.assertEqual(m.register(), 0)
                self.assertEqual(m.raw_events[0][-1], 0)
                self.assert_no_journal_touch(m)

    def test_changed_controller_at_publication_does_not_touch_bound_journal(self):
        m = self.machine()
        foreign = fixture.CONTROLLER + 0x1000
        m.map(foreign, 0x28C)
        m.configure_controller(foreign)

        def mutate(machine, pc):
            if pc == core.HOOKS['published'][0]:
                machine.r[16] = foreign

        m.on_instruction = mutate
        self.assertEqual(m.register(), 0)
        self.assert_no_journal_touch(m)

    def test_wrong_publication_tag_never_inspects_even_a_corrupt_journal(self):
        for tag in (0, core.ARMED, core.ENTERED, fixture.MASK):
            with self.subTest(tag=hex(tag)):
                m = self.machine()
                self.seed(m, core.COUNT, fixture.MASK)
                before = self.journal_snapshot(m)
                self.clear_observation(m)

                def mutate(machine, pc):
                    if pc == core.HOOKS['published'][0]:
                        machine.put(machine.r[29] + core.TAG, tag, 4)

                m.on_instruction = mutate
                self.assertEqual(m.register(), 0)
                self.assertEqual(m.carrier()[0], 0)
                self.assert_no_journal_touch(m, before)

    def test_wrong_captured_pointer_never_inspects_corrupt_journal(self):
        m = self.machine()
        self.seed(m, core.COUNT, fixture.MASK)
        before = self.journal_snapshot(m)
        self.clear_observation(m)

        def mutate(machine, pc):
            if pc == core.HOOKS['published'][0]:
                machine.put(machine.r[29] + core.PTR,
                            fixture.REGISTRY_MUTEX + 4, 4)

        m.on_instruction = mutate
        self.assertEqual(m.register(), 0)
        self.assert_no_journal_touch(m, before)

    def test_nonzero_captured_status_does_not_access_journal_while_mutex_is_held(self):
        for status in (1, 22, 0x82, fixture.MASK):
            with self.subTest(status=status):
                m = self.machine()
                self.seed(m, core.RESERVED0, fixture.MASK)
                before = self.journal_snapshot(m)
                self.clear_observation(m)

                def mutate(machine, pc):
                    if pc == core.HOOKS['published'][0]:
                        self.assertTrue(machine.registry_held)
                        machine.put(machine.r[29] + core.RAW_STATUS, status, 4)

                m.on_instruction = mutate
                self.assertEqual(m.register(), 0)
                self.assert_no_journal_touch(m, before)

    def test_duplicate_raw_return_capture_invalidates_instead_of_reusing_status(self):
        m = self.machine()
        replayed = []

        def mutate(machine, pc):
            if pc == 0x466DB8 and not replayed:
                replayed.append(True)
                self.assertEqual(machine.carrier()[0], core.CAPTURED)
                machine.run_at(machine.labels['raw_return'], 0x466DB8)

        m.on_instruction = mutate
        self.assertEqual(m.register(), 0)
        self.assertEqual(replayed, [True])
        self.assertEqual(m.carrier()[0], 0)
        self.assert_no_journal_touch(m)

    def test_nonzero_raw_acquisition_may_own_mutex_but_cannot_inspect_journal(self):
        m = self.machine(acquire=0x82)
        self.seed(m, core.COUNT, fixture.MASK)
        self.seed(m, core.RESERVED1, fixture.MASK)
        before = self.journal_snapshot(m)
        self.clear_observation(m)

        def possibly_owned(machine, target):
            if target == fixture.RAW_LOCK:
                machine.registry_held = True

        m.on_service = possibly_owned
        self.assertEqual(m.register(), 0)
        self.assertEqual(m.raw_events[0][-1], 0x82)
        self.assert_no_journal_touch(m, before)

    def test_full_capacity_stays_bounded_without_revoking_historical_receipt(self):
        m = self.machine(capacity=1)
        self.assertEqual(m.register(), 0)
        before = self.journal_snapshot(m)
        self.clear_observation(m)
        self.assertEqual(m.register(), 0)
        self.assertEqual(self.journal_snapshot(m), before)
        self.assertEqual(self.journal_writes(m), [])
        self.assertEqual(len(m.allocations), 2)
        self.assertTrue(all(event[-1] for event in m.journal_accesses))

    def test_negative_or_over_capacity_count_only_sets_terminal_fault(self):
        for count in (0x80000000, fixture.MASK, 17):
            with self.subTest(count=count):
                m = self.machine()
                self.seed(m, core.COUNT, count)
                self.clear_observation(m)
                self.assertEqual(m.register(), 0)
                self.assert_fault_only(m)
                self.assertEqual(m.header()[0], count)

    def test_count_cannot_skip_unissued_zero_rows(self):
        m = self.machine()
        self.seed(m, core.COUNT, 2)
        self.clear_observation(m)
        self.assertEqual(m.register(), 0)
        self.assert_fault_only(m)
        self.assertEqual(m.record(), (0,) * 10)
        self.assertEqual(m.record(1), (0,) * 10)

    def test_count_rollback_cannot_overwrite_an_issued_row(self):
        m = self.machine()
        self.assertEqual(m.register(), 0)
        original = m.record()
        self.seed(m, core.COUNT, 0)
        self.clear_observation(m)
        self.assertEqual(m.register(), 0)
        self.assert_fault_only(m)
        self.assertEqual(m.record(), original)
        self.assertEqual(m.header()[0], 0)

    def test_old_prefix_schema_corruption_only_sets_fault(self):
        fields = (core.MAGIC, core.SEQUENCE, core.CONTROLLER,
                  core.MUTEX, core.SITE, core.STATUS)
        for offset in fields:
            with self.subTest(offset=offset):
                m = self.machine()
                self.assertEqual(m.register(), 0)
                address = fixture.STATE + core.HEADER_BYTES + offset
                m.put(address, m.record()[offset // 4] ^ 1, 4)
                original = m.record()
                self.clear_observation(m)
                self.assertEqual(m.register(), 0)
                self.assert_fault_only(m)
                self.assertEqual(m.record(), original)
                self.assertEqual(m.header()[0], 1)

    def test_every_partially_dirty_target_word_prevents_slot_reuse(self):
        for offset in range(0, core.RECORD_BYTES, 4):
            with self.subTest(offset=offset):
                m = self.machine()
                self.seed(m, core.HEADER_BYTES + offset, 0xBAD00000 + offset)
                original = m.record()
                self.clear_observation(m)
                self.assertEqual(m.register(), 0)
                self.assert_fault_only(m)
                self.assertEqual(m.record(), original)
                self.assertEqual(m.header()[0], 0)

    def test_existing_fault_is_terminal_before_other_header_or_row_reads(self):
        m = self.machine()
        self.seed(m, core.FAULT, 0x12345678)
        self.seed(m, core.COUNT, fixture.MASK)
        self.seed(m, core.RESERVED0, fixture.MASK)
        before = self.journal_snapshot(m)
        self.clear_observation(m)
        self.assertEqual(m.register(), 0)
        self.assertEqual(self.journal_snapshot(m), before)
        self.assertEqual(self.journal_writes(m), [])
        self.assertEqual([(event[0], event[2]) for event in m.journal_accesses],
                         [('read', fixture.STATE + core.FAULT)])
        self.assertTrue(m.journal_accesses[0][-1])

    def test_old_native_scalar_fields_are_never_followed_as_live_pointers(self):
        m = self.machine()
        self.assertEqual(m.register(), 0)
        for offset, value in ((core.NODE, 1), (core.ENGINE, fixture.MASK),
                              (core.NATIVE_SP, 3), (core.CALLER, 7)):
            self.seed(m, core.HEADER_BYTES + offset, value)
        original = m.record()
        m.reads.clear()
        self.clear_observation(m)
        self.assertEqual(m.register(), 0)
        self.assertEqual(m.header(), (2, 0, 0, 0))
        self.assertEqual(m.record(), original)
        for address, size in m.reads:
            self.assertNotIn(address, (1, 3, 7, fixture.MASK))

    def test_distinct_native_stack_frames_do_not_share_carrier_readiness(self):
        m = self.machine()
        self.assertEqual(m.register(), 0)
        first = m.record()
        second_stack = fixture.STACK + 0x1000
        self.assertEqual(m.register(stack=second_stack), 0)
        self.assertEqual(m.record(1)[core.NATIVE_SP // 4], second_stack - 0x28)
        self.assertEqual(m.record(), first)
        self.assertEqual(m.carrier()[0], 0)
        self.assertEqual(m.carrier(second_stack)[0], 0)

    def test_full_journal_still_validates_old_schema_before_saturation_return(self):
        m = self.machine(capacity=1)
        self.assertEqual(m.register(), 0)
        self.seed(m, core.HEADER_BYTES + core.STATUS, 1)
        original = m.record()
        self.clear_observation(m)
        self.assertEqual(m.register(), 0)
        self.assert_fault_only(m)
        self.assertEqual(m.record(), original)
        self.assertEqual(m.header()[0], 1)

    def test_unlock_error_then_failed_acquire_does_not_revoke_earlier_receipt(self):
        m = self.machine(release=22)
        self.assertEqual(m.register(), 0)
        before = self.journal_snapshot(m)
        m.acquire = 22
        self.clear_observation(m)
        self.assertEqual(m.register(), 0)
        self.assert_no_journal_touch(m, before)
        self.assertEqual([event[-1] for event in m.raw_events], [0, 22, 22, 22])

    def test_invalid_address_extents_and_capacity_are_rejected_before_emission(self):
        defaults = [fixture.STATE, fixture.CONTROLLER,
                    fixture.REGISTRY_MUTEX, fixture.CODE]
        for index, value in ((0, 0), (0, True), (0, fixture.STATE + 1),
                              (0, 0xFFFFFFFC), (1, 0xFFFFFFFC),
                              (2, 0xFFFFFFFC), (3, 0x10000000)):
            with self.subTest(index=index, value=value):
                arguments = defaults.copy()
                arguments[index] = value
                with self.assertRaises(ValueError):
                    core.assemble(*arguments)
        for capacity in (0, True, 1025, -1, 1.0):
            with self.subTest(capacity=capacity):
                with self.assertRaises(ValueError):
                    core.assemble(*defaults, capacity=capacity)

    def test_all_shared_extent_aliases_and_native_rx_aliases_are_rejected(self):
        defaults = [fixture.STATE, fixture.CONTROLLER,
                    fixture.REGISTRY_MUTEX, fixture.CODE]
        for destination in range(4):
            for source in range(destination):
                with self.subTest(destination=destination, source=source):
                    arguments = defaults.copy()
                    arguments[destination] = arguments[source]
                    with self.assertRaises(ValueError):
                        core.assemble(*arguments)
        for index in range(4):
            with self.subTest(native_alias=index):
                arguments = defaults.copy()
                arguments[index] = 0x438000
                with self.assertRaises(ValueError):
                    core.assemble(*arguments)


if __name__ == '__main__':
    unittest.main()
