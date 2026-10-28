#!/usr/bin/env python3
"""Hostile historical birth inputs and gates, without current-identity claims.

Malformed private events are negative scalar/bounds examples, not proof of an
unforgeable callback or authenticated stack. Direct callback calls require a
valid exclusively owned frame and an already held real registry mutex. No
test installs redirects or acquires a native allocation lifetime lease.
"""

import unittest

import reveal_registry_birth_mips as core
import reveal_registry_receipt_mips as receipt
import test_reveal_registry_birth_mips as fixture


class RegistryBirthAdversarialTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture.RegistryBirthTests.setUpClass()
        cls.image = fixture.RegistryBirthTests.image

    def machine(self, **options):
        return fixture.RegistryBirthMachine(self.image, **options)

    def writes(self, machine):
        end = fixture.BIRTH + core.memory_bytes(machine.birth_capacity)
        return [(address, value, size) for address, value, size in machine.writes
                if fixture.BIRTH <= address < end]

    def assert_fault_only(self, machine):
        self.assertEqual(self.writes(machine), [(fixture.BIRTH + core.FAULT, 1, 4)])
        self.assertEqual(machine.birth_header()[1], 1)

    def observe(self, machine):
        machine.write_event()
        machine.registry_held = True
        machine.clear_events()
        machine.invoke_observe()

    def test_every_real_raw_acquire_error_denies_all_birth_access_even_if_native_publishes(self):
        for status in (1, 22, 0x82, fixture.MASK):
            with self.subTest(status=status):
                m = self.machine(acquire=status)
                m.put(fixture.BIRTH + core.COUNT, fixture.MASK, 4)
                before = m.birth_snapshot()
                m.clear_events()
                self.assertEqual(m.register(), 0)
                self.assertEqual(m.birth_accesses, [])
                self.assertEqual(m.birth_requests, [])
                self.assertEqual(m.birth_snapshot(), before)
                self.assertEqual(m.words_at(fixture.CONTROLLER + 0x34, 2),
                                 (m.allocations[0], m.allocations[0]))

    def test_raw_error_that_may_own_mutex_still_cannot_access_birth_state(self):
        m = self.machine(acquire=0x82)

        def owned_despite_error(machine, target):
            if target == fixture.RAW_LOCK and machine.r[4] == fixture.REGISTRY_MUTEX:
                machine.registry_held = True

        m.on_service = owned_despite_error
        self.assertEqual(m.register(), 0)
        self.assertEqual(m.birth_accesses, [])
        self.assertEqual(m.birth_header(), (0, 0, 0, 0))

    def test_missing_begin_raw_call_or_return_redirect_does_not_invent_fresh_birth(self):
        for name in ('begin', 'raw_call', 'raw_return'):
            with self.subTest(name=name):
                m = self.machine()
                pc = receipt.HOOKS[name][0]
                for address in (pc, pc + 4):
                    m.patches.pop(address, None)
                self.assertEqual(m.register(), 0)
                self.assertEqual(m.birth_requests, [])
                self.assertEqual(m.birth_accesses, [])

    def test_wrong_captured_tag_pointer_or_status_denies_before_corrupt_birth_state(self):
        replacements = ((receipt.TAG, 0), (receipt.TAG, receipt.ARMED),
                        (receipt.TAG, receipt.ENTERED),
                        (receipt.PTR, fixture.REGISTRY_MUTEX + 4),
                        (receipt.RAW_STATUS, 22))
        for offset, value in replacements:
            with self.subTest(offset=offset, value=value):
                m = self.machine()
                m.put(fixture.BIRTH + core.COUNT, fixture.MASK, 4)
                before = m.birth_snapshot()
                m.clear_events()

                def mutate(machine, pc):
                    if pc == receipt.HOOKS['published'][0]:
                        machine.put(machine.r[29] + offset, value, 4)

                m.on_instruction = mutate
                self.assertEqual(m.register(), 0)
                self.assertEqual(m.birth_accesses, [])
                self.assertEqual(m.birth_snapshot(), before)

    def test_changed_bound_native_routes_after_raw_zero_do_not_touch_birth_state(self):
        for offset, value in ((0x13C, fixture.REGISTRY_MUTEX + 4),
                              (0x274, 0x437CE0), (0x278, 0x437D60)):
            with self.subTest(offset=offset):
                m = self.machine()

                def mutate(machine, target):
                    if target == fixture.RAW_LOCK:
                        machine.put(fixture.CONTROLLER + offset, value, 4)

                m.on_service = mutate
                self.assertEqual(m.register(), 0)
                self.assertEqual(m.birth_requests, [])
                self.assertEqual(m.birth_accesses, [])

    def test_wrong_raw_service_pointer_cannot_be_substituted_for_expected_registry_mutex(self):
        m = self.machine()

        def mutate(machine, pc):
            if pc == receipt.HOOKS['raw_call'][0]:
                machine.r[4] = fixture.REGISTRY_MUTEX + 0x100

        m.on_instruction = mutate
        self.assertEqual(m.register(), 0)
        self.assertEqual(m.birth_requests, [])
        self.assertEqual(m.birth_accesses, [])

    def test_foreign_controller_publication_cannot_write_the_bound_birth_ledger(self):
        m = self.machine()
        foreign = fixture.CONTROLLER + 0x1000
        m.map(foreign, 0x28C)
        m.configure_controller(foreign)
        self.assertEqual(m.register(controller=foreign), 0)
        self.assertEqual(m.birth_accesses, [])
        self.assertEqual(m.birth_requests, [])

    def test_duplicate_published_redirect_cannot_reuse_consumed_native_witness(self):
        m = self.machine()
        self.assertEqual(m.register(), 0)
        before = m.birth_snapshot()
        m.r[29], m.r[16], m.r[2], m.r[3] = (
            fixture.STACK - 0x28, fixture.CONTROLLER,
            m.allocations[0], fixture.CONTROLLER + 0x34)
        m.clear_events()
        m.run_at(m.receipt_labels['published'], 0x438A60)
        self.assertEqual(m.birth_accesses, [])
        self.assertEqual(m.birth_requests, [])
        self.assertEqual(m.birth_snapshot(), before)

    def test_existing_birth_fault_is_terminal_before_other_header_or_row_reads(self):
        m = self.machine()
        m.put(fixture.BIRTH + core.FAULT, 0x12345678, 4)
        m.put(fixture.BIRTH + core.COUNT, fixture.MASK, 4)
        m.put(fixture.BIRTH + core.RESERVED0, fixture.MASK, 4)
        before = m.birth_snapshot()
        self.observe(m)
        self.assertEqual(m.birth_snapshot(), before)
        self.assertEqual(self.writes(m), [])
        self.assertEqual([(kind, address) for kind, _, address, *_ in m.birth_accesses],
                         [('read', fixture.BIRTH + core.FAULT)])

    def test_negative_or_over_capacity_count_can_only_latch_fault(self):
        for value in (0x80000000, fixture.MASK, 17):
            with self.subTest(value=value):
                m = self.machine()
                m.put(fixture.BIRTH + core.COUNT, value, 4)
                self.observe(m)
                self.assert_fault_only(m)
                self.assertEqual(m.birth_header()[0], value)

    def test_nonzero_reserved_header_words_latch_fault_without_row_mutation(self):
        for offset in (core.RESERVED0, core.RESERVED1):
            with self.subTest(offset=offset):
                m = self.machine()
                m.put(fixture.BIRTH + offset, 1, 4)
                self.observe(m)
                self.assert_fault_only(m)
                self.assertEqual(m.birth_record(), (0,) * 10)

    def test_count_cannot_skip_zero_rows_or_roll_back_to_overwrite_old_history(self):
        for variant in ('skip', 'rollback'):
            with self.subTest(variant=variant):
                m = self.machine()
                if variant == 'rollback':
                    self.assertEqual(m.register(), 0)
                    m.put(fixture.BIRTH + core.COUNT, 0, 4)
                else:
                    m.put(fixture.BIRTH + core.COUNT, 1, 4)
                old = m.birth_record()
                self.observe(m)
                self.assert_fault_only(m)
                self.assertEqual(m.birth_record(), old)

    def test_each_old_prefix_schema_field_is_revalidated_before_append(self):
        for offset in (core.MAGIC, core.TOKEN, core.CONTROLLER, core.MUTEX,
                       core.SITE, core.STATUS):
            with self.subTest(offset=offset):
                m = self.machine()
                self.assertEqual(m.register(), 0)
                address = fixture.BIRTH + core.HEADER_BYTES + offset
                m.put(address, m.birth_record()[offset // 4] ^ 1, 4)
                old = m.birth_record()
                self.observe(m)
                self.assert_fault_only(m)
                self.assertEqual(m.birth_record(), old)
                self.assertEqual(m.birth_header()[0], 1)

    def test_old_historical_scalar_words_are_not_validated_as_live_addresses(self):
        m = self.machine()
        self.assertEqual(m.register(), 0)
        for offset, value in ((core.NODE, 1), (core.ENGINE, fixture.MASK),
                              (core.NATIVE_SP, 3), (core.CALLER, 7)):
            m.put(fixture.BIRTH + core.HEADER_BYTES + offset, value, 4)
        old = m.birth_record()
        self.observe(m)
        self.assertEqual(m.birth_header(), (2, 0, 0, 0))
        self.assertEqual(m.birth_record(), old)
        self.assertFalse(any(address in (1, 3, 7, fixture.MASK)
                             for address, _ in m.reads))

    def test_every_dirty_word_in_the_next_slot_prevents_partial_reuse(self):
        for offset in range(0, core.RECORD_BYTES, 4):
            with self.subTest(offset=offset):
                m = self.machine()
                m.put(fixture.BIRTH + core.HEADER_BYTES + offset,
                      0xBAD00000 + offset, 4)
                old = m.birth_record()
                self.observe(m)
                self.assert_fault_only(m)
                self.assertEqual(m.birth_record(), old)
                self.assertEqual(m.birth_header()[0], 0)

    def test_dirty_later_unused_tail_slot_also_permanently_faults_before_append(self):
        for index in (1, 7, 15):
            with self.subTest(index=index):
                m = self.machine()
                address = fixture.BIRTH + core.HEADER_BYTES + index * core.RECORD_BYTES + 36
                m.put(address, 0xDEADC0DE, 4)
                before = m.birth_snapshot()
                self.observe(m)
                self.assert_fault_only(m)
                after = list(before)
                after[core.FAULT // 4] = 1
                self.assertEqual(m.birth_snapshot(), tuple(after))

    def test_full_birth_ledger_still_validates_old_schema_before_exhaustion_fault(self):
        m = self.machine(birth_capacity=1)
        self.assertEqual(m.register(), 0)
        m.put(fixture.BIRTH + core.HEADER_BYTES + core.STATUS, 1, 4)
        old = m.birth_record()
        self.observe(m)
        self.assert_fault_only(m)
        self.assertEqual(m.birth_record(), old)

        status_address = fixture.BIRTH + core.HEADER_BYTES + core.STATUS
        self.assertTrue(any(kind == 'read' and address == status_address
                            for kind, _, address, *_ in m.birth_accesses))

    def test_fault_remains_terminal_after_attempted_later_valid_native_publication(self):
        m = self.machine(birth_capacity=1)
        self.assertEqual(m.register(), 0)
        self.assertEqual(m.register(), 0)
        before = m.birth_snapshot()
        m.clear_events()
        self.assertEqual(m.register(), 0)
        self.assertEqual(m.birth_snapshot(), before)
        self.assertEqual(self.writes(m), [])
        self.assertEqual(m.binding_header()[0], 3)

    def test_wrong_event_schema_or_controller_argument_denies_before_any_birth_access(self):
        event = [fixture.CONTROLLER, fixture.REGISTRY_MUTEX, 1, fixture.ENGINE,
                 3, fixture.RETURN, 0x438A5C, 0]
        for index, value in ((0, fixture.CONTROLLER + 4),
                             (1, fixture.REGISTRY_MUTEX + 4), (6, 0x438A60),
                             (7, 1), (7, 22), (7, fixture.MASK)):
            with self.subTest(index=index, value=value):
                m = self.machine()
                bad = event.copy()
                bad[index] = value
                m.write_event(bad)
                m.clear_events()
                m.invoke_observe()
                self.assertEqual(m.birth_accesses, [])
                self.assertEqual(m.birth_header(), (0, 0, 0, 0))
        m = self.machine()
        m.write_event(event)
        m.clear_events()
        m.invoke_observe(controller=fixture.CONTROLLER + 4)
        self.assertEqual(m.birth_accesses, [])

    def test_event_null_unaligned_wrapped_and_protected_extents_deny_before_event_load(self):
        prototype = self.machine()
        protected = ((fixture.BIRTH, core.memory_bytes()),
                     (fixture.STATE, prototype.composition['receipt_memory_bytes']),
                     (fixture.BIND_STATE, prototype.composition['binding_memory_bytes']),
                     (fixture.OWNER_STATE, prototype.composition['owner_memory_bytes']),
                     (fixture.CONTROLLER, receipt.CONTROLLER_BYTES),
                     (fixture.REGISTRY_MUTEX, receipt.MUTEX_BYTES),
                     (fixture.PAINT_MUTEX, receipt.MUTEX_BYTES),
                     (fixture.CODE, len(prototype.code)),
                     (receipt.NATIVE_RX[0], receipt.NATIVE_RX[1] - receipt.NATIVE_RX[0]))
        addresses = [0, fixture.EVENT + 1, 0xFFFFFFF0]
        for start, size in protected:
            addresses.extend((start, start + size - 4))
        for address in addresses:
            with self.subTest(address=hex(address)):
                m = self.machine()
                m.clear_events()
                m.invoke_observe(address)
                self.assertEqual(m.birth_accesses, [])
                self.assertFalse(any(address <= read < address + 32
                                     for read, _ in m.reads))

    def test_event_cannot_overlap_the_current_private_callback_frame(self):
        for delta in (0, 4, core.FRAME - 4, -28):
            with self.subTest(delta=delta):
                m = self.machine()
                frame = fixture.STACK - core.FRAME
                m.clear_events()
                m.invoke_observe(frame + delta)
                self.assertEqual(m.birth_accesses, [])
                # Saved-frame loads on return are expected; the event itself
                # is never adopted or copied as an input snapshot.
                self.assertEqual(m.birth_header(), (0, 0, 0, 0))
                self.assertNotIn(m.birth_labels['snapshot_done'], m.trace)

    def test_valid_event_immediately_adjacent_to_fixed_extents_is_not_an_overlap(self):
        for address in (fixture.BIRTH - 32,
                        fixture.BIRTH + core.memory_bytes(),
                        fixture.CODE - 32):
            with self.subTest(address=hex(address)):
                m = self.machine()
                m.map(address, 32)
                m.write_event(address=address)
                m.registry_held = True
                m.clear_events()
                m.invoke_observe(address)
                self.assertEqual(m.birth_header(), (1, 0, 0, 0))
        m = self.machine()
        address = fixture.CODE + len(m.code)
        m.map(address, 32)
        m.write_event(address=address)
        m.registry_held = True
        m.clear_events()
        m.invoke_observe(address)
        self.assertEqual(m.birth_header(), (1, 0, 0, 0))

    def test_invalid_static_addresses_capacities_and_extent_aliases_reject_before_emission(self):
        defaults = [fixture.BIRTH, fixture.CONTROLLER, fixture.REGISTRY_MUTEX,
                    fixture.CODE]
        for index, value in ((0, 0), (0, True), (0, fixture.BIRTH + 1),
                              (0, 0xFFFFFFFC), (1, 0xFFFFFFFC),
                              (2, 0xFFFFFFFC), (3, 0x10000000)):
            with self.subTest(index=index, value=value):
                args = defaults.copy()
                args[index] = value
                with self.assertRaises(ValueError):
                    core.assemble(*args)
        for capacity in (0, True, 1025, -1, 1.0):
            with self.subTest(capacity=capacity), self.assertRaises(ValueError):
                core.assemble(*defaults, capacity=capacity)
        for destination in range(4):
            for source_index in range(destination):
                with self.subTest(destination=destination, source_index=source_index):
                    args = defaults.copy()
                    args[destination] = args[source_index]
                    with self.assertRaises(ValueError):
                        core.assemble(*args)
        for index in range(4):
            with self.subTest(native_alias=index):
                args = defaults.copy()
                args[index] = 0x438000
                with self.assertRaises(ValueError):
                    core.assemble(*args)

    def test_extra_protected_data_requires_disjoint_nonwrapping_strict_word_extents(self):
        args = (fixture.BIRTH, fixture.CONTROLLER, fixture.REGISTRY_MUTEX,
                fixture.CODE)
        invalid = (None, [], (1,), ([fixture.STATE, 16],),
                   ((True, 16),), ((fixture.STATE, True),),
                   ((fixture.STATE, 0),), ((fixture.STATE, 14),),
                   ((fixture.STATE + 1, 16),), ((0xFFFFFFFC, 8),),
                   ((fixture.BIRTH, 16),), ((fixture.CONTROLLER, 4),),
                   ((fixture.REGISTRY_MUTEX, 4),), ((0x4389E0, 4),),
                   ((fixture.CODE, 4),),
                   ((fixture.STATE, 16), (fixture.STATE + 12, 16)))
        for descriptor in invalid:
            with self.subTest(descriptor=descriptor), self.assertRaises(ValueError):
                core.assemble(*args, extra_protected_data=descriptor)

    def test_protected_code_descriptor_must_contain_the_whole_callback(self):
        args = (fixture.BIRTH, fixture.CONTROLLER, fixture.REGISTRY_MUTEX,
                fixture.CODE)
        for descriptor in ((), [fixture.CODE, 0x10000],
                           (True, 0x10000), (fixture.CODE, True),
                           (fixture.CODE + 1, 0x10000), (fixture.CODE, 0),
                           (fixture.CODE, 4), (fixture.CODE + 4, 0x10000),
                           (fixture.STATE, 0x100), (0x4389E0, 0x100),
                           (fixture.CODE, 0x10000000)):
            with self.subTest(descriptor=descriptor), self.assertRaises(ValueError):
                core.assemble(*args, protected_code=descriptor)


if __name__ == '__main__':
    unittest.main()
