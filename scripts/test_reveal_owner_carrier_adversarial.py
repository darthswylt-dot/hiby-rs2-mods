#!/usr/bin/env python3
"""Adverse explicit-carrier checks, not native producer/lifetime admission.

Every pair used for publication is captured at the fixture's exact issuance
event. Tests never manufacture a generation by looking up the latest engine,
node, name or journal row. Raw service substitutions model ambiguous outcomes,
not real mutex scheduling, leases or permission to recover an instance.
"""

import hashlib
import unittest

import reveal_paint_retirement_mips as owner
import reveal_registry_owner_mips as bindings
import test_folderfollow_reveal_static_contract as source
import test_reveal_owner_carrier_mips as fixture


class OwnerCarrierAdversarialTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = source.SOURCE.read_bytes()
        digest = hashlib.sha256(cls.image).hexdigest()
        if digest != source.SOURCE_SHA256 or len(cls.image) != source.SOURCE_SIZE:
            raise AssertionError(f'unrecognized reference: {digest}, size {len(cls.image)}')

    def machine(self, **options):
        return fixture.RegistryCarrierMachine(self.image, **options)

    def captured(self, machine):
        self.assertEqual(machine.register(), 0)
        return machine.captured_carriers[-1]

    def payload(self, machine, captured, words=fixture.PAYLOAD):
        return machine.publish_payload(captured, words)

    def snapshot(self, machine, address, size):
        return machine.words_at(address, size // 4)

    def test_retired_old_pair_cannot_adopt_a_new_same_engine_generation(self):
        m = self.machine()
        old = self.captured(m)
        self.assertEqual(m.invoke_owner('retire', old[1]), (1, 0))
        new = self.captured(m)
        self.assertNotEqual(old, new)
        before = m.owner_state(owner.SERIAL), m.owner_state(owner.OWNER_COUNT)
        self.assertEqual(self.payload(m, old), (0, 0))
        self.assertEqual((m.owner_state(owner.SERIAL),
                          m.owner_state(owner.OWNER_COUNT)), before)
        self.assertEqual(m.count(), 0)
        nonce, index = self.payload(m, new)
        self.assertGreater(nonce, new[1])
        self.assertEqual(index, 0)
        self.assertEqual(m.binding_header(), (2, 0, 0, 0))

    def test_live_historical_pair_is_not_replaced_by_the_latest_equal_engine(self):
        m = self.machine()
        old = self.captured(m)
        first_nonce, _ = self.payload(m, old)
        new = self.captured(m)
        self.assertGreater(new[1], first_nonce)
        self.assertNotEqual(new[0], new[1])  # owner serials are not dense bindings
        self.assertGreater(self.payload(m, old)[0], new[1])
        self.assertGreater(self.payload(m, new)[0], new[1])
        self.assertEqual(m.count(), 3)
        self.assertEqual(m.owner_state(owner.OWNER_COUNT), 2)
        self.assertEqual(m.binding_header(), (2, 0, 0, 0))

    def test_sequence_owner_swaps_do_not_mint_or_quarantine(self):
        m = self.machine()
        first, second = self.captured(m), self.captured(m)
        serial = m.owner_state(owner.SERIAL)
        for pair in ((first[0], second[1]), (second[0], first[1])):
            with self.subTest(pair=pair):
                m.clear_events()
                self.assertEqual(self.payload(m, pair), (0, 0))
                self.assertEqual(m.paint_events, [])
                self.assertEqual(m.owner_accesses, [])
                self.assertEqual(m.owner_state(owner.SERIAL), serial)
                self.assertEqual(m.binding_header(), (2, 0, 0, 0))
        self.assertEqual(m.count(), 0)

    def test_unknown_zero_highbit_and_out_of_range_pairs_are_denied(self):
        m = self.machine()
        known = self.captured(m)
        for pair in ((0, known[1]), (known[0], 0), (0, 0),
                     (0x80000000, known[1]), (known[0], 0x80000000),
                     (fixture.MASK, fixture.MASK), (2, known[1]),
                     (known[0], known[1] + 1)):
            with self.subTest(pair=pair):
                m.clear_events()
                self.assertEqual(self.payload(m, pair), (0, 0))
                self.assertEqual(m.paint_events, [])
                self.assertEqual(m.owner_accesses, [])
                self.assertEqual(m.binding_header(), (1, 0, 0, 0))

    def test_equal_pair_with_different_payload_engine_is_a_normal_denial(self):
        m = self.machine()
        captured = self.captured(m)
        changed = list(fixture.PAYLOAD)
        changed[2] ^= 4
        m.clear_events()
        self.assertEqual(self.payload(m, captured, changed), (0, 0))
        self.assertEqual(m.paint_events, [])
        self.assertEqual(m.owner_accesses, [])
        self.assertEqual(m.binding_header(), (1, 0, 0, 0))

    def test_second_append_index_one_is_success_not_a_raw_error(self):
        m = self.machine()
        captured = self.captured(m)
        first = self.payload(m, captured)
        second = self.payload(m, captured)
        self.assertGreater(second[0], first[0])
        self.assertEqual((first[1], second[1]), (0, 1))
        self.assertEqual(m.binding_header(), (1, 0, 0, 0))
        self.assertEqual(m.count(), 2)

    def test_full_binding_and_owner_tables_still_allow_an_existing_live_pair(self):
        m = self.machine(capacity=1, owner_capacity=1)
        captured = self.captured(m)
        self.assertEqual(m.binding_header()[0], 1)
        self.assertEqual(m.owner_state(owner.OWNER_COUNT), 1)
        self.assertGreater(self.payload(m, captured)[0], captured[1])
        self.assertEqual(m.binding_header(), (1, 0, 0, 0))
        self.assertEqual(m.owner_state(owner.OWNER_COUNT), 1)

    def test_closed_owner_kernel_is_a_normal_denial_without_remint_or_binding_quarantine(self):
        m = self.machine()
        captured = self.captured(m)
        self.assertEqual(m.invoke_owner('close')[0], 0)
        serial = m.owner_state(owner.SERIAL)
        self.assertEqual(self.payload(m, captured), (0, 0))
        self.assertEqual(m.owner_state(owner.SERIAL), serial)
        self.assertEqual(m.owner_state(owner.OWNER_COUNT), 1)
        self.assertEqual(m.binding_header(), (1, 0, 0, 0))

    def test_full_queue_denies_without_burning_nonce_or_quarantining_bindings(self):
        m = self.machine(queue_capacity=1)
        captured = self.captured(m)
        nonce, _ = self.payload(m, captured)
        self.assertGreater(nonce, 0)
        self.assertEqual(self.payload(m, captured), (0, 0))
        self.assertEqual(m.count(), 1)
        self.assertEqual(m.owner_state(owner.SERIAL), nonce)
        self.assertEqual(m.binding_header(), (1, 0, 0, 0))
        self.assertEqual(m.claim(), (fixture.OWNER_STATE + owner.COPY, nonce))
        self.assertEqual(m.complete(nonce), (1, 0))
        self.assertEqual(self.payload(m, captured), (nonce + 1, 0))

    def test_serial_exhaustion_faults_owner_without_minting_or_binding_quarantine(self):
        m = self.machine(ticket_limit=1)
        captured = self.captured(m)
        self.assertEqual(self.payload(m, captured), (0, 0))
        self.assertEqual(m.owner_state(owner.SERIAL), 1)
        self.assertEqual(m.owner_state(owner.OWNER_COUNT), 1)
        self.assertEqual(m.owner_state(owner.FAULT), 1)
        self.assertEqual(m.binding_header(), (1, 0, 0, 0))
        self.assertEqual(m.count(), 0)

    def test_retired_active_old_ack_cannot_remove_a_new_same_engine_publication(self):
        m = self.machine()
        old = self.captured(m)
        old_nonce, _ = self.payload(m, old)
        self.assertEqual(m.claim(), (fixture.OWNER_STATE + owner.COPY, old_nonce))
        self.assertEqual(m.retire(old[1]), (1, 0))
        new = self.captured(m)
        self.assertEqual(self.payload(m, old), (0, 0))
        new_nonce, index = self.payload(m, new)
        self.assertEqual(index, 1)
        self.assertGreater(new_nonce, old_nonce)
        self.assertEqual(m.complete(old_nonce), (3, 0))
        self.assertEqual(m.complete(old_nonce), (0, 0))
        self.assertEqual(m.count(), 1)
        self.assertEqual(m.words_at(m.head() + owner.NONCE, 2), (new_nonce, new[1]))
        self.assertEqual(m.claim(), (fixture.OWNER_STATE + owner.COPY, new_nonce))
        self.assertEqual(m.complete(new_nonce), (1, 0))

    def test_raw_registry_acquire_errors_never_access_binding_or_owner_state(self):
        for status in (1, 22, 0x82, fixture.MASK):
            for may_hold in (False, True):
                with self.subTest(status=status, may_hold=may_hold):
                    m = self.machine()
                    captured = self.captured(m)
                    before = m.binding_header(), m.owner_header()
                    m.acquire = status

                    def ambiguous(machine, target):
                        if (target == fixture.RAW_LOCK
                                and machine.r[4] == fixture.REGISTRY_MUTEX):
                            machine.registry_held = may_hold

                    m.on_service = ambiguous
                    m.clear_events()
                    self.assertEqual(self.payload(m, captured), (0, status))
                    self.assertEqual(m.binding_accesses, [])
                    self.assertEqual(m.owner_accesses, [])
                    self.assertEqual(m.paint_events, [])
                    self.assertEqual(m.binding_header(), before[0])
                    self.assertEqual(m.owner_header(), before[1])
                    self.assertEqual([(e[0], e[1]) for e in m.raw_events],
                                     [(fixture.RAW_LOCK, fixture.REGISTRY_MUTEX)])
                    self.assertEqual(m.registry_held, may_hold)

    def test_raw_registry_release_error_cannot_rollback_an_already_appended_record(self):
        for status in (1, 22, fixture.MASK):
            with self.subTest(status=status):
                m = self.machine()
                captured = self.captured(m)
                m.release = status
                boundaries = {}

                def at_service(machine, target):
                    if target == fixture.RAW_UNLOCK and machine.r[4] == fixture.REGISTRY_MUTEX:
                        boundaries['binding_end'] = len(machine.binding_accesses)
                        boundaries['owner_end'] = len(machine.owner_accesses)

                m.on_service = at_service
                m.clear_events()
                self.assertEqual(self.payload(m, captured), (0, status))
                self.assertEqual(m.count(), 1)
                self.assertEqual(m.binding_header(), (1, 0, 0, 0))
                self.assertEqual(len(m.binding_accesses), boundaries['binding_end'])
                self.assertEqual(len(m.owner_accesses), boundaries['owner_end'])
                self.assertEqual(m.owner_state(owner.OWNER_COUNT), 1)
                # No persistent post-R-error write is permitted. The caller
                # must externally isolate this ambiguous instance, not retry.

    def test_raw_paint_acquire_errors_quarantine_only_bindings_under_registry_guard(self):
        for status in (1, 22, 0x82, fixture.MASK):
            for may_hold in (False, True):
                with self.subTest(status=status, may_hold=may_hold):
                    m = self.machine()
                    captured = self.captured(m)
                    m.paint_acquire_result = status
                    m.paint_acquire_failure_holds = may_hold
                    m.clear_events()
                    self.assertEqual(self.payload(m, captured), (0, status))
                    self.assertEqual(m.owner_accesses, [])
                    self.assertEqual(m.binding_header(), (1, 1, status, 0))
                    self.assertTrue(all(event[-2] for event in m.binding_accesses))
                    self.assertEqual([(e[0], e[1]) for e in m.raw_events],
                                     [(fixture.RAW_LOCK, fixture.REGISTRY_MUTEX),
                                      (fixture.RAW_LOCK, fixture.PAINT_MUTEX),
                                      (fixture.RAW_UNLOCK, fixture.REGISTRY_MUTEX)])
                    self.assertEqual(m.paint_held, may_hold)

    def test_raw_paint_release_errors_preserve_partial_append_and_end_owner_access(self):
        for status in (1, 22, fixture.MASK):
            for releases in (False, True):
                with self.subTest(status=status, releases=releases):
                    m = self.machine()
                    captured = self.captured(m)
                    m.paint_release_result = status
                    m.paint_release_failure_releases = releases
                    boundaries = {}

                    def at_service(machine, target):
                        if target == fixture.RAW_UNLOCK and machine.r[4] == fixture.PAINT_MUTEX:
                            boundaries['owner_end'] = len(machine.owner_accesses)

                    m.on_service = at_service
                    m.clear_events()
                    self.assertEqual(self.payload(m, captured), (0, status))
                    self.assertEqual(m.count(), 1)
                    self.assertEqual(len(m.owner_accesses), boundaries['owner_end'])
                    self.assertEqual(m.binding_header(), (1, 1, status, 0))
                    self.assertEqual(m.paint_held, not releases)
                    self.assertTrue(all(event[-2] for event in m.binding_accesses))
                    self.assertTrue(all(event[-2] and event[-1] for event in m.owner_accesses))

    def test_existing_quarantine_refuses_before_other_schema_reads_or_nested_lock(self):
        m = self.machine()
        captured = self.captured(m)
        m.put(fixture.BIND_STATE + bindings.QUARANTINE, 1, 4)
        m.put(fixture.BIND_STATE + bindings.STATUS, 0x82, 4)
        m.put(fixture.BIND_STATE + bindings.COUNT, fixture.MASK, 4)
        m.put(fixture.BIND_STATE + bindings.RESERVED, fixture.MASK, 4)
        before = m.binding_header()
        m.clear_events()
        self.assertEqual(self.payload(m, captured), (0, 0x82))
        self.assertEqual(m.binding_header(), before)
        self.assertEqual(m.paint_events, [])
        self.assertEqual(m.owner_accesses, [])
        self.assertEqual([(event[0], event[2]) for event in m.binding_accesses],
                         [('read', fixture.BIND_STATE + bindings.QUARANTINE),
                          ('read', fixture.BIND_STATE + bindings.STATUS)])

    def test_malformed_binding_header_quarantines_before_owner_call(self):
        for offset, value in ((bindings.COUNT, fixture.MASK),
                              (bindings.STATUS, 22), (bindings.RESERVED, 1)):
            with self.subTest(offset=offset):
                m = self.machine()
                captured = self.captured(m)
                m.put(fixture.BIND_STATE + offset, value, 4)
                m.clear_events()
                self.assertEqual(self.payload(m, captured), (0, 0))
                self.assertEqual(m.binding_header()[1:3], (1, 0))
                self.assertEqual(m.paint_events, [])
                self.assertEqual(m.owner_accesses, [])
                self.assertTrue(all(event[-2] for event in m.binding_accesses))

    def test_corruption_anywhere_in_binding_prefix_denies_even_a_matching_first_pair(self):
        for offset in (bindings.MAGIC, bindings.SEQUENCE, bindings.OWNER,
                       bindings.CONTROLLER, bindings.REGISTRY_MUTEX,
                       bindings.SITE, bindings.RAW_STATUS, bindings.RECEIPT_SEQUENCE):
            with self.subTest(offset=offset):
                m = self.machine()
                first = self.captured(m)
                self.captured(m)
                address = (fixture.BIND_STATE + bindings.HEADER_BYTES
                           + bindings.RECORD_BYTES + offset)
                original = m.words_at(address, 1)[0]
                invalid = (1 if offset in (bindings.OWNER, bindings.RECEIPT_SEQUENCE)
                           else original ^ 1)
                m.put(address, invalid, 4)
                m.clear_events()
                self.assertEqual(self.payload(m, first), (0, 0))
                self.assertEqual(m.paint_events, [])
                self.assertEqual(m.owner_accesses, [])
                self.assertEqual(m.binding_header()[1:3], (1, 0))

    def test_rolled_back_binding_count_cannot_hide_an_already_issued_tail(self):
        for count in (0, 1):
            with self.subTest(count=count):
                m = self.machine()
                first = self.captured(m)
                self.captured(m)
                serial = m.owner_state(owner.SERIAL)
                m.put(fixture.BIND_STATE + bindings.COUNT, count, 4)
                m.clear_events()
                self.assertEqual(self.payload(m, first), (0, 0))
                self.assertEqual(m.binding_header(), (count, 1, 0, 0))
                self.assertEqual(m.paint_events, [])
                self.assertEqual(m.owner_accesses, [])
                self.assertEqual(m.owner_state(owner.SERIAL), serial)

    def test_each_dirty_next_unissued_slot_word_quarantines_before_publication(self):
        for offset in range(0, bindings.RECORD_BYTES, 4):
            with self.subTest(offset=offset):
                m = self.machine()
                captured = self.captured(m)
                address = (fixture.BIND_STATE + bindings.HEADER_BYTES
                           + bindings.RECORD_BYTES + offset)
                m.put(address, 1, 4)
                m.clear_events()
                self.assertEqual(self.payload(m, captured), (0, 0))
                self.assertEqual(m.binding_header(), (1, 1, 0, 0))
                self.assertEqual(m.paint_events, [])
                self.assertEqual(m.owner_accesses, [])

    def test_owned_payload_snapshot_precedes_hostile_raw_registry_call(self):
        m = self.machine()
        captured = self.captured(m)
        changed = tuple(word ^ fixture.MASK for word in fixture.PAYLOAD)

        def mutate(machine, target):
            if target == fixture.RAW_LOCK and machine.r[4] == fixture.REGISTRY_MUTEX:
                for index, word in enumerate(changed):
                    machine.put(fixture.OWNED_INPUT + index * 4, word, 4)

        m.on_service = mutate
        nonce, index = self.payload(m, captured)
        self.assertGreater(nonce, 0)
        self.assertEqual(index, 0)
        self.assertEqual(m.words_at(m.queue_element(), 9), fixture.PAYLOAD)

    def test_input_aliases_and_malformed_extents_deny_before_shared_state_or_raw_call(self):
        m = self.machine()
        captured = self.captured(m)
        sources = (0, 1, fixture.MASK - 3, fixture.BIND_STATE,
                   fixture.OWNER_STATE, fixture.CONTROLLER,
                   fixture.REGISTRY_MUTEX, fixture.PAINT_MUTEX,
                   fixture.CODE,
                   fixture.CODE + m.composition['creation_code_bytes'] - 4,
                   fixture.CODE + len(m.code) - 4)
        for pointer in sources:
            with self.subTest(pointer=hex(pointer)):
                m.clear_events()
                self.assertEqual(m.invoke_adapter(pointer, *captured), (0, 0))
                self.assertEqual(m.raw_events, [])
                self.assertEqual(m.binding_accesses, [])
                self.assertEqual(m.owner_accesses, [])

    def test_late_paint_pointer_change_before_kernel_is_denied_before_nested_acquire(self):
        m = self.machine()
        captured = self.captured(m)

        def mutate(machine, pc):
            if pc == machine.owner_labels['publish']:
                machine.put(fixture.CONTROLLER + 0x148, fixture.REGISTRY_MUTEX, 4)

        m.on_instruction = mutate
        m.clear_events()
        self.assertEqual(self.payload(m, captured), (0, 0))
        self.assertEqual(m.paint_events, [])
        self.assertEqual(m.owner_accesses, [])
        self.assertEqual(m.binding_header(), (1, 0, 0, 0))

    def test_paint_pointer_change_after_raw_acquire_cannot_retarget_unlock(self):
        m = self.machine()
        captured = self.captured(m)

        def mutate(machine, target):
            if target == fixture.RAW_LOCK and machine.r[4] == fixture.PAINT_MUTEX:
                machine.put(fixture.CONTROLLER + 0x148, fixture.REGISTRY_MUTEX, 4)

        m.on_service = mutate
        m.clear_events()
        self.assertGreater(self.payload(m, captured)[0], 0)
        self.assertEqual([event[1] for event in m.paint_events],
                         [fixture.PAINT_MUTEX, fixture.PAINT_MUTEX])
        self.assertFalse(m.paint_held)
        self.assertFalse(m.registry_held)

    def test_faulted_owner_state_is_normal_denial_without_binding_quarantine_or_remint(self):
        m = self.machine()
        captured = self.captured(m)
        m.put(fixture.OWNER_STATE + owner.FAULT, 1, 4)
        serial = m.owner_state(owner.SERIAL)
        self.assertEqual(self.payload(m, captured), (0, 0))
        self.assertEqual(m.binding_header(), (1, 0, 0, 0))
        self.assertEqual(m.owner_state(owner.SERIAL), serial)
        self.assertEqual(m.owner_state(owner.OWNER_COUNT), 1)


if __name__ == '__main__':
    unittest.main()
