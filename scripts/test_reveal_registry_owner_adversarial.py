#!/usr/bin/env python3
"""Bounded failure/interleaving checks for historical owner issuance.

These are local instruction fixtures, not native scheduling, mutex lifetime,
stack authentication, producer-generation adoption or cleanup authority. Manual
issuer calls explicitly supply its trusted outer13C-held caller premise.
"""

import unittest

import reveal_paint_retirement_mips as owner
import reveal_registry_owner_mips as issue
import reveal_registry_owner_stage as stage
import reveal_registry_receipt_mips as receipt
import test_reveal_registry_owner_mips as fixture


class RegistryOwnerAdversarialTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture.RegistryOwnerTests.setUpClass()
        cls.image = fixture.RegistryOwnerTests.image

    def machine(self, **options):
        return fixture.RegistryOwnerMachine(self.image, **options)

    @staticmethod
    def clear_accesses(m):
        m.binding_accesses.clear()
        m.owner_accesses.clear()
        m.journal_accesses.clear()
        m.paint_events.clear()
        m.reads.clear()
        m.writes.clear()

    @staticmethod
    def binding_snapshot(m):
        return m.words_at(fixture.BIND_STATE,
                          issue.memory_bytes(m.capacity) // 4)

    @staticmethod
    def owner_snapshot(m):
        return m.words_at(fixture.OWNER_STATE,
                          owner.memory_bytes(m.owner_capacity) // 4)

    @staticmethod
    def binding_writes(m):
        return [(address, value, size) for address, value, size in m.writes
                if fixture.BIND_STATE <= address
                < fixture.BIND_STATE + issue.memory_bytes(m.capacity)]

    def assert_no_issuer_access(self, m):
        self.assertEqual(m.binding_accesses, [])
        self.assertEqual(m.owner_accesses, [])
        self.assertEqual(m.paint_events, [])

    def assert_schema_quarantine_only(self, m):
        self.assertEqual(self.binding_writes(m),
                         [(fixture.BIND_STATE + issue.STATUS, 0, 4),
                          (fixture.BIND_STATE + issue.QUARANTINE, 1, 4)])
        self.assertEqual(m.owner_accesses, [])
        self.assertEqual(m.paint_events, [])
        self.assertTrue(m.binding_accesses)
        self.assertTrue(all(event[-2] for event in m.binding_accesses))

    def test_raw_paint_acquisition_errors_quarantine_without_owner_access(self):
        for status in (1, 22, 0x82, fixture.MASK):
            with self.subTest(status=status):
                m = self.machine(paint_acquire_result=status)
                self.assertEqual(m.register(), 0)  # stock result still zero
                self.assertEqual(m.binding_header(), (0, 1, status, 0))
                self.assertEqual(m.binding_record(), (0,) * 12)
                self.assertEqual(m.owner_accesses, [])
                self.assertEqual(self.owner_snapshot(m), (0,) *
                                 (owner.memory_bytes(m.owner_capacity) // 4))
                self.assertEqual([(event[0], event[-1]) for event in m.paint_events],
                                 [(fixture.RAW_LOCK, status)])
                self.assertEqual(self.binding_writes(m),
                                 [(fixture.BIND_STATE + issue.STATUS, status, 4),
                                  (fixture.BIND_STATE + issue.QUARANTINE, 1, 4)])
                self.assertTrue(all(event[-2] for event in m.binding_accesses))

    def test_nonzero_paint_acquire_may_retain_guard_but_never_guesses_unlock(self):
        m = self.machine(paint_acquire_result=0x82)
        m.paint_acquire_failure_holds = True
        self.assertEqual(m.register(), 0)
        self.assertTrue(m.paint_held)
        self.assertEqual(m.binding_header(), (0, 1, 0x82, 0))
        self.assertEqual(m.owner_accesses, [])
        self.assertEqual([event[0] for event in m.paint_events], [fixture.RAW_LOCK])
        self.assertTrue(all(event[-2] for event in m.binding_accesses))
        self.assertFalse(m.registry_held)

    def test_raw_paint_unlock_errors_leave_orphan_owner_without_positive_binding(self):
        for status in (1, 22, 0x82, fixture.MASK):
            for released in (False, True):
                with self.subTest(status=status, released=released):
                    m = self.machine(paint_release_result=status)
                    m.paint_release_failure_releases = released
                    self.assertEqual(m.register(), 0)
                    self.assertEqual(m.binding_header(), (0, 1, status, 0))
                    self.assertEqual(m.binding_record(), (0,) * 12)
                    self.assertEqual(m.owner_record(), (1, fixture.ENGINE, 0, 0))
                    self.assertEqual(m.owner_header()[owner.SERIAL // 4], 1)
                    self.assertEqual(m.owner_header()[owner.OWNER_COUNT // 4], 1)
                    self.assertEqual(m.owner_header()[owner.FAULT // 4], 0)
                    self.assertEqual(m.paint_held, not released)
                    self.assertEqual([event[0] for event in m.paint_events],
                                     [fixture.RAW_LOCK, fixture.RAW_UNLOCK])
                    self.assertTrue(all(event[-2] for event in m.binding_accesses))
                    self.assertTrue(all(event[-2] and event[-1]
                                        for event in m.owner_accesses))
                    self.assertEqual(self.binding_writes(m),
                                     [(fixture.BIND_STATE + issue.STATUS, status, 4),
                                      (fixture.BIND_STATE + issue.QUARANTINE, 1, 4)])

    def test_no_owner_reads_or_writes_after_uncertain_raw_unlock(self):
        for released in (False, True):
            with self.subTest(released=released):
                m = self.machine(paint_release_result=fixture.MASK)
                m.paint_release_failure_releases = released
                access_indices = []

                def at_unlock(machine, target):
                    if target == fixture.RAW_UNLOCK and machine.r[4] == fixture.PAINT_MUTEX:
                        access_indices.append(len(machine.owner_accesses))

                m.on_service = at_unlock
                self.assertEqual(m.register(), 0)
                self.assertEqual(len(access_indices), 1)
                self.assertEqual(m.owner_accesses[access_indices[0]:], [])
                self.assertEqual(m.binding_header(), (0, 1, fixture.MASK, 0))

    def test_quarantine_prevents_reattempt_on_later_native_creation(self):
        for operation in ('acquire', 'unlock'):
            with self.subTest(operation=operation):
                m = self.machine()
                if operation == 'acquire':
                    m.paint_acquire_result = 22
                    m.paint_acquire_failure_holds = True
                else:
                    m.paint_release_result = 22
                    m.paint_release_failure_releases = False
                self.assertEqual(m.register(), 0)
                before = self.binding_snapshot(m), self.owner_snapshot(m)
                m.paint_acquire_result = m.paint_release_result = 0
                self.clear_accesses(m)
                self.assertEqual(m.register(), 0)
                self.assertEqual((self.binding_snapshot(m), self.owner_snapshot(m)), before)
                self.assertEqual(m.owner_accesses, [])
                self.assertEqual(m.paint_events, [])
                self.assertEqual([(event[0], event[2]) for event in m.binding_accesses],
                                 [('read', fixture.BIND_STATE + issue.QUARANTINE)])
                self.assertEqual(len(m.allocations), 2)
                self.assertEqual(m.header()[0], 2)

    def test_invalid_outer_acquisition_cannot_inspect_or_quarantine_corrupt_binding(self):
        for status in (1, 22, 0x82, fixture.MASK):
            with self.subTest(status=status):
                m = self.machine(acquire=status)
                m.put(fixture.BIND_STATE + issue.COUNT, fixture.MASK, 4)
                m.put(fixture.BIND_STATE + issue.RESERVED, fixture.MASK, 4)
                before = self.binding_snapshot(m)

                def ambiguously_owned(machine, target):
                    if target == fixture.RAW_LOCK and machine.r[4] == fixture.REGISTRY_MUTEX:
                        machine.registry_held = True

                m.on_service = ambiguously_owned
                self.clear_accesses(m)
                self.assertEqual(m.register(), 0)
                self.assert_no_issuer_access(m)
                self.assertEqual(self.binding_snapshot(m), before)

    def test_missing_capture_hooks_cannot_reach_owner_issuance(self):
        for name in ('begin', 'raw_call', 'raw_return'):
            with self.subTest(name=name):
                m = self.machine()
                pc = receipt.HOOKS[name][0]
                del m.patches[pc]
                del m.patches[pc + 4]
                self.assertEqual(m.register(), 0)
                self.assert_no_issuer_access(m)
                self.assertEqual(m.issue_requests, [])
                self.assertEqual(m.binding_header(), (0, 0, 0, 0))

    def test_bad_or_nonzero_publication_capture_denies_before_binding_access(self):
        variants = ((receipt.TAG, receipt.ENTERED),
                    (receipt.PTR, fixture.REGISTRY_MUTEX + 4),
                    (receipt.RAW_STATUS, 22),
                    (receipt.RAW_STATUS, fixture.MASK))
        for offset, value in variants:
            with self.subTest(offset=offset, value=value):
                m = self.machine()
                m.put(fixture.BIND_STATE + issue.COUNT, fixture.MASK, 4)
                before = self.binding_snapshot(m)
                self.clear_accesses(m)

                def mutate(machine, pc):
                    if pc == receipt.HOOKS['published'][0]:
                        machine.put(machine.r[29] + offset, value, 4)

                m.on_instruction = mutate
                self.assertEqual(m.register(), 0)
                self.assert_no_issuer_access(m)
                self.assertEqual(self.binding_snapshot(m), before)

    def test_corrupt_receipt_header_stops_before_owner_or_binding(self):
        for offset, value in ((receipt.COUNT, fixture.MASK),
                              (receipt.COUNT, 2), (receipt.RESERVED0, 1),
                              (receipt.RESERVED1, 1)):
            with self.subTest(offset=offset, value=value):
                m = self.machine()
                m.put(fixture.STATE + offset, value, 4)
                self.clear_accesses(m)
                self.assertEqual(m.register(), 0)
                self.assert_no_issuer_access(m)
                self.assertEqual(m.issue_requests, [])
                self.assertEqual(m.header()[receipt.FAULT // 4], 1)

    def test_every_dirty_receipt_target_word_stops_before_issuance(self):
        for offset in range(0, receipt.RECORD_BYTES, 4):
            with self.subTest(offset=offset):
                m = self.machine()
                m.put(fixture.STATE + receipt.HEADER_BYTES + offset, 0xBAD00000 + offset, 4)
                self.clear_accesses(m)
                self.assertEqual(m.register(), 0)
                self.assert_no_issuer_access(m)
                self.assertEqual(m.issue_requests, [])
                self.assertEqual(m.header()[receipt.FAULT // 4], 1)

    def test_corrupt_historical_receipt_prefix_stops_before_new_owner(self):
        for offset in (receipt.MAGIC, receipt.SEQUENCE, receipt.CONTROLLER,
                       receipt.MUTEX, receipt.SITE, receipt.STATUS):
            with self.subTest(offset=offset):
                m = self.machine()
                self.assertEqual(m.register(), 0)
                address = fixture.STATE + receipt.HEADER_BYTES + offset
                m.put(address, m.record()[offset // 4] ^ 1, 4)
                before = self.binding_snapshot(m), self.owner_snapshot(m)
                self.clear_accesses(m)
                self.assertEqual(m.register(), 0)
                self.assert_no_issuer_access(m)
                self.assertEqual((self.binding_snapshot(m), self.owner_snapshot(m)), before)

    def test_full_receipt_keeps_owner_state_uninspected_even_if_corrupt(self):
        m = self.machine(capacity=1)
        self.assertEqual(m.register(), 0)
        m.put(fixture.OWNER_STATE + owner.OWNER_COUNT, fixture.MASK, 4)
        before = self.binding_snapshot(m), self.owner_snapshot(m)
        self.clear_accesses(m)
        self.assertEqual(m.register(), 0)
        self.assert_no_issuer_access(m)
        self.assertEqual((self.binding_snapshot(m), self.owner_snapshot(m)), before)

    def test_binding_header_corruption_quarantines_before_owner_allocation(self):
        for offset, value in ((issue.COUNT, fixture.MASK), (issue.COUNT, 17),
                              (issue.COUNT, 2), (issue.STATUS, 22),
                              (issue.RESERVED, 1)):
            with self.subTest(offset=offset, value=value):
                m = self.machine()
                m.put(fixture.BIND_STATE + offset, value, 4)
                self.clear_accesses(m)
                self.assertEqual(m.register(), 0)
                self.assert_schema_quarantine_only(m)
                self.assertEqual(m.binding_record(), (0,) * 12)

    def test_every_dirty_binding_target_word_prevents_owner_allocation(self):
        for offset in range(0, issue.RECORD_BYTES, 4):
            with self.subTest(offset=offset):
                m = self.machine()
                m.put(fixture.BIND_STATE + issue.HEADER_BYTES + offset,
                      0xBAD10000 + offset, 4)
                original = m.binding_record()
                self.clear_accesses(m)
                self.assertEqual(m.register(), 0)
                self.assert_schema_quarantine_only(m)
                self.assertEqual(m.binding_record(), original)
                self.assertEqual(m.binding_header()[0], 0)

    def test_binding_count_rollback_cannot_overwrite_an_issued_identity(self):
        m = self.machine()
        self.assertEqual(m.register(), 0)
        original = m.binding_record()
        m.put(fixture.BIND_STATE + issue.COUNT, 0, 4)
        self.clear_accesses(m)
        self.assertEqual(m.register(), 0)
        self.assert_schema_quarantine_only(m)
        self.assertEqual(m.binding_record(), original)
        self.assertEqual(m.binding_header()[0], 0)
        self.assertEqual(m.owner_header()[owner.OWNER_COUNT // 4], 1)

    def test_corrupt_binding_prefix_denies_before_new_owner_allocation(self):
        for offset in (issue.MAGIC, issue.SEQUENCE, issue.OWNER,
                       issue.CONTROLLER, issue.REGISTRY_MUTEX, issue.SITE,
                       issue.RAW_STATUS, issue.RECEIPT_SEQUENCE):
            with self.subTest(offset=offset):
                m = self.machine()
                self.assertEqual(m.register(), 0)
                address = fixture.BIND_STATE + issue.HEADER_BYTES + offset
                value = (0 if offset in (issue.OWNER, issue.RECEIPT_SEQUENCE)
                         else m.binding_record()[offset // 4] ^ 1)
                m.put(address, value, 4)
                original = m.binding_record()
                self.clear_accesses(m)
                self.assertEqual(m.register(), 0)
                self.assert_schema_quarantine_only(m)
                self.assertEqual(m.binding_record(), original)
                self.assertEqual(m.binding_header()[0], 1)
                self.assertEqual(m.owner_header()[owner.OWNER_COUNT // 4], 1)

    def test_duplicate_or_reordered_historical_owner_and_receipt_ids_are_refused(self):
        for offset in (issue.OWNER, issue.RECEIPT_SEQUENCE):
            with self.subTest(offset=offset):
                m = self.machine()
                self.assertEqual(m.register(), 0)
                self.assertEqual(m.register(), 0)
                address = fixture.BIND_STATE + issue.HEADER_BYTES + issue.RECORD_BYTES + offset
                m.put(address, 1, 4)
                self.clear_accesses(m)
                self.assertEqual(m.register(), 0)
                self.assert_schema_quarantine_only(m)
                self.assertEqual(m.binding_header()[0], 2)
                self.assertEqual(m.owner_header()[owner.OWNER_COUNT // 4], 2)

    def test_quarantine_is_terminal_before_other_binding_header_reads(self):
        m = self.machine()
        m.put(fixture.BIND_STATE + issue.QUARANTINE, 0x12345678, 4)
        m.put(fixture.BIND_STATE + issue.COUNT, fixture.MASK, 4)
        m.put(fixture.BIND_STATE + issue.RESERVED, fixture.MASK, 4)
        before = self.binding_snapshot(m)
        self.clear_accesses(m)
        self.assertEqual(m.register(), 0)
        self.assertEqual(self.binding_snapshot(m), before)
        self.assertEqual(self.binding_writes(m), [])
        self.assertEqual(m.owner_accesses, [])
        self.assertEqual(m.paint_events, [])
        self.assertEqual([(event[0], event[2]) for event in m.binding_accesses],
                         [('read', fixture.BIND_STATE + issue.QUARANTINE)])

    def test_full_binding_table_alone_denies_before_owner_call(self):
        # Exercise the standalone trusted callback, without resetting either
        # journal or manufacturing a producer's generation from this request.
        m = self.machine(capacity=1)
        self.assertEqual(m.register(), 0)
        words = (*m.issue_requests[0][:-1], 2)
        m.write_request(words)
        before = self.binding_snapshot(m), self.owner_snapshot(m)
        self.clear_accesses(m)
        m.registry_held = True
        m.invoke_issue()
        self.assertEqual((self.binding_snapshot(m), self.owner_snapshot(m)), before)
        self.assertEqual(m.owner_accesses, [])
        self.assertEqual(m.paint_events, [])
        self.assertEqual(self.binding_writes(m), [])
        self.assertTrue(all(event[-2] for event in m.binding_accesses))

    def test_owner_ids_are_strictly_increasing_but_not_assumed_dense(self):
        m = self.machine()
        self.assertEqual(m.register(), 0)
        first = m.binding_record()
        # Explicit separate core operation, not native producer adoption.
        self.assertEqual(m.invoke_owner('open_owner', fixture.ENGINE), (2, 0))
        self.assertEqual(m.register(), 0)
        self.assertEqual(m.binding_header(), (2, 0, 0, 0))
        self.assertEqual(m.binding_record(), first)
        self.assertEqual(m.binding_record(1)[issue.OWNER // 4], 3)
        self.assertEqual(m.binding_record(1)[issue.RECEIPT_SEQUENCE // 4], 2)
        self.assertEqual(m.register(), 0)
        self.assertEqual(m.binding_header(), (3, 0, 0, 0))
        self.assertEqual(m.binding_record(2)[issue.OWNER // 4], 4)

    def test_binding_receipt_ids_can_skip_an_unissued_native_registration(self):
        m = self.machine()
        m.put(fixture.CONTROLLER + 0x148, fixture.PAINT_MUTEX + 0x100, 4)
        self.assertEqual(m.register(), 0)
        self.assertEqual(m.header()[0], 1)
        self.assertEqual(m.binding_header(), (0, 0, 0, 0))
        self.assertEqual(m.paint_events, [])
        m.put(fixture.CONTROLLER + 0x148, fixture.PAINT_MUTEX, 4)
        self.assertEqual(m.register(), 0)
        self.assertEqual(m.binding_header(), (1, 0, 0, 0))
        self.assertEqual(m.binding_record()[issue.OWNER // 4], 1)
        self.assertEqual(m.binding_record()[issue.RECEIPT_SEQUENCE // 4], 2)

    def test_historical_native_scalars_are_not_followed_as_current_objects(self):
        m = self.machine()
        self.assertEqual(m.register(), 0)
        for offset, value in ((issue.NODE, 1), (issue.ENGINE, fixture.MASK),
                              (issue.NATIVE_SP, 3), (issue.CALLER, 7)):
            m.put(fixture.BIND_STATE + issue.HEADER_BYTES + offset, value, 4)
        original = m.binding_record()
        self.clear_accesses(m)
        self.assertEqual(m.register(), 0)
        self.assertEqual(m.binding_header(), (2, 0, 0, 0))
        self.assertEqual(m.binding_record(), original)
        for address, size in m.reads:
            self.assertNotIn(address, (1, 3, 7, fixture.MASK))
        self.assertEqual(m.freed, [])

    def test_late_controller_paint_alias_change_is_denied_by_the_callee_pin(self):
        m = self.machine()
        seen = []

        def mutate(machine, pc):
            if pc == machine.owner_labels['open_owner']:
                seen.append(True)
                # Issuer has already checked U148. The actual callee must
                # refuse this change before attempting a second13C acquire.
                machine.put(fixture.CONTROLLER + 0x148, fixture.REGISTRY_MUTEX, 4)

        m.on_instruction = mutate
        self.assertEqual(m.register(), 0)
        self.assertEqual(seen, [True])
        self.assertEqual(m.paint_events, [])
        self.assertEqual([event[1] for event in m.raw_events],
                         [fixture.REGISTRY_MUTEX, fixture.REGISTRY_MUTEX])
        self.assertEqual(m.owner_accesses, [])
        self.assertEqual(m.binding_header(), (0, 0, 0, 0))
        self.assertEqual(m.binding_record(), (0,) * 12)

    def test_changed_paint_pointer_after_acquisition_does_not_retarget_release(self):
        m = self.machine()

        def mutate(machine, target):
            if target == fixture.RAW_LOCK and machine.r[4] == fixture.PAINT_MUTEX:
                machine.put(fixture.CONTROLLER + 0x148, fixture.REGISTRY_MUTEX, 4)

        m.on_service = mutate
        self.assertEqual(m.register(), 0)
        self.assertEqual([event[1] for event in m.paint_events], [fixture.PAINT_MUTEX] * 2)
        self.assertEqual(m.binding_header(), (1, 0, 0, 0))
        self.assertFalse(m.registry_held)
        self.assertFalse(m.paint_held)
        # This bounded pointer-snapshot property is not proof of the broader
        # stable-native-fields premise violated deliberately by this test.

    def test_all_shared_extents_and_full_mutex_extent_aliases_are_rejected(self):
        defaults = [fixture.STATE, fixture.BIND_STATE, fixture.OWNER_STATE,
                    fixture.CONTROLLER, fixture.REGISTRY_MUTEX, fixture.PAINT_MUTEX,
                    fixture.CODE]
        for destination in range(len(defaults)):
            for source in range(destination):
                with self.subTest(destination=destination, source=source):
                    arguments = defaults.copy()
                    arguments[destination] = arguments[source]
                    with self.assertRaises(ValueError):
                        stage.assemble(*arguments)
        for delta in (-20, -4, 0, 4, 20):
            with self.subTest(mutex_overlap=delta):
                arguments = defaults.copy()
                arguments[5] = arguments[4] + delta
                with self.assertRaises(ValueError):
                    stage.assemble(*arguments)

    def test_native_rx_aliases_and_full_composed_code_tail_alias_are_rejected(self):
        defaults = [fixture.STATE, fixture.BIND_STATE, fixture.OWNER_STATE,
                    fixture.CONTROLLER, fixture.REGISTRY_MUTEX, fixture.PAINT_MUTEX,
                    fixture.CODE]
        for index in range(len(defaults)):
            with self.subTest(native_rx=index):
                arguments = defaults.copy()
                arguments[index] = 0x438000
                with self.assertRaises(ValueError):
                    stage.assemble(*arguments)
        composition = stage.assemble(*defaults)
        defaults[0] = fixture.CODE + len(composition['code']) - 4
        with self.assertRaises(ValueError):
            stage.assemble(*defaults)

    def test_invalid_extents_capacities_and_ticket_limits_refuse_emission(self):
        defaults = [fixture.STATE, fixture.BIND_STATE, fixture.OWNER_STATE,
                    fixture.CONTROLLER, fixture.REGISTRY_MUTEX, fixture.PAINT_MUTEX,
                    fixture.CODE]
        for index in range(len(defaults)):
            for value in (0, True, defaults[index] + 1, 0xFFFFFFFC):
                with self.subTest(index=index, value=value):
                    arguments = defaults.copy()
                    arguments[index] = value
                    with self.assertRaises(ValueError):
                        stage.assemble(*arguments)
        for keyword, values in (('capacity', (0, True, 1025, -1)),
                                 ('owner_capacity', (0, True, 1025, -1)),
                                 ('ticket_limit', (0, True, 0x80000000, -1))):
            for value in values:
                with self.subTest(keyword=keyword, value=value):
                    with self.assertRaises(ValueError):
                        stage.assemble(*defaults, **{keyword: value})


if __name__ == '__main__':
    unittest.main()
