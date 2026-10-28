#!/usr/bin/env python3
"""Refuse malformed field-correlated history without authorizing native free."""

import unittest

import reveal_registry_lifecycle_mips as core
import test_reveal_registry_lifecycle_mips as fixture
from test_reveal_registry_lifecycle_mips import (
    RegistryLifecycleMachine, LIFECYCLE, EVENT,
    ENGINE, NAME, CONTROLLER, REGISTRY_MUTEX, PAINT_MUTEX, CODE,
    STACK, RETURN, MASK)


class RegistryLifecycleAdversarialTests(unittest.TestCase):
    setUpClass = classmethod(fixture.RegistryLifecycleTests.setUpClass.__func__)

    def machine(self, **options):
        return RegistryLifecycleMachine(self.image, **options)

    def direct_birth(self, m, *, node=1, engine=ENGINE):
        m.write_event(node=node, engine=engine)
        m.registry_held = True
        m.invoke_observe()

    def direct_retirement(self, m, *, node=1, engine=ENGINE, site=0x439618):
        m.write_event(node=node, engine=engine, site=site)
        m.registry_held = True
        m.invoke_observe('retirement')

    def test_duplicate_outstanding_node_birth_permanently_faults(self):
        for engine in (ENGINE, ENGINE + 4):
            m = self.machine()
            self.direct_birth(m)
            first = m.lifecycle_record()
            self.direct_birth(m, engine=engine)
            self.assertEqual(m.lifecycle_header(), (1, 1, 0, 0))
            self.assertEqual(m.lifecycle_record(), first)
            self.direct_retirement(m)
            self.assertEqual(m.lifecycle_record(), first)

    def test_missing_or_engine_mismatched_retirement_faults_without_row_retag(self):
        for node, engine in ((2, ENGINE), (1, ENGINE + 4)):
            with self.subTest(node=node, engine=engine):
                m = self.machine()
                self.direct_birth(m)
                first = m.lifecycle_record()
                self.direct_retirement(m, node=node, engine=engine)
                self.assertEqual(m.lifecycle_header(), (1, 1, 0, 0))
                self.assertEqual(m.lifecycle_record(), first)

    def test_duplicate_retirement_never_revives_or_rewrites_terminal_record(self):
        m = self.machine()
        self.direct_birth(m)
        self.direct_retirement(m)
        terminal = m.lifecycle_record()
        self.direct_retirement(m, site=0x43CBB0)
        self.assertEqual(m.lifecycle_header(), (1, 1, 0, 0))
        self.assertEqual(m.lifecycle_record(), terminal)

    def test_reused_terminal_node_does_not_borrow_earlier_row(self):
        m = self.machine()
        self.direct_birth(m)
        self.direct_retirement(m)
        terminal = m.lifecycle_record()
        self.direct_birth(m)
        second = m.lifecycle_record(1)
        self.direct_retirement(m, site=0x43CBB0)
        self.assertEqual(m.lifecycle_record(), terminal)
        self.assertEqual(m.lifecycle_record(1)[:10], second[:10])
        self.assertEqual(m.lifecycle_record(1)[10:12], (2, 0x43CBB0))
        self.assertEqual(m.lifecycle_header(), (2, 0, 0, 0))

    def test_full_birth_faults_permanently_but_native_allocation_still_succeeds(self):
        m = self.machine(lifecycle_capacity=1)
        self.assertEqual(m.register(), 0)
        first = m.lifecycle_record()
        self.assertEqual(m.register(), 0)
        self.assertEqual(m.lifecycle_header(), (1, 1, 0, 0))
        self.assertEqual(m.lifecycle_record(), first)
        self.assertEqual(len(m.allocations), 2)

    def test_malformed_occupied_prefix_faults_without_appending(self):
        mutations = (
            (core.MAGIC, 0), (core.TOKEN, 2), (core.CONTROLLER, CONTROLLER + 4),
            (core.MUTEX, REGISTRY_MUTEX + 4), (core.SITE, 0x439618),
            (core.STATUS, 22), (core.STATE, 0), (core.STATE, 3),
            (core.RETIREMENT_SITE, 0x439618), (core.RETIREMENT_SP, 1),
            (core.RETIREMENT_CALLER, 1), (core.RESERVED2, 1),
            (core.RESERVED3, MASK))
        for offset, value in mutations:
            for operation in ('birth', 'retirement'):
                with self.subTest(offset=offset, value=value, operation=operation):
                    m = self.machine()
                    self.direct_birth(m)
                    m.put(LIFECYCLE + core.HEADER_BYTES + offset, value, 4)
                    before = m.lifecycle_record()
                    m.write_event(node=2, site=0x438A5C if operation == 'birth'
                                  else 0x439618)
                    m.invoke_observe(operation)
                    self.assertEqual(m.lifecycle_header(), (1, 1, 0, 0))
                    self.assertEqual(m.lifecycle_record(), before)
                    self.assertEqual(m.lifecycle_record(1), (0,) * 16)

    def test_corrupt_terminal_schema_is_not_promoted_back_to_outstanding(self):
        for offset, value in ((core.RETIREMENT_SITE, 0),
                              (core.RETIREMENT_SITE, 0x438A5C),
                              (core.RESERVED3, 1)):
            m = self.machine()
            self.direct_birth(m)
            self.direct_retirement(m)
            m.put(LIFECYCLE + core.HEADER_BYTES + offset, value, 4)
            terminal = m.lifecycle_record()
            self.direct_birth(m, node=2)
            self.assertEqual(m.lifecycle_header(), (1, 1, 0, 0))
            self.assertEqual(m.lifecycle_record(), terminal)

    def test_header_count_and_reserved_corruption_fault_before_row_dereference(self):
        for offset, value in ((core.COUNT, 17), (core.COUNT, MASK),
                              (core.RESERVED0, 1), (core.RESERVED1, MASK)):
            m = self.machine()
            m.put(LIFECYCLE + offset, value, 4)
            m.write_event()
            m.registry_held = True
            m.clear_events()
            m.invoke_observe()
            self.assertEqual(m.lifecycle_header()[1], 1)
            self.assertFalse(any(event[2] >= LIFECYCLE + core.HEADER_BYTES
                                 for event in m.lifecycle_accesses))

    def test_nonzero_word_anywhere_in_unused_tail_faults(self):
        for index in (0, 1, 15):
            for word in (0, 10, 15):
                with self.subTest(index=index, word=word):
                    m = self.machine()
                    address = LIFECYCLE + core.HEADER_BYTES + index * 64 + word * 4
                    m.put(address, 0xD1A70000, 4)
                    self.direct_birth(m)
                    self.assertEqual(m.lifecycle_header(), (0, 1, 0, 0))
                    self.assertEqual(m.peek(address), 0xD1A70000)

    def test_global_outstanding_node_collision_is_detected_for_unrelated_event(self):
        m = self.machine()
        self.direct_birth(m, node=1)
        self.direct_birth(m, node=2)
        m.put(LIFECYCLE + core.HEADER_BYTES + 64 + core.NODE, 1, 4)
        before = m.lifecycle_record(), m.lifecycle_record(1)
        self.direct_birth(m, node=3)
        self.assertEqual(m.lifecycle_header(), (2, 1, 0, 0))
        self.assertEqual((m.lifecycle_record(), m.lifecycle_record(1)), before)

    def test_faulted_history_denies_without_reading_rows_or_repairing_header(self):
        m = self.machine()
        m.put(LIFECYCLE + core.FAULT, 0x82, 4)
        m.write_event()
        m.registry_held = True
        m.clear_events()
        m.invoke_observe()
        self.assertEqual(m.lifecycle_header(), (0, 0x82, 0, 0))
        self.assertEqual(m.lifecycle_accesses,
                         [('read', m.lifecycle_accesses[0][1],
                           LIFECYCLE + core.FAULT, 4, True, False)])

    def test_bad_event_schema_refuses_before_history_admission(self):
        for kind in ('birth', 'retirement'):
            for offset, value in ((core.REQUEST_CONTROLLER, CONTROLLER + 4),
                                  (core.REQUEST_REGISTRY_MUTEX, REGISTRY_MUTEX + 4),
                                  (core.REQUEST_RAW_STATUS, 22),
                                  (core.REQUEST_SITE, 0),
                                  (core.REQUEST_SITE, 0x43961C)):
                with self.subTest(kind=kind, offset=offset):
                    m = self.machine()
                    m.write_event(site=0x438A5C if kind == 'birth' else 0x439618)
                    m.put(EVENT + offset, value, 4)
                    m.registry_held = True
                    m.clear_events()
                    m.invoke_observe(kind)
                    self.assertEqual(m.lifecycle_accesses, [])
                    self.assertEqual(m.lifecycle_header(), (0, 0, 0, 0))

    def test_foreign_controller_and_unpinned_native_fingerprints_deny_history(self):
        for offset, value in ((0x13C, REGISTRY_MUTEX + 4),
                              (0x274, 0x437CE0), (0x278, 0x437D60)):
            m = self.machine()
            m.write_event()
            m.put(CONTROLLER + offset, value, 4)
            m.registry_held = True
            m.clear_events()
            m.invoke_observe()
            self.assertEqual(m.lifecycle_accesses, [])
        m = self.machine()
        m.write_event()
        m.clear_events()
        m.invoke_observe(controller=CONTROLLER + 4)
        self.assertEqual(m.lifecycle_accesses, [])

    def test_invalid_or_protected_event_extent_is_not_dereferenced(self):
        m = self.machine()
        for pointer in (0, EVENT + 1, 0xFFFFFFF0, LIFECYCLE,
                        LIFECYCLE + core.memory_bytes() - 4, CONTROLLER,
                        REGISTRY_MUTEX, PAINT_MUTEX, CODE, 0x400000,
                        STACK - core.FRAME, STACK - 4):
            with self.subTest(pointer=hex(pointer)):
                m.clear_events()
                m.invoke_observe(event=pointer)
                self.assertEqual(m.lifecycle_accesses, [])
                self.assertFalse(any(pointer <= address < pointer + 32
                                     for address, _ in m.reads
                                     if not STACK - core.FRAME <= address < STACK))

    def test_opaque_historical_event_scalars_are_not_dereferenced(self):
        m = self.machine()
        event = (CONTROLLER, REGISTRY_MUTEX, 1, MASK, 3, 7, 0x438A5C, 0)
        m.write_event(event)
        m.registry_held = True
        m.clear_events()
        m.invoke_observe()
        self.assertEqual(m.lifecycle_record()[2:10], event)
        self.assertFalse(any(address in (1, 3, 7, MASK) for address, _ in m.reads))
        self.assertEqual(m.calls, [])

    def test_birth_magic_then_count_and_retirement_state_are_final_commit_stores(self):
        m = self.machine()
        m.write_event()
        m.registry_held = True
        m.clear_events()
        m.invoke_observe()
        writes = [(address, value) for address, value, _ in m.writes
                  if LIFECYCLE <= address < LIFECYCLE + core.memory_bytes()]
        self.assertEqual(writes[-2:],
                         [(LIFECYCLE + core.HEADER_BYTES, core.RECORD_MAGIC),
                          (LIFECYCLE, 1)])
        m.write_event(site=0x439618)
        m.clear_events()
        m.invoke_observe('retirement')
        writes = [(address, value) for address, value, _ in m.writes
                  if LIFECYCLE <= address < LIFECYCLE + core.memory_bytes()]
        self.assertEqual(writes[-1],
                         (LIFECYCLE + core.HEADER_BYTES + core.STATE, 2))
        self.assertEqual(len(writes), 4)

    def test_missed_raw_failure_delete_does_not_turn_healthy_old_row_into_liveness(self):
        m = self.machine()
        self.assertEqual(m.register(), 0)
        node = m.allocations[0]
        before = m.lifecycle_record()
        m.acquire = 22
        m.delete_native()
        self.assertEqual(m.lifecycle_record(), before)
        self.assertEqual(m.lifecycle_header(), (1, 0, 0, 0))
        self.assertEqual(m.words_at(CONTROLLER + 0x34, 2), (CONTROLLER + 0x34,) * 2)
        # Healthy NO_RETIREMENT_OBSERVED survives a real native unlink, because
        # observing unsafe masked acquisition cannot authorize a shared write.
        self.assertIn(node, m.freed)

    def test_unobserved_same_address_rebirth_can_correlate_the_wrong_old_birth(self):
        m = self.machine(capacity=1)
        self.assertEqual(m.register(), 0)
        node = m.allocations[0]
        old_birth = m.lifecycle_record()
        m.acquire = 22
        m.delete_native()
        m.reuse_node = node
        self.assertEqual(m.register(), 0)  # Native masks22 and republishes.
        self.assertEqual(m.lifecycle_record(), old_birth)
        self.assertEqual(m.lifecycle_header(), (1, 0, 0, 0))
        m.acquire = 0
        m.clear_events()
        m.delete_native()
        self.assertEqual(m.lifecycle_record()[:10], old_birth[:10])
        self.assertEqual(m.lifecycle_record()[10:12], (2, 0x439618))
        self.assertEqual(m.lifecycle_header(), (1, 0, 0, 0))
        # Deliberate executable counterexample: these fields are not a true
        # incarnation certificate, even though all admitted accesses held R.
        self.assertTrue(all(event[-2] for event in m.lifecycle_accesses))


if __name__ == '__main__':
    unittest.main()
