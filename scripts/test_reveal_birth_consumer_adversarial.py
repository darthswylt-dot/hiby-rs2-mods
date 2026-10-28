#!/usr/bin/env python3
"""Deny malformed history and uncertain raw results without recovery authority.

Error branches deliberately consume an already-extracted queue item. Neither
possible lock ownership outcome permits retry, rollback or guessed unlocking.
"""

import unittest

import reveal_birth_queue_mips as queue
import reveal_registry_lifecycle_mips as lifecycle
import test_reveal_birth_consumer_mips as fixture
from test_reveal_birth_consumer_mips import (
    BirthConsumerMachine, OUTPUT, OUTPUT_BYTES,
    QUEUE, TRANSPORT_MUTEX, FAULT, SOURCE, LIFECYCLE, ENGINE, CONTROLLER,
    REGISTRY_MUTEX, PAINT_MUTEX, CODE, INPUT, STATE, BIND_STATE, OWNER_STATE,
    RAW_LOCK, RAW_UNLOCK, STACK, RETURN, MASK, GET, REMOVE)


class BirthConsumerAdversarialTests(unittest.TestCase):
    setUpClass = classmethod(fixture.BirthConsumerTests.setUpClass.__func__)
    prepared, queued = (fixture.BirthConsumerTests.prepared,
                        fixture.BirthConsumerTests.queued)

    def machine(self, **options):
        return BirthConsumerMachine(self.image, **options)

    def boundary(self, machine):
        return tuple(len(getattr(machine, name)) for name in (
            'transport_accesses', 'consumer_output_accesses', 'journal_accesses',
            'binding_accesses', 'owner_accesses', 'consumer_history_accesses', 'calls'))

    def assert_denied(self, machine):
        before = machine.lifecycle_snapshot()
        machine.clear_events()
        self.assertEqual(machine.take(), (0, 0))
        self.assertEqual(machine.consumer_words(), (0,) * 25)
        self.assertEqual(machine.generated_output_writes(), [])
        self.assertEqual(machine.lifecycle_snapshot(), before)
        self.assertFalse(any(event[0] == 'write'
                             for event in machine.consumer_history_accesses))
        self.assertEqual(machine.transport_count(), 0)

    def test_transport_acquire_error_returns_without_registry_or_output_access(self):
        for status in (1, 22, 0x82, MASK):
            for held in (False, True):
                with self.subTest(status=status, held=held):
                    m = self.machine()
                    self.queued(m)
                    m.transport_acquire = status
                    m.transport_acquire_failure_holds = held
                    boundaries = []

                    def observe(machine, target):
                        if target == RAW_LOCK and machine.r[4] == TRANSPORT_MUTEX:
                            boundaries.append(self.boundary(machine))

                    m.on_service = observe
                    m.clear_events()
                    self.assertEqual(m.take(), (0, status))
                    self.assertEqual(boundaries, [self.boundary(m)])
                    self.assertEqual(m.consumer_history_accesses, [])
                    self.assertEqual(m.transport_accesses, [])
                    self.assertEqual(m.transport_count(), 1)
                    self.assertEqual(m.transport_held, held)
                    self.assertEqual([(event[0], event[1]) for event in m.raw_events],
                                     [(RAW_LOCK, TRANSPORT_MUTEX)])

    def test_transport_release_error_never_enters_registry_or_retries_removed_item(self):
        for status in (1, 22, 0x82, MASK):
            for released in (False, True):
                with self.subTest(status=status, released=released):
                    m = self.machine()
                    self.queued(m)
                    m.transport_release = status
                    m.transport_release_failure_releases = released
                    boundaries = []

                    def observe(machine, target):
                        if target == RAW_UNLOCK and machine.r[4] == TRANSPORT_MUTEX:
                            boundaries.append(self.boundary(machine))

                    m.on_service = observe
                    m.clear_events()
                    self.assertEqual(m.take(), (0, status))
                    self.assertEqual(boundaries, [self.boundary(m)])
                    self.assertEqual(m.transport_count(), 0)
                    self.assertEqual(m.consumer_history_accesses, [])
                    self.assertEqual(m.consumer_words(), (0,) * 25)
                    self.assertEqual(m.transport_held, not released)
                    self.assertEqual([(event[0], event[1]) for event in m.raw_events], [
                        (RAW_LOCK, TRANSPORT_MUTEX), (RAW_UNLOCK, TRANSPORT_MUTEX)])

    def test_registry_acquire_error_never_reads_history_or_guesses_unlock(self):
        for status in (1, 22, 0x82, MASK):
            for held in (False, True):
                with self.subTest(status=status, held=held):
                    m = self.machine()
                    self.queued(m)
                    m.acquire, m.registry_acquire_failure_holds = status, held
                    boundaries = []

                    def observe(machine, target):
                        if target == RAW_LOCK and machine.r[4] == REGISTRY_MUTEX:
                            boundaries.append(self.boundary(machine))

                    m.on_service = observe
                    m.clear_events()
                    self.assertEqual(m.take(), (0, status))
                    self.assertEqual(boundaries, [self.boundary(m)])
                    self.assertEqual(m.consumer_history_accesses, [])
                    self.assertEqual(m.consumer_words(), (0,) * 25)
                    self.assertEqual(m.transport_count(), 0)
                    self.assertEqual(m.registry_held, held)
                    self.assertEqual([(event[0], event[1]) for event in m.raw_events], [
                        (RAW_LOCK, TRANSPORT_MUTEX), (RAW_UNLOCK, TRANSPORT_MUTEX),
                        (RAW_LOCK, REGISTRY_MUTEX)])

    def test_registry_release_error_has_no_late_access_or_export_or_fault_write(self):
        for status in (1, 22, 0x82, MASK):
            for released in (False, True):
                with self.subTest(status=status, released=released):
                    m = self.machine()
                    self.queued(m)
                    before = m.lifecycle_snapshot()
                    m.release, m.registry_release_failure_releases = status, released
                    boundaries = []

                    def observe(machine, target):
                        if target == RAW_UNLOCK and machine.r[4] == REGISTRY_MUTEX:
                            machine.put(OUTPUT + 96, 0xD1700096, 4)
                            boundaries.append(self.boundary(machine))

                    m.on_service = observe
                    m.clear_events()
                    self.assertEqual(m.take(), (0, status))
                    self.assertEqual(boundaries, [self.boundary(m)])
                    self.assertEqual(m.consumer_words(), (0,) * 24 + (0xD1700096,))
                    self.assertEqual(m.generated_output_writes(), [])
                    self.assertEqual(m.lifecycle_snapshot(), before)
                    self.assertEqual(m.transport_count(), 0)
                    self.assertEqual(m.registry_held, not released)
                    self.assertEqual(m.peek(FAULT), 0)

    def test_faulted_history_reads_fault_only_and_never_repairs_it(self):
        for fault in (1, 22, MASK):
            with self.subTest(fault=fault):
                m = self.machine()
                self.queued(m)
                m.put(LIFECYCLE + lifecycle.FAULT, fault, 4)
                self.assert_denied(m)
                self.assertEqual([(event[0], event[2])
                                  for event in m.consumer_history_accesses],
                                 [('read', LIFECYCLE + lifecycle.FAULT)])

    def test_queue_fault_or_malformed_head_never_acquires_registry(self):
        for malformed in (False, True):
            with self.subTest(malformed=malformed):
                m = self.machine()
                self.queued(m)
                if malformed:
                    m.put(m.transport_element() + queue.STATUS, 22, 4)
                else:
                    m.put(FAULT, queue.HEADER_FAULT, 4)
                m.clear_events()
                self.assertEqual(m.take(), (0, 0))
                self.assertEqual(m.consumer_words(), (0,) * 25)
                self.assertEqual(m.consumer_history_accesses, [])
                self.assertEqual(m.transport_count(), 1)
                self.assertEqual([(event[0], event[1]) for event in m.raw_events], [
                    (RAW_LOCK, TRANSPORT_MUTEX), (RAW_UNLOCK, TRANSPORT_MUTEX)])

    def test_private_pop_result_schema_is_rechecked_before_registry(self):
        mutations = ((0, 0), (queue.TOKEN, 0), (queue.TOKEN, 17),
                     (queue.CONTROLLER, 0), (queue.REGISTRY_MUTEX, 0),
                     (queue.CALLER, RETURN), (queue.SITE, 0x438A58),
                     (queue.STATUS, 22), (queue.NATIVE_RESULT, 1),
                     (queue.RELEASE_STATUS, 22),
                     (queue.PAYLOAD + queue.PAYLOAD_ENGINE, 0))
        for offset, value in mutations:
            with self.subTest(offset=offset, value=value):
                m = self.machine()
                self.queued(m)

                def mutate(machine, pc):
                    if pc == machine.birth_consumer_labels['after_pop']:
                        machine.put(machine.r[29] + fixture.core.PRIVATE + offset,
                                    value, 4)

                m.on_instruction = mutate
                m.clear_events()
                self.assertEqual(m.take(), (0, 0))
                self.assertEqual(m.transport_count(), 0)
                self.assertEqual(m.consumer_words(), (0,) * 25)
                self.assertEqual(m.consumer_history_accesses, [])
                self.assertEqual([(event[0], event[1]) for event in m.raw_events], [
                    (RAW_LOCK, TRANSPORT_MUTEX), (RAW_UNLOCK, TRANSPORT_MUTEX)])

    def test_unpinned_controller_fingerprints_deny_before_history_and_release_r(self):
        for offset, value in ((0x13C, REGISTRY_MUTEX + 4),
                              (0x274, 0x437CE0), (0x278, 0x437D60)):
            with self.subTest(offset=offset):
                m = self.machine()
                self.queued(m)
                m.put(CONTROLLER + offset, value, 4)
                m.clear_events()
                self.assertEqual(m.take(), (0, 0))
                self.assertEqual(m.consumer_words(), (0,) * 25)
                self.assertEqual(m.consumer_history_accesses, [])
                self.assertEqual(m.transport_count(), 0)
                self.assertEqual([(event[0], event[1]) for event in m.raw_events], [
                    (RAW_LOCK, TRANSPORT_MUTEX), (RAW_UNLOCK, TRANSPORT_MUTEX),
                    (RAW_LOCK, REGISTRY_MUTEX), (RAW_UNLOCK, REGISTRY_MUTEX)])

    def test_header_count_and_reserved_corruption_deny_without_reading_rows(self):
        for offset, value in ((lifecycle.COUNT, 0), (lifecycle.COUNT, 17),
                              (lifecycle.COUNT, MASK), (lifecycle.RESERVED0, 1),
                              (lifecycle.RESERVED1, MASK)):
            with self.subTest(offset=offset, value=value):
                m = self.machine()
                self.queued(m)
                m.put(LIFECYCLE + offset, value, 4)
                self.assert_denied(m)
                if value != 0:
                    self.assertFalse(any(event[2] >= LIFECYCLE + lifecycle.HEADER_BYTES
                                         for event in m.consumer_history_accesses))

    def test_every_exact_birth_field_must_match_the_selected_token_row(self):
        mutations = ((queue.NODE, ENGINE + 4), (queue.ENGINE, ENGINE + 4),
                     (queue.NATIVE_SP, STACK + 8), (queue.CALLER, RETURN),
                     (queue.SITE, 0x438A58), (queue.STATUS, 22),
                     (queue.CONTROLLER, CONTROLLER + 4),
                     (queue.REGISTRY_MUTEX, REGISTRY_MUTEX + 4))
        for offset, value in mutations:
            with self.subTest(offset=offset, value=value):
                m = self.machine()
                self.queued(m)
                m.put(LIFECYCLE + lifecycle.HEADER_BYTES + offset, value, 4)
                self.assert_denied(m)

    def test_wrong_but_in_range_token_cannot_borrow_another_row(self):
        m = self.machine()
        self.queued(m)
        self.assertEqual(m.register_birth(output=SOURCE + 48), (0, SOURCE + 48))
        self.assertEqual(m.lifecycle_header(), (2, 0, 0, 0))
        m.put(m.transport_element() + queue.TOKEN, 2, 4)
        self.assert_denied(m)

    def test_token_above_healthy_count_denies_without_extending_history(self):
        m = self.machine()
        self.queued(m)
        m.put(m.transport_element() + queue.TOKEN, 16, 4)
        self.assert_denied(m)

    def test_unrelated_occupied_prefix_corruption_cannot_be_skipped(self):
        mutations = ((lifecycle.MAGIC, 0), (lifecycle.TOKEN, 1),
                     (lifecycle.CONTROLLER, CONTROLLER + 4),
                     (lifecycle.MUTEX, REGISTRY_MUTEX + 4),
                     (lifecycle.SITE, 0x439618), (lifecycle.STATUS, 22),
                     (lifecycle.STATE, 0), (lifecycle.STATE, 3),
                     (lifecycle.RETIREMENT_SITE, 0x439618),
                     (lifecycle.RETIREMENT_SP, 1), (lifecycle.RETIREMENT_CALLER, 1),
                     (lifecycle.RESERVED2, 1), (lifecycle.RESERVED3, MASK))
        for offset, value in mutations:
            with self.subTest(offset=offset, value=value):
                m = self.machine()
                self.queued(m)
                self.assertEqual(m.register_birth(output=SOURCE + 48), (0, SOURCE + 48))
                m.put(LIFECYCLE + lifecycle.HEADER_BYTES + lifecycle.RECORD_BYTES
                      + offset, value, 4)
                self.assert_denied(m)

    def test_global_outstanding_node_duplicate_denies_unrelated_selected_token(self):
        m = self.machine()
        self.queued(m)
        for index in (1, 2):
            out = SOURCE + 48 * index
            self.assertEqual(m.register_birth(output=out), (0, out))
        second = m.lifecycle_record(1)
        m.put(LIFECYCLE + lifecycle.HEADER_BYTES + 2 * lifecycle.RECORD_BYTES
              + lifecycle.NODE, second[4], 4)
        self.assert_denied(m)

    def test_invalid_terminal_schema_in_selected_or_unrelated_row_denies(self):
        for selected in (True, False):
            for offset, value in ((lifecycle.RETIREMENT_SITE, 0),
                                  (lifecycle.RETIREMENT_SITE, 0x438A5C),
                                  (lifecycle.RESERVED2, 1),
                                  (lifecycle.RESERVED3, MASK)):
                with self.subTest(selected=selected, offset=offset, value=value):
                    m = self.machine()
                    self.queued(m)
                    m.delete_native()
                    index = 0
                    if not selected:
                        self.assertEqual(m.register_birth(output=SOURCE + 48),
                                         (0, SOURCE + 48))
                        m.delete_native()
                        index = 1
                    m.put(LIFECYCLE + lifecycle.HEADER_BYTES
                          + index * lifecycle.RECORD_BYTES + offset, value, 4)
                    self.assert_denied(m)

    def test_nonzero_words_anywhere_in_unused_tail_deny_without_faulting_history(self):
        for index in (1, 8, 15):
            for word in (0, 10, 15):
                with self.subTest(index=index, word=word):
                    m = self.machine()
                    self.queued(m)
                    address = (LIFECYCLE + lifecycle.HEADER_BYTES
                               + index * lifecycle.RECORD_BYTES + 4 * word)
                    m.put(address, 0xD1A70000 + word, 4)
                    self.assert_denied(m)
                    self.assertEqual(m.peek(LIFECYCLE + lifecycle.FAULT), 0)

    def test_every_initial_dirty_output_word_denies_before_save_or_pop(self):
        for index in range(25):
            with self.subTest(word=index):
                m = self.machine()
                self.queued(m)
                m.put(OUTPUT + index * 4, 0xD1700000 + index, 4)
                expected = m.consumer_words()
                m.clear_events()
                self.assertEqual(m.take(), (0, 0))
                self.assertEqual(m.consumer_words(), expected)
                self.assertEqual(m.transport_count(), 1)
                self.assertEqual(m.raw_events, [])
                self.assertEqual(m.consumer_history_accesses, [])
                self.assertEqual(m.writes, [])

    def test_every_late_dirty_output_word_prevents_all_export_stores(self):
        for index in range(25):
            with self.subTest(word=index):
                m = self.machine()
                self.queued(m)
                dirty = 0xA11C0000 + index

                def mutate(machine, target):
                    if target == RAW_UNLOCK and machine.r[4] == REGISTRY_MUTEX:
                        machine.put(OUTPUT + index * 4, dirty, 4)

                m.on_service = mutate
                m.clear_events()
                self.assertEqual(m.take(), (0, 0))
                expected = [0] * 25
                expected[index] = dirty
                self.assertEqual(m.consumer_words(), tuple(expected))
                self.assertEqual(m.generated_output_writes(), [])
                self.assertEqual(m.transport_count(), 0)
                self.assertEqual(m.peek(FAULT), 0)
                self.assertEqual(m.peek(LIFECYCLE + lifecycle.FAULT), 0)

    def test_repeated_output_cannot_pop_again_or_overwrite_diagnostic(self):
        m = self.machine()
        self.queued(m)
        fresh = SOURCE + 48
        self.assertEqual(m.register_birth(output=fresh), (0, fresh))
        self.assertEqual(m.enqueue(fresh), (2, 0))
        self.assertEqual(m.take(), (OUTPUT, 0))
        expected = m.consumer_words()
        m.clear_events()
        self.assertEqual(m.take(), (0, 0))
        self.assertEqual(m.consumer_words(), expected)
        self.assertEqual(m.transport_count(), 1)
        self.assertEqual(m.raw_events, [])
        self.assertEqual(m.writes, [])

    def test_output_fixed_rx_and_complete_combined_frame_aliases_deny_before_access(self):
        m = self.machine()
        combined = 192 + queue.FRAME
        addresses = (STATE, BIND_STATE, OWNER_STATE, LIFECYCLE, CONTROLLER,
                     REGISTRY_MUTEX, PAINT_MUTEX, QUEUE, TRANSPORT_MUTEX, FAULT,
                     0x4389E0, CODE, CODE + len(m.code) - 4,
                     STACK - combined, STACK - combined + 4,
                     STACK - 192 - 4, STACK - 192, STACK - 4)
        for address in addresses:
            with self.subTest(address=hex(address)):
                m = self.machine()
                self.assertEqual(m.take(address), (0, 0))
                self.assertEqual(m.raw_events, [])
                self.assertEqual(m.reads, [])
                self.assertEqual(m.writes, [])

    def test_invalid_wrapping_and_unaligned_output_denies_before_any_access(self):
        for output in (0, 1, OUTPUT + 1, 0xFFFFFFFC, 0xFFFFFFA0):
            with self.subTest(output=hex(output)):
                m = self.machine()
                self.assertEqual(m.take(output), (0, 0))
                self.assertEqual(m.raw_events, [])
                self.assertEqual(m.reads, [])
                self.assertEqual(m.writes, [])

    def test_foreign_controller_invalid_stack_and_combined_frame_fixed_alias_deny(self):
        combined = 192 + queue.FRAME
        arguments = ({'controller': 0}, {'controller': CONTROLLER + 4},
                     {'stack': 0}, {'stack': 1}, {'stack': STACK + 4},
                     {'stack': combined - 8},
                     *({'stack': address + combined}
                       for address in (CODE, QUEUE, FAULT, TRANSPORT_MUTEX,
                                       LIFECYCLE, CONTROLLER, STATE)))
        for options in arguments:
            with self.subTest(options=options):
                m = self.machine()
                self.assertEqual(m.take(**options), (0, 0))
                self.assertEqual(m.raw_events, [])
                self.assertEqual(m.reads, [])
                self.assertEqual(m.writes, [])

    def test_parent_capture_guards_cover_full_consumer_rx_and_fixed_data(self):
        m = self.machine()
        addresses = (m.birth_consumer_labels['take'], CODE + len(m.code) - 4,
                     QUEUE, TRANSPORT_MUTEX, FAULT)
        for argument in ('descriptor', 'output'):
            for address in addresses:
                with self.subTest(argument=argument, address=hex(address)):
                    m = self.machine()
                    self.assertEqual(m.register_birth(**{argument: address}), (MASK, 0))
                    self.assertEqual(m.native_entries, [])
                    self.assertEqual(m.raw_events, [])
                    self.assertEqual(m.writes, [])

    def test_success_after_r_release_has_no_shared_or_native_access(self):
        m = self.machine()
        self.queued(m)
        boundaries = []

        def observe(machine, target):
            if target == RAW_UNLOCK and machine.r[4] == REGISTRY_MUTEX:
                boundaries.append((len(machine.transport_accesses),
                                   len(machine.consumer_history_accesses),
                                   len(machine.calls), len(machine.owner_accesses)))

        m.on_service = observe
        m.clear_events()
        self.assertEqual(m.take(), (OUTPUT, 0))
        self.assertEqual(boundaries, [(len(m.transport_accesses),
                                       len(m.consumer_history_accesses),
                                       len(m.calls), len(m.owner_accesses))])


if __name__ == '__main__':
    unittest.main()
