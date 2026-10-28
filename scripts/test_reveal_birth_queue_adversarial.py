#!/usr/bin/env python3
"""Deny malformed typed birth work without inferring pointer lifetime.

Substituted list returns/counts below are explicit wrapper branch coverage,
not native failure-atomicity claims. Every uncertain raw T result ends that
fixture instance; neither simulated ownership outcome authorizes retry.
"""

import unittest

from build_reveal_bridge_diag import b
import reveal_birth_capture_mips as capture
import reveal_birth_queue_mips as core
import test_reveal_birth_queue_mips as fixture
from test_reveal_birth_queue_mips import (
    BirthQueueMachine, QUEUE, TRANSPORT_MUTEX, FAULT, PAYLOAD, OUTPUT, SOURCE,
    PAYLOAD_WORDS, APPEND, GET, REMOVE, LIFECYCLE, ENGINE, CONTROLLER,
    REGISTRY_MUTEX, PAINT_MUTEX, CODE, INPUT, STATE, BIND_STATE, OWNER_STATE,
    RAW_LOCK, RAW_UNLOCK, STACK, RETURN, MASK)


class BirthQueueAdversarialTests(unittest.TestCase):
    setUpClass = classmethod(fixture.BirthQueueTests.setUpClass.__func__)
    prepared = fixture.BirthQueueTests.prepared

    def machine(self, **options):
        return BirthQueueMachine(self.image, **options)

    def boundary(self, machine):
        return tuple(len(getattr(machine, name)) for name in (
            'transport_accesses', 'owned_accesses', 'journal_accesses',
            'binding_accesses', 'owner_accesses', 'lifecycle_accesses', 'calls'))

    def generated_output_writes(self, machine, output=OUTPUT):
        # Service callbacks retain their generated call-site current_pc. An
        # injected put() at raw unlock therefore is not an emitted export SW:
        # require the actual instruction, not merely a generated RX address.
        return [event for event in machine.owned_accesses
                if event[0] == 'write' and output <= event[2] < output + 84
                and CODE <= event[1] < CODE + len(machine.code)
                and machine.word(event[1]) >> 26 == 0x2B]

    def replace_method(self, machine, target, value=0):
        machine.patches[target] = b.r_type(31, 0, 0, 8)
        machine.patches[target + 4] = b.addiu(2, 0, value & 0xFFFF)

    def test_raw_acquire_failure_never_touches_queue_or_guesses_unlock(self):
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
                        boundaries = []

                        def observe(machine, target):
                            if target == RAW_LOCK and machine.r[4] == TRANSPORT_MUTEX:
                                boundaries.append(self.boundary(machine))

                        m.on_service = observe
                        m.clear_events()
                        self.assertEqual(m.enqueue() if operation == 'enqueue'
                                         else m.pop(), (0, status))
                        self.assertEqual(boundaries, [self.boundary(m)])
                        self.assertEqual(m.transport_accesses, [])
                        self.assertEqual([event[0] for event in m.transport_events],
                                         [RAW_LOCK])
                        self.assertEqual(m.transport_held, held)
                        self.assertEqual(m.birth_output()[0], core.CONSUMED_MAGIC)
                        self.assertEqual(m.output_words(), (0,) * 21)
                        # Externally isolate this whole instance; never retry.

    def test_raw_release_failure_stops_after_uncertain_append_or_removal(self):
        for operation in ('enqueue', 'pop'):
            for status in (1, 22, 0x82, MASK):
                for released in (False, True):
                    with self.subTest(operation=operation, status=status,
                                      released=released):
                        m = self.machine()
                        self.prepared(m)
                        if operation == 'pop':
                            self.assertEqual(m.enqueue(), (1, 0))
                        m.transport_release = status
                        m.transport_release_failure_releases = released
                        boundaries = []

                        def observe(machine, target):
                            if target == RAW_UNLOCK and machine.r[4] == TRANSPORT_MUTEX:
                                boundaries.append(self.boundary(machine))

                        m.on_service = observe
                        m.clear_events()
                        self.assertEqual(m.enqueue() if operation == 'enqueue'
                                         else m.pop(), (0, status))
                        self.assertEqual(boundaries, [self.boundary(m)])
                        self.assertEqual(m.transport_count(),
                                         1 if operation == 'enqueue' else 0)
                        self.assertEqual(m.peek(FAULT), 0)
                        self.assertEqual(m.output_words(), (0,) * 21)
                        self.assertEqual(m.transport_held, not released)
                        self.assertEqual([event[0] for event in m.transport_events],
                                         [RAW_LOCK, RAW_UNLOCK])

    def test_failed_unlock_does_not_recheck_dirty_output_or_write_late_fault(self):
        m = self.machine()
        self.prepared(m)
        self.assertEqual(m.enqueue(), (1, 0))
        m.transport_release = 22
        boundaries = []

        def mutate(machine, target):
            if target == RAW_UNLOCK and machine.r[4] == TRANSPORT_MUTEX:
                machine.put(OUTPUT + 80, 0xD1700080, 4)
                boundaries.append(self.boundary(machine))

        m.on_service = mutate
        m.clear_events()
        self.assertEqual(m.pop(), (0, 22))
        self.assertEqual(boundaries, [self.boundary(m)])
        self.assertEqual(m.output_words(), (0,) * 20 + (0xD1700080,))
        self.assertEqual(self.generated_output_writes(m), [])
        self.assertEqual(m.peek(FAULT), 0)

    def test_existing_fault_is_permanent_and_read_before_native_header(self):
        for operation in ('enqueue', 'pop'):
            for fault in (1, 2, 3, 4, MASK):
                with self.subTest(operation=operation, fault=fault):
                    m = self.machine()
                    self.prepared(m)
                    m.put(FAULT, fault, 4)
                    m.clear_events()
                    self.assertEqual(m.enqueue() if operation == 'enqueue'
                                     else m.pop(), (0, 0))
                    self.assertEqual([(event[0], event[2])
                                      for event in m.transport_accesses],
                                     [('read', FAULT)])
                    self.assertEqual(m.peek(FAULT), fault)
                    self.assertNotIn(APPEND, m.trace)
                    self.assertNotIn(GET, m.trace)
                    if operation == 'enqueue':
                        self.assertEqual(m.birth_output()[0], core.CONSUMED_MAGIC)

    def test_corrupt_header_latches_fault_one_only_while_t_is_held(self):
        corruptions = ((0x10, 68), (0x10, 72), (0x10, 0), (0x14, 0),
                       (0x14, 9), (8, 20), (8, 0), (0xC, 41),
                       (0xC, MASK), (0, 0), (0, 1))
        for operation in ('enqueue', 'pop'):
            for offset, value in corruptions:
                with self.subTest(operation=operation, offset=offset, value=value):
                    m = self.machine()
                    self.prepared(m)
                    m.put(QUEUE + offset, value, 4)
                    m.clear_events()
                    self.assertEqual(m.enqueue() if operation == 'enqueue'
                                     else m.pop(), (0, 0))
                    self.assertEqual(m.peek(FAULT), 1)
                    writes = [event for event in m.transport_accesses
                              if event[0] == 'write']
                    self.assertEqual([(event[2], event[4]) for event in writes],
                                     [(FAULT, True)])
                    self.assertNotIn(APPEND, m.trace)
                    self.assertNotIn(GET, m.trace)
                    self.assertEqual([event[0] for event in m.transport_events],
                                     [RAW_LOCK, RAW_UNLOCK])

    def test_invalid_capture_schema_never_consumes_or_enters_t(self):
        corruptions = ((0, 0), (0, core.READY_MAGIC), (0, core.CONSUMED_MAGIC),
                       (4, 0), (4, 17), (4, MASK),
                       (8, CONTROLLER + 4), (12, REGISTRY_MUTEX + 4),
                       (28, RETURN), (32, 0x438A58), (36, 22),
                       (40, 1), (44, 22))
        for offset, value in corruptions:
            with self.subTest(offset=offset, value=value):
                m = self.machine()
                self.prepared(m)
                m.put(SOURCE + offset, value, 4)
                original = m.birth_output()
                m.clear_events()
                self.assertEqual(m.enqueue(), (0, 0))
                self.assertEqual(m.birth_output(), original)
                self.assertEqual(m.transport_events, [])
                self.assertEqual(m.transport_accesses, [])
                self.assertFalse(any(event[0] == 'write'
                    and SOURCE <= event[2] < SOURCE + 48 for event in m.owned_accesses))

    def test_payload_engine_mismatch_refuses_before_source_consumption(self):
        for value in (0, 1, MASK, ENGINE + 4):
            with self.subTest(value=value):
                m = self.machine()
                self.prepared(m)
                m.put(PAYLOAD + core.PAYLOAD_ENGINE, value, 4)
                original = m.birth_output()
                m.clear_events()
                self.assertEqual(m.enqueue(), (0, 0))
                self.assertEqual(m.birth_output(), original)
                self.assertEqual(m.transport_events, [])
                self.assertEqual(m.transport_accesses, [])

    def test_historical_node_engine_sp_are_opaque_even_zero_or_unaligned(self):
        for offset in (core.NODE, core.ENGINE, core.NATIVE_SP):
            for value in (0, 1, MASK):
                with self.subTest(offset=offset, value=value):
                    m = self.machine()
                    self.prepared(m)
                    m.put(SOURCE + offset, value, 4)
                    if offset == core.ENGINE:
                        m.put(PAYLOAD + core.PAYLOAD_ENGINE, value, 4)
                    expected = (core.READY_MAGIC, *m.birth_output()[1:],
                                *m.words_at(PAYLOAD, 9))
                    m.clear_events()
                    self.assertEqual(m.enqueue(), (1, 0))
                    self.assertEqual(m.pop(), (OUTPUT, 0))
                    self.assertEqual(m.output_words(), expected)
                    self.assertTrue(all(event[1] == TRANSPORT_MUTEX
                                        for event in m.raw_events))

    def test_other_payload_words_are_owned_scalars_not_pointer_requests(self):
        m = self.machine()
        words = tuple(ENGINE if index == 2 else MASK - index for index in range(9))
        expected = self.prepared(m, words=words)
        self.assertEqual(m.enqueue(), (1, 0))
        self.assertEqual(m.pop(), (OUTPUT, 0))
        self.assertEqual(m.output_words(), expected)

    def test_invalid_queued_schema_latches_head_fault_before_remove(self):
        corruptions = ((0, capture.OUTPUT_MAGIC), (0, 0), (4, 0), (4, 17),
                       (8, 0), (12, 0), (28, RETURN), (32, 0), (36, 1),
                       (40, 1), (44, 1), (core.PAYLOAD + core.PAYLOAD_ENGINE, 0))
        for offset, value in corruptions:
            with self.subTest(offset=offset, value=value):
                m = self.machine()
                self.prepared(m)
                self.assertEqual(m.enqueue(), (1, 0))
                m.put(m.transport_element() + offset, value, 4)
                m.clear_events()
                self.assertEqual(m.pop(), (0, 0))
                self.assertEqual(m.peek(FAULT), 2)
                self.assertEqual(m.transport_count(), 1)
                self.assertIn(GET, m.trace)
                self.assertNotIn(REMOVE, m.trace)
                self.assertEqual(self.generated_output_writes(m), [])

    def test_native_get_pointer_gate_denies_fixed_rx_frame_and_output_aliases(self):
        m = self.machine()
        pointers = (0, 1, 0xFFFFFFFC, FAULT, TRANSPORT_MUTEX, QUEUE, CONTROLLER,
                    REGISTRY_MUTEX, PAINT_MUTEX, STATE, BIND_STATE, OWNER_STATE,
                    LIFECYCLE, CODE, CODE + len(m.code) - 4,
                    STACK - core.FRAME + core.PRIVATE, OUTPUT, OUTPUT + 80)
        for pointer in pointers:
            with self.subTest(pointer=hex(pointer)):
                m = self.machine()
                self.prepared(m)
                self.assertEqual(m.enqueue(), (1, 0))
                self.replace_method(m, GET)

                def replace(machine, pc):
                    if pc == machine.birth_queue_labels['after_get']:
                        machine.r[2] = pointer

                m.on_instruction = replace
                m.clear_events()
                self.assertEqual(m.pop(), (0, 0))
                self.assertEqual(m.peek(FAULT), 2)
                self.assertNotIn(REMOVE, m.trace)
                self.assertEqual(self.generated_output_writes(m), [])
                self.assertFalse(any(event[0] == 'read' and event[4]
                    and OUTPUT <= event[2] < OUTPUT + 84 for event in m.owned_accesses))

    def test_append_index_mismatch_latches_fault_three_without_retry(self):
        for status in (1, 22, MASK):
            with self.subTest(status=status):
                m = self.machine()
                self.prepared(m)
                self.replace_method(m, APPEND, status)
                self.assertEqual(m.enqueue(), (0, 0))
                self.assertEqual(m.peek(FAULT), 3)
                self.assertEqual(m.transport_count(), 0)
                self.assertEqual(m.trace.count(APPEND), 1)
                self.assertEqual(m.birth_output()[0], core.CONSUMED_MAGIC)

    def test_append_expected_index_without_increment_is_fault_three(self):
        m = self.machine()
        self.prepared(m)
        self.replace_method(m, APPEND)
        self.assertEqual(m.enqueue(), (0, 0))
        self.assertEqual(m.peek(FAULT), 3)
        self.assertEqual(m.transport_count(), 0)

    def test_actual_append_with_corrupt_post_count_is_not_rolled_back(self):
        m = self.machine()
        self.prepared(m)

        def mutate(machine, pc):
            if pc == machine.birth_queue_labels['after_append']:
                machine.put(QUEUE + 0xC, 2, 4)

        m.on_instruction = mutate
        self.assertEqual(m.enqueue(), (0, 0))
        self.assertEqual(m.peek(FAULT), 3)
        self.assertEqual(m.transport_count(), 2)

    def test_remove_error_is_fault_four_without_export(self):
        for status in (1, 22, MASK):
            with self.subTest(status=status):
                m = self.machine()
                self.prepared(m)
                self.assertEqual(m.enqueue(), (1, 0))
                self.replace_method(m, REMOVE, status)
                m.clear_events()
                self.assertEqual(m.pop(), (0, 0))
                self.assertEqual(m.peek(FAULT), 4)
                self.assertEqual(m.transport_count(), 1)
                self.assertEqual(self.generated_output_writes(m), [])

    def test_remove_zero_without_decrement_is_fault_four(self):
        m = self.machine()
        self.prepared(m)
        self.assertEqual(m.enqueue(), (1, 0))
        self.replace_method(m, REMOVE)
        m.clear_events()
        self.assertEqual(m.pop(), (0, 0))
        self.assertEqual(m.peek(FAULT), 4)
        self.assertEqual(m.transport_count(), 1)
        self.assertEqual(self.generated_output_writes(m), [])

    def test_actual_remove_with_corrupt_post_count_is_not_rolled_back(self):
        m = self.machine()
        self.prepared(m)
        self.assertEqual(m.enqueue(), (1, 0))

        def mutate(machine, pc):
            if pc == machine.birth_queue_labels['after_remove']:
                machine.put(QUEUE + 0xC, 1, 4)

        m.on_instruction = mutate
        m.clear_events()
        self.assertEqual(m.pop(), (0, 0))
        self.assertEqual(m.peek(FAULT), 4)
        self.assertEqual(m.transport_count(), 1)
        self.assertEqual(self.generated_output_writes(m), [])

    def test_every_initial_dirty_output_word_denies_before_save_or_t(self):
        for index in range(21):
            with self.subTest(word=index):
                m = self.machine()
                m.put(OUTPUT + 4 * index, 0xD1700000 + index, 4)
                expected = m.output_words()
                m.clear_events()
                self.assertEqual(m.pop(), (0, 0))
                self.assertEqual(m.output_words(), expected)
                self.assertEqual(m.transport_events, [])
                self.assertEqual(m.transport_accesses, [])
                self.assertEqual(m.writes, [])

    def test_every_late_dirty_output_word_prevents_all_generated_export_stores(self):
        for index in range(21):
            with self.subTest(word=index):
                m = self.machine()
                self.prepared(m)
                self.assertEqual(m.enqueue(), (1, 0))
                dirty = 0xA11C0000 + index

                def mutate(machine, target):
                    if target == RAW_UNLOCK and machine.r[4] == TRANSPORT_MUTEX:
                        machine.put(OUTPUT + 4 * index, dirty, 4)

                m.on_service = mutate
                m.clear_events()
                self.assertEqual(m.pop(), (0, 0))
                expected = [0] * 21
                expected[index] = dirty
                self.assertEqual(m.output_words(), tuple(expected))
                self.assertEqual(self.generated_output_writes(m), [])
                self.assertEqual(m.transport_count(), 0)
                self.assertEqual(m.peek(FAULT), 0)

    def test_repeated_output_is_not_overwritten_or_used_to_extract_again(self):
        m = self.machine()
        expected = self.prepared(m)
        clone = m.clone_source()
        self.assertEqual(m.enqueue(), (1, 0))
        self.assertEqual(m.enqueue(clone), (2, 0))
        self.assertEqual(m.pop(), (OUTPUT, 0))
        m.clear_events()
        self.assertEqual(m.pop(), (0, 0))
        self.assertEqual(m.output_words(), expected)
        self.assertEqual(m.transport_count(), 1)
        self.assertEqual(m.transport_events, [])
        self.assertEqual(m.writes, [])

    def test_bq84_export_is_not_a_fresh_bcap_input(self):
        m = self.machine()
        self.prepared(m)
        self.assertEqual(m.enqueue(), (1, 0))
        self.assertEqual(m.pop(), (OUTPUT, 0))
        expected = m.output_words()
        m.clear_events()
        self.assertEqual(m.enqueue(OUTPUT, OUTPUT + 48), (0, 0))
        self.assertEqual(m.output_words(), expected)
        self.assertEqual(m.transport_events, [])

    def test_fixed_rx_data_and_own_frame_aliases_deny_before_any_access(self):
        m = self.machine()
        addresses = (STATE, BIND_STATE, OWNER_STATE, LIFECYCLE, CONTROLLER,
                     REGISTRY_MUTEX, PAINT_MUTEX, QUEUE, TRANSPORT_MUTEX,
                     FAULT, 0x4389E0, CODE, CODE + len(m.code) - 4,
                     STACK - core.FRAME, STACK - 4)
        for argument in ('source', 'payload', 'output'):
            for address in addresses:
                with self.subTest(argument=argument, address=hex(address)):
                    m = self.machine()
                    m.clear_events()
                    result = (m.pop(output=address) if argument == 'output'
                              else m.enqueue(**{argument: address}))
                    self.assertEqual(result, (0, 0))
                    self.assertEqual(m.raw_events, [])
                    self.assertEqual(m.reads, [])
                    self.assertEqual(m.writes, [])

    def test_invalid_wrapping_and_mutually_overlapping_input_extents_deny_early(self):
        cases = ({'source': 0}, {'source': 1}, {'source': 0xFFFFFFFC},
                 {'payload': 0}, {'payload': 1}, {'payload': 0xFFFFFFFC},
                 {'payload': SOURCE}, {'payload': SOURCE + 4},
                 {'source': PAYLOAD}, {'source': PAYLOAD + 32})
        for arguments in cases:
            with self.subTest(arguments=arguments):
                m = self.machine()
                self.assertEqual(m.enqueue(**arguments), (0, 0))
                self.assertEqual(m.raw_events, [])
                self.assertEqual(m.reads, [])
                self.assertEqual(m.writes, [])
        for output in (0, 1, 0xFFFFFFFC):
            with self.subTest(output=output):
                m = self.machine()
                self.assertEqual(m.pop(output), (0, 0))
                self.assertEqual(m.raw_events, [])
                self.assertEqual(m.reads, [])
                self.assertEqual(m.writes, [])

    def test_foreign_controller_invalid_stack_or_fixed_frame_alias_denies_both_entries(self):
        arguments = ({'controller': 0}, {'controller': CONTROLLER + 4},
                     {'stack': 0}, {'stack': 1}, {'stack': STACK + 4},
                     {'stack': core.FRAME - 8},
                     *({'stack': address + core.FRAME}
                       for address in (CODE, QUEUE, FAULT, TRANSPORT_MUTEX,
                                       LIFECYCLE, CONTROLLER, STATE)))
        for operation in ('enqueue', 'pop'):
            for options in arguments:
                with self.subTest(operation=operation, options=options):
                    m = self.machine()
                    result = (m.enqueue(**options) if operation == 'enqueue'
                              else m.pop(**options))
                    self.assertEqual(result, (0, 0))
                    self.assertEqual(m.raw_events, [])
                    self.assertEqual(m.reads, [])
                    self.assertEqual(m.writes, [])

    def test_parent_capture_bulk_guards_cover_new_full_rx_and_dedicated_fixed_data(self):
        m = self.machine()
        addresses = (m.birth_queue_labels['enqueue'], CODE + len(m.code) - 4,
                     QUEUE, TRANSPORT_MUTEX, FAULT)
        for argument in ('descriptor', 'output'):
            for address in addresses:
                with self.subTest(argument=argument, address=hex(address)):
                    m = self.machine()
                    self.assertEqual(m.register_birth(**{argument: address}), (MASK, 0))
                    self.assertEqual(m.native_entries, [])
                    self.assertEqual(m.raw_events, [])
                    self.assertEqual(m.writes, [])

    def test_post_release_success_has_no_shared_or_native_access(self):
        for operation in ('enqueue', 'pop'):
            with self.subTest(operation=operation):
                m = self.machine()
                self.prepared(m)
                if operation == 'pop':
                    self.assertEqual(m.enqueue(), (1, 0))
                boundaries = []

                def observe(machine, target):
                    if target == RAW_UNLOCK and machine.r[4] == TRANSPORT_MUTEX:
                        boundaries.append((len(machine.transport_accesses),
                                           len(machine.calls),
                                           len(machine.lifecycle_accesses),
                                           len(machine.owner_accesses)))

                m.on_service = observe
                m.clear_events()
                self.assertEqual(m.enqueue() if operation == 'enqueue'
                                 else m.pop(), (1, 0) if operation == 'enqueue'
                                 else (OUTPUT, 0))
                self.assertEqual(boundaries, [(len(m.transport_accesses), len(m.calls),
                                               len(m.lifecycle_accesses),
                                               len(m.owner_accesses))])


if __name__ == '__main__':
    unittest.main()
