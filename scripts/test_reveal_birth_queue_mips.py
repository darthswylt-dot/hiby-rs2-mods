#!/usr/bin/env python3
"""Execute a separate native FIFO84 of owned historical birth diagnostics.

Actual birth hooks and native segmented-list factory/APPEND/GET/REMOVE execute.
Only retained storage and bounded raw/heap/libc semantics are supplied here.
Extraction does not use a native engine, publish paint, validate liveness or
acknowledge completion. This is not a device scheduler or lifetime simulator.
"""

import copy
import unittest

import reveal_birth_capture_mips as capture
import reveal_birth_queue_mips as core
import reveal_birth_queue_stage as stage
import test_reveal_birth_capture_mips as previous
from test_reveal_birth_capture_mips import (
    BirthCaptureMachine, OUTPUT as SOURCE, LIFECYCLE, ENGINE, CONTROLLER,
    REGISTRY_MUTEX, PAINT_MUTEX, CODE, INPUT, STATE, BIND_STATE, OWNER_STATE,
    RAW_LOCK, RAW_UNLOCK, STACK, RETURN, MASK)


QUEUE, TRANSPORT_MUTEX, FAULT = 0x1FF2000, 0x1F20700, 0x1F20800
PAYLOAD, OUTPUT = 0x1F3B000, SOURCE + 0x100
FACTORY, APPEND, GET, REMOVE = 0x456E60, 0x455DA0, 0x4557E0, 0x455860
PAYLOAD_WORDS = (0, MASK, ENGINE, 1, 16, 8, 8, 0x87654321, 0)
SECOND_STACK = STACK + 0x6000


class BirthQueueMachine(BirthCaptureMachine):
    """Emitted ownership transitions and real native list copying, not an oracle."""

    def __init__(self, image, *, transport_capacity=40, transport_acquire=0,
                 transport_release=0, transport_acquire_failure_holds=False,
                 transport_release_failure_releases=True, **options):
        super().__init__(image, hooks=False, **options)
        self.r[29] = STACK
        native_header = self.stock(FACTORY, transport_capacity, core.ENVELOPE_BYTES)
        if not native_header:
            raise AssertionError('native birth FIFO84 construction failed')
        allocated = self.peek(native_header + 8)
        self.map(QUEUE, core.QUEUE_BYTES)
        data, offset = self.region(native_header, core.QUEUE_BYTES)
        self.bytes(QUEUE, bytes(data[offset:offset + core.QUEUE_BYTES]))
        self.map(TRANSPORT_MUTEX, core.MUTEX_BYTES)
        self.map(FAULT, 4)
        self.composition = stage.assemble(
            STATE, BIND_STATE, OWNER_STATE, CONTROLLER, REGISTRY_MUTEX,
            PAINT_MUTEX, CODE, LIFECYCLE, QUEUE, TRANSPORT_MUTEX, FAULT,
            capacity=options.get('capacity', 16),
            lifecycle_capacity=options.get('lifecycle_capacity', 16),
            owner_capacity=options.get('owner_capacity', 16),
            ticket_limit=options.get('ticket_limit', core.owners.MAX_TICKET),
            queue_capacity=options.get('queue_capacity', 64),
            transport_capacity=allocated)
        self.code = self.code_bytes = self.composition['code']
        self.labels = self.composition['labels']
        for name in ('owner', 'issuer', 'receipt', 'adapter', 'capture',
                     'lifecycle', 'retirement', 'birth_capture', 'birth_queue'):
            setattr(self, name + '_labels', self.composition[name + '_labels'])
        self.bridge_labels = self.receipt_labels
        for pc, words in self.composition['coherent_hooks'].items():
            for index, word in enumerate(words):
                self.patches[pc + 4 * index] = word
        self.birth_list = QUEUE
        self.transport_acquire, self.transport_release = (
            transport_acquire, transport_release)
        self.transport_acquire_failure_holds = transport_acquire_failure_holds
        self.transport_release_failure_releases = transport_release_failure_releases
        self.transport_held = False
        table, chunks = self.peek(QUEUE), allocated // 10
        self.transport_ranges = (
            (QUEUE, core.QUEUE_BYTES), (table, chunks * 4), (FAULT, 4),
            *((self.peek(table + index * 4), 10 * core.ENVELOPE_BYTES)
              for index in range(chunks)))
        self.transport_events, self.transport_accesses = [], []
        self.owned_accesses = []
        self.clear_events()

    def tracked_access(self, kind, address, size):
        super().tracked_access(kind, address, size)
        if (hasattr(self, 'transport_ranges')
                and any(start < address + size and address < start + length
                        for start, length in self.transport_ranges)):
            self.transport_accesses.append((kind, self.current_pc, address, size,
                                            self.transport_held,
                                            self.registry_held, self.paint_held))
        if (hasattr(self, 'owned_accesses')
                and any(start < address + size and address < start + length
                        for start, length in ((SOURCE, 0x1000),
                                              (PAYLOAD, core.PAYLOAD_BYTES)))):
            self.owned_accesses.append((kind, self.current_pc, address, size,
                                       getattr(self, 'transport_held', False),
                                       self.registry_held, self.paint_held))

    def external(self, target):
        if target == 0xA5B440:
            # The bounded memcpy substitute uses bytes(), bypassing get/put.
            self.tracked_access('read', self.r[5], self.r[6])
            self.tracked_access('write', self.r[4], self.r[6])
        return super().external(target)

    def service(self, target):
        if self.r[4] != TRANSPORT_MUTEX:
            return super().service(target)
        result = (self.transport_acquire if target == RAW_LOCK
                  else self.transport_release) & MASK
        self.calls.append(target)
        event = (target, self.r[4], self.r[29], self.r[31], result)
        self.raw_events.append(event)
        self.transport_events.append(event)
        if (target == RAW_LOCK
                and (result == 0 or self.transport_acquire_failure_holds)):
            self.transport_held = True
        if self.on_service is not None:
            self.on_service(self, target)
        self.hostile_result(result)
        if (target == RAW_UNLOCK
                and (result == 0 or self.transport_release_failure_releases)):
            self.transport_held = False

    def clear_events(self):
        super().clear_events()
        for name in ('transport_events', 'transport_accesses', 'owned_accesses'):
            if hasattr(self, name):
                getattr(self, name).clear()

    def payload(self, words=PAYLOAD_WORDS, pointer=PAYLOAD):
        if len(words) != core.PAYLOAD_BYTES // 4:
            raise ValueError('birth payload contains nine owned words')
        for index, word in enumerate(words):
            self.put(pointer + 4 * index, word, 4)
        return pointer

    def enqueue(self, source=SOURCE, payload=PAYLOAD, *, controller=CONTROLLER,
                stack=STACK, caller=RETURN):
        self.r[29], self.r[31] = stack, caller
        self.r[4:7] = controller, source, payload
        self.run_at(self.birth_queue_labels['enqueue'], caller)
        return self.r[2], self.r[3]

    def pop(self, output=OUTPUT, *, controller=CONTROLLER,
            stack=STACK, caller=RETURN):
        self.r[29], self.r[31] = stack, caller
        self.r[4:6] = controller, output
        self.run_at(self.birth_queue_labels['pop'], caller)
        return self.r[2], self.r[3]

    def transport_count(self):
        return self.peek(QUEUE + 0xC)

    def transport_element(self, index=0):
        return self.element(QUEUE, index)

    def queued_words(self, index=0):
        return self.words_at(self.transport_element(index), core.ENVELOPE_BYTES // 4)

    def output_words(self, output=OUTPUT):
        return self.words_at(output, core.ENVELOPE_BYTES // 4)

    def clone_source(self, source=SOURCE, output=SOURCE + 48):
        data, offset = self.region(source, capture.OUTPUT_BYTES)
        self.bytes(output, bytes(data[offset:offset + capture.OUTPUT_BYTES]))
        return output

    def fork_cpu(self):
        """Share retained bytes, not registers, stack, observations or held flags."""
        other = copy.copy(self)
        other.r = self.r.copy()
        for name, value in tuple(vars(self).items()):
            if isinstance(value, list) and name != 'r':
                setattr(other, name, [])
        other.transport_held = other.registry_held = other.paint_held = False
        other.on_instruction = other.on_service = None
        other.before_instruction = other.instruction
        return other


class BirthQueueTests(unittest.TestCase):
    setUpClass = classmethod(previous.BirthCaptureTests.setUpClass.__func__)

    def machine(self, **options):
        return BirthQueueMachine(self.image, **options)

    def prepared(self, machine, *, source=SOURCE, words=PAYLOAD_WORDS):
        self.assertEqual(machine.register_birth(output=source), (0, source))
        machine.payload(words)
        capture_words = machine.birth_output(source)
        machine.clear_events()
        return (core.READY_MAGIC, *capture_words[1:], *words)

    def assert_transport_only(self, machine):
        self.assertTrue(machine.transport_accesses)
        self.assertTrue(all(event[4] and not event[5] and not event[6]
                            for event in machine.transport_accesses),
                        machine.transport_accesses)
        self.assertTrue(all(event[1] == TRANSPORT_MUTEX
                            for event in machine.raw_events))
        for name in ('journal_accesses', 'binding_accesses', 'owner_accesses',
                     'lifecycle_accesses', 'paint_events', 'cleanup_services'):
            self.assertEqual(getattr(machine, name), [], name)

    def test_actual_birth_then_native_fifo84_extracts_without_paint_or_pointer_use(self):
        m = self.machine()
        expected = self.prepared(m)
        engine = m.words_at(ENGINE, 16)
        self.assertEqual(m.enqueue(), (1, 0))
        self.assertEqual(m.birth_output()[0], core.CONSUMED_MAGIC)
        self.assertEqual(m.birth_output()[1:], expected[1:12])
        self.assertEqual(m.queued_words(), expected)
        self.assertEqual(m.pop(), (OUTPUT, 0))
        self.assertEqual(m.output_words(), expected)
        self.assertEqual(m.transport_count(), 0)
        self.assertEqual(m.peek(QUEUE + 0x10), 84)
        self.assertEqual(m.peek(m.paint_list + 0x10), 44)
        self.assertEqual(m.count(), 0)
        self.assertEqual(m.words_at(ENGINE, 16), engine)
        for target in (APPEND, 0x455BC0, GET, REMOVE):
            self.assertIn(target, m.trace)
        self.assert_transport_only(m)
        self.assertFalse(m.transport_held)
        self.assertFalse(any(ENGINE <= address < ENGINE + 0x100
                             for address, _ in m.reads))

    def test_complete_private_snapshot_and_consumption_precede_acquire(self):
        m = self.machine()
        expected = self.prepared(m)
        observations = []

        def mutate(machine, target):
            if target == RAW_LOCK and machine.r[4] == TRANSPORT_MUTEX:
                observations.append(machine.birth_output()[0])
                for pointer, size in ((SOURCE, 48), (PAYLOAD, 36)):
                    for offset in range(0, size, 4):
                        machine.put(pointer + offset, MASK, 4)

        m.on_service = mutate
        self.assertEqual(m.enqueue(), (1, 0))
        self.assertEqual(observations, [core.CONSUMED_MAGIC])
        self.assertEqual(m.queued_words(), expected)
        ordered = ('enqueue_snapshot_done', 'enqueue_source_consumed',
                   'enqueue_before_lock', 'before_append')
        moments = [m.trace.index(m.birth_queue_labels[name]) for name in ordered]
        self.assertEqual(moments, sorted(moments))

    def test_remove_shifts_real_head_but_export_uses_owned_snapshot(self):
        m = self.machine()
        first = self.prepared(m)
        self.assertEqual(m.enqueue(), (1, 0))
        second = self.prepared(m, source=SOURCE + 48,
                               words=(*PAYLOAD_WORDS[:-1], 99))
        self.assertEqual(m.enqueue(SOURCE + 48), (2, 0))
        head = m.transport_element()
        m.clear_events()
        self.assertEqual(m.pop(), (OUTPUT, 0))
        self.assertEqual(m.words_at(head, 21), second)
        self.assertEqual(m.output_words(), first)
        self.assertEqual(m.pop(OUTPUT + 84), (OUTPUT + 84, 0))
        self.assertEqual(m.output_words(OUTPUT + 84), second)
        ordered = (GET, m.birth_queue_labels['pop_snapshot_done'], REMOVE,
                   m.birth_queue_labels['before_release'],
                   m.birth_queue_labels['before_export'])
        self.assertEqual([m.trace.index(pc) for pc in ordered],
                         sorted(m.trace.index(pc) for pc in ordered))
        self.assert_transport_only(m)

    def test_replaying_consumed_source_cannot_enqueue_twice(self):
        m = self.machine()
        self.prepared(m)
        self.assertEqual(m.enqueue(), (1, 0))
        source = m.birth_output()
        m.clear_events()
        self.assertEqual(m.enqueue(), (0, 0))
        self.assertEqual(m.birth_output(), source)
        self.assertEqual(m.transport_events, [])
        self.assertEqual(m.transport_accesses, [])
        self.assertEqual(m.transport_count(), 1)

    def test_exclusive_source_clones_are_not_globally_deduplicated(self):
        m = self.machine()
        expected = self.prepared(m)
        clone = m.clone_source()
        self.assertEqual(m.enqueue(), (1, 0))
        self.assertEqual(m.enqueue(clone), (2, 0))
        self.assertEqual(m.queued_words(0), expected)
        self.assertEqual(m.queued_words(1), expected)
        self.assertEqual(m.birth_output(clone)[0], core.CONSUMED_MAGIC)

    def test_full_native_capacity_consumes_attempt_without_growing_or_faulting(self):
        m = self.machine(transport_capacity=10)
        self.prepared(m)
        sources = [SOURCE] + [m.clone_source(output=SOURCE + 48 * index)
                              for index in range(1, 11)]
        for index, pointer in enumerate(sources[:10]):
            self.assertEqual(m.enqueue(pointer), (index + 1, 0))
        allocation = m.next_allocation
        m.clear_events()
        self.assertEqual(m.enqueue(sources[-1]), (0, 0))
        self.assertEqual(m.birth_output(sources[-1])[0], core.CONSUMED_MAGIC)
        self.assertEqual(m.transport_count(), 10)
        self.assertEqual(m.peek(FAULT), 0)
        self.assertEqual(m.next_allocation, allocation)
        self.assertNotIn(APPEND, m.trace)
        self.assert_transport_only(m)
        m.clear_events()
        self.assertEqual(m.enqueue(sources[-1]), (0, 0))
        self.assertEqual(m.transport_events, [])

    def test_preallocated_slots_cross_actual_ten_element_segment_boundary(self):
        m = self.machine(transport_capacity=20)
        expected = self.prepared(m)
        pointers = [SOURCE] + [m.clone_source(output=SOURCE + index * 48)
                               for index in range(1, 14)]
        for index, pointer in enumerate(pointers):
            m.payload((*PAYLOAD_WORDS[:-1], index))
            self.assertEqual(m.enqueue(pointer), (index + 1, 0))
        self.assertNotEqual(m.transport_element(10), m.transport_element() + 840)
        for index in range(14):
            out = OUTPUT + 0x300 + index * 84
            self.assertEqual(m.pop(out), (out, 0))
            self.assertEqual(m.output_words(out), (*expected[:-1], index))
        self.assertEqual(m.transport_count(), 0)

    def test_empty_pop_checks_transport_but_does_not_export_or_get(self):
        m = self.machine()
        self.assertEqual(m.pop(), (0, 0))
        self.assertEqual(m.output_words(), (0,) * 21)
        self.assertNotIn(GET, m.trace)
        self.assertNotIn(REMOVE, m.trace)
        self.assertEqual([event[0] for event in m.transport_events],
                         [RAW_LOCK, RAW_UNLOCK])
        self.assert_transport_only(m)

    def test_reused_native_node_keeps_distinct_birth_tokens_in_fifo_order(self):
        m = self.machine(capacity=1, lifecycle_capacity=3)
        first = self.prepared(m)
        node = m.allocations[-1]
        self.assertEqual(m.enqueue(), (1, 0))
        m.delete_native()
        m.reuse_node = node
        second = self.prepared(m, source=SOURCE + 48)
        self.assertEqual(m.reused_nodes, [])  # prepared clears observations only
        self.assertEqual(second[4:6], first[4:6])
        self.assertEqual((first[1], second[1]), (1, 2))
        self.assertEqual(m.enqueue(SOURCE + 48), (2, 0))
        self.assertEqual(m.pop(), (OUTPUT, 0))
        self.assertEqual(m.pop(OUTPUT + 84), (OUTPUT + 84, 0))
        self.assertEqual(m.output_words(), first)
        self.assertEqual(m.output_words(OUTPUT + 84), second)
        self.assert_transport_only(m)

    def test_export_magic_is_last_and_all_stores_follow_successful_release(self):
        m = self.machine()
        expected = self.prepared(m)
        self.assertEqual(m.enqueue(), (1, 0))
        m.clear_events()
        self.assertEqual(m.pop(), (OUTPUT, 0))
        writes = [event for event in m.owned_accesses if event[0] == 'write'
                  and OUTPUT <= event[2] < OUTPUT + 84]
        self.assertEqual(len(writes), 21)
        self.assertEqual(writes[-1][2], OUTPUT)
        self.assertTrue(all(not any(event[4:]) for event in writes))
        self.assertEqual(m.output_words(), expected)

    def test_transport_preserves_callee_saved_registers_sp_ra_and_hilo(self):
        for operation in ('enqueue', 'pop'):
            with self.subTest(operation=operation):
                m = self.machine()
                self.prepared(m)
                if operation == 'pop':
                    self.assertEqual(m.enqueue(), (1, 0))
                m.r[29], m.r[31] = STACK, RETURN
                indices = (*range(16, 24), 28, 29, 30, 31)
                expected = tuple(m.r[index] for index in indices), m.hi, m.lo
                result = m.enqueue() if operation == 'enqueue' else m.pop()
                self.assertEqual(result, (1, 0) if operation == 'enqueue'
                                 else (OUTPUT, 0))
                self.assertEqual((tuple(m.r[index] for index in indices), m.hi, m.lo),
                                 expected)

    def test_separate_cpus_own_independent_snapshots_and_output_buffers(self):
        m = self.machine()
        first = self.prepared(m)
        self.assertEqual(m.enqueue(), (1, 0))
        second = self.prepared(m, source=SOURCE + 48,
                               words=(*PAYLOAD_WORDS[:-1], 77))
        self.assertEqual(m.enqueue(SOURCE + 48), (2, 0))
        other = m.fork_cpu()
        extracted = []

        def interleave(machine, pc):
            if pc == machine.birth_queue_labels['before_export'] and not extracted:
                extracted.append(other.pop(OUTPUT + 84, stack=SECOND_STACK))

        m.on_instruction = interleave
        self.assertEqual(m.pop(), (OUTPUT, 0))
        self.assertEqual(extracted, [(OUTPUT + 84, 0)])
        self.assertEqual(m.output_words(), first)
        self.assertEqual(other.output_words(OUTPUT + 84), second)
        self.assertEqual(m.transport_count(), 0)
        self.assertFalse(m.transport_held or other.transport_held)


if __name__ == '__main__':
    unittest.main()
