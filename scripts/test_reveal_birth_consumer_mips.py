#!/usr/bin/env python3
"""Execute owned historical BQ84 consumption, never a native lifetime lease.

Real birth hooks, native segmented-list operations, deletion and node reuse run.
The raw services and opaque cleanup retain the preceding bounded substitutes;
deterministic CPU interleavings below are not a device scheduler simulation.
"""

import unittest

import reveal_birth_consumer_mips as core
import reveal_birth_consumer_stage as stage
import reveal_birth_queue_mips as queue
import reveal_registry_lifecycle_mips as lifecycle
import test_reveal_birth_queue_mips as previous
from test_reveal_birth_queue_mips import (
    BirthQueueMachine, QUEUE, TRANSPORT_MUTEX, FAULT, PAYLOAD, SOURCE,
    PAYLOAD_WORDS, APPEND, GET, REMOVE, LIFECYCLE, ENGINE, CONTROLLER,
    REGISTRY_MUTEX, PAINT_MUTEX, CODE, INPUT, STATE, BIND_STATE, OWNER_STATE,
    RAW_LOCK, RAW_UNLOCK, STACK, RETURN, MASK, SECOND_STACK)
from test_reveal_registry_lifecycle_mips import NAME, NATIVE_DELETE


OUTPUT = SOURCE + 0x400
OUTPUT_BYTES = 100
OUTPUT_MAGIC = int.from_bytes(b'BOBS', 'little')
OBSERVED_STATE, OBSERVED_SITE, OBSERVED_SP, OBSERVED_CALLER = 84, 88, 92, 96


class BirthConsumerMachine(BirthQueueMachine):
    """One real FIFO pop followed by emitted read-only historical comparison."""

    def __init__(self, image, *, registry_acquire_failure_holds=False,
                 registry_release_failure_releases=True, **options):
        super().__init__(image, **options)
        selected = {name: options[name] for name in (
            'capacity', 'lifecycle_capacity', 'owner_capacity', 'ticket_limit',
            'queue_capacity') if name in options}
        self.composition = stage.assemble(
            STATE, BIND_STATE, OWNER_STATE, CONTROLLER, REGISTRY_MUTEX,
            PAINT_MUTEX, CODE, LIFECYCLE, QUEUE, TRANSPORT_MUTEX, FAULT,
            transport_capacity=self.peek(QUEUE + 8), **selected)
        self.code = self.code_bytes = self.composition['code']
        self.labels = self.composition['labels']
        for name in ('owner', 'issuer', 'receipt', 'adapter', 'capture',
                     'lifecycle', 'retirement', 'birth_capture', 'birth_queue',
                     'birth_consumer'):
            setattr(self, name + '_labels', self.composition[name + '_labels'])
        self.bridge_labels = self.receipt_labels
        for pc, words in self.composition['coherent_hooks'].items():
            for index, word in enumerate(words):
                self.patches[pc + 4 * index] = word
        self.registry_acquire_failure_holds = registry_acquire_failure_holds
        self.registry_release_failure_releases = registry_release_failure_releases
        self.consumer_history_accesses, self.consumer_output_accesses = [], []
        self.clear_events()

    def tracked_access(self, kind, address, size):
        super().tracked_access(kind, address, size)
        if (hasattr(self, 'consumer_history_accesses')
                and LIFECYCLE < address + size
                and address < LIFECYCLE + lifecycle.memory_bytes(self.lifecycle_capacity)):
            self.consumer_history_accesses.append((
                kind, self.current_pc, address, size, self.registry_held,
                self.transport_held, self.paint_held))
        if (hasattr(self, 'consumer_output_accesses')
                and SOURCE < address + size and address < SOURCE + 0x1000):
            self.consumer_output_accesses.append((
                kind, self.current_pc, address, size, self.registry_held,
                self.transport_held, self.paint_held))

    def service(self, target):
        if self.r[4] != REGISTRY_MUTEX:
            return super().service(target)
        result = (self.acquire if target == RAW_LOCK else self.release) & MASK
        self.calls.append(target)
        self.raw_events.append((target, self.r[4], self.r[29], self.r[31], result))
        before = self.registry_held
        if (target == RAW_LOCK and (result == 0
                or getattr(self, 'registry_acquire_failure_holds', False))):
            self.registry_held = True
        if self.on_service is not None:
            self.on_service(self, target)
        self.hostile_result(result)
        if target == RAW_UNLOCK:
            released = (result == 0 or getattr(
                self, 'registry_release_failure_releases', True))
            self.registry_held = False if released else before

    def clear_events(self):
        super().clear_events()
        for name in ('consumer_history_accesses', 'consumer_output_accesses'):
            if hasattr(self, name):
                getattr(self, name).clear()

    def take(self, output=OUTPUT, *, controller=CONTROLLER,
             stack=STACK, caller=RETURN):
        self.r[29], self.r[31] = stack, caller
        self.r[4:6] = controller, output
        self.run_at(self.birth_consumer_labels['take'], caller)
        return self.r[2], self.r[3]

    def consumer_words(self, output=OUTPUT):
        return self.words_at(output, OUTPUT_BYTES // 4)

    def delete_at_stack(self, stack=SECOND_STACK):
        self.r[29], self.r[31] = stack, RETURN
        self.r[4:6] = CONTROLLER, NAME
        self.run_at(NATIVE_DELETE, RETURN)
        return self.r[2], self.r[3]

    def generated_output_writes(self, output=OUTPUT):
        return [event for event in self.consumer_output_accesses
                if event[0] == 'write' and output <= event[2] < output + OUTPUT_BYTES
                and CODE <= event[1] < CODE + len(self.code)
                and self.word(event[1]) >> 26 == 0x2B]


class BirthConsumerTests(unittest.TestCase):
    setUpClass = classmethod(previous.BirthQueueTests.setUpClass.__func__)
    prepared = previous.BirthQueueTests.prepared

    def machine(self, **options):
        return BirthConsumerMachine(self.image, **options)

    def queued(self, machine, *, source=SOURCE, words=PAYLOAD_WORDS):
        expected = self.prepared(machine, source=source, words=words)
        wanted_count = machine.transport_count() + 1
        self.assertEqual(machine.enqueue(source), (wanted_count, 0))
        machine.clear_events()
        return expected

    def expected(self, queued, row):
        return (OUTPUT_MAGIC, *queued[1:], *row[10:14])

    def assert_separate_checked_scopes(self, machine):
        self.assertTrue(machine.transport_accesses)
        self.assertTrue(all(event[4] and not event[5] and not event[6]
                            for event in machine.transport_accesses))
        self.assertTrue(machine.consumer_history_accesses)
        self.assertTrue(all(event[0] == 'read' and event[4]
                            and not event[5] and not event[6]
                            for event in machine.consumer_history_accesses))
        self.assertEqual([(event[0], event[1]) for event in machine.raw_events], [
            (RAW_LOCK, TRANSPORT_MUTEX), (RAW_UNLOCK, TRANSPORT_MUTEX),
            (RAW_LOCK, REGISTRY_MUTEX), (RAW_UNLOCK, REGISTRY_MUTEX)])
        for name in ('journal_accesses', 'binding_accesses', 'owner_accesses',
                     'paint_events', 'cleanup_services', 'lifecycle_requests'):
            self.assertEqual(getattr(machine, name), [], name)
        self.assertFalse(machine.transport_held or machine.registry_held
                         or machine.paint_held)

    def test_actual_birth_native_fifo_pop_and_read_only_history_export(self):
        m = self.machine()
        queued = self.queued(m)
        before, row = m.lifecycle_snapshot(), m.lifecycle_record()
        engine = m.words_at(ENGINE, 16)
        self.assertEqual(m.take(), (OUTPUT, 0))
        self.assertEqual(m.consumer_words(), self.expected(queued, row))
        self.assertEqual(m.transport_count(), 0)
        self.assertEqual(m.lifecycle_snapshot(), before)
        self.assertEqual(m.words_at(ENGINE, 16), engine)
        self.assertIn(GET, m.trace)
        self.assertIn(REMOVE, m.trace)
        self.assert_separate_checked_scopes(m)
        self.assertFalse(any(ENGINE <= address < ENGINE + 0x100
                             for address, _ in m.reads))

    def test_retirement_selected_row_is_exported_as_history_not_refused_as_dead(self):
        m = self.machine()
        queued = self.queued(m)
        m.delete_native()
        row = m.lifecycle_record()
        self.assertEqual(row[10], lifecycle.RETIREMENT_SELECTED)
        m.clear_events()
        self.assertEqual(m.take(), (OUTPUT, 0))
        self.assertEqual(m.consumer_words(), self.expected(queued, row))
        self.assert_separate_checked_scopes(m)

    def test_exact_old_token_is_not_replaced_by_same_address_newest_birth(self):
        m = self.machine(capacity=1, lifecycle_capacity=3)
        first = self.queued(m)
        node = m.allocations[-1]
        m.delete_native()
        first_row = m.lifecycle_record()
        m.reuse_node = node
        second = self.queued(m, source=SOURCE + 48,
                             words=(*PAYLOAD_WORDS[:-1], 99))
        second_row = m.lifecycle_record(1)
        self.assertEqual(first[4:6], second[4:6])
        self.assertEqual((first[1], second[1]), (1, 2))
        self.assertEqual(m.take(), (OUTPUT, 0))
        self.assertEqual(m.consumer_words(), self.expected(first, first_row))
        self.assertEqual(m.take(OUTPUT + 100), (OUTPUT + 100, 0))
        self.assertEqual(m.consumer_words(OUTPUT + 100),
                         self.expected(second, second_row))
        self.assertEqual(m.transport_count(), 0)

    def test_complete_private_queue_snapshot_precedes_registry_acquire(self):
        m = self.machine()
        queued = self.queued(m)
        row = m.lifecycle_record()
        moments = []

        def observe(machine, target):
            if target == RAW_LOCK and machine.r[4] == REGISTRY_MUTEX:
                moments.append((machine.transport_count(), machine.transport_held,
                                machine.consumer_words()))
                # The retained native head was already removed. Its bytes and
                # former source are not a borrowed input to the R comparison.
                for pointer, count in ((SOURCE, 12),
                                       (machine.transport_element(), 21)):
                    for index in range(count):
                        machine.put(pointer + 4 * index, MASK, 4)

        m.on_service = observe
        self.assertEqual(m.take(), (OUTPUT, 0))
        self.assertEqual(moments, [(0, False, (0,) * 25)])
        self.assertEqual(m.consumer_words(), self.expected(queued, row))
        ordered = ('before_pop', 'after_pop', 'snapshot_done', 'before_lock',
                   'history_snapshot_done', 'before_release', 'before_export')
        positions = [m.trace.index(m.birth_consumer_labels[name]) for name in ordered]
        self.assertEqual(positions, sorted(positions))

    def test_empty_native_queue_never_acquires_registry_or_reads_history(self):
        m = self.machine()
        self.assertEqual(m.take(), (0, 0))
        self.assertEqual(m.consumer_words(), (0,) * 25)
        self.assertEqual(m.consumer_history_accesses, [])
        self.assertEqual([(event[0], event[1]) for event in m.raw_events], [
            (RAW_LOCK, TRANSPORT_MUTEX), (RAW_UNLOCK, TRANSPORT_MUTEX)])
        self.assertNotIn(GET, m.trace)
        self.assertEqual(m.generated_output_writes(), [])

    def test_full_healthy_history_still_exports_existing_exact_birth(self):
        m = self.machine(lifecycle_capacity=1)
        queued = self.queued(m)
        row = m.lifecycle_record()
        self.assertEqual(m.take(), (OUTPUT, 0))
        self.assertEqual(m.consumer_words(), self.expected(queued, row))
        self.assertEqual(m.lifecycle_header(), (1, 0, 0, 0))

    def test_owned_payload_words_other_than_engine_are_uninterpreted_scalars(self):
        m = self.machine()
        payload = tuple(ENGINE if index == 2 else MASK - index for index in range(9))
        queued = self.queued(m, words=payload)
        self.assertEqual(m.take(), (OUTPUT, 0))
        self.assertEqual(m.consumer_words()[12:21], payload)
        self.assertEqual(m.consumer_words()[1:12], queued[1:12])

    def test_historical_node_engine_and_native_sp_are_never_followed(self):
        for offset in (queue.NODE, queue.ENGINE, queue.NATIVE_SP):
            for value in (0, 1, MASK):
                with self.subTest(offset=offset, value=value):
                    m = self.machine()
                    queued = list(self.queued(m))
                    queued[offset // 4] = value
                    m.put(m.transport_element() + offset, value, 4)
                    m.put(LIFECYCLE + lifecycle.HEADER_BYTES + offset, value, 4)
                    if offset == queue.ENGINE:
                        queued[(queue.PAYLOAD + queue.PAYLOAD_ENGINE) // 4] = value
                        m.put(m.transport_element() + queue.PAYLOAD
                              + queue.PAYLOAD_ENGINE, value, 4)
                    row = m.lifecycle_record()
                    m.clear_events()
                    self.assertEqual(m.take(), (OUTPUT, 0))
                    self.assertEqual(m.consumer_words(), self.expected(queued, row))
                    self.assertFalse(any(address == value for address, _ in m.reads))

    def test_export_magic_is_last_and_all_twenty_five_stores_follow_r_release(self):
        m = self.machine()
        queued = self.queued(m)
        row = m.lifecycle_record()
        self.assertEqual(m.take(), (OUTPUT, 0))
        writes = m.generated_output_writes()
        self.assertEqual(len(writes), 25)
        self.assertEqual(writes[-1][2], OUTPUT)
        self.assertTrue(all(not any(event[4:]) for event in writes))
        self.assertEqual(m.consumer_words(), self.expected(queued, row))

    def test_consumer_preserves_callee_saved_registers_sp_ra_and_hilo(self):
        m = self.machine()
        self.queued(m)
        m.r[29], m.r[31] = STACK, RETURN
        indices = (*range(16, 24), 28, 29, 30, 31)
        expected = tuple(m.r[index] for index in indices), m.hi, m.lo
        self.assertEqual(m.take(), (OUTPUT, 0))
        self.assertEqual((tuple(m.r[index] for index in indices), m.hi, m.lo), expected)

    def test_post_r_release_deletion_does_not_turn_exported_snapshot_into_liveness(self):
        m = self.machine()
        queued = self.queued(m)
        row = m.lifecycle_record()
        node = queued[4]
        other = m.fork_cpu()
        deleted = []

        def interleave(machine, pc):
            if pc == machine.birth_consumer_labels['before_export'] and not deleted:
                deleted.append(other.delete_at_stack())

        m.on_instruction = interleave
        self.assertEqual(m.take(), (OUTPUT, 0))
        self.assertEqual(len(deleted), 1)
        self.assertIn(node, other.freed)
        self.assertEqual(m.lifecycle_record()[10], lifecycle.RETIREMENT_SELECTED)
        self.assertEqual(m.consumer_words(), self.expected(queued, row))
        self.assertEqual(m.consumer_words()[21], lifecycle.NO_RETIREMENT_OBSERVED)
        self.assertEqual(m.words_at(CONTROLLER + 0x34, 2), (CONTROLLER + 0x34,) * 2)

    def test_missed_native_delete_and_rebirth_gap_is_not_repaired_by_exact_token(self):
        m = self.machine(capacity=1, lifecycle_capacity=3)
        queued = self.queued(m)
        row = m.lifecycle_record()
        node = queued[4]
        m.acquire = 22
        m.delete_native()
        m.reuse_node = node
        self.assertEqual(m.register(), 0)
        self.assertEqual(m.lifecycle_record(), row)
        self.assertEqual(m.lifecycle_header(), (1, 0, 0, 0))
        m.acquire = 0
        m.clear_events()
        self.assertEqual(m.take(), (OUTPUT, 0))
        self.assertEqual(m.consumer_words(), self.expected(queued, row))
        # This is a diagnostic of the observed old birth, not proof that the
        # currently linked same-address native allocation is that incarnation.
        self.assertEqual(m.words_at(CONTROLLER + 0x34, 2), (node, node))

    def test_two_cpus_own_independent_snapshots_and_may_export_out_of_order(self):
        m = self.machine()
        first = self.queued(m)
        first_row = m.lifecycle_record()
        second = self.queued(m, source=SOURCE + 48,
                             words=(*PAYLOAD_WORDS[:-1], 77))
        second_row = m.lifecycle_record(1)
        other = m.fork_cpu()
        observed = []

        def interleave(machine, pc):
            if pc == machine.birth_consumer_labels['before_export'] and not observed:
                observed.append(other.take(OUTPUT + 100, stack=SECOND_STACK))

        m.on_instruction = interleave
        self.assertEqual(m.take(), (OUTPUT, 0))
        self.assertEqual(observed, [(OUTPUT + 100, 0)])
        self.assertEqual(m.consumer_words(), self.expected(first, first_row))
        self.assertEqual(m.consumer_words(OUTPUT + 100), self.expected(second, second_row))
        self.assertEqual(m.transport_count(), 0)

    def test_standalone_history_ending_at_unsigned_limit_never_dereferences_zero(self):
        # Only the new consumer's history is relocated here. The producer's
        # actual observed row is copied into this independently retained test
        # history while quiescent; this is not a new installation/coverage claim.
        for capacity, dirty_tail in ((1, False), (16, False), (16, True)):
            with self.subTest(capacity=capacity, dirty_tail=dirty_tail):
                m = self.machine(lifecycle_capacity=capacity)
                queued = self.queued(m)
                row = m.lifecycle_record()
                size = lifecycle.memory_bytes(capacity)
                high_history = (1 << 32) - size
                m.map(high_history, size)
                data, offset = m.region(LIFECYCLE, size)
                m.bytes(high_history, bytes(data[offset:offset + size]))
                if dirty_tail:
                    m.put(MASK - 3, 1, 4)
                prefix = m.composition['birth_consumer_prefix_code_bytes']
                emitted, labels = core.assemble(
                    STATE, BIND_STATE, OWNER_STATE, CONTROLLER, REGISTRY_MUTEX,
                    PAINT_MUTEX, high_history, CODE + prefix, QUEUE,
                    TRANSPORT_MUTEX, FAULT, m.birth_queue_labels['pop'],
                    m.capture_labels['native_return'], lifecycle_capacity=capacity,
                    protected_code=(CODE, len(m.code)))
                self.assertEqual(len(emitted), len(m.code) - prefix)
                m.code = m.code_bytes = m.code[:prefix] + emitted
                m.birth_consumer_labels = labels
                m.clear_events()
                self.assertEqual(m.take(), (0, 0) if dirty_tail else (OUTPUT, 0))
                self.assertFalse(any(address == 0 for address, _ in m.reads))
                self.assertTrue(any(address == MASK - 3 for address, _ in m.reads))
                self.assertEqual(m.transport_count(), 0)
                self.assertEqual(m.consumer_words(), (0,) * 25 if dirty_tail
                                 else self.expected(queued, row))


if __name__ == '__main__':
    unittest.main()
