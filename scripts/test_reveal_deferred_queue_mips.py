#!/usr/bin/env python3
"""Execute a separate retained68 FIFO through emitted checked T wrappers.

Only the fixture constructs the typed native list and supplies initialized
mutex semantics. Table/chunk/controller/engine retention and all cooperating
access using these same wrappers remain premises. The blocking two-CPU case
uses ordinary Python locks, not a claim about the native scheduler or device.
Extraction is not rendering acknowledgement or global exactly-once delivery.
"""

import copy
import hashlib
import threading
import unittest

import reveal_deferred_envelope_mips as envelopes
import reveal_deferred_queue_mips as core
import reveal_deferred_queue_stage as stage
import reveal_registry_receipt_mips as receipt
import test_folderfollow_reveal_static_contract as source
from test_reveal_deferred_envelope_mips import (
    DeferredEnvelopeMachine, ENVELOPE, WORK, APPEND, GET, REMOVE)
from test_reveal_owner_carrier_mips import PAYLOAD
from test_reveal_registry_release_mips import OUTPUT
from test_reveal_registry_owner_mips import (
    STATE, BIND_STATE, OWNER_STATE, CODE, CONTROLLER, REGISTRY_MUTEX,
    PAINT_MUTEX, RAW_LOCK, RAW_UNLOCK, STACK, RETURN, MASK)


TRANSPORT_MUTEX, FAULT = 0x1F20400, 0x1FE0000
SECOND_STACK = STACK + 0x6000


class DeferredQueueMachine(DeferredEnvelopeMachine):
    """Actual list bodies; bounded hostile raw services, independently owned SP."""

    def __init__(self, image, *, transport_acquire=0, transport_release=0,
                 transport_acquire_failure_holds=False,
                 transport_release_failure_releases=True,
                 transport_capacity=None, **options):
        super().__init__(image, **options)
        allocated = self.peek(self.deferred_list + 8)
        transport_capacity = (allocated if transport_capacity is None
                              else transport_capacity)
        self.composition = stage.assemble(
            STATE, BIND_STATE, OWNER_STATE, CONTROLLER, REGISTRY_MUTEX,
            PAINT_MUTEX, CODE, self.deferred_list, TRANSPORT_MUTEX, FAULT,
            capacity=options.get('capacity', 16),
            owner_capacity=options.get('owner_capacity', 16),
            ticket_limit=options.get('ticket_limit', core.MAX_TICKET),
            queue_capacity=options.get('queue_capacity', 64),
            transport_capacity=transport_capacity)
        self.code = self.code_bytes = self.composition['code']
        self.labels = self.composition['labels']
        for name in ('owner_labels', 'issuer_labels', 'receipt_labels',
                     'adapter_labels', 'capture_labels', 'envelope_labels',
                     'queue_labels'):
            setattr(self, name, self.composition[name])
        self.bridge_labels = self.receipt_labels
        for pc, words in {**receipt.hook_words(self.receipt_labels),
                          **self.composition['release_hooks']}.items():
            for index, word in enumerate(words):
                self.patches[pc + 4 * index] = word
        self.map(TRANSPORT_MUTEX, 24)
        self.map(FAULT, 4)
        self.transport_acquire = transport_acquire
        self.transport_release = transport_release
        self.transport_acquire_failure_holds = transport_acquire_failure_holds
        self.transport_release_failure_releases = transport_release_failure_releases
        self.transport_held = False
        table = self.peek(self.deferred_list)
        chunks = allocated // 10
        self.transport_ranges = [(self.deferred_list, 56), (table, chunks * 4),
                                 (FAULT, 4)]
        self.transport_ranges.extend((self.peek(table + 4 * i), 680)
                                     for i in range(chunks))
        self.transport_events, self.guard_events = [], []
        self.blocking_mutexes = None
        self.cpu_name = 'first'
        self.clear_events()

    def tracked_access(self, kind, address, size):
        super().tracked_access(kind, address, size)
        if (hasattr(self, 'transport_ranges')
                and any(start < address + size and address < start + length
                        for start, length in self.transport_ranges)):
            self.guard_events.append(('access', kind, self.current_pc,
                                      address, size, self.transport_held,
                                      self.registry_held, self.paint_held))

    def external(self, target):
        if target == 0xA5B440:
            # Native memcpy is a bounded substitute. Record both bulk
            # accesses explicitly: its implementation bypasses get/put.
            self.tracked_access('read', self.r[5], self.r[6])
            self.tracked_access('write', self.r[4], self.r[6])
        return super().external(target)

    def service(self, target):
        pointer = self.r[4]
        mutex = (self.blocking_mutexes.get(pointer)
                 if getattr(self, 'blocking_mutexes', None) is not None else None)
        if mutex is not None and target == RAW_LOCK:
            if hasattr(self, 'before_blocking_acquire'):
                self.before_blocking_acquire(self, pointer)
            if not mutex.acquire(timeout=5):
                raise AssertionError('bounded blocking-mutex fixture timed out')
        try:
            if pointer != TRANSPORT_MUTEX:
                return super().service(target)
            result = (self.transport_acquire if target == RAW_LOCK
                      else self.transport_release) & MASK
            self.calls.append(target)
            event = (target, pointer, self.r[29], self.r[31], result)
            self.raw_events.append(event)
            self.transport_events.append(event)
            if (target == RAW_LOCK
                    and (result == 0 or self.transport_acquire_failure_holds)):
                self.transport_held = True
            self.guard_events.append(('raw', target, pointer, result,
                                      self.transport_held))
            if self.on_service is not None:
                self.on_service(self, target)
            self.hostile_result(result)
            if (target == RAW_UNLOCK
                    and (result == 0 or self.transport_release_failure_releases)):
                self.transport_held = False
        finally:
            if mutex is not None and target == RAW_UNLOCK:
                mutex.release()

    def clear_events(self):
        super().clear_events()
        for name in ('transport_events', 'guard_events'):
            if hasattr(self, name):
                getattr(self, name).clear()

    def enqueue(self, envelope=ENVELOPE, *, controller=CONTROLLER,
                stack=STACK, caller=RETURN):
        self.r[29], self.r[31] = stack, caller
        self.r[4:6] = controller, envelope
        self.run_at(self.queue_labels['enqueue'], caller)
        return self.r[2], self.r[3]

    def pop_dispatch(self, *, controller=CONTROLLER, stack=STACK, caller=RETURN):
        self.r[29], self.r[31], self.r[4] = stack, caller, controller
        self.run_at(self.queue_labels['pop_dispatch'], caller)
        return self.r[2], self.r[3]

    def private(self, stack=STACK):
        return stack - core.FRAME + core.PRIVATE

    def fork_cpu(self, name):
        """Share retained memory, code and locks, never registers/SP/event lists."""
        other = copy.copy(self)
        other.r = self.r.copy()
        for name_of_list, value in tuple(vars(self).items()):
            if isinstance(value, list) and name_of_list != 'r':
                setattr(other, name_of_list, [])
        other.transport_ranges = self.transport_ranges
        other.transport_held = other.registry_held = other.paint_held = False
        other.on_instruction = other.on_service = None
        other.before_instruction = other.instruction
        other.cpu_name = name
        return other


class DeferredQueueTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = source.SOURCE.read_bytes()
        digest = hashlib.sha256(cls.image).hexdigest()
        if digest != source.SOURCE_SHA256 or len(cls.image) != source.SOURCE_SIZE:
            raise AssertionError(f'unrecognized reference: {digest}')

    def machine(self, **options):
        return DeferredQueueMachine(self.image, **options)

    def prepared(self, machine, *, output=ENVELOPE, captured=OUTPUT,
                 words=PAYLOAD):
        self.assertEqual(machine.invoke_register(output=captured), (0, captured))
        self.assertEqual(machine.pack_payload(words, captured=captured, output=output),
                         (output, 0))
        self.assertEqual(machine.captured_carriers, [])
        return output

    def assert_guarded(self, machine):
        accesses = [event for event in machine.guard_events if event[0] == 'access']
        self.assertTrue(accesses)
        self.assertTrue(all(event[5] for event in accesses), accesses)
        self.assertTrue(all(not event[6] and not event[7] for event in accesses))

    def test_emitted_enqueue_and_pop_execute_actual_typed_native_fifo(self):
        m = self.machine()
        self.prepared(m)
        original = m.envelope_words()
        m.clear_events()
        self.assertEqual(m.enqueue(), (1, 0))
        self.assertEqual(m.envelope_words(), original)  # source not consumed
        self.assertEqual(m.transport_count(), 1)
        self.assertEqual(m.pop_dispatch(), (2, 0))
        self.assertEqual(m.transport_count(), 0)
        self.assertEqual(m.words_at(m.head(), 11), (*PAYLOAD, 2, 1))
        self.assertEqual(m.peek(m.deferred_list + 0x10), 68)
        self.assertEqual(m.peek(m.paint_list + 0x10), 44)
        for target in (APPEND, GET, REMOVE, 0x455BC0):
            self.assertIn(target, m.trace)
        self.assert_guarded(m)
        self.assertFalse(m.transport_held)

    def test_private_pack_precedes_lock_and_protects_against_source_change(self):
        m = self.machine()
        self.prepared(m)
        expected = m.envelope_words()

        def mutate(machine, target):
            if target == RAW_LOCK and machine.r[4] == TRANSPORT_MUTEX:
                for offset in range(0, 68, 4):
                    machine.put(ENVELOPE + offset, MASK, 4)

        m.on_service = mutate
        self.assertEqual(m.enqueue(), (1, 0))
        self.assertEqual(m.envelope_words(m.transport_element()), expected)
        self.assertLess(m.trace.index(m.envelope_labels['pack']),
                        m.trace.index(m.queue_labels['enqueue_before_lock']))

    def test_copy_remove_release_dispatch_order_does_not_borrow_reused_head(self):
        m = self.machine()
        self.prepared(m)
        changed = (*PAYLOAD[:-1], 99)
        self.assertEqual(m.pack_payload(changed, output=ENVELOPE + 68),
                         (ENVELOPE + 68, 0))
        self.assertEqual(m.enqueue(), (1, 0))
        self.assertEqual(m.enqueue(ENVELOPE + 68), (2, 0))
        head = m.transport_element()
        m.clear_events()
        self.assertEqual(m.pop_dispatch(), (2, 0))
        self.assertEqual(m.envelope_words(head)[-1], 99)
        self.assertEqual(m.words_at(m.head(), 9), PAYLOAD)
        ordered = (GET, m.envelope_labels['pack'], REMOVE,
                   m.queue_labels['before_release'],
                   m.queue_labels['before_dispatch'],
                   m.envelope_labels['dispatch'])
        self.assertEqual(sorted(m.trace.index(pc) for pc in ordered),
                         [m.trace.index(pc) for pc in ordered])
        self.assert_guarded(m)
        first_registry = next(index for index, event in enumerate(m.raw_events)
                              if event[1] == REGISTRY_MUTEX)
        self.assertEqual([(event[0], event[1])
                          for event in m.raw_events[:first_registry]],
                         [(RAW_LOCK, TRANSPORT_MUTEX),
                          (RAW_UNLOCK, TRANSPORT_MUTEX)])

    def test_empty_still_checks_and_releases_transport_guard_without_publisher(self):
        m = self.machine()
        self.assertEqual(m.pop_dispatch(), (0, 0))
        self.assertEqual([(event[0], event[1]) for event in m.raw_events],
                         [(RAW_LOCK, TRANSPORT_MUTEX), (RAW_UNLOCK, TRANSPORT_MUTEX)])
        self.assertNotIn(GET, m.trace)
        self.assertNotIn(m.envelope_labels['dispatch'], m.trace)
        self.assert_guarded(m)

    def test_preallocated_twenty_and_forty_slots_cross_segment_boundaries(self):
        for requested, expected in ((16, 20), (32, 40)):
            with self.subTest(requested=requested):
                m = self.machine(deferred_capacity=requested)
                self.prepared(m)
                self.assertEqual(m.peek(m.deferred_list + 8), expected)
                for index in range(14):
                    pointer = ENVELOPE + index * 68
                    if index:
                        self.assertEqual(m.pack_payload((*PAYLOAD[:-1], index),
                                                       output=pointer), (pointer, 0))
                    self.assertEqual(m.enqueue(pointer), (index + 1, 0))
                self.assertNotEqual(m.transport_element(10), m.transport_element() + 680)
                for index in range(14):
                    self.assertEqual(m.pop_dispatch(), (index + 2, index))
                    self.assertEqual(m.words_at(m.queue_element(index), 9),
                                     (*PAYLOAD[:-1], index))
                self.assertEqual(m.transport_count(), 0)
                self.assert_guarded(m)

    def test_full_refuses_before_native_append_or_growth(self):
        m = self.machine(deferred_capacity=16)
        self.prepared(m)
        for index in range(20):
            self.assertEqual(m.enqueue(), (index + 1, 0))
        before = m.next_allocation
        m.clear_events()
        self.assertEqual(m.enqueue(), (0, 0))
        self.assertEqual(m.transport_count(), 20)
        self.assertEqual(m.next_allocation, before)
        self.assertNotIn(APPEND, m.trace)
        self.assertNotIn(0x455980, m.trace)
        self.assertEqual(m.peek(FAULT), 0)
        self.assert_guarded(m)

    def test_old_generation_denial_cannot_adopt_equal_engine_replacement(self):
        m = self.machine()
        self.prepared(m)
        self.assertEqual(m.enqueue(), (1, 0))
        self.assertEqual(m.retire(1), (1, 0))
        self.prepared(m, captured=OUTPUT + 32, output=ENVELOPE + 68)
        self.assertEqual(m.outwords()[3], m.outwords(OUTPUT + 32)[3])
        self.assertEqual(m.enqueue(ENVELOPE + 68), (2, 0))
        self.assertEqual(m.pop_dispatch(), (0, 0))
        self.assertEqual(m.count(), 0)
        self.assertEqual(m.pop_dispatch(), (3, 0))
        self.assertEqual(m.words_at(m.head(), 11), (*PAYLOAD, 3, 2))

    def test_paint_backpressure_loses_extracted_attempt_without_queue_retry(self):
        m = self.machine(queue_capacity=1)
        self.prepared(m)
        self.assertEqual(m.enqueue(), (1, 0))
        self.assertEqual(m.enqueue(), (2, 0))
        self.assertEqual(m.pop_dispatch(), (2, 0))
        self.assertEqual(m.pop_dispatch(), (0, 0))
        self.assertEqual(m.transport_count(), 0)
        self.assertEqual(m.count(), 1)
        self.assertEqual(m.claim()[1], 2)
        self.assertEqual(m.complete(2), (1, 0))
        self.assertEqual(m.pop_dispatch(), (0, 0))
        self.assertEqual(m.count(), 0)

    def test_cloned_ready_source_is_not_a_global_deduplication_key(self):
        m = self.machine()
        self.prepared(m)
        self.assertEqual(m.enqueue(), (1, 0))
        self.assertEqual(m.enqueue(), (2, 0))
        self.assertEqual(m.pop_dispatch(), (2, 0))
        self.assertEqual(m.pop_dispatch(), (3, 1))
        self.assertEqual(m.count(), 2)

    def test_no_registry_or_paint_call_while_transport_mutex_is_held(self):
        m = self.machine()
        self.prepared(m)
        self.assertEqual(m.enqueue(), (1, 0))
        observations = []

        def observe(machine, target):
            if machine.r[4] in (REGISTRY_MUTEX, PAINT_MUTEX):
                observations.append(machine.transport_held)

        m.on_service = observe
        self.assertEqual(m.pop_dispatch(), (2, 0))
        self.assertTrue(observations)
        self.assertEqual(observations, [False] * len(observations))

    def test_every_successful_transport_acquire_has_one_matching_release(self):
        m = self.machine()
        self.prepared(m)
        m.clear_events()
        self.assertEqual(m.enqueue(), (1, 0))
        self.assertEqual(m.pop_dispatch(), (2, 0))
        self.assertEqual(m.pop_dispatch(), (0, 0))
        self.assertEqual([event[0] for event in m.transport_events],
                         [RAW_LOCK, RAW_UNLOCK] * 3)
        for _, pointer, stack, caller, status in m.transport_events:
            self.assertEqual(pointer, TRANSPORT_MUTEX)
            self.assertEqual(stack % 8, 0)
            self.assertTrue(CODE <= caller < CODE + len(m.code))
            self.assertEqual(status, 0)

    def test_wrapper_preserves_callee_registers_sp_ra_hilo_under_hostile_services(self):
        for operation in ('enqueue', 'pop', 'empty', 'full', 'acquire_error',
                          'release_error', 'fault'):
            with self.subTest(operation=operation):
                m = self.machine()
                self.prepared(m)
                if operation in ('pop', 'release_error'):
                    self.assertEqual(m.enqueue(), (1, 0))
                if operation == 'full':
                    m.put(m.deferred_list + 0xC, 40, 4)
                if operation == 'acquire_error':
                    m.transport_acquire = 22
                if operation == 'release_error':
                    m.transport_release = 22
                if operation == 'fault':
                    m.put(FAULT, 1, 4)
                saved = {reg: 0x77900000 + reg
                         for reg in (*range(16, 24), 28, 30)}
                for reg, value in saved.items():
                    m.r[reg] = value
                m.hi, m.lo = 0x12345678, 0xABCDEF01
                result = (m.enqueue() if operation in ('enqueue', 'full',
                          'acquire_error', 'fault') else m.pop_dispatch())
                expected = ((1, 0) if operation == 'enqueue' else
                            (2, 0) if operation == 'pop' else
                            (0, 22) if operation.endswith('error') else (0, 0))
                self.assertEqual(result, expected)
                self.assertEqual({reg: m.r[reg] for reg in saved}, saved)
                self.assertEqual((m.r[29], m.r[31]), (STACK, RETURN))
                self.assertEqual((m.hi, m.lo), (0x12345678, 0xABCDEF01))

    def test_two_cpus_block_on_same_guard_and_extract_distinct_owned_heads(self):
        # Deliberately pause CPU1 at release while CPU2 enters a real blocking
        # *fixture* lock. This is not contention-as-an-error or native pthread
        # scheduler proof. Independent stacks/registers share retained memory.
        m = self.machine()
        self.prepared(m)
        self.assertEqual(m.pack_payload((*PAYLOAD[:-1], 99), output=ENVELOPE + 68),
                         (ENVELOPE + 68, 0))
        self.assertEqual(m.enqueue(), (1, 0))
        self.assertEqual(m.enqueue(ENVELOPE + 68), (2, 0))
        m.blocking_mutexes = {pointer: threading.Lock() for pointer in
                             (TRANSPORT_MUTEX, REGISTRY_MUTEX, PAINT_MUTEX)}
        second = m.fork_cpu('second')
        self.assertIs(second.regions, m.regions)
        self.assertIsNot(second.r, m.r)
        first_at_release, second_waiting, allow_release = (
            threading.Event(), threading.Event(), threading.Event())
        failures, results, heads = [], {}, {}

        def before_acquire(machine, pointer):
            if machine is second and pointer == TRANSPORT_MUTEX:
                second_waiting.set()

        second.before_blocking_acquire = before_acquire

        def first_service(machine, target):
            if target == RAW_UNLOCK and machine.r[4] == TRANSPORT_MUTEX:
                first_at_release.set()
                if not allow_release.wait(5):
                    raise AssertionError('test did not release first CPU')

        m.on_service = first_service

        def record_head(machine, pc):
            if pc == machine.queue_labels['after_get']:
                heads[machine.cpu_name] = machine.r[2]

        m.on_instruction = second.on_instruction = record_head

        def run(machine, stack):
            try:
                results[machine.cpu_name] = machine.pop_dispatch(stack=stack)
            except BaseException as error:
                failures.append(error)

        m.clear_events()
        threads = [threading.Thread(target=run, args=(m, STACK)),
                   threading.Thread(target=run, args=(second, SECOND_STACK))]
        try:
            threads[0].start()
            self.assertTrue(first_at_release.wait(5))
            threads[1].start()
            self.assertTrue(second_waiting.wait(5))
            self.assertNotIn('second', results)
            self.assertEqual(second.guard_events, [])
        finally:
            allow_release.set()
            for thread in threads:
                if thread.ident is not None:
                    thread.join(10)
        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual(failures, [])
        self.assertEqual(m.transport_count(), 0)
        self.assertEqual(m.count(), 2)
        self.assertEqual(set(result[0] for result in results.values()), {2, 3})
        self.assertEqual(sorted(m.words_at(m.queue_element(i), 9)[-1]
                                for i in range(2)), [0, 99])
        # REMOVE reuses the numerical head address, so distinctness is in the
        # immutable private snapshots, not the address returned by GET.
        self.assertEqual(len(heads), 2)
        self.assertEqual(m.envelope_words(m.private())[-1], 0)
        self.assertEqual(m.envelope_words(second.private(SECOND_STACK))[-1], 99)
        self.assert_guarded(m)
        self.assert_guarded(second)


if __name__ == '__main__':
    unittest.main()
