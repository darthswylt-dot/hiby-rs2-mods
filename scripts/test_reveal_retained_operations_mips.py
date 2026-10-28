#!/usr/bin/env python3
"""Run bounded retained-operation accounting, not a native reference counter.

The real first constructor and its emitted capture produce the GCAP bytes.
The new emitted entries manage a separate native 72-byte FIFO and the existing
checked paint44 entries. Python only supplies owned memory, bounded raw/heap
services and observations; it never implements lifecycle state transitions.
All native controller/engine/resource/callback graph storage remains externally
retained. Local quiescence is not authority to free any native allocation.
"""

import hashlib
import unittest

import reveal_creation_capture_mips as capture
import reveal_paint_retirement_mips as paint
import reveal_registry_receipt_mips as receipt
import reveal_retained_operations_mips as core
import reveal_retained_operations_stage as stage
import test_folderfollow_reveal_static_contract as source
from test_reveal_constructor_capture_mips import (
    ConstructorCaptureMachine, OUTPUT, RESOURCE, REQUEST_CALLBACK,
    REQUEST_CONTEXT, NATIVE_CONSTRUCTOR)
from test_reveal_deferred_envelope_mips import ENVELOPE, FACTORY, APPEND, GET, REMOVE
from test_reveal_deferred_queue_mips import TRANSPORT_MUTEX, FAULT, SECOND_STACK
from test_reveal_registry_owner_mips import (
    STATE, BIND_STATE, OWNER_STATE, CODE, CONTROLLER, REGISTRY_MUTEX,
    PAINT_MUTEX, RAW_LOCK, RAW_UNLOCK, STACK, RETURN, MASK)


LEDGER, RETAINED_MUTEX, BUNDLE = 0x1F40000, 0x1F20500, 0x1F35000
HEADER_BYTES, OP_BYTES = 64, 16
UNBOUND, OPEN, CLOSED = 0, 1, 2
RESERVED, QUEUED, EXTRACTED, PUBLISHED, ACKING, DONE = range(1, 7)


class RetainedOperationsMachine(ConstructorCaptureMachine):
    """Actual emitted operations over native FIFO72; no Python lease oracle."""

    def __init__(self, image, *, operation_capacity=16, retained_capacity=40,
                 retained_acquire=0, retained_release=0,
                 retained_acquire_failure_holds=False,
                 retained_release_failure_releases=True, **options):
        super().__init__(image, **options)
        self.operation_capacity = operation_capacity
        self.retained_list = self.stock(FACTORY, retained_capacity, 72)
        if not self.retained_list:
            raise AssertionError('native retained72 FIFO construction failed')
        allocated = self.peek(self.retained_list + 8)
        self.composition = stage.assemble(
            STATE, BIND_STATE, OWNER_STATE, CONTROLLER, REGISTRY_MUTEX,
            PAINT_MUTEX, CODE, self.deferred_list, TRANSPORT_MUTEX, FAULT,
            LEDGER, self.retained_list, RETAINED_MUTEX,
            capacity=options.get('capacity', 16),
            owner_capacity=options.get('owner_capacity', 16),
            ticket_limit=options.get('ticket_limit', paint.MAX_TICKET),
            queue_capacity=options.get('queue_capacity', 64),
            transport_capacity=options.get(
                'transport_capacity', self.peek(self.deferred_list + 8)),
            operation_capacity=operation_capacity, retained_capacity=allocated)
        self.code = self.code_bytes = self.composition['code']
        self.labels = self.composition['labels']
        for name in ('owner_labels', 'issuer_labels', 'receipt_labels',
                     'adapter_labels', 'capture_labels', 'envelope_labels',
                     'queue_labels', 'constructor_labels', 'retained_labels'):
            setattr(self, name, self.composition[name])
        self.bridge_labels = self.receipt_labels
        for pc, words in {
                **receipt.hook_words(self.receipt_labels),
                **self.composition['release_hooks'],
                **self.composition['constructor_hooks']}.items():
            for index, word in enumerate(words):
                self.patches[pc + 4 * index] = word
        self.map(LEDGER, HEADER_BYTES + OP_BYTES * operation_capacity)
        self.map(RETAINED_MUTEX, 24)
        self.map(BUNDLE, 0x1000)
        self.retained_acquire, self.retained_release = retained_acquire, retained_release
        self.retained_acquire_failure_holds = retained_acquire_failure_holds
        self.retained_release_failure_releases = retained_release_failure_releases
        self.retained_held = False
        table, chunks = self.peek(self.retained_list), allocated // 10
        self.retained_ranges = (
            (LEDGER, HEADER_BYTES + OP_BYTES * operation_capacity),
            (self.retained_list, 56), (table, chunks * 4),
            *((self.peek(table + index * 4), 720) for index in range(chunks)))
        self.retained_events, self.retained_accesses = [], []
        self.clear_events()

    def tracked_access(self, kind, address, size):
        super().tracked_access(kind, address, size)
        if (hasattr(self, 'retained_ranges')
                and any(start < address + size and address < start + length
                        for start, length in self.retained_ranges)):
            self.retained_accesses.append((
                kind, self.current_pc, address, size, self.retained_held,
                self.registry_held, self.paint_held, self.transport_held))

    def service(self, target):
        if self.r[4] != RETAINED_MUTEX:
            return super().service(target)
        mutex = (self.blocking_mutexes.get(RETAINED_MUTEX)
                 if getattr(self, 'blocking_mutexes', None) is not None else None)
        if mutex is not None and target == RAW_LOCK:
            if hasattr(self, 'before_blocking_acquire'):
                self.before_blocking_acquire(self, RETAINED_MUTEX)
            if not mutex.acquire(timeout=5):
                raise AssertionError('bounded retained mutex fixture timed out')
        try:
            result = (self.retained_acquire if target == RAW_LOCK
                      else self.retained_release) & MASK
            self.calls.append(target)
            event = (target, RETAINED_MUTEX, self.r[29], self.r[31], result)
            self.raw_events.append(event)
            self.retained_events.append(event)
            if (target == RAW_LOCK and
                    (result == 0 or self.retained_acquire_failure_holds)):
                self.retained_held = True
            if self.on_service is not None:
                self.on_service(self, target)
            self.hostile_result(result)
            if (target == RAW_UNLOCK and
                    (result == 0 or self.retained_release_failure_releases)):
                self.retained_held = False
        finally:
            if mutex is not None and target == RAW_UNLOCK:
                mutex.release()

    def clear_events(self):
        super().clear_events()
        for name in ('retained_events', 'retained_accesses'):
            if hasattr(self, name):
                getattr(self, name).clear()

    def fork_cpu(self, name):
        other = super().fork_cpu(name)
        other.retained_ranges = self.retained_ranges
        other.retained_held = False
        return other

    def copy_bundle(self, captured=OUTPUT, pointer=BUNDLE,
                    opaque=(RESOURCE, REQUEST_CALLBACK, REQUEST_CONTEXT)):
        # Copy the actual emitted GCAP bytes. No pair/sequence is minted here.
        data, offset = self.region(captured, capture.OUTPUT_BYTES)
        self.bytes(pointer, bytes(data[offset:offset + capture.OUTPUT_BYTES]))
        for index, value in enumerate(opaque):
            self.put(pointer + capture.OUTPUT_BYTES + index * 4, value, 4)
        return pointer

    def invoke_retained(self, label, *args, controller=CONTROLLER,
                        stack=STACK, caller=RETURN):
        self.r[29], self.r[31] = stack, caller
        self.r[4:5 + len(args)] = (controller, *args)
        self.run_at(self.retained_labels[label], caller)
        return self.r[2], self.r[3]

    def bind(self, bundle=BUNDLE, **options):
        return self.invoke_retained('bind', bundle, **options)

    def enqueue(self, envelope=ENVELOPE, **options):
        return self.invoke_retained('enqueue', envelope, **options)

    def pop_dispatch(self, **options):
        return self.invoke_retained('pop_dispatch', **options)

    def complete(self, nonce, succeeded=1, **options):
        return self.invoke_retained('complete', nonce, succeeded, **options)

    def close(self, **options):
        return self.invoke_retained('close', **options)

    def quiescent(self, **options):
        return self.invoke_retained('quiescent', **options)

    def retained_count(self):
        return self.peek(self.retained_list + 12)

    def retained_element(self, index=0):
        return self.element(self.retained_list, index)

    def ledger_header(self):
        return self.words_at(LEDGER, HEADER_BYTES // 4)

    def operation_address(self, index=0):
        return LEDGER + HEADER_BYTES + index * OP_BYTES

    def operation(self, index=0):
        return self.words_at(self.operation_address(index), OP_BYTES // 4)


class RetainedOperationsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = source.SOURCE.read_bytes()
        digest = hashlib.sha256(cls.image).hexdigest()
        if digest != source.SOURCE_SHA256 or len(cls.image) != source.SOURCE_SIZE:
            raise AssertionError(f'unrecognized reference: {digest}')

    def machine(self, **options):
        return RetainedOperationsMachine(self.image, **options)

    def prepared(self, machine, *, bind=True):
        engine, output = machine.construct()
        self.assertEqual(output, OUTPUT)
        self.assertNotEqual(engine, 0)
        machine.copy_bundle()
        if bind:
            self.assertEqual(machine.bind(), (1, 0))
        self.assertEqual(machine.pack_payload(machine.positive_payload(engine),
                                              captured=OUTPUT), (ENVELOPE, 0))
        self.assertEqual(machine.captured_carriers, [])
        return engine

    def assert_guarded(self, machine):
        self.assertTrue(machine.retained_accesses)
        self.assertTrue(all(event[4] for event in machine.retained_accesses),
                        machine.retained_accesses)
        self.assertTrue(all(not any(event[5:]) for event in machine.retained_accesses))

    def publish_one(self, machine):
        self.prepared(machine)
        self.assertEqual(machine.enqueue(), (1, 0))
        self.assertEqual(machine.pop_dispatch(), (2, 0))
        return 2

    def test_actual_constructor_capture_bind_native72_then_checked_paint44(self):
        m = self.machine()
        engine = self.prepared(m)
        actual_capture = m.constructor_output()[:8]
        self.assertEqual(m.ledger_header(), (
            OPEN, 0, 0, 0, *actual_capture,
            RESOURCE, REQUEST_CALLBACK, REQUEST_CONTEXT, 0))
        self.assertEqual(m.enqueue(), (1, 0))
        self.assertEqual(m.operation(), (1, QUEUED, 0, 0))
        self.assertEqual(m.words_at(m.retained_element(), 18),
                         (1, *m.envelope_words()))
        self.assertEqual(m.pop_dispatch(), (2, 0))
        self.assertEqual(m.operation(), (1, PUBLISHED, 2, 0))
        self.assertEqual(m.retained_count(), 0)
        self.assertEqual(m.words_at(m.head(), 11),
                         (*m.positive_payload(engine), 2, 1))
        self.assertIn(NATIVE_CONSTRUCTOR, m.trace)
        for target in (APPEND, GET, REMOVE, 0x455BC0):
            self.assertIn(target, m.trace)
        self.assertEqual(m.peek(m.retained_list + 16), 72)
        self.assertEqual(m.peek(m.deferred_list + 16), 68)
        self.assertEqual(m.peek(m.paint_list + 16), 44)
        self.assertEqual(m.captured_carriers, [])
        self.assert_guarded(m)

    def test_empty_transport_and_paint_do_not_complete_an_outstanding_operation(self):
        m = self.machine()
        self.publish_one(m)
        self.assertEqual(m.retained_count(), 0)
        self.assertEqual(m.close(), (1, 0))
        m.clear_events()
        self.assertEqual(m.quiescent(), (0, 0))
        self.assertNotIn(m.owner_labels['retire'], m.trace)
        self.assertNotIn(m.owner_labels['drained'], m.trace)
        self.assertEqual(m.operation(), (1, PUBLISHED, 2, 0))

    def test_exact_claim_acknowledgement_then_close_allows_local_quiescence_only(self):
        m = self.machine()
        self.publish_one(m)
        self.assertEqual(m.claim()[1], 2)
        self.assertEqual(m.complete(2), (1, 0))
        self.assertEqual(m.operation(), (1, DONE, 2, 0))
        self.assertEqual(m.quiescent(), (0, 0))  # open is not quiescent
        self.assertEqual(m.close(), (1, 0))
        m.clear_events()
        self.assertEqual(m.quiescent(), (1, 0))
        self.assertIn(m.owner_labels['retire'], m.trace)
        self.assertIn(m.owner_labels['drained'], m.trace)
        self.assertEqual(m.owner_record()[2], 1)
        self.assertEqual(m.freed, [])
        self.assert_guarded(m)

    def test_failed_render_is_terminal_acknowledgement_not_a_retry(self):
        m = self.machine()
        self.publish_one(m)
        m.claim()
        self.assertEqual(m.complete(2, 0), (2, 0))
        self.assertEqual(m.operation(), (1, DONE, 2, 0))
        self.assertEqual(m.count(), 0)
        self.assertEqual(m.close(), (1, 0))
        self.assertEqual(m.quiescent(), (1, 0))

    def test_cancelled_exact_paint_ack_is_also_terminal(self):
        m = self.machine()
        self.publish_one(m)
        m.claim()
        # An explicit external paint retirement is a bypass premise, not
        # something the operation ledger itself uses before terminal ack.
        self.assertEqual(m.invoke_owner('retire', 1), (1, 0))
        self.assertEqual(m.complete(2), (3, 0))
        self.assertEqual(m.operation(), (1, DONE, 2, 0))

    def test_close_cancels_queued_tokens_only_when_exact_heads_are_removed(self):
        m = self.machine()
        self.prepared(m)
        for token in (1, 2, 3):
            self.assertEqual(m.enqueue(), (token, 0))
        self.assertEqual(m.close(), (1, 0))
        self.assertEqual(m.quiescent(), (0, 0))
        m.clear_events()
        for index in range(3):
            self.assertEqual(m.pop_dispatch(), (0, 0))
            self.assertEqual(m.operation(index), (index + 1, DONE, 0, 0))
            self.assertEqual(m.retained_count(), 2 - index)
        self.assertNotIn(m.envelope_labels['dispatch'], m.trace)
        self.assertEqual(m.count(), 0)
        self.assertEqual(m.quiescent(), (1, 0))

    def test_close_does_not_purge_published_unclaimed_or_active_paint(self):
        for claimed in (False, True):
            with self.subTest(claimed=claimed):
                m = self.machine()
                self.publish_one(m)
                if claimed:
                    m.claim()
                m.clear_events()
                self.assertEqual(m.close(), (1, 0))
                self.assertEqual(m.quiescent(), (0, 0))
                self.assertEqual(m.count(), 1)
                self.assertEqual(m.operation(), (1, PUBLISHED, 2, 0))
                self.assertNotIn(m.owner_labels['retire'], m.trace)

    def test_identical_ready68_clones_get_distinct_nonreused_tokens_and_nonces(self):
        m = self.machine()
        self.prepared(m)
        original = m.envelope_words()
        self.assertEqual(m.enqueue(), (1, 0))
        self.assertEqual(m.enqueue(), (2, 0))
        self.assertEqual(m.envelope_words(), original)
        self.assertEqual(m.pop_dispatch(), (2, 0))
        self.assertEqual(m.pop_dispatch(), (3, 1))
        self.assertEqual(m.operation(0), (1, PUBLISHED, 2, 0))
        self.assertEqual(m.operation(1), (2, PUBLISHED, 3, 0))
        m.claim()
        self.assertEqual(m.complete(2), (1, 0))
        m.claim()
        self.assertEqual(m.complete(3), (1, 0))
        self.assertEqual(m.enqueue(), (3, 0))
        self.assertEqual(m.operation(0), (1, DONE, 2, 0))
        self.assertEqual(m.operation(2), (3, QUEUED, 0, 0))

    def test_fourteen_native72_entries_cross_segment_boundary_and_keep_fifo_values(self):
        m = self.machine()
        engine = self.prepared(m)
        for index in range(14):
            pointer = ENVELOPE + index * 68
            if index:
                words = (*m.positive_payload(engine)[:-1], index)
                self.assertEqual(m.pack_payload(words, captured=OUTPUT, output=pointer),
                                 (pointer, 0))
            self.assertEqual(m.enqueue(pointer), (index + 1, 0))
        self.assertNotEqual(m.retained_element(10), m.retained_element() + 720)
        for index in range(14):
            self.assertEqual(m.pop_dispatch(), (index + 2, index))
            self.assertEqual(m.words_at(m.queue_element(index), 9)[-1], index)
            self.assertEqual(m.operation(index), (index + 1, PUBLISHED, index + 2, 0))
        self.assertEqual(m.retained_count(), 0)
        self.assert_guarded(m)

    def test_bound_bundle_is_owned_and_never_reloaded_from_constructor_output(self):
        m = self.machine()
        self.prepared(m)
        expected = m.ledger_header()[4:15]
        for pointer, length in ((BUNDLE, 44), (OUTPUT, 48)):
            for offset in range(0, length, 4):
                m.put(pointer + offset, MASK, 4)
        self.assertEqual(m.enqueue(), (1, 0))
        self.assertEqual(m.pop_dispatch(), (2, 0))
        self.assertEqual(m.ledger_header()[4:15], expected)

    def test_context_fields_are_opaque_scalars_not_dereferenced_or_called(self):
        m = self.machine()
        self.prepared(m, bind=False)
        opaque = (0, 0xBAD00000, MASK)
        m.copy_bundle(opaque=opaque)
        m.clear_events()
        self.assertEqual(m.bind(), (1, 0))
        self.assertEqual(m.enqueue(), (1, 0))
        self.assertEqual(m.pop_dispatch(), (2, 0))
        self.assertEqual(m.ledger_header()[12:15], opaque)
        self.assertNotIn(opaque[1], m.calls)
        self.assertFalse(any(address in opaque for address, _ in m.reads))
        self.assertEqual(m.freed, [])

    def test_second_bind_and_closed_rebind_never_replace_the_retained_context(self):
        m = self.machine()
        self.prepared(m)
        expected = m.ledger_header()
        self.assertEqual(m.bind(), (0, 0))
        self.assertEqual(m.ledger_header(), expected)
        self.assertEqual(m.close(), (1, 0))
        closed = m.ledger_header()
        self.assertEqual(m.bind(), (0, 0))
        self.assertEqual(m.ledger_header(), closed)
        self.assertEqual(m.enqueue(), (0, 0))

    def test_operation_table_full_never_reuses_completed_tokens(self):
        m = self.machine(operation_capacity=1)
        self.publish_one(m)
        m.claim()
        self.assertEqual(m.complete(2), (1, 0))
        m.clear_events()
        self.assertEqual(m.enqueue(), (0, 0))
        self.assertEqual(m.operation(), (1, DONE, 2, 0))
        self.assertEqual(m.ledger_header()[2], 1)
        self.assertNotIn(APPEND, m.trace)
        self.assertEqual(m.ledger_header()[1], 0)

    def test_retained_fifo_full_refuses_without_reservation_or_native_growth(self):
        m = self.machine(operation_capacity=64, retained_capacity=16)
        self.prepared(m)
        capacity = m.peek(m.retained_list + 8)
        self.assertEqual(capacity, 20)
        for token in range(1, capacity + 1):
            self.assertEqual(m.enqueue(), (token, 0))
        allocation = m.next_allocation
        m.clear_events()
        self.assertEqual(m.enqueue(), (0, 0))
        self.assertEqual(m.ledger_header()[2], 20)
        self.assertEqual(m.operation(20), (0, 0, 0, 0))
        self.assertEqual(m.next_allocation, allocation)
        self.assertNotIn(APPEND, m.trace)
        self.assertNotIn(0x455980, m.trace)

    def test_ordinary_paint_backpressure_finishes_only_the_extracted_attempt(self):
        m = self.machine(queue_capacity=1)
        self.prepared(m)
        self.assertEqual(m.enqueue(), (1, 0))
        self.assertEqual(m.enqueue(), (2, 0))
        self.assertEqual(m.pop_dispatch(), (2, 0))
        self.assertEqual(m.pop_dispatch(), (0, 0))
        self.assertEqual(m.operation(0), (1, PUBLISHED, 2, 0))
        self.assertEqual(m.operation(1), (2, DONE, 0, 0))
        self.assertEqual(m.close(), (1, 0))
        self.assertEqual(m.quiescent(), (0, 0))
        m.claim()
        self.assertEqual(m.complete(2), (1, 0))
        self.assertEqual(m.quiescent(), (1, 0))

    def test_unknown_duplicate_or_invalid_outcome_ack_never_calls_paint_complete(self):
        m = self.machine()
        self.publish_one(m)
        for nonce, outcome in ((0, 1), (3, 1), (MASK, 1), (2, 2)):
            m.clear_events()
            self.assertEqual(m.complete(nonce, outcome), (0, 0))
            self.assertNotIn(m.owner_labels['complete'], m.trace)
            self.assertEqual(m.operation(), (1, PUBLISHED, 2, 0))
        m.claim()
        self.assertEqual(m.complete(2), (1, 0))
        m.clear_events()
        self.assertEqual(m.complete(2), (0, 0))
        self.assertNotIn(m.owner_labels['complete'], m.trace)

    def test_no_registry_or_paint_lock_is_nested_under_retained_mutex(self):
        m = self.machine()
        self.prepared(m)
        self.assertEqual(m.enqueue(), (1, 0))
        observations = []

        def observe(machine, target):
            if machine.r[4] in (REGISTRY_MUTEX, PAINT_MUTEX):
                observations.append(machine.retained_held)

        m.on_service = observe
        self.assertEqual(m.pop_dispatch(), (2, 0))
        m.claim()
        self.assertEqual(m.complete(2), (1, 0))
        self.assertEqual(m.close(), (1, 0))
        self.assertEqual(m.quiescent(), (1, 0))
        self.assertTrue(observations)
        self.assertFalse(any(observations))
        self.assert_guarded(m)

    def test_early_claim_can_ack_only_after_actual_nonce_binding(self):
        m = self.machine()
        self.prepared(m)
        self.assertEqual(m.enqueue(), (1, 0))
        second = m.fork_cpu('second')
        observations = []

        def before_binding(machine, pc):
            if pc == machine.retained_labels['pop_rebind_before_lock']:
                observations.append(machine.operation())
                self.assertEqual(second.invoke_owner('claim', stack=SECOND_STACK)[1], 2)
                second.clear_events()
                self.assertEqual(second.complete(2, stack=SECOND_STACK), (0, 0))
                self.assertNotIn(second.owner_labels['complete'], second.trace)

        m.on_instruction = before_binding
        self.assertEqual(m.pop_dispatch(), (2, 0))
        self.assertEqual(observations, [(1, EXTRACTED, 0, 0)])
        self.assertEqual(m.operation(), (1, PUBLISHED, 2, 0))
        self.assertEqual(second.complete(2, stack=SECOND_STACK), (1, 0))
        self.assertEqual(m.operation(), (1, DONE, 2, 0))

    def test_close_between_extraction_and_publication_does_not_drop_inflight_reference(self):
        m = self.machine()
        self.prepared(m)
        self.assertEqual(m.enqueue(), (1, 0))
        second = m.fork_cpu('second')
        observations = []

        def close_at_dispatch(machine, pc):
            if pc == machine.retained_labels['before_dispatch']:
                self.assertFalse(machine.retained_held)
                self.assertEqual(second.close(stack=SECOND_STACK), (1, 0))
                self.assertEqual(second.quiescent(stack=SECOND_STACK), (0, 0))
                observations.append(machine.operation())

        m.on_instruction = close_at_dispatch
        self.assertEqual(m.pop_dispatch(), (2, 0))
        self.assertEqual(observations, [(1, EXTRACTED, 0, 0)])
        self.assertEqual(m.operation(), (1, PUBLISHED, 2, 0))
        self.assertEqual(m.ledger_header()[0], CLOSED)
        m.claim()
        self.assertEqual(m.complete(2), (1, 0))
        self.assertEqual(m.quiescent(), (1, 0))


if __name__ == '__main__':
    unittest.main()
