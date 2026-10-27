#!/usr/bin/env python3
"""Execute owned68 deferral through actual native segmented-list methods.

The emitted checked capture, pack and dispatch instructions retain the pair;
Python never reconstructs it from issuer registers, a journal or a raw engine.
The separate transport list is caller-exclusive and fully preallocated here.
Extracting its head acknowledges only the transport snapshot, not rendering,
native lifetime, retry authority, a scheduler or global exactly-once delivery.
Allocator/raw/libc services remain bounded hostile-ABI substitutes. No device,
image-builder, constructor-width patch beyond the inherited local44 fixture,
native explorer producer call-site or cleanup path is installed.
"""

import hashlib
import unittest

import reveal_creation_capture_mips as capture
import reveal_deferred_envelope_mips as core
import reveal_deferred_envelope_stage as stage
import reveal_paint_retirement_mips as owner
import reveal_registry_receipt_mips as receipt
import test_folderfollow_reveal_static_contract as source
from test_reveal_owner_carrier_mips import OWNED_INPUT, PAYLOAD
from test_reveal_registry_release_mips import RegistryReleaseMachine, OUTPUT
from test_reveal_registry_owner_mips import (
    STATE, BIND_STATE, OWNER_STATE, CODE, CONTROLLER, REGISTRY_MUTEX,
    PAINT_MUTEX, ENGINE, RAW_LOCK, RAW_UNLOCK, STACK, RETURN, MASK)


ENVELOPE, WORK, STORAGE_BYTES = 0x1FC0000, 0x1FD0000, 0x4000
FACTORY, APPEND, GET, REMOVE = 0x456E60, 0x455DA0, 0x4557E0, 0x455860


class DeferredEnvelopeMachine(RegistryReleaseMachine):
    """A serialized typed transport queue separate from controller+128 paint."""

    def __init__(self, image, *, capacity=16, owner_capacity=16,
                 ticket_limit=owner.MAX_TICKET, queue_capacity=64,
                 deferred_capacity=32, acquire=0, release=0,
                 paint_acquire_result=0, paint_release_result=0):
        super().__init__(
            image, capacity=capacity, owner_capacity=owner_capacity,
            ticket_limit=ticket_limit, queue_capacity=queue_capacity,
            acquire=acquire, release=release,
            paint_acquire_result=paint_acquire_result,
            paint_release_result=paint_release_result,
            checked_registry_release=True)
        self.composition = stage.assemble(
            STATE, BIND_STATE, OWNER_STATE, CONTROLLER, REGISTRY_MUTEX,
            PAINT_MUTEX, CODE, capacity=capacity, owner_capacity=owner_capacity,
            ticket_limit=ticket_limit, queue_capacity=queue_capacity)
        self.code = self.code_bytes = self.composition['code']
        self.labels = self.composition['labels']
        for attribute in ('owner_labels', 'issuer_labels', 'receipt_labels',
                          'adapter_labels', 'capture_labels', 'envelope_labels'):
            setattr(self, attribute, self.composition[attribute])
        self.bridge_labels = self.receipt_labels
        # Retain the inherited in-memory44 paint constructor override. Only
        # its receipt/release observers need the new composed addresses.
        for pc, words in {
                **receipt.hook_words(self.receipt_labels),
                **self.composition['release_hooks']}.items():
            for index, word in enumerate(words):
                self.patches[pc + 4 * index] = word
        self.map(ENVELOPE, STORAGE_BYTES)
        self.map(WORK, STORAGE_BYTES)
        self.envelope_accesses = []
        self.extractions = []
        self.next_work = WORK
        self.r[29] = STACK
        self.deferred_list = self.stock(FACTORY, deferred_capacity,
                                       core.ENVELOPE_BYTES)
        if not self.deferred_list:
            raise AssertionError('native typed transport construction failed')
        if self.deferred_list == self.paint_list:
            raise AssertionError('transport reused the native paint queue')
        self.clear_events()

    def tracked_access(self, kind, address, size):
        super().tracked_access(kind, address, size)
        if (hasattr(self, 'envelope_accesses')
                and any(start <= address < start + STORAGE_BYTES
                        for start in (ENVELOPE, WORK))):
            self.envelope_accesses.append((kind, self.current_pc, address, size,
                                           self.registry_held, self.paint_held))

    def clear_events(self):
        super().clear_events()
        if hasattr(self, 'envelope_accesses'):
            self.envelope_accesses.clear()
        if hasattr(self, 'extractions'):
            self.extractions.clear()

    def payload(self, words=PAYLOAD, pointer=OWNED_INPUT):
        if len(words) != core.PAYLOAD_BYTES // 4:
            raise ValueError('fixture payload requires nine owned words')
        for index, word in enumerate(words):
            self.put(pointer + 4 * index, word, 4)
        return pointer

    def invoke_pack(self, captured=OUTPUT, payload=OWNED_INPUT,
                    output=ENVELOPE, *, controller=CONTROLLER,
                    stack=STACK, caller=RETURN):
        self.r[29], self.r[31] = stack, caller
        self.r[4:8] = controller, captured, payload, output
        self.run_at(self.envelope_labels['pack'], caller)
        return self.r[2], self.r[3]

    def pack_payload(self, words=PAYLOAD, *, captured=OUTPUT, output=ENVELOPE,
                     **options):
        self.payload(words)
        return self.invoke_pack(captured, OWNED_INPUT, output, **options)

    def invoke_dispatch(self, envelope=ENVELOPE, *, controller=CONTROLLER,
                        stack=STACK, caller=RETURN):
        self.r[29], self.r[31] = stack, caller
        self.r[4:6] = controller, envelope
        self.run_at(self.envelope_labels['dispatch'], caller)
        return self.r[2], self.r[3]

    def envelope_words(self, address=ENVELOPE):
        return self.words_at(address, core.ENVELOPE_BYTES // 4)

    def transport_count(self):
        return self.peek(self.deferred_list + 0xC)

    def transport_element(self, index=0):
        return self.element(self.deferred_list, index)

    def enqueue(self, envelope=ENVELOPE):
        # This fixture owns/serializes the transport list. Avoid the native
        # grow path here: failed growth is not a safe retry/retention proof.
        if self.transport_count() >= self.peek(self.deferred_list + 8):
            return None
        self.r[29] = STACK
        return self.stock(APPEND, self.deferred_list, envelope)

    def pop_dispatch(self):
        if not self.transport_count():
            return 0, 0
        self.r[29] = STACK
        head = self.stock(GET, self.deferred_list, 0)
        work = self.next_work
        if work + core.ENVELOPE_BYTES > WORK + STORAGE_BYTES:
            raise AssertionError('fixture exhausted fresh owned work storage')
        # The emitted pack snapshots the borrowed head BEFORE native removal
        # can shift/overwrite it. Never reconstruct its pair in Python.
        result = self.invoke_pack(head, head + capture.OUTPUT_BYTES, work)
        if result != (work, 0):
            return result
        self.next_work += core.ENVELOPE_BYTES
        self.r[29] = STACK
        removed = self.stock(REMOVE, self.deferred_list, 0)
        if removed:
            self.extractions.append((head, work, removed, None))
            return 0, removed
        result = self.invoke_dispatch(work)
        self.extractions.append((head, work, removed, result))
        return result


class DeferredEnvelopeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = source.SOURCE.read_bytes()
        digest = hashlib.sha256(cls.image).hexdigest()
        if digest != source.SOURCE_SHA256 or len(cls.image) != source.SOURCE_SIZE:
            raise AssertionError(f'unrecognized reference: {digest}, size {len(cls.image)}')

    def machine(self, **options):
        return DeferredEnvelopeMachine(self.image, **options)

    def prepared(self, machine, *, output=ENVELOPE, captured=OUTPUT,
                 words=PAYLOAD):
        self.assertEqual(machine.invoke_register(output=captured), (0, captured))
        self.assertEqual(machine.pack_payload(words, captured=captured, output=output),
                         (output, 0))
        self.assertEqual(machine.captured_carriers, [])
        return output

    def test_emitted_capture_pack_actual_transport_and_actual44_paint_queue(self):
        m = self.machine()
        self.prepared(m)
        capture_words = m.outwords()
        self.assertEqual(m.envelope_words(), (*capture_words, *PAYLOAD))
        self.assertEqual(m.peek(m.deferred_list + 0x10), 68)
        self.assertEqual(m.peek(m.paint_list + 0x10), 44)
        self.assertEqual(m.peek(CONTROLLER + 0x128), m.paint_list)
        self.assertEqual(m.enqueue(), 0)
        self.assertEqual(m.pop_dispatch(), (2, 0))
        self.assertEqual(m.transport_count(), 0)
        self.assertEqual(m.count(), 1)
        self.assertEqual(m.words_at(m.head(), 11), (*PAYLOAD, 2, 1))
        for target in (APPEND, GET, REMOVE, 0x455BC0):
            self.assertIn(target, m.trace)
        self.assertEqual(m.captured_carriers, [])

    def test_native_enqueue_copies_values_not_capture_or_payload_pointers(self):
        m = self.machine()
        self.prepared(m)
        expected = m.envelope_words()
        self.assertEqual(m.enqueue(), 0)
        self.assertNotEqual(m.transport_element(), ENVELOPE)
        self.assertEqual(m.envelope_words(m.transport_element()), expected)
        for pointer, count in ((OUTPUT, 8), (OWNED_INPUT, 9), (ENVELOPE, 17)):
            for index in range(count):
                m.put(pointer + 4 * index, MASK, 4)
        self.assertEqual(m.pop_dispatch(), (2, 0))
        self.assertEqual(m.words_at(m.head(), 9), PAYLOAD)
        self.assertEqual(m.envelope_words(WORK)[1:], expected[1:])

    def test_preallocated_fifo_crosses_ten_element_native_segment_boundary(self):
        m = self.machine(deferred_capacity=32)
        self.assertEqual(m.invoke_register(), (0, OUTPUT))
        for index in range(14):
            envelope = ENVELOPE + index * 68
            words = (*PAYLOAD[:-1], index)
            self.assertEqual(m.pack_payload(words, output=envelope), (envelope, 0))
            self.assertEqual(m.enqueue(envelope), index)
        self.assertNotEqual(m.transport_element(10), m.transport_element(0) + 680)
        for index in range(14):
            self.assertEqual(m.pop_dispatch(), (index + 2, index))
            self.assertEqual(m.words_at(m.queue_element(index), 9),
                             (*PAYLOAD[:-1], index))
        self.assertEqual(m.transport_count(), 0)
        self.assertEqual(m.pop_dispatch(), (0, 0))

    def test_retired_old_pair_cannot_adopt_equal_engine_replacement(self):
        m = self.machine()
        self.prepared(m)
        self.assertEqual(m.enqueue(), 0)
        self.assertEqual(m.retire(1), (1, 0))
        second_capture, second_envelope = OUTPUT + 32, ENVELOPE + 68
        self.prepared(m, captured=second_capture, output=second_envelope)
        self.assertEqual(m.outwords()[3], m.outwords(second_capture)[3])
        self.assertEqual(m.outwords()[4:6], (1, 1))
        self.assertEqual(m.outwords(second_capture)[4:6], (2, 2))
        self.assertEqual(m.enqueue(second_envelope), 1)
        self.assertEqual(m.pop_dispatch(), (0, 0))
        self.assertEqual(m.count(), 0)
        self.assertEqual(m.transport_count(), 1)
        self.assertEqual(m.pop_dispatch(), (3, 0))
        self.assertEqual(m.words_at(m.head(), 11), (*PAYLOAD, 3, 2))

    def test_pack_accepts_only_observed_release_flag(self):
        for flag in (0, capture.HISTORICAL_RELEASE_UNOBSERVED, 3, MASK):
            with self.subTest(flag=flag):
                m = self.machine()
                self.assertEqual(m.invoke_register(), (0, OUTPUT))
                m.put(OUTPUT + capture.FLAGS, flag, 4)
                m.payload()
                m.clear_events()
                self.assertEqual(m.invoke_pack(), (0, 0))
                self.assertEqual(m.envelope_words(), (0,) * 17)
                self.assertEqual(m.raw_events, [])

    def test_pack_denies_native_nonzero_result_and_mismatched_payload_engine(self):
        for cause in ('native_result', 'engine'):
            with self.subTest(cause=cause):
                m = self.machine()
                self.assertEqual(m.invoke_register(), (0, OUTPUT))
                m.payload()
                if cause == 'native_result':
                    m.put(OUTPUT + capture.RESULT, 1, 4)
                else:
                    m.put(OWNED_INPUT + 8, ENGINE ^ MASK, 4)
                m.clear_events()
                self.assertEqual(m.invoke_pack(), (0, 0))
                self.assertEqual(m.envelope_words(), (0,) * 17)
                self.assertEqual(m.raw_events, [])

    def test_receipt_sequence_outside_composed_capacity_denies_pack_and_dispatch(self):
        for operation in ('pack', 'dispatch'):
            with self.subTest(operation=operation):
                m = self.machine(capacity=2)
                self.assertEqual(m.invoke_register(), (0, OUTPUT))
                m.payload()
                if operation == 'dispatch':
                    self.assertEqual(m.invoke_pack(), (ENVELOPE, 0))
                address = OUTPUT if operation == 'pack' else ENVELOPE
                m.put(address + capture.RECEIPT_SEQUENCE, 3, 4)
                before = m.envelope_words()
                m.clear_events()
                self.assertEqual(m.invoke_pack() if operation == 'pack'
                                 else m.invoke_dispatch(), (0, 0))
                self.assertEqual(m.envelope_words(), before)
                self.assertEqual(m.raw_events, [])
                self.assertEqual(m.count(), 0)

    def test_pack_does_not_overwrite_an_existing_owned_envelope(self):
        m = self.machine()
        self.prepared(m)
        original = m.envelope_words()
        m.clear_events()
        self.assertEqual(m.invoke_pack(), (0, 0))
        self.assertEqual(m.envelope_words(), original)
        self.assertEqual([event for event in m.envelope_accesses
                          if event[0] == 'write'], [])

    def test_pack_commits_magic_last_without_any_raw_or_shared_state_access(self):
        m = self.machine()
        self.assertEqual(m.invoke_register(), (0, OUTPUT))
        m.payload()
        m.clear_events()
        self.assertEqual(m.invoke_pack(), (ENVELOPE, 0))
        writes = [event for event in m.envelope_accesses if event[0] == 'write']
        self.assertEqual(len(writes), 17)
        self.assertEqual(writes[-1][2], ENVELOPE)
        self.assertTrue(all(not event[-2] and not event[-1] for event in writes))
        self.assertEqual(m.raw_events, [])
        self.assertEqual(m.binding_accesses, [])
        self.assertEqual(m.owner_accesses, [])
        self.assertEqual(m.journal_accesses, [])

    def test_repeated_dispatch_of_same_owned_envelope_is_denied(self):
        m = self.machine()
        self.prepared(m)
        self.assertEqual(m.invoke_dispatch(), (2, 0))
        self.assertNotEqual(m.peek(ENVELOPE), capture.OUTPUT_MAGIC)
        m.clear_events()
        self.assertEqual(m.invoke_dispatch(), (0, 0))
        self.assertEqual(m.raw_events, [])
        self.assertEqual(m.count(), 1)

    def test_retired_denial_still_consumes_the_extracted_envelope(self):
        m = self.machine()
        self.prepared(m)
        self.assertEqual(m.enqueue(), 0)
        self.assertEqual(m.retire(1), (1, 0))
        self.assertEqual(m.pop_dispatch(), (0, 0))
        self.assertEqual(m.transport_count(), 0)
        self.assertNotEqual(m.peek(WORK), capture.OUTPUT_MAGIC)
        m.clear_events()
        self.assertEqual(m.invoke_dispatch(WORK), (0, 0))
        self.assertEqual(m.raw_events, [])
        self.assertEqual(m.count(), 0)

    def test_paint_backpressure_consumes_local_attempt_without_retry(self):
        m = self.machine(queue_capacity=1)
        self.prepared(m)
        self.assertEqual(m.invoke_dispatch(), (2, 0))
        second = ENVELOPE + 68
        self.assertEqual(m.pack_payload(output=second), (second, 0))
        self.assertEqual(m.enqueue(second), 0)
        self.assertEqual(m.pop_dispatch(), (0, 0))
        self.assertEqual(m.transport_count(), 0)
        self.assertEqual(m.claim()[1], 2)
        self.assertEqual(m.complete(2), (1, 0))
        m.clear_events()
        self.assertEqual(m.invoke_dispatch(WORK), (0, 0))
        self.assertEqual(m.count(), 0)
        self.assertEqual(m.raw_events, [])

    def test_raw_registry_acquisition_error_consumes_without_paint_access(self):
        m = self.machine()
        self.prepared(m)
        m.acquire = 22
        m.clear_events()
        self.assertEqual(m.invoke_dispatch(), (0, 22))
        self.assertNotEqual(m.peek(ENVELOPE), capture.OUTPUT_MAGIC)
        self.assertEqual(m.paint_events, [])
        self.assertEqual(m.binding_accesses, [])
        self.assertEqual(m.count(), 0)
        self.assertEqual(len(m.raw_events), 1)

    def test_raw_paint_acquisition_error_consumes_and_preserves_status(self):
        m = self.machine()
        self.prepared(m)
        m.paint_acquire_result = 22
        m.clear_events()
        self.assertEqual(m.invoke_dispatch(), (0, 22))
        self.assertNotEqual(m.peek(ENVELOPE), capture.OUTPUT_MAGIC)
        self.assertEqual(m.count(), 0)
        self.assertEqual(m.binding_header()[1:3], (1, 22))

    def test_uncertain_outer_release_does_not_allow_second_publication_attempt(self):
        m = self.machine()
        self.prepared(m)
        m.release = 22
        m.clear_events()
        self.assertEqual(m.invoke_dispatch(), (0, 22))
        self.assertEqual(m.count(), 1)  # append may already have happened
        self.assertNotEqual(m.peek(ENVELOPE), capture.OUTPUT_MAGIC)
        m.clear_events()
        self.assertEqual(m.invoke_dispatch(), (0, 0))
        self.assertEqual(m.count(), 1)
        self.assertEqual(m.raw_events, [])

    def test_payload_snapshot_survives_hostile_source_mutation_at_first_raw_call(self):
        m = self.machine()
        self.prepared(m)

        def mutate(machine, target):
            if target == RAW_LOCK and machine.r[4] == REGISTRY_MUTEX:
                for offset in range(4, core.ENVELOPE_BYTES, 4):
                    machine.put(ENVELOPE + offset, MASK, 4)

        m.on_service = mutate
        self.assertEqual(m.invoke_dispatch(), (2, 0))
        self.assertEqual(m.words_at(m.head(), 11), (*PAYLOAD, 2, 1))

    def test_pack_and_dispatch_preserve_callee_saved_registers_sp_ra_hilo(self):
        for operation in ('pack', 'dispatch', 'denied_dispatch'):
            with self.subTest(operation=operation):
                m = self.machine()
                self.assertEqual(m.invoke_register(), (0, OUTPUT))
                m.payload()
                if operation != 'pack':
                    self.assertEqual(m.invoke_pack(), (ENVELOPE, 0))
                if operation == 'denied_dispatch':
                    self.assertEqual(m.retire(1), (1, 0))
                saved = {register: 0x77800000 + register
                         for register in (*range(16, 24), 28, 30)}
                for register, value in saved.items():
                    m.r[register] = value
                m.hi, m.lo = 0x12345678, 0xABCDEF01
                result = (m.invoke_pack() if operation == 'pack'
                          else m.invoke_dispatch())
                self.assertEqual(result, (ENVELOPE, 0) if operation == 'pack'
                                 else (2, 0) if operation == 'dispatch'
                                 else (0, 0))
                self.assertEqual({register: m.r[register] for register in saved}, saved)
                self.assertEqual((m.r[29], m.r[31]), (STACK, RETURN))
                self.assertEqual((m.hi, m.lo), (0x12345678, 0xABCDEF01))

    def test_preallocated_transport_backpressure_avoids_native_growth(self):
        m = self.machine(deferred_capacity=16)
        self.prepared(m)
        allocated = m.peek(m.deferred_list + 8)
        self.assertEqual(allocated, 20)
        for index in range(allocated):
            self.assertEqual(m.enqueue(), index)
        before = m.next_allocation
        self.assertIsNone(m.enqueue())
        self.assertEqual(m.next_allocation, before)
        self.assertEqual(m.transport_count(), allocated)
        self.assertEqual(m.count(), 0)

    def test_extract_uses_emitted_private_copy_before_native_remove_and_dispatch(self):
        m = self.machine()
        self.prepared(m)
        second = ENVELOPE + 68
        changed = (*PAYLOAD[:-1], 99)
        self.assertEqual(m.pack_payload(changed, output=second), (second, 0))
        self.assertEqual(m.enqueue(), 0)
        self.assertEqual(m.enqueue(second), 1)
        old_head = m.transport_element()
        m.clear_events()
        self.assertEqual(m.pop_dispatch(), (2, 0))
        self.assertEqual(m.envelope_words(old_head)[-1], 99)
        self.assertEqual(m.words_at(m.head(), 9), PAYLOAD)
        self.assertEqual(m.envelope_words(WORK)[-9:], PAYLOAD)
        pack_index = m.trace.index(m.envelope_labels['pack'])
        remove_index = m.trace.index(REMOVE)
        dispatch_index = m.trace.index(m.envelope_labels['dispatch'])
        self.assertLess(pack_index, remove_index)
        self.assertLess(remove_index, dispatch_index)
        self.assertEqual(m.extractions, [(old_head, WORK, 0, (2, 0))])


if __name__ == '__main__':
    unittest.main()
