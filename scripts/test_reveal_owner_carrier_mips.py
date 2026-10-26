#!/usr/bin/env python3
"""Execute explicit captured generations with the actual native44-byte queue.

Pairs are observed once at the emitted creation commit, never reconstructed by
a later raw-pointer lookup. Only this in-memory fixture patches constructor44;
the native producer ABI is unchanged. Raw services remain bounded hostile-ABI
stubs, not native allocation retention, producer coherence or lifecycle proof.
"""

import hashlib
import unittest

from build_reveal_bridge_diag import b
import reveal_paint_retirement_mips as owner
import reveal_registry_owner_mips as bindings
import reveal_registry_owner_stage as creation
import reveal_registry_receipt_mips as receipt
import reveal_owner_carrier_mips as carrier
import reveal_owner_carrier_stage as stage
import test_folderfollow_reveal_static_contract as source
from test_reveal_lineage_stage import LineageMachine, HEAP
from test_reveal_registry_owner_mips import (
    RegistryOwnerMachine, STATE, CODE, CONTROLLER, INPUT, REGISTRY_MUTEX,
    PAINT_MUTEX, ENGINE, DESCRIPTOR, RAW_LOCK, RAW_UNLOCK, STACK, RETURN, MASK,
    OWNER_STATE, BIND_STATE, REQUEST)


OWNED_INPUT = 0x1FA0000
PAYLOAD = (0, 0, ENGINE, 1, 16, 8, 8, 0x87654321, 0)


class RegistryCarrierMachine(RegistryOwnerMachine):
    """A caller-owned pair and payload, not a native producer-route claim."""

    def __init__(self, image, *, capacity=16, owner_capacity=16,
                 ticket_limit=owner.MAX_TICKET, queue_capacity=64,
                 acquire=0, release=0, paint_acquire_result=0,
                 paint_release_result=0, hooks=True):
        super().__init__(image, capacity=capacity, owner_capacity=owner_capacity,
                         ticket_limit=ticket_limit, acquire=acquire, release=release,
                         paint_acquire_result=paint_acquire_result,
                         paint_release_result=paint_release_result, hooks=False)
        self.composition = stage.assemble(
            STATE, BIND_STATE, OWNER_STATE, CONTROLLER, REGISTRY_MUTEX, PAINT_MUTEX,
            CODE, capacity=capacity, owner_capacity=owner_capacity,
            ticket_limit=ticket_limit, queue_capacity=queue_capacity)
        self.code = self.code_bytes = self.composition['code']
        self.labels = self.composition['labels']
        self.owner_labels = self.composition['owner_labels']
        self.issuer_labels = self.composition['issuer_labels']
        self.receipt_labels = self.composition['receipt_labels']
        self.bridge_labels = self.receipt_labels
        self.adapter_labels = self.composition['adapter_labels']
        self.patches = {0x439844: b.addiu(5, 0, owner.ELEMENT_BYTES)}
        if hooks:
            for pc, words in receipt.hook_words(self.receipt_labels).items():
                for index, word in enumerate(words):
                    self.patches[pc + index * 4] = word
        self.map(OWNED_INPUT, 0x100)
        self.captured_carriers = []
        self.queue_accesses = []
        self.in_native_registration = False
        self.fail_next_heap = False
        self.fail_heap_in = None
        self.r[29] = STACK
        if self.stock(0x439840, CONTROLLER):
            raise AssertionError('native fixture queue construction failed')
        self.paint_list = self.peek(CONTROLLER + 0x128)
        self.clear_events()

    def instruction(self, pc):
        if (hasattr(self, 'captured_carriers')
                and pc == self.issuer_labels['binding_committed']):
            # This is the actual issued result at the commit boundary. No
            # later table read can replace independently retaining this pair.
            self.captured_carriers.append((self.r[20], self.r[2]))
        super().instruction(pc)

    def tracked_access(self, kind, address, size):
        super().tracked_access(kind, address, size)
        if hasattr(self, 'queue_accesses') and HEAP <= address < HEAP + 0x80000:
            self.queue_accesses.append((kind, self.current_pc, address, size,
                                        self.registry_held, self.paint_held))

    def external(self, target):
        if target in (0x439840, 0x455BC0, 0x439960):
            self.calls.append(target)
            self.run_at(target, self.r[31])
            return
        if target in (0x4669E0, 0x466A80, 0xA5B440, 0xA5BC60):
            if target == 0x4669E0 and self.in_native_registration:
                return super().external(target)
            if target == 0x4669E0:
                if self.fail_heap_in is not None:
                    self.fail_heap_in -= 1
                    if not self.fail_heap_in:
                        self.fail_heap_in = None
                        self.calls.append(target)
                        self.hostile_result(0)
                        return
                if self.fail_next_heap:
                    self.fail_next_heap = False
                    self.calls.append(target)
                    self.hostile_result(0)
                    return
            return LineageMachine.external(self, target)
        return super().external(target)

    def register(self, **options):
        self.in_native_registration = True
        try:
            return super().register(**options)
        finally:
            self.in_native_registration = False

    def clear_events(self):
        for name in ('raw_events', 'paint_events', 'binding_accesses',
                     'owner_accesses', 'journal_accesses', 'queue_accesses',
                     'reads', 'writes', 'calls', 'trace'):
            getattr(self, name).clear()

    def peek(self, address, size=4):
        data, offset = self.region(address, size)
        return int.from_bytes(data[offset:offset + size], 'little')

    def count(self, pointer=None):
        return self.peek((self.paint_list if pointer is None else pointer) + 0xC)

    def element(self, pointer=None, index=0):
        pointer = self.paint_list if pointer is None else pointer
        chunk_count = self.peek(pointer + 0x14)
        stride = self.peek(pointer + 0x10)
        table = self.peek(pointer)
        chunk = self.peek(table + index // chunk_count * 4)
        return chunk + index % chunk_count * stride

    def queue_element(self, index=0):
        return self.element(self.paint_list, index)

    def head(self):
        return self.queue_element() if self.count() else 0

    def owner_state(self, offset=None):
        if offset is not None:
            return self.peek(OWNER_STATE + offset)
        return self.owner_header()

    def owned(self):
        return self.words_at(OWNER_STATE + owner.COPY, 9)

    def invoke_adapter(self, payload, sequence, owner_ticket, *,
                       controller=CONTROLLER, stack=STACK, caller=RETURN):
        self.r[29], self.r[31] = stack, caller
        self.r[4:8] = (controller, payload, sequence, owner_ticket)
        self.run_at(self.adapter_labels['publish'], caller)
        return self.r[2], self.r[3]

    def publish_payload(self, captured, words=PAYLOAD, **options):
        if len(words) != 9:
            raise ValueError('fixture payload must contain nine owned words')
        for index, word in enumerate(words):
            self.put(OWNED_INPUT + index * 4, word, 4)
        return self.invoke_adapter(OWNED_INPUT, *captured, **options)

    def claim(self):
        return self.invoke_owner('claim')

    def complete(self, nonce, succeeded=1):
        return self.invoke_owner('complete', nonce, succeeded)

    def retire(self, owner_ticket):
        return self.invoke_owner('retire', owner_ticket)

    def drained(self, owner_ticket):
        return self.invoke_owner('drained', owner_ticket)


class RegistryCarrierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = source.SOURCE.read_bytes()
        digest = hashlib.sha256(cls.image).hexdigest()
        if digest != source.SOURCE_SHA256 or len(cls.image) != source.SOURCE_SIZE:
            raise AssertionError(f'unrecognized reference: {digest}, size {len(cls.image)}')

    def machine(self, **options):
        return RegistryCarrierMachine(self.image, **options)

    def created(self, machine):
        self.assertEqual(machine.register(), 0)
        return machine.captured_carriers[-1]

    def test_pair_is_captured_at_emitted_creation_commit(self):
        m = self.machine()
        self.assertEqual(self.created(m), (1, 1))
        self.assertEqual(m.captured_carriers, [(1, 1)])
        self.assertIn(m.issuer_labels['binding_committed'], m.trace)
        self.assertEqual(m.binding_record()[1:3], (1, 1))

    def test_explicit_pair_publishes_actual_native44_queue_record(self):
        m = self.machine()
        captured = self.created(m)
        self.assertEqual(m.publish_payload(captured), (2, 0))
        self.assertEqual(m.count(), 1)
        self.assertEqual(m.words_at(m.head(), 11), (*PAYLOAD, 2, 1))
        for target in (owner.APPEND, 0x455BC0):
            self.assertIn(target, m.trace)
        self.assertEqual(m.peek(m.paint_list + 0x10), 44)

    def test_native_queue_claim_and_exact_ack_keep_private36_copy(self):
        m = self.machine()
        captured = self.created(m)
        self.assertEqual(m.publish_payload(captured), (2, 0))
        self.assertEqual(m.claim(), (OWNER_STATE + owner.COPY, 2))
        self.assertEqual(m.owned(), PAYLOAD)
        self.assertEqual(m.claim(), (0, 0))
        self.assertEqual(m.complete(99), (0, 0))
        self.assertEqual(m.count(), 1)
        self.assertEqual(m.complete(2), (1, 0))
        self.assertEqual(m.count(), 0)

    def test_equal_engine_generations_do_not_reissue_or_replace_old_carrier(self):
        m = self.machine()
        old = self.created(m)
        self.assertEqual(m.publish_payload(old), (2, 0))
        self.assertEqual(m.claim()[1], 2)
        self.assertEqual(m.retire(old[1]), (1, 0))
        new = self.created(m)
        self.assertEqual(new, (2, 3))
        self.assertEqual(m.captured_carriers, [old, new])
        self.assertEqual(m.publish_payload(old), (0, 0))
        self.assertEqual(m.publish_payload(new), (4, 1))
        self.assertEqual(m.complete(2), (3, 0))
        self.assertEqual(m.drained(old[1]), (1, 0))
        self.assertEqual(m.claim()[1], 4)
        self.assertEqual(m.owner_state(owner.ACTIVE_OWNER), new[1])
        self.assertEqual(m.complete(4), (1, 0))

    def test_native_append_index_one_is_success_not_error_quarantine(self):
        m = self.machine()
        captured = self.created(m)
        self.assertEqual(m.publish_payload(captured), (2, 0))
        self.assertEqual(m.publish_payload(captured), (3, 1))
        self.assertEqual(m.binding_header(), (1, 0, 0, 0))
        self.assertEqual(m.count(), 2)

    def test_payload_is_snapshotted_before_first_hostile_raw_call(self):
        m = self.machine()
        captured = self.created(m)
        changed = tuple(value ^ MASK for value in PAYLOAD)

        def mutate(machine, target):
            if target == RAW_LOCK and machine.r[4] == REGISTRY_MUTEX:
                for index, value in enumerate(changed):
                    machine.put(OWNED_INPUT + 4 * index, value, 4)

        m.on_service = mutate
        self.assertEqual(m.publish_payload(captured), (2, 0))
        self.assertEqual(m.words_at(OWNED_INPUT, 9), changed)
        self.assertEqual(m.words_at(m.head(), 9), PAYLOAD)

    def test_private_guards_follow_registry_then_paint_order(self):
        m = self.machine()
        captured = self.created(m)
        m.clear_events()
        self.assertEqual(m.publish_payload(captured), (2, 0))
        self.assertEqual([(event[0], event[1]) for event in m.raw_events],
                         [(RAW_LOCK, REGISTRY_MUTEX), (RAW_LOCK, PAINT_MUTEX),
                          (RAW_UNLOCK, PAINT_MUTEX), (RAW_UNLOCK, REGISTRY_MUTEX)])
        self.assertTrue(m.binding_accesses)
        self.assertTrue(m.owner_accesses)
        self.assertTrue(m.queue_accesses)
        self.assertTrue(all(event[-2] for event in m.binding_accesses))
        self.assertTrue(all(event[-2] and event[-1] for event in m.owner_accesses))
        self.assertTrue(all(event[-1] for event in m.queue_accesses))
        self.assertFalse(m.registry_held)
        self.assertFalse(m.paint_held)

    def test_success_and_denial_preserve_callee_saved_registers_and_hilo(self):
        for denied in (False, True):
            with self.subTest(denied=denied):
                m = self.machine()
                captured = self.created(m)
                saved = {register: 0x55300000 + register
                         for register in (*range(16, 24), 28, 30)}
                for register, value in saved.items():
                    m.r[register] = value
                m.hi, m.lo = 0x12345678, 0xABCDEF01
                result = m.publish_payload((captured[0], 99) if denied else captured)
                self.assertEqual(result[0] == 0, denied)
                self.assertEqual({register: m.r[register] for register in saved}, saved)
                self.assertEqual((m.r[29], m.r[31]), (STACK, RETURN))
                self.assertEqual((m.hi, m.lo), (0x12345678, 0xABCDEF01))

    def test_registry_acquisition_error_has_no_binding_or_owner_access(self):
        m = self.machine()
        captured = self.created(m)
        m.acquire = 22
        m.clear_events()
        self.assertEqual(m.publish_payload(captured), (0, 22))
        self.assertEqual(m.binding_accesses, [])
        self.assertEqual(m.owner_accesses, [])
        self.assertEqual(m.paint_events, [])
        self.assertEqual([event[0] for event in m.raw_events], [RAW_LOCK])

    def test_nested_raw_acquisition_error_quarantines_only_binding_storage(self):
        m = self.machine()
        captured = self.created(m)
        m.paint_acquire_result = 22
        m.clear_events()
        self.assertEqual(m.publish_payload(captured), (0, 22))
        self.assertEqual(m.binding_header(), (1, 1, 22, 0))
        self.assertEqual(m.owner_accesses, [])
        self.assertEqual(m.count(), 0)
        self.assertTrue(all(event[-2] for event in m.binding_accesses))

    def test_kernel_denial_is_not_a_reason_to_retry_remint_or_quarantine(self):
        m = self.machine()
        captured = self.created(m)
        self.assertEqual(m.retire(captured[1]), (1, 0))
        serial = m.owner_state(owner.SERIAL)
        self.assertEqual(m.publish_payload(captured), (0, 0))
        self.assertEqual(m.owner_state(owner.SERIAL), serial)
        self.assertEqual(m.binding_header(), (1, 0, 0, 0))
        self.assertEqual(m.captured_carriers, [captured])

    def test_queue_backpressure_does_not_burn_nonce_or_quarantine(self):
        m = self.machine(queue_capacity=1)
        captured = self.created(m)
        self.assertEqual(m.publish_payload(captured), (2, 0))
        self.assertEqual(m.publish_payload(captured), (0, 0))
        self.assertEqual(m.owner_state(owner.SERIAL), 2)
        self.assertEqual(m.binding_header(), (1, 0, 0, 0))
        self.assertEqual(m.count(), 1)

    def test_payload_engine_mismatch_does_not_adopt_latest_generation(self):
        m = self.machine()
        captured = self.created(m)
        changed = (*PAYLOAD[:2], ENGINE ^ 4, *PAYLOAD[3:])
        self.assertEqual(m.publish_payload(captured, changed), (0, 0))
        self.assertEqual(m.count(), 0)
        self.assertEqual(m.binding_header(), (1, 0, 0, 0))

    def test_unclaimed_retirement_removes_only_captured_generation(self):
        m = self.machine()
        old, new = self.created(m), self.created(m)
        self.assertEqual(m.publish_payload(old), (3, 0))
        self.assertEqual(m.publish_payload(new), (4, 1))
        self.assertEqual(m.retire(old[1]), (1, 1))
        self.assertEqual(m.words_at(m.head(), 11)[-2:], (4, new[1]))
        self.assertEqual(m.drained(old[1]), (1, 0))
        self.assertEqual(m.drained(new[1]), (0, 0))

    def test_creation_component_bytes_are_unchanged_and_only_adapter_is_appended(self):
        m = self.machine()
        legacy = creation.assemble(STATE, BIND_STATE, OWNER_STATE, CONTROLLER,
                                   REGISTRY_MUTEX, PAINT_MUTEX, CODE)
        code = legacy['code']
        self.assertEqual(len(code), 16216)
        self.assertEqual(hashlib.sha256(code).hexdigest(),
                         'ed9777609d63c0a2b58605d3c33fa11cf04c78861f915439296cdb99292f00bd')
        self.assertEqual(m.code[:len(code)], code)
        self.assertEqual(m.composition['creation_code_bytes'], len(code))
        self.assertEqual(len(m.code) - len(code), m.composition['adapter_code_bytes'])
        self.assertEqual(m.composition['binding_memory_bytes'], bindings.memory_bytes())

    def assert_no_early_accesses(self, machine):
        self.assertEqual(machine.reads, [])
        self.assertEqual(machine.writes, [])
        self.assertEqual(machine.raw_events, [])
        self.assertEqual(machine.journal_accesses, [])
        self.assertEqual(machine.binding_accesses, [])
        self.assertEqual(machine.owner_accesses, [])

    def test_receipt_source_aliases_deny_before_any_read_write_or_raw_service(self):
        m = self.machine()
        captured = self.created(m)
        end = STATE + m.composition['receipt_memory_bytes']
        for payload in (STATE - 32, STATE, end - 36, end - 4):
            with self.subTest(payload=hex(payload)):
                m.clear_events()
                self.assertEqual(m.invoke_adapter(payload, *captured), (0, 0))
                self.assert_no_early_accesses(m)

    def test_receipt_frame_aliases_deny_before_any_read_write_or_raw_service(self):
        m = self.machine()
        captured = self.created(m)
        end = STATE + m.composition['receipt_memory_bytes']
        for stack in (STATE + 8, STATE + carrier.FRAME,
                      end - 8, end + carrier.FRAME - 8):
            with self.subTest(stack=hex(stack)):
                m.clear_events()
                self.assertEqual(m.invoke_adapter(OWNED_INPUT, *captured,
                                                   stack=stack), (0, 0))
                self.assert_no_early_accesses(m)

    def test_payload_exactly_adjacent_to_either_receipt_boundary_is_allowed(self):
        for before in (False, True):
            with self.subTest(before=before):
                m = self.machine()
                captured = self.created(m)
                payload = (STATE - 36 if before else
                           STATE + m.composition['receipt_memory_bytes'])
                m.map(payload, 36)
                for index, word in enumerate(PAYLOAD):
                    m.put(payload + index * 4, word, 4)
                m.clear_events()
                self.assertEqual(m.invoke_adapter(payload, *captured), (2, 0))
                self.assertEqual(m.words_at(m.head(), 9), PAYLOAD)
                self.assertEqual(m.journal_accesses, [])

    def test_own_frame_adjacent_to_receipt_extent_passes_pointer_validation(self):
        # This bounds only the adapter's frame. Complete native/callee stack
        # separation remains a premise; deny at the first direct raw service
        # so this test does not put a deeper kernel frame into the journal.
        m = self.machine()
        captured = self.created(m)
        start = STATE + m.composition['receipt_memory_bytes']
        m.map(start, carrier.FRAME)
        m.acquire = 22
        m.clear_events()
        self.assertEqual(m.invoke_adapter(OWNED_INPUT, *captured,
                                           stack=start + carrier.FRAME), (0, 22))
        self.assertEqual([event[0] for event in m.raw_events], [RAW_LOCK])
        self.assertEqual(m.journal_accesses, [])
        self.assertEqual(m.binding_accesses, [])
        self.assertEqual(m.owner_accesses, [])

    def test_frame_aliases_any_creation_prefix_part_deny_before_accesses(self):
        m = self.machine()
        captured = self.created(m)
        end = CODE + m.composition['creation_code_bytes']
        for stack in (CODE + 8, CODE + carrier.FRAME, CODE + 0x1000,
                      end - 8, end + carrier.FRAME - 8):
            with self.subTest(stack=hex(stack)):
                m.clear_events()
                self.assertEqual(m.invoke_adapter(OWNED_INPUT, *captured,
                                                   stack=stack), (0, 0))
                self.assert_no_early_accesses(m)

    def adapter_assembly(self, machine, **options):
        configuration = dict(
            protected_prefix=(CODE, machine.composition['creation_code_bytes']),
            receipt_extent=(STATE, machine.composition['receipt_memory_bytes']))
        configuration.update(options)
        return carrier.assemble(
            BIND_STATE, OWNER_STATE, CONTROLLER, REGISTRY_MUTEX, PAINT_MUTEX,
            CODE + machine.composition['creation_code_bytes'],
            machine.owner_labels['publish'], **configuration)

    def test_optional_extent_descriptors_require_exact_integer_pair_tuples(self):
        m = self.machine()
        malformed = (False, True, 0, 1, 'extent', [], (), (STATE,),
                     [STATE, 16], (STATE, 16, 0), (False, 16),
                     (True, 16), (STATE, False), (STATE, True),
                     (float(STATE), 16), (STATE, 16.0), ('start', 16))
        for name in ('receipt_extent', 'protected_prefix'):
            for descriptor in malformed:
                with self.subTest(name=name, descriptor=descriptor):
                    with self.assertRaises(ValueError):
                        self.adapter_assembly(m, **{name: descriptor})

    def test_receipt_descriptor_rejects_wrap_alignment_and_protected_overlaps(self):
        m = self.machine()
        adapter_end = CODE + len(m.code)
        invalid = ((0, 16), (-4, 16), (STATE + 1, 16),
                   (STATE, 0), (STATE, -4), (STATE, 14),
                   (0xFFFFFFFC, 8), (bindings.NATIVE_RX[0], 4),
                   (BIND_STATE - 12, 16), (BIND_STATE, 4),
                   (BIND_STATE + bindings.memory_bytes() - 4, 8),
                   (OWNER_STATE, 4), (CONTROLLER, 4),
                   (REGISTRY_MUTEX, 4), (PAINT_MUTEX, 4),
                   (CODE, 4), (m.owner_labels['publish'], 4),
                   (CODE + m.composition['creation_code_bytes'], 4),
                   (adapter_end - 4, 8))
        for descriptor in invalid:
            with self.subTest(descriptor=descriptor), self.assertRaises(ValueError):
                self.adapter_assembly(m, receipt_extent=descriptor)
        # Half-open static extents may touch without sharing any byte. The
        # final machine word is a valid nonwrapping scalar extent as well.
        for descriptor in ((BIND_STATE - 4, 4),
                           (BIND_STATE + bindings.memory_bytes(), 4),
                           (adapter_end, 4), (0xFFFFFFFC, 4)):
            with self.subTest(valid_descriptor=descriptor):
                code, labels = self.adapter_assembly(m, receipt_extent=descriptor)
                self.assertIn('publish', labels)
                self.assertGreater(len(code), 0)

    def test_prefix_descriptor_requires_contained_publish_and_disjoint_preceding_rx(self):
        m = self.machine()
        length = m.composition['creation_code_bytes']
        publish = m.owner_labels['publish']
        invalid = ((0, length), (-4, length), (CODE + 1, length),
                   (CODE, 0), (CODE, -4), (CODE, length - 1),
                   (CODE, length + 4), (publish + 4, 4),
                   (CODE, publish - CODE),
                   (0x0FFFFFFC, 8), (bindings.NATIVE_RX[0], CODE),
                   (CONTROLLER, CODE + length - CONTROLLER))
        for descriptor in invalid:
            with self.subTest(descriptor=descriptor), self.assertRaises(ValueError):
                self.adapter_assembly(m, protected_prefix=descriptor)
        code, labels = self.adapter_assembly(m, protected_prefix=(CODE - 4, length + 4))
        self.assertIn('publish', labels)
        self.assertGreater(len(code), 0)


if __name__ == '__main__':
    unittest.main()
