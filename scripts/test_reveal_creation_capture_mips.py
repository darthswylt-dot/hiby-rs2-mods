#!/usr/bin/env python3
"""Execute creation-time output capture, not a native lifetime authority.

The output comes only from emitted sink/wrapper stores. No Python observer
recovers a pair from issuer registers, binding rows, a current pointer or a
count. Actual native registration and checked owner instructions execute;
allocation/raw services remain the existing bounded hostile-ABI substitutes.
"""

import hashlib
import unittest

from build_reveal_bridge_diag import b
import reveal_creation_capture_mips as capture
import reveal_creation_capture_stage as stage
import reveal_paint_retirement_mips as owner
import reveal_registry_owner_mips as bindings
import reveal_registry_receipt_mips as receipt
import test_folderfollow_reveal_static_contract as source
from test_reveal_owner_carrier_mips import RegistryCarrierMachine, OWNED_INPUT, PAYLOAD
from test_reveal_registry_owner_mips import (
    RegistryOwnerMachine, STATE, CODE, CONTROLLER, INPUT, REGISTRY_MUTEX,
    PAINT_MUTEX, ENGINE, DESCRIPTOR, RAW_LOCK, RAW_UNLOCK, STACK, RETURN, MASK,
    OWNER_STATE, BIND_STATE, REQUEST)


OUTPUT = 0x1FB0000
OUTPUT_REGION_BYTES = 0x100


class CreationCaptureMachine(RegistryCarrierMachine):
    """Observe real emitted output stores, never Python-issued pair capture."""

    def __init__(self, image, *, capacity=16, owner_capacity=16,
                 ticket_limit=owner.MAX_TICKET, queue_capacity=64,
                 acquire=0, release=0, paint_acquire_result=0,
                 paint_release_result=0, hooks=True):
        super().__init__(image, capacity=capacity, owner_capacity=owner_capacity,
                         ticket_limit=ticket_limit, queue_capacity=queue_capacity,
                         acquire=acquire, release=release,
                         paint_acquire_result=paint_acquire_result,
                         paint_release_result=paint_release_result, hooks=False)
        self.composition = stage.assemble(
            STATE, BIND_STATE, OWNER_STATE, CONTROLLER, REGISTRY_MUTEX,
            PAINT_MUTEX, CODE, capacity=capacity, owner_capacity=owner_capacity,
            ticket_limit=ticket_limit, queue_capacity=queue_capacity)
        self.code = self.code_bytes = self.composition['code']
        self.labels = self.composition['labels']
        self.owner_labels = self.composition['owner_labels']
        self.issuer_labels = self.composition['issuer_labels']
        self.receipt_labels = self.composition['receipt_labels']
        self.bridge_labels = self.receipt_labels
        self.adapter_labels = self.composition['adapter_labels']
        self.capture_labels = self.composition['capture_labels']
        self.patches = {0x439844: b.addiu(5, 0, owner.ELEMENT_BYTES)}
        if hooks:
            for pc, words in receipt.hook_words(self.receipt_labels).items():
                for index, word in enumerate(words):
                    self.patches[pc + index * 4] = word
        self.map(OUTPUT, OUTPUT_REGION_BYTES)
        self.output_accesses = []
        self.native_entries = []
        self.clear_events()

    def instruction(self, pc):
        if hasattr(self, 'native_entries') and pc == 0x4389E0:
            self.native_entries.append((pc, self.r[31], self.r[29],
                                        tuple(self.r[4:8])))
        # Deliberately bypass RegistryCarrierMachine.instruction: its Python
        # binding_committed observer cannot establish this output transport.
        RegistryOwnerMachine.instruction(self, pc)

    def tracked_access(self, kind, address, size):
        super().tracked_access(kind, address, size)
        if (hasattr(self, 'output_accesses')
                and OUTPUT <= address < OUTPUT + OUTPUT_REGION_BYTES):
            self.output_accesses.append((kind, self.current_pc, address, size,
                                         self.registry_held, self.paint_held))

    def external(self, target):
        if target == 0x4389E0:
            self.calls.append(target)
            self.run_at(target, self.r[31])
            return
        super().external(target)

    def clear_events(self):
        super().clear_events()
        for name in ('output_accesses', 'native_entries'):
            if hasattr(self, name):
                getattr(self, name).clear()

    def clear_output(self, output=OUTPUT):
        for offset in range(0, capture.OUTPUT_BYTES, 4):
            self.put(output + offset, 0, 4)
        self.clear_events()

    def outwords(self, output=OUTPUT):
        return self.words_at(output, capture.OUTPUT_BYTES // 4)

    def invoke_register(self, *, controller=CONTROLLER, descriptor=INPUT,
                        output=OUTPUT, stack=STACK, caller=RETURN):
        self.r[29], self.r[31] = stack, caller
        self.r[4:7] = controller, descriptor, output
        previous_registration = self.in_native_registration
        self.in_native_registration = True
        try:
            self.run_at(self.capture_labels['register'], caller)
            return self.r[2], self.r[3]
        finally:
            self.in_native_registration = previous_registration

    def invoke_sink(self, request=REQUEST, *, sequence=1, owner_ticket=1,
                    controller=CONTROLLER, stack=STACK, caller=RETURN):
        self.r[29], self.r[31] = stack, caller
        self.r[4:8] = controller, request, sequence, owner_ticket
        self.run_at(self.capture_labels['sink'], caller)
        return self.r[2], self.r[3]


class CreationCaptureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = source.SOURCE.read_bytes()
        digest = hashlib.sha256(cls.image).hexdigest()
        if digest != source.SOURCE_SHA256 or len(cls.image) != source.SOURCE_SIZE:
            raise AssertionError(f'unrecognized reference: {digest}, size {len(cls.image)}')

    def machine(self, **options):
        return CreationCaptureMachine(self.image, **options)

    def assert_empty_output(self, machine, output=OUTPUT):
        self.assertEqual(machine.outwords(output), (0,) * 8)
        self.assertEqual([event for event in machine.output_accesses
                          if event[0] == 'write'], [])

    def test_actual_emitted_capture_exports_only_historical_creation_pair(self):
        m = self.machine()
        self.assertEqual(m.invoke_register(), (0, OUTPUT))
        self.assertEqual(m.outwords(), (
            capture.OUTPUT_MAGIC, capture.HISTORICAL_RELEASE_UNOBSERVED,
            CONTROLLER, ENGINE, 1, 1, 1, 0))
        self.assertIn(m.capture_labels['sink'], m.trace)
        self.assertEqual(m.captured_carriers, [])
        self.assertEqual(len(m.native_entries), 1)
        self.assertEqual(m.native_entries[0][1], m.capture_labels['native_return'])
        writes = [event for event in m.output_accesses if event[0] == 'write']
        self.assertEqual(len(writes), 8)
        self.assertEqual(writes[-1][2], OUTPUT)
        self.assertTrue(all(not event[-2] and not event[-1] for event in writes))

    def test_engine_is_an_opaque_scalar_not_a_required_dereferenceable_object(self):
        m = self.machine()
        self.assertEqual(ENGINE, 0x87654321)
        self.assertEqual(m.invoke_register(), (0, OUTPUT))
        self.assertEqual(m.outwords()[3], ENGINE)
        self.assertFalse(any(address == ENGINE or ENGINE <= address < ENGINE + 0x54
                             for address, _ in m.reads))

    def test_equal_engine_creations_export_distinct_pair_into_separate_owned_outputs(self):
        m = self.machine()
        self.assertEqual(m.invoke_register(), (0, OUTPUT))
        first = m.outwords()
        second_output = OUTPUT + capture.OUTPUT_BYTES
        self.assertEqual(m.invoke_register(output=second_output), (0, second_output))
        self.assertEqual(m.outwords(), first)
        self.assertEqual(first[2:7], (CONTROLLER, ENGINE, 1, 1, 1))
        self.assertEqual(m.outwords(second_output)[2:7],
                         (CONTROLLER, ENGINE, 2, 2, 2))

    def test_already_published_output_is_not_reused_or_overwritten(self):
        m = self.machine()
        self.assertEqual(m.invoke_register(), (0, OUTPUT))
        first, count = m.outwords(), m.binding_header()[0]
        m.clear_events()
        self.assertEqual(m.invoke_register(), (MASK, 0))
        self.assertEqual(m.outwords(), first)
        self.assertEqual(m.binding_header()[0], count)
        self.assertEqual(m.native_entries, [])
        self.assertEqual([e for e in m.output_accesses if e[0] == 'write'], [])

    def test_success_preserves_normal_callee_saved_abi_and_hilo(self):
        m = self.machine()
        saved = {register: 0x77300000 + register
                 for register in (*range(16, 24), 28, 30)}
        for register, value in saved.items():
            m.r[register] = value
        m.hi, m.lo = 0x12345678, 0xABCDEF01
        self.assertEqual(m.invoke_register(), (0, OUTPUT))
        self.assertEqual({register: m.r[register] for register in saved}, saved)
        self.assertEqual((m.r[29], m.r[31]), (STACK, RETURN))
        self.assertEqual((m.hi, m.lo), (0x12345678, 0xABCDEF01))

    def test_descriptor_is_owned_before_first_hostile_raw_service(self):
        m = self.machine()
        replacement = tuple(value ^ MASK for value in DESCRIPTOR)

        def mutate(machine, target):
            if target == RAW_LOCK and machine.r[4] == REGISTRY_MUTEX:
                for index, word in enumerate(replacement):
                    machine.put(INPUT + 4 * index, word, 4)

        m.on_service = mutate
        self.assertEqual(m.invoke_register(), (0, OUTPUT))
        self.assertEqual(m.words_at(INPUT, 5), replacement)
        self.assertNotEqual(m.native_entries[0][3][1], INPUT)
        self.assertEqual(m.words_at(m.allocations[0] + 8, 5), DESCRIPTOR)
        self.assertEqual(m.outwords()[3], ENGINE)

    def test_native_allocation_failure_has_no_capture_and_preserves_missing_unlock(self):
        m = self.machine()
        m.fail_allocation = True
        self.assertEqual(m.invoke_register(), (MASK, 0))
        self.assert_empty_output(m)
        self.assertEqual(m.issue_requests, [])
        self.assertEqual([event[0] for event in m.raw_events], [RAW_LOCK])
        self.assertTrue(m.registry_held)

    def test_raw_registry_acquisition_failure_never_exports_native_forced_zero(self):
        for status in (1, 22, 0x82, MASK):
            with self.subTest(status=status):
                m = self.machine(acquire=status)
                self.assertEqual(m.invoke_register(), (0, 0))
                self.assert_empty_output(m)
                self.assertEqual(m.binding_header(), (0, 0, 0, 0))
                self.assertEqual(m.paint_events, [])

    def test_raw_paint_acquisition_failure_has_no_positive_capture(self):
        m = self.machine(paint_acquire_result=22)
        self.assertEqual(m.invoke_register(), (0, 0))
        self.assert_empty_output(m)
        self.assertEqual(m.binding_header(), (0, 1, 22, 0))
        self.assertEqual(m.owner_accesses, [])

    def test_raw_paint_release_failure_may_mint_owner_but_has_no_capture(self):
        m = self.machine(paint_release_result=22)
        self.assertEqual(m.invoke_register(), (0, 0))
        self.assert_empty_output(m)
        self.assertEqual(m.binding_header(), (0, 1, 22, 0))
        self.assertEqual(m.owner_state(owner.OWNER_COUNT), 1)

    def test_existing_binding_quarantine_denies_without_a_new_paint_call(self):
        m = self.machine()
        m.put(BIND_STATE + bindings.QUARANTINE, 1, 4)
        m.clear_events()
        self.assertEqual(m.invoke_register(), (0, 0))
        self.assert_empty_output(m)
        self.assertEqual(m.paint_events, [])

    def test_full_binding_table_does_not_export_an_earlier_pair(self):
        m = self.machine(capacity=1)
        self.assertEqual(m.invoke_register(), (0, OUTPUT))
        first = m.outwords()
        second_output = OUTPUT + capture.OUTPUT_BYTES
        m.clear_events()
        self.assertEqual(m.invoke_register(output=second_output), (0, 0))
        self.assert_empty_output(m, second_output)
        self.assertEqual(m.outwords(), first)
        self.assertEqual(m.binding_header()[0], 1)
        self.assertEqual(m.paint_events, [])

    def test_full_owner_table_leaves_new_output_unpublished(self):
        m = self.machine(owner_capacity=1)
        self.assertEqual(m.invoke_register(), (0, OUTPUT))
        second_output = OUTPUT + capture.OUTPUT_BYTES
        m.clear_events()
        self.assertEqual(m.invoke_register(output=second_output), (0, 0))
        self.assert_empty_output(m, second_output)
        self.assertEqual(m.binding_header()[0], 1)
        self.assertEqual(m.owner_state(owner.OWNER_COUNT), 1)

    def test_registry_release_error_exports_only_explicitly_unobserved_history(self):
        m = self.machine(release=22)
        self.assertEqual(m.invoke_register(), (0, OUTPUT))
        self.assertEqual(m.outwords()[1], capture.HISTORICAL_RELEASE_UNOBSERVED)
        self.assertEqual(m.outwords()[4:7], (1, 1, 1))
        self.assertEqual(m.raw_events[-1][-1], 22)
        self.assertFalse(m.registry_held)

    def test_plain_native_registration_does_not_export_a_wrapper_capture(self):
        m = self.machine()
        self.assertEqual(m.register(), 0)
        self.assertEqual(m.binding_header()[0], 1)
        self.assert_empty_output(m)
        self.assertEqual(m.captured_carriers, [])

    def test_repeated_stack_use_clears_capture_before_a_later_failed_creation(self):
        m = self.machine()
        self.assertEqual(m.invoke_register(), (0, OUTPUT))
        second_output = OUTPUT + capture.OUTPUT_BYTES
        m.fail_allocation = True
        m.clear_events()
        self.assertEqual(m.invoke_register(output=second_output), (MASK, 0))
        self.assert_empty_output(m, second_output)
        self.assertEqual(m.binding_header()[0], 1)

    def test_explicit_fixture_trust_can_publish_pair_read_from_owned_output(self):
        m = self.machine()
        self.assertEqual(m.invoke_register(), (0, OUTPUT))
        emitted = m.outwords()
        # This is explicit fixture-level trust in real-zero raw services, not
        # a release certificate inferred from the historical-only output.
        self.assertEqual(m.publish_payload(emitted[4:6]), (2, 0))
        self.assertEqual(m.words_at(m.head(), 11), (*PAYLOAD, 2, 1))
        self.assertEqual(m.captured_carriers, [])

    def test_preflight_invalid_arguments_never_enter_native_registration(self):
        for options in ({'controller': 0}, {'descriptor': 0}, {'output': 0},
                        {'descriptor': INPUT + 1}, {'output': OUTPUT + 1}):
            with self.subTest(options=options):
                m = self.machine()
                self.assertEqual(m.invoke_register(**options), (MASK, 0))
                self.assertEqual(m.native_entries, [])
                self.assertEqual(m.raw_events, [])
                self.assert_empty_output(m)


if __name__ == '__main__':
    unittest.main()
