#!/usr/bin/env python3
"""Run the first native constructor with emitted registration-result capture.

Actual43AD00,8B4120,8B0D00 and4389E0 bodies execute, followed by the existing
emitted checked capture/envelope/transport/paint path. Resource lookup, setup,
allocation, libc and raw services remain bounded hostile-ABI substitutes.
519FA0 is explicitly an opaque native UI continuation, NOT an innocuous helper:
the original constructor reaches it even after registration/raw-release error.
No generation is reconstructed by Python; no native lifetime or UI admission,
complete constructor coverage, image installation or hardware is established.
"""

import hashlib
import unittest

import reveal_constructor_capture_mips as core
import reveal_constructor_capture_stage as stage
import reveal_creation_capture_mips as capture
import reveal_paint_retirement_mips as owner
import reveal_registry_receipt_mips as receipt
import test_folderfollow_reveal_static_contract as source
from test_reveal_deferred_queue_mips import (
    DeferredQueueMachine, TRANSPORT_MUTEX, FAULT)
from test_reveal_deferred_envelope_mips import ENVELOPE
from test_reveal_lineage_stage import LineageMachine
from test_reveal_owner_carrier_mips import OWNED_INPUT, PAYLOAD
from test_reveal_registry_owner_mips import (
    STATE, BIND_STATE, OWNER_STATE, CODE, CONTROLLER, REGISTRY_MUTEX,
    PAINT_MUTEX, INPUT, RAW_LOCK, RAW_UNLOCK, STACK, RETURN, MASK)


REQUEST, DESCRIPTOR, OUTPUT, RESOURCE = (
    0x1F30000, 0x1F31000, 0x1F32000, 0x1F33000)
REQUEST_CALLBACK, REQUEST_CONTEXT = 0x490980, 0x1234ABCD
NATIVE_CONSTRUCTOR, NATIVE_ENGINE_CONSTRUCTOR = 0x43AD00, 0x8B4120
NATIVE_REGISTRATION_SITE, NATIVE_REGISTRATION_RETURN = 0x43AE8C, 0x43AE94
UI_CONTINUATION = 0x519FA0
DIAGNOSTIC_MAGIC = int.from_bytes(b'CNFL', 'little')
CONSTRUCTOR_BYTES = 136
OUTPUT_BYTES = 48


class ConstructorCaptureMachine(DeferredQueueMachine):
    """Private native allocations and substitutes; no observer-issued pair."""

    def __init__(self, image, *, constructor_hook=True, resource_missing=False,
                 validation_result=1, setup_result=1,
                 fail_engine_allocation=False, **options):
        super().__init__(image, **options)
        self.composition = stage.assemble(
            STATE, BIND_STATE, OWNER_STATE, CONTROLLER, REGISTRY_MUTEX,
            PAINT_MUTEX, CODE, self.deferred_list, TRANSPORT_MUTEX, FAULT,
            capacity=options.get('capacity', 16),
            owner_capacity=options.get('owner_capacity', 16),
            ticket_limit=options.get('ticket_limit', owner.MAX_TICKET),
            queue_capacity=options.get('queue_capacity', 64),
            transport_capacity=options.get(
                'transport_capacity', self.peek(self.deferred_list + 8)))
        self.code = self.code_bytes = self.composition['code']
        self.labels = self.composition['labels']
        for name in ('owner_labels', 'issuer_labels', 'receipt_labels',
                     'adapter_labels', 'capture_labels', 'envelope_labels',
                     'queue_labels', 'constructor_labels'):
            setattr(self, name, self.composition[name])
        self.bridge_labels = self.receipt_labels
        redirects = {**receipt.hook_words(self.receipt_labels),
                     **self.composition['release_hooks']}
        if constructor_hook:
            redirects.update(self.composition['constructor_hooks'])
        for pc, words in redirects.items():
            for index, word in enumerate(words):
                self.patches[pc + 4 * index] = word
        for address in (REQUEST, DESCRIPTOR, OUTPUT, RESOURCE):
            self.map(address, 0x1000)
        self.resource_missing = resource_missing
        self.validation_result, self.setup_result = validation_result, setup_result
        self.fail_engine_allocation = fail_engine_allocation
        self.name_allocation_failure = False
        self.registry_release_failure_releases = True
        self.constructor_entries, self.engine_entries = [], []
        self.constructor_output_accesses, self.constructor_services = [], []
        self.constructor_accesses = []
        self.native_continuations, self.created_engines = [], []
        self.put(CONTROLLER + 0x24, RESOURCE + 0x800, 4)
        self.set_descriptor()
        for index, value in enumerate((DESCRIPTOR, REQUEST_CALLBACK, REQUEST_CONTEXT)):
            self.put(REQUEST + 4 * index, value, 4)
        for offset, value in ((0x0C, 7), (0x5C, 256), (0x60, 400), (0x68, 64)):
            self.put(RESOURCE + offset, value, 4)
        self.clear_events()

    def set_descriptor(self, name=b'Show_No_Mercy\0', *, address=DESCRIPTOR):
        self.bytes(address, bytes(104))
        self.bytes(address, name)
        for offset, value in ((0x40, 7), (0x44, 0x12345678),
                              (0x48, 4), (0x4C, 8), (0x50, 16),
                              (0x54, 32), (0x58, 3), (0x60, 100), (0x64, 200)):
            self.put(address + offset, value, 4)

    def plain(self, word):
        if word >> 26 == 0x24:  # LBU used by the actual bounded name scan.
            rs, rt = (word >> 21) & 31, (word >> 16) & 31
            offset = word & 0xFFFF
            if offset & 0x8000:
                offset -= 0x10000
            self.r[rt] = self.get((self.r[rs] + offset) & MASK, 1)
            self.r[0] = 0
            return
        return super().plain(word)

    def instruction(self, pc):
        if hasattr(self, 'constructor_entries') and pc == NATIVE_CONSTRUCTOR:
            self.constructor_entries.append((pc, self.r[29], self.r[31],
                                             tuple(self.r[4:8])))
        if hasattr(self, 'engine_entries') and pc == NATIVE_ENGINE_CONSTRUCTOR:
            self.engine_entries.append((self.r[29], self.r[31],
                                        self.words_at(self.r[4], 14)))
        super().instruction(pc)

    def tracked_access(self, kind, address, size):
        super().tracked_access(kind, address, size)
        if hasattr(self, 'constructor_accesses'):
            self.constructor_accesses.append((kind, self.current_pc, address, size))
        if (hasattr(self, 'constructor_output_accesses')
                and OUTPUT <= address < OUTPUT + 0x1000):
            self.constructor_output_accesses.append((
                kind, self.current_pc, address, size,
                self.registry_held, self.paint_held))

    def external(self, target):
        if target in (NATIVE_CONSTRUCTOR, NATIVE_ENGINE_CONSTRUCTOR, 0x8B0D00):
            self.calls.append(target)
            self.run_at(target, self.r[31])
            if target == NATIVE_ENGINE_CONSTRUCTOR:
                self.created_engines.append(self.r[2])
            return
        if target == 0x4389E0:
            previous = self.in_native_registration
            self.in_native_registration = True
            try:
                return super().external(target)
            finally:
                self.in_native_registration = previous
        if target == 0x4669E0 and not self.in_native_registration:
            if getattr(self, 'name_allocation_failure', False):
                self.calls.append(target)
                self.hostile_result(0)
                return
            return LineageMachine.external(self, target)
        if target in (0x4862A0, 0xA5B240, 0xA5B4E0, 0x43A6E0,
                      0xA5B4B0, UI_CONTINUATION, 0x437EE0):
            arguments = tuple(self.r[4:8])
            self.calls.append(target)
            self.constructor_services.append((target, arguments, self.r[29], self.r[31]))
            if target == 0x4862A0:
                result = 0 if self.resource_missing else RESOURCE
            elif target == 0xA5B240:
                result = self.validation_result
            elif target == 0xA5B4E0:
                result = 0
                while self.get(self.r[4] + result, 1):
                    result += 1
                    if result > 1024:
                        raise AssertionError('bounded native strlen substitute exhausted')
            elif target == 0x43A6E0:
                self.put(self.r[6], 7, 4)
                result = self.setup_result
            elif target == 0xA5B4B0:
                if self.r[4] != 84:
                    raise AssertionError('native engine allocation width changed')
                result = 0 if self.fail_engine_allocation else self.allocation(84)
            elif target == UI_CONTINUATION:
                # Actual519FA0 may call native8B43C0 and a fresh name lookup.
                # Reaching this boundary after raw error is unsafe continuation,
                # not quarantine and not evidence of a pure allocation helper.
                self.native_continuations.append((target, arguments, self.r[29],
                                                  self.r[31], self.registry_held,
                                                  self.paint_held))
                result = 0xF00D0077
            else:
                result = 0xF00D0088
            self.hostile_result(result)
            return
        return super().external(target)

    def service(self, target):
        pointer = self.r[4]
        super().service(target)
        if (pointer == REGISTRY_MUTEX and target == RAW_UNLOCK and self.release
                and not getattr(self, 'registry_release_failure_releases', True)):
            self.registry_held = True

    def clear_events(self):
        super().clear_events()
        for name in ('constructor_entries', 'engine_entries',
                     'constructor_output_accesses', 'constructor_services',
                     'native_continuations', 'created_engines', 'constructor_accesses'):
            if hasattr(self, name):
                getattr(self, name).clear()

    def construct(self, *, controller=CONTROLLER, request=REQUEST,
                  output=OUTPUT, stack=STACK, caller=RETURN):
        self.r[29], self.r[31] = stack, caller
        self.r[4:7] = controller, request, output
        self.run_at(self.constructor_labels['construct'], caller)
        return self.r[2], self.r[3]

    def constructor_output(self, output=OUTPUT):
        return self.words_at(output, OUTPUT_BYTES // 4)

    def positive_payload(self, engine):
        return (*PAYLOAD[:2], engine, *PAYLOAD[3:])

    def constructor_frame(self, stack=STACK):
        return stack - core.FRAME


class ConstructorCaptureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = source.SOURCE.read_bytes()
        digest = hashlib.sha256(cls.image).hexdigest()
        if digest != source.SOURCE_SHA256 or len(cls.image) != source.SOURCE_SIZE:
            raise AssertionError(f'unrecognized reference: {digest}')

    def machine(self, **options):
        return ConstructorCaptureMachine(self.image, **options)

    def test_actual_constructor_exports_its_actual_checked_registration_capture(self):
        m = self.machine()
        engine, output = m.construct()
        self.assertNotEqual(engine, 0)
        self.assertEqual(output, OUTPUT)
        self.assertEqual(m.created_engines, [engine])
        self.assertEqual(m.constructor_output(), (
            capture.OUTPUT_MAGIC, capture.REGISTRY_RELEASE_OBSERVED,
            CONTROLLER, engine, 1, 1, 1, 0, engine, 0,
            STACK - core.FRAME + core.CAPTURE, 3))
        self.assertEqual(m.owner_record(), (1, engine, 0, 0))
        self.assertEqual(m.captured_carriers, [])
        self.assertEqual(len(m.native_entries), 1)
        for pc in (NATIVE_CONSTRUCTOR, NATIVE_ENGINE_CONSTRUCTOR, 0x8B0D00,
                   0x4389E0, m.receipt_labels['published'],
                   m.issuer_labels['binding_committed'],
                   m.constructor_labels['register_bridge'],
                   m.capture_labels['register'], m.capture_labels['sink']):
            self.assertIn(pc, m.trace)

    def test_native_constructor_receives_exact_owned_three_word_request(self):
        m = self.machine()
        m.construct()
        self.assertEqual(m.constructor_entries[0][1:], (
            STACK - core.FRAME, m.constructor_labels['native_return'],
            (CONTROLLER, DESCRIPTOR, REQUEST_CALLBACK, REQUEST_CONTEXT)))
        binding = m.binding_record()
        self.assertEqual(m.words_at(binding[5], 7)[3:], (
            0, 0x12345678, REQUEST_CONTEXT, REQUEST_CALLBACK))
        self.assertEqual(m.engine_entries[0][2][11:14],
                         (0x439EC0, 0x43B320, CONTROLLER))

    def test_actual84_byte_engine_copies_native_callback_and_controller_fields(self):
        m = self.machine()
        engine, _ = m.construct()
        self.assertEqual(m.peek(engine + 0x48), 0x439EC0)
        self.assertEqual(m.peek(engine + 0x4C), 0x43B320)
        self.assertEqual(m.peek(engine + 0x50), CONTROLLER)
        self.assertEqual(m.peek(engine + 0x34), 0)
        self.assertEqual(m.peek(engine + 0x0C), 16)
        self.assertEqual(m.peek(engine + 0x10), 32)

    def test_capture_survives_into_emitted_pack_guarded_native68_fifo_and_paint44(self):
        m = self.machine()
        engine, _ = m.construct()
        payload = m.positive_payload(engine)
        self.assertEqual(m.pack_payload(payload, captured=OUTPUT), (ENVELOPE, 0))
        self.assertEqual(m.enqueue(), (1, 0))
        self.assertEqual(m.pop_dispatch(), (2, 0))
        self.assertEqual(m.words_at(m.head(), 11), (*payload, 2, 1))
        self.assertEqual(m.transport_count(), 0)
        self.assertEqual(m.captured_carriers, [])
        self.assertFalse(m.registry_held or m.paint_held or m.transport_held)

    def test_two_actual_constructor_invocations_export_distinct_creation_pairs(self):
        m = self.machine()
        engine, _ = m.construct()
        first = m.constructor_output()
        other, output = m.construct(output=OUTPUT + OUTPUT_BYTES)
        self.assertNotEqual(engine, other)
        self.assertEqual(output, OUTPUT + OUTPUT_BYTES)
        self.assertEqual(m.constructor_output(), first)
        self.assertEqual(m.constructor_output(output)[3:7], (other, 2, 2, 2))
        self.assertEqual(m.captured_carriers, [])

    def test_full_binding_table_returns_actual_engine_but_no_generation_claim(self):
        m = self.machine(capacity=1)
        m.construct()
        engine, output = m.construct(output=OUTPUT + OUTPUT_BYTES)
        self.assertEqual(output, OUTPUT + OUTPUT_BYTES)
        self.assertEqual(m.constructor_output(output), (
            DIAGNOSTIC_MAGIC, 0, 0, 0, 0, 0, 0, 0, engine, 0, 0, 1))
        self.assertEqual(m.binding_header()[0], 1)
        self.assertEqual(m.owner_header()[owner.OWNER_COUNT // 4], 1)

    def test_raw_registration_release_error_is_preserved_before_native_overwrite(self):
        m = self.machine(release=0x82)
        engine, output = m.construct()
        self.assertEqual(output, OUTPUT)
        self.assertEqual(m.constructor_output(), (
            DIAGNOSTIC_MAGIC, 0, 0, 0, 0, 0, 0, 0, engine, MASK, 0x82, 1))
        self.assertTrue(m.native_continuations)
        self.assertIn(0x437EE0, m.calls)
        self.assertEqual(m.binding_header()[0], 1)  # native effects not rolled back
        self.assertEqual(m.pack_payload(m.positive_payload(engine), captured=OUTPUT), (0, 0))

    def test_failed_raw_acquisition_never_exports_owner_despite_native_writes(self):
        m = self.machine(acquire=22)
        engine, output = m.construct()
        self.assertEqual(output, OUTPUT)
        self.assertEqual(m.constructor_output()[0:8], (DIAGNOSTIC_MAGIC, *([0] * 7)))
        self.assertEqual(m.constructor_output()[8:], (engine, 0, 0, 1))
        self.assertEqual(m.binding_header()[0], 0)
        self.assertTrue(m.native_continuations)

    def test_missing_constructor_hook_has_explicit_missing_witness_diagnostic(self):
        m = self.machine(constructor_hook=False)
        engine, output = m.construct()
        self.assertEqual(output, OUTPUT)
        self.assertEqual(m.constructor_output(), (
            DIAGNOSTIC_MAGIC, 0, 0, 0, 0, 0, 0, 0, engine, 0, 0, 0))
        self.assertEqual(m.binding_header()[0], 1)
        self.assertNotIn(m.constructor_labels['register_bridge'], m.trace)
        self.assertEqual(m.captured_carriers, [])

    def test_registry_allocation_failure_keeps_actual_engine_and_missing_native_unlock(self):
        m = self.machine()
        m.fail_allocation = True
        engine, _ = m.construct()
        self.assertEqual(m.constructor_output()[8:], (engine, MASK, 0, 1))
        self.assertEqual(m.constructor_output()[0], DIAGNOSTIC_MAGIC)
        self.assertEqual([e[0] for e in m.raw_events], [RAW_LOCK])
        self.assertTrue(m.registry_held)
        self.assertTrue(m.native_continuations)  # original constructor defect unchanged

    def test_actual_native_null_engine_path_faults_without_export(self):
        m = self.machine(fail_engine_allocation=True)
        with self.assertRaisesRegex(AssertionError, r'^unmapped access 0x0, size 4$'):
            m.construct()
        self.assertEqual(m.created_engines, [0])
        self.assertTrue(m.native_continuations)
        self.assertEqual(m.constructor_output(), (0,) * 12)
        self.assertEqual(m.native_entries, [])

    def test_actual_missing_resource_path_faults_without_export(self):
        m = self.machine(resource_missing=True)
        with self.assertRaisesRegex(AssertionError, r'^unmapped access 0x0, size 4$'):
            m.construct()
        self.assertTrue(m.native_continuations)
        self.assertEqual(m.constructor_output(), (0,) * 12)
        self.assertEqual(m.created_engines, [])

    def test_output_magic_is_last_and_export_occurs_after_actual_constructor_return(self):
        m = self.machine()
        m.construct()
        writes = [e for e in m.constructor_output_accesses if e[0] == 'write']
        self.assertEqual(len(writes), 12)
        self.assertEqual(writes[-1][2], OUTPUT)
        self.assertTrue(all(not e[-2] and not e[-1] for e in writes))
        self.assertLess(m.trace.index(0x43AECC),
                        m.trace.index(m.constructor_labels['native_return']))
        self.assertTrue(all(CODE <= e[1] < CODE + len(m.code) for e in writes))

    def test_wrapper_preserves_standard_callee_saved_stack_return_and_hilo(self):
        m = self.machine()
        saved = {r: 0x77300000 + r for r in (*range(16, 24), 28, 30)}
        for register, value in saved.items():
            m.r[register] = value
        m.hi, m.lo = 0x12345678, 0xABCDEF01
        m.construct()
        self.assertEqual({r: m.r[r] for r in saved}, saved)
        self.assertEqual((m.r[29], m.r[31]), (STACK, RETURN))
        self.assertEqual((m.hi, m.lo), (0x12345678, 0xABCDEF01))

    def test_already_committed_output_refuses_before_native_side_effects(self):
        m = self.machine()
        m.construct()
        previous = m.constructor_output()
        m.clear_events()
        self.assertEqual(m.construct(), (MASK, 0))
        self.assertEqual(m.constructor_output(), previous)
        self.assertEqual(m.constructor_entries, [])
        self.assertEqual(m.calls, [])

    def test_maximum_accepted_name_has_terminator_inside64_byte_prefix(self):
        m = self.machine()
        m.set_descriptor(b'A' * 63 + b'\0')
        engine, output = m.construct()
        self.assertEqual(output, OUTPUT)
        self.assertEqual(m.constructor_output()[3], engine)
        self.assertEqual(m.constructor_output()[0], capture.OUTPUT_MAGIC)


if __name__ == '__main__':
    unittest.main()
