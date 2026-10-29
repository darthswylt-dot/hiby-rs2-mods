#!/usr/bin/env python3
"""Execute scoped constructor stops without changing the engine-return ABI.

Both actual constructors, native engine construction and registry bodies run.
Resource/libc/raw services and the opaque UI/name continuations are bounded
hostile-ABI substitutes. Genuine retained mapped nonaliasing native136/128 and
private192 frames are supplied; malformed stack unwind is not a test claim.
"""

import unittest

import reveal_constructor_continuation_gate_mips as core
import reveal_constructor_continuation_gate_stage as stage
import test_reveal_registry_acquire_gate_mips as previous
from test_reveal_registry_acquire_gate_mips import (
    RegistryAcquireGateMachine, STATE, BIND_STATE, OWNER_STATE, CONTROLLER,
    REGISTRY_MUTEX, PAINT_MUTEX, CODE, LIFECYCLE, QUEUE, TRANSPORT_MUTEX,
    FAULT, RAW_LOCK, RAW_UNLOCK, STACK, RETURN, MASK)
from test_reveal_constructor_capture_mips import (
    DESCRIPTOR, RESOURCE, REQUEST_CALLBACK, REQUEST_CONTEXT)
from test_reveal_lineage_stage import LineageMachine


FIRST, SECOND = 0x43AD00, 0x43AF00
ENGINE_CONSTRUCTOR, NAME_POSTWORK = 0x8B4120, 0x437EE0
ROUTES = ((FIRST, 'first_gate', 136), (SECOND, 'second_gate', 128))
OUTER_VIEW = 0x1D00000


class ConstructorContinuationGateMachine(RegistryAcquireGateMachine):
    """Use the same UI substitute for linked and unlinked native transfers."""

    def __init__(self, image, *, resource_missing=False, validation_result=1,
                 setup_result=1, fail_engine_allocation=False, **options):
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
                     'birth_consumer', 'acquire_gate',
                     'constructor_continuation_gate'):
            setattr(self, name + '_labels', self.composition[name + '_labels'])
        self.bridge_labels = self.receipt_labels
        for pc, words in self.composition['coherent_hooks'].items():
            for index, word in enumerate(words):
                self.patches[pc + 4 * index] = word
        self.map(DESCRIPTOR, 0x1000)
        self.map(RESOURCE, 0x1000)
        self.map(OUTER_VIEW, 0x1000)
        self.resource_missing, self.validation_result = resource_missing, validation_result
        self.setup_result = setup_result
        self.fail_engine_allocation = fail_engine_allocation
        self.constructor_entries, self.engine_entries, self.created_engines = [], [], []
        self.constructor_services, self.native_continuations = [], []
        self.constructor_accesses, self.outer_enable_events = [], []
        self.put(CONTROLLER + 0x24, RESOURCE + 0x800, 4)
        self.bytes(DESCRIPTOR, bytes(104))
        self.bytes(DESCRIPTOR, b'Show_No_Mercy\0')
        for offset, value in ((0x40, 7), (0x44, 0x12345678),
                              (0x48, 4), (0x4C, 8), (0x50, 16),
                              (0x54, 32), (0x58, 3), (0x60, 100), (0x64, 200)):
            self.put(DESCRIPTOR + offset, value, 4)
        for offset, value in ((0x0C, 7), (0x5C, 256), (0x60, 400), (0x68, 64)):
            self.put(RESOURCE + offset, value, 4)
        self.bytes(RESOURCE + 0xE4, b'Show_No_Mercy\0')
        self.clear_events()

    def plain(self, word):
        if word >> 26 == 0x24:  # Actual first-constructor bounded name scan.
            rs, rt = (word >> 21) & 31, (word >> 16) & 31
            offset = word & 0xFFFF
            if offset & 0x8000:
                offset -= 0x10000
            self.r[rt] = self.get((self.r[rs] + offset) & MASK, 1)
            self.r[0] = 0
            return
        return super().plain(word)

    def instruction(self, pc):
        if hasattr(self, 'constructor_entries') and pc in (FIRST, SECOND):
            self.constructor_entries.append((pc, self.r[29], self.r[31],
                                             tuple(self.r[4:8])))
        if hasattr(self, 'engine_entries') and pc == ENGINE_CONSTRUCTOR:
            self.engine_entries.append((self.r[29], self.r[31]))
        super().instruction(pc)
        if pc == core.POSTWORK:
            # The emitted gate uses an unlinked J with the native JAL's RA.
            self.external(core.POSTWORK)

    def word(self, pc):
        if pc == core.POSTWORK:
            return 0x03E00008
        if pc == core.POSTWORK + 4:
            return 0
        return super().word(pc)

    def tracked_access(self, kind, address, size):
        super().tracked_access(kind, address, size)
        if hasattr(self, 'constructor_accesses'):
            self.constructor_accesses.append((kind, self.current_pc, address, size))

    def external(self, target):
        if target in (FIRST, SECOND, ENGINE_CONSTRUCTOR, 0x8B0D00):
            self.calls.append(target)
            self.run_at(target, self.r[31])
            if target == ENGINE_CONSTRUCTOR:
                self.created_engines.append(self.r[2])
            return
        if target == 0x4389E0:
            previous_registration = self.in_native_registration
            self.in_native_registration = True
            try:
                return super().external(target)
            finally:
                self.in_native_registration = previous_registration
        if target == 0x4669E0 and not self.in_native_registration:
            return LineageMachine.external(self, target)
        if target == 0x439680:
            self.calls.append(target)
            self.outer_enable_events.append(tuple(self.r[4:6]))
            self.hostile_result(0)
            return
        if target in (0x4862A0, 0xA5B240, 0xA5B4E0, 0x43A6E0,
                      0xA5B4B0, 0x438CE0, core.POSTWORK, NAME_POSTWORK):
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
            elif target == core.POSTWORK:
                self.native_continuations.append((target, arguments, self.r[29],
                                                  self.r[31], self.registry_held))
                result = 0xF00D0077
            else:
                result = 0xF00D0088
            self.hostile_result(result)
            return
        return super().external(target)

    def clear_events(self):
        super().clear_events()
        for name in ('constructor_entries', 'engine_entries', 'created_engines',
                     'constructor_services', 'native_continuations',
                     'constructor_accesses', 'outer_enable_events'):
            if hasattr(self, name):
                getattr(self, name).clear()

    def construct(self, constructor=FIRST, *, controller=CONTROLLER,
                  stack=STACK, caller=RETURN):
        self.r[29], self.r[31] = stack, caller
        if constructor == FIRST:
            self.r[4:8] = controller, DESCRIPTOR, REQUEST_CALLBACK, REQUEST_CONTEXT
        elif constructor == SECOND:
            self.r[4:7] = controller, REQUEST_CALLBACK, REQUEST_CONTEXT
        else:
            raise ValueError('unknown native constructor')
        self.run_at(constructor, caller)
        return self.r[2], self.r[3]


class ConstructorContinuationGateTests(unittest.TestCase):
    setUpClass = classmethod(previous.RegistryAcquireGateTests.setUpClass.__func__)

    def machine(self, **options):
        return ConstructorContinuationGateMachine(self.image, **options)

    def test_both_actual_constructors_keep_success_engine_and_native_postwork(self):
        for constructor, gate, frame in ROUTES:
            with self.subTest(constructor=hex(constructor)):
                m = self.machine()
                result, _ = m.construct(constructor)
                self.assertEqual(result, m.created_engines[0])
                self.assertNotEqual(result, 0)
                self.assertEqual(len(m.constructor_entries), 1)
                self.assertEqual(len(m.engine_entries), 1)
                self.assertEqual(len(m.native_entries), 1)
                self.assertEqual(m.lifecycle_header(), (1, 0, 0, 0))
                self.assertEqual(m.lifecycle_record()[5], result)
                self.assertEqual([event[0] for event in m.constructor_services][-2:],
                                 [core.POSTWORK, NAME_POSTWORK])
                self.assertIn(m.constructor_continuation_gate_labels[gate + '_forward'],
                              m.trace)
                self.assertNotIn(m.constructor_continuation_gate_labels[gate + '_stopped'],
                                 m.trace)
                self.assertFalse(m.registry_held)

    def test_forward_restores_complete_architecture_before_native_JAL_effects(self):
        for constructor, gate, frame in ROUTES:
            with self.subTest(constructor=hex(constructor)):
                m = self.machine()
                observations = {}

                def observe(current, pc):
                    labels = current.constructor_continuation_gate_labels
                    for name in (gate, gate + '_replay'):
                        if pc == labels[name]:
                            observations[name] = (current.r.copy(), current.hi, current.lo)

                m.on_instruction = observe
                m.construct(constructor)
                self.assertEqual(set(observations), {gate, gate + '_replay'})
                self.assertEqual(observations[gate], observations[gate + '_replay'])
                _, arguments, native_sp, native_ra, _ = m.native_continuations[0]
                self.assertEqual((arguments[0], native_sp, native_ra),
                                 (CONTROLLER, STACK - frame,
                                  core.FIRST_CONTINUATION if constructor == FIRST
                                  else core.SECOND_CONTINUATION))

    def test_successful_registration_does_not_interpret_poisoned_v1(self):
        for constructor, gate, frame in ROUTES:
            for poisoned in (0, 1, 22, 0x82, MASK):
                with self.subTest(constructor=hex(constructor), poisoned=poisoned):
                    m = self.machine()

                    def observe(current, pc):
                        if pc == current.constructor_continuation_gate_labels[gate]:
                            self.assertEqual(current.r[2], 0)
                            current.r[3] = poisoned

                    m.on_instruction = observe
                    result, _ = m.construct(constructor)
                    self.assertEqual(result, m.created_engines[0])
                    self.assertEqual(len(m.native_continuations), 1)

    def test_stopped_constructor_preserves_native_engine_return_and_callee_state(self):
        indices = (*range(16, 24), 28, 29, 30, 31)
        for constructor, gate, frame in ROUTES:
            with self.subTest(constructor=hex(constructor)):
                m = self.machine(acquire=22)
                m.r[29], m.r[31] = STACK, RETURN
                before = tuple(m.r[index] for index in indices)
                snapshots = {}

                def observe(current, pc):
                    if pc == current.constructor_continuation_gate_labels[gate]:
                        snapshots['gate'] = (current.r.copy(), current.hi, current.lo)
                    epilogue = (core.FIRST_EPILOGUE if constructor == FIRST
                                else core.SECOND_EPILOGUE)
                    if pc == epilogue:
                        snapshots['epilogue'] = (current.r.copy(), current.hi, current.lo)

                m.on_instruction = observe
                result, raw = m.construct(constructor)
                self.assertEqual(result, m.created_engines[0])
                self.assertNotEqual(result, 0)
                self.assertEqual(raw, 22)
                self.assertEqual(tuple(m.r[index] for index in indices), before)
                self.assertEqual(snapshots['gate'], snapshots['epilogue'])
                self.assertEqual((m.hi, m.lo), snapshots['gate'][1:])
                self.assertEqual(m.native_continuations, [])
                self.assertNotIn(NAME_POSTWORK, m.calls)

    def test_actual_node_allocation_failure_stops_without_invented_v1_classifier(self):
        for constructor, gate, frame in ROUTES:
            with self.subTest(constructor=hex(constructor)):
                m = self.machine()
                m.fail_allocation = True
                result, raw = m.construct(constructor)
                self.assertEqual(result, m.created_engines[0])
                self.assertEqual(raw, 0xBAD00003)
                self.assertEqual(m.allocations, [0])
                self.assertEqual(m.native_continuations, [])
                self.assertNotIn(NAME_POSTWORK, m.calls)
                self.assertEqual([event[0] for event in m.raw_events], [RAW_LOCK])
                self.assertTrue(m.registry_held)
                self.assertIn(m.constructor_continuation_gate_labels[gate + '_stopped'],
                              m.trace)

    def test_higher_explorer_caller_still_stores_and_enables_returned_engine(self):
        m = self.machine(acquire=22)
        m.r[29], m.r[31], m.r[16] = STACK, RETURN, OUTER_VIEW
        data, offset = m.region(DESCRIPTOR, 104)
        m.bytes(STACK + 0x16E4, bytes(data[offset:offset + 104]))
        m.put(STACK + 0x17D0, CONTROLLER, 4)
        m.clear_events()
        m.run_at(0x492908, 0x492930)
        engine = m.created_engines[0]
        self.assertEqual(m.peek(OUTER_VIEW + 0xCC), engine)
        self.assertEqual(m.outer_enable_events, [(CONTROLLER, engine)])
        self.assertEqual(m.native_continuations, [])
        self.assertNotIn(NAME_POSTWORK, m.calls)
        self.assertEqual(m.lifecycle_header(), (0, 0, 0, 0))


if __name__ == '__main__':
    unittest.main()
