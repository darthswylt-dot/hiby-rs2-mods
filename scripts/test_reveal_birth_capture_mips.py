#!/usr/bin/env python3
"""Execute owned birth-token handoff, never reconstructing a latest token.

Actual4389E0 publication, emitted lifecycle commit and checked native release
execute. The fixture extends the existing bounded native deletion/reuse model;
opaque cleanup imports remain substitutes and no native lifetime is certified.
"""

import unittest

from build_reveal_bridge_diag import b
import reveal_birth_capture_mips as core
import reveal_birth_capture_stage as stage
import reveal_creation_capture_mips as capture
import reveal_registry_lifecycle_mips as lifecycle
import reveal_registry_receipt_mips as receipt
import test_reveal_registry_lifecycle_mips as previous
from test_reveal_registry_lifecycle_mips import (
    RegistryLifecycleMachine, LIFECYCLE, ENGINE, NAME, CONTROLLER,
    REGISTRY_MUTEX, PAINT_MUTEX, CODE, INPUT, STATE, BIND_STATE, OWNER_STATE,
    RAW_LOCK, RAW_UNLOCK, STACK, RETURN, MASK)


OUTPUT, OUTPUT_REGION_BYTES = 0x1F3C000, 0x1000


class BirthCaptureMachine(RegistryLifecycleMachine):
    """Outputs are emitted stores, not a Python lookup of lifecycle history."""

    def __init__(self, image, **options):
        hooks = options.pop('hooks', True)
        super().__init__(image, hooks=False, **options)
        selected = {name: options[name] for name in (
            'capacity', 'lifecycle_capacity', 'owner_capacity', 'ticket_limit',
            'queue_capacity') if name in options}
        self.composition = stage.assemble(
            STATE, BIND_STATE, OWNER_STATE, CONTROLLER, REGISTRY_MUTEX,
            PAINT_MUTEX, CODE, LIFECYCLE, **selected)
        self.code = self.code_bytes = self.composition['code']
        self.labels = self.composition['labels']
        for name in ('owner', 'issuer', 'receipt', 'adapter', 'capture',
                     'lifecycle', 'retirement', 'birth_capture'):
            setattr(self, name + '_labels', self.composition[name + '_labels'])
        self.bridge_labels = self.receipt_labels
        self.patches = {0x439844: b.addiu(5, 0, previous.owner.ELEMENT_BYTES)}
        if hooks:
            for pc, words in self.composition['coherent_hooks'].items():
                for index, word in enumerate(words):
                    self.patches[pc + 4 * index] = word
        self.map(OUTPUT, OUTPUT_REGION_BYTES)
        self.birth_output_accesses, self.birth_sink_requests = [], []
        self.clear_events()

    def tracked_access(self, kind, address, size):
        super().tracked_access(kind, address, size)
        if (hasattr(self, 'birth_output_accesses')
                and OUTPUT <= address < OUTPUT + OUTPUT_REGION_BYTES):
            self.birth_output_accesses.append((kind, self.current_pc, address,
                                                size, self.registry_held,
                                                self.paint_held))

    def instruction(self, pc):
        if (hasattr(self, 'birth_sink_requests')
                and pc == self.birth_capture_labels['birth_sink']):
            try:
                event = self.words_at(self.r[5], 8)
            except AssertionError:
                event = None
            self.birth_sink_requests.append((self.r[6], event))
        super().instruction(pc)

    def clear_events(self):
        super().clear_events()
        for name in ('birth_output_accesses', 'birth_sink_requests'):
            if hasattr(self, name):
                getattr(self, name).clear()

    def register_birth(self, *, controller=CONTROLLER, descriptor=INPUT,
                       output=OUTPUT, stack=STACK, caller=RETURN):
        self.r[29], self.r[31] = stack, caller
        self.r[4:7] = controller, descriptor, output
        previous_registration = self.in_native_registration
        self.in_native_registration = True
        try:
            self.run_at(self.birth_capture_labels['register_birth'], caller)
            return self.r[2], self.r[3]
        finally:
            self.in_native_registration = previous_registration

    def birth_output(self, output=OUTPUT):
        return self.words_at(output, core.OUTPUT_BYTES // 4)

    def birth_output_writes(self):
        return [event for event in self.birth_output_accesses if event[0] == 'write']


class BirthCaptureTests(unittest.TestCase):
    setUpClass = classmethod(previous.RegistryLifecycleTests.setUpClass.__func__)

    def machine(self, **options):
        return BirthCaptureMachine(self.image, **options)

    def assert_empty_output(self, machine, output=OUTPUT):
        self.assertEqual(machine.birth_output(output), (0,) * 12)
        self.assertFalse(any(event[0] == 'write' and output <= event[2] < output + 48
                             for event in machine.birth_output_accesses))

    def test_actual_commit_exports_its_own_token_and_complete_owned_event(self):
        m = self.machine()
        self.assertEqual(m.register_birth(), (0, OUTPUT))
        node = m.allocations[-1]
        native_sp = STACK - core.FRAME - capture.FRAME - capture.NATIVE_FRAME
        event = (CONTROLLER, REGISTRY_MUTEX, node, ENGINE, native_sp,
                 m.capture_labels['native_return'], lifecycle.PUBLICATION_SITE, 0)
        self.assertEqual(m.birth_output(), (core.OUTPUT_MAGIC, 1, *event, 0, 0))
        self.assertEqual(m.birth_sink_requests, [(1, event)])
        self.assertEqual(m.captured_carriers, [])
        self.assertEqual(len(m.native_entries), 1)
        self.assertEqual(m.native_entries[0][1], m.capture_labels['native_return'])
        writes = m.birth_output_writes()
        self.assertEqual(len(writes), 12)
        self.assertEqual(writes[-1][2], OUTPUT)
        self.assertTrue(all(not event[-2] and not event[-1] for event in writes))
        self.assertEqual(m.lifecycle_header(), (1, 0, 0, 0))

    def test_equal_engine_invocations_export_distinct_tokens_to_owned_outputs(self):
        m = self.machine()
        self.assertEqual(m.register_birth(), (0, OUTPUT))
        first = m.birth_output()
        self.assertEqual(m.register_birth(output=OUTPUT + 48), (0, OUTPUT + 48))
        second = m.birth_output(OUTPUT + 48)
        self.assertEqual((first[1], second[1]), (1, 2))
        self.assertNotEqual(first[4], second[4])
        self.assertEqual((first[5], second[5]), (ENGINE, ENGINE))
        self.assertEqual(m.birth_output(), first)

    def test_full_old_receipt_and_binding_do_not_hide_actual_new_birth(self):
        m = self.machine(capacity=1, lifecycle_capacity=3)
        self.assertEqual(m.register_birth(), (0, OUTPUT))
        old_receipt, old_binding = m.record(), m.binding_record()
        m.clear_events()
        self.assertEqual(m.register_birth(output=OUTPUT + 48), (0, OUTPUT + 48))
        self.assertEqual(m.birth_output(OUTPUT + 48)[1], 2)
        self.assertEqual((m.record(), m.binding_record()), (old_receipt, old_binding))
        self.assertEqual(m.paint_events, [])
        self.assertEqual(len(m.native_entries), 1)

    def test_owner_quota_does_not_hide_an_independent_birth(self):
        m = self.machine(owner_capacity=1)
        self.assertEqual(m.register_birth(), (0, OUTPUT))
        self.assertEqual(m.register_birth(output=OUTPUT + 48), (0, OUTPUT + 48))
        self.assertEqual(m.birth_output(OUTPUT + 48)[1], 2)
        self.assertEqual(m.binding_header()[0], 1)

    def test_paint_errors_do_not_become_a_false_birth_or_release_failure(self):
        for field in ('paint_acquire_result', 'paint_release_result'):
            for status in (1, 22, 0x82, MASK):
                with self.subTest(field=field, status=status):
                    m = self.machine(**{field: status})
                    self.assertEqual(m.register_birth(), (0, OUTPUT))
                    self.assertEqual(m.birth_output()[1:6],
                                     (1, CONTROLLER, REGISTRY_MUTEX,
                                      m.allocations[-1], ENGINE))
                    self.assertEqual(m.birth_output()[-2:], (0, 0))
                    self.assertEqual(m.binding_header()[0], 0)
                    self.assertEqual(m.lifecycle_header(), (1, 0, 0, 0))

    def test_actual_delete_and_reused_node_export_new_token_without_retagging_old(self):
        m = self.machine(capacity=1, lifecycle_capacity=3)
        self.assertEqual(m.register_birth(), (0, OUTPUT))
        first, node = m.birth_output(), m.allocations[-1]
        m.delete_native()
        self.assertEqual(m.lifecycle_record()[10], lifecycle.RETIREMENT_SELECTED)
        m.reuse_node = node
        m.clear_events()
        self.assertEqual(m.register_birth(output=OUTPUT + 48), (0, OUTPUT + 48))
        self.assertEqual(m.birth_output(OUTPUT + 48)[1:6],
                         (2, CONTROLLER, REGISTRY_MUTEX, node, ENGINE))
        self.assertEqual(m.reused_nodes, [node])
        self.assertEqual(m.birth_output(), first)
        self.assertEqual(m.lifecycle_record()[1], 1)
        self.assertEqual(m.lifecycle_record()[10], lifecycle.RETIREMENT_SELECTED)
        self.assertEqual(m.lifecycle_record(1)[1], 2)

    def test_raw_registry_acquire_failure_can_publish_but_cannot_export(self):
        for status in (1, 22, 0x82, MASK):
            with self.subTest(status=status):
                m = self.machine(acquire=status)
                self.assertEqual(m.register_birth(), (0, 0))
                self.assert_empty_output(m)
                self.assertEqual(m.lifecycle_accesses, [])
                self.assertEqual(m.birth_sink_requests, [])
                self.assertNotEqual(m.peek(CONTROLLER + 0x34), CONTROLLER + 0x34)

    def test_raw_registry_release_error_preserves_exact_error_and_has_no_late_access(self):
        for status in (1, 22, 0x82, MASK):
            with self.subTest(status=status):
                m = self.machine(release=status)
                boundaries = []

                def observe(machine, target):
                    if target == RAW_UNLOCK and machine.r[4] == REGISTRY_MUTEX:
                        boundaries.append((len(machine.lifecycle_accesses),
                                           len(machine.binding_accesses),
                                           len(machine.owner_accesses),
                                           len(machine.journal_accesses),
                                           len(machine.birth_output_accesses)))

                m.on_service = observe
                self.assertEqual(m.register_birth(), (MASK, status))
                self.assert_empty_output(m)
                self.assertEqual(boundaries, [(len(m.lifecycle_accesses),
                    len(m.binding_accesses), len(m.owner_accesses),
                    len(m.journal_accesses), len(m.birth_output_accesses))])
                self.assertEqual(m.lifecycle_header(), (1, 0, 0, 0))

    def test_native_allocation_failure_preserves_missing_unlock_without_output(self):
        m = self.machine()
        m.fail_allocation = True
        self.assertEqual(m.register_birth(), (MASK, 0))
        self.assert_empty_output(m)
        self.assertEqual(m.birth_sink_requests, [])
        self.assertEqual([event[0] for event in m.raw_events], [RAW_LOCK])
        self.assertTrue(m.registry_held)

    def test_lifecycle_fault_or_capacity_refuses_without_borrowing_previous_token(self):
        for failure in ('fault', 'full'):
            with self.subTest(failure=failure):
                m = self.machine(lifecycle_capacity=1)
                self.assertEqual(m.register_birth(), (0, OUTPUT))
                first = m.birth_output()
                if failure == 'fault':
                    m.put(LIFECYCLE + lifecycle.FAULT, 1, 4)
                m.clear_events()
                self.assertEqual(m.register_birth(output=OUTPUT + 48), (0, 0))
                self.assert_empty_output(m, OUTPUT + 48)
                self.assertEqual(m.birth_output(), first)
                self.assertEqual(m.birth_sink_requests, [])
                self.assertEqual(m.lifecycle_header()[0:2], (1, 1))

    def test_no_shared_history_is_read_after_checked_capture_returns(self):
        m = self.machine()
        boundaries = []

        def observe(machine, pc):
            if pc == machine.birth_capture_labels['capture_return']:
                boundaries.append((len(machine.lifecycle_accesses),
                                   len(machine.binding_accesses),
                                   len(machine.owner_accesses),
                                   len(machine.journal_accesses), len(machine.calls)))

        m.on_instruction = observe
        self.assertEqual(m.register_birth(), (0, OUTPUT))
        self.assertEqual(boundaries, [(len(m.lifecycle_accesses), len(m.binding_accesses),
                                       len(m.owner_accesses), len(m.journal_accesses),
                                       len(m.calls))])

    def test_plain_native_registration_never_exports_to_an_unarmed_wrapper(self):
        m = self.machine()
        self.assertEqual(m.register(), 0)
        self.assert_empty_output(m)
        self.assertEqual(m.lifecycle_header(), (1, 0, 0, 0))

    def test_success_and_refusals_preserve_callee_saved_registers_and_hilo(self):
        for case in ('success', 'acquire', 'release', 'full', 'allocation'):
            with self.subTest(case=case):
                m = self.machine(acquire=22 if case == 'acquire' else 0,
                                 release=22 if case == 'release' else 0)
                if case == 'full':
                    m.put(LIFECYCLE + lifecycle.FAULT, 1, 4)
                m.fail_allocation = case == 'allocation'
                saved = {register: 0x77440000 + register
                         for register in (*range(16, 24), 28, 30)}
                for register, value in saved.items():
                    m.r[register] = value
                m.hi, m.lo = 0x12345678, 0xABCDEF01
                m.register_birth()
                self.assertEqual({register: m.r[register] for register in saved}, saved)
                self.assertEqual((m.r[29], m.r[31]), (STACK, RETURN))
                self.assertEqual((m.hi, m.lo), (0x12345678, 0xABCDEF01))


if __name__ == '__main__':
    unittest.main()
