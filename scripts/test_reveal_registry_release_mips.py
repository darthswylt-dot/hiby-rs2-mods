#!/usr/bin/env python3
"""Execute the optional same-invocation raw13C release witness, offline only.

Raw pthread services remain bounded hostile-ABI substitutes. Observing a real
zero result from this exact release is not native lifetime, initialized mutex,
allocation retention, free/retry authority or a native producer transport.
"""

import hashlib
import unittest

from build_reveal_bridge_diag import b
import reveal_creation_capture_mips as capture
import reveal_creation_capture_stage as stage
import reveal_paint_retirement_mips as owner
import reveal_registry_receipt_mips as receipt
import test_folderfollow_reveal_static_contract as source
from test_reveal_creation_capture_mips import (
    CreationCaptureMachine, OUTPUT, OUTPUT_REGION_BYTES)
from test_reveal_registry_owner_mips import (
    STATE, CODE, CONTROLLER, INPUT, REGISTRY_MUTEX, PAINT_MUTEX, ENGINE,
    DESCRIPTOR, RAW_LOCK, RAW_UNLOCK, STACK, RETURN, MASK, OWNER_STATE,
    BIND_STATE)


class RegistryReleaseMachine(CreationCaptureMachine):
    """Run actual native unlock and optional observers, no Python pair capture."""

    def __init__(self, image, *, capacity=16, owner_capacity=16,
                 ticket_limit=owner.MAX_TICKET, queue_capacity=64,
                 acquire=0, release=0, paint_acquire_result=0,
                 paint_release_result=0, hooks=True,
                 checked_registry_release=True):
        super().__init__(image, capacity=capacity, owner_capacity=owner_capacity,
                         ticket_limit=ticket_limit, queue_capacity=queue_capacity,
                         acquire=acquire, release=release,
                         paint_acquire_result=paint_acquire_result,
                         paint_release_result=paint_release_result, hooks=False)
        self.composition = stage.assemble(
            STATE, BIND_STATE, OWNER_STATE, CONTROLLER, REGISTRY_MUTEX,
            PAINT_MUTEX, CODE, capacity=capacity, owner_capacity=owner_capacity,
            ticket_limit=ticket_limit, queue_capacity=queue_capacity,
            checked_registry_release=checked_registry_release)
        self.code = self.code_bytes = self.composition['code']
        self.labels = self.composition['labels']
        for attribute in ('owner_labels', 'issuer_labels', 'receipt_labels',
                          'adapter_labels', 'capture_labels'):
            setattr(self, attribute, self.composition[attribute])
        self.bridge_labels = self.receipt_labels
        self.patches = {0x439844: b.addiu(5, 0, owner.ELEMENT_BYTES)}
        if hooks:
            redirects = receipt.hook_words(self.receipt_labels)
            if checked_registry_release:
                redirects.update(self.composition['release_hooks'])
            for pc, words in redirects.items():
                for index, word in enumerate(words):
                    self.patches[pc + index * 4] = word
        self.checked_registry_release = checked_registry_release
        self.clear_events()

    def private_release(self, stack=STACK):
        wrapper = stack - capture.FRAME
        return tuple(self.peek(wrapper + offset) for offset in (
            capture.RELEASE_TAG, capture.RELEASE_STATUS,
            capture.RELEASE_NATIVE_SP, capture.RELEASE_RAW_SP,
            capture.RELEASE_MUTEX))

    def remove_release_hook(self, name):
        pc = capture.HOOKS[name][0]
        for offset in (0, 4):
            self.patches.pop(pc + offset, None)


class RegistryReleaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = source.SOURCE.read_bytes()
        digest = hashlib.sha256(cls.image).hexdigest()
        if digest != source.SOURCE_SHA256 or len(cls.image) != source.SOURCE_SIZE:
            raise AssertionError(f'unrecognized reference: {digest}, size {len(cls.image)}')

    def machine(self, **options):
        return RegistryReleaseMachine(self.image, **options)

    def output_writes(self, machine):
        return [event for event in machine.output_accesses
                if event[0] == 'write'
                and CODE <= event[1] < CODE + len(machine.code)]

    def assert_empty_output(self, machine, output=OUTPUT):
        self.assertEqual(machine.outwords(output), (0,) * 8)
        self.assertEqual(self.output_writes(machine), [])

    def test_exact_raw_zero_exports_distinct_observed_release_flag(self):
        m = self.machine()
        self.assertEqual(m.invoke_register(), (0, OUTPUT))
        self.assertEqual(m.outwords(), (
            capture.OUTPUT_MAGIC, capture.REGISTRY_RELEASE_OBSERVED,
            CONTROLLER, ENGINE, 1, 1, 1, 0))
        self.assertEqual(capture.REGISTRY_RELEASE_OBSERVED, 2)
        self.assertNotEqual(capture.REGISTRY_RELEASE_OBSERVED,
                            capture.HISTORICAL_RELEASE_UNOBSERVED)
        self.assertEqual(m.captured_carriers, [])
        self.assertEqual(m.private_release(), (
            0, 0,
            STACK - capture.FRAME - capture.NATIVE_FRAME,
            STACK - capture.FRAME - capture.NATIVE_FRAME - 0x40,
            REGISTRY_MUTEX))

    def test_raw_release_keeps_native_argument_stack_and_return_pc(self):
        m = self.machine()
        self.assertEqual(m.invoke_register(), (0, OUTPUT))
        self.assertEqual(m.raw_events[-1], (
            RAW_UNLOCK, REGISTRY_MUTEX,
            STACK - capture.FRAME - capture.NATIVE_FRAME - 0x40,
            0x466DD0, 0))
        self.assertIn(0x466DC8, m.trace)
        self.assertIn(0x466DD0, m.trace)
        self.assertIn(0x466DD8, m.trace)
        self.assertEqual(m.words_at(m.raw_events[-1][2], 4),
                         tuple(0xD00D0000 + offset for offset in range(0, 16, 4)))

    def test_release_selection_observes_the_actual_callback_and_native_frame(self):
        m = self.machine()
        selected = []

        def at_selection(machine, pc):
            if pc == 0x438A60:
                selected.append((machine.r[25], machine.r[16], machine.r[29],
                                 machine.peek(machine.r[29] + 0x24)))

        m.on_instruction = at_selection
        self.assertEqual(m.invoke_register(), (0, OUTPUT))
        self.assertEqual(selected, [(
            0x437DA0, CONTROLLER, STACK - capture.FRAME - capture.NATIVE_FRAME,
            m.capture_labels['native_return'])])

    def test_private_witness_is_fresh_selected_entered_captured_then_consumed(self):
        m = self.machine()
        snapshots = []
        watched = (0x438A60, 0x466DC8, 0x466DD0,
                   m.capture_labels['native_return'])

        def observe(machine, pc):
            if pc in watched:
                snapshots.append((pc, machine.private_release()[0:2]))

        m.on_instruction = observe
        self.assertEqual(m.invoke_register(), (0, OUTPUT))
        self.assertEqual(snapshots, [
            (0x438A60, (capture.RELEASE_ARMED, MASK)),
            (0x466DC8, (capture.RELEASE_SELECTED, MASK)),
            (0x466DD0, (capture.RELEASE_ENTERED, MASK)),
            (m.capture_labels['native_return'], (capture.RELEASE_CAPTURED, 0))])
        self.assertEqual(m.private_release()[0:2], (0, 0))

    def test_raw_nonzero_cannot_be_upgraded_by_native_forced_zero(self):
        for status in (1, 22, 0x82, MASK):
            with self.subTest(status=status):
                m = self.machine(release=status)
                self.assertEqual(m.invoke_register(), (MASK, status))
                self.assert_empty_output(m)
                self.assertEqual(m.private_release()[1], status)
                self.assertEqual(m.raw_events[-1][-1], status)
                self.assertEqual(m.binding_header(), (1, 0, 0, 0))
                self.assertEqual(m.header(), (1, 0, 0, 0))
                self.assertEqual(m.owner_state(owner.OWNER_COUNT), 1)
                self.assertEqual(m.freed, [])

    def test_uncertain_release_never_accesses_shared_generation_or_registry_state(self):
        for status in (22, MASK):
            with self.subTest(status=status):
                m = self.machine(release=status)
                boundaries = []

                def at_service(machine, target):
                    if target == RAW_UNLOCK and machine.r[4] == REGISTRY_MUTEX:
                        boundaries.append((len(machine.binding_accesses),
                                           len(machine.owner_accesses),
                                           len(machine.journal_accesses)))

                m.on_service = at_service
                self.assertEqual(m.invoke_register(), (MASK, status))
                self.assertEqual(boundaries, [(len(m.binding_accesses),
                                               len(m.owner_accesses),
                                               len(m.journal_accesses))])
                self.assert_empty_output(m)
                self.assertEqual(m.binding_header(), (1, 0, 0, 0))

    def test_missing_either_raw_observer_denies_positive_output(self):
        for name in ('release_call', 'raw_release_call', 'raw_release_return'):
            with self.subTest(name=name):
                m = self.machine()
                m.remove_release_hook(name)
                self.assertEqual(m.invoke_register(), (MASK, 0))
                self.assert_empty_output(m)
                self.assertEqual(m.binding_header(), (1, 0, 0, 0))
                self.assertEqual(m.raw_events[-1][-1], 0)

    def test_no_release_observers_cannot_reuse_prior_same_stack_zero(self):
        m = self.machine()
        self.assertEqual(m.invoke_register(), (0, OUTPUT))
        first = m.outwords()
        for name in ('release_call', 'raw_release_call', 'raw_release_return'):
            m.remove_release_hook(name)
        second = OUTPUT + capture.OUTPUT_BYTES
        m.clear_events()
        self.assertEqual(m.invoke_register(output=second), (MASK, 0))
        self.assert_empty_output(m, second)
        self.assertEqual(m.outwords(), first)
        self.assertEqual(m.binding_header()[0], 2)
        self.assertEqual(m.private_release()[0], 0)

    def test_return_observer_alone_cannot_adopt_an_old_success_on_stack_reuse(self):
        m = self.machine()
        self.assertEqual(m.invoke_register(), (0, OUTPUT))
        m.remove_release_hook('raw_release_call')
        second = OUTPUT + capture.OUTPUT_BYTES
        m.clear_events()
        self.assertEqual(m.invoke_register(output=second), (MASK, 0))
        self.assert_empty_output(m, second)
        self.assertEqual(m.private_release()[0], 0)

    def test_each_new_bridge_preserves_all_gprs_except_displaced_native_effects(self):
        for status in (0, 22):
            with self.subTest(status=status):
                m = self.machine(release=status)
                snapshots = {}
                watched = {0x438A60, 0x437DA0, 0x466DC8,
                           RAW_UNLOCK, 0x466DD0, 0x466DD8}

                def observe(machine, pc):
                    if pc in watched:
                        snapshots[pc] = machine.r.copy(), machine.hi, machine.lo

                m.on_instruction = observe
                self.assertEqual(m.invoke_register(),
                                 (0, OUTPUT) if status == 0 else (MASK, status))
                for start, end, changes in (
                        (0x438A60, 0x437DA0, {4: CONTROLLER, 31: 0x438A68}),
                        (0x466DC8, RAW_UNLOCK, {31: 0x466DD0}),
                        (0x466DD0, 0x466DD8, {2: 0, 31: 0x437DB0})):
                    with self.subTest(bridge=hex(start)):
                        registers, hi, lo = snapshots[start]
                        expected = registers.copy()
                        for register, value in changes.items():
                            expected[register] = value
                        self.assertEqual(snapshots[end], (expected, hi, lo))

    def test_wrapper_preserves_callee_saved_registers_and_hilo_on_all_outcomes(self):
        for outcome in ('success', 'release_error', 'missing_observer', 'allocation'):
            with self.subTest(outcome=outcome):
                m = self.machine(release=22 if outcome == 'release_error' else 0)
                if outcome == 'missing_observer':
                    m.remove_release_hook('raw_release_return')
                if outcome == 'allocation':
                    m.fail_allocation = True
                saved = {register: 0x77500000 + register
                         for register in (*range(16, 24), 28, 30)}
                for register, value in saved.items():
                    m.r[register] = value
                m.hi, m.lo = 0x12345678, 0xABCDEF01
                result = m.invoke_register()
                self.assertEqual(result[0], 0 if outcome == 'success' else MASK)
                self.assertEqual(result[1], OUTPUT if outcome == 'success'
                                 else 22 if outcome == 'release_error' else 0)
                self.assertEqual({register: m.r[register] for register in saved}, saved)
                self.assertEqual((m.r[29], m.r[31]), (STACK, RETURN))
                self.assertEqual((m.hi, m.lo), (0x12345678, 0xABCDEF01))

    def test_native_allocation_failure_still_skips_unlock_and_has_no_release_witness(self):
        m = self.machine()
        m.fail_allocation = True
        self.assertEqual(m.invoke_register(), (MASK, 0))
        self.assert_empty_output(m)
        self.assertEqual([event[0] for event in m.raw_events], [RAW_LOCK])
        self.assertTrue(m.registry_held)
        self.assertEqual(m.binding_header(), (0, 0, 0, 0))
        self.assertEqual(m.private_release()[0], 0)

    def test_failed_raw_acquisition_retains_native_unchecked_writes_but_no_export(self):
        for status in (1, 22, MASK):
            with self.subTest(status=status):
                m = self.machine(acquire=status)
                self.assertEqual(m.invoke_register(), (0, 0))
                self.assert_empty_output(m)
                node = m.allocations[0]
                self.assertNotEqual(node, 0)
                self.assertEqual(m.words_at(node + 8, 5), DESCRIPTOR)
                self.assertEqual(m.words_at(CONTROLLER + 0x34, 2), (node, node))
                self.assertEqual(m.binding_header(), (0, 0, 0, 0))
                self.assertEqual(m.paint_events, [])

    def test_observed_release_without_owner_capture_is_not_a_positive_generation(self):
        for cause in ('owner_denied', 'paint_acquire_error', 'paint_release_error'):
            with self.subTest(cause=cause):
                options = ({'paint_acquire_result': 22} if cause == 'paint_acquire_error'
                           else {'paint_release_result': 22}
                           if cause == 'paint_release_error' else {})
                m = self.machine(**options)
                if cause == 'owner_denied':
                    m.put(OWNER_STATE + owner.CLOSED, 1, 4)
                    m.clear_events()
                self.assertEqual(m.invoke_register(), (0, 0))
                self.assert_empty_output(m)
                self.assertEqual(m.private_release()[0:2], (0, 0))
                self.assertEqual(m.raw_events[-1][-1], 0)

    def test_equal_engine_invocations_keep_distinct_emitted_pairs_and_outputs(self):
        m = self.machine()
        self.assertEqual(m.invoke_register(), (0, OUTPUT))
        first = m.outwords()
        second = OUTPUT + capture.OUTPUT_BYTES
        self.assertEqual(m.invoke_register(output=second), (0, second))
        self.assertEqual(first[1:7],
                         (capture.REGISTRY_RELEASE_OBSERVED, CONTROLLER, ENGINE, 1, 1, 1))
        self.assertEqual(m.outwords(second)[1:7],
                         (capture.REGISTRY_RELEASE_OBSERVED, CONTROLLER, ENGINE, 2, 2, 2))
        self.assertEqual(m.outwords(), first)
        self.assertEqual(m.captured_carriers, [])

    def test_output_is_committed_only_after_successful_raw_release_and_magic_is_last(self):
        m = self.machine()
        seen = []

        def before_release(machine, target):
            if target == RAW_UNLOCK and machine.r[4] == REGISTRY_MUTEX:
                seen.append(machine.outwords())

        m.on_service = before_release
        self.assertEqual(m.invoke_register(), (0, OUTPUT))
        self.assertEqual(seen, [(0,) * 8])
        writes = self.output_writes(m)
        self.assertEqual(len(writes), 8)
        self.assertEqual(writes[-1][2], OUTPUT)
        self.assertTrue(all(not event[-2] and not event[-1] for event in writes))

    def test_ordinary_native_registration_never_exports_wrapper_output(self):
        m = self.machine()
        self.assertEqual(m.register(), 0)
        self.assert_empty_output(m)
        self.assertEqual(m.binding_header()[0], 1)
        self.assertEqual(m.captured_carriers, [])

    def test_disabled_mode_keeps_historical_output_even_for_actual_release_error(self):
        m = self.machine(checked_registry_release=False, release=22)
        self.assertEqual(m.invoke_register(), (0, OUTPUT))
        self.assertEqual(m.outwords()[1], capture.HISTORICAL_RELEASE_UNOBSERVED)
        self.assertEqual(m.composition['release_hooks'], {})

    def test_default_composition_and_explicit_false_keep_the_previous_bytes(self):
        arguments = (STATE, BIND_STATE, OWNER_STATE, CONTROLLER,
                     REGISTRY_MUTEX, PAINT_MUTEX, CODE)
        implicit = stage.assemble(*arguments)
        explicit = stage.assemble(*arguments, checked_registry_release=False)
        self.assertEqual(implicit, explicit)
        self.assertEqual(len(implicit['code']), 22676)
        self.assertEqual(hashlib.sha256(implicit['code']).hexdigest(),
                         '90be0fdb56fa349782d7a5b89009661ca26484ad1beed25fb8628ddfc2383da5')
        self.assertEqual(implicit['release_hooks'], {})

    def test_no_late_generation_table_lookup_after_native_return(self):
        m = self.machine()
        boundaries = []

        def at_return(machine, pc):
            if pc == machine.capture_labels['native_return']:
                boundaries.append((len(machine.binding_accesses),
                                   len(machine.owner_accesses),
                                   len(machine.journal_accesses)))

        m.on_instruction = at_return
        self.assertEqual(m.invoke_register(), (0, OUTPUT))
        self.assertEqual(boundaries, [(len(m.binding_accesses),
                                       len(m.owner_accesses),
                                       len(m.journal_accesses))])


if __name__ == '__main__':
    unittest.main()
