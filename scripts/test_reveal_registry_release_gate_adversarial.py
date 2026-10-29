#!/usr/bin/env python3
"""Missing/incoherent release evidence refuses only scoped continuation.

Controlled private-witness/context mutations are restored before native unwind
where needed; they do not assert malformed-stack recovery. Separate-CPU cases
are adversarial schedules, not permission to reuse an uncertain instance. The
new gate supplies no rollback, unlock retry, graph cleanup or global quarantine.
"""

import unittest

import reveal_constructor_continuation_gate_mips as constructor
import reveal_registry_acquire_gate_mips as acquire
import reveal_registry_receipt_mips as receipt
import test_reveal_registry_release_gate_mips as fixture
from test_reveal_registry_release_gate_mips import (
    RegistryReleaseGateMachine, ExplorerFailureGateMachine, FIRST, SECOND,
    ROUTES, PHASES, NAME_POSTWORK, EXPLORER_SLICE_END, EXPLORER_NULL,
    OUTER_VIEW, SECOND_CALLER_STACK, CONTROLLER, REGISTRY_MUTEX, PAINT_MUTEX,
    RAW_LOCK, RAW_UNLOCK, STACK, RETURN, MASK, core)


PAINT_UNLOCK = 0x437D60


class RegistryReleaseGateAdversarialTests(unittest.TestCase):
    setUpClass = classmethod(fixture.RegistryReleaseGateTests.setUpClass.__func__)
    machine = fixture.RegistryReleaseGateTests.machine
    assert_null_unwind = fixture.RegistryReleaseGateTests.assert_null_unwind
    watch_raw_release = fixture.RegistryReleaseGateTests.watch_raw_release
    assert_private_after_release = fixture.RegistryReleaseGateTests.assert_private_after_release
    assert_local_stop = fixture.RegistryReleaseGateTests.assert_local_stop

    def assert_unknown_stop(self, machine, address=FIRST):
        self.assertEqual(machine.construct(address), (machine.created_engines[0], 0))
        self.assert_local_stop(machine, address, 0)
        native_sp = machine.native_entries[0][2] - core.REGISTER_FRAME
        self.assertEqual(machine.release_words(native_sp)[0], 0)
        self.assertIn(machine.registry_release_gate_labels['complete_denied'], machine.trace)

    def assert_legacy_explorer_use(self, machine):
        machine.seed_explorer()
        machine.clear_events()
        machine.run_explorer_slice(EXPLORER_SLICE_END)
        engine = machine.created_engines[0]
        self.assertEqual(machine.peek(OUTER_VIEW + 0xCC), engine)
        self.assertEqual(machine.outer_enable_events, [(CONTROLLER, engine)])
        self.assertNotIn(EXPLORER_NULL, machine.trace)

    def test_each_raw_release_error_stops_both_constructors_without_guessing_mutex_ownership(self):
        for address, gate, frame in ROUTES:
            for status in (1, 22, 0x82, MASK):
                for released in (False, True):
                    with self.subTest(constructor=hex(address), status=status, released=released):
                        m = self.machine(release=status,
                                         registry_release_failure_releases=released)
                        marks = self.watch_raw_release(m)
                        self.assertEqual(m.construct(address), (m.created_engines[0], status))
                        self.assert_private_after_release(m, marks)
                        self.assert_local_stop(m, address, status)
                        self.assertEqual(m.registry_held, not released)
                        self.assertEqual(m.raw_events[-1][-1], status)
                        self.assertEqual(m.lifecycle_header(), (1, 0, 0, 0))
                        self.assertEqual(len(m.allocations), 1)
                        self.assertEqual(m.freed, [])

    def test_each_raw_release_error_cuts_explorer_store_and_enable_with_retention_unchanged(self):
        for status in (1, 22, 0x82, MASK):
            for released in (False, True):
                with self.subTest(status=status, released=released):
                    m = self.machine(release=status,
                                     registry_release_failure_releases=released)
                    context = m.seed_explorer()
                    m.clear_events()
                    marks = self.watch_raw_release(m)
                    self.assertEqual(m.run_explorer_slice(), (0, status))
                    self.assert_private_after_release(m, marks, context['caller_stack'])
                    self.assert_null_unwind(m, context)
                    self.assertEqual(m.registry_held, not released)
                    self.assertEqual(len(m.allocations), 1)
                    self.assertEqual(m.lifecycle_header(), (1, 0, 0, 0))

    def test_missing_each_observer_phase_chains_old_handler_but_denies_unknown_release(self):
        for phase in PHASES:
            for status in (0, 22):
                with self.subTest(phase=phase, status=status):
                    m = self.machine(release=status)
                    m.restore_legacy_release_phase(phase)
                    self.assert_unknown_stop(m)
                    self.assertNotIn(m.registry_release_gate_labels[phase], m.trace)
                    self.assertEqual(m.raw_events[-1][-1], status)
                    self.assertEqual(m.lifecycle_header(), (1, 0, 0, 0))
                    self.assertEqual(len([e for e in m.raw_events
                                          if e[0:2] == (RAW_UNLOCK, REGISTRY_MUTEX)]), 1)

    def test_missing_completion_retains_masked_release_and_original_outer_use_counterexample(self):
        m = self.machine(release=22)
        m.restore_legacy_release_phase('complete')
        self.assert_legacy_explorer_use(m)
        self.assertNotIn(m.registry_release_gate_labels['complete'], m.trace)
        self.assertEqual(len(m.native_continuations), 1)
        self.assertIn(NAME_POSTWORK, m.calls)
        self.assertEqual(m.raw_events[-1][-1], 22)

    def test_missing_acquire_gate_is_not_repaired_by_a_later_actual_zero_release(self):
        m = self.machine(acquire=22, release=0)
        m.remove_pair(acquire.HOOKS['register_gate'][0])
        self.assert_legacy_explorer_use(m)
        self.assertEqual(len(m.allocations), 1)
        self.assertEqual(m.lifecycle_header(), (0, 0, 0, 0))
        self.assertEqual(len(m.native_continuations), 1)
        self.assertIn(m.registry_release_gate_labels['complete_admitted'], m.trace)

    def test_missing_constructor_status_gate_leaves_original_ui_and_outer_use(self):
        m = self.machine(release=22)
        m.remove_pair(constructor.HOOKS['first_gate'][0])
        self.assert_legacy_explorer_use(m)
        self.assertIn(m.registry_release_gate_labels['complete_denied'], m.trace)
        self.assertEqual(len(m.native_continuations), 1)
        self.assertIn(NAME_POSTWORK, m.calls)

    def test_missing_explorer_splice_keeps_nonzero_engine_outer_store_after_local_stop(self):
        m = self.machine(release=22)
        m.remove_generated_splice()
        self.assert_legacy_explorer_use(m)
        self.assertIn(m.registry_release_gate_labels['complete_denied'], m.trace)
        self.assertEqual(m.native_continuations, [])
        self.assertNotIn(NAME_POSTWORK, m.calls)

    def test_v1_poison_cannot_replace_the_actual_fresh_private_release_result(self):
        for status in (0, 22):
            for poison in (0, 1, MASK):
                with self.subTest(status=status, poison=poison):
                    m = self.machine(release=status)
                    observations = []

                    def observe(current, pc):
                        if pc == current.registry_release_gate_labels['complete']:
                            current.r[3] = poison
                        if pc == current.constructor_continuation_gate_labels['first_gate']:
                            observations.append(tuple(current.r[2:4]))

                    m.on_instruction = observe
                    m.construct(FIRST)
                    self.assertEqual(observations,
                                     [(0, poison) if status == 0 else (MASK, status)])
                    self.assertEqual(len(m.native_continuations), int(status == 0))

    def test_invalid_completion_tag_or_raw_frame_identity_denies_without_status_guess(self):
        corruptions = ((core.TAG, 0), (core.TAG, core.SELECTED),
                       (core.TAG, core.ENTERED), (core.TAG, MASK),
                       (core.RAW_SP, 0), (core.RAW_SP, STACK))
        for offset, value in corruptions:
            with self.subTest(offset=offset, value=value):
                m = self.machine(release=22)

                def corrupt(current, pc):
                    if pc == current.registry_release_gate_labels['complete']:
                        current.put(current.r[29] + offset, value, 4)

                m.on_instruction = corrupt
                self.assert_unknown_stop(m)
                native_sp = m.native_entries[0][2] - core.REGISTER_FRAME
                completion = m.registry_release_gate_labels['complete']
                self.assertFalse(any(kind == 'read' and address == native_sp + core.STATUS
                                     and pc >= completion
                                     for kind, pc, address, _ in m.constructor_accesses))

    def test_invalid_selected_fields_are_consumed_before_real_raw_release_without_adopting_status(self):
        corruptions = ((core.TAG, 0), (core.STATUS, 0), (core.RAW_SP, STACK))
        for offset, value in corruptions:
            with self.subTest(offset=offset):
                m = self.machine(release=22)

                def corrupt(current, pc):
                    if pc == current.registry_release_gate_labels['raw_release_call']:
                        native = current.r[29] + core.FACADE_FRAME + core.RAW_FRAME
                        current.put(native + offset, value, 4)

                m.on_instruction = corrupt
                self.assert_unknown_stop(m)
                self.assertEqual(m.raw_events[-1][-1], 22)

    def test_incoherent_raw_saved_return_chain_is_rejected_before_native_unwind(self):
        for offset in (0x1C, 0x3C):
            with self.subTest(offset=offset):
                m = self.machine(release=22)
                original = []

                def corrupt_and_restore(current, pc):
                    labels = current.registry_release_gate_labels
                    if pc == labels['raw_release_call']:
                        address = current.r[29] + offset
                        original.append((address, current.words_at(address, 1)[0]))
                        current.put(address, 0, 4)
                    if pc == labels['raw_release_call_replay']:
                        address, value = original[0]
                        current.put(address, value, 4)

                m.on_instruction = corrupt_and_restore
                self.assert_unknown_stop(m)
                self.assertEqual(len(original), 1)
                self.assertEqual(m.raw_events[-1][-1], 22)

    def test_wrong_raw_a0_or_t9_rejects_witness_even_when_restored_before_real_import(self):
        for register, value in ((4, PAINT_MUTEX), (25, MASK)):
            with self.subTest(register=register):
                m = self.machine(release=22)
                original = []

                def corrupt_and_restore(current, pc):
                    labels = current.registry_release_gate_labels
                    if pc == labels['raw_release_call']:
                        original.append(current.r[register])
                        current.r[register] = value
                    if pc == labels['raw_release_call_replay']:
                        current.r[register] = original[0]

                m.on_instruction = corrupt_and_restore
                self.assert_unknown_stop(m)
                self.assertEqual(m.raw_events[-1][0:2], (RAW_UNLOCK, REGISTRY_MUTEX))
                self.assertEqual(m.raw_events[-1][-1], 22)

    def test_wrong_actual_callback_is_executed_once_but_does_not_certify_registry_release(self):
        m = self.machine()
        selections = []

        def substitute_selected_callback(current, pc):
            if pc == current.registry_release_gate_labels['release_select']:
                # Keep acquisition/publication prerequisites intact, then
                # alter the actual callback register at release selection.
                selections.append((len(current.trace), len(current.raw_events)))
                current.r[25] = PAINT_UNLOCK

        m.on_instruction = substitute_selected_callback
        self.assert_unknown_stop(m)
        self.assertEqual(len(selections), 1)
        trace_start, raw_events = selections[0]
        # The inherited observer tail-jumps to this native callback. Its real
        # entry is in the instruction trace, not the linked-external call log.
        self.assertEqual(m.trace[trace_start:].count(PAINT_UNLOCK), 1)
        self.assertEqual(m.raw_events[-1][0:2], (RAW_UNLOCK, PAINT_MUTEX))
        self.assertEqual(len([e for e in m.raw_events
                              if e[0:2] == (RAW_UNLOCK, REGISTRY_MUTEX)]), 0)
        self.assertEqual([e[0:2] for e in m.raw_events[raw_events:]],
                         [(RAW_UNLOCK, PAINT_MUTEX)])
        self.assertEqual(m.lifecycle_header(), (1, 0, 0, 0))
        self.assertEqual(len(m.allocations), 1)
        self.assertTrue(m.registry_held)

    def test_wrong_actual_raw_return_ra_cannot_be_captured_as_fresh_evidence(self):
        m = self.machine(release=22)
        originals = []

        def corrupt_and_restore(current, pc):
            labels = current.registry_release_gate_labels
            if pc == labels['raw_release_return']:
                originals.append(current.r[31])
                current.r[31] = 0x466DD4
            if pc == labels['raw_release_return_replay']:
                current.r[31] = originals[0]

        m.on_instruction = corrupt_and_restore
        self.assert_unknown_stop(m)
        self.assertEqual(originals, [0x466DD0])

    def test_old_same_frame_success_is_not_adopted_after_missing_new_raw_call_phase(self):
        m = self.machine()
        self.assertNotEqual(m.construct(FIRST)[0], 0)
        self.assertEqual(len(m.native_continuations), 1)
        m.release = 22
        m.restore_legacy_release_phase('raw_release_call')
        m.clear_events()
        self.assert_unknown_stop(m)
        self.assertEqual(m.lifecycle_header()[0], 2)
        self.assertEqual(m.binding_header()[0], 2)

    def test_new_selection_resets_a_stale_success_before_capturing_actual_new_error(self):
        m = self.machine(release=22)
        observations = []

        def inject(current, pc):
            labels = current.registry_release_gate_labels
            if pc == labels['release_select']:
                native = current.r[29]
                current.put(native + core.TAG, core.CAPTURED, 4)
                current.put(native + core.STATUS, 0, 4)
                current.put(native + core.RAW_SP,
                            native - core.FACADE_FRAME - core.RAW_FRAME, 4)
            if pc == labels['release_select_replay']:
                observations.append(current.release_words(current.r[29]))

        m.on_instruction = inject
        self.assertEqual(m.construct(FIRST), (m.created_engines[0], 22))
        self.assertEqual(observations, [(core.SELECTED, MASK, 0)])
        self.assert_local_stop(m, FIRST, 22)

    def test_independent_cpu_frames_do_not_share_a_failure_or_success_latch(self):
        m = self.machine(release=22, registry_release_failure_releases=True)
        other = m.fork_cpu()
        other.release = 0
        observations = []

        def interleave(current, pc):
            if pc == current.registry_release_gate_labels['complete']:
                # This deliberately adversarial second invocation is not
                # permission to retry/reuse an uncertain native instance.
                other.next_allocation = current.next_allocation
                result, _ = other.construct(SECOND, stack=SECOND_CALLER_STACK)
                current.next_allocation = other.next_allocation
                observations.append(result)

        m.on_instruction = interleave
        self.assertEqual(m.construct(FIRST), (m.created_engines[0], 22))
        self.assert_local_stop(m, FIRST, 22)
        self.assertEqual(observations, [other.created_engines[0]])
        self.assertEqual(len(other.native_continuations), 1)
        first_native = m.native_entries[0][2] - core.REGISTER_FRAME
        other_native = other.native_entries[0][2] - core.REGISTER_FRAME
        self.assertNotEqual(first_native, other_native)
        self.assertEqual(m.release_words(first_native)[1], 22)
        self.assertEqual(other.release_words(other_native)[1], 0)

    def test_foreign_controller_refusal_and_partial_release_keep_prior_behavior(self):
        foreign = CONTROLLER + 0x1000
        for acquire_gate_present in (True, False):
            with self.subTest(acquire_gate_present=acquire_gate_present):
                old = ExplorerFailureGateMachine(self.image, release=22)
                m = self.machine(release=22)
                for machine in (old, m):
                    machine.map(foreign, receipt.CONTROLLER_BYTES)
                    machine.configure_controller(foreign)
                    if not acquire_gate_present:
                        # Explicit partial-hook counterexample, not an allowed
                        # activation or permission to use a foreign instance.
                        # With the gate present, refusal precedes release.
                        machine.remove_pair(acquire.HOOKS['register_gate'][0])
                    machine.clear_events()
                self.assertEqual(m.register(controller=foreign), old.register(controller=foreign))
                self.assertEqual(m.r[2], MASK if acquire_gate_present else 0)
                self.assertEqual(m.words_at(foreign + 0x34, 2),
                                 old.words_at(foreign + 0x34, 2))
                self.assertEqual(m.raw_events, old.raw_events)
                expected = [(RAW_LOCK, REGISTRY_MUTEX, 0)]
                if not acquire_gate_present:
                    expected.append((RAW_UNLOCK, REGISTRY_MUTEX, 22))
                    self.assertIn(m.registry_release_gate_labels['complete'], m.trace)
                else:
                    self.assertNotIn(m.registry_release_gate_labels['complete'], m.trace)
                self.assertEqual([(e[0], e[1], e[-1]) for e in m.raw_events], expected)
                self.assertNotIn(m.registry_release_gate_labels['complete_classified'], m.trace)

    def test_registry_error_is_not_replaced_by_an_earlier_paint_error(self):
        m = self.machine(release=0x82, paint_release_result=22)
        self.assertEqual(m.construct(FIRST), (m.created_engines[0], 0x82))
        self.assert_local_stop(m, FIRST, 0x82)
        self.assertEqual(m.raw_events[-1][0:2], (RAW_UNLOCK, REGISTRY_MUTEX))
        self.assertEqual(m.raw_events[-1][-1], 0x82)
        self.assertEqual(m.lifecycle_header(), (1, 0, 0, 0))


if __name__ == '__main__':
    unittest.main()
