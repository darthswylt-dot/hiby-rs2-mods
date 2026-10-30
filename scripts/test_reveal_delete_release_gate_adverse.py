#!/usr/bin/env python3
"""Delimit fresh destructor-only release evidence under controlled mutation.

All mutations use genuine mapped retained frames and restore changed native
returns/registers before unwind where needed. Missing-hook counterexamples are
unsupported partial activation. Neither witness scalars nor these schedules
authenticate a fabricated frame, prove ownership, authorize retry/free or undo
earlier deletion effects. No device, installer or network operation is used.
"""

import unittest

import reveal_registry_acquire_gate_mips as acquire
import test_reveal_delete_release_gate_mips as fixture
from test_reveal_delete_release_gate_mips import (
    DeleteReleaseGateMachine, DestructorContinuationGateMachine, CONTROLLER,
    REGISTRY_MUTEX, PAINT_MUTEX, RAW_LOCK, RAW_UNLOCK, STACK, RETURN, MASK,
    NAME, DESTRUCTOR, core)


PAINT_UNLOCK = 0x437D60


class DeleteReleaseGateAdverseTests(unittest.TestCase):
    setUpClass = classmethod(fixture.DeleteReleaseGateTests.setUpClass.__func__)
    machine = fixture.DeleteReleaseGateTests.machine
    watch_completion = fixture.DeleteReleaseGateTests.watch_completion
    assert_completion_architecture = fixture.DeleteReleaseGateTests.assert_completion_architecture
    assert_failed = fixture.DeleteReleaseGateTests.assert_failed
    assert_forwarded = fixture.DeleteReleaseGateTests.assert_forwarded
    watch_raw_release = fixture.DeleteReleaseGateTests.watch_raw_release
    assert_private_after_raw_release = fixture.DeleteReleaseGateTests.assert_private_after_raw_release

    def run_unknown_stop(self, machine):
        context = machine.seed_destructor()
        machine.clear_events()
        marks, snapshots = self.watch_completion(machine)
        observer = getattr(machine, 'adverse_observer', None)
        watch = machine.on_instruction
        if observer is not None:
            def combined(current, pc):
                observer(current, pc)
                watch(current, pc)
            machine.on_instruction = combined
        self.assertEqual(machine.run_destructor_slice(), (MASK, 0))
        self.assert_failed(machine, context, marks, snapshots, 0)
        self.assert_completion_architecture(snapshots, (MASK, 0))
        self.assertIn(machine.delete_release_gate_labels['complete_denied'], machine.trace)
        return context, snapshots

    def test_each_actual_raw_error_stops_held_or_unheld_without_ownership_guess(self):
        for status in (1, 22, 0x82, MASK):
            for released in (False, True):
                with self.subTest(status=status, released=released):
                    m = self.machine(release=status, registry_release_failure_releases=released)
                    context = m.seed_destructor()
                    m.clear_events()
                    marks, snapshots = self.watch_completion(m)
                    raw_marks = self.watch_raw_release(m)
                    self.assertEqual(m.run_destructor_slice(), (MASK, status))
                    self.assert_private_after_raw_release(m, context, raw_marks)
                    self.assert_failed(m, context, marks, snapshots, status)
                    self.assert_completion_architecture(snapshots, (MASK, status))
                    self.assertEqual(m.registry_held, not released)
                    self.assertEqual([(event[0], event[1], event[-1]) for event in m.raw_events],
                                     [(RAW_LOCK, REGISTRY_MUTEX, 0),
                                      (RAW_UNLOCK, REGISTRY_MUTEX, status)])

    def test_missing_each_observer_phase_denies_fresh_unknown_but_runs_raw_once(self):
        for phase in fixture.PHASES:
            for status in (0, 22):
                with self.subTest(phase=phase, status=status):
                    m = self.machine(release=status)
                    m.restore_legacy_delete_release_phase(phase)
                    self.run_unknown_stop(m)
                    self.assertNotIn(m.delete_release_gate_labels[phase], m.trace)
                    self.assertEqual(m.raw_events[-1][-1], status)
                    self.assertEqual(len([event for event in m.raw_events
                                          if event[0:2] == (RAW_UNLOCK, REGISTRY_MUTEX)]), 1)

    def test_missing_completion_keeps_native_masked_error_and_resource_continuation(self):
        m = self.machine(release=22, registry_release_failure_releases=False)
        context = m.seed_destructor()
        m.restore_legacy_delete_release_phase('complete')
        m.clear_events()
        _, snapshots = fixture.previous.DestructorContinuationGateTests.watch_gate(self, m)
        m.run_destructor_slice()
        fixture.previous.DestructorContinuationGateTests.assert_forwarded(self, m, context, snapshots)
        self.assertEqual(snapshots['gate'][0][2], 0)
        self.assertEqual(m.raw_events[-1][-1], 22)
        self.assertTrue(m.registry_held)
        self.assertTrue(m.resource_deletions[0][-1])
        self.assertNotIn(m.delete_release_gate_labels['complete'], m.trace)
        self.assertEqual(m.delete_release_words()[0], core.CAPTURED)

    def test_fresh_begin_resets_each_stale_state_before_actual_new_error(self):
        for tag in (core.ARMED, core.SELECTED, core.ENTERED, core.CAPTURED):
            with self.subTest(tag=tag):
                m = self.machine(release=22)
                context = m.seed_destructor()
                destructor_sp = context['sp']
                m.put(destructor_sp + core.TAG, tag, 4)
                m.put(destructor_sp + core.STATUS, 0, 4)
                m.put(destructor_sp + core.RAW_SP, destructor_sp - 64, 4)
                m.clear_events()
                resets = []

                def observe(current, pc):
                    if pc == current.delete_release_gate_labels['begin_replay']:
                        resets.append(current.delete_release_words())

                m.on_instruction = observe
                self.assertEqual(m.run_destructor_slice(), (MASK, 22))
                self.assertEqual(resets, [(core.ARMED, MASK, 0)])
                self.assertEqual(m.delete_release_words(), (0, 22, destructor_sp - 64))
                self.assertEqual(m.resource_deletions, [])

    def test_same_frame_success_cannot_supply_missing_new_selection_or_raw_phase(self):
        for phase in ('release_select', 'raw_release_call', 'raw_release_return'):
            with self.subTest(phase=phase):
                m = self.machine()
                first = m.seed_destructor()
                m.clear_events()
                m.run_destructor_slice()
                self.assertEqual(len(m.resource_deletions), 1)
                self.assertEqual(m.delete_release_words(), (0, 0, first['sp'] - 64))
                m.release = 22
                m.restore_legacy_delete_release_phase(phase)
                context, _ = self.run_unknown_stop(m)
                self.assertEqual(context['sp'], first['sp'])
                self.assertEqual(m.raw_events[-1][-1], 22)

    def test_multiple_missing_phases_can_adopt_stale_capture_partial_activation_counterexample(self):
        # This deliberately omits fresh begin AND every observer. A scalar old
        # CAPTURED is not authenticated evidence under arbitrary partial hooks.
        m = self.machine(release=22)
        context = m.seed_destructor()
        destructor_sp = context['sp']
        for phase in fixture.PHASES:
            m.restore_legacy_delete_release_phase(phase)
        m.put(destructor_sp + core.TAG, core.CAPTURED, 4)
        m.put(destructor_sp + core.STATUS, 0, 4)
        m.put(destructor_sp + core.RAW_SP, destructor_sp - 64, 4)
        m.clear_events()
        _, snapshots = self.watch_completion(m)
        m.run_destructor_slice()
        self.assert_forwarded(m, context, snapshots)
        self.assertEqual(m.raw_events[-1][-1], 22)
        self.assertEqual(m.delete_release_words(), (0, 0, destructor_sp - 64))

    def test_invalid_admission_or_selection_fields_are_consumed_before_capture(self):
        cases = (
            ('release_select', core.TAG, 0),
            ('release_select', core.STATUS, 0),
            ('release_select', core.RAW_SP, STACK),
            ('raw_release_call', core.TAG, core.CAPTURED),
            ('raw_release_call', core.STATUS, 0),
            ('raw_release_call', core.RAW_SP, STACK),
            ('raw_release_return', core.TAG, core.SELECTED),
            ('raw_release_return', core.RAW_SP, STACK),
        )
        for phase, offset, value in cases:
            with self.subTest(phase=phase, offset=offset, value=value):
                m = self.machine(release=22)

                def corrupt(current, pc):
                    if pc == current.delete_release_gate_labels[phase]:
                        current.put(current.destructor_context['sp'] + offset, value, 4)

                m.adverse_observer = corrupt
                self.run_unknown_stop(m)
                self.assertEqual(m.raw_events[-1][-1], 22)

    def test_incoherent_saved_raw_chain_is_rejected_before_following_destructor_carrier(self):
        for phase in ('raw_release_call', 'raw_release_return'):
            for offset in (0x1C, 0x3C):
                with self.subTest(phase=phase, offset=offset):
                    m = self.machine(release=22)
                    original = []

                    def corrupt_and_restore(current, pc):
                        labels = current.delete_release_gate_labels
                        if pc == labels[phase]:
                            address = current.r[29] + offset
                            original.append((address, current.words_at(address, 1)[0]))
                            current.put(address, 0, 4)
                        if pc == labels[phase + '_replay']:
                            address, value = original[0]
                            current.put(address, value, 4)

                    m.adverse_observer = corrupt_and_restore
                    self.run_unknown_stop(m)
                    self.assertEqual(len(original), 1)
                    self.assertEqual(m.raw_events[-1][-1], 22)
                    first = m.delete_release_gate_labels[phase]
                    last = m.delete_release_gate_labels[phase + '_done']
                    carrier = m.destructor_context['sp'] + core.TAG
                    self.assertFalse(any(kind == 'read' and address == carrier
                                         and first <= pc < last
                                         for kind, pc, address, _ in m.constructor_accesses))

    def test_wrong_scope_and_actual_raw_arguments_cannot_create_release_witness(self):
        cases = (('begin', 4, PAINT_MUTEX),
                 ('release_select', 21, PAINT_MUTEX),
                 ('raw_release_call', 4, PAINT_MUTEX),
                 ('raw_release_call', 25, MASK),
                 ('raw_release_call', 17, PAINT_MUTEX),
                 ('raw_release_return', 17, PAINT_MUTEX),
                 ('raw_release_return', 31, 0x466DD4))
        for phase, register, value in cases:
            with self.subTest(phase=phase, register=register):
                m = self.machine(release=22)
                original = []

                def corrupt_and_restore(current, pc):
                    labels = current.delete_release_gate_labels
                    if pc == labels[phase]:
                        original.append(current.r[register])
                        current.r[register] = value
                    if pc == labels[phase + '_replay']:
                        current.r[register] = original[0]

                m.adverse_observer = corrupt_and_restore
                self.run_unknown_stop(m)
                self.assertEqual(len(original), 1)
                self.assertEqual(m.raw_events[-1][0:2], (RAW_UNLOCK, REGISTRY_MUTEX))
                self.assertEqual(m.raw_events[-1][-1], 22)

    def test_wrong_begin_or_selection_native_return_is_not_admitted(self):
        for phase in ('begin', 'release_select'):
            with self.subTest(phase=phase):
                m = self.machine(release=22)
                original = []

                def corrupt_and_restore(current, pc):
                    labels = current.delete_release_gate_labels
                    if pc == labels[phase]:
                        address = current.r[29] + 0x34
                        original.append((address, current.words_at(address, 1)[0]))
                        current.put(address, RETURN, 4)
                    if pc == labels[phase + '_replay']:
                        address, value = original[0]
                        current.put(address, value, 4)

                m.adverse_observer = corrupt_and_restore
                self.run_unknown_stop(m)
                self.assertEqual(original[0][1], 0x493F4C)

    def test_actual_wrong_selected_callback_executes_once_then_stops_unknown(self):
        m = self.machine()
        starts = []

        def substitute(current, pc):
            if pc == current.delete_release_gate_labels['release_select']:
                starts.append(len(current.trace))
                current.r[25] = PAINT_UNLOCK

        m.adverse_observer = substitute
        self.run_unknown_stop(m)
        self.assertEqual(len(starts), 1)
        self.assertEqual(m.trace[starts[0]:].count(PAINT_UNLOCK), 1)
        self.assertEqual([(event[0], event[1], event[-1]) for event in m.raw_events],
                         [(RAW_LOCK, REGISTRY_MUTEX, 0), (RAW_UNLOCK, PAINT_MUTEX, 0)])
        self.assertTrue(m.registry_held)

    def test_invalid_completion_tag_or_raw_frame_denies_before_status_read(self):
        cases = ((core.TAG, 0), (core.TAG, core.ARMED),
                 (core.TAG, core.SELECTED), (core.TAG, core.ENTERED),
                 (core.TAG, MASK), (core.RAW_SP, 0), (core.RAW_SP, STACK))
        for offset, value in cases:
            with self.subTest(offset=offset, value=value):
                m = self.machine(release=22)

                def corrupt(current, pc):
                    if pc == current.delete_release_gate_labels['complete']:
                        current.put(current.r[29] + offset, value, 4)

                m.adverse_observer = corrupt
                context, _ = self.run_unknown_stop(m)
                complete = m.delete_release_gate_labels['complete']
                self.assertFalse(any(kind == 'read' and address == context['sp'] + core.STATUS
                                     and pc >= complete
                                     for kind, pc, address, _ in m.constructor_accesses))

    def test_incoming_nonzero_is_preserved_exactly_and_consumes_stale_release_tag(self):
        for result in (1, 0x80000001, MASK):
            for diagnostic in (0, 22, MASK):
                with self.subTest(result=result, diagnostic=diagnostic):
                    m = self.machine()
                    m.seed_destructor()
                    m.put(m.destructor_context['sp'] + core.TAG, core.CAPTURED, 4)
                    m.put(m.destructor_context['sp'] + core.STATUS, 0x82, 4)
                    _, snapshots = self.watch_completion(m)
                    self.assertEqual(m.invoke_destructor_gate(result=result, diagnostic=diagnostic),
                                     (result, diagnostic))
                    self.assert_completion_architecture(snapshots)
                    self.assertEqual(snapshots['legacy'], snapshots['epilogue'])
                    self.assertEqual(m.delete_release_words()[0], 0)
                    self.assertEqual(m.resource_entries, [])
                    self.assertEqual(m.calls, [])
                    self.assertEqual((m.r[29], m.r[31]), (STACK, RETURN))

    def test_foreign_completion_u_or_ra_delegates_previous_abi_without_consuming_carrier(self):
        foreign = CONTROLLER + 0x1000
        for controller, caller in ((foreign, 0x493F4C), (CONTROLLER, RETURN),
                                   (CONTROLLER, 0x493F50)):
            with self.subTest(controller=controller, caller=caller):
                old = DestructorContinuationGateMachine(self.image)
                m = self.machine()
                destructor_sp = STACK - core.DESTRUCTOR_FRAME
                for current in (old, m):
                    if controller == foreign:
                        current.map(foreign, core.CONTROLLER_BYTES)
                        current.put(foreign + 0x24, 0x1234ABCD, 4)
                    current.put(destructor_sp + core.TAG, core.CAPTURED, 4)
                    current.put(destructor_sp + core.STATUS, 0x82, 4)
                    current.put(destructor_sp + core.RAW_SP, destructor_sp - 64, 4)
                _, snapshots = self.watch_completion(m)
                self.assertEqual(m.invoke_destructor_gate(controller=controller, caller=caller),
                                 old.invoke_destructor_gate(controller=controller, caller=caller))
                self.assert_completion_architecture(snapshots)
                self.assertEqual((m.r, m.hi, m.lo), (old.r, old.hi, old.lo))
                self.assertEqual(m.resource_entries, old.resource_entries)
                self.assertEqual(len(m.resource_entries), 1)
                self.assertEqual(m.delete_release_words(),
                                 (core.CAPTURED, 0x82, destructor_sp - 64))
                self.assertNotIn(m.delete_release_gate_labels['complete_classified'], m.trace)

    def test_post_raw_caller_clobbers_and_v1_poison_do_not_replace_actual_status(self):
        for status in (0, 22):
            for poison in (0, MASK):
                with self.subTest(status=status, poison=poison):
                    m = self.machine(release=status)
                    context = m.seed_destructor()
                    m.clear_events()
                    marks, snapshots = self.watch_completion(m)
                    observe = m.on_instruction
                    raw_architecture = []

                    def poison_after_raw(current, pc):
                        if pc == current.delete_release_gate_labels['raw_release_return']:
                            raw_architecture.append((current.r[4], current.r[25], current.r[2]))
                        if pc == current.delete_release_gate_labels['complete']:
                            current.r[3] = poison
                        observe(current, pc)

                    m.on_instruction = poison_after_raw
                    m.run_destructor_slice()
                    self.assertEqual(len(raw_architecture), 1)
                    self.assertNotEqual(raw_architecture[0][0], REGISTRY_MUTEX)
                    self.assertNotEqual(raw_architecture[0][1], core.REGISTRY_UNLOCK)
                    self.assertEqual(raw_architecture[0][2], status)
                    if status:
                        self.assert_failed(m, context, marks, snapshots, status)
                        self.assert_completion_architecture(snapshots, (MASK, status))
                    else:
                        self.assert_forwarded(m, context, snapshots)
                        self.assertEqual(m.resource_entries[0][0][2:4], [0, poison])

    def test_missing_earlier_acquire_gate_still_allows_prior_unlink_counterexample(self):
        m = self.machine()
        self.assertEqual(m.register(), 0)
        node = m.allocations[-1]
        m.acquire = 22
        context = m.seed_destructor()
        m.remove_pair(acquire.HOOKS['delete_gate'][0])
        m.clear_events()
        _, snapshots = self.watch_completion(m)
        m.run_destructor_slice()
        self.assert_forwarded(m, context, snapshots)
        self.assertEqual([(event[0], event[-1]) for event in m.raw_events],
                         [(RAW_LOCK, 22), (RAW_UNLOCK, 0)])
        self.assertIn(node, m.freed)
        self.assertEqual(m.words_at(CONTROLLER + 0x34, 2), (CONTROLLER + 0x34,) * 2)
        self.assertNotIn(m.acquire_gate_labels['delete_gate'], m.trace)
        self.assertEqual(len(m.resource_entries), 1)


if __name__ == '__main__':
    unittest.main()
