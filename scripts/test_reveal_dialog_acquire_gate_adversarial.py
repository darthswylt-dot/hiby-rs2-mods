#!/usr/bin/env python3
"""Exercise fresh dialog acquisition evidence and coherent-activation limits.

Mapped retained genuine D104/W32/private192 frames are premises throughout.
Chosen uncertain raw outcomes are not ownership recovery; denial never guesses
an unlock. Missing-hook and stale-evidence cases expose limits of arbitrary
partial activation and are not a safe installation/removal or retry protocol.
"""

import unittest

import test_reveal_dialog_acquire_gate_mips as fixture
from test_reveal_dialog_acquire_gate_mips import (
    core, DIALOG, PROPERTY, DIALOG_MUTEX, ALTERNATE_MUTEX, RAW_LOCK,
    ACQUIRE, ADMISSION, ADMITTED, STACK, RETURN, MASK)


class DialogAcquireGateAdversarialTests(unittest.TestCase):
    setUpClass = classmethod(fixture.DialogAcquireGateTests.setUpClass.__func__)
    machine = fixture.DialogAcquireGateTests.machine
    watch_gate = fixture.DialogAcquireGateTests.watch_gate
    assert_denied = fixture.DialogAcquireGateTests.assert_denied
    assert_admitted = fixture.DialogAcquireGateTests.assert_admitted

    def test_missing_each_freshness_phase_denies_unknown_even_when_actual_raw_returns_zero(self):
        for phase in ('begin', 'raw_call', 'raw_return'):
            with self.subTest(phase=phase):
                m = self.machine()
                context = m.seed_dialog()
                for offset in (core.TAG, core.MUTEX, core.RAW_STATUS):
                    m.put(context['sp'] + offset, 0, 4)
                m.restore_legacy_dialog_phase(phase)
                m.clear_events()
                marks, snapshots = self.watch_gate(m)
                self.assertEqual(m.run_dialog_acquire(), (MASK, 0))
                self.assert_denied(m, context, marks, snapshots, raw=0)
                self.assertEqual(m.dialog_raw_events,
                                 [(RAW_LOCK, DIALOG_MUTEX, context['sp'] - 32, 0x466DB0, 0)])
                self.assertTrue(m.mutex_held[DIALOG_MUTEX])

    def test_missing_final_gate_restores_native_graph_read_after_failed_acquire(self):
        m = self.machine(dialog_acquire=22)
        context = m.seed_dialog()
        m.restore_legacy_dialog_phase('gate')
        m.clear_events()
        m.run_dialog_acquire()
        self.assertEqual(m.r[2], PROPERTY)
        self.assertEqual(m.r[5], 0)
        self.assertEqual(m.r[29], context['sp'])
        self.assertEqual(m.reads.count((DIALOG + 0x3C, 4)), 1)
        self.assertEqual(m.reads.count((PROPERTY, 4)), 1)
        self.assertEqual(m.dialog_raw_events[-1][-1], 22)
        self.assertFalse(m.mutex_held[DIALOG_MUTEX])
        self.assertEqual(m.dialog_witness(), (core.CAPTURED, DIALOG_MUTEX, 22))

    def test_missing_all_freshness_phases_can_adopt_stale_success_and_is_not_fail_closed(self):
        m = self.machine(dialog_acquire=22)
        context = m.seed_dialog()
        for phase in ('begin', 'raw_call', 'raw_return'):
            m.restore_legacy_dialog_phase(phase)
        for offset, value in ((core.TAG, core.CAPTURED), (core.MUTEX, DIALOG_MUTEX),
                              (core.RAW_STATUS, 0)):
            m.put(context['sp'] + offset, value, 4)
        m.clear_events()
        marks, snapshots = self.watch_gate(m)
        m.run_dialog_acquire()
        self.assert_admitted(m, context, snapshots)
        self.assertEqual(m.dialog_raw_events[-1][-1], 22)
        self.assertFalse(m.mutex_held[DIALOG_MUTEX])

    def test_begin_resets_every_stale_word_before_current_raw_result_is_captured(self):
        for status in (0, 22):
            with self.subTest(status=status):
                m = self.machine(dialog_acquire=status)
                context = m.seed_dialog()
                for offset, value in ((core.TAG, core.CAPTURED),
                                      (core.MUTEX, ALTERNATE_MUTEX),
                                      (core.RAW_STATUS, 0)):
                    m.put(context['sp'] + offset, value, 4)
                m.clear_events()
                marks, snapshots = self.watch_gate(m)
                observed, watch = [], m.on_instruction

                def observe(current, pc):
                    if pc == current.dialog_acquire_gate_labels['begin_done']:
                        observed.append(current.dialog_witness())
                    watch(current, pc)

                m.on_instruction = observe
                m.run_dialog_acquire()
                self.assertEqual(observed, [(core.ARMED, DIALOG_MUTEX, MASK)])
                if status:
                    self.assert_denied(m, context, marks, snapshots, raw=status)
                else:
                    self.assert_admitted(m, context, snapshots)

    def test_actual_raw_argument_mismatch_consumes_witness_and_denies_unknown(self):
        m = self.machine()
        context = m.seed_dialog()
        m.clear_events()
        marks, snapshots = self.watch_gate(m)
        watch = m.on_instruction

        def observe(current, pc):
            if pc == core.HOOKS['raw_call'][0]:
                current.r[4] = ALTERNATE_MUTEX
            watch(current, pc)

        m.on_instruction = observe
        self.assertEqual(m.run_dialog_acquire(), (MASK, 0))
        self.assert_denied(m, context, marks, snapshots, raw=0)
        self.assertEqual(m.dialog_raw_events,
                         [(RAW_LOCK, ALTERNATE_MUTEX, context['sp'] - 32, 0x466DB0, 0)])
        self.assertTrue(m.mutex_held[ALTERNATE_MUTEX])
        self.assertFalse(m.mutex_held[DIALOG_MUTEX])

    def test_mutating_object_mutex_after_original_delay_does_not_replace_actual_captured_argument(self):
        for status in (0, 0x82):
            with self.subTest(status=status):
                m = self.machine(dialog_acquire=status)
                context = m.seed_dialog()
                m.clear_events()
                marks, snapshots = self.watch_gate(m)
                watch = m.on_instruction

                def observe(current, pc):
                    if pc == current.dialog_acquire_gate_labels['begin_done']:
                        current.put(DIALOG + 0x10, ALTERNATE_MUTEX, 4)
                    watch(current, pc)

                m.on_instruction = observe
                m.run_dialog_acquire()
                self.assertEqual(m.dialog_raw_events[0][1], DIALOG_MUTEX)
                self.assertEqual(m.dialog_delay_effects, [(ACQUIRE, DIALOG, DIALOG_MUTEX)])
                self.assertEqual(m.reads.count((DIALOG + 0x10, 4)), 1)
                self.assertEqual(m.words_at(DIALOG + 0x10, 1), (ALTERNATE_MUTEX,))
                self.assertEqual(m.dialog_witness()[1], DIALOG_MUTEX)
                if status:
                    self.assert_denied(m, context, marks, snapshots, raw=status)
                else:
                    self.assert_admitted(m, context, snapshots)

    def test_post_raw_caller_clobbers_and_v1_poison_do_not_change_saved_actual_status(self):
        for status in (0, 1, MASK):
            with self.subTest(status=status):
                m = self.machine(dialog_acquire=status)
                context = m.seed_dialog()
                m.clear_events()
                marks, snapshots = self.watch_gate(m)
                watch = m.on_instruction

                def observe(current, pc):
                    if pc == core.HOOKS['raw_return'][0]:
                        current.r[3:8] = MASK, ALTERNATE_MUTEX, 0xDEAD0005, 0, 1
                        current.r[25] = 0xDEAD0025
                    watch(current, pc)

                m.on_instruction = observe
                m.run_dialog_acquire()
                if status:
                    self.assert_denied(m, context, marks, snapshots, raw=status)
                else:
                    self.assert_admitted(m, context, snapshots)
                self.assertEqual(len(m.dialog_raw_events), 1)
                self.assertEqual(m.dialog_raw_events[0][-1], status)

    def test_corrupt_entered_wrapper_identity_denies_unknown_without_retry_or_unlock(self):
        m = self.machine(dialog_acquire=22)
        context = m.seed_dialog()
        m.clear_events()
        marks, snapshots = self.watch_gate(m)
        watch = m.on_instruction

        def observe(current, pc):
            if pc == core.HOOKS['raw_return'][0]:
                current.put(context['sp'] + core.RAW_STATUS, context['sp'] - 64, 4)
            watch(current, pc)

        m.on_instruction = observe
        self.assertEqual(m.run_dialog_acquire(), (MASK, 0))
        self.assert_denied(m, context, marks, snapshots, raw=0)
        self.assertEqual(m.dialog_raw_events,
                         [(RAW_LOCK, DIALOG_MUTEX, context['sp'] - 32, 0x466DB0, 22)])

    def test_same_native_frame_uses_current_success_error_and_mutex_without_prior_admission(self):
        m = self.machine()
        frames = []
        for status, mutex in ((0, DIALOG_MUTEX), (22, ALTERNATE_MUTEX), (0, DIALOG_MUTEX)):
            m.dialog_acquire = status
            context = m.seed_dialog(mutex=mutex)
            frames.append(context['sp'])
            m.clear_events()
            marks, snapshots = self.watch_gate(m)
            m.run_dialog_acquire()
            self.assertEqual(m.dialog_delay_effects, [(ACQUIRE, DIALOG, mutex)])
            self.assertEqual(len(m.dialog_raw_events), 1)
            self.assertEqual(m.dialog_raw_events[0][1], mutex)
            if status:
                self.assert_denied(m, context, marks, snapshots, raw=status)
            else:
                self.assert_admitted(m, context, snapshots)
        self.assertEqual(len(set(frames)), 1)

    def test_saved_raw_return_scope_mismatch_leaves_foreign_route_original_and_no_native_witness_capture(self):
        m, old = self.machine(dialog_acquire=22), self.machine(dialog_acquire=22)
        for phase in core.HOOKS:
            old.restore_legacy_dialog_phase(phase)
        for current in (m, old):
            context = current.seed_dialog()
            current.put(context['sp'] + core.TAG, core.ARMED, 4)
            current.put(context['sp'] + core.MUTEX, DIALOG_MUTEX, 4)
            current.put(context['sp'] + core.RAW_STATUS, MASK, 4)
            current.r[29], current.r[31], current.r[4] = (
                context['sp'], RETURN, DIALOG_MUTEX)
            current.clear_events()
            current.run_at(0x466DA0, RETURN)
        self.assertEqual((m.r, m.hi, m.lo), (old.r, old.hi, old.lo))
        self.assertEqual(m.dialog_witness(), (core.ARMED, DIALOG_MUTEX, MASK))
        self.assertEqual(m.dialog_witness(), old.dialog_witness())
        self.assertEqual(m.dialog_raw_events, old.dialog_raw_events)
        self.assertEqual(m.r[2], 0)

    def test_missing_raw_return_reports_unknown_zero_distinct_from_observed_mask_status(self):
        states = []
        for missing in (False, True):
            with self.subTest(missing=missing):
                m = self.machine(dialog_acquire=MASK)
                context = m.seed_dialog()
                if missing:
                    m.restore_legacy_dialog_phase('raw_return')
                m.clear_events()
                marks, snapshots = self.watch_gate(m)
                states.append(m.run_dialog_acquire())
                self.assert_denied(m, context, marks, snapshots, raw=0 if missing else MASK)
                self.assertEqual(m.dialog_raw_events[-1][-1], MASK)
        self.assertEqual(states, [(MASK, MASK), (MASK, 0)])


if __name__ == '__main__':
    unittest.main()
