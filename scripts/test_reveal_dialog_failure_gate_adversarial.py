#!/usr/bin/env python3
"""Expose classified dialog-exit proof and coherent-splice boundaries.

Every invocation supplies genuine retained mapped independently nonaliasing
live frames. Chosen mutex outcomes do not recover ownership. Same-frame
fixture repetition is a freshness check, not permission to retry a native
instance after an uncertain release. Partial-hook cases are counterexamples,
not a safe activation/removal protocol.
"""

import unittest

import test_reveal_dialog_failure_gate_mips as fixture
from test_reveal_dialog_failure_gate_mips import (
    core, ACQUIRE_CORE, CALLBACKS, DIALOG, DIALOG_MUTEX, ALTERNATE_MUTEX,
    CONTROLLER, OPERATION, RAW_LOCK, RAW_UNLOCK, MASK, RETURN,
    CALLBACK_RETURN, CACHE_RETURN, CACHE_REMOVE, NativeReturnBoundary)


class DialogFailureGateAdversarialTests(unittest.TestCase):
    setUpClass = classmethod(fixture.DialogFailureGateTests.setUpClass.__func__)
    machine = fixture.DialogFailureGateTests.machine
    watch_failure = fixture.DialogFailureGateTests.watch_failure
    assert_error_exit = fixture.DialogFailureGateTests.assert_error_exit

    def test_object_mutex_rebinding_after_acquire_never_replaces_captured_release_argument(self):
        for kind in CALLBACKS:
            for status in (0, 0x82):
                with self.subTest(kind=kind, status=status):
                    m = self.machine(acquire=22, dialog_release=status)
                    context = m.seed_dialog(callback=kind)
                    m.clear_events()
                    marks, snapshots = self.watch_failure(m)
                    watch = m.on_instruction

                    def observe(current, pc):
                        if pc == current.refresh_callback_gate_labels[kind + '_abort_return']:
                            current.put(DIALOG + 0x10, ALTERNATE_MUTEX, 4)
                        watch(current, pc)

                    m.on_instruction = observe
                    self.assertEqual(m.run_dialog_failure(), (MASK, 22))
                    self.assert_error_exit(m, context, marks, snapshots, release_status=status)
                    self.assertEqual(m.dialog_raw_events[-1][1], DIALOG_MUTEX)
                    self.assertEqual(m.reads.count((DIALOG + 0x10, 4)), 1)
                    self.assertEqual(m.words_at(DIALOG + 0x10, 1), (ALTERNATE_MUTEX,))
                    self.assertFalse(m.mutex_held[ALTERNATE_MUTEX])

    def test_missing_or_nonzero_admission_proof_stops_classified_error_without_guessing_unlock(self):
        cases = ((0, 0), (ACQUIRE_CORE.CAPTURED, 0),
                 (ACQUIRE_CORE.ADMITTED, 1), (ACQUIRE_CORE.ADMITTED, MASK))
        for kind in CALLBACKS:
            for tag, raw in cases:
                with self.subTest(kind=kind, tag=tag, raw=raw):
                    m = self.machine(acquire=22)
                    context = m.seed_dialog(callback=kind)
                    m.clear_events()
                    marks, snapshots = self.watch_failure(m)
                    watch = m.on_instruction

                    def observe(current, pc):
                        if pc == current.refresh_callback_gate_labels[kind + '_abort_return']:
                            current.put(context['sp'] + ACQUIRE_CORE.TAG, tag, 4)
                            current.put(context['sp'] + ACQUIRE_CORE.RAW_STATUS, raw, 4)
                        watch(current, pc)

                    m.on_instruction = observe
                    self.assertEqual(m.run_dialog_failure(), (MASK, 22))
                    self.assert_error_exit(m, context, marks, snapshots,
                                           release_attempted=False)
                    self.assertEqual(m.dialog_witness(), (core.NO_RELEASE, DIALOG_MUTEX, 0))
                    self.assertTrue(m.mutex_held[DIALOG_MUTEX])
                    self.assertEqual([event[0] for event in m.dialog_raw_events], [RAW_LOCK])

    def test_missing_acquisition_observation_and_gate_cannot_authorize_release_after_classified_error(self):
        for kind in CALLBACKS:
            with self.subTest(kind=kind):
                m = self.machine(acquire=22)
                context = m.seed_dialog(callback=kind)
                for phase in ('begin', 'raw_call', 'raw_return', 'gate'):
                    m.restore_legacy_dialog_phase(phase)
                for offset in (ACQUIRE_CORE.TAG, ACQUIRE_CORE.MUTEX, ACQUIRE_CORE.RAW_STATUS):
                    m.put(context['sp'] + offset, 0, 4)
                m.clear_events()
                marks, snapshots = self.watch_failure(m)
                self.assertEqual(m.run_dialog_failure(), (MASK, 22))
                self.assert_error_exit(m, context, marks, snapshots, release_attempted=False)
                self.assertEqual(m.dialog_witness(), (core.NO_RELEASE, 0, 0))
                self.assertTrue(m.mutex_held[DIALOG_MUTEX])

    def test_missing_both_generated_copies_restores_native_graph_cleanup_after_callback_error(self):
        for kind in CALLBACKS:
            with self.subTest(kind=kind):
                m = self.machine(acquire=22)
                context = m.seed_dialog(callback=kind)
                m.remove_generated_failure_splice()
                m.clear_events()
                self.assertEqual(m.run_dialog_failure(
                    NativeReturnBoundary(CACHE_RETURN, context['caller'])), (0, 0xBAD00003))
                self.assertEqual(m.native_cleanup_entries,
                                 [((CONTROLLER, context['sp'] + 0x18,
                                    m.native_cleanup_entries[0][0][2],
                                    m.native_cleanup_entries[0][0][3]),
                                   context['sp'], CACHE_RETURN)])
                self.assertEqual(m.calls.count(CACHE_REMOVE), 1)
                self.assertEqual(m.direct_release_entries, [])
                self.assertTrue(m.mutex_held[DIALOG_MUTEX])
                self.assertIn(CALLBACK_RETURN, m.trace)
                self.assertNotIn(m.dialog_failure_gate_labels['error_return'], m.trace)

    def test_removing_only_fetch_or_only_prefix_copy_keeps_each_generated_failure_route_active(self):
        for kind in CALLBACKS:
            for fetch_override, prefix_bytes in ((True, False), (False, True)):
                with self.subTest(kind=kind, fetch=fetch_override, prefix=prefix_bytes):
                    m = self.machine(release=22)
                    context = m.seed_dialog(callback=kind)
                    m.remove_generated_failure_splice(kind, fetch_override=fetch_override,
                                                       prefix_bytes=prefix_bytes)
                    m.clear_events()
                    marks, snapshots = self.watch_failure(m)
                    self.assertEqual(m.run_dialog_failure(), (MASK, 22))
                    self.assert_error_exit(m, context, marks, snapshots)

    def test_removing_one_callback_splice_leaves_the_other_callback_error_route_active(self):
        for removed, active in (('first', 'second'), ('second', 'first')):
            with self.subTest(removed=removed, active=active):
                m = self.machine(acquire=22)
                m.remove_generated_failure_splice(removed)
                context = m.seed_dialog(callback=active)
                m.clear_events()
                marks, snapshots = self.watch_failure(m)
                self.assertEqual(m.run_dialog_failure(), (MASK, 22))
                self.assert_error_exit(m, context, marks, snapshots)
                self.assertNotIn(m.dialog_failure_gate_labels[removed + '_scope'], m.trace)

    def test_same_frame_fresh_acquisition_and_callback_saves_do_not_reuse_prior_error_exit(self):
        for kind in CALLBACKS:
            with self.subTest(kind=kind):
                m = self.machine(acquire=22)
                frames = []
                for release_status, mutex in ((0, DIALOG_MUTEX), (0x82, ALTERNATE_MUTEX)):
                    m.dialog_release = release_status
                    context = m.seed_dialog(callback=kind, mutex=mutex)
                    frames.append(context['sp'])
                    m.clear_events()
                    marks, snapshots = self.watch_failure(m)
                    watch, original_returns = m.on_instruction, []

                    def observe(current, pc):
                        if pc == current.dialog_failure_gate_labels[kind + '_scope']:
                            slot = current.r[29] + CALLBACKS[kind]['saves'][31]
                            original_returns.append(current.words_at(slot, 1)[0])
                        watch(current, pc)

                    m.on_instruction = observe
                    self.assertEqual(m.run_dialog_failure(), (MASK, 22))
                    self.assert_error_exit(m, context, marks, snapshots,
                                           release_status=release_status)
                    self.assertEqual(original_returns, [CALLBACK_RETURN])
                self.assertEqual(frames[0], frames[1])
                m.acquire, m.release = 0, 0
                context = m.seed_dialog(callback=kind, refresh_flag=1)
                m.clear_events()
                m.run_dialog_to_callback()
                self.assertEqual((m.r[29], m.r[31]), (context['sp'], CALLBACK_RETURN))
                self.assertEqual(m.direct_release_entries, [])
                self.assertEqual(m.dialog_witness(), (ACQUIRE_CORE.ADMITTED, DIALOG_MUTEX, 0))

    def test_changing_saved_callback_return_before_scope_is_foreign_and_does_not_unlock(self):
        for kind in CALLBACKS:
            with self.subTest(kind=kind):
                m = self.machine(acquire=22)
                context = m.seed_dialog(callback=kind)
                m.clear_events()

                def observe(current, pc):
                    if pc == current.refresh_callback_gate_labels[kind + '_abort_return']:
                        current.put(current.r[29] + CALLBACKS[kind]['saves'][31], RETURN, 4)

                m.on_instruction = observe
                self.assertEqual(m.run_dialog_failure(), (MASK, 22))
                self.assertEqual((m.r[29], m.r[31]), (context['sp'], RETURN))
                self.assertEqual(m.direct_release_entries, [])
                self.assertTrue(m.mutex_held[DIALOG_MUTEX])
                self.assertEqual(m.dialog_witness(), (ACQUIRE_CORE.ADMITTED, DIALOG_MUTEX, 0))
                self.assertNotIn(m.dialog_failure_gate_labels['error_return'], m.trace)

    def test_actual_raw_mask_error_is_distinct_from_missing_admission_no_release_state(self):
        states = []
        for missing in (False, True):
            with self.subTest(missing=missing):
                m = self.machine(acquire=22, dialog_release=MASK,
                                 dialog_release_failure_releases=False)
                context = m.seed_dialog(callback='second')
                m.clear_events()
                marks, snapshots = self.watch_failure(m)
                watch = m.on_instruction

                def observe(current, pc):
                    if (missing and pc == current.refresh_callback_gate_labels['second_abort_return']):
                        current.put(context['sp'] + ACQUIRE_CORE.TAG, 0, 4)
                    watch(current, pc)

                m.on_instruction = observe
                self.assertEqual(m.run_dialog_failure(), (MASK, 22))
                self.assert_error_exit(m, context, marks, snapshots,
                                       release_status=MASK, release_attempted=not missing)
                states.append(m.dialog_witness())
                self.assertTrue(m.mutex_held[DIALOG_MUTEX])
        self.assertEqual(states, [(core.RELEASE_ERROR, DIALOG_MUTEX, MASK),
                                  (core.NO_RELEASE, DIALOG_MUTEX, 0)])

    def test_stale_admitted_tag_is_not_ownership_proof_when_fresh_observation_hooks_are_missing(self):
        m = self.machine(acquire=22, dialog_acquire=22, dialog_release=1)
        context = m.seed_dialog(callback='first')
        for phase in ('begin', 'raw_call', 'raw_return', 'gate'):
            m.restore_legacy_dialog_phase(phase)
        for offset, value in ((ACQUIRE_CORE.TAG, ACQUIRE_CORE.ADMITTED),
                              (ACQUIRE_CORE.MUTEX, DIALOG_MUTEX),
                              (ACQUIRE_CORE.RAW_STATUS, 0)):
            m.put(context['sp'] + offset, value, 4)
        m.clear_events()
        marks, snapshots = self.watch_failure(m)
        self.assertEqual(m.run_dialog_failure(), (MASK, 22))
        self.assert_error_exit(m, context, marks, snapshots, release_status=1)
        self.assertEqual([event[0] for event in m.dialog_raw_events], [RAW_LOCK, RAW_UNLOCK])
        self.assertEqual(m.dialog_raw_events[0][-1], 22)
        self.assertFalse(m.mutex_held[DIALOG_MUTEX])


if __name__ == '__main__':
    unittest.main()
