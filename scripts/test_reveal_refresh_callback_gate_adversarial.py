#!/usr/bin/env python3
"""Exercise callback-exit scope, fresh native saves and missing-hook limits.

All entries have genuine mapped retained nonaliasing live frames. Controlled
errors and repeated fixture calls are ABI/freshness checks, not permission to
retry or reclaim a native instance. The dialog callback-result policy and its
lock/cleanup obligations remain outside this local callback escape.
"""

import unittest

import test_reveal_refresh_callback_gate_mips as fixture
from test_reveal_refresh_callback_gate_mips import (
    CALLBACKS, CONTROLLER, REGISTRY_MUTEX, RAW_LOCK, RAW_UNLOCK,
    DIALOG, OPERATION, RETURN, MASK, REFRESH, WRAPPER_RESET)


class RefreshCallbackGateAdversarialTests(unittest.TestCase):
    setUpClass = classmethod(fixture.RefreshCallbackGateTests.setUpClass.__func__)
    machine = fixture.RefreshCallbackGateTests.machine
    watch_scope = fixture.RefreshCallbackGateTests.watch_scope
    assert_callback_unwind = fixture.RefreshCallbackGateTests.assert_callback_unwind
    assert_selected_stop = fixture.RefreshCallbackGateTests.assert_selected_stop

    def test_each_acquire_error_and_ownership_outcome_preserves_result_through_both_callbacks(self):
        for status in (1, 22, 0x82, MASK):
            for held in (False, True):
                for kind in CALLBACKS:
                    for wrapper_flag, refresh_flag in ((0, 0), (1, 1)):
                        with self.subTest(status=status, held=held, kind=kind,
                                          wrapper=wrapper_flag, refresh=refresh_flag):
                            m = self.machine(acquire=status,
                                             registry_acquire_failure_holds=held)
                            context = m.seed_callback(kind, wrapper_flag=wrapper_flag,
                                                      refresh_flag=refresh_flag)
                            m.clear_events()
                            marks, snapshots = self.watch_scope(m)
                            self.assertEqual(m.run_callback_slice(), (MASK, status))
                            self.assert_selected_stop(m, context, marks, snapshots, raw=status)
                            self.assertEqual(m.registry_held, held)
                            self.assertEqual([(event[0], event[1], event[-1])
                                              for event in m.raw_events],
                                             [(RAW_LOCK, REGISTRY_MUTEX, status)])
                            self.assertEqual(m.freed, [])

    def test_each_release_error_and_ownership_outcome_preserves_result_through_both_callbacks(self):
        for status in (1, 22, 0x82, MASK):
            for released in (False, True):
                for kind in CALLBACKS:
                    for wrapper_flag, refresh_flag in ((0, 0), (1, 1)):
                        with self.subTest(status=status, released=released, kind=kind,
                                          wrapper=wrapper_flag, refresh=refresh_flag):
                            m = self.machine(release=status,
                                             registry_release_failure_releases=released)
                            context = m.seed_callback(kind, wrapper_flag=wrapper_flag,
                                                      refresh_flag=refresh_flag)
                            m.clear_events()
                            marks, snapshots = self.watch_scope(m)
                            self.assertEqual(m.run_callback_slice(), (MASK, status))
                            self.assert_selected_stop(m, context, marks, snapshots, raw=status)
                            self.assertEqual(m.registry_held, not released)
                            self.assertEqual([(event[0], event[1], event[-1])
                                              for event in m.raw_events],
                                             [(RAW_LOCK, REGISTRY_MUTEX, 0),
                                              (RAW_UNLOCK, REGISTRY_MUTEX, status)])

    def test_classified_nonzero_including_one_preserves_uninterpreted_v1(self):
        cases = ((1, 0), (1, MASK), (22, 0x82), (MASK, 0x12345678),
                 (0x80000001, 1), (0x12345678, 0x80000000))
        for kind in CALLBACKS:
            for result, diagnostic in cases:
                with self.subTest(kind=kind, result=result, diagnostic=diagnostic):
                    m = self.machine()
                    marks, snapshots = self.watch_scope(m)
                    self.assertEqual(m.invoke_callback_refresh_gate(
                        kind, result=result, diagnostic=diagnostic), (result, diagnostic))
                    self.assert_selected_stop(m, m.callback_context, marks, snapshots,
                                              result=result, raw=diagnostic)
                    self.assertEqual(m.calls, [])

    def test_zero_with_poisoned_v1_keeps_native_callback_behavior_and_context_free(self):
        for kind in CALLBACKS:
            for diagnostic in (0, MASK):
                for refresh_flag in (0, 1):
                    with self.subTest(kind=kind, diagnostic=diagnostic, flag=refresh_flag):
                        m, old = self.machine(), self.machine()
                        old.remove_generated_callback_splice()
                        expected = old.invoke_callback_refresh_gate(
                            kind, result=0, diagnostic=diagnostic, refresh_flag=refresh_flag)
                        self.assertEqual(m.invoke_callback_refresh_gate(
                            kind, result=0, diagnostic=diagnostic,
                            refresh_flag=refresh_flag), expected)
                        self.assertEqual((m.r, m.hi, m.lo), (old.r, old.hi, old.lo))
                        self.assertEqual(m.operation_free_entries, old.operation_free_entries)
                        self.assertEqual(m.callback_postwork_entries, old.callback_postwork_entries)
                        self.assertEqual(len(m.operation_free_entries), 1)
                        self.assertNotIn(m.refresh_callback_gate_labels['scope'], m.trace)

    def test_missing_both_generated_copies_allows_context_cleanup_and_destroys_diagnostic(self):
        for kind in CALLBACKS:
            for option in ('acquire', 'release'):
                with self.subTest(kind=kind, option=option):
                    m = self.machine(**{option: 22})
                    context = m.seed_callback(kind)
                    m.remove_generated_callback_splice()
                    m.clear_events()
                    self.assertEqual(m.run_callback_slice(), (0, 0xBAD00003))
                    self.assert_callback_unwind(m, context)
                    self.assertEqual(len(m.operation_free_entries), 1)
                    self.assertIn(OPERATION, m.freed)
                    self.assertEqual(m.callback_postwork_entries, [])
                    self.assertEqual(m.wrapper_reset_entries, [])
                    self.assertIn(CALLBACKS[kind]['return_pc'], m.trace)
                    expected_context = 0 if kind == 'first' else OPERATION
                    self.assertEqual(m.words_at(DIALOG + 0x58, 1), (expected_context,))
                    self.assertNotIn(m.refresh_callback_gate_labels['scope'], m.trace)
                    self.assertEqual(m.raw_events[-1][-1], 22)
                    self.assertEqual(m.words_at(m.wrapper_context['sp'] + 0x2C, 1),
                                     (CALLBACKS[kind]['return_pc'],))

    def test_removing_only_fetch_or_only_prefix_copy_retains_callback_splice(self):
        for kind in CALLBACKS:
            for fetch_override, prefix_bytes in ((True, False), (False, True)):
                with self.subTest(kind=kind, fetch=fetch_override, prefix=prefix_bytes):
                    m = self.machine(release=22)
                    context = m.seed_callback(kind)
                    m.remove_generated_callback_splice(fetch_override=fetch_override,
                                                        prefix_bytes=prefix_bytes)
                    m.clear_events()
                    marks, snapshots = self.watch_scope(m)
                    self.assertEqual(m.run_callback_slice(), (MASK, 22))
                    self.assert_selected_stop(m, context, marks, snapshots)

    def test_missing_earlier_wrapper_splice_restores_view_work_and_callback_cleanup(self):
        for kind in CALLBACKS:
            with self.subTest(kind=kind):
                m = self.machine(acquire=22)
                context = m.seed_callback(kind)
                m.remove_generated_wrapper_splice()
                m.clear_events()
                m.run_callback_slice()
                self.assert_callback_unwind(m, context)
                self.assertEqual(m.raw_events[-1][-1], 22)
                self.assertEqual(len(m.wrapper_reset_entries), 1)
                self.assertEqual(m.calls.count(WRAPPER_RESET), 1)
                self.assertEqual(len(m.operation_free_entries), 1)
                self.assertEqual(m.recreate_entries, [])
                self.assertNotIn(m.refresh_callback_gate_labels['scope'], m.trace)

    def test_missing_earlier_refresh_gate_masks_error_before_callback_helper(self):
        for kind in CALLBACKS:
            with self.subTest(kind=kind):
                m = self.machine(release=22)
                context = m.seed_callback(kind)
                m.remove_pair(REFRESH.HOOKS['gate'][0])
                m.clear_events()
                m.run_callback_slice()
                self.assert_callback_unwind(m, context)
                self.assertEqual(m.raw_events[-1][-1], 22)
                self.assertEqual(len(m.recreate_entries), 1)
                self.assertEqual(len(m.wrapper_reset_entries), 1)
                self.assertEqual(len(m.operation_free_entries), 1)
                self.assertEqual(m.refresh_delay_effects, [(0x4ACD94, MASK)])
                self.assertNotIn(m.refresh_callback_gate_labels['scope'], m.trace)

    def test_missing_raw_capture_preserves_unknown_zero_diagnostic_through_callback_exit(self):
        for kind in CALLBACKS:
            with self.subTest(kind=kind):
                m = self.machine(release=22)
                context = m.seed_callback(kind)
                m.restore_legacy_delete_release_phase('raw_release_return')
                m.clear_events()
                marks, snapshots = self.watch_scope(m)
                self.assertEqual(m.run_callback_slice(), (MASK, 0))
                self.assert_selected_stop(m, context, marks, snapshots, raw=0)
                self.assertEqual(m.raw_events[-1][-1], 22)
                self.assertEqual(m.resource_entries, [])

    def test_fresh_same_frame_saved_return_does_not_reuse_previous_callback_abort(self):
        for kind in CALLBACKS:
            with self.subTest(kind=kind):
                m = self.machine(acquire=22)
                frames = []
                for acquire_status, release_status, flag in ((22, 0, 0), (0, 0x82, 1)):
                    m.acquire, m.release = acquire_status, release_status
                    context = m.seed_callback(kind, refresh_flag=flag)
                    frames.append(context['sp'])
                    m.clear_events()
                    marks, snapshots = self.watch_scope(m)
                    callers, watch = [], m.on_instruction

                    def observe(current, pc):
                        if pc == current.refresh_callback_gate_labels['scope']:
                            callers.append(current.words_at(
                                current.wrapper_context['sp'] + 0x2C, 1)[0])
                        watch(current, pc)

                    m.on_instruction = observe
                    status = acquire_status or release_status
                    self.assertEqual(m.run_callback_slice(), (MASK, status))
                    self.assert_selected_stop(m, context, marks, snapshots, raw=status)
                    self.assertEqual(callers, [CALLBACKS[kind]['return_pc']])
                self.assertEqual(frames[0], frames[1])
                m.acquire, m.release = 0, 0
                context = m.seed_callback(kind, refresh_flag=1)
                m.clear_events()
                m.run_callback_slice()
                self.assert_callback_unwind(m, context)
                self.assertEqual(len(m.operation_free_entries), 1)
                self.assertNotIn(m.refresh_callback_gate_labels['scope'], m.trace)
                self.assertEqual(m.words_at(m.wrapper_context['sp'] + 0x2C, 1),
                                 (CALLBACKS[kind]['return_pc'],))

    def test_parent_scope_mismatch_preserves_baseline_without_callback_helper(self):
        for kind in CALLBACKS:
            for controller, return_pc in ((CONTROLLER + 0x1000, 0x4ACD94),
                                          (CONTROLLER, RETURN)):
                with self.subTest(kind=kind, controller=controller, return_pc=return_pc):
                    m, old = self.machine(), self.machine()
                    old.remove_generated_callback_splice()
                    expected = old.invoke_callback_refresh_gate(
                        kind, result=MASK, diagnostic=22, refresh_flag=1,
                        controller=controller, return_pc=return_pc)
                    self.assertEqual(m.invoke_callback_refresh_gate(
                        kind, result=MASK, diagnostic=22, refresh_flag=1,
                        controller=controller, return_pc=return_pc), expected)
                    self.assertEqual((m.r, m.hi, m.lo), (old.r, old.hi, old.lo))
                    self.assertEqual(len(m.operation_free_entries), 1)
                    self.assertEqual(m.wrapper_reset_entries, [])
                    self.assertNotIn(m.refresh_callback_gate_labels['scope'], m.trace)


if __name__ == '__main__':
    unittest.main()
