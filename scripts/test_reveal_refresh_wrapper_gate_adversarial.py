#!/usr/bin/env python3
"""Expose the selected wrapper splice's scope and coherent-activation limits.

Controlled entries have genuine retained mapped W/C/private frames. No helper
entry is a fabricated-frame API or malformed-stack recovery. Repeated fixture
invocations are adversarial freshness checks, not permission to retry an
uncertain native instance. Earlier effects and higher callbacks remain outside
this local saved-return diversion; missing-hook cases are counterexamples.
"""

import unittest

import test_reveal_refresh_wrapper_gate_mips as fixture
from test_reveal_refresh_wrapper_gate_mips import (
    CONTROLLER, REGISTRY_MUTEX, RAW_LOCK, RAW_UNLOCK, OUTER_VIEW,
    STACK, RETURN, MASK, REFRESH, WRAPPER_RESET, core)


class RefreshWrapperGateAdversarialTests(unittest.TestCase):
    setUpClass = classmethod(fixture.RefreshWrapperGateTests.setUpClass.__func__)
    machine = fixture.RefreshWrapperGateTests.machine
    watch_scope = fixture.RefreshWrapperGateTests.watch_scope
    assert_wrapper_unwind = fixture.RefreshWrapperGateTests.assert_wrapper_unwind
    assert_selected_stop = fixture.RefreshWrapperGateTests.assert_selected_stop

    def test_each_acquire_error_preserves_exact_status_for_both_flags_and_ownership_outcomes(self):
        for status in (1, 22, 0x82, MASK):
            for held in (False, True):
                for wrapper_flag, refresh_flag in ((0, 0), (0, 1), (1, 0), (1, 1)):
                    with self.subTest(status=status, held=held, wrapper_flag=wrapper_flag,
                                      refresh_flag=refresh_flag):
                        m = self.machine(acquire=status, registry_acquire_failure_holds=held)
                        context = m.seed_wrapper(wrapper_flag=wrapper_flag, refresh_flag=refresh_flag)
                        m.clear_events()
                        marks, snapshots = self.watch_scope(m)
                        self.assertEqual(m.run_wrapper_slice(), (MASK, status))
                        self.assert_selected_stop(m, context, marks, snapshots, raw=status)
                        self.assertEqual(m.registry_held, held)
                        self.assertEqual([(event[0], event[1], event[-1]) for event in m.raw_events],
                                         [(RAW_LOCK, REGISTRY_MUTEX, status)])
                        self.assertEqual(m.freed, [])

    def test_each_release_error_preserves_exact_status_for_both_flags_and_ownership_outcomes(self):
        for status in (1, 22, 0x82, MASK):
            for released in (False, True):
                for wrapper_flag, refresh_flag in ((0, 0), (0, 1), (1, 0), (1, 1)):
                    with self.subTest(status=status, released=released, wrapper_flag=wrapper_flag,
                                      refresh_flag=refresh_flag):
                        m = self.machine(release=status,
                                         registry_release_failure_releases=released)
                        context = m.seed_wrapper(wrapper_flag=wrapper_flag, refresh_flag=refresh_flag)
                        m.clear_events()
                        marks, snapshots = self.watch_scope(m)
                        self.assertEqual(m.run_wrapper_slice(), (MASK, status))
                        self.assert_selected_stop(m, context, marks, snapshots, raw=status)
                        self.assertEqual(m.registry_held, not released)
                        self.assertEqual([(event[0], event[1], event[-1]) for event in m.raw_events],
                                         [(RAW_LOCK, REGISTRY_MUTEX, 0),
                                          (RAW_UNLOCK, REGISTRY_MUTEX, status)])

    def test_classified_nonzero_results_including_one_preserve_uninterpreted_v1(self):
        cases = ((1, 0), (1, MASK), (22, 0x82), (MASK, 0x12345678),
                 (0x80000001, 1), (0x12345678, 0x80000000))
        for result, diagnostic in cases:
            for wrapper_flag, refresh_flag in ((0, 0), (1, 1)):
                with self.subTest(result=result, diagnostic=diagnostic,
                                  wrapper_flag=wrapper_flag, refresh_flag=refresh_flag):
                    m = self.machine()
                    marks, snapshots = self.watch_scope(m)
                    self.assertEqual(m.invoke_wrapper_refresh_gate(
                        result=result, diagnostic=diagnostic, wrapper_flag=wrapper_flag,
                        refresh_flag=refresh_flag), (result, diagnostic))
                    self.assert_selected_stop(m, m.wrapper_context, marks, snapshots,
                                              result=result, raw=diagnostic)
                    self.assertEqual(m.calls, [])

    def test_zero_with_v1_poison_retains_same_ordinary_wrapper_behavior(self):
        for diagnostic in (0, MASK):
            for wrapper_flag, refresh_flag in ((0, 0), (0, 1), (1, 0), (1, 1)):
                with self.subTest(diagnostic=diagnostic, wrapper_flag=wrapper_flag,
                                  refresh_flag=refresh_flag):
                    m, old = self.machine(), self.machine()
                    old.remove_generated_wrapper_splice()
                    expected = old.invoke_wrapper_refresh_gate(
                        result=0, diagnostic=diagnostic, wrapper_flag=wrapper_flag,
                        refresh_flag=refresh_flag)
                    self.assertEqual(m.invoke_wrapper_refresh_gate(
                        result=0, diagnostic=diagnostic, wrapper_flag=wrapper_flag,
                        refresh_flag=refresh_flag), expected)
                    self.assertEqual((m.r, m.hi, m.lo), (old.r, old.hi, old.lo))
                    self.assertEqual(m.recreate_entries, old.recreate_entries)
                    self.assertEqual(m.wrapper_reset_entries, old.wrapper_reset_entries)
                    self.assertNotIn(m.refresh_wrapper_gate_labels['scope'], m.trace)

    def test_missing_both_generated_copies_allows_wrapper_view_work_after_actual_failure(self):
        for option in ('acquire', 'release'):
            with self.subTest(option=option):
                m = self.machine(**{option: 22})
                context = m.seed_wrapper(wrapper_flag=1, refresh_flag=0)
                m.remove_generated_wrapper_splice()
                m.clear_events()
                self.assertEqual(m.run_wrapper_slice(), (MASK, 0xBAD00003))
                self.assert_wrapper_unwind(m, context)
                self.assertEqual(len(m.wrapper_reset_entries), 1)
                self.assertEqual(m.wrapper_reset_entries[0][0][0], context['view'])
                self.assertEqual(m.wrapper_reset_entries[0][1:], (context['sp'], 0x4AD8FC))
                self.assertEqual(m.calls.count(WRAPPER_RESET), 1)
                self.assertEqual(m.recreate_entries, [])
                self.assertIn(core.WRAPPER_RETURN, m.trace)
                self.assertIn(0x4AD900, m.trace)
                self.assertNotIn(m.refresh_wrapper_gate_labels['scope'], m.trace)
                self.assertEqual(m.raw_events[-1][-1], 22)
                self.assertEqual(m.words_at(m.refresh_context['sp'] + 0x484, 1),
                                 (core.WRAPPER_RETURN,))

    def test_removing_only_fetch_or_only_prefix_copy_does_not_remove_the_splice(self):
        for fetch_override, prefix_bytes in ((True, False), (False, True)):
            with self.subTest(fetch_override=fetch_override, prefix_bytes=prefix_bytes):
                m = self.machine(release=22)
                context = m.seed_wrapper(wrapper_flag=1, refresh_flag=0)
                m.remove_generated_wrapper_splice(fetch_override=fetch_override,
                                                   prefix_bytes=prefix_bytes)
                m.clear_events()
                marks, snapshots = self.watch_scope(m)
                self.assertEqual(m.run_wrapper_slice(), (MASK, 22))
                self.assert_selected_stop(m, context, marks, snapshots)

    def test_missing_earlier_refresh_gate_masks_error_before_generated_scope(self):
        m = self.machine(release=22)
        context = m.seed_wrapper(wrapper_flag=1, refresh_flag=0)
        m.remove_pair(REFRESH.HOOKS['gate'][0])
        m.clear_events()
        self.assertEqual(m.run_wrapper_slice()[0], 0)
        self.assert_wrapper_unwind(m, context)
        self.assertEqual(m.raw_events[-1][-1], 22)
        self.assertEqual(len(m.recreate_entries), 1)
        self.assertEqual(len(m.wrapper_reset_entries), 1)
        self.assertNotIn(m.refresh_wrapper_gate_labels['scope'], m.trace)
        self.assertEqual(m.refresh_delay_effects, [(0x4ACD94, MASK)])

    def test_missing_earlier_delete_completion_leaves_masked_release_success(self):
        m = self.machine(release=22, registry_release_failure_releases=False)
        context = m.seed_wrapper(wrapper_flag=1, refresh_flag=1)
        m.restore_legacy_delete_release_phase('complete')
        m.clear_events()
        self.assertEqual(m.run_wrapper_slice()[0], 1)
        self.assert_wrapper_unwind(m, context)
        self.assertTrue(m.registry_held)
        self.assertEqual(m.raw_events[-1][-1], 22)
        self.assertEqual(len(m.resource_entries), 1)
        self.assertEqual(m.wrapper_reset_entries, [])
        self.assertNotIn(m.refresh_wrapper_gate_labels['scope'], m.trace)

    def test_missing_raw_capture_propagates_unknown_zero_diagnostic_without_reclassification(self):
        m = self.machine(release=22)
        context = m.seed_wrapper(wrapper_flag=1, refresh_flag=0)
        m.restore_legacy_delete_release_phase('raw_release_return')
        m.clear_events()
        marks, snapshots = self.watch_scope(m)
        self.assertEqual(m.run_wrapper_slice(), (MASK, 0))
        self.assert_selected_stop(m, context, marks, snapshots, raw=0)
        self.assertEqual(m.raw_events[-1][-1], 22)
        self.assertEqual(m.resource_entries, [])

    def test_fresh_native_save_slot_does_not_adopt_a_prior_same_frame_abort_return(self):
        m = self.machine(acquire=22)
        frames = []
        for acquire_status, release_status, refresh_flag in ((22, 0, 0), (0, 0x82, 1)):
            m.acquire, m.release = acquire_status, release_status
            context = m.seed_wrapper(wrapper_flag=1, refresh_flag=refresh_flag)
            frames.append(context['sp'])
            m.clear_events()
            marks, snapshots = self.watch_scope(m)
            scope_callers = []
            watch = m.on_instruction

            def observe(current, pc):
                if pc == current.refresh_wrapper_gate_labels['scope']:
                    scope_callers.append(current.words_at(
                        current.r[29] + core.OUTER_RA_OFFSET, 1)[0])
                watch(current, pc)

            m.on_instruction = observe
            status = acquire_status or release_status
            self.assertEqual(m.run_wrapper_slice(), (MASK, status))
            self.assert_selected_stop(m, context, marks, snapshots, raw=status)
            self.assertEqual(scope_callers, [core.WRAPPER_RETURN])
        self.assertEqual(frames[0], frames[1])
        m.acquire, m.release = 0, 0
        context = m.seed_wrapper(wrapper_flag=1, refresh_flag=1)
        m.clear_events()
        self.assertEqual(m.run_wrapper_slice()[0], 1)
        self.assert_wrapper_unwind(m, context)
        self.assertNotIn(m.refresh_wrapper_gate_labels['scope'], m.trace)
        self.assertEqual(m.words_at(m.refresh_context['sp'] + 0x484, 1),
                         (core.WRAPPER_RETURN,))

    def test_foreign_outer_refresh_caller_keeps_each_classified_error_and_original_ra(self):
        foreign_return = 0x4AEC24
        for result, diagnostic, flag in ((1, 0x82, 0), (MASK, 0, 1)):
            with self.subTest(result=result, diagnostic=diagnostic, flag=flag):
                m, old = self.machine(), self.machine()
                old.remove_generated_wrapper_splice()
                for current in (m, old):
                    current.seed_refresh(caller=foreign_return, flag=flag)
                    current.r[2:4] = result, diagnostic
                    current.r[31] = REFRESH.HOOKS['gate'][0]
                    current.clear_events()
                marks, snapshots = self.watch_scope(m)
                for current in (m, old):
                    current.run_at(REFRESH.HOOKS['gate'][0], foreign_return)
                self.assertEqual((m.r[2], m.r[3]), (result, diagnostic))
                self.assertEqual((m.r, m.hi, m.lo), (old.r, old.hi, old.lo))
                self.assertEqual((m.r[29], m.r[31]), (STACK, foreign_return))
                self.assertEqual(snapshots['gate'], snapshots['refresh_epilogue'])
                self.assertEqual(m.writes[marks[0][1]:], [])
                self.assertNotIn(m.refresh_wrapper_gate_labels['selected'], m.trace)
                self.assertNotIn(m.refresh_wrapper_gate_labels['abort_return'], m.trace)

    def test_parent_scope_mismatch_preserves_ordinary_return_without_entering_helper(self):
        for controller, return_pc in ((CONTROLLER + 0x1000, 0x4ACD94),
                                      (CONTROLLER, RETURN)):
            with self.subTest(controller=controller, return_pc=return_pc):
                m, old = self.machine(), self.machine()
                old.remove_generated_wrapper_splice()
                expected = old.invoke_wrapper_refresh_gate(
                    result=MASK, diagnostic=22, refresh_flag=1,
                    controller=controller, return_pc=return_pc)
                self.assertEqual(m.invoke_wrapper_refresh_gate(
                    result=MASK, diagnostic=22, refresh_flag=1,
                    controller=controller, return_pc=return_pc), expected)
                self.assertEqual(m.r[2], 1)
                self.assertEqual((m.r, m.hi, m.lo), (old.r, old.hi, old.lo))
                self.assertEqual(m.wrapper_reset_entries, [])
                self.assertNotIn(m.refresh_wrapper_gate_labels['scope'], m.trace)


if __name__ == '__main__':
    unittest.main()
