#!/usr/bin/env python3
"""Explicit scope and missing-hook counterexamples, not graph isolation.

Every invocation here supplies genuine retained mapped nonaliasing native and
private stack frames. Neither a forged saved RA nor a malformed native unwind
is claimed safe. Raw ownership ambiguity and skipped/masked legacy failures
remain visible; no cleanup, retry or release is inferred from a local NULL.
"""

import unittest

import reveal_constructor_continuation_gate_mips as parent
import reveal_registry_acquire_gate_mips as acquire
import test_reveal_explorer_failure_gate_mips as fixture
from test_reveal_explorer_failure_gate_mips import (
    ExplorerFailureGateMachine, FIRST, SECOND, ROUTES, NAME_POSTWORK,
    EXPLORER_SLICE_END, EXPLORER_RETURN, EXPLORER_NULL,
    EXPLORER_FRAME, FIRST_FRAME, PRIVATE_FRAME, OUTER_VIEW,
    VIEW_SENTINEL, SECOND_CALLER_STACK, CONTROLLER, REGISTRY_MUTEX,
    PAINT_MUTEX, RAW_LOCK, RAW_UNLOCK, STACK, RETURN, MASK)


class ExplorerFailureGateAdversarialTests(unittest.TestCase):
    setUpClass = classmethod(fixture.ExplorerFailureGateTests.setUpClass.__func__)
    machine = fixture.ExplorerFailureGateTests.machine
    assert_null_unwind = fixture.ExplorerFailureGateTests.assert_null_unwind
    watch_scope = fixture.ExplorerFailureGateTests.watch_scope
    assert_private_stop = fixture.ExplorerFailureGateTests.assert_private_stop

    def test_each_nonzero_raw_acquire_error_cuts_only_the_selected_explorer_invocation(self):
        for status in (1, 22, 0x82, MASK):
            for held in (False, True):
                with self.subTest(status=status, held=held):
                    m = self.machine(acquire=status,
                                     registry_acquire_failure_holds=held)
                    context = m.seed_explorer()
                    m.clear_events()
                    marks = self.watch_scope(m)
                    self.assertEqual(m.run_explorer_slice(), (0, status))
                    self.assert_private_stop(m, context, marks)
                    self.assert_null_unwind(m, context)
                    self.assertEqual(m.registry_held, held)
                    self.assertEqual([(e[0], e[1], e[-1]) for e in m.raw_events],
                                     [(RAW_LOCK, REGISTRY_MUTEX, status)])
                    self.assertEqual(m.allocations, [])
                    self.assertEqual(m.freed, [])

    def test_failure_v1_is_never_interpreted_as_an_outer_stop_classifier(self):
        for poison in (0, 1, 22, 0x82, 0x80000000, MASK):
            with self.subTest(poison=poison):
                m = self.machine(acquire=22)
                context = m.seed_explorer()

                def mutate(current, pc):
                    if pc == current.constructor_continuation_gate_labels['first_gate']:
                        self.assertNotEqual(current.r[2], 0)
                        current.r[3] = poison

                m.on_instruction = mutate
                m.clear_events()
                self.assertEqual(m.run_explorer_slice(), (0, poison))
                self.assert_null_unwind(m, context)

    def test_success_v1_poison_does_not_enter_the_new_failure_helper(self):
        for poison in (0, 1, 22, 0x82, 0x80000000, MASK):
            with self.subTest(poison=poison):
                m = self.machine()
                m.seed_explorer()

                def mutate(current, pc):
                    if pc == current.constructor_continuation_gate_labels['first_gate']:
                        self.assertEqual(current.r[2], 0)
                        current.r[3] = poison

                m.on_instruction = mutate
                m.clear_events()
                m.run_explorer_slice(EXPLORER_SLICE_END)
                self.assertNotIn(m.explorer_failure_gate_labels['scope'], m.trace)
                self.assertEqual(m.peek(OUTER_VIEW + 0xCC), m.created_engines[0])
                self.assertEqual(m.outer_enable_events,
                                 [(CONTROLLER, m.created_engines[0])])
                self.assertEqual(len(m.native_continuations), 1)

    def test_parent_nonzero_v0_scope_remains_exact_and_does_not_normalize_statuses(self):
        for status in (1, 22, 0x82, 0x7FFFFFFF, 0x80000000, MASK):
            with self.subTest(status=status):
                m = self.machine()
                context = m.seed_explorer()

                def mutate(current, pc):
                    if pc == current.constructor_continuation_gate_labels['first_gate']:
                        current.r[2], current.r[3] = status, 0xABCD0011

                m.on_instruction = mutate
                m.clear_events()
                self.assertEqual(m.run_explorer_slice(), (0, 0xABCD0011))
                self.assert_null_unwind(m, context)
                # Real registration already happened before this controlled
                # classifier mutation. The local exit does not roll it back.
                self.assertEqual(m.lifecycle_header(), (1, 0, 0, 0))
                self.assertEqual(len(m.allocations), 1)
                self.assertEqual(m.freed, [])

    def test_other_first_constructor_caller_saved_ra_is_unchanged(self):
        for caller in (RETURN, 0x12345670, 0x492918, 0x492924):
            with self.subTest(caller=hex(caller)):
                m = self.machine(acquire=22)
                marks = self.watch_scope(m)
                result, raw = m.construct(FIRST, caller=caller)
                self.assertEqual((result, raw), (m.created_engines[0], 22))
                self.assertEqual((m.r[29], m.r[31]), (STACK, caller))
                self.assertEqual(m.peek(STACK - FIRST_FRAME + 0x84), caller)
                self.assertNotIn(m.explorer_failure_gate_labels['selected'], m.trace)
                self.assertNotIn(EXPLORER_NULL, m.trace)
                self.assertEqual(len(marks), 1)
                _, writes, calls, _, _ = marks[0]
                self.assertEqual(m.writes[writes:], [])
                self.assertEqual(m.calls[calls:], [])

    def test_other_first_caller_replays_hi_and_parent_restore_without_new_private_writes(self):
        m = self.machine(acquire=22)
        snapshots = {}

        def observe(current, pc):
            labels = current.constructor_continuation_gate_labels
            if pc in (labels['first_gate'], parent.FIRST_EPILOGUE):
                snapshots[pc] = (current.r.copy(), current.hi, current.lo)

        m.on_instruction = observe
        result, _ = m.construct(FIRST)
        gate = m.constructor_continuation_gate_labels['first_gate']
        self.assertEqual(snapshots[gate], snapshots[parent.FIRST_EPILOGUE])
        self.assertEqual(result, m.created_engines[0])
        start = m.explorer_failure_gate_labels['scope']
        helper = [event for event in m.constructor_accesses
                  if start <= event[1] < fixture.CODE + len(m.code)]
        self.assertEqual([(kind, address, size) for kind, _, address, size in helper],
                         [('read', STACK - FIRST_FRAME + 0x84, 4),
                          ('read', STACK - FIRST_FRAME - PRIVATE_FRAME + parent.HI, 4)])

    def test_second_constructor_success_and_failure_keep_the_inherited_engine_abi(self):
        for status in (0, 22):
            with self.subTest(status=status):
                m = self.machine(acquire=status)
                result, raw = m.construct(SECOND, caller=EXPLORER_RETURN)
                self.assertEqual(result, m.created_engines[0])
                self.assertNotEqual(result, 0)
                self.assertNotIn(m.explorer_failure_gate_labels['scope'], m.trace)
                self.assertEqual(len(m.native_continuations), int(status == 0))
                self.assertEqual(m.r[29], STACK)

    def test_wrong_parent_u_or_registration_ra_forwards_legacy_work_not_the_outer_cut(self):
        for register, value in ((17, CONTROLLER + 4), (31, 0x43AE98)):
            with self.subTest(register=register):
                m = self.machine(acquire=22)
                m.seed_explorer()

                def mutate(current, pc):
                    if pc == current.constructor_continuation_gate_labels['first_gate']:
                        current.r[register] = value

                m.on_instruction = mutate
                m.clear_events()
                m.run_explorer_slice(EXPLORER_SLICE_END)
                self.assertNotIn(m.explorer_failure_gate_labels['scope'], m.trace)
                self.assertEqual(m.peek(OUTER_VIEW + 0xCC), m.created_engines[0])
                self.assertEqual(m.outer_enable_events,
                                 [(CONTROLLER, m.created_engines[0])])
                self.assertEqual(len(m.native_continuations), 1)

    def test_missing_generated_splice_requires_removing_fetch_override_and_actual_prefix_patch(self):
        m = self.machine(acquire=22)
        m.remove_generated_splice()
        m.seed_explorer()
        m.clear_events()
        m.run_explorer_slice(EXPLORER_SLICE_END)
        self.assertNotIn(m.explorer_failure_gate_labels['scope'], m.trace)
        self.assertEqual(m.peek(OUTER_VIEW + 0xCC), m.created_engines[0])
        self.assertEqual(m.outer_enable_events, [(CONTROLLER, m.created_engines[0])])
        self.assertEqual(m.native_continuations, [])
        self.assertNotIn(NAME_POSTWORK, m.calls)
        self.assertNotIn(EXPLORER_NULL, m.trace)

    def test_removing_only_fetch_override_leaves_the_explicit_code_prefix_splice_active(self):
        m = self.machine(acquire=22)
        m.remove_generated_splice(fetch_override=True, prefix_bytes=False)
        context = m.seed_explorer()
        m.clear_events()
        self.assertEqual(m.run_explorer_slice(), (0, 22))
        self.assert_null_unwind(m, context)

    def test_restoring_only_prefix_bytes_leaves_the_same_coherent_fetch_override_active(self):
        m = self.machine(acquire=22)
        m.remove_generated_splice(fetch_override=False, prefix_bytes=True)
        context = m.seed_explorer()
        m.clear_events()
        self.assertEqual(m.run_explorer_slice(), (0, 22))
        self.assert_null_unwind(m, context)

    def test_missing_first_constructor_status_hook_leaves_the_outer_failure_unhandled(self):
        m = self.machine(acquire=22)
        m.remove_pair(parent.HOOKS['first_gate'][0])
        m.seed_explorer()
        m.clear_events()
        m.run_explorer_slice(EXPLORER_SLICE_END)
        self.assertNotIn(m.explorer_failure_gate_labels['scope'], m.trace)
        self.assertEqual(m.peek(OUTER_VIEW + 0xCC), m.created_engines[0])
        self.assertEqual(len(m.native_continuations), 1)
        self.assertIn(NAME_POSTWORK, m.calls)
        self.assertEqual(m.outer_enable_events, [(CONTROLLER, m.created_engines[0])])

    def test_missing_raw_acquire_gate_still_masks_error_and_admits_native_outer_use(self):
        m = self.machine(acquire=22)
        m.remove_pair(acquire.HOOKS['register_gate'][0])
        m.seed_explorer()
        m.clear_events()
        m.run_explorer_slice(EXPLORER_SLICE_END)
        self.assertNotIn(m.explorer_failure_gate_labels['scope'], m.trace)
        self.assertEqual(len(m.allocations), 1)
        self.assertEqual(m.peek(OUTER_VIEW + 0xCC), m.created_engines[0])
        self.assertEqual(len(m.native_continuations), 1)
        self.assertIn(NAME_POSTWORK, m.calls)
        self.assertEqual(m.lifecycle_header(), (0, 0, 0, 0))

    def test_masked_raw_release_errors_still_reach_ui_and_outer_store_with_ambiguous_r(self):
        for status in (1, 22, 0x82, MASK):
            for released in (False, True):
                with self.subTest(status=status, released=released):
                    m = self.machine(release=status,
                                     registry_release_failure_releases=released)
                    m.seed_explorer()
                    m.clear_events()
                    m.run_explorer_slice(EXPLORER_SLICE_END)
                    self.assertNotIn(m.explorer_failure_gate_labels['scope'], m.trace)
                    self.assertEqual(len(m.native_continuations), 1)
                    self.assertIn(NAME_POSTWORK, m.calls)
                    self.assertEqual(m.peek(OUTER_VIEW + 0xCC), m.created_engines[0])
                    self.assertEqual(m.outer_enable_events,
                                     [(CONTROLLER, m.created_engines[0])])
                    self.assertEqual(m.registry_held, not released)
                    self.assertEqual(m.raw_events[-1][-1], status)
                    self.assertEqual(m.lifecycle_header(), (1, 0, 0, 0))
                    self.assertEqual(m.freed, [])

    def test_skipped_first_registration_null_faults_remain_outside_the_new_stop(self):
        for options in ({'resource_missing': True}, {'validation_result': 0},
                        {'fail_engine_allocation': True}):
            with self.subTest(options=options):
                m = self.machine(**options)
                m.seed_explorer()
                m.clear_events()
                with self.assertRaisesRegex(AssertionError, r'^unmapped access 0x0, size 4$'):
                    m.run_explorer_slice()
                self.assertNotIn(m.explorer_failure_gate_labels['scope'], m.trace)
                self.assertEqual(m.native_entries, [])
                self.assertEqual(len(m.native_continuations), 1)
                self.assertEqual(m.peek(OUTER_VIEW + 0xCC), VIEW_SENTINEL)
                self.assertEqual(m.outer_enable_events, [])
                self.assertIn(('read', 0x43AEA0, 0, 4), m.constructor_accesses)


if __name__ == '__main__':
    unittest.main()
