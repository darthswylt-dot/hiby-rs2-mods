#!/usr/bin/env python3
"""Scoped local stops preserve legacy gaps, not whole-instance isolation.

These fixtures retain genuine mapped nonaliasing native and bridge frames.
Raw ownership ambiguity, missing coherent hooks and masked release failures
remain explicit counterexamples; no malformed-stack safe unwind is asserted.
"""

import unittest

import reveal_constructor_continuation_gate_mips as core
import reveal_registry_acquire_gate_mips as acquire
import test_reveal_constructor_continuation_gate_mips as fixture
from test_reveal_constructor_continuation_gate_mips import (
    ConstructorContinuationGateMachine, FIRST, SECOND, ROUTES, NAME_POSTWORK,
    CONTROLLER, REGISTRY_MUTEX, PAINT_MUTEX, RAW_LOCK, RAW_UNLOCK, STACK, MASK)


class ConstructorContinuationGateAdversarialTests(unittest.TestCase):
    setUpClass = classmethod(fixture.ConstructorContinuationGateTests.setUpClass.__func__)

    def machine(self, **options):
        return ConstructorContinuationGateMachine(self.image, **options)

    def watch_gate(self, machine, gate, mutation=None):
        marks = []

        def observe(current, pc):
            if pc == current.constructor_continuation_gate_labels[gate]:
                if mutation is not None:
                    mutation(current)
                marks.append((len(current.reads), len(current.writes),
                              len(current.calls), current.r[29],
                              len(current.constructor_accesses)))

        machine.on_instruction = observe
        return marks

    def assert_only_retained_frames_after_stop(self, machine, marks, frame):
        self.assertEqual(len(marks), 1)
        reads, writes, calls, native_sp, accesses = marks[0]
        first, end = native_sp - core.FRAME, native_sp + frame
        self.assertEqual(machine.calls[calls:], [])
        self.assertTrue(all(first <= address and address + size <= end
                            for address, size in machine.reads[reads:]))
        self.assertTrue(all(first <= address and address + size <= end
                            for address, _, size in machine.writes[writes:]))
        # The emitted decision uses its saved registers only. Native SP+50
        # is read later by the unchanged stock epilogue, not by this gate.
        labels = machine.constructor_continuation_gate_labels
        start = labels['first_gate']
        end_code = machine.composition['protected_code_extent'][0] + len(machine.code)
        generated = [event for event in machine.constructor_accesses[accesses:]
                     if start <= event[1] < end_code]
        self.assertTrue(generated)
        self.assertTrue(all(first <= address and address + size <= native_sp
                            for _, _, address, size in generated))

    def test_each_raw_error_stops_both_constructors_with_ambiguous_ownership_unchanged(self):
        for constructor, gate, frame in ROUTES:
            for status in (1, 22, 0x82, MASK):
                for held in (False, True):
                    with self.subTest(constructor=hex(constructor), status=status, held=held):
                        m = self.machine(acquire=status,
                                         registry_acquire_failure_holds=held)
                        marks = self.watch_gate(m, gate)
                        result, raw = m.construct(constructor)
                        self.assertEqual((result, raw), (m.created_engines[0], status))
                        self.assertNotEqual(result, 0)
                        self.assert_only_retained_frames_after_stop(m, marks, frame)
                        self.assertEqual(m.native_continuations, [])
                        self.assertNotIn(NAME_POSTWORK, m.calls)
                        self.assertEqual(m.registry_held, held)
                        self.assertEqual([(event[0], event[1]) for event in m.raw_events],
                                         [(RAW_LOCK, REGISTRY_MUTEX)])
                        self.assertEqual(m.allocations, [])
                        self.assertEqual(m.freed, [])
                        self.assertEqual(m.lifecycle_header(), (0, 0, 0, 0))

    def test_every_nonzero_status_stops_without_v1_or_native_engine_decision_reads(self):
        for constructor, gate, frame in ROUTES:
            for status in (1, 22, 0x82, 0x7FFFFFFF, 0x80000000, MASK):
                for poison in (0, MASK):
                    with self.subTest(constructor=hex(constructor), status=status, poison=poison):
                        m = self.machine()

                        def mutate(current):
                            current.r[2], current.r[3] = status, poison

                        marks = self.watch_gate(m, gate, mutate)
                        result, raw = m.construct(constructor)
                        self.assertEqual((result, raw), (m.created_engines[0], poison))
                        self.assert_only_retained_frames_after_stop(m, marks, frame)
                        self.assertEqual(m.native_continuations, [])
                        self.assertNotIn(NAME_POSTWORK, m.calls)

    def test_wrong_ra_or_u_forwards_legacy_work_even_with_nonzero_status(self):
        for constructor, gate, frame in ROUTES:
            for register, values in ((31, (0, core.HOOKS[gate][0] + 4, MASK)),
                                      (17, (0, CONTROLLER + 4, MASK))):
                for value in values:
                    with self.subTest(constructor=hex(constructor), register=register, value=value):
                        m = self.machine(acquire=22)

                        def mutate(current):
                            current.r[register] = value

                        self.watch_gate(m, gate, mutate)
                        result, _ = m.construct(constructor)
                        self.assertEqual(result, m.created_engines[0])
                        self.assertEqual(len(m.native_continuations), 1)
                        self.assertIn(NAME_POSTWORK, m.calls)
                        self.assertNotIn(m.constructor_continuation_gate_labels[gate + '_stopped'],
                                         m.trace)
                        expected_u = value if register == 17 else CONTROLLER
                        self.assertEqual(m.native_continuations[0][1][0], expected_u)

    def test_masked_raw_release_error_still_admits_UI_with_no_release_certificate(self):
        for constructor, gate, frame in ROUTES:
            for status in (1, 22, 0x82, MASK):
                for released in (False, True):
                    with self.subTest(constructor=hex(constructor), status=status,
                                      released=released):
                        m = self.machine(release=status,
                                         registry_release_failure_releases=released)
                        result, _ = m.construct(constructor)
                        self.assertEqual(result, m.created_engines[0])
                        self.assertEqual(len(m.native_continuations), 1)
                        self.assertIn(NAME_POSTWORK, m.calls)
                        self.assertEqual(m.registry_held, not released)
                        self.assertEqual(
                            [(event[0], event[1], event[-1]) for event in m.raw_events],
                            [(RAW_LOCK, REGISTRY_MUTEX, 0),
                             (RAW_LOCK, PAINT_MUTEX, 0),
                             (RAW_UNLOCK, PAINT_MUTEX, 0),
                             (RAW_UNLOCK, REGISTRY_MUTEX, status)])
                        self.assertEqual(m.lifecycle_header(), (1, 0, 0, 0))

    def test_missing_acquire_gate_allows_masked_raw_error_and_native_UI(self):
        for constructor, gate, frame in ROUTES:
            with self.subTest(constructor=hex(constructor)):
                m = self.machine(acquire=22)
                m.remove_pair(acquire.HOOKS['register_gate'][0])
                result, _ = m.construct(constructor)
                self.assertEqual(result, m.created_engines[0])
                self.assertEqual(len(m.allocations), 1)
                self.assertEqual(len(m.native_continuations), 1)
                self.assertIn(NAME_POSTWORK, m.calls)
                self.assertEqual(m.lifecycle_header(), (0, 0, 0, 0))

    def test_missing_continuation_hook_leaves_existing_ignored_error_work(self):
        for constructor, gate, frame in ROUTES:
            with self.subTest(constructor=hex(constructor)):
                m = self.machine(acquire=22)
                m.remove_pair(core.HOOKS[gate][0])
                result, _ = m.construct(constructor)
                self.assertEqual(result, m.created_engines[0])
                self.assertEqual(m.allocations, [])
                self.assertEqual(len(m.native_continuations), 1)
                self.assertIn(NAME_POSTWORK, m.calls)

    def test_first_skipped_registration_resource_and_validation_NULL_faults_remain(self):
        for options in ({'resource_missing': True}, {'validation_result': 0}):
            with self.subTest(options=options):
                m = self.machine(**options)
                with self.assertRaisesRegex(AssertionError, r'^unmapped access 0x0, size 4$'):
                    m.construct(FIRST)
                self.assertEqual(m.native_entries, [])
                self.assertEqual(m.engine_entries, [])
                self.assertEqual(len(m.native_continuations), 1)
                self.assertIn(0x43AEA0, m.trace)
                self.assertIn(('read', 0x43AEA0, 0, 4), m.constructor_accesses)
                self.assertNotIn(m.constructor_continuation_gate_labels['first_gate_stopped'],
                                 m.trace)

    def test_both_engine_NULL_legacy_paths_still_reach_name_dereference_fault(self):
        for constructor, gate, frame in ROUTES:
            with self.subTest(constructor=hex(constructor)):
                m = self.machine(fail_engine_allocation=True)
                with self.assertRaisesRegex(AssertionError, r'^unmapped access 0x0, size 4$'):
                    m.construct(constructor)
                self.assertEqual(m.created_engines, [0])
                self.assertEqual(m.native_entries, [])
                self.assertEqual(len(m.native_continuations), 1)
                fault_pc = 0x43AEA0 if constructor == FIRST else 0x43B044
                self.assertIn(fault_pc, m.trace)
                self.assertIn(('read', fault_pc, 0, 4), m.constructor_accesses)
                self.assertNotIn(m.constructor_continuation_gate_labels[gate + '_stopped'],
                                 m.trace)

    def test_second_missing_resource_or_validation_keeps_native_safe_NULL_return(self):
        for options in ({'resource_missing': True}, {'validation_result': 0}):
            with self.subTest(options=options):
                m = self.machine(**options)
                self.assertEqual(m.construct(SECOND)[0], 0)
                self.assertEqual(m.native_entries, [])
                self.assertEqual(m.engine_entries, [])
                self.assertEqual(m.native_continuations, [])
                self.assertNotIn(m.constructor_continuation_gate_labels['second_gate'], m.trace)
                self.assertEqual(m.r[29], STACK)


if __name__ == '__main__':
    unittest.main()
