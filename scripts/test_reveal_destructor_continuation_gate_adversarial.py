#!/usr/bin/env python3
"""Counterexamples delimit one direct destructor continuation stop.

Controlled architectural mutations use valid retained native/private frames.
They supply neither frame authentication nor malformed-stack recovery. The
bounded actual slice cannot replay earlier worker/list/cache/purge effects,
isolate49 outer destructor callers, roll back graphs or authorize later frees.
In particular, constructor-only release propagation leaves native delete's
masked release zero unchanged, and a missing earlier acquisition gate cannot
be repaired by checking its later zero result.
"""

import unittest

import reveal_registry_acquire_gate_mips as acquire
import test_reveal_destructor_continuation_gate_mips as fixture
from test_reveal_destructor_continuation_gate_mips import (
    DestructorContinuationGateMachine, CONTROLLER, REGISTRY_MUTEX,
    NAME, RAW_LOCK, RAW_UNLOCK, STACK, RETURN, MASK, core)


class DestructorContinuationGateAdversarialTests(unittest.TestCase):
    setUpClass = classmethod(fixture.DestructorContinuationGateTests.setUpClass.__func__)
    machine = fixture.DestructorContinuationGateTests.machine
    watch_gate = fixture.DestructorContinuationGateTests.watch_gate
    assert_stopped = fixture.DestructorContinuationGateTests.assert_stopped
    assert_forwarded = fixture.DestructorContinuationGateTests.assert_forwarded

    def test_each_actual_delete_acquisition_error_stops_held_or_unheld_without_later_work(self):
        for status in (1, 22, 0x82, MASK):
            for held in (False, True):
                with self.subTest(status=status, held=held):
                    m = self.machine(acquire=status, registry_acquire_failure_holds=held)
                    context = m.seed_destructor()
                    m.clear_events()
                    marks, snapshots = self.watch_gate(m)
                    self.assertEqual(m.run_destructor_slice(), (MASK, status))
                    self.assert_stopped(m, context, marks, snapshots, status)
                    self.assertEqual(m.registry_held, held)
                    self.assertEqual([(event[0], event[1], event[-1])
                                      for event in m.raw_events],
                                     [(RAW_LOCK, REGISTRY_MUTEX, status)])
                    self.assertEqual(m.lifecycle_requests, [])
                    self.assertEqual(m.freed, [])

    def test_missing_destructor_hook_continues_resource_cleanup_after_real_delete_denial(self):
        m = self.machine(acquire=22)
        context = m.seed_destructor()
        m.remove_pair(core.HOOKS['gate'][0])
        m.clear_events()
        m.run_destructor_slice()
        self.assertIn(m.acquire_gate_labels['delete_gate_denied'], m.trace)
        self.assertNotIn(m.destructor_continuation_gate_labels['gate'], m.trace)
        self.assertEqual(len(m.resource_deletions), 1)
        self.assertEqual(m.resource_entries[0][0][2:4], [MASK, 22])
        self.assertEqual(m.resource_deletions[0][1][:2],
                         (m.peek(CONTROLLER + 0x24), NAME))
        self.assertEqual(m.resource_deletions[0][2:4],
                         (context['sp'], core.CONTINUATION))
        self.assertIn(('read', 0x493F4C, CONTROLLER + 0x24, 4),
                      m.constructor_accesses)
        self.assertEqual([(event[0], event[-1]) for event in m.raw_events],
                         [(RAW_LOCK, 22)])

    def test_every_classified_nonzero_v0_stops_without_interpreting_v1(self):
        for result in (1, 22, 0x82, MASK, 0x80000000, 0x12345678):
            for diagnostic in (0, 1, MASK):
                with self.subTest(result=result, diagnostic=diagnostic):
                    m = self.machine()
                    _, snapshots = self.watch_gate(m)
                    self.assertEqual(m.invoke_destructor_gate(
                        result=result, diagnostic=diagnostic), (result, diagnostic))
                    self.assertEqual(snapshots['gate'], snapshots['epilogue'])
                    self.assertEqual(m.resource_deletions, [])
                    self.assertEqual(m.calls, [])
                    self.assertEqual((m.r[29], m.r[31]), (STACK, RETURN))

    def test_wrong_saved_u_or_ra_forwards_legacy_nonzero_and_preserves_architecture(self):
        foreign = CONTROLLER + 0x1000
        for controller, caller in ((foreign, core.HOOKS['gate'][0]),
                                   (CONTROLLER, RETURN),
                                   (CONTROLLER, core.HOOKS['gate'][0] + 4)):
            with self.subTest(controller=controller, caller=caller):
                m = self.machine()
                if controller == foreign:
                    m.map(foreign, core.CONTROLLER_BYTES)
                    m.put(foreign + 0x24, 0x1234ABCD, 4)
                _, snapshots = self.watch_gate(m)
                m.invoke_destructor_gate(controller=controller, caller=caller)
                self.assert_forwarded(m, m.destructor_context, snapshots)
                self.assertEqual(m.resource_entries[0][0][2:4], [MASK, 22])

    def test_zero_v0_with_any_v1_poison_forwards_and_does_not_certify_cleanup(self):
        for diagnostic in (0, 1, 22, 0x82, MASK, 0x80000000):
            with self.subTest(diagnostic=diagnostic):
                m = self.machine()
                _, snapshots = self.watch_gate(m)
                m.invoke_destructor_gate(result=0, diagnostic=diagnostic)
                self.assert_forwarded(m, m.destructor_context, snapshots)
                self.assertEqual(m.resource_entries[0][0][2:4], [0, diagnostic])

    def test_actual_delete_zero_ignores_v1_poison_at_its_real_destructor_return(self):
        for poison in (1, MASK):
            with self.subTest(poison=poison):
                m = self.machine()
                context = m.seed_destructor()
                m.clear_events()
                _, snapshots = self.watch_gate(m)
                observe = m.on_instruction

                def poison_return(current, pc):
                    if pc == current.destructor_continuation_gate_labels['gate']:
                        self.assertEqual(current.r[2], 0)
                        current.r[3] = poison
                    observe(current, pc)

                m.on_instruction = poison_return
                m.run_destructor_slice()
                self.assert_forwarded(m, context, snapshots)
                self.assertEqual(m.resource_entries[0][0][2:4], [0, poison])

    def test_masked_actual_delete_release_error_still_forwards_held_or_unheld_counterexample(self):
        for released in (False, True):
            with self.subTest(released=released):
                m = self.machine(release=22, registry_release_failure_releases=released)
                context = m.seed_destructor()
                m.clear_events()
                _, snapshots = self.watch_gate(m)
                m.run_destructor_slice()
                self.assertEqual(snapshots['gate'][0][2], 0)
                self.assert_forwarded(m, context, snapshots)
                self.assertEqual([(event[0], event[1], event[-1])
                                  for event in m.raw_events],
                                 [(RAW_LOCK, REGISTRY_MUTEX, 0),
                                  (RAW_UNLOCK, REGISTRY_MUTEX, 22)])
                self.assertEqual(m.registry_held, not released)
                self.assertEqual(m.resource_deletions[0][-1], not released)
                # The earlier raw-release gate scopes its completion check to
                # constructor registration, not this native name-delete body.
                self.assertNotIn(m.registry_release_gate_labels['complete'], m.trace)
                self.assertEqual(m.cleanup_services, [])

    def test_missing_earlier_acquisition_gate_cannot_be_repaired_by_later_zero_result(self):
        m = self.machine()
        self.assertEqual(m.register(), 0)
        node = m.allocations[-1]
        m.acquire = 22
        context = m.seed_destructor()
        m.remove_pair(acquire.HOOKS['delete_gate'][0])
        m.clear_events()
        _, snapshots = self.watch_gate(m)
        m.run_destructor_slice()
        self.assertNotIn(m.acquire_gate_labels['delete_gate'], m.trace)
        self.assertEqual(snapshots['gate'][0][2], 0)
        self.assert_forwarded(m, context, snapshots)
        self.assertEqual([(event[0], event[1], event[-1]) for event in m.raw_events],
                         [(RAW_LOCK, REGISTRY_MUTEX, 22),
                          (RAW_UNLOCK, REGISTRY_MUTEX, 0)])
        self.assertIn(('read', acquire.HOOKS['delete_gate'][0],
                       CONTROLLER + 0x34, 4), m.constructor_accesses)
        self.assertIn(node, m.freed)
        self.assertEqual(m.words_at(CONTROLLER + 0x34, 2),
                         (CONTROLLER + 0x34,) * 2)
        self.assertEqual(len(m.resource_deletions), 1)
        self.assertFalse(m.registry_held)


if __name__ == '__main__':
    unittest.main()
