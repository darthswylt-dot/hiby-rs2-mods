#!/usr/bin/env python3
"""Bound one refresh return stop and expose its partial-activation limits.

Controlled entries use genuine retained mapped caller/private frames. They
are not APIs for fabricated/unmapped-stack recovery. Actual raw errors pass
through the existing delete and destructor gates; the explicit bounded
destructor substitute and native refresh epilogue are the same for all cases.
No higher caller, callback quarantine, rollback, retry or free authority is
implemented or certified by stopping this single local continuation.
"""

import unittest

import reveal_registry_acquire_gate_mips as acquire
import test_reveal_refresh_failure_gate_mips as fixture
from test_reveal_refresh_failure_gate_mips import (
    CONTROLLER, RAW_LOCK, RAW_UNLOCK, REGISTRY_MUTEX, OUTER_VIEW, RETURN, MASK,
    RECREATE, OFFSET_SETTER, core)


class RefreshFailureGateAdversarialTests(unittest.TestCase):
    setUpClass = classmethod(fixture.RefreshFailureGateTests.setUpClass.__func__)
    machine = fixture.RefreshFailureGateTests.machine
    watch_gate = fixture.RefreshFailureGateTests.watch_gate
    assert_native_unwind = fixture.RefreshFailureGateTests.assert_native_unwind
    assert_stopped = fixture.RefreshFailureGateTests.assert_stopped
    assert_forwarded_boundary = fixture.RefreshFailureGateTests.assert_forwarded_boundary

    def test_each_acquisition_error_stops_both_flags_held_or_unheld(self):
        for status in (1, 22, 0x82, MASK):
            for held in (False, True):
                for flag in (0, 1):
                    with self.subTest(status=status, held=held, flag=flag):
                        m = self.machine(acquire=status, registry_acquire_failure_holds=held)
                        context = m.seed_refresh(flag=flag)
                        m.clear_events()
                        marks, snapshots = self.watch_gate(m)
                        self.assertEqual(m.run_refresh_slice(), (MASK, status))
                        self.assert_stopped(m, context, marks, snapshots, raw=status)
                        self.assertEqual(m.registry_held, held)
                        self.assertEqual([(event[0], event[1], event[-1]) for event in m.raw_events],
                                         [(RAW_LOCK, REGISTRY_MUTEX, status)])
                        self.assertEqual(m.resource_entries, [])
                        self.assertEqual(m.freed, [])

    def test_each_release_error_stops_both_flags_held_or_unheld(self):
        for status in (1, 22, 0x82, MASK):
            for released in (False, True):
                for flag in (0, 1):
                    with self.subTest(status=status, released=released, flag=flag):
                        m = self.machine(release=status,
                                         registry_release_failure_releases=released)
                        context = m.seed_refresh(flag=flag)
                        m.clear_events()
                        marks, snapshots = self.watch_gate(m)
                        self.assertEqual(m.run_refresh_slice(), (MASK, status))
                        self.assert_stopped(m, context, marks, snapshots, raw=status)
                        self.assertEqual(m.registry_held, not released)
                        self.assertEqual([(event[0], event[1], event[-1]) for event in m.raw_events],
                                         [(RAW_LOCK, REGISTRY_MUTEX, 0),
                                          (RAW_UNLOCK, REGISTRY_MUTEX, status)])
                        self.assertEqual(m.resource_entries, [])

    def test_every_nonzero_v0_stops_without_interpreting_v1_or_s4(self):
        cases = ((1, 0), (22, MASK), (0x82, 1), (MASK, 0x12345678),
                 (0x80000000, 22), (0x12345678, 0x80000001))
        for result, diagnostic in cases:
            for flag in (0, 1):
                with self.subTest(result=result, diagnostic=diagnostic, flag=flag):
                    m = self.machine()
                    marks, snapshots = self.watch_gate(m)
                    self.assertEqual(m.invoke_refresh_gate(result=result, diagnostic=diagnostic,
                                                         flag=flag), (result, diagnostic))
                    self.assert_stopped(m, m.refresh_context, marks, snapshots,
                                        result=result, raw=diagnostic)
                    self.assertEqual(m.calls, [])

    def test_zero_v0_and_any_v1_poison_replay_original_branch_once(self):
        for diagnostic in (0, 1, 22, 0x82, MASK, 0x80000000):
            for flag in (0, 1):
                with self.subTest(diagnostic=diagnostic, flag=flag):
                    m, old = self.machine(), self.machine()
                    old.remove_pair(core.HOOKS['gate'][0])
                    _, snapshots = self.watch_gate(m)
                    self.assertEqual(m.invoke_refresh_gate(result=0, diagnostic=diagnostic,
                                                         flag=flag),
                                     old.invoke_refresh_gate(result=0, diagnostic=diagnostic,
                                                             flag=flag))
                    self.assert_forwarded_boundary(m, m.refresh_context, snapshots)
                    self.assertEqual((m.r, m.hi, m.lo), (old.r, old.hi, old.lo))
                    self.assertEqual((m.r[2], m.r[3]), (1, diagnostic))
                    self.assertEqual(m.calls, [])

    def test_wrong_saved_u_or_ra_preserves_legacy_branch_and_architecture(self):
        foreign = CONTROLLER + 0x1000
        for controller, return_pc in ((foreign, 0x4ACD94), (CONTROLLER, RETURN),
                                      (CONTROLLER, 0x4ACD98)):
            for flag in (0, 1):
                with self.subTest(controller=controller, return_pc=return_pc, flag=flag):
                    m, old = self.machine(), self.machine()
                    old.remove_pair(core.HOOKS['gate'][0])
                    _, snapshots = self.watch_gate(m)
                    expected = old.invoke_refresh_gate(result=MASK, diagnostic=22, flag=flag,
                                                      controller=controller, return_pc=return_pc)
                    self.assertEqual(m.invoke_refresh_gate(result=MASK, diagnostic=22, flag=flag,
                                                          controller=controller, return_pc=return_pc),
                                     expected)
                    self.assert_forwarded_boundary(m, m.refresh_context, snapshots)
                    self.assertEqual((m.r, m.hi, m.lo), (old.r, old.hi, old.lo))
                    self.assertEqual((m.r[2], m.r[3]), (1, 22))
                    self.assertEqual(m.calls, [])

    def test_missing_refresh_hook_overwrites_actual_error_with_one_then_recreates(self):
        for option in ('acquire', 'release'):
            with self.subTest(option=option):
                m = self.machine(**{option: 22})
                context = m.seed_refresh(flag=0)
                m.remove_pair(core.HOOKS['gate'][0])
                m.clear_events()
                returned = []

                def observe(current, pc):
                    if pc == core.HOOKS['gate'][0]:
                        returned.append((tuple(current.r[2:4]), current.r[29], current.r[31]))

                m.on_instruction = observe
                self.assertEqual(m.run_refresh_slice(), (1, 22))
                self.assertEqual(returned, [((MASK, 22), context['sp'], 0x4ACD94)])
                self.assertEqual(m.refresh_delay_effects, [(0x4ACD94, MASK)])
                self.assertEqual(m.recreate_entries, [])
                m.run_at(core.FALLTHROUGH, context['caller'])
                self.assert_native_unwind(m, context)
                self.assertEqual(len(m.recreate_entries), 1)
                self.assertEqual(m.calls.count(RECREATE), 1)
                self.assertEqual(m.calls.count(OFFSET_SETTER), 0)
                self.assertNotIn(m.refresh_failure_gate_labels['gate'], m.trace)
                self.assertEqual(m.raw_events[-1][-1], 22)

    def test_missing_delete_release_completion_masks_error_before_this_gate(self):
        m = self.machine(release=22, registry_release_failure_releases=False)
        context = m.seed_refresh(flag=0)
        m.restore_legacy_delete_release_phase('complete')
        m.clear_events()
        _, snapshots = self.watch_gate(m)
        self.assertEqual(m.run_refresh_slice()[0], 1)
        self.assertEqual(snapshots['gate'][0][2], 0)
        self.assert_forwarded_boundary(m, context, snapshots)
        self.assertTrue(m.registry_held)
        self.assertEqual(m.raw_events[-1][-1], 22)
        self.assertEqual(len(m.resource_entries), 1)
        m.run_at(core.FALLTHROUGH, context['caller'])
        self.assertEqual(len(m.recreate_entries), 1)
        self.assert_native_unwind(m, context)

    def test_unknown_delete_release_diagnostic_zero_is_preserved_through_caller_stop(self):
        for flag in (0, 1):
            with self.subTest(flag=flag):
                m = self.machine(release=22)
                context = m.seed_refresh(flag=flag)
                m.restore_legacy_delete_release_phase('raw_release_return')
                m.clear_events()
                marks, snapshots = self.watch_gate(m)
                self.assertEqual(m.run_refresh_slice(), (MASK, 0))
                self.assert_stopped(m, context, marks, snapshots, raw=0)
                self.assertEqual(m.raw_events[-1][-1], 22)
                self.assertIn(m.delete_release_gate_labels['complete_denied'], m.trace)
                self.assertEqual(m.resource_entries, [])

    def test_missing_acquire_gate_allows_prior_unlink_despite_later_release_zero(self):
        m = self.machine()
        self.assertEqual(m.register(), 0)
        node = m.allocations[-1]
        m.acquire = 22
        context = m.seed_refresh(flag=0)
        m.remove_pair(acquire.HOOKS['delete_gate'][0])
        m.clear_events()
        _, snapshots = self.watch_gate(m)
        m.run_refresh_slice()
        self.assert_forwarded_boundary(m, context, snapshots)
        self.assertEqual([(event[0], event[-1]) for event in m.raw_events],
                         [(RAW_LOCK, 22), (RAW_UNLOCK, 0)])
        self.assertIn(node, m.freed)
        self.assertEqual(m.words_at(CONTROLLER + 0x34, 2), (CONTROLLER + 0x34,) * 2)
        self.assertNotIn(m.acquire_gate_labels['delete_gate'], m.trace)
        self.assertEqual(len(m.resource_entries), 1)

    def test_scoped_stop_does_not_consult_mutated_view_or_resource_fields(self):
        m = self.machine()
        m.put(CONTROLLER + 0x24, MASK, 4)
        m.put(OUTER_VIEW + 0xCC, MASK, 4)
        marks, snapshots = self.watch_gate(m)
        self.assertEqual(m.invoke_refresh_gate(result=MASK, diagnostic=0x82), (MASK, 0x82))
        self.assert_stopped(m, m.refresh_context, marks, snapshots, raw=0x82)
        self.assertEqual(m.calls, [])
        self.assertFalse(any(address in (CONTROLLER + 0x24, OUTER_VIEW + 0xCC)
                             for address, _ in m.reads))

    def test_new_same_frame_invocation_uses_its_actual_error_after_prior_success(self):
        m = self.machine()
        first = m.seed_refresh(flag=1)
        m.clear_events()
        self.assertEqual(m.run_refresh_slice()[0], 1)
        self.assertEqual(len(m.resource_entries), 1)
        m.acquire = 22
        context = m.seed_refresh(flag=0)
        m.clear_events()
        marks, snapshots = self.watch_gate(m)
        self.assertEqual(m.run_refresh_slice(), (MASK, 22))
        self.assert_stopped(m, context, marks, snapshots)
        self.assertEqual(first['sp'], context['sp'])
        self.assertEqual(m.resource_entries, [])
        self.assertEqual([(event[0], event[-1]) for event in m.raw_events], [(RAW_LOCK, 22)])


if __name__ == '__main__':
    unittest.main()
