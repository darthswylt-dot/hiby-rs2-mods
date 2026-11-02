#!/usr/bin/env python3
"""Check quarantine races, fresh owner stamps and missing-hook limits.

Q/H sharing is explicit and simultaneous stacks are disjoint. Deterministic
instruction interleavings and chosen service ownership are not a scheduler or
memory-order proof. Arbitrary missing redirects remain unsafe; no test grants
retry, reset, free or release permission for a quarantined native object.
"""

import unittest

import test_reveal_dialog_retention_gate_mips as fixture
from test_reveal_dialog_retention_gate_mips import (
    core, GUARD, GLOBAL, LIST, DIALOG, OPERATION, DIALOG_MUTEX,
    OUTERS, RAW_LOCK, RAW_UNLOCK, STACK, SECOND_STACK, RETURN, MASK,
    NAME, GET, guard_instruction)


class DialogRetentionGateAdversarialTests(unittest.TestCase):
    setUpClass = classmethod(fixture.DialogRetentionGateTests.setUpClass.__func__)
    machine = fixture.DialogRetentionGateTests.machine
    assert_retained = fixture.DialogRetentionGateTests.assert_retained
    assert_denied_before_objects = fixture.DialogRetentionGateTests.assert_denied_before_objects

    def test_entry_stamp_occupies_padding_and_preserves_all_registers_before_real_prologue(self):
        m = self.machine()
        before, hi, lo = m.r.copy(), m.hi, m.lo
        before[4], before[29], before[31] = NAME, STACK - 48, RETURN
        m.clear_events()
        m.run_outer('poll', stop=0x47CC28)
        self.assertEqual((m.r, m.hi, m.lo), (before, hi, lo))
        self.assertEqual(m.words_at(STACK - 48 + 0x10, 1),
                         (int.from_bytes(b'QOWN', 'little'),))
        self.assertEqual(m.guard_value(), core.BUSY)
        self.assertEqual(m.calls, [])

    def test_shared_entry_conflict_invalidates_old_reservation_and_only_one_claim_survives(self):
        first, second = self.machine(), self.machine()
        second.attach_shared(first)
        interleaved = []

        def observe(current, pc):
            if not interleaved and guard_instruction(current, pc, 0x38):
                interleaved.append(pc)
                second.clear_events()
                second.run_outer('poll', stack=SECOND_STACK, stop=0x47CC28)

        first.on_instruction = observe
        first.clear_events()
        first.run_outer('poll')
        self.assertEqual(len(interleaved), 1)
        self.assert_denied_before_objects(first)
        self.assertEqual(second.guard_value(), core.BUSY)
        self.assertEqual(second.r[29], SECOND_STACK - 48)
        self.assertTrue(any(event[0] == 'sc' and not event[3]
                            for event in first.guard_atomic_events))

    def test_quarantine_store_between_exit_ll_sc_cannot_be_overwritten_with_ready(self):
        owner, fault = self.machine(), self.machine()
        fault.attach_shared(owner)
        owner.configure_outer(count=0)
        injected = []

        def observe(current, pc):
            if (not injected and current.list_events and current.guard_value() == core.BUSY
                    and guard_instruction(current, pc, 0x38)):
                injected.append(len(current.writes))
                fault.put(GUARD, core.QUARANTINED, 4)

        owner.on_instruction = observe
        owner.clear_events()
        owner.run_outer('poll')
        self.assertEqual(len(injected), 1)
        self.assertEqual(owner.guard_value(), core.QUARANTINED)
        self.assertFalse(any(address == GUARD and value == core.READY
                             for address, value, size in owner.writes[injected[0]:]))
        self.assertTrue(any(event[0] == 'sc' and not event[3]
                            for event in owner.guard_atomic_events))

    def test_entry_spurious_sc_failures_are_bounded_without_claiming_or_reading_objects(self):
        for kind in OUTERS:
            with self.subTest(kind=kind):
                m = self.machine(retry_limit=2)
                m.guard_sc_failures = 2
                m.clear_events()
                m.run_outer(kind)
                self.assert_denied_before_objects(m)
                self.assertEqual(m.guard_value(), core.READY)
                self.assertEqual(sum(event[0] == 'sc' for event in m.guard_atomic_events), 2)

    def test_exit_retry_exhaustion_quarantines_instead_of_releasing_busy(self):
        for kind in OUTERS:
            with self.subTest(kind=kind):
                m = self.machine(retry_limit=2)
                m.configure_outer(count=0)

                def observe(current, pc):
                    if pc == current.dialog_retention_gate_labels[kind + '_leave']:
                        current.guard_sc_failures = 2

                m.on_instruction = observe
                m.clear_events()
                m.run_outer(kind)
                self.assertEqual(m.guard_value(), core.QUARANTINED)
                self.assertEqual((m.r[29], m.r[31]), (STACK, RETURN))
                self.assertEqual(m.freed, [])

    def test_missing_owner_stamp_never_releases_another_busy_owner(self):
        for kind in OUTERS:
            with self.subTest(kind=kind):
                m = self.machine()
                m.configure_outer(count=0)

                def observe(current, pc):
                    if pc == OUTERS[kind]['tail']:
                        current.put(current.r[29] + 0x10, 0, 4)

                m.on_instruction = observe
                m.clear_events()
                m.run_outer(kind)
                self.assertEqual(m.guard_value(), core.BUSY)
                self.assertEqual((m.r[29], m.r[31]), (STACK, RETURN))

    def test_quarantined_known_entries_do_not_dereference_poisoned_global_or_object_fields(self):
        m = self.machine()
        m.put(GUARD, core.QUARANTINED, 4)
        m.put(GLOBAL, 0xDEAD0000, 4)
        m.put(DIALOG + 0x6C, 0xDEAD0004, 4)
        for kind in OUTERS:
            m.clear_events()
            m.run_outer(kind)
            self.assert_denied_before_objects(m)
            self.assertEqual(m.guard_value(), core.QUARANTINED)

    def test_callback_guard_suppresses_old_raw_release_even_for_foreign_dialog_caller(self):
        m = self.machine(acquire=22)
        context = m.seed_dialog(callback='first')
        m.clear_events()
        self.assertEqual(m.run_dialog_failure(), (MASK, 22))
        self.assertEqual((m.r[29], m.r[31]), (context['caller_stack'], RETURN))
        self.assertEqual(m.guard_value(), core.QUARANTINED)
        self.assertEqual(m.direct_release_entries, [])
        self.assertTrue(m.mutex_held[DIALOG_MUTEX])
        self.assertEqual(m.freed, [])

    def test_missing_entry_redirect_can_reach_objects_while_guard_is_busy(self):
        m = self.machine()
        m.put(GUARD, core.BUSY, 4)
        m.restore_retention_hook(OUTERS['poll']['entry'])
        m.clear_events()
        m.run_outer('poll')
        self.assertTrue(m.list_events)
        self.assertEqual(m.freed.count(DIALOG), 1)
        self.assertEqual(m.guard_value(), core.BUSY)

    def test_missing_callback_intercept_restores_conditional_release_and_outer_free_counterexample(self):
        m = self.machine(acquire=22)
        m.restore_retention_hook(m.dialog_failure_gate_labels['error_return'])
        m.clear_events()
        m.run_outer('poll')
        self.assertEqual(len(m.direct_release_entries), 1)
        self.assertEqual(m.freed.count(DIALOG), 1)
        self.assertEqual(m.guard_value(), core.READY)

    def test_missing_acquisition_denial_intercept_restores_outer_free_counterexample(self):
        m = self.machine(dialog_acquire=22)
        m.restore_retention_hook(m.dialog_acquire_gate_labels['gate_denied'])
        m.clear_events()
        m.run_outer('close')
        self.assertEqual(m.freed.count(DIALOG), 1)
        self.assertEqual(m.guard_value(), core.READY)
        self.assertEqual(m.direct_release_entries, [])

    def test_private_writes_do_not_invalidate_q_reservation_but_shared_q_write_does(self):
        m, other = self.machine(), self.machine()
        other.attach_shared(m)
        m.r[8], m.r[9] = GUARD, 0
        m.plain(b := (0x30 << 26) | (8 << 21) | (9 << 16))
        m.put(STACK - 0x100, 123, 4)
        m.r[9] = core.BUSY
        m.plain((0x38 << 26) | (8 << 21) | (9 << 16))
        self.assertEqual(m.r[9], 1)
        m.plain(b)
        other.put(GUARD, core.QUARANTINED, 4)
        m.r[9] = core.READY
        m.plain((0x38 << 26) | (8 << 21) | (9 << 16))
        self.assertEqual(m.r[9], 0)
        self.assertEqual(m.guard_value(), core.QUARANTINED)

    def test_retention_helpers_read_only_live_frames_and_guard_after_classified_failure(self):
        for kind in OUTERS:
            for denied in (False, True):
                with self.subTest(kind=kind, denied=denied):
                    m = self.machine(**({'dialog_acquire': 22} if denied else {'acquire': 22}))
                    marks, dialog_ends = [], []

                    def observe(current, pc):
                        name = 'deny_entry' if denied else 'callback_entry'
                        if pc == current.dialog_retention_gate_labels[name]:
                            marks.append((len(current.reads), len(current.calls),
                                          current.hi, current.lo,
                                          current.r[29] + (core.FRAME if denied else 0)))
                        if pc == core.DIALOG_EPILOGUE and marks:
                            dialog_ends.append(len(current.reads))

                    m.on_instruction = observe
                    m.clear_events()
                    m.run_outer(kind)
                    self.assert_retained(m, kind)
                    self.assertEqual(len(marks), 1)
                    reads, calls, hi, lo, dialog_sp = marks[0]
                    self.assertEqual(m.calls[calls:], [])
                    self.assertEqual((m.hi, m.lo), (hi, lo))
                    self.assertTrue(all(address == GUARD or STACK - 0x4000 <= address
                                        and address + size <= STACK
                                        for address, size in m.reads[reads:]))
                    self.assertEqual(len(dialog_ends), 1)
                    # After D unwinds, an O-tail private save may legitimately
                    # reuse this address. Check M nonuse while D is still live.
                    self.assertNotIn((dialog_sp + 0x14, 4), m.reads[reads:dialog_ends[0]])

    def test_facade_busy_and_quarantine_fences_run_before_flagsetter_or_mutex_access(self):
        for state in (core.BUSY, core.QUARANTINED):
            with self.subTest(state=state):
                m = self.machine()
                m.put(GUARD, state, 4)
                m.clear_events()
                m.run_facade()
                self.assert_denied_before_objects(m)
                self.assertEqual(m.guard_value(), state)
                self.assertEqual(m.facade_events, [])
                self.assertEqual(m.dialog_raw_events, [])


if __name__ == '__main__':
    unittest.main()
