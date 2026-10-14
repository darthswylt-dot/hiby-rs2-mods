"""Run grouped entry/writer/exit hooks from the actual intermediate ELF."""
import hashlib
import unittest

import build_reveal_guard_stage as stage
from folderfollow_reveal_guard_mips import FAULT, WRITER_MASK
from test_reveal_guard_stage import StageMachine, SOURCE, PLAYER, ITEM, STACK, RETURN
from verify_reveal_guard_stage import verify


class GroupedStageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = SOURCE.read_bytes()
        cls.image, cls.meta = stage.build(cls.source, grouped=True)

    def machine(self):
        return StageMachine(self.image, self.meta)

    def word(self, m, offset):
        return m.get(m.state + offset, 4)

    def enter(self, m):
        entry_sp, original_s0 = m.r[29], m.r[16]
        before = (m.r.copy(), m.hi, m.lo)
        m.site('scope_entry')
        expected = before[0]
        expected[29] -= stage.GENERAL_FRAME
        self.assertEqual((m.r, m.hi, m.lo), (expected, before[1], before[2]))
        self.assertEqual(m.get(m.r[29] + 0x1DA8, 4), original_s0)
        # The remaining ORIGINAL prologue saves RA/FP before inner calls.
        m.put(m.r[29] + 0x1DCC, RETURN, 4)
        m.put(m.r[29] + 0x1DC8, 0x12345678, 4)
        m.r[16] = PLAYER
        self.assertEqual(m.r[29], entry_sp - stage.GENERAL_FRAME)

    def copy(self, m, name='general'):
        m.r[4:7], m.r[2], m.r[16] = [ITEM, 0x1800000, 0xA88], 1, PLAYER
        m.callback = lambda target: m.hostile_result(ITEM)
        m.site(name)

    def prepare(self, m, return_pc=0x42CD40):
        m.r[29] -= 0x20
        m.put(m.r[29] + 0x1C, return_pc, 4)
        m.r[16] = PLAYER
        m.site('prepare')
        # Original helper continuation restores this frame after the hook.
        m.r[29] += 0x20

    def leave(self, m, result=0):
        m.r[2] = result & 0xFFFFFFFF
        before = (m.r.copy(), m.hi, m.lo)
        expected_ra = m.get(m.r[29] + 0x1DCC, 4)
        expected_fp = m.get(m.r[29] + 0x1DC8, 4)
        m.site('scope_exit')
        expected = before[0]
        expected[31], expected[30] = expected_ra, expected_fp
        self.assertEqual((m.r, m.hi, m.lo), (expected, before[1], before[2]))

    def test_grouped_build_verified_and_old_image_bytes_remain_identical(self):
        report = verify(self.source, self.image, grouped=True)
        self.assertEqual(report['stage'], 'grouped-guard-only')
        self.assertEqual(report['memory_bytes'], 20)
        self.assertFalse(report['autoscroll'])
        self.assertEqual(report['sha256'],
                         'cce0d3ddb5fbee1284f1e47ed6976421b78a9f7b882caea8f363b9a9998a4e57')
        self.assertEqual(report['output_size'], 7146352)
        self.assertEqual(report['changed_original_bytes'], 65)
        self.assertEqual(len(stage.hook_inventory(True)), 11)
        old, _ = stage.build(self.source)
        self.assertEqual(hashlib.sha256(old).hexdigest(),
                         'c8b6d9544bfccf98375efb871029e5fbb6d292e17f3a198f2eaa06578b12749d')
        with self.assertRaises(ValueError):
            verify(self.source, self.image)
        with self.assertRaises(ValueError):
            stage.build(self.source, grouped=True, enable_reveal=True)

    def test_clear_and_three_copies_remain_one_unfinished_scope(self):
        m = self.machine()
        self.enter(m)
        self.assertEqual(self.word(m, stage.OWNER_SP), m.r[29])
        self.assertEqual(self.word(m, stage.OWNER_TICKET), 1)
        for operation in ('prepare', 'general', 'general_recopy', 'general_mode3'):
            if operation == 'prepare':
                self.prepare(m)
            else:
                self.copy(m, operation)
            self.assertEqual(self.word(m, stage.SCOPE), WRITER_MASK | 1)
            self.assertEqual(self.word(m, stage.OUTCOME), 0xFFFFFFFE)
        self.assertEqual(self.word(m, 0), 4)
        self.leave(m)
        self.assertEqual(self.word(m, stage.SCOPE), 1)
        self.assertEqual(self.word(m, stage.OUTCOME), 0)
        self.assertEqual(m.calls, [stage.MEMCPY] * 3)

    def test_no_copy_and_failed_update_outcome_are_not_success(self):
        for with_copy in (False, True):
            m = self.machine()
            self.enter(m)
            if with_copy:
                self.copy(m)
            self.leave(m, -1)
            self.assertEqual(self.word(m, stage.SCOPE), 1)
            self.assertEqual(self.word(m, stage.OUTCOME), 0xFFFFFFFF)

    def test_sequential_same_frame_gets_fresh_outer_tickets(self):
        m = self.machine()
        for ticket in range(1, 4):
            m.r[29] = STACK
            self.enter(m)
            self.copy(m)
            self.leave(m)
            self.assertEqual(self.word(m, stage.SCOPE), ticket)
            self.assertEqual(self.word(m, stage.OWNER_TICKET), ticket)

    def test_inner_copy_without_outer_entry_fails_closed_but_runs_stock(self):
        m = self.machine()
        self.copy(m)
        self.assertEqual(self.word(m, stage.SCOPE), FAULT)
        self.assertEqual(m.calls, [stage.MEMCPY])

    def test_other_frame_cannot_adopt_same_inner_callsite(self):
        m = self.machine()
        self.enter(m)
        m.r[29] += 0x100
        self.copy(m)
        self.assertEqual(self.word(m, stage.SCOPE), FAULT)
        self.assertEqual(m.calls, [stage.MEMCPY])

    def test_wrong_preparation_caller_cannot_adopt_owner_frame(self):
        for return_pc in (0x42C2BC, 0x42E7E0, 0, 0x42CD64):
            with self.subTest(return_pc=return_pc):
                m = self.machine()
                self.enter(m)
                self.prepare(m, return_pc)
                self.assertEqual(self.word(m, stage.SCOPE), FAULT)

    def test_wrong_writer_kind_cannot_adopt_preparation_or_copy_return(self):
        for label, return_pc in (('copy', 0x42CD40), ('zero', 0x42CD64),
                                 ('zero', 0x42CD40)):
            with self.subTest(label=label, return_pc=return_pc):
                m = self.machine()
                self.enter(m)
                m.r[4:7] = [ITEM, 0x1800000, 0xA88]
                m.r[31] = return_pc
                def stock(target):
                    self.assertEqual(self.word(m, stage.SCOPE), FAULT)
                    m.hostile_result(ITEM)
                m.callback = stock
                m.run_at(m.labels[label], return_pc)
                self.assertEqual(self.word(m, stage.SCOPE), FAULT)
                self.assertEqual(m.calls, [stage.MEMCPY if label == 'copy' else stage.MEMSET])

    def test_foreign_writers_revoke_active_scope_before_stock_mutation(self):
        for name in ('set', 'fast', 'clear', 'initialize', 'cue'):
            with self.subTest(name=name):
                m = self.machine()
                self.enter(m)
                m.r[4:7] = [ITEM, 0x1800000, 0xA88]
                m.r[16], m.r[18] = PLAYER, 17
                m.r[2] = 0xAE0000 if name == 'clear' else 1
                def stock(target):
                    self.assertEqual(self.word(m, stage.SCOPE), FAULT)
                    m.hostile_result(ITEM)
                m.callback = stock
                m.site(name)
                self.assertEqual(self.word(m, stage.SCOPE), FAULT)
                self.leave(m)
                self.assertEqual(self.word(m, stage.SCOPE), FAULT)

    def test_foreign_write_outside_scope_does_not_poison_future_update(self):
        m = self.machine()
        self.copy(m, 'fast')
        self.assertEqual(self.word(m, stage.SCOPE), 0)
        self.enter(m)
        self.copy(m)
        self.leave(m)
        self.assertEqual(self.word(m, stage.SCOPE), 1)
        self.copy(m, 'fast')
        # READY is a historical completion, not current identity permission.
        self.assertEqual(self.word(m, stage.SCOPE), 1)
        self.assertEqual(self.word(m, 0), 3)

    def test_entry_with_existing_raw_writer_or_fault_cannot_publish(self):
        for raw_state in (WRITER_MASK | 1, FAULT):
            m = self.machine()
            m.put(m.state, raw_state, 4)
            self.enter(m)
            self.assertEqual(self.word(m, stage.SCOPE), FAULT)
            self.leave(m)
            self.assertEqual(self.word(m, stage.SCOPE), FAULT)

    def test_overlapping_entry_does_not_relabel_the_original_owner(self):
        m = self.machine()
        self.enter(m)
        owner = self.word(m, stage.OWNER_SP)
        m.r[29] = STACK + 0x2000
        self.enter(m)
        self.assertEqual(self.word(m, stage.SCOPE), FAULT)
        self.assertEqual(self.word(m, stage.OWNER_SP), owner)
        self.assertEqual(self.word(m, stage.OWNER_TICKET), 1)

    def test_unexpected_outcome_or_wrong_exit_frame_faults_without_changing_stock_result(self):
        for result in (1, -12, 0x80000000):
            m = self.machine()
            self.enter(m)
            self.leave(m, result)
            self.assertEqual(self.word(m, stage.SCOPE), FAULT)
        m = self.machine()
        self.enter(m)
        m.r[29] += 0x100
        self.leave(m)
        self.assertEqual(self.word(m, stage.SCOPE), FAULT)

    def test_invalidation_around_outer_finish_cannot_restore_ready(self):
        for label in ('scope_guard_finish', 'scope_guard_finish_sc',
                      'scope_guard_finish_success'):
            with self.subTest(label=label):
                m = self.machine()
                self.enter(m)
                self.copy(m)
                fired = []
                def interrupt(pc):
                    if pc == m.labels[label] and not fired:
                        fired.append(pc)
                        m.put(m.state + stage.SCOPE, FAULT, 4)
                m.before_instruction = interrupt
                self.leave(m)
                self.assertTrue(fired)
                self.assertEqual(self.word(m, stage.SCOPE), FAULT)

    def test_outer_sc_retry_exhaustion_is_bounded_and_preserves_original_entry(self):
        m = self.machine()
        m.sc_failures = 8
        self.enter(m)
        self.assertEqual(self.word(m, stage.SCOPE), FAULT)
        self.assertEqual(self.word(m, stage.OWNER_TICKET), 0)

    def test_late_foreign_begin_can_outlive_historical_scope_completion(self):
        m = self.machine()
        self.enter(m)
        self.copy(m)
        foreign = []
        return_pc = stage.HOOKS['fast'][0] + 8

        def interrupt(pc):
            if pc != m.labels['scope_guard_finish'] or foreign:
                return
            # The exit already checked raw READY. On a disjoint stock stack,
            # run a foreign wrapper through raw BEGIN, but pause before its
            # scope classification. This is actual emitted code, not a forced
            # state replacement. Scope completion is not a lock/reader lease.
            m.before_instruction = None
            outer = (m.r.copy(), m.hi, m.lo)
            m.r[29], m.r[31] = STACK + 0x1000, return_pc
            m.r[4:7] = [ITEM, 0x1800000, 0xA88]
            m.run_at(m.labels['copy'], m.labels['scope_write'])
            foreign.append((m.r.copy(), m.hi, m.lo))
            self.assertEqual(self.word(m, 0), WRITER_MASK | 2)
            m.r, m.hi, m.lo = outer

        m.before_instruction = interrupt
        self.leave(m)
        self.assertEqual(len(foreign), 1)
        self.assertEqual(self.word(m, stage.SCOPE), 1)
        self.assertEqual(self.word(m, 0), WRITER_MASK | 2)
        m.r, m.hi, m.lo = foreign[0]
        m.callback = lambda target: m.hostile_result(ITEM)
        m.run_at(m.labels['scope_write'], return_pc)
        self.assertEqual(self.word(m, stage.SCOPE), 1)
        self.assertEqual(self.word(m, 0), 2)
        expected, hi, lo = m.after_call
        expected[29], expected[31] = STACK + 0x1000, return_pc
        self.assertEqual((m.r, m.hi, m.lo), (expected, hi, lo))
        self.assertEqual(m.calls, [stage.MEMCPY] * 2)


if __name__ == '__main__':
    unittest.main()
