"""Execute dedicated same-file block grouping; no device or identity claims."""
import hashlib
import unittest

import build_reveal_guard_stage as stage
from folderfollow_reveal_guard_mips import FAULT, WRITER_MASK
from test_reveal_guard_stage import SOURCE, PLAYER, ITEM, STACK
import test_reveal_grouped_stage as grouped_tests
from verify_reveal_guard_stage import verify


class FastGroupedStageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = SOURCE.read_bytes()
        cls.image, cls.meta = stage.build(cls.source, grouped=True, fast_grouped=True)

    machine = grouped_tests.GroupedStageTests.machine
    word = grouped_tests.GroupedStageTests.word
    enter_general = grouped_tests.GroupedStageTests.enter
    leave_general = grouped_tests.GroupedStageTests.leave
    prepare = grouped_tests.GroupedStageTests.prepare

    def enter_fast(self, m):
        # These saved stock registers were established before the narrow hook;
        # no extra allocation or whole-function entry assumption is introduced.
        m.r[16], m.r[17], m.r[19], m.r[20] = 0x1800000, PLAYER, 0xAE0000, 0xAE0000
        before = (m.r.copy(), m.hi, m.lo)
        m.site('fast_scope_entry')
        expected = before[0]
        expected[4], expected[5] = ITEM, 0x1800000
        self.assertEqual((m.r, m.hi, m.lo), (expected, before[1], before[2]))

    def copy(self, m, name='fast'):
        m.r[4:7], m.r[2] = [ITEM, 0x1800000, 0xA88], 1
        if name == 'general_mode3':
            m.r[16] = PLAYER
        m.callback = lambda target: m.hostile_result(ITEM)
        m.site(name)

    def leave_fast(self, m, result=0x87654321):
        m.r[2] = result
        before = (m.r.copy(), m.hi, m.lo)
        m.site('fast_scope_exit')
        expected = before[0]
        expected[4] = (expected[19] - 8268) & 0xFFFFFFFF
        self.assertEqual((m.r, m.hi, m.lo), (expected, before[1], before[2]))

    def test_exact_mode_verified_and_previous_builds_unchanged(self):
        report = verify(self.source, self.image, grouped=True, fast_grouped=True)
        self.assertEqual(report['stage'], 'fast-grouped-guard-only')
        self.assertEqual(report['memory_bytes'], 24)
        self.assertFalse(report['autoscroll'])
        self.assertEqual(report['sha256'],
                         '0c587656d2bd169b6763bebf8ddf0f1103f65275b46e1f43f6604718e7f23d72')
        self.assertEqual(report['output_size'], 7147040)
        self.assertEqual(report['changed_original_bytes'], 80)
        self.assertEqual(len(stage.hook_inventory(True, True)), 13)
        for grouped, digest in (
                (False, 'c8b6d9544bfccf98375efb871029e5fbb6d292e17f3a198f2eaa06578b12749d'),
                (True, 'cce0d3ddb5fbee1284f1e47ed6976421b78a9f7b882caea8f363b9a9998a4e57')):
            old, _ = stage.build(self.source, grouped=grouped)
            self.assertEqual(hashlib.sha256(old).hexdigest(), digest)
            with self.assertRaises(ValueError):
                verify(self.source, self.image, grouped=grouped)

    def test_invalid_mode_and_active_reveal_refused(self):
        for values in ({'fast_grouped': True}, {'grouped': 1},
                       {'grouped': True, 'fast_grouped': 1},
                       {'grouped': True, 'fast_grouped': None},
                       {'grouped': True, 'fast_grouped': True, 'enable_reveal': True}):
            with self.subTest(values=values), self.assertRaises(ValueError):
                stage.build(self.source, **values)

    def test_copy_completion_does_not_finish_fast_scope(self):
        m = self.machine()
        self.enter_fast(m)
        self.assertEqual(self.word(m, stage.OWNER_SP), STACK)
        self.assertEqual(self.word(m, stage.OWNER_KIND), stage.FAST_KIND)
        self.copy(m)
        self.assertEqual(self.word(m, 0), 1)
        self.assertEqual(self.word(m, stage.SCOPE), WRITER_MASK | 1)
        self.assertEqual(self.word(m, stage.OUTCOME), 0xFFFFFFFE)
        self.leave_fast(m)
        self.assertEqual(self.word(m, stage.SCOPE), 1)
        self.assertEqual(self.word(m, stage.OUTCOME), 0)
        self.assertEqual(m.calls, [stage.MEMCPY])

    def test_fast_completion_preserves_arbitrary_queue_result(self):
        for result in (0, 1, 0xFFFFFFFF, 0xFFFFFFF4, 0x80000000):
            with self.subTest(result=result):
                m = self.machine()
                self.enter_fast(m)
                self.copy(m)
                self.leave_fast(m, result)
                # This is block-completion only, NOT a success claim about v0.
                self.assertEqual(self.word(m, stage.OUTCOME), 0)
                self.assertEqual(self.word(m, stage.SCOPE), 1)

    def test_general_clear_and_recopies_still_one_scope(self):
        for result in (0, -1):
            m = self.machine()
            self.enter_general(m)
            self.assertEqual(self.word(m, stage.OWNER_KIND), stage.GENERAL_KIND)
            self.prepare(m)
            for name in ('general', 'general_recopy', 'general_mode3'):
                self.copy(m, name)
                self.assertEqual(self.word(m, stage.SCOPE), WRITER_MASK | 1)
            self.leave_general(m, result)
            self.assertEqual(self.word(m, stage.SCOPE), 1)
            self.assertEqual(self.word(m, stage.OUTCOME), result & 0xFFFFFFFF)

    def test_alternating_kinds_at_reused_stack_use_fresh_tickets(self):
        m = self.machine()
        for ticket, fast in enumerate((True, False, True, False), 1):
            m.r[29] = STACK
            if fast:
                self.enter_fast(m)
                self.copy(m)
                self.leave_fast(m)
            else:
                self.enter_general(m)
                self.copy(m, 'general')
                self.leave_general(m)
            self.assertEqual(self.word(m, stage.SCOPE), ticket)
            self.assertEqual(self.word(m, stage.OWNER_TICKET), ticket)

    def test_fast_copy_or_exit_without_entry_faults(self):
        for operation in ('copy', 'exit'):
            m = self.machine()
            if operation == 'copy':
                self.copy(m)
                self.assertEqual(m.calls, [stage.MEMCPY])
            else:
                self.leave_fast(m)
            self.assertEqual(self.word(m, stage.SCOPE), FAULT)

    def test_same_frame_cannot_adopt_other_kind_copy(self):
        for fast in (True, False):
            m = self.machine()
            if fast:
                self.enter_fast(m)
                self.copy(m, 'general')
            else:
                self.enter_general(m)
                self.copy(m)
            self.assertEqual(self.word(m, stage.SCOPE), FAULT)
            self.assertEqual(m.calls, [stage.MEMCPY])

    def test_preparation_cannot_be_absorbed_into_fast_kind(self):
        m = self.machine()
        self.enter_fast(m)
        self.prepare(m)
        self.assertEqual(self.word(m, stage.SCOPE), FAULT)

    def test_same_frame_wrong_exit_kind_faults_without_changing_stock_effects(self):
        m = self.machine()
        self.enter_general(m)
        self.leave_fast(m)
        self.assertEqual(self.word(m, stage.SCOPE), FAULT)
        m = self.machine()
        self.enter_fast(m)
        self.leave_general(m)
        self.assertEqual(self.word(m, stage.SCOPE), FAULT)

    def test_other_frame_fast_writer_or_exit_cannot_adopt_owner(self):
        for operation in ('copy', 'exit'):
            m = self.machine()
            self.enter_fast(m)
            m.r[29] += 0x100
            self.copy(m) if operation == 'copy' else self.leave_fast(m)
            self.assertEqual(self.word(m, stage.SCOPE), FAULT)

    def test_both_entry_kinds_overlap_fail_without_replacing_original_owner(self):
        for first_fast, second_fast in ((True, False), (False, True), (True, True)):
            with self.subTest(first=first_fast, second=second_fast):
                m = self.machine()
                (self.enter_fast if first_fast else self.enter_general)(m)
                owner = (self.word(m, stage.OWNER_SP), self.word(m, stage.OWNER_KIND))
                m.r[29] = STACK + 0x2000
                (self.enter_fast if second_fast else self.enter_general)(m)
                self.assertEqual(self.word(m, stage.SCOPE), FAULT)
                self.assertEqual((self.word(m, stage.OWNER_SP),
                                  self.word(m, stage.OWNER_KIND)), owner)

    def test_foreign_public_copy_faults_before_mutation(self):
        m = self.machine()
        self.enter_fast(m)
        m.r[4:7] = [ITEM, 0x1800000, 0xA88]
        def stock(target):
            self.assertEqual(self.word(m, stage.SCOPE), FAULT)
            m.hostile_result(ITEM)
        m.callback = stock
        m.site('set')
        self.leave_fast(m)
        self.assertEqual(self.word(m, stage.SCOPE), FAULT)
        self.assertEqual(m.calls, [stage.MEMCPY])

    def test_fast_entry_and_exit_reject_raw_busy_or_fault(self):
        for at_exit in (False, True):
            for raw in (FAULT, WRITER_MASK | 1):
                m = self.machine()
                if at_exit:
                    self.enter_fast(m)
                m.put(m.state, raw, 4)
                (self.leave_fast if at_exit else self.enter_fast)(m)
                self.assertEqual(self.word(m, stage.SCOPE), FAULT)

    def test_invalidation_at_fast_finish_remains_sticky(self):
        for label in ('scope_guard_finish', 'scope_guard_finish_sc',
                      'scope_guard_finish_success'):
            m = self.machine()
            self.enter_fast(m)
            self.copy(m)
            fired = []
            def interrupt(pc):
                if pc == m.labels[label] and not fired:
                    fired.append(pc)
                    m.put(m.state + stage.SCOPE, FAULT, 4)
            m.before_instruction = interrupt
            self.leave_fast(m)
            self.assertTrue(fired)
            self.assertEqual(self.word(m, stage.SCOPE), FAULT)

    def test_fast_entry_retry_exhaustion_preserves_stock_argument_setup(self):
        m = self.machine()
        m.sc_failures = 8
        self.enter_fast(m)
        self.assertEqual(self.word(m, stage.SCOPE), FAULT)
        self.assertEqual(self.word(m, stage.OWNER_TICKET), 0)

    def test_tampered_fast_hooks_or_private_state_extent_rejected(self):
        for offset in [stage.FAST_HOOKS[name][0] - stage.BASE for name in stage.FAST_HOOKS
                       ] + [self.meta['memsize_offset'], self.meta['code_offset']]:
            bad = bytearray(self.image)
            bad[offset] ^= 1
            with self.assertRaises(ValueError):
                verify(self.source, bad, grouped=True, fast_grouped=True)


if __name__ == '__main__':
    unittest.main()
