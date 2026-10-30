#!/usr/bin/env python3
"""Pin one refresh caller's destructor-result stop, not caller isolation.

The hash-pinned native pair, branch delay, frame and existing pure epilogue
are checked separately from private classification and exact branch replay.
Earlier cleanup, higher callback effects and native lifetime remain outside.
"""

import hashlib
import struct
import unittest

from build_reveal_bridge_diag import b
import reveal_refresh_failure_gate_mips as gates
import reveal_refresh_failure_gate_stage as stage
import reveal_delete_release_gate_stage as parent_stage
import reveal_registry_receipt_mips as receipt
import reveal_registry_owner_mips as bindings
import reveal_registry_lifecycle_mips as lifecycle
import reveal_paint_retirement_mips as owners
import reveal_birth_queue_mips as queue
import test_reveal_delete_release_gate_contract as preceding
import test_reveal_registry_birth_contract as native


ARGS, STAGE_ARGS = preceding.ARGS, preceding.STAGE_ARGS
CORE_ARGS = (ARGS[3], ARGS[4], 0x1EE0000)
SOURCE_PAIR = (0x1680FFD3, 0x24020001)
GATED_SHA256 = '88c32e213641ce6731c4e6eeef00f7fbf2487cef4976d061e27ec1c682e46d85'


class RefreshFailureGateContractTests(unittest.TestCase):
    setUpClass = classmethod(native.RegistryBirthContractTests.setUpClass.__func__)
    words = native.RegistryBirthContractTests.words

    @staticmethod
    def fragment(code, base, first, last):
        selected = code[first - base:last - base]
        return struct.unpack('<' + 'I' * (len(selected) // 4), selected)

    def core_words(self, first, last):
        code, labels = gates.assemble(*CORE_ARGS)
        end = CORE_ARGS[2] + len(code) if last is None else labels[last]
        return self.fragment(code, CORE_ARGS[2], labels[first], end)

    @staticmethod
    def restored_architecture():
        return (b.lw(8, gates.HI, 29), b.r_type(8, 0, 0, 0x11),
                b.lw(8, gates.LO, 29), b.r_type(8, 0, 0, 0x13),
                *(b.lw(register, offset, 29) for register, offset in gates.SAVE.items()),
                b.addiu(29, 29, gates.FRAME))

    def test_source_pair_is_the_ordinary_refresh_post_destructor_branch_and_success_delay(self):
        self.assertEqual(gates.HOOKS, {'gate': (0x4ACD94, SOURCE_PAIR)})
        self.words(0x4ACD8C, [0x0C124EB0, 0x02002021, *SOURCE_PAIR,
                              0x02402021, 0x27A50420, 0x0C1247A0, 0x27A60020])
        self.assertEqual(self.branches[0x4ACD94], 0x4ACCE4)
        self.assertEqual(0x4ACD8C + 8, 0x4ACD94)
        self.assertEqual((gates.REFRESH_FRAME, gates.EPILOGUE, gates.TAKEN,
                          gates.FALLTHROUGH, gates.REFRESH_DELAY),
                         (1160, 0x4ACCE4, 0x4ACCE4, 0x4ACD9C, 0x24020001))
        # The source delay overwrites a destructor error with1 on both paths.

    def test_native_prologue_saves_the_genuine_frame_and_classifies_owner_in_S2(self):
        self.words(0x4ACBC0, [0x27BDFB78, 0x00002821, 0x24060040,
                              0xAFB00470, 0x00808021, 0x27A40420,
                              0xAFBF0484, 0xAFB40480, 0xAFB3047C,
                              0xAFB20478, 0x0C296F18, 0xAFB10474])
        self.words(0x4ACC08, [0x02002821, 0x26113DD8,
                              0x0C296FB8, 0x8E1200D4])
        self.words(0x4ACC18, [0x27A40020, 0x02202821, 0x0C107EE0, 0x24060200])
        self.assertEqual(0x488, 1160)
        # S0=V and S2=*(V+D4) have already been established before cleanup.
        # No new controller/view reload is needed after its uncertain result.

    def test_pure_existing_epilogue_preserves_result_and_skips_earlier_success_store(self):
        self.words(0x4ACCE0, [0x24020001, 0x8FBF0484, 0x8FB40480,
                              0x8FB3047C, 0x8FB20478, 0x8FB10474,
                              0x8FB00470, 0x03E00008, 0x27BD0488])
        self.assertEqual(gates.EPILOGUE, 0x4ACCE4)
        self.words(0x4ACE30, [0x1000FFAC, 0x2402FFFF])
        self.assertEqual(self.branches[0x4ACE30], gates.EPILOGUE)
        # The function already has a native -1 return through this unwind.

    def test_earlier_list_work_and_path_flags_do_not_become_rollback(self):
        self.words(0x4ACC28, [0x8E0300CC, 0x8E040064, 0x8C630018,
                              0x10800033, 0xAFA30464,
                              0x8C990030, 0x0320F809, 0])
        self.words(0x4ACC48, [0x1840002E, 0x02202021, 0x3C050092,
                              0x0C107FB0, 0x24A51230,
                              0x1040003A, 0x0000A021])
        self.words(0x4ACD04, [0x3C050092, 0x02202021, 0x0C107FB0,
                              0x24A51230, 0x1040000C, 0x24140001])
        self.words(0x4ACD64, [0x1040002D, 0x3C130094])
        self.words(0x4ACD84, [0x1040001E, 0])
        # Ordinary populated-list and null/empty-list routes can both reach
        # D94; native S4 chooses recreate versus immediate success return.

    def test_later_recreation_and_new_view_offset_work_are_bypassed_on_stop(self):
        self.words(0x4ACD9C, [0x02402021, 0x27A50420,
                              0x0C1247A0, 0x27A60020,
                              0x1040FFCD, 0x8FA30464,
                              0x8C4400CC, 0x8C470060, 0x8C860010])
        self.words(0x4ACDE4, [0x3C070002, 0x27A50460, 0x00003021,
                              0x0C22D0F0, 0x24E70002])
        self.assertEqual(self.jumps[0x4ACDA4], 0x491E80)
        self.assertEqual(self.jumps[0x4ACDF0], 0x8B43C0)
        # A stopped error cannot re-enter constructor or offset setter here.

    def test_bounded_incoming_census_includes_pair_delay_and_fallthrough(self):
        for target in (0x4ACD94, 0x4ACD98, 0x4ACD9C):
            with self.subTest(target=hex(target)):
                self.assertEqual({pc for pc, destination in self.jumps.items()
                                  if destination == target}, set())
                self.assertEqual({pc for pc, destination in self.branches.items()
                                  if destination == target}, set())
        self.assertEqual({pc for pc, target in self.jumps.items() if target == 0x4ACBC0},
                         {0x4AD860, 0x4AD8D8})
        self.assertEqual(len({pc for pc, target in self.jumps.items() if target == 0x493AC0}), 49)
        # These encoded targets do not prove absence of computed/forged entry.

    def test_other_destructor_call_and_higher_true_result_handling_remain_outside(self):
        self.words(0x4ACD1C, [0x0C124EB0, 0x02002021,
                              0x8FBF0484, 0x8FB40480, 0x8FB3047C,
                              0x8FB20478, 0x8FB10474, 0x8FB00470,
                              0x24020001, 0x03E00008, 0x27BD0488])
        self.words(0x4AD8D8, [0x0C12B2F0, 0x02002021,
                              0x12600006, 0x00408821, 0x24020001,
                              0x12220004, 0x8FBF002C,
                              0x0C12B390, 0x02002021])
        self.words(0x4AD8FC, [0x8FBF002C, 0x02201021])
        self.words(0x4ACE70, [0x26043DD8, 0x0C107F20, 0x27A50018])
        self.words(0x450D9C, [0x0C12B620, 0x26050050, 0x0C119AA0, 0x02002021])
        self.words(0x4AEEE8, [0x24030001, 0x1443FFF6, 0x02402021])
        #4ACD1C still forces1. Higher4AD880 may call4ACE40(V) on !=1,
        # Other callbacks ignore the result or free their operation context
        # and exit on the inspected error path; they do not isolate failure.

    def test_complete_save_precedes_only_private_S2_RA_V0_decision(self):
        self.assertEqual(len(gates.assemble(*CORE_ARGS)[0]), 504)
        expected = {register: 0x10 + index * 4
                    for index, register in enumerate(
                        register for register in range(1, 32) if register != 29)}
        self.assertEqual(gates.SAVE, expected)
        self.assertEqual((gates.FRAME, gates.HI, gates.LO), (192, 0x88, 0x8C))
        prefix = (b.addiu(29, 29, -192),
                  *(b.sw(register, offset, 29) for register, offset in expected.items()),
                  b.r_type(0, 0, 8, 0x10), b.sw(8, 0x88, 29),
                  b.r_type(0, 0, 8, 0x12), b.sw(8, 0x8C, 29))
        words = self.core_words('gate', 'gate_stopped')
        self.assertEqual(words[:len(prefix)], prefix)
        decision = words[len(prefix):]
        accesses = [word for word in decision if word >> 26 in (32, 33, 35, 36, 37, 40, 41, 43)]
        self.assertEqual(accesses, [b.lw(8, expected[18], 29),
                                   b.lw(8, expected[31], 29), b.lw(8, expected[2], 29)])
        for value in (ARGS[3], 0x4ACD94):
            self.assertIn(b.lui(9, value >> 16), decision)
            self.assertIn(b.ori(9, 9, value & 0xFFFF), decision)
        self.assertNotIn(b.lw(8, expected[3], 29), decision)

    def test_scope_mismatches_and_zero_result_forward_without_a_new_status_ABI(self):
        code, labels = gates.assemble(*CORE_ARGS)
        start = labels['gate'] + (1 + len(gates.SAVE) + 4) * 4
        branches = []
        for pc in range(start, labels['gate_stopped'], 4):
            word = self.fragment(code, CORE_ARGS[2], pc, pc + 4)[0]
            if word >> 26 in (4, 5):
                immediate = word & 0xFFFF
                immediate -= 0x10000 if immediate & 0x8000 else 0
                branches.append((word >> 26, pc + 4 + immediate * 4))
        self.assertEqual(branches, [(5, labels['gate_forward']),
                                    (5, labels['gate_forward']), (4, labels['gate_forward'])])

    def test_stop_and_forward_restore_all_registers_and_HI_LO(self):
        self.assertEqual(self.core_words('gate_stopped', 'gate_forward'),
                         (*self.restored_architecture(), b.j_type(2, 0x4ACCE4), 0))
        self.assertEqual(self.core_words('gate_forward', 'gate_replay'),
                         self.restored_architecture())
        _, labels = gates.assemble(*CORE_ARGS)
        self.assertEqual(set(labels), {'gate', 'gate_stopped', 'gate_forward', 'gate_replay',
                                      'gate_replay_branch', 'gate_replay_fallthrough', 'gate_replay_taken'})
        self.assertEqual(labels['gate_replay'], labels['gate_replay_branch'])

    def test_forward_relocates_branch_target_and_executes_success_delay_once(self):
        code, labels = gates.assemble(*CORE_ARGS)
        words = self.core_words('gate_replay', None)
        self.assertEqual(len(words), 6)
        self.assertEqual((words[0] >> 26, (words[0] >> 21) & 31, (words[0] >> 16) & 31), (5, 20, 0))
        immediate = words[0] & 0xFFFF
        immediate -= 0x10000 if immediate & 0x8000 else 0
        self.assertEqual(labels['gate_replay_branch'] + 4 + immediate * 4, labels['gate_replay_taken'])
        self.assertNotEqual(words[0], SOURCE_PAIR[0])
        self.assertEqual(words[1], gates.REFRESH_DELAY)
        self.assertEqual(words.count(gates.REFRESH_DELAY), 1)
        self.assertEqual(words[2:], (b.j_type(2, 0x4ACD9C), 0, b.j_type(2, 0x4ACCE4), 0))
        self.assertEqual(labels['gate_replay_fallthrough'], labels['gate_replay_branch'] + 8)

    def test_entire_fragment_is_private_only_with_no_service_graph_or_native_frame_access(self):
        code, labels = gates.assemble(*CORE_ARGS)
        words = self.fragment(code, CORE_ARGS[2], CORE_ARGS[2], CORE_ARGS[2] + len(code))
        accesses = [word for word in words if word >> 26 in (32, 33, 35, 36, 37, 40, 41, 43)]
        self.assertEqual({(word >> 21) & 31 for word in accesses}, {29})
        self.assertEqual([word & 0xFFFF for word in accesses if word >> 26 in (40, 41, 43)],
                         [*gates.SAVE.values(), gates.HI, gates.LO])
        self.assertFalse(any(word >> 26 == 3 for word in words))
        self.assertFalse(any(word >> 26 == 0 and word & 63 in (8, 9) for word in words))
        self.assertEqual(gates.hook_words(labels), {0x4ACD94: (b.j_type(2, labels['gate']), 0)})

    def test_hook_target_and_primary_U_R_CODE_layout_are_strict(self):
        _, labels = gates.assemble(*CORE_ARGS)
        for value in (True, False, None, 0, -4, 1, 0x10000000, 0x100000000):
            with self.subTest(target=value), self.assertRaises(ValueError):
                gates.hook_words(dict(labels, gate=value))
        for index in range(3):
            for value in (True, False, None, 0, -4, 1, 1.0, '16',
                          0x400000, 0xFFFFFFFC, 0x100000000):
                args = list(CORE_ARGS)
                args[index] = value
                with self.subTest(index=index, value=value), self.assertRaises(ValueError):
                    gates.assemble(*args)
        for index, value in ((0, CORE_ARGS[1]), (1, CORE_ARGS[0]),
                              (0, CORE_ARGS[2]), (1, CORE_ARGS[2]),
                              (2, CORE_ARGS[0]), (2, CORE_ARGS[1]),
                              (2, 0x10000000), (2, 0x0FFFFFFC)):
            args = list(CORE_ARGS)
            args[index] = value
            with self.subTest(index=index, overlap=value), self.assertRaises(ValueError):
                gates.assemble(*args)

    def test_extra_static_extents_and_complete_RX_are_strict_without_dynamic_guards(self):
        baseline = gates.assemble(*CORE_ARGS)
        size = len(baseline[0])
        for extra in (((0x1F90000, 4),), ((0xFFFFFFFC, 4),)):
            self.assertEqual(gates.assemble(*CORE_ARGS, extra_protected_data=extra), baseline)
        for extra in (None, [], ((True, 4),), ((0x1F90000, True),),
                      ((0x1F90000, 0),), ((0x1F90000, 3),), ((0xFFFFFFFC, 8),),
                      ((0x400000, 4),), ((CORE_ARGS[0] + 0x288, 4),),
                      ((CORE_ARGS[1] + 20, 4),), ((CORE_ARGS[2] + size - 4, 4),),
                      ((0x1F90000, 8), (0x1F90004, 4))):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                gates.assemble(*CORE_ARGS, extra_protected_data=extra)
        for protected in (None, (CORE_ARGS[2], size), (CORE_ARGS[2] - 4, size + 8)):
            self.assertEqual(gates.assemble(*CORE_ARGS, protected_code=protected), baseline)
        for protected in ([], (), (True, size), (CORE_ARGS[2], True),
                          (CORE_ARGS[2], 0), (CORE_ARGS[2], 3),
                          (CORE_ARGS[2], size - 4), (CORE_ARGS[2] + 4, size),
                          (0x400000, 0x2000000), (CORE_ARGS[0], 0x1000000), (0xFFFFFFC, 8)):
            with self.subTest(protected=protected), self.assertRaises(ValueError):
                gates.assemble(*CORE_ARGS, protected_code=protected)

    def test_each_fixed_role_is_excluded_from_the_new_fragment_by_pure_core_checks(self):
        code, _ = gates.assemble(*CORE_ARGS)
        tail = CORE_ARGS[2] + len(code) - 4
        roles = (('receipt', receipt.memory_bytes(16)), ('binding', bindings.memory_bytes(16)),
                 ('owner', owners.memory_bytes(16)), ('paint_mutex', receipt.MUTEX_BYTES),
                 ('lifecycle', lifecycle.memory_bytes(16)), ('queue', queue.QUEUE_BYTES),
                 ('transport_mutex', queue.MUTEX_BYTES), ('fault', 4))
        for name, size in roles:
            with self.subTest(role=name), self.assertRaises(ValueError):
                gates.assemble(*CORE_ARGS, extra_protected_data=((tail, size),))
        for index in (0, 1):
            args = list(CORE_ARGS)
            args[index] = tail
            with self.subTest(primary_role=index), self.assertRaises(ValueError):
                gates.assemble(*args)

    def test_all_twenty_prior_default_hashes_and_zero_parent_extension_are_preserved(self):
        preceding.DeleteReleaseGateContractTests.test_all_nineteen_prior_default_hashes_and_zero_parent_extension_are_preserved(self)
        parent = parent_stage.assemble(*STAGE_ARGS)
        self.assertEqual((len(parent['code']), hashlib.sha256(parent['code']).hexdigest()),
                         (91940, preceding.GATED_SHA256))
        self.assertEqual(parent_stage.assemble(*STAGE_ARGS, following_code_bytes=0), parent)

    def test_parent_and_successor_following_RX_are_strict_and_not_appended(self):
        for selected in (parent_stage, stage):
            baseline = selected.assemble(*STAGE_ARGS)
            extended = selected.assemble(*STAGE_ARGS, following_code_bytes=4)
            with self.subTest(stage=selected.__name__):
                self.assertEqual(selected.assemble(*STAGE_ARGS, following_code_bytes=0), baseline)
                self.assertEqual(len(extended['code']), len(baseline['code']))
                self.assertEqual(extended['labels'], baseline['labels'])
                self.assertEqual(extended['coherent_hooks'], baseline['coherent_hooks'])
                self.assertEqual(extended['protected_code_extent'], (ARGS[6], len(baseline['code']) + 4))
                self.assertNotEqual(extended['code'], baseline['code'])
            for value in (True, False, None, -4, 1, 2, 3, 1.0, '4', 0x100000000):
                with self.subTest(stage=selected.__name__, following=value), self.assertRaises(ValueError):
                    selected.assemble(*STAGE_ARGS, following_code_bytes=value)

    def test_stage_appends_exact_bound_gate_after_the_complete_guarded_parent(self):
        result = stage.assemble(*STAGE_ARGS)
        prefix, tail = (result['refresh_failure_gate_prefix_code_bytes'], result['refresh_failure_gate_code_bytes'])
        self.assertEqual((prefix, tail, len(result['code'])), (91940, 504, 92444))
        self.assertEqual(prefix + tail, len(result['code']))
        self.assertEqual(hashlib.sha256(result['code']).hexdigest(), GATED_SHA256)
        full = (ARGS[6], len(result['code']))
        self.assertEqual(result['protected_code_extent'], full)
        parent = parent_stage.assemble(*STAGE_ARGS, following_code_bytes=tail)
        self.assertEqual(parent['protected_code_extent'], full)
        self.assertEqual(parent['code'], result['code'][:prefix])
        emitted, labels = gates.assemble(ARGS[3], ARGS[4], ARGS[6] + prefix, protected_code=full)
        self.assertEqual((emitted, labels), (result['code'][prefix:], result['refresh_failure_gate_labels']))
        for name, address in labels.items():
            self.assertEqual(result['labels']['refresh_failure_gate_' + name], address)

    def test_stage_adds_one_native_hook_and_keeps_the_inherited_generated_splice(self):
        result = stage.assemble(*STAGE_ARGS)
        parent = parent_stage.assemble(*STAGE_ARGS)
        hooks = gates.hook_words(result['refresh_failure_gate_labels'])
        self.assertEqual(result['refresh_failure_gate_hooks'], hooks)
        self.assertEqual(set(hooks), {0x4ACD94})
        self.assertFalse(set(hooks) & set(parent['coherent_hooks']))
        self.assertEqual(result['coherent_hooks'], {**parent['coherent_hooks'], **hooks})
        self.assertEqual(result['native_coherent_hooks'], {**parent['native_coherent_hooks'], **hooks})
        self.assertEqual(result['generated_coherent_hooks'], parent['generated_coherent_hooks'])
        self.assertEqual((len(result['native_coherent_hooks']), len(result['generated_coherent_hooks']),
                          len(result['coherent_hooks'])), (24, 1, 25))

    def test_stage_tail_and_following_aliases_are_rejected_and_scope_flags_remain_limited(self):
        result = stage.assemble(*STAGE_ARGS)
        for address, following in ((ARGS[6] + len(result['code']) - 4, 0),
                                   (ARGS[6] + len(result['code']), 4)):
            args = list(STAGE_ARGS)
            args[-1] = address
            with self.subTest(following=following), self.assertRaises(ValueError):
                stage.assemble(*args, following_code_bytes=following)
        self.assertIs(result['refresh_destructor_failure_continuation_stopped'], True)
        for flag in ('native_callers_isolated', 'destructor_entry_fenced', 'earlier_cleanup_rolled_back',
                     'raw_release_proven', 'native_lifetime_proven', 'partial_graph_cleanup_proven'):
            with self.subTest(flag=flag):
                self.assertIs(result[flag], False)


if __name__ == '__main__':
    unittest.main()
