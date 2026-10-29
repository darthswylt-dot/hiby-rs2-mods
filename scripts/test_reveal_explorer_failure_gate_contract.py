#!/usr/bin/env python3
"""Pin a private explorer-failure splice, not graph rollback or isolation.

The original native source is hash checked. The generated splice is separately
checked against the exact parent assembly, not mistaken for vendor words. No
installer, device operation, whole-instance lifetime or safe cleanup is implied.
"""

import hashlib
import struct
import unittest

from build_reveal_bridge_diag import b
import reveal_constructor_continuation_gate_mips as constructor
import reveal_constructor_continuation_gate_stage as parent_stage
import reveal_explorer_failure_gate_mips as gates
import reveal_explorer_failure_gate_stage as stage
import test_reveal_constructor_continuation_gate_contract as preceding
import test_reveal_registry_birth_contract as native


ARGS, STAGE_ARGS = preceding.ARGS, preceding.STAGE_ARGS
PARENT_STOP = 0x1ED0000
CORE_ARGS = (ARGS[3], ARGS[4], 0x1EE0000, PARENT_STOP)
SOURCE_PAIR = (0x8FA80088, 0x01000011)
NATIVE_OUTER_RA_OFFSET = 192 + 0x84
EXPLORER_EPILOGUE = 0x492F84
GATED_SHA256 = '540034a7349e240a95047fbb39b01a48dc8379669f1510d53c59e64992c888e9'


class ExplorerFailureGateContractTests(unittest.TestCase):
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

    def test_splice_source_is_the_exact_generated_parent_stop_restore_pair(self):
        parent = parent_stage.assemble(*STAGE_ARGS)
        stop = parent['constructor_continuation_gate_labels']['first_gate_stopped']
        self.assertEqual(self.fragment(parent['code'], ARGS[6], stop, stop + 8),
                         SOURCE_PAIR)
        self.assertEqual(SOURCE_PAIR,
                         (b.lw(8, constructor.HI, 29), b.r_type(8, 0, 0, 0x11)))
        self.assertGreaterEqual(stop, native.receipt.NATIVE_RX[1])
        # This pair is generated code, not a word pair from the vendor image.
        # Parent U/RA/V0 classification has already selected its stopped label.

    def test_parent_scope_is_exact_U_registration_RA_and_nonzero_V0_before_splice(self):
        parent = parent_stage.assemble(*STAGE_ARGS)
        labels = parent['constructor_continuation_gate_labels']
        words = self.fragment(parent['code'], ARGS[6], labels['first_gate'],
                              labels['first_gate_stopped'])
        decision = words[1 + len(constructor.SAVE) + 4:]
        accesses = [word for word in decision
                    if word >> 26 in (32, 33, 35, 36, 37, 40, 41, 43)]
        self.assertEqual(accesses,
                         [b.lw(8, constructor.SAVE[17], 29),
                          b.lw(8, constructor.SAVE[31], 29),
                          b.lw(8, constructor.SAVE[2], 29)])
        for value in (ARGS[3], 0x43AE94):
            self.assertIn(b.lui(9, value >> 16), decision)
            self.assertIn(b.ori(9, 9, value & 0xFFFF), decision)
        self.assertEqual(decision[-2] >> 26, 4)
        self.assertEqual(((decision[-2] >> 21) & 31,
                          (decision[-2] >> 16) & 31), (8, 0))
        # The helper does not infer failure from the engine or native V1.

    def test_explorer_call_and_native_constructor_saved_return_relation_are_pinned(self):
        self.words(0x492908, [0x8FA417D0, 0x3C060049, 0x27A516E4,
                              0x24C63AC0, 0x0C10EB40, 0x02003821,
                              0x8FA417D0, 0xAE0200CC, 0x0C10E5A0,
                              0x00402821])
        self.words(0x43AD00, [0x27BDFF78, 0xAFBF0084])
        self.assertEqual(0x492918 + 8, 0x492920)
        self.assertEqual(NATIVE_OUTER_RA_OFFSET, 0x144)
        self.assertEqual(constructor.FIRST_FRAME, 136)
        self.assertEqual(constructor.FRAME, 192)

    def test_stock_constructor_epilogue_preserves_engine_and_uses_only_private_unwind(self):
        self.words(0x43AEA8, [0x8FBF0084, 0x8FA20050, 0x8FB60080,
                              0x8FB5007C, 0x8FB40078, 0x8FB30074,
                              0x8FB20070, 0x8FB1006C, 0x8FB00068,
                              0x03E00008, 0x27BD0088])
        self.assertEqual(constructor.FIRST_EPILOGUE, 0x43AEA8)
        # Only the targeted invocation's saved return is changed. The stock
        # engine-return load and native136-byte callee restore remain literal.

    def test_explorer_native_NULL_epilogue_restores_6096_byte_frame_without_calls(self):
        self.words(0x491E80, [0x27BDE830, 0xAFA417D0,
                              0xAFA517D4, 0xAFA617D8])
        self.words(0x491E9C, [0xAFBF17CC, 0xAFBE17C8, 0xAFB717C4,
                              0xAFB617C0, 0xAFB517BC, 0xAFB417B8,
                              0xAFB317B4, 0xAFB217B0, 0xAFB117AC,
                              0x0C296F18, 0xAFB017A8])
        self.words(EXPLORER_EPILOGUE,
                   [0x8FBF17CC, 0x00008021, 0x02001021, 0x8FBE17C8,
                    0x8FB717C4, 0x8FB617C0, 0x8FB517BC, 0x8FB417B8,
                    0x8FB317B4, 0x8FB217B0, 0x8FB117AC, 0x8FB017A8,
                    0x03E00008, 0x27BD17D0])
        self.assertEqual(0x17D0, 6096)
        self.assertEqual({pc for pc, target in self.branches.items()
                          if target == EXPLORER_EPILOGUE},
                         {0x491ED0, 0x491EE0, 0x491EE8, 0x491F44})
        # Native entry spills its three arguments just above the allocated
        # frame. The helper does not read those additional argument slots.

    def test_skipping_only_enable_would_leave_later_engine_uses_and_partial_view_return(self):
        self.words(0x492930, [0x8E0241D8, 0x1040024E, 0x8FA417D0])
        self.words(0x492944, [0x8E0500CC])
        self.words(0x4929C4, [0x8E0500CC])
        self.words(0x4929F0, [0x0C296DB8, 0x8CA50000])
        self.words(0x493270, [0x8E0200CC, 0x26A517D8,
                              0x0C10EC38, 0x8C460038])
        self.words(0x492F50, [0x8FBF17CC, 0x02001021])
        self.assertEqual(self.branches[0x492934], 0x493270)
        #492F50 returns S0 (the partial view), unlike the native NULL exit.

    def test_partial_graph_allocations_and_resource_alias_already_precede_failure(self):
        self.words(0x491F3C, [0x0C119A78, 0x24044238])
        self.words(0x491F84, [0x0C119A78, 0x24040948])
        self.words(0x491FC8, [0x0C119A58, 0xAE0300D4])
        self.words(0x4926E0, [0x24040005, 0x0C10F500,
                              0x24A51948, 0x104001AB, 0xAE023B68])
        self.words(0x49274C, [0x0C1164C8, 0x02002821])
        self.words(0x459320, [0x10800004, 0, 0x10A00002, 0, 0xAC85007C])
        self.words(0x491F34, [0x0C296DB8, 0xAC6000F0])
        self.assertEqual(0x4238, 16952)
        self.assertEqual(0x948, 2376)
        # A resource+7C alias to V and earlier controller mutations exist.
        # Not yet entering the owner's list is not exclusive ownership.

    def test_callbacks_and_resource_binding_precede_later_owner_list_insertion(self):
        self.words(0x4928A8, [0x3C050049, 0x02402021,
                              0x0C116560, 0x24A50980])
        self.words(0x4928C8, [0x3C050049, 0x02402021,
                              0x0C116550, 0x24A506E0])
        self.words(0x4928F4, [0x8FA417D0, 0x26450020, 0x27A615E4,
                              0x0C10F008, 0x24070001])
        self.words(0x492A38, [0x8FA417D0, 0x0C1394A0, 0x02002821])
        self.assertLess(0x492900, 0x492918)
        self.assertGreater(0x492A3C, 0x492918)
        # No new free/unlock can be justified by the local stop or NULL result.

    def test_encoded_explorer_caller_census_and_hook_incoming_edges_are_bounded(self):
        callers = {pc for pc, target in self.jumps.items()
                   if target == 0x491E80 and self.elf.word(pc) >> 26 == 3}
        self.assertEqual(len(callers), 188)
        self.assertTrue({0x495CE0, 0x495DCC, 0x49E68C, 0x49E734} <= callers)
        for target in (0x492918, 0x49291C, 0x492920, 0x492924, 0x492928):
            with self.subTest(target=hex(target)):
                self.assertEqual({pc for pc, destination in self.jumps.items()
                                  if destination == target}, set())
                self.assertEqual({pc for pc, destination in self.branches.items()
                                  if destination == target}, set())
        # This is not a classification of every NULL-result continuation,
        # indirect entry, runtime alias, forged frame or partial activation.

    def test_helper_memory_is_only_native_return_scalar_and_original_private_HI_load(self):
        code, labels = gates.assemble(*CORE_ARGS)
        words = self.fragment(code, CORE_ARGS[2], CORE_ARGS[2],
                              CORE_ARGS[2] + len(code))
        accesses = [word for word in words
                    if word >> 26 in (32, 33, 35, 36, 37, 40, 41, 43)]
        self.assertEqual([(word >> 26, (word >> 21) & 31, word & 0xFFFF)
                          for word in accesses],
                         [(35, 29, NATIVE_OUTER_RA_OFFSET),
                          (43, 29, NATIVE_OUTER_RA_OFFSET), (35, 29, 0x88)])
        self.assertFalse(any(word >> 26 == 3 for word in words))
        self.assertFalse(any(word >> 26 == 0 and word & 63 == 9 for word in words))
        self.assertFalse(any(word >> 26 == 9 and (word >> 16) & 31 == 29
                             for word in words))
        self.assertEqual(set(labels), {'scope', 'selected', 'replay', 'abort_return'})

    def test_both_scope_outcomes_replay_exact_HI_pair_then_resume_original_restore(self):
        replay = self.core_words('replay', 'abort_return')
        self.assertEqual(replay, (*SOURCE_PAIR, b.j_type(2, PARENT_STOP + 8), 0))
        self.assertEqual(self.core_words('abort_return', None),
                         (b.j_type(2, EXPLORER_EPILOGUE), 0))
        code, labels = gates.assemble(*CORE_ARGS)
        scope = self.fragment(code, CORE_ARGS[2], labels['scope'], labels['selected'])
        self.assertIn(b.lui(9, 0x492920 >> 16), scope)
        self.assertIn(b.ori(9, 9, 0x492920 & 0xFFFF), scope)
        self.assertEqual(scope[-2] >> 26, 5)
        branch_pc = labels['selected'] - 8
        immediate = scope[-2] & 0xFFFF
        immediate -= 0x10000 if immediate & 0x8000 else 0
        self.assertEqual(branch_pc + 4 + immediate * 4, labels['replay'])

    def test_selected_route_retargets_only_the_current_native_saved_return(self):
        code, labels = gates.assemble(*CORE_ARGS)
        selected = self.fragment(code, CORE_ARGS[2], labels['selected'], labels['replay'])
        escape = labels['abort_return']
        self.assertEqual(selected,
                         (b.lui(8, escape >> 16), b.ori(8, 8, escape & 0xFFFF),
                          b.sw(8, NATIVE_OUTER_RA_OFFSET, 29)))

    def test_generated_hook_is_strict_and_does_not_claim_a_native_source_site(self):
        _, labels = gates.assemble(*CORE_ARGS)
        self.assertEqual(gates.hook_words(labels, PARENT_STOP),
                         {PARENT_STOP: (b.j_type(2, labels['scope']), 0)})
        for value in (True, False, 0, -4, 1, 0x10000000, 0x100000000):
            with self.subTest(target=value), self.assertRaises(ValueError):
                gates.hook_words(dict(labels, scope=value), PARENT_STOP)
            with self.subTest(site=value), self.assertRaises(ValueError):
                gates.hook_words(labels, value)

    def test_primary_layout_and_parent_source_plus_resume_word_are_strict(self):
        for index in range(4):
            for value in (True, False, None, 0, -4, 1, 1.0, '16',
                          0x400000, 0xFFFFFFFC, 0x100000000):
                args = list(CORE_ARGS)
                args[index] = value
                with self.subTest(index=index, value=value), self.assertRaises(ValueError):
                    gates.assemble(*args)
        for parent in (0x1000, CORE_ARGS[0], CORE_ARGS[1],
                       CORE_ARGS[2] - 8, CORE_ARGS[2] - 4,
                       CORE_ARGS[2], CORE_ARGS[2] + 4):
            with self.subTest(parent=parent), self.assertRaises(ValueError):
                gates.assemble(*CORE_ARGS[:3], parent)
        for index, value in ((0, CORE_ARGS[1]), (0, PARENT_STOP + 8),
                              (1, PARENT_STOP + 8), (2, CORE_ARGS[0]),
                              (2, CORE_ARGS[1])):
            args = list(CORE_ARGS)
            args[index] = value
            with self.subTest(index=index, overlap=value), self.assertRaises(ValueError):
                gates.assemble(*args)

    def test_extra_static_extents_are_strict_and_do_not_add_dynamic_stack_guards(self):
        baseline = gates.assemble(*CORE_ARGS)
        for extra in (((0x1F90000, 4),), ((0xFFFFFFFC, 4),)):
            with self.subTest(extra=extra):
                self.assertEqual(gates.assemble(*CORE_ARGS, extra_protected_data=extra),
                                 baseline)
        for extra in (None, [], ((True, 4),), ((0x1F90000, True),),
                      ((0x1F90000, 0),), ((0x1F90000, 3),),
                      ((0xFFFFFFFC, 8),), ((0x400000, 4),),
                      ((CORE_ARGS[0], 4),), ((CORE_ARGS[1], 4),),
                      ((CORE_ARGS[2], 4),), ((PARENT_STOP, 4),),
                      ((PARENT_STOP + 8, 4),),
                      ((0x1F90000, 8), (0x1F90004, 4))):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                gates.assemble(*CORE_ARGS, extra_protected_data=extra)

    def test_complete_RX_must_contain_both_parent_resume_and_entire_helper(self):
        baseline = gates.assemble(*CORE_ARGS)
        size = CORE_ARGS[2] + len(baseline[0]) - PARENT_STOP
        for protected in (None, (PARENT_STOP, size), (PARENT_STOP - 4, size + 8)):
            with self.subTest(protected=protected):
                self.assertEqual(gates.assemble(*CORE_ARGS, protected_code=protected),
                                 baseline)
        for protected in ([], (), (True, size), (PARENT_STOP, True),
                          (PARENT_STOP, 0), (PARENT_STOP, 3),
                          (PARENT_STOP, size - 4), (PARENT_STOP + 4, size),
                          (CORE_ARGS[2], len(baseline[0])),
                          (0x400000, 0x2000000), (CORE_ARGS[0], 0x1000000),
                          (0xFFFFFFC, 8)):
            with self.subTest(protected=protected), self.assertRaises(ValueError):
                gates.assemble(*CORE_ARGS, protected_code=protected)

    def test_parent_zero_default_and_all_sixteen_prior_composition_hashes_are_preserved(self):
        preceding.ConstructorContinuationGateContractTests.test_all_fifteen_preceding_default_composition_hashes_are_preserved(self)
        parent = parent_stage.assemble(*STAGE_ARGS)
        self.assertEqual((len(parent['code']), hashlib.sha256(parent['code']).hexdigest()),
                         (87112, preceding.GATED_SHA256))
        self.assertEqual(parent_stage.assemble(*STAGE_ARGS, following_code_bytes=0), parent)

    def test_parent_following_RX_is_strict_protected_and_not_appended(self):
        parent = parent_stage.assemble(*STAGE_ARGS)
        extended = parent_stage.assemble(*STAGE_ARGS, following_code_bytes=4)
        self.assertEqual(len(extended['code']), len(parent['code']))
        self.assertEqual(extended['labels'], parent['labels'])
        self.assertEqual(extended['coherent_hooks'], parent['coherent_hooks'])
        self.assertEqual(extended['protected_code_extent'],
                         (ARGS[6], len(parent['code']) + 4))
        self.assertNotEqual(extended['code'], parent['code'])
        for value in (True, False, None, -4, 1, 2, 3, 1.0, '4', 0x100000000):
            with self.subTest(following=value), self.assertRaises(ValueError):
                parent_stage.assemble(*STAGE_ARGS, following_code_bytes=value)

    def test_stage_changes_only_exact_guarded_prefix_splice_and_appends_bound_helper(self):
        result = stage.assemble(*STAGE_ARGS)
        prefix = result['explorer_failure_gate_prefix_code_bytes']
        tail = result['explorer_failure_gate_code_bytes']
        self.assertEqual((prefix, tail, len(result['code'])), (87112, 56, 87168))
        self.assertEqual(hashlib.sha256(result['code']).hexdigest(), GATED_SHA256)
        self.assertEqual(prefix + tail, len(result['code']))
        full = (ARGS[6], len(result['code']))
        self.assertEqual(result['protected_code_extent'], full)
        parent = parent_stage.assemble(*STAGE_ARGS, following_code_bytes=tail)
        self.assertEqual(parent['protected_code_extent'], full)
        stop = parent['constructor_continuation_gate_labels']['first_gate_stopped']
        labels = result['explorer_failure_gate_labels']
        self.assertEqual(result['explorer_failure_gate_source_words'], {stop: SOURCE_PAIR})
        hooks = gates.hook_words(labels, stop)
        self.assertEqual(result['explorer_failure_gate_hooks'], hooks)
        expected = bytearray(parent['code'])
        struct.pack_into('<II', expected, stop - ARGS[6], *hooks[stop])
        self.assertEqual(result['code'][:prefix], bytes(expected))
        self.assertEqual(self.fragment(result['code'], ARGS[6], stop, stop + 8), hooks[stop])
        emitted, emitted_labels = gates.assemble(ARGS[3], ARGS[4], ARGS[6] + prefix,
                                                stop, protected_code=full)
        self.assertEqual((emitted, emitted_labels), (result['code'][prefix:], labels))
        for name, address in labels.items():
            self.assertEqual(result['labels']['explorer_failure_gate_' + name], address)

    def test_stage_distinguishes_twenty_native_hooks_from_one_generated_splice(self):
        result = stage.assemble(*STAGE_ARGS)
        parent = parent_stage.assemble(*STAGE_ARGS)
        generated = result['explorer_failure_gate_hooks']
        self.assertEqual(result['native_coherent_hooks'], parent['coherent_hooks'])
        self.assertEqual(result['generated_coherent_hooks'], generated)
        self.assertEqual(len(result['native_coherent_hooks']), 20)
        self.assertEqual(len(generated), 1)
        self.assertFalse(set(generated) & set(parent['coherent_hooks']))
        self.assertEqual(result['coherent_hooks'], {**parent['coherent_hooks'], **generated})
        self.assertEqual(len(result['coherent_hooks']), 21)
        self.assertTrue(all(pc < native.receipt.NATIVE_RX[1]
                            for pc in result['native_coherent_hooks']))
        self.assertTrue(all(ARGS[6] <= pc < ARGS[6] + len(result['code'])
                            for pc in generated))

    def test_stage_rejects_fixed_data_in_final_tail_and_retains_scope_limit_flags(self):
        result = stage.assemble(*STAGE_ARGS)
        tail_word = ARGS[6] + len(result['code']) - 4
        self.assertGreaterEqual(tail_word, ARGS[6] + 87112)
        for index in range(len(STAGE_ARGS)):
            if index == 6:
                continue
            args = list(STAGE_ARGS)
            args[index] = tail_word
            with self.subTest(data_role=index), self.assertRaises(ValueError):
                stage.assemble(*args)
        for flag in ('explorer_failed_registration_continuation_stopped',
                     'explorer_returns_native_null_on_classified_failure',
                     'constructor_engine_return_preserved',
                     'constructor_status_continuations_gated'):
            with self.subTest(flag=flag):
                self.assertIs(result[flag], True)
        for flag in ('partial_graph_cleanup_proven', 'native_callers_isolated',
                     'raw_release_proven', 'native_lifetime_proven'):
            with self.subTest(flag=flag):
                self.assertIs(result[flag], False)


if __name__ == '__main__':
    unittest.main()
