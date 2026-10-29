#!/usr/bin/env python3
"""Pin a late destructor-result stop, not an entry fence or cleanup proof.

The original image is hash checked; its already effective cleanup and masked
release results remain explicit counterexamples. No installer, player, device
or network operation is supplied by these offline source/layout contracts.
"""

import hashlib
import struct
import unittest

from build_reveal_bridge_diag import b
import reveal_destructor_continuation_gate_mips as gates
import reveal_destructor_continuation_gate_stage as stage
import reveal_registry_release_gate_stage as parent_stage
import test_reveal_registry_release_gate_contract as preceding
import test_reveal_registry_birth_contract as native


ARGS, STAGE_ARGS = preceding.ARGS, preceding.STAGE_ARGS
CORE_ARGS = (ARGS[3], ARGS[4], 0x1EE0000)
SOURCE_PAIR = (0x8E240024, 0x0C1214C8)
SOURCE_DELAY = 0x02602821
DESTRUCTOR_EPILOGUE, RESOURCE_DELETE, RESOURCE_RETURN = 0x493C98, 0x485320, 0x493F58
GATED_SHA256 = '996f66b14285bdb35490b4e4e2cbc380c2ed888a558323ea1828a58ebc246b1c'


class DestructorContinuationGateContractTests(unittest.TestCase):
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

    def test_native_pair_and_retained_source_delay_are_after_engine_delete_return(self):
        self.assertEqual(gates.HOOKS, {'gate': (0x493F4C, SOURCE_PAIR)})
        self.assertEqual((gates.DESTRUCTOR_FRAME, gates.EPILOGUE, gates.CONTINUATION,
                          gates.RESOURCE_DELETE, gates.RESOURCE_DELAY),
                         (1208, DESTRUCTOR_EPILOGUE, RESOURCE_RETURN, RESOURCE_DELETE, SOURCE_DELAY))
        self.words(0x493F40, [0x02202021, 0x0C10E568, 0x02602821,
                              *SOURCE_PAIR, SOURCE_DELAY, 0x8E043B68])
        self.assertEqual(0x493F44 + 8, 0x493F4C)
        self.assertEqual(0x493F50 + 8, RESOURCE_RETURN)
        self.words(0x493EF4, [0x8E0200CC, 0x8C510050])
        # S1 is the controller used by this native delete/resource sequence.
        # The displaced load must happen before a replayed resource call.

    def test_native_frame_and_selected_epilogue_restore_without_graph_or_services(self):
        self.words(0x493AC0, [0x27BDFB48, 0xAFB10494, 0x27B10228,
                              0xAFB00490, 0x00002821, 0x00808021,
                              0x24060208, 0x02202021, 0xAFBF04B4,
                              0xAFBE04B0, 0xAFB704AC, 0xAFB604A8,
                              0xAFB504A4, 0xAFB404A0, 0xAFB3049C,
                              0x0C296F18, 0xAFB20498])
        self.words(DESTRUCTOR_EPILOGUE,
                   [0x8FBF04B4, 0x8FBE04B0, 0x8FB704AC, 0x8FB604A8,
                    0x8FB504A4, 0x8FB404A0, 0x8FB3049C, 0x8FB20498,
                    0x8FB10494, 0x8FB00490, 0x03E00008, 0x27BD04B8])
        self.words(0x494264, [0x1000FE8C, 0x2402FFFF])
        self.assertEqual(self.branches[0x494264], DESTRUCTOR_EPILOGUE)
        self.assertEqual(0x4B8, 1208)
        # Native NULL failure already returns -1 through this same unwind.
        # The epilogue preserves V0/V1 and makes no cleanup or unlock call.

    def test_preceding_close_worker_and_callback_effects_are_not_rolled_back(self):
        self.words(0x493B04, [0x120001D7, 0x02002021, 0x24020001,
                              0xAE020044, 0x8E1641E8, 0x8E1500D4,
                              0x0C1245A8, 0x8E1741D8])
        self.words(0x493B3C, [0x0C123E00, 0x02002021,
                              0x0C12E358, 0x8E043B9C])
        self.words(0x493BF4, [0x0C123D48, 0x8E043B84])
        self.words(0x493CCC, [0x0C123B88, 0x8C440030])
        self.words(0x493C2C, [0x8E194224, 0x13200003, 0,
                              0x0320F809, 0x02002021])
        self.words(0x493C4C, [0x0C119AA0, 0, 0xAE003BA4])
        # Private stop and shared cancellation precede the later delete gate.
        # Neither path is undone by a local nonzero-result return.

    def test_worker_list_cache_and_detach_cleanup_precede_the_new_stop(self):
        self.words(0x493EA8, [0x8E040078, 0x10800003, 0,
                              0x0C1302A0, 0, 0x8E042A08,
                              0x10800003, 0, 0x0C115BA0, 0, 0xAE002A08])
        self.words(0x4C0AA4, [0x8C84000C, 0xAE0005A4, 0xAE020430,
                              0x0C119B40, 0xAE020018])
        self.words(0x493EDC, [0x02111021, 0x8C4400E8,
                              0x0C110188, 0x26310314,
                              0x163EFFFC, 0x02111021])
        self.words(0x493EFC, [0x8E240028, 0x0C22C7B8, 0xAE2000F0,
                              0x0C12F688, 0x8E043B90,
                              0x8E0200CC, 0xAE003B90])
        self.words(0x493F28, [0x02202021, 0x0C11EA88, 0x02602821,
                              0x02202021, 0x0C10E5E0, 0x02602821])
        self.words(0x47AAAC, [0x8E020004, 0x8E030000, 0xAC620004, 0xAC430000])
        self.words(0x4397F8, [0x0C10E5B0, 0x02402821, 0x8E84002C,
                              0x0C22C1D8, 0x8E050008])
        self.words(0x8B0794, [0x8C430008, 0x10600002, 0x8C42000C,
                              0xAC62000C, 0x10400002, 0, 0xAC430008])
        # A stop here cannot recover purged work, parent membership or a worker.

    def test_remaining_independent_resource_callback_and_view_frees_are_bypassed(self):
        self.words(0x493F58, [0x8E043B68, 0xAE0000D0, 0x8C99042C,
                              0x0320F809, 0x00002821,
                              0x8E0400D4, 0x0C139528, 0x02002821])
        self.words(0x493FA8, [0x0C115BA0, 0, 0x8E040064])
        self.words(0x493FBC, [0x0C115BA0, 0, 0x8E043B68])
        self.words(0x493FD0, [0x0C10F530, 0, 0xAE003B68,
                              0x0C119AA0, 0x02002021])
        self.words(0x485398, [0x8E1000D0, 0x12000012, 0x8FBF002C,
                              0x8E0400F8, 0x0C116968, 0x02002821,
                              0x02802021, 0x0C1214A0, 0x02002821])
        # The stopped route does not call independent resource deletion or free.

    def test_prior_escaped_resource_alias_does_not_become_free_authority(self):
        self.words(0x49274C, [0x0C1164C8, 0x02002821])
        self.words(0x459320, [0x10800004, 0, 0x10A00002, 0, 0xAC85007C])
        # The existing resource+7C=view alias is not revoked by returning -1.

    def test_bounded_incoming_census_and_other_delete_and_destructor_callers(self):
        for target in (0x493F4C, 0x493F50, 0x493F54):
            with self.subTest(target=hex(target)):
                self.assertEqual({pc for pc, destination in self.jumps.items()
                                  if destination == target}, set())
                self.assertEqual({pc for pc, destination in self.branches.items()
                                  if destination == target}, set())
        delete = {pc for pc, target in self.jumps.items() if target == 0x4395A0}
        destructors = {pc for pc, target in self.jumps.items() if target == 0x493AC0}
        self.assertEqual(len(delete), 56)
        self.assertEqual(len(destructors), 49)
        self.assertIn(0x493F44, delete)
        self.assertTrue({0x43BAA4, 0x4ACD8C, 0x4E4B40} <= destructors)
        self.assertEqual(sum(self.jumps.get(pc + 12) == RESOURCE_DELETE for pc in delete), 54)
        self.words(0x4E4B40, [0x0C124EB0, 0x8C440008, 0x02001021,
                              0x1622FFFC, 0x8E100000])
        self.words(0x4ACD8C, [0x0C124EB0, 0x02002021,
                              0x1680FFD3, 0x24020001])
        # Outer callers can keep iterating or recreating; their return handling
        # and computed/runtime entries are not made safe by this local gate.

    def test_delete_release_error_still_masks_to_zero_and_forwards(self):
        self.words(0x439654, [0x8EB90278, 0x8FBF0034, 0x8FB4002C,
                              0x8FB30028, 0x8FB20024, 0x8FB10020,
                              0x8FB0001C, 0x02A02021, 0x8FB50030,
                              0x03200008, 0x27BD0038])
        self.words(0x437DA8, [0x0C119B70, 0x8C84013C])
        self.words(0x466DC8, [0x0C296E0C, 0, 0x8FBF001C,
                              0x00001021, 0x03E00008, 0x27BD0020])
        # Constructor-only release propagation does not normalize deletion's
        # tail-unlock result. Actual raw nonzero can still arrive here as V0=0.

    def test_complete_architecture_is_saved_before_private_scalar_classification(self):
        self.assertEqual(len(gates.assemble(*CORE_ARGS)[0]), 500)
        expected = {register: 0x10 + index * 4
                    for index, register in enumerate(
                        register for register in range(1, 32) if register != 29)}
        self.assertEqual(gates.SAVE, expected)
        self.assertEqual((gates.FRAME, gates.HI, gates.LO), (192, 0x88, 0x8C))
        words = self.core_words('gate', 'gate_stopped')
        prefix = (b.addiu(29, 29, -192),
                  *(b.sw(register, offset, 29) for register, offset in expected.items()),
                  b.r_type(0, 0, 8, 0x10), b.sw(8, 0x88, 29),
                  b.r_type(0, 0, 8, 0x12), b.sw(8, 0x8C, 29))
        self.assertEqual(words[:len(prefix)], prefix)
        decision = words[len(prefix):]
        accesses = [word for word in decision if word >> 26 in (32, 33, 35, 36, 37, 40, 41, 43)]
        self.assertEqual(accesses, [b.lw(8, expected[17], 29),
                                   b.lw(8, expected[31], 29), b.lw(8, expected[2], 29)])
        for value in (ARGS[3], 0x493F4C):
            self.assertIn(b.lui(9, value >> 16), decision)
            self.assertIn(b.ori(9, 9, value & 0xFFFF), decision)
        self.assertNotIn(b.lw(8, expected[3], 29), decision)
        # Saved V1 is preserved, never interpreted as a raw status or marker.

    def test_each_scope_mismatch_and_zero_result_branch_to_forward(self):
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

    def test_stopped_and_forward_routes_restore_all_registers_and_HI_LO(self):
        self.assertEqual(self.core_words('gate_stopped', 'gate_forward'),
                         (*self.restored_architecture(), b.j_type(2, DESTRUCTOR_EPILOGUE), 0))
        self.assertEqual(self.core_words('gate_forward', 'gate_replay'),
                         self.restored_architecture())
        self.assertEqual(set(gates.assemble(*CORE_ARGS)[1]),
                         {'gate', 'gate_stopped', 'gate_forward', 'gate_replay'})

    def test_forward_load_precedes_original_RA_and_single_replayed_delay(self):
        replay = self.core_words('gate_replay', None)
        self.assertEqual(replay, (SOURCE_PAIR[0], b.lui(31, RESOURCE_RETURN >> 16),
                                  b.ori(31, 31, RESOURCE_RETURN & 0xFFFF),
                                  b.j_type(2, RESOURCE_DELETE), SOURCE_DELAY))
        _, labels = gates.assemble(*CORE_ARGS)
        self.assertEqual(gates.hook_words(labels), {0x493F4C: (b.j_type(2, labels['gate']), 0)})
        # Native493F54 remains in the source but is not executed again: the
        # forward jump calls485320 directly with original RA493F58 and A1=S3.

    def test_decision_and_stop_touch_only_private_save_and_make_no_service_call(self):
        code, labels = gates.assemble(*CORE_ARGS)
        words = self.fragment(code, CORE_ARGS[2], labels['gate'], labels['gate_replay'])
        accesses = [word for word in words if word >> 26 in (32, 33, 35, 36, 37, 40, 41, 43)]
        self.assertEqual({(word >> 21) & 31 for word in accesses}, {29})
        self.assertFalse(any(word >> 26 == 3 for word in words))
        self.assertFalse(any(word >> 26 == 0 and word & 63 in (8, 9) for word in words))
        writes = [word & 0xFFFF for word in accesses if word >> 26 in (40, 41, 43)]
        self.assertEqual(writes, [*gates.SAVE.values(), gates.HI, gates.LO])
        # The only non-stack access in the fragment is the admitted replay's
        # actual original controller+24 load; R participates in static layout.

    def test_hook_targets_and_primary_static_layout_are_strict(self):
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
                              (2, CORE_ARGS[0]), (2, CORE_ARGS[1])):
            args = list(CORE_ARGS)
            args[index] = value
            with self.subTest(index=index, overlap=value), self.assertRaises(ValueError):
                gates.assemble(*args)

    def test_extra_static_extents_do_not_invent_dynamic_stack_or_lifetime_guards(self):
        baseline = gates.assemble(*CORE_ARGS)
        for extra in (((0x1F90000, 4),), ((0xFFFFFFFC, 4),)):
            self.assertEqual(gates.assemble(*CORE_ARGS, extra_protected_data=extra), baseline)
        for extra in (None, [], ((True, 4),), ((0x1F90000, True),),
                      ((0x1F90000, 0),), ((0x1F90000, 3),), ((0xFFFFFFFC, 8),),
                      ((0x400000, 4),), ((CORE_ARGS[0], 4),), ((CORE_ARGS[0] + 0x288, 4),),
                      ((CORE_ARGS[1], 4),), ((CORE_ARGS[1] + 20, 4),),
                      ((CORE_ARGS[2], 4),), ((CORE_ARGS[2] + len(baseline[0]) - 4, 4),),
                      ((0x1F90000, 8), (0x1F90004, 4))):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                gates.assemble(*CORE_ARGS, extra_protected_data=extra)

    def test_declared_complete_RX_must_contain_entire_fragment_and_exclude_data(self):
        baseline = gates.assemble(*CORE_ARGS)
        size = len(baseline[0])
        for protected in (None, (CORE_ARGS[2], size), (CORE_ARGS[2] - 4, size + 8)):
            self.assertEqual(gates.assemble(*CORE_ARGS, protected_code=protected), baseline)
        for protected in ([], (), (True, size), (CORE_ARGS[2], True),
                          (CORE_ARGS[2], 0), (CORE_ARGS[2], 3),
                          (CORE_ARGS[2], size - 4), (CORE_ARGS[2] + 4, size),
                          (0x400000, 0x2000000), (CORE_ARGS[0], 0x1000000),
                          (0xFFFFFFC, 8)):
            with self.subTest(protected=protected), self.assertRaises(ValueError):
                gates.assemble(*CORE_ARGS, protected_code=protected)

    def test_all_eighteen_prior_hashes_and_zero_parent_extension_are_preserved(self):
        preceding.RegistryReleaseGateContractTests.test_all_seventeen_prior_default_hashes_and_zero_parent_extension_are_preserved(self)
        parent = parent_stage.assemble(*STAGE_ARGS)
        self.assertEqual((len(parent['code']), hashlib.sha256(parent['code']).hexdigest()),
                         (89140, preceding.GATED_SHA256))
        self.assertEqual(parent_stage.assemble(*STAGE_ARGS, following_code_bytes=0), parent)

    def test_parent_following_RX_is_strict_protected_not_appended(self):
        parent = parent_stage.assemble(*STAGE_ARGS)
        extended = parent_stage.assemble(*STAGE_ARGS, following_code_bytes=4)
        self.assertEqual(len(extended['code']), len(parent['code']))
        self.assertEqual(extended['labels'], parent['labels'])
        self.assertEqual(extended['coherent_hooks'], parent['coherent_hooks'])
        self.assertEqual(extended['protected_code_extent'], (ARGS[6], len(parent['code']) + 4))
        self.assertNotEqual(extended['code'], parent['code'])
        for value in (True, False, None, -4, 1, 2, 3, 1.0, '4', 0x100000000):
            with self.subTest(following=value), self.assertRaises(ValueError):
                parent_stage.assemble(*STAGE_ARGS, following_code_bytes=value)

    def test_stage_uses_exact_guarded_prefix_and_appends_only_bound_gate(self):
        result = stage.assemble(*STAGE_ARGS)
        prefix, tail = (result['destructor_continuation_gate_prefix_code_bytes'],
                        result['destructor_continuation_gate_code_bytes'])
        self.assertEqual((prefix, tail, len(result['code'])), (89140, 500, 89640))
        self.assertEqual(prefix + tail, len(result['code']))
        self.assertEqual(hashlib.sha256(result['code']).hexdigest(), GATED_SHA256)
        full = (ARGS[6], len(result['code']))
        self.assertEqual(result['protected_code_extent'], full)
        parent = parent_stage.assemble(*STAGE_ARGS, following_code_bytes=tail)
        self.assertEqual(parent['protected_code_extent'], full)
        self.assertEqual(result['code'][:prefix], parent['code'])
        emitted, labels = gates.assemble(ARGS[3], ARGS[4], ARGS[6] + prefix,
                                         protected_code=full)
        self.assertEqual((emitted, labels),
                         (result['code'][prefix:], result['destructor_continuation_gate_labels']))
        for name, address in labels.items():
            self.assertEqual(result['labels']['destructor_continuation_gate_' + name], address)

    def test_stage_adds_one_native_hook_and_preserves_the_one_generated_splice(self):
        result = stage.assemble(*STAGE_ARGS)
        parent = parent_stage.assemble(*STAGE_ARGS)
        hooks = gates.hook_words(result['destructor_continuation_gate_labels'])
        self.assertEqual(result['destructor_continuation_gate_hooks'], hooks)
        self.assertEqual(set(hooks), {0x493F4C})
        self.assertFalse(set(hooks) & set(parent['coherent_hooks']))
        self.assertEqual(result['coherent_hooks'], {**parent['coherent_hooks'], **hooks})
        self.assertEqual(result['native_coherent_hooks'], {**parent['native_coherent_hooks'], **hooks})
        self.assertEqual(result['generated_coherent_hooks'], parent['generated_coherent_hooks'])
        self.assertEqual((len(result['native_coherent_hooks']), len(result['generated_coherent_hooks']),
                          len(result['coherent_hooks'])), (22, 1, 23))
        self.assertTrue(all(pc < native.receipt.NATIVE_RX[1] for pc in result['native_coherent_hooks']))

    def test_stage_final_tail_excludes_all_fixed_data_and_keeps_limit_flags(self):
        result = stage.assemble(*STAGE_ARGS)
        tail_word = ARGS[6] + len(result['code']) - 4
        self.assertGreaterEqual(tail_word, ARGS[6] + 89140)
        for index in range(len(STAGE_ARGS)):
            if index == 6:
                continue
            args = list(STAGE_ARGS)
            args[index] = tail_word
            with self.subTest(data_role=index), self.assertRaises(ValueError):
                stage.assemble(*args)
        self.assertIs(result['destructor_delete_failure_continuation_stopped'], True)
        for flag in ('destructor_entry_fenced', 'earlier_cleanup_rolled_back',
                     'native_callers_isolated', 'raw_release_proven',
                     'native_lifetime_proven', 'partial_graph_cleanup_proven'):
            with self.subTest(flag=flag):
                self.assertIs(result[flag], False)


if __name__ == '__main__':
    unittest.main()
