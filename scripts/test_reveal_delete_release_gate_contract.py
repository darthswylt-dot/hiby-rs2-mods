#!/usr/bin/env python3
"""Pin destructor-scoped delete-release propagation, not cleanup rollback.

The source hash and native ABI are pinned separately from generated delegates.
Private frame witnesses are not authentication, an allocation lease, complete
release coverage or permission to retry cleanup after an uncertain result.
"""

import hashlib
import struct
import unittest

from build_reveal_bridge_diag import b
import reveal_delete_release_gate_mips as gates
import reveal_delete_release_gate_stage as stage
import reveal_destructor_continuation_gate_stage as parent_stage
import test_reveal_destructor_continuation_gate_contract as preceding
import test_reveal_registry_birth_contract as native


ARGS, STAGE_ARGS = preceding.ARGS, preceding.STAGE_ARGS
LEGACY_NAMES = ('begin', 'raw_release_call', 'raw_release_return', 'complete')
LEGACY_ENTRIES = (0x1ED0000, 0x1ED0100, 0x1ED0200, 0x1ED0300)
CORE_ARGS = (ARGS[3], ARGS[4], 0x1EE0000, *LEGACY_ENTRIES)
GATED_SHA256 = '332b5cf381ecd46f117651638d992475b8ceed505721f66c8cc1eeecdba58364'


class DeleteReleaseGateContractTests(unittest.TestCase):
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
    def restored_architecture(denied=False):
        return (b.lw(8, gates.HI, 29), b.r_type(8, 0, 0, 0x11),
                b.lw(8, gates.LO, 29), b.r_type(8, 0, 0, 0x13),
                *(b.lw(register, offset, 29)
                  for register, offset in gates.SAVE.items()
                  if not denied or register not in (2, 3)),
                *((b.addiu(2, 0, -1), b.lw(3, gates.RAW, 29)) if denied else ()),
                b.addiu(29, 29, gates.FRAME))

    def test_five_source_pairs_include_four_old_sites_and_common_native_tail(self):
        expected = {
            'begin': (0x4395C0, (0x8C990274, 0x0080A821)),
            'release_select': (0x439658, (0x8FBF0034, 0x8FB4002C)),
            'raw_release_call': (0x466DC8, (0x0C296E0C, 0)),
            'raw_release_return': (0x466DD0, (0x8FBF001C, 0x00001021)),
            'complete': (0x493F4C, (0x8E240024, 0x0C1214C8)),
        }
        self.assertEqual(gates.HOOKS, expected)
        for site, pair in expected.values():
            self.words(site, pair)
        self.words(0x493F40, [0x02202021, 0x0C10E568, 0x02602821])
        self.words(0x493F54, [0x02602821])
        self.assertEqual(gates.DELETE_RETURN, 0x493F44 + 8)

    def test_empty_no_match_and_removed_node_paths_share_the_selected_tail(self):
        self.words(0x4395E0, [0x1000001D, 0x8EB90278])
        self.words(0x4395EC, [0x12700019, 0x8E310000])
        self.words(0x43964C, [0x0C119AA0, 0x02002021, 0x8EB90278,
                              0x8FBF0034, 0x8FB4002C, 0x8FB30028,
                              0x8FB20024, 0x8FB10020, 0x8FB0001C,
                              0x02A02021, 0x8FB50030, 0x03200008, 0x27BD0038])
        self.assertEqual(self.branches[0x4395E0], 0x439658)
        self.assertEqual(self.branches[0x4395EC], 0x439654)
        self.assertEqual(gates.SELECT_CONTINUATION, 0x439660)
        self.assertEqual({pc for pc, target in self.branches.items() if target == 0x439658},
                         {0x4395E0})
        # Selecting at654 would miss the direct empty-ring entry to658.

    def test_bounded_incoming_census_keeps_every_displaced_second_word_unentered(self):
        for site in (0x4395C0, 0x4395C4, 0x43965C,
                     0x466DC8, 0x466DCC, 0x466DD0, 0x466DD4,
                     0x493F4C, 0x493F50, 0x493F54):
            with self.subTest(site=hex(site)):
                self.assertEqual({pc for pc, target in self.jumps.items() if target == site}, set())
                self.assertEqual({pc for pc, target in self.branches.items() if target == site}, set())
        self.assertEqual({pc for pc, target in self.jumps.items() if target == 0x439658}, set())
        # This encoded census cannot exclude computed or fabricated entries.

    def test_native_delete_facade_raw_and_destructor_frame_chain_is_exact(self):
        self.words(0x4395A0, [0x27BDFFC8, 0xAFB50030, 0xAFB4002C,
                              0xAFB30028, 0xAFB10020, 0xAFB0001C,
                              0xAFBF0034, 0xAFB20024])
        self.words(0x437DA0, [0x27BDFFE0, 0xAFBF001C, 0x0C119B70,
                              0x8C84013C, 0x8FBF001C, 0x03E00008, 0x27BD0020])
        self.words(0x466DC0, [0x27BDFFE0, 0xAFBF001C, 0x0C296E0C, 0,
                              0x8FBF001C, 0x00001021, 0x03E00008, 0x27BD0020])
        self.assertEqual((gates.DELETE_FRAME, gates.DESTRUCTOR_FRAME,
                          gates.FACADE_FRAME, gates.RAW_FRAME), (56, 1208, 32, 32))
        self.assertEqual(gates.RAW_RELEASE_RETURN, 0x466DD0)
        self.assertEqual(0x20 + 0x1C, 0x3C)
        self.assertEqual(0x40 - 0x38 + 0x14, 0x1C)
        # N=D-38 is popped before the facade/raw calls. Its former+14 is
        # W+1C, now overwritten by the raw wrapper's saved437DB0 return.

    def test_carrier_is_beyond_argument_homes_and_not_a_native_destructor_local(self):
        self.assertEqual((gates.TAG, gates.STATUS, gates.RAW_SP), (0x14, 0x18, 0x1C))
        memory_ops = (32, 33, 35, 36, 37, 40, 41, 43, 49, 57)
        accesses, addresses, copies = [], [], []
        for pc in range(0x493AC0, 0x494A00, 4):
            word = self.elf.word(pc)
            op, rs, rt, rd = word >> 26, (word >> 21) & 31, (word >> 16) & 31, (word >> 11) & 31
            if op in memory_ops and rs == 29:
                accesses.append((pc, word & 0xFFFF))
            if op in (8, 9) and rs == 29 and rt != 29:
                addresses.append(word & 0xFFFF)
            if op == 0 and (rs == 29 or rt == 29) and rd != 29:
                copies.append(pc)
        self.assertFalse({gates.TAG, gates.STATUS, gates.RAW_SP} & {offset for _, offset in accesses})
        self.assertFalse({gates.TAG, gates.STATUS, gates.RAW_SP} & set(addresses))
        self.assertEqual(copies, [])
        self.assertEqual(min(addresses), 0x20)
        self.assertEqual([(pc, offset) for pc, offset in accesses if offset < 0x20],
                         [(0x494180, 0x10), (0x49483C, 0x10)])
        self.words(0x494180, [0xAFBE0010])
        self.words(0x49483C, [0xAFA30010])
        # D+10 is an actual fifth-argument slot and is deliberately excluded.
        # Ordinary callee ABI and valid nonaliasing buffers remain premises.

    def test_native_unlink_and_free_already_precede_release_selection(self):
        self.words(0x439610, [0x8E020004, 0x8E030000,
                              0xAC620004, 0xAC430000, 0xAE000000,
                              0x12400003, 0xAE000004, 0x0C119AA0,
                              0x02402021, 0x8E020008, 0x24050001,
                              0x0C22CFC0, 0x8C440034, 0x0C22D088,
                              0x8E040008, 0x0C119AA0, 0x02002021])
        self.assertLess(0x439618, gates.HOOKS['release_select'][0])
        # Release uncertainty cannot undo name, paint queue, engine or node free.

    def test_prior_destructor_effects_alias_and_outer_callers_remain_unresolved(self):
        preceding.DestructorContinuationGateContractTests.test_preceding_close_worker_and_callback_effects_are_not_rolled_back(self)
        preceding.DestructorContinuationGateContractTests.test_worker_list_cache_and_detach_cleanup_precede_the_new_stop(self)
        preceding.DestructorContinuationGateContractTests.test_prior_escaped_resource_alias_does_not_become_free_authority(self)
        preceding.DestructorContinuationGateContractTests.test_bounded_incoming_census_and_other_delete_and_destructor_callers(self)
        preceding.DestructorContinuationGateContractTests.test_native_frame_and_selected_epilogue_restore_without_graph_or_services(self)

    def test_foreign_wrapper_users_and_direct_raw_sites_are_not_global_release_coverage(self):
        self.assertEqual(len({pc for pc, target in self.jumps.items() if target == 0x466DC0}), 154)
        self.assertEqual({pc for pc, target in self.jumps.items() if target == 0xA5B830},
                         {0x466DC8, 0x57E208, 0x706D4C, 0x708FAC, 0x70B46C})
        self.assertEqual(len({pc for pc, target in self.jumps.items() if target == 0x4395A0}), 56)
        self.assertEqual(len({pc for pc, target in self.jumps.items() if target == 0x493AC0}), 49)
        # Only the exact493F4C destructor route gains this private witness.

    def test_scope_namespaces_and_complete_architectural_save_are_distinct(self):
        self.assertEqual(len(gates.assemble(*CORE_ARGS)[0]), 2300)
        expected = {register: 0x10 + index * 4
                    for index, register in enumerate(
                        register for register in range(1, 32) if register != 29)}
        self.assertEqual(gates.SAVE, expected)
        self.assertEqual((gates.FRAME, gates.HI, gates.LO, gates.RAW), (192, 0x88, 0x8C, 0x90))
        self.assertEqual((gates.ARMED, gates.SELECTED, gates.ENTERED, gates.CAPTURED),
                         tuple(int.from_bytes(value, 'little')
                               for value in (b'DRAR', b'DRSL', b'DREN', b'DRCP')))
        prefix = (b.addiu(29, 29, -192),
                  *(b.sw(register, offset, 29) for register, offset in expected.items()),
                  b.r_type(0, 0, 8, 0x10), b.sw(8, 0x88, 29),
                  b.r_type(0, 0, 8, 0x12), b.sw(8, 0x8C, 29),
                  b.sw(0, gates.RAW, 29), b.addiu(23, 29, 192))
        for name in gates.HOOKS:
            with self.subTest(phase=name):
                self.assertEqual(self.core_words(name, name + '_classified')[:len(prefix)], prefix)

    def test_begin_and_selection_classify_private_U_before_native_caller_then_D(self):
        for name, u_register in (('begin', 4), ('release_select', 21)):
            words = self.core_words(name, name + '_classified')
            with self.subTest(phase=name):
                self.assertIn(b.lw(8, gates.SAVE[u_register], 29), words)
                self.assertIn(b.lw(8, 0x34, 23), words)
                self.assertLess(words.index(b.lw(8, gates.SAVE[u_register], 29)),
                                words.index(b.lw(8, 0x34, 23)))
                self.assertEqual(words[-1], b.addiu(22, 23, 56))
                for value in (ARGS[3], 0x493F4C):
                    self.assertIn(b.lui(9, value >> 16), words)
                    self.assertIn(b.ori(9, 9, value & 0xFFFF), words)
        self.assertEqual(self.core_words('begin_classified', 'begin_done'),
                         (b.sw(0, gates.TAG, 22), b.addiu(8, 0, -1),
                          b.sw(8, gates.STATUS, 22), b.sw(0, gates.RAW_SP, 22),
                          b.lui(8, gates.ARMED >> 16), b.ori(8, 8, gates.ARMED & 0xFFFF),
                          b.sw(8, gates.TAG, 22)))

    def test_selection_consumes_fresh_admission_before_checking_actual_callback(self):
        words = self.core_words('release_select_classified', 'release_select_done')
        self.assertEqual(words[:2], (b.lw(8, gates.TAG, 22), b.sw(0, gates.TAG, 22)))
        for instruction in (b.lw(8, gates.STATUS, 22), b.lw(8, gates.RAW_SP, 22),
                            b.lw(8, gates.SAVE[25], 29)):
            self.assertIn(instruction, words)
        for value in (gates.ARMED, 0xFFFFFFFF, 0, gates.REGISTRY_UNLOCK):
            self.assertIn(b.lui(9, value >> 16), words)
            self.assertIn(b.ori(9, 9, value & 0xFFFF), words)
        self.assertEqual(words[-3:], (b.lui(8, gates.SELECTED >> 16),
                                     b.ori(8, 8, gates.SELECTED & 0xFFFF), b.sw(8, gates.TAG, 22)))

    def test_raw_scope_uses_restored_S1_and_two_saved_PCs_before_following_D(self):
        for name in ('raw_release_call', 'raw_release_return'):
            words = self.core_words(name, name + '_classified')
            with self.subTest(phase=name):
                scope = words[1 + len(gates.SAVE) + 6:]
                accesses = [word for word in scope if word >> 26 in (32, 33, 35, 36, 37, 40, 41, 43)]
                self.assertEqual(accesses, [b.lw(8, gates.SAVE[17], 29),
                                           b.lw(8, 0x1C, 23), b.lw(8, 0x3C, 23)])
                self.assertEqual(scope[-1], b.addiu(22, 23, 64))
                for value in (ARGS[3], 0x437DB0, 0x493F4C):
                    self.assertIn(b.lui(9, value >> 16), scope)
                    self.assertIn(b.ori(9, 9, value & 0xFFFF), scope)
                self.assertNotIn(b.lw(8, gates.SAVE[16], 29), scope)
        # The delete tail restored outer S1=U before entering its facade;
        # outer S0 is the view and does not classify this release chain.

    def test_raw_call_binds_actual_argument_callback_and_exact_wrapper_SP(self):
        words = self.core_words('raw_release_call_classified', 'raw_release_call_done')
        self.assertEqual(words[:2], (b.lw(8, gates.TAG, 22), b.sw(0, gates.TAG, 22)))
        for instruction in (b.lw(8, gates.STATUS, 22), b.lw(8, gates.RAW_SP, 22),
                            b.lw(8, gates.SAVE[4], 29), b.lw(8, gates.SAVE[25], 29),
                            b.sw(23, gates.RAW_SP, 22)):
            self.assertIn(instruction, words)
        self.assertLess(words.index(b.lw(8, gates.SAVE[4], 29)),
                        words.index(b.sw(23, gates.RAW_SP, 22)))
        for value in (gates.SELECTED, 0xFFFFFFFF, 0, ARGS[4], gates.REGISTRY_UNLOCK):
            self.assertIn(b.lui(9, value >> 16), words)
            self.assertIn(b.ori(9, 9, value & 0xFFFF), words)
        self.assertEqual(words[-3:], (b.lui(8, gates.ENTERED >> 16),
                                     b.ori(8, 8, gates.ENTERED & 0xFFFF), b.sw(8, gates.TAG, 22)))

    def test_raw_return_captures_actual_V0_without_post_service_argument_reconstruction(self):
        words = self.core_words('raw_release_return_classified', 'raw_release_return_done')
        accesses = [word for word in words if word >> 26 in (32, 33, 35, 36, 37, 40, 41, 43)]
        self.assertEqual(accesses, [b.lw(8, gates.SAVE[31], 29),
                                   b.lw(8, gates.TAG, 22), b.sw(0, gates.TAG, 22),
                                   b.lw(8, gates.RAW_SP, 22), b.lw(8, gates.SAVE[2], 29),
                                   b.sw(8, gates.STATUS, 22), b.sw(8, gates.TAG, 22)])
        self.assertNotIn(b.lw(8, gates.SAVE[4], 29), words)
        self.assertNotIn(b.lw(8, gates.SAVE[25], 29), words)
        self.assertEqual(words[-3:], (b.lui(8, gates.CAPTURED >> 16),
                                     b.ori(8, 8, gates.CAPTURED & 0xFFFF), b.sw(8, gates.TAG, 22)))

    def test_complete_consumes_tag_but_preserves_incoming_nonzero_before_release_checks(self):
        code, labels = gates.assemble(*CORE_ARGS)
        words = self.core_words('complete_classified', 'complete_admitted')
        self.assertEqual(words[:3], (b.lw(8, gates.TAG, 22), b.sw(0, gates.TAG, 22),
                                    b.lw(10, gates.SAVE[2], 29)))
        branch = words[3]
        self.assertEqual((branch >> 26, (branch >> 21) & 31, (branch >> 16) & 31), (5, 10, 0))
        immediate = branch & 0xFFFF
        immediate -= 0x10000 if immediate & 0x8000 else 0
        self.assertEqual(labels['complete_classified'] + 12 + 4 + immediate * 4,
                         labels['complete_admitted'])
        raw_index = words.index(b.lw(8, gates.RAW_SP, 22))
        status_index = words.index(b.lw(8, gates.STATUS, 22))
        self.assertGreater(raw_index, 3)
        self.assertGreater(status_index, raw_index)
        self.assertIn(b.addiu(9, 23, -64), words)
        self.assertNotIn(b.lw(8, gates.SAVE[3], 29), words)
        scope = self.core_words('complete', 'complete_classified')
        self.assertIn(b.lw(8, gates.SAVE[17], 29), scope)
        self.assertIn(b.lw(8, gates.SAVE[31], 29), scope)
        # T2 holds saved V0, leaving the consumed tag in T0 for the zero case.

    def test_all_legacy_delegates_receive_full_architecture_after_private_phase(self):
        for name, legacy in zip(LEGACY_NAMES, LEGACY_ENTRIES):
            with self.subTest(phase=name):
                self.assertEqual(self.core_words(name + '_done', name + '_replay'),
                                 self.restored_architecture())
                code, labels = gates.assemble(*CORE_ARGS)
                start = labels[name + '_replay']
                self.assertEqual(self.fragment(code, CORE_ARGS[2], start, start + 8),
                                 (b.j_type(2, legacy), 0))
        self.assertEqual(self.core_words('complete_denied', 'complete_done'),
                         (*self.restored_architecture(denied=True), b.j_type(2, LEGACY_ENTRIES[3]), 0))

    def test_selection_replays_native_saved_RA_S4_once_without_relocating_tail_return(self):
        self.assertEqual(self.core_words('release_select_done', 'release_select_replay'),
                         self.restored_architecture())
        self.assertEqual(self.core_words('release_select_replay', 'raw_release_call'),
                         (*gates.HOOKS['release_select'][1], b.j_type(2, 0x439660), 0))

    def test_protocol_accesses_only_private_or_genuine_native_frames_and_calls_no_service(self):
        code, _ = gates.assemble(*CORE_ARGS)
        words = self.fragment(code, CORE_ARGS[2], CORE_ARGS[2], CORE_ARGS[2] + len(code))
        accesses = [word for word in words if word >> 26 in (32, 33, 35, 36, 37, 40, 41, 43)]
        self.assertEqual({(word >> 21) & 31 for word in accesses}, {22, 23, 29})
        carrier_stores = [word for word in accesses if word >> 26 in (40, 41, 43)
                          and (word >> 21) & 31 != 29]
        self.assertEqual({(word >> 21) & 31 for word in carrier_stores}, {22})
        self.assertEqual({word & 0xFFFF for word in carrier_stores}, {0x14, 0x18, 0x1C})
        self.assertFalse(any(word >> 26 == 3 for word in words))
        self.assertFalse(any(word >> 26 == 0 and word & 63 == 9 for word in words))

    def test_all_four_delegates_are_preceding_distinct_generated_entries(self):
        for index in range(len(CORE_ARGS)):
            for value in (True, False, None, 0, -4, 1, 1.0, '16',
                          0x400000, 0xFFFFFFFC, 0x100000000):
                args = list(CORE_ARGS)
                args[index] = value
                with self.subTest(index=index, value=value), self.assertRaises(ValueError):
                    gates.assemble(*args)
        for index in range(3, 7):
            for value in (0x1000, CORE_ARGS[0], CORE_ARGS[1], CORE_ARGS[2], CORE_ARGS[2] + 4):
                args = list(CORE_ARGS)
                args[index] = value
                with self.subTest(index=index, overlap=value), self.assertRaises(ValueError):
                    gates.assemble(*args)
        for index, value in ((0, CORE_ARGS[1]), (1, CORE_ARGS[0]),
                              (2, CORE_ARGS[0]), (2, CORE_ARGS[1]),
                              (0, CORE_ARGS[2]), (1, CORE_ARGS[2]),
                              (2, 0x10000000), (2, 0x0FFFFFFC)):
            args = list(CORE_ARGS)
            args[index] = value
            with self.subTest(index=index, overlap=value), self.assertRaises(ValueError):
                gates.assemble(*args)
        for first in range(3, 7):
            for second in range(first + 1, 7):
                args = list(CORE_ARGS)
                args[second] = args[first]
                with self.subTest(duplicate=(first, second)), self.assertRaises(ValueError):
                    gates.assemble(*args)

    def test_extra_data_excludes_full_U_R_and_all_four_legacy_entries(self):
        baseline = gates.assemble(*CORE_ARGS)
        for extra in (((0x1F90000, 4),), ((0xFFFFFFFC, 4),)):
            self.assertEqual(gates.assemble(*CORE_ARGS, extra_protected_data=extra), baseline)
        for extra in (None, [], ((True, 4),), ((0x1F90000, True),),
                      ((0x1F90000, 0),), ((0x1F90000, 3),), ((0xFFFFFFFC, 8),),
                      ((0x400000, 4),), ((CORE_ARGS[0], 4),), ((CORE_ARGS[0] + 0x288, 4),),
                      ((CORE_ARGS[1] + 20, 4),), ((CORE_ARGS[2], 4),),
                      *(((entry, 4),) for entry in LEGACY_ENTRIES),
                      ((CORE_ARGS[2] + len(baseline[0]) - 4, 4),),
                      ((0x1F90000, 8), (0x1F90004, 4))):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                gates.assemble(*CORE_ARGS, extra_protected_data=extra)

    def test_complete_RX_contains_every_delegate_and_the_entire_new_fragment(self):
        baseline = gates.assemble(*CORE_ARGS)
        size = CORE_ARGS[2] + len(baseline[0]) - LEGACY_ENTRIES[0]
        for protected in (None, (LEGACY_ENTRIES[0], size), (LEGACY_ENTRIES[0] - 4, size + 8)):
            self.assertEqual(gates.assemble(*CORE_ARGS, protected_code=protected), baseline)
        for protected in ([], (), (True, size), (LEGACY_ENTRIES[0], True),
                          (LEGACY_ENTRIES[0], 0), (LEGACY_ENTRIES[0], 3),
                          (LEGACY_ENTRIES[0], size - 4), (LEGACY_ENTRIES[0] + 4, size),
                          (CORE_ARGS[2], len(baseline[0])), (0x400000, 0x2000000),
                          (CORE_ARGS[0], 0x1000000), (0xFFFFFFC, 8)):
            with self.subTest(protected=protected), self.assertRaises(ValueError):
                gates.assemble(*CORE_ARGS, protected_code=protected)

    def test_hook_targets_are_strict_and_every_native_redirect_has_NOP_delay(self):
        _, labels = gates.assemble(*CORE_ARGS)
        for name, (pc, _) in gates.HOOKS.items():
            self.assertEqual(gates.hook_words(labels)[pc], (b.j_type(2, labels[name]), 0))
            for value in (True, False, None, 0, -4, 1, 0x10000000, 0x100000000):
                with self.subTest(name=name, target=value), self.assertRaises(ValueError):
                    gates.hook_words(dict(labels, **{name: value}))

    def test_all_nineteen_prior_default_hashes_and_zero_parent_extension_are_preserved(self):
        preceding.DestructorContinuationGateContractTests.test_all_eighteen_prior_hashes_and_zero_parent_extension_are_preserved(self)
        parent = parent_stage.assemble(*STAGE_ARGS)
        self.assertEqual((len(parent['code']), hashlib.sha256(parent['code']).hexdigest()),
                         (89640, preceding.GATED_SHA256))
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

    @staticmethod
    def legacy_entries(parent):
        return {'begin': parent['retirement_labels']['delete_begin'],
                'raw_release_call': parent['registry_release_gate_labels']['raw_release_call'],
                'raw_release_return': parent['registry_release_gate_labels']['raw_release_return'],
                'complete': parent['destructor_continuation_gate_labels']['gate']}

    def test_stage_appends_exact_bound_tail_after_full_guarded_prefix(self):
        result = stage.assemble(*STAGE_ARGS)
        prefix, tail = (result['delete_release_gate_prefix_code_bytes'],
                        result['delete_release_gate_code_bytes'])
        self.assertEqual((prefix, tail, len(result['code'])), (89640, 2300, 91940))
        self.assertEqual(prefix + tail, len(result['code']))
        self.assertEqual(hashlib.sha256(result['code']).hexdigest(), GATED_SHA256)
        full = (ARGS[6], len(result['code']))
        self.assertEqual(result['protected_code_extent'], full)
        parent = parent_stage.assemble(*STAGE_ARGS, following_code_bytes=tail)
        self.assertEqual(parent['protected_code_extent'], full)
        self.assertEqual(parent['code'], result['code'][:prefix])
        legacy = self.legacy_entries(parent)
        self.assertEqual(result['delete_release_gate_legacy_entries'], legacy)
        emitted, labels = gates.assemble(ARGS[3], ARGS[4], ARGS[6] + prefix,
                                         *legacy.values(), protected_code=full)
        self.assertEqual((emitted, labels), (result['code'][prefix:], result['delete_release_gate_labels']))
        for name, address in labels.items():
            self.assertEqual(result['labels']['delete_release_gate_' + name], address)

    def test_stage_replaces_four_exact_native_hooks_and_adds_only_common_tail_selection(self):
        result = stage.assemble(*STAGE_ARGS)
        parent = parent_stage.assemble(*STAGE_ARGS)
        new = gates.hook_words(result['delete_release_gate_labels'])
        replaced = {gates.HOOKS[name][0]: parent['coherent_hooks'][gates.HOOKS[name][0]]
                    for name in LEGACY_NAMES}
        self.assertEqual(result['delete_release_gate_replaced_hooks'], replaced)
        self.assertEqual(result['delete_release_gate_hooks'], new)
        self.assertEqual(set(new) - set(parent['coherent_hooks']), {0x439658})
        for pc, pair in replaced.items():
            self.assertNotEqual(new[pc], pair)
        self.assertEqual(result['coherent_hooks'], {**parent['coherent_hooks'], **new})
        self.assertEqual(result['native_coherent_hooks'], {**parent['native_coherent_hooks'], **new})
        self.assertEqual(result['generated_coherent_hooks'], parent['generated_coherent_hooks'])
        self.assertEqual((len(result['native_coherent_hooks']), len(result['generated_coherent_hooks']),
                          len(result['coherent_hooks'])), (23, 1, 24))
        # Provenance maps remain historical. Final coherent overrides give
        # precedence to this layer at begin, both raw sites and completion.
        for key in ('retirement_hooks', 'registry_release_gate_hooks', 'destructor_continuation_gate_hooks'):
            self.assertEqual(result[key], parent[key])

    def test_final_tail_and_following_RX_exclude_every_fixed_data_role(self):
        result = stage.assemble(*STAGE_ARGS)
        for address, following in ((ARGS[6] + len(result['code']) - 4, 0),
                                   (ARGS[6] + len(result['code']), 4)):
            self.assertGreaterEqual(address, ARGS[6] + 89640)
            for index in range(len(STAGE_ARGS)):
                if index == 6:
                    continue
                args = list(STAGE_ARGS)
                args[index] = address
                with self.subTest(data_role=index, following=following), self.assertRaises(ValueError):
                    stage.assemble(*args, following_code_bytes=following)

    def test_stage_limit_flags_keep_local_result_propagation_separate_from_cleanup(self):
        result = stage.assemble(*STAGE_ARGS)
        for flag in ('destructor_name_delete_release_gated', 'delete_release_failure_propagated',
                     'destructor_delete_failure_continuation_stopped'):
            self.assertIs(result[flag], True)
        for flag in ('destructor_entry_fenced', 'earlier_cleanup_rolled_back',
                     'native_callers_isolated', 'raw_release_proven',
                     'native_lifetime_proven', 'partial_graph_cleanup_proven'):
            with self.subTest(flag=flag):
                self.assertIs(result[flag], False)


if __name__ == '__main__':
    unittest.main()
