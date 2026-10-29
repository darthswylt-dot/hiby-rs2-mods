#!/usr/bin/env python3
"""Pin constructor-only release propagation, not publication rollback.

Actual raw status and a fresh private same-invocation witness are required.
Vendor words and generated observer delegation are separately checked. These
contracts grant no ownership, cleanup, complete caller isolation or installer.
"""

import hashlib
import struct
import unittest

from build_reveal_bridge_diag import b
import reveal_creation_capture_mips as capture
import reveal_registry_acquire_gate_mips as acquire
import reveal_registry_receipt_mips as receipt
import reveal_registry_release_gate_mips as gates
import reveal_registry_release_gate_stage as stage
import reveal_explorer_failure_gate_stage as parent_stage
import test_reveal_explorer_failure_gate_contract as preceding
import test_reveal_registry_birth_contract as native


ARGS, STAGE_ARGS = preceding.ARGS, preceding.STAGE_ARGS
LEGACY_NAMES = ('release_call', 'raw_release_call', 'raw_release_return')
LEGACY_ENTRIES = (0x1ED0000, 0x1ED0100, 0x1ED0200)
CORE_ARGS = (ARGS[3], ARGS[4], 0x1EE0000, *LEGACY_ENTRIES)
GATED_SHA256 = '03ec46d436914eef93a8aa118496608d59df4539926dc6272ff81449e50687de'


class RegistryReleaseGateContractTests(unittest.TestCase):
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

    def test_four_source_pairs_follow_publication_and_both_status_masks(self):
        expected = {
            'release_select': (0x438A60, (0x0320F809, 0x02002021)),
            'raw_release_call': (0x466DC8, (0x0C296E0C, 0)),
            'raw_release_return': (0x466DD0, (0x8FBF001C, 0x00001021)),
            'complete': (0x438A68, (0x00001021, 0x8FBF0024)),
        }
        self.assertEqual(gates.HOOKS, expected)
        for site, pair in expected.values():
            self.words(site, pair)
        self.words(0x438A58, [0xAC620000, 0x8E190278])
        self.assertLess(0x438A58, 0x438A60)
        # Release denial occurs after final publication; it cannot undo links.

    def test_facade_and_raw_frame_chain_and_original_return_PCs_are_exact(self):
        self.words(0x437DA0, [0x27BDFFE0, 0xAFBF001C, 0x0C119B70,
                              0x8C84013C, 0x8FBF001C, 0x03E00008, 0x27BD0020])
        self.words(0x466DC0, [0x27BDFFE0, 0xAFBF001C, 0x0C296E0C, 0,
                              0x8FBF001C, 0x00001021, 0x03E00008, 0x27BD0020])
        self.assertEqual((gates.REGISTER_FRAME, gates.FACADE_FRAME, gates.RAW_FRAME),
                         (40, 32, 32))
        self.assertEqual((gates.REGISTRATION_RELEASE_RETURN, gates.RAW_RELEASE_RETURN),
                         (0x438A68, 0x466DD0))
        self.assertEqual(0x437DA8 + 8, 0x437DB0)
        self.assertEqual(0x20 + 0x1C, 0x3C)
        self.assertEqual(0x20 + 0x20 + 0x24, 0x64)

    def test_registration_local_reuse_is_after_acquisition_publication_consumption(self):
        self.assertEqual((receipt.TAG, receipt.PTR, receipt.RAW_STATUS), (0x10, 0x14, 0x18))
        self.assertEqual((gates.TAG, gates.STATUS, gates.RAW_SP), (0x10, 0x14, 0x18))
        explicit = {self.elf.word(pc) & 0xFFFF
                    for pc in range(0x4389F0, 0x438A90, 4)
                    if self.elf.word(pc) >> 26 in (32, 33, 35, 36, 37, 40, 41, 43)
                    and (self.elf.word(pc) >> 21) & 31 == 29}
        self.assertEqual(explicit, {0x1C, 0x20, 0x24})
        parent = parent_stage.assemble(*STAGE_ARGS)
        labels = parent['receipt_labels']
        publication = self.fragment(parent['code'], ARGS[6], labels['published'],
                                    labels['published_done'])
        take = publication.index(b.lw(8, receipt.TAG, 23))
        self.assertEqual(publication[take + 1], b.sw(0, receipt.TAG, 23))
        first_callback = next(index for index, word in enumerate(publication)
                              if word >> 26 == 3)
        self.assertLess(take + 1, first_callback)
        self.assertEqual(publication[0], 0xAC620000)
        # No active receipt is overwritten: all synchronous publication
        # observers return before the native release selection point.

    def test_completion_delay_word_keeps_both_independent_native_failure_entries(self):
        self.words(0x438A18, [0x10400019, 0x26050034])
        self.words(0x438A80, [0x1000FFFA, 0x2402FFFF])
        self.assertEqual(self.branches[0x438A80], 0x438A6C)
        self.assertEqual(acquire.REGISTER_EPILOGUE, 0x438A6C)
        self.words(0x438A6C, [0x8FBF0024, 0x8FB10020, 0x8FB0001C,
                              0x03E00008, 0x27BD0028])
        _, labels = gates.assemble(*CORE_ARGS)
        hooks = gates.hook_words(labels)
        self.assertEqual(hooks[0x438A68], (b.j_type(2, labels['complete']), 0x8FBF0024))
        for pc in (0x438A60, 0x466DC8, 0x466DD0):
            self.assertEqual(hooks[pc][1], 0)
        #438A6C is BOTH the complete hook's delay and a direct failure entry.
        #Replacing it with NOP would corrupt allocation/acquisition failures.

    def test_bounded_incoming_census_includes_the_completion_second_word_exception(self):
        for site in (0x438A60, 0x438A64, 0x438A68,
                     0x466DC8, 0x466DCC, 0x466DD0, 0x466DD4):
            with self.subTest(site=hex(site)):
                self.assertEqual({pc for pc, target in self.jumps.items() if target == site}, set())
                self.assertEqual({pc for pc, target in self.branches.items() if target == site}, set())
        self.assertEqual({pc for pc, target in self.branches.items() if target == 0x438A6C},
                         {0x438A80})
        # Encoded scans cannot exclude fabricated returns or computed entries.

    def test_global_raw_wrapper_154_callers_and_five_raw_sites_are_not_global_coverage(self):
        self.assertEqual(len({pc for pc, target in self.jumps.items() if target == 0x466DC0}), 154)
        self.assertEqual({pc for pc, target in self.jumps.items() if target == receipt.RAW_UNLOCK},
                         {0x466DC8, 0x57E208, 0x706D4C, 0x708FAC, 0x70B46C})
        self.assertEqual({pc for pc, target in self.jumps.items() if target == receipt.REGISTRY_UNLOCK},
                         set())
        self.assertEqual(gates.CONSTRUCTOR_RETURNS, (0x43AE94, 0x43B038))
        # Only two genuine constructor registration returns for pinned U gain
        # this protocol; other wrappers/services remain historical delegates.

    def test_all_architecture_is_saved_before_scope_and_legacy_delegation(self):
        expected = {register: 0x10 + index * 4
                    for index, register in enumerate(
                        register for register in range(1, 32) if register != 29)}
        self.assertEqual(gates.SAVE, expected)
        self.assertEqual((gates.FRAME, gates.HI, gates.LO, gates.RAW), (192, 0x88, 0x8C, 0x90))
        prefix = (b.addiu(29, 29, -192),
                  *(b.sw(register, offset, 29) for register, offset in expected.items()),
                  b.r_type(0, 0, 8, 0x10), b.sw(8, 0x88, 29),
                  b.r_type(0, 0, 8, 0x12), b.sw(8, 0x8C, 29),
                  b.sw(0, 0x90, 29), b.addiu(23, 29, 192))
        for name in gates.HOOKS:
            with self.subTest(phase=name):
                words = self.core_words(name, name + '_classified')
                self.assertEqual(words[:len(prefix)], prefix)
        # Complete's retained native LWRA delay executes before this save.

    def test_scope_uses_private_saved_S0_and_two_native_registration_callers(self):
        for name in gates.HOOKS:
            with self.subTest(phase=name):
                words = self.core_words(name, name + '_classified')
                self.assertIn(b.lw(8, gates.SAVE[16], 29), words)
                self.assertIn(b.lw(8, 0x24, 22), words)
                for value in (ARGS[3], 0x43AE94, 0x43B038):
                    self.assertIn(b.lui(9, value >> 16), words)
                    self.assertIn(b.ori(9, 9, value & 0xFFFF), words)
                self.assertNotIn(b.lw(8, gates.SAVE[3], 29), words)

    def test_selection_freshens_all_three_native_slots_before_callback_check(self):
        words = self.core_words('release_select_classified', 'release_select_done')
        fresh = (b.sw(0, gates.TAG, 22), b.addiu(8, 0, -1),
                 b.sw(8, gates.STATUS, 22), b.sw(0, gates.RAW_SP, 22),
                 b.lw(8, gates.SAVE[25], 29))
        self.assertEqual(words[:len(fresh)], fresh)
        self.assertIn(b.lui(9, receipt.REGISTRY_UNLOCK >> 16), words)
        self.assertIn(b.ori(9, 9, receipt.REGISTRY_UNLOCK & 0xFFFF), words)
        self.assertEqual(words[-1], b.sw(8, gates.TAG, 22))
        self.assertEqual(len({gates.SELECTED, gates.ENTERED, gates.CAPTURED,
                              receipt.ARMED, receipt.ENTERED, receipt.CAPTURED}), 6)

    def test_raw_call_binds_actual_precall_argument_and_fresh_raw_frame(self):
        words = self.core_words('raw_release_call_classified', 'raw_release_call_done')
        self.assertEqual(words[:2], (b.lw(8, gates.TAG, 22), b.sw(0, gates.TAG, 22)))
        for instruction in (b.lw(8, gates.STATUS, 22), b.lw(8, gates.RAW_SP, 22),
                            b.lw(8, gates.SAVE[4], 29), b.lw(8, gates.SAVE[25], 29),
                            b.sw(23, gates.RAW_SP, 22)):
            self.assertIn(instruction, words)
        self.assertLess(words.index(b.lw(8, gates.SAVE[4], 29)),
                        words.index(b.sw(23, gates.RAW_SP, 22)))
        self.assertEqual(words[-1], b.sw(8, gates.TAG, 22))

    def test_raw_return_never_reconstructs_clobbered_A0_or_T9_or_shared_mutex_fields(self):
        words = self.core_words('raw_release_return', 'raw_release_return_done')
        self.assertIn(b.lw(8, gates.SAVE[31], 29), words)
        self.assertIn(b.lw(8, gates.SAVE[2], 29), words)
        self.assertIn(b.sw(8, gates.STATUS, 22), words)
        self.assertIn(b.lw(8, gates.RAW_SP, 22), words)
        self.assertNotIn(b.lw(8, gates.SAVE[4], 29), words)
        self.assertNotIn(b.lw(8, gates.SAVE[25], 29), words)
        self.assertEqual(words[-1], b.sw(8, gates.TAG, 22))

    def test_raw_phase_chain_checks_both_saved_return_frames_before_deeper_native_frame(self):
        for name in ('raw_release_call', 'raw_release_return'):
            words = self.core_words(name, name + '_classified')
            with self.subTest(phase=name):
                first = words.index(b.lw(8, 0x1C, 23))
                second = words.index(b.lw(8, 0x3C, 23))
                deeper = words.index(b.lw(8, 0x24, 22))
                self.assertLess(first, second)
                self.assertLess(second, deeper)
                for value in (0x437DB0, 0x438A68):
                    self.assertIn(b.lui(9, value >> 16), words)
                    self.assertIn(b.ori(9, 9, value & 0xFFFF), words)

    def test_three_bridges_restore_all_architecture_then_tail_chain_old_observer_once(self):
        for name, legacy in zip(('release_select', 'raw_release_call', 'raw_release_return'),
                                LEGACY_ENTRIES):
            with self.subTest(phase=name):
                self.assertEqual(self.core_words(name + '_done', name + '_replay'),
                                 self.restored_architecture())
                code, labels = gates.assemble(*CORE_ARGS)
                replay = self.fragment(code, CORE_ARGS[2], labels[name + '_replay'],
                                       labels[name + '_replay'] + 8)
                self.assertEqual(replay, (b.j_type(2, legacy), 0))

    def test_completion_consumes_capture_and_raw_frame_identity_before_status(self):
        words = self.core_words('complete_classified', 'complete_admitted')
        self.assertEqual(words[:2], (b.lw(8, gates.TAG, 22), b.sw(0, gates.TAG, 22)))
        self.assertIn(b.addiu(9, 23, -64), words)
        self.assertLess(words.index(b.lw(8, gates.RAW_SP, 22)),
                        words.index(b.lw(8, gates.STATUS, 22)))
        self.assertIn(b.sw(8, gates.RAW, 29), words)
        self.assertEqual((gates.COMPLETE_CONTINUATION, gates.REGISTRATION_EPILOGUE),
                         (0x438A70, 0x438A6C))

    def test_completion_replay_and_denial_use_early_loaded_RA_without_reloading_source_delay(self):
        self.assertEqual(self.core_words('complete_replay', None),
                         (b.move(2, 0), b.j_type(2, 0x438A70), 0))
        denied = self.core_words('complete_denied', 'complete_done')
        self.assertEqual(denied, (*self.restored_architecture(denied=True),
                                  b.j_type(2, 0x438A70), 0))
        # The native438A6C delay already restored RA exactly once. Unknown
        # evidence leaves RAW=0; observed nonzero preserves its exact word.

    def test_entire_fragment_accesses_only_owned_frames_and_never_calls_new_services(self):
        code, _ = gates.assemble(*CORE_ARGS)
        words = self.fragment(code, CORE_ARGS[2], CORE_ARGS[2], CORE_ARGS[2] + len(code))
        accesses = [word for word in words if word >> 26 in (32, 33, 35, 36, 37, 40, 41, 43)]
        self.assertEqual({(word >> 21) & 31 for word in accesses}, {22, 23, 29})
        native_stores = [word for word in accesses
                         if word >> 26 in (40, 41, 43) and (word >> 21) & 31 == 22]
        self.assertEqual({word & 0xFFFF for word in native_stores}, {0x10, 0x14, 0x18})
        self.assertFalse(any(word >> 26 == 3 for word in words))
        self.assertFalse(any(word >> 26 == 0 and word & 63 == 9 for word in words))

    def test_hook_targets_are_strict_and_completion_source_delay_is_not_erased(self):
        _, labels = gates.assemble(*CORE_ARGS)
        for name, (pc, _) in gates.HOOKS.items():
            for value in (True, False, None, 0, -4, 1, 0x10000000, 0x100000000):
                with self.subTest(name=name, target=value), self.assertRaises(ValueError):
                    gates.hook_words(dict(labels, **{name: value}))
            expected_delay = 0x8FBF0024 if name == 'complete' else 0
            self.assertEqual(gates.hook_words(labels)[pc],
                             (b.j_type(2, labels[name]), expected_delay))

    def test_primary_static_layout_and_all_legacy_entries_are_strict(self):
        for index in range(len(CORE_ARGS)):
            for value in (True, False, None, 0, -4, 1, 1.0, '16',
                          0x400000, 0xFFFFFFFC, 0x100000000):
                args = list(CORE_ARGS)
                args[index] = value
                with self.subTest(index=index, value=value), self.assertRaises(ValueError):
                    gates.assemble(*args)
        for index in (3, 4, 5):
            for value in (0x1000, CORE_ARGS[0], CORE_ARGS[1], CORE_ARGS[2], CORE_ARGS[2] + 4):
                args = list(CORE_ARGS)
                args[index] = value
                with self.subTest(index=index, overlap=value), self.assertRaises(ValueError):
                    gates.assemble(*args)
        for index in (4, 5):
            args = list(CORE_ARGS)
            args[index] = args[3]
            with self.subTest(duplicate=index), self.assertRaises(ValueError):
                gates.assemble(*args)

    def test_extra_static_data_does_not_invent_runtime_mapping_or_lifetime_guards(self):
        baseline = gates.assemble(*CORE_ARGS)
        for extra in (((0x1F90000, 4),), ((0xFFFFFFFC, 4),)):
            self.assertEqual(gates.assemble(*CORE_ARGS, extra_protected_data=extra), baseline)
        for extra in (None, [], ((True, 4),), ((0x1F90000, True),),
                      ((0x1F90000, 0),), ((0x1F90000, 3),), ((0xFFFFFFFC, 8),),
                      ((0x400000, 4),), ((CORE_ARGS[0], 4),), ((CORE_ARGS[1], 4),),
                      ((CORE_ARGS[2], 4),), ((LEGACY_ENTRIES[0], 4),),
                      ((LEGACY_ENTRIES[1], 4),), ((LEGACY_ENTRIES[2], 4),),
                      ((0x1F90000, 8), (0x1F90004, 4))):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                gates.assemble(*CORE_ARGS, extra_protected_data=extra)

    def test_complete_RX_must_contain_all_three_legacy_entries_and_entire_fragment(self):
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

    def test_all_seventeen_prior_default_hashes_and_zero_parent_extension_are_preserved(self):
        preceding.ExplorerFailureGateContractTests.test_parent_zero_default_and_all_sixteen_prior_composition_hashes_are_preserved(self)
        parent = parent_stage.assemble(*STAGE_ARGS)
        self.assertEqual((len(parent['code']), hashlib.sha256(parent['code']).hexdigest()),
                         (87168, preceding.GATED_SHA256))
        self.assertEqual(parent_stage.assemble(*STAGE_ARGS, following_code_bytes=0), parent)

    def test_parent_following_RX_is_strict_protected_not_appended_and_keeps_hook_labels(self):
        parent = parent_stage.assemble(*STAGE_ARGS)
        extended = parent_stage.assemble(*STAGE_ARGS, following_code_bytes=4)
        self.assertEqual(len(parent['code']), len(extended['code']))
        self.assertEqual(parent['labels'], extended['labels'])
        self.assertEqual(parent['coherent_hooks'], extended['coherent_hooks'])
        self.assertEqual(extended['protected_code_extent'], (ARGS[6], len(parent['code']) + 4))
        self.assertNotEqual(parent['code'], extended['code'])
        for value in (True, False, None, -4, 1, 2, 3, 1.0, '4', 0x100000000):
            with self.subTest(following=value), self.assertRaises(ValueError):
                parent_stage.assemble(*STAGE_ARGS, following_code_bytes=value)

    def test_stage_uses_exact_guarded_prefix_old_observer_entries_and_bound_tail(self):
        result = stage.assemble(*STAGE_ARGS)
        prefix, tail = (result['registry_release_gate_prefix_code_bytes'],
                        result['registry_release_gate_code_bytes'])
        self.assertEqual((prefix, tail, len(result['code'])), (87168, 1972, 89140))
        self.assertEqual(hashlib.sha256(result['code']).hexdigest(), GATED_SHA256)
        self.assertEqual(prefix + tail, len(result['code']))
        full = (ARGS[6], len(result['code']))
        self.assertEqual(result['protected_code_extent'], full)
        parent = parent_stage.assemble(*STAGE_ARGS, following_code_bytes=tail)
        self.assertEqual(parent['protected_code_extent'], full)
        self.assertEqual(parent['code'], result['code'][:prefix])
        legacy = {name: parent['capture_labels'][name] for name in LEGACY_NAMES}
        self.assertEqual(result['registry_release_gate_legacy_entries'], legacy)
        emitted, labels = gates.assemble(ARGS[3], ARGS[4], ARGS[6] + prefix,
                                         *legacy.values(), protected_code=full)
        self.assertEqual((emitted, labels), (result['code'][prefix:], result['registry_release_gate_labels']))
        for name, address in labels.items():
            self.assertEqual(result['labels']['registry_release_gate_' + name], address)

    def test_stage_replaces_exact_three_old_native_hooks_and_adds_one_completion(self):
        result = stage.assemble(*STAGE_ARGS)
        parent = parent_stage.assemble(*STAGE_ARGS)
        old = capture.hook_words(parent['capture_labels'])
        replaced = {capture.HOOKS[name][0]: old[capture.HOOKS[name][0]] for name in LEGACY_NAMES}
        self.assertEqual(result['registry_release_gate_replaced_hooks'], replaced)
        self.assertEqual(result['release_hooks'], parent['release_hooks'])
        for pc, pair in replaced.items():
            self.assertEqual(parent['coherent_hooks'][pc], pair)
            self.assertNotEqual(result['coherent_hooks'][pc], pair)
        new = gates.hook_words(result['registry_release_gate_labels'])
        self.assertEqual(result['registry_release_gate_hooks'], new)
        self.assertEqual(set(new) - set(parent['coherent_hooks']), {0x438A68})
        self.assertEqual(result['coherent_hooks'], {**parent['coherent_hooks'], **new})
        self.assertEqual(result['native_coherent_hooks'], {**parent['native_coherent_hooks'], **new})
        self.assertEqual(result['generated_coherent_hooks'], parent['generated_coherent_hooks'])
        self.assertEqual((len(result['native_coherent_hooks']), len(result['generated_coherent_hooks']),
                          len(result['coherent_hooks'])), (21, 1, 22))

    def test_stage_rejects_fixed_data_in_final_tail_and_keeps_scope_limit_flags(self):
        result = stage.assemble(*STAGE_ARGS)
        tail_word = ARGS[6] + len(result['code']) - 4
        self.assertGreaterEqual(tail_word, ARGS[6] + 87168)
        for index in range(len(STAGE_ARGS)):
            if index == 6:
                continue
            args = list(STAGE_ARGS)
            args[index] = tail_word
            with self.subTest(data_role=index), self.assertRaises(ValueError):
                stage.assemble(*args)
        for flag in ('constructor_registration_release_gated', 'registration_release_failure_propagated',
                     'explorer_failed_registration_continuation_stopped'):
            with self.subTest(flag=flag):
                self.assertIs(result[flag], True)
        for flag in ('partial_graph_cleanup_proven', 'native_callers_isolated',
                     'raw_release_proven', 'native_lifetime_proven'):
            with self.subTest(flag=flag):
                self.assertIs(result[flag], False)


if __name__ == '__main__':
    unittest.main()
