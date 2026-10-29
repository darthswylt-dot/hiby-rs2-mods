#!/usr/bin/env python3
"""Bounded constructor-result continuation contracts, not caller isolation.

The hash-pinned vendor image supplies native facts. Private saved U/RA/V0
classification is not frame authentication, a release certificate or an engine
lease. No hook installer, firmware/player operation or network I/O is used.
"""

import hashlib
import struct
import unittest

from build_reveal_bridge_diag import b
import reveal_constructor_continuation_gate_mips as gates
import reveal_constructor_continuation_gate_stage as stage
import reveal_registry_acquire_gate_stage as acquire_stage
import reveal_registry_receipt_mips as receipt
import test_reveal_registry_acquire_gate_contract as preceding
import test_reveal_registry_birth_contract as native


ARGS, STAGE_ARGS = preceding.ARGS, preceding.STAGE_ARGS
CORE_ARGS = (ARGS[3], ARGS[4], 0x1EE0000)
ACQUIRE_SHA256 = 'a4c3ec89cc4a7b01b2f385abfb5daf2146694a48a03118aaaaea756b524a4041'
GATED_SHA256 = 'c13d8485f4644b90c1dd2029877a13626cd5d7231e6fa65c54ff6ec87f208dd8'


class ConstructorContinuationGateContractTests(unittest.TestCase):
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
                *(b.lw(register, offset, 29)
                  for register, offset in gates.SAVE.items()),
                b.addiu(29, 29, gates.FRAME))

    def test_both_displaced_pairs_are_the_original_post_registration_UI_calls(self):
        expected = {
            'first_gate': (0x43AE94, (0x0C1467E8, 0x02202021)),
            'second_gate': (0x43B038, (0x0C1467E8, 0x02202021)),
        }
        self.assertEqual(gates.HOOKS, expected)
        self.assertEqual(list(self.elf.executable_ranges()), [receipt.NATIVE_RX])
        for site, pair in expected.values():
            self.words(site, pair)
        self.assertEqual(gates.POSTWORK, 0x519FA0)

    def test_genuine_registration_calls_have_the_exact_scope_return_addresses(self):
        self.words(0x43AE88, [0x02202021, 0x0C10E278, 0x27A50050])
        self.words(0x43B02C, [0x02202021, 0x0C10E278, 0x27A50050])
        self.assertEqual({pc for pc, target in self.jumps.items()
                          if target == 0x4389E0}, {0x43AE8C, 0x43B030})
        self.assertEqual(0x43AE8C + 8, gates.HOOKS['first_gate'][0])
        self.assertEqual(0x43B030 + 8, gates.HOOKS['second_gate'][0])
        # Only actual saved RA equal to that registration return qualifies.
        # A branch reaching the same UI-call site is not that return.

    def test_native_frame_sizes_and_saved_engine_return_epilogues_are_pinned(self):
        self.assertEqual((gates.FIRST_FRAME, gates.SECOND_FRAME), (136, 128))
        self.words(0x43AD00, [0x27BDFF78, 0xAFBF0084])
        self.words(0x43AF00, [0x27BDFF80, 0xAFB40078,
                              0xAFB30074, 0xAFB1006C])
        self.words(0x43AEA8, [0x8FBF0084, 0x8FA20050, 0x8FB60080,
                              0x8FB5007C, 0x8FB40078, 0x8FB30074,
                              0x8FB20070, 0x8FB1006C, 0x8FB00068,
                              0x03E00008, 0x27BD0088])
        self.words(0x43B04C, [0x8FBF007C, 0x8FA20050, 0x8FB40078,
                              0x8FB30074, 0x8FB20070, 0x8FB1006C,
                              0x8FB00068, 0x03E00008, 0x27BD0080])
        self.assertEqual((gates.FIRST_EPILOGUE, gates.SECOND_EPILOGUE),
                         (0x43AEA8, 0x43B04C))
        # These epilogues return the saved engine, not the registration status.

    def test_original_forward_path_calls_postwork_then_dereferences_saved_engine(self):
        for pc in (0x43AE94, 0x43B038):
            self.words(pc, [0x0C1467E8, 0x02202021, 0x8FA20050,
                            0x0C10DFB8, 0x8C440000])
        self.assertEqual((gates.FIRST_CONTINUATION, gates.SECOND_CONTINUATION),
                         (0x43AE9C, 0x43B040))
        self.words(0x519FB4, [0x27BDFEC0, 0xAFBF013C, 0xAFB10138,
                              0xAFB00134, 0x8C91021C])
        self.words(0x51A018, [0x0C22D0F0, 0xAFA20120])
        self.words(0x51A038, [0x02002021, 0x0C10E830, 0x27A50018])
        #519FA0 is an opaque widget/name-lookup boundary, not a harmless stub.

    def test_first_skipped_registration_resource_and_validation_paths_still_reach_UI(self):
        self.words(0x43AD54, [0x0C1218A8, 0x24A508B4, 0x1040004D])
        self.words(0x43AD6C, [0x0C296C90, 0x00409021, 0x10400047])
        self.assertEqual(self.branches[0x43AD5C], 0x43AE94)
        self.assertEqual(self.branches[0x43AD74], 0x43AE94)
        for actual_return in (0x43AD5C, 0x43AD74):
            self.assertNotEqual(actual_return, gates.HOOKS['first_gate'][0])
        self.words(0x43AE9C, [0x8FA20050, 0x0C10DFB8, 0x8C440000])
        # These paths did not call4389E0. An unrelated nonzero V0 must not
        # invent a safely stopped constructor; the old NULL fault remains.

    def test_engine_NULL_skips_registration_in_both_constructors_and_still_forwards(self):
        self.words(0x43AE80, [0x10400004, 0xAFA30058,
                              0x02202021, 0x0C10E278, 0x27A50050])
        self.words(0x43B024, [0x10400004, 0xAFA00058,
                              0x02202021, 0x0C10E278, 0x27A50050])
        self.assertEqual(self.branches[0x43AE80], 0x43AE94)
        self.assertEqual(self.branches[0x43B024], 0x43B038)
        self.assertNotEqual(0x43AE64 + 8, gates.HOOKS['first_gate'][0])
        self.assertNotEqual(0x43B00C + 8, gates.HOOKS['second_gate'][0])
        self.words(0x43AEA4, [0x8C440000])
        self.words(0x43B048, [0x8C440000])

    def test_second_resource_and_validation_failures_bypass_the_gate_and_return_NULL(self):
        self.words(0x43AF44, [0x0C1218A8, 0x24A508B4, 0x1040003F])
        self.words(0x43AF5C, [0x0C296C90, 0x00408021,
                              0x1040003A, 0x8FBF007C])
        self.assertEqual(self.branches[0x43AF4C], 0x43B04C)
        self.assertEqual(self.branches[0x43AF64], 0x43B050)
        self.words(0x43B050, [0x8FA20050])
        # Unlike the first constructor, these two second-constructor failures
        # already bypass519FA0 and its subsequent name dereference.

    def test_raw_release_failure_is_still_masked_to_the_zero_status_forward_route(self):
        self.words(0x466DC8, [0x0C296E0C, 0, 0x8FBF001C,
                              0x00001021, 0x03E00008, 0x27BD0020])
        self.words(0x438A60, [0x0320F809, 0x02002021,
                              0x00001021, 0x8FBF0024])
        # V0=0 reaches the forward branch even if an independently observed
        # raw release was nonzero. V1 is intentionally not reinterpreted.

    def test_omitting_the_earlier_acquire_gate_can_still_publish_after_raw_acquire_error(self):
        self.words(0x466DA8, [0x0C296E58, 0, 0x8FBF001C,
                              0x00001021, 0x03E00008, 0x27BD0020])
        self.words(0x438A00, [0x8C990274, 0x00808021, 0x0320F809,
                              0x00A08821, 0x0C119A78, 0x2404001C])
        self.words(0x438A48, [0x8E030038, 0xAE020038, 0xAC450000,
                              0xAC430004, 0xAC620000, 0x8E190278])
        self.words(0x438A68, [0x00001021])
        # A post-registration status gate cannot retroactively veto already
        # published native links or detect a facade-masked zero result.

    def test_encoded_constructor_census_is13_first_and46_second_not_indirect_coverage(self):
        callers = {target: [pc for pc, destination in self.jumps.items()
                            if destination == target and self.elf.word(pc) >> 26 == 3]
                   for target in (0x43AD00, 0x43AF00)}
        self.assertEqual(callers[0x43AD00], [
            0x492918, 0x4B90D0, 0x4BC078, 0x4BE24C, 0x4BED38,
            0x4C10D4, 0x4DD7A8, 0x4EABE0, 0x4FBC2C, 0x4FDE8C,
            0x4FE8E0, 0x5123B4, 0x520A1C])
        self.assertEqual(len(callers[0x43AF00]), 46)
        self.words(0x492918, [0x0C10EB40, 0x02003821, 0x8FA417D0,
                              0xAE0200CC, 0x0C10E5A0, 0x00402821])
        # The explorer still stores and enables the returned raw engine. This
        # gate does not make ignored results safe in any higher caller.

    def test_no_encoded_incoming_jump_or_relative_branch_targets_either_delay_slot(self):
        for site in (0x43AE98, 0x43B03C):
            with self.subTest(site=hex(site)):
                self.assertEqual({pc for pc, target in self.jumps.items()
                                  if target == site}, set())
                self.assertEqual({pc for pc, target in self.branches.items()
                                  if target == site}, set())
        # JR/JALR, runtime changes, fabricated returns and arbitrary partial
        # activation are deliberately not classified by this encoded census.

    def test_complete_architecture_is_saved_before_any_scope_or_status_decision(self):
        expected_save = {register: 0x10 + index * 4
                         for index, register in enumerate(
                             register for register in range(1, 32) if register != 29)}
        self.assertEqual(gates.SAVE, expected_save)
        self.assertEqual((gates.FRAME, gates.HI, gates.LO), (192, 0x88, 0x8C))
        expected = (b.addiu(29, 29, -gates.FRAME),
                    *(b.sw(register, offset, 29)
                      for register, offset in gates.SAVE.items()),
                    b.r_type(0, 0, 8, 0x10), b.sw(8, gates.HI, 29),
                    b.r_type(0, 0, 8, 0x12), b.sw(8, gates.LO, 29))
        for name in gates.HOOKS:
            words = self.core_words(name, name + '_stopped')
            with self.subTest(gate=name):
                self.assertEqual(words[:len(expected)], expected)
        # This initial save is why retained mapped writable nonaliasing frames
        # are prerequisites, not established by later scalar classification.

    def test_classification_reads_only_private_saved_S1_RA_and_V0_never_V1_or_engine(self):
        for name in gates.HOOKS:
            words = self.core_words(name, name + '_stopped')
            decision = words[1 + len(gates.SAVE) + 4:]
            accesses = [word for word in decision
                        if word >> 26 in (32, 33, 35, 36, 37, 40, 41, 43)]
            with self.subTest(gate=name):
                self.assertEqual(accesses,
                                 [b.lw(8, gates.SAVE[17], 29),
                                  b.lw(8, gates.SAVE[31], 29),
                                  b.lw(8, gates.SAVE[2], 29)])
                self.assertNotIn(b.lw(8, gates.SAVE[3], 29), decision)
                self.assertNotIn(b.lw(8, gates.FRAME + 0x50, 29), decision)
                self.assertEqual(decision[-2] >> 26, 4)
                self.assertEqual(((decision[-2] >> 21) & 31,
                                  (decision[-2] >> 16) & 31), (8, 0))
        # Private SP+50 contains saved S1 here; native SP+50 would be private
        # SP+110. The gate never inspects that native saved-engine slot.

    def test_scope_compares_saved_U_and_exact_registration_return_before_status(self):
        for name, (pc, _) in gates.HOOKS.items():
            words = self.core_words(name, name + '_stopped')
            with self.subTest(gate=name):
                for value in (ARGS[3], pc):
                    self.assertIn(b.lui(9, value >> 16), words)
                    self.assertIn(b.ori(9, 9, value & 0xFFFF), words)
                s1 = words.index(b.lw(8, gates.SAVE[17], 29))
                ra = words.index(b.lw(8, gates.SAVE[31], 29))
                status = words.index(b.lw(8, gates.SAVE[2], 29))
                self.assertLess(s1, ra)
                self.assertLess(ra, status)
                self.assertEqual(sum(word >> 26 == 5 for word in words), 2)

    def test_stop_restores_every_saved_register_then_enters_the_stock_engine_epilogue(self):
        for name, target in (('first_gate', gates.FIRST_EPILOGUE),
                             ('second_gate', gates.SECOND_EPILOGUE)):
            words = self.core_words(name + '_stopped', name + '_forward')
            with self.subTest(gate=name):
                self.assertEqual(words, (*self.restored_architecture(),
                                         b.j_type(2, target), 0))
                self.assertFalse(any(word >> 26 == 3 for word in words))
                self.assertFalse(any(word >> 26 == 0 and word & 63 == 9
                                     for word in words))
                self.assertFalse(any(word >> 26 in (40, 41, 43) for word in words))
        # The gate does not turn the native engine return into NULL/status,
        # free an allocation, select an unlock or call an opaque continuation.

    def test_forward_restores_architecture_before_replaying_the_original_JAL_effects(self):
        for name in gates.HOOKS:
            words = self.core_words(name + '_forward', name + '_replay')
            with self.subTest(gate=name):
                self.assertEqual(words, self.restored_architecture())
        for name, end, return_pc in (
                ('first_gate', 'second_gate', gates.FIRST_CONTINUATION),
                ('second_gate', None, gates.SECOND_CONTINUATION)):
            words = self.core_words(name + '_replay', end)
            with self.subTest(gate=name):
                self.assertEqual(words,
                                 (b.lui(31, return_pc >> 16),
                                  b.ori(31, 31, return_pc & 0xFFFF),
                                  b.j_type(2, gates.POSTWORK), b.move(4, 17)))

    def test_all_fragment_memory_accesses_use_only_the_private_save_frame(self):
        code, _ = gates.assemble(*CORE_ARGS)
        words = struct.unpack('<' + 'I' * (len(code) // 4), code)
        accesses = [word for word in words
                    if word >> 26 in (32, 33, 35, 36, 37, 40, 41, 43)]
        self.assertEqual({(word >> 21) & 31 for word in accesses}, {29})
        self.assertTrue(all(0x10 <= word & 0xFFFF < gates.FRAME for word in accesses))
        self.assertFalse(any(word >> 26 == 3 for word in words))
        self.assertFalse(any(word >> 26 == 0 and word & 63 == 9 for word in words))

    def test_two_local_hook_words_require_strict_same_region_targets(self):
        _, labels = gates.assemble(*CORE_ARGS)
        hooks = gates.hook_words(labels)
        for name, (pc, _) in gates.HOOKS.items():
            self.assertEqual(hooks[pc], (b.j_type(2, labels[name]), 0))
            for value in (True, False, 0, -4, 1, 0x10000000, 0x100000000):
                with self.subTest(gate=name, target=value), self.assertRaises(ValueError):
                    gates.hook_words(dict(labels, **{name: value}))

    def test_static_extra_extents_do_not_invent_dynamic_frame_or_native_lifetime_checks(self):
        baseline = gates.assemble(*CORE_ARGS)
        for extra in (((0x1F90000, 4),), ((0xFFFFFFFC, 4),)):
            with self.subTest(extra=extra):
                self.assertEqual(gates.assemble(*CORE_ARGS, extra_protected_data=extra),
                                 baseline)
        for extra in (None, [], ((True, 4),), ((0x1F90000, True),),
                      ((0x1F90000, 0),), ((0x1F90000, 3),),
                      ((0xFFFFFFFC, 8),), ((0x400000, 4),),
                      ((CORE_ARGS[0], 4),), ((CORE_ARGS[1], 4),),
                      ((CORE_ARGS[2], 4),), ((0x1F90000, 8), (0x1F90004, 4))):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                gates.assemble(*CORE_ARGS, extra_protected_data=extra)

    def test_complete_protected_RX_is_strict_and_does_not_change_emitted_decisions(self):
        baseline = gates.assemble(*CORE_ARGS)
        size = len(baseline[0])
        for protected in (None, (CORE_ARGS[2], size), (CORE_ARGS[2] - 4, size + 8)):
            with self.subTest(protected=protected):
                self.assertEqual(gates.assemble(*CORE_ARGS, protected_code=protected),
                                 baseline)
        for protected in ([], (), (True, 4), (CORE_ARGS[2], True),
                          (CORE_ARGS[2], 0), (CORE_ARGS[2], 3),
                          (CORE_ARGS[2], size - 4), (CORE_ARGS[2] + 4, size),
                          (0x400000, 0x2000000), (CORE_ARGS[0], 0x1000000),
                          (0xFFFFFFC, 8)):
            with self.subTest(protected=protected), self.assertRaises(ValueError):
                gates.assemble(*CORE_ARGS, protected_code=protected)

    def test_primary_U_R_and_CODE_are_strict_nonwrapping_disjoint_and_in_the_native_jump_region(self):
        for index in range(3):
            for value in (True, False, 0, -4, 1, 1.0, '16', None,
                          0x400000, 0xFFFFFFFC, 0x100000000):
                args = list(CORE_ARGS)
                args[index] = value
                with self.subTest(index=index, value=value), self.assertRaises(ValueError):
                    gates.assemble(*args)
        for args in ((CORE_ARGS[0], CORE_ARGS[0] + 4, CORE_ARGS[2]),
                     (CORE_ARGS[1], CORE_ARGS[1], CORE_ARGS[2]),
                     (CORE_ARGS[0], CORE_ARGS[1], CORE_ARGS[0]),
                     (CORE_ARGS[0], CORE_ARGS[1], CORE_ARGS[1]),
                     (CORE_ARGS[2] + 4, CORE_ARGS[1], CORE_ARGS[2]),
                     (CORE_ARGS[0], CORE_ARGS[2] + 4, CORE_ARGS[2]),
                     (CORE_ARGS[0], CORE_ARGS[1], 0x10000000),
                     (CORE_ARGS[0], CORE_ARGS[1], 0x0FFFFFFC)):
            with self.subTest(args=args), self.assertRaises(ValueError):
                gates.assemble(*args)

    def test_stage_rejects_every_fixed_data_role_in_the_final_new_tail_word(self):
        #87108 is outside the86120-byte parent, but is the last word of the
        #new87112-byte composition. This exercises the new tail rather than
        #an address already rejected by a preceding parent's RX extent.
        tail_word = ARGS[6] + 87112 - 4
        self.assertGreaterEqual(tail_word, ARGS[6] + 86120)
        for index in range(len(STAGE_ARGS)):
            if index == 6:  # CODE is the sole non-data argument among11 roles.
                continue
            args = list(STAGE_ARGS)
            args[index] = tail_word
            with self.subTest(fixed_data_role=index), self.assertRaises(ValueError):
                stage.assemble(*args)

    def test_all_fifteen_preceding_default_composition_hashes_are_preserved(self):
        preceding.RegistryAcquireGateContractTests.test_all_fourteen_preceding_default_hashes_are_preserved(self)
        result = acquire_stage.assemble(*STAGE_ARGS)
        self.assertEqual((len(result['code']), hashlib.sha256(result['code']).hexdigest()),
                         (86120, ACQUIRE_SHA256))
        self.assertEqual(acquire_stage.assemble(*STAGE_ARGS, following_code_bytes=0),
                         result)

    def test_parent_following_RX_is_strict_protected_but_not_appended(self):
        baseline = acquire_stage.assemble(*STAGE_ARGS)
        extended = acquire_stage.assemble(*STAGE_ARGS, following_code_bytes=4)
        self.assertEqual(len(extended['code']), len(baseline['code']))
        self.assertEqual(extended['labels'], baseline['labels'])
        self.assertEqual(extended['coherent_hooks'], baseline['coherent_hooks'])
        self.assertEqual(extended['protected_code_extent'],
                         (ARGS[6], len(extended['code']) + 4))
        self.assertNotEqual(extended['code'], baseline['code'])
        for value in (True, False, None, -4, 1, 2, 3, 1.0, '4', 0x100000000):
            with self.subTest(following=value), self.assertRaises(ValueError):
                acquire_stage.assemble(*STAGE_ARGS, following_code_bytes=value)

    def test_stage_adds_exactly_two_sites_and_reports_all_twenty_coherent_hooks(self):
        result = stage.assemble(*STAGE_ARGS)
        prefix = result['constructor_continuation_gate_prefix_code_bytes']
        tail = result['constructor_continuation_gate_code_bytes']
        self.assertEqual((prefix, tail, len(result['code'])), (86120, 992, 87112))
        self.assertEqual(hashlib.sha256(result['code']).hexdigest(), GATED_SHA256)
        full = (ARGS[6], len(result['code']))
        self.assertEqual(result['protected_code_extent'], full)
        self.assertEqual(prefix + tail, len(result['code']))
        parent = acquire_stage.assemble(*STAGE_ARGS, following_code_bytes=tail)
        self.assertEqual(parent['code'], result['code'][:prefix])
        self.assertEqual(parent['protected_code_extent'], full)
        labels = result['constructor_continuation_gate_labels']
        added = gates.hook_words(labels)
        self.assertEqual(result['constructor_continuation_gate_hooks'], added)
        self.assertEqual(set(added), {0x43AE94, 0x43B038})
        self.assertFalse(set(parent['coherent_hooks']) & set(added))
        self.assertEqual(result['coherent_hooks'], {**parent['coherent_hooks'], **added})
        self.assertEqual(len(result['coherent_hooks']), 20)
        self.assertEqual(labels['first_gate'], ARGS[6] + prefix)
        for name, address in labels.items():
            self.assertEqual(result['labels']['constructor_continuation_gate_' + name],
                             address)
        emitted, emitted_labels = gates.assemble(ARGS[3], ARGS[4], ARGS[6] + prefix,
                                                protected_code=full)
        self.assertEqual((emitted, emitted_labels), (result['code'][prefix:], labels))

    def test_stage_scope_flags_distinguish_engine_ABI_from_release_isolation_and_lifetime(self):
        result = stage.assemble(*STAGE_ARGS)
        for flag in ('constructor_status_continuations_gated',
                     'constructor_engine_return_preserved',
                     'registration_and_delete_acquire_gated',
                     'registry_release_checked', 'birth_consumer_historical_only'):
            with self.subTest(flag=flag):
                self.assertIs(result[flag], True)
        for flag in ('native_callers_isolated', 'raw_release_proven',
                     'native_lifetime_proven'):
            with self.subTest(flag=flag):
                self.assertIs(result[flag], False)
        # Inherited historical raw-release observation does not certify that
        # either constructor/native caller handles every raw release error.


if __name__ == '__main__':
    unittest.main()
