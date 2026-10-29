#!/usr/bin/env python3
"""Pinned pre-mutation acquisition gates, not complete native isolation.

Only the preserved hash-pinned vendor source supplies native facts. Encoded
branch absence does not cover computed targets, and local denial does not
stop callers that ignore the result. No image, hook installer or I/O is used.
"""

import hashlib
import struct
import unittest

from build_reveal_bridge_diag import b
import reveal_birth_consumer_stage as consumer_stage
import reveal_registry_acquire_gate_mips as gates
import reveal_registry_acquire_gate_stage as stage
import reveal_creation_capture_mips as capture
import reveal_registry_receipt_mips as receipt
import reveal_registry_retirement_mips as retirement
import test_reveal_birth_consumer_contract as previous
import test_reveal_cleanup_intent_contract as cleanup
import test_reveal_registry_birth_contract as native


ARGS = previous.ARGS
STAGE_ARGS = previous.STAGE_ARGS
CORE_ARGS = (ARGS[3], ARGS[4], 0x1EE0000)
CONSUMER_SHA256 = '765759c2a2ee7a29a2f6d7f0b9af90496d4ef0510a5d1fe809c6bb6fbd9db71f'


class RegistryAcquireGateContractTests(unittest.TestCase):
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

    def test_two_displaced_pairs_match_the_hash_pinned_primary_source(self):
        expected = {
            'register_gate': (0x438A10, (0x0C119A78, 0x2404001C)),
            'delete_gate': (0x4395D4, (0x8EB00034, 0x16130006)),
        }
        self.assertEqual(gates.HOOKS, expected)
        self.assertEqual(list(self.elf.executable_ranges()), [receipt.NATIVE_RX])
        for site, pair in expected.values():
            self.words(site, pair)

    def test_encoded_incoming_census_covers_pairs_and_the_replayed_delete_delay(self):
        for site in (0x438A10, 0x438A14, 0x4395D4, 0x4395D8, 0x4395DC):
            with self.subTest(site=hex(site)):
                self.assertEqual({pc for pc, target in self.jumps.items()
                                  if target == site}, set())
                self.assertEqual({pc for pc, target in self.branches.items()
                                  if target == site}, set())
        # This bounded census cannot classify JR/JALR, fabricated returns,
        # runtime-patched imports or arbitrary partial hook activation.

    def test_native_registration_reaches_allocator_without_checking_facade_result(self):
        self.words(0x438A00, [0x8C990274, 0x00808021, 0x0320F809,
                              0x00A08821, 0x0C119A78, 0x2404001C])
        self.assertEqual(0x438A08 + 8, gates.HOOKS['register_gate'][0])
        self.assertEqual((gates.ALLOCATOR, gates.ALLOCATOR_RETURN),
                         (0x4669E0, 0x438A18))
        self.assertEqual(self.jumps[0x438A10], gates.ALLOCATOR)
        self.assertEqual(0x438A10 + 8, gates.ALLOCATOR_RETURN)

    def test_registration_failure_uses_existing_epilogue_and_missing_unlock_is_unchanged(self):
        self.words(0x438A18, [0x10400019, 0x26050034])
        self.assertEqual(self.branches[0x438A18], 0x438A80)
        self.words(0x438A68, [0x00001021, 0x8FBF0024, 0x8FB10020,
                              0x8FB0001C, 0x03E00008, 0x27BD0028])
        self.words(0x438A80, [0x1000FFFA, 0x2402FFFF])
        self.assertEqual(self.branches[0x438A80], gates.REGISTER_EPILOGUE)
        self.assertEqual(gates.REGISTER_EPILOGUE, 0x438A6C)
        # The admitted allocation-failure branch still skips native unlock.
        # V1 there remains the old ABI, not a normalized gate raw-error code.

    def test_native_delete_first_ring_read_and_exact_branch_delay_are_pinned(self):
        self.words(0x4395C0, [0x8C990274, 0x0080A821, 0x00A0A021,
                              0x0320F809, 0x24930034,
                              0x8EB00034, 0x16130006, 0x8E110000])
        self.assertEqual(0x4395CC + 8, gates.HOOKS['delete_gate'][0])
        self.assertEqual((gates.DELETE_DELAY, gates.DELETE_TAKEN,
                          gates.DELETE_FALLTHROUGH),
                         (0x8E110000, 0x4395F4, 0x4395E0))
        self.assertEqual(self.branches[0x4395D8], gates.DELETE_TAKEN)

    def test_stock_delete_epilogue_tail_calls_unlock_and_cannot_be_used_for_denial(self):
        self.words(0x439654, [0x8EB90278, 0x8FBF0034, 0x8FB4002C,
                              0x8FB30028, 0x8FB20024, 0x8FB10020,
                              0x8FB0001C, 0x02A02021, 0x8FB50030,
                              0x03200008, 0x27BD0038])
        denied = self.core_words('delete_gate_denied', 'delete_gate_admitted')
        self.assertFalse(any(word >> 26 in (2, 3) for word in denied))
        expected = [b.lw(31, 0x34, 29), b.lw(21, 0x30, 29),
                    b.lw(20, 0x2C, 29), b.lw(19, 0x28, 29),
                    b.lw(18, 0x24, 29), b.lw(17, 0x20, 29),
                    b.lw(16, 0x1C, 29), b.r_type(31, 0, 0, 8),
                    b.addiu(29, 29, gates.DELETE_FRAME)]
        self.assertEqual(list(denied[-len(expected):]), expected)

    def test_frame_storage_preserves_all_gprs_and_HI_LO_before_local_checks(self):
        self.assertEqual((gates.FRAME, gates.HI, gates.LO, gates.RAW),
                         (192, 0x88, 0x8C, 0x90))
        self.assertEqual((gates.REGISTER_FRAME, gates.DELETE_FRAME), (40, 56))
        expected = {register: 0x10 + index * 4
                    for index, register in enumerate(
                        register for register in range(1, 32) if register != 29)}
        self.assertEqual(gates.SAVE, expected)
        self.assertEqual(len({*gates.SAVE.values(), gates.HI, gates.LO,
                              gates.RAW}), 33)
        for name in gates.HOOKS:
            with self.subTest(gate=name):
                words = self.core_words(name, name + '_denied')
                self.assertEqual(words[0], b.addiu(29, 29, -gates.FRAME))
                for register, offset in gates.SAVE.items():
                    self.assertIn(b.sw(register, offset, 29), words)
                self.assertIn(b.r_type(0, 0, 8, 0x10), words)
                self.assertIn(b.r_type(0, 0, 8, 0x12), words)
                self.assertIn(b.sw(0, gates.RAW, 29), words)
                self.assertIn(b.addiu(23, 29, gates.FRAME), words)

    def test_registration_requires_same_U_TAG_mutex_pointer_and_actual_raw_zero(self):
        words = self.core_words('register_gate', 'register_gate_denied')
        for instruction in (b.lw(8, gates.SAVE[16], 29),
                            b.lw(8, receipt.TAG, 23),
                            b.lw(8, receipt.PTR, 23),
                            b.lw(8, receipt.RAW_STATUS, 23),
                            b.sw(8, gates.RAW, 29)):
            self.assertIn(instruction, words)
        self.assertIn(b.lui(9, receipt.CAPTURED >> 16), words)
        self.assertIn(b.ori(9, 9, receipt.CAPTURED & 0xFFFF), words)
        self.assertEqual(words[-1], 0)  # Actual raw-zero branch delay slot.
        self.assertEqual((words[-2] >> 26, (words[-2] >> 21) & 31,
                          (words[-2] >> 16) & 31), (4, 8, 0))

    def test_delete_requires_current_U_and_its_own_captured_raw_witness(self):
        words = self.core_words('delete_gate', 'delete_gate_denied')
        for instruction in (b.lw(8, gates.SAVE[21], 29),
                            b.lw(8, retirement.TAG, 23),
                            b.lw(8, retirement.RAW_STATUS, 23),
                            b.sw(8, gates.RAW, 29)):
            self.assertIn(instruction, words)
        self.assertIn(b.lui(9, retirement.CAPTURED >> 16), words)
        self.assertIn(b.ori(9, 9, retirement.CAPTURED & 0xFFFF), words)
        self.assertNotEqual(retirement.CAPTURED, receipt.CAPTURED)

    def test_admission_reads_only_owned_frames_and_never_writes_native_witnesses(self):
        for name in gates.HOOKS:
            words = self.core_words(name, name + '_replay')
            accesses = [word for word in words
                        if word >> 26 in (32, 33, 35, 36, 37, 40, 41, 43)]
            with self.subTest(gate=name):
                self.assertEqual({(word >> 21) & 31 for word in accesses}, {23, 29})
                stores = [word for word in accesses if word >> 26 in (40, 41, 43)]
                self.assertEqual({(word >> 21) & 31 for word in stores}, {29})
                self.assertFalse(any(word >> 26 == 3 for word in words))
                self.assertFalse(any(word >> 26 == 0 and word & 63 == 9
                                     for word in words))

    def test_success_restores_complete_architecture_before_replaying_native_effects(self):
        for name in gates.HOOKS:
            words = self.core_words(name + '_admitted', name + '_replay')
            with self.subTest(gate=name):
                self.assertEqual(words[:4], (b.lw(8, gates.HI, 29),
                                            b.r_type(8, 0, 0, 0x11),
                                            b.lw(8, gates.LO, 29),
                                            b.r_type(8, 0, 0, 0x13)))
                self.assertEqual(words[4:-1], tuple(b.lw(register, offset, 29)
                                                  for register, offset in gates.SAVE.items()))
                self.assertEqual(words[-1], b.addiu(29, 29, gates.FRAME))

    def test_denial_restores_other_registers_and_returns_only_private_saved_raw_status(self):
        for name in gates.HOOKS:
            words = self.core_words(name + '_denied', name + '_admitted')
            with self.subTest(gate=name):
                for register, offset in gates.SAVE.items():
                    if register not in (2, 3):
                        self.assertIn(b.lw(register, offset, 29), words)
                self.assertIn(b.addiu(2, 0, -1), words)
                self.assertIn(b.lw(3, gates.RAW, 29), words)
                self.assertFalse(any(word >> 26 == 3 for word in words))
                accesses = [word for word in words
                            if word >> 26 in (32, 33, 35, 36, 37, 40, 41, 43)]
                self.assertEqual({(word >> 21) & 31 for word in accesses}, {29})

    def test_registration_replays_original_allocator_RA_and_size_without_new_call_return(self):
        words = self.core_words('register_gate_replay', 'delete_gate')
        self.assertEqual(words, (b.lui(31, gates.ALLOCATOR_RETURN >> 16),
                                 b.ori(31, 31, gates.ALLOCATOR_RETURN & 0xFFFF),
                                 b.j_type(2, gates.ALLOCATOR), b.addiu(4, 0, 28)))

    def test_delete_replays_the_displaced_head_load_and_one_branch_delay_exactly(self):
        words = self.core_words('delete_gate_replay', None)
        self.assertEqual(words[0], gates.HOOKS['delete_gate'][1][0])
        self.assertEqual(sum(word == gates.DELETE_DELAY for word in words), 1)
        self.assertEqual((words[1] >> 26, (words[1] >> 21) & 31,
                          (words[1] >> 16) & 31), (5, 16, 19))
        self.assertEqual(words[2:], (gates.DELETE_DELAY,
                                     b.j_type(2, gates.DELETE_FALLTHROUGH), 0,
                                     b.j_type(2, gates.DELETE_TAKEN), 0))

    def test_hook_words_are_two_explicit_local_redirects_with_strict_targets(self):
        _, labels = gates.assemble(*CORE_ARGS)
        hooks = gates.hook_words(labels)
        for name, (pc, _) in gates.HOOKS.items():
            self.assertEqual(hooks[pc], (b.j_type(2, labels[name]), 0))
            for value in (True, False, 0, -4, 1, 0x10000000, 0x100000000):
                with self.subTest(gate=name, target=value), self.assertRaises(ValueError):
                    gates.hook_words(dict(labels, **{name: value}))

    def test_controller_mutex_and_code_addresses_are_strict_nonwrapping_and_disjoint(self):
        for index in range(3):
            for value in (True, False, 0, -4, 1, 1.0, '16', None,
                          0x400000, 0xFFFFFFFC, 0x100000000):
                args = list(CORE_ARGS)
                args[index] = value
                with self.subTest(index=index, value=value), self.assertRaises(ValueError):
                    gates.assemble(*args)
        for args in ((CORE_ARGS[0], CORE_ARGS[0] + 4, CORE_ARGS[2]),
                     (CORE_ARGS[0], CORE_ARGS[1], CORE_ARGS[0]),
                     (CORE_ARGS[0], CORE_ARGS[1], CORE_ARGS[1])):
            with self.subTest(args=args), self.assertRaises(ValueError):
                gates.assemble(*args)

    def test_extra_data_is_a_strict_static_layout_declaration_not_runtime_guard_code(self):
        baseline = gates.assemble(*CORE_ARGS)
        for extra in (((0x1F90000, 4),), ((0xFFFFFFFC, 4),)):
            with self.subTest(extra=extra):
                self.assertEqual(gates.assemble(*CORE_ARGS, extra_protected_data=extra),
                                 baseline)
        for extra in (None, [], ((True, 4),), ((0, 4),),
                      ((0x1F90000, True),), ((0x1F90000, 0),),
                      ((0x1F90000, 3),), ((0xFFFFFFFC, 8),),
                      ((0x400000, 4),), ((CORE_ARGS[0], 4),),
                      ((CORE_ARGS[1], 4),), ((CORE_ARGS[2], 4),),
                      ((0x1F90000, 8), (0x1F90004, 4))):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                gates.assemble(*CORE_ARGS, extra_protected_data=extra)

    def test_complete_protected_RX_is_strict_and_does_not_add_dynamic_frame_checks(self):
        code, labels = gates.assemble(*CORE_ARGS)
        for protected in (None, (CORE_ARGS[2], len(code)),
                          (CORE_ARGS[2] - 4, len(code) + 8)):
            with self.subTest(protected=protected):
                self.assertEqual(gates.assemble(*CORE_ARGS, protected_code=protected),
                                 (code, labels))
        for protected in ([], (), (True, 4), (CORE_ARGS[2], True),
                          (CORE_ARGS[2], 0), (CORE_ARGS[2], 3),
                          (CORE_ARGS[2], len(code) - 4),
                          (CORE_ARGS[2] + 4, len(code)),
                          (0x400000, 0x2000000), (CORE_ARGS[0], 0x1000000),
                          (0xFFFFFFC, 8)):
            with self.subTest(protected=protected), self.assertRaises(ValueError):
                gates.assemble(*CORE_ARGS, protected_code=protected)

    def test_native_constructors_and_all_direct_delete_callers_ignore_failure(self):
        self.assertEqual({pc for pc, target in self.jumps.items()
                          if target == 0x4389E0}, {0x43AE8C, 0x43B030})
        self.words(0x43AE94, [0x0C1467E8, 0x02202021,
                              0x8FA20050, 0x0C10DFB8, 0x8C440000])
        self.words(0x43B038, [0x0C1467E8, 0x02202021, 0x8FA20050])
        # Reuse the pinned 56-caller census, including 54 independent resource
        # deletes, not an assertion that this gate safely stops those callers.
        self.edges = self.jumps
        self.inbound = lambda target: {pc for pc, destination in self.jumps.items()
                                       if destination == target}
        cleanup.CleanupIntentContractTests.test_direct_delete_callers_continue_without_checking_native_result(self)

    def test_other_known_unlink_routes_remain_separate_and_ungated(self):
        for site in (0x43CB9C, 0x4E3F08, 0x51A3A8):
            self.assertNotIn(site, {pc for pc, _ in gates.HOOKS.values()})
        self.words(0x43CB9C, [0x8E220034, 0x1052000B, 0x8C500000])
        self.words(0x4E3F48, [0xAC620004])
        self.words(0x51A3E8, [0xAC620004])
        self.assertFalse(any(0x43CB20 <= pc < 0x43CC74 and target == 0x4395A0
                             for pc, target in self.jumps.items()))

    def test_inherited_raw_return_can_still_read_controller_before_the_new_gate(self):
        result = stage.assemble(*STAGE_ARGS)
        labels = result['retirement_labels']
        words = self.fragment(result['code'], ARGS[6], labels['raw_return_scope_0'],
                              labels['raw_return_scope_1'])
        for offset in (0x274, 0x278, 0x13C):
            self.assertIn(b.lw(8, offset, 16), words)
        # These existing reads precede native4395D4. The new gate's
        # private-only admission decision does not retroactively remove them.

    def test_older_checked_creation_wrapper_has_no_preservation_of_native_gate_V1(self):
        result = stage.assemble(*STAGE_ARGS)
        labels = result['capture_labels']
        words = self.fragment(result['code'], ARGS[6], labels['native_return'],
                              labels['early_denied'])
        self.assertEqual(words[0], b.sw(2, capture.NATIVE_RESULT, 29))
        self.assertFalse(any(word >> 26 == 43 and (word >> 16) & 31 == 3
                             for word in words))
        self.assertIn(b.lw(3, capture.EXPORTED_PTR, 29), words)
        self.assertIn(b.sw(8, capture.EXPORTED_PTR, 29), words)
        # V1 becomes this older wrapper's output/release diagnostic, never
        # an automatically propagated native-entry acquire-gate diagnostic.

    def test_default_zero_consumer_following_RX_keeps_the_fourteenth_composition(self):
        baseline = consumer_stage.assemble(*STAGE_ARGS)
        self.assertEqual(consumer_stage.assemble(*STAGE_ARGS, following_code_bytes=0),
                         baseline)
        self.assertEqual((len(baseline['code']), hashlib.sha256(baseline['code']).hexdigest()),
                         (85044, CONSUMER_SHA256))

    def test_consumer_following_RX_protects_tail_without_appending_or_moving_labels(self):
        baseline = consumer_stage.assemble(*STAGE_ARGS)
        extended = consumer_stage.assemble(*STAGE_ARGS, following_code_bytes=4)
        self.assertEqual(len(extended['code']), len(baseline['code']))
        self.assertEqual(extended['labels'], baseline['labels'])
        self.assertEqual(extended['coherent_hooks'], baseline['coherent_hooks'])
        self.assertEqual(extended['protected_code_extent'],
                         (ARGS[6], len(extended['code']) + 4))
        self.assertNotEqual(extended['code'], baseline['code'])
        for value in (True, False, None, -4, 1, 2, 3, 1.0, '4', 0x100000000):
            with self.subTest(following=value), self.assertRaises(ValueError):
                consumer_stage.assemble(*STAGE_ARGS, following_code_bytes=value)

    def test_all_fourteen_preceding_default_hashes_are_preserved(self):
        previous.BirthConsumerContractTests.test_all_thirteen_preceding_composition_hashes_are_preserved(self)
        baseline = consumer_stage.assemble(*STAGE_ARGS)
        self.assertEqual((len(baseline['code']), hashlib.sha256(baseline['code']).hexdigest()),
                         (85044, CONSUMER_SHA256))

    def test_stage_extends_complete_RX_and_explicitly_adds_only_two_fixture_hooks(self):
        result = stage.assemble(*STAGE_ARGS)
        self.assertTrue(result['registration_and_delete_acquire_gated'])
        self.assertFalse(result['native_callers_isolated'])
        self.assertFalse(result['native_lifetime_proven'])
        self.assertTrue(result['birth_consumer_historical_only'])
        prefix, tail = (result['acquire_gate_prefix_code_bytes'],
                        result['acquire_gate_code_bytes'])
        self.assertEqual(prefix, 85044)
        self.assertEqual((tail, len(result['code'])), (1076, 86120))
        self.assertEqual(hashlib.sha256(result['code']).hexdigest(),
                         'a4c3ec89cc4a7b01b2f385abfb5daf2146694a48a03118aaaaea756b524a4041')
        self.assertEqual(prefix + tail, len(result['code']))
        full = (ARGS[6], len(result['code']))
        self.assertEqual(result['protected_code_extent'], full)
        labels = result['acquire_gate_labels']
        self.assertEqual(labels['register_gate'], ARGS[6] + prefix)
        parent = consumer_stage.assemble(*STAGE_ARGS, following_code_bytes=tail)
        self.assertEqual(result['code'][:prefix], parent['code'])
        self.assertEqual(parent['protected_code_extent'], full)
        added = gates.hook_words(labels)
        self.assertEqual(result['acquire_gate_hooks'], added)
        self.assertEqual(result['coherent_hooks'], {**parent['coherent_hooks'], **added})
        self.assertEqual(len(result['coherent_hooks']), 18)
        self.assertFalse(set(parent['coherent_hooks']) & set(added))
        for name, address in labels.items():
            self.assertEqual(result['labels']['acquire_gate_' + name], address)
        core, core_labels = gates.assemble(ARGS[3], ARGS[4], ARGS[6] + prefix,
                                          protected_code=full)
        self.assertEqual((core, core_labels), (result['code'][prefix:], labels))


if __name__ == '__main__':
    unittest.main()
