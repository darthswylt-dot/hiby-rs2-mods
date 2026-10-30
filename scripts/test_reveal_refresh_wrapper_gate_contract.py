#!/usr/bin/env python3
"""Pin a generated wrapper escape, not new native hooks or caller isolation.

The inherited pinned-U failure decision precedes the splice. Its generated HI
pair/resume are checked separately from the hash-pinned native frames and pure
wrapper suffix. No receipt mailbox, new failure ABI or cleanup authority follows.
"""

import hashlib
import struct
import unittest
from copy import deepcopy

from build_reveal_bridge_diag import b
import reveal_refresh_failure_gate_mips as refresh
import reveal_refresh_failure_gate_stage as parent_stage
import reveal_refresh_wrapper_gate_mips as gates
import reveal_refresh_wrapper_gate_stage as stage
import reveal_registry_receipt_mips as receipt
import reveal_registry_owner_mips as bindings
import reveal_registry_lifecycle_mips as lifecycle
import reveal_paint_retirement_mips as owners
import reveal_birth_queue_mips as queue
import test_reveal_refresh_failure_gate_contract as preceding
import test_reveal_registry_birth_contract as native


ARGS, STAGE_ARGS = preceding.ARGS, preceding.STAGE_ARGS
PARENT_STOP = 0x1ED0000
CORE_ARGS = (ARGS[3], ARGS[4], 0x1EE0000, PARENT_STOP)
SOURCE_PAIR, RESUME_WORD = (0x8FA80088, 0x01000011), 0x8FA8008C
GATED_SHA256 = 'b10314826317ea55438b21abcb4de04825346d3c593c132ec6cdd7921b74e696'


class RefreshWrapperGateContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        native.RegistryBirthContractTests.setUpClass.__func__(cls)
        cls._canonical_outputs = {}

    words = native.RegistryBirthContractTests.words

    @classmethod
    def canonical(cls, name):
        """Copy one already-emitted valid output; never wrap an assembler.

        Each of these three exact configurations is evaluated once per class
        through its actual assembler. Distinct extension/invalid arguments,
        the preceding default-hash chain and pure-core checks are uncached.
        """
        if name not in cls._canonical_outputs:
            if name == 'parent_default':
                emitted = parent_stage.assemble(*STAGE_ARGS)
            elif name == 'parent_guarded':
                emitted = parent_stage.assemble(*STAGE_ARGS, following_code_bytes=56)
            elif name == 'stage_default':
                emitted = stage.assemble(*STAGE_ARGS)
            else:
                raise ValueError('unknown canonical configuration')
            cls._canonical_outputs[name] = deepcopy(emitted)
        return deepcopy(cls._canonical_outputs[name])

    @staticmethod
    def fragment(code, base, first, last):
        selected = code[first - base:last - base]
        return struct.unpack('<' + 'I' * (len(selected) // 4), selected)

    def core_words(self, first, last):
        code, labels = gates.assemble(*CORE_ARGS)
        end = CORE_ARGS[2] + len(code) if last is None else labels[last]
        return self.fragment(code, CORE_ARGS[2], labels[first], end)

    def test_generated_source_pair_and_separate_resume_are_exact_before_patching(self):
        parent = self.canonical('parent_default')
        stop = parent['refresh_failure_gate_labels']['gate_stopped']
        self.assertEqual(self.fragment(parent['code'], ARGS[6], stop, stop + 12),
                         (*SOURCE_PAIR, RESUME_WORD))
        self.assertEqual(gates.PARENT_STOP_PAIR, SOURCE_PAIR)
        self.assertEqual(SOURCE_PAIR, (b.lw(8, refresh.HI, 29), b.r_type(8, 0, 0, 0x11)))
        self.assertGreaterEqual(stop, gates.NATIVE_RX[1])
        # These are generated instructions, not a vendor source hook pair.

    def test_parent_already_classifies_pinned_S2_return_and_nonzero_V0_before_helper(self):
        base = 0x1EC0000
        code, labels = refresh.assemble(ARGS[3], ARGS[4], base)
        words = self.fragment(code, base, labels['gate'], labels['gate_stopped'])
        decision = words[1 + len(refresh.SAVE) + 4:]
        accesses = [word for word in decision if word >> 26 in (32, 33, 35, 36, 37, 40, 41, 43)]
        self.assertEqual(accesses, [b.lw(8, refresh.SAVE[18], 29),
                                   b.lw(8, refresh.SAVE[31], 29), b.lw(8, refresh.SAVE[2], 29)])
        for value in (ARGS[3], 0x4ACD94):
            self.assertIn(b.lui(9, value >> 16), decision)
            self.assertIn(b.ori(9, 9, value & 0xFFFF), decision)
        self.assertEqual((decision[-2] >> 26, (decision[-2] >> 21) & 31,
                          (decision[-2] >> 16) & 31), (4, 8, 0))
        self.assertNotIn(b.lw(8, refresh.SAVE[3], 29), decision)

    def test_genuine_native_call_frames_and_private_saved_outer_return_offset_are_pinned(self):
        self.words(0x4AD880, [0x27BDFFD0, 0xAFB0001C, 0x00808021,
                              0x00A02021, 0xAFB20024, 0xAFB10020,
                              0xAFBF002C, 0xAFB30028, 0x00A08821,
                              0x0C12B3F0, 0x00C09021])
        self.words(0x4AD8D8, [0x0C12B2F0, 0x02002021])
        self.words(0x4ACBC0, [0x27BDFB78, 0x00002821, 0x24060040,
                              0xAFB00470, 0x00808021, 0x27A40420, 0xAFBF0484])
        self.assertEqual((gates.FRAME, gates.REFRESH_FRAME, gates.WRAPPER_FRAME), (192, 1160, 48))
        self.assertEqual(gates.OUTER_RA_OFFSET, 192 + 0x484)
        self.assertEqual(gates.OUTER_RA_OFFSET, 0x544)
        self.assertEqual(gates.WRAPPER_RETURN, 0x4AD8D8 + 8)
        # The helper reads the refresh frame's saved caller, not the current
        # wrapper S2 (mode), descriptor S1, view S0 or an object owner field.

    def test_native_refresh_unwind_preserves_result_and_enters_retargeted_caller(self):
        self.words(0x4ACCE0, [0x24020001, 0x8FBF0484, 0x8FB40480,
                              0x8FB3047C, 0x8FB20478, 0x8FB10474,
                              0x8FB00470, 0x03E00008, 0x27BD0488])
        self.assertEqual(refresh.EPILOGUE, 0x4ACCE4)
        # Only the saved return slot changes. Actual1160-byte restore/unwind
        # still runs and bypasses the preceding success overwrite at4ACCE0.

    def test_wrapper_thunk_supplies_RA_and_uses_pure_native_48_byte_suffix(self):
        self.words(0x4AD8FC, [0x8FBF002C, 0x02201021,
                              0x8FB30028, 0x8FB20024, 0x8FB10020,
                              0x8FB0001C, 0x03E00008, 0x27BD0030])
        self.assertEqual((gates.WRAPPER_EPILOGUE, gates.WRAPPER_RA_DELAY),
                         (0x4AD904, 0x8FBF002C))
        self.assertEqual(self.core_words('abort_return', None),
                         (b.j_type(2, 0x4AD904), 0x8FBF002C))
        #4AD900 would overwrite V0 from descriptor S1. The thunk loads genuine
        #wrapper RA once in its jump delay and bypasses that result overwrite.

    def test_earlier_operation_work_and_skipped_post_refresh_view_use_are_pinned(self):
        self.words(0x4AD8BC, [0x02403021, 0x02202821, 0x0C12B478,
                              0x02002021, 0x02202821, 0x0C12B290, 0x02002021])
        self.words(0x4AD8E0, [0x12600006, 0x00408821, 0x24020001,
                              0x12220004, 0x8FBF002C, 0x0C12B390, 0x02002021])
        self.words(0x4AD91C, [0x0C10B0A0, 0x24130001])
        self.words(0x4ACE70, [0x26043DD8, 0x0C107F20, 0x27A50018])
        self.words(0x4ACE84, [0x24040008, 0x0C10AC50, 0x00002821])
        # Earlier helpers and cleanup are not undone. The selected escape
        #prevents this wrapper's later4ACE40 view read/property continuation.

    def test_bounded_native_callers_and_incoming_census_do_not_authenticate_frames(self):
        self.assertEqual({pc for pc, target in self.jumps.items() if target == 0x4AD880},
                         {0x450D9C, 0x4AEEE0})
        for target in (0x4AD8D8, 0x4AD8DC, 0x4AD8E0, 0x4AD8E4, 0x4AD904):
            with self.subTest(target=hex(target)):
                self.assertEqual({pc for pc, destination in self.jumps.items() if destination == target}, set())
                self.assertEqual({pc for pc, destination in self.branches.items() if destination == target}, set())
        self.assertEqual({pc for pc, target in self.branches.items() if target == 0x4AD8FC}, {0x4AD8E0})
        self.assertEqual({pc for pc, target in self.branches.items() if target == 0x4AD900}, {0x4AD8EC})
        self.assertEqual({pc for pc, target in self.jumps.items() if target == 0x4ACE40},
                         {0x4AD8F4, 0x4ADBCC})
        # Neither computed entries nor the other4ACE40 caller is covered.

    def test_higher_callbacks_ignore_error_and_free_context_before_exit(self):
        self.words(0x450D9C, [0x0C12B620, 0x26050050, 0x0C119AA0,
                              0x02002021, 0x8FBF0024, 0x8FB00020,
                              0x27BD0028, 0x03E00008, 0])
        self.words(0x4AEEE0, [0x0C12B620, 0x02803021, 0x24030001,
                              0x1443FFF6, 0x02402021])
        self.words(0x4AEEC8, [0x8E110058, 0x1620FF7F, 0,
                              0x1000FF80, 0xAE000058])
        self.words(0x4AECCC, [0x0C119AA0, 0x02202021, 0xAE000058,
                              0x8FBF14BC])
        self.assertEqual(self.branches[0x4AEEEC], 0x4AEEC8)
        self.assertEqual(self.branches[0x4AEECC], 0x4AECCC)
        self.assertEqual(self.branches[0x4AEED4], 0x4AECD8)
        # One caller ignores the result before a context free; the other
        # overwrites V1, reads/frees a nonnull context, clears dialog+58 and
        # exits. Neither outcome retries the wrapper on this error path.

    def test_scope_reads_only_actual_saved_outer_RA_and_foreign_callers_replay(self):
        words = self.core_words('scope', 'selected')
        self.assertEqual(words[:3], (b.lw(8, 0x544, 29), b.lui(9, 0x4A), b.ori(9, 9, 0xD8E0)))
        self.assertEqual((words[-2] >> 26, (words[-2] >> 21) & 31,
                          (words[-2] >> 16) & 31), (5, 8, 9))
        _, labels = gates.assemble(*CORE_ARGS)
        immediate = words[-2] & 0xFFFF
        immediate -= 0x10000 if immediate & 0x8000 else 0
        self.assertEqual(labels['selected'] - 8 + 4 + immediate * 4, labels['replay'])

    def test_selected_route_retargets_only_that_native_saved_return(self):
        code, labels = gates.assemble(*CORE_ARGS)
        target = labels['abort_return']
        self.assertEqual(self.core_words('selected', 'replay'),
                         (b.lui(8, target >> 16), b.ori(8, 8, target & 0xFFFF), b.sw(8, 0x544, 29)))

    def test_both_scope_outcomes_replay_exact_HI_pair_and_resume_at_original_LO_load(self):
        self.assertEqual(self.core_words('replay', 'abort_return'),
                         (*SOURCE_PAIR, b.j_type(2, PARENT_STOP + 8), 0))
        self.assertEqual(set(gates.assemble(*CORE_ARGS)[1]), {'scope', 'selected', 'replay', 'abort_return'})

    def test_helper_has_only_four_private_frame_accesses_and_no_new_allocation_or_service(self):
        code, _ = gates.assemble(*CORE_ARGS)
        self.assertEqual(len(code), 56)
        words = self.fragment(code, CORE_ARGS[2], CORE_ARGS[2], CORE_ARGS[2] + len(code))
        accesses = [word for word in words if word >> 26 in (32, 33, 35, 36, 37, 40, 41, 43)]
        self.assertEqual([(word >> 26, (word >> 21) & 31, word & 0xFFFF) for word in accesses],
                         [(35, 29, 0x544), (43, 29, 0x544), (35, 29, 0x88), (35, 29, 0x2C)])
        self.assertFalse(any(word >> 26 == 3 for word in words))
        self.assertFalse(any(word >> 26 == 0 and word & 63 == 9 for word in words))
        self.assertFalse(any(word >> 26 == 9 and (word >> 16) & 31 == 29 for word in words))
        # Last LW is executed only after native refresh unwinds, with SP=W.

    def test_helper_does_not_write_V0_V1_or_build_a_failure_receipt(self):
        code, _ = gates.assemble(*CORE_ARGS)
        words = self.fragment(code, CORE_ARGS[2], CORE_ARGS[2], CORE_ARGS[2] + len(code))
        written = {(word >> 16) & 31 for word in words if word >> 26 in (8, 9, 12, 13, 14, 15, 35)}
        self.assertEqual(written, {8, 9, 31})
        self.assertEqual([word for word in words if word >> 26 in (40, 41, 43)], [b.sw(8, 0x544, 29)])
        # Existing parent restoration recovers T0/T1. The abort's RA load is
        #the ordinary wrapper-return prerequisite; V0/V1 are never markers.

    def test_generated_hook_targets_and_parent_twelve_byte_reservation_are_strict(self):
        _, labels = gates.assemble(*CORE_ARGS)
        self.assertEqual(gates.hook_words(labels, PARENT_STOP),
                         {PARENT_STOP: (b.j_type(2, labels['scope']), 0)})
        for value in (True, False, None, 0, -4, 1, 0x10000000, 0x100000000):
            with self.subTest(target=value), self.assertRaises(ValueError):
                gates.hook_words(dict(labels, scope=value), PARENT_STOP)
            with self.subTest(site=value), self.assertRaises(ValueError):
                gates.hook_words(labels, value)
        for parent in (0x1000, CORE_ARGS[0], CORE_ARGS[1], CORE_ARGS[2] - 8,
                       CORE_ARGS[2] - 4, CORE_ARGS[2], CORE_ARGS[2] + 4):
            with self.subTest(parent=parent), self.assertRaises(ValueError):
                gates.assemble(*CORE_ARGS[:3], parent)

    def test_primary_and_extra_static_layout_do_not_invent_runtime_frame_guards(self):
        for index in range(4):
            for value in (True, False, None, 0, -4, 1, 1.0, '16',
                          0x400000, 0xFFFFFFFC, 0x100000000):
                args = list(CORE_ARGS)
                args[index] = value
                with self.subTest(index=index, value=value), self.assertRaises(ValueError):
                    gates.assemble(*args)
        for index, value in ((0, CORE_ARGS[1]), (0, PARENT_STOP + 8),
                              (1, PARENT_STOP + 8), (2, CORE_ARGS[0]), (2, CORE_ARGS[1])):
            args = list(CORE_ARGS)
            args[index] = value
            with self.subTest(index=index, overlap=value), self.assertRaises(ValueError):
                gates.assemble(*args)
        baseline = gates.assemble(*CORE_ARGS)
        for extra in (((0x1F90000, 4),), ((0xFFFFFFFC, 4),)):
            self.assertEqual(gates.assemble(*CORE_ARGS, extra_protected_data=extra), baseline)
        for extra in (None, [], ((True, 4),), ((0x1F90000, True),),
                      ((0x1F90000, 0),), ((0x1F90000, 3),), ((0xFFFFFFFC, 8),),
                      ((0x400000, 4),), ((CORE_ARGS[0] + 0x288, 4),),
                      ((CORE_ARGS[1] + 20, 4),), ((PARENT_STOP, 4),), ((PARENT_STOP + 8, 4),),
                      ((CORE_ARGS[2], 4),), ((0x1F90000, 8), (0x1F90004, 4))):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                gates.assemble(*CORE_ARGS, extra_protected_data=extra)

    def test_every_fixed_role_is_excluded_from_new_tail_by_pure_core_validation(self):
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

    def test_complete_RX_contains_parent_pair_resume_and_entire_helper(self):
        baseline = gates.assemble(*CORE_ARGS)
        size = CORE_ARGS[2] + len(baseline[0]) - PARENT_STOP
        for protected in (None, (PARENT_STOP, size), (PARENT_STOP - 4, size + 8)):
            self.assertEqual(gates.assemble(*CORE_ARGS, protected_code=protected), baseline)
        for protected in ([], (), (True, size), (PARENT_STOP, True),
                          (PARENT_STOP, 0), (PARENT_STOP, 3), (PARENT_STOP, size - 4),
                          (PARENT_STOP + 4, size), (CORE_ARGS[2], len(baseline[0])),
                          (0x400000, 0x2000000), (CORE_ARGS[0], 0x1000000), (0xFFFFFFC, 8)):
            with self.subTest(protected=protected), self.assertRaises(ValueError):
                gates.assemble(*CORE_ARGS, protected_code=protected)

    def test_all_twenty_one_prior_hashes_and_zero_parent_extension_are_preserved(self):
        # The complete preceding chain is evaluated directly once here. Its
        # final parent is emitted once by canonical(), without an assembly
        # wrapper; later tests inspect copies of that same immutable output.
        preceding.RefreshFailureGateContractTests.test_all_twenty_prior_default_hashes_and_zero_parent_extension_are_preserved(self)
        parent = self.canonical('parent_default')
        self.assertEqual((len(parent['code']), hashlib.sha256(parent['code']).hexdigest()),
                         (92444, preceding.GATED_SHA256))
        self.assertEqual(parent_stage.assemble(*STAGE_ARGS, following_code_bytes=0), parent)

    def test_parent_and_successor_following_RX_are_strict_and_not_appended(self):
        for selected, canonical in ((parent_stage, 'parent_default'), (stage, 'stage_default')):
            baseline = self.canonical(canonical)
            extended = selected.assemble(*STAGE_ARGS, following_code_bytes=4)
            with self.subTest(stage=selected.__name__):
                if selected is stage:
                    # The parent zero-extension comparison already ran in
                    # the uncached preceding-default hash-chain contract.
                    self.assertEqual(selected.assemble(*STAGE_ARGS, following_code_bytes=0), baseline)
                self.assertEqual(len(extended['code']), len(baseline['code']))
                self.assertEqual(extended['labels'], baseline['labels'])
                self.assertEqual(extended['coherent_hooks'], baseline['coherent_hooks'])
                self.assertEqual(extended['protected_code_extent'], (ARGS[6], len(baseline['code']) + 4))
                self.assertNotEqual(extended['code'], baseline['code'])
            for value in (True, False, None, -4, 1, 2, 3, 1.0, '4', 0x100000000):
                with self.subTest(stage=selected.__name__, following=value), self.assertRaises(ValueError):
                    selected.assemble(*STAGE_ARGS, following_code_bytes=value)

    def test_stage_patches_only_the_verified_guarded_parent_pair_and_appends_bound_helper(self):
        result = self.canonical('stage_default')
        prefix, tail = (result['refresh_wrapper_gate_prefix_code_bytes'], result['refresh_wrapper_gate_code_bytes'])
        self.assertEqual((prefix, tail, len(result['code'])), (92444, 56, 92500))
        self.assertEqual(prefix + tail, len(result['code']))
        self.assertEqual(hashlib.sha256(result['code']).hexdigest(), GATED_SHA256)
        full = (ARGS[6], len(result['code']))
        self.assertEqual(result['protected_code_extent'], full)
        parent = self.canonical('parent_guarded')
        self.assertEqual(parent['protected_code_extent'], full)
        stop = parent['refresh_failure_gate_labels']['gate_stopped']
        self.assertEqual(stop, 0x1E967E4)
        self.assertEqual(result['refresh_wrapper_gate_parent_stopped_address'], stop)
        self.assertEqual(result['refresh_wrapper_gate_source_words'], {stop: SOURCE_PAIR})
        self.assertEqual(result['refresh_wrapper_gate_resume_word'], RESUME_WORD)
        self.assertEqual(self.fragment(parent['code'], ARGS[6], stop, stop + 12), (*SOURCE_PAIR, RESUME_WORD))
        labels = result['refresh_wrapper_gate_labels']
        hooks = gates.hook_words(labels, stop)
        self.assertEqual(result['refresh_wrapper_gate_hooks'], hooks)
        expected = bytearray(parent['code'])
        struct.pack_into('<II', expected, stop - ARGS[6], *hooks[stop])
        self.assertEqual(result['code'][:prefix], bytes(expected))
        self.assertEqual(self.fragment(result['code'], ARGS[6], stop, stop + 12), (*hooks[stop], RESUME_WORD))
        emitted, emitted_labels = gates.assemble(ARGS[3], ARGS[4], ARGS[6] + prefix, stop, protected_code=full)
        self.assertEqual((emitted, emitted_labels), (result['code'][prefix:], labels))
        for name, address in labels.items():
            self.assertEqual(result['labels']['refresh_wrapper_gate_' + name], address)

    def test_stage_adds_one_generated_splice_and_keeps_all_twenty_four_native_hooks(self):
        result = self.canonical('stage_default')
        parent = self.canonical('parent_default')
        new = result['refresh_wrapper_gate_hooks']
        self.assertFalse(set(new) & set(parent['coherent_hooks']))
        self.assertEqual(result['native_coherent_hooks'], parent['native_coherent_hooks'])
        self.assertEqual(result['generated_coherent_hooks'], {**parent['generated_coherent_hooks'], **new})
        self.assertEqual(result['coherent_hooks'], {**parent['coherent_hooks'], **new})
        self.assertEqual((len(result['native_coherent_hooks']), len(result['generated_coherent_hooks']),
                          len(result['coherent_hooks'])), (24, 2, 26))
        self.assertTrue(all(gates.NATIVE_RX[0] <= pc < gates.NATIVE_RX[1]
                            for pc in result['native_coherent_hooks']))
        self.assertTrue(all(ARGS[6] <= pc < ARGS[6] + len(result['code'])
                            for pc in result['generated_coherent_hooks']))

    def test_stage_final_tail_following_alias_and_scope_flags_retain_all_limitations(self):
        result = self.canonical('stage_default')
        for address, following in ((ARGS[6] + len(result['code']) - 4, 0),
                                   (ARGS[6] + len(result['code']), 4)):
            args = list(STAGE_ARGS)
            args[-1] = address
            with self.subTest(following=following), self.assertRaises(ValueError):
                stage.assemble(*args, following_code_bytes=following)
        for flag in ('refresh_wrapper_failure_continuation_stopped', 'refresh_wrapper_exact_result_preserved',
                     'refresh_destructor_failure_continuation_stopped'):
            self.assertIs(result[flag], True)
        for flag in ('native_callers_isolated', 'destructor_entry_fenced', 'earlier_cleanup_rolled_back',
                     'raw_release_proven', 'native_lifetime_proven', 'partial_graph_cleanup_proven'):
            with self.subTest(flag=flag):
                self.assertIs(result[flag], False)

    def test_canonical_output_snapshots_do_not_share_mutable_metadata(self):
        first = self.canonical('stage_default')
        second = self.canonical('stage_default')
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        self.assertIsNot(first['labels'], second['labels'])
        self.assertIsNot(first['coherent_hooks'], second['coherent_hooks'])
        first['labels']['snapshot_only'] = 0
        first['coherent_hooks'].clear()
        self.assertNotIn('snapshot_only', second['labels'])
        self.assertEqual(len(second['coherent_hooks']), 26)
        self.assertEqual(self.canonical('stage_default'), second)


if __name__ == '__main__':
    unittest.main()
