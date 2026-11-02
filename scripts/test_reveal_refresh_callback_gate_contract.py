#!/usr/bin/env python3
"""Pin two classified callback exits without extending them into the dialog.

The generated splice inherits the pinned-U refresh and wrapper decisions.
Native frames, context cleanup and the surrounding lock-service continuation are
separate source facts, not ownership, allocation or whole-instance proofs.
"""

import hashlib
import struct
import unittest
from copy import deepcopy

from build_reveal_bridge_diag import b
import reveal_refresh_wrapper_gate_mips as wrapper
import reveal_refresh_wrapper_gate_stage as parent_stage
import reveal_refresh_callback_gate_mips as gates
import reveal_refresh_callback_gate_stage as stage
import reveal_registry_receipt_mips as receipt
import reveal_registry_owner_mips as bindings
import reveal_registry_lifecycle_mips as lifecycle
import reveal_paint_retirement_mips as owners
import reveal_birth_queue_mips as queue
import test_reveal_refresh_wrapper_gate_contract as preceding
import test_reveal_refresh_wrapper_gate_mips as parent_fixture
import test_reveal_registry_birth_contract as native


ARGS, STAGE_ARGS = preceding.ARGS, preceding.STAGE_ARGS
PARENT_SELECTED, PARENT_ABORT = 0x1ED0000, 0x1ED0040
CORE_ARGS = (ARGS[3], ARGS[4], 0x1EE0000, PARENT_SELECTED, PARENT_ABORT)
RESUME_WORD = 0xAFA80544
GATE_BYTES, GATED_BYTES = 100, 92600
GATED_SHA256 = 'e76f86cc4cea0ecb445eee4eb712e14993004f3a42138e2b7150831899b9f7c4'


class RefreshCallbackGateContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        native.RegistryBirthContractTests.setUpClass.__func__(cls)
        cls._canonical_outputs = {}
        cls._parent_assemblers = tuple((module, module.assemble)
                                      for module in parent_fixture._ASSEMBLY_CACHE_MODULES)
        cls._new_assemblers = (gates.assemble, stage.assemble)
        cls._parent_cache = parent_fixture._fixture_assembly_cache(True)
        # The context restores its own partial entry on error. Once entered,
        # class cleanup restores every parent even if a test/setup fails.
        cls._parent_cache.__enter__()
        cls.addClassCleanup(cls._finish_parent_cache)

    @classmethod
    def _finish_parent_cache(cls):
        try:
            cls._parent_cache.__exit__(None, None, None)
        finally:
            for module, original in cls._parent_assemblers:
                if module.assemble is not original:
                    raise AssertionError('parent assembler not restored: ' + module.__name__)
            if (gates.assemble is not cls._new_assemblers[0]
                    or stage.assemble is not cls._new_assemblers[1]):
                raise AssertionError('new callback core/stage assembler was replaced')

    words = native.RegistryBirthContractTests.words

    @classmethod
    def canonical(cls, name):
        """Copy a named valid output into an independent metadata snapshot.

        Only these three exact configurations are retained once per class.
        The33 unchanged parent assemblers use the preceding fixture's pure
        assembly cache. NEW core/stage are never wrapped; every distinct new
        invalid/extension configuration still calls them directly. No CPU,
        execution state/results or historical hash-chain suite is cached here.
        """
        if name not in cls._canonical_outputs:
            if name == 'parent_default':
                emitted = parent_stage.assemble(*STAGE_ARGS)
            elif name == 'parent_guarded':
                tail = len(gates.assemble(*CORE_ARGS)[0])
                emitted = parent_stage.assemble(*STAGE_ARGS, following_code_bytes=tail)
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

    def test_parent_selected_pair_and_separate_saved_refresh_RA_write_are_generated(self):
        parent = self.canonical('parent_default')
        labels = parent['refresh_wrapper_gate_labels']
        selected, abort = labels['selected'], labels['abort_return']
        pair = (b.lui(8, abort >> 16), b.ori(8, 8, abort & 0xFFFF))
        self.assertEqual(self.fragment(parent['code'], ARGS[6], selected, selected + 12),
                         (*pair, RESUME_WORD))
        self.assertEqual(gates.parent_stop_pair(abort), pair)
        self.assertEqual(RESUME_WORD, b.sw(8, wrapper.OUTER_RA_OFFSET, 29))
        self.assertGreaterEqual(selected, gates.NATIVE_RX[1])
        # This is a generated interior splice, not a native callback hook.

    def test_parent_already_selected_the_classified_refresh_wrapper_return(self):
        code, labels = wrapper.assemble(ARGS[3], ARGS[4], 0x1EC0000, 0x1EB0000)
        scope = self.fragment(code, 0x1EC0000, labels['scope'], labels['selected'])
        self.assertEqual(scope[:3], (b.lw(8, 0x544, 29), b.lui(9, 0x4A), b.ori(9, 9, 0xD8E0)))
        self.assertEqual((scope[-2] >> 26, (scope[-2] >> 21) & 31,
                          (scope[-2] >> 16) & 31), (5, 8, 9))
        self.words(0x4ACBC0, [0x27BDFB78, 0x00002821, 0x24060040,
                              0xAFB00470, 0x00808021, 0x27A40420, 0xAFBF0484])
        self.words(0x4AD880, [0x27BDFFD0, 0xAFB0001C, 0x00808021,
                              0x00A02021, 0xAFB20024, 0xAFB10020,
                              0xAFBF002C, 0xAFB30028])
        self.words(0x4AD8D8, [0x0C12B2F0, 0x02002021])
        self.assertEqual((gates.FRAME, gates.REFRESH_FRAME, gates.WRAPPER_FRAME), (192, 1160, 48))
        self.assertEqual(gates.OUTER_RA_OFFSET, 192 + 1160 + 0x2C)
        self.assertEqual(gates.OUTER_RA_OFFSET, 0x574)
        self.assertEqual(192 + 1160 + 48, 0x578)

    def test_first_callback_has_genuine_5312_byte_frame_and_exact_wrapper_return(self):
        self.words(0x4AEC60, [0x27BDEB40, 0x00002821, 0x24060400,
                              0xAFB014A8, 0x00808021, 0x27A40AA8,
                              0xAFBF14BC, 0xAFB414B8, 0xAFB314B4,
                              0xAFB214B0, 0x0C296F18, 0xAFB114AC])
        self.words(0x4AECA8, [0x8E120048, 0x1240000B, 0,
                              0x8E110058, 0x12200008, 0, 0x8E220004])
        self.words(0x4AECF8, [0x27A514A0, 0x0C1395A0, 0x8E340000,
                              0x8FB314A0])
        self.words(0x4AEEDC, [0x26250050, 0x0C12B620, 0x02803021])
        self.assertEqual((gates.FIRST_CALLBACK_FRAME, gates.FIRST_CALLBACK_RETURN),
                         (5312, 0x4AEEE0 + 8))
        # S0 is dialog, S2 its borrowed controller, S1 its +58 context; the
        # selected return rewrite avoids needing to read them after failure.

    def test_second_callback_has_conditional_40_byte_frame_and_exact_wrapper_return(self):
        self.words(0x450D60, [0x10A00015, 0, 0x27BDFFD8, 0xAFB00020,
                              0xAFBF0024, 0x8C820058, 0x1040000A,
                              0x00A08021, 0x8C840048, 0x0C1395A0,
                              0x27A50018, 0x8FA40018, 0x10800004,
                              0, 0x8E060000, 0x0C12B620, 0x26050050])
        self.assertEqual((gates.SECOND_CALLBACK_FRAME, gates.SECOND_CALLBACK_RETURN),
                         (40, 0x450D9C + 8))
        self.assertEqual(self.branches[0x450D60], 0x450DB8)
        # Under the genuine native-route premise this return follows the
        # conditional prologue; arbitrary SP or forged frames are not recovered.

    def test_both_full_native_callback_epilogues_preserve_V0_V1(self):
        self.words(0x4AECD8, [0x8FBF14BC, 0x8FB414B8, 0x8FB314B4,
                              0x8FB214B0, 0x8FB114AC, 0x8FB014A8,
                              0x03E00008, 0x27BD14C0])
        self.words(0x450DAC, [0x8FBF0024, 0x8FB00020, 0x27BD0028,
                              0x03E00008, 0])
        self.assertEqual((gates.FIRST_CALLBACK_EPILOGUE, gates.SECOND_CALLBACK_EPILOGUE),
                         (0x4AECD8, 0x450DAC))
        self.words(0x4AD8FC, [0x8FBF002C, 0x02201021, 0x8FB30028,
                              0x8FB20024, 0x8FB10020, 0x8FB0001C,
                              0x03E00008, 0x27BD0030])
        self.words(0x4ACCE4, [0x8FBF0484, 0x8FB40480, 0x8FB3047C,
                              0x8FB20478, 0x8FB10474, 0x8FB00470,
                              0x03E00008, 0x27BD0488])
        # Existing wrapper abort bypasses4AD900's V0=S1 overwrite. New thunks
        # enter complete callback suffixes, including the genuine RA loads.

    def test_bypassed_context_cleanup_is_not_a_wrapper_retry_or_retention_proof(self):
        self.words(0x4AEEE8, [0x24030001, 0x1443FFF6, 0x02402021,
                              0x27A51438, 0x0C12BA68, 0x27A60AA8,
                              0x1000FFF2, 0x8E110058])
        self.words(0x4AEEC8, [0x8E110058, 0x1620FF7F, 0,
                              0x1000FF80, 0xAE000058])
        self.words(0x4AECCC, [0x0C119AA0, 0x02202021, 0xAE000058,
                              0x8FBF14BC])
        self.words(0x450DA4, [0x0C119AA0, 0x02002021])
        self.assertEqual(self.branches[0x4AEEEC], 0x4AEEC8)
        self.assertEqual(self.branches[0x4AEECC], 0x4AECCC)
        self.assertEqual(self.branches[0x4AEED4], 0x4AECD8)
        # Selected escape omits the V1 overwrite and later context read/free/
        # clear. It does not give that retained context a new allocation lease.

    def test_context_is_native_allocation_with_copied_descriptor_and_published_alias(self):
        self.words(0x4AF79C, [0x0C119A78, 0x24040CF0, 0x0040B021,
                              0x00402021, 0x00002821, 0x0C296F18,
                              0x24060CF0, 0x26C4000C, 0x26650020,
                              0x24060040, 0xAEC00000, 0x0C296DB8,
                              0xAEC00004, 0x26C40050, 0x02402821,
                              0x0C296D10, 0x24060A88, 0x1000FEAB,
                              0xAE360058])
        # Copying a descriptor does not prove every pointee retained after a
        # partial native teardown or the surrounding dialog's later cleanup.

    def test_callback_bodies_have_no_explicit_lock_facade_or_indirect_call(self):
        lock_calls = {0x466DA0, 0x466DC0, 0x466DE0, 0x437D20, 0x437DA0,
                      0xA5B960, 0xA5B830, 0xA5B0F0}
        for start, end in ((0x4AEC60, 0x4AEFBC), (0x450D60, 0x450DC0)):
            direct = {destination for pc, destination in self.jumps.items()
                      if start <= pc < end and self.elf.word(pc) >> 26 == 3}
            with self.subTest(callback=hex(start)):
                self.assertFalse(direct & lock_calls)
                self.assertFalse(any(word >> 26 == 0 and word & 63 == 9
                                     for pc in range(start, end, 4)
                                     for word in (self.elf.word(pc),)))
        # This bounded direct-call fact does not certify transitive services.

    def test_dialog_retains_native_lock_services_and_post_callback_cleanup(self):
        self.words(0x47C740, [0x27BDFF98, 0x00002821, 0x24060040,
                              0xAFB0005C, 0x00808021, 0x27A40018,
                              0xAFBF0064, 0x0C296F18, 0xAFB10060])
        self.words(0x47C794, [0x0C119B68, 0x8E040010])
        self.words(0x47C7B8, [0x8E190074, 0x13200004, 0,
                              0x8E050050, 0x0320F809, 0x02002021])
        self.words(0x47C7D0, [0x02202021, 0x0C11EA88, 0x27A50018,
                              0x02202021, 0x0C10E5E0, 0x27A50018,
                              0x02202021, 0x0C10E568, 0x27A50018,
                              0x8E240024, 0x0C1214C8, 0x27A50018,
                              0x0C119B70, 0x8E040010, 0x0C119B78,
                              0x8E040010, 0x00001021, 0x8FBF0064,
                              0x8FB10060, 0x8FB0005C, 0x03E00008,
                              0x27BD0068])
        # The dialog ignores this error and later masks V0. Jumping directly
        # to47C814 skips the matching+10 release/destruction calls. Acquisition
        # masks raw status, so successful lock ownership remains a premise.

    def test_bounded_incoming_census_keeps_ordinary_native_free_entries(self):
        self.assertEqual({pc for pc, target in self.jumps.items() if target == 0x4AD880},
                         {0x450D9C, 0x4AEEE0})
        for target in (0x4AEEE0, 0x4AEEE4, 0x4AEEE8, 0x4AEEEC, 0x4AEEF0,
                       0x450D9C, 0x450DA0, 0x450DA8, 0x450DAC, 0x450DB0):
            with self.subTest(target=hex(target)):
                self.assertEqual({pc for pc, destination in self.jumps.items()
                                  if destination == target}, set())
                self.assertEqual({pc for pc, destination in self.branches.items()
                                  if destination == target}, set())
        self.assertEqual({pc for pc, target in self.branches.items() if target == 0x450DA4},
                         {0x450D78, 0x450D90})
        self.assertEqual({pc for pc, target in self.branches.items() if target == 0x4AECD8},
                         {0x4AEED4})
        self.assertEqual({pc for pc, target in self.branches.items() if target == 0x4AECDC},
                         {0x4AECA0, 0x4AECAC, 0x4AECB8, 0x4AEF2C, 0x4AEFB4})
        # No computed-entry exclusion or saved-return authentication follows.

    def test_scope_compares_only_the_actual_W_saved_return_after_inherited_selection(self):
        code, labels = gates.assemble(*CORE_ARGS)
        words = self.fragment(code, CORE_ARGS[2], labels['scope'], labels['selected_second'])
        self.assertEqual(words[:3], (b.lw(8, 0x574, 29),
                                    b.lui(9, 0x4A), b.ori(9, 9, 0xEEE8)))
        self.assertEqual(words[5:7], (b.lui(9, 0x45), b.ori(9, 9, 0xDA4)))
        for index, opcode, target in ((3, 4, 'selected_first'), (7, 5, 'replay')):
            word = words[index]
            self.assertEqual((word >> 26, (word >> 21) & 31, (word >> 16) & 31),
                             (opcode, 8, 9))
            immediate = word & 0xFFFF
            immediate -= 0x10000 if immediate & 0x8000 else 0
            self.assertEqual(labels['scope'] + index * 4 + 4 + immediate * 4,
                             labels[target])
            self.assertEqual(words[index + 1], 0)
        self.assertEqual(gates.CALLBACK_SP_OFFSET, 0x578)
        # No view, descriptor, saved V0/V1 or second failure classification is
        # read here. A foreign W return branches to replay without a store.

    def test_selected_routes_rewrite_only_W_saved_RA_and_replay_parent_materialization(self):
        code, labels = gates.assemble(*CORE_ARGS)
        for first, last, target, extra in (
                ('selected_first', 'replay', 'first_abort_return', ()),
                ('selected_second', 'selected_first', 'second_abort_return',
                 (b.j_type(2, labels['replay']), 0))):
            address = labels[target]
            with self.subTest(route=first):
                self.assertEqual(self.fragment(code, CORE_ARGS[2], labels[first], labels[last]),
                                 (b.lui(8, address >> 16), b.ori(8, 8, address & 0xFFFF),
                                  b.sw(8, 0x574, 29), *extra))
        self.assertEqual(self.core_words('replay', 'first_abort_return'),
                         (*gates.parent_stop_pair(PARENT_ABORT),
                          b.j_type(2, PARENT_SELECTED + 8), 0))
        self.assertEqual(set(labels), {'scope', 'selected_first', 'selected_second',
                                      'replay', 'first_abort_return', 'second_abort_return'})
        self.assertEqual(gates.PARENT_RESUME_WORD, RESUME_WORD)
        # The parent's separate SW at resume still writes C.savedRA. The new
        # helper only edits W.savedRA, never the callback's own saved outer RA.

    def test_callback_thunks_use_full_native_epilogues_without_new_services_or_frames(self):
        self.assertEqual(self.core_words('first_abort_return', 'second_abort_return'),
                         (b.j_type(2, 0x4AECD8), 0))
        self.assertEqual(self.core_words('second_abort_return', None),
                         (b.j_type(2, 0x450DAC), 0))
        code, _ = gates.assemble(*CORE_ARGS)
        self.assertEqual(len(code), GATE_BYTES)
        words = self.fragment(code, CORE_ARGS[2], CORE_ARGS[2], CORE_ARGS[2] + len(code))
        accesses = [word for word in words if word >> 26 in (32, 33, 35, 36, 37, 40, 41, 43)]
        self.assertEqual(accesses, [b.lw(8, 0x574, 29), b.sw(8, 0x574, 29),
                                   b.sw(8, 0x574, 29)])
        written = {(word >> 16) & 31 for word in words
                   if word >> 26 in (8, 9, 12, 13, 14, 15, 35)}
        self.assertEqual(written, {8, 9})
        self.assertFalse(any(word >> 26 == 3 for word in words))
        self.assertFalse(any(word >> 26 == 0 and word & 63 == 9 for word in words))
        self.assertFalse(any(word >> 26 == 9 and (word >> 16) & 31 == 29 for word in words))
        # T0/T1 are recovered by the unchanged inherited restore. V0/V1 and
        # SP are untouched; no allocation lease or unlock/free is introduced.

    def test_generated_hook_parent_regions_and_label_derived_pair_are_strict(self):
        _, labels = gates.assemble(*CORE_ARGS)
        self.assertEqual(gates.hook_words(labels, PARENT_SELECTED),
                         {PARENT_SELECTED: (b.j_type(2, labels['scope']), 0)})
        for value in (True, False, None, 0, -4, 1, 0x10000000, 0x100000000):
            with self.subTest(target=value), self.assertRaises(ValueError):
                gates.hook_words(dict(labels, scope=value), PARENT_SELECTED)
            with self.subTest(site=value), self.assertRaises(ValueError):
                gates.hook_words(labels, value)
            with self.subTest(abort=value), self.assertRaises(ValueError):
                gates.parent_stop_pair(value)
        for selected, abort in ((0x400000, PARENT_ABORT),
                                (PARENT_SELECTED, 0x400000),
                                (CORE_ARGS[2] - 8, PARENT_ABORT),
                                (PARENT_SELECTED, CORE_ARGS[2] - 4),
                                (PARENT_SELECTED, PARENT_SELECTED),
                                (PARENT_SELECTED, PARENT_SELECTED + 8),
                                (PARENT_SELECTED, PARENT_SELECTED - 4)):
            with self.subTest(selected=selected, abort=abort), self.assertRaises(ValueError):
                gates.assemble(*CORE_ARGS[:3], selected, abort)
        # Both nonoverlapping generated regions may occur in either order.
        reversed_args = (*CORE_ARGS[:3], PARENT_ABORT, PARENT_SELECTED)
        self.assertEqual(len(gates.assemble(*reversed_args)[0]), GATE_BYTES)

    def test_static_primary_extra_and_complete_RX_extents_are_strict(self):
        for index in range(5):
            for value in (True, False, None, 0, -4, 1, 1.0, '16',
                          0x400000, 0xFFFFFFFC, 0x100000000):
                args = list(CORE_ARGS)
                args[index] = value
                with self.subTest(index=index, value=value), self.assertRaises(ValueError):
                    gates.assemble(*args)
        for index, value in ((0, CORE_ARGS[1]), (1, CORE_ARGS[0]),
                              (0, PARENT_SELECTED + 8), (1, PARENT_ABORT + 4),
                              (2, CORE_ARGS[0]), (2, CORE_ARGS[1])):
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
                      ((CORE_ARGS[1] + 20, 4),), ((PARENT_SELECTED, 4),),
                      ((PARENT_SELECTED + 8, 4),), ((PARENT_ABORT, 4),),
                      ((PARENT_ABORT + 4, 4),), ((CORE_ARGS[2], 4),),
                      ((0x1F90000, 8), (0x1F90004, 4))):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                gates.assemble(*CORE_ARGS, extra_protected_data=extra)
        size = CORE_ARGS[2] + len(baseline[0]) - PARENT_SELECTED
        for protected in (None, (PARENT_SELECTED, size), (PARENT_SELECTED - 4, size + 8)):
            self.assertEqual(gates.assemble(*CORE_ARGS, protected_code=protected), baseline)
        for protected in ([], (), (True, size), (PARENT_SELECTED, True),
                          (PARENT_SELECTED, 0), (PARENT_SELECTED, 3),
                          (PARENT_SELECTED, size - 4), (PARENT_SELECTED + 4, size),
                          (PARENT_ABORT, size), (CORE_ARGS[2], len(baseline[0])),
                          (0x400000, 0x2000000), (CORE_ARGS[0], 0x1000000), (0xFFFFFFC, 8)):
            with self.subTest(protected=protected), self.assertRaises(ValueError):
                gates.assemble(*CORE_ARGS, protected_code=protected)

    def test_all_fixed_roles_are_excluded_from_final_tail_by_direct_pure_core_checks(self):
        tail = CORE_ARGS[2] + GATE_BYTES - 4
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
        # Full dynamic-frame mapping/lifetime and transitive stack are premises,
        # not consequences of these declared static exclusions.

    def test_direct_parent_default_hash_and_explicit_zero_extension_are_unchanged(self):
        parent = self.canonical('parent_default')
        self.assertEqual((len(parent['code']), hashlib.sha256(parent['code']).hexdigest()),
                         (92500, preceding.GATED_SHA256))
        self.assertEqual(parent_stage.assemble(*STAGE_ARGS, following_code_bytes=0), parent)
        # Earlier published source/hash contracts are not rerun by this suite.

    def test_parent_and_successor_following_RX_are_strict_protection_not_appended_bytes(self):
        for selected, name in ((parent_stage, 'parent_default'), (stage, 'stage_default')):
            baseline = self.canonical(name)
            extended = selected.assemble(*STAGE_ARGS, following_code_bytes=4)
            with self.subTest(stage=selected.__name__):
                if selected is stage:
                    self.assertEqual(selected.assemble(*STAGE_ARGS, following_code_bytes=0), baseline)
                self.assertEqual(len(extended['code']), len(baseline['code']))
                self.assertEqual(extended['labels'], baseline['labels'])
                self.assertEqual(extended['coherent_hooks'], baseline['coherent_hooks'])
                self.assertEqual(extended['protected_code_extent'], (ARGS[6], len(baseline['code']) + 4))
                self.assertNotEqual(extended['code'], baseline['code'])
            for value in (True, False, None, -4, 1, 2, 3, 1.0, '4'):
                with self.subTest(stage=selected.__name__, following=value), self.assertRaises(ValueError):
                    selected.assemble(*STAGE_ARGS, following_code_bytes=value)

    def test_stage_patches_one_verified_guarded_pair_preserving_resume_and_parent_abort(self):
        result = self.canonical('stage_default')
        prefix, tail = (result['refresh_callback_gate_prefix_code_bytes'],
                        result['refresh_callback_gate_code_bytes'])
        self.assertEqual((prefix, tail, len(result['code'])), (92500, GATE_BYTES, GATED_BYTES))
        self.assertEqual(prefix + tail, len(result['code']))
        self.assertEqual(hashlib.sha256(result['code']).hexdigest(), GATED_SHA256)
        full = (ARGS[6], len(result['code']))
        self.assertEqual(result['protected_code_extent'], full)
        parent = self.canonical('parent_guarded')
        self.assertEqual(parent['protected_code_extent'], full)
        selected = parent['refresh_wrapper_gate_labels']['selected']
        abort = parent['refresh_wrapper_gate_labels']['abort_return']
        self.assertEqual((selected, abort), (0x1E96930, 0x1E9694C))
        source = gates.parent_stop_pair(abort)
        abort_words = (b.j_type(2, 0x4AD904), 0x8FBF002C)
        self.assertEqual(result['refresh_callback_gate_parent_selected_address'], selected)
        self.assertEqual(result['refresh_callback_gate_parent_abort_return_address'], abort)
        self.assertEqual(result['refresh_callback_gate_source_words'], {selected: source})
        self.assertEqual(result['refresh_callback_gate_resume_word'], RESUME_WORD)
        self.assertEqual(result['refresh_callback_gate_parent_abort_words'], abort_words)
        self.assertEqual(self.fragment(parent['code'], ARGS[6], selected, selected + 12),
                         (*source, RESUME_WORD))
        self.assertEqual(self.fragment(parent['code'], ARGS[6], abort, abort + 8), abort_words)
        labels = result['refresh_callback_gate_labels']
        self.assertEqual(labels, dict(scope=0x1E96954, selected_second=0x1E96978,
                                      selected_first=0x1E9698C, replay=0x1E96998,
                                      first_abort_return=0x1E969A8,
                                      second_abort_return=0x1E969B0))
        hooks = gates.hook_words(labels, selected)
        self.assertEqual(result['refresh_callback_gate_hooks'], hooks)
        expected = bytearray(parent['code'])
        struct.pack_into('<II', expected, selected - ARGS[6], *hooks[selected])
        self.assertEqual(result['code'][:prefix], bytes(expected))
        self.assertEqual(self.fragment(result['code'], ARGS[6], selected, selected + 12),
                         (*hooks[selected], RESUME_WORD))
        self.assertEqual(self.fragment(result['code'], ARGS[6], abort, abort + 8), abort_words)
        emitted, emitted_labels = gates.assemble(ARGS[3], ARGS[4], ARGS[6] + prefix,
                                                selected, abort, protected_code=full)
        self.assertEqual((emitted, emitted_labels), (result['code'][prefix:], labels))
        for name, address in labels.items():
            self.assertEqual(result['labels']['refresh_callback_gate_' + name], address)

    def test_stage_adds_only_one_generated_hook_and_keeps_scope_limitations(self):
        result = self.canonical('stage_default')
        parent = self.canonical('parent_default')
        new = result['refresh_callback_gate_hooks']
        self.assertFalse(set(new) & set(parent['coherent_hooks']))
        self.assertEqual(result['native_coherent_hooks'], parent['native_coherent_hooks'])
        self.assertEqual(result['generated_coherent_hooks'], {**parent['generated_coherent_hooks'], **new})
        self.assertEqual(result['coherent_hooks'], {**parent['coherent_hooks'], **new})
        self.assertEqual((len(result['native_coherent_hooks']), len(result['generated_coherent_hooks']),
                          len(result['coherent_hooks'])), (24, 3, 27))
        self.assertTrue(all(gates.NATIVE_RX[0] <= pc < gates.NATIVE_RX[1]
                            for pc in result['native_coherent_hooks']))
        self.assertTrue(all(ARGS[6] <= pc < ARGS[6] + len(result['code'])
                            for pc in result['generated_coherent_hooks']))
        for flag in ('refresh_callback_failure_continuations_stopped',
                     'refresh_callback_exact_result_preserved',
                     'refresh_wrapper_failure_continuation_stopped',
                     'refresh_wrapper_exact_result_preserved'):
            self.assertIs(result[flag], True)
        for flag in ('native_callers_isolated', 'destructor_entry_fenced', 'earlier_cleanup_rolled_back',
                     'raw_release_proven', 'native_lifetime_proven', 'partial_graph_cleanup_proven'):
            with self.subTest(flag=flag):
                self.assertIs(result[flag], False)
        self.assertEqual(parent['coherent_hooks'], self.canonical('parent_default')['coherent_hooks'])

    def test_stage_rejects_new_tail_and_following_alias_with_actual_compositions(self):
        result = self.canonical('stage_default')
        for address, following in ((ARGS[6] + len(result['code']) - 4, 0),
                                   (ARGS[6] + len(result['code']), 4)):
            args = list(STAGE_ARGS)
            args[-1] = address
            with self.subTest(following=following), self.assertRaises(ValueError):
                stage.assemble(*args, following_code_bytes=following)

    def test_cached_valid_outputs_are_independent_metadata_snapshots(self):
        first, second = self.canonical('stage_default'), self.canonical('stage_default')
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        self.assertIsNot(first['labels'], second['labels'])
        self.assertIsNot(first['coherent_hooks'], second['coherent_hooks'])
        first['labels']['snapshot_only'] = 0
        first['coherent_hooks'].clear()
        self.assertNotIn('snapshot_only', second['labels'])
        self.assertEqual(len(second['coherent_hooks']), 27)
        self.assertEqual(self.canonical('stage_default'), second)

    def test_parent_only_cache_restores_identities_after_error_and_never_wraps_new_code(self):
        self.assertEqual(len(self._parent_assemblers), 33)
        self.assertEqual(len({module for module, _ in self._parent_assemblers}), 33)
        outer = tuple((module, module.assemble) for module, _ in self._parent_assemblers)
        for module, original in self._parent_assemblers:
            self.assertIsNot(module.assemble, original)
        self.assertIs(gates.assemble, self._new_assemblers[0])
        self.assertIs(stage.assemble, self._new_assemblers[1])
        with self.assertRaisesRegex(RuntimeError, 'parent-cache restoration probe'):
            with parent_fixture._fixture_assembly_cache(True):
                for module, function in outer:
                    self.assertIsNot(module.assemble, function)
                self.assertIs(gates.assemble, self._new_assemblers[0])
                self.assertIs(stage.assemble, self._new_assemblers[1])
                raise RuntimeError('parent-cache restoration probe')
        for module, function in outer:
            self.assertIs(module.assemble, function)
        self.assertIs(gates.assemble, self._new_assemblers[0])
        self.assertIs(stage.assemble, self._new_assemblers[1])


if __name__ == '__main__':
    unittest.main()
