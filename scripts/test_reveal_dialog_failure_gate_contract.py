#!/usr/bin/env python3
"""Pin PC-carried dialog failure exit and a qualified single raw release.

ADMITTED is an acquisition observation, not continuous ownership authority.
The additional ordinary same-thread ownership/lifetime premises, worker use
and outer container frees remain separate from these source/layout contracts.
"""

import hashlib
import struct
import unittest
from copy import deepcopy

from build_reveal_bridge_diag import b
import reveal_dialog_failure_gate_mips as gates
import reveal_dialog_failure_gate_stage as stage
import reveal_dialog_acquire_gate_mips as acquire
import reveal_dialog_acquire_gate_stage as parent_stage
import reveal_registry_receipt_mips as receipt
import reveal_registry_owner_mips as bindings
import reveal_registry_lifecycle_mips as lifecycle
import reveal_paint_retirement_mips as owners
import reveal_birth_queue_mips as queue
import test_reveal_dialog_acquire_gate_contract as preceding
import test_reveal_dialog_acquire_gate_mips as parent_fixture
import test_reveal_registry_birth_contract as native


ARGS, STAGE_ARGS = preceding.ARGS, preceding.STAGE_ARGS
PARENT_FIRST, PARENT_SECOND = 0x1ED0000, 0x1ED0010
CORE_ARGS = (ARGS[3], ARGS[4], 0x1EE0000, PARENT_FIRST, PARENT_SECOND)
GATE_BYTES, GATED_BYTES = 1068, 95300
GATED_SHA256 = '92f44f4def0777f77207b6d0c9a1ad973b88f9e667c3919b3b095200b0aa668e'


class DialogFailureGateContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        native.RegistryBirthContractTests.setUpClass.__func__(cls)
        cls._canonical_outputs = {}
        cls._parent_assemblers = tuple((module, module.assemble)
                                      for module in parent_fixture._ASSEMBLY_CACHE_MODULES)
        cls._new_assemblers = (gates.assemble, stage.assemble)
        cls._parent_cache = parent_fixture._fixture_assembly_cache(True)
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
                raise AssertionError('new dialog failure core/stage was replaced')

    words = native.RegistryBirthContractTests.words

    @classmethod
    def canonical(cls, name):
        """Deep-copy three valid outputs; only37 unchanged parents are cached.

        The new core/stage stay unwrapped for every distinct configuration.
        No CPU, native execution state/results or older hash chain is cached.
        """
        if name not in cls._canonical_outputs:
            if name == 'parent_default':
                emitted = parent_stage.assemble(*STAGE_ARGS)
            elif name == 'parent_guarded':
                emitted = parent_stage.assemble(*STAGE_ARGS, following_code_bytes=GATE_BYTES)
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

    @staticmethod
    def accesses(words):
        return [word for word in words if word >> 26 in (32, 33, 35, 36, 37, 40, 41, 43)]

    @staticmethod
    def save_words():
        return (b.addiu(29, 29, -192),
                *(b.sw(register, offset, 29) for register, offset in gates.SAVE.items()),
                b.r_type(0, 0, 8, 0x10), b.sw(8, 0x88, 29),
                b.r_type(0, 0, 8, 0x12), b.sw(8, 0x8C, 29), b.addiu(23, 29, 192))

    @staticmethod
    def restore_words():
        return (b.lw(8, 0x88, 29), b.r_type(8, 0, 0, 0x11),
                b.lw(8, 0x8C, 29), b.r_type(8, 0, 0, 0x13),
                *(b.lw(register, offset, 29) for register, offset in gates.SAVE.items()),
                b.addiu(29, 29, 192))

    def test_two_actual_parent_abort_pairs_are_generated_not_new_native_entry_hooks(self):
        parent = self.canonical('parent_default')
        labels = parent['refresh_callback_gate_labels']
        parents = (labels['first_abort_return'], labels['second_abort_return'])
        self.assertEqual(parents, (0x1E969A8, 0x1E969B0))
        self.assertEqual((gates.PARENT_FIRST_PAIR, gates.PARENT_SECOND_PAIR),
                         ((b.j_type(2, 0x4AECD8), 0), (b.j_type(2, 0x450DAC), 0)))
        for pc, expected in zip(parents, (gates.PARENT_FIRST_PAIR, gates.PARENT_SECOND_PAIR)):
            self.assertEqual(self.fragment(parent['code'], ARGS[6], pc, pc + 8), expected)
            self.assertNotIn(pc, parent['coherent_hooks'])
        # These two thunks already follow the inherited pinned-U classified
        # callback failure. Their source bytes, not a generic V0, carry scope.

    def test_native_callback_frames_saved_outer_returns_and_full_epilogues_are_exact(self):
        self.words(0x4AEC60, [0x27BDEB40, 0x00002821, 0x24060400,
                              0xAFB014A8, 0x00808021, 0x27A40AA8,
                              0xAFBF14BC, 0xAFB414B8, 0xAFB314B4,
                              0xAFB214B0, 0x0C296F18, 0xAFB114AC])
        self.words(0x450D68, [0x27BDFFD8, 0xAFB00020, 0xAFBF0024])
        self.words(0x4AECD8, [0x8FBF14BC, 0x8FB414B8, 0x8FB314B4,
                              0x8FB214B0, 0x8FB114AC, 0x8FB014A8,
                              0x03E00008, 0x27BD14C0])
        self.words(0x450DAC, [0x8FBF0024, 0x8FB00020, 0x27BD0028,
                              0x03E00008, 0])
        self.words(0x47C7C4, [0x8E050050, 0x0320F809, 0x02002021])
        self.assertEqual((gates.FIRST_CALLBACK_FRAME, gates.SECOND_CALLBACK_FRAME,
                          gates.FIRST_RA, gates.SECOND_RA), (5312, 40, 0x14BC, 0x24))
        self.assertEqual((gates.DIALOG_RETURN, gates.DIALOG_FRAME), (0x47C7D0, 104))
        # With genuine native B, D is B+frame. The helper changes B.savedRA,
        # never D's own saved outer caller at D+64.

    def test_dialog_cleanup_pair_delay_and_incoming_edges_remain_native(self):
        self.words(0x47C7D0, [0x02202021, 0x0C11EA88, 0x27A50018,
                              0x02202021, 0x0C10E5E0, 0x27A50018,
                              0x02202021, 0x0C10E568, 0x27A50018,
                              0x8E240024, 0x0C1214C8, 0x27A50018,
                              0x0C119B70, 0x8E040010, 0x0C119B78,
                              0x8E040010, 0x00001021])
        self.words(0x47C814, [0x8FBF0064, 0x8FB10060, 0x8FB0005C,
                              0x03E00008, 0x27BD0068])
        self.assertEqual(gates.EPILOGUE, 0x47C814)
        self.assertEqual({pc for pc, target in self.branches.items() if target == 0x47C7D0}, {0x47C7BC})
        for target in (0x47C7D0, 0x47C7D4, 0x47C7D8, 0x47C7DC):
            self.assertEqual({pc for pc, destination in self.jumps.items() if destination == target}, set())
            if target != 0x47C7D0:
                self.assertEqual({pc for pc, destination in self.branches.items()
                                  if destination == target}, set())
        # No native hook broadens the stop to the null callback or ordinary0/1.

    def test_native_release_and_destroy_facades_cannot_supply_this_actual_status_policy(self):
        self.words(0x466DC0, [0x27BDFFE0, 0xAFBF001C, 0x0C296E0C, 0,
                              0x8FBF001C, 0x00001021, 0x03E00008, 0x27BD0020])
        self.words(0xA5B830, [0x3C0F00A7, 0x8DF9FA0C, 0x03200008, 0x25F8FA0C])
        self.words(0x466DEC, [0x0C296C3C, 0x00808021, 0x12000004,
                              0x8FBF001C, 0x0C119AA0, 0x02002021])
        self.assertEqual(gates.RAW_UNLOCK, receipt.RAW_UNLOCK)
        # Native unlock masks raw V0; destroy frees nonnull M regardless of
        # raw destroy success. Neither facade is called by the new error route.

    def test_prior_worker_use_and_outer_free_continuations_remain_unisolated(self):
        self.words(0x47C6E8, [0x0C119B70, 0x8E04000C, 0x8E040014,
                              0x10800005, 0x8FBF0034, 0x0C119AA0,
                              0, 0xAE000014])
        self.words(0x47CC88, [0x8E39006C, 0x0320F809, 0x02202021,
                              0x3C0200B9, 0x8C44AEB8, 0x24020001,
                              0xA222001D, 0xA220001C])
        self.words(0x47CCC8, [0x0C119AA0, 0x02202021])
        self.words(0x47D000, [0x8E39006C, 0x0320F809, 0x02202021,
                              0x3C0200B9, 0x8C44AEB8, 0x24020001,
                              0xA222001D, 0xA220001C])
        self.words(0x47D02C, [0x0C119AA0, 0x02202021])
        # These callers ignore error and free H. A live D58 observation is
        # neither a durable release report nor permission for that outer free.

    def test_scopes_read_only_B_saved_return_and_retarget_only_the_matching_word(self):
        code, labels = gates.assemble(*CORE_ARGS)
        for name, offset in (('first', 0x14BC), ('second', 0x24)):
            words = self.core_words(name + '_scope', name + '_selected')
            self.assertEqual(words[:len(self.save_words())], self.save_words())
            decision = words[len(self.save_words()):]
            self.assertEqual(decision[:3], (b.lw(8, offset, 23),
                                           b.lui(9, 0x47), b.ori(9, 9, 0xC7D0)))
            self.assertEqual(self.accesses(decision), [b.lw(8, offset, 23)])
            branch = decision[-2]
            self.assertEqual((branch >> 26, (branch >> 21) & 31, (branch >> 16) & 31), (5, 8, 9))
            immediate = branch & 0xFFFF
            immediate -= 0x10000 if immediate & 0x8000 else 0
            self.assertEqual(labels[name + '_selected'] - 4 + immediate * 4, labels[name + '_done'])
            self.assertEqual(decision[-1], 0)
            target = labels['error_return']
            self.assertEqual(self.core_words(name + '_selected', name + '_done'),
                             (b.lui(8, target >> 16), b.ori(8, 8, target & 0xFFFF),
                              b.sw(8, offset, 23)))
        # Foreign B.savedRA branches straight to restoration. No acquire tag
        # is needed to retain this inherited failure classification.

    def test_callback_scope_restores_all_state_then_replays_the_original_epilogue_jump(self):
        for name, epilogue, following in (('first', 0x4AECD8, 'second_scope'),
                                           ('second', 0x450DAC, 'error_return')):
            self.assertEqual(self.core_words(name + '_done', name + '_replay'), self.restore_words())
            self.assertEqual(self.core_words(name + '_replay', following), (b.j_type(2, epilogue), 0))
        self.assertEqual((gates.FRAME, gates.HI, gates.LO), (192, 0x88, 0x8C))
        self.assertEqual(set(gates.SAVE), set(range(1, 32)) - {29})
        self.assertTrue(all(0x10 <= offset <= 0x84 for offset in gates.SAVE.values()))

    def test_error_return_consumes_ADMITTED_and_raw_zero_before_any_release_attempt(self):
        _, labels = gates.assemble(*CORE_ARGS)
        words = self.core_words('error_return', 'release_attempt')
        self.assertEqual(words[:len(self.save_words())], self.save_words())
        decision = words[len(self.save_words()):]
        self.assertEqual(self.accesses(decision), [b.lw(8, 0x10, 23), b.sw(0, 0x10, 23),
                                                  b.lw(8, 0x58, 23)])
        self.assertEqual(decision[2:4], (b.lui(9, acquire.ADMITTED >> 16),
                                        b.ori(9, 9, acquire.ADMITTED & 0xFFFF)))
        for index, compared in ((4, 9), (7, 0)):
            branch = decision[index]
            self.assertEqual((branch >> 26, (branch >> 21) & 31, (branch >> 16) & 31), (5, 8, compared))
            immediate = branch & 0xFFFF
            immediate -= 0x10000 if immediate & 0x8000 else 0
            pc = labels['error_return'] + (len(self.save_words()) + index) * 4
            self.assertEqual(pc + 4 + immediate * 4, labels['no_release'])
            self.assertEqual(decision[index + 1], 0)
        attempt = self.core_words('release_attempt', 'release_return')
        self.assertEqual(attempt, (b.lui(8, gates.ATTEMPTING >> 16),
                                   b.ori(8, 8, gates.ATTEMPTING & 0xFFFF),
                                   b.sw(8, 0x10, 23), b.lw(4, 0x14, 23),
                                   b.j_type(3, receipt.RAW_UNLOCK), 0))
        self.assertEqual((gates.TAG, gates.MUTEX, gates.STATUS), (0x10, 0x14, 0x58))
        # ADMITTED alone does not prove continuous same-thread ownership or
        # initialized/live M. Those additional hard premises remain external.

    def test_direct_raw_call_has_private_homes_and_captures_actual_V0_immediately(self):
        code, labels = gates.assemble(*CORE_ARGS)
        words = self.fragment(code, CORE_ARGS[2], CORE_ARGS[2], CORE_ARGS[2] + len(code))
        calls = [(CORE_ARGS[2] + index * 4, word) for index, word in enumerate(words) if word >> 26 == 3]
        self.assertEqual(calls, [(labels['release_return'] - 8, b.j_type(3, 0xA5B830))])
        self.assertEqual(self.core_words('release_return', 'release_error')[0], b.sw(2, 0x58, 23))
        returned = self.core_words('release_return', 'release_error')
        branch = returned[1]
        self.assertEqual((branch >> 26, (branch >> 21) & 31, (branch >> 16) & 31), (4, 2, 0))
        immediate = branch & 0xFFFF
        immediate -= 0x10000 if immediate & 0x8000 else 0
        self.assertEqual(labels['release_return'] + 8 + immediate * 4, labels['release_zero'])
        self.assertEqual(returned[2], 0)
        self.assertFalse(any(word >> 26 == 0 and word & 63 == 9 for word in words))
        private = [word & 0xFFFF for word in self.accesses(words) if (word >> 21) & 31 == 29]
        self.assertTrue(private and all(0x10 <= offset <= 0x8C for offset in private))
        self.assertEqual(gates.FRAME % 8, 0)
        self.assertNotEqual(labels['release_return'], 0x466DD0)
        # This is a new ordinary-ABI import call with a generated RA and free
        # homes00..0F, not a duplicate native466DC0 mask or observer-chain call.

    def test_release_outcome_tags_distinguish_zero_error_and_absent_call(self):
        _, labels = gates.assemble(*CORE_ARGS)
        for first, last, tag in (('release_error', 'release_zero', gates.RELEASE_ERROR),
                                 ('release_zero', 'no_release', gates.RELEASE_ZERO)):
            self.assertEqual(self.core_words(first, last),
                             (b.lui(8, tag >> 16), b.ori(8, 8, tag & 0xFFFF),
                              b.sw(8, 0x10, 23), b.j_type(2, labels['release_done']), 0))
        self.assertEqual(self.core_words('no_release', 'release_done'),
                         (b.sw(0, 0x58, 23), b.lui(8, gates.NO_RELEASE >> 16),
                          b.ori(8, 8, gates.NO_RELEASE & 0xFFFF), b.sw(8, 0x10, 23)))
        self.assertEqual((gates.ATTEMPTING, gates.NO_RELEASE, gates.RELEASE_ZERO, gates.RELEASE_ERROR),
                         tuple(int.from_bytes(tag, 'little') for tag in (b'DGAT', b'DGNR', b'DGR0', b'DGRE')))
        self.assertEqual(self.core_words('release_done', 'exit_replay'), self.restore_words())
        self.assertEqual(self.core_words('exit_replay', None), (b.j_type(2, 0x47C814), 0))
        # Every outcome restores original callback V0/V1 and skips cleanup;
        # no_release also skips it when acquisition proof is absent.

    def test_no_H_lookup_or_generic_callback_V0_classification_is_introduced(self):
        code, labels = gates.assemble(*CORE_ARGS)
        self.assertEqual(len(code), GATE_BYTES)
        words = self.fragment(code, CORE_ARGS[2], CORE_ARGS[2], CORE_ARGS[2] + len(code))
        self.assertTrue(all((word >> 21) & 31 in (23, 29) for word in self.accesses(words)))
        v0_branches = [CORE_ARGS[2] + index * 4 for index, word in enumerate(words)
                       if word >> 26 in (4, 5) and (((word >> 21) & 31) == 2 or ((word >> 16) & 31) == 2)]
        self.assertEqual(v0_branches, [labels['release_return'] + 4])
        alternate = (ARGS[3] + 0x1000, ARGS[4] + 0x1000, *CORE_ARGS[2:])
        self.assertEqual(gates.assemble(*alternate), (code, labels))
        # Only actual raw unlock V0 is branched on, after its immediate store.
        # Original callback V0/V1 are saved/restored without interpretation.

    def test_parent_pairs_and_generated_hook_targets_require_disjoint_preceding_RX(self):
        _, labels = gates.assemble(*CORE_ARGS)
        expected = {PARENT_FIRST: (b.j_type(2, labels['first_scope']), 0),
                    PARENT_SECOND: (b.j_type(2, labels['second_scope']), 0)}
        self.assertEqual(gates.hook_words(labels, PARENT_FIRST, PARENT_SECOND), expected)
        for value in (True, False, None, 0, -4, 1, 0x10000000, 0x100000000):
            for name in ('first_scope', 'second_scope'):
                with self.subTest(label=name, value=value), self.assertRaises(ValueError):
                    gates.hook_words(dict(labels, **{name: value}), PARENT_FIRST, PARENT_SECOND)
            with self.subTest(parent=value), self.assertRaises(ValueError):
                gates.hook_words(labels, value, PARENT_SECOND)
        for first, second in ((PARENT_FIRST, PARENT_FIRST), (PARENT_FIRST, PARENT_FIRST + 4),
                               (CORE_ARGS[2] - 4, PARENT_SECOND), (PARENT_FIRST, CORE_ARGS[2] - 4)):
            with self.subTest(first=first, second=second), self.assertRaises(ValueError):
                gates.assemble(*CORE_ARGS[:3], first, second)
        self.assertEqual(gates.assemble(*CORE_ARGS[:3], PARENT_SECOND, PARENT_FIRST),
                         gates.assemble(*CORE_ARGS))

    def test_static_primary_extra_and_complete_RX_extents_are_strict(self):
        for index in range(5):
            for value in (True, False, None, 0, -4, 1, 1.0, '16', 0x400000, 0xFFFFFFFC, 0x100000000):
                args = list(CORE_ARGS)
                args[index] = value
                with self.subTest(index=index, value=value), self.assertRaises(ValueError):
                    gates.assemble(*args)
        for index, value in ((0, CORE_ARGS[1]), (1, CORE_ARGS[0]),
                              (0, PARENT_FIRST + 4), (1, PARENT_SECOND + 4),
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
                      ((0x400000, 4),), ((CORE_ARGS[0] + 0x288, 4),), ((CORE_ARGS[1] + 20, 4),),
                      ((PARENT_FIRST + 4, 4),), ((PARENT_SECOND + 4, 4),),
                      ((CORE_ARGS[2], 4),), ((0x1F90000, 8), (0x1F90004, 4))):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                gates.assemble(*CORE_ARGS, extra_protected_data=extra)
        size = CORE_ARGS[2] + len(baseline[0]) - PARENT_FIRST
        for protected in (None, (PARENT_FIRST, size), (PARENT_FIRST - 4, size + 8)):
            self.assertEqual(gates.assemble(*CORE_ARGS, protected_code=protected), baseline)
        for protected in ([], (), (True, size), (PARENT_FIRST, True), (PARENT_FIRST, 0),
                          (PARENT_FIRST, 3), (PARENT_FIRST, size - 4), (PARENT_FIRST + 4, size),
                          (PARENT_SECOND, size), (CORE_ARGS[2], len(baseline[0])),
                          (0x400000, 0x2000000), (CORE_ARGS[0], 0x1000000), (0xFFFFFFC, 8)):
            with self.subTest(protected=protected), self.assertRaises(ValueError):
                gates.assemble(*CORE_ARGS, protected_code=protected)

    def test_each_fixed_role_is_excluded_from_new_tail_by_pure_core_checks(self):
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

    def test_direct_parent_default_hash_and_explicit_zero_extension_are_preserved(self):
        parent = self.canonical('parent_default')
        self.assertEqual((len(parent['code']), hashlib.sha256(parent['code']).hexdigest()),
                         (94232, preceding.GATED_SHA256))
        self.assertEqual(parent_stage.assemble(*STAGE_ARGS, following_code_bytes=0), parent)
        # No complete older default-hash chain is rerun here.

    def test_stage_changes_only_two_verified_pairs_in_guarded_prefix_and_appends_core(self):
        result = self.canonical('stage_default')
        prefix, tail = result['dialog_failure_gate_prefix_code_bytes'], result['dialog_failure_gate_code_bytes']
        self.assertEqual((prefix, tail, len(result['code'])), (94232, GATE_BYTES, GATED_BYTES))
        self.assertEqual(hashlib.sha256(result['code']).hexdigest(), GATED_SHA256)
        protected = (ARGS[6], len(result['code']))
        self.assertEqual(result['protected_code_extent'], protected)
        parent = self.canonical('parent_guarded')
        self.assertEqual(parent['protected_code_extent'], protected)
        parents = tuple(parent['refresh_callback_gate_labels'][name]
                        for name in ('first_abort_return', 'second_abort_return'))
        self.assertEqual(parents, (0x1E969A8, 0x1E969B0))
        self.assertEqual(result['dialog_failure_gate_parent_abort_addresses'], parents)
        sources = dict(zip(parents, (gates.PARENT_FIRST_PAIR, gates.PARENT_SECOND_PAIR)))
        self.assertEqual(result['dialog_failure_gate_source_words'], sources)
        hooks = gates.hook_words(result['dialog_failure_gate_labels'], *parents)
        self.assertEqual(result['dialog_failure_gate_hooks'], hooks)
        expected = bytearray(parent['code'])
        for pc, pair in sources.items():
            self.assertEqual(self.fragment(parent['code'], ARGS[6], pc, pc + 8), pair)
            struct.pack_into('<II', expected, pc - ARGS[6], *hooks[pc])
        self.assertEqual(result['code'][:prefix], bytes(expected))
        emitted, labels = gates.assemble(ARGS[3], ARGS[4], ARGS[6] + prefix, *parents,
                                         protected_code=protected)
        self.assertEqual((emitted, labels), (result['code'][prefix:], result['dialog_failure_gate_labels']))
        for name, address in dict(first_scope=0x1E97018, second_scope=0x1E9715C,
                                   error_return=0x1E972A0, release_return=0x1E9736C,
                                   exit_replay=0x1E9743C).items():
            self.assertEqual(labels[name], address)
        for name, address in labels.items():
            self.assertEqual(result['labels']['dialog_failure_gate_' + name], address)

    def test_stage_keeps_all_native_hooks_adds_two_generated_and_preserves_global_limits(self):
        result, parent = self.canonical('stage_default'), self.canonical('parent_default')
        new = result['dialog_failure_gate_hooks']
        self.assertFalse(set(new) & set(parent['coherent_hooks']))
        self.assertEqual(result['native_coherent_hooks'], parent['native_coherent_hooks'])
        self.assertEqual(result['generated_coherent_hooks'], {**parent['generated_coherent_hooks'], **new})
        self.assertEqual(result['coherent_hooks'], {**parent['coherent_hooks'], **new})
        self.assertEqual((len(result['native_coherent_hooks']), len(result['generated_coherent_hooks']),
                          len(result['coherent_hooks'])), (26, 5, 31))
        self.assertNotIn(0x47C7D0, new)
        for flag in ('dialog_callback_failure_cleanup_stopped',
                     'dialog_callback_failure_exact_result_preserved', 'dialog_failure_release_attempt_guarded'):
            self.assertIs(result[flag], True)
        for flag in ('native_callers_isolated', 'destructor_entry_fenced', 'earlier_cleanup_rolled_back',
                     'raw_release_proven', 'native_lifetime_proven', 'partial_graph_cleanup_proven'):
            with self.subTest(flag=flag):
                self.assertIs(result[flag], False)

    def test_parent_and_successor_following_RX_are_strict_and_not_appended(self):
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

    def test_distinct_tail_and_following_alias_inputs_use_the_actual_new_stage(self):
        result = self.canonical('stage_default')
        for address, following in ((ARGS[6] + len(result['code']) - 4, 0),
                                   (ARGS[6] + len(result['code']), 4)):
            args = list(STAGE_ARGS)
            args[-1] = address
            with self.subTest(following=following), self.assertRaises(ValueError):
                stage.assemble(*args, following_code_bytes=following)

    def test_named_valid_outputs_have_independent_metadata_snapshots(self):
        first, second = self.canonical('stage_default'), self.canonical('stage_default')
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        self.assertIsNot(first['labels'], second['labels'])
        self.assertIsNot(first['coherent_hooks'], second['coherent_hooks'])
        first['labels']['snapshot_only'] = 0
        first['coherent_hooks'].clear()
        self.assertNotIn('snapshot_only', second['labels'])
        self.assertEqual(len(second['coherent_hooks']), 31)
        self.assertEqual(self.canonical('stage_default'), second)

    def test_parent_only_cache_restores_after_error_and_never_wraps_new_core_or_stage(self):
        self.assertEqual(len(self._parent_assemblers), 37)
        self.assertEqual(len({module for module, _ in self._parent_assemblers}), 37)
        outer = tuple((module, module.assemble) for module, _ in self._parent_assemblers)
        for module, original in self._parent_assemblers:
            self.assertIsNot(module.assemble, original)
        self.assertIs(gates.assemble, self._new_assemblers[0])
        self.assertIs(stage.assemble, self._new_assemblers[1])
        with self.assertRaisesRegex(RuntimeError, 'dialog-failure parent-cache restoration probe'):
            with parent_fixture._fixture_assembly_cache(True):
                for module, function in outer:
                    self.assertIsNot(module.assemble, function)
                self.assertIs(gates.assemble, self._new_assemblers[0])
                self.assertIs(stage.assemble, self._new_assemblers[1])
                raise RuntimeError('dialog-failure parent-cache restoration probe')
        for module, function in outer:
            self.assertIs(module.assemble, function)
        self.assertIs(gates.assemble, self._new_assemblers[0])
        self.assertIs(stage.assemble, self._new_assemblers[1])


if __name__ == '__main__':
    unittest.main()
