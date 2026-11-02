#!/usr/bin/env python3
"""Pin fresh dialog acquire admission without claiming safe outer cleanup.

The local receipt selects actual raw status before the native facade masks it.
It gates every genuine47C740+10 callsite, not a runtime pinned-U scope. Worker,
callback release and outer container destruction remain separate obligations.
"""

import hashlib
import struct
import unittest
from copy import deepcopy

from build_reveal_bridge_diag import b
import reveal_dialog_acquire_gate_mips as gates
import reveal_dialog_acquire_gate_stage as stage
import reveal_refresh_callback_gate_stage as parent_stage
import reveal_registry_retirement_mips as retirement
import reveal_registry_receipt_mips as receipt
import reveal_registry_owner_mips as bindings
import reveal_registry_lifecycle_mips as lifecycle
import reveal_paint_retirement_mips as owners
import reveal_birth_queue_mips as queue
import test_reveal_refresh_callback_gate_contract as preceding
import test_reveal_refresh_callback_gate_mips as parent_fixture
import test_reveal_registry_birth_contract as native


ARGS, STAGE_ARGS = preceding.ARGS, preceding.STAGE_ARGS
LEGACY_CALL, LEGACY_RETURN = 0x1EC0000, 0x1EC0100
CORE_ARGS = (ARGS[3], ARGS[4], 0x1EE0000, LEGACY_CALL, LEGACY_RETURN)
GATE_BYTES, GATED_BYTES = 1632, 94232
GATED_SHA256 = '6469c7baf0e41b95efbf4992cc74bdb3116ed1e044d84aa3fcffa0d780c0a4f6'


class DialogAcquireGateContractTests(unittest.TestCase):
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
                raise AssertionError('new dialog core/stage assembler was replaced')

    words = native.RegistryBirthContractTests.words

    @classmethod
    def canonical(cls, name):
        """Keep three exact valid outputs as independent metadata snapshots.

        Only35 unchanged parent assemblers are memoized. The new core/stage
        remain unwrapped and validate each distinct invalid/extension input.
        No CPU, native execution state/results or older hash chain is cached.
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

    @staticmethod
    def accesses(words):
        return [word for word in words if word >> 26 in (32, 33, 35, 36, 37, 40, 41, 43)]

    @staticmethod
    def save_words():
        return (b.addiu(29, 29, -192),
                *(b.sw(register, offset, 29) for register, offset in gates.SAVE.items()),
                b.r_type(0, 0, 8, 0x10), b.sw(8, 0x88, 29),
                b.r_type(0, 0, 8, 0x12), b.sw(8, 0x8C, 29),
                b.sw(0, 0x90, 29), b.addiu(23, 29, 192))

    @staticmethod
    def restore_words(denied=False):
        return (b.lw(8, 0x88, 29), b.r_type(8, 0, 0, 0x11),
                b.lw(8, 0x8C, 29), b.r_type(8, 0, 0, 0x13),
                *(b.lw(register, offset, 29) for register, offset in gates.SAVE.items()
                  if not denied or register not in (2, 3)),
                *((b.addiu(2, 0, -1), b.lw(3, 0x90, 29)) if denied else ()),
                b.addiu(29, 29, 192))

    def test_native_frame_buffer_and_three_unused_non_home_locals_are_exact(self):
        self.words(0x47C740, [0x27BDFF98, 0x00002821, 0x24060040,
                              0xAFB0005C, 0x00808021, 0x27A40018,
                              0xAFBF0064, 0x0C296F18, 0xAFB10060])
        memory = {word & 0xFFFF for pc in range(0x47C740, 0x47C828, 4)
                  for word in (self.elf.word(pc),)
                  if word >> 26 in (32, 33, 35, 36, 37, 40, 41, 43)
                  and (word >> 21) & 31 == 29}
        addresses = {word & 0xFFFF for pc in range(0x47C740, 0x47C828, 4)
                     for word in (self.elf.word(pc),)
                     if word >> 26 in (8, 9) and (word >> 21) & 31 == 29
                     and (word >> 16) & 31 != 29}
        self.assertEqual(memory, {0x5C, 0x60, 0x64})
        self.assertEqual(addresses, {0x18})
        self.assertEqual((gates.DIALOG_FRAME, gates.RAW_FRAME, gates.FRAME), (104, 32, 192))
        self.assertEqual((gates.HI, gates.LO, gates.RAW), (0x88, 0x8C, 0x90))
        self.assertEqual((gates.TAG, gates.MUTEX, gates.RAW_STATUS), (0x10, 0x14, 0x58))
        self.assertEqual(0x18 + 0x40, gates.RAW_STATUS)
        self.assertTrue(all(offset >= 0x10 and offset not in memory | addresses
                            for offset in (gates.TAG, gates.MUTEX, gates.RAW_STATUS)))
        # Homes00..0F and buffer18..57 are unavailable. Arithmetic nonuse is
        # not arbitrary-SP mapping, frame authentication or allocation proof.

    def test_direct_facade_chain_preserves_actual_raw_return_before_forced_zero(self):
        self.words(0x47C794, [0x0C119B68, 0x8E040010, 0x8E02003C, 0x8C450000])
        self.words(0x466DA0, [0x27BDFFE0, 0xAFBF001C, 0x0C296E58, 0,
                              0x8FBF001C, 0x00001021, 0x03E00008, 0x27BD0020])
        self.words(0xA5B960, [0x3C0F00A7, 0x8DF9FA58, 0x03200008, 0x25F8FA58])
        self.assertEqual((gates.ACQUIRE, gates.DIALOG_ACQUIRE_RETURN,
                          gates.RAW_ACQUIRE_RETURN), (0x466DA0, 0x47C79C, 0x466DB0))
        self.assertEqual(self.jumps[0x47C794], 0x466DA0)
        self.assertEqual(self.jumps[0x466DA8], receipt.RAW_LOCK)
        # No437D20 facade frame intervenes: actual W=D-32, saved W+1C=47C79C.

    def test_refusal_epilogue_is_pure_and_admission_keeps_callback_and_native_cleanup(self):
        self.words(0x47C814, [0x8FBF0064, 0x8FB10060, 0x8FB0005C,
                              0x03E00008, 0x27BD0068])
        self.words(0x47C79C, [0x8E02003C, 0x8C450000, 0x10A00004, 0x8C510050])
        self.words(0x47C7B8, [0x8E190074, 0x13200004, 0, 0x8E050050,
                              0x0320F809, 0x02002021])
        self.words(0x47C7F4, [0x8E240024, 0x0C1214C8, 0x27A50018,
                              0x0C119B70, 0x8E040010, 0x0C119B78,
                              0x8E040010, 0x00001021])
        self.assertEqual((gates.EPILOGUE, gates.CONTINUATION), (0x47C814, 0x47C7A4))
        # A1 is loaded from H+50, not its address. No callback-error release
        # or cleanup bypass is added after successful acquire admission.

    def test_earlier_worker_handshake_does_not_prove_quiescence_or_destroy_success(self):
        self.words(0x47C77C, [0x0C119B68, 0x8E04000C, 0x0C119B70,
                              0x8E04000C, 0x0C119B78, 0x8E04000C])
        self.words(0x47C6E0, [0x0C119B70, 0x8E040010, 0x0C119B70,
                              0x8E04000C, 0x8E040014, 0x10800005,
                              0x8FBF0034, 0x0C119AA0, 0, 0xAE000014])
        self.words(0x466DE0, [0x27BDFFE0, 0xAFB00018, 0xAFBF001C,
                              0x0C296C3C, 0x00808021, 0x12000004,
                              0x8FBF001C, 0x0C119AA0, 0x02002021])
        self.assertEqual(self.branches[0x466DF4], 0x466E08)
        # Worker still accesses H+14 after+C release. Native destroy frees a
        # nonnull pointer irrespective of raw failure; admission cannot undo it.

    def test_outer_dialog_consumers_ignore_failure_then_unlink_and_free_container(self):
        self.words(0x47CC88, [0x8E39006C, 0x0320F809, 0x02202021,
                              0x3C0200B9, 0x8C44AEB8, 0x24020001,
                              0xA222001D, 0xA220001C, 0x8C990020,
                              0x0320F809, 0x02002821])
        self.words(0x47CCC8, [0x0C119AA0, 0x02202021, 0x8FBF002C])
        self.words(0x47D000, [0x8E39006C, 0x0320F809, 0x02202021,
                              0x3C0200B9, 0x8C44AEB8, 0x24020001,
                              0xA222001D, 0xA220001C, 0x8C990020,
                              0x0320F809, 0x02002821, 0x0C119AA0,
                              0x02202021, 0x8FBF002C])
        # A local refusal preserves V0/V1 only until these native callers
        # ignore them. It neither retains H nor coordinates its other aliases.

    def test_all_four_native_pairs_and_bounded_incoming_census_are_pinned(self):
        expected = dict(begin=(0x47C794, (0x0C119B68, 0x8E040010)),
                        raw_call=(0x466DA8, (0x0C296E58, 0)),
                        raw_return=(0x466DB0, (0x8FBF001C, 0x00001021)),
                        gate=(0x47C79C, (0x8E02003C, 0x8C450000)))
        self.assertEqual(gates.HOOKS, expected)
        for name, (pc, pair) in expected.items():
            self.words(pc, pair)
            for target in (pc, pc + 4):
                with self.subTest(hook=name, target=hex(target)):
                    self.assertEqual({source for source, destination in self.jumps.items()
                                      if destination == target}, set())
                    self.assertEqual({source for source, destination in self.branches.items()
                                      if destination == target}, set())
        self.assertEqual({source for source, destination in self.branches.items()
                          if destination == 0x47C814}, {0x47C764, 0x47C774})
        # Encoded incoming edges are not authentication or a computed-call ban.

    def test_begin_delay_reads_actual_M_once_before_fresh_native_local_initialization(self):
        code, labels = gates.assemble(*CORE_ARGS)
        hooks = gates.hook_words(labels)
        self.assertEqual(hooks[0x47C794], (b.j_type(2, labels['begin']), 0x8E040010))
        words = self.core_words('begin', 'begin_done')
        self.assertEqual(words[:len(self.save_words())], self.save_words())
        self.assertEqual(words[len(self.save_words()):],
                         (b.sw(0, 0x10, 23), b.addiu(8, 0, -1), b.sw(8, 0x58, 23),
                          b.lw(8, gates.SAVE[4], 29), b.sw(8, 0x14, 23),
                          b.lui(8, gates.ARMED >> 16),
                          b.ori(8, 8, gates.ARMED & 0xFFFF), b.sw(8, 0x10, 23)))
        self.assertEqual(self.core_words('begin_replay', 'raw_call'),
                         (b.lui(31, 0x47), b.ori(31, 31, 0xC79C),
                          b.j_type(2, 0x466DA0), 0))
        self.assertNotIn(0x8E040010, struct.unpack('<' + 'I' * (len(code) // 4), code))
        # The sole H+10 load lives in the retained hook delay, not a second
        # helper/decision lookup. The sentinel is MASK, not assumed raw success.

    def test_raw_call_binds_actual_A0_and_W_only_after_ARMED_and_sentinel(self):
        words = self.core_words('raw_call_classified', 'raw_call_done')
        self.assertEqual(self.accesses(words),
                         [b.lw(8, 0x10, 22), b.sw(0, 0x10, 22),
                          b.lw(8, 0x58, 22), b.lw(8, gates.SAVE[4], 29),
                          b.lw(9, 0x14, 22), b.sw(23, 0x58, 22), b.sw(8, 0x10, 22)])
        for value in (gates.ARMED, 0xFFFFFFFF):
            self.assertIn(b.lui(9, value >> 16), words)
            self.assertIn(b.ori(9, 9, value & 0xFFFF), words)
        self.assertEqual(words[-3:], (b.lui(8, gates.ENTERED >> 16),
                                     b.ori(8, 8, gates.ENTERED & 0xFFFF), b.sw(8, 0x10, 22)))
        self.assertEqual(self.core_words('raw_call_replay', 'raw_return'),
                         (b.j_type(2, LEGACY_CALL), 0))
        # RAW_STATUS58 is exact W only during ENTERED. M14 retains actual
        # pre-service A0, independent of any later H field or pinned registry R.

    def test_raw_return_uses_native_RA_same_W_and_saved_V0_before_masking(self):
        words = self.core_words('raw_return_classified', 'raw_return_done')
        self.assertEqual(self.accesses(words),
                         [b.lw(8, gates.SAVE[31], 29), b.lw(8, 0x10, 22),
                          b.sw(0, 0x10, 22), b.lw(8, 0x58, 22),
                          b.lw(8, gates.SAVE[2], 29), b.sw(8, 0x58, 22), b.sw(8, 0x10, 22)])
        self.assertEqual(words[:3], (b.lw(8, gates.SAVE[31], 29),
                                    b.lui(9, 0x46), b.ori(9, 9, 0x6DB0)))
        self.assertEqual(words[-3:], (b.lui(8, gates.CAPTURED >> 16),
                                     b.ori(8, 8, gates.CAPTURED & 0xFFFF), b.sw(8, 0x10, 22)))
        self.assertNotIn(b.lw(8, gates.SAVE[4], 29), words)
        self.assertNotIn(b.lw(8, gates.SAVE[25], 29), words)
        self.assertEqual(self.core_words('raw_return_replay', 'gate'),
                         (b.j_type(2, LEGACY_RETURN), 0))
        # Returned A0/T9 are volatile. Actual saved V0 is consumed before the
        # delegated native forced-zero pair, without adding a second service.

    def test_gate_consumes_CAPTURED_zero_becomes_ADMITTED_and_denial_has_no_service(self):
        words = self.core_words('gate', 'gate_denied')[len(self.save_words()):]
        self.assertEqual(self.accesses(words), [b.lw(8, 0x10, 23), b.sw(0, 0x10, 23),
                                               b.lw(8, 0x58, 23), b.sw(8, 0x90, 29)])
        self.assertEqual(words[2:4], (b.lui(9, gates.CAPTURED >> 16),
                                     b.ori(9, 9, gates.CAPTURED & 0xFFFF)))
        self.assertEqual(self.core_words('gate_admitted', 'gate_done'),
                         (b.lui(8, gates.ADMITTED >> 16),
                          b.ori(8, 8, gates.ADMITTED & 0xFFFF), b.sw(8, 0x10, 23)))
        self.assertEqual(self.core_words('gate_denied', 'gate_admitted'),
                         (*self.restore_words(denied=True), b.j_type(2, 0x47C814), 0))
        self.assertEqual(self.core_words('gate_replay', None),
                         (0x8E02003C, 0x8C450000, b.j_type(2, 0x47C7A4), 0))
        self.assertEqual((gates.ARMED, gates.ENTERED, gates.CAPTURED, gates.ADMITTED),
                         tuple(int.from_bytes(tag, 'little')
                               for tag in (b'DGAA', b'DGAE', b'DGAC', b'DGAD')))
        self.assertEqual(len({gates.ARMED, gates.ENTERED, gates.CAPTURED, gates.ADMITTED}), 4)
        # Save zeroes privateRAW90 before classification: missing CAPTURED gives
        # MASK/0, captured error gives MASK/exact. ADMITTED cannot replay CAPTURED.

    def test_all_phases_preserve_full_architecture_and_raw_scope_never_reads_H_or_U(self):
        code, labels = gates.assemble(*CORE_ARGS)
        self.assertEqual(len(code), GATE_BYTES)
        for name in ('begin', 'raw_call', 'raw_return', 'gate'):
            with self.subTest(prologue=name):
                self.assertEqual(self.fragment(code, CORE_ARGS[2], labels[name],
                                               labels[name] + len(self.save_words()) * 4),
                                 self.save_words())
            with self.subTest(restore=name):
                self.assertEqual(self.core_words(name + '_done', name + '_replay'),
                                 self.restore_words())
        for name in ('raw_call', 'raw_return'):
            scope = self.core_words(name, name + '_classified')[len(self.save_words()):]
            self.assertEqual(self.accesses(scope), [b.lw(8, 0x1C, 23)])
            self.assertEqual(scope[:3], (b.lw(8, 0x1C, 23),
                                        b.lui(9, 0x47), b.ori(9, 9, 0xC79C)))
            self.assertEqual(scope[-1], b.addiu(22, 23, 32))
        words = self.fragment(code, CORE_ARGS[2], CORE_ARGS[2], labels['gate_replay'])
        self.assertTrue(all((word >> 21) & 31 in (22, 23, 29) for word in self.accesses(words)))
        self.assertFalse(any(word >> 26 == 3 for word in words))
        self.assertFalse(any(word >> 26 == 0 and word & 63 == 9 for word in words))
        alternate = (ARGS[3] + 0x1000, ARGS[4] + 0x1000, *CORE_ARGS[2:])
        self.assertEqual(gates.assemble(*alternate), (code, labels))
        # U/R change only validation, not emitted runtime scope. The two graph
        # reads occur exclusively in admitted gate_replay after full restoration.

    def test_hook_targets_and_two_exact_preceding_delegate_entries_are_strict(self):
        _, labels = gates.assemble(*CORE_ARGS)
        hooks = gates.hook_words(labels)
        self.assertEqual(set(hooks), {0x47C794, 0x466DA8, 0x466DB0, 0x47C79C})
        for name, (pc, _) in gates.HOOKS.items():
            self.assertEqual(hooks[pc], (b.j_type(2, labels[name]), 0x8E040010 if name == 'begin' else 0))
            for value in (True, False, None, 0, -4, 1, 0x10000000, 0x100000000):
                with self.subTest(hook=name, value=value), self.assertRaises(ValueError):
                    gates.hook_words(dict(labels, **{name: value}))
        for call, returned in ((0x400000, LEGACY_RETURN), (LEGACY_CALL, 0x400000),
                               (CORE_ARGS[2], LEGACY_RETURN), (LEGACY_CALL, CORE_ARGS[2]),
                               (LEGACY_CALL, LEGACY_CALL)):
            with self.subTest(call=call, returned=returned), self.assertRaises(ValueError):
                gates.assemble(*CORE_ARGS[:3], call, returned)
        self.assertEqual(len(gates.assemble(*CORE_ARGS[:3], LEGACY_RETURN, LEGACY_CALL)[0]), GATE_BYTES)

    def test_primary_extra_and_complete_RX_layout_validation_is_static_and_strict(self):
        for index in range(5):
            for value in (True, False, None, 0, -4, 1, 1.0, '16',
                          0x400000, 0xFFFFFFFC, 0x100000000):
                args = list(CORE_ARGS)
                args[index] = value
                with self.subTest(index=index, value=value), self.assertRaises(ValueError):
                    gates.assemble(*args)
        for index, value in ((0, CORE_ARGS[1]), (1, CORE_ARGS[0]),
                              (0, LEGACY_CALL), (1, LEGACY_RETURN),
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
                      ((CORE_ARGS[1] + 20, 4),), ((LEGACY_CALL, 4),),
                      ((LEGACY_RETURN, 4),), ((CORE_ARGS[2], 4),),
                      ((0x1F90000, 8), (0x1F90004, 4))):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                gates.assemble(*CORE_ARGS, extra_protected_data=extra)
        size = CORE_ARGS[2] + len(baseline[0]) - LEGACY_CALL
        for protected in (None, (LEGACY_CALL, size), (LEGACY_CALL - 4, size + 8)):
            self.assertEqual(gates.assemble(*CORE_ARGS, protected_code=protected), baseline)
        for protected in ([], (), (True, size), (LEGACY_CALL, True),
                          (LEGACY_CALL, 0), (LEGACY_CALL, 3), (LEGACY_CALL, size - 4),
                          (LEGACY_CALL + 4, size), (CORE_ARGS[2], len(baseline[0])),
                          (0x400000, 0x2000000), (CORE_ARGS[0], 0x1000000), (0xFFFFFFC, 8)):
            with self.subTest(protected=protected), self.assertRaises(ValueError):
                gates.assemble(*CORE_ARGS, protected_code=protected)

    def test_all_fixed_roles_are_excluded_from_new_tail_by_pure_core_validation(self):
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

    def test_direct_parent_hash_and_explicit_zero_extension_remain_unchanged(self):
        parent = self.canonical('parent_default')
        self.assertEqual((len(parent['code']), hashlib.sha256(parent['code']).hexdigest()),
                         (92600, preceding.GATED_SHA256))
        self.assertEqual(parent_stage.assemble(*STAGE_ARGS, following_code_bytes=0), parent)
        # No complete older default-hash chain is rerun here.

    def test_stage_appends_only_the_exact_new_core_to_the_complete_guarded_parent(self):
        result = self.canonical('stage_default')
        prefix, tail = (result['dialog_acquire_gate_prefix_code_bytes'],
                        result['dialog_acquire_gate_code_bytes'])
        self.assertEqual((prefix, tail, len(result['code'])), (92600, GATE_BYTES, GATED_BYTES))
        self.assertEqual(hashlib.sha256(result['code']).hexdigest(), GATED_SHA256)
        protected = (ARGS[6], len(result['code']))
        self.assertEqual(result['protected_code_extent'], protected)
        parent = self.canonical('parent_guarded')
        self.assertEqual(parent['protected_code_extent'], protected)
        self.assertEqual(result['code'][:prefix], parent['code'])
        legacy = {name: parent['retirement_labels'][name] for name in ('raw_call', 'raw_return')}
        self.assertEqual(result['dialog_acquire_gate_legacy_entries'], legacy)
        emitted, labels = gates.assemble(ARGS[3], ARGS[4], ARGS[6] + prefix,
                                         *legacy.values(), protected_code=protected)
        self.assertEqual((emitted, labels), (result['code'][prefix:], result['dialog_acquire_gate_labels']))
        self.assertEqual(labels['begin'], 0x1E969B8)
        for name, address in labels.items():
            self.assertEqual(result['labels']['dialog_acquire_gate_' + name], address)

    def test_stage_replaces_current_raw_observers_adds_two_pairs_and_keeps_generated_hooks(self):
        result, parent = self.canonical('stage_default'), self.canonical('parent_default')
        old = retirement.hook_words(parent['retirement_labels'])
        replaced = {retirement.HOOKS[name][0]: old[retirement.HOOKS[name][0]]
                    for name in ('raw_call', 'raw_return')}
        self.assertEqual(result['dialog_acquire_gate_replaced_hooks'], replaced)
        for pc, pair in replaced.items():
            self.assertEqual(parent['coherent_hooks'][pc], pair)
            self.assertEqual(parent['native_coherent_hooks'][pc], pair)
        hooks = gates.hook_words(result['dialog_acquire_gate_labels'])
        self.assertEqual(result['dialog_acquire_gate_hooks'], hooks)
        self.assertEqual(set(hooks) - set(replaced), {0x47C794, 0x47C79C})
        self.assertFalse((set(hooks) - set(replaced)) & set(parent['coherent_hooks']))
        self.assertEqual(result['native_coherent_hooks'], {**parent['native_coherent_hooks'], **hooks})
        self.assertEqual(result['generated_coherent_hooks'], parent['generated_coherent_hooks'])
        self.assertEqual(result['coherent_hooks'], {**parent['coherent_hooks'], **hooks})
        self.assertEqual((len(result['native_coherent_hooks']), len(result['generated_coherent_hooks']),
                          len(result['coherent_hooks'])), (26, 3, 29))
        self.assertIs(result['dialog_acquire_failure_admission_gated'], True)
        for flag in ('native_callers_isolated', 'destructor_entry_fenced', 'earlier_cleanup_rolled_back',
                     'raw_release_proven', 'native_lifetime_proven', 'partial_graph_cleanup_proven'):
            with self.subTest(flag=flag):
                self.assertIs(result[flag], False)

    def test_following_RX_configuration_is_strict_and_never_appended(self):
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

    def test_distinct_tail_and_following_alias_configurations_call_actual_new_stage(self):
        result = self.canonical('stage_default')
        for address, following in ((ARGS[6] + len(result['code']) - 4, 0),
                                   (ARGS[6] + len(result['code']), 4)):
            args = list(STAGE_ARGS)
            args[-1] = address
            with self.subTest(following=following), self.assertRaises(ValueError):
                stage.assemble(*args, following_code_bytes=following)

    def test_named_valid_output_snapshots_have_independent_mutable_metadata(self):
        first, second = self.canonical('stage_default'), self.canonical('stage_default')
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        self.assertIsNot(first['labels'], second['labels'])
        self.assertIsNot(first['coherent_hooks'], second['coherent_hooks'])
        first['labels']['snapshot_only'] = 0
        first['coherent_hooks'].clear()
        self.assertNotIn('snapshot_only', second['labels'])
        self.assertEqual(len(second['coherent_hooks']), 29)
        self.assertEqual(self.canonical('stage_default'), second)

    def test_parent_only_cache_restores_identities_after_error_and_leaves_new_code_unwrapped(self):
        self.assertEqual(len(self._parent_assemblers), 35)
        self.assertEqual(len({module for module, _ in self._parent_assemblers}), 35)
        outer = tuple((module, module.assemble) for module, _ in self._parent_assemblers)
        for module, original in self._parent_assemblers:
            self.assertIsNot(module.assemble, original)
        self.assertIs(gates.assemble, self._new_assemblers[0])
        self.assertIs(stage.assemble, self._new_assemblers[1])
        with self.assertRaisesRegex(RuntimeError, 'dialog-parent-cache restoration probe'):
            with parent_fixture._fixture_assembly_cache(True):
                for module, function in outer:
                    self.assertIsNot(module.assemble, function)
                self.assertIs(gates.assemble, self._new_assemblers[0])
                self.assertIs(stage.assemble, self._new_assemblers[1])
                raise RuntimeError('dialog-parent-cache restoration probe')
        for module, function in outer:
            self.assertIs(module.assemble, function)
        self.assertIs(gates.assemble, self._new_assemblers[0])
        self.assertIs(stage.assemble, self._new_assemblers[1])


if __name__ == '__main__':
    unittest.main()
