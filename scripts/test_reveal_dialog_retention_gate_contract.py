#!/usr/bin/env python3
"""Pin terminal known-consumer retention without inventing M ownership.

The dedicated Q word serializes two native consumer bodies and blocks their
future entry after a classified error. Other H/M clients and higher callers
remain outside this bounded protection; no direct unlock is authorized.
"""

import hashlib
import struct
import unittest
from copy import deepcopy

from build_reveal_bridge_diag import b
import reveal_dialog_retention_gate_mips as gates
import reveal_dialog_retention_gate_stage as stage
import reveal_dialog_failure_gate_stage as parent_stage
import reveal_registry_receipt_mips as receipt
import reveal_registry_owner_mips as bindings
import reveal_registry_lifecycle_mips as lifecycle
import reveal_paint_retirement_mips as owners
import reveal_birth_queue_mips as queue
import test_reveal_dialog_failure_gate_contract as preceding
import test_reveal_dialog_failure_gate_mips as parent_fixture
import test_reveal_registry_birth_contract as native


ARGS, STAGE_ARGS = preceding.ARGS, preceding.STAGE_ARGS
GUARD, PARENT_ERROR, PARENT_DENIED = 0x1F20900, 0x1ED0000, 0x1ED0010
CORE_ARGS = (ARGS[3], ARGS[4], 0x1EE0000, PARENT_ERROR, PARENT_DENIED, GUARD)
GATE_BYTES, GATED_BYTES = 3808, 99108
GATED_SHA256 = 'c0ed5db6dcc4a668fe2532ffde5ca3c874c354c97860acb24d56e14f0d4180d3'


class DialogRetentionGateContractTests(unittest.TestCase):
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
                raise AssertionError('new retention core/stage was replaced')

    words = native.RegistryBirthContractTests.words

    @classmethod
    def canonical(cls, name):
        """Copy three valid outputs; only39 unchanged parents are memoized.

        New core/stage stay unwrapped for distinct validation/configuration.
        No CPU, native execution state/results or older hash chain is cached.
        """
        if name not in cls._canonical_outputs:
            if name == 'parent_default':
                emitted = parent_stage.assemble(*STAGE_ARGS)
            elif name == 'parent_guarded':
                tail = len(gates.assemble(*CORE_ARGS)[0])
                emitted = parent_stage.assemble(*STAGE_ARGS, following_code_bytes=tail)
            elif name == 'stage_default':
                emitted = stage.assemble(*STAGE_ARGS, guard_address=GUARD)
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
        return [word for word in words if word >> 26 in (32, 33, 35, 36, 37, 40, 41, 43, 0x30, 0x38)]

    @staticmethod
    def save_words():
        return (b.addiu(29, 29, -192),
                *(b.sw(register, offset, 29) for register, offset in gates.SAVE.items()),
                b.r_type(0, 0, 8, 0x10), b.sw(8, 0x88, 29),
                b.r_type(0, 0, 8, 0x12), b.sw(8, 0x8C, 29), b.addiu(23, 29, 192))

    @staticmethod
    def restore_words(denied=False):
        return (b.lw(8, 0x88, 29), b.r_type(8, 0, 0, 0x11),
                b.lw(8, 0x8C, 29), b.r_type(8, 0, 0, 0x13),
                *(b.lw(register, offset, 29) for register, offset in gates.SAVE.items()
                  if not denied or register not in (2, 3)),
                *((b.addiu(2, 0, -1), b.move(3, 0)) if denied else ()),
                b.addiu(29, 29, 192))

    def test_native_entry_pairs_frames_and_null_close_leaf_are_exact(self):
        self.words(0x47CC20, [0x27BDFFD0, 0xAFB20024, 0x3C1200B9,
                              0x8E44AEB8, 0xAFB30028, 0xAFB0001C,
                              0xAFBF002C, 0xAFB10020])
        self.words(0x47CF80, [0x10800033, 0, 0x27BDFFD0, 0xAFB30024,
                              0x3C1300B9, 0xAFB20020, 0x00809021,
                              0x8E64AEB8, 0xAFB40028, 0xAFBF002C,
                              0xAFB1001C, 0xAFB00018])
        self.words(0x47D050, [0x03E00008, 0])
        self.assertEqual(self.branches[0x47CF80], 0x47D050)
        self.assertEqual((gates.OUTER_FRAME, gates.OWNER, gates.FUTURE_OWNER), (48, 0x10, 0xA0))
        self._assert_native_stamp_slots_have_no_uses()
        # close(NULL) has no native O frame; helper private192 mapping is an
        # extra hard premise even though its result and Q are left untouched.

    def test_every_framed_return_crosses_the_selected_pure_leave_pair(self):
        self.words(0x47CCD0, [0x8FBF002C, 0x8FB30028, 0x8FB20024,
                              0x8FB10020, 0x8FB0001C, 0x03E00008, 0x27BD0030])
        self.words(0x47D034, [0x8FBF002C, 0x8FB40028, 0x8FB30024,
                              0x8FB20020, 0x8FB1001C, 0x8FB00018,
                              0x27BD0030, 0x03E00008, 0])
        self.assertEqual({pc for pc, target in self.branches.items() if target == 0x47CCD4}, {0x47CC54, 0x47CC5C})
        self.words(0x47CC54, [0x1000001F, 0x8FBF002C, 0x1213001D, 0x8FBF002C])
        self.assertEqual(self.branches[0x47CFBC], 0x47D034)
        self.assertEqual(self.branches[0x47CFCC], 0x47D038)
        self.words(0x47CFCC, [0x1214001A, 0x8FBF002C])
        for first, last, expected in ((0x47CC20, 0x47CCEC, {0x47CCE4}),
                                       (0x47CF80, 0x47D058, {0x47D050})):
            returns = {pc for pc in range(first, last, 4) if self.elf.word(pc) == 0x03E00008}
            self.assertEqual(returns, expected)
        # RA/S3 are already restored at poll_leave; RA/S4 at close_leave.
        # After replay, only native stack restoration and JR remain.

    def _assert_native_stamp_slots_have_no_uses(self):
        for first, last, saved in ((0x47CC20, 0x47CCEC, {0x1C, 0x20, 0x24, 0x28, 0x2C}),
                                    (0x47CF80, 0x47D058, {0x18, 0x1C, 0x20, 0x24, 0x28, 0x2C})):
            memory, addresses = set(), set()
            for pc in range(first, last, 4):
                word = self.elf.word(pc)
                if (word >> 21) & 31 != 29:
                    continue
                if word >> 26 in (32, 33, 35, 36, 37, 40, 41, 43):
                    memory.add(word & 0xFFFF)
                if word >> 26 in (8, 9) and (word >> 16) & 31 != 29:
                    addresses.add(word & 0xFFFF)
            self.assertEqual(memory, saved)
            self.assertEqual(addresses, set())
        self.assertEqual(gates.FRAME - gates.OUTER_FRAME + gates.OWNER, gates.FUTURE_OWNER)
        self.assertGreater(gates.FUTURE_OWNER, gates.LO + 3)
        self.assertLessEqual(gates.FUTURE_OWNER + 4, gates.FRAME)
        self.assertEqual(gates.OWNERSTAMP, int.from_bytes(b'QOWN', 'little'))
        # FutureO+10=P+A0=S-32 is padding after saves endingP+8F. Native
        # prologues and ordinary callee argument homes00..0F do not use it.

    def test_encoded_entry_tail_and_delay_census_is_bounded_not_authentication(self):
        expected = dict(poll_enter=(0x47CC20, (0x27BDFFD0, 0xAFB20024)),
                        close_enter=(0x47CF80, (0x10800033, 0)),
                        poll_leave=(0x47CCD8, (0x8FB20024, 0x8FB10020)),
                        close_leave=(0x47D03C, (0x8FB30024, 0x8FB20020)),
                        facade_enter=(0x47D060, (0x27BDFFE0, 0xAFBF001C)),
                        facade_leave=(0x47D084, (0x8FBF001C, 0x8FB00018)))
        self.assertEqual(gates.HOOKS, expected)
        for name, (pc, pair) in expected.items():
            self.words(pc, pair)
            for target in (pc + 4,):
                self.assertEqual({source for source, destination in self.jumps.items() if destination == target}, set())
                self.assertEqual({source for source, destination in self.branches.items() if destination == target}, set())
        self.assertEqual({pc for pc, target in self.jumps.items() if target == 0x47CC20}, {0x43C9CC})
        self.assertEqual({pc for pc, target in self.jumps.items() if target == 0x47CF80}, {0x47D07C})
        for target in (0x47CCD8, 0x47D03C, 0x47CCE0, 0x47D044):
            self.assertEqual({pc for pc, destination in self.jumps.items() if destination == target}, set())
            self.assertEqual({pc for pc, destination in self.branches.items() if destination == target}, set())
        # Other computed entries and functions holding escaped H aliases are
        # outside this exact six-pair native frontier.

    def test_ownership_audit_has_concrete_escaped_H_and_masked_mutex_clients(self):
        self.words(0x459330, [0xAC85007C, 0x03E00008, 0])
        self.words(0x459348, [0x03E00008, 0x8C82007C])
        self.words(0x4AF008, [0x0C1164D0, 0x00A02021, 0x8C430058,
                              0x10600002, 0x00402021, 0xAC600004,
                              0x0C11F428, 0x24050001])
        self.words(0x47D0C0, [0x8C840010, 0x0C119B68, 0x00A08821])
        self.words(0x47D0DC, [0x0C119B70, 0x8E040010])
        self.words(0x493C2C, [0x8E194224, 0x13200003, 0, 0x0320F809, 0x02002021])
        # Synchronous call/return does not close these alias/computed/import
        # paths. ADMITTED is not continuous M ownership or release authority.

    def test_higher_close_facade_and_music_loop_keep_their_existing_obligations(self):
        self.words(0x47D060, [0x27BDFFE0, 0xAFBF001C, 0xAFB00018,
                              0x0C11F268, 0x00808021, 0x0C119B88,
                              0x2404000A, 0x0C11F3E0, 0x8E040024])
        self.words(0x43C9CC, [0x0C11F308, 0, 0x0C10DE98, 0x02002021,
                              0x0C10DF50, 0x02002021])
        self.words(0x47C9B0, [0x0C119B68, 0x8C840010, 0x8E040010,
                              0x24020001, 0xAE020004, 0x0C119B70, 0])
        self.words(0x47D084, [0x8FBF001C, 0x8FB00018, 0x00001021,
                              0x03E00008, 0x27BD0020])
        memory = {word & 0xFFFF for pc in range(0x47D060, 0x47D098, 4)
                  for word in (self.elf.word(pc),)
                  if word >> 26 in (35, 43) and (word >> 21) & 31 == 29}
        self.assertEqual(memory, {0x18, 0x1C})
        self.assertEqual((gates.FACADE_FRAME, gates.FUTURE_FACADE_OWNER), (32, 0xB0))
        self.assertEqual(gates.FRAME - gates.FACADE_FRAME + gates.OWNER, gates.FUTURE_FACADE_OWNER)
        for target in (0x47D060, 0x47D064, 0x47D068, 0x47D084, 0x47D088, 0x47D08C, 0x47D090, 0x47D094):
            self.assertEqual({pc for pc, destination in self.jumps.items() if destination == target}, set())
            self.assertEqual({pc for pc, destination in self.branches.items() if destination == target}, set())
        # Facade entry claims before47C9A0's M operation. Its child borrows
        # that live claim; higher music-loop paint-unlock remains unchanged.

    def test_both_generated_parent_pairs_and_separate_denial_resume_are_verified(self):
        parent = self.canonical('parent_default')
        callback = parent['dialog_failure_gate_labels']['error_return']
        denied = parent['dialog_acquire_gate_labels']['gate_denied']
        self.assertEqual((callback, denied), (0x1E972A0, 0x1E96EDC))
        self.assertEqual(self.fragment(parent['code'], ARGS[6], callback, callback + 8),
                         (0x27BDFF40, 0xAFA10010))
        self.assertEqual(self.fragment(parent['code'], ARGS[6], denied, denied + 12),
                         (0x8FA80088, 0x01000011, 0x8FA8008C))
        self.assertEqual(gates.PARENT_CALLBACK_PAIR, (0x27BDFF40, 0xAFA10010))
        self.assertEqual((*gates.PARENT_DENIED_PAIR, gates.PARENT_DENIED_RESUME),
                         (0x8FA80088, 0x01000011, 0x8FA8008C))

    def test_callback_error_latches_Q_and_bypasses_old_unlock_without_M_lookup(self):
        words = self.core_words('callback_entry', 'callback_retain_second')
        self.assertEqual(words[:len(self.save_words())], self.save_words())
        body = words[len(self.save_words()):]
        self.assertEqual(body[:6], (b.lui(20, GUARD >> 16), b.ori(20, 20, GUARD & 0xFFFF),
                                   b.addiu(8, 0, 2), gates.SYNC, b.sw(8, 0, 20), gates.SYNC))
        self.assertEqual(self.accesses(body), [b.sw(8, 0, 20), b.sw(0, 0x58, 23),
                                              b.sw(8, 0x10, 23), b.lw(8, 0x64, 23)])
        self.assertEqual(self.core_words('callback_retain_done', 'deny_entry'),
                         (*self.restore_words(), b.j_type(2, 0x47C814), 0))
        self.assertEqual(gates.RETAINED_CALLBACK, int.from_bytes(b'QDCB', 'little'))
        # QDCB invalidates ADMITTED. No captured M load or old raw-release
        # body is entered; original callback V0/V1 survive the pure D unwind.

    def test_acquisition_denial_uses_existing_save_RAW90_and_exact_HI_resume(self):
        words = self.core_words('deny_entry', 'denied_retain_second')
        self.assertEqual(words[0], b.addiu(23, 29, 192))
        self.assertNotIn(b.addiu(29, 29, -192), words)
        self.assertEqual(self.accesses(words), [b.sw(8, 0, 20), b.lw(8, 0x90, 29),
                                               b.sw(8, 0x58, 23), b.sw(8, 0x10, 23),
                                               b.lw(8, 0x64, 23)])
        self.assertEqual(self.core_words('deny_replay', 'poll_enter'),
                         (0x8FA80088, 0x01000011, b.j_type(2, PARENT_DENIED + 8), 0))
        self.assertEqual(gates.RETAINED_ACQUIRE, int.from_bytes(b'QDAD', 'little'))
        # The parent's LO/GPR restore and MASK/exactRAW assignment still run.

    def test_errors_retarget_only_the_two_genuine_D_saved_outer_returns(self):
        _, labels = gates.assemble(*CORE_ARGS)
        for scope in ('callback_retain', 'denied_retain'):
            for first, last, target, trailer in (
                    (scope + '_first', scope + '_done', 'first_outer_return', ()),
                    (scope + '_second', scope + '_first', 'second_outer_return',
                     (b.j_type(2, labels[scope + '_done']), 0))):
                address = labels[target]
                self.assertEqual(self.core_words(first, last),
                                 (b.lui(8, address >> 16), b.ori(8, 8, address & 0xFFFF),
                                  b.sw(8, 0x64, 23), *trailer))
        self.assertEqual(self.core_words('first_outer_return', 'second_outer_return'),
                         (b.j_type(2, 0x47CCD0), 0))
        self.assertEqual(self.core_words('second_outer_return', None), (b.j_type(2, 0x47D034), 0))
        self.assertEqual((gates.FIRST_RETURN, gates.SECOND_RETURN), (0x47CC94, 0x47D00C))
        # Foreign D.savedRA remains unchanged, but Q stays terminal. No H
        # lookup or guessed native free/unlock is needed to select these exits.

    def test_entry_claims_have_bounded_LL_SC_READY_to_BUSY_before_native_reads(self):
        _, labels = gates.assemble(*CORE_ARGS)
        for name in ('poll_enter', 'close_enter', 'facade_enter'):
            words = self.core_words(name + '_retry', name + '_claimed')
            self.assertEqual(words[0], b.i_type(0x30, 20, 8, 0))
            self.assertEqual(words[3:5], (b.addiu(9, 0, 1), b.i_type(0x38, 20, 9, 0)))
            self.assertIn(b.addiu(12, 12, -1), words)
            self.assertEqual(words[-2:], (b.j_type(2, labels[name + '_denied']), 0))
            self.assertEqual(self.accesses(words), [b.i_type(0x30, 20, 8, 0), b.i_type(0x38, 20, 9, 0)])
            scope = self.core_words(name, name + '_retry')
            self.assertIn(b.addiu(12, 0, 8), scope)
        self.assertEqual((gates.READY, gates.BUSY, gates.QUARANTINED), (0, 1, 2))
        # Any nonzero Q refuses independent admission; SC exhaustion reaches
        # a local MASK/0 return without entering a list/object body.

    def test_success_stamps_owned_future_frames_and_replays_native_prologues_once(self):
        for name, stamp, offset, pair, continuation in (
                ('poll_enter', gates.OWNERSTAMP, 0xA0, (0x27BDFFD0, 0xAFB20024), 0x47CC28),
                ('close_enter', gates.OWNERSTAMP, 0xA0, (), 0x47CF88),
                ('facade_enter', gates.FACADESTAMP, 0xB0, (0x27BDFFE0, 0xAFBF001C), 0x47D068)):
            self.assertEqual(self.core_words(name + '_claimed', name + '_done'),
                             (gates.SYNC, b.lui(8, stamp >> 16),
                              b.ori(8, 8, stamp & 0xFFFF), b.sw(8, offset, 29)))
            self.assertEqual(self.core_words(name + '_done', name + '_replay'), self.restore_words())
            self.assertEqual(self.core_words(name + '_replay', name + '_denied'),
                             (*pair, b.j_type(2, continuation), 0))
        self.assertEqual(gates.FACADESTAMP, int.from_bytes(b'QFAC', 'little'))

    def test_busy_rejections_and_close_NULL_restore_without_claiming_an_O_frame(self):
        for name, following in (('poll_enter', 'close_enter'),
                                 ('close_enter', 'close_enter_null'),
                                 ('facade_enter', 'poll_leave')):
            self.assertEqual(self.core_words(name + '_denied', following),
                             (*self.restore_words(denied=True), b.r_type(31, 0, 0, 8), 0))
        self.assertEqual(self.core_words('close_enter_null', 'facade_enter'),
                         (*self.restore_words(), b.r_type(31, 0, 0, 8), 0))
        prefix = self.core_words('close_enter', 'close_enter_own')[len(self.save_words()):]
        self.assertEqual(prefix[:1], (b.lw(8, gates.SAVE[4], 29),))
        self.assertEqual((prefix[1] >> 26, (prefix[1] >> 21) & 31, (prefix[1] >> 16) & 31), (4, 8, 0))
        # NULL branches before Q inspection or borrowing. Private saves still
        # require mapped retained stack even on native-leaf/rejected routes.

    def test_inner_close_borrows_only_verified_facade_return_stamp_and_BUSY(self):
        _, labels = gates.assemble(*CORE_ARGS)
        words = self.core_words('close_enter', 'close_enter_own')[len(self.save_words()):]
        self.assertEqual(self.accesses(words), [b.lw(8, gates.SAVE[4], 29),
                                               b.lw(8, gates.SAVE[31], 29), b.lw(8, 0x10, 23),
                                               b.lw(8, 0, 20), b.sw(8, 0xA0, 29)])
        for value in (0x47D084, gates.FACADESTAMP, gates.BORROWED):
            register = 8 if value == gates.BORROWED else 9
            self.assertIn(b.lui(register, value >> 16), words)
            self.assertIn(b.ori(register, register, value & 0xFFFF), words)
        self.assertEqual(words[-2:], (b.j_type(2, labels['close_enter_done']), 0))
        self.assertEqual(gates.BORROWED, int.from_bytes(b'QBOR', 'little'))
        self.assertEqual(self.core_words('close_leave_borrowed', 'close_leave_done'), (b.sw(0, 0x10, 23),))
        # Borrowing consumes only the child's O stamp at leave; the facade's
        # current F stamp and atomic Q claim remain live until facade_leave.

    def test_owned_leave_consumes_stamp_and_clears_only_BUSY_never_QUARANTINED(self):
        for name in ('poll_leave', 'close_leave'):
            prefix = self.core_words(name, name + '_retry')[len(self.save_words()):]
            self.assertEqual(prefix[0], b.lw(8, 0x10, 23))
            self.assertIn(b.sw(0, 0x10, 23), prefix)
            stop = name + '_borrowed' if name == 'close_leave' else name + '_done'
            words = self.core_words(name + '_retry', stop)
            self.assertEqual(words[:2], (b.i_type(0x30, 20, 8, 0), b.addiu(9, 0, 1)))
            self.assertEqual((words[2] >> 26, (words[2] >> 21) & 31, (words[2] >> 16) & 31), (5, 8, 9))
            self.assertEqual(words[4:6], (b.move(9, 0), b.i_type(0x38, 20, 9, 0)))
            self.assertIn(b.addiu(12, 12, -1), words)
            self.assertIn(b.addiu(8, 0, 2), words)
        # A Q2 load branches to restoration before SC0; exhausted SC retries
        # latch2. No code attempts to reset the guard from terminal quarantine.

    def test_leave_replays_only_displaced_stack_loads_before_native_return_suffix(self):
        for name, following, pair, continuation in (
                ('poll_leave', 'close_leave', (0x8FB20024, 0x8FB10020), 0x47CCE0),
                ('close_leave', 'facade_leave', (0x8FB30024, 0x8FB20020), 0x47D044)):
            self.assertEqual(self.core_words(name + '_done', name + '_replay'),
                             (gates.SYNC, *self.restore_words()))
            self.assertEqual(self.core_words(name + '_replay', following),
                             (*pair, b.j_type(2, continuation), 0))
        # No H lookup/service remains after releasing the owned Q claim.

    def test_facade_owned_leave_preserves_child_error_on_quarantine_and_native_zero_normally(self):
        _, labels = gates.assemble(*CORE_ARGS)
        retry = self.core_words('facade_leave_retry', 'facade_leave_fault')
        self.assertEqual(retry[:2], (b.i_type(0x30, 20, 8, 0), b.addiu(9, 0, 1)))
        self.assertEqual(retry[4:6], (b.move(9, 0), b.i_type(0x38, 20, 9, 0)))
        fault = self.core_words('facade_leave_fault', 'facade_leave_normal')
        self.assertEqual(fault[:6], (b.lui(20, GUARD >> 16), b.ori(20, 20, GUARD & 0xFFFF),
                                    b.addiu(8, 0, 2), gates.SYNC, b.sw(8, 0, 20), gates.SYNC))
        pair = (0x8FBF001C, 0x8FB00018)
        self.assertEqual(fault[6:], (gates.SYNC, *self.restore_words(), *pair, b.j_type(2, 0x47D090), 0))
        self.assertEqual(self.core_words('facade_leave_normal', 'first_outer_return'),
                         (gates.SYNC, *self.restore_words(), *pair, b.j_type(2, 0x47D08C), 0))
        self.assertEqual(gates.FACADE_RETURN, 0x47D084)
        # Normal path retains native V0=0; Q fault skips that overwrite so
        # an actual classified child MASK/raw pair reaches the facade caller.

    def test_helper_has_no_services_H_M_lookups_or_transport_fault_writes(self):
        code, _ = gates.assemble(*CORE_ARGS)
        words = struct.unpack('<' + 'I' * (len(code) // 4), code)
        self.assertEqual(len(code), GATE_BYTES)
        self.assertFalse(any(word >> 26 == 3 for word in words))
        self.assertFalse(any(word >> 26 == 0 and word & 63 == 9 for word in words))
        self.assertTrue(all((word >> 21) & 31 in (20, 23, 29) for word in self.accesses(words)))
        self.assertNotIn(b.lw(8, 0x14, 23), words)
        self.assertEqual(sum(word >> 26 == 0x30 for word in words), 6)
        self.assertEqual(sum(word >> 26 == 0x38 for word in words), 6)
        self.assertNotEqual(GUARD, STAGE_ARGS[-1])
        alternate = (ARGS[3] + 0x1000, ARGS[4] + 0x1000, *CORE_ARGS[2:])
        self.assertEqual(gates.assemble(*alternate), (code, gates.assemble(*CORE_ARGS)[1]))
        # All non-stack accesses target independent Q. Ownership is unproved;
        # the old parent's direct raw call is physically present but bypassed.

    def test_native_and_generated_hook_targets_and_parent8_12_regions_are_strict(self):
        _, labels = gates.assemble(*CORE_ARGS)
        hooks = gates.hook_words(labels, PARENT_ERROR, PARENT_DENIED)
        self.assertEqual(set(hooks), {*(pc for pc, _ in gates.HOOKS.values()), PARENT_ERROR, PARENT_DENIED})
        for name, pc in {**{name: pc for name, (pc, _) in gates.HOOKS.items()},
                         'callback_entry': PARENT_ERROR, 'deny_entry': PARENT_DENIED}.items():
            self.assertEqual(hooks[pc], (b.j_type(2, labels[name]), 0))
            for value in (True, False, None, 0, -4, 1, 0x10000000, 0x100000000):
                with self.subTest(label=name, value=value), self.assertRaises(ValueError):
                    gates.hook_words(dict(labels, **{name: value}), PARENT_ERROR, PARENT_DENIED)
        for callback, denied in ((PARENT_ERROR, PARENT_ERROR), (PARENT_ERROR, PARENT_ERROR + 4),
                                  (CORE_ARGS[2] - 4, PARENT_DENIED), (PARENT_ERROR, CORE_ARGS[2] - 8)):
            with self.subTest(callback=callback, denied=denied), self.assertRaises(ValueError):
                gates.assemble(*CORE_ARGS[:3], callback, denied, GUARD)

    def test_primary_guard_extra_and_complete_RX_static_extents_are_strict(self):
        for index in range(6):
            bad = (True, False, None, 0, -4, 1, 1.0, '16', 0x400000, 0x100000000)
            if index != 5:
                bad += (0xFFFFFFFC,)
            for value in bad:
                args = list(CORE_ARGS)
                args[index] = value
                with self.subTest(index=index, value=value), self.assertRaises(ValueError):
                    gates.assemble(*args)
        for index, value in ((0, CORE_ARGS[1]), (1, CORE_ARGS[0]), (0, GUARD), (1, GUARD),
                              (5, CORE_ARGS[0]), (5, CORE_ARGS[1]), (5, PARENT_ERROR + 4),
                              (5, PARENT_DENIED + 8), (5, CORE_ARGS[2])):
            args = list(CORE_ARGS)
            args[index] = value
            with self.subTest(index=index, overlap=value), self.assertRaises(ValueError):
                gates.assemble(*args)
        baseline = gates.assemble(*CORE_ARGS)
        for extra in (((0x1F90000, 4),), ((0xFFFFFFFC, 4),)):
            self.assertEqual(gates.assemble(*CORE_ARGS, extra_protected_data=extra), baseline)
        for extra in (None, [], ((True, 4),), ((0x1F90000, True),), ((0x1F90000, 0),),
                      ((0x1F90000, 3),), ((0xFFFFFFFC, 8),), ((0x400000, 4),),
                      ((CORE_ARGS[0] + 0x288, 4),), ((CORE_ARGS[1] + 20, 4),), ((GUARD, 4),),
                      ((PARENT_ERROR + 4, 4),), ((PARENT_DENIED + 8, 4),),
                      ((CORE_ARGS[2], 4),), ((0x1F90000, 8), (0x1F90004, 4))):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                gates.assemble(*CORE_ARGS, extra_protected_data=extra)
        size = CORE_ARGS[2] + len(baseline[0]) - PARENT_ERROR
        self.assertEqual(gates.assemble(*CORE_ARGS, protected_code=(PARENT_ERROR, size)), baseline)
        for protected in ([], (), (True, size), (PARENT_ERROR, True), (PARENT_ERROR, 0),
                          (PARENT_ERROR, 3), (PARENT_ERROR, size - 4), (PARENT_ERROR + 4, size),
                          (CORE_ARGS[2], len(baseline[0])), (0x400000, 0x2000000), (GUARD, 4)):
            with self.subTest(protected=protected), self.assertRaises(ValueError):
                gates.assemble(*CORE_ARGS, protected_code=protected)
        self._assert_all_fixed_roles_and_Q_exclude_new_tail()

    def _assert_all_fixed_roles_and_Q_exclude_new_tail(self):
        tail = CORE_ARGS[2] + GATE_BYTES - 4
        roles = (('receipt', receipt.memory_bytes(16)), ('binding', bindings.memory_bytes(16)),
                 ('owner', owners.memory_bytes(16)), ('paint_mutex', receipt.MUTEX_BYTES),
                 ('lifecycle', lifecycle.memory_bytes(16)), ('queue', queue.QUEUE_BYTES),
                 ('transport_mutex', queue.MUTEX_BYTES), ('fault', 4))
        for name, size in roles:
            with self.subTest(role=name), self.assertRaises(ValueError):
                gates.assemble(*CORE_ARGS, extra_protected_data=((tail, size),))
        for index in (0, 1, 5):
            args = list(CORE_ARGS)
            args[index] = tail
            with self.subTest(role=index), self.assertRaises(ValueError):
                gates.assemble(*args)

    def test_retry_limits_and_required_independent_guard_are_validated_by_actual_new_code(self):
        baseline = self.canonical('stage_default')
        self.assertEqual(stage.assemble(*STAGE_ARGS, guard_address=GUARD, retry_limit=8), baseline)
        for value in (1, 64):
            result = stage.assemble(*STAGE_ARGS, guard_address=GUARD, retry_limit=value)
            self.assertEqual(len(result['code']), len(baseline['code']))
            self.assertEqual(result['dialog_retention_gate_labels'], baseline['dialog_retention_gate_labels'])
            self.assertEqual(result['guard_retry_limit'], value)
            self.assertNotEqual(result['code'], baseline['code'])
        for value in (True, False, None, 0, -1, 65, 1.0, '8'):
            with self.subTest(retry=value), self.assertRaises(ValueError):
                gates.assemble(*CORE_ARGS, retry_limit=value)
            with self.subTest(stage_retry=value), self.assertRaises(ValueError):
                stage.assemble(*STAGE_ARGS, guard_address=GUARD, retry_limit=value)
        with self.assertRaises(TypeError):
            stage.assemble(*STAGE_ARGS)
        with self.assertRaises(ValueError):
            stage.assemble(*STAGE_ARGS, guard_address=STAGE_ARGS[-1])
        # F belongs to the old transport allocation; Q must be independently
        # mapped/retained and externally initialized before quiescent activation.

    def test_direct_parent_hash_and_zero_extension_are_unchanged(self):
        parent = self.canonical('parent_default')
        self.assertEqual((len(parent['code']), hashlib.sha256(parent['code']).hexdigest()),
                         (95300, preceding.GATED_SHA256))
        self.assertEqual(parent_stage.assemble(*STAGE_ARGS, following_code_bytes=0), parent)

    def test_stage_patches_exactly_two_parent_pairs_preserves_resume_and_appends_core(self):
        result = self.canonical('stage_default')
        prefix, tail = result['dialog_retention_gate_prefix_code_bytes'], result['dialog_retention_gate_code_bytes']
        self.assertEqual((prefix, tail, len(result['code'])), (95300, GATE_BYTES, GATED_BYTES))
        self.assertEqual(hashlib.sha256(result['code']).hexdigest(), GATED_SHA256)
        full = (ARGS[6], len(result['code']))
        self.assertEqual(result['protected_code_extent'], full)
        parent = self.canonical('parent_guarded')
        self.assertEqual(parent['protected_code_extent'], full)
        callback, denied = (parent['dialog_failure_gate_labels']['error_return'],
                             parent['dialog_acquire_gate_labels']['gate_denied'])
        self.assertEqual((callback, denied), (0x1E972A0, 0x1E96EDC))
        self.assertEqual((result['dialog_retention_gate_parent_error_return'],
                          result['dialog_retention_gate_parent_gate_denied']), (callback, denied))
        sources = {callback: gates.PARENT_CALLBACK_PAIR, denied: gates.PARENT_DENIED_PAIR}
        self.assertEqual(result['dialog_retention_gate_source_words'], sources)
        self.assertEqual(result['dialog_retention_gate_denied_resume_word'], 0x8FA8008C)
        labels = result['dialog_retention_gate_labels']
        hooks = gates.hook_words(labels, callback, denied)
        self.assertEqual(result['dialog_retention_gate_hooks'], hooks)
        expected = bytearray(parent['code'])
        for pc, source in sources.items():
            self.assertEqual(self.fragment(parent['code'], ARGS[6], pc, pc + 8), source)
            struct.pack_into('<II', expected, pc - ARGS[6], *hooks[pc])
        self.assertEqual(result['code'][:prefix], bytes(expected))
        self.assertEqual(self.fragment(result['code'], ARGS[6], denied + 8, denied + 12), (0x8FA8008C,))
        emitted, core_labels = gates.assemble(ARGS[3], ARGS[4], ARGS[6] + prefix,
                                              callback, denied, GUARD, protected_code=full)
        self.assertEqual((emitted, core_labels), (result['code'][prefix:], labels))
        for name, pc in dict(callback_entry=0x1E97444, deny_entry=0x1E975D4,
                             poll_enter=0x1E97658, close_enter=0x1E97868, facade_enter=0x1E97B6C,
                             poll_leave=0x1E97D7C, close_leave=0x1E97F20, facade_leave=0x1E980D8,
                             first_outer_return=0x1E98314, second_outer_return=0x1E9831C).items():
            self.assertEqual(labels[name], pc)
        for name, pc in labels.items():
            self.assertEqual(result['labels']['dialog_retention_gate_' + name], pc)

    def test_hook_inventory_and_metadata_limit_the_retention_and_suppress_unproven_unlock(self):
        result, parent = self.canonical('stage_default'), self.canonical('parent_default')
        new = result['dialog_retention_gate_hooks']
        native_hooks = {pc: pair for pc, pair in new.items() if gates.NATIVE_RX[0] <= pc < gates.NATIVE_RX[1]}
        generated = {pc: pair for pc, pair in new.items() if pc not in native_hooks}
        self.assertEqual((len(native_hooks), len(generated)), (6, 2))
        self.assertFalse(set(new) & set(parent['coherent_hooks']))
        self.assertEqual(result['native_coherent_hooks'], {**parent['native_coherent_hooks'], **native_hooks})
        self.assertEqual(result['generated_coherent_hooks'], {**parent['generated_coherent_hooks'], **generated})
        self.assertEqual(result['coherent_hooks'], {**parent['coherent_hooks'], **new})
        self.assertEqual((len(result['native_coherent_hooks']), len(result['generated_coherent_hooks']),
                          len(result['coherent_hooks'])), (32, 7, 39))
        self.assertEqual((result['guard_address'], result['guard_bytes'], result['guard_initial_value'],
                          result['guard_retry_limit']), (GUARD, 4, 0, 8))
        for flag in ('unconfirmed_dialog_unlock_suppressed', 'known_dialog_outer_frees_guarded',
                     'known_dialog_reentry_guarded', 'known_dialog_close_facade_guarded'):
            self.assertIs(result[flag], True)
        for flag in ('guard_runtime_reset_supported', 'dialog_ownership_proven', 'dialog_failure_release_attempt_guarded',
                     'native_callers_isolated', 'raw_release_proven', 'native_lifetime_proven',
                     'partial_graph_cleanup_proven', 'earlier_cleanup_rolled_back', 'destructor_entry_fenced'):
            self.assertIs(result[flag], False)

    def test_following_RX_and_distinct_alias_inputs_use_actual_new_composition(self):
        baseline = self.canonical('stage_default')
        self.assertEqual(stage.assemble(*STAGE_ARGS, guard_address=GUARD, following_code_bytes=0), baseline)
        extended = stage.assemble(*STAGE_ARGS, guard_address=GUARD, following_code_bytes=4)
        self.assertEqual(len(extended['code']), len(baseline['code']))
        self.assertEqual(extended['labels'], baseline['labels'])
        self.assertEqual(extended['coherent_hooks'], baseline['coherent_hooks'])
        self.assertEqual(extended['protected_code_extent'], (ARGS[6], len(baseline['code']) + 4))
        self.assertNotEqual(extended['code'], baseline['code'])
        for value in (True, False, None, -4, 1, 2, 3, 1.0, '4'):
            with self.subTest(following=value), self.assertRaises(ValueError):
                stage.assemble(*STAGE_ARGS, guard_address=GUARD, following_code_bytes=value)
        for address, following in ((ARGS[6] + len(baseline['code']) - 4, 0),
                                   (ARGS[6] + len(baseline['code']), 4)):
            with self.subTest(guard_alias=address, following=following), self.assertRaises(ValueError):
                stage.assemble(*STAGE_ARGS, guard_address=address, following_code_bytes=following)

    def test_named_snapshots_and_parent_only_cache_restore_identities_after_errors(self):
        first, second = self.canonical('stage_default'), self.canonical('stage_default')
        self.assertEqual(first, second)
        self.assertIsNot(first['labels'], second['labels'])
        first['labels']['snapshot_only'] = 0
        first['coherent_hooks'].clear()
        self.assertNotIn('snapshot_only', second['labels'])
        self.assertEqual(len(second['coherent_hooks']), 39)
        self.assertEqual(self.canonical('stage_default'), second)
        self.assertEqual(len(self._parent_assemblers), 39)
        self.assertEqual(len({module for module, _ in self._parent_assemblers}), 39)
        outer = tuple((module, module.assemble) for module, _ in self._parent_assemblers)
        for module, original in self._parent_assemblers:
            self.assertIsNot(module.assemble, original)
        with self.assertRaisesRegex(RuntimeError, 'retention parent-cache restoration probe'):
            with parent_fixture._fixture_assembly_cache(True):
                for module, function in outer:
                    self.assertIsNot(module.assemble, function)
                self.assertIs(gates.assemble, self._new_assemblers[0])
                self.assertIs(stage.assemble, self._new_assemblers[1])
                raise RuntimeError('retention parent-cache restoration probe')
        for module, function in outer:
            self.assertIs(module.assemble, function)
        self.assertIs(gates.assemble, self._new_assemblers[0])
        self.assertIs(stage.assemble, self._new_assemblers[1])


if __name__ == '__main__':
    unittest.main()
