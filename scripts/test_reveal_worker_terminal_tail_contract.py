#!/usr/bin/env python3
"""Pin a bounded worker tail reorder without claiming join or free authority.

The native source proves a direct post-C-release H access. The optional tail
captures and clears H+14 before that same masked release, then uses only the
captured pointer and the genuine W56 epilogue. Earlier aliases, import ABI,
pointer ownership and changed shared-field ordering remain hard premises.
"""

import hashlib
import struct
import unittest
from copy import deepcopy

from build_reveal_bridge_diag import b
import reveal_worker_terminal_tail_mips as gates
import reveal_worker_terminal_tail_stage as stage
import reveal_dialog_retention_gate_stage as parent_stage
import reveal_registry_receipt_mips as receipt
import reveal_registry_owner_mips as bindings
import reveal_registry_lifecycle_mips as lifecycle
import reveal_paint_retirement_mips as owners
import reveal_birth_queue_mips as queue
import test_reveal_dialog_retention_gate_contract as preceding
import test_reveal_dialog_retention_gate_mips as parent_fixture
import test_reveal_registry_birth_contract as native


ARGS, STAGE_ARGS = preceding.ARGS, preceding.STAGE_ARGS
GUARD = preceding.GUARD
CORE_ARGS = (STAGE_ARGS[3], STAGE_ARGS[4], 0x1EE0000, GUARD)
GATE_BYTES, PARENT_BYTES, GATED_BYTES = 56, 99108, 99164
GATED_SHA256 = '6449ade76e68805fd8857f7a2f9346e5605b3ba04de42bbc71e962fff3b8d4c0'
GUARDED_PARENT_SHA256 = '4f83e6252ba521ccb96049b6471cf214bea1c79dcba023b655b44a49727134ba'


class WorkerTerminalTailContractTests(unittest.TestCase):
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
                raise AssertionError('new worker core/stage was replaced')

    words = native.RegistryBirthContractTests.words

    @classmethod
    def canonical(cls, name):
        """Deep-copy three valid outputs under only41 unchanged parent caches.

        The new core/stage remain unwrapped for distinct configuration checks.
        No CPU execution, native service results or old hash chain is cached.
        This is not a full uncached43 composition equivalence certificate.
        """
        if name not in cls._canonical_outputs:
            if name == 'parent_default':
                result = parent_stage.assemble(*STAGE_ARGS, guard_address=GUARD)
            elif name == 'parent_guarded':
                result = parent_stage.assemble(*STAGE_ARGS, guard_address=GUARD,
                                               following_code_bytes=GATE_BYTES)
            elif name == 'stage_default':
                result = stage.assemble(*STAGE_ARGS, guard_address=GUARD)
            else:
                raise ValueError('unknown canonical configuration')
            cls._canonical_outputs[name] = deepcopy(result)
        return deepcopy(cls._canonical_outputs[name])

    @staticmethod
    def unpack(code):
        return struct.unpack('<' + 'I' * (len(code) // 4), code)

    def test_native_hook_retains_the_C_pointer_load_in_its_delay_slot(self):
        self.assertEqual(gates.HOOKS,
                         {'terminal': (0x47C6E8, (0x0C119B70, 0x8E04000C))})
        self.words(0x47C6E0, [0x0C119B70, 0x8E040010,
                              0x0C119B70, 0x8E04000C,
                              0x8E040014, 0x10800005, 0x8FBF0034,
                              0x0C119AA0, 0, 0xAE000014])
        _, labels = gates.assemble(*CORE_ARGS)
        self.assertEqual(gates.hook_words(labels),
                         {0x47C6E8: (b.j_type(2, labels['entry']), 0x8E04000C)})
        # The original H+0C read runs once before helper entry. Replacing its
        # delay with NOP would lose the actual C pointer passed to the facade.

    def test_worker_frame_preserves_S1_and_has_a_stack_only_complete_epilogue(self):
        self.words(0x47C580, [0x27BDFFC8, 0xAFB0001C, 0x00808021,
                              0x3C040094, 0x24848BF8, 0xAFBF0034,
                              0xAFB50030, 0xAFB4002C, 0xAFB30028,
                              0xAFB20024, 0x0C119B10, 0xAFB10020])
        self.words(0x47C708, [0x8FBF0034, 0x8FB50030, 0x8FB4002C,
                              0x8FB30028, 0x8FB20024, 0x8FB10020,
                              0x8FB0001C, 0x03E00008, 0x27BD0038])
        # Original W56 owns S1 and restores it at47C71C. The helper may use
        # this saved callee register without allocating another private frame.
        uses = []
        for pc in range(0x47C6E8, 0x47C72C, 4):
            word = self.elf.word(pc)
            opcode = word >> 26
            rs, rt, rd = (word >> 21) & 31, (word >> 16) & 31, (word >> 11) & 31
            if (opcode in (4, 5, 8, 9, 32, 33, 35, 36, 37, 40, 41, 43)
                    and 17 in (rs, rt) or opcode == 0 and 17 in (rs, rt, rd)):
                uses.append(pc)
        self.assertEqual(uses, [0x47C71C])

    def test_encoded_entries_do_not_reenter_the_skipped_tail_or_hook_delay(self):
        jumps = {pc: target for pc, target in self.jumps.items()
                 if 0x47C6E8 <= target < 0x47C72C}
        branches = {pc: target for pc, target in self.branches.items()
                    if 0x47C6E8 <= target < 0x47C72C}
        self.assertEqual(jumps, {})
        self.assertEqual(branches, {0x47C5B0: 0x47C70C, 0x47C6F4: 0x47C70C})
        self.words(0x47C5B0, [0x12000056, 0x8FBF0034])
        # The two original branches have already loaded RA in their delay.
        # Computed/foreign entries are not excluded by an encoded census.

    def test_completion_flag_and_C_handshake_are_not_worker_termination(self):
        self.words(0x47C6BC, [0x8C520000, 0x8E050024, 0x0C296D80,
                              0x8E440024, 0x14400002, 0, 0xA255001C])
        self.words(0x47CC74, [0x8C510000, 0x9223001C, 0x1060FFF7,
                              0x26100001, 0x2610FFFF, 0x8E39006C,
                              0x0320F809, 0x02202021])
        self.words(0x47C77C, [0x0C119B68, 0x8E04000C, 0x0C119B70,
                              0x8E04000C, 0x0C119B78, 0x8E04000C])
        self.assertLess(0x47C6D4, 0x47C6E8)
        self.assertLess(0x47C6E8, 0x47C704)
        # The worker flags every matching-name S2, not just its own S0/H.
        # Completion waits on C before the worker's old final H use, not join.

    def test_H18_is_a_repeated_loop_handshake_and_H14_can_escape_to_a_callback(self):
        self.words(0x47C654, [0x8E020018, 0x1040FFE0, 0,
                              0x0C119B68, 0x8E040010, 0x8E040010,
                              0x0C119B70, 0xAE000018, 0x1000FFD9, 0])
        self.words(0x47C620, [0x8E190078, 0x13200003, 0x02002021,
                              0x0320F809, 0x8E050054])
        stores = {pc for pc in range(0x47C580, 0x47C900, 4)
                  if self.elf.word(pc) == b.sw(0, 0x14, 16)}
        self.assertEqual(stores, {0x47C704, 0x47C8A8})
        self.words(0x47C8A4, [0x0C119B68, 0xAE000014, 0x8E060014])
        # The bounded native range has only these zero writes. An external
        # H+78 callback receives H and can invalidate any global writer claim.

    def _import_names_at(self, addresses):
        """Read actual ELF symbol relocations, without executing import code."""
        data = self.elf.data
        sections = [struct.unpack_from('<10I', data,
                                       self.elf.u32(0x20) + index * self.elf.u16(0x2E))
                    for index in range(self.elf.u16(0x30))]
        found = {}
        for section in sections:
            if section[1] not in (4, 9):
                continue
            symbols = sections[section[6]]
            strings = sections[symbols[6]]
            for offset in range(section[4], section[4] + section[5], section[9]):
                address, info = struct.unpack_from('<II', data, offset)
                if address not in addresses:
                    continue
                name_offset = struct.unpack_from('<I', data,
                                                 symbols[4] + (info >> 8) * symbols[9])[0]
                first = strings[4] + name_offset
                found[address] = data[first:data.index(b'\0', first)].decode('ascii')
        return found

    def test_starter_creates_a_detached_thread_and_has_no_join_handoff(self):
        self.words(0x47C8AC, [0x8E060014, 0x3C040048, 0x02002821,
                              0x24C6000C, 0x24070081, 0x0C119AE8,
                              0x2484C580, 0x8E040008, 0x0C119B68,
                              0xAE020000, 0x0C119B70, 0x8E040008,
                              0x0C119B78, 0x8E040008])
        self.words(0x466BC0, [0x27A40018, 0x0C296FB4, 0x24050001])
        self.words(0x466BF4, [0x02203021, 0x02003821,
                              0x0C296E6C, 0x27A4003C,
                              0x0C296CB0, 0x27A40018])
        self.assertEqual(self._import_names_at({0xA6FA6C, 0xA6FBB4, 0xA6F8B0}),
                         {0xA6FA6C: 'pthread_create',
                          0xA6FBB4: 'pthread_attr_setdetachstate',
                          0xA6F8B0: 'pthread_attr_destroy'})
        self.assertEqual({pc for pc, target in self.jumps.items() if target == 0x47C840},
                         {0x47D3B8, 0x47D6CC, 0x47D920, 0x47DC5C, 0x47E000})
        self.assertEqual({pc for pc, target in self.jumps.items() if target == 0x47C580}, set())
        # The starter waits on H+08 until worker startup, not final return.

    def test_native_free_wrapper_and_masked_release_are_exact_and_not_new_authority(self):
        self.words(0x466A80, [0x1080000F, 0, 0x27BDFFE0, 0xAFBF001C,
                              0x8C82FFFC, 0x1040000C, 0x00802821,
                              0x3C0200B9, 0x244294A0, 0x8C43000C,
                              0x10A3000D, 0x2484FFFC, 0x0C296E70, 0])
        self.words(0x466AC8, [0x3C040093, 0x0C296EC8, 0x2484A6AC])
        self.words(0x466DC0, [0x27BDFFE0, 0xAFBF001C, 0x0C296E0C, 0,
                              0x8FBF001C, 0x00001021, 0x03E00008, 0x27BD0020])
        self.assertEqual(self._import_names_at({0xA6FA70, 0xA6FAC8, 0xA6FA0C}),
                         {0xA6FA70: 'free', 0xA6FAC8: 'printf',
                          0xA6FA0C: 'pthread_mutex_unlock'})
        self.assertFalse(any(self.elf.word(pc) >> 26 == 0
                             and self.elf.word(pc) & 63 == 9
                             for pc in range(0x466A80, 0x466B0C, 4)))
        # No native indirect callback here proves neither import reentry
        # exclusion nor that an arbitrary captured pointer may be freed.

    def test_exact_helper_detaches_before_release_without_a_new_frame_or_Q_claim(self):
        code, labels = gates.assemble(*CORE_ARGS)
        base = CORE_ARGS[2]
        self.assertEqual(labels, dict(entry=base, captured=base + 16,
                                      release_return=base + 28, finish=base + 48))
        self.assertEqual(self.unpack(code),
                         (b.lw(17, 0x14, 16), 0x12200002, 0, b.sw(0, 0x14, 16),
                          0xF, b.j_type(3, 0x466DC0), 0, b.move(4, 17), 0x12200003, 0,
                          b.j_type(3, 0x466A80), 0, b.j_type(2, 0x47C708), 0))
        self.assertEqual(len(code), GATE_BYTES)
        accesses = [word for word in self.unpack(code)
                    if word >> 26 in (32, 33, 35, 36, 37, 40, 41, 43, 0x30, 0x38)]
        self.assertEqual(accesses, [b.lw(17, 0x14, 16), b.sw(0, 0x14, 16)])
        # Both accesses precede the existing C release. This shared store is
        # deliberately earlier than stock; it is not a no-observer proof.

    def test_after_release_only_captured_pointer_calls_and_native_epilogue_remain(self):
        code, labels = gates.assemble(*CORE_ARGS)
        words = self.unpack(code[labels['release_return'] - CORE_ARGS[2]:])
        self.assertEqual(words, (b.move(4, 17), 0x12200003, 0,
                                 b.j_type(3, 0x466A80), 0, b.j_type(2, 0x47C708), 0))
        self.assertFalse(any(word >> 26 in (32, 33, 35, 36, 37, 40, 41, 43, 0x30, 0x38)
                             for word in words))
        self.assertEqual(sum(word >> 26 == 3 for word in self.unpack(code)), 2)
        # free(ptr) still reads ptr-4 inside its wrapper. A distinct retained
        # freeable pointer is required; this is not arbitrary-alias safety.

    def test_hook_target_validation_retains_the_original_delay_word(self):
        _, labels = gates.assemble(*CORE_ARGS)
        for value in (True, False, None, 0, -4, 1, 1.0, '16', 0x10000000, 0x100000000):
            with self.subTest(target=value), self.assertRaises(ValueError):
                gates.hook_words(dict(labels, entry=value))
        for value in (0xA5BFA0, 0xFFFFFFC):
            self.assertEqual(gates.hook_words(dict(labels, entry=value)),
                             {0x47C6E8: (b.j_type(2, value), 0x8E04000C)})

    def test_primary_fixed_roles_types_and_complete_static_extents_are_strict(self):
        for index in range(4):
            invalid = (True, False, None, 0, -4, 1, 1.0, '16', 0x400000, 0x100000000)
            if index != 3:
                invalid += (0xFFFFFFFC,)
            for value in invalid:
                args = list(CORE_ARGS)
                args[index] = value
                with self.subTest(role=index, value=value), self.assertRaises(ValueError):
                    gates.assemble(*args)
        for index, value in ((0, CORE_ARGS[1]), (1, CORE_ARGS[0]),
                              (0, GUARD), (1, GUARD), (3, CORE_ARGS[0]),
                              (3, CORE_ARGS[1]), (3, CORE_ARGS[2]),
                              (0, CORE_ARGS[2] - receipt.CONTROLLER_BYTES + 4),
                              (1, CORE_ARGS[2] - receipt.MUTEX_BYTES + 4)):
            args = list(CORE_ARGS)
            args[index] = value
            with self.subTest(role=index, overlap=value), self.assertRaises(ValueError):
                gates.assemble(*args)

    def test_extra_fixed_regions_reject_partial_aliases_native_RX_and_wrapping(self):
        baseline = gates.assemble(*CORE_ARGS)
        for extra in (((0x1F90000, 4),), ((0xFFFFFFFC, 4),)):
            self.assertEqual(gates.assemble(*CORE_ARGS, extra_protected_data=extra), baseline)
        for extra in (None, [], ((True, 4),), ((0x1F90000, True),),
                      ((0x1F90000, 0),), ((0x1F90000, 3),), ((0xFFFFFFFC, 8),),
                      ((0x400000, 4),), ((CORE_ARGS[0] + receipt.CONTROLLER_BYTES - 4, 4),),
                      ((CORE_ARGS[1] + receipt.MUTEX_BYTES - 4, 4),), ((GUARD, 4),),
                      ((CORE_ARGS[2] + GATE_BYTES - 4, 4),),
                      ((0x1F90000, 8), (0x1F90004, 4))):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                gates.assemble(*CORE_ARGS, extra_protected_data=extra)

    def test_complete_generated_RX_and_native_jump_region_end_are_checked(self):
        baseline = gates.assemble(*CORE_ARGS)
        self.assertEqual(gates.assemble(*CORE_ARGS,
                                        protected_code=(CORE_ARGS[2], GATE_BYTES)), baseline)
        self.assertEqual(gates.assemble(*CORE_ARGS,
                                        protected_code=(CORE_ARGS[2] - 4, GATE_BYTES + 8)), baseline)
        for protected in ([], (), (True, GATE_BYTES), (CORE_ARGS[2], True),
                          (CORE_ARGS[2], 0), (CORE_ARGS[2], 3),
                          (CORE_ARGS[2], GATE_BYTES - 4), (CORE_ARGS[2] + 4, GATE_BYTES),
                          (0x400000, 0x2000000), (GUARD, 4), (0xFFFFFFFC, 8)):
            with self.subTest(protected=protected), self.assertRaises(ValueError):
                gates.assemble(*CORE_ARGS, protected_code=protected)
        final = list(CORE_ARGS)
        final[2] = 0x10000000 - GATE_BYTES
        self.assertEqual(len(gates.assemble(*final)[0]), GATE_BYTES)
        final[2] += 4
        with self.assertRaises(ValueError):
            gates.assemble(*final)

    def test_every_declared_fixed_role_excludes_the_complete_new_tail(self):
        tail = CORE_ARGS[2] + GATE_BYTES - 4
        sizes = (receipt.memory_bytes(16), bindings.memory_bytes(16), owners.memory_bytes(16),
                 receipt.MUTEX_BYTES, lifecycle.memory_bytes(16), queue.QUEUE_BYTES,
                 queue.MUTEX_BYTES, 4)
        for size in sizes:
            with self.subTest(extra_size=size), self.assertRaises(ValueError):
                gates.assemble(*CORE_ARGS, extra_protected_data=((tail, size),))
        for index in (0, 1, 3):
            args = list(CORE_ARGS)
            args[index] = tail
            with self.subTest(role=index), self.assertRaises(ValueError):
                gates.assemble(*args)

    def test_parent_default_hash_and_zero_extension_are_unchanged(self):
        parent = self.canonical('parent_default')
        self.assertEqual((len(parent['code']), hashlib.sha256(parent['code']).hexdigest()),
                         (PARENT_BYTES, preceding.GATED_SHA256))
        self.assertEqual(parent_stage.assemble(*STAGE_ARGS, guard_address=GUARD,
                                               following_code_bytes=0), parent)

    def test_stage_appends_only_the_new_tail_to_the_complete_protected_parent(self):
        result, parent = self.canonical('stage_default'), self.canonical('parent_guarded')
        self.assertEqual((result['worker_terminal_tail_prefix_code_bytes'],
                          result['worker_terminal_tail_code_bytes'], len(result['code'])),
                         (PARENT_BYTES, GATE_BYTES, GATED_BYTES))
        self.assertEqual(result['protected_code_extent'], (STAGE_ARGS[6], GATED_BYTES))
        self.assertEqual(parent['protected_code_extent'], result['protected_code_extent'])
        self.assertEqual(result['code'][:PARENT_BYTES], parent['code'])
        self.assertEqual(hashlib.sha256(parent['code']).hexdigest(), GUARDED_PARENT_SHA256)
        self.assertEqual(hashlib.sha256(result['code']).hexdigest(), GATED_SHA256)
        emitted, labels = gates.assemble(STAGE_ARGS[3], STAGE_ARGS[4],
                                         STAGE_ARGS[6] + PARENT_BYTES, GUARD,
                                         protected_code=result['protected_code_extent'])
        self.assertEqual((result['code'][PARENT_BYTES:], result['worker_terminal_tail_labels']),
                         (emitted, labels))
        self.assertEqual(result['worker_terminal_tail_source_words'],
                         {0x47C6E8: (0x0C119B70, 0x8E04000C)})
        self.assertEqual(labels, dict(entry=0x1E98324, captured=0x1E98334,
                                      release_return=0x1E98340, finish=0x1E98354))
        for name, address in labels.items():
            self.assertEqual(result['labels']['worker_terminal_tail_' + name], address)

    def test_one_native_hook_and_inherited_metadata_do_not_promote_safety_claims(self):
        result, parent = self.canonical('stage_default'), self.canonical('parent_default')
        hooks = gates.hook_words(result['worker_terminal_tail_labels'])
        self.assertEqual(result['worker_terminal_tail_hooks'], hooks)
        self.assertFalse(set(hooks) & set(parent['coherent_hooks']))
        self.assertEqual(result['native_coherent_hooks'], {**parent['native_coherent_hooks'], **hooks})
        self.assertEqual(result['generated_coherent_hooks'], parent['generated_coherent_hooks'])
        self.assertEqual(result['coherent_hooks'], {**parent['coherent_hooks'], **hooks})
        self.assertEqual((len(result['native_coherent_hooks']), len(result['generated_coherent_hooks']),
                          len(result['coherent_hooks'])), (33, 7, 40))
        for flag in ('worker_post_terminal_release_H_access_removed',
                     'worker_tail_field_detached_before_release',
                     'worker_terminal_release_status_masked'):
            self.assertIs(result[flag], True)
        for flag in ('worker_termination_proven', 'worker_terminal_release_proven',
                     'worker_buffer_free_authority_proven'):
            self.assertIs(result[flag], False)
        for flag in ('unconfirmed_dialog_unlock_suppressed', 'known_dialog_outer_frees_guarded',
                     'known_dialog_reentry_guarded', 'known_dialog_close_facade_guarded',
                     'dialog_ownership_proven', 'dialog_failure_release_attempt_guarded',
                     'native_callers_isolated', 'raw_release_proven', 'native_lifetime_proven',
                     'partial_graph_cleanup_proven', 'earlier_cleanup_rolled_back',
                     'destructor_entry_fenced', 'guard_runtime_reset_supported'):
            self.assertIs(result[flag], parent[flag])
        self.assertEqual((result['guard_address'], result['guard_bytes']), (GUARD, 4))

    def test_following_code_extent_and_required_guard_are_validated_by_new_stage(self):
        baseline = self.canonical('stage_default')
        self.assertEqual(stage.assemble(*STAGE_ARGS, guard_address=GUARD,
                                        following_code_bytes=0), baseline)
        result = stage.assemble(*STAGE_ARGS, guard_address=GUARD, following_code_bytes=4)
        self.assertEqual((len(result['code']), result['labels'], result['coherent_hooks']),
                         (GATED_BYTES, baseline['labels'], baseline['coherent_hooks']))
        self.assertEqual(result['protected_code_extent'], (STAGE_ARGS[6], GATED_BYTES + 4))
        self.assertNotEqual(result['code'], baseline['code'])
        for value in (True, False, None, -4, 1, 2, 3, 1.0, '4'):
            with self.subTest(following=value), self.assertRaises(ValueError):
                stage.assemble(*STAGE_ARGS, guard_address=GUARD, following_code_bytes=value)
        with self.assertRaises(TypeError):
            stage.assemble(*STAGE_ARGS)
        for address, following in ((STAGE_ARGS[6] + GATED_BYTES - 4, 0),
                                   (STAGE_ARGS[6] + GATED_BYTES, 4), (STAGE_ARGS[-1], 0)):
            with self.subTest(guard=address, following=following), self.assertRaises(ValueError):
                stage.assemble(*STAGE_ARGS, guard_address=address, following_code_bytes=following)

    def test_retry_configuration_is_inherited_without_changing_the_worker_tail(self):
        baseline = self.canonical('stage_default')
        for limit in (1, 64):
            result = stage.assemble(*STAGE_ARGS, guard_address=GUARD, retry_limit=limit)
            self.assertEqual(result['guard_retry_limit'], limit)
            self.assertEqual(len(result['code']), GATED_BYTES)
            self.assertEqual(result['worker_terminal_tail_labels'], baseline['worker_terminal_tail_labels'])
            self.assertEqual(result['code'][PARENT_BYTES:], baseline['code'][PARENT_BYTES:])
            self.assertNotEqual(result['code'], baseline['code'])
        for limit in (True, False, None, 0, -1, 65, 1.0, '8'):
            with self.subTest(retry=limit), self.assertRaises(ValueError):
                stage.assemble(*STAGE_ARGS, guard_address=GUARD, retry_limit=limit)

    def test_named_snapshots_and_parent_cache_restore_every_temporary_identity(self):
        first, second = self.canonical('stage_default'), self.canonical('stage_default')
        self.assertEqual(first, second)
        first['labels']['snapshot_only'] = 0
        first['coherent_hooks'].clear()
        self.assertNotIn('snapshot_only', second['labels'])
        self.assertEqual(len(second['coherent_hooks']), 40)
        self.assertEqual(self.canonical('stage_default'), second)
        self.assertEqual(len(self._parent_assemblers), 41)
        self.assertEqual(len({module for module, _ in self._parent_assemblers}), 41)
        outer = tuple((module, module.assemble) for module, _ in self._parent_assemblers)
        for module, original in self._parent_assemblers:
            self.assertIsNot(module.assemble, original)
        with self.assertRaisesRegex(RuntimeError, 'worker parent-cache restoration probe'):
            with parent_fixture._fixture_assembly_cache(True):
                for module, function in outer:
                    self.assertIsNot(module.assemble, function)
                self.assertIs(gates.assemble, self._new_assemblers[0])
                self.assertIs(stage.assemble, self._new_assemblers[1])
                raise RuntimeError('worker parent-cache restoration probe')
        for module, function in outer:
            self.assertIs(module.assemble, function)
        self.assertIs(gates.assemble, self._new_assemblers[0])
        self.assertIs(stage.assemble, self._new_assemblers[1])


if __name__ == '__main__':
    unittest.main()
