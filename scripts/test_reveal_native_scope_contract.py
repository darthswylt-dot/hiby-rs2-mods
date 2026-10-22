#!/usr/bin/env python3
"""Pinned normal-return premises for the two known native writer scopes.

This is a bounded direct-CFG/source audit, not complete writer coverage,
exception/unwind/longjmp instrumentation, native object ownership, a coherent
snapshot or UI-request freshness proof. In particular the renderer's third
argument is freshly allocated cache-canvas data on the inspected miss path,
not an immutable original UI request. No device, network or binary writes.
"""

import hashlib
import unittest

import test_folderfollow_reveal_static_contract as source
import test_reveal_contents_revision_contract as boundary


SCOPES = {
    'reset': {
        'entry': 0x491240, 'end': 0x49144C, 'frame': 0x48,
        'pair': (0x27BDFFB8, 0xAFBF0044), 'ra_slot': 0x44,
        'exits': (0x4913F0,),
        'callers': (0x45259C, 0x4A2D18, 0x4A5ED4,
                    0x4ACE0C, 0x4ACE20, 0x532AC4),
        'memory': {0x10, 0x20, 0x24, 0x28, 0x2C,
                   0x34, 0x38, 0x3C, 0x40, 0x44},
        'addresses': {0x20},
    },
    'reconcile': {
        'entry': 0x4919E0, 'end': 0x491E70, 'frame': 0x258,
        'pair': (0x27BDFDA8, 0xAFB3024C), 'ra_slot': 0x254,
        'exits': (0x491D08, 0x491E68),
        'callers': (0x492B8C, 0x494038),
        'memory': {0x10, 0x228, 0x22C, 0x238, 0x240, 0x244,
                   0x248, 0x24C, 0x250, 0x254},
        'addresses': {0x20, 0x228, 0x238},
    },
}


def direct_target(pc, word):
    """Aligned executable-word census, including likely/COP branches.

    This intentionally includes possible executable literals. An empty result
    is still only absence of an encoded direct target, never of indirect entry.
    """
    op, rs = word >> 26, (word >> 21) & 31
    if op in (2, 3):
        return ((pc + 4) & 0xF0000000) | ((word & 0x3FFFFFF) << 2)
    if (op in (1, 4, 5, 6, 7, 0x14, 0x15, 0x16, 0x17)
            or (op in (16, 17, 18, 19) and rs == 8)):
        imm = word & 0xFFFF
        return pc + 4 + (imm - 0x10000 if imm & 0x8000 else imm) * 4
    return None


class RevealNativeScopeContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.elf = source.Elf32(source.SOURCE)
        digest = hashlib.sha256(cls.elf.data).hexdigest()
        if digest != source.SOURCE_SHA256 or len(cls.elf.data) != source.SOURCE_SIZE:
            raise AssertionError(f'unrecognized reference: SHA-256 {digest}, '
                                 f'size {len(cls.elf.data)}')
        cls.direct = []
        for low, high in cls.elf.executable_ranges():
            for pc in range(low, high & ~3, 4):
                target = direct_target(pc, cls.elf.word(pc))
                if target is not None:
                    cls.direct.append((pc, target))

    instructions = boundary.RevealContentsRevisionContractTests.instructions
    reachable = boundary.RevealContentsRevisionContractTests.reachable

    def words(self, low, high):
        return [(pc, self.elf.word(pc)) for pc in range(low, high, 4)]

    def test_exact_entry_pairs_allocate_native_frames_before_the_carrier_write(self):
        for scope in SCOPES.values():
            entry = scope['entry']
            with self.subTest(entry=f'{entry:#x}'):
                self.assertEqual((self.elf.word(entry), self.elf.word(entry + 4)),
                                 scope['pair'])
                self.assertEqual(self.elf.word(entry) & 0xFFFF,
                                 (-scope['frame']) & 0xFFFF)
        # Reconcile saves s3 in its second word, not RA. An observer must
        # preserve original entry RA until the later native save at491A08.
        self.instructions(0x491A08, 'sw ra,+0x254(sp)', 'sw s4,+0x250(sp)')

    def test_exact_return_pairs_require_one_native_pop_and_actual_result_preservation(self):
        pairs = {
            0x4913F0: (0x03E00008, 0x27BD0048),
            0x491D08: (0x03E00008, 0x27BD0258),
            0x491E68: (0x03E00008, 0x27BD0258),
        }
        for pc, expected in pairs.items():
            with self.subTest(pc=f'{pc:#x}'):
                self.assertEqual((self.elf.word(pc), self.elf.word(pc + 4)), expected)
        # An exit observer replaces JR/pop, not a body call. It must return
        # through the already-restored native RA, restore the original v0,
        # and perform the displaced native frame pop exactly once.

    def test_global_direct_targets_do_not_enter_either_word_of_any_exit_pair(self):
        exits = {pc for scope in SCOPES.values() for pc in scope['exits']}
        for target in sorted(exits | {pc + 4 for pc in exits}):
            with self.subTest(target=f'{target:#x}'):
                self.assertEqual([pc for pc, dest in self.direct if dest == target], [])

    def test_only_named_entries_have_external_encoded_direct_inbound_edges(self):
        for scope in SCOPES.values():
            low, high = scope['entry'], scope['end']
            inbound = [(pc, target) for pc, target in self.direct
                       if low <= target < high and not low <= pc < high]
            with self.subTest(entry=f'{low:#x}'):
                self.assertEqual(inbound, [(pc, low) for pc in scope['callers']])
                self.assertEqual([pc for pc, dest in self.direct if dest == low + 4], [])
                self.assertTrue(all(self.elf.word(pc) >> 26 == 3 for pc, _ in inbound))
        # Runtime function pointers, corrupted control flow, exceptions and
        # unobserved computed entries are deliberately outside this census.

    def test_native_sp14_has_no_direct_access_or_locally_derived_alias(self):
        memory_ops = set(range(0x20, 0x30)) | set(range(0x30, 0x40))
        for scope in SCOPES.values():
            memory, addresses, adjustments = set(), set(), []
            for pc, word in self.words(scope['entry'], scope['end']):
                op, rs, rt = word >> 26, (word >> 21) & 31, (word >> 16) & 31
                with self.subTest(pc=f'{pc:#x}'):
                    if rs == 29:
                        offset = word & 0xFFFF
                        if op in memory_ops:
                            self.assertIn(op, (0x23, 0x2B))
                            memory.add(offset)
                        else:
                            self.assertEqual(op, 9)
                            if rt == 29:
                                adjustments.append((pc, offset))
                            else:
                                self.assertIn(rt, (4, 5, 6))
                                addresses.add(offset)
                    if op == 0:
                        self.assertNotEqual(rt, 29)
                        self.assertNotEqual((word >> 11) & 31, 29)
                    elif op not in (2, 3) and rt == 29:
                        self.assertEqual((op, rs), (9, 29))
            with self.subTest(entry=f"{scope['entry']:#x}"):
                self.assertEqual(memory, scope['memory'])
                self.assertEqual(addresses, scope['addresses'])
                self.assertNotIn(0x14, memory | addresses)
                self.assertEqual(adjustments, [
                    (scope['entry'], (-scope['frame']) & 0xFFFF),
                    *((pc + 4, scope['frame']) for pc in scope['exits']),
                ])
        # SP+14 is outside four O32 argument homes, but would be arg6.
        # The audited shapes use arg5 at+10; unknown indirect target ABI or
        # a callee writing outside its actual arguments is not certified.

    def test_native_fifth_argument_is_sp10_not_the_proposed_sp14_carrier(self):
        self.instructions(0x4912B0,
                          'sw zero,+0x10(sp)', 'lw t9,+0x410(a0)',
                          'jalr ra,t9', 'addu a2,zero,zero')
        self.instructions(0x491C00,
                          'sw zero,+0x10(sp)', 'lw t9,+0x410(a0)',
                          'jalr ra,t9', 'addu a2,zero,zero')
        for scope in SCOPES.values():
            outgoing = [(pc, word & 0xFFFF) for pc, word in
                        self.words(scope['entry'], scope['end'])
                        if word >> 26 == 0x2B and (word >> 21) & 31 == 29
                        and word & 0xFFFF < 0x20]
            self.assertEqual(outgoing,
                             [(0x4912B0 if scope['frame'] == 0x48 else 0x491C00, 0x10)])

    def test_named_entry_direct_cfg_has_only_the_enumerated_normal_returns(self):
        for scope in SCOPES.values():
            low, high = scope['entry'], scope['end']
            reached = self.reachable(low, low, high)
            returns, escapes = [], []
            for pc in sorted(reached):
                word = self.elf.word(pc)
                if word >> 26 == 0 and word & 63 == 8:
                    self.assertEqual(word, 0x03E00008)  # no tail JR t9
                    returns.append(pc)
                target = direct_target(pc, word)
                if target is not None and word >> 26 != 3 and not low <= target < high:
                    escapes.append((pc, target))
            with self.subTest(entry=f'{low:#x}'):
                self.assertEqual(returns, list(scope['exits']))
                self.assertEqual(escapes, [])
        # Calls are assumed to return normally. Native unwind/longjmp,
        # termination or unknown indirect transfers can bypass these ends;
        # such a missing end must stay open/fault, never imply quietness.

    def test_every_normal_return_has_reloaded_native_ra_after_the_last_call(self):
        for scope in SCOPES.values():
            low, high, slot = scope['entry'], scope['end'], scope['ra_slot']

            def effect(pc, restored):
                word = self.elf.word(pc)
                if word >> 26 == 3 or (word >> 26 == 0 and word & 63 == 9):
                    return False
                if word == (0x8FBF0000 | slot):
                    return True
                return restored

            todo, seen, checked = [(low, False)], set(), set()
            while todo:
                pc, restored = todo.pop()
                if (pc, restored) in seen or not low <= pc < high:
                    continue
                seen.add((pc, restored))
                word, restored = self.elf.word(pc), effect(pc, restored)
                op, fn = word >> 26, word & 63
                target = direct_target(pc, word)
                control = target is not None or (op == 0 and fn in (8, 9))
                if control:
                    restored = effect(pc + 4, restored)
                if op == 0 and fn == 8:
                    self.assertTrue(restored, f'RA not restored before {pc:#x}')
                    checked.add(pc)
                elif op == 3 or (op == 0 and fn == 9):
                    todo.append((pc + 8, restored))
                elif target is not None:
                    todo.append((target, restored))
                    if op != 2 and word != (0x10000000 | (word & 0xFFFF)):
                        todo.append((pc + 8, restored))
                else:
                    todo.append((pc + 4, restored))
            self.assertEqual(checked, set(scope['exits']))

    def test_entry_arguments_are_raw_scalars_not_universal_owner_view_pairs(self):
        self.instructions(0x491254,
                          'beq a1,zero,0x491430', 'sw s0,+0x34(sp)',
                          'addu s2,a0,zero', 'lw a0,+0x64(a1)')
        self.instructions(0x491268, 'addu s0,a1,zero')
        self.instructions(0x4919F0,
                          'addu s2,a1,zero', 'addu s1,a0,zero',
                          'addu s3,a2,zero')
        self.instructions(0x491A34, 'lhu v0,+0x0(s2)')
        self.instructions(0x491A5C, 'lhu v0,+0x0(s3)')
        # Reset's(U,V) differs from reconcile's(U,oldUTF16path,newUTF16path).
        # A private scope table must label entry args as raw_arg0/raw_arg1,
        # not dereference or reinterpret arg1 as a retained view in both.

    def test_normal_scope_end_does_not_claim_sql_success_or_completed_destruction(self):
        self.instructions(0x4913C0,
                          'lw v0,+0x70(s0)', 'andi v0,v0,0x1',
                          'beq v0,zero,0x4913E0', 'lw ra,+0x44(sp)')
        self.instructions(0x4913D0,
                          'lw a1,+0xcc(s0)', 'jal 0x499C20',
                          'addu a0,s0,zero', 'lw ra,+0x44(sp)')
        self.instructions(0x491CCC,
                          'lw ra,+0x254(sp)', 'lw v1,+0x70(v0)',
                          'andi v1,v1,0x1', 'beq v1,zero,0x491CF8',
                          'lw s4,+0x250(sp)')
        self.instructions(0x491CEC, 'lw v0,+0x238(sp)', 'lw ra,+0x254(sp)')
        self.instructions(0x491E64, 'addu v0,zero,zero',
                          'jr ra', 'addiu sp,sp,600')
        self.instructions(0x493B0C, 'addiu v0,zero,1', 'sw v0,+0x44(s0)')
        self.instructions(0x493FDC, 'jal 0x466A80', 'addu a0,s0,zero')
        # reset v0 can be its masked flag, final callback or logger result;
        # reconcile's first return is resolved V/null, second is forced zero.
        # The close-attempt marker occurs much earlier than actual free(V).

    def test_renderer_third_argument_is_created_after_cache_miss_not_original_ui_request(self):
        self.instructions(0x438438,
                          'sw v0,+0x10(sp)', 'jal 0x47AB40',
                          'addu a1,s2,zero', 'lw v0,+0x1b0(sp)',
                          'beq v0,zero,0x4386F4', 'lw t2,+0x1cc(sp)')
        self.instructions(0x438720,
                          'addiu a3,sp,432', 'jal 0x47A920',
                          'sw t2,+0x1cc(sp)', 'lw t9,+0x148(fp)',
                          'beq t9,zero,0x4388A4', 'lw t2,+0x1cc(sp)',
                          'lw a2,+0x1b0(sp)', 'addu a0,fp,zero',
                          'jalr ra,t9', 'addu a1,s0,zero')
        self.instructions(0x47A958,
                          'lw a1,+0x18(sp)', 'lw a2,+0x1c(sp)',
                          'jal 0x47A6E0', 'addu a0,s0,zero')
        self.instructions(0x47A970,
                          'jalr ra,t9', 'addu s0,v0,zero',
                          'beq s1,zero,0x47A984', 'addu v0,zero,zero',
                          'sw s0,+0x0(s1)')

    def test_allocated_canvas_node_coordinate_and_height_are_forwarded_to_renderer(self):
        self.instructions(0x47A72C,
                          'beq v0,zero,0x47A8C8', 'addiu a0,zero,112',
                          'addu s5,v0,zero', 'lw s7,+0x88(v0)',
                          'jal 0x4669E0', 'lw fp,+0x8c(v0)',
                          'beq v0,zero,0x47A8C8', 'addu s1,v0,zero',
                          'lw a2,+0x0(s0)', 'addiu s3,v0,8')
        self.instructions(0x47A768, 'sw s3,+0x18(sp)')
        self.instructions(0x47A79C,
                          'lw v0,+0x50(sp)', 'addu a0,zero,zero',
                          'sw s7,+0x64(s1)', 'sw fp,+0x68(s1)')
        self.instructions(0x47A7C0, 'jal 0x4752E0', 'sw v0,+0x58(s1)')
        self.instructions(0x47A898, 'lw v0,+0x18(sp)')
        self.instructions(0x49078C, 'lw v1,+0x50(s1)', 'lw v0,+0x60(s1)')
        self.assertEqual((0x58 - 8, 0x68 - 8), (0x50, 0x60))
        # A stamp minted here can be new even when the outer cause is stale.
        # Descriptor/address equality does not prove request freshness.


if __name__ == '__main__':
    unittest.main()
