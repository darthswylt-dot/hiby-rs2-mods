#!/usr/bin/env python3
"""Pinned same-file descriptor-block boundary; not live ownership/coherence."""

import hashlib
import unittest

from test_folderfollow_reveal_logical_contract import (
    direct_target, executable_sections, successors,
)
from test_folderfollow_reveal_static_contract import (
    SOURCE, SOURCE_SHA256, SOURCE_SIZE, Elf32, decode,
)


ENTRY, END = 0x42CAC0, 0x42CC54
BLOCK_ENTRY, BLOCK_EXIT = 0x42CBD4, 0x42CC20


def graph(elf, entry, stop=None):
    pending, reached, slots = [entry], set(), set()
    while pending:
        pc = pending.pop()
        if pc in reached or pc == stop:
            continue
        if not ENTRY <= pc < END:
            raise AssertionError(f'unexpected normal exit to {pc:#x}')
        reached.add(pc)
        continuation, delay = successors(pc, elf.word(pc))
        if delay:
            slots.add(pc + 4)
        pending.extend(continuation)
    return reached, slots


class RevealFastContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.elf = Elf32(SOURCE)
        digest = hashlib.sha256(cls.elf.data).hexdigest()
        if digest != SOURCE_SHA256 or len(cls.elf.data) != SOURCE_SIZE:
            raise AssertionError(f'unrecognized reference: {digest}, '
                                 f'size {len(cls.elf.data)}')
        cls.sections = executable_sections(cls.elf)
        cls.edges = []
        for _, start, end in cls.sections:
            for pc in range(start, end, 4):
                target = direct_target(pc, cls.elf.word(pc))
                if target is not None:
                    cls.edges.append((pc, target))

    def instructions(self, start, *expected):
        for index, (word, assembly) in enumerate(expected):
            pc = start + 4 * index
            with self.subTest(pc=f'{pc:#x}'):
                self.assertEqual(self.elf.word(pc), word)
                self.assertEqual(decode(pc, word), assembly)

    def test_full_body_and_only_two_returns(self):
        reached, slots = graph(self.elf, ENTRY)
        self.assertEqual((len(reached), len(slots)), (74, 27))
        self.assertEqual(reached | slots, set(range(ENTRY, END, 4)))
        self.assertEqual(len(reached | slots), 101)
        self.assertEqual([pc for pc in range(ENTRY, END, 4)
                          if self.elf.word(pc) >> 26 == 0
                          and self.elf.word(pc) & 63 == 8],
                         [0x42CB94, 0x42CC40])
        self.assertEqual(sum(self.elf.word(pc) >> 26 == 3
                             for pc in range(ENTRY, END, 4)), 8)
        self.assertEqual([pc for pc in range(ENTRY, END, 4)
                          if self.elf.word(pc) >> 26 == 0
                          and self.elf.word(pc) & 63 == 9], [0x42CC0C])

    def test_four_direct_entries_no_direct_interior_entry(self):
        self.assertEqual([(pc, target) for pc, target in self.edges
                          if ENTRY <= target < END and not ENTRY <= pc < END],
                         [(0x42E014, ENTRY), (0x42E198, ENTRY),
                          (0x42E4E8, ENTRY), (0x42E780, ENTRY)])
        for pc in (0x42E010, 0x42E194):
            self.instructions(pc,
                              (0x8FA50AA4, 'lw a1,+0xaa4(sp)'),
                              (0x0C10B2B0, 'jal 0x42CAC0'),
                              (0x02402021, 'addu a0,s2,zero'))
        for pc in (0x42E4E0, 0x42E778):
            self.instructions(pc,
                              (0x8FA50AB0, 'lw a1,+0xab0(sp)'),
                              (0x3C040001, 'lui a0,0x1'),
                              (0x0C10B2B0, 'jal 0x42CAC0'),
                              (0x24840002, 'addiu a0,a0,2'))

    def test_unframed_early_returns_cannot_use_framed_exit_contract(self):
        self.instructions(ENTRY,
                          (0x10A0005F, 'beq a1,zero,0x42CC40'),
                          (0, 'nop'),
                          (0x94A3020C, 'lhu v1,+0x20c(a1)'),
                          (0x10600031, 'beq v1,zero,0x42CB94'),
                          (0x00001021, 'addu v0,zero,zero'))
        self.instructions(0x42CC40,
                          (0x03E00008, 'jr ra'),
                          (0x2402FFFF, 'addiu v0,zero,-1'))
        self.instructions(0x42CB94,
                          (0x03E00008, 'jr ra'), (0, 'nop'))

    def test_framed_route_has_fixed_48_byte_frame_and_common_epilogue(self):
        self.instructions(0x42CAD4,
                          (0x27BDFFD0, 'addiu sp,sp,-48'),
                          (0xAFB40028, 'sw s4,+0x28(sp)'),
                          (0xAFB1001C, 'sw s1,+0x1c(sp)'),
                          (0xAFB00018, 'sw s0,+0x18(sp)'),
                          (0xAFBF002C, 'sw ra,+0x2c(sp)'),
                          (0xAFB30024, 'sw s3,+0x24(sp)'),
                          (0xAFB20020, 'sw s2,+0x20(sp)'))
        self.instructions(0x42CB74,
                          (0x8FBF002C, 'lw ra,+0x2c(sp)'),
                          (0x8FB40028, 'lw s4,+0x28(sp)'),
                          (0x8FB30024, 'lw s3,+0x24(sp)'),
                          (0x8FB20020, 'lw s2,+0x20(sp)'),
                          (0x8FB1001C, 'lw s1,+0x1c(sp)'),
                          (0x8FB00018, 'lw s0,+0x18(sp)'),
                          (0x00001021, 'addu v0,zero,zero'),
                          (0x27BD0030, 'addiu sp,sp,48'))
        reached, slots = graph(self.elf, 0x42CAD4, 0x42CB74)
        self.assertEqual((len(reached), len(slots)), (61, 23))
        self.assertNotIn(0x42CB94, reached)
        self.assertNotIn(0x42CC40, reached)
        self.assertEqual([pc for pc in range(ENTRY, END, 4)
                          if self.elf.word(pc) >> 26 == 9
                          and (self.elf.word(pc) >> 16) & 31 == 29],
                         [0x42CAD4, 0x42CB90])

    def test_fallback_is_not_synchronous_copy_and_zero_is_not_playback_success(self):
        self.instructions(0x42CB04,
                          (0x308300FF, 'andi v1,a0,0xFF'),
                          (0x24020002, 'addiu v0,zero,2'),
                          (0x00A08021, 'addu s0,a1,zero'),
                          (0x10620045, 'beq v1,v0,0x42CC28'))
        self.instructions(0x42CB58,
                          (0x02002821, 'addu a1,s0,zero'),
                          (0x0C10AC60, 'jal 0x42B180'),
                          (0x2406FFFF, 'addiu a2,zero,-1'))
        self.instructions(0x42CC28,
                          (0x02802021, 'addu a0,s4,zero'),
                          (0x0C10AC60, 'jal 0x42B180'),
                          (0x2406FFFF, 'addiu a2,zero,-1'),
                          (0x26120004, 'addiu s2,s0,4'),
                          (0x1000FFCA, 'beq zero,zero,0x42CB64'),
                          (0x3C1300AE, 'lui s3,0xAE'))
        self.instructions(0x42B1EC,
                          (0x24040009, 'addiu a0,zero,9'),
                          (0x00002821, 'addu a1,zero,zero'),
                          (0x0810AC50, 'j 0x42B140'),
                          (0x27BD0028, 'addiu sp,sp,40'))

    def test_narrow_hook_pairs_and_same_frame_copy_provenance(self):
        self.instructions(0x42CBD0,
                          (0x3C1400AE, 'lui s4,0xAE'),
                          (0x2684D468, 'addiu a0,s4,-11160'),
                          (0x02002821, 'addu a1,s0,zero'),
                          (0x0C296D10, 'jal 0xA5B440'),
                          (0x24060A88, 'addiu a2,zero,2696'))
        self.instructions(BLOCK_EXIT,
                          (0x1000FFD1, 'beq zero,zero,0x42CB68'),
                          (0x2664DFB4, 'addiu a0,s3,-8268'))
        self.assertEqual(0x42CBDC + 8, 0x42CBE4)
        self.assertEqual(0xAE0000 - 11160, 0xADD468)

    def test_every_narrow_normal_route_reaches_exit_without_fallback(self):
        reached, slots = graph(self.elf, BLOCK_ENTRY, BLOCK_EXIT)
        self.assertEqual(reached, {
            0x42CBD4, 0x42CBD8, 0x42CBDC, 0x42CBE4, 0x42CBE8,
            0x42CBEC, 0x42CBF4, 0x42CBFC, 0x42CC00, 0x42CC08,
            0x42CC0C, 0x42CC14, 0x42CC18, 0x42CC48, 0x42CC4C,
        })
        self.assertEqual((len(reached), len(slots)), (15, 7))
        self.assertEqual({pc for pc in reached
                          if not successors(pc, self.elf.word(pc))[0]}, set())
        def reaches_exit(pc, visiting):
            if pc == BLOCK_EXIT:
                return True
            self.assertNotIn(pc, visiting, 'unproved loop in narrow block')
            next_pcs = successors(pc, self.elf.word(pc))[0]
            self.assertTrue(next_pcs, 'return/tail exit before completion')
            return all(reaches_exit(target, visiting | {pc})
                       for target in next_pcs)
        self.assertTrue(reaches_exit(BLOCK_ENTRY, set()))
        block = reached | slots | {BLOCK_EXIT, BLOCK_EXIT + 4}
        self.assertEqual([(pc, target) for pc, target in self.edges
                          if target in block and pc not in block], [])
        self.assertEqual([direct_target(pc, self.elf.word(pc))
                          for pc in sorted(reached) if self.elf.word(pc) >> 26 == 3],
                         [0xA5B440, 0x42CA00, 0x42B140])
        self.assertNotIn(0x42CB5C, reached)
        self.assertNotIn(0x42CC2C, reached)
        self.instructions(0x42CBEC,
                          (0x10430016, 'beq v0,v1,0x42CC48'),
                          (0xAE2200E8, 'sw v0,+0xe8(s1)'))
        self.instructions(0x42CC48,
                          (0x8E22001C, 'lw v0,+0x1c(s1)'),
                          (0x1000FFE9, 'beq zero,zero,0x42CBF4'),
                          (0xAE2200E8, 'sw v0,+0xe8(s1)'))

    def test_callback_and_event_are_inside_but_no_checked_result_at_exit(self):
        self.instructions(0x42CBF4,
                          (0x0C10B280, 'jal 0x42CA00'),
                          (0x02002021, 'addu a0,s0,zero'),
                          (0x8E390BA0, 'lw t9,+0xba0(s1)'),
                          (0x13200004, 'beq t9,zero,0x42CC14'),
                          (0, 'nop'),
                          (0x8E240B98, 'lw a0,+0xb98(s1)'),
                          (0x0320F809, 'jalr ra,t9'),
                          (0x2685D468, 'addiu a1,s4,-11160'),
                          (0x2404000B, 'addiu a0,zero,11'),
                          (0x0C10AC50, 'jal 0x42B140'),
                          (0x00002821, 'addu a1,zero,zero'))
        self.instructions(0x42B15C,
                          (0x0C114138, 'jal 0x4504E0'),
                          (0x27A50018, 'addiu a1,sp,24'),
                          (0x8FBF0024, 'lw ra,+0x24(sp)'),
                          (0x03E00008, 'jr ra'),
                          (0x27BD0028, 'addiu sp,sp,40'))
        # There is no v0 check between that call and BLOCK_EXIT. A private
        # outcome can mark synchronous completion only, not playback success.

    def test_trailing_backing_path_copy_is_disjoint_from_current_descriptor(self):
        self.instructions(0x42CB18,
                          (0x24B20004, 'addiu s2,a1,4'),
                          (0x3C1300AE, 'lui s3,0xAE'))
        self.instructions(0x42CB64,
                          (0x2664DFB4, 'addiu a0,s3,-8268'),
                          (0x02402821, 'addu a1,s2,zero'),
                          (0x0C107EE0, 'jal 0x41FB80'),
                          (0x24060104, 'addiu a2,zero,260'))
        self.instructions(0x41FB80,
                          (0x94A30000, 'lhu v1,+0x0(a1)'),
                          (0x00801021, 'addu v0,a0,zero'),
                          (0x10600008, 'beq v1,zero,0x41FBAC'),
                          (0x00803821, 'addu a3,a0,zero'))
        self.instructions(0x41FB90,
                          (0x10C00006, 'beq a2,zero,0x41FBAC'),
                          (0x24A50002, 'addiu a1,a1,2'),
                          (0xA4E30000, 'sh v1,+0x0(a3)'),
                          (0x94A30000, 'lhu v1,+0x0(a1)'),
                          (0x24C6FFFF, 'addiu a2,a2,-1'),
                          (0x1460FFFA, 'bne v1,zero,0x41FB90'),
                          (0x24E70002, 'addiu a3,a3,2'),
                          (0x03E00008, 'jr ra'),
                          (0xA4E00000, 'sh zero,+0x0(a3)'))
        destination = 0xAE0000 - 8268
        self.assertEqual(destination, 0xADDFB4)
        self.assertEqual(destination - 0xADD368, 0xC4C)
        self.assertEqual(0xADD468 + 0xA88, 0xADDEF0)
        self.assertEqual(destination + (260 + 1) * 2, 0xADE1BE)
        self.assertGreaterEqual(destination, 0xADD468 + 0xA88)
        self.assertLess(0xADD368 + 0xE8, 0xADD468)


if __name__ == '__main__':
    unittest.main()
