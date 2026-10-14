#!/usr/bin/env python3
"""Exact-reference general-commit grouping anchors, not a live ownership proof.

The control-flow census scans SHF_EXECINSTR sections, not whole RX segments
(which also contain strings). Calls are assumed to return for the bounded
intraprocedural graph. Indirect callees, source ownership, escaped writers,
thread stacks, hardware ordering and nonlocal exits are not proved here.
"""

import hashlib
import unittest

from mips_static_trace import sx16
from test_folderfollow_reveal_static_contract import (
    SOURCE, SOURCE_SHA256, SOURCE_SIZE, Elf32, decode,
)


ENTRY, END = 0x42CC60, 0x42DCA8
EPILOGUE, RETURN = 0x42D6E4, 0x42D70C
FRAME = 0x1DD0


def executable_sections(elf):
    """File-backed SHF_EXECINSTR section ranges, with their literal names."""
    offset, size, count = elf.u32(0x20), elf.u16(0x2E), elf.u16(0x30)
    names_header = offset + size * elf.u16(0x32)
    names_offset, names_size = elf.u32(names_header + 16), elf.u32(names_header + 20)
    names = elf.data[names_offset:names_offset + names_size]
    result = []
    for index in range(count):
        header = offset + index * size
        if elf.u32(header + 8) & 4:  # SHF_EXECINSTR
            if elf.u32(header + 4) == 8:  # SHT_NOBITS cannot supply instructions.
                raise AssertionError('executable section has no file contents')
            name = names[elf.u32(header):].split(b'\0', 1)[0].decode('ascii')
            start = elf.u32(header + 12)
            result.append((name, start, start + elf.u32(header + 20)))
    return result


def direct_target(pc, word):
    op, rs, rt = word >> 26, (word >> 21) & 31, (word >> 16) & 31
    if op in (2, 3):
        return ((pc + 4) & 0xF0000000) | ((word & 0x3FFFFFF) << 2)
    if (op in (4, 5, 6, 7, 20, 21, 22, 23)
            or (op == 1 and rt in (0, 1, 2, 3, 16, 17, 18, 19))
            or (op == 17 and rs == 8)):
        return pc + 4 + sx16(word & 0xFFFF) * 4
    return None


def successors(pc, word):
    """Return normal continuations plus a delay-slot flag; do not enter callees."""
    op, fn = word >> 26, word & 63
    rs, rt = (word >> 21) & 31, (word >> 16) & 31
    target = direct_target(pc, word)
    if op == 3 or (op == 0 and fn == 9):
        return [pc + 8], True
    if op == 2:
        return [target], True
    if target is not None:
        return ([target] if op == 4 and rs == rt else [target, pc + 8]), True
    if op == 0 and fn == 8:
        return [], True
    return [pc + 4], False


class RevealLogicalContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.elf = Elf32(SOURCE)
        digest = hashlib.sha256(cls.elf.data).hexdigest()
        if digest != SOURCE_SHA256 or len(cls.elf.data) != SOURCE_SIZE:
            raise AssertionError(f'unrecognized reference: {digest}, '
                                 f'size {len(cls.elf.data)}')
        cls.sections = executable_sections(cls.elf)
        cls.edges = []
        cls.calls = {}
        for _, start, end in cls.sections:
            for pc in range(start, end, 4):
                word = cls.elf.word(pc)
                target = direct_target(pc, word)
                if target is not None:
                    cls.edges.append((pc, target))
                if word >> 26 == 3:
                    cls.calls.setdefault(target, []).append(pc)

    def instructions(self, start, *expected):
        for index, (word, assembly) in enumerate(expected):
            pc = start + 4 * index
            with self.subTest(pc=f'{pc:#x}'):
                self.assertEqual(self.elf.word(pc), word)
                self.assertEqual(decode(pc, word), assembly)

    def test_executable_section_scope_is_explicit(self):
        self.assertEqual(self.sections, [
            ('.init', 0x41B9D8, 0x41BA34),
            ('.text', 0x41BA40, 0x91F340),
            ('.MIPS.stubs', 0x91F340, 0x91F850),
            ('.fini', 0x91F850, 0x91F884),
            ('.plt', 0xA5B0C0, 0xA5BFA0),
        ])

    def test_only_two_direct_entries_and_no_direct_interior_entries(self):
        self.assertEqual([(pc, target) for pc, target in self.edges
                          if ENTRY <= target < END and not ENTRY <= pc < END],
                         [(0x42E42C, ENTRY), (0x42E598, ENTRY)])
        self.instructions(0x42E424,
                          (0x8E040BA4, 'lw a0,+0xba4(s0)'),
                          (0x27A50018, 'addiu a1,sp,24'),
                          (0x0C10B318, 'jal 0x42CC60'),
                          (0x03C03021, 'addu a2,fp,zero'))
        self.instructions(0x42E588,
                          (0x3C0500AE, 'lui a1,0xAE'),
                          (0x8E040BA4, 'lw a0,+0xba4(s0)'),
                          (0x8E060020, 'lw a2,+0x20(s0)'),
                          (0x24A5D468, 'addiu a1,a1,-11160'),
                          (0x0C10B318, 'jal 0x42CC60'),
                          (0xAE000BB8, 'sw zero,+0xbb8(s0)'))

    def test_complete_body_has_one_normal_exit_and_no_tail_exit(self):
        pending, reached, slots = [ENTRY], set(), set()
        while pending:
            pc = pending.pop()
            if pc in reached:
                continue
            self.assertTrue(ENTRY <= pc < END, f'normal exit to {pc:#x}')
            reached.add(pc)
            next_pcs, delay = successors(pc, self.elf.word(pc))
            if delay:
                slots.add(pc + 4)
            pending.extend(next_pcs)
        self.assertEqual(len(reached), 767)
        self.assertEqual(len(slots), 275)
        self.assertEqual(reached | slots, set(range(ENTRY, END, 4)))
        self.assertEqual(len(reached | slots), 1042)
        self.assertEqual([pc for pc in range(ENTRY, END, 4)
                          if self.elf.word(pc) >> 26 == 0
                          and self.elf.word(pc) & 63 == 8], [RETURN])
        self.assertEqual([pc for pc in range(ENTRY, END, 4)
                          if self.elf.word(pc) >> 26 in (20, 21, 22, 23)
                          or (self.elf.word(pc) >> 26 == 17
                              and (self.elf.word(pc) >> 21) & 31 == 8)], [])
        self.assertEqual(sum(self.elf.word(pc) >> 26 == 3
                             for pc in range(ENTRY, END, 4)), 141)

    def test_shared_epilogue_is_on_every_normal_return_path(self):
        pending, reached = [ENTRY], set()
        while pending:
            pc = pending.pop()
            if pc in reached or pc == EPILOGUE:
                continue
            reached.add(pc)
            pending.extend(successors(pc, self.elf.word(pc))[0])
        self.assertNotIn(RETURN, reached)
        self.instructions(EPILOGUE,
                          (0x8FBF1DCC, 'lw ra,+0x1dcc(sp)'),
                          (0x8FBE1DC8, 'lw fp,+0x1dc8(sp)'),
                          (0x8FB71DC4, 'lw s7,+0x1dc4(sp)'),
                          (0x8FB61DC0, 'lw s6,+0x1dc0(sp)'),
                          (0x8FB51DBC, 'lw s5,+0x1dbc(sp)'),
                          (0x8FB41DB8, 'lw s4,+0x1db8(sp)'),
                          (0x8FB31DB4, 'lw s3,+0x1db4(sp)'),
                          (0x8FB21DB0, 'lw s2,+0x1db0(sp)'),
                          (0x8FB11DAC, 'lw s1,+0x1dac(sp)'),
                          (0x8FB01DA8, 'lw s0,+0x1da8(sp)'),
                          (0x03E00008, 'jr ra'),
                          (0x27BD1DD0, 'addiu sp,sp,7632'))

    def test_frame_is_fixed_and_entry_arguments_are_saved(self):
        self.instructions(ENTRY,
                          (0x27BDE230, 'addiu sp,sp,-7632'),
                          (0xAFB01DA8, 'sw s0,+0x1da8(sp)'))
        self.instructions(0x42CC80,
                          (0x0080F021, 'addu fp,a0,zero'),
                          (0x00A08821, 'addu s1,a1,zero'))
        self.instructions(0x42CC90, (0x00C09821, 'addu s3,a2,zero'))
        self.instructions(0x42CC98, (0xAFBF1DCC, 'sw ra,+0x1dcc(sp)'))
        writes_sp = []
        for pc in range(ENTRY, END, 4):
            word = self.elf.word(pc)
            op = word >> 26
            if ((op in (8, 9) and (word >> 16) & 31 == 29)
                    or (op == 0 and word & 63 in (0x20, 0x21, 0x22, 0x23, 0x25)
                        and (word >> 11) & 31 == 29)):
                writes_sp.append(pc)
        self.assertEqual(writes_sp, [ENTRY, RETURN + 4])
        self.assertEqual(FRAME, 7632)

    def test_every_return_explicitly_sets_zero_or_minus_one(self):
        incoming = [(pc, target) for pc, target in self.edges
                    if ENTRY <= pc < END and EPILOGUE <= target <= RETURN + 4]
        self.assertEqual(incoming, [(0x42DAFC, EPILOGUE), (0x42DB10, EPILOGUE),
                                    (0x42DC64, EPILOGUE), (0x42DC6C, EPILOGUE)])
        for pc in (0x42DAFC, 0x42DB10, 0x42DC64, 0x42DC6C):
            self.assertEqual(direct_target(pc, self.elf.word(pc)), EPILOGUE)
            self.instructions(pc + 4, (0x2402FFFF, 'addiu v0,zero,-1'))
        self.instructions(0x42D6DC,
                          (0xAE0000E0, 'sw zero,+0xe0(s0)'),
                          (0x00001021, 'addu v0,zero,zero'))

    def test_minus_twelve_is_an_error_out_local_not_a_return(self):
        self.instructions(0x42CC78, (0x2402FFF4, 'addiu v0,zero,-12'))
        self.instructions(0x42CCB8, (0xAFA21D8C, 'sw v0,+0x1d8c(sp)'))
        self.assertEqual([(pc, self.elf.word(pc)) for pc in range(ENTRY, END, 4)
                          if self.elf.word(pc) >> 26 in (32, 33, 35, 36, 37, 40, 41, 43)
                          and (self.elf.word(pc) >> 21) & 31 == 29
                          and self.elf.word(pc) & 0xFFFF == 0x1D8C], [
                              (0x42CCB8, 0xAFA21D8C),
                              (0x42DBB4, 0x8FA61D8C),
                              (0x42DBD0, 0x8FA51D8C),
                          ])
        for pc in (0x42D5F8, 0x42D890, 0x42DB2C):
            self.instructions(pc,
                              (0x0C10C7B8, 'jal 0x431EE0'),
                              (0x27A71D8C, 'addiu a3,sp,7564'))

    def test_preparation_clear_precedes_null_source_failure(self):
        self.instructions(0x42CD38,
                          (0x0C10A7A0, 'jal 0x429E80'),
                          (0xAFA21D88, 'sw v0,+0x1d88(sp)'),
                          (0x0C10A378, 'jal 0x428DE0'),
                          (0, 'nop'),
                          (0x1220036E, 'beq s1,zero,0x42DB04'))
        self.instructions(0x42DB04,
                          (0x24020003, 'addiu v0,zero,3'),
                          (0xAE0200D8, 'sw v0,+0xd8(s0)'),
                          (0xAE000018, 'sw zero,+0x18(s0)'),
                          (0x1000FEF4, 'beq zero,zero,0x42D6E4'),
                          (0x2402FFFF, 'addiu v0,zero,-1'))
        self.instructions(0x429EC0,
                          (0x8E020018, 'lw v0,+0x18(s0)'),
                          (0x1040000F, 'beq v0,zero,0x429F04'))
        self.instructions(0x429EF8,
                          (0xA6000104, 'sh zero,+0x104(s0)'),
                          (0xA600144C, 'sh zero,+0x144c(s0)'))

    def test_prep_frame_relation_requires_its_saved_outer_return_address(self):
        self.instructions(0x429E80,
                          (0x27BDFFE0, 'addiu sp,sp,-32'),
                          (0x2404001B, 'addiu a0,zero,27'),
                          (0xAFBF001C, 'sw ra,+0x1c(sp)'))
        self.instructions(0x429F00,
                          (0x8FBF001C, 'lw ra,+0x1c(sp)'),
                          (0x8FB00018, 'lw s0,+0x18(sp)'),
                          (0x03E00008, 'jr ra'),
                          (0x27BD0020, 'addiu sp,sp,32'))
        self.assertEqual(self.calls[0x429E80], [0x42C2B4, 0x42CD38, 0x42E7D8])
        self.assertEqual([pc + 8 for pc in self.calls[0x429E80]],
                         [0x42C2BC, 0x42CD40, 0x42E7E0])
        self.assertEqual([pc for pc in range(0x429E80, 0x429F20, 4)
                          if self.elf.word(pc) >> 26 == 9
                          and (self.elf.word(pc) >> 16) & 31 == 29],
                         [0x429E80, 0x429F0C])
        self.instructions(0x429EE0,
                          (0x0C111DC0, 'jal 0x447700'),
                          (0x24040002, 'addiu a0,zero,2'))
        # Live ra at the clear is the nested call's RA, not 42CD40. An adapter
        # must use the pinned saved stack slot and its own ORIGINAL SP.
        self.assertEqual(0x42CD38 + 8, 0x42CD40)

    def test_three_inner_copies_share_fixed_original_general_frame(self):
        for pc in (0x42CD5C, 0x42CF84):
            self.instructions(pc,
                              (0x0C296D10, 'jal 0xA5B440'),
                              (0x24060A88, 'addiu a2,zero,2696'))
        self.instructions(0x42D380,
                          (0x2684D468, 'addiu a0,s4,-11160'),
                          (0x02202821, 'addu a1,s1,zero'),
                          (0x24060A88, 'addiu a2,zero,2696'))
        self.instructions(0x42D398,
                          (0x0C296D10, 'jal 0xA5B440'),
                          (0xAE020BA8, 'sw v0,+0xba8(s0)'))
        self.instructions(0x42CF68,
                          (0x0C14B9F8, 'jal 0x52E7E0'),
                          (0x24A5EDCC, 'addiu a1,a1,-4660'),
                          (0x044002E1, 'bltz v0,0x42DAF8'))
        self.instructions(0x42DAF8,
                          (0xAE000BA8, 'sw zero,+0xba8(s0)'),
                          (0x1000FEF9, 'beq zero,zero,0x42D6E4'),
                          (0x2402FFFF, 'addiu v0,zero,-1'))
        self.instructions(0x42D8A0,
                          (0x0C110BB0, 'jal 0x442EC0'),
                          (0x02E02021, 'addu a0,s7,zero'),
                          (0x104000F0, 'beq v0,zero,0x42DC6C'))

    def test_indirect_descriptor_callback_is_inside_the_boundary_not_proved_safe(self):
        self.assertEqual([pc for pc in range(ENTRY, END, 4)
                          if self.elf.word(pc) >> 26 == 0
                          and self.elf.word(pc) & 63 == 9], [0x42D6A0])
        self.instructions(0x42D690,
                          (0x8E190BA0, 'lw t9,+0xba0(s0)'),
                          (0x13200004, 'beq t9,zero,0x42D6A8'),
                          (0, 'nop'),
                          (0x8E040B98, 'lw a0,+0xb98(s0)'),
                          (0x0320F809, 'jalr ra,t9'),
                          (0x2685D468, 'addiu a1,s4,-11160'))
        # Failure can schedule retry and pause for 2000 ms. This is not a
        # short critical section or permission to hold a stock/UI mutex.
        self.instructions(0x42DC74,
                          (0x0C119B88, 'jal 0x466E20'),
                          (0x240407D0, 'addiu a0,zero,2000'),
                          (0x0C10AC80, 'jal 0x42B200'),
                          (0x24040003, 'addiu a0,zero,3'))
        self.instructions(0x466E20,
                          (0x000419C0, 'sll v1,a0,7'),
                          (0x00041080, 'sll v0,a0,2'),
                          (0x00621023, 'subu v0,v1,v0'),
                          (0x00442021, 'addu a0,v0,a0'),
                          (0x27BDFFE0, 'addiu sp,sp,-32'),
                          (0xAFBF001C, 'sw ra,+0x1c(sp)'),
                          (0x0C296D4C, 'jal 0xA5B530'),
                          (0x000420C0, 'sll a0,a0,3'))
        self.assertEqual(((2000 << 7) - (2000 << 2) + 2000) << 3, 2000000)


if __name__ == '__main__':
    unittest.main()
