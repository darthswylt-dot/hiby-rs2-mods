#!/usr/bin/env python3
"""Hash-pinned native row/terminal/end boundaries, not SQL/UI ownership.

The path analysis is bounded to the normal producer body and assumes native
calls return normally. It says nothing about indirect entries, arbitrary
aliases, object lifetime, complete row publication or device behavior.
No binary/source write, network, installer, or player access.
"""

import hashlib
import unittest

from test_folderfollow_reveal_static_contract import (
    SOURCE, SOURCE_SHA256, SOURCE_SIZE, Elf32, decode,
)


class RevealLineageRowsContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.elf = Elf32(SOURCE)
        digest = hashlib.sha256(cls.elf.data).hexdigest()
        if digest != SOURCE_SHA256 or len(cls.elf.data) != SOURCE_SIZE:
            raise AssertionError(f'unrecognized reference: SHA-256 {digest}, '
                                 f'size {len(cls.elf.data)}')

    def instructions(self, start, *expected):
        for index, assembly in enumerate(expected):
            pc = start + 4 * index
            with self.subTest(pc=f'{pc:#x}', assembly=assembly):
                self.assertEqual(decode(pc, self.elf.word(pc)), assembly)

    def producer_reachable(self, start, *, blocked=()):
        """Overapproximate bounded direct flow, treating calls as returning.

        Delay slots are not vertices: none contains the tested BEGIN/END.
        Conditional (including likely) branches admit both outcomes. This
        is not an interprocedural/indirect-entry or exception-flow proof.
        """
        todo, seen, blocked = [start], set(), set(blocked)
        while todo:
            pc = todo.pop()
            if not 0x6ED5C0 <= pc < 0x6ED838 or pc in seen or pc in blocked:
                continue
            seen.add(pc)
            word = self.elf.word(pc)
            op, rs, rt = word >> 26, (word >> 21) & 31, (word >> 16) & 31
            imm = word & 0xFFFF
            imm -= 0x10000 if imm & 0x8000 else 0
            if op == 0 and (word & 63) == 8:  # JR return: no next invocation.
                continue
            if op == 2:
                todo.append(((pc + 4) & 0xF0000000) | ((word & 0x3FFFFFF) << 2))
            elif op == 3 or (op == 0 and (word & 63) == 9):
                todo.append(pc + 8)
            elif op in (1, 4, 5, 6, 7, 0x14, 0x15, 0x16, 0x17):
                todo.append(pc + 4 + imm * 4)
                if not (op == 4 and rs == rt == 0):
                    todo.append(pc + 8)
            else:
                todo.append(pc + 4)
        return seen

    def test_exact_three_hooks_and_postappend_old_ordinal_boundary(self):
        hooks = {
            0x6ED6E8: (0x0320F809, 0x27A50020),
            0x6ED704: (0x0C170C70, 0x02002021),
            0x6ED7D4: (0x8FBE0AC8, 0x8FB70AC4),
        }
        for pc, words in hooks.items():
            self.assertEqual((self.elf.word(pc), self.elf.word(pc + 4)), words)
        self.instructions(0x6ED6E0,
                          'lw t9,+0x18(s6)', 'addu a0,s6,zero',
                          'jalr ra,t9', 'addiu a1,sp,32',
                          'addiu s1,s1,1', 'jal 0x5DFA80',
                          'addu a0,s0,zero')
        # At the append return PC F0, v0 is actual append result and s1
        # is still the old SQL ordinal. Preserve the native call exactly once.
        self.assertEqual(0x6ED6E8 + 8, 0x6ED6F0)

    def test_mode_zero_descriptor_gate_is_not_implied_by_the_append_site(self):
        self.instructions(0x6ED6B4,
                          'addiu s2,zero,100', 'addiu s3,zero,1',
                          'sltiu s4,s7,1', 'bne v0,s2,0x6ED704',
                          'addiu s5,zero,15', 'beq s7,s3,0x6ED758',
                          'addiu a0,sp,32', 'beq s4,zero,0x6ED738',
                          'nop', 'jal 0x6E8D80', 'addu a1,s0,zero')
        # BNE likely s7,s5 loops without the descriptor append unless mode15.
        self.assertEqual(self.elf.word(0x6ED738), 0x56F5FFEE)
        self.instructions(0x6ED740,
                          'addu a0,s0,zero', 'jal 0x590E40',
                          'addu a1,zero,zero', 'sw v0,+0x20(sp)',
                          'beq zero,zero,0x6ED6E4', 'lw t9,+0x18(s6)')
        # Mode15 reaches the SAME append with only a word at SP+20. A
        # journal must gate mode0/receipt before path, cue or list-count reads.
        self.instructions(0x6ED788,
                          'addiu a1,sp,32', 'jal 0xA5B440',
                          'addiu a2,zero,2696')

    def test_sql_terminal_precedes_reset_and_actual_reset_result_survives(self):
        self.instructions(0x6ED6AC,
                          'jal 0x5DFA80', 'addu a0,s0,zero')
        self.instructions(0x6ED6FC,
                          'beq v0,s2,0x6ED6C8', 'nop',
                          'jal 0x5C31C0', 'addu a0,s0,zero',
                          'beq v0,zero,0x6ED7CC', 'addiu v1,zero,19',
                          'beq v0,v1,0x6ED7CC')
        # SQL step v0 arrives at704 when !=100. The original call replaces
        # it with statement-reset status at70C, so capture BEFORE and AFTER.
        self.assertEqual(0x6ED704 + 8, 0x6ED70C)
        # Stock treats reset0 and19 similarly here; a strict row decoder
        # may accept only0 but must preserve the original native result/flow.
        self.instructions(0x6ED730,
                          'beq zero,zero,0x6ED7D0', 'lw ra,+0xacc(sp)')
        # The DISTINCT statement-finalize is later, after producer END.
        # It is not captured by the terminal/reset wrapper above.
        self.instructions(0x6F8BF4,
                          'lw a0,+0xba8(sp)', 'jal 0x5C30E0',
                          'addu s0,zero,zero')

    def test_normal_end_has_initialized_receipt_but_null_return_has_separate_epilogue(self):
        self.instructions(0x6ED5EC,
                          'sw a2,+0xad8(sp)', 'beq a1,zero,0x6ED800',
                          'lw s7,+0xae0(sp)', 'beq a0,zero,0x6ED800')
        self.instructions(0x6ED61C,
                          'jal 0xA5BC60', 'addu s3,zero,zero',
                          'addiu s2,s2,-19672', 'addiu s4,s4,-15040')
        self.instructions(0x6ED7C4,
                          'jal 0x5C31C0', 'addiu s1,zero,-1',
                          'lw ra,+0xacc(sp)', 'addu v0,s1,zero',
                          'lw fp,+0xac8(sp)', 'lw s7,+0xac4(sp)')
        self.instructions(0x6ED800,
                          'lw ra,+0xacc(sp)', 'addiu s1,zero,1',
                          'addu v0,s1,zero', 'lw fp,+0xac8(sp)')
        self.instructions(0x6ED830, 'jr ra', 'addiu sp,sp,2768')
        all_paths = self.producer_reachable(0x6ED5C0)
        without_begin = self.producer_reachable(0x6ED5C0, blocked=(0x6ED624,))
        self.assertIn(0x6ED7D4, all_paths)
        self.assertIn(0x6ED800, without_begin)
        self.assertNotIn(0x6ED7D4, without_begin)
        self.assertNotIn(0x6ED7D4, self.producer_reachable(0x6ED800))
        # Bind failures after BEGIN can reach END without TERMINAL704.
        self.instructions(0x6ED640,
                          'bne fp,v0,0x6ED7C0', 'addu a0,s0,zero',
                          'bne s3,zero,0x6ED7C4', 'nop')
        self.instructions(0x6ED6A4,
                          'bne v0,zero,0x6ED79C', 'addu s1,zero,zero')
        self.assertIn(0x6ED7D4, self.producer_reachable(0x6ED79C, blocked=(0x6ED704,)))
        # At normal END v0 is already s1 and RA is already the real caller.
        # A nonlinked hook must replay the saved-fp/s7 restores once only.

    def test_mode_zero_path_cue_and_standard_append_count_are_concrete_fields(self):
        self.instructions(0x6E8D88,
                          'addu s1,a1,zero', 'sw s0,+0x1c(sp)',
                          'addu a1,zero,zero', 'addu s0,a0,zero')
        self.instructions(0x6E8DA8,
                          'sh zero,+0x4(s0)', 'addu a0,s1,zero',
                          'jal 0x5A9920', 'addiu a1,zero,1',
                          'beq v0,zero,0x6E8DF8', 'addiu a0,s0,4',
                          'lhu v1,+0x0(v0)')
        self.instructions(0x6E8DE0,
                          'sh v1,+0x0(a0)', 'addiu v0,v0,2',
                          'lhu v1,+0x0(v0)', 'bne v1,zero,0x6E8DD4',
                          'addiu a1,a0,2', 'sh zero,+0x0(a1)')
        self.instructions(0x6E8F78,
                          'addu a0,s1,zero', 'jal 0x590E40',
                          'addiu a1,zero,12', 'sw v0,+0x424(s0)')
        self.assertEqual(0x20 + 4, 0x24)
        self.assertEqual(0x20 + 0x424, 0x444)
        self.assertEqual(0x24 + (260 - 1) * 2, 0x22A)
        self.assertEqual(0x24 + 260 * 2, 0x22C)  # Next field, not path NUL.
        self.instructions(0x6E8DC4,
                          'bne v1,zero,0x6E8DE0', 'addiu a2,v0,520')
        self.assertEqual(self.elf.word(0x6E8DD4), 0x50460007)
        self.instructions(0x455CF0,
                          'lw v0,+0xc(s6)', 'addiu v0,v0,1',
                          'sw v0,+0xc(s6)', 'lw ra,+0x3c(sp)',
                          'addu v0,s5,zero')
        self.instructions(0x455DCC, 'lw v0,+0xc(a0)')
        self.instructions(0x455D94,
                          'beq zero,zero,0x455CFC', 'addiu s5,zero,-1')
        # Full cue bits are preserved (including negative int32 values).
        # Path termination within260 inspected units must be checked; this
        # native loop alone does not guarantee that bound for length260.

    def test_original_prefix_and_local_descriptor_sizes_are_not_row_journal_space(self):
        self.instructions(0x48F1B4,
                          'addiu a2,zero,708', 'addiu a0,sp,24',
                          'jal 0xA5B440', 'addu a1,s1,zero')
        self.instructions(0x48F3EC,
                          'addiu a2,zero,708', 'addiu a0,sp,24',
                          'jal 0xA5B440', 'addu a1,s3,zero')
        self.assertEqual(0x38A4 + 0x2C4, 0x3B68)  # Native panel field follows.
        self.instructions(0x6ED608,
                          'addiu a0,sp,32', 'addiu a2,zero,2696')
        self.assertEqual(0x20 + 0xA88, 0xAA8)  # Ends before saved s0.
        self.instructions(0x6ED5E8, 'sw s0,+0xaa8(sp)')
        # The private producer receipt at SP18 is outside descriptor bytes.
        self.assertLess(0x18 + 4, 0x20)


if __name__ == '__main__':
    unittest.main()
