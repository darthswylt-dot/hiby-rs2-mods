"""Hash-gated revocation leads, not emitted hooks or complete coverage."""

import hashlib
import unittest

from test_folderfollow_reveal_static_contract import (
    SOURCE, SOURCE_SHA256, SOURCE_SIZE, Elf32, decode,
)


class LifecycleContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.elf = Elf32(SOURCE)
        digest = hashlib.sha256(cls.elf.data).hexdigest()
        if digest != SOURCE_SHA256 or len(cls.elf.data) != SOURCE_SIZE:
            raise AssertionError(f'unrecognized reference: {digest}, '
                                 f'size {len(cls.elf.data)}')

    def instructions(self, start, *expected):
        for index, assembly in enumerate(expected):
            pc = start + 4 * index
            with self.subTest(pc=f'{pc:#x}'):
                self.assertEqual(decode(pc, self.elf.word(pc)), assembly)

    def test_nonnull_preclose_pair_precedes_first_view_fields_and_cleanup(self):
        self.instructions(0x493AC0,
                          'addiu sp,sp,-1208', 'sw s1,+0x494(sp)',
                          'addiu s1,sp,552', 'sw s0,+0x490(sp)',
                          'addu a1,zero,zero', 'addu s0,a0,zero',
                          'addiu a2,zero,520', 'addu a0,s1,zero',
                          'sw ra,+0x4b4(sp)')
        self.instructions(0x493AFC,
                          'jal 0xA5BC60', 'sw s2,+0x498(sp)',
                          'beq s0,zero,0x494264', 'addu a0,s0,zero',
                          'addiu v0,zero,1', 'sw v0,+0x44(s0)',
                          'lw s6,+0x41e8(s0)', 'lw s5,+0xd4(s0)',
                          'jal 0x4916A0', 'lw s7,+0x41d8(s0)')
        # Before 493B0C the only call clears a stack buffer. Hooking the
        # pair would replay it once and resume 493B14 with the existing frame.
        calls = [(pc, decode(pc, self.elf.word(pc)))
                 for pc in range(0x493AC0, 0x493B0C, 4)
                 if self.elf.word(pc) >> 26 == 3]
        self.assertEqual(calls, [(0x493AFC, 'jal 0xA5BC60')])
        self.assertEqual(self.elf.word(0x493B0C), 0x24020001)
        self.assertEqual(self.elf.word(0x493B10), 0xAE020044)

    def test_distinct_reset_entries_precede_old_list_reads_and_frees(self):
        for entry, frame, saved, displacement in (
                (0x491240, -72, 'ra', '0x44'),
                (0x4919E0, -600, 's3', '0x24c'),
                (0x494A00, -80, 'ra', '0x4c')):
            self.instructions(entry, f'addiu sp,sp,{frame}',
                              f'sw {saved},+{displacement}(sp)')
        self.instructions(0x491260,
                          'lw a0,+0x64(a1)', 'beq a0,zero,0x491274',
                          'addu s0,a1,zero', 'jal 0x456E80', 'nop')
        self.instructions(0x494A24,
                          'addiu a2,sp,48', 'addu s2,a1,zero',
                          'jal 0x4E5320', 'addu s3,a0,zero')
        for pc in (0x49126C, 0x491280, 0x491BB0, 0x491BC8,
                   0x494A4C, 0x494A64):
            self.instructions(pc, 'jal 0x456E80', 'nop')

    def test_depth_reconciliation_changes_scope_before_common_reset_block(self):
        self.instructions(0x4919F0,
                          'addu s2,a1,zero', 'addu s1,a0,zero',
                          'addu s3,a2,zero')
        self.instructions(0x491AC8,
                          'beq a0,zero,0x491E4C', 'addiu a0,a0,15832',
                          'addiu a1,sp,32', 'jal 0x41FB80',
                          'addiu a2,zero,259')
        self.instructions(0x491D44,
                          'lw a0,+0x238(sp)', 'beq a0,zero,0x491E4C',
                          'addiu a0,a0,15832', 'addu a1,s3,zero',
                          'jal 0x41FB80', 'addiu a2,zero,259')
        self.assertEqual(15832, 0x3DD8)
        self.instructions(0x491BA4,
                          'lw a0,+0x64(a3)', 'beq a0,zero,0x491BBC',
                          'nop', 'jal 0x456E80', 'nop')

    def test_render_guarded_prologue_is_not_the_branching_function_entry(self):
        self.instructions(0x4906E0,
                          'beq a0,zero,0x490890', 'nop',
                          'beq a1,zero,0x490890', 'nop',
                          'beq a2,zero,0x490890', 'nop',
                          'addiu sp,sp,-48', 'sw ra,+0x2c(sp)')
        self.instructions(0x49075C,
                          'addiu a0,v0,14508', 'addu a1,s1,zero',
                          'jal 0xA5BEE0', 'lw s4,+0xdc(v0)',
                          'sw s1,+0x3b50(s0)', 'lw v0,+0x1bc(s2)',
                          'sw s2,+0x3b54(s0)', 'addiu a0,s0,14572',
                          'sw v0,+0x64(s0)')
        # No prologue trampoline is emitted here; the branch at 4906E0
        # cannot simply be copied to a different PC unchanged.

    def test_worker_fill_mutates_lists_before_postfill_binding(self):
        self.assertEqual(self.elf.word(0x94166C), 0x922704)
        self.assertEqual(self.elf.word(0x941670), 0x48D280)
        self.instructions(0x48D280, 'j 0x48D080', 'nop')
        self.instructions(0x48D080, 'addiu sp,sp,-64', 'sw ra,+0x3c(sp)')
        self.instructions(0x48D0D4,
                          'addiu a2,sp,32', 'addiu a1,a1,72',
                          'jal 0x4E5320', 'lw s4,+0x29c(s0)')
        self.instructions(0x48D110,
                          'lw a0,+0x68(s2)', 'beq a0,zero,0x48D12C',
                          'nop', 'lw t9,+0x24(a0)', 'jalr ra,t9', 'nop')
        self.instructions(0x48D168,
                          'lw a0,+0x1bc(s1)', 'lw t9,+0x24(a0)',
                          'jalr ra,t9', 'nop')
        self.instructions(0x48F880, 'addiu sp,sp,-48', 'sw ra,+0x2c(sp)')
        self.instructions(0x48F8D4,
                          'lw t9,+0x410(a0)', 'jalr ra,t9', 'nop')
        self.instructions(0x4A0EE0, 'addiu sp,sp,-64', 'sw s1,+0x2c(sp)')
        self.instructions(0x4A0F2C, 'sw s1,+0x1bc(s0)')

    def test_depth_helper_degenerate_branch_is_not_a_proved_noop_return(self):
        self.instructions(0x491D10,
                          'slt a0,a0,s4', 'beq a0,zero,0x491E2C',
                          'addu a3,zero,zero')
        self.instructions(0x491E2C,
                          'beq zero,zero,0x491BA4', 'addu s2,zero,zero')
        # This pins CFG, not reachability under valid equal-depth input,
        # successful reset semantics or an observed stock null dereference.


if __name__ == '__main__':
    unittest.main()
