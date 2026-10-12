#!/usr/bin/env python3
"""Hash-gated rebinding/post-fill anchors, not a live ownership proof."""

import hashlib
import unittest

from test_folderfollow_reveal_static_contract import (
    SOURCE, SOURCE_SHA256, SOURCE_SIZE, Elf32, decode,
)


class RevealPublicationContractTests(unittest.TestCase):
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

    def test_shared_binding_method_stores_list_without_generation_check(self):
        self.instructions(0x4A0908,
                          'lui v0,0x4A', 'addiu v0,v0,3808',
                          'sw v0,+0x410(s0)')
        self.instructions(0x4A0F2C, 'sw s1,+0x1bc(s0)',
                          'jal 0x459740', 'special(fn=0xA)')
        # Constructor and reset both use the method; the worker does too.
        self.instructions(0x49281C, 'lw t9,+0x410(a0)', 'jalr ra,t9',
                          'addu a2,zero,zero')

    def test_render_binding_precedes_the_enqueue_mutex(self):
        self.instructions(0x4928C8, 'lui a1,0x49', 'addu a0,s2,zero',
                          'jal 0x459540', 'addiu a1,a1,1760')
        self.instructions(0x459548, 'sw a1,+0x148(a0)')
        self.instructions(0x438738, 'lw a2,+0x1b0(sp)',
                          'addu a0,fp,zero', 'jalr ra,t9',
                          'addu a1,s0,zero')
        self.instructions(0x49076C,
                          'sw s1,+0x3b50(s0)', 'lw v0,+0x1bc(s2)',
                          'sw s2,+0x3b54(s0)', 'addiu a0,s0,14572',
                          'sw v0,+0x64(s0)', 'lui v0,0x49',
                          'addiu v0,v0,-1920', 'sw v0,+0x3b60(s0)')
        self.instructions(0x49080C, 'jal 0x48F180',
                          'addiu a1,s0,14500')
        self.instructions(0x48F194, 'lw a0,+0x10(a0)',
                          'jal 0x466DA0', 'addu s1,a1,zero')
        self.assertEqual(0x38A4 + 0x2BC, 0x3B60)

    def test_copied_job_postfill_callback_runs_inside_worker_mutex(self):
        self.instructions(0x48F1B4,
                          'addiu a2,zero,708', 'addiu a0,sp,24',
                          'jal 0xA5B440', 'addu a1,s1,zero')
        self.instructions(0x48EA30, 'lw v1,+0x4(s4)',
                          'sw v1,+0x2c0(s3)')
        self.instructions(0x48EC34,
                          'jal 0x466DA0', 'lw a0,+0x10(s0)',
                          'lw v0,+0x4(s1)', 'bne v0,zero,0x48EC84',
                          'nop', 'lw t9,+0x2c0(s1)',
                          'beq t9,zero,0x48EC7C', 'addu a0,s0,zero',
                          'jalr ra,t9', 'addu a1,s1,zero',
                          'addiu v1,zero,-1', 'beq v0,v1,0x48EDCC',
                          'addiu a0,s3,5200', 'lw t9,+0x2bc(s1)',
                          'beq t9,zero,0x48EC7C', 'addu a0,s0,zero',
                          'jalr ra,t9', 'addu a1,s1,zero',
                          'addiu v0,zero,2', 'sw v0,+0x4(s1)',
                          'jal 0x466DC0', 'lw a0,+0x10(s0)')

    def test_worker_postfill_resolves_name_and_calls_same_binding_method(self):
        self.instructions(0x48F8A0, 'addiu a2,sp,32',
                          'jal 0x4E5320', 'addiu a1,a1,72')
        self.instructions(0x48F8B8, 'lw a0,+0x3b68(v0)',
                          'beq a0,zero,0x48F8E4', 'nop',
                          'lw a1,+0x64(v0)', 'lw a2,+0x290(s0)',
                          'lw a3,+0x294(s0)', 'sw zero,+0x10(sp)',
                          'lw t9,+0x410(a0)', 'jalr ra,t9', 'nop')
        # Window metadata follows the fill, whose return is not tested here.
        self.instructions(0x48D1B8,
                          'jal 0x6F7CA0', 'sw s0,+0x10(sp)',
                          'lw t9,+0x404(s1)', 'addu a1,s2,zero',
                          'jalr ra,t9', 'addu a0,s1,zero',
                          'lw t9,+0x408(s1)', 'addu a0,s1,zero',
                          'jalr ra,t9', 'addu a1,s4,zero')

    def test_postfill_and_renderer_signal_do_not_certify_sql_completion(self):
        # Append outcome is still in v0 at F0, then ignored by stock.
        self.instructions(0x6ED6E8,
                          'jalr ra,t9', 'addiu a1,sp,32',
                          'addiu s1,s1,1', 'jal 0x5DFA80',
                          'addu a0,s0,zero', 'beq v0,s2,0x6ED6C8',
                          'nop', 'jal 0x5C31C0', 'addu a0,s0,zero')
        self.instructions(0x6F8BF4,
                          'lw a0,+0xba8(sp)', 'jal 0x5C30E0',
                          'addu s0,zero,zero', 'beq zero,zero,0x6F7F5C')
        # Explicit fill failure also reaches state 2 and the renderer wake.
        self.instructions(0x48EDCC,
                          'jal 0x467160', 'addu a1,s5,zero',
                          'beq zero,zero,0x48EC80', 'addiu v0,zero,2')
        self.instructions(0x48EC8C,
                          'lw v0,+0x138(s0)', 'jal 0x466D00',
                          'lw a0,+0x144(v0)')
        self.instructions(0x438764, 'lw a0,+0x144(t2)',
                          'jal 0x466CE0', 'addiu a1,zero,-1')

    def test_reset_cancellation_must_precede_postload_binding(self):
        self.instructions(0x49126C, 'jal 0x456E80', 'nop')
        self.instructions(0x49127C, 'sw zero,+0x64(s0)',
                          'jal 0x456E80', 'nop')
        self.instructions(0x49128C,
                          'sw zero,+0x68(s0)', 'lw t9,+0x4218(s0)',
                          'lw a2,+0x1d4(a0)', 'addiu a1,s0,100',
                          'jalr ra,t9', 'addiu a3,s0,108')
        self.instructions(0x4912B4, 'lw t9,+0x410(a0)',
                          'jalr ra,t9', 'addu a2,zero,zero')
        # Additional local reset implementations bypass 0x491240 itself.
        for pc in (0x491BB0, 0x491BC8, 0x494A4C, 0x494A64):
            self.instructions(pc, 'jal 0x456E80', 'nop')
        for pc in (0x491C04, 0x494AA0):
            self.instructions(pc, 'lw t9,+0x410(a0)',
                              'jalr ra,t9', 'addu a2,zero,zero')


if __name__ == '__main__':
    unittest.main()
