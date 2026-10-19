#!/usr/bin/env python3
"""Hash-pinned renderer/job lineage, not native operation ownership.

These bounded original-instruction checks do not provide a sidecar, lifetime
lease, callback coverage, cross-thread handoff, or permission to reveal rows.
No firmware build, device access, network, or source-binary writes.
"""

import hashlib
import unittest

from test_folderfollow_reveal_static_contract import (
    SOURCE, SOURCE_SHA256, SOURCE_SIZE, Elf32, decode,
)


# MIPS32 scalar, unaligned, atomic and coprocessor load/store opcodes. Do not
# mistake an unrelated arithmetic/branch immediate for a memory displacement.
MEMORY_OPS = frozenset((
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26,
    0x28, 0x29, 0x2A, 0x2B, 0x2E,
    0x30, 0x31, 0x32, 0x35, 0x36,
    0x38, 0x39, 0x3A, 0x3D, 0x3E,
))


class RevealJobProvenanceContractTests(unittest.TestCase):
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

    def test_original_associated_view_is_available_before_renderer_mutation(self):
        self.instructions(0x459320,
                          'beq a0,zero,0x459334', 'nop',
                          'beq a1,zero,0x459334', 'nop',
                          'sw a1,+0x7c(a0)', 'jr ra', 'nop')
        self.instructions(0x459340,
                          'beq a0,zero,0x459350', 'nop',
                          'jr ra', 'lw v0,+0x7c(a0)')
        self.instructions(0x492748,
                          'lw a0,+0x3b68(s0)', 'jal 0x459320',
                          'addu a1,s0,zero')
        self.instructions(0x490744,
                          'lw s2,+0x0(v0)', 'beq s2,zero,0x490818',
                          'addiu v0,zero,-1', 'jal 0x459340',
                          'addu a0,s2,zero', 'addu s0,v0,zero',
                          'addiu a0,v0,14508', 'addu a1,s1,zero',
                          'jal 0xA5BEE0', 'lw s4,+0xdc(v0)')
        # At 490758 v0 is the associated V; the first template copy is later.
        # This getter is a raw association, not a generation or retained V.
        self.assertLess(0x490758, 0x490764)

    def test_template_preserves_original_pointers_and_copied_scope(self):
        self.instructions(0x4929A4,
                          'sw a2,+0x3b60(s0)', 'sw v0,+0x3b54(s0)',
                          'sw a1,+0x3b38(s0)', 'lw a1,+0x17d0(sp)',
                          'sw a0,+0x3b5c(s0)', 'sw s0,+0x3b58(s0)')
        self.instructions(0x49076C,
                          'sw s1,+0x3b50(s0)', 'lw v0,+0x1bc(s2)',
                          'sw s2,+0x3b54(s0)', 'addiu a0,s0,14572',
                          'sw v0,+0x64(s0)', 'lui v0,0x49',
                          'addiu v0,v0,-1920', 'sw v0,+0x3b60(s0)')
        self.instructions(0x4907B0,
                          'jal 0xA5B6E0', 'lw a1,+0x0(s3)',
                          'addiu a0,s0,14636', 'addiu a1,s0,15832',
                          'jal 0x41FB80', 'addiu a2,zero,260')
        for field, address in ((0x48, 0x38EC), (0x88, 0x392C),
                               (0x2AC, 0x3B50), (0x2B0, 0x3B54),
                               (0x2B4, 0x3B58), (0x2BC, 0x3B60)):
            self.assertEqual(0x38A4 + field, address)

    def test_constructor_and_later_enqueue_make_their_own_record_copies(self):
        self.instructions(0x492A2C,
                          'lw a1,+0x17d0(sp)', 'jal 0x48F360',
                          'addiu a2,s0,14500')
        self.instructions(0x48F3EC,
                          'addiu a2,zero,708', 'addiu a0,sp,24',
                          'jal 0xA5B440', 'addu a1,s3,zero',
                          'addiu a0,sp,24', 'addu a1,s2,zero',
                          'jal 0x48E980', 'sw zero,+0x18(sp)',
                          'lw a0,+0x130(s0)', 'lw t9,+0x18(a0)',
                          'jalr ra,t9', 'addiu a1,sp,24')
        for call in (0x49080C, 0x490878):
            self.instructions(call, 'jal 0x48F180',
                              'addiu a1,s0,14500')
        self.instructions(0x48F1B4,
                          'addiu a2,zero,708', 'addiu a0,sp,24',
                          'jal 0xA5B440', 'addu a1,s1,zero',
                          'addiu a1,s1,72', 'jal 0x48E980',
                          'addiu a0,sp,24', 'lw a0,+0x130(s0)',
                          'lw t9,+0x24(a0)', 'jalr ra,t9', 'nop',
                          'lw a0,+0x130(s0)', 'lw t9,+0x18(a0)',
                          'jalr ra,t9', 'addiu a1,sp,24')
        # Resolver chooses the copied record's fill callback; it does not
        # attach an original owner epoch or reserve a private-token field.
        self.instructions(0x48EA30,
                          'lw v1,+0x4(s4)', 'sw v1,+0x2c0(s3)')
        self.assertEqual(self.elf.word(0x941670), 0x48D280)
        self.instructions(0x48D280, 'j 0x48D080', 'nop')

    def test_master_to_work_copy_and_borrow_keep_exact_dispatch_arguments(self):
        self.instructions(0x48F3B4,
                          'addiu a0,zero,16', 'jal 0x456E60',
                          'addiu a1,zero,708', 'sw v0,+0x130(s0)',
                          'addiu a0,zero,16', 'jal 0x456E60',
                          'addiu a1,zero,708', 'sw v0,+0x134(s0)')
        self.instructions(0x456C98,
                          'lui v0,0x45', 'addiu v0,v0,23968',
                          'sw v0,+0x18(s0)')
        self.instructions(0x455DA0,
                          'addu a2,a1,zero', 'j 0x455BC0',
                          'lw a1,+0xc(a0)')
        self.instructions(0x455CDC,
                          'lw a0,+0x0(a1)', 'lw a1,+0x48(sp)',
                          'addu a2,v0,zero', 'jal 0xA5B440',
                          'addu a0,v1,a0')
        self.instructions(0x48ED64,
                          'lw a0,+0x130(s0)', 'lw t9,+0x2c(a0)',
                          'jalr ra,t9', 'addiu a1,v0,-1',
                          'lw a0,+0x134(s0)', 'lw t9,+0x18(a0)',
                          'jalr ra,t9', 'addu a1,v0,zero')
        self.instructions(0x48EB28,
                          'lw a0,+0x134(s0)', 'lw t9,+0x2c(a0)',
                          'jalr ra,t9', 'addu a1,zero,zero',
                          'beq v0,zero,0x48EAE0', 'addu s1,v0,zero')
        self.instructions(0x48EC48,
                          'lw t9,+0x2c0(s1)', 'beq t9,zero,0x48EC7C',
                          'addu a0,s0,zero', 'jalr ra,t9',
                          'addu a1,s1,zero')
        self.instructions(0x48EC68,
                          'lw t9,+0x2bc(s1)', 'beq t9,zero,0x48EC7C',
                          'addu a0,s0,zero', 'jalr ra,t9',
                          'addu a1,s1,zero')

    def test_files_destination_is_newly_resolved_but_scope_is_original_job(self):
        self.instructions(0x48D0CC,
                          'lw a0,+0x138(a0)', 'addu s0,a1,zero',
                          'addiu a2,sp,32', 'addiu a1,a1,72',
                          'jal 0x4E5320', 'lw s4,+0x29c(s0)',
                          'lw s2,+0x20(sp)', 'beq s2,zero,0x48D22C',
                          'lw ra,+0x3c(sp)', 'lw s1,+0x3b68(s2)')
        self.instructions(0x48D168,
                          'lw a0,+0x1bc(s1)', 'lw t9,+0x24(a0)',
                          'jalr ra,t9', 'nop')
        self.instructions(0x48D1A0,
                          'lw v0,+0x20(sp)', 'addiu s0,s0,136',
                          'addu a2,s4,zero', 'lw a0,+0x64(v0)',
                          'addu a3,zero,zero', 'addu a1,s2,zero',
                          'jal 0x6F7CA0', 'sw s0,+0x10(sp)')
        self.instructions(0x48F89C,
                          'lw a0,+0x138(a0)', 'addiu a2,sp,32',
                          'jal 0x4E5320', 'addiu a1,a1,72',
                          'lw v0,+0x20(sp)', 'beq v0,zero,0x48F8E4',
                          'lw ra,+0x2c(sp)', 'lw a0,+0x3b68(v0)')
        self.instructions(0x48F8C4,
                          'lw a1,+0x64(v0)', 'lw a2,+0x290(s0)',
                          'lw a3,+0x294(s0)', 'sw zero,+0x10(sp)',
                          'lw t9,+0x410(a0)', 'jalr ra,t9', 'nop')

    def test_original_pointer_fields_have_no_direct_access_in_only_named_bodies(self):
        bodies = ((0x48EA80, 0x48EE08, 'worker'),
                  (0x48D080, 0x48D260, 'Files fill'),
                  (0x48F880, 0x48F8F0, 'post-fill'))
        for start, end, name in bodies:
            with self.subTest(body=name, start=f'{start:#x}', end=f'{end:#x}'):
                uses = []
                for pc in range(start, end, 4):
                    word = self.elf.word(pc)
                    if word >> 26 in MEMORY_OPS and word & 0xFFFF in (0x2B0, 0x2B4):
                        uses.append((f'{pc:#x}', decode(pc, word)))
                self.assertEqual(uses, [])
        # No statement about callees, computed/aliased addresses, other
        # entry points or global field use follows from this syntax scan.


if __name__ == '__main__':
    unittest.main()
