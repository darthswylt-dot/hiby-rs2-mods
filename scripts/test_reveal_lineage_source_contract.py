#!/usr/bin/env python3
"""Hash-gated source bounds for extended native job-lineage transport.

These checks identify space and direct-call gates in the preserved stock ELF.
They do not implement transport, prove arbitrary indirect writes/callers, or
turn an invocation ticket into native object lifetime or UI ownership.
No device, network, firmware build, or source-binary writes.
"""

import hashlib
import unittest

from test_folderfollow_reveal_static_contract import (
    SOURCE, SOURCE_SHA256, SOURCE_SIZE, Elf32, decode,
)


# Only actual memory opcodes are relevant to a direct SP-use check. The
# widths include unaligned/coprocessor accesses, conservatively as intervals.
MEMORY_WIDTHS = {
    0x20: 1, 0x21: 2, 0x22: 4, 0x23: 4, 0x24: 1, 0x25: 2, 0x26: 4,
    0x28: 1, 0x29: 2, 0x2A: 4, 0x2B: 4, 0x2E: 4,
    0x30: 4, 0x31: 4, 0x32: 4, 0x35: 8, 0x36: 8,
    0x38: 4, 0x39: 4, 0x3A: 4, 0x3D: 8, 0x3E: 8,
}


class RevealLineageSourceContractTests(unittest.TestCase):
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

    def no_direct_sp_overlap(self, start, end, low, high):
        uses = []
        for pc in range(start, end, 4):
            word = self.elf.word(pc)
            width = MEMORY_WIDTHS.get(word >> 26)
            if width is None or ((word >> 21) & 31) != 29:
                continue
            offset = word & 0xFFFF
            if offset & 0x8000:
                offset -= 0x10000
            if offset < high and low < offset + width:
                uses.append((f'{pc:#x}', decode(pc, word)))
        self.assertEqual(uses, [])

    def test_bounded_708_literal_inventory_separates_prefix_from_list_stride(self):
        # The inventory is ONLY the named worker/job framework range; other
        # unrelated objects have the same immediate elsewhere in this ELF.
        constants = [(pc, decode(pc, self.elf.word(pc)))
                     for pc in range(0x48C000, 0x48FA00, 4)
                     if (self.elf.word(pc) >> 26) in (9, 13)
                     and (self.elf.word(pc) & 0xFFFF) == 0x2C4]
        self.assertEqual(constants, [
            (0x48F1B4, 'addiu a2,zero,708'),
            (0x48F3BC, 'addiu a1,zero,708'),
            (0x48F3CC, 'addiu a1,zero,708'),
            (0x48F3EC, 'addiu a2,zero,708'),
        ])
        # The first/last constants are template-prefix copies, not strides.
        # List indexing and record copies use the element-size field L+10.
        self.instructions(0x455808,
                          'lw v1,+0x14(a0)', 'lw a2,+0x0(a0)',
                          'lw v0,+0x10(a0)', 'div a1,v1')
        self.instructions(0x455CCC,
                          'lw v0,+0x10(s6)', 'sll s3,s3,2',
                          'addu a1,a1,s3', 'word 0x70541802',
                          'lw a0,+0x0(a1)', 'lw a1,+0x48(sp)',
                          'addu a2,v0,zero', 'jal 0xA5B440',
                          'addu a0,v1,a0')

    def test_extended_local_record_tail_fits_both_original_enqueue_frames(self):
        self.assertEqual(0x18 + 0x2C4, 0x2DC)
        self.assertEqual(0x18 + 0x2C8, 0x2E0)
        self.instructions(0x48F180,
                          'addiu sp,sp,-752', 'sw s1,+0x2e8(sp)',
                          'sw s0,+0x2e4(sp)', 'sw ra,+0x2ec(sp)')
        self.instructions(0x48F360,
                          'addiu sp,sp,-760', 'sw s2,+0x2e8(sp)',
                          'lw s2,+0x308(sp)', 'sw ra,+0x2f4(sp)')
        self.instructions(0x48F37C,
                          'beq s2,zero,0x48F510', 'sw s0,+0x2e0(sp)')
        for start, end in ((0x48F180, 0x48F218), (0x48F360, 0x48F518)):
            with self.subTest(body=f'{start:#x}'):
                self.no_direct_sp_overlap(start, end, 0x2DC, 0x2E0)
        self.instructions(0x48F1B4,
                          'addiu a2,zero,708', 'addiu a0,sp,24',
                          'jal 0xA5B440', 'addu a1,s1,zero')
        self.instructions(0x48F3EC,
                          'addiu a2,zero,708', 'addiu a0,sp,24',
                          'jal 0xA5B440', 'addu a1,s3,zero')
        # A widened append reads the new tail. The unchanged prefix copy
        # does not initialize it: every admitted/unsupported path must do so.

    def test_renderer_scratch_is_above_o32_home_words_and_before_saved_state(self):
        self.instructions(0x4906F8,
                          'addiu sp,sp,-48', 'sw ra,+0x2c(sp)',
                          'sw s3,+0x24(sp)', 'sw s1,+0x1c(sp)',
                          'sw s0,+0x18(sp)')
        self.instructions(0x490750,
                          'jal 0x459340', 'addu a0,s2,zero',
                          'addu s0,v0,zero', 'addiu a0,v0,14508')
        self.no_direct_sp_overlap(0x4906F8, 0x490898, 0x14, 0x18)
        derived = [(pc, decode(pc, self.elf.word(pc)))
                   for pc in range(0x4906F8, 0x490898, 4)
                   if (self.elf.word(pc) >> 26) == 9
                   and ((self.elf.word(pc) >> 21) & 31) == 29
                   and (self.elf.word(pc) & 0xFFFF) == 0x14]
        self.assertEqual(derived, [])
        self.assertGreaterEqual(0x14, 0x10)  # Outside O32 a0..a3 home words.
        self.assertEqual(0x14 + 4, 0x18)  # Ends before saved s0.
        # This is a bounded native-SP check and ABI premise, not a claim
        # about arbitrary callees violating their argument/stack contracts.

    def test_worker_scratch_is_after_exact_descriptor_and_before_saved_state(self):
        self.instructions(0x48EA80,
                          'addiu sp,sp,-2760', 'sw s3,+0xab0(sp)')
        self.instructions(0x48EA8C, 'sw s0,+0xaa4(sp)')
        self.instructions(0x48EB50,
                          'addiu a0,sp,24', 'addu a1,s2,zero',
                          'jal 0xA5B440', 'addiu a2,zero,2696')
        self.assertEqual(0x18 + 0xA88, 0xAA0)
        self.assertEqual(0xAA0 + 4, 0xAA4)
        self.no_direct_sp_overlap(0x48EA80, 0x48EE08, 0xAA0, 0xAA4)
        # Stock's exact descriptor copy ends before AA0. The check does
        # not assert that every possible indirect/callee write is covered.

    def test_producer_receipt_scratch_and_query_wrapper_frame_gates(self):
        self.instructions(0x6ED5C0,
                          'addiu sp,sp,-2768', 'sw s7,+0xac4(sp)',
                          'sw ra,+0xacc(sp)')
        self.instructions(0x6ED604,
                          'addu a1,zero,zero', 'addiu a0,sp,32',
                          'addiu a2,zero,2696')
        self.no_direct_sp_overlap(0x6ED5C0, 0x6ED820, 0x18, 0x1C)
        derived = [(pc, decode(pc, self.elf.word(pc)))
                   for pc in range(0x6ED5C0, 0x6ED820, 4)
                   if (self.elf.word(pc) >> 26) == 9
                   and ((self.elf.word(pc) >> 21) & 31) == 29
                   and (self.elf.word(pc) & 0xFFFF) == 0x18]
        self.assertEqual(derived, [])
        self.instructions(0x6ED638, 'sw s1,+0x10(sp)')
        self.instructions(0x6ED7A8, 'sw v1,+0x10(sp)')
        self.assertLess(0x18 + 4, 0x20)  # Before local descriptor at SP+20.
        # With producer SP P, stock wrapper SP is P+AD0. Check its saved
        # return address BEFORE accessing our query wrapper's private words.
        self.instructions(0x6F7CA0, 'addiu sp,sp,-3040')
        self.instructions(0x6F7CC4, 'sw ra,+0xbdc(sp)')
        self.assertEqual(0xAD0 + 0xBDC, 0x16AC)
        self.assertEqual(0xAD0 + 0xBE0, 0x16B0)
        self.assertEqual(0x16B0 + 0x18, 0x16C8)  # Private query ticket.
        self.assertEqual(0x16B0 + 0x1C, 0x16CC)  # Private query marker.
        # Syntactic SP/address checks do not rule out arbitrary computed
        # aliases or callees violating the bounded native stack contracts.

    def test_renderer_enqueue_and_worker_fill_have_exact_original_return_gates(self):
        for call, return_pc in ((0x49080C, 0x490814), (0x490878, 0x490880)):
            self.instructions(call, 'jal 0x48F180',
                              'addiu a1,s0,14500')
            self.assertEqual(call + 8, return_pc)
        self.instructions(0x48F18C, 'sw ra,+0x2ec(sp)')
        self.assertEqual(0x2F0 + 0x14, 0x304)
        # At enqueue SP E, caller renderer scratch is E+304, not E+14.
        self.instructions(0x48EB38,
                          'beq v0,zero,0x48EAE0', 'addu s1,v0,zero',
                          'lw a0,+0x10(s0)', 'addiu s6,zero,1')
        self.instructions(0x48EC50,
                          'addu a0,s0,zero', 'jalr ra,t9',
                          'addu a1,s1,zero', 'addiu v1,zero,-1')
        self.assertEqual(0x48EC54 + 8, 0x48EC5C)
        self.instructions(0x48D080,
                          'addiu sp,sp,-64', 'sw ra,+0x3c(sp)')
        self.assertEqual(0x40 + 0xAA0, 0xAE0)
        self.instructions(0x48D1B8,
                          'jal 0x6F7CA0', 'sw s0,+0x10(sp)')
        # Before reading a worker-private frame, require the original saved
        # callback return gate. A direct/foreign Files call is not a borrow.

    def test_initial_and_shared_alternate_origins_cannot_be_treated_as_renderer(self):
        self.instructions(0x492A2C,
                          'lw a1,+0x17d0(sp)', 'jal 0x48F360',
                          'addiu a2,s0,14500')
        self.assertEqual(0x492A30 + 8, 0x492A38)
        self.instructions(0x48F36C, 'sw ra,+0x2f4(sp)')
        self.instructions(0x48F40C,
                          'lw a0,+0x130(s0)', 'lw t9,+0x18(a0)',
                          'jalr ra,t9', 'addiu a1,sp,24')
        # The shared worker's constructor has no initial job (a2=0).
        self.instructions(0x439B40,
                          'addiu a0,s0,48', 'addu a1,s0,zero',
                          'addu a2,zero,zero', 'addu a3,zero,zero',
                          'jal 0x48F360', 'sw v0,+0x10(sp)')
        # Shared Files creation later uses another enqueue origin. Neither
        # this nor 49B730 may inherit an unrelated renderer-frame ticket.
        self.instructions(0x4932A8,
                          'lw v1,+0x17d0(sp)', 'addu a2,s3,zero',
                          'jal 0x48F2A0', 'lw a0,+0x30(v1)',
                          'lw v0,+0x3ba0(s0)', 'bne v0,zero,0x4936D8',
                          'addiu a1,s0,14500')
        self.instructions(0x4936D8,
                          'lw v0,+0xd4(s0)', 'jal 0x48F180',
                          'lw a0,+0x30(v0)')
        self.instructions(0x49B72C,
                          'addiu a1,s0,14500', 'jal 0x48F180',
                          'lw a0,+0x30(v0)')
        self.assertNotIn(0x4936DC + 8, (0x490814, 0x490880))
        self.assertNotIn(0x49B730 + 8, (0x490814, 0x490880))


if __name__ == '__main__':
    unittest.main()
