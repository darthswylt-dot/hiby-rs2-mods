#!/usr/bin/env python3
"""Hash-gated synchronous Files/query argument association, not ownership.

These anchors bind the inspected register/stack arguments and copied config
field in one preserved executable. They do not create operation identities,
retain native objects, serialize threads, prove all query branches, validate
completed rows, or establish that a later same-name lookup is the same owner.
No job-field reservation, sidecar registry, device access or firmware writes.
"""

import hashlib
import unittest

from test_folderfollow_reveal_static_contract import (
    SOURCE, SOURCE_SHA256, SOURCE_SIZE, Elf32, decode,
)


class RevealProvenanceContractTests(unittest.TestCase):
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

    def test_explorer_loader_config_is_copied_into_the_view_loader_field(self):
        record = 0xA98610 + 2 * 0x20C
        self.assertEqual(record, 0xA98A28)
        self.assertEqual(self.elf.word(record + 0x104), 0x49E360)
        self.assertEqual(self.elf.word(record + 0x16C), 0x49CC80)
        # Lookup's s3 is its output argument, not the native view itself.
        self.instructions(0x4A03B0, 'addu s0,a0,zero', 'addu s3,a1,zero')
        self.instructions(0x4A06CC,
                          'lw v1,+0x104(v0)', 'addiu a1,v0,268',
                          'addiu a0,s3,268', 'sw v1,+0x104(s3)')
        self.instructions(0x492340,
                          'lw a0,+0x17d4(sp)', 'lw a3,+0x17d8(sp)',
                          'addiu a1,sp,5336', 'jal 0x4A03A0',
                          'addiu a2,sp,6028')
        self.assertEqual(0x14D8 + 0x104, 0x15DC)
        self.instructions(0x492400,
                          'lw v0,+0x15dc(sp)', 'lw v1,+0x17d0(sp)',
                          'addiu a1,sp,5964', 'sw v0,+0x4218(s0)')

    def test_sync_loader_preserves_panel_output_requested_and_count_output(self):
        # This reset call supplies P, &V->list, requested count and count-out.
        self.instructions(0x491288,
                          'lw a0,+0x3b68(s0)', 'sw zero,+0x68(s0)',
                          'lw t9,+0x4218(s0)', 'lw a2,+0x1d4(a0)',
                          'addiu a1,s0,100', 'jalr ra,t9',
                          'addiu a3,s0,108')
        self.instructions(0x49E360,
                          'beq a0,zero,0x49E50C', 'nop',
                          'beq a1,zero,0x49E50C', 'nop',
                          'beq a3,zero,0x49E50C', 'nop')
        self.instructions(0x49E388,
                          'addu s1,a1,zero', 'addu s0,a0,zero',
                          'addiu a1,zero,2696', 'addiu a0,zero,16',
                          'addu s4,a2,zero', 'addiu a2,zero,16')
        self.instructions(0x49E3B0,
                          'jal 0x456C40', 'addu s3,a3,zero',
                          'sw v0,+0x0(s1)', 'addu a0,s0,zero',
                          'jal 0x459340', 'addu s2,v0,zero',
                          'addu s1,v0,zero')
        # New list is written through the output before filling. The store
        # is not READY publication; s2 retains that exact list argument.
        self.assertLess(0x49E3B8, 0x49E430)

    def test_sync_normal_branch_passes_new_list_zero_offset_and_captured_scope(self):
        self.instructions(0x49E3D8,
                          'sw v1,+0xaac(sp)', 'addiu s5,s1,15832',
                          'addiu v1,sp,32', 'addu a0,s2,zero',
                          'sw v1,+0xab0(sp)', 'sw s5,+0xaa8(sp)',
                          'sw s2,+0xab4(sp)')
        self.assertEqual(15832, 0x3DD8)
        self.instructions(0x49E408,
                          'jal 0x490A80', 'addu a0,s1,zero',
                          'bne v0,zero,0x49E4C0', 'addiu v0,zero,4',
                          'jal 0x6FC0A0', 'addiu a0,sp,2728',
                          'addu a2,s4,zero', 'addu a3,zero,zero',
                          'addu a0,s2,zero', 'addu a1,zero,zero',
                          'jal 0x6F7CA0', 'sw s5,+0x10(sp)')
        # The alternate branch at E410 is deliberately not covered by this
        # normal-call association; this is not a universal loader proof.

    def test_sync_count_outputs_and_return_are_cached_total_not_producer_result(self):
        # v0 from the query is immediately overwritten with V+0x3B74.
        self.instructions(0x49E438,
                          'lw v0,+0x3b74(s1)', 'addu a0,s0,zero',
                          'sw v0,+0x0(s3)', 'lw t9,+0x400(s0)',
                          'jalr ra,t9', 'lw a1,+0x3b74(s1)')
        self.instructions(0x49E498,
                          'lw ra,+0xaec(sp)', 'lw v0,+0x3b74(s1)',
                          'lw s5,+0xae8(sp)', 'lw s4,+0xae4(sp)',
                          'lw s3,+0xae0(sp)', 'lw s2,+0xadc(sp)',
                          'lw s1,+0xad8(sp)', 'lw s0,+0xad4(sp)',
                          'jr ra', 'addiu sp,sp,2800')
        self.instructions(0x6F8BF4,
                          'lw a0,+0xba8(sp)', 'jal 0x5C30E0',
                          'addu s0,zero,zero', 'beq zero,zero,0x6F7F5C')
        # Neither count-out nor successful wrapper return replaces original
        # append results, SQL terminal 101 or ownership of the destination.

    def test_query_wrapper_captures_destination_offset_requested_mode_and_scope(self):
        self.instructions(0x6F7CA0, 'addiu sp,sp,-3040')
        self.assertEqual(0xBE0 + 0x10, 0xBF0)
        self.instructions(0x6F7CD4,
                          'lw s0,+0xbf0(sp)', 'lw t9,+0x560(v0)',
                          'sw zero,+0xba8(sp)', 'addu s5,a0,zero',
                          'addu s4,a1,zero', 'addu s6,a2,zero',
                          'jalr ra,t9', 'addu s2,a3,zero')
        # s5=destination, s4=offset, s6=requested, s2=mode; s0 is
        # caller's fifth argument (scope). Capturing pointers is not retention.

    def test_both_physical_query_calls_forward_statement_and_same_captured_arguments(self):
        for prepare, call in ((0x6F8BC4, 0x6F8BEC), (0x6F8DDC, 0x6F8E04)):
            with self.subTest(call=f'{call:#x}'):
                self.instructions(prepare,
                                  'lw a0,+0x0(v0)', 'addiu a2,zero,-1',
                                  'addiu a3,sp,2984', 'jal 0x5F5D40',
                                  'sw zero,+0x10(sp)',
                                  'lw a0,+0xba8(sp)', 'sw s2,+0x10(sp)',
                                  'sw s0,+0x14(sp)', 'addu a1,s5,zero',
                                  'addu a2,s4,zero', 'jal 0x6ED5C0',
                                  'addu a3,s6,zero')
                self.assertEqual(prepare + 10 * 4, call)
        # stmt is read from the prepare output slot. dest/offset/requested
        # remain the saved wrapper arguments; mode/scope use stack args 5/6.
        # This does not certify statement success or cover every query branch.

    def test_physical_query_selection_also_reads_current_global_context(self):
        self.instructions(0x6F7CA8,
                          'lui s1,0xBB', 'lw v0,-0x2850(s1)')
        self.assertEqual((0xBB << 16) - 0x2850, 0xBAD7B0)
        self.instructions(0x6F8B74,
                          'lw v0,-0x2850(s1)', 'addiu v1,zero,3',
                          'lw v0,+0x4fc(v0)', 'beq v0,v1,0x6F8D84')
        self.instructions(0x6F8B34,
                          'beq v1,v0,0x6F8D90', 'lw v0,-0x2850(s1)')
        self.instructions(0x6F8D90,
                          'addiu v1,zero,3', 'lw v0,+0x538(v0)',
                          'beq v0,v1,0x6F8EA0')
        # A copied scope is not the wrapper's entire query input. This pins
        # only the current-global selectors, not a complete sorting protocol,
        # concurrent writer coverage or the lifetime of the pointed context.

    def test_producer_frame_binds_statement_destination_offset_requested_and_mode(self):
        self.instructions(0x6ED5C0, 'addiu sp,sp,-2768')
        self.assertEqual(0xAD0 + 0x08, 0xAD8)  # Saved incoming a2.
        self.assertEqual(0xAD0 + 0x10, 0xAE0)  # Fifth incoming argument.
        self.assertEqual(0xAD0 + 0x14, 0xAE4)  # Sixth incoming argument.
        self.instructions(0x6ED5EC,
                          'sw a2,+0xad8(sp)', 'beq a1,zero,0x6ED800',
                          'lw s7,+0xae0(sp)', 'beq a0,zero,0x6ED800',
                          'addu s6,a1,zero', 'addu s0,a0,zero',
                          'addu a1,zero,zero', 'addiu a0,sp,32',
                          'addiu a2,zero,2696', 'lui s2,0x9A',
                          'lui s4,0x9A', 'addu s1,a3,zero')
        self.instructions(0x6ED66C,
                          'addu a0,s0,zero', 'addu a2,s1,zero',
                          'jal 0x5A2D00', 'addiu a1,zero,1')
        self.instructions(0x6ED694,
                          'lw a2,+0xad8(sp)', 'addu a0,s0,zero',
                          'jal 0x5A2D00', 'addiu a1,zero,2')
        self.instructions(0x6ED6BC,
                          'sltiu s4,s7,1', 'bne v0,s2,0x6ED704',
                          'addiu s5,zero,15', 'beq s7,s3,0x6ED758',
                          'addiu a0,sp,32', 'beq s4,zero,0x6ED738',
                          'nop', 'jal 0x6E8D80', 'addu a1,s0,zero',
                          'lw t9,+0x18(s6)', 'addu a0,s6,zero',
                          'jalr ra,t9', 'addiu a1,sp,32')
        # Mode zero appends a descriptor decoded from stmt into the preserved
        # destination. Scope's explicit read below belongs to mode ONE, not
        # independent parent-folder validation for the mode-zero rows.
        self.instructions(0x6ED76C,
                          'lw v0,+0xae4(sp)', 'beq v0,zero,0x6ED788',
                          'addu a1,v0,zero')


if __name__ == '__main__':
    unittest.main()
