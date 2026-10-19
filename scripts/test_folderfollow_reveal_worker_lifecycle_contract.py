#!/usr/bin/env python3
"""Hash-gated worker close/start limits; not a runtime race reproduction.

The shared cancel and private wake-lifetime counterexamples are conditional
source paths. They must not be relabelled as observed ordinary Files failures.
No firmware, device, network, or source-binary writes are performed.
"""

import hashlib
import unittest

from test_folderfollow_reveal_static_contract import (
    SOURCE, SOURCE_SHA256, SOURCE_SIZE, Elf32, decode,
)


class RevealWorkerLifecycleContractTests(unittest.TestCase):
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
            with self.subTest(pc=f'{pc:#x}', assembly=assembly):
                self.assertEqual(decode(pc, self.elf.word(pc)), assembly)

    def test_master_and_work_lists_contain_separate_copied_records(self):
        self.instructions(0x48F3B4,
                          'addiu a0,zero,16', 'jal 0x456E60',
                          'addiu a1,zero,708', 'sw v0,+0x130(s0)',
                          'addiu a0,zero,16', 'jal 0x456E60',
                          'addiu a1,zero,708', 'sw v0,+0x134(s0)')
        self.instructions(0x48ED64,
                          'lw a0,+0x130(s0)', 'lw t9,+0x2c(a0)',
                          'jalr ra,t9', 'addiu a1,v0,-1',
                          'lw a0,+0x134(s0)', 'lw t9,+0x18(a0)',
                          'jalr ra,t9', 'addu a1,v0,zero')
        self.instructions(0x456C98,
                          'lui v0,0x45', 'addiu v0,v0,23968',
                          'sw v0,+0x18(s0)')
        self.instructions(0x455DA0,
                          'addu a2,a1,zero', 'j 0x455BC0',
                          'lw a1,+0xc(a0)')
        # Insert copies the caller's record, not its pointer. The element
        # size is initialized at list+10 by 456C90 from the second argument.
        self.instructions(0x456C90, 'sw s3,+0x10(v0)')
        self.instructions(0x455CCC,
                          'lw v0,+0x10(s6)', 'sll s3,s3,2',
                          'addu a1,a1,s3', 'word 0x70541802',
                          'lw a0,+0x0(a1)', 'lw a1,+0x48(sp)',
                          'addu a2,v0,zero', 'jal 0xA5B440',
                          'addu a0,v1,a0')

    def test_worker_borrows_work_record_before_acquiring_callback_mutex(self):
        self.instructions(0x48EB28,
                          'lw a0,+0x134(s0)', 'lw t9,+0x2c(a0)',
                          'jalr ra,t9', 'addu a1,zero,zero',
                          'beq v0,zero,0x48EAE0', 'addu s1,v0,zero',
                          'lw a0,+0x10(s0)', 'addiu s6,zero,1',
                          'jal 0x466DA0', 'sw s6,+0x12c(s0)')
        self.instructions(0x456CC8,
                          'lui v0,0x45', 'addiu v0,v0,22496',
                          'sw v0,+0x2c(s0)')
        self.instructions(0x455828,
                          'mfhi a1', 'lw a0,+0x0(v1)',
                          'word 0x70A21802', 'jr ra', 'addu v0,v1,a0')

    def test_shared_cancel_targets_master_scope_then_only_clears_work_count(self):
        self.instructions(0x48EE58,
                          'addu s7,a0,zero', 'lw a0,+0x10(a0)',
                          'addu s3,a1,zero', 'jal 0x466DA0',
                          'addu s0,zero,zero')
        self.instructions(0x48EECC,
                          'lw a0,+0x130(s7)', 'lw t9,+0x2c(a0)',
                          'jalr ra,t9', 'addu a1,s0,zero',
                          'addiu a0,v0,136', 'addu a1,s3,zero',
                          'jal 0x41FC80', 'addu s1,v0,zero',
                          'bne v0,zero,0x48EEC4', 'addiu s0,s0,1',
                          'addiu s0,s0,-1', 'sw s6,+0x0(s1)',
                          'sw zero,+0x2c0(s1)', 'sw zero,+0x2bc(s1)',
                          'sw zero,+0x4(s1)', 'lw a0,+0x130(s7)',
                          'lw t9,+0x20(a0)', 'jalr ra,t9',
                          'addu a1,s0,zero')
        self.instructions(0x48EF24,
                          'lw a0,+0x134(s7)', 'lw t9,+0x24(a0)',
                          'jalr ra,t9', 'nop', 'jal 0x466DC0',
                          'lw a0,+0x10(s7)')
        self.instructions(0x456CD4,
                          'lui v0,0x45', 'addiu v0,v0,22464',
                          'sw v0,+0x24(s0)')
        # Complete clear body: retained bytes are not wiped or freed.
        self.instructions(0x4557C0,
                          'beq a0,zero,0x4557D4', 'nop',
                          'sw zero,+0xc(a0)', 'jr ra',
                          'addu v0,zero,zero', 'jr ra',
                          'addiu v0,zero,-6')

    def test_borrowed_copy_can_reach_fill_without_membership_revalidation(self):
        # T+128!=0 or a null prefill reaches EC34 directly. The first
        # brief mutex bracket only copies the player descriptor to stack.
        self.instructions(0x48EB50,
                          'addiu a0,sp,24', 'addu a1,s2,zero',
                          'jal 0xA5B440', 'addiu a2,zero,2696',
                          'jal 0x466DC0', 'lw a0,+0x10(s0)')
        self.instructions(0x48EB8C,
                          'lw v0,+0x128(s0)', 'bne v0,zero,0x48EC34',
                          'addiu s7,zero,1', 'sw s7,+0x128(s0)',
                          'sw zero,+0xbcc(s0)', 'lw v0,+0x2b8(s1)',
                          'beq v0,zero,0x48EC34', 'nop')
        self.instructions(0x48EC34,
                          'jal 0x466DA0', 'lw a0,+0x10(s0)',
                          'lw v0,+0x4(s1)', 'bne v0,zero,0x48EC84',
                          'nop', 'lw t9,+0x2c0(s1)',
                          'beq t9,zero,0x48EC7C', 'addu a0,s0,zero',
                          'jalr ra,t9', 'addu a1,s1,zero',
                          'addiu v1,zero,-1', 'beq v0,v1,0x48EDCC',
                          'addiu a0,s3,5200', 'lw t9,+0x2bc(s1)',
                          'beq t9,zero,0x48EC7C', 'addu a0,s0,zero',
                          'jalr ra,t9', 'addu a1,s1,zero')

    def test_optional_prefill_and_renderer_signal_are_outside_callback_bracket(self):
        self.instructions(0x48EBB4,
                          'lw t9,+0x2b8(s1)', 'addu a0,s0,zero',
                          'jalr ra,t9', 'addu a1,s1,zero')
        self.instructions(0x48EC7C,
                          'addiu v0,zero,2', 'sw v0,+0x4(s1)',
                          'jal 0x466DC0', 'lw a0,+0x10(s0)',
                          'lw v0,+0x138(s0)', 'jal 0x466D00',
                          'lw a0,+0x144(v0)')

    def test_private_normal_start_waits_for_worker_completion_lock(self):
        self.instructions(0x48F454, 'lw a0,+0x8(s0)')
        self.instructions(0x48F4A4,
                          'addiu v0,v0,-5792', 'sw zero,+0x18(s0)',
                          'jal 0x466DA0', 'sw v0,+0xbdc(s0)',
                          'lw a2,+0x18(s0)', 'lui a0,0x49',
                          'addu a1,s0,zero', 'addiu a2,a2,12',
                          'addiu a3,zero,128', 'jal 0x466BA0',
                          'addiu a0,a0,-5504', 'lw a0,+0x8(s0)',
                          'jal 0x466DA0', 'sw v0,+0x0(s0)',
                          'jal 0x466DC0', 'lw a0,+0x8(s0)',
                          'jal 0x466DE0', 'lw a0,+0x8(s0)')
        self.instructions(0x48EAC0,
                          'lw a0,+0xc(s0)', 'jal 0x466DA0',
                          'lui s4,0x94', 'lw a0,+0x8(s0)',
                          'addiu s2,s0,320', 'addiu s5,s5,5232',
                          'jal 0x466DC0', 'addiu s4,s4,5216')
        self.instructions(0x48ECD4,
                          'jal 0x466DC0', 'lw a0,+0xc(s0)',
                          'lw ra,+0xac4(sp)', 'lw s7,+0xac0(sp)',
                          'lw s6,+0xabc(sp)', 'lw s5,+0xab8(sp)',
                          'lw s4,+0xab4(sp)', 'lw s3,+0xab0(sp)',
                          'lw s2,+0xaac(sp)', 'lw s1,+0xaa8(sp)',
                          'lw s0,+0xaa4(sp)', 'jr ra', 'addiu sp,sp,2760')
        # Constructor locks +8; another thread unlocks it. This test pins
        # the stock sequence, not portable mutex ownership semantics.

    def test_zero_return_does_not_certify_worker_start(self):
        self.instructions(0x48F3D4,
                          'beq s3,zero,0x48F41C', 'sw s0,+0x0(s1)')
        self.instructions(0x48F454,
                          'lw a0,+0x8(s0)', 'beq a0,zero,0x48F46C',
                          'sw v0,+0x14(s0)', 'lw v0,+0xc(s0)',
                          'bne v0,zero,0x48F4A4', 'lui v0,0x49',
                          'lui a0,0x94', 'lui a1,0x92',
                          'addiu a0,a0,5248', 'jal 0x467160',
                          'addiu a1,a1,4100', 'addu v0,zero,zero')
        self.instructions(0x48F49C, 'jr ra', 'addiu sp,sp,760')
        self.instructions(0x492A30,
                          'jal 0x48F360', 'addiu a2,s0,14500',
                          'lw a0,+0x17d0(sp)', 'jal 0x4E5280',
                          'addu a1,s0,zero')
        self.instructions(0x466BFC,
                          'jal 0xA5B9B0', 'addiu a0,sp,60',
                          'jal 0xA5B2C0', 'addiu a0,sp,24',
                          'lw ra,+0x4c(sp)', 'lw v0,+0x3c(sp)')

    def test_private_stop_releases_wake_object_before_completion_wait(self):
        self.instructions(0x48F538,
                          'lw a0,+0x14(a0)', 'addiu v0,zero,1',
                          'sw v0,+0x4(s0)', 'jal 0x466D00', 'nop',
                          'jal 0x466D20', 'lw a0,+0x14(s0)',
                          'jal 0x466DA0', 'lw a0,+0xc(s0)')
        self.instructions(0x466D2C,
                          'jal 0xA5BBA0', 'addu s0,a0,zero',
                          'beq s0,zero,0x466D48', 'lw ra,+0x1c(sp)',
                          'jal 0x466A80', 'addu a0,s0,zero')

    def test_stop_check_and_wake_wait_are_separate_operations(self):
        # Even a Files job with no progression/prefill can take this path.
        # Stop can destroy T+14 after the first read and before sem_wait;
        # the second stop read is after the semaphore operation.
        self.instructions(0x48EAE0,
                          'lw v0,+0x4(s0)', 'bne v0,zero,0x48ECD4',
                          'nop', 'lw a0,+0x14(s0)', 'jal 0x466CE0',
                          'addiu a1,zero,-1', 'lw v0,+0x4(s0)',
                          'bne v0,zero,0x48ECD4', 'nop')

    def test_progression_can_post_wake_before_reading_stop_flag(self):
        # Conditional path only: nonzero total and current+request<total.
        # Ordinary Files applicability needs the separate scope audit.
        self.instructions(0x48EC98,
                          'lw v0,+0x2a8(s1)', 'beq v0,zero,0x48ED94',
                          'nop', 'lw a0,+0x290(s1)', 'lw v1,+0x2a4(s1)',
                          'addu v1,a0,v1', 'slt v0,v1,v0',
                          'beq v0,zero,0x48ED20', 'addiu a0,zero,4',
                          'lw a0,+0x14(s0)', 'jal 0x466D00',
                          'sw zero,+0x128(s0)', 'lw v0,+0x4(s0)',
                          'beq v0,zero,0x48EAEC', 'nop',
                          'jal 0x466DC0', 'lw a0,+0xc(s0)')

    def test_semaphore_and_name_copy_imports_resolve_through_relocations(self):
        elf = self.elf
        wanted = {0xA6FBCC: 'sem_post', 0xA6FAE8: 'sem_destroy',
                  0xA6FAB8: 'sem_wait', 0xA6FB38: 'sem_init',
                  0xA6FBB8: 'strcpy'}
        start, size, count = elf.u32(0x20), elf.u16(0x2E), elf.u16(0x30)
        found = {}
        for index in range(count):
            rel = start + size * index
            if elf.u32(rel + 4) != 9:  # SHT_REL
                continue
            symbols = start + size * elf.u32(rel + 24)
            self.assertEqual(elf.u32(symbols + 4), 11)  # SHT_DYNSYM
            self.assertEqual(elf.u32(symbols + 36), 16)
            strings = start + size * elf.u32(symbols + 24)
            string_offset = elf.u32(strings + 16)
            offset, length = elf.u32(rel + 16), elf.u32(rel + 20)
            for item in range(offset, offset + length, 8):
                address, info = elf.u32(item), elf.u32(item + 4)
                if address not in wanted:
                    continue
                self.assertEqual(info & 0xFF, 127)  # R_MIPS_JUMP_SLOT
                symbol = elf.u32(symbols + 16) + (info >> 8) * 16
                name = elf.data[string_offset + elf.u32(symbol):].split(b'\0', 1)[0]
                found[address] = name.decode('ascii')
        self.assertEqual(found, wanted)
        for plt, got in ((0xA5BF30, 0xA6FBCC), (0xA5BBA0, 0xA6FAE8),
                         (0xA5BAE0, 0xA6FAB8), (0xA5BCE0, 0xA6FB38),
                         (0xA5BEE0, 0xA6FBB8)):
            self.assertEqual(elf.word(plt), 0x3C0F00A7)
            self.assertEqual(elf.word(plt + 4), 0x8DF90000 | (got & 0xFFFF))
        self.instructions(0x466D08, 'jal 0xA5BF30')
        self.instructions(0x466CE8, 'jal 0xA5BAE0')

    def test_files_initial_prefill_is_null_not_the_adjacent_widget_callback(self):
        record = 0xA98610 + 2 * 0x20C
        self.assertEqual(record, 0xA98A28)
        self.assertEqual(self.elf.word(record + 0x16C), 0x49CC80)
        self.assertEqual(self.elf.word(record + 0x174), 0)
        self.instructions(0x4A06F4,
                          'lw v0,+0x174(v0)', 'jal 0xA5B440',
                          'sw v0,+0x174(s3)')
        self.assertEqual(0x14D8 + 0x174, 0x164C)
        self.instructions(0x49242C,
                          'lw v0,+0x164c(sp)', 'sw v0,+0x4228(s0)')
        self.instructions(0x492988, 'lw a0,+0x4228(s0)')
        self.instructions(0x4929B4, 'sw a0,+0x3b5c(s0)')
        self.assertEqual(0x38A4 + 0x2B8, 0x3B5C)
        # The whole view, including progression fields +3B48/+3B4C,
        # starts zeroed. This is not an all-alias writer-coverage proof.
        self.instructions(0x491F4C,
                          'addu a0,v0,zero', 'addu a1,zero,zero',
                          'jal 0xA5BC60', 'addiu a2,zero,16952')

    def test_runtime_resource_mode_uses_different_create_and_close_predicates(self):
        self.instructions(0x492454,
                          'lw v1,+0x17d0(sp)', 'addiu a2,s2,2228',
                          'addiu a1,sp,5964', 'jal 0x485DE0',
                          'lw a0,+0x24(v1)', 'beq v0,zero,0x492ED0',
                          'addu s2,v0,zero', 'jal 0x424600',
                          'sw v0,+0xd0(s0)')
        self.instructions(0x485FD4,
                          'beq zero,zero,0x486008', 'lw v0,+0xd0(v0)')
        self.instructions(0x492A08,
                          'lw a1,+0xd0(s0)', 'sh zero,+0x3b32(s0)',
                          'addiu v0,zero,1', 'lw v1,+0x74(a1)',
                          'beq v1,v0,0x4932A8', 'addiu a0,s0,15236')
        self.instructions(0x4907D8,
                          'lw v0,+0xd0(s0)', 'lw v1,+0x74(v0)',
                          'addiu v0,zero,1', 'beq v1,v0,0x490838')
        self.instructions(0x493BE4,
                          'lw v0,+0xd0(s0)', 'lw v0,+0x74(v0)',
                          'bne v0,zero,0x493CC8', 'addu a1,s2,zero')
        self.instructions(0x459820,
                          'beq a0,zero,0x45982C', 'nop',
                          'sw a1,+0x74(a0)', 'jr ra', 'nop')
        # This pins mutable resource state, not its value at a live lookup
        # or applicability of other views' setter callers to Files.

    def test_viewgroup_factory_zeros_mode_outside_the_prototype_header(self):
        prototype = 0x927F6C
        self.assertEqual(self.elf.word(prototype), 0x927EF8)
        name = self.elf.va_to_off(0x927EF8)
        self.assertEqual(self.elf.data[name:name + 13], b'lg_viewgroup\0')
        self.assertEqual(self.elf.word(prototype + 8), 5)
        self.assertEqual(self.elf.word(prototype + 0xC), 0x178)
        self.assertEqual(self.elf.word(prototype + 0x18), 0x459E00)
        self.instructions(0x45A6A0,
                          'lui a0,0x92', 'addiu sp,sp,-32',
                          'sw ra,+0x1c(sp)', 'jal 0x43D2C0',
                          'addiu a0,a0,32620')
        self.instructions(0x43D41C,
                          'lw s1,+0x0(v0)', 'jal 0x4669E0',
                          'lw a0,+0xc(s1)', 'beq v0,zero,0x43D46C',
                          'addu s0,v0,zero', 'lw a2,+0xc(s1)',
                          'addu a0,v0,zero', 'jal 0xA5BC60',
                          'addu a1,zero,zero', 'addu a0,s0,zero',
                          'addu a1,s1,zero', 'jal 0xA5B440',
                          'addiu a2,zero,32', 'lw t9,+0x18(s0)',
                          'beq t9,zero,0x43D46C', 'nop',
                          'jalr ra,t9', 'addu a0,s0,zero')
        self.assertLess(0x20, 0x74)
        self.assertLess(0x74 + 4, 0x178)

    def test_viewgroup_constructor_leaves_factory_mode_zero(self):
        # Bounded constructor stores/calls only, not all runtime writers.
        stores, calls = [], []
        for pc in range(0x459E00, 0x459E7C, 4):
            word = self.elf.word(pc)
            op, base = word >> 26, (word >> 21) & 31
            if op in (40, 41, 42, 43, 46) and base != 29:
                stores.append((pc, base, word & 0xFFFF))
            if op == 3 or (op == 0 and word & 63 == 9):
                calls.append((pc, decode(pc, word)))
        self.assertEqual(stores, [
            (0x459E18, 16, 0x12C), (0x459E24, 16, 0x134),
            (0x459E30, 16, 0x13C), (0x459E3C, 16, 0x138),
            (0x459E54, 16, 0x144), (0x459E58, 16, 0xFC),
        ])
        self.assertEqual(calls, [(0x459E50, 'jal 0x456E60'),
                                 (0x459E60, 'jal 0x4597C0')])
        self.instructions(0x459E5C,
                          'addu a0,s0,zero', 'jal 0x4597C0',
                          'addiu a1,zero,1')
        self.instructions(0x4597C0,
                          'beq a0,zero,0x4597D4', 'andi a1,a1,0xFF',
                          'sw a1,+0x114(a0)', 'jr ra',
                          'addu v0,zero,zero', 'jr ra',
                          'addiu v0,zero,-1')

    def test_viewgroup_parser_registers_the_created_resource_pointer(self):
        self.instructions(0x488DC4,
                          'ori s2,zero,0xABB0', 'bne v1,zero,0x489078',
                          'addu s2,s0,s2')
        self.instructions(0x488ED8,
                          'lui a1,0x92', 'addiu a0,zero,5',
                          'addiu a1,a1,32504', 'jal 0x43D400',
                          'lui s7,0x1', 'addu s7,s0,s7',
                          'beq v0,zero,0x489B80', 'sw v0,-0x5380(s7)',
                          'ori fp,zero,0xABB0', 'addu fp,s0,fp')
        self.assertEqual(0x10000 - 0x5380, 0xABB0 + 0xD0)
        # Name copy has no explicit size argument. The inferred 0x40-byte
        # source field is not a termination certificate for arbitrary input;
        # factory zero alone must not certify the full parser output.
        self.instructions(0x488F00,
                          'addiu a0,v0,32', 'addiu a1,fp,228',
                          'jal 0xA5BEE0', 'lui s6,0x92')
        self.instructions(0x489090,
                          'lui a0,0x92', 'addiu a2,a0,2228',
                          'addu a1,s2,zero', 'jal 0x480680',
                          'addu a0,s0,zero')
        self.instructions(0x480964,
                          'addu a0,s1,zero', 'addu a1,s2,zero',
                          'jal 0xA5B440', 'addiu a2,zero,4904')
        # This copies a node containing W, not W+74 from external bytes;
        # it does not certify prior string copies into W.
        # Later lookup returning node+D0 is pinned by the mode-scope test.

    def test_inspected_parser_attribute_helpers_do_not_write_worker_mode(self):
        helpers = (
            (0x488FA4, 0x459420, 0x459468, {0xF4, 0x118}),
            (0x48B1AC, 0x4593A0, 0x4593C0, {0xEC}),
            (0x48B190, 0x4593E0, 0x459400, {0xF0}),
            (0x488FD4, 0x4596E0, 0x459740,
             {0x90, 0x94, 0x98, 0x9C, 0xA0, 0xA4, 0xA8, 0xAC}),
            (0x488FE4, 0x459660, 0x4596E0, {0x80, 0x84, 0x88, 0x8C, 0x10C}),
            (0x488FF0, 0x459620, 0x459660, {0xB0, 0xB4, 0xB8, 0xBC}),
            (0x48906C, 0x459780, 0x4597B0, {0x10C, 0x110}),
        )
        for call, start, end, fields in helpers:
            with self.subTest(helper=f'{start:#x}'):
                self.instructions(call, f'jal 0x{start:X}')
                stores, calls = set(), []
                for pc in range(start, end, 4):
                    word = self.elf.word(pc)
                    op, base = word >> 26, (word >> 21) & 31
                    if op in (40, 41, 42, 43, 46) and base != 29:
                        self.assertEqual(base, 4)  # resource argument a0
                        stores.add(word & 0xFFFF)
                    if op == 3 or (op == 0 and word & 63 == 9):
                        calls.append((pc, decode(pc, word)))
                self.assertEqual(stores, fields)
                self.assertNotIn(0x74, stores)
                # Only image setter's failure path logs a diagnostic.
                self.assertEqual(calls, [(0x459458, 'jal 0x467160')]
                                 if start == 0x459420 else [])
        # Other parser operations (notably names/reuse) are not certified
        # by a census of these helpers. This is a bounded field-write check.

    def test_known_mode_setter_calls_are_registered_to_other_view_loaders(self):
        expected = (
            (22, 0x4B1E20, 'vg_listview_tidal_item', 0x4B1EF4),
            (56, 0x4B5BC0, 'vg_listview_recent_add', 0x4B5C14),
            (53, 0x515760, 'vg_listview_tidal_play_info', 0x5157DC),
            (61, 0x530440, 'vg_listview_qobuz_item', 0x530538),
            (68, 0x539020, 'vg_listview_sony_item', 0x5390C4),
        )
        calls = []
        for start, end in self.elf.executable_ranges():
            for pc in range(start, end & ~3, 4):
                if self.elf.word(pc) == 0x0C116608:  # direct jal 459820
                    calls.append(pc)
        self.assertEqual(calls, sorted(item[3] for item in expected))
        for index, loader, name, call in expected:
            record = 0xA98610 + index * 0x20C
            with self.subTest(name=name):
                self.assertEqual(self.elf.word(record + 0x104), loader)
                name_offset = self.elf.va_to_off(record + 0x10C)
                self.assertEqual(self.elf.data[name_offset:].split(b'\0', 1)[0],
                                 name.encode('ascii'))
                if call == 0x4B5C14:
                    self.instructions(0x4B5C0C,
                                      'lw a0,+0xd0(v0)', 'addiu a1,zero,1',
                                      'jal 0x459820', 'addu s3,v0,zero')
                else:
                    self.instructions(call - 4, 'lw a0,+0xd0(s2)',
                                      'jal 0x459820', 'addiu a1,zero,1')
        self.assertEqual(self.elf.word(0xA98A28 + 0x104), 0x49E360)
        # Ordinary explorer's registered initial loader has no direct mode
        # setter or +74 store. Other aliases/indirect calls are not excluded.
        for pc in range(0x49E360, 0x49E514, 4):
            word = self.elf.word(pc)
            with self.subTest(explorer_pc=f'{pc:#x}'):
                self.assertNotEqual(word, 0x0C116608)
                self.assertFalse(word >> 26 in (40, 41, 42, 43, 46)
                                 and word & 0xFFFF == 0x74)


if __name__ == '__main__':
    unittest.main()
