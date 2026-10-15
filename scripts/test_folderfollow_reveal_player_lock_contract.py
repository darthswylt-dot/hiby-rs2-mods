#!/usr/bin/env python3
"""Stock player-lock anchors, not a common-lock or coherent-snapshot proof."""

import hashlib
import unittest

from test_folderfollow_reveal_logical_contract import executable_sections
from test_folderfollow_reveal_static_contract import (
    SOURCE, SOURCE_SHA256, SOURCE_SIZE, Elf32, decode,
)


class RevealPlayerLockContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.elf = Elf32(SOURCE)
        digest = hashlib.sha256(cls.elf.data).hexdigest()
        if digest != SOURCE_SHA256 or len(cls.elf.data) != SOURCE_SIZE:
            raise AssertionError(f'unrecognized reference: {digest}, '
                                 f'size {len(cls.elf.data)}')
        cls.calls = {}
        for _, start, end in executable_sections(cls.elf):
            for pc in range(start, end, 4):
                word = cls.elf.word(pc)
                if word >> 26 == 3:
                    target = ((pc + 4) & 0xF0000000) | ((word & 0x3FFFFFF) << 2)
                    cls.calls.setdefault(target, []).append(pc)

    def instructions(self, start, *expected):
        for index, (word, assembly) in enumerate(expected):
            pc = start + index * 4
            with self.subTest(pc=f'{pc:#x}'):
                self.assertEqual(self.elf.word(pc), word)
                self.assertEqual(decode(pc, word), assembly)

    def test_player_initializes_and_binds_a_separate_mutex(self):
        self.instructions(0x42BA28,
                          (0x0C119B58, 'jal 0x466D60'),
                          (0xAE020024, 'sw v0,+0x24(s0)'),
                          (0x0C119B58, 'jal 0x466D60'),
                          (0xAE020044, 'sw v0,+0x44(s0)'))
        self.instructions(0x42BACC,
                          (0x3C020043, 'lui v0,0x43'),
                          (0x24428B00, 'addiu v0,v0,-29952'),
                          (0xAE020048, 'sw v0,+0x48(s0)'),
                          (0x3C020043, 'lui v0,0x43'),
                          (0x24428BE0, 'addiu v0,v0,-29728'),
                          (0x24040032, 'addiu a0,zero,50'),
                          (0x0C114118, 'jal 0x450460'),
                          (0xAE02004C, 'sw v0,+0x4c(s0)'))
        for start, target in ((0x428B00, 0x466DA0), (0x428BE0, 0x466DC0)):
            self.instructions(start,
                              (0x3C0200AE, 'lui v0,0xAE'),
                              (0x8C44D3AC, 'lw a0,-0x2c54(v0)'))
            self.assertEqual(decode(start + 16, self.elf.word(start + 16)),
                             f'jal 0x{target:X}')
        self.assertEqual((0xAE << 16) - 0x2C54, 0xADD368 + 0x44)

    def test_plt_relocations_name_actual_pthread_primitives(self):
        # Resolve section links and symbol indexes; do not infer names from
        # call shape. This reference uses SHT_REL, ELF32 symbol size 16.
        elf = self.elf
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
                if address not in (0xA6FA0C, 0xA6FA28, 0xA6FA58):
                    continue
                self.assertEqual(info & 0xFF, 127)  # R_MIPS_JUMP_SLOT
                symbol = elf.u32(symbols + 16) + (info >> 8) * 16
                name = elf.data[string_offset + elf.u32(symbol):].split(b'\0', 1)[0]
                found[address] = name.decode('ascii')
        self.assertEqual(found, {
            0xA6FA0C: 'pthread_mutex_unlock',
            0xA6FA28: 'pthread_mutex_init',
            0xA6FA58: 'pthread_mutex_lock',
        })
        for pc, word in ((0xA5B834, 0x8DF9FA0C),
                         (0xA5B8A4, 0x8DF9FA28),
                         (0xA5B964, 0x8DF9FA58)):
            self.assertEqual(elf.word(pc - 4), 0x3C0F00A7)
            self.assertEqual(elf.word(pc), word)

    def test_mutex_init_has_null_attributes_and_wrappers_discard_status(self):
        self.instructions(0x466D74,
                          (0x00402021, 'addu a0,v0,zero'),
                          (0x00002821, 'addu a1,zero,zero'),
                          (0x0C296E28, 'jal 0xA5B8A0'),
                          (0x00408021, 'addu s0,v0,zero'),
                          (0x8FBF001C, 'lw ra,+0x1c(sp)'),
                          (0x02001021, 'addu v0,s0,zero'))
        for start, call, target in ((0x466DA8, 0x0C296E58, 0xA5B960),
                                    (0x466DC8, 0x0C296E0C, 0xA5B830)):
            self.instructions(start,
                              (call, f'jal 0x{target:X}'), (0, 'nop'),
                              (0x8FBF001C, 'lw ra,+0x1c(sp)'),
                              (0x00001021, 'addu v0,zero,zero'))

    def test_public_setter_brackets_copy_and_cue_with_same_callbacks(self):
        self.instructions(0x42AB30, (0x8E190048, 'lw t9,+0x48(s0)'))
        self.instructions(0x42AB4C,
                          (0x0320F809, 'jalr ra,t9'),
                          (0x00C09821, 'addu s3,a2,zero'))
        self.instructions(0x42AC0C,
                          (0x0C296D10, 'jal 0xA5B440'),
                          (0x24060A88, 'addiu a2,zero,2696'),
                          (0x1000FFE1, 'beq zero,zero,0x42AB9C'),
                          (0x8FBF002C, 'lw ra,+0x2c(sp)'))
        self.instructions(0x42AC68,
                          (0x1000FFCB, 'beq zero,zero,0x42AB98'),
                          (0xAE120524, 'sw s2,+0x524(s0)'))
        self.instructions(0x42ABA8,
                          (0x8E19004C, 'lw t9,+0x4c(s0)'),
                          (0x8FB0001C, 'lw s0,+0x1c(sp)'),
                          (0x03200008, 'jr t9'),
                          (0x27BD0030, 'addiu sp,sp,48'))

    def test_getter_copy_precedes_unlock_but_null_lock_skips_copy(self):
        self.instructions(0x42AD70, (0x8E190048, 'lw t9,+0x48(s0)'))
        self.instructions(0x42AD80,
                          (0x13200016, 'beq t9,zero,0x42ADDC'),
                          (0xAFB10020, 'sw s1,+0x20(sp)'))
        self.instructions(0x42AD90,
                          (0x0320F809, 'jalr ra,t9'),
                          (0x00C09821, 'addu s3,a2,zero'))
        self.instructions(0x42B050,
                          (0x02202021, 'addu a0,s1,zero'),
                          (0x24A5D468, 'addiu a1,a1,-11160'),
                          (0x0C296D10, 'jal 0xA5B440'),
                          (0x24060A88, 'addiu a2,zero,2696'),
                          (0x1260FF51, 'beq s3,zero,0x42ADA8'))
        self.instructions(0x42ADB4,
                          (0x8E19004C, 'lw t9,+0x4c(s0)'),
                          (0x8FB0001C, 'lw s0,+0x1c(sp)'),
                          (0x03200008, 'jr t9'),
                          (0x27BD0030, 'addiu sp,sp,48'))
        self.instructions(0x42ADF0,
                          (0x03E00008, 'jr ra'),
                          (0x27BD0030, 'addiu sp,sp,48'))

    def test_all_four_direct_same_file_callers_have_local_lock_brackets(self):
        self.assertEqual(self.calls[0x42CAC0],
                         [0x42E014, 0x42E198, 0x42E4E8, 0x42E780])
        for call in self.calls[0x42CAC0]:
            lock = call - (16 if call in (0x42E014, 0x42E198) else 20)
            self.instructions(lock,
                              (0x8E190048, 'lw t9,+0x48(s0)'),
                              (0x0320F809, 'jalr ra,t9'), (0, 'nop'))
            self.assertEqual(self.elf.word(call), 0x0C10B2B0)
            self.instructions(call + 8,
                              (0x8E19004C, 'lw t9,+0x4c(s0)'),
                              (0x0320F809, 'jalr ra,t9'), (0, 'nop'))
        for call in (0x42E4E8, 0x42E780):
            self.instructions(call - 4,
                              (0x3C040001, 'lui a0,0x1'),
                              (0x0C10B2B0, 'jal 0x42CAC0'),
                              (0x24840002, 'addiu a0,a0,2'))

    def test_general_body_does_not_itself_bracket_the_player_mutex(self):
        # Bounded syntax only: not absence of locks in arbitrary callees.
        words = [self.elf.word(pc) for pc in range(0x42CC60, 0x42DCA8, 4)]
        direct = {((word & 0x3FFFFFF) << 2) for word in words if word >> 26 == 3}
        self.assertTrue(direct.isdisjoint({0x428B00, 0x428BE0, 0x466DA0, 0x466DC0}))
        self.assertEqual([word for word in words if word >> 26 in (35, 43)
                          and (word >> 21) & 31 == 16
                          and word & 0xFFFF in (0x44, 0x48, 0x4C)], [])
        self.instructions(0x42D690,
                          (0x8E190BA0, 'lw t9,+0xba0(s0)'),
                          (0x13200004, 'beq t9,zero,0x42D6A8'), (0, 'nop'),
                          (0x8E040B98, 'lw a0,+0xb98(s0)'),
                          (0x0320F809, 'jalr ra,t9'),
                          (0x2685D468, 'addiu a1,s4,-11160'))

    def test_worker_outer_and_staging_mutexes_are_not_the_getter_mutex(self):
        self.instructions(0x42E220,
                          (0x0C119B68, 'jal 0x466DA0'),
                          (0x8E04000C, 'lw a0,+0xc(s0)'))
        self.instructions(0x42E40C,
                          (0x0C119B70, 'jal 0x466DC0'),
                          (0x8E040BB4, 'lw a0,+0xbb4(s0)'))
        self.instructions(0x42E42C,
                          (0x0C10B318, 'jal 0x42CC60'),
                          (0x03C03021, 'addu a2,fp,zero'))
        self.instructions(0x42E2BC,
                          (0x0C119B70, 'jal 0x466DC0'),
                          (0x8E04000C, 'lw a0,+0xc(s0)'))

    def test_preparation_has_three_callers_but_one_local_public_bracket(self):
        self.assertEqual(self.calls[0x429E80], [0x42C2B4, 0x42CD38, 0x42E7D8])
        self.instructions(0x42C290, (0x8E390048, 'lw t9,+0x48(s1)'))
        self.instructions(0x42C298,
                          (0x0320F809, 'jalr ra,t9'),
                          (0xAFB0001C, 'sw s0,+0x1c(sp)'))
        self.instructions(0x42C2B4,
                          (0x0C10A7A0, 'jal 0x429E80'), (0, 'nop'))
        self.instructions(0x42C2D4,
                          (0x8E39004C, 'lw t9,+0x4c(s1)'),
                          (0x8FB10020, 'lw s1,+0x20(sp)'),
                          (0x03200008, 'jr t9'),
                          (0x27BD0028, 'addiu sp,sp,40'))

    def test_full_clear_follows_the_already_returned_unlocking_helper(self):
        self.instructions(0x42DEA8,
                          (0x0C10B0A0, 'jal 0x42C280'), (0, 'nop'),
                          (0x0C10AEF8, 'jal 0x42BBE0'), (0, 'nop'),
                          (0x3C0400AE, 'lui a0,0xAE'),
                          (0x2484D468, 'addiu a0,a0,-11160'),
                          (0x00002821, 'addu a1,zero,zero'),
                          (0x24060A88, 'addiu a2,zero,2696'),
                          (0x3C0200AE, 'lui v0,0xAE'),
                          (0x0C296F18, 'jal 0xA5BC60'),
                          (0xA440E9BC, 'sh zero,-0x1644(v0)'))
        self.instructions(0x42B9DC,
                          (0x0C296F18, 'jal 0xA5BC60'),
                          (0xAFB0001C, 'sw s0,+0x1c(sp)'))


if __name__ == '__main__':
    unittest.main()
