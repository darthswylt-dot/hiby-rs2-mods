#!/usr/bin/env python3
"""Exact-reference pointer consumers; deliberately not all-alias/writer proof."""

import hashlib
import unittest

from mips_static_trace import locally_resolved_call_constant
from test_folderfollow_reveal_static_contract import (
    SOURCE, SOURCE_SHA256, SOURCE_SIZE, Elf32, decode,
)


class RevealPointerContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.elf = Elf32(SOURCE)
        digest = hashlib.sha256(cls.elf.data).hexdigest()
        if digest != SOURCE_SHA256 or len(cls.elf.data) != SOURCE_SIZE:
            raise AssertionError(f'unrecognized reference: {digest}, '
                                 f'{len(cls.elf.data)} bytes')
        cls.getter_calls = [
            pc for start, end in cls.elf.executable_ranges()
            for pc in range(start, end & ~3, 4)
            if cls.elf.word(pc) == 0x0C10AB58
        ]

    def words(self, start, *expected):
        for index, word in enumerate(expected):
            pc = start + index * 4
            with self.subTest(pc=hex(pc), assembly=decode(pc, word)):
                self.assertEqual(self.elf.word(pc), word)

    def test_direct_getter_inventory_and_nonlocal_property_arguments(self):
        self.assertEqual(len(self.getter_calls), 216)
        values = {pc: locally_resolved_call_constant(self.elf, pc, 4)[0]
                  for pc in self.getter_calls}
        self.assertEqual([pc for pc, value in values.items() if value is None],
                         [0x446A6C, 0x446AA0, 0x4ED678])
        self.assertEqual([pc for pc, value in values.items() if value == 24], [
            0x41BD54, 0x42F9E8, 0x444628, 0x446C9C, 0x447908, 0x475938,
            0x490EB8, 0x496268, 0x4977D8, 0x4A75C8, 0x4AD0D8, 0x4AEDB4,
            0x4B4794, 0x4E8598, 0x4E8EE8, 0x4E94E4, 0x4E9674, 0x4E96E8,
            0x4E9A20, 0x4E9C64, 0x4E9EE8, 0x4EA11C, 0x4EC534, 0x4EC97C,
            0x4ECA90, 0x4ED4D0, 0x4ED83C, 0x4ED87C, 0x4EDA00, 0x4EE264,
            0x5228CC, 0x522B44, 0x522BAC, 0x91FA30,
        ])
        self.words(0x4469EC, 0x1440002B, 0x2404001C)
        self.words(0x446A00, 0x14400019, 0x2404001C)
        self.words(0x4ED634, 0x1440000F, 0x24040018)
        self.words(0x4ED674, 0x27A50020, 0x0C10AB58, 0x00003021)

    def test_thirteen_pointer_out_setups_include_nonlocal_delay_slots(self):
        setups = {
            0x41BD58: 0x27A60428, 0x444620: 0x27A60220,
            0x475934: 0x27A6001C, 0x4977DC: 0x27A60D40,
            0x4B4798: 0x27A60230, 0x4E8EEC: 0x02003021,
            0x4E9C68: 0x27A61B00, 0x4E9EEC: 0x27A61B00,
            0x4ED4C8: 0x27A60228, 0x4ED7A4: 0x27A60244,
            0x4ED7BC: 0x27A60244, 0x4EDA04: 0x27A60778,
            0x522BB0: 0x27A60EC8,
        }
        for pc, word in setups.items():
            self.words(pc, word)
        self.words(0x4E8EB4, 0x27B00638)  # s0 = pointer-out stack slot
        self.words(0x4ED7A0, 0x14400024, 0x27A60244)
        self.words(0x4ED7B8, 0x1440002E, 0x27A60244)

    def test_getter_returns_borrowed_pointer_after_unlock_tail(self):
        self.assertEqual(self.elf.word(0x9212B8 + 24 * 4), 0x42B048)
        self.words(0x42B048, 0x12200005, 0x3C0500AE, 0x02202021,
                   0x24A5D468, 0x0C296D10, 0x24060A88, 0x1260FF51,
                   0x8FBF002C, 0x3C0200AE, 0x2442D468, 0x1000FF4C,
                   0xAE620000)
        self.words(0x42ADB4, 0x8E19004C, 0x8FB0001C, 0x03200008,
                   0x27BD0030)

    def test_path_cue_consumer_compares_and_loads_without_store(self):
        self.words(0x444654, 0x8FB30220, 0x26250004, 0x0C107F20,
                   0x26640004, 0x14400005, 0x02202021, 0x8E630424,
                   0x8E220424, 0x10620018)
        self.words(0x41FC80, 0x94820000, 0x94A30000, 0x24840002,
                   0x00433023, 0x14C00007, 0x24A50002)

    def test_metadata_scalar_consumers_read_not_write_descriptor(self):
        for pc, word in {
            0x475970: 0x8C440A58, 0x4977F8: 0x94640004,
            0x497848: 0x8C640000, 0x4B47BC: 0x8C430414,
            0x4B4A7C: 0x8C420A80, 0x4B4AF4: 0x8C420A80,
            0x4EDB60: 0x8C460A5C,
        }.items():
            self.words(pc, word)

    def test_path_terminator_write_is_to_the_local_copy(self):
        self.words(0x4E8F7C, 0x8FB60638)
        self.words(0x4E8FA0, 0x26D40004, 0xAFB70630, 0x26D6020C)
        self.words(0x4E8FBC, 0x24060104, 0x02202021, 0x0C107EE0,
                   0x02802821, 0x02202021, 0x2405002E, 0x0C107FA0,
                   0xA7A00426, 0x10400007, 0x02202021, 0x0C107F80,
                   0xA4400000)
        self.words(0x4E8F78, 0x27B10220)  # s1 = stack copy, not D
        self.words(0x41FB80, 0x94A30000, 0x00801021, 0x10600008,
                   0x00803821, 0x10C00006, 0x24A50002, 0xA4E30000)

    def test_command9_forwards_descriptor_as_copy_source(self):
        for pc, load in ((0x4ED4D8, 0x8FA50228),
                         (0x4ED844, 0x8FA50244),
                         (0x4ED884, 0x8FA50244)):
            self.words(pc, load, 0x0C1093D8, 0x24040009)
        self.words(0x424F80, 0xAFA50844)
        self.words(0x424FA8, 0x27A30844)
        self.assertEqual(self.elf.word(0x920834 + 9 * 4), 0x425128)
        self.words(0x425128, 0x8FA20818, 0x8C450000, 0x24420004,
                   0x10A0FFB9, 0xAFA20818, 0x8E24002C, 0x0C296D10,
                   0x24060A88, 0x1000FFB4, 0x00000000)

    def test_lookup_does_not_forward_apparent_incoming_a1(self):
        self.words(0x442ED8, 0x00808821, 0x0C119B68, 0x8E040020,
                   0x8E040018, 0x8C99002C, 0x0320F809, 0x02202821)
        # Incoming a0 (lookup index), not incoming a1 (apparent D), is saved
        # and passed to the indirect lookup. No transitive target claim here.

    def test_metadata_interior_pointer_still_escapes_to_indirect_ui_method(self):
        self.words(0x522FBC, 0x8FA50EC8)
        self.words(0x522FF4, 0x8E790190, 0x02602021, 0x0320F809,
                   0x24A5052C)
        self.words(0x523088, 0x8FA50EC8)
        self.words(0x5230BC, 0x8E790190, 0x02602021, 0x0320F809,
                   0x24A5020C)

    def test_player_callback_target_is_unresolved_not_proven_null(self):
        self.words(0x42CBFC, 0x8E390BA0, 0x13200004, 0, 0x8E240B98,
                   0x0320F809, 0x2685D468)
        self.words(0x42D690, 0x8E190BA0, 0x13200004, 0, 0x8E040B98,
                   0x0320F809, 0x2685D468)
        memory_ops = {0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26,
                      0x28, 0x29, 0x2A, 0x2B, 0x2E, 0x30, 0x38}
        matches = [pc for pc in range(0x428B00, 0x42EAA0, 4)
                   if self.elf.word(pc) >> 26 in memory_ops
                   and self.elf.word(pc) & 0xFFFF == 0xBA0]
        self.assertEqual(matches, [0x42CBFC, 0x42D690])
        self.words(0x42B9CC, 0x2624D368, 0x00002821, 0x24061E68,
                   0xAFBF0024, 0x0C296F18)
        self.assertLess(0xBA0 + 4, 0x1E68)


if __name__ == '__main__':
    unittest.main()
