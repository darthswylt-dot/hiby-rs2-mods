#!/usr/bin/env python3
"""Pin source-pointer identity and lifetime ordering, not runtime safety."""

import hashlib
import unittest

from mips_static_trace import direct_small_constant
from test_folderfollow_reveal_logical_contract import direct_target, executable_sections
from test_folderfollow_reveal_static_contract import (
    SOURCE, SOURCE_SHA256, SOURCE_SIZE, Elf32, decode,
)


SOURCE_SLOT = 0xADD360
PLAYER = 0xADD368
SETTER = 0x422BA0
PLAYER_SETTER = 0x42AB20


class SourceFinalizerContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.elf = Elf32(SOURCE)
        digest = hashlib.sha256(cls.elf.data).hexdigest()
        if digest != SOURCE_SHA256 or len(cls.elf.data) != SOURCE_SIZE:
            raise AssertionError(f'unrecognized reference: {digest}, '
                                 f'size {len(cls.elf.data)}')
        cls.calls = []
        cls.player_setter_calls = []
        for _, start, end in executable_sections(cls.elf):
            for pc in range(start, end, 4):
                word = cls.elf.word(pc)
                if word >> 26 == 3:
                    target = direct_target(pc, word)
                    if target == SETTER:
                        cls.calls.append(pc)
                    elif target == PLAYER_SETTER:
                        cls.player_setter_calls.append(pc)

    def instructions(self, start, *expected):
        for index, (word, assembly) in enumerate(expected):
            pc = start + index * 4
            with self.subTest(pc=f'{pc:#x}'):
                self.assertEqual(self.elf.word(pc), word)
                self.assertEqual(decode(pc, word), assembly)

    def property_argument(self, call_pc):
        value = direct_small_constant(self.elf.word(call_pc + 4), 4)
        if value is not None:
            return value
        for back in range(1, 13):
            candidate_pc = call_pc - back * 4
            word = self.elf.word(candidate_pc)
            value = direct_small_constant(word, 4)
            if value is not None:
                return value
            if word >> 26 == 3 or (word >> 26 == 0 and word & 63 == 9):
                break
        return None

    def test_source_global_is_add360_not_aed360(self):
        self.assertEqual(((0xAE << 16) +
                          (0xD360 - 0x10000)), SOURCE_SLOT)
        self.assertEqual(PLAYER - 8, SOURCE_SLOT)
        self.instructions(0x422B20,
                          (0x3C0200AE, 'lui v0,0xAE'),
                          (0x03E00008, 'jr ra'),
                          (0x8C42D360, 'lw v0,-0x2ca0(v0)'))
        self.instructions(0x422BA8,
                          (0x3C1200AE, 'lui s2,0xAE'),
                          (0xAFB00224, 'sw s0,+0x224(sp)'),
                          (0x8E50D360, 'lw s0,-0x2ca0(s2)'),
                          (0xAFBF0234, 'sw ra,+0x234(sp)'),
                          (0xAFB30230, 'sw s3,+0x230(sp)'),
                          (0x1200000B, 'beq s0,zero,0x422BEC'))

    def test_constructor_publishes_and_teardown_destroys_before_clear(self):
        self.instructions(0x42400C,
                          (0x0C119A78, 'jal 0x4669E0'),
                          (0x3C1000AE, 'lui s0,0xAE'),
                          (0x10400064, 'beq v0,zero,0x4241A8'),
                          (0xAE02D360, 'sw v0,-0x2ca0(s0)'))
        self.instructions(0x422B58,
                          (0x24030001, 'addiu v1,zero,1'),
                          (0x0C108A48, 'jal 0x422920'),
                          (0xAC430414, 'sw v1,+0x414(v0)'),
                          (0x0C119AA0, 'jal 0x466A80'),
                          (0x8E04D360, 'lw a0,-0x2ca0(s0)'),
                          (0xAE00D360, 'sw zero,-0x2ca0(s0)'))
        self.assertLess(0x422B64, 0x422B6C)

    def test_only_bounded_direct_property_31_32_setters_are_finalizer_pair(self):
        resolved = {}
        for pc in self.calls:
            prop = self.property_argument(pc)
            if prop in (31, 32):
                resolved.setdefault(prop, []).append(pc)
        self.assertEqual(resolved, {
            31: [0x42BC30, 0x42BC50],
            32: [0x42BBFC, 0x5191AC],
        })

    def test_public_player_setter_has_no_resolved_direct_property_17_call(self):
        properties = {}
        for pc in self.player_setter_calls:
            prop = self.property_argument(pc)
            if prop in (17, 24):
                properties.setdefault(prop, []).append(pc)
        self.assertEqual(properties, {
            24: [0x4B55E8, 0x531170, 0x533C68],
        })

    def test_secondary_property_32_writer_clears_effective_source_path(self):
        self.assertEqual(self.elf.word(0xAAE660), 0x00519140)
        pointer_refs = []
        for vaddr, offset, filesz, _, _ in self.elf.loads:
            for relative in range(0, filesz & ~3, 4):
                if self.elf.u32(offset + relative) == 0x00519140:
                    pointer_refs.append(vaddr + relative)
        self.assertEqual(pointer_refs, [0x00AAE660])

        direct_control_refs = []
        for start, end in self.elf.executable_ranges():
            for pc in range(start, end & ~3, 4):
                word = self.elf.word(pc)
                op = word >> 26
                if op in (2, 3):
                    target = ((pc + 4) & 0xF0000000) | ((word & 0x03FFFFFF) << 2)
                elif op in (1, 4, 5, 6, 7):
                    immediate = word & 0xFFFF
                    if immediate & 0x8000:
                        immediate -= 0x10000
                    target = pc + 4 + immediate * 4
                else:
                    continue
                if target == 0x00519140:
                    direct_control_refs.append(pc)
        self.assertEqual(direct_control_refs, [])

        self.instructions(0x519140,
                          (0x8C820110, 'lw v0,+0x110(a0)'),
                          (0x24030001, 'addiu v1,zero,1'),
                          (0x10430021, 'beq v0,v1,0x5191D0'),
                          (0x00000000, 'nop'))
        self.instructions(0x5191A4,
                          (0x3C050092, 'lui a1,0x92'),
                          (0x24040020, 'addiu a0,zero,32'),
                          (0x0C108AE8, 'jal 0x422BA0'),
                          (0x24A50AB4, 'addiu a1,a1,2740'))
        path = self.elf.va_to_off(0x920AB4)
        self.assertEqual(self.elf.data[path:path + 4], b'\x00\x00\x00\x00')
        self.assertEqual(self.elf.data[path + 4:path + 18],
                         '#EXTINF'.encode('utf-16le'))

    def test_secondary_writer_is_only_located_in_nearby_ui_metadata(self):
        for address, label in (
                (0xAAE610, b'pull_down_menu_iv_mseb'),
                (0xAAE670, b'pull_down_menu_iv_lineout'),
                (0xAAE6D0, b'pull_down_menu_iv_balance')):
            offset = self.elf.va_to_off(address)
            with self.subTest(address=f'{address:#x}'):
                self.assertEqual(self.elf.data[offset:offset + len(label) + 1],
                                 label + b'\0')
        self.assertEqual({
            address: self.elf.word(address)
            for address in (0xAAE658, 0xAAE660, 0xAAE6B8, 0xAAE718)
        }, {
            0xAAE658: 0x005190A0,
            0xAAE660: 0x00519140,
            0xAAE6B8: 0x005191E0,
            0xAAE718: 0x005192A0,
        })

    def test_callback_offset_scan_separates_player_reads_from_other_objects(self):
        memory_ops = {32, 33, 35, 36, 37, 40, 41, 43, 49, 57}
        hits = []
        for start, end in self.elf.executable_ranges():
            for pc in range(start, end & ~3, 4):
                word = self.elf.word(pc)
                if (word >> 26) in memory_ops and (word & 0xFFFF) == 0x0BA0:
                    hits.append((pc, word))
        self.assertEqual(hits, [
            (0x42CBFC, 0x8E390BA0),
            (0x42D690, 0x8E190BA0),
            (0x4A66F4, 0xAFBE0BA0),
            (0x4A69D0, 0x8FBE0BA0),
            (0x6C7328, 0x8E790BA0),
            (0x6CBEF8, 0xAC430BA0),
            (0x97D03C, 0xE7C00BA0),
        ])


if __name__ == '__main__':
    unittest.main()
