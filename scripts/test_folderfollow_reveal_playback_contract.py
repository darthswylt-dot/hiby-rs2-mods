#!/usr/bin/env python3
"""Hash-gated playback writer/provenance anchors, not an all-writers proof.

These checks pin original instructions and bounded direct-call observations.
They do not establish input ownership, cross-thread serialization, mutation
coverage through aliases/indirect calls, or a coherent live playback mailbox.
No firmware generation, device access, or source-binary modification.
"""

import hashlib
import unittest

from mips_static_trace import locally_resolved_call_constant
from test_folderfollow_reveal_static_contract import (
    SOURCE, SOURCE_SHA256, SOURCE_SIZE, Elf32, decode,
)


PLAYER = 0xADD368
ITEM = 0xADD468


class RevealPlaybackContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.elf = Elf32(SOURCE)
        digest = hashlib.sha256(cls.elf.data).hexdigest()
        if digest != SOURCE_SHA256 or len(cls.elf.data) != SOURCE_SIZE:
            raise AssertionError(f'unrecognized reference: SHA-256 {digest}, '
                                 f'size {len(cls.elf.data)}')
        cls.calls = {}
        for start, end in cls.elf.executable_ranges():
            for pc in range(start, end & ~3, 4):
                word = cls.elf.word(pc)
                if word >> 26 == 3:
                    target = ((pc + 4) & 0xF0000000) | ((word & 0x3FFFFFF) << 2)
                    cls.calls.setdefault(target, []).append(pc)

    def instructions(self, start, *expected):
        for index, (word, assembly) in enumerate(expected):
            pc = start + 4 * index
            with self.subTest(pc=f'{pc:#x}', assembly=assembly):
                self.assertEqual(self.elf.word(pc), word)
                self.assertEqual(decode(pc, word), assembly)

    def test_five_known_whole_item_commits_have_the_same_copy_size(self):
        self.assertEqual(self.elf.word(0x92123C + 24 * 4), 0x42AC00)
        for pc in (0x42AC0C, 0x42CBDC, 0x42CD5C, 0x42CF84):
            self.instructions(pc,
                              (0x0C296D10, 'jal 0xA5B440'),
                              (0x24060A88, 'addiu a2,zero,2696'))
        self.instructions(0x42AC00,
                          (0x3C0400AE, 'lui a0,0xAE'),
                          (0x2484D468, 'addiu a0,a0,-11160'),
                          (0x02402821, 'addu a1,s2,zero'))
        self.assertEqual((0xAE << 16) - 11160, ITEM)
        self.instructions(0x42D380,
                          (0x2684D468, 'addiu a0,s4,-11160'),
                          (0x02202821, 'addu a1,s1,zero'),
                          (0x24060A88, 'addiu a2,zero,2696'))
        self.instructions(0x42D398,
                          (0x0C296D10, 'jal 0xA5B440'),
                          (0xAE020BA8, 'sw v0,+0xba8(s0)'))
        self.instructions(0x42CF7C,
                          (0x2684D468, 'addiu a0,s4,-11160'),
                          (0x02202821, 'addu a1,s1,zero'))

    def test_descriptor_escapes_via_pointer_out_and_indirect_callbacks(self):
        # These are pointer escapes, NOT proof that any consumer mutates D.
        self.instructions(0x42B068,
                          (0x3C0200AE, 'lui v0,0xAE'),
                          (0x2442D468, 'addiu v0,v0,-11160'),
                          (0x1000FF4C, 'beq zero,zero,0x42ADA4'),
                          (0xAE620000, 'sw v0,+0x0(s3)'))
        for pc in (0x42CC0C, 0x42D6A0):
            self.instructions(pc,
                              (0x0320F809, 'jalr ra,t9'),
                              (0x2685D468, 'addiu a1,s4,-11160'))

    def test_preparation_conditionally_clears_first_current_path_unit(self):
        self.instructions(0x429EBC,
                          (0x2610D368, 'addiu s0,s0,-11416'),
                          (0x8E020018, 'lw v0,+0x18(s0)'),
                          (0x1040000F, 'beq v0,zero,0x429F04'))
        self.instructions(0x429EAC, (0x3C1000AE, 'lui s0,0xAE'))
        self.instructions(0x429EE8,
                          (0xAE000018, 'sw zero,+0x18(s0)'),
                          (0xAE000020, 'sw zero,+0x20(s0)'),
                          (0xAE00001C, 'sw zero,+0x1c(s0)'),
                          (0xA6000C4C, 'sh zero,+0xc4c(s0)'),
                          (0xA6000104, 'sh zero,+0x104(s0)'),
                          (0xA600144C, 'sh zero,+0x144c(s0)'))
        self.assertEqual((0xAE << 16) - 11416, PLAYER)
        self.assertEqual(PLAYER + 0x104, ITEM + 4)

    def test_preparation_callers_include_the_general_commit_before_its_copy(self):
        self.assertEqual(self.calls[0x429E80],
                         [0x42C2B4, 0x42CD38, 0x42E7D8])
        self.instructions(0x42CD38,
                          (0x0C10A7A0, 'jal 0x429E80'),
                          (0xAFA21D88, 'sw v0,+0x1d88(sp)'),
                          (0x0C10A378, 'jal 0x428DE0'),
                          (0, 'nop'),
                          (0x1220036E, 'beq s1,zero,0x42DB04'),
                          (0xAE02002C, 'sw v0,+0x2c(s0)'),
                          (0x3C1400AE, 'lui s4,0xAE'),
                          (0x2684D468, 'addiu a0,s4,-11160'),
                          (0x02202821, 'addu a1,s1,zero'),
                          (0x0C296D10, 'jal 0xA5B440'),
                          (0x24060A88, 'addiu a2,zero,2696'))

    def test_full_clear_has_its_own_memset_not_a_commit_memcpy(self):
        self.instructions(0x42DEB8,
                          (0x3C0400AE, 'lui a0,0xAE'),
                          (0x2484D468, 'addiu a0,a0,-11160'),
                          (0x00002821, 'addu a1,zero,zero'),
                          (0x24060A88, 'addiu a2,zero,2696'),
                          (0x3C0200AE, 'lui v0,0xAE'),
                          (0x0C296F18, 'jal 0xA5BC60'),
                          (0xA440E9BC, 'sh zero,-0x1644(v0)'))

    def test_full_clear_has_twelve_statically_direct_call_sites(self):
        # Exact JAL inventory, not a claim about runtime reachability, aliases,
        # indirect entries, or execution frequency of any of these callers.
        self.assertEqual(self.calls[0x42DEA0], [
            0x423284, 0x42DFE0, 0x42E164, 0x4521FC, 0x4522EC, 0x4F9550,
            0x5026A0, 0x503044, 0x5055F0, 0x5098B8, 0x532DE4, 0x538588,
        ])

    def test_public_clear_passes_a_zeroed_stack_item_to_property24(self):
        self.instructions(0x531140,
                          (0x27BDF4D8, 'addiu sp,sp,-2856'),
                          (0x27A40018, 'addiu a0,sp,24'),
                          (0x00002821, 'addu a1,zero,zero'),
                          (0xAFBF0B24, 'sw ra,+0xb24(sp)'),
                          (0x0C296F18, 'jal 0xA5BC60'),
                          (0x24060A88, 'addiu a2,zero,2696'),
                          (0x27A40AA0, 'addiu a0,sp,2720'),
                          (0x00002821, 'addu a1,zero,zero'),
                          (0x0C296F18, 'jal 0xA5BC60'),
                          (0x24060080, 'addiu a2,zero,128'),
                          (0x27A50018, 'addiu a1,sp,24'),
                          (0x24040018, 'addiu a0,zero,24'),
                          (0x0C10AAC8, 'jal 0x42AB20'),
                          (0x00003021, 'addu a2,zero,zero'))

    def test_property17_branch_can_store_current_cue_without_whole_copy(self):
        self.assertEqual(self.elf.word(0x92123C + 17 * 4), 0x42AC68)
        self.instructions(0x42AC68,
                          (0x1000FFCB, 'beq zero,zero,0x42AB98'),
                          (0xAE120524, 'sw s2,+0x524(s0)'))
        self.assertEqual(PLAYER + 0x524, ITEM + 0x424)

    def test_direct_setter_audit_has_no_property17_argument(self):
        calls = self.calls[0x42AB20]
        self.assertEqual(len(calls), 69)
        values = {pc: locally_resolved_call_constant(self.elf, pc, 4)[0]
                  for pc in calls}
        self.assertEqual([pc for pc, value in values.items() if value is None],
                         [0x42E7C0, 0x42E928, 0x4451D4])
        # Three locally unresolved values arrive from the pinned branches.
        # This remains a bounded static argument audit, not whole-CFG proof.
        self.instructions(0x42E564,
                          (0x10400095, 'beq v0,zero,0x42E7BC'),
                          (0x24040013, 'addiu a0,zero,19'))
        self.instructions(0x42E7BC,
                          (0x24050001, 'addiu a1,zero,1'),
                          (0x0C10AAC8, 'jal 0x42AB20'),
                          (0x00003021, 'addu a2,zero,zero'))
        self.instructions(0x42E898,
                          (0x10400022, 'beq v0,zero,0x42E924'),
                          (0x24040013, 'addiu a0,zero,19'))
        self.instructions(0x42E924,
                          (0x00002821, 'addu a1,zero,zero'),
                          (0x0C10AAC8, 'jal 0x42AB20'),
                          (0x00003021, 'addu a2,zero,zero'))
        self.instructions(0x445180,
                          (0x24040017, 'addiu a0,zero,23'),
                          (0x00002821, 'addu a1,zero,zero'),
                          (0x10620012, 'beq v1,v0,0x4451D4'),
                          (0x00003021, 'addu a2,zero,zero'))
        self.instructions(0x4451D4,
                          (0x0C10AAC8, 'jal 0x42AB20'), (0, 'nop'))
        values.update({0x42E7C0: 19, 0x42E928: 19, 0x4451D4: 23})
        self.assertNotIn(17, values.values())
        self.assertEqual([pc for pc, value in values.items() if value == 24],
                         [0x4B55E8, 0x531170, 0x533C68])

    def test_player_initialization_clears_a_region_containing_current_item(self):
        self.instructions(0x42B9C8,
                          (0x3C1100AE, 'lui s1,0xAE'),
                          (0x2624D368, 'addiu a0,s1,-11416'),
                          (0x00002821, 'addu a1,zero,zero'),
                          (0x24061E68, 'addiu a2,zero,7784'),
                          (0xAFBF0024, 'sw ra,+0x24(sp)'),
                          (0x0C296F18, 'jal 0xA5BC60'),
                          (0xAFB0001C, 'sw s0,+0x1c(sp)'))
        self.assertLessEqual(PLAYER, ITEM)
        self.assertLessEqual(ITEM + 0xA88, PLAYER + 0x1E68)

    def test_general_commit_has_both_stack_and_current_item_alias_callers(self):
        self.assertEqual(self.calls[0x42CC60], [0x42E42C, 0x42E598])
        self.instructions(0x42E424,
                          (0x8E040BA4, 'lw a0,+0xba4(s0)'),
                          (0x27A50018, 'addiu a1,sp,24'),
                          (0x0C10B318, 'jal 0x42CC60'),
                          (0x03C03021, 'addu a2,fp,zero'))
        self.instructions(0x42E588,
                          (0x3C0500AE, 'lui a1,0xAE'),
                          (0x8E040BA4, 'lw a0,+0xba4(s0)'),
                          (0x8E060020, 'lw a2,+0x20(s0)'),
                          (0x24A5D468, 'addiu a1,a1,-11160'),
                          (0x0C10B318, 'jal 0x42CC60'),
                          (0xAE000BB8, 'sw zero,+0xbb8(s0)'))
        self.instructions(0x42CC84, (0x00A08821, 'addu s1,a1,zero'))
        # Both outer callers converge on the same inner memcpy/return site;
        # its PC alone cannot certify an independently owned source object.
        self.instructions(0x42CD58,
                          (0x02202821, 'addu a1,s1,zero'),
                          (0x0C296D10, 'jal 0xA5B440'),
                          (0x24060A88, 'addiu a2,zero,2696'))


if __name__ == '__main__':
    unittest.main()
