#!/usr/bin/env python3
"""Pinned native premises for a diagnostic queue-birth receipt.

These contracts do not change firmware or prove queue/view ownership. They
cover only the exact reference and encoded control transfers in its executable
sections; aliases, indirect entries and callees' ABI behavior remain separate.
"""

import hashlib
import struct
import unittest

import test_folderfollow_reveal_static_contract as source


class RevealQueueBirthContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.elf = source.Elf32(source.SOURCE)
        digest = hashlib.sha256(cls.elf.data).hexdigest()
        if digest != source.SOURCE_SHA256 or len(cls.elf.data) != source.SOURCE_SIZE:
            raise AssertionError(f'unrecognized reference: {digest}')
        cls.inbound = {}
        cls.calls = {}
        for low, high in cls.elf.executable_ranges():
            for pc in range(low, high & ~3, 4):
                word = cls.elf.word(pc)
                op = word >> 26
                if op in (2, 3):
                    target = ((pc + 4) & 0xF0000000) | ((word & 0x3FFFFFF) << 2)
                    if op == 3:
                        cls.calls.setdefault(target, []).append(pc)
                elif op in (1, 4, 5, 6, 7, 20, 21, 22, 23):
                    immediate = word & 0xFFFF
                    if immediate & 0x8000:
                        immediate -= 0x10000
                    target = pc + 4 + immediate * 4
                else:
                    continue
                cls.inbound.setdefault(target, []).append(pc)

    def words(self, anchors):
        for pc, expected in anchors.items():
            with self.subTest(pc=f'{pc:#x}'):
                self.assertEqual(self.elf.word(pc), expected)

    def test_entry_pair_follows_native_surface_guard(self):
        self.words({
            0x8B4280: 0x8C820044, 0x8B4284: 0x1040004C,
            0x8B4288: 0x00000000, 0x8B428C: 0x27BDFFC0,
            0x8B4290: 0xAFB00030, 0x8B4294: 0xAFBF003C,
            0x8B4298: 0xAFB20038, 0x8B429C: 0xAFB10034,
            0x8B43B8: 0x03E00008, 0x8B43BC: 0x00001021,
        })

    def test_null_rectangle_uses_existing_full_redraw_bit_not_queue(self):
        self.words({
            0x8B42A0: 0x10A00036, 0x8B42A4: 0x00808021,
            0x8B437C: 0x8C87003C, 0x8B4390: 0x3C064000,
            0x8B4394: 0x00E63025, 0x8B4398: 0xAE06003C,
            0x8B43A8: 0x1000FFE1, 0x8B43AC: 0xAFA20024,
        })

    def test_entry_precedes_native_allocation_and_input_copy(self):
        self.words({
            0x8B42A8: 0x24040010, 0x8B42AC: 0xAFA60028,
            0x8B42B0: 0x0C22C340, 0x8B42B4: 0x00A09021,
            0x8B42B8: 0x00408821, 0x8B42BC: 0x1040003C,
            0x8B42C0: 0x8FA60028,
            0x8B42C4: 0x8E470000, 0x8B42C8: 0x8E450004,
            0x8B42CC: 0x8E430008, 0x8B42D0: 0x8E42000C,
        })

    def test_prepared_pair_has_four_rectangle_scalars_not_four_stored_words(self):
        # At 42E0 entry, a3/a1/v1/v0 hold the four input words. The last
        # store is still in the original append call's delay slot.
        self.words({
            0x8B42D4: 0x26040034, 0x8B42D8: 0xAE270000,
            0x8B42DC: 0xAE250004, 0x8B42E0: 0xAE230008,
            0x8B42E4: 0x02202821, 0x8B42E8: 0x0C22CF30,
            0x8B42EC: 0xAE22000C,
        })

    def test_native_append_call_and_delay_slot_fix_original_return_address(self):
        self.assertEqual(self.elf.word(0x8B42E8), 0x0C22CF30)
        self.assertEqual(self.elf.word(0x8B42EC), 0xAE22000C)
        self.assertEqual(0x8B42E8 + 8, 0x8B42F0)

    def test_append_return_pair_precedes_native_result_overwrite(self):
        self.words({
            0x8B42F0: 0x8E280000, 0x8B42F4: 0x8E240004,
            0x8B42F8: 0x8E020018, 0x8B42FC: 0x8E050014,
        })

    def test_original_metadata_is_saved_and_passed_without_repurposing(self):
        self.words({
            0x8B42AC: 0xAFA60028, 0x8B42C0: 0x8FA60028,
            0x8B3CE4: 0x00C08821, 0x8B3D20: 0xAC510004,
            0x8B3D48: 0xAC510004,
        })

    def test_generic_append_allocates_16_byte_node_and_returns_raw_node_or_zero(self):
        self.words({
            0x8B3CC0: 0x27BDFFD8, 0x8B3CCC: 0x24040010,
            0x8B3CE0: 0x0C22C340, 0x8B3CE8: 0x10400010,
            0x8B3CEC: 0x8FBF0024,
            0x8B3D14: 0xAC520000, 0x8B3D18: 0xAC470008,
            0x8B3D1C: 0xAC40000C, 0x8B3D20: 0xAC510004,
            0x8B3D24: 0xACE2000C,
            0x8B3D38: 0x03E00008, 0x8B3D3C: 0x27BD0028,
            0x8B3D40: 0xAC400008, 0x8B3D44: 0xAC40000C,
            0x8B3D48: 0xAC510004, 0x8B3D4C: 0xAE020000,
            0x8B3D60: 0x03E00008, 0x8B3D64: 0x27BD0028,
        })

    def test_outer_zero_return_is_not_evidence_that_generic_append_linked(self):
        self.words({
            0x8B4350: 0x00001021, 0x8B4374: 0x1000FFF7,
            0x8B4378: 0x00001021, 0x8B43B0: 0x1000FFE8,
            0x8B43B4: 0x2402FFFF,
        })

    def test_native_epilogue_restores_exact_40_byte_frame(self):
        self.words({
            0x8B4354: 0x8FBF003C, 0x8B4358: 0x8FB20038,
            0x8B435C: 0x8FB10034, 0x8B4360: 0x8FB00030,
            0x8B4364: 0x03E00008, 0x8B4368: 0x27BD0040,
        })

    def test_sp14_has_no_bounded_direct_native_use_or_formed_address(self):
        memory, addresses = set(), set()
        for pc in range(0x8B4280, 0x8B43C0, 4):
            word = self.elf.word(pc)
            op, rs, rt = word >> 26, (word >> 21) & 31, (word >> 16) & 31
            if rs == 29 and op in (32, 33, 35, 36, 37, 40, 41, 43, 49, 57):
                memory.add(word & 0xFFFF)
            if op == 9 and rs == 29 and rt != 29:
                addresses.add(word & 0xFFFF)
        self.assertEqual(memory, {0x18, 0x1C, 0x20, 0x24, 0x28,
                                  0x30, 0x34, 0x38, 0x3C})
        self.assertEqual(addresses, {0x18})
        self.assertNotIn(0x14, memory | addresses)

    def test_bounded_native_calls_do_not_pass_stack_arguments(self):
        calls = {pc: target for target, sites in self.calls.items()
                 for pc in sites if 0x8B4280 <= pc < 0x8B43C0}
        self.assertEqual(calls, {
            0x8B42B0: 0x8B0D00, 0x8B42E8: 0x8B3CC0,
            0x8B4340: 0x8B3220, 0x8B436C: 0x8B06E0,
        })
        for pc in range(0x8B4280, 0x8B43C0, 4):
            word = self.elf.word(pc)
            with self.subTest(pc=f'{pc:#x}'):
                self.assertFalse(word >> 26 == 0 and word & 63 == 9)
        # This is only an outgoing-call/source premise, not a universal ABI
        # guarantee for indirect aliases or arbitrary writes by callees.

    def test_hook_words_have_no_encoded_inbound_control_transfer(self):
        for address in (0x8B428C, 0x8B4290, 0x8B42E0, 0x8B42E4,
                        0x8B42F0, 0x8B42F4):
            with self.subTest(address=f'{address:#x}'):
                self.assertEqual(self.inbound.get(address, []), [])

    def test_hook_words_have_no_aligned_file_backed_pointer_literal(self):
        values = {value[0] for value in struct.iter_unpack(
            '<I', self.elf.data[:len(self.elf.data) // 4 * 4])}
        for address in (0x8B428C, 0x8B4290, 0x8B42E0, 0x8B42E4,
                        0x8B42F0, 0x8B42F4):
            with self.subTest(address=f'{address:#x}'):
                self.assertNotIn(address, values)


if __name__ == '__main__':
    unittest.main()
