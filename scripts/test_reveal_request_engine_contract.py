#!/usr/bin/env python3
"""Bounded source premises for deferred paint carriers, never UI ownership.

No binary patch, device, network, native tail read or pointer registry. The
direct-call census is not complete alias/indirect/lifetime coverage.
"""

import hashlib
import struct
import unittest

import test_folderfollow_reveal_static_contract as source


class RevealRequestEngineContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.elf = source.Elf32(source.SOURCE)
        digest = hashlib.sha256(cls.elf.data).hexdigest()
        if digest != source.SOURCE_SHA256 or len(cls.elf.data) != source.SOURCE_SIZE:
            raise AssertionError(f'unrecognized reference: {digest}')
        cls.calls = {}
        for low, high in cls.elf.executable_ranges():
            for pc in range(low, high & ~3, 4):
                word = cls.elf.word(pc)
                if word >> 26 == 3:
                    target = ((pc + 4) & 0xF0000000) | ((word & 0x3FFFFFF) << 2)
                    cls.calls.setdefault(target, []).append(pc)

    def words(self, anchors):
        for pc, expected in anchors.items():
            with self.subTest(pc=f'{pc:#x}'):
                self.assertEqual(self.elf.word(pc), expected)

    def test_render_object_is_84_bytes_not_a_new_request_per_callback(self):
        self.words({
            0x8B4134: 0x0C22C340, 0x8B4138: 0x24040054,
            0x8B4144: 0x00402021, 0x8B4148: 0x00002821,
            0x8B414C: 0x0C296F18, 0x8B4150: 0x24060054,
            0x8B418C: 0x8E22002C, 0x8B4190: 0xAE020048,
            0x8B419C: 0x8E220034, 0x8B41A0: 0xAE020050,
            0x43AE54: 0x24429EC0, 0x43AE58: 0xAFA20044,
            0x43AE48: 0xAFB1004C, 0x43AE64: 0x0C22D048,
            0x43AFF4: 0x24429EC0, 0x43AFF8: 0xAFA20044,
            0x43B008: 0xAFB1004C, 0x43B00C: 0x0C22D048,
        })

    def test_redraw_facade_is_only_global_predicate_and_original_arguments(self):
        self.assertEqual(self.calls[0x8B4280], [0x459874])
        self.words({
            0x45985C: 0x0C11A350, 0x459864: 0x10400006,
            0x45986C: 0x02402021, 0x459870: 0x02202821,
            0x459874: 0x0C22D0A0, 0x459878: 0x02003021,
            0x468D40: 0x3C0200B9, 0x468D44: 0x8C4296D0,
            0x468D48: 0x03E00008, 0x468D4C: 0x2C420001,
        })

    def test_queue_copy_allocates_exactly_four_words_before_publish(self):
        self.words({
            0x8B42A0: 0x10A00036, 0x8B42A8: 0x24040010,
            0x8B42B0: 0x0C22C340, 0x8B42B4: 0x00A09021,
            0x8B42B8: 0x00408821, 0x8B42BC: 0x1040003C,
            0x8B42C0: 0x8FA60028, 0x8B42D4: 0x26040034,
            0x8B42D8: 0xAE270000, 0x8B42DC: 0xAE250004,
            0x8B42E0: 0xAE230008, 0x8B42E4: 0x02202821,
            0x8B42E8: 0x0C22CF30, 0x8B42EC: 0xAE22000C,
        })

    def test_generic_queue_node_has_no_spare_word(self):
        self.words({
            0x8B3CCC: 0x24040010, 0x8B3CE0: 0x0C22C340,
            0x8B3CE4: 0x00C08821, 0x8B3D14: 0xAC520000,
            0x8B3D18: 0xAC470008, 0x8B3D1C: 0xAC40000C,
            0x8B3D20: 0xAC510004, 0x8B3D24: 0xACE2000C,
            0x8B3D40: 0xAC400008, 0x8B3D44: 0xAC40000C,
            0x8B3D48: 0xAC510004, 0x8B3D4C: 0xAE020000,
        })

    def test_all_encoded_direct_queue_calls_are_pinned_not_alias_coverage(self):
        self.assertEqual(self.calls[0x8B3CC0], [
            0x8B083C, 0x8B0E30, 0x8B0EA4,
            0x8B0FB4, 0x8B1060, 0x8B42E8,
        ])
        values = (value[0] for value in struct.iter_unpack('<I',
                  self.elf.data[:len(self.elf.data) // 4 * 4]))
        self.assertNotIn(0x8B3CC0, values)
        self.words({
            0x8B0840: 0x24840028, 0x8B0E18: 0x27A4005C,
            0x8B0EC0: 0x27A40058, 0x8B0F34: 0x26F2002C,
            0x8B0FD4: 0x0C22C340, 0x8B0FD0: 0x2404002C,
            0x8B1058: 0x02402021, 0x8B42D4: 0x26040034,
        })

    def test_queue_payload_and_metadata_borrow_precedes_delete(self):
        self.words({
            0x8B4748: 0x8EBE0034, 0x8B474C: 0x13C00009,
            0x8B4754: 0x8FC50000, 0x8B4758: 0x8FC60004,
            0x8B475C: 0x0C22CFE8, 0x8B4760: 0x02A02021,
            0x8B4764: 0x8FDE000C, 0x8B4768: 0x17C0FFFA,
            0x8B4770: 0x8EA40034, 0x8B4774: 0x0C22CFC0,
            0x8B4778: 0x24050001, 0x8B4788: 0xAEA00034,
            0x8B4BB0: 0x8EA40034, 0x8B4BB4: 0x0C22CFC0,
            0x8B4BB8: 0x24050001, 0x8B4BBC: 0xAEA00034,
        })

    def test_copy_node_and_canvas_failure_paths_are_distinct_native_behaviors(self):
        self.words({
            # First allocation failure returns -1 before publishing a copy.
            0x8B42BC: 0x1040003C, 0x8B43B0: 0x1000FFE8,
            0x8B43B4: 0x2402FFFF,
            # Generic node-allocation failure returns without linking a node.
            0x8B3CE8: 0x10400010, 0x8B3D2C: 0x8FB20020,
            # Render canvas creation failure separately drains the old queue.
            0x8B490C: 0x0C22D720, 0x8B4910: 0x26A40044,
            0x8B4914: 0x144000A6, 0x8B4BB0: 0x8EA40034,
            0x8B4BB4: 0x0C22CFC0, 0x8B4BB8: 0x24050001,
            0x8B4BBC: 0xAEA00034, 0x8B4BC4: 0x00001021,
        })

    def test_mode_one_queue_delete_frees_payload_then_nodes(self):
        self.words({
            0x8B3F18: 0x3C05008B, 0x8B3F1C: 0x24A53100,
            0x8B3F20: 0x0822CF80, 0x8B3F24: 0x24070001,
            0x8B3110: 0x0C22C348, 0x8B3114: 0x00A02021,
            0x8B3E54: 0x8E050000, 0x8B3E58: 0x0240C821,
            0x8B3E5C: 0x0320F809, 0x8B3E60: 0x8E060004,
            0x8B3E80: 0x0C22C348, 0x8B3E84: 0x02002021,
        })

    def test_borrow_helper_also_accepts_nonqueued_rectangles(self):
        self.assertEqual(self.calls[0x8B3FA0], [
            0x8B475C, 0x8B4A14, 0x8B4AF8,
        ])
        self.words({
            0x8B4A10: 0x26050014, 0x8B4A18: 0x00003021,
            0x8B4AEC: 0x001E2900, 0x8B4AF4: 0x00E52821,
            0x8B4AFC: 0x00003021,
        })

    def test_callback_descriptor_preserves_original_metadata(self):
        self.words({
            0x8B3FCC: 0x00C0A821, 0x8B4090: 0x02C02021,
            0x8B4094: 0x27A50058, 0x8B40CC: 0x27A20074,
            0x8B40D0: 0x8ED90048, 0x8B40D4: 0xAFA2005C,
            0x8B40D8: 0xAFA60058, 0x8B40DC: 0xAFA00064,
            0x8B40E0: 0xAFA00060, 0x8B40E4: 0x0320F809,
            0x8B40E8: 0xAFB50068,
        })

    def test_borrow_frame_sp14_is_only_a_local_unused_slot_premise(self):
        memory = set()
        addresses = set()
        for pc in range(0x8B3FA0, 0x8B4120, 4):
            word = self.elf.word(pc)
            op, rs, rt = word >> 26, (word >> 21) & 31, (word >> 16) & 31
            if rs == 29 and op in (32, 33, 35, 36, 37, 40, 41, 43, 49, 57):
                memory.add(word & 0xFFFF)
            if op == 9 and rs == 29 and rt != 29:
                addresses.add(word & 0xFFFF)
        self.assertEqual(memory, {
            0x58, 0x5C, 0x60, 0x64, 0x68, 0x74, 0x78, 0x7C, 0x80,
            0x84, 0x88, 0x8C, 0x90, 0x98, 0x9C, 0xA0,
            0xA4, 0xA8, 0xAC, 0xB0, 0xB4,
        })
        self.assertEqual(addresses, {0x18, 0x1C, 0x58, 0x74, 0x84})
        self.assertNotIn(0x14, memory | addresses)

    def test_full_redraw_coalesces_in_mutable_bit_then_clears_before_dispatch(self):
        self.words({
            0x8B437C: 0x8C87003C, 0x8B4390: 0x3C064000,
            0x8B4394: 0x00E63025, 0x8B4398: 0xAE06003C,
            0x8B1508: 0x8C62003C, 0x8B150C: 0x00551025,
            0x8B1510: 0xAC62003C, 0x8B46B8: 0x3C07BFFF,
            0x8B46C0: 0x34E7FFFF, 0x8B46C8: 0x00473824,
            0x8B46E4: 0x1200007A, 0x8B46E8: 0xAEA7003C,
            0x8B46EC: 0x1480008C,
        })

    def test_full_callback_uses_stack_carrier_without_queue_metadata(self):
        self.words({
            0x8B492C: 0x27A30018, 0x8B4958: 0x8EB90048,
            0x8B4964: 0x24020001, 0x8B496C: 0x00602821,
            0x8B4970: 0x02A02021, 0x8B4980: 0xAFB4001C,
            0x8B4984: 0xAFB20018, 0x8B4988: 0xAFA00024,
            0x8B498C: 0xAFA00028, 0x8B4990: 0x0320F809,
            0x8B4994: 0xAFA20020,
        })

    def test_callback_resolves_widget_at_dispatch_not_from_queue_copy(self):
        self.words({
            0x439EE8: 0x8C930050, 0x439F1C: 0x8E640024,
            0x439F20: 0x8E050000, 0x439F34: 0x0C121778,
            0x439F48: 0x0C10E788, 0x439F4C: 0x24450020,
            0x439F50: 0x8E640024, 0x439F54: 0x8E050000,
            0x439F5C: 0x0C121508, 0x439F84: 0x02002021,
            0x439F88: 0x02202821, 0x439F8C: 0x27A60018,
            0x439F90: 0x0C10E080, 0x439F94: 0x02403821,
        })

    def test_reset_uses_existing_render_object_to_queue_new_rectangle(self):
        self.words({
            0x491384: 0x8E0200CC, 0x4913A4: 0x8C450000,
            0x4913A8: 0x0C11EA88, 0x4913AC: 0x02402021,
            0x4913B0: 0x8E0400CC, 0x4913B4: 0x27A50020,
            0x4913B8: 0x0C116610, 0x4913BC: 0x00003021,
        })
        self.assertNotIn(0x8B3F00, [
            target for target, calls in self.calls.items()
            if any(0x491240 <= pc < 0x49144C for pc in calls)
        ])

    def test_reconcile_explicit_redraw_is_also_a_nonnull_rectangle(self):
        self.words({
            0x491CB8: 0x8FA50238, 0x491CBC: 0x0C124340,
            0x491CC0: 0x02202021, 0x490D24: 0x8C4400CC,
            0x490D60: 0x27A50018, 0x490D64: 0x00003021,
            0x490DB0: 0x0C116610, 0x490DB4: 0xAFA20024,
        })
        # Only a bounded syntactic negative: not an alias/indirect-call proof.
        for lo, hi in ((0x491240, 0x49144C), (0x4919E0, 0x491E70),
                       (0x490D00, 0x490E20)):
            for pc in range(lo, hi, 4):
                word = self.elf.word(pc)
                if word >> 26 == 43 and ((word >> 21) & 31) != 29:
                    with self.subTest(pc=f'{pc:#x}'):
                        self.assertNotIn(word & 0xFFFF, (0x34, 0xCC))

    def test_teardown_distinctly_frees_queue_and_render_object(self):
        self.assertEqual(self.calls[0x8B4220], [0x439644])
        self.words({
            0x439610: 0x8E020004, 0x439618: 0xAC620004,
            0x43961C: 0xAC430000, 0x43962C: 0x0C119AA0,
            0x439638: 0x24050001, 0x43963C: 0x0C22CFC0,
            0x439640: 0x8C440034, 0x439644: 0x0C22D088,
            0x439648: 0x8E040008, 0x8B4238: 0x0C22D6E8,
            0x8B423C: 0x8C840044, 0x8B4240: 0x0C22C348,
            0x8B4244: 0x02002021,
        })


if __name__ == '__main__':
    unittest.main()
