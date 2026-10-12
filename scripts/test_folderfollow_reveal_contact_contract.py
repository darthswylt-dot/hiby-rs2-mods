#!/usr/bin/env python3
"""Original contact-path anchors, not a physical-sensor/lifetime proof."""

import hashlib
import unittest

from test_folderfollow_reveal_static_contract import (
    SOURCE, SOURCE_SHA256, SOURCE_SIZE, Elf32,
)


class RevealContactContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.elf = Elf32(SOURCE)
        if (len(cls.elf.data) != SOURCE_SIZE
                or hashlib.sha256(cls.elf.data).hexdigest() != SOURCE_SHA256):
            raise AssertionError('unrecognized reference')

    def words(self, start, expected):
        for index, word in enumerate(expected):
            with self.subTest(pc=hex(start + index * 4)):
                self.assertEqual(self.elf.word(start + index * 4), word)

    def test_release_source_ignores_nonzero_touch_button_value(self):
        self.words(0x472778, [0x1462FFF7, 0x97A30022, 0x2402014A,
                             0x1462FFF4, 0x8FA20024, 0x1440FFF2])
        self.words(0x4727AC, [0x24020003, 0x0C11C920, 0xAE020000])

    def test_raw_input_uses_contact_object_not_capture_object(self):
        # H+08=G; H+10=A. G's callback is 8B16A0, with H as context.
        self.words(0x8B1AE8, [0x8CE40008, 0x3C06008B, 0x02002821,
                             0x0C22D330, 0x24C616A0])

    def test_first_contact_precedes_raw_release_check_even_for_orphan_release(self):
        self.words(0x8B4CDC, [0x8CA20000, 0x24030001])
        self.words(0x8B4D38, [0x8E0B0000])
        self.words(0x8B4D50, [0x11600039, 0xAFA8004C, 0x24030003,
                             0x10430049, 0x24020005])
        self.words(0x8B4E38, [0xAE030000])
        self.words(0x8B4E58, [0x24050004, 0xAFA50034])
        # G==0 branches to start BEFORE comparing raw code with 3.
        # This preserves the orphan-release counterexample, not a repair.

    def test_normal_release_clears_contact_before_callback_and_recognizer(self):
        self.words(0x8B4E84, [0xAE000000, 0xAFA20034, 0x1000FFC3,
                             0xAE000004])
        self.words(0x8B4D9C, [0x12200019, 0, 0x02402021, 0x0220C821,
                             0x0320F809, 0x27A50034, 0x8E040024,
                             0x27A50018, 0x0C22D520, 0x27A60034])

    def test_long_press_release_does_not_require_a_completion_event(self):
        # Recognizer event 5 -> long-press branch -> v0=0, no output callback.
        self.words(0x8B54A8, [0x24030005, 0x00C08821, 0x00808021,
                             0x10430013, 0x00A09021])
        self.words(0x8B5504, [0x8C820044, 0x14400074, 0xAC80003C])
        self.words(0x8B56DC, [0xAC800044])
        self.words(0x8B5700, [0x00001021, 0x03E00008, 0x27BD0140])
        self.words(0x8B4DC4, [0x10400015, 0x02402021])

    def test_stationary_repeat_does_not_clear_contact(self):
        self.words(0x8B4E94, [0x8E020014, 0x1446FFB5, 0, 0x8E020018,
                             0x1447FFB2, 0x2402FFFF, 0x1000FF97,
                             0x8FBF005C])

    def test_capture_cleanup_and_animation_abort_are_not_contact_release(self):
        self.words(0x8B1AD8, [0x8C910010])  # s1=A, not G.
        self.words(0x8B1BD4, [0xAE200000, 0xAE200004])
        self.words(0x8B1C00, [0xAE200008, 0xAE200000, 0x1000FFF4,
                             0xAE200004])
        self.words(0x8B1EF4, [0x8C900010, 0x8E040010, 0x1080000B,
                             0xAE000008, 0x0C22CBE0, 0, 0x24020001,
                             0xAE020034, 0xAE00000C])
        self.words(0x8B11B0, [0x8E040008, 0x10800003, 0, 0x0C22D318, 0])


if __name__ == '__main__':
    unittest.main()
