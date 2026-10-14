#!/usr/bin/env python3
"""Hash-gated object-close/owner anchors, not a runtime lifetime proof."""

import hashlib
import unittest

from test_folderfollow_reveal_static_contract import (
    SOURCE, SOURCE_SHA256, SOURCE_SIZE, Elf32,
)


class RevealUiOwnerContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.elf = Elf32(SOURCE)
        digest = hashlib.sha256(cls.elf.data).hexdigest()
        if digest != SOURCE_SHA256 or len(cls.elf.data) != SOURCE_SIZE:
            raise AssertionError(f'unrecognized reference: {digest}, '
                                 f'size {len(cls.elf.data)}')

    def words(self, start, expected):
        for index, word in enumerate(expected):
            pc = start + index * 4
            with self.subTest(pc=f'{pc:#x}'):
                self.assertEqual(self.elf.word(pc), word)

    @classmethod
    def direct_calls(cls, target):
        # Direct JAL census only: deliberately not called an ownership proof.
        return [pc for start, end in cls.elf.executable_ranges()
                for pc in range(start, end & ~3, 4)
                if cls.elf.word(pc) >> 26 == 3
                and (((pc + 4) & 0xF0000000)
                     | ((cls.elf.word(pc) & 0x03FFFFFF) << 2)) == target]

    def test_registration_copies_callback_context_and_close_flag(self):
        self.words(0x438A10, [0x0C119A78, 0x2404001C])
        self.words(0x438A20, [0x8E230004, 0xAC43000C, 0x8E230000,
                               0xAC430008, 0x8E230010, 0xAC430018,
                               0x8E23000C, 0xAC430014, 0x8E230008,
                               0xAC430010])

    def test_dialog_registration_binds_same_record_callback(self):
        self.words(0x47D310, [0x3C050048, 0x02002021, 0x8CC30028,
                               0x24A5D060, 0x0C10EBC0, 0xAC430008])
        self.words(0x43AF10, [0x00A0A021])
        self.words(0x43AF20, [0x00C09821])
        self.words(0x43B014, [0xAFA20050, 0xAFA00054, 0xAFB40060,
                               0xAFB3005C, 0x10400004, 0xAFA00058,
                               0x02202021, 0x0C10E278, 0x27A50050])

    def test_files_registration_binds_destructor_and_view_context(self):
        self.words(0x49290C, [0x3C060049, 0x27A516E4, 0x24C63AC0,
                               0x0C10EB40, 0x02003821])
        self.words(0x43AD38, [0x00C0B021, 0x24060014, 0x00E0A821])
        self.words(0x43AE78, [0xAFB60060, 0xAFB5005C, 0x10400004,
                               0xAFA30058, 0x02202021, 0x0C10E278,
                               0x27A50050])

    def test_deferred_facade_only_sets_record_close_request(self):
        self.words(0x43B218, [0x0C10EC48, 0, 0x10400002, 0x24030001,
                               0xAC430004])
        self.words(0x437A8C, [0x8E110034, 0x26060034, 0x1226000C,
                               0x8E220000, 0x8E23000C, 0x10600007])

    def test_deferred_consumer_unlocks_before_resource_and_callback_use(self):
        self.words(0x437AF8, [0x0C121778, 0x24C608B4, 0x8E190278,
                               0x00409021, 0x0320F809, 0x02002021,
                               0x1240000D, 0x8FBF0024, 0x0C1164D0,
                               0x02402021])
        self.words(0x437B28, [0x8E390018, 0x13200006, 0x8FB20020,
                               0x8FB1001C, 0x8FB00018, 0x00402021,
                               0x03200008, 0x27BD0028])
        self.words(0x459340, [0x10800003, 0, 0x03E00008, 0x8C82007C])
        self.words(0x47D350, [0x8FA50220, 0x0C1164C8, 0x8CA40040])

    def test_deferred_direct_callers_precede_timer_in_each_loop(self):
        self.assertEqual(self.direct_calls(0x437A60), [0x43C9D4, 0x43CA94])
        self.words(0x43C9D4, [0x0C10DE98, 0x02002021, 0x0C10DF50,
                               0x02002021, 0x0C11CD58, 0])
        self.words(0x43CA94, [0x0C10DE98, 0x02002021, 0x0C11CD58, 0])

    def test_resolver_returns_unretained_record_interior_after_unlock(self):
        self.words(0x43B190, [0x8E990278, 0x0320F809, 0x02802021,
                               0x8FBF002C, 0x26020008])

    def test_synchronous_facade_calls_same_callback_without_queue(self):
        # Pin the complete function, including null guards, shifted fields,
        # and tail-call. The only direct call resolves R+8.
        self.words(0x43B240, [0x27BDFFE0, 0xAFBF001C, 0x0C10EC48, 0,
                               0x10400009, 0x8FBF001C, 0x8C590010,
                               0x13200006, 0, 0x8C44000C, 0x10800003,
                               0, 0x03200008, 0x27BD0020, 0x03E00008,
                               0x27BD0020])
        self.assertEqual(len(self.direct_calls(0x43B240)), 194)

    def test_files_activation_has_synchronous_close_before_recreate(self):
        self.words(0x49E710, [0x02202021, 0x0C10EC90, 0x27A50AA8,
                               0x02202021, 0x0C126890, 0x27A50024,
                               0x1440FFB7, 0x02202021, 0x27A50AA8,
                               0x0C1247A0, 0x27A60024])

    def test_controller_brackets_are_distinct_and_timer_does_not_inherit_138(self):
        self.words(0x439A40, [0xAE020138, 0x3C020043, 0x24427CC0,
                               0xAE02026C, 0x3C020043, 0x24427D40,
                               0x0C119B58, 0xAE020270, 0xAE02013C,
                               0x3C020043, 0x24427D20, 0xAE020274,
                               0x3C020043, 0x24427DA0, 0x0C119B58,
                               0xAE020278])
        self.words(0x437CC8, [0x0C119B68, 0x8C840138])
        self.words(0x437D48, [0x0C119B70, 0x8C840138])
        self.words(0x437D28, [0x0C119B68, 0x8C84013C])
        self.words(0x437DA8, [0x0C119B70, 0x8C84013C])
        self.words(0x43C9C4, [0x0C10DF30, 0x02002021, 0x0C11F308, 0,
                               0x0C10DE98, 0x02002021, 0x0C10DF50,
                               0x02002021, 0x0C11CD58, 0])

    def test_dialog_close_completes_inline_not_on_another_dispatcher(self):
        self.words(0x47D07C, [0x0C11F3E0, 0x8E040024])
        self.words(0x47D000, [0x8E39006C, 0x0320F809, 0x02202021])
        self.words(0x47C7B8, [0x8E190074, 0x13200004, 0, 0x8E050050,
                               0x0320F809, 0x02002021])

    def test_refresh_has_a_render_callback_route_not_only_ui_timer_callers(self):
        self.assertEqual(self.direct_calls(0x499C20), [
            0x452F9C, 0x490920, 0x490DD4, 0x4913D4,
            0x491CE4, 0x494CC4, 0x49A1F8, 0x4BDBAC,
        ])
        self.words(0x4928B8, [0x3C050049, 0x02402021, 0x0C116548, 0x24A508A0])
        self.words(0x4382F4, [0x8FD90154, 0x13200003, 0x02002021,
                               0x0320F809, 0x03C02821])
        self.words(0x490920, [0x0C126708, 0x02402821])
        self.words(0x499CB4, [0x8E360010, 0x8E02004C, 0x8E370018])


if __name__ == '__main__':
    unittest.main()
