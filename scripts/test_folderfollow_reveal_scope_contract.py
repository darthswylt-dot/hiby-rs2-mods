#!/usr/bin/env python3
"""Hash-gated static scope anchors; no device, patch, or runtime-safety claim.

Import reference constants/reader only, not the existing TestCase: running
this module must not silently rerun the older suite.
"""

import hashlib
import unittest

from test_folderfollow_reveal_static_contract import (
    SOURCE, SOURCE_SHA256, SOURCE_SIZE, Elf32,
)


class RevealScopeContractTests(unittest.TestCase):
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

    def utf16(self, address, expected):
        value = (expected + '\0').encode('utf-16-le')
        offset = self.elf.va_to_off(address)
        self.assertEqual(self.elf.data[offset:offset + len(value)], value)

    def test_literals_are_pseudo_scope_markers_not_view_type_names(self):
        for address, value in (
                (0x921230, 'tidal'), (0x921194, 'music_search_'),
                (0x941654, 'recent'), (0x942220, 'music_search_albums'),
                (0x942248, 'music_search_artists')):
            self.utf16(address, value)

    def test_search_helper_advances_candidate_and_returns_pointer_or_null(self):
        # UTF-16 strstr, not strcmp: match retains candidate v0; failure
        # advances by two bytes, and exhaustion returns zero.
        self.words(0x41FEC0, [0x94AA0000, 0x1140001D, 0x00801021])
        self.words(0x41FEF4, [0x94C80002, 0x11000010, 0x01203021])
        self.words(0x41FF24, [0x24420002, 0x94430000, 0x1460FFEA,
                               0x00000000, 0x03E00008, 0x00001021,
                               0x03E00008, 0x00000000])

    def test_reset_special_branches_exclude_tidal_for_full_or_empty_list(self):
        self.words(0x4ACC34, [0x10800033, 0xAFA30464])  # null list
        self.words(0x4ACC48, [0x1840002E, 0x02202021, 0x3C050092,
                               0x0C107FB0, 0x24A51230, 0x1040003A])
        self.words(0x4ACD04, [0x3C050092, 0x02202021, 0x0C107FB0,
                               0x24A51230, 0x1040000C])

    def test_reset_uses_literal_length_prefix_comparisons_and_exact_sites(self):
        self.words(0x4ACD48, [0x3C130092, 0x0C107F80, 0x26641194,
                               0x00403021, 0x02202021, 0x0C107F38,
                               0x26651194, 0x1040002D, 0x3C130094,
                               0x0C107F80, 0x26641654, 0x00403021,
                               0x02202021, 0x0C107F38, 0x26651654,
                               0x1040001E])
        self.words(0x4ACE00, [0x0C12E358, 0x8E043B9C, 0x02402021,
                               0x0C124490, 0x02002821])
        self.words(0x4ACE1C, [0x02402021, 0x0C124490, 0x02002821])
        # Bounded compare returns zero on length exhaustion.
        self.words(0x41FCF8, [0x10C00009, 0x00001021])

    def test_ordinary_scope_still_destroys_and_recreates_view(self):
        self.words(0x4ACD8C, [0x0C124EB0, 0x02002021, 0x1680FFD3,
                               0x24020001, 0x02402021, 0x27A50420,
                               0x0C1247A0, 0x27A60020])
        self.words(0x4ACDF0, [0x0C22D0F0, 0x24E70002])

    def test_three_found_operation_entry_routes(self):
        self.words(0x450D98, [0x8E060000, 0x0C12B620, 0x26050050])
        self.words(0x4AEEE0, [0x0C12B620, 0x02803021])
        self.words(0x4AD8D8, [0x0C12B2F0, 0x02002021])
        self.words(0x4AEC1C, [0x0C12B618, 0x8FA4047C])
        self.words(0x4AD860, [0x0812B2F0, 0x00000000])

    def test_operation_callbacks_are_dialog_completion_slot_not_worker_tick(self):
        self.words(0x45334C, [0x24420D60])
        self.words(0x45336C, [0x0C11F460, 0xAFA20024])
        self.words(0x4AF1F4, [0x2442EC60])
        self.words(0x4AF230, [0x10800106, 0xAFA2022C])
        self.words(0x4AFBF4, [0x2442EA80, 0xAFA20024])
        self.words(0x47D24C, [0x8E420004, 0xAC620074])
        self.words(0x47D254, [0x8E420008, 0xAC620078])
        self.words(0x47C620, [0x8E190078, 0x13200003, 0x02002021,
                               0x0320F809, 0x8E050054])

    def test_normal_completion_calls_operation_under_dialog_mutex(self):
        self.words(0x47D380, [0x3C020048, 0x2442C740, 0x0C11F278,
                               0xAC62006C])
        self.words(0x47CC78, [0x9223001C, 0x1060FFF7, 0x26100001,
                               0x2610FFFF, 0x8E39006C, 0x0320F809,
                               0x02202021])
        self.words(0x47C794, [0x0C119B68, 0x8E040010])
        self.words(0x47C7B8, [0x8E190074, 0x13200004, 0x00000000,
                               0x8E050050, 0x0320F809, 0x02002021])
        self.words(0x47C800, [0x0C119B70, 0x8E040010])

    def test_completion_precedes_timer_in_one_music_loop_invocation(self):
        self.words(0x43C9CC, [0x0C11F308, 0x00000000])
        self.words(0x43C9E4, [0x0C11CD58, 0x00000000])
        self.words(0x926D2C, [0x138, 0x453320])

    def test_close_by_name_is_an_additional_route_not_unique_loop_proof(self):
        self.words(0x47D07C, [0x0C11F3E0, 0x8E040024])
        self.words(0x47D000, [0x8E39006C, 0x0320F809, 0x02202021])
        self.words(0x47D310, [0x3C050048, 0x02002021, 0x8CC30028,
                               0x24A5D060, 0x0C10EBC0, 0xAC430008])
        self.words(0x43B01C, [0xAFB40060, 0xAFB3005C])
        self.words(0x438A30, [0x8E230010, 0xAC430018])

    def test_files_type_two_reaches_substring_guards(self):
        self.words(0x499D4C, [0x8E020040, 0x2442FFFD, 0x2C43002A,
                               0x10600015, 0x8FB50018])
        # This evaluates the pinned unsigned subtract/range gate only;
        # it is not a firmware emulator or runtime reachability assertion.
        self.assertFalse(((2 - 3) & 0xFFFFFFFF) < 42)
        self.words(0x499DB0, [0x02802021, 0x0C107FB0, 0x03C02821,
                               0x14400008, 0x27A40AA0, 0x3C020094,
                               0x02802021, 0x0C107FB0, 0x24452248,
                               0x104000BA, 0x02802021])
        normal = '/mnt/sdcard/Slayer/Show No Mercy/*'
        edge = '/mnt/sdcard/music_search_albums/Album/*'
        marker = 'music_search_albums'
        self.assertNotIn(marker, normal)
        self.assertIn(marker, edge)
        self.assertFalse(edge.startswith('music_search_'))

    def test_matching_scope_writes_raw_row_not_only_stack_descriptor(self):
        self.words(0x499E24, [0x8E040064, 0xAFB50018, 0x8C99002C,
                               0x0320F809, 0x02802821, 0x10400006,
                               0x00409821, 0x24440004, 0x27A5001C,
                               0x0C107EE0, 0x24060104, 0xA660020A])
        # No marker -> local-path adjustment branch -> common continuation,
        # not a second entry into the raw getter/write block.
        self.words(0x49A0CC, [0x1040FF61, 0x27A4001C, 0x27A50224,
                               0x0C107EE0, 0x24060104, 0x1000FF5C,
                               0xA7A00222])


if __name__ == '__main__':
    unittest.main()
