#!/usr/bin/env python3
"""Hash-gated queued-refresh anchors; not thread/lifetime or trigger coverage."""

import hashlib
import unittest

from test_folderfollow_reveal_static_contract import (
    SOURCE, SOURCE_SHA256, SOURCE_SIZE, Elf32,
)


class RevealNonrenderContractTests(unittest.TestCase):
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
        # Literal JAL census, not proof against indirect/alternate entries.
        return [pc for start, end in cls.elf.executable_ranges()
                for pc in range(start, end & ~3, 4)
                if cls.elf.word(pc) >> 26 == 3
                and (((pc + 4) & 0xF0000000)
                     | ((cls.elf.word(pc) & 0x03FFFFFF) << 2)) == target]

    def test_queue_copies_scalars_not_owned_objects(self):
        self.words(0x4743D4, [0x27A50018, 0x24060014, 0xAFA20028,
                               0xAFB1001C, 0xAFB30020, 0x0C114138,
                               0xAFB20024])

    def test_event_table_and_dispatch_call(self):
        self.words(0x926D74, [0x140, 0x453940])
        self.words(0x454248, [0x8E040014, 0x0C114180, 0x24060014])
        self.words(0x45425C, [0x24846B94, 0x8FA6001C])
        self.words(0x454294, [0x8C990004, 0x1320FFE6, 0x02202021,
                               0x0320F809, 0x27A50018])

    def test_subtype_three_is_delayed_default_is_explicit_refresh(self):
        self.words(0x453948, [0x8CA20008, 0x24060001, 0x10460013,
                               0x24060002, 0x10460015, 0x24060003,
                               0x10460017, 0x24060004, 0x10460007,
                               0, 0x0C114BB0, 0])
        self.words(0x4539C0, [0x0C114BA0, 0])
        self.assertEqual(self.direct_calls(0x452E80), [0x4539C0])
        self.assertEqual(self.direct_calls(0x452EC0), [0x453970])

    def test_delayed_route_resolves_then_swaps_timer_arguments(self):
        self.words(0x452E88, [0x0C1395A0, 0x27A50018, 0x8FA40018,
                               0x10800004, 0x8FBF0024, 0x0C126888,
                               0x24050064])
        self.words(0x49A220, [0x00801021, 0x00A02021,
                               0x08126490, 0x00402821])
        self.words(0x499260, [0x24040014, 0x1440000A, 0x02002821,
                               0x3C06004A, 0x02203821,
                               0x0C11CE28, 0x24C6A1A0])

    def test_timer_ignores_registered_view_and_resolves_current(self):
        self.words(0x49A1B0, [0x0C10F480, 0x00808021, 0x00402021,
                               0x0C1395A0, 0x27A50018])
        self.words(0x49A1D0, [0x0C1242D0, 0x00002821, 0x14400007,
                               0x8FA40018, 0x0C126858, 0x02002021])
        self.words(0x49A1F8, [0x0C126708, 0x8C8500CC,
                               0x0C126858, 0x02002021])

    def test_explicit_refresh_has_current_or_name_lookup_then_bit_gate(self):
        self.words(0x452EE8, [0x8E050008, 0x10A00033])
        self.words(0x452F10, [0x02202021, 0x27A50220,
                               0x0C1394C8, 0x27A60334])
        self.words(0x452FBC, [0x02202021, 0x0C1395A0, 0x27A50334])
        self.words(0x452F84, [0x00002821, 0x0C1242D0, 0x00008021,
                               0x10400005, 0x8FBF0344, 0x8FA40334,
                               0x0C126708, 0x8C8500CC])

    def test_both_lookups_release_registry_before_return(self):
        self.words(0x4E5398, [0xAEB10000, 0x8E9902A8,
                               0x0320F809, 0x02802021])
        self.words(0x4E562C, [0x8C420008, 0xAEA20000,
                               0x0C115BA0, 0x02202021,
                               0x8E9902A8, 0x0320F809, 0x02802021])

    def test_delayed_queue_producer_is_shared_not_manual_only(self):
        self.words(0x450F30, [0x24040140, 0x24050003,
                               0x0C11D0E0, 0x00003021])
        self.assertEqual(self.direct_calls(0x450F00), [
            0x4526A8, 0x4526C8, 0x4526E8, 0x452708,
        ])
        for pc, event, callback in [
            (0x926C74, 0x11D, 0x4526A0),
            (0x926C7C, 0x11F, 0x4526C0),
            (0x926C84, 0x121, 0x4526E0),
            (0x926C94, 0x124, 0x452700),
        ]:
            self.words(pc, [event, callback])
        self.assertEqual(self.direct_calls(0x474480), [0x7150F8, 0x7151C0])

    def test_playing_plane_producer_is_action_fourteen_png_completion(self):
        self.words(0x94BC08, [0x4E9BCC])  # action table + 14 * 4
        self.words(0x4E9BFC, [0x24040140, 0x00002821,
                               0x0C11D0E0, 0x24060007])
        self.words(0x44566C, [0x02402021, 0x0C107F50, 0x24A5302C])
        self.words(0x44569C, [0x0C13A9A8, 0x2405000E])
        offset = self.elf.va_to_off(0x92302C)
        self.assertEqual(self.elf.data[offset:offset + 8],
                         'png\0'.encode('utf-16-le'))
        self.words(0x452F74, [0x8E03000C, 0x24020007, 0x10620033])
        self.words(0x453090, [0x1000FFBC, 0x8FA40334])

    def test_fast_commit_not_a_direct_files_refresh_notification(self):
        self.words(0x42CBFC, [0x8E390BA0, 0x13200004, 0,
                               0x8E240B98, 0x0320F809, 0x2685D468,
                               0x2404000B, 0x0C10AC50, 0x00002821])
        # The instruction block pins only an indirect callback plus player
        # event 11. It says nothing about transitive/indirect event producers.


if __name__ == '__main__':
    unittest.main()
