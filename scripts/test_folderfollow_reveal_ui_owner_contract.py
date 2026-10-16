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

    def test_explorer_recreate_uses_path_depth_name_and_closes_first(self):
        self.words(0x49E6D8, [0x27A30024, 0x24630002, 0x3844005C,
                               0x94620000, 0x2C840001, 0x1440FFFB,
                               0x00C43021, 0x24C6FFFF, 0x18C00012,
                               0x00000000])
        self.words(0x49E700, [0x3C050094, 0x27A40AA8, 0x0C296D5C,
                               0x24A52124])
        self.words(0x49E710, [0x02202021, 0x0C10EC90, 0x27A50AA8,
                               0x02202021, 0x0C126890, 0x27A50024,
                               0x1440FFB7, 0x02202021, 0x27A50AA8,
                               0x0C1247A0, 0x27A60024])
        self.words(0x49E744, [0x3C050092, 0x27A40AA8, 0x0C296D5C,
                               0x24A52704, 0x1000FFEF, 0x02202021])
        for address, expected in (
                (0x942124, b'vg_listview_explorer##%d'),
                (0x922704, b'vg_listview_explorer')):
            offset = self.elf.va_to_off(address)
            with self.subTest(address=f'{address:#x}'):
                self.assertEqual(self.elf.data[offset:offset + len(expected) + 1],
                                 expected + b'\0')

    def test_storage_open_cleans_explorer_before_restore_or_fallback(self):
        self.assertEqual(self.direct_calls(0x495D40),
                         [0x49D4A8, 0x49D524, 0x49D560])
        self.assertEqual(self.direct_calls(0x495A40), [0x495D60])
        self.assertEqual(self.direct_calls(0x495B80), [0x495D78])
        self.words(0x495D60, [0x0C125690, 0x00808021, 0x0C1BCB48,
                               0x02202021, 0x04400010, 0x3C050092,
                               0x0C1256E0, 0x02002021])
        self.words(0x495D84, [0x00409021, 0x2404000B, 0x0C1093D8,
                               0x24A50AB4, 0x1240000A])
        self.words(0x495DC0, [0x3C050092, 0x02002021, 0x02203021,
                               0x0C1247A0, 0x24A52704])
        for call, delay, address, expected in (
                (0x49D4A8, 0x26454504, 0x944504, 'b:\\*'),
                (0x49D524, 0x26454510, 0x944510, 'c:\\*'),
                (0x49D560, 0x264544F8, 0x9444F8, 'a:\\*')):
            self.words(call, [0x0C125750, delay])
            offset = self.elf.va_to_off(address)
            encoded = expected.encode('utf-16le') + b'\0\0'
            with self.subTest(call=f'{call:#x}'):
                self.assertEqual(self.elf.data[offset:offset + len(encoded)],
                                 encoded)

    def test_storage_cleanup_copies_explorer_names_under_lock_then_closes(self):
        self.words(0x495A40, [0x27BDF848, 0x00002821, 0x24060780,
                               0xAFB507AC, 0x0080A821, 0x27A40018,
                               0xAFBF07B4, 0xAFB607B0])
        self.words(0x495A78, [0x8EB90274, 0x02A02021, 0x0320F809,
                               0x26B60034])
        self.words(0x495AAC, [0x0C296D38, 0x02602021, 0x8E030008,
                               0x02602821, 0x00403021, 0x8C720000,
                               0x02208021, 0x0C296E90, 0x02402021])
        self.words(0x495AD0, [0x1440FFF4, 0x00142180, 0x27A20018,
                               0x00442021, 0x02402821, 0x0C296FB8,
                               0x26940001, 0x2A82001E, 0x1440FFEC,
                               0x00000000])
        self.words(0x495AF8, [0x8EB90278, 0x0320F809, 0x02A02021,
                               0x00008021])
        self.words(0x495B08, [0x00102980, 0x27A20018, 0x02A02021,
                               0x00452821, 0x0C10EC90, 0x26100001,
                               0x1614FFFA, 0x00102980])

        prefix_offset = self.elf.va_to_off(0x922704)
        prefix = b'vg_listview_explorer\0'
        self.assertEqual(self.elf.data[prefix_offset:
                                       prefix_offset + len(prefix)], prefix)

    def test_main_explorer_open_closes_dynamic_view_names_first(self):
        # This is the controller's ordered view list at +0x298, distinct from
        # the storage cleanup list and +0x3BA8 name slots. The entry's view
        # object supplies its named widget via +0xCC. Same-owner views created
        # through 0x491E80 are included. The callback's constructor owner is
        # traced separately below; this loop does not retain arbitrary views.
        self.words(0x495260, [0x27BDFF98, 0xAFB0005C, 0x00808021,
                               0xAFB10060, 0x27A40018, 0x00002821,
                               0x24060040, 0xAFBF0064, 0x0C296F18,
                               0x26110298])
        self.words(0x495298, [0x8E020298, 0x10510005, 0x27A40018,
                               0x8C420008, 0x8C4200CC, 0x0C296FB8,
                               0x8C450000, 0x83A20018, 0x14400005,
                               0x8FBF0064])
        self.words(0x4952D0, [0x02002021, 0x0C10EC90, 0x27A50018,
                               0x83A20018, 0x1440FFEA, 0x27A40018])
        self.assertIn(0x4952D4, self.direct_calls(0x43B240))
        self.words(0x4E55A4, [0x8E830298, 0x00408821, 0x00009021,
                               0x10730010, 0x8C700000, 0x1220000B,
                               0x02202021, 0x8C620008])
        # A newly constructed view stores its supplied owner at +0xD4,
        # creates a named list widget at +0xCC, and registers itself in that
        # owner's +0x298 list through 0x4E5280.
        self.words(0x491FC0, [0xAE003BA0, 0xAE1000E0, 0x0C119A58,
                               0xAE0300D4])
        self.words(0x492908, [0x8FA417D0, 0x3C060049, 0x27A516E4,
                               0x24C63AC0, 0x0C10EB40, 0x02003821,
                               0x8FA417D0, 0xAE0200CC])
        self.words(0x492A38, [0x8FA417D0, 0x0C1394A0, 0x02002821])
        self.words(0x4E52C0, [0x8E1902A4, 0x0320F809, 0x02002021,
                               0xAE320008, 0x8E02029C, 0x26030298,
                               0xAE11029C, 0xAE230000, 0xAE220004,
                               0xAC510000, 0x8E1902A8])

        # Closing through 0x43B240 invokes the list-view destructor, which
        # unlinks the view from its saved parent under the same mutex.
        self.words(0x493C6C, [0x8E0400D4, 0x0C139528, 0x02002821])
        self.assertEqual(self.direct_calls(0x4E54A0),
                         [0x493C70, 0x493F70])
        self.words(0x4E54C4, [0x8C9902A4, 0x0080A021, 0x00A09021,
                               0x0320F809, 0x24930298, 0x8E900298,
                               0x16130006, 0x8E110000, 0x10000011])
        self.words(0x4E54F8, [0x8E040008, 0x0C296D80, 0x02402821,
                               0x1440FFF9, 0x02002021, 0x8E020004,
                               0x8E030000, 0xAC620004, 0xAC430000,
                               0xAE000000, 0x0C119AA0, 0xAE000004,
                               0x8E9902A8])

        # Unlike insertion/removal, the 0x495260 walk itself has no mutex
        # callback: its complete direct-call set contains only string helpers
        # and the close facade, and there is no jalr in the body.
        close_walk_calls = []
        indirect_calls = []
        for pc in range(0x495260, 0x4952F0, 4):
            word = self.elf.word(pc)
            if word >> 26 == 3:
                target = (((pc + 4) & 0xF0000000)
                          | ((word & 0x03FFFFFF) << 2))
                close_walk_calls.append((pc, target))
            elif word >> 26 == 0 and word & 0x3F == 9:
                indirect_calls.append(pc)
        self.assertEqual(close_walk_calls,
                         [(0x495280, 0xA5BC60), (0x495290, 0xA5BC60),
                          (0x4952AC, 0xA5BEE0), (0x4952D4, 0x43B240)])
        self.assertEqual(indirect_calls, [])

        # Both handlers read the engine object's saved owner. They have data
        # table bindings rather than direct JAL callers, as tested below.
        self.words(0x49DCC0, [0x27BDFFD8, 0xAFBF0024, 0xAFB10020,
                               0xAFB0001C, 0x8CB00050])
        self.words(0x49E560, [0x27BDF500, 0xAFBF0AFC, 0xAFB40AF8,
                               0xAFB30AF4, 0xAFB20AF0, 0xAFB10AEC,
                               0xAFB00AE8, 0x8CB10050])
        self.assertEqual(self.direct_calls(0x49DCC0), [])
        self.assertEqual(self.direct_calls(0x49E560), [])
        self.words(0x49DDB0, [0x0C125498, 0x02002021, 0x3C110094,
                               0x3C060094, 0x02002021, 0x262519E8,
                               0x0C1247A0, 0x24C62374])
        self.assertIn(0x49DDB0, self.direct_calls(0x495260))
        explorer_name = b'vg_listview_main_explorer\0'
        name_offset = self.elf.va_to_off(0x9419E8)
        self.assertEqual(self.elf.data[name_offset:
                                       name_offset + len(explorer_name)],
                         explorer_name)

    def test_navigation_callback_tables_preserve_constructor_owner(self):
        # address-xrefs scans executable address forms, so its empty result
        # cannot rule out these file-backed callback-table pointers.
        for index, name, callback in (
                (40, b'vg_listview_main_category', 0x49DCC0),
                (1, b'vg_listview_main_explorer', 0x49D3A0),
                (2, b'vg_listview_explorer', 0x49E560)):
            table = 0xA98610 + index * 0x20C + 0x10C
            with self.subTest(table=f'{table:#x}'):
                offset = self.elf.va_to_off(table)
                self.assertEqual(self.elf.data[offset:offset + len(name) + 1],
                                 name + b'\0')
                self.assertEqual(self.elf.word(table + 0x48), callback)
        # The config lookup copies the callback record into the constructor's
        # output; binding consumes output+0x10C and installs event 7 at R+160.
        # It removes the ## suffix before matching the base config record.
        self.assertEqual(self.elf.word(0x4A03B4), 0x00A09821)
        self.assertEqual(self.elf.word(0x4A0440), 0x3C1400AA)
        self.assertEqual(self.elf.word(0x4A0454), 0x26948610)
        marker = self.elf.va_to_off(0x9225A0)
        self.assertEqual(self.elf.data[marker:marker + 3], b'##\0')
        self.words(0x4A040C, [0x3C050092, 0x27A4019C, 0x0C296C90,
                               0x24A525A0, 0x10400005, 0x00408021,
                               0x8FA40218, 0x0C296FB8, 0x00402821,
                               0xA2000000])
        self.words(0x4A06B8, [0x24060060, 0x02518821, 0x02308023,
                               0x00108080, 0x02901021, 0x8C430104,
                               0x2445010C, 0x2664010C])
        self.words(0x4A06F8, [0x0C296D10, 0xAE620174])
        self.words(0x492340, [0x8FA417D4, 0x8FA717D8, 0x27A514D8,
                               0x0C1280E8, 0x27A6178C])
        self.words(0x4928F4, [0x8FA417D0, 0x26450020, 0x27A615E4,
                               0x0C10F008, 0x24070001])
        self.words(0x43C0D0, [0x8E050048, 0x8C4400D0, 0xAC850160])

        # U is stored in V+D4 and also in descriptor+34. 8B4120 copies that
        # field into engine object O+50; O+4C is the 43B320 event callback.
        self.words(0x491FBC, [0x8FA317D0, 0xAE003BA0, 0xAE1000E0,
                               0x0C119A58, 0xAE0300D4])
        self.words(0x43AD28, [0x00808821, 0x00A08021])
        self.words(0x43AE44, [0x27A40018, 0xAFB1004C, 0xAFA20030,
                               0x3C020044, 0x24429EC0, 0xAFA20044,
                               0x3C020044, 0x2442B320, 0x0C22D048,
                               0xAFA20048])
        self.assertEqual(self.elf.word(0x8B4128), 0x00808821)
        self.assertEqual(self.elf.word(0x8B4140), 0x00408021)
        self.words(0x8B4194, [0x8E220030, 0xAE02004C, 0x8E220034,
                               0xAE020050])
        # 43B320 passes (U,O,R,msg) to 438EA0, which dispatches (O,R,msg).
        # 43BB40's event-7 tail then passes (R,O,msg) to the table handler.
        self.words(0x43B34C, [0x8C900050, 0x3C130092, 0x00809021,
                               0x26642730, 0x0C296D38, 0x00A08821])
        self.words(0x43B4F4, [0x02002021, 0x02402821, 0x02803021,
                               0x0C10E3A8, 0x02203821])
        self.words(0x438ED8, [0x00C0A821, 0x00809821, 0x00A0A021,
                               0x10620004, 0x00E09021])
        self.words(0x4390F4, [0x8EB90138, 0x13200018, 0x8FB70048,
                               0x8FB60044, 0x8FB30038, 0x8FB10030,
                               0x8FB0002C, 0x02802021, 0x02A02821,
                               0x8FB4003C, 0x8FB50040, 0x02403021,
                               0x8FB20034, 0x03200008, 0x27BD0050])
        self.words(0x43BB54, [0x8CC20000, 0x24030007, 0x00808021,
                               0x10430054, 0x8C920050])
        self.words(0x43BCD8, [0x8CB90160, 0x00A02021, 0x02203021,
                               0x1000FFBD, 0x02002821])
        self.words(0x43BBDC, [0x8FBF002C, 0x8FB20028, 0x8FB10024,
                               0x8FB00020, 0x03200008, 0x27BD0030])
        # Storage restore/fallback and row navigation pass the inherited U
        # back into creation, preserving it through the ordinary folder chain.
        self.assertEqual(self.elf.word(0x49D3B4), 0x8CB10050)
        for pc in (0x49D4A4, 0x49D520, 0x49D55C):
            self.words(pc, [0x02202021, 0x0C125750])
        self.assertEqual(self.elf.word(0x495B90), 0x0080B821)
        self.words(0x495CD0, [0x02E02021, 0x27A50C18, 0x27A60418,
                               0x24140001, 0x0C1247A0, 0x26730001])
        self.words(0x495DC0, [0x3C050092, 0x02002021, 0x02203021,
                               0x0C1247A0, 0x24A52704])

    def test_navigation_input_returns_before_next_timer_in_music_loop(self):
        # This is an ordering proof for the inspected loop invocation, not
        # evidence that no other loop or indirect caller can run concurrently.
        self.words(0x43C9E4, [0x0C11CD58, 0])
        self.words(0x43CA1C, [0x8E040028, 0x27A50018, 0xAE02011C,
                               0x8FA20024, 0x0C22C6A8, 0xAE020120,
                               0x1000FFDB, 0])
        self.assertEqual(self.elf.word(0x8B1ACC), 0x00803821)
        self.words(0x8B1AE8, [0x8CE40008, 0x3C06008B, 0x02002821,
                               0x0C22D330, 0x24C616A0])
        self.words(0x8B4CE8, [0x00C08821, 0x10430041, 0x00E09021])
        self.words(0x8B4DC8, [0x02402021, 0x0220C821, 0x0320F809,
                               0x27A50018])
        self.words(0x8B16C8, [0x8CA20000, 0x2442FFFC, 0x2C430007,
                               0x00A08821, 0x1460001D, 0x8C940010])
        self.words(0x8B1750, [0x3C03009F, 0x00021080, 0x24634740,
                               0x00621021, 0x8C420000, 0x00400008, 0])
        self.assertEqual(self.elf.word(0x9F4740 + (7 - 4) * 4), 0x8B176C)
        self.words(0x8B176C, [0x8E840000, 0x10800025, 0,
                               0x8C99004C, 0x13200022])
        self.words(0x8B17F4, [0x0320F809, 0x27A50018])

    def test_music_list_close_before_create_callers_are_name_scoped(self):
        # The direct 0x49D000 caller family passes fixed music-list names to
        # 0x495060. A third syntactic call sits in 0x49D0E0, whose reachability
        # is unresolved and is not silently treated as covered.
        self.assertEqual(self.direct_calls(0x495060),
                         [0x49D070, 0x49D18C, 0x49D9BC])
        self.assertEqual(self.direct_calls(0x49D000),
                         [0x49E940, 0x49EAB8, 0x49F4B8, 0x4A0098])
        for call, delay, address, expected in (
                (0x49E940, 0x24C614F4, 0x9414F4,
                 b'vg_listview_albums_of_an_artist'),
                (0x49EAB8, 0x24C61AD4, 0x941AD4,
                 b'vg_listview_albums_of_a_genre'),
                (0x49F4B8, 0x24C61514, 0x941514,
                 b'vg_listview_songs_of_an_album'),
                (0x4A0098, 0x24C61AF4, 0x941AF4,
                 b'vg_listview_songs_of_an_album_artist')):
            with self.subTest(call=f'{call:#x}'):
                self.assertEqual(self.elf.word(call), 0x0C127400)
                self.assertEqual(self.elf.word(call + 4), delay)
                offset = self.elf.va_to_off(address)
                self.assertEqual(self.elf.data[
                    offset:offset + len(expected) + 1], expected + b'\0')

        self.words(0x49D9B0, [0x3C050094, 0x02202021, 0x24A51D10,
                               0x0C125418, 0x27A60018])
        expected = b'vg_listview_songs_of_format\0'
        offset = self.elf.va_to_off(0x941D10)
        self.assertEqual(self.elf.data[offset:offset + len(expected)],
                         expected)

    def test_playlist_view_replacement_does_not_close_folder_explorer(self):
        self.words(0x49E668, [0x02202021, 0x0C10EC90, 0x2645271C,
                               0x02202021, 0x0C10E830, 0x2645271C,
                               0x1440FFE1, 0x2645271C, 0x8E0400D4,
                               0x0C1247A0, 0x27A60024])
        offset = self.elf.va_to_off(0x92271C)
        expected = b'vg_listview_m3ulist\0'
        self.assertEqual(self.elf.data[offset:offset + len(expected)],
                         expected)

    def test_main_category_and_songlist_closures_are_not_folder_explorer(self):
        self.words(0x49DF34, [0x3C050094, 0x02202021, 0x0C10EC90,
                               0x24A51CE0, 0xAE000084, 0xAE0041E0])
        self.words(0x49DFA0, [0x02202021, 0x0C10EC90, 0x26651CC4,
                               0xAE000084, 0xAE0041E0])
        for address, expected in (
                (0x941CC4, b'vg_listview_main_category\0'),
                (0x941CE0, b'vg_listview_main_songlist\0')):
            offset = self.elf.va_to_off(address)
            with self.subTest(address=f'{address:#x}'):
                self.assertEqual(self.elf.data[offset:offset + len(expected)],
                                 expected)

    def test_listview_owner_has_named_slot_close_routes(self):
        # Eight 64-byte name slots are addressed from owner +0x3BA8. The
        # slot is resolved through 0x4E5320, and named slots are synchronously
        # closed by the controller; this does not prove every slot's content.
        self.words(0x492A88, [0x00129980, 0x26633BA8, 0x0203B821,
                               0x02802021, 0x02E02821, 0x0C1394C8,
                               0x27A61798])
        self.words(0x493034, [0x26520001, 0x24020008, 0x1642FE93,
                               0x00129980])
        self.words(0x492B18, [0x92E40002, 0x24050003, 0x14450005,
                               0x2484FFA1, 0x14800134, 0x26653BA8,
                               0x92E40003, 0x2484FF94, 0x1480012F,
                               0x24020001, 0xAE223DCC, 0x02802021,
                               0x0C10EC90, 0x02E02821])
        self.words(0x493114, [0x02E02021, 0x0C296D80, 0x02C02821,
                               0x1000FE85, 0x00402021])
        self.words(0x4931C0, [0x92E20000, 0x10800011, 0x2442FF8A,
                               0x14400147, 0x00000000, 0x92E20001,
                               0x24050001, 0x1085000B, 0x2442FF99,
                               0x14400141, 0x00000000, 0x92E20002,
                               0x24050003, 0x14850005, 0x2442FFA1,
                               0x1440013C, 0x02802021, 0x92E20003,
                               0x2442FF94, 0x14400137, 0x02802021,
                               0x0C10EC90, 0x02E02821])
        for pc in (0x49302C, 0x4930D8, 0x493214, 0x4936FC):
            with self.subTest(pc=f'{pc:#x}'):
                self.assertIn(pc, self.direct_calls(0x43B240))

        offset = self.elf.va_to_off(0x9419E8)
        expected = b'vg_listview_main_explorer\0'
        self.assertEqual(self.elf.data[offset:offset + len(expected)],
                         expected)

    def test_unresolved_explorer_retarget_helper_is_not_owner_evidence(self):
        # This body implements the same depth-derived explorer replacement,
        # but the bounded reference scan found no direct caller or pointer
        # literal. Its enclosing routine only stores this address in a local
        # stack slot and does not reload that slot.
        self.words(0x527920, [0x0C296D5C, 0x24A52124, 0x02002021,
                               0x0C10EC90, 0x27A50260, 0x02002021,
                               0x0C126890, 0x27A50018, 0x1440000B,
                               0x24060040, 0x02002021, 0x27A50260,
                               0x0C1247A0, 0x27A60018])
        self.words(0x5279F4, [0x0C296D5C, 0x26452704,
                               0x1000FFCB, 0x02002021])
        self.words(0x527C98, [0x3C030052, 0x24637860])
        self.assertEqual(self.elf.word(0x527CD4), 0xAFA3022C)
        fmt_offset = self.elf.va_to_off(0x942124)
        fmt = b'vg_listview_explorer##%d\0'
        self.assertEqual(self.elf.data[fmt_offset:fmt_offset + len(fmt)], fmt)
        self.assertEqual(self.direct_calls(0x527860), [])

        pointer_literals = [
            vaddr + relative
            for vaddr, offset, filesz, _, _ in self.elf.loads
            for relative in range(0, filesz & ~3, 4)
            if self.elf.u32(offset + relative) == 0x527860
        ]
        self.assertEqual(pointer_literals, [])

        local_reads = [
            pc for start, end in self.elf.executable_ranges()
            for pc in range(0x527C60, min(0x527F00, end & ~3), 4)
            if (self.elf.word(pc) >> 26) in (32, 33, 35, 36, 37)
            and ((self.elf.word(pc) >> 21) & 31) == 29
            and (self.elf.word(pc) & 0xFFFF) == 0x22C
        ]
        self.assertEqual(local_reads, [])

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
