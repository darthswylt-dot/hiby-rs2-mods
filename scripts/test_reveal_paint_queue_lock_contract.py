#!/usr/bin/env python3
"""Pinned native lock-order/lifecycle premises for a host-only coordinator.

The common copy/claim protocol is NOT installed by these tests. Bounded
instruction/call inventories are not universal exclusion, scheduler, callback,
engine/controller retention or UI authority proofs. Distinct receiver types
may use the same displacement; only the constructor-bound controller routes
below are classified. No firmware/image, player or network writes occur.
"""

import hashlib
import struct
import unittest

import test_folderfollow_reveal_static_contract as source


class RevealPaintQueueLockContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.elf = source.Elf32(source.SOURCE)
        digest = hashlib.sha256(cls.elf.data).hexdigest()
        if digest != source.SOURCE_SHA256 or len(cls.elf.data) != source.SOURCE_SIZE:
            raise AssertionError(f'unrecognized reference: SHA-256 {digest}, '
                                 f'size {len(cls.elf.data)}')
        cls.edges = {}
        for start, end in cls.elf.executable_ranges():
            offset = cls.elf.va_to_off(start)
            data = cls.elf.data[offset:offset + (end - start) // 4 * 4]
            for index, (word,) in enumerate(struct.iter_unpack('<I', data)):
                if word >> 26 in (2, 3):
                    pc = start + index * 4
                    cls.edges[pc] = (((pc + 4) & 0xF0000000)
                                     | ((word & 0x3FFFFFF) << 2))

    def words(self, start, expected):
        for index, word in enumerate(expected):
            pc = start + index * 4
            with self.subTest(pc=f'{pc:#x}'):
                self.assertEqual(self.elf.word(pc), word)

    def direct(self, start, end):
        return {pc: target for pc, target in self.edges.items()
                if start <= pc < end}

    def inbound(self, target):
        return {pc for pc, destination in self.edges.items()
                if destination == target}

    def jalrs(self, start, end):
        return {pc for pc in range(start, end, 4)
                if self.elf.word(pc) >> 26 == 0
                and self.elf.word(pc) & 63 == 9}

    def test_constructor_binds_distinct_registry_and_paint_callbacks(self):
        self.words(0x439A60, [0xAE02013C, 0x3C020043, 0x24427D20,
                              0xAE020274, 0x3C020043, 0x24427DA0,
                              0x0C119B58, 0xAE020278])
        self.words(0x439AA0, [0xAE020148, 0x3C020043, 0x24427CE0,
                              0xAE020284, 0x3C020043, 0x24427D60,
                              0xAE020288])
        # Factory allocation and default attribute argument, not an assumed
        # recursive-mutex implementation or a whole-controller lifetime lease.
        self.words(0x466D64, [0x24040018, 0xAFBF001C,
                              0x0C119A78, 0xAFB00018,
                              0x00402021, 0x00002821, 0x0C296E28])

    def test_bound_callbacks_load_their_actual_mutex_fields(self):
        for pc, call, field in ((0x437CE8, 0x0C119B68, 0x148),
                                (0x437D68, 0x0C119B70, 0x148),
                                (0x437D28, 0x0C119B68, 0x13C),
                                (0x437DA8, 0x0C119B70, 0x13C)):
            self.words(pc, [call, 0x8C840000 | field])
        self.assertEqual(self.direct(0x466DA0, 0x466DC0),
                         {0x466DA8: 0xA5B960})
        self.assertEqual(self.direct(0x466DC0, 0x466DE0),
                         {0x466DC8: 0xA5B830})

    def test_four_known_paint_sections_have_only_the_expected_calls(self):
        # These are classified receivers from the constructor, NOT a global
        # claim that every +284/+288 load refers to this controller.
        sections = (
            (0x4398A0, 0x4398F0, {0x4398C4: 0x456E80},
             {0x4398B0, 0x4398D4}, 0x4398AC, 0x4398CC),
            (0x439900, 0x43994C, {},
             {0x439914, 0x439924, 0x439930}, 0x43990C, 0x43992C),
            (0x439960, 0x4399AC, {},
             {0x439974, 0x439984, 0x439990}, 0x43996C, 0x43998C),
            (0x4399C0, 0x439A0C, {},
             {0x4399D0, 0x4399E0, 0x4399F0}, 0x4399CC, 0x4399E8),
        )
        for start, end, edges, indirect, acquire, release in sections:
            with self.subTest(section=f'{start:#x}'):
                self.assertEqual(self.direct(start, end), edges)
                self.assertEqual(self.jalrs(start, end), indirect)
                self.assertEqual(self.elf.word(acquire) & 0xFFFF, 0x284)
                self.assertEqual(self.elf.word(release) & 0xFFFF, 0x288)
                # Bounded absence of another controller callback load only.
                self.assertFalse(any(
                    self.elf.word(pc) >> 26 == 35
                    and (self.elf.word(pc) >> 16) & 31 == 25
                    and self.elf.word(pc) & 0xFFFF in (0x274, 0x278)
                    for pc in range(start, end, 4)))

    def test_known_list_methods_are_bound_and_contain_no_nested_registry_call(self):
        self.words(0x456C98, [0x3C020045, 0x24425DA0, 0xAE020018])
        self.words(0x456CB0, [0x3C020045, 0x24425860, 0xAE020020])
        self.words(0x456CC8, [0x3C020045, 0x244257E0, 0xAE02002C])
        expected = (
            (0x4557E0, 0x455844, {}),
            (0x455860, 0x45597C,
             {0x4558E0: 0xA5B440, 0x455914: 0xA5B440}),
            (0x455980, 0x455AD0,
             {0x4559FC: 0x466B20, 0x455A30: 0xA5BC60,
              0x455A4C: 0x4669E0, 0x455A6C: 0xA5BC60}),
            (0x455BC0, 0x455DA0,
             {0x455CA0: 0xA5B440, 0x455CE8: 0xA5B440,
              0x455D48: 0xA5B440, 0x455D60: 0x455980}),
            (0x455DA0, 0x455DAC, {0x455DA4: 0x455BC0}),
            (0x456E80, 0x456F44,
             {0x456EE8: 0x466A80, 0x456F10: 0x466A80,
              0x456F1C: 0x466A80}),
        )
        for start, end, edges in expected:
            with self.subTest(method=f'{start:#x}'):
                self.assertEqual(self.direct(start, end), edges)
                self.assertEqual(self.jalrs(start, end), set())
        # This census stops at heap/libc services, and is not a statement
        # about arbitrary replacement methods or runtime callback rebinding.

    def test_raw_removal_moves_dynamic_width_and_decrements_count(self):
        self.words(0x455914, [0x0C296D10, 0x00822821,
                              0x8E040014, 0x8E020010])
        self.words(0x45593C, [0x8E03000C, 0x00001021,
                              0x2463FFFF, 0xAE03000C])
        self.words(0x43997C, [0x8E040128, 0x8C990020,
                              0x0320F809, 0x8FA50018])
        # Direct raw +20 invocation is different from reentering439960,
        # whose facade reacquires148 and is not a recursive-lock contract.

    def test_name_purge_holds13c_across_the_only_raw_purge_call(self):
        self.words(0x4397AC, [0x8C990274, 0x0080A021, 0x00A09021,
                              0x0320F809, 0x24930034])
        self.words(0x4397F8, [0x0C10E5B0, 0x02402821,
                              0x8E84002C, 0x0C22C1D8, 0x8E050008])
        self.words(0x43980C, [0x8E990278])
        self.words(0x439824, [0x02802021, 0x8FB40028,
                              0x03200008, 0x27BD0030])
        self.assertEqual(self.inbound(0x4396C0), {0x4397F8})

    def test_raw_purge_selects_and_removes_paint_entries_without148_bracket(self):
        self.words(0x4396D4, [0x00808821, 0x8C840128, 0x00A09021,
                              0x8C990030, 0x0320F809, 0x00008021])
        self.words(0x4396F4, [0x8E240128, 0x8C99002C,
                              0x0320F809, 0x02002821])
        self.words(0x43970C, [0x8C420008, 0x0C296D80,
                              0x8C440000, 0x1040000F, 0])
        self.words(0x439758, [0x8E240128, 0x8C990020,
                              0x0320F809, 0x02002821])
        self.assertEqual(self.direct(0x4396C0, 0x439770),
                         {0x439710: 0xA5B600})
        self.assertEqual(self.jalrs(0x4396C0, 0x439770),
                         {0x4396E4, 0x4396FC, 0x43972C, 0x439760})

    def test_purge_rechecks_count_without_incrementing_removed_index(self):
        self.words(0x439720, [0x26100001, 0x8E240128, 0x8C990030,
                              0x0320F809, 0, 0x0202102A,
                              0x1440FFEE, 0x8FBF0024])
        self.words(0x439768, [0x1000FFEF, 0x8E240128])
        self.assertEqual(0x439768 + 4 - 17 * 4, 0x439728)
        self.assertEqual(0x439738 + 4 - 18 * 4, 0x4396F4)

    def test_bounded_census_has55_purge_and56_engine_destructor_edges(self):
        purge, destroy = self.inbound(0x439780), self.inbound(0x4395A0)
        self.assertEqual(len(purge), 55)
        self.assertEqual(len(destroy), 56)
        self.assertEqual(destroy, {pc + 12 for pc in purge} | {0x50294C})
        # Only encoded direct J/JAL edges, not computed callers or scheduling.

    def test_direct_destructor_exception_has_no_purge_in_its_bounded_body(self):
        self.words(0x502924, [0x8FA20018, 0x10400007, 0x3C050092,
                              0x8C443B8C, 0x10800004, 0,
                              0x0C130310, 0, 0x3C050092,
                              0x02002021, 0x0C10E568, 0x24A52CF0])
        self.assertNotIn(0x439780, self.direct(0x502900, 0x502954).values())
        self.assertEqual(self.edges[0x50294C], 0x4395A0)
        # No claim that the other callee4C0C40 has no unrelated teardown;
        # its null branch can reach this direct call without invoking it.

    def test_engine_destructor_under13c_does_not_purge_or_take148(self):
        self.words(0x4395C0, [0x8C990274, 0x0080A821, 0x00A0A021,
                              0x0320F809, 0x24930034])
        self.words(0x439610, [0x8E020004, 0x8E030000,
                              0xAC620004, 0xAC430000, 0xAE000000])
        self.words(0x43962C, [0x0C119AA0, 0x02402021,
                              0x8E020008, 0x24050001, 0x0C22CFC0,
                              0x8C440034, 0x0C22D088, 0x8E040008,
                              0x0C119AA0, 0x02002021, 0x8EB90278])
        self.assertEqual(self.direct(0x4395A0, 0x439680),
                         {0x439600: 0xA5B600, 0x43962C: 0x466A80,
                          0x43963C: 0x8B3F00, 0x439644: 0x8B4220,
                          0x43964C: 0x466A80})
        self.assertEqual(self.jalrs(0x4395A0, 0x439680), {0x4395CC})
        self.words(0x439678, [0x03200008, 0x27BD0038])

    def test_actual_engine_free_is_not_an_inflight_or_reference_count_release(self):
        self.assertEqual(self.inbound(0x8B4220), {0x439644})
        self.words(0x8B4234, [0x00808021, 0x0C22D6E8,
                              0x8C840044, 0x0C22C348, 0x02002021])
        self.words(0x8B0D20, [0x27BDFFE0, 0xAFBF001C,
                              0x0C296E70, 0])
        # These concrete frees do not establish an outstanding-consumer lease.
        self.assertEqual(self.direct(0x8B4220, 0x8B4264),
                         {0x8B4238: 0x8B5BA0, 0x8B4240: 0x8B0D20})

    def test_parent_detach_clears_parent_and_frees_link_not_engine_lease(self):
        self.words(0x8B07BC, [0x26450004, 0x02202021,
                              0x0C22C1B8, 0xAE400040,
                              0x0C22C348, 0x02002021])
        self.words(0x439800, [0x8E84002C, 0x0C22C1D8, 0x8E050008])
        self.assertNotIn(0x8B4220, self.direct(0x8B0760, 0x8B0820).values())
        # Parent-membership cancellation is a separate obligation even if
        # the numeric engine allocation remains readable.

    def test_controller_destruction_releases148_before_acquiring13c(self):
        self.assertEqual(self.inbound(0x4398A0), {0x43CB84})
        self.words(0x43CB80, [0x02202021, 0x0C10E628, 0xAE20012C,
                              0x8E390274, 0x02202021,
                              0x0320F809, 0x26320034])
        self.words(0x4398CC, [0x8E190288, 0x02002021,
                              0x0320F809, 0xAE000128])
        self.words(0x4398E8, [0x03E00008, 0x27BD0020])
        # Sequential148 then13C does not create a nested148->13C edge.

    def test_controller_shutdown_calls_workers_before_queue_and_mutex_deletion(self):
        self.words(0x43CB38, [0x0C123D48, 0x8C840030,
                              0x0C12EAF8, 0x8E2400C4,
                              0x0C11EB80, 0x02202021])
        self.words(0x4BABF0, [0x8C840014, 0x24020001, 0xAE020004,
                              0x0C119B40, 0])
        self.words(0x4BAC04, [0x0C119B68, 0x8E04000C,
                              0x0C119B70, 0x8E04000C])
        # A stop flag and completion-like mutex handshake do not establish
        # all caller lifetimes, both UI-loop identities or full shutdown coverage.

    def test_controller_teardown_destroys_the_actual13c_and148_mutexes(self):
        self.words(0x43CC08, [0x8E24013C, 0x1480000D, 0,
                              0x8E240148, 0x10800005, 0x8FBF0024,
                              0x0C119B78, 0, 0xAE200148])
        self.words(0x43CC44, [0x0C119B78, 0,
                              0x1000FFF1, 0xAE20013C])
        self.words(0x466DEC, [0x0C296C3C, 0x00808021,
                              0x12000004, 0x8FBF001C,
                              0x0C119AA0, 0x02002021])
        # Merely holding a private request copy does not retain its controller.

    def test_source_has_a13c_held_redraw_call_without_paint_mutex_nesting(self):
        self.words(0x43A3EC, [0x8E190274, 0x02002021,
                              0x0320F809, 0x26130034])
        self.words(0x43A440, [0x00602821, 0x0C116610, 0x00003021,
                              0x8E190278, 0x0320F809, 0x02002021])
        self.assertEqual(self.direct(0x43A3EC, 0x43A458),
                         {0x43A41C: 0x43A060, 0x43A444: 0x459840})
        self.assertEqual(self.jalrs(0x43A3EC, 0x43A458),
                         {0x43A3F4, 0x43A450})
        # This is a positive native lock-order precedent, not a license to
        # run arbitrary UI callbacks under13C or assert universal reentrancy.

    def test_bounded_redraw_copy_path_has_no_encoded_ui_callback(self):
        expected = (
            (0x459840, 0x459894,
             {0x45985C: 0x468D40, 0x459874: 0x8B4280}),
            (0x8B4280, 0x8B43C0,
             {0x8B42B0: 0x8B0D00, 0x8B42E8: 0x8B3CC0,
              0x8B4340: 0x8B3220, 0x8B436C: 0x8B06E0}),
            (0x8B3CC0, 0x8B3D60, {0x8B3CE0: 0x8B0D00}),
            (0x8B06E0, 0x8B0748,
             {0x8B06F4: 0x8B3220, 0x8B072C: 0x8B3140}),
        )
        for start, end, edges in expected:
            with self.subTest(body=f'{start:#x}'):
                self.assertEqual(self.direct(start, end), edges)
                self.assertEqual(self.jalrs(start, end), set())
        self.words(0x459874, [0x0C22D0A0, 0x02003021])
        self.words(0x8B42E8, [0x0C22CF30, 0xAE22000C])
        # Only these bodies are covered; heap/geometry services, later render
        # callbacks, runtime modifications and full scheduler remain outside.


if __name__ == '__main__':
    unittest.main()
