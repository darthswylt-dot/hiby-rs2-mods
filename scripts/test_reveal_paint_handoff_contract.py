#!/usr/bin/env python3
"""Pinned premises for a separate, OFFLINE owned paint handoff helper.

The original producer's borrowed loads, hidden append status and lifecycle
mutations are not fixed by these contracts. No builder/image is changed and
no observed integer or owned rectangle grants engine/controller lifetime,
successful publication, native cleanup or scrolling authority. Findings are
bounded to the hash-pinned original bodies below, not all runtime writers.
"""

import hashlib
import unittest

import test_folderfollow_reveal_static_contract as source


class RevealPaintHandoffContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.elf = source.Elf32(source.SOURCE)
        digest = hashlib.sha256(cls.elf.data).hexdigest()
        if digest != source.SOURCE_SHA256 or len(cls.elf.data) != source.SOURCE_SIZE:
            raise AssertionError(f'unrecognized reference: SHA-256 {digest}, '
                                 f'size {len(cls.elf.data)}')

    def words(self, start, expected):
        for index, word in enumerate(expected):
            pc = start + index * 4
            with self.subTest(pc=f'{pc:#x}'):
                self.assertEqual(self.elf.word(pc), word)

    def test_nonnull_producer_reads_four_borrowed_words_before_append_call(self):
        self.words(0x43C878, [0x10C00010, 0xAFA50020,
                              0x8CC50004, 0x8CC80000,
                              0x8CC30008, 0x8CC2000C,
                              0xAFA50028, 0x27A50018,
                              0xAFA80024, 0xAFA3002C,
                              0xAFA70034, 0x0C10E640,
                              0xAFA20030])
        # All four loads precede439900, hence precede its148 acquisition.
        # Copying this stack body later cannot repair a torn borrowed input.
        self.words(0x43990C, [0x8C990284, 0x00808021,
                              0x0320F809, 0xAFA50018])

    def test_null_rectangle_path_constructs_owned_zero_quad_but_no_lease(self):
        self.words(0x43C8BC, [0x27A50018, 0xAFA70034,
                              0xAFA00024, 0xAFA00028,
                              0xAFA0002C, 0x0C10E640,
                              0xAFA00030])
        # Null rectangle is an explicit zero value, not permission to copy
        # from null or proof that the separately stored engine remains alive.

    def test_original_producer_discards_both_append_call_results(self):
        for pc in (0x43C8AC, 0x43C8D8):
            self.words(pc, [0x8FBF003C, 0x00001021,
                            0x03E00008, 0x27BD0040])
        self.words(0x43C8E8, [0x03E00008, 0x00001021])

    def test_controller_append_facade_hides_raw_status_after_unlock(self):
        self.words(0x43991C, [0x8E040128, 0x8C990018,
                              0x0320F809, 0x8FA50018,
                              0x8E190288, 0x0320F809,
                              0x02002021, 0x8FBF0024,
                              0x8FB00020, 0x00001021,
                              0x03E00008, 0x27BD0028])
        # Neither the facade nor43C860 returns the raw index/error word.

    def test_list_append_method_is_bound_to_index_returning_raw_insert(self):
        self.words(0x456C98, [0x3C020045, 0x24425DA0, 0xAE020018,
                              0x3C020045, 0x24425BC0, 0xAE02001C])
        self.words(0x455DA0, [0x00A03021, 0x081156F0, 0x8C85000C])
        self.words(0x455CF0, [0x8EC2000C, 0x24420001,
                              0xAEC2000C, 0x8FBF003C, 0x02A01021])
        self.words(0x455D94, [0x1000FFD9, 0x2415FFFF])
        # A raw successful first append returns index0. Testing v0!=0
        # would reject that success and acceptFFFFFFFF failure.

    def test_raw_insert_failure_path_includes_null_receiver_and_resize_failure(self):
        self.words(0x455BEC, [0x10800069, 0xAFA60048])
        self.assertEqual(0x455BEC + 4 + 0x69 * 4, 0x455D94)
        self.words(0x455D5C, [0x8EC50014, 0x0C115660,
                              0x02C02021, 0x0440000A, 0])
        self.assertEqual(0x455D68 + 4 + 10 * 4, 0x455D94)

    def test_paint_constructor_passes64_and32_into_segmented_list_factory(self):
        self.words(0x439840, [0x27BDFFE0, 0x24050020,
                              0xAFB00018, 0x00808021,
                              0xAFBF001C, 0x0C115B98,
                              0x24040040, 0xAE020128])
        self.words(0x456E60, [0x08115B10, 0x2406000A])
        # Arguments are initial geometry64, element width32 and segment10;
        # this call is not an original fixed pending-work limit of64.

    def test_constructor_stores_width_segment_count_and_rounded_capacity(self):
        self.words(0x456C7C, [0x02512021, 0x2484FFFF,
                              0x0091001A, 0x022001F4,
                              0xAC40000C, 0xAC530010, 0xAC510014])
        self.words(0x456CFC, [0x00001812, 0x70711002,
                              0x0051001A, 0x022001F4,
                              0xAE020008, 0x0000A812])
        # The encoded rounding of64 by10 yields initial capacity70. This
        # arithmetic explains these fields only; it imposes no hard cap70.
        self.assertEqual(((64 + 10 - 1) // 10) * 10, 70)

    def test_full_raw_insert_can_extend_capacity_by_segment(self):
        self.words(0x455C10, [0x8EC20008, 0x0082102A,
                              0x10400050, 0])
        self.assertEqual(0x455C18 + 4 + 0x50 * 4, 0x455D5C)
        self.words(0x455D5C, [0x8EC50014, 0x0C115660, 0x02C02021])
        self.words(0x4559D4, [0x02B1A821])
        self.words(0x455A9C, [0xAE150008])
        # Capacity+8 is updated by the grow helper; fixed-capacity admission
        # in a new helper therefore needs its own explicit refusal protocol.

    def test_failed_raw_growth_can_mutate_header_even_with_unchanged_count(self):
        self.words(0x4559F8, [0x8E040000, 0x0C119AC8,
                              0x00142880, 0x10400030, 0xAE020000])
        self.assertEqual(0x455A04 + 4 + 0x30 * 4, 0x455AC8)
        self.words(0x455AC8, [0x1000FFEB, 0x2402FFFF])
        # Failed realloc returns null; its branch delay stores that null into
        # list+0 before returningFFFFFFFF. Checking count+C alone therefore
        # cannot prove a failed append left a usable/retryable native list.

    def test_original_getter_returns_borrowed_head_after_releasing148(self):
        self.words(0x4399D8, [0x8E040128, 0x8C99002C,
                              0x0320F809, 0x00002821,
                              0x8E190288, 0x02002021,
                              0x0320F809, 0xAFA20018,
                              0x8FBF0024, 0x8FA20018,
                              0x8FB00020, 0x03E00008, 0x27BD0028])
        # No owned-body transfer is installed at this stock return boundary.

    def test_zero_engine_and_predicate_false_join_current_index_zero_removal(self):
        self.words(0x43C920, [0x8C420008, 0x10400006,
                              0x02202021, 0x0C11A350, 0,
                              0x1440000A, 0, 0x02202021,
                              0x0C10E658, 0x00002821])
        self.assertEqual(0x43C924 + 4 + 6 * 4, 0x43C940)
        self.words(0x43C970, [0x1000FFF3, 0x02202021])
        self.assertEqual(0x43C970 + 4 - 13 * 4, 0x43C940)
        # Even predicate refusal removes the then-current index0, not an
        # exact issued claim. A new claim protocol must cover this branch.

    def test_native_predicate_ignores_receiver_instead_of_validating_engine(self):
        self.words(0x468D40, [0x3C0200B9, 0x8C4296D0,
                              0x03E00008, 0x2C420001])
        # This global test is not a lifetime/current-owner validation.

    def test_resource_retirement_must_precede_unlink_name_and_queue_destruction(self):
        self.words(0x439610, [0x8E020004, 0x8E030000,
                              0xAC620004, 0xAC430000,
                              0xAE000000, 0x12400003,
                              0xAE000004, 0x0C119AA0,
                              0x02402021, 0x8E020008,
                              0x24050001, 0x0C22CFC0,
                              0x8C440034, 0x0C22D088,
                              0x8E040008, 0x0C119AA0, 0x02002021])
        # Intercepting only8B4220 at439644 would leave earlier destructive
        # effects already committed. A deferred continuation needs the bundle.

    def test_detach_mutates_neighbors_before_clearing_parent_or_freeing_link(self):
        self.words(0x8B078C, [0x10400021, 0x00408021,
                              0x8C430008, 0x10600002,
                              0x8C42000C, 0xAC62000C,
                              0x10400002, 0, 0xAC430008])
        self.words(0x8B07BC, [0x26450004, 0x02202021,
                              0x0C22C1B8, 0xAE400040,
                              0x0C22C348, 0x02002021])
        self.words(0x8B080C, [0x1000FFEB, 0xAE220028])
        # The post-lookup gate must precede8B0794, covering both neighbor
        # and head paths, not merely engine+40 at8B07C8 or link free8B07CC.

    def test_controller_fence_must_precede_worker_shutdown_and_mutex_destruction(self):
        self.words(0x43CB34, [0x00808821, 0x0C123D48,
                              0x8C840030, 0x0C12EAF8,
                              0x8E2400C4, 0x0C11EB80, 0x02202021])
        self.words(0x43CB80, [0x02202021, 0x0C10E628, 0xAE20012C])
        self.words(0x43CC20, [0x0C119B78, 0, 0xAE200148])
        self.words(0x43CC44, [0x0C119B78, 0, 0x1000FFF1, 0xAE20013C])
        # A copied body alone cannot retain controller workers or mutexes.

    def test_direct_resource_deletion_exception_cannot_rely_on_name_purge(self):
        self.words(0x502924, [0x8FA20018, 0x10400007, 0x3C050092,
                              0x8C443B8C, 0x10800004, 0,
                              0x0C130310, 0, 0x3C050092,
                              0x02002021, 0x0C10E568, 0x24A52CF0])
        # In this bounded body the null branch reaches4395A0 without the
        # conditional other callee and without a439780 call. No claim is made
        # about the other callee's complete behavior or computed callers.
        calls = [self.elf.word(pc) for pc in range(0x502900, 0x502954, 4)]
        self.assertNotIn(0x0C10E5E0, calls)  # jal439780


if __name__ == '__main__':
    unittest.main()
