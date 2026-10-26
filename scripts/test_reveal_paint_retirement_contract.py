#!/usr/bin/env python3
"""Pinned native premises for a separate cooperative owner-retirement helper.

The original record is NOT44 bytes and the original purge is NOT cooperative.
These checks establish only the bounded raw-list semantics used by an offline
versioned44-byte fixture. They do not install a queue format, retain a native
owner, cover all mutation paths, or authorize a destructor/continuation/UI.
Missing or changed reference input fails rather than skipping these checks.
"""

import hashlib
import unittest

import test_folderfollow_reveal_static_contract as source


class RevealPaintRetirementContractTests(unittest.TestCase):
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

    def direct(self, start, end):
        result = {}
        for pc in range(start, end, 4):
            word = self.elf.word(pc)
            if word >> 26 in (2, 3):
                result[pc] = (((pc + 4) & 0xF0000000)
                              | ((word & 0x3FFFFFF) << 2))
        return result

    def branch(self, pc):
        word = self.elf.word(pc)
        immediate = word & 0xFFFF
        if immediate & 0x8000:
            immediate -= 0x10000
        return pc + 4 + immediate * 4

    def test_get_checks_signed_index_and_count_before_reading_storage(self):
        self.words(0x4557E0, [0x10800016, 0,
                              0x8C82000C, 0x18400013, 0,
                              0x04A00011, 0,
                              0x00A2102A, 0x1040000E, 0])
        for pc in (0x4557E0, 0x4557EC, 0x4557F4, 0x455800):
            self.assertEqual(self.branch(pc), 0x45583C)
        self.words(0x45583C, [0x03E00008, 0x00001021])
        # Null/empty/negative/out-of-range all return null, not an owned copy.

    def test_get_uses_segment_and_width_fields_not_a_fixed_record_format(self):
        self.words(0x455808, [0x8C830014, 0x8C860000, 0x8C820010,
                              0x00A3001A, 0x006001F4,
                              0x00002012, 0x00041880, 0x00C31821,
                              0x00002810, 0x8C640000,
                              0x70A21802, 0x03E00008, 0x00641021])
        self.assertEqual(self.direct(0x4557E0, 0x455844), {})
        # index//segment selects a block; (index%segment)*width selects bytes.
        # The header's existence/heap validity remains a separate premise.

    def test_remove_null_receiver_returns_minus_one_without_a_frame(self):
        self.words(0x455860, [0x10800044, 0, 0x27BDFFD0])
        self.assertEqual(self.branch(0x455860), 0x455974)
        self.words(0x455974, [0x03E00008, 0x2402FFFF])

    def test_remove_empty_or_negative_count_returns_minus_two_before_storage(self):
        self.words(0x455884, [0x8C94000C, 0x1A800030, 0x2402FFFE])
        self.assertEqual(self.branch(0x455888), 0x45594C)
        # The delay slot suppliesFFFFFFFE even on the nonempty path.

    def test_remove_negative_index_preserves_minus_two_before_storage(self):
        self.words(0x455890, [0x04A0002F, 0x8FBF002C])
        self.assertEqual(self.branch(0x455890), 0x455950)
        self.words(0x455950, [0x8FB40028, 0x8FB30024, 0x8FB20020,
                              0x8FB1001C, 0x8FB00018,
                              0x03E00008, 0x27BD0030])

    def test_remove_out_of_range_index_returns_minus_two_before_storage(self):
        self.words(0x455898, [0x00B4102A, 0x10400033, 0x00808021])
        self.assertEqual(self.branch(0x45589C), 0x45596C)
        self.words(0x45596C, [0x1000FFF7, 0x2402FFFE])
        self.assertEqual(self.branch(0x45596C), 0x45594C)
        # All of these refusals precede table/block/element loads and memcpy.

    def test_remove_rounds_used_segment_count_and_locates_requested_block(self):
        self.words(0x4558A4, [0x8C830014, 0x8C910000,
                              0x00A3001A, 0x006001F4,
                              0x0283A021, 0x2694FFFF,
                              0x8C820010, 0x00009012,
                              0x00122880, 0x02258821, 0x00002010,
                              0x0283001A, 0x006001F4,
                              0x10000006, 0x0000A012])
        self.assertEqual(self.branch(0x4558D8), 0x4558F4)
        # ceil(count/segment), not a fixed64/70 pending limit, bounds bridges.

    def test_remove_moves_dynamic_width_remainder_including_spare_slots(self):
        self.words(0x4558F4, [0x00641823, 0x2466FFFF,
                              0x70821802, 0x8E330000,
                              0x26520001, 0x26310004,
                              0x70C23002, 0x00732021,
                              0x0C296D10, 0x00822821])
        # a2=(segment-remainder-1)*width; not merely remaining logical count.
        # Thus a44-byte fixture still requires full mapped allocated segments,
        # including their unused slots. A selected-pointer check is not enough.

    def test_remove_cross_segment_bridge_copies_exactly_one_dynamic_width(self):
        self.words(0x45591C, [0x8E040014, 0x8E020010,
                              0x0254182A, 0x2484FFFF,
                              0x70822802, 0x00403021,
                              0x1460FFEA, 0x00B32021])
        self.assertEqual(self.branch(0x455934), 0x4558E0)
        self.words(0x4558E0, [0x0C296D10, 0x8E250000,
                              0x8E030014, 0x8E020010, 0x00002021])
        # Bridge source is the next block's first element and length=width.

    def test_success_sets_zero_and_decrements_count_once_after_moves(self):
        self.words(0x45593C, [0x8E03000C, 0x00001021,
                              0x2463FFFF, 0xAE03000C])
        count_stores = [pc for pc in range(0x455860, 0x45597C, 4)
                        if self.elf.word(pc) == 0xAE03000C]
        self.assertEqual(count_stores, [0x455948])
        # There is no old-tail zeroing or emitted removal receipt. A new
        # protocol must compare exact owner/entry IDs before this mutation.

    def test_raw_remove_has_only_two_copy_calls_and_no_heap_or_cleanup_calls(self):
        self.assertEqual(self.direct(0x455860, 0x45597C),
                         {0x4558E0: 0xA5B440, 0x455914: 0xA5B440})
        self.assertFalse(any(self.elf.word(pc) >> 26 == 0
                             and self.elf.word(pc) & 63 == 9
                             for pc in range(0x455860, 0x45597C, 4)))
        # This is a bounded encoded-call census. It does not prove libc,
        # runtime callback rebinding, native heap validity or concurrency.

    def test_raw_count_returns_header_word_without_owner_or_claim_check(self):
        self.words(0x455DC0, [0x10800003, 0x3C050092,
                              0x03E00008, 0x8C82000C])
        # A zero count alone is not a retired-owner or native-drain proof.

    def test_raw_clear_only_resets_count_and_cannot_ack_an_outstanding_claim(self):
        self.words(0x4557C0, [0x10800004, 0, 0xAC80000C,
                              0x03E00008, 0x00001021,
                              0x03E00008, 0x2402FFFA])
        self.assertEqual(self.direct(0x4557C0, 0x4557DC), {})
        # Old bytes/claims survive a count reset; this is not cooperative purge.

    def test_stock_purge_compares_borrowed_engine_name_not_generation_tail(self):
        self.words(0x439704, [0x10400006, 0x02402821,
                              0x8C420008, 0x0C296D80,
                              0x8C440000, 0x1040000F, 0])
        self.assertEqual(self.branch(0x439704), 0x439720)
        self.assertEqual(self.branch(0x439718), 0x439758)
        # It dereferences entry+8, then engine+0, before strcmp. Numeric owner
        # generations in a new44-byte format must not reintroduce either load.

    def test_stock_purge_rechecks_same_index_after_each_success_assumption(self):
        self.words(0x439758, [0x8E240128, 0x8C990020,
                              0x0320F809, 0x02002821,
                              0x1000FFEF, 0x8E240128])
        self.assertEqual(self.branch(0x439768), 0x439728)
        self.words(0x439728, [0x8C990030, 0x0320F809, 0,
                              0x0202102A, 0x1440FFEE, 0x8FBF0024])
        self.assertEqual(self.branch(0x439738), 0x4396F4)
        self.words(0x439720, [0x26100001])
        # Removal does not increment; retained/null entries increment once.
        # Unlike a cooperative helper this code does not inspect raw status:
        # a failed removal is not converted into a safe return here.

    def test_stock_remove_facade_erases_raw_status_and_reacquires_paint_mutex(self):
        self.words(0x43996C, [0x8C990284, 0x00808021,
                              0x0320F809, 0xAFA50018,
                              0x8E040128, 0x8C990020,
                              0x0320F809, 0x8FA50018,
                              0x8E190288, 0x0320F809, 0x02002021,
                              0x8FBF0024, 0x8FB00020,
                              0x00001021, 0x03E00008, 0x27BD0028])
        # Do not call this facade while148 is held or trust its zero as raw
        # success; a cooperative walk invokes the pinned raw+20 method.

    def test_stock_name_purge_includes_parent_detach_after_raw_queue_purge(self):
        self.words(0x4397F8, [0x0C10E5B0, 0x02402821,
                              0x8E84002C, 0x0C22C1D8, 0x8E050008])
        self.assertEqual(self.direct(0x4397F8, 0x43980C),
                         {0x4397F8: 0x4396C0, 0x439804: 0x8B0760})
        # Calling439780 for native-like purge would also perform detach;
        # a local retire/drained query must not execute this continuation.

    def test_stock_queue_destructor_frees_storage_before_clearing_binding(self):
        self.words(0x4398B8, [0x8E040128, 0x10800003, 0,
                              0x0C115BA0, 0, 0x8E190288,
                              0x02002021, 0x0320F809, 0xAE000128])
        # Queue destruction is a separate bypass, not a purge option or
        # something a generation drained query can authorize or roll back.


if __name__ == '__main__':
    unittest.main()
