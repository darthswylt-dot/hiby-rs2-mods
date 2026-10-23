#!/usr/bin/env python3
"""Pinned paint-payload/removal boundaries, not a new firmware or lease.

The native getter returns a borrowed record after unlocking. These contracts
do not infer thread exclusion, a coherent four-word source snapshot or a live
engine from a global predicate. A known purge uses a DIFFERENT mutex from
the getter, so holding148 is not atomic against every inspected writer.
Adversarial mutations in companion fixtures
are explored interleavings, not proof of actual native thread coverage.
The larger consumer frame below is an unimplemented layout proposal only.
No file/native data mutation, image generation, device or network operation.
"""

import hashlib
import struct
import unittest

import test_folderfollow_reveal_static_contract as source


class RevealPaintPayloadContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.elf = source.Elf32(source.SOURCE)
        digest = hashlib.sha256(cls.elf.data).hexdigest()
        if digest != source.SOURCE_SHA256 or len(cls.elf.data) != source.SOURCE_SIZE:
            raise AssertionError(f'unrecognized reference: SHA-256 {digest}, '
                                 f'size {len(cls.elf.data)}')
        wanted = {0x439900, 0x439960, 0x4399C0, 0x43C900, 0x4396C0}
        cls.calls = {target: set() for target in wanted}
        cls.copy_candidate_entries = set()
        candidates = {0x8B42D4, 0x8B42D8}
        for start, end in cls.elf.executable_ranges():
            offset = cls.elf.va_to_off(start)
            data = cls.elf.data[offset:offset + (end - start) // 4 * 4]
            for index, (word,) in enumerate(struct.iter_unpack('<I', data)):
                pc, op, target = start + index * 4, word >> 26, None
                if op in (2, 3):
                    target = ((pc + 4) & 0xF0000000) | ((word & 0x3FFFFFF) << 2)
                    if op == 3 and target in wanted:
                        cls.calls[target].add(pc)
                elif (op in (1, 4, 5, 6, 7, 20, 21, 22, 23)
                      or (op in (16, 17, 18, 19) and (word >> 21) & 31 == 8)):
                    imm = word & 0xFFFF
                    target = pc + 4 + (imm - (0x10000 if imm & 0x8000 else 0)) * 4
                if target in candidates:
                    cls.copy_candidate_entries.add((pc, target))

    def words(self, start, expected):
        for index, word in enumerate(expected):
            pc = start + index * 4
            with self.subTest(pc=f'{pc:#x}'):
                self.assertEqual(self.elf.word(pc), word)

    def test_complete_native_consumer_has_no_space_for_an_added_36_byte_body(self):
        self.words(0x43C900, [0x27BDFFD8, 0xAFB10020,
                              0xAFBF0024, 0xAFB0001C])
        self.words(0x43C948, [0x8FBF0024, 0x8FB10020, 0x8FB0001C,
                              0x00001021, 0x03E00008, 0x27BD0028])
        # Home words0..F, current private ID18, and saved registers1C..27
        # cannot be overwritten by treating an apparent unused word as a body.
        self.assertLess(0x28 - 0x10, 36)
        self.assertEqual(0x24 + 4, 0x28)

    def test_unimplemented_50_frame_proposal_has_disjoint_body_and_valid_word(self):
        # Arithmetic only: this test does not patch a native frame or redirect
        # v0/S0/arguments. All exact caller/ID and BIRTH bindings need review.
        proposed_frame, body, body_size, valid = 0x50, 0x28, 36, 0x4C
        self.assertEqual(proposed_frame % 8, 0)
        self.assertEqual(body + body_size, valid)
        self.assertEqual(valid + 4, proposed_frame)
        self.assertGreaterEqual(body, 0x24 + 4)  # after native saved RA
        self.assertLess(0x18 + 4, body)          # existing frozen-ID carrier
        self.assertEqual(self.elf.word(0x43C900), 0x27BDFFD8)  # still original28

    def test_common_paint_producer_initializes_all_eight_native_body_words(self):
        self.words(0x43C868, [0x27BDFFC0, 0xAFBF003C, 0xAFA00018,
                              0xAFA0001C, 0x10C00010, 0xAFA50020])
        self.words(0x43C880, [0x8CC50004, 0x8CC80000,
                              0x8CC30008, 0x8CC2000C, 0xAFA50028,
                              0x27A50018, 0xAFA80024, 0xAFA3002C,
                              0xAFA70034, 0x0C10E640, 0xAFA20030])
        self.words(0x43C8BC, [0x27A50018, 0xAFA70034, 0xAFA00024,
                              0xAFA00028, 0xAFA0002C,
                              0x0C10E640, 0xAFA00030])
        # Record: [zero,zero,engine,rect0,rect1,rect2,rect3,metadata]. The
        # existing successor's private ID is a separate ninth word at+20.

    def test_paint_append_copies_the_stack_record_inside_native_bracket(self):
        self.words(0x43990C, [0x8C990284, 0x00808021, 0x0320F809,
                              0xAFA50018, 0x8E040128, 0x8C990018,
                              0x0320F809, 0x8FA50018, 0x8E190288,
                              0x0320F809, 0x02002021])
        self.words(0x439844, [0x24050020])
        self.words(0x439854, [0x0C115B98, 0x24040040, 0xAE020128])
        # Queue locking does not make arbitrary producer rectangle inputs
        # coherent before this caller-owned stack body was assembled.

    def test_getter_selects_zero_under_lock_but_returns_pointer_after_unlock(self):
        self.words(0x4399C0, [0x27BDFFD8, 0xAFBF0024, 0xAFB00020,
                              0x8C990284, 0x0320F809, 0x00808021,
                              0x8E040128, 0x8C99002C, 0x0320F809,
                              0x00002821, 0x8E190288, 0x02002021,
                              0x0320F809, 0xAFA20018, 0x8FBF0024,
                              0x8FA20018, 0x8FB00020,
                              0x03E00008, 0x27BD0028])
        # Getter SP+18 saves only the borrowed return pointer in unlock's
        # delay slot. It is neither an owned body nor storage lasting in caller.
        # The separate known purge below does not share this148 bracket.

    def test_consumer_reads_engine_metadata_and_rectangle_only_after_getter_return(self):
        self.words(0x43C910, [0x0C10E670, 0x00808821, 0x1040000B,
                              0x00408021, 0x8C420008, 0x10400006,
                              0x02202021, 0x0C11A350, 0])
        self.words(0x43C960, [0x8E040008, 0x8E06001C,
                              0x0C116610, 0x2605000C])
        self.assertEqual(0x43C910 + 8, 0x43C918)
        # Its +8 is read twice, separated by a native global predicate call.
        # The four rectangle values are read later by8B4280, not here atomically.

    def test_consumer_does_not_mark_record_zero_or_four_or_write_any_body_word(self):
        record_reads, nonstack_stores = [], []
        for pc in range(0x43C900, 0x43C978, 4):
            word = self.elf.word(pc)
            op, base, offset = word >> 26, (word >> 21) & 31, word & 0xFFFF
            if op == 35 and base in (2, 16):
                record_reads.append((pc, offset))
            if op in (40, 41, 43) and base != 29:
                nonstack_stores.append(pc)
        self.assertEqual(record_reads, [(0x43C920, 8), (0x43C960, 8), (0x43C964, 0x1C)])
        self.assertEqual(nonstack_stores, [])
        # No selected-body field must be written back to advance this path.
        # Progress still requires the original controller/list/index0 removal.

    def test_every_nonnull_outcome_joins_fixed_index_zero_removal(self):
        self.words(0x43C920, [0x8C420008, 0x10400006, 0x02202021,
                              0x0C11A350, 0, 0x1440000A, 0,
                              0x02202021, 0x0C10E658, 0x00002821])
        self.words(0x43C970, [0x1000FFF3, 0x02202021])
        self.assertEqual(0x43C924 + 4 + 6 * 4, 0x43C940)
        self.assertEqual(0x43C970 + 4 - 13 * 4, 0x43C940)
        # Engine0, predicatefalse and render-return all remove U,index0;
        # the redraw wrapper's returned v0 does not condition removal.

    def test_null_getter_result_skips_both_render_and_removal(self):
        self.words(0x43C918, [0x1040000B, 0x00408021])
        self.assertEqual(0x43C918 + 4 + 11 * 4, 0x43C948)
        self.words(0x43C948, [0x8FBF0024, 0x8FB10020, 0x8FB0001C])

    def test_predicate_is_a_global_test_not_controller_or_engine_identity(self):
        self.words(0x468D40, [0x3C0200B9, 0x8C4296D0,
                              0x03E00008, 0x2C420001])
        self.assertEqual(0xB90000 - 0x6930, 0xB896D0)
        # No instruction reads a0. Returning true says only that this global
        # word is zero; it confers no ownership/currentness on the caller's a0.
        for pc in range(0x468D40, 0x468D50, 4):
            self.assertNotEqual((self.elf.word(pc) >> 21) & 31, 4)

    def test_redraw_wrapper_retests_global_then_uses_original_native_call_delay(self):
        self.words(0x459854, [0x00809021, 0x00A08821,
                              0x0C11A350, 0x00C08021, 0x10400006,
                              0x8FBF0024, 0x02402021, 0x02202821,
                              0x0C22D0A0, 0x02003021])
        self.assertEqual(0x459874 + 8, 0x45987C)
        # A global change between the two tests may skip BIRTH; copy or native
        # allocation failure later likewise does not prevent caller removal.

    def test_birth_observer_site_precedes_native_allocation_and_rectangle_reads(self):
        self.words(0x8B4280, [0x8C820044, 0x1040004C, 0,
                              0x27BDFFC0, 0xAFB00030, 0xAFBF003C,
                              0xAFB20038, 0xAFB10034, 0x10A00036,
                              0x00808021, 0x24040010, 0xAFA60028,
                              0x0C22C340, 0x00A09021])
        self.assertLess(0x8B428C, 0x8B42B0)
        self.assertLess(0x8B42B0, 0x8B42C4)
        # Existing BIRTH records an invocation before any native rectangle
        # copy, not proof that bytes already belong to an immutable payload.

    def test_native_rectangle_loads_all_four_words_before_first_copy_store(self):
        self.words(0x8B42C4, [0x8E470000, 0x8E450004, 0x8E430008,
                              0x8E42000C, 0x26040034,
                              0xAE270000, 0xAE250004, 0xAE230008,
                              0x02202821, 0x0C22CF30, 0xAE22000C])
        self.assertEqual(0x8B42E8 + 8, 0x8B42F0)
        self.assertEqual(self.elf.word(0x8B42EC), 0xAE22000C)
        # Final store is append JAL's delay. A four-register observation can
        # record exactly what native read, but the reads may span mutations.

    def test_copy_candidate_has_no_encoded_direct_inbound_and_input_is_not_written(self):
        self.words(0x8B42D4, [0x26040034, 0xAE270000])
        self.assertEqual(self.copy_candidate_entries, set())
        native_input_stores = []
        for pc in range(0x8B42C4, 0x8B4330, 4):
            word = self.elf.word(pc)
            if word >> 26 in (40, 41, 43) and (word >> 21) & 31 == 18:
                native_input_stores.append(pc)
        self.assertEqual(native_input_stores, [])
        # This bounded census excludes computed/runtime entries. There is no
        # payload observation hook or register replacement installed by this test.

    def test_removal_and_destruction_each_use_paint_bracket_and_dynamic_width(self):
        self.words(0x43996C, [0x8C990284, 0x00808021, 0x0320F809,
                              0xAFA50018, 0x8E040128, 0x8C990020,
                              0x0320F809, 0x8FA50018, 0x8E190288,
                              0x0320F809, 0x02002021])
        self.words(0x4398B8, [0x8E040128, 0x10800003, 0,
                              0x0C115BA0, 0, 0x8E190288, 0x02002021,
                              0x0320F809, 0xAE000128])
        self.words(0x45591C, [0x8E040014, 0x8E020010])
        self.words(0x45593C, [0x8E03000C, 0x00001021,
                              0x2463FFFF, 0xAE03000C])
        # A second consumer/remover or destruction after getter unlock is an
        # explored race boundary; a stack copy alone is not an atomic dequeue.

    def test_native_queue_callbacks_bind_the_same_controller_148_mutex(self):
        self.words(0x439AA0, [0xAE020148, 0x3C020043, 0x24427CE0,
                              0xAE020284, 0x3C020043, 0x24427D60,
                              0xAE020288])
        self.words(0x437CE8, [0x0C119B68, 0x8C840148])
        self.words(0x437D68, [0x0C119B70, 0x8C840148])
        self.words(0x466D60, [0x27BDFFE0, 0x24040018, 0xAFBF001C,
                              0x0C119A78, 0xAFB00018, 0x00402021,
                              0x00002821, 0x0C296E28, 0x00408021])
        # Each successful factory call allocates its own24-byte mutex object;
        # different field offsets alone would not prove different live locks.

    def test_known_name_purge_removes_paint_entries_under_different_13c_mutex(self):
        self.words(0x439A64, [0x3C020043, 0x24427D20, 0xAE020274,
                              0x3C020043, 0x24427DA0,
                              0x0C119B58, 0xAE020278])
        self.words(0x437D28, [0x0C119B68, 0x8C84013C])
        self.words(0x437DA8, [0x0C119B70, 0x8C84013C])
        self.words(0x4397AC, [0x8C990274, 0x0080A021, 0x00A09021,
                              0x0320F809, 0x24930034])
        self.words(0x4397F8, [0x0C10E5B0, 0x02402821])
        self.words(0x43980C, [0x8E990278, 0x8FBF002C, 0x8FB30024,
                              0x8FB20020, 0x8FB1001C, 0x8FB00018,
                              0x02802021, 0x8FB40028,
                              0x03200008, 0x27BD0030])
        self.words(0x4396F4, [0x8E240128, 0x8C99002C,
                              0x0320F809, 0x02002821])
        self.words(0x43970C, [0x8C420008, 0x0C296D80,
                              0x8C440000, 0x1040000F, 0])
        self.words(0x439758, [0x8E240128, 0x8C990020,
                              0x0320F809, 0x02002821])
        self.assertEqual(self.calls[0x4396C0], {0x4397F8})
        self.assertNotEqual(0x13C, 0x148)
        # 4396C0 itself takes no148 lock. This known protocol permits neither
        # an all-writer atomic-copy claim under148 nor a proven real overlap:
        # its scheduling/exclusion with both UI loops remains unestablished.

    def test_bounded_direct_call_inventory_does_not_claim_universal_thread_exclusion(self):
        self.assertEqual(self.calls[0x439900], {0x43C8A4, 0x43C8D0})
        self.assertEqual(self.calls[0x4399C0], {0x43C910})
        self.assertEqual(self.calls[0x439960], {0x43C940})
        self.assertEqual(self.calls[0x43C900], {0x43C9AC, 0x43CA8C})
        self.words(0x43C9AC, [0x0C10F240, 0x02002021])
        self.words(0x43CA8C, [0x0C10F240, 0x02002021])
        # Two inspected loop callers are not proof that they cannot overlap,
        # that no indirect caller exists, or that U/engine objects are retained.


if __name__ == '__main__':
    unittest.main()
