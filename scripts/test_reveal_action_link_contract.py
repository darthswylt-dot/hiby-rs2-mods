#!/usr/bin/env python3
"""Pinned source assumptions for diagnostic 20/36-byte native carriers.

No image is generated or installed here. The new words carry private IDs,
not native-pointer registry keys or a latest/current clock. In particular,
freezing a selected paint parent under its lock proves a selected control-flow
cause, NOT coherence/ownership of the returned native body after unlock.
Direct-call/inbound inventories below are bounded encoded-source censuses;
they do not exclude computed aliases, runtime writes or unknown native users.
Generated hook gates, zero initialization and private ABI are tested elsewhere.
"""

import hashlib
import struct
import unittest

import test_folderfollow_reveal_static_contract as source


ACTION_CALLS = {
    0x42D614, 0x42DEDC, 0x42E31C, 0x42E374, 0x42E398, 0x42E53C,
    0x42E54C, 0x42E5A8, 0x42E5B8, 0x42E79C, 0x42E7AC, 0x42E818,
    0x42E844, 0x42E8F4, 0x48ED24, 0x4CD56C, 0x4EBF00,
}
HOOK_SITES = (0x4BACBC, 0x4BA96C, 0x4BAA58, 0x4909A4,
              0x43C868, 0x4399E8, 0x8B428C)


class RevealActionLinkContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.elf = source.Elf32(source.SOURCE)
        digest = hashlib.sha256(cls.elf.data).hexdigest()
        if digest != source.SOURCE_SHA256 or len(cls.elf.data) != source.SOURCE_SIZE:
            raise AssertionError(f'unrecognized reference: SHA-256 {digest}, '
                                 f'size {len(cls.elf.data)}')

    def words(self, start, expected):
        for index, word in enumerate(expected):
            pc = start + 4 * index
            with self.subTest(pc=f'{pc:#x}'):
                self.assertEqual(self.elf.word(pc), word)

    def code_words(self):
        for start, end in self.elf.executable_ranges():
            offset = self.elf.va_to_off(start)
            data = self.elf.data[offset:offset + (end - start) // 4 * 4]
            for index, (word,) in enumerate(struct.iter_unpack('<I', data)):
                yield start + index * 4, word

    def direct_calls(self, target):
        return {pc for pc, word in self.code_words()
                if word >> 26 == 3
                and (((pc + 4) & 0xF0000000) | ((word & 0x03FFFFFF) << 2)) == target}

    def sp_accesses(self, start, end):
        """Explicit native SP-relative loads/stores, not an alias proof."""
        return {word & 0xFFFF for pc in range(start, end, 4)
                if (word := self.elf.word(pc)) >> 26 in (32, 33, 35, 36, 37, 40, 41, 43)
                and (word >> 21) & 31 == 29}

    def test_action_width_site_is_distinct_from_unchanged_capacity_request(self):
        self.words(0x4BAAEC, [0x24040010, 0x0C115B98, 0x24050010])
        # The design changes ONLY the a1 element width at 4BAAF4: 10 -> 14.
        self.assertEqual(0x24050014 & 0xFFFF, 20)
        self.assertEqual(self.elf.word(0x4BAAEC) & 0xFFFF, 16)
        self.words(0x456E60, [0x08115B10, 0x2406000A])
        # Capacity is a request rounded in chunks of ten, not exactly sixteen.

    def test_paint_width_site_is_distinct_from_unchanged_capacity_request(self):
        self.words(0x439840, [0x27BDFFE0, 0x24050020, 0xAFB00018,
                              0x00808021, 0xAFBF001C, 0x0C115B98,
                              0x24040040, 0xAE020128])
        # The design changes ONLY 439844's a1 width: 20 -> 24 (32 -> 36).
        self.assertEqual(0x24050024 & 0xFFFF, 36)
        self.assertEqual(self.elf.word(0x439858) & 0xFFFF, 64)

    def test_direct_action_producers_all_use_common_native_sender(self):
        self.assertEqual(self.direct_calls(0x4BAC80), ACTION_CALLS)
        self.assertEqual(self.direct_calls(0x4BAAC0), {0x439B58})
        self.words(0x439B58, [0x0C12EAB0, 0, 0xAE0200C4])
        self.words(0x4BAAF8, [0x10400030, 0xAE02001C])
        # This is the audited constructor/sender lineage, not a claim that
        # every unrelated +C4 or +1C field in the binary is this queue.

    def test_native_action_frame_has_free_tail_word_before_saved_s0(self):
        self.words(0x4BAC80, [0x27BDFFC0, 0xAFB30038, 0xAFB20034,
                              0xAFB10030, 0xAFBF003C, 0xAFB0002C])
        self.words(0x4BACCC, [0xAFA20018, 0xAFB30024, 0xAFB2001C,
                              0x0320F809, 0xAFB10020])
        self.words(0x4BAD00, [0x8FB0002C, 0x03E00008, 0x27BD0040])
        self.assertNotIn(0x28, self.sp_accesses(0x4BAC80, 0x4BAD0C))
        self.assertEqual(0x18 + 20, 0x2C)
        # SP+28, NOT SP+2C, is the added word. Every common-sender append
        # must initialize it to an owned ID or zero before native publication.

    def test_common_action_append_remains_inside_native_mutex_and_wake_path(self):
        self.words(0x4BACB4, [0x0C119B68, 0x8E040010,
                              0x8E04001C, 0x24020001, 0x27A50018,
                              0x8C990018, 0xAFA20018, 0xAFB30024,
                              0xAFB2001C, 0x0320F809, 0xAFB10020,
                              0x0C119B70, 0x8E040010,
                              0x0C119B40, 0x8E040014])
        # Native append failure does not gain a new conditional unlock/wake.

    def test_generic_append_index_and_remove_bind_dynamic_element_stride(self):
        self.words(0x456C98, [0x3C020045, 0x24425DA0, 0xAE020018,
                              0x3C020045, 0x24425BC0, 0xAE02001C,
                              0x3C020045, 0x24425860, 0xAE020020])
        self.words(0x456CC8, [0x3C020045, 0x244257E0, 0xAE02002C,
                              0x3C020045, 0x244257C0, 0xAE020024])
        self.words(0x455DA0, [0x00A03021, 0x081156F0, 0x8C85000C])
        self.words(0x455CCC, [0x8EC20010, 0x00139880, 0x00B32821,
                              0x70541802, 0x8CA40000, 0x8FA50048,
                              0x00403021, 0x0C296D10, 0x00642021,
                              0x8EC2000C, 0x24420001, 0xAEC2000C])
        # The full stride copy precedes count publication. Removed/reused
        # storage is not a fresh identity, even when its address is equal.
        self.words(0x455918, [0x00822821, 0x8E040014, 0x8E020010])

    def test_worker_sp1c_is_outside_native_name_buffer_and_saved_registers(self):
        self.words(0x4BA880, [0x27BDDFB0, 0xAFB32034])
        self.words(0x4BA98C, [0x27A40020, 0x00002821,
                              0x0C296F18, 0x24062000])
        self.words(0x4BA974, [0xAFA32020, 0x8C43000C,
                              0x0C10F480, 0xAFA32024])
        self.words(0x4BA8B8, [0xAFB02028])
        self.assertNotIn(0x1C, self.sp_accesses(0x4BA880, 0x4BAAC0))
        self.assertEqual(0x20 + 0x2000 - 1, 0x201F)
        self.assertLess(0x1C + 4, 0x20 + 1)

    def test_selected_action_tail_borrow_hook_is_after_nonnull_get_under_lock(self):
        self.words(0x4BA934, [0x0C119B68, 0x8E640010, 0x8E64001C,
                              0x8C990030, 0x0320F809, 0, 0x1040FFF1,
                              0x0040A821, 0x8E64001C, 0x8C99002C,
                              0x0320F809, 0x00002821, 0x1040FFE4,
                              0x0040B821, 0x8C430004, 0x8C5E0008])
        self.assertLess(0x10, 20)
        # Only the extended selected element's +10 may be borrowed here.
        # There is no record-address registry, post-removal lookup or count ID.

    def test_action_queue_unlock_follows_native_fanout_and_removal(self):
        self.words(0x4BAA70, [0x1000FFA1, 0xAEE00000])
        self.words(0x4BA8F8, [0x8E64001C, 0x00002821, 0x8C990020,
                              0x0320F809, 0x2AB50002, 0x12A0000B,
                              0, 0x0C119B70, 0x8E640010])
        # The loop may select the next item without unlocking. Any new
        # invocation carrier must be overwritten with its ID or zero each time.

    def test_native_callback_arguments_and_return_pc_remain_exact(self):
        self.words(0x4BAA4C, [0x8C590150, 0x13200005, 0x02C02821,
                              0x8FA62024, 0x8FA72020, 0x0320F809,
                              0xAFBE0010])
        self.assertEqual(0x4BAA60 + 8, 0x4BAA68)
        # That RA is the exact incoming gate for explorer's caller frame;
        # the dispatch site alone must not be promoted to callback entry.

    def test_actual_explorer_entry_has_free_sp30_in_its_native_frame(self):
        self.words(0x490980, [0x10800006, 0, 0x10A00004, 0,
                              0x24020001, 0x10C20003, 0,
                              0x03E00008, 0x00001021,
                              0x27BDFFC0, 0xAFBF003C, 0xAFB10038,
                              0xAFB00034])
        self.assertNotIn(0x30, self.sp_accesses(0x490980, 0x490A68))
        self.assertEqual(0x40 + 0x1C, 0x5C)  # worker carrier from explorer frame
        self.assertEqual(0x30 + 4, 0x34)     # before explorer's saved S0

    def test_both_explorer_paint_calls_have_specific_native_return_addresses(self):
        self.words(0x490A08, [0x0C10F218, 0xAFA3001C])
        self.words(0x490A58, [0x0C10F218, 0xAFA20024])
        self.assertEqual({0x490A08 + 8, 0x490A58 + 8}, {0x490A10, 0x490A60})
        self.assertEqual(0x40 + 0x30, 0x70)  # explorer carrier from paint frame
        # Other calls of the common paint producer must carry zero, not a
        # sampled last explorer ID or an address-matched historical record.

    def test_common_paint_entry_has_free_sp38_before_saved_ra(self):
        self.words(0x43C860, [0x10800021, 0, 0x27BDFFC0, 0xAFBF003C,
                              0xAFA00018, 0xAFA0001C, 0x10C00010,
                              0xAFA50020])
        self.assertNotIn(0x38, self.sp_accesses(0x43C860, 0x43C8F0))
        self.assertEqual(0x18 + 32, 0x38)
        self.assertEqual(0x18 + 36, 0x3C)

    def test_all_direct_paint_appends_share_common_initialized_stack_record(self):
        self.assertEqual(self.direct_calls(0x439900), {0x43C8A4, 0x43C8D0})
        self.words(0x43C890, [0xAFA50028, 0x27A50018, 0xAFA80024,
                              0xAFA3002C, 0xAFA70034,
                              0x0C10E640, 0xAFA20030])
        self.words(0x43C8BC, [0x27A50018, 0xAFA70034, 0xAFA00024,
                              0xAFA00028, 0xAFA0002C,
                              0x0C10E640, 0xAFA00030])
        # The added +20 record word must be initialized even for null rects.

    def test_paint_append_and_remove_use_their_existing_native_mutex_brackets(self):
        self.words(0x43990C, [0x8C990284, 0x00808021, 0x0320F809,
                              0xAFA50018, 0x8E040128, 0x8C990018,
                              0x0320F809, 0x8FA50018,
                              0x8E190288, 0x0320F809, 0x02002021])
        self.words(0x43997C, [0x8E040128, 0x8C990020, 0x0320F809,
                              0x8FA50018, 0x8E190288,
                              0x0320F809, 0x02002021])

    def test_paint_getter_hook_freezes_selected_parent_before_native_unlock(self):
        self.words(0x4399C0, [0x27BDFFD8, 0xAFBF0024, 0xAFB00020,
                              0x8C990284, 0x0320F809, 0x00808021,
                              0x8E040128, 0x8C99002C, 0x0320F809,
                              0x00002821, 0x8E190288, 0x02002021,
                              0x0320F809, 0xAFA20018])
        self.assertLess(0x20, 36)  # selected extended paint record's tail
        self.assertEqual(0x4399E0 + 8, 0x4399E8)
        self.assertEqual(0x4399F0 + 8, 0x4399F8)
        # 4399E8 is after indexed get returned and BEFORE unlock at 4399F0.
        # Reading returned_record+20 later at 43C960/BIRTH would be too late.

    def test_getter_saved_ra_gate_identifies_only_the_actual_consumer_frame(self):
        self.assertEqual(self.direct_calls(0x4399C0), {0x43C910})
        self.words(0x43C910, [0x0C10E670, 0x00808821])
        self.assertEqual(0x43C910 + 8, 0x43C918)
        self.assertEqual(self.elf.word(0x4399C4), 0xAFBF0024)
        self.assertEqual(0x28 + 0x18, 0x40)  # G+40 == consumer SP+18
        # The new getter may write this word ONLY with saved RA=43C918.
        # Getter SP+18 itself is native returned-pointer storage, not free.
        self.words(0x4399F4, [0xAFA20018, 0x8FBF0024, 0x8FA20018])

    def test_consumer_sp18_is_unused_by_the_complete_native_consumer(self):
        self.words(0x43C900, [0x27BDFFD8, 0xAFB10020,
                              0xAFBF0024, 0xAFB0001C])
        self.assertNotIn(0x18, self.sp_accesses(0x43C900, 0x43C978))
        self.words(0x43C948, [0x8FBF0024, 0x8FB10020, 0x8FB0001C,
                              0x00001021, 0x03E00008, 0x27BD0028])
        self.assertEqual(0x18 + 4, 0x1C)

    def test_frozen_parent_does_not_certify_native_body_coherence_after_unlock(self):
        self.words(0x43C918, [0x1040000B, 0x00408021, 0x8C420008,
                              0x10400006, 0x02202021,
                              0x0C11A350, 0])
        self.words(0x43C960, [0x8E040008, 0x8E06001C,
                              0x0C116610, 0x2605000C])
        # Native loads after getter unlock remain native borrowed-body loads.
        # An immutable diagnostic parent ID is NOT a lease for these fields.

    def test_actual_birth_link_has_two_exact_native_return_gates(self):
        self.words(0x459840, [0x27BDFFD8, 0xAFB20020, 0xAFB1001C,
                              0xAFB00018, 0xAFBF0024])
        self.words(0x459864, [0x10400006, 0x8FBF0024,
                              0x02402021, 0x02202821,
                              0x0C22D0A0, 0x02003021])
        self.words(0x43C968, [0x0C116610, 0x2605000C])
        self.words(0x8B4280, [0x8C820044, 0x1040004C, 0,
                              0x27BDFFC0, 0xAFB00030, 0xAFBF003C])
        self.assertEqual(0x459874 + 8, 0x45987C)
        self.assertEqual(0x43C968 + 8, 0x43C970)
        # Require BOTH current BIRTH entry RA45987C and the saved wrapper
        # RA43C970, not merely an engine/descriptor pointer matching an ID.

    def test_birth_frame_offsets_reach_frozen_consumer_id_not_recycled_tail(self):
        birth_frame, wrapper_frame = 0x40, 0x28
        self.assertEqual(birth_frame + 0x24, 0x64)
        self.assertEqual(birth_frame + wrapper_frame + 0x18, 0x80)
        # E+64 is 459840's saved RA43C970; E+80 is consumer SP+18.
        # No diagnostic read through the post-unlock native record is needed.

    def test_encoded_direct_inbound_census_has_only_known_explorer_admission(self):
        targets = {site + delta for site in HOOK_SITES for delta in (0, 4)}
        targets.update((0x4BAAF4, 0x439844))
        incoming = set()
        for pc, word in self.code_words():
            op, target = word >> 26, None
            if op in (2, 3):
                target = ((pc + 4) & 0xF0000000) | ((word & 0x03FFFFFF) << 2)
            elif op in (1, 4, 5, 6, 7, 20, 21, 22, 23):
                imm = word & 0xFFFF
                target = pc + 4 + (imm - (0x10000 if imm & 0x8000 else 0)) * 4
            if target in targets:
                incoming.add((pc, target))
        self.assertEqual(incoming, {(0x490994, 0x4909A4)})


if __name__ == '__main__':
    unittest.main()
