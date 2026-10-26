#!/usr/bin/env python3
"""Bounded native owner-carrier gaps; no generation is inferred from pointers.

These pinned source checks do not install hooks or establish complete indirect
caller coverage, a retained native context, initialized mutexes, object lifetime
or a producer-generation transport. In particular, a historical owner binding
cannot be recovered as the latest row matching a native engine or node.
"""

import hashlib
import struct
import unittest

import test_folderfollow_reveal_static_contract as source


PAINT_CALLERS = {
    0x490634, 0x490A08, 0x490A58, 0x497918, 0x4A6F44,
    0x4DC714, 0x515584, 0x51D064, 0x51DB98,
}


class OwnerCarrierContractTests(unittest.TestCase):
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
                pc = start + index * 4
                if word >> 26 in (2, 3):
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

    def test_nine_encoded_paint_callers_are_not_only_the_explorer_action_branch(self):
        incoming = {pc for pc, target in self.edges.items() if target == 0x43C860}
        self.assertEqual(incoming, PAINT_CALLERS)
        for pc in incoming:
            self.assertEqual(self.elf.word(pc) >> 26, 3)
        # This includes J and JAL in executable bytes, not computed targets,
        # callback rebinding, alternate entries or runtime-generated aliases.

    def test_no_file_backed_aligned_literal_is_a_common_paint_entry_pointer(self):
        matches = set()
        for address, offset, size, _, _ in self.elf.loads:
            data = self.elf.data[offset:offset + (size & ~3)]
            for index, (word,) in enumerate(struct.iter_unpack('<I', data)):
                if word == 0x43C860:
                    matches.add(address + index * 4)
        self.assertEqual(matches, set())
        # Absence in this bounded form does not exclude computed indirect use.

    def test_native_producer_copies_four_arguments_not_an_owner_generation(self):
        self.words(0x43C870, [0xAFA00018, 0xAFA0001C,
                              0x10C00010, 0xAFA50020,
                              0x8CC50004, 0x8CC80000,
                              0x8CC30008, 0x8CC2000C,
                              0xAFA50028, 0x27A50018,
                              0xAFA80024, 0xAFA3002C,
                              0xAFA70034, 0x0C10E640,
                              0xAFA20030])
        self.assertEqual(self.direct(0x43C860, 0x43C8F0),
                         {0x43C8A4: 0x439900, 0x43C8D0: 0x439900})
        # A1 is an engine scalar, A2 points to four rectangle words and A3
        # is metadata. None is an independently captured logical generation.

    def test_native64_byte_frame_cannot_hold_an_in_place44_byte_record(self):
        self.words(0x43C868, [0x27BDFFC0, 0xAFBF003C])
        self.assertEqual(0x18 + 32, 0x38)
        self.assertEqual(0x18 + 36, 0x3C)
        self.assertEqual(0x18 + 44, 0x44)
        # The saved RA occupies the first extra word after the existing
        # 36-byte diagnostic record. A 44-byte copy would corrupt the frame
        # and incoming caller area; widening a native queue is insufficient.
        accesses = []
        for pc in range(0x43C860, 0x43C8F0, 4):
            word = self.elf.word(pc)
            if word >> 26 in (32, 33, 35, 36, 37, 40, 41, 43):
                if (word >> 21) & 31 == 29:
                    accesses.append(word & 0xFFFF)
        self.assertNotIn(0x50, accesses)  # incoming O32 fifth argument

    def test_all_native_producer_returns_zero_instead_of_a_publication_receipt(self):
        self.words(0x43C8AC, [0x8FBF003C, 0x00001021,
                              0x03E00008, 0x27BD0040])
        self.words(0x43C8D8, [0x8FBF003C, 0x00001021,
                              0x03E00008, 0x27BD0040,
                              0x03E00008, 0x00001021])
        # Queue append failure and a null controller do not produce a new
        # checked publication nonce, captured owner or lifetime authority.

    def test_constructor_wrappers_ignore_registration_status_and_return_raw_engine(self):
        for pc in (0x43AE94, 0x43B038):
            self.words(pc, [0x0C1467E8, 0x02202021,
                             0x8FA20050, 0x0C10DFB8, 0x8C440000])
        self.words(0x43AEAC, [0x8FA20050])
        self.words(0x43B050, [0x8FA20050])
        self.assertEqual(self.edges[0x43AE8C], 0x4389E0)
        self.assertEqual(self.edges[0x43B030], 0x4389E0)
        # Neither return transports the exact issuer invocation's owner. An
        # outer nonnull engine cannot repair a denied or absent issuance.

    def test_native_engine_tail_is_callback_context_not_a_verified_spare_owner_field(self):
        self.words(0x8B4134, [0x0C22C340, 0x24040054])
        self.words(0x8B4190, [0xAE020048, 0x8E220030,
                              0xAE02004C, 0x8E220034, 0xAE020050])
        self.words(0x43AE48, [0xAFB1004C])
        # Descriptor SP18+34=SP4C contains U and is copied to engine+50.
        # The allocation ends at+54. Extending it requires a new layout and
        # every allocation/copy/user/free path, not a post-allocation tail read.

    def test_registry_node_contains_links_and_five_scalars_not_a_generation(self):
        self.words(0x438A10, [0x0C119A78, 0x2404001C])
        self.words(0x438A20, [0x8E230004, 0xAC43000C,
                              0x8E230000, 0xAC430008,
                              0x8E230010, 0xAC430018,
                              0x8E23000C, 0xAC430014,
                              0x8E230008, 0xAC430010])
        self.words(0x438A50, [0xAC450000, 0xAC430004, 0xAC620000])
        # A matching node or engine address is historical scalar equality,
        # not permission to borrow a new generation from another registration.

    def test_explorer_callback_route_is_registered_and_queued_but_has_no_owner_word(self):
        self.words(0x4928A8, [0x3C050049, 0x02402021,
                              0x0C116560, 0x24A50980])
        self.words(0x459580, [0x10800004, 0, 0xAC850150,
                              0x03E00008, 0x00001021])
        self.words(0x4BAA4C, [0x8C590150, 0x13200005, 0x02C02821,
                              0x8FA62024, 0x8FA72020,
                              0x0320F809, 0xAFBE0010])
        self.words(0x4BA96C, [0x8C430004, 0x8C5E0008,
                              0xAFA32020, 0x8C43000C,
                              0x0C10F480, 0xAFA32024])
        # The callback's fifth argument already carries selected action+8.
        # Its engine A1 is found by native fanout; this queue has no verified
        # independently retained owner-generation context for that engine.

    def test_explorer_paint_uses_engine_parent_and_rectangles_not_registry_owner_lookup(self):
        self.words(0x4909B4, [0x8CB10050])
        self.words(0x4909DC, [0x04E00015, 0x02202021])
        self.words(0x490A08, [0x0C10F218, 0xAFA3001C])
        self.words(0x490A58, [0x0C10F218, 0xAFA20024])
        # Engine+50 supplies U, not an owner ticket. Neither this ancestry nor
        # an existing historical notification ID is a creation-generation lease.


if __name__ == '__main__':
    unittest.main()
