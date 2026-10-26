#!/usr/bin/env python3
"""Pin the bounded native sites used by an offline registry lock receipt.

These checks describe original instructions only. They do not install hooks,
authenticate arbitrary forged stacks, prove mutex initialization/lifetime, or
authorize generation issuance, retention, deferred cleanup, or native frees.
The native caller still proceeds after a masked raw acquisition failure.
"""

import hashlib
import struct
import unittest

import reveal_registry_receipt_mips as receipt
import test_folderfollow_reveal_static_contract as source


class RevealRegistryReceiptContractTests(unittest.TestCase):
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

    def test_begin_pair_precedes_actual_callback_and_preserves_its_delay_slot(self):
        self.words(0x438A00, [0x8C990274, 0x00808021,
                              0x0320F809, 0x00A08821])
        # The first pair loads the actual callback into T9 and establishes
        # controller S0. The original callback return is438A10; its delay slot
        # establishes descriptor S1. Initializing a carrier at that return
        # instead would be too late to precede the raw acquisition.
        self.assertEqual(0x438A08 + 8, 0x438A10)

    def test_excluded_native_executable_extent_matches_the_entire_pinned_image(self):
        self.assertEqual(receipt.NATIVE_RX, (0x400000, 0xA5BFA0))
        self.assertEqual(list(self.elf.executable_ranges()), [receipt.NATIVE_RX])
        # Emitted bridge code and private objects must not shadow even an
        # otherwise unreferenced instruction in this original executable span.

    def test_native_carrier_slots_are_not_homes_saved_registers_or_native_locals(self):
        self.words(0x4389F0, [0x27BDFFD8, 0xAFBF0024,
                              0xAFB10020, 0xAFB0001C])
        explicit_offsets = set()
        for pc in range(0x4389F0, 0x438A90, 4):
            word = self.elf.word(pc)
            if word >> 26 in (32, 33, 35, 36, 37, 40, 41, 43):
                if (word >> 21) & 31 == 29:
                    explicit_offsets.add(word & 0xFFFF)
        self.assertEqual(explicit_offsets, {0x1C, 0x20, 0x24})
        for offset in (0x10, 0x14, 0x18):
            self.assertGreaterEqual(offset, 4 * 4)
            self.assertLess(offset + 3, 0x1C)
            self.assertNotIn(offset, explicit_offsets)
        # This is bounded native integer-memory coverage, not a claim that
        # arbitrary rebound callbacks or non-ABI code respect these locals.

    def test_acquisition_saved_return_chain_has_two_distinct32_byte_frames(self):
        self.words(0x437D20, [0x27BDFFE0, 0xAFBF001C,
                              0x0C119B68, 0x8C84013C,
                              0x8FBF001C, 0x03E00008, 0x27BD0020])
        self.words(0x466DA0, [0x27BDFFE0, 0xAFBF001C])
        self.assertEqual(self.edges[0x437D28], 0x466DA0)
        self.assertEqual(0x437D28 + 8, 0x437D30)
        # At wrapper SP=W, saved returns are W+1C=437D30 and W+3C=438A10.
        # The native caller's three local carriers are consequently W+50/54/58.
        self.assertEqual(0x20 + 0x1C, 0x3C)
        self.assertEqual(tuple(0x20 + 0x20 + local
                               for local in (0x10, 0x14, 0x18)),
                         (0x50, 0x54, 0x58))

    def test_raw_call_pair_passes_actual_mutex_argument_before_any_result_exists(self):
        self.words(0x466DA8, [0x0C296E58, 0])
        self.assertEqual(self.edges[0x466DA8], 0xA5B960)
        self.assertEqual(0x466DA8 + 8, 0x466DB0)
        # A0 was loaded from U+13C in the enclosing callback's delay slot.
        # A pre-call receipt stage can compare this actual argument with its
        # separately pinned mutex scalar. A post-service A0 is caller-clobbered.
        self.words(0x437D2C, [0x8C84013C])

    def test_raw_return_pair_is_the_last_status_observation_before_native_mask(self):
        self.words(0x466DB0, [0x8FBF001C, 0x00001021,
                              0x03E00008, 0x27BD0020])
        # Any observer must capture raw V0 before replaying the forced zero.
        # CapturedFFFFFFFF is a real scalar status, not a missing marker.
        self.assertNotEqual(0x466DB0, 0x466DB4)

    def test_ordinary_raw_lock_plt_preserves_the_resolved_service_result(self):
        self.words(0xA5B960, [0x3C0F00A7, 0x8DF9FA58,
                              0x03200008, 0x25F8FA58])
        # The bounded PLT body jumps through A6FA58; existing relocation
        # contracts name pthread_mutex_lock. Import resolution, initialization
        # and the native mutex allocation's lifetime are still caller premises.
        self.assertEqual(((0xA7 << 16) - 0x5A8) & 0xFFFFFFFF, 0xA6FA58)

    def test_publication_observer_must_replay_final_link_store_before_observation(self):
        self.words(0x438A48, [0x8E030038, 0xAE020038,
                              0xAC450000, 0xAC430004,
                              0xAC620000, 0x8E190278])
        self.words(0x438A60, [0x0320F809, 0x02002021])
        # Replacing438A58/5C displaces the final old-tail link store and only
        # then the unlock-callback load. No raw unlock result exists here yet.
        self.assertEqual(0x438A60 + 8, 0x438A68)

    def test_unlock_chain_is_not_acquisition_and_failure_path_keeps_native_defect(self):
        self.words(0x437DA0, [0x27BDFFE0, 0xAFBF001C,
                              0x0C119B70, 0x8C84013C])
        self.words(0x466DC0, [0x27BDFFE0, 0xAFBF001C,
                              0x0C296E0C, 0])
        self.assertEqual(0x437DA8 + 8, 0x437DB0)
        self.assertEqual(self.edges[0x466DC8], 0xA5B830)
        self.assertNotEqual((0x437DB0, 0x438A68), (0x437D30, 0x438A10))
        self.words(0x438A80, [0x1000FFFA, 0x2402FFFF])
        self.words(0x438A6C, [0x8FBF0024, 0x8FB10020,
                              0x8FB0001C, 0x03E00008, 0x27BD0028])
        # Allocation failure branches directly to the epilogue, bypassing
        # native unlock. A passive receipt must neither hide nor repair it.
        immediate = self.elf.word(0x438A80) & 0xFFFF
        self.assertEqual(0x438A84 + (immediate - 0x10000) * 4, 0x438A6C)

    def test_no_encoded_absolute_jump_enters_any_displaced_pair_in_this_image(self):
        for site in (0x438A00, 0x466DA8, 0x466DB0, 0x438A58):
            with self.subTest(site=f'{site:#x}'):
                self.assertEqual({pc for pc, target in self.edges.items()
                                  if target in (site, site + 4)}, set())
        # Encoded J/JAL census only: not runtime-computed targets, arbitrary
        # callbacks, alternate entry routes, complete branch or alias coverage.


if __name__ == '__main__':
    unittest.main()
