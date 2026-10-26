#!/usr/bin/env python3
"""Pinned native prerequisites for a local per-invocation release witness.

These are source contracts, not installed hooks or proof of arbitrary callback,
computed-target, runtime-import, stack, mutex or native-object lifetime safety.
The global raw-wrapper bridges require extra stack even for rejected callers.
Neither a native zero nor a historical issuance pair is a release certificate.
"""

import hashlib
import struct
import unittest

import reveal_creation_capture_mips as capture
import reveal_registry_receipt_mips as receipt
import test_folderfollow_reveal_static_contract as source


class RegistryReleaseContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.elf = source.Elf32(source.SOURCE)
        digest = hashlib.sha256(cls.elf.data).hexdigest()
        if digest != source.SOURCE_SHA256 or len(cls.elf.data) != source.SOURCE_SIZE:
            raise AssertionError(f'unrecognized reference: SHA-256 {digest}, '
                                 f'size {len(cls.elf.data)}')
        cls.jumps, cls.branches = {}, {}
        for start, end in cls.elf.executable_ranges():
            offset = cls.elf.va_to_off(start)
            data = cls.elf.data[offset:offset + (end - start) // 4 * 4]
            for index, (word,) in enumerate(struct.iter_unpack('<I', data)):
                pc, opcode = start + index * 4, word >> 26
                if opcode in (2, 3):
                    cls.jumps[pc] = (((pc + 4) & 0xF0000000)
                                     | ((word & 0x3FFFFFF) << 2))
                # Conservatively include every REGIMM encoding and COP0..3
                # rs=8 encoding, as well as ordinary/likely integer branches.
                # This proves absence only for these encoded relative forms.
                elif (opcode in (1, 4, 5, 6, 7, 20, 21, 22, 23)
                      or (opcode in (16, 17, 18, 19)
                          and (word >> 21) & 31 == 8)):
                    immediate = word & 0xFFFF
                    if immediate & 0x8000:
                        immediate -= 0x10000
                    cls.branches[pc] = (pc + 4 + immediate * 4) & 0xFFFFFFFF

    def words(self, start, expected):
        for index, word in enumerate(expected):
            pc = start + index * 4
            with self.subTest(pc=f'{pc:#x}'):
                self.assertEqual(self.elf.word(pc), word)

    def test_three_new_displaced_pairs_match_the_hash_pinned_native_image(self):
        expected = {
            'release_call': (0x438A60, (0x0320F809, 0x02002021)),
            'raw_release_call': (0x466DC8, (0x0C296E0C, 0)),
            'raw_release_return': (0x466DD0, (0x8FBF001C, 0x00001021)),
        }
        self.assertEqual(capture.HOOKS, expected)
        for site, pair in expected.values():
            self.words(site, pair)
        self.assertEqual(list(self.elf.executable_ranges()), [receipt.NATIVE_RX])

    def test_actual_unlock_callback_is_loaded_before_jalr_and_its_delay_slot(self):
        self.words(0x438A58, [0xAC620000, 0x8E190278,
                             0x0320F809, 0x02002021])
        self.assertEqual(0x438A60 + 8, 0x438A68)
        # An observer must validate this actual T9, not just reread U+278.
        # The original delay slot supplies U in A0 before the selected call.

    def test_registry_unlock_facade_and_raw_wrapper_have_distinct32_byte_frames(self):
        self.words(0x437DA0, [0x27BDFFE0, 0xAFBF001C,
                             0x0C119B70, 0x8C84013C,
                             0x8FBF001C, 0x03E00008, 0x27BD0020])
        self.words(0x466DC0, [0x27BDFFE0, 0xAFBF001C,
                             0x0C296E0C, 0,
                             0x8FBF001C, 0x00001021,
                             0x03E00008, 0x27BD0020])
        self.assertEqual(self.jumps[0x437DA8], 0x466DC0)

    def test_saved_return_chain_pins_native_sp_and_enclosing_capture_frame(self):
        self.assertEqual(0x437DA8 + 8, 0x437DB0)
        self.assertEqual(0x438A60 + 8, 0x438A68)
        # At raw-wrapper SP=W: W+1C is437DB0, W+3C is438A68,
        # N=W+40 is the registration SP and V=N+28 is the capture SP.
        self.assertEqual(0x20 + 0x1C, 0x3C)
        self.assertEqual(0x20 + 0x20, 0x40)
        self.assertEqual(capture.NATIVE_FRAME, 0x28)
        self.assertEqual(0x40 + capture.NATIVE_FRAME, 0x68)
        self.assertNotEqual((0x437DB0, 0x438A68), (0x437D30, 0x438A10))
        self.words(0x4389F0, [0x27BDFFD8, 0xAFBF0024])

    def test_native40_byte_frame_has_only_three_non_home_unused_scalar_slots(self):
        self.words(0x4389F0, [0x27BDFFD8, 0xAFBF0024,
                             0xAFB10020, 0xAFB0001C])
        explicit = set()
        for pc in range(0x4389F0, 0x438A90, 4):
            word = self.elf.word(pc)
            if (word >> 26 in (32, 33, 35, 36, 37, 40, 41, 43)
                    and (word >> 21) & 31 == 29):
                explicit.add(word & 0xFFFF)
        self.assertEqual(explicit, {0x1C, 0x20, 0x24})
        self.assertEqual(set(range(0x10, 0x1C, 4)) - explicit,
                         {0x10, 0x14, 0x18})
        # Existing acquisition receipts already use these locals. A separate
        # release witness must not pretend that the native frame has extra tail.

    def test_actual_raw_unlock_argument_is_loaded_from13c_before_the_service(self):
        self.words(0x437DA8, [0x0C119B70, 0x8C84013C])
        self.words(0x466DC8, [0x0C296E0C, 0])
        self.assertEqual(self.jumps[0x466DC8], 0xA5B830)
        self.assertEqual(0x466DC8 + 8, 0x466DD0)
        # A0 at raw-call entry is authoritative for this exact service. It is
        # caller-clobbered on return and cannot be reconstructed from U later.

    def test_raw_status_must_be_captured_before_both_native_forced_zeroes(self):
        self.words(0x466DD0, [0x8FBF001C, 0x00001021,
                             0x03E00008, 0x27BD0020])
        self.words(0x438A68, [0x00001021, 0x8FBF0024])
        self.assertLess(0x466DD0, 0x466DD4)
        # FFFFFFFF remains a possible raw status, not a missing-receipt marker.

    def test_raw_plt_and_relocation_name_the_unlock_primitive(self):
        self.words(0xA5B830, [0x3C0F00A7, 0x8DF9FA0C,
                             0x03200008, 0x25F8FA0C])
        self.assertEqual((0xA7 << 16) - 0x5F4, 0xA6FA0C)
        elf = self.elf
        start, size, count = elf.u32(0x20), elf.u16(0x2E), elf.u16(0x30)
        found = []
        for index in range(count):
            rel = start + size * index
            if elf.u32(rel + 4) != 9:  # SHT_REL
                continue
            symbols = start + size * elf.u32(rel + 24)
            self.assertEqual(elf.u32(symbols + 4), 11)  # SHT_DYNSYM
            self.assertEqual(elf.u32(symbols + 36), 16)
            strings = start + size * elf.u32(symbols + 24)
            string_offset = elf.u32(strings + 16)
            offset, length = elf.u32(rel + 16), elf.u32(rel + 20)
            for item in range(offset, offset + length, 8):
                address, info = elf.u32(item), elf.u32(item + 4)
                if address != 0xA6FA0C:
                    continue
                self.assertEqual(info & 0xFF, 127)  # R_MIPS_JUMP_SLOT
                symbol = elf.u32(symbols + 16) + (info >> 8) * 16
                name = elf.data[string_offset + elf.u32(symbol):].split(b'\0', 1)[0]
                found.append(name.decode('ascii'))
        self.assertEqual(found, ['pthread_mutex_unlock'])
        # A symbol/PLT identity is not runtime resolution, initialization,
        # ownership, ordinary-mutex semantics or lifetime evidence.

    def test_no_encoded_absolute_jump_enters_either_word_of_any_new_pair(self):
        for site in (0x438A60, 0x466DC8, 0x466DD0):
            with self.subTest(site=f'{site:#x}'):
                self.assertEqual({pc for pc, target in self.jumps.items()
                                  if target in (site, site + 4)}, set())

    def test_no_encoded_relative_branch_enters_either_word_of_any_new_pair(self):
        for site in (0x438A60, 0x466DC8, 0x466DD0):
            with self.subTest(site=f'{site:#x}'):
                self.assertEqual({pc for pc, target in self.branches.items()
                                  if target in (site, site + 4)}, set())
        # Neither census classifies arbitrary JR/JALR destinations, forged
        # frames, rebound callbacks or runtime-generated executable code.

    def test_global_wrapper_has_many_unrelated_callers_and_raw_unlock_bypasses(self):
        callers = {pc for pc, target in self.jumps.items() if target == 0x466DC0}
        self.assertGreater(len(callers), 100)
        self.assertTrue({0x437D68, 0x437DA8, 0x428BF0} <= callers)
        raw = {pc for pc, target in self.jumps.items() if target == 0xA5B830}
        self.assertEqual(raw, {0x466DC8, 0x57E208, 0x706D4C,
                               0x708FAC, 0x70B46C})
        self.assertEqual({pc for pc, target in self.jumps.items()
                          if target == 0x437DA0}, set())
        # The witness is scoped to one retained wrapper invocation, not all
        # native unlocks or all synchronization users in this executable.

    def test_allocation_failure_still_bypasses_unlock_and_keeps_native_defect(self):
        self.words(0x438A18, [0x10400019, 0x26050034])
        self.words(0x438A80, [0x1000FFFA, 0x2402FFFF])
        self.words(0x438A6C, [0x8FBF0024, 0x8FB10020,
                             0x8FB0001C, 0x03E00008, 0x27BD0028])
        self.assertEqual(self.branches[0x438A18], 0x438A80)
        self.assertEqual(self.branches[0x438A80], 0x438A6C)
        self.assertGreater(0x438A6C, 0x438A60)
        # No receipt is permission for a guessed unlock, retry, cleanup or
        # continuation after the stock missing-unlock allocation failure.


if __name__ == '__main__':
    unittest.main()
