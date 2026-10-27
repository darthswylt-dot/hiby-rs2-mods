#!/usr/bin/env python3
"""Bounded native premises for a separate owned68-byte deferred envelope.

The original action queue is16 bytes, not an owner-scoped envelope queue.
These hash-pinned source contracts describe native copy/get/remove behavior
and known generation-loss boundaries; they do not install helpers, widen a
stock queue, establish exclusive access, retain objects or admit UI work.
Missing/mismatched reference input fails rather than skipping these checks.
"""

import hashlib
import unittest

import reveal_creation_capture_mips as capture
import test_folderfollow_reveal_static_contract as source


class DeferredEnvelopeContractTests(unittest.TestCase):
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

    def branch(self, pc):
        immediate = self.elf.word(pc) & 0xFFFF
        if immediate & 0x8000:
            immediate -= 0x10000
        return pc + 4 + immediate * 4

    def direct(self, start, end):
        result = {}
        for pc in range(start, end, 4):
            word = self.elf.word(pc)
            if word >> 26 in (2, 3):
                result[pc] = (((pc + 4) & 0xF0000000)
                              | ((word & 0x3FFFFFF) << 2))
        return result

    def test_factory_width_is_independent_of_capacity_and_fixed_chunkcount(self):
        self.words(0x456E60, [0x08115B10, 0x2406000A])
        self.words(0x456C40, [0x27BDFFC8, 0xAFB20024,
                             0x00809021, 0x24040038])
        self.words(0x456C68, [0x00A09821, 0x0C119A78,
                             0x00C08821])
        self.words(0x456C8C, [0xAC40000C, 0xAC530010, 0xAC510014])
        self.assertEqual(capture.OUTPUT_BYTES + 9 * 4, 68)
        #456E60(initial_capacity,68) would produce a separate typed queue.
        #Its requested capacity is rounded in chunks of10, not an exact cap.

    def test_constructor_binds_the_audited_raw_list_methods(self):
        self.words(0x456C98, [0x3C020045, 0x24425DA0, 0xAE020018,
                             0x3C020045, 0x24425BC0, 0xAE02001C,
                             0x3C020045, 0x24425860, 0xAE020020])
        self.words(0x456CC8, [0x3C020045, 0x244257E0, 0xAE02002C,
                             0x3C020045, 0x244257C0, 0xAE020024,
                             0x3C020045, 0x24425DC0, 0xAE020030])
        #Header+18/+20/+2C are append/remove/get, not a stock callback ABI.
        #Runtime replacement methods and arbitrary header corruption are not
        #excluded by this constructor-bound source observation.

    def test_append_copies_dynamic_width_before_count_and_returns_index(self):
        self.words(0x455DA0, [0x00A03021, 0x081156F0, 0x8C85000C])
        self.words(0x455CCC, [0x8EC20010, 0x00139880, 0x00B32821,
                             0x70541802, 0x8CA40000, 0x8FA50048,
                             0x00403021, 0x0C296D10, 0x00642021,
                             0x8EC2000C, 0x24420001, 0xAEC2000C,
                             0x8FBF003C, 0x02A01021])
        self.assertLess(0x455CE8, 0x455CF8)
        #Successful v0 is the previous insertion index:0,1,..., not a raw
        #mutex status. A positive index does not mean failure or paint ack.

    def test_get_checks_signed_bounds_and_returns_only_a_borrowed_pointer(self):
        self.words(0x4557E0, [0x10800016, 0, 0x8C82000C,
                             0x18400013, 0, 0x04A00011, 0,
                             0x00A2102A, 0x1040000E, 0])
        for pc in (0x4557E0, 0x4557EC, 0x4557F4, 0x455800):
            self.assertEqual(self.branch(pc), 0x45583C)
        self.words(0x455808, [0x8C830014, 0x8C860000, 0x8C820010,
                             0x00A3001A, 0x006001F4, 0x00002012,
                             0x00041880, 0x00C31821, 0x00002810,
                             0x8C640000, 0x70A21802, 0x03E00008,
                             0x00641021])
        self.assertEqual(self.direct(0x4557E0, 0x455844), {})
        #No copy/retain occurs. Owned work must be packed before removal or
        #any concurrent mutation, under separately established exclusivity.

    def test_remove_relocates_full_width_and_reuses_the_selected_head_storage(self):
        self.words(0x4558F4, [0x00641823, 0x2466FFFF, 0x70821802,
                             0x8E330000, 0x26520001, 0x26310004,
                             0x70C23002, 0x00732021,
                             0x0C296D10, 0x00822821])
        self.words(0x45591C, [0x8E040014, 0x8E020010,
                             0x0254182A, 0x2484FFFF,
                             0x70822802, 0x00403021,
                             0x1460FFEA, 0x00B32021])
        self.words(0x45593C, [0x8E03000C, 0x00001021,
                             0x2463FFFF, 0xAE03000C])
        self.assertEqual(self.direct(0x455860, 0x45597C),
                         {0x4558E0: 0xA5B440, 0x455914: 0xA5B440})
        #At index0 the following element moves over the borrowed head. Native
        #remove zero acknowledges extraction only; it invokes no paint ack.
        #Moves include allocated spare slots, not just logical live bytes.

    def test_clear_only_resets_count_without_wiping_or_retiring_envelopes(self):
        self.words(0x4557C0, [0x10800004, 0, 0xAC80000C,
                             0x03E00008, 0x00001021,
                             0x03E00008, 0x2402FFFA])
        self.assertEqual(self.direct(0x4557C0, 0x4557DC), {})
        #Count0 does not prove erasure, revocation, drain, native free safety
        #or removal of private copies already extracted by another caller.

    def test_native_growth_failure_can_clobber_table_and_is_not_rollback(self):
        self.words(0x455A04, [0x10400030, 0xAE020000])
        self.assertEqual(self.branch(0x455A04), 0x455AC8)
        self.words(0x455AC8, [0x1000FFEB, 0x2402FFFF])
        self.words(0x455A4C, [0x0C119A78, 0x70442002,
                             0x00402021, 0x00002821,
                             0x1440FFF0, 0xAE420000])
        self.words(0x455D5C, [0x8EC50014, 0x0C115660,
                             0x02C02021, 0x0440000A, 0])
        #Realloc NULL is stored into Q+0 in the branch delay slot, and block
        #allocation may already modify the table. Failure is not no-effects.
        #A bounded preallocated FIFO must deny full before calling append.

    def test_original_action_body_and_diagnostic_tail_cannot_hold_gcap32(self):
        self.words(0x4BAAEC, [0x24040010, 0x0C115B98, 0x24050010])
        self.words(0x4BAC80, [0x27BDFFC0, 0xAFB30038,
                             0xAFB20034, 0xAFB10030,
                             0xAFBF003C, 0xAFB0002C])
        self.words(0x4BACCC, [0xAFA20018, 0xAFB30024,
                             0xAFB2001C, 0x0320F809, 0xAFB10020])
        self.assertEqual(0x18 + 16, 0x28)
        self.assertEqual(0x18 + 20, 0x2C)
        self.assertGreater(0x18 + capture.OUTPUT_BYTES, 0x2C)
        #The diagnostic+28 word ends immediately before savedS0. It is not
        #a32-byte creation carrier, and no native ABI is widened by pack().

    def test_callback_fifth_argument_is_selected_action_data_not_generation(self):
        self.words(0x4BA96C, [0x8C430004, 0x8C5E0008,
                             0xAFA32020, 0x8C43000C,
                             0x0C10F480, 0xAFA32024])
        self.words(0x4BAA4C, [0x8C590150, 0x13200005,
                             0x02C02821, 0x8FA62024,
                             0x8FA72020, 0x0320F809, 0xAFBE0010])
        self.assertEqual(0x4BAA60 + 8, 0x4BAA68)
        #Existing resource callback(A0,A1,A2,A3,selected_action+8) cannot be
        #silently reused as a captured generation-bearing helper interface.

    def test_name_only_snapshot_and_post_unlock_relookup_lose_generation(self):
        self.words(0x4BA98C, [0x27A40020, 0x00002821,
                             0x0C296F18, 0x24062000])
        self.words(0x4BA9D4, [0x00112180, 0x27A30020,
                             0x00642021, 0x24450020,
                             0x0C296FB8, 0x26310001])
        self.words(0x4BA9F8, [0x8E190278, 0x02002021,
                             0x0320F809, 0x00009021])
        self.words(0x4BAA1C, [0x02C02821, 0x0C10E830,
                             0x02002021, 0x8E040024,
                             0x02C02821, 0x02803021,
                             0x0C121778, 0x0040B021])
        self.assertEqual(0x2000 // 64, 128)
        #Strcpy has neither a64-byte bound nor a verified128-target bound.
        #Names are re-resolved after registry unlock; equal names/pointers
        #cannot recover the old selected generation or retain engine storage.

    def test_known_worker_edges_are_t_to_registry_then_t_to_paint_not_reverse(self):
        self.words(0x4BA934, [0x0C119B68, 0x8E640010])
        self.words(0x4BA99C, [0x8E190274, 0x02002021,
                             0x0320F809, 0x26160034])
        self.words(0x4BAA70, [0x1000FFA1, 0xAEE00000])
        self.assertEqual(self.branch(0x4BAA70), 0x4BA8F8)
        self.words(0x4BA8F8, [0x8E64001C, 0x00002821,
                             0x8C990020, 0x0320F809,
                             0x2AB50002, 0x12A0000B, 0,
                             0x0C119B70, 0x8E640010])
        self.assertNotIn(0x466DC0,
                         self.direct(0x4BA934, 0x4BAA78).values())
        self.words(0x4928A8, [0x3C050049, 0x02402021,
                             0x0C116560, 0x24A50980])
        self.words(0x490A08, [0x0C10F218, 0xAFA3001C])
        self.words(0x43990C, [0x8C990284, 0x00808021,
                             0x0320F809, 0xAFA50018])
        #This bounded native route retains T+10 while entering13C, releases
        #13C before its callback, and can enter148 through explorer paint.
        #It proves neither arbitrary callback behavior nor a universal lock
        #order; adding a reverse edge requires an independent analysis.

    def test_worker_mutex_facades_discard_real_raw_status(self):
        self.words(0x4BACB4, [0x0C119B68, 0x8E040010])
        self.words(0x4BACE0, [0x0C119B70, 0x8E040010])
        self.words(0x466DA0, [0x27BDFFE0, 0xAFBF001C,
                             0x0C296E58, 0, 0x8FBF001C,
                             0x00001021, 0x03E00008, 0x27BD0020])
        self.words(0x466DC0, [0x27BDFFE0, 0xAFBF001C,
                             0x0C296E0C, 0, 0x8FBF001C,
                             0x00001021, 0x03E00008, 0x27BD0020])
        #A nativezero is not a checked raw T+10 acquisition/release witness.
        #The envelope helpers themselves supply no list or mutex operation.


if __name__ == '__main__':
    unittest.main()
