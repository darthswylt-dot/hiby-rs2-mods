#!/usr/bin/env python3
"""Pinned creation/callback carrier prerequisites, not installed integration.

The native worker copies names and later resolves them again. These bounded
instruction contracts do not establish lifetime, raw-lock success, complete
indirect caller coverage or a generation-bearing native producer context.
"""

import hashlib
import unittest

import test_folderfollow_reveal_static_contract as source


class CreationCaptureContractTests(unittest.TestCase):
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

    def test_worker_name_snapshot_has64_byte_stride_not_a_generation_record(self):
        self.words(0x4BA98C, [0x27A40020, 0x00002821,
                             0x0C296F18, 0x24062000])
        self.words(0x4BA9D4, [0x00112180, 0x27A30020,
                             0x00642021, 0x24450020,
                             0x0C296FB8, 0x26310001])
        self.assertEqual(0x2000 // 64, 128)
        # The copy is native strcpy, not a bounded64-byte copy. Neither this
        # stride nor the8192-byte area proves a name/count overflow bound.

    def test_name_snapshot_walk_is_inside_native_registry_callback_bracket(self):
        self.words(0x4BA99C, [0x8E190274, 0x02002021,
                             0x0320F809, 0x26160034,
                             0x8E020034, 0x1056FFCD,
                             0x8C520000])
        self.words(0x4BA9BC, [0x8C420008, 0x8E040024,
                             0x02803021, 0x0C121778,
                             0x8C450000])
        self.words(0x4BA9F8, [0x8E190278, 0x02002021,
                             0x0320F809, 0x00009021])
        # A native callback bracket is not checked raw13C ownership. The
        # selected node/engine is not copied into each64-byte name slot.

    def test_worker_rebinds_name_to_engine_and_resource_after_registry_unlock(self):
        self.words(0x4BAA10, [0x0012B180, 0x27A20020,
                             0x0056B021, 0x02C02821,
                             0x0C10E830, 0x02002021,
                             0x8E040024, 0x02C02821,
                             0x02803021, 0x0C121778,
                             0x0040B021])
        self.assertLess(0x4BAA00, 0x4BAA20)
        self.assertLess(0x4BAA20, 0x4BAA34)
        # 43A0C0(U,name) and485DE0(resources,name,type) are new lookups.
        # Equal names cannot recover the generation selected before unlock.

    def test_engine_name_lookup_returns_borrowed_node_field_after_unlock(self):
        self.words(0x43A118, [0x8E020008, 0x02402821,
                             0x0C296D80, 0x8C440000])
        self.words(0x43A130, [0x8E990278, 0x0320F809,
                             0x02802021, 0x8FBF002C,
                             0x8E020008])
        # Loading engine from node+8 after the callback unlock is not a
        # retained engine lease, even when its numeric address is unchanged.

    def test_callback_fifth_argument_already_belongs_to_selected_action(self):
        self.words(0x4BA96C, [0x8C430004, 0x8C5E0008,
                             0xAFA32020, 0x8C43000C,
                             0x0C10F480, 0xAFA32024])
        self.words(0x4BAA4C, [0x8C590150, 0x13200005,
                             0x02C02821, 0x8FA62024,
                             0x8FA72020, 0x0320F809,
                             0xAFBE0010])
        # A future additional carrier needs its own explicit ABI. Existing
        # selected-action+8 is not a free generation word.

    def test_explorer_registers_callback_before_creating_engine_then_keeps_only_engine(self):
        self.words(0x4928A8, [0x3C050049, 0x02402021,
                             0x0C116560, 0x24A50980])
        self.words(0x492908, [0x8FA417D0, 0x3C060049,
                             0x27A516E4, 0x24C63AC0,
                             0x0C10EB40, 0x02003821,
                             0x8FA417D0, 0xAE0200CC,
                             0x0C10E5A0, 0x00402821])
        # The returned rawengine is stored at explorer+CC and enabled. No
        # independent creation pair/outparam is transported at these sites.

    def test_registration40_byte_frame_pins_request_caller_and_commit_before_unlock(self):
        self.words(0x4389F0, [0x27BDFFD8, 0xAFBF0024,
                             0xAFB10020, 0xAFB0001C])
        self.words(0x438A48, [0x8E030038, 0xAE020038,
                             0xAC450000, 0xAC430004,
                             0xAC620000, 0x8E190278,
                             0x0320F809, 0x02002021,
                             0x00001021])
        # Saved RA is nativeSP+24. The creation event precedes final unlock;
        # observing it alone does not certify that unlock succeeded.

    def test_constructor_registration_requests_have_five_native_scalars_not_pair_slots(self):
        self.words(0x43AE6C, [0x8E030044, 0xAFA20050,
                             0xAFA00054, 0xAFB60060,
                             0xAFB5005C, 0x10400004,
                             0xAFA30058, 0x02202021,
                             0x0C10E278, 0x27A50050])
        self.words(0x43B014, [0xAFA20050, 0xAFA00054,
                             0xAFB40060, 0xAFB3005C,
                             0x10400004, 0xAFA00058,
                             0x02202021, 0x0C10E278,
                             0x27A50050])
        self.words(0x438A20, [0x8E230004, 0xAC43000C,
                             0x8E230000, 0xAC430008,
                             0x8E230010, 0xAC430018,
                             0x8E23000C, 0xAC430014,
                             0x8E230008, 0xAC430010])
        # All20 request bytes and all five node scalars have native meanings.
        # Extending a request/node requires new checked storage, not a tail read.

    def test_constructor_wrappers_discard_registration_status_and_return_raw_engine(self):
        for pc, returned in ((0x43AE94, 0x43AEAC),
                             (0x43B038, 0x43B050)):
            self.words(pc, [0x0C1467E8, 0x02202021,
                            0x8FA20050, 0x0C10DFB8,
                            0x8C440000])
            self.words(returned, [0x8FA20050])
        # Nonnull outer construction does not certify receipt/owner issuance.

    def test_native_registry_unlock_hides_raw_status_and_registration_forces_zero(self):
        self.words(0x437DA0, [0x27BDFFE0, 0xAFBF001C,
                             0x0C119B70, 0x8C84013C])
        self.words(0x466DC0, [0x27BDFFE0, 0xAFBF001C,
                             0x0C296E0C, 0,
                             0x8FBF001C, 0x00001021,
                             0x03E00008, 0x27BD0020])
        self.words(0x438A60, [0x0320F809, 0x02002021,
                             0x00001021, 0x8FBF0024])
        # A successful-looking4389E0 result cannot certify raw13C release.
        # An explicit capture wrapper needs an independent raw-result witness.

    def test_resource_deletion_has_no_generation_lease_before_engine_free(self):
        self.words(0x439610, [0x8E020004, 0x8E030000,
                             0xAC620004, 0xAC430000,
                             0xAE000000, 0x12400003,
                             0xAE000004, 0x0C119AA0,
                             0x02402021, 0x8E020008,
                             0x24050001, 0x0C22CFC0,
                             0x8C440034, 0x0C22D088,
                             0x8E040008, 0x0C119AA0,
                             0x02002021])
        # Unlink/name/queue/engine/node destruction requires a separate lease
        # and deferred continuation; retaining a scalar pair is not that lease.


if __name__ == '__main__':
    unittest.main()
