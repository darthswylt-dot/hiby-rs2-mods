#!/usr/bin/env python3
"""Pinned source gates for an explicit first-constructor capture handoff.

The native43AD00 continuation is deliberately not a checked admission path:
it ignores registration status, can invoke UI/name lookup after a raw error,
and has existing NULL-dereference paths. These source observations do not
establish retention, indirect-call coverage, safe retry/free or worker fanout.
Missing or changed02fd reference data fails rather than skipping any check.
"""

import hashlib
import unittest

import test_folderfollow_reveal_static_contract as source


class ConstructorCaptureContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.elf = source.Elf32(source.SOURCE)
        digest = hashlib.sha256(cls.elf.data).hexdigest()
        if digest != source.SOURCE_SHA256 or len(cls.elf.data) != source.SOURCE_SIZE:
            raise AssertionError(f'unrecognized reference: SHA-256 {digest}, '
                                 f'size {len(cls.elf.data)}')
        # One whole-executable census, shared by all checks in this class.
        # Direct JAL coverage does not exclude indirect callers or forged
        # stacks; explicit capture still needs its genuine invocation scope.
        cls.direct_callers = {0x43AD00: [], 0x4389E0: []}
        for start, end in cls.elf.executable_ranges():
            for pc in range(start, end & ~3, 4):
                word = cls.elf.word(pc)
                if word >> 26 != 3:
                    continue
                target = ((pc + 4) & 0xF0000000) | ((word & 0x3FFFFFF) << 2)
                if target in cls.direct_callers:
                    cls.direct_callers[target].append(pc)

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

    def test_first_constructor_entry_has136_byte_frame_not_second_epilogue(self):
        self.words(0x43AD00, [0x27BDFF78, 0xAFBF0084, 0xAFB60080,
                             0xAFB5007C, 0xAFB1006C, 0xAFB00068,
                             0xAFB40078, 0xAFB30074, 0xAFB20070])
        self.words(0x43AEC0, [0x8FB20070, 0x8FB1006C, 0x8FB00068,
                             0x03E00008, 0x27BD0088])
        self.words(0x43AF00, [0x27BDFF80, 0xAFB40078, 0xAFB30074])
        #43AEC0 is inside the first epilogue, not the second entry43AF00.

    def test_first_constructor_uses_all_four_native_argument_registers(self):
        self.words(0x43AD24, [0x8C920024, 0x00808821, 0x00A08021,
                             0x27A40050, 0x00002821, 0x00C0B021,
                             0x24060014, 0x00E0A821, 0x0C296F18,
                             0xAFA00064])
        #U->S1, mutable descriptor->S0, callback->S6 and context->S5.
        #A new capture output cannot silently replace A2 or A3.

    def test_explorer_calls_first_constructor_and_retains_only_raw_engine(self):
        self.words(0x492908, [0x8FA417D0, 0x3C060049, 0x27A516E4,
                             0x24C63AC0, 0x0C10EB40, 0x02003821,
                             0x8FA417D0, 0xAE0200CC, 0x0C10E5A0,
                             0x00402821])
        #Existing explorer stores V0 atV+CC and enables that raw engine.
        #It has no independent creation-output/pair handoff at this site.

    def test_outer_input_has104_byte_fixed_extent_and_unbounded_name_prefix(self):
        self.words(0x43AD7C, [0x0C296D38, 0x02002021, 0x24540001])
        self.words(0x43ADB4, [0x27A4001C, 0x26050048, 0x24060010,
                             0x0C296D10, 0xAFB30018, 0x8E030064])
        self.words(0x43ADD4, [0x8E060058, 0x8E020060, 0x0065282A,
                             0xAFA60034, 0xAE04005C])
        self.words(0x43AE14, [0x8E020040])
        self.words(0x43AE6C, [0x8E030044])
        self.assertEqual(0x64 + 4, 104)
        #The fixed extent is not a maximum name length. strlen(A1) has no
        #length argument, and native construction also writes descriptor+5C.

    def test_native_engine_constructor_allocates84_bytes_and_stores_name(self):
        self.words(0x43AE64, [0x0C22D048, 0xAFA20048])
        self.words(0x8B4120, [0x27BDFFD8, 0xAFB10020, 0x00808821,
                             0xAFB0001C, 0xAFBF0024, 0x0C22C340,
                             0x24040054, 0x1040002D, 0x00408021])
        self.words(0x8B4144, [0x00402021, 0x00002821, 0x0C296F18,
                             0x24060054, 0x8E220000, 0xAE020000])
        #No generation-sized spare field is established by the84-byte object.

    def test_inner_registration_descriptor_and_exact_native_continuation(self):
        self.words(0x43AE6C, [0x8E030044, 0xAFA20050, 0xAFA00054,
                             0xAFB60060, 0xAFB5005C, 0x10400004,
                             0xAFA30058, 0x02202021, 0x0C10E278,
                             0x27A50050, 0x0C1467E8, 0x02202021])
        self.assertEqual(self.branch(0x43AE80), 0x43AE94)
        self.assertEqual(0x43AE8C + 8, 0x43AE94)
        #The real register call consumes five native scalars atSP+50..60.
        #A scoped adapter must preserve its delay-slot argument and continuation.

    def test_constructor_scratch_is_not_an_owned_capture_output(self):
        self.words(0x43AD30, [0x27A40050, 0x00002821, 0x00C0B021,
                             0x24060014, 0x00E0A821, 0x0C296F18,
                             0xAFA00064])
        self.words(0x43AE20, [0x27A60064, 0x27A7001C, 0x0C10E9B8])
        self.words(0x43AE38, [0x8FA20064, 0xAFA2002C])
        self.words(0x43AD10, [0xAFB1006C, 0xAFB00068])
        self.assertEqual(0x50 + 20, 0x64)
        self.assertGreater(0x50 + 32, 0x68)
        #SP+64 already belongs to native scratch/outparam; SP+68 starts
        #saved registers. Neither is independently owned capture32 storage.

    def test_native_post_register_continuation_does_not_branch_on_status(self):
        self.words(0x43AE94, [0x0C1467E8, 0x02202021, 0x8FA20050,
                             0x0C10DFB8, 0x8C440000, 0x8FBF0084,
                             0x8FA20050])
        #Actual registration V0/V1 are discarded before the native postwork.
        #The new capture handoff must not label this continuation isolated.

    def test_native_return_is_saved_engine_not_registration_success(self):
        self.words(0x43AEAC, [0x8FA20050, 0x8FB60080, 0x8FB5007C,
                             0x8FB40078, 0x8FB30074, 0x8FB20070,
                             0x8FB1006C, 0x8FB00068, 0x03E00008,
                             0x27BD0088])
        #A positive raw engine does not certify a receipt, owner, raw release,
        #retained engine or successful checked output from that invocation.

    def test_first_missing_resource_or_validation_reaches_null_name_load(self):
        self.words(0x43AD54, [0x0C1218A8, 0x24A508B4, 0x1040004D])
        self.words(0x43AD6C, [0x0C296C90, 0x00409021, 0x10400047])
        self.assertEqual(self.branch(0x43AD5C), 0x43AE94)
        self.assertEqual(self.branch(0x43AD74), 0x43AE94)
        self.words(0x43AE9C, [0x8FA20050, 0x0C10DFB8, 0x8C440000])
        #SP+50 was zeroed and no engine was created on these paths. They do
        #not safely returnNULL; the unchanged native continuation dereferences it.

    def test_engine_allocation_null_also_reaches_unchanged_name_dereference(self):
        self.words(0x8B41F4, [0x8FBF0024, 0x02001021, 0x8FB10020,
                             0x8FB0001C, 0x03E00008, 0x27BD0028])
        self.words(0x43AE70, [0xAFA20050, 0xAFA00054, 0xAFB60060,
                             0xAFB5005C, 0x10400004, 0xAFA30058])
        self.assertEqual(self.branch(0x43AE80), 0x43AE94)
        self.words(0x43AEA4, [0x8C440000])
        #A diagnostic fixture must preserve this fault instead of inventing
        #a safe NULL return or claiming wrapper rollback of native creation.

    def test_postwork_can_set_widgets_and_relookup_engine_after_raw_error(self):
        self.words(0x519FB4, [0x27BDFEC0, 0xAFBF013C, 0xAFB10138,
                             0xAFB00134, 0x8C91021C])
        self.words(0x51A018, [0x0C22D0F0, 0xAFA20120])
        self.words(0x51A038, [0x02002021, 0x0C10E830, 0x27A50018])
        self.words(0x51A054, [0x0C22D0F0, 0x24070002])
        #519FA0 is not a harmless return stub: it can execute8B43C0 and
        #43A0C0 even after registration lost/returned an actual raw error.

    def test_direct_census_has13_first_constructor_and_two_registration_calls(self):
        self.assertEqual(self.direct_callers[0x43AD00], [
            0x492918, 0x4B90D0, 0x4BC078, 0x4BE24C, 0x4BED38,
            0x4C10D4, 0x4DD7A8, 0x4EABE0, 0x4FBC2C, 0x4FDE8C,
            0x4FE8E0, 0x5123B4, 0x520A1C])
        self.assertEqual(self.direct_callers[0x4389E0], [0x43AE8C, 0x43B030])
        self.words(0x43B02C, [0x02202021, 0x0C10E278, 0x27A50050])
        #The second constructor's call is distinct and must not be adopted
        #by a first-constructor-scoped wrapper, even for an equal U/engine.

    def test_engine_node_and_resource_cleanup_are_independent_lifetime_gates(self):
        self.words(0x439610, [0x8E020004, 0x8E030000, 0xAC620004,
                             0xAC430000, 0xAE000000, 0x12400003,
                             0xAE000004, 0x0C119AA0, 0x02402021,
                             0x8E020008, 0x24050001, 0x0C22CFC0,
                             0x8C440034, 0x0C22D088, 0x8E040008,
                             0x0C119AA0, 0x02002021])
        self.words(0x8B4240, [0x0C22C348, 0x02002021])
        self.words(0x493F40, [0x02202021, 0x0C10E568, 0x02602821,
                             0x8E240024, 0x0C1214C8, 0x02602821])
        #Registry deletion frees engine and node; explorer then separately
        #deletes resource metadata. A scalar capture retains neither object.

    def test_native_raw_masking_and_allocation_failure_are_not_repaired(self):
        self.words(0x466DA8, [0x0C296E58, 0, 0x8FBF001C,
                             0x00001021, 0x03E00008, 0x27BD0020])
        self.words(0x466DC8, [0x0C296E0C, 0, 0x8FBF001C,
                             0x00001021, 0x03E00008, 0x27BD0020])
        self.words(0x438A18, [0x10400019, 0x26050034])
        self.words(0x438A60, [0x0320F809, 0x02002021, 0x00001021])
        self.words(0x438A80, [0x1000FFFA, 0x2402FFFF])
        self.assertEqual(self.branch(0x438A18), 0x438A80)
        self.assertEqual(self.branch(0x438A80), 0x438A6C)
        #Native allocation failure skips release; successful-looking native
        #zero masks actual raw failure. Constructor capture is not repair,
        #whole-instance quarantine, retry authority or a native lifetime lease.


if __name__ == '__main__':
    unittest.main()
