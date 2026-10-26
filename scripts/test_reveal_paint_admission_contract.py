#!/usr/bin/env python3
"""Pinned native admission/cleanup premises for an offline passive observer.

These are bounded original-instruction checks, not installed hooks, complete
caller coverage, successful mutex acquisition, owned engine storage or native
permission to defer/free anything. In particular the native mutex wrappers
erase the lower service result. A callback's zero is not a raw lock receipt.
Missing or mismatched reference input fails instead of skipping the checks.
"""

import hashlib
import struct
import unittest

import test_folderfollow_reveal_static_contract as source


class RevealPaintAdmissionContractTests(unittest.TestCase):
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

    def branch(self, pc):
        immediate = self.elf.word(pc) & 0xFFFF
        if immediate & 0x8000:
            immediate -= 0x10000
        return pc + 4 + immediate * 4

    def direct(self, start, end):
        return {pc: target for pc, target in self.edges.items()
                if start <= pc < end}

    def inbound(self, target):
        return {pc for pc, destination in self.edges.items()
                if destination == target}

    def test_null_arguments_return_minus_one_before_frame_or_lock(self):
        self.words(0x4389E0, [0x10800029, 0, 0x10A00027, 0,
                              0x27BDFFD8])
        self.assertEqual(self.branch(0x4389E0), 0x438A88)
        self.assertEqual(self.branch(0x4389E8), 0x438A88)
        self.words(0x438A88, [0x03E00008, 0x2402FFFF])

    def test_native40_byte_frame_has_no_explicit_sp10_carrier_access(self):
        self.words(0x4389F0, [0x27BDFFD8, 0xAFBF0024,
                              0xAFB10020, 0xAFB0001C])
        stack_offsets = set()
        for pc in range(0x4389F0, 0x438A90, 4):
            word = self.elf.word(pc)
            # Explicit integer memory accesses whose base is this frame's SP.
            if word >> 26 in (32, 33, 35, 36, 37, 40, 41, 43):
                if (word >> 21) & 31 == 29:
                    stack_offsets.add(word & 0xFFFF)
        self.assertEqual(stack_offsets, {0x1C, 0x20, 0x24})
        self.assertNotIn(0x10, stack_offsets)
        # SP10 is beyond the four o32 argument homes [00,10), below saves.
        # This is not a claim about arbitrary rebound callbacks or ABI users.

    def test_registry_lock_callback_return_is_immediately_followed_by_allocation(self):
        self.words(0x438A00, [0x8C990274, 0x00808021,
                              0x0320F809, 0x00A08821,
                              0x0C119A78, 0x2404001C])
        # JALR's return is438A10; no native branch inspects its v0 status.
        self.assertEqual(0x438A08 + 8, 0x438A10)

    def test_native_allocator_call_keeps28_byte_argument_and438a18_return(self):
        self.words(0x438A10, [0x0C119A78, 0x2404001C,
                              0x10400019, 0x26050034])
        self.assertEqual(self.edges[0x438A10], 0x4669E0)
        self.assertEqual(0x438A10 + 8, 0x438A18)
        self.assertEqual(self.branch(0x438A18), 0x438A80)

    def test_allocation_failure_returns_minus_one_without_native_unlock(self):
        self.words(0x438A80, [0x1000FFFA, 0x2402FFFF])
        self.assertEqual(self.branch(0x438A80), 0x438A6C)
        self.words(0x438A6C, [0x8FBF0024, 0x8FB10020,
                              0x8FB0001C, 0x03E00008, 0x27BD0028])
        # The failure edge bypasses success-only438A5C..64 unlock. Preserve
        # this native defect in a passive fixture; do not call it rollback.

    def test_five_input_scalars_are_copied_without_validating_engine_or_name(self):
        self.words(0x438A20, [0x8E230004, 0xAC43000C,
                              0x8E230000, 0xAC430008,
                              0x8E230010, 0xAC430018,
                              0x8E23000C, 0xAC430014,
                              0x8E230008, 0xAC430010])
        # Input+0 becomes node+8 (raw engine word), not a generation or lease.
        self.assertEqual(self.direct(0x438A20, 0x438A48), {})

    def test_list_publication_has_four_ordered_link_stores_before_unlock(self):
        self.words(0x438A48, [0x8E030038, 0xAE020038,
                              0xAC450000, 0xAC430004,
                              0xAC620000, 0x8E190278])
        # Controller+38 changes before node/old-tail links finish. Observing
        # allocation or the first store alone is not completed publication.
        self.assertEqual(self.direct(0x438A48, 0x438A60), {})

    def test_publication_observation_pair_is_a_store_and_callback_load_not_call(self):
        self.words(0x438A58, [0xAC620000, 0x8E190278,
                              0x0320F809, 0x02002021])
        self.assertNotIn(0x438A58, self.edges)
        # An offline trampoline must reproduce both displaced instructions;
        # only the following native JALR has return PC438A68.
        self.assertEqual(0x438A60 + 8, 0x438A68)

    def test_success_unlock_and_zero_return_are_not_a_new_admission_receipt(self):
        self.words(0x438A5C, [0x8E190278, 0x0320F809,
                              0x02002021, 0x00001021,
                              0x8FBF0024, 0x8FB10020,
                              0x8FB0001C, 0x03E00008, 0x27BD0028])
        # The callback result is ignored. No versioned local generation is
        # returned to native callers; the successful native result remains0.

    def test_constructor_binds_registry_callbacks_to13c_mutex(self):
        self.words(0x439A60, [0xAE02013C, 0x3C020043, 0x24427D20,
                              0xAE020274, 0x3C020043, 0x24427DA0])
        self.words(0x437D28, [0x0C119B68, 0x8C84013C])
        self.words(0x437DA8, [0x0C119B70, 0x8C84013C])

    def test_native_lock_wrapper_erases_raw_service_failure(self):
        self.words(0x466DA0, [0x27BDFFE0, 0xAFBF001C,
                              0x0C296E58, 0, 0x8FBF001C,
                              0x00001021, 0x03E00008, 0x27BD0020])
        self.assertEqual(self.edges[0x466DA8], 0xA5B960)
        # A native callback0 alone cannot distinguish raw service success
        # from failure. Any positive offline guard premise must be explicit.

    def test_native_unlock_wrapper_also_erases_raw_service_failure(self):
        self.words(0x466DC0, [0x27BDFFE0, 0xAFBF001C,
                              0x0C296E0C, 0, 0x8FBF001C,
                              0x00001021, 0x03E00008, 0x27BD0020])
        self.assertEqual(self.edges[0x466DC8], 0xA5B830)

    def test_raw_lock_plt_uses_absolute_got_without_replacing_its_result(self):
        self.words(0xA5B960, [0x3C0F00A7, 0x8DF9FA58,
                              0x03200008, 0x25F8FA58])
        # The existing player-lock relocation contract resolves A6FA58 to
        # pthread_mutex_lock. Normal resolved-import/lifetime remains a premise.

    def test_raw_unlock_plt_uses_absolute_got_without_replacing_its_result(self):
        self.words(0xA5B830, [0x3C0F00A7, 0x8DF9FA0C,
                              0x03200008, 0x25F8FA0C])
        # The existing player-lock relocation contract names A6FA0C unlock.

    def test_all_four_controller_lock_facades_reach_the_same_status_masker(self):
        for pc, field in ((0x437CC0, 0x138), (0x437CE0, 0x148),
                          (0x437D00, 0x140), (0x437D20, 0x13C)):
            self.words(pc, [0x27BDFFE0, 0xAFBF001C,
                            0x0C119B68, 0x8C840000 | field,
                            0x8FBF001C, 0x03E00008, 0x27BD0020])

    def test_all_four_controller_unlock_facades_reach_the_same_status_masker(self):
        for pc, field in ((0x437D40, 0x138), (0x437D60, 0x148),
                          (0x437D80, 0x140), (0x437DA0, 0x13C)):
            self.words(pc, [0x27BDFFE0, 0xAFBF001C,
                            0x0C119B70, 0x8C840000 | field,
                            0x8FBF001C, 0x03E00008, 0x27BD0020])

    def test_native_mutex_factory_neither_checks_allocation_nor_init_status(self):
        self.words(0x466D60, [0x27BDFFE0, 0x24040018,
                              0xAFBF001C, 0x0C119A78,
                              0xAFB00018, 0x00402021,
                              0x00002821, 0x0C296E28,
                              0x00408021, 0x8FBF001C,
                              0x02001021, 0x8FB00018,
                              0x03E00008, 0x27BD0020])
        self.assertEqual(self.direct(0x466D60, 0x466D98),
                         {0x466D6C: 0x4669E0, 0x466D7C: 0xA5B8A0})
        # The returned pointer is not an initialization receipt: a null
        # allocation is still passed to init; its raw result is discarded.

    def test_native_mutex_destroy_discards_failure_and_frees_nonnull_storage(self):
        self.words(0x466DE0, [0x27BDFFE0, 0xAFB00018,
                              0xAFBF001C, 0x0C296C3C,
                              0x00808021, 0x12000004,
                              0x8FBF001C, 0x0C119AA0,
                              0x02002021, 0x8FBF001C,
                              0x8FB00018, 0x00001021,
                              0x03E00008, 0x27BD0020])
        self.assertEqual(self.branch(0x466DF4), 0x466E08)
        self.assertEqual(self.direct(0x466DE0, 0x466E18),
                         {0x466DEC: 0xA5B0F0, 0x466DFC: 0x466A80})
        # Only pointer nullity gates the free, not raw mutex-destroy success.

    def test_bounded_admission_census_has_only_two_encoded_callers(self):
        self.assertEqual(self.inbound(0x4389E0), {0x43AE8C, 0x43B030})
        # Encoded direct edges only, not proof against computed callers,
        # alternate constructors, callback rebinding or runtime aliases.

    def test_callers_construct_engine_before_attempting_registry_admission(self):
        self.words(0x43AE64, [0x0C22D048, 0xAFA20048,
                              0x8E030044, 0xAFA20050])
        self.words(0x43B00C, [0x0C22D048, 0xAFA20048,
                              0xAFA20050, 0xAFA00054])
        self.assertEqual(self.edges[0x43AE64], 0x8B4120)
        self.assertEqual(self.edges[0x43B00C], 0x8B4120)
        self.words(0x43AE80, [0x10400004, 0xAFA30058,
                              0x02202021, 0x0C10E278, 0x27A50050])
        self.words(0x43B024, [0x10400004, 0xAFA00058,
                              0x02202021, 0x0C10E278, 0x27A50050])

    def test_both_native_callers_ignore_admission_status_and_reload_engine(self):
        for pc in (0x43AE94, 0x43B038):
            self.words(pc, [0x0C1467E8, 0x02202021,
                             0x8FA20050, 0x0C10DFB8, 0x8C440000])
        self.words(0x43AEAC, [0x8FA20050])
        self.words(0x43B050, [0x8FA20050])
        # A nonnull constructor result survives an unsuccessful4389E0 call;
        # returning an engine pointer is not successful registry admission.

    def test_engine_constructor_does_not_perform_controller_registry_admission(self):
        self.words(0x8B4134, [0x0C22C340, 0x24040054,
                              0x1040002D, 0x00408021])
        self.words(0x8B41F8, [0x02001021, 0x8FB10020,
                              0x8FB0001C, 0x03E00008, 0x27BD0028])
        self.assertEqual(self.direct(0x8B4120, 0x8B4220),
                         {0x8B4134: 0x8B0D00, 0x8B414C: 0xA5BC60})
        # Bounded constructor call census only, not all possible creation.

    def test_inner_shutdown_census_has_two_callers_which_ignore_its_result(self):
        self.assertEqual(self.inbound(0x43CB20), {0x4E3F74, 0x51A40C})
        for pc in (0x4E3F74, 0x51A40C):
            self.words(pc, [0x0C10F2C8, 0x02002021,
                             0x8FBF0034, 0x8FB50030, 0x8FB4002C,
                             0x8FB30028, 0x8FB20024,
                             0x8FB10020, 0x8FB0001C,
                             0x27BD0038, 0x03E00008, 0])

    def test_both_outer_shutdown_bodies_can_call_registry_callbacks_first(self):
        self.words(0x4E3EE8, [0x0320F809, 0x8E240014])
        self.words(0x51A388, [0x0320F809, 0x8E240014])
        self.words(0x4E3F20, [0x8E390018, 0x1720FFF0, 0x02A02021])
        self.words(0x51A3C0, [0x8E390018, 0x1720FFF0, 0x02A02021])
        self.assertEqual(self.branch(0x4E3F24), 0x4E3EE8)
        self.assertEqual(self.branch(0x51A3C4), 0x51A388)
        # Unknown node callbacks precede the inner43CB38 fence, not vice versa.

    def test_both_outer_shutdown_bodies_can_unlink_and_free_registry_nodes_first(self):
        for pc in (0x4E3F3C, 0x51A3DC):
            self.words(pc, [0x8E220004, 0x8E230000,
                             0x02202021, 0xAC620004,
                             0xAC430000, 0xAE200000,
                             0x0C119AA0, 0xAE200004])
            self.assertEqual(self.edges[pc + 24], 0x466A80)
        self.words(0x4E3F6C, [0x0C119B78, 0x8E040290])
        # The first outer path also destroys controller+290 before43CB20.

    def test_inner_shutdown_fence_precedes_only_its_own_first_worker_call(self):
        self.words(0x43CB20, [0x27BDFFD8, 0xAFBF0024,
                              0xAFB1001C, 0xAFB20020,
                              0xAFB00018, 0x00808821,
                              0x0C123D48, 0x8C840030,
                              0x0C12EAF8, 0x8E2400C4])
        self.assertEqual(self.edges[0x43CB38], 0x48F520)
        # An observation here cannot retroactively fence caller cleanup.

    def test_destructor_census_includes_one_unpaired_native_delete(self):
        purge, delete = self.inbound(0x439780), self.inbound(0x4395A0)
        self.assertEqual(len(purge), 55)
        self.assertEqual(len(delete), 56)
        self.assertEqual(delete, {pc + 12 for pc in purge} | {0x50294C})
        self.assertEqual(self.inbound(0x8B0760), {0x439804})

    def test_all_encoded_delete_callers_ignore_native_result_before_followup(self):
        delete = self.inbound(0x4395A0)
        ordinary = delete - {0x4FB164, 0x50294C}
        self.assertEqual(len(ordinary), 54)
        for pc in ordinary:
            self.assertEqual(self.edges[pc + 12], 0x485320)
            # A0 is loaded from a saved controller, not from resultV0.
            word = self.elf.word(pc + 8)
            self.assertEqual(word >> 26, 35)
            self.assertEqual((word >> 16) & 31, 4)
            self.assertIn((word >> 21) & 31, range(16, 24))
            self.assertEqual(word & 0xFFFF, 0x24)
        self.words(0x4FB16C, [0x8E040050, 0x10800003, 0])
        self.words(0x502954, [0x3C050094, 0x02002021,
                              0x24A51CFC, 0x0C1394C8])

    def test_native_delete_returns_through_unlock_not_deferred_continuation(self):
        self.words(0x439610, [0x8E020004, 0x8E030000,
                              0xAC620004, 0xAC430000, 0xAE000000])
        self.words(0x439654, [0x8EB90278, 0x8FBF0034,
                              0x8FB4002C, 0x8FB30028,
                              0x8FB20024, 0x8FB10020,
                              0x8FB0001C, 0x02A02021,
                              0x8FB50030, 0x03200008, 0x27BD0038])
        # No local retire/drained result can turn this tail return into an
        # exact native deferred cleanup receipt or retain an actual engine.

    def test_native_detach_status_is_not_propagated_by_parent_facade(self):
        self.words(0x8B07EC, [0x00001021])
        self.words(0x8B0814, [0x1000FFF6, 0x2402FFFF])
        self.words(0x439804, [0x0C22C1D8, 0x8E050008,
                              0x8E990278, 0x8FBF002C])
        self.words(0x43982C, [0x03200008, 0x27BD0030])
        # Facade tail-unlock masks detach0/-1; no cancel/defer protocol exists.


if __name__ == '__main__':
    unittest.main()
