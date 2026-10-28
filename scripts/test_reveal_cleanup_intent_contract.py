#!/usr/bin/env python3
"""Pinned native reasons why cleanup intent is not native free authority.

Only an explicit offline prepare API is composed. These source contracts pin
the destructive work preceding the apparent delete pair, name-based identity,
masked lock/deletion results and independent resource cleanup. They neither
install a gate nor execute cleanup, UI, player or network operations. Missing
or changed reference bytes are an error, not a skipped contract.
"""

import hashlib
import struct
import unittest

import reveal_retained_operations_stage as retained
import test_folderfollow_reveal_static_contract as source


BASE_ARGS = (0x1F50000, 0x1F80000, 0x1F70000, 0x1800000,
             0x1F20300, 0x1F20200, 0x1E80000,
             0x1FF0000, 0x1F20400, 0x1FE0000)
LEDGER, QUEUE, MUTEX, INTENT = 0x1F40000, 0x1FF1000, 0x1F20500, 0x1F20600
ARGS = (*BASE_ARGS, LEDGER, QUEUE, MUTEX)
RETAINED_SHA256 = '8217a5c2c4a091c73892b76a5f95ae0d178b866e6253ffffb89bc6fad333acb8'


class CleanupIntentContractTests(unittest.TestCase):
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

    def direct(self, start, end):
        return {pc: target for pc, target in self.edges.items()
                if start <= pc < end}

    def inbound(self, target):
        return {pc for pc, destination in self.edges.items()
                if destination == target}

    def test_engine_delete_resolves_first_equal_name_not_captured_engine(self):
        self.words(0x4395D4, [0x8EB00034, 0x16130006, 0x8E110000])
        self.words(0x4395E8, [0x02208021, 0x12700019, 0x8E310000,
                              0x8E020008, 0x02802021, 0x8C520000,
                              0x0C296D80, 0x02402821, 0x1440FFF7, 0])
        # A matching string selects the native node. Neither a captured GCAP
        # nor an exact expected engine argument participates in this lookup.

    def test_engine_delete_acquires_masked_registry_callback_without_status_check(self):
        self.words(0x4395C0, [0x8C990274, 0x0080A821, 0x00A0A021,
                              0x0320F809, 0x24930034, 0x8EB00034])
        self.words(0x437D28, [0x0C119B68, 0x8C84013C])
        self.words(0x466DA8, [0x0C296E58, 0, 0x8FBF001C,
                              0x00001021, 0x03E00008, 0x27BD0020])
        # Even raw acquisition failure becomes facade zero; unchanged native
        # deletion continues and is not isolated by a later intent receipt.

    def test_first_engine_unlink_precedes_all_name_queue_engine_and_node_frees(self):
        self.words(0x439610, [0x8E020004, 0x8E030000,
                              0xAC620004, 0xAC430000, 0xAE000000,
                              0x12400003, 0xAE000004,
                              0x0C119AA0, 0x02402021,
                              0x8E020008, 0x24050001,
                              0x0C22CFC0, 0x8C440034,
                              0x0C22D088, 0x8E040008,
                              0x0C119AA0, 0x02002021])
        self.assertEqual(self.direct(0x439610, 0x439654),
                         {0x43962C: 0x466A80, 0x43963C: 0x8B3F00,
                          0x439644: 0x8B4220, 0x43964C: 0x466A80})

    def test_native_delete_tail_and_unlock_do_not_report_deferred_cleanup(self):
        self.words(0x439654, [0x8EB90278, 0x8FBF0034, 0x8FB4002C,
                              0x8FB30028, 0x8FB20024, 0x8FB10020,
                              0x8FB0001C, 0x02A02021, 0x8FB50030,
                              0x03200008, 0x27BD0038])
        self.words(0x437DA8, [0x0C119B70, 0x8C84013C])
        self.words(0x466DC8, [0x0C296E0C, 0, 0x8FBF001C,
                              0x00001021, 0x03E00008, 0x27BD0020])
        # Tail return is masked R unlock zero, not a node-removal identity,
        # successful free, deferred continuation or observed raw status.

    def test_direct_delete_callers_continue_without_checking_native_result(self):
        purge, delete = self.inbound(0x439780), self.inbound(0x4395A0)
        self.assertEqual(len(purge), 55)
        self.assertEqual(len(delete), 56)
        self.assertEqual(delete, {pc + 12 for pc in purge} | {0x50294C})
        for pc in delete - {0x4FB164, 0x50294C}:
            with self.subTest(caller=f'{pc:#x}'):
                self.assertEqual(self.edges[pc + 12], 0x485320)
                word = self.elf.word(pc + 8)
                self.assertEqual(word >> 26, 35)
                self.assertEqual((word >> 16) & 31, 4)
                self.assertIn((word >> 21) & 31, range(16, 24))
                self.assertEqual(word & 0xFFFF, 0x24)
        self.words(0x4FB16C, [0x8E040050, 0x10800003, 0])
        self.words(0x502954, [0x3C050094, 0x02002021,
                              0x24A51CFC, 0x0C1394C8])

    def test_preceding_purge_uses_raw_paint_list_under_registry_not_paint_guard(self):
        self.words(0x4397AC, [0x8C990274, 0x0080A021, 0x00A09021,
                              0x0320F809, 0x24930034])
        self.words(0x4397F8, [0x0C10E5B0, 0x02402821, 0x8E84002C,
                              0x0C22C1D8, 0x8E050008, 0x8E990278])
        self.words(0x439758, [0x8E240128, 0x8C990020,
                              0x0320F809, 0x02002821])
        self.assertEqual(self.direct(0x439780, 0x439834),
                         {0x4397E8: 0xA5B600, 0x4397F8: 0x4396C0,
                          0x439804: 0x8B0760})
        for start, end in ((0x439780, 0x439834), (0x4396C0, 0x439770)):
            self.assertFalse(any(
                self.elf.word(pc) >> 26 == 35
                and ((self.elf.word(pc) >> 16) & 31) == 25
                and self.elf.word(pc) & 0xFFFF in (0x284, 0x288)
                for pc in range(start, end, 4)))
        # This bounded receiver-specific absence is not a universal lock proof.

    def test_parent_detach_mutates_membership_before_attachment_free(self):
        self.words(0x8B0794, [0x8C430008, 0x10600002, 0x8C42000C,
                              0xAC62000C, 0x10400002, 0, 0xAC430008])
        self.words(0x8B07BC, [0x26450004, 0x02202021,
                              0x0C22C1B8, 0xAE400040,
                              0x0C22C348, 0x02002021])
        self.words(0x8B080C, [0x1000FFEB, 0xAE220028])
        self.words(0x43982C, [0x03200008, 0x27BD0030])
        # 439780 then tail-unlocks: detach failure is not a cleanup receipt.

    def test_explorer_earlier_optional_worker_shutdown_already_mutates(self):
        self.words(0x493EA8, [0x8E040078, 0x10800003, 0,
                              0x0C1302A0, 0, 0x8E042A08,
                              0x10800003, 0, 0x0C115BA0, 0,
                              0xAE002A08])
        self.words(0x4C0AA4, [0x8C84000C, 0xAE0005A4, 0xAE020430,
                              0x0C119B40, 0xAE020018])
        self.words(0x4C0AC8, [0x0C119B68, 0x8E040014,
                              0x0C119B70, 0x8E040014,
                              0x0C119B78, 0x8E040014])
        # Closing only at493F38/44 misses this earlier teardown arm. This
        # contract deliberately does not claim every arm entry is identified.

    def test_explorer_cleanup_order_precedes_engine_and_separate_resource_delete(self):
        self.words(0x493EFC, [0x8E240028, 0x0C22C7B8, 0xAE2000F0,
                              0x0C12F688, 0x8E043B90,
                              0x8E0200CC, 0xAE003B90])
        self.words(0x493F28, [0x02202021, 0x0C11EA88, 0x02602821,
                              0x02202021, 0x0C10E5E0, 0x02602821,
                              0x02202021, 0x0C10E568, 0x02602821,
                              0x8E240024, 0x0C1214C8, 0x02602821])
        self.words(0x47AAAC, [0x8E020004, 0x8E030000,
                              0xAC620004, 0xAC430000])
        # 47AA20 already unlinks/frees cache nodes,439780 purges/detaches,
        #4395A0 deletes engine, and485320 separately deletes resource metadata.

    def test_resource_delete_detaches_parent_before_recursive_resource_destruction(self):
        self.words(0x485398, [0x8E1000D0, 0x12000012, 0x8FBF002C,
                              0x8E0400F8, 0x0C116968, 0x02002821,
                              0x02802021, 0x0C1214A0, 0x02002821])
        self.words(0x45A548, [0x8C990020, 0x0320F809, 0,
                              0x0C116440, 0x02002021])
        self.words(0x4852D4, [0x8C450000, 0x02402021,
                              0x0C1214A0, 0x26100001])
        self.words(0x48530C, [0x081211C0, 0x27BD0030])

    def test_resource_delete_forces_zero_after_inner_cleanup_and_has_no_error_branch(self):
        self.words(0x4853A8, [0x0C116968, 0x02002821, 0x02802021,
                              0x0C1214A0, 0x02002821, 0x8FBF002C,
                              0x8FB40028, 0x8FB30024, 0x8FB20020,
                              0x8FB1001C, 0x8FB00018, 0x00001021,
                              0x03E00008, 0x27BD0030])
        self.words(0x485404, [0x03E00008, 0x2402FFFF])
        # Zero after the two calls does not prove those calls succeeded.

    def test_resource_metadata_unlinks_then_destroys_viewgroup_handles_and_node(self):
        self.words(0x4850E4, [0x8E020004, 0x8E030000,
                              0xAC620004, 0xAC430000, 0x8E0400D0,
                              0xAE000000, 0x10800003, 0xAE000004,
                              0x0C10F530, 0])
        self.words(0x485110, [0xAE0000D0, 0x02008821, 0x24120010])
        self.words(0x485130, [0x8ED993E4, 0x0320F809, 0, 0xAE20008C])
        self.words(0x48515C, [0x8C5993E4, 0x0320F809, 0, 0xAE0000CC])
        self.words(0x48518C, [0x0C119AA0, 0x02002021])

    def test_disabled_cleanup_extension_preserves_exact_predecessor_composition(self):
        default = retained.assemble(*ARGS)
        explicit = retained.assemble(*ARGS, cleanup_intent_address=None)
        self.assertEqual(default['code'], explicit['code'])
        self.assertEqual(default['labels'], explicit['labels'])
        self.assertEqual(len(default['code']), 55164)
        self.assertEqual(hashlib.sha256(default['code']).hexdigest(), RETAINED_SHA256)
        self.assertNotIn('prepare_cleanup', default['retained_labels'])

    def test_opt_in_intent_storage_must_be_distinct_aligned_nonwrapping_data(self):
        invalid = (True, False, 0, 1, -4, 0x100000000, 1.0, '0x1F20600',
                   *BASE_ARGS, LEDGER, QUEUE, MUTEX, 0x400000)
        for address in invalid:
            with self.subTest(address=address), self.assertRaises(ValueError):
                retained.assemble(*ARGS, cleanup_intent_address=address)
        result = retained.assemble(*ARGS, cleanup_intent_address=INTENT)
        self.assertIn('prepare_cleanup', result['retained_labels'])
        self.assertEqual(result['labels']['retained_prepare_cleanup'],
                         result['retained_labels']['prepare_cleanup'])

    def test_opt_in_composition_protects_exact_rx_without_native_cleanup_calls(self):
        result = retained.assemble(*ARGS, cleanup_intent_address=INTENT)
        code, labels = result['code'], result['retained_labels']
        start = BASE_ARGS[6]
        self.assertEqual(result['protected_code_extent'], (start, len(code)))
        self.assertEqual(result['constructor_prefix_code_bytes']
                         + result['retained_code_bytes'], len(code))
        self.assertLess(labels['prepare_cleanup'], start + len(code))
        self.assertGreaterEqual(labels['prepare_cleanup'],
                                start + result['constructor_prefix_code_bytes'])
        tail = code[result['constructor_prefix_code_bytes']:]
        for entry in (0x4395A0, 0x439780, 0x8B0760, 0x485320, 0x485280,
                      0x484700, 0x43CB20, 0x466A80, 0x8B0D20):
            with self.subTest(forbidden_native_entry=f'{entry:#x}'):
                encoded = struct.pack('<I', 0x0C000000 | (entry >> 2))
                materialized = struct.pack('<II', 0x3C190000 | (entry >> 16),
                                           0x37390000 | (entry & 0xFFFF))
                self.assertNotIn(encoded, tail)
                self.assertNotIn(materialized, tail)
        # Absence concerns this emitted fragment, not computed native routes
        # elsewhere or a future caller treating CINT as teardown permission.


if __name__ == '__main__':
    unittest.main()
