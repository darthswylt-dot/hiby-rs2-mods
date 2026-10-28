#!/usr/bin/env python3
"""Pinned source and composition boundaries for cooperative operation accounting.

The new ledger does not retain native engine/resource allocations. These checks
pin why extraction/count/ordinary zero cannot stand in for exact paint completion,
and verify that the explicit composition rejects advertised RX/data aliases.
No device, network, installed hook, native cleanup or UI operation is performed.
Missing or changed reference bytes fail instead of silently skipping contracts.
"""

import hashlib
import struct
import unittest

import reveal_constructor_capture_stage as constructors
import reveal_paint_retirement_mips as paint
import reveal_retained_operations_mips as operations
import reveal_retained_operations_stage as retained
import test_folderfollow_reveal_static_contract as source


BASE_ARGS = (0x1F50000, 0x1F80000, 0x1F70000, 0x1800000,
             0x1F20300, 0x1F20200, 0x1E80000,
             0x1FF0000, 0x1F20400, 0x1FE0000)
LEDGER, QUEUE, MUTEX = 0x2100000, 0x2110000, 0x1F20500
ARGS = (*BASE_ARGS, LEDGER, QUEUE, MUTEX)
CONSTRUCTOR_SHA256 = '3bf7a75351ea9c91d2ff629d1a24f6deb478a918b2fa2696217f8c250c000693'


class RetainedOperationsContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.elf = source.Elf32(source.SOURCE)
        digest = hashlib.sha256(cls.elf.data).hexdigest()
        if digest != source.SOURCE_SHA256 or len(cls.elf.data) != source.SOURCE_SIZE:
            raise AssertionError(f'unrecognized reference: SHA-256 {digest}, '
                                 f'size {len(cls.elf.data)}')
        cls.paint_code, cls.paint_labels = paint.assemble(
            BASE_ARGS[2], BASE_ARGS[3], BASE_ARGS[6], checked_mutex=True,
            expected_mutex_address=BASE_ARGS[5])

    def words(self, address, expected, *, emitted=False):
        for index, word in enumerate(expected):
            if word is None:
                continue
            pc = address + 4 * index
            with self.subTest(pc=f'{pc:#x}'):
                actual = (self.emitted_word(pc) if emitted else self.elf.word(pc))
                self.assertEqual(actual, word)

    def emitted_word(self, pc):
        return struct.unpack_from('<I', self.paint_code, pc - BASE_ARGS[6])[0]

    def branch(self, pc, *, emitted=False):
        immediate = ((self.emitted_word(pc) if emitted else self.elf.word(pc))
                     & 0xFFFF)
        if immediate & 0x8000:
            immediate -= 0x10000
        return pc + 4 + immediate * 4

    def find_emitted(self, start_label, end_label, expected):
        start = self.paint_labels[start_label] - BASE_ARGS[6]
        end = self.paint_labels[end_label] - BASE_ARGS[6]
        needle = struct.pack('<' + 'I' * len(expected), *expected)
        offset = self.paint_code.find(needle, start, end)
        self.assertNotEqual(offset, -1)
        self.assertEqual(offset % 4, 0)
        self.assertEqual(self.paint_code.find(needle, offset + 4, end), -1)
        return BASE_ARGS[6] + offset

    def core_args(self):
        prefix = constructors.assemble(*BASE_ARGS)
        owner = prefix['owner_labels']
        return (*BASE_ARGS[:6], BASE_ARGS[6] + len(prefix['code']),
                *BASE_ARGS[7:], LEDGER, QUEUE, MUTEX,
                prefix['envelope_labels']['pack'],
                prefix['envelope_labels']['dispatch'], owner['complete'],
                owner['retire'], owner['drained'])

    def test_fifo_factory_width_and_append_copy_are_not_acknowledgement(self):
        self.words(0x456E60, [0x08115B10, 0x2406000A])
        self.words(0x456C68, [0x00A09821, 0x0C119A78, 0x00C08821])
        self.words(0x456C8C, [0xAC40000C, 0xAC530010, 0xAC510014])
        self.words(0x455DA0, [0x00A03021, 0x081156F0, 0x8C85000C])
        self.words(0x455CCC, [0x8EC20010, 0x00139880, 0x00B32821,
                             0x70541802, 0x8CA40000, 0x8FA50048,
                             0x00403021, 0x0C296D10, 0x00642021,
                             0x8EC2000C, 0x24420001, 0xAEC2000C,
                             0x8FBF003C, 0x02A01021])
        # Width is an independent constructor argument. APPEND copies that
        # many bytes before count, returning the old index, not an operation
        # token, generation, paint nonce or completion receipt.

    def test_get_borrows_and_remove_reuses_full_width_head_including_token(self):
        self.words(0x455808, [0x8C830014, 0x8C860000, 0x8C820010,
                             0x00A3001A, 0x006001F4, 0x00002012,
                             0x00041880, 0x00C31821, 0x00002810,
                             0x8C640000, 0x70A21802, 0x03E00008,
                             0x00641021])
        self.words(0x4558F4, [0x00641823, 0x2466FFFF, 0x70821802,
                             0x8E330000, 0x26520001, 0x26310004,
                             0x70C23002, 0x00732021, 0x0C296D10,
                             0x00822821])
        self.words(0x45591C, [0x8E040014, 0x8E020010, 0x0254182A,
                             0x2484FFFF, 0x70822802, 0x00403021,
                             0x1460FFEA, 0x00B32021])
        self.words(0x45593C, [0x8E03000C, 0x00001021,
                             0x2463FFFF, 0xAE03000C])
        # Copy token+READY together under the guard BEFORE REMOVE, which
        # moves the next72 bytes over the same borrowed head address.

    def test_native_growth_and_clear_cannot_release_retained_operations(self):
        self.words(0x455A04, [0x10400030, 0xAE020000])
        self.assertEqual(self.branch(0x455A04), 0x455AC8)
        self.words(0x455A4C, [0x0C119A78, 0x70442002, 0x00402021,
                             0x00002821, 0x1440FFF0, 0xAE420000])
        self.words(0x4557C0, [0x10800004, 0, 0xAC80000C,
                             0x03E00008, 0x00001021,
                             0x03E00008, 0x2402FFFA])
        # Growth is not transactional. Count reset has no token/nonce,
        # retirement, active-claim or privately extracted-copy participation.

    def test_original_worker_format_and_callback_argument_remain_occupied(self):
        self.words(0x4BAAEC, [0x24040010, 0x0C115B98, 0x24050010])
        self.words(0x4BAC80, [0x27BDFFC0, 0xAFB30038, 0xAFB20034,
                             0xAFB10030, 0xAFBF003C, 0xAFB0002C])
        self.words(0x4BACCC, [0xAFA20018, 0xAFB30024, 0xAFB2001C,
                             0x0320F809, 0xAFB10020])
        self.words(0x4BAA4C, [0x8C590150, 0x13200005, 0x02C02821,
                             0x8FA62024, 0x8FA72020,
                             0x0320F809, 0xAFBE0010])
        # The explicit72-byte queue is not installed at worker+1C; its
        # fifth callback argument is not spare retained-operation storage.

    def test_constructor_still_continues_into_lookup_ui_without_admission(self):
        self.words(0x43AE94, [0x0C1467E8, 0x02202021, 0x8FA20050,
                             0x0C10DFB8, 0x8C440000, 0x8FBF0084,
                             0x8FA20050])
        self.words(0x519FB4, [0x27BDFEC0, 0xAFBF013C, 0xAFB10138,
                             0xAFB00134, 0x8C91021C])
        self.words(0x51A018, [0x0C22D0F0, 0xAFA20120])
        self.words(0x51A038, [0x02002021, 0x0C10E830, 0x27A50018])
        # A later bind does not protect the native constructor's earlier
        # continuation, NULL name loads or raw-error reentrant lookup.

    def test_native_engine_resource_deletion_still_bypasses_local_ledger(self):
        self.words(0x439610, [0x8E020004, 0x8E030000, 0xAC620004,
                             0xAC430000, 0xAE000000, 0x12400003,
                             0xAE000004, 0x0C119AA0, 0x02402021,
                             0x8E020008, 0x24050001, 0x0C22CFC0,
                             0x8C440034, 0x0C22D088, 0x8E040008,
                             0x0C119AA0, 0x02002021])
        self.words(0x493F40, [0x02202021, 0x0C10E568, 0x02602821,
                             0x8E240024, 0x0C1214C8, 0x02602821])
        # Native engine/node destruction and separate resource deletion
        # neither consult this ledger nor receive safe-free authority.

    def test_checked_complete_zero_includes_no_claim_and_post_remove_fault(self):
        pc = self.paint_labels['complete_state_ok']
        self.words(pc, [0x8E140004, None, 0, None, 0], emitted=True)
        self.assertEqual(self.branch(pc + 4, emitted=True), self.paint_labels['unlock'])
        self.assertEqual(self.branch(pc + 12, emitted=True), self.paint_labels['unlock'])
        remove = self.find_emitted('complete', 'retire',
                                  [0x8E790020, 0x02602021,
                                   0x00002821, 0x0320F809, 0,
                                   0xAFA20044])
        self.assertEqual(self.branch(remove + 24, emitted=True),
                         self.paint_labels['fault'])
        self.words(remove + 32, [0x8FA80050, 0x2508FFFF,
                                 0x8E69000C, None, 0], emitted=True)
        self.assertEqual(self.branch(remove + 44, emitted=True),
                         self.paint_labels['fault'])
        self.words(self.paint_labels['fault'],
                   [0x24080001, 0xAE08000C, 0xAFA00040], emitted=True)
        # Successful native REMOVE0 followed by a failed count check keeps
        # RAW0 and clears RESULT0. Therefore complete(0,0) is not a certified
        # harmless NOT_CLAIMED discriminator and must not authorize retry.

    def test_checked_publish_zero_can_follow_actual_append_and_partial_effects(self):
        append = self.find_emitted('publish', 'claim',
                                  [0x27A50010, 0x8E790018,
                                   0x02602021, 0x0320F809, 0,
                                   0xAFA20044, 0x2408FFFF])
        self.assertEqual(self.branch(append + 28, emitted=True),
                         self.paint_labels['fault'])
        self.words(append + 36, [0x8FA80050, None, 0,
                                 0x25080001, 0x8E69000C, None, 0,
                                 0xAFB40040], emitted=True)
        self.assertEqual(self.branch(append + 40, emitted=True),
                         self.paint_labels['fault'])
        self.assertEqual(self.branch(append + 56, emitted=True),
                         self.paint_labels['fault'])
        # At previous index0, a post-append count mismatch yields RESULT0,
        # RAW0 even if an element was copied. Local DONE alone is not drain.

    def test_retire_reports_only_removed_count_and_drained_requires_healthy_retired(self):
        pc = self.paint_labels['retire_finished']
        self.words(pc, [0x8E68000C, None, 0, 0x24080001,
                        0xAFA80040, 0x8FA80058, 0xAFA80044], emitted=True)
        self.words(self.paint_labels['retire_remove'] + 56,
                   [0x8FA80058, 0x25080001, 0xAFA80058], emitted=True)
        pc = self.paint_labels['drained_state_ok']
        self.words(pc, [0x8E08000C, None, 0], emitted=True)
        self.assertEqual(self.branch(pc + 4, emitted=True), self.paint_labels['unlock'])
        pc = self.paint_labels['drained_owner_found']
        self.words(pc, [0x0160A821, 0x8EA80008, None, 0], emitted=True)
        self.assertEqual(self.branch(pc + 8, emitted=True), self.paint_labels['unlock'])
        # Purge returns a count, not the identities needed to release exact
        # operation rows. It may run only after CLOSED/allDONE/Qempty here.

    def test_checked_unlock_error_has_no_late_shared_fault_store(self):
        pc = self.paint_labels['unlock']
        self.words(pc, [0x0000000F, 0x8FA40064, 0x0C296E0C,
                        0, None, 0, 0xAFA00040, 0xAFA20044], emitted=True)
        self.assertEqual(self.branch(pc + 16, emitted=True), self.paint_labels['restore'])
        # A raw release error may already have released the mutex. Only our
        # retained private stack receives RESULT0/exactstatus afterward.

    def test_constructor_default_golden_and_following_extent_are_strict(self):
        default = constructors.assemble(*BASE_ARGS)
        explicit = constructors.assemble(*BASE_ARGS, following_code_bytes=0,
                                         extra_protected_data=())
        self.assertEqual(default['code'], explicit['code'])
        self.assertEqual(default['labels'], explicit['labels'])
        self.assertEqual(len(default['code']), 40076)
        self.assertEqual(hashlib.sha256(default['code']).hexdigest(),
                         CONSTRUCTOR_SHA256)
        extended = constructors.assemble(*BASE_ARGS, following_code_bytes=16)
        self.assertEqual(extended['labels'], default['labels'])
        self.assertEqual(len(extended['code']), len(default['code']))
        self.assertEqual(extended['protected_code_extent'],
                         (BASE_ARGS[6], len(default['code']) + 16))
        self.assertNotEqual(extended['code'], default['code'])
        for value in (True, False, None, -4, 1, 2, 3, 4.0, '4', 0x100000000):
            with self.subTest(value=value), self.assertRaises(ValueError):
                constructors.assemble(*BASE_ARGS, following_code_bytes=value)

    def test_constructor_additional_data_descriptors_are_strict_and_nonaliasing(self):
        malformed = ([], None, ((True, 4),), ((LEDGER, True),),
                     ([LEDGER, 4],), ((LEDGER,),), ((LEDGER, 0),),
                     ((LEDGER, -4),), ((LEDGER + 1, 4),),
                     ((0xFFFFFFFC, 8),), ((LEDGER, 4), (LEDGER, 4)),
                     ((BASE_ARGS[2], 4),), ((BASE_ARGS[7], 4),),
                     ((BASE_ARGS[6], 4),), ((0x400000, 4),))
        for value in malformed:
            with self.subTest(value=value), self.assertRaises(ValueError):
                constructors.assemble(*BASE_ARGS, extra_protected_data=value)
        valid = constructors.assemble(*BASE_ARGS,
                                      extra_protected_data=((LEDGER, 4),))
        self.assertGreater(len(valid['code']), 40076)
        # The descriptor changes emitted exclusion instructions, not merely
        # metadata; it does not certify every inherited internal entry.

    def test_new_composition_binds_real_entries_and_exact_complete_rx_extent(self):
        result = retained.assemble(*ARGS)
        code, labels = result['code'], result['retained_labels']
        start = BASE_ARGS[6]
        self.assertEqual(result['protected_code_extent'], (start, len(code)))
        self.assertEqual(result['constructor_prefix_code_bytes']
                         + result['retained_code_bytes'], len(code))
        for name in ('bind', 'enqueue', 'pop_dispatch', 'complete',
                     'close', 'quiescent'):
            self.assertIn(name, labels)
            self.assertGreaterEqual(labels[name],
                                    start + result['constructor_prefix_code_bytes'])
            self.assertLess(labels[name], start + len(code))
            self.assertEqual(result['labels']['retained_' + name], labels[name])
        tail = code[result['constructor_prefix_code_bytes']:]
        direct = {((struct.unpack_from('<I', tail, i)[0] & 0x3FFFFFF) << 2)
                  for i in range(0, len(tail), 4)
                  if struct.unpack_from('<I', tail, i)[0] >> 26 == 3}
        expected = (result['envelope_labels']['pack'],
                    result['envelope_labels']['dispatch'],
                    result['owner_labels']['complete'],
                    result['owner_labels']['retire'],
                    result['owner_labels']['drained'], paint.RAW_LOCK, paint.RAW_UNLOCK)
        # Calls encoded with JAL or full-address JALR are both legitimate;
        # the actual callees must be represented by the emitted immediates.
        for entry in expected:
            encoded_jal = struct.pack('<I', 0x0C000000 | (entry >> 2))
            materialized = struct.pack('<II', 0x3C190000 | (entry >> 16),
                                       0x37390000 | (entry & 0xFFFF))
            self.assertTrue(entry in direct or encoded_jal in tail
                            or materialized in tail, f'missing bound entry {entry:#x}')

    def test_new_core_capacities_and_fixed_state_aliases_are_strict(self):
        self.assertEqual(operations.memory_bytes(1), 64 + 16)
        self.assertEqual(operations.memory_bytes(1024), 64 + 16 * 1024)
        for value in (True, False, None, 0, -1, 1025, 1.0, '16'):
            with self.subTest(operation_capacity=value), self.assertRaises(ValueError):
                operations.memory_bytes(value)
        for value in (True, False, None, 0, -10, 1, 39, 10250, 40.0, '40'):
            with self.subTest(retained_capacity=value), self.assertRaises(ValueError):
                operations.assemble(*self.core_args(), retained_capacity=value)
        for position, address in ((10, BASE_ARGS[0]), (10, BASE_ARGS[2]),
                                  (10, BASE_ARGS[3]), (10, BASE_ARGS[6]),
                                  (10, BASE_ARGS[7]), (10, QUEUE),
                                  (11, LEDGER), (11, BASE_ARGS[8]),
                                  (12, BASE_ARGS[4]), (12, BASE_ARGS[5]),
                                  (12, LEDGER), (12, QUEUE)):
            args = list(ARGS)
            args[position] = address
            with self.subTest(position=position, address=hex(address)), self.assertRaises(ValueError):
                retained.assemble(*args)

    def test_new_core_protected_rx_descriptor_rejects_partial_or_aliased_regions(self):
        args = self.core_args()
        code_base = args[6]
        for value in ([], (), (True, 4), (BASE_ARGS[6], True),
                      (BASE_ARGS[6], -4), (BASE_ARGS[6], 2),
                      (BASE_ARGS[6] + 1, 4), (code_base, 4),
                      (BASE_ARGS[6], code_base - BASE_ARGS[6]),
                      (BASE_ARGS[6], 0x10000000), (0x400000, code_base - 0x400000 + 4)):
            with self.subTest(value=value), self.assertRaises(ValueError):
                operations.assemble(*args, protected_code=value)
        standalone, labels = operations.assemble(*args)
        exact = (BASE_ARGS[6], code_base - BASE_ARGS[6] + len(standalone))
        protected, bound_labels = operations.assemble(*args, protected_code=exact)
        self.assertEqual(len(standalone), len(protected))
        self.assertEqual(labels, bound_labels)
        self.assertNotEqual(standalone, protected)


if __name__ == '__main__':
    unittest.main()
