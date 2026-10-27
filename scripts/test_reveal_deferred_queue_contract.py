#!/usr/bin/env python3
"""Hash-pinned native premises for a separate checked deferred transport guard.

These checks leave the original worker, its16-byte action queue and T+10
mutex unchanged. They are bounded source observations, not initialized-mutex,
mapped-storage, cooperating-writer, object-lifetime or universal lock-order
proofs. A distinct retained transport mutex must guard every access, including
cleanup/rebind paths; a successful extraction does not acknowledge paint.
Missing or changed reference data fails instead of skipping these checks.
"""

import hashlib
import unittest

import test_folderfollow_reveal_static_contract as source


class DeferredQueueContractTests(unittest.TestCase):
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

    def test_raw_endpoints_jump_to_relocated_pthread_lock_and_unlock(self):
        self.words(0xA5B960, [0x3C0F00A7, 0x8DF9FA58,
                             0x03200008, 0x25F8FA58])
        self.words(0xA5B830, [0x3C0F00A7, 0x8DF9FA0C,
                             0x03200008, 0x25F8FA0C])
        elf = self.elf
        start, size, count = elf.u32(0x20), elf.u16(0x2E), elf.u16(0x30)
        found = {}
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
                if address not in (0xA6FA0C, 0xA6FA58):
                    continue
                self.assertEqual(info & 0xFF, 127)  # R_MIPS_JUMP_SLOT
                symbol = elf.u32(symbols + 16) + (info >> 8) * 16
                name = elf.data[string_offset + elf.u32(symbol):].split(b'\0', 1)[0]
                found[address] = name.decode('ascii')
        self.assertEqual(found, {0xA6FA0C: 'pthread_mutex_unlock',
                                 0xA6FA58: 'pthread_mutex_lock'})
        # Import resolution, mutex initialization and retained24-byte storage
        # remain caller premises; this does not execute a platform mutex.

    def test_native_facades_replace_both_actual_raw_results_with_zero(self):
        self.words(0x466DA0, [0x27BDFFE0, 0xAFBF001C,
                             0x0C296E58, 0, 0x8FBF001C,
                             0x00001021, 0x03E00008, 0x27BD0020])
        self.words(0x466DC0, [0x27BDFFE0, 0xAFBF001C,
                             0x0C296E0C, 0, 0x8FBF001C,
                             0x00001021, 0x03E00008, 0x27BD0020])
        self.assertEqual(self.direct(0x466DA0, 0x466DC0),
                         {0x466DA8: 0xA5B960})
        self.assertEqual(self.direct(0x466DC0, 0x466DE0),
                         {0x466DC8: 0xA5B830})
        # Raw errors require external quarantine, not a guessed unlock,
        # retry or shared fault write after uncertain acquisition/release.

    def test_native_mutex_factory_ignores_initialization_status(self):
        self.words(0x466D64, [0x24040018, 0xAFBF001C,
                             0x0C119A78, 0xAFB00018,
                             0x00402021, 0x00002821,
                             0x0C296E28, 0x00408021,
                             0x8FBF001C, 0x02001021])
        # The returned allocation is not proof pthread_mutex_init succeeded;
        # default attributes also do not establish a recursive-lock contract.

    def test_factory_has_dynamic_width_and_rounds_capacity_to_ten_slots(self):
        self.words(0x456E60, [0x08115B10, 0x2406000A])
        self.words(0x456C40, [0x27BDFFC8, 0xAFB20024,
                             0x00809021, 0x24040038])
        self.words(0x456C68, [0x00A09821, 0x0C119A78, 0x00C08821])
        self.words(0x456C7C, [0x02512021, 0x2484FFFF,
                             0x0091001A, 0x022001F4,
                             0xAC40000C, 0xAC530010, 0xAC510014])
        self.words(0x456CFC, [0x00001812, 0x70711002,
                             0x0051001A, 0x022001F4, 0xAE020008])
        # For a positive requested capacity: Q+8=ceil(request/10)*10.
        # Q+10 is independently supplied width, not this capacity or count.
        self.assertEqual(((32 + 10 - 1) // 10) * 10, 40)

    def test_constructor_binds_methods_without_initializing_header_plus_four(self):
        for start, target, field in ((0x456C98, 0x455DA0, 0x18),
                                      (0x456CA4, 0x455BC0, 0x1C),
                                      (0x456CB0, 0x455860, 0x20),
                                      (0x456CBC, 0x455AE0, 0x28),
                                      (0x456CC8, 0x4557E0, 0x2C),
                                      (0x456CD4, 0x4557C0, 0x24),
                                      (0x456CE0, 0x455DC0, 0x30),
                                      (0x456CEC, 0x455E00, 0x34)):
            self.words(start, [0x3C020045,
                               0x24420000 | (target & 0xFFFF),
                               0xAE020000 | field])
        offsets = set()
        for pc in range(0x456C8C, 0x456D10, 4):
            word = self.elf.word(pc)
            if word >> 26 == 43 and (word >> 21) & 31 in (2, 16):
                offsets.add(word & 0xFFFF)
        self.assertEqual(offsets, {0, 8, 0xC, 0x10, 0x14, 0x18, 0x1C,
                                   0x20, 0x24, 0x28, 0x2C, 0x30, 0x34})
        # Do not invent a reserved-zero test for the uninitialized Q+4 word.
        # Pointer-table and complete touched chunks still require retention,
        # mapped extents, nonaliasing and participation by every list user.

    def test_append_full_boundary_uses_actual_capacity_and_can_enter_growth(self):
        self.words(0x455DA0, [0x00A03021, 0x081156F0, 0x8C85000C])
        self.words(0x455C10, [0x8EC20008, 0x0082102A,
                             0x10400050, 0])
        self.assertEqual(self.branch(0x455C18), 0x455D5C)
        self.words(0x455D5C, [0x8EC50014, 0x0C115660,
                             0x02C02021, 0x0440000A, 0])
        # Wrappers must deny count>=Q+8 before invoking append, as well as
        # enforce their own bounded logical limit and known header schema.

    def test_append_copies_body_before_count_and_returns_previous_index(self):
        self.words(0x455CCC, [0x8EC20010, 0x00139880, 0x00B32821,
                             0x70541802, 0x8CA40000, 0x8FA50048,
                             0x00403021, 0x0C296D10, 0x00642021,
                             0x8EC2000C, 0x24420001, 0xAEC2000C,
                             0x8FBF003C, 0x02A01021])
        self.assertLess(0x455CE8, 0x455CF8)
        # Actual success0,1,... is not a pthread status or paint nonce.
        # A postcondition mismatch cannot promise transactional rollback.

    def test_get_returns_borrowed_head_without_copy_or_lock(self):
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
        # The private68 snapshot must finish while the separate guard is
        # held and before REMOVE can immediately reuse this borrowed address.

    def test_remove_moves_spare_slots_in_last_live_chunk_not_only_live_bytes(self):
        self.words(0x455884, [0x8C94000C, 0x1A800030, 0x2402FFFE])
        self.words(0x4558A4, [0x8C830014, 0x8C910000,
                             0x00A3001A, 0x006001F4,
                             0x0283A021, 0x2694FFFF, 0x8C820010,
                             0x00009012, 0x00122880, 0x02258821,
                             0x00002010, 0x0283001A, 0x006001F4,
                             0x10000006, 0x0000A012])
        self.words(0x4558F4, [0x00641823, 0x2466FFFF, 0x70821802,
                             0x8E330000, 0x26520001, 0x26310004,
                             0x70C23002, 0x00732021,
                             0x0C296D10, 0x00822821])
        self.words(0x45591C, [0x8E040014, 0x8E020010,
                             0x0254182A, 0x2484FFFF, 0x70822802,
                             0x00403021, 0x1460FFEA, 0x00B32021])
        self.words(0x45593C, [0x8E03000C, 0x00001021,
                             0x2463FFFF, 0xAE03000C])
        # The loop bound is ceil(count/chunk), NOT all allocated chunks.
        # Even count1,chunk10,width68 moves nine spare slots in that chunk.
        # Return0 acknowledges extraction, never publication or rendering.

    def test_list_methods_have_no_embedded_guard_or_registry_callback(self):
        expected = (
            (0x4557E0, 0x455844, {}),
            (0x455860, 0x45597C,
             {0x4558E0: 0xA5B440, 0x455914: 0xA5B440}),
            (0x455BC0, 0x455DA0,
             {0x455CA0: 0xA5B440, 0x455CE8: 0xA5B440,
              0x455D48: 0xA5B440, 0x455D60: 0x455980}),
            (0x455DA0, 0x455DAC, {0x455DA4: 0x455BC0}),
        )
        for start, end, edges in expected:
            with self.subTest(method=f'{start:#x}'):
                self.assertEqual(self.direct(start, end), edges)
                self.assertFalse(any(self.elf.word(pc) >> 26 == 0
                                     and self.elf.word(pc) & 63 == 9
                                     for pc in range(start, end, 4)))
        # This stops at native heap/libc services, not a universal proof
        # about arbitrary imported services, rebound methods or callbacks.

    def test_growth_null_result_clobbers_table_before_error_and_no_rollback(self):
        self.words(0x4559F8, [0x8E040000, 0x0C119AC8, 0x00142880,
                             0x10400030, 0xAE020000])
        self.assertEqual(self.branch(0x455A04), 0x455AC8)
        self.words(0x455AC8, [0x1000FFEB, 0x2402FFFF])
        self.words(0x455A4C, [0x0C119A78, 0x70442002,
                             0x00402021, 0x00002821,
                             0x1440FFF0, 0xAE420000])
        # NULL is written to Q+0 in the branch delay slot. Earlier growth
        # effects are not undone if later block allocation fails either.

    def test_clear_is_only_count_reset_not_erasure_revocation_or_drain(self):
        self.words(0x4557C0, [0x10800004, 0, 0xAC80000C,
                             0x03E00008, 0x00001021,
                             0x03E00008, 0x2402FFFA])
        self.assertEqual(self.direct(0x4557C0, 0x4557DC), {})
        # A transport guard cannot turn native clear into an owner-retire,
        # paint acknowledgement, private-copy wipe or safe-free operation.

    def test_original_worker_constructor_keeps_its_own_sixteen_byte_queue_and_mutex(self):
        self.words(0x4BAAEC, [0x24040010, 0x0C115B98,
                             0x24050010, 0x10400030, 0xAE02001C])
        self.words(0x4BAB04, [0x0C119B58, 0, 0x0C119B58,
                             0xAE020008, 0x0C119B58,
                             0xAE02000C, 0xAE020010])
        self.words(0x4BACB4, [0x0C119B68, 0x8E040010,
                             0x8E04001C, 0x24020001,
                             0x27A50018, 0x8C990018,
                             0xAFA20018, 0xAFB30024,
                             0xAFB2001C, 0x0320F809, 0xAFB10020,
                             0x0C119B70, 0x8E040010])
        # A new dedicated pinned T/Q is not this worker's+10/+1C pair.
        # The original frame/record width and producer route stay unchanged.

    def test_original_worker_nests_registry_before_releasing_its_own_ten_mutex(self):
        self.words(0x4BA914, [0x0C119B70, 0x8E640010])
        self.words(0x4BA934, [0x0C119B68, 0x8E640010])
        self.words(0x4BA93C, [0x8E64001C, 0x8C990030,
                             0x0320F809, 0])
        self.words(0x4BA954, [0x8E64001C, 0x8C99002C,
                             0x0320F809, 0x00002821])
        self.words(0x4BA99C, [0x8E190274, 0x02002021,
                             0x0320F809, 0x26160034])
        self.words(0x4BAA70, [0x1000FFA1, 0xAEE00000])
        self.assertEqual(self.branch(0x4BAA70), 0x4BA8F8)
        self.words(0x4BA8F8, [0x8E64001C, 0x00002821,
                             0x8C990020, 0x0320F809])
        # This known local stock T+10->R route is not permission to reuse T.
        # The separate transport must release its guard before R->P dispatch.
        # With multiple drainers, FIFO extraction alone does not order later
        # publication; single ordered dispatch remains a caller premise.


if __name__ == '__main__':
    unittest.main()
