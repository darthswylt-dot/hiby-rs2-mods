#!/usr/bin/env python3
"""Hash-pinned source boundaries for passive playback dispatch observations.

These inspect the preserved ELF only. They neither build/install firmware nor
claim that an optional indirect callback returned, delivered UI event 140, or
caused a paint. The inbound census covers encoded direct branches/jumps and
aligned file-backed words, not computed entries, runtime writes or lifetimes.
"""

import hashlib
import struct
import unittest

import test_folderfollow_reveal_static_contract as source


HOOKS = ((0x42CC0C, 0x42CC14), (0x42D6A0, 0x42D6A8))


class RevealPlaybackDispatchContractTests(unittest.TestCase):
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

    def test_fast_optional_callback_guard_and_arguments_precede_hook(self):
        self.words(0x42CBF4, [0x0C10B280, 0x02002021, 0x8E390BA0,
                              0x13200004, 0, 0x8E240B98,
                              0x0320F809, 0x2685D468])
        # The zero-target branch skips both replaced words. A passive wrapper
        # must not turn that branch into a capture/call of an absent callback.
        self.assertEqual(0x42CC00 + 4 + 4 * 4, 0x42CC14)

    def test_general_optional_callback_guard_and_arguments_precede_hook(self):
        self.words(0x42D690, [0x8E190BA0, 0x13200004, 0,
                              0x8E040B98, 0x0320F809, 0x2685D468])
        self.assertEqual(0x42D694 + 4 + 4 * 4, 0x42D6A8)

    def test_native_calls_link_ra_to_original_post_delay_address(self):
        for site, resume in HOOKS:
            with self.subTest(site=f'{site:#x}'):
                word = self.elf.word(site)
                self.assertEqual(word, 0x0320F809)
                self.assertEqual(source.decode(site, word), 'jalr ra,t9')
                self.assertEqual((word >> 21) & 31, 25)  # native t9 target
                self.assertEqual((word >> 11) & 31, 31)  # native ra link
                self.assertEqual(site + 8, resume)
        # Native link addresses are source facts, not evidence that execution
        # eventually reaches either address after the indirect dispatch.

    def test_native_delay_sets_a1_to_global_media_not_an_owned_cause(self):
        self.words(0x42CBD0, [0x3C1400AE, 0x2684D468, 0x02002821,
                              0x0C296D10, 0x24060A88])
        self.words(0x42CD50, [0x3C1400AE, 0x2684D468, 0x02202821,
                              0x0C296D10, 0x24060A88])
        for site, _ in HOOKS:
            with self.subTest(site=f'{site:#x}'):
                self.assertEqual(self.elf.word(site + 4), 0x2685D468)
                self.assertEqual(source.decode(site + 4, 0x2685D468),
                                 'addiu a1,s4,-11160')
        self.assertEqual(0xAE0000 - 11160, 0xADD468)

    def test_fast_preconditions_and_index_fallback_are_outside_hook(self):
        self.words(0x42CBC8, [0x1440FFE3, 0x02802021])
        self.words(0x42CBE4, [0x8E020420, 0x2403FFFF, 0x10430016,
                              0xAE2200E8, 0x0C10B280, 0x02002021])
        self.words(0x42CC48, [0x8E22001C, 0x1000FFE9, 0xAE2200E8])
        # Both index paths rejoin before the optional callback; neither
        # branch is permission to move the capture ahead of native admission.

    def test_original_post_dispatch_operations_are_distinct(self):
        self.words(0x42CC14, [0x2404000B, 0x0C10AC50, 0x00002821,
                              0x1000FFD1, 0x2664DFB4])
        self.words(0x42D6A8, [0x0C10B280, 0x02202021,
                              0x0C2295C1, 0x00002021])
        # General's continuation is not fast's player-event11 continuation.

    def test_no_encoded_direct_branch_or_jump_enters_either_replaced_range(self):
        targets = {site + offset for site, _ in HOOKS for offset in (0, 4)}
        incoming = []
        for start, end in self.elf.executable_ranges():
            offset = self.elf.va_to_off(start)
            for index, (word,) in enumerate(struct.iter_unpack(
                    self.elf.endian + 'I', self.elf.data[offset:offset + (end - start) // 4 * 4])):
                pc = start + index * 4
                op = word >> 26
                target = None
                if op in (2, 3):
                    target = ((pc + 4) & 0xF0000000) | ((word & 0x03FFFFFF) << 2)
                elif op in (1, 4, 5, 6, 7, 20, 21, 22, 23):
                    imm = word & 0xFFFF
                    signed = imm - 0x10000 if imm & 0x8000 else imm
                    target = pc + 4 + signed * 4
                if target in targets:
                    incoming.append((pc, target))
        self.assertEqual(incoming, [])

    def test_no_aligned_file_backed_word_names_hook_or_delay_address(self):
        targets = {site + offset for site, _ in HOOKS for offset in (0, 4)}
        references = []
        for start, offset, size, _, _ in self.elf.loads:
            for index, (word,) in enumerate(struct.iter_unpack(
                    self.elf.endian + 'I', self.elf.data[offset:offset + size // 4 * 4])):
                if word in targets:
                    references.append((start + index * 4, word))
        self.assertEqual(references, [])

    def test_event_eleven_table_entry_is_not_event_nine_or_ui_140(self):
        self.words(0x921334 + 9 * 4, [0x42E3A8, 0x42E384, 0x42E32C])
        self.words(0x42B140, [0x27BDFFD8, 0x3C0200AE, 0xAFA40018,
                              0x8C44D368, 0xAFA5001C, 0x24060008,
                              0xAFBF0024, 0x0C114138, 0x27A50018])

    def test_event_eleven_parameter_selects_action_zero_or_five(self):
        self.words(0x42E360, [0x8FA20AA4, 0x1040012B, 0x00002821,
                              0x24040005, 0x24050001, 0x0C12EB20,
                              0x00003021, 0x1000FFB7, 0])
        self.words(0x42E814, [0x00003021, 0x0C12EB20, 0x00002021])
        # The taken branch retains its delay-slot a1=0: (0,0,0).
        # The nonzero branch overwrites a1=1: (5,1,0). Neither contains an ID.

    def test_action_sender_uses_current_controller_and_sixteen_byte_record(self):
        self.words(0x43D200, [0x3C0200AE, 0x03E00008, 0x8C42F208])
        self.words(0x4BAC98, [0x00809821, 0x00A09021, 0x0C10F480,
                              0x00C08821, 0x10400012, 0x8FBF003C,
                              0x8C5000C4, 0x0C119B68, 0x8E040010,
                              0x8E04001C, 0x24020001, 0x27A50018,
                              0x8C990018, 0xAFA20018, 0xAFB30024,
                              0xAFB2001C, 0x0320F809, 0xAFB10020])
        self.words(0x4BAAEC, [0x24040010, 0x0C115B98, 0x24050010])
        # Append copies [marker1,param1,param2,action], not a retained B pointer
        # or a newly owned immutable playback/notification ID.

    def test_action_worker_takes_fifo_zero_and_resolves_current_controller_again(self):
        self.words(0x4BA934, [0x0C119B68, 0x8E640010, 0x8E64001C,
                              0x8C990030, 0x0320F809, 0, 0x1040FFF1,
                              0x0040A821, 0x8E64001C, 0x8C99002C,
                              0x0320F809, 0x00002821, 0x1040FFE4,
                              0x0040B821, 0x8C430004, 0x8C5E0008,
                              0xAFA32020, 0x8C43000C, 0x0C10F480,
                              0xAFA32024])

    def test_action_fanout_re_resolves_names_then_passes_original_three_scalars(self):
        self.words(0x4BAA1C, [0x02C02821, 0x0C10E830, 0x02002021,
                              0x8E040024, 0x02C02821, 0x02803021,
                              0x0C121778, 0x0040B021, 0x1040000A,
                              0x26520001, 0x12C00008, 0x00402021,
                              0x8C590150, 0x13200005, 0x02C02821,
                              0x8FA62024, 0x8FA72020, 0x0320F809,
                              0xAFBE0010])
        self.words(0x4BA8F8, [0x8E64001C, 0x00002821, 0x8C990020,
                              0x0320F809, 0x2AB50002])
        # Queue storage and name-resolved objects are separate lifetimes.
        # Callback success, identity retention and complete fanout are unproved.

    def test_explorer_callback_binding_and_admission_ignore_actions_zero_and_five(self):
        self.words(0x4928A8, [0x3C050049, 0x02402021,
                              0x0C116560, 0x24A50980])
        self.words(0x459580, [0x10800004, 0, 0xAC850150,
                              0x03E00008, 0x00001021])
        self.words(0x490980, [0x10800006, 0, 0x10A00004, 0,
                              0x24020001, 0x10C20003, 0,
                              0x03E00008, 0x00001021])
        # 0/5 follow the immediate return; this callback cannot establish an
        # event11 -> Files reset, reconcile or paint edge for those actions.

    def test_now_playing_action_zero_sets_lazy_refresh_flag_not_a_files_reset(self):
        self.words(0x4E5FCC, [0x16200010, 0x24020004, 0x16400005,
                              0x24030001, 0x8E020044, 0xAE030048,
                              0xAE000034, 0xAC4001B0])
        self.words(0x4E6010, [0x1622FFF6, 0x24020001,
                              0x1000FFF4, 0xAE02053C])
        self.words(0x4E96D8, [0x24040018, 0x02402821, 0x00003021,
                              0xAE000048, 0x0C10AB58, 0xAE000030])
        # Later refresh samples property24; the flag owns no original media ID.

    def test_general_action_one_paint_route_is_separate_from_event_eleven(self):
        self.words(0x42D60C, [0x8E050038, 0x24040001,
                              0x0C12EB20, 0x00003021])
        self.words(0x4909F4, [0x27A60018, 0x00003821, 0xAFA90018,
                              0xAFA80020, 0xAFA20024, 0x0C10F218,
                              0xAFA3001C])
        self.words(0x43C8A4, [0x0C10E640, 0xAFA20030])
        self.words(0x43990C, [0x8C990284, 0x00808021, 0x0320F809,
                              0xAFA50018, 0x8E040128, 0x8C990018,
                              0x0320F809, 0x8FA50018, 0x8E190288,
                              0x0320F809, 0x02002021])
        # This is a source-grounded conditional route to a paint-request list,
        # not proof of reset, completed paint or association with an LQBR ID.


if __name__ == '__main__':
    unittest.main()
