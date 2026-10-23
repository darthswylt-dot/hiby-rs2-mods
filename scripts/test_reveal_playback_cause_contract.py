#!/usr/bin/env python3
"""Pinned native boundaries that forbid inferred playback -> paint parents.

Original instructions only: no firmware generation, hook, live read or device
operation. These bounded contracts distinguish an event message, a separately
staged media record, a playback invocation and a later UI message. They do not
resolve B+BA0, establish complete callers or prove a native scheduling edge.
"""

import hashlib
import unittest

import test_folderfollow_reveal_static_contract as source


class RevealPlaybackCauseContractTests(unittest.TestCase):
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

    def test_staged_list_requests_a90_elements_not_an_extended_event_message(self):
        self.words(0x42BA38, [0x24040010, 0x24050A90, 0x0C115B98,
                              0xAE020BB4, 0x8E030044, 0x1460001F,
                              0xAE020BB0])
        # 16 is the capacity REQUEST, not a fixed queue limit. The wrapper
        # requests chunks of ten; constructor rounding gives twenty initially.
        self.words(0x456E60, [0x08115B10, 0x2406000A])
        self.words(0x456C7C, [0x02512021, 0x2484FFFF, 0x0091001A,
                              0x022001F4, 0xAC40000C, 0xAC530010,
                              0xAC510014])
        self.assertEqual(((16 + 10 - 1) // 10) * 10, 20)

    def test_staged_methods_bind_append_clear_index_and_count_to_distinct_slots(self):
        self.words(0x456C98, [0x3C020045, 0x24425DA0, 0xAE020018])
        self.words(0x456CC8, [0x3C020045, 0x244257E0, 0xAE02002C,
                              0x3C020045, 0x244257C0, 0xAE020024,
                              0x3C020045, 0x24425DC0, 0xAE020030])
        self.words(0x455DA0, [0x00A03021, 0x081156F0, 0x8C85000C])
        self.words(0x455DC0, [0x10800003, 0x3C050092,
                              0x03E00008, 0x8C82000C])
        # Append forwards the current count as its insertion index. Indexing
        # and count have separate native methods; no event FIFO pairs them.

    def test_selection_producer_copies_media_and_transition_before_list_append(self):
        self.words(0x428B6C, [0x0C119B68, 0x8E110BB0, 0x1240000B,
                              0, 0x12200009, 0x27A40018, 0x02402821,
                              0x0C296D10, 0x24060A88, 0xAFB30AA0,
                              0x8E390018, 0x02202021, 0x0320F809,
                              0x27A50018, 0x0C119B70, 0x8E040BB4])
        self.assertEqual(0x18 + 0xA88, 0xAA0)

    def test_locally_uninitialized_staged_tail_is_not_an_owned_cause_id(self):
        # The A90-byte append receives the stack record at SP+18. Only the
        # A88-byte media and following transition word are initialized here.
        # No direct store at the last word is NOT a spare-field/lifetime proof.
        tail = 0x18 + 0xA8C
        stores = []
        for pc in range(0x428B40, 0x428BC8, 4):
            word = self.elf.word(pc)
            if word >> 26 == 0x2B and (word >> 21) & 31 == 29:
                stores.append(word & 0xFFFF)
        self.assertNotIn(tail, stores)
        self.assertIn(0xAA0, stores)
        self.assertLess(tail, 0x18 + 0xA90)

    def test_player_message_copies_only_event_and_parameter_words(self):
        self.words(0x42B140, [0x27BDFFD8, 0x3C0200AE, 0xAFA40018,
                              0x8C44D368, 0xAFA5001C, 0x24060008,
                              0xAFBF0024, 0x0C114138, 0x27A50018])
        self.words(0x42E270, [0x8E24D368, 0x27A50AA8, 0x24060008,
                              0xAFA00AA0, 0x0C114180, 0xAFA00AA4,
                              0x1440FFF4, 0x27A40AA0, 0x27A50AA8,
                              0x0C296D10, 0x24060008])
        # The copied eight bytes carry no staged-item pointer, owned media
        # record or additional immutable playback invocation ID.

    def test_event_nine_sender_uses_zero_parameter_not_the_selected_record(self):
        self.words(0x42B1EC, [0x24040009, 0x00002821,
                              0x0810AC50, 0x27BD0028])
        self.words(0x921334 + 9 * 4, [0x42E3A8, 0x42E384, 0x42E32C])
        self.words(0x42E2AC, [0x02621021, 0x8C420000, 0x00400008, 0])
        # Player event 11 and event 9 are separate entries in this table.

    def test_event_nine_chooses_last_staged_item_not_first_event_parent(self):
        self.words(0x42E3CC, [0x8EF90030, 0x0320F809, 0x02E02021,
                              0x14400103, 0x02E02021])
        self.words(0x42E7E8, [0x8EF9002C, 0x0320F809, 0x2445FFFF,
                              0x1040FEFA, 0x0040B821, 0x27A40018,
                              0x00402821, 0x0C296D10, 0x24060A88,
                              0x1000FEF5, 0x8EFE0A88])
        # The selected media and transition are copied before the first
        # unlock. A future receipt must follow THIS selected record.

    def test_selection_unlock_and_later_clear_are_two_distinct_mutex_brackets(self):
        self.words(0x42E3E4, [0x0C119B70, 0x8E040BB4, 0x8E170BB0,
                              0x0C119B68, 0x8E040BB4, 0x12E00004,
                              0, 0x8EF90024, 0x0320F809, 0x02E02021,
                              0x0C119B70, 0x8E040BB4])
        # Clear drops the ENTIRE staged count. It does not remove only the
        # selected item; another producer can append between the brackets.
        self.words(0x4557C0, [0x10800004, 0, 0xAC80000C,
                              0x03E00008, 0x00001021])

    def test_worker_media_copy_must_not_expand_over_live_event_message(self):
        self.words(0x42E294, [0x0C296D10, 0x24060008,
                              0x8FA20AA0])
        self.words(0x42E804, [0x0C296D10, 0x24060A88,
                              0x1000FEF5, 0x8EFE0A88])
        self.assertEqual(0x18 + 0xA88, 0xAA0)
        # Producer appends A90, but worker intentionally copies only A88:
        # SP+AA0/AA4 still hold its event/parameter, with transition in FP.

    def test_general_commit_uses_local_copy_after_clear_not_a_message_receipt(self):
        self.words(0x42E414, [0x0C108E60, 0x24040032, 0x1040012C,
                              0x24020001, 0x8E040BA4, 0x27A50018,
                              0x0C10B318, 0x03C03021, 0x1000FF89])
        # The shown return rejoins the worker loop. It is not evidence of
        # a common player-event11 or Files-event140 path after general commit.

    def test_general_callee_also_flushes_events_outside_staging_fixture_boundary(self):
        self.words(0x42CD64, [0x3C0200AE, 0x8C44D368,
                              0x0C1141C8, 0xAE000BB8])
        # The instruction fixture substitutes42CC60. Its repeat-event empty
        # cases do not prove later queued events survive the actual callee.

    def test_optional_playback_callbacks_pass_mutable_global_media_not_cause_id(self):
        self.words(0x42CBFC, [0x8E390BA0, 0x13200004, 0,
                              0x8E240B98, 0x0320F809, 0x2685D468])
        self.words(0x42D690, [0x8E190BA0, 0x13200004, 0,
                              0x8E040B98, 0x0320F809, 0x2685D468])
        # Fast calls42CA00 before this optional callback; general does it
        # afterwards. The actual B+BA0 target/causal propagation remain unknown.
        self.words(0x42CBF4, [0x0C10B280, 0x02002021])
        self.words(0x42D6A8, [0x0C10B280, 0x02202021])

    def test_fast_completion_posts_player_event_eleven_not_ui_event_140(self):
        self.words(0x42CC14, [0x2404000B, 0x0C10AC50, 0x00002821])
        self.words(0x42E36C, [0x24040005, 0x24050001,
                              0x0C12EB20, 0x00003021])
        # Do not promote an unresolved indirect/transitive route to a proved
        # UI notification merely because it sometimes follows a media change.

    def test_ui_sender_fills_five_words_without_an_extra_playback_identity(self):
        self.words(0x4743B4, [0x27A40018, 0x00002821, 0x00C09021,
                              0x0C296F18, 0x24060014, 0x0C119A58, 0])
        self.words(0x4743D4, [0x27A50018, 0x24060014, 0xAFA20028,
                              0xAFB1001C, 0xAFB30020, 0x0C114138,
                              0xAFB20024])
        # [zero, event, parameter1, parameter2, clock]. Even if a parameter
        # happens to be a pointer, copying it creates no target-retention lease.

    def test_ui_dispatch_uses_message_event_and_borrowed_stack_copy(self):
        self.words(0x454248, [0x8E040014, 0x0C114180, 0x24060014])
        self.words(0x45425C, [0x24846B94, 0x8FA6001C])
        self.words(0x454294, [0x8C990004, 0x1320FFE6, 0x02202021,
                              0x0320F809, 0x27A50018])
        self.words(0x926D74, [0x140, 0x453940])

    def test_native_dequeue_frees_heap_message_after_copy_not_after_handler(self):
        self.words(0x45066C, [0x8C450000, 0x0C296D10, 0x02203021])
        self.words(0x450688, [0x8C840000, 0x10800006, 0x00031880,
                              0x0C119AA0, 0])
        # A later map-by-heap-address is ABA-unsafe. This bounded observation
        # neither classifies every producer nor permits reading freed memory.


if __name__ == '__main__':
    unittest.main()
