#!/usr/bin/env python3
"""Hash-gated structural guards for reveal-design inputs; no firmware build.

These compare audited original instructions, not live object lifetimes,
thread serialization, callback coverage, or readiness for installation.
The preserved reference is required: missing/mismatched input is an error,
never a skipped test. No device, network, or source-binary writes are made.
"""

import hashlib
from pathlib import Path
import unittest

from mips_static_trace import Elf32, decode


SOURCE = (Path(__file__).resolve().parents[1]
          / 'artifacts/import-20261001/hiby_player_02fd.bin')
SOURCE_SHA256 = '02fd1dd13db7aac1e6d150ec1866b93f57022c1d668b114720a36b7f232e5f87'
SOURCE_SIZE = 7_133_528


class RevealStaticContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.elf = Elf32(SOURCE)
        digest = hashlib.sha256(cls.elf.data).hexdigest()
        if digest != SOURCE_SHA256 or len(cls.elf.data) != SOURCE_SIZE:
            raise AssertionError(f'unrecognized reference: SHA-256 {digest}, '
                                 f'size {len(cls.elf.data)}')

    def instructions(self, start, expected):
        """Keep each expected instruction readable and independently anchored."""
        for index, (word, assembly) in enumerate(expected):
            pc = start + 4 * index
            with self.subTest(pc=f'{pc:#x}', assembly=assembly):
                self.assertEqual(self.elf.word(pc), word)
                self.assertEqual(decode(pc, word), assembly)

    def test_metadata_setters_store_distinct_fields_in_return_delay_slots(self):
        # +1E0 is the total-count field in the inspected loader chain, not
        # evidence that this many cache descriptors have completed filling.
        for address, offset in ((0x4A07E0, 0x1E0), (0x4A0800, 0x1DC),
                                (0x4A0820, 0x1E4), (0x4A0840, 0x1D4)):
            self.instructions(address, [
                (0x03E00008, 'jr ra'),
                (0xAC850000 | offset, f'sw a1,+{offset:#x}(a0)'),
            ])

    def test_constructor_binds_each_metadata_setter_to_its_own_slot(self):
        self.instructions(0x4A0920, [
            (0x3C02004A, 'lui v0,0x4A'),
            (0x244207E0, 'addiu v0,v0,2016'),
            (0xAE020400, 'sw v0,+0x400(s0)'),
            (0x3C02004A, 'lui v0,0x4A'),
            (0x24420800, 'addiu v0,v0,2048'),
            (0xAE020404, 'sw v0,+0x404(s0)'),
            (0x3C02004A, 'lui v0,0x4A'),
            (0x24420820, 'addiu v0,v0,2080'),
            (0xAE020408, 'sw v0,+0x408(s0)'),
            (0x3C02004A, 'lui v0,0x4A'),
            (0x24420840, 'addiu v0,v0,2112'),
            (0xAE02040C, 'sw v0,+0x40c(s0)'),
        ])

    def test_loader_publishes_count_and_window_metadata_before_fill(self):
        # The list is published in 0x6F76E0's call delay slot BEFORE its
        # result is passed to +400, and before 0x6F7CA0 populates rows.
        # Thus publication/total alone cannot certify a completed mapping.
        self.instructions(0x495130, [
            (0x00E0A821, 'addu s5,a3,zero'),
            (0x10400047, 'beq v0,zero,0x495254'),
            (0x00408821, 'addu s1,v0,zero'),
            (0x02A02021, 'addu a0,s5,zero'),
            (0x0C1BDDB8, 'jal 0x6F76E0'),
            (0xAE820000, 'sw v0,+0x0(s4)'),
            (0xAE420000, 'sw v0,+0x0(s2)'),
            (0x8E190400, 'lw t9,+0x400(s0)'),
            (0x00402821, 'addu a1,v0,zero'),
            (0x0320F809, 'jalr ra,t9'),
            (0x02002021, 'addu a0,s0,zero'),
            (0x8E190404, 'lw t9,+0x404(s0)'),
            (0x02002021, 'addu a0,s0,zero'),
            (0x0320F809, 'jalr ra,t9'),
            (0x00002821, 'addu a1,zero,zero'),
            (0x8E190408, 'lw t9,+0x408(s0)'),
            (0x02002021, 'addu a0,s0,zero'),
            (0x0320F809, 'jalr ra,t9'),
            (0x02602821, 'addu a1,s3,zero'),
            (0x8E19040C, 'lw t9,+0x40c(s0)'),
            (0x02002021, 'addu a0,s0,zero'),
            (0x0320F809, 'jalr ra,t9'),
            (0x02602821, 'addu a1,s3,zero'),
            (0xAFB50010, 'sw s5,+0x10(sp)'),
            (0x02202021, 'addu a0,s1,zero'),
            (0x00002821, 'addu a1,zero,zero'),
            (0x02603021, 'addu a2,s3,zero'),
            (0x0C1BDF28, 'jal 0x6F7CA0'),
            (0x00003821, 'addu a3,zero,zero'),
            (0x8E23000C, 'lw v1,+0xc(s1)'),
        ])

    def test_property24_getter_copies_full_descriptor_to_passed_buffer(self):
        self.assertEqual(self.elf.word(0x9212B8 + 24 * 4), 0x42B048)
        self.instructions(0x42AD88, [
            (0x00809021, 'addu s2,a0,zero'),
            (0x00A08821, 'addu s1,a1,zero'),
            (0x0320F809, 'jalr ra,t9'),
            (0x00C09821, 'addu s3,a2,zero'),
        ])
        self.instructions(0x42B048, [
            (0x12200005, 'beq s1,zero,0x42B060'),
            (0x3C0500AE, 'lui a1,0xAE'),
            (0x02202021, 'addu a0,s1,zero'),
            (0x24A5D468, 'addiu a1,a1,-11160'),
            (0x0C296D10, 'jal 0xA5B440'),
            (0x24060A88, 'addiu a2,zero,2696'),
        ])
        # Existing descriptor audit identifies path at +4 and cue at +424.
        # Those field meanings are not established by this memcpy block.
        self.assertEqual((0xAE << 16) - 11160, 0xADD468)
        self.assertEqual(2696, 0xA88)

    def test_getter_callbacks_do_not_imply_unproved_writer_serialization(self):
        self.instructions(0x42AD70, [(0x8E190048, 'lw t9,+0x48(s0)')])
        self.instructions(0x42ADB4, [
            (0x8E19004C, 'lw t9,+0x4c(s0)'),
            (0x8FB0001C, 'lw s0,+0x1c(sp)'),
            (0x03200008, 'jr t9'),
            (0x27BD0030, 'addiu sp,sp,48'),
        ])

    def test_timer10_registration_preserves_original_callback_and_context(self):
        self.instructions(0x4EAEBC, [
            (0x3C06004F, 'lui a2,0x4F'),
            (0xAE020014, 'sw v0,+0x14(s0)'),
            (0x02003821, 'addu a3,s0,zero'),
            (0x24050064, 'addiu a1,zero,100'),
            (0x24C690C0, 'addiu a2,a2,-28480'),
            (0x0C11CE28, 'jal 0x4738A0'),
            (0x2404000A, 'addiu a0,zero,10'),
        ])
        self.assertEqual((0x4F << 16) - 28480, 0x4E90C0)

    def test_teardown_clears_playing_owner_then_removes_timer10(self):
        self.instructions(0x4E5E38, [
            (0x3C0200B9, 'lui v0,0xB9'),
            (0xAC40BACC, 'sw zero,-0x4534(v0)'),
        ])
        self.instructions(0x4E5E64, [
            (0x0C11CE80, 'jal 0x473A00'),
            (0x2404000A, 'addiu a0,zero,10'),
            (0x0C10C788, 'jal 0x431E20'),
            (0x8E040254, 'lw a0,+0x254(s0)'),
        ])
        self.assertEqual((0xB9 << 16) - 0x4534, 0xB8BACC)

    def test_view_teardown_marks_closing_and_conditionally_stops_private_worker(self):
        # V+44 is a teardown marker, not an atomic lifetime acquisition.
        self.instructions(0x493B0C, [
            (0x24020001, 'addiu v0,zero,1'),
            (0xAE020044, 'sw v0,+0x44(s0)'),
        ])
        self.instructions(0x493BE4, [
            (0x8E0200D0, 'lw v0,+0xd0(s0)'),
            (0x8C420074, 'lw v0,+0x74(v0)'),
            (0x14400036, 'bne v0,zero,0x493CC8'),
            (0x02402821, 'addu a1,s2,zero'),
            (0x0C123D48, 'jal 0x48F520'),
            (0x8E043B84, 'lw a0,+0x3b84(s0)'),
        ])
        # The other branch cancels a job on controller+30's shared worker;
        # it must not be described as joining the private V+3B84 worker.
        self.instructions(0x493CC8, [
            (0x8E0200D4, 'lw v0,+0xd4(s0)'),
            (0x0C123B88, 'jal 0x48EE20'),
            (0x8C440030, 'lw a0,+0x30(v0)'),
        ])

    def test_worker_completion_barrier_uses_mutex_not_a_pthread_join_call(self):
        # Worker locks T+0C on entry and unlocks it at its stop exit.
        # These are bounded structural anchors, not a full CFG/lock proof.
        self.instructions(0x48EAC0, [
            (0x8E04000C, 'lw a0,+0xc(s0)'),
            (0x0C119B68, 'jal 0x466DA0'),
            (0x3C140094, 'lui s4,0x94'),
        ])
        self.instructions(0x48ECD4, [
            (0x0C119B70, 'jal 0x466DC0'),
            (0x8E04000C, 'lw a0,+0xc(s0)'),
        ])
        # Stop flag and wake, then lock/unlock T+0C before destroying it.
        self.instructions(0x48F538, [
            (0x8C840014, 'lw a0,+0x14(a0)'),
            (0x24020001, 'addiu v0,zero,1'),
            (0xAE020004, 'sw v0,+0x4(s0)'),
            (0x0C119B40, 'jal 0x466D00'),
            (0x00000000, 'nop'),
            (0x0C119B48, 'jal 0x466D20'),
            (0x8E040014, 'lw a0,+0x14(s0)'),
            (0x0C119B68, 'jal 0x466DA0'),
            (0x8E04000C, 'lw a0,+0xc(s0)'),
            (0x0C119B70, 'jal 0x466DC0'),
            (0x8E04000C, 'lw a0,+0xc(s0)'),
            (0x0C119B78, 'jal 0x466DE0'),
            (0x8E04000C, 'lw a0,+0xc(s0)'),
        ])

    def test_worker_mutex_and_object_destroyed_before_later_registry_removal(self):
        # 0x493BF4 calls this worker destructor before the later registry
        # removal sites below. Holding only the registry lookup bracket is
        # therefore NOT established to keep T or its mutex alive. These
        # anchors preserve that counterexample, not a concurrency guarantee.
        self.instructions(0x48F594, [
            (0x8E040010, 'lw a0,+0x10(s0)'),
            (0x0C119B78, 'jal 0x466DE0'),
            (0xAE000134, 'sw zero,+0x134(s0)'),
            (0x8E040018, 'lw a0,+0x18(s0)'),
            (0x10800003, 'beq a0,zero,0x48F5B4'),
            (0x00000000, 'nop'),
            (0x0C119AA0, 'jal 0x466A80'),
            (0x00000000, 'nop'),
            (0x02002021, 'addu a0,s0,zero'),
            (0x0C119AA0, 'jal 0x466A80'),
            (0xAE000018, 'sw zero,+0x18(s0)'),
        ])
        for address in (0x493C6C, 0x493F6C):
            self.instructions(address, [
                (0x8E0400D4, 'lw a0,+0xd4(s0)'),
                (0x0C139528, 'jal 0x4E54A0'),
                (0x02002821, 'addu a1,s0,zero'),
            ])
        # The ordinary list/P/V frees occur still later on this path.
        for address in (0x493FA8, 0x493FBC):
            self.instructions(address, [
                (0x0C115BA0, 'jal 0x456E80'),
                (0x00000000, 'nop'),
            ])
        self.instructions(0x493FD0, [
            (0x0C10F530, 'jal 0x43D4C0'),
            (0x00000000, 'nop'),
            (0xAE003B68, 'sw zero,+0x3b68(s0)'),
            (0x0C119AA0, 'jal 0x466A80'),
            (0x02002021, 'addu a0,s0,zero'),
        ])

    def test_timer_pump_calls_synchronously_then_reloads_mutable_timer_count(self):
        self.instructions(0x47361C, [
            (0x8E190008, 'lw t9,+0x8(s0)'),
            (0x13200009, 'beq t9,zero,0x473648'),
            (0xAE00FFFC, 'sw zero,-0x4(s0)'),
            (0x8E04FFF4, 'lw a0,-0xc(s0)'),
            (0x0320F809, 'jalr ra,t9'),
            (0x8E050004, 'lw a1,+0x4(s0)'),
            (0x8EA39B74, 'lw v1,-0x648c(s5)'),
            (0x10760005, 'beq v1,s6,0x473650'),
            (0x26310001, 'addiu s1,s1,1'),
            (0x1000FFE9, 'beq zero,zero,0x4735E8'),
            (0x0060B021, 'addu s6,v1,zero'),
        ])
        # Bounded direct-call scan, NOT proof of a caller-held lock or of the
        # absence of locking inside an arbitrary registered callback.
        links = []
        for pc in range(0x473560, 0x473690, 4):
            word = self.elf.word(pc)
            if word >> 26 == 3 or (word >> 26 == 0 and word & 63 == 9):
                links.append((pc, word))
        self.assertEqual(links, [(0x47358C, 0x0C119A58),
                                 (0x47362C, 0x0320F809)])

    def test_music_activity_orders_init_loop_then_teardown_in_one_invocation(self):
        # This is a serial call chain, not proof that all possible callers
        # execute on one unique thread or that every Files destructor uses it.
        self.instructions(0x4E3DEC, [
            (0x8C990254, 'lw t9,+0x254(a0)'),
            (0x0320F809, 'jalr ra,t9'),
            (0x00808021, 'addu s0,a0,zero'),
            (0x8E19025C, 'lw t9,+0x25c(s0)'),
            (0x0320F809, 'jalr ra,t9'),
            (0x02002021, 'addu a0,s0,zero'),
            (0x8E190258, 'lw t9,+0x258(s0)'),
            (0x0320F809, 'jalr ra,t9'),
            (0x02002021, 'addu a0,s0,zero'),
        ])

    def test_controller_transition_follows_activity_callback_return(self):
        self.instructions(0x43D054, [
            (0x8E44F208, 'lw a0,-0xdf8(s2)'),
            (0x00002821, 'addu a1,zero,zero'),
            (0x00003021, 'addu a2,zero,zero'),
            (0x8C990260, 'lw t9,+0x260(a0)'),
            (0x0320F809, 'jalr ra,t9'),
            (0xAC800134, 'sw zero,+0x134(a0)'),
            (0x1440001B, 'bne v0,zero,0x43D0DC'),
            (0x8EE2F214, 'lw v0,-0xdec(s7)'),
            (0x14400019, 'bne v0,zero,0x43D0DC'),
            (0x8E02F20C, 'lw v0,-0xdf4(s0)'),
            (0xAE00F20C, 'sw zero,-0xdf4(s0)'),
            (0xAEC2F208, 'sw v0,-0xdf8(s6)'),
        ])

    def test_explorer_gesture_callbacks_are_bound_to_distinct_resource_slots(self):
        expected = (0x49B000, 0x49B1A0, 0x49E560, 0x49B460,
                    0, 0x49E7E0, 0, 0)
        self.assertEqual(tuple(self.elf.word(0xA98B74 + i * 4)
                               for i in range(8)), expected)
        # Binder table slot -> resource callback slot. Event meanings require
        # the separately inspected dispatcher; none is a generic active flag.
        for pc, table_slot, resource_slot in (
                (0x43C0B8, 0x4C, 0x164), (0x43C0C4, 0x44, 0x15C),
                (0x43C0D0, 0x48, 0x160), (0x43C0DC, 0x40, 0x158),
                (0x43C0E8, 0x54, 0x16C), (0x43C0F4, 0x50, 0x168)):
            self.instructions(pc, [
                (0x8E050000 | table_slot, f'lw a1,+{table_slot:#x}(s0)'),
                (0x8C4400D0, 'lw a0,+0xd0(v0)'),
                (0xAC850000 | resource_slot, f'sw a1,+{resource_slot:#x}(a0)'),
            ])

    def test_general_list_reset_is_queued_before_timer_in_music_loop(self):
        # General Files-capable reset is event 0x11A in the dispatch table,
        # not a direct jal to 0x452400. This proves the inspected UI route,
        # not absence of other indirect invocations or background mutations.
        self.assertEqual(self.elf.word(0x926C4C), 0x11A)
        self.assertEqual(self.elf.word(0x926C50), 0x452400)
        self.instructions(0x45425C, [
            (0x24846B94, 'addiu a0,a0,27540'),
            (0x8FA6001C, 'lw a2,+0x1c(sp)'),
        ])
        self.instructions(0x45428C, [
            (0x000318C0, 'sll v1,v1,3'),
            (0x00832021, 'addu a0,a0,v1'),
            (0x8C990004, 'lw t9,+0x4(a0)'),
            (0x1320FFE6, 'beq t9,zero,0x454234'),
            (0x02202021, 'addu a0,s1,zero'),
            (0x0320F809, 'jalr ra,t9'),
            (0x27A50018, 'addiu a1,sp,24'),
        ])
        self.instructions(0x43C9A4, [
            (0x0C115080, 'jal 0x454200'),
            (0x02002021, 'addu a0,s0,zero'),
        ])
        self.instructions(0x43C9E4, [
            (0x0C11CD58, 'jal 0x473560'),
            (0x00000000, 'nop'),
        ])
        self.instructions(0x45259C, [
            (0x0C124490, 'jal 0x491240'),
            (0x8E050008, 'lw a1,+0x8(s0)'),
        ])


if __name__ == '__main__':
    unittest.main()
