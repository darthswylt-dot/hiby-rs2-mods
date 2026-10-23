#!/usr/bin/env python3
"""Pinned premises for the explicit widened generic-node transport stage.

The original node is 16 bytes. A separate opt-in builder may widen its sole
allocation to 20 for every direct caller, then initialize the new word before
publication. These source checks are not evidence that an arbitrary native
pointer is a widened node, nor lifetime/alias coverage or deployment approval.
No device, network, firmware build or source-binary writes.
"""

import hashlib
import struct
import unittest

import test_folderfollow_reveal_static_contract as source
from test_reveal_lineage_source_contract import MEMORY_WIDTHS
from test_reveal_native_scope_contract import direct_target


APPEND = 0x8B3CC0
APPEND_END = 0x8B3D68
APPEND_CALLS = (0x8B083C, 0x8B0E30, 0x8B0EA4,
                0x8B0FB4, 0x8B1060, 0x8B42E8)
HOOK_PAIRS = {
    0x8B3CE8: (0x10400010, 0x8FBF0024),
    0x8B4754: (0x8FC50000, 0x8FC60004),
    0x8B3FA0: (0x27BDFF48, 0xAFB600B0),
    0x439EC0: (0x27BDFFC8, 0xAFBF0034),
}


class RevealQueueTransportContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.elf = source.Elf32(source.SOURCE)
        digest = hashlib.sha256(cls.elf.data).hexdigest()
        if digest != source.SOURCE_SHA256 or len(cls.elf.data) != source.SOURCE_SIZE:
            raise AssertionError(f'unrecognized reference: SHA-256 {digest}, '
                                 f'size {len(cls.elf.data)}')
        cls.direct, cls.calls = [], {}
        for low, high in cls.elf.executable_ranges():
            for pc in range(low, high & ~3, 4):
                word = cls.elf.word(pc)
                target = direct_target(pc, word)
                if target is not None:
                    cls.direct.append((pc, target))
                if word >> 26 == 3:
                    cls.calls.setdefault(target, []).append(pc)

    def anchors(self, values):
        for pc, expected in values.items():
            with self.subTest(pc=f'{pc:#x}'):
                self.assertEqual(self.elf.word(pc), expected)

    def stack_inventory(self, low, high):
        memory, addresses = set(), set()
        for pc in range(low, high, 4):
            word = self.elf.word(pc)
            op, rs, rt = word >> 26, (word >> 21) & 31, (word >> 16) & 31
            if rs == 29 and op in MEMORY_WIDTHS:
                offset = word & 0xFFFF
                offset -= 0x10000 if offset & 0x8000 else 0
                with self.subTest(pc=f'{pc:#x}'):
                    self.assertFalse(offset < 0x18 and 0x14 < offset + MEMORY_WIDTHS[op])
                memory.add(offset)
            if op == 9 and rs == 29 and rt != 29:
                addresses.add(word & 0xFFFF)
        self.assertNotIn(0x14, addresses)
        return memory, addresses

    def test_single_generic_allocation_covers_all_six_encoded_direct_callers(self):
        self.assertEqual(self.calls[APPEND], list(APPEND_CALLS))
        self.anchors({
            0x8B3CCC: 0x24040010, 0x8B3CE0: 0x0C22C340,
            0x8B3CE4: 0x00C08821,
        })
        allocations = [pc for pc in self.calls[0x8B0D00]
                       if APPEND <= pc < APPEND_END]
        self.assertEqual(allocations, [0x8B3CE0])
        # One opt-in instruction change 24040010 -> 24040014 therefore widens
        # this helper's allocation for all six classified direct callers,
        # not just the paint queue. Indirect aliases remain unclassified.

    def test_rectangle_copy_allocation_stays_distinct_from_the_widened_node(self):
        self.anchors({
            0x8B42A8: 0x24040010, 0x8B42B0: 0x0C22C340,
            0x8B42B8: 0x00408821, 0x8B42D4: 0x26040034,
            0x8B42E8: 0x0C22CF30, 0x8B42EC: 0xAE22000C,
        })
        self.assertEqual(0x8B42E8 + 8, 0x8B42F0)
        # The new word is node+10, never rectangle+10. The four-word payload
        # and append's final copy store in its original delay remain native.

    def test_postallocation_pair_restores_original_ra_on_both_branches(self):
        self.anchors({
            0x8B3CE8: 0x10400010, 0x8B3CEC: 0x8FBF0024,
            0x8B3CF0: 0x8E070000, 0x8B3D2C: 0x8FB20020,
        })
        self.assertEqual(direct_target(0x8B3CE8, self.elf.word(0x8B3CE8)),
                         0x8B3D2C)
        self.anchors({
            0x8B3CC0: 0x27BDFFD8, 0x8B3CC8: 0x00808021,
            0x8B3CD8: 0xAFBF0024, 0x8B3CDC: 0x00A09021,
            0x8B3D38: 0x03E00008, 0x8B3D3C: 0x27BD0028,
            0x8B3D60: 0x03E00008, 0x8B3D64: 0x27BD0028,
        })
        # Relocation must execute LW RA even when v0==0, branch to3D2C,
        # and never access v0+10 on that failure path. Nonnull resumes3CF0.

    def test_postallocation_precedes_every_native_node_publication(self):
        self.anchors({
            0x8B3CF4: 0x14E00004, 0x8B3CFC: 0x10000010,
            0x8B3D00: 0xAC520000, 0x8B3D14: 0xAC520000,
            0x8B3D18: 0xAC470008, 0x8B3D1C: 0xAC40000C,
            0x8B3D20: 0xAC510004, 0x8B3D24: 0xACE2000C,
            0x8B3D40: 0xAC400008, 0x8B3D44: 0xAC40000C,
            0x8B3D48: 0xAC510004, 0x8B3D4C: 0xAE020000,
        })
        stores = [(pc, (self.elf.word(pc) >> 21) & 31,
                   self.elf.word(pc) & 0xFFFF)
                  for pc in range(APPEND, APPEND_END, 4)
                  if self.elf.word(pc) >> 26 == 0x2B
                  and (self.elf.word(pc) >> 21) & 31 != 29]
        self.assertEqual(stores, [
            (0x8B3D00, 2, 0), (0x8B3D14, 2, 0),
            (0x8B3D18, 2, 8), (0x8B3D1C, 2, 12),
            (0x8B3D20, 2, 4), (0x8B3D24, 7, 12),
            (0x8B3D40, 2, 8), (0x8B3D44, 2, 12),
            (0x8B3D48, 2, 4), (0x8B3D4C, 16, 0),
        ])
        # Stock writes only the 16-byte prefix. The added zero/ID store must
        # happen before the two publication stores3D24/3D4C, never afterward.

    def test_install_parent_frame_geometry_is_exact_but_not_a_pointer_registry(self):
        self.assertEqual(0x28 + 0x14, 0x3C)
        self.anchors({
            0x8B3CC4: 0xAFB00018, 0x8B3CD0: 0xAFB20020,
            0x8B3CD4: 0xAFB1001C, 0x8B3CDC: 0x00A09021,
            0x8B3CE4: 0x00C08821, 0x8B42D4: 0x26040034,
            0x8B42E4: 0x02202821,
        })
        # After displaced LW RA, require original RA42F0 before reading the
        # producer carrier at genericSP+3C. Private ENQUEUE ancestry must bind
        # producerSP=genericSP+28, C/list, payload s2 and metadata s1. A raw
        # matching node or C address cannot supply that ancestry.

    def test_queue_loop_hook_preserves_original_call_return_pc_and_delay(self):
        self.anchors({
            0x8B4748: 0x8EBE0034, 0x8B474C: 0x13C00009,
            0x8B4754: 0x8FC50000, 0x8B4758: 0x8FC60004,
            0x8B475C: 0x0C22CFE8, 0x8B4760: 0x02A02021,
            0x8B4764: 0x8FDE000C, 0x8B4768: 0x17C0FFFA,
        })
        self.assertEqual(0x8B475C + 8, 0x8B4764)

    def test_full_route_can_reenter_same_queue_loop_without_acquiring_full_identity(self):
        self.anchors({
            0x8B4990: 0x0320F809, 0x8B4994: 0xAFA20020,
            0x8B49B8: 0x8EBE0034, 0x8B49BC: 0x17C0FF65,
            0x8B49C0: 0x00002021,
        })
        self.assertEqual(direct_target(0x8B49BC, self.elf.word(0x8B49BC)),
                         0x8B4754)
        # Callback RA4998 is unknown. A later real queued iteration may carry
        # its own receipt; it does not make the earlier full callback known.

    def test_parent_loop_sp14_is_locally_unused_through_all_three_helper_calls(self):
        memory, addresses = self.stack_inventory(0x8B4660, 0x8B4BC8)
        self.assertEqual(memory, {
            0x18, 0x1C, 0x20, 0x24, 0x28, 0x58, 0x5C, 0x60, 0x64,
            0x68, 0x70, 0x78, 0x7C, 0x80, 0x84, 0x88, 0x8C, 0x90,
            0x94, 0x98, 0x9C, 0xA0, 0xA4, 0xA8, 0xAC, 0xB0,
            0xB4, 0xB8, 0xBC,
        })
        self.assertEqual(addresses, {0x18, 0x1C, 0x58, 0x78})
        self.anchors({0x8B4660: 0x27BDFF40, 0x8B48CC: 0x27BD00C0})

    def test_helper_frame_carrier_and_three_distinct_callsite_domains(self):
        self.assertEqual(self.calls[0x8B3FA0], [0x8B475C, 0x8B4A14, 0x8B4AF8])
        self.anchors({
            0x8B3FA0: 0x27BDFF48, 0x8B3FA4: 0xAFB600B0,
            0x8B3FB0: 0xAFBF00B4, 0x8B3FC8: 0x0080B021,
            0x8B3FCC: 0x00C0A821, 0x8B3FDC: 0x00A09821,
            0x8B4A10: 0x26050014, 0x8B4A18: 0x00003021,
            0x8B4AEC: 0x001E2900, 0x8B4AF4: 0x00E52821,
            0x8B4AFC: 0x00003021,
        })
        memory, addresses = self.stack_inventory(0x8B3FA0, 0x8B4120)
        self.assertEqual(memory, {
            0x58, 0x5C, 0x60, 0x64, 0x68, 0x74, 0x78, 0x7C, 0x80,
            0x84, 0x88, 0x8C, 0x90, 0x98, 0x9C, 0xA0, 0xA4,
            0xA8, 0xAC, 0xB0, 0xB4,
        })
        self.assertEqual(addresses, {0x18, 0x1C, 0x58, 0x74, 0x84})
        self.assertEqual(0xB8 + 0x14, 0xCC)
        # Entry must zero its carrier before the RA4764 gate, then validate
        # the BORROW's exact parent SP/C/fp/payload/metadata. Other callers
        # have legitimate nonqueued rectangles and must not read any tail.

    def test_native_a3_is_forwarded_to_a_helper_before_its_explicit_local_load(self):
        self.anchors({
            0x8B3FD0: 0x00A02021, 0x8B3FD4: 0x26460014,
            0x8B3FD8: 0x0C22CC88, 0x8B3FDC: 0x00A09821,
            0x8B4014: 0x8E470020,
        })
        # Absence of an earlier local a3 load is NOT permission to change
        # incoming a3 into a hidden argument: the first native call sees it.

    def test_split_callbacks_keep_original_metadata_and_native_frame(self):
        self.anchors({
            0x8B4048: 0x00008821, 0x8B4090: 0x02C02021,
            0x8B4094: 0x27A50058, 0x8B4098: 0x26310001,
            0x8B40CC: 0x27A20074, 0x8B40D0: 0x8ED90048,
            0x8B40D4: 0xAFA2005C, 0x8B40D8: 0xAFA60058,
            0x8B40DC: 0xAFA00064, 0x8B40E0: 0xAFA00060,
            0x8B40E4: 0x0320F809, 0x8B40E8: 0xAFB50068,
            0x8B40EC: 0x1634FFD7, 0x8B40F0: 0x26100010,
        })
        self.assertEqual(0x8B40E4 + 8, 0x8B40EC)
        self.assertEqual(direct_target(0x8B40EC, self.elf.word(0x8B40EC)),
                         0x8B404C)
        # A single queued cause can produce multiple callback invocations.
        # The helper receipt persists in its own slot14; callback receipts
        # remain distinct, without rewriting the native metadata atSP68.

    def test_callback_entry_and_bounded_helper_ancestor_offsets(self):
        self.anchors({
            0x439EC0: 0x27BDFFC8, 0x439EC4: 0xAFBF0034,
            0x439EC8: 0xAFB30030, 0x439ECC: 0xAFB2002C,
            0x439ED0: 0xAFB10028, 0x439ED8: 0xAFB00024,
            0x439F14: 0x00808021, 0x439F18: 0x00A09021,
        })
        memory, addresses = self.stack_inventory(0x439EC0, 0x43A044)
        self.assertEqual(memory, {0x18, 0x1C, 0x24, 0x28, 0x2C, 0x30, 0x34})
        self.assertEqual(addresses, {0x18})
        self.assertEqual(0x38 + 0x58, 0x90)   # Original descriptor a1.
        self.assertEqual(0x38 + 0xB4, 0xEC)   # Helper's saved original RA.
        self.assertEqual(0x38 + 0x14, 0x4C)   # Helper receipt carrier.
        self.assertEqual(0x38 + 0xB8, 0xF0)   # Parent queue-loop SP.
        # First gate original RA40EC plus a0==incoming s6/a1==B+90.
        # Then require saved helper RA4764 before consuming its carrierB+4C,
        # and validate private HELPER bound to Q=B+38/C/fp/s3/s5. No native
        # node+10 or rectangle-tail read is necessary at this callback.

    def test_generic_delete_and_payload_cleanup_use_prefix_and_pointer_only_free(self):
        self.anchors({
            0x8B3F18: 0x3C05008B, 0x8B3F1C: 0x24A53100,
            0x8B3F20: 0x0822CF80, 0x8B3F24: 0x24070001,
            0x8B3E3C: 0x8E02000C, 0x8B3E54: 0x8E050000,
            0x8B3E60: 0x8E060004, 0x8B3E70: 0x8E110008,
            0x8B3E7C: 0xAE20000C, 0x8B3E80: 0x0C22C348,
            0x8B3E84: 0x02002021, 0x8B3110: 0x0C22C348,
            0x8B3114: 0x00A02021,
        })
        uses = [(pc, self.elf.word(pc) & 0xFFFF)
                for pc in range(0x8B3E00, 0x8B3EB4, 4)
                if self.elf.word(pc) >> 26 in MEMORY_WIDTHS
                and (self.elf.word(pc) >> 21) & 31 in (16, 17)]
        self.assertEqual(uses, [(0x8B3E3C, 12), (0x8B3E54, 0),
                                (0x8B3E60, 4), (0x8B3E70, 8), (0x8B3E7C, 12)])
        # The free call receives pointer a0, not a node-size argument. This
        # does not promise identical allocation success or memory pressure.

    def test_paint_queue_type_premise_begins_empty_and_clears_after_native_cleanup(self):
        self.anchors({
            0x8B4138: 0x24040054, 0x8B4148: 0x00002821,
            0x8B414C: 0x0C296F18, 0x8B4150: 0x24060054,
            0x8B42D4: 0x26040034, 0x8B42E8: 0x0C22CF30,
            0x8B4770: 0x8EA40034, 0x8B4774: 0x0C22CFC0,
            0x8B4778: 0x24050001, 0x8B4788: 0xAEA00034,
            0x8B4BB0: 0x8EA40034, 0x8B4BB4: 0x0C22CFC0,
            0x8B4BB8: 0x24050001, 0x8B4BBC: 0xAEA00034,
        })
        # This classified producer/consumer path supports a conditional type
        # premise, not proof against every alias writer, foreign/preexisting
        # node, native corruption, concurrent free or runtime function edit.

    def test_hook_pair_census_includes_known_first_word_loop_and_entry_targets(self):
        expected = {
            0x8B3CE8: [], 0x8B3CEC: [],
            0x8B4754: [0x8B4768, 0x8B49BC], 0x8B4758: [],
            0x8B3FA0: [0x8B475C, 0x8B4A14, 0x8B4AF8], 0x8B3FA4: [],
            0x439EC0: [], 0x439EC4: [],
        }
        for first, pair in HOOK_PAIRS.items():
            self.anchors({first: pair[0], first + 4: pair[1]})
        for target, sites in expected.items():
            with self.subTest(target=f'{target:#x}'):
                self.assertEqual([pc for pc, dest in self.direct if dest == target], sites)
        for target in (0x8B475C, 0x8B4760, 0x8B40D0, 0x8B40D4):
            self.assertEqual([pc for pc, dest in self.direct if dest == target], [])

    def test_hook_pairs_have_no_aligned_file_backed_pointer_literal(self):
        values = {value[0] for value in struct.iter_unpack(
            '<I', self.elf.data[:len(self.elf.data) // 4 * 4])}
        for first in HOOK_PAIRS:
            for address in (first, first + 4):
                with self.subTest(address=f'{address:#x}'):
                    self.assertNotIn(address, values)
        # This and the encoded control-flow census do not exclude computed
        # entries, aliases, exceptions or unclassified indirect callers.


if __name__ == '__main__':
    unittest.main()
