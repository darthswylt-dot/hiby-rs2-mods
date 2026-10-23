#!/usr/bin/env python3
"""Pinned callback/outer/renderer receipt-association source premises.

These checks establish bounded native frames and exact scalar capture sites,
not C/W/V/P retention, a UI/playback epoch, arbitrary alias safety or coherent
capture. The two new sites must not replace the existing renderer root hook,
reuse its occupied carriers, add a native lookup or infer an ID from pointers.
No device, network, firmware build or source-binary writes.
"""

import hashlib
import struct
import unittest

import test_folderfollow_reveal_static_contract as source
import test_reveal_contents_revision_contract as boundary
from test_reveal_lineage_source_contract import MEMORY_WIDTHS
from test_reveal_native_scope_contract import direct_target


OUTER, OUTER_END = 0x438200, 0x4388B8
RENDERER, RENDERER_END = 0x4906E0, 0x490898
HOOKS = {
    0x438248: (0x00C0A021, 0x00E08821),
    0x49076C: (0xAE113B50, 0x8E4201BC),
}


class RevealRendererTransportContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.elf = source.Elf32(source.SOURCE)
        digest = hashlib.sha256(cls.elf.data).hexdigest()
        if digest != source.SOURCE_SHA256 or len(cls.elf.data) != source.SOURCE_SIZE:
            raise AssertionError(f'unrecognized reference: SHA-256 {digest}, '
                                 f'size {len(cls.elf.data)}')
        cls.direct = []
        for low, high in cls.elf.executable_ranges():
            for pc in range(low, high & ~3, 4):
                target = direct_target(pc, cls.elf.word(pc))
                if target is not None:
                    cls.direct.append((pc, target))

    reachable = boundary.RevealContentsRevisionContractTests.reachable
    dominated = boundary.RevealContentsRevisionContractTests.dominated

    def anchors(self, values):
        for pc, expected in values.items():
            with self.subTest(pc=f'{pc:#x}'):
                self.assertEqual(self.elf.word(pc), expected)

    def test_exact_two_linear_hook_pairs_have_separate_native_resumes(self):
        for pc, pair in HOOKS.items():
            self.anchors({pc: pair[0], pc + 4: pair[1]})
        self.anchors({0x438250: 0x13C0000D, 0x490774: 0xAE123B54})
        self.assertEqual([pc + 8 for pc in HOOKS], [0x438250, 0x490774])

    def test_outer_prologue_preserves_callback_scalars_before_its_local_register_changes(self):
        self.anchors({
            0x438200: 0x27BDFE00, 0x438204: 0xAFBF01FC,
            0x438208: 0xAFBE01F8, 0x438214: 0xAFB501EC,
            0x438218: 0xAFB401E8, 0x43821C: 0xAFB301E4,
            0x438220: 0xAFB201E0, 0x438224: 0xAFB101DC,
            0x43822C: 0xAFB001D8, 0x438238: 0x8C930050,
            0x438240: 0x00A0F021, 0x438244: 0x00808021,
        })
        # Outer saves incoming callback fp/node before fp becomes W at240.
        # Its saved1D8/1DC/1E0/1E4 are callback C/W/input/controller.

    def test_outer_guards_precede_hook_and_hook_dominates_cache_and_child_call(self):
        self.anchors({
            0x438228: 0x10800122, 0x438230: 0x10E00128,
            0x43823C: 0x12600105, 0x438248: 0x00C0A021,
            0x43824C: 0x00E08821,
        })
        self.dominated(OUTER, OUTER_END, 0x438248, 0x438290, 0x438724, 0x438740)
        # This is only domination from the named entry and encoded CFG.

    def test_callback_passes_exact_coordinates_and_original_input_to_outer(self):
        self.anchors({
            0x439EC0: 0x27BDFFC8, 0x439EC4: 0xAFBF0034,
            0x439EE8: 0x8C930050, 0x439F14: 0x00808021,
            0x439F18: 0x00A09021, 0x439F60: 0x00408821,
            0x439F78: 0xAFA40018, 0x439F80: 0xAFA2001C,
            0x439F84: 0x02002021, 0x439F88: 0x02202821,
            0x439F8C: 0x27A60018, 0x439F90: 0x0C10E080,
            0x439F94: 0x02403821,
        })
        self.assertEqual(0x439F90 + 8, 0x439F98)
        self.assertEqual(0x200 + 0x34, 0x234)
        self.assertEqual(0x200 + 0x14, 0x214)
        self.assertEqual(0x200 + 0x18, 0x218)
        # Gate [O+1FC]=439F98, then [O+234]=8B40EC, BEFORE carrierO+214.
        # a2=O+218 and saved C/W/input/controller remain numeric bindings.

    def test_outer_sp14_is_separate_from_fifth_arguments_and_local_buffers(self):
        memory, formed = set(), set()
        for pc in range(OUTER, OUTER_END, 4):
            word = self.elf.word(pc)
            op, rs, rt = word >> 26, (word >> 21) & 31, (word >> 16) & 31
            if rs == 29 and op in MEMORY_WIDTHS:
                offset = word & 0xFFFF
                offset -= 0x10000 if offset & 0x8000 else 0
                memory.add(offset)
                self.assertFalse(offset < 0x18 and 0x14 < offset + MEMORY_WIDTHS[op])
            if op == 9 and rs == 29 and rt != 29:
                formed.add(word & 0xFFFF)
        self.assertNotIn(0x14, memory | formed)
        self.assertEqual(formed, {0x20, 0x140, 0x180, 0x190, 0x1A0, 0x1B0})
        self.assertEqual([pc for pc in range(OUTER, OUTER_END, 4)
                          if self.elf.word(pc) >> 26 == 0x2B
                          and (self.elf.word(pc) >> 21) & 31 == 29
                          and self.elf.word(pc) & 0xFFFF == 0x10],
                         [0x438438, 0x438464, 0x4384D4])
        # This local direct-use premise assumes valid actual callees/buffers;
        # do not use the upper1B4 word beside sprintf's local buffer instead.

    def test_child_call_uses_fresh_cache_descriptor_with_original_w_and_c(self):
        self.anchors({
            0x438720: 0x27A701B0, 0x438724: 0x0C11EA48,
            0x43872C: 0x8FD90148, 0x438730: 0x1320005C,
            0x438738: 0x8FA601B0, 0x43873C: 0x03C02021,
            0x438740: 0x0320F809, 0x438744: 0x02002821,
        })
        self.assertEqual(0x438740 + 8, 0x438748)
        self.assertEqual(0x30 + 0x1B0, 0x1E0)
        # Cache descriptor is a numeric current-call binding, not the queue
        # cause. No extra lookup or descriptor-tail read is justified here.

    def test_renderer_preserves_original_input_scalars_in_s_registers_and_saved_outer_slots(self):
        self.anchors({
            0x4906F8: 0x27BDFFD0, 0x4906FC: 0xAFBF002C,
            0x490700: 0xAFB30024, 0x490704: 0xAFB1001C,
            0x490708: 0xAFB00018, 0x49070C: 0xAFB40028,
            0x490710: 0xAFB20020, 0x490714: 0x00808021,
            0x49071C: 0x00A09821, 0x490728: 0x00C08821,
        })
        fp_writes = []
        for pc in range(RENDERER, RENDERER_END, 4):
            word, op = self.elf.word(pc), self.elf.word(pc) >> 26
            if ((op == 0 and (word >> 11) & 31 == 30)
                    or (op not in (0, 2, 3) and (word >> 16) & 31 == 30)):
                fp_writes.append(pc)
        self.assertEqual(fp_writes, [])
        # Subject to actual callee ABI, fp stays W; s3=C and s1=cache.
        # SavedR18/R1C/R24/R28 are C/input/controller/coordinates.

    def test_native_panel_and_view_resolution_needs_no_new_pointer_reread(self):
        self.anchors({
            0x49072C: 0x8E0400FC, 0x490730: 0x8C99002C,
            0x490734: 0x0320F809, 0x490738: 0x2445FFFF,
            0x49073C: 0x10400052, 0x490744: 0x8C520000,
            0x490748: 0x12400033, 0x490750: 0x0C1164D0,
            0x490754: 0x02402021, 0x459340: 0x10800003,
            0x459348: 0x03E00008, 0x45934C: 0x8C82007C,
            0x459350: 0x03E00008, 0x459354: 0x00001021,
        })
        # P=s2 is the native selected item; V is native459340(P)'s rawP+7C
        # result, moved into s0 by old render pair. No retention follows.

    def test_existing_render_hook_and_original_call_complete_before_new_association(self):
        self.anchors({
            0x490758: 0x00408021, 0x49075C: 0x244438AC,
            0x490760: 0x02202821, 0x490764: 0x0C296FB8,
            0x490768: 0x8C5400DC, 0x49076C: 0xAE113B50,
            0x490770: 0x8E4201BC,
        })
        self.dominated(RENDERER, RENDERER_END, 0x490758, 0x490764, 0x49076C)
        self.dominated(RENDERER, RENDERER_END, 0x49076C, 0x49080C, 0x490878)
        self.assertEqual(0x490764 + 8, 0x49076C)
        # At new hook s0=V, s2=P, s3=C, s1=cache, fp=W. s4 is V+DC's
        # loaded value, NOT coordinates: only savedR28 supplies coordinates.
        # Preserve actual opaque-call v0 before replaying native LW770 once.

    def test_renderer_own_slots10_and14_remain_occupied_by_existing_diagnostics(self):
        import build_reveal_lineage_stage as lineage_stage
        import build_reveal_origin_frontier_stage as frontier_stage

        self.assertEqual(lineage_stage.RENDER_TICKET, 0x14)
        self.assertEqual(frontier_stage.ENTRY_OFFSET, 0x10)
        self.assertEqual(lineage_stage.HOOKS['render'],
                         (0x490758, (0x00408021, 0x244438AC)))
        uses = [(pc, self.elf.word(pc) & 0xFFFF)
                for pc in range(RENDERER, RENDERER_END, 4)
                if self.elf.word(pc) >> 26 in MEMORY_WIDTHS
                and (self.elf.word(pc) >> 21) & 31 == 29]
        self.assertEqual({offset for _, offset in uses}, {0x18, 0x1C, 0x20, 0x24, 0x28, 0x2C})
        # Source-local absence does not free slots already used by preceding
        # stages. New association reads exact rootID R14, never replaces it.

    def test_ordered_renderer_ancestor_offsets_and_root_bindings_are_exact(self):
        renderer_to_outer, outer_to_callback = 0x30, 0x200
        self.assertEqual(renderer_to_outer + 0x1FC, 0x22C)
        self.assertEqual(renderer_to_outer + outer_to_callback + 0x34, 0x264)
        self.assertEqual(renderer_to_outer + 0x14, 0x44)
        self.assertEqual(renderer_to_outer + outer_to_callback + 0x14, 0x244)
        self.assertEqual(renderer_to_outer + 0x1F8, 0x228)
        self.assertEqual(renderer_to_outer + 0x1B0, 0x1E0)
        # Ordered gates R2C=438748 -> R22C=439F98 -> R264=8B40EC precede
        # reading carrierR44. Private OUTER must bind frameR+30 and the exact
        # saved C/W/input/coordinates/controller; validate exact LNRG.RENDER
        # ID R14 with STACK=R, VIEW=s0, PANEL=s2, JOB=s0+38A4, SITE=490758.
        # R228 is saved incoming callback fp/node, NOT a saved W value.

    def test_global_direct_targets_do_not_enter_either_new_pair(self):
        for first in HOOKS:
            for target in (first, first + 4):
                with self.subTest(target=f'{target:#x}'):
                    self.assertEqual([pc for pc, dest in self.direct if dest == target], [])
        self.assertEqual([(pc, target) for pc, target in self.direct
                          if OUTER <= target < OUTER_END and not OUTER <= pc < OUTER_END],
                         [(0x439F90, OUTER)])
        # Census includes likely/REGIMM/COP branches but excludes unknown
        # computed entries, exceptions, unwind, alias writes and callee ABI.

    def test_new_hook_words_have_no_aligned_file_backed_pointer_literal(self):
        values = {value[0] for value in struct.iter_unpack(
            '<I', self.elf.data[:len(self.elf.data) // 4 * 4])}
        for first in HOOKS:
            for address in (first, first + 4):
                with self.subTest(address=f'{address:#x}'):
                    self.assertNotIn(address, values)


if __name__ == '__main__':
    unittest.main()
