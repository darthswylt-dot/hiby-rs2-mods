#!/usr/bin/env python3
"""Pinned callback/outer-render premises for future request-ID transport.

This source-only contract implements no carrier or callback interception. A
per-invocation value frozen here would precede the cache-canvas allocation,
but a newly invoked old C still has no immutable original UI cause/epoch.
Only a separately justified, already-frozen upstream ID could be transported.
Numeric RA/frame/C/W matches are not pointer lifetime, retention or authority.
No device, network, firmware builder or source-binary writes.
"""

import hashlib
import unittest

import test_folderfollow_reveal_static_contract as source
import test_reveal_contents_revision_contract as boundary
from test_reveal_native_scope_contract import direct_target
from test_reveal_lineage_source_contract import MEMORY_WIDTHS


CALLBACK, CALLBACK_END, CALLBACK_FRAME = 0x439EC0, 0x43A044, 0x38
OUTER, OUTER_END, OUTER_FRAME = 0x438200, 0x4388B8, 0x200
CARRIER = 0x14


class RevealRequestCallbackContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.elf = source.Elf32(source.SOURCE)
        digest = hashlib.sha256(cls.elf.data).hexdigest()
        if digest != source.SOURCE_SHA256 or len(cls.elf.data) != source.SOURCE_SIZE:
            raise AssertionError(f'unrecognized reference: SHA-256 {digest}, '
                                 f'size {len(cls.elf.data)}')
        cls.direct, cls.callback_constructors = [], []
        for low, high in cls.elf.executable_ranges():
            for pc in range(low, high & ~3, 4):
                word = cls.elf.word(pc)
                target = direct_target(pc, word)
                if target is not None:
                    cls.direct.append((pc, target))
                # Exact bounded LUI/addiu construction census, not a general
                # proof that no computed function pointer can name callback.
                if word >> 26 == 15 and word & 0xFFFF == 0x44:
                    register = (word >> 16) & 31
                    for distance in range(1, 5):
                        other = cls.elf.word(pc + 4 * distance)
                        if (other >> 26 == 9 and (other >> 21) & 31 == register
                                and other & 0xFFFF == 0x9EC0):
                            cls.callback_constructors.append((pc, pc + 4 * distance))

    instructions = boundary.RevealContentsRevisionContractTests.instructions
    reachable = boundary.RevealContentsRevisionContractTests.reachable
    dominated = boundary.RevealContentsRevisionContractTests.dominated

    def words(self, low, high):
        return [(pc, self.elf.word(pc)) for pc in range(low, high, 4)]

    def stack_inventory(self, low, high):
        memory, addresses, adjustments = set(), set(), []
        for pc, word in self.words(low, high):
            op, rs, rt = word >> 26, (word >> 21) & 31, (word >> 16) & 31
            with self.subTest(pc=f'{pc:#x}'):
                if rs == 29:
                    if op in MEMORY_WIDTHS:
                        self.assertIn(op, (0x23, 0x2B))
                        offset, width = word & 0xFFFF, MEMORY_WIDTHS[op]
                        self.assertTrue(offset >= CARRIER + 4 or offset + width <= CARRIER)
                        memory.add(offset)
                    else:
                        self.assertEqual(op, 9)
                        if rt == 29:
                            adjustments.append((pc, word & 0xFFFF))
                        else:
                            addresses.add(word & 0xFFFF)
                if op == 0:
                    self.assertNotEqual(rt, 29)
                    self.assertNotEqual((word >> 11) & 31, 29)
                elif op not in (2, 3) and rt == 29:
                    self.assertEqual((op, rs), (9, 29))
        return memory, addresses, adjustments

    def test_callback_prologue_guards_and_two_normal_return_pairs(self):
        self.instructions(CALLBACK,
                          'addiu sp,sp,-56', 'sw ra,+0x34(sp)',
                          'sw s3,+0x30(sp)', 'sw s2,+0x2c(sp)',
                          'sw s1,+0x28(sp)', 'beq a0,zero,0x439FEC',
                          'sw s0,+0x24(sp)', 'beq a1,zero,0x439FBC')
        self.instructions(0x439EE4,
                          'lw v0,+0xf94(v0)', 'lw s3,+0x50(a0)',
                          'bne v0,zero,0x439F14', 'addu s1,zero,zero')
        self.assertEqual([(pc, word) for pc, word in self.words(CALLBACK, CALLBACK_END)
                          if word >> 26 == 0 and word & 63 == 8],
                         [(0x439F0C, 0x03E00008), (0x439FB4, 0x03E00008)])
        for pc in (0x439F0C, 0x439FB4):
            self.instructions(pc, 'jr ra', 'addiu sp,sp,56')
        reached = self.reachable(CALLBACK, CALLBACK, CALLBACK_END)
        self.assertTrue({0x439F0C, 0x439FB4}.issubset(reached))
        # Callback entry must replay the native frame allocation before a
        # private wrapper can name nativeSP+14. It need not read C to carry ID.

    def test_global_direct_census_includes_cop_and_likely_branch_encodings(self):
        # Exercise the shared census helper's COP condition (rs=8), ordinary,
        # likely and REGIMM target calculations, not only its J/JAL arm.
        for op in (1, 4, 5, 6, 7, 0x14, 0x15, 0x16, 0x17):
            self.assertEqual(direct_target(0x1000, op << 26 | 2), 0x100C)
        for op in (16, 17, 18, 19):
            self.assertEqual(direct_target(0x1000, op << 26 | 8 << 21 | 2), 0x100C)
        for low, high, expected in (
                (CALLBACK, CALLBACK_END, []),
                (OUTER, OUTER_END, [(0x439F90, OUTER)])):
            inbound = [(pc, target) for pc, target in self.direct
                       if low <= target < high and not low <= pc < high]
            self.assertEqual(inbound, expected)
        # No direct target enters either word of a candidate linear pair or
        # return pair. This does not rule out computed/indirect entries.
        pairs = (CALLBACK, OUTER, 0x438248, 0x439F0C, 0x439FB4,
                 0x438330, 0x438694)
        for target in sorted({pc + delta for pc in pairs for delta in (0, 4)}):
            expected = [0x439F90] if target == OUTER else []
            self.assertEqual([pc for pc, dest in self.direct if dest == target], expected)

    def test_callback_sp14_is_not_directly_used_or_locally_exported(self):
        memory, addresses, adjustments = self.stack_inventory(CALLBACK, CALLBACK_END)
        self.assertEqual(memory, {0x18, 0x1C, 0x24, 0x28, 0x2C, 0x30, 0x34})
        self.assertEqual(addresses, {0x18})
        self.assertEqual(adjustments, [(CALLBACK, 0xFFC8),
                                      (0x439F10, 0x38), (0x439FB8, 0x38)])
        self.assertEqual([pc for pc, word in self.words(CALLBACK, CALLBACK_END)
                          if word >> 26 == 3 or (word >> 26 == 0 and word & 63 == 9)],
                         [0x439F34, 0x439F48, 0x439F5C, 0x439F90,
                          0x439FDC, 0x439FFC, 0x43A018, 0x43A034])
        # Observed calls have <=4 register arguments; no fifth/sixth stack
        # argument is written. Valid O32 actual-callee behavior is a separate
        # premise, not proved by this absence of a native SP+14 access.

    def test_outer_frame_guards_and_linear_capture_pair_precede_geometry(self):
        self.instructions(OUTER, 'addiu sp,sp,-512', 'sw ra,+0x1fc(sp)')
        self.instructions(0x438228,
                          'beq a0,zero,0x4386B4', 'sw s0,+0x1d8(sp)',
                          'beq a3,zero,0x4386D4', 'nop',
                          'lw s3,+0x50(a0)', 'beq s3,zero,0x438654',
                          'addu fp,a1,zero', 'addu s0,a0,zero',
                          'addu s4,a2,zero', 'addu s1,a3,zero')
        self.dominated(OUTER, OUTER_END, 0x438248,
                       0x438290, 0x43843C, 0x438724, 0x438740)
        self.assertEqual([(pc, word) for pc, word in self.words(OUTER, OUTER_END)
                          if word >> 26 == 0 and word & 63 == 8],
                         [(0x438330, 0x03E00008), (0x438694, 0x03E00008)])
        for pc in (0x438330, 0x438694):
            self.instructions(pc, 'jr ra', 'addiu sp,sp,512')
        # W/a1 itself has no early NULL guard. The admitted W+148 branch
        # depends on a live native target, not merely on reaching this pair.

    def test_outer_sp14_is_separate_from_actual_fifth_arguments_and_local_buffers(self):
        memory, addresses, adjustments = self.stack_inventory(OUTER, OUTER_END)
        self.assertEqual(memory, {
            0x10, 0x20, 0x24, 0x28, 0x2C, 0x140, 0x144, 0x148, 0x14C,
            0x150, 0x154, 0x158, 0x15C, 0x160, 0x180, 0x184, 0x188,
            0x18C, 0x190, 0x194, 0x198, 0x19C, 0x1B0, 0x1B8, 0x1BC,
            0x1C0, 0x1C4, 0x1C8, 0x1CC, 0x1D0, 0x1D4, 0x1D8, 0x1DC,
            0x1E0, 0x1E4, 0x1E8, 0x1EC, 0x1F0, 0x1F4, 0x1F8, 0x1FC,
        })
        self.assertEqual(addresses, {0x20, 0x140, 0x180, 0x190, 0x1A0, 0x1B0})
        self.assertEqual(adjustments, [(OUTER, 0xFE00),
                                      (0x438334, 0x200), (0x438698, 0x200)])
        self.assertEqual([pc for pc, word in self.words(OUTER, OUTER_END)
                          if word >> 26 == 0x2B and (word >> 21) & 31 == 29
                          and word & 0xFFFF == 0x10],
                         [0x438438, 0x438464, 0x4384D4])
        # Sprintf("canvas_%s", name) begins at SP+140. Avoid claiming the
        # upper apparently-unused SP+1B4 word is safe for arbitrary names.
        # The low slot14 remains conditional on bounded buffer/O32 premises.

    def test_engine_callbacks_receive_persistent_c_and_stack_built_rect_pair(self):
        self.instructions(0x8B40CC,
                          'addiu v0,sp,116', 'lw t9,+0x48(s6)',
                          'sw v0,+0x5c(sp)', 'sw a2,+0x58(sp)',
                          'sw zero,+0x64(sp)', 'sw zero,+0x60(sp)',
                          'jalr ra,t9', 'sw s5,+0x68(sp)')
        self.instructions(0x8B4090,
                          'addu a0,s6,zero', 'addiu a1,sp,88')
        self.instructions(0x8B4958, 'lw t9,+0x48(s5)')
        self.instructions(0x8B496C,
                          'addu a1,v1,zero', 'addu a0,s5,zero',
                          'sw v1,+0x88(sp)', 'sw zero,+0x58(sp)',
                          'sw zero,+0x5c(sp)', 'sw s4,+0x1c(sp)',
                          'sw s2,+0x18(sp)', 'sw zero,+0x24(sp)',
                          'sw zero,+0x28(sp)', 'jalr ra,t9', 'sw v0,+0x20(sp)')
        self.assertEqual([0x8B40E4 + 8, 0x8B4990 + 8], [0x8B40EC, 0x8B4998])
        self.instructions(0x8B4134, 'jal 0x8B0D00', 'addiu a0,zero,84')
        # These a1 values point into each engine invocation's stack. They
        # are not a stable queued immutable original request object.

    def test_both_bounded_constructor_bindings_install_the_same_c48_callback(self):
        self.assertEqual(self.callback_constructors,
                         [(0x43AE50, 0x43AE54), (0x43AFF0, 0x43AFF4)])
        self.instructions(0x43AE50,
                          'lui v0,0x44', 'addiu v0,v0,-24896',
                          'sw v0,+0x44(sp)')
        self.instructions(0x43AFF0,
                          'lui v0,0x44', 'addiu v0,v0,-24896',
                          'sw v0,+0x44(sp)')
        self.instructions(0x43AE64, 'jal 0x8B4120', 'sw v0,+0x48(sp)')
        self.instructions(0x43B00C, 'jal 0x8B4120', 'sw v0,+0x48(sp)')
        self.instructions(0x8B418C, 'lw v0,+0x2c(s1)', 'sw v0,+0x48(s0)')
        self.assertEqual(0x18 + 0x2C, 0x44)
        # Split immediate constructions are the bounded inventory here, not
        # proof that all possible runtime callback replacements are covered.

    def test_callback_uses_current_c_name_and_controller_resource_lookup(self):
        self.instructions(0x439F14,
                          'addu s0,a0,zero', 'addu s2,a1,zero',
                          'lw a0,+0x24(s3)', 'lw a1,+0x0(s0)',
                          'lui s1,0x92', 'addiu v0,zero,-1',
                          'addiu a2,s1,2228', 'sw v0,+0x18(sp)',
                          'jal 0x485DE0', 'sw zero,+0x1c(sp)')
        self.instructions(0x439F3C,
                          'beq v0,zero,0x43A00C', 'lui a0,0x92',
                          'addu a0,v0,zero', 'jal 0x439E20',
                          'addiu a1,v0,32', 'lw a0,+0x24(s3)',
                          'lw a1,+0x0(s0)', 'addiu a2,s1,2228',
                          'jal 0x485420', 'addu s1,v0,zero')
        self.instructions(0x485FC0,
                          'addu a1,s2,zero', 'jal 0x485420',
                          'addiu a2,s1,2228', 'beq v0,zero,0x4861F4',
                          'nop', 'beq zero,zero,0x486008', 'lw v0,+0xd0(v0)')
        offset = self.elf.va_to_off(0x9208B4)
        self.assertEqual(self.elf.data[offset:offset + 10], b'viewgroup\0')
        # Two resource lookups are not one retained transaction. C+0 is read
        # afresh for both, without a captured original playback/UI epoch.

    def test_resource_viewgroup_lookup_releases_its_opaque_registry_callback(self):
        self.instructions(0x485988,
                          'beq s3,zero,0x485764', 'lui v0,0x2',
                          'addu v0,s3,v0', 'lw t9,-0x6c18(v0)',
                          'lui a2,0x94', 'addu a0,s3,zero',
                          'addiu a1,s6,2228', 'addiu a2,a2,-29364',
                          'jalr ra,t9', 'addiu a3,zero,3531')
        self.instructions(0x4859B0,
                          'lui v0,0x1', 'addu v0,s3,v0',
                          'lw s0,-0x2c88(v0)', 'ori s4,zero,0xD378',
                          'addu s4,s3,s4')
        self.instructions(0x4859E0,
                          'addiu a0,s0,228', 'jal 0xA5B600',
                          'addu a1,s2,zero', 'bne v0,zero,0x4859D4',
                          'lui v0,0x2', 'addu v0,s3,v0',
                          'lw t9,-0x6c14(v0)', 'addu a0,s3,zero',
                          'jalr ra,t9', 'addiu a1,s6,2228',
                          'beq zero,zero,0x485500', 'addu v0,s0,zero')
        self.instructions(0x485500, 'lw ra,+0x34(sp)')
        # Callback addresses manager+193E8/+193EC and their exact runtime
        # locking/retention contract remain opaque. The latter dispatch has
        # completed before the selected node is returned; no retained lease
        # across439E20, the second lookup or438200 follows from this source.

    def test_outer_call_arguments_and_saved_registers_support_only_bounded_ra_frame_gates(self):
        self.instructions(0x439F84,
                          'addu a0,s0,zero', 'addu a1,s1,zero',
                          'addiu a2,sp,24', 'jal 0x438200',
                          'addu a3,s2,zero')
        self.instructions(0x43821C,
                          'sw s3,+0x1e4(sp)', 'sw s2,+0x1e0(sp)',
                          'sw s1,+0x1dc(sp)')
        self.assertEqual(0x439F90 + 8, 0x439F98)
        self.assertEqual(OUTER_FRAME + 0x34, 0x234)
        self.assertEqual(OUTER_FRAME + CARRIER, 0x214)
        self.assertEqual(OUTER_FRAME + 0x18, 0x218)
        # Candidate BEFORE reading callback carrier: saved outer RA+1FC is
        # 439F98; saved callback RA+234 is an audited engine continuation.
        # Then require a2==outerSP+218, C/a0==savedS0+1D8,
        # W/a1==savedS1+1DC, a3==savedS2+1E0 and controller==savedS3+1E4.
        # Unknown source must remain unsupported/zero, not acquire a new ID.

    def test_renderer_binding_and_nested_frame_chain_have_no_extra_child_carrier_word(self):
        self.instructions(0x4928C8,
                          'lui a1,0x49', 'addu a0,s2,zero',
                          'jal 0x459540', 'addiu a1,a1,1760')
        self.instructions(0x459540,
                          'beq a0,zero,0x459554', 'nop',
                          'sw a1,+0x148(a0)')
        self.instructions(0x43872C,
                          'lw t9,+0x148(fp)', 'beq t9,zero,0x4388A4',
                          'lw t2,+0x1cc(sp)', 'lw a2,+0x1b0(sp)',
                          'addu a0,fp,zero', 'jalr ra,t9', 'addu a1,s0,zero')
        self.instructions(0x4906F8,
                          'addiu sp,sp,-48', 'sw ra,+0x2c(sp)',
                          'sw s3,+0x24(sp)', 'sw s1,+0x1c(sp)',
                          'sw s0,+0x18(sp)')
        self.assertEqual(0x438740 + 8, 0x438748)
        self.assertEqual(0x30 + CARRIER, 0x44)
        self.assertEqual(0x30 + OUTER_FRAME, 0x230)
        self.assertEqual(0x30 + OUTER_FRAME + CARRIER, 0x244)
        # At rendererSP R, gate R+2C==438748 before ancestor reads; outer
        # savedRA is R+22C and callback savedRA is R+264. The outer carrier
        # is R+44. Existing diagnostic renderer slots10/14 are entryR/rootID,
        # so a new ID needs a separate private record/frame field, or a
        # guarded ancestor read, never overwriting either occupied word.

    def test_cache_canvas_is_created_after_the_earlier_callback_not_ui_epoch(self):
        self.instructions(0x438430,
                          'addiu v0,sp,432', 'addu a0,t2,zero',
                          'sw v0,+0x10(sp)', 'jal 0x47AB40',
                          'addu a1,s2,zero', 'lw v0,+0x1b0(sp)',
                          'beq v0,zero,0x4386F4')
        self.instructions(0x438720,
                          'addiu a3,sp,432', 'jal 0x47A920', 'sw t2,+0x1cc(sp)')
        self.instructions(0x49078C, 'lw v1,+0x50(s1)', 'lw v0,+0x60(s1)')
        self.dominated(OUTER, OUTER_END, 0x438248, 0x438724, 0x438740)
        # A callback-entry or fresh-canvas stamp detects no request queued
        # earlier than its own entry. An old C newly invoked after a known
        # boundary can receive a fresh stamp: retain the upstream gap.


if __name__ == '__main__':
    unittest.main()
