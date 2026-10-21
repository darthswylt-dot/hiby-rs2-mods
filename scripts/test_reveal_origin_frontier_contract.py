#!/usr/bin/env python3
"""Hash-pinned native premises for the diagnostic render-origin frontier.

The stock renderer has no private revision counter. These tests pin the source
frame/call/mutation facts needed by the separate emitted-entry tests, which
must check that the actual bump return is stored after replaying the prologue
and frozen into the original root receipt, never reloaded from a later clock.

SP+10 is outside the four O32 argument homes, but is also the conventional
fifth outgoing argument position. The inspected body does not use it. Indirect
targets still require the audited target/O32 premise; this is not a universal
callee, alias, native-lifetime, serialization, currentness or READY proof.
No device, network, installer or source-binary writes.
"""

import hashlib
import unittest

import test_folderfollow_reveal_static_contract as source
import test_reveal_contents_revision_contract as boundary


class RevealOriginFrontierContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.elf = source.Elf32(source.SOURCE)
        digest = hashlib.sha256(cls.elf.data).hexdigest()
        if digest != source.SOURCE_SHA256 or len(cls.elf.data) != source.SOURCE_SIZE:
            raise AssertionError(f'unrecognized reference: SHA-256 {digest}, '
                                 f'size {len(cls.elf.data)}')

    # Reuse only helpers, not a TestCase subclass/import that would duplicate
    # the earlier stage's test inventory during unittest discovery.
    instructions = boundary.RevealContentsRevisionContractTests.instructions
    reachable = boundary.RevealContentsRevisionContractTests.reachable
    dominated = boundary.RevealContentsRevisionContractTests.dominated

    def words(self, start, end):
        return [(pc, self.elf.word(pc)) for pc in range(start, end, 4)]

    def calls(self, start, end):
        return [pc for pc, word in self.words(start, end)
                if word >> 26 == 3
                or (word >> 26 == 0 and word & 63 == 9)]

    def assert_stack_free_leaf(self, start, end):
        self.assertEqual(self.calls(start, end), [])
        for pc, word in self.words(start, end):
            op, rs, rt = word >> 26, (word >> 21) & 31, (word >> 16) & 31
            with self.subTest(leaf=f'{start:#x}', pc=f'{pc:#x}'):
                self.assertNotEqual(rs, 29)
                if op == 0:
                    self.assertNotEqual(rt, 29)
                    self.assertNotEqual((word >> 11) & 31, 29)
                elif op not in (2, 3):
                    self.assertNotEqual(rt, 29)
                self.assertNotIn(op, (0x28, 0x29, 0x2A, 0x2B, 0x2E))

    def test_entry_guards_and_prologue_precede_the_available_native_slot(self):
        self.instructions(0x4906E0,
                          'beq a0,zero,0x490890', 'nop',
                          'beq a1,zero,0x490890', 'nop',
                          'beq a2,zero,0x490890', 'nop',
                          'addiu sp,sp,-48', 'sw ra,+0x2c(sp)',
                          'sw s3,+0x24(sp)', 'sw s1,+0x1c(sp)',
                          'sw s0,+0x18(sp)', 'sw s4,+0x28(sp)',
                          'sw s2,+0x20(sp)')
        self.instructions(0x490890, 'jr ra', 'addiu v0,zero,-1')
        self.dominated(0x4906E0, 0x490898, 0x4906F8, 0x490758)
        self.assertIn(0x490890, self.reachable(
            0x4906E0, 0x4906E0, 0x490898, blocked=(0x4906F8,)))
        # The replacement entry must replay these two prologue words FIRST;
        # its own observer frame then addresses nativeSP+10, not entrySP+10.
        # Resume490700 must not replay the native allocation a second time.
        self.assertEqual((self.elf.word(0x4906F8), self.elf.word(0x4906FC)),
                         (0x27BDFFD0, 0xAFBF002C))

    def test_body_has_no_direct_or_locally_derived_sp10_access(self):
        memory = set(range(0x20, 0x30)) | {0x30, 0x31, 0x32, 0x33,
                                         0x35, 0x36, 0x38, 0x39,
                                         0x3A, 0x3B, 0x3D, 0x3E}
        addressed, adjustments = set(), []
        for pc, word in self.words(0x4906F8, 0x490898):
            op, rs, rt = word >> 26, (word >> 21) & 31, (word >> 16) & 31
            with self.subTest(pc=f'{pc:#x}'):
                if rs == 29:
                    if op in memory:
                        self.assertIn(op, (0x23, 0x2B))
                        self.assertIn(rt, (16, 17, 18, 19, 20, 31))
                        addressed.add(word & 0xFFFF)
                    else:
                        # No addiu/addu/other export of this SP to an argument,
                        # alias register or native structure in the body.
                        self.assertEqual((op, rt), (9, 29))
                        adjustments.append((pc, word & 0xFFFF))
                if op == 0:
                    self.assertNotEqual(rt, 29)
                    self.assertNotEqual((word >> 11) & 31, 29)
                elif op not in (2, 3) and rt == 29:
                    self.assertEqual((op, rs), (9, 29))
        self.assertEqual(addressed, {0x18, 0x1C, 0x20, 0x24, 0x28, 0x2C})
        self.assertEqual(adjustments, [(0x4906F8, 0xFFD0),
                                      (0x490834, 0x30), (0x490874, 0x30)])
        # New entry-revision carrier10, existing private root-ID carrier14,
        # and first stock saved register18 are distinct four-byte intervals.
        self.assertEqual([set(range(x, x + 4)) for x in (0x10, 0x14, 0x18)],
                         [{16, 17, 18, 19}, {20, 21, 22, 23}, {24, 25, 26, 27}])
        self.assertTrue(set(range(0x10, 0x14)).isdisjoint(range(0x10)))

    def test_pre_root_calls_use_child_count_getter_and_stack_free_view_accessor(self):
        self.assertEqual(self.calls(0x4906F8, 0x490758),
                         [0x490724, 0x490734, 0x490750])
        self.instructions(0x490714,
                          'addu s0,a0,zero', 'lw a0,+0xfc(a0)',
                          'addu s3,a1,zero', 'lw t9,+0x30(a0)',
                          'jalr ra,t9', 'addu s1,a2,zero',
                          'lw a0,+0xfc(s0)', 'lw t9,+0x2c(a0)',
                          'jalr ra,t9', 'addiu a1,v0,-1')
        self.instructions(0x49073C,
                          'beq v0,zero,0x490888', 'nop',
                          'lw s2,+0x0(v0)', 'beq s2,zero,0x490818',
                          'addiu v0,zero,-1', 'jal 0x459340',
                          'addu a0,s2,zero')
        self.instructions(0x459340,
                          'beq a0,zero,0x459350', 'nop', 'jr ra',
                          'lw v0,+0x7c(a0)', 'jr ra', 'addu v0,zero,zero')
        self.assert_stack_free_leaf(0x459340, 0x459358)
        # A known outer invocation supplies exactly these three arguments;
        # neither this site nor its numeric saved RA proves all callers.
        self.instructions(0x438738,
                          'lw a2,+0x1b0(sp)', 'addu a0,fp,zero',
                          'jalr ra,t9', 'addu a1,s0,zero')

    def test_installed_child_getter_and_nonnull_count_path_do_not_touch_stack(self):
        self.instructions(0x459E48,
                          'addiu a0,zero,10', 'addiu a1,zero,4',
                          'jal 0x456E60', 'sw v0,+0x144(s0)',
                          'sw v0,+0xfc(s0)')
        self.instructions(0x456E60, 'j 0x456C40', 'addiu a2,zero,10')
        self.instructions(0x456CC8,
                          'lui v0,0x45', 'addiu v0,v0,22496',
                          'sw v0,+0x2c(s0)')
        self.instructions(0x456CE0,
                          'lui v0,0x45', 'addiu v0,v0,24000',
                          'sw v0,+0x30(s0)')
        self.assertEqual(0x450000 + 22496, 0x4557E0)
        self.assertEqual(0x450000 + 24000, 0x455DC0)
        self.assert_stack_free_leaf(0x4557E0, 0x455844)
        self.instructions(0x455DC0,
                          'beq a0,zero,0x455DD0', 'lui a1,0x92',
                          'jr ra', 'lw v0,+0xc(a0)')
        self.assert_stack_free_leaf(0x455DC0, 0x455DD0)
        # Only the admitted non-null path is leaf; the null logging path
        # allocates its own frame. Do not promote an installed method pointer
        # into proof that a live object/table cannot have changed.
        self.instructions(0x455DD0, 'lui a0,0x92', 'addiu sp,sp,-32')

    def test_later_call_shapes_do_not_add_a_fifth_argument_to_renderer_frame(self):
        self.assertEqual(self.calls(0x490758, 0x490898),
                         [0x490764, 0x4907B0, 0x4907C0,
                          0x49080C, 0x49084C, 0x490878])
        self.instructions(0x49075C,
                          'addiu a0,v0,14508', 'addu a1,s1,zero',
                          'jal 0xA5BEE0', 'lw s4,+0xdc(v0)')
        self.instructions(0x490798, 'addiu a2,zero,64')
        self.instructions(0x4907B0, 'jal 0xA5B6E0', 'lw a1,+0x0(s3)')
        self.instructions(0x4907B8,
                          'addiu a0,s0,14636', 'addiu a1,s0,15832',
                          'jal 0x41FB80', 'addiu a2,zero,260')
        for pc in (0x49080C, 0x490878):
            self.instructions(pc, 'jal 0x48F180', 'addiu a1,s0,14500')
        self.instructions(0x49084C, 'jal 0x466D00', 'lw a0,+0x14(a0)')
        # Source call shapes are strcpy(2), strncpy(3), UTF16 copy(3),
        # enqueue(2), wake(1). No fifth argument is stored at SP+10. Imported
        # implementations and replaceable indirect targets still require the
        # O32 premise. Once490758 freezes the carrier, later calls cannot
        # legitimately retag that immutable receipt from a current clock.
        for pc, word in self.words(0x4906F8, 0x490898):
            if word >> 26 == 0x2B and (word >> 21) & 31 == 29:
                self.assertGreaterEqual(word & 0xFFFF, 0x18, f'{pc:#x}')

    def test_root_site_precedes_template_changes_but_does_not_guard_view_lifetime(self):
        self.instructions(0x490758,
                          'addu s0,v0,zero', 'addiu a0,v0,14508',
                          'addu a1,s1,zero', 'jal 0xA5BEE0',
                          'lw s4,+0xdc(v0)', 'sw s1,+0x3b50(s0)',
                          'lw v0,+0x1bc(s2)', 'sw s2,+0x3b54(s0)',
                          'addiu a0,s0,14572', 'sw v0,+0x64(s0)')
        self.dominated(0x4906E0, 0x490898, 0x490758,
                       0x490764, 0x49076C, 0x490774, 0x49077C)
        # Child lookup failure returns after the entry without minting a
        # root. Conversely, a non-null child can contain V==0: accessor459340
        # simply loads+7C and there is no V-null branch before this dereference.
        self.instructions(0x490888,
                          'beq zero,zero,0x490818', 'addiu v0,zero,-1')
        self.assertEqual([pc for pc, word in self.words(0x490758, 0x49076C)
                          if word >> 26 in (1, 4, 5, 6, 7)], [])
        # A numeric V/P pair or frontier equality is not native object life,
        # immutable template contents, exclusive ownership or UI authority.

    def test_worker_entry_dominates_query_but_occurs_after_dispatch_observation(self):
        self.instructions(0x48EC48,
                          'lw t9,+0x2c0(s1)', 'beq t9,zero,0x48EC7C',
                          'addu a0,s0,zero', 'jalr ra,t9',
                          'addu a1,s1,zero')
        self.instructions(0x48D080, 'addiu sp,sp,-64', 'sw ra,+0x3c(sp)')
        self.dominated(0x48D080, 0x48D260, 0x48D080,
                       0x48D120, 0x48D140, 0x48D170, 0x48D1B8, 0x48D250)
        self.instructions(0x48D1B8, 'jal 0x6F7CA0', 'sw s0,+0x10(sp)')
        self.instructions(0x48EC68,
                          'lw t9,+0x2bc(s1)', 'beq t9,zero,0x48EC7C',
                          'addu a0,s0,zero', 'jalr ra,t9',
                          'addu a1,s1,zero')
        # The worker's SP+10 here is its unrelated fifth query argument,
        # not the renderer's carrier. A FILL_BEGIN sample before48EC54 may
        # match the root entry revision; a producer-start sample after the
        # worker entry cannot substitute for this stale-start comparison.

    def test_one_renderer_can_enqueue_twice_and_master_can_be_reborrowed(self):
        self.instructions(0x490878,
                          'jal 0x48F180', 'addiu a1,s0,14500',
                          'beq zero,zero,0x4907F0', 'lw a0,+0x3b84(s0)')
        self.instructions(0x49080C, 'jal 0x48F180', 'addiu a1,s0,14500')
        after_shared = self.reachable(0x490880, 0x4906E0, 0x490898)
        self.assertIn(0x49080C, after_shared)
        self.assertNotIn(0x490758, after_shared)
        self.instructions(0x48ED64,
                          'lw a0,+0x130(s0)', 'lw t9,+0x2c(a0)',
                          'jalr ra,t9', 'addiu a1,v0,-1',
                          'lw a0,+0x134(s0)', 'lw t9,+0x18(a0)',
                          'jalr ra,t9', 'addu a1,v0,zero',
                          'jal 0x466DC0', 'lw a0,+0x10(s0)',
                          'beq zero,zero,0x48EB2C', 'lw a0,+0x134(s0)')
        self.instructions(0x48EB2C,
                          'lw t9,+0x2c(a0)', 'jalr ra,t9',
                          'addu a1,zero,zero', 'beq v0,zero,0x48EAE0',
                          'addu s1,v0,zero', 'lw a0,+0x10(s0)',
                          'addiu s6,zero,1')
        # Recopy/borrow does not re-enter the renderer or mint a new root.
        # The first worker/postfill/bind entries advance the diagnostic clock;
        # another chunk of the same root may therefore be rejected. This
        # deliberate conservative frontier is not a whole-folder generation.


if __name__ == '__main__':
    unittest.main()
