#!/usr/bin/env python3
"""Hash-gated ENTRY-only contents-revision leads in the preserved stock ELF.

The bounded CFG checks below start at the named native entries, overapproximate
conditional branches and assume calls return normally. They do not prove all
writers, arbitrary indirect/computed entries, native lifetime, serialization or
currentness. A diagnostic increment is not BEGIN/END, a non-nesting guard,
successful mutation, completed destruction, row publication or READY.
No binary/source writes, installer, network or player access.
"""

import hashlib
import unittest

import test_folderfollow_reveal_static_contract as source


# Original word pairs only. All are entry notifications BEFORE replaying the
# pair; there is no exit pair and no completion/ownership meaning in this list.
HOOKS = {
    'render_entry': (0x4906F8, (0x27BDFFD0, 0xAFBF002C)),
    'worker_entry': (0x48D080, (0x27BDFFC0, 0xAFBF003C)),
    'reset': (0x491240, (0x27BDFFB8, 0xAFBF0044)),
    'reconcile': (0x4919E0, (0x27BDFDA8, 0xAFB3024C)),
    'reset_named': (0x494A00, (0x27BDFFB0, 0xAFBF004C)),
    'close_attempt': (0x493B0C, (0x24020001, 0xAE020044)),
    'postfill': (0x48F880, (0x27BDFFD0, 0xAFBF002C)),
    'bind': (0x4A0EE0, (0x27BDFFC0, 0xAFB1002C)),
}


class RevealContentsRevisionContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.elf = source.Elf32(source.SOURCE)
        digest = hashlib.sha256(cls.elf.data).hexdigest()
        if digest != source.SOURCE_SHA256 or len(cls.elf.data) != source.SOURCE_SIZE:
            raise AssertionError(f'unrecognized reference: SHA-256 {digest}, '
                                 f'size {len(cls.elf.data)}')

    def instructions(self, start, *expected):
        for index, assembly in enumerate(expected):
            pc = start + 4 * index
            with self.subTest(pc=f'{pc:#x}', assembly=assembly):
                self.assertEqual(source.decode(pc, self.elf.word(pc)), assembly)

    def reachable(self, entry, low, high, *, blocked=()):
        """Named-entry direct CFG only; no callee/exception/alias proof.

        Delay slots are included as visited instructions, then the control
        instruction supplies successors. No tested target is a delay slot.
        Calls fall through, and conditional branches admit both outcomes.
        """
        todo, seen, blocked = [entry], set(), set(blocked)
        while todo:
            pc = todo.pop()
            if not low <= pc < high or pc in seen or pc in blocked:
                continue
            seen.add(pc)
            word = self.elf.word(pc)
            op, rs, rt = word >> 26, (word >> 21) & 31, (word >> 16) & 31
            fn = word & 63
            control = op in (1, 2, 3, 4, 5, 6, 7, 0x14, 0x15, 0x16, 0x17)
            control = control or (op == 0 and fn in (8, 9))
            if control:
                if pc + 4 in blocked:
                    continue
                seen.add(pc + 4)
            if op == 0 and fn == 8:  # JR: native return, not a later call.
                continue
            if op == 2:
                todo.append(((pc + 4) & 0xF0000000) | ((word & 0x3FFFFFF) << 2))
            elif op == 3 or (op == 0 and fn == 9):
                todo.append(pc + 8)
            elif op in (1, 4, 5, 6, 7, 0x14, 0x15, 0x16, 0x17):
                imm = word & 0xFFFF
                imm -= 0x10000 if imm & 0x8000 else 0
                todo.append(pc + 4 + imm * 4)
                if not (op == 4 and rs == rt == 0):
                    todo.append(pc + 8)
            else:
                todo.append(pc + 4)
        return seen

    def dominated(self, entry, end, hook, *targets):
        """Only domination from this named native entry, not all entries."""
        admitted = self.reachable(entry, entry, end)
        absent = self.reachable(entry, entry, end, blocked=(hook,))
        for target in targets:
            with self.subTest(entry=f'{entry:#x}', target=f'{target:#x}'):
                self.assertIn(target, admitted)
                self.assertNotIn(target, absent)

    def test_exact_eight_entry_pairs_are_not_completion_or_ready_hooks(self):
        self.assertEqual(len(HOOKS), 8)
        for name, (pc, pair) in HOOKS.items():
            with self.subTest(name=name, pc=f'{pc:#x}'):
                self.assertEqual((self.elf.word(pc), self.elf.word(pc + 4)), pair)
        # Seven pairs only establish native frames/saved registers. The one
        # mid-function pair sets a closing marker, not completed destruction.
        self.assertEqual(HOOKS['close_attempt'][0] + 8, 0x493B14)

    def test_renderer_null_guards_precede_hook_and_template_changes_precede_lock(self):
        self.instructions(0x4906E0,
                          'beq a0,zero,0x490890', 'nop',
                          'beq a1,zero,0x490890', 'nop',
                          'beq a2,zero,0x490890', 'nop',
                          'addiu sp,sp,-48', 'sw ra,+0x2c(sp)')
        self.instructions(0x490758,
                          'addu s0,v0,zero', 'addiu a0,v0,14508',
                          'addu a1,s1,zero', 'jal 0xA5BEE0',
                          'lw s4,+0xdc(v0)', 'sw s1,+0x3b50(s0)',
                          'lw v0,+0x1bc(s2)', 'sw s2,+0x3b54(s0)',
                          'addiu a0,s0,14572', 'sw v0,+0x64(s0)')
        self.instructions(0x49080C, 'jal 0x48F180', 'addiu a1,s0,14500')
        self.instructions(0x48F194,
                          'lw a0,+0x10(a0)', 'jal 0x466DA0', 'addu s1,a1,zero')
        self.dominated(0x4906E0, 0x490898, 0x4906F8,
                       0x490764, 0x49076C, 0x49077C, 0x49080C)
        # Null-guard rejection bypasses the hook. Relocating the branching
        # function entry as an ordinary two-word prologue would be incorrect.
        self.assertIn(0x490890, self.reachable(
            0x4906E0, 0x4906E0, 0x490898, blocked=(0x4906F8,)))

    def test_worker_entry_precedes_both_clear_calls_and_auxiliary_append_chain(self):
        self.instructions(0x48D09C,
                          'beq a0,zero,0x48D228', 'sw zero,+0x20(sp)',
                          'lw v0,+0x290(a1)', 'bltz v0,0x48D228', 'nop',
                          'lw v1,+0x294(a1)', 'blez v1,0x48D22C')
        self.instructions(0x48D110,
                          'lw a0,+0x68(s2)', 'beq a0,zero,0x48D12C',
                          'nop', 'lw t9,+0x24(a0)', 'jalr ra,t9', 'nop')
        self.instructions(0x48D13C,
                          'addu a3,a2,a3', 'jal 0x48D040', 'addiu a3,a3,-1')
        self.instructions(0x48D168,
                          'lw a0,+0x1bc(s1)', 'lw t9,+0x24(a0)', 'jalr ra,t9', 'nop')
        self.instructions(0x48D24C,
                          'lw a1,+0x1bc(s1)', 'jal 0x48D040',
                          'addiu a3,a3,-1', 'beq zero,zero,0x48D16C',
                          'lw a0,+0x1bc(s1)')
        self.instructions(0x48D040,
                          'beq a0,zero,0x48D06C', 'nop',
                          'lw v0,+0x68(a0)', 'beq v0,zero,0x48D06C', 'nop',
                          'beq a1,zero,0x48D06C', 'nop',
                          'bltz a2,0x48D06C', 'nop', 'j 0x48CC80', 'nop')
        self.instructions(0x48CD1C,
                          'jal 0xA5B440', 'nop', 'lw a0,+0x68(s3)',
                          'addu v0,s4,s0', 'sw v0,+0xaa0(sp)',
                          'lw t9,+0x18(a0)', 'jalr ra,t9', 'addiu a1,sp,24')
        self.dominated(0x48D080, 0x48D260, 0x48D080,
                       0x48D120, 0x48D140, 0x48D170, 0x48D1B8, 0x48D250)
        self.assertLess(0x48D140, 0x48D1B8)
        # The native auxiliary-list append can precede the SQL producer. A
        # postfill-only notification cannot invalidate before these writes.
        self.instructions(0x48D1B8, 'jal 0x6F7CA0', 'sw s0,+0x10(sp)')

    def test_reset_entry_precedes_free_and_can_contain_a_later_producer(self):
        self.instructions(0x491254,
                          'beq a1,zero,0x491430', 'sw s0,+0x34(sp)',
                          'addu s2,a0,zero', 'lw a0,+0x64(a1)',
                          'beq a0,zero,0x491274', 'addu s0,a1,zero',
                          'jal 0x456E80', 'nop')
        self.instructions(0x491288,
                          'lw a0,+0x3b68(s0)', 'sw zero,+0x68(s0)',
                          'lw t9,+0x4218(s0)', 'lw a2,+0x1d4(a0)',
                          'addiu a1,s0,100', 'jalr ra,t9', 'addiu a3,s0,108')
        self.dominated(0x491240, 0x49144C, 0x491240,
                       0x49126C, 0x491280, 0x49129C, 0x4912B8)
        # Ordinary Files config copies49E360 into V+4218 (separate contract).
        # Its query executes synchronously INSIDE this already-entered reset.
        self.assertEqual(self.elf.word(0xA98A28 + 0x104), 0x49E360)
        self.instructions(0x49E428,
                          'addu a0,s2,zero', 'addu a1,zero,zero',
                          'jal 0x6F7CA0', 'sw s5,+0x10(sp)')
        self.instructions(0x6F8BEC, 'jal 0x6ED5C0', 'addu a3,s6,zero')
        self.instructions(0x4912B4,
                          'lw t9,+0x410(a0)', 'jalr ra,t9', 'addu a2,zero,zero')
        # A producer beginning after the entry bump can observe the same
        # revision through END while the outer reset is still in progress.
        # Equality is therefore not an implicit contents END or READY.

    def test_reconcile_entry_precedes_scope_copy_and_distinct_local_frees(self):
        self.instructions(0x491A1C,
                          'beq s1,zero,0x491E50', 'lw ra,+0x254(sp)',
                          'beq s2,zero,0x491E50', 'nop',
                          'beq s3,zero,0x491E50', 'nop')
        self.instructions(0x491AC8,
                          'beq a0,zero,0x491E4C', 'addiu a0,a0,15832',
                          'addiu a1,sp,32', 'jal 0x41FB80', 'addiu a2,zero,259')
        self.instructions(0x491D44,
                          'lw a0,+0x238(sp)', 'beq a0,zero,0x491E4C',
                          'addiu a0,a0,15832', 'addu a1,s3,zero',
                          'jal 0x41FB80', 'addiu a2,zero,259')
        self.instructions(0x491E2C,
                          'beq zero,zero,0x491BA4', 'addu s2,zero,zero')
        for pc in (0x491BB0, 0x491BC8):
            self.instructions(pc, 'jal 0x456E80', 'nop')
        self.dominated(0x4919E0, 0x491E70, 0x4919E0,
                       0x491AD4, 0x491D54, 0x491BB0, 0x491BC8, 0x491BE8, 0x491C08)
        # Local frees bypass491240. The degenerate-depth branch goes into
        # reset, not directly to a no-op return; no valid-input claim follows.

    def test_named_reset_entry_precedes_resolution_guard_and_local_mutation(self):
        self.instructions(0x494A1C,
                          'beq a1,zero,0x494C1C', 'sw zero,+0x30(sp)',
                          'addiu a2,sp,48', 'addu s2,a1,zero',
                          'jal 0x4E5320', 'addu s3,a0,zero',
                          'lw a3,+0x30(sp)', 'beq a3,zero,0x494D0C')
        for pc in (0x494A4C, 0x494A64):
            self.instructions(pc, 'jal 0x456E80', 'nop')
        self.instructions(0x494A78,
                          'lw t9,+0x4218(a3)', 'lw a2,+0x1d4(a0)',
                          'addiu a1,a3,100', 'jalr ra,t9', 'addiu a3,a3,108')
        self.dominated(0x494A00, 0x494D24, 0x494A00,
                       0x494A4C, 0x494A64, 0x494A84, 0x494AA4)
        # Name resolution and raw pointer reuse are not ownership; even a
        # path that fails resolution has already entered the diagnostic hook.

    def test_close_attempt_has_nonnull_guard_and_can_return_without_destruction(self):
        self.instructions(0x493AFC,
                          'jal 0xA5BC60', 'sw s2,+0x498(sp)',
                          'beq s0,zero,0x494264', 'addu a0,s0,zero',
                          'addiu v0,zero,1', 'sw v0,+0x44(s0)',
                          'lw s6,+0x41e8(s0)', 'lw s5,+0xd4(s0)')
        self.dominated(0x493AC0, 0x494290, 0x493B0C,
                       0x493B10, 0x493B14, 0x493B3C, 0x493FDC, 0x494038)
        self.instructions(0x494030,
                          'addu a0,s5,zero', 'addu a1,s2,zero',
                          'jal 0x4919E0', 'addu a2,s1,zero',
                          'bne v0,zero,0x493C98', 'addu v0,zero,zero')
        self.instructions(0x493CC0, 'jr ra', 'addiu sp,sp,1208')
        # Conditional source path only: a returning reconcile can take the
        # epilogue without ordinary cleanup48F800 or final native free466A80.
        no_destruction = self.reachable(
            0x493FEC, 0x493AC0, 0x494290, blocked=(0x493B3C, 0x493FDC))
        self.assertIn(0x494038, no_destruction)
        self.assertIn(0x493CC0, no_destruction)
        self.assertNotIn(0x493B3C, no_destruction)
        self.assertNotIn(0x493FDC, no_destruction)

    def test_postfill_and_binding_entries_nest_and_do_not_seal_rows(self):
        self.instructions(0x48F88C,
                          'beq a0,zero,0x48F8E0', 'sw zero,+0x20(sp)',
                          'beq a1,zero,0x48F8E0', 'addu s0,a1,zero')
        self.instructions(0x48F8C4,
                          'lw a1,+0x64(v0)', 'lw a2,+0x290(s0)',
                          'lw a3,+0x294(s0)', 'sw zero,+0x10(sp)',
                          'lw t9,+0x410(a0)', 'jalr ra,t9', 'nop')
        self.instructions(0x4A0908,
                          'lui v0,0x4A', 'addiu v0,v0,3808', 'sw v0,+0x410(s0)')
        self.instructions(0x4A0F00,
                          'beq a0,zero,0x4A10AC', 'addu s1,a1,zero',
                          'beq a1,zero,0x4A10AC', 'addu a0,a1,zero')
        self.instructions(0x4A0F2C, 'sw s1,+0x1bc(s0)')
        self.dominated(0x48F880, 0x48F8F0, 0x48F880, 0x48F8D8)
        self.dominated(0x4A0EE0, 0x4A10D0, 0x4A0EE0, 0x4A0F2C)
        # Postfill invokes the constructor-installed bind method before its
        # own return. Reset/reconcile/named-reset also use that same callback;
        # known nested increments must not be treated as a nesting fault.
        self.assertEqual(3808, 0x0EE0)
        self.instructions(0x48EC68,
                          'lw t9,+0x2bc(s1)', 'beq t9,zero,0x48EC7C',
                          'addu a0,s0,zero', 'jalr ra,t9', 'addu a1,s1,zero',
                          'addiu v0,zero,2', 'sw v0,+0x4(s1)')
        # Native state2 is unconditionally published after this callback; it
        # is not append/reset/terminal success or a private contents END.


if __name__ == '__main__':
    unittest.main()
