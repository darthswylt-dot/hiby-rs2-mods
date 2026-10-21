#!/usr/bin/env python3
"""Hash-pinned worker/postfill observation sites, not completion authority.

The native indirect calls and their return PCs are part of the contract: an
observer must not replace them with cave calls bearing different ancestry.
The control-flow census covers direct edges in file-backed SHF_EXECINSTR
sections only. Indirect entries, exceptions, lifetime, cross-thread ownership,
complete writer coverage and successful/READY publication remain unproved.
No device, network, installer or binary/source writes.
"""

import hashlib
import unittest

import test_folderfollow_reveal_logical_contract as cfg
import test_folderfollow_reveal_static_contract as source


PAIRS = {
    'fill_dispatch': (0x48EC48, (0x8E3902C0, 0x1320000B)),
    'fill_return': (0x48EC5C, (0x2403FFFF, 0x1043005A)),
    'post_dispatch': (0x48EC68, (0x8E3902BC, 0x13200003)),
    'normal_end': (0x48EC7C, (0x24020002, 0xAE220004)),
    'error_end': (0x48EDD4, (0x1000FFAA, 0x24020002)),
    'bind_entry': (0x4A0EE0, (0x27BDFFC0, 0xAFB1002C)),
    'post_return': (0x48F8E4, (0x8FB00028, 0x03E00008)),
}


class RevealOperationContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.elf = source.Elf32(source.SOURCE)
        digest = hashlib.sha256(cls.elf.data).hexdigest()
        if digest != source.SOURCE_SHA256 or len(cls.elf.data) != source.SOURCE_SIZE:
            raise AssertionError(f'unrecognized reference: SHA-256 {digest}, '
                                 f'size {len(cls.elf.data)}')
        # Scan actual executable sections, not whole RX segments containing
        # data. This remains a direct-target inventory, not all-entry proof.
        cls.inbounds = {}
        cls.sections = cfg.executable_sections(cls.elf)
        for _, low, high in cls.sections:
            for pc in range(low, high, 4):
                target = cfg.direct_target(pc, cls.elf.word(pc))
                if target is not None:
                    cls.inbounds.setdefault(target, []).append(pc)

    def instructions(self, start, *expected):
        for index, assembly in enumerate(expected):
            pc = start + 4 * index
            with self.subTest(pc=f'{pc:#x}', assembly=assembly):
                self.assertEqual(source.decode(pc, self.elf.word(pc)), assembly)

    def reachable(self, entry, low, high, *, blocked=()):
        """Bounded native direct CFG; callees return and conditions vary."""
        todo, seen, blocked = [entry], set(), set(blocked)
        while todo:
            pc = todo.pop()
            if not low <= pc < high or pc in seen or pc in blocked:
                continue
            seen.add(pc)
            next_pcs, delayed = cfg.successors(pc, self.elf.word(pc))
            if delayed:
                if pc + 4 in blocked:
                    continue
                seen.add(pc + 4)
            todo.extend(next_pcs)
        return seen

    def test_exact_observer_pairs_retain_separate_native_call_instructions(self):
        for name, (pc, pair) in PAIRS.items():
            with self.subTest(name=name):
                self.assertEqual((self.elf.word(pc), self.elf.word(pc + 4)), pair)
        self.instructions(0x48EC48,
                          'lw t9,+0x2c0(s1)', 'beq t9,zero,0x48EC7C',
                          'addu a0,s0,zero', 'jalr ra,t9', 'addu a1,s1,zero')
        self.instructions(0x48EC68,
                          'lw t9,+0x2bc(s1)', 'beq t9,zero,0x48EC7C',
                          'addu a0,s0,zero', 'jalr ra,t9', 'addu a1,s1,zero')
        # These words must remain at their original PCs, not be replayed as
        # observer-owned calls. RA identifies the original worker invocation.
        self.assertEqual(0x48EC54 + 8, 0x48EC5C)
        self.assertEqual(0x48EC74 + 8, 0x48EC7C)

    def test_branch_delay_words_and_fill_error_test_are_original_native_effects(self):
        self.instructions(0x48EC5C,
                          'addiu v1,zero,-1', 'beq v0,v1,0x48EDCC',
                          'addiu a0,s3,5200', 'lw t9,+0x2bc(s1)')
        self.instructions(0x48EC7C,
                          'addiu v0,zero,2', 'sw v0,+0x4(s1)',
                          'jal 0x466DC0', 'lw a0,+0x10(s0)')
        # The worker ignores other fill results at this boundary. Observer
        # events must retain the actual result, not turn !=-1 into SQL success.
        self.assertEqual(self.elf.word(0x48EC50), 0x02002021)
        self.assertEqual(self.elf.word(0x48EC64), 0x26641450)
        self.assertEqual(self.elf.word(0x48EC70), 0x02002021)

    def test_direct_inbound_inventory_covers_displaced_second_words(self):
        expected = {
            0x48EC48: [], 0x48EC4C: [],
            0x48EC5C: [], 0x48EC60: [],
            0x48EC68: [], 0x48EC6C: [],
            0x48EC7C: [0x48EC4C, 0x48EC6C],
            0x48EC80: [0x48EDD4],
            0x48EDD4: [], 0x48EDD8: [],
            0x48F8E0: [0x48F88C, 0x48F894],
            0x48F8E4: [0x48F8B0, 0x48F8BC],
            0x48F8E8: [], 0x48F8EC: [],
        }
        for pc, incoming in expected.items():
            with self.subTest(target=f'{pc:#x}'):
                self.assertEqual(self.inbounds.get(pc, []), incoming)
        # EC80 is the crucial exception: it is the NORMAL_END pair's second
        # word, but ERROR_END jumps to it. A J+NOP at EC7C cannot leave that
        # old error jump unchanged. The error wrapper must replay its force2
        # AND EC80's store itself, then resume EC84 (not overwritten EC80).
        self.assertEqual(cfg.direct_target(0x48EDD4, self.elf.word(0x48EDD4)),
                         PAIRS['normal_end'][0] + 4)
        self.assertEqual(PAIRS['normal_end'][0] + 8, 0x48EC84)

    def test_fill_minus_one_reports_then_skips_the_normal_end_entry(self):
        self.instructions(0x48EDCC,
                          'jal 0x467160', 'addu a1,s5,zero',
                          'beq zero,zero,0x48EC80', 'addiu v0,zero,2')
        error_path = self.reachable(0x48EDCC, 0x48EC30, 0x48EDDC)
        self.assertIn(0x48EDD4, error_path)
        self.assertIn(0x48EC80, error_path)
        self.assertNotIn(0x48EC7C, error_path)
        self.assertNotIn(0x48EC74, error_path)
        # A successful report call and state2 store are the stock error path
        # too; neither can seal rows, establish READY or certify completion.

    def test_post_return_hook_covers_null_lookup_branches_that_bypass_ra_load(self):
        self.instructions(0x48F8AC,
                          'lw v0,+0x20(sp)', 'beq v0,zero,0x48F8E4',
                          'lw ra,+0x2c(sp)', 'lw a0,+0x3b68(v0)',
                          'beq a0,zero,0x48F8E4', 'nop')
        self.instructions(0x48F8D4,
                          'lw t9,+0x410(a0)', 'jalr ra,t9', 'nop',
                          'lw ra,+0x2c(sp)', 'lw s0,+0x28(sp)',
                          'jr ra', 'addiu sp,sp,48')
        without_e0 = self.reachable(
            0x48F880, 0x48F880, 0x48F8F0, blocked=(0x48F8E0,))
        self.assertIn(0x48F8E4, without_e0)
        without_e4 = self.reachable(
            0x48F880, 0x48F880, 0x48F8F0, blocked=(0x48F8E4,))
        self.assertNotIn(0x48F8E8, without_e4)
        # E0/E4 would be an unsafe hook pair: V/P-null branches target its
        # second word directly. E4/E8 plus the original EC stack delay must
        # instead be handled by one custom epilogue preserving RA and SP.
        self.assertEqual(PAIRS['post_return'][0], 0x48F8E4)
        self.assertEqual(self.elf.word(0x48F8EC), 0x27BD0030)

    def test_exact_bind_ancestry_uses_native_ra_cached_view_and_worker_job(self):
        self.instructions(0x48F880,
                          'addiu sp,sp,-48', 'sw ra,+0x2c(sp)',
                          'sw s0,+0x28(sp)')
        self.instructions(0x48F894,
                          'beq a1,zero,0x48F8E0', 'addu s0,a1,zero',
                          'lw a0,+0x138(a0)', 'addiu a2,sp,32',
                          'jal 0x4E5320', 'addiu a1,a1,72',
                          'lw v0,+0x20(sp)')
        self.instructions(0x48F8C4,
                          'lw a1,+0x64(v0)', 'lw a2,+0x290(s0)',
                          'lw a3,+0x294(s0)', 'sw zero,+0x10(sp)',
                          'lw t9,+0x410(a0)', 'jalr ra,t9', 'nop')
        # At bind entry SP=P is still the post callback's native SP:
        #   current RA=48F8E0; [P+2C]=48EC7C; cached V=[P+20].
        # These are exact source ancestry gates, not retained native owners.
        self.assertEqual(0x48F8D8 + 8, 0x48F8E0)
        self.assertEqual(0x48EC74 + 8, 0x48EC7C)
        self.assertEqual(0x30 + 0xAA0, 0xAD0)
        self.instructions(0x48EA80, 'addiu sp,sp,-2760', 'sw s3,+0xab0(sp)')
        self.instructions(0x48EA8C, 'sw s0,+0xaa4(sp)')
        # P+30 is the worker SP, whose private borrow word lies at+AA0.
        # No direct assignment to s1 occurs in this bounded post body. Native
        # callees preserving it remains the O32 ABI premise, not a live proof.
        writes_s1 = []
        for pc in range(0x48F880, 0x48F8F0, 4):
            word = self.elf.word(pc)
            op, rt, rd = word >> 26, (word >> 16) & 31, (word >> 11) & 31
            fn = word & 63
            if ((op == 0 and fn not in (8, 9, 0x11, 0x13, 0x18, 0x19, 0x1A, 0x1B)
                 and rd == 17)
                    or (op in (8, 9, 10, 11, 12, 13, 14, 15,
                               32, 33, 34, 35, 36, 37, 38) and rt == 17)):
                writes_s1.append(pc)
        self.assertEqual(writes_s1, [])
        self.instructions(0x48EC74, 'jalr ra,t9', 'addu a1,s1,zero')

    def test_binder_entry_is_before_prologue_and_dispatch_remains_a_shared_method(self):
        self.instructions(0x4A0EE0,
                          'addiu sp,sp,-64', 'sw s1,+0x2c(sp)',
                          'sw s0,+0x28(sp)', 'sw ra,+0x3c(sp)')
        self.instructions(0x4A0908,
                          'lui v0,0x4A', 'addiu v0,v0,3808', 'sw v0,+0x410(s0)')
        self.instructions(0x4A0F2C, 'sw s1,+0x1bc(s0)')
        # Existing revision notification runs at entry before these displaced
        # words. The operation observer must also sample the pre-prologue RA
        # and worker s1; later binder s1 has already become its list argument.
        self.instructions(0x4A0F00,
                          'beq a0,zero,0x4A10AC', 'addu s1,a1,zero')
        self.assertEqual(3808, 0xEE0)
        # Other callers use the same method: entry address alone is not a
        # Files-post invocation identity or permission to dereference ancestry.
        self.instructions(0x4912B4,
                          'lw t9,+0x410(a0)', 'jalr ra,t9', 'addu a2,zero,zero')


if __name__ == '__main__':
    unittest.main()
